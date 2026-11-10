//! A runtime that holds many ships. Each ship is one SQLite file plus the WASM agents installed
//! on it; it handles one event at a time, and each event is one transaction.

mod host;
mod ship;
mod store;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use wasmtime::{Engine, InstancePre, Linker, Module};

use host::Ctx;
use ship::Ship;

/// How often the watchdog advances the clock that event deadlines are measured against.
pub(crate) const EPOCH_TICK_MILLIS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Sync to disk on every commit.
    Full,
    /// Sync at checkpoints: a power cut can lose the last few events, never corrupt the file.
    Normal,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_effect_bytes: usize,
    pub max_effects_per_event: u32,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Compute budget for one event, shared by guest instructions and host calls.
    pub fuel_per_event: u64,
    /// Wall-clock cap on one event. Fuel cannot see how large a bulk memory operation is.
    pub max_event_millis: u64,
    pub max_memory_bytes: usize,
    pub max_module_bytes: usize,
    pub max_agents_per_ship: usize,
    /// Largest ship file `import_ship` will read, and the longest it will spend reading one.
    pub max_import_bytes: u64,
    pub max_import_millis: u64,
    pub max_table_elements: usize,
    pub max_event_bytes: usize,
    pub max_reply_bytes: usize,
    /// Undelivered outgoing messages a ship may hold, counting each as its payload plus a fixed
    /// overhead; events that would exceed it are rejected.
    pub max_outbox_bytes: u64,
    /// Ships kept open for events at once. Beyond this the least recently used idle ship is put
    /// to sleep first. Creating, importing, and exporting ships open their own files outside
    /// this limit.
    pub max_awake: usize,
    pub audit_rows: u64,
    pub durability: Durability,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            fuel_per_event: 100_000_000,
            max_event_millis: 5_000,
            max_memory_bytes: 64 << 20,
            max_module_bytes: 16 << 20,
            max_agents_per_ship: 256,
            max_import_bytes: 256 << 20,
            max_import_millis: 60_000,
            max_table_elements: 100_000,
            max_event_bytes: 1 << 20,
            max_reply_bytes: 1 << 20,
            max_outbox_bytes: 64 << 20,
            max_awake: 64,
            audit_rows: 10_000,
            durability: Durability::Full,
            limits: Limits {
                max_key_bytes: 1024,
                max_value_bytes: 1 << 20,
                max_effect_bytes: 1 << 20,
                max_effects_per_event: 1024,
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub reply: Vec<u8>,
    /// Messages this event queued in the ship's outbox.
    pub effects: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Effect {
    pub seq: i64,
    pub agent: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub agent: String,
    pub event: Vec<u8>,
    /// False when the event was rejected and rolled back.
    pub ok: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    OutOfFuel,
    Timeout,
    Limit(String),
    Trap(String),
}

#[derive(Debug)]
pub enum Error {
    InvalidName(String),
    UnknownShip(String),
    ShipExists(String),
    UnknownAgent(String),
    UnknownModule(String),
    BadModule(String),
    BadShipFile(String),
    TooManyAgents,
    /// Another runtime already has this data directory open.
    DataDirInUse,
    /// The event was refused. It changed no state and queued no messages. The audit log records
    /// it on a best-effort basis.
    Rejected(Rejection),
    Store(rusqlite::Error),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidName(name) => write!(f, "invalid name: {name:?}"),
            Error::UnknownShip(name) => write!(f, "no such ship: {name}"),
            Error::ShipExists(name) => write!(f, "ship already exists: {name}"),
            Error::UnknownAgent(name) => write!(f, "no such agent: {name}"),
            Error::UnknownModule(hash) => write!(f, "no such module: {hash}"),
            Error::BadModule(why) => write!(f, "bad module: {why}"),
            Error::BadShipFile(why) => write!(f, "bad ship file: {why}"),
            Error::TooManyAgents => write!(f, "ship already has the most agents this runtime allows"),
            Error::DataDirInUse => write!(f, "another runtime is using this data directory"),
            Error::Rejected(Rejection::OutOfFuel) => write!(f, "event rejected: compute budget exhausted"),
            Error::Rejected(Rejection::Timeout) => write!(f, "event rejected: ran too long"),
            Error::Rejected(Rejection::Limit(why)) => write!(f, "event rejected: limit exceeded: {why}"),
            Error::Rejected(Rejection::Trap(why)) => write!(f, "event rejected: {why}"),
            Error::Store(e) => write!(f, "store error: {e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Store(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) struct AgentModule {
    pub pre: InstancePre<Ctx>,
}

struct Slot {
    ship: Option<Ship>,
    last_used: Instant,
}

type SlotRef = Arc<Mutex<Slot>>;

pub(crate) struct Inner {
    pub engine: Engine,
    pub cfg: Config,
    linker: Linker<Ctx>,
    ships_dir: PathBuf,
    blobs_dir: PathBuf,
    tmp_dir: PathBuf,
    modules: Mutex<HashMap<String, Arc<AgentModule>>>,
    slots: Mutex<HashMap<String, SlotRef>>,
    /// Ships that are open or being opened. Its size never exceeds `max_awake`.
    ///
    /// Lock order: a slot lock may be held while taking this lock. While holding this lock,
    /// slot locks are only ever tried, never waited on.
    awake: Mutex<HashMap<String, SlotRef>>,
    awake_changed: Condvar,
}

pub struct Runtime {
    inner: Inner,
    watchdog: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    /// Holds an exclusive lock on the data directory for as long as the runtime lives.
    _dir_lock: fs::File,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
    }
}

/// Two runtimes on one directory would each trust their own in-memory accounting, so refuse.
fn lock_data_dir(data_dir: &Path) -> Result<fs::File, Error> {
    let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(data_dir.join("runtime.lock"))?;
    // flock belongs to this open file. Unlike fcntl locks, it is not released when some other
    // descriptor for the same file is closed, which untrusted input could otherwise arrange.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        return Err(if err.kind() == io::ErrorKind::WouldBlock { Error::DataDirInUse } else { err.into() });
    }
    Ok(file)
}

/// Make a newly created or renamed entry in `dir` survive a power cut. Syncing a file's
/// contents does not by itself make its name durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// How much of an oversized event is kept in the audit log.
const OVERSIZED_AUDIT_BYTES: usize = 256;

/// Open an untrusted path for reading. Never follows a symlink, never blocks on a pipe, and
/// accepts only a regular file, so the caller cannot be pointed at a device or an endless stream.
fn open_regular(path: &Path) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(file)
}

/// Rewrite a module so that every bulk memory or table operation is preceded by an empty loop.
///
/// The engine checks fuel and the deadline at function entries and loop headers only. A bulk
/// operation can move the whole memory in one instruction, and code that runs many of them
/// without a loop or a call in between (straight-line, or while returning from deep recursion)
/// would otherwise run unchecked. An empty loop is a loop header, so it forces a check, and it
/// leaves the operand stack untouched.
fn add_bulk_checks(wasm: &[u8]) -> Result<Vec<u8>, wasmparser::BinaryReaderError> {
    use wasm_encoder::{CodeSection, RawSection};
    use wasmparser::{Operator, Payload};
    const EMPTY_LOOP: [u8; 3] = [0x03, 0x40, 0x0b];

    let mut out = wasm_encoder::Module::new();
    let mut code: Option<CodeSection> = None;
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::CodeSectionStart { .. } => code = Some(CodeSection::new()),
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                let (mut ops, mut rewritten, mut copied) = (body.get_operators_reader()?, Vec::new(), range.start);
                while !ops.eof() {
                    let (op, offset) = ops.read_with_offset()?;
                    if matches!(
                        op,
                        Operator::MemoryFill { .. }
                            | Operator::MemoryCopy { .. }
                            | Operator::MemoryInit { .. }
                            | Operator::TableFill { .. }
                            | Operator::TableCopy { .. }
                            | Operator::TableInit { .. }
                    ) {
                        rewritten.extend_from_slice(&wasm[copied..offset]);
                        rewritten.extend_from_slice(&EMPTY_LOOP);
                        copied = offset;
                    }
                }
                rewritten.extend_from_slice(&wasm[copied..range.end]);
                code.get_or_insert_with(CodeSection::new).raw(&rewritten);
            }
            other => {
                if let Some(code) = code.take() {
                    out.section(&code);
                }
                if let Some((id, range)) = other.as_section() {
                    out.section(&RawSection { id, data: &wasm[range] });
                }
            }
        }
    }
    Ok(out.finish())
}

fn canonical_ship(name: &str) -> Result<String, Error> {
    let bare = name.strip_prefix('~').unwrap_or(name);
    let ok = !bare.is_empty()
        && bare.len() <= 64
        && bare.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && !bare.starts_with('-')
        && !bare.ends_with('-');
    if ok { Ok(bare.to_string()) } else { Err(Error::InvalidName(name.to_string())) }
}

fn check_agent_name(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_lowercase()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok { Ok(()) } else { Err(Error::InvalidName(name.to_string())) }
}

fn check_hash(hash: &str) -> Result<(), Error> {
    let ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok { Ok(()) } else { Err(Error::UnknownModule(hash.to_string())) }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A scratch file that no other call can share, removed (with any SQLite side files) on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(dir: &Path) -> Scratch {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Scratch(dir.join(format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = fs::remove_file(path);
        }
    }
}

impl Runtime {
    pub fn open(data_dir: impl AsRef<Path>, mut cfg: Config) -> Result<Runtime, Error> {
        let data_dir = data_dir.as_ref();
        let (ships_dir, blobs_dir, tmp_dir) = (data_dir.join("ships"), data_dir.join("blobs"), data_dir.join("tmp"));
        for dir in [&ships_dir, &blobs_dir, &tmp_dir] {
            fs::create_dir_all(dir)?;
        }
        cfg.max_awake = cfg.max_awake.max(1);
        let dir_lock = lock_data_dir(data_dir)?;

        let mut wasm_cfg = wasmtime::Config::new();
        wasm_cfg.consume_fuel(true);
        wasm_cfg.epoch_interruption(true);
        let engine = Engine::new(&wasm_cfg).map_err(|e| Error::BadModule(format!("{e:#}")))?;
        let linker = host::linker(&engine).map_err(|e| Error::BadModule(format!("{e:#}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let (engine, stop) = (engine.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MILLIS));
                    engine.increment_epoch();
                }
            })
        };

        Ok(Runtime {
            watchdog: Some(watchdog),
            stop,
            _dir_lock: dir_lock,
            inner: Inner {
                engine,
                cfg,
                linker,
                ships_dir,
                blobs_dir,
                tmp_dir,
                modules: Mutex::new(HashMap::new()),
                slots: Mutex::new(HashMap::new()),
                awake: Mutex::new(HashMap::new()),
                awake_changed: Condvar::new(),
            },
        })
    }

    /// Store a module by content hash and compile it. Ships that install it share the compiled code.
    pub fn add_module(&self, wasm: &[u8]) -> Result<String, Error> {
        if wasm.len() > self.inner.cfg.max_module_bytes {
            return Err(Error::BadModule("module is larger than this runtime allows".into()));
        }
        let hash = sha256_hex(wasm);
        let mut modules = lock(&self.inner.modules);
        if !modules.contains_key(&hash) {
            let compiled = self.inner.compile(wasm)?;
            self.inner.store_blob(&hash, wasm)?;
            modules.insert(hash.clone(), Arc::new(compiled));
        }
        Ok(hash)
    }

    pub fn create_ship(&self, name: &str) -> Result<(), Error> {
        let name = canonical_ship(name)?;
        store::create(&self.inner.ship_path(&name), &name)?;
        Ok(sync_dir(&self.inner.ships_dir)?)
    }

    pub fn install(&self, ship: &str, agent: &str, module_hash: &str) -> Result<(), Error> {
        check_agent_name(agent)?;
        check_hash(module_hash)?;
        let module = self.inner.module(module_hash)?;
        self.inner.with_ship(ship, |ship| {
            if !ship.agents.contains_key(agent) && ship.agents.len() >= self.inner.cfg.max_agents_per_ship {
                return Err(Error::TooManyAgents);
            }
            store::set_agent(&lock(&ship.conn), agent, module_hash)?;
            ship.agents.insert(agent.to_string(), module);
            Ok(())
        })
    }

    /// Deliver one event. Events for the same ship run one at a time; different ships run in parallel.
    ///
    /// An event over the size limit is rejected without running, and only its first bytes are
    /// kept in the audit log.
    pub fn deliver(&self, ship: &str, agent: &str, event: &[u8]) -> Result<Outcome, Error> {
        if event.len() > self.inner.cfg.max_event_bytes {
            let why = format!("event is {} bytes, limit is {}", event.len(), self.inner.cfg.max_event_bytes);
            return self.inner.with_ship(ship, |ship| {
                if !ship.agents.contains_key(agent) {
                    return Err(Error::UnknownAgent(agent.to_string()));
                }
                let kept = &event[..OVERSIZED_AUDIT_BYTES.min(event.len())];
                store::audit_failure(&lock(&ship.conn), agent, kept, self.inner.cfg.audit_rows);
                Err(Error::Rejected(Rejection::Limit(why)))
            });
        }
        self.inner.with_ship(ship, |ship| ship.run(&self.inner, agent, event))
    }

    /// Take the oldest committed outgoing messages, up to `max_bytes` in total (always at least
    /// one if any is pending). A network driver would call this.
    pub fn drain_outbox(&self, ship: &str, max_bytes: usize) -> Result<Vec<Effect>, Error> {
        self.inner.with_ship(ship, |ship| {
            let effects = store::outbox_drain(&lock(&ship.conn), 1024, max_bytes)?;
            let drained: u64 =
                effects.iter().map(|e| e.payload.len() as u64 + store::OUTBOX_MESSAGE_OVERHEAD).sum();
            ship.outbox_bytes = ship.outbox_bytes.saturating_sub(drained);
            Ok(effects)
        })
    }

    /// The newest audit entries, newest first.
    pub fn audit(&self, ship: &str, limit: usize) -> Result<Vec<AuditEntry>, Error> {
        self.inner.with_ship(ship, |ship| store::audit_tail(&lock(&ship.conn), limit))
    }

    /// Write `<dest>/<ship>.ship` plus the module blobs it needs under `<dest>/blobs`.
    pub fn export_ship(&self, ship: &str, dest: impl AsRef<Path>) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let dest = dest.as_ref();
        fs::create_dir_all(dest.join("blobs"))?;
        self.inner.with_ship(&name, |ship| {
            let conn = lock(&ship.conn);
            store::snapshot_into(&conn, &dest.join(format!("{name}.ship")))?;
            for (_, hash) in store::agents(&conn)? {
                // Read, verify, then rename into place: copying a file onto itself (an export into
                // this runtime's own directory) would truncate it.
                let bytes = self.inner.read_blob(&hash)?;
                let scratch = Scratch::new(&dest.join("blobs"));
                fs::write(&scratch.0, &bytes)?;
                fs::rename(&scratch.0, dest.join("blobs").join(format!("{hash}.wasm")))?;
            }
            Ok(())
        })
    }

    /// Bring in a ship exported by `export_ship`, from this or another runtime.
    ///
    /// The source is treated as untrusted: its rows are copied into a freshly created file, and
    /// every module it names is verified against its hash.
    pub fn import_ship(&self, src: impl AsRef<Path>, ship: &str) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let src = src.as_ref();
        let dest_file = self.inner.ship_path(&name);
        if dest_file.exists() {
            return Err(Error::ShipExists(name));
        }

        let source = match open_regular(&src.join(format!("{name}.ship"))) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::UnknownShip(name)),
            Err(e) => return Err(e.into()),
        };
        let (copy, fresh) = (Scratch::new(&self.inner.tmp_dir), Scratch::new(&self.inner.tmp_dir));
        // Copy by bytes read, not by reported size, which a special file can misstate.
        let limit = self.inner.cfg.max_import_bytes;
        if io::copy(&mut source.take(limit + 1), &mut fs::File::create(&copy.0)?)? > limit {
            return Err(Error::BadShipFile(format!("{name}: larger than this runtime will import")));
        }
        let hashes = store::import(&copy.0, &fresh.0, &name, &self.inner.cfg, check_agent_name, check_hash)?;
        for hash in hashes {
            // Check the bytes on disk, not the compiled cache, which could hide a damaged blob.
            if self.inner.read_blob(&hash).is_err() {
                let bytes = self.inner.read_verified(&src.join("blobs").join(format!("{hash}.wasm")), &hash)?;
                self.inner.compile(&bytes)?;
                self.inner.store_blob(&hash, &bytes)?;
            }
        }
        // A hard link publishes the finished file without ever replacing an existing ship.
        match fs::hard_link(&fresh.0, &dest_file) {
            Ok(()) => Ok(sync_dir(&self.inner.ships_dir)?),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(Error::ShipExists(name)),
            Err(e) => Err(e.into()),
        }
    }

    /// Put to sleep every ship that has been idle for at least `idle`. Returns how many slept.
    pub fn sleep_idle(&self, idle: Duration) -> usize {
        let candidates: Vec<(String, SlotRef)> =
            lock(&self.inner.awake).iter().map(|(name, slot)| (name.clone(), slot.clone())).collect();
        let mut slept = 0;
        for (name, slot) in candidates {
            if let Ok(mut guard) = slot.try_lock() {
                if guard.ship.is_some() && guard.last_used.elapsed() >= idle {
                    // Close the file before giving up the place, so the cap also bounds open files.
                    drop(guard.ship.take());
                    lock(&self.inner.awake).remove(&name);
                    slept += 1;
                }
            };
        }
        self.inner.awake_changed.notify_all();
        slept
    }

    /// Ships that are open or being opened.
    pub fn awake(&self) -> usize {
        lock(&self.inner.awake).len()
    }

    pub fn compiled_modules(&self) -> usize {
        lock(&self.inner.modules).len()
    }
}

impl Inner {
    fn ship_path(&self, name: &str) -> PathBuf {
        self.ships_dir.join(format!("{name}.ship"))
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.blobs_dir.join(format!("{hash}.wasm"))
    }

    /// Read a module file, refusing one that is too large or does not match its hash.
    fn read_verified(&self, path: &Path, hash: &str) -> Result<Vec<u8>, Error> {
        let file = match open_regular(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::UnknownModule(hash.to_string())),
            Err(e) => return Err(e.into()),
        };
        let limit = self.cfg.max_module_bytes as u64;
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(Error::BadModule(format!("{hash}: larger than this runtime allows")));
        }
        if sha256_hex(&bytes) != hash {
            return Err(Error::BadModule(format!("{hash}: contents do not match the hash")));
        }
        Ok(bytes)
    }

    fn read_blob(&self, hash: &str) -> Result<Vec<u8>, Error> {
        self.read_verified(&self.blob_path(hash), hash)
    }

    /// Write a verified blob, replacing whatever is at its path. A rename means readers see
    /// either the old file or the whole new one.
    fn store_blob(&self, hash: &str, bytes: &[u8]) -> Result<(), Error> {
        let path = self.blob_path(hash);
        // read_blob refuses anything but an intact regular file, so a damaged entry is replaced
        // without ever being read in full.
        if self.read_blob(hash).is_ok_and(|existing| existing == bytes) {
            return Ok(());
        }
        let scratch = Scratch::new(&self.tmp_dir);
        let mut file = fs::File::create(&scratch.0)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&scratch.0, path)?;
        Ok(sync_dir(&self.blobs_dir)?)
    }

    fn compile(&self, wasm: &[u8]) -> Result<AgentModule, Error> {
        let bad = |e: anyhow::Error| Error::BadModule(format!("{e:#}"));
        // Validate the module as given before rewriting it, so a rewrite can never rescue bad input.
        Module::validate(&self.engine, wasm).map_err(bad)?;
        let checked = add_bulk_checks(wasm).map_err(|e| Error::BadModule(e.to_string()))?;
        let module = Module::new(&self.engine, &checked).map_err(bad)?;
        for name in ["alloc", "handle"] {
            if module.get_export(name).and_then(|export| export.func().cloned()).is_none() {
                return Err(Error::BadModule(format!("missing exported function `{name}`")));
            }
        }
        if module.get_export("memory").and_then(|export| export.memory().cloned()).is_none() {
            return Err(Error::BadModule("missing exported memory".into()));
        }
        Ok(AgentModule { pre: self.linker.instantiate_pre(&module).map_err(bad)? })
    }

    /// The compiled module for `hash`, loading and verifying its blob on first use.
    fn module(&self, hash: &str) -> Result<Arc<AgentModule>, Error> {
        let mut modules = lock(&self.modules);
        if let Some(module) = modules.get(hash) {
            return Ok(module.clone());
        }
        let module = Arc::new(self.compile(&self.read_blob(hash)?)?);
        modules.insert(hash.to_string(), module.clone());
        Ok(module)
    }

    fn slot(&self, name: &str) -> Result<SlotRef, Error> {
        let mut slots = lock(&self.slots);
        if let Some(slot) = slots.get(name) {
            return Ok(slot.clone());
        }
        if !self.ship_path(name).exists() {
            return Err(Error::UnknownShip(name.to_string()));
        }
        let slot = Arc::new(Mutex::new(Slot { ship: None, last_used: Instant::now() }));
        slots.insert(name.to_string(), slot.clone());
        Ok(slot)
    }

    fn wake(&self, name: &str) -> Result<Ship, Error> {
        let conn = store::open(&self.ship_path(name), self.cfg.durability)?;
        store::check_meta(&conn, name)?;
        let mut agents = HashMap::new();
        for (agent, hash) in store::agents(&conn)? {
            agents.insert(agent, self.module(&hash)?);
        }
        let outbox_bytes = store::outbox_bytes(&conn)?;
        Ok(Ship { conn: Arc::new(Mutex::new(conn)), agents, outbox_bytes })
    }

    fn with_ship<R>(&self, name: &str, f: impl FnOnce(&mut Ship) -> Result<R, Error>) -> Result<R, Error> {
        let name = canonical_ship(name)?;
        let slot = self.slot(&name)?;
        let result = {
            let mut guard = lock(&slot);
            if guard.ship.is_none() {
                self.reserve(&name, &slot);
                match self.wake(&name) {
                    Ok(ship) => guard.ship = Some(ship),
                    Err(e) => {
                        lock(&self.awake).remove(&name);
                        self.awake_changed.notify_one();
                        return Err(e);
                    }
                }
            }
            let result = f(guard.ship.as_mut().expect("woken above"));
            // Stamped after the work, so a long event does not make its ship look long idle.
            guard.last_used = Instant::now();
            result
        };
        // This ship is idle again, so a thread waiting for a place can now evict it.
        self.awake_changed.notify_one();
        result
    }

    /// Claim a place among the awake ships before opening `name`, closing the least recently
    /// used idle ship if the runtime is full. Waits if every awake ship is mid-event.
    fn reserve(&self, name: &str, slot: &SlotRef) {
        loop {
            let mut awake = lock(&self.awake);
            if awake.len() < self.cfg.max_awake {
                awake.insert(name.to_string(), slot.clone());
                return;
            }
            let idle = awake
                .iter()
                .filter_map(|(other, other_slot)| {
                    let guard = other_slot.try_lock().ok()?;
                    guard.ship.as_ref()?;
                    Some((guard.last_used, other.clone(), other_slot.clone()))
                })
                .min_by_key(|(last_used, _, _)| *last_used);
            let Some((_, victim_name, victim)) = idle else {
                let _ = self.awake_changed.wait_timeout(awake, Duration::from_millis(2));
                continue;
            };
            let Ok(mut guard) = victim.try_lock() else { continue };
            let Some(ship) = guard.ship.take() else { continue };
            awake.remove(&victim_name);
            awake.insert(name.to_string(), slot.clone());
            drop(awake);
            // Still holding the victim's lock: it cannot be reopened until its file is closed.
            drop(ship);
            return;
        }
    }
}
