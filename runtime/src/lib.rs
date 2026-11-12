//! A runtime that holds many ships. Each ship is one SQLite file, a kernel module that decides
//! what may run, and the WASM agents installed on it. A ship handles one event at a time, and
//! each event is one transaction.

mod host;
pub mod net;
pub mod server;
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

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ship_proto::admin_request::Op;
use ship_proto::{AdminRequest, CheckpointBody, Install, Message, Source};
use wasmtime::{Engine, InstancePre, Linker, Module};

pub use ship_proto::{Device, EntryBody, Manifest, Provide, SignedCheckpoint, SignedEntry, Use};

use host::Ctx;
use ship::Ship;

/// How often the watchdog advances the clock that event deadlines are measured against.
pub(crate) const EPOCH_TICK_MILLIS: u64 = 10;

/// Native stack each WASM instance may use.
pub(crate) const WASM_STACK_BYTES: usize = 512 << 10;

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
    /// Compute budget for each decision the kernel makes, separate from the agent's.
    pub kernel_fuel: u64,
    /// Wall-clock cap on one event. Fuel cannot see how large a bulk memory operation is.
    pub max_event_millis: u64,
    pub max_memory_bytes: usize,
    /// How large a ship's file may grow. A write that would pass it is rejected, like any other
    /// event that breaks a limit.
    pub max_ship_bytes: u64,
    pub max_module_bytes: usize,
    /// Largest ship file `import_ship` will read, and the longest it will spend reading one.
    pub max_import_bytes: u64,
    pub max_import_millis: u64,
    pub max_table_elements: usize,
    pub max_event_bytes: usize,
    pub max_reply_bytes: usize,
    /// Undelivered outgoing messages a ship may hold, counting each as its payload plus a fixed
    /// overhead; events that would exceed it are rejected.
    pub max_outbox_bytes: u64,
    /// Commands between agents that may be waiting to run, counted the same way.
    pub max_inbox_bytes: u64,
    /// Commands that may be waiting to go to any one other ship, counted the same way. A
    /// send that would pass it is rejected. Each other ship has its own allowance, so one
    /// that cannot be reached does not stop commands to the rest.
    pub max_peer_out_bytes: u64,
    /// How many other ships a ship may exchange commands with.
    pub max_peers: usize,
    /// How many commands a ship may have sent to any one other ship without yet having a
    /// receipt for them. A send that would pass it is rejected. The same number bounds the
    /// other direction: a ship takes no more commands from another while it owes it this
    /// many receipts, counting commands still queued, so a ship that will not take its
    /// receipts cannot make this one hold them without end.
    pub max_unanswered: usize,
    /// Entries one log may hold, counted the same way. When an append has no room, the entries
    /// that log's checkpoint already covers are dropped to make some. Each log has its own
    /// limit, so one log can never use up another's room. A log's checkpoint is not counted:
    /// there is at most one, of at most `max_checkpoint_bytes`. What bounds all of a ship's
    /// logs together is `max_logs` and, in the end, `max_ship_bytes`.
    pub max_log_bytes: u64,
    /// How many logs a ship may have.
    pub max_logs: usize,
    /// A log's publisher is asked for a checkpoint once the entries added since the last one
    /// outweigh both this and that checkpoint itself.
    pub checkpoint_min_bytes: u64,
    /// The largest state a checkpoint may carry.
    pub max_checkpoint_bytes: usize,
    /// Queued commands run straight after the event that caused them, up to this many. The rest
    /// wait for `run_pending`, so agents that keep sending to each other cannot hold a ship.
    pub max_queued_per_deliver: usize,
    /// Ships kept open for events at once. Beyond this the least recently used idle ship is put
    /// to sleep first. Creating, importing, and exporting ships open their own files outside
    /// this limit.
    pub max_awake: usize,
    pub audit_rows: u64,
    /// How many devices may be signed in to a ship at once, and how many one-time sign-in codes
    /// may be waiting to be used.
    pub max_devices: usize,
    pub max_signin_codes: usize,
    /// After this many wrong sign-in codes in a row, nothing can sign in to the ship for
    /// `signin_lock_millis`. Devices that are already signed in are not affected.
    pub signin_max_failures: u32,
    pub signin_lock_millis: u64,
    pub durability: Durability,
    pub limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            fuel_per_event: 100_000_000,
            kernel_fuel: 50_000_000,
            max_event_millis: 5_000,
            max_memory_bytes: 64 << 20,
            max_ship_bytes: 1 << 30,
            max_module_bytes: 16 << 20,
            max_import_bytes: 256 << 20,
            max_import_millis: 60_000,
            max_table_elements: 100_000,
            max_event_bytes: 1 << 20,
            max_reply_bytes: 1 << 20,
            max_outbox_bytes: 64 << 20,
            max_inbox_bytes: 64 << 20,
            max_peer_out_bytes: 16 << 20,
            max_peers: 4096,
            max_unanswered: 4096,
            max_log_bytes: 64 << 20,
            max_logs: 16_384,
            checkpoint_min_bytes: 64 << 10,
            max_checkpoint_bytes: 1 << 20,
            max_queued_per_deliver: 64,
            max_awake: 64,
            audit_rows: 10_000,
            max_devices: 64,
            max_signin_codes: 32,
            signin_max_failures: 5,
            signin_lock_millis: 60_000,
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
    /// Commands this event sent to other agents on the ship.
    pub queued: u32,
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
    /// The kernel refused the call, or a read handler tried to change something.
    Denied(String),
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
    /// The kernel would not install the agent.
    InstallRefused(String),
    /// Another runtime already has this data directory open.
    DataDirInUse,
    /// The entries asked for have been dropped: the log now starts after this entry number. The
    /// reader should fetch the log's checkpoint and carry on from there.
    LogTrimmed(u64),
    /// The sign-in code was not one this ship accepts: wrong, already used, or out of date.
    SignInRefused,
    /// Too many wrong sign-in codes. Nothing can sign in for this many more milliseconds.
    SignInLocked(u64),
    /// The token is not one of this ship's signed-in devices.
    NotSignedIn,
    /// The ship already has as many devices or waiting sign-in codes as it may.
    TooMany(&'static str),
    /// Another ship's count of the commands between it and this one cannot be squared with
    /// this ship's own. One of the two has gone back to an earlier state, such as a restored
    /// backup. Nothing more is sent to it until that is sorted out, since carrying on could
    /// lose commands or deliver them twice.
    OutOfStep(String),
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
            Error::InstallRefused(why) => write!(f, "install refused: {why}"),
            Error::DataDirInUse => write!(f, "another runtime is using this data directory"),
            Error::LogTrimmed(base) => write!(f, "the log no longer holds entries up to {base}; fetch its checkpoint"),
            Error::SignInRefused => write!(f, "that sign-in code is not accepted"),
            Error::SignInLocked(millis) => write!(f, "too many wrong sign-in codes; try again in {} seconds", millis.div_ceil(1000)),
            Error::NotSignedIn => write!(f, "not signed in"),
            Error::TooMany(what) => write!(f, "this ship already has as many {what} as it may"),
            Error::OutOfStep(peer) => write!(f, "this ship and {peer} disagree about the commands between them"),
            Error::Rejected(Rejection::OutOfFuel) => write!(f, "event rejected: compute budget exhausted"),
            Error::Rejected(Rejection::Timeout) => write!(f, "event rejected: ran too long"),
            Error::Rejected(Rejection::Denied(why)) => write!(f, "event rejected: not permitted: {why}"),
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
    keys_dir: PathBuf,
    tmp_dir: PathBuf,
    modules: Mutex<HashMap<String, Arc<AgentModule>>>,
    slots: Mutex<HashMap<String, SlotRef>>,
    /// Ships that are open or being opened. Its size never exceeds `max_awake`.
    ///
    /// Lock order: a slot lock may be held while taking this lock. While holding this lock,
    /// slot locks are only ever tried, never waited on.
    awake: Mutex<HashMap<String, SlotRef>>,
    /// Held while a ship's file and key are put in place together, and while a key is read, so
    /// that nothing ever sees one without the matching other. Only `identities` is locked
    /// under it.
    lifecycle: Mutex<()>,
    /// The signing keys of the ships this runtime holds, kept in memory once the network has
    /// started. The network asks on every connection and every request, from places that must
    /// not wait on a disk. A ship's key does not change while the runtime runs: nothing here
    /// replaces one, and the files of a running runtime must not be swapped underneath it.
    identities: std::sync::RwLock<Option<HashMap<String, Arc<SigningKey>>>>,
    awake_changed: Condvar,
    /// For each ship, how many events have added to its logs since the runtime started. A
    /// reader waiting for new entries sleeps on `logs_changed` until this moves. Nothing else
    /// is locked while this is held.
    log_growth: Mutex<HashMap<String, u64>>,
    logs_changed: Condvar,
    /// Called with a ship's name when an event on it has queued commands for other ships.
    /// The network sets it, to learn there is something to send. It must not block.
    outbound_hook: std::sync::RwLock<Option<OutboundHook>>,
    /// Whether a network is running for this runtime. There is one at most: it alone carries
    /// what the ships here have waiting for other ships.
    networked: AtomicBool,
}

/// Called with a ship's name when it has something waiting to go to other ships. The second
/// argument says the ship may also have events queued that nothing is about to run.
type OutboundHook = Arc<dyn Fn(&str, bool) + Send + Sync>;

pub struct Runtime {
    inner: Arc<Inner>,
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

fn require_exports(module: &AgentModule, names: &[&str]) -> Result<(), Error> {
    for name in names {
        if module.pre.module().get_export(name).and_then(|export| export.func().cloned()).is_none() {
            return Err(Error::BadModule(format!("missing exported function `{name}`")));
        }
    }
    Ok(())
}

fn check_hash(hash: &str) -> Result<(), Error> {
    let ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok { Ok(()) } else { Err(Error::BadModule(format!("{hash:?} is not a module hash"))) }
}

/// The runtime's own rules for what may be called, whatever a ship's kernel says. The name
/// `kernel` is where the kernel keeps its keys, so nothing else may ever run under it.
pub(crate) fn check_target(agent: &str, interface: &str) -> Result<(), Error> {
    check_agent_name(agent)?;
    if agent == "kernel" || !store::interface_ok(interface) {
        return Err(Error::InvalidName(format!("{agent} {interface}")));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The labels that go in front of a message before it is signed, one per kind of message, so
/// that a signature made for one kind can never be passed off as another.
pub(crate) const ENTRY_DOMAIN: &[u8] = b"ship.v1.entry\n";
pub(crate) const CHECKPOINT_DOMAIN: &[u8] = b"ship.v1.checkpoint\n";

/// The bytes a signature covers: the label for the kind of message, then the message.
pub(crate) fn signed_bytes(domain: &[u8], body: &[u8]) -> Vec<u8> {
    [domain, body].concat()
}

/// Checks a run of log entries one at a time: each must be signed by the ship's key, belong to
/// the expected log, and follow directly on from the one before.
pub(crate) struct ChainCheck<'a> {
    key: &'a VerifyingKey,
    ship: &'a str,
    pub agent: String,
    pub log: String,
    last: Last,
}

/// How far a chain check has got.
enum Last {
    /// Nothing accepted yet, so the next must be entry 1.
    Start,
    /// The entry already accepted, as (number, hash).
    Entry(u64, [u8; 32]),
    /// The entries up to this number have been dropped, so the next one's link back to them
    /// cannot be checked. Its signature and number still are.
    Dropped(u64),
}

impl<'a> ChainCheck<'a> {
    /// `after` is the last entry the caller already trusts, or `None` to start from entry 1.
    pub fn new(key: &'a VerifyingKey, ship: &'a str, agent: &str, log: &str, after: Option<(u64, [u8; 32])>) -> Self {
        let last = after.map_or(Last::Start, |(seq, hash)| Last::Entry(seq, hash));
        ChainCheck { key, ship, agent: agent.to_string(), log: log.to_string(), last }
    }

    /// For a log whose entries up to `base` have been dropped: the next must be `base + 1`.
    pub fn resuming(key: &'a VerifyingKey, ship: &'a str, agent: &str, log: &str, base: u64) -> Self {
        ChainCheck { key, ship, agent: agent.to_string(), log: log.to_string(), last: Last::Dropped(base) }
    }

    /// The last entry accepted, if any has been.
    fn position(&self) -> Option<Position> {
        match self.last {
            Last::Entry(seq, hash) => Some((seq, hash)),
            Last::Start | Last::Dropped(_) => None,
        }
    }

    /// Accept the next entry, returning its number, its hash, and the size of its payload.
    pub fn accept(&mut self, body: &[u8], signature: &[u8]) -> Result<(u64, [u8; 32], usize), String> {
        let signature = Signature::from_slice(signature).map_err(|_| "an entry's signature is malformed")?;
        // Checked over the bytes as stored, never over a re-encoding of them.
        self.key.verify(&signed_bytes(ENTRY_DOMAIN, body), &signature).map_err(|_| "an entry is not signed by this ship's key")?;
        let entry = EntryBody::decode(body).map_err(|_| "an entry cannot be decoded")?;
        if entry.ship != self.ship || entry.agent != self.agent || entry.log != self.log {
            return Err("an entry belongs to a different log".into());
        }
        let follows_on = match &self.last {
            Last::Entry(seq, hash) => seq.checked_add(1) == Some(entry.seq) && entry.prev == hash,
            Last::Start => entry.seq == 1 && entry.prev.is_empty(),
            Last::Dropped(base) => base.checked_add(1) == Some(entry.seq) && entry.prev.len() == 32,
        };
        if !follows_on {
            return Err(format!("entry {} does not follow on from the one before it", entry.seq));
        }
        let hash = sha256(body);
        self.last = Last::Entry(entry.seq, hash);
        Ok((entry.seq, hash, entry.payload.len()))
    }
}

/// Where a reader has got to in a log: the number and hash of the last entry it accepted.
pub type Position = (u64, [u8; 32]);

/// Check entries read from a ship's log, as a client or another ship would. Each must be signed
/// by `public_key`, belong to that log, and carry on directly from `after`: the last entry the
/// reader already accepted, or `None` if it has none and these must start at entry 1. Returns
/// the reader's new position.
///
/// This proves the entries are genuine and that none is missing between them. It cannot show
/// that these are all the entries there are; for that the reader needs the log's current end
/// from somewhere it trusts.
pub fn verify_log(
    public_key: &[u8; 32],
    ship: &str,
    agent: &str,
    log: &str,
    after: Option<Position>,
    entries: &[SignedEntry],
) -> Result<Option<Position>, String> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| "not a valid public key")?;
    let ship = canonical_ship(ship).map_err(|e| e.to_string())?;
    let mut chain = ChainCheck::new(&key, &ship, agent, log, after);
    entries.iter().try_for_each(|entry| chain.accept(&entry.body, &entry.signature).map(drop))?;
    Ok(chain.position())
}

/// Check a checkpoint read from a ship's log, as a client or another ship would. It must be
/// signed by `public_key` and belong to that log. Returns the position it stands for and the
/// state as of that position. The reader replaces what it holds with the state, and carries on
/// by asking for the entries after that position and checking them with `verify_log`.
///
/// Like `verify_log`, this shows the checkpoint is genuine, not that it is the newest one.
pub fn verify_checkpoint(
    public_key: &[u8; 32],
    ship: &str,
    agent: &str,
    log: &str,
    checkpoint: &SignedCheckpoint,
) -> Result<(Position, Vec<u8>), String> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| "not a valid public key")?;
    let ship = canonical_ship(ship).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&checkpoint.signature).map_err(|_| "the checkpoint's signature is malformed")?;
    // Checked over the bytes as stored, never over a re-encoding of them.
    key.verify(&signed_bytes(CHECKPOINT_DOMAIN, &checkpoint.body), &signature)
        .map_err(|_| "the checkpoint is not signed by this ship's key")?;
    let body = CheckpointBody::decode(&*checkpoint.body).map_err(|_| "the checkpoint cannot be decoded")?;
    if body.ship != ship || body.agent != agent || body.log != log {
        return Err("the checkpoint belongs to a different log".into());
    }
    let hash = <[u8; 32]>::try_from(body.hash).map_err(|_| "the checkpoint names no entry")?;
    if body.seq == 0 {
        return Err("the checkpoint names no entry".into());
    }
    Ok(((body.seq, hash), body.state))
}

/// Labels for the two kinds of secret a ship hashes, so that a device's token can never be
/// offered as a sign-in code or the other way round.
const SIGNIN_DOMAIN: &[u8] = b"ship.v1.signin\n";
const DEVICE_DOMAIN: &[u8] = b"ship.v1.device\n";

/// What the ship stores in place of a secret. The secrets are long and random, so a plain
/// hash is enough: there is nothing to guess that a slow hash would slow down.
fn secret_hash(domain: &[u8], secret: &str) -> [u8; 32] {
    sha256(&[domain, secret.as_bytes()].concat())
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An access code as its owner sees it: 100 random bits as twenty letters and digits in four
/// groups, from an alphabet with no pairs that look alike (no i, l, o, or u).
fn access_code(random: &[u8; 13]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let bits = random.iter().fold(0u128, |all, byte| (all << 8) | *byte as u128);
    let letters: Vec<u8> = (0..20).map(|i| ALPHABET[((bits >> (99 - 5 * (i + 1) + 1)) & 31) as usize]).collect();
    letters.chunks(5).map(|group| String::from_utf8_lossy(group).into_owned()).collect::<Vec<_>>().join("-")
}

/// A sign-in code as typed, without the dashes, spaces, and capitals people add.
fn normal_code(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace() && *c != '-').flat_map(char::to_lowercase).collect()
}

/// A device's label, made safe to store and show: no control characters, not too long, not empty.
fn clean_label(label: &str) -> String {
    let mut clean: String = label.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string();
    while clean.len() > store::MAX_LABEL_BYTES {
        clean.pop();
    }
    if clean.is_empty() { "device".to_string() } else { clean }
}

/// Read a ship's signing key: 32 bytes in a regular file.
fn load_key(path: &Path) -> Result<SigningKey, Error> {
    let bad = || Error::BadShipFile(format!("{}: not a ship key", path.display()));
    let mut seed = Vec::new();
    open_regular(path).map_err(|_| bad())?.take(33).read_to_end(&mut seed)?;
    Ok(SigningKey::from_bytes(&<[u8; 32]>::try_from(seed).map_err(|_| bad())?))
}

/// Put a key at `path`, replacing whatever is there. It is written to a new file that only its
/// owner can read and then renamed into place, so the key is never in a file with looser
/// permissions, is never half written under its real name, and an existing symlink at `path`
/// is replaced rather than followed.
fn write_key(path: &Path, key: &SigningKey) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let scratch = Scratch::new(dir);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&scratch.0)?;
    file.write_all(&key.to_bytes())?;
    file.sync_all()?;
    fs::rename(&scratch.0, path)?;
    sync_dir(dir)
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
        let keys_dir = data_dir.join("keys");
        for dir in [&ships_dir, &blobs_dir, &keys_dir, &tmp_dir] {
            fs::create_dir_all(dir)?;
        }
        cfg.max_awake = cfg.max_awake.max(1);
        let dir_lock = lock_data_dir(data_dir)?;

        let mut wasm_cfg = wasmtime::Config::new();
        wasm_cfg.consume_fuel(true);
        wasm_cfg.epoch_interruption(true);
        wasm_cfg.max_wasm_stack(WASM_STACK_BYTES);
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
            inner: Arc::new(Inner {
                engine,
                cfg,
                linker,
                ships_dir,
                blobs_dir,
                keys_dir,
                tmp_dir,
                modules: Mutex::new(HashMap::new()),
                slots: Mutex::new(HashMap::new()),
                awake: Mutex::new(HashMap::new()),
                lifecycle: Mutex::new(()),
                identities: std::sync::RwLock::new(None),
                awake_changed: Condvar::new(),
                log_growth: Mutex::new(HashMap::new()),
                logs_changed: Condvar::new(),
                outbound_hook: std::sync::RwLock::new(None),
                networked: AtomicBool::new(false),
            }),
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

    /// Create a ship whose policy is the kernel module with the given hash.
    pub fn create_ship(&self, name: &str, kernel_hash: &str) -> Result<(), Error> {
        let name = canonical_ship(name)?;
        self.inner.kernel(kernel_hash)?;
        if self.inner.ship_path(&name).exists() {
            return Err(Error::ShipExists(name));
        }
        // The ship's signing key, a stand-in for its Urbit ID networking key. It lives beside the
        // ship file, not in it.
        let seed = random_bytes::<32>()?;
        // Built under a private name and then published, so a failure part way through cannot
        // leave a broken file sitting on the ship's name for ever.
        let fresh = Scratch::new(&self.inner.tmp_dir);
        store::create(&fresh.0, &name, kernel_hash, self.inner.cfg.max_ship_bytes)?;
        self.inner.publish(&name, &fresh.0, &SigningKey::from_bytes(&seed))
    }

    /// Install an agent, or replace it. The manifest says which interfaces it offers and which
    /// it may use; passing it here is the owner's approval. The ship's kernel has the final say.
    pub fn install(&self, ship: &str, agent: &str, module_hash: &str, manifest: &Manifest) -> Result<(), Error> {
        check_agent_name(agent)?;
        let module = self.inner.module(module_hash)?;
        require_exports(&module, &["handle"])?;
        let install = Install { agent: agent.into(), module: module_hash.into(), manifest: Some(manifest.clone()) };
        let request = AdminRequest { op: Some(Op::Install(install)) };
        self.inner.with_ship(ship, |ship| {
            let reply = ship.admin(&self.inner, &request, true)?;
            if reply.ok { Ok(()) } else { Err(Error::InstallRefused(reply.error)) }
        })
    }

    /// Deliver a command from the ship's owner, then run events that are waiting on the ship:
    /// the commands it caused agents to send each other, and anything left from earlier calls.
    /// Events for the same ship run one at a time; different ships run in parallel.
    ///
    /// `Error::Rejected` means this command changed nothing. It does not mean nothing ran:
    /// waiting events are run after a rejected command too, because one of them may be the
    /// checkpoint that makes room for what was just refused.
    ///
    /// A command over the size limit is rejected without running anything, and only its first
    /// bytes are kept in the audit log.
    pub fn deliver(&self, ship: &str, agent: &str, event: &[u8]) -> Result<Outcome, Error> {
        check_agent_name(agent)?;
        let cfg = &self.inner.cfg;
        self.inner.with_ship(ship, |ship| {
            if event.len() > cfg.max_event_bytes {
                let why = format!("event is {} bytes, limit is {}", event.len(), cfg.max_event_bytes);
                // Never more than a normal event may hold, or this ship's own export would be
                // refused on import.
                let kept = &event[..OVERSIZED_AUDIT_BYTES.min(cfg.max_event_bytes)];
                store::audit_failure(&lock(&ship.conn), agent, kept, cfg.audit_rows);
                return Err(Error::Rejected(Rejection::Limit(why)));
            }
            let source = Source { owner: true, agent: String::new(), ship: String::new() };
            let outcome = ship.command(&self.inner, &source, agent, "", event);
            // The owner's command has committed or been rejected: either way it is settled, so
            // a problem while running what is queued must not change what is reported for it.
            // A rejected command queues nothing itself, but the runtime may have queued a
            // checkpoint request on its account, which is what lets a full log recover.
            // Whatever is left runs on a later call.
            if matches!(outcome, Ok(_) | Err(Error::Rejected(_))) {
                for _ in 0..cfg.max_queued_per_deliver {
                    if !matches!(ship.run_queued(&self.inner), Ok(true)) {
                        break;
                    }
                }
            }
            outcome
        })
    }

    /// How many queued events are waiting to run on a ship.
    pub fn pending(&self, ship: &str) -> Result<usize, Error> {
        self.inner.with_ship(ship, |ship| store::inbox_len(&lock(&ship.conn)))
    }

    /// The number of the newest event queued on a ship, or 0 if none is.
    pub(crate) fn inbox_newest(&self, ship: &str) -> Result<i64, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::inbox_newest(&lock(&ship.conn))?))
    }

    /// Run up to `max` queued events, but none numbered after `through`. Returns how many
    /// ran, and whether any numbered up to `through` are still queued.
    pub(crate) fn run_pending_through(&self, ship: &str, max: usize, through: i64) -> Result<(usize, bool), Error> {
        self.inner.with_ship(ship, |ship| {
            let mut ran = 0;
            loop {
                let due = store::inbox_oldest(&lock(&ship.conn))?.is_some_and(|oldest| oldest <= through);
                if !due || ran >= max {
                    return Ok((ran, due));
                }
                if !ship.run_queued(&self.inner)? {
                    return Ok((ran, false));
                }
                ran += 1;
            }
        })
    }

    /// Run up to `max` queued commands. Returns how many ran.
    pub fn run_pending(&self, ship: &str, max: usize) -> Result<usize, Error> {
        self.inner.with_ship(ship, |ship| {
            let mut ran = 0;
            while ran < max && ship.run_queued(&self.inner)? {
                ran += 1;
            }
            Ok(ran)
        })
    }

    /// Read from an agent on the owner's behalf. A read cannot change anything.
    pub fn read(&self, ship: &str, agent: &str, interface: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
        check_agent_name(agent)?;
        if request.len() > self.inner.cfg.max_event_bytes {
            return Err(Error::Rejected(Rejection::Limit("read request is too large".into())));
        }
        self.inner.with_ship(ship, |ship| ship.read(&self.inner, agent, interface, request))
    }

    /// Take the oldest committed outgoing messages, up to `max_bytes` in total (always at least
    /// one if any is pending). A network driver would call this.
    pub fn drain_outbox(&self, ship: &str, max_bytes: usize) -> Result<Vec<Effect>, Error> {
        self.inner.with_ship(ship, |ship| {
            let effects = store::outbox_drain(&lock(&ship.conn), 1024, max_bytes)?;
            let drained: u64 = effects.iter().map(|e| e.payload.len() as u64 + store::MESSAGE_OVERHEAD).sum();
            ship.outbox_bytes = ship.outbox_bytes.saturating_sub(drained);
            Ok(effects)
        })
    }

    /// Entries of a ship's log after number `after`, oldest first. `max_bytes` limits the total
    /// size of the entries' bodies, not counting their 64-byte signatures, and at least one
    /// entry is always returned if any exist. It does not run the agent. Check what comes back
    /// with `verify_log`.
    ///
    /// Old entries of a log are dropped once a checkpoint can stand in for them. If the entry
    /// straight after `after` is gone, this returns `Error::LogTrimmed`, never a run of entries
    /// with a gap before it; the reader then takes `log_checkpoint` and carries on from there.
    ///
    /// This is the owner's view and checks no permissions. Anything that serves logs to other
    /// people has to decide who may read which log before calling it.
    pub fn log_entries(&self, ship: &str, agent: &str, log: &str, after: u64, max_bytes: usize) -> Result<Vec<SignedEntry>, Error> {
        check_target(agent, log)?;
        self.inner.with_ship(ship, |ship| {
            let conn = lock(&ship.conn);
            let base = store::log_base(&conn, agent, log)?;
            if after < base {
                return Err(Error::LogTrimmed(base));
            }
            let stored = store::log_range(&conn, agent, log, after, 1024, max_bytes)?;
            Ok(stored.into_iter().map(|entry| SignedEntry { body: entry.body, signature: entry.signature }).collect())
        })
    }

    /// A log's newest checkpoint, if it has one: the state behind the log as of one of its
    /// entries, signed by the ship. Check it with `verify_checkpoint`. Like `log_entries`, this
    /// is the owner's view and checks no permissions.
    pub fn log_checkpoint(&self, ship: &str, agent: &str, log: &str) -> Result<Option<SignedCheckpoint>, Error> {
        check_target(agent, log)?;
        self.inner.with_ship(ship, |ship| {
            let stored = store::checkpoint(&lock(&ship.conn), agent, log)?;
            Ok(stored.map(|stored| SignedCheckpoint { body: stored.body, signature: stored.signature }))
        })
    }

    /// How far a follower has got in a log: the number of the last entry it has taken, or
    /// `None` if it does not follow that log.
    pub fn log_position(&self, ship: &str, follower: &str, agent: &str, log: &str) -> Result<Option<u64>, Error> {
        check_agent_name(follower)?;
        check_target(agent, log)?;
        self.inner.with_ship(ship, |ship| Ok(store::cursor(&lock(&ship.conn), follower, agent, log)?))
    }

    /// The public half of a ship's signing key, for checking its log entries.
    pub fn public_key(&self, ship: &str) -> Result<[u8; 32], Error> {
        let name = canonical_ship(ship)?;
        let _together = lock(&self.inner.lifecycle);
        if !self.inner.ship_path(&name).exists() {
            return Err(Error::UnknownShip(name));
        }
        Ok(load_key(&self.inner.key_path(&name))?.verifying_key().to_bytes())
    }

    /// A ship's signing key, for proving to other ships that this runtime speaks for it. It
    /// never leaves the runtime.
    pub(crate) fn signing_key(&self, ship: &str) -> Result<Arc<SigningKey>, Error> {
        let name = canonical_ship(ship)?;
        // Memory only. This is called from inside connections being made, where waiting on a
        // disk or on another thread's lock would hold up the whole network.
        let identities = self.inner.identities.read().unwrap_or_else(PoisonError::into_inner);
        identities.as_ref().and_then(|held| held.get(&name).cloned()).ok_or(Error::UnknownShip(name))
    }

    /// Read every ship's signing key into memory, if that has not been done. The network calls
    /// this once as it starts, and fails to start if the keys cannot be read. From then on new
    /// ships are added as they are made. A ship whose key file cannot be read is left out: it
    /// cannot speak on the network until the runtime is restarted with the file repaired.
    pub(crate) fn load_identities(&self) -> Result<(), Error> {
        // Nothing can be published while this runs.
        let _together = lock(&self.inner.lifecycle);
        let mut identities = self.inner.identities.write().unwrap_or_else(PoisonError::into_inner);
        if identities.is_some() {
            return Ok(());
        }
        let mut held = HashMap::new();
        for entry in fs::read_dir(&self.inner.ships_dir)? {
            let file = entry?.file_name();
            let Some(ship) = file.to_str().and_then(|file| file.strip_suffix(".ship")).and_then(|ship| canonical_ship(ship).ok()) else {
                continue;
            };
            if let Ok(key) = load_key(&self.inner.key_path(&ship)) {
                held.insert(ship, Arc::new(key));
            }
        }
        *identities = Some(held);
        Ok(())
    }

    /// Where a ship's log currently ends: the number and hash of its newest entry, or `None` if
    /// it has no entries. A reader compares this with where its own copy ends to tell whether
    /// it has everything.
    pub fn log_head(&self, ship: &str, agent: &str, log: &str) -> Result<Option<Position>, Error> {
        check_target(agent, log)?;
        self.inner.with_ship(ship, |ship| {
            let (head, hash) = store::log_head(&lock(&ship.conn), agent, log)?;
            Ok(<[u8; 32]>::try_from(hash).ok().filter(|_| head > 0).map(|hash| (head, hash)))
        })
    }

    /// Where a log ends, waiting up to `timeout` for it to grow past entry `after`. Returns as
    /// soon as it has, or with whatever its end is when the time is up. A client uses this to
    /// hear of new entries without asking over and over. It does not keep the ship awake.
    pub fn wait_log(&self, ship: &str, agent: &str, log: &str, after: u64, timeout: Duration) -> Result<Option<Position>, Error> {
        let name = canonical_ship(ship)?;
        let deadline = Instant::now() + timeout;
        loop {
            // Read before looking at the log, so growth between the look and the sleep is seen.
            let seen = lock(&self.inner.log_growth).get(&name).copied().unwrap_or(0);
            let head = self.log_head(ship, agent, log)?;
            if head.is_some_and(|(seq, _)| seq > after) || Instant::now() >= deadline {
                return Ok(head);
            }
            let mut growth = lock(&self.inner.log_growth);
            while growth.get(&name).copied().unwrap_or(0) == seen {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                growth = self.inner.logs_changed.wait_timeout(growth, left).unwrap_or_else(PoisonError::into_inner).0;
            }
        }
    }

    /// Make a one-time sign-in code for a ship, good for a single use within `valid_for`. Being
    /// able to call this is what approves the device that ends up using the code: it is for
    /// whoever controls the machine the ship runs on, such as a hosting service after the owner
    /// has logged in to it, or the owner at the command line. The code is returned this once;
    /// the ship keeps only a hash of it.
    pub fn new_signin_code(&self, ship: &str, valid_for: Duration) -> Result<String, Error> {
        let code = hex(&random_bytes::<16>()?);
        let (hash, max) = (secret_hash(SIGNIN_DOMAIN, &code), self.inner.cfg.max_signin_codes);
        self.inner.with_ship(ship, |ship| {
            ship.transact(|conn| {
                let now = store::now_ms();
                store::codes_purge(conn, now)?;
                if store::code_count(conn)? >= max {
                    return Err(Error::TooMany("sign-in codes waiting"));
                }
                Ok(store::code_add(conn, &hash, now.saturating_add(valid_for.as_millis() as u64))?)
            })
        })?;
        Ok(code)
    }

    /// Give a ship a new reusable access code, replacing any it had, and return it this once.
    /// The owner keeps it somewhere safe and types it into the ship's sign-in page from any
    /// new device. Changing it stops the old one from signing anything new in; devices that
    /// are already signed in stay signed in.
    pub fn set_access_code(&self, ship: &str) -> Result<String, Error> {
        let code = access_code(&random_bytes::<13>()?);
        let hash = secret_hash(SIGNIN_DOMAIN, &normal_code(&code));
        self.inner.with_ship(ship, |ship| ship.transact(|conn| Ok(store::access_code_set(conn, Some(&hash))?)))?;
        Ok(code)
    }

    /// Leave a ship with no reusable access code. One-time codes still work.
    pub fn clear_access_code(&self, ship: &str) -> Result<(), Error> {
        self.inner.with_ship(ship, |ship| ship.transact(|conn| Ok(store::access_code_set(conn, None)?)))
    }

    /// Sign a device in: trade a sign-in code for a token of the device's own. The token is
    /// returned this once and the ship keeps only a hash of it. `label` is what the device is
    /// called in the owner's list.
    ///
    /// A wrong code is `Error::SignInRefused`. After several in a row the ship refuses every
    /// sign-in for a while with `Error::SignInLocked`, good codes included, so that codes
    /// cannot be guessed at speed.
    pub fn sign_in(&self, ship: &str, code: &str, label: &str) -> Result<(String, Device), Error> {
        self.sign_in_with(ship, code, label, true)
    }

    /// Sign a device in with a one-time code only. The ship's reusable access code is refused
    /// here, as a wrong code would be. This is for sign-in links, where the code is part of an
    /// address and may be kept in histories and logs. A one-time code found there later has
    /// been used or has run out; an access code would still work. Until it is used a one-time
    /// code is as sensitive as any other, and a link is only as private as the way it is sent.
    pub fn sign_in_once(&self, ship: &str, code: &str, label: &str) -> Result<(String, Device), Error> {
        self.sign_in_with(ship, code, label, false)
    }

    fn sign_in_with(&self, ship: &str, code: &str, label: &str, access_code_ok: bool) -> Result<(String, Device), Error> {
        let cfg = &self.inner.cfg;
        let (code_hash, label) = (secret_hash(SIGNIN_DOMAIN, &normal_code(code)), clean_label(label));
        let token = hex(&random_bytes::<32>()?);
        let token_hash = secret_hash(DEVICE_DOMAIN, &token);
        let outcome = self.inner.with_ship(ship, |ship| {
            // What a wrong code changes has to be kept, so it is this transaction's result,
            // not an error that would undo it.
            ship.transact(|conn| -> Result<Result<Device, Error>, Error> {
                let now = store::now_ms();
                let locked_until = store::signin_locked_until(conn)?;
                if now < locked_until {
                    return Ok(Err(Error::SignInLocked(locked_until - now)));
                }
                store::codes_purge(conn, now)?;
                let good = match store::code_find(conn, &code_hash, now)? {
                    Some(reusable) => access_code_ok || !reusable,
                    None => false,
                };
                if !good {
                    store::signin_failed(conn, now, cfg.signin_max_failures, cfg.signin_lock_millis)?;
                    return Ok(Err(Error::SignInRefused));
                }
                store::signin_succeeded(conn)?;
                // Only someone holding a good code is told the ship is full of devices, and the
                // code is not used up by finding that out.
                if store::device_count(conn)? >= cfg.max_devices {
                    return Ok(Err(Error::TooMany("devices signed in")));
                }
                store::code_use(conn, &code_hash)?;
                let id = store::device_add(conn, &token_hash, &label, now)?;
                Ok(Ok(Device { id, label: label.clone(), created_ms: now }))
            })
        })?;
        outcome.map(|device| (token, device))
    }

    /// Which device a token belongs to, or `Error::NotSignedIn`. Whoever holds a device's
    /// token acts as the ship's owner.
    pub fn authenticate(&self, ship: &str, token: &str) -> Result<Device, Error> {
        let hash = secret_hash(DEVICE_DOMAIN, token);
        self.inner
            .with_ship(ship, |ship| Ok(store::device_by_token(&lock(&ship.conn), &hash)?))?
            .ok_or(Error::NotSignedIn)
    }

    /// The devices signed in to a ship, oldest first.
    pub fn devices(&self, ship: &str) -> Result<Vec<Device>, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::devices(&lock(&ship.conn))?))
    }

    /// Sign one device out, so its token stops working. Returns whether there was such a device.
    pub fn revoke_device(&self, ship: &str, id: u64) -> Result<bool, Error> {
        self.inner.with_ship(ship, |ship| ship.transact(|conn| Ok(store::device_revoke(conn, id)?)))
    }

    /// How many messages are waiting to go from a ship to other ships: commands its agents
    /// have sent, and receipts for commands other ships sent it.
    pub fn outbound_pending(&self, ship: &str) -> Result<usize, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::peer_out_len(&lock(&ship.conn))?))
    }

    /// How many commands a ship has sent to other ships and has had no receipt for yet.
    pub fn unanswered(&self, ship: &str) -> Result<usize, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::peer_wait_len(&lock(&ship.conn))?))
    }

    /// Take this runtime for a network, if it has none. A runtime has one network at most.
    pub(crate) fn claim_network(&self) -> bool {
        !self.inner.networked.swap(true, Ordering::SeqCst)
    }

    /// The network that claimed this runtime has stopped.
    pub(crate) fn release_network(&self) {
        self.inner.networked.store(false, Ordering::SeqCst);
    }

    /// Have `hook` called with a ship's name whenever an event on it queues commands for
    /// other ships, or with `None` stop that.
    pub(crate) fn set_outbound_hook(&self, hook: Option<OutboundHook>) {
        *self.inner.outbound_hook.write().unwrap_or_else(PoisonError::into_inner) = hook;
    }

    /// The ships that have messages waiting to go to other ships, or events queued. Looks in
    /// every ship's file, so it is for when the network starts, not for every moment.
    pub(crate) fn ships_with_work(&self) -> Result<Vec<String>, Error> {
        let mut found = Vec::new();
        for entry in fs::read_dir(&self.inner.ships_dir)? {
            let file = entry?.file_name();
            let Some(ship) = file.to_str().and_then(|file| file.strip_suffix(".ship")).and_then(|ship| canonical_ship(ship).ok()) else {
                continue;
            };
            // Asked of the ship itself if it is awake, so a write in progress is not read around.
            let has_work = |ship: &mut ship::Ship| {
                let conn = lock(&ship.conn);
                Ok(!store::peers_waiting(&conn)?.is_empty() || store::inbox_len(&conn)? > 0)
            };
            if self.inner.with_ship(&ship, has_work).unwrap_or(false) {
                found.push(ship);
            }
        }
        Ok(found)
    }

    /// The other ships that a ship has commands waiting to go to.
    pub(crate) fn outbound_peers(&self, ship: &str) -> Result<Vec<String>, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::peers_waiting(&lock(&ship.conn))?))
    }

    /// The oldest commands waiting to go from a ship to `peer`.
    pub(crate) fn outbound_batch(&self, ship: &str, peer: &str, max_bytes: usize) -> Result<Vec<ship_proto::PeerMessage>, Error> {
        self.inner.with_ship(ship, |ship| Ok(store::peer_batch(&lock(&ship.conn), peer, max_bytes)?))
    }

    /// `peer` says it holds every command from this ship up to `last`, so those are done with.
    pub(crate) fn outbound_acked(&self, ship: &str, peer: &str, last: u64) -> Result<(), Error> {
        self.inner.with_ship(ship, |ship| {
            ship.transact(|conn| store::peer_acked(conn, peer, last)?.ok_or_else(|| Error::OutOfStep(peer.to_string())))
        })
    }

    /// Take messages that `peer` has sent to a ship here, and return the number of the last
    /// one this ship now holds. Each is taken once, in order: a command into the ship's
    /// queue, a receipt to the agent whose command it answers. One that has been taken before
    /// is passed over. If there is no room for some, the number returned says how far it
    /// got, and the rest are for the sender to send again.
    pub(crate) fn accept_commands(&self, ship: &str, peer: &str, messages: &[ship_proto::PeerMessage]) -> Result<u64, Error> {
        let peer = canonical_ship(peer)?;
        self.inner.with_ship(ship, |ship| ship.accept(&self.inner, &peer, messages))
    }

    /// The newest audit entries, newest first.
    pub fn audit(&self, ship: &str, limit: usize) -> Result<Vec<AuditEntry>, Error> {
        self.inner.with_ship(ship, |ship| store::audit_tail(&lock(&ship.conn), limit))
    }

    /// Write `<dest>/<ship>.ship` plus the module blobs it needs under `<dest>/blobs`.
    ///
    /// The export includes the ship's private signing key, because a ship is its file plus its
    /// key. It is a way to move or back up a ship, not something to hand to anyone else: whoever
    /// holds it can sign as the ship. Running both the original and an imported copy would give
    /// two writers of the same logs, which nothing here yet prevents.
    ///
    /// Which agent modules a ship needs is known only to its kernel, so the export contains the
    /// modules the kernel lists. A kernel that leaves one out produces a ship that imports
    /// cleanly and then fails when that agent is first called.
    pub fn export_ship(&self, ship: &str, dest: impl AsRef<Path>) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let dest = dest.as_ref();
        fs::create_dir_all(dest.join("blobs"))?;
        self.inner.with_ship(&name, |ship| {
            let mut hashes = ship.modules(&self.inner)?;
            let conn = lock(&ship.conn);
            hashes.push(store::kernel(&conn)?);
            store::snapshot_into(&conn, &dest.join(format!("{name}.ship")))?;
            // A ship is its file plus its key, so the key travels with it.
            write_key(&dest.join(format!("{name}.key")), &ship.key)?;
            for hash in hashes {
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
    /// every module it names is verified against its hash. The ship brings its own kernel, which
    /// decides policy for that ship only; the runtime's limits and the separation between ships
    /// do not depend on it.
    pub fn import_ship(&self, src: impl AsRef<Path>, ship: &str) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let src = src.as_ref();
        let dest_file = self.inner.ship_path(&name);
        if dest_file.exists() {
            return Err(Error::ShipExists(name));
        }
        // Timed from here, so the limit covers copying and checking the file as well as reading it.
        let deadline = Instant::now() + Duration::from_millis(self.inner.cfg.max_import_millis);

        let source = match open_regular(&src.join(format!("{name}.ship"))) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::UnknownShip(name)),
            Err(e) => return Err(e.into()),
        };
        let key = load_key(&src.join(format!("{name}.key")))?;
        let (copy, fresh) = (Scratch::new(&self.inner.tmp_dir), Scratch::new(&self.inner.tmp_dir));
        // Copy by bytes read, not by reported size, which a special file can misstate.
        let limit = self.inner.cfg.max_import_bytes;
        if io::copy(&mut source.take(limit + 1), &mut fs::File::create(&copy.0)?)? > limit {
            return Err(Error::BadShipFile(format!("{name}: larger than this runtime will import")));
        }
        let public = key.verifying_key();
        let kernel_hash =
            store::import(&copy.0, &fresh.0, &name, &self.inner.cfg, deadline, &public, check_agent_name, check_hash)?;
        let fetch = |hash: &str| -> Result<(), Error> {
            // Check the bytes on disk, not the compiled cache, which could hide a damaged blob.
            if self.inner.read_blob(hash).is_err() {
                let bytes = self.inner.read_verified(&src.join("blobs").join(format!("{hash}.wasm")), hash)?;
                self.inner.compile(&bytes)?;
                self.inner.store_blob(hash, &bytes)?;
            }
            Ok(())
        };
        fetch(&kernel_hash)?;
        // Only the ship's kernel knows which agent modules it needs, so ask it, reading the new
        // file without changing it.
        let hashes = {
            let conn = store::open_read_only(&fresh.0)?;
            let kernel = self.inner.kernel(&kernel_hash)?;
            let mut staged = Ship {
                name: name.as_str().into(),
                conn: Arc::new(Mutex::new(conn)),
                kernel,
                key: Arc::new(key.clone()),
                outbox_bytes: 0,
                inbox_bytes: 0,
            };
            staged.modules(&self.inner)?
        };
        for hash in hashes {
            check_hash(&hash)?;
            fetch(&hash)?;
        }
        if Instant::now() > deadline {
            return Err(Error::BadShipFile(format!("{name}: import took too long")));
        }
        self.inner.publish(&name, &fresh.0, &key)?;
        // The ship may have arrived with messages waiting to go to other ships, and with
        // events queued.
        self.inner.work_ready(&name);
        Ok(())
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
    /// An event on this ship has queued commands for other ships.
    pub(crate) fn outbound_ready(&self, ship: &str) {
        if let Some(hook) = self.outbound_hook.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
            hook(ship, false);
        }
    }

    /// A ship has appeared that may have messages for other ships and events queued.
    pub(crate) fn work_ready(&self, ship: &str) {
        if let Some(hook) = self.outbound_hook.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
            hook(ship, true);
        }
    }

    /// An event on this ship has added to its logs.
    pub(crate) fn logs_grew(&self, ship: &str) {
        *lock(&self.log_growth).entry(ship.to_string()).or_default() += 1;
        self.logs_changed.notify_all();
    }

    fn ship_path(&self, name: &str) -> PathBuf {
        self.ships_dir.join(format!("{name}.ship"))
    }

    /// Make a finished ship file and its key appear together under the ship's name.
    ///
    /// Creating and importing both end here, one at a time, so two of them racing for the same
    /// name cannot leave one's file with the other's key. The key goes in first: a key with no
    /// ship is harmless and is replaced next time, while a ship with no key could not be woken.
    /// The hard link never replaces an existing ship.
    fn publish(&self, name: &str, staged: &Path, key: &SigningKey) -> Result<(), Error> {
        let _together = lock(&self.lifecycle);
        let dest_file = self.ship_path(name);
        if dest_file.exists() {
            return Err(Error::ShipExists(name.to_string()));
        }
        write_key(&self.key_path(name), key)?;
        match fs::hard_link(staged, &dest_file) {
            Ok(()) => {
                // The network learns of a new ship here, the one place a ship comes to be. The
                // ship is in place from this moment, so this comes before anything that can
                // still fail: a ship that exists is never unknown to the network.
                if let Some(held) = self.identities.write().unwrap_or_else(PoisonError::into_inner).as_mut() {
                    held.insert(name.to_string(), Arc::new(key.clone()));
                }
                Ok(sync_dir(&self.ships_dir)?)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(Error::ShipExists(name.to_string())),
            Err(e) => Err(e.into()),
        }
    }

    fn key_path(&self, name: &str) -> PathBuf {
        self.keys_dir.join(format!("{name}.key"))
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
        // Checked here, at the one place a hash turns into a path, because hashes can come from
        // a ship's own kernel.
        check_hash(hash)?;
        self.read_verified(&self.blob_path(hash), hash)
    }

    /// Write a verified blob, replacing whatever is at its path. A rename means readers see
    /// either the old file or the whole new one.
    fn store_blob(&self, hash: &str, bytes: &[u8]) -> Result<(), Error> {
        check_hash(hash)?;
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
        if module.get_export("memory").and_then(|export| export.memory().cloned()).is_none() {
            return Err(Error::BadModule("missing exported memory".into()));
        }
        let compiled = AgentModule { pre: self.linker.instantiate_pre(&module).map_err(bad)? };
        require_exports(&compiled, &["alloc"])?;
        Ok(compiled)
    }

    /// The compiled kernel module for `hash`.
    fn kernel(&self, hash: &str) -> Result<Arc<AgentModule>, Error> {
        let module = self.module(hash)?;
        require_exports(&module, &["route", "admin"])?;
        Ok(module)
    }

    /// The compiled module for `hash`, loading and verifying its blob on first use.
    pub(crate) fn module(&self, hash: &str) -> Result<Arc<AgentModule>, Error> {
        check_hash(hash)?;
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
        let conn = store::open(&self.ship_path(name), self.cfg.durability, self.cfg.max_ship_bytes)?;
        store::check_meta(&conn, name)?;
        let kernel = self.kernel(&store::kernel(&conn)?)?;
        let key = {
            let _together = lock(&self.lifecycle);
            Arc::new(load_key(&self.key_path(name))?)
        };
        let (outbox_bytes, inbox_bytes) = (store::outbox_bytes(&conn)?, store::inbox_bytes(&conn)?);
        Ok(Ship { name: name.into(), conn: Arc::new(Mutex::new(conn)), kernel, key, outbox_bytes, inbox_bytes })
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
            let ship = guard.ship.as_mut().expect("woken above");
            let result = f(ship);
            // Every operation is meant to end with no transaction open. If one is still open,
            // the cleanup itself failed, so close the file and reopen it on the next call
            // rather than carry on with a connection in an unknown state.
            if !lock(&ship.conn).is_autocommit() {
                drop(guard.ship.take());
                lock(&self.awake).remove(&name);
            }
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
