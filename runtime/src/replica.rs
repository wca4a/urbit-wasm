//! A copy of Azimuth's state, kept on this machine and worked out from Ethereum alone.
//!
//! `crate::azimuth` asks Ethereum about one ship at a time, and for a ship on layer 2 asks
//! Urbit's roller and takes its word. This instead does what every Urbit ship does for
//! itself: it reads every log the Azimuth contract has written and every batch sent to the
//! layer 2 contract, in the order Ethereum has them, and works out the state of every ship
//! from them under Urbit's own rules (`urbit_id::naive`). Only the Ethereum node is trusted.
//!
//! The state is kept in one SQLite file: a table of points, and how far the file has read.
//! It holds only public data and is not encrypted. Only blocks Ethereum has finalised are
//! read, so nothing in the file ever has to be undone, and lookups are answered from the
//! file alone. The newest blocks are not read: they can still be replaced, and a copy that
//! never has to take anything back is simpler to trust. So a change on Ethereum is seen
//! once its block is final, about fifteen minutes after it lands.
//!
//! Each step forward (a range of blocks applied, and the new high-water mark) is one
//! transaction, so a crash or a failed question leaves the file where it was, and it carries
//! on from there. Only one copy may have the file open at a time.
//!
//! Lookups are refused until the file has reached the newest finalised block this run has
//! heard of. A file part way through its history is history: answering from it would hand
//! out keys that have since changed.

use std::collections::HashMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use urbit_id::naive::{self, Dominion, Holder, NetKeys, Outcome, Point, Points};

use crate::azimuth::{listed, Keys, Listing};
use crate::chain::{hex, Ethereum, Limits, Log, Placed, Stop, Trouble};

/// Where Azimuth is, how to read it, and how often.
#[derive(Clone, Debug)]
pub struct ReplicaConfig {
    /// An Ethereum node's JSON-RPC address. It must answer `eth_getLogs` for old blocks.
    pub ethereum: String,
    /// The Azimuth contract, and the block it was made in.
    pub azimuth: [u8; 20],
    pub azimuth_from: u64,
    /// The layer 2 contract, and the block it was made in.
    pub naive: [u8; 20],
    pub naive_from: u64,
    /// Ethereum's chain number, which layer 2 signatures include. 1 is the main network.
    pub chain: u64,
    /// How long one question to the node may take.
    pub timeout: Duration,
    /// How often to ask whether more blocks have become final.
    pub every: Duration,
    /// The least time between two questions to the node.
    pub pause: Duration,
    /// The most blocks asked about in one question. Fewer are asked about when the node
    /// refuses, more again when answers are small.
    pub widest: u64,
    /// How much of the node's answers is read (see `Limits`).
    pub limits: Limits,
    /// The most bytes of batches held in memory for a range of blocks, each transaction's
    /// input once. A range whose batches come to more is read in smaller ranges.
    pub most_batch_bytes: usize,
    /// The same for one block alone, which cannot be split. A block's inputs are at most a
    /// quarter of its gas in bytes (a zero byte of input costs 4 gas), 15 MB at 60 million
    /// gas; this leaves room for limits that grow. Only a broken node can pass it.
    pub most_block_batch_bytes: usize,
    /// The most work for a range of blocks, counted as the bytes of every batch logged: an
    /// input logged several times is held once but applied each time. A range with more is
    /// read in smaller ranges. One block is applied whatever its work, a stop being noticed
    /// between one event and the next, since Ethereum lets one transaction log its input
    /// many times over.
    pub most_work_bytes: usize,
    /// How many questions in a row may go unanswered before a poll gives up until the next.
    pub tries: u32,
}

impl ReplicaConfig {
    /// Azimuth on Ethereum's main network, read through `ethereum`.
    pub fn mainnet(ethereum: &str) -> ReplicaConfig {
        ReplicaConfig {
            ethereum: ethereum.to_string(),
            azimuth: [0x22, 0x3c, 0x06, 0x7f, 0x8c, 0xf2, 0x8a, 0xe1, 0x73, 0xee, 0x5c, 0xaf, 0xea, 0x60, 0xca, 0x44, 0xc3, 0x35, 0xfe, 0xcb],
            azimuth_from: 6_784_880,
            naive: [0xeb, 0x70, 0x02, 0x9c, 0xfb, 0x3c, 0x53, 0xc7, 0x78, 0xea, 0xf6, 0x8c, 0xd2, 0x8d, 0xe7, 0x25, 0x39, 0x0a, 0x1f, 0xe9],
            naive_from: 13_369_829,
            chain: 1,
            timeout: Duration::from_secs(30),
            // Ethereum finalises blocks 32 at a time, about every six and a half minutes.
            every: Duration::from_secs(60),
            pause: Duration::from_millis(500),
            widest: 100_000,
            limits: Limits::default(),
            most_batch_bytes: 64 << 20,
            most_block_batch_bytes: 128 << 20,
            most_work_bytes: 64 << 20,
            tries: 8,
        }
    }
}

/// How much has been read, over the life of the file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Logs from the Azimuth contract.
    pub logs: u64,
    /// Batches sent to the layer 2 contract, and how many of those could not be read (and
    /// so counted for nothing).
    pub batches: u64,
    pub unreadable: u64,
    /// Layer 2 transactions done, signed but refused by the rules, and not signed by whoever
    /// they would have to be.
    pub applied: u64,
    pub failed: u64,
    pub unsigned: u64,
}

/// Where the copy stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The last block the file has applied.
    pub read_to: u64,
    /// The newest finalised block heard of in this run.
    pub finalized: Option<u64>,
    pub counts: Counts,
    /// Why the last poll did not finish, if it did not.
    pub trouble: Option<String>,
}

/// One thing to apply: a log from Azimuth, or a batch.
enum Event {
    Log(Log),
    Batch { block: u64, index: u64, transaction: [u8; 32], transaction_index: u64, input: Arc<Vec<u8>> },
}

impl Event {
    fn place(&self) -> (u64, u64) {
        match self {
            Event::Log(log) => (log.block, log.index),
            Event::Batch { block, index, .. } => (*block, *index),
        }
    }

    fn transaction(&self) -> [u8; 32] {
        match self {
            Event::Log(log) => log.transaction,
            Event::Batch { transaction, .. } => *transaction,
        }
    }

    fn transaction_index(&self) -> u64 {
        match self {
            Event::Log(log) => log.transaction_index,
            Event::Batch { transaction_index, .. } => *transaction_index,
        }
    }
}

struct Inner {
    cfg: ReplicaConfig,
    ethereum: Ethereum,
    /// The connection that writes. Holding it is holding the right to poll.
    writer: Mutex<Connection>,
    /// The connection lookups read through, so that they do not wait for a poll.
    reader: Mutex<Connection>,
    status: Mutex<Status>,
    /// How many blocks to ask about at once, as last worked out.
    span: AtomicU64,
    /// Inputs of transactions fetched for blocks the file has not reached yet, by hash, with
    /// the block (number and hash) each was had for, so that a range tried again does not
    /// ask for them again, and an input had for one block is never used for another.
    fetched: Mutex<Fetched>,
    stop: Arc<Stop>,
    /// Held for as long as the copy is open: no other copy may use the file meanwhile.
    _owned: fs::File,
    /// How long a lookup waits between deciding that it may answer and reading its answer,
    /// so that a test can see that nothing moves meanwhile.
    #[cfg(test)]
    dawdle: Mutex<Duration>,
}

#[derive(Default)]
struct Fetched {
    inputs: HashMap<[u8; 32], (Placed, Arc<Vec<u8>>)>,
    bytes: usize,
}

impl Fetched {
    /// Keep a transaction's input, had for one block. Two different inputs for the same
    /// transaction in the same block are a node contradicting itself.
    fn keep(&mut self, hash: [u8; 32], placed: Placed, input: Vec<u8>) -> Result<(), Trouble> {
        if let Some((before, kept)) = self.inputs.get(&hash) {
            if *before == placed && **kept != input {
                return Err(Trouble::Wrong(format!("transaction {} is said to have two different inputs", hex(&hash))));
            }
        }
        self.bytes += input.len();
        if let Some((_, old)) = self.inputs.insert(hash, (placed, Arc::new(input))) {
            self.bytes -= old.len();
        }
        Ok(())
    }
}

/// The copy. Lookups are answered from it once it has caught up (`Keys`).
pub struct Replica {
    inner: Arc<Inner>,
    follower: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for Replica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Replica")
    }
}

const SCHEMA: &str = "
create table if not exists meta (name text primary key, value not null);
create table if not exists points (
    ship integer primary key check (ship between 0 and 4294967295),
    dominion text not null check (dominion in ('l1', 'l2', 'spawn')),
    owner blob not null check (length(owner) = 20),
    owner_nonce integer not null,
    spawn_proxy blob not null check (length(spawn_proxy) = 20),
    spawn_nonce integer not null,
    management_proxy blob not null check (length(management_proxy) = 20),
    management_nonce integer not null,
    voting_proxy blob not null check (length(voting_proxy) = 20),
    voting_nonce integer not null,
    transfer_proxy blob not null check (length(transfer_proxy) = 20),
    transfer_nonce integer not null,
    continuity integer not null,
    revision integer not null,
    suite integer not null,
    authentication blob not null check (length(authentication) = 32),
    encryption blob not null check (length(encryption) = 32),
    has_sponsor integer not null check (has_sponsor in (0, 1)),
    sponsor integer not null,
    escape_to integer
);
";

const COUNTS: [&str; 6] = ["logs", "batches", "unreadable", "applied", "failed", "unsigned"];

fn sql(e: rusqlite::Error) -> String {
    format!("the copy of Azimuth could not be read or written: {e}")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The file's one true name: links followed, so that the same file is always locked under the
/// same name. A file with more than one name (a hard link) is refused, since another copy
/// could open it by the other name and lock that instead.
fn true_name(path: &Path) -> Result<PathBuf, String> {
    let resolved = match fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A new file: its directory's true name, and its own name as given. A link to a
            // file that does not exist yet is refused: the file would be made under the name
            // it points to, and locked under the link's.
            if fs::symlink_metadata(path).is_ok() {
                return Err(format!("{} is a link to a file that does not exist", path.display()));
            }
            let name = path.file_name().ok_or_else(|| format!("{} does not name a file", path.display()))?;
            let directory = match path.parent() {
                Some(directory) if !directory.as_os_str().is_empty() => directory,
                _ => Path::new("."),
            };
            fs::canonicalize(directory).map_err(|e| format!("cannot find {}: {e}", directory.display()))?.join(name)
        }
        Err(e) => return Err(format!("cannot find {}: {e}", path.display())),
    };
    if let Ok(found) = fs::metadata(&resolved) {
        if found.nlink() > 1 {
            return Err(format!("{} has more than one name (a hard link), so another copy could open it under another; it is not used", path.display()));
        }
    }
    Ok(resolved)
}

/// Open the file, by its true name, without following a link: a link put in its place after
/// its name was worked out is refused, not followed to some other file. A hard link made by
/// someone else in that same moment is not caught, and is left out of what this guards
/// against: it takes someone who can already write to the directory.
fn connect(path: &Path, read_only: bool) -> Result<Connection, String> {
    let how = if read_only { OpenFlags::SQLITE_OPEN_READ_ONLY } else { OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE };
    Connection::open_with_flags(path, how | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW).map_err(sql)
}

/// Take the file for this copy alone, for as long as the returned file is held. Two copies
/// on one file would each believe their own idea of how far it has read.
fn own(path: &Path) -> Result<fs::File, String> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&name).map_err(|e| format!("cannot open {}: {e}", Path::new(&name).display()))?;
    // flock belongs to this open file, so a second opener in this same program is refused
    // too, and closing some other descriptor for the file does not let it go.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Err(format!("{} is in use by another copy of Azimuth, in this program or another; only one may use it at a time", path.display()));
        }
        return Err(format!("cannot lock {}: {err}", Path::new(&name).display()));
    }
    Ok(file)
}

impl Replica {
    /// Open the copy kept in `path`, or start one there. Nothing is asked of Ethereum yet.
    pub fn open(path: &Path, cfg: ReplicaConfig) -> Result<Replica, String> {
        let given = path;
        let path = &true_name(given)?;
        let owned = own(path)?;
        let writer = connect(path, false)?;
        // Readers do not wait for the writer, and the writer does not wait for the disk on
        // every step: a step lost to a power cut is read again.
        writer.pragma_update(None, "journal_mode", "wal").map_err(sql)?;
        writer.pragma_update(None, "synchronous", "normal").map_err(sql)?;
        writer.busy_timeout(Duration::from_secs(10)).map_err(sql)?;
        writer.execute_batch(SCHEMA).map_err(sql)?;
        // A file made for one chain and pair of contracts is never read as another's.
        let made_for = format!("chain {}, azimuth {} from block {}, naive {} from block {}", cfg.chain, hex(&cfg.azimuth), cfg.azimuth_from, hex(&cfg.naive), cfg.naive_from);
        let found: Option<String> = writer.query_row("select value from meta where name = 'made for'", [], |row| row.get(0)).optional().map_err(sql)?;
        match found {
            Some(found) if found != made_for => return Err(format!("{} is a copy of another Azimuth ({found})", given.display())),
            Some(_) => {}
            None => {
                let start = i64::try_from(cfg.azimuth_from.min(cfg.naive_from).saturating_sub(1)).map_err(|_| "the contracts start at a block too far on to write down".to_string())?;
                writer.execute("insert into meta (name, value) values ('made for', ?1), ('read to', ?2)", params![made_for, start]).map_err(sql)?;
            }
        }
        let read_to = read_to(&writer)?;
        let mut counts = Counts::default();
        for (name, count) in COUNTS.iter().zip(counts_mut(&mut counts)) {
            let found: Option<i64> = writer.query_row("select value from meta where name = ?1", [name], |row| row.get(0)).optional().map_err(sql)?;
            *count = found.unwrap_or(0).max(0) as u64;
        }
        let reader = connect(path, true)?;
        reader.busy_timeout(Duration::from_secs(10)).map_err(sql)?;
        let stop = Arc::new(Stop::default());
        let ethereum = Ethereum::new(&cfg.ethereum, cfg.timeout, cfg.pause, stop.clone()).with_limits(cfg.limits);
        let span = AtomicU64::new(cfg.widest.clamp(1, 10_000));
        let status = Status { read_to, counts, ..Status::default() };
        let inner = Inner {
            cfg,
            ethereum,
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
            status: Mutex::new(status),
            span,
            fetched: Mutex::default(),
            stop,
            _owned: owned,
            #[cfg(test)]
            dawdle: Mutex::default(),
        };
        Ok(Replica { inner: Arc::new(inner), follower: Mutex::new(None) })
    }

    /// Bring the file up to the newest finalised block. This can take a while the first time
    /// (all of Azimuth's history), and is quick after that.
    pub fn poll(&self) -> Result<(), String> {
        self.inner.poll()
    }

    /// Keep polling, every so often, on a thread of its own, until the copy is dropped.
    pub fn keep_up(&self) {
        let mut follower = lock(&self.follower);
        if follower.is_some() {
            return;
        }
        let inner = self.inner.clone();
        *follower = Some(std::thread::spawn(move || {
            while !inner.stop.stopped() {
                let _ = inner.poll();
                inner.stop.wait(inner.cfg.every);
            }
        }));
    }

    pub fn status(&self) -> Status {
        lock(&self.inner.status).clone()
    }

    /// Whether lookups are answered: the file has reached the newest finalised block heard
    /// of in this run.
    pub fn caught_up(&self) -> bool {
        behind(&lock(&self.inner.status)).is_none()
    }
}

impl Drop for Replica {
    /// Stops the polling thread. No new question is asked after this, and a wait between
    /// questions ends at once; a question already sent is waited for, which takes at most
    /// the time a question may take.
    fn drop(&mut self) {
        self.inner.stop.stop();
        if let Some(follower) = lock(&self.follower).take() {
            let _ = follower.join();
        }
    }
}

impl Keys for Replica {
    /// Answered from the file, which holds finalised blocks only and only ever moves forward.
    /// So, for as long as Ethereum's finality holds, an answer is never older than one given
    /// before it: a ship's key revision never goes down from one lookup to the next. The
    /// network's directory relies on that when it refuses a lower revision than it has seen.
    ///
    /// Deciding that the copy may answer and reading the answer are one step: the status is
    /// held throughout, so the file cannot be found caught up and then be read part way
    /// through a newer catching up. A poll takes the status only for a moment, never while
    /// it asks the node anything, so a lookup does not wait on the network.
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
        let status = lock(&self.inner.status);
        if let Some(why) = behind(&status) {
            return Err(why);
        }
        #[cfg(test)]
        std::thread::sleep(*lock(&self.inner.dawdle));
        let point = Stored(&lock(&self.inner.reader)).get(ship)?;
        drop(status);
        Ok(point.map(|point| listed(&point.keys.authentication, point.keys.suite, point.keys.revision, point.continuity, point.has_sponsor.then_some(point.sponsor))))
    }
}

/// What an argument of an event is, as it is written in a word of 32 bytes.
#[derive(Clone, Copy)]
enum Arg {
    /// A `uint32`, such as a ship's number: 28 zero bytes, then 4.
    Number,
    /// An address: 12 zero bytes, then 20.
    Address,
    /// A `bytes32`: any 32 bytes.
    Word,
}

/// A kind of log the Azimuth contract writes that `naive.hoon` applies: its first topic, its
/// other topics, and the words of its data, as the contract declares the event.
struct Kind {
    name: [u8; 32],
    topics: &'static [Arg],
    data: &'static [Arg],
}

/// The kinds of Azimuth's logs that are asked for. Every event in `Azimuth.sol` that
/// `naive.hoon` applies is here. Left out, and not asked for at all, are those it does not:
/// `Activated` and `Spawned` (a ship's point starts from the ship above it, so it ignores
/// them), `OwnershipTransferred` (who owns the contract itself, not a ship), and `ChangedDns`
/// (the network's domain names, which nothing here needs, and whose data can be of any
/// length). `ApprovalForAll` is written by another contract, Ecliptic.
fn kinds() -> &'static [Kind] {
    use Arg::{Address, Number, Word};
    static KINDS: std::sync::OnceLock<Vec<Kind>> = std::sync::OnceLock::new();
    KINDS.get_or_init(|| {
        let kind = |event: &str, topics: &'static [Arg], data: &'static [Arg]| Kind { name: naive::keccak(event.as_bytes()), topics, data };
        vec![
            kind("OwnerChanged(uint32,address)", &[Number, Address], &[]),
            kind("EscapeRequested(uint32,uint32)", &[Number, Number], &[]),
            kind("EscapeCanceled(uint32,uint32)", &[Number, Number], &[]),
            kind("EscapeAccepted(uint32,uint32)", &[Number, Number], &[]),
            kind("LostSponsor(uint32,uint32)", &[Number, Number], &[]),
            kind("ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", &[Number], &[Word, Word, Number, Number]),
            kind("BrokeContinuity(uint32,uint32)", &[Number], &[Number]),
            kind("ChangedSpawnProxy(uint32,address)", &[Number, Address], &[]),
            kind("ChangedTransferProxy(uint32,address)", &[Number, Address], &[]),
            kind("ChangedManagementProxy(uint32,address)", &[Number, Address], &[]),
            kind("ChangedVotingProxy(uint32,address)", &[Number, Address], &[]),
        ]
    })
}

/// Check that a log is shaped as the contract writes its kind: as many topics and words of
/// data as the event declares, and each as wide as its type allows. A log in any other shape
/// is not one the contract wrote, and stops the step. This is checked before `naive.hoon`'s
/// rules run, since some of them return early, before they read every argument.
fn check_shape(log: &Log) -> Result<(), Trouble> {
    let wrong = || Trouble::Wrong(format!("the log at block {}, place {} is not shaped as the contract writes its kind", log.block, log.index));
    let kind = kinds().iter().find(|kind| kind.name == log.topics[0]).ok_or_else(wrong)?;
    if log.topics.len() != 1 + kind.topics.len() || log.data.len() != 32 * kind.data.len() {
        return Err(wrong());
    }
    let fits = |arg: &Arg, word: &[u8]| match arg {
        Arg::Number => word[..28].iter().all(|byte| *byte == 0),
        Arg::Address => word[..12].iter().all(|byte| *byte == 0),
        Arg::Word => true,
    };
    let topics_fit = kind.topics.iter().zip(&log.topics[1..]).all(|(arg, topic)| fits(arg, topic));
    let data_fits = kind.data.iter().zip(log.data.chunks(32)).all(|(arg, word)| fits(arg, word));
    if !topics_fit || !data_fits {
        return Err(wrong());
    }
    Ok(())
}

/// Says when the copy runs into trouble and when it is out of it again, once each, and not
/// at every poll that fails the same way.
#[derive(Debug, Default)]
pub struct TroubleWatch {
    troubled: bool,
}

impl TroubleWatch {
    /// What to say, if anything, of the copy as it now stands.
    pub fn notice(&mut self, status: &Status) -> Option<String> {
        match (&status.trouble, self.troubled) {
            (Some(why), false) => {
                self.troubled = true;
                Some(format!("The copy of Azimuth has run into trouble, at block {}: {why}", status.read_to))
            }
            (None, true) => {
                self.troubled = false;
                Some(format!("The copy of Azimuth is out of trouble, at block {}.", status.read_to))
            }
            _ => None,
        }
    }
}

/// Why lookups are not answered yet, if they are not.
fn behind(status: &Status) -> Option<String> {
    match status.finalized {
        None => {
            let trouble = status.trouble.as_ref().map_or(String::new(), |why| format!(", and is held up: {why}"));
            Some(format!("the copy of Azimuth has not yet heard from Ethereum how far the chain is final{trouble}"))
        }
        Some(finalized) if status.read_to < finalized => {
            let trouble = status.trouble.as_ref().map_or(String::new(), |why| format!(", and is held up: {why}"));
            Some(format!("the copy of Azimuth is still catching up: it has read to block {} of {finalized}{trouble}", status.read_to))
        }
        Some(_) => None,
    }
}

/// A table of points that stops being read or written once the copy is being closed, so that
/// a step being applied gives up between one layer 2 transaction and the next.
struct Stoppable<'a, P> {
    points: P,
    stop: &'a Stop,
}

const CLOSING: &str = "the copy of Azimuth is being closed";

impl<P: Points> Points for Stoppable<'_, P> {
    fn get(&self, ship: u32) -> Result<Option<Point>, String> {
        if self.stop.stopped() {
            return Err(CLOSING.into());
        }
        self.points.get(ship)
    }

    fn put(&mut self, ship: u32, point: &Point) -> Result<(), String> {
        if self.stop.stopped() {
            return Err(CLOSING.into());
        }
        self.points.put(ship, point)
    }
}

impl Inner {
    fn poll(&self) -> Result<(), String> {
        let mut writer = lock(&self.writer);
        let done = self.poll_with(&mut writer);
        lock(&self.status).trouble = done.as_ref().err().cloned();
        done
    }

    fn poll_with(&self, writer: &mut Connection) -> Result<(), String> {
        let finalized = self.asking(|| self.ethereum.finalized())?;
        {
            // A node whose finalised block goes back, behind one it gave before or behind
            // what the file has read, does not know its own chain, and is not followed.
            let mut status = lock(&self.status);
            let before = status.finalized.unwrap_or(0).max(status.read_to);
            if finalized < before {
                return Err(format!("Ethereum says the chain is final to block {finalized}, behind block {before}, which it said or the file has read before"));
            }
            status.finalized = Some(finalized);
        }
        self.catch_up(writer, finalized)
    }

    /// Ask until answered, waiting longer each time, up to the number of tries allowed.
    fn asking<T>(&self, mut ask: impl FnMut() -> Result<T, Trouble>) -> Result<T, String> {
        let mut tries = 0;
        loop {
            match ask() {
                Ok(answer) => return Ok(answer),
                Err(trouble) => self.after(&trouble, &mut tries)?,
            }
        }
    }

    /// After a question went unanswered: wait, longer each time, or give up.
    fn after(&self, trouble: &Trouble, tries: &mut u32) -> Result<(), String> {
        *tries += 1;
        if *tries >= self.cfg.tries || matches!(trouble, Trouble::Stopped) || self.stop.wait(self.backoff(*tries)) {
            return Err(trouble.why().to_string());
        }
        Ok(())
    }

    /// How long to wait after so many tries in a row have gone unanswered: twice as long
    /// each time, up to a minute.
    fn backoff(&self, tries: u32) -> Duration {
        let first = self.cfg.pause.max(Duration::from_millis(100));
        first.saturating_mul(1 << tries.saturating_sub(1).min(10)).min(Duration::from_secs(60))
    }

    fn read_to(&self) -> u64 {
        lock(&self.status).read_to
    }

    /// Read forward to `target`, one step at a time, each step one transaction.
    fn catch_up(&self, writer: &mut Connection, target: u64) -> Result<(), String> {
        let mut tries = 0;
        loop {
            if self.stop.stopped() {
                return Err(CLOSING.into());
            }
            let from = self.read_to().checked_add(1).ok_or("the copy of Azimuth has read as far as it can count")?;
            if from > target {
                return Ok(());
            }
            let span = self.span.load(Ordering::Relaxed).max(1);
            let to = target.min(from.saturating_add(span - 1));
            match self.events(from, to) {
                Ok(events) => {
                    self.grow_if_small(&events);
                    self.commit(writer, from, to, &events)?;
                    tries = 0;
                }
                Err(trouble) => self.after_range(&trouble, &mut tries, to - from + 1)?,
            }
        }
    }

    fn grow_if_small(&self, events: &[Event]) {
        if events.len() < self.cfg.limits.range_logs / 10 {
            let span = self.span.load(Ordering::Relaxed);
            self.span.store(span.saturating_mul(2).min(self.cfg.widest.max(1)), Ordering::Relaxed);
        }
    }

    /// After a range of blocks could not be read: ask about far fewer blocks next time.
    /// Nodes word their limits in many ways, refuse, fail, or take too long when asked
    /// about too much, so anything but being asked to ask less often is taken as that. The
    /// range grows again when answers are small.
    fn after_range(&self, trouble: &Trouble, tries: &mut u32, width: u64) -> Result<(), String> {
        if let Trouble::Wrong(why) = trouble {
            return Err(why.clone());
        }
        if !matches!(trouble, Trouble::Busy(_) | Trouble::Stopped) {
            self.span.store((width / 8).max(1), Ordering::Relaxed);
        }
        self.after(trouble, tries)
    }

    /// Everything to apply from blocks `from` to `to`, in order.
    fn events(&self, from: u64, to: u64) -> Result<Vec<Event>, Trouble> {
        let cfg = &self.cfg;
        let mut events = Vec::new();
        // Which block each transaction is in, and each block's hash, as the logs of both
        // contracts say. One transaction in two blocks, or one block number with two hashes,
        // is a node contradicting itself. (Several logs from one transaction, in its block,
        // are as they should be.)
        let mut placed: HashMap<[u8; 32], u64> = HashMap::new();
        let mut hashes: HashMap<u64, [u8; 32]> = HashMap::new();
        let mut heights: HashMap<[u8; 32], u64> = HashMap::new();
        let mut place = |log: &Log| {
            if let Some(before) = placed.insert(log.transaction, log.block).filter(|before| *before != log.block) {
                return Err(Trouble::Wrong(format!("transaction {} is said to be in block {before} and in block {}", hex(&log.transaction), log.block)));
            }
            if hashes.insert(log.block, log.block_hash).is_some_and(|before| before != log.block_hash) {
                return Err(Trouble::Wrong(format!("block {} is said to have two hashes", log.block)));
            }
            if heights.insert(log.block_hash, log.block).is_some_and(|before| before != log.block) {
                return Err(Trouble::Wrong(format!("block hash {} is said to be of two blocks", hex(&log.block_hash))));
            }
            Ok(())
        };
        if to >= cfg.azimuth_from {
            let wanted: Vec<[u8; 32]> = kinds().iter().map(|kind| kind.name).collect();
            for log in self.ethereum.logs(&cfg.azimuth, &wanted, from.max(cfg.azimuth_from), to)? {
                check_shape(&log)?;
                place(&log)?;
                events.push(Event::Log(log));
            }
        }
        if to >= cfg.naive_from {
            let logs = self.ethereum.logs(&cfg.naive, &[naive::batch_topic()], from.max(cfg.naive_from), to)?;
            for log in &logs {
                place(log)?;
            }
            // The layer 2 contract writes one kind of log, with no arguments.
            if let Some(log) = logs.iter().find(|log| log.topics != [naive::batch_topic()] || !log.data.is_empty()) {
                return Err(Trouble::Wrong(format!("the layer 2 contract's log at block {}, place {} is not a batch", log.block, log.index)));
            }
            // A batch is the whole input of the transaction that made the log.
            let wanted: Vec<([u8; 32], Placed)> = logs.iter().map(|log| (log.transaction, Placed { block: log.block, hash: log.block_hash, index: log.transaction_index })).collect();
            let inputs = self.inputs(&wanted, from, to)?;
            // Each batch log is applied, and applying one is reading its input and checking
            // the signature of every transaction in it. Inputs repeated by several logs are
            // held once but applied as often as they are logged, so the work of a step is
            // counted by each log's input: past `most_work_bytes`, a range is read in smaller
            // pieces. One block is applied whatever its work.
            let work: usize = inputs.iter().map(|input| input.len()).sum();
            if from < to && work > cfg.most_work_bytes {
                return Err(Trouble::TooLong(format!("the batches logged in blocks {from} to {to} come to more than is applied in one step")));
            }
            events.extend(logs.iter().zip(inputs).map(|(log, input)| Event::Batch { block: log.block, index: log.index, transaction: log.transaction, transaction_index: log.transaction_index, input }));
        }
        // Layer 1 and layer 2 interleaved, in the order Ethereum has them. Two logs in one
        // place would be a node that does not know its own chain.
        events.sort_by_key(Event::place);
        if events.windows(2).any(|pair| pair[0].place() == pair[1].place()) {
            return Err(Trouble::Failed(format!("two logs in one place in blocks {from} to {to}")));
        }
        // A transaction's logs are all together in its block: one that comes back after
        // another transaction's cannot be, and applied in that order would give a state no
        // order of transactions gives.
        //
        // And a transaction has one place in its block, a place one transaction, and logs
        // come in the order of the transactions that wrote them: a transaction's place never
        // goes down as its logs' places go up.
        let mut done_in_block: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut place_of: HashMap<[u8; 32], u64> = HashMap::new();
        let mut at_place: HashMap<u64, [u8; 32]> = HashMap::new();
        for (at, event) in events.iter().enumerate() {
            let previous = at.checked_sub(1).map(|before| &events[before]);
            if previous.is_some_and(|previous| previous.place().0 != event.place().0) {
                done_in_block.clear();
                place_of.clear();
                at_place.clear();
            }
            let (block, index) = event.place();
            let wrong = |why: &str| Trouble::Wrong(format!("transaction {} in block {block}, at log {index}: {why}", hex(&event.transaction())));
            if place_of.insert(event.transaction(), event.transaction_index()).is_some_and(|before| before != event.transaction_index()) {
                return Err(wrong("it is said to have two places in its block"));
            }
            if at_place.insert(event.transaction_index(), event.transaction()).is_some_and(|before| before != event.transaction()) {
                return Err(wrong("its place in the block is said to be another transaction's"));
            }
            if previous.is_some_and(|previous| previous.place().0 == block && previous.transaction_index() > event.transaction_index()) {
                return Err(wrong("its logs come after those of a transaction later in the block"));
            }
            if let Some(previous) = previous.filter(|previous| previous.place().0 == event.place().0 && previous.transaction() != event.transaction()) {
                done_in_block.insert(previous.transaction());
            }
            if done_in_block.contains(&event.transaction()) {
                let (block, index) = event.place();
                return Err(Trouble::Wrong(format!("transaction {} has logs on both sides of another's in block {block}, at place {index}", hex(&event.transaction()))));
            }
        }
        Ok(events)
    }

    /// The inputs of these transactions: kept from an earlier try, or asked for a few at a
    /// time, each few asked again after a wait if the node is busy or fails. So a range with
    /// many batches gets through a node that allows only so many questions a minute,
    /// without asking again for what it has. No more than `most_batch_bytes` are held: past
    /// that, what is held is let go and the range is read in smaller pieces.
    fn inputs(&self, wanted: &[([u8; 32], Placed)], from: u64, to: u64) -> Result<Vec<Arc<Vec<u8>>>, Trouble> {
        let most = if from == to { self.cfg.most_block_batch_bytes } else { self.cfg.most_batch_bytes };
        // Only inputs this range wants are kept from before. Those had for a range that was
        // then refused, or for blocks no longer asked about, are let go, so that polls that
        // fail do not pile them up, however small they are.
        let mut missing: Vec<([u8; 32], Placed)> = Vec::new();
        {
            let mut fetched = lock(&self.fetched);
            let wanted_now: std::collections::HashSet<([u8; 32], Placed)> = wanted.iter().copied().collect();
            fetched.inputs.retain(|hash, (placed, _)| wanted_now.contains(&(*hash, *placed)));
            fetched.bytes = fetched.inputs.values().map(|(_, input)| input.len()).sum();
            // Each transaction is asked for once, however many of its logs there are: a
            // transaction can write several batches, and each is applied.
            let mut asked = std::collections::HashSet::new();
            for (hash, placed) in wanted {
                if fetched.inputs.get(hash).map(|(found, _)| found) != Some(placed) && asked.insert((*hash, *placed)) {
                    missing.push((*hash, *placed));
                }
            }
        }
        // Each input is taken in as it comes, against the room there is, so that no more
        // than one is in hand beyond it. When there is no more room, the fetching stops, and
        // the range is read in smaller pieces.
        let mut admit = |hash: [u8; 32], placed: Placed, input: Vec<u8>| -> Result<(), Trouble> {
            let mut fetched = lock(&self.fetched);
            fetched.keep(hash, placed, input)?;
            if fetched.bytes > most {
                *fetched = Fetched::default();
                return Err(Trouble::TooLong(format!("the batches in blocks {from} to {to} come to more than is held in memory at once")));
            }
            Ok(())
        };
        for group in missing.chunks(crate::chain::TRANSACTIONS_AT_ONCE) {
            let mut tries = 0;
            loop {
                // Asked again after a failure, only what has not come yet.
                let still: Vec<([u8; 32], Placed)> = {
                    let fetched = lock(&self.fetched);
                    group.iter().filter(|(hash, placed)| fetched.inputs.get(hash).map(|(found, _)| found) != Some(placed)).copied().collect()
                };
                if still.is_empty() {
                    break;
                }
                match self.ethereum.inputs(&still, &mut admit) {
                    Ok(()) => break,
                    Err(trouble) => {
                        tries += 1;
                        if tries >= self.cfg.tries || matches!(trouble, Trouble::Stopped | Trouble::Wrong(_) | Trouble::TooLong(_)) || self.stop.wait(self.backoff(tries)) {
                            return Err(trouble);
                        }
                    }
                }
            }
        }
        let fetched = lock(&self.fetched);
        // An input is used only for the block it was had for.
        let found = wanted.iter().map(|(hash, block)| fetched.inputs.get(hash).filter(|(found, _)| found == block).map(|(_, input)| input.clone()));
        found.collect::<Option<Vec<_>>>().ok_or_else(|| Trouble::Failed("a transaction's input was not kept".into()))
    }

    /// Apply one step's events to the file and move its high-water mark, all in one
    /// transaction.
    fn commit(&self, writer: &mut Connection, from: u64, to: u64, events: &[Event]) -> Result<(), String> {
        let to_written = i64::try_from(to).map_err(|_| "a block too far on to write down".to_string())?;
        // Begun for writing at once, so that anything else writing the same file waits, and
        // then finds the file has moved on and that this step would be a repeat.
        let transaction = writer.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
        if Some(read_to(&transaction)?) != from.checked_sub(1) {
            return Err("the copy of Azimuth was moved on by something else writing its file".into());
        }
        let mut counts = lock(&self.status).counts;
        // Closing gives up part way, and the step, never committed, leaves nothing behind.
        apply(&mut Stoppable { points: Stored(&transaction), stop: &self.stop }, &self.stop, self.cfg.chain, events, &mut counts)?;
        transaction.execute("update meta set value = ?1 where name = 'read to'", [to_written]).map_err(sql)?;
        for (name, count) in COUNTS.iter().zip(counts_mut(&mut counts)) {
            transaction.execute("insert or replace into meta (name, value) values (?1, ?2)", params![name, *count as i64]).map_err(sql)?;
        }
        if self.stop.stopped() {
            return Err(CLOSING.into());
        }
        transaction.commit().map_err(sql)?;
        {
            let mut fetched = lock(&self.fetched);
            fetched.inputs.retain(|_, (placed, _)| placed.block > to);
            fetched.bytes = fetched.inputs.values().map(|(_, input)| input.len()).sum();
        }
        let mut status = lock(&self.status);
        status.read_to = to;
        status.counts = counts;
        Ok(())
    }
}

/// Apply events to a table of points, counting what became of them. A stop is noticed before
/// each event (and, through the table, between one layer 2 transaction and the next).
fn apply(points: &mut impl Points, stop: &Stop, chain: u64, events: &[Event], counts: &mut Counts) -> Result<(), String> {
    for event in events {
        if stop.stopped() {
            return Err(CLOSING.into());
        }
        match event {
            Event::Log(log) => {
                naive::receive_log(points, &log.topics, &log.data).map_err(|why| format!("the log at block {}, place {}: {why}", log.block, log.index))?;
                counts.logs += 1;
            }
            Event::Batch { input, .. } => {
                let received = naive::receive_batch(points, chain, input)?;
                counts.batches += 1;
                match received.outcomes {
                    None => counts.unreadable += 1,
                    Some(outcomes) => {
                        for outcome in outcomes {
                            match outcome {
                                Outcome::Applied => counts.applied += 1,
                                Outcome::Failed => counts.failed += 1,
                                Outcome::Unsigned => counts.unsigned += 1,
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn counts_mut(counts: &mut Counts) -> [&mut u64; 6] {
    [&mut counts.logs, &mut counts.batches, &mut counts.unreadable, &mut counts.applied, &mut counts.failed, &mut counts.unsigned]
}

fn read_to(connection: &Connection) -> Result<u64, String> {
    let read_to: i64 = connection.query_row("select value from meta where name = 'read to'", [], |row| row.get(0)).map_err(sql)?;
    u64::try_from(read_to).map_err(|_| "the copy of Azimuth is damaged".to_string())
}

/// The table of points in the file.
struct Stored<'a>(&'a Connection);

impl Points for Stored<'_> {
    fn get(&self, ship: u32) -> Result<Option<Point>, String> {
        let mut query = self.0.prepare_cached("select * from points where ship = ?1").map_err(sql)?;
        let row = query.query_row([ship], |row| Ok(point_of_row(row))).optional().map_err(sql)?;
        row.transpose()
    }

    fn put(&mut self, ship: u32, point: &Point) -> Result<(), String> {
        let dominion = match point.dominion {
            Dominion::L1 => "l1",
            Dominion::L2 => "l2",
            Dominion::Spawn => "spawn",
        };
        let mut query = self.0.prepare_cached("insert or replace into points values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)").map_err(sql)?;
        let keys = &point.keys;
        query
            .execute(params![
                ship,
                dominion,
                &point.owner.address[..],
                point.owner.nonce,
                &point.spawn_proxy.address[..],
                point.spawn_proxy.nonce,
                &point.management_proxy.address[..],
                point.management_proxy.nonce,
                &point.voting_proxy.address[..],
                point.voting_proxy.nonce,
                &point.transfer_proxy.address[..],
                point.transfer_proxy.nonce,
                point.continuity,
                keys.revision,
                keys.suite,
                &keys.authentication[..],
                &keys.encryption[..],
                point.has_sponsor,
                point.sponsor,
                point.escape,
            ])
            .map_err(sql)?;
        Ok(())
    }
}

fn point_of_row(row: &rusqlite::Row) -> Result<Point, String> {
    let damaged = || "the copy of Azimuth is damaged".to_string();
    let number = |at: usize| row.get::<_, i64>(at).ok().and_then(|value| u32::try_from(value).ok()).ok_or_else(damaged);
    let address = |at: usize| row.get::<_, Vec<u8>>(at).ok().and_then(|bytes| <[u8; 20]>::try_from(bytes).ok()).ok_or_else(damaged);
    let key = |at: usize| row.get::<_, Vec<u8>>(at).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()).ok_or_else(damaged);
    let holder = |at: usize| Ok::<_, String>(Holder { address: address(at)?, nonce: number(at + 1)? });
    let dominion = match row.get::<_, String>(1).map_err(|_| damaged())?.as_str() {
        "l1" => Dominion::L1,
        "l2" => Dominion::L2,
        "spawn" => Dominion::Spawn,
        _ => return Err(damaged()),
    };
    let escape = match row.get::<_, Option<i64>>(19).map_err(|_| damaged())? {
        None => None,
        Some(escape) => Some(u32::try_from(escape).map_err(|_| damaged())?),
    };
    Ok(Point {
        dominion,
        owner: holder(2)?,
        spawn_proxy: holder(4)?,
        management_proxy: holder(6)?,
        voting_proxy: holder(8)?,
        transfer_proxy: holder(10)?,
        continuity: number(12)?,
        keys: NetKeys { revision: number(13)?, suite: number(14)?, authentication: key(15)?, encryption: key(16)? },
        has_sponsor: number(17)? == 1,
        sponsor: number(18)?,
        escape,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use urbit_id::naive::{address_of, keccak, signed_message, written, Action, Address, Proxy, DEPOSIT};

    const AZIMUTH: [u8; 20] = [0xaa; 20];
    const NAIVE: [u8; 20] = [0xbb; 20];
    const STAR: u32 = 0x0100;
    const PLANET: u32 = 0x0001_0100;

    struct FakeLog {
        block: u64,
        block_hash: [u8; 32],
        index: u64,
        /// The place of its transaction in the block, if a test says; otherwise worked out
        /// from the order in which transactions first log in the block.
        transaction_index: Option<u64>,
        address: [u8; 20],
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
        transaction: [u8; 32],
    }

    /// How a stand-in node gets the wrapping of its answers wrong.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Wrong {
        Id,
        Version,
    }

    /// A stand-in for an Ethereum node: a chain of logs and transactions, made up by each
    /// test, answered over JSON-RPC as a node answers, with the faults real nodes have.
    #[derive(Default)]
    struct Chain {
        finalized: u64,
        logs: Vec<FakeLog>,
        inputs: HashMap<[u8; 32], (u64, Vec<u8>)>,
        /// The most blocks one `eth_getLogs` may cover.
        widest: u64,
        /// How many more times each method is answered with HTTP status 500.
        failing: HashMap<String, usize>,
        /// How many more times each method is answered with HTTP status 429, as a node
        /// that is asked too often answers.
        busy: HashMap<String, usize>,
        /// `eth_getLogs` up to this block or past it is refused.
        refused_from: Option<u64>,
        /// Whether several questions are taken in one request.
        together: bool,
        /// A log from another contract is slipped into every answer.
        garbled: bool,
        /// Answers to this method are wrapped wrongly.
        wrong: Option<(&'static str, Wrong)>,
        /// Every question asked: the method and its parameters.
        asked: Vec<(String, Value)>,
        /// How many requests held several questions.
        together_asked: usize,
        /// How long the node takes over each answer.
        slow: Duration,
        /// Logs of every kind are answered, whatever kinds are asked for.
        unfiltered: bool,
        /// Transactions said to be in a block of another hash than their logs say.
        moved: HashMap<[u8; 32], [u8; 32]>,
        /// Transactions said to be at another place in their block than their logs say.
        moved_index: HashMap<[u8; 32], u64>,
        /// How many transactions the final block is said to have, each listed by hash.
        block_transactions: usize,
        /// Several questions asked at once are each refused, as some nodes do past a few.
        refuse_together: bool,
        made: u64,
    }

    impl Chain {
        fn add(&mut self, block: u64, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> [u8; 32] {
            self.made += 1;
            let transaction = keccak(&self.made.to_be_bytes());
            self.add_in(transaction, block, address, topics, data)
        }

        /// A log written by the given transaction.
        fn add_in(&mut self, transaction: [u8; 32], block: u64, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> [u8; 32] {
            let index = self.logs.iter().filter(|log| log.block == block).count() as u64;
            self.logs.push(FakeLog { block, block_hash: block_hash(block), index, transaction_index: None, address, topics, data, transaction });
            self.logs.sort_by_key(|log| (log.block, log.index));
            transaction
        }

        fn azimuth(&mut self, block: u64, name: &[u8], ship: u32, third: Option<[u8; 32]>, data: Vec<u8>) {
            let mut topics = vec![keccak(name), word(&ship.to_be_bytes())];
            topics.extend(third);
            self.add(block, AZIMUTH, topics, data);
        }

        fn batch(&mut self, block: u64, transactions: &[Vec<u8>]) {
            let input = transactions.iter().rev().flatten().copied().collect();
            let transaction = self.add(block, NAIVE, vec![naive::batch_topic()], vec![]);
            self.inputs.insert(transaction, (block, input));
        }

        /// Take away every log in a block.
        fn forget(&mut self, block: u64) {
            self.logs.retain(|log| log.block != block);
        }

        /// The place in its block of the transaction that wrote a log, as a chain has it.
        fn place_in_block(&self, block: u64, transaction: &[u8; 32]) -> u64 {
            let mut seen: Vec<[u8; 32]> = Vec::new();
            for log in self.logs.iter().filter(|log| log.block == block) {
                if !seen.contains(&log.transaction) {
                    seen.push(log.transaction);
                }
            }
            seen.iter().position(|found| found == transaction).unwrap_or(0) as u64
        }

        fn methods(&self, method: &str) -> Vec<&Value> {
            self.asked.iter().filter(|(asked, _)| asked == method).map(|(_, params)| params).collect()
        }

        fn answer(&mut self, question: &Value) -> Value {
            let method = question["method"].as_str().unwrap_or_default().to_string();
            let params = question["params"].clone();
            self.asked.push((method.clone(), params.clone()));
            let id = question["id"].clone();
            let quantity = |value: &Value| u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let refuse = |why: &str| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": why } });
            let result = match method.as_str() {
                "eth_getBlockByNumber" => {
                    let transactions: Vec<String> = (0..self.block_transactions as u64).map(|at| hex(&keccak(&at.to_be_bytes()))).collect();
                    json!({ "number": format!("{:#x}", self.finalized), "hash": hex(&block_hash(self.finalized)), "transactions": transactions })
                }
                "eth_getLogs" => {
                    let filter = &params[0];
                    let (from, to) = (quantity(&filter["fromBlock"]), quantity(&filter["toBlock"]));
                    if self.refused_from.is_some_and(|refused| to >= refused) {
                        return refuse("service unavailable for these blocks");
                    }
                    if to - from + 1 > self.widest {
                        return refuse("block range too large");
                    }
                    let address = crate::chain::bytes(filter["address"].as_str().unwrap()).unwrap();
                    // Only the kinds asked for, if any are named, as a node does.
                    let kinds: Option<Vec<String>> = filter["topics"][0].as_array().filter(|_| !self.unfiltered).map(|kinds| kinds.iter().map(|kind| kind.as_str().unwrap().to_string()).collect());
                    let mut found: Vec<Value> = self
                        .logs
                        .iter()
                        .filter(|log| log.address[..] == address[..] && log.block >= from && log.block <= to)
                        .filter(|log| kinds.as_ref().is_none_or(|kinds| kinds.contains(&hex(&log.topics[0]))))
                        .map(|log| {
                            json!({
                                "address": hex(&log.address),
                                "blockNumber": format!("{:#x}", log.block),
                                "blockHash": hex(&log.block_hash),
                                "logIndex": format!("{:#x}", log.index),
                                "transactionHash": hex(&log.transaction),
                                "transactionIndex": format!("{:#x}", log.transaction_index.unwrap_or_else(|| self.place_in_block(log.block, &log.transaction))),
                                "topics": log.topics.iter().map(|topic| hex(topic)).collect::<Vec<_>>(),
                                "data": hex(&log.data),
                                "removed": false,
                            })
                        })
                        .collect();
                    if self.garbled && !found.is_empty() {
                        let mut stray = found[0].clone();
                        stray["address"] = json!(hex(&[0xcc; 20]));
                        found.push(stray);
                    }
                    Value::Array(found)
                }
                "eth_getTransactionByHash" => {
                    let hash: [u8; 32] = crate::chain::bytes(params[0].as_str().unwrap()).unwrap().try_into().unwrap();
                    match self.inputs.get(&hash) {
                        Some((block, input)) => {
                            let placed = self.moved.get(&hash).copied().unwrap_or(block_hash(*block));
                            let index = self.moved_index.get(&hash).copied().unwrap_or_else(|| self.place_in_block(*block, &hash));
                            json!({ "hash": hex(&hash), "blockNumber": format!("{block:#x}"), "blockHash": hex(&placed), "transactionIndex": format!("{index:#x}"), "input": hex(input) })
                        }
                        None => Value::Null,
                    }
                }
                _ => return refuse("no such method"),
            };
            let mut answer = json!({ "jsonrpc": "2.0", "id": id, "result": result });
            match self.wrong {
                Some((wrong, Wrong::Id)) if wrong == method => answer["id"] = json!("7"),
                Some((wrong, Wrong::Version)) if wrong == method => answer["jsonrpc"] = json!("1.0"),
                _ => {}
            }
            answer
        }

        /// The answer to a whole request, and its HTTP status.
        fn request(&mut self, body: &str) -> (u16, String) {
            let Ok(question) = serde_json::from_str::<Value>(body) else { return (400, String::new()) };
            let methods: Vec<String> = match &question {
                Value::Array(questions) => questions.iter().map(|question| question["method"].as_str().unwrap_or_default().to_string()).collect(),
                question => vec![question["method"].as_str().unwrap_or_default().to_string()],
            };
            for method in methods {
                if let Some(left) = self.failing.get_mut(&method).filter(|left| **left > 0) {
                    *left -= 1;
                    return (500, String::new());
                }
                if let Some(left) = self.busy.get_mut(&method).filter(|left| **left > 0) {
                    *left -= 1;
                    return (429, r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32005,"message":"rate limit exceeded"}}"#.into());
                }
            }
            match &question {
                Value::Array(_) if !self.together => (400, r#"{"error":{"code":-32600,"message":"batch requests are not supported"}}"#.into()),
                Value::Array(questions) if self.refuse_together => {
                    let refusals: Vec<Value> = questions.iter().map(|_| json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "batch too large" } })).collect();
                    (200, Value::Array(refusals).to_string())
                }
                Value::Array(questions) => {
                    self.together_asked += 1;
                    (200, Value::Array(questions.iter().rev().map(|question| self.answer(question)).collect()).to_string())
                }
                question => (200, self.answer(question).to_string()),
            }
        }
    }

    struct Node {
        url: String,
        chain: Arc<Mutex<Chain>>,
    }

    impl Node {
        fn start() -> Node {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let chain = Arc::new(Mutex::new(Chain { widest: 1000, together: true, ..Chain::default() }));
            let serving = chain.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let (mut length, mut line) = (0usize, String::new());
                    while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                        line.clear();
                    }
                    let mut body = vec![0; length];
                    if reader.read_exact(&mut body).is_err() {
                        continue;
                    }
                    let (status, answer, slow) = {
                        let mut chain = serving.lock().unwrap();
                        let (status, answer) = chain.request(&String::from_utf8_lossy(&body));
                        (status, answer, chain.slow)
                    };
                    std::thread::sleep(slow);
                    let _ = write!(stream, "HTTP/1.1 {status} Whatever\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len());
                }
            });
            Node { url, chain }
        }

        fn with<T>(&self, change: impl FnOnce(&mut Chain) -> T) -> T {
            change(&mut self.chain.lock().unwrap())
        }

        fn config(&self) -> ReplicaConfig {
            ReplicaConfig {
                ethereum: self.url.clone(),
                azimuth: AZIMUTH,
                azimuth_from: 10,
                naive: NAIVE,
                naive_from: 20,
                chain: 1,
                timeout: Duration::from_secs(5),
                every: Duration::from_millis(20),
                pause: Duration::ZERO,
                widest: 1000,
                limits: Limits::default(),
                most_batch_bytes: 1 << 20,
                most_block_batch_bytes: 2 << 20,
                most_work_bytes: 1 << 20,
                tries: 5,
            }
        }
    }

    /// A data directory of its own for one test, removed when the test is over.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("replica-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn file(&self) -> std::path::PathBuf {
            self.0.join("azimuth.sqlite")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The hash a block has on the stand-in's chain, unless a test says otherwise.
    fn block_hash(block: u64) -> [u8; 32] {
        keccak(&[b"block".as_slice(), &block.to_be_bytes()].concat())
    }

    fn word(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        out
    }

    fn wallet(seed: u8) -> (SigningKey, Address) {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let address = address_of(key.verifying_key());
        (key, address)
    }

    /// A layer 2 transaction as written in a batch, signed with `key` at count `nonce`.
    fn signed(key: &SigningKey, nonce: u32, ship: u32, proxy: Proxy, action: Action) -> Vec<u8> {
        let raw = written(ship, proxy, &action);
        let (signature, id) = key.sign_prehash_recoverable(&keccak(&signed_message(1, nonce, &raw))).unwrap();
        [raw, signature.to_bytes().to_vec(), vec![27 + id.to_byte()]].concat()
    }

    /// An authentication key as Azimuth keeps it: a number, most significant byte first.
    /// Each byte differs, so that a key turned the wrong way round would show.
    fn azimuth_key(seed: u8) -> [u8; 32] {
        std::array::from_fn(|at| seed.wrapping_add(at as u8))
    }

    /// The same key as a ship holds it, which is Azimuth's number reversed.
    fn key(seed: u8) -> Option<[u8; 32]> {
        let mut key = azimuth_key(seed);
        key.reverse();
        Some(key)
    }

    fn keys(seed: u8, revision: u32) -> Vec<u8> {
        [[9; 32], azimuth_key(seed), word(&[1]), word(&revision.to_be_bytes())].concat()
    }

    fn configure(seed: u8) -> Action {
        Action::ConfigureKeys { encryption: [9; 32], authentication: azimuth_key(seed), suite: 1, breach: false }
    }

    /// A small history: a galaxy and a star on layer 1, the star then making its planets on
    /// layer 2, and a planet made there that sets its keys.
    fn history(chain: &mut Chain) {
        let (galaxy, star, planet) = (wallet(1).1, wallet(2), wallet(3));
        chain.azimuth(11, b"OwnerChanged(uint32,address)", 0, Some(word(&galaxy)), vec![]);
        chain.azimuth(12, b"OwnerChanged(uint32,address)", STAR, Some(word(&star.1)), vec![]);
        chain.azimuth(12, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, keys(0x51, 1));
        chain.azimuth(13, b"Activated(uint32)", STAR, None, vec![]);
        chain.azimuth(15, b"ChangedSpawnProxy(uint32,address)", STAR, Some(word(&DEPOSIT)), vec![]);
        chain.batch(22, &[signed(&star.0, 0, STAR, Proxy::Owner, Action::Spawn { ship: PLANET, to: planet.1 })]);
        // The planet's new owner takes it, then sets its keys, in one batch.
        chain.batch(24, &[signed(&planet.0, 0, PLANET, Proxy::Transfer, Action::TransferPoint { to: planet.1, reset: false }), signed(&planet.0, 0, PLANET, Proxy::Owner, configure(0x71))]);
    }

    fn file_revision(path: &Path, ship: u32) -> Option<u32> {
        let file = Connection::open(path).unwrap();
        file.query_row("select revision from points where ship = ?1", [ship], |row| row.get(0)).optional().unwrap()
    }

    fn revision(replica: &Replica, ship: u32) -> (u32, Option<[u8; 32]>) {
        let listing = replica.listing(ship).unwrap().unwrap();
        (listing.revision, listing.key)
    }

    #[test]
    fn the_copy_reads_both_contracts_in_order_through_a_node_that_refuses_and_fails() {
        let scratch = Scratch::new("order");
        let path = scratch.file();
        let node = Node::start();
        let new_owner = wallet(4);
        node.with(|chain| {
            history(chain);
            // The star changes hands on layer 1 at block 30. A spawn signed by the new owner
            // just before that is not theirs to sign; one just after, in the same block, is.
            // Read all of layer 1 first and both would count.
            chain.batch(29, &[signed(&new_owner.0, 1, STAR, Proxy::Owner, Action::Spawn { ship: 0x0003_0100, to: new_owner.1 })]);
            chain.azimuth(30, b"OwnerChanged(uint32,address)", STAR, Some(word(&new_owner.1)), vec![]);
            chain.batch(30, &[signed(&new_owner.0, 1, STAR, Proxy::Owner, Action::Spawn { ship: 0x0002_0100, to: new_owner.1 })]);
            chain.batch(30, &[signed(&new_owner.0, 2, STAR, Proxy::Owner, Action::Spawn { ship: 0x0004_0100, to: new_owner.1 })]);
            chain.finalized = 40;
            // A node that takes only seven blocks at a time, fails a question of each kind
            // once, and asks to be asked less often.
            chain.widest = 7;
            chain.failing.insert("eth_getLogs".into(), 1);
            chain.failing.insert("eth_getTransactionByHash".into(), 1);
            chain.busy.insert("eth_getTransactionByHash".into(), 2);
            chain.busy.insert("eth_getLogs".into(), 1);
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        assert!(replica.listing(0).unwrap_err().contains("not yet heard"));
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(revision(&replica, STAR), (1, key(0x51)));
        let planet = replica.listing(PLANET).unwrap().unwrap();
        assert_eq!(planet, Listing { key: key(0x71), revision: 1, continuity: 0, sponsor: Some(STAR) });
        assert_eq!(replica.listing(0x0002_0100).unwrap().unwrap().key, None);
        assert_eq!(replica.listing(0x0003_0100).unwrap(), None, "signed before its signer owned the star");
        assert_eq!(replica.listing(0x0009_0100).unwrap(), None, "never made");
        assert_eq!(replica.listing(0).unwrap().unwrap().key, None, "a galaxy with no keys");
        let counts = replica.status().counts;
        // Six logs from Azimuth, five of them of a kind that is applied, and so asked for.
        assert_eq!(counts, Counts { logs: 5, batches: 5, unreadable: 0, applied: 5, failed: 0, unsigned: 1 });
        assert!(replica.listing(0x0004_0100).unwrap().is_some());
        // It asked about more blocks than the node takes, was refused, and asked about
        // fewer. Several transactions went in one request, as this node takes that.
        node.with(|chain| {
            let width = |filter: &&Value| {
                let number = |name: &str| u64::from_str_radix(filter[0][name].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                number("toBlock") - number("fromBlock") + 1
            };
            let logs = chain.methods("eth_getLogs");
            assert!(logs.iter().any(|filter| width(filter) > 7));
            assert!(logs.iter().any(|filter| width(filter) > 1 && width(filter) <= 7));
            assert!(chain.together_asked > 0);
            // A transaction's input, once had, was not asked for again, though ranges were.
            let mut hashes: Vec<String> = chain.methods("eth_getTransactionByHash").iter().map(|params| params[0].to_string()).collect();
            let asked = hashes.len();
            hashes.sort();
            hashes.dedup();
            assert_eq!((asked, hashes.len()), (5, 5));
        });

        // Closed and opened again, it carries on from where it was. Until it has heard how
        // far the chain is final, it answers nothing, for it could be far behind.
        drop(replica);
        node.with(|chain| {
            chain.azimuth(45, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", 0, None, keys(0x0a, 1));
            chain.finalized = 50;
            chain.asked.clear();
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(replica.status().counts, counts);
        assert!(replica.listing(PLANET).is_err());
        replica.poll().unwrap();
        assert_eq!(revision(&replica, 0), (1, key(0x0a)));
        assert_eq!(revision(&replica, PLANET), (1, key(0x71)));
        node.with(|chain| {
            for filter in chain.methods("eth_getLogs") {
                assert!(u64::from_str_radix(filter[0]["fromBlock"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() > 40, "{filter}");
            }
        });
        assert_eq!(replica.status().counts.logs, 6);

        // A file is a copy of one Azimuth, and is not opened as another's.
        drop(replica);
        let other = ReplicaConfig { naive_from: 21, ..node.config() };
        assert!(Replica::open(&path, other).unwrap_err().contains("another Azimuth"));
    }

    #[test]
    fn only_final_blocks_are_read_and_answers_never_go_back() {
        let scratch = Scratch::new("forward");
        let node = Node::start();
        let planet = wallet(3);
        node.with(|chain| {
            history(chain);
            chain.finalized = 30;
        });
        let replica = Replica::open(&scratch.file(), node.config()).unwrap();
        replica.poll().unwrap();
        // On a chain that only moves forward, poll after poll, the planet's revision as
        // looked up never goes down. Each poll the node has newer blocks than are final,
        // and what is in them is not seen until it is final.
        let mut seen = Vec::new();
        for step in 0..6u32 {
            node.with(|chain| {
                chain.batch(31 + 4 * step as u64, &[signed(&planet.0, 1 + step, PLANET, Proxy::Owner, configure(0x80 + step as u8))]);
                chain.finalized = 30 + 4 * step as u64 + if step % 2 == 0 { 0 } else { 4 };
            });
            replica.poll().unwrap();
            let (revision, key_now) = revision(&replica, PLANET);
            assert!(seen.last().is_none_or(|(last, _)| *last <= revision), "{seen:?} then {revision}");
            let finalized = replica.status().finalized.unwrap();
            let expected = 1 + (0..=step).filter(|at| 31 + 4 * *at as u64 <= finalized).count() as u32;
            assert_eq!(revision, expected, "at step {step}, final to {finalized}");
            seen.push((revision, key_now));
        }
        assert_eq!(seen.last().unwrap().0, 7);
        assert_eq!(seen.last().unwrap().1, key(0x85));
        // The node never asked how far the chain goes beyond the final block.
        node.with(|chain| assert!(chain.asked.iter().all(|(method, _)| method != "eth_blockNumber")));
        // Nothing has moved: nothing is asked for but the final block.
        node.with(|chain| chain.asked.clear());
        replica.poll().unwrap();
        node.with(|chain| assert_eq!(chain.asked.iter().map(|(method, _)| method.as_str()).collect::<Vec<_>>(), ["eth_getBlockByNumber"]));
    }

    #[test]
    fn lookups_wait_for_the_file_to_reach_the_final_block_and_go_on_without_the_node() {
        let scratch = Scratch::new("behind");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
            // Blocks from 23 on cannot be had for now.
            chain.refused_from = Some(23);
            chain.widest = 5;
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        assert!(replica.poll().is_err());
        let status = replica.status();
        assert!(status.read_to < 23 && status.read_to >= 20, "{status:?}");
        assert!(status.trouble.is_some());
        assert!(!replica.caught_up());
        assert!(replica.listing(STAR).unwrap_err().contains("catching up"));
        // Nothing half-read was kept: the planet made at block 22 is in the file, the keys
        // it set at block 24 are not.
        assert_eq!(file_revision(&path, PLANET), Some(0));
        // One block short of the final block is still short: no lookups.
        node.with(|chain| chain.refused_from = Some(40));
        assert!(replica.poll().is_err());
        assert_eq!(replica.status().read_to, 39);
        assert!(replica.listing(STAR).unwrap_err().contains("catching up"));
        node.with(|chain| chain.refused_from = None);
        replica.poll().unwrap();
        assert!(replica.caught_up());
        assert_eq!(revision(&replica, PLANET), (1, key(0x71)));
        // The node goes away. What the copy has is answered from.
        node.with(|chain| {
            chain.failing.insert("eth_getBlockByNumber".into(), 100);
        });
        assert!(replica.poll().is_err());
        assert_eq!(revision(&replica, PLANET), (1, key(0x71)));

        // Answers that are not what was asked for are an error, never an empty answer, and
        // the file does not move.
        node.with(|chain| {
            chain.failing.clear();
            chain.garbled = true;
            chain.azimuth(45, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", 0, None, keys(0x0a, 1));
            chain.finalized = 50;
        });
        assert!(replica.poll().unwrap_err().contains("another contract"));
        assert!(replica.status().read_to < 45);
        assert_eq!(file_revision(&path, 0), Some(0));
        node.with(|chain| chain.garbled = false);
        replica.poll().unwrap();
        assert_eq!(revision(&replica, 0), (1, key(0x0a)));

        // A node that takes one question per request is asked one at a time.
        node.with(|chain| {
            chain.together = false;
            let planet = wallet(3);
            chain.batch(52, &[signed(&planet.0, 1, PLANET, Proxy::Owner, configure(0x72))]);
            chain.batch(53, &[signed(&planet.0, 2, PLANET, Proxy::Owner, configure(0x73))]);
            chain.finalized = 60;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (3, key(0x73)));

        // Kept up on its own thread, it sees what comes next, and stops when dropped.
        replica.keep_up();
        node.with(|chain| {
            chain.azimuth(61, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", 0, None, keys(0x0b, 2));
            chain.finalized = 61;
        });
        let started = std::time::Instant::now();
        while replica.listing(0).ok().flatten().map(|listing| listing.revision) != Some(2) {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = std::time::Instant::now();
        drop(replica);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn only_one_copy_may_have_a_file_open() {
        let scratch = Scratch::new("owned");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let first = Replica::open(&scratch.file(), node.config()).unwrap();
        first.poll().unwrap();
        let refused = Replica::open(&scratch.file(), node.config()).unwrap_err();
        assert!(refused.contains("in use by another copy"), "{refused}");
        drop(first);
        let second = Replica::open(&scratch.file(), node.config()).unwrap();
        assert_eq!(second.status().read_to, 40);
    }

    #[test]
    fn a_log_not_shaped_as_the_contract_writes_it_stops_the_step() {
        let scratch = Scratch::new("shapes");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        let ugly: [(&[u8], Vec<[u8; 32]>, Vec<u8>, [u8; 20]); 7] = [
            // Keys with no data, which read as numbers would set every key to zero.
            (b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", vec![word(&STAR.to_be_bytes())], vec![], AZIMUTH),
            (b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", vec![word(&STAR.to_be_bytes())], [keys(0x51, 2), vec![0]].concat(), AZIMUTH),
            (b"BrokeContinuity(uint32,uint32)", vec![word(&STAR.to_be_bytes())], vec![7; 31], AZIMUTH),
            (b"OwnerChanged(uint32,address)", vec![word(&STAR.to_be_bytes())], vec![], AZIMUTH),
            (b"OwnerChanged(uint32,address)", vec![word(&STAR.to_be_bytes()), word(&[5; 20])], vec![0; 32], AZIMUTH),
            (b"Batch()", vec![[1; 32]], vec![], NAIVE),
            (b"Batch()", vec![], vec![1], NAIVE),
        ];
        for (name, rest, data, contract) in ugly {
            node.with(|chain| {
                let topics = [vec![keccak(name)], rest].concat();
                let transaction = chain.add(41, contract, topics, data);
                chain.inputs.insert(transaction, (41, vec![]));
                chain.finalized = 45;
            });
            let refused = replica.poll().unwrap_err();
            assert!(refused.contains("not shaped") || refused.contains("not a batch"), "{refused}");
            assert_eq!(replica.status().read_to, 40);
            assert_eq!(file_revision(&path, STAR), Some(1));
            node.with(|chain| chain.forget(41));
        }
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 45);
    }

    #[test]
    fn answers_that_do_not_answer_the_question_asked_change_nothing() {
        let scratch = Scratch::new("envelopes");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let open = || Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        let mut replica = open();
        // An answer to another question, or not in JSON-RPC 2.0, about how far the chain is
        // final: no number is taken from it.
        for wrong in [Wrong::Id, Wrong::Version] {
            node.with(|chain| chain.wrong = Some(("eth_getBlockByNumber", wrong)));
            assert!(replica.poll().unwrap_err().contains("not an answer to the question"));
            assert_eq!(replica.status().finalized, None);
        }
        // The same of logs, and of transactions asked for one at a time and several at once.
        // Each case starts afresh, asking about the whole range, which has two batches in it.
        for (method, together) in [("eth_getLogs", true), ("eth_getTransactionByHash", true), ("eth_getTransactionByHash", false)] {
            for wrong in [Wrong::Id, Wrong::Version] {
                drop(replica);
                replica = open();
                node.with(|chain| {
                    chain.wrong = Some((method, wrong));
                    chain.together = together;
                });
                let refused = replica.poll().unwrap_err();
                assert!(refused.contains("not an answer to the question") || refused.contains("a question that was not asked"), "{method}: {refused}");
                assert!(replica.status().read_to < 22, "{method}");
            }
        }
        node.with(|chain| chain.wrong = None);
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (1, key(0x71)));
    }

    #[test]
    fn a_node_whose_final_block_goes_back_is_not_followed() {
        let scratch = Scratch::new("heads");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        node.with(|chain| chain.finalized = 39);
        assert!(replica.poll().unwrap_err().contains("behind block 40"));
        assert_eq!(replica.status().finalized, Some(40));
        // Final to block 50, heard of while the blocks after 40 cannot be had, so that the
        // file stays at 40. Then the node says 45: behind what it said before, though ahead
        // of the file. It is not followed, and 50 is kept.
        node.with(|chain| {
            chain.finalized = 50;
            chain.refused_from = Some(41);
        });
        assert!(replica.poll().is_err());
        assert_eq!((replica.status().read_to, replica.status().finalized), (40, Some(50)));
        node.with(|chain| {
            chain.finalized = 45;
            chain.refused_from = None;
        });
        assert!(replica.poll().unwrap_err().contains("behind block 50"));
        assert_eq!((replica.status().read_to, replica.status().finalized), (40, Some(50)));
        node.with(|chain| chain.finalized = 50);
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 50);
        // Opened again with a node behind the file: it is not followed, and nothing is
        // answered, for nothing says how far the chain is really final.
        drop(replica);
        node.with(|chain| chain.finalized = 49);
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        assert!(replica.poll().unwrap_err().contains("behind block 50"));
        assert!(replica.listing(PLANET).is_err());
        node.with(|chain| chain.finalized = 50);
        replica.poll().unwrap();
        assert!(replica.listing(PLANET).is_ok());
        // A final block too big to write down is not a block number. (Taken as one, it
        // would have the copy read for ever: the poll runs on a thread of its own here, so
        // that the test fails rather than waits if it does.)
        node.with(|chain| chain.finalized = u64::MAX);
        let replica = Arc::new(replica);
        let (done, answer) = std::sync::mpsc::channel();
        let polling = replica.clone();
        std::thread::spawn(move || done.send(polling.poll()));
        let polled = answer.recv_timeout(Duration::from_secs(10));
        assert!(polled.as_ref().is_ok_and(|polled| polled.as_ref().is_err_and(|why| why.contains("no number"))), "{polled:?}");
        assert_eq!(replica.status().finalized, Some(50));
    }

    #[test]
    fn a_lookup_never_reads_a_file_part_way_through_catching_up() {
        let scratch = Scratch::new("atomic");
        let node = Node::start();
        let planet = wallet(3);
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Arc::new(Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap());
        replica.poll().unwrap();
        // The planet sets new keys at block 50, and they are taken away at block 90. The
        // node says the chain is final to 100, but blocks from 60 on cannot be had yet, so
        // a poll reads as far as 59 and stops: the file then holds the keys of block 50,
        // which by block 90 are gone.
        node.with(|chain| {
            chain.batch(50, &[signed(&planet.0, 1, PLANET, Proxy::Owner, configure(0x72))]);
            chain.batch(90, &[signed(&planet.0, 2, PLANET, Proxy::Owner, Action::ConfigureKeys { encryption: [0; 32], authentication: [0; 32], suite: 0, breach: false })]);
            chain.finalized = 100;
            chain.refused_from = Some(60);
        });
        // A lookup that has found the copy caught up, at block 40, and dawdles before it
        // reads. A poll meanwhile must not move the file under it.
        *lock(&replica.inner.dawdle) = Duration::from_secs(1);
        let looking = replica.clone();
        let lookup = std::thread::spawn(move || looking.listing(PLANET));
        std::thread::sleep(Duration::from_millis(100));
        assert!(replica.poll().is_err());
        assert_eq!(replica.status().read_to, 59);
        let answered = lookup.join().unwrap().unwrap().unwrap();
        assert_eq!((answered.revision, answered.key), (1, key(0x71)), "the answer is the file as it was at block 40");
        *lock(&replica.inner.dawdle) = Duration::ZERO;
        assert!(replica.listing(PLANET).unwrap_err().contains("catching up"));
    }

    #[test]
    fn an_argument_wider_than_its_type_stops_the_step() {
        let scratch = Scratch::new("widths");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        let wide_number = [[0, 0, 0, 1], 1u32.to_be_bytes()].concat();
        let ugly: [(&[u8], Vec<[u8; 32]>, Vec<u8>); 5] = [
            // The planet's sponsor is the star, 0x0100. A sponsor written as 2^32 + 0x0100
            // is not the star, and read as a number would be quietly taken as someone else.
            (b"LostSponsor(uint32,uint32)", vec![word(&PLANET.to_be_bytes()), word(&[[0, 0, 0, 1], STAR.to_be_bytes()].concat())], vec![]),
            // The star is no longer on layer 1, so naive.hoon would return before reading
            // this address at all.
            (b"ChangedSpawnProxy(uint32,address)", vec![word(&STAR.to_be_bytes()), [7; 32]], vec![]),
            (b"OwnerChanged(uint32,address)", vec![word(&wide_number), word(&[5; 20])], vec![]),
            (b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", vec![word(&STAR.to_be_bytes())], [vec![9; 64], word(&[1]).to_vec(), word(&wide_number).to_vec()].concat()),
            (b"BrokeContinuity(uint32,uint32)", vec![word(&STAR.to_be_bytes())], word(&wide_number).to_vec()),
        ];
        for (name, rest, data) in ugly {
            node.with(|chain| {
                chain.add(41, AZIMUTH, [vec![keccak(name)], rest].concat(), data);
                chain.finalized = 45;
            });
            let refused = replica.poll().unwrap_err();
            assert!(refused.contains("not shaped"), "{} {refused}", String::from_utf8_lossy(name));
            assert_eq!(replica.status().read_to, 40);
            node.with(|chain| chain.forget(41));
        }
        replica.poll().unwrap();
        assert_eq!(replica.listing(PLANET).unwrap().unwrap().sponsor, Some(STAR));
        // Losing it for real, written as the contract writes it, leaves the planet with no
        // sponsor to give, though the file keeps the number of the one it had.
        node.with(|chain| {
            chain.azimuth(46, b"LostSponsor(uint32,uint32)", PLANET, Some(word(&STAR.to_be_bytes())), vec![]);
            chain.finalized = 50;
        });
        replica.poll().unwrap();
        assert_eq!(replica.listing(PLANET).unwrap().unwrap().sponsor, None);
        assert_eq!(Connection::open(&path).unwrap().query_row("select has_sponsor, sponsor from points where ship = ?1", [PLANET], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?))).unwrap(), (0, STAR));
    }

    #[test]
    fn events_that_are_not_applied_are_not_asked_for() {
        let scratch = Scratch::new("dns");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            // Domain names a hundred kilobytes long: the contract allows it, and nothing
            // here reads them.
            chain.add(30, AZIMUTH, vec![keccak(b"ChangedDns(string,string,string)")], vec![b'a'; 100 << 10]);
            chain.azimuth(31, b"Spawned(uint32,uint32)", STAR, Some(word(&PLANET.to_be_bytes())), vec![]);
            chain.finalized = 40;
        });
        let replica = Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (1, key(0x71)));
        // Asked for only by kind, and every kind applied is among those asked for.
        node.with(|chain| {
            let azimuth = hex(&AZIMUTH);
            for filter in chain.methods("eth_getLogs").iter().filter(|filter| filter[0]["address"] == azimuth.as_str()) {
                let asked: Vec<&str> = filter[0]["topics"][0].as_array().unwrap().iter().map(|kind| kind.as_str().unwrap()).collect();
                assert_eq!(asked.len(), 11);
                for applied in ["OwnerChanged(uint32,address)", "EscapeRequested(uint32,uint32)", "EscapeCanceled(uint32,uint32)", "EscapeAccepted(uint32,uint32)", "LostSponsor(uint32,uint32)", "ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", "BrokeContinuity(uint32,uint32)", "ChangedSpawnProxy(uint32,address)", "ChangedTransferProxy(uint32,address)", "ChangedManagementProxy(uint32,address)", "ChangedVotingProxy(uint32,address)"] {
                    assert!(asked.contains(&hex(&keccak(applied.as_bytes())).as_str()), "{applied}");
                }
            }
        });
        // A node that answers with a kind not asked for is not answering the question.
        node.with(|chain| {
            chain.azimuth(41, b"Activated(uint32)", STAR, None, vec![]);
            chain.finalized = 45;
            chain.unfiltered = true;
        });
        assert!(replica.poll().unwrap_err().contains("a kind not asked for"));
        assert_eq!(replica.status().read_to, 40);
    }

    #[test]
    fn one_transaction_in_two_blocks_is_refused() {
        let scratch = Scratch::new("placed");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        let topics = vec![keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)"), word(&STAR.to_be_bytes())];
        // The same transaction in blocks 41 and 42.
        node.with(|chain| {
            chain.add_in([0x42; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
            chain.add_in([0x42; 32], 42, AZIMUTH, topics.clone(), keys(0x53, 3));
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("in block 41 and in block 42"));
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(file_revision(&path, STAR), Some(1));
        // Two logs from one transaction in one block are as they should be.
        node.with(|chain| {
            chain.forget(42);
            chain.add_in([0x42; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, STAR), (3, key(0x53)));
        // The same of a batch and a log of the same transaction in different blocks.
        let planet = wallet(3);
        node.with(|chain| {
            chain.add_in([0x43; 32], 46, AZIMUTH, topics.clone(), keys(0x54, 4));
            chain.add_in([0x43; 32], 47, NAIVE, vec![naive::batch_topic()], vec![]);
            chain.inputs.insert([0x43; 32], (47, signed(&planet.0, 1, PLANET, Proxy::Owner, configure(0x72))));
            chain.finalized = 50;
        });
        assert!(replica.poll().unwrap_err().contains("in block 46 and in block 47"));
        assert_eq!(replica.status().read_to, 45);
    }

    #[test]
    fn a_block_with_two_hashes_is_refused() {
        let scratch = Scratch::new("hashes");
        let path = scratch.file();
        let node = Node::start();
        let planet = wallet(3);
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        // Two logs of block 41, of the two contracts, naming two different hashes for it.
        node.with(|chain| {
            chain.azimuth(41, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, keys(0x52, 2));
            chain.batch(41, &[signed(&planet.0, 1, PLANET, Proxy::Owner, configure(0x72))]);
            chain.logs.last_mut().unwrap().block_hash = [0x77; 32];
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("two hashes"));
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(file_revision(&path, STAR), Some(1));
        // The same block, one hash: as it should be.
        node.with(|chain| chain.logs.last_mut().unwrap().block_hash = block_hash(41));
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (2, key(0x72)));
        // A batch whose transaction the node puts in a block of another hash than its log,
        // though of the same number.
        let moved = node.with(|chain| {
            chain.batch(46, &[signed(&planet.0, 2, PLANET, Proxy::Owner, configure(0x73))]);
            let transaction = chain.logs.last().unwrap().transaction;
            chain.moved.insert(transaction, [0x88; 32]);
            chain.finalized = 50;
            transaction
        });
        assert!(replica.poll().unwrap_err().contains("in another block than its log"));
        assert_eq!(replica.status().read_to, 45);
        node.with(|chain| {
            chain.moved.remove(&moved);
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (3, key(0x73)));

        // An input had for one block is never used for another of the same number. A batch
        // at block 51 is fetched, then the step fails on a damaged row further on, leaving
        // the input kept. The node then says block 51 has another hash, logs and
        // transaction alike: the input is asked for again.
        let damaged = 0x0200u32;
        Connection::open(&path)
            .unwrap()
            .execute(
                "insert into points select ?1, dominion, owner, owner_nonce, spawn_proxy, spawn_nonce, management_proxy, management_nonce, voting_proxy, voting_nonce, transfer_proxy, transfer_nonce, 1099511627776, revision, suite, authentication, encryption, has_sponsor, sponsor, escape_to from points where ship = ?2",
                [damaged, STAR],
            )
            .unwrap();
        let transaction = node.with(|chain| {
            chain.batch(51, &[signed(&planet.0, 3, PLANET, Proxy::Owner, configure(0x74))]);
            let transaction = chain.logs.last().unwrap().transaction;
            chain.azimuth(52, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", damaged, None, keys(0x53, 1));
            chain.finalized = 55;
            transaction
        });
        assert!(replica.poll().unwrap_err().contains("damaged"));
        let asked = |node: &Node| node.with(|chain| chain.methods("eth_getTransactionByHash").iter().filter(|params| params[0] == hex(&transaction).as_str()).count());
        assert_eq!(asked(&node), 1);
        node.with(|chain| {
            chain.forget(52);
            chain.logs.iter_mut().filter(|log| log.block == 51).for_each(|log| log.block_hash = [0x99; 32]);
            chain.moved.insert(transaction, [0x99; 32]);
        });
        replica.poll().unwrap();
        assert_eq!(asked(&node), 2);
        assert_eq!(revision(&replica, PLANET), (4, key(0x74)));
    }

    #[test]
    fn a_transaction_with_several_batches_is_asked_for_once_and_each_is_applied() {
        let scratch = Scratch::new("repeats");
        let node = Node::start();
        let planet = wallet(3);
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        let counts = replica.status().counts;
        // One transaction that wrote three batch logs, all with its one input. The first is
        // applied; the other two find its count already used.
        node.with(|chain| {
            let input = signed(&planet.0, 1, PLANET, Proxy::Owner, configure(0x72));
            for _ in 0..3 {
                chain.add_in([0x51; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x51; 32], (41, input));
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (2, key(0x72)));
        let after = replica.status().counts;
        assert_eq!((after.batches - counts.batches, after.applied - counts.applied, after.unsigned - counts.unsigned), (3, 1, 2));
        let asked = node.with(|chain| chain.methods("eth_getTransactionByHash").iter().filter(|params| params[0] == hex(&[0x51; 32]).as_str()).count());
        assert_eq!(asked, 1);
    }

    /// The widths of the ranges of blocks the layer 2 contract's logs were asked about.
    fn naive_widths(node: &Node) -> Vec<u64> {
        node.with(|chain| {
            let number = |filter: &Value, name: &str| u64::from_str_radix(filter[0][name].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            chain.methods("eth_getLogs").iter().filter(|filter| filter[0]["address"] == hex(&NAIVE).as_str()).map(|filter| number(filter, "toBlock") - number(filter, "fromBlock") + 1).collect()
        })
    }

    /// A copy, read to block 40 of `history`, with these limits, and its node.
    fn limited(name: &str, cfg: impl FnOnce(ReplicaConfig) -> ReplicaConfig) -> (Scratch, Node, Replica) {
        let scratch = Scratch::new(name);
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&scratch.file(), cfg(ReplicaConfig { tries: 3, ..node.config() })).unwrap();
        replica.poll().unwrap();
        (scratch, node, replica)
    }

    /// One transaction of the planet's, setting new keys, as its own batch.
    fn new_keys(nonce: u32) -> Vec<u8> {
        signed(&wallet(3).0, nonce, PLANET, Proxy::Owner, configure(0x80 + nonce as u8))
    }

    #[test]
    fn one_block_with_more_logs_than_a_range_may_have_is_read_whole() {
        let limits = |cfg: ReplicaConfig| ReplicaConfig { limits: Limits { range_logs: 5, block_logs: 50, ..Limits::default() }, ..cfg };
        // Twenty batches in one block, logged by one transaction: more than a range's answer
        // may hold, fewer than one block's may.
        let (_scratch, node, replica) = limited("block-logs", limits);
        node.with(|chain| {
            for _ in 0..20 {
                chain.add_in([0x81; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x81; 32], (41, new_keys(1)));
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!((revision(&replica, PLANET).0, replica.status().counts.batches), (2, 22));
        assert!(naive_widths(&node).contains(&1));
        // The same twenty spread over twenty blocks: read in smaller ranges.
        let (_scratch, node, replica) = limited("range-logs", limits);
        node.with(|chain| {
            for at in 0..20u32 {
                chain.batch(41 + at as u64, &[new_keys(1 + at)]);
            }
            chain.finalized = 60;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 21);
        let widths = naive_widths(&node);
        assert!(widths.iter().any(|width| *width >= 20) && widths.iter().any(|width| *width > 1 && *width < 5), "{widths:?}");
        // More in one block than any block could hold: only a broken node says so.
        let (_scratch, node, replica) = limited("too-many-logs", limits);
        node.with(|chain| {
            for _ in 0..60 {
                chain.add_in([0x82; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x82; 32], (41, new_keys(1)));
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("than are taken in one answer"));
        assert_eq!(replica.status().read_to, 40);
    }

    #[test]
    fn one_block_with_a_longer_answer_than_a_range_may_have_is_read_whole() {
        // A batch log is about 400 bytes as the stand-in writes it.
        let limits = |cfg: ReplicaConfig| ReplicaConfig { limits: Limits { range_log_bytes: 3_000, block_log_bytes: 100_000, ..Limits::default() }, ..cfg };
        let (_scratch, node, replica) = limited("block-bytes", limits);
        node.with(|chain| {
            for _ in 0..20 {
                chain.add_in([0x83; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x83; 32], (41, new_keys(1)));
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 2);
        let (_scratch, node, replica) = limited("range-bytes", limits);
        node.with(|chain| {
            for at in 0..20u32 {
                chain.batch(41 + at as u64, &[new_keys(1 + at)]);
            }
            chain.finalized = 60;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 21);
        assert!(naive_widths(&node).iter().any(|width| *width > 1 && *width < 20));
    }

    #[test]
    fn one_block_with_more_input_than_a_range_may_hold_is_read_whole() {
        // Five transactions' inputs of 139 bytes: more than a range may hold, less than one
        // block may.
        let limits = |cfg: ReplicaConfig| ReplicaConfig { most_batch_bytes: 300, most_block_batch_bytes: 2_000, ..cfg };
        let (_scratch, node, replica) = limited("block-held", limits);
        node.with(|chain| {
            for at in 0..5u32 {
                chain.batch(41, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 6);
        let (_scratch, node, replica) = limited("range-held", limits);
        node.with(|chain| {
            for at in 0..5u32 {
                chain.batch(41 + at as u64, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 6);
        assert!(naive_widths(&node).iter().any(|width| *width > 1 && *width < 5));
        // More than any block could hold.
        let (_scratch, node, replica) = limited("too-much-held", limits);
        node.with(|chain| {
            for at in 0..20u32 {
                chain.batch(41, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("more than is held"));
    }

    #[test]
    fn one_block_with_more_work_than_a_range_may_have_is_applied_whole() {
        // One input of 139 bytes logged five times in one block: 695 bytes of work, more
        // than a range may have. One block is applied whatever its work.
        let limits = |cfg: ReplicaConfig| ReplicaConfig { most_work_bytes: 300, ..cfg };
        let (_scratch, node, replica) = limited("block-work", limits);
        node.with(|chain| {
            for _ in 0..5 {
                chain.add_in([0x84; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x84; 32], (41, new_keys(1)));
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        let counts = replica.status().counts;
        assert_eq!((revision(&replica, PLANET).0, counts.batches, counts.unsigned), (2, 7, 4));
        // The same work over five blocks: read in smaller ranges.
        let (_scratch, node, replica) = limited("range-work", limits);
        node.with(|chain| {
            for at in 0..5u32 {
                chain.batch(41 + at as u64, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 6);
        assert!(naive_widths(&node).iter().any(|width| *width > 1 && *width < 5));
    }

    #[test]
    fn a_transactions_input_is_read_up_to_its_limit() {
        // The longest input in the history before is 230 bytes.
        let limits = |cfg: ReplicaConfig| ReplicaConfig { limits: Limits { input_bytes: 240, ..Limits::default() }, ..cfg };
        // Exactly the limit: a batch with zeros in front (which are not part of it).
        let (_scratch, node, replica) = limited("input-at-limit", limits);
        node.with(|chain| {
            let mut input = vec![0; 240 - new_keys(1).len()];
            input.extend(new_keys(1));
            let transaction = chain.add(41, NAIVE, vec![naive::batch_topic()], vec![]);
            chain.inputs.insert(transaction, (41, input));
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 2);
        // Past it: more than any transaction could have, from a broken node.
        let (_scratch, node, replica) = limited("input-past-limit", limits);
        node.with(|chain| {
            let mut input = vec![0; 241 - new_keys(1).len()];
            input.extend(new_keys(1));
            let transaction = chain.add(41, NAIVE, vec![naive::batch_topic()], vec![]);
            chain.inputs.insert(transaction, (41, input));
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("longer than any transaction's could be"));
    }

    #[test]
    fn a_final_block_with_thousands_of_transactions_is_read() {
        let scratch = Scratch::new("dense");
        let node = Node::start();
        // Three thousand transactions' hashes: over 200 KB as a node writes the block.
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
            chain.block_transactions = 3_000;
        });
        let replica = Replica::open(&scratch.file(), node.config()).unwrap();
        replica.poll().unwrap();
        assert_eq!(replica.status().finalized, Some(40));
    }

    #[test]
    fn a_transaction_on_both_sides_of_another_in_its_block_is_refused() {
        let scratch = Scratch::new("interleaved");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        let topics = vec![keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)"), word(&STAR.to_be_bytes())];
        // Transaction A writes a log, then B a batch, then A again: places 0, 1 and 2.
        node.with(|chain| {
            chain.add_in([0xa1; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
            chain.add_in([0xb1; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            chain.inputs.insert([0xb1; 32], (41, new_keys(1)));
            chain.add_in([0xa1; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
            chain.finalized = 45;
        });
        // (The places of the transactions, as a chain would give them, already say so.)
        let refused = replica.poll().unwrap_err();
        assert!(refused.contains("on both sides of another") || refused.contains("later in the block"), "{refused}");
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(file_revision(&path, STAR), Some(1));
        // A's logs together, then B's: as a chain has them.
        node.with(|chain| {
            chain.forget(41);
            chain.add_in([0xa1; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
            chain.add_in([0xa1; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
            chain.add_in([0xb1; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
        });
        replica.poll().unwrap();
        assert_eq!((revision(&replica, STAR).0, revision(&replica, PLANET).0), (3, 2));
    }

    #[test]
    fn the_places_of_transactions_in_a_block_must_agree_with_the_order_of_their_logs() {
        let topics = vec![keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)"), word(&STAR.to_be_bytes())];
        let cases: [(&str, [Option<u64>; 3]); 3] = [
            // A's log first, B's next, but A said to come after B in the block.
            ("later in the block", [Some(1), Some(0), None]),
            // A's two logs at two different places.
            ("two places", [Some(0), Some(2), Some(3)]),
            // A and B at the same place.
            ("another transaction's", [Some(0), Some(0), Some(0)]),
        ];
        for (said, places) in cases {
            let (scratch, node, replica) = limited("places", |cfg| ReplicaConfig { tries: 2, ..cfg });
            node.with(|chain| {
                chain.add_in([0xa2; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
                if said == "two places" {
                    chain.add_in([0xa2; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
                } else {
                    chain.add_in([0xb2; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
                }
                for (log, place) in chain.logs.iter_mut().filter(|log| log.block == 41).zip(places) {
                    log.transaction_index = place;
                }
                chain.finalized = 45;
            });
            let refused = replica.poll().unwrap_err();
            assert!(refused.contains(said), "{said}: {refused}");
            assert_eq!(replica.status().read_to, 40);
            assert_eq!(file_revision(&scratch.file(), STAR), Some(1));
        }
        // Places as a chain gives them, with gaps for transactions that wrote nothing here.
        let (_scratch, node, replica) = limited("places-good", |cfg| cfg);
        node.with(|chain| {
            chain.add_in([0xa2; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
            chain.add_in([0xb2; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
            for (log, place) in chain.logs.iter_mut().filter(|log| log.block == 41).zip([3, 7]) {
                log.transaction_index = Some(place);
            }
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, STAR), (3, key(0x53)));
        // A batch whose transaction the node puts at another place than its log does.
        let (_scratch, node, replica) = limited("places-batch", |cfg| ReplicaConfig { tries: 2, ..cfg });
        node.with(|chain| {
            chain.batch(41, &[new_keys(1)]);
            let transaction = chain.logs.last().unwrap().transaction;
            chain.moved_index.insert(transaction, 5);
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("in another block than its log"));
        assert_eq!(replica.status().read_to, 40);
    }

    #[test]
    fn a_node_that_refuses_questions_asked_together_is_asked_them_one_at_a_time() {
        let (_scratch, node, replica) = limited("refused-together", |cfg| ReplicaConfig { tries: 2, ..cfg });
        node.with(|chain| {
            chain.refuse_together = true;
            for at in 0..3u32 {
                chain.batch(41, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
            chain.asked.clear();
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 4);
        // (The stand-in counts only questions it answers: the three asked one at a time.)
        node.with(|chain| assert_eq!(chain.methods("eth_getTransactionByHash").len(), 3));
    }

    #[test]
    fn trouble_is_said_once_when_it_starts_and_once_when_it_ends() {
        let mut watch = TroubleWatch::default();
        let mut status = Status { read_to: 40, finalized: Some(50), ..Status::default() };
        assert_eq!(watch.notice(&status), None);
        status.trouble = Some("the node refused".into());
        assert!(watch.notice(&status).is_some_and(|said| said.contains("run into trouble") && said.contains("the node refused")));
        assert_eq!(watch.notice(&status), None);
        status.trouble = Some("the node refused again".into());
        assert_eq!(watch.notice(&status), None);
        status.trouble = None;
        assert!(watch.notice(&status).is_some_and(|said| said.contains("out of trouble")));
        assert_eq!(watch.notice(&status), None);

        // A lookup refused while the copy is held up says why.
        let scratch = Scratch::new("held-up");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
            chain.refused_from = Some(23);
        });
        let replica = Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        assert!(replica.poll().is_err());
        let refused = replica.listing(PLANET).unwrap_err();
        assert!(refused.contains("held up") && refused.contains("service unavailable"), "{refused}");
    }

    #[test]
    fn inputs_had_for_a_range_that_was_refused_do_not_pile_up() {
        let (_scratch, node, replica) = limited("pile", |cfg| ReplicaConfig { tries: 2, ..cfg });
        let topics = vec![keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)"), word(&STAR.to_be_bytes())];
        // Poll after poll, the node answers with a block whose batch has an empty input, and
        // which is then refused (another transaction's logs on both sides of it). The input
        // costs nothing against the room for inputs, so only letting it go keeps it from
        // piling up.
        for round in 0..20u8 {
            node.with(|chain| {
                chain.forget(41);
                chain.add_in([round; 32], 41, AZIMUTH, topics.clone(), keys(0x52, 2));
                chain.add_in([0xe0 ^ round; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
                chain.inputs.insert([0xe0 ^ round; 32], (41, vec![]));
                chain.add_in([round; 32], 41, AZIMUTH, topics.clone(), keys(0x53, 3));
                chain.finalized = 45;
            });
            assert!(replica.poll().unwrap_err().contains("in block 41"));
        }
        assert!(lock(&replica.inner.fetched).inputs.len() <= 1, "{}", lock(&replica.inner.fetched).inputs.len());
    }

    #[test]
    fn inputs_are_taken_in_one_at_a_time_against_the_room_there_is() {
        // Asked for one at a time, five inputs of 139 bytes, with room for 300 bytes: the
        // third would pass the room, so the fetching stops there, and the range is read in
        // smaller pieces. No range has more than three inputs asked for.
        let (_scratch, node, replica) = limited("admit", |cfg| ReplicaConfig { most_batch_bytes: 300, ..cfg });
        node.with(|chain| {
            chain.together = false;
            for at in 0..5u32 {
                chain.batch(41 + at as u64, &[new_keys(1 + at)]);
            }
            chain.finalized = 45;
            chain.asked.clear();
        });
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET).0, 6);
        node.with(|chain| {
            let (mut most, mut now) = (0, 0);
            for (method, _) in &chain.asked {
                match method.as_str() {
                    "eth_getLogs" => now = 0,
                    "eth_getTransactionByHash" => {
                        now += 1;
                        most = most.max(now);
                    }
                    _ => {}
                }
            }
            assert!(most <= 3, "{most} inputs asked for in one try");
        });
    }

    #[test]
    fn a_lookup_refused_before_the_node_has_answered_says_why() {
        let scratch = Scratch::new("never-heard");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
            chain.failing.insert("eth_getBlockByNumber".into(), 100);
        });
        let replica = Replica::open(&scratch.file(), ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        assert!(replica.poll().is_err());
        let refused = replica.listing(PLANET).unwrap_err();
        assert!(refused.contains("not yet heard") && refused.contains("held up") && refused.contains("500"), "{refused}");
    }

    #[test]
    fn two_inputs_for_one_transaction_in_one_block_are_refused() {
        let placed = Placed { block: 41, hash: [1; 32], index: 0 };
        let mut fetched = Fetched::default();
        fetched.keep([7; 32], placed, vec![1, 2, 3]).unwrap();
        fetched.keep([7; 32], placed, vec![1, 2, 3]).unwrap();
        assert!(matches!(fetched.keep([7; 32], placed, vec![1, 2, 4]), Err(Trouble::Wrong(_))));
        assert_eq!(fetched.inputs[&[7; 32]].1.as_slice(), [1, 2, 3]);
        // Had for another block, it is another answer, and takes the place of the first.
        fetched.keep([7; 32], Placed { block: 42, hash: [2; 32], index: 0 }, vec![9]).unwrap();
        assert_eq!((fetched.inputs[&[7; 32]].1.as_slice(), fetched.bytes), ([9].as_slice(), 1));
    }

    #[test]
    fn one_block_hash_for_two_blocks_is_refused() {
        let scratch = Scratch::new("heights");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        node.with(|chain| {
            chain.azimuth(41, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, keys(0x52, 2));
            chain.azimuth(42, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, keys(0x53, 3));
            chain.logs.last_mut().unwrap().block_hash = block_hash(41);
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("of two blocks"));
        assert_eq!(replica.status().read_to, 40);
        assert_eq!(file_revision(&path, STAR), Some(1));
        node.with(|chain| chain.logs.last_mut().unwrap().block_hash = block_hash(42));
        replica.poll().unwrap();
        assert_eq!(revision(&replica, STAR), (3, key(0x53)));
    }

    #[test]
    fn dropping_the_copy_stops_it_promptly_among_unreadable_batches() {
        let scratch = Scratch::new("unreadable");
        let path = scratch.file();
        let node = Node::start();
        // One input of seven thousand transactions with one that cannot be read at its
        // front, which is read last: each time it is applied it is read nearly to the end
        // and then given up, without a ship being looked at. Four thousand batch logs of one
        // transaction share it.
        let planet = wallet(3);
        let one = signed(&planet.0, 0, PLANET, Proxy::Owner, Action::SetTransferProxy([5; 20]));
        // Read from the end back, the last transaction is a signature, a role, a ship, and
        // then a kind of transaction (11) that there is not.
        let mut input = [vec![0x0b], 0x0001_0100u32.to_be_bytes().to_vec(), vec![0], vec![1; 65]].concat();
        input.extend(one.iter().copied().cycle().take(one.len() * 7000));
        node.with(|chain| {
            history(chain);
            for _ in 0..4000 {
                chain.add_in([0x61; 32], 41, NAIVE, vec![naive::batch_topic()], vec![]);
            }
            chain.inputs.insert([0x61; 32], (41, input.clone()));
            chain.finalized = 40;
        });
        assert!(naive::parse_batch(&input).is_none());
        // One block: applied whatever its work, which takes seconds.
        let replica = Replica::open(&path, node.config()).unwrap();
        replica.poll().unwrap();
        let counts = replica.status().counts;
        node.with(|chain| chain.finalized = 45);
        replica.keep_up();
        let started = std::time::Instant::now();
        while node.with(|chain| chain.methods("eth_getTransactionByHash").iter().filter(|params| params[0] == hex(&[0x61; 32]).as_str()).count()) < 1 {
            assert!(started.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        let started = std::time::Instant::now();
        drop(replica);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        let replica = Replica::open(&path, node.config()).unwrap();
        assert_eq!((replica.status().read_to, replica.status().counts), (40, counts));
    }

    #[test]
    fn a_file_is_owned_under_its_true_name() {
        let scratch = Scratch::new("names");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let first = Replica::open(&scratch.file(), node.config()).unwrap();
        first.poll().unwrap();
        // Another name for the same file, by a link to it, or a link to its directory: the
        // same lock, so refused.
        let link = scratch.0.join("link.sqlite");
        std::os::unix::fs::symlink(scratch.file(), &link).unwrap();
        assert!(Replica::open(&link, node.config()).unwrap_err().contains("in use by another copy"));
        let directory = scratch.0.join("again");
        std::os::unix::fs::symlink(&scratch.0, &directory).unwrap();
        assert!(Replica::open(&directory.join("azimuth.sqlite"), node.config()).unwrap_err().contains("in use by another copy"));
        drop(first);
        // Opened by the link, it is the same file.
        let by_link = Replica::open(&link, node.config()).unwrap();
        assert_eq!(by_link.status().read_to, 40);
        drop(by_link);
        // A second name of the file's own (a hard link) could be locked apart: refused.
        let hard = scratch.0.join("hard.sqlite");
        std::fs::hard_link(scratch.file(), &hard).unwrap();
        assert!(Replica::open(&scratch.file(), node.config()).unwrap_err().contains("more than one name"));
        assert!(Replica::open(&hard, node.config()).unwrap_err().contains("more than one name"));
        std::fs::remove_file(&hard).unwrap();
        assert!(Replica::open(&scratch.file(), node.config()).is_ok());
        // A link put in place after the name was worked out is not followed when the file
        // is opened, for writing or for reading.
        let directory = std::fs::canonicalize(&scratch.0).unwrap();
        let late = directory.join("late.sqlite");
        std::os::unix::fs::symlink(directory.join("azimuth.sqlite"), &late).unwrap();
        assert!(connect(&late, false).unwrap_err().contains("could not be read or written"));
        assert!(connect(&late, true).is_err());
        assert!(connect(&directory.join("azimuth.sqlite"), false).is_ok());
        assert!(connect(&directory.join("azimuth.sqlite"), true).is_ok());
        // A link to nothing yet is refused, rather than making the file under another name.
        let dangling = scratch.0.join("dangling.sqlite");
        std::os::unix::fs::symlink(scratch.0.join("not-yet.sqlite"), &dangling).unwrap();
        assert!(Replica::open(&dangling, node.config()).unwrap_err().contains("does not exist"));
    }

    #[test]
    fn dropping_the_copy_stops_it_promptly_while_it_is_applying() {
        let scratch = Scratch::new("applying");
        let path = scratch.file();
        let node = Node::start();
        // Thirty batches of a thousand transactions each, all signed with a signature
        // made for something else: each is checked, which takes a curve operation, and
        // none is done. Checking them all takes seconds.
        let stranger = wallet(9);
        let one = signed(&stranger.0, 0, PLANET, Proxy::Owner, configure(0x99));
        let mut wrong = written(PLANET, Proxy::Owner, &configure(0x98));
        wrong.extend_from_slice(&one[one.len() - 65..]);
        node.with(|chain| {
            history(chain);
            for at in 0..30 {
                chain.batch(41 + at, &vec![wrong.clone(); 1000]);
            }
            chain.finalized = 80;
        });
        let replica = Replica::open(&path, ReplicaConfig { most_batch_bytes: 16 << 20, most_work_bytes: 16 << 20, ..node.config() }).unwrap();
        node.with(|chain| chain.finalized = 40);
        replica.poll().unwrap();
        let counts = replica.status().counts;
        node.with(|chain| chain.finalized = 80);
        replica.keep_up();
        let started = std::time::Instant::now();
        while node.with(|chain| chain.methods("eth_getTransactionByHash").len()) < 32 {
            assert!(started.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        let started = std::time::Instant::now();
        drop(replica);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        // Nothing of the step was written.
        let replica = Replica::open(&path, node.config()).unwrap();
        assert_eq!((replica.status().read_to, replica.status().counts), (40, counts));
    }

    #[test]
    fn dropping_the_copy_stops_it_promptly_while_it_is_reading() {
        let star = wallet(2);
        // Sixty batches in sixty blocks, asked for one at a time: once with three seconds
        // between questions, once with a node that takes a third of a second over each
        // answer and no pause. Either way it would take a good while to read them all.
        for (pause, slow) in [(Duration::from_secs(3), Duration::ZERO), (Duration::ZERO, Duration::from_millis(300))] {
            let scratch = Scratch::new("stop");
            let node = Node::start();
            node.with(|chain| {
                history(chain);
                for at in 0..60u32 {
                    chain.batch(26 + at as u64, &[signed(&star.0, 1 + at, STAR, Proxy::Owner, Action::Spawn { ship: (2 + at) << 16 | STAR, to: star.1 })]);
                }
                chain.together = false;
                chain.finalized = 100;
                chain.slow = slow;
            });
            let replica = Replica::open(&scratch.file(), ReplicaConfig { pause, ..node.config() }).unwrap();
            replica.keep_up();
            let started = std::time::Instant::now();
            while node.with(|chain| chain.methods("eth_getTransactionByHash").len()) < 2 {
                assert!(started.elapsed() < Duration::from_secs(30));
                std::thread::sleep(Duration::from_millis(10));
            }
            let started = std::time::Instant::now();
            drop(replica);
            assert!(started.elapsed() < Duration::from_secs(1), "{:?} with a pause of {pause:?}", started.elapsed());
            let asked = node.with(|chain| chain.methods("eth_getTransactionByHash").len());
            assert!(asked < 10, "{asked}");
            std::thread::sleep(Duration::from_millis(700));
            assert_eq!(node.with(|chain| chain.methods("eth_getTransactionByHash").len()), asked, "nothing is asked after the copy is dropped");
        }
    }

    #[test]
    fn batches_too_big_to_hold_at_once_are_read_in_smaller_ranges() {
        let scratch = Scratch::new("bytes");
        let path = scratch.file();
        let node = Node::start();
        let planet = wallet(3);
        node.with(|chain| {
            history(chain);
            for at in 0..6u32 {
                chain.batch(30 + at as u64, &[signed(&planet.0, 1 + at, PLANET, Proxy::Owner, configure(0x90 + at as u8))]);
            }
            chain.finalized = 40;
        });
        // Room for about two of these batches at a time.
        let replica = Replica::open(&path, ReplicaConfig { most_batch_bytes: 300, ..node.config() }).unwrap();
        replica.poll().unwrap();
        assert_eq!(revision(&replica, PLANET), (7, key(0x95)));
        assert_eq!(replica.status().counts.batches, 8);
        drop(replica);
        // Room for none, even for one block alone, which only a broken node could need:
        // nothing can be read, and nothing is written.
        node.with(|chain| {
            chain.batch(41, &[signed(&planet.0, 7, PLANET, Proxy::Owner, configure(0x99))]);
            chain.finalized = 45;
        });
        let replica = Replica::open(&path, ReplicaConfig { most_batch_bytes: 50, most_block_batch_bytes: 50, ..node.config() }).unwrap();
        assert!(replica.poll().unwrap_err().contains("more than is held"));
        assert_eq!(replica.status().read_to, 40);
    }

    #[test]
    fn a_step_that_fails_part_way_writes_nothing() {
        let scratch = Scratch::new("halfway");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        replica.poll().unwrap();
        let counts = replica.status().counts;
        // A ship whose row in the file has been damaged: its count of new starts is more than
        // a count can be. Then a good log, and one about that ship. Both in one step: the
        // first is applied before the second fails to read the ship.
        let damaged = 0x0200u32;
        Connection::open(&path)
            .unwrap()
            .execute(
                "insert into points select ?1, dominion, owner, owner_nonce, spawn_proxy, spawn_nonce, management_proxy, management_nonce, voting_proxy, voting_nonce, transfer_proxy, transfer_nonce, 1099511627776, revision, suite, authentication, encryption, has_sponsor, sponsor, escape_to from points where ship = ?2",
                [damaged, STAR],
            )
            .unwrap();
        node.with(|chain| {
            chain.azimuth(41, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, keys(0x52, 2));
            chain.azimuth(42, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", damaged, None, keys(0x53, 1));
            chain.finalized = 45;
        });
        assert!(replica.poll().unwrap_err().contains("damaged"));
        drop(replica);
        let file = Connection::open(&path).unwrap();
        let read_to: i64 = file.query_row("select value from meta where name = 'read to'", [], |row| row.get(0)).unwrap();
        let logs: i64 = file.query_row("select value from meta where name = 'logs'", [], |row| row.get(0)).unwrap();
        assert_eq!((read_to, logs as u64), (40, counts.logs));
        drop(file);
        assert_eq!(file_revision(&path, STAR), Some(1));
        let replica = Replica::open(&path, node.config()).unwrap();
        assert_eq!((replica.status().read_to, replica.status().counts), (40, counts));
    }
}
