//! A copy of Azimuth's state, kept on this machine and worked out from Ethereum alone.
//!
//! `crate::azimuth` asks Ethereum about one ship at a time, and for a ship on layer 2 asks
//! Urbit's roller and takes its word. This instead does what every Urbit ship does for
//! itself: it reads every log the Azimuth contract has written and every batch sent to the
//! layer 2 contract, in the order Ethereum has them, and works out the state of every ship
//! from them under Urbit's own rules (`urbit_id::naive`). Only the Ethereum node is trusted.
//!
//! The state is kept in one SQLite file: a table of points, and how far the file has read, the
//! hash of that block, what the file is a copy of, and counts of what was read.
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
//!
//! Beside the number of the block it has read to, the file keeps that block's hash, as the
//! node gave it for a block it had said was final, written in the same step. At the start of
//! every run, before anything is applied or answered, the node is asked for that block's hash
//! again: if they differ, the node follows another chain, or the file (or the snapshot it was
//! made from) is wrong, and nothing is read, written or answered until they agree. A file made
//! before the hash was kept learns it the next time it moves forward, and until then is used
//! as before.
//!
//! What the node says in a poll is held against what it says later only once that poll has
//! succeeded, so a wrong answer in a poll that failed never holds back a right one.
//!
//! A copy can also be started from a snapshot (`snapshot`) instead of from the beginning of
//! Azimuth's history, and then catches up from the snapshot's block as usual. When a snapshot
//! is asked for, something at the copy's name that is not a copy is refused, not set up as one.
//!
//! A file that is not there is made only when nothing SQLite would take as part of it (the
//! same name with `-wal`, `-shm` or `-journal` added) is there either; a file that is there is
//! handed to SQLite only if it, and each of those beside it, is a plain file with one name.
//! The numbers in `meta` (the block read to and the six counts) are whole numbers from 0 to
//! 2^63 - 1; a count stops there; anything else is a damaged file.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use urbit_id::naive::{self, Dominion, Holder, NetKeys, Outcome, Point, Points};

use crate::azimuth::{listed, Keys, Listing};
use crate::chain::{hex, Block, Ethereum, Limits, Log, Placed, Stop, Trouble};

pub mod snapshot;

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
    /// The last block to read, for a copy that is to stop short of the end of the chain: to
    /// make a snapshot at exactly that block, such as to check one someone else made. It must
    /// be final to be read; until it is, the copy reads as far as is final and waits. A copy
    /// told to stop never counts as caught up, and answers no lookups.
    pub until: Option<u64>,
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
            until: None,
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

/// Blocks as the node has given them, each a number and a hash: one number never has two
/// hashes, and one hash is never of two numbers, wherever the node gave them. Every pair the
/// node gives in a poll goes through one of these: the final block, the block the file had read
/// to when the run began, the last block of each range, and the block of every log in that
/// range (and so of every batch's transaction, which must be in its log's block). It holds the
/// poll's block answers and, for one range at a time, the blocks of that range, so it is never
/// bigger than a range's answers.
#[derive(Clone, Default)]
struct Blocks {
    hashes: HashMap<u64, [u8; 32]>,
    numbers: HashMap<[u8; 32], u64>,
}

impl Blocks {
    fn see(&mut self, number: u64, hash: [u8; 32]) -> Result<(), Trouble> {
        if self.hashes.insert(number, hash).is_some_and(|before| before != hash) {
            return Err(Trouble::Wrong(format!("block {number} is said to have two hashes")));
        }
        if self.numbers.insert(hash, number).is_some_and(|before| before != number) {
            return Err(Trouble::Wrong(format!("block hash {} is said to be of two blocks", hex(&hash))));
        }
        Ok(())
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
    /// Whether the hash of the block the file had read to when it was opened has been found to
    /// be the node's, in this run. Nothing is applied or answered before.
    checked: AtomicBool,
    /// The final block as the node gave it in the last poll that succeeded: the next poll's
    /// final block must not be behind it, and its blocks must be one chain with it. Only a
    /// poll that succeeded is remembered, so a wrong answer in one that failed never holds a
    /// later right one back.
    last_final: Mutex<Option<Block>>,
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
fn connect(path: &Path, access: Access) -> Result<Connection, String> {
    open_with(path, access).map_err(sql)
}

/// The same, keeping SQLite's own error, for a caller that tells one kind from another.
fn open_with(path: &Path, access: Access) -> rusqlite::Result<Connection> {
    let how = match access {
        Access::Read => OpenFlags::SQLITE_OPEN_READ_ONLY,
        Access::Make => OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        Access::Write => OpenFlags::SQLITE_OPEN_READ_WRITE,
    };
    Connection::open_with_flags(path, how | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW)
}

/// SQLite's answer to a database opened only to read that has a change left unfinished by a
/// crash beside it (a hot rollback journal): undoing that change is a write, which only a
/// connection that may write can make.
const SQLITE_READONLY_ROLLBACK: i32 = 776;

/// The extended code of an SQLite error, if it is one.
fn sqlite_code(error: &rusqlite::Error) -> Option<i32> {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => Some(failure.extended_code),
        _ => None,
    }
}

/// The first sixteen bytes of every SQLite database.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// How a file is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    /// To read it only.
    Read,
    /// To read and write it, making it if it is not there.
    Make,
    /// To read and write it, and it must be there already.
    Write,
}

/// The ends of the names of the files SQLite keeps beside a database while it is used: its
/// write-ahead log, the memory that log is shared through, and its rollback journal. SQLite
/// takes whatever it finds under those names as part of the database of that name, and plays
/// a log or journal it finds there over the database when it opens it.
const BESIDE: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The same name with `suffix` added.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Before a database is made where there is none: refuse while any file SQLite would take as
/// part of it is there (one left by an earlier copy whose file was removed, say), since its old
/// pages would be played over the new file. None of them is touched.
fn none_beside(path: &Path) -> Result<(), String> {
    let found: Vec<String> = BESIDE.iter().map(|end| beside(path, end)).filter(|name| fs::symlink_metadata(name).is_ok()).map(|name| name.display().to_string()).collect();
    if found.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} is not there, but {} is, left perhaps by an earlier copy, and SQLite would take it as part of a new file of that name. Remove it, then try again",
        path.display(),
        found.join(" and ")
    ))
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

/// What became of a snapshot a copy was asked to start from.
#[derive(Debug)]
pub enum Restored {
    /// There was no copy, and it was made from the snapshot.
    Made(snapshot::Summary),
    /// There was a copy already, so the snapshot was not used. A copy is never replaced.
    Ignored,
}

/// What a file is a copy of: the chain and the two contracts, each from the block it was made
/// in. A file made for one is never read as another's, and a snapshot made for one is never
/// restored as another's.
fn made_for(cfg: &ReplicaConfig) -> String {
    format!("chain {}, azimuth {} from block {}, naive {} from block {}", cfg.chain, hex(&cfg.azimuth), cfg.azimuth_from, hex(&cfg.naive), cfg.naive_from)
}

/// Before a database that is there is handed to SQLite: each file SQLite keeps beside it that
/// is there must be a plain file with one name, SQLite's own. SQLite opens those and writes to
/// them, even for a database opened only to read, so through a link, a second name of another
/// file, or something that is not a plain file, it would write to something else. None is
/// touched. This covers what is in place when the copy is opened; another program writing in
/// the directory meanwhile is not defended against.
fn plain_beside(path: &Path) -> Result<(), String> {
    for end in BESIDE {
        let name = beside(path, end);
        let found = match fs::symlink_metadata(&name) {
            Ok(found) => found,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("cannot look at {}: {e}", name.display())),
        };
        let what = if found.file_type().is_symlink() {
            "a link"
        } else if !found.file_type().is_file() {
            "not a plain file"
        } else if found.nlink() > 1 {
            "a file with more than one name (a hard link)"
        } else {
            continue;
        };
        return Err(format!(
            "{} is {what}, and SQLite would write through it as part of {}, to whatever it is. Remove it, then try again",
            name.display(),
            path.display()
        ));
    }
    Ok(())
}

/// What is at a copy's name, as far as can be told, and whether SQLite undid a change a crash
/// had left unfinished in it while it was looked at (see `found_at`).
enum Found {
    /// A copy of Azimuth: it keeps a record of what it is a copy of.
    Copy,
    /// Certainly not one, and why: empty, not an SQLite database, or one that reads cleanly
    /// and keeps no such record.
    NotCopy { what: &'static str, recovered: bool },
    /// It could not be read to tell, with SQLite's own error.
    Unreadable { why: String, recovered: bool },
    /// It has a change a crash left unfinished, and could not be opened to undo it, with the
    /// error that stopped that. Nothing was undone and nothing was changed.
    Unfinished(String),
}

/// Whether a database keeps a copy's record of what it is a copy of. Only a table or a row
/// that is not there is taken for absence; any error reading is an error.
fn keeps_record(connection: &Connection) -> rusqlite::Result<bool> {
    let tables: i64 = connection.query_row("select count(*) from sqlite_master where type = 'table' and name = 'meta'", [], |row| row.get(0))?;
    if tables == 0 {
        return Ok(false);
    }
    let records: i64 = connection.query_row("select count(*) from meta where name = 'made for'", [], |row| row.get(0))?;
    Ok(records > 0)
}

/// Look at what is at the copy's name, writing nothing to it, but for one thing: a database
/// with a change a crash left unfinished (a hot journal beside it) cannot be read by a
/// connection that may only read, and is opened once to write, without the right to make a
/// file, so that SQLite undoes that change as any opening would, and then looked at again.
/// That is done only for a file that begins as every SQLite database does: a file that is not
/// one is never handed to a connection that may write.
fn found_at(path: &Path) -> Result<Found, String> {
    let mut start = [0; 16];
    let mut file = fs::File::open(path).map_err(|e| format!("cannot look at {}: {e}", path.display()))?;
    let mut read = 0;
    while read < start.len() {
        match file.read(&mut start[read..]).map_err(|e| format!("cannot read {}: {e}", path.display()))? {
            0 => break,
            more => read += more,
        }
    }
    drop(file);
    if read == 0 {
        return Ok(Found::NotCopy { what: "is empty", recovered: false });
    }
    if read < start.len() || start != *SQLITE_HEADER {
        return Ok(Found::NotCopy { what: "is not an SQLite database", recovered: false });
    }
    let look = |access| open_with(path, access).and_then(|opened| keeps_record(&opened));
    let (looked, recovered) = match look(Access::Read) {
        Err(e) if sqlite_code(&e) == Some(SQLITE_READONLY_ROLLBACK) => {
            // SQLite opens a file it may not write to for reading only, without saying so: a
            // connection that came back that way, or a look that still finds it may only read,
            // undid nothing.
            let opened = match open_with(path, Access::Write) {
                Ok(opened) => opened,
                Err(e) => return Ok(Found::Unfinished(e.to_string())),
            };
            if opened.is_readonly(rusqlite::DatabaseName::Main).unwrap_or(true) {
                return Ok(Found::Unfinished("it could not be opened to write".to_string()));
            }
            match keeps_record(&opened) {
                Err(e) if matches!(&e, rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ReadOnly) => return Ok(Found::Unfinished(e.to_string())),
                looked => (looked, true),
            }
        }
        looked => (looked, false),
    };
    Ok(match looked {
        Ok(true) => Found::Copy,
        Ok(false) => Found::NotCopy { what: "keeps no record of what it is a copy of", recovered },
        Err(e) => Found::Unreadable { why: e.to_string(), recovered },
    })
}

/// Whether the file that is there is a copy of Azimuth. When a snapshot is asked for, anything
/// else at the copy's name (an empty file, a file whose first start was cut short, some other
/// database) is not taken for a copy, set up afresh and read from the beginning: it is refused,
/// and left as it is. One that cannot be read to tell is refused too, with SQLite's own error,
/// and how to go on.
fn is_a_copy(given: &Path, path: &Path) -> Result<(), String> {
    let remove = "remove it, and any file of the same name with -wal, -shm or -journal added";
    // What was done to it while it was looked at: nothing, or only what any opening of it does.
    let done = |recovered: bool| {
        if recovered {
            "SQLite undid a change a crash had left unfinished in it, as any opening of it would have done; nothing else was changed"
        } else {
            "It has been left as it is"
        }
    };
    match found_at(path)? {
        Found::Copy => Ok(()),
        Found::NotCopy { what, recovered } => {
            // Only a file an ordinary start can make a copy of is pointed there.
            let first_start = if what == "is not an SQLite database" {
                ""
            } else {
                " (If it is a copy whose first start was cut short, which keeps no record yet, starting once without --azimuth-snapshot finishes it as a copy read from the beginning.)"
            };
            Err(format!("{} is there, but {what}, so it is not a copy of Azimuth. {}: {remove}, for the snapshot to be used.{first_start}", given.display(), done(recovered)))
        }
        Found::Unfinished(why) => Err(format!(
            "{} is there, with a change a crash left unfinished (a -journal beside it), which could not be undone: {why}. Nothing was changed. If it is a copy, an ordinary start (without --azimuth-snapshot) undoes that change once the file can be written to; or {remove}, for the snapshot to be used",
            given.display()
        )),
        Found::Unreadable { why, recovered } => {
            let way_on = if recovered {
                // The change a crash left unfinished has been undone already, and it still
                // cannot be read: an ordinary start would meet the same.
                format!("The file is damaged: {remove}, to start again from the snapshot or from the beginning")
            } else {
                format!("If the trouble is a change a crash left unfinished, an ordinary start (without --azimuth-snapshot) will finish it; otherwise the file is damaged: {remove}, to start again from the snapshot or from the beginning")
            };
            Err(format!("{} is there, but could not be read to tell whether it is a copy of Azimuth: {why}. {}. {way_on}", given.display(), done(recovered)))
        }
    }
}

/// How a copy is being opened.
enum Opening<'a> {
    /// There is no file: it is made, as a copy that has read nothing.
    New,
    /// There is a file: it is opened as it is, and must still be there.
    There,
    /// The file was just made from the snapshot this describes: it must still be there, and
    /// must be what was made.
    Restored(&'a snapshot::Summary),
}

/// Whether there is a file at `path`, its true name. A file being there is never replaced; a
/// file not being there is made only when nothing SQLite would take as part of it is there.
fn is_there(given: &Path, path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(found) => {
            // Something there that is not a plain file (a directory, a pipe) is not a copy, and
            // SQLite could wait for ever on some of them.
            if !found.file_type().is_file() {
                return Err(format!("{} is there, but is not a plain file, so it is not a copy of Azimuth; it has been left as it is", given.display()));
            }
            plain_beside(path)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            none_beside(path)?;
            Ok(false)
        }
        Err(e) => Err(format!("cannot find {}: {e}", given.display())),
    }
}

impl Replica {
    /// Open the copy kept in `path`, or start one there. Nothing is asked of Ethereum yet.
    pub fn open(path: &Path, cfg: ReplicaConfig) -> Result<Replica, String> {
        let given = path;
        let path = &true_name(given)?;
        let owned = own(path)?;
        let opening = if is_there(given, path)? { Opening::There } else { Opening::New };
        Replica::open_owned(given, path, owned, cfg, opening)
    }

    /// Open the copy kept in `path`; if there is none, first make it from the snapshot in
    /// `from`, which must have the fingerprint `sha256` if one is given. A copy that is there
    /// already is opened as it is, and the snapshot is not read.
    ///
    /// The copy is made under the same lock as any copy is opened under, so no other copy can
    /// be made or opened there meanwhile, and it is made whole under a name of its own and then
    /// given its name, so that whatever happens part way, the next start finds either no copy
    /// (and makes it again) or a whole one.
    pub fn open_from_snapshot(path: &Path, cfg: ReplicaConfig, from: &Path, sha256: Option<[u8; 32]>) -> Result<(Replica, Restored), String> {
        // Where snapshots cannot be restored, nothing is made or opened, not even the lock.
        snapshot::supported()?;
        let given = path;
        let path = &true_name(given)?;
        let owned = own(path)?;
        if is_there(given, path)? {
            is_a_copy(given, path)?;
            return Ok((Replica::open_owned(given, path, owned, cfg, Opening::There)?, Restored::Ignored));
        }
        let made = snapshot::restore(path, &cfg, from, sha256)?;
        snapshot::step_in(from, "placed", path);
        plain_beside(path)?;
        let replica = Replica::open_owned(given, path, owned, cfg, Opening::Restored(&made))?;
        Ok((replica, Restored::Made(made)))
    }

    /// Open the copy at `path`, its true name, with the file already taken for this copy alone.
    fn open_owned(given: &Path, path: &Path, owned: fs::File, cfg: ReplicaConfig, opening: Opening) -> Result<Replica, String> {
        let writer = connect(path, if matches!(opening, Opening::New) { Access::Make } else { Access::Write })?;
        // A copy just made from a snapshot is read back before anything is written to it: the
        // file at its name must be the one that was made.
        if let Opening::Restored(made) = opening {
            check_made(&writer, &cfg, given, made)?;
        }
        // Readers do not wait for the writer, and the writer does not wait for the disk on
        // every step: a step lost to a power cut is read again.
        writer.pragma_update(None, "journal_mode", "wal").map_err(sql)?;
        writer.pragma_update(None, "synchronous", "normal").map_err(sql)?;
        writer.busy_timeout(Duration::from_secs(10)).map_err(sql)?;
        writer.execute_batch(SCHEMA).map_err(sql)?;
        // A file made for one chain and pair of contracts is never read as another's.
        let made_for = made_for(&cfg);
        let found: Option<String> = writer.query_row("select value from meta where name = 'made for'", [], |row| row.get(0)).optional().map_err(sql)?;
        match found {
            Some(found) if found != made_for => return Err(format!("{} is a copy of another Azimuth ({found})", given.display())),
            Some(_) => {}
            None => {
                let starting = writer.unchecked_transaction().map_err(sql)?;
                starting.execute("insert into meta (name, value) values ('made for', ?1)", [&made_for]).map_err(sql)?;
                keep_number(&starting, "read to", start(&cfg))?;
                for name in COUNTS {
                    keep_number(&starting, name, 0)?;
                }
                starting.commit().map_err(sql)?;
            }
        }
        let read_to = read_to(&writer)?;
        let counts = read_counts(&writer, &cfg)?;
        let reader = connect(path, Access::Read)?;
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
            checked: AtomicBool::new(false),
            last_final: Mutex::new(None),
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

    /// Whether a copy told to stop at a block has read to it, with this run's check of the
    /// file's block hash passed and that block final. A copy that is already at the block when
    /// it is opened has not got there in this run until the node has agreed with it. Never,
    /// for a copy not told to stop.
    pub fn reached_until(&self) -> bool {
        let status = lock(&self.inner.status);
        self.inner.cfg.until.is_some_and(|until| status.read_to >= until && status.finalized.is_some_and(|finalized| finalized >= until))
    }

    /// Whether lookups are answered: the file's block hash has been found to be the node's,
    /// and the file has reached the newest finalised block heard of in this run. Never, for a
    /// copy told to stop at a block.
    pub fn caught_up(&self) -> bool {
        behind(&lock(&self.inner.status), self.inner.cfg.until).is_none()
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
        if let Some(why) = behind(&status, self.inner.cfg.until) {
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

/// Why lookups are not answered yet, if they are not. The newest finalised block is only
/// taken into the status once the file's block hash has been found to be the node's, so a
/// copy whose hash is not yet checked, or is wrong, has heard of no finalised block, and
/// answers nothing.
fn behind(status: &Status, until: Option<u64>) -> Option<String> {
    if let Some(until) = until {
        return Some(format!(
            "the copy of Azimuth was told to stop at block {until}, short of the end of the chain, so it answers no lookups; it has read to block {}",
            status.read_to
        ));
    }
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
        let read_to = self.read_to();
        // A node whose finalised block goes back, behind one it gave in a poll that succeeded,
        // does not know its own chain, and is not followed. (Behind one it gave only in a poll
        // that then failed is not held against it: that one may have been the wrong answer.)
        let before = *lock(&self.last_final);
        if let Some(before) = before.filter(|before| finalized.number < before.number) {
            return Err(format!("Ethereum says the chain is final to block {}, behind block {}, which it said before", finalized.number, before.number));
        }
        // One behind what the file has read is waited for: a node not yet caught up with the
        // chain, or a copy made from a snapshot newer than what the node has finalised.
        if finalized.number < read_to {
            return Err(format!("Ethereum says the chain is final to block {}, behind block {read_to}, which the file has read; this waits until it is final there", finalized.number));
        }
        if let Some(until) = self.cfg.until.filter(|until| read_to > *until) {
            return Err(format!("the file has read to block {read_to} already, past block {until}, where it was told to stop; it cannot go back"));
        }
        // The final block given in the last poll that succeeded, and this one, are one chain
        // with everything else given in this poll.
        let mut answers = Blocks::default();
        if let Some(before) = before {
            answers.see(before.number, before.hash).map_err(|trouble| trouble.why().to_string())?;
        }
        answers.see(finalized.number, finalized.hash).map_err(|trouble| trouble.why().to_string())?;
        // Once each run, before anything is applied or answered: the block the file has read
        // to must be the node's. Nothing is written either way, and a later poll asks again.
        // Passing is remembered for the run, since it is the file's own hash that was matched.
        if !self.checked.load(Ordering::SeqCst) {
            if let Some(kept) = read_to_hash(writer)? {
                let said = if read_to == finalized.number { finalized.hash } else { self.asking(|| self.ethereum.block(read_to))?.hash };
                answers.see(read_to, said).map_err(|trouble| trouble.why().to_string())?;
                if said != kept {
                    return Err(format!(
                        "Ethereum says block {read_to}, which the file has read to, has the hash {}, but the file has {}: the node follows another chain, or the file is wrong. Nothing is read or answered until they agree. If the file was made from a snapshot, remove it, and any file of the same name with -wal, -shm or -journal added, to try another",
                        hex(&said),
                        hex(&kept)
                    ));
                }
            }
            self.checked.store(true, Ordering::SeqCst);
        }
        // Taken into the status at once, so that lookups wait while the file catches up to it;
        // remembered for the next poll only once this one has succeeded.
        lock(&self.status).finalized = Some(finalized.number);
        let target = self.cfg.until.map_or(finalized.number, |until| until.min(finalized.number));
        self.catch_up(writer, target, &finalized, &answers)?;
        *lock(&self.last_final) = Some(finalized);
        Ok(())
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

    /// Read forward to `target`, one step at a time, each step one transaction. `finalized` is
    /// the finalised block heard of in this poll, at or past `target`, and `answers` the blocks
    /// the node has given in this poll so far.
    fn catch_up(&self, writer: &mut Connection, target: u64, finalized: &Block, answers: &Blocks) -> Result<(), String> {
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
            match self.step(from, to, finalized, answers) {
                Ok((events, hash)) => {
                    self.grow_if_small(&events);
                    self.commit(writer, from, to, &hash, &events)?;
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

    /// Everything to apply from blocks `from` to `to`, in order, and the hash of block `to`,
    /// which the file keeps once they are applied: the node's word for a block at or before
    /// the finalised one (`finalized`). Every block the range's logs name, block `to` as the
    /// node gives it, and the blocks it has given in this poll before (`answers`) are one
    /// chain: no number with two hashes, no hash of two numbers.
    fn step(&self, from: u64, to: u64, finalized: &Block, answers: &Blocks) -> Result<(Vec<Event>, [u8; 32]), Trouble> {
        let mut blocks = answers.clone();
        let events = self.events(from, to, &mut blocks)?;
        let hash = if to == finalized.number { finalized.hash } else { self.ethereum.block(to)?.hash };
        blocks.see(to, hash)?;
        Ok((events, hash))
    }

    /// Everything to apply from blocks `from` to `to`, in order. The block of every log is
    /// seen in `blocks`.
    fn events(&self, from: u64, to: u64, blocks: &mut Blocks) -> Result<Vec<Event>, Trouble> {
        let cfg = &self.cfg;
        let mut events = Vec::new();
        // Which block each transaction is in, as the logs of both contracts say, and each
        // log's block, with the blocks given before. One transaction in two blocks, or one
        // block number with two hashes, is a node contradicting itself. (Several logs from one
        // transaction, in its block, are as they should be.)
        let mut placed: HashMap<[u8; 32], u64> = HashMap::new();
        let mut place = |log: &Log| {
            if let Some(before) = placed.insert(log.transaction, log.block).filter(|before| *before != log.block) {
                return Err(Trouble::Wrong(format!("transaction {} is said to be in block {before} and in block {}", hex(&log.transaction), log.block)));
            }
            blocks.see(log.block, log.block_hash)
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

    /// Apply one step's events to the file and move its high-water mark, with the hash of the
    /// block it now reaches, all in one transaction.
    fn commit(&self, writer: &mut Connection, from: u64, to: u64, hash: &[u8; 32], events: &[Event]) -> Result<(), String> {
        // Begun for writing at once, so that anything else writing the same file waits, and
        // then finds the file has moved on and that this step would be a repeat.
        let transaction = writer.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
        if Some(read_to(&transaction)?) != from.checked_sub(1) {
            return Err("the copy of Azimuth was moved on by something else writing its file".into());
        }
        let mut counts = lock(&self.status).counts;
        // Closing gives up part way, and the step, never committed, leaves nothing behind.
        apply(&mut Stoppable { points: Stored(&transaction), stop: &self.stop }, &self.stop, self.cfg.chain, events, &mut counts)?;
        keep_number(&transaction, "read to", to)?;
        transaction.execute("insert or replace into meta (name, value) values ('read to hash', ?1)", [&hash[..]]).map_err(sql)?;
        for (name, count) in COUNTS.iter().zip(counts_mut(&mut counts)) {
            keep_number(&transaction, name, *count)?;
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
                count_one(&mut counts.logs);
            }
            Event::Batch { input, .. } => {
                let received = naive::receive_batch(points, chain, input)?;
                count_one(&mut counts.batches);
                match received.outcomes {
                    None => count_one(&mut counts.unreadable),
                    Some(outcomes) => {
                        for outcome in outcomes {
                            match outcome {
                                Outcome::Applied => count_one(&mut counts.applied),
                                Outcome::Failed => count_one(&mut counts.failed),
                                Outcome::Unsigned => count_one(&mut counts.unsigned),
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

/// The largest number kept in `meta`: SQLite keeps whole numbers up to 2^63 - 1.
const MOST_KEPT: u64 = i64::MAX as u64;

const DAMAGED: &str = "the copy of Azimuth is damaged";

/// A number kept in `meta`, the block read to or one of the six counts: a whole number from 0
/// to 2^63 - 1, kept as an SQLite integer. Anything else under its name (a number below zero,
/// text, bytes) is a damaged file, never taken for something else. `None` if nothing is kept
/// under the name.
fn kept_number(connection: &Connection, name: &str) -> Result<Option<u64>, String> {
    let found: Option<Option<u64>> = connection
        .query_row("select value from meta where name = ?1", [name], |row| {
            Ok(match row.get_ref(0)? {
                rusqlite::types::ValueRef::Integer(number) => u64::try_from(number).ok(),
                _ => None,
            })
        })
        .optional()
        .map_err(sql)?;
    match found {
        None => Ok(None),
        Some(Some(number)) => Ok(Some(number)),
        Some(None) => Err(DAMAGED.to_string()),
    }
}

/// Keep a number in `meta` under `name`, the only way such a number is written. One past
/// 2^63 - 1 cannot be written down.
fn keep_number(connection: &Connection, name: &str, value: u64) -> Result<(), String> {
    let written = i64::try_from(value).map_err(|_| format!("{value}, for the copy of Azimuth's {name}, is too big to write down"))?;
    connection.execute("insert or replace into meta (name, value) values (?1, ?2)", params![name, written]).map_err(sql)?;
    Ok(())
}

/// Add one to a count, stopping at the largest number that can be kept. A count that has got
/// there stays there, so that every copy that reads the same history keeps the same count,
/// however often it is closed and opened again on the way.
fn count_one(count: &mut u64) {
    *count = count.saturating_add(1).min(MOST_KEPT);
}

/// The block before either contract was made: where a copy that has read nothing stands.
fn start(cfg: &ReplicaConfig) -> u64 {
    cfg.azimuth_from.min(cfg.naive_from).saturating_sub(1)
}

fn read_to(connection: &Connection) -> Result<u64, String> {
    kept_number(connection, "read to")?.ok_or_else(|| DAMAGED.to_string())
}

/// The six counts, as the file keeps them. A file made by this code keeps all six from the
/// moment it is made. One made before that kept none until its first step forward, and then
/// all six; so a file that has read nothing yet may keep none of them, which is nothing
/// counted. Any other count missing is a damaged file.
fn read_counts(connection: &Connection, cfg: &ReplicaConfig) -> Result<Counts, String> {
    let read_to = read_to(connection)?;
    let mut counts = Counts::default();
    let mut missing = 0;
    for (name, count) in COUNTS.iter().zip(counts_mut(&mut counts)) {
        match kept_number(connection, name)? {
            Some(kept) => *count = kept,
            None => missing += 1,
        }
    }
    match missing {
        0 => Ok(counts),
        6 if read_to == start(cfg) => Ok(counts),
        _ => Err(DAMAGED.to_string()),
    }
}

/// Read back a copy just made from a snapshot, before anything is written to it: what it is a
/// copy of, the block it has read to and that block's hash, its counts and how many points it
/// holds must all be what the snapshot's header says. Anything else is not the file that was
/// made.
fn check_made(connection: &Connection, cfg: &ReplicaConfig, given: &Path, made: &snapshot::Summary) -> Result<(), String> {
    let not_made = |what: &str| format!("the copy at {} is not the one just made from the snapshot ({what} is not what was made), so it is not used", given.display());
    // An error reading it back is not taken for a difference: it is said as it is.
    let unreadable = |why: String| format!("the copy at {} could not be read back after it was made ({why}), so it is not used", given.display());
    let tables: i64 = connection
        .query_row("select count(*) from sqlite_master where type = 'table' and name in ('meta', 'points')", [], |row| row.get(0))
        .map_err(|e| unreadable(e.to_string()))?;
    if tables != 2 {
        return Err(not_made("its tables"));
    }
    // Made in its usual journal before it was given its name, so that opening it changes
    // nothing to make it a good copy.
    let journal: String = connection.query_row("pragma journal_mode", [], |row| row.get(0)).map_err(|e| unreadable(e.to_string()))?;
    if journal != "wal" {
        return Err(not_made("its journal"));
    }
    let found: Option<String> = connection.query_row("select value from meta where name = 'made for'", [], |row| row.get(0)).optional().map_err(|e| unreadable(e.to_string()))?;
    if found.as_deref() != Some(made_for(cfg).as_str()) {
        return Err(not_made("what it is a copy of"));
    }
    if read_to(connection).map_err(unreadable)? != made.block {
        return Err(not_made("the block it has read to"));
    }
    if read_to_hash(connection).map_err(unreadable)? != Some(made.hash) {
        return Err(not_made("that block's hash"));
    }
    if read_counts(connection, cfg).map_err(unreadable)? != made.counts {
        return Err(not_made("its counts"));
    }
    let points: i64 = connection.query_row("select count(*) from points", [], |row| row.get(0)).map_err(|e| unreadable(e.to_string()))?;
    if u64::try_from(points).ok() != Some(made.points) {
        return Err(not_made("how many points it holds"));
    }
    Ok(())
}

/// The hash of the block the file has read to, if it keeps one: 32 bytes, nothing else. A file
/// made before the hash was kept has none.
fn read_to_hash(connection: &Connection) -> Result<Option<[u8; 32]>, String> {
    let found: Option<Option<[u8; 32]>> = connection
        .query_row("select value from meta where name = 'read to hash'", [], |row| Ok(row.get_ref(0)?.as_blob().ok().and_then(|blob| <[u8; 32]>::try_from(blob).ok())))
        .optional()
        .map_err(sql)?;
    match found {
        None => Ok(None),
        Some(Some(hash)) => Ok(Some(hash)),
        Some(None) => Err(DAMAGED.to_string()),
    }
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
        has_sponsor: match number(17)? {
            0 => false,
            1 => true,
            _ => return Err(damaged()),
        },
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
        /// Blocks given another hash than their logs have, when asked for as blocks.
        lying: HashMap<u64, [u8; 32]>,
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
                    let number = match params[0].as_str() {
                        Some("finalized") => self.finalized,
                        _ => quantity(&params[0]),
                    };
                    // Only blocks the chain has made are answered.
                    if number > self.finalized.saturating_add(100) {
                        Value::Null
                    } else {
                        let transactions: Vec<String> = (0..self.block_transactions as u64).map(|at| hex(&keccak(&at.to_be_bytes()))).collect();
                        let hash = self.lying.get(&number).copied().unwrap_or(block_hash(number));
                        json!({ "number": format!("{number:#x}"), "hash": hex(&hash), "transactions": transactions })
                    }
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
                until: None,
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
        assert!(replica.poll().unwrap_err().contains("behind block 40, which it said before"));
        assert_eq!(replica.status().finalized, Some(40));
        // Final to block 50, heard of while the blocks after 40 cannot be had, so that the
        // poll fails and the file stays at 40; lookups wait for 50 meanwhile. Then the node
        // says 45: behind 50, but 50 came in a poll that failed, and may have been the wrong
        // answer, so it is not held against the node, and the copy reads to 45.
        node.with(|chain| {
            chain.finalized = 50;
            chain.refused_from = Some(41);
        });
        assert!(replica.poll().is_err());
        assert_eq!((replica.status().read_to, replica.status().finalized), (40, Some(50)));
        assert!(replica.listing(PLANET).is_err());
        node.with(|chain| {
            chain.finalized = 45;
            chain.refused_from = None;
        });
        replica.poll().unwrap();
        assert_eq!((replica.status().read_to, replica.status().finalized), (45, Some(45)));
        // Behind one given in a poll that succeeded is still not followed.
        node.with(|chain| chain.finalized = 44);
        assert!(replica.poll().unwrap_err().contains("behind block 45, which it said before"));
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
        // A copy told to stop short of the final block is still not led back by it: the file
        // is at 30, the node said 50 in a poll that succeeded, and now says 40.
        drop(replica);
        let stopped = scratch.0.join("stopped.sqlite");
        let short = Replica::open(&stopped, ReplicaConfig { until: Some(30), tries: 2, ..node.config() }).unwrap();
        short.poll().unwrap();
        assert_eq!(short.status().read_to, 30);
        node.with(|chain| chain.finalized = 40);
        assert!(short.poll().unwrap_err().contains("behind block 50, which it said before"));
        drop(short);
        node.with(|chain| chain.finalized = 50);
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
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
        assert!(connect(&late, Access::Make).unwrap_err().contains("could not be read or written"));
        assert!(connect(&late, Access::Write).is_err());
        assert!(connect(&late, Access::Read).is_err());
        for access in [Access::Make, Access::Write, Access::Read] {
            assert!(connect(&directory.join("azimuth.sqlite"), access).is_ok());
        }
        // Opened to write a file that must be there, a file that is not is not made.
        assert!(connect(&directory.join("absent.sqlite"), Access::Write).is_err());
        assert!(!directory.join("absent.sqlite").exists());
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

    /// The snapshot of a copy, written to `out`, and its bytes.
    fn snapshot_bytes(path: &Path, cfg: &ReplicaConfig, out: &Path) -> (snapshot::Summary, Vec<u8>) {
        let summary = snapshot::write(path, cfg, out).unwrap();
        (summary, fs::read(out).unwrap())
    }

    /// A copy read to `until`, or to the end of the stand-in's chain, in steps of at most
    /// `widest` blocks.
    fn read_to_block(path: &Path, node: &Node, widest: u64, until: Option<u64>) {
        let replica = Replica::open(path, ReplicaConfig { widest, until, ..node.config() }).unwrap();
        replica.poll().unwrap();
        if let Some(until) = until {
            assert_eq!(replica.status().read_to, until);
        }
    }

    /// The names in a directory, but for the lock files copies leave.
    fn names_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).filter(|name| !name.ends_with(".lock")).collect();
        names.sort();
        names
    }

    fn kept_hash(path: &Path) -> Option<[u8; 32]> {
        read_to_hash(&Connection::open(path).unwrap()).unwrap()
    }

    #[test]
    fn a_snapshot_restored_and_written_again_is_the_same_bytes() {
        let scratch = Scratch::new("snapshot-again");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let first = scratch.0.join("first.sqlite");
        read_to_block(&first, &node, 1000, None);
        let (summary, written) = snapshot_bytes(&first, &node.config(), &scratch.0.join("a.snapshot"));
        assert_eq!((summary.block, summary.hash, summary.bytes), (40, block_hash(40), written.len() as u64));
        assert_eq!(written.len() as u64, 176 + 211 * summary.points);
        let notes = fs::read_to_string(scratch.0.join("a.snapshot.txt")).unwrap();
        assert_eq!(notes, summary.lines());
        assert!(notes.contains("block: 40\n") && notes.contains(&format!("sha256: {}", summary.sha256.iter().map(|byte| format!("{byte:02x}")).collect::<String>())));

        // Made again from it, with its fingerprint: the same bytes, before and after reading on.
        let second = scratch.0.join("second.sqlite");
        let (replica, restored) = Replica::open_from_snapshot(&second, node.config(), &scratch.0.join("a.snapshot"), Some(summary.sha256)).unwrap();
        assert!(matches!(&restored, Restored::Made(made) if *made == summary), "{restored:?}");
        assert!(replica.listing(PLANET).unwrap_err().contains("not yet heard"), "nothing is answered before the node is asked");
        let (_, again) = snapshot_bytes(&second, &node.config(), &scratch.0.join("b.snapshot"));
        assert!(again == written);
        replica.poll().unwrap();
        assert_eq!(replica.status().counts, Replica::open(&first, node.config()).map(|first| first.status().counts).unwrap());
        assert_eq!(replica.listing(PLANET).unwrap().unwrap(), Listing { key: key(0x71), revision: 1, continuity: 0, sponsor: Some(STAR) });
        drop(replica);
        let (_, after) = snapshot_bytes(&second, &node.config(), &scratch.0.join("c.snapshot"));
        assert!(after == written);
    }

    #[test]
    fn copies_read_to_one_block_in_steps_of_any_size_write_the_same_snapshot() {
        let scratch = Scratch::new("snapshot-steps");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let (one, wide) = (scratch.0.join("one.sqlite"), scratch.0.join("wide.sqlite"));
        read_to_block(&one, &node, 1, None);
        read_to_block(&wide, &node, 1000, None);
        let (_, by_ones) = snapshot_bytes(&one, &node.config(), &scratch.0.join("one.snapshot"));
        let (_, at_once) = snapshot_bytes(&wide, &node.config(), &scratch.0.join("wide.snapshot"));
        assert!(by_ones == at_once);
        // Each step asked for the hash of its last block, but the last, which the final block's
        // answer gave.
        let asked: Vec<u64> = node.with(|chain| chain.methods("eth_getBlockByNumber").iter().filter_map(|params| params[0].as_str().filter(|which| *which != "finalized").map(|which| u64::from_str_radix(&which[2..], 16).unwrap())).collect());
        assert!(asked.contains(&10) && asked.contains(&39) && !asked.contains(&40), "{asked:?}");
    }

    #[test]
    fn a_snapshot_read_on_from_is_the_same_as_reading_straight_there() {
        let scratch = Scratch::new("snapshot-on");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        // Stopped part way, between the two batches.
        let early = scratch.0.join("early.sqlite");
        read_to_block(&early, &node, 1000, Some(23));
        assert_eq!(kept_hash(&early), Some(block_hash(23)), "the hash kept is the node's for the block asked for");
        let (at_23, _) = snapshot_bytes(&early, &node.config(), &scratch.0.join("23.snapshot"));
        assert_eq!(at_23.block, 23);
        let restored = scratch.0.join("restored.sqlite");
        let (replica, _) = Replica::open_from_snapshot(&restored, node.config(), &scratch.0.join("23.snapshot"), Some(at_23.sha256)).unwrap();
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 40);
        drop(replica);
        let straight = scratch.0.join("straight.sqlite");
        read_to_block(&straight, &node, 1000, None);
        let (_, from_snapshot) = snapshot_bytes(&restored, &node.config(), &scratch.0.join("restored.snapshot"));
        let (_, from_start) = snapshot_bytes(&straight, &node.config(), &scratch.0.join("straight.snapshot"));
        assert!(from_snapshot == from_start);
    }

    #[test]
    fn a_snapshot_not_in_the_one_form_allowed_makes_nothing() {
        let scratch = Scratch::new("snapshot-refused");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let source = scratch.0.join("source.sqlite");
        read_to_block(&source, &node, 1000, None);
        let good_path = scratch.0.join("good.snapshot");
        let (summary, good) = snapshot_bytes(&source, &node.config(), &good_path);
        assert!(summary.points >= 3);
        let record = |at: usize| 176 + 211 * at;
        let changed = |at: usize, bytes: &[u8]| {
            let mut other = good.clone();
            other[at..at + bytes.len()].copy_from_slice(bytes);
            other
        };
        let mut swapped = good.clone();
        swapped[record(0)..record(2)].rotate_left(211);
        let mut repeated = good.clone();
        repeated.copy_within(record(0)..record(1), record(1));
        let refused: Vec<(&str, Vec<u8>, Option<[u8; 32]>, &str)> = vec![
            ("one byte too many", [good.clone(), vec![0]].concat(), None, "bytes long"),
            ("one byte too few", good[..good.len() - 1].to_vec(), None, "bytes long"),
            ("shorter than a header", good[..100].to_vec(), None, "shorter"),
            ("one point more said than there is", changed(168, &(summary.points + 1).to_be_bytes()), None, "bytes long"),
            ("one byte of a key changed, with the fingerprint", changed(record(1) + 140, &[0xee]), Some(summary.sha256), "fingerprint"),
            ("a place that is none of the three", changed(record(0) + 4, &[3]), None, "none of the three"),
            ("a sponsor that is neither yes nor no", changed(record(0) + 201, &[2]), None, "one form"),
            ("an escape that is neither yes nor no", changed(record(0) + 206, &[2]), None, "one form"),
            ("an escape not asked for, not zero", changed(record(0) + 207, &[0, 0, 0, 9]), None, "one form"),
            ("ships out of order", swapped, None, "not after"),
            ("a ship twice", repeated, None, "not after"),
            ("another chain", changed(16, &5u64.to_be_bytes()), None, "made for chain 5"),
            ("another Azimuth contract", changed(24, &[0xcc]), None, "made for"),
            ("another first block", changed(72, &21u64.to_be_bytes()), None, "made for"),
            ("other rules", changed(12, &2u32.to_be_bytes()), None, "version 2 of the rules"),
            ("another format", changed(8, &2u32.to_be_bytes()), None, "format 2"),
            ("not a snapshot", changed(0, b"SQLite f"), None, "not a snapshot"),
            ("a count that does not fit", changed(120, &u64::MAX.to_be_bytes()), None, "too big"),
            ("a block that does not fit", changed(80, &u64::MAX.to_be_bytes()), None, "too big"),
        ];
        let before = names_in(&scratch.0);
        for (what, bytes, sha256, why) in refused {
            let offered = scratch.0.join("offered.snapshot");
            fs::write(&offered, &bytes).unwrap();
            let copy = scratch.0.join("copy.sqlite");
            let refusal = Replica::open_from_snapshot(&copy, node.config(), &offered, sha256).err().unwrap_or_else(|| panic!("{what}: taken"));
            assert!(refusal.contains(why) && refusal.contains("no copy is made"), "{what}: {refusal}");
            fs::remove_file(&offered).unwrap();
            assert_eq!(names_in(&scratch.0), before, "{what}: no copy, and nothing left behind");
        }
        // Without its fingerprint, a byte changed where any byte is allowed is not caught: it
        // is the fingerprint that shows a snapshot is the one somebody named.
        let offered = scratch.0.join("offered.snapshot");
        fs::write(&offered, changed(record(1) + 140, &[0xee])).unwrap();
        assert!(Replica::open_from_snapshot(&scratch.0.join("copy.sqlite"), node.config(), &offered, None).is_ok());
        // A copy that would be made for another Azimuth is not made from this one.
        let other = ReplicaConfig { naive_from: 21, ..node.config() };
        assert!(Replica::open_from_snapshot(&scratch.0.join("other.sqlite"), other, &good_path, None).unwrap_err().contains("made for"));
        assert!(!scratch.0.join("other.sqlite").exists());
    }

    #[test]
    fn a_file_that_is_there_is_never_replaced_and_links_are_not_followed() {
        let scratch = Scratch::new("snapshot-there");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let copy = scratch.0.join("copy.sqlite");
        read_to_block(&copy, &node, 1000, Some(30));
        let snapshot_path = scratch.0.join("at-30.snapshot");
        let (_, written) = snapshot_bytes(&copy, &node.config(), &snapshot_path);
        // A copy that is there is opened as it is: the snapshot is not even read.
        let (replica, restored) = Replica::open_from_snapshot(&copy, node.config(), &scratch.0.join("no such snapshot"), None).unwrap();
        assert!(matches!(restored, Restored::Ignored));
        assert_eq!(replica.status().read_to, 30);
        drop(replica);
        // The writer replaces neither the snapshot nor its notes, and follows no link.
        let refusal = snapshot::write(&copy, &node.config(), &snapshot_path).unwrap_err();
        assert!(refusal.contains("never replaces"), "{refusal}");
        assert!(fs::read(&snapshot_path).unwrap() == written);
        let notes_only = scratch.0.join("notes-only.snapshot");
        fs::write(scratch.0.join("notes-only.snapshot.txt"), "mine").unwrap();
        assert!(snapshot::write(&copy, &node.config(), &notes_only).unwrap_err().contains("never replaces"));
        assert!(!notes_only.exists());
        assert_eq!(fs::read_to_string(scratch.0.join("notes-only.snapshot.txt")).unwrap(), "mine");
        let target = scratch.0.join("target");
        let link = scratch.0.join("link.snapshot");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(snapshot::write(&copy, &node.config(), &link).unwrap_err().contains("never replaces"));
        assert!(!target.exists());
        // A copy is not made through a link to where there is none.
        let made_through = scratch.0.join("made-through.sqlite");
        std::os::unix::fs::symlink(&target, &made_through).unwrap();
        assert!(Replica::open_from_snapshot(&made_through, node.config(), &snapshot_path, None).unwrap_err().contains("link"));
        assert!(!target.exists());
        // Nor a snapshot written of a copy that is not there.
        assert!(snapshot::write(&scratch.0.join("absent.sqlite"), &node.config(), &scratch.0.join("absent.snapshot")).unwrap_err().contains("no copy"));
        assert!(!scratch.0.join("absent.sqlite").exists());
    }

    #[test]
    fn a_node_that_disagrees_about_the_files_block_stops_it_and_writes_nothing() {
        let scratch = Scratch::new("snapshot-disagrees");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replayed = scratch.0.join("replayed.sqlite");
        read_to_block(&replayed, &node, 1000, None);
        let (summary, _) = snapshot_bytes(&replayed, &node.config(), &scratch.0.join("40.snapshot"));
        let restored = scratch.0.join("restored.sqlite");
        drop(Replica::open_from_snapshot(&restored, node.config(), &scratch.0.join("40.snapshot"), Some(summary.sha256)).unwrap());
        for (path, made_from_snapshot) in [(&replayed, false), (&restored, true)] {
            // The node now says block 40 has another hash: as the final block, and then as a
            // block asked for by number once the chain is final further on.
            node.with(|chain| {
                chain.finalized = 40;
                chain.lying.insert(40, [0xdd; 32]);
            });
            let before = fs::read(path).unwrap();
            let replica = Replica::open(path, node.config()).unwrap();
            let refusal = replica.poll().unwrap_err();
            assert!(refusal.contains("another chain") && refusal.contains(&hex(&[0xdd; 32])), "{refusal}");
            assert!(refusal.contains("remove it, and any file of the same name with -wal, -shm or -journal added, to try another"), "{refusal}");
            assert!(replica.listing(PLANET).unwrap_err().contains("another chain"), "{made_from_snapshot}");
            assert!(!replica.caught_up());
            node.with(|chain| chain.finalized = 50);
            assert!(replica.poll().unwrap_err().contains("another chain"));
            assert_eq!(replica.status().read_to, 40);
            assert!(replica.listing(PLANET).is_err());
            assert!(fs::read(path).unwrap() == before, "nothing was written");
            // An honest answer later lets it go on.
            node.with(|chain| chain.lying.clear());
            replica.poll().unwrap();
            assert_eq!(replica.status().read_to, 50);
            assert_eq!(kept_hash(path), Some(block_hash(50)));
            assert!(replica.listing(PLANET).unwrap().is_some());
        }
    }

    #[test]
    fn a_file_kept_before_the_hash_learns_one_and_is_then_checked() {
        let scratch = Scratch::new("snapshot-old-file");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        read_to_block(&path, &node, 1000, None);
        Connection::open(&path).unwrap().execute("delete from meta where name = 'read to hash'", []).unwrap();
        assert!(snapshot::write(&path, &node.config(), &scratch.0.join("none.snapshot")).unwrap_err().contains("does not keep the hash"));
        assert!(!scratch.0.join("none.snapshot").exists());
        // With nothing to check, it is used as before, even by a node that would disagree.
        node.with(|chain| {
            chain.lying.insert(40, [0xdd; 32]);
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        replica.poll().unwrap();
        assert!(replica.listing(PLANET).unwrap().is_some());
        assert_eq!(kept_hash(&path), None);
        node.with(|chain| {
            chain.lying.clear();
            chain.finalized = 45;
        });
        replica.poll().unwrap();
        assert_eq!(kept_hash(&path), Some(block_hash(45)));
        drop(replica);
        // From then on it is checked.
        node.with(|chain| {
            chain.lying.insert(45, [0xdd; 32]);
        });
        let replica = Replica::open(&path, node.config()).unwrap();
        assert!(replica.poll().unwrap_err().contains("another chain"));
        assert!(replica.listing(PLANET).is_err());
    }

    #[test]
    fn a_copy_told_to_stop_stops_there_and_answers_nothing() {
        let scratch = Scratch::new("snapshot-until");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { until: Some(30), ..node.config() }).unwrap();
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 30);
        assert!(!replica.caught_up());
        assert!(replica.listing(PLANET).unwrap_err().contains("told to stop at block 30"));
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 30);
        drop(replica);
        // Past what is final, it reads as far as is final, and waits.
        let replica = Replica::open(&path, ReplicaConfig { until: Some(50), ..node.config() }).unwrap();
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 40);
        node.with(|chain| chain.finalized = 60);
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 50);
        assert_eq!(kept_hash(&path), Some(block_hash(50)));
        assert!(!replica.caught_up());
        drop(replica);
        // It cannot be told to stop behind where it is.
        let replica = Replica::open(&path, ReplicaConfig { until: Some(45), ..node.config() }).unwrap();
        assert!(replica.poll().unwrap_err().contains("cannot go back"));
        assert_eq!(replica.status().read_to, 50);
    }

    #[test]
    fn a_block_whose_hash_is_not_its_logs_hash_stops_the_step() {
        let scratch = Scratch::new("snapshot-logs-hash");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
            // Block 24 holds a batch, and the node gives the block another hash than its log.
            chain.lying.insert(24, [0xdd; 32]);
        });
        for (name, until, tries) in [("asked.sqlite", Some(24), 5), ("final.sqlite", None, 5)] {
            if until.is_none() {
                node.with(|chain| chain.finalized = 24);
            }
            let path = scratch.0.join(name);
            let replica = Replica::open(&path, ReplicaConfig { until, tries, ..node.config() }).unwrap();
            let refusal = replica.poll().unwrap_err();
            assert!(refusal.contains("block 24 is said to have two hashes"), "{name}: {refusal}");
            assert_eq!(replica.status().read_to, 9, "{name}: nothing was applied");
            assert_eq!(kept_hash(&path), None);
        }
    }

    #[test]
    fn a_snapshot_newer_than_the_nodes_final_block_waits() {
        let scratch = Scratch::new("snapshot-ahead");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let source = scratch.0.join("source.sqlite");
        read_to_block(&source, &node, 1000, None);
        let (summary, _) = snapshot_bytes(&source, &node.config(), &scratch.0.join("40.snapshot"));
        // A node that has finalised less than the snapshot has.
        node.with(|chain| chain.finalized = 30);
        let restored = scratch.0.join("restored.sqlite");
        let (replica, _) = Replica::open_from_snapshot(&restored, node.config(), &scratch.0.join("40.snapshot"), Some(summary.sha256)).unwrap();
        let waiting = replica.poll().unwrap_err();
        assert!(waiting.contains("waits until it is final there"), "{waiting}");
        assert!(replica.listing(PLANET).is_err());
        assert_eq!(replica.status().read_to, 40);
        assert!(node.with(|chain| chain.methods("eth_getBlockByNumber").iter().all(|params| params[0] == "finalized")), "no block past the final one is asked about");
        node.with(|chain| chain.finalized = 41);
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 41);
        assert!(replica.listing(PLANET).unwrap().is_some());
    }

    #[test]
    fn a_damaged_hash_in_the_file_is_not_taken_for_none() {
        let scratch = Scratch::new("snapshot-damaged-hash");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        read_to_block(&path, &node, 1000, None);
        for damaged in [rusqlite::types::Value::Blob(vec![1; 31]), rusqlite::types::Value::Text(hex(&block_hash(40)))] {
            Connection::open(&path).unwrap().execute("update meta set value = ?1 where name = 'read to hash'", [damaged]).unwrap();
            let replica = Replica::open(&path, node.config()).unwrap();
            assert!(replica.poll().unwrap_err().contains("damaged"));
            assert!(replica.listing(PLANET).is_err());
            assert!(snapshot::write(&path, &node.config(), &scratch.0.join("damaged.snapshot")).unwrap_err().contains("damaged"));
        }
    }

    #[test]
    fn a_snapshot_is_written_only_of_a_copy_of_the_azimuth_asked_for() {
        let scratch = Scratch::new("snapshot-made-for");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        read_to_block(&path, &node, 1000, None);
        let other = ReplicaConfig { chain: 5, ..node.config() };
        assert!(snapshot::write(&path, &other, &scratch.0.join("other.snapshot")).unwrap_err().contains("not a copy of the Azimuth"));
        assert!(!scratch.0.join("other.snapshot").exists());
    }

    /// Have a test step in at a place in the snapshot code, for one file.
    fn step_in_at(file: &Path, at: &'static str, hook: impl FnMut(&Path) + Send + 'static) {
        snapshot::HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push((file.to_path_buf(), at, Box::new(hook)));
    }

    fn step_out(file: &Path) {
        snapshot::HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|(for_file, ..)| for_file != file);
    }

    /// A copy read to block 40 of the usual history, and a snapshot of it.
    fn source_and_snapshot(scratch: &Scratch, node: &Node) -> (PathBuf, PathBuf, snapshot::Summary) {
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let source = scratch.0.join("source.sqlite");
        read_to_block(&source, node, 1000, None);
        let from = scratch.0.join("40.snapshot");
        let (summary, _) = snapshot_bytes(&source, &node.config(), &from);
        (source, from, summary)
    }

    #[test]
    fn a_restore_that_crashes_part_way_leaves_no_copy_and_is_made_again() {
        let scratch = Scratch::new("snapshot-crash");
        let node = Node::start();
        let (_, from, summary) = source_and_snapshot(&scratch, &node);
        step_in_at(&from, "restoring", |_| panic!("a crash part way through making a copy"));
        let copy = scratch.0.join("copy.sqlite");
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Replica::open_from_snapshot(&copy, node.config(), &from, None)));
        step_out(&from);
        assert!(crashed.is_err());
        // No copy, so the next start makes it again, whole; the half-made file is left under
        // its own name, never the copy's.
        assert!(!copy.exists());
        assert!(names_in(&scratch.0).iter().any(|name| name.starts_with(".copy.sqlite.") && name.ends_with(".part")), "{:?}", names_in(&scratch.0));
        let (replica, restored) = Replica::open_from_snapshot(&copy, node.config(), &from, Some(summary.sha256)).unwrap();
        assert!(matches!(restored, Restored::Made(_)));
        assert_eq!(replica.status().read_to, 40);
        replica.poll().unwrap();
        assert!(replica.listing(PLANET).unwrap().is_some());
    }

    #[test]
    fn a_snapshot_that_grows_while_it_is_read_is_refused() {
        let scratch = Scratch::new("snapshot-grows");
        let node = Node::start();
        let (_, from, _) = source_and_snapshot(&scratch, &node);
        let growing = from.clone();
        step_in_at(&from, "restored", move |_| {
            fs::OpenOptions::new().append(true).open(&growing).unwrap().write_all(&[0]).unwrap();
        });
        let copy = scratch.0.join("copy.sqlite");
        let refusal = Replica::open_from_snapshot(&copy, node.config(), &from, None).unwrap_err();
        step_out(&from);
        assert!(refusal.contains("changed while it was being read"), "{refusal}");
        assert!(!copy.exists());
    }

    #[test]
    fn a_snapshot_is_of_one_moment_while_the_copy_moves_on() {
        let scratch = Scratch::new("snapshot-moment");
        let node = Node::start();
        let (source, before, counted) = source_and_snapshot(&scratch, &node);
        // Something else adds a point to the copy after the snapshot has counted its points.
        let during = scratch.0.join("during.snapshot");
        let writing = source.clone();
        step_in_at(&during, "counted", move |_| {
            Connection::open(&writing)
                .unwrap()
                .execute(
                    "insert into points select 77777, dominion, owner, owner_nonce, spawn_proxy, spawn_nonce, management_proxy, management_nonce, voting_proxy, voting_nonce, transfer_proxy, transfer_nonce, continuity, revision, suite, authentication, encryption, has_sponsor, sponsor, escape_to from points where ship = 0",
                    [],
                )
                .unwrap();
        });
        let written = snapshot::write(&source, &node.config(), &during);
        step_out(&during);
        written.unwrap();
        assert!(fs::read(&during).unwrap() == fs::read(&before).unwrap(), "the snapshot is of the copy as it was when it began");
        let (after, _) = snapshot_bytes(&source, &node.config(), &scratch.0.join("after.snapshot"));
        assert_eq!(after.points, counted.points + 1, "the point was added, and is in a snapshot begun after it");
    }

    #[test]
    fn a_copy_is_not_made_beside_files_an_earlier_copy_left() {
        let scratch = Scratch::new("snapshot-beside");
        let node = Node::start();
        let (_, from, summary) = source_and_snapshot(&scratch, &node);
        for end in ["-wal", "-shm", "-journal"] {
            let copy = scratch.0.join(format!("copy{end}.sqlite"));
            let left = beside(&copy, end);
            fs::write(&left, b"left by an earlier copy").unwrap();
            // Neither made from a snapshot nor made new, and what was left is not touched.
            let refusal = Replica::open_from_snapshot(&copy, node.config(), &from, Some(summary.sha256)).unwrap_err();
            assert!(refusal.contains(&left.display().to_string()) && refusal.contains("Remove it"), "{end}: {refusal}");
            let refusal = Replica::open(&copy, node.config()).unwrap_err();
            assert!(refusal.contains(&left.display().to_string()), "{end}: {refusal}");
            assert!(!copy.exists(), "{end}");
            assert_eq!(fs::read(&left).unwrap(), b"left by an earlier copy", "{end}");
            // Once it is removed, the copy is made.
            fs::remove_file(&left).unwrap();
            let (replica, restored) = Replica::open_from_snapshot(&copy, node.config(), &from, Some(summary.sha256)).unwrap();
            assert!(matches!(restored, Restored::Made(_)));
            assert_eq!(replica.status().read_to, 40);
        }
        // Nor beside the file it is first made under, under its own name: a journal put there
        // refuses the restore, and is left as it was.
        // (A restore makes the copy under its true name, links followed.)
        let copy = fs::canonicalize(&scratch.0).unwrap().join("planted.sqlite");
        let planted = Arc::new(Mutex::new(None));
        let noting = planted.clone();
        step_in_at(&copy, "making", move |making| {
            let journal = beside(making, "-journal");
            fs::write(&journal, b"planted").unwrap();
            *noting.lock().unwrap() = Some(journal);
        });
        let refusal = Replica::open_from_snapshot(&copy, node.config(), &from, None).unwrap_err();
        step_out(&copy);
        assert!(refusal.contains("-journal"), "{refusal}");
        assert!(!copy.exists());
        let journal = planted.lock().unwrap().clone().unwrap();
        assert_eq!(fs::read(&journal).unwrap(), b"planted");
    }

    #[test]
    fn every_block_the_node_gives_in_a_poll_is_one_chain() {
        let scratch = Scratch::new("snapshot-one-chain");
        let node = Node::start();
        let (galaxy, star) = (wallet(1).1, wallet(2).1);
        let setup = |chain: &mut Chain| {
            *chain = Chain { widest: 1000, together: true, ..Chain::default() };
            history(chain);
        };
        let refused = |name: &str, until: Option<u64>| {
            let path = scratch.0.join(name);
            let replica = Replica::open(&path, ReplicaConfig { until, ..node.config() }).unwrap();
            let refusal = replica.poll().unwrap_err();
            assert_eq!(replica.status().read_to, 9, "{name}: nothing applied");
            assert_eq!(kept_hash(&path), None, "{name}");
            refusal
        };
        // A log in block 41 with the final block's hash, and no log in block 42.
        node.with(|chain| {
            setup(chain);
            chain.azimuth(41, b"OwnerChanged(uint32,address)", 0, Some(word(&galaxy)), vec![]);
            chain.logs.iter_mut().filter(|log| log.block == 41).for_each(|log| log.block_hash = block_hash(42));
            chain.finalized = 42;
        });
        assert!(refused("final.sqlite", None).contains("is said to be of two blocks"));
        // A log in block 25 with the hash the node gives for block 30, the range's last.
        node.with(|chain| {
            setup(chain);
            chain.azimuth(25, b"OwnerChanged(uint32,address)", STAR, Some(word(&star)), vec![]);
            chain.logs.iter_mut().filter(|log| log.block == 25).for_each(|log| log.block_hash = block_hash(30));
            chain.finalized = 40;
        });
        assert!(refused("last.sqlite", Some(30)).contains("is said to be of two blocks"));
        // The range's last block given the final block's hash.
        node.with(|chain| {
            setup(chain);
            chain.finalized = 40;
            chain.lying.insert(30, block_hash(40));
        });
        assert!(refused("last-and-final.sqlite", Some(30)).contains("is said to be of two blocks"));
        // The block the file had read to, given the hash the final block is given.
        node.with(|chain| {
            setup(chain);
            chain.finalized = 40;
        });
        let path = scratch.0.join("start.sqlite");
        read_to_block(&path, &node, 1000, Some(30));
        node.with(|chain| {
            chain.lying.insert(40, block_hash(30));
        });
        let before = fs::read(&path).unwrap();
        let replica = Replica::open(&path, node.config()).unwrap();
        assert!(replica.poll().unwrap_err().contains("is said to be of two blocks"));
        assert!(replica.listing(PLANET).is_err());
        drop(replica);
        assert!(fs::read(&path).unwrap() == before);
        // The final block given another hash in a later poll of the same run, though nothing
        // after it is read.
        node.with(|chain| chain.lying.clear());
        let replica = Replica::open(&path, node.config()).unwrap();
        replica.poll().unwrap();
        node.with(|chain| {
            chain.lying.insert(40, [0xdd; 32]);
        });
        assert!(replica.poll().unwrap_err().contains("block 40 is said to have two hashes"));
    }

    #[test]
    fn a_count_stops_at_the_most_that_can_be_kept_whenever_the_copy_is_reopened() {
        let scratch = Scratch::new("snapshot-most");
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        // A snapshot at block 23 whose count of batches is the most that can be kept. The
        // batch at block 24 comes after it.
        let early = scratch.0.join("early.sqlite");
        read_to_block(&early, &node, 1000, Some(23));
        let (_, mut written) = snapshot_bytes(&early, &node.config(), &scratch.0.join("23.snapshot"));
        written[128..136].copy_from_slice(&(i64::MAX as u64).to_be_bytes());
        let most = scratch.0.join("most.snapshot");
        fs::write(&most, &written).unwrap();
        // One copy reads on in one go; the other stops at 24 and is opened again.
        let (straight, again) = (scratch.0.join("straight.sqlite"), scratch.0.join("again.sqlite"));
        drop(Replica::open_from_snapshot(&straight, node.config(), &most, None).unwrap());
        drop(Replica::open_from_snapshot(&again, node.config(), &most, None).unwrap());
        read_to_block(&straight, &node, 1000, None);
        read_to_block(&again, &node, 1000, Some(24));
        read_to_block(&again, &node, 1000, None);
        for path in [&straight, &again] {
            let replica = Replica::open(path, node.config()).unwrap();
            assert_eq!(replica.status().counts.batches, i64::MAX as u64);
            assert_eq!(replica.status().read_to, 40);
        }
        let (_, one_go) = snapshot_bytes(&straight, &node.config(), &scratch.0.join("straight.snapshot"));
        let (_, reopened) = snapshot_bytes(&again, &node.config(), &scratch.0.join("again.snapshot"));
        assert!(one_go == reopened);
    }

    #[test]
    fn a_number_kept_in_meta_is_a_whole_number_in_range_or_the_file_is_damaged() {
        use rusqlite::types::Value as Kept;
        let scratch = Scratch::new("snapshot-meta-numbers");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        read_to_block(&path, &node, 1000, None);
        let set = |name: &str, value: Kept| Connection::open(&path).unwrap().execute("update meta set value = ?1 where name = ?2", params![value, name]).unwrap();
        for (name, bad) in [
            ("read to", Kept::Text("40".into())),
            ("read to", Kept::Integer(-1)),
            ("read to", Kept::Real(40.0)),
            ("logs", Kept::Integer(-1)),
            ("logs", Kept::Text("5".into())),
            ("batches", Kept::Real(2.0)),
            ("applied", Kept::Blob(vec![1])),
        ] {
            let good: Kept = Connection::open(&path).unwrap().query_row("select value from meta where name = ?1", [name], |row| row.get(0)).unwrap();
            set(name, bad.clone());
            assert!(Replica::open(&path, node.config()).unwrap_err().contains("damaged"), "{name}: {bad:?}");
            assert!(snapshot::write(&path, &node.config(), &scratch.0.join("damaged.snapshot")).unwrap_err().contains("damaged"), "{name}: {bad:?}");
            set(name, good);
        }
        // A count missing from a file that has read on is damage too.
        Connection::open(&path).unwrap().execute("delete from meta where name = 'failed'", []).unwrap();
        assert!(Replica::open(&path, node.config()).unwrap_err().contains("damaged"));
        // A file that has read nothing, made before the counts were kept from the start, has
        // none of them, and they are nothing counted. A file made now keeps all six at once.
        let fresh = scratch.0.join("fresh.sqlite");
        drop(Replica::open(&fresh, node.config()).unwrap());
        let kept: i64 = Connection::open(&fresh).unwrap().query_row("select count(*) from meta where name in ('logs', 'batches', 'unreadable', 'applied', 'failed', 'unsigned') and value = 0", [], |row| row.get(0)).unwrap();
        assert_eq!(kept, 6);
        Connection::open(&fresh).unwrap().execute("delete from meta where name in ('logs', 'batches', 'unreadable', 'applied', 'failed', 'unsigned')", []).unwrap();
        assert_eq!(Replica::open(&fresh, node.config()).unwrap().status().counts, Counts::default());
        // Every one of them can be kept up to 2^63 - 1, and no further.
        assert!(keep_number(&Connection::open(&fresh).unwrap(), "logs", i64::MAX as u64).is_ok());
        assert!(keep_number(&Connection::open(&fresh).unwrap(), "logs", i64::MAX as u64 + 1).unwrap_err().contains("too big"));
        let mut count = i64::MAX as u64 - 1;
        count_one(&mut count);
        count_one(&mut count);
        assert_eq!(count, i64::MAX as u64);
    }

    #[test]
    fn a_copy_already_at_its_stopping_block_has_not_reached_it_until_the_node_agrees() {
        let scratch = Scratch::new("snapshot-until-agreed");
        let path = scratch.file();
        let node = Node::start();
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let until = ReplicaConfig { until: Some(30), ..node.config() };
        let replica = Replica::open(&path, until.clone()).unwrap();
        assert!(!replica.reached_until());
        replica.poll().unwrap();
        assert!(replica.reached_until());
        drop(replica);
        // Opened again, already at the block, with a node that disagrees about its hash.
        node.with(|chain| {
            chain.lying.insert(30, [0xdd; 32]);
        });
        let replica = Replica::open(&path, until.clone()).unwrap();
        assert_eq!(replica.status().read_to, 30);
        assert!(!replica.reached_until());
        assert!(replica.poll().unwrap_err().contains("another chain"));
        assert!(!replica.reached_until());
        node.with(|chain| chain.lying.clear());
        replica.poll().unwrap();
        assert!(replica.reached_until());
        // Nor while the node has not finalised the block.
        drop(replica);
        node.with(|chain| chain.finalized = 29);
        let replica = Replica::open(&path, until).unwrap();
        assert!(replica.poll().is_err());
        assert!(!replica.reached_until());
        assert!(!Replica::open(&scratch.0.join("other.sqlite"), node.config()).unwrap().reached_until(), "never, for a copy not told to stop");
    }

    #[test]
    fn a_restored_copy_is_read_back_and_never_made_anew_by_opening_it() {
        let scratch = Scratch::new("snapshot-read-back");
        let node = Node::start();
        let (_, from, summary) = source_and_snapshot(&scratch, &node);
        // Another good copy, of another block, to put in the copy's place.
        let other = scratch.0.join("other.sqlite");
        read_to_block(&other, &node, 1000, Some(23));
        let substituted = |name: &str, change: Box<dyn FnMut(&Path) + Send>| {
            let copy = scratch.0.join(name);
            step_in_at(&from, "placed", change);
            let opened = Replica::open_from_snapshot(&copy, node.config(), &from, Some(summary.sha256));
            step_out(&from);
            (copy, opened.err().unwrap_or_default())
        };
        let other_file = other.clone();
        let (copy, refusal) = substituted("swapped.sqlite", Box::new(move |placed: &Path| {
            fs::copy(&other_file, placed).unwrap();
        }));
        assert!(refusal.contains("is not the one just made") && refusal.contains("the block it has read to"), "{refusal}");
        assert_eq!(Replica::open(&copy, node.config()).unwrap().status().read_to, 23, "it is left as it was found");
        let (copy, refusal) = substituted("emptied.sqlite", Box::new(|placed: &Path| fs::write(placed, b"").unwrap()));
        assert!(refusal.contains("is not the one just made"), "{refusal}");
        assert_eq!(fs::metadata(&copy).unwrap().len(), 0, "nothing is written to it");
        // Each thing read back, changed alone.
        for (name, change, what) in [
            ("block", "update meta set value = 39 where name = 'read to'", "the block it has read to"),
            ("hash", "update meta set value = zeroblob(32) where name = 'read to hash'", "that block's hash"),
            ("count", "update meta set value = 99 where name = 'logs'", "its counts"),
            ("point", "delete from points where ship = 0", "how many points it holds"),
            ("made-for", "update meta set value = 'another' where name = 'made for'", "what it is a copy of"),
            ("journal", "pragma journal_mode = delete", "its journal"),
        ] {
            let (_, refusal) = substituted(&format!("{name}.sqlite"), Box::new(move |placed: &Path| {
                Connection::open(placed).unwrap().execute_batch(change).unwrap();
            }));
            assert!(refusal.contains("is not the one just made") && refusal.contains(what), "{name}: {refusal}");
        }
        // One that cannot be read back is not taken for one that differs: the error is said.
        let (_, refusal) = substituted("unreadable.sqlite", Box::new(|placed: &Path| {
            Connection::open(placed).unwrap().execute("update meta set value = 'forty' where name = 'read to'", []).unwrap();
        }));
        assert!(refusal.contains("could not be read back") && refusal.contains("damaged"), "{refusal}");
        let (copy, refusal) = substituted("gone.sqlite", Box::new(|placed: &Path| fs::remove_file(placed).unwrap()));
        assert!(!refusal.is_empty());
        assert!(!copy.exists(), "opening a copy just made never makes one");
        // Left alone, the copy made is the one opened.
        let (replica, _) = Replica::open_from_snapshot(&scratch.0.join("left.sqlite"), node.config(), &from, Some(summary.sha256)).unwrap();
        assert_eq!(replica.status().read_to, 40);
    }

    #[test]
    fn a_wrong_answer_in_a_poll_that_failed_does_not_hold_back_a_right_one() {
        let scratch = Scratch::new("snapshot-failed-poll");
        let path = scratch.file();
        let node = Node::start();
        let galaxy = wallet(1).1;
        node.with(|chain| {
            history(chain);
            chain.finalized = 40;
        });
        let replica = Replica::open(&path, ReplicaConfig { tries: 2, ..node.config() }).unwrap();
        replica.poll().unwrap();
        // The node confirms the file's block, but gives the final block, 42, a wrong hash
        // once; a right log from block 42 then disagrees with it, and nothing is committed.
        node.with(|chain| {
            chain.azimuth(42, b"OwnerChanged(uint32,address)", 0, Some(word(&galaxy)), vec![]);
            chain.finalized = 42;
            chain.lying.insert(42, [0xdd; 32]);
        });
        assert!(replica.poll().unwrap_err().contains("block 42 is said to have two hashes"));
        assert_eq!(replica.status().read_to, 40);
        // Then it answers rightly, at the same final block: the copy goes on, without being
        // opened again.
        node.with(|chain| chain.lying.clear());
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 42);
        assert_eq!(kept_hash(&path), Some(block_hash(42)));
        assert!(replica.listing(PLANET).unwrap().is_some());
        // The same for a final block far ahead of the chain, given once in a poll that then
        // fails: a right, lower one afterwards is not taken for the chain going back.
        node.with(|chain| {
            chain.finalized = 1_000_000;
            chain.failing.insert("eth_getLogs".into(), 100);
        });
        assert!(replica.poll().is_err());
        assert!(replica.listing(PLANET).is_err(), "lookups wait meanwhile");
        node.with(|chain| {
            chain.finalized = 45;
            chain.failing.clear();
        });
        replica.poll().unwrap();
        assert_eq!(replica.status().read_to, 45);
        assert!(replica.listing(PLANET).unwrap().is_some());
    }

    #[test]
    fn a_file_at_the_copys_name_that_is_not_a_copy_is_not_taken_for_one_when_a_snapshot_is_asked_for() {
        let scratch = Scratch::new("snapshot-not-a-copy");
        let node = Node::start();
        let (_, from, summary) = source_and_snapshot(&scratch, &node);
        // An empty file, and a database that is not a copy.
        let empty = scratch.0.join("empty.sqlite");
        fs::write(&empty, b"").unwrap();
        let other = scratch.0.join("other.sqlite");
        Connection::open(&other).unwrap().execute_batch("create table notes (text text); insert into notes values ('mine');").unwrap();
        for (path, why) in [(&empty, "is empty"), (&other, "keeps no record of what it is a copy of")] {
            let before = fs::read(path).unwrap();
            let refusal = Replica::open_from_snapshot(path, node.config(), &from, Some(summary.sha256)).unwrap_err();
            assert!(refusal.contains(why) && refusal.contains("remove it"), "{refusal}");
            assert!(fs::read(path).unwrap() == before, "nothing is written to it");
            for end in BESIDE {
                assert!(!beside(path, end).exists(), "{end}");
            }
        }
        // Opened without a snapshot, an empty file is set up as a copy that has read nothing,
        // as before.
        let replica = Replica::open(&empty, node.config()).unwrap();
        assert_eq!(replica.status().read_to, 9);
        drop(replica);
        // A copy that is there is used as it is, and the snapshot is not.
        let (_, restored) = Replica::open_from_snapshot(&empty, node.config(), &from, None).unwrap();
        assert!(matches!(restored, Restored::Ignored));
        // A copy just made and found emptied is refused, and on the next start it is not
        // quietly read from the beginning either.
        let emptied = scratch.0.join("emptied.sqlite");
        step_in_at(&from, "placed", |placed: &Path| fs::write(placed, b"").unwrap());
        assert!(Replica::open_from_snapshot(&emptied, node.config(), &from, None).unwrap_err().contains("is not the one just made"));
        step_out(&from);
        assert!(Replica::open_from_snapshot(&emptied, node.config(), &from, None).unwrap_err().contains("is empty"));
        assert_eq!(fs::metadata(&emptied).unwrap().len(), 0);
    }

    #[test]
    fn files_beside_a_copy_that_are_not_plain_files_of_its_own_are_refused_and_left_alone() {
        let scratch = Scratch::new("snapshot-plain-beside");
        let node = Node::start();
        let (source, from, _) = source_and_snapshot(&scratch, &node);
        let elsewhere = scratch.0.join("elsewhere.txt");
        fs::write(&elsewhere, b"someone else's").unwrap();
        for end in BESIDE {
            for (kind, said) in [("link", "is a link"), ("second name", "is a file with more than one name"), ("directory", "is not a plain file")] {
                // (Writing the snapshot read the copy, which leaves SQLite's own plain files
                // beside it; they are taken away first, to put something else there.)
                for left in BESIDE {
                    let _ = fs::remove_file(beside(&source, left));
                }
                let name = beside(&source, end);
                match kind {
                    "link" => std::os::unix::fs::symlink(&elsewhere, &name).unwrap(),
                    "second name" => fs::hard_link(&elsewhere, &name).unwrap(),
                    _ => fs::create_dir(&name).unwrap(),
                }
                let named = name.display().to_string();
                for refusal in [
                    Replica::open(&source, node.config()).err(),
                    Replica::open_from_snapshot(&source, node.config(), &from, None).err(),
                    snapshot::write(&source, &node.config(), &scratch.0.join("out.snapshot")).err(),
                ] {
                    let refusal = refusal.unwrap_or_else(|| panic!("{end} as {kind}: taken"));
                    assert!(refusal.contains(&format!("{named} {said}")) && refusal.contains("Remove it"), "{end} as {kind}: {refusal}");
                }
                assert_eq!(fs::read(&elsewhere).unwrap(), b"someone else's", "{end} as {kind}");
                assert!(!scratch.0.join("out.snapshot").exists());
                match kind {
                    "directory" => fs::remove_dir(&name).unwrap(),
                    _ => fs::remove_file(&name).unwrap(),
                }
            }
        }
        // Nor is anything at the copy's own name that is not a plain file, such as a pipe,
        // which SQLite could wait on for ever.
        // (Each is tried on a thread of its own, so that the test fails rather than waits if
        // one does wait.)
        let pipe = scratch.0.join("pipe.sqlite");
        let named = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(named.as_ptr(), 0o600) }, 0);
        let within = |try_it: Box<dyn FnOnce() -> Option<String> + Send>| {
            let (done, answer) = std::sync::mpsc::channel();
            std::thread::spawn(move || done.send(try_it()));
            answer.recv_timeout(Duration::from_secs(10)).ok().flatten().unwrap_or_default()
        };
        let (cfg, piped, out) = (node.config(), pipe.clone(), scratch.0.join("pipe.snapshot"));
        assert!(within(Box::new(move || Replica::open(&piped, cfg).err())).contains("not a plain file"));
        let (cfg, piped, offered) = (node.config(), pipe.clone(), from.clone());
        assert!(within(Box::new(move || Replica::open_from_snapshot(&piped, cfg, &offered, None).err())).contains("not a plain file"));
        let (cfg, piped) = (node.config(), pipe.clone());
        assert!(within(Box::new(move || snapshot::write(&piped, &cfg, &out).err())).contains("not a plain file"));
        // Nor a link put beside a copy a restore has just made, before it is opened.
        let made = fs::canonicalize(&scratch.0).unwrap().join("made.sqlite");
        let pointing = elsewhere.clone();
        step_in_at(&from, "placed", move |placed: &Path| std::os::unix::fs::symlink(&pointing, beside(placed, "-shm")).unwrap());
        let refusal = Replica::open_from_snapshot(&made, node.config(), &from, None).unwrap_err();
        step_out(&from);
        assert!(refusal.contains("-shm is a link"), "{refusal}");
        assert_eq!(fs::read(&elsewhere).unwrap(), b"someone else's");
        // Plain files of its own beside it are SQLite's, and left to it.
        let replica = Replica::open(&source, node.config()).unwrap();
        assert!(beside(&source, "-wal").exists() && beside(&source, "-shm").exists());
        assert!(snapshot::write(&source, &node.config(), &scratch.0.join("beside.snapshot")).is_ok());
        drop(replica);
    }

    /// Leave at `to` the copy in `of` as a crash part way through a change would leave it: in a
    /// rollback journal, its file part changed and the change beside it in a hot journal, to be
    /// undone. (`of` is left in that journal, with the change undone.)
    fn crashed_part_way(of: &Path, to: &Path) {
        let changing = Connection::open(of).unwrap();
        changing.execute_batch("pragma journal_mode = delete").unwrap();
        changing.execute_batch("pragma cache_size = 2; begin; create table spill (x blob);").unwrap();
        for _ in 0..200 {
            changing.execute("insert into spill values (randomblob(4000))", []).unwrap();
        }
        fs::copy(of, to).unwrap();
        fs::copy(beside(of, "-journal"), beside(to, "-journal")).unwrap();
        changing.execute_batch("rollback").unwrap();
    }

    #[test]
    fn a_copy_with_a_change_a_crash_left_unfinished_is_recovered_not_refused() {
        let scratch = Scratch::new("snapshot-hot-journal");
        let node = Node::start();
        let (_, from, summary) = source_and_snapshot(&scratch, &node);
        let directory = fs::canonicalize(&scratch.0).unwrap();
        // A restore leaves nothing of the kind: when the copy is given its name it is already
        // in its usual journal, with nothing beside it, and opening it changes nothing.
        let restored = directory.join("restored.sqlite");
        let seen = Arc::new(Mutex::new(None));
        let seeing = seen.clone();
        step_in_at(&from, "placed", move |placed: &Path| {
            let header = fs::read(placed).unwrap();
            let beside_it: Vec<bool> = BESIDE.iter().map(|end| beside(placed, end).exists()).collect();
            *seeing.lock().unwrap() = Some(((header[18], header[19]), beside_it, header));
        });
        let (replica, _) = Replica::open_from_snapshot(&restored, node.config(), &from, Some(summary.sha256)).unwrap();
        step_out(&from);
        drop(replica);
        let (journal, beside_it, placed_bytes) = seen.lock().unwrap().clone().unwrap();
        assert_eq!(journal, (2, 2), "in its write-ahead journal when named");
        assert_eq!(beside_it, [false; 3], "nothing beside it when named");
        assert!(fs::read(&restored).unwrap() == placed_bytes, "opened and closed, it is as it was named");
        // A restored copy as a crash in a change of journal would leave it (the way copies were
        // made before), and the same start again: it is recovered and used, not refused.
        let crashed = directory.join("crashed.sqlite");
        crashed_part_way(&restored, &crashed);
        assert!(beside(&crashed, "-journal").exists());
        assert!(connect(&crashed, Access::Read).unwrap().query_row("select count(*) from meta", [], |row| row.get::<_, i64>(0)).is_err(), "it cannot be read without being recovered");
        let (replica, restored_again) = Replica::open_from_snapshot(&crashed, node.config(), &from, Some(summary.sha256)).unwrap();
        assert!(matches!(restored_again, Restored::Ignored));
        assert_eq!(replica.status().read_to, 40);
        assert!(!beside(&crashed, "-journal").exists(), "the unfinished change was undone");
        replica.poll().unwrap();
        assert!(replica.listing(PLANET).unwrap().is_some());
        drop(replica);
        let (_, written) = snapshot_bytes(&crashed, &node.config(), &directory.join("crashed.snapshot"));
        assert!(written == fs::read(&from).unwrap(), "the copy recovered is the copy made");
        // A file that is not a database, with such a journal beside it, is left exactly as found.
        let junk = directory.join("junk.sqlite");
        fs::write(&junk, vec![0x5a; 8192]).unwrap();
        let again = directory.join("again.sqlite");
        crashed_part_way(&restored, &again);
        fs::copy(beside(&again, "-journal"), beside(&junk, "-journal")).unwrap();
        let journal_bytes = fs::read(beside(&junk, "-journal")).unwrap();
        let refusal = Replica::open_from_snapshot(&junk, node.config(), &from, None).unwrap_err();
        assert!(refusal.contains("is not an SQLite database") && refusal.contains("It has been left as it is"), "{refusal}");
        assert!(!refusal.contains("first start"), "an ordinary start cannot make a copy of what is not a database: {refusal}");
        // Another SQLite database, not a copy, with such a change left unfinished: SQLite undoes
        // it on the way, as any opening would, and the refusal says so, not that it was left.
        let theirs = directory.join("theirs.sqlite");
        Connection::open(&theirs).unwrap().execute_batch("create table notes (text text); insert into notes values ('mine');").unwrap();
        let unfinished = directory.join("unfinished.sqlite");
        crashed_part_way(&theirs, &unfinished);
        let refusal = Replica::open_from_snapshot(&unfinished, node.config(), &from, None).unwrap_err();
        assert!(refusal.contains("keeps no record") && refusal.contains("SQLite undid a change a crash had left unfinished in it"), "{refusal}");
        assert!(!refusal.contains("left as it is"), "{refusal}");
        assert!(!beside(&unfinished, "-journal").exists());
        let notes: String = Connection::open(&unfinished).unwrap().query_row("select text from notes", [], |row| row.get(0)).unwrap();
        assert_eq!(notes, "mine", "nothing else was changed");
        assert_eq!(fs::read(&junk).unwrap(), vec![0x5a; 8192]);
        assert!(fs::read(beside(&junk, "-journal")).unwrap() == journal_bytes);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_refused_with_sqlites_own_error_and_left_as_it_is() {
        let scratch = Scratch::new("snapshot-unreadable");
        let node = Node::start();
        let (source, from, _) = source_and_snapshot(&scratch, &node);
        // An SQLite database's beginning, and damage after it.
        let damaged = scratch.0.join("damaged.sqlite");
        let mut bytes = fs::read(&source).unwrap()[..100].to_vec();
        bytes.extend(vec![0xa5; 8092]);
        fs::write(&damaged, &bytes).unwrap();
        let refusal = Replica::open_from_snapshot(&damaged, node.config(), &from, None).unwrap_err();
        // It says what was done to it (nothing), and promises a recovery only for a change a
        // crash left unfinished, which an ordinary start can finish; otherwise it is damaged.
        assert!(refusal.contains("could not be read to tell whether it is a copy") && refusal.contains("It has been left as it is"), "{refusal}");
        assert!(refusal.contains("If the trouble is a change a crash left unfinished, an ordinary start") && refusal.contains("otherwise the file is damaged"), "{refusal}");
        assert!(refusal.contains("malformed") || refusal.contains("not a database"), "SQLite's own error: {refusal}");
        assert!(fs::read(&damaged).unwrap() == bytes);
        // A change a crash left unfinished, undone, and the file still damaged (its record's
        // page, which the change did not touch, overwritten): no ordinary start is promised to
        // mend it, and it says what was done.
        let crashed = scratch.0.join("crashed.sqlite");
        crashed_part_way(&source, &crashed);
        // (Both the table's page and its key's, since the record is found through the key.)
        let (page_size, meta_pages): (u64, Vec<u64>) = {
            let reading = Connection::open(&source).unwrap();
            let pages = reading.prepare("select rootpage from sqlite_master where tbl_name = 'meta'").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
            (reading.query_row("pragma page_size", [], |row| row.get(0)).unwrap(), pages)
        };
        let mut file = fs::OpenOptions::new().write(true).open(&crashed).unwrap();
        for page in meta_pages {
            std::io::Seek::seek(&mut file, std::io::SeekFrom::Start((page - 1) * page_size)).unwrap();
            file.write_all(&vec![0xa5; page_size as usize]).unwrap();
        }
        drop(file);
        let refusal = Replica::open_from_snapshot(&crashed, node.config(), &from, None).unwrap_err();
        assert!(refusal.contains("SQLite undid a change a crash had left unfinished in it") && refusal.contains("The file is damaged"), "{refusal}");
        assert!(!refusal.contains("an ordinary start (without --azimuth-snapshot) will finish it") && !refusal.contains("left as it is"), "{refusal}");
    }

    #[test]
    fn a_snapshot_is_not_written_of_a_copy_with_a_change_left_unfinished_and_says_why() {
        let scratch = Scratch::new("snapshot-writer-hot");
        let node = Node::start();
        let (source, before, _) = source_and_snapshot(&scratch, &node);
        let crashed = scratch.0.join("crashed.sqlite");
        crashed_part_way(&source, &crashed);
        let out = scratch.0.join("out.snapshot");
        let refusal = snapshot::write(&crashed, &node.config(), &out).unwrap_err();
        assert!(refusal.contains("a crash left unfinished") && refusal.contains("open it once"), "{refusal}");
        assert!(!out.exists());
        // Opened once, it is recovered, and the snapshot is the copy's.
        drop(Replica::open(&crashed, node.config()).unwrap());
        assert!(snapshot::write(&crashed, &node.config(), &out).is_ok());
        assert!(fs::read(&out).unwrap() == fs::read(&before).unwrap());
    }

    #[test]
    fn a_first_start_cut_short_is_finished_by_an_ordinary_open_and_not_taken_for_a_copy_with_a_snapshot() {
        let scratch = Scratch::new("snapshot-first-start");
        let node = Node::start();
        let (_, from, _) = source_and_snapshot(&scratch, &node);
        let directory = fs::canonicalize(&scratch.0).unwrap();
        // The points at which a first start writes: the file made, put in its journal, its
        // tables made, its record of what it is a copy of written. (Empty is tested elsewhere.)
        for (name, steps) in [("journal.sqlite", "pragma journal_mode = wal;"), ("tables.sqlite", "pragma journal_mode = wal;")] {
            let path = directory.join(name);
            let making = connect(&path, Access::Make).unwrap();
            making.execute_batch(steps).unwrap();
            if name == "tables.sqlite" {
                making.execute_batch(SCHEMA).unwrap();
            }
            drop(making);
            let before = fs::read(&path).unwrap();
            let refusal = Replica::open_from_snapshot(&path, node.config(), &from, None).unwrap_err();
            assert!(refusal.contains("keeps no record of what it is a copy of") && refusal.contains("starting once without --azimuth-snapshot finishes it"), "{name}: {refusal}");
            assert!(fs::read(&path).unwrap() == before, "{name}: left as it is");
            let replica = Replica::open(&path, node.config()).unwrap();
            assert_eq!(replica.status().read_to, 9, "{name}: finished as a copy that has read nothing");
            drop(replica);
            let (_, restored) = Replica::open_from_snapshot(&path, node.config(), &from, None).unwrap();
            assert!(matches!(restored, Restored::Ignored), "{name}");
        }
    }

    #[test]
    fn a_restore_that_leaves_anything_beside_the_file_it_makes_makes_no_copy() {
        let scratch = Scratch::new("snapshot-left-beside");
        let node = Node::start();
        let (_, from, _) = source_and_snapshot(&scratch, &node);
        let copy = fs::canonicalize(&scratch.0).unwrap().join("copy.sqlite");
        step_in_at(&from, "closed", |made: &Path| fs::write(beside(made, "-wal"), b"left").unwrap());
        let refusal = Replica::open_from_snapshot(&copy, node.config(), &from, None).unwrap_err();
        step_out(&from);
        assert!(refusal.contains("was not whole on its own") && refusal.contains("-wal"), "{refusal}");
        assert!(!copy.exists());
        assert!(!names_in(&scratch.0).iter().any(|name| name.ends_with(".part") || name.ends_with(".part-wal")), "{:?}", names_in(&scratch.0));
    }

    #[test]
    fn a_change_left_unfinished_that_cannot_be_undone_is_said_so_without_claiming_more() {
        use std::os::unix::fs::PermissionsExt;
        // Whoever may write any file would undo it; the case is one of a file that may not be.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let scratch = Scratch::new("snapshot-cannot-undo");
        let node = Node::start();
        let (source, from, _) = source_and_snapshot(&scratch, &node);
        let crashed = scratch.0.join("crashed.sqlite");
        crashed_part_way(&source, &crashed);
        // The copy may not be written to; the directory it is in still may.
        fs::set_permissions(&crashed, fs::Permissions::from_mode(0o444)).unwrap();
        let before = (fs::read(&crashed).unwrap(), fs::read(beside(&crashed, "-journal")).unwrap());
        let refusal = Replica::open_from_snapshot(&crashed, node.config(), &from, None).err();
        let after = (fs::read(&crashed).unwrap(), fs::read(beside(&crashed, "-journal")).unwrap());
        fs::set_permissions(&crashed, fs::Permissions::from_mode(0o644)).unwrap();
        let refusal = refusal.expect("refused");
        assert!(refusal.contains("a change a crash left unfinished") && refusal.contains("could not be undone") && refusal.contains("Nothing was changed"), "{refusal}");
        assert!(!refusal.contains("SQLite undid") && !refusal.contains("damaged"), "{refusal}");
        assert!(before == after, "nothing was changed");
        // Once it may be written to, the same start undoes the change and uses the copy.
        let (replica, restored) = Replica::open_from_snapshot(&crashed, node.config(), &from, None).unwrap();
        assert!(matches!(restored, Restored::Ignored));
        assert_eq!(replica.status().read_to, 40);
    }
}
