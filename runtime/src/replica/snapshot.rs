//! A snapshot of the copy of Azimuth: one flat file holding every point in the copy, the
//! block the copy has read to with that block's hash, and its counts.
//!
//! A copy built from nothing reads all of Azimuth's history, which takes a node that answers
//! questions about wide ranges of old blocks. A copy started from a snapshot reads only what
//! came after the snapshot's block, which any node can answer.
//!
//! A snapshot is written in one form only: the same table at the same block, by the same
//! rules, always gives the same bytes, however the copy got there (from the beginning or from
//! another snapshot, in steps of any size). So its fingerprint, the SHA-256 of the whole file,
//! can be checked by anyone who reads Azimuth to the same block themselves
//! (`ReplicaConfig::until`) and writes their own. What a snapshot does and does not prove is
//! set out in the README.
//!
//! A snapshot is handed over by someone else, so it is read as if it were hostile: its length
//! must be exactly what its header says before any point in it is believed, it is read through
//! a buffer of fixed size, every point must be in the one form allowed, and the copy is made
//! from it whole or not at all. Its points may still be wrong; nothing in the file can show
//! otherwise. Once made and given its name, the copy is opened without making a file if there
//! is none, and read back before anything is written to it: its tables, its journal, what it
//! is a copy of, the block, its hash, the counts and the number of points must be what was
//! made, or the copy is not used.
//!
//! Snapshots are written and restored only where a file can be given a name only if the name
//! is free, in one step: macOS and Linux (`SUPPORTED`). Elsewhere `serve` refuses either
//! snapshot flag before the copy is opened or anything is made, and `Replica::open_from_snapshot`
//! and `write` each refuse before they make or open anything.
//!
//! A restore, and what a crash at each point of it leaves:
//!
//! 1. A file is made new under a name of its own beside the copy's (`.<name>.<pid>.<time>.part`),
//!    with nothing of SQLite's beside that name. Every point, the block, its hash and the
//!    counts go into it in one transaction, with a rollback journal. A crash leaves that file,
//!    perhaps with its journal; the copy's name is still free, so the next start makes the copy
//!    again, under another name of its own. What was left is never taken for the copy.
//! 2. The file is put in the copy's usual journal (write-ahead), which SQLite does with a
//!    rollback journal of its own. A crash leaves the same as in 1.
//! 3. The only connection is closed, which writes everything into the file and takes its log
//!    away. A crash before then leaves the file with its log beside it, under its own name: the
//!    same as in 1.
//! 4. Nothing of SQLite's may be left beside the file: if anything is, the restore fails, and
//!    takes away the file and what is beside it, which it made itself. The file is put on disk.
//! 5. It is given the copy's name, only if that name is still free. A crash before then is as in
//!    1; after, the copy is there and whole, in its usual journal, with nothing beside it.
//! 6. It is opened, without the right to make a file, and read back before anything is written
//!    to it; opening it needs no change to its journal. A crash then leaves the copy with, at
//!    most, SQLite's own log and shared memory beside it, which the next start reads as any
//!    copy's.
//!
//! The directory that holds the copy is taken to be the operator's own. What is found there
//! when the copy is opened is checked: nothing SQLite would take as part of a new copy; at the
//! copy's name, once a symbolic link to it has been followed (which is done on purpose, so that
//! a copy is reached under one name however it is named), a plain file with one name; and
//! beside it, no link, second name or other thing that is not a plain file.
//! Another program able to write in the directory while the copy runs is not defended against:
//! it could replace the copy itself at any time, so nothing here tries to stop it changing the
//! files a restore makes there while it works.
//!
//! # Layout
//!
//! Every number is unsigned and written with its most significant byte first. A yes or no is
//! one byte, 0 or 1. A field with nothing in it is all zeros.
//!
//! The header, 176 bytes:
//!
//! | at  | bytes | what                                                          |
//! |-----|-------|---------------------------------------------------------------|
//! | 0   | 8     | `AZSNAP` then a carriage return and a line feed               |
//! | 8   | 4     | the format, 1                                                 |
//! | 12  | 4     | the version of the rules the table was worked out by (`RULES`) |
//! | 16  | 8     | Ethereum's chain number                                       |
//! | 24  | 20    | the Azimuth contract                                          |
//! | 44  | 8     | the block it was made in                                      |
//! | 52  | 20    | the layer 2 contract                                          |
//! | 72  | 8     | the block it was made in                                      |
//! | 80  | 8     | the block the copy had read to                                |
//! | 88  | 32    | that block's hash                                             |
//! | 120 | 48    | the counts: logs, batches, unreadable, applied, failed, unsigned, 8 bytes each |
//! | 168 | 8     | how many points follow                                        |
//!
//! Then one record for each point in the table, 211 bytes each, in strictly ascending order of
//! ship:
//!
//! | at  | bytes | what                                                  |
//! |-----|-------|-------------------------------------------------------|
//! | 0   | 4     | the ship                                              |
//! | 4   | 1     | where it is: 0 layer 1, 1 layer 2, 2 layer 1 with its children made on layer 2 |
//! | 5   | 24    | its owner: an address of 20 bytes, then a count of 4  |
//! | 29  | 24    | its spawn proxy, the same way                         |
//! | 53  | 24    | its management proxy                                  |
//! | 77  | 24    | its voting proxy                                      |
//! | 101 | 24    | its transfer proxy                                    |
//! | 125 | 4     | its continuity (how many times it has started afresh) |
//! | 129 | 4     | its key revision                                      |
//! | 133 | 4     | its key suite                                         |
//! | 137 | 32    | its authentication key, as Azimuth keeps it           |
//! | 169 | 32    | its encryption key, as Azimuth keeps it               |
//! | 201 | 1     | whether it has a sponsor                              |
//! | 202 | 4     | its sponsor (kept when it has none: the one it had)   |
//! | 206 | 1     | whether it has asked to escape                        |
//! | 207 | 4     | to whom; zero when it has not                         |
//!
//! So a snapshot of n points is exactly 176 + 211 × n bytes long.

use std::ffi::OsString;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use urbit_id::naive::{Dominion, Holder, NetKeys, Point, Points};

use super::{beside, connect, sqlite_code, BESIDE, SQLITE_READONLY_ROLLBACK, counts_mut, keep_number, made_for, none_beside, plain_beside, point_of_row, read_counts, read_to, read_to_hash, sql, true_name, Access, Counts, ReplicaConfig, Stored, COUNTS, SCHEMA};
use crate::chain::hex;

/// The first bytes of every snapshot. The carriage return and line feed show at once a file
/// that has been carried as text and had its line endings changed.
pub const MAGIC: [u8; 8] = *b"AZSNAP\r\n";
/// The layout above. Another layout is another number.
pub const FORMAT: u32 = 1;
/// The version of the rules a table is worked out by. It is raised whenever `urbit_id::naive`
/// or the way the copy reads and applies Azimuth's history changes what a given history gives,
/// so that a snapshot worked out by other rules is never taken as one worked out by these.
pub const RULES: u32 = 1;
pub const HEADER_BYTES: u64 = 176;
pub const RECORD_BYTES: u64 = 211;
/// The most points a snapshot can hold: every ship there can be, since ships are numbered in
/// 32 bits and each is in a snapshot at most once.
const MOST_POINTS: u64 = 1 << 32;
/// How much of a snapshot is held in memory at once while it is read.
const BUFFER_BYTES: usize = 64 << 10;

/// Whether snapshots are written and restored on this system: only where a file can be given a
/// name only if the name is free, in one step (macOS's `renamex_np` with `RENAME_EXCL`, Linux's
/// `renameat2` with `RENAME_NOREPLACE`). Elsewhere a copy or a snapshot could not be put in
/// place without a moment when a crash would leave it with two names, or replace a file.
pub const SUPPORTED: bool = cfg!(any(target_os = "macos", target_os = "linux"));

/// What is said where snapshots are not supported.
pub const UNSUPPORTED: &str =
    "this system has no way to put a file in place without the risk of replacing one, so snapshots are neither written nor restored here; the copy can still be made by reading Azimuth from the start";

/// Refuse where snapshots are not supported. Each caller asks this before it makes or opens
/// anything.
pub fn supported() -> Result<(), String> {
    if SUPPORTED {
        Ok(())
    } else {
        Err(UNSUPPORTED.to_string())
    }
}

/// Something a test does part way through: crash a restore, grow a snapshot while it is read,
/// write to a copy while a snapshot of it is read, or put something where a new file is to be
/// made. Each is for one file, named as the test gave it, so that tests running at once do not
/// meet; each is handed the name of the file being made.
#[cfg(test)]
type Hook = Box<dyn FnMut(&Path) + Send>;
#[cfg(test)]
pub(super) static HOOKS: std::sync::Mutex<Vec<(std::path::PathBuf, &'static str, Hook)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(super) fn step_in(file: &Path, at: &'static str, making: &Path) {
    let mut hooks = HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    for (for_file, for_at, hook) in hooks.iter_mut() {
        if for_file == file && *for_at == at {
            hook(making);
        }
    }
}

#[cfg(not(test))]
pub(super) fn step_in(_: &Path, _: &'static str, _: &Path) {}

/// What a snapshot holds, and its fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The block the copy had read to, and its hash.
    pub block: u64,
    pub hash: [u8; 32],
    pub counts: Counts,
    pub points: u64,
    pub bytes: u64,
    /// The SHA-256 of the whole file.
    pub sha256: [u8; 32],
}

impl Summary {
    /// The lines a person publishes beside a snapshot, so that whoever takes it can pin it.
    pub fn lines(&self) -> String {
        format!(
            "Snapshot of Azimuth, format {FORMAT}, rules version {RULES}\nblock: {}\nblock hash: {}\npoints: {}\nbytes: {}\nsha256: {}\n",
            self.block,
            hex(&self.hash),
            self.points,
            self.bytes,
            plain_hex(&self.sha256)
        )
    }
}

/// A fingerprint written as 64 hexadecimal digits, as `shasum -a 256` writes one.
pub fn fingerprint(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || text.starts_with("0x") {
        return None;
    }
    crate::chain::bytes(&format!("0x{text}"))?.try_into().ok()
}

/// Bytes as hexadecimal digits, with no `0x` in front: how a fingerprint is written.
pub fn plain_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(2 * bytes.len()), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// What the header says.
struct Header {
    chain: u64,
    azimuth: [u8; 20],
    azimuth_from: u64,
    naive: [u8; 20],
    naive_from: u64,
    block: u64,
    hash: [u8; 32],
    counts: Counts,
    points: u64,
}

/// Bytes put one after another into a buffer of a fixed size.
struct Put<const N: usize> {
    bytes: [u8; N],
    at: usize,
}

impl<const N: usize> Put<N> {
    fn new() -> Put<N> {
        Put { bytes: [0; N], at: 0 }
    }

    fn put(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }

    fn done(self) -> [u8; N] {
        assert_eq!(self.at, N, "every byte of a header or record is written");
        self.bytes
    }
}

/// Bytes taken one after another from a buffer of a fixed size.
struct Take<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Take<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        out.copy_from_slice(&self.bytes[self.at..self.at + N]);
        self.at += N;
        out
    }

    fn byte(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }
}

fn header_bytes(header: &Header) -> [u8; HEADER_BYTES as usize] {
    let mut out = Put::new();
    out.put(&MAGIC);
    out.put(&FORMAT.to_be_bytes());
    out.put(&RULES.to_be_bytes());
    out.put(&header.chain.to_be_bytes());
    out.put(&header.azimuth);
    out.put(&header.azimuth_from.to_be_bytes());
    out.put(&header.naive);
    out.put(&header.naive_from.to_be_bytes());
    out.put(&header.block.to_be_bytes());
    out.put(&header.hash);
    let mut counts = header.counts;
    for count in counts_mut(&mut counts) {
        out.put(&count.to_be_bytes());
    }
    out.put(&header.points.to_be_bytes());
    out.done()
}

/// The header, if it is one this runtime reads. Every number the copy writes down must fit
/// SQLite's numbers, which go up to 2^63 - 1.
fn read_header(bytes: &[u8; HEADER_BYTES as usize]) -> Result<Header, String> {
    let mut take = Take { bytes, at: 0 };
    if take.take::<8>() != MAGIC {
        return Err("it is not a snapshot of Azimuth".into());
    }
    let format = take.u32();
    if format != FORMAT {
        return Err(format!("it is in format {format}, and only format {FORMAT} is read"));
    }
    let rules = take.u32();
    if rules != RULES {
        return Err(format!("it was worked out by version {rules} of the rules, and this runtime has version {RULES}"));
    }
    let mut header = Header {
        chain: take.u64(),
        azimuth: take.take(),
        azimuth_from: take.u64(),
        naive: take.take(),
        naive_from: take.u64(),
        block: take.u64(),
        hash: take.take(),
        counts: Counts::default(),
        points: 0,
    };
    for count in counts_mut(&mut header.counts) {
        *count = take.u64();
    }
    header.points = take.u64();
    let mut counts = header.counts;
    if header.block > i64::MAX as u64 || counts_mut(&mut counts).iter().any(|count| **count > i64::MAX as u64) {
        return Err("a number in its header is too big to be written down".into());
    }
    if header.points > MOST_POINTS {
        return Err(format!("it says it holds {} points, more than there are ships", header.points));
    }
    Ok(header)
}

/// One point, written in the one form allowed.
fn record(ship: u32, point: &Point) -> [u8; RECORD_BYTES as usize] {
    let mut out = Put::new();
    out.put(&ship.to_be_bytes());
    out.put(&[match point.dominion {
        Dominion::L1 => 0,
        Dominion::L2 => 1,
        Dominion::Spawn => 2,
    }]);
    for holder in [&point.owner, &point.spawn_proxy, &point.management_proxy, &point.voting_proxy, &point.transfer_proxy] {
        out.put(&holder.address);
        out.put(&holder.nonce.to_be_bytes());
    }
    out.put(&point.continuity.to_be_bytes());
    out.put(&point.keys.revision.to_be_bytes());
    out.put(&point.keys.suite.to_be_bytes());
    out.put(&point.keys.authentication);
    out.put(&point.keys.encryption);
    out.put(&[u8::from(point.has_sponsor)]);
    out.put(&point.sponsor.to_be_bytes());
    out.put(&[u8::from(point.escape.is_some())]);
    out.put(&point.escape.unwrap_or(0).to_be_bytes());
    out.done()
}

/// The point a record holds, if the record is in the one form allowed: read, written again,
/// and the same bytes. So a yes or no that is neither 0 nor 1, or an escape that is not asked
/// for but is not zero, is refused, as is a place that is not one of the three.
fn point_of_record(bytes: &[u8; RECORD_BYTES as usize]) -> Result<(u32, Point), String> {
    let mut take = Take { bytes, at: 0 };
    let ship = take.u32();
    let dominion = match take.byte() {
        0 => Dominion::L1,
        1 => Dominion::L2,
        2 => Dominion::Spawn,
        other => return Err(format!("ship {ship} is in place {other}, which is none of the three")),
    };
    let mut holder = || Holder { address: take.take(), nonce: take.u32() };
    let (owner, spawn_proxy, management_proxy, voting_proxy, transfer_proxy) = (holder(), holder(), holder(), holder(), holder());
    let continuity = take.u32();
    let keys = NetKeys { revision: take.u32(), suite: take.u32(), authentication: take.take(), encryption: take.take() };
    let has_sponsor = take.byte() != 0;
    let sponsor = take.u32();
    let escape = (take.byte() != 0).then_some(take.u32());
    let point = Point { dominion, owner, spawn_proxy, management_proxy, voting_proxy, transfer_proxy, continuity, keys, has_sponsor, sponsor, escape };
    if record(ship, &point) != *bytes {
        return Err(format!("ship {ship} is not written in the one form a snapshot allows"));
    }
    Ok((ship, point))
}

/// Write a snapshot of the copy in `copy`, made for the Azimuth `cfg` names, to `out`, and the
/// same lines `Summary::lines` gives to `out` with `.txt` added. No node is asked anything.
///
/// Everything is read in one read transaction, so the points, the block, its hash and the
/// counts all belong to one moment, even while another copy is moving the file on. A copy
/// that does not keep the hash of the block it has read to is refused: a snapshot nobody can
/// place on the chain is not made. Neither file may be there already.
pub fn write(copy: &Path, cfg: &ReplicaConfig, out: &Path) -> Result<Summary, String> {
    supported()?;
    let given = copy;
    let copy = true_name(given)?;
    match fs::symlink_metadata(&copy) {
        Err(_) => return Err(format!("there is no copy of Azimuth at {}", given.display())),
        Ok(found) if !found.file_type().is_file() => return Err(format!("{} is not a plain file, so it is not a copy of Azimuth", given.display())),
        Ok(_) => {}
    }
    let notes = beside(out, ".txt");
    for path in [out, notes.as_path()] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(format!("{} is there already, and a snapshot never replaces a file", path.display()));
        }
    }
    plain_beside(&copy)?;
    let connection = connect(&copy, Access::Read)?;
    connection.busy_timeout(Duration::from_secs(10)).map_err(sql)?;
    let reading = connection.unchecked_transaction().map_err(sql)?;
    let found: Option<String> = reading.query_row("select value from meta where name = 'made for'", [], |row| row.get(0)).optional().map_err(|e| {
        if sqlite_code(&e) == Some(SQLITE_READONLY_ROLLBACK) {
            format!(
                "{} has a change a crash left unfinished (a -journal beside it), which only opening it to write can undo: open it once as a copy (with --lookup, say), which undoes that change unless the file is damaged as well, and then write the snapshot",
                given.display()
            )
        } else {
            sql(e)
        }
    })?;
    let wanted = made_for(cfg);
    if found.as_deref() != Some(wanted.as_str()) {
        return Err(format!("{} is not a copy of the Azimuth this runtime reads ({wanted})", given.display()));
    }
    let block = read_to(&reading)?;
    let hash = read_to_hash(&reading)?.ok_or_else(|| {
        format!("{} does not keep the hash of block {block}, which it has read to, so a snapshot of it could not be placed on the chain. It keeps one once it has read on", given.display())
    })?;
    let counts = read_counts(&reading, cfg)?;
    let points: i64 = reading.query_row("select count(*) from points", [], |row| row.get(0)).map_err(sql)?;
    let points = u64::try_from(points).map_err(|_| "the copy of Azimuth is damaged".to_string())?;
    step_in(out, "counted", out);
    let header = header_bytes(&Header { chain: cfg.chain, azimuth: cfg.azimuth, azimuth_from: cfg.azimuth_from, naive: cfg.naive, naive_from: cfg.naive_from, block, hash, counts, points });
    let summary = write_new(out, |_, file| {
        let mut hasher = Sha256::new();
        let mut writer = BufWriter::with_capacity(BUFFER_BYTES, file);
        let failed = |e: std::io::Error| format!("cannot write {}: {e}", out.display());
        hasher.update(header);
        writer.write_all(&header).map_err(failed)?;
        let mut query = reading.prepare("select * from points order by ship").map_err(sql)?;
        let mut rows = query.query([]).map_err(sql)?;
        let mut written = 0u64;
        while let Some(row) = rows.next().map_err(sql)? {
            let ship = row.get::<_, i64>(0).ok().and_then(|ship| u32::try_from(ship).ok()).ok_or("the copy of Azimuth is damaged")?;
            let written_point = record(ship, &point_of_row(row)?);
            hasher.update(written_point);
            writer.write_all(&written_point).map_err(failed)?;
            written += 1;
        }
        if written != points {
            return Err("the copy of Azimuth changed while it was being read".into());
        }
        writer.flush().map_err(failed)?;
        Ok(Summary { block, hash, counts, points, bytes: HEADER_BYTES + points * RECORD_BYTES, sha256: hasher.finalize().into() })
    })?;
    drop(reading);
    write_new(&notes, |_, file| file.write_all(summary.lines().as_bytes()).map_err(|e| format!("cannot write {}: {e}", notes.display())))?;
    Ok(summary)
}

/// Make a new copy at `path`, where there is none, from the snapshot in `from`. The caller
/// holds the copy's lock. `sha256`, if given, is the fingerprint the snapshot must have.
///
/// The copy is made by the same code as any copy, in one transaction: every point, the block,
/// its hash and the counts, or nothing. It is made under a name of its own beside `path`, put
/// on disk, and only then given its name, and only if that name is still free. Before that it
/// is put in the copy's usual journal and closed, and nothing of SQLite's may be left beside
/// it, so that the file is whole on its own and needs nothing changed once named. So a failure
/// or a crash at any moment leaves no copy, never a part of one, and the next start makes it
/// again (the points at the top of this file). (A crash can leave the file under its own name
/// behind, ending in `.part`; it is never taken for the copy.)
pub(super) fn restore(path: &Path, cfg: &ReplicaConfig, from: &Path, sha256: Option<[u8; 32]>) -> Result<Summary, String> {
    supported()?;
    let named = from.display();
    let refused = |why: String| format!("the snapshot {named} is refused, and no copy is made: {why}");
    let file = fs::File::open(from).map_err(|e| format!("cannot open the snapshot {named}: {e}"))?;
    let length = file.metadata().map_err(|e| format!("cannot read the snapshot {named}: {e}"))?.len();
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, file);
    let mut hasher = Sha256::new();
    if length < HEADER_BYTES {
        return Err(refused("it is shorter than a snapshot's header".into()));
    }
    let mut header = [0; HEADER_BYTES as usize];
    reader.read_exact(&mut header).map_err(|e| refused(format!("it could not be read: {e}")))?;
    hasher.update(header);
    let header = read_header(&header).map_err(refused)?;
    let made = (header.chain, header.azimuth, header.azimuth_from, header.naive, header.naive_from);
    if made != (cfg.chain, cfg.azimuth, cfg.azimuth_from, cfg.naive, cfg.naive_from) {
        return Err(refused(format!(
            "it was made for chain {}, azimuth {} from block {}, naive {} from block {}, and this runtime reads {}",
            header.chain,
            hex(&header.azimuth),
            header.azimuth_from,
            hex(&header.naive),
            header.naive_from,
            made_for(cfg)
        )));
    }
    // Nothing more in the header is believed until the file's length agrees with it.
    let expected = header.points.checked_mul(RECORD_BYTES).and_then(|records| records.checked_add(HEADER_BYTES));
    if expected != Some(length) {
        return Err(refused(format!("it is {length} bytes long, and a snapshot of {} points is not", header.points)));
    }
    let made_for = made_for(cfg);
    write_new(path, |scratch, _| {
        // Made new just now, so it must be there, and nothing SQLite would take as part of it
        // may be beside it.
        none_beside(scratch)?;
        let mut connection = connect(scratch, Access::Write)?;
        // A plain rollback journal for this one transaction, deleted when it is done, so that
        // the file is whole on its own when it is given its name. The copy is switched to its
        // usual journal when it is opened.
        connection.pragma_update(None, "journal_mode", "delete").map_err(sql)?;
        connection.pragma_update(None, "synchronous", "full").map_err(sql)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sql)?;
        transaction.execute_batch(SCHEMA).map_err(sql)?;
        transaction.execute("insert into meta (name, value) values ('made for', ?1), ('read to hash', ?2)", params![made_for, &header.hash[..]]).map_err(sql)?;
        keep_number(&transaction, "read to", header.block)?;
        let mut counts = header.counts;
        for (name, count) in COUNTS.iter().zip(counts_mut(&mut counts)) {
            keep_number(&transaction, name, *count)?;
        }
        let mut points = Stored(&transaction);
        let mut written = [0; RECORD_BYTES as usize];
        let mut last: Option<u32> = None;
        for at in 0..header.points {
            reader.read_exact(&mut written).map_err(|_| refused("it changed while it was being read".into()))?;
            hasher.update(written);
            let (ship, point) = point_of_record(&written).map_err(|why| refused(format!("point {at}: {why}")))?;
            if last.is_some_and(|last| ship <= last) {
                return Err(refused(format!("point {at}: ship {ship} is not after the ship before it")));
            }
            last = Some(ship);
            points.put(ship, &point)?;
            step_in(from, "restoring", scratch);
        }
        step_in(from, "restored", scratch);
        // Nothing after the last point: a file that has grown since its length was found.
        if reader.read(&mut [0; 1]).map_err(|e| refused(format!("it could not be read: {e}")))? != 0 {
            return Err(refused("it changed while it was being read".into()));
        }
        let found: [u8; 32] = hasher.finalize().into();
        if let Some(wanted) = sha256.filter(|wanted| *wanted != found) {
            return Err(refused(format!("its fingerprint is {}, not {}", plain_hex(&found), plain_hex(&wanted))));
        }
        transaction.commit().map_err(sql)?;
        // The copy's usual journal, set here, on the file under its own name: once it has the
        // copy's name, opening it changes nothing to make it a good copy.
        let journal: String = connection.query_row("pragma journal_mode = wal", [], |row| row.get(0)).map_err(sql)?;
        if journal != "wal" {
            return Err(format!("SQLite would not put the copy being made in its usual journal (it says {journal}); it is not made"));
        }
        // Closing the only connection writes everything into the file itself and takes the
        // log and its shared memory away.
        connection.close().map_err(|(_, e)| sql(e))?;
        step_in(from, "closed", scratch);
        // Nothing of SQLite's may be left beside it: the file must be whole on its own when it
        // is given its name. Whatever is there was made by this restore, since nothing was
        // there when it began, and is taken away with it.
        let left: Vec<PathBuf> = BESIDE.iter().map(|end| beside(scratch, end)).filter(|name| fs::symlink_metadata(name).is_ok()).collect();
        if !left.is_empty() {
            let named: Vec<String> = left.iter().map(|name| name.display().to_string()).collect();
            for name in &left {
                let _ = fs::remove_file(name);
            }
            return Err(format!("SQLite left {} beside the copy being made, so it was not whole on its own; it is not made", named.join(" and ")));
        }
        Ok(Summary { block: header.block, hash: header.hash, counts: header.counts, points: header.points, bytes: length, sha256: found })
    })
}

/// Make a new file at `out`, never replacing one there and never following a link there. It
/// is written by `write`, given the file's name for now and the file open, under a name of
/// its own in the same directory; put on disk; and given its name only if that name is still
/// free. On any failure the file under its own name is removed, and nothing is at `out`.
fn write_new<T>(out: &Path, write: impl FnOnce(&Path, &mut fs::File) -> Result<T, String>) -> Result<T, String> {
    let name = out.file_name().ok_or_else(|| format!("{} does not name a file", out.display()))?;
    let directory = match out.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        _ => Path::new("."),
    };
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_nanos());
    let mut own_name = OsString::from(".");
    own_name.push(name);
    own_name.push(format!(".{}.{nanos}.part", std::process::id()));
    let scratch = directory.join(own_name);
    step_in(out, "making", &scratch);
    // Made new, so that nothing there, not even a link, is written through.
    let mut file = fs::OpenOptions::new().read(true).write(true).create_new(true).open(&scratch).map_err(|e| format!("cannot make {}: {e}", scratch.display()))?;
    let done = write(&scratch, &mut file).and_then(|made| {
        file.sync_all().map_err(|e| format!("cannot put {} on disk: {e}", scratch.display()))?;
        place(&scratch, out)?;
        Ok(made)
    });
    drop(file);
    match &done {
        Ok(_) => {
            // So that the new name is on disk too. Some systems cannot do this for a
            // directory; the file is whole either way.
            if let Ok(directory) = fs::File::open(directory) {
                let _ = directory.sync_all();
            }
        }
        // Only the file made here is removed. SQLite removes its own journal when the
        // transaction it was for is rolled back; anything else under a name beside it was not
        // made here, and is left alone.
        Err(_) => {
            let _ = fs::remove_file(&scratch);
        }
    }
    done
}

/// Give `from` the name `to`, only if nothing has that name: never replacing a file there, and
/// never following a link there.
#[cfg(target_os = "macos")]
fn place(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let named = |path: &Path| std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{} is not a name a file can have", path.display()));
    let (from_named, to_named) = (named(from)?, named(to)?);
    if unsafe { libc::renamex_np(from_named.as_ptr(), to_named.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err(format!("cannot name {}: {}", to.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn place(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let named = |path: &Path| std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{} is not a name a file can have", path.display()));
    let (from_named, to_named) = (named(from)?, named(to)?);
    if unsafe { libc::renameat2(libc::AT_FDCWD, from_named.as_ptr(), libc::AT_FDCWD, to_named.as_ptr(), libc::RENAME_NOREPLACE) } != 0 {
        return Err(format!("cannot name {}: {}", to.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Elsewhere there is no such step, and nothing is put in place (`SUPPORTED`).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn place(_from: &Path, _to: &Path) -> Result<(), String> {
    Err(UNSUPPORTED.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(seed: u8) -> Point {
        let holder = |at: u8| Holder { address: [seed.wrapping_add(at); 20], nonce: u32::from(seed) * 7 + u32::from(at) };
        Point {
            dominion: Dominion::Spawn,
            owner: holder(1),
            spawn_proxy: holder(2),
            management_proxy: holder(3),
            voting_proxy: holder(4),
            transfer_proxy: holder(5),
            continuity: 3,
            keys: NetKeys { revision: 9, suite: 1, authentication: [seed; 32], encryption: [!seed; 32] },
            has_sponsor: true,
            sponsor: 0x0100,
            escape: Some(0x0200),
        }
    }

    #[test]
    fn a_point_reads_back_as_written_and_only_in_one_form() {
        let ship = 0x0001_0100;
        let written = record(ship, &point(5));
        assert_eq!(written.len(), 211);
        assert_eq!(point_of_record(&written).unwrap(), (ship, point(5)));
        let without = Point { escape: None, has_sponsor: false, dominion: Dominion::L1, ..point(5) };
        assert_eq!(point_of_record(&record(ship, &without)).unwrap().1, without);
        // Each byte that has one meaning only, written another way.
        for (at, byte) in [(4, 3), (201, 2), (206, 2)] {
            let mut other = written;
            other[at] = byte;
            assert!(point_of_record(&other).is_err(), "byte {at} as {byte}");
        }
        let mut unasked = record(ship, &without);
        unasked[210] = 1;
        assert!(point_of_record(&unasked).unwrap_err().contains("one form"));
    }

    #[test]
    fn a_header_reads_back_and_refuses_what_does_not_fit() {
        let header = Header {
            chain: 1,
            azimuth: [0xaa; 20],
            azimuth_from: 10,
            naive: [0xbb; 20],
            naive_from: 20,
            block: 40,
            hash: [7; 32],
            counts: Counts { logs: 1, batches: 2, unreadable: 3, applied: 4, failed: 5, unsigned: 6 },
            points: 9,
        };
        let written = header_bytes(&header);
        assert_eq!(&written[..8], b"AZSNAP\r\n");
        let read = read_header(&written).unwrap();
        assert_eq!((read.block, read.hash, read.counts, read.points), (40, [7; 32], header.counts, 9));
        let changed = |at: usize, bytes: &[u8]| {
            let mut other = written;
            other[at..at + bytes.len()].copy_from_slice(bytes);
            read_header(&other).err().unwrap_or_default()
        };
        assert!(changed(0, b"B").contains("not a snapshot"));
        assert!(changed(8, &2u32.to_be_bytes()).contains("format 2"));
        assert!(changed(12, &2u32.to_be_bytes()).contains("version 2 of the rules"));
        assert!(changed(80, &(1u64 << 63).to_be_bytes()).contains("too big"));
        for count in 0..6 {
            assert!(changed(120 + 8 * count, &u64::MAX.to_be_bytes()).contains("too big"), "count {count}");
        }
        assert!(changed(168, &((1u64 << 32) + 1).to_be_bytes()).contains("more than there are ships"));
    }

    #[test]
    fn a_name_that_is_taken_is_never_replaced() {
        let directory = std::env::temp_dir().join(format!("snapshot-names-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let (from, to) = (directory.join("from"), directory.join("to"));
        fs::write(&from, "new").unwrap();
        fs::write(&to, "old").unwrap();
        assert!(place(&from, &to).is_err());
        assert_eq!(fs::read_to_string(&to).unwrap(), "old");
        // Nor a link there, whatever it points to.
        let (link, target) = (directory.join("link"), directory.join("target"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(place(&from, &link).is_err());
        assert!(!target.exists());
        // A new file is written whole under its own name, then named, and a taken name is
        // left as it was, with nothing left behind.
        assert!(write_new(&to, |_, file| file.write_all(b"new").map_err(|e| e.to_string())).is_err());
        assert_eq!(fs::read_to_string(&to).unwrap(), "old");
        let fresh = directory.join("fresh");
        write_new(&fresh, |_, file| file.write_all(b"new").map_err(|e| e.to_string())).unwrap();
        assert_eq!(fs::read_to_string(&fresh).unwrap(), "new");
        let mut names: Vec<String> = fs::read_dir(&directory).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["fresh", "from", "link", "to"]);
        // Nor through a link put where the file is first made, under its own name.
        let (planted, elsewhere) = (directory.join("planted"), directory.join("elsewhere"));
        let pointing = elsewhere.clone();
        HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push((planted.clone(), "making", Box::new(move |making: &Path| std::os::unix::fs::symlink(&pointing, making).unwrap())));
        let made = write_new(&planted, |_, file| file.write_all(b"new").map_err(|e| e.to_string()));
        HOOKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|(file, ..)| *file != planted);
        assert!(made.is_err());
        assert!(!elsewhere.exists() && !planted.exists());
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn snapshots_are_supported_here_and_said_not_to_be_where_they_are_not() {
        // Only the side this machine is on can run; the other is the message, and the refusal.
        assert!(SUPPORTED, "macOS and Linux put a file in place without replacing one");
        assert!(supported().is_ok());
        assert!(UNSUPPORTED.contains("without the risk of replacing one") && UNSUPPORTED.contains("reading Azimuth from the start"));
    }

    #[test]
    fn a_fingerprint_is_sixty_four_hexadecimal_digits() {
        assert_eq!(fingerprint(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(fingerprint(&format!("{}\n", "AB".repeat(32))), Some([0xab; 32]));
        for not in ["ab".repeat(31), "ab".repeat(33), format!("0x{}", "ab".repeat(31)), "zz".repeat(32)] {
            assert_eq!(fingerprint(&not), None, "{not}");
        }
    }
}
