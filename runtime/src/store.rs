//! One SQLite file per ship. The file is the ship's source of truth.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::serialize::{Data, OwnedData};
use rusqlite::{params, Connection, DatabaseName, OpenFlags, OptionalExtension, Row};

use ship_proto::{CheckpointBody, Device, Kind, LogNews, Message, PeerMessage, Receipt, Verdict};

use crate::moon::PROOF_BYTES;
use crate::{signed_bytes, AuditEntry, ChainCheck, Config, Durability, Effect, Error, CHECKPOINT_DOMAIN};

const SCHEMA_VERSION: i64 = 9;

// The schema and one query name a command by its number, where SQLite needs to see it written out.
const _: () = assert!(Kind::Command as i32 == 1);

/// Each pending message counts as its payload plus this, so empty messages still use up quota.
pub const MESSAGE_OVERHEAD: u64 = 64;

const MAX_INTERFACE_BYTES: usize = 128;

/// Whether this can be the name of an interface, and so of a log. Not too long, and not `.` or
/// `..`: those mean "here" and "up one" in an address, so a browser rewrites any address that
/// contains them and a log by that name could never be asked for.
pub fn interface_ok(name: &str) -> bool {
    name.len() <= MAX_INTERFACE_BYTES && name != "." && name != ".."
}

/// How many logs one agent may follow. Notifications are not counted against the inbox quota;
/// this is what bounds them, since at most one is ever queued per follower and log.
pub const MAX_FOLLOWS: usize = 64;

/// How many times in a row a follower's notify handler may fail before the runtime stops
/// prompting it. A new entry in the log, or the follower asking to follow again, starts it off
/// afresh.
const MAX_NOTIFY_FAILURES: i64 = 3;

/// A command one agent sent another, or a notification that a log has new entries, waiting to
/// run as its own event.
pub struct Queued {
    pub seq: i64,
    /// `Kind::Command`, `Kind::Notify`, or `Kind::Checkpoint`, as a number.
    pub kind: i32,
    pub source: String,
    pub agent: String,
    pub interface: String,
    pub payload: Vec<u8>,
    /// The ship the sending agent is on, if it is another ship. Empty for this one.
    pub ship: String,
    /// For a command from another ship: the number that ship gave it, which the receipt for
    /// it will carry back.
    pub ship_seq: u64,
}

impl Queued {
    /// What this takes of the inbox quota. Commands and receipts count; see `MAX_FOLLOWS` for
    /// why the rest need not.
    pub fn cost(&self) -> u64 {
        let counted = self.kind == Kind::Command as i32 || self.kind == Kind::Receipt as i32;
        if counted { self.payload.len() as u64 + MESSAGE_OVERHEAD } else { 0 }
    }
}

/// The most a receipt says about why a command did not run.
pub const MAX_REASON_BYTES: usize = 200;

/// More than any receipt takes up, whatever names it carries. A receipt is the runtime's own
/// record and not an agent's payload, so its size has a bound of its own, apart from
/// `max_event_bytes`.
pub const MAX_RECEIPT_BYTES: usize = 512;

/// The most messages that go to another ship in one delivery.
pub const MAX_BATCH_MESSAGES: usize = 256;

/// Far below the point where SQLite refuses to hand out another AUTOINCREMENT value.
const MAX_SEQ: i64 = 1 << 62;

/// The highest entry number this ship will believe of a log on another ship. No log gets
/// there by being written to, and a number beyond it could not be kept in the ship's file.
pub const MAX_LOG_SEQ: u64 = (MAX_SEQ / 2) as u64;

const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value) WITHOUT ROWID;
CREATE TABLE kv (
    agent TEXT NOT NULL,
    key BLOB NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (agent, key)
) WITHOUT ROWID;
CREATE TABLE outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE inbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind INTEGER NOT NULL,
    source TEXT NOT NULL,
    agent TEXT NOT NULL,
    interface TEXT NOT NULL,
    payload BLOB NOT NULL,
    ship TEXT NOT NULL DEFAULT '',
    ship_seq INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX inbox_from ON inbox (ship) WHERE ship != '' AND kind = 1;
CREATE TABLE peers (
    peer TEXT PRIMARY KEY,
    sent INTEGER NOT NULL,
    received INTEGER NOT NULL,
    out_bytes INTEGER NOT NULL,
    resync INTEGER NOT NULL,
    epoch INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE peer_out (
    peer TEXT NOT NULL,
    seq INTEGER NOT NULL,
    source TEXT NOT NULL,
    agent TEXT NOT NULL,
    interface TEXT NOT NULL,
    payload BLOB NOT NULL,
    receipt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (peer, seq)
) WITHOUT ROWID;
CREATE TABLE peer_wait (
    peer TEXT NOT NULL,
    seq INTEGER NOT NULL,
    source TEXT NOT NULL,
    agent TEXT NOT NULL,
    interface TEXT NOT NULL,
    tell INTEGER NOT NULL,
    PRIMARY KEY (peer, seq)
) WITHOUT ROWID;
CREATE TABLE logs (
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    head INTEGER NOT NULL,
    head_hash BLOB NOT NULL,
    bytes INTEGER NOT NULL,
    base INTEGER NOT NULL,
    tail_bytes INTEGER NOT NULL,
    asked INTEGER NOT NULL,
    history INTEGER NOT NULL,
    marked INTEGER NOT NULL,
    PRIMARY KEY (agent, name)
) WITHOUT ROWID;
CREATE TABLE checkpoints (
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    seq INTEGER NOT NULL,
    body BLOB NOT NULL,
    signature BLOB NOT NULL,
    PRIMARY KEY (agent, name)
) WITHOUT ROWID;
CREATE TABLE log_entries (
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    seq INTEGER NOT NULL,
    body BLOB NOT NULL,
    signature BLOB NOT NULL,
    PRIMARY KEY (agent, name, seq)
) WITHOUT ROWID;
CREATE TABLE follows (
    follower TEXT NOT NULL,
    ship TEXT NOT NULL,
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    cursor INTEGER NOT NULL,
    notified INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (follower, ship, agent, name)
) WITHOUT ROWID;
CREATE TABLE remote_logs (
    peer TEXT NOT NULL,
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    follower TEXT NOT NULL,
    head INTEGER NOT NULL,
    head_hash BLOB NOT NULL,
    announced INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    joined INTEGER NOT NULL,
    stopped TEXT NOT NULL,
    gen INTEGER NOT NULL,
    seen BLOB NOT NULL,
    PRIMARY KEY (peer, agent, name, follower)
) WITHOUT ROWID;
CREATE TABLE remote_entries (
    peer TEXT NOT NULL,
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    follower TEXT NOT NULL,
    seq INTEGER NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (peer, agent, name, follower, seq)
) WITHOUT ROWID;
CREATE TABLE remote_checkpoints (
    peer TEXT NOT NULL,
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    follower TEXT NOT NULL,
    seq INTEGER NOT NULL,
    state BLOB NOT NULL,
    PRIMARY KEY (peer, agent, name, follower)
) WITHOUT ROWID;
CREATE TABLE log_shares (
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    peer TEXT NOT NULL,
    PRIMARY KEY (agent, name, peer)
) WITHOUT ROWID;
CREATE TABLE log_peers (
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    peer TEXT NOT NULL,
    due INTEGER NOT NULL,
    kicked INTEGER NOT NULL,
    gen INTEGER NOT NULL,
    PRIMARY KEY (agent, name, peer)
) WITHOUT ROWID;
CREATE INDEX log_peers_due ON log_peers (due, peer);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    agent TEXT NOT NULL,
    event BLOB NOT NULL,
    ok INTEGER NOT NULL
);
CREATE TABLE devices (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE TABLE signin_codes (
    code_hash BLOB PRIMARY KEY,
    expires_ms INTEGER NOT NULL,
    reusable INTEGER NOT NULL
) WITHOUT ROWID;
";

/// The longest label a device may carry.
pub const MAX_LABEL_BYTES: usize = 64;

/// Create a ship file at `path`, which must not exist. The caller creates it under a private
/// name and publishes it afterwards, so a failure here never leaves a half-made ship behind.
pub fn create(
    path: &Path,
    name: &str,
    kernel: &str,
    max_bytes: u64,
    incarnation: &[u8; 16],
    file_key: &[u8; 32],
    recovery: Option<&[u8; 32]>,
    moon_proof: Option<&[u8; PROOF_BYTES]>,
) -> Result<(), Error> {
    // create_new makes "does this ship already exist" atomic.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Error::ShipExists(name.to_string()))
        }
        Err(e) => return Err(e.into()),
    }
    let conn = open(path, Durability::Full, max_bytes, file_key)?;
    // Not WAL while the file is being built: a commit must put the data in the file itself,
    // because only that file is published.
    let mode: String = conn.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))?;
    if mode != "delete" {
        return Err(Error::BadShipFile(format!("{name}: could not prepare a new ship file")));
    }
    conn.execute_batch("BEGIN")?;
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT INTO meta VALUES ('schema', ?1), ('name', ?2), ('kernel', ?3), ('incarnation', ?4)",
        params![SCHEMA_VERSION, name, kernel, &incarnation[..]],
    )?;
    // With everything else, so that a ship that is to have a recovery key never exists
    // without it.
    if let Some(public) = recovery {
        recovery_set(&conn, public)?;
    }
    // Likewise a moon and its parent's word for its key.
    if let Some(proof) = moon_proof {
        conn.execute("INSERT INTO meta VALUES ('moon', ?1)", [&proof[..]])?;
    }
    conn.execute_batch("COMMIT")?;
    Ok(())
}

/// For a moon: its parent's word for its key, which it shows to other ships. It is not a
/// secret. `None` for a ship that has none, or whose file holds something else there.
pub fn moon_proof(conn: &Connection) -> rusqlite::Result<Option<[u8; PROOF_BYTES]>> {
    let stored: Option<Vec<u8>> = conn.query_row("SELECT value FROM meta WHERE key = 'moon'", [], |r| r.get(0)).optional()?;
    Ok(stored.and_then(|proof| <[u8; PROOF_BYTES]>::try_from(proof).ok()))
}

/// The mark this copy of the ship was given when it was made or brought in. Every ship file
/// made by this runtime has one. It is a way to tell that a ship has been brought back from
/// a saved copy of itself, and so may have forgotten things it knew: it changes on every
/// import. It is not a secret, and proves nothing.
pub fn incarnation(conn: &Connection) -> rusqlite::Result<[u8; 16]> {
    let stored: Option<Vec<u8>> = conn.query_row("SELECT value FROM meta WHERE key = 'incarnation'", [], |r| r.get(0)).optional()?;
    Ok(stored.and_then(|mark| <[u8; 16]>::try_from(mark).ok()).unwrap_or_default())
}

/// Give a connection the key its file is encrypted under. This comes before anything else is
/// asked of the file: every page of it, and of the files SQLite keeps beside it while it is
/// open, is encrypted, and nothing can be read until the key is there. A wrong key shows as
/// the file not being a database at all.
///
/// The key is given as it is, with nothing derived from it: it is thirty-two random bytes,
/// so there is no weak passphrase to stretch.
fn unlock(conn: &Connection, file_key: &[u8; 32]) -> Result<(), Error> {
    let hex: String = file_key.iter().map(|byte| format!("{byte:02x}")).collect();
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    // Whatever SQLite needs to set aside while working is kept in memory, not in a file of
    // its own, which would not be encrypted.
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    // Read something, so that a file this key does not open is reported here, as that, and
    // not later as whatever the first query happens to make of it.
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())) {
        Err(rusqlite::Error::SqliteFailure(failure, _)) if failure.code == rusqlite::ErrorCode::NotADatabase => {
            Err(Error::BadShipFile("not a ship's file that this runtime's storage key opens".into()))
        }
        other => Ok(other?),
    }
}

/// A setting that is a number. With the file encrypted, some of these come back as text.
fn pragma_number(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    conn.query_row(&format!("PRAGMA {name}"), [], |r| match r.get_ref(0)? {
        ValueRef::Integer(number) => Ok(number),
        ValueRef::Text(text) => Ok(std::str::from_utf8(text).ok().and_then(|text| text.parse().ok()).unwrap_or(0)),
        _ => Ok(0),
    })
}

pub fn open(path: &Path, durability: Durability, max_bytes: u64, file_key: &[u8; 32]) -> Result<Connection, Error> {
    // NO_MUTEX: the runtime guarantees one thread at a time per ship.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    unlock(&conn, file_key)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    // The ship's storage limit. A write that would grow the file past it fails as "full".
    let page = pragma_number(&conn, "page_size")?;
    let pages = (max_bytes / page.max(1) as u64).clamp(1, u32::MAX as u64);
    conn.query_row(&format!("PRAGMA max_page_count = {pages}"), [], |r| r.get::<_, i64>(0))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    match durability {
        Durability::Full => {
            conn.pragma_update(None, "synchronous", "FULL")?;
            // On macOS a plain fsync does not reach the platter; this is a no-op elsewhere.
            conn.pragma_update(None, "fullfsync", "ON")?;
        }
        Durability::Normal => conn.pragma_update(None, "synchronous", "NORMAL")?,
    }
    Ok(conn)
}

pub fn check_meta(conn: &Connection, name: &str) -> Result<(), Error> {
    let read = |key: &str| -> Result<Option<rusqlite::types::Value>, rusqlite::Error> {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()
    };
    let bad = |why: &str| Error::BadShipFile(format!("{name}: {why}"));
    match read("schema").map_err(|_| bad("not a ship file"))? {
        Some(rusqlite::types::Value::Integer(SCHEMA_VERSION)) => {}
        _ => return Err(bad("unsupported schema version")),
    }
    match read("name")? {
        Some(rusqlite::types::Value::Text(stored)) if stored == name => Ok(()),
        _ => Err(bad("file belongs to a different ship")),
    }
}

/// Open a ship file without changing anything about it, not even its journal mode.
pub fn open_read_only(path: &Path, file_key: &[u8; 32]) -> Result<Connection, Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    unlock(&conn, file_key)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(conn)
}

/// The public half of the key pair made from the owner's recovery code, if the ship has
/// been given one. An exported copy of the ship is sealed to it.
pub fn recovery_public(conn: &Connection) -> rusqlite::Result<Option<[u8; 32]>> {
    let stored: Option<Vec<u8>> = conn.query_row("SELECT value FROM meta WHERE key = 'recovery'", [], |r| r.get(0)).optional()?;
    Ok(stored.and_then(|public| <[u8; 32]>::try_from(public).ok()))
}

pub fn recovery_set(conn: &Connection, public: &[u8; 32]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT OR REPLACE INTO meta VALUES ('recovery', ?1)")?.execute([&public[..]]).map(drop)
}

/// The content hash of the ship's kernel module.
pub fn kernel(conn: &Connection) -> Result<String, Error> {
    let stored = conn.query_row("SELECT value FROM meta WHERE key = 'kernel'", [], |r| r.get(0)).optional()?;
    match stored {
        Some(rusqlite::types::Value::Text(hash)) => Ok(hash),
        _ => Err(Error::BadShipFile("ship file names no kernel".into())),
    }
}

pub fn inbox_push(conn: &Connection, kind: Kind, source: &str, agent: &str, interface: &str, payload: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO inbox (kind, source, agent, interface, payload) VALUES (?1, ?2, ?3, ?4, ?5)")?
        .execute(params![kind as i32, source, agent, interface, payload])
        .map(drop)
}

/// Queue a command that came from an agent on another ship, which numbered it `ship_seq`.
pub fn inbox_push_from(
    conn: &Connection,
    ship: &str,
    ship_seq: u64,
    source: &str,
    agent: &str,
    interface: &str,
    payload: &[u8],
) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO inbox (kind, source, agent, interface, payload, ship, ship_seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")?
        .execute(params![Kind::Command as i32, source, agent, interface, payload, ship, ship_seq as i64])
        .map(drop)
}

/// Queue, for `agent`, the receipt for a command it sent to `target` on another ship.
pub fn inbox_push_receipt(conn: &Connection, ship: &str, target: &str, agent: &str, interface: &str, receipt: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO inbox (kind, source, agent, interface, payload, ship) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
        .execute(params![Kind::Receipt as i32, target, agent, interface, receipt, ship])
        .map(drop)
}

// Commands between ships, and the receipts for them. For each other ship this one talks to,
// `peers` holds the number of the last message sent to it, the number of the last message
// taken from it, and how much is waiting to go to it. `peer_out` holds the messages waiting,
// each until the other ship says it has it: commands, and receipts for commands that ship
// sent here. `peer_wait` holds, for each command sent, who sent it, until its receipt comes.

/// How many other ships this ship has exchanged commands with.
pub fn peer_count(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM peers")?.query_row([], |r| r.get::<_, i64>(0)).map(|n| n as usize)
}

fn peer_row(conn: &Connection, peer: &str) -> rusqlite::Result<Option<(u64, u64, u64)>> {
    conn.prepare_cached("SELECT sent, received, out_bytes FROM peers WHERE peer = ?1")?
        .query_row([peer], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64)))
        .optional()
}

/// Whether this ship has a record for `peer`.
pub fn peer_known(conn: &Connection, peer: &str) -> rusqlite::Result<bool> {
    Ok(peer_row(conn, peer)?.is_some())
}

/// How much is waiting to go to `peer`, counted like any other queue.
pub fn peer_out_bytes(conn: &Connection, peer: &str) -> rusqlite::Result<u64> {
    Ok(peer_row(conn, peer)?.map_or(0, |(_, _, bytes)| bytes))
}

/// The number of the last command taken from `peer`.
pub fn peer_received(conn: &Connection, peer: &str) -> rusqlite::Result<u64> {
    Ok(peer_row(conn, peer)?.map_or(0, |(_, received, _)| received))
}

pub fn peer_set_received(conn: &Connection, peer: &str, received: u64) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "INSERT INTO peers VALUES (?1, 0, ?2, 0, 0, 0) ON CONFLICT (peer) DO UPDATE SET received = excluded.received",
    )?
    .execute(params![peer, received as i64])
    .map(drop)
}

/// Queue a command for an agent on another ship, giving it the next number for that ship.
/// Put a message at the end of what is waiting to go to `peer`, and return its number.
fn peer_out_push(conn: &Connection, peer: &str, source: &str, agent: &str, interface: &str, payload: &[u8], receipt: bool) -> rusqlite::Result<u64> {
    let cost = (payload.len() as u64 + MESSAGE_OVERHEAD) as i64;
    conn.prepare_cached(
        "INSERT INTO peers VALUES (?1, 1, 0, ?2, 0, 0) ON CONFLICT (peer) DO UPDATE SET sent = sent + 1, out_bytes = out_bytes + ?2",
    )?
    .execute(params![peer, cost])?;
    let (seq, _, _) = peer_row(conn, peer)?.expect("written above");
    conn.prepare_cached("INSERT INTO peer_out VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")?
        .execute(params![peer, seq as i64, source, agent, interface, payload, receipt])?;
    Ok(seq)
}

/// Queue a command from `source` for an agent on `peer`, and return its number. `tell` says
/// whether `source` is to be handed the receipt when it comes.
pub fn peer_send(conn: &Connection, peer: &str, source: &str, agent: &str, interface: &str, payload: &[u8], tell: bool) -> rusqlite::Result<u64> {
    let seq = peer_out_push(conn, peer, source, agent, interface, payload, false)?;
    conn.prepare_cached("INSERT INTO peer_wait VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
        .execute(params![peer, seq as i64, source, agent, interface, tell])?;
    Ok(seq)
}

/// How many commands sent to `peer` have had no receipt yet.
pub fn peer_unanswered(conn: &Connection, peer: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM peer_wait WHERE peer = ?1")?.query_row([peer], |r| r.get::<_, i64>(0)).map(|n| n as usize)
}

/// How many commands sent to other ships have had no receipt yet.
pub fn peer_wait_len(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM peer_wait")?.query_row([], |r| r.get::<_, i64>(0)).map(|n| n as usize)
}

/// A command sent to `peer` that has had no receipt yet.
pub struct Unanswered {
    pub source: String,
    pub agent: String,
    pub interface: String,
    pub tell: bool,
}

pub fn peer_wait_get(conn: &Connection, peer: &str, seq: u64) -> rusqlite::Result<Option<Unanswered>> {
    conn.prepare_cached("SELECT source, agent, interface, tell FROM peer_wait WHERE peer = ?1 AND seq = ?2")?
        .query_row(params![peer, seq as i64], |r| Ok(Unanswered { source: r.get(0)?, agent: r.get(1)?, interface: r.get(2)?, tell: r.get(3)? }))
        .optional()
}

/// The receipt for a command has come, so it is no longer waited for.
pub fn peer_wait_done(conn: &Connection, peer: &str, seq: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM peer_wait WHERE peer = ?1 AND seq = ?2")?.execute(params![peer, seq as i64]).map(drop)
}

/// `reason`, cut to what a receipt may carry.
pub fn short_reason(reason: &str) -> &str {
    let mut end = reason.len().min(MAX_REASON_BYTES);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// Queue, for `peer`, the receipt for the command it numbered `about`. A receipt takes no
/// notice of how much is already waiting to go there: the command has run, or been refused,
/// and saying so must not be what fails. `peer_owed` is what keeps their number down.
pub fn receipt_push(conn: &Connection, peer: &str, about: u64, verdict: Verdict, reason: &str) -> rusqlite::Result<()> {
    let receipt = Receipt { about, verdict: verdict as i32, reason: short_reason(reason).to_string(), ..Receipt::default() };
    peer_out_push(conn, peer, "", "", "", &receipt.encode_to_vec(), true).map(drop)
}

/// How many receipts this ship owes `peer` or soon will, as two counts: those written and
/// waiting to go to it, and the commands from it that are queued and have yet to run.
pub fn peer_owed(conn: &Connection, peer: &str) -> rusqlite::Result<(usize, usize)> {
    let waiting = conn
        .prepare_cached("SELECT COUNT(*) FROM peer_out WHERE peer = ?1 AND receipt")?
        .query_row([peer], |r| r.get::<_, i64>(0))?;
    let queued = conn
        // (Written out as the index on commands from other ships has it, so that it is used.)
        .prepare_cached("SELECT COUNT(*) FROM inbox WHERE ship = ?1 AND ship != '' AND kind = 1")?
        .query_row(params![peer], |r| r.get::<_, i64>(0))?;
    Ok((waiting as usize, queued as usize))
}

/// Where this ship stands with another: what it has sent it, what it holds of what that
/// ship sent, and which of that ship's commands it has yet to answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stand {
    pub sent: u64,
    pub received: u64,
    /// The oldest message still waiting to go: one more than the last that ship said it
    /// held. One more than `sent` if nothing is waiting.
    pub oldest: u64,
    /// That ship's commands held here and not yet answered, or answered in a receipt still
    /// waiting to go: lowest first.
    pub owed: Vec<u64>,
    /// Whether `owed` is all of them. If not, nothing is said about any above the last.
    pub owed_complete: bool,
    /// Not sent: the mark on this ship's record of the other when this was read. Nothing
    /// if the other ship is up to date with where this ship stands. See `resync_heard`.
    pub mark: i64,
    /// Not sent: which round of comparing notes the record was of when this was read.
    pub epoch: i64,
}

/// The highest number either ship's account of the other is moved to on the other's word.
/// A ship whose account is moved there still has as far again to go before its numbers pass
/// what an import accepts, so another ship cannot talk it into a file it could not read back.
pub const MAX_RESYNC_SEQ: u64 = (MAX_SEQ / 4) as u64;

/// Where this ship stands with `peer`, listing at most `most_owed` commands as owed.
pub fn standing(conn: &Connection, peer: &str, most_owed: usize) -> rusqlite::Result<Stand> {
    let (sent, received, _) = peer_row(conn, peer)?.unwrap_or_default();
    let mark = resync_mark_of(conn, peer)?;
    let oldest = conn
        .prepare_cached("SELECT MIN(seq) FROM peer_out WHERE peer = ?1")?
        .query_row([peer], |r| r.get::<_, Option<i64>>(0))?
        .map_or(sent + 1, |seq| seq as u64);
    // Commands from that ship still queued, and those answered in receipts not yet gone.
    let mut owed: Vec<u64> = conn
        .prepare_cached("SELECT ship_seq FROM inbox WHERE ship = ?1 AND ship != '' AND kind = 1")?
        .query_map([peer], |r| r.get::<_, i64>(0).map(|seq| seq as u64))?
        .collect::<rusqlite::Result<_>>()?;
    let mut stmt = conn.prepare_cached("SELECT payload FROM peer_out WHERE peer = ?1 AND receipt")?;
    let mut rows = stmt.query([peer])?;
    while let Some(row) = rows.next()? {
        // Written by this runtime, or checked when the ship was imported.
        if let Ok(receipt) = Receipt::decode(&*row.get::<_, Vec<u8>>(0)?) {
            owed.push(receipt.about);
        }
    }
    owed.sort_unstable();
    owed.dedup();
    let owed_complete = owed.len() <= most_owed;
    owed.truncate(most_owed);
    Ok(Stand { sent, received, oldest, owed, owed_complete, mark, epoch: peer_epoch(conn, peer)? })
}

/// The mark on this ship's record of `peer`: nothing if that ship is up to date with where
/// this ship stands, and otherwise a number given when this ship's account last moved.
fn resync_mark_of(conn: &Connection, peer: &str) -> rusqlite::Result<i64> {
    conn.prepare_cached("SELECT resync FROM peers WHERE peer = ?1")?.query_row([peer], |r| r.get(0)).optional().map(|mark| mark.unwrap_or(0))
}

/// A command this ship sent whose answer will never come.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Orphan {
    pub seq: u64,
    pub source: String,
    pub agent: String,
    pub interface: String,
    pub tell: bool,
}

/// Bring this ship's account of `peer` into line with where `peer` says it stands, and
/// return the commands this ship sent it whose answers will never come. `None` if what the
/// other ship says cannot be so, in which case nothing is changed.
///
/// Three things are put right, each only ever moving forward, so that doing it again with
/// the same or a later account changes nothing more:
///
/// - That ship holds messages numbered beyond the last this ship remembers sending. This
///   ship went back to an earlier state. Its next message is numbered after those, or it
///   would be taken for one of them and dropped.
/// - That ship's oldest waiting message is numbered beyond the next one this ship expects.
///   The ones between went to this ship in a state it has since gone back on, and that ship
///   let go of them. They are gone. This ship takes up from where that ship now starts.
/// - Whatever that ship says it holds is done with here, as when it acknowledges a delivery.
///
/// A command is an orphan if that ship has held it and does not list it as owed: it was
/// answered, and the answer went to a state of this ship that is gone, or it was taken by a
/// state of that ship that is gone. Either way no answer is coming.
///
/// Sets the mark that says the other ship has yet to hear where this ship now stands, if
/// anything moved.
pub fn reconcile(conn: &Connection, peer: &str, theirs: &Stand) -> rusqlite::Result<Option<Vec<Orphan>>> {
    let sound = theirs.sent <= MAX_RESYNC_SEQ
        && theirs.received <= MAX_RESYNC_SEQ
        && theirs.oldest >= 1
        && theirs.oldest <= theirs.sent + 1
        && theirs.owed.windows(2).all(|pair| pair[0] < pair[1])
        && theirs.owed.last().is_none_or(|last| *last <= MAX_RESYNC_SEQ);
    if !sound {
        return Ok(None);
    }
    let known = peer_row(conn, peer)?;
    let (mut sent, mut received, _) = known.unwrap_or_default();
    let before = (sent, received);
    sent = sent.max(theirs.received);
    received = received.max(theirs.oldest - 1);
    if known.is_some() || (sent, received) != before {
        // If the account moved, the other ship has to hear the new one. The record is given
        // a mark no earlier state of it has had, so that an answer to where this ship stood
        // before cannot be taken as the other ship having heard where it stands now.
        //
        // The record is also given a new `epoch` every time, moved or not. A delivery that
        // was under way when the two compared notes was acknowledged by the other ship as
        // it was before: that acknowledgement is of the epoch before, and is not acted on.
        let moved = (sent, received) != before;
        let mark = fresh_mark(conn, "resync_gen")? as i64;
        conn.prepare_cached(
            "INSERT INTO peers VALUES (?1, ?2, ?3, 0, CASE WHEN ?5 THEN ?4 ELSE 0 END, ?4) ON CONFLICT (peer) DO UPDATE
             SET sent = excluded.sent, received = excluded.received, epoch = ?4, resync = CASE WHEN ?5 THEN ?4 ELSE resync END",
        )?
        .execute(params![peer, sent as i64, received as i64, mark, moved])?;
        // The call cannot fail to find the row: it was written, or was there already.
        peer_acked(conn, peer, theirs.received.min(sent))?;
    }
    let oldest = conn
        .prepare_cached("SELECT MIN(seq) FROM peer_out WHERE peer = ?1")?
        .query_row([peer], |r| r.get::<_, Option<i64>>(0))?
        .map_or(sent + 1, |seq| seq as u64);
    // Commands that ship has held: numbered up to what it holds now, and no longer waiting
    // to go from here. Of those, the ones it does not owe an answer to.
    let listed_to = if theirs.owed_complete { u64::MAX } else { theirs.owed.last().copied().unwrap_or(0) };
    let mut stmt = conn.prepare_cached("SELECT seq, source, agent, interface, tell FROM peer_wait WHERE peer = ?1 AND seq < ?2 AND seq <= ?3 ORDER BY seq")?;
    let waiting = stmt.query_map(params![peer, oldest as i64, theirs.received as i64], |r| {
        Ok(Orphan { seq: r.get::<_, i64>(0)? as u64, source: r.get(1)?, agent: r.get(2)?, interface: r.get(3)?, tell: r.get(4)? })
    })?;
    let mut orphans = Vec::new();
    for wait in waiting {
        let wait = wait?;
        if wait.seq <= listed_to && theirs.owed.binary_search(&wait.seq).is_err() {
            orphans.push(wait);
        }
    }
    Ok(Some(orphans))
}

/// Not everything could be settled just now, so the two ships have to go over it again.
pub fn resync_mark(conn: &Connection, peer: &str) -> rusqlite::Result<()> {
    let mark = fresh_mark(conn, "resync_gen")? as i64;
    conn.prepare_cached("UPDATE peers SET resync = ?2 WHERE peer = ?1")?.execute(params![peer, mark]).map(drop)
}

/// Whether the other ship has yet to hear where this ship stands since its account moved.
pub fn resync_due(conn: &Connection, peer: &str) -> rusqlite::Result<bool> {
    Ok(resync_mark_of(conn, peer)? != 0)
}

/// The other ship has heard where this ship stood when its record carried `mark`. If the
/// record carries another mark by now, the account has moved since, and that ship has yet
/// to hear of it. Commands going back and forth in the ordinary way do not change the mark,
/// so they do not keep two busy ships from ever being done with this.
pub fn resync_heard(conn: &Connection, peer: &str, mark: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE peers SET resync = 0 WHERE peer = ?1 AND resync = ?2")?.execute(params![peer, mark]).map(drop)
}

/// The ships that have yet to answer commands this ship sent them.
pub fn wait_peers(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT DISTINCT peer FROM peer_wait")?.query_map([], |r| r.get(0))?.collect()
}

/// The ships on which agents here follow logs.
pub fn follow_peers(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT DISTINCT peer FROM remote_logs")?.query_map([], |r| r.get(0))?.collect()
}

/// The ship `peer` shows the mark `now`. Every copy of its logs here that last heard from a
/// ship showing another mark, or has yet to hear from it at all, asks afresh: that ship has
/// been brought back from a saved copy and may no longer know that this ship follows it.
/// A copy that is already asking is numbered anew as well: the answer on its way may be
/// from the ship as it was before, and must not be taken for an answer from the ship as it
/// is. Returns how many copies there are of that ship's logs, and whether any now has to ask.
pub fn replica_reborn(conn: &Connection, peer: &str, now: &[u8; 16]) -> rusqlite::Result<(usize, bool)> {
    let copies: i64 = conn.prepare_cached("SELECT COUNT(*) FROM remote_logs WHERE peer = ?1")?.query_row([peer], |r| r.get(0))?;
    let stale: bool = conn
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM remote_logs WHERE peer = ?1 AND stopped = '' AND seen != ?2)")?
        .query_row(params![peer, &now[..]], |r| r.get(0))?;
    if stale {
        let gen = fresh_mark(conn, "follow_gen")?;
        conn.prepare_cached("UPDATE remote_logs SET joined = 0, gen = ?3 WHERE peer = ?1 AND stopped = '' AND seen != ?2")?
            .execute(params![peer, &now[..], gen as i64])?;
    }
    Ok((copies as usize, stale))
}

/// What a ship has to take up with another ship.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerWork {
    /// Commands or receipts waiting to go to it.
    pub messages: bool,
    /// News of this ship's logs for it, or entries of its logs to ask it for.
    pub logs: bool,
}

/// The other ships this ship has something to take up with, and what. `max_follow_bytes` is
/// how much of another ship's log is held for an agent before no more is asked for.
pub fn peers_waiting(conn: &Connection, max_follow_bytes: u64) -> rusqlite::Result<BTreeMap<String, PeerWork>> {
    let mut found: BTreeMap<String, PeerWork> = BTreeMap::new();
    let mut stmt = conn.prepare_cached("SELECT peer FROM peers WHERE out_bytes > 0 OR resync != 0")?;
    for peer in stmt.query_map([], |r| r.get::<_, String>(0))? {
        found.entry(peer?).or_default().messages = true;
    }
    let mut stmt = conn.prepare_cached("SELECT DISTINCT peer FROM log_peers WHERE due = 1")?;
    for peer in stmt.query_map([], |r| r.get::<_, String>(0))? {
        found.entry(peer?).or_default().logs = true;
    }
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT peer FROM remote_logs WHERE stopped = '' AND (joined = 0 OR head < announced) AND bytes < ?1",
    )?;
    for peer in stmt.query_map([max_follow_bytes.min(i64::MAX as u64) as i64], |r| r.get::<_, String>(0))? {
        found.entry(peer?).or_default().logs = true;
    }
    Ok(found)
}

/// How many messages are waiting to go to other ships.
pub fn peer_out_len(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM peer_out")?.query_row([], |r| r.get::<_, i64>(0)).map(|n| n as usize)
}

/// The oldest messages waiting to go to `peer`: at most `max_bytes` as they will be sent,
/// names and framing included, except that one is always returned if there is one, and at
/// most a few hundred.
pub fn peer_batch(conn: &Connection, peer: &str, max_bytes: usize) -> rusqlite::Result<Vec<PeerMessage>> {
    let mut stmt = conn.prepare_cached(
        "SELECT seq, LENGTH(payload), source, agent, interface, payload, receipt FROM peer_out WHERE peer = ?1 ORDER BY seq",
    )?;
    let mut rows = stmt.query([peer])?;
    let (mut batch, mut bytes) = (Vec::new(), 0usize);
    while let Some(row) = rows.next()? {
        let (seq, payload) = (row.get::<_, i64>(0)? as u64, row.get::<_, Vec<u8>>(5)?);
        let message = if row.get::<_, bool>(6)? {
            // Written by this runtime, or checked when the ship was imported.
            PeerMessage { seq, receipt: Some(Receipt::decode(&*payload).unwrap_or_default()), ..PeerMessage::default() }
        } else {
            PeerMessage { seq, from_agent: row.get(2)?, agent: row.get(3)?, interface: row.get(4)?, payload, receipt: None }
        };
        // Its size as it will be sent, with the few bytes that mark where it starts and ends.
        // Counting payloads alone would let long names carry a batch past what can be sent,
        // and the same batch would then be tried, and refused, for ever.
        let len = message.encoded_len() + 8;
        if batch.len() >= MAX_BATCH_MESSAGES || (!batch.is_empty() && bytes + len > max_bytes) {
            break;
        }
        bytes += len;
        batch.push(message);
    }
    Ok(batch)
}

/// Which round of comparing notes this ship's record of `peer` is of. It changes every time
/// the two compare notes, and a delivery is acknowledged only within the round it was
/// made in.
pub fn peer_epoch(conn: &Connection, peer: &str) -> rusqlite::Result<i64> {
    conn.prepare_cached("SELECT epoch FROM peers WHERE peer = ?1")?.query_row([peer], |r| r.get(0)).optional().map(|epoch| epoch.unwrap_or(0))
}

/// The other ship says it holds every message up to `last`. Those are done with. `None` if
/// that cannot be: it names a message this ship never sent.
pub fn peer_acked(conn: &Connection, peer: &str, last: u64) -> rusqlite::Result<Option<()>> {
    let Some((sent, _, _)) = peer_row(conn, peer)? else { return Ok((last == 0).then_some(())) };
    if last > sent {
        return Ok(None);
    }
    conn.prepare_cached("DELETE FROM peer_out WHERE peer = ?1 AND seq <= ?2")?.execute(params![peer, last as i64])?;
    // Counted afresh from what is left, so it cannot drift.
    conn.prepare_cached(
        "UPDATE peers SET out_bytes = (SELECT COALESCE(SUM(LENGTH(payload) + ?2), 0) FROM peer_out WHERE peer = ?1) WHERE peer = ?1",
    )?
    .execute(params![peer, MESSAGE_OVERHEAD as i64])?;
    Ok(Some(()))
}

/// Remove and return the oldest queued command. Call inside the transaction that will run it,
/// so that taking it and its effects land together.
///
/// For a notification about a log on another ship, also returns how much room the file had
/// before it was taken off the queue. See `Ship::execute`.
pub fn inbox_pop(conn: &Connection) -> rusqlite::Result<Option<(Queued, Option<u64>)>> {
    let oldest = conn
        .prepare_cached("SELECT seq, kind, source, agent, interface, payload, ship, ship_seq FROM inbox ORDER BY seq LIMIT 1")?
        .query_row([], |r| {
            Ok(Queued {
                seq: r.get(0)?,
                kind: r.get(1)?,
                source: r.get(2)?,
                agent: r.get(3)?,
                interface: r.get(4)?,
                payload: r.get(5)?,
                ship: r.get(6)?,
                ship_seq: r.get::<_, i64>(7)? as u64,
            })
        })
        .optional()?;
    let Some(queued) = oldest else { return Ok(None) };
    let from_elsewhere = queued.kind == Kind::Notify as i32 && !queued.ship.is_empty();
    let spare_before = if from_elsewhere { Some(spare_bytes(conn)?) } else { None };
    inbox_delete(conn, queued.seq)?;
    Ok(Some((queued, spare_before)))
}

pub fn inbox_delete(conn: &Connection, seq: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM inbox WHERE seq = ?1")?.execute([seq]).map(drop)
}

pub fn inbox_bytes(conn: &Connection) -> Result<u64, Error> {
    let commands = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(payload) + ?1), 0) FROM inbox WHERE kind IN (?2, ?3)",
        params![MESSAGE_OVERHEAD as i64, Kind::Command as i32, Kind::Receipt as i32],
        |r| r.get::<_, i64>(0),
    )?;
    Ok(commands as u64)
}

/// An entry as it sits in a log.
pub struct StoredEntry {
    pub seq: u64,
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

/// What an entry counts for against its log's limit.
pub fn entry_cost(body_len: usize) -> u64 {
    body_len as u64 + 64 + MESSAGE_OVERHEAD
}

/// A log's newest entry number and that entry's hash: `(0, empty)` while the log has no entries.
pub fn log_head(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<(u64, Vec<u8>)> {
    let head = conn
        .prepare_cached("SELECT head, head_hash FROM logs WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)))
        .optional()?;
    Ok(head.unwrap_or_default())
}

pub fn log_append(conn: &Connection, agent: &str, name: &str, seq: u64, body: &[u8], signature: &[u8], hash: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO log_entries VALUES (?1, ?2, ?3, ?4, ?5)")?
        .execute(params![agent, name, seq as i64, body, signature])?;
    // Columns: head, head_hash, bytes held, base (entries up to here are dropped), tail_bytes
    // (entries since the last checkpoint), asked (a checkpoint request is queued), history
    // (the publisher has said this log must never be trimmed), marked (every ship that
    // follows this log is already down as needing to be told it has grown).
    conn.prepare_cached(
        "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5, 0, ?5, 0, 0, 0) ON CONFLICT (agent, name) DO UPDATE
         SET head = excluded.head, head_hash = excluded.head_hash, bytes = bytes + excluded.bytes,
             tail_bytes = tail_bytes + excluded.tail_bytes",
    )?
    .execute(params![agent, name, seq as i64, hash, entry_cost(body.len()) as i64])
    .map(drop)
}

/// Entries after `after`, oldest first: at most `max_entries`, and at most `max_bytes` of bodies
/// in total, except that one entry is always returned if there is one.
pub fn log_range(conn: &Connection, agent: &str, name: &str, after: u64, max_entries: usize, max_bytes: usize) -> rusqlite::Result<Vec<StoredEntry>> {
    let mut stmt = conn.prepare_cached(
        "SELECT seq, LENGTH(body), body, signature FROM log_entries WHERE agent = ?1 AND name = ?2 AND seq > ?3 ORDER BY seq",
    )?;
    // A position beyond what SQLite can hold is simply past the end.
    let mut rows = stmt.query(params![agent, name, i64::try_from(after).unwrap_or(i64::MAX)])?;
    let (mut entries, mut bytes) = (Vec::new(), 0usize);
    while let Some(row) = rows.next()? {
        let len = row.get::<_, i64>(1)? as usize;
        if entries.len() >= max_entries || (!entries.is_empty() && bytes + len > max_bytes) {
            break;
        }
        bytes += len;
        entries.push(StoredEntry { seq: row.get::<_, i64>(0)? as u64, body: row.get(2)?, signature: row.get(3)? });
    }
    Ok(entries)
}

/// The number of the newest entry that has been dropped: 0 if the log still starts at entry 1.
pub fn log_base(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<u64> {
    let base = conn
        .prepare_cached("SELECT base FROM logs WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .optional()?;
    Ok(base.unwrap_or(0) as u64)
}

/// A checkpoint as it sits in the file.
pub struct StoredCheckpoint {
    pub seq: u64,
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The entry a log's checkpoint stands for, if it has a checkpoint.
pub fn checkpoint_seq(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<Option<u64>> {
    conn.prepare_cached("SELECT seq FROM checkpoints WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .optional()
        .map(|seq| seq.map(|seq| seq as u64))
}

/// What a log's entries count for against its limit.
pub fn log_size(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<u64> {
    let bytes = conn
        .prepare_cached("SELECT bytes FROM logs WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .optional()?;
    Ok(bytes.unwrap_or(0) as u64)
}

pub fn checkpoint(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<Option<StoredCheckpoint>> {
    conn.prepare_cached("SELECT seq, body, signature FROM checkpoints WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| {
            Ok(StoredCheckpoint { seq: r.get::<_, i64>(0)? as u64, body: r.get(1)?, signature: r.get(2)? })
        })
        .optional()
}

/// Whether a log has grown enough since its last checkpoint to be worth another. The entries
/// since then must outweigh both `min_tail` and the last checkpoint itself, which keeps what a
/// log holds to about twice its state. Never while a request is already queued, and never for
/// a log its publisher has declared a history.
pub fn checkpoint_due(conn: &Connection, agent: &str, name: &str, min_tail: u64) -> rusqlite::Result<bool> {
    let row = conn
        .prepare_cached(
            "SELECT l.tail_bytes, l.asked, l.history, LENGTH(c.body)
             FROM logs l LEFT JOIN checkpoints c ON c.agent = l.agent AND c.name = l.name
             WHERE l.agent = ?1 AND l.name = ?2",
        )?
        .query_row(params![agent, name], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<i64>>(3)?))
        })
        .optional()?;
    Ok(row.is_some_and(|(tail, asked, history, last)| {
        // Both sides are counted the way a log's limit counts entries.
        let last = last.map_or(0, |body| entry_cost(body as usize));
        asked == 0 && history == 0 && tail > min_tail.max(last)
    }))
}

/// An append to this log was refused for lack of room. If the log has entries that no
/// checkpoint covers yet, ask for one whatever the usual threshold says: once it exists, the
/// entries it covers can go.
pub fn ask_checkpoint_when_full(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    let behind = conn
        .prepare_cached("SELECT 1 FROM logs WHERE agent = ?1 AND name = ?2 AND asked = 0 AND history = 0 AND tail_bytes > 0")?
        .query_row(params![agent, name], |_| Ok(()))
        .optional()?
        .is_some();
    if behind {
        ask_checkpoint(conn, agent, name)?;
    }
    Ok(())
}

/// How many logs this ship has.
pub fn log_count(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM logs")?.query_row([], |r| r.get::<_, i64>(0)).map(|count| count as usize)
}

/// Work out afresh what a log's entries count for, from the entries that are actually there.
fn recount(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "UPDATE logs SET bytes =
             (SELECT COALESCE(SUM(LENGTH(body) + ?3), 0) FROM log_entries WHERE agent = ?1 AND name = ?2)
         WHERE agent = ?1 AND name = ?2",
    )?
    .execute(params![agent, name, entry_cost(0) as i64])
    .map(drop)
}

/// Drop every entry that a log's checkpoint already covers, where normally those back to the
/// checkpoint before are kept. Does nothing for a log with no checkpoint, or one its publisher
/// has declared a history.
pub fn trim_to_checkpoint(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    let found = conn
        .prepare_cached(
            "SELECT c.seq FROM logs l JOIN checkpoints c ON c.agent = l.agent AND c.name = l.name
             WHERE l.agent = ?1 AND l.name = ?2 AND l.history = 0 AND l.base < c.seq",
        )?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .optional()?;
    let Some(seq) = found else { return Ok(()) };
    conn.prepare_cached("DELETE FROM log_entries WHERE agent = ?1 AND name = ?2 AND seq <= ?3")?
        .execute(params![agent, name, seq])?;
    conn.prepare_cached("UPDATE logs SET base = ?3 WHERE agent = ?1 AND name = ?2")?.execute(params![agent, name, seq])?;
    recount(conn, agent, name)
}

/// Queue a request to the publisher for a checkpoint of one of its logs. At most one is ever
/// queued per log, so like notifications these need no room in the command queue.
pub fn ask_checkpoint(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    let marked = conn
        .prepare_cached("UPDATE logs SET asked = 1 WHERE agent = ?1 AND name = ?2 AND asked = 0")?
        .execute(params![agent, name])?;
    if marked == 1 {
        inbox_push(conn, Kind::Checkpoint, agent, agent, name, name.as_bytes())?;
    }
    Ok(())
}

/// A checkpoint request has been taken off the queue, so a later append may queue another.
pub fn checkpoint_answered(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE logs SET asked = 0 WHERE agent = ?1 AND name = ?2")?
        .execute(params![agent, name])
        .map(drop)
}

/// The publisher has said this log is a history: every entry matters and none may be dropped.
pub fn mark_history(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE logs SET history = 1 WHERE agent = ?1 AND name = ?2")?
        .execute(params![agent, name])
        .map(drop)
}

/// Store a checkpoint for the log's present end, and drop the entries up to the checkpoint
/// before it. Keeping entries back to the previous checkpoint means a follower that is only a
/// little behind still catches up entry by entry. All of it lands in the caller's transaction.
///
/// What always holds for a log with a checkpoint: `base <= checkpoint <= head`, and the
/// entries held are exactly those after `base`. A log can hold none (`base == head`), but only
/// when its checkpoint stands for its newest entry.
pub fn checkpoint_write(conn: &Connection, agent: &str, name: &str, seq: u64, body: &[u8], signature: &[u8]) -> rusqlite::Result<()> {
    // The entries go first, so that their room is free for the new checkpoint. In a ship whose
    // file is nearly full the other order can fail for want of the very room this frees.
    if let Some(previous) = checkpoint_seq(conn, agent, name)? {
        conn.prepare_cached("DELETE FROM log_entries WHERE agent = ?1 AND name = ?2 AND seq <= ?3")?
            .execute(params![agent, name, previous as i64])?;
        conn.prepare_cached("UPDATE logs SET base = MAX(base, ?3) WHERE agent = ?1 AND name = ?2")?
            .execute(params![agent, name, previous as i64])?;
    }
    conn.prepare_cached("INSERT OR REPLACE INTO checkpoints VALUES (?1, ?2, ?3, ?4, ?5)")?
        .execute(params![agent, name, seq as i64, body, signature])?;
    conn.prepare_cached("UPDATE logs SET tail_bytes = 0 WHERE agent = ?1 AND name = ?2")?.execute(params![agent, name])?;
    recount(conn, agent, name)
}

/// The ship's file is full. Drop, from every log, the entries its checkpoint already covers,
/// which are normally kept a while for followers that are only a little behind. A log whose
/// checkpoint covers everything is left with no entries at all: its checkpoint and its
/// recorded end are enough to carry on from. A ship with nothing to let go of pays one query
/// over its logs; otherwise each log that gives something up is counted afresh.
pub fn reclaim(conn: &Connection) -> rusqlite::Result<()> {
    let covered: Vec<(String, String, i64)> = conn
        .prepare_cached(
            "SELECT l.agent, l.name, c.seq
             FROM logs l JOIN checkpoints c ON c.agent = l.agent AND c.name = l.name
             WHERE l.history = 0 AND l.base < c.seq",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (agent, name, upto) in &covered {
        conn.prepare_cached("DELETE FROM log_entries WHERE agent = ?1 AND name = ?2 AND seq <= ?3")?
            .execute(params![agent, name, upto])?;
        conn.prepare_cached("UPDATE logs SET base = ?3 WHERE agent = ?1 AND name = ?2")?.execute(params![agent, name, upto])?;
        recount(conn, agent, name)?;
    }
    Ok(())
}

/// The time now, in milliseconds since 1970.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// Signing in. A device proves the owner wants it connected by presenting a sign-in code, and is
// given a token of its own. The ship keeps only hashes: of each device's token, of each
// one-time code until it is used or expires, and of the one reusable access code.

/// Record a new device and return its number. Numbers are never reused.
pub fn device_add(conn: &Connection, token_hash: &[u8; 32], label: &str, now: u64) -> rusqlite::Result<u64> {
    conn.prepare_cached("INSERT INTO devices (token_hash, label, created_ms) VALUES (?1, ?2, ?3)")?
        .execute(params![&token_hash[..], label, now as i64])?;
    Ok(conn.last_insert_rowid() as u64)
}

fn device_row(r: &Row) -> rusqlite::Result<Device> {
    Ok(Device { id: r.get::<_, i64>(0)? as u64, label: r.get(1)?, created_ms: r.get::<_, i64>(2)? as u64 })
}

/// The device that holds the token with this hash, if any does.
pub fn device_by_token(conn: &Connection, token_hash: &[u8; 32]) -> rusqlite::Result<Option<Device>> {
    conn.prepare_cached("SELECT seq, label, created_ms FROM devices WHERE token_hash = ?1")?
        .query_row([&token_hash[..]], device_row)
        .optional()
}

pub fn devices(conn: &Connection) -> rusqlite::Result<Vec<Device>> {
    conn.prepare_cached("SELECT seq, label, created_ms FROM devices ORDER BY seq")?.query_map([], device_row)?.collect()
}

pub fn device_count(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM devices")?.query_row([], |r| r.get::<_, i64>(0)).map(|n| n as usize)
}

/// Forget a device, so its token stops working. Returns whether there was one.
pub fn device_revoke(conn: &Connection, id: u64) -> rusqlite::Result<bool> {
    // A number too large for SQLite to hold names no device.
    let Ok(id) = i64::try_from(id) else { return Ok(false) };
    conn.prepare_cached("DELETE FROM devices WHERE seq = ?1")?.execute([id]).map(|gone| gone == 1)
}

/// Drop the one-time codes whose time has passed.
pub fn codes_purge(conn: &Connection, now: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM signin_codes WHERE reusable = 0 AND expires_ms <= ?1")?.execute([now as i64]).map(drop)
}

/// How many one-time codes are waiting to be used.
pub fn code_count(conn: &Connection) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM signin_codes WHERE reusable = 0")?
        .query_row([], |r| r.get::<_, i64>(0))
        .map(|n| n as usize)
}

/// Keep a one-time code until `expires`.
pub fn code_add(conn: &Connection, code_hash: &[u8; 32], expires: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO signin_codes VALUES (?1, ?2, 0)")?
        .execute(params![&code_hash[..], i64::try_from(expires).unwrap_or(i64::MAX)])
        .map(drop)
}

/// Replace the ship's reusable access code, or with `None` leave it with none.
pub fn access_code_set(conn: &Connection, code_hash: Option<&[u8; 32]>) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM signin_codes WHERE reusable = 1")?.execute([])?;
    if let Some(hash) = code_hash {
        conn.prepare_cached("INSERT INTO signin_codes VALUES (?1, 0, 1)")?.execute([&hash[..]])?;
    }
    Ok(())
}

/// Whether a sign-in code is good at this moment, and if so whether it is the reusable access
/// code (`Some(true)`) or a one-time code (`Some(false)`). Nothing is used up by asking.
pub fn code_find(conn: &Connection, code_hash: &[u8; 32], now: u64) -> rusqlite::Result<Option<bool>> {
    let found = conn
        .prepare_cached("SELECT expires_ms, reusable FROM signin_codes WHERE code_hash = ?1")?
        .query_row([&code_hash[..]], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? != 0)))
        .optional()?;
    Ok(match found {
        Some((_, true)) => Some(true),
        Some((expires, false)) if now < expires => Some(false),
        _ => None,
    })
}

/// A one-time code has been used, so it is gone. The reusable access code stays.
pub fn code_use(conn: &Connection, code_hash: &[u8; 32]) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM signin_codes WHERE code_hash = ?1 AND reusable = 0")?.execute([&code_hash[..]]).map(drop)
}

fn meta_number(conn: &Connection, key: &str) -> rusqlite::Result<u64> {
    let value = conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?.query_row([key], |r| r.get::<_, i64>(0)).optional()?;
    Ok(value.unwrap_or(0) as u64)
}

fn meta_set(conn: &Connection, key: &str, value: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT OR REPLACE INTO meta VALUES (?1, ?2)")?
        .execute(params![key, i64::try_from(value).unwrap_or(i64::MAX)])
        .map(drop)
}

/// A number this ship has not used before for the purpose `key` names, and will not use
/// again: one more than the last. It marks one state of a record apart from every other
/// state that record, or a later record in its place, will ever be in, so that something
/// decided about one cannot be carried out on another.
fn fresh_mark(conn: &Connection, key: &str) -> rusqlite::Result<u64> {
    let mark = meta_number(conn, key)? + 1;
    // No ship gets through these. But one that somehow had must stop here: carrying on
    // would hand the same number out again and again.
    if mark > MAX_SEQ as u64 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(0, MAX_SEQ));
    }
    meta_set(conn, key, mark)?;
    Ok(mark)
}

/// Until when signing in to this ship is locked after too many wrong codes, or 0.
pub fn signin_locked_until(conn: &Connection) -> rusqlite::Result<u64> {
    meta_number(conn, "signin_locked_until")
}

/// A wrong code was offered. After `max` in a row, nothing can sign in for `lock_ms`.
pub fn signin_failed(conn: &Connection, now: u64, max: u32, lock_ms: u64) -> rusqlite::Result<()> {
    let failures = meta_number(conn, "signin_failures")? + 1;
    if failures >= max as u64 {
        meta_set(conn, "signin_locked_until", now.saturating_add(lock_ms))?;
        return meta_set(conn, "signin_failures", 0);
    }
    meta_set(conn, "signin_failures", failures)
}

/// A good code was offered, so the count of wrong ones starts again.
pub fn signin_succeeded(conn: &Connection) -> rusqlite::Result<()> {
    meta_set(conn, "signin_failures", 0)
}

/// A log that an agent follows: one on this ship when `ship` is empty, and otherwise one on
/// that ship, which this ship keeps a copy of the part its agent has yet to take.
#[derive(Clone, Copy, Debug)]
pub struct Followed<'a> {
    pub ship: &'a str,
    pub agent: &'a str,
    pub name: &'a str,
}

impl<'a> Followed<'a> {
    pub fn here(agent: &'a str, name: &'a str) -> Self {
        Followed { ship: "", agent, name }
    }
}

/// Record that `follower` follows a log, starting before its first entry. Returns false if it
/// already did.
pub fn follow(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<bool> {
    conn.prepare_cached("INSERT OR IGNORE INTO follows VALUES (?1, ?2, ?3, ?4, 0, 0, 0)")?
        .execute(params![follower, log.ship, log.agent, log.name])
        .map(|added| added == 1)
}

pub fn follow_count(conn: &Connection, follower: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM follows WHERE follower = ?1")?
        .query_row([follower], |r| r.get::<_, i64>(0))
        .map(|count| count as usize)
}

/// The number of the last entry `follower` has taken from a log, if it follows that log.
pub fn cursor(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<Option<u64>> {
    conn.prepare_cached("SELECT cursor FROM follows WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .query_row(params![follower, log.ship, log.agent, log.name], |r| r.get::<_, i64>(0))
        .optional()
        .map(|cursor| cursor.map(|seq| seq as u64))
}

pub fn set_cursor(conn: &Connection, follower: &str, log: Followed, cursor: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET cursor = ?5 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .execute(params![follower, log.ship, log.agent, log.name, cursor as i64])
        .map(drop)
}

/// Where the log ends, as far as this ship holds it: for a log on another ship, the newest
/// entry fetched.
fn followed_head(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<u64> {
    if log.ship.is_empty() {
        return Ok(log_head(conn, log.agent, log.name)?.0);
    }
    Ok(replica(conn, follower, log)?.map_or(0, |held| held.head))
}

/// Queue a notification for one follower, unless one is already waiting. At most one is ever
/// queued per follower and log, however many entries arrive and whatever the follower's own
/// handler does; that bound is why notifications need no room in the command queue.
pub fn notify(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    let marked = conn
        .prepare_cached(
            "UPDATE follows SET notified = 1 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4 AND notified = 0",
        )?
        .execute(params![follower, log.ship, log.agent, log.name])?;
    if marked == 1 {
        conn.prepare_cached("INSERT INTO inbox (kind, source, agent, interface, payload, ship) VALUES (?1, ?2, ?3, ?4, x'', ?5)")?
            .execute(params![Kind::Notify as i32, log.agent, follower, log.name, log.ship])?;
    }
    Ok(())
}

/// The number of the newest event waiting to run on this ship, or 0 if there is none.
pub fn inbox_newest(conn: &Connection) -> rusqlite::Result<i64> {
    conn.prepare_cached("SELECT COALESCE(MAX(seq), 0) FROM inbox")?.query_row([], |r| r.get(0))
}

/// The number of the oldest event waiting to run on this ship: the next to run.
pub fn inbox_oldest(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.prepare_cached("SELECT MIN(seq) FROM inbox")?.query_row([], |r| r.get(0))
}

/// How much more the ship's file may hold before it reaches its limit.
pub fn spare_bytes(conn: &Connection) -> rusqlite::Result<u64> {
    let pragma = |name: &str| pragma_number(conn, name);
    let (size, most, used, unused) = (pragma("page_size")?, pragma("max_page_count")?, pragma("page_count")?, pragma("freelist_count")?);
    Ok(((most - used).max(0) + unused).max(0) as u64 * size.max(0) as u64)
}

/// How many events are waiting to run on this ship.
pub fn inbox_len(conn: &Connection) -> Result<usize, Error> {
    Ok(conn.query_row("SELECT COUNT(*) FROM inbox", [], |r| r.get::<_, i64>(0))? as usize)
}

/// Notify every follower on this ship of one of its logs that has no notification waiting.
/// Returns how many.
pub fn notify_followers(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<u32> {
    let followers: Vec<String> = conn
        .prepare_cached("SELECT follower FROM follows WHERE ship = '' AND agent = ?1 AND name = ?2 AND notified = 0")?
        .query_map(params![agent, name], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    // A new entry starts a follower off afresh, including one that had been given up on.
    conn.prepare_cached("UPDATE follows SET failures = 0 WHERE ship = '' AND agent = ?1 AND name = ?2 AND notified = 0")?
        .execute(params![agent, name])?;
    for follower in &followers {
        notify(conn, follower, Followed::here(agent, name))?;
    }
    Ok(followers.len() as u32)
}

/// A follower's notification has been taken off the queue, so the next new entry may queue another.
pub fn clear_notified(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET notified = 0 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .execute(params![follower, log.ship, log.agent, log.name])
        .map(drop)
}

/// A follower's notify handler failed. Its position has not moved, so it is still behind. Try it
/// again a few times, in case the cause was passing, and then stop: an entry it can never
/// handle must not be retried for ever.
pub fn notify_failed(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET failures = failures + 1 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .execute(params![follower, log.ship, log.agent, log.name])?;
    let failures = conn
        .prepare_cached("SELECT failures FROM follows WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .query_row(params![follower, log.ship, log.agent, log.name], |r| r.get::<_, i64>(0))
        .optional()?;
    if failures.is_some_and(|failures| failures < MAX_NOTIFY_FAILURES) {
        notify(conn, follower, log)?;
    }
    Ok(())
}

/// A follower's notify handler has finished without error. `before` is where it had got to
/// when the handler started. If it is still behind and took nothing, prompting it again would
/// go round for ever, so that counts as a failed round. Otherwise it is started off afresh.
pub fn notify_handled(conn: &Connection, follower: &str, log: Followed, before: Option<u64>) -> rusqlite::Result<()> {
    let head = followed_head(conn, follower, log)?;
    match cursor(conn, follower, log)? {
        Some(now) if now < head && Some(now) == before => notify_failed(conn, follower, log),
        _ => resume(conn, follower, log),
    }
}

/// Start a follower off afresh: forget its past failures and prompt it if it is behind.
pub fn resume(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET failures = 0 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .execute(params![follower, log.ship, log.agent, log.name])?;
    renotify_if_behind(conn, follower, log)
}

/// After a follower has handled a notification: if entries remain that it has not taken and
/// nothing is queued, queue another.
pub fn renotify_if_behind(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    let head = followed_head(conn, follower, log)?;
    if cursor(conn, follower, log)?.is_some_and(|cursor| cursor < head) {
        notify(conn, follower, log)?;
    }
    Ok(())
}

/// Stop following a log. A notification already queued for it goes too: there would be
/// nothing for it to hand over.
pub fn unfollow(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM follows WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4")?
        .execute(params![follower, log.ship, log.agent, log.name])?;
    conn.prepare_cached("DELETE FROM inbox WHERE kind = ?1 AND agent = ?2 AND ship = ?3 AND source = ?4 AND interface = ?5")?
        .execute(params![Kind::Notify as i32, follower, log.ship, log.agent, log.name])?;
    if !log.ship.is_empty() {
        for table in ["remote_logs", "remote_entries", "remote_checkpoints"] {
            conn.prepare_cached(&format!("DELETE FROM {table} WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4"))?
                .execute(params![log.ship, log.agent, log.name, follower])?;
        }
    }
    Ok(())
}

// Following a log on another ship. For each agent that follows one, `remote_logs` says how
// far this ship has fetched it, how far the publishing ship has said it reaches, and whether
// it has stopped. `remote_entries` holds the entries fetched and not yet taken by the agent,
// and `remote_checkpoints` a checkpoint fetched in place of entries that ship had dropped.
// Only payloads are kept: each entry was checked against that ship's key as it arrived.

/// What this ship holds of a log on another ship, for one of its agents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replica {
    /// The newest entry fetched, and its hash, which the next entry must link back to.
    pub head: u64,
    pub head_hash: Vec<u8>,
    /// The newest entry the publishing ship has said the log has.
    pub announced: u64,
    /// What is held and not yet taken, counted like any other queue.
    pub bytes: u64,
    /// Whether the publishing ship has answered since this agent last asked to follow.
    pub joined: bool,
    /// Empty, or why no more of the log will come.
    pub stopped: String,
    /// A number given to this copy each time the agent asks to follow: no two askings on
    /// one ship share one. An answer from the other ship is for the asking it was put under,
    /// and is not taken for a later one.
    pub gen: u64,
    /// The mark the publishing ship showed when it last answered. Empty if it never has.
    pub seen: Vec<u8>,
}

pub fn replica(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<Option<Replica>> {
    conn.prepare_cached(
        "SELECT head, head_hash, announced, bytes, joined, stopped, gen, seen FROM remote_logs
         WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4",
    )?
    .query_row(params![log.ship, log.agent, log.name, follower], |r| {
        Ok(Replica {
            head: r.get::<_, i64>(0)? as u64,
            head_hash: r.get(1)?,
            announced: r.get::<_, i64>(2)? as u64,
            bytes: r.get::<_, i64>(3)? as u64,
            joined: r.get(4)?,
            stopped: r.get(5)?,
            gen: r.get::<_, i64>(6)? as u64,
            seen: r.get(7)?,
        })
    })
    .optional()
}

/// Begin following a log on another ship, or ask afresh for one already followed: it is no
/// longer stopped, and the publishing ship is asked again where it stands.
pub fn replica_start(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<()> {
    // A number no earlier asking on this ship has had, whether or not that one is still
    // followed. An answer still on its way to an earlier asking then fits no copy.
    let gen = fresh_mark(conn, "follow_gen")?;
    conn.prepare_cached(
        "INSERT INTO remote_logs VALUES (?1, ?2, ?3, ?4, 0, x'', 0, 0, 0, '', ?5, x'')
         ON CONFLICT (peer, agent, name, follower) DO UPDATE SET joined = 0, stopped = '', gen = ?5",
    )?
    .execute(params![log.ship, log.agent, log.name, follower, gen as i64])
    .map(drop)
}

pub fn replica_save(conn: &Connection, follower: &str, log: Followed, held: &Replica) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "UPDATE remote_logs SET head = ?5, head_hash = ?6, announced = ?7, bytes = ?8, joined = ?9, stopped = ?10, seen = ?11
         WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4",
    )?
    .execute(params![
        log.ship,
        log.agent,
        log.name,
        follower,
        held.head as i64,
        held.head_hash,
        held.announced as i64,
        held.bytes as i64,
        held.joined,
        held.stopped,
        held.seen
    ])
    .map(drop)
}

/// Keep an entry fetched from another ship until the agent takes it.
pub fn replica_push(conn: &Connection, follower: &str, log: Followed, seq: u64, payload: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO remote_entries VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
        .execute(params![log.ship, log.agent, log.name, follower, seq as i64, payload])
        .map(drop)
}

/// Keep a checkpoint fetched from another ship in place of entries it had dropped. Whatever
/// entries were being held come before it, so they go: the checkpoint stands for them.
pub fn replica_checkpoint_set(conn: &Connection, follower: &str, log: Followed, seq: u64, state: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM remote_entries WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4")?
        .execute(params![log.ship, log.agent, log.name, follower])?;
    conn.prepare_cached("INSERT OR REPLACE INTO remote_checkpoints VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?
        .execute(params![log.ship, log.agent, log.name, follower, seq as i64, state])
        .map(drop)
}

/// The checkpoint waiting for the agent, if there is one, as (entry number, state).
pub fn replica_checkpoint(conn: &Connection, follower: &str, log: Followed) -> rusqlite::Result<Option<(u64, Vec<u8>)>> {
    conn.prepare_cached("SELECT seq, state FROM remote_checkpoints WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4")?
        .query_row(params![log.ship, log.agent, log.name, follower], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)))
        .optional()
}

/// Held entries after `after`, oldest first, as (number, payload): at most `max_entries`, and
/// at most `max_bytes` in total, except that one is always returned if there is one.
pub fn replica_range(
    conn: &Connection,
    follower: &str,
    log: Followed,
    after: u64,
    max_entries: usize,
    max_bytes: usize,
) -> rusqlite::Result<Vec<(u64, Vec<u8>)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT seq, payload FROM remote_entries WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4 AND seq > ?5 ORDER BY seq",
    )?;
    let mut rows = stmt.query(params![log.ship, log.agent, log.name, follower, i64::try_from(after).unwrap_or(i64::MAX)])?;
    let (mut entries, mut bytes) = (Vec::new(), 0usize);
    while let Some(row) = rows.next()? {
        let payload: Vec<u8> = row.get(1)?;
        if entries.len() >= max_entries || (!entries.is_empty() && bytes + payload.len() > max_bytes) {
            break;
        }
        bytes += payload.len();
        entries.push((row.get::<_, i64>(0)? as u64, payload));
    }
    Ok(entries)
}

/// The agent has taken everything up to entry `last`, so its position moves there and what
/// was held up to it is let go.
pub fn replica_taken(conn: &Connection, follower: &str, log: Followed, last: u64) -> rusqlite::Result<()> {
    set_cursor(conn, follower, log, last)?;
    for table in ["remote_entries", "remote_checkpoints"] {
        conn.prepare_cached(&format!("DELETE FROM {table} WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4 AND seq <= ?5"))?
            .execute(params![log.ship, log.agent, log.name, follower, last as i64])?;
    }
    // Counted afresh from what is left, so it cannot drift.
    conn.prepare_cached(
        "UPDATE remote_logs SET bytes =
             (SELECT COALESCE(SUM(LENGTH(payload) + ?5), 0) FROM remote_entries WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4)
           + (SELECT COALESCE(SUM(LENGTH(state) + ?5), 0) FROM remote_checkpoints WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4)
         WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4",
    )?
    .execute(params![log.ship, log.agent, log.name, follower, MESSAGE_OVERHEAD as i64])
    .map(drop)
}

/// The agents on this ship that follow a log on another ship.
pub fn replica_followers(conn: &Connection, peer: &str, agent: &str, name: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT follower FROM remote_logs WHERE peer = ?1 AND agent = ?2 AND name = ?3")?
        .query_map(params![peer, agent, name], |r| r.get(0))?
        .collect()
}

/// The publishing ship says a log is closed to this ship. That is taken as a prompt to ask
/// and no more: every agent here that follows it asks afresh, and it is the answer to that
/// asking which says whether the log has stopped. News can be overtaken on its way, by the
/// log being shared again and followed again, and must not stop a copy on its own.
///
/// An answer that ship gave before it closed the log may still be on its way. Taken now, it
/// would count as the answer to this asking and call it off. So the copies are numbered
/// anew, as they are when an agent asks to follow, and that answer fits none of them.
pub fn replica_recheck(conn: &Connection, peer: &str, agent: &str, name: &str) -> rusqlite::Result<()> {
    let gen = fresh_mark(conn, "follow_gen")?;
    conn.prepare_cached("UPDATE remote_logs SET joined = 0, gen = ?4 WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND stopped = ''")?
        .execute(params![peer, agent, name, gen as i64])
        .map(drop)
}

/// The publishing ship says its log reaches entry `head`. Remembered for every agent here
/// that follows it and has not stopped, never lowered.
pub fn replica_heard(conn: &Connection, peer: &str, agent: &str, name: &str, head: u64) -> rusqlite::Result<()> {
    conn.prepare_cached(
        "UPDATE remote_logs SET announced = MAX(announced, ?4) WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND stopped = ''",
    )?
    .execute(params![peer, agent, name, head as i64])
    .map(drop)
}

/// One thing to ask another ship for: the entries of a log after `after`, for `follower`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchJob {
    pub follower: String,
    pub agent: String,
    pub name: String,
    pub after: u64,
    /// How much more this ship will hold for the follower.
    pub room: u64,
    /// The publishing ship has not answered since the follower last asked to follow.
    pub joining: bool,
    /// Which asking to follow this is for. See `Replica::gen`.
    pub gen: u64,
}

/// What to ask `peer` for: every log on it that an agent here follows, that has not stopped,
/// that this ship has yet to join or knows to have grown, and that it has room to hold more
/// of. An entry is taken whenever less than `max_bytes` is held, so each of these is sure to
/// get somewhere.
pub fn replica_work(conn: &Connection, peer: &str, max_bytes: u64) -> rusqlite::Result<Vec<FetchJob>> {
    conn.prepare_cached(
        "SELECT follower, agent, name, head, bytes, joined, gen FROM remote_logs
         WHERE peer = ?1 AND stopped = '' AND (joined = 0 OR head < announced) AND bytes < ?2",
    )?
    .query_map(params![peer, max_bytes.min(i64::MAX as u64) as i64], |r| {
        Ok(FetchJob {
            follower: r.get(0)?,
            agent: r.get(1)?,
            name: r.get(2)?,
            after: r.get::<_, i64>(3)? as u64,
            room: max_bytes.saturating_sub(r.get::<_, i64>(4)? as u64),
            joining: !r.get::<_, bool>(5)?,
            gen: r.get::<_, i64>(6)? as u64,
        })
    })?
    .collect()
}

/// A log on another ship as one of this ship's agents follows it, for the owner to look at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteFollow {
    pub follower: String,
    pub ship: String,
    pub agent: String,
    pub log: String,
    /// The last entry the agent has taken, the last this ship has fetched, and the last the
    /// publishing ship has said there is.
    pub taken: u64,
    pub fetched: u64,
    pub announced: u64,
    /// Why no more will come, if that is so.
    pub stopped: Option<String>,
}

pub fn remote_follows(conn: &Connection) -> rusqlite::Result<Vec<RemoteFollow>> {
    conn.prepare_cached(
        "SELECT r.follower, r.peer, r.agent, r.name, f.cursor, r.head, r.announced, r.stopped
         FROM remote_logs r JOIN follows f ON f.follower = r.follower AND f.ship = r.peer AND f.agent = r.agent AND f.name = r.name
         ORDER BY r.follower, r.peer, r.agent, r.name",
    )?
    .query_map([], |r| {
        let stopped: String = r.get(7)?;
        Ok(RemoteFollow {
            follower: r.get(0)?,
            ship: r.get(1)?,
            agent: r.get(2)?,
            log: r.get(3)?,
            taken: r.get::<_, i64>(4)? as u64,
            fetched: r.get::<_, i64>(5)? as u64,
            announced: r.get::<_, i64>(6)? as u64,
            stopped: (!stopped.is_empty()).then_some(stopped),
        })
    })?
    .collect()
}

// Letting other ships follow this ship's logs. `log_shares` is who each log's publisher has
// said may follow it: ships by name, or "*" for all. `log_peers` is who does: a ship is put
// there when it first asks, and is told from then on when the log grows. `due` marks a ship
// that has yet to be told of the log's newest entries, `kicked` one that may no longer
// follow and has yet to be told so, and `gen` is given a number never used before whenever
// something changes what the row means, or a row is written in the place of one that was
// struck off, so that an answer to old news cannot undo something newer. The index on `due`
// covers every row, told or not: a row then takes the same room in the file whichever it is,
// and marking rows as untold, as an import does, cannot make the file grow.

/// How many ships, counting "*" as one, a log is shared with.
pub fn share_count(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM log_shares WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .map(|count| count as usize)
}

/// Whether `peer` may follow a log: it is named, or every ship is let in.
pub fn shared_with(conn: &Connection, agent: &str, name: &str, peer: &str) -> rusqlite::Result<bool> {
    conn.prepare_cached("SELECT EXISTS (SELECT 1 FROM log_shares WHERE agent = ?1 AND name = ?2 AND peer IN (?3, '*'))")?
        .query_row(params![agent, name, peer], |r| r.get(0))
}

/// Whether a log is shared with exactly `peer`: that ship by name, or "*" itself.
pub fn shared_exactly(conn: &Connection, agent: &str, name: &str, peer: &str) -> rusqlite::Result<bool> {
    conn.prepare_cached("SELECT EXISTS (SELECT 1 FROM log_shares WHERE agent = ?1 AND name = ?2 AND peer = ?3)")?
        .query_row(params![agent, name, peer], |r| r.get(0))
}

/// The ships a log is shared with, "*" among them if every ship is.
pub fn shares(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT peer FROM log_shares WHERE agent = ?1 AND name = ?2 ORDER BY peer")?
        .query_map(params![agent, name], |r| r.get(0))?
        .collect()
}

/// The ships that follow a log, leaving out any that have been shut out and not yet told.
pub fn log_followers(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare_cached("SELECT peer FROM log_peers WHERE agent = ?1 AND name = ?2 AND kicked = 0 ORDER BY peer")?
        .query_map(params![agent, name], |r| r.get(0))?
        .collect()
}

/// Let `peer` (a ship, or "*") follow a log. A ship that was shut out and has not been told
/// yet is simply let back in. Returns whether anything changed.
pub fn share_add(conn: &Connection, agent: &str, name: &str, peer: &str) -> rusqlite::Result<bool> {
    let added = conn.prepare_cached("INSERT OR IGNORE INTO log_shares VALUES (?1, ?2, ?3)")?.execute(params![agent, name, peer])?;
    let back = conn
        .prepare_cached("UPDATE log_peers SET kicked = 0, gen = ?4 WHERE agent = ?1 AND name = ?2 AND kicked = 1 AND (peer = ?3 OR ?3 = '*')")?
        .execute(params![agent, name, peer, fresh_mark(conn, "peer_gen")? as i64])?;
    Ok(added + back > 0)
}

/// Stop letting `peer` (a ship, or "*") follow a log. Every ship that follows it and is no
/// longer let in is marked to be told so. Returns how many were.
pub fn share_remove(conn: &Connection, agent: &str, name: &str, peer: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("DELETE FROM log_shares WHERE agent = ?1 AND name = ?2 AND peer = ?3")?.execute(params![agent, name, peer])?;
    conn.prepare_cached(
        "UPDATE log_peers SET kicked = 1, due = 1, gen = ?3
         WHERE agent = ?1 AND name = ?2 AND kicked = 0
           AND NOT EXISTS (SELECT 1 FROM log_shares s WHERE s.agent = ?1 AND s.name = ?2 AND s.peer IN (log_peers.peer, '*'))",
    )?
    .execute(params![agent, name, fresh_mark(conn, "peer_gen")? as i64])
}

/// How many ships follow a log, counting those shut out and not yet told.
pub fn log_peer_count(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM log_peers WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get::<_, i64>(0))
        .map(|count| count as usize)
}

/// Some followers of this log are no longer all marked as needing to be told.
fn unmark(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE logs SET marked = 0 WHERE agent = ?1 AND name = ?2 AND marked = 1")?.execute(params![agent, name]).map(drop)
}

/// `peer`, which may follow this log, has asked for some of it. Note it as a follower if it
/// is not one, so that it is told when the log grows. It is being given where the log ends
/// along with whatever it asked for, so it has nothing yet to be told. `joining` says it is
/// starting afresh. Says whether it was noted just now, was a follower already, or could
/// not be noted because the log already has `max` followers.
pub fn log_peer_join(conn: &Connection, agent: &str, name: &str, peer: &str, joining: bool, max: usize) -> rusqlite::Result<Joined> {
    let known = conn
        .prepare_cached("SELECT kicked FROM log_peers WHERE agent = ?1 AND name = ?2 AND peer = ?3")?
        .query_row(params![agent, name, peer], |r| r.get::<_, bool>(0))
        .optional()?;
    match known {
        None if log_peer_count(conn, agent, name)? >= max => return Ok(Joined::Full),
        None => {
            conn.prepare_cached("INSERT INTO log_peers VALUES (?1, ?2, ?3, 0, 0, ?4)")?
                .execute(params![agent, name, peer, fresh_mark(conn, "peer_gen")? as i64])?;
            unmark(conn, agent, name)?;
            return Ok(Joined::New);
        }
        // Let back in before it was told it had been shut out: it need not be told now.
        Some(true) => {
            conn.prepare_cached("UPDATE log_peers SET kicked = 0, due = 0, gen = ?4 WHERE agent = ?1 AND name = ?2 AND peer = ?3")?
                .execute(params![agent, name, peer, fresh_mark(conn, "peer_gen")? as i64])?;
        }
        Some(false) if joining => {
            conn.prepare_cached("UPDATE log_peers SET gen = ?4 WHERE agent = ?1 AND name = ?2 AND peer = ?3")?
                .execute(params![agent, name, peer, fresh_mark(conn, "peer_gen")? as i64])?;
            return Ok(Joined::Known);
        }
        Some(false) => return Ok(Joined::Known),
    }
    unmark(conn, agent, name)?;
    Ok(Joined::Known)
}

/// What came of noting a ship as a follower of a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joined {
    /// It was one already.
    Known,
    /// It is one now: a new record was written.
    New,
    /// The log has as many followers as it may.
    Full,
}

/// A log has grown. Mark every ship that follows it as needing to be told, and return how
/// many were not marked already. Once all are marked, further entries cost one look at the
/// log's own row until some ship has been told.
pub fn log_peers_mark(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<usize> {
    let marked: bool = conn
        .prepare_cached("SELECT marked FROM logs WHERE agent = ?1 AND name = ?2")?
        .query_row(params![agent, name], |r| r.get(0))
        .optional()?
        .unwrap_or(false);
    if marked {
        return Ok(0);
    }
    let changed = conn.prepare_cached("UPDATE log_peers SET due = 1 WHERE agent = ?1 AND name = ?2 AND due = 0")?.execute(params![agent, name])?;
    conn.prepare_cached("UPDATE logs SET marked = 1 WHERE agent = ?1 AND name = ?2")?.execute(params![agent, name])?;
    Ok(changed)
}

/// Something to tell a ship that follows one of this ship's logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewsItem {
    pub agent: String,
    pub name: String,
    pub head: u64,
    pub closed: bool,
    /// What the row said when this was read. See `news_heard`.
    pub gen: i64,
}

impl NewsItem {
    pub fn as_sent(&self) -> LogNews {
        LogNews { agent: self.agent.clone(), log: self.name.clone(), head: self.head, closed: self.closed }
    }
}

/// The most logs one ship is told about at once.
pub const MAX_NEWS_LOGS: usize = 256;

/// The most entries of a log that go to another ship in one answer.
pub const MAX_FETCH_ENTRIES: usize = 256;

/// What `peer` has yet to be told about the logs it follows here. A ship that has been shut
/// out of a log is told so and nothing else: where the log ends now is no longer its business.
///
/// They are taken in the order of their names, starting after `after`, the last log this
/// ship was told about, and going round to the beginning. A ship that follows more logs than
/// one piece of news holds, many of them busy, would otherwise hear of the same ones every
/// time, and never of the rest.
pub fn news_for(conn: &Connection, peer: &str, after: Option<(&str, &str)>) -> rusqlite::Result<Vec<NewsItem>> {
    let (agent, name) = after.unwrap_or(("", ""));
    let read = |round: &str, limit: usize| -> rusqlite::Result<Vec<NewsItem>> {
        conn.prepare_cached(&format!(
            "SELECT p.agent, p.name, CASE WHEN p.kicked THEN 0 ELSE COALESCE(l.head, 0) END, p.kicked, p.gen
             FROM log_peers p LEFT JOIN logs l ON l.agent = p.agent AND l.name = p.name
             WHERE p.due = 1 AND p.peer = ?1 AND (p.agent, p.name) {round} (?2, ?3)
             ORDER BY p.agent, p.name LIMIT ?4"
        ))?
        .query_map(params![peer, agent, name, limit as i64], |r| {
            Ok(NewsItem { agent: r.get(0)?, name: r.get(1)?, head: r.get::<_, i64>(2)? as u64, closed: r.get(3)?, gen: r.get(4)? })
        })?
        .collect()
    };
    let mut news = read(">", MAX_NEWS_LOGS)?;
    if after.is_some() && news.len() < MAX_NEWS_LOGS {
        news.extend(read("<=", MAX_NEWS_LOGS - news.len())?);
    }
    Ok(news)
}

/// `peer` has taken in what it was told. `unknown` says, for each item, whether it answered
/// that it does not follow that log.
///
/// A ship told a log is closed to it, or that says it does not follow one, is no longer a
/// follower. One told where a log ends needs no more telling, unless the log has grown since.
/// Each of these holds only if the row still says what it said when the news was read: a
/// ship that has since asked to follow afresh, or been let back in, is not struck off on the
/// strength of an answer to old news.
pub fn news_heard(conn: &Connection, peer: &str, told: &[NewsItem], unknown: &[bool]) -> rusqlite::Result<()> {
    for (index, item) in told.iter().enumerate() {
        if item.closed || unknown.get(index).copied().unwrap_or(false) {
            conn.prepare_cached("DELETE FROM log_peers WHERE agent = ?1 AND name = ?2 AND peer = ?3 AND gen = ?4")?
                .execute(params![item.agent, item.name, peer, item.gen])?;
            continue;
        }
        let settled = conn
            .prepare_cached(
                "UPDATE log_peers SET due = 0 WHERE agent = ?1 AND name = ?2 AND peer = ?3 AND gen = ?4 AND kicked = 0
                   AND ?5 >= COALESCE((SELECT head FROM logs WHERE agent = ?1 AND name = ?2), 0)",
            )?
            .execute(params![item.agent, item.name, peer, item.gen, item.head as i64])?;
        if settled > 0 {
            unmark(conn, &item.agent, &item.name)?;
        }
    }
    Ok(())
}

/// Returns the value's length, and the value itself only when it fits in `cap` bytes.
pub fn kv_get(conn: &Connection, agent: &str, key: &[u8], cap: usize) -> rusqlite::Result<Option<(usize, Option<Vec<u8>>)>> {
    conn.prepare_cached(
        "SELECT LENGTH(value), CASE WHEN LENGTH(value) <= ?3 THEN value END FROM kv WHERE agent = ?1 AND key = ?2",
    )?
    .query_row(params![agent, key, cap as i64], |r| Ok((r.get::<_, i64>(0)? as usize, r.get(1)?)))
    .optional()
}

pub fn kv_put(conn: &Connection, agent: &str, key: &[u8], value: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT OR REPLACE INTO kv VALUES (?1, ?2, ?3)")?
        .execute(params![agent, key, value])
        .map(drop)
}

pub fn kv_delete(conn: &Connection, agent: &str, key: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM kv WHERE agent = ?1 AND key = ?2")?
        .execute(params![agent, key])
        .map(drop)
}

pub fn outbox_push(conn: &Connection, agent: &str, payload: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO outbox (agent, payload) VALUES (?1, ?2)")?
        .execute(params![agent, payload])
        .map(drop)
}

pub fn outbox_bytes(conn: &Connection) -> Result<u64, Error> {
    Ok(conn.query_row("SELECT COALESCE(SUM(LENGTH(payload) + ?1), 0) FROM outbox", [MESSAGE_OVERHEAD as i64], |r| r.get::<_, i64>(0))? as u64)
}

/// Remove and return the oldest messages: at most `max_messages`, and at most `max_bytes` in
/// total, except that one message is always returned if any is pending.
pub fn outbox_drain(conn: &Connection, max_messages: usize, max_bytes: usize) -> Result<Vec<Effect>, Error> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let drained = (|| -> rusqlite::Result<Vec<Effect>> {
        let mut stmt = conn.prepare_cached("SELECT seq, agent, LENGTH(payload), payload FROM outbox ORDER BY seq")?;
        let mut rows = stmt.query([])?;
        let (mut effects, mut bytes) = (Vec::new(), 0usize);
        while let Some(row) = rows.next()? {
            let len = row.get::<_, i64>(2)? as usize;
            if effects.len() >= max_messages || (!effects.is_empty() && bytes + len > max_bytes) {
                break;
            }
            bytes += len;
            effects.push(Effect { seq: row.get(0)?, agent: row.get(1)?, payload: row.get(3)? });
        }
        drop(rows);
        if let Some(last) = effects.last() {
            conn.execute("DELETE FROM outbox WHERE seq <= ?1", [last.seq])?;
        }
        Ok(effects)
    })();
    // A failed commit can leave the transaction open, so every failure ends in a rollback.
    match drained.and_then(|effects| conn.execute_batch("COMMIT").map(|()| effects)) {
        Ok(effects) => Ok(effects),
        Err(e) => {
            if !conn.is_autocommit() {
                let _ = conn.execute_batch("ROLLBACK");
            }
            Err(e.into())
        }
    }
}

/// Record an input and keep only the newest `keep` rows.
pub fn audit(conn: &Connection, agent: &str, event: &[u8], ok: bool, keep: u64) -> rusqlite::Result<()> {
    let at_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    conn.prepare_cached("INSERT INTO audit (at_ms, agent, event, ok) VALUES (?1, ?2, ?3, ?4)")?
        .execute(params![at_ms, agent, event, ok])?;
    conn.prepare_cached("DELETE FROM audit WHERE seq <= (SELECT MAX(seq) FROM audit) - ?1")?
        .execute([keep as i64])?;
    Ok(())
}

/// Record a rejected input in a transaction of its own and, when it was queued, take it off the
/// queue in that same transaction. `notice` names the log when the input was a notification
/// to `agent`, so that the next new entry can notify it again, and says whether the failure
/// is to be counted and the agent prompted once more; `checkpoint`
/// names the log when it was a checkpoint request to `agent`, so that one can be asked for
/// again; `full` names the log of `agent` that an append found full, so that a checkpoint of
/// it is asked for; `storage_full` says the ship's file itself was full, so that entries its
/// logs no longer need are let go; `owed` names the ship and number when the input was a
/// command from another ship, with what to tell it. Leaves no transaction open, whatever
/// happens. `recorded` says whether to write the audit row, the one part of this that can be
/// done without.
#[allow(clippy::too_many_arguments)]
pub fn record_rejection(
    conn: &Connection,
    recorded: bool,
    queued: Option<i64>,
    owed: Option<(&str, u64, Verdict, &str)>,
    notice: Option<(Followed, bool)>,
    checkpoint: Option<&str>,
    full: Option<&str>,
    storage_full: bool,
    agent: &str,
    event: &[u8],
    keep: u64,
) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    // Making room comes first, since everything after it needs some.
    let saved = (if storage_full { reclaim(conn) } else { Ok(()) })
        .and_then(|()| queued.map_or(Ok(()), |seq| inbox_delete(conn, seq)))
        .and_then(|()| owed.map_or(Ok(()), |(peer, about, verdict, reason)| receipt_push(conn, peer, about, verdict, reason)))
        .and_then(|()| checkpoint.map_or(Ok(()), |log| checkpoint_answered(conn, agent, log)))
        .and_then(|()| full.map_or(Ok(()), |log| ask_checkpoint_when_full(conn, agent, log)))
        .and_then(|()| {
            notice.map_or(Ok(()), |(log, again)| {
                clear_notified(conn, agent, log)?;
                if again { notify_failed(conn, agent, log) } else { Ok(()) }
            })
        })
        .and_then(|()| if recorded { audit(conn, agent, event, false, keep) } else { Ok(()) })
        .and_then(|()| conn.execute_batch("COMMIT"));
    if saved.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    saved
}

/// Record a rejected input that never reached a handler. Best effort: the caller's rejection
/// is the result that matters, so a failure to log it is not reported.
pub fn audit_failure(conn: &Connection, agent: &str, event: &[u8], keep: u64) {
    let _ = record_rejection(conn, true, None, None, None, None, None, false, agent, event, keep);
}

/// The newest audit rows, newest first.
pub fn audit_tail(conn: &Connection, limit: usize) -> Result<Vec<AuditEntry>, Error> {
    let mut stmt = conn.prepare("SELECT seq, agent, event, ok FROM audit ORDER BY seq DESC LIMIT ?1")?;
    let rows = stmt.query_map([limit as i64], |r| {
        Ok(AuditEntry { seq: r.get(0)?, agent: r.get(1)?, event: r.get(2)?, ok: r.get(3)? })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Write a consistent single-file copy, safe while the ship is live.
///
/// The copy is the file's contents as they would be with nothing encrypted, and it is made
/// in memory: it is never written anywhere as it stands. Whoever asked for it seals it
/// before it goes to disk.
pub fn snapshot(conn: &Connection) -> Result<Data<'_>, Error> {
    // A database of its own, in memory and with no key, filled from this one in a single
    // transaction and then read out whole. If an earlier copy could not be cleared away,
    // it is cleared away now, so that one failure does not stop every copy after it.
    let _ = conn.execute_batch("DETACH DATABASE plain");
    conn.execute_batch("ATTACH DATABASE ':memory:' AS plain KEY ''")?;
    let copied = conn
        .execute_batch("BEGIN; SELECT sqlcipher_export('plain'); COMMIT;")
        .and_then(|()| conn.serialize(DatabaseName::Attached("plain")));
    if copied.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    let detached = conn.execute_batch("DETACH DATABASE plain");
    let contents = copied?;
    detached?;
    Ok(contents)
}

/// Open the contents of a ship's file, as `snapshot` gives them, as a database in memory
/// that can be read and not changed. Nothing is read from it here: SQLite looks at none of
/// it until the first statement is run.
fn in_memory(contents: &[u8]) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    // SQLite takes over a buffer that came from its own allocator.
    let owned = unsafe {
        let buffer = rusqlite::ffi::sqlite3_malloc64(contents.len().max(1) as u64) as *mut u8;
        let Some(buffer) = std::ptr::NonNull::new(buffer) else {
            return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOMEM), None));
        };
        std::ptr::copy_nonoverlapping(contents.as_ptr(), buffer.as_ptr(), contents.len());
        OwnedData::from_raw_nonnull(buffer, contents.len())
    };
    conn.deserialize(DatabaseName::Main, owned, true)?;
    Ok(conn)
}

fn schema_objects(conn: &Connection, limit: usize) -> Result<BTreeSet<(String, String, Option<String>)>, Error> {
    let mut stmt = conn.prepare("SELECT type, name, sql FROM sqlite_master LIMIT ?1")?;
    let rows = stmt.query_map([limit.min(i64::MAX as usize) as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// True if the file's schema holds exactly `entries` rows, read straight from its pages.
///
/// The schema is a table whose top is the file's first page. This runtime's schema is small:
/// either that page holds every row, or it points at a few pages that between them do. A
/// file whose schema is laid out any other way is not one this runtime wrote. Nothing is
/// taken on trust here: every number read is checked against what was actually read.
fn schema_has(contents: &[u8], entries: usize) -> Result<bool, Error> {
    const TABLE_LEAF: u8 = 0x0d;
    const TABLE_INTERIOR: u8 = 0x05;
    /// The most pages a schema of this runtime's size is ever spread over.
    const MAX_LEAVES: usize = 8;
    let mut file = io::Cursor::new(contents);
    let mut header = [0u8; 112];
    if file.read_exact(&mut header).is_err() || !header.starts_with(b"SQLite format 3\0") {
        return Ok(false);
    }
    let cells = u16::from_be_bytes([header[103], header[104]]) as usize;
    match header[100] {
        TABLE_LEAF => Ok(cells == entries),
        TABLE_INTERIOR if cells < MAX_LEAVES => {
            let page_size = match u16::from_be_bytes([header[16], header[17]]) {
                1 => 65536u64,
                size if size >= 512 && size.is_power_of_two() => u64::from(size),
                _ => return Ok(false),
            };
            let mut top = vec![0u8; page_size as usize];
            if file.seek(SeekFrom::Start(0)).is_err() || file.read_exact(&mut top).is_err() {
                return Ok(false);
            }
            // Each cell starts with the number of the page below it, and the header holds
            // the number of the last.
            let mut below = Vec::with_capacity(cells + 1);
            for cell in 0..cells {
                let at = u16::from_be_bytes([top[112 + 2 * cell], top[113 + 2 * cell]]) as usize;
                let Some(number) = top.get(at..at + 4) else { return Ok(false) };
                below.push(u32::from_be_bytes(number.try_into().expect("four bytes")));
            }
            below.push(u32::from_be_bytes(header[108..112].try_into().expect("four bytes")));
            let mut found = 0usize;
            for page in below {
                let mut start = [0u8; 8];
                let at = u64::from(page).checked_sub(1).filter(|before| *before >= 1).map(|before| before * page_size);
                let Some(at) = at else { return Ok(false) };
                if file.seek(SeekFrom::Start(at)).is_err() || file.read_exact(&mut start).is_err() || start[0] != TABLE_LEAF {
                    return Ok(false);
                }
                found += u16::from_be_bytes([start[3], start[4]]) as usize;
            }
            Ok(found == entries)
        }
        _ => Ok(false),
    }
}

fn text(row: &Row, index: usize) -> Result<String, Error> {
    match row.get_ref(index)? {
        ValueRef::Text(bytes) => String::from_utf8(bytes.to_vec()).map_err(|_| bad_row("text is not UTF-8")),
        _ => Err(bad_row("expected text")),
    }
}

fn blob(row: &Row, index: usize, max: usize) -> Result<Vec<u8>, Error> {
    match row.get_ref(index)? {
        ValueRef::Blob(bytes) if bytes.len() <= max => Ok(bytes.to_vec()),
        ValueRef::Blob(_) => Err(bad_row("value is larger than this runtime allows")),
        _ => Err(bad_row("expected bytes")),
    }
}

fn integer(row: &Row, index: usize) -> Result<i64, Error> {
    match row.get_ref(index)? {
        ValueRef::Integer(n) if (0..=MAX_SEQ).contains(&n) => Ok(n),
        _ => Err(bad_row("expected a non-negative integer in range")),
    }
}

/// Whether this is how a ship's name is written here: lower-case letters and dashes.
pub fn ship_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// A stored receipt that another ship sent, if it is one this runtime could have kept: about
/// a numbered command, with a reason no longer than a receipt may carry. Its verdict is the
/// other ship's word and is kept as it came, so it may be one this runtime has no name for.
fn taken_receipt(bytes: &[u8]) -> Option<Receipt> {
    let receipt = Receipt::decode(bytes).ok()?;
    (bytes.len() <= MAX_RECEIPT_BYTES && receipt.about >= 1 && receipt.reason.len() <= MAX_REASON_BYTES).then_some(receipt)
}

/// A stored receipt that this ship is to send, if it is one this runtime could have written:
/// as above, and with a verdict it knows.
fn own_receipt(bytes: &[u8]) -> Option<Receipt> {
    let known = |receipt: &Receipt| Verdict::try_from(receipt.verdict).is_ok_and(|verdict| verdict != Verdict::Unspecified);
    taken_receipt(bytes).filter(known)
}

fn bad_row(why: &str) -> Error {
    Error::BadShipFile(format!("import: {why}"))
}

/// Copy a ship file from an untrusted source into a freshly created file at `dest`.
///
/// The source must have exactly this runtime's schema, so it cannot carry triggers or views, and
/// every row is re-validated on the way across. Returns the hash of the ship's kernel module.
pub fn import(
    contents: Vec<u8>,
    dest: &Path,
    name: &str,
    cfg: &Config,
    deadline: Instant,
    key: &VerifyingKey,
    check_agent: fn(&str) -> Result<(), Error>,
    check_hash: fn(&str) -> Result<(), Error>,
    incarnation: &[u8; 16],
    file_key: &[u8; 32],
    recovery: &[u8; 32],
) -> Result<String, Error> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    let expected = schema_objects(&reference, usize::MAX)?;
    // SQLite parses a file's whole schema before any query can limit it, so count the schema
    // entries straight from the file first.
    if !schema_has(&contents, expected.len())? {
        return Err(bad_row("schema does not match this runtime's"));
    }

    // Limits go on before the first statement, because that is when SQLite reads and parses the
    // source's schema. They make it refuse oversized values and SQL instead of loading them.
    // The source is read where it is, in memory, and cannot be written to.
    let from = in_memory(&contents).map_err(|_| bad_row("not a ship file"))?;
    // SQLite has its own copy now.
    drop(contents);
    let largest =
        cfg.limits.max_value_bytes.max(cfg.limits.max_effect_bytes).max(cfg.max_event_bytes).max(cfg.max_checkpoint_bytes);
    let _ = from.set_limit(Limit::SQLITE_LIMIT_LENGTH, i32::try_from(largest + (64 << 10)).unwrap_or(i32::MAX));
    let _ = from.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 64 << 10);
    from.pragma_update(None, "trusted_schema", "OFF").map_err(|_| bad_row("not a ship file"))?;

    // One more than expected is enough to tell that the source has extra objects.
    let found = schema_objects(&from, expected.len() + 1).map_err(|_| bad_row("not a ship file"))?;
    if found != expected {
        return Err(bad_row("schema does not match this runtime's"));
    }
    // A damaged file can point several parts of a table at the same pages, which would make a
    // plain read revisit them over and over. The check visits each page once and reports that.
    let verdict: String =
        from.query_row("PRAGMA quick_check(1)", [], |r| r.get(0)).map_err(|_| bad_row("file is damaged"))?;
    if verdict != "ok" {
        return Err(bad_row("file is damaged"));
    }
    let in_time = || if Instant::now() > deadline { Err(bad_row("took too long")) } else { Ok(()) };
    in_time()?;
    check_meta(&from, name)?;
    let kernel_hash = kernel(&from)?;
    check_hash(&kernel_hash)?;

    // The copy is given a mark of its own, whatever mark the source had: it may be an old
    // copy of the ship, brought back, and other ships tell by the mark that it may have
    // forgotten what it once knew of them.
    // The ship keeps the recovery key of the code that opened this copy, whatever the copy
    // itself says its key is. So the code that brought a ship back is the code that opens
    // the copies made of it from here on.
    // A moon keeps its parent's word for its key. Whether that word is good is for the
    // ships it meets to say: a bad one only stops the moon being believed.
    let proof = moon_proof(&from).map_err(|_| bad_row("not a ship file"))?;
    create(dest, name, &kernel_hash, cfg.max_ship_bytes, incarnation, file_key, Some(recovery), proof.as_ref())?;
    let to = open(dest, Durability::Full, cfg.max_ship_bytes, file_key)?;
    // Leave WAL mode so that a commit means the data is in the main file, which is the only
    // file that gets published. The switch itself fails if earlier writes cannot be folded in.
    let mode: String = to.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))?;
    if mode != "delete" {
        return Err(bad_row("could not finalize the imported file"));
    }
    to.execute_batch("BEGIN IMMEDIATE")?;

    let mut stmt = from.prepare("SELECT agent, key, value FROM kv")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let agent = text(row, 0)?;
        check_agent(&agent)?;
        in_time()?;
        let key = blob(row, 1, cfg.limits.max_key_bytes)?;
        // A plain insert, so a key that appears twice in the source is an error, not an overwrite.
        to.prepare_cached("INSERT INTO kv VALUES (?1, ?2, ?3)")?
            .execute(params![agent, key, blob(row, 2, cfg.limits.max_value_bytes)?])?;
    }

    let mut pending = 0u64;
    let mut stmt = from.prepare("SELECT seq, agent, payload FROM outbox ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, agent) = (integer(row, 0)?, text(row, 1)?);
        check_agent(&agent)?;
        let payload = blob(row, 2, cfg.limits.max_effect_bytes)?;
        pending += payload.len() as u64 + MESSAGE_OVERHEAD;
        if seq == 0 || pending > cfg.max_outbox_bytes {
            return Err(bad_row("outbox is larger than this runtime allows"));
        }
        to.execute("INSERT INTO outbox VALUES (?1, ?2, ?3)", params![seq, agent, payload])?;
    }

    // Logs. First, what the source says about each one: where it ends, how much of its start
    // has been dropped, and its checkpoint if it has one. Then its entries, each of which must
    // be signed by this ship's key and follow on from the one before, and must between them
    // reach exactly where the source says the log ends. Each log's summary is rebuilt from what
    // is actually there. A file with its newest entries removed would otherwise be accepted,
    // and the ship would go on to reuse their numbers.
    struct Claim {
        head: u64,
        head_hash: Vec<u8>,
        base: u64,
        history: bool,
        /// The checkpoint's entry number and that entry's hash.
        checkpoint: Option<(u64, [u8; 32])>,
        rebuilt: bool,
    }
    let mut claims: HashMap<(String, String), Claim> = HashMap::new();
    let mut stmt = from.prepare("SELECT agent, name, head, head_hash, base, history FROM logs")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log) = (text(row, 0)?, text(row, 1)?);
        let (head, head_hash) = (integer(row, 2)? as u64, blob(row, 3, 32)?);
        let (base, history) = (integer(row, 4)? as u64, integer(row, 5)?);
        check_agent(&agent)?;
        // A damaged file can list one log twice, so each must be seen once and only once.
        let fresh = Claim { head, head_hash, base, history: history == 1, checkpoint: None, rebuilt: false };
        // Counted before anything is kept, so a file listing millions of logs is turned away
        // after reading a bounded number of them.
        if claims.len() >= cfg.max_logs {
            return Err(bad_row("more logs than this runtime allows"));
        }
        if !interface_ok(&log) || head == 0 || base > head || history > 1 || claims.insert((agent, log), fresh).is_some() {
            return Err(bad_row("a log is described wrongly or twice"));
        }
    }

    let mut stmt = from.prepare("SELECT agent, name, seq, body, signature FROM checkpoints")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, seq) = (text(row, 0)?, text(row, 1)?, integer(row, 2)? as u64);
        let (body, signature) = (blob(row, 3, cfg.max_checkpoint_bytes + (4 << 10))?, blob(row, 4, 64)?);
        let genuine = Signature::from_slice(&signature)
            .is_ok_and(|signature| key.verify(&signed_bytes(CHECKPOINT_DOMAIN, &body), &signature).is_ok());
        let stated = CheckpointBody::decode(&*body).map_err(|_| bad_row("a checkpoint cannot be decoded"))?;
        let Some(claim) = claims.get_mut(&(agent.clone(), log.clone())) else {
            return Err(bad_row("there is a checkpoint for a log the file does not list"));
        };
        // Entries are only ever dropped up to a checkpoint, never past the newest one. So the
        // checkpoint stands for an entry that is still held, or for the last one dropped.
        let fits = stated.ship == name
            && stated.agent == agent
            && stated.log == log
            && stated.seq == seq
            && stated.state.len() <= cfg.max_checkpoint_bytes
            && seq >= 1
            && seq >= claim.base
            && seq <= claim.head;
        let hash = <[u8; 32]>::try_from(stated.hash).ok();
        let (true, true, Some(hash), None) = (genuine, fits, hash, &claim.checkpoint) else {
            return Err(bad_row("a checkpoint is not signed by this ship's key or does not fit its log"));
        };
        claim.checkpoint = Some((seq, hash));
        to.execute("INSERT INTO checkpoints VALUES (?1, ?2, ?3, ?4, ?5)", params![agent, log, seq as i64, body, signature])?;
    }
    // Entries can only have been dropped from a log that has a checkpoint to stand in for them.
    if claims.values().any(|claim| claim.base > 0 && claim.checkpoint.is_none()) {
        return Err(bad_row("a log has lost its early entries but has no checkpoint"));
    }

    // A log can hold no entries at all, when a full ship let go of everything its checkpoint
    // covers. The checkpoint is then the only signed evidence of where the log ends, so it
    // must stand for exactly that entry and name the hash the log gives for it.
    for ((agent, log), claim) in claims.iter_mut().filter(|(_, claim)| claim.base == claim.head) {
        in_time()?;
        let ends_here = claim.checkpoint.is_some_and(|(seq, hash)| seq == claim.head && hash[..] == claim.head_hash[..]);
        if !ends_here {
            return Err(bad_row("a log with no entries left has no checkpoint for its end"));
        }
        to.execute(
            "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, 0, ?6, 0)",
            params![agent, log, claim.head as i64, claim.head_hash, claim.base as i64, claim.history],
        )?;
        claim.rebuilt = true;
    }

    struct Open<'a> {
        chain: ChainCheck<'a>,
        head: u64,
        hash: [u8; 32],
        bytes: u64,
        tail: u64,
        /// Whether the entry the checkpoint stands for has been seen and has the stated hash.
        anchored: bool,
    }
    let mut open: Option<Open> = None;
    let close = |finished: Option<Open>, claims: &mut HashMap<(String, String), Claim>| -> Result<(), Error> {
        let Some(log) = finished else { return Ok(()) };
        let claim = claims.get_mut(&(log.chain.agent.clone(), log.chain.log.clone())).expect("checked when opened");
        if log.head != claim.head || log.hash[..] != claim.head_hash[..] || (claim.checkpoint.is_some() && !log.anchored) {
            return Err(bad_row("a log's entries do not reach where the log says it ends"));
        }
        claim.rebuilt = true;
        to.execute(
            "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, 0)",
            params![
                log.chain.agent,
                log.chain.log,
                log.head as i64,
                &log.hash[..],
                log.bytes as i64,
                claim.base as i64,
                log.tail as i64,
                claim.history
            ],
        )?;
        Ok(())
    };
    let mut stmt = from.prepare("SELECT agent, name, seq, body, signature FROM log_entries ORDER BY agent, name, seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, seq) = (text(row, 0)?, text(row, 1)?, integer(row, 2)? as u64);
        let (body, signature) = (blob(row, 3, cfg.max_event_bytes + (4 << 10))?, blob(row, 4, 64)?);
        if open.as_ref().is_none_or(|open| open.chain.agent != agent || open.chain.log != log) {
            close(open.take(), &mut claims)?;
            let Some(claim) = claims.get(&(agent.clone(), log.clone())) else {
                return Err(bad_row("there are log entries for a log the file does not list"));
            };
            // The entries that are left start straight after the ones that were dropped.
            if seq != claim.base + 1 || claim.rebuilt {
                return Err(bad_row("a log does not start where it says it does"));
            }
            let (chain, anchored) = match (claim.base, &claim.checkpoint) {
                (0, _) => (ChainCheck::new(key, name, &agent, &log, None), false),
                // Everything the checkpoint covers is gone. The first entry left must link back
                // to the very entry the checkpoint names, which ties the two together.
                (base, Some((at, hash))) if *at == base => {
                    (ChainCheck::new(key, name, &agent, &log, Some((base, *hash))), true)
                }
                (base, _) => (ChainCheck::resuming(key, name, &agent, &log, base), false),
            };
            open = Some(Open { chain, head: 0, hash: [0; 32], bytes: 0, tail: 0, anchored });
        }
        let open = open.as_mut().expect("opened above");
        let (accepted, accepted_hash, payload_len) = open.chain.accept(&body, &signature).map_err(|why| bad_row(&why))?;
        let cost = entry_cost(body.len());
        if accepted != seq || payload_len > cfg.max_event_bytes || open.bytes + cost > cfg.max_log_bytes {
            return Err(bad_row("logs are numbered wrongly or larger than this runtime allows"));
        }
        let claim = &claims[&(agent.clone(), log.clone())];
        let after_checkpoint = match &claim.checkpoint {
            Some((at, hash)) if *at == accepted => {
                // The checkpoint names this entry, so it must be the entry the checkpoint saw.
                if hash[..] != accepted_hash[..] {
                    return Err(bad_row("a checkpoint does not match the entry it stands for"));
                }
                open.anchored = true;
                false
            }
            Some((at, _)) => accepted > *at,
            None => true,
        };
        (open.head, open.hash, open.bytes) = (accepted, accepted_hash, open.bytes + cost);
        if after_checkpoint {
            open.tail += cost;
        }
        to.execute("INSERT INTO log_entries VALUES (?1, ?2, ?3, ?4, ?5)", params![agent, log, seq as i64, body, signature])?;
    }
    close(open.take(), &mut claims)?;
    if claims.values().any(|claim| !claim.rebuilt) {
        return Err(bad_row("the file lists a log that has no entries"));
    }
    // Where each log ends, and whether it is a history.
    let heads: HashMap<(String, String), (u64, bool)> =
        claims.into_iter().map(|(log, claim)| (log, (claim.head, claim.history))).collect();

    // What this ship holds of logs on other ships, for the agents that follow them. Only
    // payloads are kept, and they were checked against the other ship's key as they came,
    // which cannot be done again here: this is the ship's own account of what it was sent,
    // as its agents' stored values are. What is checked is that the account hangs together:
    // each copy belongs to an agent that follows that log, holds exactly the entries between
    // what the agent has taken and what was fetched, and is no larger than it could have
    // grown. A file that lied about a hash would only stop its own ship from following on.
    struct Held {
        head: u64,
        checkpoint: Option<u64>,
        first: Option<u64>,
        last: u64,
        bytes: u64,
        newest_cost: u64,
        followed: bool,
    }
    type Copy = (String, String, String, String);
    let mut held: HashMap<Copy, Held> = HashMap::new();
    let mut stmt = from.prepare("SELECT peer, agent, name, follower, head, head_hash, announced, stopped, seen FROM remote_logs")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (peer, agent, log, follower) = (text(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?);
        let (head, head_hash, announced, stopped) = (integer(row, 4)? as u64, blob(row, 5, 32)?, integer(row, 6)?, text(row, 7)?);
        check_agent(&agent)?;
        check_agent(&follower)?;
        let seen = blob(row, 8, 16)?;
        let linked = (if head == 0 { head_hash.is_empty() } else { head_hash.len() == 32 }) && (seen.is_empty() || seen.len() == 16);
        if !ship_name_ok(&peer) || peer == name || !interface_ok(&log) || !linked || stopped.len() > MAX_REASON_BYTES {
            return Err(bad_row("a log followed on another ship is recorded wrongly"));
        }
        // No entry numbered beyond this is ever kept or believed in, so that whatever
        // another ship sends, the numbers in this ship's file stay ones it can be read
        // back with.
        if head > MAX_LOG_SEQ || announced as u64 > MAX_LOG_SEQ {
            return Err(bad_row("a log followed on another ship is numbered beyond what this runtime allows"));
        }
        // It starts afresh with the other ship: an import may be a return to an earlier
        // state, and asking again is how the two find out where they stand. (The number that
        // tells one asking from the next starts again too.)
        to.execute(
            "INSERT INTO remote_logs VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, 0, ?9)",
            params![peer, agent, log, follower, head as i64, head_hash, announced, stopped, seen],
        )?;
        let fresh = Held { head, checkpoint: None, first: None, last: 0, bytes: 0, newest_cost: 0, followed: false };
        held.insert((peer, agent, log, follower), fresh);
    }
    let mut stmt = from.prepare("SELECT peer, agent, name, follower, seq, state FROM remote_checkpoints")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let copy: Copy = (text(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?);
        let (seq, state) = (integer(row, 4)? as u64, blob(row, 5, cfg.max_checkpoint_bytes)?);
        let Some(copy_held) = held.get_mut(&copy).filter(|held| seq >= 1 && seq <= held.head) else {
            return Err(bad_row("a checkpoint held from another ship belongs to no log followed there"));
        };
        (copy_held.checkpoint, copy_held.bytes) = (Some(seq), state.len() as u64 + MESSAGE_OVERHEAD);
        to.execute("INSERT INTO remote_checkpoints VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![copy.0, copy.1, copy.2, copy.3, seq as i64, state])?;
    }
    let mut stmt = from.prepare("SELECT peer, agent, name, follower, seq, payload FROM remote_entries ORDER BY peer, agent, name, follower, seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let copy: Copy = (text(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?);
        let (seq, payload) = (integer(row, 4)? as u64, blob(row, 5, cfg.max_event_bytes)?);
        // Each follows the one before, with no gaps. Where they start and end is checked
        // below, once it is known how far the agent has got.
        let Some(copy_held) = held.get_mut(&copy).filter(|held| seq >= 1 && (held.first.is_none() || seq == held.last + 1)) else {
            return Err(bad_row("entries held from another ship are numbered wrongly, or belong to no log followed there"));
        };
        let cost = payload.len() as u64 + MESSAGE_OVERHEAD;
        copy_held.first.get_or_insert(seq);
        (copy_held.last, copy_held.bytes, copy_held.newest_cost) = (seq, copy_held.bytes + cost, cost);
        to.execute("INSERT INTO remote_entries VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![copy.0, copy.1, copy.2, copy.3, seq as i64, payload])?;
    }

    let mut behind = Vec::new();
    let mut following: HashMap<String, usize> = HashMap::new();
    let mut follows: HashMap<(String, String, String, String), bool> = HashMap::new();
    let mut stmt = from.prepare("SELECT follower, ship, agent, name, cursor FROM follows")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (follower, ship, agent, log, cursor) = (text(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?, integer(row, 4)? as u64);
        check_agent(&follower)?;
        check_agent(&agent)?;
        let head = if ship.is_empty() {
            heads.get(&(agent.clone(), log.clone())).map_or(0, |(head, _)| *head)
        } else {
            // A log on another ship. What is held of it is exactly what lies between the
            // agent's position and the newest entry fetched: a checkpoint first, if one is
            // waiting, and then entries up to that newest one. An entry is only taken while
            // less than the limit is held, so all but the newest come to less than it.
            let Some(copy) = held.get_mut(&(ship.clone(), agent.clone(), log.clone(), follower.clone())).filter(|copy| !copy.followed) else {
                return Err(bad_row("an agent follows a log on another ship that the file holds nothing of"));
            };
            copy.followed = true;
            let from_here = match copy.checkpoint {
                Some(at) if at > cursor => at,
                Some(_) => return Err(bad_row("a checkpoint held from another ship is one the agent has already passed")),
                None => cursor,
            };
            let whole = match copy.first {
                Some(first) => first == from_here + 1 && copy.last == copy.head && copy.bytes - copy.newest_cost < cfg.max_follow_bytes,
                None => copy.head == from_here,
            };
            if !whole {
                return Err(bad_row("what is held of a log on another ship is not what lies between its follower and its end"));
            }
            to.execute(
                "UPDATE remote_logs SET bytes = ?5 WHERE peer = ?1 AND agent = ?2 AND name = ?3 AND follower = ?4",
                params![ship, agent, log, follower, copy.bytes as i64],
            )?;
            copy.head
        };
        let count = following.entry(follower.clone()).or_default();
        *count += 1;
        if !interface_ok(&log) || cursor > head || *count > MAX_FOLLOWS {
            return Err(bad_row("a follower is ahead of the log it follows, or follows too many"));
        }
        to.execute("INSERT INTO follows VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)", params![follower, ship, agent, log, cursor as i64])?;
        if cursor < head {
            behind.push((follower.clone(), ship.clone(), agent.clone(), log.clone()));
        }
        follows.insert((follower, ship, agent, log), false);
    }
    if held.values().any(|copy| !copy.followed) {
        return Err(bad_row("the file holds part of a log on another ship that no agent follows"));
    }

    // Who may follow this ship's logs, and who does. A ship that follows a log and has not
    // been shut out must be one the log is shared with. Every one of them is told afresh
    // where the log stands: this ship may have come back from an earlier state.
    let mut shared: HashSet<(String, String, String)> = HashSet::new();
    let mut shared_count: HashMap<(String, String), usize> = HashMap::new();
    let mut stmt = from.prepare("SELECT agent, name, peer FROM log_shares")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, peer) = (text(row, 0)?, text(row, 1)?, text(row, 2)?);
        check_agent(&agent)?;
        let count = shared_count.entry((agent.clone(), log.clone())).or_default();
        *count += 1;
        if !interface_ok(&log) || !(peer == "*" || (ship_name_ok(&peer) && peer != name)) || *count > cfg.max_log_shares {
            return Err(bad_row("a log is shared with something that is not a ship, or with too many"));
        }
        to.execute("INSERT INTO log_shares VALUES (?1, ?2, ?3)", params![agent, log, peer])?;
        shared.insert((agent, log, peer));
    }
    let mut follower_count: HashMap<(String, String), usize> = HashMap::new();
    let mut stmt = from.prepare("SELECT agent, name, peer, kicked FROM log_peers")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, peer, kicked) = (text(row, 0)?, text(row, 1)?, text(row, 2)?, integer(row, 3)?);
        check_agent(&agent)?;
        let count = follower_count.entry((agent.clone(), log.clone())).or_default();
        *count += 1;
        let let_in = shared.contains(&(agent.clone(), log.clone(), peer.clone())) || shared.contains(&(agent.clone(), log.clone(), "*".to_string()));
        if !interface_ok(&log) || !ship_name_ok(&peer) || peer == name || kicked > 1 || (kicked == 0 && !let_in) || *count > cfg.max_log_followers {
            return Err(bad_row("a ship is recorded as following a log it may not, or too many are"));
        }
        // The marks that tell one asking from another start again with the import: nothing
        // asked of the ship before it can still be on its way to this copy of it.
        to.execute("INSERT INTO log_peers VALUES (?1, ?2, ?3, 1, ?4, 0)", params![agent, log, peer, kicked])?;
    }

    // What this ship has sent to and taken from other ships: for each, the number of the last
    // message sent, the number of the last taken, the messages still waiting to go, and the
    // commands sent that have had no receipt. The numbers are what make a command arrive
    // exactly once, so they go with the ship. What is recorded as waiting is counted afresh
    // from the messages that are actually there.
    let mut taken_from: HashMap<String, u64> = HashMap::new();
    let mut sent_to: HashMap<String, u64> = HashMap::new();
    let mut stmt = from.prepare("SELECT peer, sent, received FROM peers")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (peer, sent, received) = (text(row, 0)?, integer(row, 1)?, integer(row, 2)?);
        if sent_to.len() >= cfg.max_peers || !ship_name_ok(&peer) || peer == name || sent_to.insert(peer.clone(), sent as u64).is_some() {
            return Err(bad_row("another ship is recorded wrongly, or there are too many"));
        }
        // The numbers of messages have a ceiling. A ship that was let in close to it could
        // run into it while running, where there is no good way out: a command already
        // taken could not have its receipt numbered. So a file is only let in with numbers
        // no more than half way there, which leaves more room than any ship will ever use.
        if sent > MAX_SEQ / 2 || received > MAX_SEQ / 2 {
            return Err(bad_row("another ship's message numbers are beyond what this runtime allows"));
        }
        taken_from.insert(peer.clone(), received as u64);
        // Every ship this one has exchanged commands with is told afresh where this ship
        // stands, and asked where it stands. An import may be a return to an earlier state,
        // and that is how the two find out, and put right what can be.
        to.execute("INSERT INTO peers VALUES (?1, ?2, ?3, 0, 1, 0)", params![peer, sent, received])?;
    }
    /// What is waiting to go to one other ship.
    #[derive(Default)]
    struct Waiting {
        last: u64,
        bytes: u64,
        command_bytes: u64,
        receipts: usize,
    }
    let mut waiting: HashMap<String, Waiting> = HashMap::new();
    // The commands from other ships that receipts waiting to go are about, as (ship, number
    // that ship gave the command).
    let mut answered: HashSet<(String, u64)> = HashSet::new();
    let mut stmt = from.prepare("SELECT peer, seq, source, agent, interface, payload, receipt FROM peer_out ORDER BY peer, seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (peer, seq, receipt) = (text(row, 0)?, integer(row, 1)? as u64, integer(row, 6)?);
        let (source, agent, interface) = (text(row, 2)?, text(row, 3)?, text(row, 4)?);
        let payload = blob(row, 5, cfg.max_event_bytes.max(MAX_RECEIPT_BYTES))?;
        let Some(received) = taken_from.get(&peer).copied() else {
            return Err(bad_row("something is waiting to go to a ship this one has no record of"));
        };
        // Each is numbered after the one before it. They need not start at 1: the earlier ones
        // have been delivered. The newest must be the last one sent, which is checked below.
        let line = waiting.entry(peer.clone()).or_default();
        let cost = payload.len() as u64 + MESSAGE_OVERHEAD;
        if seq == 0 || (line.last != 0 && seq != line.last + 1) {
            return Err(bad_row("what is waiting to go to another ship is numbered wrongly"));
        }
        (line.last, line.bytes) = (seq, line.bytes + cost);
        match receipt {
            0 => {
                check_agent(&source)?;
                check_agent(&agent)?;
                line.command_bytes += cost;
                if !interface_ok(&interface) || payload.len() > cfg.max_event_bytes || line.command_bytes > cfg.max_peer_out_bytes {
                    return Err(bad_row("commands waiting to go to another ship are named wrongly or too large"));
                }
            }
            // A receipt is for a command that ship sent here, and there is one for each. It
            // names no agent: the other ship knows which command it numbered so.
            1 => {
                let sound = own_receipt(&payload).filter(|receipt| {
                    let bare = receipt.ship.is_empty() && receipt.agent.is_empty() && receipt.interface.is_empty();
                    bare && receipt.about <= received && answered.insert((peer.clone(), receipt.about))
                });
                line.receipts += 1;
                if sound.is_none() || !(source.is_empty() && agent.is_empty() && interface.is_empty()) || line.receipts > cfg.max_unanswered {
                    return Err(bad_row("a receipt waiting to go to another ship is not one this ship would have made"));
                }
            }
            _ => return Err(bad_row("what is waiting to go to another ship is neither a command nor a receipt")),
        }
        to.execute(
            "INSERT INTO peer_out VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![peer, seq as i64, source, agent, interface, payload, receipt],
        )?;
    }
    for (peer, line) in &waiting {
        // The newest waiting message is the last one sent, or some would have gone missing.
        if line.last != sent_to[peer] {
            return Err(bad_row("what is waiting to go to another ship does not reach the last one sent"));
        }
        to.execute("UPDATE peers SET out_bytes = ?2 WHERE peer = ?1", params![peer, line.bytes as i64])?;
    }
    // The commands sent that have had no receipt: each one a command this ship sent, and only
    // so many to any one ship.
    let mut unanswered: HashMap<String, usize> = HashMap::new();
    let mut stmt = from.prepare("SELECT peer, seq, source, agent, interface, tell FROM peer_wait ORDER BY peer, seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (peer, seq, tell) = (text(row, 0)?, integer(row, 1)? as u64, integer(row, 5)?);
        let (source, agent, interface) = (text(row, 2)?, text(row, 3)?, text(row, 4)?);
        check_agent(&source)?;
        check_agent(&agent)?;
        let sent = sent_to.get(&peer).copied().unwrap_or(0);
        let count = unanswered.entry(peer.clone()).or_default();
        *count += 1;
        if seq == 0 || seq > sent || !interface_ok(&interface) || !(0..=1).contains(&tell) || *count > cfg.max_unanswered {
            return Err(bad_row("a command recorded as awaiting its receipt is not one this ship sent, or there are too many"));
        }
        to.execute("INSERT INTO peer_wait VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![peer, seq as i64, source, agent, interface, tell])?;
    }
    // Where a command awaiting its receipt is still waiting to go, the two records are of one
    // command and must say the same of it. Otherwise its receipt would be handed to the wrong
    // agent, or with the wrong account of where the command went.
    in_time()?;
    let at_odds: bool = to.query_row(
        "SELECT EXISTS (SELECT 1 FROM peer_wait w JOIN peer_out o ON o.peer = w.peer AND o.seq = w.seq
         WHERE o.receipt != 0 OR o.source != w.source OR o.agent != w.agent OR o.interface != w.interface)",
        [],
        |r| r.get(0),
    )?;
    if at_odds {
        return Err(bad_row("a command recorded as awaiting its receipt does not match the command waiting to go"));
    }

    // The queue, in its order and with its numbers, so that what runs after an import is what
    // would have run without one. That matters: a queued command that is refused is dropped
    // for good, and whether it is refused can depend on a checkpoint request ahead of it.
    //
    // A command is carried over as it is. The runtime's own two kinds of event carry nothing
    // but names, so each is checked against the logs and followers just rebuilt, and written
    // afresh: a checkpoint request must be for a log this ship has, addressed to its own
    // publisher, and a notification must be for a follower of that log. At most one of each
    // per log or follower, as the runtime itself keeps it. Anything else is not a ship file.
    let mut pending = 0u64;
    let mut asked: HashSet<(String, String)> = HashSet::new();
    // For each other ship: the number of the last queued command from it and how many there
    // are, and the commands sent to it whose receipts are queued.
    let mut queued_from: HashMap<String, (u64, usize)> = HashMap::new();
    let mut told_of: HashSet<(String, u64)> = HashSet::new();
    let mut stmt = from.prepare("SELECT seq, kind, source, agent, interface, payload, ship, ship_seq FROM inbox ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, kind, ship_seq) = (integer(row, 0)?, integer(row, 1)?, integer(row, 7)? as u64);
        let (source, agent, interface, ship) = (text(row, 2)?, text(row, 3)?, text(row, 4)?, text(row, 6)?);
        check_agent(&source)?;
        check_agent(&agent)?;
        // Only a command or a receipt can have come from another ship, and only from one this
        // ship has a record of. A command from another ship carries the number that ship gave
        // it: one it has been taken under, higher than that of any command from that ship
        // queued ahead of it, since they are taken and queued in order, and one no receipt
        // has gone out for yet. With the receipts waiting to go, they are no more than this
        // ship would have let itself owe. Nothing else carries such a number.
        let from_elsewhere = !ship.is_empty();
        let numbered = if from_elsewhere && kind == Kind::Command as i64 {
            let (last, count) = queued_from.entry(ship.clone()).or_default();
            let in_order = ship_seq > *last;
            (*last, *count) = (ship_seq, *count + 1);
            let owed = *count + waiting.get(&ship).map_or(0, |line| line.receipts);
            in_order
                && taken_from.get(&ship).is_some_and(|received| ship_seq <= *received)
                && !answered.contains(&(ship.clone(), ship_seq))
                && owed <= cfg.max_unanswered
        } else {
            // (That a receipt's ship is one this ship has a record of is checked with the
            // receipt itself, below, and that a notification is about a log some agent
            // follows, on this ship or another, with the notification.)
            ship_seq == 0 && (!from_elsewhere || kind == Kind::Receipt as i64 || kind == Kind::Notify as i64)
        };
        if seq == 0 || !interface_ok(&interface) || !numbered {
            return Err(bad_row("a queued event is numbered or named wrongly"));
        }
        let payload = if kind == Kind::Command as i64 {
            let payload = blob(row, 5, cfg.max_event_bytes)?;
            pending += payload.len() as u64 + MESSAGE_OVERHEAD;
            if pending > cfg.max_inbox_bytes {
                return Err(bad_row("queued commands are larger than this runtime allows"));
            }
            payload
        } else if kind == Kind::Receipt as i64 {
            let payload = blob(row, 5, MAX_RECEIPT_BYTES)?;
            pending += payload.len() as u64 + MESSAGE_OVERHEAD;
            // A receipt is handed to the agent that sent the command, and says where it went.
            // It is about a command this ship sent to that ship, there is one for a command,
            // and once it is queued the command is no longer recorded as awaiting it.
            let sound = taken_receipt(&payload).filter(|receipt| {
                let told = receipt.ship == ship && receipt.agent == source && receipt.interface == interface;
                told && sent_to.get(&ship).is_some_and(|sent| receipt.about <= *sent) && told_of.insert((ship.clone(), receipt.about))
            });
            // And if the command is still waiting to go, it is a command, sent by the agent
            // this receipt is for, to where the receipt says.
            let awaited = match &sound {
                Some(receipt) => to.query_row(
                    "SELECT EXISTS (SELECT 1 FROM peer_wait WHERE peer = ?1 AND seq = ?2)
                         OR EXISTS (SELECT 1 FROM peer_out WHERE peer = ?1 AND seq = ?2
                                    AND (receipt != 0 OR source != ?3 OR agent != ?4 OR interface != ?5))",
                    params![ship, receipt.about as i64, agent, source, interface],
                    |r| r.get::<_, bool>(0),
                )?,
                None => false,
            };
            if sound.is_none() || awaited || pending > cfg.max_inbox_bytes {
                return Err(bad_row("a queued receipt is not one this ship would have made"));
            }
            payload
        } else if kind == Kind::Checkpoint as i64 {
            let log = (agent.clone(), interface.clone());
            let known = heads.get(&log).is_some_and(|(_, history)| !history);
            if source != agent || !known || !asked.insert(log) {
                return Err(bad_row("a queued checkpoint request is not one this ship would have made"));
            }
            to.execute("UPDATE logs SET asked = 1 WHERE agent = ?1 AND name = ?2", params![agent, interface])?;
            interface.clone().into_bytes()
        } else if kind == Kind::Notify as i64 {
            // `source` is the publisher and `agent` the follower being told.
            match follows.get_mut(&(agent.clone(), ship.clone(), source.clone(), interface.clone())) {
                Some(told @ false) => *told = true,
                _ => return Err(bad_row("a queued notification is not one this ship would have made")),
            }
            to.execute(
                "UPDATE follows SET notified = 1 WHERE follower = ?1 AND ship = ?2 AND agent = ?3 AND name = ?4",
                params![agent, ship, source, interface],
            )?;
            Vec::new()
        } else {
            return Err(bad_row("a queued event is of a kind this runtime does not know"));
        };
        to.execute(
            "INSERT INTO inbox VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![seq, kind, source, agent, interface, payload, ship, ship_seq as i64],
        )?;
    }
    // A follower that is behind and has no notification waiting had been given up on after
    // repeated failures. An import starts it off afresh, behind everything already queued.
    for (follower, ship, agent, log) in &behind {
        in_time()?;
        notify(&to, follower, Followed { ship, agent, name: log })?;
    }

    let mut stmt = from.prepare("SELECT seq, at_ms, agent, event, ok FROM audit ORDER BY seq DESC LIMIT ?1")?;
    let mut rows = stmt.query([cfg.audit_rows as i64])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, at_ms, agent) = (integer(row, 0)?, integer(row, 1)?, text(row, 2)?);
        check_agent(&agent)?;
        // An audit row is an event, or a line the runtime wrote about a receipt, or a receipt.
        let event = blob(row, 3, cfg.max_event_bytes.max(MAX_RECEIPT_BYTES))?;
        to.execute("INSERT INTO audit VALUES (?1, ?2, ?3, ?4, ?5)", params![seq, at_ms, agent, event, integer(row, 4)? != 0])?;
    }

    // Signed-in devices and sign-in codes go with the ship, so a ship that moves keeps its
    // owner's phone and browser. Only hashes are stored, and each must be the right size. The
    // count of wrong sign-in codes does not travel: the copy starts with a clean slate.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut stmt = from.prepare("SELECT seq, token_hash, label, created_ms FROM devices ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, hash, label, created) = (integer(row, 0)?, blob(row, 1, 32)?, text(row, 2)?, integer(row, 3)?);
        if seq == 0 || hash.len() != 32 || label.len() > MAX_LABEL_BYTES || seen.len() >= cfg.max_devices || !seen.insert(hash.clone()) {
            return Err(bad_row("a signed-in device is recorded wrongly, or there are too many"));
        }
        to.execute("INSERT INTO devices VALUES (?1, ?2, ?3, ?4)", params![seq, hash, label, created])?;
    }
    let (mut codes, mut access_codes, mut once_codes) = (HashSet::new(), 0, 0);
    let mut stmt = from.prepare("SELECT code_hash, expires_ms, reusable FROM signin_codes")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (hash, expires, reusable) = (blob(row, 0, 32)?, integer(row, 1)?, integer(row, 2)?);
        // Counted by kind: at most one access code, and no more one-time codes than may wait.
        if reusable == 0 {
            once_codes += 1;
        }
        access_codes += reusable;
        let too_many = once_codes > cfg.max_signin_codes || access_codes > 1;
        if hash.len() != 32 || reusable > 1 || too_many || !codes.insert(hash.clone()) {
            return Err(bad_row("a sign-in code is recorded wrongly, or there are too many"));
        }
        to.execute("INSERT INTO signin_codes VALUES (?1, ?2, ?3)", params![hash, expires, reusable])?;
    }

    // Every record of another ship was written above with the mark 1. Marks handed out
    // from now on start after it.
    meta_set(&to, "resync_gen", 1)?;

    // Carry the counters across so sequence numbers are never reused after an import. `integer`
    // bounds them, so a source cannot hand over a counter that is already exhausted.
    let mut counters = [("outbox", None), ("inbox", None), ("audit", None), ("devices", None)];
    let mut stmt = from.prepare("SELECT name, seq FROM sqlite_sequence")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let (table, seq) = (text(row, 0)?, integer(row, 1)?);
        match counters.iter_mut().find(|(known, _)| *known == table) {
            Some((_, slot @ None)) => *slot = Some(seq),
            _ => return Err(bad_row("unexpected sequence counter")),
        }
    }
    for (table, counter) in counters {
        let highest: i64 = to.query_row(&format!("SELECT COALESCE(MAX(seq), 0) FROM {table}"), [], |r| r.get(0))?;
        to.execute("DELETE FROM sqlite_sequence WHERE name = ?1", [table])?;
        let next = counter.unwrap_or(0).max(highest);
        to.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?1, ?2)", params![table, next])?;
    }

    to.execute_batch("COMMIT")?;
    Ok(kernel_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_mark_makes_every_copy_ask_afresh_whether_or_not_it_was_already_asking() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let (old, new) = ([1u8; 16], [2u8; 16]);
        let copy = |log: &str, joined: bool, stopped: &str, seen: &[u8]| {
            conn.execute("INSERT INTO remote_logs VALUES ('bus', 'agent', ?1, 'tally', 0, x'', 0, 0, ?2, ?3, 7, ?4)", params![log, joined, stopped, seen]).unwrap();
        };
        copy("joined", true, "", &old);
        copy("asking", false, "", &[]);
        copy("stopped", true, "no", &old);
        copy("current", true, "", &new);
        let state = |log: &str| conn.query_row("SELECT joined, gen FROM remote_logs WHERE name = ?1", [log], |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?))).unwrap();
        assert_eq!(replica_reborn(&conn, "bus", &new).unwrap(), (4, true));
        // The copy that had joined the ship as it was asks again, under a new number. So
        // does the one that was already asking: its answer may come from the ship as it was.
        assert!(state("joined") == (false, 1) && state("asking") == (false, 1));
        // One that has stopped, and one that has heard from the ship as it is, are left be.
        assert!(state("stopped") == (true, 7) && state("current") == (true, 7));
        // Another ship's logs are not touched, and a ship nobody follows has no copies.
        assert_eq!(replica_reborn(&conn, "nec", &new).unwrap(), (0, false));
    }

    #[test]
    fn news_goes_round_every_log_a_ship_follows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        // ~nec follows 300 logs here, all with something to be told. ~bus follows one.
        for n in 0..300 {
            conn.execute("INSERT INTO log_peers VALUES ('agent', ?1, 'nec', 1, 0, 0)", [format!("log-{n:03}")]).unwrap();
        }
        conn.execute("INSERT INTO log_peers VALUES ('agent', 'log-000', 'bus', 1, 0, 0)", []).unwrap();
        let names = |news: &[NewsItem]| news.iter().map(|item| item.name.clone()).collect::<Vec<_>>();
        let expect = |range: std::ops::Range<usize>| range.map(|n| format!("log-{n:03}")).collect::<Vec<_>>();

        // The first piece of news is the first 256, in order.
        let first = news_for(&conn, "nec", None).unwrap();
        assert_eq!(names(&first), expect(0..256));
        // Nothing is settled: those logs are busy, and stay marked. The next piece of news
        // starts after the last one told, takes the rest, and goes round to the beginning.
        let last = first.last().unwrap();
        let second = news_for(&conn, "nec", Some((&last.agent, &last.name))).unwrap();
        assert_eq!(names(&second), [expect(256..300), expect(0..212)].concat());
        // Starting after the very last log is starting from the beginning.
        assert_eq!(names(&news_for(&conn, "nec", Some(("agent", "log-299"))).unwrap()), expect(0..256));
        // Another ship's news is its own.
        assert_eq!(names(&news_for(&conn, "bus", Some(("agent", "log-100"))).unwrap()), expect(0..1));
        // And only what has yet to be told.
        conn.execute("UPDATE log_peers SET due = 0 WHERE peer = 'nec' AND name < 'log-298'", []).unwrap();
        assert_eq!(names(&news_for(&conn, "nec", Some(("agent", "log-298"))).unwrap()), [expect(299..300), expect(298..299)].concat());
    }
}
