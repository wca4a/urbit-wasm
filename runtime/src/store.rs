//! One SQLite file per ship. The file is the ship's source of truth.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};

use ship_proto::{CheckpointBody, Device, Kind, Message};

use crate::{signed_bytes, AuditEntry, ChainCheck, Config, Durability, Effect, Error, CHECKPOINT_DOMAIN};

const SCHEMA_VERSION: i64 = 6;

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
}

impl Queued {
    /// What this takes of the inbox quota. Only commands count; see `MAX_FOLLOWS`.
    pub fn cost(&self) -> u64 {
        if self.kind == Kind::Command as i32 { self.payload.len() as u64 + MESSAGE_OVERHEAD } else { 0 }
    }
}

/// Far below the point where SQLite refuses to hand out another AUTOINCREMENT value.
const MAX_SEQ: i64 = 1 << 62;

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
    payload BLOB NOT NULL
);
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
    agent TEXT NOT NULL,
    name TEXT NOT NULL,
    cursor INTEGER NOT NULL,
    notified INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (follower, agent, name)
) WITHOUT ROWID;
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
pub fn create(path: &Path, name: &str, kernel: &str, max_bytes: u64) -> Result<(), Error> {
    // create_new makes "does this ship already exist" atomic.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Error::ShipExists(name.to_string()))
        }
        Err(e) => return Err(e.into()),
    }
    let conn = open(path, Durability::Full, max_bytes)?;
    // Not WAL while the file is being built: a commit must put the data in the file itself,
    // because only that file is published.
    let mode: String = conn.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))?;
    if mode != "delete" {
        return Err(Error::BadShipFile(format!("{name}: could not prepare a new ship file")));
    }
    conn.execute_batch("BEGIN")?;
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT INTO meta VALUES ('schema', ?1), ('name', ?2), ('kernel', ?3)",
        params![SCHEMA_VERSION, name, kernel],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(())
}

pub fn open(path: &Path, durability: Durability, max_bytes: u64) -> Result<Connection, Error> {
    // NO_MUTEX: the runtime guarantees one thread at a time per ship.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    // The ship's storage limit. A write that would grow the file past it fails as "full".
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
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
pub fn open_read_only(path: &Path) -> Result<Connection, Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(conn)
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

/// Remove and return the oldest queued command. Call inside the transaction that will run it,
/// so that taking it and its effects land together.
pub fn inbox_pop(conn: &Connection) -> rusqlite::Result<Option<Queued>> {
    let oldest = conn
        .prepare_cached("SELECT seq, kind, source, agent, interface, payload FROM inbox ORDER BY seq LIMIT 1")?
        .query_row([], |r| {
            Ok(Queued {
                seq: r.get(0)?,
                kind: r.get(1)?,
                source: r.get(2)?,
                agent: r.get(3)?,
                interface: r.get(4)?,
                payload: r.get(5)?,
            })
        })
        .optional()?;
    if let Some(queued) = &oldest {
        inbox_delete(conn, queued.seq)?;
    }
    Ok(oldest)
}

pub fn inbox_delete(conn: &Connection, seq: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("DELETE FROM inbox WHERE seq = ?1")?.execute([seq]).map(drop)
}

pub fn inbox_bytes(conn: &Connection) -> Result<u64, Error> {
    let commands = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(payload) + ?1), 0) FROM inbox WHERE kind = ?2",
        params![MESSAGE_OVERHEAD as i64, Kind::Command as i32],
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
    // (the publisher has said this log must never be trimmed).
    conn.prepare_cached(
        "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5, 0, ?5, 0, 0) ON CONFLICT (agent, name) DO UPDATE
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

/// Record that `follower` follows a log, starting before its first entry. Returns false if it
/// already did.
pub fn follow(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<bool> {
    conn.prepare_cached("INSERT OR IGNORE INTO follows VALUES (?1, ?2, ?3, 0, 0, 0)")?
        .execute(params![follower, agent, name])
        .map(|added| added == 1)
}

pub fn follow_count(conn: &Connection, follower: &str) -> rusqlite::Result<usize> {
    conn.prepare_cached("SELECT COUNT(*) FROM follows WHERE follower = ?1")?
        .query_row([follower], |r| r.get::<_, i64>(0))
        .map(|count| count as usize)
}

/// The number of the last entry `follower` has taken from a log, if it follows that log.
pub fn cursor(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<Option<u64>> {
    conn.prepare_cached("SELECT cursor FROM follows WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .query_row(params![follower, agent, name], |r| r.get::<_, i64>(0))
        .optional()
        .map(|cursor| cursor.map(|seq| seq as u64))
}

pub fn set_cursor(conn: &Connection, follower: &str, agent: &str, name: &str, cursor: u64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET cursor = ?4 WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .execute(params![follower, agent, name, cursor as i64])
        .map(drop)
}

/// Queue a notification for one follower, unless one is already waiting. At most one is ever
/// queued per follower and log, however many entries arrive and whatever the follower's own
/// handler does; that bound is why notifications need no room in the command queue.
pub fn notify(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<()> {
    let marked = conn
        .prepare_cached("UPDATE follows SET notified = 1 WHERE follower = ?1 AND agent = ?2 AND name = ?3 AND notified = 0")?
        .execute(params![follower, agent, name])?;
    if marked == 1 {
        inbox_push(conn, Kind::Notify, agent, follower, name, &[])?;
    }
    Ok(())
}

/// How many events are waiting to run on this ship.
pub fn inbox_len(conn: &Connection) -> Result<usize, Error> {
    Ok(conn.query_row("SELECT COUNT(*) FROM inbox", [], |r| r.get::<_, i64>(0))? as usize)
}

/// Notify every follower of a log that has no notification waiting. Returns how many.
pub fn notify_followers(conn: &Connection, agent: &str, name: &str) -> rusqlite::Result<u32> {
    let followers: Vec<String> = conn
        .prepare_cached("SELECT follower FROM follows WHERE agent = ?1 AND name = ?2 AND notified = 0")?
        .query_map(params![agent, name], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    // A new entry starts a follower off afresh, including one that had been given up on.
    conn.prepare_cached("UPDATE follows SET failures = 0 WHERE agent = ?1 AND name = ?2 AND notified = 0")?
        .execute(params![agent, name])?;
    for follower in &followers {
        notify(conn, follower, agent, name)?;
    }
    Ok(followers.len() as u32)
}

/// A follower's notification has been taken off the queue, so the next new entry may queue another.
pub fn clear_notified(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET notified = 0 WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .execute(params![follower, agent, name])
        .map(drop)
}

/// A follower's notify handler failed. Its position has not moved, so it is still behind. Try it
/// again a few times, in case the cause was passing, and then stop: an entry it can never
/// handle must not be retried for ever.
pub fn notify_failed(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET failures = failures + 1 WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .execute(params![follower, agent, name])?;
    let failures = conn
        .prepare_cached("SELECT failures FROM follows WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .query_row(params![follower, agent, name], |r| r.get::<_, i64>(0))
        .optional()?;
    if failures.is_some_and(|failures| failures < MAX_NOTIFY_FAILURES) {
        notify(conn, follower, agent, name)?;
    }
    Ok(())
}

/// A follower's notify handler has finished without error. `before` is where it had got to
/// when the handler started. If it is still behind and took nothing, prompting it again would
/// go round for ever, so that counts as a failed round. Otherwise it is started off afresh.
pub fn notify_handled(conn: &Connection, follower: &str, agent: &str, name: &str, before: Option<u64>) -> rusqlite::Result<()> {
    let (head, _) = log_head(conn, agent, name)?;
    match cursor(conn, follower, agent, name)? {
        Some(now) if now < head && Some(now) == before => notify_failed(conn, follower, agent, name),
        _ => resume(conn, follower, agent, name),
    }
}

/// Start a follower off afresh: forget its past failures and prompt it if it is behind.
pub fn resume(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE follows SET failures = 0 WHERE follower = ?1 AND agent = ?2 AND name = ?3")?
        .execute(params![follower, agent, name])?;
    renotify_if_behind(conn, follower, agent, name).map(drop)
}

/// After a follower has handled a notification: if entries remain that it has not taken and
/// nothing is queued, queue another. Returns whether it did.
pub fn renotify_if_behind(conn: &Connection, follower: &str, agent: &str, name: &str) -> rusqlite::Result<bool> {
    let behind = conn
        .prepare_cached(
            "SELECT 1 FROM follows f JOIN logs l ON l.agent = f.agent AND l.name = f.name
             WHERE f.follower = ?1 AND f.agent = ?2 AND f.name = ?3 AND f.notified = 0 AND f.cursor < l.head",
        )?
        .query_row(params![follower, agent, name], |_| Ok(()))
        .optional()?
        .is_some();
    if behind {
        notify(conn, follower, agent, name)?;
    }
    Ok(behind)
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
/// queue in that same transaction. `notice` names the log (publisher, name) when the input was
/// a notification to `agent`, so that the next new entry can notify it again; `checkpoint`
/// names the log when it was a checkpoint request to `agent`, so that one can be asked for
/// again; `full` names the log of `agent` that an append found full, so that a checkpoint of
/// it is asked for; `storage_full` says the ship's file itself was full, so that entries its
/// logs no longer need are let go. Leaves no transaction open, whatever happens.
#[allow(clippy::too_many_arguments)]
pub fn record_rejection(
    conn: &Connection,
    queued: Option<i64>,
    notice: Option<(&str, &str)>,
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
        .and_then(|()| checkpoint.map_or(Ok(()), |log| checkpoint_answered(conn, agent, log)))
        .and_then(|()| full.map_or(Ok(()), |log| ask_checkpoint_when_full(conn, agent, log)))
        .and_then(|()| {
            notice.map_or(Ok(()), |(publisher, name)| {
                clear_notified(conn, agent, publisher, name)?;
                notify_failed(conn, agent, publisher, name)
            })
        })
        .and_then(|()| audit(conn, agent, event, false, keep))
        .and_then(|()| conn.execute_batch("COMMIT"));
    if saved.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    saved
}

/// Record a rejected input that never reached a handler. Best effort: the caller's rejection
/// is the result that matters, so a failure to log it is not reported.
pub fn audit_failure(conn: &Connection, agent: &str, event: &[u8], keep: u64) {
    let _ = record_rejection(conn, None, None, None, None, false, agent, event, keep);
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
pub fn snapshot_into(conn: &Connection, dest: &Path) -> Result<(), Error> {
    let dest = dest.to_str().ok_or_else(|| Error::BadShipFile("export path is not UTF-8".into()))?;
    conn.execute("VACUUM INTO ?1", [dest])?;
    Ok(())
}

fn schema_objects(conn: &Connection, limit: usize) -> Result<BTreeSet<(String, String, Option<String>)>, Error> {
    let mut stmt = conn.prepare("SELECT type, name, sql FROM sqlite_master LIMIT ?1")?;
    let rows = stmt.query_map([limit.min(i64::MAX as usize) as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// True if the file's first page is a single b-tree leaf holding exactly `entries` schema rows.
fn schema_page_has(path: &Path, entries: usize) -> Result<bool, Error> {
    let mut header = [0u8; 108];
    if std::fs::File::open(path)?.read_exact(&mut header).is_err() {
        return Ok(false);
    }
    const TABLE_LEAF: u8 = 0x0d;
    let cells = u16::from_be_bytes([header[103], header[104]]) as usize;
    Ok(header.starts_with(b"SQLite format 3\0") && header[100] == TABLE_LEAF && cells == entries)
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

fn bad_row(why: &str) -> Error {
    Error::BadShipFile(format!("import: {why}"))
}

/// Copy a ship file from an untrusted source into a freshly created file at `dest`.
///
/// The source must have exactly this runtime's schema, so it cannot carry triggers or views, and
/// every row is re-validated on the way across. Returns the hash of the ship's kernel module.
pub fn import(
    src: &Path,
    dest: &Path,
    name: &str,
    cfg: &Config,
    deadline: Instant,
    key: &VerifyingKey,
    check_agent: fn(&str) -> Result<(), Error>,
    check_hash: fn(&str) -> Result<(), Error>,
) -> Result<String, Error> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    let expected = schema_objects(&reference, usize::MAX)?;
    // SQLite parses a file's whole schema before any query can limit it, so count the schema
    // entries straight from the file first. A schema as small as ours always fits on page one.
    if !schema_page_has(src, expected.len())? {
        return Err(bad_row("schema does not match this runtime's"));
    }

    // Limits go on before the first statement, because that is when SQLite reads and parses the
    // source's schema. They make it refuse oversized values and SQL instead of loading them.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let from = Connection::open_with_flags(src, flags).map_err(|_| bad_row("not a ship file"))?;
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

    create(dest, name, &kernel_hash, cfg.max_ship_bytes)?;
    let to = open(dest, Durability::Full, cfg.max_ship_bytes)?;
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
            "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, 0, ?6)",
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
            "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
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

    let mut behind = Vec::new();
    let mut following: HashMap<String, usize> = HashMap::new();
    let mut follows: HashMap<(String, String, String), bool> = HashMap::new();
    let mut stmt = from.prepare("SELECT follower, agent, name, cursor FROM follows")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (follower, agent, log, cursor) = (text(row, 0)?, text(row, 1)?, text(row, 2)?, integer(row, 3)? as u64);
        check_agent(&follower)?;
        check_agent(&agent)?;
        let head = heads.get(&(agent.clone(), log.clone())).map_or(0, |(head, _)| *head);
        let count = following.entry(follower.clone()).or_default();
        *count += 1;
        if !interface_ok(&log) || cursor > head || *count > MAX_FOLLOWS {
            return Err(bad_row("a follower is ahead of the log it follows, or follows too many"));
        }
        to.execute("INSERT INTO follows VALUES (?1, ?2, ?3, ?4, 0, 0)", params![follower, agent, log, cursor as i64])?;
        if cursor < head {
            behind.push((follower.clone(), agent.clone(), log.clone()));
        }
        follows.insert((follower, agent, log), false);
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
    let mut stmt = from.prepare("SELECT seq, kind, source, agent, interface, payload FROM inbox ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, kind) = (integer(row, 0)?, integer(row, 1)?);
        let (source, agent, interface) = (text(row, 2)?, text(row, 3)?, text(row, 4)?);
        check_agent(&source)?;
        check_agent(&agent)?;
        if seq == 0 || !interface_ok(&interface) {
            return Err(bad_row("a queued event is numbered or named wrongly"));
        }
        let payload = if kind == Kind::Command as i64 {
            let payload = blob(row, 5, cfg.max_event_bytes)?;
            pending += payload.len() as u64 + MESSAGE_OVERHEAD;
            if pending > cfg.max_inbox_bytes {
                return Err(bad_row("queued commands are larger than this runtime allows"));
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
            match follows.get_mut(&(agent.clone(), source.clone(), interface.clone())) {
                Some(told @ false) => *told = true,
                _ => return Err(bad_row("a queued notification is not one this ship would have made")),
            }
            to.execute(
                "UPDATE follows SET notified = 1 WHERE follower = ?1 AND agent = ?2 AND name = ?3",
                params![agent, source, interface],
            )?;
            Vec::new()
        } else {
            return Err(bad_row("a queued event is of a kind this runtime does not know"));
        };
        to.execute("INSERT INTO inbox VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![seq, kind, source, agent, interface, payload])?;
    }
    // A follower that is behind and has no notification waiting had been given up on after
    // repeated failures. An import starts it off afresh, behind everything already queued.
    for (follower, agent, log) in &behind {
        in_time()?;
        notify(&to, follower, agent, log)?;
    }

    let mut stmt = from.prepare("SELECT seq, at_ms, agent, event, ok FROM audit ORDER BY seq DESC LIMIT ?1")?;
    let mut rows = stmt.query([cfg.audit_rows as i64])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, at_ms, agent) = (integer(row, 0)?, integer(row, 1)?, text(row, 2)?);
        check_agent(&agent)?;
        let event = blob(row, 3, cfg.max_event_bytes)?;
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
