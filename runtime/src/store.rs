//! One SQLite file per ship. The file is the ship's source of truth.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};

use ship_proto::Kind;

use crate::{AuditEntry, ChainCheck, Config, Durability, Effect, Error};

const SCHEMA_VERSION: i64 = 4;

/// Each pending message counts as its payload plus this, so empty messages still use up quota.
pub const MESSAGE_OVERHEAD: u64 = 64;

const MAX_INTERFACE_BYTES: usize = 128;

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
    /// `Kind::Command` or `Kind::Notify`, as a number.
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
";

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

/// What an entry counts for against the ship's log quota.
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
    conn.prepare_cached(
        "INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (agent, name) DO UPDATE
         SET head = excluded.head, head_hash = excluded.head_hash, bytes = bytes + excluded.bytes",
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

pub fn log_bytes(conn: &Connection) -> Result<u64, Error> {
    Ok(conn.query_row("SELECT COALESCE(SUM(bytes), 0) FROM logs", [], |r| r.get::<_, i64>(0))? as u64)
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
/// a notification to `agent`, so that the next new entry can notify it again. Leaves no
/// transaction open, whatever happens.
pub fn record_rejection(conn: &Connection, queued: Option<i64>, notice: Option<(&str, &str)>, agent: &str, event: &[u8], keep: u64) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let saved = queued
        .map_or(Ok(()), |seq| inbox_delete(conn, seq))
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
    let _ = record_rejection(conn, None, None, agent, event, keep);
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
    let largest = cfg.limits.max_value_bytes.max(cfg.limits.max_effect_bytes).max(cfg.max_event_bytes);
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

    let mut pending = 0u64;
    // Only commands are carried over. Notifications are worked out again below from where each
    // follower has got to, so they can never disagree with the logs.
    let mut stmt = from.prepare("SELECT seq, source, agent, interface, payload FROM inbox WHERE kind = 1 ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (seq, source, agent, interface) = (integer(row, 0)?, text(row, 1)?, text(row, 2)?, text(row, 3)?);
        check_agent(&source)?;
        check_agent(&agent)?;
        let payload = blob(row, 4, cfg.max_event_bytes)?;
        pending += payload.len() as u64 + MESSAGE_OVERHEAD;
        if seq == 0 || interface.len() > MAX_INTERFACE_BYTES || pending > cfg.max_inbox_bytes {
            return Err(bad_row("queued commands are larger than this runtime allows"));
        }
        to.execute(
            "INSERT INTO inbox VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![seq, Kind::Command as i32, source, agent, interface, payload],
        )?;
    }

    // Logs. Every entry must be signed by this ship's key and follow on from the one before it,
    // and each log's summary row is rebuilt from its entries rather than copied.
    let (mut heads, mut total) = (HashMap::new(), 0u64);
    let mut open: Option<(ChainCheck, u64, [u8; 32], u64)> = None;
    let close = |finished: Option<(ChainCheck, u64, [u8; 32], u64)>, heads: &mut HashMap<(String, String), u64>| -> Result<(), Error> {
        if let Some((chain, head, hash, bytes)) = finished {
            to.execute("INSERT INTO logs VALUES (?1, ?2, ?3, ?4, ?5)", params![chain.agent, chain.log, head as i64, &hash[..], bytes as i64])?;
            heads.insert((chain.agent, chain.log), head);
        }
        Ok(())
    };
    let mut stmt = from.prepare("SELECT agent, name, seq, body, signature FROM log_entries ORDER BY agent, name, seq")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, seq) = (text(row, 0)?, text(row, 1)?, integer(row, 2)? as u64);
        let (body, signature) = (blob(row, 3, cfg.max_event_bytes + (4 << 10))?, blob(row, 4, 64)?);
        if open.as_ref().is_none_or(|(chain, ..)| chain.agent != agent || chain.log != log) {
            close(open.take(), &mut heads)?;
            check_agent(&agent)?;
            if log.len() > MAX_INTERFACE_BYTES || seq != 1 {
                return Err(bad_row("a log does not start at its first entry"));
            }
            open = Some((ChainCheck::new(key, name, &agent, &log, None), 0, [0; 32], 0));
        }
        let (chain, head, hash, bytes) = open.as_mut().expect("opened above");
        let (accepted, accepted_hash, payload_len) = chain.accept(&body, &signature).map_err(|why| bad_row(&why))?;
        total += entry_cost(body.len());
        if accepted != seq || payload_len > cfg.max_event_bytes || total > cfg.max_log_bytes {
            return Err(bad_row("logs are numbered wrongly or larger than this runtime allows"));
        }
        (*head, *hash, *bytes) = (accepted, accepted_hash, *bytes + entry_cost(body.len()));
        to.execute("INSERT INTO log_entries VALUES (?1, ?2, ?3, ?4, ?5)", params![agent, log, seq as i64, body, signature])?;
    }
    close(open.take(), &mut heads)?;

    // The source's own record of where each log ends must agree with the entries that are
    // actually there. Otherwise a file with its newest entries removed would be accepted, and
    // the ship would go on to reuse their numbers.
    let mut claimed = HashSet::new();
    let mut stmt = from.prepare("SELECT agent, name, head, head_hash FROM logs")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (agent, log, head, hash) = (text(row, 0)?, text(row, 1)?, integer(row, 2)? as u64, blob(row, 3, 32)?);
        let rebuilt: Option<Vec<u8>> = to
            .query_row("SELECT head_hash FROM logs WHERE agent = ?1 AND name = ?2 AND head = ?3", params![agent, log, head as i64], |r| r.get(0))
            .optional()?;
        // A damaged file can list one log twice, so each must be seen once and only once.
        if rebuilt != Some(hash) || !claimed.insert((agent, log)) {
            return Err(bad_row("a log's entries do not reach where the log says it ends"));
        }
    }
    if claimed.len() != heads.len() || !heads.keys().all(|log| claimed.contains(log)) {
        return Err(bad_row("there are log entries for a log the file does not list"));
    }

    let mut behind = Vec::new();
    let mut following: HashMap<String, usize> = HashMap::new();
    let mut stmt = from.prepare("SELECT follower, agent, name, cursor FROM follows")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        in_time()?;
        let (follower, agent, log, cursor) = (text(row, 0)?, text(row, 1)?, text(row, 2)?, integer(row, 3)? as u64);
        check_agent(&follower)?;
        check_agent(&agent)?;
        let head = heads.get(&(agent.clone(), log.clone())).copied().unwrap_or(0);
        let count = following.entry(follower.clone()).or_default();
        *count += 1;
        if log.len() > MAX_INTERFACE_BYTES || cursor > head || *count > MAX_FOLLOWS {
            return Err(bad_row("a follower is ahead of the log it follows, or follows too many"));
        }
        to.execute("INSERT INTO follows VALUES (?1, ?2, ?3, ?4, 0, 0)", params![follower, agent, log, cursor as i64])?;
        if cursor < head {
            behind.push((follower, agent, log));
        }
    }
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

    // Carry the counters across so sequence numbers are never reused after an import. `integer`
    // bounds them, so a source cannot hand over a counter that is already exhausted.
    let mut counters = [("outbox", None), ("inbox", None), ("audit", None)];
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
