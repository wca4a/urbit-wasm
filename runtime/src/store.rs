//! One SQLite file per ship. The file is the ship's source of truth.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};

use crate::{AuditEntry, Config, Durability, Effect, Error};

const SCHEMA_VERSION: i64 = 2;

/// Each pending message counts as its payload plus this, so empty messages still use up quota.
pub const MESSAGE_OVERHEAD: u64 = 64;

const MAX_INTERFACE_BYTES: usize = 128;

/// A command one agent sent another, waiting to run as its own event.
pub struct Queued {
    pub seq: i64,
    pub source: String,
    pub agent: String,
    pub interface: String,
    pub payload: Vec<u8>,
}

impl Queued {
    pub fn cost(&self) -> u64 {
        self.payload.len() as u64 + MESSAGE_OVERHEAD
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
    source TEXT NOT NULL,
    agent TEXT NOT NULL,
    interface TEXT NOT NULL,
    payload BLOB NOT NULL
);
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

pub fn inbox_push(conn: &Connection, source: &str, agent: &str, interface: &str, payload: &[u8]) -> rusqlite::Result<()> {
    conn.prepare_cached("INSERT INTO inbox (source, agent, interface, payload) VALUES (?1, ?2, ?3, ?4)")?
        .execute(params![source, agent, interface, payload])
        .map(drop)
}

/// Remove and return the oldest queued command. Call inside the transaction that will run it,
/// so that taking it and its effects land together.
pub fn inbox_pop(conn: &Connection) -> rusqlite::Result<Option<Queued>> {
    let oldest = conn
        .prepare_cached("SELECT seq, source, agent, interface, payload FROM inbox ORDER BY seq LIMIT 1")?
        .query_row([], |r| {
            Ok(Queued { seq: r.get(0)?, source: r.get(1)?, agent: r.get(2)?, interface: r.get(3)?, payload: r.get(4)? })
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
    Ok(conn.query_row("SELECT COALESCE(SUM(LENGTH(payload) + ?1), 0) FROM inbox", [MESSAGE_OVERHEAD as i64], |r| r.get::<_, i64>(0))? as u64)
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

/// Record a rejected input in a transaction of its own and, when it was a queued command, take
/// it off the queue in that same transaction. Leaves no transaction open, whatever happens.
pub fn record_rejection(conn: &Connection, queued: Option<i64>, agent: &str, event: &[u8], keep: u64) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let saved = queued
        .map_or(Ok(()), |seq| inbox_delete(conn, seq))
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
    let _ = record_rejection(conn, None, agent, event, keep);
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
    let mut stmt = from.prepare("SELECT seq, source, agent, interface, payload FROM inbox ORDER BY seq")?;
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
        to.execute("INSERT INTO inbox VALUES (?1, ?2, ?3, ?4, ?5)", params![seq, source, agent, interface, payload])?;
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
