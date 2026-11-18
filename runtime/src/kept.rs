//! Files on the ship, part 3: what was opened from another ship is kept for a while, and the
//! owner can save a copy for good.
//!
//! A kept file is a file of another ship's that this ship holds some or all of, known by its
//! id. It is kept only once its length and every chunk hash have been checked against the id
//! (`crate::remote`), and only if it has at most `FANOUT` chunks, so those hashes are one
//! group. From then on its hashes are this ship's own rows (`kept_chunks`), and each piece held
//! is read back from disk and checked against its hash every time, as every chunk of a file of
//! the ship's own is. A piece that does not open or does not match is given up (its row no
//! longer names it and its bytes go to the trash) and fetched again as if it had never been
//! held. A kept file is never served to another ship and no agent sees it.
//!
//! A kept file is in the cache (no agent saving it), counted against `max_cache_bytes` and
//! thrown away at any time, least recently opened first; or being saved (some agent saving it),
//! its whole length reserved against `max_file_bytes`, until every piece is held and it becomes
//! a file of the ship's, claimed by every agent that saved it, under the same directory and with
//! no byte moved.
//!
//! The rule at the top of `files.rs` holds here with no special case: a piece is put on disk by
//! the same code as an upload's chunk (`Runtime::prepare_copy` and `PreparedChunk`), under the
//! kept file's directory, which is never reused; what is thrown away is recorded in the same
//! trash, in a synced transaction, and removed by the same drain once that is durable. Keeping
//! is best effort and never makes opening worse: whatever stops a piece being kept, the checked
//! piece is passed on as it would have been without a cache.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::files::{self, chunk_count, chunk_len, fail, keeping_room, rows_cost, seams, FileError, Holder, FANOUT};
use crate::remote::{Ask, Failed, Remote};
use crate::ship::room_to_take_one;
use crate::store::{self, KeptFile, Pool};
use crate::{canonical_ship, check_agent_name, lock, random_bytes, Config, Error, Inner, Runtime};

/// A kept file's last-opened time is written at most this often, so that reading is not a
/// write per request.
pub(crate) const TOUCH_EVERY_MS: u64 = 60_000;
/// The most rows one request throws away under the ship's slot, counting each kept file's chunk
/// rows and its own row: two whole kept files of `FANOUT` chunks.
pub(crate) const THROW_ROWS: u64 = 2 * (FANOUT as u64 + 1);
/// The most kept files one request throws away under the ship's slot.
pub(crate) const THROW_FILES: u64 = 64;
/// The most saves not touched for too long that one sweep looks at.
pub(crate) const SAVES_SWEPT: usize = 64;
/// The most kept files one page of the listing gives, and one page of clearing every one.
pub const MAX_KEPT_LISTED: usize = 256;
/// How many batches of the trash are drained after throwing away, at most.
const DRAIN_ROUNDS: usize = 72;
/// The most copies this runtime may make in one kept file's directory that it can neither name
/// nor remove (a commit of unknown outcome, or a removal that failed), in its life. At the cap
/// nothing more is kept into that directory.
pub(crate) const MOST_STRAYS: u32 = 2;
/// The most pieces kept at once after their answer was sent, in a runtime. Taken without
/// waiting: with none free, the piece is not kept.
pub(crate) const MOST_KEEPING_AFTER: usize = 2;

/// What one request may throw away under the ship's slot (`THROW_FILES`, `THROW_ROWS`), shared
/// by everything it throws away: saves that ran out, the sweep of the cache, room made for
/// bytes, for rows and in the count, and its own target. What does not fit waits for a later
/// request. A request can keep back room to throw away a file of its own (`keeping_back`), which
/// nothing else it throws away may use. It also holds the directories thrown away, so that their
/// records are retired once the transaction that threw them away is known to have landed.
#[derive(Default, Debug)]
pub(crate) struct Budget {
    rows: u64,
    files: u64,
    /// Kept back for one file of this many chunks, until `throw_own` uses it.
    kept_back: Option<u64>,
    thrown: Vec<[u8; 16]>,
}

impl Budget {
    /// A budget that keeps back room to throw away one kept file of up to `chunks` chunks.
    pub(crate) fn keeping_back(chunks: u64) -> Budget {
        Budget { kept_back: Some(chunks), ..Budget::default() }
    }

    /// Whether a kept file of `chunks` chunks may still be thrown away, keeping back enough to
    /// throw away one of `keep_back` chunks after it, and what the budget keeps back already.
    fn fits(&self, chunks: u64, keep_back: Option<u64>) -> bool {
        let back = [keep_back, self.kept_back].into_iter().flatten().fold((0, 0), |(rows, files), chunks| (rows + chunks + 1, files + 1));
        self.files + 1 + back.1 <= THROW_FILES && self.rows + chunks + 1 + back.0 <= THROW_ROWS
    }

    /// Throw away the kept file `id` on `ship`, counted against `pool`, if the budget allows:
    /// its rows, and its directory recorded in the trash at its held bytes plus 1 MiB for each
    /// stray and each copy on its way into it now (`Inner::charge_of`). Whether it was thrown
    /// away.
    fn throw(&mut self, inner: &Inner, ship: &str, conn: &Connection, id: &[u8; 32], pool: Pool, keep_back: Option<u64>) -> Result<bool, Error> {
        let Some(kept) = store::kept_get(conn, id)? else { return Ok(false) };
        let chunks = chunk_count(kept.length);
        if !self.fits(chunks, keep_back) {
            return Ok(false);
        }
        store::kept_throw(conn, id, pool, inner.charge_of(ship, &kept.dir))?;
        self.rows += chunks + 1;
        self.files += 1;
        self.thrown.push(kept.dir);
        Ok(true)
    }

    /// Throw away the request's own target, using the room kept back for it.
    fn throw_own(&mut self, inner: &Inner, ship: &str, conn: &Connection, id: &[u8; 32], pool: Pool) -> Result<bool, Error> {
        let kept_back = self.kept_back.take();
        let thrown = self.throw(inner, ship, conn, id, pool, None)?;
        if !thrown {
            self.kept_back = kept_back;
        }
        Ok(thrown)
    }
}

/// What this runtime knows, in memory, of one kept file's directory it has kept into.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirRecord {
    /// Looked through for what a crash left (`Inner::look`), once in this runtime's life,
    /// whatever came of it.
    pub looked: bool,
    /// Copies made here that could be neither named nor removed.
    pub strays: u32,
    /// Copies on their way: made, or about to be, and not yet named or removed.
    pub on_way: u32,
    /// The directory was thrown away, or became a file's, while copies were on their way: the
    /// record goes when the last of them ends, and counts no more strays meanwhile.
    pub retired: bool,
}

/// The records of kept directories, and where each ship's prune carries on from.
#[derive(Default)]
pub(crate) struct KeptDirs {
    records: BTreeMap<(String, [u8; 16]), DirRecord>,
    prune_after: HashMap<String, [u8; 16]>,
}

/// The most records one sweep looks at to drop those whose directory has gone.
pub(crate) const PRUNE_LOOKED: usize = 64;

/// A copy on its way into a kept directory, counted in its record from under the ship's slot
/// until it ends, exactly once: named by a commit known to have landed, removed, or become a
/// stray (an unknown commit, or a removal that failed). Ending it by dropping is "removed".
pub(crate) struct CopySlot {
    inner: Arc<Inner>,
    ship: String,
    dir: [u8; 16],
    ended: bool,
}

impl CopySlot {
    /// End the copy: `stray` if it could be neither named nor removed.
    pub(crate) fn end(&mut self, stray: bool) {
        if std::mem::replace(&mut self.ended, true) {
            return;
        }
        let mut dirs = lock(&self.inner.kept_dirs);
        let key = (self.ship.clone(), self.dir);
        let Some(record) = dirs.records.get_mut(&key) else { return };
        record.on_way = record.on_way.saturating_sub(1);
        if stray && !record.retired {
            record.strays += 1;
        }
        if record.retired && record.on_way == 0 {
            dirs.records.remove(&key);
        }
    }
}

impl Drop for CopySlot {
    fn drop(&mut self) {
        self.end(false);
    }
}

/// What a request does before its first question to another ship: take what waiting on another
/// ship holds (the server's places). Called before every question; takes once.
pub(crate) trait Gate {
    fn take(&mut self) -> Result<(), Failed>;
    /// Give back whatever was taken.
    fn release(&mut self);
}

/// A gate that takes nothing, for tests that call the runtime directly.
#[cfg(test)]
pub(crate) struct Ungated;

#[cfg(test)]
impl Gate for Ungated {
    fn take(&mut self) -> Result<(), Failed> {
        Ok(())
    }

    fn release(&mut self) {}
}

type SharedGate<'a> = Rc<RefCell<Box<dyn Gate + 'a>>>;

/// `ask`, with `gate` taken before each question.
fn gated<'a>(mut ask: Ask<'a>, gate: SharedGate<'a>) -> Ask<'a> {
    Box::new(move |body| {
        gate.borrow_mut().take()?;
        ask(body)
    })
}

/// One of the `MOST_KEEPING_AFTER` places for keeping a piece after its answer.
pub(crate) struct KeepingAfter<'a>(&'a AtomicUsize);

impl Drop for KeepingAfter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Inner {
    /// The record of the kept directory `dir` of `ship`, if there is one.
    pub(crate) fn dir_record(&self, ship: &str, dir: &[u8; 16]) -> Option<DirRecord> {
        lock(&self.kept_dirs).records.get(&(ship.to_string(), *dir)).copied()
    }

    /// Under the ship's slot, before a copy is made in the kept directory `dir`: count one more
    /// on its way, unless strays and copies on their way are `MOST_STRAYS` already (`Unsettled`)
    /// or the directory is retired. Whether the directory is to be looked through now: the first
    /// copy of this life there, marked looked here, before the look, whatever comes of it.
    pub(crate) fn reserve_copy(self: &Arc<Self>, ship: &str, dir: &[u8; 16]) -> Result<(CopySlot, bool), FileError> {
        let mut dirs = lock(&self.kept_dirs);
        let record = dirs.records.entry((ship.to_string(), *dir)).or_default();
        if record.retired {
            return Err(FileError::NotFound);
        }
        if record.strays + record.on_way >= MOST_STRAYS {
            return Err(FileError::Unsettled);
        }
        record.on_way += 1;
        let look = !std::mem::replace(&mut record.looked, true);
        Ok((CopySlot { inner: self.clone(), ship: ship.to_string(), dir: *dir, ended: false }, look))
    }

    /// The kept directories of `ship` with strays.
    pub(crate) fn strays_in(&self, ship: &str) -> HashSet<[u8; 16]> {
        lock(&self.kept_dirs).records.range(Self::ship_range(ship)).filter(|(_, record)| record.strays > 0 && !record.retired).map(|((_, dir), _)| *dir).collect()
    }

    /// The keys of `ship`'s records, from the first to the last.
    fn ship_range(ship: &str) -> std::ops::RangeInclusive<(String, [u8; 16])> {
        (ship.to_string(), [0; 16])..=(ship.to_string(), [0xff; 16])
    }

    /// What a kept directory is charged beyond its held bytes when it is thrown away: 1 MiB for
    /// each stray and each copy on its way into it now.
    pub(crate) fn charge_of(&self, ship: &str, dir: &[u8; 16]) -> u64 {
        lock(&self.kept_dirs).records.get(&(ship.to_string(), *dir)).filter(|record| !record.retired).map_or(0, |record| u64::from(record.strays + record.on_way) * files::CHUNK)
    }

    /// The transaction that threw away the kept directory `dir`, or made it a file's, has
    /// landed: its record goes, or, with copies still on their way, is retired and goes when
    /// the last of them ends.
    fn retire(&self, ship: &str, dir: &[u8; 16]) {
        let mut dirs = lock(&self.kept_dirs);
        let key = (ship.to_string(), *dir);
        match dirs.records.get_mut(&key) {
            Some(record) if record.on_way == 0 => {
                dirs.records.remove(&key);
            }
            Some(record) => record.retired = true,
            None => {}
        }
    }

    /// After the transaction that threw them away is known to have landed: retire the
    /// directories in `budget`.
    pub(crate) fn retire_thrown(&self, ship: &str, budget: &mut Budget) {
        for dir in std::mem::take(&mut budget.thrown) {
            self.retire(ship, &dir);
        }
    }

    /// Under the ship's slot (in the sweep): drop the records of `ship` whose directory no
    /// `kept` row names and that have nothing on their way (a throwing away that landed and
    /// reported an error leaves such a record). At most `PRUNE_LOOKED` records are looked at,
    /// carrying on from where the last prune of this ship stopped. They are taken under
    /// `kept_dirs`, which is then let go while the rows are read, and taken again to drop those
    /// that still have nothing on their way. (A `kept` row for a directory cannot appear after it
    /// was seen absent: directories are never reused.)
    pub(crate) fn prune(&self, ship: &str, conn: &Connection) -> Result<(), Error> {
        let keys = self.prune_candidates(ship);
        let mut gone = Vec::new();
        for (dir, record) in &keys {
            if record.on_way == 0 && store::kept_in_dir(conn, dir)?.is_none() {
                gone.push(*dir);
            }
        }
        let mut dirs = lock(&self.kept_dirs);
        for dir in gone {
            let key = (ship.to_string(), dir);
            if dirs.records.get(&key).is_some_and(|record| record.on_way == 0) {
                dirs.records.remove(&key);
            }
        }
        match keys.last() {
            Some((dir, _)) => {
                dirs.prune_after.insert(ship.to_string(), *dir);
            }
            None => {
                dirs.prune_after.remove(ship);
            }
        }
        Ok(())
    }

    /// Up to `PRUNE_LOOKED` of `ship`'s records, from where the last prune stopped, wrapping
    /// round to the first.
    fn prune_candidates(&self, ship: &str) -> Vec<([u8; 16], DirRecord)> {
        let dirs = lock(&self.kept_dirs);
        let after = dirs.prune_after.get(ship).copied();
        let mut keys: Vec<([u8; 16], DirRecord)> = dirs
            .records
            .range((ship.to_string(), after.unwrap_or([0; 16]))..)
            .take_while(|((held, _), _)| held == ship)
            .filter(|((_, dir), _)| after.is_none_or(|after| *dir != after))
            .take(PRUNE_LOOKED)
            .map(|((_, dir), record)| (*dir, *record))
            .collect();
        if keys.len() < PRUNE_LOOKED {
            // Round to the start of this ship's records.
            let more = PRUNE_LOOKED - keys.len();
            let wrapped: Vec<([u8; 16], DirRecord)> = dirs
                .records
                .range((ship.to_string(), [0; 16])..)
                .take_while(|((held, dir), _)| held == ship && after.is_some_and(|after| *dir <= after))
                .take(more)
                .map(|((_, dir), record)| (*dir, *record))
                .collect();
            keys.extend(wrapped);
        }
        keys
    }

    /// Under the ship's slot, the first time in this runtime's life that a copy is about to be
    /// made in the kept directory `dir` (its record already marked looked, by `reserve_copy`,
    /// before this runs, whatever comes of it): remove every entry there that no `kept_chunks`
    /// row names by its exact generation and the trash does not record. What is removed can only
    /// be what a crash or an earlier life left. The look precedes every copy this life makes in
    /// that directory, all of them made under the slot after it; a second look would not, and
    /// could remove a copy made and not yet named, so there never is one in a life. Any error
    /// reading the rows or listing the directory removes nothing, and what is left stays until
    /// the next life's first copy there, or until the directory goes.
    pub(crate) fn look(&self, ship: &str, dir: &[u8; 16], conn: &Connection) {
        let Ok((named, whole)) = store::kept_dir_names(conn, dir) else { return };
        if whole {
            return;
        }
        let place = self.dir_path(ship, dir);
        let Ok(entries) = fs::read_dir(&place) else { return };
        let Ok(entries) = entries.collect::<Result<Vec<_>, _>>() else { return };
        if seams::hit("look-list") {
            return;
        }
        for entry in entries {
            if !entry.file_name().to_str().is_some_and(|name| named.contains(name)) {
                let _ = files::remove_entry(&entry.path());
            }
        }
    }
}

/// A kept file, as the owner's devices see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptInfo {
    pub id: [u8; 32],
    pub length: u64,
    /// The bytes of its pieces held.
    pub held: u64,
    /// When it was last opened, in milliseconds.
    pub used_ms: u64,
    /// Whether some agent is saving it. A file being saved is never thrown away from the
    /// cache, nor cleared.
    pub saving: bool,
}

/// What a clearing of the cache did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Cleared {
    /// Kept files thrown away: no row names them, and their bytes are in the trash or gone.
    pub thrown_away: u64,
    /// Kept files left alone because some agent is saving them.
    pub being_saved: u64,
}

/// Where a save stands after a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaveState {
    /// The file is one of the ship's own, claimed by the agent.
    pub done: bool,
    /// How many of its chunks the ship holds.
    pub held: u64,
    /// How many chunks it has.
    pub chunks: u64,
}

/// A save in progress, as an agent's devices see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaveInfo {
    pub id: [u8; 32],
    pub length: u64,
    /// The bytes of its pieces held.
    pub held: u64,
    pub chunks: u64,
    /// When the agent's save was last called, in milliseconds.
    pub touched_ms: u64,
}

/// Why a save could not go on: something on this ship, or the other ship.
#[derive(Debug)]
pub(crate) enum SaveFailed {
    Here(Error),
    There(Failed),
}

impl From<Error> for SaveFailed {
    fn from(error: Error) -> SaveFailed {
        SaveFailed::Here(error)
    }
}

/// The room the rows of kept files in the cache may take in the ship's file: a sixteenth of it.
pub(crate) fn cache_rows_allowance(cfg: &Config) -> u64 {
    cfg.max_ship_bytes / 16
}

/// In the open transaction `conn`, within `budget`: saves not touched for `upload_keep_millis`
/// are stopped; and kept files in the cache are thrown away, least recently opened first, while
/// any of these holds of the oldest: it was not opened for `cache_keep_millis`; the cache holds
/// more bytes than `max_cache_bytes`, or more rows than its allowance, or more than `max_kept`
/// files are kept (any of which can be after a setting is lowered). A kept file in the cache
/// whose directory has strays is thrown away too; and records of directories that have gone are
/// dropped (`Inner::prune`). Whatever is thrown away is recorded in the trash, so the transaction
/// must be committed synced, and the trash drained after; and `budget`'s directories retired once
/// it is known to have landed.
pub(crate) fn sweep(inner: &Inner, ship: &str, conn: &Connection, cfg: &Config, now: u64, budget: &mut Budget) -> Result<(), Error> {
    inner.prune(ship, conn)?;
    let strays = inner.strays_in(ship);
    let strays = &strays;
    // A save nobody has called for too long stops as one stopped by its agent does, except
    // that nothing else is thrown away to make room for it: it goes back to the cache if it
    // fits there as the cache is, and is thrown away if not. One that may be thrown away is
    // stopped only if the budget can take it.
    for (agent, id) in store::saves_expired(conn, now.saturating_sub(cfg.upload_keep_millis), SAVES_SWEPT)? {
        let Some(kept) = store::kept_get(conn, &id)? else {
            store::save_remove(conn, &agent, &id)?;
            continue;
        };
        if store::save_agents(conn, &id)?.len() == 1 && !budget.fits(chunk_count(kept.length), None) {
            break;
        }
        store::save_remove(conn, &agent, &id)?;
        settle_unsaved(inner, ship, conn, cfg, &id, budget, strays)?;
    }
    for dir in strays {
        let Some(id) = store::kept_in_dir(conn, dir)? else { continue };
        if store::kept_get(conn, &id)?.is_some_and(|kept| !kept.saving) && !budget.throw(inner, ship, conn, &id, Pool::Cache, None)? {
            break;
        }
    }
    loop {
        let Some((id, _, _, used)) = store::cached_oldest(conn, None, 1)?.pop() else { break };
        let stale = used < now.saturating_sub(cfg.cache_keep_millis);
        let over = store::cache_held(conn)? > cfg.max_cache_bytes
            || store::cache_rows(conn)? > cache_rows_allowance(cfg)
            || store::kept_count(conn)? > cfg.max_kept;
        if !(stale || over) || !budget.throw(inner, ship, conn, &id, Pool::Cache, None)? {
            break;
        }
    }
    Ok(())
}

/// Whether `sweep` has anything to do on `ship` now: a save not touched for too long, a kept file
/// in the cache whose directory has strays, or a least recently opened one that is stale or that
/// the cache is over a setting for. Read under the ship's slot; changes nothing.
fn sweep_due(inner: &Inner, ship: &str, conn: &Connection, cfg: &Config, now: u64) -> Result<bool, Error> {
    if !store::saves_expired(conn, now.saturating_sub(cfg.upload_keep_millis), 1)?.is_empty() {
        return Ok(true);
    }
    for dir in inner.strays_in(ship) {
        let Some(id) = store::kept_in_dir(conn, &dir)? else { continue };
        if store::kept_get(conn, &id)?.is_some_and(|kept| !kept.saving) {
            return Ok(true);
        }
    }
    let Some((_, _, _, used)) = store::cached_oldest(conn, None, 1)?.pop() else { return Ok(false) };
    Ok(used < now.saturating_sub(cfg.cache_keep_millis)
        || store::cache_held(conn)? > cfg.max_cache_bytes
        || store::cache_rows(conn)? > cache_rows_allowance(cfg)
        || store::kept_count(conn)? > cfg.max_kept)
}

/// A request's opening sweep, in a synced transaction of its own, so that what it throws away
/// lands whatever then becomes of the request, and drained after; within `budget`, which the
/// request carries on. Run only if there is something for it to do: a request that throws
/// nothing away makes no synced commit for it (the records of directories that have gone are
/// pruned all the same).
pub(crate) fn sweep_first(inner: &Inner, ship: &str, cfg: &Config, budget: &mut Budget) -> Result<(), Error> {
    let swept = inner.with_ship(ship, |held| {
        let due = {
            let conn = lock(&held.conn);
            let due = sweep_due(inner, ship, &conn, cfg, store::now_ms())?;
            if !due {
                inner.prune(ship, &conn)?;
            }
            due
        };
        if due {
            held.transact_synced(cfg, |conn| sweep(inner, ship, conn, cfg, store::now_ms(), budget))?;
        }
        Ok(due)
    });
    if matches!(swept, Ok(true)) {
        inner.retire_thrown(ship, budget);
    }
    budget.thrown.clear();
    if matches!(swept, Ok(true)) {
        inner.empty_trash_rounds(ship, DRAIN_ROUNDS);
    }
    swept.map(drop)
}

/// In the open transaction `conn`, after a save of `id` was stopped: if no agent is saving it
/// any more, its reservation is returned, and it stays in the cache if it fits there as the
/// cache is (keeping is on, its directory has no strays, and the cache with it is within
/// `max_cache_bytes` and its allowance of rows), and is thrown away if not. Its bytes were
/// counted against the file allowance, and are counted there, in the trash, until they are
/// gone. If it must be thrown away and `budget` cannot take it, nothing is decided: `Unsettled`,
/// and the caller's transaction is not kept.
#[allow(clippy::too_many_arguments)]
fn settle_unsaved(inner: &Inner, ship: &str, conn: &Connection, cfg: &Config, id: &[u8; 32], budget: &mut Budget, strays: &HashSet<[u8; 16]>) -> Result<(), Error> {
    let Some(kept) = store::kept_get(conn, id)? else { return Ok(()) };
    if kept.saving {
        return Ok(());
    }
    let fits = cfg.max_cache_bytes > 0
        && !strays.contains(&kept.dir)
        && store::cache_bytes(conn)? <= cfg.max_cache_bytes
        && store::cache_rows(conn)? <= cache_rows_allowance(cfg);
    if !fits && !budget.throw(inner, ship, conn, id, Pool::Files, None)? {
        return fail(FileError::Unsettled);
    }
    Ok(())
}

/// In the open transaction `conn`: `agent` saves the kept file `id`. If no agent was saving it,
/// its whole length is reserved against the file allowance now, as an upload's is, and it
/// leaves the cache: refused with part 1's answers if the ship may hold no more files, has no
/// room for the length, or has no room in its own file for the rows the file will need.
fn save_begin(conn: &Connection, cfg: &Config, agent: &str, id: &[u8; 32]) -> Result<(), Error> {
    let Some(kept) = store::kept_get(conn, id)? else { return fail(FileError::NotFound) };
    if !kept.saving {
        if store::file_count(conn)?.saturating_add(store::saving_count(conn)?) >= cfg.max_files {
            return Err(Error::TooMany("files"));
        }
        if store::counted_bytes(conn)?.saturating_add(kept.length) > cfg.max_file_bytes {
            return fail(FileError::NoRoom);
        }
        // Room for the file's rows when it is made (BEST EFFORT: checked again then).
        if store::spare_bytes(conn)? < rows_cost(chunk_count(kept.length)).saturating_add(room_to_take_one(cfg)) {
            return fail(FileError::NoRoom);
        }
    }
    keeping_room(conn, cfg, || Ok(store::save_add(conn, agent, id, store::now_ms())?))
}

/// Whether a file of `length` bytes could ever be a file of this ship's, by the rule part 1
/// applies before looking at how full the ship is.
fn too_large(cfg: &Config, length: u64) -> bool {
    length > cfg.max_file_bytes || rows_cost(chunk_count(length)) > cfg.max_ship_bytes / 4
}

/// A file on another ship being opened for this ship's owner, from this ship's own rows and
/// disk where it is kept, and from the other ship where it is not. Made by
/// `Runtime::open_remote`. Every piece it returns has been checked against the hash the id
/// vouches for: read back from disk and checked against its row, or fetched and checked by
/// `Remote`. Nothing is taken through its gate until a question is about to go to the other
/// ship.
pub(crate) struct Opened<'a> {
    rt: &'a Runtime,
    here: String,
    id: [u8; 32],
    length: u64,
    media_type: String,
    /// The kept file this request reads from and keeps into: its directory, which is never
    /// reused, so a piece fetched here is only ever named by this very kept file.
    kept: Option<[u8; 16]>,
    /// The other ship, asked only for what is not held, through `gate`.
    remote: Remote<Ask<'a>>,
    gate: SharedGate<'a>,
    /// What this request may throw away.
    budget: RefCell<Budget>,
}

impl Opened<'_> {
    /// The file's length, checked against its id.
    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    /// The media type, as checked at upload.
    pub(crate) fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Whether this request keeps what it fetches.
    #[cfg(test)]
    pub(crate) fn kept_dir(&self) -> Option<[u8; 16]> {
        self.kept
    }

    /// Chunk `n`, checked, and whether it was fetched from the other ship (and so is one to
    /// keep). A piece held is read from disk and checked against its hash; one that fails is
    /// given up and fetched as if it had never been held.
    pub(crate) fn piece(&mut self, n: u64) -> Result<(Vec<u8>, bool), Failed> {
        let len = chunk_len(self.length, n).ok_or(Failed::Wrong("no such chunk"))?;
        // Read back only against the hash this request checked against the id, whatever a row
        // says.
        if let (Some(dir), Some(leaf)) = (self.kept, self.remote.held_leaf(n)) {
            if let Some(data) = self.rt.kept_read(&self.here, &self.id, &dir, n, len, &leaf, &mut self.budget.borrow_mut()) {
                return Ok((data, false));
            }
        }
        Ok((self.remote.chunk(n)?, true))
    }

    /// Try to keep chunk `n`, fetched and checked by `piece`, in the kept file this request
    /// reads from. Best effort: an error here changes nothing about what was read.
    pub(crate) fn keep(&self, n: u64, data: Vec<u8>) -> Result<(), Error> {
        match self.kept {
            Some(dir) => self.rt.keep_piece_within(&self.here, &self.id, &dir, self.length, n, data, &mut self.budget.borrow_mut()),
            None => Ok(()),
        }
    }

    /// Give back whatever the gate took: the request waits on the other ship no more.
    pub(crate) fn release_places(&self) {
        self.gate.borrow_mut().release();
    }

    /// After the answer carrying chunk `n` has gone: give back the request's places, and keep
    /// the piece if one of the `MOST_KEEPING_AFTER` places for that can be had at once; if not,
    /// it is not kept (`Unsettled`).
    pub(crate) fn keep_after(self, n: u64, data: Vec<u8>) -> Result<(), Error> {
        self.release_places();
        let Some(_keeping) = self.rt.keeping_after() else { return fail(FileError::Unsettled) };
        self.keep(n, data)
    }
}

impl Runtime {
    /// One of the places for keeping a piece after its answer, if one is free now.
    pub(crate) fn keeping_after(&self) -> Option<KeepingAfter<'_>> {
        let count = &self.inner.keeping_after;
        let place = KeepingAfter(count);
        (count.fetch_add(1, Ordering::SeqCst) < MOST_KEEPING_AFTER).then_some(place)
    }

    /// `open_remote_gated` with nothing taken before a question: for tests.
    #[cfg(test)]
    pub(crate) fn open_remote<'a>(&'a self, here: &str, other: &str, agent: &str, id: &[u8; 32]) -> Result<Opened<'a>, Failed> {
        self.open_remote_gated(here, other, agent, id, Box::new(Ungated))
    }

    /// Open the file `id` that `agent` on `other` claims, for the owner of `here`. If `here`
    /// keeps it, its length, media type and hashes come from `here`'s own rows and nothing is
    /// asked of `other` (whatever `other` and `agent` are: what `here` was given, it has). If
    /// not, `other` is asked as part 2 asks, and once its answer has been checked against the
    /// id the file begins to be kept, if keeping is on and there is room for its rows. Anything
    /// that goes wrong with keeping leaves opening as it would have been. `gate` is taken
    /// before the first question to `other`, if there is one.
    pub(crate) fn open_remote_gated<'a>(&'a self, here: &str, other: &str, agent: &str, id: &[u8; 32], gate: Box<dyn Gate + 'a>) -> Result<Opened<'a>, Failed> {
        // The ship's name becomes a directory and goes into the key its pieces are sealed
        // under: only ever as this runtime writes it.
        let Ok(here) = canonical_ship(here) else { return Err(Failed::Wrong("not a ship of this runtime")) };
        let here = here.as_str();
        let gate: SharedGate<'a> = Rc::new(RefCell::new(gate));
        let mut budget = Budget::default();
        let ask = || gated(self.remote_ask(here, other, agent, id), gate.clone());
        if let Some((dir, kept, leaves)) = self.kept_open(here, id, &mut budget) {
            if let Some(remote) = Remote::known(ask(), kept.length, kept.media_type.clone(), leaves) {
                let budget = RefCell::new(budget);
                return Ok(Opened { rt: self, here: here.to_string(), id: *id, length: kept.length, media_type: kept.media_type, kept: Some(dir), remote, gate, budget });
            }
        }
        let remote = Remote::open(ask(), id)?;
        let kept = match remote.leaves() {
            Some(leaves) if self.inner.cfg.max_cache_bytes > 0 => self.begin_keeping_within(here, id, remote.length(), remote.media_type(), leaves, None, &mut budget).ok(),
            _ => None,
        };
        let (length, media_type) = (remote.length(), remote.media_type().to_string());
        Ok(Opened { rt: self, here: here.to_string(), id: *id, length, media_type, kept, remote, gate, budget: RefCell::new(budget) })
    }

    /// The kept file `id` on `here`, if there is one to read from: its directory, its row, and
    /// every chunk hash, checked again against the id. Only then is its last-opened time brought
    /// up to date, if it is a minute old. A file in the cache is not read from while keeping is
    /// off. One in the cache whose rows were read without error and are certainly unusable (not
    /// as many as its length takes, or not coming to its id) is thrown away by the ordinary path;
    /// one being saved is left (its save calls answer `Damaged`). `None` for all of these, and
    /// for anything that goes wrong: the file is then opened as part 2 opens it.
    fn kept_open(&self, here: &str, id: &[u8; 32], budget: &mut Budget) -> Option<([u8; 16], KeptFile, Vec<[u8; 32]>)> {
        let cfg = &self.inner.cfg;
        let read = self.inner.with_ship(here, |held| {
            let conn = lock(&held.conn);
            match store::kept_get(&conn, id)? {
                Some(kept) if kept.saving || cfg.max_cache_bytes > 0 => {
                    let leaves = store::kept_leaves(&conn, &kept.dir, chunk_count(kept.length))?;
                    Ok(Some((kept, leaves)))
                }
                _ => Ok(None),
            }
        });
        let (kept, leaves) = read.ok()??;
        // Checked when it was kept; checked again, so that no row of this ship's file is
        // believed about a file without its id vouching for it.
        match leaves {
            Some(leaves) if files::id_from_leaves(kept.length, &leaves) == Some(*id) => {
                let now = store::now_ms();
                if now >= kept.used.saturating_add(TOUCH_EVERY_MS) {
                    // Best effort, and not synced: losing it loses only when it was opened.
                    let _ = self.inner.with_ship(here, |held| held.transact(|conn| keeping_room(conn, cfg, || Ok(store::kept_touch(conn, id, now)?))));
                }
                Some((kept.dir, kept, leaves))
            }
            _ => {
                if !kept.saving {
                    self.throw_cached(here, id, &kept.dir, budget);
                }
                None
            }
        }
    }

    /// Throw away the kept file `id`, if it is still the one in `dir` and is in the cache, within
    /// `budget`: rows first in a synced transaction, then the trash drained. Best effort.
    fn throw_cached(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], budget: &mut Budget) {
        let cfg = &self.inner.cfg;
        let thrown = self.inner.with_ship(here, |held| {
            Ok(held.transact_synced(cfg, |conn| match store::kept_get(conn, id)? {
                Some(kept) if kept.dir == *dir && !kept.saving => budget.throw(&self.inner, here, conn, id, Pool::Cache, None),
                _ => Ok(false),
            })?)
        });
        if matches!(thrown, Ok(true)) {
            self.inner.retire_thrown(here, budget);
        }
        budget.thrown.clear();
        self.inner.empty_trash_rounds(here, DRAIN_ROUNDS);
    }

    /// Chunk `n` of the kept file `id` in `dir`, `len` bytes, if it is held there, its row's
    /// hash is `leaf`, and it reads back whole and matching it. One held that is certainly bad
    /// (missing, the wrong size, not opening, not matching) is given up, by the rule; and for
    /// it, for one that could not be read, and for one not held, `None` is returned.
    #[allow(clippy::too_many_arguments)]
    fn kept_read(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], n: u64, len: u64, leaf: &[u8; 32], _budget: &mut Budget) -> Option<Vec<u8>> {
        let row = self.inner.with_ship(here, |held| {
            let conn = lock(&held.conn);
            // The very kept file this request opened: the directory is never reused.
            match store::kept_get(&conn, id)? {
                Some(kept) if kept.dir == *dir => Ok(store::kept_piece(&conn, dir, n)?),
                _ => Ok(None),
            }
        });
        let Ok(Some((hash, Some(gen)))) = row else { return None };
        if hash != *leaf {
            return None;
        }
        match self.inner.read_copy(here, dir, n, &gen, len, &hash) {
            files::ReadBack::Good(data) => Some(data),
            // Certainly not the piece: given up, and fetched as if it had never been held.
            files::ReadBack::Bad => {
                self.give_up_piece(here, id, dir, n, &gen, len);
                None
            }
            // Not read, for a reason that says nothing about the copy: never taken as leave to
            // give it up. It is fetched, and the copy stays named.
            files::ReadBack::Unread => None,
        }
    }

    /// Give up copy `gen` of chunk `n` of the kept file `id` in `dir`, which did not read back
    /// whole and matching: in one synced transaction its row stops naming it, if it still does,
    /// and it is recorded to be removed, counted where the file's bytes are counted (the cache,
    /// or the file allowance for a file being saved); then it is removed. Best effort: if this
    /// fails the copy stays named, and is checked, and fails, at every read.
    fn give_up_piece(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], n: u64, gen: &store::Gen, len: u64) {
        let cfg = &self.inner.cfg;
        let _ = self.inner.with_ship(here, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                let Some(kept) = store::kept_get(conn, id)? else { return Ok(()) };
                if kept.dir != *dir {
                    return Ok(());
                }
                let pool = if kept.saving { Pool::Files } else { Pool::Cache };
                store::kept_piece_drop(conn, id, dir, n, gen, len, pool)?;
                Ok(())
            })?)
        });
        self.inner.empty_trash(here);
    }

    /// `keep_piece_within`, with a budget of its own: for tests.
    #[cfg(test)]
    pub(crate) fn keep_piece(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], length: u64, n: u64, data: Vec<u8>) -> Result<(), Error> {
        self.keep_piece_within(here, id, dir, length, n, data, &mut Budget::default())
    }

    /// Keep chunk `n`, already checked against its hash, in the kept file `id` of `length`
    /// bytes in `dir`: put on disk exactly as an upload's chunk is, and named in a synced
    /// transaction only if the kept file is still there under `dir` and does not hold the piece
    /// yet. In the cache, the piece must fit `max_cache_bytes`: if it does not, the least
    /// recently opened other kept files in the cache are thrown away within `budget` (rows
    /// first, synced, then bytes), the trash is drained whether or not anything new was thrown
    /// away, and it is tried once more. A copy not named is removed; one whose commit had an
    /// unknown outcome, or that could not be removed, is a stray: a kept file in the cache with
    /// strays is then thrown away, once, here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn keep_piece_within(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], length: u64, n: u64, data: Vec<u8>, budget: &mut Budget) -> Result<(), Error> {
        let here = canonical_ship(here)?;
        let here = here.as_str();
        let Some(len) = chunk_len(length, n) else { return fail(FileError::Malformed("no such chunk")) };
        if data.len() as u64 != len {
            return fail(FileError::Malformed("a chunk of the wrong size"));
        }
        let strays = |inner: &Inner| inner.dir_record(here, dir).map_or(0, |record| record.strays);
        let strays_before = strays(&self.inner);
        let kept = (|| {
            let mut ready = self.prepare_copy(here, dir, n, data, Holder::Kept { id: *id, length })?;
            match ready.try_commit() {
                Err(Error::File(FileError::NoRoom)) => {
                    let cached = self.inner.with_ship(here, |held| Ok(store::kept_get(&lock(&held.conn), id)?.is_some_and(|kept| kept.dir == *dir && !kept.saving)));
                    if !matches!(cached, Ok(true)) {
                        return fail(FileError::NoRoom);
                    }
                    self.make_cache_room_within(here, id, len, budget, None);
                    ready.try_commit()
                }
                other => other,
            }
        })();
        if strays(&self.inner) > strays_before {
            self.throw_cached(here, id, dir, budget);
        }
        kept
    }

    /// `make_cache_room_within`, with a budget of its own.
    #[cfg(test)]
    pub(crate) fn make_cache_room(&self, here: &str, except: &[u8; 32], need: u64) {
        self.make_cache_room_within(here, except, need, &mut Budget::default(), None)
    }

    /// Make room in the cache for `need` more bytes: throw away the least recently opened kept
    /// files in the cache other than `except`, rows first in one synced transaction with the
    /// trash record, until what is left with `need` would fit once the trash is drained, or
    /// `budget` is spent (keeping back enough for one of `keep_back` chunks); then drain the
    /// trash, whether or not anything new was thrown away (what was thrown away before, and
    /// could not be removed then, may go now). Best effort.
    pub(crate) fn make_cache_room_within(&self, here: &str, except: &[u8; 32], need: u64, budget: &mut Budget, keep_back: Option<u64>) {
        let cfg = &self.inner.cfg;
        if need > cfg.max_cache_bytes {
            return;
        }
        let threw = self.inner.with_ship(here, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                let mut over = store::cache_held(conn)?.saturating_add(need).saturating_sub(cfg.max_cache_bytes);
                let mut threw = 0;
                while over > 0 {
                    let Some((victim, _, held, _)) = store::cached_oldest(conn, Some(except), 1)?.pop() else { break };
                    if !budget.throw(&self.inner, here, conn, &victim, Pool::Cache, keep_back)? {
                        break;
                    }
                    over = over.saturating_sub(held);
                    threw += 1;
                }
                if seams::hit("throw-commit") {
                    return Err(files::injected("throw-commit"));
                }
                if seams::hit("throw-uncertain") {
                    seams::arm("at-commit");
                }
                Ok(threw)
            })?)
        });
        if threw.is_ok() {
            self.inner.retire_thrown(here, budget);
        }
        budget.thrown.clear();
        self.inner.empty_trash_rounds(here, DRAIN_ROUNDS);
    }

    /// `begin_keeping_within`, with a budget of its own: for tests.
    #[cfg(test)]
    pub(crate) fn begin_keeping(&self, here: &str, id: &[u8; 32], length: u64, media_type: &str, leaves: &[[u8; 32]], saver: Option<&str>) -> Result<[u8; 16], Error> {
        self.begin_keeping_within(here, id, length, media_type, leaves, saver, &mut Budget::default())
    }

    /// Begin keeping the file `id` on `here`, its length and every chunk hash checked against
    /// the id: in one transaction, committed synced, its row and a row for each chunk with its
    /// hash, and its directory made and durable before that commit; and if `saver` is given, a
    /// save for that agent, with the reservation (`save_begin`). If it is kept already, the
    /// directory it has. Into the cache (no `saver`), its rows must fit the cache's allowance of
    /// rows: the least recently opened in the cache are thrown away within `budget` to make
    /// room, and a file whose own rows pass the allowance is never kept in the cache. Refused if
    /// the ship keeps `max_kept` files already and none in the cache can be thrown away, or its
    /// own file has no room for the rows. Kept files and saves gone stale are swept first, within
    /// the same budget.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_keeping_within(&self, here: &str, id: &[u8; 32], length: u64, media_type: &str, leaves: &[[u8; 32]], saver: Option<&str>, budget: &mut Budget) -> Result<[u8; 16], Error> {
        let (inner, cfg) = (&self.inner, &self.inner.cfg);
        let here = canonical_ship(here)?;
        let here = here.as_str();
        let chunks = chunk_count(length);
        if chunks > FANOUT as u64 || files::id_from_leaves(length, leaves) != Some(*id) {
            return fail(FileError::Malformed("not a file this ship keeps"));
        }
        // Kept files and saves gone stale first, in a transaction of their own: what is thrown
        // away there lands even if this file is then refused.
        sweep_first(inner, here, cfg, budget)?;
        let dir = random_bytes::<16>()?;
        let path = inner.dir_path(here, &dir);
        let made = std::cell::Cell::new(false);
        let begun = inner.with_ship(here, |held| {
            let begun = held.transact_synced(cfg, |conn| {
                let now = store::now_ms();
                let dir = match store::kept_get(conn, id)? {
                    // Kept already: used only if its rows hold exactly the hashes just checked.
                    Some(kept) if store::kept_leaves(conn, &kept.dir, chunks)?.as_deref() == Some(leaves) => kept.dir,
                    Some(_) => return fail(FileError::Damaged),
                    None => {
                        if saver.is_none() {
                            // Into the cache: its rows, held or not, within the cache's
                            // allowance of rows.
                            let (allowance, mine) = (cache_rows_allowance(cfg), rows_cost(chunks));
                            if mine > allowance {
                                return fail(FileError::NoRoom);
                            }
                            while store::cache_rows(conn)?.saturating_add(mine) > allowance {
                                let Some((victim, ..)) = store::cached_oldest(conn, None, 1)?.pop() else { break };
                                if !budget.throw(inner, here, conn, &victim, Pool::Cache, None)? {
                                    break;
                                }
                            }
                            if store::cache_rows(conn)?.saturating_add(mine) > allowance {
                                return fail(FileError::NoRoom);
                            }
                        }
                        if store::kept_count(conn)? >= cfg.max_kept {
                            // The least recently opened in the cache goes to make room, if
                            // there is one and the budget allows.
                            let victim = store::cached_oldest(conn, None, 1)?.pop();
                            let thrown = match victim {
                                Some((victim, ..)) => budget.throw(inner, here, conn, &victim, Pool::Cache, None)?,
                                None => false,
                            };
                            if !thrown {
                                return Err(Error::TooMany("kept files"));
                            }
                        }
                        // Room in the ship's file for every row the kept file needs, as for an
                        // upload: others may use it meanwhile, and every write is checked.
                        if store::spare_bytes(conn)? < rows_cost(chunks).saturating_add(room_to_take_one(cfg)) {
                            return fail(FileError::NoRoom);
                        }
                        keeping_room(conn, cfg, || Ok(store::kept_add(conn, id, &dir, length, media_type, now, leaves)?))?;
                        // The directory, and its name, are on disk before the row that names it.
                        inner.ship_files_made(here)?;
                        files::make_dir(&path)?;
                        made.set(true);
                        if seams::hit("kept-begin") {
                            return Err(files::injected("kept-begin"));
                        }
                        dir
                    }
                };
                if let Some(agent) = saver {
                    save_begin(conn, cfg, agent, id)?;
                }
                Ok(dir)
            });
            // A directory made for a row that was certainly not kept is removed. If the commit
            // itself failed, the row may yet come back, naming it: it is left, and if no row
            // names it, it is removed when the ship first wakes.
            if begun.as_ref().is_err_and(|not_kept| !not_kept.uncertain) && made.get() {
                let _ = std::fs::remove_dir(&path);
            }
            Ok(begun)
        })?;
        if begun.is_ok() {
            inner.retire_thrown(here, budget);
        }
        budget.thrown.clear();
        inner.empty_trash_rounds(here, DRAIN_ROUNDS);
        begun.map_err(Error::from)
    }

    /// The kept files of `ship`, in order of id, after `after`, at most `max` (and never more
    /// than `MAX_KEPT_LISTED`).
    pub fn kept(&self, ship: &str, after: Option<[u8; 32]>, max: usize) -> Result<Vec<KeptInfo>, Error> {
        let after = after.map_or(Vec::new(), |id| id.to_vec());
        self.inner.with_ship(ship, |held| {
            let listed = store::kept_list(&lock(&held.conn), &after, max.clamp(1, MAX_KEPT_LISTED))?;
            Ok(listed.into_iter().map(|(id, kept)| KeptInfo { id, length: kept.length, held: kept.held, used_ms: kept.used, saving: kept.saving }).collect())
        })
    }

    /// Throw away the kept file `id` from the cache. One being saved is left alone, and the
    /// answer says so. When this returns, no row names it, and its bytes are in the trash or
    /// gone.
    pub fn kept_clear(&self, ship: &str, id: &[u8; 32]) -> Result<Cleared, Error> {
        let ship = canonical_ship(ship)?;
        let cfg = &self.inner.cfg;
        let mut budget = Budget::default();
        let cleared = self.inner.with_ship(&ship, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                let Some(kept) = store::kept_get(conn, id)? else { return fail(FileError::NotFound) };
                if kept.saving {
                    return Ok(Cleared { thrown_away: 0, being_saved: 1 });
                }
                // One kept file always fits a request's budget.
                budget.throw(&self.inner, &ship, conn, id, Pool::Cache, None)?;
                if seams::hit("throw-commit") {
                    return Err(files::injected("throw-commit"));
                }
                if seams::hit("throw-uncertain") {
                    seams::arm("at-commit");
                }
                Ok(Cleared { thrown_away: 1, being_saved: 0 })
            })?)
        });
        if cleared.is_ok() {
            self.inner.retire_thrown(&ship, &mut budget);
        }
        self.inner.empty_trash_rounds(&ship, DRAIN_ROUNDS);
        cleared
    }

    /// Throw away every kept file in the cache: every kept file there is, listed by id in pages
    /// of `MAX_KEPT_LISTED` until there are no more (whatever `max_kept` now is), and thrown away
    /// in transactions each with a budget of its own, letting the ship go between them. One
    /// that some agent is saving when its batch runs is left alone, and counted in the answer.
    /// When this returns, no row names a file it threw away, and their bytes are in the trash or
    /// gone.
    pub fn kept_clear_all(&self, ship: &str) -> Result<Cleared, Error> {
        let ship = canonical_ship(ship)?;
        let cfg = &self.inner.cfg;
        let mut cleared = Cleared::default();
        let mut after: Vec<u8> = Vec::new();
        loop {
            let page = self.inner.with_ship(&ship, |held| Ok(store::kept_ids_after(&lock(&held.conn), &after, MAX_KEPT_LISTED)?))?;
            let Some(last) = page.last() else { break };
            after = last.to_vec();
            seams::before_batch();
            let mut at = 0usize;
            while at < page.len() {
                let mut budget = Budget::default();
                let (taken, thrown, saving) = self.inner.with_ship(&ship, |held| {
                    Ok(held.transact_synced(cfg, |conn| {
                        let (mut taken, mut thrown, mut saving) = (0usize, 0u64, 0u64);
                        while at + taken < page.len() {
                            let id = page[at + taken];
                            match store::kept_get(conn, &id)? {
                                // Gone meanwhile: not this call's to count.
                                None => {}
                                Some(kept) if kept.saving => saving += 1,
                                Some(_) => {
                                    if !budget.throw(&self.inner, &ship, conn, &id, Pool::Cache, None)? {
                                        break;
                                    }
                                    thrown += 1;
                                }
                            }
                            taken += 1;
                        }
                        Ok((taken, thrown, saving))
                    })?)
                })?;
                self.inner.retire_thrown(&ship, &mut budget);
                at += taken;
                cleared.thrown_away += thrown;
                cleared.being_saved += saving;
                self.inner.empty_trash_rounds(&ship, DRAIN_ROUNDS);
            }
        }
        Ok(cleared)
    }

    /// How many bytes of `ship`'s kept files count against the cache (held in the cache, and
    /// thrown away from it and still on disk), and how many are reserved by saves.
    pub fn cache_bytes(&self, ship: &str) -> Result<(u64, u64, u64), Error> {
        self.inner.with_ship(ship, |held| {
            let conn = lock(&held.conn);
            Ok((store::cache_held(&conn)?, store::pool_removing(&conn, Pool::Cache)?, store::saving_bytes(&conn)?))
        })
    }

    /// What the rows of `ship`'s kept files in the cache take, by `rows_cost`.
    pub fn cache_rows(&self, ship: &str) -> Result<u64, Error> {
        self.inner.with_ship(ship, |held| Ok(store::cache_rows(&lock(&held.conn))?))
    }

    /// Save, for `agent` on `ship`, the file `id` that `other_agent` on `other` claims: carry on
    /// a save, or start one. If `ship` holds a file with that id already, `agent` claims it and
    /// nothing is asked. Otherwise the file becomes kept if it is not, and a save for `agent`
    /// is added with the file's whole length reserved, in one transaction; then missing pieces
    /// are fetched from `other`, checked and kept, for at most `save_slice_millis` (one fetch
    /// begun is let finish) or until none is missing; and when none is, the file becomes one of
    /// `ship`'s, claimed by every agent saving it. The device calls again until it is done. One
    /// budget for everything the call throws away.
    pub(crate) fn save_file(&self, ship: &str, agent: &str, other: &str, other_agent: &str, id: &[u8; 32]) -> Result<SaveState, SaveFailed> {
        check_agent_name(agent)?;
        check_agent_name(other_agent)?;
        let (here, other) = (canonical_ship(ship)?, canonical_ship(other)?);
        if here == other {
            return Err(SaveFailed::Here(Error::File(FileError::Malformed("not a ship other than this one"))));
        }
        let (inner, cfg) = (&self.inner, &self.inner.cfg);
        inner.files_on()?;
        let deadline = Instant::now() + Duration::from_millis(cfg.save_slice_millis.min(24 * 60 * 60 * 1000));
        // One budget for everything the call throws away, keeping back from the first room to
        // throw away its own target (as large as a kept file can be), so that this always fits.
        let mut budget = Budget::keeping_back(FANOUT as u64);
        enum Found {
            File(u64),
            Kept(KeptFile, Vec<[u8; 32]>),
            Damaged,
            Nothing,
        }
        // Saves and kept files gone stale are swept first, as uploads are, in a transaction of
        // their own: what is thrown away there lands whatever this call then finds.
        // The agent is asked of the kernel once, first (nothing uninstalls one).
        inner.with_ship(&here, |held| files::installed(inner, held, agent))?;
        sweep_first(inner, &here, cfg, &mut budget)?;
        // Then, asking nothing: a file the ship holds already, or a kept one.
        let found = inner.with_ship(&here, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                let strays = inner.strays_in(&here);
                if let Some(file) = store::file_by_id(conn, id)? {
                    keeping_room(conn, cfg, || Ok(store::claim_add(conn, agent, id)?))?;
                    // A save of it this agent had begun is done with: the ship holds the file.
                    // If no other agent is saving the kept copy, it is thrown away, its bytes
                    // counted where its reservation was until they are gone.
                    if store::save_remove(conn, agent, id)? && store::kept_get(conn, id)?.is_some_and(|kept| !kept.saving) {
                        // With the room kept back if it is there; if not, it goes back to the
                        // cache as any stopped save does, or waits.
                        if !budget.throw_own(inner, &here, conn, id, Pool::Files)? {
                            settle_unsaved(inner, &here, conn, cfg, id, &mut budget, &strays)?;
                        }
                    }
                    return Ok(Found::File(chunk_count(file.length)));
                }
                let Some(kept) = store::kept_get(conn, id)? else { return Ok(Found::Nothing) };
                if too_large(cfg, kept.length) {
                    return fail(FileError::TooLarge);
                }
                // Its rows read without error (an error decides nothing: the transaction is
                // not kept). Rows that certainly do not vouch for the id end this agent's save
                // here, and if no other agent is saving the file it is thrown away, never
                // returned to the cache, with the room kept back.
                match store::kept_leaves(conn, &kept.dir, chunk_count(kept.length))? {
                    Some(leaves) if files::id_from_leaves(kept.length, &leaves) == Some(*id) => {
                        save_begin(conn, cfg, agent, id)?;
                        Ok(Found::Kept(kept, leaves))
                    }
                    _ => {
                        let pool = if kept.saving { Pool::Files } else { Pool::Cache };
                        store::save_remove(conn, agent, id)?;
                        if store::save_agents(conn, id)?.is_empty() && !budget.throw_own(inner, &here, conn, id, pool)? {
                            return fail(FileError::Unsettled);
                        }
                        Ok(Found::Damaged)
                    }
                }
            })?)
        });
        if found.is_ok() {
            inner.retire_thrown(&here, &mut budget);
        }
        budget.thrown.clear();
        inner.empty_trash_rounds(&here, DRAIN_ROUNDS);
        let (dir, length, mut remote) = match found? {
            Found::File(chunks) => return Ok(SaveState { done: true, held: chunks, chunks }),
            Found::Damaged => return Err(Error::File(FileError::Damaged).into()),
            Found::Kept(kept, leaves) => {
                let remote = Remote::known(self.remote_ask(&here, &other, other_agent, id), kept.length, kept.media_type.clone(), leaves).ok_or(Error::File(FileError::Damaged))?;
                (kept.dir, kept.length, remote)
            }
            Found::Nothing => {
                let remote = self.remote_file(&here, &other, other_agent, id).map_err(SaveFailed::There)?;
                let length = remote.length();
                let Some(leaves) = remote.leaves().filter(|_| !too_large(cfg, length)) else { return Err(Error::File(FileError::TooLarge).into()) };
                let dir = self.begin_keeping_within(&here, id, length, remote.media_type(), leaves, Some(agent), &mut budget)?;
                (dir, length, remote)
            }
        };
        let chunks = chunk_count(length);
        // Then the missing pieces, one at a time, until none is missing or the slice is spent.
        loop {
            let next = inner.with_ship(&here, |held| {
                let conn = lock(&held.conn);
                // The very kept file this save began with, still saved by this agent.
                match store::kept_get(&conn, id)? {
                    Some(kept) if kept.dir == dir && store::save_of(&conn, agent, id)? => Ok(store::kept_missing(&conn, &dir, 0)?),
                    _ => fail(FileError::NotFound),
                }
            })?;
            let Some(n) = next else { break };
            if Instant::now() >= deadline {
                let held = inner.with_ship(&here, |held| Ok(store::kept_held_count(&lock(&held.conn), &dir)?))?;
                return Ok(SaveState { done: false, held, chunks });
            }
            let data = remote.chunk(n).map_err(SaveFailed::There)?;
            match self.keep_piece_within(&here, id, &dir, length, n, data, &mut budget) {
                // Kept by another request meanwhile, or the save gone: the next look says which.
                Ok(()) | Err(Error::File(FileError::NotFound)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        seams::before_finish();
        self.save_finish(&here, id, &dir, &mut budget)?;
        Ok(SaveState { done: true, held: chunks, chunks })
    }

    /// Make the kept file `id` in `dir`, every piece of which is held, a file of `here`'s, in
    /// one synced transaction that keeps to the rule: the file's rows made from the kept rows
    /// under the same directory (no byte is moved or rewritten), a claim for every agent saving
    /// it, the kept and saves rows gone, the reservation become held bytes, and the directory
    /// recorded to be swept of copies no row names. The id is worked out from the stored hashes
    /// and must be `id`. If the ship holds a file with that id already (an upload finished
    /// meanwhile), every agent saving it claims that one instead, and this one is thrown away,
    /// within the request's budget, with the room kept back for it; if that room is not there,
    /// `Unsettled`, and nothing is thrown away. The recorded sweep of a directory made a file's
    /// is charged 1 MiB for each stray and copy on its way into it, until the sweep is done.
    fn save_finish(&self, here: &str, id: &[u8; 32], dir: &[u8; 16], budget: &mut Budget) -> Result<(), Error> {
        let (inner, cfg) = (&self.inner, &self.inner.cfg);
        let finished = self.inner.with_ship(here, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                let Some(kept) = store::kept_get(conn, id)?.filter(|kept| kept.dir == *dir && kept.saving) else { return fail(FileError::NotFound) };
                let chunks = chunk_count(kept.length);
                if store::kept_held_count(conn, dir)? != chunks {
                    return fail(FileError::Incomplete);
                }
                let Some(leaves) = store::kept_leaves(conn, dir, chunks)? else { return fail(FileError::Incomplete) };
                if files::id_from_leaves(kept.length, &leaves) != Some(*id) {
                    return fail(FileError::WrongId);
                }
                let agents = store::save_agents(conn, id)?;
                keeping_room(conn, cfg, || {
                    if store::file_by_id(conn, id)?.is_some() {
                        for agent in &agents {
                            store::claim_add(conn, agent, id)?;
                        }
                        if !budget.throw_own(inner, here, conn, id, Pool::Files)? {
                            return fail(FileError::Unsettled);
                        }
                        return Ok(());
                    }
                    if store::file_count(conn)? >= cfg.max_files {
                        return Err(Error::TooMany("files"));
                    }
                    store::kept_to_file(conn, id, &kept, &agents, store::now_ms())?;
                    // In this same synced commit: the directory is to be swept of every copy
                    // no row names (one a failed or cut-off keeping left), as finishing an
                    // upload records.
                    Ok(store::trash_sweep_charged(conn, dir, inner.charge_of(here, dir))?)
                })?;
                if seams::hit("save-commit") {
                    return Err(files::injected("save-commit"));
                }
                if seams::hit("save-uncertain") {
                    seams::arm("at-commit");
                }
                if seams::hit("save-then-fail") {
                    seams::arm("commit-then-fail");
                }
                Ok(())
            })?)
        });
        if finished.is_ok() {
            // A file's directory now, or thrown away: its record is retired.
            self.inner.retire_thrown(here, budget);
            self.inner.retire(here, dir);
        }
        budget.thrown.clear();
        self.inner.empty_trash_rounds(here, DRAIN_ROUNDS);
        finished
    }

    /// The saves `agent` on `ship` has in progress.
    pub fn saves(&self, ship: &str, agent: &str) -> Result<Vec<SaveInfo>, Error> {
        check_agent_name(agent)?;
        let inner = &self.inner;
        inner.with_ship(ship, |held| {
            files::installed(inner, held, agent)?;
            let listed = store::saves_of(&lock(&held.conn), agent, inner.cfg.max_kept.max(1))?;
            Ok(listed.into_iter().map(|(id, touched, kept)| SaveInfo { id, length: kept.length, held: kept.held, chunks: chunk_count(kept.length), touched_ms: touched }).collect())
        })
    }

    /// Stop `agent`'s save of the kept file `id`. When the last save of it stops, its
    /// reservation is returned, and it goes back to the cache if its held bytes and rows fit
    /// there after the least recently opened others are thrown away to make room (within the
    /// request's budget, keeping back enough to throw this one away), and its directory has no
    /// strays; and it is thrown away if not.
    pub fn save_stop(&self, ship: &str, agent: &str, id: &[u8; 32]) -> Result<(), Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let (inner, cfg) = (&self.inner, &self.inner.cfg);
        let last = inner.with_ship(&ship, |held| {
            files::installed(inner, held, agent)?;
            let conn = lock(&held.conn);
            if !store::save_of(&conn, agent, id)? {
                return fail(FileError::NotFound);
            }
            let kept = store::kept_get(&conn, id)?.ok_or(Error::File(FileError::NotFound))?;
            Ok((store::save_agents(&conn, id)?.len() == 1).then_some(kept))
        })?;
        let mut budget = Budget::default();
        // The last save: room is made in the cache first, while the file is still reserved,
        // so that the cache is within its allowance at every instant.
        if let Some(kept) = last.as_ref().filter(|_| cfg.max_cache_bytes > 0) {
            self.make_cache_room_within(&ship, id, kept.held, &mut budget, Some(chunk_count(kept.length)));
        }
        let strays = inner.strays_in(&ship);
        let stopped = inner.with_ship(&ship, |held| {
            Ok(held.transact_synced(cfg, |conn| {
                if !store::save_remove(conn, agent, id)? {
                    return fail(FileError::NotFound);
                }
                settle_unsaved(inner, &ship, conn, cfg, id, &mut budget, &strays)
            })?)
        });
        if stopped.is_ok() {
            inner.retire_thrown(&ship, &mut budget);
        }
        inner.empty_trash_rounds(&ship, DRAIN_ROUNDS);
        stopped
    }
}
