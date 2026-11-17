//! Files on the ship: a store of files of any size, kept beside the ship's own file, that the
//! owner's signed-in devices put files in and take them out of over HTTP.
//!
//! A file is split into chunks of `CHUNK` bytes and named by a hash over its length and the
//! hashes of its chunks (`file_id`), so a copy can be checked chunk by chunk without holding
//! the whole of it. The ship's SQLite file is the truth about what is held: a row for each
//! file, each agent's claim on it, and the hash and copy of each chunk. The bytes are in
//! `files/<ship>/<dir>/<n>.<gen>` in the runtime's directory: one directory per upload, named
//! with sixteen random bytes that are never used again, and in it each copy of chunk `n` under
//! sixteen more random bytes of its own, encrypted under a key derived from the storage key, the
//! ship and the directory. (An import writes each chunk once into a fresh directory, so its
//! copies all carry sixteen zero bytes instead.) Nothing on disk is named by a hash of what it
//! holds.
//!
//! The ship's file and the directory are two stores, and either can move without the other:
//! a crash, a failed sync, a failed commit, a power cut. One rule keeps them in step:
//!
//! - Bytes are written and durable (the file and the name of every directory down to it
//!   synced) before any row names them.
//! - Bytes are removed only after the transaction that stopped naming them is durable. Every
//!   transaction that stops naming bytes or records something to remove (a chunk's commit,
//!   finish, abandon, expiry, delete) is committed with its log synced, whatever the ship's
//!   durability setting, and records what it stopped naming in `file_trash`. Making an upload
//!   is not: losing that commit loses only a directory no row names.
//! - A name on disk is never used for other bytes: directories and chunk copies are named with
//!   random bytes chosen when they are made, and a file is never written over.
//! - After a failure, only what can be shown never to be named, and never to come to be
//!   named, is removed. If the outcome of a commit is not known (the commit itself reported an
//!   error, and may still have reached the log), nothing is removed: the copy is left for a
//!   later step that runs after a successful synced commit has settled what is named. And if
//!   anything unwinds while a ship is held, its connection is closed, rolling back whatever
//!   was open, before anything else can read it.
//! - Anything no row names is rubbish that a later step is sure to try to remove again: what
//!   is in `file_trash` is removed after every operation that puts something there (a chunk's
//!   commit, finish, abandon, start with expiry, delete), at the start of upload start, finish
//!   and delete, and at the ship's first wake, 16 at a time, struck off only once the
//!   directory it was in is synced (a whole directory taking every record of what was in it),
//!   and counted against the allowance until then. A chunk copy's name is made under the
//!   ship's slot and only while its upload is open; finish records, in its own synced commit,
//!   that the file's directory is to be swept of every copy no row names, and that record is
//!   struck off only after a sweep that listed the whole directory without error, removed
//!   every such copy, and synced it. A directory no row names goes when the ship first wakes
//!   in the life of a runtime, and the ship is not marked as looked through until every such
//!   removal has worked.
//!
//! Every chunk read is checked against the hash its row holds before any of it is served, so
//! what is served is what was stored, or an error. Rows change only under the ship's slot and
//! transaction; hashing, encrypting, and moving bytes over the network happen outside it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::ship::{room_to_take_one, Ship};
use crate::{canonical_ship, check_agent_name, hex, lock, open_regular, random_bytes, seal, store, sync_dir, Error, Inner, Runtime};

/// The version of the file id below. Fixed: another ship checks a file it is sent by it.
pub const FILE_FORMAT: u32 = 1;
/// The size of every chunk but a file's last, which holds the rest (1 to `CHUNK` bytes).
pub const CHUNK: u64 = 1 << 20;
/// How many hashes go into one index hash.
pub const FANOUT: usize = 32768;

const CHUNK_DOMAIN: &[u8] = b"ship.v1.chunk\n";
const INDEX_DOMAIN: &[u8] = b"ship.v1.index\n";
const STORED_DOMAIN: &[u8] = b"ship.v1.stored\n";

/// How many chunks a file of `length` bytes has.
pub fn chunk_count(length: u64) -> u64 {
    length.div_ceil(CHUNK)
}

/// The length of chunk `n` of a file of `length` bytes, if it has such a chunk.
pub fn chunk_len(length: u64, n: u64) -> Option<u64> {
    (n < chunk_count(length)).then(|| (length - n * CHUNK).min(CHUNK))
}

/// The hash a chunk is known by.
pub fn leaf(chunk: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(CHUNK_DOMAIN).chain_update(chunk).finalize().into()
}

fn index(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new().chain_update(INDEX_DOMAIN);
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// The root over a list of chunk hashes, worked out as the format says: while more than one
/// hash is left, each run of up to `FANOUT` of them is replaced by its index hash. One hash is
/// its own root; none has the hash of an empty chunk.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => leaf(&[]),
        [only] => *only,
        _ => {
            let mut level: Vec<[u8; 32]> = leaves.to_vec();
            while level.len() > 1 {
                level = level.chunks(FANOUT).map(index).collect();
            }
            level[0]
        }
    }
}

/// The same root, taken one chunk hash at a time, so that a file's hashes need never all be in
/// memory at once: it holds one hash per `FANOUT` chunks.
pub struct RootBuilder {
    first: Option<[u8; 32]>,
    count: u64,
    run: Sha256,
    in_run: usize,
    upper: Vec<[u8; 32]>,
}

impl Default for RootBuilder {
    fn default() -> Self {
        RootBuilder::new()
    }
}

impl RootBuilder {
    pub fn new() -> RootBuilder {
        RootBuilder { first: None, count: 0, run: Sha256::new().chain_update(INDEX_DOMAIN), in_run: 0, upper: Vec::new() }
    }

    pub fn push(&mut self, leaf: &[u8; 32]) {
        self.first.get_or_insert(*leaf);
        self.count += 1;
        self.run.update(leaf);
        self.in_run += 1;
        if self.in_run == FANOUT {
            let run = std::mem::replace(&mut self.run, Sha256::new().chain_update(INDEX_DOMAIN));
            self.upper.push(run.finalize().into());
            self.in_run = 0;
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        match (self.count, self.first) {
            (0, _) | (_, None) => leaf(&[]),
            (1, Some(only)) => only,
            _ => {
                if self.in_run > 0 {
                    self.upper.push(self.run.finalize().into());
                }
                let mut level = self.upper;
                while level.len() > 1 {
                    level = level.chunks(FANOUT).map(index).collect();
                }
                level[0]
            }
        }
    }
}

/// A file's id: its length and the root over its chunks' hashes.
pub fn file_id(length: u64, root: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(STORED_DOMAIN).chain_update(length.to_le_bytes()).chain_update(root).finalize().into()
}

/// How many groups of `FANOUT` chunk hashes a file of `length` bytes has: one index hash each
/// in the level above the chunks' own hashes. An empty file has none.
pub fn group_count(length: u64) -> u64 {
    chunk_count(length).div_ceil(FANOUT as u64)
}

/// How many chunk hashes group `g` of a file of `length` bytes holds, if it has such a group.
pub fn group_len(length: u64, g: u64) -> Option<u64> {
    (g < group_count(length)).then(|| (chunk_count(length) - g * FANOUT as u64).min(FANOUT as u64))
}

/// The index hash of one group of chunk hashes: what the level above holds for it.
pub fn group_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    index(leaves)
}

/// Whether a file of `length` bytes is served to other ships at all: its hashes come down to
/// its root in at most two levels, so a ship fetching it holds at most one list of index
/// hashes (`FANOUT` of them, 1 MiB) besides one group of chunk hashes. That is up to 2^30
/// chunks, a file of 1 PiB.
pub fn fetchable(length: u64) -> bool {
    group_count(length) <= FANOUT as u64
}

/// The id of a file of `length` bytes whose chunks have these hashes, every one of them, in
/// order; for a file of at most `FANOUT` chunks only. `None` if that is not so.
pub fn id_from_leaves(length: u64, leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    let chunks = chunk_count(length);
    (chunks <= FANOUT as u64 && leaves.len() as u64 == chunks).then(|| file_id(length, &root(leaves)))
}

/// The id of a file of `length` bytes whose groups of chunk hashes have these index hashes,
/// every one of them, in order; for a file of more than `FANOUT` chunks, and at most `FANOUT`
/// groups, only. `None` if that is not so.
pub fn id_from_groups(length: u64, groups: &[[u8; 32]]) -> Option<[u8; 32]> {
    let (chunks, count) = (chunk_count(length), group_count(length));
    // More than one group, and at most one index's worth of them: the root is their index.
    (chunks > FANOUT as u64 && count <= FANOUT as u64 && groups.len() as u64 == count).then(|| file_id(length, &index(groups)))
}

/// The id of a file with these contents, worked out as a client would before uploading.
pub fn id_of(contents: &[u8]) -> [u8; 32] {
    let mut root = RootBuilder::new();
    for chunk in contents.chunks(CHUNK as usize) {
        root.push(&leaf(chunk));
    }
    file_id(contents.len() as u64, &root.finish())
}

/// The most a media type may be, written out.
pub const MAX_MEDIA_TYPE_BYTES: usize = 127;

/// A media type as the ship keeps it: `type/subtype`, plain lower-case words, no parameters,
/// at most `MAX_MEDIA_TYPE_BYTES`. None given is `application/octet-stream`. `None` if what
/// is given is not one.
pub fn media_type(given: &str) -> Option<String> {
    let given = given.trim().to_ascii_lowercase();
    if given.is_empty() {
        return Some("application/octet-stream".into());
    }
    let word = |part: &str| {
        !part.is_empty()
            && part.len() <= 63
            && part.as_bytes()[0].is_ascii_alphanumeric()
            && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
    };
    let (kind, sub) = given.split_once('/')?;
    (given.len() <= MAX_MEDIA_TYPE_BYTES && word(kind) && word(sub)).then_some(given)
}

/// The media types a browser is let show in place. Pictures, sound and video only: nothing
/// that can run script or draw a page, so no SVG, no HTML, no PDF. Anything else is sent as an
/// attachment, to be saved and not shown.
const INLINE: &[&str] = &[
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm",
    "audio/aac", "audio/flac", "audio/mp4", "video/mp4", "video/webm", "video/ogg",
];

pub fn shown_inline(media_type: &str) -> bool {
    INLINE.contains(&media_type)
}

/// What can go wrong with a file or an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// This runtime keeps no files: its `max_file_bytes` is 0.
    Off,
    /// No such upload or file for this agent. A file that exists and is not this agent's is
    /// reported the same way.
    NotFound,
    /// Larger than this runtime would ever keep, however empty the ship.
    TooLarge,
    /// No room for it now: the ship's allowance for files, or its own file, is full.
    NoRoom,
    /// A chunk of the wrong size or number, or something that is not a media type.
    Malformed(&'static str),
    /// Finishing an upload that does not hold every chunk.
    Incomplete,
    /// The id the client worked out is not the id of what it sent.
    WrongId,
    /// Bytes on disk are not what the ship's file says they are. Nothing of them is served.
    Damaged,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::Off => write!(f, "this runtime keeps no files"),
            FileError::NotFound => write!(f, "no such file or upload"),
            FileError::TooLarge => write!(f, "the file is larger than this runtime keeps"),
            FileError::NoRoom => write!(f, "there is no room for the file now"),
            FileError::Malformed(why) => write!(f, "{why}"),
            FileError::Incomplete => write!(f, "the upload does not hold every chunk"),
            FileError::WrongId => write!(f, "the stated id is not the id of what was sent"),
            FileError::Damaged => write!(f, "a stored file is damaged"),
        }
    }
}

fn fail<T>(error: FileError) -> Result<T, Error> {
    Err(Error::File(error))
}

/// A write that found the ship's file full is a file without room, not a failure.
fn full_is_no_room(error: Error) -> Error {
    match error {
        Error::Store(ref e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) => Error::File(FileError::NoRoom),
        other => other,
    }
}

/// A file the ship holds, as an agent's devices see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileInfo {
    pub id: [u8; 32],
    pub length: u64,
    pub chunks: u64,
    pub media_type: String,
    pub added_ms: u64,
    /// The agent has marked its claim open: any ship that names the file may have it.
    pub open: bool,
}

impl FileInfo {
    fn of(id: [u8; 32], file: &store::StoredFile) -> FileInfo {
        FileInfo { id, length: file.length, chunks: chunk_count(file.length), media_type: file.media_type.clone(), added_ms: file.added, open: file.open }
    }
}

/// What an upload holds so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadState {
    pub length: u64,
    pub chunks: u64,
    pub media_type: String,
    /// The chunks held, as runs: (first chunk, how many).
    pub held: Vec<(u64, u64)>,
    /// Set when there is more to list: ask again from this chunk.
    pub next: Option<u64>,
}

/// What an import made of the files that came with a ship.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FilesKept {
    /// Files whose every chunk arrived and matched, now held.
    pub kept: u64,
    /// Files the copy's file names that did not all arrive or match, struck off with their
    /// claims.
    pub dropped: u64,
}

/// The most chunk numbers one look at an upload goes through.
pub const MAX_HELD_LISTED: usize = 16_384;
/// The most files one page of a listing gives.
pub const MAX_LISTED: usize = 256;
/// Chunk hashes read from the ship's file in one go, when they are needed in order.
pub(crate) const LEAF_BATCH: u64 = 4096;

/// At most what one row of `file_chunks` takes in the ship's file, with its share of the
/// table's pages. A file's rows are never let take more than a quarter of `max_ship_bytes`.
pub const CHUNK_ROW_BYTES: u64 = 128;

/// The room a file of this many chunks needs in the ship's file for its rows.
fn rows_cost(chunks: u64) -> u64 {
    chunks.saturating_mul(CHUNK_ROW_BYTES).saturating_add(1024)
}

/// Run `work` and keep it only if it leaves the ship's file the room the ship keeps to go on
/// working (`room_to_take_one`), or used none. As for what is written for other ships.
fn keeping_room<R>(conn: &Connection, cfg: &crate::Config, work: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
    let before = store::spare_bytes(conn)?;
    let done = work().map_err(full_is_no_room)?;
    let after = store::spare_bytes(conn)?;
    if after < before && after < room_to_take_one(cfg) {
        return fail(FileError::NoRoom);
    }
    Ok(done)
}

/// Sixteen bytes written as thirty-two lower-case hexadecimal digits, and nothing else.
pub fn parse_dir(text: &str) -> Option<[u8; 16]> {
    parse_hex::<16>(text)
}

/// Thirty-two bytes written as sixty-four lower-case hexadecimal digits, and nothing else.
pub fn parse_id(text: &str) -> Option<[u8; 32]> {
    parse_hex::<32>(text)
}

pub(crate) fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Places where tests make the file store fail, to show what a failure leaves. Compiled only
/// into this crate's own tests: elsewhere every check is `false`, and nothing can arm one.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::Mutex;

    thread_local! {
        static ARMED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        static GEN: RefCell<Option<[u8; 16]>> = const { RefCell::new(None) };
        static SYNCED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    }

    thread_local! {
        static BEFORE_CREATE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Run `then` on this thread when the next chunk copy is about to be made, after its
    /// upload was looked up and its bytes hashed and encrypted.
    pub fn on_before_create(then: impl FnOnce() + 'static) {
        BEFORE_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(then)));
    }

    pub fn before_create() {
        let then = BEFORE_CREATE.with(|slot| slot.borrow_mut().take());
        if let Some(then) = then {
            then();
        }
    }

    /// Make the next chunk copy written on this thread take generation `gen`.
    pub fn force_gen(gen: [u8; 16]) {
        GEN.with(|forced| *forced.borrow_mut() = Some(gen));
    }

    pub fn forced_gen() -> Option<[u8; 16]> {
        GEN.with(|forced| forced.borrow_mut().take())
    }

    /// A directory synced into its parent on this thread, as `parent_synced` does it.
    pub fn synced(dir: &Path) {
        SYNCED.with(|synced| synced.borrow_mut().push(dir.to_path_buf()));
    }

    /// The directories synced on this thread since the last call, emptied.
    pub fn take_synced() -> Vec<PathBuf> {
        SYNCED.with(|synced| std::mem::take(&mut *synced.borrow_mut()))
    }

    /// Make the next pass through `point` on this thread fail.
    pub fn arm(point: &'static str) {
        ARMED.with(|armed| armed.borrow_mut().push(point));
    }

    /// Whether this pass through `point` fails. Each arming fails one pass.
    pub fn hit(point: &'static str) -> bool {
        ARMED.with(|armed| {
            let mut armed = armed.borrow_mut();
            let at = armed.iter().position(|armed| *armed == point);
            at.map(|at| armed.remove(at)).is_some()
        })
    }

    /// The first export into `dest` to reach the point between writing its stream and writing
    /// its copy says so on the first channel and waits there for the second.
    pub struct Gate {
        pub dest: PathBuf,
        pub reached: Sender<()>,
        pub go: Receiver<()>,
    }

    pub static GATE: Mutex<Option<Gate>> = Mutex::new(None);

    pub fn between_stream_and_copy(dest: &Path) {
        let gate = {
            let mut gate = GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if gate.as_ref().is_some_and(|gate| gate.dest == dest) { gate.take() } else { None }
        };
        if let Some(gate) = gate {
            let _ = gate.reached.send(());
            let _ = gate.go.recv();
        }
    }
}

#[cfg(not(test))]
pub(crate) mod seams {
    #[inline(always)]
    pub fn hit(_: &'static str) -> bool {
        false
    }

    #[inline(always)]
    pub fn between_stream_and_copy(_: &std::path::Path) {}

    #[inline(always)]
    pub fn forced_gen() -> Option<[u8; 16]> {
        None
    }

    #[inline(always)]
    pub fn before_create() {}

    #[inline(always)]
    pub fn synced(_: &std::path::Path) {}
}

fn injected(point: &str) -> Error {
    Error::Io(io::Error::other(format!("failure injected at {point}")))
}

/// What kind of entry this is. An error is an error, never a kind.
fn entry_type(entry: &fs::DirEntry) -> io::Result<fs::FileType> {
    if seams::hit("file-type") {
        return Err(io::Error::other("failure injected at file-type"));
    }
    entry.file_type()
}

/// Remove a directory and what is in it, or a file, without following a link. Something
/// already gone is removed.
pub(crate) fn remove_entry(path: &Path) -> io::Result<()> {
    if seams::hit("remove") {
        return Err(io::Error::other("failure injected at remove"));
    }
    let gone = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) => Err(e),
    };
    match gone {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Write a new file that only its owner can read, all of it, and flush it to disk. Never
/// writes over anything: a name that is taken is an error.
fn write_new(path: &Path, parts: &[&[u8]]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
    for part in parts {
        file.write_all(part)?;
    }
    file.sync_all()
}

/// Sync the directory `path` is in, so that the name `path` is durable.
fn parent_synced(path: &Path) -> io::Result<()> {
    if seams::hit("sync-parent") {
        return Err(io::Error::other("failure injected at sync-parent"));
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    sync_dir(parent)?;
    seams::synced(parent);
    Ok(())
}

/// Make a new directory, and make its name durable. One already there is an error.
fn make_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    parent_synced(path)
}

/// Make sure a directory is there and its name is durable. The directory it is in is synced
/// whether or not the directory was made now: one that is there may have been made by an
/// earlier attempt whose sync failed.
fn ensure_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    parent_synced(path)
}

/// How many things waiting to be removed one attempt takes on.
pub const TRASH_BATCH: usize = 16;

impl Inner {
    /// Where one ship's files are.
    pub(crate) fn ship_files(&self, ship: &str) -> PathBuf {
        self.files_dir.join(ship)
    }

    /// The ship's files directory, there and with its name durable.
    fn ship_files_made(&self, ship: &str) -> io::Result<PathBuf> {
        let root = self.ship_files(ship);
        ensure_dir(&root)?;
        Ok(root)
    }

    /// Where the bytes of one upload or file are. The name is the directory's own sixteen
    /// bytes, which are never anything a request or another ship's copy said.
    fn dir_path(&self, ship: &str, dir: &[u8; 16]) -> PathBuf {
        self.ship_files(ship).join(hex(dir))
    }

    /// Where one copy of one chunk is.
    fn chunk_path(&self, ship: &str, dir: &[u8; 16], n: u64, gen: &store::Gen) -> PathBuf {
        self.dir_path(ship, dir).join(format!("{n}.{}", hex(gen)))
    }

    fn files_on(&self) -> Result<(), Error> {
        if self.cfg.max_file_bytes == 0 {
            return fail(FileError::Off);
        }
        Ok(())
    }

    /// Read copy `gen` of chunk `n` of the file in `dir`, which is `len` bytes long, and check
    /// it against `leaf_hash`, the hash its row holds. Only bytes that match are returned. Done
    /// outside the ship's slot; the directory and the copy are the ship's own never-reused
    /// names, so these are that chunk's bytes or none.
    pub(crate) fn read_chunk(&self, ship: &str, dir: &[u8; 16], n: u64, gen: &store::Gen, len: u64, leaf_hash: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let path = self.chunk_path(ship, dir, n, gen);
        let whole = len as usize + seal::CHUNK_FILE_OVERHEAD;
        let mut buf = Vec::with_capacity(whole + 1);
        let read = open_regular(&path).and_then(|file| file.take(whole as u64 + 1).read_to_end(&mut buf));
        if read.is_err() || buf.len() != whole {
            return fail(FileError::Damaged);
        }
        let key = seal::chunk_key(&self.storage, ship, dir);
        let matches = key.open(n, gen, &mut buf).is_some_and(|chunk| chunk.len() as u64 == len && leaf(chunk) == *leaf_hash);
        if !matches {
            return fail(FileError::Damaged);
        }
        buf.truncate(12 + len as usize);
        buf.drain(..12);
        Ok(buf)
    }

    /// The first time a ship wakes in the life of this runtime: what in `files/<ship>/` no row
    /// names. That is what a crash can leave: a directory made for an upload whose row was
    /// never committed. The caller removes it once it has let go of the ship. Its names are
    /// random and never used again, so nothing can come to need them.
    pub(crate) fn files_rubbish(&self, ship: &str, conn: &Connection) -> Result<Vec<PathBuf>, Error> {
        let root = self.ship_files(ship);
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let named = store::named_dirs(conn)?;
        let mut rubbish = Vec::new();
        for entry in entries {
            // An error reading the listing makes this look decline: nothing is removed, and the
            // ship is looked at again at its next wake.
            let entry = entry?;
            // Decided first, and on the name alone: an entry a row names is never rubbish,
            // whatever else is odd about it. Named directories are 32 lower-case hex digits,
            // so a name that is not text, or does not parse, is certainly not one of them.
            if entry.file_name().to_str().and_then(parse_dir).is_some_and(|dir| named.contains(&dir)) {
                continue;
            }
            // Not named. Its type is read, and an error doing so is never taken as an answer:
            // it makes this look decline, as above.
            entry_type(&entry)?;
            rubbish.push(entry.path());
        }
        Ok(rubbish)
    }

    /// Remove up to `TRASH_BATCH` things waiting to be removed, and strike off those that
    /// went. Each was recorded by a transaction committed with its log synced, so nothing that
    /// can come back after a power cut names them. What fails to go stays recorded, counted
    /// against the allowance, and is tried again next time.
    pub(crate) fn empty_trash(&self, ship: &str) {
        let read = self.with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let batch = store::trash_batch(&conn, TRASH_BATCH)?;
            batch
                .into_iter()
                .map(|trash| {
                    let owner = match trash.what {
                        store::Discard::Unnamed => Some(store::dir_owner(&conn, &trash.dir)?),
                        _ => None,
                    };
                    Ok((trash, owner))
                })
                .collect::<Result<Vec<_>, Error>>()
        });
        let Ok(batch) = read else { return };
        // What went, and the directories whose entries changed, each to be synced once.
        let mut gone: Vec<store::Trash> = Vec::new();
        let mut touched: Vec<PathBuf> = Vec::new();
        for (trash, owner) in batch {
            let (removed, place) = match (trash.what, owner) {
                (store::Discard::All, _) => (remove_entry(&self.dir_path(ship, &trash.dir)).is_ok(), self.ship_files(ship)),
                (store::Discard::Chunk(n, gen), _) => (remove_entry(&self.chunk_path(ship, &trash.dir, n, &gen)).is_ok(), self.dir_path(ship, &trash.dir)),
                // An open upload's directory is looked through when it finishes, never while
                // copies may be on their way that no row names yet.
                (store::Discard::Unnamed, Some(store::Owner::Upload)) => continue,
                (store::Discard::Unnamed, Some(store::Owner::File(named))) => {
                    let place = self.dir_path(ship, &trash.dir);
                    (remove_unnamed(&place, &named), place)
                }
                // No one's: the directory itself is to go, or already has.
                (store::Discard::Unnamed, _) => {
                    gone.push(trash);
                    continue;
                }
            };
            if removed {
                if !touched.contains(&place) {
                    touched.push(place.clone());
                }
                gone.push(trash);
            }
        }
        // An entry is struck off only once its removal is durable: the directory it was in is
        // synced first. If that fails, the entries stay, and removing them again is harmless.
        let unsynced: Vec<PathBuf> = touched.into_iter().filter(|place| seams::hit("drain-sync") || sync_dir(place).is_err()).collect();
        gone.retain(|trash| {
            let place = match trash.what {
                store::Discard::All => self.ship_files(ship),
                _ => self.dir_path(ship, &trash.dir),
            };
            !unsynced.contains(&place)
        });
        if gone.is_empty() {
            return;
        }
        // Striking them off need not be durable: if it is lost, removing them again finds
        // them already gone.
        let _ = self.with_ship(ship, |held| {
            held.transact(|conn| {
                for trash in &gone {
                    store::trash_done(conn, trash)?;
                }
                Ok(())
            })
        });
    }

}

/// Remove every entry in `place` not in `named`. True only if the whole directory was listed
/// without error and every such entry went: an error opening or reading the directory may hide
/// an entry, and then the sweep is not complete.
fn remove_unnamed(place: &Path, named: &HashSet<String>) -> bool {
    let Ok(entries) = fs::read_dir(place) else { return false };
    let mut complete = true;
    for entry in entries {
        let entry = match entry {
            Ok(entry) if !seams::hit("list") => entry,
            _ => {
                complete = false;
                continue;
            }
        };
        if !entry.file_name().to_str().is_some_and(|name| named.contains(name)) && remove_entry(&entry.path()).is_err() {
            complete = false;
        }
    }
    complete
}

/// Whether `agent` is installed on the ship: whether the kernel would take a command for it
/// from the owner.
fn installed(rt: &Arc<Inner>, ship: &mut Ship, agent: &str) -> Result<(), Error> {
    if ship.installed(rt, agent)? { Ok(()) } else { Err(Error::UnknownAgent(agent.to_string())) }
}

/// A chunk that has been hashed, encrypted, and written to disk under a name of its own,
/// outside the ship's slot, and is waiting to be named by its upload's row. `commit` names it;
/// dropping it throws it away.
pub struct PreparedChunk<'a> {
    rt: &'a Runtime,
    ship: String,
    agent: String,
    dir: [u8; 16],
    n: u64,
    gen: store::Gen,
    length: u64,
    hash: [u8; 32],
    /// The copy, while it is still this chunk's to remove: made by this upload's own exclusive
    /// create, and no commit that may name it attempted.
    owned: Owned,
}

/// A chunk copy this call made and may remove. Removed on drop unless let go. If removing it
/// fails it is left: it was made while its upload was open, so it is a copy no row names in
/// that upload's directory, which finish records to be swept, and which otherwise goes with
/// the directory.
struct Owned(Option<PathBuf>);

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = remove_entry(&path);
        }
    }
}

impl PreparedChunk<'_> {
    /// Name the chunk, under the ship's slot and in one transaction committed with its log
    /// synced: the upload must still be there (named by its directory, which is never reused),
    /// and the row for chunk `n` is made to name this copy. A copy it replaces is recorded to
    /// be removed, and is removed once that is durable; it is counted against the allowance
    /// until then, so a replacement is refused while the ship is already over it.
    ///
    /// If it is refused, or fails before the commit is tried, this copy is removed and no
    /// other. If the commit itself fails, nothing is removed: the commit may still have
    /// reached the log and come back after a crash, naming this copy. What is left goes when
    /// the upload finishes, after a synced commit has settled what is named, or with its
    /// directory.
    pub fn commit(mut self) -> Result<(), Error> {
        let inner = &self.rt.inner;
        let cfg = &inner.cfg;
        let (dir, n, gen, hash, length, agent) = (self.dir, self.n, self.gen, self.hash, self.length, self.agent.clone());
        let len = chunk_len(length, n).expect("checked when prepared");
        let done = inner.with_ship(&self.ship, |ship| {
            Ok(ship.transact_synced(cfg, |conn| {
                match store::upload_of(conn, &dir, &agent)? {
                    Some((held, _)) if held == length => {}
                    _ => return fail(FileError::NotFound),
                }
                if store::chunk_of(conn, &dir, n)?.is_some() && store::counted_bytes(conn)? > cfg.max_file_bytes {
                    return fail(FileError::NoRoom);
                }
                keeping_room(conn, cfg, || {
                    store::chunk_put(conn, &dir, n, &gen, &hash, len)?;
                    Ok(store::upload_touch(conn, &dir, store::now_ms())?)
                })?;
                if seams::hit("chunk-commit") {
                    return Err(injected("chunk-commit"));
                }
                if seams::hit("panic-before-commit") {
                    panic!("panic injected before commit");
                }
                Ok(())
            }))
        });
        match done {
            // Named now, durably: no longer this call's to remove.
            Ok(Ok(())) => {
                self.owned.0 = None;
                inner.empty_trash(&self.ship);
                Ok(())
            }
            // The commit was tried, and its outcome is not known: this copy may be named.
            Ok(Err(not_kept)) if not_kept.uncertain => {
                self.owned.0 = None;
                Err(not_kept.error)
            }
            // Refused, or failed before the commit: dropping this removes its own copy.
            Ok(Err(not_kept)) => Err(not_kept.error),
            Err(e) => Err(e),
        }
    }
}

impl Runtime {
    /// Start an upload of a file of `length` bytes for `agent` on `ship`. Returns the upload's
    /// name and how many chunks to send. The whole length is reserved against the ship's
    /// allowance here, so that held, reserved, and still-to-be-removed bytes together never
    /// pass `max_file_bytes` because of a new upload.
    pub fn upload_start(&self, ship: &str, agent: &str, length: u64, media_type: &str) -> Result<([u8; 16], u64), Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let inner = &self.inner;
        inner.files_on()?;
        let cfg = &inner.cfg;
        let Some(media_type) = self::media_type(media_type) else { return fail(FileError::Malformed("not a media type")) };
        // Whether it could ever fit is decided first, by a rule that does not look at how full
        // the ship is now, so that a ship that is nearly full never says "later" of a file that
        // will never fit.
        let chunks = chunk_count(length);
        if length > cfg.max_file_bytes || rows_cost(chunks) > cfg.max_ship_bytes / 4 {
            return fail(FileError::TooLarge);
        }
        inner.empty_trash(&ship);
        let dir = random_bytes::<16>()?;
        let path = inner.dir_path(&ship, &dir);
        let made = std::cell::Cell::new(false);
        let started = inner.with_ship(&ship, |held| {
            installed(inner, held, agent)?;
            // Uploads left untouched too long go first, and their reservations with them,
            // whatever becomes of this one.
            let before = store::now_ms().saturating_sub(cfg.upload_keep_millis);
            held.transact_synced(cfg, |conn| Ok(store::uploads_expire(conn, before)?))?;
            let started = held.transact_knowing(|conn| {
                if store::upload_count(conn)? >= cfg.max_uploads {
                    return Err(Error::TooMany("uploads open"));
                }
                if store::counted_bytes(conn)?.saturating_add(length) > cfg.max_file_bytes {
                    return fail(FileError::NoRoom);
                }
                // Room in the ship's file for every row the upload will need. Others may use
                // that room meanwhile; each chunk's row is checked again as it is written.
                if store::spare_bytes(conn)? < rows_cost(chunks).saturating_add(room_to_take_one(cfg)) {
                    return fail(FileError::NoRoom);
                }
                keeping_room(conn, cfg, || Ok(store::upload_add(conn, &dir, agent, length, &media_type, store::now_ms())?))?;
                // The directory, and its name, are on disk before the row that names it.
                inner.ship_files_made(&ship)?;
                make_dir(&path)?;
                made.set(true);
                Ok(())
            });
            // A directory made for a row that was certainly not kept is removed. If the commit
            // itself failed, the row may yet come back, naming it: it is left, and if no row
            // names it, it is removed when the ship first wakes.
            if started.as_ref().is_err_and(|not_kept| !not_kept.uncertain) && made.get() {
                let _ = fs::remove_dir(&path);
            }
            Ok(started)
        })?;
        inner.empty_trash(&ship);
        started.map(|()| (dir, chunks)).map_err(Error::from)
    }

    /// Hash, encrypt and write chunk `n` of an upload under a name of its own, ready to be
    /// named. While the ship is held: looking the upload up, and then, after hashing and
    /// encrypting, making the copy's name, and only if the upload is still open. So a name only
    /// ever appears in an upload's directory while it is open, never after finishing has
    /// recorded the directory to be swept. Writing the bytes and syncing are done outside.
    pub fn prepare_chunk(&self, ship: &str, agent: &str, upload: &[u8; 16], n: u64, mut chunk: Vec<u8>) -> Result<PreparedChunk<'_>, Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let inner = &self.inner;
        inner.files_on()?;
        let length = inner.with_ship(&ship, |held| {
            installed(inner, held, agent)?;
            store::upload_of(&lock(&held.conn), upload, agent)?.map(|(length, _)| length).ok_or(Error::File(FileError::NotFound))
        })?;
        let Some(expected) = chunk_len(length, n) else { return fail(FileError::Malformed("the upload has no chunk of that number")) };
        if chunk.len() as u64 != expected {
            return fail(FileError::Malformed("a chunk of the wrong size"));
        }
        let hash = leaf(&chunk);
        // Sixteen random bytes, as for a directory: taken as never chosen twice.
        let gen = match seams::forced_gen() {
            Some(gen) => gen,
            None => random_bytes::<16>()?,
        };
        let nonce = random_bytes::<12>()?;
        seal::chunk_key(&inner.storage, &ship, upload).seal(n, &gen, nonce, &mut chunk);
        seams::before_create();
        // The name is made under the ship's slot, and only while the upload is still the open
        // one it was (its directory is never reused). A name that is taken is an error that
        // touches nothing: the copy there is not this call's.
        let path = inner.chunk_path(&ship, upload, n, &gen);
        let (mut file, owned) = inner.with_ship(&ship, |held| {
            match store::upload_of(&lock(&held.conn), upload, agent)? {
                Some((held_length, _)) if held_length == length => {}
                _ => return fail(FileError::NotFound),
            }
            let file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => Error::File(FileError::NotFound),
                _ => Error::Io(e),
            })?;
            // Made by this call's own exclusive create: from this instant it is this call's to
            // remove.
            Ok((file, Owned(Some(path.clone()))))
        })?;
        file.write_all(&nonce)?;
        file.write_all(&chunk)?;
        file.sync_all()?;
        drop(file);
        sync_dir(&inner.dir_path(&ship, upload))?;
        Ok(PreparedChunk { rt: self, ship, agent: agent.to_string(), dir: *upload, n, gen, length, hash, owned })
    }

    /// Put chunk `n` of an upload in place: `prepare_chunk` then `commit`. A chunk sent again
    /// replaces the one held until the upload is finished.
    pub fn upload_chunk(&self, ship: &str, agent: &str, upload: &[u8; 16], n: u64, chunk: Vec<u8>) -> Result<(), Error> {
        self.prepare_chunk(ship, agent, upload, n, chunk)?.commit()
    }

    /// Which chunks an upload holds, from chunk `from` on, so a client can carry on where it
    /// left off without sending again what is there.
    pub fn upload_state(&self, ship: &str, agent: &str, upload: &[u8; 16], from: u64) -> Result<UploadState, Error> {
        check_agent_name(agent)?;
        let inner = &self.inner;
        inner.files_on()?;
        inner.with_ship(ship, |held| {
            installed(inner, held, agent)?;
            let conn = lock(&held.conn);
            let Some((length, media_type)) = store::upload_of(&conn, upload, agent)? else { return fail(FileError::NotFound) };
            let numbers = store::chunks_held(&conn, upload, from, MAX_HELD_LISTED)?;
            let next = (numbers.len() == MAX_HELD_LISTED).then(|| numbers.last().map_or(from, |last| last + 1));
            let mut held: Vec<(u64, u64)> = Vec::new();
            for n in numbers {
                match held.last_mut() {
                    Some((first, count)) if *first + *count == n => *count += 1,
                    _ => held.push((n, 1)),
                }
            }
            Ok(UploadState { length, chunks: chunk_count(length), media_type, held, next })
        })
    }

    /// Finish an upload: every chunk must be held. The id is worked out from the chunk hashes
    /// the ship holds, without reading the bytes again, and must be `stated` if one is given.
    /// The upload becomes a file claimed by `agent`. If the ship already holds a file with that
    /// id, `agent` claims that one and the upload's bytes go, with its reservation: a ship
    /// holds identical files once.
    pub fn upload_finish(&self, ship: &str, agent: &str, upload: &[u8; 16], stated: Option<[u8; 32]>) -> Result<FileInfo, Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let inner = &self.inner;
        inner.files_on()?;
        let cfg = &inner.cfg;
        inner.empty_trash(&ship);
        let info = inner.with_ship(&ship, |held| {
            installed(inner, held, agent)?;
            Ok(held.transact_synced(cfg, |conn| {
                let Some((length, media_type)) = store::upload_of(conn, upload, agent)? else { return fail(FileError::NotFound) };
                let chunks = chunk_count(length);
                if store::chunk_total(conn, upload)? != chunks {
                    return fail(FileError::Incomplete);
                }
                let mut root = RootBuilder::new();
                let mut from = 0;
                while from < chunks {
                    let count = LEAF_BATCH.min(chunks - from);
                    let Some(rows) = store::chunks(conn, upload, from, count)? else { return fail(FileError::Incomplete) };
                    rows.iter().for_each(|(hash, _)| root.push(hash));
                    from += count;
                }
                let id = file_id(length, &root.finish());
                if stated.is_some_and(|stated| stated != id) {
                    return fail(FileError::WrongId);
                }
                keeping_room(conn, cfg, || {
                    if store::file_by_id(conn, &id)?.is_some() {
                        store::claim_add(conn, agent, &id)?;
                        // The whole directory is recorded to be removed.
                        store::upload_drop(conn, upload)?;
                        // As the agent's claim now has it: an earlier claim of its own keeps
                        // its mark.
                        let claimed = store::file_claimed(conn, agent, &id)?.ok_or_else(|| Error::BadShipFile("a claim just made is not there".into()))?;
                        return Ok(FileInfo::of(id, &claimed));
                    }
                    if store::file_count(conn)? >= cfg.max_files {
                        return Err(Error::TooMany("files"));
                    }
                    let now = store::now_ms();
                    store::file_add(conn, &id, upload, length, &media_type, agent, now)?;
                    // In this same synced commit: the directory is to be swept of every copy
                    // no row names (one a failed or cut-off chunk upload left). The entry is
                    // forgotten only after a sweep that listed the whole directory, removed
                    // every such copy, and synced it; a crash at any point leaves it.
                    store::trash_sweep(conn, upload)?;
                    Ok(FileInfo { id, length, chunks, media_type, added_ms: now, open: false })
                })
            })?)
        })?;
        // The file's chunks never change again, and no new name can appear in its directory:
        // names are made only while an upload is open. The sweep, or the directory's removal,
        // is done by the drain.
        if !seams::hit("skip-sweep") {
            inner.empty_trash(&ship);
        }
        Ok(info)
    }

    /// Give up an upload, its bytes and its reservation.
    pub fn upload_abandon(&self, ship: &str, agent: &str, upload: &[u8; 16]) -> Result<(), Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let inner = &self.inner;
        inner.files_on()?;
        let cfg = &inner.cfg;
        inner.with_ship(&ship, |held| {
            installed(inner, held, agent)?;
            Ok(held.transact_synced(cfg, |conn| {
                if store::upload_of(conn, upload, agent)?.is_none() {
                    return fail(FileError::NotFound);
                }
                Ok(store::upload_drop(conn, upload)?)
            })?)
        })?;
        inner.empty_trash(&ship);
        Ok(())
    }

    /// The files `agent` claims, in order of id, after `after`, at most `max` (and never more
    /// than `MAX_LISTED`).
    pub fn files(&self, ship: &str, agent: &str, after: Option<[u8; 32]>, max: usize) -> Result<Vec<FileInfo>, Error> {
        check_agent_name(agent)?;
        let inner = &self.inner;
        inner.files_on()?;
        let after = after.map_or(Vec::new(), |id| id.to_vec());
        inner.with_ship(ship, |held| {
            installed(inner, held, agent)?;
            let listed = store::files_claimed(&lock(&held.conn), agent, &after, max.clamp(1, MAX_LISTED))?;
            Ok(listed.iter().map(|(id, file)| FileInfo::of(*id, file)).collect())
        })
    }

    /// A file `agent` claims. Any other id, whether the ship holds it or not, is `NotFound`.
    pub fn file_info(&self, ship: &str, agent: &str, id: &[u8; 32]) -> Result<FileInfo, Error> {
        self.file_open(ship, agent, id).map(|file| FileInfo::of(*id, &file))
    }

    pub(crate) fn file_open(&self, ship: &str, agent: &str, id: &[u8; 32]) -> Result<store::StoredFile, Error> {
        check_agent_name(agent)?;
        let inner = &self.inner;
        inner.files_on()?;
        inner.with_ship(ship, |held| {
            installed(inner, held, agent)?;
            store::file_claimed(&lock(&held.conn), agent, id)?.ok_or(Error::File(FileError::NotFound))
        })
    }

    /// The hashes and copies of chunks `from` on, `count` of them, of a file `agent` still
    /// claims and that is still the one in `dir`.
    pub(crate) fn file_chunks(&self, ship: &str, agent: &str, id: &[u8; 32], dir: &[u8; 16], from: u64, count: u64) -> Result<Vec<([u8; 32], store::Gen)>, Error> {
        self.inner.with_ship(ship, |held| {
            let conn = lock(&held.conn);
            match store::file_claimed(&conn, agent, id)? {
                Some(file) if file.dir == *dir => {}
                _ => return fail(FileError::NotFound),
            }
            store::chunks(&conn, dir, from, count)?.ok_or(Error::File(FileError::Damaged))
        })
    }

    /// Chunk `n` of a file `agent` claims, checked against its hash.
    pub fn file_chunk(&self, ship: &str, agent: &str, id: &[u8; 32], n: u64) -> Result<Vec<u8>, Error> {
        let ship = canonical_ship(ship)?;
        let file = self.file_open(&ship, agent, id)?;
        let Some(len) = chunk_len(file.length, n) else { return fail(FileError::NotFound) };
        let (hash, gen) = self.file_chunks(&ship, agent, id, &file.dir, n, 1)?[0];
        self.inner.read_chunk(&ship, &file.dir, n, &gen, len, &hash)
    }

    /// Read copy `gen` of chunk `n` of the file in `dir`, checked against `leaf`.
    pub(crate) fn read_chunk(&self, ship: &str, dir: &[u8; 16], n: u64, gen: &store::Gen, len: u64, leaf: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.inner.read_chunk(ship, dir, n, gen, len, leaf)
    }

    /// Take back `agent`'s claim on a file. When no claim is left, the file's rows go in the
    /// same transaction and its bytes once that is durable.
    pub fn file_delete(&self, ship: &str, agent: &str, id: &[u8; 32]) -> Result<(), Error> {
        check_agent_name(agent)?;
        let ship = canonical_ship(ship)?;
        let inner = &self.inner;
        inner.files_on()?;
        let cfg = &inner.cfg;
        inner.empty_trash(&ship);
        let gone = inner.with_ship(&ship, |held| {
            installed(inner, held, agent)?;
            Ok(held.transact_synced(cfg, |conn| store::claim_remove(conn, agent, id)?.ok_or(Error::File(FileError::NotFound)))?)
        })?;
        if gone {
            inner.empty_trash(&ship);
        }
        Ok(())
    }

    /// How many bytes a ship's files take, and how many its open uploads have reserved.
    pub fn file_bytes(&self, ship: &str) -> Result<(u64, u64), Error> {
        self.inner.with_ship(ship, |held| {
            let conn = lock(&held.conn);
            Ok((store::file_bytes(&conn)?, store::reserved_bytes(&conn)?))
        })
    }

    /// How many bytes no row names any more and are still to be removed from disk, and how
    /// many things that is. They count against the ship's allowance until they are gone.
    pub fn files_to_remove(&self, ship: &str) -> Result<(u64, usize), Error> {
        self.inner.with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM file_trash", [], |r| r.get(0))?;
            Ok((store::removing_bytes(&conn)?, count as usize))
        })
    }
}

// Serving a file to another ship.
//
// Another ship names the agent that claims a file and the file's id, and asks for one part at a
// time (see `Part`). Before each, in one hold of the ship's slot and one read transaction
// (`Ship::file_permit`), the ship decides afresh whether that ship may have it: the agent is
// installed and claims the file, and the claim is marked open, or the agent's remembered
// answer says yes, or the agent asked now says yes. Every no, whatever its reason, is the same
// `Served::Denied`. Serving writes nothing of its own and keeps nothing: no row, and nothing
// on disk. (A request that is the first thing to wake a ship in a runtime's life sets off the
// clearing of leftovers owed at first wake, as anything that wakes it does: what the ship
// recorded to be removed, and directories no row names. It only ever removes.) Chunk hashes
// are read and hashed, and a chunk
// read and checked against its hash, outside the slot.

/// The words every refusal of a file carries. The same whatever the reason, so a ship that may
/// not have a file learns nothing of whether it, its claim, or its agent exists.
pub(crate) fn not_shared(ship: &str, peer: &str) -> String {
    format!("~{ship} does not share that file with ~{peer}")
}

/// A part of a file another ship asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// Its length and media type.
    About,
    /// The hashes of the chunks in group `g`: chunks `g * FANOUT` on, as many as there are.
    Leaves(u64),
    /// The index hash of every group, for a file of more than `FANOUT` chunks.
    Upper,
    /// Chunk `n`, whole.
    Chunk(u64),
}

/// What is served for a part of a file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Served {
    /// The one refusal, whatever the reason.
    Denied,
    About { length: u64, media_type: String },
    /// Hashes of 32 bytes each, one after another.
    Hashes(Vec<u8>),
    Chunk(Vec<u8>),
    /// The caller may have the file, and it has no such part.
    NoSuchPart,
}

/// How long an agent's answer about a file is remembered: a yes, and a no.
pub(crate) const ANSWER_YES: Duration = Duration::from_secs(30);
pub(crate) const ANSWER_NO: Duration = Duration::from_secs(5);
/// How many answers are remembered. When full the oldest goes, which only costs an ask.
pub(crate) const MOST_ANSWERS: usize = 4096;

/// What an answer is remembered under: the ship and its incarnation mark (new at every
/// import, sixteen random bytes), the module the kernel routes the agent to (a hash of its
/// code), the agent, the asking ship, the file's id, and the file's directory (sixteen random
/// bytes, never used again, so a file deleted and put back is another file here).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AnswerKey {
    pub ship: String,
    pub incarnation: [u8; 16],
    pub module: String,
    pub agent: String,
    pub caller: String,
    pub id: [u8; 32],
    pub dir: [u8; 16],
}

/// Agents' answers about their files, remembered for a while. In memory only, per runtime.
#[derive(Default)]
pub(crate) struct Answers {
    /// Each answer, until when it holds, and its place in `order`.
    held: HashMap<AnswerKey, (bool, Instant, u64)>,
    /// The answers in the order they were remembered, oldest first.
    order: BTreeMap<u64, AnswerKey>,
    next: u64,
}

impl Answers {
    fn get(&mut self, key: &AnswerKey, now: Instant) -> Option<bool> {
        let (allowed, until, place) = *self.held.get(key)?;
        if now < until {
            return Some(allowed);
        }
        self.held.remove(key);
        self.order.remove(&place);
        None
    }

    fn put(&mut self, key: AnswerKey, allowed: bool, now: Instant) {
        if let Some((_, _, place)) = self.held.remove(&key) {
            self.order.remove(&place);
        }
        while self.held.len() >= MOST_ANSWERS {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            self.held.remove(&oldest);
        }
        let until = now + if allowed { ANSWER_YES } else { ANSWER_NO };
        let place = self.next;
        self.next += 1;
        self.order.insert(place, key.clone());
        self.held.insert(key, (allowed, until, place));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.held.len()
    }

    /// For tests: make every answer as old as if `by` had passed.
    #[cfg(test)]
    pub(crate) fn age(&mut self, by: Duration) {
        for (_, until, _) in self.held.values_mut() {
            *until = until.checked_sub(by).unwrap_or_else(Instant::now);
        }
    }
}

/// The answer remembered under `key`, if one still holds. A table left poisoned by a panic is
/// emptied and this answer is no: nothing remembered there is trusted.
pub(crate) fn remembered(answers: &Mutex<Answers>, key: &AnswerKey, now: Instant) -> Option<bool> {
    match answers.lock() {
        Ok(mut held) => held.get(key, now),
        Err(poisoned) => {
            *poisoned.into_inner() = Answers::default();
            answers.clear_poison();
            Some(false)
        }
    }
}

/// Remember an answer from `now`.
pub(crate) fn remember(answers: &Mutex<Answers>, key: AnswerKey, allowed: bool, now: Instant) {
    let mut held = answers.lock().unwrap_or_else(|poisoned| {
        let mut held = poisoned.into_inner();
        *held = Answers::default();
        held
    });
    answers.clear_poison();
    held.put(key, allowed, now);
}

/// An error if whoever asked has stopped waiting.
fn gave_up(given_up: &std::sync::atomic::AtomicBool) -> Result<(), Error> {
    if given_up.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(Error::Io(io::Error::new(io::ErrorKind::Interrupted, "the request was given up on")));
    }
    Ok(())
}

/// Forget every answer remembered for `ship`, all agents: called under the ship's slot by every
/// change made through its kernel, so no request is decided between the change and this. A
/// module hash is not an installation, and one agent's answer can rest on a read of another.
pub(crate) fn forget_ship(answers: &Mutex<Answers>, ship: &str) {
    let mut held = answers.lock().unwrap_or_else(|poisoned| {
        let mut held = poisoned.into_inner();
        *held = Answers::default();
        held
    });
    answers.clear_poison();
    let gone: Vec<(AnswerKey, u64)> = held.held.iter().filter(|(key, _)| key.ship == ship).map(|(key, (_, _, place))| (key.clone(), *place)).collect();
    for (key, place) in gone {
        held.held.remove(&key);
        held.order.remove(&place);
    }
}

/// Whether `ship` is resting from asking its agents about files: after a question that took
/// `t`, it asks none for `3 t`, so questions take at most about a quarter of its time, however
/// many ships ask. A table left poisoned by a panic is emptied and this is yes: nothing is asked.
pub(crate) fn resting(rests: &Mutex<HashMap<String, Instant>>, ship: &str, now: Instant) -> bool {
    match rests.lock() {
        Ok(rests) => rests.get(ship).is_some_and(|until| now < *until),
        Err(poisoned) => {
            poisoned.into_inner().clear();
            rests.clear_poison();
            true
        }
    }
}

/// Rest `ship` from asking after a question that took `took`, ending at `now`.
pub(crate) fn rest_after(rests: &Mutex<HashMap<String, Instant>>, ship: &str, took: Duration, now: Instant) {
    let mut rests = rests.lock().unwrap_or_else(|poisoned| {
        let mut rests = poisoned.into_inner();
        rests.clear();
        rests
    });
    rests.insert(ship.to_string(), now + took.saturating_mul(ASK_REST));
}

/// How many times as long as its last question a ship rests from asking.
pub(crate) const ASK_REST: u32 = 3;

impl Runtime {
    /// Serve `peer`, a ship that proved who it is, a part of the file `id` that `agent` claims
    /// on `ship`. Whether it may have it is decided afresh, before anything is read (see
    /// `Ship::file_permit`). Every no is `Served::Denied`, whatever its reason, and anything that
    /// fails while deciding is a no. Once it is yes, a chunk or hashes that cannot be read, or
    /// do not match what the ship's file holds, are an error, never wrong bytes.
    ///
    /// `given_up` is set when whoever asked has stopped waiting: the work then stops before its
    /// next batch of hashes, or before reading the chunk, with an error.
    pub(crate) fn serve_file(&self, ship: &str, peer: &str, agent: &str, id: &[u8], part: Part, given_up: &std::sync::atomic::AtomicBool) -> Result<Served, Error> {
        let (Ok(ship), Ok(peer), Ok(()), Ok(id)) = (canonical_ship(ship), canonical_ship(peer), check_agent_name(agent), <[u8; 32]>::try_from(id)) else {
            return Ok(Served::Denied);
        };
        if self.inner.files_on().is_err() {
            return Ok(Served::Denied);
        }
        let inner = &self.inner;
        let chunk = match part {
            Part::Chunk(n) => Some(n),
            _ => None,
        };
        // Given up on while waiting for the slot: nothing is decided or read, and nobody is told.
        let permit = inner.with_ship(&ship, |held| {
            gave_up(given_up)?;
            #[cfg(test)]
            inner.served_decisions.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.file_permit(inner, &peer, agent, &id, chunk)
        });
        let (file, row) = match permit {
            Ok(crate::ship::Permit::Yes { file, row }) => (file, row),
            // No, or failed while deciding: both are no.
            Ok(crate::ship::Permit::No) | Err(_) => return Ok(Served::Denied),
        };
        #[cfg(test)]
        if let Some(wait) = *crate::lock(&inner.serve_delay) {
            std::thread::sleep(wait);
        }
        match part {
            Part::About => Ok(Served::About { length: file.length, media_type: file.media_type }),
            Part::Leaves(g) => {
                let Some(count) = group_len(file.length, g) else { return Ok(Served::NoSuchPart) };
                let mut hashes = Vec::with_capacity(count as usize * 32);
                self.read_hashes(&ship, agent, &id, &file.dir, g * FANOUT as u64, count, given_up, |hash| hashes.extend_from_slice(hash))?;
                Ok(Served::Hashes(hashes))
            }
            Part::Upper => {
                let count = group_count(file.length);
                if count < 2 || !fetchable(file.length) {
                    return Ok(Served::NoSuchPart);
                }
                let mut upper = Vec::with_capacity(count as usize * 32);
                for g in 0..count {
                    let len = group_len(file.length, g).expect("a group of the file");
                    let mut run = Sha256::new().chain_update(INDEX_DOMAIN);
                    self.read_hashes(&ship, agent, &id, &file.dir, g * FANOUT as u64, len, given_up, |hash| run.update(hash))?;
                    upper.extend_from_slice(&run.finalize());
                }
                Ok(Served::Hashes(upper))
            }
            Part::Chunk(n) => {
                let Some(len) = chunk_len(file.length, n) else { return Ok(Served::NoSuchPart) };
                // The file has the chunk, and its row was read with the decision: one missing
                // is damage.
                let Some((hash, gen)) = row else { return fail(FileError::Damaged) };
                gave_up(given_up)?;
                #[cfg(test)]
                inner.served_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Served::Chunk(inner.read_chunk(&ship, &file.dir, n, &gen, len, &hash)?))
            }
        }
    }

    /// Read the hashes of chunks `from` to `from + count - 1` of a file `agent` still claims
    /// and that is still the one in `dir`, a batch at a time, each batch under the slot, and
    /// hand each to `each` outside it.
    #[allow(clippy::too_many_arguments)]
    fn read_hashes(
        &self,
        ship: &str,
        agent: &str,
        id: &[u8; 32],
        dir: &[u8; 16],
        from: u64,
        count: u64,
        given_up: &std::sync::atomic::AtomicBool,
        mut each: impl FnMut(&[u8; 32]),
    ) -> Result<(), Error> {
        #[cfg(test)]
        let batch_size = match self.inner.hash_batch.load(std::sync::atomic::Ordering::SeqCst) {
            0 => LEAF_BATCH,
            size => size,
        };
        #[cfg(not(test))]
        let batch_size = LEAF_BATCH;
        let mut done = 0;
        while done < count {
            gave_up(given_up)?;
            let batch = batch_size.min(count - done);
            // Looked up again under the slot, by claim and directory; and checked again there
            // that the request has not been given up on while this waited for the slot.
            let rows = self.inner.with_ship(ship, |held| {
                gave_up(given_up)?;
                #[cfg(test)]
                self.inner.served_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let conn = lock(&held.conn);
                match store::file_claimed(&conn, agent, id)? {
                    Some(file) if file.dir == *dir => {}
                    _ => return fail(FileError::NotFound),
                }
                store::chunks(&conn, dir, from + done, batch)?.ok_or(Error::File(FileError::Damaged))
            })?;
            for (hash, _) in rows {
                each(&hash);
            }
            done += batch;
            #[cfg(test)]
            if let Some(wait) = *crate::lock(&self.inner.batch_delay) {
                std::thread::sleep(wait);
            }
        }
        Ok(())
    }
}

// The stream of a ship's files that goes beside an exported copy. Sealed in segments to the
// owner's recovery key, and bound to the copy. Inside, in order:
//
//   1, id (32 bytes), length (8 bytes, low byte first): a file begins; then for each chunk,
//   2 and the chunk's bytes, or 3 if the file's bytes could not all be read, which ends it.
//   0, then how many files went in whole (8 bytes): the end.
const RECORD_END: u8 = 0;
const RECORD_FILE: u8 = 1;
const RECORD_CHUNK: u8 = 2;
const RECORD_GIVEN_UP: u8 = 3;

/// Writes the plain stream into sealed segments, one at a time.
struct SegmentWriter<W: Write> {
    out: W,
    seal: seal::StreamSeal,
    segment: Vec<u8>,
}

impl<W: Write> SegmentWriter<W> {
    fn put(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            // A full segment goes only once more is coming: the last one is sealed as such.
            if self.segment.len() == seal::SEGMENT_BYTES {
                self.flush(false)?;
            }
            let take = (seal::SEGMENT_BYTES - self.segment.len()).min(bytes.len());
            self.segment.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
        }
        Ok(())
    }

    fn flush(&mut self, last: bool) -> io::Result<()> {
        self.seal.seal(&mut self.segment, last);
        self.out.write_all(&self.segment)?;
        self.segment.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        self.flush(true)?;
        Ok(self.out)
    }
}

/// Reads the plain stream out of sealed segments, checking each.
struct SegmentReader<R: Read> {
    input: R,
    open: seal::StreamOpen,
    plain: Vec<u8>,
    at: usize,
    /// A byte read to learn whether another segment follows.
    carried: Option<u8>,
    ended: bool,
}

impl<R: Read> SegmentReader<R> {
    /// The next segment, or false if there is none or it does not open.
    fn next_segment(&mut self) -> bool {
        if self.ended {
            return false;
        }
        let whole = seal::SEGMENT_BYTES + seal::SEGMENT_TAG_BYTES;
        let mut sealed = Vec::with_capacity(whole);
        sealed.extend(self.carried.take());
        if self.input.by_ref().take((whole - sealed.len()) as u64).read_to_end(&mut sealed).is_err() {
            return false;
        }
        // A full segment is the last only if nothing follows it.
        let last = sealed.len() < whole || {
            let mut one = [0u8; 1];
            match self.input.read(&mut one) {
                Ok(0) => true,
                Ok(_) => {
                    self.carried = Some(one[0]);
                    false
                }
                Err(_) => return false,
            }
        };
        let Some(plain) = self.open.open(&mut sealed, last) else { return false };
        let len = plain.len();
        sealed.truncate(len);
        self.plain = sealed;
        self.at = 0;
        self.ended = last;
        true
    }

    fn read_exact(&mut self, out: &mut [u8]) -> bool {
        let mut filled = 0;
        while filled < out.len() {
            if self.at == self.plain.len() && !self.next_segment() {
                return false;
            }
            let take = (self.plain.len() - self.at).min(out.len() - filled);
            out[filled..filled + take].copy_from_slice(&self.plain[self.at..self.at + take]);
            (self.at, filled) = (self.at + take, filled + take);
        }
        true
    }

    fn byte(&mut self) -> Option<u8> {
        let mut one = [0u8; 1];
        self.read_exact(&mut one).then_some(one[0])
    }
}

impl Runtime {
    /// Write the stream of a ship's files to `path`, sealed to `recovery` and bound to the
    /// sealed copy whose hash is `binding`. Each file's chunks are read from disk outside the
    /// ship's slot and checked against their hashes; a file whose bytes cannot all be read is
    /// marked as given up, and an import drops it.
    pub(crate) fn write_files_stream(
        &self,
        ship: &str,
        recovery: &[u8; 32],
        binding: &[u8; 32],
        files: &[([u8; 32], [u8; 16], u64)],
        out: fs::File,
    ) -> Result<fs::File, Error> {
        let (head, seal) = seal::seal_files_stream(recovery, ship, binding, random_bytes::<32>()?);
        let mut out = out;
        out.write_all(&head)?;
        let mut writer = SegmentWriter { out: io::BufWriter::new(out), seal, segment: Vec::with_capacity(seal::SEGMENT_BYTES + seal::SEGMENT_TAG_BYTES) };
        let mut whole = 0u64;
        for (id, dir, length) in files {
            writer.put(&[RECORD_FILE])?;
            writer.put(id)?;
            writer.put(&length.to_le_bytes())?;
            let chunks = chunk_count(*length);
            let mut from = 0;
            let mut given_up = false;
            'file: while from < chunks {
                let count = LEAF_BATCH.min(chunks - from);
                // The file is looked up again by its id and directory, which is never reused:
                // one deleted since the copy was made is given up.
                let rows = self.inner.with_ship(ship, |held| {
                    let conn = lock(&held.conn);
                    match store::file_by_id(&conn, id)? {
                        Some(file) if file.dir == *dir => Ok(store::chunks(&conn, dir, from, count)?),
                        _ => Ok(None),
                    }
                })?;
                let Some(rows) = rows else {
                    given_up = true;
                    break;
                };
                for (i, (hash, gen)) in rows.iter().enumerate() {
                    let n = from + i as u64;
                    let len = chunk_len(*length, n).expect("a chunk of the file");
                    let Ok(chunk) = self.inner.read_chunk(ship, dir, n, gen, len, hash) else {
                        given_up = true;
                        break 'file;
                    };
                    writer.put(&[RECORD_CHUNK])?;
                    writer.put(&chunk)?;
                }
                from += count;
            }
            if given_up {
                writer.put(&[RECORD_GIVEN_UP])?;
            } else {
                whole += 1;
            }
        }
        writer.put(&[RECORD_END])?;
        writer.put(&whole.to_le_bytes())?;
        let out = writer.finish()?.into_inner().map_err(|e| e.into_error())?;
        out.sync_all()?;
        Ok(out)
    }

    /// Bring in the files of an imported ship from the stream `input`, for the ship file
    /// built at `staged`, which is not yet published. Each file is checked chunk by chunk
    /// against the hashes in that file and stored under this runtime's key. Returns the ids
    /// of the files whose every chunk arrived and matched. Reading stops at the first thing
    /// that is not as it should be; what was kept by then stays kept.
    ///
    /// Nothing in the stream is made into a path: a file is written to the directory the new
    /// ship file gives it. What is read is bounded by the files that ship file lists, whose
    /// lengths `import` has already held to `max_file_bytes`. Nothing is kept per file until
    /// the stream is known to open; then about 100 bytes per file the ship file lists.
    ///
    /// Every directory made, and the ship's files directory, is synced into the directory it is
    /// in before this returns, so that the files are durable before the ship is published.
    pub(crate) fn read_files_stream(&self, ship: &str, code: &str, binding: &[u8; 32], input: fs::File, staged: &Connection) -> Result<HashSet<[u8; 32]>, Error> {
        let mut kept = HashSet::new();
        let mut input = io::BufReader::new(input);
        let mut head = [0u8; seal::FILES_HEAD];
        if input.read_exact(&mut head).is_err() {
            return Ok(kept);
        }
        let Some(open) = seal::open_files_stream(code, ship, binding, &head) else { return Ok(kept) };
        // Each file the new ship lists: its directory and length, and whether it has been seen.
        let mut listed: std::collections::HashMap<[u8; 32], ([u8; 16], u64, bool)> =
            store::all_files(staged)?.into_iter().map(|(id, dir, length)| (id, (dir, length, false))).collect();
        if listed.is_empty() {
            return Ok(kept);
        }
        let mut reader = SegmentReader { input, open, plain: Vec::new(), at: 0, carried: None, ended: false };
        let root = self.inner.ship_files_made(ship)?;
        let mut chunk = Vec::with_capacity(CHUNK as usize + seal::CHUNK_FILE_OVERHEAD);
        'records: while let Some(record) = reader.byte() {
            if record != RECORD_FILE {
                break;
            }
            let (mut id, mut length) = ([0u8; 32], [0u8; 8]);
            if !reader.read_exact(&mut id) || !reader.read_exact(&mut length) {
                break;
            }
            let length = u64::from_le_bytes(length);
            // Each file the new ship lists, once, with the length it lists.
            let Some((dir, listed_length, seen)) = listed.get_mut(&id) else { break };
            if *listed_length != length || std::mem::replace(seen, true) {
                break;
            }
            let dir = *dir;
            let dir_path = self.inner.dir_path(ship, &dir);
            make_dir(&dir_path)?;
            let key = seal::chunk_key(&self.inner.storage, ship, &dir);
            for n in 0..chunk_count(length) {
                match reader.byte() {
                    Some(RECORD_CHUNK) => {}
                    Some(RECORD_GIVEN_UP) => {
                        let _ = remove_entry(&dir_path);
                        continue 'records;
                    }
                    _ => {
                        let _ = remove_entry(&dir_path);
                        break 'records;
                    }
                }
                let len = chunk_len(length, n).expect("a chunk of the file") as usize;
                chunk.resize(len, 0);
                let expected = store::chunks(staged, &dir, n, 1)?.and_then(|rows| rows.first().copied());
                if !reader.read_exact(&mut chunk) || expected.map(|(hash, _)| hash) != Some(leaf(&chunk)) {
                    let _ = remove_entry(&dir_path);
                    break 'records;
                }
                let gen = expected.expect("checked above").1;
                let nonce = random_bytes::<12>()?;
                key.seal(n, &gen, nonce, &mut chunk);
                write_new(&self.inner.chunk_path(ship, &dir, n, &gen), &[&nonce, &chunk])?;
            }
            sync_dir(&dir_path)?;
            kept.insert(id);
        }
        sync_dir(&root)?;
        Ok(kept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(text: &str) -> [u8; 32] {
        parse_id(text).unwrap()
    }

    /// The format's own numbers, worked out apart from this code (with Python's hashlib) and
    /// written down. They must never change: another ship checks files by them.
    #[test]
    fn file_ids_are_as_the_format_says() {
        assert_eq!(FILE_FORMAT, 1);
        assert_eq!((CHUNK, FANOUT), (1 << 20, 32768));
        let cases: [(&str, Vec<u8>, &str); 4] = [
            ("empty", Vec::new(), ID_EMPTY),
            ("one byte", vec![0x61], ID_ONE),
            ("one whole chunk", vec![0x5a; CHUNK as usize], ID_CHUNK),
            ("one chunk and a byte", [vec![0x5a; CHUNK as usize], vec![0x61]].concat(), ID_CHUNK_AND_ONE),
        ];
        for (what, contents, expected) in cases {
            assert_eq!(hex(&id_of(&contents)), expected, "{what}");
        }
        // The root of no chunks is the hash of an empty chunk; one chunk is its own root.
        assert_eq!(root(&[]), leaf(&[]));
        assert_eq!(root(&[leaf(b"a")]), leaf(b"a"));
        assert_eq!(chunk_count(0), 0);
        assert_eq!((chunk_len(CHUNK + 1, 0), chunk_len(CHUNK + 1, 1), chunk_len(CHUNK + 1, 2)), (Some(CHUNK), Some(1), None));
    }

    /// One more chunk than fits under one index hash: the list takes two rounds to come down
    /// to one. Made-up hashes, so as not to hash 32 GiB.
    #[test]
    fn a_file_of_more_chunks_than_one_index_takes_crosses_a_level() {
        let leaves: Vec<[u8; 32]> = (0..=FANOUT as u32).map(|i| <[u8; 32]>::try_from(Sha256::digest(i.to_le_bytes()).as_slice()).unwrap()).collect();
        assert_eq!(hex(&root(&leaves)), ROOT_FANOUT_PLUS_ONE);
        assert_eq!(hex(&file_id(32 << 30, &root(&leaves))), ID_FANOUT_PLUS_ONE);
        // Taken one at a time, the same.
        let mut builder = RootBuilder::new();
        leaves.iter().for_each(|leaf| builder.push(leaf));
        assert_eq!(builder.finish(), root(&leaves));
        // And for exactly one index's worth, and for two hashes.
        for take in [2, FANOUT] {
            let mut builder = RootBuilder::new();
            leaves[..take].iter().for_each(|leaf| builder.push(leaf));
            assert_eq!(builder.finish(), index(&leaves[..take]), "{take}");
        }
        assert_ne!(hex32(ROOT_FANOUT_PLUS_ONE), index(&leaves));
    }

    #[test]
    fn media_types_are_plain_and_bounded() {
        assert_eq!(media_type("").as_deref(), Some("application/octet-stream"));
        assert_eq!(media_type(" Image/PNG ").as_deref(), Some("image/png"));
        for bad in ["text", "text/", "/html", "text/html; charset=utf-8", "text/ht ml", "text/html\r\nX: y", "a/b/c", "-x/y"] {
            assert_eq!(media_type(bad), None, "{bad:?}");
        }
        assert!(media_type(&format!("a/{}", "b".repeat(63))).is_some() && media_type(&format!("a/{}", "b".repeat(64))).is_none());
        assert!(shown_inline("image/png") && !shown_inline("image/svg+xml") && !shown_inline("text/html") && !shown_inline("application/pdf"));
    }

    const ID_EMPTY: &str = "21c6be437fc80b8454e56c66510a2eb4fbee3ebf56f15074947b100b749d820c";
    const ID_ONE: &str = "afa071af12e36559fa4386cd4d4ab3ac23eedc591a14f6cac0c2c272a678f830";
    const ID_CHUNK: &str = "acae030272dfd6ba7b7abed2cc9fe673ae8064fce446278bb9e8e975838fdf03";
    const ID_CHUNK_AND_ONE: &str = "f2f7783028bb9d6921a7d3d4a71f1499dee5ad359fc4a06628d435975ba0be03";
    const ROOT_FANOUT_PLUS_ONE: &str = "d3ceed2bcb4a59bd61852a1c0b13537a365a62f12e61c6b15fbb0273eab74db5";
    const ID_FANOUT_PLUS_ONE: &str = "85e6348b9cbfb8519ba159fe992bd063ae08ec08eaab52fd55e15652689f9e69";
}

/// Failures made to happen at chosen points (see `seams`), and what they leave behind.
#[cfg(test)]
mod fault_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{id_of, seams, store, FileError, CHUNK};
    use crate::{seal, Config, Durability, Error, Manifest, Provide, Runtime};

    /// The one builder of the test agents in this test binary: two building at once could
    /// each read a module while the other's build was putting it in place.
    fn wasm(name: &str) -> Vec<u8> {
        crate::net::router_tests::wasm(name)
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!("urbit-wasm-faults-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fast() -> Config {
        Config { durability: Durability::Normal, ..Config::default() }
    }

    fn boot(dir: &TempDir, cfg: Config) -> Runtime {
        let rt = Runtime::open(&dir.0, cfg).unwrap();
        let (kernel, counter) = (rt.add_module(&wasm("kernel")).unwrap(), rt.add_module(&wasm("counter")).unwrap());
        rt.create_ship("~zod", &kernel).unwrap();
        let manifest = Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: false }], uses: vec![] };
        rt.install("~zod", "counter", &counter, &manifest).unwrap();
        rt
    }

    /// The copies of chunk `n` on disk in an upload's or file's directory.
    fn copies(dir: &TempDir, upload: &[u8; 16], n: u64) -> Vec<String> {
        let place = dir.0.join("files/zod").join(crate::hex(upload));
        let mut found: Vec<String> = fs::read_dir(place)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(&format!("{n}.")))
            .collect();
        found.sort();
        found
    }

    fn put_file(rt: &Runtime, data: &[u8]) -> [u8; 32] {
        let (upload, _) = rt.upload_start("~zod", "counter", data.len() as u64, "").unwrap();
        for (n, chunk) in data.chunks(CHUNK as usize).enumerate() {
            rt.upload_chunk("~zod", "counter", &upload, n as u64, chunk.to_vec()).unwrap();
        }
        rt.upload_finish("~zod", "counter", &upload, Some(id_of(data))).unwrap().id
    }

    #[test]
    fn a_replacement_whose_commit_fails_leaves_the_chunk_it_would_have_replaced() {
        let dir = TempDir::new("replace");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let held = copies(&dir, &upload, 0);
        assert_eq!(held.len(), 1);
        // The new copy is on disk when the commit fails: it goes, and the old one stays named.
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        seams::arm("chunk-commit");
        assert!(ready.commit().is_err());
        assert_eq!(copies(&dir, &upload, 0), held);
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        // A replacement that is kept removes the copy it replaced, once that is durable.
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'c'; 20]).unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'd'; 20]).unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn a_commit_whose_outcome_is_not_known_removes_nothing() {
        let dir = TempDir::new("uncertain");
        let rt = boot(&dir, fast());
        // The commit fails and is undone: the old copy is still the one named, and the new
        // copy is left on disk, since the commit might have been kept.
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("at-commit");
        assert!(ready.commit().is_err());
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        // A later good upload of the chunk works, and finishing clears what no row names.
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'c'; 20]).unwrap();
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'c'; 20]);
        // The commit reaches the log and then reports failure: the copy it names is there.
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'd'; 20]).unwrap();
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'e'; 20]).unwrap();
        seams::arm("commit-then-fail");
        assert!(ready.commit().is_err());
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'e'; 20]);
    }

    #[test]
    fn a_generation_already_taken_touches_the_copy_that_has_it() {
        let dir = TempDir::new("collide");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let held = copies(&dir, &upload, 0);
        let gen = crate::files::parse_hex::<16>(held[0].split_once('.').unwrap().1).unwrap();
        seams::force_gen(gen);
        assert!(rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).is_err());
        assert_eq!(copies(&dir, &upload, 0), held);
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
    }

    #[test]
    fn a_directory_sync_that_failed_is_done_on_the_next_try() {
        let dir = TempDir::new("resync");
        let rt = boot(&dir, fast());
        let files = dir.0.join("files");
        // Making the ship's files directory works; making its name durable does not.
        seams::take_synced();
        seams::arm("sync-parent");
        assert!(rt.upload_start("~zod", "counter", 10, "").is_err());
        assert!(files.join("zod").exists(), "inconclusive: the directory was not made");
        // The next try finds it there, and syncs it into `files/` all the same.
        seams::take_synced();
        rt.upload_start("~zod", "counter", 10, "").unwrap();
        assert!(seams::take_synced().contains(&files), "files/ was not synced on the retry");
        drop(rt);
        // The same for the runtime's own directories when it starts.
        seams::arm("open-sync");
        assert!(Runtime::open(&dir.0, fast()).is_err());
        seams::take_synced();
        drop(Runtime::open(&dir.0, fast()).unwrap());
        assert!(seams::take_synced().contains(&files), "the data directory was not synced on the retry");
    }

    #[test]
    fn an_unwind_inside_a_transaction_leaves_nothing_for_the_next_to_act_on() {
        let dir = TempDir::new("unwind");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let held = copies(&dir, &upload, 0);
        // A panic after the replacement recorded the old copy to be removed, before commit.
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("panic-before-commit");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ready.commit()));
        assert!(unwound.is_err(), "inconclusive: nothing unwound");
        // The next operations empty what is to be removed: the old copy is not among it.
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(copies(&dir, &upload, 0), held);
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn a_removal_is_forgotten_only_once_it_is_durable() {
        let dir = TempDir::new("forget");
        let rt = boot(&dir, fast());
        let id = put_file(&rt, b"some bytes");
        // The directory goes, but syncing where it was fails: its record stays.
        seams::arm("drain-sync");
        rt.file_delete("~zod", "counter", &id).unwrap();
        assert_eq!(fs::read_dir(dir.0.join("files/zod")).unwrap().count(), 0);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (10, 1));
        // The next operation removes it again (it is already gone), syncs, and forgets it.
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn a_failed_finish_sweep_is_noted_and_done_later() {
        let dir = TempDir::new("sweep-later");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        // A copy left by a commit whose outcome was not known.
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("at-commit");
        assert!(ready.commit().is_err());
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        // Finishing cannot remove it: the directory is noted, at no counted size.
        seams::arm("remove");
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 1));
        // The next operation looks through it and the copy goes; the file's own stays.
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
    }

    #[test]
    fn a_chunk_made_ready_before_finish_cannot_appear_after_it() {
        let dir = TempDir::new("late");
        let rt = std::sync::Arc::new(boot(&dir, fast()));
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let held = copies(&dir, &upload, 0);
        // The replacement has looked the upload up and hashed and encrypted its chunk; at that
        // point, before it makes a name, the upload is finished.
        let finished = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (rt2, finished2) = (rt.clone(), finished.clone());
        seams::on_before_create(move || {
            *finished2.lock().unwrap() = Some(rt2.upload_finish("~zod", "counter", &upload, None).unwrap().id);
        });
        assert!(matches!(rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]), Err(Error::File(FileError::NotFound))));
        let id = finished.lock().unwrap().expect("inconclusive: the upload was not finished in between");
        assert_eq!(copies(&dir, &upload, 0), held);
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
    }

    #[test]
    fn a_sweep_cut_off_after_finish_is_done_by_the_next_drain() {
        let dir = TempDir::new("cut-off");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("at-commit");
        assert!(ready.commit().is_err());
        // Finish commits, and is stopped before its sweep, as a crash would stop it.
        seams::arm("skip-sweep");
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 1));
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
    }

    #[test]
    fn a_sweep_whose_listing_fails_is_kept_and_done_later() {
        let dir = TempDir::new("listing");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("at-commit");
        assert!(ready.commit().is_err());
        // Reading the directory fails part way: the sweep is not complete, and is kept.
        seams::arm("list");
        rt.upload_finish("~zod", "counter", &upload, None).unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 1));
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn a_directory_removed_takes_the_records_of_what_was_in_it() {
        let dir = TempDir::new("stranded");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        // The replaced copy cannot be removed yet: its record stays, counted.
        seams::arm("remove");
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (20, 1));
        // The upload is given up: its directory goes, and every record of what was in it.
        rt.upload_abandon("~zod", "counter", &upload).unwrap();
        assert!(!dir.0.join("files/zod").join(crate::hex(&upload)).exists());
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn a_sweep_entry_never_touches_an_open_upload() {
        let dir = TempDir::new("open-sweep");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        // A copy on its way: named on disk, not yet by a row.
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        // Only finish writes sweep entries, for a directory that is then a file's. One for an
        // open upload, written here by hand, is never acted on while the upload is open.
        rt.inner.with_ship("~zod", |held| held.transact(|conn| Ok(store::trash_sweep(conn, &upload)?))).unwrap();
        rt.upload_start("~zod", "counter", 5, "").unwrap();
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        ready.commit().unwrap();
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
    }

    #[test]
    fn an_entry_whose_type_cannot_be_read_is_never_removed_for_it() {
        let dir = TempDir::new("kind");
        let data = vec![b'k'; 40];
        let id = {
            let rt = boot(&dir, fast());
            put_file(&rt, &data)
        };
        let named = fs::read_dir(dir.0.join("files/zod")).unwrap().next().unwrap().unwrap().path();
        // The first look meets the file's directory, and reading its type fails.
        let rt = Runtime::open(&dir.0, fast()).unwrap();
        seams::arm("file-type");
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), data);
        assert!(named.exists());
        // It was never asked: a named entry is kept on its name alone.
        assert!(seams::hit("file-type"), "the type of a named directory was read");
        // A leftover whose type cannot be read: the look declines and removes nothing, and the
        // ship is looked at again at its next wake, when it goes.
        let stale = dir.0.join("files/zod").join("0f".repeat(16));
        fs::create_dir(&stale).unwrap();
        drop(rt);
        let rt = Runtime::open(&dir.0, fast()).unwrap();
        seams::arm("file-type");
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), data);
        assert!(stale.exists() && named.exists());
        rt.sleep_idle(Duration::ZERO);
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), data);
        assert!(!stale.exists() && named.exists());
    }

    #[test]
    fn an_import_never_clears_files_on_a_failed_look_for_the_ship() {
        let (a, b, out) = (TempDir::new("look-a"), TempDir::new("look-b"), TempDir::new("look-out"));
        let rt = boot(&a, fast());
        put_file(&rt, b"exported");
        rt.set_recovery_key("~zod", seal::recovery_public("code-code")).unwrap();
        rt.export_ship("~zod", &out.0).unwrap();
        // The runtime it goes to already has a ~zod, with files of its own.
        let there = boot(&b, fast());
        let mine = put_file(&there, b"already here");
        // Looking for that ship's file fails: the import stops there, and clears nothing.
        seams::arm("ship-lookup");
        assert!(matches!(there.import_ship_counted(&out.0, "~zod", "code-code"), Err(Error::Io(_))));
        assert_eq!(there.file_chunk("~zod", "counter", &mine, 0).unwrap(), b"already here");
    }

    #[test]
    fn a_relative_data_directory_is_synced_into_the_current_one() {
        let name = format!("urbit-wasm-relative-{}", std::process::id());
        let _ = fs::remove_dir_all(&name);
        seams::take_synced();
        let opened = Runtime::open(&name, fast());
        let synced = seams::take_synced();
        drop(opened);
        let _ = fs::remove_dir_all(&name);
        assert!(synced.contains(&PathBuf::from(".")), "{synced:?}");
    }

    #[test]
    fn a_failed_replacement_never_takes_another_puts_bytes_whatever_the_order() {
        let dir = TempDir::new("race");
        let rt = boot(&dir, fast());
        for good_first in [true, false] {
            let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
            rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
            let failing = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'f'; 20]).unwrap();
            let good = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'g'; 20]).unwrap();
            if good_first {
                good.commit().unwrap();
                seams::arm("chunk-commit");
                assert!(failing.commit().is_err());
            } else {
                seams::arm("chunk-commit");
                assert!(failing.commit().is_err());
                good.commit().unwrap();
            }
            assert_eq!(copies(&dir, &upload, 0).len(), 1, "good first: {good_first}");
            let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
            assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'g'; 20], "good first: {good_first}");
            rt.file_delete("~zod", "counter", &id).unwrap();
        }
    }

    #[test]
    fn a_copy_no_row_names_goes_when_its_upload_finishes() {
        let dir = TempDir::new("orphan");
        let rt = boot(&dir, fast());
        let (upload, _) = rt.upload_start("~zod", "counter", 20, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, vec![b'a'; 20]).unwrap();
        // A commit that fails, and then cannot even remove its own copy: as a crash would leave.
        let ready = rt.prepare_chunk("~zod", "counter", &upload, 0, vec![b'b'; 20]).unwrap();
        seams::arm("chunk-commit");
        seams::arm("remove");
        assert!(ready.commit().is_err());
        assert_eq!(copies(&dir, &upload, 0).len(), 2, "inconclusive: the failed copy was removed after all");
        // Nothing is noted while the upload is open: finishing records its directory to be
        // swept, in its own commit.
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        assert_eq!(copies(&dir, &upload, 0).len(), 1);
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), vec![b'a'; 20]);
    }

    #[test]
    fn a_removal_that_fails_is_counted_and_tried_again() {
        let dir = TempDir::new("retry");
        let data = vec![b'x'; 3 * (CHUNK as usize) / 2];
        let rt = boot(&dir, Config { max_file_bytes: 2 * CHUNK, ..fast() });
        let id = put_file(&rt, &data);
        let place = |dir: &TempDir| fs::read_dir(dir.0.join("files/zod")).unwrap().count();
        assert_eq!(place(&dir), 1);
        // The delete is done; removing the bytes fails, and they stay counted.
        seams::arm("remove");
        rt.file_delete("~zod", "counter", &id).unwrap();
        assert_eq!(place(&dir), 1);
        assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (data.len() as u64, 1));
        // While they are there, an upload that would need their room is refused.
        seams::arm("remove");
        seams::arm("remove");
        assert!(matches!(rt.upload_start("~zod", "counter", CHUNK, ""), Err(Error::File(FileError::NoRoom))));
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (data.len() as u64, 1));
        // The next file operation tries again, and they go.
        rt.upload_start("~zod", "counter", CHUNK, "").unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        assert_eq!(place(&dir), 1, "only the new upload's directory is left");
    }

    #[test]
    fn a_replacement_may_not_take_the_ship_over_its_allowance_by_more_than_a_chunk() {
        let dir = TempDir::new("over");
        let rt = boot(&dir, Config { max_file_bytes: 2 * CHUNK, ..fast() });
        let chunk = |fill: u8| vec![fill; CHUNK as usize];
        let (upload, _) = rt.upload_start("~zod", "counter", 2 * CHUNK, "").unwrap();
        rt.upload_chunk("~zod", "counter", &upload, 0, chunk(b'a')).unwrap();
        // A replacement whose old copy cannot be removed yet: the ship is now over its
        // allowance by that one chunk, which stays counted.
        seams::arm("remove");
        rt.upload_chunk("~zod", "counter", &upload, 0, chunk(b'b')).unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (CHUNK, 1), "inconclusive: the replaced copy was removed");
        // While it is over, no further replacement is taken.
        assert!(matches!(rt.upload_chunk("~zod", "counter", &upload, 0, chunk(b'c')), Err(Error::File(FileError::NoRoom))));
        assert_eq!(copies(&dir, &upload, 0).len(), 2);
        // A chunk sent for the first time adds nothing, and its commit removes what was waiting.
        rt.upload_chunk("~zod", "counter", &upload, 1, chunk(b'd')).unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));
        rt.upload_chunk("~zod", "counter", &upload, 0, chunk(b'c')).unwrap();
        let id = rt.upload_finish("~zod", "counter", &upload, None).unwrap().id;
        assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), chunk(b'c'));
    }

    #[test]
    fn a_ship_is_looked_through_again_until_its_leftovers_have_all_gone() {
        let dir = TempDir::new("sweep");
        drop(boot(&dir, fast()));
        let stale = dir.0.join("files/zod").join("0f".repeat(16));
        fs::create_dir_all(&stale).unwrap();
        let rt = Runtime::open(&dir.0, fast()).unwrap();
        seams::arm("remove");
        assert!(rt.has_recovery_key("~zod").is_ok());
        assert!(stale.exists(), "inconclusive: the leftover went though its removal was made to fail");
        // Put to sleep and woken again: looked through again, and this time it goes.
        rt.sleep_idle(Duration::ZERO);
        assert!(rt.has_recovery_key("~zod").is_ok());
        assert!(!stale.exists());
    }

    #[test]
    fn a_failure_after_an_import_is_published_leaves_the_ship_its_files() {
        let (a, b, out) = (TempDir::new("link-a"), TempDir::new("link-b"), TempDir::new("link-out"));
        let rt = boot(&a, fast());
        let data = vec![b'q'; CHUNK as usize + 9];
        let id = put_file(&rt, &data);
        rt.set_recovery_key("~zod", seal::recovery_public("code-code")).unwrap();
        rt.export_ship("~zod", &out.0).unwrap();
        let other = Runtime::open(&b.0, fast()).unwrap();
        seams::arm("after-link");
        assert!(other.import_ship_counted(&out.0, "~zod", "code-code").is_err());
        // The ship was published before the failure, and its files are still its own.
        let read: Vec<u8> = (0..2).flat_map(|n| other.file_chunk("~zod", "counter", &id, n).unwrap()).collect();
        assert!(read == data);
    }

    #[test]
    fn two_exports_into_one_place_leave_a_copy_and_a_stream_from_the_same_export() {
        let (a, b, out) = (TempDir::new("exports-a"), TempDir::new("exports-b"), TempDir::new("exports-out"));
        let rt = std::sync::Arc::new(boot(&a, fast()));
        let data = vec![b'e'; 1000];
        let id = put_file(&rt, &data);
        rt.set_recovery_key("~zod", seal::recovery_public("code-code")).unwrap();
        let (reached_tx, reached) = mpsc::channel();
        let (go, go_rx) = mpsc::channel();
        *seams::GATE.lock().unwrap() = Some(seams::Gate { dest: out.0.clone(), reached: reached_tx, go: go_rx });
        // The first export stops between writing its stream and writing its copy.
        let first = std::thread::spawn({
            let (rt, dest) = (rt.clone(), out.0.clone());
            move || rt.export_ship("~zod", &dest)
        });
        reached.recv_timeout(Duration::from_secs(60)).expect("inconclusive: the first export never reached the point between stream and copy");
        // A second export into the same place cannot get between the two.
        let second = std::thread::spawn({
            let (rt, dest) = (rt.clone(), out.0.clone());
            move || rt.export_ship("~zod", &dest)
        });
        std::thread::sleep(Duration::from_millis(500));
        assert!(!second.is_finished(), "a second export finished while the first was between its stream and its copy");
        go.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        let other = Runtime::open(&b.0, fast()).unwrap();
        assert_eq!(other.import_ship_counted(&out.0, "~zod", "code-code").unwrap().kept, 1);
        assert_eq!(other.file_chunk("~zod", "counter", &id, 0).unwrap(), data);
    }
}
