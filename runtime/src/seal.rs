//! What keeps a ship's data unreadable when it is at rest: in its file on disk, in the file
//! that holds its signing key, and in an exported copy.
//!
//! There are two keys, held by two different people.
//!
//! The storage key belongs to whoever runs the runtime. Every ship's file is encrypted under
//! a key derived from it, and so is the file that holds the ship's signing key. A disk that is
//! stolen, or a ship's file that is copied off the machine, cannot be read without it. It does
//! not hide anything from whoever runs the runtime: a ship cannot run unless its file can be
//! read, so that person has to have the key.
//!
//! The recovery code belongs to the ship's owner. It is not something more to keep: it is
//! derived from the master ticket the owner already holds for the ship's Urbit ID, as a
//! branch of its own (`urbit_id::Wallet::backup_code`), so whoever holds the ticket holds
//! the code. An exported copy of a ship is sealed so that only someone who has the code
//! can open it. The ship keeps the
//! public half of a key pair made from the code, which is enough to seal a copy and no use
//! for opening one. So a copy can be made at any time with nobody present, by a host on a
//! schedule for instance, and the host cannot read what it has made.

use std::fmt;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hkdf::{Salt, HKDF_SHA256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The key the operator of a runtime holds. Everything the runtime keeps on disk for its
/// ships is encrypted under keys derived from it.
#[derive(Clone)]
pub struct StorageKey([u8; 32]);

impl StorageKey {
    pub fn new(bytes: [u8; 32]) -> StorageKey {
        StorageKey(bytes)
    }

    /// A key written as 64 hexadecimal digits, as it might be kept in a secret store.
    pub fn from_hex(hex: &str) -> Option<StorageKey> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).ok()?;
        }
        Some(StorageKey(bytes))
    }
}

/// Never printed, however the configuration it sits in is logged.
impl fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageKey(..)")
    }
}

/// The labels that go into deriving a key, one for each use, so that a key made for one
/// purpose is never the key for another.
const FILE_LABEL: &[u8] = b"ship.v1.file\n";
const SIGNING_LABEL: &[u8] = b"ship.v1.signing\n";
const RECOVERY_LABEL: &[u8] = b"ship.v1.recovery\n";
const EXPORT_LABEL: &[u8] = b"ship.v1.export\n";
const CHECK_LABEL: &[u8] = b"ship.v1.check\n";
/// For the chunks of the files a ship keeps on disk, one key per upload directory.
const FILES_LABEL: &[u8] = b"ship.v1.files\n";
/// For the stream of a ship's files that goes beside an exported copy.
const FILES_EXPORT_LABEL: &[u8] = b"ship.v1.files-export\n";

/// Thirty-two bytes derived from `secret` for the use `info` names.
fn derive(secret: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let prk = Salt::new(HKDF_SHA256, &[]).extract(secret);
    // Asking for the hash's own length cannot fail.
    prk.expand(info, HKDF_SHA256).and_then(|okm| okm.fill(&mut out)).expect("a key of the hash's own length");
    out
}

/// The key a ship's file is encrypted under. A tool that opens a ship's file directly, with
/// the operator's key in hand, uses this.
pub fn ship_file_key(storage: &StorageKey, ship: &str) -> [u8; 32] {
    derive(&storage.0, &[FILE_LABEL, ship.as_bytes()])
}

/// Something a data directory keeps to tell its storage key by. It is derived from the key
/// for this use alone, so it says nothing about the key or about any key made from it.
pub(crate) fn storage_check(storage: &StorageKey) -> [u8; 32] {
    derive(&storage.0, &[CHECK_LABEL])
}

fn cipher(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("a key of the right length"))
}

/// How long a ship's key file is: a nonce, the key, and the tag that shows it is unchanged.
pub const SIGNING_KEY_FILE_BYTES: usize = 12 + 32 + 16;

/// A ship's signing key as it is kept on disk: under a key derived from the storage key and
/// the ship's name, and bound to that name, so that one ship's key file is of no use as
/// another's.
pub(crate) fn wrap_signing_key(storage: &StorageKey, ship: &str, seed: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    let key = derive(&storage.0, &[SIGNING_LABEL, ship.as_bytes()]);
    let mut sealed = seed.to_vec();
    cipher(&key)
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(ship.as_bytes()), &mut sealed)
        .expect("thirty-two bytes can be sealed");
    [&nonce[..], &sealed].concat()
}

/// The signing key in a ship's key file, if the file is that ship's and the storage key is
/// the one it was written under.
pub fn open_signing_key(storage: &StorageKey, ship: &str, file: &[u8]) -> Option<[u8; 32]> {
    let (nonce, sealed) = (file.get(..12)?, file.get(12..)?);
    let key = derive(&storage.0, &[SIGNING_LABEL, ship.as_bytes()]);
    let mut sealed = sealed.to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce.try_into().ok()?);
    let seed = cipher(&key).open_in_place(nonce, Aad::from(ship.as_bytes()), &mut sealed).ok()?;
    seed.try_into().ok()
}

/// A recovery code as its owner typed it, without the dashes, spaces, and capitals people add.
fn normal(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace() && *c != '-').flat_map(char::to_lowercase).collect()
}

fn recovery_secret(code: &str) -> StaticSecret {
    StaticSecret::from(derive(normal(code).as_bytes(), &[RECOVERY_LABEL]))
}

/// The public half of the key pair a recovery code stands for. This is what a ship is given
/// to keep. It can seal a copy of the ship and cannot open one, so the code itself never has
/// to be shown to the machine the ship runs on.
pub fn recovery_public(code: &str) -> [u8; 32] {
    PublicKey::from(&recovery_secret(code)).to_bytes()
}

/// What an exported copy of a ship begins with.
const EXPORT_MAGIC: &[u8] = b"ship.v1.export\n";

/// The key one exported copy is sealed under: agreed between a key pair made for that copy
/// alone and the recovery key pair, and bound to both public halves and the ship's name.
fn export_key(shared: &[u8; 32], made_for_copy: &[u8; 32], recovery: &[u8; 32], ship: &str) -> [u8; 32] {
    derive(shared, &[EXPORT_LABEL, made_for_copy, recovery, ship.as_bytes()])
}

/// Seal a copy of a ship, its signing key and the contents of its file, so that only the
/// holder of the recovery code can open it. `fresh` is thirty-two random bytes, used for
/// this copy and nothing else.
pub fn seal_export(recovery: &[u8; 32], ship: &str, seed: &[u8; 32], contents: &[u8], fresh: [u8; 32]) -> Vec<u8> {
    let for_copy = StaticSecret::from(fresh);
    let made_for_copy = PublicKey::from(&for_copy).to_bytes();
    let shared = for_copy.diffie_hellman(&PublicKey::from(*recovery)).to_bytes();
    let key = export_key(&shared, &made_for_copy, recovery, ship);
    // One buffer, sealed where it lies: a ship's file can be large.
    let mut sealed = Vec::with_capacity(EXPORT_HEAD + seed.len() + contents.len() + TAG_BYTES);
    sealed.extend_from_slice(EXPORT_MAGIC);
    sealed.extend_from_slice(&made_for_copy);
    sealed.extend_from_slice(seed);
    sealed.extend_from_slice(contents);
    // The key is made for this one copy, so the same nonce is never used with it twice.
    let tag = cipher(&key)
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(EXPORT_MAGIC), &mut sealed[EXPORT_HEAD..])
        .expect("a copy of a ship is far below what one key may seal");
    sealed.extend_from_slice(tag.as_ref());
    sealed
}

/// What comes before the sealed part of a copy: the magic and the public key made for it.
const EXPORT_HEAD: usize = EXPORT_MAGIC.len() + 32;
const TAG_BYTES: usize = 16;

/// Open an exported copy of a ship with its recovery code: the ship's signing key and the
/// contents of its file. `None` if it is not a copy of that ship sealed to that code, or has
/// been changed in any way since it was sealed. The copy is opened where it lies, so nothing
/// the size of a ship's file is held twice.
pub fn open_export(code: &str, ship: &str, mut sealed: Vec<u8>) -> Option<([u8; 32], Vec<u8>)> {
    if !sealed.starts_with(EXPORT_MAGIC) {
        return None;
    }
    let made_for_copy = <[u8; 32]>::try_from(sealed.get(EXPORT_MAGIC.len()..EXPORT_HEAD)?).ok()?;
    let secret = recovery_secret(code);
    let recovery = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(made_for_copy));
    // A copy whose own key makes the agreement come out the same for every code was not
    // sealed to this code, whatever else is true of it.
    if !shared.was_contributory() {
        return None;
    }
    let key = export_key(&shared.to_bytes(), &made_for_copy, &recovery, ship);
    let opened = cipher(&key)
        .open_in_place(Nonce::assume_unique_for_key([0; 12]), Aad::from(EXPORT_MAGIC), &mut sealed[EXPORT_HEAD..])
        .ok()?
        .len();
    // What was sealed is a signing key and then a file. Less than a key is neither, however
    // well it was sealed. (The bytes past what was opened are still there, so this cannot
    // be left to the slice below.)
    if opened < 32 {
        return None;
    }
    let seed = <[u8; 32]>::try_from(sealed.get(EXPORT_HEAD..EXPORT_HEAD + 32)?).ok()?;
    sealed.truncate(EXPORT_HEAD + opened);
    sealed.drain(..EXPORT_HEAD + 32);
    Some((seed, sealed))
}

/// What a chunk file holds besides the chunk: the nonce at its head and the tag at its end.
pub const CHUNK_FILE_OVERHEAD: usize = 12 + TAG_BYTES;

/// The key the chunks in one directory of a ship's file store are encrypted under, and what
/// binds each chunk to its place: the ship, the directory, the chunk's number, and which copy
/// of it this is. A chunk moved to another number, copy, directory or ship does not open.
pub(crate) struct ChunkKey {
    key: LessSafeKey,
    /// The ship's name and then the directory's sixteen bytes. The name comes first and the
    /// directory is of fixed length, so no two (ship, directory) pairs give the same bytes.
    place: Vec<u8>,
}

pub(crate) fn chunk_key(storage: &StorageKey, ship: &str, dir: &[u8; 16]) -> ChunkKey {
    ChunkKey { key: cipher(&derive(&storage.0, &[FILES_LABEL, ship.as_bytes(), dir])), place: [ship.as_bytes(), dir].concat() }
}

impl ChunkKey {
    fn aad(&self, n: u64, gen: &[u8; 16]) -> Vec<u8> {
        [&self.place[..], &n.to_le_bytes(), gen].concat()
    }

    /// Seal copy `gen` of chunk `n` where it lies, appending its tag. The file to write is
    /// `nonce` and then `chunk`. A nonce is random and used once: the same key seals every
    /// chunk of a directory.
    pub fn seal(&self, n: u64, gen: &[u8; 16], nonce: [u8; 12], chunk: &mut Vec<u8>) {
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(self.aad(n, gen)), chunk)
            .expect("a chunk is far below what one key may seal");
    }

    /// Open a chunk file as written for copy `gen` of chunk `n`, where it lies. `None` if it
    /// was not written for this place under this key, or has been changed since.
    pub fn open<'a>(&self, n: u64, gen: &[u8; 16], file: &'a mut [u8]) -> Option<&'a [u8]> {
        if file.len() < CHUNK_FILE_OVERHEAD {
            return None;
        }
        let (nonce, sealed) = file.split_at_mut(12);
        let nonce = Nonce::assume_unique_for_key(<[u8; 12]>::try_from(&*nonce).ok()?);
        let opened = self.key.open_in_place(nonce, Aad::from(self.aad(n, gen)), sealed).ok()?;
        Some(&*opened)
    }
}

/// What a stream of a ship's files begins with: this, then the public key made for it.
pub const FILES_MAGIC: &[u8] = b"ship.v1.files\n";
pub const FILES_HEAD: usize = FILES_MAGIC.len() + 32;
/// How much of the stream each sealed segment carries. Every segment but the last carries
/// exactly this much; the last carries this much or less, and is marked as the last.
pub const SEGMENT_BYTES: usize = 64 << 10;
/// A sealed segment's tag.
pub const SEGMENT_TAG_BYTES: usize = TAG_BYTES;

/// The key one stream of files is sealed under: agreed, as for an exported copy, between a
/// key pair made for this stream alone and the owner's recovery key pair, and bound to both
/// public halves, to `binding` (the hash of the sealed copy the stream goes with), and to the
/// ship's name. A stream is of use only beside the copy it was made with.
fn files_key(shared: &[u8; 32], made_for_stream: &[u8; 32], recovery: &[u8; 32], binding: &[u8; 32], ship: &str) -> [u8; 32] {
    derive(shared, &[FILES_EXPORT_LABEL, made_for_stream, recovery, binding, ship.as_bytes()])
}

/// The nonce for segment number `index`: the number, then whether it is the last. A segment
/// opens only in its own place in its own stream, so a stream cut short, reordered, or with
/// a segment dropped, repeated, or taken from another stream does not open.
fn segment_nonce(index: u64, last: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&index.to_le_bytes());
    nonce[8] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

/// Seals one stream of files, segment by segment, in order.
pub struct StreamSeal {
    key: LessSafeKey,
    next: u64,
}

impl StreamSeal {
    /// Seal the next segment where it lies, appending its tag. `last` marks the final one.
    pub fn seal(&mut self, segment: &mut Vec<u8>, last: bool) {
        let nonce = segment_nonce(self.next, last);
        self.next += 1;
        self.key.seal_in_place_append_tag(nonce, Aad::from(FILES_MAGIC), segment).expect("a segment is small");
    }
}

/// Opens one stream of files, segment by segment, in order.
pub struct StreamOpen {
    key: LessSafeKey,
    next: u64,
}

impl StreamOpen {
    /// Open the next segment where it lies: its sealed bytes and tag. `last` says whether it is
    /// the final one. `None` if it is not the next segment of this stream, or is not the last
    /// when it is said to be, or the other way round.
    pub fn open<'a>(&mut self, segment: &'a mut [u8], last: bool) -> Option<&'a [u8]> {
        let opened = self.key.open_in_place(segment_nonce(self.next, last), Aad::from(FILES_MAGIC), segment).ok()?;
        self.next += 1;
        Some(&*opened)
    }
}

/// Start sealing a stream of a ship's files to its owner's recovery key, beside the sealed
/// copy whose hash is `binding`. Returns the head to write first. `fresh` is thirty-two random
/// bytes, used for this stream and nothing else.
pub fn seal_files_stream(recovery: &[u8; 32], ship: &str, binding: &[u8; 32], fresh: [u8; 32]) -> (Vec<u8>, StreamSeal) {
    let for_stream = StaticSecret::from(fresh);
    let made_for_stream = PublicKey::from(&for_stream).to_bytes();
    let shared = for_stream.diffie_hellman(&PublicKey::from(*recovery)).to_bytes();
    let key = cipher(&files_key(&shared, &made_for_stream, recovery, binding, ship));
    ([FILES_MAGIC, &made_for_stream[..]].concat(), StreamSeal { key, next: 0 })
}

/// Start opening a stream of files with the recovery code, given its head and the hash of the
/// sealed copy it should go with. `None` if the head is not one of a stream sealed to a code.
pub fn open_files_stream(code: &str, ship: &str, binding: &[u8; 32], head: &[u8]) -> Option<StreamOpen> {
    if head.len() != FILES_HEAD || !head.starts_with(FILES_MAGIC) {
        return None;
    }
    let made_for_stream = <[u8; 32]>::try_from(&head[FILES_MAGIC.len()..]).ok()?;
    let secret = recovery_secret(code);
    let recovery = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(made_for_stream));
    if !shared.was_contributory() {
        return None;
    }
    Some(StreamOpen { key: cipher(&files_key(&shared.to_bytes(), &made_for_stream, &recovery, binding, ship)), next: 0 })
}

/// Whether a public key is one a copy can safely be sealed to. A handful of values make
/// every agreement come out the same whatever the other side brings, so a copy sealed to
/// one of them could be opened by anyone.
///
/// A key must also be written the one way `recovery_public` writes it. The same key can be
/// written in other ways that work just as well for sealing, but the bytes as given go into
/// the seal, and the code would then not open what was sealed.
pub fn recovery_key_usable(public: &[u8; 32]) -> bool {
    // The field these keys live in has 2^255 - 19 elements, written low byte first.
    let below_modulus = public[31] < 0x7f || public[1..31].iter().any(|byte| *byte != 0xff) || public[0] < 0xed;
    public[31] & 0x80 == 0
        && below_modulus
        && StaticSecret::from([1; 32]).diffie_hellman(&PublicKey::from(*public)).was_contributory()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_for_one_ship_and_one_use() {
        let (one, other) = (StorageKey::new([1; 32]), StorageKey::new([2; 32]));
        assert_ne!(ship_file_key(&one, "zod"), ship_file_key(&one, "nec"));
        assert_ne!(ship_file_key(&one, "zod"), ship_file_key(&other, "zod"));
        assert_eq!(ship_file_key(&one, "zod"), ship_file_key(&StorageKey::new([1; 32]), "zod"));
        // The key for the file is not the key the signing key is kept under.
        let wrapped = wrap_signing_key(&one, "zod", &[9; 32], [3; 12]);
        let mut as_file_key = wrapped[12..].to_vec();
        let file_key = cipher(&ship_file_key(&one, "zod"));
        assert!(file_key.open_in_place(Nonce::assume_unique_for_key([3; 12]), Aad::from(&b"zod"[..]), &mut as_file_key).is_err());
        assert_eq!(format!("{one:?}"), "StorageKey(..)");
        assert!(StorageKey::from_hex(&"0f".repeat(32)).is_some_and(|key| key.0 == [15; 32]));
        assert!(StorageKey::from_hex("0f").is_none() && StorageKey::from_hex(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn a_signing_key_file_opens_only_for_its_ship_under_its_storage_key() {
        let (storage, seed) = (StorageKey::new([1; 32]), [9u8; 32]);
        let file = wrap_signing_key(&storage, "zod", &seed, [3; 12]);
        assert_eq!(file.len(), 60);
        assert!(!file.windows(4).any(|window| window == [9; 4]), "the key is there to be read");
        assert_eq!(open_signing_key(&storage, "zod", &file), Some(seed));
        // Another ship's name, another storage key, a changed byte, a short file.
        assert_eq!(open_signing_key(&storage, "nec", &file), None);
        assert_eq!(open_signing_key(&StorageKey::new([2; 32]), "zod", &file), None);
        for index in [0, 11, 12, 40, 59] {
            let mut changed = file.clone();
            changed[index] ^= 1;
            assert_eq!(open_signing_key(&storage, "zod", &changed), None, "byte {index}");
        }
        assert_eq!(open_signing_key(&storage, "zod", &file[..59]), None);
        assert_eq!(open_signing_key(&storage, "zod", &seed), None);
    }

    #[test]
    fn a_sealed_copy_opens_only_with_its_recovery_code_for_its_ship_unchanged() {
        let (code, seed, contents) = ("abcde-fghjk-mnpqr-stvwx", [9u8; 32], b"what is in the ship's file".to_vec());
        let public = recovery_public(code);
        let sealed = seal_export(&public, "zod", &seed, &contents, [5; 32]);
        assert!(!sealed.windows(8).any(|window| window == &contents[..8]), "the contents are there to be read");
        assert_eq!(open_export(code, "zod", sealed.clone()), Some((seed, contents.clone())));
        // The code as people type it.
        assert_eq!(open_export(" ABCDE fghjk-MNPQR-stvwx ", "zod", sealed.clone()), Some((seed, contents.clone())));
        // Another code, another ship, a changed byte anywhere, a copy cut short.
        assert_eq!(open_export("abcde-fghjk-mnpqr-stvwy", "zod", sealed.clone()), None);
        assert_eq!(open_export(code, "nec", sealed.clone()), None);
        for index in [0, 14, 15, 46, 47, 80, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert_eq!(open_export(code, "zod", changed), None, "byte {index}");
        }
        assert_eq!(open_export(code, "zod", sealed[..sealed.len() - 1].to_vec()), None);
        assert_eq!(open_export(code, "zod", sealed[..40].to_vec()), None);
        // An empty file seals and opens.
        assert_eq!(open_export(code, "zod", seal_export(&public, "zod", &seed, &[], [5; 32])), Some((seed, Vec::new())));
        // Something sealed to the code that is too short to hold a signing key is not a
        // copy of a ship. Anyone who has the public half can make one.
        for short in [0, 1, 15, 16, 17, 31] {
            let for_copy = StaticSecret::from([5; 32]);
            let made_for_copy = PublicKey::from(&for_copy).to_bytes();
            let shared = for_copy.diffie_hellman(&PublicKey::from(public)).to_bytes();
            let mut body = vec![7u8; short];
            cipher(&export_key(&shared, &made_for_copy, &public, "zod"))
                .seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(EXPORT_MAGIC), &mut body)
                .unwrap();
            assert_eq!(open_export(code, "zod", [EXPORT_MAGIC, &made_for_copy[..], &body].concat()), None, "{short} bytes");
        }
        // A copy that names, as the key made for it, one that makes the agreement come out
        // as nothing whatever the code is. It is sealed correctly under what that gives,
        // and is still not a copy sealed to this code.
        let mut body = [&seed[..], &contents].concat();
        cipher(&export_key(&[0; 32], &[0; 32], &public, "zod"))
            .seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(EXPORT_MAGIC), &mut body)
            .unwrap();
        assert_eq!(open_export(code, "zod", [EXPORT_MAGIC, &[0; 32][..], &body].concat()), None);
        // The public half seals and cannot open: it is not the code.
        assert_ne!(recovery_public(code), recovery_public("abcde-fghjk-mnpqr-stvwy"));
        // Two copies of the same ship do not look alike.
        assert_ne!(sealed, seal_export(&public, "zod", &seed, &contents, [6; 32]));
    }

    const G: [u8; 16] = [5; 16];

    #[test]
    fn a_chunk_opens_only_in_its_own_place() {
        let (storage, dir) = (StorageKey::new([1; 32]), [7u8; 16]);
        let key = chunk_key(&storage, "zod", &dir);
        let mut sealed = b"the chunk's bytes".to_vec();
        key.seal(3, &G, [4; 12], &mut sealed);
        let file = [&[4u8; 12][..], &sealed].concat();
        assert_eq!(file.len(), 17 + CHUNK_FILE_OVERHEAD);
        assert!(!file.windows(5).any(|window| window == b"chunk"), "the chunk is there to be read");
        assert_eq!(key.open(3, &G, &mut file.clone()), Some(&b"the chunk's bytes"[..]));
        // Another number, directory, ship or storage key; a changed byte; a short file.
        assert_eq!(key.open(4, &G, &mut file.clone()), None);
        assert_eq!(key.open(3, &[6; 16], &mut file.clone()), None);
        assert_eq!(chunk_key(&storage, "zod", &[8; 16]).open(3, &G, &mut file.clone()), None);
        assert_eq!(chunk_key(&storage, "nec", &dir).open(3, &G, &mut file.clone()), None);
        assert_eq!(chunk_key(&StorageKey::new([2; 32]), "zod", &dir).open(3, &G, &mut file.clone()), None);
        for index in [0, 11, 12, file.len() - 1] {
            let mut changed = file.clone();
            changed[index] ^= 1;
            assert_eq!(key.open(3, &G, &mut changed), None, "byte {index}");
        }
        assert_eq!(key.open(3, &G, &mut file[..CHUNK_FILE_OVERHEAD - 1].to_vec()), None);
        // The key itself is the directory's: with the same associated data, another
        // directory's key does not open it.
        let elsewhere = ChunkKey { key: chunk_key(&storage, "zod", &[8; 16]).key, place: key.place.clone() };
        assert_eq!(elsewhere.open(3, &G, &mut file.clone()), None);
        // The ship's name and the directory cannot be traded off against each other.
        assert_eq!(chunk_key(&storage, "zo", &[b'd'; 16]).place.len(), 18);
        assert_ne!(chunk_key(&storage, "zod", &[0; 16]).place, chunk_key(&storage, "zo", &[b'd', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).place[..]);
    }

    #[test]
    fn a_stream_opens_only_whole_in_order_and_beside_its_copy() {
        let (code, binding) = ("abcde-fghjk-mnpqr-stvwx", [3u8; 32]);
        let (head, mut seal) = seal_files_stream(&recovery_public(code), "zod", &binding, [5; 32]);
        let segments: Vec<Vec<u8>> = (0..3u8)
            .map(|i| {
                let mut segment = vec![i; 10];
                seal.seal(&mut segment, i == 2);
                segment
            })
            .collect();
        let open = |order: &[usize], last_at: usize| -> bool {
            let Some(mut opener) = open_files_stream(code, "zod", &binding, &head) else { return false };
            order.iter().enumerate().all(|(at, i)| opener.open(&mut segments[*i].clone(), at == last_at).is_some())
        };
        assert!(open(&[0, 1, 2], 2));
        // Reordered, one dropped, one repeated, cut short, or the last not said to be last.
        assert!(!open(&[1, 0, 2], 2) && !open(&[0, 2], 1) && !open(&[0, 0, 1, 2], 3) && !open(&[0, 1], 1) && !open(&[0, 1, 2], 9));
        // Beside another copy, for another ship, or with another code, nothing opens.
        assert!(open_files_stream(code, "zod", &[4; 32], &head).is_some_and(|mut o| o.open(&mut segments[0].clone(), false).is_none()));
        assert!(open_files_stream(code, "nec", &binding, &head).is_some_and(|mut o| o.open(&mut segments[0].clone(), false).is_none()));
        assert!(open_files_stream("another code", "zod", &binding, &head).is_some_and(|mut o| o.open(&mut segments[0].clone(), false).is_none()));
        assert!(open_files_stream(code, "zod", &binding, &head[..FILES_HEAD - 1]).is_none());
        assert!(open_files_stream(code, "zod", &binding, &[FILES_MAGIC, &[0; 32][..]].concat()).is_none());
    }

    #[test]
    fn a_recovery_key_that_is_no_use_is_told_apart() {
        let plain = "0000-0000-0000-0000-0000-0000-0000-0000";
        assert!(recovery_key_usable(&recovery_public(plain)));
        assert!(!recovery_key_usable(&[0; 32]));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(!recovery_key_usable(&one));
        // The same key written another way would seal a copy its code cannot open.
        let (code, seed) = ("abcde-fghjk-mnpqr-stvwx", [9u8; 32]);
        let mut top_bit = recovery_public(code);
        top_bit[31] |= 0x80;
        assert_eq!(open_export(code, "zod", seal_export(&top_bit, "zod", &seed, b"file", [5; 32])), None);
        assert!(!recovery_key_usable(&top_bit));
        // Numbers at and past the end of the field stand for small ones.
        let mut modulus = [0xffu8; 32];
        (modulus[0], modulus[31]) = (0xed, 0x7f);
        let (mut below, mut lower, mut above) = (modulus, modulus, modulus);
        // (One below the end is itself one of the keys that are no use, so two below.)
        (below[0], above[0]) = (0xeb, 0xff);
        (lower[0], lower[9]) = (0xff, 0xfe);
        assert!(!recovery_key_usable(&modulus) && !recovery_key_usable(&above));
        assert!(recovery_key_usable(&below) && recovery_key_usable(&lower));
        let mut high = [0u8; 32];
        (high[0], high[31]) = (9, 0x7f);
        assert!(recovery_key_usable(&high));
    }
}
