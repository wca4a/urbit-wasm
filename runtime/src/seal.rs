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
//! The recovery code belongs to the ship's owner, and to nobody else. An exported copy of a
//! ship is sealed so that only someone who has the code can open it. The ship keeps the
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

/// A new recovery code as its owner sees it: 160 random bits as thirty-two letters and digits
/// in eight groups, from an alphabet with no pairs that look alike (no i, l, o, or u). It is
/// long because nothing slows down someone guessing at it: whoever has a sealed copy can try
/// codes against it for as long as they like.
pub fn recovery_code(random: &[u8; 20]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let letters: Vec<u8> = (0..32)
        .map(|index| {
            // Five bits at a time, counted from the front.
            let (byte, shift) = (index * 5 / 8, index * 5 % 8);
            let pair = (random[byte] as u16) << 8 | random.get(byte + 1).copied().unwrap_or(0) as u16;
            ALPHABET[((pair >> (11 - shift)) & 31) as usize]
        })
        .collect();
    letters.chunks(4).map(|group| String::from_utf8_lossy(group).into_owned()).collect::<Vec<_>>().join("-")
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

    #[test]
    fn a_recovery_code_carries_all_its_random_bits_and_a_weak_key_is_told_apart() {
        assert_eq!(recovery_code(&[0; 20]), "0000-0000-0000-0000-0000-0000-0000-0000");
        assert_eq!(recovery_code(&[255; 20]), "zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz");
        // Every bit of the twenty bytes changes the code.
        let plain = recovery_code(&[0; 20]);
        for bit in 0..160 {
            let mut random = [0u8; 20];
            random[bit / 8] |= 0x80 >> (bit % 8);
            let code = recovery_code(&random);
            assert_eq!(code.chars().zip(plain.chars()).filter(|(a, b)| a != b).count(), 1, "bit {bit}");
            assert_eq!(code.replace('-', "").find(|letter| letter != '0'), Some(bit / 5), "bit {bit}");
        }
        assert!(recovery_key_usable(&recovery_public(&plain)));
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
