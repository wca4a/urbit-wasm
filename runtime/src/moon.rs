//! Moons: ships that belong to another ship, and are in no public list.
//!
//! A galaxy, star or planet has its key in Azimuth, where anyone can look it up. A moon does
//! not. Its number is its parent's with more in front, and the parent alone decides what
//! its key is. On Urbit, other ships learn a moon's key by asking the parent, so a moon
//! cannot meet anyone new while its parent is switched off.
//!
//! Here the parent signs a short statement instead: "this moon, at this revision of its
//! keys, has this key". The moon carries that with it and shows it to each ship it meets,
//! which checks the signature against the parent's key from Azimuth. So a moon needs
//! nothing from its parent after it is made.
//!
//! What this cannot do is take a moon's key back at once. A ship that has seen a later
//! revision of a moon refuses earlier ones, but a ship that has not will go on believing an
//! old statement until the parent changes its own key, which ends every statement it has
//! signed.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// What goes in front of the statement, so that a signature on it can never be taken for a
/// signature on anything else a ship signs.
const LABEL: &[u8] = b"ship.v1.moon\n";

/// A parent's word for its moon's key: the revision, and the signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub revision: u32,
    pub signed: [u8; 64],
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proof(revision {})", self.revision)
    }
}

/// How a proof is kept in a ship's file: the revision, then the signature.
pub const PROOF_BYTES: usize = 68;

impl Proof {
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES] {
        let mut bytes = [0; PROOF_BYTES];
        bytes[..4].copy_from_slice(&self.revision.to_be_bytes());
        bytes[4..].copy_from_slice(&self.signed);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Proof> {
        let bytes: &[u8; PROOF_BYTES] = bytes.try_into().ok()?;
        Some(Proof { revision: u32::from_be_bytes(bytes[..4].try_into().ok()?), signed: bytes[4..].try_into().ok()? })
    }
}

fn statement(moon: u64, revision: u32, key: &[u8; 32]) -> Vec<u8> {
    [LABEL, &moon.to_be_bytes(), &revision.to_be_bytes(), key].concat()
}

/// A parent's word that `key` is the key of its moon `moon` at `revision`.
pub fn vouch(parent: &SigningKey, moon: u64, revision: u32, key: &[u8; 32]) -> Proof {
    Proof { revision, signed: parent.sign(&statement(moon, revision, key)).to_bytes() }
}

/// Whether `proof` is the word of the holder of `parent` that `key` is the moon's key.
pub fn holds(parent: &[u8; 32], moon: u64, key: &[u8; 32], proof: &Proof) -> bool {
    let Ok(parent) = VerifyingKey::from_bytes(parent) else { return false };
    parent.verify_strict(&statement(moon, proof.revision, key), &Signature::from_bytes(&proof.signed)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parents_word_holds_for_the_moon_the_revision_and_the_key_it_names_and_nothing_else() {
        let (parent, other) = (SigningKey::from_bytes(&[1; 32]), SigningKey::from_bytes(&[2; 32]));
        let (moon, key) = (7u64 << 32 | 65_536, [9; 32]);
        let proof = vouch(&parent, moon, 3, &key);
        let public = parent.verifying_key().to_bytes();
        assert!(holds(&public, moon, &key, &proof));
        assert_eq!(Proof::from_bytes(&proof.to_bytes()), Some(proof));
        // Another moon, another key, another revision, another parent.
        assert!(!holds(&public, moon + 1, &key, &proof));
        assert!(!holds(&public, moon ^ 1 << 40, &key, &proof));
        assert!(!holds(&public, moon, &[8; 32], &proof));
        assert!(!holds(&public, moon, &key, &Proof { revision: 4, ..proof }));
        assert!(!holds(&other.verifying_key().to_bytes(), moon, &key, &proof));
        // A signature that has been touched, and a parent's key that is not a key.
        let mut touched = proof;
        touched.signed[10] ^= 1;
        assert!(!holds(&public, moon, &key, &touched));
        assert!(!holds(&[0xff; 32], moon, &key, &proof));
        // A signature by the same parent on something else it signs is not a proof.
        let entry = parent.sign(&[b"ship.v1.entry\n".as_slice(), &moon.to_be_bytes(), &3u32.to_be_bytes(), &key].concat());
        assert!(!holds(&public, moon, &key, &Proof { revision: 3, signed: entry.to_bytes() }));
        // Nor is one on the same words with nothing in front to say what they are.
        let bare = parent.sign(&[&moon.to_be_bytes()[..], &3u32.to_be_bytes(), &key].concat());
        assert!(!holds(&public, moon, &key, &Proof { revision: 3, signed: bare.to_bytes() }));
        // Each of the three things said is in what is signed: leave any one out, and what
        // was signed is something else.
        for partial in [[&3u32.to_be_bytes()[..], &key].concat(), [&moon.to_be_bytes()[..], &key].concat(), [&moon.to_be_bytes()[..], &3u32.to_be_bytes()].concat()] {
            let signed = parent.sign(&[LABEL, &partial].concat()).to_bytes();
            assert!(!holds(&public, moon, &key, &Proof { revision: 3, signed }));
        }
        // Kept in a ship's file as so many bytes, and nothing else is one.
        assert_eq!(Proof::from_bytes(&[0; 67]), None);
        assert_eq!(Proof::from_bytes(&[0; 69]), None);
        assert_eq!(proof.to_bytes()[..4], [0, 0, 0, 3]);
    }
}
