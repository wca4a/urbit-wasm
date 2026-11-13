//! From a master ticket to a ship's keys, by the steps of Urbit's HD wallet (UP 8).
//!
//! ```text
//! ticket, ship number
//!   └─ master seed            Argon2u, salted with the ship's number
//!        ├─ ownership seed    (and transfer, spawn, voting: the planet's keys on Ethereum)
//!        ├─ management seed   a phrase of 24 words
//!        │    └─ network seed, for a revision number
//!        │         └─ the ship's two networking keys
//!        └─ backup code       this runtime's own branch, not part of UP 8
//! ```
//!
//! Each branch is a hash of what is above it with the branch's name, so one cannot be
//! worked out from another, and the same ticket gives different keys for different ships.

use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha512};

use crate::argon2::{self, Cost, Kind};
use crate::ob;

/// What Urbit's wallet asks of Argon2: half a gigabyte, once over, in four lanes.
const TICKET_COST: Cost = Cost { lanes: 4, memory_blocks: 512_000, passes: 1 };

/// A wallet: what a master ticket gives for one ship. Making one takes half a gigabyte of
/// memory and a good part of a second, as it is meant to.
pub struct Wallet {
    master: [u8; 32],
    passphrase: String,
}

impl Wallet {
    /// The wallet of the ship with this name, from its master ticket as written. `None` if
    /// either is not written as Urbit writes them.
    pub fn from_ticket(ticket: &str, ship: &str) -> Option<Wallet> {
        Wallet::from_ticket_bytes(&ob::ticket_bytes(ticket)?, ob::ship_number(ship)?, "")
    }

    /// The same, from the ticket's bytes and the ship's number, with the optional passphrase
    /// UP 8 allows on the phrases.
    pub fn from_ticket_bytes(ticket: &[u8], ship: u32, passphrase: &str) -> Option<Wallet> {
        let salt = format!("urbitkeygen{ship}");
        let master = argon2::hash(Kind::U, ticket, salt.as_bytes(), &TICKET_COST, 32)?;
        Some(Wallet { master: master.try_into().ok()?, passphrase: passphrase.to_string() })
    }

    /// The phrase of 24 words that stands for one branch: "ownership", "transfer", "spawn",
    /// "voting" or "management".
    pub fn phrase(&self, branch: &str) -> String {
        let seed: [u8; 32] = Sha256::new().chain_update(self.master).chain_update(branch).finalize().into();
        Mnemonic::from_entropy_in(Language::English, &seed).expect("thirty-two bytes make a phrase").to_string()
    }

    /// The seed of the ship's networking keys, for a revision number. The number starts at
    /// nought and goes up each time the keys are replaced.
    pub fn network_seed(&self, revision: u32) -> [u8; 32] {
        let management = Mnemonic::parse_in_normalized(Language::English, &self.phrase("management")).expect("a phrase this made");
        // A passphrase is put into one standard form first, as BIP39 says, so that the same
        // passphrase typed on two keyboards gives the same keys.
        let stretched = management.to_seed(&self.passphrase);
        let once: [u8; 32] = Sha256::new().chain_update(stretched).chain_update("network").chain_update(revision.to_string()).finalize().into();
        if revision == 0 { once } else { Sha256::digest(once).into() }
    }

    /// The ship's networking keys for a revision number.
    pub fn network_keys(&self, revision: u32) -> NetworkKeys {
        NetworkKeys::from_seed(&self.network_seed(revision))
    }

    /// The code that opens copies of the ship sealed to this wallet. It is a branch of its
    /// own, so that it cannot be worked out from the networking keys, which the machine the
    /// ship runs on has to hold. Not part of UP 8.
    pub fn backup_code(&self) -> String {
        let code: [u8; 32] = Sha256::new().chain_update(self.master).chain_update("ship.v1.backup").finalize().into();
        code.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// A ship's two networking keys, as Urbit ID lists them: one it proves who it is with, and
/// one for encryption. Each is the seed of an ed25519 key pair.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkKeys {
    pub auth: [u8; 32],
    pub crypt: [u8; 32],
}

impl NetworkKeys {
    /// The keys a network seed gives, as `++pit:nu:crub:crypto` in Urbit's standard library
    /// gives them: the seed is hashed, the first half is one key and the second the other.
    pub fn from_seed(seed: &[u8; 32]) -> NetworkKeys {
        // Urbit reads a seed as a number, lowest byte first, where it is written highest first.
        let mut as_urbit_reads_it = *seed;
        as_urbit_reads_it.reverse();
        let hashed: [u8; 64] = Sha512::digest(as_urbit_reads_it).into();
        let (auth, crypt) = hashed.split_at(32);
        NetworkKeys { auth: auth.try_into().expect("half of 64"), crypt: crypt.try_into().expect("half of 64") }
    }

    /// The public half of the authentication key, which is what Azimuth lists for the ship
    /// and what other ships check it against.
    pub fn auth_public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.auth).verifying_key().to_bytes()
    }

    pub fn crypt_public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.crypt).verifying_key().to_bytes()
    }
}

/// Never printed.
impl std::fmt::Debug for NetworkKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkKeys(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Urbit writes keys as numbers, highest byte first; the bytes themselves run the
    /// other way.
    fn as_urbit_writes(bytes: &[u8; 32]) -> String {
        hex(&bytes.iter().rev().copied().collect::<Vec<u8>>())
    }

    fn unhex(hex: &str) -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The vectors of `deriveNetworkKeys` in Urbit's key-generation library, which match
    /// Urbit's own standard library.
    #[test]
    fn a_network_seed_gives_the_keys_urbit_gives() {
        let keys = NetworkKeys::from_seed(&unhex("88359ba61d766e1c2ec9598831668d4233b0f8f58b29da8cf33d25b2590d62a0"));
        assert_eq!(as_urbit_writes(&keys.crypt), "9c513a22795147661234eea13ee5fa5b1a8b9bed1aa4b1cf87f6bcf353afa8bb");
        assert_eq!(as_urbit_writes(&keys.crypt_public()), "f7187602dff5e3eea27b4c46368601106916d704a2ef2e451838d4ea80b395e0");
        assert_eq!(as_urbit_writes(&keys.auth), "52c830cd009a4c6599778b258fa8898cb8b49dd71279c7ca502cb04c2f530d7a");
        assert_eq!(as_urbit_writes(&keys.auth_public()), "9a09b7e816467b10ebdcd47d71861a2d0896189f2e66690b636ad3bdf8fcc343");

        let keys = NetworkKeys::from_seed(&unhex("52dc7422d68c0209610502e71009d6e9f054da2accafb612180c853f3f77d606"));
        assert_eq!(as_urbit_writes(&keys.crypt), "972bd3bc056ac414a3c38bc948a74506120b2fc84ae22ba605c9eeef2b7cc1db");
        assert_eq!(as_urbit_writes(&keys.crypt_public()), "fadea0a37e6d111eb0806648fa66d689f200f38cfd1e3fe683fc148d76c69d27");
        assert_eq!(as_urbit_writes(&keys.auth), "25619a9ce9458f869f064ca5693785283a20aa7a8433baf5fcccbb0a84f76cae");
        assert_eq!(as_urbit_writes(&keys.auth_public()), "76fa3a858dfeb18fd7cd1a63b2fe84f95840e3e5b19e0e6950692cbdc55f3821");
        assert_eq!(format!("{keys:?}"), "NetworkKeys(..)");
    }

    /// The test wallets of Urbit's key-generation library (0.20.1): a galaxy, a star and a
    /// planet, short tickets and the longest, with and without a passphrase.
    #[test]
    fn a_ticket_gives_the_wallet_urbit_gives() {
        let long = "~wacfus-dabpex-danted-mosfep-pasrud-lavmer-nodtex-taslus-pactyp-milpub-pildeg-fornev-ralmed-dinfeb-fopbyr-sanbet-sovmyl-dozsut-mogsyx-mapwyc-sorrup-ricnec-marnys-lignex";
        let known = [
            ("~doznec-marbud", 1, "", "fabric impulse bone solar six turkey midnight loud pizza catalog diet slice problem hover market type light shift response fit fantasy glory member wisdom", "veteran flash code abuse course front better grace fabric chef puzzle outside visual sauce spice auction cactus galaxy need view tomorrow spirit chimney course"),
            ("~marbud-tidsev-litsut-hidfep", 65012, "", "polar rich inch innocent image swear among sense rent kit bench scissors menu coil sunny plate virus robot neutral craft have attend wish pig", "know legal prefer express valve minor tornado three have future bean acoustic sound helmet crane bronze also royal choice expire dust priority nation wide"),
            (long, 222, "froot loops", "ability hill trap old orbit sing fine fashion tragic remove danger absurd outer bid settle winter frown element present member manage zebra loud leopard", "pact range install display tower curve remind click detail ecology like debate luggage bless scissors taste sun leaf flash inhale myth finish vapor father"),
            ("~doznec-marbud", 0, "", "degree crime auto culture problem polar neither senior east rabbit erode wink avocado profit mandate interest display feature baby elite brisk battle food salad", "easily there citizen popular super other verb average august corn assault guard scatter spin quiz brass tooth chase mosquito oblige relief purity chronic race"),
            ("~doznec-marbud", 16_777_215, "", "coast pill lecture express front endless arctic swarm escape impose slush trust trigger churn culture tag direct net amount comic shoot way climb blur", "convince globe olive leaf avocado angry prefer describe phone almost survey dolphin dice toy glove fortune obvious hat viable provide whip silver uphold sick"),
        ];
        let mut codes = Vec::new();
        for (ticket, ship, passphrase, ownership, management) in known {
            let wallet = Wallet::from_ticket_bytes(&ob::written_bytes(ticket).unwrap(), ship, passphrase).unwrap();
            assert_eq!(wallet.phrase("ownership"), ownership, "{ticket} for {ship}");
            assert_eq!(wallet.phrase("management"), management, "{ticket} for {ship}");
            codes.push(wallet.backup_code());
            if ship != 65012 {
                continue;
            }
            // The star's wallet was made with its networking keys.
            assert_eq!(hex(&wallet.network_seed(0)), "bd9d88d3096603b5de362259e97b78b4d9ca21c8d4e264ac698cabde683b936a");
            let keys = wallet.network_keys(0);
            assert_eq!(as_urbit_writes(&keys.crypt), "cc3388537bf91f941a7aaf2b007ae010bee594ce5814ad930c2e1c72e8b11e3f");
            assert_eq!(as_urbit_writes(&keys.crypt_public()), "6889eede94634a060d3403ca06531bc38bb4a44ac68e6cea99c2c3b7e76f3a8a");
            assert_eq!(as_urbit_writes(&keys.auth), "4bd50bfda11ff12623b56a4c20bb9821ea41a2f4b125e9af0b195c4df833fe7c");
            assert_eq!(as_urbit_writes(&keys.auth_public()), "25bd0bb620181c1c80f807a04bb7d7701711bdf6793ddbf9ed49d6f03fbba34f");
            // The same wallet from the ticket and the name as they are written.
            let written = Wallet::from_ticket(ticket, "~matbyr").unwrap();
            assert!(written.network_keys(0) == keys && written.backup_code() == wallet.backup_code());
            // Each revision has keys of its own, and a later one is hashed once more than the first.
            let (first, second, third) = (wallet.network_seed(0), wallet.network_seed(1), wallet.network_seed(2));
            assert!(first != second && second != third && first != third);
            let stretched = Mnemonic::parse_in_normalized(Language::English, management).unwrap().to_seed_normalized("");
            let once: [u8; 32] = Sha256::new().chain_update(stretched).chain_update("network1").finalize().into();
            assert_eq!(second, <[u8; 32]>::from(Sha256::digest(once)));
            // The backup code is a branch of its own: it is not a key the ship runs with.
            let code = wallet.backup_code();
            assert_eq!(code.len(), 64);
            assert!(code != hex(&keys.auth) && code != hex(&keys.crypt) && code != hex(&first));
            // Nor is it any branch of Urbit's own wallet under another name.
            for branch in ["ownership", "transfer", "spawn", "voting", "management", "network", "network0"] {
                let phrase = Mnemonic::parse_in_normalized(Language::English, &wallet.phrase(branch)).unwrap();
                assert_ne!(code, hex(&phrase.to_entropy()), "{branch}");
            }
        }
        // A passphrase with an accent in it gives the same keys however the accent was typed:
        // as one letter, or as a letter and a mark.
        let ticket = ob::written_bytes("~doznec-marbud").unwrap();
        let (one_letter, letter_and_mark) = ("caf\u{e9}", "cafe\u{301}");
        let typed = |passphrase: &str| Wallet::from_ticket_bytes(&ticket, 1, passphrase).unwrap().network_seed(0);
        assert_eq!(typed(one_letter), typed(letter_and_mark));
        assert_ne!(typed(one_letter), typed("cafe"));
        // The same ticket gives another ship another backup code.
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), 5);
        // A ticket or a name that is not one gives nothing, before any work is done.
        assert!(Wallet::from_ticket("~doznec-marbud", "~zod").is_none());
        assert!(Wallet::from_ticket("~marbud-tidsev-litsut-hidfep", "~not-a-ship").is_none());
    }
}
