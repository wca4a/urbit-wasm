//! Urbit ID's keys, as Urbit itself derives them.
//!
//! A planet's owner holds one secret, the master ticket. Everything else comes from it by
//! fixed steps (Urbit's HD wallet, proposal UP 8): the keys that own and manage the planet
//! on Ethereum, and the networking keys its ship runs with. This crate does the part a ship
//! needs: from a ticket and a ship's name to its networking keys, and reading and writing
//! the keyfile a ship is started from. It is checked against the test vectors of Urbit's
//! own key-generation library, so that a real planet's ticket gives here the keys it gives
//! there.

pub mod argon2;
pub mod keyfile;
pub mod naive;
pub mod ob;
mod syllables;
pub mod wallet;

pub use keyfile::Keyfile;
pub use wallet::{NetworkKeys, Wallet};
