//! How ships reach each other: an encrypted link in which each end has proved who it is.
//!
//! Two ships talk over QUIC, which is encrypted and runs over UDP. There is no certificate
//! authority. Each ship has a key, and a directory says which key belongs to which ship and
//! where that ship can be reached. When a connection is made, each end shows its key and
//! proves it holds the private half by signing with it, and the other end checks that key
//! against the directory: the caller checks it reached the ship it meant to, and the ship
//! called learns which ship is calling.
//!
//! What is sent, and the keys each end shows, are encrypted. Someone watching the network
//! still sees which ship is being called, that this protocol is in use, the addresses at each
//! end, and how much is sent and when.
//!
//! One runtime has one address for all the ships it holds, and answers as whichever of them
//! the caller names. Two ships in the same runtime talk this way too.
//!
//! Over the link, ships carry commands to each other. A command an agent sends to another
//! ship is kept by the sending ship, numbered, until the other ship says it has it; the other
//! ship takes commands strictly in order and passes over any it has taken before. So each
//! arrives exactly once, in the order sent, however many times the link drops or either side
//! restarts in between. When the other ship has run a command, or refused it, it sends back a
//! receipt the same way, so every command is answered exactly once too. This module only
//! carries them, and sees that what a ship has taken gets run: the numbering and the queues
//! are in each ship's file.
//!
//! Ships also follow each other's logs over the link. A ship that publishes a log tells each
//! ship that follows it when the log has grown. That is only a prompt: the ship that follows
//! then asks for the entries after the last one it holds, checks each against the publisher's
//! key and against the entry before it, and keeps them for its agent. Asking is what moves
//! entries, so a ship takes them when it has room, and one that has been away, or has gone
//! back to an earlier state, catches up by asking from wherever it stands.
//!
//! The directory's keys come from Urbit ID: a ship's key is the one Azimuth lists for its
//! name, read when the ship is first met and again every so often (see `crate::azimuth`).
//! A moon, which Azimuth does not list, shows its parent's signed word for its key (see
//! `crate::moon`). Since nothing can be looked up by key, the ship that makes a connection
//! says which ship it is, as the first thing on it, and is believed only if the key it
//! proved it holds is the one listed for that name. A directory can also be a fixed list,
//! handed in by whoever starts the network, which is how the tests run.
//!
//! Where a ship is to be found is not in Urbit ID, and is still a list handed in. A wrong
//! address there cannot pass one ship off as another: whatever answers must still prove
//! the key. A ship's own key does not change while its runtime runs.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, IdleTimeout, Incoming, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use ship_proto::{
    peer_reply, peer_request, Deliver, Delivered, Fetch, Heard, Hello, Message, MoonProof, News, PeerReply, PeerRequest, Ping, Pong, Resync,
    Resynced, Standing, Welcome,
};
use tokio::sync::Semaphore;

use urbit_id::ob;

use crate::azimuth::{Keys, Listing};
use crate::moon;
use crate::ship::Taken;
use crate::store::{PeerWork, Stand, MAX_BATCH_MESSAGES, MAX_FETCH_ENTRIES, MAX_NEWS_LOGS};
use crate::{canonical_ship, lock, Acked, Error, Runtime};

/// The name of this protocol, agreed while connecting. A connection that does not ask for it
/// is not one of ours.
const PROTOCOL: &[u8] = b"ship/1";

/// The longest any time limit here may be set to.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// The most a ship's first words on a connection, or the answer to them, may come to.
const MOST_HELLO_BYTES: usize = 1024;

/// How many callers nothing is known of may be looked up in Urbit ID in a second, and at a
/// stroke. Anyone can say any name, and each name not yet known costs questions to an
/// Ethereum node: without a limit, callers could have this runtime ask as fast as they
/// can connect. Past it a new caller is turned away, and tries again.
const MOST_MEETINGS: u32 = 32;

/// How many ships may be waiting to be asked about, or being asked about, at once. Past
/// this a new name is not asked about, and whoever wanted it tries again later. Half are
/// kept back for the ships this runtime's own ships want to call, so that callers saying
/// names cannot take them all.
const MOST_LOOKUPS: usize = 64;

/// How many questions to Urbit ID may be out at once.
const MOST_READING: usize = 8;

/// Room in a request for what goes round a command: names, numbers, and framing.
const MESSAGE_ENVELOPE_BYTES: usize = 4096;

/// The smallest a ship's file may be allowed to grow to, for a runtime that goes on the
/// network. A ship refuses outright any command larger than a quarter of its file, and takes
/// any other when it has room. For that to hold, an empty ship must have room for a quarter
/// of its file on top of what every ship file needs just to exist, which is some tens of
/// kilobytes. Below this size it would not, and a command could wait for ever.
const MIN_SHIP_BYTES: u64 = 256 << 10;

/// What the directory knows about a ship: its key and where to reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub key: [u8; 32],
    pub addr: SocketAddr,
}

/// How a ship's key came to be listed.
#[derive(Clone, Copy)]
enum From {
    /// Put there by whoever runs this runtime. It stands until they change it.
    Set,
    /// Read from Urbit ID, at this moment, as this revision of the ship's keys. `doubted`
    /// once something has suggested it is out of date: it still stands, and is read again
    /// at the next chance.
    Read { at: Instant, revision: u32, doubted: bool },
    /// Urbit ID said, at this moment, that the ship's keys had been taken away, as of this
    /// revision. Kept in the place of a key that was held, so that an answer from before
    /// they were taken away is known for the old one it is. There is no key here.
    Cleared { at: Instant, revision: u32 },
    /// A moon's: its parent has given its word for it, at this revision, signing with the
    /// key `by`. It stands for as long as that is the parent's key.
    Vouched { revision: u32, by: [u8; 32] },
}

#[derive(Clone, Copy)]
struct Entry {
    key: [u8; 32],
    from: From,
    /// Whether the ship has ever proved, on a connection, that it holds the key held for
    /// it here, or has had a moon's proof checked against that key. Until then the key is
    /// here only because someone said the ship's name, and it may be dropped to make room
    /// for another like it. After, what is kept of the ship is never dropped for room
    /// while it is still believed, through every later change of its keys: it is what
    /// keeps an older key of the ship's from being taken for a newer one.
    proved: bool,
}

#[derive(Default)]
struct Listed {
    keys: HashMap<String, Entry>,
    places: HashMap<String, SocketAddr>,
    /// When Urbit ID was last asked about a ship, and whether it gave an answer.
    asked: HashMap<String, (Instant, bool)>,
    /// Why the last question to Urbit ID that failed did, or the last key that could not
    /// be kept was not.
    trouble: Option<String>,
}

/// How many ships a directory keeps keys for.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Ships that have proved their keys, moons included. These are never dropped for room
    /// while they are believed, so past this a new ship cannot be met until some lapse.
    pub proved: usize,
    /// Ships whose keys were read because their names were said, and that have proved
    /// nothing yet. Past this the oldest are dropped. Anyone can say any name, so this is
    /// kept apart from the ships that have proved their keys, and small. There is always
    /// room for one: a ship cannot prove its key before its key has been read.
    pub unproved: usize,
    /// Moons in all, and moons of any one ship. A moon costs its parent nothing to make,
    /// so without these one ship, or a few, could take all the room there is.
    pub moons: usize,
    pub moons_each: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds { proved: 1 << 16, unproved: 4096, moons: 1 << 15, moons_each: 256 }
    }
}

/// The most ships a directory remembers having asked about.
const MOST_ASKED: usize = 1 << 16;

/// Which key belongs to which ship, and where each ship is.
pub struct Directory {
    /// Where keys are read from. With none, the directory is a fixed list.
    keys: Option<Arc<dyn Keys>>,
    fresh_for: Duration,
    good_for: Duration,
    bounds: Bounds,
    listed: RwLock<Listed>,
    /// Ships Urbit ID is being asked about at this moment. One question about a ship at a
    /// time: two answers arriving out of order could otherwise put an old key back.
    reading: Mutex<HashSet<String>>,
    read_done: std::sync::Condvar,
}

/// A ship's place among those being asked about, given up when the asking is over,
/// however it ends.
struct Reading<'a>(&'a Directory, &'a str);

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        lock(&self.0.reading).remove(self.1);
        self.0.read_done.notify_all();
    }
}

impl fmt::Debug for Directory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Directory")
    }
}

/// Whether Urbit ID should be asked about a ship.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Due {
    /// No: what is held is recent, or was just asked for, or does not come from Urbit ID.
    No,
    /// What is held will do for now, and should be read again.
    Soon,
    /// Nothing usable is held. Ask before going on.
    Now,
}

/// After Urbit ID has failed to answer about a ship, how long before it is asked again.
/// Also how often a ship can be asked about again because its key looked out of date.
const ASK_AGAIN: Duration = Duration::from_secs(5);

/// The ship a moon belongs to, by name, if the name is a moon's.
fn parent_of(name: &str) -> Option<String> {
    let moon = ob::moon_number(name)?;
    Some(ob::ship_name(ob::moon_parent(moon)).trim_start_matches('~').to_string())
}

/// What is needed to call a ship: where it is, and its key if that is known. For a moon
/// met for the first time the key is not known, and its parent's is.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Reach {
    key: Option<[u8; 32]>,
    addr: SocketAddr,
}

impl Directory {
    /// A directory that is a fixed list: every ship in it is put there with `set`.
    pub fn new() -> Arc<Directory> {
        Directory::made(None, Duration::MAX, Duration::MAX, Bounds::default())
    }

    /// A directory whose keys are read from Urbit ID. A key is read again once it is five
    /// minutes old, and is no longer believed once it is a day old and cannot be read again.
    pub fn reading(keys: Arc<dyn Keys>) -> Arc<Directory> {
        Directory::reading_with(keys, Duration::from_secs(300), Duration::from_secs(24 * 60 * 60))
    }

    /// The same, saying how old a key may be before it is read again (`fresh_for`), and how
    /// old before it is no longer believed (`good_for`), which is the longer.
    pub fn reading_with(keys: Arc<dyn Keys>, fresh_for: Duration, good_for: Duration) -> Arc<Directory> {
        Directory::reading_within(keys, fresh_for, good_for, Bounds::default())
    }

    /// The same, saying also how many ships it keeps keys for.
    pub fn reading_within(keys: Arc<dyn Keys>, fresh_for: Duration, good_for: Duration, bounds: Bounds) -> Arc<Directory> {
        Directory::made(Some(keys), fresh_for, good_for.max(fresh_for), bounds)
    }

    fn made(keys: Option<Arc<dyn Keys>>, fresh_for: Duration, good_for: Duration, bounds: Bounds) -> Arc<Directory> {
        let bounds = Bounds { unproved: bounds.unproved.max(1), ..bounds };
        Arc::new(Directory { keys, fresh_for, good_for, bounds, listed: RwLock::default(), reading: Mutex::default(), read_done: std::sync::Condvar::new() })
    }

    /// List a ship, or change what is listed for it. A key can be set for only one ship.
    /// What is set this way is not read from Urbit ID, and stands until it is changed.
    pub fn set(&self, ship: &str, key: [u8; 32], addr: SocketAddr) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if listed.keys.iter().any(|(other, entry)| *other != name && entry.key == key && matches!(entry.from, From::Set)) {
            return Err(Error::InvalidName(format!("{name}: its key is already listed for another ship")));
        }
        listed.keys.insert(name.clone(), Entry { key, from: From::Set, proved: true });
        listed.places.insert(name, addr);
        Ok(())
    }

    /// Say where a ship is to be found, and leave its key to Urbit ID, or for a moon to its
    /// parent's word.
    pub fn place(&self, ship: &str, addr: SocketAddr) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if !listed.places.contains_key(&name) && listed.places.len() >= MOST_ASKED {
            return Err(Error::InvalidName(format!("{name}: this directory has places for as many ships as it may")));
        }
        listed.places.insert(name, addr);
        Ok(())
    }

    pub fn remove(&self, ship: &str) {
        if let Ok(name) = canonical_ship(ship) {
            let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
            listed.keys.remove(&name);
            listed.places.remove(&name);
        }
    }

    /// A ship's key and where it is, if both are known.
    pub fn lookup(&self, ship: &str) -> Option<Peer> {
        let name = canonical_ship(ship).ok()?;
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        Some(Peer { key: self.held(&listed, &name)?, addr: *listed.places.get(&name)? })
    }

    /// The key listed for a ship, if one is, and is still to be believed.
    pub fn key_of(&self, ship: &str) -> Option<[u8; 32]> {
        let name = canonical_ship(ship).ok()?;
        self.held(&self.listed.read().unwrap_or_else(|e| e.into_inner()), &name)
    }

    /// Why the last question to Urbit ID that failed did, or why the last key that could
    /// not be kept was not, if either has happened.
    pub fn trouble(&self) -> Option<String> {
        self.listed.read().unwrap_or_else(|e| e.into_inner()).trouble.clone()
    }

    fn held(&self, listed: &Listed, name: &str) -> Option<[u8; 32]> {
        let entry = listed.keys.get(name)?;
        match entry.from {
            From::Set => Some(entry.key),
            From::Read { at, .. } => (at.elapsed() < self.good_for).then_some(entry.key),
            From::Cleared { .. } => None,
            // A moon's key stands on its parent's. A moon has no moons, so this goes one
            // step and no further.
            From::Vouched { by, .. } => {
                let parent = parent_of(name)?;
                let stands = listed.keys.get(&parent).is_some_and(|parent| !matches!(parent.from, From::Vouched { .. }));
                (stands && self.held(listed, &parent) == Some(by)).then_some(entry.key)
            }
        }
    }

    /// The key held for a ship that has proved it holds it: the key a connection from
    /// that ship is taken on.
    fn proved_key_of(&self, name: &str) -> Option<[u8; 32]> {
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        self.held(&listed, name).filter(|_| listed.keys.get(name).is_some_and(|entry| entry.proved))
    }

    /// What is needed to call a ship, as things stand.
    fn reach(&self, name: &str) -> Option<Reach> {
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        let addr = *listed.places.get(name)?;
        match self.held(&listed, name) {
            Some(key) => Some(Reach { key: Some(key), addr }),
            // A moon whose key is not known can be asked for its parent's word, provided
            // the parent's key is known to check that word against.
            None => self.held(&listed, &parent_of(name)?).map(|_| Reach { key: None, addr }),
        }
    }

    /// Whether Urbit ID should be asked about a ship. Only galaxies, stars and planets are
    /// asked about: for a moon, the ship to ask about is its parent.
    fn due(&self, name: &str) -> Due {
        if self.keys.is_none() || ob::ship_number(name).is_none() {
            return Due::No;
        }
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        let asked = listed.asked.get(name).map(|(at, answered)| (at.elapsed(), *answered));
        let lately = asked.is_some_and(|(since, _)| since < ASK_AGAIN.min(self.fresh_for));
        match listed.keys.get(name).map(|entry| entry.from) {
            Some(From::Set | From::Vouched { .. }) => Due::No,
            Some(From::Read { at, doubted, .. }) if at.elapsed() < self.good_for => {
                if (doubted || at.elapsed() >= self.fresh_for) && !lately { Due::Soon } else { Due::No }
            }
            Some(From::Cleared { at, .. }) if at.elapsed() < self.fresh_for => Due::No,
            // Nothing held. If Urbit ID said so itself not long ago, that answer stands.
            _ if lately || asked.is_some_and(|(since, answered)| answered && since < self.fresh_for) => Due::No,
            _ => Due::Now,
        }
    }

    /// Ask Urbit ID about a ship and keep the answer. This waits on the network.
    ///
    /// One question about a ship is out at a time. A second asker waits for the first one's
    /// answer and takes that. And by the time this gets to ask, the answer may already be
    /// there, in which case nothing is asked.
    fn read(&self, name: &str) {
        let (Some(keys), Some(number)) = (&self.keys, ob::ship_number(name)) else { return };
        {
            let mut reading = lock(&self.reading);
            if reading.contains(name) {
                while reading.contains(name) {
                    reading = self.read_done.wait(reading).unwrap_or_else(|e| e.into_inner());
                }
                return;
            }
            reading.insert(name.to_string());
        }
        let _asking = Reading(self, name);
        if self.due(name) == Due::No {
            return;
        }
        let answer = keys.listing(number);
        let now = Instant::now();
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if !listed.asked.contains_key(name) && listed.asked.len() >= MOST_ASKED {
            // Forget having asked about ships nothing is held for, and if that is not
            // enough, about all of them. The cost is asking again sooner than need be.
            let Listed { keys, asked, .. } = &mut *listed;
            asked.retain(|name, _| keys.contains_key(name));
            if asked.len() >= MOST_ASKED {
                asked.clear();
            }
        }
        listed.asked.insert(name.to_string(), (now, answer.is_ok()));
        let held = listed.keys.get(name).copied();
        // How many times the ship's keys had been set, as far as is still believed here,
        // and as far as this answer says. No such ship is none at all.
        let believed = match held.map(|entry| entry.from) {
            Some(From::Read { at, revision, .. } | From::Cleared { at, revision }) if at.elapsed() < self.good_for => Some(revision),
            _ => None,
        };
        let said = match &answer {
            Ok(listing) => Some(listing.map_or(0, |listing| listing.revision)),
            Err(_) => None,
        };
        // Whether the ship has ever proved a key goes with the ship, whatever its keys
        // become.
        let proved = held.is_some_and(|entry| entry.proved);
        match answer {
            _ if matches!(held, Some(Entry { from: From::Set, .. })) => {}
            // A ship's keys are counted upwards and never back. An answer with a lower
            // count than the one still believed is from somewhere that is behind, and is
            // not taken, whatever it says: it would put back a key that has been replaced,
            // or take away one that has since been set.
            Ok(_) if believed.zip(said).is_some_and(|(believed, said)| said < believed) => {
                listed.trouble = Some(format!("{name}: an answer gave an earlier revision of its keys than the one held"));
            }
            Ok(Some(Listing { key: Some(key), revision, .. })) => {
                if held.is_none() {
                    self.room_for_unproved(&mut listed);
                }
                listed.keys.insert(name.to_string(), Entry { key, from: From::Read { at: now, revision, doubted: false }, proved });
            }
            // The ship has no keys. If it had, what is kept in their place is how many
            // times they have now been set, so that the old ones are not taken back.
            Ok(Some(Listing { key: None, revision, .. })) => {
                if held.is_some() {
                    listed.keys.insert(name.to_string(), Entry { key: [0; 32], from: From::Cleared { at: now, revision }, proved });
                }
            }
            // There is no such ship, and nothing still believed says there was.
            Ok(None) => {
                listed.keys.remove(name);
            }
            // No answer. What was held stands, until it is too old to believe.
            Err(why) => listed.trouble = Some(format!("{name}: {why}")),
        }
    }

    /// Make room for the key of one more ship that has proved nothing yet. There always is
    /// some: past the bound, the older half of such keys are dropped, with the record of
    /// having asked about them, so that they are asked about afresh if they are wanted.
    /// Nothing is lost that meeting those ships for the first time would have had.
    fn room_for_unproved(&self, listed: &mut Listed) {
        if listed.keys.len() < self.bounds.unproved {
            return;
        }
        let read_at = |entry: &Entry| match entry.from {
            From::Read { at, .. } | From::Cleared { at, .. } if !entry.proved => Some(at),
            _ => None,
        };
        let mut unproved: Vec<(Instant, String)> = listed.keys.iter().filter_map(|(name, entry)| Some((read_at(entry)?, name.clone()))).collect();
        if unproved.len() < self.bounds.unproved {
            return;
        }
        unproved.sort();
        for (_, name) in unproved.into_iter().take(self.bounds.unproved / 2 + 1) {
            listed.keys.remove(&name);
            listed.asked.remove(&name);
        }
    }

    /// Whether there is room among the ships that are kept for one more. Only what is no
    /// longer believed is dropped to make it: keys too old, and moons whose parent's word
    /// has lapsed. If that is not enough there is no room, and the ship cannot be met
    /// until there is.
    fn room_for_proved(&self, listed: &mut Listed) -> bool {
        let kept = |listed: &Listed| listed.keys.values().filter(|entry| entry.proved && !matches!(entry.from, From::Set)).count();
        if listed.keys.len() < self.bounds.proved || kept(listed) < self.bounds.proved {
            return true;
        }
        self.drop_lapsed(listed);
        kept(listed) < self.bounds.proved
    }

    /// Drop what is kept and no longer believed, with the record of having asked about it.
    fn drop_lapsed(&self, listed: &mut Listed) {
        let gone = |(name, entry): (&String, &Entry)| match entry.from {
            From::Set => false,
            From::Read { at, .. } | From::Cleared { at, .. } => at.elapsed() >= self.good_for,
            From::Vouched { .. } => self.held(listed, name).is_none(),
        };
        let lapsed: Vec<String> = listed.keys.iter().filter(|(name, entry)| gone((*name, *entry))).map(|(name, _)| name.clone()).collect();
        for name in lapsed {
            listed.keys.remove(&name);
            listed.asked.remove(&name);
        }
    }

    /// A ship has proved, on a connection, that it holds `key`. Whether that is the key
    /// held for it here, and it is now among the ships that are kept. Both are settled in
    /// one step: a connection is taken on the strength of this and nothing looser.
    fn prove(&self, name: &str, key: &[u8; 32]) -> bool {
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if self.held(&listed, name) != Some(*key) {
            return false;
        }
        if listed.keys.get(name).is_some_and(|entry| entry.proved) {
            return true;
        }
        if !self.room_for_proved(&mut listed) {
            listed.trouble = Some(format!("{name}: there is no room to keep another ship's key"));
            return false;
        }
        // Still there: making room drops only what is no longer believed, and this is.
        match listed.keys.get_mut(name) {
            Some(entry) => entry.proved = true,
            None => return false,
        }
        true
    }

    /// Something suggests the key held for a ship is out of date: a ship answering to the
    /// name showed another. The key stands, and is read again at the next chance.
    fn doubt(&self, name: &str) {
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if let Some(Entry { from: From::Read { doubted, .. }, .. }) = listed.keys.get_mut(name) {
            *doubted = true;
        }
    }

    /// Take a moon's key on its parent's word, if the word is good: signed with the key
    /// held for the parent, and not for an earlier revision than one already seen. The
    /// moon has proved it holds the key, so it is kept from here on, and so is its parent,
    /// whose key now has something standing on it.
    fn vouched(&self, name: &str, key: [u8; 32], proof: &moon::Proof) -> Result<(), &'static str> {
        let (Some(number), Some(parent)) = (ob::moon_number(name), parent_of(name)) else { return Err("not a moon") };
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        let by = self.held(&listed, &parent).ok_or("the moon's parent is not listed")?;
        if !moon::holds(&by, number, &key, proof) {
            return Err("not the word of the moon's parent for the key shown");
        }
        match listed.keys.get(name) {
            // Set by whoever runs this runtime, which no word from elsewhere changes.
            Some(Entry { key: set, from: From::Set, .. }) => return if *set == key { Ok(()) } else { Err("another key is set for the moon here") },
            // Under the same key of the parent's: only forwards, and one key to a revision.
            Some(Entry { key: seen, from: From::Vouched { revision, by: then }, .. }) if *then == by => {
                if proof.revision < *revision || (proof.revision == *revision && *seen != key) {
                    return Err("the moon has shown a later key than this one");
                }
            }
            _ => {}
        }
        // The parent first: its key now has something standing on it, and it is kept.
        if listed.keys.get(&parent).is_some_and(|parent| !parent.proved) {
            if !self.room_for_proved(&mut listed) {
                return Err("there is no room to keep the key of the moon's parent");
            }
            if let Some(parent) = listed.keys.get_mut(&parent) {
                parent.proved = true;
            }
        }
        if !listed.keys.contains_key(name) {
            // A moon's name ends with its parent's, written at a planet's length.
            let family = &name[name.len().saturating_sub(14)..];
            let counted = |listed: &Listed| {
                let moons = listed.keys.iter().filter(|(_, entry)| matches!(entry.from, From::Vouched { .. }));
                moons.fold((0, 0), |(all, kin), (other, _)| (all + 1, kin + other.ends_with(family) as usize))
            };
            let full = |(all, kin): (usize, usize)| all >= self.bounds.moons || kin >= self.bounds.moons_each;
            if full(counted(&listed)) {
                self.drop_lapsed(&mut listed);
            }
            if full(counted(&listed)) || !self.room_for_proved(&mut listed) {
                return Err("there is no room to keep another moon's key");
            }
        }
        // Making room drops only what is no longer believed, and the parent is believed.
        if self.held(&listed, &parent) != Some(by) {
            return Err("the moon's parent is not listed");
        }
        listed.keys.insert(name.to_string(), Entry { key, from: From::Vouched { revision: proof.revision, by }, proved: true });
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    /// The UDP address to listen on, such as `0.0.0.0:4433`. Port 0 picks a free one.
    pub addr: String,
    /// How long one request to another ship may take, connecting included.
    pub request_timeout: Duration,
    /// A connection with nothing on it for this long is closed.
    pub idle_timeout: Duration,
    /// How many connections from other ships may be open at once, counting those still being
    /// set up. More are turned away. A calling ship has one connection to each ship it calls
    /// here; a newer one from the same ship replaces the older.
    pub max_connections: usize,
    /// How many other ships this runtime's ships may have connections to at once.
    pub max_calls: usize,
    /// How many requests one connection from another ship may have in progress at once.
    pub max_streams: u32,
    /// The largest request or reply this runtime will take from another ship.
    pub max_message_bytes: usize,
    /// Room for the requests being read from other ships at any moment, all connections
    /// together. Each request being read holds room for the largest it could be, so this over
    /// `max_message_bytes` is how many are read at once. Past that, a request is told to try
    /// again.
    pub max_reading_bytes: usize,
    /// How many requests this runtime's ships may have out to other ships at once. Each may be
    /// holding a reply as large as `max_message_bytes`. Past this, a new request fails at once.
    pub max_requests: usize,
    /// How many pieces of work on ships the network may have in hand at once: taking in
    /// commands, running them, and reading out commands to send. Each holds a thread.
    pub max_working: usize,
    /// How many deliveries of commands and receipts to other ships may be in hand at once.
    /// Each holds a batch as large as half of `max_message_bytes`. Past this, a delivery
    /// waits its turn. Separate from `max_requests`, so that deliveries to ships that are
    /// slow to answer cannot make this runtime's own requests fail.
    pub max_carrying: usize,
    /// After a failed try at carrying commands to a ship, how long before the next. It doubles
    /// with each failure, up to `max_retry_delay`, and starts over after a success.
    pub retry_delay: Duration,
    pub max_retry_delay: Duration,
    /// How often each ship that follows logs on another ship asks that ship for its mark,
    /// to see whether it is still the copy of itself it was. A ship brought back from a
    /// saved copy may no longer know who follows it, and would never say when its logs
    /// grow. Asking costs one small request and wakes neither ship unless the mark changed.
    ///
    /// Also how often a ship with commands another ship has yet to answer compares notes
    /// with it, for the like reason: that ship may have gone back to a state in which it
    /// never had them.
    pub follow_check: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            addr: "127.0.0.1:0".into(),
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1024,
            max_calls: 1024,
            max_streams: 8,
            // Room for a command of the largest size a ship takes, with its wrapping.
            max_message_bytes: (1 << 20) + (64 << 10),
            max_reading_bytes: 64 << 20,
            max_requests: 64,
            max_working: 16,
            max_carrying: 16,
            retry_delay: Duration::from_millis(200),
            max_retry_delay: Duration::from_secs(30),
            follow_check: Duration::from_secs(600),
        }
    }
}

/// Why a request to another ship did not get an answer.
#[derive(Debug)]
pub enum NetError {
    /// The ship asking is not one this runtime holds.
    NotHere(String),
    /// The directory does not list the ship being called.
    Unlisted(String),
    /// No connection could be made, or it was lost. This includes the other end failing to
    /// prove it is the ship that was called.
    Unreachable(String),
    /// The other ship would not answer the request.
    Refused(String),
    /// No answer in the time allowed.
    TimedOut,
    /// The other ship answered with something that makes no sense.
    Garbled,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::NotHere(ship) => write!(f, "{ship} is not a ship on this runtime"),
            NetError::Unlisted(ship) => write!(f, "{ship} is not listed in the directory"),
            NetError::Unreachable(why) => write!(f, "could not reach the ship: {why}"),
            NetError::Refused(why) => write!(f, "the ship refused: {why}"),
            NetError::TimedOut => write!(f, "the ship did not answer in time"),
            NetError::Garbled => write!(f, "the ship's answer made no sense"),
        }
    }
}

impl std::error::Error for NetError {}

/// What came of asking a ship who it is.
#[derive(Debug, PartialEq, Eq)]
pub struct Answered {
    /// The ship that answered. This is known for certain: it is the ship that was called, and
    /// the other end proved it holds the key the directory lists for that ship.
    pub ship: String,
    /// The ship the answerer says it was shown proof of at this end. This is its word, and
    /// cannot be checked from here. An honest ship gives the name the directory lists for the
    /// caller's key.
    pub seen_as: String,
    pub took: Duration,
}

/// A runtime's presence on the network. Dropping it closes every connection.
///
/// Its calls wait for an answer, so they are for ordinary threads. Called from inside async
/// code they still work, but hold up that code's thread while they wait.
pub struct Network {
    shared: Arc<Shared>,
    threads: Threads,
    /// Let go of last, when the rest has been stopped.
    _claim: Claim,
}

/// A runtime's one place for a network, held for as long as that network runs. Two at once
/// would each carry the same waiting messages, and the first to stop would leave the other
/// never told of new ones.
struct Claim(Arc<Runtime>);

impl Claim {
    fn take(runtime: &Arc<Runtime>) -> Option<Claim> {
        runtime.claim_network().then(|| Claim(runtime.clone()))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.release_network();
    }
}

/// The threads the network runs on. Letting go of them never waits, so it is safe wherever it
/// happens: in ordinary code, inside async code, or part way through a start that failed.
struct Threads(Option<tokio::runtime::Runtime>);

impl Threads {
    fn get(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("held until dropped")
    }
}

impl Drop for Threads {
    fn drop(&mut self) {
        if let Some(tokio) = self.0.take() {
            tokio.shutdown_background();
        }
    }
}

/// A connection this runtime made, with what it was made against. It is good for as long as
/// those still hold.
struct Made {
    connection: Connection,
    /// What the directory listed for the ship called.
    peer: Peer,
    /// The key the calling ship showed.
    shown: [u8; 32],
}

type Pair = (String, String);

struct Shared {
    runtime: Arc<Runtime>,
    directory: Arc<Directory>,
    cfg: NetConfig,
    endpoint: Endpoint,
    provider: Arc<CryptoProvider>,
    /// Connections this runtime has made, by (calling ship, called ship). Each pair has a
    /// lock of its own, held while its connection is being made, so that two calls to one
    /// ship share one connection and a slow ship holds up only calls to itself.
    made: Mutex<HashMap<Pair, Arc<tokio::sync::Mutex<Option<Made>>>>>,
    /// Connections from other ships, counting those still being set up.
    taken: AtomicUsize,
    /// The newest connection from each (calling ship, called ship).
    callers: Mutex<HashMap<Pair, Caller>>,
    /// The highest number among the callers that have been forgotten to make room. A
    /// connection numbered at or below it, from a pair nothing is remembered of, may be
    /// older than one that came and went, and is turned away to try again.
    forgotten: AtomicU64,
    /// How many connections from other ships have been let in so far. Each is given the
    /// next number as it arrives, before anything is done about it.
    admitted: AtomicU64,
    /// Room left for requests being read. See `NetConfig::max_reading_bytes`.
    reading: Arc<Semaphore>,
    /// Requests this runtime may still send. See `NetConfig::max_requests`.
    asking: Arc<Semaphore>,
    /// Pieces of work on ships the network may still take on. See `NetConfig::max_working`.
    working: Arc<Semaphore>,
    /// Deliveries to other ships the network may still take on. See `NetConfig::max_carrying`.
    carrying: Arc<Semaphore>,
    carrier: Arc<Carrier>,
    /// Questions to Urbit ID that may still be started.
    reading_keys: Arc<Semaphore>,
    /// Ships Urbit ID is being asked about right now, each with the means to wait for the
    /// answer. Everyone who wants to know about a ship waits on the one question.
    looking_up: Mutex<HashMap<String, tokio::sync::watch::Receiver<()>>>,
    /// How many callers nothing is known of may still be looked up in Urbit ID just now,
    /// and when that was last topped up.
    meeting: Mutex<(u32, Instant)>,
}

/// What the network knows about commands waiting to go to other ships.
#[derive(Default)]
struct Carrier {
    /// Ships that may have commands waiting. A ship is put here when an event on it queues
    /// some, and looked at once.
    waiting: Mutex<HashSet<String>>,
    /// Rung when there is something to look at.
    news: tokio::sync::Notify,
    /// For each (ship, other ship) with commands in hand, how carrying them is going.
    lanes: Mutex<HashMap<Pair, Lane>>,
    /// Ships that may have events queued which nothing else is about to run: ones that
    /// another ship has just delivered, or that were there when the network started.
    queued: Mutex<HashSet<String>>,
    /// Ships whose queues are being run now. The flag says more arrived meanwhile.
    tending: Mutex<HashMap<String, bool>>,
    /// Each (ship, other ship) where the first follows logs on the second, with the mark
    /// the second showed when last asked, once that has been checked against the first
    /// ship's file.
    watching: Mutex<HashMap<Pair, Option<[u8; 16]>>>,
    /// Whether a round of asking those ships for their marks is under way.
    checking: std::sync::atomic::AtomicBool,
    /// Each (ship, other ship) where the first may have commands the second has yet to
    /// answer. Looked at in the same rounds: if the answers are still owed after a while,
    /// the two compare notes, in case the second has gone back to a state it never had
    /// them in.
    awaiting: Mutex<HashSet<Pair>>,
    /// Each (ship, other ship) where the first is comparing notes with the second, at its
    /// own asking, right now.
    resyncing: Mutex<HashSet<Pair>>,
}

#[derive(Default)]
struct Lane {
    /// Some are being carried now. Only one carrier works a lane at a time, so that commands
    /// go in order.
    busy: bool,
    /// The last try failed. Not before this moment, and after this long the time after.
    retry_at: Option<tokio::time::Instant>,
    delay: Duration,
    /// The two ships disagree about what has passed between them. Nothing more is carried.
    stalled: bool,
    /// The last of this ship's logs the other ship was told about, as (agent, log). News
    /// goes round the logs from there, so that no log is always left out.
    told: Option<(String, String)>,
}

impl Carrier {
    /// There may be commands waiting on this ship.
    fn look_at(&self, ship: &str) {
        lock(&self.waiting).insert(ship.to_string());
        self.news.notify_one();
    }

    /// There may be events queued on this ship that nothing else will run.
    fn run_at(&self, ship: &str) {
        lock(&self.queued).insert(ship.to_string());
        self.news.notify_one();
    }
}

/// What came of trying to carry a lane's commands.
enum Carried {
    /// Everything that was waiting has gone.
    All,
    /// Some could not go. Try again after a while.
    NotYet,
    /// The two ships cannot agree on what has passed between them.
    OutOfStep,
}

impl Network {
    pub fn start(runtime: Arc<Runtime>, directory: Arc<Directory>, cfg: NetConfig) -> io::Result<Network> {
        let addr: SocketAddr = cfg.addr.parse().map_err(|_| io::Error::other("not an address to listen on"))?;
        if cfg.max_message_bytes == 0 || cfg.max_message_bytes > u32::MAX as usize || cfg.max_reading_bytes < cfg.max_message_bytes {
            return Err(io::Error::other("max_reading_bytes must have room for at least one message"));
        }
        if cfg.max_reading_bytes > Semaphore::MAX_PERMITS || cfg.max_requests == 0 || cfg.max_requests > Semaphore::MAX_PERMITS {
            return Err(io::Error::other("max_reading_bytes or max_requests is out of range"));
        }
        if cfg.max_working == 0 || cfg.max_working > Semaphore::MAX_PERMITS {
            return Err(io::Error::other("max_working is out of range"));
        }
        if cfg.max_carrying == 0 || cfg.max_carrying > Semaphore::MAX_PERMITS {
            return Err(io::Error::other("max_carrying is out of range"));
        }
        // A command too large to send would wait for ever, with everything behind it. (Two
        // runtimes with different limits can still disagree; settling one size for the wire
        // is for the protocol to do.)
        if runtime.inner.cfg.max_ship_bytes < MIN_SHIP_BYTES {
            return Err(io::Error::other("max_ship_bytes is too small for ships that take commands from other ships"));
        }
        if cfg.max_message_bytes < runtime.inner.cfg.max_event_bytes.saturating_add(MESSAGE_ENVELOPE_BYTES) {
            return Err(io::Error::other("max_message_bytes must have room for the largest command a ship here may send"));
        }
        // Likewise a log's checkpoint, which a ship that follows the log may be sent whole.
        if cfg.max_message_bytes < runtime.inner.cfg.max_checkpoint_bytes.saturating_add(MESSAGE_ENVELOPE_BYTES) {
            return Err(io::Error::other("max_message_bytes must have room for the largest checkpoint a log here may have"));
        }
        // And for a ship to say where it stands with another: the list of that ship's
        // commands it has yet to answer, at eight bytes each. A list cut short would leave
        // commands that nobody could ever say were lost.
        if cfg.max_message_bytes / 2 < runtime.inner.cfg.max_unanswered.saturating_mul(8) {
            return Err(io::Error::other("max_message_bytes must have room for max_unanswered command numbers, twice over"));
        }
        if cfg.follow_check.is_zero() || cfg.follow_check > MAX_TIMEOUT {
            return Err(io::Error::other("follow_check must be more than nothing and at most a day"));
        }
        if cfg.retry_delay.is_zero() || cfg.retry_delay > cfg.max_retry_delay || cfg.max_retry_delay > MAX_TIMEOUT {
            return Err(io::Error::other("retry_delay must be more than nothing and at most max_retry_delay, itself at most a day"));
        }
        // A time limit has to be one a clock can keep. Far beyond a day it is no limit at all,
        // and near the largest a clock can hold, working out when it ends goes wrong.
        if cfg.request_timeout.is_zero() || cfg.request_timeout > MAX_TIMEOUT || cfg.idle_timeout.is_zero() || cfg.idle_timeout > MAX_TIMEOUT {
            return Err(io::Error::other("request_timeout and idle_timeout must be more than nothing and at most a day"));
        }
        // The ships' keys are read into memory now, and never from inside a connection being
        // made. If they cannot be read, there is no network.
        runtime.load_identities().map_err(io::Error::other)?;
        let threads = Threads(Some(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("ship-net").build()?));
        let tokio = threads.get();
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // The side that answers: it shows the key of whichever ship was asked for, and wants
        // proof of some key. Whose key it is, the caller says once connected.
        let mut answering = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(AnyCaller { supported: provider.signature_verification_algorithms }))
            .with_cert_resolver(Arc::new(ShipKeys { runtime: runtime.clone(), provider: provider.clone() }));
        answering.alpn_protocols = vec![PROTOCOL.to_vec()];
        // Every connection proves its keys afresh. None picks up where an earlier one left off.
        answering.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        answering.send_tls13_tickets = 0;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(answering).map_err(io::Error::other)?));
        server.transport_config(Arc::new(transport(&cfg, cfg.max_streams)?));
        // A ship stays where it was first reached: a connection does not follow a caller that
        // turns up at a new address.
        server.migration(false);
        // Connections waiting for this runtime to decide whether to take them.
        server.max_incoming(256);

        let endpoint = {
            let _entered = tokio.enter();
            Endpoint::server(server, addr)?
        };
        let reading = Arc::new(Semaphore::new(cfg.max_reading_bytes));
        let asking = Arc::new(Semaphore::new(cfg.max_requests));
        let working = Arc::new(Semaphore::new(cfg.max_working));
        let carrying = Arc::new(Semaphore::new(cfg.max_carrying));
        let carrier = Arc::new(Carrier::default());
        // Taken last of the things that can fail, so that a start that fails gives it back.
        let claim = Claim::take(&runtime).ok_or_else(|| io::Error::other("this runtime already has a network running"))?;
        let shared = Arc::new(Shared {
            runtime,
            directory,
            cfg,
            endpoint,
            provider,
            made: Mutex::new(HashMap::new()),
            taken: AtomicUsize::new(0),
            callers: Mutex::new(HashMap::new()),
            forgotten: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            reading,
            asking,
            working,
            carrying,
            carrier: carrier.clone(),
            reading_keys: Arc::new(Semaphore::new(MOST_READING)),
            looking_up: Mutex::new(HashMap::new()),
            meeting: Mutex::new((MOST_MEETINGS, Instant::now())),
        });
        tokio.spawn(answer_calls(shared.clone()));
        tokio.spawn(carry(shared.clone()));
        // From now on the runtime says when a ship has queued commands for other ships.
        let told = carrier.clone();
        shared.runtime.set_outbound_hook(Some(Arc::new(move |ship: &str, queued: bool| {
            told.look_at(ship);
            if queued {
                told.run_at(ship);
            }
        })));
        // Ships may have had commands waiting since before this network started: to go to
        // other ships, or taken from other ships and not yet run. A command that was taken
        // just before a runtime stopped has been acknowledged, so nobody will send it again,
        // and running it is up to this runtime.
        let starting = shared.clone();
        tokio.spawn(async move {
            let runtime = starting.runtime.clone();
            let found = work(&starting, move || runtime.ships_with_work()).await;
            let (busy, following, awaiting) = found.and_then(Result::ok).unwrap_or_default();
            lock(&starting.carrier.awaiting).extend(awaiting);
            for ship in busy {
                starting.carrier.look_at(&ship);
                starting.carrier.run_at(&ship);
            }
            // And every ship that follows logs elsewhere is known, so that the ships it
            // follows can be asked now and then whether they are still what they were.
            lock(&starting.carrier.watching).extend(following.into_iter().map(|pair| (pair, None)));
        });
        Ok(Network { shared, threads, _claim: claim })
    }

    /// The address other ships reach this runtime at.
    pub fn addr(&self) -> SocketAddr {
        self.shared.endpoint.local_addr().expect("the endpoint is bound")
    }

    /// How many (calling ship, called ship) pairs this network remembers a connection from.
    /// It stays within bounds however many ships have called.
    pub fn callers_remembered(&self) -> usize {
        lock(&self.shared.callers).len()
    }

    /// How many connections are open, made or taken.
    pub fn open_connections(&self) -> usize {
        self.shared.endpoint.open_connections()
    }

    /// The (ship, other ship) pairs between which commands have stopped being carried,
    /// because the two disagree about what has passed between them. That happens when one of
    /// them has gone back to an earlier state, such as a restored backup. The commands are
    /// kept. Nothing here sorts it out yet.
    pub fn stalled(&self) -> Vec<(String, String)> {
        let lanes = lock(&self.shared.carrier.lanes);
        let mut stalled: Vec<Pair> = lanes.iter().filter(|(_, lane)| lane.stalled).map(|(pair, _)| pair.clone()).collect();
        stalled.sort();
        stalled
    }

    /// From one of this runtime's ships, ask another ship who it is. An answer means this end
    /// was shown proof of the key the directory lists for the ship called, so it is that ship.
    /// The answer also carries who that ship says is calling.
    pub fn ping(&self, from: &str, to: &str) -> Result<Answered, NetError> {
        let started = Instant::now();
        let nonce = crate::store::now_ms().to_le_bytes().to_vec();
        let asked = PeerRequest { body: Some(peer_request::Body::Ping(Ping { nonce: nonce.clone() })) };
        match self.ask(from, to, asked)?.body {
            Some(peer_reply::Body::Pong(Pong { nonce: echoed, caller, .. })) if echoed == nonce => {
                let ship = canonical_ship(to).map_err(|_| NetError::Garbled)?;
                Ok(Answered { ship, seen_as: caller, took: started.elapsed() })
            }
            _ => Err(NetError::Garbled),
        }
    }

    /// Send one request from one of this runtime's ships to another ship and wait for its reply.
    fn ask(&self, from: &str, to: &str, request: PeerRequest) -> Result<PeerReply, NetError> {
        let shared = self.shared.clone();
        let (from, to) = (from.to_string(), to.to_string());
        // Each request out may be holding a whole reply, so only so many go out at once.
        let Ok(turn) = shared.asking.clone().try_acquire_owned() else {
            return Err(NetError::Unreachable("this runtime already has as many requests out as it may".into()));
        };
        // Handed to the network's own threads and waited for here. Unlike running it in
        // place, this is safe wherever it is called from.
        let (report, outcome) = std::sync::mpsc::channel();
        self.threads.get().spawn(async move {
            let answer = shared.ask(&from, &to, request).await;
            // Given up before the caller hears, so that its very next request finds it free.
            drop(turn);
            let _ = report.send(answer);
        });
        outcome.recv().unwrap_or_else(|_| Err(NetError::Unreachable("the network has stopped".into())))
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.shared.runtime.set_outbound_hook(None);
        self.shared.endpoint.close(VarInt::from_u32(0), b"stopping");
        // Give the goodbyes a moment to go out, so the ships at the other end know at once and
        // do not hold a dead connection until it times out. Only a moment: a ship that is not
        // listening must not be able to keep this one from stopping. The threads themselves
        // are let go of straight after, without waiting.
        let (done, waited) = std::sync::mpsc::channel();
        let endpoint = self.shared.endpoint.clone();
        self.threads.get().spawn(async move {
            endpoint.wait_idle().await;
            let _ = done.send(());
        });
        let _ = waited.recv_timeout(Duration::from_millis(500));
    }
}

/// How a connection carries data. `streams` is how many requests the other end may have in
/// progress on it at once.
fn transport(cfg: &NetConfig, streams: u32) -> io::Result<TransportConfig> {
    // The other end may send this much on one stream before this end has read any of it: a
    // whole message, or a small fixed amount where messages are smaller than that. How large
    // a message is taken is checked separately, as it is read.
    let stream_room = cfg.max_message_bytes.clamp(16 << 10, u32::MAX as usize) as u64;
    let room = |bytes: u64| VarInt::from_u64(bytes).map_err(io::Error::other);
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(streams));
    // Everything is a request and its reply on one stream. Nothing else is taken.
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(None);
    transport.stream_receive_window(room(stream_room)?);
    transport.receive_window(room(stream_room.saturating_mul(u64::from(streams.max(1))))?);
    transport.max_idle_timeout(Some(IdleTimeout::try_from(cfg.idle_timeout).map_err(io::Error::other)?));
    Ok(transport)
}

/// The public half of an ed25519 key, in the wrapping TLS carries bare keys in.
fn wrapped(key: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    [&PREFIX[..], key].concat()
}

/// The key inside that wrapping, if it is an ed25519 key and nothing else.
fn unwrapped(wrapped_key: &[u8]) -> Option<[u8; 32]> {
    let key = <[u8; 32]>::try_from(wrapped_key.get(12..)?).ok()?;
    (wrapped(&key) == wrapped_key).then_some(key)
}

/// What a ship shows to prove who it is: its public key, and the means to sign with the
/// private half. The private half stays in this process.
fn proof(key: &ed25519_dalek::SigningKey, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, rustls::Error> {
    // The private key in the standard wrapping (PKCS#8 version 2) the TLS library reads.
    let mut der = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&key.to_bytes());
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(&key.verifying_key().to_bytes());
    let signer = provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(der).into())?;
    let shown = CertificateDer::from(wrapped(&key.verifying_key().to_bytes()));
    Ok(Arc::new(CertifiedKey::new(vec![shown], signer)))
}

/// Whether the other end signed the connection's handshake with the key it showed. Showing a
/// key proves nothing, since public keys are public; signing with it is the proof.
fn signed_with(
    shown: &CertificateDer<'_>,
    message: &[u8],
    signed: &DigitallySignedStruct,
    supported: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, supported)
}

fn refuse(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_string())
}

/// For the side that answers: which key to show. It is the key of the ship the caller asked
/// for, if this runtime holds that ship. Keys are held in memory, so this never waits on disk.
struct ShipKeys {
    runtime: Arc<Runtime>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for ShipKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShipKeys")
    }
}

impl ResolvesServerCert for ShipKeys {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let key = self.runtime.signing_key(hello.server_name()?).ok()?;
        proof(&key, &self.provider).ok()
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// For the side that answers: a caller must show a ship's key and prove it holds it. Which
/// ship it is cannot be told from the key, since Urbit ID is looked up by name. The caller
/// says its name as the first thing on the connection, and nothing is done for it until
/// the key shown here has been checked against that name.
#[derive(Debug)]
struct AnyCaller {
    supported: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyCaller {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, shown: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        unwrapped(shown.as_ref()).ok_or_else(|| refuse("the caller did not show a ship's key"))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refuse("only TLS 1.3 is spoken"))
    }

    fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed_with(shown, message, signed, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// For the side that calls: whether the ship that answered showed the key listed for the ship
/// that was called. With no key expected, any ship's key will do here: that is for a moon
/// met for the first time, whose key is then checked against its parent's word for it
/// before anything is asked of it.
#[derive(Debug)]
struct ListedKey {
    expected: Option<Vec<u8>>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ListedKey {
    fn verify_server_cert(
        &self,
        shown: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fits = match &self.expected {
            Some(expected) => shown.as_ref() == expected,
            None => unwrapped(shown.as_ref()).is_some(),
        };
        if fits {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refuse("the ship that answered did not show the key listed for the ship that was called"))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refuse("only TLS 1.3 is spoken"))
    }

    fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed_with(shown, message, signed, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl Shared {
    /// Send one request and read its reply, over a connection made for this pair of ships,
    /// all within the time allowed for a request.
    async fn ask(self: &Arc<Self>, from: &str, to: &str, request: PeerRequest) -> Result<PeerReply, NetError> {
        self.ask_keyed(from, to, request).await.map(|(reply, _)| reply)
    }

    /// The same, also returning the key the ship that answered proved it holds: the one the
    /// directory listed for it when the connection was made.
    async fn ask_keyed(self: &Arc<Self>, from: &str, to: &str, request: PeerRequest) -> Result<(PeerReply, [u8; 32]), NetError> {
        let from = canonical_ship(from).map_err(|_| NetError::NotHere(from.to_string()))?;
        let to = canonical_ship(to).map_err(|_| NetError::Unlisted(to.to_string()))?;
        let deadline = tokio::time::Instant::now().checked_add(self.cfg.request_timeout).ok_or(NetError::TimedOut)?;
        let lost = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        let (connection, key) = tokio::time::timeout_at(deadline, self.connection(&from, &to)).await.map_err(|_| NetError::TimedOut)??;
        let opened = tokio::time::timeout_at(deadline, connection.open_bi()).await.map_err(|_| NetError::TimedOut)?;
        let (mut send, mut receive) = opened.map_err(|e| lost(&e))?;
        // The streams are held out here, so that if time runs out part way they can be told
        // to stop. Merely letting go of them would leave the request to go on being sent.
        let exchanged = tokio::time::timeout_at(deadline, async {
            send.write_all(&request.encode_to_vec()).await.map_err(|e| lost(&e))?;
            send.finish().map_err(|e| lost(&e))?;
            read_whole(&mut receive, self.cfg.max_message_bytes).await.ok_or_else(|| lost(&"the reply could not be read, or was too large"))
        })
        .await;
        let Ok(answer) = exchanged else {
            let _ = send.reset(VarInt::from_u32(3));
            let _ = receive.stop(VarInt::from_u32(3));
            return Err(NetError::TimedOut);
        };
        let answer = answer?;
        // Counted before it is decoded, as a request is: an answer can be all padding too.
        if !repeats_within(&answer, 3, 1, MAX_FETCH_ENTRIES) {
            return Err(NetError::Garbled);
        }
        let reply = PeerReply::decode(&*answer).map_err(|_| NetError::Garbled)?;
        if reply.body.is_none() {
            return Err(NetError::Refused(reply.refused));
        }
        Ok((reply, key))
    }

    /// The place where the connection for a pair of ships is kept, making one if the pair is new.
    fn slot(&self, pair: &Pair) -> Result<Arc<tokio::sync::Mutex<Option<Made>>>, NetError> {
        let mut made = lock(&self.made);
        if !made.contains_key(pair) && made.len() >= self.cfg.max_calls {
            // Forget the pairs whose connections have closed. A pair that some call is holding
            // is left alone, whatever state it is in: that call got its place while this lock
            // was held, and is about to use it. Only this map can hand a place out, so with
            // the lock held, a place nobody else holds cannot be taken up meanwhile.
            // A connection to a ship the directory no longer lists, or lists differently, goes
            // too: it would never be used again, and must not hold a place another ship needs.
            made.retain(|(_, to), kept| {
                let in_use = Arc::strong_count(kept) > 1;
                in_use || kept.try_lock().map_or(true, |held| {
                    // And neither does one to a ship that is no longer among those that are
                    // kept, and cannot be again: it could not be used either.
                    let keep = held.as_ref().is_some_and(|made| {
                        made.connection.close_reason().is_none() && self.directory.lookup(to) == Some(made.peer) && self.directory.prove(to, &made.peer.key)
                    });
                    if let Some(made) = held.as_ref().filter(|_| !keep) {
                        made.connection.close(VarInt::from_u32(2), b"no longer needed");
                    }
                    keep
                })
            });
            if made.len() >= self.cfg.max_calls {
                return Err(NetError::Unreachable("this runtime is already calling as many ships as it may".into()));
            }
        }
        Ok(made.entry(pair.clone()).or_default().clone())
    }

    /// The connection from one of this runtime's ships to another ship, made if there is
    /// none, and the key the other ship proved it holds when it was made.
    async fn connection(self: &Arc<Self>, from: &str, to: &str) -> Result<(Connection, [u8; 32]), NetError> {
        let key = self.runtime.signing_key(from).map_err(|_| NetError::NotHere(from.to_string()))?;
        let shown = key.verifying_key().to_bytes();
        let pair = (from.to_string(), to.to_string());
        // If the directory reads its keys from Urbit ID, see that it has this ship's.
        self.know(to, 0).await;
        if self.directory.reach(to).is_none() {
            // Not listed, so not called, whatever room there is for calls. A connection made
            // while it was listed is closed, unless some call is still holding it.
            let mut made = lock(&self.made);
            if made.get(&pair).is_some_and(|kept| Arc::strong_count(kept) == 1) {
                let kept = made.remove(&pair).expect("found above");
                if let Some(made) = kept.try_lock().ok().and_then(|mut held| held.take()) {
                    made.connection.close(VarInt::from_u32(2), b"the directory changed");
                }
            }
            return Err(NetError::Unlisted(to.to_string()));
        }
        let slot = self.slot(&pair)?;
        // Held while connecting, so a second call to the same ship waits for this connection
        // and does not make another. Calls to other ships have their own.
        let mut kept = slot.lock().await;
        // Read after any wait, so it is what the directory says now.
        let Some(reach) = self.directory.reach(to) else {
            // The ship is no longer listed. A connection made while it was is closed, not left
            // open with nothing to use it.
            if let Some(made) = kept.take() {
                made.connection.close(VarInt::from_u32(2), b"the directory changed");
            }
            return Err(NetError::Unlisted(to.to_string()));
        };
        if let Some(made) = kept.take() {
            // A connection proves what was true when it was made. If the directory now lists
            // a different key or address for the ship, or the calling ship would now show a
            // different key, that proof is stale: start again.
            // And the ship must still be among those that are kept. What was held for it
            // when the connection was made may since have lapsed and been read afresh, as
            // the key of a ship that has proved nothing: the connection is the proof, and
            // counts again here, if there is room.
            let stands = made.connection.close_reason().is_none() && Some(made.peer.key) == reach.key && made.peer.addr == reach.addr && made.shown == shown;
            if stands && self.directory.prove(to, &made.peer.key) {
                let (connection, proved) = (made.connection.clone(), made.peer.key);
                *kept = Some(made);
                return Ok((connection, proved));
            }
            made.connection.close(VarInt::from_u32(2), b"the directory changed");
        }

        let unreachable = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        // This side shows the calling ship's key, and accepts only the key listed for the ship
        // being called.
        let shows = proof(&key, &self.provider).map_err(|e| unreachable(&e))?;
        // A moon may have been given a new key since it was last met, which only the moon
        // can show. So any key is let through here for a moon, and looked at below.
        let expected = if ob::moon_number(to).is_some() { None } else { reach.key };
        let expects = ListedKey { expected: expected.as_ref().map(wrapped), supported: self.provider.signature_verification_algorithms };
        let mut calling = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| unreachable(&e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(expects))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(shows)));
        calling.alpn_protocols = vec![PROTOCOL.to_vec()];
        calling.resumption = rustls::client::Resumption::disabled();
        let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(calling).map_err(|e| unreachable(&e))?));
        // Requests go one way on a connection this runtime made. The ship called may not
        // start any of its own on it.
        client.transport_config(Arc::new(transport(&self.cfg, 0).map_err(|e| unreachable(&e))?));

        let connecting = self.endpoint.connect_with(client, reach.addr, to).map_err(|e| unreachable(&e))?;
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(e) => {
                // It may be that the ship has a new key, and the one held for it is old.
                self.directory.doubt(to);
                return Err(unreachable(&e));
            }
        };
        // Say which ship is calling, and hear that it is believed. Nothing else is said on
        // the connection before that.
        let welcome = match self.hello(&connection, from).await {
            Ok(welcome) => welcome,
            Err(e) => {
                connection.close(VarInt::from_u32(1), b"no welcome");
                return Err(e);
            }
        };
        let Some(proved) = shown_key(&connection) else {
            connection.close(VarInt::from_u32(1), b"no key shown");
            return Err(NetError::Unreachable("the ship that answered showed no key".into()));
        };
        // A moon shows its parent's word for its key, and that word is taken in whether or
        // not the key is the one already held: it may be for a later revision, and what
        // was seen latest is what holds earlier ones off.
        let word = welcome.proof.as_ref().and_then(proof_read).ok_or("the moon did not show its parent's word for its key");
        let vouched = word.and_then(|proof| self.directory.vouched(to, proved, &proof));
        if reach.key != Some(proved) {
            // Only a moon gets this far having shown a key other than the one held for it:
            // one never met, or one that has been given a new key. It has proved it holds
            // the key it showed, and that key is the moon's if the moon's parent has given
            // its word for it, at no earlier a revision than any seen before.
            if let Err(why) = vouched {
                connection.close(VarInt::from_u32(1), b"not the moon that was called");
                return Err(NetError::Unreachable(why.to_string()));
            }
        }
        // The ship has proved it holds the key held for it. From now on it is among the
        // ships that are kept; if there is no room for it there, it cannot be called.
        if !self.directory.prove(to, &proved) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return Err(NetError::Unreachable("the key the ship proved is no longer the one held for it, or there is no room to keep it".into()));
        }
        let peer = Peer { key: proved, addr: reach.addr };
        // Connecting took time. If the directory changed meanwhile, what was just proved is
        // already out of date.
        if self.directory.lookup(to) != Some(peer) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return Err(NetError::Unreachable("the directory changed while connecting".into()));
        }
        *kept = Some(Made { connection: connection.clone(), peer, shown });
        Ok((connection, peer.key))
    }

    /// The first thing said on a connection this runtime has made: which ship is calling,
    /// and for a moon its parent's word for its key. The answer says the caller is believed.
    async fn hello(&self, connection: &Connection, from: &str) -> Result<Welcome, NetError> {
        let lost = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        let proof = self.runtime.moon_proof(from).map(|proof| MoonProof { revision: proof.revision, signed: proof.signed.to_vec() });
        let said = PeerRequest { body: Some(peer_request::Body::Hello(Hello { ship: from.to_string(), proof })) };
        let (mut send, mut receive) = connection.open_bi().await.map_err(|e| lost(&e))?;
        send.write_all(&said.encode_to_vec()).await.map_err(|e| lost(&e))?;
        send.finish().map_err(|e| lost(&e))?;
        let answer = read_whole(&mut receive, MOST_HELLO_BYTES).await.ok_or_else(|| lost(&"the ship called did not say whether the caller is believed"))?;
        match PeerReply::decode(&*answer) {
            Ok(PeerReply { body: Some(peer_reply::Body::Welcome(welcome)), .. }) => Ok(welcome),
            Ok(PeerReply { body: None, refused }) => Err(NetError::Refused(refused)),
            _ => Err(NetError::Garbled),
        }
    }

    /// See that what the directory holds for a ship is recent enough to go on with, asking
    /// Urbit ID if need be. For a moon, the ship that matters is its parent. A directory
    /// that is a fixed list has nothing to ask.
    async fn know(self: &Arc<Self>, ship: &str, spare: usize) {
        let subject = parent_of(ship).unwrap_or_else(|| ship.to_string());
        match self.directory.due(&subject) {
            Due::No => {}
            Due::Soon => self.read_soon(subject, spare),
            Due::Now => self.read(&subject, spare).await,
        }
    }

    /// Whether one more caller that nothing is known of may be looked up just now.
    fn may_meet(&self) -> bool {
        let mut meeting = lock(&self.meeting);
        let (left, at) = *meeting;
        let earned = (at.elapsed().as_secs_f64() * MOST_MEETINGS as f64) as u32;
        if earned > 0 {
            *meeting = (left.saturating_add(earned).min(MOST_MEETINGS), Instant::now());
        }
        if meeting.0 == 0 {
            return false;
        }
        meeting.0 -= 1;
        true
    }

    /// If the key held for a ship that has called (or, for a moon, its parent) is due to
    /// be read again, start that, and do not wait for it. Like anything done because of
    /// who is calling, it gets only half the places for questions.
    fn freshen(self: &Arc<Self>, ship: &str) {
        let subject = parent_of(ship).unwrap_or_else(|| ship.to_string());
        if self.directory.due(&subject) != Due::No {
            self.read_soon(subject, MOST_LOOKUPS / 2);
        }
    }

    /// Ask Urbit ID about a ship, without waiting for the answer, if there is room for
    /// one more question with `spare` places left free.
    fn read_soon(self: &Arc<Self>, ship: String, spare: usize) {
        drop(self.asked(&ship, spare));
    }

    /// Ask Urbit ID about a ship and wait for the directory to have the answer, if there
    /// is room for one more question. If the one waiting here gives up, the question is
    /// still seen through. `spare` is how many of the places for questions are to be left
    /// free for others.
    async fn read(self: &Arc<Self>, ship: &str, spare: usize) {
        if let Some(mut answered) = self.asked(ship, spare) {
            // Done when the asking ends, however it ends.
            let _ = answered.changed().await;
        }
    }

    /// The means to wait for an answer about a ship: the question already out about it, or
    /// a new one. One question about a ship is out at a time, and those who wait for it
    /// hold nothing while they wait. Asking waits on the network, so it is done on a thread
    /// that may wait, and only so many questions are out at once. `None` if this would be
    /// a new question and there are as many waiting as there may be.
    fn asked(self: &Arc<Self>, ship: &str, spare: usize) -> Option<tokio::sync::watch::Receiver<()>> {
        let mut looking_up = lock(&self.looking_up);
        if let Some(answered) = looking_up.get(ship) {
            return Some(answered.clone());
        }
        if looking_up.len() >= MOST_LOOKUPS.saturating_sub(spare) {
            return None;
        }
        let (done, answered) = tokio::sync::watch::channel(());
        looking_up.insert(ship.to_string(), answered.clone());
        let (shared, ship) = (self.clone(), ship.to_string());
        tokio::spawn(async move {
            if let Ok(turn) = shared.reading_keys.clone().acquire_owned().await {
                let (directory, name) = (shared.directory.clone(), ship.clone());
                let asked = tokio::task::spawn_blocking(move || {
                    directory.read(&name);
                    drop(turn);
                });
                let _ = asked.await;
            }
            lock(&shared.looking_up).remove(&ship);
            drop(done);
        });
        Some(answered)
    }

    /// Whether a ship that has said its name, and proved it holds the key `shown`, is the
    /// ship of that name. Its canonical name if so.
    async fn admit(self: &Arc<Self>, shown: [u8; 32], hello: &Hello) -> Option<String> {
        let caller = canonical_ship(&hello.ship).ok()?;
        let subject = parent_of(&caller).unwrap_or_else(|| caller.clone());
        if self.directory.due(&subject) == Due::Now && !self.may_meet() {
            return None;
        }
        // A caller's say-so gets only half the places for questions.
        self.know(&caller, MOST_LOOKUPS / 2).await;
        if ob::moon_number(&caller).is_some() {
            // A moon is believed on its parent's word, if it brings one.
            if let Some(proof) = hello.proof.as_ref().and_then(proof_read) {
                self.directory.vouched(&caller, shown, &proof).ok()?;
            }
        } else if self.directory.key_of(&caller) != Some(shown) {
            // The key held for that name may be from before the ship was given a new one.
            // Read it again, if that has not just been done, and then see.
            self.directory.doubt(&caller);
            if self.directory.due(&caller) != Due::No {
                self.read(&caller, MOST_LOOKUPS / 2).await;
            }
        }
        // Believed only if the key shown is the one held for the name, and the ship is from
        // now on among those that are kept: settled together, in one step.
        self.directory.prove(&caller, &shown).then_some(caller)
    }
}

/// The key the other end of a connection proved it holds.
fn shown_key(connection: &Connection) -> Option<[u8; 32]> {
    let shown = connection.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    unwrapped(shown.first()?.as_ref())
}

/// A moon's proof as it travels, if it is the right shape.
fn proof_read(proof: &MoonProof) -> Option<moon::Proof> {
    Some(moon::Proof { revision: proof.revision, signed: proof.signed.as_slice().try_into().ok()? })
}


/// A place among the connections from other ships, given up when the connection ends.
struct Place(Arc<Shared>);

impl Place {
    /// Take a place, if one is free. Counted in one step, so that however many callers arrive
    /// at once, no more than the limit get in.
    fn take(shared: &Arc<Shared>) -> Option<Place> {
        if shared.taken.fetch_add(1, Ordering::SeqCst) >= shared.cfg.max_connections {
            shared.taken.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Place(shared.clone()))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.0.taken.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Take connections from other ships for as long as the network runs.
async fn answer_calls(shared: Arc<Shared>) {
    while let Some(incoming) = shared.endpoint.accept().await {
        // Before doing any work for a caller, make it show that it really is at the address
        // it claims. Otherwise anyone could have this runtime send replies to a third party.
        if !incoming.remote_address_validated() && incoming.may_retry() {
            let _ = incoming.retry();
            continue;
        }
        let Some(place) = Place::take(&shared) else {
            incoming.refuse();
            continue;
        };
        // Numbered now, in the order they arrive. Which of two connections from one ship
        // is the newer is decided by this, and not by which gets through its handshake
        // first: an old one that is slow to finish must not take the place of a new one.
        let admission = shared.admitted.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::spawn(answer_caller(shared.clone(), incoming, place, admission));
    }
}

/// The newest connection from one ship to a ship here: the number it was let in under, and
/// the connection while it is open. The number is kept after the connection has gone, so
/// that an older one still finishing its handshake does not then count as the newest.
struct Caller {
    admission: u64,
    connection: Option<Connection>,
}

/// How many (calling ship, called ship) pairs are remembered before those with no
/// connection open are forgotten. Open connections are within `max_connections`, so this
/// always leaves room for them.
fn most_callers(cfg: &NetConfig) -> usize {
    cfg.max_connections.saturating_mul(2).saturating_add(16)
}

/// Whether the connection `id` is still the newest from that ship to the ship here.
fn newest_from(shared: &Shared, pair: &Pair, id: usize) -> bool {
    let callers = lock(&shared.callers);
    callers.get(pair).and_then(|caller| caller.connection.as_ref()).is_some_and(|newest| newest.stable_id() == id)
}

/// One connection from another ship: learn who is calling and which ship they called, then
/// answer their requests until the connection closes.
async fn answer_caller(shared: Arc<Shared>, incoming: Incoming, _place: Place, admission: u64) {
    let Ok(connecting) = incoming.accept() else { return };
    let Ok(Ok(connection)) = tokio::time::timeout(shared.cfg.request_timeout, connecting).await else { return };
    // The caller has proved it holds a key. It now says which ship it is, and is believed
    // if that key is the one listed for the name.
    let greeted = tokio::time::timeout(shared.cfg.request_timeout, greet(&shared, &connection)).await;
    let Some(pair) = greeted.ok().flatten().and_then(|caller| parties(&shared, &connection, &caller)) else {
        connection.close(VarInt::from_u32(1), b"not a ship this runtime knows");
        return;
    };
    // One connection from each calling ship to each ship here. A newer one takes the place
    // of the older, so a ship cannot use up the places by connecting over and over.
    // Newer by when it arrived. A connection that arrived before the one already here is
    // the older of the two, however late it comes to this point, and is closed.
    {
        let mut callers = lock(&shared.callers);
        let newest = callers.get(&pair).map(|newest| newest.admission);
        if newest.is_some_and(|newest| newest > admission) || (newest.is_none() && admission <= shared.forgotten.load(Ordering::SeqCst)) {
            connection.close(VarInt::from_u32(5), b"replaced by a newer connection");
            return;
        }
        // Only so many pairs are remembered. Past that, those with no connection open are
        // forgotten, and the highest of their numbers is kept in their place.
        if newest.is_none() && callers.len() >= most_callers(&shared.cfg) {
            let mut highest = 0;
            callers.retain(|_, caller| {
                let open = caller.connection.as_ref().is_some_and(|connection| connection.close_reason().is_none());
                if !open {
                    highest = highest.max(caller.admission);
                }
                open
            });
            shared.forgotten.fetch_max(highest, Ordering::SeqCst);
        }
        let older = callers.insert(pair.clone(), Caller { admission, connection: Some(connection.clone()) });
        if let Some(older) = older.and_then(|older| older.connection) {
            older.close(VarInt::from_u32(5), b"replaced by a newer connection");
        }
    }
    while let Ok((send, receive)) = connection.accept_bi().await {
        tokio::spawn(answer_request(shared.clone(), connection.clone(), pair.clone(), send, receive));
    }
    // The connection has gone. Its number stays, as the newest there has been.
    let mut callers = lock(&shared.callers);
    if let Some(caller) = callers.get_mut(&pair).filter(|caller| caller.admission == admission) {
        caller.connection = None;
    }
}

/// One request on a connection from another ship.
async fn answer_request(shared: Arc<Shared>, connection: Connection, pair: Pair, mut send: SendStream, mut receive: RecvStream) {
    let limit = shared.cfg.request_timeout;
    let served = tokio::time::timeout(limit, async {
        // Room is set aside before a byte is read. With none to spare, the request is told so
        // at once, and nothing of it is taken in.
        let Ok(_room) = shared.reading.clone().try_acquire_many_owned(shared.cfg.max_message_bytes as u32) else {
            let _ = receive.stop(VarInt::from_u32(4));
            return reply(&mut send, &refused("too busy; try again")).await;
        };
        let Some(bytes) = read_whole(&mut receive, shared.cfg.max_message_bytes).await else {
            return reply(&mut send, &refused("the request could not be read, or was too large")).await;
        };
        // Who is calling was settled when the connection was made. It is checked again here,
        // with the whole request in hand and just before acting on it: the directory may
        // since have given that ship a new key or dropped it. A request that began arriving
        // while its sender was still listed is not acted on once it is not.
        // If its key was read from Urbit ID a while ago, it is read again, behind this.
        shared.freshen(&pair.0);
        if parties(&shared, &connection, &pair.0).as_ref() != Some(&pair) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return;
        }
        reply(&mut send, &answer(&shared, &connection, &pair.0, &pair.1, &bytes).await).await;
    })
    .await;
    if served.is_err() {
        // Out of time. Say so on the wire, so nothing of this request lingers at either end.
        let _ = send.reset(VarInt::from_u32(3));
        let _ = receive.stop(VarInt::from_u32(3));
    }
}

/// Read a whole message from a stream, up to `max` bytes. `None` if it is longer, or the
/// stream fails.
///
/// What arrives is copied straight into one buffer that never holds more than `max`. Keeping
/// the pieces as they arrive would not do: each piece can keep alive the whole packet it came
/// in, so a message sent a byte at a time could hold many times its own size in memory.
async fn read_whole(receive: &mut RecvStream, max: usize) -> Option<Vec<u8>> {
    let (mut whole, mut piece) = (Vec::new(), [0u8; 8192]);
    loop {
        match receive.read(&mut piece).await.ok()? {
            None => return Some(whole),
            Some(read) if whole.len() + read > max => return None,
            Some(read) => whole.extend_from_slice(&piece[..read]),
        }
    }
}

async fn reply(send: &mut SendStream, reply: &PeerReply) {
    let _ = send.write_all(&reply.encode_to_vec()).await;
    let _ = send.finish();
    // Wait for the caller to take the reply, so closing does not cut it short.
    let _ = send.stopped().await;
}

/// Who is at each end of a connection from another ship, as things stand now: the calling
/// ship, if the key it proved it holds is the one listed for the name it gave, and the
/// ship of this runtime that it asked for.
fn parties(shared: &Shared, connection: &Connection, caller: &str) -> Option<Pair> {
    if shared.directory.proved_key_of(caller)? != shown_key(connection)? {
        return None;
    }
    Some((caller.to_string(), called(shared, connection)?))
}

/// The ship of this runtime that a connection from another ship asked for.
fn called(shared: &Shared, connection: &Connection) -> Option<String> {
    let handshake = connection.handshake_data()?.downcast::<HandshakeData>().ok()?;
    let called = canonical_ship(handshake.server_name.as_deref()?).ok()?;
    // The ship is one this runtime holds, or no key could have been shown for it.
    shared.runtime.signing_key(&called).ok()?;
    Some(called)
}

/// Hear which ship is calling, on the first stream of its connection, and answer if it is
/// believed. The name of the caller if so. Nothing else on the connection is looked at
/// until this is done.
async fn greet(shared: &Arc<Shared>, connection: &Connection) -> Option<String> {
    let (mut send, mut receive) = connection.accept_bi().await.ok()?;
    let said = read_whole(&mut receive, MOST_HELLO_BYTES).await?;
    let Ok(PeerRequest { body: Some(peer_request::Body::Hello(hello)) }) = PeerRequest::decode(&*said) else { return None };
    let called = called(shared, connection)?;
    let caller = shared.admit(shown_key(connection)?, &hello).await?;
    // If the ship called is a moon, the caller may not know its key, and is shown its
    // parent's word for it.
    let proof = shared.runtime.moon_proof(&called).map(|proof| MoonProof { revision: proof.revision, signed: proof.signed.to_vec() });
    reply(&mut send, &PeerReply { body: Some(peer_reply::Body::Welcome(Welcome { proof })), refused: String::new() }).await;
    Some(caller)
}

/// What a ship says to a request of a kind it does not know.
const UNKNOWN_REQUEST: &str = "not a request this ship answers";

fn refused(why: &str) -> PeerReply {
    PeerReply { body: None, refused: why.to_string() }
}

/// Do a piece of work on a ship, off the network's own threads. Work on a ship can wait on
/// its file, and the network must keep answering meanwhile. Only so many are in hand at once.
/// `None` if the network is stopping.
async fn work<T: Send + 'static>(shared: &Shared, job: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let turn = shared.working.clone().acquire_owned().await.ok()?;
    let done = tokio::task::spawn_blocking(move || {
        let done = job();
        drop(turn);
        done
    });
    done.await.ok()
}

/// Answer one request from `caller` to `called`.
async fn answer(shared: &Arc<Shared>, connection: &Connection, caller: &str, called: &str, request: &[u8]) -> PeerReply {
    // Counted before it is decoded. A request of a megabyte can hold half a million empty
    // messages, and decoding would give each one a few hundred bytes of memory. The same
    // goes for the logs in a piece of news.
    if !repeats_within(request, 2, 1, MAX_BATCH_MESSAGES) || !repeats_within(request, 4, 1, MAX_NEWS_LOGS) {
        return refused("not a request, or one with too many messages");
    }
    let Ok(request) = PeerRequest::decode(request) else { return refused("not a request") };
    match request.body {
        Some(peer_request::Body::Ping(Ping { nonce })) if nonce.len() <= 64 => {
            // The ship's mark is kept in memory once it has been read, so this wakes the
            // ship at most once.
            let (runtime, ship) = (shared.runtime.clone(), called.to_string());
            let mark = work(shared, move || runtime.incarnation(&ship)).await.and_then(Result::ok);
            let incarnation = mark.map_or(Vec::new(), |mark| mark.to_vec());
            let pong = Pong { nonce, ship: called.to_string(), caller: caller.to_string(), incarnation };
            PeerReply { body: Some(peer_reply::Body::Pong(pong)), refused: String::new() }
        }
        // Where the caller stands with a ship here, for the two to get back in step. The
        // ship here brings its account into line and says where it stands in turn.
        Some(peer_request::Body::Resync(Resync { standing: Some(standing) })) => {
            // An account that cannot be so is answered with none. That is an answer, and a
            // final one, where a refusal would be taken as a reason to try again.
            let unsound = PeerReply { body: Some(peer_reply::Body::Resynced(Resynced { standing: None })), refused: String::new() };
            let Some(theirs) = stand_read(&standing) else { return unsound };
            // If the ship here is comparing notes with that one at its own asking right now,
            // one of the two has to wait: each taking the other's account in would make
            // the answer each is waiting for out of date, and they could go on like that.
            // The ship whose name comes first goes first. The other is told to try again,
            // and nothing of its account is taken in.
            if called < caller && lock(&shared.carrier.resyncing).contains(&(called.to_string(), caller.to_string())) {
                return refused("comparing notes the other way just now; try again");
            }
            let (runtime, ship, peer, most) = (shared.runtime.clone(), called.to_string(), caller.to_string(), most_owed(shared));
            // The account is acted on only if this is still the newest connection from that
            // ship when the ship here comes to act on it. If that ship has since come back
            // as an earlier copy of itself, it has connected afresh, and this account is of
            // a ship that is no longer there.
            let (callers, pair, id) = (shared.clone(), (caller.to_string(), called.to_string()), connection.stable_id());
            let current = move || newest_from(&callers, &pair, id);
            match work(shared, move || runtime.resync(&ship, &peer, &theirs, most, current)).await {
                Some(Ok(None)) => refused("that account is no longer the newest; try again"),
                Some(Ok(Some((ours, _, queued)))) => {
                    if queued {
                        shared.carrier.run_at(called);
                    }
                    // Whatever had stopped commands between the two may be put right now.
                    if let Some(lane) = lock(&shared.carrier.lanes).get_mut(&(called.to_string(), caller.to_string())) {
                        lane.stalled = false;
                    }
                    shared.carrier.look_at(called);
                    PeerReply { body: Some(peer_reply::Body::Resynced(Resynced { standing: Some(stand_sent(&ours)) })), refused: String::new() }
                }
                Some(Err(Error::OutOfStep(_))) => unsound,
                _ => refused("the account could not be taken; try again"),
            }
        }
        // Commands for a ship here, from the ship at the other end. Who that is was proved
        // when the connection was made and checked again just now, so they are filed as
        // coming from it and nobody else.
        Some(peer_request::Body::Deliver(Deliver { messages })) => {
            let (runtime, ship, peer) = (shared.runtime.clone(), called.to_string(), caller.to_string());
            // Taken only if this is still the newest connection from that ship when the
            // ship here comes to take them: see the same check on comparing notes, below.
            let (callers, pair, id) = (shared.clone(), (caller.to_string(), called.to_string()), connection.stable_id());
            let current = move || newest_from(&callers, &pair, id);
            let taken = work(shared, move || runtime.accept_commands(&ship, &peer, &messages, current)).await;
            let Some(Ok(last)) = taken else { return refused("the commands could not be taken; try again") };
            // They are saved. Running them is the ship's own business and is not waited for:
            // the sender is told only that they arrived.
            shared.carrier.run_at(called);
            PeerReply { body: Some(peer_reply::Body::Delivered(Delivered { last })), refused: String::new() }
        }
        // Entries of one of a ship's logs, for the ship at the other end, which follows it
        // or wants to. Whether it may is for the log's publisher, and is looked up afresh
        // each time.
        Some(peer_request::Body::Fetch(fetch)) => {
            let (runtime, ship, peer, most) = (shared.runtime.clone(), called.to_string(), caller.to_string(), shared.cfg.max_message_bytes / 2);
            match work(shared, move || runtime.serve_log(&ship, &peer, &fetch, most)).await {
                Some(Ok(fetched)) => PeerReply { body: Some(peer_reply::Body::Fetched(fetched)), refused: String::new() },
                _ => refused("the log could not be read; try again"),
            }
        }
        // News of the caller's logs, for agents here that follow them.
        Some(peer_request::Body::News(News { logs })) => {
            let (runtime, ship, peer) = (shared.runtime.clone(), called.to_string(), caller.to_string());
            let Some(Ok(unknown)) = work(shared, move || runtime.hear_news(&ship, &peer, &logs)).await else {
                return refused("the news could not be taken; try again");
            };
            // There may now be something to ask that ship for.
            shared.carrier.look_at(called);
            PeerReply { body: Some(peer_reply::Body::Heard(Heard { unknown })), refused: String::new() }
        }
        _ => refused(UNKNOWN_REQUEST),
    }
}

/// Whether an encoded request or reply is one that can be walked through field by field and
/// in which field `outer`, a message, holds at most `most` of its field `inner`: the
/// messages in a delivery, the logs in a piece of news, the entries in an answer. This reads
/// only the sizes written there and keeps nothing, so it costs nothing to run on something
/// that is all padding.
fn repeats_within(request: &[u8], outer: u64, inner: u64, most: usize) -> bool {
    /// Walk the fields of one encoded message, handing each length-delimited one to `each`.
    /// False if the bytes are not fields from end to end, or `each` says to stop.
    fn walk<'a>(mut bytes: &'a [u8], mut each: impl FnMut(u64, &'a [u8]) -> bool) -> bool {
        fn varint(bytes: &mut &[u8]) -> Option<u64> {
            let mut value = 0u64;
            for shift in (0..64).step_by(7) {
                let (&byte, rest) = bytes.split_first()?;
                *bytes = rest;
                value |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    return Some(value);
                }
            }
            None
        }
        while !bytes.is_empty() {
            let Some(key) = varint(&mut bytes) else { return false };
            let skipped = match key & 7 {
                0 => varint(&mut bytes).map(drop),
                1 => bytes.get(8..).map(|rest| bytes = rest),
                5 => bytes.get(4..).map(|rest| bytes = rest),
                2 => varint(&mut bytes).and_then(|len| {
                    let len = usize::try_from(len).ok()?;
                    let body = bytes.get(..len)?;
                    bytes = &bytes[len..];
                    each(key >> 3, body).then_some(())
                }),
                // Groups are not used by anything a ship sends.
                _ => None,
            };
            if skipped.is_none() {
                return false;
            }
        }
        true
    }
    let mut count = 0usize;
    // A field may be given more than once, and all of them count.
    walk(request, |field, body| {
        field != outer
            || walk(body, |field, _| {
                count += usize::from(field == inner);
                count <= most
            })
    })
}

/// Carry commands from this runtime's ships to other ships, for as long as the network runs.
async fn carry(shared: Arc<Shared>) {
    let carrier = &shared.carrier;
    let mut check_at = tokio::time::Instant::now() + shared.cfg.follow_check;
    loop {
        // Now and then, ask the ships whose logs are followed from here whether they are
        // still the copies of themselves they were. One round at a time.
        if tokio::time::Instant::now() >= check_at {
            check_at = tokio::time::Instant::now() + shared.cfg.follow_check;
            if !carrier.checking.swap(true, Ordering::SeqCst) {
                tokio::spawn(check_publishers(shared.clone()));
            }
        }
        // Ships that may have events queued: see that they are run.
        let ships: Vec<String> = lock(&carrier.queued).drain().collect();
        for ship in ships {
            tend(&shared, ship);
        }
        // Ships that may have commands waiting: see which other ships they are for.
        let ships: Vec<String> = lock(&carrier.waiting).drain().collect();
        for ship in ships {
            let (runtime, name) = (shared.runtime.clone(), ship.clone());
            let peers = work(&shared, move || runtime.outbound_peers(&name)).await;
            for (peer, work) in peers.and_then(Result::ok).unwrap_or_default() {
                start_lane(&shared, &ship, &peer, work);
            }
        }
        // Then wait for news, or for the earliest moment a failed lane may be tried again.
        let now = tokio::time::Instant::now();
        let mut next = Some(check_at);
        for ((ship, _), lane) in lock(&carrier.lanes).iter_mut().filter(|(_, lane)| !lane.busy) {
            match lane.retry_at {
                Some(at) if at <= now => {
                    lane.retry_at = None;
                    lock(&carrier.waiting).insert(ship.clone());
                }
                Some(at) => next = Some(next.map_or(at, |soonest: tokio::time::Instant| soonest.min(at))),
                None => {}
            }
        }
        if !lock(&carrier.waiting).is_empty() || !lock(&carrier.queued).is_empty() {
            continue;
        }
        match next {
            Some(at) => drop(tokio::time::timeout_at(at, carrier.news.notified()).await),
            None => carrier.news.notified().await,
        }
    }
}

/// See that what is queued on a ship is run.
///
/// Commands another ship delivers are acknowledged as soon as they are saved, so that ship
/// will not send them again. From then on it is up to this runtime to run them, all of them,
/// however many arrived at once. So everything that is queued when this starts is run, in
/// rounds of `max_queued_per_deliver` events, giving up its turn between rounds so that one
/// busy ship does not keep the others waiting.
///
/// What those events queue in their turn gets one more round and no further. Agents that
/// keep sending each other commands would otherwise keep a ship running for ever on the
/// strength of one command from outside. The rest wait, as they do after any event.
///
/// With `max_queued_per_deliver` set to nothing, the network runs nothing, and the queue is
/// left to whoever embeds the runtime.
///
/// One of these runs for a ship at a time. If more arrives meanwhile, it goes round again.
/// If the queue cannot be run, most likely because the ship's file is full, it is tried
/// again a few times at growing intervals, and then left for the next arrival or the next
/// start. Whatever could not be run is still queued.
fn tend(shared: &Arc<Shared>, ship: String) {
    /// How many times in a row a ship's queue is tried again after failing to run.
    const TRIES: u32 = 8;
    {
        let mut tending = lock(&shared.carrier.tending);
        if let Some(again) = tending.get_mut(&ship) {
            *again = true;
            return;
        }
        tending.insert(ship.clone(), false);
    }
    let shared = shared.clone();
    tokio::spawn(async move {
        let most = shared.runtime.inner.cfg.max_queued_per_deliver;
        let (mut failures, mut delay) = (0, Duration::ZERO);
        loop {
            // `None` means the network is stopping.
            let ran = if most == 0 { None } else { run_queue(&shared, &ship, most).await };
            let failed = matches!(ran, Some(Err(_)));
            failures = if failed { failures + 1 } else { 0 };
            {
                let mut tending = lock(&shared.carrier.tending);
                let again = tending.get_mut(&ship).is_some_and(std::mem::take);
                if ran.is_none() || !(again || (failed && failures < TRIES)) {
                    tending.remove(&ship);
                    return;
                }
            }
            if failed {
                delay = if delay.is_zero() { shared.cfg.retry_delay } else { (delay * 2).min(shared.cfg.max_retry_delay) };
                tokio::time::sleep(delay).await;
            } else {
                delay = Duration::ZERO;
                tokio::task::yield_now().await;
            }
        }
    });
}

/// Run everything queued on a ship as of now, then one round of what that queued.
async fn run_queue(shared: &Arc<Shared>, ship: &str, most: usize) -> Option<Result<(), Error>> {
    let (runtime, name) = (shared.runtime.clone(), ship.to_string());
    let through = match work(shared, move || runtime.inbox_newest(&name)).await? {
        Ok(newest) => newest,
        Err(e) => return Some(Err(e)),
    };
    loop {
        let (runtime, name) = (shared.runtime.clone(), ship.to_string());
        match work(shared, move || runtime.run_pending_through(&name, most, through)).await? {
            Ok((_, true)) => tokio::task::yield_now().await,
            Ok((_, false)) => break,
            Err(e) => return Some(Err(e)),
        }
    }
    let (runtime, name) = (shared.runtime.clone(), ship.to_string());
    Some(work(shared, move || runtime.run_pending(&name, most)).await?.map(drop))
}

/// Take up with one other ship whatever one ship has for it, unless that is already under
/// way or has to wait after a failure. Commands are left alone between two ships that
/// disagree about them; their logs go on regardless.
fn start_lane(shared: &Arc<Shared>, ship: &str, peer: &str, work: PeerWork) {
    let pair = (ship.to_string(), peer.to_string());
    let messages = {
        let mut lanes = lock(&shared.carrier.lanes);
        let lane = lanes.entry(pair.clone()).or_default();
        let messages = work.messages && !lane.stalled;
        if lane.busy || lane.retry_at.is_some() || !(messages || work.logs) {
            return;
        }
        lane.busy = true;
        messages
    };
    let shared = shared.clone();
    tokio::spawn(async move {
        let carried = carry_lane(&shared, &pair.0, &pair.1, messages, work.logs).await;
        {
            let mut lanes = lock(&shared.carrier.lanes);
            let lane = lanes.entry(pair.clone()).or_default();
            lane.busy = false;
            match carried {
                Carried::All => (lane.retry_at, lane.delay) = (None, Duration::ZERO),
                Carried::NotYet => {
                    let delay = if lane.delay.is_zero() { shared.cfg.retry_delay } else { (lane.delay * 2).min(shared.cfg.max_retry_delay) };
                    (lane.retry_at, lane.delay) = (Some(tokio::time::Instant::now() + delay), delay);
                }
                Carried::OutOfStep => lane.stalled = true,
            }
        }
        // Something may have been queued while this was finishing, and the wait may need
        // working out again.
        shared.carrier.look_at(&pair.0);
    });
}

/// How one part of what two ships have for each other went.
enum Step {
    /// Done, or as far as one turn goes; anything left is found when the ship is looked at again.
    Done,
    /// The other ship answered, but something could not be done yet. Try again after a while.
    Later,
    /// The other ship could not be reached. Nothing else will get through to it either.
    Lost,
}

/// Whether a request failed because the other ship could not be reached at all.
fn lost(error: &NetError) -> bool {
    matches!(error, NetError::Unreachable(_) | NetError::TimedOut | NetError::Unlisted(_) | NetError::NotHere(_))
}

/// Take up with one other ship everything one ship has for it: news of its logs, entries of
/// the other ship's logs to ask for, and messages waiting to go.
async fn carry_lane(shared: &Arc<Shared>, ship: &str, peer: &str, messages: bool, logs: bool) -> Carried {
    let mut later = false;
    if logs {
        for step in [tell_news(shared, ship, peer).await, fetch_logs(shared, ship, peer).await] {
            match step {
                Step::Done => {}
                Step::Later => later = true,
                Step::Lost => return Carried::NotYet,
            }
        }
    }
    if messages {
        match carry_messages(shared, ship, peer).await {
            Carried::All => {}
            other => return other,
        }
    }
    if later { Carried::NotYet } else { Carried::All }
}

/// Tell one other ship what it has yet to hear about the logs of this ship that it follows:
/// that they have grown, or are closed to it.
async fn tell_news(shared: &Arc<Shared>, ship: &str, peer: &str) -> Step {
    /// How many rounds go to one ship in one turn.
    const ROUNDS: usize = 4;
    for _ in 0..ROUNDS {
        let Ok(_turn) = shared.carrying.acquire().await else { return Step::Later };
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        let pair = (ship.to_string(), peer.to_string());
        let after = lock(&shared.carrier.lanes).get(&pair).and_then(|lane| lane.told.clone());
        let Some(Ok(mut told)) = work(shared, move || runtime.outbound_news(&from, &to, after)).await else { return Step::Later };
        if told.is_empty() {
            return Step::Done;
        }
        // Only as much as the other ship will read in one request. The rest stays marked
        // as untold, and goes next time round.
        fitting(&mut told, shared.cfg.max_message_bytes / 2);
        let logs = told.iter().map(crate::store::NewsItem::as_sent).collect();
        let unknown = match shared.ask(ship, peer, PeerRequest { body: Some(peer_request::Body::News(News { logs })) }).await {
            Ok(PeerReply { body: Some(peer_reply::Body::Heard(Heard { unknown })), .. }) if unknown.len() <= told.len() => unknown,
            Err(error) if lost(&error) => return Step::Lost,
            _ => return Step::Later,
        };
        // The next piece of news starts after the last log in this one.
        if let (Some(last), Some(lane)) = (told.last(), lock(&shared.carrier.lanes).get_mut(&pair)) {
            lane.told = Some((last.agent.clone(), last.name.clone()));
        }
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        if !matches!(work(shared, move || runtime.news_heard(&from, &to, &told, &unknown)).await, Some(Ok(()))) {
            return Step::Later;
        }
    }
    Step::Done
}

/// Cut a piece of news down to what fits in `most` bytes as it will be sent, keeping at least
/// one log.
fn fitting(told: &mut Vec<crate::store::NewsItem>, most: usize) {
    let mut bytes = 0usize;
    let fits = told.iter().take_while(|item| {
        bytes += item.as_sent().encoded_len() + 8;
        bytes <= most
    });
    let keep = fits.count().max(1);
    told.truncate(keep);
}

/// Ask one other ship for the entries of its logs that agents on this ship follow and have
/// room for, and take in what it answers.
async fn fetch_logs(shared: &Arc<Shared>, ship: &str, peer: &str) -> Step {
    /// How many times one log is asked for in one turn.
    const ROUNDS: usize = 8;
    let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
    let Some(Ok((jobs, blocked))) = work(shared, move || runtime.follow_work(&from, &to)).await else { return Step::Later };
    // This ship follows logs on that one, so that one is among the ships asked now and
    // then whether they are still what they were.
    if !jobs.is_empty() || blocked {
        lock(&shared.carrier.watching).entry((ship.to_string(), peer.to_string())).or_insert(None);
    }
    let mut later = blocked;
    for mut job in jobs {
        for _ in 0..ROUNDS {
            let Ok(_turn) = shared.carrying.acquire().await else { return Step::Later };
            let fetch = Fetch {
                agent: job.agent.clone(),
                log: job.name.clone(),
                after: job.after,
                max_bytes: job.room.min((shared.cfg.max_message_bytes / 2) as u64) as u32,
                joining: job.joining,
            };
            let (fetched, key) = match shared.ask_keyed(ship, peer, PeerRequest { body: Some(peer_request::Body::Fetch(fetch)) }).await {
                Ok((PeerReply { body: Some(peer_reply::Body::Fetched(fetched)), .. }, key)) => (fetched, key),
                Err(error) if lost(&error) => return Step::Lost,
                _ => {
                    later = true;
                    break;
                }
            };
            let (runtime, from, to, asked) = (shared.runtime.clone(), ship.to_string(), peer.to_string(), job.clone());
            let Some(Ok((taken, queued))) = work(shared, move || runtime.take_entries(&from, &to, &key, &asked, &fetched)).await else {
                later = true;
                break;
            };
            // What was taken is saved, and the agent that follows the log has been queued a
            // notice. Running it is up to this runtime.
            if queued {
                shared.carrier.run_at(ship);
            }
            match taken {
                Taken::More(next) => job = next,
                Taken::Done => break,
                // No room, so wait a while. And a log that has stopped counts as a try that
                // failed: an agent that answers every refusal by asking again is then held
                // to the pace at which failed tries are made, however fast the other ship
                // refuses, and cannot keep its ship and that one busy without end.
                Taken::NoRoom | Taken::Stopped => {
                    later = true;
                    break;
                }
            }
        }
    }
    if later { Step::Later } else { Step::Done }
}

/// How many of the other ship's commands a ship lists as owed when it says where it stands:
/// as many as it may owe at all. The network does not start unless a message has room for
/// them, so the list is always whole.
fn most_owed(shared: &Shared) -> usize {
    shared.runtime.inner.cfg.max_unanswered
}

/// Where a ship stands, as it is sent.
fn stand_sent(stand: &Stand) -> Standing {
    let owed = stand.owed.iter().flat_map(|seq| seq.to_le_bytes()).collect();
    Standing { sent: stand.sent, received: stand.received, oldest: stand.oldest, owed, owed_complete: stand.owed_complete }
}

/// Where a ship stands, as it was sent. `None` if the list of what it owes is not whole numbers.
fn stand_read(standing: &Standing) -> Option<Stand> {
    if standing.owed.len() % 8 != 0 {
        return None;
    }
    let owed = standing.owed.chunks_exact(8).map(|seq| u64::from_le_bytes(seq.try_into().expect("eight bytes"))).collect();
    Some(Stand { sent: standing.sent, received: standing.received, oldest: standing.oldest, owed, owed_complete: standing.owed_complete, mark: 0, epoch: 0 })
}

/// Get one ship back in step with another: say where it stands, hear where the other
/// stands, and bring its own account into line. If that moved its account, the other ship
/// has to hear the new one, so it goes round again, a few times at most.
///
/// `All` means the two agree and nothing is left to settle. `NotYet` means try again after a
/// while. `OutOfStep` means the other ship will not do this, or what it says cannot be so.
async fn resync(shared: &Arc<Shared>, ship: &str, peer: &str) -> Carried {
    const ROUNDS: usize = 4;
    let most = most_owed(shared);
    // For as long as this goes on, the pair is down as comparing notes at this ship's
    // asking: see where a request to compare notes is answered.
    struct Comparing<'a>(&'a Shared, Pair);
    impl Drop for Comparing<'_> {
        fn drop(&mut self) {
            lock(&self.0.carrier.resyncing).remove(&self.1);
        }
    }
    let pair = (ship.to_string(), peer.to_string());
    lock(&shared.carrier.resyncing).insert(pair.clone());
    let _comparing = Comparing(shared, pair.clone());
    // If there are commands the other ship has yet to answer, the pair is looked at again
    // later, in case the answers never come.
    lock(&shared.carrier.awaiting).insert(pair);
    // (Whoever calls this holds a turn among the deliveries in hand. It takes none of its own.)
    for _ in 0..ROUNDS {
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        let Some(Ok(ours)) = work(shared, move || runtime.standing(&from, &to, most)).await else { return Carried::NotYet };
        let request = PeerRequest { body: Some(peer_request::Body::Resync(Resync { standing: Some(stand_sent(&ours)) })) };
        let theirs = match shared.ask(ship, peer, request).await {
            // Where it stands, or its word that what this ship said cannot be so.
            Ok(PeerReply { body: Some(peer_reply::Body::Resynced(Resynced { standing })), .. }) => standing.as_ref().and_then(stand_read),
            // A ship that does not know this request cannot be got back in step with.
            Err(NetError::Refused(why)) if why == UNKNOWN_REQUEST => None,
            // Anything else is a reason to try again: it could not be reached, was busy, or
            // had no room just now.
            _ => return Carried::NotYet,
        };
        let Some(theirs) = theirs else { return Carried::OutOfStep };
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        match work(shared, move || runtime.resync_answered(&from, &to, &theirs, most, ours.epoch)).await {
            // The two compared notes again while this was on its way, so the answer is to
            // an account that no longer holds. Round again, from where things stand now.
            Some(Ok(None)) => continue,
            Some(Ok(Some((_, finished, queued)))) => {
                if queued {
                    shared.carrier.run_at(ship);
                }
                // Something could not be settled for want of room. It is gone over again later.
                if !finished {
                    return Carried::NotYet;
                }
            }
            Some(Err(Error::OutOfStep(_))) => return Carried::OutOfStep,
            _ => return Carried::NotYet,
        }
        // The other ship has heard where this one stood before this round. If that is
        // still where it stands, they are done.
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        match work(shared, move || runtime.resync_heard(&from, &to, ours.mark)).await {
            Some(Ok(false)) => return Carried::All,
            Some(Ok(true)) => {}
            _ => return Carried::NotYet,
        }
    }
    Carried::NotYet
}

/// Ask each ship whose logs are followed from here for its mark, and where the mark is not
/// the one that ship showed before, have the ship that follows it ask afresh.
///
/// A ship that has been brought back from a saved copy may no longer know that a ship
/// follows it, if that ship started following after the copy was saved. It would never
/// say when its logs grow, and the follower would wait for ever. Only the follower can
/// find that out, by asking.
async fn check_publishers(shared: Arc<Shared>) {
    let pairs: Vec<(Pair, Option<[u8; 16]>)> = lock(&shared.carrier.watching).iter().map(|(pair, mark)| (pair.clone(), *mark)).collect();
    for ((ship, peer), known) in pairs {
        let Ok(_turn) = shared.carrying.acquire().await else { break };
        let nonce = crate::store::now_ms().to_le_bytes().to_vec();
        let asked = PeerRequest { body: Some(peer_request::Body::Ping(Ping { nonce: nonce.clone() })) };
        let Ok(PeerReply { body: Some(peer_reply::Body::Pong(pong)), .. }) = shared.ask(&ship, &peer, asked).await else { continue };
        // A ship that shows no mark is one from before there were marks: nothing to go by.
        let Ok(mark) = <[u8; 16]>::try_from(&pong.incarnation[..]) else { continue };
        if pong.nonce != nonce || known == Some(mark) {
            continue;
        }
        // Not the mark it showed before, or the first time of asking since this runtime
        // started: checked against what the ship's own file says it last saw.
        let (runtime, from, to) = (shared.runtime.clone(), ship.clone(), peer.clone());
        match work(&shared, move || runtime.publisher_seen(&from, &to, &mark)).await {
            // Nothing is followed there any more. The pair is struck off, and then looked
            // at once more: an agent may have started following again in the meantime,
            // and its being put back on the list must not be what is struck off.
            Some(Ok((0, _))) => {
                lock(&shared.carrier.watching).remove(&(ship.clone(), peer.clone()));
                let (runtime, from, to) = (shared.runtime.clone(), ship.clone(), peer.clone());
                match work(&shared, move || runtime.publisher_seen(&from, &to, &mark)).await {
                    Some(Ok((0, _))) => {}
                    Some(Ok((_, stale))) => {
                        lock(&shared.carrier.watching).insert((ship.clone(), peer), Some(mark));
                        if stale {
                            shared.carrier.look_at(&ship);
                        }
                    }
                    // It could not be looked at. Kept on the list, as not yet checked.
                    _ => drop(lock(&shared.carrier.watching).insert((ship, peer), None)),
                }
            }
            Some(Ok((_, stale))) => {
                lock(&shared.carrier.watching).insert((ship.clone(), peer), Some(mark));
                if stale {
                    shared.carrier.look_at(&ship);
                }
            }
            _ => {}
        }
    }
    // And each ship that may have commands another has yet to answer. A ship that has
    // gone back to a state from before it ever dealt with this one does not know there is
    // anything to put right, and with nothing waiting to go to it, nothing here would find
    // out. So where answers are still owed, the two compare notes: no change between ships
    // that are in step, and the only way to learn that an answer is never coming.
    let pairs: Vec<Pair> = lock(&shared.carrier.awaiting).iter().cloned().collect();
    for (ship, peer) in pairs {
        // The pair is taken off the list before it is looked at, and put back unless
        // everything turns out to have been answered. Taken off afterwards, on the strength
        // of what was seen a moment before, it could take with it a command that went in
        // between.
        lock(&shared.carrier.awaiting).remove(&(ship.clone(), peer.clone()));
        let (runtime, from, to) = (shared.runtime.clone(), ship.clone(), peer.clone());
        match work(&shared, move || runtime.probe_waits(&from, &to)).await {
            // Everything has been answered. The pair goes back on when more commands go.
            Some(Ok(false)) => {}
            Some(Ok(true)) => {
                lock(&shared.carrier.awaiting).insert((ship.clone(), peer));
                shared.carrier.look_at(&ship);
            }
            // It could not be looked at. Kept, to be looked at next time.
            _ => drop(lock(&shared.carrier.awaiting).insert((ship, peer))),
        }
    }
    shared.carrier.checking.store(false, Ordering::SeqCst);
}

/// Carry what one ship has waiting for one other ship, a batch at a time, in order: a few
/// batches in one turn. If more is waiting after that, the ship is looked at again and the
/// lane has another turn, which begins with the two ships' logs. Carrying on here until
/// nothing was waiting would let a steady run of commands keep news of a log, or the asking
/// for one, from ever having its turn.
async fn carry_messages(shared: &Arc<Shared>, ship: &str, peer: &str) -> Carried {
    /// How many batches go to one ship in one turn.
    const ROUNDS: usize = 8;
    // If this ship's account of the other has moved, or it has been brought in from a saved
    // copy, the other ship has to hear where it stands before anything else goes.
    let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
    let mut resynced = false;
    if let Some(Ok(true)) = work(shared, move || runtime.resync_due(&from, &to)).await {
        let Ok(_turn) = shared.carrying.acquire().await else { return Carried::NotYet };
        match resync(shared, ship, peer).await {
            Carried::All => {}
            other => return other,
        }
    }
    for _ in 0..ROUNDS {
        // One turn for each batch, taken before the batch is read out and given back when it
        // has gone, so that a busy pair of ships does not keep the others waiting.
        let Ok(_turn) = shared.carrying.acquire().await else { return Carried::NotYet };
        let (runtime, from, to, most) = (shared.runtime.clone(), ship.to_string(), peer.to_string(), shared.cfg.max_message_bytes / 2);
        let Some(Ok((batch, epoch))) = work(shared, move || runtime.outbound_batch(&from, &to, most)).await else { return Carried::NotYet };
        let (Some(first), Some(newest)) = (batch.first().map(|message| message.seq), batch.last().map(|message| message.seq)) else {
            return Carried::All;
        };
        let request = PeerRequest { body: Some(peer_request::Body::Deliver(Deliver { messages: batch })) };
        let Ok(PeerReply { body: Some(peer_reply::Body::Delivered(Delivered { last })), .. }) = shared.ask(ship, peer, request).await else {
            return Carried::NotYet;
        };
        let (runtime, from, to) = (shared.runtime.clone(), ship.to_string(), peer.to_string());
        match work(shared, move || runtime.outbound_acked(&from, &to, first, last, epoch)).await {
            // Commands have gone that the other ship now has to answer.
            Some(Ok(Acked::Taken)) => drop(lock(&shared.carrier.awaiting).insert((ship.to_string(), peer.to_string()))),
            // The two compared notes while this delivery was under way, so what the other
            // ship said it held, it said as it was before. The delivery is made again.
            Some(Ok(Acked::Stale)) => continue,
            // The other ship holds less than this ship has let go of, or more than it
            // remembers sending. One of the two has gone back to an earlier state. They
            // say where each stands and bring their accounts into line, once. If they are
            // still out of step after that, something is wrong that this cannot put right.
            Some(Ok(Acked::Short)) | Some(Err(Error::OutOfStep(_))) => {
                if std::mem::replace(&mut resynced, true) {
                    return Carried::OutOfStep;
                }
                match resync(shared, ship, peer).await {
                    Carried::All => continue,
                    other => return other,
                }
            }
            _ => return Carried::NotYet,
        }
        // It had no room for some of them. They wait, and go again later.
        if last < newest {
            return Carried::NotYet;
        }
    }
    Carried::All
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for Urbit ID in which every galaxy, star and planet has a key at
    /// revision one, made from its number, unless the test has said otherwise for it:
    /// a key (or none) at some revision, or that there is no such ship.
    #[derive(Default)]
    struct Told(Mutex<HashMap<u32, Option<(Option<[u8; 32]>, u32)>>>, AtomicUsize, AtomicU64);

    impl Told {
        /// How many times it has been asked.
        fn asked(&self) -> usize {
            self.1.load(Ordering::SeqCst)
        }

        /// Take this many milliseconds over every answer from now on.
        fn slow(&self, millis: u64) {
            self.2.store(millis, Ordering::SeqCst);
        }
    }

    impl Told {
        fn say(&self, ship: u32, listing: Option<(Option<[u8; 32]>, u32)>) {
            lock(&self.0).insert(ship, listing);
        }
    }

    impl Keys for Told {
        fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
            self.1.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(self.2.load(Ordering::SeqCst)));
            let (key, revision) = match lock(&self.0).get(&ship) {
                Some(None) => return Ok(None),
                Some(Some(told)) => *told,
                None => (Some(key_of_number(ship)), 1),
            };
            Ok(Some(Listing { key, revision, continuity: 0, sponsor: None }))
        }
    }

    fn key_of_number(ship: u32) -> [u8; 32] {
        let mut key = [0x55; 32];
        key[..4].copy_from_slice(&ship.to_be_bytes());
        key
    }

    fn name(ship: u32) -> String {
        ob::ship_name(ship).trim_start_matches('~').to_string()
    }

    fn moon_of(planet: u32, nth: u64) -> (u64, String) {
        let moon = nth << 32 | planet as u64;
        (moon, ob::moon_name(moon).unwrap().trim_start_matches('~').to_string())
    }

    /// A directory with little room, whose keys are read again as soon as they are a
    /// moment old and are believed for `good_for`.
    fn small(told: &Arc<Told>, good_for: Duration) -> Arc<Directory> {
        let bounds = Bounds { proved: 12, unproved: 8, moons: 5, moons_each: 3 };
        Directory::made(Some(told.clone()), Duration::from_millis(1), good_for, bounds)
    }

    /// Read a ship's key again, as the network would once something had cast doubt on it.
    fn reread(directory: &Directory, ship: u32) {
        std::thread::sleep(Duration::from_millis(3));
        directory.doubt(&name(ship));
        directory.read(&name(ship));
    }

    /// Have `count` planets nobody has heard of looked up, starting from `first`.
    fn crowd(directory: &Directory, first: u32, count: u32) {
        for ship in first..first + count {
            directory.read(&name(ship));
        }
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn keys_nobody_has_proved_make_way_for_each_other_and_for_nothing_else() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        let count = |directory: &Directory| directory.listed.read().unwrap().keys.len();
        // Eight planets are looked up because someone said their names. None proves
        // anything. There is room for eight such.
        crowd(&directory, 0x1000_0000, 8);
        assert_eq!(count(&directory), 8);
        assert_eq!(directory.key_of(&name(0x1000_0000)), Some(key_of_number(0x1000_0000)));
        // The ninth has the older half dropped, and the record of asking about them, so
        // that they are asked about afresh if they are wanted. The newer ones stay.
        std::thread::sleep(Duration::from_millis(3));
        crowd(&directory, 0x1000_0008, 1);
        assert_eq!(count(&directory), 4);
        assert_eq!(directory.key_of(&name(0x1000_0000)), None);
        assert_eq!(directory.due(&name(0x1000_0000)), Due::Now);
        // Only what was dropped is forgotten: not the ones that stay, not the one room
        // was made for, and not a ship that was asked about and found to have no keys.
        let asked = |ship: u32| directory.listed.read().unwrap().asked.contains_key(&name(ship));
        assert!((0x1000_0000..0x1000_0005).all(|ship| !asked(ship)));
        assert!((0x1000_0005..0x1000_0009).all(asked));
        assert_eq!(directory.key_of(&name(0x1000_0007)), Some(key_of_number(0x1000_0007)));
        assert_eq!(directory.key_of(&name(0x1000_0008)), Some(key_of_number(0x1000_0008)));
        // A key nobody has proved is a key all the same, to call a ship by. It is not one
        // a connection from that ship is taken on.
        assert_eq!(directory.proved_key_of(&name(0x1000_0008)), None);
        told.say(0x2000_0003, Some((None, 9)));
        directory.read(&name(0x2000_0003));
        std::thread::sleep(Duration::from_millis(3));
        crowd(&directory, 0x1000_0010, 12);
        assert!(asked(0x2000_0003) && asked(0x1000_001b) && !asked(0x1000_0005));

        // A ship that proves its key is kept, however many names are said after it. So is
        // one set by hand. Proving takes the key held, and no other, and a ship held.
        let (proved, set) = (0x2000_0000u32, 0x2000_0001u32);
        directory.read(&name(proved));
        assert!(!directory.prove(&name(proved), &[9; 32]));
        assert!(!directory.prove(&name(0x2000_0009), &key_of_number(0x2000_0009)));
        assert_eq!(directory.proved_key_of(&name(proved)), None);
        assert!(directory.prove(&name(proved), &key_of_number(proved)));
        assert_eq!(directory.proved_key_of(&name(proved)), Some(key_of_number(proved)));
        directory.set(&name(set), [4; 32], "127.0.0.1:9".parse().unwrap()).unwrap();
        crowd(&directory, 0x1100_0000, 40);
        assert!(count(&directory) <= 8 + 2);
        assert_eq!(directory.key_of(&name(proved)), Some(key_of_number(proved)));
        assert_eq!(directory.key_of(&name(set)), Some([4; 32]));

        // Its keys are replaced in Urbit ID: revision two. It was kept for having proved
        // the old one, and it is kept still, though nobody has proved the new one. So what
        // is known of it is still there after another crowd, and an answer from somewhere
        // that is behind, with the old key, is not news.
        let later = [7; 32];
        told.say(proved, Some((Some(later), 2)));
        reread(&directory, proved);
        assert_eq!(directory.key_of(&name(proved)), Some(later));
        crowd(&directory, 0x1200_0000, 40);
        assert_eq!(directory.key_of(&name(proved)), Some(later));
        told.say(proved, Some((Some(key_of_number(proved)), 1)));
        reread(&directory, proved);
        assert_eq!(directory.key_of(&name(proved)), Some(later));
        // The same when its keys are taken away: revision three. Nothing answers to its
        // name, and the keys it had do not come back, crowd or no crowd.
        told.say(proved, Some((None, 3)));
        reread(&directory, proved);
        assert_eq!(directory.key_of(&name(proved)), None);
        crowd(&directory, 0x1300_0000, 40);
        for behind in [Some((Some(later), 2)), Some((Some(key_of_number(proved)), 1)), None] {
            told.say(proved, behind);
            std::thread::sleep(Duration::from_millis(3));
            directory.read(&name(proved));
            assert_eq!(directory.key_of(&name(proved)), None, "{behind:?}");
        }
        // A key set after that is taken, and the ship is still one that is kept.
        told.say(proved, Some((Some([8; 32]), 4)));
        std::thread::sleep(Duration::from_millis(3));
        directory.read(&name(proved));
        assert_eq!(directory.proved_key_of(&name(proved)), Some([8; 32]));

        // A ship nobody has proved, whose keys are taken away, is only as well remembered
        // as its key was: a crowd has it forgotten, and then an old answer is taken.
        let unproved = 0x2000_0002u32;
        directory.read(&name(unproved));
        told.say(unproved, Some((None, 5)));
        reread(&directory, unproved);
        assert_eq!(directory.key_of(&name(unproved)), None);
        // A directory told to keep none of these keeps one all the same, and only one.
        let none = Directory::made(Some(told.clone()), Duration::from_millis(1), HOUR, Bounds { unproved: 0, ..Bounds::default() });
        crowd(&none, 0x1400_0000, 5);
        assert_eq!(count(&none), 1);
        assert_eq!(none.key_of(&name(0x1400_0004)), Some(key_of_number(0x1400_0004)));
        // A ship never held, with no keys, takes no room at all.
        let before = count(&directory);
        told.say(0x2000_0003, Some((None, 9)));
        directory.read(&name(0x2000_0003));
        assert_eq!(count(&directory), before);
    }

    #[test]
    fn only_so_many_ships_are_kept_and_none_is_dropped_while_it_is_believed() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        // Twelve ships prove their keys. That is as many as are kept.
        for ship in 0x3000_0000..0x3000_000cu32 {
            directory.read(&name(ship));
            assert!(directory.prove(&name(ship), &key_of_number(ship)), "{ship:x}");
        }
        // A thirteenth is looked up, and can be called by its key, but there is no room
        // to keep it: no connection from it is taken, and none of the twelve is lost.
        // (Two more are looked up beside it. Ships that have proved nothing make way only
        // for each other, when there are too many of them, and three is not too many
        // however many ships of the other kind there are.)
        let extra = 0x3000_00ffu32;
        directory.read(&name(extra - 2));
        directory.read(&name(extra - 1));
        directory.read(&name(extra));
        assert_eq!(directory.key_of(&name(extra - 2)), Some(key_of_number(extra - 2)));
        assert_eq!(directory.key_of(&name(extra - 1)), Some(key_of_number(extra - 1)));
        assert_eq!(directory.key_of(&name(extra)), Some(key_of_number(extra)));
        assert!(!directory.prove(&name(extra), &key_of_number(extra)));
        assert!(directory.trouble().is_some_and(|why| why.contains("no room")));
        assert_eq!(directory.proved_key_of(&name(extra)), None);
        for ship in 0x3000_0000..0x3000_000cu32 {
            assert_eq!(directory.proved_key_of(&name(ship)), Some(key_of_number(ship)));
        }
        // One of the twelve proving its key again is no trouble.
        assert!(directory.prove(&name(0x3000_0000), &key_of_number(0x3000_0000)));

        // Where keys are believed only briefly, the ones that have lapsed make way.
        let brief = small(&told, Duration::from_millis(40));
        for ship in 0x3000_0000..0x3000_000cu32 {
            brief.read(&name(ship));
            assert!(brief.prove(&name(ship), &key_of_number(ship)));
        }
        brief.read(&name(extra));
        assert!(!brief.prove(&name(extra), &key_of_number(extra)));
        std::thread::sleep(Duration::from_millis(60));
        brief.read(&name(extra));
        assert!(brief.prove(&name(extra), &key_of_number(extra)));
        assert!(brief.listed.read().unwrap().keys.len() <= 2);
    }

    #[test]
    fn a_ship_is_asked_about_once_at_a_time_and_not_again_at_once() {
        let told = Arc::new(Told::default());
        // Keys here are good for a while, as they usually are.
        let directory = Directory::made(Some(told.clone()), Duration::from_secs(60), HOUR, Bounds::default());
        let ship = name(0x5000_0000);
        // Several want to know about one ship at the same moment, as happens when one
        // directory serves more than one network. Urbit ID is slow. It is asked once, and
        // the rest wait for that answer and take it.
        told.slow(200);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| directory.read(&ship));
            }
        });
        assert_eq!(told.asked(), 1);
        assert_eq!(directory.key_of(&ship), Some(key_of_number(0x5000_0000)));
        // And one whose turn to ask comes after the answer is in does not ask again.
        told.slow(0);
        directory.read(&ship);
        directory.read(&ship);
        assert_eq!(told.asked(), 1);
        // Another ship is another question.
        directory.read(&name(0x5000_0001));
        assert_eq!(told.asked(), 2);
    }

    #[test]
    fn moons_are_kept_within_bounds_and_with_the_ship_they_stand_on() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        let key = |nth: u8| [nth; 32];
        // Three planets with real keys, as Urbit ID has them. Nobody has proved them.
        let planets = [0x4000_0000u32, 0x4000_0001, 0x4000_0002];
        let parents: Vec<ed25519_dalek::SigningKey> = (1..=3).map(|n| ed25519_dalek::SigningKey::from_bytes(&[n; 32])).collect();
        for (planet, parent) in planets.iter().zip(&parents) {
            told.say(*planet, Some((Some(parent.verifying_key().to_bytes()), 1)));
        }
        // The directory is as full as it gets of names that were only said, the first
        // planet's among them. Its moon shows the planet's word, at revision two.
        directory.read(&name(planets[0]));
        crowd(&directory, 0x1000_0000, 7);
        let (moon, moon_name) = moon_of(planets[0], 1);
        directory.vouched(&moon_name, key(2), &moon::vouch(&parents[0], moon, 2, &key(2))).unwrap();
        // The planet now has something standing on it, and is kept with its moon however
        // many names are said afterwards. And what was seen of the moon is kept: its
        // earlier key does not come back.
        crowd(&directory, 0x1100_0000, 40);
        assert_eq!(directory.key_of(&name(planets[0])), Some(parents[0].verifying_key().to_bytes()));
        assert_eq!(directory.proved_key_of(&moon_name), Some(key(2)));
        assert!(directory.vouched(&moon_name, key(1), &moon::vouch(&parents[0], moon, 1, &key(1))).is_err());

        // A ship has room for three moons here. A fourth is not kept, and the three are
        // untouched.
        for nth in 2..=3 {
            let (moon, moon_name) = moon_of(planets[0], nth);
            directory.vouched(&moon_name, key(10 + nth as u8), &moon::vouch(&parents[0], moon, 1, &key(10 + nth as u8))).unwrap();
        }
        let (fourth, fourth_name) = moon_of(planets[0], 4);
        assert_eq!(directory.vouched(&fourth_name, key(9), &moon::vouch(&parents[0], fourth, 1, &key(9))), Err("there is no room to keep another moon's key"));
        assert_eq!(directory.key_of(&moon_name), Some(key(2)));
        // There is room for five moons in all: two of the second planet's, and then none
        // of the third's, though it has none here yet.
        directory.read(&name(planets[1]));
        directory.read(&name(planets[2]));
        for nth in 1..=2 {
            let (moon, moon_name) = moon_of(planets[1], nth);
            directory.vouched(&moon_name, key(20 + nth as u8), &moon::vouch(&parents[1], moon, 1, &key(20 + nth as u8))).unwrap();
        }
        let (sixth, sixth_name) = moon_of(planets[2], 1);
        assert_eq!(directory.vouched(&sixth_name, key(30), &moon::vouch(&parents[2], sixth, 1, &key(30))), Err("there is no room to keep another moon's key"));
        // A moon already kept still moves on to a later key.
        directory.vouched(&moon_name, key(3), &moon::vouch(&parents[0], moon, 3, &key(3))).unwrap();
        assert_eq!(directory.key_of(&moon_name), Some(key(3)));

        // The first planet's key is replaced in Urbit ID. Its word for its moons has
        // lapsed with it, and they make way: for its own moons under the new key, and for
        // other ships' moons.
        let renewed = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        told.say(planets[0], Some((Some(renewed.verifying_key().to_bytes()), 2)));
        reread(&directory, planets[0]);
        assert_eq!(directory.key_of(&moon_name), None);
        directory.vouched(&sixth_name, key(30), &moon::vouch(&parents[2], sixth, 1, &key(30))).unwrap();
        directory.vouched(&fourth_name, key(9), &moon::vouch(&renewed, fourth, 1, &key(9))).unwrap();
        assert_eq!(directory.key_of(&fourth_name), Some(key(9)));
        assert_eq!(directory.key_of(&sixth_name), Some(key(30)));
        let moons = directory.listed.read().unwrap().keys.values().filter(|entry| matches!(entry.from, From::Vouched { .. })).count();
        assert_eq!(moons, 4);

        // A moon is among the ships that are kept, and so is the planet it stands on. With
        // no room among those, a moon is not kept, though its parent's word is good.
        let full = small(&told, HOUR);
        for ship in 0x3000_0000..0x3000_000bu32 {
            full.read(&name(ship));
            assert!(full.prove(&name(ship), &key_of_number(ship)));
        }
        full.read(&name(planets[1]));
        let (moon, moon_name) = moon_of(planets[1], 1);
        // Room for one more: the planet takes it, and then its moon has none.
        assert_eq!(full.vouched(&moon_name, key(1), &moon::vouch(&parents[1], moon, 1, &key(1))), Err("there is no room to keep another moon's key"));
        assert_eq!(full.key_of(&moon_name), None);
        assert_eq!(full.listed.read().unwrap().keys.values().filter(|entry| entry.proved).count(), 12);
        // And with none at all, the planet is not kept either.
        let (other, other_name) = moon_of(planets[2], 1);
        full.read(&name(planets[2]));
        assert_eq!(full.vouched(&other_name, key(1), &moon::vouch(&parents[2], other, 1, &key(1))), Err("there is no room to keep the key of the moon's parent"));
        assert_eq!(full.proved_key_of(&name(planets[2])), None);
        assert_eq!(full.proved_key_of(&name(0x3000_0000)), Some(key_of_number(0x3000_0000)));
    }

    fn messages_within(request: &[u8], most: usize) -> bool {
        repeats_within(request, 2, 1, most)
    }

    fn deliver(count: usize) -> Vec<u8> {
        let messages = (0..count).map(|_| ship_proto::PeerMessage::default()).collect();
        PeerRequest { body: Some(peer_request::Body::Deliver(Deliver { messages })) }.encode_to_vec()
    }

    #[test]
    fn news_and_answers_are_counted_before_they_are_decoded() {
        let news = |logs: usize| PeerRequest { body: Some(peer_request::Body::News(News { logs: vec![Default::default(); logs] })) }.encode_to_vec();
        assert!(repeats_within(&news(3), 4, 1, 3));
        assert!(!repeats_within(&news(4), 4, 1, 3));
        assert!(!repeats_within(&news(500_000), 4, 1, MAX_NEWS_LOGS));
        let answer = |entries: usize| {
            let fetched = ship_proto::Fetched { entries: vec![Default::default(); entries], ..Default::default() };
            PeerReply { body: Some(peer_reply::Body::Fetched(fetched)), refused: String::new() }.encode_to_vec()
        };
        assert!(repeats_within(&answer(3), 3, 1, 3));
        assert!(!repeats_within(&answer(4), 3, 1, 3));
        assert!(!repeats_within(&answer(500_000), 3, 1, MAX_FETCH_ENTRIES));
        // Each kind of thing is counted against its own limit and no other.
        assert!(repeats_within(&deliver(10), 4, 1, 3));
        assert!(repeats_within(&news(10), 2, 1, 3));
    }

    #[test]
    fn news_is_cut_to_what_one_request_can_carry() {
        let item = |name: &str| crate::store::NewsItem { agent: "a".repeat(64), name: name.repeat(40), head: 7, closed: false, gen: 0 };
        let all = vec![item("x"), item("y"), item("z")];
        let size = |told: &[crate::store::NewsItem]| News { logs: told.iter().map(crate::store::NewsItem::as_sent).collect() }.encoded_len();
        // Everything, when there is room for it.
        let mut told = all.clone();
        fitting(&mut told, 4096);
        assert_eq!(told, all);
        // Room for two of the three: the first two, in order, and they do fit.
        let mut told = all.clone();
        fitting(&mut told, size(&all[..2]) + 20);
        assert_eq!(told, all[..2]);
        assert!(size(&told) <= size(&all[..2]) + 20);
        // Room for none: still one, so that something always gets through.
        let mut told = all.clone();
        fitting(&mut told, 10);
        assert_eq!(told, all[..1]);
    }

    #[test]
    fn a_request_is_counted_before_it_is_decoded() {
        assert!(messages_within(&deliver(0), 3));
        assert!(messages_within(&deliver(3), 3));
        assert!(!messages_within(&deliver(4), 3));
        // Half a million empty messages fit in a megabyte.
        let padded = deliver(500_000);
        assert!(padded.len() < (1 << 20) + (1 << 16));
        assert!(!messages_within(&padded, 256));
        // The same field given twice adds up, as it does when decoded.
        let twice = [deliver(2), deliver(2)].concat();
        assert_eq!(PeerRequest::decode(&*twice).ok().and_then(|request| request.body), PeerRequest::decode(&*deliver(4)).unwrap().body);
        assert!(!messages_within(&twice, 3));
        // Other requests, and fields this runtime does not know, pass.
        let ping = PeerRequest { body: Some(peer_request::Body::Ping(Ping { nonce: vec![1; 16] })) }.encode_to_vec();
        assert!(messages_within(&ping, 0));
        assert!(messages_within(&[ping.clone(), vec![0x78, 0x05]].concat(), 0));
        // Anything that cannot be walked from end to end is refused: a length that runs off
        // the end, a number that never ends, a group.
        assert!(!messages_within(&[0x12, 0x05, 0x0a], 3));
        assert!(!messages_within(&[0x80; 12], 3));
        assert!(!messages_within(&[0x1b, 0x1c], 3));
        // A count hidden behind a group is not reached, so the request is refused whole.
        assert!(!messages_within(&[vec![0x1b, 0x1c], deliver(1)].concat(), 3));
    }
}
