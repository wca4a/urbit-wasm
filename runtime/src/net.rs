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
//! Where a ship is to be found is not in Urbit ID. It can be set by hand, ship by ship, and
//! what is set by hand is always used and nothing else is tried. Or, for a ship with no
//! address set, it can be asked of the lookup point for the ship's galaxy, which hands out
//! a record of where the ship is that the ship itself signed (see `crate::lookup` and
//! `crate::whereabouts`). Either way, a wrong address cannot pass one ship off as another:
//! whatever answers must still prove the key. A connection made to an address found that way
//! is proved, each time it is made or used again, in one step with the directory that also
//! settles that no address has been set by hand meanwhile: no such connection is kept or
//! used once one is (an idle one is refused the next time it would be used, not closed at
//! once). A call that begins after an address is set by hand never uses a record; a call
//! already under way stops at its next check that sees the address, best effort, and may
//! begin one more attempt or question after it. A ship's own key does not change while its
//! runtime runs.
//!
//! The runtime owns its UDP socket and hands it to QUIC, keeping the means to send a bare
//! packet from the same port. It does so for one thing only: a ship behind a home router, told
//! by its lookup point that a caller wants it, sends three small packets from that port to the
//! caller's addresses, which opens its router to that caller (see `crate::lookup`). The packet
//! (`PUNCH`) is four bytes that any QUIC endpoint drops without a word, and nothing is done on
//! receiving one. A caller about to try a record that asks for this asks the ship's point to
//! introduce it first, and gives the attempt the time a lost first packet takes to be sent
//! again; a connection made that way sends a packet every `keep_alive`, so that the routers
//! keep the way open while it is idle.
//!
//! When that fails too (a router that gives each destination a port of its own cannot be
//! opened that way), a caller with a record of its own asks the ship's point to relay, within
//! a share of its time kept for that, and dials the ship through the session it is given (see
//! `crate::relay`). With lookup settings the socket handed to QUIC is the relay's wrapper, and
//! QUIC is told not to grease the fixed bit; with none, both are exactly as before. A
//! connection through a relay is an ordinary one, proved as any other; it is marked as relayed
//! where it is kept, holds its session, and while it is used the direct way is tried again now
//! and then: a direct connection takes its place, with the pair's slot held and proved as any
//! kept connection is, and it is closed (the ship called closes it from its end as soon as it
//! takes the direct one, which replaces the older connection there); a request under way on it
//! then fails, and commands are delivered exactly once by the redelivery that exists. A
//! made-up address set by hand for a ship is refused before anything is sent.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::udp::Transmit;
use quinn::{AsyncUdpSocket, Connection, Endpoint, EndpointConfig, IdleTimeout, Incoming, MtuDiscoveryConfig, RecvStream, Runtime as _, SendStream, TokioRuntime, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use ship_proto::{
    peer_reply, peer_request, Deliver, Delivered, Fetch, Heard, Hello, Introduction, Message, MoonProof, News, PeerReply, PeerRequest, Ping, Pong,
    Resync, Resynced, Standing, Welcome,
};
use tokio::sync::Semaphore;

use urbit_id::ob;

use crate::azimuth::{Keys, Listing};
use crate::lookup::{self, Bucket, Finder, Lead, Lookup, Point, PointStatus};
use crate::moon;
use crate::relay::{self, Leg, RelayStatus, Relayed, SessionId};
use crate::whereabouts;
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

/// The packet a ship behind a home router sends toward a caller it has been introduced to, to
/// open its router: four bytes that are no QUIC packet. Its first byte says a short header
/// follows, and four bytes are too few for one, so a QUIC endpoint drops it as malformed; and
/// it is far too small to be answered by the only things QUIC sends to strangers, a version
/// negotiation (only for a long header of at least 1,200 bytes) or a stateless reset (only
/// for a packet larger than the reset, which is at least 21 bytes, and by the standard never
/// three times the size of what it answers).
pub const PUNCH: &[u8] = &[0, 0, 0, 0];

/// How many times a ship sends the packet to each of a caller's addresses, and how long it
/// waits between. Three, a quarter of a second apart, so that one or two lost on the way, or
/// arriving at the caller's router before the caller has sent anything through it, still
/// leave one to open the way; the caller's own attempt is what gets in.
const PUNCH_ROUNDS: usize = 3;
const PUNCH_GAP: Duration = Duration::from_millis(250);


/// How many introductions a runtime holds at once, handed on by points and not yet weighed.
/// Past this they are dropped.
pub const MOST_INTRODUCTIONS_IN_HAND: usize = 8;

/// How many introductions are weighed, all together: as many as this at a stroke, then this
/// many a second, earned back as time passes. Each may cost a question to Urbit ID and a
/// signature to check.
pub const INTRODUCTIONS_WEIGHED: u32 = 32;

/// How many introductions are acted on for any one caller ship, and in all: as many as this
/// at a stroke, then this many a second, earned back as time passes. The allowance is per
/// full ship name, so each moon has its own. An introduction is acted on only once it holds
/// one of the `MOST_PUNCHING` places, taken before either allowance is charged and held until
/// its last packet; it sends `PUNCH_ROUNDS` packets to each of the caller's addresses, at most
/// four, so at most twelve.
///
/// So the packets in any span of T seconds come from jobs holding a place when the span
/// begins (at most 16, twelve packets each) or from introductions charged within the span (at
/// most 2 + 2T for one caller ship, 16 + 16T in all), however the threads are scheduled. In
/// any span of T seconds: at most 12 x (16 + 2 + 2T) = 216 + 24T packets attributable to one
/// caller ship, and 12 x (16 + 16 + 16T) = 384 + 192T in all; and, four addresses a job, at
/// most 72 + 8T distinct addresses for one caller ship and 128 + 64T in all. Kept up, 24 and
/// 192 packets a second, 8 and 64 addresses a second. Several ships may name the same
/// addresses, so what any one address can receive is bounded only by the figures in all.
pub const PUNCHES_EACH: u32 = 2;
pub const PUNCHES: u32 = 16;

/// How many introductions may be being acted on at once (their packets still being sent), and
/// how many callers are counted against `PUNCHES_EACH`.
const MOST_PUNCHING: usize = 16;
const MOST_PUNCHED_FOR: usize = 1024;

/// The longest one introduction is worked on, a question to Urbit ID included.
const INTRODUCTION_LIMIT: Duration = Duration::from_secs(5);

/// How many tries at going direct again, for pairs whose connections go through a relay, may
/// be under way at once, all pairs together. Each pair has at most one under way.
const MOST_DIRECT_TRIES: usize = 16;

/// The largest QUIC packet sent through a relay: the most QUIC sends on an IPv6 path with the
/// usual 1,500 bytes of room (1,452), less the relay's header, so that the datagram with its
/// header still fits.
const MOST_RELAYED_PACKET: u16 = 1452 - relay::HEADER as u16;

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

    /// Where a ship stands, read in one step, so that what is set by hand and what key is
    /// held are seen as they were at one moment: the address set by hand for it, if any, and
    /// what is needed to call it, if that is known (its key, or for a moon met for the first
    /// time nothing, provided its parent's key is known to check the moon's word against).
    fn standing(&self, name: &str) -> (Option<SocketAddr>, Option<Option<[u8; 32]>>) {
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        let keyed = match self.held(&listed, name) {
            Some(key) => Some(Some(key)),
            None => parent_of(name).and_then(|parent| self.held(&listed, &parent)).map(|_| None),
        };
        (listed.places.get(name).copied(), keyed)
    }

    /// For a moon whose parent's word has been taken here and still stands: the revision of
    /// that word, and the key it was for.
    pub(crate) fn moon_seen(&self, name: &str) -> Option<(u32, [u8; 32])> {
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        match listed.keys.get(name)?.from {
            From::Vouched { revision, .. } => self.held(&listed, name).map(|key| (revision, key)),
            _ => None,
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
        self.prove_as(name, key, false)
    }

    /// The same, for a connection this runtime made or is about to use again. `found` says
    /// it was made to an address found through a lookup point: then a third thing is settled
    /// in the same step, that no address has been set by hand for the ship, since an address
    /// set by hand is always the one used. A connection made to an address set by hand is
    /// proved as `prove` proves it.
    fn prove_as(&self, name: &str, key: &[u8; 32], found: bool) -> bool {
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if found && listed.places.contains_key(name) {
            return false;
        }
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
        self.word(name, key, proof, true, None)
    }

    /// Take a moon's key on its parent's word as it came in a record of where the moon is
    /// (see `crate::whereabouts`), by the same rules as `vouched`: signed with the key held
    /// for the parent, only forwards, one key to a revision, and a key set here by hand is
    /// never changed. The moon has not proved it holds the key, so it is not marked as having
    /// proved anything; its parent is kept, as for any moon's word checked against its key.
    ///
    /// This is the one memory of a moon's keys at a ship. What a record shows here holds for
    /// every connection after, made or taken, and for connections already open, whether or
    /// not any address in the record ever answers. It is never dropped for room, nor when the
    /// record runs out: only when the parent's key it stands on is no longer believed.
    ///
    /// `still_good` says whether the record the word came in is still good by the clock. It
    /// is asked with the directory held, after waiting for it and before anything is
    /// changed, so that a clock that moved while the record was checked cannot have a word
    /// taken from a record that is no longer good.
    pub(crate) fn recorded_word(&self, name: &str, key: [u8; 32], proof: &moon::Proof, still_good: &dyn Fn() -> bool) -> Result<(), &'static str> {
        self.word(name, key, proof, false, Some(still_good))
    }

    /// Whether a moon's word for `key` stands by what is held here, read from `listed`: the
    /// parent's word signed with the key held for the parent; a key set here by hand never
    /// changed by a word from elsewhere (only the same key stands, and then there is nothing
    /// to take); under the same key of the parent's, only forwards, and one key to a
    /// revision. The parent's key if the word is to be taken, `None` if the key set by hand is
    /// this one. The one statement of this rule, for taking a word and for weighing one
    /// without taking it.
    fn weigh_word(&self, listed: &Listed, name: &str, key: [u8; 32], proof: &moon::Proof) -> Result<Option<[u8; 32]>, &'static str> {
        let (Some(number), Some(parent)) = (ob::moon_number(name), parent_of(name)) else { return Err("not a moon") };
        let by = self.held(listed, &parent).ok_or("the moon's parent is not listed")?;
        if !moon::holds(&by, number, &key, proof) {
            return Err("not the word of the moon's parent for the key shown");
        }
        match listed.keys.get(name) {
            // Set by whoever runs this runtime, which no word from elsewhere changes.
            Some(Entry { key: set, from: From::Set, .. }) => return if *set == key { Ok(None) } else { Err("another key is set for the moon here") },
            // Under the same key of the parent's: only forwards, and one key to a revision.
            Some(Entry { key: seen, from: From::Vouched { revision, by: then }, .. }) if *then == by => {
                if proof.revision < *revision || (proof.revision == *revision && *seen != key) {
                    return Err("the moon has shown a later key than this one");
                }
            }
            _ => {}
        }
        Ok(Some(by))
    }

    /// Whether a moon's word, as it came in a record, would be taken here, by the very rule
    /// taking it uses (`weigh_word`), read with the directory held and nothing changed: no
    /// word kept, nothing marked proved, no room taken. For weighing a record this runtime
    /// acts on but keeps nothing of (an introduction).
    pub(crate) fn moon_word_stands(&self, name: &str, key: [u8; 32], proof: &moon::Proof) -> Result<(), &'static str> {
        let listed = self.listed.read().unwrap_or_else(|e| e.into_inner());
        self.weigh_word(&listed, name, key, proof).map(drop)
    }

    /// Take a moon's word, as `vouched` and `recorded_word` describe. `proves` says the moon
    /// has proved, on a connection, that it holds the key. `still_good`, for a word from a
    /// record, is asked once the directory is held.
    fn word(&self, name: &str, key: [u8; 32], proof: &moon::Proof, proves: bool, still_good: Option<&dyn Fn() -> bool>) -> Result<(), &'static str> {
        let (Some(_), Some(parent)) = (ob::moon_number(name), parent_of(name)) else { return Err("not a moon") };
        let mut listed = self.listed.write().unwrap_or_else(|e| e.into_inner());
        if still_good.is_some_and(|good| !good()) {
            return Err("the record the moon's word came in is no longer good by this clock");
        }
        // A key set by hand, and the same: nothing to change.
        let Some(by) = self.weigh_word(&listed, name, key, proof)? else { return Ok(()) };
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
        // Whether the moon has proved a key goes with the moon, whatever its keys become.
        // A moon that has not, and proves one now, takes a place among the ships that are
        // kept, as any ship that proves its key does: if there is none, its word is still
        // taken (that is what holds earlier keys off), but it is not kept as having proved
        // anything, and `prove` refuses its connection for want of room. A moon new here had
        // room made for it above.
        let proved = match listed.keys.get(name).map(|entry| entry.proved) {
            Some(true) => true,
            Some(false) => proves && self.room_for_proved(&mut listed),
            None => proves,
        };
        // Making room drops only what is no longer believed, and the parent is believed.
        if self.held(&listed, &parent) != Some(by) {
            return Err("the moon's parent is not listed");
        }
        listed.keys.insert(name.to_string(), Entry { key, from: From::Vouched { revision: proof.revision, by }, proved });
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
    /// Finding ships through lookup points, announcing this runtime's ships to them, and
    /// being one. Off by default: with none of it set, nothing of it is sent, listened for,
    /// or kept. See `crate::lookup`.
    pub lookup: Lookup,
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
            lookup: Lookup::default(),
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
    /// What the directory listed for the ship called: its key, and the address it was
    /// reached at.
    peer: Peer,
    /// The key the calling ship showed.
    shown: [u8; 32],
    /// The address was not set by hand but found through a lookup point. Such a connection
    /// is never used once an address is set by hand.
    found: bool,
    /// The connection goes through the relay of the called ship's point: its session, held for
    /// as long as this is, and when the direct way is next to be tried.
    relayed: Option<Relaying>,
    /// A number given to this entry when it was made, from one counter of 64 bits (it would come
    /// round only after 2^64 entries): what a try at going direct names the entry it began from by. (QUIC's
    /// `stable_id` will not do: it is an allocation's address, and can be given to a newer
    /// connection once the old one is dropped.)
    generation: u64,
}

/// What a kept connection through a relay goes with.
struct Relaying {
    /// The session: let go of when this is. Held for that alone.
    #[allow(dead_code)]
    leg: Leg,
    /// Not before this moment, the direct way is tried again.
    next_try: tokio::time::Instant,
}

/// For tests: holds one Deliver request, written and with its reply not yet read, until released;
/// and says whether it is still held, and on which connection, and whether it has ended.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct DeliverGate {
    pub(crate) armed: std::sync::atomic::AtomicBool,
    /// The connection the held request was written on, by QUIC's number for it, while held.
    pub(crate) holding: Mutex<Option<usize>>,
    pub(crate) release: tokio::sync::Notify,
    /// Set when the held request ends, however it ends (its reply read, its time run out).
    pub(crate) ended: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
pub(crate) struct Ended<'a>(&'a DeliverGate);

#[cfg(test)]
impl Drop for Ended<'_> {
    fn drop(&mut self) {
        *lock(&self.0.holding) = None;
        self.0.ended.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl DeliverGate {
    /// Hold here until released; the guard marks the request ended when the request does.
    async fn hold(&self, connection: usize) -> Ended<'_> {
        *lock(&self.holding) = Some(connection);
        let ended = Ended(self);
        self.release.notified().await;
        ended
    }
}

/// A pair's place among those trying to go direct again, given up when the try ends, however
/// it ends.
struct Trying(Arc<Shared>, Pair);

impl Drop for Trying {
    fn drop(&mut self) {
        lock(&self.0.going_direct).remove(&self.1);
    }
}

/// How a ship is to be called, as things stand.
#[derive(Clone, Copy)]
enum Route {
    /// At the address set by hand for it. Nothing else is tried.
    Placed(Reach),
    /// No address is set for it, and it is to be found through the lookup point for its
    /// galaxy. The key held for it, if one is: for a moon met for the first time there is
    /// none, and its parent's is known.
    Found(Option<[u8; 32]>),
}

impl Route {
    /// Whether a connection made earlier was made as this route would make it now.
    fn fits(&self, made: &Made) -> bool {
        match self {
            Route::Placed(reach) => !made.found && Some(made.peer.key) == reach.key && made.peer.addr == reach.addr,
            Route::Found(key) => made.found && Some(made.peer.key) == *key,
        }
    }
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
    /// The means to find ships through lookup points, if this runtime has settings for them.
    finder: Option<Arc<Finder>>,
    /// This runtime's role as a lookup point, if it has one.
    point: Option<Arc<Point>>,
    /// The UDP socket QUIC runs on, kept to send the packets an introduction calls for.
    socket: Arc<dyn AsyncUdpSocket>,
    /// The same socket as the relay's wrapper, with its sessions, when the runtime has lookup
    /// settings; `None` otherwise, and then the socket is the bare one.
    relayed: Option<Arc<Relayed>>,
    /// Whether QUIC was left to grease the fixed bit, as by default: only with no lookup
    /// settings. Read by tests.
    #[cfg_attr(not(test), allow(dead_code))]
    greases: bool,
    /// Pairs trying to go direct again now, and places among the tries under way, and how
    /// many tries have begun.
    going_direct: Mutex<HashSet<Pair>>,
    #[cfg_attr(not(test), allow(dead_code))]
    direct_tried: AtomicU64,
    /// Candidates tries at going direct have made (connections proved), for tests.
    #[cfg_attr(not(test), allow(dead_code))]
    direct_made: AtomicU64,
    /// The generation the next kept entry is given.
    generations: AtomicU64,
    /// A gate that, when armed, holds the next Deliver request after it is written and before its
    /// reply is read. For tests.
    #[cfg(test)]
    pub(crate) deliver_gate: DeliverGate,
    direct_tries: Arc<Semaphore>,
    /// What introductions this runtime's ships have been given, and what came of them.
    punching: Punching,
}

/// How a runtime acts on introductions its lookup points pass to its ships.
struct Punching {
    /// Introductions that may still be weighed just now.
    weighing: Mutex<Bucket>,
    /// Introductions that may still be acted on just now, for each caller, and in all.
    each: Mutex<HashMap<String, Bucket>>,
    all: Mutex<Bucket>,
    /// Places among the introductions being acted on.
    under_way: Arc<Semaphore>,
    /// Introductions heard, those let past the weighing allowance, those acted on, and packets
    /// sent because of them; and sessions registered for them.
    heard: AtomicU64,
    weighed: AtomicU64,
    acted: AtomicU64,
    sent: Arc<AtomicU64>,
    sessions: AtomicU64,
}

impl Punching {
    fn new() -> Punching {
        Punching {
            weighing: Mutex::new(Bucket::new(INTRODUCTIONS_WEIGHED)),
            each: Mutex::default(),
            all: Mutex::new(Bucket::new(PUNCHES)),
            under_way: Arc::new(Semaphore::new(MOST_PUNCHING)),
            heard: AtomicU64::new(0),
            weighed: AtomicU64::new(0),
            acted: AtomicU64::new(0),
            sent: Arc::new(AtomicU64::new(0)),
            sessions: AtomicU64::new(0),
        }
    }

    /// Count one introduction against a caller's allowance, if it has one left. Only so many
    /// callers are counted; past that, those whose allowance is whole are forgotten.
    fn for_caller(&self, caller: &str) -> bool {
        let mut each = lock(&self.each);
        if !each.contains_key(caller) && each.len() >= MOST_PUNCHED_FOR {
            each.retain(|_, bucket| !bucket.whole());
            if each.len() >= MOST_PUNCHED_FOR {
                return false;
            }
        }
        each.entry(caller.to_string()).or_insert_with(|| Bucket::new(PUNCHES_EACH)).take()
    }
}

/// What introductions a runtime's ships have been given by their lookup points.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Introductions {
    /// Introductions heard and taken to be weighed, those let past the allowance for weighing,
    /// and those acted on (packets sent for them).
    pub heard: u64,
    pub weighed: u64,
    pub acted: u64,
    /// Packets sent toward callers because of them.
    pub sent: u64,
    /// Introductions that carried a session and were believed: sessions registered, through
    /// which the caller then calls.
    pub sessions: u64,
}

/// A stand-in for the UDP socket a network makes for itself, for tests to put something
/// between a runtime and everything else. Made inside the network's own threads.
pub(crate) type MakeSocket = Box<dyn FnOnce() -> io::Result<Arc<dyn AsyncUdpSocket>> + Send>;

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
        Network::start_on(runtime, directory, cfg, None)
    }

    /// The same, with the UDP socket made by `socket` rather than bound at `cfg.addr`: for
    /// tests only.
    pub(crate) fn start_on(runtime: Arc<Runtime>, directory: Arc<Directory>, cfg: NetConfig, socket: Option<MakeSocket>) -> io::Result<Network> {
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
        cfg.lookup.sound().map_err(io::Error::other)?;
        // A packet every `keep_alive` keeps a connection open only if it comes before the
        // connection is taken to be idle.
        if cfg.lookup.finds() && cfg.lookup.keep_alive >= cfg.idle_timeout {
            return Err(io::Error::other("keep_alive must be less than idle_timeout"));
        }
        // The ships' keys are read into memory now, and never from inside a connection being
        // made. If they cannot be read, there is no network.
        runtime.load_identities().map_err(io::Error::other)?;
        let threads = Threads(Some(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("ship-net").build()?));
        let tokio = threads.get();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let point = cfg.lookup.serve.clone().map(|serve| Point::new(serve, &provider)).transpose()?.map(Arc::new);

        // The side that answers: it shows the key of whichever ship was asked for, and wants
        // proof of some key. Whose key it is, the caller says once connected.
        let mut answering = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(AnyCaller { supported: provider.signature_verification_algorithms }))
            .with_cert_resolver(Arc::new(ShipKeys { runtime: runtime.clone(), provider: provider.clone(), point: point.as_ref().map(|point| point.shown.clone()) }));
        answering.alpn_protocols = vec![PROTOCOL.to_vec()];
        // A lookup point also answers its own protocol, second: a caller that offers both is
        // taken as a ship.
        if point.is_some() {
            answering.alpn_protocols.push(lookup::WHERE_PROTOCOL.to_vec());
        }
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

        // The socket is this runtime's own, handed to QUIC, so that the packets an introduction
        // calls for go out from the very port the ships are reached at. With lookup settings it
        // is wrapped, for relay sessions (see `crate::relay`), and QUIC is told not to grease
        // the fixed bit, so that no packet it takes can be taken for a relayed one. With none,
        // the socket and QUIC's settings are exactly as they were.
        let wraps = cfg.lookup.finds() || cfg.lookup.serve.is_some();
        let (endpoint, socket, relayed, greases) = {
            let _entered = tokio.enter();
            let socket = match socket {
                Some(make) => make()?,
                None => TokioRuntime.wrap_udp_socket(std::net::UdpSocket::bind(addr)?)?,
            };
            let mut endpoint_config = EndpointConfig::default();
            let (socket, relayed) = if wraps {
                endpoint_config.grease_quic_bit(false);
                let relaying = point.clone().filter(|point| point.relays());
                let relayed = Arc::new(Relayed::new(socket, relaying, cfg.idle_timeout)?);
                (relayed.clone() as Arc<dyn AsyncUdpSocket>, Some(relayed))
            } else {
                (socket, None)
            };
            // What QUIC was given, as it says it of itself.
            let greases = format!("{endpoint_config:?}").contains("grease_quic_bit: true");
            (Endpoint::new_with_abstract_socket(endpoint_config, Some(server), socket.clone(), Arc::new(TokioRuntime))?, socket, relayed, greases)
        };
        let bound = endpoint.local_addr()?;
        let reading = Arc::new(Semaphore::new(cfg.max_reading_bytes));
        let asking = Arc::new(Semaphore::new(cfg.max_requests));
        let working = Arc::new(Semaphore::new(cfg.max_working));
        let carrying = Arc::new(Semaphore::new(cfg.max_carrying));
        let carrier = Arc::new(Carrier::default());
        // Introductions points pass to this runtime's ships wait here to be weighed, only so many.
        let (pushed, introductions) = match cfg.lookup.finds() {
            true => {
                let (pushed, introductions) = tokio::sync::mpsc::channel(MOST_INTRODUCTIONS_IN_HAND);
                (Some(pushed), Some(introductions))
            }
            false => (None, None),
        };
        let finder = match cfg.lookup.finds() {
            true => Some(Arc::new(Finder::new(cfg.lookup.clone(), &cfg, endpoint.clone(), &provider, bound, pushed, relayed.clone())?)),
            false => None,
        };
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
            finder,
            point,
            socket,
            relayed,
            greases,
            direct_tried: AtomicU64::new(0),
            direct_made: AtomicU64::new(0),
            generations: AtomicU64::new(0),
            #[cfg(test)]
            deliver_gate: DeliverGate::default(),
            going_direct: Mutex::default(),
            direct_tries: Arc::new(Semaphore::new(MOST_DIRECT_TRIES)),
            punching: Punching::new(),
        });
        tokio.spawn(answer_calls(shared.clone()));
        tokio.spawn(carry(shared.clone()));
        // This runtime's ships are announced to the lookup points for their galaxies, at the
        // addresses given, or else at the one each point sees this runtime's connection come
        // from; and introductions those points pass on are weighed.
        if let Some(finder) = &shared.finder {
            tokio.spawn(finder.clone().announce(shared.runtime.clone(), shared.cfg.lookup.announce.clone()));
        }
        if let Some(introductions) = introductions {
            tokio.spawn(weigh_introductions(shared.clone(), introductions));
        }
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

    /// How this runtime is doing as a lookup point, if it is one.
    pub fn point_status(&self) -> Option<PointStatus> {
        self.shared.point.as_ref().map(|point| point.status())
    }

    /// What introductions this runtime's ships have been given, and the packets sent because of
    /// them.
    pub fn introductions(&self) -> Introductions {
        let punching = &self.shared.punching;
        Introductions {
            heard: punching.heard.load(Ordering::SeqCst),
            weighed: punching.weighed.load(Ordering::SeqCst),
            acted: punching.acted.load(Ordering::SeqCst),
            sent: punching.sent.load(Ordering::SeqCst),
            sessions: punching.sessions.load(Ordering::SeqCst),
        }
    }

    /// This runtime's relay sessions, and what has passed through them; all nought for a
    /// runtime with no lookup settings.
    pub fn relay_status(&self) -> RelayStatus {
        self.shared.relayed.as_ref().map(|relayed| relayed.status()).unwrap_or_default()
    }

    /// What one of this runtime's ships was last announced as, if a point took its record:
    /// its addresses, and whether callers were asked to be introduced.
    pub fn announced_as(&self, ship: &str) -> Option<(Vec<SocketAddr>, bool)> {
        let ship = canonical_ship(ship).ok()?;
        self.shared.finder.as_ref()?.shown_as(&ship)
    }

    /// The last thing that went wrong in finding ships through lookup points or announcing
    /// this runtime's ships to them, if anything has.
    pub fn lookup_trouble(&self) -> Option<String> {
        self.shared.finder.as_ref().and_then(|finder| finder.trouble())
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
pub(crate) fn transport(cfg: &NetConfig, streams: u32) -> io::Result<TransportConfig> {
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
pub(crate) fn unwrapped(wrapped_key: &[u8]) -> Option<[u8; 32]> {
    let key = <[u8; 32]>::try_from(wrapped_key.get(12..)?).ok()?;
    (wrapped(&key) == wrapped_key).then_some(key)
}

/// What a ship shows to prove who it is: its public key, and the means to sign with the
/// private half. The private half stays in this process.
pub(crate) fn proof(key: &ed25519_dalek::SigningKey, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, rustls::Error> {
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
pub(crate) fn signed_with(
    shown: &CertificateDer<'_>,
    message: &[u8],
    signed: &DigitallySignedStruct,
    supported: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, supported)
}

pub(crate) fn refuse(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_string())
}

/// For the side that answers: which key to show. It is the key of the ship the caller asked
/// for, if this runtime holds that ship. Keys are held in memory, so this never waits on disk.
/// A caller that asks only for the lookup protocol, of a runtime that is a lookup point, is
/// shown the point's key instead, whatever ship it names.
struct ShipKeys {
    runtime: Arc<Runtime>,
    provider: Arc<CryptoProvider>,
    point: Option<Arc<CertifiedKey>>,
}

impl fmt::Debug for ShipKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShipKeys")
    }
}

impl ResolvesServerCert for ShipKeys {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // The protocol agreed is the first of this side's that the caller offers, and the
        // ship protocol comes first. So the point's key is shown only where the lookup
        // protocol is what will be agreed.
        if let Some(point) = &self.point {
            let offered = |protocol: &[u8]| hello.alpn().is_some_and(|mut offered| offered.any(|named| named == protocol));
            if !offered(PROTOCOL) && offered(lookup::WHERE_PROTOCOL) {
                return Some(point.clone());
            }
        }
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
        let (connection, key) = tokio::time::timeout_at(deadline, self.connection(&from, &to, deadline)).await.map_err(|_| NetError::TimedOut)??;
        let opened = tokio::time::timeout_at(deadline, connection.open_bi()).await.map_err(|_| NetError::TimedOut)?;
        let (mut send, mut receive) = opened.map_err(|e| lost(&e))?;
        // The streams are held out here, so that if time runs out part way they can be told
        // to stop. Merely letting go of them would leave the request to go on being sent.
        let exchanged = tokio::time::timeout_at(deadline, async {
            send.write_all(&request.encode_to_vec()).await.map_err(|e| lost(&e))?;
            send.finish().map_err(|e| lost(&e))?;
            #[cfg(test)]
            let _held = match matches!(request.body, Some(peer_request::Body::Deliver(_))) && self.deliver_gate.armed.swap(false, Ordering::SeqCst) {
                true => Some(self.deliver_gate.hold(connection.stable_id()).await),
                false => None,
            };
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
                        made.connection.close_reason().is_none() && self.route(to).is_some_and(|route| route.fits(made)) && self.directory.prove_as(to, &made.peer.key, made.found)
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

    /// How a ship is to be called, as things stand: at the address set by hand for it, or
    /// through a lookup point if it has none and this runtime finds ships that way. `None`
    /// if it cannot be called, for want of its key (or for a moon, its parent's).
    fn route(&self, to: &str) -> Option<Route> {
        // One reading of the directory, so that a place set by hand and the key held are
        // weighed as they stood together.
        match self.directory.standing(to) {
            (Some(addr), keyed) => keyed.map(|key| Route::Placed(Reach { key, addr })),
            // An address set by hand is never passed over: with one set, the ship is not
            // looked for elsewhere, whatever else is or is not known of it.
            (None, keyed) => keyed.filter(|_| self.finder.is_some()).map(Route::Found),
        }
    }

    /// The connection from one of this runtime's ships to another ship, made if there is
    /// none, and the key the other ship proved it holds when it was made. `deadline` is when the
    /// request it is for runs out of time.
    ///
    /// A kept connection that goes through a relay starts a try at going direct again when it
    /// is used, if one is due (`Lookup::direct_again`) and none is under way for the pair.
    async fn connection(self: &Arc<Self>, from: &str, to: &str, deadline: tokio::time::Instant) -> Result<(Connection, [u8; 32]), NetError> {
        let key = self.runtime.signing_key(from).map_err(|_| NetError::NotHere(from.to_string()))?;
        let shown = key.verifying_key().to_bytes();
        let pair = (from.to_string(), to.to_string());
        // If the directory reads its keys from Urbit ID, see that it has this ship's.
        self.know(to, 0).await;
        if self.route(to).is_none() {
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
        let Some(route) = self.route(to) else {
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
            let stands = made.connection.close_reason().is_none() && route.fits(&made) && made.shown == shown;
            // Proved again in one step with the directory: for a connection found through a
            // lookup point, that includes that no address has been set by hand meanwhile.
            if stands && self.directory.prove_as(to, &made.peer.key, made.found) {
                let mut made = made;
                let (connection, proved) = (made.connection.clone(), made.peer.key);
                let generation = made.generation;
                if let Some(relaying) = made.relayed.as_mut() {
                    self.direct_due(&pair, relaying, generation);
                }
                *kept = Some(made);
                return Ok((connection, proved));
            }
            made.connection.close(VarInt::from_u32(2), b"the directory changed");
            // A connection found through a point that the directory would not prove again:
            // the directory has changed since the route was read (most likely an address set
            // by hand). This call ends here; the next goes by what the directory says then.
            if stands && made.found {
                return Err(NetError::Unreachable("the directory changed while connecting".into()));
            }
        }

        let held = match route {
            Route::Placed(reach) => reach.key,
            Route::Found(key) => key,
        };
        let client = self.calling(&key, to, held)?;

        let (connection, peer, found, leg) = match route {
            // Where the socket is wrapped for relaying, a made-up address is a session's, and a
            // call to an address set by hand never goes through a session: no ship can be at
            // such an address. (With no lookup settings the bare socket is as it was.)
            Route::Placed(reach) if self.relayed.is_some() && relay::is_made_up(&reach.addr) => {
                return Err(NetError::Unreachable(format!("~{to} is set by hand at {}, an address no ship can be at", reach.addr)));
            }
            Route::Placed(reach) => {
                let (connection, proved) = self.dial(&client, from, to, held, reach.addr, false, true).await?;
                let peer = Peer { key: proved, addr: reach.addr };
                // Connecting took time. If the directory changed meanwhile, what was just
                // proved is already out of date.
                if self.directory.lookup(to) != Some(peer) {
                    connection.close(VarInt::from_u32(2), b"the directory changed");
                    return Err(NetError::Unreachable("the directory changed while connecting".into()));
                }
                (connection, peer, false, None)
            }
            Route::Found(_) => {
                let (connection, peer, leg) = self.dial_found(&client, from, to, held, deadline).await?;
                (connection, peer, true, leg)
            }
        };
        // A connection through a relay is marked so where it is kept, with its session.
        let relayed = leg.map(|leg| Relaying { leg, next_try: tokio::time::Instant::now() + self.cfg.lookup.direct_again });
        *kept = Some(Made { connection: connection.clone(), peer, shown, found, relayed, generation: self.generation() });
        Ok((connection, peer.key))
    }

    /// How a ship of this runtime (with `key`) calls `to`: showing its key, and accepting only
    /// `held`, the key listed for `to` (for a moon, any key, which is then checked against its
    /// parent's word).
    fn calling(&self, key: &ed25519_dalek::SigningKey, to: &str, held: Option<[u8; 32]>) -> Result<quinn::ClientConfig, NetError> {
        let unreachable = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        // This side shows the calling ship's key, and accepts only the key listed for the ship
        // being called.
        let shows = proof(key, &self.provider).map_err(|e| unreachable(&e))?;
        // A moon may have been given a new key since it was last met, which only the moon
        // can show. So any key is let through here for a moon, and looked at below.
        let expected = if ob::moon_number(to).is_some() { None } else { held };
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
        Ok(client)
    }

    /// The generation for a kept entry being made now: not given before. (A counter of 64 bits
    /// taken one at a time would come round only after 2^64 entries, which does not happen in
    /// practice; nothing checks for it.)
    fn generation(&self) -> u64 {
        self.generations.fetch_add(1, Ordering::SeqCst)
    }

    /// For a kept connection through a relay (the entry of generation `relayed`), just used: if a
    /// try at the direct way is due, and none is under way for the pair, and there is a place
    /// among the tries, start one, and set when the next is due. Weighed with the pair's slot
    /// held.
    fn direct_due(self: &Arc<Self>, pair: &Pair, relaying: &mut Relaying, relayed: u64) {
        let now = tokio::time::Instant::now();
        if now < relaying.next_try {
            return;
        }
        relaying.next_try = now + self.cfg.lookup.direct_again;
        if !lock(&self.going_direct).insert(pair.clone()) {
            return;
        }
        let trying = Trying(self.clone(), pair.clone());
        let Ok(turn) = self.direct_tries.clone().try_acquire_owned() else { return };
        self.direct_tried.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(self.clone().go_direct(pair.clone(), relayed, trying, turn));
    }

    /// Connect to a ship at one address, say which ship is calling, and see that what
    /// answered is the ship called: it proved it holds the key held for the ship (`held`),
    /// or for a moon, a key its parent has given its word for. The connection, and the key
    /// proved.
    /// `found` says the address came from a lookup point: then the proof is refused if an
    /// address has been set by hand for the ship meanwhile. `doubts` says a failure to connect
    /// makes the key held for the ship be read again; a try at going direct again, which may
    /// fail for reasons of routers alone, changes nothing.
    #[allow(clippy::too_many_arguments)]
    async fn dial(&self, client: &quinn::ClientConfig, from: &str, to: &str, held: Option<[u8; 32]>, addr: SocketAddr, found: bool, doubts: bool) -> Result<(Connection, [u8; 32]), NetError> {
        let unreachable = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        let connecting = self.endpoint.connect_with(client.clone(), addr, to).map_err(|e| unreachable(&e))?;
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(e) => {
                // It may be that the ship has a new key, and the one held for it is old.
                if doubts {
                    self.directory.doubt(to);
                }
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
        if held != Some(proved) {
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
        if !self.directory.prove_as(to, &proved, found) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return Err(NetError::Unreachable("the key the ship proved is no longer the one held for it, or there is no room to keep it".into()));
        }
        Ok((connection, proved))
    }

    /// Call a ship that has no address set here, at the addresses of its record: first the
    /// record already held, if it is still good, then one asked afresh of the lookup point
    /// for its galaxy. Each address is tried in turn, each for part of the time left, and a
    /// record none of whose addresses answer as the ship (and whose ship its point's relay did
    /// not reach either) is not tried again. Whatever answers must prove the ship's key, as at
    /// any address.
    ///
    /// Immediately before each address is tried, the directory is read again, in one step.
    /// If the re-read sees an address set by hand, or a key held that is not the one the call
    /// began with, nothing more from the record is tried. (For a moon the key may have come
    /// to be held meanwhile, from the very record being tried: a moon is let show any key,
    /// and its parent's word decides.) The same is read again before a new question to the
    /// point, before an introduction or a relay is asked for, and before a session is dialed.
    /// These are best-effort checks: a call already under way when an address is set by hand
    /// stops at its next check that sees it, and may begin one more attempt, question or
    /// request after the address is set, following its last check. An attempt already begun
    /// cannot be called back; what it makes is refused by its proof, which settles in one step
    /// with the directory that no address is set by hand, so no connection made through a
    /// record or a relay is kept or used once one is. A record that has been replaced while its
    /// addresses were being tried goes on being tried to its end (its few addresses are each
    /// time-limited, and whatever answers must prove the key); the newer record is used by the
    /// next round of this call, if there is one, or by the next call. Only the record that was
    /// tried is marked failed.
    ///
    /// A record that asks callers to be introduced: before its addresses are tried, the ship's
    /// point is asked to introduce this ship, waiting at most `INTRODUCE_WAIT` (or a quarter of
    /// the time left) for it to say so; whatever it says, or if it says nothing, the addresses
    /// are then tried as for any record, each for longer (`TRY_INTRODUCED`, or three quarters of
    /// the time left), on a connection that keeps itself alive. If the calling ship has a record
    /// of its own to show, a relay may follow: then all of that direct work, in this call,
    /// ends by `lookup::direct_by` (five seconds, or half the call), and if no address answered,
    /// the point is asked to relay (waiting at most `RELAY_WAIT`, or a quarter of the time
    /// left), and on a session the ship is dialed through it with the rest of the time. A
    /// record the direct way failed for and the relay worked for is remembered, and the next
    /// call on it goes straight to the relay. A ship that announces no record of its own
    /// cannot be introduced or relayed, and tries the addresses without.
    ///
    /// The connection, what it was proved against (for one through a relay, its address is
    /// the session's made-up one), and the session, if it goes through one.
    async fn dial_found(
        self: &Arc<Self>,
        client: &quinn::ClientConfig,
        from: &str,
        to: &str,
        held: Option<[u8; 32]>,
        deadline: tokio::time::Instant,
    ) -> Result<(Connection, Peer, Option<Leg>), NetError> {
        let finder = self.finder.as_ref().ok_or_else(|| NetError::Unlisted(to.to_string()))?;
        let moon = ob::moon_number(to).is_some();
        let changed = || NetError::Unreachable("the directory changed while looking for the ship".into());
        // Whether a relay may follow, and if so, when the direct work must be over by.
        let relays = finder.may_relay(from);
        let direct_by = lookup::direct_by(tokio::time::Instant::now(), deadline);
        let direct_left = || direct_by.saturating_duration_since(tokio::time::Instant::now());
        let mut why = NetError::Unreachable(format!("nowhere is known to reach ~{to}"));
        for asking in [false, true] {
            // Before a new question, the directory is read again: if the re-read sees an
            // address set by hand, the point is not asked.
            if asking && !matches!(self.route(to), Some(Route::Found(key)) if moon || key == held) {
                return Err(changed());
            }
            // The record the addresses come from, by the number it was kept under, so that
            // only that one is marked failed.
            let lead: Lead = if asking { finder.ask(&self.directory, to, deadline).await? } else { finder.cached(to).unwrap_or_default() };
            if lead.addresses.is_empty() {
                continue;
            }
            let relaying = relays && lead.introduce;
            // The direct way failed for this very record, and the relay worked: straight there.
            let straight = relaying && finder.relay_worked(to, lead.kept_as);
            if lead.introduce && !straight {
                // Read again before the point is asked, as before a question.
                if !matches!(self.route(to), Some(Route::Found(key)) if moon || key == held) {
                    return Err(changed());
                }
                let wait = if relaying { lookup::introduce_wait(deadline).min(direct_left()) } else { lookup::introduce_wait(deadline) };
                if let Ok(Err(failed)) = tokio::time::timeout(wait, finder.introduce(&self.runtime, from, to, deadline)).await {
                    finder.worried(format!("~{to}: {failed}"));
                }
            }
            // A connection made on such a record keeps itself alive, so that the routers on the
            // way keep it open while it is idle.
            let kept_alive;
            let client = if lead.introduce {
                kept_alive = self.kept_alive(client)?;
                &kept_alive
            } else {
                client
            };
            for &addr in lead.addresses.iter().filter(|_| !straight) {
                // The last thing read before an attempt: nothing waits after it.
                let now_held = match self.route(to) {
                    Some(Route::Found(key)) if moon || key == held => key,
                    _ => return Err(changed()),
                };
                let mut limit = if lead.introduce { lookup::introduced_limit(deadline) } else { lookup::try_limit(deadline) };
                if relaying {
                    // The relay's share of the call is not spent here.
                    limit = limit.min(direct_left());
                    if limit.is_zero() {
                        why = NetError::Unreachable(format!("the time for reaching ~{to} directly ran out"));
                        break;
                    }
                }
                match tokio::time::timeout(limit, self.dial(client, from, to, now_held, addr, true, true)).await {
                    Ok(Ok((connection, proved))) => {
                        // Connecting took time. If an address has been set by hand meanwhile,
                        // or the ship's key has changed, what was just proved is out of date.
                        if !matches!(self.route(to), Some(Route::Found(Some(key))) if key == proved) {
                            connection.close(VarInt::from_u32(2), b"the directory changed");
                            return Err(changed());
                        }
                        return Ok((connection, Peer { key: proved, addr }, None));
                    }
                    Ok(Err(failed)) => why = failed,
                    Err(_) => why = NetError::Unreachable(format!("nothing answered as ~{to} at {addr} in time")),
                }
            }
            if relaying {
                // Read again before the point is asked to relay: by hand wins.
                let now_held = match self.route(to) {
                    Some(Route::Found(key)) if moon || key == held => key,
                    _ => return Err(changed()),
                };
                match self.dial_relayed(finder, client, from, to, now_held, held, deadline).await? {
                    Ok((connection, proved, leg)) => {
                        // As after any attempt: the directory read again.
                        if !matches!(self.route(to), Some(Route::Found(Some(key))) if key == proved) {
                            connection.close(VarInt::from_u32(2), b"the directory changed");
                            return Err(changed());
                        }
                        finder.relay_did(to, lead.kept_as);
                        let addr = leg.addr;
                        return Ok((connection, Peer { key: proved, addr }, Some(leg)));
                    }
                    Err(relay_failed) => {
                        let tried = if straight { "it was reached through its point's relay last time, so that was tried first" } else { "it asks to be introduced first, and nothing answered as it after that (its router, or this runtime's, lets nothing in this way)" };
                        why = NetError::Unreachable(format!("~{to} could not be reached directly: {tried}; and it was not relayed: {relay_failed}. Last: {why}"));
                    }
                }
            } else if lead.introduce {
                why = NetError::Unreachable(format!(
                    "~{to} could not be reached directly: it asks to be introduced first, and nothing answered as it after that (its router, or this runtime's, lets nothing in this way; reaching it needs its point's relay, which this ship can ask for only once it announces a record of its own). Last: {why}"
                ));
            }
            finder.failed(to, lead.kept_as);
        }
        Err(why)
    }

    /// Ask `to`'s point to carry this ship's packets to `to`, and on a session, dial `to`
    /// through it with the rest of the time: `held` is the key held now, `began` the key the
    /// call began with. An error that ends the call (the directory changed), or why the relay
    /// did not reach the ship: the point does not relay, refused for a limit, or did not answer,
    /// or nothing answered through it.
    #[allow(clippy::too_many_arguments)]
    async fn dial_relayed(
        &self,
        finder: &Arc<Finder>,
        client: &quinn::ClientConfig,
        from: &str,
        to: &str,
        held: Option<[u8; 32]>,
        began: Option<[u8; 32]>,
        deadline: tokio::time::Instant,
    ) -> Result<Result<(Connection, [u8; 32], Leg), String>, NetError> {
        let Some(relayed) = &self.relayed else { return Ok(Err("this runtime cannot relay".into())) };
        let moon = ob::moon_number(to).is_some();
        let (point, id) = match tokio::time::timeout(lookup::relay_wait(deadline), finder.relay(&self.runtime, from, to, deadline)).await {
            Ok(Ok(answered)) => answered,
            Ok(Err(refused)) => return Ok(Err(refused)),
            Err(_) => return Ok(Err("its point did not answer the request to relay in time".into())),
        };
        // The last thing read before the attempt, as before any: by hand wins.
        let now_held = match self.route(to) {
            Some(Route::Found(key)) if moon || (key == held && key == began) => key,
            _ => return Err(NetError::Unreachable("the directory changed while looking for the ship".into())),
        };
        let leg = match relayed.calling(point, id) {
            Ok(leg) => leg,
            Err(why) => return Ok(Err(format!("its point would relay, and no session could be registered here: {why}"))),
        };
        let client = self.through_relay(client)?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        Ok(match tokio::time::timeout(left, self.dial(&client, from, to, now_held, leg.addr, true, true)).await {
            Ok(Ok((connection, proved))) => Ok((connection, proved, leg)),
            Ok(Err(failed)) => Err(format!("its point took the session, and nothing answered as ~{to} through it: {failed}")),
            Err(_) => Err(format!("its point took the session, and nothing answered as ~{to} through it in time")),
        })
    }

    /// The way of calling a ship through a relay: as `client` (which keeps itself alive), with
    /// packets small enough to take the relay's header and still fit.
    fn through_relay(&self, client: &quinn::ClientConfig) -> Result<quinn::ClientConfig, NetError> {
        let mut transport = transport(&self.cfg, 0).map_err(|e| NetError::Unreachable(e.to_string()))?;
        transport.keep_alive_interval(Some(self.cfg.lookup.keep_alive));
        let mut mtu = MtuDiscoveryConfig::default();
        mtu.upper_bound(MOST_RELAYED_PACKET);
        transport.mtu_discovery_config(Some(mtu));
        let mut client = client.clone();
        client.transport_config(Arc::new(transport));
        Ok(client)
    }

    /// Try the direct way again for a pair whose kept connection goes through a relay (the entry
    /// of generation `relayed`), by the path any call to a record takes: the record held (or one
    /// asked of the point), an introduction if it asks for one, then each address. The
    /// directory is read again before the introduction and before each attempt, and the try
    /// stops if it sees an address set by hand or another key. A connection made takes the
    /// relayed one's place only with the pair's slot held (waited for until the try's deadline
    /// at most), and only if the entry kept is still the very one the try began from (by its
    /// generation, whether or not it has since closed: the ship called closes it from its
    /// end as soon as it takes the direct connection, the newest from a calling ship replacing
    /// the older), the route still fits, and it is proved in one step with the directory
    /// (`prove_as`), as any kept connection is. Otherwise the candidate is closed. On taking its
    /// place the old entry is closed and dropped, and its session with it; a request under way
    /// on it then fails as any request on a closed connection does, and commands are delivered
    /// exactly once by the redelivery that already exists. A try that fails before the ship
    /// called has taken its connection changes nothing (no record is marked failed, no key
    /// doubted); one that fails after (its last proof fails, or the route changed under it)
    /// leaves the pair with no working kept connection until the next call makes one.
    async fn go_direct(self: Arc<Self>, pair: Pair, relayed: u64, _trying: Trying, _turn: tokio::sync::OwnedSemaphorePermit) {
        let (from, to) = (pair.0.as_str(), pair.1.as_str());
        let deadline = tokio::time::Instant::now() + self.cfg.request_timeout;
        let Some(finder) = self.finder.clone() else { return };
        let moon = ob::moon_number(to).is_some();
        let Some(Route::Found(held)) = self.route(to) else { return };
        let Ok(key) = self.runtime.signing_key(from) else { return };
        let shown = key.verifying_key().to_bytes();
        let Ok(lead) = finder.ask(&self.directory, to, deadline).await else { return };
        let Ok(client) = self.calling(&key, to, held) else { return };
        let client = match lead.introduce {
            true => {
                if !matches!(self.route(to), Some(Route::Found(key)) if moon || key == held) {
                    return;
                }
                let _ = tokio::time::timeout(lookup::introduce_wait(deadline), finder.introduce(&self.runtime, from, to, deadline)).await;
                let Ok(client) = self.kept_alive(&client) else { return };
                client
            }
            false => client,
        };
        for &addr in &lead.addresses {
            let now_held = match self.route(to) {
                Some(Route::Found(key)) if moon || key == held => key,
                _ => return,
            };
            let limit = if lead.introduce { lookup::introduced_limit(deadline) } else { lookup::try_limit(deadline) };
            let Ok(Ok((connection, proved))) = tokio::time::timeout(limit, self.dial(&client, from, to, now_held, addr, true, false)).await else { continue };
            self.direct_made.fetch_add(1, Ordering::SeqCst);
            let Ok(slot) = self.slot(&pair) else {
                connection.close(VarInt::from_u32(2), b"no longer wanted");
                return;
            };
            // The slot is waited for no longer than the try's own deadline.
            let Ok(mut kept) = tokio::time::timeout_at(deadline, slot.lock()).await else {
                connection.close(VarInt::from_u32(2), b"no longer wanted");
                return;
            };
            // Weighed with the pair's slot held: the entry kept is still the relayed one this try
            // began from (closed or not), the ship is still found through its point with the key
            // just proved, and the directory proves it again in one step.
            let current = kept.as_ref().is_some_and(|made| made.relayed.is_some() && made.generation == relayed && made.shown == shown);
            let fits = matches!(self.route(to), Some(Route::Found(Some(key))) if key == proved);
            if current && fits && self.directory.prove_as(to, &proved, true) {
                let direct = Made { connection, peer: Peer { key: proved, addr }, shown, found: true, relayed: None, generation: self.generation() };
                if let Some(old) = kept.replace(direct) {
                    old.connection.close(VarInt::from_u32(2), b"replaced by a direct connection");
                }
                drop(kept);
                finder.direct_again(to);
            } else {
                connection.close(VarInt::from_u32(2), b"no longer wanted");
            }
            return;
        }
    }

    /// The same way of calling, with a packet sent every `keep_alive`: for a connection made
    /// on a record that asks for introductions, so that the routers it passes through keep it
    /// open while it is idle. Nothing else about it changes.
    fn kept_alive(&self, client: &quinn::ClientConfig) -> Result<quinn::ClientConfig, NetError> {
        let mut transport = transport(&self.cfg, 0).map_err(|e| NetError::Unreachable(e.to_string()))?;
        transport.keep_alive_interval(Some(self.cfg.lookup.keep_alive));
        let mut client = client.clone();
        client.transport_config(Arc::new(transport));
        Ok(client)
    }

    /// A lookup point has passed on a caller's record for one of this runtime's ships. If that
    /// ship was last announced asking callers to be introduced, the record is believed by this
    /// runtime's own checks, and the allowances let it, `PUNCH` is sent from this runtime's
    /// port to each address the record names, `PUNCH_ROUNDS` times, and nothing else.
    ///
    /// Nothing the point says is taken on its word, the record is weighed against what this
    /// runtime already believes of the caller as an ordinary lookup would weigh it, and nothing
    /// of the introduction is kept:
    /// not the record, not a moon's word in it, not a route. The caller's key is read from
    /// Urbit ID into the directory as for any ship that says its name, under the same limits.
    ///
    /// An introduction that carries a session (the caller asked the point to relay) is weighed
    /// by the very same steps and allowance (weighing is the same work), and then, instead of
    /// any packet being sent, the session is registered with the relay's wrapper, bound to the
    /// point at the other end of the connection it came on (`pushed_on`), within the wrapper's
    /// own bounds on sessions. Nothing is sent for it. The caller's connection attempt then
    /// arrives through it and is taken, checked and limited as any caller's is.
    async fn introduced(self: &Arc<Self>, introduction: &[u8], pushed_on: Option<&Connection>) -> Result<(), &'static str> {
        let finder = self.finder.as_ref().ok_or("this runtime finds no ships through lookup points")?;
        let Introduction { callee, record, session } = Introduction::decode(introduction).map_err(|_| "not an introduction")?;
        let session: Option<SessionId> = match session.len() {
            0 => None,
            _ => Some(session.as_slice().try_into().map_err(|_| "the introduction names a session that cannot be one")?),
        };
        let callee = whereabouts::name_of(callee).ok_or("the introduction names no ship")?;
        // Only for a ship held here, and last announced asking for introductions.
        if self.runtime.signing_key(&callee).is_err() || !finder.introduces(&callee) {
            return Err("the introduction is for no ship here that asks for introductions");
        }
        if !lock(&self.punching.weighing).take() {
            return Err("too many introductions just now");
        }
        self.punching.weighed.fetch_add(1, Ordering::SeqCst);
        let caller = whereabouts::ship_of(&record).and_then(whereabouts::name_of).ok_or("the introduction carries no record")?;
        if self.runtime.signing_key(&caller).is_ok() {
            return Err("the introduction is of a ship of this runtime's own");
        }
        // The caller's key is found as any caller's is, and under the same limits.
        let subject = parent_of(&caller).unwrap_or_else(|| caller.clone());
        if self.directory.due(&subject) == Due::Now && !self.may_meet() {
            return Err("too many ships nothing is known of just now");
        }
        self.know(&caller, MOST_LOOKUPS / 2).await;
        // Believed by this runtime's own checks: keys from its own directory, fresh by its own
        // clock, and weighed against what this runtime already believes of the caller (the
        // newest record held for it, and for a moon the latest of its parent's word), as an
        // ordinary lookup would weigh it. Nothing of it is kept: neither is advanced.
        let (known, now) = finder.known(&caller, &self.directory);
        let believed = whereabouts::check(&record, &|name: &str| self.directory.key_of(name), known, now)?;
        // For a moon, its parent's word is weighed by the directory's own rule, as an ordinary
        // lookup weighs it (a key set by hand for the moon included), without taking it.
        if let (Some((_, key)), Some(proof)) = (believed.moon, believed.proof) {
            self.directory.moon_word_stands(&caller, key, &proof)?;
        }
        // Finding the caller's key may have waited: whether the ship still asks to be
        // introduced is read again before anything is sent or registered.
        if !finder.introduces(&callee) {
            return Err("the ship no longer asks for introductions");
        }
        if let Some(id) = session {
            let relayed = self.relayed.as_ref().ok_or("this runtime cannot be relayed to")?;
            let pushed_on = pushed_on.ok_or("a session came on no connection to a point")?;
            // The point that carries the session is the one the push came from.
            // A moon caller counts as its planet against the bound for any one caller.
            let owner = parent_of(&caller).unwrap_or_else(|| caller.clone());
            relayed.called(pushed_on.remote_address(), id, &owner, pushed_on.stable_id())?;
            self.punching.sessions.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        // A place among those under way first, then the allowances; a refusal after the place is
        // taken gives it back at once. Introductions are weighed one at a time, so no other can
        // want a place while a refused one briefly holds it.
        let turn = self.punching.under_way.clone().try_acquire_owned().map_err(|_| "too many introductions being acted on")?;
        if !self.punching.for_caller(&caller) {
            return Err("too many introductions of that caller just now");
        }
        if !lock(&self.punching.all).take() {
            return Err("too many introductions acted on just now");
        }
        self.punching.acted.fetch_add(1, Ordering::SeqCst);
        let (socket, sent) = (self.socket.clone(), self.punching.sent.clone());
        tokio::spawn(async move {
            for round in 0..PUNCH_ROUNDS {
                if round > 0 {
                    tokio::time::sleep(PUNCH_GAP).await;
                }
                for &destination in &believed.addresses {
                    let packet = Transmit { destination, ecn: None, contents: PUNCH, segment_size: None, src_ip: None };
                    if socket.try_send(&packet).is_ok() {
                        sent.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            drop(turn);
        });
        Ok(())
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

/// The protocol agreed on a connection, if one was.
fn protocol_of(connection: &Connection) -> Option<Vec<u8>> {
    connection.handshake_data()?.downcast::<HandshakeData>().ok()?.protocol
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

/// Weigh the introductions lookup points pass to this runtime's ships, one at a time, each
/// within `INTRODUCTION_LIMIT`, for as long as the network runs. Each comes with the
/// connection to the point it came on.
async fn weigh_introductions(shared: Arc<Shared>, mut introductions: tokio::sync::mpsc::Receiver<(Vec<u8>, Connection)>) {
    while let Some((introduction, pushed_on)) = introductions.recv().await {
        shared.punching.heard.fetch_add(1, Ordering::SeqCst);
        let _ = tokio::time::timeout(INTRODUCTION_LIMIT, shared.introduced(&introduction, Some(&pushed_on))).await;
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
async fn answer_caller(shared: Arc<Shared>, incoming: Incoming, place: Place, admission: u64) {
    let Ok(connecting) = incoming.accept() else { return };
    let Ok(Ok(connection)) = tokio::time::timeout(shared.cfg.request_timeout, connecting).await else { return };
    // A connection under the lookup protocol is no ship's. It gives up its place among the
    // ships' connections, and the point counts it among its own. Only a runtime that is a
    // lookup point agrees to the protocol at all.
    if protocol_of(&connection).as_deref() == Some(lookup::WHERE_PROTOCOL) {
        drop(place);
        match &shared.point {
            // Through a relay session, nobody is a point's to answer (`lookup::serve` refuses it
            // too): nothing may be sent toward a made-up address but through the session.
            Some(_) if relay::is_made_up(&connection.remote_address()) => connection.close(VarInt::from_u32(1), b"not through a relay"),
            Some(point) => lookup::serve(point.clone(), connection, shared.cfg.request_timeout).await,
            None => connection.close(VarInt::from_u32(1), b"not a lookup point"),
        }
        return;
    }
    let _place = place;
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
pub(crate) async fn read_whole(receive: &mut RecvStream, max: usize) -> Option<Vec<u8>> {
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
            // The closure owns a handle to the connection, and reads its number from it when it
            // runs. The job may outlive this request (which can time out and let go of its own
            // handle): while the closure holds one, the connection's allocation cannot be given to
            // a newer connection, so its number cannot be mistaken for the newer one's.
            let (callers, pair, held) = (shared.clone(), (caller.to_string(), called.to_string()), connection.clone());
            let current = move || newest_from(&callers, &pair, held.stable_id());
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
            // The closure owns a handle to the connection, as on comparing notes below, so that a
            // job that outlives this request cannot take a newer connection's number for its own.
            let (callers, pair, held) = (shared.clone(), (caller.to_string(), called.to_string()), connection.clone());
            let current = move || newest_from(&callers, &pair, held.stable_id());
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
pub(crate) fn repeats_within(request: &[u8], outer: u64, inner: u64, most: usize) -> bool {
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

/// Ships behind pretend home routers, which need the crate's own way of giving a network a
/// socket.
#[cfg(test)]
#[path = "router_tests.rs"]
mod router_tests;

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

    #[test]
    fn a_moons_word_from_a_record_is_the_one_memory_of_its_keys() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        let planet = 0x4100_0000u32;
        let parent = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        told.say(planet, Some((Some(parent.verifying_key().to_bytes()), 1)));
        directory.read(&name(planet));
        let (moon, moon_name) = moon_of(planet, 1);
        let (first, second) = ([1; 32], [2; 32]);
        // The moon was met at its first key, and proved it.
        directory.vouched(&moon_name, first, &moon::vouch(&parent, moon, 1, &first)).unwrap();
        assert_eq!(directory.proved_key_of(&moon_name), Some(first));
        // A record shows the parent's word for a second key, at revision two. It holds at
        // once: the first key is no longer the moon's for any connection, made or taken, and
        // the moon is still among the ships kept.
        directory.recorded_word(&moon_name, second, &moon::vouch(&parent, moon, 2, &second), &|| true).unwrap();
        assert_eq!(directory.key_of(&moon_name), Some(second));
        assert_eq!(directory.proved_key_of(&moon_name), Some(second));
        assert_eq!(directory.moon_seen(&moon_name), Some((2, second)));
        assert!(directory.vouched(&moon_name, first, &moon::vouch(&parent, moon, 1, &first)).is_err());
        assert!(directory.recorded_word(&moon_name, first, &moon::vouch(&parent, moon, 1, &first), &|| true).is_err());
        assert!(directory.recorded_word(&moon_name, first, &moon::vouch(&parent, moon, 2, &first), &|| true).is_err());
        // A word not the parent's is not taken.
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        assert!(directory.recorded_word(&moon_name, [3; 32], &moon::vouch(&stranger, moon, 3, &[3; 32]), &|| true).is_err());

        // A moon never met, known only from a record: its key is held, it has proved nothing,
        // and its parent is kept. Neither is dropped for any number of names said after.
        let (other, other_name) = moon_of(planet, 2);
        directory.recorded_word(&other_name, [4; 32], &moon::vouch(&parent, other, 1, &[4; 32]), &|| true).unwrap();
        assert_eq!(directory.key_of(&other_name), Some([4; 32]));
        assert_eq!(directory.proved_key_of(&other_name), None);
        crowd(&directory, 0x1500_0000, 40);
        assert_eq!(directory.key_of(&other_name), Some([4; 32]));
        assert_eq!(directory.proved_key_of(&name(planet)), Some(parent.verifying_key().to_bytes()));
        // Moons from records count against the moons of one ship: three here.
        let (third, third_name) = moon_of(planet, 3);
        directory.recorded_word(&third_name, [5; 32], &moon::vouch(&parent, third, 1, &[5; 32]), &|| true).unwrap();
        let (fourth, fourth_name) = moon_of(planet, 4);
        assert_eq!(directory.recorded_word(&fourth_name, [6; 32], &moon::vouch(&parent, fourth, 1, &[6; 32]), &|| true), Err("there is no room to keep another moon's key"));
        // A key set here by hand is never changed by a record.
        directory.set(&fourth_name, [9; 32], "127.0.0.1:9".parse().unwrap()).unwrap();
        assert!(directory.recorded_word(&fourth_name, [6; 32], &moon::vouch(&parent, fourth, 2, &[6; 32]), &|| true).is_err());
        assert_eq!(directory.key_of(&fourth_name), Some([9; 32]));
        // It goes only when the parent's key it stands on is no longer believed.
        told.say(planet, Some((Some([0x77; 32]), 2)));
        reread(&directory, planet);
        assert_eq!(directory.key_of(&other_name), None);
    }

    #[test]
    fn a_moon_known_from_a_record_takes_a_place_when_it_proves_its_key() {
        let told = Arc::new(Told::default());
        let bounds = Bounds { proved: 2, unproved: 8, moons: 5, moons_each: 3 };
        let directory = Directory::made(Some(told.clone()), Duration::from_millis(1), HOUR, bounds);
        let planet = 0x4200_0000u32;
        let parent = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        told.say(planet, Some((Some(parent.verifying_key().to_bytes()), 1)));
        directory.read(&name(planet));
        let (moon, moon_name) = moon_of(planet, 1);
        let key = [1; 32];
        let word = moon::vouch(&parent, moon, 1, &key);
        // The moon is remembered from a record: its parent takes one of the two places.
        directory.recorded_word(&moon_name, key, &word, &|| true).unwrap();
        // Another ship takes the other.
        let other = 0x4300_0000u32;
        directory.read(&name(other));
        assert!(directory.prove(&name(other), &key_of_number(other)));
        // The moon now proves its key on a connection. Its word stands, but there is no room
        // to keep it as proved, and the connection is refused as any other would be.
        assert!(directory.vouched(&moon_name, key, &word).is_ok());
        assert!(!directory.prove(&moon_name, &key));
        assert_eq!(directory.proved_key_of(&moon_name), None);
        assert_eq!(directory.key_of(&moon_name), Some(key));
        let kept = directory.listed.read().unwrap().keys.values().filter(|entry| entry.proved && !matches!(entry.from, From::Set)).count();
        assert_eq!(kept, 2);
        // With room, it is taken.
        let roomy = Directory::made(Some(told.clone()), Duration::from_millis(1), HOUR, Bounds { proved: 3, ..bounds });
        roomy.read(&name(planet));
        roomy.recorded_word(&moon_name, key, &word, &|| true).unwrap();
        roomy.read(&name(other));
        assert!(roomy.prove(&name(other), &key_of_number(other)));
        assert!(roomy.vouched(&moon_name, key, &word).is_ok());
        assert!(roomy.prove(&moon_name, &key));
        assert_eq!(roomy.proved_key_of(&moon_name), Some(key));
    }

    #[test]
    fn a_connection_found_through_a_point_is_not_proved_once_an_address_is_set_by_hand() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        let ship = 0x4400_0000u32;
        directory.read(&name(ship));
        let key = key_of_number(ship);
        // With no address set by hand, a connection found through a point is proved.
        assert!(directory.prove_as(&name(ship), &key, true));
        // Once one is set, it is refused in the same step, though the key is the one held and
        // the ship is kept; a connection to the address set by hand is proved as ever.
        directory.place(&name(ship), "127.0.0.1:9".parse().unwrap()).unwrap();
        assert!(!directory.prove_as(&name(ship), &key, true));
        assert!(directory.prove_as(&name(ship), &key, false));
        assert!(directory.prove(&name(ship), &key));
    }

    #[test]
    fn a_moons_word_from_a_record_no_longer_good_is_not_taken() {
        let told = Arc::new(Told::default());
        let directory = small(&told, HOUR);
        let planet = 0x4500_0000u32;
        let parent = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        told.say(planet, Some((Some(parent.verifying_key().to_bytes()), 1)));
        directory.read(&name(planet));
        let (moon, moon_name) = moon_of(planet, 1);
        let word = moon::vouch(&parent, moon, 2, &[2; 32]);
        // Asked with the directory held, the record is found no longer good: nothing changes,
        // neither the moon nor its parent.
        assert!(directory.recorded_word(&moon_name, [2; 32], &word, &|| false).is_err());
        assert_eq!(directory.key_of(&moon_name), None);
        assert_eq!(directory.moon_seen(&moon_name), None);
        assert_eq!(directory.proved_key_of(&name(planet)), None);
        // Still good, it is taken.
        assert!(directory.recorded_word(&moon_name, [2; 32], &word, &|| true).is_ok());
        assert_eq!(directory.moon_seen(&moon_name), Some((2, [2; 32])));
    }

    fn messages_within(request: &[u8], most: usize) -> bool {
        repeats_within(request, 2, 1, most)
    }

    fn deliver(count: usize) -> Vec<u8> {
        let messages = (0..count).map(|_| ship_proto::PeerMessage::default()).collect();
        PeerRequest { body: Some(peer_request::Body::Deliver(Deliver { messages })) }.encode_to_vec()
    }

    #[test]
    fn only_so_many_callers_are_counted_for_introductions() {
        let punching = Punching::new();
        for n in 0..MOST_PUNCHED_FOR {
            assert!(punching.for_caller(&format!("caller-{n}")));
        }
        // Each has spent half its allowance, so none is forgotten: a new caller is turned away.
        assert!(!punching.for_caller("another"));
        // One already counted has its allowance still.
        assert!(punching.for_caller("caller-0"));
        assert!(!punching.for_caller("caller-0"));
        // Once allowances are whole again, the callers are forgotten and a new one is counted.
        std::thread::sleep(Duration::from_millis(1100));
        assert!(punching.for_caller("another"));
        assert!(lock(&punching.each).len() < 3);
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
