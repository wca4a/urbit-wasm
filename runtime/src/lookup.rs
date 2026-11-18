//! Finding a ship by its name alone: lookup points, and asking them.
//!
//! Urbit ID says which key belongs to which ship, but not where the ship is. Without this
//! module a runtime has to be told by hand where every other ship can be reached. With it, a
//! runtime that has a public address signs a record of where each of its ships is (see
//! `crate::whereabouts`) and gives it to the lookup point for that ship's galaxy, again every
//! two minutes. A runtime that wants to call a ship it has no address for asks the point for
//! that ship's galaxy, checks the record itself against the key Urbit ID lists for the ship,
//! and calls the addresses it names.
//!
//! A lookup point is a role any runtime can play. It listens on the same UDP port as the
//! ships, under a protocol name of its own (`ship-where/1`), so nothing it does shares a path
//! with ship-to-ship requests once the connection is made. It has no identity worth proving:
//! it shows a key made when it starts, and callers take any key. That is safe because nothing
//! a point says about who anyone is, or about what a ship's record says, is taken on its word.
//! A record is believed only if the ship signed it, so a point can keep one back, or hand out
//! one that has not run out yet, and nothing more; the one thing a ship does take on a point's
//! word is where that point sees it from (`Seen`, below), with the limits said there. The
//! point checks what it is given too, against its own copy of Urbit ID, and keeps and hands
//! out only records that pass its own checks. A ship that asks may know more than the point
//! (a later word of a moon's parent, a newer record of the ship) and refuse what the point
//! hands out.
//!
//! The point for a galaxy is found at a fixed address given by whoever runs the runtime, or by
//! looking up `<galaxy>.<domain>` (`zod.example.net` for `~zod`) through the system's resolver.
//! The domain is a setting; who runs the points under it is not decided here.
//!
//! At a ship, the directory (`crate::net::Directory`) is the one memory of a moon's keys: a
//! moon's record carries its parent's word, and believing the record takes that word into
//! the directory, where it holds for every connection. What this module keeps of other
//! ships is only the newest record believed for each, which keeps older ones off until it
//! runs out and is never dropped for room before then.
//!
//! A change to what is kept is weighed under the lock that guards it, and that is a hard
//! promise: a record is kept at the point, or by a ship that asked, only if it is still good
//! by the clock read with the table (or the records) held, and a moon's word from a record is
//! taken into the directory only if the record is still good by the clock read with the
//! directory held. A reading taken earlier may refuse early, never keep. A clock that moves
//! during checking stops a record being kept if the move makes it no longer good. A call in
//! progress when something changes only notices at its next check that sees it; that is best
//! effort. Each record a ship keeps is named by a number never used for another (when the
//! numbers run out, no more records are kept), and only the record whose addresses were
//! tried is marked failed.
//!
//! A point bounds the work strangers can give it by a count of requests in hand, taken
//! before a request is read, by the size of a request, and by rates of records and
//! questions counted as requests arrive.
//!
//! A runtime with none of these settings sends nothing new, listens for nothing new, and keeps
//! nothing new: everything here is off unless asked for.
//!
//! The outside address. A runtime asks the point of its own galaxy, over the connection it
//! announces on, what address that connection comes from (`Seen`), and announces that, unless
//! whoever runs it has stated the addresses by hand, which always win. What a point reports
//! is believed only for the ships of that point's own galaxy, only over the connection it was
//! asked on, and only as an address a record may carry.
//!
//! Presence. A ship gives its record to a point together with its presence on that one
//! connection (see `crate::whereabouts`), and the point keeps the record only with it. So the
//! point knows, for each record it holds, the connection the ship itself is on: where the ship
//! attends. That stops being so when the connection closes, the record runs out, or a newer
//! record of the ship is kept, which names its own connection. The connection stays open, with
//! a packet every `keep_alive` so that a home router keeps its way in open, and is made again
//! at once if it drops, with fresh presence.
//!
//! Introductions. A ship behind a home router can be reached only once it has sent something
//! toward its caller, which opens its router to that caller. Its record says so, under its
//! signature, and a caller about to try such a record first asks the ship's point to introduce
//! it (`Introduce`), showing its own record and its presence. The point checks both as it
//! would an announcement, keeps nothing, and passes the caller's record to the ship over the
//! connection the ship attends on, never anywhere else. The ship checks the record itself, and
//! sends three small packets from its own port to the caller's addresses, and nothing else:
//! its router then lets the caller's ordinary connection attempt in. Nothing on this path is
//! believed about who anyone is; the connection that follows is proved as any other is.
//!
//! Relaying. A ship behind a router of the strict kind, which gives each destination a port of
//! its own, cannot be opened by an introduction. A point set to relay (`PointConfig::relay`)
//! answers `Relay`, checked as `Introduce` is, by making a session between two addresses it has
//! itself seen (the remote addresses of the ship's attending connection and of the caller's),
//! with its table held, and passing the caller's record and the session to the ship as an
//! introduction is passed. The packets themselves are carried by the socket's wrapper, which
//! asks the point (`Point::carry`) with the table held; see `crate::relay`. A point not set to
//! relay refuses, and says so.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};
use ship_proto::{
    where_reply, where_request, Announce, Announced, Found, Introduce, Introduced, Introduction, Message, Relay, Relaying, Saw, Seen, Where, WhereReply,
    WhereRequest,
};
use tokio::sync::{Notify, Semaphore};
use urbit_id::ob;

use crate::azimuth::Keys;
use crate::net::{self, Directory, NetConfig, NetError};
use crate::relay::{self, Carry, RelayBounds, SessionId, Sessions, NO_RELAY};
use crate::store::now_ms;
use crate::whereabouts::{self, Believed, Binding, Known};
use crate::{lock, Runtime};

/// The name of the lookup protocol, agreed while connecting. A runtime that is not a lookup
/// point does not offer it.
pub(crate) const WHERE_PROTOCOL: &[u8] = b"ship-where/1";

/// The name a caller gives when connecting to a lookup point. A point shows the same key
/// whatever name it is given; this is only something the TLS library will take as a name.
const POINT_NAME: &str = "lookup";

/// The most a request to a lookup point, or its answer, may come to: room for an
/// announcement of as many records as one may carry, each as large as a record may be, with
/// their framing.
const MOST_WHERE_BYTES: usize = 2 * MOST_ANNOUNCED * whereabouts::MOST_RECORD_BYTES;

/// The most records one announcement may carry. A runtime with more ships of one galaxy
/// sends them in several.
pub const MOST_ANNOUNCED: usize = 16;

/// What further credit for requests in progress on one lookup connection is held to, once
/// its handshake is over. Credit given at the handshake (the ships' allowance, `max_streams`
/// with room for a whole message on each) cannot be taken back and stays usable after it;
/// only what is given later is held to this. A runtime announcing its ships and asking about
/// others needs a few. This is not what bounds a point's work: `MOST_IN_HAND` is.
const MOST_POINT_STREAMS: u32 = 4;

/// How many questions to Urbit ID a lookup point may have out at once, each on a thread that
/// may wait. A copy of Azimuth answers from a file, but any source of keys may be slow.
const MOST_POINT_READING: usize = 8;

/// How many requests a lookup point has in hand at once, all connections together: being
/// read, waiting for a thread to check on, or being checked. Each holds at most a request's
/// worth of bytes (`MOST_WHERE_BYTES`) and what it decodes to, about 24 KiB, so this is
/// about 1.5 MiB in all. Past it a request is refused at once, before any of it is read.
pub const MOST_IN_HAND: usize = 64;

/// How many questions about ships one connection to a lookup point may ask at a stroke, and
/// are earned back a second. A
/// question costs the point next to nothing, so this is only there so that it costs
/// something to ask about every ship there is.
const MOST_QUESTIONS_EACH: u32 = 64;

/// After the table of a lookup point was last swept of records that have run out, how long
/// before it is swept again. It is swept only when it is full, and sweeping looks at every
/// record, so this keeps a stream of new ships at a full point from making it sweep for each.
const SWEEP_AGAIN: Duration = Duration::from_secs(1);

/// The longest one address is tried for before the next. A connection to an address where
/// nothing answers fails only when it times out, and a record may name such an address, so
/// each try is cut short. It is never more than half of the time left, so that there is
/// always time to ask the point again, or to try another address.
const TRY_ADDRESS: Duration = Duration::from_secs(3);

/// How many lookup points a runtime keeps connections to. There is one point for each galaxy
/// with ships here or called from here, and the points are usually far fewer: often one.
const MOST_POINTS: usize = 64;

/// The most addresses taken from one answer of the system's resolver. Each is tried in turn.
const MOST_POINT_ADDRESSES: usize = 8;

/// The longest a caller waits for a name to be looked up. The system's resolver cannot be
/// stopped once asked, so a lookup that runs over is given up on and left to finish on its
/// own thread, which keeps one of the `MOST_RESOLVING` places until it returns.
const RESOLVE_LIMIT: Duration = Duration::from_secs(5);

/// How many names may be being looked up at once. A resolver that hangs holds a thread for
/// each, so this is how many threads one that hangs can hold.
const MOST_RESOLVING: usize = 4;

/// How many ships' records a runtime keeps from what points have told it. A record is never
/// dropped for room before it has run out, since it is what holds older records of its ship
/// off; past this, a record of a ship not yet held is not believed. An entry is small, and
/// the only way one is made is for one of this runtime's own ships to call a ship.
const MOST_FLOORS: usize = 1 << 16;

/// How many ships a runtime remembers having asked a point about, recently.
const MOST_ASKED_ABOUT: usize = 4096;

/// How many questions to lookup points may be out at once. Calls to ships not yet found
/// past this fail at once and are tried again later.
const MOST_ASKING: usize = 16;

/// How often the ships of a runtime are looked over to see which are due to be announced.
const ANNOUNCE_TICK: Duration = Duration::from_secs(1);

/// The longest any time setting here may be.
const MAX_SETTING: Duration = Duration::from_secs(24 * 60 * 60);

/// The shortest and longest `keep_alive` may be. A home router forgets an opening it has seen
/// nothing on for some tens of seconds, and a connection with nothing on it for the idle time
/// (thirty seconds unless set otherwise) is closed, so a packet must go well inside both; more
/// often than once a second is more than any router needs.
const MIN_KEEP_ALIVE: Duration = Duration::from_secs(1);
const MAX_KEEP_ALIVE: Duration = Duration::from_secs(25);

/// How many introductions a point may have open toward one ship's connection at once. Each is
/// a stream the point opens, carrying one introduction.
const MOST_PUSHES_OPEN: u32 = 4;

/// The most an introduction passed to a ship may come to: the ship's number, a record as large
/// as a record may be, and their framing.
pub(crate) const MOST_PUSH_BYTES: usize = whereabouts::MOST_RECORD_BYTES + 64;

/// The longest a point gives one introduction to reach a ship, once it begins to pass it on:
/// a few hundred bytes, which an honest ship takes in one trip there and back. After that the
/// stream is given up, and the next introduction begun.
const PUSH_LIMIT: Duration = Duration::from_secs(1);

/// The longest an introduction waits to be passed on at all. After that it is dropped: the
/// caller it is for has given up on the attempt it was for (`TRY_INTRODUCED`) or soon will.
const PUSH_WAIT: Duration = Duration::from_secs(3);

/// The longest a ship gives the point to finish one introduction it has begun to pass on.
const PUSH_READ_LIMIT: Duration = Duration::from_secs(2);

/// How many introductions may wait to be passed over one connection at once, and how many of
/// them for any one ship.
const MOST_WAITING: usize = 16;
pub const MOST_WAITING_EACH: usize = 4;

/// How many callers a point keeps count of introductions for. Past this, those whose
/// allowance is whole again are forgotten; if none is, a new caller is refused for a moment.
const MOST_INTRODUCERS: usize = 4096;

/// The longest one attempt at an address of a record that asks for introductions is given: a
/// caller's first packet may arrive before the ship's own packets have opened its router, and
/// is then lost, and QUIC sends it again after about a second (its first guess at the time a
/// packet takes there and back is a third of a second, and it waits three of those and a bit
/// before sending again). Then the ship asks the caller to show it is at the address it says
/// (one more time there and back), and the handshake follows. Four seconds leaves room for
/// all of that over real distances.
const TRY_INTRODUCED: Duration = Duration::from_secs(4);

/// The longest a caller waits for a point to say it has passed an introduction on, never more
/// than a quarter of the time left. A point that does not answer in time does not stop the
/// call: the ship is tried anyway.
const INTRODUCE_WAIT: Duration = Duration::from_secs(1);

/// When a relay may follow, the longest all the direct work on records that ask for
/// introductions may take in one call (the introductions and the attempts together), and never
/// more than half the time the call has when it begins: the rest is the relay's. A hole that
/// opens does so within about one Retry round trip and one retransmission of the first packet
/// (about a second, see `TRY_INTRODUCED`); five seconds is that with room for a slow first
/// answer from the point and real distances, and half the call leaves the relay as much.
const DIRECT_SHARE: Duration = Duration::from_secs(5);

/// The longest a caller waits for a point to answer a request to relay, never more than a
/// quarter of the time left. The point answers without waiting for the ship called.
const RELAY_WAIT: Duration = Duration::from_secs(1);

/// The shortest `direct_again` may be. Each try costs an introduction at the point, a few
/// packets from the ship called, and a connection attempt.
const MIN_DIRECT_AGAIN: Duration = Duration::from_secs(2);

/// How many records a runtime remembers that its direct attempts failed for and the relay
/// worked for, so that the next call on the same record goes straight to the relay.
const MOST_RELAY_REMEMBERED: usize = 1024;

/// The value both ends of a connection work out from its handshake, for a ship's presence on
/// it. `None` if the TLS library cannot give it, and then no presence can be made
/// or checked on the connection.
pub(crate) fn binding_of(connection: &Connection) -> Option<Binding> {
    let mut binding = [0u8; 32];
    connection.export_keying_material(&mut binding, whereabouts::BINDING_LABEL, b"").ok()?;
    Some(binding)
}

/// An address as it is, with an IPv4 address that came written as IPv6 written as IPv4.
fn plain(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Somewhere to look names up. The system's resolver is the one used, unless a test or a
/// private network gives another.
pub trait Resolve: Send + Sync {
    /// The addresses `host` has, each with `port`. This may wait as long as asking over a
    /// network takes, and is never called from a thread that must not wait.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String>;
}

/// The system's resolver, as anything else on this machine would use it.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        (host, port).to_socket_addrs().map(Iterator::collect).map_err(|e| format!("{host} could not be looked up: {e}"))
    }
}

/// How much a lookup point keeps and takes.
#[derive(Clone, Copy, Debug)]
pub struct PointBounds {
    /// Records in all. A record that is still good is never dropped to make room for
    /// another ship's, so past this a new ship is refused until some run out.
    pub records: usize,
    /// Moons in all, and moons of any one ship. A moon costs its parent nothing to make, so
    /// without these one ship could take all the room there is.
    pub moons: usize,
    pub moons_each: usize,
    /// Connections under the lookup protocol at once, apart from those of ships.
    pub connections: usize,
    /// Records checked each `rate_period`, on one connection and in all. Each costs a
    /// question to Urbit ID and a signature to check. As many as one period's worth may be
    /// checked at a stroke; after that they are earned back as the period passes.
    pub per_connection: u32,
    pub in_all: u32,
    /// The span of time the record rates are counted over: a second, unless set otherwise.
    pub rate_period: Duration,
    /// Introductions passed on each `rate_period`, in all, and for any one caller.
    pub introductions: u32,
    pub introductions_each: u32,
}

impl Default for PointBounds {
    fn default() -> Self {
        // Sixty-five thousand ships each announcing every two minutes is some five hundred
        // records a second.
        PointBounds {
            records: 1 << 16,
            moons: 1 << 14,
            moons_each: 64,
            connections: 256,
            per_connection: 256,
            in_all: 2048,
            rate_period: Duration::from_secs(1),
            introductions: 512,
            introductions_each: 4,
        }
    }
}

/// What a runtime needs to be a lookup point.
#[derive(Clone)]
pub struct PointConfig {
    /// Where ships' keys are read from, to check their records. Read straight from here, not
    /// through the runtime's directory, so that announcements cannot take room in it.
    pub keys: Arc<dyn Keys>,
    /// The galaxies whose ships this point keeps records for, by number. `None` for all.
    pub galaxies: Option<Vec<u8>>,
    pub bounds: PointBounds,
    /// Carry the packets of ships that cannot reach each other directly, within these bounds
    /// (see `crate::relay`). `None`, as by default, carries nothing, and says so.
    pub relay: Option<RelayBounds>,
}

impl fmt::Debug for PointConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PointConfig").field("galaxies", &self.galaxies).field("bounds", &self.bounds).field("relay", &self.relay).finish()
    }
}

/// Settings for finding ships through lookup points, and for being one. With none of them
/// set, as by default, a runtime does nothing of this.
#[derive(Clone)]
pub struct Lookup {
    /// Be a lookup point, with these settings.
    pub serve: Option<PointConfig>,
    /// Where lookup points are, given by hand: for one galaxy, by number, or with `None` for
    /// every galaxy. One given for a galaxy wins over one for all, and either over the domain.
    pub at: Vec<(Option<u8>, SocketAddr)>,
    /// The domain, and the port, lookup points are found under: the point for `~zod` is
    /// looked up as `zod.<domain>`.
    pub domain: Option<(String, u16)>,
    /// What names are looked up through. The system's resolver if not given.
    pub resolver: Option<Arc<dyn Resolve>>,
    /// The addresses to announce this runtime's ships at, as they are reached from outside.
    /// With none, the address the lookup point of each ship's galaxy sees this runtime's
    /// connection come from. Stated addresses always win: what a point says is then not used.
    pub announce: Vec<SocketAddr>,
    /// Ask callers to be introduced first, even with addresses stated by hand: for a runtime
    /// that knows its outside address but whose router lets nothing in unasked. With no
    /// addresses stated, callers are asked to be introduced whenever the address the point
    /// sees is not the one this runtime listens on, whatever this says.
    pub behind_router: bool,
    /// How often a packet goes over the connection to each lookup point this runtime announces
    /// to, and over a connection made to a ship that asks for introductions, so that a home
    /// router keeps the way in open. One to twenty-five seconds, and less than `idle_timeout`.
    pub keep_alive: Duration,
    /// How often each ship is announced again. Records last ten minutes, so this must leave
    /// room for some announcements to go astray.
    pub announce_every: Duration,
    /// How long after asking a point about a ship before asking about it again, whatever
    /// the answer was. Also how long a failure to look up a point's name is remembered.
    pub ask_again: Duration,
    /// How long an answer from the resolver is used before the name is looked up again.
    pub resolved_for: Duration,
    /// While a connection to a ship goes through its point's relay and is in use, how often
    /// the direct way is tried again. Two seconds to a day.
    pub direct_again: Duration,
}

impl Default for Lookup {
    fn default() -> Self {
        Lookup {
            serve: None,
            at: Vec::new(),
            domain: None,
            resolver: None,
            announce: Vec::new(),
            behind_router: false,
            keep_alive: Duration::from_secs(15),
            announce_every: Duration::from_secs(120),
            ask_again: Duration::from_secs(3),
            resolved_for: Duration::from_secs(300),
            direct_again: Duration::from_secs(60),
        }
    }
}

impl fmt::Debug for Lookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lookup")
            .field("serve", &self.serve)
            .field("at", &self.at)
            .field("domain", &self.domain)
            .field("resolver", &self.resolver.as_ref().map(|_| "given"))
            .field("announce", &self.announce)
            .field("behind_router", &self.behind_router)
            .field("keep_alive", &self.keep_alive)
            .field("announce_every", &self.announce_every)
            .field("ask_again", &self.ask_again)
            .field("resolved_for", &self.resolved_for)
            .field("direct_again", &self.direct_again)
            .finish()
    }
}

impl Lookup {
    /// Whether this runtime finds other ships through lookup points, and announces its own.
    pub fn finds(&self) -> bool {
        !self.at.is_empty() || self.domain.is_some()
    }

    /// Whether these settings make sense, and why not if they do not.
    pub(crate) fn sound(&self) -> Result<(), String> {
        let within = |time: Duration| !time.is_zero() && time <= MAX_SETTING;
        if !within(self.ask_again) || !within(self.resolved_for) {
            return Err("ask_again and resolved_for must be more than nothing and at most a day".into());
        }
        // Half a record's life: a record made then is still good when the next is due, with
        // room for one announcement to go astray.
        if self.announce_every.is_zero() || self.announce_every.as_millis() > u128::from(whereabouts::LIFETIME_MS / 2) {
            return Err("announce_every must be more than nothing and at most five minutes".into());
        }
        if self.keep_alive < MIN_KEEP_ALIVE || self.keep_alive > MAX_KEEP_ALIVE {
            return Err("keep_alive must be from one second to twenty-five".into());
        }
        if self.direct_again < MIN_DIRECT_AGAIN || self.direct_again > MAX_SETTING {
            return Err("direct_again must be from two seconds to a day".into());
        }
        if self.behind_router && !self.finds() {
            return Err("behind_router needs somewhere to announce: a lookup point's address or domain".into());
        }
        if !self.announce.is_empty() {
            if !self.finds() {
                return Err("addresses to announce at need somewhere to announce them: a lookup point's address or domain".into());
            }
            whereabouts::fits(&self.announce).map_err(|why| format!("the addresses to announce at: {why}"))?;
        }
        if let Some((domain, port)) = &self.domain {
            let fine = !domain.is_empty() && domain.len() <= 200 && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
            if !fine || *port == 0 {
                return Err(format!("{domain}:{port} is not a domain and port lookup points can be found under"));
            }
        }
        if self.at.iter().any(|(_, addr)| addr.port() == 0 || addr.ip().is_unspecified()) {
            return Err("a lookup point's address must be one that can be reached".into());
        }
        if let Some(point) = &self.serve {
            let b = point.bounds;
            if b.records == 0 || b.moons == 0 || b.moons_each == 0 || b.connections == 0 || b.per_connection == 0 || b.in_all == 0 || b.introductions == 0 || b.introductions_each == 0 {
                return Err("a lookup point's bounds must each be more than nothing".into());
            }
            if !within(b.rate_period) {
                return Err("a lookup point's rate_period must be more than nothing and at most a day".into());
            }
            if point.galaxies.as_ref().is_some_and(Vec::is_empty) {
                return Err("a lookup point must serve some galaxy".into());
            }
            if let Some(relay) = &point.relay {
                relay.sound()?;
            }
        }
        Ok(())
    }
}

/// A galaxy's name, without the `~`.
fn galaxy_name(galaxy: u8) -> String {
    ob::ship_name(u32::from(galaxy)).trim_start_matches('~').to_string()
}

/// How long to give one try, with `deadline` for all of them: `TRY_ADDRESS`, or half of what
/// is left if that is less.
pub(crate) fn try_limit(deadline: tokio::time::Instant) -> Duration {
    TRY_ADDRESS.min(deadline.saturating_duration_since(tokio::time::Instant::now()) / 2)
}

/// How long to give one try at an address of a record that asks for introductions:
/// `TRY_INTRODUCED`, or three quarters of what is left if that is less.
pub(crate) fn introduced_limit(deadline: tokio::time::Instant) -> Duration {
    introduced_limit_at(deadline, tokio::time::Instant::now())
}

/// The same, with the clock read already (`now`).
fn introduced_limit_at(deadline: tokio::time::Instant, now: tokio::time::Instant) -> Duration {
    let left = deadline.saturating_duration_since(now);
    TRY_INTRODUCED.min(left - left / 4)
}

/// How long to wait for a point to say it has passed an introduction on: `INTRODUCE_WAIT`, or
/// a quarter of what is left if that is less.
pub(crate) fn introduce_wait(deadline: tokio::time::Instant) -> Duration {
    introduce_wait_at(deadline, tokio::time::Instant::now())
}

/// The same, with the clock read already (`now`).
fn introduce_wait_at(deadline: tokio::time::Instant, now: tokio::time::Instant) -> Duration {
    INTRODUCE_WAIT.min(deadline.saturating_duration_since(now) / 4)
}

/// When a relay may follow, when all direct work on records that ask for introductions must be
/// over, for a call that began at `started` and must end by `deadline`: `DIRECT_SHARE` after
/// it began, or half way, whichever is sooner.
pub(crate) fn direct_by(started: tokio::time::Instant, deadline: tokio::time::Instant) -> tokio::time::Instant {
    started + DIRECT_SHARE.min(deadline.saturating_duration_since(started) / 2)
}

/// How long to wait for a point to answer a request to relay: `RELAY_WAIT`, or a quarter of
/// what is left if that is less.
pub(crate) fn relay_wait(deadline: tokio::time::Instant) -> Duration {
    relay_wait_at(deadline, tokio::time::Instant::now())
}

/// The same, with the clock read already (`now`).
fn relay_wait_at(deadline: tokio::time::Instant, now: tokio::time::Instant) -> Duration {
    RELAY_WAIT.min(deadline.saturating_duration_since(now) / 4)
}

/// So many things allowed in a second, topped up as time passes, up to a second's worth.
pub(crate) struct Bucket {
    left: f64,
    /// The most there may be, which is one period's worth.
    most: f64,
    /// How many are earned back in a second.
    per_second: f64,
    at: Instant,
}

impl Bucket {
    /// So many a second.
    pub(crate) fn new(rate: u32) -> Bucket {
        Bucket::per(rate, Duration::from_secs(1))
    }

    /// So many each `period`, which is more than nothing.
    pub(crate) fn per(rate: u32, period: Duration) -> Bucket {
        let most = f64::from(rate);
        Bucket { left: most, most, per_second: most / period.as_secs_f64().max(f64::MIN_POSITIVE), at: Instant::now() }
    }

    /// Whether it has earned back all it may hold: nothing has been taken from it lately.
    pub(crate) fn whole(&self) -> bool {
        self.left + self.at.elapsed().as_secs_f64() * self.per_second >= self.most
    }

    /// How many it holds now, earned back so far included. For tests, to see what was taken.
    #[cfg(test)]
    pub(crate) fn holds(&self) -> f64 {
        (self.left + self.at.elapsed().as_secs_f64() * self.per_second).min(self.most)
    }

    /// Take one, if there is one.
    pub(crate) fn take(&mut self) -> bool {
        let now = Instant::now();
        self.left = (self.left + now.duration_since(self.at).as_secs_f64() * self.per_second).min(self.most);
        self.at = now;
        if self.left < 1.0 {
            return false;
        }
        self.left -= 1.0;
        true
    }
}

// The lookup point.

/// A record a lookup point holds for a ship.
struct Held {
    record: Vec<u8>,
    issued: u64,
    moon: Option<(u32, [u8; 32])>,
    /// The ship's word, under its signature, that callers should ask to be introduced: only
    /// such a ship is relayed for.
    introduce: bool,
    /// The connection the ship proved it is on when this record was kept, by the number the
    /// point gave the connection, while that connection is open: where the ship attends.
    attends: Option<u64>,
}

/// A connection to a lookup point, while the point has it open: the ships that attend on it,
/// and the introductions waiting to be passed to them over it.
struct Present {
    ships: HashSet<u64>,
    waiting: VecDeque<Push>,
    /// Rung when an introduction is put in `waiting`.
    wake: Arc<Notify>,
    /// The connection's remote address, as the point sees it: where a session's packets go
    /// toward a ship that attends on it.
    from: SocketAddr,
}

/// An introduction waiting to be passed to a ship: the caller's record, when it was taken, and
/// for a relay, the session it is for.
struct Push {
    callee: u64,
    record: Vec<u8>,
    at: Instant,
    session: Option<SessionId>,
}

/// Why an introduction is refused when the ship is not where it can be passed to.
const NOT_ATTENDING: &str = "that ship is not attending this lookup point";

/// What a lookup point holds, by ship number, with its moons counted as they come and go, and
/// the connections it has open, with who attends on each.
#[derive(Default)]
struct Table {
    held: HashMap<u64, Held>,
    moons: usize,
    moons_of: HashMap<u32, usize>,
    swept: Option<Instant>,
    present: HashMap<u64, Present>,
    /// The sessions this point carries packets for, if it relays. Under this same lock, so
    /// that a session is made, and a packet carried, only toward a ship that attends at that
    /// moment.
    sessions: Sessions,
}

impl Table {
    /// A connection under the lookup protocol has opened, from `from`. Records may be kept from
    /// it from now on, and introductions passed over it.
    fn open(&mut self, connection: u64, wake: Arc<Notify>, from: SocketAddr) {
        self.present.insert(connection, Present { ships: HashSet::new(), waiting: VecDeque::new(), wake, from: plain(from) });
    }

    /// A connection has closed. No ship attends on it any more, what was waiting to be passed
    /// over it is dropped, and the sessions made toward a ship that attended on it end. Its
    /// records stay, and are handed out until they run out.
    fn close(&mut self, connection: u64) {
        if let Some(present) = self.present.remove(&connection) {
            for ship in present.ships {
                if let Some(held) = self.held.get_mut(&ship).filter(|held| held.attends == Some(connection)) {
                    held.attends = None;
                }
            }
        }
        self.sessions.callee_gone(connection);
    }

    /// The connection a ship attends on, if its record is still good and the connection open.
    fn attending(&self, ship: u64, now: u64) -> Option<u64> {
        self.held.get(&ship).filter(|held| whereabouts::fresh(held.issued, now)).and_then(|held| held.attends)
    }

    /// Put an introduction in the way of being passed to a ship, over the connection it attends
    /// on, if it attends anywhere and there is room. Weighed with the table held, at `now`.
    fn pass(&mut self, callee: u64, record: Vec<u8>, now: u64) -> Result<(), &'static str> {
        self.push(callee, record, None, now)
    }

    /// The same, for an introduction that carries a session.
    fn push(&mut self, callee: u64, record: Vec<u8>, session: Option<SessionId>, now: u64) -> Result<(), &'static str> {
        let connection = self.attending(callee, now).ok_or(NOT_ATTENDING)?;
        let present = self.present.get_mut(&connection).ok_or(NOT_ATTENDING)?;
        present.waiting.retain(|push| push.at.elapsed() < PUSH_WAIT);
        if present.waiting.iter().filter(|push| push.callee == callee).count() >= MOST_WAITING_EACH {
            return Err("that ship has as many introductions waiting as it may; try again later");
        }
        if present.waiting.len() >= MOST_WAITING {
            return Err("as many introductions are waiting for that ship's connection as may be; try again later");
        }
        present.waiting.push_back(Push { callee, record, at: Instant::now(), session });
        present.wake.notify_one();
        Ok(())
    }

    /// The next introduction to pass over a connection: one that has not waited too long, for a
    /// ship that still attends on this connection, weighed with the table held, at `now`. The
    /// rest are dropped as they are come to.
    fn next_push(&mut self, connection: u64, now: u64) -> Option<Push> {
        loop {
            let push = self.present.get_mut(&connection)?.waiting.pop_front()?;
            if push.at.elapsed() < PUSH_WAIT && self.attending(push.callee, now) == Some(connection) {
                return Some(push);
            }
        }
    }

    /// What is held of a ship, to weigh a new record against: the record held, until it has
    /// run out, and with it the moon's word it carried.
    fn known(&self, ship: u64, now: u64) -> Known {
        self.held.get(&ship).filter(|held| whereabouts::holds_off(held.issued, now)).map_or(Known::default(), |held| Known { issued: Some(held.issued), moon: held.moon })
    }

    fn remove(&mut self, ship: u64) {
        self.sessions.callee_dropped(ship);
        let Some(held) = self.held.remove(&ship) else { return };
        if let Some(present) = held.attends.and_then(|connection| self.present.get_mut(&connection)) {
            present.ships.remove(&ship);
        }
        if ship > u64::from(u32::MAX) {
            self.moons -= 1;
            let parent = ob::moon_parent(ship);
            if let Some(count) = self.moons_of.get_mut(&parent) {
                *count -= 1;
                if *count == 0 {
                    self.moons_of.remove(&parent);
                }
            }
        }
    }

    /// Drop every record that has run out, if that has not just been done. A record dated
    /// ahead of a clock that has stepped back has not run out, and stays.
    fn sweep(&mut self, now: u64) {
        if self.swept.is_some_and(|at| at.elapsed() < SWEEP_AGAIN) {
            return;
        }
        self.swept = Some(Instant::now());
        let gone: Vec<u64> = self.held.iter().filter(|(_, held)| !whereabouts::holds_off(held.issued, now)).map(|(ship, _)| *ship).collect();
        for ship in gone {
            self.remove(ship);
        }
    }

    /// Whether there is room for one more ship, besides those held.
    fn room(&self, ship: u64, bounds: &PointBounds) -> Result<(), &'static str> {
        if self.held.len() >= bounds.records {
            return Err("this lookup point is full; try again later");
        }
        if ship > u64::from(u32::MAX) {
            if self.moons >= bounds.moons {
                return Err("this lookup point has as many moons as it may; try again later");
            }
            if self.moons_of.get(&ob::moon_parent(ship)).copied().unwrap_or(0) >= bounds.moons_each {
                return Err("this lookup point has as many moons of that ship as it may");
            }
        }
        Ok(())
    }

    /// Whether a believed record still stands against what is held of its ship, at `now`, read
    /// with the table held: newer than the record held while that holds older ones off, and
    /// for a moon, at no earlier a revision of its parent's word than held, and at the same
    /// revision only for the same key. Used where a record is kept, and where a caller's
    /// record is passed on in an introduction.
    fn weighs_against_held(&self, believed: &Believed, now: u64) -> Result<(), &'static str> {
        let known = self.known(believed.number, now);
        if known.issued.is_some_and(|seen| believed.issued <= seen) {
            return Err(whereabouts::HELD_NEWER);
        }
        if let (Some((seen, seen_key)), Some((revision, key))) = (known.moon, believed.moon) {
            if revision < seen {
                return Err("a later revision of the moon's key has been seen");
            }
            if revision == seen && key != seen_key {
                return Err("another key has been seen for the moon at this revision");
            }
        }
        Ok(())
    }

    /// Keep a record that has been checked, in the place of the ship's last, with the ship
    /// attending on `connection`, where its presence was checked. Weighed again, with the lock
    /// held and the clock read after the checking (`now`): checking waits on the source of
    /// keys, and meanwhile the record may have run out, another announcement of the same ship
    /// may have been kept, or the connection may have closed.
    fn keep(&mut self, believed: &Believed, record: Vec<u8>, bounds: &PointBounds, now: u64, connection: u64) -> Result<(), &'static str> {
        if !self.present.contains_key(&connection) {
            return Err("the connection the record came on has closed");
        }
        if !whereabouts::fresh(believed.issued, now) {
            return Err("the record ran out, or this clock went back, while it was being checked");
        }
        self.weighs_against_held(believed, now)?;
        if !self.held.contains_key(&believed.number) {
            if self.room(believed.number, bounds).is_err() {
                self.sweep(now);
            }
            self.room(believed.number, bounds)?;
            if believed.number > u64::from(u32::MAX) {
                self.moons += 1;
                *self.moons_of.entry(ob::moon_parent(believed.number)).or_default() += 1;
            }
        }
        let before = self.held.insert(believed.number, Held { record, issued: believed.issued, moon: believed.moon, introduce: believed.introduce, attends: Some(connection) });
        // The newer record names its own connection: the ship no longer attends on the old one,
        // and the sessions made toward it there end.
        if let Some(present) = before.and_then(|held| held.attends).filter(|&old| old != connection).and_then(|old| self.present.get_mut(&old)) {
            present.ships.remove(&believed.number);
        }
        self.sessions.callee_moved(believed.number, connection);
        if let Some(present) = self.present.get_mut(&connection) {
            present.ships.insert(believed.number);
        }
        Ok(())
    }

    /// Make a session for `caller`, at `caller_at`, to call `callee`, named `id`, and put the
    /// caller's record, with the session, in the way of being passed to `callee` over the
    /// connection it attends on. All weighed with the table held, at `now` (by the clock
    /// records are weighed by) and `at` (by the relay's): the ship must attend at this moment,
    /// on an open connection, and its record must ask for introductions; there must be room for
    /// the session and for the push. The session's two addresses are pinned here, from the two
    /// connections, and nothing changes them after.
    #[allow(clippy::too_many_arguments)]
    fn relay(&mut self, callee: u64, caller: u64, record: Vec<u8>, id: SessionId, caller_at: SocketAddr, now: u64, at: Instant) -> Result<(), &'static str> {
        if !self.sessions.relays() {
            return Err(NO_RELAY);
        }
        let connection = self.attending(callee, now).ok_or(NOT_ATTENDING)?;
        if !self.held.get(&callee).is_some_and(|held| held.introduce) {
            return Err("that ship says it can be reached directly, and is not relayed for");
        }
        let callee_at = self.present.get(&connection).ok_or(NOT_ATTENDING)?.from;
        if callee_at == plain(caller_at) {
            return Err("the caller is at the very address of the ship it wants; there is nothing to carry");
        }
        self.sessions.room(&id, callee, caller, at)?;
        // The push first: if there is no room for it, no session is made. Once it is in the
        // way, there is room for the session, weighed in this same hold.
        self.push(callee, record, Some(id), now)?;
        self.sessions.make(id, callee, caller, connection, callee_at, caller_at, at)
    }
}

/// How a lookup point is doing, for whoever runs it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PointStatus {
    /// Records held, moons' included, whether or not they have run out yet.
    pub records: usize,
    pub moons: usize,
    /// Connections open under the lookup protocol.
    pub connections: usize,
    /// Requests in hand: being read, waiting, or being checked. At most `MOST_IN_HAND`.
    pub in_hand: usize,
    /// Questions about ships asked of it, and records announced to it, since it started.
    pub questions: u64,
    pub announced: u64,
    /// Records announced whose place in the rates has been decided, let in or refused.
    pub rated: u64,
    /// Questions about where a connection comes from, since it started.
    pub seen: u64,
    /// Ships whose records are held and who attend on a connection open now.
    pub attending: usize,
    /// Introductions put in the way of being passed on, and those passed over a ship's
    /// connection, since it started.
    pub introduced: u64,
    pub pushed: u64,
    /// Connections refused because every number for one has been given.
    pub unnumbered: u64,
    /// Requests to relay heard (each counted as it arrives, before anything else), and
    /// sessions made, since it started.
    pub relay_asked: u64,
    pub relays_made: u64,
    /// Sessions live now (any that have gone idle are let go of first).
    pub sessions: usize,
    /// Bytes carried, and dropped for each reason, since it started.
    pub relayed: relay::RelayCounts,
    /// Bytes carried for each ship called that has a session now, by number.
    pub carried_for: Vec<(u64, u64)>,
}

/// A runtime's role as a lookup point.
pub(crate) struct Point {
    keys: Arc<dyn Keys>,
    galaxies: Option<HashSet<u8>>,
    bounds: PointBounds,
    /// The key it shows on connections, made when it started. It proves nothing.
    pub(crate) shown: Arc<CertifiedKey>,
    table: Mutex<Table>,
    connections: AtomicUsize,
    /// Questions to Urbit ID that may still be started.
    reading: Arc<Semaphore>,
    /// Places among the requests in hand, point-wide: being read, waiting, or being checked.
    in_hand: Arc<Semaphore>,
    in_all: Mutex<Bucket>,
    /// Introductions that may still be passed on just now, in all, and for each caller.
    introductions: Mutex<Bucket>,
    introducers: Mutex<HashMap<u64, Bucket>>,
    /// The number the next connection under the lookup protocol is given.
    pub(crate) next_connection: AtomicU64,
    /// How far this point's clock is set from the machine's, in milliseconds. Nothing but a
    /// test sets it, to step the clock back or forward; otherwise it is the machine's clock.
    skew: AtomicI64,
    questions: AtomicU64,
    announced: AtomicU64,
    rated: AtomicU64,
    seen: AtomicU64,
    introduced: AtomicU64,
    pushed: AtomicU64,
    unnumbered: AtomicU64,
    /// How much it carries for ships that cannot reach each other directly, if it relays.
    relay: Option<RelayBounds>,
    /// Sessions that may still be made just now, in all, and for each caller.
    relays: Mutex<Bucket>,
    relayers: Mutex<HashMap<u64, Bucket>>,
    /// How far the relay's clock is set ahead of the machine's, in milliseconds. Nothing but a
    /// test sets it.
    relay_skew: AtomicU64,
    relay_asked: AtomicU64,
    relays_made: AtomicU64,
}

/// A place among the connections to a lookup point, given up when the connection ends.
struct PointPlace(Arc<Point>);

impl PointPlace {
    fn take(point: &Arc<Point>) -> Option<PointPlace> {
        if point.connections.fetch_add(1, Ordering::SeqCst) >= point.bounds.connections {
            point.connections.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(PointPlace(point.clone()))
    }
}

impl Drop for PointPlace {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Point {
    pub(crate) fn new(cfg: PointConfig, provider: &CryptoProvider) -> std::io::Result<Point> {
        let seed = crate::random_bytes::<32>()?;
        let shown = net::proof(&ed25519_dalek::SigningKey::from_bytes(&seed), provider).map_err(std::io::Error::other)?;
        Ok(Point {
            keys: cfg.keys,
            galaxies: cfg.galaxies.map(|galaxies| galaxies.into_iter().collect()),
            bounds: cfg.bounds,
            shown,
            table: Mutex::new(Table { sessions: Sessions::new(cfg.relay, Instant::now()), ..Table::default() }),
            connections: AtomicUsize::new(0),
            reading: Arc::new(Semaphore::new(MOST_POINT_READING)),
            in_hand: Arc::new(Semaphore::new(MOST_IN_HAND)),
            in_all: Mutex::new(Bucket::per(cfg.bounds.in_all, cfg.bounds.rate_period)),
            introductions: Mutex::new(Bucket::per(cfg.bounds.introductions, cfg.bounds.rate_period)),
            introducers: Mutex::default(),
            next_connection: AtomicU64::new(0),
            skew: AtomicI64::new(0),
            questions: AtomicU64::new(0),
            announced: AtomicU64::new(0),
            rated: AtomicU64::new(0),
            seen: AtomicU64::new(0),
            introduced: AtomicU64::new(0),
            pushed: AtomicU64::new(0),
            unnumbered: AtomicU64::new(0),
            relay: cfg.relay,
            relays: Mutex::new(Bucket::per(cfg.relay.map_or(1, |relay| relay.made), cfg.bounds.rate_period)),
            relayers: Mutex::default(),
            relay_skew: AtomicU64::new(0),
            relay_asked: AtomicU64::new(0),
            relays_made: AtomicU64::new(0),
        })
    }

    /// Whether this point carries packets for ships that cannot reach each other directly.
    pub(crate) fn relays(&self) -> bool {
        self.relay.is_some()
    }

    pub(crate) fn status(&self) -> PointStatus {
        let mut table = lock(&self.table);
        let at = self.relay_now();
        table.sessions.sweep(at);
        PointStatus {
            records: table.held.len(),
            moons: table.moons,
            connections: self.connections.load(Ordering::SeqCst),
            in_hand: MOST_IN_HAND - self.in_hand.available_permits(),
            questions: self.questions.load(Ordering::SeqCst),
            announced: self.announced.load(Ordering::SeqCst),
            rated: self.rated.load(Ordering::SeqCst),
            seen: self.seen.load(Ordering::SeqCst),
            attending: table.held.values().filter(|held| held.attends.is_some()).count(),
            introduced: self.introduced.load(Ordering::SeqCst),
            pushed: self.pushed.load(Ordering::SeqCst),
            unnumbered: self.unnumbered.load(Ordering::SeqCst),
            relay_asked: self.relay_asked.load(Ordering::SeqCst),
            relays_made: self.relays_made.load(Ordering::SeqCst),
            sessions: table.sessions.len(),
            relayed: table.sessions.counts,
            carried_for: table.sessions.carried_for(),
        }
    }

    /// The relay's clock: the machine's own steady clock, unless a test has set it ahead.
    fn relay_now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.relay_skew.load(Ordering::SeqCst))
    }

    /// Set the relay's clock ahead by `by`, for tests.
    #[cfg(test)]
    pub(crate) fn step_relay(&self, by: Duration) {
        self.relay_skew.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }

    /// A relayed datagram naming `id` has arrived from `from`: carry it on to the other side of
    /// its session with `send`, or drop it, and count which. Weighed, and sent, with the table
    /// held: the session must be live, `from` one of its two pinned addresses, the side it goes
    /// toward still there (the ship called attending on the connection the session was made
    /// toward, judged as passing an introduction judges it; the caller having sent lately), and
    /// the byte allowances must let it. Nothing here waits: `send` never does.
    pub(crate) fn carry(&self, id: &SessionId, from: SocketAddr, datagram: &[u8], send: &mut dyn FnMut(SocketAddr) -> bool) -> Carry {
        let mut table = lock(&self.table);
        let now = self.now();
        let at = self.relay_now();
        let Table { held, sessions, .. } = &mut *table;
        let attends = |ship: u64, connection: u64| held.get(&ship).is_some_and(|held| whereabouts::fresh(held.issued, now) && held.attends == Some(connection));
        sessions.carry(id, from, datagram.len(), at, &|| self.relay_now(), &attends, send)
    }

    /// The sessions live, each with its ship called, caller, and two pinned addresses. For tests.
    #[cfg(test)]
    pub(crate) fn sessions(&self) -> Vec<(SessionId, u64, u64, SocketAddr, SocketAddr)> {
        lock(&self.table).sessions.list()
    }

    /// When the record held for a ship was made, if one is held. For tests.
    #[cfg(test)]
    pub(crate) fn held_issued(&self, ship: u64) -> Option<u64> {
        lock(&self.table).held.get(&ship).map(|held| held.issued)
    }

    /// Count one session made for a caller against its allowance, if it has one left. Only so
    /// many callers are counted; past that, those whose allowance is whole are forgotten.
    fn relayer(&self, caller: u64) -> Result<(), &'static str> {
        let made_each = self.relay.ok_or(NO_RELAY)?.made_each;
        // A moon is counted as its planet.
        let caller = relay::owner(caller);
        let mut relayers = lock(&self.relayers);
        if !relayers.contains_key(&caller) && relayers.len() >= MOST_INTRODUCERS {
            relayers.retain(|_, bucket| !bucket.whole());
            if relayers.len() >= MOST_INTRODUCERS {
                return Err("this lookup point is counting as many callers as it may; try again later");
            }
        }
        let bucket = relayers.entry(caller).or_insert_with(|| Bucket::per(made_each, self.bounds.rate_period));
        if bucket.take() { Ok(()) } else { Err("too many sessions made for that ship just now; try again later") }
    }

    /// Check a caller's record and its presence on the connection the request came on (from
    /// `caller_at`), as an introduction is checked, keep nothing of it, and make a session named
    /// `id` for it to call `callee`, passing its record and the session to `callee` over the
    /// connection `callee` attends on. This waits on the source of keys, so it is for a thread
    /// that may wait. Nothing is made for a caller that has gone (`gone`).
    #[allow(clippy::too_many_arguments)]
    fn relay_one(&self, callee: u64, record: Vec<u8>, presence: &[u8], binding: Option<&Binding>, caller_at: SocketAddr, id: SessionId, gone: &Mutex<bool>) -> Result<(), &'static str> {
        let caller = whereabouts::ship_of(&record).ok_or("not a record")?;
        let (known, now) = {
            let table = lock(&self.table);
            let now = self.now();
            (table.known(caller, now), now)
        };
        if *lock(gone) {
            return Err(GONE);
        }
        let believed = whereabouts::check(&record, &|name: &str| self.key_of(name), known, now)?;
        // Nobody else can name a ship as a caller, or spend its allowance: its presence on
        // this very connection says the caller is here.
        whereabouts::present(&believed, binding.ok_or(NO_BINDING)?, presence)?;
        self.relayer(caller)?;
        // Made only with the table and the mark both held, in that order, with both clocks read
        // then: the ship must attend on an open connection at this moment.
        let mut table = lock(&self.table);
        let gone = lock(gone);
        if *gone {
            return Err(GONE);
        }
        let now = self.now();
        if !whereabouts::fresh(believed.issued, now) {
            return Err("the record ran out, or this clock went back, while it was being checked");
        }
        // What is held of the caller may have moved on while its key was asked about.
        table.weighs_against_held(&believed, now)?;
        let at = self.relay_now();
        table.relay(callee, caller, record, id, caller_at, now, at)?;
        self.relays_made.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// The key Urbit ID lists for a galaxy, star or planet, by name, read from this point's
    /// own source of keys. This waits on that source.
    fn key_of(&self, name: &str) -> Option<[u8; 32]> {
        let number = ob::ship_number(name)?;
        self.keys.listing(number).ok().flatten()?.key
    }

    /// Take the records of an announcement, each with its ship's presence, on the connection
    /// tests announce on (`TESTING`), each checked against Urbit ID and kept if it is
    /// believed. What became of each, in order: empty if it was kept, or why not. This waits
    /// on the source of keys, so it is for a thread that may wait.
    /// (The tests' records are signed with keys the tests can work out again, and their
    /// presence is made here.)
    #[cfg(test)]
    fn take(&self, records: Vec<Vec<u8>>, each: &Mutex<Bucket>) -> Vec<String> {
        let presence = records.iter().map(|record| tests::presence_for(record)).collect();
        self.check_all(self.admit(records, each), presence, Some(TESTING.1), TESTING.0, &Mutex::new(false))
    }

    /// The same, for a caller whose going is marked by `gone`.
    #[cfg(test)]
    fn take_gone(&self, records: Vec<Vec<u8>>, gone: &Mutex<bool>) -> Vec<String> {
        let presence = records.iter().map(|record| tests::presence_for(record)).collect();
        self.check_all(self.admit(records, &Mutex::new(Bucket::new(1 << 20))), presence, Some(TESTING.1), TESTING.0, gone)
    }

    /// Count the records of an announcement against the allowances for checking (a burst,
    /// earned back as time passes), on this connection and in all. Done as the request arrives, before it waits for a thread
    /// to check on: a record past the allowance is refused then, and costs nothing more.
    fn admit(&self, records: Vec<Vec<u8>>, each: &Mutex<Bucket>) -> Vec<Result<Vec<u8>, &'static str>> {
        records
            .into_iter()
            .map(|record| {
                self.announced.fetch_add(1, Ordering::SeqCst);
                let decided = if !lock(each).take() {
                    Err("too many records on this connection just now; try again later")
                } else if !lock(&self.in_all).take() {
                    Err("too many records at this point just now; try again later")
                } else {
                    Ok(record)
                };
                // Counted once the rates have decided, so that whoever watches this count
                // knows the decision has been made.
                self.rated.fetch_add(1, Ordering::SeqCst);
                decided
            })
            .collect()
    }

    /// Check and keep the records that were let in. This waits on the source of keys.
    ///
    /// `gone` is set once whoever asked has gone (its connection closed, or its time ran
    /// out). From then on nothing of the batch is kept, and nothing more is asked of the
    /// source of keys but at most the one question that was already begun, or beginning, as
    /// the caller went; its answer is thrown away.
    ///
    /// Each record comes with its ship's presence on the connection it came on (`connection`,
    /// whose value is `binding`), and is kept only with it, with the ship attending there.
    fn check_all(&self, admitted: Vec<Result<Vec<u8>, &'static str>>, presence: Vec<Vec<u8>>, binding: Option<Binding>, connection: u64, gone: &Mutex<bool>) -> Vec<String> {
        admitted
            .into_iter()
            .zip(presence)
            .map(|(record, presence)| match record.and_then(|record| self.take_one(record, &presence, binding.as_ref(), connection, gone)) {
                Ok(()) => String::new(),
                Err(why) => why.to_string(),
            })
            .collect()
    }

    fn take_one(&self, record: Vec<u8>, presence: &[u8], binding: Option<&Binding>, connection: u64, gone: &Mutex<bool>) -> Result<(), &'static str> {
        let ship = whereabouts::ship_of(&record).ok_or("not a record")?;
        if self.galaxies.as_ref().is_some_and(|galaxies| !galaxies.contains(&whereabouts::galaxy_of(ship))) {
            return Err("this lookup point does not keep records for that ship's galaxy");
        }
        // The clock is read with the table held, after waiting for it, so that what is known
        // is weighed at the time it is read.
        let (known, now) = {
            let table = lock(&self.table);
            let now = self.now();
            (table.known(ship, now), now)
        };
        // Nothing is asked of the source of keys for a caller that has gone. The mark is read
        // here, after the wait for the table and immediately before the question. A question
        // that begins just as the caller goes is the one a batch may still finish; its answer
        // is thrown away below.
        if *lock(gone) {
            return Err(GONE);
        }
        let believed = whereabouts::check(&record, &|name: &str| self.key_of(name), known, now)?;
        // Only the ship can give its record here: its presence on this very connection, by the
        // key that signed the record, is what says so.
        whereabouts::present(&believed, binding.ok_or(NO_BINDING)?, presence)?;
        // The record is kept only with the table and the mark both held, in that order, so
        // that a caller that goes while this waits for the table is seen to have gone, and
        // nothing is kept for it. Neither lock is held across a question to the source of
        // keys. Checking waited on the source of keys, and then on the table: the clock is
        // read again only now, with both held, immediately before keeping, so that a clock
        // that stepped back meanwhile cannot make a newer record held look run out.
        let mut table = lock(&self.table);
        let gone = lock(gone);
        if *gone {
            return Err(GONE);
        }
        let now = self.now();
        table.keep(&believed, record, &self.bounds, now, connection)
    }

    /// Whether a ship attends here now, read with the table held. Only to refuse early: the
    /// introduction itself is weighed again where it is passed on.
    fn attends(&self, ship: u64) -> bool {
        let table = lock(&self.table);
        let now = self.now();
        table.attending(ship, now).is_some()
    }

    /// Count one introduction against a caller's allowance, if it has one left. Only so many
    /// callers are counted; past that, those whose allowance is whole are forgotten.
    fn introducer(&self, caller: u64) -> Result<(), &'static str> {
        let mut introducers = lock(&self.introducers);
        if !introducers.contains_key(&caller) && introducers.len() >= MOST_INTRODUCERS {
            introducers.retain(|_, bucket| !bucket.whole());
            if introducers.len() >= MOST_INTRODUCERS {
                return Err("this lookup point is counting as many callers as it may; try again later");
            }
        }
        let bucket = introducers.entry(caller).or_insert_with(|| Bucket::per(self.bounds.introductions_each, self.bounds.rate_period));
        if bucket.take() { Ok(()) } else { Err("too many introductions from that ship just now; try again later") }
    }

    /// Check a caller's record and its presence on the connection the request came on, as an
    /// announcement would be checked, keep nothing of it, and pass it to `callee` over the
    /// connection `callee` attends on. This waits on the source of keys, so it is for a thread
    /// that may wait. Nothing is passed for a caller that has gone (`gone`).
    fn introduce_one(&self, callee: u64, record: Vec<u8>, presence: &[u8], binding: Option<&Binding>, gone: &Mutex<bool>) -> Result<(), &'static str> {
        let caller = whereabouts::ship_of(&record).ok_or("not a record")?;
        let (known, now) = {
            let table = lock(&self.table);
            let now = self.now();
            (table.known(caller, now), now)
        };
        if *lock(gone) {
            return Err(GONE);
        }
        let believed = whereabouts::check(&record, &|name: &str| self.key_of(name), known, now)?;
        // Nobody else can name a ship as a caller, or spend its allowance: its presence on
        // this very connection says the caller is here.
        whereabouts::present(&believed, binding.ok_or(NO_BINDING)?, presence)?;
        self.introducer(caller)?;
        // Passed on only with the table and the mark both held, in that order, with the clock
        // read then: the ship must attend on an open connection at this moment.
        let mut table = lock(&self.table);
        let gone = lock(gone);
        if *gone {
            return Err(GONE);
        }
        let now = self.now();
        if !whereabouts::fresh(believed.issued, now) {
            return Err("the record ran out, or this clock went back, while it was being checked");
        }
        // What is held of the caller may have moved on while its key was asked about: the
        // record is weighed against it again here, as it would be if it were being kept.
        table.weighs_against_held(&believed, now)?;
        table.pass(callee, record, now)?;
        self.introduced.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// The record held for a ship, if one is and it is still good.
    fn find(&self, ship: u64) -> Option<Vec<u8>> {
        self.questions.fetch_add(1, Ordering::SeqCst);
        let table = lock(&self.table);
        let now = self.now();
        table.held.get(&ship).filter(|held| whereabouts::fresh(held.issued, now)).map(|held| held.record.clone())
    }

    /// This point's clock, in milliseconds since 1970: the machine's, unless a test has set
    /// it off.
    fn now(&self) -> u64 {
        now_ms().saturating_add_signed(self.skew.load(Ordering::SeqCst))
    }
}

/// Why nothing is kept or passed on for a caller whose request has ended.
const GONE: &str = "whoever announced this has gone";

/// Why a presence cannot be checked on a connection whose handshake gave no value for it.
const NO_BINDING: &str = "this connection has nothing a ship's presence could be checked against";

/// The connection number and value the unit tests announce on, as if over a connection open
/// at a point. A test point opens it in its table when it is made.
#[cfg(test)]
const TESTING: (u64, Binding) = (u64::MAX, [9; 32]);

/// One connection under the lookup protocol, as its requests see it.
struct Asker {
    /// Records, and questions, it may still have checked or answered just now.
    each: Arc<Mutex<Bucket>>,
    questions: Arc<Mutex<Bucket>>,
    /// The number the point gave it, and the value both ends work out from its handshake.
    connection: u64,
    binding: Option<Binding>,
    /// Where it comes from, as this point sees it.
    from: SocketAddr,
}

/// While a point has a connection open: it is in the table, and when this is dropped, however
/// the connection's task ends, it is taken out, so that no ship attends on it any more.
struct Attendance(Arc<Point>, u64);

impl Attendance {
    fn open(point: &Arc<Point>, connection: u64, wake: Arc<Notify>, from: SocketAddr) -> Attendance {
        lock(&point.table).open(connection, wake, from);
        Attendance(point.clone(), connection)
    }
}

impl Drop for Attendance {
    fn drop(&mut self) {
        lock(&self.0.table).close(self.1);
    }
}

/// Answer one connection under the lookup protocol until it closes.
///
/// What bounds the work a point does for strangers is the count of requests in hand
/// (`MOST_IN_HAND`, point-wide, taken before a byte of a request is read), the size of a
/// request, and the rates of records, questions and introductions. The stream limit and
/// receive window set here hold only the credit given from now on: what was given at the
/// handshake (the ships' transport allowance) stays usable, since QUIC cannot take credit back.
///
/// The point opens streams of its own on the connection only to pass introductions to ships
/// that attend on it, one at a time, each within `PUSH_LIMIT`.
pub(crate) async fn serve(point: Arc<Point>, connection: Connection, limit: Duration) {
    // Read once, before any lock: where the connection comes from, as this point sees it.
    let from = plain(connection.remote_address());
    // A connection under this protocol through a relay session is nobody's to answer: its
    // address is made up, and nothing may be sent toward it but through the session.
    if relay::is_made_up(&from) {
        connection.close(VarInt::from_u32(1), b"not through a relay");
        return;
    }
    let Some(_place) = PointPlace::take(&point) else {
        connection.close(VarInt::from_u32(4), b"this lookup point has as many connections as it may");
        return;
    };
    // Fewer requests at once, and less room for what they carry, than a ship's connection,
    // from here on.
    connection.set_max_concurrent_bi_streams(VarInt::from_u32(MOST_POINT_STREAMS));
    connection.set_receive_window(VarInt::from_u32((MOST_WHERE_BYTES as u32).saturating_mul(MOST_POINT_STREAMS)));
    // Each connection is given a number never given to another; when there are none left,
    // which takes 2^64 connections, no more are taken.
    let Ok(number) = point.next_connection.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |next| next.checked_add(1)) else {
        point.unnumbered.fetch_add(1, Ordering::SeqCst);
        connection.close(VarInt::from_u32(4), b"this lookup point has numbered as many connections as it can");
        return;
    };
    let wake = Arc::new(Notify::new());
    let _attendance = Attendance::open(&point, number, wake.clone(), from);
    let asker = Arc::new(Asker {
        each: Arc::new(Mutex::new(Bucket::per(point.bounds.per_connection, point.bounds.rate_period))),
        questions: Arc::new(Mutex::new(Bucket::new(MOST_QUESTIONS_EACH))),
        connection: number,
        binding: binding_of(&connection),
        from,
    });
    // The requests of this connection, so that what they leave waiting stops when it closes,
    // and what passes introductions over it.
    let mut answering = tokio::task::JoinSet::new();
    answering.spawn(pass_on(point.clone(), number, connection.clone(), wake));
    while let Ok((mut send, mut receive)) = connection.accept_bi().await {
        while answering.try_join_next().is_some() {}
        // A place among the requests in hand, point-wide, or the request is refused at once
        // and nothing of it is read.
        let Ok(turn) = point.in_hand.clone().try_acquire_owned() else {
            let _ = receive.stop(VarInt::from_u32(4));
            let _ = send.reset(VarInt::from_u32(4));
            continue;
        };
        answering.spawn(answer(point.clone(), asker.clone(), send, receive, limit, turn));
    }
    // The connection has gone. Requests of it still waiting, for a thread to check on or
    // anything else, stop now and give up their places. A question to the source of keys
    // already under way cannot be stopped; it is one of `MOST_POINT_READING` at most, and its
    // answer is thrown away.
    answering.abort_all();
}

/// Pass the introductions waiting for ships that attend on one connection, for as long as it
/// is open. Each is taken off the queue with the table held, and only if its ship still
/// attends on this connection and it has not waited too long: that is the moment it is passed
/// on. Then a stream is opened and the introduction written, all within `PUSH_LIMIT`.
async fn pass_on(point: Arc<Point>, number: u64, connection: Connection, wake: Arc<Notify>) {
    loop {
        wake.notified().await;
        loop {
            let next = {
                let mut table = lock(&point.table);
                let now = point.now();
                table.next_push(number, now)
            };
            let Some(push) = next else { break };
            let message = Introduction { callee: push.callee, record: push.record, session: push.session.map_or(Vec::new(), |id| id.to_vec()) }.encode_to_vec();
            let deadline = tokio::time::Instant::now() + PUSH_LIMIT;
            let Ok(Ok(mut stream)) = tokio::time::timeout_at(deadline, connection.open_uni()).await else { continue };
            match tokio::time::timeout_at(deadline, stream.write_all(&message)).await {
                Ok(Ok(())) => {
                    let _ = stream.finish();
                    point.pushed.fetch_add(1, Ordering::SeqCst);
                }
                _ => {
                    let _ = stream.reset(VarInt::from_u32(3));
                }
            }
        }
    }
}

/// One request to a lookup point. `_turn` is its place among the requests in hand.
async fn answer(point: Arc<Point>, asker: Arc<Asker>, mut send: SendStream, mut receive: RecvStream, limit: Duration, _turn: tokio::sync::OwnedSemaphorePermit) {
    let refused = |why: &str| WhereReply { body: None, refused: why.to_string() };
    let served = tokio::time::timeout(limit, async {
        let Some(bytes) = net::read_whole(&mut receive, MOST_WHERE_BYTES).await else {
            return send_back(&mut send, &refused("the request could not be read, or was too large")).await;
        };
        // Counted before it is decoded: a request can be all empty records, or presences.
        if !net::repeats_within(&bytes, 1, 1, MOST_ANNOUNCED) || !net::repeats_within(&bytes, 1, 2, MOST_ANNOUNCED) {
            return send_back(&mut send, &refused("not a request, or one with too many records")).await;
        }
        let reply = match WhereRequest::decode(&*bytes).map(|request| request.body) {
            Ok(Some(where_request::Body::Announce(Announce { records, presence }))) if presence.len() != records.len() => {
                refused("each record must come with its ship's presence on this connection, and only one")
            }
            Ok(Some(where_request::Body::Announce(Announce { records, presence }))) => {
                // Counted against the rates now, before waiting for anything.
                let admitted = point.admit(records, &asker.each);
                if admitted.iter().all(Result::is_err) {
                    // Nothing to check (no records, or all past the rates): answered now,
                    // without waiting for a thread to check on.
                    let outcomes = admitted.into_iter().map(|refused| refused.err().unwrap_or_default().to_string()).collect();
                    WhereReply { body: Some(where_reply::Body::Announced(Announced { outcomes })), refused: String::new() }
                } else {
                    // Checking waits on the source of keys, so it is done on a thread that may
                    // wait, and only so many at once. When this request ends (its connection
                    // closed, its time ran out, or the checking finished), the mark tells the
                    // thread.
                    let gone = Arc::new(Mutex::new(false));
                    let _going = Going(gone.clone());
                    let Ok(turn) = point.reading.clone().acquire_owned().await else { return };
                    let (checking, binding, connection) = (point.clone(), asker.binding, asker.connection);
                    let taken = tokio::task::spawn_blocking(move || {
                        let outcomes = checking.check_all(admitted, presence, binding, connection, &gone);
                        drop(turn);
                        outcomes
                    });
                    match taken.await {
                        Ok(outcomes) => WhereReply { body: Some(where_reply::Body::Announced(Announced { outcomes })), refused: String::new() },
                        Err(_) => refused("the records could not be checked; try again"),
                    }
                }
            }
            Ok(Some(where_request::Body::Ask(Where { ship }))) => {
                if lock(&asker.questions).take() {
                    let record = point.find(ship).unwrap_or_default();
                    WhereReply { body: Some(where_reply::Body::Found(Found { record })), refused: String::new() }
                } else {
                    refused("too many questions just now; try again later")
                }
            }
            Ok(Some(where_request::Body::Seen(Seen {}))) => {
                if lock(&asker.questions).take() {
                    point.seen.fetch_add(1, Ordering::SeqCst);
                    WhereReply { body: Some(where_reply::Body::Saw(Saw { address: whereabouts::address_bytes(&asker.from) })), refused: String::new() }
                } else {
                    refused("too many questions just now; try again later")
                }
            }
            Ok(Some(where_request::Body::Introduce(Introduce { callee, record, presence }))) => introduce(&point, &asker, callee, record, presence).await,
            Ok(Some(where_request::Body::Relay(Relay { callee, record, presence }))) => relay_for(&point, &asker, callee, record, presence).await,
            _ => refused("not a request this lookup point answers"),
        };
        send_back(&mut send, &reply).await;
    })
    .await;
    if served.is_err() {
        let _ = send.reset(VarInt::from_u32(3));
        let _ = receive.stop(VarInt::from_u32(3));
    }
}

/// A caller asks to be introduced to `callee`. In order: the connection's allowance of
/// questions; refused at once if the ship does not attend here; the record counted against the
/// record rates, the connection's and then the point's; the point's allowance of introductions;
/// then checked on a thread that may wait, as an announcement is, before being passed on. The
/// answer does not wait for the ship.
async fn introduce(point: &Arc<Point>, asker: &Asker, callee: u64, record: Vec<u8>, presence: Vec<u8>) -> WhereReply {
    let refused = |why: &str| WhereReply { body: None, refused: why.to_string() };
    // Cheapest and narrowest first. The connection's own allowance of questions, as for
    // `Where`, before the table is looked at: a stranger's introductions cost the table no
    // more each second than its questions would.
    if !lock(&asker.questions).take() {
        return refused("too many questions just now; try again later");
    }
    // An early reading, only to refuse: passing on weighs it again.
    if !point.attends(callee) {
        return refused(NOT_ATTENDING);
    }
    // The record is counted against the record rates, this connection's first, then the
    // point's; and only then against the point's allowance of introductions.
    let record = match point.admit(vec![record], &asker.each).pop() {
        Some(Ok(record)) => record,
        Some(Err(why)) => return refused(why),
        None => return refused("not a record"),
    };
    if !lock(&point.introductions).take() {
        return refused("too many introductions at this point just now; try again later");
    }
    let gone = Arc::new(Mutex::new(false));
    let _going = Going(gone.clone());
    let Ok(turn) = point.reading.clone().acquire_owned().await else { return refused("this lookup point is stopping") };
    let (checking, binding) = (point.clone(), asker.binding);
    let passed = tokio::task::spawn_blocking(move || {
        let passed = checking.introduce_one(callee, record, &presence, binding.as_ref(), &gone);
        drop(turn);
        passed
    });
    match passed.await {
        Ok(Ok(())) => WhereReply { body: Some(where_reply::Body::Introduced(Introduced {})), refused: String::new() },
        Ok(Err(why)) => refused(why),
        Err(_) => refused("the introduction could not be checked; try again"),
    }
}

/// A caller asks the point to carry its packets to `callee`. In order: refused at once if this
/// point does not relay; the connection's allowance of questions; refused at once if the ship
/// does not attend here; the record counted against the record rates, the connection's and then
/// the point's; the point's allowance of sessions made; then checked on a thread that may wait,
/// as an introduction is, and the session made (the caller's own allowance of sessions charged
/// once its presence is checked) and passed to the ship with the table held. The answer names
/// the session and does not wait for the ship.
async fn relay_for(point: &Arc<Point>, asker: &Asker, callee: u64, record: Vec<u8>, presence: Vec<u8>) -> WhereReply {
    let refused = |why: &str| WhereReply { body: None, refused: why.to_string() };
    point.relay_asked.fetch_add(1, Ordering::SeqCst);
    if !point.relays() {
        return refused(NO_RELAY);
    }
    if !lock(&asker.questions).take() {
        return refused("too many questions just now; try again later");
    }
    // An early reading, only to refuse: making the session weighs it again.
    if !point.attends(callee) {
        return refused(NOT_ATTENDING);
    }
    let record = match point.admit(vec![record], &asker.each).pop() {
        Some(Ok(record)) => record,
        Some(Err(why)) => return refused(why),
        None => return refused("not a record"),
    };
    if !lock(&point.relays).take() {
        return refused("too many sessions made at this point just now; try again later");
    }
    // The name, from the system's randomness, read before any lock is taken.
    let Ok(id) = crate::random_bytes::<16>() else { return refused("this lookup point could not make a session just now; try again") };
    let gone = Arc::new(Mutex::new(false));
    let _going = Going(gone.clone());
    let Ok(turn) = point.reading.clone().acquire_owned().await else { return refused("this lookup point is stopping") };
    let (checking, binding, caller_at) = (point.clone(), asker.binding, asker.from);
    let made = tokio::task::spawn_blocking(move || {
        let made = checking.relay_one(callee, record, &presence, binding.as_ref(), caller_at, id, &gone);
        drop(turn);
        made
    });
    match made.await {
        Ok(Ok(())) => WhereReply { body: Some(where_reply::Body::Relaying(Relaying { session: id.to_vec() })), refused: String::new() },
        Ok(Err(why)) => refused(why),
        Err(_) => refused("the request to relay could not be checked; try again"),
    }
}

/// Sets its mark when dropped. That is when the checking ends for the request that holds
/// it: aborted with its connection, cut off by its time limit, or, on a normal end, as soon
/// as the checking thread has finished and before the reply is written (by then there is
/// nothing left for the mark to stop). It takes only the mark's lock, so if a worker is
/// keeping a record at that moment, with the table and the mark both held, it waits those
/// few instructions.
struct Going(Arc<Mutex<bool>>);

impl Drop for Going {
    fn drop(&mut self) {
        *lock(&self.0) = true;
    }
}

async fn send_back(send: &mut SendStream, reply: &WhereReply) {
    let _ = send.write_all(&reply.encode_to_vec()).await;
    let _ = send.finish();
    // Wait for the caller to take the reply, so closing does not cut it short.
    let _ = send.stopped().await;
}

// Asking lookup points, and announcing to them.

/// What a call to a ship found through a point goes on: the number the record was kept under,
/// its addresses, and whether its ship asks callers to be introduced first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lead {
    pub(crate) kept_as: u64,
    pub(crate) addresses: Vec<SocketAddr>,
    pub(crate) introduce: bool,
}

/// A ship's record, as this runtime last believed it.
struct Cached {
    /// The number this record was kept under, never used for another.
    kept_as: u64,
    issued: u64,
    addresses: Vec<SocketAddr>,
    introduce: bool,
    /// None of its addresses answered as the ship when last tried. The record still holds
    /// older ones off until it runs out, but its addresses are not tried again.
    failed: bool,
}

/// The records this runtime believes, one for each ship it has looked for. Each is the
/// floor for its ship: no record made no later than it is believed until it has run out,
/// whether its addresses answered, failed, or were never tried. So nothing here is dropped
/// for room before it has run out; when every place is taken by a record still good, a
/// record of a new ship is not believed.
struct Floors {
    held: HashMap<String, Cached>,
    most: usize,
    /// The number the next record kept is kept under. Each record is named by its own, so
    /// that two records of one ship made at the same moment are never taken for each other.
    next: u64,
}

impl Floors {
    fn new(most: usize) -> Floors {
        Floors { held: HashMap::new(), most, next: 0 }
    }

    /// When the record held for a ship was made, while it holds older ones off.
    fn floor(&self, ship: &str, now: u64) -> Option<u64> {
        self.held.get(ship).map(|held| held.issued).filter(|&issued| whereabouts::holds_off(issued, now))
    }

    /// The record held for a ship, by the number it was kept under, with its addresses and
    /// whether to be introduced, if it is still good and they have not failed. A record that
    /// has run out is let go of here.
    fn addresses(&mut self, ship: &str, now: u64) -> Option<Lead> {
        match self.held.get(ship) {
            Some(held) if !whereabouts::holds_off(held.issued, now) => {
                self.held.remove(ship);
                None
            }
            Some(held) if !held.failed && whereabouts::fresh(held.issued, now) => Some(Lead { kept_as: held.kept_as, addresses: held.addresses.clone(), introduce: held.introduce }),
            _ => None,
        }
    }

    /// None of the addresses of the record kept under `kept_as` answered as the ship. Only
    /// that record is marked: one that has taken its place meanwhile is left as it is.
    fn failed(&mut self, ship: &str, kept_as: u64) {
        if let Some(held) = self.held.get_mut(ship).filter(|held| held.kept_as == kept_as) {
            held.failed = true;
        }
    }

    /// Keep a record that has been believed, weighed once more, at `now`, read with the
    /// floors held: it must still be good by this clock (no further ahead than may be, and
    /// not run out), and newer than what is held.
    fn keep(&mut self, believed: Believed, now: u64) -> Result<(), &'static str> {
        if !whereabouts::fresh(believed.issued, now) {
            return Err("the record is no longer good by this clock");
        }
        if self.floor(&believed.ship, now).is_some_and(|floor| believed.issued <= floor) {
            return Err(whereabouts::HELD_NEWER);
        }
        if !self.held.contains_key(&believed.ship) && self.held.len() >= self.most {
            // Only what has run out makes way.
            self.held.retain(|_, held| whereabouts::holds_off(held.issued, now));
            if self.held.len() >= self.most {
                return Err("this runtime holds as many ships' records as it may, none of them yet run out; try again later");
            }
        }
        // Each record is named by a number never used before. When there are none left, which
        // takes 2^64 records, no more are kept.
        let kept_as = self.next;
        self.next = self.next.checked_add(1).ok_or("this runtime has named as many records as it can")?;
        self.held.insert(believed.ship, Cached { kept_as, issued: believed.issued, addresses: believed.addresses, introduce: believed.introduce, failed: false });
        Ok(())
    }
}

/// What came of a question to a point (`None` if it ran out of time), once a record it
/// brought that was believed has been kept, with the clock (`now`) read with the floors
/// held: `None` if a record is now held, or why not, in words for whoever made the call.
fn settle(floors: &Mutex<Floors>, asked: Option<Result<Believed, String>>, now: &dyn Fn() -> u64) -> Option<String> {
    match asked {
        None => Some("the lookup point did not answer in time".into()),
        Some(Err(why)) => Some(why),
        Some(Ok(believed)) => {
            // The clock is read with the floors held, after waiting for them.
            let mut floors = lock(floors);
            let now = now();
            floors.keep(believed, now).err().map(|why| format!("the lookup point's record is not believed: {why}"))
        }
    }
}

/// How announcing the ships of one galaxy is going.
#[derive(Default)]
struct Lane {
    busy: bool,
    /// Not before this moment, again.
    next_at: Option<Instant>,
    /// After a failure, how long the wait was. It doubles with each failure, and starts over
    /// after a success.
    delay: Duration,
    /// For each ship whose record the point took, by that record's own outcome: the
    /// addresses it was announced at, and whether callers were asked to be introduced. What a
    /// ship shows of itself when it asks to be introduced, and whether an introduction to it
    /// makes this runtime send anything. A record the point refuses leaves its ship's entry as
    /// it was (the point still holds that ship's last record, if any).
    shown: HashMap<String, (Vec<SocketAddr>, bool)>,
    /// The connection to the galaxy's point the ships were last announced over, and attend on.
    /// It is kept open, and made again if it drops.
    connection: Option<Connection>,
}

/// A runtime's means of finding other ships through lookup points, and of announcing its own.
pub(crate) struct Finder {
    lookup: Lookup,
    endpoint: Endpoint,
    client: quinn::ClientConfig,
    /// For the connection to each galaxy's point that ships are announced over: it sends a
    /// packet every `keep_alive`, and lets the point open a few streams of its own, small ones,
    /// to pass introductions.
    announcing: quinn::ClientConfig,
    /// The address this runtime listens on.
    bound: SocketAddr,
    /// Where introductions points pass to this runtime's ships go, to be weighed, each with the
    /// connection it came on. Only so many wait there; past that they are dropped.
    pushed: Option<tokio::sync::mpsc::Sender<(Vec<u8>, Connection)>>,
    /// The runtime's socket, with its sessions: told which connections to points sessions may
    /// come on, and when each closes.
    relayed: Option<Arc<relay::Relayed>>,
    /// Records (by ship, and the number each was kept under) whose addresses did not answer and
    /// whose ship the relay did reach, newest last: a call on one of them goes straight to the
    /// relay.
    relay_worked: Mutex<VecDeque<(String, u64)>>,
    /// Whether this runtime asks to be introduced to ships whose records ask for it. Nothing
    /// but a test turns it off, to show what happens without.
    pub(crate) introducing: std::sync::atomic::AtomicBool,
    resolver: Arc<dyn Resolve>,
    /// How long one question to a point may take, and how long to wait between tries at
    /// announcing: as for ships.
    limit: Duration,
    retry_delay: Duration,
    max_retry_delay: Duration,
    /// What the resolver said for each galaxy, and when.
    resolved: Mutex<HashMap<u8, (Instant, Result<Vec<SocketAddr>, String>)>>,
    resolving: Arc<Semaphore>,
    /// A connection to each lookup point, by address. Each has a lock of its own, held while
    /// connecting, so that two questions to one point share one connection.
    points: Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<Option<Connection>>>>>,
    /// The same for the connections ships are announced over, which stay open: one to each
    /// point, however many galaxies' ships it takes.
    kept: Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<Option<Connection>>>>>,
    floors: Mutex<Floors>,
    /// When each ship was last asked about.
    asked: Mutex<HashMap<String, Instant>>,
    /// Questions out now, each with the means to wait for its answer. Lock order: this
    /// before `asked`.
    asking: Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<String>>>>,
    lanes: Mutex<HashMap<u8, Lane>>,
    /// When the newest record this runtime has made was made, so that each is newer than the
    /// one before even if the clock steps back.
    last_issued: AtomicU64,
    trouble: Mutex<Option<String>>,
    /// The clock records are weighed by: the machine's. Nothing but a test sets another.
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    /// For tests: what is done with each request to a point made once a connection is in hand.
    #[cfg(test)]
    pub(crate) stand_in: Mutex<Option<StandIn>>,
    /// For tests: the deadline each round of asking a point (`exchange_from`) was given, kept
    /// only while a stand-in is set.
    #[cfg(test)]
    pub(crate) rounds: Mutex<Vec<tokio::time::Instant>>,
}

/// For tests: given a request to a point, made (its record signed, if it carries one) and not
/// yet sent, an answer to take in place of the point's, and then nothing is sent; or nothing,
/// and it is sent as usual. It may wait first, for the test to make something happen between
/// the signing and the sending.
#[cfg(test)]
pub(crate) type StandIn = Arc<dyn Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<WhereReply>> + Send>> + Send + Sync>;

impl Finder {
    pub(crate) fn new(
        lookup: Lookup,
        cfg: &NetConfig,
        endpoint: Endpoint,
        provider: &Arc<CryptoProvider>,
        bound: SocketAddr,
        pushed: Option<tokio::sync::mpsc::Sender<(Vec<u8>, Connection)>>,
        relayed: Option<Arc<relay::Relayed>>,
    ) -> std::io::Result<Finder> {
        // A caller shows a key of its own, made now, which names nobody: the point needs no
        // proof of who is asking, and the ship protocol, on the same port, needs every caller
        // to show some key.
        let seed = crate::random_bytes::<32>()?;
        let shows = net::proof(&ed25519_dalek::SigningKey::from_bytes(&seed), provider).map_err(std::io::Error::other)?;
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(std::io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyPoint { supported: provider.signature_verification_algorithms }))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(shows)));
        tls.alpn_protocols = vec![WHERE_PROTOCOL.to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).map_err(std::io::Error::other)?));
        client.transport_config(Arc::new(net::transport(cfg, 0)?));
        // The connection ships are announced over stays open, a packet going every
        // `keep_alive`, so that a router keeps its way in open; and the point may open up to
        // four streams on it, each to pass one small introduction, with little room for each.
        let mut kept = net::transport(cfg, 0)?;
        kept.keep_alive_interval(Some(lookup.keep_alive));
        kept.max_concurrent_uni_streams(VarInt::from_u32(MOST_PUSHES_OPEN));
        kept.stream_receive_window(VarInt::from_u32(MOST_WHERE_BYTES as u32));
        kept.receive_window(VarInt::from_u32((MOST_WHERE_BYTES as u32) * MOST_PUSHES_OPEN));
        let mut announcing = client.clone();
        announcing.transport_config(Arc::new(kept));
        let resolver = lookup.resolver.clone().unwrap_or_else(|| Arc::new(SystemResolver));
        Ok(Finder {
            lookup,
            endpoint,
            client,
            announcing,
            bound,
            pushed,
            relayed,
            relay_worked: Mutex::default(),
            introducing: std::sync::atomic::AtomicBool::new(true),
            resolver,
            limit: cfg.request_timeout,
            retry_delay: cfg.retry_delay,
            max_retry_delay: cfg.max_retry_delay,
            resolved: Mutex::default(),
            resolving: Arc::new(Semaphore::new(MOST_RESOLVING)),
            points: Mutex::default(),
            kept: Mutex::default(),
            floors: Mutex::new(Floors::new(MOST_FLOORS)),
            asked: Mutex::default(),
            asking: Mutex::default(),
            lanes: Mutex::default(),
            last_issued: AtomicU64::new(0),
            trouble: Mutex::default(),
            clock: Box::new(now_ms),
            #[cfg(test)]
            stand_in: Mutex::new(None),
            #[cfg(test)]
            rounds: Mutex::default(),
        })
    }

    pub(crate) fn trouble(&self) -> Option<String> {
        lock(&self.trouble).clone()
    }

    pub(crate) fn worried(&self, why: String) {
        *lock(&self.trouble) = Some(why);
    }

    /// The addresses of the lookup point for a galaxy, in the order to try them.
    async fn points_for(&self, galaxy: u8, deadline: tokio::time::Instant) -> Result<Vec<SocketAddr>, String> {
        let given = |which: Option<u8>| self.lookup.at.iter().filter(|(of, _)| *of == which).map(|(_, addr)| *addr).collect::<Vec<_>>();
        for which in [Some(galaxy), None] {
            let given = given(which);
            if !given.is_empty() {
                return Ok(given);
            }
        }
        let Some((domain, port)) = &self.lookup.domain else {
            return Err(format!("no lookup point is known for ~{}", galaxy_name(galaxy)));
        };
        if let Some((at, answer)) = lock(&self.resolved).get(&galaxy) {
            let lasts = if answer.is_ok() { self.lookup.resolved_for } else { self.lookup.ask_again };
            if at.elapsed() < lasts {
                return answer.clone();
            }
        }
        let host = format!("{}.{domain}", galaxy_name(galaxy));
        let answer = match self.resolving.clone().try_acquire_owned() {
            Err(_) => Err("too many names are being looked up already".to_string()),
            Ok(turn) => {
                let (resolver, asked, port) = (self.resolver.clone(), host.clone(), *port);
                let resolving = tokio::task::spawn_blocking(move || {
                    let answer = resolver.resolve(&asked, port);
                    drop(turn);
                    answer
                });
                let limit = RESOLVE_LIMIT.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                match tokio::time::timeout(limit, resolving).await {
                    Ok(Ok(Ok(mut found))) => {
                        found.truncate(MOST_POINT_ADDRESSES);
                        if found.is_empty() { Err(format!("{host} has no addresses")) } else { Ok(found) }
                    }
                    Ok(Ok(Err(why))) => Err(why),
                    _ => Err(format!("{host} was not looked up in time")),
                }
            }
        };
        lock(&self.resolved).insert(galaxy, (Instant::now(), answer.clone()));
        answer
    }

    /// The place where the connection to a point is kept.
    fn point_slot(&self, addr: SocketAddr) -> Result<Arc<tokio::sync::Mutex<Option<Connection>>>, String> {
        slot_in(&self.points, addr)
    }

    /// The place where the connection ships are announced over to a point is kept. When there
    /// is no room, connections no lane announces over are let go of first.
    fn kept_slot(&self, addr: SocketAddr) -> Result<Arc<tokio::sync::Mutex<Option<Connection>>>, String> {
        let full = {
            let kept = lock(&self.kept);
            !kept.contains_key(&addr) && kept.len() >= MOST_POINTS
        };
        if full {
            self.retire_unused();
        }
        slot_in(&self.kept, addr)
    }

    /// Let go of the connections ships are announced over that no lane announces over now:
    /// each is closed, which ends the task hearing introductions on it, and its place freed.
    /// One whose slot someone holds (connecting through it) is left. Which lanes use which
    /// connection is read first, and the map is then changed under its own lock; a lane that
    /// takes a connection between the two finds it closed, and its round fails and is tried
    /// again, as for any connection that drops.
    fn retire_unused(&self) {
        let used: HashSet<SocketAddr> = lock(&self.lanes).values().filter_map(|lane| lane.connection.as_ref()).filter(|connection| connection.close_reason().is_none()).map(Connection::remote_address).collect();
        lock(&self.kept).retain(|addr, slot| {
            if used.contains(addr) || Arc::strong_count(slot) > 1 {
                return true;
            }
            match slot.try_lock() {
                Ok(mut held) => {
                    if let Some(connection) = held.take() {
                        connection.close(VarInt::from_u32(2), b"no longer announced over");
                    }
                    false
                }
                Err(_) => true,
            }
        });
    }
}

/// The place in `map` where the connection to the point at `addr` is kept, made if need be.
/// Only so many points are kept: past that, those nothing is using and whose connections have
/// closed are forgotten.
fn slot_in(map: &Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<Option<Connection>>>>>, addr: SocketAddr) -> Result<Arc<tokio::sync::Mutex<Option<Connection>>>, String> {
    let mut points = lock(map);
    if !points.contains_key(&addr) && points.len() >= MOST_POINTS {
        // Forget points nothing is using and whose connections have closed.
        points.retain(|_, kept| Arc::strong_count(kept) > 1 || kept.try_lock().map_or(true, |held| held.as_ref().is_some_and(|c| c.close_reason().is_none())));
        if points.len() >= MOST_POINTS {
            return Err("this runtime is already talking to as many lookup points as it may".into());
        }
    }
    Ok(points.entry(addr).or_default().clone())
}

impl Finder {
    /// Let go of the connection to a point, so the next question makes a new one.
    fn forget_point(&self, addr: SocketAddr) {
        if let Some(kept) = lock(&self.points).remove(&addr) {
            if let Ok(mut held) = kept.try_lock() {
                if let Some(connection) = held.take() {
                    connection.close(VarInt::from_u32(2), b"no answer");
                }
            }
        }
    }

    /// Send one request to the point at one address and read its reply. The request is made
    /// once the connection is in hand, by `make`, since it may have to be bound to it.
    async fn over(&self, addr: SocketAddr, make: &(dyn Fn(&Connection) -> Result<Vec<u8>, String> + Send + Sync)) -> Result<WhereReply, String> {
        // A lookup point is never at an address made up for a relay session: that is never
        // connected to, and counts as this point failing.
        if relay::is_made_up(&addr) {
            return Err(format!("a lookup point cannot be at {addr}, an address made up for relay sessions"));
        }
        let slot = self.point_slot(addr)?;
        let connection = {
            let mut kept = slot.lock().await;
            match kept.as_ref().filter(|connection| connection.close_reason().is_none()) {
                Some(connection) => connection.clone(),
                None => {
                    let connecting = self.endpoint.connect_with(self.client.clone(), addr, POINT_NAME).map_err(|e| e.to_string())?;
                    let connection = connecting.await.map_err(|e| format!("the lookup point at {addr} could not be reached: {e}"))?;
                    *kept = Some(connection.clone());
                    connection
                }
            }
        };
        let request = make(&connection)?;
        #[cfg(test)]
        {
            let stand_in = lock(&self.stand_in).clone();
            if let Some(stand_in) = stand_in {
                if let Some(reply) = stand_in(request.clone()).await {
                    return Ok(reply);
                }
            }
        }
        request_on(&connection, addr, &request).await
    }

    /// Send one request to the lookup point for a galaxy, trying each of its addresses in
    /// turn, all within `deadline`.
    async fn exchange(&self, galaxy: u8, request: WhereRequest, deadline: tokio::time::Instant) -> Result<WhereReply, String> {
        let request = request.encode_to_vec();
        self.exchange_with(galaxy, &|_| Ok(request.clone()), deadline).await
    }

    /// The same, with the request made by `make` once a connection is in hand.
    async fn exchange_with(&self, galaxy: u8, make: &(dyn Fn(&Connection) -> Result<Vec<u8>, String> + Send + Sync), deadline: tokio::time::Instant) -> Result<WhereReply, String> {
        self.exchange_from(galaxy, make, deadline).await.map(|(reply, _)| reply)
    }

    /// The same, with the address of the point that answered.
    async fn exchange_from(&self, galaxy: u8, make: &(dyn Fn(&Connection) -> Result<Vec<u8>, String> + Send + Sync), deadline: tokio::time::Instant) -> Result<(WhereReply, SocketAddr), String> {
        #[cfg(test)]
        if lock(&self.stand_in).is_some() {
            lock(&self.rounds).push(deadline);
        }
        let mut why = format!("no lookup point is known for ~{}", galaxy_name(galaxy));
        for addr in self.points_for(galaxy, deadline).await? {
            match tokio::time::timeout(try_limit(deadline), self.over(addr, make)).await {
                Ok(Ok(reply)) => return Ok((reply, addr)),
                Ok(Err(failed)) => why = failed,
                Err(_) => why = format!("the lookup point at {addr} did not answer in time"),
            }
            self.forget_point(addr);
        }
        Err(why)
    }

    /// The same, for a request that carries a record of one of this runtime's ships, signed by
    /// `make` (to be introduced, or relayed). The ship's own announcer signs records from the
    /// same clock and sends them on other streams, so one signed after `make`'s may reach the
    /// point first, and the point then refuses the request for not being newer. On that refusal
    /// alone, and only if `deadline` has not passed, the point is asked once more, the record
    /// signed afresh (later than any this runtime has signed) with its presence on the connection
    /// it then goes over, within the same `deadline`. Never more than two rounds of asking, each
    /// one `exchange_from` as before (the point's addresses as then listed tried in turn until
    /// one answers, the second round starting again at the first of them): one address, two
    /// requests; a list of N addresses that does not change between the rounds, up to 2N, each
    /// with its own record signed. The second round's answer, of any kind, is the answer.
    async fn exchange_signed(&self, galaxy: u8, make: &(dyn Fn(&Connection) -> Result<Vec<u8>, String> + Send + Sync), deadline: tokio::time::Instant) -> Result<(WhereReply, SocketAddr), String> {
        let first = self.exchange_from(galaxy, make, deadline).await;
        let overtaken = matches!(&first, Ok((WhereReply { refused, body: None }, _)) if refused == whereabouts::HELD_NEWER);
        if !overtaken || tokio::time::Instant::now() >= deadline {
            return first;
        }
        self.exchange_from(galaxy, make, deadline).await
    }

    /// The clock records are weighed by, in milliseconds since 1970.
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The record held for a ship, by the number it was kept under, its addresses, and
    /// whether to be introduced first, if there is one, it is still good, and they have not
    /// failed.
    pub(crate) fn cached(&self, ship: &str) -> Option<Lead> {
        let mut floors = lock(&self.floors);
        let now = self.now();
        floors.addresses(ship, now)
    }

    /// None of the addresses of the record kept under `kept_as` answered as the ship.
    pub(crate) fn failed(&self, ship: &str, kept_as: u64) {
        lock(&self.floors).failed(ship, kept_as);
    }

    /// What is believed of a ship already, to weigh a new record of it against: the record
    /// held here, and for a moon, the latest of its parent's word the directory has taken.
    /// The directory is the one memory of a moon's keys at a ship; nothing of them is kept
    /// here.
    /// The directory is read first; then the clock is read with the floors held, after
    /// waiting for them, and given back with what is known, to weigh the record by. That is
    /// an early reading: whatever is kept on the strength of it is weighed again where it is
    /// kept.
    pub(crate) fn known(&self, ship: &str, directory: &Directory) -> (Known, u64) {
        let moon = directory.moon_seen(ship);
        let floors = lock(&self.floors);
        let now = self.now();
        (Known { issued: floors.floor(ship, now), moon }, now)
    }


    /// Whether a ship may be asked about now, and if so, that it has been.
    fn may_ask(&self, ship: &str) -> bool {
        let mut asked = lock(&self.asked);
        if asked.get(ship).is_some_and(|at| at.elapsed() < self.lookup.ask_again) {
            return false;
        }
        if !asked.contains_key(ship) && asked.len() >= MOST_ASKED_ABOUT {
            asked.retain(|_, at| at.elapsed() < self.lookup.ask_again);
            if asked.len() >= MOST_ASKED_ABOUT {
                return false;
            }
        }
        asked.insert(ship.to_string(), Instant::now());
        true
    }

    /// Ask the lookup point for a ship's galaxy where the ship is, and wait, until `deadline`
    /// at most, for the answer to be checked and kept. The addresses believed then. One
    /// question about a ship is out at a time, and is seen through if the one who asked gives
    /// up. A ship is asked about at most once every `ask_again`, whatever the answer. If a
    /// record whose addresses may be tried is held already (one that took the place of a
    /// record being tried), it is handed back without asking.
    pub(crate) async fn ask(self: &Arc<Self>, directory: &Arc<Directory>, ship: &str, deadline: tokio::time::Instant) -> Result<Lead, NetError> {
        if let Some(found) = self.cached(ship) {
            return Ok(found);
        }
        let mut answered = {
            let mut asking = lock(&self.asking);
            match asking.get(ship) {
                Some(answered) => answered.clone(),
                None => {
                    if asking.len() >= MOST_ASKING {
                        return Err(NetError::Unreachable("as many questions to lookup points are out as may be; try again".into()));
                    }
                    if !self.may_ask(ship) {
                        return Err(NetError::Unreachable(format!("~{ship} was asked about a moment ago, and nowhere is known to reach it")));
                    }
                    let (done, answered) = tokio::sync::watch::channel(None);
                    asking.insert(ship.to_string(), answered.clone());
                    let (finder, directory, ship) = (self.clone(), directory.clone(), ship.to_string());
                    tokio::spawn(async move {
                        let asked = tokio::time::timeout(finder.limit, finder.question(&directory, &ship)).await.ok();
                        // Why no record is held, if none is, goes to whoever is waiting, and
                        // to the runtime's trouble.
                        if let Some(why) = settle(&finder.floors, asked, &|| finder.now()) {
                            finder.worried(format!("~{ship}: {why}"));
                            done.send_replace(Some(why));
                        }
                        lock(&finder.asking).remove(&ship);
                        drop(done);
                    });
                    answered
                }
            }
        };
        // Done when the question ends, however it ends.
        let _ = tokio::time::timeout_at(deadline, answered.changed()).await;
        match self.cached(ship) {
            Some(found) => Ok(found),
            None => {
                let why = answered.borrow().clone().unwrap_or_else(|| "the lookup point for its galaxy said nowhere that reaches it".to_string());
                Err(NetError::Unreachable(format!("~{ship}: {why}")))
            }
        }
    }

    /// Ask the point where a ship is, and check what it says.
    async fn question(&self, directory: &Directory, ship: &str) -> Result<Believed, String> {
        let number = ob::any_number(ship).ok_or("not the name of a ship")?;
        let deadline = tokio::time::Instant::now() + self.limit;
        let request = WhereRequest { body: Some(where_request::Body::Ask(Where { ship: number })) };
        let record = match self.exchange(whereabouts::galaxy_of(number), request, deadline).await?.body {
            Some(where_reply::Body::Found(Found { record })) if record.is_empty() => return Err("the lookup point does not know where it is".into()),
            Some(where_reply::Body::Found(Found { record })) => record,
            _ => return Err("the lookup point's answer made no sense".into()),
        };
        if whereabouts::ship_of(&record) != Some(number) {
            return Err("the lookup point answered with another ship's record".into());
        }
        self.weigh(directory, ship, &record)
    }

    /// Check a record a point gave for a ship, and take a moon's word in it into the
    /// directory. The record is kept after this, by `settle`.
    fn weigh(&self, directory: &Directory, ship: &str, record: &[u8]) -> Result<Believed, String> {
        let (known, now) = self.known(ship, directory);
        let believed = whereabouts::check(record, &|name: &str| directory.key_of(name), known, now).map_err(|why| format!("the lookup point's record is not believed: {why}"))?;
        // A moon's word in a record is taken into the directory in the same step, by the
        // rules it takes any moon's word by, and holds for every connection from now on. If
        // the directory will not take it, the record is not believed. Whether the record is
        // still good is weighed again there, by the clock read with the directory held.
        if let (Some((_, key)), Some(proof)) = (believed.moon, believed.proof) {
            let issued = believed.issued;
            let still_good = || whereabouts::fresh(issued, self.now());
            directory.recorded_word(ship, key, &proof, &still_good).map_err(|why| format!("the lookup point's record is not believed: {why}"))?;
        }
        Ok(believed)
    }

    /// When the next record is made: now, or just after the last, whichever is later.
    fn next_issued(&self) -> u64 {
        next_after(&self.last_issued, now_ms())
    }

    /// Announce this runtime's ships to the lookup points for their galaxies, for as long as
    /// the network runs: each at start, then every `announce_every`, any ship that is new at
    /// once, and all of a galaxy's at once if the connection to its point drops. A point that
    /// is down or refuses is tried again after a wait that doubles. `stated` are the addresses
    /// given by hand; with none, each galaxy's ships are announced at the address its point
    /// sees.
    pub(crate) async fn announce(self: Arc<Self>, runtime: Arc<Runtime>, stated: Vec<SocketAddr>) {
        loop {
            let mut galaxies: HashMap<u8, Vec<String>> = HashMap::new();
            for ship in runtime.held_ships() {
                if let Some(number) = ob::any_number(&ship) {
                    galaxies.entry(whereabouts::galaxy_of(number)).or_default().push(ship);
                }
            }
            for (galaxy, mut ships) in galaxies {
                ships.sort();
                {
                    let mut lanes = lock(&self.lanes);
                    let lane = lanes.entry(galaxy).or_default();
                    let new = ships.iter().any(|ship| !lane.shown.contains_key(ship));
                    // A connection that has dropped is made again, and the ships announced over
                    // the new one: a point keeps a record only with presence on the connection
                    // it came on.
                    let lost = lane.connection.as_ref().is_some_and(|connection| connection.close_reason().is_some());
                    let due = lane.next_at.is_none_or(|at| Instant::now() >= at) || ((new || lost) && lane.delay.is_zero());
                    if lane.busy || !due {
                        continue;
                    }
                    lane.busy = true;
                }
                tokio::spawn(self.clone().announce_galaxy(runtime.clone(), galaxy, ships, stated.clone()));
            }
            tokio::time::sleep(ANNOUNCE_TICK).await;
        }
    }

    /// Announce the ships of one galaxy, and settle when to do so again.
    async fn announce_galaxy(self: Arc<Self>, runtime: Arc<Runtime>, galaxy: u8, ships: Vec<String>, stated: Vec<SocketAddr>) {
        let deadline = tokio::time::Instant::now() + self.limit;
        let why = match self.lane_connection(galaxy, deadline).await {
            Err(failed) => Some(failed),
            Ok(connection) => match self.announce_over(&runtime, galaxy, &ships, &stated, &connection, deadline).await {
                Ok(refused) => refused,
                // The connection did not do what was asked of it: it is let go of, and made
                // again next time.
                Err(failed) => {
                    connection.close(VarInt::from_u32(2), b"no answer");
                    Some(failed)
                }
            },
        };
        let mut lanes = lock(&self.lanes);
        let lane = lanes.entry(galaxy).or_default();
        lane.busy = false;
        match why {
            None => {
                lane.next_at = Some(Instant::now() + self.lookup.announce_every);
                lane.delay = Duration::ZERO;
            }
            Some(why) => {
                lane.delay = if lane.delay.is_zero() { self.retry_delay } else { (lane.delay * 2).min(self.max_retry_delay) };
                lane.next_at = Some(Instant::now() + lane.delay);
                drop(lanes);
                self.worried(why);
            }
        }
    }

    /// The connection a galaxy's ships are announced over: the one kept, if it is still open,
    /// or a new one to the galaxy's point, trying each of its addresses in turn. The
    /// introductions the point passes over a new one are heard from then on.
    async fn lane_connection(self: &Arc<Self>, galaxy: u8, deadline: tokio::time::Instant) -> Result<Connection, String> {
        let addresses = self.points_for(galaxy, deadline).await?;
        // The lane's connection, if it is still open and still to one of the point's
        // addresses, is the one to use.
        let current = lock(&self.lanes).get(&galaxy).and_then(|lane| lane.connection.clone());
        if let Some(current) = current.filter(|current| current.close_reason().is_none() && addresses.contains(&current.remote_address())) {
            return Ok(current);
        }
        // Otherwise the point has moved, or the connection dropped. The lane gives up its old
        // connection first, and it is let go of unless another lane announces over it, so
        // that its place is free before one is taken for the new.
        if lock(&self.lanes).entry(galaxy).or_default().connection.take().is_some() {
            self.retire_unused();
        }
        let mut why = format!("no lookup point is known for ~{}", galaxy_name(galaxy));
        for addr in addresses {
            match tokio::time::timeout(try_limit(deadline), self.kept_connection(addr)).await {
                Ok(Ok(connection)) => {
                    lock(&self.lanes).entry(galaxy).or_default().connection = Some(connection.clone());
                    // Read again after the lane took it: another lane may have let it go just
                    // before.
                    if connection.close_reason().is_some() {
                        why = format!("the connection to the lookup point at {addr} was let go of; trying again");
                        continue;
                    }
                    return Ok(connection);
                }
                Ok(Err(failed)) => why = failed,
                Err(_) => why = format!("the lookup point at {addr} did not answer in time"),
            }
        }
        Err(why)
    }

    /// The connection ships are announced over to the point at `addr`: the one kept, if it is
    /// still open, or a new one, whose introductions are heard from then on.
    async fn kept_connection(self: &Arc<Self>, addr: SocketAddr) -> Result<Connection, String> {
        if relay::is_made_up(&addr) {
            return Err(format!("a lookup point cannot be at {addr}, an address made up for relay sessions"));
        }
        let slot = self.kept_slot(addr)?;
        let mut kept = slot.lock().await;
        if let Some(connection) = kept.as_ref().filter(|connection| connection.close_reason().is_none()) {
            return Ok(connection.clone());
        }
        let connecting = self.endpoint.connect_with(self.announcing.clone(), addr, POINT_NAME).map_err(|e| format!("the lookup point at {addr} could not be reached: {e}"))?;
        let connection = connecting.await.map_err(|e| format!("the lookup point at {addr} could not be reached: {e}"))?;
        *kept = Some(connection.clone());
        tokio::spawn(self.clone().hear(connection.clone()));
        Ok(connection)
    }

    /// Announce ships over the connection to their galaxy's point, each record with the
    /// ship's presence on that connection: at the addresses stated by hand, or with none, at
    /// the address that point sees this connection come from. Each ship whose record the point
    /// took is recorded in the lane at once, chunk by chunk as the answers come, with what it
    /// was shown as (the addresses, and whether callers are asked to be introduced), whatever
    /// becomes of the other ships or of later chunks. Why some record was not kept, if one was
    /// not; an error if the connection did not do what was asked of it.
    async fn announce_over(&self, runtime: &Runtime, galaxy: u8, ships: &[String], stated: &[SocketAddr], connection: &Connection, deadline: tokio::time::Instant) -> Result<Option<String>, String> {
        let point = connection.remote_address();
        let binding = binding_of(connection).ok_or_else(|| NO_BINDING.to_string())?;
        // Stated by hand wins, and then what the point says is not asked. Otherwise what the
        // point sees is announced, alone, and callers are asked to be introduced unless it is
        // the very address this runtime listens on.
        let (addresses, introduce) = if stated.is_empty() {
            let seen = self.seen(connection, deadline).await?;
            (vec![seen], seen != self.bound || self.lookup.behind_router)
        } else {
            (stated.to_vec(), self.lookup.behind_router)
        };
        let mut why = None;
        for some in ships.chunks(MOST_ANNOUNCED) {
            let (mut named, mut records, mut presence) = (Vec::new(), Vec::new(), Vec::new());
            for ship in some {
                let (Ok(key), Some(number)) = (runtime.signing_key(ship), ob::any_number(ship)) else { continue };
                let issued = self.next_issued();
                match whereabouts::sign_flagged(ship, &addresses, issued, introduce, &key, runtime.moon_proof(ship)) {
                    Ok(record) => {
                        named.push(ship);
                        records.push(record);
                        presence.push(whereabouts::presence(number, issued, &binding, &key));
                    }
                    Err(failed) => why = Some(format!("~{ship}: no record could be made: {failed}")),
                }
            }
            let count = records.len();
            let request = WhereRequest { body: Some(where_request::Body::Announce(Announce { records, presence })) }.encode_to_vec();
            let reply = tokio::time::timeout_at(deadline, request_on(connection, point, &request)).await.map_err(|_| format!("the lookup point at {point} did not answer in time"))??;
            match reply {
                WhereReply { body: Some(where_reply::Body::Announced(Announced { outcomes })), .. } if outcomes.len() == count => {
                    let mut lanes = lock(&self.lanes);
                    let lane = lanes.entry(galaxy).or_default();
                    for (ship, outcome) in named.iter().zip(&outcomes) {
                        if outcome.is_empty() {
                            lane.shown.insert(ship.to_string(), (addresses.clone(), introduce));
                        } else {
                            why = Some(format!("~{ship}: the lookup point did not keep its record: {}", outcome.chars().take(200).collect::<String>()));
                        }
                    }
                }
                WhereReply { refused, body: None } => why = Some(format!("the lookup point at {point} refused: {}", refused.chars().take(200).collect::<String>())),
                _ => return Err(format!("the answer of the lookup point at {point} made no sense")),
            }
        }
        Ok(why)
    }

    /// Where the point sees a connection come from, if it says, and if that is an address a
    /// record may carry.
    async fn seen(&self, connection: &Connection, deadline: tokio::time::Instant) -> Result<SocketAddr, String> {
        let point = connection.remote_address();
        let request = WhereRequest { body: Some(where_request::Body::Seen(Seen {})) }.encode_to_vec();
        let reply = tokio::time::timeout_at(deadline, request_on(connection, point, &request)).await.map_err(|_| format!("the lookup point at {point} did not say in time where it sees this runtime"))??;
        let address = match reply {
            WhereReply { body: Some(where_reply::Body::Saw(Saw { address })), .. } => address,
            WhereReply { refused, body: None } if !refused.is_empty() => {
                return Err(format!("the lookup point at {point} would not say where it sees this runtime: {}", refused.chars().take(200).collect::<String>()));
            }
            _ => return Err(format!("the lookup point at {point} said nothing that makes sense about where it sees this runtime")),
        };
        let seen = whereabouts::address_read(&address).map(plain).ok_or_else(|| format!("the lookup point at {point} said this runtime is at something that is not an address"))?;
        whereabouts::fits(&[seen]).map_err(|why| format!("the lookup point at {point} sees this runtime at {seen}, which cannot be announced: {why}"))?;
        Ok(seen)
    }

    /// Hear the introductions the point passes over a connection ships are announced on, for
    /// as long as it is open, and hand each on to be weighed. Each is read within
    /// `PUSH_READ_LIMIT`, and no more than `MOST_PUSH_BYTES` of it; what will not fit where
    /// introductions wait to be weighed is dropped.
    ///
    /// Sessions may be pushed on the connection while this hears it, and those pushed on it end
    /// when it closes.
    async fn hear(self: Arc<Self>, connection: Connection) {
        if let Some(relayed) = &self.relayed {
            relayed.heard_on(connection.stable_id());
        }
        while let Ok(mut receive) = connection.accept_uni().await {
            match tokio::time::timeout(PUSH_READ_LIMIT, net::read_whole(&mut receive, MOST_PUSH_BYTES)).await {
                Ok(Some(introduction)) => {
                    if let Some(pushed) = &self.pushed {
                        let _ = pushed.try_send((introduction, connection.clone()));
                    }
                }
                _ => {
                    let _ = receive.stop(VarInt::from_u32(4));
                }
            }
        }
        if let Some(relayed) = &self.relayed {
            relayed.no_longer_heard_on(connection.stable_id());
        }
    }

    /// What a ship of this runtime was last announced as, if the point for its galaxy took it:
    /// its addresses, and whether callers are asked to be introduced.
    pub(crate) fn shown_as(&self, ship: &str) -> Option<(Vec<SocketAddr>, bool)> {
        let galaxy = whereabouts::galaxy_of(ob::any_number(ship)?);
        lock(&self.lanes).get(&galaxy)?.shown.get(ship).cloned()
    }

    /// Whether a ship of this runtime was last announced asking callers to be introduced. Only
    /// for such a ship does an introduction make this runtime send anything.
    pub(crate) fn introduces(&self, ship: &str) -> bool {
        self.shown_as(ship).is_some_and(|(_, introduce)| introduce)
    }

    /// Close the connections this runtime's ships are announced over, as if each had dropped.
    /// For tests.
    #[cfg(test)]
    pub(crate) fn drop_lanes(&self) {
        for lane in lock(&self.lanes).values() {
            if let Some(connection) = &lane.connection {
                connection.close(VarInt::from_u32(0), b"dropped by the test");
            }
        }
    }

    /// Announce one ship of this runtime to the point for its galaxy now, as a round of
    /// announcing does: a record signed now, over the connection ships are announced on. Why
    /// the point did not keep it, if it did not. For tests.
    #[cfg(test)]
    pub(crate) async fn announce_now(self: &Arc<Self>, runtime: &Runtime, ship: &str) -> Result<Option<String>, String> {
        let galaxy = whereabouts::galaxy_of(ob::any_number(ship).ok_or("not the name of a ship")?);
        let deadline = tokio::time::Instant::now() + self.limit;
        let connection = self.lane_connection(galaxy, deadline).await?;
        self.announce_over(runtime, galaxy, &[ship.to_string()], &[], &connection, deadline).await
    }

    /// Whether a call from `from` may be relayed: this runtime has the socket for it, and `from`
    /// has a record of its own to show (it is announced, and its point took its record).
    pub(crate) fn may_relay(&self, from: &str) -> bool {
        self.relayed.is_some() && self.shown_as(from).is_some()
    }

    /// Whether the record of `ship` kept under `kept_as` is one whose addresses did not answer
    /// and through whose point's relay the ship was reached.
    pub(crate) fn relay_worked(&self, ship: &str, kept_as: u64) -> bool {
        lock(&self.relay_worked).iter().any(|(held, number)| held == ship && *number == kept_as)
    }

    /// Whether any record of `ship` is remembered as one the relay worked for. For tests.
    #[cfg(test)]
    pub(crate) fn remembers_relay(&self, ship: &str) -> bool {
        lock(&self.relay_worked).iter().any(|(held, _)| held == ship)
    }

    /// Remember that the record of `ship` kept under `kept_as` was reached through the relay
    /// after its addresses did not answer, so that the next call on it goes straight there.
    pub(crate) fn relay_did(&self, ship: &str, kept_as: u64) {
        let mut worked = lock(&self.relay_worked);
        worked.retain(|(held, _)| held != ship);
        if worked.len() >= MOST_RELAY_REMEMBERED {
            worked.pop_front();
        }
        worked.push_back((ship.to_string(), kept_as));
    }

    /// Forget that the relay was needed for `ship`: the direct way has worked again.
    pub(crate) fn direct_again(&self, ship: &str) {
        lock(&self.relay_worked).retain(|(held, _)| held != ship);
    }

    /// Ask the point for `to`'s galaxy to carry `from`'s packets to `to`: `from`'s record, signed
    /// now at the addresses it is announced at, with its presence on the connection the request
    /// goes over. The address of the point that answered (which is what carries the session)
    /// and the session's name; or why not, in words that say whether the point does not relay,
    /// refused for a limit, or could not be asked. Overtaken by `from`'s own announcement, it
    /// asks once more (`exchange_signed`).
    pub(crate) async fn relay(&self, runtime: &Runtime, from: &str, to: &str, deadline: tokio::time::Instant) -> Result<(SocketAddr, SessionId), String> {
        let (Some(number), Some(callee)) = (ob::any_number(from), ob::any_number(to)) else { return Err("not the name of a ship".into()) };
        let no_record = "this ship announces no record of its own, so it cannot be relayed";
        self.shown_as(from).ok_or(no_record)?;
        let key = runtime.signing_key(from).map_err(|e| e.to_string())?;
        let proof = runtime.moon_proof(from);
        // Made once the connection is in hand, which may have waited: what the ship is
        // announced as is read then.
        let make = |connection: &Connection| -> Result<Vec<u8>, String> {
            let (addresses, introduce) = self.shown_as(from).ok_or(no_record)?;
            let binding = binding_of(connection).ok_or_else(|| NO_BINDING.to_string())?;
            let issued = self.next_issued();
            let record = whereabouts::sign_flagged(from, &addresses, issued, introduce, &key, proof)?;
            let presence = whereabouts::presence(number, issued, &binding, &key);
            Ok(WhereRequest { body: Some(where_request::Body::Relay(Relay { callee, record, presence })) }.encode_to_vec())
        };
        match self.exchange_signed(whereabouts::galaxy_of(callee), &make, deadline).await {
            Ok((WhereReply { body: Some(where_reply::Body::Relaying(Relaying { session })), .. }, point)) => {
                let id = SessionId::try_from(session.as_slice()).map_err(|_| "its point answered with something that names no session".to_string())?;
                Ok((point, id))
            }
            Ok((WhereReply { refused, body: None }, _)) if refused == NO_RELAY => Err("its point does not relay".into()),
            Ok((WhereReply { refused, body: None }, _)) => Err(format!("its point refused to relay: {}", refused.chars().take(200).collect::<String>())),
            Ok(_) => Err("its point's answer made no sense".into()),
            Err(why) => Err(format!("its point could not be asked to relay: {why}")),
        }
    }

    /// Ask the point for `to`'s galaxy to introduce `from` to it: `from`'s record, signed now at
    /// the addresses it is announced at, with its presence on the connection the request goes
    /// over. Fails if `from` announces no record of its own, or the point refuses. Overtaken by
    /// `from`'s own announcement, it asks once more (`exchange_signed`).
    pub(crate) async fn introduce(&self, runtime: &Runtime, from: &str, to: &str, deadline: tokio::time::Instant) -> Result<(), String> {
        if !self.introducing.load(Ordering::SeqCst) {
            return Err("this runtime does not ask for introductions".into());
        }
        let (Some(number), Some(callee)) = (ob::any_number(from), ob::any_number(to)) else { return Err("not the name of a ship".into()) };
        let no_record = "this ship announces no record of its own, so it cannot be introduced";
        self.shown_as(from).ok_or(no_record)?;
        let key = runtime.signing_key(from).map_err(|e| e.to_string())?;
        let proof = runtime.moon_proof(from);
        // Made once the connection is in hand, which may have waited: what the ship is
        // announced as is read then.
        let make = |connection: &Connection| -> Result<Vec<u8>, String> {
            let (addresses, introduce) = self.shown_as(from).ok_or(no_record)?;
            let binding = binding_of(connection).ok_or_else(|| NO_BINDING.to_string())?;
            let issued = self.next_issued();
            let record = whereabouts::sign_flagged(from, &addresses, issued, introduce, &key, proof)?;
            let presence = whereabouts::presence(number, issued, &binding, &key);
            Ok(WhereRequest { body: Some(where_request::Body::Introduce(Introduce { callee, record, presence })) }.encode_to_vec())
        };
        match self.exchange_signed(whereabouts::galaxy_of(callee), &make, deadline).await?.0 {
            WhereReply { body: Some(where_reply::Body::Introduced(Introduced {})), .. } => Ok(()),
            WhereReply { refused, .. } => Err(format!("the lookup point did not introduce ~{from} to ~{to}: {}", refused.chars().take(200).collect::<String>())),
        }
    }
}

/// Send one request on a connection to a lookup point (at `addr`), and read its reply.
async fn request_on(connection: &Connection, addr: SocketAddr, request: &[u8]) -> Result<WhereReply, String> {
    let lost = |e: &dyn fmt::Display| format!("the lookup point at {addr} was lost: {e}");
    let (mut send, mut receive) = connection.open_bi().await.map_err(|e| lost(&e))?;
    send.write_all(request).await.map_err(|e| lost(&e))?;
    send.finish().map_err(|e| lost(&e))?;
    let answer = net::read_whole(&mut receive, MOST_WHERE_BYTES).await.ok_or_else(|| format!("the answer of the lookup point at {addr} could not be read, or was too large"))?;
    WhereReply::decode(&*answer).map_err(|_| format!("the answer of the lookup point at {addr} made no sense"))
}

/// The time to put on a record made at `now`, given when the last was made (`last`, which
/// it moves on): `now`, or just after the last if the clock has not moved past it. So each
/// record a runtime makes is dated later than the one before, even if two are made in one
/// millisecond or the clock steps back. That does not mean a point takes it: after this
/// clock is set back, its date may be too far ahead for the point. It never goes round.
fn next_after(last: &AtomicU64, now: u64) -> u64 {
    let before = last.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |last| Some(now.max(last.saturating_add(1)))).unwrap_or(0);
    now.max(before.saturating_add(1))
}

/// For a caller of a lookup point: any key will do, so long as the point proves it holds it.
/// Nothing a point says about who anyone is, or about what a record says, is taken on its word,
/// so who it is does not matter.
#[derive(Debug)]
struct AnyPoint {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AnyPoint {
    fn verify_server_cert(&self, shown: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        net::unwrapped(shown.as_ref()).ok_or_else(|| net::refuse("the lookup point did not show a key"))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(net::refuse("only TLS 1.3 is spoken"))
    }

    fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        net::signed_with(shown, message, signed, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::azimuth::Listing;
    use ed25519_dalek::SigningKey;

    /// A stand-in for Urbit ID in which every galaxy, star and planet has the key made from
    /// its number.
    struct Everyone;

    impl Keys for Everyone {
        fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
            Ok(Some(Listing { key: Some(key_of(u64::from(ship)).verifying_key().to_bytes()), revision: 1, continuity: 0, sponsor: None }))
        }
    }

    fn key_of(ship: u64) -> SigningKey {
        let mut seed = [7u8; 32];
        seed[..8].copy_from_slice(&ship.to_be_bytes());
        SigningKey::from_bytes(&seed)
    }

    fn name(ship: u64) -> String {
        ob::any_name(ship).trim_start_matches('~').to_string()
    }

    fn point(bounds: PointBounds, galaxies: Option<Vec<u8>>) -> Point {
        testing(Point::new(PointConfig { keys: Arc::new(Everyone), galaxies, bounds, relay: None }, &rustls::crypto::ring::default_provider()).unwrap())
    }

    /// A point with the connection the tests announce on open.
    fn testing(point: Point) -> Point {
        lock(&point.table).open(TESTING.0, Arc::new(Notify::new()), test_from());
        point
    }

    /// The presence, on the connection the tests announce on, of the ship whose record this
    /// is, signed with the key the tests made it with: a planet's from its number, a moon's
    /// from its number or the revision of its parent's word. Nothing for what is no record.
    pub(super) fn presence_for(record: &[u8]) -> Vec<u8> {
        let Ok(read) = ship_proto::Whereabouts::decode(record) else { return Vec::new() };
        let candidates = [key_of(read.ship), SigningKey::from_bytes(&[(read.ship >> 32) as u8; 32]), SigningKey::from_bytes(&[read.proof.as_ref().map_or(0, |proof| proof.revision as u8).wrapping_add(60); 32])];
        let signer = if read.moon_key.is_empty() { Some(&candidates[0]) } else { candidates[1..].iter().find(|key| key.verifying_key().to_bytes().as_slice() == read.moon_key.as_slice()) };
        signer.map_or(Vec::new(), |key| whereabouts::presence(read.ship, read.issued, &TESTING.1, key))
    }

    fn record(ship: u64, issued: u64) -> Vec<u8> {
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        whereabouts::sign(&name(ship), &[addr], issued, &key_of(ship), None).unwrap()
    }

    /// A moon's record, its parent having vouched for its key.
    fn moon_record(moon: u64, issued: u64) -> Vec<u8> {
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        let key = SigningKey::from_bytes(&[(moon >> 32) as u8; 32]);
        let proof = crate::moon::vouch(&key_of(u64::from(ob::moon_parent(moon))), moon, 1, &key.verifying_key().to_bytes());
        whereabouts::sign(&name(moon), &[addr], issued, &key, Some(proof)).unwrap()
    }

    /// Where the tests' connections to a point come from.
    fn test_from() -> SocketAddr {
        "198.51.100.1:4433".parse().unwrap()
    }

    fn plenty() -> Mutex<Bucket> {
        Mutex::new(Bucket::new(1 << 20))
    }

    const PLANET: u64 = 0x1234_0100;

    #[test]
    fn a_point_keeps_what_it_believes_and_hands_it_out_while_it_is_good() {
        let point = point(PointBounds::default(), None);
        let now = now_ms();
        assert_eq!(point.take(vec![record(PLANET, now)], &plenty()), vec![String::new()]);
        assert_eq!(point.find(PLANET), Some(record(PLANET, now)));
        assert_eq!(point.find(PLANET + 1), None);
        // An older record, the same one again, a forged one, and rubbish are not kept, and
        // the one held stays.
        let forged = whereabouts::sign(&name(PLANET), &["203.0.113.9:1".parse().unwrap()], now + 5, &key_of(PLANET + 1), None).unwrap();
        let outcomes = point.take(vec![record(PLANET, now - 1), record(PLANET, now), forged, vec![1, 2, 3]], &plenty());
        assert!(outcomes.iter().all(|outcome| !outcome.is_empty()), "{outcomes:?}");
        assert_eq!(point.find(PLANET), Some(record(PLANET, now)));
        // A newer one takes its place.
        assert_eq!(point.take(vec![record(PLANET, now + 1)], &plenty()), vec![String::new()]);
        assert_eq!(point.find(PLANET), Some(record(PLANET, now + 1)));
        // One that has run out is not handed out, though it is still held until swept.
        let point = self::point(PointBounds::default(), None);
        let old = now - whereabouts::LIFETIME_MS + 300;
        assert_eq!(point.take(vec![record(PLANET, old)], &plenty()), vec![String::new()]);
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(point.find(PLANET), None);
        assert_eq!(point.status().questions, 1);
    }

    #[test]
    fn a_point_keeps_only_the_galaxies_it_serves() {
        let point = point(PointBounds::default(), Some(vec![0]));
        let now = now_ms();
        // ~zod's ships have zero at the bottom of their numbers; this planet is ~nec's.
        assert_eq!(point.take(vec![record(PLANET, now)], &plenty()), vec![String::new()]);
        assert_eq!(point.take(vec![record(PLANET + 1, now)], &plenty()), vec!["this lookup point does not keep records for that ship's galaxy".to_string()]);
    }

    #[test]
    fn a_full_point_refuses_new_ships_and_keeps_the_ones_it_has() {
        let bounds = PointBounds { records: 3, moons: 2, moons_each: 1, ..PointBounds::default() };
        let point = point(bounds, None);
        let now = now_ms();
        let ships: Vec<u64> = (0..3).map(|n| PLANET + (n << 16)).collect();
        assert!(point.take(ships.iter().map(|&ship| record(ship, now)).collect(), &plenty()).iter().all(String::is_empty));
        // A fourth ship is refused, and says why. The three are still there, and each still
        // takes a newer record of itself.
        let fourth = PLANET + (9 << 16);
        assert_eq!(point.take(vec![record(fourth, now)], &plenty()), vec!["this lookup point is full; try again later".to_string()]);
        assert!(ships.iter().all(|&ship| point.find(ship) == Some(record(ship, now))));
        assert_eq!(point.take(vec![record(ships[0], now + 1)], &plenty()), vec![String::new()]);
        assert_eq!(point.status().records, 3);

        // Records that have run out make way, but only those.
        let point = self::point(bounds, None);
        let old = now - whereabouts::LIFETIME_MS + 300;
        point.take(vec![record(ships[0], old), record(ships[1], now), record(ships[2], now)], &plenty());
        assert!(!point.take(vec![record(fourth, now)], &plenty())[0].is_empty());
        std::thread::sleep(SWEEP_AGAIN + Duration::from_millis(100));
        assert_eq!(point.take(vec![record(fourth, now)], &plenty()), vec![String::new()]);
        assert_eq!(point.find(ships[0]), None);
        assert!(point.find(ships[1]).is_some() && point.find(fourth).is_some());

        // Moons: one of each ship, two in all.
        let point = self::point(bounds, None);
        let moon = |nth: u64, parent: u64| nth << 32 | parent;
        assert_eq!(point.take(vec![moon_record(moon(1, ships[0]), now)], &plenty()), vec![String::new()]);
        assert_eq!(point.take(vec![moon_record(moon(2, ships[0]), now)], &plenty()), vec!["this lookup point has as many moons of that ship as it may".to_string()]);
        assert_eq!(point.take(vec![moon_record(moon(1, ships[1]), now)], &plenty()), vec![String::new()]);
        assert_eq!(point.take(vec![moon_record(moon(1, ships[2]), now)], &plenty()), vec!["this lookup point has as many moons as it may; try again later".to_string()]);
        // The moons held still take newer records, and a planet still has room.
        assert_eq!(point.take(vec![moon_record(moon(1, ships[0]), now + 1)], &plenty()), vec![String::new()]);
        assert_eq!(point.take(vec![record(ships[2], now)], &plenty()), vec![String::new()]);
        assert_eq!(point.status().moons, 2);
    }

    #[test]
    fn a_point_checks_only_so_many_records_a_second() {
        let point = point(PointBounds { per_connection: 3, in_all: 5, ..PointBounds::default() }, None);
        let now = now_ms();
        let (one, two) = (Mutex::new(Bucket::new(3)), Mutex::new(Bucket::new(3)));
        let ships: Vec<u64> = (0..8).map(|n| PLANET + (n << 16)).collect();
        let outcomes = point.take(ships[..4].iter().map(|&ship| record(ship, now)).collect(), &one);
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_empty()).count(), 3);
        assert_eq!(outcomes[3], "too many records on this connection just now; try again later");
        // A second connection has its own allowance, and both share the point's.
        let outcomes = point.take(ships[4..].iter().map(|&ship| record(ship, now)).collect(), &two);
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_empty()).count(), 2);
        // What was refused for want of time left everything as it was; a second later
        // there is room again.
        assert_eq!(point.status().records, 5);
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(point.take(vec![record(ships[3], now)], &one), vec![String::new()]);
    }

    /// The key Urbit ID lists for a ship, by name, as `Everyone` has it.
    fn listed(name: &str) -> Option<[u8; 32]> {
        Everyone.listing(ob::ship_number(name)?).ok()??.key
    }

    #[test]
    fn a_record_still_good_is_never_dropped_for_room_and_holds_older_ones_off() {
        let now = now_ms();
        let (ship, other, third) = (PLANET, PLANET + (1 << 16), PLANET + (2 << 16));
        let checked = |record: &[u8], floors: &Floors| {
            let known = Known { issued: floors.floor(&name(whereabouts::ship_of(record).unwrap()), now), moon: None };
            whereabouts::check(record, &listed, known, now)
        };
        // Whether the newer record's addresses failed or worked, it is kept through any
        // amount of pressure for room, and the older record is never believed while it is.
        for failed in [true, false] {
            let mut floors = Floors::new(2);
            // The newer record is the oldest held, so that nothing could prefer to drop
            // another in its place.
            let (newer, older) = (record(ship, now - 500), record(ship, now - 1000));
            floors.keep(checked(&newer, &floors).unwrap(), now).unwrap();
            if failed {
                let kept_as = floors.addresses(&name(ship), now).unwrap().kept_as;
                floors.failed(&name(ship), kept_as);
                assert_eq!(floors.addresses(&name(ship), now), None);
            }
            floors.keep(checked(&record(other, now), &floors).unwrap(), now).unwrap();
            assert_eq!(
                floors.keep(checked(&record(third, now), &floors).unwrap(), now),
                Err("this runtime holds as many ships' records as it may, none of them yet run out; try again later")
            );
            assert_eq!(checked(&older, &floors), Err("a record of the ship as new or newer is already held"));
            assert_eq!(floors.floor(&name(ship), now), Some(now - 500));
            // Even weighed again at keeping, the older one does not take the newer's place.
            let believed = whereabouts::check(&older, &listed, Known::default(), now).unwrap();
            assert!(floors.keep(believed, now).is_err());
        }
        // Records that have run out make way, and only those.
        let mut floors = Floors::new(2);
        let old = now - whereabouts::LIFETIME_MS + 100;
        floors.keep(whereabouts::check(&record(ship, old), &listed, Known::default(), now).unwrap(), now).unwrap();
        floors.keep(whereabouts::check(&record(other, now), &listed, Known::default(), now).unwrap(), now).unwrap();
        let later = now + 200;
        assert!(floors.keep(whereabouts::check(&record(third, now), &listed, Known::default(), now).unwrap(), later).is_ok());
        assert_eq!(floors.floor(&name(ship), later), None);
        assert_eq!(floors.floor(&name(other), later), Some(now));
    }

    #[test]
    fn a_point_never_lets_a_clock_that_stepped_back_put_an_older_record_in() {
        let now = now_ms();
        let believed = |ship: u64, issued: u64| whereabouts::check(&record(ship, issued), &listed, Known::default(), issued).unwrap();
        // A record taken when the clock was ten minutes later than it now says.
        let ahead = now + whereabouts::LIFETIME_MS;
        let bounds = PointBounds { records: 1, ..PointBounds::default() };
        let mut table = Table::default();
        table.open(TESTING.0, Arc::new(Notify::new()), test_from());
        table.keep(&believed(PLANET, ahead), record(PLANET, ahead), &bounds, ahead, TESTING.0).unwrap();
        // An older record, good by the clock as it is now, does not take its place.
        assert_eq!(table.keep(&believed(PLANET, now), record(PLANET, now), &bounds, now, TESTING.0), Err("a record of the ship as new or newer is already held"));
        // And when the table is full, sweeping does not take the record dated ahead for one
        // that has run out.
        let other = PLANET + (1 << 16);
        assert_eq!(table.keep(&believed(other, now), record(other, now), &bounds, now, TESTING.0), Err("this lookup point is full; try again later"));
        assert_eq!(table.known(PLANET, now).issued, Some(ahead));
    }

    fn settle_now(floors: &Mutex<Floors>, asked: Option<Result<Believed, String>>) -> Option<String> {
        settle(floors, asked, &now_ms)
    }

    #[test]
    fn why_a_record_was_not_kept_is_said_in_words() {
        let now = now_ms();
        let floors = Mutex::new(Floors::new(1));
        let believed = |ship: u64| whereabouts::check(&record(ship, now), &listed, Known::default(), now).unwrap();
        assert_eq!(settle_now(&floors, Some(Ok(believed(PLANET)))), None);
        // The map is full of records still good: the call is told so.
        let why = settle_now(&floors, Some(Ok(believed(PLANET + (1 << 16))))).unwrap();
        assert!(why.contains("as many ships' records as it may"), "{why}");
        assert_eq!(settle_now(&floors, Some(Err("the lookup point does not know where it is".into()))).as_deref(), Some("the lookup point does not know where it is"));
        assert_eq!(settle_now(&floors, None).as_deref(), Some("the lookup point did not answer in time"));
    }

    /// `Everyone`, but every question waits until let go, and says how far it has got: asked,
    /// then answered.
    #[derive(Default)]
    struct Gate {
        asked: AtomicUsize,
        open: std::sync::atomic::AtomicBool,
        answered: std::sync::atomic::AtomicBool,
    }

    impl Keys for Gate {
        fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            while !self.open.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            let listing = Everyone.listing(ship);
            self.answered.store(true, Ordering::SeqCst);
            listing
        }
    }

    fn gated_point(gate: &Arc<Gate>) -> Arc<Point> {
        Arc::new(testing(Point::new(PointConfig { keys: gate.clone(), galaxies: None, bounds: PointBounds::default(), relay: None }, &rustls::crypto::ring::default_provider()).unwrap()))
    }

    /// Wait, briefly, for something another thread does.
    fn until(holds: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !holds() {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn nothing_is_kept_for_a_caller_that_goes_while_its_record_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        let point = gated_point(&gate);
        let gone = Arc::new(Mutex::new(false));
        let worker = {
            let (point, gone) = (point.clone(), gone.clone());
            std::thread::spawn(move || point.take_gone(vec![record(PLANET, now_ms())], &gone))
        };
        // The worker's question is out. The table is held, and the question answered: the
        // worker now goes on to keep the record, and waits for the table.
        until(|| gate.asked.load(Ordering::SeqCst) == 1);
        let table = lock(&point.table);
        gate.open.store(true, Ordering::SeqCst);
        until(|| gate.answered.load(Ordering::SeqCst));
        // The few instructions from the answer to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        // The caller goes while the worker waits. Then the table is let go.
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), vec!["whoever announced this has gone".to_string()]);
        assert_eq!(point.status().records, 0);
    }

    #[test]
    fn nothing_is_asked_for_a_caller_that_goes_while_its_record_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        gate.open.store(true, Ordering::SeqCst);
        let point = gated_point(&gate);
        let gone = Arc::new(Mutex::new(false));
        // The table is held before the worker starts, so it waits at its first look at the
        // table, before any question.
        let table = lock(&point.table);
        let worker = {
            let (point, gone) = (point.clone(), gone.clone());
            std::thread::spawn(move || point.take_gone(vec![record(PLANET, now_ms())], &gone))
        };
        // The worker's few instructions up to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), vec!["whoever announced this has gone".to_string()]);
        assert_eq!(gate.asked.load(Ordering::SeqCst), 0, "the source of keys was asked for a caller that had gone");
        assert_eq!(point.status().records, 0);
    }

    /// A moon's record at a revision of its keys, its parent having vouched for that key.
    fn moon_word_record(moon: u64, revision: u32, issued: u64) -> Vec<u8> {
        let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        let key = SigningKey::from_bytes(&[revision as u8 + 60; 32]);
        let proof = crate::moon::vouch(&key_of(u64::from(ob::moon_parent(moon))), moon, revision, &key.verifying_key().to_bytes());
        whereabouts::sign(&name(moon), &[addr], issued, &key, Some(proof)).unwrap()
    }

    #[test]
    fn a_clock_that_steps_back_while_a_record_waits_to_be_kept_cannot_undo_a_later_word() {
        let gate = Arc::new(Gate::default());
        let point = gated_point(&gate);
        let moon = 1u64 << 32 | PLANET;
        let start = now_ms();
        // Worker A has a genuine record of the moon at revision one, made now. Its question
        // to the source of keys is held, then the table is held, then the question answered:
        // A goes on to keep the record, and waits for the table.
        let first = moon_word_record(moon, 1, start);
        let worker = {
            let point = point.clone();
            std::thread::spawn(move || point.take(vec![first], &plenty()))
        };
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        let mut table = lock(&point.table);
        gate.open.store(true, Ordering::SeqCst);
        until(|| gate.answered.load(Ordering::SeqCst));
        // The few instructions from the answer to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        // The clock steps back a minute. A genuine record at revision two, made just over ten
        // minutes before A's, so still good by the clock as it now is, is kept meanwhile.
        point.skew.store(-60_000, Ordering::SeqCst);
        let second = moon_word_record(moon, 2, start - whereabouts::LIFETIME_MS - 1000);
        let believed = whereabouts::check(&second, &listed, Known::default(), point.now()).unwrap();
        table.keep(&believed, second.clone(), &PointBounds::default(), point.now(), TESTING.0).unwrap();
        drop(table);
        // A weighs its record by the clock as it is when it keeps it: revision two is held,
        // and revision one does not take its place.
        assert_eq!(worker.join().unwrap(), vec!["a later revision of the moon's key has been seen".to_string()]);
        assert_eq!(point.find(moon), Some(second));
    }

    #[test]
    fn what_is_known_of_a_ship_is_weighed_by_the_clock_read_after_waiting_for_the_table() {
        let point = point(PointBounds::default(), None);
        let point = Arc::new(point);
        let start = now_ms();
        // The table is held before worker A starts, so A waits at its first look at it, with
        // a record made just over ten minutes ago.
        let first = record(PLANET, start - whereabouts::LIFETIME_MS - 2000);
        let mut table = lock(&point.table);
        let worker = {
            let point = point.clone();
            std::thread::spawn(move || point.take(vec![first], &plenty()))
        };
        // The few instructions up to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        // The clock steps back a minute, and a newer record of the ship is kept meanwhile.
        point.skew.store(-60_000, Ordering::SeqCst);
        let second = record(PLANET, start - whereabouts::LIFETIME_MS - 1000);
        let believed = whereabouts::check(&second, &listed, Known::default(), point.now()).unwrap();
        table.keep(&believed, second.clone(), &PointBounds::default(), point.now(), TESTING.0).unwrap();
        drop(table);
        // A weighs its record by the clock read with the table held: its record is good by
        // that clock, and the newer one held keeps it off. (By a clock read before the wait,
        // A's record would have looked run out.)
        assert_eq!(worker.join().unwrap(), vec!["a record of the ship as new or newer is already held".to_string()]);
        assert_eq!(point.find(PLANET), Some(second));
    }

    #[test]
    fn only_the_record_that_was_tried_is_marked_failed() {
        let now = now_ms();
        let mut floors = Floors::new(4);
        let first = whereabouts::check(&record(PLANET, now - 1000), &listed, Known::default(), now).unwrap();
        floors.keep(first, now).unwrap();
        let tried = floors.addresses(&name(PLANET), now).unwrap().kept_as;
        // While R1's addresses are being tried, R2 takes its place. R1 then fails: R2 is left
        // as it is, and its addresses are handed out.
        let second = whereabouts::check(&record(PLANET, now), &listed, Known::default(), now).unwrap();
        floors.keep(second, now).unwrap();
        floors.failed(&name(PLANET), tried);
        let newer = floors.addresses(&name(PLANET), now).unwrap().kept_as;
        assert_ne!(newer, tried);
        // R2 failing is marked.
        floors.failed(&name(PLANET), newer);
        assert_eq!(floors.addresses(&name(PLANET), now), None);

        // Two records of one ship made at the same moment are not taken for each other. R1 is
        // handed out; the clock jumps past its life, and it is let go of; the clock comes
        // back, and another record with the same time, at another address, is kept. R1
        // failing does not mark it.
        let mut floors = Floors::new(4);
        let issued = now - 1000;
        floors.keep(whereabouts::check(&record(PLANET, issued), &listed, Known::default(), now).unwrap(), now).unwrap();
        let tried = floors.addresses(&name(PLANET), now).unwrap().kept_as;
        assert_eq!(floors.addresses(&name(PLANET), issued + whereabouts::LIFETIME_MS), None);
        let elsewhere: SocketAddr = "198.51.100.9:4433".parse().unwrap();
        let other = whereabouts::sign(&name(PLANET), &[elsewhere], issued, &key_of(PLANET), None).unwrap();
        floors.keep(whereabouts::check(&other, &listed, Known::default(), now).unwrap(), now).unwrap();
        floors.failed(&name(PLANET), tried);
        assert_eq!(floors.addresses(&name(PLANET), now).map(|lead| lead.addresses), Some(vec![elsewhere]));

        // When the numbers run out, no more records are kept, and none is named twice.
        let mut floors = Floors::new(4);
        floors.next = u64::MAX;
        let refused = floors.keep(whereabouts::check(&record(PLANET, now), &listed, Known::default(), now).unwrap(), now);
        assert_eq!(refused, Err("this runtime has named as many records as it can"));
        assert_eq!(floors.addresses(&name(PLANET), now), None);
    }

    #[test]
    fn a_record_kept_must_be_good_by_the_clock_read_where_it_is_kept() {
        let now = now_ms();
        let mut floors = Floors::new(4);
        // Believed by one reading, kept by another taken with the floors held: a clock that
        // stepped back makes it too far ahead, one that stepped forward makes it run out.
        let ahead = whereabouts::check(&record(PLANET, now + whereabouts::MOST_AHEAD_MS), &listed, Known::default(), now).unwrap();
        assert_eq!(floors.keep(ahead, now - 60_000), Err("the record is no longer good by this clock"));
        let old = whereabouts::check(&record(PLANET, now - whereabouts::LIFETIME_MS + 1000), &listed, Known::default(), now).unwrap();
        assert_eq!(floors.keep(old, now + 2000), Err("the record is no longer good by this clock"));
        assert_eq!(floors.floor(&name(PLANET), now), None);
    }

    /// A finder whose clock reads `first` the first time it is read, and `first` moved by
    /// `step` every time after: as if the clock stepped between the first reading and any
    /// later one.
    fn stepping_finder(first: u64, step: i64) -> (tokio::runtime::Runtime, Finder) {
        finder_with(Lookup::default(), first, step)
    }

    /// The same, with these lookup settings.
    fn finder_with(lookup: Lookup, first: u64, step: i64) -> (tokio::runtime::Runtime, Finder) {
        let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let endpoint = {
            let _entered = tokio.enter();
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut finder = Finder::new(lookup, &NetConfig::default(), endpoint, &provider, "127.0.0.1:9".parse().unwrap(), None, None).unwrap();
        let readings = AtomicUsize::new(0);
        finder.clock = Box::new(move || if readings.fetch_add(1, Ordering::SeqCst) == 0 { first } else { first.saturating_add_signed(step) });
        (tokio, finder)
    }

    /// A directory that lists the planet the tests' moons belong to, with its key.
    fn listing_directory() -> Arc<Directory> {
        let directory = Directory::new();
        directory.set(&name(PLANET), key_of(PLANET).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
        directory
    }

    #[test]
    fn a_clock_that_moves_while_a_record_is_checked_keeps_nothing_of_it() {
        let moon = 1u64 << 32 | PLANET;
        let start = now_ms();
        // Back a minute, and forward past the record's life: in each case the record was
        // good by the first reading and is not by the one taken where it would be kept.
        for (issued, step) in [(start + whereabouts::MOST_AHEAD_MS, -60_000), (start - whereabouts::LIFETIME_MS + 1000, 5000)] {
            // A moon's record: its word is not taken into the directory.
            let (_tokio, finder) = stepping_finder(start, step);
            let directory = listing_directory();
            let why = finder.weigh(&directory, &name(moon), &moon_word_record(moon, 2, issued)).unwrap_err();
            assert!(why.contains("no longer good"), "{why}");
            assert_eq!(directory.moon_seen(&name(moon)), None);
            assert_eq!(lock(&finder.floors).floor(&name(moon), start), None);
            // A planet's record: believed by the first reading, it is not kept.
            let (_tokio, finder) = stepping_finder(start, step);
            let believed = finder.weigh(&directory, &name(PLANET), &record(PLANET, issued));
            assert!(believed.is_ok());
            let why = settle(&finder.floors, believed.ok().map(Ok), &|| finder.now()).unwrap();
            assert!(why.contains("no longer good"), "{why}");
            assert_eq!(lock(&finder.floors).floor(&name(PLANET), start), None);
        }
    }

    /// `Everyone`, but the first question it is asked takes this long to answer.
    struct SlowOnce(std::sync::atomic::AtomicBool, Duration);

    impl Keys for SlowOnce {
        fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
            if self.0.swap(false, Ordering::SeqCst) {
                std::thread::sleep(self.1);
            }
            Everyone.listing(ship)
        }
    }

    fn slow_point(delay: Duration) -> Arc<Point> {
        let keys = Arc::new(SlowOnce(std::sync::atomic::AtomicBool::new(true), delay));
        Arc::new(testing(Point::new(PointConfig { keys, galaxies: None, bounds: PointBounds::default(), relay: None }, &rustls::crypto::ring::default_provider()).unwrap()))
    }

    #[test]
    fn a_record_checked_slowly_is_weighed_again_with_the_clock_as_it_is_then() {
        // R1 waits on a slow answer about its key. Meanwhile R2, made later and dated as far
        // ahead as may be, is taken. When R1's answer comes, R2 is held and is newer: R1 is
        // refused, however far ahead of the clock R1 was first weighed against R2 is.
        let point = slow_point(Duration::from_millis(600));
        let first = record(PLANET, now_ms() - 1000);
        let waiting = {
            let point = point.clone();
            std::thread::spawn(move || point.take(vec![first], &plenty()))
        };
        std::thread::sleep(Duration::from_millis(300));
        let second = record(PLANET, now_ms() + whereabouts::MOST_AHEAD_MS - 50);
        assert_eq!(point.take(vec![second.clone()], &plenty()), vec![String::new()]);
        let outcome = waiting.join().unwrap();
        assert_eq!(outcome, vec!["a record of the ship as new or newer is already held".to_string()]);
        assert_eq!(point.find(PLANET), Some(second));

        // A record that runs out while its key is being asked about is not kept.
        let point = slow_point(Duration::from_millis(600));
        let outcome = point.take(vec![record(PLANET, now_ms() - whereabouts::LIFETIME_MS + 300)], &plenty());
        assert_eq!(outcome, vec!["the record ran out, or this clock went back, while it was being checked".to_string()]);
        assert_eq!(point.status().records, 0);
    }

    #[test]
    fn each_record_made_is_newer_than_the_last() {
        let last = AtomicU64::new(0);
        assert_eq!(next_after(&last, 1000), 1000);
        // In the same millisecond, and with the clock stepped back: still later each time.
        assert_eq!(next_after(&last, 1000), 1001);
        assert_eq!(next_after(&last, 500), 1002);
        assert_eq!(next_after(&last, 5000), 5000);
        // At the end of the range it stays there rather than going round.
        let end = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_after(&end, 0), u64::MAX);
        assert_eq!(next_after(&end, 0), u64::MAX);
    }

    #[test]
    fn a_ship_attends_on_the_connection_its_newest_record_came_on_and_nowhere_once_it_closes() {
        let now = now_ms();
        let believed = |issued: u64| whereabouts::check(&record(PLANET, issued), &listed, Known::default(), now).unwrap();
        let bounds = PointBounds::default();
        let mut table = Table::default();
        let (first, second) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        table.open(1, first.clone(), test_from());
        table.open(2, second.clone(), test_from());
        // Kept from connection one: the ship attends there, and an introduction waits there.
        table.keep(&believed(now - 10), record(PLANET, now - 10), &bounds, now, 1).unwrap();
        assert_eq!(table.attending(PLANET, now), Some(1));
        table.pass(PLANET, vec![1], now).unwrap();
        // A newer record from connection two moves the ship: what waited on one is not passed
        // there, and introductions go to two.
        table.keep(&believed(now), record(PLANET, now), &bounds, now, 2).unwrap();
        assert_eq!(table.attending(PLANET, now), Some(2));
        assert!(table.next_push(1, now).is_none());
        table.pass(PLANET, vec![2], now).unwrap();
        assert_eq!(table.next_push(2, now).map(|push| push.record), Some(vec![2]));
        // An older record from one does not move it back.
        assert!(table.keep(&believed(now - 5), record(PLANET, now - 5), &bounds, now, 1).is_err());
        // Two closes: the ship attends nowhere, nothing waits, nothing is passed, and nothing is
        // kept from the closed connection. The record is still handed out.
        table.pass(PLANET, vec![3], now).unwrap();
        table.close(2);
        assert_eq!(table.attending(PLANET, now), None);
        assert!(table.next_push(2, now).is_none());
        assert_eq!(table.pass(PLANET, vec![4], now), Err(NOT_ATTENDING));
        assert_eq!(table.keep(&believed(now + 5), record(PLANET, now + 5), &bounds, now, 2), Err("the connection the record came on has closed"));
        assert!(table.held.contains_key(&PLANET));
        // A record that has run out: the ship attends nowhere, whatever its connection.
        table.keep(&believed(now + 5), record(PLANET, now + 5), &bounds, now, 1).unwrap();
        assert_eq!(table.attending(PLANET, now + 5 + whereabouts::LIFETIME_MS), None);
        // And when a record is dropped, its connection no longer counts it.
        table.remove(PLANET);
        assert!(table.present[&1].ships.is_empty());
    }

    #[test]
    fn an_introduction_whose_record_runs_out_while_it_is_checked_is_not_passed_on() {
        let gate = Arc::new(Gate::default());
        let point = gated_point(&gate);
        let start = now_ms();
        // The callee attends on the tests' connection, with a record dated as far ahead as may
        // be, so that it is still good eleven minutes on.
        let callee = PLANET + (1 << 16);
        {
            let mut table = lock(&point.table);
            let believed = whereabouts::check(&record(callee, start + whereabouts::MOST_AHEAD_MS), &listed, Known::default(), start).unwrap();
            table.keep(&believed, record(callee, start + whereabouts::MOST_AHEAD_MS), &PointBounds::default(), start, TESTING.0).unwrap();
        }
        // The caller's record is good now, with half a minute left. Its key question is held,
        // then the table, then the question answered: the worker waits for the table to pass
        // the introduction on. The clock steps on a minute meanwhile.
        let caller = record(PLANET, start - whereabouts::LIFETIME_MS + 30_000);
        let presence = tests::presence_for(&caller);
        let worker = {
            let point = point.clone();
            std::thread::spawn(move || point.introduce_one(callee, caller, &presence, Some(&TESTING.1), &Mutex::new(false)))
        };
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        let table = lock(&point.table);
        gate.open.store(true, Ordering::SeqCst);
        until(|| gate.answered.load(Ordering::SeqCst));
        // The few instructions from the answer to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        point.skew.store(60_000, Ordering::SeqCst);
        drop(table);
        assert_eq!(worker.join().unwrap(), Err("the record ran out, or this clock went back, while it was being checked"));
        assert!(lock(&point.table).next_push(TESTING.0, point.now()).is_none());
    }

    /// A point with a ship attending on the tests' connection, whose record is good now; and a
    /// caller's record with its presence there.
    fn introducing(gate: &Arc<Gate>) -> (Arc<Point>, u64, Vec<u8>, Vec<u8>) {
        let point = gated_point(gate);
        let now = now_ms();
        let callee = PLANET + (1 << 16);
        let believed = whereabouts::check(&record(callee, now), &listed, Known::default(), now).unwrap();
        lock(&point.table).keep(&believed, record(callee, now), &PointBounds::default(), now, TESTING.0).unwrap();
        let caller = record(PLANET, now);
        let presence = tests::presence_for(&caller);
        (point, callee, caller, presence)
    }

    #[test]
    fn nothing_is_passed_on_for_a_caller_that_goes_while_its_introduction_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        let (point, callee, caller, presence) = introducing(&gate);
        let gone = Arc::new(Mutex::new(false));
        let worker = {
            let (point, gone) = (point.clone(), gone.clone());
            std::thread::spawn(move || point.introduce_one(callee, caller, &presence, Some(&TESTING.1), &gone))
        };
        // The worker's question is out. The table is held, and the question answered: the
        // worker goes on to pass the introduction on, and waits for the table.
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        let table = lock(&point.table);
        gate.open.store(true, Ordering::SeqCst);
        until(|| gate.answered.load(Ordering::SeqCst));
        // The few instructions from the answer to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), Err(GONE));
        assert!(lock(&point.table).next_push(TESTING.0, point.now()).is_none());
        assert_eq!(point.status().introduced, 0);
    }

    #[test]
    fn nothing_is_asked_for_a_caller_that_goes_while_its_introduction_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        gate.open.store(true, Ordering::SeqCst);
        let (point, callee, caller, presence) = introducing(&gate);
        let asked = gate.asked.load(Ordering::SeqCst);
        let gone = Arc::new(Mutex::new(false));
        // The table is held before the worker starts, so it waits at its first look at it.
        let table = lock(&point.table);
        let worker = {
            let (point, gone) = (point.clone(), gone.clone());
            std::thread::spawn(move || point.introduce_one(callee, caller, &presence, Some(&TESTING.1), &gone))
        };
        // The worker's few instructions up to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), Err(GONE));
        assert_eq!(gate.asked.load(Ordering::SeqCst), asked, "the source of keys was asked for a caller that had gone");
    }

    #[test]
    fn an_introduction_is_weighed_again_against_the_callers_history_where_it_is_passed_on() {
        // The reviewer's interleaving. An introduction of A (R1) to B waits on A's key. An
        // announcement of A's newer R2 completes, and then one moving B from connection one to
        // connection two. The introduction resumes: R1 is now older than what is held of A, so
        // it is refused, and nothing waits for either connection.
        let gate = Arc::new(Gate::default());
        let point = gated_point(&gate);
        let now = now_ms();
        let callee = PLANET + (1 << 16);
        let keep = |table: &mut Table, ship: u64, issued: u64, connection: u64| {
            let believed = whereabouts::check(&record(ship, issued), &listed, Known::default(), now).unwrap();
            table.keep(&believed, record(ship, issued), &PointBounds::default(), now, connection).unwrap();
        };
        {
            let mut table = lock(&point.table);
            table.open(1, Arc::new(Notify::new()), test_from());
            table.open(2, Arc::new(Notify::new()), test_from());
            keep(&mut table, callee, now - 100, 1);
        }
        let first = record(PLANET, now - 50);
        let presence = tests::presence_for(&first);
        let worker = {
            let point = point.clone();
            std::thread::spawn(move || point.introduce_one(callee, first, &presence, Some(&TESTING.1), &Mutex::new(false)))
        };
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        {
            let mut table = lock(&point.table);
            keep(&mut table, PLANET, now - 10, TESTING.0);
            keep(&mut table, callee, now - 5, 2);
        }
        gate.open.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Err("a record of the ship as new or newer is already held"));
        let mut table = lock(&point.table);
        assert!(table.next_push(1, now).is_none() && table.next_push(2, now).is_none());
    }

    #[test]
    fn an_introduction_that_waited_too_long_is_dropped_when_taken_and_makes_room_when_more_come() {
        let now = now_ms();
        let mut table = Table::default();
        table.open(1, Arc::new(Notify::new()), test_from());
        let believed = whereabouts::check(&record(PLANET, now), &listed, Known::default(), now).unwrap();
        table.keep(&believed, record(PLANET, now), &PointBounds::default(), now, 1).unwrap();
        let long_ago = Instant::now().checked_sub(PUSH_WAIT + Duration::from_millis(100)).unwrap();
        // One that has waited past its time, and nothing after it: when it is come to, it is
        // dropped, not passed on.
        table.present.get_mut(&1).unwrap().waiting.push_back(Push { callee: PLANET, record: vec![1], at: long_ago, session: None });
        assert!(table.next_push(1, now).is_none());
        // As many as may wait for the ship, all past their time: a new one finds room.
        for _ in 0..MOST_WAITING_EACH {
            table.present.get_mut(&1).unwrap().waiting.push_back(Push { callee: PLANET, record: vec![2], at: long_ago, session: None });
        }
        assert_eq!(table.pass(PLANET, vec![3], now), Ok(()));
        assert_eq!(table.next_push(1, now).map(|push| push.record), Some(vec![3]));
    }

    #[test]
    fn the_time_given_to_an_introduction_and_its_attempts_is_a_share_of_what_is_left() {
        // One reading of the clock, so that the figures are exact.
        let now = tokio::time::Instant::now();
        let at = |left: u64| now + Duration::from_millis(left);
        // Plenty left: the whole allowance.
        assert_eq!(introduced_limit_at(at(60_000), now), TRY_INTRODUCED);
        assert_eq!(introduce_wait_at(at(60_000), now), INTRODUCE_WAIT);
        // Little left: three quarters of it for an attempt, a quarter for the point's answer.
        assert_eq!(introduced_limit_at(at(2000), now), Duration::from_millis(1500));
        assert_eq!(introduce_wait_at(at(2000), now), Duration::from_millis(500));
        // None left, or less than none: nothing.
        assert_eq!(introduced_limit_at(now, now), Duration::ZERO);
        assert_eq!(introduced_limit_at(now, now + Duration::from_secs(1)), Duration::ZERO);
        assert_eq!(introduce_wait_at(now, now + Duration::from_secs(1)), Duration::ZERO);
    }

    /// `count` live lookup points, each a runtime of its own, under `base`.
    fn live_points(base: &std::path::Path, count: usize) -> Vec<(Arc<crate::Runtime>, crate::net::Network)> {
        (0..count)
            .map(|n| {
                let dir = base.join(n.to_string());
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let runtime = Arc::new(crate::Runtime::open(&dir, crate::Config { durability: crate::Durability::Normal, ..crate::Config::default() }).unwrap());
                let lookup = Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: None }), ..Lookup::default() };
                let net = crate::net::Network::start(runtime.clone(), Directory::new(), NetConfig { lookup, ..NetConfig::default() }).unwrap();
                (runtime, net)
            })
            .collect()
    }

    #[test]
    fn a_lane_whose_point_moves_gives_up_its_old_connection_before_taking_room() {
        let base = std::env::temp_dir().join(format!("urbit-wasm-{}-moving-points", std::process::id()));
        let points = live_points(&base, MOST_POINTS + 1);
        // Galaxy 0's point is now the last one; every other galaxy's is where it was.
        let lookup = Lookup { at: vec![(Some(0), points[MOST_POINTS].1.addr())], ..Lookup::default() };
        let (tokio, finder) = finder_with(lookup, now_ms(), 0);
        let finder = Arc::new(finder);
        tokio.block_on(async {
            // Every place in the map is a connection some lane announces over.
            for (galaxy, (_, point)) in points[..MOST_POINTS].iter().enumerate() {
                let connection = finder.kept_connection(point.addr()).await.unwrap();
                lock(&finder.lanes).entry(galaxy as u8).or_default().connection = Some(connection);
            }
            assert_eq!(lock(&finder.kept).len(), MOST_POINTS);
            // Galaxy 0's lane gives up its old connection, and so finds room for the new.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let connection = finder.lane_connection(0, deadline).await.expect("the lane could not move");
            assert_eq!(connection.remote_address(), points[MOST_POINTS].1.addr());
            // The new point has taken the connection.
            let started = Instant::now();
            while points[MOST_POINTS].1.point_status().unwrap().connections == 0 {
                assert!(started.elapsed() < Duration::from_secs(10), "the new point never took the connection");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let started = Instant::now();
            while points[0].1.point_status().unwrap().connections > 0 {
                assert!(started.elapsed() < Duration::from_secs(10), "the old point's connection was not closed");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The others' lanes are as they were.
            assert!(points[1..MOST_POINTS].iter().all(|(_, point)| point.point_status().unwrap().connections == 1));
        });
        drop(points);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn connections_no_lane_announces_over_are_let_go_of_to_make_room() {
        let (tokio, finder) = stepping_finder(now_ms(), 0);
        let finder = Arc::new(finder);
        // One live point more than a runtime keeps connections to.
        let base = std::env::temp_dir().join(format!("urbit-wasm-{}-kept-points", std::process::id()));
        let points = live_points(&base, MOST_POINTS + 1);
        tokio.block_on(async {
            let mut first = None;
            for (_, point) in &points[..MOST_POINTS] {
                let connection = finder.kept_connection(point.addr()).await.unwrap();
                first.get_or_insert(connection);
            }
            // One lane announces over the first. Room for the last is made from the others.
            lock(&finder.lanes).entry(0).or_default().connection = first.clone();
            finder.kept_connection(points[MOST_POINTS].1.addr()).await.expect("no room was made");
            let started = Instant::now();
            while points[1..MOST_POINTS].iter().any(|(_, point)| point.point_status().unwrap().connections > 0) {
                assert!(started.elapsed() < Duration::from_secs(10), "connections no lane uses were not closed");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(first.unwrap().close_reason().is_none(), "the connection a lane announces over was let go of");
            assert_eq!(points[0].1.point_status().unwrap().connections, 1);
            assert_eq!(lock(&finder.kept).len(), 2);
        });
        drop(points);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_point_counts_only_so_many_callers_of_introductions() {
        let point = point(PointBounds { introductions_each: 1, rate_period: Duration::from_millis(50), ..PointBounds::default() }, None);
        for caller in 0..MOST_INTRODUCERS as u64 {
            assert_eq!(point.introducer(caller), Ok(()));
        }
        assert_eq!(point.introducer(0), Err("too many introductions from that ship just now; try again later"));
        assert_eq!(point.introducer(MOST_INTRODUCERS as u64), Err("this lookup point is counting as many callers as it may; try again later"));
        // Once the allowances are whole again, those callers are forgotten, and a new one is
        // counted.
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(point.introducer(MOST_INTRODUCERS as u64), Ok(()));
        assert!(lock(&point.introducers).len() <= 2);
    }

    #[test]
    fn settings_that_make_no_sense_are_refused() {
        let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        assert!(Lookup::default().sound().is_ok());
        assert!(!Lookup::default().finds());
        let finds = Lookup { at: vec![(None, at)], ..Lookup::default() };
        assert!(finds.finds() && finds.sound().is_ok());
        for bad in [
            Lookup { announce: vec![at], ..Lookup::default() },
            Lookup { announce: vec!["0.0.0.0:4433".parse().unwrap()], ..finds.clone() },
            Lookup { announce: vec![at; 2], ..finds.clone() },
            Lookup { announce_every: Duration::ZERO, ..finds.clone() },
            Lookup { announce_every: Duration::from_secs(301), ..finds.clone() },
            Lookup { ask_again: Duration::ZERO, ..finds.clone() },
            Lookup { resolved_for: Duration::from_secs(90_000), ..finds.clone() },
            Lookup { domain: Some(("".into(), 4433)), ..Lookup::default() },
            Lookup { domain: Some(("points.example".into(), 0)), ..Lookup::default() },
            Lookup { domain: Some(("a b".into(), 4433)), ..Lookup::default() },
            Lookup { at: vec![(Some(1), "0.0.0.0:4433".parse().unwrap())], ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: Some(vec![]), bounds: PointBounds::default(), relay: None }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { in_all: 0, ..PointBounds::default() }, relay: None }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { rate_period: Duration::ZERO, ..PointBounds::default() }, relay: None }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { introductions: 0, ..PointBounds::default() }, relay: None }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { introductions_each: 0, ..PointBounds::default() }, relay: None }), ..Lookup::default() },
            Lookup { keep_alive: Duration::from_millis(999), ..finds.clone() },
            Lookup { keep_alive: Duration::from_millis(25_001), ..finds.clone() },
            Lookup { behind_router: true, ..Lookup::default() },
            Lookup { direct_again: Duration::from_millis(1999), ..finds.clone() },
            Lookup { direct_again: Duration::from_secs(90_000), ..finds.clone() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds { ship_rate: 0, ..RelayBounds::default() }) }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds { point_burst: 2047, ..RelayBounds::default() }) }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds { sessions_from: 0, ..RelayBounds::default() }) }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds { sessions_pair: 0, ..RelayBounds::default() }) }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds { made: 0, ..RelayBounds::default() }) }), ..Lookup::default() },
        ] {
            assert!(bad.sound().is_err(), "{bad:?}");
        }
        let relaying = Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds::default()) }), ..Lookup::default() };
        assert!(relaying.sound().is_ok());
    }

    // Relaying, at the point.

    /// Where the tests' callers' requests to relay come from.
    const CALLER_AT: &str = "203.0.113.50:1000";

    /// A point that relays within `relay`, counting by `bounds`, with the connection the tests
    /// announce on open (from `test_from`).
    fn relaying_within(bounds: PointBounds, relay: RelayBounds) -> Arc<Point> {
        Arc::new(testing(Point::new(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds, relay: Some(relay) }, &rustls::crypto::ring::default_provider()).unwrap()))
    }

    fn relaying(relay: RelayBounds) -> Arc<Point> {
        relaying_within(PointBounds::default(), relay)
    }

    /// A ship's record asking callers to be introduced, made now.
    fn flagged(ship: u64) -> Vec<u8> {
        whereabouts::sign_flagged(&name(ship), &["203.0.113.7:4433".parse().unwrap()], now_ms(), true, &key_of(ship), None).unwrap()
    }

    /// `callee` announces itself, asking to be introduced, on the connection the tests announce
    /// on, and attends there.
    fn attend(point: &Point, callee: u64) {
        assert_eq!(point.take(vec![flagged(callee)], &plenty()), vec![String::new()]);
    }

    /// Ask the point to relay for `caller`, from `from`, to `callee`, as a request on the
    /// connection the tests announce on would: the session's name, or why not.
    fn relay_from(point: &Point, caller: u64, callee: u64, from: &str) -> Result<SessionId, &'static str> {
        let record = record(caller, now_ms());
        let presence = presence_for(&record);
        let id = crate::random_bytes::<16>().unwrap();
        point.relay_one(callee, record, &presence, Some(&TESTING.1), from.parse().unwrap(), id, &Mutex::new(false)).map(|()| id)
    }

    /// Hand the point a relayed datagram of `len` bytes naming `id`, from `from`: where it was
    /// carried, if it was. What reaches the socket is counted by the stand-in sender.
    fn carry(point: &Point, id: &SessionId, from: &str, len: usize) -> Option<SocketAddr> {
        let datagram = vec![relay::KIND; len];
        let mut sent = Vec::new();
        let carried = point.carry(id, from.parse().unwrap(), &datagram, &mut |to| {
            sent.push(to);
            true
        });
        match carried {
            Carry::To(to) => {
                assert_eq!(sent, vec![to]);
                Some(to)
            }
            Carry::Dropped(_) => {
                assert!(sent.is_empty(), "something was sent for a datagram that was dropped");
                None
            }
        }
    }

    const CALLEE: u64 = PLANET;
    const CALLER: u64 = PLANET + (1 << 16);
    const STRANGER: &str = "198.51.100.77:5000";

    #[test]
    fn a_point_carries_only_between_the_two_pinned_addresses_of_a_live_session() {
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        let (callee_at, caller_at): (SocketAddr, SocketAddr) = (test_from(), CALLER_AT.parse().unwrap());
        // The callee's record and the session went over the connection it attends on, together.
        {
            let table = lock(&point.table);
            let waiting = &table.present[&TESTING.0].waiting;
            assert_eq!(waiting.len(), 1);
            assert_eq!(waiting[0].session, Some(id));
            assert_eq!(whereabouts::ship_of(&waiting[0].record), Some(CALLER));
        }
        assert_eq!(point.sessions(), vec![(id, CALLEE, CALLER, callee_at, caller_at)]);
        // Each way between the two pinned addresses, and nowhere else.
        assert_eq!(carry(&point, &id, CALLER_AT, 100), Some(callee_at));
        assert_eq!(carry(&point, &id, "198.51.100.1:4433", 120), Some(caller_at));
        // From anyone else, or naming no session: nothing is sent, and the session is untouched.
        assert_eq!(carry(&point, &id, STRANGER, 50), None);
        assert_eq!(carry(&point, &[0; 16], CALLER_AT, 60), None);
        // An IPv4 address written as IPv6 is the same address.
        assert_eq!(carry(&point, &id, "[::ffff:203.0.113.50]:1000", 10), Some(callee_at));
        let status = point.status();
        assert_eq!(status.sessions, 1);
        assert_eq!(status.relayed.carried, 230);
        assert_eq!(status.relayed.stranger, 50);
        assert_eq!(status.relayed.unknown, 60);
        assert_eq!(status.carried_for, vec![(CALLEE, 230)]);
        assert_eq!(status.relays_made, 1);
    }

    #[test]
    fn a_point_carries_toward_a_caller_only_while_it_has_sent_lately() {
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let callee_at = "198.51.100.1:4433";
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        // In the grace after making, the callee may answer first.
        assert!(carry(&point, &id, callee_at, 10).is_some());
        // The caller sends; twenty seconds later the callee answers, and it is carried; eleven
        // more (the caller silent for thirty-one) and it is not, though the session is live:
        // something was carried eleven seconds ago.
        assert!(carry(&point, &id, CALLER_AT, 10).is_some());
        point.step_relay(Duration::from_secs(20));
        assert!(carry(&point, &id, callee_at, 10).is_some());
        point.step_relay(Duration::from_secs(11));
        assert_eq!(carry(&point, &id, callee_at, 10), None);
        assert_eq!(point.status().relayed.absent, 10);
        assert_eq!(point.status().sessions, 1);
        // The caller is heard from again: both ways go again.
        assert!(carry(&point, &id, CALLER_AT, 10).is_some());
        assert!(carry(&point, &id, callee_at, 10).is_some());
        // A session past its grace whose caller has sent nothing: nothing goes toward it.
        let other = relay_from(&point, CALLER + (1 << 16), CALLEE, "203.0.113.51:1000").unwrap();
        point.step_relay(relay::GRACE);
        assert_eq!(carry(&point, &other, callee_at, 10), None);
    }

    #[test]
    fn a_session_nothing_is_carried_on_for_the_idle_time_is_dropped_and_carries_nothing_after() {
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert!(carry(&point, &id, CALLER_AT, 10).is_some());
        point.step_relay(relay::IDLE - Duration::from_secs(1));
        assert!(carry(&point, &id, CALLER_AT, 10).is_some());
        point.step_relay(relay::IDLE);
        assert_eq!(carry(&point, &id, CALLER_AT, 10), None);
        assert_eq!(carry(&point, &id, "198.51.100.1:4433", 10), None);
        assert_eq!(point.status().sessions, 0);
        assert_eq!(point.status().relayed.unknown, 20);
    }

    #[test]
    fn a_session_ends_when_the_ship_called_stops_attending_where_it_was_made() {
        // The connection the callee attends on closes.
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert!(carry(&point, &id, CALLER_AT, 10).is_some());
        lock(&point.table).close(TESTING.0);
        // Gone at once, with the table, before any packet comes to show it.
        assert_eq!(point.status().sessions, 0);
        assert_eq!(carry(&point, &id, CALLER_AT, 10), None);
        assert_eq!(carry(&point, &id, "198.51.100.1:4433", 10), None);
        assert_eq!(point.status().sessions, 0);
        // A newer record of the callee is kept on another connection: it has moved.
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        lock(&point.table).open(7, Arc::new(Notify::new()), "198.51.100.2:4433".parse().unwrap());
        let newer = whereabouts::sign_flagged(&name(CALLEE), &["203.0.113.7:4433".parse().unwrap()], now_ms() + 1, true, &key_of(CALLEE), None).unwrap();
        let believed = whereabouts::check(&newer, &listed, Known::default(), now_ms()).unwrap();
        lock(&point.table).keep(&believed, newer, &PointBounds::default(), now_ms(), 7).unwrap();
        assert_eq!(point.status().sessions, 0);
        assert_eq!(carry(&point, &id, CALLER_AT, 10), None);
        // And the record running out ends attendance too: weighed as passing an introduction
        // weighs it, per packet.
        let point = relaying(RelayBounds::default());
        let old = whereabouts::sign_flagged(&name(CALLEE), &["203.0.113.7:4433".parse().unwrap()], now_ms() - whereabouts::LIFETIME_MS + 300, true, &key_of(CALLEE), None).unwrap();
        assert_eq!(point.take(vec![old], &plenty()), vec![String::new()]);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(carry(&point, &id, CALLER_AT, 10), None);
        assert_eq!(point.status().relayed.absent, 10);
        // A record the point lets go of (swept when it has run out) takes its ship's sessions
        // with it.
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        lock(&point.table).remove(CALLEE);
        assert_eq!(point.status().sessions, 0);
    }

    /// A point that relays, its source of keys gated, with `CALLEE` attending on the connection
    /// the tests announce on and asking for introductions; and a caller's record with presence.
    fn relaying_gated(gate: &Arc<Gate>) -> (Arc<Point>, Vec<u8>, Vec<u8>) {
        let point = Arc::new(testing(Point::new(PointConfig { keys: gate.clone(), galaxies: None, bounds: PointBounds::default(), relay: Some(RelayBounds::default()) }, &rustls::crypto::ring::default_provider()).unwrap()));
        let now = now_ms();
        let believed = whereabouts::check(&flagged(CALLEE), &listed, Known::default(), now).unwrap();
        lock(&point.table).keep(&believed, flagged(CALLEE), &PointBounds::default(), now, TESTING.0).unwrap();
        let caller = record(CALLER, now);
        let presence = tests::presence_for(&caller);
        (point, caller, presence)
    }

    fn relay_worker(point: &Arc<Point>, caller: Vec<u8>, presence: Vec<u8>, gone: &Arc<Mutex<bool>>) -> std::thread::JoinHandle<Result<(), &'static str>> {
        let (point, gone) = (point.clone(), gone.clone());
        std::thread::spawn(move || point.relay_one(CALLEE, caller, &presence, Some(&TESTING.1), CALLER_AT.parse().unwrap(), [8; 16], &gone))
    }

    #[test]
    fn no_session_is_made_for_a_caller_that_goes_while_its_request_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        let (point, caller, presence) = relaying_gated(&gate);
        let gone = Arc::new(Mutex::new(false));
        let worker = relay_worker(&point, caller, presence, &gone);
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        let table = lock(&point.table);
        gate.open.store(true, Ordering::SeqCst);
        until(|| gate.answered.load(Ordering::SeqCst));
        // The few instructions from the answer to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), Err(GONE));
        assert_eq!(point.status().sessions, 0);
        assert!(lock(&point.table).next_push(TESTING.0, point.now()).is_none());
    }

    #[test]
    fn nothing_is_asked_for_a_request_to_relay_whose_caller_goes_while_it_waits_for_the_table() {
        let gate = Arc::new(Gate::default());
        gate.open.store(true, Ordering::SeqCst);
        let (point, caller, presence) = relaying_gated(&gate);
        let asked = gate.asked.load(Ordering::SeqCst);
        let gone = Arc::new(Mutex::new(false));
        let table = lock(&point.table);
        let worker = relay_worker(&point, caller, presence, &gone);
        // The worker's few instructions up to the wait for the table.
        std::thread::sleep(Duration::from_millis(50));
        *lock(&gone) = true;
        drop(table);
        assert_eq!(worker.join().unwrap(), Err(GONE));
        assert_eq!(gate.asked.load(Ordering::SeqCst), asked, "the source of keys was asked for a caller that had gone");
    }

    #[test]
    fn a_session_is_weighed_where_it_is_made_against_the_ship_called_and_the_callers_history() {
        // The callee's connection closes while the caller's key is asked about: when the answer
        // comes, no session is made toward the connection the table has seen close.
        let gate = Arc::new(Gate::default());
        let (point, caller, presence) = relaying_gated(&gate);
        let worker = relay_worker(&point, caller, presence, &Arc::new(Mutex::new(false)));
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        lock(&point.table).close(TESTING.0);
        gate.open.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Err(NOT_ATTENDING));
        assert_eq!(point.status().sessions, 0);
        // A newer record of the caller is kept while its older one is checked: the older one is
        // refused where the session would be made.
        let gate = Arc::new(Gate::default());
        let (point, caller, presence) = relaying_gated(&gate);
        let worker = relay_worker(&point, caller, presence, &Arc::new(Mutex::new(false)));
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        let now = now_ms();
        let newer = record(CALLER, now + 1000);
        let believed = whereabouts::check(&newer, &listed, Known::default(), now).unwrap();
        lock(&point.table).keep(&believed, newer, &PointBounds::default(), now, TESTING.0).unwrap();
        gate.open.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Err("a record of the ship as new or newer is already held"));
        assert_eq!(point.status().sessions, 0);
        // And a caller's record that runs out while it is checked is refused there too.
        let gate = Arc::new(Gate::default());
        let (point, _, _) = relaying_gated(&gate);
        let old = record(CALLER, now_ms() - whereabouts::LIFETIME_MS + 300);
        let presence = tests::presence_for(&old);
        let worker = relay_worker(&point, old, presence, &Arc::new(Mutex::new(false)));
        until(|| gate.asked.load(Ordering::SeqCst) >= 1);
        std::thread::sleep(Duration::from_millis(400));
        gate.open.store(true, Ordering::SeqCst);
        assert_eq!(worker.join().unwrap(), Err("the record ran out, or this clock went back, while it was being checked"));
        assert_eq!(point.status().sessions, 0);
    }

    #[test]
    fn a_request_to_relay_is_refused_saying_why_and_within_each_bound() {
        // A point that does not relay says so.
        let quiet = self::point(PointBounds::default(), None);
        assert_eq!(quiet.take(vec![flagged(CALLEE)], &plenty()), vec![String::new()]);
        let record = record(CALLER, now_ms());
        assert_eq!(quiet.relay_one(CALLEE, record.clone(), &presence_for(&record), Some(&TESTING.1), CALLER_AT.parse().unwrap(), [1; 16], &Mutex::new(false)), Err(NO_RELAY));
        let bounds = RelayBounds { sessions_each: 2, sessions_from: 2, sessions: 3, made_each: 100, ..RelayBounds::default() };
        let point = relaying(bounds);
        // Not attending; attending but saying it can be reached directly.
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), Err(NOT_ATTENDING));
        assert_eq!(point.take(vec![self::record(CALLEE, now_ms())], &plenty()), vec![String::new()]);
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), Err("that ship says it can be reached directly, and is not relayed for"));
        attend(&point, CALLEE);
        // A forged caller's record; one with no presence; a caller at the callee's own address.
        let forged = whereabouts::sign(&name(CALLER), &["203.0.113.9:1".parse().unwrap()], now_ms(), &key_of(CALLER + 1), None).unwrap();
        assert_eq!(point.relay_one(CALLEE, forged.clone(), &presence_for(&forged), Some(&TESTING.1), CALLER_AT.parse().unwrap(), [2; 16], &Mutex::new(false)), Err("the record is not signed by the ship's key"));
        let genuine = self::record(CALLER, now_ms());
        assert!(point.relay_one(CALLEE, genuine, &[], Some(&TESTING.1), CALLER_AT.parse().unwrap(), [3; 16], &Mutex::new(false)).unwrap_err().contains("presence"));
        assert_eq!(relay_from(&point, CALLER, CALLEE, "198.51.100.1:4433"), Err("the caller is at the very address of the ship it wants; there is nothing to carry"));
        assert_eq!(point.status().sessions, 0);
        // Two for the callee, and the third (from another caller) is refused for that reason.
        let other_callee = CALLEE + (2 << 16);
        attend(&point, other_callee);
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        relay_from(&point, CALLER + (3 << 16), CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_from(&point, CALLER + (4 << 16), CALLEE, CALLER_AT), Err("this lookup point carries as many sessions for that ship as it may; try again later"));
        // Two from one caller: the third, to another callee, is refused for that reason.
        relay_from(&point, CALLER, other_callee, CALLER_AT).unwrap();
        // Three in all.
        assert_eq!(relay_from(&point, CALLER + (5 << 16), other_callee, CALLER_AT), Err("this lookup point carries as many sessions as it may; try again later"));
        assert_eq!(point.status().sessions, 3);
        let point = relaying(RelayBounds { sessions_from: 1, ..RelayBounds::default() });
        attend(&point, CALLEE);
        attend(&point, other_callee);
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_from(&point, CALLER, other_callee, CALLER_AT), Err("this lookup point carries as many sessions from that ship as it may; try again later"));
        // Sessions made for one caller, counted by the hour so nothing is earned back: two, then
        // refused for that reason, while another caller is still served.
        let point = relaying_within(PointBounds { rate_period: Duration::from_secs(3600), ..PointBounds::default() }, RelayBounds { made_each: 2, ..RelayBounds::default() });
        attend(&point, CALLEE);
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), Err("too many sessions made for that ship just now; try again later"));
        relay_from(&point, CALLER + (6 << 16), CALLEE, CALLER_AT).unwrap();
        // None of it stopped ordinary questions.
        assert!(point.find(CALLEE).is_some());
        // A callee whose record has run out does not attend, though its connection is open.
        let point = relaying(RelayBounds::default());
        let old = whereabouts::sign_flagged(&name(CALLEE), &["203.0.113.7:4433".parse().unwrap()], now_ms() - whereabouts::LIFETIME_MS + 300, true, &key_of(CALLEE), None).unwrap();
        assert_eq!(point.take(vec![old], &plenty()), vec![String::new()]);
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), Err(NOT_ATTENDING));
        // No session without room for its push: four pushes wait for the callee (nobody takes
        // them here), and the fifth request is refused for that, with no session made.
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        for n in 0..MOST_WAITING_EACH as u64 {
            relay_from(&point, CALLER + ((n + 1) << 16), CALLEE, CALLER_AT).unwrap();
        }
        assert_eq!(relay_from(&point, CALLER + (9 << 16), CALLEE, CALLER_AT), Err("that ship has as many introductions waiting as it may; try again later"));
        assert_eq!(point.status().sessions, MOST_WAITING_EACH);
    }

    /// Ask the point to relay for the ship of `record` (its presence made here), from `from`,
    /// to `callee`.
    fn relay_record(point: &Point, record: Vec<u8>, callee: u64, from: &str) -> Result<SessionId, &'static str> {
        let presence = presence_for(&record);
        let id = crate::random_bytes::<16>().unwrap();
        point.relay_one(callee, record, &presence, Some(&TESTING.1), from.parse().unwrap(), id, &Mutex::new(false)).map(|()| id)
    }

    #[test]
    fn a_lookup_point_at_a_made_up_address_is_never_connected_to_and_the_walk_goes_on() {
        let made_up: SocketAddr = "255.255.255.255:4433".parse().unwrap();
        let (tokio, finder) = finder_with(Lookup { at: vec![(None, made_up)], ..Lookup::default() }, now_ms(), 0);
        let finder = Arc::new(finder);
        let seen = WhereRequest { body: Some(where_request::Body::Seen(Seen {})) };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let why = tokio.block_on(finder.exchange(0, seen.clone(), deadline)).unwrap_err();
        assert!(why.contains("made up for relay sessions"), "{why}");
        let why = tokio.block_on(finder.kept_connection(made_up)).unwrap_err();
        assert!(why.contains("made up for relay sessions"), "{why}");
        // A made-up address first, then one where nothing answers: the second is still tried.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (tokio, finder) = finder_with(Lookup { at: vec![(None, made_up), (None, silent.local_addr().unwrap())], ..Lookup::default() }, now_ms(), 0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let why = tokio.block_on(Arc::new(finder).exchange(0, seen, deadline)).unwrap_err();
        assert!(why.contains(&silent.local_addr().unwrap().to_string()), "{why}");
    }

    #[test]
    fn a_pair_of_ships_holds_at_most_two_sessions_and_a_moon_counts_as_its_planet() {
        let point = relaying(RelayBounds { made_each: 100, ..RelayBounds::default() });
        attend(&point, CALLEE);
        let pair_full = Err("this lookup point carries as many sessions between those two ships as it may; try again later");
        // Two for one caller and callee; the third is refused for that reason.
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        let second = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), pair_full);
        // Another caller still gets one to that callee meanwhile.
        relay_from(&point, CALLER + (3 << 16), CALLEE, CALLER_AT).unwrap();
        // One of the two ends (its callee's... here, it goes idle while the other is kept busy):
        // there is room for the pair again.
        carry(&point, &second, CALLER_AT, 10).unwrap();
        point.step_relay(relay::IDLE - Duration::from_secs(1));
        carry(&point, &second, CALLER_AT, 10).unwrap();
        point.step_relay(Duration::from_secs(2));
        relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), pair_full);
        // Two moons of one planet share the pair's count with each other (and with the planet).
        let point = relaying(RelayBounds { made_each: 100, ..RelayBounds::default() });
        attend(&point, CALLEE);
        let (first_moon, second_moon) = ((1u64 << 32) | CALLER, (2u64 << 32) | CALLER);
        relay_record(&point, moon_record(first_moon, now_ms()), CALLEE, CALLER_AT).unwrap();
        relay_record(&point, moon_record(second_moon, now_ms()), CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_record(&point, moon_record(first_moon, now_ms() + 1), CALLEE, CALLER_AT), pair_full);
        assert_eq!(relay_from(&point, CALLER, CALLEE, CALLER_AT), pair_full);
        // And the caller's count: one session from a planet's moons in all.
        let point = relaying(RelayBounds { sessions_from: 1, made_each: 100, ..RelayBounds::default() });
        attend(&point, CALLEE);
        attend(&point, CALLEE + (2 << 16));
        relay_record(&point, moon_record(first_moon, now_ms()), CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_record(&point, moon_record(second_moon, now_ms()), CALLEE + (2 << 16), CALLER_AT), Err("this lookup point carries as many sessions from that ship as it may; try again later"));
        // And the caller's allowance of sessions made, counted by the hour: one for the planet
        // and its moons together.
        let point = relaying_within(PointBounds { rate_period: Duration::from_secs(3600), ..PointBounds::default() }, RelayBounds { made_each: 1, ..RelayBounds::default() });
        attend(&point, CALLEE);
        relay_record(&point, moon_record(first_moon, now_ms()), CALLEE, CALLER_AT).unwrap();
        assert_eq!(relay_record(&point, moon_record(second_moon, now_ms()), CALLEE, CALLER_AT), Err("too many sessions made for that ship just now; try again later"));
    }

    #[test]
    fn a_session_whose_every_send_fails_goes_idle_all_the_same() {
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        // A socket whose every send would block.
        let stand = relay::tests::Stand::at("203.0.113.1:4433");
        stand.blocks.store(true, Ordering::SeqCst);
        let wrapper = relay::Relayed::new(stand.clone(), Some(point.clone()), Duration::from_secs(30)).unwrap();
        let from_caller = relay::wrapped(&id, &[0x41; 100]);
        // Attempts ten seconds apart, none delivered.
        for _ in 0..3 {
            stand.arrive(vec![(CALLER_AT.parse().unwrap(), from_caller.clone(), 0)]);
            assert!(relay::tests::received(&wrapper).is_empty());
            point.step_relay(Duration::from_secs(10));
        }
        assert_eq!(point.status().relayed.carried, 0);
        assert_eq!(point.status().relayed.unsent, 3 * from_caller.len() as u64);
        // Thirty seconds after it was made, nothing having gone, it is gone.
        assert_eq!(point.status().sessions, 0);
    }

    #[test]
    fn the_byte_allowances_hold_over_every_interval_and_one_ship_at_its_allowance_does_not_stop_another() {
        // A small allowance for each ship, and a large one in all.
        let bounds = RelayBounds { ship_rate: 20_000, ship_burst: 40_000, point_rate: 1 << 30, point_burst: 1 << 30, ..RelayBounds::default() };
        let point = relaying(bounds);
        let other_callee = CALLEE + (2 << 16);
        attend(&point, CALLEE);
        attend(&point, other_callee);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        let other = relay_from(&point, CALLER, other_callee, CALLER_AT).unwrap();
        // Offer far more than the bound, as fast as it can be offered, for half a second.
        let started = Instant::now();
        let (mut offered, mut carried) = (0u64, 0u64);
        while started.elapsed() < Duration::from_millis(500) {
            offered += 1000;
            if carry(&point, &id, CALLER_AT, 1000).is_some() {
                carried += 1000;
            }
        }
        let took = started.elapsed().as_secs_f64();
        let bound = 40_000.0 + 20_000.0 * took;
        assert!(offered as f64 >= 4.0 * bound, "inconclusive: only {offered} bytes were offered against a bound of {bound}");
        assert!(carried as f64 <= bound, "{carried} carried in {took} s, more than {bound}");
        assert!(carried >= 40_000, "the burst was not carried: {carried}");
        assert_eq!(point.status().relayed.over_ship, offered - carried);
        // The other ship's session still carries, from the same caller.
        assert!(carry(&point, &other, CALLER_AT, 1000).is_some());
        // And over the point's own allowance, every ship is held.
        let bounds = RelayBounds { ship_rate: 1 << 30, ship_burst: 1 << 30, point_rate: 10_000, point_burst: 20_000, ..RelayBounds::default() };
        let point = relaying(bounds);
        attend(&point, CALLEE);
        attend(&point, other_callee);
        let ids = [relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap(), relay_from(&point, CALLER, other_callee, CALLER_AT).unwrap()];
        let started = Instant::now();
        let (mut offered, mut carried) = (0u64, 0u64);
        while started.elapsed() < Duration::from_millis(500) {
            for id in &ids {
                offered += 1000;
                if carry(&point, id, CALLER_AT, 1000).is_some() {
                    carried += 1000;
                }
            }
        }
        let took = started.elapsed().as_secs_f64();
        let bound = 20_000.0 + 10_000.0 * took;
        assert!(offered as f64 >= 4.0 * bound, "inconclusive: only {offered} bytes were offered against a bound of {bound}");
        assert!(carried as f64 <= bound && carried >= 20_000, "{carried} carried in {took} s against {bound}");
        assert_eq!(point.status().relayed.over_point, offered - carried);
    }

    #[test]
    fn what_a_point_carries_goes_out_as_it_came_in_and_never_reaches_quic() {
        let point = relaying(RelayBounds::default());
        attend(&point, CALLEE);
        let id = relay_from(&point, CALLER, CALLEE, CALLER_AT).unwrap();
        let stand = relay::tests::Stand::at("203.0.113.1:4433");
        let wrapper = relay::Relayed::new(stand.clone(), Some(point.clone()), Duration::from_secs(30)).unwrap();
        let from_caller = relay::wrapped(&id, &[0x41; 300]);
        let from_callee = relay::wrapped(&id, &[0x42; 200]);
        let unknown = relay::wrapped(&[5; 16], &[0x43; 100]);
        stand.arrive(vec![(CALLER_AT.parse().unwrap(), from_caller.clone(), 0), ("198.51.100.1:4433".parse().unwrap(), from_callee.clone(), 0), (STRANGER.parse().unwrap(), from_caller.clone(), 0), (CALLER_AT.parse().unwrap(), unknown, 0)]);
        // Nothing reaches QUIC, and exactly what came in from each pinned side went to the
        // other, byte for byte, and nothing else went anywhere.
        assert!(relay::tests::received(&wrapper).is_empty());
        let sent = stand.sent();
        assert_eq!(sent, vec![(test_from(), from_caller, None), (CALLER_AT.parse().unwrap(), from_callee, None)]);
        let status = point.status();
        assert_eq!(status.relayed.carried, (2 * relay::HEADER + 500) as u64);
    }
}
