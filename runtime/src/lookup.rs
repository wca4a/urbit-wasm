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
//! a point says is taken on its word. A record is believed only if the ship signed it, so a
//! point can keep one back, or hand out one that has not run out yet, and nothing more. The
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
//! What this does not do yet: learn the address a runtime is seen at from outside its router,
//! introduce two ships to each other, open a path through home routers, or carry traffic for
//! ships that cannot be reached directly. Ships behind home routers stay unreachable for now.

use std::collections::{HashMap, HashSet};
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
use ship_proto::{where_reply, where_request, Announce, Announced, Found, Message, Where, WhereReply, WhereRequest};
use tokio::sync::Semaphore;
use urbit_id::ob;

use crate::azimuth::Keys;
use crate::net::{self, Directory, NetConfig, NetError};
use crate::store::now_ms;
use crate::whereabouts::{self, Believed, Known};
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

/// How many questions about ships one connection to a lookup point may ask in a second. A
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
}

impl Default for PointBounds {
    fn default() -> Self {
        // Sixty-five thousand ships each announcing every two minutes is some five hundred
        // records a second.
        PointBounds { records: 1 << 16, moons: 1 << 14, moons_each: 64, connections: 256, per_connection: 256, in_all: 2048, rate_period: Duration::from_secs(1) }
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
}

impl fmt::Debug for PointConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PointConfig").field("galaxies", &self.galaxies).field("bounds", &self.bounds).finish()
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
    /// With none, the address the runtime listens on, unless that is one that means "any"
    /// (`0.0.0.0` or `::`), in which case nothing is announced.
    pub announce: Vec<SocketAddr>,
    /// How often each ship is announced again. Records last ten minutes, so this must leave
    /// room for some announcements to go astray.
    pub announce_every: Duration,
    /// How long after asking a point about a ship before asking about it again, whatever
    /// the answer was. Also how long a failure to look up a point's name is remembered.
    pub ask_again: Duration,
    /// How long an answer from the resolver is used before the name is looked up again.
    pub resolved_for: Duration,
}

impl Default for Lookup {
    fn default() -> Self {
        Lookup {
            serve: None,
            at: Vec::new(),
            domain: None,
            resolver: None,
            announce: Vec::new(),
            announce_every: Duration::from_secs(120),
            ask_again: Duration::from_secs(3),
            resolved_for: Duration::from_secs(300),
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
            .field("announce_every", &self.announce_every)
            .field("ask_again", &self.ask_again)
            .field("resolved_for", &self.resolved_for)
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
            if b.records == 0 || b.moons == 0 || b.moons_each == 0 || b.connections == 0 || b.per_connection == 0 || b.in_all == 0 {
                return Err("a lookup point's bounds must each be more than nothing".into());
            }
            if !within(b.rate_period) {
                return Err("a lookup point's rate_period must be more than nothing and at most a day".into());
            }
            if point.galaxies.as_ref().is_some_and(Vec::is_empty) {
                return Err("a lookup point must serve some galaxy".into());
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

/// So many things allowed in a second, topped up as time passes, up to a second's worth.
struct Bucket {
    left: f64,
    /// The most there may be, which is one period's worth.
    most: f64,
    /// How many are earned back in a second.
    per_second: f64,
    at: Instant,
}

impl Bucket {
    /// So many a second.
    fn new(rate: u32) -> Bucket {
        Bucket::per(rate, Duration::from_secs(1))
    }

    /// So many each `period`, which is more than nothing.
    fn per(rate: u32, period: Duration) -> Bucket {
        let most = f64::from(rate);
        Bucket { left: most, most, per_second: most / period.as_secs_f64().max(f64::MIN_POSITIVE), at: Instant::now() }
    }

    /// Take one, if there is one.
    fn take(&mut self) -> bool {
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
}

/// What a lookup point holds, by ship number, with its moons counted as they come and go.
#[derive(Default)]
struct Table {
    held: HashMap<u64, Held>,
    moons: usize,
    moons_of: HashMap<u32, usize>,
    swept: Option<Instant>,
}

impl Table {
    /// What is held of a ship, to weigh a new record against: the record held, until it has
    /// run out, and with it the moon's word it carried.
    fn known(&self, ship: u64, now: u64) -> Known {
        self.held.get(&ship).filter(|held| whereabouts::holds_off(held.issued, now)).map_or(Known::default(), |held| Known { issued: Some(held.issued), moon: held.moon })
    }

    fn remove(&mut self, ship: u64) {
        if self.held.remove(&ship).is_some() && ship > u64::from(u32::MAX) {
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

    /// Keep a record that has been checked, in the place of the ship's last. Weighed again,
    /// with the lock held and the clock read after the checking (`now`): checking waits on
    /// the source of keys, and meanwhile the record may have run out, or another
    /// announcement of the same ship may have been kept.
    fn keep(&mut self, believed: &Believed, record: Vec<u8>, bounds: &PointBounds, now: u64) -> Result<(), &'static str> {
        if !whereabouts::fresh(believed.issued, now) {
            return Err("the record ran out, or this clock went back, while it was being checked");
        }
        let known = self.known(believed.number, now);
        if known.issued.is_some_and(|seen| believed.issued <= seen) {
            return Err("a record of the ship as new or newer is already held");
        }
        if let (Some((seen, seen_key)), Some((revision, key))) = (known.moon, believed.moon) {
            if revision < seen {
                return Err("a later revision of the moon's key has been seen");
            }
            if revision == seen && key != seen_key {
                return Err("another key has been seen for the moon at this revision");
            }
        }
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
        self.held.insert(believed.number, Held { record, issued: believed.issued, moon: believed.moon });
        Ok(())
    }
}

/// How a lookup point is doing, for whoever runs it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// How far this point's clock is set from the machine's, in milliseconds. Nothing but a
    /// test sets it, to step the clock back or forward; otherwise it is the machine's clock.
    skew: AtomicI64,
    questions: AtomicU64,
    announced: AtomicU64,
    rated: AtomicU64,
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
            table: Mutex::default(),
            connections: AtomicUsize::new(0),
            reading: Arc::new(Semaphore::new(MOST_POINT_READING)),
            in_hand: Arc::new(Semaphore::new(MOST_IN_HAND)),
            in_all: Mutex::new(Bucket::per(cfg.bounds.in_all, cfg.bounds.rate_period)),
            skew: AtomicI64::new(0),
            questions: AtomicU64::new(0),
            announced: AtomicU64::new(0),
            rated: AtomicU64::new(0),
        })
    }

    pub(crate) fn status(&self) -> PointStatus {
        let table = lock(&self.table);
        PointStatus {
            records: table.held.len(),
            moons: table.moons,
            connections: self.connections.load(Ordering::SeqCst),
            in_hand: MOST_IN_HAND - self.in_hand.available_permits(),
            questions: self.questions.load(Ordering::SeqCst),
            announced: self.announced.load(Ordering::SeqCst),
            rated: self.rated.load(Ordering::SeqCst),
        }
    }

    /// The key Urbit ID lists for a galaxy, star or planet, by name, read from this point's
    /// own source of keys. This waits on that source.
    fn key_of(&self, name: &str) -> Option<[u8; 32]> {
        let number = ob::ship_number(name)?;
        self.keys.listing(number).ok().flatten()?.key
    }

    /// Take the records of an announcement, each checked against Urbit ID and kept if it is
    /// believed. What became of each, in order: empty if it was kept, or why not. This waits
    /// on the source of keys, so it is for a thread that may wait.
    #[cfg(test)]
    fn take(&self, records: Vec<Vec<u8>>, each: &Mutex<Bucket>) -> Vec<String> {
        self.check_all(self.admit(records, each), &Mutex::new(false))
    }

    /// Count the records of an announcement against what may be checked in a second, on
    /// this connection and in all. Done as the request arrives, before it waits for a thread
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
    fn check_all(&self, admitted: Vec<Result<Vec<u8>, &'static str>>, gone: &Mutex<bool>) -> Vec<String> {
        admitted
            .into_iter()
            .map(|record| match record.and_then(|record| self.take_one(record, gone)) {
                Ok(()) => String::new(),
                Err(why) => why.to_string(),
            })
            .collect()
    }

    fn take_one(&self, record: Vec<u8>, gone: &Mutex<bool>) -> Result<(), &'static str> {
        const GONE: &str = "whoever announced this has gone";
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
        table.keep(&believed, record, &self.bounds, now)
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

/// Answer one connection under the lookup protocol until it closes.
///
/// What bounds the work a point does for strangers is the count of requests in hand
/// (`MOST_IN_HAND`, point-wide, taken before a byte of a request is read), the size of a
/// request, and the rates of records and questions. The stream limit and receive window set
/// here hold only the credit given from now on: what was given at the handshake (the ships'
/// transport allowance) stays usable, since QUIC cannot take credit back.
pub(crate) async fn serve(point: Arc<Point>, connection: Connection, limit: Duration) {
    let Some(_place) = PointPlace::take(&point) else {
        connection.close(VarInt::from_u32(4), b"this lookup point has as many connections as it may");
        return;
    };
    // Fewer requests at once, and less room for what they carry, than a ship's connection,
    // from here on.
    connection.set_max_concurrent_bi_streams(VarInt::from_u32(MOST_POINT_STREAMS));
    connection.set_receive_window(VarInt::from_u32((MOST_WHERE_BYTES as u32).saturating_mul(MOST_POINT_STREAMS)));
    let each = Arc::new(Mutex::new(Bucket::per(point.bounds.per_connection, point.bounds.rate_period)));
    let questions = Arc::new(Mutex::new(Bucket::new(MOST_QUESTIONS_EACH)));
    // The requests of this connection, so that what they leave waiting stops when it closes.
    let mut answering = tokio::task::JoinSet::new();
    while let Ok((mut send, mut receive)) = connection.accept_bi().await {
        while answering.try_join_next().is_some() {}
        // A place among the requests in hand, point-wide, or the request is refused at once
        // and nothing of it is read.
        let Ok(turn) = point.in_hand.clone().try_acquire_owned() else {
            let _ = receive.stop(VarInt::from_u32(4));
            let _ = send.reset(VarInt::from_u32(4));
            continue;
        };
        answering.spawn(answer(point.clone(), each.clone(), questions.clone(), send, receive, limit, turn));
    }
    // The connection has gone. Requests of it still waiting, for a thread to check on or
    // anything else, stop now and give up their places. A question to the source of keys
    // already under way cannot be stopped; it is one of `MOST_POINT_READING` at most, and its
    // answer is thrown away.
    answering.abort_all();
}

/// One request to a lookup point. `_turn` is its place among the requests in hand.
async fn answer(
    point: Arc<Point>,
    each: Arc<Mutex<Bucket>>,
    questions: Arc<Mutex<Bucket>>,
    mut send: SendStream,
    mut receive: RecvStream,
    limit: Duration,
    _turn: tokio::sync::OwnedSemaphorePermit,
) {
    let refused = |why: &str| WhereReply { body: None, refused: why.to_string() };
    let served = tokio::time::timeout(limit, async {
        let Some(bytes) = net::read_whole(&mut receive, MOST_WHERE_BYTES).await else {
            return send_back(&mut send, &refused("the request could not be read, or was too large")).await;
        };
        // Counted before it is decoded: a request can be all empty records.
        if !net::repeats_within(&bytes, 1, 1, MOST_ANNOUNCED) {
            return send_back(&mut send, &refused("not a request, or one with too many records")).await;
        }
        let reply = match WhereRequest::decode(&*bytes).map(|request| request.body) {
            Ok(Some(where_request::Body::Announce(Announce { records }))) => {
                // Counted against the rates now, before waiting for anything.
                let admitted = point.admit(records, &each);
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
                    let checking = point.clone();
                    let taken = tokio::task::spawn_blocking(move || {
                        let outcomes = checking.check_all(admitted, &gone);
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
                if lock(&questions).take() {
                    let record = point.find(ship).unwrap_or_default();
                    WhereReply { body: Some(where_reply::Body::Found(Found { record })), refused: String::new() }
                } else {
                    refused("too many questions just now; try again later")
                }
            }
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

/// A ship's record, as this runtime last believed it.
struct Cached {
    /// The number this record was kept under, never used for another.
    kept_as: u64,
    issued: u64,
    addresses: Vec<SocketAddr>,
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

    /// The record held for a ship, by the number it was kept under, with its addresses, if it
    /// is still good and they have not failed. A record that has run out is let go of here.
    fn addresses(&mut self, ship: &str, now: u64) -> Option<(u64, Vec<SocketAddr>)> {
        match self.held.get(ship) {
            Some(held) if !whereabouts::holds_off(held.issued, now) => {
                self.held.remove(ship);
                None
            }
            Some(held) if !held.failed && whereabouts::fresh(held.issued, now) => Some((held.kept_as, held.addresses.clone())),
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
            return Err("a record of the ship as new or newer is already held");
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
        self.held.insert(believed.ship, Cached { kept_as, issued: believed.issued, addresses: believed.addresses, failed: false });
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
    /// The ships whose records the point has taken.
    announced: HashSet<String>,
}

/// A runtime's means of finding other ships through lookup points, and of announcing its own.
pub(crate) struct Finder {
    lookup: Lookup,
    endpoint: Endpoint,
    client: quinn::ClientConfig,
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
}

impl Finder {
    pub(crate) fn new(lookup: Lookup, cfg: &NetConfig, endpoint: Endpoint, provider: &Arc<CryptoProvider>) -> std::io::Result<Finder> {
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
        let resolver = lookup.resolver.clone().unwrap_or_else(|| Arc::new(SystemResolver));
        Ok(Finder {
            lookup,
            endpoint,
            client,
            resolver,
            limit: cfg.request_timeout,
            retry_delay: cfg.retry_delay,
            max_retry_delay: cfg.max_retry_delay,
            resolved: Mutex::default(),
            resolving: Arc::new(Semaphore::new(MOST_RESOLVING)),
            points: Mutex::default(),
            floors: Mutex::new(Floors::new(MOST_FLOORS)),
            asked: Mutex::default(),
            asking: Mutex::default(),
            lanes: Mutex::default(),
            last_issued: AtomicU64::new(0),
            trouble: Mutex::default(),
            clock: Box::new(now_ms),
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
        let mut points = lock(&self.points);
        if !points.contains_key(&addr) && points.len() >= MOST_POINTS {
            // Forget points nothing is using and whose connections have closed.
            points.retain(|_, kept| Arc::strong_count(kept) > 1 || kept.try_lock().map_or(true, |held| held.as_ref().is_some_and(|c| c.close_reason().is_none())));
            if points.len() >= MOST_POINTS {
                return Err("this runtime is already talking to as many lookup points as it may".into());
            }
        }
        Ok(points.entry(addr).or_default().clone())
    }

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

    /// Send one request to the point at one address and read its reply.
    async fn over(&self, addr: SocketAddr, request: &[u8]) -> Result<WhereReply, String> {
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
        let lost = |e: &dyn fmt::Display| format!("the lookup point at {addr} was lost: {e}");
        let (mut send, mut receive) = connection.open_bi().await.map_err(|e| lost(&e))?;
        send.write_all(request).await.map_err(|e| lost(&e))?;
        send.finish().map_err(|e| lost(&e))?;
        let answer = net::read_whole(&mut receive, MOST_WHERE_BYTES).await.ok_or_else(|| format!("the answer of the lookup point at {addr} could not be read, or was too large"))?;
        WhereReply::decode(&*answer).map_err(|_| format!("the answer of the lookup point at {addr} made no sense"))
    }

    /// Send one request to the lookup point for a galaxy, trying each of its addresses in
    /// turn, all within `deadline`.
    async fn exchange(&self, galaxy: u8, request: WhereRequest, deadline: tokio::time::Instant) -> Result<WhereReply, String> {
        let request = request.encode_to_vec();
        let mut why = format!("no lookup point is known for ~{}", galaxy_name(galaxy));
        for addr in self.points_for(galaxy, deadline).await? {
            match tokio::time::timeout(try_limit(deadline), self.over(addr, &request)).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(failed)) => why = failed,
                Err(_) => why = format!("the lookup point at {addr} did not answer in time"),
            }
            self.forget_point(addr);
        }
        Err(why)
    }

    /// The clock records are weighed by, in milliseconds since 1970.
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The record held for a ship, by the number it was kept under, and its addresses, if
    /// there is one, it is still good, and they have not failed.
    pub(crate) fn cached(&self, ship: &str) -> Option<(u64, Vec<SocketAddr>)> {
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
    fn known(&self, ship: &str, directory: &Directory) -> (Known, u64) {
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
    pub(crate) async fn ask(self: &Arc<Self>, directory: &Arc<Directory>, ship: &str, deadline: tokio::time::Instant) -> Result<(u64, Vec<SocketAddr>), NetError> {
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
    /// the network runs: each at start, then every `announce_every`, and any ship that is new
    /// at once. A point that is down or refuses is tried again after a wait that doubles.
    pub(crate) async fn announce(self: Arc<Self>, runtime: Arc<Runtime>, addresses: Vec<SocketAddr>) {
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
                    let new = ships.iter().any(|ship| !lane.announced.contains(ship));
                    let due = lane.next_at.is_none_or(|at| Instant::now() >= at) || (new && lane.delay.is_zero());
                    if lane.busy || !due {
                        continue;
                    }
                    lane.busy = true;
                }
                tokio::spawn(self.clone().announce_galaxy(runtime.clone(), galaxy, ships, addresses.clone()));
            }
            tokio::time::sleep(ANNOUNCE_TICK).await;
        }
    }

    /// Announce the ships of one galaxy, and settle when to do so again.
    async fn announce_galaxy(self: Arc<Self>, runtime: Arc<Runtime>, galaxy: u8, ships: Vec<String>, addresses: Vec<SocketAddr>) {
        let mut why = None;
        for some in ships.chunks(MOST_ANNOUNCED) {
            let mut named = Vec::new();
            let mut records = Vec::new();
            for ship in some {
                let Ok(key) = runtime.signing_key(ship) else { continue };
                match whereabouts::sign(ship, &addresses, self.next_issued(), &key, runtime.moon_proof(ship)) {
                    Ok(record) => {
                        named.push(ship);
                        records.push(record);
                    }
                    Err(failed) => why = Some(format!("~{ship}: no record could be made: {failed}")),
                }
            }
            let count = records.len();
            let request = WhereRequest { body: Some(where_request::Body::Announce(Announce { records })) };
            let deadline = tokio::time::Instant::now() + self.limit;
            match self.exchange(galaxy, request, deadline).await {
                Ok(WhereReply { body: Some(where_reply::Body::Announced(Announced { outcomes })), .. }) if outcomes.len() == count => {
                    for (ship, outcome) in named.iter().zip(&outcomes) {
                        if !outcome.is_empty() {
                            why = Some(format!("~{ship}: the lookup point did not keep its record: {}", outcome.chars().take(200).collect::<String>()));
                        }
                    }
                }
                Ok(WhereReply { refused, body: None }) => why = Some(format!("the lookup point for ~{} refused: {}", galaxy_name(galaxy), refused.chars().take(200).collect::<String>())),
                Ok(_) => why = Some(format!("the answer of the lookup point for ~{} made no sense", galaxy_name(galaxy))),
                Err(failed) => why = Some(failed),
            }
        }
        let mut lanes = lock(&self.lanes);
        let lane = lanes.entry(galaxy).or_default();
        lane.busy = false;
        match why {
            None => {
                lane.next_at = Some(Instant::now() + self.lookup.announce_every);
                lane.delay = Duration::ZERO;
                lane.announced = ships.into_iter().collect();
            }
            Some(why) => {
                lane.delay = if lane.delay.is_zero() { self.retry_delay } else { (lane.delay * 2).min(self.max_retry_delay) };
                lane.next_at = Some(Instant::now() + lane.delay);
                drop(lanes);
                self.worried(why);
            }
        }
    }
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
/// Nothing a point says is taken on its word, so who it is does not matter.
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
        Point::new(PointConfig { keys: Arc::new(Everyone), galaxies, bounds }, &rustls::crypto::ring::default_provider()).unwrap()
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
                let (kept_as, _) = floors.addresses(&name(ship), now).unwrap();
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
        table.keep(&believed(PLANET, ahead), record(PLANET, ahead), &bounds, ahead).unwrap();
        // An older record, good by the clock as it is now, does not take its place.
        assert_eq!(table.keep(&believed(PLANET, now), record(PLANET, now), &bounds, now), Err("a record of the ship as new or newer is already held"));
        // And when the table is full, sweeping does not take the record dated ahead for one
        // that has run out.
        let other = PLANET + (1 << 16);
        assert_eq!(table.keep(&believed(other, now), record(other, now), &bounds, now), Err("this lookup point is full; try again later"));
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
        Arc::new(Point::new(PointConfig { keys: gate.clone(), galaxies: None, bounds: PointBounds::default() }, &rustls::crypto::ring::default_provider()).unwrap())
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
            std::thread::spawn(move || point.check_all(point.admit(vec![record(PLANET, now_ms())], &plenty()), &gone))
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
            std::thread::spawn(move || point.check_all(point.admit(vec![record(PLANET, now_ms())], &plenty()), &gone))
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
        table.keep(&believed, second.clone(), &PointBounds::default(), point.now()).unwrap();
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
        table.keep(&believed, second.clone(), &PointBounds::default(), point.now()).unwrap();
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
        let (tried, _) = floors.addresses(&name(PLANET), now).unwrap();
        // While R1's addresses are being tried, R2 takes its place. R1 then fails: R2 is left
        // as it is, and its addresses are handed out.
        let second = whereabouts::check(&record(PLANET, now), &listed, Known::default(), now).unwrap();
        floors.keep(second, now).unwrap();
        floors.failed(&name(PLANET), tried);
        let (newer, _) = floors.addresses(&name(PLANET), now).unwrap();
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
        let (tried, _) = floors.addresses(&name(PLANET), now).unwrap();
        assert_eq!(floors.addresses(&name(PLANET), issued + whereabouts::LIFETIME_MS), None);
        let elsewhere: SocketAddr = "198.51.100.9:4433".parse().unwrap();
        let other = whereabouts::sign(&name(PLANET), &[elsewhere], issued, &key_of(PLANET), None).unwrap();
        floors.keep(whereabouts::check(&other, &listed, Known::default(), now).unwrap(), now).unwrap();
        floors.failed(&name(PLANET), tried);
        assert_eq!(floors.addresses(&name(PLANET), now).map(|(_, addresses)| addresses), Some(vec![elsewhere]));

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
        let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let endpoint = {
            let _entered = tokio.enter();
            Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut finder = Finder::new(Lookup::default(), &NetConfig::default(), endpoint, &provider).unwrap();
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
        Arc::new(Point::new(PointConfig { keys, galaxies: None, bounds: PointBounds::default() }, &rustls::crypto::ring::default_provider()).unwrap())
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
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: Some(vec![]), bounds: PointBounds::default() }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { in_all: 0, ..PointBounds::default() } }), ..Lookup::default() },
            Lookup { serve: Some(PointConfig { keys: Arc::new(Everyone), galaxies: None, bounds: PointBounds { rate_period: Duration::ZERO, ..PointBounds::default() } }), ..Lookup::default() },
        ] {
            assert!(bad.sound().is_err(), "{bad:?}");
        }
    }
}
