//! Carrying the packets of two ships that cannot reach each other directly.
//!
//! Some home routers give a machine inside a different outside port for each address it sends
//! to. The port its lookup point sees is then not the one its packets toward a caller leave
//! from, and the caller's packets arrive at a port that lets in only the point: sending at the
//! same moment (an introduction, see `crate::lookup`) cannot open a way. What both ships can
//! always reach is the point itself, since each keeps a connection open to it. So the point
//! carries their packets: each ship sends to the point's own port, and the point sends each
//! packet on, unchanged, to the other.
//!
//! The connection between the two ships is still an ordinary ship-to-ship QUIC connection, end
//! to end, with every key check there is. The point sees only encrypted packets: it can drop,
//! delay, repeat or misdeliver them, and nothing more. Nothing it says about a session is
//! believed about who anyone is.
//!
//! On the wire a relayed packet is one UDP datagram to or from the point's ordinary port: one
//! byte (`KIND`), the sixteen bytes that name the session, then the ships' QUIC packet as it
//! is. The first byte has its two top bits clear. A QUIC packet's first byte has the top bit
//! set (a long header) or the second (the fixed bit), unless the fixed bit has been cleared as
//! a "grease", which QUIC allows only toward a peer that has said it takes such packets. A
//! runtime that relays tells QUIC not to grease (`EndpointConfig::grease_quic_bit`): then it
//! never says it takes them, so no peer clears the bit toward it, and its QUIC endpoint refuses
//! any packet with the bit clear. So no packet its endpoint would take begins with `KIND`, by
//! construction and not by odds. (`net::PUNCH`, the packet that opens a router, begins with a
//! nought, which `KIND` is not.)
//!
//! Two jobs are done here, both by one wrapper (`Relayed`) around the runtime's UDP socket,
//! put in place whenever the runtime has lookup settings and not otherwise:
//!
//! At a ship, a session it has registered is given a made-up address, and QUIC is told to dial,
//! or sees packets arrive from, that address. A packet QUIC sends to a made-up address is
//! wrapped and sent to the session's point; one with no session is dropped. A made-up address
//! is never handed to the real socket. A datagram from a point that carries `KIND` and a
//! registered session's name, from that session's point, is unwrapped and shown to QUIC as
//! coming from the made-up address; one that carries `KIND` and matches no session goes no
//! further. Everything else passes as it is, the ship's own connection to that same point
//! included. A session is registered by the caller once its point has answered its own
//! request, and by the ship called once it has believed the caller's record by its own checks.
//!
//! At a point set to relay, a datagram carrying `KIND` whose session is live, and whose source
//! is exactly one of the two addresses pinned when the session was made, is sent to the other
//! pinned address unchanged, if the session's sides are still there and the byte allowances
//! let it; otherwise it is dropped. Either way it never reaches QUIC. This is done where the
//! datagram is received, with a send that never waits: nothing is queued, nothing waits, and
//! there is no task per session. Which point carries a session is held in one place at each
//! end: the caller's is the point its request was answered by, and the called ship's is the
//! point the session's push came from.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::lock;
use crate::lookup::Point;

/// The first byte of a relayed datagram: neither of its two top bits is set, and it is not
/// nought.
pub const KIND: u8 = 0x15;

/// The length of what goes in front of a relayed packet: `KIND` and the session's name.
pub const HEADER: usize = 1 + 16;

/// What names a session: sixteen bytes from the system's randomness, given by the point.
pub type SessionId = [u8; 16];

/// A session nothing has passed through for this long is let go of, at a point and at a ship.
pub const IDLE: Duration = Duration::from_secs(30);

/// At a point, packets go toward a caller only if it has itself sent one on the session within
/// this long. (`IDLE` and this are the same thirty seconds, said for two different things.)
pub const CALLER_HEARD: Duration = Duration::from_secs(30);

/// At a point, for this long after a session is made, packets may go toward the caller before
/// it has sent any: room for the ship called to answer first. The caller dials straight after
/// it is answered, so this is seldom used.
pub const GRACE: Duration = Duration::from_secs(5);

/// At a ship: sessions registered as the ship called, in all, and for any one caller ship; and
/// sessions registered as the caller, in all.
pub const MOST_CALLED: usize = 64;
pub const MOST_CALLED_EACH: usize = 8;
pub const MOST_CALLING: usize = 256;

/// At a ship, a made-up address that is let go of is not given to another session while a
/// `Leg` that owns it is alive, and then not until nothing has been sent to it or come from it
/// for the connection idle time (`idle_timeout`) and this much more; a send by QUIC to it
/// counts. That is what this establishes, and no more: QUIC's closing and draining periods are
/// three probe timeouts, which depend on the path, so it is not a proof that everything that
/// once knew the address has let it go. If a stale packet ever did cross a reuse, it would be
/// another connection's QUIC packet to the far ship: it cannot be decrypted there, and no key
/// check depends on it.
pub const RETIRE_MARGIN: Duration = Duration::from_secs(60);

/// How many callee ships a point keeps a byte allowance for. One with a live session always has
/// one; past this, those whose allowance is whole again and who have no session are forgotten
/// (which gives back nothing a new allowance would not), and if that is not enough no session
/// is made for a new ship.
const MOST_ALLOWANCES: usize = 4096;

/// How many times one call to receive goes back to the socket when everything it was given was
/// relayed on or dropped, before it lets other work run and comes back. So a flood of relayed
/// packets cannot keep the endpoint from its other work.
const MOST_ROUNDS: usize = 16;

/// The session a datagram names, if it is a relayed one: `KIND` first, then the name, then
/// something.
pub fn session_of(datagram: &[u8]) -> Option<SessionId> {
    if datagram.len() <= HEADER || datagram[0] != KIND {
        return None;
    }
    datagram[1..HEADER].try_into().ok()
}

/// A packet with the header that names its session in front.
pub fn wrapped(id: &SessionId, packet: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(HEADER + packet.len());
    datagram.push(KIND);
    datagram.extend_from_slice(id);
    datagram.extend_from_slice(packet);
    datagram
}

/// A made-up address, for a socket of one family, by the port that tells it from the others.
///
/// For IPv4, the limited broadcast address, `255.255.255.255`: no record may name it (records
/// refuse broadcast addresses), routers never pass it on beyond the local link, and a socket
/// that has not asked for broadcast (the runtime's never does) cannot send to it at all, so even
/// a mistake here would be refused by the system. For IPv6, `ff00::1`: a multicast address
/// (records refuse multicast) of the reserved scope nought, which nodes must not send to and
/// must drop (RFC 4291). An IPv6 address cannot be used on an IPv4 socket: QUIC refuses to
/// dial one (`InvalidRemoteAddress`), which is why the family follows the socket's.
fn made_up(v6: bool, port: u16) -> SocketAddr {
    match v6 {
        false => SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port),
        true => SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1)), port),
    }
}

/// Whether an address is of the kind made up for sessions, of either family (an IPv4 one also
/// as it is written on an IPv6 socket). Such an address is never sent to on the real socket,
/// and a datagram that says it comes from one is dropped: no network delivers from it, so it
/// can only be forged, and it must not pass for a session's packets.
pub fn is_made_up(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_broadcast(),
        IpAddr::V6(ip) => ip.segments()[0] == 0xff00 || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_broadcast()),
    }
}

/// Whose a caller is, for counting what it may have: a moon's planet, or the ship itself.
/// Moons are free to whoever has a planet, so a moon is counted as its planet.
pub fn owner(ship: u64) -> u64 {
    if ship > u64::from(u32::MAX) { u64::from(urbit_id::ob::moon_parent(ship)) } else { ship }
}

/// An address as it is, with an IPv4 address that came written as IPv6 written as IPv4.
fn plain(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

// At a point.

/// How much a lookup point that relays carries, and for whom. What it carries is what its
/// operator pays for, so every figure here is a bound on that bill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayBounds {
    /// Bytes carried for any one attending ship, as the ship called, in both directions of all
    /// its sessions together: `ship_burst` at a stroke, and `ship_rate` earned back each
    /// second, up to `ship_burst` again.
    pub ship_rate: u64,
    pub ship_burst: u64,
    /// Bytes carried in all, the same way.
    pub point_rate: u64,
    pub point_burst: u64,
    /// Sessions live for any one ship called, for any one caller ship, for any one pair of
    /// caller and ship called (two, so that a caller that lost its session can make another
    /// before the old one idles out), and in all. For the caller's counts (and its sessions
    /// made), a moon counts as its planet: moons are free to whoever has a planet.
    pub sessions_each: usize,
    pub sessions_from: usize,
    pub sessions_pair: usize,
    pub sessions: usize,
    /// Sessions made for any one caller ship, and in all: as many as this at a stroke, and as
    /// many earned back each `rate_period` of the point.
    pub made_each: u32,
    pub made: u32,
}

impl Default for RelayBounds {
    fn default() -> Self {
        RelayBounds {
            ship_rate: 128 << 10,
            ship_burst: 256 << 10,
            point_rate: 4 << 20,
            point_burst: 8 << 20,
            sessions_each: 16,
            sessions_from: 16,
            sessions_pair: 2,
            sessions: 1024,
            made_each: 4,
            made: 512,
        }
    }
}

impl RelayBounds {
    /// Whether these make sense, and why not if they do not. A burst smaller than a datagram
    /// would carry nothing at all.
    pub(crate) fn sound(&self) -> Result<(), String> {
        if self.ship_rate == 0 || self.point_rate == 0 || self.ship_burst < 2048 || self.point_burst < 2048 {
            return Err("a relay's byte rates must be more than nothing, and its bursts at least 2,048 bytes".into());
        }
        if self.sessions_each == 0 || self.sessions_from == 0 || self.sessions_pair == 0 || self.sessions == 0 || self.made_each == 0 || self.made == 0 {
            return Err("a relay's bounds on sessions must each be more than nothing".into());
        }
        Ok(())
    }
}

/// A byte allowance: so many bytes at a stroke (`most`), and so many earned back each second,
/// up to that again. In any span of T seconds it lets through at most `most + per_second * T`:
/// it holds at most `most` when the span begins, and earns at most `per_second * T` in it.
#[derive(Clone, Debug)]
struct Allowance {
    left: f64,
    most: f64,
    per_second: f64,
    at: Instant,
}

impl Allowance {
    fn new(burst: u64, per_second: u64, now: Instant) -> Allowance {
        Allowance { left: burst as f64, most: burst as f64, per_second: per_second as f64, at: now }
    }

    /// What it holds at `now`, earned back so far included. Time is never taken to run back.
    fn holds(&mut self, now: Instant) -> f64 {
        if now > self.at {
            self.left = (self.left + now.duration_since(self.at).as_secs_f64() * self.per_second).min(self.most);
            self.at = now;
        }
        self.left
    }

    fn whole(&mut self, now: Instant) -> bool {
        self.holds(now) >= self.most
    }

    /// Move the refill stamp up to `now` without earning anything for the time since it was
    /// last moved: for the time between charging a packet and sending it, which earns nothing.
    fn restamp(&mut self, now: Instant) {
        if now > self.at {
            self.at = now;
        }
    }
}

/// One session a point carries packets for.
struct Session {
    /// The ship called, and the caller's owner (a moon's planet, or the caller itself), by
    /// number.
    callee: u64,
    caller: u64,
    /// The connection the ship called attended on when the session was made, by the point's
    /// number for it. Packets go toward that ship only while it still attends there.
    connection: u64,
    /// The two pinned addresses: the remote address of the connection the ship called attends
    /// on, and of the connection the caller's request came on. Nothing ever changes them.
    callee_at: SocketAddr,
    caller_at: SocketAddr,
    made: Instant,
    /// When the caller last sent a packet on the session from its pinned address.
    heard: Option<Instant>,
    /// When a packet was last carried, or the session made.
    carried: Instant,
}

/// What a point has carried, and what it has dropped and why, in bytes, since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCounts {
    /// Carried on to the other side.
    pub carried: u64,
    /// Naming no session that is live.
    pub unknown: u64,
    /// From an address that is neither of the session's two.
    pub stranger: u64,
    /// Toward a side that is not there: a ship called that no longer attends on the connection
    /// the session was made on, or a caller that has sent nothing for `CALLER_HEARD`.
    pub absent: u64,
    /// Over the allowance of the ship called, or over the point's.
    pub over_ship: u64,
    pub over_point: u64,
    /// Let through, but the socket would not take it at once.
    pub unsent: u64,
}

/// The sessions a point carries packets for, with their counts and allowances. Kept with the
/// point's table, under its lock: a session is made, weighed, and dropped with the table held,
/// and a packet is sent on with the table held, so none goes on a session the point has let go
/// of.
#[derive(Default)]
pub(crate) struct Sessions {
    bounds: Option<RelayBounds>,
    live: HashMap<SessionId, Session>,
    of_callee: HashMap<u64, usize>,
    of_caller: HashMap<u64, usize>,
    /// By (caller's owner, ship called).
    of_pair: HashMap<(u64, u64), usize>,
    allowances: HashMap<u64, Allowance>,
    all: Option<Allowance>,
    /// Bytes carried for each ship called while it has a session.
    carried_for: HashMap<u64, u64>,
    pub(crate) counts: RelayCounts,
}

/// What a point does with a relayed datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Carry {
    /// Carried on, to this address.
    To(SocketAddr),
    /// Dropped, for this reason.
    Dropped(&'static str),
}

impl Sessions {
    pub(crate) fn new(bounds: Option<RelayBounds>, now: Instant) -> Sessions {
        Sessions { bounds, all: bounds.map(|b| Allowance::new(b.point_burst, b.point_rate, now)), ..Sessions::default() }
    }

    /// Whether this point relays at all.
    pub(crate) fn relays(&self) -> bool {
        self.bounds.is_some()
    }

    /// How many sessions are live.
    pub(crate) fn len(&self) -> usize {
        self.live.len()
    }

    /// Bytes carried for each ship called that has a session, by number, lowest first.
    pub(crate) fn carried_for(&self) -> Vec<(u64, u64)> {
        let mut carried: Vec<(u64, u64)> = self.carried_for.iter().map(|(ship, bytes)| (*ship, *bytes)).collect();
        carried.sort();
        carried
    }

    /// The sessions live, each with its ship called, caller, and two pinned addresses. For tests.
    #[cfg(test)]
    pub(crate) fn list(&self) -> Vec<(SessionId, u64, u64, SocketAddr, SocketAddr)> {
        self.live.iter().map(|(id, session)| (*id, session.callee, session.caller, session.callee_at, session.caller_at)).collect()
    }

    fn remove(&mut self, id: &SessionId) {
        let Some(session) = self.live.remove(id) else { return };
        let less = |counts: &mut HashMap<u64, usize>, ship: u64| -> bool {
            let gone = counts.get_mut(&ship).is_some_and(|count| {
                *count -= 1;
                *count == 0
            });
            if gone {
                counts.remove(&ship);
            }
            gone
        };
        if less(&mut self.of_callee, session.callee) {
            self.carried_for.remove(&session.callee);
        }
        less(&mut self.of_caller, session.caller);
        let pair = (session.caller, session.callee);
        if self.of_pair.get_mut(&pair).is_some_and(|count| {
            *count -= 1;
            *count == 0
        }) {
            self.of_pair.remove(&pair);
        }
    }

    fn remove_where(&mut self, gone: impl Fn(&Session) -> bool) {
        let ids: Vec<SessionId> = self.live.iter().filter(|(_, session)| gone(session)).map(|(id, _)| *id).collect();
        for id in ids {
            self.remove(&id);
        }
    }

    /// Let go of the sessions nothing has been carried on for `IDLE`.
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.remove_where(|session| now.saturating_duration_since(session.carried) >= IDLE);
    }

    /// The connection `connection` has closed: sessions toward a ship that attended on it end.
    pub(crate) fn callee_gone(&mut self, connection: u64) {
        self.remove_where(|session| session.connection == connection);
    }

    /// A newer record of `ship` was kept, naming `connection`: its sessions made toward another
    /// connection end.
    pub(crate) fn callee_moved(&mut self, ship: u64, connection: u64) {
        self.remove_where(|session| session.callee == ship && session.connection != connection);
    }

    /// The point no longer holds a record of `ship`: its sessions end.
    pub(crate) fn callee_dropped(&mut self, ship: u64) {
        self.remove_where(|session| session.callee == ship);
    }

    /// Whether there is room for one more session from `caller` to `callee`, once sessions
    /// that have gone idle are let go of. Why not, if not. A moon caller counts as its planet.
    pub(crate) fn room(&mut self, id: &SessionId, callee: u64, caller: u64, now: Instant) -> Result<(), &'static str> {
        let bounds = self.bounds.ok_or(NO_RELAY)?;
        let caller = owner(caller);
        self.sweep(now);
        if self.live.contains_key(id) {
            return Err("a session of that name is already carried; try again");
        }
        if self.live.len() >= bounds.sessions {
            return Err("this lookup point carries as many sessions as it may; try again later");
        }
        if self.of_callee.get(&callee).copied().unwrap_or(0) >= bounds.sessions_each {
            return Err("this lookup point carries as many sessions for that ship as it may; try again later");
        }
        if self.of_caller.get(&caller).copied().unwrap_or(0) >= bounds.sessions_from {
            return Err("this lookup point carries as many sessions from that ship as it may; try again later");
        }
        if self.of_pair.get(&(caller, callee)).copied().unwrap_or(0) >= bounds.sessions_pair {
            return Err("this lookup point carries as many sessions between those two ships as it may; try again later");
        }
        if !self.allowances.contains_key(&callee) && self.allowances.len() >= MOST_ALLOWANCES {
            let Sessions { allowances, of_callee, .. } = self;
            allowances.retain(|ship, allowance| of_callee.contains_key(ship) || !allowance.whole(now));
            if allowances.len() >= MOST_ALLOWANCES {
                return Err("this lookup point is keeping count for as many ships as it may; try again later");
            }
        }
        Ok(())
    }

    /// Make a session, `room` having said there is room, with the same hold of the table.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make(&mut self, id: SessionId, callee: u64, caller: u64, connection: u64, callee_at: SocketAddr, caller_at: SocketAddr, now: Instant) -> Result<(), &'static str> {
        let bounds = self.bounds.ok_or(NO_RELAY)?;
        if self.live.contains_key(&id) {
            return Err("a session of that name is already carried; try again");
        }
        let caller = owner(caller);
        *self.of_pair.entry((caller, callee)).or_default() += 1;
        self.live.insert(id, Session { callee, caller, connection, callee_at: plain(callee_at), caller_at: plain(caller_at), made: now, heard: None, carried: now });
        *self.of_callee.entry(callee).or_default() += 1;
        *self.of_caller.entry(caller).or_default() += 1;
        self.allowances.entry(callee).or_insert_with(|| Allowance::new(bounds.ship_burst, bounds.ship_rate, now));
        self.carried_for.entry(callee).or_default();
        Ok(())
    }

    /// Weigh a relayed datagram of `len` bytes naming `id`, from `from`, at `now`, and if it is
    /// to be carried, hand it to `send` with the address it goes to, all with the table held.
    /// `attends` says whether a ship still attends on a connection, judged as the table judges
    /// it where an introduction is passed on. `clock` is the relay's clock, read again after the
    /// send.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn carry(&mut self, id: &SessionId, from: SocketAddr, len: usize, now: Instant, clock: &dyn Fn() -> Instant, attends: &dyn Fn(u64, u64) -> bool, send: &mut dyn FnMut(SocketAddr) -> bool) -> Carry {
        let len = len as u64;
        let from = plain(from);
        let Some(session) = self.live.get_mut(id) else {
            self.counts.unknown += len;
            return Carry::Dropped("no such session");
        };
        // A session nothing has passed through for the idle time is gone, whenever that is
        // seen.
        let idle = now.saturating_duration_since(session.carried) >= IDLE;
        let side = if idle {
            None
        } else if from == session.caller_at {
            // The caller is there: it has just sent from its pinned address.
            session.heard = Some(now);
            Some(Ok((session.callee_at, attends(session.callee, session.connection))))
        } else if from == session.callee_at {
            let heard = session.heard.is_some_and(|heard| now.saturating_duration_since(heard) < CALLER_HEARD);
            Some(Err((session.caller_at, heard || now.saturating_duration_since(session.made) < GRACE)))
        } else {
            self.counts.stranger += len;
            return Carry::Dropped("not from either of the session's addresses");
        };
        let callee = session.callee;
        let to = match side {
            None => {
                self.remove(id);
                self.counts.unknown += len;
                return Carry::Dropped("no such session");
            }
            // Toward the ship called only while it still attends on the connection the session
            // was made toward. Once it does not, the session is over.
            Some(Ok((_, false))) => {
                self.remove(id);
                self.counts.absent += len;
                return Carry::Dropped("the ship called no longer attends on that connection");
            }
            // Toward the caller only while it has sent lately, or in the grace after making.
            Some(Err((_, false))) => {
                self.counts.absent += len;
                return Carry::Dropped("the caller has sent nothing lately");
            }
            Some(Ok((to, true)) | Err((to, true))) => to,
        };
        // Never to a made-up address, whatever is pinned.
        if is_made_up(&to) {
            self.counts.stranger += len;
            return Carry::Dropped("not an address that can be sent to");
        }
        let (Some(allowance), Some(all)) = (self.allowances.get_mut(&callee), self.all.as_mut()) else {
            self.counts.over_ship += len;
            return Carry::Dropped("no allowance is kept for that ship");
        };
        if allowance.holds(now) < len as f64 {
            self.counts.over_ship += len;
            return Carry::Dropped("over the allowance of the ship called");
        }
        if all.holds(now) < len as f64 {
            self.counts.over_point += len;
            return Carry::Dropped("over the point's allowance");
        }
        allowance.left -= len as f64;
        all.left -= len as f64;
        let sent = send(to);
        // Nothing is earned for the time the send took: the clock is read again, with the table
        // still held, and both allowances' refill stamps moved up to it. So a packet charged
        // before an interval and sent inside it was paid for out of what the allowance held then,
        // with nothing earned meanwhile, and B + r x T holds for every interval.
        let after = clock();
        if let Some(allowance) = self.allowances.get_mut(&callee) {
            allowance.restamp(after);
        }
        if let Some(all) = self.all.as_mut() {
            all.restamp(after);
        }
        if !sent {
            self.counts.unsent += len;
            return Carry::Dropped("the socket would not take it at once");
        }
        // Only a packet actually sent keeps the session from going idle.
        if let Some(session) = self.live.get_mut(id) {
            session.carried = now;
        }
        self.counts.carried += len;
        *self.carried_for.entry(callee).or_default() += len;
        Carry::To(to)
    }
}

/// Why a point that does not relay refuses to.
pub const NO_RELAY: &str = "this lookup point does not relay";

// At a ship.

/// Which end of a session a ship is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Side {
    /// It asked its callee's point, and was answered.
    Calling,
    /// It was called: the caller (by name), and the connection to its point the session came
    /// on, by QUIC's number for it.
    Called { caller: String, pushed_on: usize },
}

/// A session a ship has registered.
struct Registered {
    id: SessionId,
    /// The point that carries it.
    point: SocketAddr,
    side: Side,
    /// When a packet last went through it, either way, or it was registered.
    last: Instant,
}

#[derive(Default)]
struct Legs {
    /// By made-up address.
    live: HashMap<SocketAddr, Registered>,
    ids: HashMap<SessionId, SocketAddr>,
    /// Made-up addresses let go of, with when anything was last sent to or came from each.
    retired: HashMap<SocketAddr, Instant>,
    /// The connections to points that sessions may be pushed on: open, and heard on now.
    open: HashSet<usize>,
    /// Made-up addresses a `Leg` still owns, whatever state its session is in, each with the
    /// name of the session whose `Leg` it is: never given to another session while it does.
    owned: HashMap<SocketAddr, SessionId>,
    /// The port of the made-up address given last.
    next: u16,
    /// The highest port given: all of them, unless a test makes the range small.
    ports: Option<u16>,
}

impl Legs {
    fn release(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(registered) = self.live.remove(&addr) {
            self.ids.remove(&registered.id);
            self.retired.insert(addr, now.max(registered.last));
        }
    }

    /// A `Leg` for session `id` at `addr` is dropped: its own registration is let go of (and
    /// not another's that was given the same address since), and the address is no longer
    /// owned. Its quarantine runs from now, or from when it was last touched, if later.
    fn release_leg(&mut self, addr: SocketAddr, id: &SessionId, now: Instant) {
        if self.live.get(&addr).is_some_and(|registered| registered.id == *id) {
            self.release(addr, now);
        }
        if self.owned.get(&addr) == Some(id) {
            self.owned.remove(&addr);
            let touched = self.retired.entry(addr).or_insert(now);
            *touched = now.max(*touched);
        }
    }

    fn release_where(&mut self, gone: impl Fn(&Registered) -> bool, now: Instant) {
        let addrs: Vec<SocketAddr> = self.live.iter().filter(|(_, registered)| gone(registered)).map(|(addr, _)| *addr).collect();
        for addr in addrs {
            self.release(addr, now);
        }
    }

    /// The session a datagram from `from` naming `id` belongs to, if this ship registered it and
    /// it came from that session's point: its made-up address. `Err` if this ship registered
    /// the session and the datagram is not for it.
    fn arrived(&mut self, id: &SessionId, from: SocketAddr, now: Instant) -> Option<Result<SocketAddr, ()>> {
        let addr = *self.ids.get(id)?;
        let registered = self.live.get_mut(&addr).expect("each name has its address");
        if plain(from) != registered.point {
            return Some(Err(()));
        }
        if now.saturating_duration_since(registered.last) >= IDLE {
            self.release(addr, now);
            return Some(Err(()));
        }
        registered.last = now;
        Some(Ok(addr))
    }

    /// Where a packet QUIC sends to the made-up address `to` goes: the session's point and
    /// name, if it is live. A made-up address with no session left is remembered as touched.
    fn leaving(&mut self, to: SocketAddr, now: Instant) -> Option<(SocketAddr, SessionId)> {
        match self.live.get_mut(&to) {
            Some(registered) if now.saturating_duration_since(registered.last) < IDLE => {
                registered.last = now;
                Some((registered.point, registered.id))
            }
            Some(_) => {
                self.release(to, now);
                None
            }
            None => {
                if let Some(touched) = self.retired.get_mut(&to) {
                    *touched = now.max(*touched);
                }
                None
            }
        }
    }
}

/// A session a ship is calling through, registered for as long as this is held: dropping it
/// lets the session go.
pub(crate) struct Leg {
    relayed: Arc<Relayed>,
    /// The session's made-up address: what QUIC dials.
    pub(crate) addr: SocketAddr,
    /// The session's name: what this releases, and nothing else.
    id: SessionId,
}

impl Drop for Leg {
    fn drop(&mut self) {
        let now = self.relayed.now();
        lock(&self.relayed.legs).release_leg(self.addr, &self.id, now);
    }
}

impl fmt::Debug for Leg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leg").field("addr", &self.addr).finish()
    }
}

/// What a ship's sessions are, and what has passed through them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStatus {
    /// Sessions registered as the caller, and as the ship called.
    pub calling: usize,
    pub called: usize,
    /// Relayed datagrams shown to QUIC, unwrapped, and those that went no further (no such
    /// session here, not from its point, or from a made-up address).
    pub delivered: u64,
    pub dropped: u64,
    /// Packets QUIC sent to made-up addresses that were wrapped and sent to a point, and those
    /// dropped for want of a session.
    pub sent: u64,
    pub unsent: u64,
}

/// A datagram left over from a batch that could not be handed to QUIC as it came.
struct Spilled {
    addr: SocketAddr,
    bytes: Vec<u8>,
    ecn: Option<EcnCodepoint>,
    dst_ip: Option<IpAddr>,
}

/// What becomes of one datagram that has arrived.
enum Seen {
    /// It passes to QUIC as it is.
    Pass,
    /// It is a relayed packet of a session here: shown to QUIC, without its header, as from
    /// this made-up address.
    From(SocketAddr),
    /// It goes no further: carried on by the point, or dropped.
    Gone,
}

/// The runtime's UDP socket, as QUIC sees it when the runtime has lookup settings: the real one
/// inside, with sessions at a ship, and carrying at a point that relays, done on the way.
pub(crate) struct Relayed {
    inner: Arc<dyn AsyncUdpSocket>,
    /// Whether the real socket is IPv6, which decides the made-up addresses' family.
    v6: bool,
    /// The point this runtime is, if it relays.
    point: Option<Arc<Point>>,
    /// How long a made-up address is kept from another session after it was last used.
    keep_for: Duration,
    legs: Mutex<Legs>,
    spill: Mutex<VecDeque<Spilled>>,
    /// How far this wrapper's clock is set ahead of the machine's, in milliseconds. Nothing but
    /// a test sets it.
    skew: AtomicU64,
    delivered: AtomicU64,
    dropped: AtomicU64,
    sent: AtomicU64,
    unsent: AtomicU64,
    /// While set, packets for sessions are held back (dropped), and the size of each kept: for
    /// tests to hold a request under way.
    #[cfg(test)]
    pub(crate) holding: Mutex<Option<Vec<usize>>>,
}

impl fmt::Debug for Relayed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relayed").field("v6", &self.v6).field("relays", &self.point.is_some()).finish()
    }
}

impl Relayed {
    /// The real socket `inner` with the relay's work done on the way; `point`, if this runtime
    /// is a point that relays; `idle_timeout`, the connections' idle time.
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, point: Option<Arc<Point>>, idle_timeout: Duration) -> io::Result<Relayed> {
        let v6 = inner.local_addr()?.is_ipv6();
        Ok(Relayed {
            inner,
            v6,
            point,
            keep_for: idle_timeout.saturating_add(RETIRE_MARGIN),
            legs: Mutex::default(),
            spill: Mutex::default(),
            skew: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            unsent: AtomicU64::new(0),
            #[cfg(test)]
            holding: Mutex::default(),
        })
    }

    fn now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.skew.load(Ordering::SeqCst))
    }

    /// Set this wrapper's clock ahead by `by`, for tests.
    #[cfg(test)]
    pub(crate) fn step(&self, by: Duration) {
        self.skew.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }

    pub(crate) fn status(&self) -> RelayStatus {
        let now = self.now();
        let mut legs = lock(&self.legs);
        // Sessions gone idle are let go of first, so that what is counted is live.
        legs.release_where(|registered| now.saturating_duration_since(registered.last) >= IDLE, now);
        let calling = legs.live.values().filter(|registered| registered.side == Side::Calling).count();
        RelayStatus {
            calling,
            called: legs.live.len() - calling,
            delivered: self.delivered.load(Ordering::SeqCst),
            dropped: self.dropped.load(Ordering::SeqCst),
            sent: self.sent.load(Ordering::SeqCst),
            unsent: self.unsent.load(Ordering::SeqCst),
        }
    }

    /// Register a session, within the bounds, with a made-up address of its own. `pushed_on`,
    /// for the ship called, is weighed with the sessions held: the connection must still be
    /// heard on.
    fn register(&self, point: SocketAddr, id: SessionId, side: Side) -> Result<SocketAddr, &'static str> {
        // A point's address is never made up: the session's packets go to it on the real socket.
        if is_made_up(&point) {
            return Err("a session's point cannot be at an address that is made up");
        }
        let mut legs = lock(&self.legs);
        let now = self.now();
        legs.release_where(|registered| now.saturating_duration_since(registered.last) >= IDLE, now);
        if legs.ids.contains_key(&id) {
            return Err("that session is registered here already");
        }
        match &side {
            Side::Calling => {
                if legs.live.values().filter(|registered| registered.side == Side::Calling).count() >= MOST_CALLING {
                    return Err("this runtime is calling through as many sessions as it may");
                }
            }
            Side::Called { caller, pushed_on } => {
                if !legs.open.contains(pushed_on) {
                    return Err("the connection the session came on has closed");
                }
                let called = legs.live.values().filter(|registered| matches!(registered.side, Side::Called { .. })).count();
                if called >= MOST_CALLED {
                    return Err("this runtime is called through as many sessions as it may");
                }
                let from = legs.live.values().filter(|registered| matches!(&registered.side, Side::Called { caller: other, .. } if other == caller)).count();
                if from >= MOST_CALLED_EACH {
                    return Err("this runtime is called through as many sessions from that ship as it may");
                }
            }
        }
        // The next made-up address that no session has, no `Leg` owns, and nothing has used
        // lately.
        let mut found = None;
        let ports = legs.ports.unwrap_or(u16::MAX);
        for _ in 0..ports {
            legs.next = if legs.next >= ports { 1 } else { legs.next + 1 };
            let addr = made_up(self.v6, legs.next);
            if legs.live.contains_key(&addr) || legs.owned.contains_key(&addr) {
                continue;
            }
            if legs.retired.get(&addr).is_some_and(|touched| now.saturating_duration_since(*touched) < self.keep_for) {
                continue;
            }
            legs.retired.remove(&addr);
            found = Some(addr);
            break;
        }
        let addr = found.ok_or("no made-up address is free just now; try again later")?;
        // The caller's `Leg` owns the address from this very moment, in this same hold: there is
        // never a registration of ours whose address nobody owns, nor two owners of one address.
        if side == Side::Calling {
            legs.owned.insert(addr, id);
        }
        legs.ids.insert(id, addr);
        legs.live.insert(addr, Registered { id, point: plain(point), side, last: now });
        Ok(addr)
    }

    /// Register a session this ship calls through, carried by the point at `point`: the one its
    /// request was answered by.
    pub(crate) fn calling(self: &Arc<Self>, point: SocketAddr, id: SessionId) -> Result<Leg, &'static str> {
        let addr = self.register(point, id, Side::Calling)?;
        Ok(Leg { relayed: self.clone(), addr, id })
    }

    /// Register a session a caller calls this ship through, carried by the point the session's
    /// push came from (`point`, over the connection QUIC numbers `pushed_on`). Its made-up
    /// address.
    pub(crate) fn called(&self, point: SocketAddr, id: SessionId, caller: &str, pushed_on: usize) -> Result<SocketAddr, &'static str> {
        self.register(point, id, Side::Called { caller: caller.to_string(), pushed_on })
    }

    /// Sessions may be pushed on this connection to a point (by QUIC's number for it) from now
    /// on.
    pub(crate) fn heard_on(&self, connection: usize) {
        lock(&self.legs).open.insert(connection);
    }

    /// The connection is no longer heard on: it has closed. The sessions pushed on it end.
    pub(crate) fn no_longer_heard_on(&self, connection: usize) {
        let now = self.now();
        let mut legs = lock(&self.legs);
        legs.open.remove(&connection);
        legs.release_where(|registered| matches!(registered.side, Side::Called { pushed_on, .. } if pushed_on == connection), now);
    }

    /// Let every session go, as if each had gone idle. For tests.
    #[cfg(test)]
    pub(crate) fn release_all(&self) {
        let now = self.now();
        lock(&self.legs).release_where(|_| true, now);
    }

    /// An address as the real socket takes it: on an IPv6 socket, an IPv4 address written as
    /// IPv6, as QUIC itself hands them over.
    fn socket_form(&self, to: SocketAddr) -> SocketAddr {
        match (self.v6, to) {
            (true, SocketAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
            _ => to,
        }
    }

    /// The one place anything is handed to the real socket. Nothing with a made-up destination
    /// is, whatever asked for it (the plain path, a session's point, a point carrying): it is
    /// dropped, and counted.
    fn send_inner(&self, transmit: &Transmit) -> io::Result<()> {
        if is_made_up(&transmit.destination) {
            self.unsent.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        self.inner.try_send(transmit)
    }

    /// Send a datagram as it is, on the real socket, without waiting: for a point carrying a
    /// session's packet on.
    fn send_raw(&self, to: SocketAddr, contents: &[u8]) -> bool {
        if is_made_up(&to) {
            return false;
        }
        self.send_inner(&Transmit { destination: self.socket_form(to), ecn: None, contents, segment_size: None, src_ip: None }).is_ok()
    }

    /// What becomes of one datagram that has arrived from `from`.
    fn inspect(&self, from: SocketAddr, datagram: &[u8]) -> Seen {
        if is_made_up(&from) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return Seen::Gone;
        }
        let Some(id) = session_of(datagram) else { return Seen::Pass };
        let arrived = {
            let mut legs = lock(&self.legs);
            let now = self.now();
            legs.arrived(&id, from, now)
        };
        match arrived {
            Some(Ok(addr)) => {
                self.delivered.fetch_add(1, Ordering::SeqCst);
                Seen::From(addr)
            }
            Some(Err(())) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                Seen::Gone
            }
            None => {
                match &self.point {
                    // A point carries it on, or drops it, and counts which.
                    Some(point) => {
                        point.carry(&id, from, datagram, &mut |to| self.send_raw(to, datagram));
                    }
                    None => {
                        self.dropped.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Seen::Gone
            }
        }
    }

    /// Go through what the real socket handed over (`n` entries), and keep, at the front, what
    /// is to go on to QUIC: unchanged, or unwrapped and shown as from a made-up address. A
    /// batch of several datagrams in one buffer (`stride`) that cannot be handed on as it came
    /// is split, and what is to go on is kept to be handed over next. How many are kept.
    fn sift(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta], n: usize) -> usize {
        let mut kept = 0;
        for i in 0..n.min(bufs.len()).min(meta.len()) {
            let got = meta[i];
            let len = got.len.min(bufs[i].len());
            let stride = if got.stride == 0 { len } else { got.stride };
            if len <= stride {
                // One datagram, the usual case.
                match self.inspect(got.addr, &bufs[i][..len]) {
                    Seen::Pass => {}
                    Seen::Gone => continue,
                    Seen::From(addr) => {
                        bufs[i].copy_within(HEADER..len, 0);
                        meta[i].len = len - HEADER;
                        meta[i].stride = len - HEADER;
                        meta[i].addr = addr;
                    }
                }
            } else {
                // Several of one size, handed over at once. If all of them pass, so does the
                // batch; otherwise each goes its own way.
                let mut seen = Vec::new();
                for start in (0..len).step_by(stride) {
                    let end = (start + stride).min(len);
                    seen.push((start, end, self.inspect(got.addr, &bufs[i][start..end])));
                }
                if !seen.iter().all(|(_, _, seen)| matches!(seen, Seen::Pass)) {
                    let mut spill = lock(&self.spill);
                    for (start, end, seen) in seen {
                        let (addr, bytes) = match seen {
                            Seen::Pass => (got.addr, &bufs[i][start..end]),
                            Seen::From(addr) => (addr, &bufs[i][start + HEADER..end]),
                            Seen::Gone => continue,
                        };
                        spill.push_back(Spilled { addr, bytes: bytes.to_vec(), ecn: got.ecn, dst_ip: got.dst_ip });
                    }
                    continue;
                }
            }
            if kept != i {
                bufs.swap(kept, i);
                meta[kept] = meta[i];
            }
            kept += 1;
        }
        kept
    }

    /// Hand over what an earlier batch left, if anything: one datagram to each buffer.
    fn spilled(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Option<usize> {
        let mut spill = lock(&self.spill);
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let Some(next) = spill.pop_front() else { break };
            // Each came out of such a buffer, so it fits; one that did not would be dropped.
            if next.bytes.len() > bufs[n].len() {
                continue;
            }
            bufs[n][..next.bytes.len()].copy_from_slice(&next.bytes);
            let mut handed = RecvMeta::default();
            handed.addr = next.addr;
            handed.len = next.bytes.len();
            handed.stride = next.bytes.len();
            handed.ecn = next.ecn;
            handed.dst_ip = next.dst_ip;
            meta[n] = handed;
            n += 1;
        }
        (n > 0).then_some(n)
    }
}

impl AsyncUdpSocket for Relayed {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if !is_made_up(&transmit.destination) {
            return self.send_inner(transmit);
        }
        // A made-up address never reaches the real socket: the packet goes to the session's
        // point, wrapped, or nowhere.
        let leaving = {
            let mut legs = lock(&self.legs);
            let now = self.now();
            legs.leaving(transmit.destination, now)
        };
        let Some((point, id)) = leaving else {
            self.unsent.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        };
        #[cfg(test)]
        if let Some(held) = lock(&self.holding).as_mut() {
            held.push(transmit.contents.len());
            return Ok(());
        }
        // Each segment of a batch is a packet of its own, with a header of its own.
        let size = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for (n, segment) in transmit.contents.chunks(size).enumerate() {
            let datagram = wrapped(&id, segment);
            let sending = Transmit { destination: self.socket_form(point), ecn: transmit.ecn, contents: &datagram, segment_size: None, src_ip: transmit.src_ip };
            match self.send_inner(&sending) {
                Ok(()) => {
                    self.sent.fetch_add(1, Ordering::SeqCst);
                }
                // Nothing has gone yet: QUIC waits for room and sends it all again.
                Err(e) if n == 0 && e.kind() == io::ErrorKind::WouldBlock => return Err(e),
                // The rest is lost, as on any path, and QUIC sends it again as for any loss.
                Err(_) => {
                    self.unsent.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        if let Some(n) = self.spilled(bufs, meta) {
            return Poll::Ready(Ok(n));
        }
        for _ in 0..MOST_ROUNDS {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            let kept = self.sift(bufs, meta, n);
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
            if let Some(n) = self.spilled(bufs, meta) {
                return Poll::Ready(Ok(n));
            }
        }
        // Everything lately was carried on or dropped. Let the endpoint's other work run, and
        // come back at once.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A stand-in for the real socket: hands over what the test puts in, one batch a call, and
    /// keeps what is sent. It fails the test if it is ever asked to send to a made-up address.
    #[derive(Default)]
    pub(crate) struct Stand {
        /// Batches to hand over: each entry is (from, bytes, stride), one entry to a buffer.
        pub(crate) arriving: Mutex<VecDeque<Vec<(SocketAddr, Vec<u8>, usize)>>>,
        pub(crate) sent: Mutex<Vec<(SocketAddr, Vec<u8>, Option<usize>)>>,
        pub(crate) addr: Option<SocketAddr>,
        /// While set, every send would block.
        pub(crate) blocks: std::sync::atomic::AtomicBool,
    }

    impl Stand {
        pub(crate) fn at(addr: &str) -> Arc<Stand> {
            Arc::new(Stand { addr: Some(addr.parse().unwrap()), ..Stand::default() })
        }

        pub(crate) fn arrive(&self, batch: Vec<(SocketAddr, Vec<u8>, usize)>) {
            lock(&self.arriving).push_back(batch);
        }

        pub(crate) fn sent(&self) -> Vec<(SocketAddr, Vec<u8>, Option<usize>)> {
            lock(&self.sent).clone()
        }
    }

    #[derive(Debug)]
    struct Ready;

    impl UdpPoller for Ready {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl fmt::Debug for Stand {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Stand")
        }
    }

    impl AsyncUdpSocket for Stand {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(Ready)
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            assert!(!is_made_up(&transmit.destination), "a made-up address reached the real socket: {}", transmit.destination);
            if self.blocks.load(Ordering::SeqCst) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            lock(&self.sent).push((transmit.destination, transmit.contents.to_vec(), transmit.segment_size));
            Ok(())
        }

        fn poll_recv(&self, _: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
            let Some(batch) = lock(&self.arriving).pop_front() else { return Poll::Pending };
            for (n, (from, bytes, stride)) in batch.iter().enumerate() {
                bufs[n][..bytes.len()].copy_from_slice(bytes);
                let mut got = RecvMeta::default();
                got.addr = *from;
                got.len = bytes.len();
                got.stride = *stride;
                meta[n] = got;
            }
            Poll::Ready(Ok(batch.len()))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.addr.unwrap_or_else(|| "127.0.0.1:4433".parse().unwrap()))
        }

        fn max_receive_segments(&self) -> usize {
            8
        }
    }

    /// Everything QUIC would be handed, from as many calls to receive as it takes: each
    /// datagram, cut out by its stride, with where it is said to come from.
    pub(crate) fn received(relayed: &Relayed) -> Vec<(SocketAddr, Vec<u8>)> {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut got = Vec::new();
        let mut store = vec![[0u8; 4096]; 8];
        loop {
            let mut bufs: Vec<IoSliceMut> = store.iter_mut().map(|buf| IoSliceMut::new(&mut buf[..])).collect();
            let mut meta = [RecvMeta::default(); 8];
            match relayed.poll_recv(&mut cx, &mut bufs, &mut meta) {
                Poll::Ready(Ok(n)) => {
                    for (buf, meta) in bufs.iter().zip(&meta).take(n) {
                        let stride = if meta.stride == 0 { meta.len } else { meta.stride };
                        for start in (0..meta.len).step_by(stride) {
                            got.push((meta.addr, buf[start..(start + stride).min(meta.len)].to_vec()));
                        }
                    }
                }
                _ => return got,
            }
        }
    }

    const POINT: &str = "203.0.113.1:4433";

    fn id(n: u8) -> SessionId {
        [n; 16]
    }

    fn point() -> SocketAddr {
        POINT.parse().unwrap()
    }

    fn wrapper(stand: &Arc<Stand>) -> Arc<Relayed> {
        Arc::new(Relayed::new(stand.clone(), None, Duration::from_secs(30)).unwrap())
    }

    #[test]
    fn a_relayed_datagram_is_told_apart_from_quic_and_from_the_punch_by_its_first_byte() {
        // Neither top bit is set: no QUIC packet the endpoint takes begins so, with the fixed bit
        // not greased. And it is not the punch's nought.
        assert_eq!(KIND & 0xc0, 0);
        assert_ne!(KIND, 0);
        assert_eq!(crate::net::PUNCH[0], 0);
        let packet = wrapped(&id(7), &[0x41, 1, 2]);
        assert_eq!(packet.len(), HEADER + 3);
        assert_eq!(session_of(&packet), Some(id(7)));
        // A header with nothing after it, the punch, and any byte with a top bit set are not
        // relayed datagrams.
        assert_eq!(session_of(&packet[..HEADER]), None);
        assert_eq!(session_of(crate::net::PUNCH), None);
        for first in [0x40u8, 0x80, 0xc0, 0x55, 0x00] {
            let mut other = packet.clone();
            other[0] = first;
            assert_eq!(session_of(&other), None, "{first:#x}");
        }
        // Made-up addresses are of kinds no record may carry.
        assert!(crate::whereabouts::fits(&[made_up(false, 9)]).is_err());
        assert!(crate::whereabouts::fits(&[made_up(true, 9)]).is_err());
        assert!(is_made_up(&made_up(false, 1)) && is_made_up(&made_up(true, 1)));
        assert!(is_made_up(&"[::ffff:255.255.255.255]:5".parse().unwrap()));
        assert!(!is_made_up(&point()) && !is_made_up(&"[ff02::1]:5".parse().unwrap()));
    }

    #[test]
    fn packets_for_a_session_go_to_its_point_each_segment_with_a_header_of_its_own() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        let leg = relayed.calling(point(), id(1)).unwrap();
        assert!(is_made_up(&leg.addr));
        // Three segments of four bytes, the last of two.
        let contents = [1u8, 1, 1, 1, 2, 2, 2, 2, 3, 3];
        relayed.try_send(&Transmit { destination: leg.addr, ecn: None, contents: &contents, segment_size: Some(4), src_ip: None }).unwrap();
        let sent = stand.sent();
        assert_eq!(sent.len(), 3, "{sent:?}");
        for ((to, datagram, segments), body) in sent.iter().zip([&contents[..4], &contents[4..8], &contents[8..]]) {
            assert_eq!(*to, point());
            assert_eq!(*segments, None);
            assert_eq!(session_of(datagram), Some(id(1)));
            assert_eq!(&datagram[HEADER..], body);
        }
        // A packet for anywhere else goes as it is.
        let elsewhere: SocketAddr = "198.51.100.2:9".parse().unwrap();
        relayed.try_send(&Transmit { destination: elsewhere, ecn: None, contents: &contents, segment_size: Some(4), src_ip: None }).unwrap();
        assert_eq!(stand.sent().last().unwrap(), &(elsewhere, contents.to_vec(), Some(4)));
        // Once the session is let go of, a packet for its address goes nowhere at all: the stand
        // fails the test if a made-up address ever reaches it.
        let addr = leg.addr;
        drop(leg);
        let before = stand.sent().len();
        relayed.try_send(&Transmit { destination: addr, ecn: None, contents: &contents, segment_size: None, src_ip: None }).unwrap();
        relayed.try_send(&Transmit { destination: made_up(false, 7), ecn: None, contents: &contents, segment_size: None, src_ip: None }).unwrap();
        assert_eq!(stand.sent().len(), before);
        assert_eq!(relayed.status().unsent, 2);
        assert_eq!(relayed.status().sent, 3);
    }

    #[test]
    fn a_relayed_datagram_reaches_quic_only_for_a_session_here_and_from_its_point() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        relayed.heard_on(5);
        let addr = relayed.called(point(), id(2), "nec", 5).unwrap();
        let stranger: SocketAddr = "198.51.100.9:4000".parse().unwrap();
        let body = [0x41u8, 9, 9, 9];
        // Ours, from its point: unwrapped, and shown as from the made-up address.
        stand.arrive(vec![(point(), wrapped(&id(2), &body), 0)]);
        assert_eq!(received(&relayed), vec![(addr, body.to_vec())]);
        // From anyone else, naming no session here, or from a made-up address: nothing reaches
        // QUIC. And a datagram that is not a relayed one passes as it is, from the point too.
        stand.arrive(vec![(stranger, wrapped(&id(2), &body), 0), (point(), wrapped(&id(3), &body), 0), (made_up(false, 1), body.to_vec(), 0), (point(), body.to_vec(), 0)]);
        assert_eq!(received(&relayed), vec![(point(), body.to_vec())]);
        assert_eq!(relayed.status().dropped, 3);
        // Idle for the idle time: the session is gone, and so is anything for it after.
        relayed.step(IDLE);
        stand.arrive(vec![(point(), wrapped(&id(2), &body), 0)]);
        assert!(received(&relayed).is_empty());
        assert_eq!(relayed.status().called, 0);
        // And on none of it was anything sent.
        assert!(stand.sent().is_empty());
        // A session idle for the idle time sends nothing either, seen first on the way out.
        relayed.heard_on(6);
        let other = relayed.called(point(), id(3), "bud", 6).unwrap();
        relayed.step(IDLE);
        relayed.try_send(&Transmit { destination: other, ecn: None, contents: &body, segment_size: None, src_ip: None }).unwrap();
        assert!(stand.sent().is_empty());
    }

    /// A stand-in that always has a relayed datagram for no session to hand over, and counts how
    /// often it is asked.
    #[derive(Debug, Default)]
    struct Flood {
        polled: std::sync::atomic::AtomicUsize,
    }

    impl AsyncUdpSocket for Flood {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(Ready)
        }

        fn try_send(&self, _: &Transmit) -> io::Result<()> {
            Ok(())
        }

        fn poll_recv(&self, _: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
            // After a thousand, it runs dry, so that a wrapper that never stops still returns.
            if self.polled.fetch_add(1, Ordering::SeqCst) >= 1000 {
                return Poll::Pending;
            }
            let packet = wrapped(&[0xab; 16], &[0x41; 100]);
            bufs[0][..packet.len()].copy_from_slice(&packet);
            let mut got = RecvMeta::default();
            got.addr = point();
            got.len = packet.len();
            got.stride = packet.len();
            meta[0] = got;
            Poll::Ready(Ok(1))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:4433".parse().unwrap())
        }
    }

    #[test]
    fn a_flood_of_relayed_datagrams_lets_the_endpoint_get_on_with_its_other_work() {
        let flood = Arc::new(Flood::default());
        let relayed = Relayed::new(flood.clone(), None, Duration::from_secs(30)).unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut store = vec![[0u8; 2048]; 4];
        let mut bufs: Vec<IoSliceMut> = store.iter_mut().map(|buf| IoSliceMut::new(&mut buf[..])).collect();
        let mut meta = [RecvMeta::default(); 4];
        // Everything is dropped; the call gives up after so many rounds, asking to be woken.
        assert!(relayed.poll_recv(&mut cx, &mut bufs, &mut meta).is_pending());
        assert_eq!(flood.polled.load(Ordering::SeqCst), MOST_ROUNDS);
    }

    #[test]
    fn a_made_up_destination_never_reaches_the_real_socket_whatever_asked_for_it() {
        // The last guard alone: a session whose point is made up, put in as no registration
        // would let it be, and a point asked to carry toward a made-up address. The stand fails
        // the test if a made-up address ever reaches it.
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        let addr = made_up(false, 77);
        {
            let mut legs = lock(&relayed.legs);
            let now = relayed.now();
            legs.ids.insert(id(1), addr);
            legs.live.insert(addr, Registered { id: id(1), point: made_up(false, 78), side: Side::Calling, last: now });
        }
        relayed.try_send(&Transmit { destination: addr, ecn: None, contents: &[1, 2, 3], segment_size: None, src_ip: None }).unwrap();
        assert!(relayed.send_inner(&Transmit { destination: made_up(true, 5), ecn: None, contents: &[1], segment_size: None, src_ip: None }).is_ok());
        assert!(stand.sent().is_empty());
        assert_eq!(relayed.status().unsent, 2);
        // And registration refuses a made-up point, at either end.
        relayed.heard_on(1);
        assert_eq!(relayed.calling(made_up(false, 9), id(2)).err(), Some("a session's point cannot be at an address that is made up"));
        assert_eq!(relayed.called(made_up(true, 9), id(3), "nec", 1), Err("a session's point cannot be at an address that is made up"));
    }

    #[test]
    fn a_stale_leg_releases_only_its_own_session_and_its_address_is_not_given_again_while_it_lives() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        // Four addresses only, so that the allocator comes round quickly.
        lock(&relayed.legs).ports = Some(4);
        let old = relayed.calling(point(), id(1)).unwrap();
        // Its session goes idle and is let go of; the `Leg` lives on (in a closed connection kept
        // somewhere).
        relayed.step(IDLE);
        assert_eq!(relayed.status().calling, 0);
        // Other sessions come and go, past the quarantine, round and round the four addresses.
        for n in 2..10u8 {
            let leg = relayed.calling(point(), id(n)).unwrap();
            assert_ne!(leg.addr, old.addr, "an address a Leg still owns was given again");
            drop(leg);
            relayed.step(relayed.keep_for);
        }
        let newer = relayed.calling(point(), id(20)).unwrap();
        assert_ne!(newer.addr, old.addr);
        // The stale `Leg` is dropped late: the newer session is untouched.
        drop(old);
        assert_eq!(relayed.status().calling, 1);
        relayed.try_send(&Transmit { destination: newer.addr, ecn: None, contents: &[1], segment_size: None, src_ip: None }).unwrap();
        assert_eq!(stand.sent().len(), 1);
        // A Leg dropped while its session lives releases it (its own).
        let addr = newer.addr;
        drop(newer);
        assert_eq!(relayed.status().calling, 0);
        relayed.try_send(&Transmit { destination: addr, ecn: None, contents: &[1], segment_size: None, src_ip: None }).unwrap();
        assert_eq!(stand.sent().len(), 1);
    }

    #[test]
    fn a_leg_whose_address_was_given_again_releases_only_its_own_registration() {
        // Driven directly: the Legs are told to drop a Leg's registration by address and name,
        // while another session holds the address. Only a matching name is let go of.
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        let leg = relayed.calling(point(), id(1)).unwrap();
        let now = relayed.now();
        lock(&relayed.legs).release_leg(leg.addr, &id(9), now);
        assert_eq!(relayed.status().calling, 1, "a Leg let go of a session that was not its own");
        assert!(lock(&relayed.legs).owned.contains_key(&leg.addr), "a Leg let go of another's hold on the address");
        std::mem::forget(leg);
    }

    #[test]
    fn nothing_is_earned_for_the_time_a_packet_took_to_send() {
        // A ship's allowance of 2,048 bytes, earned back at 2,048 a second. A packet takes all
        // of it, and its send takes a second: nothing is earned for that second, so a byte
        // offered the moment after is refused.
        let bounds = RelayBounds { ship_rate: 2048, ship_burst: 2048, ..RelayBounds::default() };
        let t0 = Instant::now();
        let mut sessions = Sessions::new(Some(bounds), t0);
        let (callee_at, caller_at): (SocketAddr, SocketAddr) = ("198.51.100.1:4433".parse().unwrap(), "198.51.100.2:4433".parse().unwrap());
        sessions.room(&id(1), 1, 2, t0).unwrap();
        sessions.make(id(1), 1, 2, 7, callee_at, caller_at, t0).unwrap();
        let later = t0 + Duration::from_secs(1);
        let sent = sessions.carry(&id(1), caller_at, 2048, t0, &|| later, &|_, _| true, &mut |_| true);
        assert!(matches!(sent, Carry::To(_)));
        let next = sessions.carry(&id(1), caller_at, 1, later, &|| later, &|_, _| true, &mut |_| true);
        assert_eq!(next, Carry::Dropped("over the allowance of the ship called"));
        // A second after that, a second's worth is there again.
        let after = sessions.carry(&id(1), caller_at, 2048, later + Duration::from_secs(1), &|| later + Duration::from_secs(1), &|_, _| true, &mut |_| true);
        assert!(matches!(after, Carry::To(_)));
        // The same for the point's own allowance.
        let bounds = RelayBounds { point_rate: 2048, point_burst: 2048, ..RelayBounds::default() };
        let mut sessions = Sessions::new(Some(bounds), t0);
        sessions.room(&id(1), 1, 2, t0).unwrap();
        sessions.make(id(1), 1, 2, 7, callee_at, caller_at, t0).unwrap();
        assert!(matches!(sessions.carry(&id(1), caller_at, 2048, t0, &|| later, &|_, _| true, &mut |_| true), Carry::To(_)));
        assert_eq!(sessions.carry(&id(1), caller_at, 1, later, &|| later, &|_, _| true, &mut |_| true), Carry::Dropped("over the point's allowance"));
    }

    #[test]
    fn a_point_never_carries_toward_a_made_up_address_whatever_is_pinned() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Some(RelayBounds::default()), now);
        let callee_at: SocketAddr = "198.51.100.1:4433".parse().unwrap();
        sessions.room(&id(1), 1, 2, now).unwrap();
        sessions.make(id(1), 1, 2, 7, callee_at, made_up(false, 9), now).unwrap();
        let mut sent = Vec::new();
        let carried = sessions.carry(&id(1), callee_at, 100, now, &|| now, &|_, _| true, &mut |to| {
            sent.push(to);
            true
        });
        assert!(matches!(carried, Carry::Dropped(_)), "{carried:?}");
        assert!(sent.is_empty());
    }

    #[test]
    fn received_batches_are_split_and_rebuilt() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        let leg = relayed.calling(point(), id(4)).unwrap();
        // A batch of plain datagrams of one size passes as one batch, unchanged.
        let plain_batch: Vec<u8> = [[1u8; 5], [2; 5], [3; 5]].concat();
        stand.arrive(vec![(point(), [plain_batch.clone(), vec![4, 4]].concat(), 5)]);
        assert_eq!(received(&relayed), vec![(point(), vec![1; 5]), (point(), vec![2; 5]), (point(), vec![3; 5]), (point(), vec![4, 4])]);
        // A batch of the session's packets, the last shorter: each unwrapped, as from the
        // made-up address.
        let one = wrapped(&id(4), &[7; 6]);
        let last = wrapped(&id(4), &[8; 3]);
        stand.arrive(vec![(point(), [one.clone(), one.clone(), last.clone()].concat(), one.len())]);
        assert_eq!(received(&relayed), vec![(leg.addr, vec![7; 6]), (leg.addr, vec![7; 6]), (leg.addr, vec![8; 3])]);
        // Mixed: a plain one, one of ours, and one naming no session, all of one size.
        let plain_one = vec![0x41u8; one.len()];
        let unknown = wrapped(&id(9), &[7; 6]);
        stand.arrive(vec![(point(), [plain_one.clone(), one.clone(), unknown].concat(), one.len()), (point(), vec![0x42; 3], 0)]);
        let got = received(&relayed);
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(got.contains(&(point(), plain_one)) && got.contains(&(leg.addr, vec![7; 6])) && got.contains(&(point(), vec![0x42; 3])));
        assert!(stand.sent().is_empty());
    }

    #[test]
    fn sessions_at_a_ship_are_bounded_and_end_with_the_connection_they_came_on() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = wrapper(&stand);
        // Not on a connection heard on: refused.
        assert_eq!(relayed.called(point(), id(0), "nec", 1), Err("the connection the session came on has closed"));
        relayed.heard_on(1);
        relayed.heard_on(2);
        let mut n = 0u8;
        let mut next = || {
            n += 1;
            id(n)
        };
        for _ in 0..MOST_CALLED_EACH {
            relayed.called(point(), next(), "nec", 1).unwrap();
        }
        assert_eq!(relayed.called(point(), next(), "nec", 1), Err("this runtime is called through as many sessions from that ship as it may"));
        // The same session twice is refused.
        assert_eq!(relayed.called(point(), id(1), "bud", 1), Err("that session is registered here already"));
        let mut callers = 0;
        while relayed.status().called < MOST_CALLED {
            relayed.called(point(), next(), &format!("caller{}", callers / MOST_CALLED_EACH), 2).unwrap();
            callers += 1;
        }
        assert_eq!(relayed.called(point(), next(), "someone-new", 2), Err("this runtime is called through as many sessions as it may"));
        // The connection the first eight came on closes: they end, and there is room again.
        relayed.no_longer_heard_on(1);
        assert_eq!(relayed.status().called, MOST_CALLED - MOST_CALLED_EACH);
        assert_eq!(relayed.called(point(), next(), "nec", 1), Err("the connection the session came on has closed"));
        relayed.called(point(), next(), "someone-new", 2).unwrap();
        // A ship's own calls have a bound of their own.
        let legs: Vec<Leg> = (0..MOST_CALLING).map(|k| relayed.calling(point(), [k as u8, (k >> 8) as u8, 0xee, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap()).collect();
        assert_eq!(relayed.calling(point(), [0xff; 16]).err(), Some("this runtime is calling through as many sessions as it may"));
        drop(legs);
        assert_eq!(relayed.status().calling, 0);
    }

    #[test]
    fn a_made_up_address_is_not_given_again_while_anything_may_remember_it() {
        let stand = Stand::at("127.0.0.1:4433");
        let relayed = Arc::new(Relayed::new(stand.clone(), None, Duration::from_secs(30)).unwrap());
        let first = relayed.calling(point(), id(1)).unwrap();
        let addr = first.addr;
        drop(first);
        // Every other address is taken in turn before that one could come round again, and
        // even then it is not given while it was used within the time kept.
        {
            let mut legs = lock(&relayed.legs);
            legs.next = addr.port().wrapping_sub(1);
        }
        let second = relayed.calling(point(), id(2)).unwrap();
        assert_ne!(second.addr, addr);
        // Something still sends to it: that keeps it out longer.
        relayed.step(relayed.keep_for - Duration::from_secs(1));
        relayed.try_send(&Transmit { destination: addr, ecn: None, contents: &[1], segment_size: None, src_ip: None }).unwrap();
        relayed.step(Duration::from_secs(2));
        lock(&relayed.legs).next = addr.port().wrapping_sub(1);
        let third = relayed.calling(point(), id(3)).unwrap();
        assert_ne!(third.addr, addr);
        // Once nothing has touched it for the whole time, it may be given again.
        relayed.step(relayed.keep_for);
        lock(&relayed.legs).next = addr.port().wrapping_sub(1);
        let fourth = relayed.calling(point(), id(4)).unwrap();
        assert_eq!(fourth.addr, addr);
        // On an IPv6 socket the made-up addresses are IPv6.
        let six = Arc::new(Relayed::new(Stand::at("[::1]:4433"), None, Duration::from_secs(30)).unwrap());
        assert!(six.calling(point(), id(5)).unwrap().addr.is_ipv6());
    }
}
