//! Ships behind a pretend home router, called by name: real runtimes on this machine, a real
//! lookup point, and keys from a stand-in for Urbit ID.
//!
//! The router stands between a runtime and everything else, as the runtime's UDP socket (the
//! crate-private `Network::start_on`). It comes in two kinds:
//! - `Cone`: one outside port for everything, and a packet is let in only from an address the
//!   inside has sent to lately. Most home routers are like this.
//! - `Strict`: a different outside port for each address the inside sends to, and each lets in
//!   only that address. Introductions cannot get through two of these.
//! An opening is forgotten once nothing has gone out through it for `forget_after`.
//!
//! Phase 3's tests are here too: two ships behind strict routers reach each other through their
//! point's relay; a relayed pair goes direct when it can; and the point's and the ships' rules
//! for relayed packets, counted at the routers. Last, a request to be introduced or relayed that
//! the ship's own announcement overtakes, made to happen every time by a stand-in.

use std::collections::HashMap;
use std::fs;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use ship_proto::{where_request, Introduce, Message, Relay, WhereReply, WhereRequest, Whereabouts};

use crate::azimuth::{Keys, Listing};
use crate::lookup::{Lookup, PointBounds, PointConfig, StandIn};
use crate::net::{Directory, MakeSocket, NetConfig, Network, MOST_DIRECT_TRIES};
use crate::relay::{RelayBounds, NO_RELAY};
use crate::whereabouts::HELD_NEWER;
use crate::{lock, Config, Durability, Manifest, Provide, Runtime, Use};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Cone,
    Strict,
}

/// A pretend home router, which the runtime behind it takes for its UDP socket.
struct Router {
    kind: Kind,
    /// The address the runtime is told it has: one on its home network, which nobody outside
    /// can reach. A socket is held there so that nothing else takes it, and never read.
    inside: SocketAddr,
    _inside: std::net::UdpSocket,
    /// The outside ports: for a cone, one, for every destination (`None`); for a strict router,
    /// one for each destination, made as the inside first sends there.
    outside: Mutex<Vec<(Option<SocketAddr>, Arc<tokio::net::UdpSocket>)>>,
    /// When the inside last sent to each address, through each outside port.
    sent: Mutex<HashMap<(usize, SocketAddr), Instant>>,
    forget_after: Duration,
    /// Whoever last waited for a packet, to be told when a new outside port is made.
    waiting: Mutex<Option<Waker>>,
    /// Packets from outside that were not let in.
    dropped: AtomicUsize,
    /// Relayed datagrams (see `crate::relay`) that were let in.
    relayed_in: AtomicUsize,
    /// Times the runtime inside asked to send to a made-up address. It never should.
    made_up_seen: AtomicUsize,
    /// The largest relayed datagram the runtime inside has sent.
    largest_relayed_out: AtomicUsize,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").field("kind", &self.kind).field("inside", &self.inside).finish()
    }
}

impl Router {
    fn new(kind: Kind, forget_after: Duration) -> Router {
        let held = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        Router {
            kind,
            inside: held.local_addr().unwrap(),
            _inside: held,
            outside: Mutex::default(),
            sent: Mutex::default(),
            forget_after,
            waiting: Mutex::default(),
            dropped: AtomicUsize::new(0),
            relayed_in: AtomicUsize::new(0),
            made_up_seen: AtomicUsize::new(0),
            largest_relayed_out: AtomicUsize::new(0),
        }
    }

    /// Send a datagram from the outside port that packets to `to` go out from, as if the
    /// runtime inside had: for tests to speak from an address a point has pinned.
    fn send_from(&self, to: SocketAddr, datagram: &[u8]) {
        let (index, port) = self.port_for(to).unwrap();
        self.sent.lock().unwrap().insert((index, to), Instant::now());
        port.try_send_to(datagram, to).unwrap();
    }

    /// A new outside port, inside the network's own threads.
    fn port() -> io::Result<Arc<tokio::net::UdpSocket>> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(tokio::net::UdpSocket::from_std(socket)?))
    }

    /// The outside port packets to `to` go out from, made if need be.
    fn port_for(&self, to: SocketAddr) -> io::Result<(usize, Arc<tokio::net::UdpSocket>)> {
        let mut outside = self.outside.lock().unwrap();
        let found = match self.kind {
            Kind::Cone => Some(0),
            Kind::Strict => outside.iter().position(|(dest, _)| *dest == Some(to)),
        };
        if let Some(index) = found {
            return Ok((index, outside[index].1.clone()));
        }
        outside.push((Some(to), Router::port()?));
        // Whoever is waiting for packets must wait on the new port too.
        if let Some(waker) = self.waiting.lock().unwrap().take() {
            waker.wake();
        }
        Ok((outside.len() - 1, outside.last().unwrap().1.clone()))
    }

    /// Whether a packet from `from`, arriving at outside port `index` (for `dest`), is let in.
    fn lets_in(&self, index: usize, dest: Option<SocketAddr>, from: SocketAddr) -> bool {
        let lately = self.sent.lock().unwrap().get(&(index, from)).is_some_and(|at| at.elapsed() < self.forget_after);
        lately && (self.kind == Kind::Cone || dest == Some(from))
    }

    /// The outside address of a cone router.
    fn outside(&self) -> SocketAddr {
        self.outside.lock().unwrap()[0].1.local_addr().unwrap()
    }
}

/// Ready to send whenever asked: the router's ports seldom fill, and a send that would wait
/// is tried again.
#[derive(Debug)]
struct AlwaysReady;

impl UdpPoller for AlwaysReady {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for Router {
    /// A router does not fragment: QUIC searches for the path's size through it, as through a
    /// real socket that sets "don't fragment".
    fn may_fragment(&self) -> bool {
        false
    }

    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysReady)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if crate::relay::is_made_up(&transmit.destination) {
            self.made_up_seen.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        let (index, port) = self.port_for(transmit.destination)?;
        self.sent.lock().unwrap().insert((index, transmit.destination), Instant::now());
        if crate::relay::session_of(transmit.contents).is_some() {
            self.largest_relayed_out.fetch_max(transmit.contents.len(), Ordering::SeqCst);
        }
        port.try_send_to(transmit.contents, transmit.destination).map(drop)
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        *self.waiting.lock().unwrap() = Some(cx.waker().clone());
        let ports = self.outside.lock().unwrap().clone();
        for (index, (dest, port)) in ports.iter().enumerate() {
            loop {
                let mut read = tokio::io::ReadBuf::new(&mut bufs[0]);
                match port.poll_recv_from(cx, &mut read) {
                    Poll::Ready(Ok(from)) => {
                        let len = read.filled().len();
                        if self.lets_in(index, *dest, from) {
                            if crate::relay::session_of(read.filled()).is_some() {
                                self.relayed_in.fetch_add(1, Ordering::SeqCst);
                            }
                            let mut taken = RecvMeta::default();
                            taken.addr = from;
                            taken.len = len;
                            taken.stride = len;
                            meta[0] = taken;
                            return Poll::Ready(Ok(1));
                        }
                        self.dropped.fetch_add(1, Ordering::SeqCst);
                    }
                    // A packet that could not be delivered somewhere, said back: passed over.
                    Poll::Ready(Err(_)) => {}
                    Poll::Pending => break,
                }
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.inside)
    }
}

/// A router of this kind, and the means to give it to a network as its socket.
fn behind(kind: Kind, forget_after: Duration) -> (Arc<Router>, MakeSocket) {
    let router = Arc::new(Router::new(kind, forget_after));
    let made = router.clone();
    let make: MakeSocket = Box::new(move || {
        if made.kind == Kind::Cone {
            made.outside.lock().unwrap().push((None, Router::port()?));
        }
        Ok(made as Arc<dyn AsyncUdpSocket>)
    });
    (router, make)
}

// Runtimes, agents, and keys.

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Build the kernel and test agents once per test run, and return one of them by name. The
/// crate's other tests use this too, so that only one build runs in this test binary.
pub(crate) fn wasm(name: &str) -> Vec<u8> {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .current_dir(workspace())
            .args(["build", "-p", "kernel", "-p", "counter", "-p", "tally", "-p", "guestbook", "-p", "kit", "--release"])
            .args(["--target", "wasm32-unknown-unknown", "--target-dir", "target/wasm"])
            .status()
            .expect("run cargo");
        assert!(status.success(), "building the kernel and agents failed");
    });
    fs::read(workspace().join(format!("target/wasm/wasm32-unknown-unknown/release/{name}.wasm"))).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-router-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A stand-in for Urbit ID: the keys the test has listed, each at revision one. While the flag
/// is set every question waits (for half a minute at most); the count is of questions asked.
#[derive(Default)]
struct Listings(Mutex<HashMap<u32, [u8; 32]>>, std::sync::atomic::AtomicBool, AtomicUsize);

impl Listings {
    fn list(&self, ship: &str, key: [u8; 32]) {
        self.0.lock().unwrap().insert(urbit_id::ob::ship_number(ship).unwrap(), key);
    }
}

impl Keys for Listings {
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
        self.2.fetch_add(1, Ordering::SeqCst);
        let started = Instant::now();
        while self.1.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(self.0.lock().unwrap().get(&ship).map(|key| Listing { key: Some(*key), revision: 1, continuity: 0, sponsor: None }))
    }
}

/// A network that gives a call eight seconds, room for an introduction, a lost first packet
/// sent again, and the handshake; and lookup settings that announce every second and keep the
/// way open with a packet every second.
fn settings(point: Option<SocketAddr>) -> NetConfig {
    let lookup = match point {
        Some(point) => Lookup {
            at: vec![(None, point)],
            announce_every: Duration::from_secs(1),
            ask_again: Duration::from_millis(150),
            keep_alive: Duration::from_secs(1),
            ..Lookup::default()
        },
        None => Lookup::default(),
    };
    NetConfig { request_timeout: Duration::from_secs(8), retry_delay: Duration::from_millis(50), max_retry_delay: Duration::from_millis(300), lookup, ..NetConfig::default() }
}

/// A runtime that holds no ships and is a lookup point for every galaxy, at a public address.
fn point_on(dir: &TempDir, urbit: &Arc<Listings>) -> (Arc<Runtime>, Network) {
    point_relaying(dir, urbit, None)
}

/// The same, relaying within these bounds, if any are given.
fn point_relaying(dir: &TempDir, urbit: &Arc<Listings>, relay: Option<RelayBounds>) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
    let lookup = Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies: None, bounds: PointBounds::default(), relay }), ..Lookup::default() };
    let net = Network::start(rt.clone(), Directory::new(), NetConfig { lookup, ..settings(None) }).unwrap();
    (rt, net)
}

/// A runtime with one ship, with the counter and tally agents, open to other ships, listed in
/// `urbit`, finding others through the point at `point`, and behind `socket` if one is given.
fn crew(dir: &TempDir, ship: &str, urbit: &Arc<Listings>, point: SocketAddr, socket: Option<MakeSocket>) -> (Arc<Runtime>, Network) {
    crew_with(dir, ship, urbit, settings(Some(point)), socket)
}

/// The same, with these settings.
fn crew_with(dir: &TempDir, ship: &str, urbit: &Arc<Listings>, cfg: NetConfig, socket: Option<MakeSocket>) -> (Arc<Runtime>, Network) {
    crew_of(dir, &[ship], urbit, cfg, socket)
}

/// The same, for several ships on the one runtime.
fn crew_of(dir: &TempDir, ships: &[&str], urbit: &Arc<Listings>, cfg: NetConfig, socket: Option<MakeSocket>) -> (Arc<Runtime>, Network) {
    let open_counter = Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true, asked: false }], uses: vec![] };
    let to = |agent: &str| Use { ship: "*".into(), agent: agent.into(), interface: agent.into(), read: false, send: true, ask: false };
    let far_tally = Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true, asked: false }], uses: vec![to("counter"), to("tally")] };
    let rt = Arc::new(Runtime::open(&dir.0, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let (counter, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    for ship in ships {
        rt.create_ship(ship, &kernel).unwrap();
        rt.install(ship, "counter", &counter, &open_counter).unwrap();
        rt.install(ship, "tally", &tally, &far_tally).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    let net = Network::start_on(rt.clone(), Directory::reading(urbit.clone()), cfg, socket).unwrap();
    (rt, net)
}

/// Wait for something that happens on its own time.
fn eventually(what: &str, holds: impl Fn() -> bool) {
    let started = Instant::now();
    while !holds() {
        assert!(started.elapsed() < Duration::from_secs(20), "never happened: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether one ship reaches another, and is seen there as itself.
fn reaches(net: &Network, from: &str, to: &str) -> bool {
    match net.ping(from, to) {
        Ok(answered) => answered.ship == to.trim_start_matches('~') && answered.seen_as == from.trim_start_matches('~'),
        Err(e) => {
            eprintln!("{from} could not reach {to}: {e}");
            false
        }
    }
}

/// Send `count` commands from `from`'s tally to the counter on `to`, and see them arrive and
/// their receipts come back.
fn trade(from: &Runtime, from_ship: &str, to: &Runtime, to_ship: &str, count: u64) {
    let told = format!("tell {} log hits", to_ship.trim_start_matches('~'));
    let before = to.log_head(to_ship, "counter", "counter").unwrap().map_or(0, |(seq, _)| seq);
    for _ in 0..count {
        assert_eq!(String::from_utf8(from.deliver(from_ship, "tally", told.as_bytes()).unwrap().reply).unwrap(), "sent");
    }
    eventually("the commands arrive", || to.log_head(to_ship, "counter", "counter").unwrap().is_some_and(|(seq, _)| seq == before + count));
    eventually("their receipts come back", || from.outbound_pending(from_ship).unwrap() == 0);
}

#[test]
fn a_ship_behind_a_home_router_is_called_by_name_from_a_public_address_and_from_behind_another() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("cone-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    // ~zod has a public address. ~nec and ~bud are each behind a home router of their own.
    let (zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    let (nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    let (bud_router, bud_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (bud, bud_net) = crew(&dirs[3], "~bud", &urbit, point.addr(), Some(bud_socket));
    eventually("all three are announced, and attend on their connections", || point.point_status().unwrap().attending == 3);
    // Each runtime behind a router was told by the point where it is seen from, its router's
    // outside port, and announced that, asking to be introduced.
    assert_ne!(nec_router.outside(), nec_net.addr());
    // Called by name from a public address, and from behind a router of its own.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(reaches(&bud_net, "~bud", "~nec"));
    // And the other way.
    assert!(reaches(&nec_net, "~nec", "~zod"));
    assert!(reaches(&nec_net, "~nec", "~bud"));
    let introduced = point.point_status().unwrap().introduced;
    assert!(introduced >= 3, "{introduced} introductions");
    // Commands, and their receipts, flow both ways through the routers.
    trade(&zod, "~zod", &nec, "~nec", 3);
    trade(&nec, "~nec", &zod, "~zod", 2);
    trade(&bud, "~bud", &nec, "~nec", 2);
    trade(&nec, "~nec", &bud, "~bud", 2);
    // ~nec was introduced, and sent three packets for each introduction it acted on (each
    // caller's record names one address).
    let _ = bud_router.dropped.load(Ordering::SeqCst);
    eventually("every round is sent", || {
        let seen = nec_net.introductions();
        seen.acted >= 2 && seen.sent == 3 * seen.acted
    });
}

#[test]
fn without_the_introduction_a_ship_behind_a_home_router_cannot_be_called() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("nointro-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    let (nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (_nec, _nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // ~zod does not ask to be introduced. Its call goes to ~nec's outside address, and the
    // router lets nothing in: the call fails, in its time, and says it could not get through.
    zod_net.shared.finder.as_ref().unwrap().introducing.store(false, Ordering::SeqCst);
    let started = Instant::now();
    let why = zod_net.ping("~zod", "~nec").unwrap_err().to_string();
    assert!(started.elapsed() < Duration::from_secs(9), "{:?}", started.elapsed());
    assert!(why.contains("could not be reached directly"), "{why}");
    assert!(nec_router.dropped.load(Ordering::SeqCst) > 0);
    assert_eq!(point.point_status().unwrap().introduced, 0);
    // Asking to be introduced again, it gets through.
    zod_net.shared.finder.as_ref().unwrap().introducing.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    assert!(reaches(&zod_net, "~zod", "~nec"));
}

#[test]
fn with_a_point_that_does_not_relay_a_ship_behind_a_strict_router_cannot_be_called_and_the_call_says_so() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("strict-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (_zod_router, zod_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_nec, _nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    let (_bud, bud_net) = crew(&dirs[3], "~bud", &urbit, point.addr(), None);
    eventually("all three are announced", || point.point_status().unwrap().attending == 3);
    // The introduction is passed on and ~nec sends its packets, but each router gives each
    // destination a port of its own, so neither the packets nor the call find the way open; and
    // the point, asked to relay, says it does not. From behind a strict router of its own, and
    // from a public address, alike.
    for net in [&zod_net, &bud_net] {
        let started = Instant::now();
        let why = net.ping(if std::ptr::eq(net, &zod_net) { "~zod" } else { "~bud" }, "~nec").unwrap_err().to_string();
        assert!(started.elapsed() < Duration::from_secs(9), "{:?}", started.elapsed());
        assert!(why.contains("could not be reached directly") && why.contains("does not relay"), "{why}");
    }
    let status = point.point_status().unwrap();
    assert!(status.introduced >= 2 && status.relay_asked >= 2, "{status:?}");
    assert_eq!((status.relays_made, status.sessions), (0, 0));
    assert_eq!(zod_net.relay_status().calling, 0);
}

#[test]
fn a_connection_through_an_opened_router_keeps_itself_open_while_it_is_idle() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("idle-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    // ~nec's router forgets an opening two seconds after anything last went out through it.
    let (nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(2));
    let (_nec, _nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    let introduced = point.point_status().unwrap().introduced;
    // Nothing is asked of the connection for five seconds, more than twice what the router
    // remembers an idle opening for. (This test waits on the clock, as it must.)
    std::thread::sleep(Duration::from_secs(5));
    // The next request goes over the same connection, at once: it was kept alive, so the
    // router kept the way open, and nobody had to be introduced again.
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    assert_eq!(point.point_status().unwrap().introduced, introduced, "the connection was made again");
    let _ = nec_router.dropped.load(Ordering::SeqCst);
}

#[test]
fn a_ship_behind_a_home_router_stays_within_reach_of_its_point_while_it_says_nothing() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("quiet-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    // ~nec announces itself only every two minutes, and its router forgets an opening two
    // seconds after anything last went out through it.
    let (_nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(2));
    let mut cfg = settings(Some(point.addr()));
    cfg.lookup.announce_every = Duration::from_secs(120);
    let (_nec, _nec_net) = crew_with(&dirs[2], "~nec", &urbit, cfg, Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // Five seconds pass with nothing announced. (This test waits on the clock, as it must.)
    std::thread::sleep(Duration::from_secs(5));
    // The connection to the point kept itself alive, so the router kept the point's way in
    // open: the introduction reaches ~nec, and the call gets through.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(point.point_status().unwrap().pushed >= 1);
}

#[test]
fn a_point_that_has_numbered_as_many_connections_as_it_can_takes_no_more() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("numbered-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    // The last number is given out: the next connection would need one more.
    point.shared.point.as_ref().unwrap().next_connection.store(u64::MAX, Ordering::SeqCst);
    let (_zod, _zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    // ~zod's connections reach the point, and are closed unanswered, so nothing is announced.
    eventually("a connection reaches the point and is refused", || point.point_status().unwrap().unnumbered >= 2);
    assert_eq!(point.point_status().unwrap().records, 0);
    // With numbers to give again, it is announced.
    point.shared.point.as_ref().unwrap().next_connection.store(0, Ordering::SeqCst);
    eventually("~zod is announced", || point.point_status().unwrap().records == 1);
}

/// A runtime holding ~nec, announced to `point` at an address given by hand and asking callers
/// to be introduced, and the callers given, each with its key set by hand in ~nec's directory
/// (so that weighing them asks Urbit ID nothing).
fn introduced_ship(dir: &TempDir, urbit: &Arc<Listings>, point: &Network, callers: &[(String, ed25519_dalek::SigningKey)]) -> (Arc<Runtime>, Network) {
    let mut cfg = settings(Some(point.addr()));
    cfg.lookup.announce = vec!["127.0.0.1:9".parse().unwrap()];
    cfg.lookup.behind_router = true;
    let (nec, nec_net) = crew_with(dir, "~nec", urbit, cfg, None);
    for (ship, key) in callers {
        nec_net.shared.directory.set(ship, key.verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    }
    eventually("~nec is announced asking to be introduced", || nec_net.announced_as("~nec").is_some_and(|(_, introduce)| introduce));
    (nec, nec_net)
}

/// `count` callers from `first` on, each with a key of its own.
fn callers(first: u32, count: u32) -> Vec<(String, ed25519_dalek::SigningKey)> {
    (0..count)
        .map(|n| {
            let ship = first + (n << 16);
            let mut seed = [90u8; 32];
            seed[..4].copy_from_slice(&ship.to_be_bytes());
            (urbit_id::ob::ship_name(ship), ed25519_dalek::SigningKey::from_bytes(&seed))
        })
        .collect()
}

/// Weigh an introduction of `caller` to ~nec, as if its point had passed it on, and what
/// came of it.
fn introduce(net: &Network, caller: &(String, ed25519_dalek::SigningKey)) -> Result<(), &'static str> {
    let record = crate::whereabouts::sign(&caller.0, &["127.0.0.1:9".parse().unwrap()], crate::store::now_ms(), &caller.1, None).unwrap();
    let introduction = ship_proto::Message::encode_to_vec(&ship_proto::Introduction { callee: 1, record, session: Vec::new() });
    net.threads.get().block_on(net.shared.introduced(&introduction, None))
}

#[test]
fn an_introduction_is_acted_on_only_with_a_place_among_those_under_way() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("places-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (first, more) = (callers(0x1234_0100, 16), callers(0x2234_0100, 3));
    let all: Vec<_> = first.iter().chain(&more).cloned().collect();
    let (_nec, nec_net) = introduced_ship(&dirs[1], &urbit, &point, &all);
    // Sixteen callers, each introduced once: sixteen jobs, each holding its place for the half
    // second its packets take. They spend the overall allowance.
    for caller in &first {
        assert_eq!(introduce(&nec_net, caller), Ok(()));
    }
    assert_eq!(nec_net.introductions().acted, 16);
    // The overall allowance earns some back meanwhile. Three more callers: none is acted on
    // while every place is held, for that reason.
    std::thread::sleep(Duration::from_millis(200));
    let punching = &nec_net.shared.punching;
    let before = lock(&punching.all).holds();
    for caller in &more {
        assert_eq!(introduce(&nec_net, caller), Err("too many introductions being acted on"));
    }
    let after = lock(&punching.all).holds();
    assert_eq!(nec_net.introductions().acted, 16);
    // And refused for want of a place, they were charged to no allowance, since the place is
    // taken first: the overall allowance holds no less than before (it only earned more), and
    // none of the three callers was counted at all.
    assert!(after >= before, "the overall allowance went from {before} to {after}");
    let each = lock(&punching.each);
    assert!(more.iter().all(|(caller, _)| !each.contains_key(caller.trim_start_matches('~'))), "a refused caller was charged");
}

#[test]
fn introductions_are_acted_on_only_as_the_overall_allowance_has_earned_back() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("allowance-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (first, more) = (callers(0x1234_0100, 16), callers(0x2234_0100, 16));
    let all: Vec<_> = first.iter().chain(&more).cloned().collect();
    let (_nec, nec_net) = introduced_ship(&dirs[1], &urbit, &point, &all);
    // Sixteen at a stroke spend the overall allowance.
    let started = Instant::now();
    for caller in &first {
        assert_eq!(introduce(&nec_net, caller), Ok(()));
    }
    // The places empty again (each job's packets take half a second), with the allowance only
    // part earned back.
    eventually("the places are free again", || nec_net.shared.punching.under_way.available_permits() == 16);
    // Sixteen more callers: only as many are acted on as the allowance has earned back since,
    // sixteen a second, and the rest are refused for that reason.
    let said: Vec<_> = more.iter().map(|caller| introduce(&nec_net, caller)).collect();
    let earned = 16.0 * started.elapsed().as_secs_f64();
    let acted = said.iter().filter(|outcome| outcome.is_ok()).count();
    assert!(earned < 16.0, "the machine was too slow for this test to mean anything: {earned}");
    assert!(acted as f64 <= earned.ceil(), "{acted} acted on with {earned} earned back");
    assert!(said.iter().any(|outcome| *outcome == Err("too many introductions acted on just now")), "{said:?}");
}

#[test]
fn introductions_of_one_caller_ship_are_acted_on_only_within_its_own_allowance() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("percaller-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let caller = callers(0x1234_0100, 1);
    let (_nec, nec_net) = introduced_ship(&dirs[1], &urbit, &point, &caller);
    // Two at a stroke, then the third is refused for that caller, while the overall allowance
    // and the places have plenty.
    assert_eq!(introduce(&nec_net, &caller[0]), Ok(()));
    assert_eq!(introduce(&nec_net, &caller[0]), Ok(()));
    // The caller's allowance is spent (a slow machine that let it earn one back would make the
    // test mean nothing, and is told so).
    let holds = lock(&nec_net.shared.punching.each).get(caller[0].0.trim_start_matches('~')).map(|bucket| bucket.holds());
    assert!(holds.is_some_and(|holds| holds < 1.0), "inconclusive: the caller's allowance holds {holds:?}");
    assert_eq!(introduce(&nec_net, &caller[0]), Err("too many introductions of that caller just now"));
}


// Relaying through the point (phase 3).

/// Whether the connection kept from one ship to another goes through a relay; `None` if none
/// is kept (or some call holds it just now).
fn relayed(net: &Network, from: &str, to: &str) -> Option<bool> {
    let pair = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    let slot = lock(&net.shared.made).get(&pair)?.clone();
    let held = slot.try_lock().ok()?;
    held.as_ref().map(|made| made.relayed.is_some())
}

/// Close and let go of the connection kept from one ship to another, as if it had been lost.
fn forget_connection(net: &Network, from: &str, to: &str) {
    let pair = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    let slot = lock(&net.shared.made).get(&pair).cloned().expect("a connection is kept");
    let made = slot.try_lock().expect("nobody holds it").take().expect("a connection is kept");
    made.connection.close(quinn::VarInt::from_u32(0), b"forgotten by the test");
}

#[test]
fn two_ships_behind_strict_routers_call_each_other_through_their_point_and_stop_promptly() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("relay-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (zod_router, zod_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // Each calls the other by name, and each direction is relayed: the direct way cannot get
    // through two strict routers.
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(started.elapsed() < Duration::from_secs(8), "{:?}", started.elapsed());
    assert!(reaches(&nec_net, "~nec", "~zod"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    assert_eq!(relayed(&nec_net, "~nec", "~zod"), Some(true));
    assert_eq!((zod_net.relay_status().calling, zod_net.relay_status().called), (1, 1));
    assert_eq!((nec_net.relay_status().calling, nec_net.relay_status().called), (1, 1));
    // Commands and their receipts flow both ways through it.
    trade(&zod, "~zod", &nec, "~nec", 3);
    trade(&nec, "~nec", &zod, "~zod", 2);
    let status = point.point_status().unwrap();
    assert_eq!((status.relays_made, status.sessions), (2, 2), "{status:?}");
    assert!(status.carried_for.len() == 2 && status.carried_for.iter().all(|(_, bytes)| *bytes > 0), "{status:?}");
    // The ships' own connections to that very point, whose packets come from its address too,
    // still work while the sessions carry traffic: both go on being announced over them.
    let announced = status.announced;
    trade(&zod, "~zod", &nec, "~nec", 1);
    eventually("the ships are announced again", || point.point_status().unwrap().announced >= announced + 2);
    // The direct way failed for ~nec's record and the relay worked: the next call on the same
    // record goes straight to the relay, asking for no introduction.
    let introduced = point.point_status().unwrap().introduced;
    forget_connection(&zod_net, "~zod", "~nec");
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    let status = point.point_status().unwrap();
    assert_eq!(status.introduced, introduced);
    assert_eq!(status.relays_made, 3);
    // No made-up address ever reached a router.
    assert_eq!(zod_router.made_up_seen.load(Ordering::SeqCst) + nec_router.made_up_seen.load(Ordering::SeqCst), 0);
    // Stopping is prompt at each of the three, with sessions live.
    for net in [zod_net, nec_net, point] {
        let started = Instant::now();
        drop(net);
        assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
    }
}

#[test]
fn a_ship_at_a_public_address_and_one_behind_a_strict_router_call_each_other() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("halfrelay-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    // ~zod gives a call six seconds: the direct way gets half, three, though one attempt alone
    // would be given four.
    let mut cfg = settings(Some(point.addr()));
    cfg.request_timeout = Duration::from_secs(6);
    let (zod, zod_net) = crew_with(&dirs[1], "~zod", &urbit, cfg, None);
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // ~zod calls ~nec: the router lets in only the point, so it is relayed, and the point is
    // asked to relay when the direct share is spent. ~nec calls ~zod, which can be reached
    // directly, and does so.
    let started = Instant::now();
    let asked_at = std::thread::scope(|scope| {
        let calling = scope.spawn(|| reaches(&zod_net, "~zod", "~nec"));
        while point.point_status().unwrap().relay_asked == 0 && started.elapsed() < Duration::from_secs(6) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let asked_at = started.elapsed();
        assert!(calling.join().unwrap());
        asked_at
    });
    assert!(asked_at > Duration::from_millis(2500) && asked_at < Duration::from_millis(3600), "the point was asked to relay {asked_at:?} into the call");
    assert!(reaches(&nec_net, "~nec", "~zod"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    assert_eq!(relayed(&nec_net, "~nec", "~zod"), Some(false));
    trade(&zod, "~zod", &nec, "~nec", 2);
    trade(&nec, "~nec", &zod, "~zod", 2);
    assert_eq!(point.point_status().unwrap().relays_made, 1);
}

#[test]
fn a_relayed_pair_goes_direct_when_it_can_and_nothing_is_lost_or_delivered_twice() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("godirect-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    // Both behind routers of the usual kind, which an introduction gets through; ~zod tries the
    // direct way again every two seconds while relayed.
    let mut cfg = settings(Some(point.addr()));
    cfg.lookup.direct_again = Duration::from_secs(2);
    let (_zod_router, zod_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (zod, zod_net) = crew_with(&dirs[1], "~zod", &urbit, cfg, Some(zod_socket));
    let (_nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // With the introduction made to fail, the direct way cannot get in, and the call is
    // relayed. (At both ends: the receipts go back from ~nec to ~zod, and an introduction that
    // way would open both routers.)
    let introducing = &zod_net.shared.finder.as_ref().unwrap().introducing;
    let nec_introducing = &nec_net.shared.finder.as_ref().unwrap().introducing;
    introducing.store(false, Ordering::SeqCst);
    nec_introducing.store(false, Ordering::SeqCst);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    assert!(zod_net.shared.finder.as_ref().unwrap().remembers_relay("nec"));
    // Tries at the direct way (only pings meanwhile, which go one way: a call back from ~nec
    // would open both routers by itself, as calls both ways do): none before two seconds of use; then one, which fails (the
    // introduction still fails) and runs for its four seconds; two seconds on, another use
    // would be due, but one is still under way for the pair, so none begins.
    let tried = || zod_net.shared.direct_tried.load(Ordering::SeqCst);
    for _ in 0..5 {
        assert!(reaches(&zod_net, "~zod", "~nec"));
    }
    assert_eq!(tried(), 0, "a try began before it was due");
    // Due, but every place among the tries in all is taken: none begins, and the pair is not
    // left marked as trying.
    let all_places = zod_net.shared.direct_tries.clone().try_acquire_many_owned(MOST_DIRECT_TRIES as u32).unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(tried(), 0, "a try began with no place for it");
    assert!(lock(&zod_net.shared.going_direct).is_empty());
    drop(all_places);
    std::thread::sleep(Duration::from_millis(2100));
    for _ in 0..5 {
        assert!(reaches(&zod_net, "~zod", "~nec"));
    }
    assert_eq!(tried(), 1);
    std::thread::sleep(Duration::from_millis(2100));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(tried(), 1, "a second try began while one was under way for the pair");
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true), "a failed try changed the connection");
    // The try under way ends (failing, before the ship called took anything) before the direct
    // way is let work, so that only the tries below can get through.
    eventually("the try under way ends", || lock(&zod_net.shared.going_direct).is_empty());
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true), "a failed try changed the connection");
    // Later the direct way works: the pair moves to it while commands keep going.
    introducing.store(true, Ordering::SeqCst);
    nec_introducing.store(true, Ordering::SeqCst);
    // First, a try that began from some other kept connection (by QUIC's number for it) makes a
    // direct connection, and must not take the place of the one kept now.
    let opened = zod_net.open_connections();
    let made = zod_net.shared.direct_made.load(Ordering::SeqCst);
    zod_net.threads.get().block_on(try_direct(&zod_net, "zod", "nec", u64::MAX)).unwrap();
    assert_eq!(zod_net.shared.direct_made.load(Ordering::SeqCst), made + 1, "the try made no candidate");
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true), "a try replaced a connection it did not begin from");
    eventually("the try's own connection is closed", || zod_net.open_connections() <= opened);
    // And the kept connection still carries what is asked of it.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    let started = Instant::now();
    while relayed(&zod_net, "~zod", "~nec") != Some(false) {
        assert!(started.elapsed() < Duration::from_secs(30), "the pair never went direct");
        trade(&zod, "~zod", &nec, "~nec", 1);
        std::thread::sleep(Duration::from_millis(100));
    }
    // New requests go direct: nothing more is carried. Every command arrived exactly once, and
    // its receipt came back (each `trade` counts them).
    eventually("the relayed connection is closed, and its session let go of", || zod_net.relay_status().calling == 0);
    let carried = point.point_status().unwrap().relayed.carried;
    trade(&zod, "~zod", &nec, "~nec", 3);
    trade(&nec, "~nec", &zod, "~zod", 1);
    assert_eq!(point.point_status().unwrap().relayed.carried, carried);
    // The session ends at the point and at ~nec once nothing passes for the idle time.
    point.shared.point.as_ref().unwrap().step_relay(crate::relay::IDLE);
    assert_eq!(point.point_status().unwrap().sessions, 0);
    nec_net.shared.relayed.as_ref().unwrap().step(crate::relay::IDLE);
    assert_eq!(nec_net.relay_status().called, 0);
    // The direct way worked: no record of ~nec is remembered as one for the relay any more.
    assert!(!zod_net.shared.finder.as_ref().unwrap().remembers_relay("nec"));
}

#[test]
fn with_an_address_set_by_hand_no_relay_is_asked_for_or_used() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("relayhand-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (_zod_router, zod_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    zod_net.shared.finder.as_ref().unwrap().introducing.store(false, Ordering::SeqCst);
    // Set while a relayed call is under way: the point holds the request to relay (its source
    // of keys waits); the address is set by hand; the point answers. The call reads the
    // directory again before it uses the session, and stops.
    // ~zod's directory reads ~nec's key now, from the same stand-in, so that holding it below
    // holds only the point.
    zod_net.shared.directory.read("nec");
    assert!(zod_net.shared.directory.key_of("~nec").is_some());
    urbit.1.store(true, Ordering::SeqCst);
    let asked = point.point_status().unwrap().relay_asked;
    let why = std::thread::scope(|scope| {
        let calling = scope.spawn(|| zod_net.ping("~zod", "~nec"));
        eventually("the point holds the request to relay", || point.point_status().unwrap().relay_asked > asked);
        zod_net.shared.directory.place("~nec", nec_net.addr()).unwrap();
        urbit.1.store(false, Ordering::SeqCst);
        calling.join().unwrap().unwrap_err().to_string()
    });
    assert!(why.contains("the directory changed"), "{why}");
    assert_eq!(zod_net.relay_status().calling, 0);
    assert_eq!(point.point_status().unwrap().relayed.carried, 0);
    // With the address set, a call goes there and nowhere else: no relay is asked for.
    let (asked, introduced) = (point.point_status().unwrap().relay_asked, point.point_status().unwrap().introduced);
    assert!(zod_net.ping("~zod", "~nec").is_err());
    let status = point.point_status().unwrap();
    assert_eq!((status.relay_asked, status.introduced), (asked, introduced));
    assert_eq!(zod_net.relay_status().calling, 0);
}

#[test]
fn a_runtime_with_no_lookup_settings_has_its_socket_and_quic_as_they_were() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("plain-{n}"))).collect();
    let rt = Arc::new(Runtime::open(&dirs[0].0, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
    let plain = Network::start(rt, Directory::new(), settings(None)).unwrap();
    assert!(plain.shared.relayed.is_none());
    assert!(plain.shared.greases);
    assert_eq!(plain.relay_status(), crate::relay::RelayStatus::default());
    // With lookup settings, the socket is wrapped and the fixed bit is not greased.
    let urbit = Arc::new(Listings::default());
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, "127.0.0.1:9".parse().unwrap(), None);
    assert!(zod_net.shared.relayed.is_some());
    assert!(!zod_net.shared.greases);
}

#[test]
fn a_relayed_connection_idle_past_its_routers_memory_still_works_and_no_made_up_address_reaches_them() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("relayidle-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    // Both routers forget an opening two seconds after anything last went out through it.
    let (zod_router, zod_socket) = behind(Kind::Strict, Duration::from_secs(2));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(2));
    let (_nec, _nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    let made = point.point_status().unwrap().relays_made;
    // Nothing is asked of it for five seconds. (This test waits on the clock, as it must.)
    std::thread::sleep(Duration::from_secs(5));
    // The next request goes over the same connection, at once: it kept itself alive, through the
    // session, so the routers kept the way to the point open.
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    assert_eq!(point.point_status().unwrap().relays_made, made, "the connection was made again");
    // ~zod's session is let go of while QUIC still sends on the connection (a packet every
    // second keeps it alive): QUIC's packets for the made-up address go nowhere, and none
    // reaches the router.
    // ~zod only calls through its session here, and its connection holds its packets to what
    // fits with the header. QUIC's search for the path's size reaches that bound (1,452 with
    // the header); it must not go past it while traffic goes on.
    let largest = || zod_router.largest_relayed_out.load(Ordering::SeqCst);
    let searching = Instant::now();
    while largest() < 1452 {
        assert!(searching.elapsed() < Duration::from_secs(20), "inconclusive: QUIC's size search reached only {} bytes", largest());
        assert!(reaches(&zod_net, "~zod", "~nec"));
        std::thread::sleep(Duration::from_millis(100));
    }
    for _ in 0..20 {
        assert!(reaches(&zod_net, "~zod", "~nec"));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(largest(), 1452, "a relayed datagram of {} bytes", largest());
    let unsent = zod_net.relay_status().unsent;
    zod_net.shared.relayed.as_ref().unwrap().release_all();
    eventually("QUIC sends to the made-up address", || zod_net.relay_status().unsent > unsent);
    assert_eq!(zod_router.made_up_seen.load(Ordering::SeqCst) + nec_router.made_up_seen.load(Ordering::SeqCst), 0);
}

#[test]
fn a_point_carries_a_sessions_packets_only_from_its_two_addresses_and_only_while_the_ship_called_attends() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("carry-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (zod_router, zod_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (_nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // A session is made as a call makes one, and nothing dials through it: the test speaks on
    // it itself, from the routers' own outside ports, which are what the point pinned.
    let finder = zod_net.shared.finder.clone().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (at, id) = zod_net.threads.get().block_on(finder.relay(&zod, "zod", "nec", deadline)).unwrap();
    assert_eq!(at, point.addr());
    eventually("~nec registers the session", || nec_net.relay_status().called == 1);
    let counts = || point.point_status().unwrap().relayed;
    let carried_in = || nec_router.relayed_in.load(Ordering::SeqCst);
    // A packet of noughts, which QUIC drops without a word.
    let packet = crate::relay::wrapped(&id, &[0; 40]);
    // From ~zod's pinned address: carried to ~nec, as it came.
    let before = carried_in();
    zod_router.send_from(point.addr(), &packet);
    eventually("it is carried to ~nec", || carried_in() == before + 1);
    // From a stranger, and naming no session from ~zod's own address: neither is carried, and
    // nothing comes back to the stranger.
    let stranger = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (stranger_before, unknown_before) = (counts().stranger, counts().unknown);
    stranger.send_to(&packet, point.addr()).unwrap();
    zod_router.send_from(point.addr(), &crate::relay::wrapped(&[9; 16], &[0; 40]));
    eventually("the point drops both", || counts().stranger > stranger_before && counts().unknown > unknown_before);
    // ~nec's connection to the point closes: its session ends at the point and at ~nec, and a
    // packet on it from ~zod's own address is not carried.
    nec_net.shared.finder.as_ref().unwrap().drop_lanes();
    eventually("the session ends at the point", || point.point_status().unwrap().sessions == 0);
    eventually("and at ~nec", || nec_net.relay_status().called == 0);
    let unknown_before = counts().unknown;
    zod_router.send_from(point.addr(), &packet);
    eventually("the point drops it", || counts().unknown > unknown_before);
    assert_eq!(carried_in(), before + 1);
    stranger.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    assert!(stranger.recv_from(&mut [0u8; 2048]).is_err(), "the stranger was answered");
}

#[test]
fn a_flood_of_relayed_packets_and_requests_to_relay_leaves_ordinary_lookups_and_calls_working() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("relayflood-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    // ~nec is behind a strict router: ~zod's calls to it go through the point, and keep going
    // through it while the floods are on.
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    let (bud, bud_net) = crew(&dirs[3], "~bud", &urbit, point.addr(), None);
    eventually("all three are announced", || point.point_status().unwrap().attending == 3);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (packets, requests) = (AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|scope| {
        // Relayed packets naming sessions nobody has, at the point and at ~nec, as fast as one
        // thread sends them with a breath every fifty.
        scope.spawn(|| {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut n = 0u64;
            while !stop.load(Ordering::SeqCst) {
                n += 1;
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&n.to_be_bytes());
                let packet = crate::relay::wrapped(&id, &[0x41; 1200]);
                let _ = socket.send_to(&packet, point.addr());
                let _ = socket.send_to(&packet, zod_net.addr());
                if packets.fetch_add(1, Ordering::SeqCst) % 50 == 0 {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
        });
        // Requests to relay, from ~bud, over and over: each refused (~nec asks for no
        // introductions, and soon the rates refuse them first).
        scope.spawn(|| {
            let finder = bud_net.shared.finder.clone().unwrap();
            while !stop.load(Ordering::SeqCst) {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                let _ = bud_net.threads.get().block_on(finder.relay(&bud, "bud", "nec", deadline));
                requests.fetch_add(1, Ordering::SeqCst);
            }
        });
        // The floods stop however this ends, a failed assertion included.
        struct Stop<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _stop = Stop(&stop);
        // Meanwhile, calls that each need a lookup and a new connection first: each completes,
        // and both floods went on while it did (counted before and after). (~bud's own
        // questions share its connection with its flood, which its connection's allowance
        // meters, so ~bud does not call.)
        eventually("both floods are under way", || packets.load(Ordering::SeqCst) > 100 && requests.load(Ordering::SeqCst) > 5);
        // Live sessions carry traffic meanwhile: ~zod calls ~nec through the point, over and
        // over, and the point carries it.
        let carried = point.point_status().unwrap().relayed.carried;
        let p = packets.load(Ordering::SeqCst);
        for _ in 0..20 {
            let started = Instant::now();
            assert!(reaches(&zod_net, "~zod", "~nec"), "the relayed call failed during the flood");
            assert!(started.elapsed() < Duration::from_secs(3), "a relayed call took {:?}", started.elapsed());
        }
        assert!(packets.load(Ordering::SeqCst) > p, "inconclusive: no packet was sent during the relayed calls");
        assert!(point.point_status().unwrap().relayed.carried > carried);
        assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
        for (net, from, to) in [(&nec_net, "~nec", "~zod"), (&zod_net, "~zod", "~bud"), (&nec_net, "~nec", "~bud")] {
            let (p, r) = (packets.load(Ordering::SeqCst), requests.load(Ordering::SeqCst));
            let started = Instant::now();
            assert!(reaches(net, from, to), "{from} could not reach {to} during the flood");
            assert!(started.elapsed() < Duration::from_secs(3), "{from} to {to} took {:?}", started.elapsed());
            assert!(packets.load(Ordering::SeqCst) > p, "inconclusive: no packet was sent during the call");
            assert!(requests.load(Ordering::SeqCst) > r || started.elapsed() < Duration::from_millis(50), "inconclusive: no request was made during the call");
        }
    });
    let status = point.point_status().unwrap();
    assert!(status.relayed.unknown > 0 && status.relay_asked > 0 && status.relays_made >= 1, "{status:?}");
    assert!(zod_net.relay_status().dropped > 0);
}

#[test]
fn a_relay_is_asked_for_only_for_a_record_that_asks_for_introductions() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("onlyflagged-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), None);
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), None);
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // ~nec, at a public address, asks for no introduction, and then goes away. Its record is
    // still handed out; nothing answers at its address; and no relay is asked for.
    assert_eq!(nec_net.announced_as("~nec").map(|(_, introduce)| introduce), Some(false));
    drop(nec_net);
    drop(nec);
    let why = zod_net.ping("~zod", "~nec").unwrap_err().to_string();
    assert!(!why.contains("relay"), "{why}");
    let status = point.point_status().unwrap();
    assert_eq!((status.relay_asked, status.introduced), (0, 0), "{status:?}");
}

/// Start a try at going direct for a pair, as the kept connection's use would, from the kept
/// entry of generation `relayed`, on the network's own threads.
fn try_direct(net: &Network, from: &str, to: &str, relayed: u64) -> tokio::task::JoinHandle<()> {
    let pair = (from.to_string(), to.to_string());
    let shared = net.shared.clone();
    let turn = shared.direct_tries.clone().try_acquire_owned().unwrap();
    lock(&shared.going_direct).insert(pair.clone());
    let trying = crate::net::Trying(shared.clone(), pair.clone());
    net.threads.get().spawn(shared.go_direct(pair, relayed, trying, turn))
}

/// The generation of the entry kept from one ship to another.
fn kept_id(net: &Network, from: &str, to: &str) -> u64 {
    let pair = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    let slot = lock(&net.shared.made).get(&pair).cloned().expect("a connection is kept");
    let held = slot.try_lock().expect("nobody holds it");
    held.as_ref().expect("a connection is kept").generation
}

/// QUIC's number for the connection kept from one ship to another (held by the entry while it
/// is kept, so the number names that connection meanwhile).
fn kept_connection(net: &Network, from: &str, to: &str) -> usize {
    let pair = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    let slot = lock(&net.shared.made).get(&pair).cloned().expect("a connection is kept");
    let held = slot.try_lock().expect("nobody holds it");
    held.as_ref().expect("a connection is kept").connection.stable_id()
}

/// The place where the connection from one ship to another is kept.
fn slot_of(net: &Network, from: &str, to: &str) -> Arc<tokio::sync::Mutex<Option<crate::net::Made>>> {
    let pair = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    lock(&net.shared.made).get(&pair).cloned().expect("a connection is kept")
}

struct ConePair {
    _dirs: Vec<TempDir>,
    urbit: Arc<Listings>,
    point: Network,
    zod: Arc<Runtime>,
    zod_net: Network,
    nec: Arc<Runtime>,
    nec_net: Network,
    _routers: (Arc<Router>, Arc<Router>),
    _point_rt: Arc<Runtime>,
}

/// Two ships behind routers of the usual kind, ~zod's call to ~nec relayed (introductions made
/// to fail at both ends), and then introductions working again: a try at going direct will get
/// through.
fn relayed_cone_pair(label: &str) -> ConePair {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("{label}-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let (zod_router, zod_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (nec_router, nec_socket) = behind(Kind::Cone, Duration::from_secs(30));
    let (nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    let introducing = |net: &Network, on: bool| net.shared.finder.as_ref().unwrap().introducing.store(on, Ordering::SeqCst);
    introducing(&zod_net, false);
    introducing(&nec_net, false);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    introducing(&zod_net, true);
    introducing(&nec_net, true);
    ConePair { _dirs: dirs, urbit, point, zod, zod_net, nec, nec_net, _routers: (zod_router, nec_router), _point_rt: point_rt }
}

#[test]
fn a_try_at_going_direct_is_weighed_where_it_commits_and_waits_for_the_slot_no_longer_than_its_deadline() {
    let pair = relayed_cone_pair("commit");
    let net = &pair.zod_net;
    let made = || net.shared.direct_made.load(Ordering::SeqCst);
    let slot = slot_of(net, "~zod", "~nec");
    let relayed_id = kept_id(net, "~zod", "~nec");
    // An address set by hand between the try's candidate and its commit: the candidate is closed
    // and the kept entry untouched. (The test holds the pair's slot: the try waits for it.)
    let opened = net.open_connections();
    let held = slot.try_lock().unwrap();
    let trying = try_direct(net, "zod", "nec", relayed_id);
    eventually("the try has made its candidate", || made() == 1);
    net.shared.directory.place("~nec", pair.nec_net.addr()).unwrap();
    drop(held);
    net.threads.get().block_on(trying).unwrap();
    assert_eq!(kept_id(net, "~zod", "~nec"), relayed_id);
    assert_eq!(relayed(net, "~zod", "~nec"), Some(true));
    eventually("the candidate is closed", || net.open_connections() <= opened);
    net.shared.directory.listed.write().unwrap().places.remove("nec");
    // The ship's key changes in the same gap: the same.
    let held = slot.try_lock().unwrap();
    let trying = try_direct(net, "zod", "nec", relayed_id);
    eventually("the try has made its candidate", || made() == 2);
    let real = {
        let mut listed = net.shared.directory.listed.write().unwrap();
        let entry = listed.keys.get_mut("nec").unwrap();
        std::mem::replace(&mut entry.key, [7; 32])
    };
    drop(held);
    net.threads.get().block_on(trying).unwrap();
    assert_eq!(kept_id(net, "~zod", "~nec"), relayed_id);
    eventually("the candidate is closed", || net.open_connections() <= opened);
    net.shared.directory.listed.write().unwrap().keys.get_mut("nec").unwrap().key = real;
    // The kept entry is replaced, in the gap, by another for the same pair: the same relayed
    // connection, session and calling key, so the same by every field but its generation (and
    // by QUIC's number for the connection, which the check used to compare). The try's commit
    // refuses it.
    let held = slot.try_lock().unwrap();
    let trying = try_direct(net, "zod", "nec", relayed_id);
    eventually("the try has made its candidate", || made() == 3);
    let mut held = held;
    let renewed = net.shared.generations.fetch_add(1, Ordering::SeqCst);
    held.as_mut().unwrap().generation = renewed;
    drop(held);
    net.threads.get().block_on(trying).unwrap();
    assert_eq!(kept_id(net, "~zod", "~nec"), renewed);
    assert_eq!(relayed(net, "~zod", "~nec"), Some(true));
    eventually("the candidate is closed", || net.open_connections() <= opened);
    let relayed_id = renewed;
    // In the gap, the ship called is dropped from the directory, the room for proved keys is
    // filled with other ships, and the same key is read afresh for it, not yet proved. The route
    // is still found with the same key; the proof finds no room, and refuses.
    let held = slot.try_lock().unwrap();
    let trying = try_direct(net, "zod", "nec", relayed_id);
    eventually("the try has made its candidate", || made() == 4);
    let proved_room = net.shared.directory.bounds.proved;
    {
        let mut listed = net.shared.directory.listed.write().unwrap();
        let entry = listed.keys.remove("nec").unwrap();
        for n in 0..proved_room {
            listed.keys.insert(format!("filler-{n}"), crate::net::Entry { key: [1; 32], from: crate::net::From::Read { at: std::time::Instant::now(), revision: 1, doubted: false }, proved: true });
        }
        listed.keys.insert("nec".into(), crate::net::Entry { key: entry.key, from: crate::net::From::Read { at: std::time::Instant::now(), revision: 1, doubted: false }, proved: false });
    }
    drop(held);
    net.threads.get().block_on(trying).unwrap();
    assert_eq!(kept_id(net, "~zod", "~nec"), relayed_id);
    assert_eq!(relayed(net, "~zod", "~nec"), Some(true));
    eventually("the candidate is closed", || net.open_connections() <= opened);
    {
        let mut listed = net.shared.directory.listed.write().unwrap();
        listed.keys.retain(|name, _| !name.starts_with("filler-"));
        listed.keys.get_mut("nec").unwrap().proved = true;
    }
    // The slot held past the try's deadline: the try gives up then, closes its candidate, and
    // gives back its place.
    let held = slot.try_lock().unwrap();
    let started = Instant::now();
    let trying = try_direct(net, "zod", "nec", relayed_id);
    let ended = net.threads.get().block_on(async { tokio::time::timeout(Duration::from_secs(12), trying).await });
    assert!(ended.is_ok(), "the try waited for the slot past its deadline");
    assert!(started.elapsed() >= Duration::from_secs(7), "{:?}", started.elapsed());
    assert_eq!(made(), 5);
    assert_eq!(net.shared.direct_tries.available_permits(), MOST_DIRECT_TRIES);
    drop(held);
    assert_eq!(kept_id(net, "~zod", "~nec"), relayed_id);
    eventually("the candidate is closed", || net.open_connections() <= opened);
    // The relayed connection closed (as the ship called closes it when it takes a direct one)
    // before the commit: the candidate still takes its place.
    slot.try_lock().unwrap().as_ref().unwrap().connection.close(quinn::VarInt::from_u32(0), b"closed by the test");
    net.threads.get().block_on(try_direct(net, "zod", "nec", relayed_id)).unwrap();
    assert_eq!(relayed(net, "~zod", "~nec"), Some(false), "a good candidate was thrown away");
    assert!(reaches(net, "~zod", "~nec"));
    assert_eq!(relayed(net, "~zod", "~nec"), Some(false));
}

#[test]
fn a_command_under_way_on_a_relayed_connection_when_the_pair_goes_direct_arrives_exactly_once() {
    let pair = relayed_cone_pair("handoff");
    let net = &pair.zod_net;
    let relayed_id = kept_id(net, "~zod", "~nec");
    // ~zod's packets for its sessions are held back: a command sent now is under way on the
    // relayed connection, and does not arrive.
    let wrapper = net.shared.relayed.clone().unwrap();
    *lock(&wrapper.holding) = Some(Vec::new());
    let before = pair.nec.log_head("~nec", "counter", "counter").unwrap().map_or(0, |(seq, _)| seq);
    // The gate: the next Deliver request is held once it has been written, before its reply is
    // read, until the test lets it go.
    let gate = &net.shared.deliver_gate;
    gate.armed.store(true, Ordering::SeqCst);
    assert_eq!(String::from_utf8(pair.zod.deliver("~zod", "tally", b"tell nec log hits").unwrap().reply).unwrap(), "sent");
    let relayed_connection = kept_connection(net, "~zod", "~nec");
    eventually("a Deliver is written on the relayed connection and held", || *lock(&gate.holding) == Some(relayed_connection));
    assert_eq!(pair.nec.log_head("~nec", "counter", "counter").unwrap().map_or(0, |(seq, _)| seq), before, "the command got through the hold");
    // The pair goes direct while that request is still under way.
    net.threads.get().block_on(try_direct(net, "zod", "nec", relayed_id)).unwrap();
    assert_eq!(relayed(net, "~zod", "~nec"), Some(false));
    assert!(!gate.ended.load(Ordering::SeqCst) && lock(&gate.holding).is_some(), "inconclusive: the held Deliver ended before the pair went direct");
    // It is let go: its connection has closed, so it fails, and the command is delivered again.
    gate.release.notify_one();
    eventually("the held Deliver ends", || gate.ended.load(Ordering::SeqCst));
    *lock(&wrapper.holding) = None;
    // The command arrives, once, and its receipt comes back; the next goes too, on the direct
    // connection, and is counted exactly.
    eventually("the command arrives", || pair.nec.log_head("~nec", "counter", "counter").unwrap().is_some_and(|(seq, _)| seq >= before + 1));
    eventually("its receipt comes back", || pair.zod.outbound_pending("~zod").unwrap() == 0);
    trade(&pair.zod, "~zod", &pair.nec, "~nec", 1);
    assert_eq!(pair.nec.log_head("~nec", "counter", "counter").unwrap().map(|(seq, _)| seq), Some(before + 2));
    assert_eq!(relayed(net, "~zod", "~nec"), Some(false));
    let _ = (&pair.urbit, &pair.point, &pair.nec_net);
}

#[test]
fn a_ship_set_by_hand_at_a_made_up_address_is_not_called_through_anyones_session() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("placedmadeup-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    // ~zod and ~marzod on one runtime; ~nec behind a strict router.
    let (_zod, zod_net) = crew_of(&dirs[1], &["~zod", "~marzod"], &urbit, settings(Some(point.addr())), None);
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_nec, nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("all three are announced", || point.point_status().unwrap().attending == 3);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
    // ~nec is set by hand at the very made-up address of ~zod's live session to it.
    let session = {
        let slot = slot_of(&zod_net, "~zod", "~nec");
        let held = slot.try_lock().unwrap();
        held.as_ref().unwrap().peer.addr
    };
    assert!(crate::relay::is_made_up(&session));
    zod_net.shared.directory.place("~nec", session).unwrap();
    // ~marzod's call is refused before anything is sent, saying why: no connection from it
    // reaches ~nec through the session (~nec counts each calling pair it has taken).
    let callers = nec_net.callers_remembered();
    let why = zod_net.ping("~marzod", "~nec").unwrap_err().to_string();
    assert!(why.contains("an address no ship can be at"), "{why}");
    assert_eq!(nec_net.callers_remembered(), callers);
    // ~zod's relayed connection is undisturbed.
    assert_eq!(relayed(&zod_net, "~zod", "~nec"), Some(true));
}

/// Files go over a relayed connection too, at the relay's limits: ~zod's owner, whose ship
/// reaches ~nec only through their point's relay, fetches a file ~nec's counter has opened.
#[test]
fn a_file_is_fetched_over_a_relayed_connection() {
    use std::io::{Read, Write};
    let pair = relayed_cone_pair("file");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
    let (upload, chunks) = pair.nec.upload_start("~nec", "counter", data.len() as u64, "").unwrap();
    assert_eq!(chunks, 1);
    pair.nec.upload_chunk("~nec", "counter", &upload, 0, data.clone()).unwrap();
    let id = pair.nec.upload_finish("~nec", "counter", &upload, None).unwrap().id;
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(String::from_utf8(pair.nec.deliver("~nec", "counter", format!("open {hex}").as_bytes()).unwrap().reply).unwrap(), "true");
    let server = crate::server::Server::start(pair.zod.clone(), crate::server::ServerConfig::default()).unwrap();
    let code = pair.zod.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let token = pair.zod.sign_in("~zod", &code, "test").unwrap().0;
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    write!(stream, "GET /ships/zod/files/from/nec/counter/{hex}/content HTTP/1.0\r\nAuthorization: Bearer {token}\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
    assert!(raw.starts_with(b"HTTP/1.1 200 "), "{}", String::from_utf8_lossy(&raw[..split]));
    assert!(raw[split + 4..] == data[..], "the contents differ");
    assert_eq!(relayed(&pair.zod_net, "~zod", "~nec"), Some(true));
}

// A request to be introduced or relayed, overtaken by the ship's own announcement.

struct QuietPair {
    _dirs: Vec<TempDir>,
    point: Network,
    zod: Arc<Runtime>,
    zod_net: Network,
    _nec: Arc<Runtime>,
    _nec_net: Network,
    _point_rt: Arc<Runtime>,
}

/// A point that relays, and ~zod and ~nec at public addresses, each announced once, at start,
/// and not again for five minutes (the longest `announce_every` may be, far longer than these
/// tests) unless the test does it; ~nec's record asks callers to be introduced. So no
/// announcement can overtake a request but the one a test makes.
fn quiet_pair(label: &str) -> QuietPair {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("{label}-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (point_rt, point) = point_relaying(&dirs[0], &urbit, Some(RelayBounds::default()));
    let quiet = |behind_router: bool| {
        let mut cfg = settings(Some(point.addr()));
        cfg.lookup.announce_every = Duration::from_secs(300);
        cfg.lookup.behind_router = behind_router;
        cfg
    };
    let (zod, zod_net) = crew_with(&dirs[1], "~zod", &urbit, quiet(false), None);
    let (nec, nec_net) = crew_with(&dirs[2], "~nec", &urbit, quiet(true), None);
    eventually("both are announced", || point.point_status().unwrap().attending == 2 && zod_net.announced_as("~zod").is_some() && nec_net.announced_as("~nec").is_some_and(|(_, introduce)| introduce));
    QuietPair { _dirs: dirs, point, zod, zod_net, _nec: nec, _nec_net: nec_net, _point_rt: point_rt }
}

/// Which request to a point these bytes are, to be introduced or relayed, and when the record in
/// it was made; `None` for any other.
fn signed_request(request: &[u8]) -> Option<(&'static str, u64)> {
    let (kind, record) = match WhereRequest::decode(request).ok()?.body? {
        where_request::Body::Introduce(Introduce { record, .. }) => ("introduce", record),
        where_request::Body::Relay(Relay { record, .. }) => ("relay", record),
        _ => return None,
    };
    Some((kind, Whereabouts::decode(&*record).ok()?.issued))
}

/// What a stand-in saw of the requests of one kind ~zod made: when each one's record was made,
/// what came of the announcement made after the first was signed and before it was sent, and
/// when the record the point then held of ~zod was made.
#[derive(Default)]
struct Overtaking {
    issued: Mutex<Vec<u64>>,
    announced: Mutex<Option<Result<Option<String>, String>>>,
    overtook: Mutex<Option<u64>>,
}

/// Between signing ~zod's first request of `kind` and sending it, ~zod's own announcer signs a
/// newer record and the point keeps it: the overtaking, made to happen every time. Every request
/// is then sent to the point as it is.
fn overtake_first(pair: &QuietPair, kind: &'static str) -> Arc<Overtaking> {
    let finder = pair.zod_net.shared.finder.clone().unwrap();
    let seen = Arc::new(Overtaking::default());
    let (weak, zod, point, kept) = (Arc::downgrade(&finder), pair.zod.clone(), pair.point.shared.point.clone().unwrap(), seen.clone());
    let stand_in: StandIn = Arc::new(move |request| {
        let (weak, zod, point, seen) = (weak.clone(), zod.clone(), point.clone(), kept.clone());
        Box::pin(async move {
            let (_, issued) = signed_request(&request).filter(|(asked, _)| *asked == kind)?;
            let first = {
                let mut all = lock(&seen.issued);
                all.push(issued);
                all.len() == 1
            };
            if let (true, Some(finder)) = (first, weak.upgrade()) {
                let announced = finder.announce_now(&zod, "zod").await;
                *lock(&seen.announced) = Some(announced);
                *lock(&seen.overtook) = point.held_issued(0);
            }
            None
        })
    });
    *lock(&finder.stand_in) = Some(stand_in);
    seen
}

/// After an overtaken call: two requests, the first's record made before the announcement that
/// overtook it, which the point kept, and the second's after it; and the point still holds that
/// announcement (a request's record is never kept).
fn overtaken_twice(pair: &QuietPair, seen: &Overtaking) {
    assert_eq!(lock(&seen.announced).clone(), Some(Ok(None)), "the overtaking announcement was not kept");
    let issued = lock(&seen.issued).clone();
    let overtook = lock(&seen.overtook).expect("the point holds a record of ~zod");
    assert_eq!(issued.len(), 2, "{issued:?}");
    assert!(issued[0] < overtook && overtook < issued[1], "requests {issued:?}, announcement {overtook}");
    assert_eq!(pair.point.shared.point.as_ref().unwrap().held_issued(0), Some(overtook));
}

/// Put a stand-in point before ~zod's: each request to be introduced or relayed is counted and
/// refused in these words, and nothing is sent.
fn refusing(net: &Network, words: &str) -> Arc<AtomicUsize> {
    let asked = Arc::new(AtomicUsize::new(0));
    let (counted, words) = (asked.clone(), words.to_string());
    let stand_in: StandIn = Arc::new(move |request| {
        let answer = signed_request(&request).map(|_| {
            counted.fetch_add(1, Ordering::SeqCst);
            WhereReply { body: None, refused: words.clone() }
        });
        Box::pin(async move { answer })
    });
    *lock(&net.shared.finder.as_ref().unwrap().stand_in) = Some(stand_in);
    asked
}

/// ~zod asks the point to relay it to ~nec, and to introduce it, each by `deadline`.
fn relay_and_introduce(pair: &QuietPair, deadline: impl Fn() -> tokio::time::Instant) -> (Result<(SocketAddr, crate::relay::SessionId), String>, Result<(), String>) {
    let finder = pair.zod_net.shared.finder.clone().unwrap();
    let relayed = pair.zod_net.threads.get().block_on(finder.relay(&pair.zod, "zod", "nec", deadline()));
    let introduced = pair.zod_net.threads.get().block_on(finder.introduce(&pair.zod, "zod", "nec", deadline()));
    (relayed, introduced)
}

fn eight_seconds() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(8)
}

#[test]
fn a_request_to_relay_overtaken_by_the_ships_own_announcement_is_made_once_more_and_relayed() {
    let pair = quiet_pair("overtaken-relay");
    let seen = overtake_first(&pair, "relay");
    let before = pair.point.point_status().unwrap();
    let finder = pair.zod_net.shared.finder.clone().unwrap();
    let relayed = pair.zod_net.threads.get().block_on(finder.relay(&pair.zod, "zod", "nec", eight_seconds()));
    assert!(relayed.is_ok(), "{relayed:?}");
    let after = pair.point.point_status().unwrap();
    assert_eq!((after.relay_asked - before.relay_asked, after.relays_made - before.relays_made), (2, 1), "{after:?}");
    overtaken_twice(&pair, &seen);
}

#[test]
fn a_request_to_be_introduced_overtaken_by_the_ships_own_announcement_is_made_once_more_and_passed_on() {
    let pair = quiet_pair("overtaken-introduce");
    let seen = overtake_first(&pair, "introduce");
    let before = pair.point.point_status().unwrap();
    let finder = pair.zod_net.shared.finder.clone().unwrap();
    let introduced = pair.zod_net.threads.get().block_on(finder.introduce(&pair.zod, "zod", "nec", eight_seconds()));
    assert_eq!(introduced, Ok(()));
    // The point weighed three records: the announcement and the two requests' (each request's
    // record is counted against the record rates as it arrives); it passed one on.
    let after = pair.point.point_status().unwrap();
    assert_eq!((after.announced - before.announced, after.introduced - before.introduced), (3, 1), "{after:?}");
    overtaken_twice(&pair, &seen);
}

#[test]
fn a_point_that_always_says_a_newer_record_is_held_gets_two_requests_and_the_call_fails_as_before() {
    let pair = quiet_pair("twice");
    let asked = refusing(&pair.zod_net, HELD_NEWER);
    let (relayed, introduced) = relay_and_introduce(&pair, eight_seconds);
    assert_eq!(relayed, Err(format!("its point refused to relay: {HELD_NEWER}")));
    assert_eq!(introduced, Err(format!("the lookup point did not introduce ~zod to ~nec: {HELD_NEWER}")));
    assert_eq!(asked.load(Ordering::SeqCst), 4, "two requests for each call, not three");
}

#[test]
fn any_other_refusal_is_answered_after_one_request_in_the_same_words_as_before() {
    let pair = quiet_pair("other");
    let near = format!("{HELD_NEWER} (and more)");
    let others = [NO_RELAY, "too many sessions made for that ship just now; try again later", "the record is not signed by the ship's key", near.as_str()];
    for words in others {
        let asked = refusing(&pair.zod_net, words);
        let (relayed, introduced) = relay_and_introduce(&pair, eight_seconds);
        let relay_words = if words == NO_RELAY { "its point does not relay".to_string() } else { format!("its point refused to relay: {words}") };
        assert_eq!(relayed, Err(relay_words));
        assert_eq!(introduced, Err(format!("the lookup point did not introduce ~zod to ~nec: {words}")));
        assert_eq!(asked.load(Ordering::SeqCst), 2, "one request for each call: {words}");
    }
}

#[test]
fn a_request_overtaken_is_made_again_only_within_its_deadline() {
    let pair = quiet_pair("deadline");
    // A first call opens the connection to the point, so that the next is made at once.
    let asked = refusing(&pair.zod_net, NO_RELAY);
    let _ = relay_and_introduce(&pair, eight_seconds);
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    // With the deadline already passed, the one request made is answered at once, and refused as
    // overtaken: the first refusal is the answer, and nothing more is sent. (This relies on the
    // connection the first call opened being still open, so that the request is made at once.)
    let asked = refusing(&pair.zod_net, HELD_NEWER);
    let (relayed, introduced) = relay_and_introduce(&pair, tokio::time::Instant::now);
    assert_eq!(relayed, Err(format!("its point refused to relay: {HELD_NEWER}")));
    assert_eq!(introduced, Err(format!("the lookup point did not introduce ~zod to ~nec: {HELD_NEWER}")));
    assert_eq!(asked.load(Ordering::SeqCst), 2, "one request for each call");
    // With time left, the first request refused as overtaken and the second never answered: both
    // rounds of asking are given exactly the caller's deadline, nothing later.
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = asked.clone();
    let stand_in: StandIn = Arc::new(move |request| {
        let first = signed_request(&request).is_some() && counted.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move {
            match first {
                true => Some(WhereReply { body: None, refused: HELD_NEWER.to_string() }),
                false => std::future::pending().await,
            }
        })
    });
    let finder = pair.zod_net.shared.finder.clone().unwrap();
    *lock(&finder.stand_in) = Some(stand_in);
    lock(&finder.rounds).clear();
    // A generous deadline, so that the test does not turn on reaching the second round within a
    // couple of seconds; normally the second request, never answered, is given up after about
    // three seconds (the most one try at an address is given).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    // Only a watchdog: what is judged is the deadlines the rounds were given, not the clock.
    let relayed = pair.zod_net.threads.get().block_on(async { tokio::time::timeout(Duration::from_secs(30), finder.relay(&pair.zod, "zod", "nec", deadline)).await });
    let relayed = relayed.expect("the call did not end at all");
    assert!(relayed.as_ref().is_err_and(|why| why.ends_with("did not answer in time")), "{relayed:?}");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    assert_eq!(*lock(&finder.rounds), vec![deadline, deadline], "each round of asking given exactly the caller's deadline");
}
