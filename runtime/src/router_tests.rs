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

use crate::azimuth::{Keys, Listing};
use crate::lookup::{Lookup, PointBounds, PointConfig};
use crate::net::{Directory, MakeSocket, NetConfig, Network};
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
        }
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
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysReady)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (index, port) = self.port_for(transmit.destination)?;
        self.sent.lock().unwrap().insert((index, transmit.destination), Instant::now());
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

/// Build the kernel and test agents once per test run, and return one of them by name.
fn wasm(name: &str) -> Vec<u8> {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .current_dir(workspace())
            .args(["build", "-p", "kernel", "-p", "counter", "-p", "tally", "--release"])
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

/// A stand-in for Urbit ID: the keys the test has listed, each at revision one.
#[derive(Default)]
struct Listings(Mutex<HashMap<u32, [u8; 32]>>);

impl Listings {
    fn list(&self, ship: &str, key: [u8; 32]) {
        self.0.lock().unwrap().insert(urbit_id::ob::ship_number(ship).unwrap(), key);
    }
}

impl Keys for Listings {
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
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
    let rt = Arc::new(Runtime::open(&dir.0, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
    let lookup = Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies: None, bounds: PointBounds::default() }), ..Lookup::default() };
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
    let open_counter = Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true }], uses: vec![] };
    let to = |agent: &str| Use { ship: "*".into(), agent: agent.into(), interface: agent.into(), read: false, send: true };
    let far_tally = Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true }], uses: vec![to("counter"), to("tally")] };
    let rt = Arc::new(Runtime::open(&dir.0, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let (counter, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship(ship, &kernel).unwrap();
    rt.install(ship, "counter", &counter, &open_counter).unwrap();
    rt.install(ship, "tally", &tally, &far_tally).unwrap();
    urbit.list(ship, rt.public_key(ship).unwrap());
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
fn two_ships_behind_strict_routers_fail_in_time_and_say_they_could_not_reach_directly() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("strict-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&dirs[0], &urbit);
    let (_zod_router, zod_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_zod, zod_net) = crew(&dirs[1], "~zod", &urbit, point.addr(), Some(zod_socket));
    let (_nec_router, nec_socket) = behind(Kind::Strict, Duration::from_secs(30));
    let (_nec, _nec_net) = crew(&dirs[2], "~nec", &urbit, point.addr(), Some(nec_socket));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    // The introduction is passed on and ~nec sends its packets, but each router gives each
    // destination a port of its own, so neither the packets nor the call find the way open.
    let started = Instant::now();
    let why = zod_net.ping("~zod", "~nec").unwrap_err().to_string();
    assert!(started.elapsed() < Duration::from_secs(9), "{:?}", started.elapsed());
    assert!(why.contains("could not be reached directly"), "{why}");
    assert!(point.point_status().unwrap().introduced >= 1);
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
    let introduction = ship_proto::Message::encode_to_vec(&ship_proto::Introduction { callee: 1, record });
    net.threads.get().block_on(net.shared.introduced(&introduction))
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
