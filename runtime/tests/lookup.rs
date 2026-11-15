//! Ships finding each other by name alone, through lookup points: real runtimes on this
//! machine, keys from a stand-in for Urbit ID, and no address set by hand unless a test is
//! about that.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use runtime::azimuth::{Keys, Listing};
use runtime::lookup::{Lookup, PointBounds, PointConfig, Resolve};
use runtime::net::{Directory, NetConfig, NetError, Network};
use runtime::urbit_id::{ob, NetworkKeys};
use runtime::whereabouts;
use runtime::{Config, Durability, Manifest, Provide, Runtime, Use};
use ship_proto::Message;

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

fn kernel(rt: &Runtime) -> String {
    rt.add_module(&wasm("kernel")).unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-where-{label}", std::process::id()));
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

fn fast() -> Config {
    Config { durability: Durability::Normal, ..Config::default() }
}

/// A stand-in for Urbit ID: the keys the test has listed, each at revision one. The flag,
/// while set, makes every question wait; the count is of questions asked.
#[derive(Default)]
struct Listings(Mutex<HashMap<u32, [u8; 32]>>, AtomicBool, AtomicUsize);

impl Listings {
    fn list(&self, ship: &str, key: [u8; 32]) {
        self.0.lock().unwrap().insert(ob::ship_number(ship).unwrap(), key);
    }
}

impl Keys for Listings {
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
        // While held, every question waits (for half a minute at most), as a slow source of
        // keys would. Each question is counted as it is asked.
        self.2.fetch_add(1, Ordering::SeqCst);
        let started = Instant::now();
        while self.1.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(self.0.lock().unwrap().get(&ship).map(|key| Listing { key: Some(*key), revision: 1, continuity: 0, sponsor: None }))
    }
}

/// A network that gives up quickly and tries again soon.
fn eager() -> NetConfig {
    NetConfig { request_timeout: Duration::from_millis(1500), retry_delay: Duration::from_millis(50), max_retry_delay: Duration::from_millis(300), ..NetConfig::default() }
}

/// Lookup settings for a ship that finds others through the point at `point`, for every
/// galaxy, announces itself every second, and asks again soon.
fn finding(point: SocketAddr) -> Lookup {
    Lookup { at: vec![(None, point)], announce_every: Duration::from_secs(1), ask_again: Duration::from_millis(150), ..Lookup::default() }
}

fn with(lookup: Lookup) -> NetConfig {
    NetConfig { lookup, ..eager() }
}

/// A runtime that holds no ships and is a lookup point for the galaxies given (all, if
/// none), checking records against `urbit`.
fn point_on(dir: &TempDir, urbit: &Arc<Listings>, galaxies: Option<Vec<u8>>, bounds: PointBounds, addr: &str) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let lookup = Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies, bounds }), ..Lookup::default() };
    let net = Network::start(rt.clone(), Directory::new(), NetConfig { addr: addr.into(), lookup, ..eager() }).unwrap();
    (rt, net)
}

/// A runtime with one ship, listed in `urbit` with its own key, on a network with these
/// settings, whose directory reads keys from `urbit` and has no address set for anyone.
fn ship_on(dir: &TempDir, ship: &str, urbit: &Arc<Listings>, cfg: NetConfig) -> (Arc<Runtime>, Network, Arc<Directory>) {
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    rt.create_ship(ship, &kernel(&rt)).unwrap();
    urbit.list(ship, rt.public_key(ship).unwrap());
    let directory = Directory::reading(urbit.clone());
    let net = Network::start(rt.clone(), directory.clone(), cfg).unwrap();
    (rt, net, directory)
}

/// The same, for a ship whose key the test holds: made from a keyfile with this seed.
fn keyed_ship_on(dir: &TempDir, ship: &str, seed: [u8; 32], urbit: &Arc<Listings>, cfg: NetConfig) -> (Arc<Runtime>, Network, Arc<Directory>) {
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let keyfile = Runtime::keyfile(ship, 1, &NetworkKeys { auth: seed, crypt: [0; 32] }).unwrap();
    rt.create_ship_from_keyfile(&kernel(&rt), &keyfile).unwrap();
    assert_eq!(rt.public_key(ship).unwrap(), SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    urbit.list(ship, rt.public_key(ship).unwrap());
    let directory = Directory::reading(urbit.clone());
    let net = Network::start(rt.clone(), directory.clone(), cfg).unwrap();
    (rt, net, directory)
}

/// The same, with the counter and tally agents installed, open to other ships, and the tally
/// allowed to send to both on any ship.
fn crew(dir: &TempDir, ship: &str, urbit: &Arc<Listings>, cfg: NetConfig) -> (Arc<Runtime>, Network, Arc<Directory>) {
    let open_counter = Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true }], uses: vec![] };
    let to = |agent: &str| Use { ship: "*".into(), agent: agent.into(), interface: agent.into(), read: false, send: true };
    let far_tally = Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true }], uses: vec![to("counter"), to("tally")] };
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let (counter, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship(ship, &kernel(&rt)).unwrap();
    rt.install(ship, "counter", &counter, &open_counter).unwrap();
    rt.install(ship, "tally", &tally, &far_tally).unwrap();
    urbit.list(ship, rt.public_key(ship).unwrap());
    let directory = Directory::reading(urbit.clone());
    let net = Network::start(rt.clone(), directory.clone(), cfg).unwrap();
    (rt, net, directory)
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
    net.ping(from, to).is_ok_and(|answered| answered.ship == to.trim_start_matches('~') && answered.seen_as == from.trim_start_matches('~'))
}

/// An address at which a UDP socket is held open and nothing ever answers. Packets sent
/// there go unread, as they do to a machine that has gone, so a connection to it fails
/// only by running out of time.
fn silent() -> (std::net::UdpSocket, SocketAddr) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

/// A free UDP port on this machine, let go of so that something can start there later.
fn free_port() -> SocketAddr {
    silent().1
}

#[test]
fn two_ships_find_each_other_through_a_lookup_point_and_trade_commands() {
    let (p, a, b) = (TempDir::new("find-p"), TempDir::new("find-a"), TempDir::new("find-b"));
    let urbit = Arc::new(Listings::default());
    let (_point_rt, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (zod, zod_net, zod_dir) = crew(&a, "~zod", &urbit, with(finding(point.addr())));
    let (nec, nec_net, nec_dir) = crew(&b, "~nec", &urbit, with(finding(point.addr())));
    eventually("both ships are announced", || point.point_status().unwrap().records == 2);

    // Neither runtime was told where the other is. Each finds the other by name, and each
    // end proved the other's key as on any connection.
    assert!(zod_dir.lookup("~nec").is_none() && nec_dir.lookup("~zod").is_none());
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(reaches(&nec_net, "~nec", "~zod"));

    // An agent on ~zod sends commands to one on ~nec, and they arrive, once each, in order.
    for _ in 0..5 {
        assert_eq!(String::from_utf8(zod.deliver("~zod", "tally", b"tell nec log hits").unwrap().reply).unwrap(), "sent");
    }
    eventually("the commands reach ~nec", || nec.log_head("~nec", "counter", "counter").unwrap().is_some_and(|(seq, _)| seq == 5));
    eventually("~zod lets go of what was delivered", || zod.outbound_pending("~zod").unwrap() == 0);
    // The point holds the two records and was asked about each ship once: after that the
    // connections and what was learned are kept.
    let status = point.point_status().unwrap();
    assert_eq!((status.records, status.questions), (2, 2), "{status:?}");
    assert!(zod_net.lookup_trouble().is_none(), "{:?}", zod_net.lookup_trouble());
}

#[test]
fn ships_of_two_galaxies_are_found_through_their_own_points() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("two-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_zp, zod_point) = point_on(&dirs[0], &urbit, Some(vec![0]), PointBounds::default(), "127.0.0.1:0");
    let (_np, nec_point) = point_on(&dirs[1], &urbit, Some(vec![1]), PointBounds::default(), "127.0.0.1:0");
    let lookup = Lookup { at: vec![(Some(0), zod_point.addr()), (Some(1), nec_point.addr())], ..finding(free_port()) };
    // A star of ~zod's, and a planet of a star of ~nec's.
    let (star, planet) = ("~marzod", ob::ship_name(0x1234_0101));
    let (_s, star_net, _) = ship_on(&dirs[2], star, &urbit, with(lookup.clone()));
    let (_p, planet_net, _) = ship_on(&dirs[3], &planet, &urbit, with(lookup));
    eventually("each point holds its own galaxy's ship", || zod_point.point_status().unwrap().records == 1 && nec_point.point_status().unwrap().records == 1);
    assert!(reaches(&star_net, star, &planet));
    assert!(reaches(&planet_net, &planet, star));
    // Each point was asked about its own galaxy's ship and no other.
    assert_eq!(zod_point.point_status().unwrap().questions, 1);
    assert_eq!(nec_point.point_status().unwrap().questions, 1);
}

#[test]
fn a_moon_is_found_on_its_parents_word() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("moon-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&dirs[0], &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (planet_name, moon_name) = ("~sampel-palnet", "~doznec-sampel-palnet");
    // The planet is in Urbit ID and holds no network of its own here; it only makes the moon.
    let planet = Runtime::open(&dirs[1].0, fast()).unwrap();
    planet.create_ship(planet_name, &kernel(&planet)).unwrap();
    urbit.list(planet_name, planet.public_key(planet_name).unwrap());
    let moon = Arc::new(Runtime::open(&dirs[2].0, fast()).unwrap());
    moon.create_ship_from_keyfile(&kernel(&moon), &planet.moon_keyfile(planet_name, moon_name, 1).unwrap()).unwrap();
    let moon_net = Network::start(moon.clone(), Directory::reading(urbit.clone()), with(finding(point.addr()))).unwrap();
    eventually("the moon is announced", || point.point_status().unwrap().moons == 1);
    // A ship that has never heard of the moon finds it by name, and learns its key from
    // the moon on its parent's word.
    let (_nec, nec_net, nec_dir) = ship_on(&dirs[3], "~nec", &urbit, with(finding(point.addr())));
    assert_eq!(nec_dir.key_of(moon_name), None);
    assert!(reaches(&nec_net, "~nec", moon_name));
    assert_eq!(nec_dir.key_of(moon_name), Some(moon.public_key(moon_name).unwrap()));
    assert!(reaches(&moon_net, moon_name, "~nec"));
}

#[test]
fn a_ship_that_comes_back_somewhere_else_is_found_there() {
    let (p, a, b) = (TempDir::new("moved-p"), TempDir::new("moved-a"), TempDir::new("moved-b"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(finding(point.addr())));
    let (nec, nec_net, _) = ship_on(&b, "~nec", &urbit, with(finding(point.addr())));
    eventually("~zod reaches ~nec", || reaches(&zod_net, "~zod", "~nec"));
    let first = nec_net.addr();
    drop(nec_net);
    // The runtime starts again on another port, and says so to the point at once. ~zod
    // finds the address it had dead, asks again, and reaches it at the new one.
    let nec_net = Network::start(nec.clone(), Directory::reading(urbit.clone()), with(finding(point.addr()))).unwrap();
    assert_ne!(nec_net.addr(), first);
    eventually("~zod reaches ~nec where it is now", || reaches(&zod_net, "~zod", "~nec"));
    assert!(reaches(&nec_net, "~nec", "~zod"));
}

#[test]
fn a_point_that_starts_late_or_goes_away_is_used_again_once_it_is_there() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("late-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let at = free_port();
    let (_zod, zod_net, _) = ship_on(&dirs[1], "~zod", &urbit, with(finding(at)));
    let (_nec, nec_net, _) = ship_on(&dirs[2], "~nec", &urbit, with(finding(at)));
    // No point yet. A call fails, within its time, and says why.
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert!(started.elapsed() < Duration::from_secs(4), "giving up took {:?}", started.elapsed());
    // The point starts. Both ships are announced to it without being restarted, and find
    // each other.
    let (point_rt, point) = point_on(&dirs[0], &urbit, None, PointBounds::default(), &at.to_string());
    eventually("both ships are announced to the late point", || point.point_status().unwrap().records == 2);
    eventually("~zod reaches ~nec", || reaches(&zod_net, "~zod", "~nec"));
    eventually("~nec reaches ~zod", || reaches(&nec_net, "~nec", "~zod"));
    // The point goes away. Ships that already know each other carry on.
    drop(point);
    drop(point_rt);
    for _ in 0..3 {
        assert!(reaches(&zod_net, "~zod", "~nec"));
        assert!(reaches(&nec_net, "~nec", "~zod"));
    }
    // It comes back, empty, at the same address. The ships announce themselves to it again,
    // and a ship that never met them finds them.
    let point_dir = TempDir::new("late-again");
    let (_point_rt, point) = point_on(&point_dir, &urbit, None, PointBounds::default(), &at.to_string());
    eventually("both ships are announced again", || point.point_status().unwrap().records >= 2);
    let (_bud, bud_net, _) = ship_on(&dirs[3], "~bud", &urbit, with(finding(at)));
    eventually("~bud reaches ~zod", || reaches(&bud_net, "~bud", "~zod"));
    assert!(reaches(&bud_net, "~bud", "~nec"));
}

#[test]
fn many_ships_on_one_runtime_are_announced_over_one_connection() {
    let (p, a) = (TempDir::new("many-p"), TempDir::new("many-a"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    let ships = ["~zod", "~nec", "~bud", "~marzod", "~sampel-palnet"];
    for ship in ships {
        rt.create_ship(ship, &kernel(&rt)).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    let net = Network::start(rt.clone(), Directory::reading(urbit.clone()), with(finding(point.addr()))).unwrap();
    eventually("every ship is announced", || point.point_status().unwrap().records == ships.len());
    assert_eq!(point.point_status().unwrap().connections, 1);
    // A ship made after the network started is announced too, at once, over the same
    // connection.
    rt.create_ship("~wes", &kernel(&rt)).unwrap();
    urbit.list("~wes", rt.public_key("~wes").unwrap());
    eventually("the new ship is announced", || point.point_status().unwrap().records == ships.len() + 1);
    assert_eq!(point.point_status().unwrap().connections, 1);
    drop(net);
}

#[test]
fn an_address_set_by_hand_wins_and_nothing_else_is_tried() {
    let (p, a, b) = (TempDir::new("hand-p"), TempDir::new("hand-a"), TempDir::new("hand-b"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, with(finding(point.addr())));
    let (_nec, nec_net, _) = ship_on(&b, "~nec", &urbit, with(finding(point.addr())));
    eventually("~zod finds ~nec", || reaches(&zod_net, "~zod", "~nec"));
    let asked = point.point_status().unwrap().questions;
    // An address set by hand where nothing answers. The connection found through the point
    // is not used again, and the point is not asked: the call fails.
    let (_quiet, nowhere) = silent();
    zod_dir.place("~nec", nowhere).unwrap();
    for _ in 0..2 {
        assert!(zod_net.ping("~zod", "~nec").is_err());
    }
    assert_eq!(point.point_status().unwrap().questions, asked);
    // Set by hand where it is, and it is reached there.
    zod_dir.place("~nec", nec_net.addr()).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    // The same for a ship set whole, key and address.
    let bud_dir = TempDir::new("hand-c");
    let (bud, bud_net, _) = ship_on(&bud_dir, "~bud", &urbit, with(finding(point.addr())));
    eventually("~bud is announced", || point.point_status().unwrap().records == 3);
    zod_dir.set("~bud", bud.public_key("~bud").unwrap(), nowhere).unwrap();
    assert!(zod_net.ping("~zod", "~bud").is_err());
    zod_dir.set("~bud", bud.public_key("~bud").unwrap(), bud_net.addr()).unwrap();
    assert!(reaches(&zod_net, "~zod", "~bud"));
    assert_eq!(point.point_status().unwrap().questions, asked);
}

#[test]
fn a_ship_is_asked_about_at_most_once_in_a_while() {
    let (p, a) = (TempDir::new("often-p"), TempDir::new("often-a"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    // ~nec is in Urbit ID but has never been announced.
    urbit.list("~nec", SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes());
    let lookup = Lookup { ask_again: Duration::from_secs(2), ..finding(point.addr()) };
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(lookup));
    // Called over and over, it is asked about once, and each call fails at once after.
    let started = Instant::now();
    for _ in 0..10 {
        assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_))));
    }
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(point.point_status().unwrap().questions, 1);
    // After a while it may be asked about again.
    std::thread::sleep(Duration::from_millis(2100));
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert_eq!(point.point_status().unwrap().questions, 2);
    // A ship Urbit ID has no key for is not asked about at all: there would be nothing to
    // check its record against.
    assert!(matches!(zod_net.ping("~zod", "~bud"), Err(NetError::Unlisted(_))));
    assert_eq!(point.point_status().unwrap().questions, 2);
}

// A lookup point that lies.

/// What a lying point answers to a question about a ship.
#[derive(Clone)]
enum Lie {
    /// This record, whatever it is.
    Record(Vec<u8>),
    /// These bytes, which are not an answer.
    Rubbish(Vec<u8>),
    /// An answer that is never finished.
    Endless,
    /// An answer larger than any answer may be.
    Huge,
    /// This record (or with none, "not known"), after this long.
    Late(Duration, Vec<u8>),
}

/// What a lying point answers when asked where it sees a connection come from.
#[derive(Clone)]
enum SeenLie {
    /// The address it does see.
    Truth,
    /// These bytes, as the address.
    Address(Vec<u8>),
    /// It will not say.
    Refuse,
    /// It never answers.
    Silent,
}

/// A stand-in for a lookup point that speaks the protocol and answers questions as the test
/// says. Announcements it takes, keeps the records of, and does not check; it can pass anything
/// at all, as an introduction, over the connection of whoever announced last.
struct Liar {
    addr: SocketAddr,
    lie: Arc<Mutex<Lie>>,
    asked: Arc<AtomicUsize>,
    seen: Arc<Mutex<SeenLie>>,
    /// Questions about where a connection is seen from, the records announced to it, and the
    /// introductions asked of it.
    seens: Arc<AtomicUsize>,
    announced: Arc<Mutex<Vec<Vec<u8>>>>,
    introductions: Arc<AtomicUsize>,
    /// How long it takes to answer a request for an introduction.
    introduce_after: Arc<Mutex<Duration>>,
    announcers: Arc<Mutex<Vec<quinn::Connection>>>,
    /// Ships, by number, whose records it refuses in every announcement.
    refuse: Arc<Mutex<Vec<u64>>>,
    /// While set, every question about a ship waits.
    hold: Arc<AtomicBool>,
    /// While set, an announcement of fewer than sixteen records (the last chunk of a round) is
    /// answered with rubbish.
    garble_short: Arc<AtomicBool>,
    /// Introductions it has begun to pass on.
    pushes: AtomicUsize,
    tokio: tokio::runtime::Runtime,
}

/// A raw public key, with the means to sign with it, as either end of a connection shows one.
fn shown(seed: [u8; 32], provider: &rustls::crypto::CryptoProvider) -> Arc<rustls::sign::CertifiedKey> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let key = SigningKey::from_bytes(&seed);
    let mut der = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&key.to_bytes());
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(&key.verifying_key().to_bytes());
    let signer = provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(der).into()).unwrap();
    let public = [&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00][..], &key.verifying_key().to_bytes()].concat();
    Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(public)], signer))
}

mod anykey {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

    /// Either end: any raw key will do, so long as the other end signs with it.
    #[derive(Debug)]
    pub struct AnyKey(pub rustls::crypto::WebPkiSupportedAlgorithms);

    impl ServerCertVerifier for AnyKey {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("only TLS 1.3".into()))
        }
        fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    impl ClientCertVerifier for AnyKey {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
        fn verify_client_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("only TLS 1.3".into()))
        }
        fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
}

fn liar() -> Liar {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(anykey::AnyKey(provider.signature_verification_algorithms)))
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(shown([8; 32], &provider))));
    tls.alpn_protocols = vec![b"ship-where/1".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let endpoint = {
        let _entered = tokio.enter();
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    };
    let addr = endpoint.local_addr().unwrap();
    let lie = Arc::new(Mutex::new(Lie::Rubbish(vec![])));
    let asked = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(SeenLie::Truth));
    let (seens, announced, introductions) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
    let introduce_after = Arc::new(Mutex::new(Duration::ZERO));
    let announcers = Arc::new(Mutex::new(Vec::new()));
    let (refuse, hold, garble_short) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let (lying, counting) = (lie.clone(), asked.clone());
    let doubles = (seen.clone(), seens.clone(), announced.clone(), introductions.clone(), introduce_after.clone(), announcers.clone(), refuse.clone(), hold.clone(), garble_short.clone());
    tokio.spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (lying, counting, doubles) = (lying.clone(), counting.clone(), doubles.clone());
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                let from = connection.remote_address();
                while let Ok((mut send, mut receive)) = connection.accept_bi().await {
                    let (lying, counting, doubles, connection) = (lying.clone(), counting.clone(), doubles.clone(), connection.clone());
                    tokio::spawn(async move {
                        let (seen, seens, announced, introductions, introduce_after, announcers, refuse, hold, garble_short) = doubles;
                        let Ok(bytes) = receive.read_to_end(1 << 16).await else { return };
                        let Ok(request) = ship_proto::WhereRequest::decode(&*bytes) else { return };
                        let answer = match request.body {
                            // Where a caller is seen from: as the test says. It does not count
                            // among the questions.
                            Some(ship_proto::where_request::Body::Seen(_)) => {
                                seens.fetch_add(1, Ordering::SeqCst);
                                let saw = |address: Vec<u8>| ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Saw(ship_proto::Saw { address })), refused: String::new() }.encode_to_vec();
                                let said = seen.lock().unwrap().clone();
                                match said {
                                    SeenLie::Truth => saw(address_bytes(from)),
                                    SeenLie::Address(bytes) => saw(bytes),
                                    SeenLie::Refuse => ship_proto::WhereReply { body: None, refused: "not telling".into() }.encode_to_vec(),
                                    SeenLie::Silent => {
                                        tokio::time::sleep(Duration::from_secs(60)).await;
                                        return;
                                    }
                                }
                            }
                            Some(ship_proto::where_request::Body::Introduce(_)) => {
                                introductions.fetch_add(1, Ordering::SeqCst);
                                let after = *introduce_after.lock().unwrap();
                                tokio::time::sleep(after).await;
                                ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Introduced(ship_proto::Introduced {})), refused: String::new() }.encode_to_vec()
                            }
                            Some(ship_proto::where_request::Body::Announce(announce)) if garble_short.load(Ordering::SeqCst) && announce.records.len() < 16 => vec![0xff; 10],
                            Some(ship_proto::where_request::Body::Announce(announce)) => {
                                let refused = refuse.lock().unwrap().clone();
                                let taken = |record: &Vec<u8>| !refused.contains(&ship_proto::Whereabouts::decode(&**record).map_or(0, |record| record.ship));
                                announced.lock().unwrap().extend(announce.records.iter().filter(|record| taken(record)).cloned());
                                announcers.lock().unwrap().push(connection.clone());
                                let outcomes = announce.records.iter().map(|record| if taken(record) { String::new() } else { "refused by the test".to_string() }).collect();
                                ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Announced(ship_proto::Announced { outcomes })), refused: String::new() }.encode_to_vec()
                            }
                            _ => {
                                counting.fetch_add(1, Ordering::SeqCst);
                                while hold.load(Ordering::SeqCst) {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                                let lie = lying.lock().unwrap().clone();
                                match lie {
                                    Lie::Record(record) => ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Found(ship_proto::Found { record })), refused: String::new() }.encode_to_vec(),
                                    Lie::Rubbish(bytes) => bytes,
                                    Lie::Late(wait, record) => {
                                        tokio::time::sleep(wait).await;
                                        ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Found(ship_proto::Found { record })), refused: String::new() }.encode_to_vec()
                                    }
                                    Lie::Huge => ship_proto::WhereReply { body: Some(ship_proto::where_reply::Body::Found(ship_proto::Found { record: vec![1; 40 << 10] })), refused: String::new() }.encode_to_vec(),
                                    Lie::Endless => {
                                        loop {
                                            if send.write_all(b"\x12").await.is_err() {
                                                return;
                                            }
                                            tokio::time::sleep(Duration::from_millis(20)).await;
                                        }
                                    }
                                }
                            }
                        };
                        let _ = send.write_all(&answer).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    });
                }
            });
        }
    });
    Liar { addr, lie, asked, seen, seens, announced, introductions, introduce_after, announcers, refuse, hold, garble_short, pushes: AtomicUsize::new(0), tokio }
}

/// An address as it travels in a record: four or sixteen bytes, then the port.
fn address_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

impl Liar {
    fn say(&self, lie: Lie) {
        *self.lie.lock().unwrap() = lie;
    }

    fn see(&self, seen: SeenLie) {
        *self.seen.lock().unwrap() = seen;
    }

    /// The records announced to it so far, as they were sent.
    fn records(&self) -> Vec<ship_proto::Whereabouts> {
        self.announced.lock().unwrap().iter().map(|record| ship_proto::Whereabouts::decode(&**record).unwrap()).collect()
    }

    /// Whether a stream of its own can be opened, within a moment, over the connection of
    /// whoever announced to it last. One that opens is held open, unfinished, for `held`, and
    /// then given up.
    fn opens(&self, held: Duration) -> bool {
        let connection = self.announcers.lock().unwrap().last().cloned().expect("nobody has announced");
        self.tokio.block_on(async {
            match tokio::time::timeout(Duration::from_millis(300), connection.open_uni()).await {
                Ok(Ok(mut stream)) => {
                    let _ = stream.write_all(&[0x08]).await;
                    tokio::spawn(async move {
                        tokio::time::sleep(held).await;
                        let _ = stream.reset(0u32.into());
                    });
                    true
                }
                _ => false,
            }
        })
    }

    /// Pass these bytes, on a stream of their own, over the connection of whoever announced
    /// to it last: finished, or (if `endless`) never finished, a byte now and then.
    fn push(&self, bytes: Vec<u8>, endless: bool) {
        self.pushes.fetch_add(1, Ordering::SeqCst);
        let connection = self.announcers.lock().unwrap().last().cloned().expect("nobody has announced");
        // Within a time limit, so that a ship that takes nothing fails the test, not hangs it.
        let pushed = self.tokio.block_on(async move { tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = connection.open_uni().await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            if endless {
                tokio::spawn(async move {
                    while stream.write_all(&[0]).await.is_ok() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
            } else {
                stream.finish().unwrap();
            }
        }).await });
        assert!(pushed.is_ok(), "the ship took no introduction in five seconds");
    }
}

const NOW_SLACK: Duration = Duration::from_secs(4);

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn a_point_that_lies_is_not_believed_and_does_not_hold_a_call_past_its_time() {
    let (a, b) = (TempDir::new("liar-a"), TempDir::new("liar-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [21u8; 32];
    let nec_key = SigningKey::from_bytes(&seed);
    // ~nec is real, at a real address, and announces itself to nobody: everything ~zod
    // hears of it comes from the liar.
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let lookup = Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) };
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(lookup));
    let bus = SigningKey::from_bytes(&[22; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let here = [nec_net.addr()];
    let record = |ship: &str, key: &SigningKey, issued: u64, at: &[SocketAddr]| whereabouts::sign(ship, at, issued, key, None).unwrap();
    // Each lie, in turn. None is believed, and no call waits past its time.
    let tried = |what: &str| {
        std::thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        let failed = zod_net.ping("~zod", "~nec");
        assert!(failed.is_err(), "believed {what}");
        assert!(started.elapsed() < NOW_SLACK, "{what}: giving up took {:?}", started.elapsed());
        failed.err().map(|e| e.to_string()).unwrap_or_default()
    };
    let now = now_ms();
    liar.say(Lie::Record(record("~bus", &bus, now, &here)));
    // The call says why: not that the point knew nowhere, but what was wrong with what it said.
    let why = tried("another ship's record");
    assert!(why.contains("another ship's record"), "{why}");
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("another ship's record")), "{:?}", zod_net.lookup_trouble());
    liar.say(Lie::Record(record("~nec", &bus, now, &here)));
    tried("a record signed with another key");
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("not believed")), "{:?}", zod_net.lookup_trouble());
    let mut altered = ship_proto::Whereabouts::decode(&*record("~nec", &nec_key, now, &here)).unwrap();
    altered.issued += 1;
    liar.say(Lie::Record(altered.encode_to_vec()));
    tried("a record changed after it was signed");
    liar.say(Lie::Record(record("~nec", &nec_key, now - whereabouts::LIFETIME_MS - 1000, &here)));
    tried("a record that has run out");
    liar.say(Lie::Record(record("~nec", &nec_key, now + whereabouts::MOST_AHEAD_MS + 60_000, &here)));
    tried("a record dated ahead");
    liar.say(Lie::Rubbish(vec![0xff; 300]));
    tried("rubbish");
    liar.say(Lie::Endless);
    tried("an answer that never ends");
    liar.say(Lie::Huge);
    tried("an answer too large");
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("too large")), "{:?}", zod_net.lookup_trouble());

    // A newer record that names an address where nothing answers is believed, and the call
    // fails there. Then the older record, which names the right address, is refused: the
    // newer is still good.
    let (_quiet, nowhere) = silent();
    liar.say(Lie::Record(record("~nec", &nec_key, now, &[nowhere])));
    tried("a record of an address where nothing answers");
    // And the address that failed is not tried again: the call fails at once.
    liar.say(Lie::Record(record("~nec", &nec_key, now - 5000, &here)));
    std::thread::sleep(Duration::from_millis(150));
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err(), "believed an older record after a newer one");
    assert!(started.elapsed() < Duration::from_millis(600), "the address that failed was tried again: {:?}", started.elapsed());
    // A record newer than both, at the right address, is believed. The liar can only
    // hand out what ~nec signed.
    liar.say(Lie::Record(record("~nec", &nec_key, now + 1, &here)));
    std::thread::sleep(Duration::from_millis(150));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(liar.asked.load(Ordering::SeqCst) >= 11);
}

#[test]
fn a_record_that_has_run_out_is_not_used_even_where_it_would_still_do() {
    let (a, b) = (TempDir::new("runout-a"), TempDir::new("runout-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [71u8; 32];
    let (nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let at = nec_net.addr();
    let here = NetConfig { addr: at.to_string(), ..eager() };
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) }));
    // A record with eight seconds left to run: room for the first call, even on a busy
    // machine.
    let key = SigningKey::from_bytes(&seed);
    let issued = now_ms() - whereabouts::LIFETIME_MS + 8000;
    liar.say(Lie::Record(whereabouts::sign("~nec", &[at], issued, &key, None).unwrap()));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    // ~nec starts again at the same address: the connection is lost, though the address
    // would still do. The point has nothing more to say, and the record runs out.
    liar.say(Lie::Rubbish(vec![0xff; 10]));
    drop(nec_net);
    let nec_net = Network::start(nec.clone(), Directory::reading(urbit.clone()), here).unwrap();
    let waiting = Instant::now();
    while now_ms() < issued + whereabouts::LIFETIME_MS + 200 {
        assert!(waiting.elapsed() < Duration::from_secs(30), "the wall clock went back while waiting");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(zod_net.ping("~zod", "~nec").is_err(), "a record that had run out was used");
    // A record still good, and ~nec is reached there.
    liar.say(Lie::Record(whereabouts::sign("~nec", &[at], now_ms(), &key, None).unwrap()));
    std::thread::sleep(Duration::from_millis(150));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    drop(nec_net);
}

#[test]
fn a_record_cannot_make_a_ship_talk_to_anyone_but_the_ship_it_named() {
    let (a, b, c) = (TempDir::new("imp-a"), TempDir::new("imp-b"), TempDir::new("imp-c"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [31u8; 32];
    let (_nec, _nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let (zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) }));
    // An impostor runtime holds a ship it calls ~nec, under a key of its own. It knows ~zod's
    // real key and address, so it would take ~zod's call: whatever stops the call, it is not
    // the impostor.
    let impostor = Arc::new(Runtime::open(&c.0, fast()).unwrap());
    impostor.create_ship("~nec", &kernel(&impostor)).unwrap();
    let impostor_dir = Directory::new();
    let impostor_net = Network::start(impostor.clone(), impostor_dir.clone(), eager()).unwrap();
    impostor_dir.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    // To show it: a ship that takes the impostor's key for ~nec's, as nobody should, is
    // answered by it.
    let d = TempDir::new("imp-d");
    let fooled = Arc::new(Runtime::open(&d.0, fast()).unwrap());
    fooled.create_ship("~bus", &kernel(&fooled)).unwrap();
    let fooled_dir = Directory::new();
    let fooled_net = Network::start(fooled.clone(), fooled_dir.clone(), eager()).unwrap();
    fooled_dir.set("~nec", impostor.public_key("~nec").unwrap(), impostor_net.addr()).unwrap();
    impostor_dir.set("~bus", fooled.public_key("~bus").unwrap(), fooled_net.addr()).unwrap();
    assert!(reaches(&fooled_net, "~bus", "~nec"));
    // The liar hands out ~nec's own signed record, but naming the impostor's address: ~nec
    // signed it, so it is believed, and the call goes there. What answers cannot prove
    // ~nec's key, so ~zod does not take it for ~nec.
    let record = whereabouts::sign("~nec", &[impostor_net.addr()], now_ms(), &SigningKey::from_bytes(&seed), None).unwrap();
    liar.say(Lie::Record(record));
    assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_) | NetError::TimedOut)));
    assert!(liar.asked.load(Ordering::SeqCst) >= 1);
}

// Talking to a lookup point directly, as anyone could.

fn where_client() -> quinn::ClientConfig {
    client_offering(&[b"ship-where/1"])
}

/// A caller that shows a key of its own, takes any key, and offers these protocols.
fn client_offering(protocols: &[&[u8]]) -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(anykey::AnyKey(provider.signature_verification_algorithms)))
        .with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(shown([3; 32], &provider))));
    tls.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
    quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()))
}

/// Send a request on a new stream and read the reply, if one comes in time.
async fn ask_point(connection: &quinn::Connection, request: &[u8]) -> Option<ship_proto::WhereReply> {
    let attempt = async {
        let (mut send, mut receive) = connection.open_bi().await.ok()?;
        send.write_all(request).await.ok()?;
        send.finish().ok()?;
        ship_proto::WhereReply::decode(&*receive.read_to_end(1 << 16).await.ok()?).ok()
    };
    tokio::time::timeout(Duration::from_secs(3), attempt).await.ok().flatten()
}

/// An announcement of records whose presence does not matter to the test: each comes with an
/// empty one, so none of them could be kept.
fn announce(records: Vec<Vec<u8>>) -> Vec<u8> {
    let presence = vec![Vec::new(); records.len()];
    ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Announce(ship_proto::Announce { records, presence })) }.encode_to_vec()
}

/// The value both ends of a connection work out from its handshake, as the protocol names it.
fn binding_of(connection: &quinn::Connection) -> [u8; 32] {
    let mut binding = [0u8; 32];
    connection.export_keying_material(&mut binding, b"ship.v1.here", b"").unwrap();
    binding
}

/// A ship's presence on a connection, for a record of its signed with `key`.
fn presence_on(connection: &quinn::Connection, record: &[u8], key: &SigningKey) -> Vec<u8> {
    let read = ship_proto::Whereabouts::decode(record).unwrap();
    whereabouts::presence(read.ship, read.issued, &binding_of(connection), key)
}

/// An announcement over `connection` of records each with its ship's presence on it.
fn announce_on(connection: &quinn::Connection, records: &[(Vec<u8>, SigningKey)]) -> Vec<u8> {
    let presence = records.iter().map(|(record, key)| presence_on(connection, record, key)).collect();
    let records = records.iter().map(|(record, _)| record.clone()).collect();
    ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Announce(ship_proto::Announce { records, presence })) }.encode_to_vec()
}

fn question(ship: &str) -> Vec<u8> {
    let ship = ob::any_number(ship).unwrap();
    ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Ask(ship_proto::Where { ship })) }.encode_to_vec()
}

fn outcomes(reply: Option<ship_proto::WhereReply>) -> Vec<String> {
    match reply.and_then(|reply| reply.body) {
        Some(ship_proto::where_reply::Body::Announced(announced)) => announced.outcomes,
        other => panic!("not an answer to an announcement: {other:?}"),
    }
}

fn found(reply: Option<ship_proto::WhereReply>) -> Option<Vec<u8>> {
    match reply?.body? {
        ship_proto::where_reply::Body::Found(found) => Some(found.record).filter(|record| !record.is_empty()),
        _ => None,
    }
}

#[test]
fn a_point_holds_its_bounds_against_anyone_and_keeps_what_it_has() {
    let p = TempDir::new("bounds-p");
    let urbit = Arc::new(Listings::default());
    let bounds = PointBounds { connections: 2, per_connection: 3, ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    let keys: Vec<SigningKey> = (0..6u8).map(|n| SigningKey::from_bytes(&[40 + n; 32])).collect();
    let ships: Vec<String> = (0..6u32).map(|n| ob::ship_name(0x1234_0100 + (n << 16))).collect();
    for (ship, key) in ships.iter().zip(&keys) {
        urbit.list(ship, key.verifying_key().to_bytes());
    }
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let records: Vec<Vec<u8>> = ships.iter().zip(&keys).map(|(ship, key)| whereabouts::sign(ship, &[at], now_ms(), key, None).unwrap()).collect();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = || async { endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap() };
        let first = connect().await;
        // Three records a second on one connection: the fourth is refused, and says why.
        let keyed: Vec<(Vec<u8>, SigningKey)> = records.iter().cloned().zip(keys.iter().cloned()).collect();
        let said = outcomes(ask_point(&first, &announce_on(&first, &keyed[..4])).await);
        assert_eq!(said[..3], [String::new(), String::new(), String::new()]);
        assert_eq!(said[3], "too many records on this connection just now; try again later");
        assert_eq!(found(ask_point(&first, &question(&ships[0])).await), Some(records[0].clone()));
        // More records than one announcement may carry, and more bytes than a request may
        // be, are refused whole, unread.
        // (With no presences at all, so that only the count of records refuses it.)
        let crowd = announce_with(vec![records[4].clone(); 17], Vec::new());
        let refused = ask_point(&first, &crowd).await.unwrap();
        assert!(refused.body.is_none() && refused.refused.contains("too many records"), "{refused:?}");
        // A question that would be answered, but for twenty kilobytes of a field nobody
        // knows after it.
        let huge = [question(&ships[0]), vec![0xfa, 0x07], vec![0x80, 0xa0, 0x01], vec![0; 20 << 10]].concat();
        assert!(ship_proto::WhereRequest::decode(&*huge).is_ok());
        let huge = ask_point(&first, &huge).await;
        assert!(huge.as_ref().is_none_or(|reply| reply.body.is_none()), "{huge:?}");
        // A forged record and rubbish are refused one by one; the records held stay.
        let second = connect().await;
        let forged = whereabouts::sign(&ships[0], &["198.51.100.1:1".parse().unwrap()], now_ms() + 10, &keys[1], None).unwrap();
        let said = outcomes(ask_point(&second, &announce(vec![forged, vec![1, 2, 3]])).await);
        assert!(said.iter().all(|outcome| !outcome.is_empty()), "{said:?}");
        assert_eq!(found(ask_point(&second, &question(&ships[0])).await), Some(records[0].clone()));
        assert_eq!(point.point_status().unwrap().records, 3);
        // Two connections are as many as this point takes under its protocol. A third is
        // closed unanswered; when one goes, there is room again.
        assert_eq!(point.point_status().unwrap().connections, 2);
        let third = connect().await;
        assert!(ask_point(&third, &question(&ships[0])).await.is_none());
        first.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let fourth = connect().await;
        assert_eq!(found(ask_point(&fourth, &question(&ships[0])).await), Some(records[0].clone()));
        // Questions cost next to nothing, and still only so many are answered in a second on
        // one connection.
        let mut refused = 0;
        for _ in 0..150 {
            let reply = ask_point(&fourth, &question(&ships[0])).await.unwrap();
            refused += usize::from(reply.body.is_none() && reply.refused.contains("too many questions"));
        }
        assert!(refused > 0 && refused < 150, "{refused} of 150 refused");
    });
}

#[test]
fn a_runtime_that_is_no_lookup_point_does_not_answer_as_one() {
    let (a, b) = (TempDir::new("nopoint-a"), TempDir::new("nopoint-b"));
    let urbit = Arc::new(Listings::default());
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, eager());
    // And a runtime that is one still answers ships as ever, on the same port.
    let (_nec, nec_net, nec_dir) = ship_on(&b, "~nec", &urbit, NetConfig { lookup: Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies: None, bounds: PointBounds::default() }), ..Lookup::default() }, ..eager() });
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // Not even when the caller names a ship the runtime holds.
        for named in ["lookup", "zod"] {
            let attempt = tokio::time::timeout(Duration::from_secs(3), endpoint.connect_with(where_client(), zod_net.addr(), named).unwrap()).await;
            assert!(!matches!(attempt, Ok(Ok(_))), "a runtime with no lookup settings agreed to the lookup protocol");
        }
        let point = endpoint.connect_with(where_client(), nec_net.addr(), "lookup").unwrap().await.unwrap();
        assert!(found(ask_point(&point, &question("~zod")).await).is_none());
    });
    nec_dir.place("~zod", zod_net.addr()).unwrap();
    assert!(reaches(&nec_net, "~nec", "~zod"));
}

// Finding points by name.

/// A stand-in for the system's resolver. It answers with whole addresses, ports included,
/// whatever port is asked for, so that a test can name places with nothing there.
#[derive(Default)]
struct Names {
    said: Mutex<HashMap<String, Vec<SocketAddr>>>,
    hang: AtomicBool,
    /// Hang on the next lookup only.
    hang_once: AtomicBool,
    asked: Mutex<Vec<String>>,
}

impl Names {
    fn say(&self, host: &str, addresses: Vec<SocketAddr>) {
        self.said.lock().unwrap().insert(host.to_string(), addresses);
    }

    fn times_asked(&self, host: &str) -> usize {
        self.asked.lock().unwrap().iter().filter(|asked| *asked == host).count()
    }
}

impl Resolve for Names {
    fn resolve(&self, host: &str, _: u16) -> Result<Vec<SocketAddr>, String> {
        self.asked.lock().unwrap().push(host.to_string());
        if self.hang.load(Ordering::SeqCst) || self.hang_once.swap(false, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(60));
        }
        self.said.lock().unwrap().get(host).cloned().ok_or_else(|| format!("{host}: no such name"))
    }
}

fn by_name(names: &Arc<Names>) -> Lookup {
    Lookup { domain: Some(("points.test".into(), 4433)), resolver: Some(names.clone()), announce_every: Duration::from_secs(1), ask_again: Duration::from_millis(150), ..Lookup::default() }
}

#[test]
fn points_are_found_by_name_trying_each_address_in_turn() {
    let (p, a, b) = (TempDir::new("dns-p"), TempDir::new("dns-a"), TempDir::new("dns-b"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let names = Arc::new(Names::default());
    // Each galaxy's name has two addresses, and nothing answers at the first.
    let (_quiet, nowhere) = silent();
    for galaxy in ["zod", "nec"] {
        names.say(&format!("{galaxy}.points.test"), vec![nowhere, point.addr()]);
    }
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(by_name(&names)));
    let (_nec, nec_net, _) = ship_on(&b, "~nec", &urbit, with(by_name(&names)));
    eventually("both ships are announced through the second address", || point.point_status().unwrap().records == 2);
    eventually("~zod reaches ~nec", || reaches(&zod_net, "~zod", "~nec"));
    assert!(reaches(&nec_net, "~nec", "~zod"));
}

#[test]
fn a_name_is_looked_up_again_once_its_answer_is_old() {
    let (p, a, b) = (TempDir::new("reread-p"), TempDir::new("reread-a"), TempDir::new("reread-b"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let names = Arc::new(Names::default());
    names.say("nec.points.test", vec![point.addr()]);
    let (_nec, _nec_net, _) = ship_on(&b, "~nec", &urbit, with(finding(point.addr())));
    eventually("~nec is announced", || point.point_status().unwrap().records == 1);
    // ~zod's own galaxy's point cannot be found by name, so it announces nothing and looks
    // names up only to ask about others. Answers are kept for a second.
    let lookup = Lookup { resolved_for: Duration::from_secs(1), ..by_name(&names) };
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, NetConfig { addr: "0.0.0.0:0".into(), ..with(lookup) });
    eventually("~zod finds it has nowhere to announce", || zod_net.lookup_trouble().is_some_and(|why| why.contains("zod.points.test")));
    // Two more ships of ~nec's galaxy, in Urbit ID and never announced.
    let (one, two) = (ob::ship_name(0x1234_0101), ob::ship_name(0x1235_0101));
    for ship in [&one, &two] {
        urbit.list(ship, SigningKey::from_bytes(&[50; 32]).verifying_key().to_bytes());
    }
    eventually("~zod reaches ~nec", || zod_net.ping("~zod", "~nec").is_ok());
    let looked_up = names.times_asked("nec.points.test");
    assert!(looked_up >= 1);
    // Asked again at once, the answer kept is used.
    assert!(zod_net.ping("~zod", &one).is_err());
    assert_eq!(names.times_asked("nec.points.test"), looked_up);
    // Once it is old, the name is looked up again.
    std::thread::sleep(Duration::from_millis(1100));
    assert!(zod_net.ping("~zod", &two).is_err());
    assert_eq!(names.times_asked("nec.points.test"), looked_up + 1);
}

#[test]
fn a_name_with_no_addresses_or_a_resolver_that_hangs_holds_nothing_up() {
    let (a, b, c) = (TempDir::new("hang-a"), TempDir::new("hang-b"), TempDir::new("hang-c"));
    let urbit = Arc::new(Listings::default());
    let names = Arc::new(Names::default());
    names.say("nec.points.test", vec![]);
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, with(by_name(&names)));
    let (_nec, _nec_net, _) = ship_on(&b, "~nec", &urbit, eager());
    // No addresses: the call fails at once, and says why.
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert!(started.elapsed() < Duration::from_millis(1000), "{:?}", started.elapsed());
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("has no addresses")), "{:?}", zod_net.lookup_trouble());
    // A resolver that never answers: the call gives up in its time.
    names.hang.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert!(started.elapsed() < NOW_SLACK, "{:?}", started.elapsed());
    // Meanwhile a ship whose address is set by hand is called as quickly as ever.
    let (bud, bud_net, _) = ship_on(&c, "~bud", &urbit, eager());
    zod_dir.place("~bud", bud_net.addr()).unwrap();
    let _ = bud;
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~bud"));
    assert!(started.elapsed() < Duration::from_millis(1000), "{:?}", started.elapsed());
    // And stopping is prompt, with lookups still hanging.
    let started = Instant::now();
    drop(zod_net);
    assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
}

#[test]
fn a_resolver_that_hangs_once_is_not_waited_on() {
    let (p, a) = (TempDir::new("hangonce-p"), TempDir::new("hangonce-a"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let names = Arc::new(Names::default());
    names.say("zod.points.test", vec![point.addr()]);
    // The first lookup of the point's name never comes back. Announcing gives up on it in
    // its time, tries again, and gets through.
    names.hang_once.store(true, Ordering::SeqCst);
    let (_zod, _zod_net, _) = ship_on(&a, "~zod", &urbit, with(by_name(&names)));
    let started = Instant::now();
    eventually("~zod is announced once the resolver answers", || point.point_status().unwrap().records == 1);
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert!(names.times_asked("zod.points.test") >= 2);
}

#[test]
fn stopping_is_prompt_with_a_point_that_never_answers_and_a_question_out() {
    let (a, b) = (TempDir::new("stop-a"), TempDir::new("stop-b"));
    let urbit = Arc::new(Listings::default());
    let (_quiet, nowhere) = silent();
    let (nec, _nec_net, _) = crew(&b, "~nec", &urbit, eager());
    let (zod, zod_net, _) = crew(&a, "~zod", &urbit, with(Lookup { ask_again: Duration::from_millis(50), ..finding(nowhere) }));
    // A call into a point that never answers fails in its time.
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert!(started.elapsed() < NOW_SLACK, "{:?}", started.elapsed());
    // Commands for ~nec wait, and the network keeps asking the point where it is, while
    // the ship's own announcements wait on the point too.
    for _ in 0..3 {
        assert_eq!(String::from_utf8(zod.deliver("~zod", "tally", b"tell nec inc hits").unwrap().reply).unwrap(), "sent");
    }
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 3);
    assert_eq!(String::from_utf8(nec.read("~nec", "counter", "counter", b"hits").unwrap()).unwrap(), "0");
    // Stopped with all of that under way, it stops at once, and lets go of the runtime.
    let started = Instant::now();
    drop(zod_net);
    assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
    eventually("the network lets go of the runtime", || Arc::strong_count(&zod) == 1);
}

#[test]
fn a_record_is_signed_over_exactly_what_it_says() {
    // The fixed layout a record is signed over, written out here by hand, as anyone
    // implementing it elsewhere would: so that a change to it is seen.
    let key = SigningKey::from_bytes(&[60; 32]);
    let ship = "~sampel-palnet";
    let number = ob::ship_number(ship).unwrap() as u64;
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let record = ship_proto::Whereabouts::decode(&*whereabouts::sign(ship, &[at], 1_800_000_000_000, &key, None).unwrap()).unwrap();
    let mut statement = b"ship.v1.where\n".to_vec();
    statement.extend_from_slice(&number.to_be_bytes());
    statement.extend_from_slice(&1_800_000_000_000u64.to_be_bytes());
    // Callers are not asked to be introduced.
    statement.push(0);
    statement.push(1);
    statement.push(4);
    statement.extend_from_slice(&[203, 0, 113, 7]);
    statement.extend_from_slice(&[0; 12]);
    statement.extend_from_slice(&4433u16.to_be_bytes());
    statement.extend_from_slice(&[0; 19 * 3]);
    assert_eq!(record.signature, key.sign(&statement).to_bytes().to_vec());
    assert_eq!(record.addresses, vec![vec![203, 0, 113, 7, 0x11, 0x51]]);
    // With callers asked to be introduced, that byte is one, and the record says so.
    let flagged = ship_proto::Whereabouts::decode(&*whereabouts::sign_flagged(ship, &[at], 1_800_000_000_000, true, &key, None).unwrap()).unwrap();
    statement[b"ship.v1.where\n".len() + 16] = 1;
    assert_eq!(flagged.signature, key.sign(&statement).to_bytes().to_vec());
    assert!(flagged.introduce);
    // And a ship's presence on a connection is signed over its own label, the ship, the
    // record's time, and the connection's value.
    let binding = [5u8; 32];
    let mut here = b"ship.v1.here\n".to_vec();
    here.extend_from_slice(&number.to_be_bytes());
    here.extend_from_slice(&1_800_000_000_000u64.to_be_bytes());
    here.extend_from_slice(&binding);
    assert_eq!(whereabouts::presence(number, 1_800_000_000_000, &binding, &key), key.sign(&here).to_bytes().to_vec());
}

// What this round of review asked for.

#[test]
fn a_moons_later_key_seen_in_a_record_holds_for_every_connection() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("moonkey-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let (planet_name, moon_name) = ("~sampel-palnet", "~doznec-sampel-palnet");
    let planet = Runtime::open(&dirs[0].0, fast()).unwrap();
    planet.create_ship(planet_name, &kernel(&planet)).unwrap();
    urbit.list(planet_name, planet.public_key(planet_name).unwrap());
    // The parent gives the moon a key at revision one, and later another at revision two.
    let first = planet.moon_keyfile(planet_name, moon_name, 1).unwrap();
    let words = |keyfile: &str| {
        let read = runtime::urbit_id::Keyfile::parse(keyfile).unwrap();
        (SigningKey::from_bytes(&read.keys.auth), runtime::moon::Proof { revision: read.revision, signed: read.signed.unwrap() })
    };
    let (first_key, first_word) = words(&first);
    let (second_key, second_word) = words(&planet.moon_keyfile(planet_name, moon_name, 2).unwrap());
    // The holder of the first key is still running, and knows where ~nec is.
    let old = Arc::new(Runtime::open(&dirs[1].0, fast()).unwrap());
    old.create_ship_from_keyfile(&kernel(&old), &first).unwrap();
    let old_dir = Directory::reading(urbit.clone());
    let old_net = Network::start(old.clone(), old_dir.clone(), eager()).unwrap();
    // ~nec and ~bud, on one runtime, look for ships through the liar.
    let rt = Arc::new(Runtime::open(&dirs[2].0, fast()).unwrap());
    for ship in ["~nec", "~bud"] {
        rt.create_ship(ship, &kernel(&rt)).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    let dir = Directory::reading(urbit.clone());
    let net = Network::start(rt.clone(), dir.clone(), with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) })).unwrap();
    old_dir.place("~nec", net.addr()).unwrap();
    old_dir.place("~bud", net.addr()).unwrap();
    let signed = |key: &SigningKey, word: runtime::moon::Proof, issued: u64, at: SocketAddr| whereabouts::sign(moon_name, &[at], issued, key, Some(word)).unwrap();

    // A record of the first key, at its holder's address, with three seconds to run.
    liar.say(Lie::Record(signed(&first_key, first_word, now_ms() - whereabouts::LIFETIME_MS + 3000, old_net.addr())));
    assert!(reaches(&net, "~nec", moon_name));
    assert!(reaches(&old_net, moon_name, "~nec"));
    // It runs out. The point now has the parent's later word, for the second key, at an
    // address where nothing answers. ~bud believes it, and the call fails there; but the
    // later word is now what this runtime knows of the moon.
    std::thread::sleep(Duration::from_millis(3200));
    let (_quiet, nowhere) = silent();
    let later = now_ms();
    liar.say(Lie::Record(signed(&second_key, second_word, later, nowhere)));
    assert!(net.ping("~bud", moon_name).is_err());
    assert_eq!(dir.key_of(moon_name), Some(second_key.verifying_key().to_bytes()));
    // The connection ~nec has open to the first key is not used again.
    assert!(net.ping("~nec", moon_name).is_err(), "a kept connection to the earlier key was used");
    // A record of the later word that names the first key's address: the first key
    // answers there, and is not taken for the moon.
    liar.say(Lie::Record(signed(&second_key, second_word, later + 1, old_net.addr())));
    std::thread::sleep(Duration::from_millis(150));
    assert!(net.ping("~bud", moon_name).is_err(), "the earlier key was taken for the moon");
    // And the holder of the first key, calling in, is no longer believed: not on the
    // connection it had, nor on a new one.
    assert!(old_net.ping(moon_name, "~nec").is_err(), "the earlier key was believed on its open connection");
    assert!(old_net.ping(moon_name, "~bud").is_err(), "the earlier key was believed calling in afresh");
}

#[test]
fn an_address_set_by_hand_while_the_point_answers_is_the_only_one_tried() {
    let (a, b) = (TempDir::new("handlate-a"), TempDir::new("handlate-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [91u8; 32];
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) }));
    // The record names an address the test watches. The point takes its time answering.
    let watched = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    watched.set_nonblocking(true).unwrap();
    let record = whereabouts::sign("~nec", &[watched.local_addr().unwrap()], now_ms(), &SigningKey::from_bytes(&seed), None).unwrap();
    liar.say(Lie::Late(Duration::from_millis(700), record));
    // While it does, an address is set by hand. Nothing from the record is tried.
    std::thread::scope(|scope| {
        let call = scope.spawn(|| zod_net.ping("~zod", "~nec"));
        std::thread::sleep(Duration::from_millis(200));
        zod_dir.place("~nec", nec_net.addr()).unwrap();
        assert!(call.join().unwrap().is_err());
    });
    let mut packet = [0u8; 2048];
    assert!(watched.recv_from(&mut packet).is_err(), "the record's address was tried after an address was set by hand");
    // The address set by hand is the one used.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(watched.recv_from(&mut packet).is_err());
}

#[test]
fn a_point_holds_only_so_many_requests_and_lets_go_of_what_a_closed_connection_left() {
    let p = TempDir::new("inhand-p");
    let urbit = Arc::new(Listings::default());
    // A point that would let a request wait a long time.
    let rt = Arc::new(Runtime::open(&p.0, fast()).unwrap());
    let lookup = Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies: None, bounds: PointBounds::default() }), ..Lookup::default() };
    let point = Network::start(rt.clone(), Directory::new(), NetConfig { request_timeout: Duration::from_secs(20), lookup, ..eager() }).unwrap();
    let keys: Vec<SigningKey> = (0..4u8).map(|n| SigningKey::from_bytes(&[80 + n; 32])).collect();
    let ships: Vec<String> = (0..4u32).map(|n| ob::ship_name(0x1234_0100 + (n << 16))).collect();
    for (ship, key) in ships.iter().zip(&keys) {
        urbit.list(ship, key.verifying_key().to_bytes());
    }
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let record = |n: usize| whereabouts::sign(&ships[n], &[at], now_ms(), &keys[n], None).unwrap();
    // The source of keys stops answering.
    urbit.1.store(true, Ordering::SeqCst);
    let most = runtime::lookup::MOST_IN_HAND;
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // Thirty connections, four announcements on each, none of which can be checked.
        let (mut connections, mut replies) = (Vec::new(), Vec::new());
        for _ in 0..30 {
            let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap();
            for n in 0..4 {
                let (mut send, receive) = connection.open_bi().await.unwrap();
                send.write_all(&announce(vec![record(n)])).await.unwrap();
                send.finish().unwrap();
                replies.push(receive);
            }
            connections.push(connection);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Only so many are in hand; the rest were refused at once, unread.
        assert_eq!(point.point_status().unwrap().in_hand, most);
        let mut refused = 0;
        for receive in &mut replies {
            refused += usize::from(matches!(tokio::time::timeout(Duration::from_millis(20), receive.read_to_end(1 << 16)).await, Ok(Err(_))));
        }
        assert_eq!(refused, 120 - most, "{refused} refused");
        // The connections close. What they left waiting is let go of at once, though the
        // source of keys has still not answered.
        for connection in &connections {
            connection.close(0u32.into(), b"gone");
        }
        let started = Instant::now();
        while point.point_status().unwrap().in_hand > 0 {
            assert!(started.elapsed() < Duration::from_secs(1), "still in hand: {:?}", point.point_status());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The source of keys answers again, and an honest announcement is taken.
        urbit.1.store(false, Ordering::SeqCst);
        let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap();
        let started = Instant::now();
        loop {
            let said = outcomes(ask_point(&connection, &announce_on(&connection, &[(record(0), keys[0].clone())])).await);
            if said == [String::new()] {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(10), "{said:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

#[test]
fn only_so_many_questions_to_points_are_out_at_once() {
    let a = TempDir::new("asking-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.say(Lie::Late(Duration::from_millis(1000), Vec::new()));
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(finding(liar.addr)));
    let ships: Vec<String> = (0..17u32).map(|n| ob::ship_name(0x2345_0100 + (n << 16))).collect();
    for ship in &ships {
        urbit.list(ship, SigningKey::from_bytes(&[95; 32]).verifying_key().to_bytes());
    }
    // Seventeen ships nobody has found, called at once, while the point is slow to answer.
    let said: Vec<String> = std::thread::scope(|scope| {
        let calls: Vec<_> = ships.iter().map(|ship| scope.spawn(|| zod_net.ping("~zod", ship).map(|_| String::new()).unwrap_or_else(|e| e.to_string()))).collect();
        calls.into_iter().map(|call| call.join().unwrap()).collect()
    });
    assert!(liar.asked.load(Ordering::SeqCst) <= 16, "{} questions out at once", liar.asked.load(Ordering::SeqCst));
    assert!(said.iter().any(|why| why.contains("as many questions")), "{said:?}");
}

#[test]
fn no_more_than_eight_addresses_are_taken_from_one_answer_for_a_name() {
    let (p, a) = (TempDir::new("nine-p"), TempDir::new("nine-a"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let names = Arc::new(Names::default());
    // Eight addresses at which a connection fails at once, and the point ninth.
    let dead: Vec<SocketAddr> = (1..=8).map(|port| SocketAddr::from(([0, 0, 0, 0], port))).collect();
    names.say("zod.points.test", [dead.clone(), vec![point.addr()]].concat());
    let lookup = Lookup { resolved_for: Duration::from_millis(200), ..by_name(&names) };
    let (_zod, _zod_net, _) = ship_on(&a, "~zod", &urbit, with(lookup));
    std::thread::sleep(Duration::from_millis(2500));
    assert!(names.times_asked("zod.points.test") >= 2);
    assert_eq!(point.point_status().unwrap().records, 0, "a ninth address was tried");
    // Among the first eight, it is found.
    names.say("zod.points.test", [dead[..7].to_vec(), vec![point.addr()]].concat());
    eventually("~zod is announced", || point.point_status().unwrap().records == 1);
}

#[test]
fn a_connection_made_to_an_address_set_by_hand_is_not_used_once_the_ship_is_looked_for() {
    let (p, a, b) = (TempDir::new("relearn-p"), TempDir::new("relearn-a"), TempDir::new("relearn-b"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    // ~nec announces itself nowhere.
    let (_nec, nec_net, _) = ship_on(&b, "~nec", &urbit, eager());
    let zod = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    zod.create_ship("~zod", &kernel(&zod)).unwrap();
    urbit.list("~zod", zod.public_key("~zod").unwrap());
    // Keys here are read again once they are a fifth of a second old.
    let zod_dir = Directory::reading_with(urbit.clone(), Duration::from_millis(200), Duration::from_secs(60));
    let zod_net = Network::start(zod.clone(), zod_dir.clone(), with(finding(point.addr()))).unwrap();
    zod_dir.place("~nec", nec_net.addr()).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    // ~nec is struck from the directory, and its key comes back from Urbit ID with no
    // address set. It is looked for through the point, which has never heard of it: the
    // connection made to the address that was set by hand is not used.
    zod_dir.remove("~nec");
    std::thread::sleep(Duration::from_millis(400));
    let asked = point.point_status().unwrap().questions;
    assert!(zod_net.ping("~zod", "~nec").is_err(), "a connection made to an address set by hand was used as one found");
    assert_eq!(point.point_status().unwrap().questions, asked + 1);
}

#[test]
fn a_caller_offering_both_protocols_is_a_ship_and_one_offering_neither_is_nobody() {
    let a = TempDir::new("alpn-a");
    let urbit = Arc::new(Listings::default());
    let serve = PointConfig { keys: urbit.clone(), galaxies: None, bounds: PointBounds::default() };
    let (nec, nec_net, _) = ship_on(&a, "~nec", &urbit, NetConfig { lookup: Lookup { serve: Some(serve), ..Lookup::default() }, ..eager() });
    let nec_key = nec.public_key("~nec").unwrap();
    let shown = |connection: &quinn::Connection| -> [u8; 32] {
        let certificates = connection.peer_identity().unwrap().downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().unwrap();
        certificates[0].as_ref()[12..].try_into().unwrap()
    };
    let agreed = |connection: &quinn::Connection| connection.handshake_data().unwrap().downcast::<quinn::crypto::rustls::HandshakeData>().unwrap().protocol;
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // Both, in either order: the ship protocol is agreed, and the ship's key is shown.
        for offered in [[&b"ship-where/1"[..], &b"ship/1"[..]], [&b"ship/1"[..], &b"ship-where/1"[..]]] {
            let connection = endpoint.connect_with(client_offering(&offered), nec_net.addr(), "nec").unwrap().await.unwrap();
            assert_eq!(agreed(&connection).as_deref(), Some(&b"ship/1"[..]));
            assert_eq!(shown(&connection), nec_key);
        }
        // Only the lookup protocol: the point's key, which is no ship's.
        let connection = endpoint.connect_with(client_offering(&[b"ship-where/1"]), nec_net.addr(), "nec").unwrap().await.unwrap();
        assert_eq!(agreed(&connection).as_deref(), Some(&b"ship-where/1"[..]));
        assert_ne!(shown(&connection), nec_key);
        // Neither, or none at all: no connection.
        for offered in [&[&b"other/1"[..]][..], &[][..]] {
            let attempt = tokio::time::timeout(Duration::from_secs(3), endpoint.connect_with(client_offering(offered), nec_net.addr(), "nec").unwrap()).await;
            assert!(!matches!(attempt, Ok(Ok(_))), "a caller offering {offered:?} was let in");
        }
    });
}

#[test]
fn a_moons_record_is_not_believed_when_there_is_no_room_to_remember_the_moon() {
    let (a, b) = (TempDir::new("moonroom-a"), TempDir::new("moonroom-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let planet_name = "~sampel-palnet";
    let planet = Runtime::open(&a.0, fast()).unwrap();
    planet.create_ship(planet_name, &kernel(&planet)).unwrap();
    urbit.list(planet_name, planet.public_key(planet_name).unwrap());
    let record = |moon: &str, at: SocketAddr| {
        let read = runtime::urbit_id::Keyfile::parse(&planet.moon_keyfile(planet_name, moon, 1).unwrap()).unwrap();
        let word = runtime::moon::Proof { revision: read.revision, signed: read.signed.unwrap() };
        whereabouts::sign(moon, &[at], now_ms(), &SigningKey::from_bytes(&read.keys.auth), Some(word)).unwrap()
    };
    // A directory with room for one moon of any one ship.
    let zod = Arc::new(Runtime::open(&b.0, fast()).unwrap());
    zod.create_ship("~zod", &kernel(&zod)).unwrap();
    urbit.list("~zod", zod.public_key("~zod").unwrap());
    let bounds = runtime::net::Bounds { moons_each: 1, ..runtime::net::Bounds::default() };
    let zod_dir = Directory::reading_within(urbit.clone(), Duration::from_secs(300), Duration::from_secs(3600), bounds);
    let zod_net = Network::start(zod.clone(), zod_dir.clone(), with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) })).unwrap();
    // The first moon's record is believed, and its word remembered.
    let (_quiet, nowhere) = silent();
    liar.say(Lie::Record(record("~doznec-sampel-palnet", nowhere)));
    assert!(zod_net.ping("~zod", "~doznec-sampel-palnet").is_err());
    assert!(zod_dir.key_of("~doznec-sampel-palnet").is_some());
    // The second's cannot be remembered, so it is not believed, and its address is not tried.
    let watched = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    watched.set_nonblocking(true).unwrap();
    liar.say(Lie::Record(record("~marnec-sampel-palnet", watched.local_addr().unwrap())));
    let why = zod_net.ping("~zod", "~marnec-sampel-palnet").unwrap_err().to_string();
    assert!(why.contains("no room to keep another moon"), "{why}");
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("no room to keep another moon")), "{:?}", zod_net.lookup_trouble());
    let mut packet = [0u8; 2048];
    assert!(watched.recv_from(&mut packet).is_err(), "the address of a record not believed was tried");
    assert_eq!(zod_dir.key_of("~marnec-sampel-palnet"), None);
}

// What the second review asked for.

/// A point that would let a request wait a long time, checking against `urbit`.
fn patient_point(dir: &TempDir, urbit: &Arc<Listings>, bounds: PointBounds) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let lookup = Lookup { serve: Some(PointConfig { keys: urbit.clone(), galaxies: None, bounds }), ..Lookup::default() };
    let net = Network::start(rt.clone(), Directory::new(), NetConfig { request_timeout: Duration::from_secs(20), lookup, ..eager() }).unwrap();
    (rt, net)
}

/// `count` planets listed in `urbit`, each with a key of its own, and a record of each at
/// an address nobody uses.
fn planets(urbit: &Listings, first: u32, count: u32) -> Vec<Vec<u8>> {
    planets_keyed(urbit, first, count).into_iter().map(|(record, _)| record).collect()
}

/// The same, each with the key it was signed with.
fn planets_keyed(urbit: &Listings, first: u32, count: u32) -> Vec<(Vec<u8>, SigningKey)> {
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    (0..count)
        .map(|n| {
            let (ship, key) = (ob::ship_name(first + (n << 16)), SigningKey::from_bytes(&[(n as u8).wrapping_add(120); 32]));
            urbit.list(&ship, key.verifying_key().to_bytes());
            (whereabouts::sign(&ship, &[at], now_ms(), &key, None).unwrap(), key)
        })
        .collect()
}

#[test]
fn a_closed_connections_announcement_asks_no_more_and_keeps_nothing() {
    let p = TempDir::new("batch-p");
    let urbit = Arc::new(Listings::default());
    let (_rt, point) = patient_point(&p, &urbit, PointBounds::default());
    let records = planets(&urbit, 0x1234_0100, 32);
    urbit.1.store(true, Ordering::SeqCst);
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // Eight connections, each announcing four ships. The first question of each is held.
        let mut connections = Vec::new();
        for batch in records.chunks(4) {
            let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap();
            let (mut send, _receive) = connection.open_bi().await.unwrap();
            send.write_all(&announce(batch.to_vec())).await.unwrap();
            send.finish().unwrap();
            connections.push((connection, _receive));
        }
        let started = Instant::now();
        while urbit.2.load(Ordering::SeqCst) < 8 {
            assert!(started.elapsed() < Duration::from_secs(10), "the first questions were not all asked");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(urbit.2.load(Ordering::SeqCst), 8);
        // The callers go. Then the source of keys answers.
        for (connection, _) in &connections {
            connection.close(0u32.into(), b"gone");
        }
        let started = Instant::now();
        while point.point_status().unwrap().in_hand > 0 {
            assert!(started.elapsed() < Duration::from_secs(2), "{:?}", point.point_status());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        urbit.1.store(false, Ordering::SeqCst);
        // An honest announcement on a new connection goes through, which takes a checking
        // place, so the eight held are free again by then.
        let honest = planets_keyed(&urbit, 0x2234_0100, 1);
        let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap();
        assert_eq!(outcomes(ask_point(&connection, &announce_on(&connection, &honest)).await), [String::new()]);
        // No question was asked for the rest of the closed connections' records, and nothing
        // of theirs was kept: only the honest one.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(urbit.2.load(Ordering::SeqCst), 9, "questions were asked on behalf of callers that had gone");
        assert_eq!(point.point_status().unwrap().records, 1, "an answer for a caller that had gone was kept");
    });
}

#[test]
fn what_cannot_be_checked_is_answered_without_waiting_for_a_checking_place() {
    let p = TempDir::new("ratewait-p");
    let urbit = Arc::new(Listings::default());
    // Allowances counted by the hour: one record an hour on each connection, and nine an hour
    // in all, so the next record overall is earned back 400 seconds after one is spent, and
    // the next on a connection an hour after. Nothing in the test turns on how fast it runs.
    let bounds = PointBounds { per_connection: 1, in_all: 9, rate_period: Duration::from_secs(3600), ..PointBounds::default() };
    let (_rt, point) = patient_point(&p, &urbit, bounds);
    let records = planets(&urbit, 0x1234_0100, 30);
    urbit.1.store(true, Ordering::SeqCst);
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = || async { endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap() };
        // Eight announcements take every checking place, and wait on the source of keys.
        let mut fillers = Vec::new();
        for record in &records[..8] {
            let connection = connect().await;
            let (mut send, receive) = connection.open_bi().await.unwrap();
            send.write_all(&announce(vec![record.clone()])).await.unwrap();
            send.finish().unwrap();
            fillers.push((connection, receive));
        }
        let started = Instant::now();
        while urbit.2.load(Ordering::SeqCst) < 8 {
            assert!(started.elapsed() < Duration::from_secs(10));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let at_once = |connection: quinn::Connection, request: Vec<u8>| async move {
            tokio::time::timeout(Duration::from_secs(1), ask_point(&connection, &request)).await.ok().flatten()
        };
        // A connection past its own rate is answered at once, for that reason: the overall
        // allowance still has a record left (nine, and eight spent).
        let over = at_once(fillers[0].0.clone(), announce(vec![records[8].clone()])).await;
        assert_eq!(outcomes(over), ["too many records on this connection just now; try again later".to_string()]);
        // So is an announcement of nothing.
        assert_eq!(outcomes(at_once(fillers[1].0.clone(), announce(Vec::new())).await), Vec::<String>::new());
        // The last record of the overall allowance is spent by a new connection; that one is
        // let in, and waits for a checking place. The test waits until the point has made its
        // rate decision on it (the count of records rated goes up only after deciding).
        let spender = connect().await;
        let (mut send, _waiting) = spender.open_bi().await.unwrap();
        send.write_all(&announce(vec![records[9].clone()])).await.unwrap();
        send.finish().unwrap();
        let started = Instant::now();
        while point.point_status().unwrap().rated < 10 {
            assert!(started.elapsed() < Duration::from_secs(10));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // With the overall allowance spent, new connections, each with its own allowance
        // whole, are answered at once too, for that reason.
        let mut refused = 0;
        for record in &records[10..20] {
            let reply = at_once(connect().await, announce(vec![record.clone()])).await;
            refused += usize::from(reply.is_some_and(|reply| matches!(reply.body, Some(ship_proto::where_reply::Body::Announced(ref said)) if said.outcomes == ["too many records at this point just now; try again later"])));
        }
        assert_eq!(refused, 10, "only {refused} of 10 answered at once");
        urbit.1.store(false, Ordering::SeqCst);
    });
}

/// A stand-in for a ship, holding the key of `seed`, that answers `Hello` and `Ping` as a
/// ship would. It counts the connections made to it and those that have closed, and can be
/// told to hold its `Welcome` back until let go.
struct FakeShip {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    hold: Arc<AtomicBool>,
    heard: Arc<AtomicBool>,
    _tokio: tokio::runtime::Runtime,
}

fn fake_ship(seed: [u8; 32]) -> FakeShip {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(anykey::AnyKey(provider.signature_verification_algorithms)))
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(shown(seed, &provider))));
    tls.alpn_protocols = vec![b"ship/1".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let endpoint = {
        let _entered = tokio.enter();
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    };
    let addr = endpoint.local_addr().unwrap();
    let (connections, closed, hold, heard) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let (counting, closing, holding, hearing) = (connections.clone(), closed.clone(), hold.clone(), heard.clone());
    tokio.spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (counting, closing, holding, hearing) = (counting.clone(), closing.clone(), holding.clone(), hearing.clone());
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                counting.fetch_add(1, Ordering::SeqCst);
                let watching = connection.clone();
                tokio::spawn(async move {
                    watching.closed().await;
                    closing.fetch_add(1, Ordering::SeqCst);
                });
                let caller = Arc::new(Mutex::new(String::new()));
                while let Ok((mut send, mut receive)) = connection.accept_bi().await {
                    let (caller, holding, hearing) = (caller.clone(), holding.clone(), hearing.clone());
                    tokio::spawn(async move {
                        let Ok(bytes) = receive.read_to_end(1 << 16).await else { return };
                        let Ok(request) = ship_proto::PeerRequest::decode(&*bytes) else { return };
                        let reply = match request.body {
                            Some(ship_proto::peer_request::Body::Hello(hello)) => {
                                *caller.lock().unwrap() = hello.ship;
                                hearing.store(true, Ordering::SeqCst);
                                while holding.load(Ordering::SeqCst) {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                                ship_proto::peer_reply::Body::Welcome(ship_proto::Welcome { proof: None })
                            }
                            Some(ship_proto::peer_request::Body::Ping(ping)) => {
                                let caller = caller.lock().unwrap().clone();
                                ship_proto::peer_reply::Body::Pong(ship_proto::Pong { nonce: ping.nonce, ship: "nec".into(), caller, incarnation: Vec::new() })
                            }
                            _ => return,
                        };
                        let _ = send.write_all(&ship_proto::PeerReply { body: Some(reply), refused: String::new() }.encode_to_vec()).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    });
                }
            });
        }
    });
    FakeShip { addr, connections, closed, hold, heard, _tokio: tokio }
}

#[test]
fn a_found_connection_is_closed_and_made_again_once_its_address_is_set_by_hand() {
    let a = TempDir::new("redial-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [101u8; 32];
    let nec = fake_ship(seed);
    urbit.list("~nec", SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, with(finding(liar.addr)));
    liar.say(Lie::Record(whereabouts::sign("~nec", &[nec.addr], now_ms(), &SigningKey::from_bytes(&seed), None).unwrap()));
    // Found through the point, and the connection is kept.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(nec.connections.load(Ordering::SeqCst), 1);
    // The very address in use is set by hand. The connection found through the point is
    // closed, and one is made afresh to the address set by hand.
    zod_dir.place("~nec", nec.addr).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(nec.connections.load(Ordering::SeqCst), 2, "the connection found through the point was used for an address set by hand");
    eventually("the found connection is closed", || nec.closed.load(Ordering::SeqCst) >= 1);
    // And the new one is kept.
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(nec.connections.load(Ordering::SeqCst), 2);
}

#[test]
fn a_connection_whose_ship_was_set_by_hand_while_it_was_made_is_not_kept() {
    let a = TempDir::new("midway-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [102u8; 32];
    let nec = fake_ship(seed);
    urbit.list("~nec", SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, with(finding(liar.addr)));
    liar.say(Lie::Record(whereabouts::sign("~nec", &[nec.addr], now_ms(), &SigningKey::from_bytes(&seed), None).unwrap()));
    // The stand-in holds its welcome back. While it does, an address is set by hand for
    // ~nec, somewhere nothing answers. Then the welcome is let go.
    nec.hold.store(true, Ordering::SeqCst);
    let (_quiet, nowhere) = silent();
    std::thread::scope(|scope| {
        let call = scope.spawn(|| zod_net.ping("~zod", "~nec"));
        eventually("the stand-in hears hello", || nec.heard.load(Ordering::SeqCst));
        zod_dir.place("~nec", nowhere).unwrap();
        nec.hold.store(false, Ordering::SeqCst);
        // The connection was made under what no longer holds: the call does not use it.
        assert!(call.join().unwrap().is_err(), "a connection made before the address was set by hand was used");
    });
    // It is closed, not kept: the next call goes where the address set by hand says.
    eventually("the connection is closed", || nec.closed.load(Ordering::SeqCst) >= 1);
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert_eq!(nec.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn credit_given_after_the_handshake_holds_a_lookup_connection_to_four_requests() {
    let p = TempDir::new("credit-p");
    let urbit = Arc::new(Listings::default());
    let (_rt, point) = patient_point(&p, &urbit, PointBounds::default());
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").unwrap().await.unwrap();
        // The credit given at the handshake, the ships' eight requests, is used up, one
        // question at a time, each answered and done with.
        for _ in 0..8 {
            assert!(ask_point(&connection, &question("~zod")).await.is_some());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        // What was given back as they finished is four at a time, not eight: four requests
        // can be started now, and no fifth while they are open.
        let mut open = Vec::new();
        while let Ok(Ok(streams)) = tokio::time::timeout(Duration::from_millis(300), connection.open_bi()).await {
            open.push(streams);
            assert!(open.len() <= 8);
        }
        assert_eq!(open.len(), 4);
    });
}

#[test]
fn an_address_set_by_hand_while_a_records_attempt_fails_stops_the_next_question() {
    let (a, b) = (TempDir::new("noask-a"), TempDir::new("noask-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [111u8; 32];
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let at = nec_net.addr();
    // ~zod and ~bud, on one runtime, look for ships through the liar.
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    for ship in ["~zod", "~bud"] {
        rt.create_ship(ship, &kernel(&rt)).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    let dir = Directory::reading(urbit.clone());
    let net = Network::start(rt.clone(), dir.clone(), with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) })).unwrap();
    liar.say(Lie::Record(whereabouts::sign("~nec", &[at], now_ms(), &SigningKey::from_bytes(&seed), None).unwrap()));
    // ~zod finds ~nec through the point; the record is held, its address good.
    assert!(reaches(&net, "~zod", "~nec"));
    let asked = liar.asked.load(Ordering::SeqCst);
    // ~nec goes, and the test listens at its old address, so as to know when an attempt
    // there has begun.
    drop(nec_net);
    let started = Instant::now();
    let watcher = loop {
        match std::net::UdpSocket::bind(at) {
            Ok(socket) => break socket,
            Err(_) if started.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not listen at {at}: {e}"),
        }
    };
    watcher.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (_quiet, nowhere) = silent();
    // ~bud calls ~nec: the record held is tried. Once that attempt has begun, an address is
    // set by hand. The attempt fails; the point is not asked again.
    std::thread::scope(|scope| {
        let call = scope.spawn(|| net.ping("~bud", "~nec"));
        // The new attempt is known by its first packet: a QUIC Initial, a long-header packet
        // of the Initial type, padded to at least 1,200 bytes. A late packet of ~zod's earlier
        // connection is none of these, and is passed over.
        let mut packet = [0u8; 2048];
        loop {
            let (read, _) = watcher.recv_from(&mut packet).expect("no attempt was made at the record's address");
            let initial = read >= 1200 && packet[0] & 0x80 != 0 && (packet[0] >> 4) & 0x03 == 0;
            if initial {
                break;
            }
        }
        dir.place("~nec", nowhere).unwrap();
        assert!(call.join().unwrap().is_err());
    });
    assert_eq!(liar.asked.load(Ordering::SeqCst), asked, "the point was asked after an address was set by hand");
}

// Routing, phase 2: presence, the outside address, introductions.

/// An announcement of records, each with the presence given.
fn announce_with(records: Vec<Vec<u8>>, presence: Vec<Vec<u8>>) -> Vec<u8> {
    ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Announce(ship_proto::Announce { records, presence })) }.encode_to_vec()
}

/// A request over `connection` to introduce `caller` (with `key`, at `at`, its record made at
/// `issued`) to `callee`, with the caller's presence on that connection.
fn introduce_on(connection: &quinn::Connection, callee: &str, caller: &str, key: &SigningKey, issued: u64, at: SocketAddr) -> Vec<u8> {
    let record = whereabouts::sign(caller, &[at], issued, key, None).unwrap();
    let presence = presence_on(connection, &record, key);
    introduce_with(callee, record, presence)
}

fn introduce_with(callee: &str, record: Vec<u8>, presence: Vec<u8>) -> Vec<u8> {
    let callee = ob::any_number(callee).unwrap();
    ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Introduce(ship_proto::Introduce { callee, record, presence })) }.encode_to_vec()
}

/// Why a request was refused, or nothing if it was not.
fn refusal(reply: Option<ship_proto::WhereReply>) -> String {
    match reply {
        Some(ship_proto::WhereReply { body: None, refused }) => refused,
        Some(_) => String::new(),
        None => "no answer".into(),
    }
}

/// The next introduction the point passes over `connection`, if one comes within a second.
async fn passed(connection: &quinn::Connection) -> Option<ship_proto::Introduction> {
    let mut stream = tokio::time::timeout(Duration::from_secs(1), connection.accept_uni()).await.ok()?.ok()?;
    ship_proto::Introduction::decode(&*stream.read_to_end(4096).await.ok()?).ok()
}

/// A caller that offers the lookup protocol and lets the point open no streams of its own: a
/// ship that never takes the introductions passed to it.
fn deaf_client() -> quinn::ClientConfig {
    let mut client = where_client();
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0u32.into());
    client.transport_config(Arc::new(transport));
    client
}

#[test]
fn a_record_is_kept_only_with_its_ships_presence_on_the_connection_it_came_on() {
    let p = TempDir::new("presence-p");
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (ship, key, other) = (ob::ship_name(0x1234_0100), SigningKey::from_bytes(&[130; 32]), SigningKey::from_bytes(&[131; 32]));
    urbit.list(&ship, key.verifying_key().to_bytes());
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let record = whereabouts::sign(&ship, &[at], now_ms(), &key, None).unwrap();
    let read = ship_proto::Whereabouts::decode(&*record).unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let first = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let second = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let said = |presence: Vec<u8>| {
            let (first, record) = (first.clone(), record.clone());
            async move { outcomes(ask_point(&first, &announce_with(vec![record], vec![presence])).await).remove(0) }
        };
        let not_here = "the ship's presence is not for this connection";
        // None at all; one for another connection; for another ship; for the record at another
        // time; by another key. None of these is kept.
        assert_eq!(said(Vec::new()).await, "the record came without the ship's presence on this connection");
        assert_eq!(said(presence_on(&second, &record, &key)).await, not_here);
        assert_eq!(said(whereabouts::presence(read.ship + (1 << 16), read.issued, &binding_of(&first), &key)).await, not_here);
        assert_eq!(said(whereabouts::presence(read.ship, read.issued + 1, &binding_of(&first), &key)).await, not_here);
        assert_eq!(said(presence_on(&first, &record, &other)).await, not_here);
        // Records and presences must pair off.
        let unpaired = ask_point(&first, &announce_with(vec![record.clone()], Vec::new())).await;
        assert!(refusal(unpaired).contains("presence"));
        assert_eq!(point.point_status().unwrap().records, 0);
        // The ship's own presence on this connection: kept, and the ship attends here.
        assert_eq!(said(presence_on(&first, &record, &key)).await, "");
        assert_eq!(point.point_status().unwrap().attending, 1);
        // It stops attending when the connection closes, and the record is still handed out.
        first.close(0u32.into(), b"gone");
        let started = Instant::now();
        while point.point_status().unwrap().attending > 0 {
            assert!(started.elapsed() < Duration::from_secs(5));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(found(ask_point(&second, &question(&ship)).await), Some(record.clone()));

        // A moon's presence is by the key its record carries, which its parent vouched for.
        let moon = ob::any_name(7u64 << 32 | 0x1234_0100);
        let moon_key = SigningKey::from_bytes(&[132; 32]);
        let word = runtime::moon::vouch(&key, ob::any_number(&moon).unwrap(), 1, &moon_key.verifying_key().to_bytes());
        let moons = whereabouts::sign(&moon, &[at], now_ms(), &moon_key, Some(word)).unwrap();
        let by_parent = presence_on(&second, &moons, &key);
        assert_eq!(outcomes(ask_point(&second, &announce_with(vec![moons.clone()], vec![by_parent])).await), [not_here.to_string()]);
        let by_moon = presence_on(&second, &moons, &moon_key);
        assert_eq!(outcomes(ask_point(&second, &announce_with(vec![moons], vec![by_moon])).await), [String::new()]);
        assert_eq!(point.point_status().unwrap().attending, 1);
    });
}

/// Waiting for a connection that is expected to be made.
trait Connected {
    async fn await_connected(self) -> quinn::Connection;
}

impl Connected for Result<quinn::Connecting, quinn::ConnectError> {
    async fn await_connected(self) -> quinn::Connection {
        self.unwrap().await.unwrap()
    }
}

#[test]
fn a_record_read_from_a_point_cannot_be_announced_by_anyone_else_nor_move_where_the_ship_attends() {
    let (p, q) = (TempDir::new("borrowed-p"), TempDir::new("borrowed-q"));
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (_qr, elsewhere) = point_on(&q, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let (ship, key) = (ob::ship_name(0x1234_0100), SigningKey::from_bytes(&[133; 32]));
    let (caller, caller_key) = (ob::ship_name(0x1235_0100), SigningKey::from_bytes(&[134; 32]));
    let thief = SigningKey::from_bytes(&[135; 32]);
    urbit.list(&ship, key.verifying_key().to_bytes());
    urbit.list(&caller, caller_key.verifying_key().to_bytes());
    let at: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = |to: SocketAddr| endpoint.connect_with(where_client(), to, "lookup").await_connected();
        // The ship announces itself to one point, on its own connection.
        let own = connect(point.addr()).await;
        let first = whereabouts::sign(&ship, &[at], now_ms(), &key, None).unwrap();
        assert_eq!(outcomes(ask_point(&own, &announce_with(vec![first.clone()], vec![presence_on(&own, &first, &key)])).await), [String::new()]);
        // And a newer record of itself to another point, where anyone can read it.
        let there = connect(elsewhere.addr()).await;
        let newer = whereabouts::sign(&ship, &[at], now_ms() + 5, &key, None).unwrap();
        assert_eq!(outcomes(ask_point(&there, &announce_with(vec![newer.clone()], vec![presence_on(&there, &newer, &key)])).await), [String::new()]);
        // Someone reads it there, and announces it to the first point: with no presence, with
        // the ship's presence on the other connection, with one of its own making. None is
        // taken, so the ship still attends where it was.
        let thief_connection = connect(point.addr()).await;
        let read = found(ask_point(&thief_connection, &question(&ship)).await).expect("the first point has the ship");
        assert_eq!(read, first);
        let stolen = found(ask_point(&connect(elsewhere.addr()).await, &question(&ship)).await).expect("the other point has the newer");
        for presence in [Vec::new(), presence_on(&there, &newer, &key), presence_on(&thief_connection, &stolen, &thief)] {
            let said = outcomes(ask_point(&thief_connection, &announce_with(vec![stolen.clone()], vec![presence])).await);
            assert!(said.len() == 1 && said[0].contains("presence"), "{said:?}");
        }
        assert_eq!(found(ask_point(&thief_connection, &question(&ship)).await), Some(first.clone()));
        // An introduction to the ship goes over the ship's own connection, and nowhere else.
        let caller_connection = connect(point.addr()).await;
        let asked = introduce_on(&caller_connection, &ship, &caller, &caller_key, now_ms(), "198.51.100.4:4433".parse().unwrap());
        assert_eq!(refusal(ask_point(&caller_connection, &asked).await), "");
        let introduction = passed(&own).await.expect("the introduction did not reach the ship's own connection");
        assert_eq!(introduction.callee, ob::any_number(&ship).unwrap());
        assert_eq!(whereabouts::ship_of(&introduction.record), ob::any_number(&caller));
        assert!(passed(&thief_connection).await.is_none(), "an introduction went to someone who only read the record");
        assert_eq!(point.point_status().unwrap().pushed, 1);
    });
}

#[test]
fn introductions_at_a_point_are_checked_bounded_and_refused_saying_which_limit() {
    let p = TempDir::new("introlimits-p");
    let urbit = Arc::new(Listings::default());
    // Seven introductions in all and two for any one caller, counted by the hour, so nothing is
    // earned back while the test runs.
    let bounds = PointBounds { introductions: 7, introductions_each: 2, rate_period: Duration::from_secs(3600), ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    let keys: Vec<SigningKey> = (0..5u8).map(|n| SigningKey::from_bytes(&[140 + n; 32])).collect();
    let ships: Vec<String> = (0..5u32).map(|n| ob::ship_name(0x1234_0100 + (n << 16))).collect();
    for (ship, key) in ships.iter().zip(&keys) {
        urbit.list(ship, key.verifying_key().to_bytes());
    }
    let (callee, callee_key) = (&ships[0], &keys[0]);
    let at: SocketAddr = "198.51.100.4:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = || endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected();
        let (own, asker, other) = (connect().await, connect().await, connect().await);
        // Not attending: nobody has announced the callee.
        let ask = |connection: quinn::Connection, request: Vec<u8>| async move { refusal(ask_point(&connection, &request).await) };
        assert_eq!(ask(asker.clone(), introduce_on(&asker, callee, &ships[1], &keys[1], now_ms(), at)).await, "that ship is not attending this lookup point");
        // The callee announces itself, and attends.
        let record = whereabouts::sign(callee, &[at], now_ms(), callee_key, None).unwrap();
        assert_eq!(outcomes(ask_point(&own, &announce_with(vec![record.clone()], vec![presence_on(&own, &record, callee_key)])).await), [String::new()]);
        // A caller's record forged, run out, or shown with a presence for another connection.
        let forged = introduce_on(&asker, callee, &ships[1], &keys[2], now_ms(), at);
        assert_eq!(ask(asker.clone(), forged).await, "the record is not signed by the ship's key");
        let stale = introduce_on(&asker, callee, &ships[1], &keys[1], now_ms() - whereabouts::LIFETIME_MS - 1000, at);
        assert_eq!(ask(asker.clone(), stale).await, "the record has run out");
        let replayed = introduce_on(&other, callee, &ships[1], &keys[1], now_ms(), at);
        assert_eq!(ask(asker.clone(), replayed).await, "the ship's presence is not for this connection");
        assert!(passed(&own).await.is_none(), "an introduction not believed was passed on");
        // A genuine one is passed to the callee, over its own connection.
        assert_eq!(ask(asker.clone(), introduce_on(&asker, callee, &ships[1], &keys[1], now_ms(), at)).await, "");
        let introduction = passed(&own).await.expect("passed on");
        assert_eq!(whereabouts::ship_of(&introduction.record), ob::any_number(&ships[1]));
        // Two for one caller, and the third is refused for that reason.
        assert_eq!(ask(asker.clone(), introduce_on(&asker, callee, &ships[1], &keys[1], now_ms(), at)).await, "");
        assert_eq!(ask(asker.clone(), introduce_on(&asker, callee, &ships[1], &keys[1], now_ms(), at)).await, "too many introductions from that ship just now; try again later");
        // Seven in all, the refused ones counted: one more is let in, and then none.
        assert_eq!(ask(other.clone(), introduce_on(&other, callee, &ships[2], &keys[2], now_ms(), at)).await, "");
        assert_eq!(ask(other.clone(), introduce_on(&other, callee, &ships[3], &keys[3], now_ms(), at)).await, "too many introductions at this point just now; try again later");
        // None of that stops ordinary questions.
        assert_eq!(found(ask_point(&other, &question(callee)).await), Some(record.clone()));
        // The callee's connection closes; a moment later, it is not attending, whatever else.
        own.close(0u32.into(), b"gone");
        let started = Instant::now();
        while point.point_status().unwrap().attending > 0 {
            assert!(started.elapsed() < Duration::from_secs(5));
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(ask(other.clone(), introduce_on(&other, callee, &ships[4], &keys[4], now_ms(), at)).await, "that ship is not attending this lookup point");
        assert_eq!(found(ask_point(&other, &question(callee)).await), Some(record));
    });
}

#[test]
fn a_point_holds_only_so_many_introductions_waiting_for_a_ship_that_does_not_take_them() {
    let p = TempDir::new("introwait-p");
    let urbit = Arc::new(Listings::default());
    let bounds = PointBounds { introductions_each: 100, ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    let (callee, callee_key) = (ob::ship_name(0x1234_0100), SigningKey::from_bytes(&[150; 32]));
    let (caller, caller_key) = (ob::ship_name(0x1235_0100), SigningKey::from_bytes(&[151; 32]));
    urbit.list(&callee, callee_key.verifying_key().to_bytes());
    urbit.list(&caller, caller_key.verifying_key().to_bytes());
    let at: SocketAddr = "198.51.100.4:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let point_net = tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // The callee lets the point open no streams: nothing passed to it is ever taken.
        let own = endpoint.connect_with(deaf_client(), point.addr(), "lookup").await_connected().await;
        let record = whereabouts::sign(&callee, &[at], now_ms(), &callee_key, None).unwrap();
        assert_eq!(outcomes(ask_point(&own, &announce_with(vec![record.clone()], vec![presence_on(&own, &record, &callee_key)])).await), [String::new()]);
        let asker = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let mut said = Vec::new();
        for _ in 0..(runtime::lookup::MOST_WAITING_EACH + 2) {
            said.push(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await));
        }
        // One may be on its way (waiting for the callee to take it), and four more wait. Past
        // that, each is refused for that reason.
        let taken = said.iter().filter(|why| why.is_empty()).count();
        assert!(taken == runtime::lookup::MOST_WAITING_EACH || taken == runtime::lookup::MOST_WAITING_EACH + 1, "{said:?}");
        assert!(said.last().unwrap().contains("as many introductions waiting"), "{said:?}");
        // What waits too long is dropped, and there is room again. (This waits on the clock.)
        tokio::time::sleep(Duration::from_millis(4500)).await;
        assert_eq!(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await), "");
        assert_eq!(point.point_status().unwrap().pushed, 0);
        (own, asker)
    });
    // And the point stops promptly, with introductions in hand for a ship that takes none.
    let started = Instant::now();
    drop(point);
    assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
    drop(point_net);
}

/// The packets that arrive at `socket` within `wait` of the last, and where each came from.
fn packets(socket: &std::net::UdpSocket, wait: Duration) -> Vec<(Vec<u8>, SocketAddr)> {
    socket.set_read_timeout(Some(wait)).unwrap();
    let mut got = Vec::new();
    let mut packet = [0u8; 2048];
    while let Ok((read, from)) = socket.recv_from(&mut packet) {
        got.push((packet[..read].to_vec(), from));
    }
    got
}

/// An introduction of `caller`'s record to `callee`, as a point passes it on.
fn introduction(callee: &str, record: Vec<u8>) -> Vec<u8> {
    ship_proto::Introduction { callee: ob::any_number(callee).unwrap(), record }.encode_to_vec()
}

#[test]
fn a_ship_sends_its_packets_only_for_introductions_it_believes_and_only_so_many() {
    let a = TempDir::new("punch-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    // The point says ~nec is seen somewhere it does not listen, so ~nec asks to be introduced.
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(finding(liar.addr)));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let here = watch.local_addr().unwrap();
    let bus = SigningKey::from_bytes(&[160; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let heard = |count: u64| eventually("the introductions are heard", || nec_net.introductions().heard >= count);
    let now = now_ms();
    // A forged record, one run out, ~nec's own, rubbish, one for a ship not here, one that never
    // ends: none is believed, and nothing is sent.
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now, &SigningKey::from_bytes(&[161; 32]), None).unwrap()), false);
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now - whereabouts::LIFETIME_MS - 1, &bus, None).unwrap()), false);
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now, &bus, None).unwrap()[..20].to_vec()), false);
    liar.push(vec![0xff; 64], false);
    liar.push(introduction("~bud", whereabouts::sign("~bus", &[here], now, &bus, None).unwrap()), false);
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now, &bus, None).unwrap()), true);
    heard(5);
    // ~nec's own record, signed as ~nec signs: the network has it; the test reads it back.
    let own = liar.records().last().unwrap().encode_to_vec();
    liar.push(introduction("~nec", own), false);
    heard(6);
    // Then a genuine one: exactly three packets, each the one that opens a router, from the
    // port ~nec is reached at. (Weighed in order, so the ones before were weighed first.)
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now, &bus, None).unwrap()), false);
    let got = packets(&watch, Duration::from_millis(800));
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|(packet, from)| packet == runtime::net::PUNCH && *from == nec_net.addr()), "{got:?}");
    assert_eq!(nec_net.introductions().sent, 3);
    // An introduction of a ship nothing is known of waits on Urbit ID. Meanwhile ~nec stops
    // asking to be introduced (the point now says it sees ~nec where it listens). When the
    // caller's key comes, nothing is sent: that is weighed again after the wait.
    let wes = SigningKey::from_bytes(&[163; 32]);
    urbit.list("~wes", wes.verifying_key().to_bytes());
    urbit.1.store(true, Ordering::SeqCst);
    let asked = urbit.2.load(Ordering::SeqCst);
    let heard_before = nec_net.introductions().heard;
    liar.push(introduction("~nec", whereabouts::sign("~wes", &[here], now_ms(), &wes, None).unwrap()), false);
    eventually("it waits on Urbit ID", || urbit.2.load(Ordering::SeqCst) > asked);
    liar.see(SeenLie::Truth);
    eventually("~nec is announced asking for no introduction", || liar.records().last().is_some_and(|record| !record.introduce));
    std::thread::sleep(Duration::from_millis(200));
    urbit.1.store(false, Ordering::SeqCst);
    // And an introduction of a caller already known, now: nothing either.
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now_ms(), &bus, None).unwrap()), false);
    eventually("both are heard", || nec_net.introductions().heard >= heard_before + 2);
    assert!(packets(&watch, Duration::from_millis(800)).is_empty());
    assert_eq!(nec_net.introductions().sent, 3);
    let _ = nec;
}

/// Push introductions from each caller in turn, `rounds` times, and count the packets that
/// come of them at each caller's socket. Each count is held to the allowances by the time the
/// weighing ended: whole at the start, earned back at their rate after.
fn flood(liar: &Liar, net: &Network, urbit: &Listings, first: u32, callers: u32, rounds: usize) -> (Vec<usize>, f64, f64) {
    let callers: Vec<(String, SigningKey, std::net::UdpSocket)> = (0..callers)
        .map(|n| {
            let (ship, key) = (ob::ship_name(first + (n << 16)), SigningKey::from_bytes(&[(first >> 16) as u8 ^ n as u8; 32]));
            urbit.list(&ship, key.verifying_key().to_bytes());
            (ship, key, std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        })
        .collect();
    let heard = net.introductions().heard;
    let started = Instant::now();
    for _ in 0..rounds {
        for (ship, key, socket) in &callers {
            liar.push(introduction("~nec", whereabouts::sign(ship, &[socket.local_addr().unwrap()], now_ms(), key, None).unwrap()), false);
        }
    }
    // Weighing has ended once nothing more is heard for a while; the time taken to see that is
    // more than the weighing took, so the bound it gives is loose the right way.
    let mut last = (net.introductions().heard, Instant::now());
    while last.1.elapsed() < Duration::from_millis(300) {
        std::thread::sleep(Duration::from_millis(20));
        let now = net.introductions().heard;
        if now != last.0 {
            last = (now, Instant::now());
        }
    }
    assert!(last.0 > heard);
    let took = (last.1 - started).as_secs_f64();
    std::thread::sleep(Duration::from_millis(700));
    let counted = callers.iter().map(|(_, _, socket)| packets(socket, Duration::from_millis(50)).len()).collect();
    (counted, took, started.elapsed().as_secs_f64())
}

#[test]
fn a_ship_flooded_with_introductions_still_answers_its_ordinary_callers() {
    let (a, b) = (TempDir::new("flood-a"), TempDir::new("flood-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(finding(liar.addr)));
    let (_zod, zod_net, zod_dir) = ship_on(&b, "~zod", &urbit, eager());
    zod_dir.place("~nec", nec_net.addr()).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    // An introduction in hand: Urbit ID is held, and an introduction of a ship ~nec knows
    // nothing of waits on its key. While it does, an ordinary call to ~nec completes.
    let wes = SigningKey::from_bytes(&[171; 32]);
    urbit.list("~wes", wes.verifying_key().to_bytes());
    urbit.1.store(true, Ordering::SeqCst);
    let asked = urbit.2.load(Ordering::SeqCst);
    liar.push(introduction("~nec", whereabouts::sign("~wes", &["127.0.0.1:9".parse().unwrap()], now_ms(), &wes, None).unwrap()), false);
    eventually("the introduction waits on Urbit ID", || urbit.2.load(Ordering::SeqCst) > asked);
    let acted = nec_net.introductions().acted;
    let calling = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(calling.elapsed() < Duration::from_secs(3), "{:?}", calling.elapsed());
    // The introduction was still in hand when the call completed: not acted on.
    assert_eq!(nec_net.introductions().acted, acted);
    urbit.1.store(false, Ordering::SeqCst);
    // Then floods of introductions, while ~zod calls ~nec over and over: every call goes
    // through, within a time a loaded machine meets. (This shows calls succeed throughout a
    // period in which introductions are pushed and weighed, not that each overlaps one. The
    // limits on what introductions send are shown on their own by the unit tests in
    // `router_tests.rs`: a caller's allowance, the places under way, the overall allowance,
    // and their order.)
    let flooding = AtomicBool::new(true);
    /// Tells the calling thread to stop however the floods end, a failed check included.
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let calls = std::thread::scope(|scope| {
        let stop = Stop(&flooding);
        let caller = scope.spawn(|| {
            let mut calls = Vec::new();
            while flooding.load(Ordering::SeqCst) {
                let started = Instant::now();
                calls.push((reaches(&zod_net, "~zod", "~nec"), started.elapsed()));
                std::thread::sleep(Duration::from_millis(10));
            }
            calls
        });
        // Three callers, each introduced twenty times; then forty callers, each once. Some of
        // each are acted on.
        let (each, _, _) = flood(&liar, &nec_net, &urbit, 0x2234_0100, 3, 20);
        assert!(each.iter().all(|&got| got >= 3), "{each:?}");
        std::thread::sleep(Duration::from_millis(1100));
        let (each, _, _) = flood(&liar, &nec_net, &urbit, 0x3334_0100, 40, 1);
        assert!(each.iter().sum::<usize>() >= 3, "{each:?}");
        drop(stop);
        caller.join().unwrap()
    });
    assert!(!calls.is_empty());
    assert!(calls.iter().all(|(reached, took)| *reached && *took < Duration::from_secs(3)), "{calls:?}");
}

#[test]
fn a_ship_lets_go_of_the_connection_to_a_point_it_no_longer_announces_to() {
    let dirs: Vec<TempDir> = (0..4).map(|n| TempDir::new(&format!("walk-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let points: Vec<(Arc<Runtime>, Network)> = dirs[..3].iter().map(|dir| point_on(dir, &urbit, None, PointBounds::default(), "127.0.0.1:0")).collect();
    let names = Arc::new(Names::default());
    names.say("zod.points.test", vec![points[0].1.addr()]);
    let lookup = Lookup { resolved_for: Duration::from_millis(200), ..by_name(&names) };
    let (_zod, _zod_net, _) = ship_on(&dirs[3], "~zod", &urbit, with(lookup));
    eventually("~zod attends at the first point", || points[0].1.point_status().unwrap().attending == 1);
    // The name moves on to each of the other points in turn. ~zod announces there, and lets
    // go of the connection to the point before, which nothing else announces over.
    for n in 1..3 {
        names.say("zod.points.test", vec![points[n].1.addr()]);
        eventually("~zod attends at the next point", || points[n].1.point_status().unwrap().attending == 1);
        eventually("the point before sees its connection closed", || points[n - 1].1.point_status().unwrap().connections == 0);
    }
}

#[test]
fn a_ship_holds_only_so_many_introductions_and_stops_promptly_with_one_in_hand() {
    let (a, b) = (TempDir::new("inhandintro-a"), TempDir::new("inhandintro-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(finding(liar.addr)));
    let (_zod, zod_net, zod_dir) = ship_on(&b, "~zod", &urbit, eager());
    zod_dir.place("~nec", nec_net.addr()).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    // Urbit ID stops answering. Each introduction is of a ship ~nec knows nothing of, so the
    // first waits on its key, and the rest wait behind it, as many as may.
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let callers: Vec<(String, SigningKey)> = (0..40u32).map(|n| (ob::ship_name(0x3234_0100 + (n << 16)), SigningKey::from_bytes(&[200 + (n % 50) as u8; 32]))).collect();
    for (ship, key) in &callers {
        urbit.list(ship, key.verifying_key().to_bytes());
    }
    urbit.1.store(true, Ordering::SeqCst);
    let asked = urbit.2.load(Ordering::SeqCst);
    for (ship, key) in &callers {
        liar.push(introduction("~nec", whereabouts::sign(ship, &[watch.local_addr().unwrap()], now_ms(), key, None).unwrap()), false);
    }
    eventually("the first waits on Urbit ID", || urbit.2.load(Ordering::SeqCst) > asked);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(nec_net.introductions().heard, 1, "{:?}", nec_net.introductions());
    // A ship already known calls ~nec meanwhile, and is answered at once.
    let calling = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(calling.elapsed() < Duration::from_secs(1), "{:?}", calling.elapsed());
    // The one being weighed is given up on in its time (five seconds), and the next is taken,
    // though Urbit ID still says nothing. (This waits on the clock.)
    eventually("the next introduction is taken", || nec_net.introductions().heard >= 2);
    // Urbit ID answers again. The introductions that waited are weighed: one, and eight more
    // that waited behind it. The rest were dropped as they came.
    urbit.1.store(false, Ordering::SeqCst);
    eventually("those that waited are weighed", || nec_net.introductions().heard == 1 + runtime::net::MOST_INTRODUCTIONS_IN_HAND as u64);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(nec_net.introductions().heard, 1 + runtime::net::MOST_INTRODUCTIONS_IN_HAND as u64);
    // One more, of a ship nothing is known of, with Urbit ID silent again: stopped with that
    // introduction in hand, the network stops at once.
    urbit.1.store(true, Ordering::SeqCst);
    let (late, late_key) = (ob::ship_name(0x4234_0100), SigningKey::from_bytes(&[250; 32]));
    urbit.list(&late, late_key.verifying_key().to_bytes());
    let asked = urbit.2.load(Ordering::SeqCst);
    liar.push(introduction("~nec", whereabouts::sign(&late, &[watch.local_addr().unwrap()], now_ms(), &late_key, None).unwrap()), false);
    eventually("it waits on Urbit ID", || urbit.2.load(Ordering::SeqCst) > asked);
    let started = Instant::now();
    drop(nec_net);
    assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
    urbit.1.store(false, Ordering::SeqCst);
}

#[test]
fn a_caller_stops_promptly_while_its_introduction_is_being_answered() {
    let (a, b) = (TempDir::new("callerstop-a"), TempDir::new("callerstop-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    // The point holds every request for an introduction back.
    *liar.introduce_after.lock().unwrap() = Duration::from_secs(60);
    let seed = [180u8; 32];
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let (zod, zod_net, _) = crew(&a, "~zod", &urbit, with(finding(liar.addr)));
    eventually("~zod is announced", || !liar.records().is_empty());
    liar.say(Lie::Record(whereabouts::sign_flagged("~nec", &[nec_net.addr()], now_ms(), true, &SigningKey::from_bytes(&seed), None).unwrap()));
    // A command for ~nec: carrying it, ~zod finds ~nec's record asks to be introduced, and asks.
    assert_eq!(String::from_utf8(zod.deliver("~zod", "tally", b"tell nec inc hits").unwrap().reply).unwrap(), "sent");
    eventually("~zod asks to be introduced", || liar.introductions.load(Ordering::SeqCst) >= 1);
    let started = Instant::now();
    drop(zod_net);
    assert!(started.elapsed() < Duration::from_secs(2), "stopping took {:?}", started.elapsed());
}

#[test]
fn a_runtime_with_nothing_stated_announces_what_its_point_sees_and_stated_addresses_win() {
    let dirs: Vec<TempDir> = (0..5).map(|n| TempDir::new(&format!("seen-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&dirs[0], &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let record_of = |ship: &str| {
        let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio.block_on(async {
            let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
            found(ask_point(&connection, &question(ship)).await).map(|record| ship_proto::Whereabouts::decode(&*record).unwrap())
        })
    };
    let addr_of = |record: &ship_proto::Whereabouts| record.addresses.iter().map(|bytes| bytes.clone()).collect::<Vec<_>>();
    // Listening where it is reached: the point sees just that, and callers need no introduction.
    let (_zod, zod_net, _) = ship_on(&dirs[1], "~zod", &urbit, with(finding(point.addr())));
    eventually("~zod is announced", || record_of("~zod").is_some());
    let zod_record = record_of("~zod").unwrap();
    assert_eq!(addr_of(&zod_record), vec![address_bytes(zod_net.addr())]);
    assert!(!zod_record.introduce);
    // Listening on "any address", which says nothing of where it is reached: the address the
    // point sees is announced, and callers are asked to be introduced, since it is not the one
    // listened on. And it is called by name, through an introduction.
    let (_nec, nec_net, _) = ship_on(&dirs[2], "~nec", &urbit, NetConfig { addr: "0.0.0.0:0".into(), ..with(finding(point.addr())) });
    eventually("~nec is announced", || record_of("~nec").is_some());
    let nec_record = record_of("~nec").unwrap();
    assert_eq!(addr_of(&nec_record), vec![address_bytes(SocketAddr::from(([127, 0, 0, 1], nec_net.addr().port())))]);
    assert!(nec_record.introduce);
    // ~nec calls ~zod, whose record asks for no introduction: none is asked for.
    assert!(reaches(&nec_net, "~nec", "~zod"));
    assert_eq!(point.point_status().unwrap().introduced, 0);
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(point.point_status().unwrap().introduced, 1);
    // Stated by hand: exactly what is stated, whatever the point sees, and no introduction
    // unless the runtime says it is behind a router.
    let stated: SocketAddr = "203.0.113.5:7".parse().unwrap();
    let (_bud, _bud_net, _) = ship_on(&dirs[3], "~bud", &urbit, with(Lookup { announce: vec![stated], ..finding(point.addr()) }));
    eventually("~bud is announced", || record_of("~bud").is_some());
    let bud_record = record_of("~bud").unwrap();
    assert_eq!(addr_of(&bud_record), vec![address_bytes(stated)]);
    assert!(!bud_record.introduce);
    let (_wes, _wes_net, _) = ship_on(&dirs[4], "~wes", &urbit, with(Lookup { announce: vec![stated], behind_router: true, ..finding(point.addr()) }));
    eventually("~wes is announced", || record_of("~wes").is_some());
    let wes_record = record_of("~wes").unwrap();
    assert_eq!(addr_of(&wes_record), vec![address_bytes(stated)]);
    assert!(wes_record.introduce);
}

#[test]
fn a_point_listening_on_both_kinds_of_address_reports_an_ipv4_caller_as_ipv4() {
    let (p, a) = (TempDir::new("dualstack-p"), TempDir::new("dualstack-a"));
    let urbit = Arc::new(Listings::default());
    // On this machine a socket bound to [::] takes IPv4 callers too, and sees them written as
    // IPv6 (::ffff:127.0.0.1). What a point reports, and what a ship announces, is plain IPv4.
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "[::]:0");
    let at = SocketAddr::from(([127, 0, 0, 1], point.addr().port()));
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(finding(at)));
    eventually("~zod is announced", || point.point_status().unwrap().records == 1);
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(where_client(), at, "lookup").await_connected().await;
        let seen = ask_point(&connection, &ship_proto::WhereRequest { body: Some(ship_proto::where_request::Body::Seen(ship_proto::Seen {})) }.encode_to_vec()).await;
        let Some(ship_proto::where_reply::Body::Saw(saw)) = seen.and_then(|reply| reply.body) else { panic!("no answer") };
        assert_eq!(saw.address, address_bytes(endpoint.local_addr().unwrap()));
        let record = ship_proto::Whereabouts::decode(&*found(ask_point(&connection, &question("~zod")).await).unwrap()).unwrap();
        assert_eq!(record.addresses, vec![address_bytes(zod_net.addr())]);
        assert!(!record.introduce);
    });
}

#[test]
fn a_ship_is_announced_again_at_once_when_its_connection_to_the_point_drops() {
    let (p, q, a) = (TempDir::new("redo-p"), TempDir::new("redo-q"), TempDir::new("redo-a"));
    let urbit = Arc::new(Listings::default());
    let at = free_port();
    let (point_rt, point) = point_on(&p, &urbit, None, PointBounds::default(), &at.to_string());
    // Announced every two minutes, as by default.
    let (_zod, _zod_net, _) = ship_on(&a, "~zod", &urbit, with(Lookup { announce_every: Duration::from_secs(120), ..finding(at) }));
    eventually("~zod is announced", || point.point_status().unwrap().attending == 1);
    // The point goes and comes back, empty. The connection ~zod announced over has dropped,
    // so ~zod is announced again over a new one, at once, not two minutes later.
    drop(point);
    drop(point_rt);
    let (_point_rt, point) = point_on(&q, &urbit, None, PointBounds::default(), &at.to_string());
    eventually("~zod is announced again, and attends on the new connection", || point.point_status().unwrap().attending == 1);
}

#[test]
fn what_a_point_says_of_where_it_sees_a_runtime_is_used_only_if_a_record_may_carry_it() {
    let (a, b) = (TempDir::new("seenlie-a"), TempDir::new("seenlie-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let lookup = Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) };
    // A refused kind of address, rubbish, a refusal, and silence: nothing is announced, and
    // the next round asks again.
    liar.see(SeenLie::Address(address_bytes("0.0.0.0:4433".parse().unwrap())));
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, with(lookup.clone()));
    for lie in [SeenLie::Address(address_bytes("0.0.0.0:4433".parse().unwrap())), SeenLie::Address(vec![1, 2, 3, 4, 5]), SeenLie::Refuse, SeenLie::Silent] {
        liar.see(lie);
        let asked = liar.seens.load(Ordering::SeqCst);
        eventually("the point is asked again", || liar.seens.load(Ordering::SeqCst) >= asked + 2);
        assert!(liar.records().is_empty(), "something was announced on a lie");
    }
    assert!(zod_net.lookup_trouble().is_some_and(|why| why.contains("sees this runtime") || why.contains("where it sees")), "{:?}", zod_net.lookup_trouble());
    // The truth: announced, and since it is where ~zod listens, no introduction is asked for.
    liar.see(SeenLie::Truth);
    eventually("~zod is announced", || !liar.records().is_empty());
    let record = liar.records().last().unwrap().clone();
    assert_eq!(record.addresses, vec![address_bytes(zod_net.addr())]);
    assert!(!record.introduce);
    // Somewhere else: announced there, asking for introductions.
    let there: SocketAddr = "203.0.113.9:4433".parse().unwrap();
    liar.see(SeenLie::Address(address_bytes(there)));
    eventually("~zod is announced where the point says", || liar.records().last().is_some_and(|record| record.addresses == vec![address_bytes(there)]));
    assert!(liar.records().last().unwrap().introduce);
    // With addresses stated by hand, the point is not asked at all, and what it would say
    // changes nothing.
    let stated: SocketAddr = "203.0.113.5:7".parse().unwrap();
    let other = crate::liar();
    other.see(SeenLie::Address(address_bytes(there)));
    let (_nec, _nec_net, _) = ship_on(&b, "~nec", &urbit, with(Lookup { announce: vec![stated], ..finding(other.addr) }));
    eventually("~nec is announced", || !other.records().is_empty());
    assert!(other.records().iter().all(|record| record.addresses == vec![address_bytes(stated)] && !record.introduce));
    assert_eq!(other.seens.load(Ordering::SeqCst), 0);
}

#[test]
fn with_an_address_set_by_hand_no_introduction_is_asked_for() {
    let dirs: Vec<TempDir> = (0..3).map(|n| TempDir::new(&format!("handintro-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&dirs[0], &urbit, None, PointBounds::default(), "127.0.0.1:0");
    // ~nec asks callers to be introduced.
    let (_nec, nec_net, _) = ship_on(&dirs[1], "~nec", &urbit, NetConfig { addr: "0.0.0.0:0".into(), ..with(finding(point.addr())) });
    let (_zod, zod_net, zod_dir) = ship_on(&dirs[2], "~zod", &urbit, with(finding(point.addr())));
    eventually("both are announced", || point.point_status().unwrap().attending == 2);
    zod_dir.place("~nec", SocketAddr::from(([127, 0, 0, 1], nec_net.addr().port()))).unwrap();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert_eq!(point.point_status().unwrap().introduced, 0);
    assert_eq!(point.point_status().unwrap().questions, 0);
}

#[test]
fn the_packet_that_opens_a_router_draws_no_answer_from_quic_and_a_flood_of_them_changes_nothing() {
    let (a, b) = (TempDir::new("quiet-a"), TempDir::new("quiet-b"));
    let urbit = Arc::new(Listings::default());
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, eager());
    let (_zod, zod_net, zod_dir) = ship_on(&b, "~zod", &urbit, eager());
    zod_dir.place("~nec", nec_net.addr()).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // Something QUIC does answer, to show that an answer would be seen: a long header of a
    // version it does not speak, padded to 1,200 bytes, draws a version negotiation.
    let mut unknown = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    unknown.extend_from_slice(&[7; 8]);
    unknown.push(8);
    unknown.extend_from_slice(&[9; 8]);
    unknown.resize(1200, 0);
    socket.send_to(&unknown, nec_net.addr()).unwrap();
    let answered = packets(&socket, Duration::from_millis(500));
    assert!(answered.len() == 1 && answered[0].0[1..5] == [0, 0, 0, 0], "no version negotiation came back: {answered:?}");
    // The packet that opens a router: nothing comes back.
    for _ in 0..3 {
        socket.send_to(runtime::net::PUNCH, nec_net.addr()).unwrap();
    }
    assert!(packets(&socket, Duration::from_millis(500)).is_empty());
    // A flood of them, while ~zod calls ~nec: every call goes through, and nothing is answered.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..20_000 {
                let _ = socket.send_to(runtime::net::PUNCH, nec_net.addr());
            }
        });
        for _ in 0..5 {
            assert!(reaches(&zod_net, "~zod", "~nec"));
        }
    });
    assert!(packets(&socket, Duration::from_millis(500)).is_empty());
}

#[test]
fn a_point_may_open_only_four_streams_at_a_ship_and_pass_it_only_so_much() {
    let a = TempDir::new("pushbound-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(finding(liar.addr)));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    // Four streams the point may open at once, and no fifth while they are open. (A stream
    // frees its place when the point ends it; one that a point holds open holds its place, and
    // so only that point's own introductions are held up.)
    for n in 0..4 {
        assert!(liar.opens(Duration::from_secs(2)), "stream {n} could not be opened");
    }
    assert!(!liar.opens(Duration::ZERO), "a fifth stream was opened");
    eventually("room for a stream again once the point ends them", || liar.opens(Duration::ZERO));
    std::thread::sleep(Duration::from_millis(300));
    // An introduction too large to be one is not taken, though the record in it is genuine.
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bus = SigningKey::from_bytes(&[190; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let record = whereabouts::sign("~bus", &[watch.local_addr().unwrap()], now_ms(), &bus, None).unwrap();
    let padded = [introduction("~nec", record.clone()), vec![0x7a, 0x80, 0x10], vec![0; 2048]].concat();
    assert!(ship_proto::Introduction::decode(&*padded).is_ok());
    let heard = nec_net.introductions().heard;
    liar.push(padded, false);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(nec_net.introductions().heard, heard);
    liar.push(introduction("~nec", record), false);
    assert_eq!(packets(&watch, Duration::from_millis(800)).len(), 3);
}

#[test]
fn a_ship_that_does_not_read_what_is_passed_to_it_holds_up_only_its_own_introductions_and_only_so_long() {
    let p = TempDir::new("slowread-p");
    let urbit = Arc::new(Listings::default());
    let bounds = PointBounds { introductions_each: 100, ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    let (callee, callee_key) = (ob::ship_name(0x1234_0100), SigningKey::from_bytes(&[152; 32]));
    let (caller, caller_key) = (ob::ship_name(0x1235_0100), SigningKey::from_bytes(&[153; 32]));
    urbit.list(&callee, callee_key.verifying_key().to_bytes());
    urbit.list(&caller, caller_key.verifying_key().to_bytes());
    let at: SocketAddr = "198.51.100.4:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        // The callee takes streams but reads nothing from them, and has room for only a few
        // bytes on each: the point cannot finish writing an introduction to it.
        let mut client = where_client();
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(32u32.into());
        client.transport_config(Arc::new(transport));
        let own = endpoint.connect_with(client, point.addr(), "lookup").await_connected().await;
        let record = whereabouts::sign(&callee, &[at], now_ms(), &callee_key, None).unwrap();
        assert_eq!(outcomes(ask_point(&own, &announce_with(vec![record.clone()], vec![presence_on(&own, &record, &callee_key)])).await), [String::new()]);
        let asker = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        for _ in 0..2 {
            assert_eq!(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await), "");
        }
        // The first is begun, and not finished. Only after its time is it given up, and the
        // second begun.
        let first = tokio::time::timeout(Duration::from_secs(2), own.accept_uni()).await.expect("the first was not begun").unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(500), own.accept_uni()).await.is_err(), "the second was begun before the first was given up");
        let second = tokio::time::timeout(Duration::from_secs(3), own.accept_uni()).await.expect("the second was never begun").unwrap();
        drop((first, second));
        // Meanwhile the point answered everyone else as ever.
        assert_eq!(found(ask_point(&asker, &question(&callee)).await), Some(record));
    });
}

#[test]
fn a_point_holds_only_so_many_introductions_waiting_on_one_connection() {
    let p = TempDir::new("connwait-p");
    let urbit = Arc::new(Listings::default());
    let bounds = PointBounds { introductions_each: 100, ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    // Five ships announced over one connection that takes nothing passed to it.
    let callees = planets_keyed(&urbit, 0x1234_0100, 5);
    let (caller, caller_key) = (ob::ship_name(0x2235_0100), SigningKey::from_bytes(&[154; 32]));
    urbit.list(&caller, caller_key.verifying_key().to_bytes());
    let at: SocketAddr = "198.51.100.4:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let own = endpoint.connect_with(deaf_client(), point.addr(), "lookup").await_connected().await;
        assert!(outcomes(ask_point(&own, &announce_on(&own, &callees)).await).iter().all(String::is_empty));
        assert_eq!(point.point_status().unwrap().attending, 5);
        let asker = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let mut said = Vec::new();
        for (record, _) in &callees {
            let callee = ob::any_name(whereabouts::ship_of(record).unwrap());
            for _ in 0..runtime::lookup::MOST_WAITING_EACH {
                said.push(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await));
            }
        }
        // Sixteen wait (and one may be on its way); past that, each is refused for that reason.
        let taken = said.iter().filter(|why| why.is_empty()).count();
        assert!(taken == 16 || taken == 17, "{said:?}");
        assert!(said.last().unwrap().contains("waiting for that ship's connection"), "{said:?}");
    });
}

#[test]
fn a_point_that_says_nothing_of_an_introduction_does_not_stop_or_delay_the_call() {
    let (a, b) = (TempDir::new("silentintro-a"), TempDir::new("silentintro-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    *liar.introduce_after.lock().unwrap() = Duration::from_secs(60);
    let seed = [181u8; 32];
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    // Ten seconds for a call, as by default.
    let cfg = NetConfig { request_timeout: Duration::from_secs(10), ..with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) }) };
    let (_zod, zod_net, _) = ship_on(&a, "~zod", &urbit, cfg);
    eventually("~zod is announced", || !liar.records().is_empty());
    // ~nec's record asks to be introduced; the point never answers that request. The call
    // waits for it a second at most, tries ~nec anyway, and gets through.
    liar.say(Lie::Record(whereabouts::sign_flagged("~nec", &[nec_net.addr()], now_ms(), true, &SigningKey::from_bytes(&seed), None).unwrap()));
    let started = Instant::now();
    assert!(reaches(&zod_net, "~zod", "~nec"));
    assert!(started.elapsed() < Duration::from_millis(1800), "{:?}", started.elapsed());
    assert_eq!(liar.introductions.load(Ordering::SeqCst), 1);
}

#[test]
fn settings_for_staying_reachable_that_make_no_sense_are_refused() {
    let a = TempDir::new("keepalive-a");
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    let point: SocketAddr = "127.0.0.1:9".parse().unwrap();
    // A packet every twenty seconds keeps nothing open that is closed after ten idle.
    let cfg = NetConfig { idle_timeout: Duration::from_secs(10), lookup: Lookup { keep_alive: Duration::from_secs(20), ..finding(point) }, ..eager() };
    assert!(Network::start(rt.clone(), Directory::new(), cfg).is_err());
    for lookup in [
        Lookup { keep_alive: Duration::from_millis(500), ..finding(point) },
        Lookup { keep_alive: Duration::from_secs(26), ..finding(point) },
        Lookup { behind_router: true, ..Lookup::default() },
    ] {
        assert!(Network::start(rt.clone(), Directory::new(), with(lookup)).is_err());
    }
    assert!(Network::start(rt, Directory::new(), with(finding(point))).is_ok());
}

#[test]
fn an_announcement_with_more_presences_than_records_may_be_is_refused_unread() {
    let p = TempDir::new("manypresence-p");
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let request = announce_with(vec![vec![1]], vec![vec![2; 64]; 17]);
        assert!(refusal(ask_point(&connection, &request).await).contains("too many records"));
        assert_eq!(point.point_status().unwrap().rated, 0);
    });
}

#[test]
fn an_introductions_record_counts_against_the_record_rates_of_its_connection() {
    let p = TempDir::new("introrate-p");
    let urbit = Arc::new(Listings::default());
    // Two records an hour on any one connection; introductions themselves are plentiful.
    let bounds = PointBounds { per_connection: 2, introductions_each: 100, rate_period: Duration::from_secs(3600), ..PointBounds::default() };
    let (_pr, point) = point_on(&p, &urbit, None, bounds, "127.0.0.1:0");
    let (callee, callee_key) = (ob::ship_name(0x1234_0100), SigningKey::from_bytes(&[155; 32]));
    let (caller, caller_key) = (ob::ship_name(0x1235_0100), SigningKey::from_bytes(&[156; 32]));
    urbit.list(&callee, callee_key.verifying_key().to_bytes());
    urbit.list(&caller, caller_key.verifying_key().to_bytes());
    let at: SocketAddr = "198.51.100.4:4433".parse().unwrap();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let own = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let record = whereabouts::sign(&callee, &[at], now_ms(), &callee_key, None).unwrap();
        assert_eq!(outcomes(ask_point(&own, &announce_with(vec![record.clone()], vec![presence_on(&own, &record, &callee_key)])).await), [String::new()]);
        let asker = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        for _ in 0..2 {
            assert_eq!(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await), "");
        }
        assert_eq!(refusal(ask_point(&asker, &introduce_on(&asker, &callee, &caller, &caller_key, now_ms(), at)).await), "too many records on this connection just now; try again later");
    });
}

// Round two of phase 2.

#[test]
fn an_introduction_of_a_record_older_than_one_already_believed_sends_nothing() {
    let a = TempDir::new("introfloor-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let lookup = Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) };
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(lookup));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    let bus = SigningKey::from_bytes(&[164; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let here = watch.local_addr().unwrap();
    let (_quiet, nowhere) = silent();
    let now = now_ms();
    // ~nec looks ~bus up, the ordinary way, and believes R2 (whose address does not answer).
    liar.say(Lie::Record(whereabouts::sign("~bus", &[nowhere], now, &bus, None).unwrap()));
    assert!(nec_net.ping("~nec", "~bus").is_err());
    // The point then passes on ~bus's genuine R1, older than R2 and still good: nothing.
    let heard = nec_net.introductions().heard;
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now - 1000, &bus, None).unwrap()), false);
    // And R3, newer: three packets. (Weighed in order, so R1 was weighed first.)
    liar.push(introduction("~nec", whereabouts::sign("~bus", &[here], now + 1000, &bus, None).unwrap()), false);
    eventually("both are heard", || nec_net.introductions().heard >= heard + 2);
    assert_eq!(packets(&watch, Duration::from_millis(800)).len(), 3);
}

#[test]
fn a_strangers_introductions_are_metered_by_its_own_connection_before_the_point_looks() {
    let p = TempDir::new("intrometer-p");
    let urbit = Arc::new(Listings::default());
    let (_pr, point) = point_on(&p, &urbit, None, PointBounds::default(), "127.0.0.1:0");
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let stranger = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        let honest = endpoint.connect_with(where_client(), point.addr(), "lookup").await_connected().await;
        // Requests to introduce nobody to a ship that is not there, with nothing in them, as
        // fast as they can be sent: past its own allowance of questions, each is refused for
        // that, before the point looks at who attends.
        let request = introduce_with("~nec", Vec::new(), Vec::new());
        let mut said = Vec::new();
        let started = Instant::now();
        for _ in 0..150 {
            said.push(refusal(ask_point(&stranger, &request).await));
        }
        // At most 64 at a stroke and 64 a second earned back get as far as the table; the rest
        // were refused for that, however slowly the requests went.
        let metered = said.iter().filter(|why| why.contains("too many questions")).count();
        let took = started.elapsed();
        // Slower than this, too much is earned back for the count to mean anything.
        assert!(took < Duration::from_secs(1), "inconclusive: 150 requests took {took:?}");
        let let_through = 64.0 + 64.0 * took.as_secs_f64();
        assert!(150.0 - metered as f64 <= let_through.floor(), "{metered} metered in {:?}", started.elapsed());
        assert!(said.iter().all(|why| why.contains("too many questions") || why == "that ship is not attending this lookup point"), "{said:?}");
        // Another connection's question is answered as ever.
        assert!(ask_point(&honest, &question("~zod")).await.is_some_and(|reply| reply.body.is_some()));
    });
}

#[test]
fn a_ship_whose_record_is_taken_is_introduced_though_another_of_its_galaxy_is_refused() {
    let a = TempDir::new("partial-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    // The point refuses ~nec's record every time, and takes ~marnec's (both of ~nec's galaxy).
    liar.refuse.lock().unwrap().push(1);
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    for ship in ["~nec", "~marnec"] {
        rt.create_ship(ship, &kernel(&rt)).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    let net = Network::start(rt.clone(), Directory::reading(urbit.clone()), with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) })).unwrap();
    eventually("~marnec is recorded as announced, asking to be introduced", || net.announced_as("~marnec").is_some_and(|(_, introduce)| introduce));
    assert_eq!(net.announced_as("~nec"), None);
    // ~marnec is introduced: a caller's packets go out.
    let bus = SigningKey::from_bytes(&[165; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    liar.push(introduction("~marnec", whereabouts::sign("~bus", &[watch.local_addr().unwrap()], now_ms(), &bus, None).unwrap()), false);
    assert_eq!(packets(&watch, Duration::from_millis(800)).len(), 3);
    // And ~marnec, calling a ship that asks to be introduced, asks for it.
    let seed = [166u8; 32];
    urbit.list("~wes", SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    let (_quiet, nowhere) = silent();
    liar.say(Lie::Record(whereabouts::sign_flagged("~wes", &[nowhere], now_ms(), true, &SigningKey::from_bytes(&seed), None).unwrap()));
    assert!(net.ping("~marnec", "~wes").is_err());
    assert!(liar.introductions.load(Ordering::SeqCst) >= 1);
}

#[test]
fn a_point_that_writes_an_ipv4_address_as_ipv6_is_read_as_ipv4() {
    let a = TempDir::new("mapped-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let mut mapped = std::net::Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped().octets().to_vec();
    mapped.extend_from_slice(&4433u16.to_be_bytes());
    liar.see(SeenLie::Address(mapped));
    let (_zod, _zod_net, _) = ship_on(&a, "~zod", &urbit, with(finding(liar.addr)));
    eventually("~zod is announced", || !liar.records().is_empty());
    assert_eq!(liar.records().last().unwrap().addresses, vec![address_bytes("203.0.113.9:4433".parse().unwrap())]);
}

#[test]
fn introductions_are_weighed_only_so_many_a_second_and_not_at_all_for_a_ship_that_asked_for_none() {
    let a = TempDir::new("weighrate-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (_nec, nec_net, _) = ship_on(&a, "~nec", &urbit, with(finding(liar.addr)));
    eventually("~nec is announced, asking to be introduced", || liar.records().last().is_some_and(|record| record.introduce));
    let bus = SigningKey::from_bytes(&[167; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let record = whereabouts::sign("~bus", &[watch.local_addr().unwrap()], now_ms(), &bus, None).unwrap();
    // Two hundred introductions of one caller, as fast as they can be passed on: no more are
    // weighed than the allowance for weighing lets through, whole at the start.
    let started = Instant::now();
    for _ in 0..200 {
        liar.push(introduction("~nec", record.clone()), false);
    }
    let mut last = (nec_net.introductions().heard, Instant::now());
    while last.1.elapsed() < Duration::from_millis(300) {
        std::thread::sleep(Duration::from_millis(20));
        let now = nec_net.introductions().heard;
        if now != last.0 {
            last = (now, Instant::now());
        }
    }
    let took = (last.1 - started).as_secs_f64();
    let weighed = nec_net.introductions().weighed as f64;
    let most = f64::from(runtime::net::INTRODUCTIONS_WEIGHED) * (1.0 + took);
    assert!(weighed <= most, "{weighed} weighed in {took}s");
    assert!(nec_net.introductions().heard as f64 > most, "{:?}: not enough were heard to show the limit", nec_net.introductions());
    // ~nec stops asking for introductions. One of a ship nothing is known of costs no
    // question to Urbit ID at all, and nothing is weighed.
    liar.see(SeenLie::Truth);
    eventually("~nec is announced asking for none", || liar.records().last().is_some_and(|record| !record.introduce));
    std::thread::sleep(Duration::from_millis(1100));
    let wes = SigningKey::from_bytes(&[168; 32]);
    urbit.list("~wes", wes.verifying_key().to_bytes());
    let (asked, heard, weighed) = (urbit.2.load(Ordering::SeqCst), nec_net.introductions().heard, nec_net.introductions().weighed);
    liar.push(introduction("~nec", whereabouts::sign("~wes", &[watch.local_addr().unwrap()], now_ms(), &wes, None).unwrap()), false);
    eventually("it is heard", || nec_net.introductions().heard > heard);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(urbit.2.load(Ordering::SeqCst), asked, "Urbit ID was asked about a caller of a ship that asked for no introductions");
    assert_eq!(nec_net.introductions().weighed, weighed);
}

#[test]
fn an_address_set_by_hand_while_a_flagged_answer_is_held_means_no_introduction() {
    let (a, b) = (TempDir::new("holdintro-a"), TempDir::new("holdintro-b"));
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    let seed = [169u8; 32];
    let (_nec, nec_net, _) = keyed_ship_on(&b, "~nec", seed, &urbit, eager());
    let cfg = NetConfig { request_timeout: Duration::from_secs(10), ..with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) }) };
    let (_zod, zod_net, zod_dir) = ship_on(&a, "~zod", &urbit, cfg);
    eventually("~zod is announced", || !liar.records().is_empty());
    liar.say(Lie::Record(whereabouts::sign_flagged("~nec", &[nec_net.addr()], now_ms(), true, &SigningKey::from_bytes(&seed), None).unwrap()));
    // The point's answer, which asks for an introduction, is held. Meanwhile an address is
    // set by hand. Once the answer comes, no introduction is asked for.
    liar.hold.store(true, Ordering::SeqCst);
    let asked = liar.asked.load(Ordering::SeqCst);
    std::thread::scope(|scope| {
        let call = scope.spawn(|| zod_net.ping("~zod", "~nec"));
        eventually("the point is asked", || liar.asked.load(Ordering::SeqCst) > asked);
        zod_dir.place("~nec", nec_net.addr()).unwrap();
        liar.hold.store(false, Ordering::SeqCst);
        let _ = call.join().unwrap();
    });
    assert_eq!(liar.introductions.load(Ordering::SeqCst), 0, "an introduction was asked for after the address was set by hand");
}

// Round three of phase 2.

#[test]
fn an_introduced_moon_is_weighed_by_the_key_set_by_hand_for_it() {
    let dirs: Vec<TempDir> = (0..2).map(|n| TempDir::new(&format!("handmoon-{n}"))).collect();
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    let (planet_name, moon_name) = ("~sampel-palnet", "~doznec-sampel-palnet");
    let planet = Runtime::open(&dirs[0].0, fast()).unwrap();
    planet.create_ship(planet_name, &kernel(&planet)).unwrap();
    urbit.list(planet_name, planet.public_key(planet_name).unwrap());
    // The parent vouches for two keys of the moon's, at revisions one and two.
    let words = |keyfile: &str| {
        let read = runtime::urbit_id::Keyfile::parse(keyfile).unwrap();
        (SigningKey::from_bytes(&read.keys.auth), runtime::moon::Proof { revision: read.revision, signed: read.signed.unwrap() })
    };
    let (first_key, first_word) = words(&planet.moon_keyfile(planet_name, moon_name, 1).unwrap());
    let (second_key, second_word) = words(&planet.moon_keyfile(planet_name, moon_name, 2).unwrap());
    let (_nec, nec_net, nec_dir) = ship_on(&dirs[1], "~nec", &urbit, with(finding(liar.addr)));
    eventually("~nec is announced, asking to be introduced", || nec_net.announced_as("~nec").is_some_and(|(_, introduce)| introduce));
    // ~nec's directory has the moon's second key set by hand.
    nec_dir.set(moon_name, second_key.verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let here = watch.local_addr().unwrap();
    // Introduced under the first key, which its parent vouches for but is not the key set by
    // hand: refused, as an ordinary lookup refuses it; nothing is sent.
    let heard = nec_net.introductions().heard;
    liar.push(introduction("~nec", whereabouts::sign(moon_name, &[here], now_ms(), &first_key, Some(first_word)).unwrap()), false);
    // Introduced under the key set by hand, which its parent vouches for too: acted on, three
    // packets, as an ordinary lookup would believe it. (Weighed in order: the first, first.)
    liar.push(introduction("~nec", whereabouts::sign(moon_name, &[here], now_ms() + 1, &second_key, Some(second_word)).unwrap()), false);
    eventually("both are heard", || nec_net.introductions().heard >= heard + 2);
    assert_eq!(packets(&watch, Duration::from_millis(800)).len(), 3);
    // Nothing of either was kept: the key set by hand is still the one held.
    assert_eq!(nec_dir.key_of(moon_name), Some(second_key.verifying_key().to_bytes()));
}

#[test]
fn what_an_earlier_chunk_of_a_round_achieved_survives_a_later_chunks_failure() {
    let a = TempDir::new("chunks-a");
    let urbit = Arc::new(Listings::default());
    let liar = liar();
    liar.see(SeenLie::Address(address_bytes("127.0.0.1:9".parse().unwrap())));
    // Seventeen stars of ~nec's galaxy on one runtime: two chunks, sixteen and one.
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    let kernel = kernel(&rt);
    let mut ships: Vec<String> = (1..=17u32).map(|k| ob::ship_name(k << 8 | 1)).collect();
    for ship in &ships {
        rt.create_ship(ship, &kernel).unwrap();
        urbit.list(ship, rt.public_key(ship).unwrap());
    }
    ships.sort();
    let first = ships[0].clone();
    let net = Network::start(rt.clone(), Directory::reading(urbit.clone()), with(Lookup { ask_again: Duration::from_millis(100), ..finding(liar.addr) })).unwrap();
    eventually("every ship is recorded as asking to be introduced", || ships.iter().all(|ship| net.announced_as(ship).is_some_and(|(_, introduce)| introduce)));
    // The point answers the second chunk of each round with rubbish; and then sees the
    // runtime where it listens, so its records ask for no introduction. (In that order, so
    // that no whole round asking for none gets through in between.)
    liar.garble_short.store(true, Ordering::SeqCst);
    liar.see(SeenLie::Truth);
    eventually("the first chunk's ship is recorded as asking for none", || net.announced_as(&first).is_some_and(|(_, introduce)| !introduce));
    // (Each garbled round closes the connection; so that an introduction has one to come on,
    // the point stops garbling, and a whole round goes through.)
    liar.garble_short.store(false, Ordering::SeqCst);
    eventually("a whole round goes through", || ships.iter().all(|ship| net.announced_as(ship).is_some_and(|(_, introduce)| !introduce)));
    // An introduction to the first chunk's ship sends nothing.
    let bus = SigningKey::from_bytes(&[170; 32]);
    urbit.list("~bus", bus.verifying_key().to_bytes());
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let heard = net.introductions().heard;
    liar.push(introduction(&first, whereabouts::sign("~bus", &[watch.local_addr().unwrap()], now_ms(), &bus, None).unwrap()), false);
    eventually("it is heard", || net.introductions().heard > heard);
    assert!(packets(&watch, Duration::from_millis(800)).is_empty());
}
