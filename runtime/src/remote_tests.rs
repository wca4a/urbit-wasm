//! Files on the ship, part 2: another ship fetches a file. Real runtimes on this machine, each
//! with its network, the fetching one with its HTTP server, and keys set by hand.
//!
//! Inside the crate, because the ship answering can be made to lie through a door only the
//! crate's own code can use (`Shared::liar`): a reply put in place of the true one, a reply
//! held back, a stream cut off. And because a kernel that does not know the kind of call can
//! be stood for (`Inner::file_ask_kind`), and remembered answers made old at will.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ship_proto::{peer_reply, peer_request, FileBytes, FileFacts, FileWanted, Message, PeerReply, PeerRequest, Pong};

use super::{Directory, FileAskError, Lie, NetConfig, NetError, Network, TOO_BUSY};
use crate::files::{self, id_of, Part, Served, CHUNK};
use crate::server::{Server, ServerConfig};
use crate::{lock, Config, Durability, Manifest, Provide, Runtime, Use};

fn wasm(name: &str) -> Vec<u8> {
    super::router_tests::wasm(name)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-remote-{label}", std::process::id()));
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

fn open_counter() -> Manifest {
    Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true }], uses: vec![] }
}

fn following_tally(ship: &str) -> Manifest {
    let counter = Use { ship: ship.into(), agent: "counter".into(), interface: "counter".into(), read: true, send: true };
    let tally = Use { ship: ship.into(), agent: "tally".into(), interface: "tally".into(), read: false, send: true };
    Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true }], uses: vec![counter, tally] }
}

/// A runtime with `ships`, each with `counter` (open to other ships, and asked about files),
/// `keeper` (the same module under another name) and `tally` (no file_ask handler) following
/// the counter on `other`.
fn crewed(dir: &TempDir, cfg: Config, ships: &[&str], other: &str) -> Arc<Runtime> {
    let rt = Arc::new(Runtime::open(&dir.0, cfg).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let (counter, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    for ship in ships {
        rt.create_ship(ship, &kernel).unwrap();
        rt.install(ship, "counter", &counter, &open_counter()).unwrap();
        rt.install(ship, "keeper", &counter, &Manifest::default()).unwrap();
        rt.install(ship, "tally", &tally, &following_tally(other.trim_start_matches('~'))).unwrap();
    }
    rt
}

/// Run a command on an agent and return its answer as text.
fn say(rt: &Runtime, ship: &str, agent: &str, command: &str) -> String {
    String::from_utf8(rt.deliver(ship, agent, command.as_bytes()).unwrap().reply).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Contents that differ in every chunk.
fn contents(length: usize, seed: u8) -> Vec<u8> {
    (0..length).map(|i| (i as u64).wrapping_mul(2654435761).wrapping_add(seed as u64 * 97) as u8 ^ (i >> 20) as u8).collect()
}

/// Put a file on a ship under an agent, through the runtime, and return its id.
fn put(rt: &Runtime, ship: &str, agent: &str, data: &[u8], media_type: &str) -> [u8; 32] {
    let (upload, chunks) = rt.upload_start(ship, agent, data.len() as u64, media_type).unwrap();
    for n in 0..chunks {
        let chunk = data[(n * CHUNK) as usize..((n + 1) * CHUNK).min(data.len() as u64) as usize].to_vec();
        rt.upload_chunk(ship, agent, &upload, n, chunk).unwrap();
    }
    let info = rt.upload_finish(ship, agent, &upload, None).unwrap();
    assert_eq!(info.id, id_of(data));
    info.id
}

/// Make every answer the ship's agents gave about files as old as if `by` had passed, and end
/// every ship's rest from asking (a test that wants a fresh question asks it now).
fn age(rt: &Runtime, by: Duration) {
    lock(&rt.inner.file_answers).age(by);
    unrest(rt);
}

/// End every ship's rest from asking, so the next question is asked, not refused for the rest.
fn unrest(rt: &Runtime) {
    lock(&rt.inner.ask_rest).clear();
}

/// Never given up on, for calls made straight to `Runtime::serve_file`.
static WAITING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Two runtimes: ~zod, holding files, and ~nec, with an HTTP server and a signed-in device.
struct Two {
    a: Arc<Runtime>,
    a_net: Network,
    b: Arc<Runtime>,
    b_net: Network,
    server: Server,
    auth: String,
    directory: Arc<Directory>,
    _dirs: (TempDir, TempDir),
}

fn two(label: &str) -> Two {
    two_with(label, (fast(), NetConfig::default()), (fast(), NetConfig::default()), &["~nec"])
}

/// As `two`, with keeping off on ~nec (`max_cache_bytes` 0): opening another ship's file is
/// then exactly as part 2 made it. For the tests of part 2 whose point is that ~nec keeps
/// nothing and asks ~zod every time; part 3's own tests show what changes with keeping on.
fn two_uncached(label: &str) -> Two {
    two_with(label, (fast(), NetConfig::default()), (Config { max_cache_bytes: 0, ..fast() }, NetConfig::default()), &["~nec"])
}

/// Network deadlines longer than any test's own watchdog (their waits add up to at most about two minutes), for tests
/// that hold requests at the other ship (`Lie::Held`) while they assert what else is answered:
/// the held requests cannot run out of time and give their places back meanwhile.
fn held_net() -> NetConfig {
    NetConfig { file_timeout: Duration::from_secs(300), request_timeout: Duration::from_secs(300), ..NetConfig::default() }
}

fn two_with(label: &str, (a_cfg, a_net_cfg): (Config, NetConfig), (b_cfg, b_net_cfg): (Config, NetConfig), b_ships: &[&str]) -> Two {
    let dirs = (TempDir::new(&format!("{label}-a")), TempDir::new(&format!("{label}-b")));
    let directory = Directory::new();
    let a = crewed(&dirs.0, a_cfg, &["~zod"], "~nec");
    let a_net = Network::start(a.clone(), directory.clone(), a_net_cfg).unwrap();
    directory.set("~zod", a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    let b = crewed(&dirs.1, b_cfg, b_ships, "~zod");
    let b_net = Network::start(b.clone(), directory.clone(), b_net_cfg).unwrap();
    for ship in b_ships {
        directory.set(ship, b.public_key(ship).unwrap(), b_net.addr()).unwrap();
    }
    let server = Server::start(b.clone(), ServerConfig::default()).unwrap();
    let code = b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", b.sign_in("~nec", &code, "test").unwrap().0);
    Two { a, a_net, b, b_net, server, auth, directory, _dirs: dirs }
}

impl Two {
    /// The path, on ~nec's server, of a file on ~zod under `agent`, with `rest` after it.
    fn path(&self, agent: &str, id: &[u8; 32], rest: &str) -> String {
        format!("/ships/nec/files/from/zod/{agent}/{}{rest}", hex(id))
    }

    fn get(&self, path: &str, headers: &[(&str, &str)]) -> Answer {
        let mut all = vec![("Authorization", self.auth.as_str())];
        all.extend_from_slice(headers);
        http(&self.server, path, &all)
    }

    /// Have ~zod's network answer for files as `liar` says.
    fn lie(&self, liar: impl Fn(&peer_request::Body, &PeerReply) -> Option<Lie> + Send + Sync + 'static) {
        *lock(&self.a_net.shared.liar) = Some(Arc::new(liar));
    }

    fn honest(&self) {
        *lock(&self.a_net.shared.liar) = None;
    }
}

struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn http(server: &Server, path: &str, headers: &[(&str, &str)]) -> Answer {
    request(server, "GET", path, headers, b"")
}

fn request(server: &Server, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Answer {
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.0\r\nHost: {}\r\n", server.addr());
    for (name, value) in headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let top = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = top.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines.filter_map(|line| line.split_once(": ")).map(|(name, value)| (name.to_string(), value.to_string())).collect();
    Answer { status, headers, body: raw[split + 4..].to_vec() }
}

/// What every file answer carries, so that it cannot act as a page.
fn kept_from_acting(answer: &Answer) {
    assert_eq!(answer.header("X-Content-Type-Options"), Some("nosniff"), "{}", answer.status);
    assert_eq!(answer.header("Content-Security-Policy"), Some("sandbox; default-src 'none'"), "{}", answer.status);
    assert!(matches!(answer.header("Content-Disposition"), Some("attachment" | "inline")), "{}", answer.status);
}

/// What ~nec's device is told of every refusal from ~zod: ~nec's own words.
const NOT_SHARED: &str = "the other ship does not share that file with this one";

/// What ~zod says on the wire to every refusal of ~nec.
const ZOD_SAYS_NO: &str = "~zod does not share that file with ~nec";

/// The parts of a file asked for through `Runtime::serve_file`.
fn about(rt: &Runtime, agent: &str, id: &[u8; 32]) -> Served {
    rt.serve_file("~zod", "~nec", agent, id, Part::About, &WAITING).unwrap()
}

/// The four requests for parts of a file.
fn every_part(agent: &str, id: &[u8; 32]) -> [peer_request::Body; 4] {
    let wanted = || FileWanted { agent: agent.into(), id: id.to_vec(), index: 0 };
    [
        peer_request::Body::FileAbout(wanted()),
        peer_request::Body::FileLeaves(wanted()),
        peer_request::Body::FileUpper(wanted()),
        peer_request::Body::FileChunk(wanted()),
    ]
}

/// Every file of a size that matters is had whole, by range, by chunk, and as what it is; and
/// what is passed on is exactly the file. (G1, G5)
#[test]
fn another_ships_file_is_had_whole_by_range_and_by_chunk() {
    let t = two("whole");
    let sizes = [0, 1, CHUNK as usize, CHUNK as usize + 1, 3 * CHUNK as usize + 5];
    for (i, size) in sizes.into_iter().enumerate() {
        let data = contents(size, i as u8);
        let media_type = if i == 2 { "image/png" } else { "" };
        let id = put(&t.a, "~zod", "counter", &data, media_type);
        assert_eq!(say(&t.a, "~zod", "counter", &format!("open {}", hex(&id))), "true");
        // What it is.
        let info = t.get(&t.path("counter", &id, ""), &[]);
        assert_eq!(info.status, 200, "{size}: {}", info.text());
        kept_from_acting(&info);
        let info = ship_proto::FileInfo::decode(&*info.body).unwrap();
        let expected = if i == 2 { "image/png" } else { "application/octet-stream" };
        assert_eq!((info.length, info.chunks, info.media_type.as_str()), (size as u64, files::chunk_count(size as u64), expected));
        // Whole.
        let whole = t.get(&t.path("counter", &id, "/content"), &[]);
        assert_eq!(whole.status, 200, "{size}");
        assert!(whole.body == data, "{size}: the contents differ");
        kept_from_acting(&whole);
        assert_eq!(whole.header("Content-Type"), Some(expected));
        assert_eq!(whole.header("Content-Disposition"), Some(if i == 2 { "inline" } else { "attachment" }));
        assert_eq!(whole.header("Accept-Ranges"), Some("bytes"));
        assert_eq!(whole.header("Content-Length"), Some(size.to_string().as_str()));
        // A range across a chunk boundary, where there is one.
        if size > 10 {
            let (from, to) = (5usize, (CHUNK as usize + 9).min(size - 1));
            let part = t.get(&t.path("counter", &id, "/content"), &[("Range", &format!("bytes={from}-{to}"))]);
            assert_eq!(part.status, 206, "{size}");
            assert!(part.body == data[from..=to], "{size}: the range differs");
            assert_eq!(part.header("Content-Range"), Some(format!("bytes {from}-{to}/{size}").as_str()));
            let suffix = t.get(&t.path("counter", &id, "/content"), &[("Range", "bytes=-3")]);
            assert!(suffix.status == 206 && suffix.body == data[size - 3..], "{size}");
        }
        let past = t.get(&t.path("counter", &id, "/content"), &[("Range", &format!("bytes={size}-"))]);
        assert_eq!((past.status, past.header("Content-Range")), (416, Some(format!("bytes */{size}").as_str())), "{size}");
        // Each chunk, and none past the last.
        let chunks = files::chunk_count(size as u64);
        for n in 0..chunks {
            let chunk = t.get(&t.path("counter", &id, &format!("/chunks/{n}")), &[]);
            assert_eq!(chunk.status, 200, "{size} {n}");
            assert!(chunk.body == data[(n * CHUNK) as usize..((n + 1) * CHUNK).min(size as u64) as usize], "{size} {n}");
            assert_eq!((chunk.header("Content-Type"), chunk.header("Content-Disposition")), (Some("application/octet-stream"), Some("attachment")));
            kept_from_acting(&chunk);
        }
        assert_eq!(t.get(&t.path("counter", &id, &format!("/chunks/{chunks}")), &[]).status, 404, "{size}");
    }
}

/// A file closed and not let answers exactly as a file that does not exist, an agent that does
/// not exist, an agent that does not claim it, an agent with no handler, a handler that fails,
/// a kernel that does not know the question, an open claim by an agent not installed, a row
/// that cannot be read, and a ship resting from asking; on the wire every refusal is the same
/// bytes for each of the four parts, and the device is told the same sentence of ~nec's own.
/// (G4)
#[test]
fn every_no_is_the_same_whatever_its_reason() {
    let t = two("same-no");
    let closed = put(&t.a, "~zod", "counter", &contents(100, 1), "");
    let tallys = put(&t.a, "~zod", "tally", &contents(100, 2), "");
    let failing = put(&t.a, "~zod", "keeper", &contents(100, 3), "");
    let refused_by_kernel = put(&t.a, "~zod", "counter", &contents(100, 4), "");
    let ghostly = put(&t.a, "~zod", "counter", &contents(100, 5), "");
    let damaged = put(&t.a, "~zod", "counter", &contents(100, 6), "");
    let while_resting = put(&t.a, "~zod", "counter", &contents(100, 7), "");
    let put_row = |sql: &str, id: &[u8; 32]| {
        t.a.inner.with_ship("~zod", |held| Ok(lock(&held.conn).execute(sql, [&id[..]])?)).unwrap();
    };
    // Each reason: a name, how to set it up, and the agent and file asked about.
    type Setup<'a> = Box<dyn Fn() + 'a>;
    let none: Setup = Box::new(|| {});
    let reasons: Vec<(&str, Setup, &str, [u8; 32])> = vec![
        // An agent that would say yes, of a file it does not claim.
        ("not claimed by that agent", Box::new(|| drop(say(&t.a, "~zod", "keeper", &format!("let nec {}", hex(&closed))))), "keeper", closed),
        ("closed and not let", Box::new(|| {}), "counter", closed),
        ("no such file", Box::new(|| {}), "counter", [7; 32]),
        ("no such agent", Box::new(|| {}), "nobody", closed),
        ("no handler", Box::new(|| {}), "tally", tallys),
        (
            "a handler that fails",
            Box::new(|| {
                say(&t.a, "~zod", "keeper", "asks trap");
                say(&t.a, "~zod", "keeper", &format!("let nec {}", hex(&failing)));
            }),
            "keeper",
            failing,
        ),
        ("the kernel's own agent", Box::new(|| {}), "kernel", closed),
        (
            "a kernel that does not know the question",
            Box::new(|| {
                say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&refused_by_kernel)));
                t.a.inner.file_ask_kind.store(99, Ordering::SeqCst);
            }),
            "counter",
            refused_by_kernel,
        ),
        // A claim by an agent that is not installed (as an imported copy can hold), marked
        // open: the agent is not installed, so no.
        ("an open claim by an agent not installed", Box::new(|| put_row("INSERT INTO file_claims VALUES ('ghost', ?1, 1)", &ghostly)), "ghost", ghostly),
        // A row that cannot be read while deciding (a damaged directory name).
        (
            "a row that cannot be read",
            Box::new(|| {
                say(&t.a, "~zod", "counter", &format!("open {}", hex(&damaged)));
                put_row("UPDATE files SET dir = x'00' WHERE id = ?1", &damaged);
            }),
            "counter",
            damaged,
        ),
        // A ship resting from asking: the agent would say yes, and is not asked.
        (
            "a ship resting from asking",
            Box::new(|| {
                say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&while_resting)));
                lock(&t.a.inner.ask_rest).insert("zod".into(), Instant::now() + Duration::from_secs(60));
            }),
            "counter",
            while_resting,
        ),
    ];
    let _ = none;
    let mut wire: Vec<Vec<Vec<u8>>> = vec![Vec::new(); 4];
    for (why, setup, agent, id) in &reasons {
        unrest(&t.a);
        setup();
        for (kind, body) in every_part(agent, id).into_iter().enumerate() {
            let reply = t.b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(body) }).unwrap().unwrap();
            wire[kind].push(reply.encode_to_vec());
        }
        for rest in ["", "/content", "/chunks/0"] {
            let answer = t.get(&t.path(agent, id, rest), &[]);
            assert_eq!((answer.status, answer.text().as_str()), (404, NOT_SHARED), "{why}, {rest:?}");
            kept_from_acting(&answer);
        }
        t.a.inner.file_ask_kind.store(0, Ordering::SeqCst);
        assert_eq!(about(&t.a, agent, id), Served::Denied, "{why}");
    }
    // Byte for byte, for each part, whatever the reason; and the denied words are ~zod's.
    for (kind, replies) in wire.iter().enumerate() {
        assert_eq!(replies.len(), reasons.len());
        assert!(replies.iter().all(|reply| reply == &replies[0]), "part {kind}: refusals differ on the wire");
        assert!(String::from_utf8_lossy(&replies[0]).contains(ZOD_SAYS_NO), "part {kind}");
    }
    // A no for the rest is not remembered: rested, the agent is asked, and says yes.
    unrest(&t.a);
    assert_eq!(t.get(&t.path("counter", &while_resting, ""), &[]).status, 200);
    // On the wire only (the device's server refuses such names before asking): an agent name
    // that is not one, and an id of the wrong length. And a ship whose runtime keeps no files.
    let asked = |b: &Runtime, agent: &str, id: &[u8]| -> Vec<Vec<u8>> {
        (0..4)
            .map(|kind| {
                let wanted = FileWanted { agent: agent.into(), id: id.to_vec(), index: 0 };
                let body = match kind {
                    0 => peer_request::Body::FileAbout(wanted),
                    1 => peer_request::Body::FileLeaves(wanted),
                    2 => peer_request::Body::FileUpper(wanted),
                    _ => peer_request::Body::FileChunk(wanted),
                };
                b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(body) }).unwrap().unwrap().encode_to_vec()
            })
            .collect()
    };
    unrest(&t.a);
    let off = two_with("same-no-wire-off", (Config { max_file_bytes: 0, ..fast() }, NetConfig::default()), (fast(), NetConfig::default()), &["~nec"]);
    for (why, replies) in [
        ("an agent name that is not one", asked(&t.b, "Not An Agent", &closed)),
        ("an id of the wrong length", asked(&t.b, "counter", &closed[..31])),
        ("an id of no length", asked(&t.b, "counter", &[])),
        ("a ship whose runtime keeps no files", asked(&off.b, "counter", &closed)),
    ] {
        for (kind, reply) in replies.iter().enumerate() {
            assert!(reply == &wire[kind][0], "{why}, part {kind}: differs on the wire");
        }
    }
    drop(off);
    // A remembered yes is still honoured while the ship rests.
    let remembered = put(&t.a, "~zod", "counter", &contents(100, 8), "");
    unrest(&t.a);
    say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&remembered)));
    assert_eq!(t.get(&t.path("counter", &remembered, ""), &[]).status, 200);
    lock(&t.a.inner.ask_rest).insert("zod".into(), Instant::now() + Duration::from_secs(60));
    assert_eq!(t.get(&t.path("counter", &remembered, "/content"), &[]).status, 200);
    // And from a ship whose runtime keeps no files at all.
    let off = TempDir::new("same-no-off");
    let rt = crewed(&off, Config { max_file_bytes: 0, ..fast() }, &["~zod"], "~nec");
    assert_eq!(about(&rt, "counter", &closed), Served::Denied);
}

/// Asking is read-only and has its own budget, and every way it can fail is a no: a trap, out
/// of fuel, out of time, a reply that does not decode, one over 64 bytes, no handler at all, a
/// kernel that does not know the question. Nothing it tried to change is kept, and asking
/// writes no row. (G3)
#[test]
fn asking_changes_nothing_and_every_failure_is_no() {
    let dir = TempDir::new("asking");
    let rt = crewed(&dir, fast(), &["~zod"], "~nec");
    let rows = || rows(&rt, "~zod");
    // Hand-written agents that answer with fixed bytes.
    let answering = |bytes: &[u8]| {
        let escaped: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        let packed = (16u64 << 32) | bytes.len() as u64;
        wat::parse_str(format!(
            r#"(module (memory (export "memory") 1) (data (i32.const 16) "{escaped}")
               (func (export "alloc") (param i32) (result i32) (i32.const 4096))
               (func (export "handle") (param i32 i32) (result i64) (i64.const 0))
               (func (export "file_ask") (param i32 i32) (result i64) (i64.const {packed})))"#
        ))
        .unwrap()
    };
    let padded = [&[0x08u8, 0x01, 0x1a, 100][..], &[b'x'; 100][..]].concat();
    for (agent, bytes) in [("yes", vec![0x08u8, 0x01]), ("garbage", vec![0xff, 0xff, 0xff]), ("padded", padded)] {
        let module = rt.add_module(&answering(&bytes)).unwrap();
        rt.install("~zod", agent, &module, &Manifest::default()).unwrap();
    }
    let file = |agent: &str, seed: u8| put(&rt, "~zod", agent, &contents(10, seed), "");
    // A hand-written yes is a yes: the bytes it answers are taken as they are.
    assert!(matches!(about(&rt, "yes", &file("yes", 1)), Served::About { length: 10, .. }));
    let before = rows();
    // The same yes, padded past 64 bytes, is no; as is something that is not an answer. (Each
    // question is asked, not refused for the ship's rest after the one before.)
    unrest(&rt);
    assert_eq!(about(&rt, "padded", &file("padded", 2)), Served::Denied);
    unrest(&rt);
    assert_eq!(about(&rt, "garbage", &file("garbage", 3)), Served::Denied);
    // No handler at all.
    unrest(&rt);
    assert_eq!(about(&rt, "tally", &file("tally", 4)), Served::Denied);
    // A handler that is let say yes, but fails, runs out of fuel, or tries to change something.
    for (mode, seed) in [("trap", 5), ("spin", 6), ("meddle", 7), ("mark", 10)] {
        let id = file("counter", seed);
        say(&rt, "~zod", "counter", &format!("let nec {}", hex(&id)));
        say(&rt, "~zod", "counter", &format!("asks {mode}"));
        unrest(&rt);
        let asked = lock(&rt.inner.asked).len();
        let started = Instant::now();
        assert_eq!(about(&rt, "counter", &id), Served::Denied, "{mode}");
        assert!(started.elapsed() < Duration::from_secs(2), "{mode} took {:?}", started.elapsed());
        assert_eq!(lock(&rt.inner.asked).len(), asked + 1, "{mode}: the agent was not asked");
        say(&rt, "~zod", "counter", "asks behave");
        age(&rt, Duration::from_secs(60));
        assert!(matches!(about(&rt, "counter", &id), Served::About { .. }), "{mode}: the same question, behaving");
    }
    assert_eq!(say(&rt, "~zod", "counter", "get meddled"), "0", "a change made while asking was kept");
    assert!(!rt.file_info("~zod", "counter", &id_of(&contents(10, 10))).unwrap().open, "a mark made while asking was kept");
    // A kernel that does not know the question: no, though the agent would say yes; and an
    // open file is still had, since the agent is not asked.
    let let_in = file("counter", 8);
    say(&rt, "~zod", "counter", &format!("let nec {}", hex(&let_in)));
    let opened = file("counter", 9);
    say(&rt, "~zod", "counter", &format!("open {}", hex(&opened)));
    rt.inner.file_ask_kind.store(99, Ordering::SeqCst);
    unrest(&rt);
    assert_eq!(about(&rt, "counter", &let_in), Served::Denied);
    assert!(matches!(about(&rt, "counter", &opened), Served::About { .. }));
    rt.inner.file_ask_kind.store(0, Ordering::SeqCst);
    // Asking, refused or not, wrote no row: the rows that differ are those the commands made.
    let after = rows();
    for (table, count) in &before {
        if !["kv", "audit", "sqlite_sequence", "files", "file_claims", "file_chunks", "file_trash", "uploads"].contains(&table.as_str()) {
            assert_eq!(after.get(table), Some(count), "{table}");
        }
    }

    // Out of time: a budget of fuel that would last for ever, and 300 ms.
    let slow_dir = TempDir::new("asking-slow");
    let slow = crewed(&slow_dir, Config { file_ask_fuel: 1 << 50, file_ask_millis: 300, ..fast() }, &["~zod"], "~nec");
    let id = put(&slow, "~zod", "counter", &contents(10, 1), "");
    say(&slow, "~zod", "counter", &format!("let nec {}", hex(&id)));
    say(&slow, "~zod", "counter", "asks spin");
    unrest(&slow);
    let started = Instant::now();
    assert_eq!(about(&slow, "counter", &id), Served::Denied);
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(300) && took < Duration::from_secs(3), "took {took:?}");
}

/// Every table's row count on a ship.
fn rows(rt: &Runtime, ship: &str) -> BTreeMap<String, i64> {
    rt.inner
        .with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let mut counts = BTreeMap::new();
            for table in tables {
                counts.insert(table.clone(), conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| r.get(0))?);
            }
            Ok(counts)
        })
        .unwrap()
}

/// Let, then not let: refused once the remembered yes has run out (30 s). Open, then closed:
/// refused on the very next request. A claim taken back, or the agent's module replaced: refused
/// at once, whatever was remembered. (G2, G10)
#[test]
fn a_file_is_had_only_while_its_agent_allows_it() {
    let t = two_uncached("allowed");
    let id = put(&t.a, "~zod", "counter", &contents(2 * CHUNK as usize, 1), "");
    let status = || t.get(&t.path("counter", &id, ""), &[]).status;
    assert_eq!(status(), 404);
    say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&id)));
    // The no is remembered for 5 s.
    assert_eq!(status(), 404);
    age(&t.a, Duration::from_secs(5));
    assert_eq!(status(), 200);
    say(&t.a, "~zod", "counter", &format!("unlet nec {}", hex(&id)));
    // The yes is remembered for 30 s, and no longer.
    assert_eq!(status(), 200);
    age(&t.a, Duration::from_secs(29));
    assert_eq!(status(), 200);
    age(&t.a, Duration::from_secs(1));
    assert_eq!(status(), 404);

    // Open and closed: the mark is read afresh for every request.
    let marked = put(&t.a, "~zod", "counter", &contents(10, 2), "");
    let marked_status = || t.get(&t.path("counter", &marked, "/content"), &[]).status;
    assert_eq!(say(&t.a, "~zod", "counter", &format!("open {}", hex(&marked))), "true");
    assert_eq!(marked_status(), 200);
    assert_eq!(say(&t.a, "~zod", "counter", &format!("file {}", hex(&marked))), "10 1 application/octet-stream open");
    assert_eq!(say(&t.a, "~zod", "counter", &format!("close {}", hex(&marked))), "true");
    assert_eq!(marked_status(), 404);
    // Marking a file the agent does not claim changes nothing and fails nothing.
    assert_eq!(say(&t.a, "~zod", "keeper", &format!("open {}", hex(&marked))), "false");
    assert_eq!(t.get(&t.path("keeper", &marked, ""), &[]).status, 404);
    // The owner sees the mark.
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&marked)));
    assert!(t.a.file_info("~zod", "counter", &marked).unwrap().open);

    // A claim taken back, though a yes is remembered.
    let taken = put(&t.a, "~zod", "counter", &contents(10, 3), "");
    say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&taken)));
    unrest(&t.a);
    assert_eq!(t.get(&t.path("counter", &taken, ""), &[]).status, 200);
    t.a.file_delete("~zod", "counter", &taken).unwrap();
    assert_eq!(t.get(&t.path("counter", &taken, ""), &[]).status, 404);
    // Put back, the same bytes under the same id, and still let: it is another file here, and
    // the agent is asked again (and, its let gone, says no).
    say(&t.a, "~zod", "counter", &format!("unlet nec {}", hex(&taken)));
    assert_eq!(put(&t.a, "~zod", "counter", &contents(10, 3), ""), taken);
    assert_eq!(t.get(&t.path("counter", &taken, ""), &[]).status, 404);

    // The agent's module replaced, though a yes is remembered: the answer was the old
    // module's, and is never found for the new one.
    let replaced = put(&t.a, "~zod", "counter", &contents(10, 4), "");
    say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&replaced)));
    unrest(&t.a);
    assert_eq!(t.get(&t.path("counter", &replaced, ""), &[]).status, 200);
    let tally = t.a.add_module(&wasm("tally")).unwrap();
    t.a.install("~zod", "counter", &tally, &open_counter()).unwrap();
    assert_eq!(t.get(&t.path("counter", &replaced, ""), &[]).status, 404);
}

/// The same bytes claimed by two agents: open under one, which says nothing of the other.
#[test]
fn a_file_open_under_one_agent_is_not_open_under_another() {
    let t = two_uncached("agents");
    let data = contents(CHUNK as usize + 3, 5);
    let id = put(&t.a, "~zod", "counter", &data, "");
    assert_eq!(put(&t.a, "~zod", "keeper", &data, ""), id);
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    let other = t.get(&t.path("keeper", &id, "/content"), &[]);
    assert_eq!((other.status, other.text().as_str()), (404, NOT_SHARED));
}

/// A ship that lies is caught: in what it says the file is, in its hashes, their number, the
/// kind of its reply, and its chunks' bytes and lengths. Before anything is sent where it can
/// be; part way, by ending short, where it cannot. Media types it gives go through the check
/// made at upload. (G1, G5)
#[test]
fn a_ship_that_lies_is_caught_before_anything_wrong_is_passed_on() {
    let t = two_uncached("lies");
    let data = contents(3 * CHUNK as usize + 5, 6);
    let id = put(&t.a, "~zod", "counter", &data, "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    let info = || t.get(&t.path("counter", &id, ""), &[]);
    let content = || t.get(&t.path("counter", &id, "/content"), &[]);
    let chunk = |n: u64| t.get(&t.path("counter", &id, &format!("/chunks/{n}")), &[]);
    let changed = |change: fn(&mut PeerReply)| {
        move |_: &peer_request::Body, honest: &PeerReply| {
            let mut reply = honest.clone();
            change(&mut reply);
            Some(Lie::Reply(reply))
        }
    };
    // Lies about chunk 1.
    let chunk_lies: [(&str, fn(&mut Vec<u8>)); 3] = [
        ("wrong bytes", |data| data[7] ^= 1),
        ("short", |data| {
            data.pop();
        }),
        ("long", |data| data.push(0)),
    ];
    for (what, change) in chunk_lies {
        t.lie(move |asked, honest| {
            let mut reply = honest.clone();
            match (asked, &mut reply.body) {
                (peer_request::Body::FileChunk(FileWanted { index: 1, .. }), Some(peer_reply::Body::FileChunk(sent))) => change(&mut sent.data),
                _ => return None,
            }
            Some(Lie::Reply(reply))
        });
        let one = chunk(1);
        assert_eq!(one.status, 502, "{what}: {}", one.text());
        assert!(chunk(0).status == 200 && chunk(2).status == 200, "{what}");
        // The whole file: told its true length, then ended short, after the chunk before.
        let whole = content();
        assert_eq!(whole.status, 200, "{what}");
        assert_eq!(whole.header("Content-Length"), Some(data.len().to_string().as_str()));
        assert!(whole.body == data[..CHUNK as usize], "{what}: {} bytes passed on", whole.body.len());
    }
    // Lies about the length and the hashes: caught before a number or a byte goes out.
    let lies: [(&str, fn(&mut PeerReply)); 8] = [
        ("length nought", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length = 0;
            }
        }),
        ("length", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length += 1;
            }
        }),
        ("length short", |reply| {
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.length -= 1;
            }
        }),
        ("a hash", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes[40] ^= 1;
            }
        }),
        ("a hash too few", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.truncate(sent.hashes.len() - 32);
            }
        }),
        ("a hash too many", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.extend_from_slice(&[9; 32]);
            }
        }),
        ("hashes not whole", |reply| {
            if let Some(peer_reply::Body::FileLeaves(sent)) = &mut reply.body {
                sent.hashes.push(1);
            }
        }),
        ("hashes in place of what the file is", |reply| {
            if matches!(reply.body, Some(peer_reply::Body::FileAbout(_))) {
                reply.body = Some(peer_reply::Body::FileLeaves(ship_proto::FileHashes::default()));
            }
        }),
    ];
    for (what, change) in lies {
        t.lie(changed(change));
        for (route, answer) in [("info", info()), ("content", content()), ("chunk", chunk(0))] {
            assert_eq!(answer.status, 502, "{what}, {route}: {}", answer.text());
            assert!(answer.header("Content-Length").map_or(true, |length| length == answer.body.len().to_string()), "{what}");
            assert!(answer.header("Content-Range").is_none(), "{what}");
            kept_from_acting(&answer);
        }
    }
    // A reply of another kind altogether, and a refusal of the request.
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::Pong(Pong::default())), refused: String::new() })));
    assert_eq!(info().status, 502);
    t.lie(|asked, honest| match asked {
        peer_request::Body::FileChunk(_) => Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileAbout(FileFacts::default())), refused: String::new() })),
        _ => {
            let _ = honest;
            None
        }
    });
    assert_eq!(chunk(0).status, 502);
    // Nothing ~zod says reaches the device: neither its words of refusal, as a file that is not
    // there, nor the reason for a refusal of the request, as an answer that is not right.
    const HOSTILE: &str = "<script>alert(1)</script>\r\nSet-Cookie: x=1\u{7}\u{0}";
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: None, refused: HOSTILE.into() })));
    let refused = info();
    assert_eq!(refused.status, 502);
    t.lie(|_, _| Some(Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileAbout(FileFacts { denied: HOSTILE.into(), ..FileFacts::default() })), refused: String::new() })));
    let denied = info();
    assert_eq!((denied.status, denied.text().as_str()), (404, NOT_SHARED));
    for answer in [&refused, &denied] {
        let text = answer.text();
        assert!(!text.contains("script") && !text.contains("Set-Cookie") && !text.contains('\u{7}'), "{text:?}");
        assert!(answer.header("Set-Cookie").is_none());
        assert_eq!(answer.header("Content-Type"), Some("text/plain; charset=utf-8"));
        kept_from_acting(answer);
    }
    // A chunk refused part way.
    t.lie(|asked, _| {
        matches!(asked, peer_request::Body::FileChunk(FileWanted { index: 2, .. }))
            .then(|| Lie::Reply(PeerReply { body: Some(peer_reply::Body::FileChunk(FileBytes { denied: "no".into(), data: Vec::new() })), refused: String::new() }))
    });
    assert!(content().body == data[..2 * CHUNK as usize]);
    assert_eq!(chunk(2).status, 404);

    // Media types: whatever the other ship says goes through the check made at upload, and
    // decides how the contents are sent as a local file's would.
    for (said, sent, shown) in [
        ("IMAGE/PNG", "image/png", "inline"),
        ("text/html", "text/html", "attachment"),
        ("image/svg+xml", "image/svg+xml", "attachment"),
        ("text/html; charset=utf-8", "application/octet-stream", "attachment"),
        ("text/html\r\nX-Evil: 1", "application/octet-stream", "attachment"),
        ("", "application/octet-stream", "attachment"),
    ] {
        t.lie(move |_, honest| {
            let mut reply = honest.clone();
            if let Some(peer_reply::Body::FileAbout(facts)) = &mut reply.body {
                facts.media_type = said.to_string();
            }
            Some(Lie::Reply(reply))
        });
        let whole = content();
        assert!(whole.status == 200 && whole.body == data, "{said:?}");
        assert_eq!((whole.header("Content-Type"), whole.header("Content-Disposition")), (Some(sent), Some(shown)), "{said:?}");
        assert!(whole.header("X-Evil").is_none());
        kept_from_acting(&whole);
    }

    // Cut off part way: the answer ends short, and a range carries on where it stopped.
    t.lie(|asked, _| matches!(asked, peer_request::Body::FileChunk(FileWanted { index: 2.., .. })).then_some(Lie::Cut));
    let cut = content();
    assert!(cut.status == 200 && cut.body == data[..2 * CHUNK as usize], "{} bytes passed on", cut.body.len());
    t.honest();
    let rest = t.get(&t.path("counter", &id, "/content"), &[("Range", &format!("bytes={}-", cut.body.len()))]);
    assert_eq!(rest.status, 206);
    assert!([cut.body, rest.body].concat() == data);
}

/// A ship too slow to answer within `file_timeout`: 504, in about that time. One that cannot
/// be reached at all: 504 too. (G1, G7)
#[test]
fn a_ship_too_slow_or_gone_is_waited_for_only_so_long() {
    let quick = NetConfig { file_timeout: Duration::from_millis(1500), request_timeout: Duration::from_millis(1500), ..NetConfig::default() };
    let t = two_with("slow", (fast(), NetConfig::default()), (fast(), quick), &["~nec"]);
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    t.lie(|_, _| Some(Lie::Slow(Duration::from_secs(5))));
    let started = Instant::now();
    assert_eq!(t.get(&t.path("counter", &id, "/content"), &[]).status, 504);
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1400) && took < Duration::from_secs(4), "took {took:?}");
    t.honest();
    let path = t.path("counter", &id, "");
    drop(t.a_net);
    let gone = http(&t.server, &path, &[("Authorization", &t.auth)]);
    assert_eq!(gone.status, 504, "{}", gone.text());
}

/// The bounds on the ship answering: four requests for files at once on one connection and
/// eight in all; past them, "too busy", and nothing else held up. And on the ship asking: half
/// the downloads' places, so its own files can still be had. (G7)
#[test]
fn requests_for_files_are_bounded_at_both_ends() {
    let t = two_with("bounds", (fast(), held_net()), (fast(), held_net()), &["~nec", "~bud", "~wes"]);
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    for ship in ["~nec", "~bud", "~wes"] {
        t.b_net.ping(ship, "~zod").unwrap();
    }
    // Every request let in is held at ~zod until the test lets them all go, by a barrier, not a
    // delay that runs out by itself: those turned away answer at once, while the rest are held,
    // so the first `busy` answers must all be turned away, and no more come until the barrier
    // goes.
    let ask = |ships: Vec<&'static str>, busy: usize| {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let holding = gate.clone();
        t.lie(move |_, _| Some(Lie::Held(holding.clone())));
        let (answers, answered) = std::sync::mpsc::channel();
        let asked = ships.len();
        let handles: Vec<_> = ships
            .into_iter()
            .map(|ship| {
                let (b, answers) = (t.b.clone(), answers.clone());
                std::thread::spawn(move || {
                    let wanted = FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 };
                    let _ = answers.send(b.ask_for_file(ship, "~zod", PeerRequest { body: Some(peer_request::Body::FileAbout(wanted)) }).unwrap());
                })
            })
            .collect();
        let sort = |answer| match answer {
            Ok(PeerReply { body: Some(peer_reply::Body::FileAbout(_)), .. }) => true,
            Err(FileAskError::Net(NetError::Refused(why))) if why == TOO_BUSY => false,
            other => panic!("{other:?}"),
        };
        for _ in 0..busy {
            let answer = answered.recv_timeout(Duration::from_secs(20)).expect("fewer were turned away than should be");
            assert!(!sort(answer), "a request was answered while those let in were held");
        }
        assert!(answered.recv_timeout(Duration::from_millis(300)).is_err(), "more were turned away than should be");
        gate.close();
        let served = (0..asked - busy).filter(|_| sort(answered.recv_timeout(Duration::from_secs(30)).expect("a held request never answered"))).count();
        for handle in handles {
            handle.join().unwrap();
        }
        (served, busy)
    };
    // One connection: four at once.
    assert_eq!(ask(vec!["~nec"; 6], 2), (4, 2));
    // Three connections: eight at once.
    assert_eq!(ask([vec!["~nec"; 4], vec!["~bud"; 4], vec!["~wes"; 4]].concat(), 4), (8, 4));

    // On the ship asking: two requests for other ships' files at once, of the four places for
    // downloads; a third is told to try again, and a file of its own is still had meanwhile.
    let own = contents(10, 9);
    let own_id = put(&t.b, "~nec", "counter", &own, "");
    let server = &t.server;
    let auth = t.auth.clone();
    let path = t.path("counter", &id, "/content");
    // Each request for the file asks ~zod (nothing of it is kept on ~nec: its earlier requests
    // were made straight to the network), and is held there by a barrier the test lets go after
    // its assertions; its first question counted, once a request, so as to wait until both hold
    // their places, never for a fixed time.
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = asked.clone();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let holding = gate.clone();
    t.lie(move |asked, _| {
        if matches!(asked, peer_request::Body::FileAbout(_)) {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        Some(Lie::Held(holding.clone()))
    });
    std::thread::scope(|scope| {
        let slow: Vec<_> = (0..2).map(|_| scope.spawn(|| http(server, &path, &[("Authorization", &auth)]).status)).collect();
        let until = Instant::now() + Duration::from_secs(20);
        while asked.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "inconclusive: the two slow requests never asked ~zod");
            std::thread::sleep(Duration::from_millis(10));
        }
        let third = http(server, &path, &[("Authorization", &auth)]);
        assert_eq!((third.status, third.header("Retry-After")), (503, Some("1")));
        let mine = http(server, &format!("/ships/nec/agents/counter/files/{}/content", hex(&own_id)), &[("Authorization", &auth)]);
        assert!(mine.status == 200 && mine.body == own);
        gate.close();
        for status in slow {
            assert_eq!(status.join().unwrap(), 200);
        }
    });
}

/// Every name in the address is checked, no request works without a device, a ship is not
/// asked for its own files this way, and with no network the answer is 503. (G6)
#[test]
fn only_the_owners_devices_and_only_good_names() {
    let t = two_uncached("names");
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    let good = t.path("counter", &id, "/content");
    assert_eq!(t.get(&good, &[]).status, 200);
    assert_eq!(http(&t.server, &good, &[]).status, 401);
    assert_eq!(http(&t.server, &good, &[("Authorization", "Bearer nonsense")]).status, 401);
    let bad = [
        format!("/ships/nec/files/from/nec/counter/{}", hex(&id)),
        format!("/ships/nec/files/from/~nec/counter/{}", hex(&id)),
        format!("/ships/nec/files/from/Zod/counter/{}", hex(&id)),
        format!("/ships/nec/files/from/%2e%2e/counter/{}", hex(&id)),
        format!("/ships/nec/files/from/zod/Counter/{}", hex(&id)),
        format!("/ships/nec/files/from/zod/..%2f..%2fx/{}", hex(&id)),
        format!("/ships/nec/files/from/zod/counter/{}", hex(&id).to_uppercase()),
        format!("/ships/nec/files/from/zod/counter/{}", &hex(&id)[..62]),
        format!("/ships/nec/files/from/zod/counter/{}/chunks/x", hex(&id)),
    ];
    for path in &bad {
        let answer = t.get(path, &[]);
        assert_eq!(answer.status, 400, "{path}: {}", answer.text());
        kept_from_acting(&answer);
    }
    assert_eq!(t.get(&format!("/ships/nec/files/from/zod/counter/{}/other", hex(&id)), &[]).status, 404);
    // A method other than GET.
    let mut stream = std::net::TcpStream::connect(t.server.addr()).unwrap();
    write!(stream, "DELETE {good} HTTP/1.0\r\nAuthorization: {}\r\n\r\n", t.auth).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 405"), "{raw}");
    // No network: try again later.
    drop(t.b_net);
    let none = http(&t.server, &good, &[("Authorization", &t.auth)]);
    assert_eq!((none.status, none.header("Retry-After")), (503, Some("5")));
    let _ = &t.directory;
}

/// A runtime whose messages are too small for a chunk refuses files both ways, saying so, and
/// starts and carries everything else as before.
#[test]
fn a_runtime_whose_messages_are_too_small_refuses_files_both_ways() {
    let small = || {
        let cfg = Config { max_event_bytes: 256 << 10, max_checkpoint_bytes: 256 << 10, ..fast() };
        (cfg, NetConfig { max_message_bytes: 512 << 10, ..NetConfig::default() })
    };
    // The ship asking.
    let t = two_with("unfit-b", (fast(), NetConfig::default()), small(), &["~nec"]);
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    let answer = t.get(&t.path("counter", &id, ""), &[]);
    assert_eq!(answer.status, 503, "{}", answer.text());
    assert!(answer.text().contains("max_message_bytes"));
    assert!(t.b_net.ping("~nec", "~zod").is_ok());
    // The ship asked.
    let t = two_with("unfit-a", small(), (fast(), NetConfig::default()), &["~nec"]);
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    assert_eq!(t.get(&t.path("counter", &id, ""), &[]).status, 502);
    let wanted = FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 };
    match t.b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(peer_request::Body::FileAbout(wanted)) }) {
        Some(Err(FileAskError::Net(NetError::Refused(why)))) => assert_eq!(why, super::FILES_UNFIT),
        other => panic!("{other:?}"),
    }
}

/// Every path under a directory, with its size.
fn listing(root: &Path) -> BTreeMap<String, u64> {
    let mut found = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                todo.push(entry.path());
            }
            found.insert(entry.path().strip_prefix(root).unwrap().display().to_string(), if meta.is_dir() { 0 } else { meta.len() });
        }
    }
    found
}

/// Nothing is kept or written by fetching: no file or directory on either runtime, and no row
/// on the ship asked. (G8)
#[test]
fn fetching_a_file_writes_nothing_at_either_end() {
    let t = two_uncached("nothing");
    let data = contents(3 * CHUNK as usize + 5, 2);
    let id = put(&t.a, "~zod", "counter", &data, "");
    let closed = put(&t.a, "~zod", "counter", &contents(100, 3), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    say(&t.a, "~zod", "counter", &format!("let nec {}", hex(&closed)));
    // Once, so that both ships are awake and connected.
    assert_eq!(t.get(&t.path("counter", &id, ""), &[]).status, 200);
    let (a_files, b_files) = (listing(&t._dirs.0 .0), listing(&t._dirs.1 .0));
    let a_rows = rows(&t.a, "~zod");
    let b_rows = rows(&t.b, "~nec");
    assert!(t.get(&t.path("counter", &id, "/content"), &[]).body == data);
    assert_eq!(t.get(&t.path("counter", &id, "/chunks/1"), &[]).status, 200);
    unrest(&t.a);
    assert_eq!(t.get(&t.path("counter", &closed, "/content"), &[]).status, 200);
    assert_eq!(t.get(&t.path("counter", &[1; 32], ""), &[]).status, 404);
    assert_eq!((listing(&t._dirs.0 .0), listing(&t._dirs.1 .0)), (a_files, b_files));
    assert_eq!((rows(&t.a, "~zod"), rows(&t.b, "~nec")), (a_rows, b_rows));
}

/// Commands and a log between the same two ships go through while one pulls files from the
/// other as fast as it is let. (G9)
#[test]
fn commands_and_logs_go_through_while_files_are_pulled() {
    let t = two("alongside");
    let data = contents(3 * CHUNK as usize, 4);
    let id = put(&t.a, "~zod", "counter", &data, "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    say(&t.a, "~zod", "counter", "share nec");
    assert_eq!(say(&t.b, "~nec", "tally", "follow-on zod"), "following");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pulled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pullers: Vec<_> = (0..6)
        .map(|_| {
            let (b, stop, pulled, data) = (t.b.clone(), stop.clone(), pulled.clone(), data.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok(mut remote) = b.remote_file("~nec", "~zod", "counter", &id) else { continue };
                    for n in 0..3u64 {
                        if let Ok(chunk) = remote.chunk(n) {
                            assert!(chunk == data[(n * CHUNK) as usize..((n + 1) * CHUNK) as usize]);
                            pulled.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    // One command and one log entry at a time, each waited for, for as long as the pulling goes
    // on: none may be held up behind the files.
    let seen = || String::from_utf8(t.b.read("~nec", "tally", "tally", b"seen-on zod").unwrap()).unwrap();
    let (started, before) = (Instant::now(), pulled.load(Ordering::SeqCst));
    let mut slowest = Duration::ZERO;
    for round in 1..=10u32 {
        let asked = Instant::now();
        assert_eq!(say(&t.b, "~nec", "tally", "tell zod inc hits"), "sent");
        say(&t.a, "~zod", "counter", "log hits");
        while say(&t.a, "~zod", "counter", "get hits") != (2 * round).to_string() || seen() != round.to_string() {
            assert!(asked.elapsed() < Duration::from_secs(10), "round {round}: hits {} seen {}", say(&t.a, "~zod", "counter", "get hits"), seen());
            std::thread::sleep(Duration::from_millis(20));
        }
        slowest = slowest.max(asked.elapsed());
    }
    let took = started.elapsed();
    let during = pulled.load(Ordering::SeqCst) - before;
    stop.store(true, Ordering::SeqCst);
    for puller in pullers {
        puller.join().unwrap();
    }
    eprintln!("ten commands and log entries went through in {took:?} (the slowest {slowest:?}), with {during} chunks pulled meanwhile");
    assert!(during >= 10, "only {during} chunks pulled meanwhile");
}

/// Serving a file holds the ship only for the decision; the time, for the record.
#[test]
fn how_long_serving_holds_the_ship() {
    let dir = TempDir::new("hold");
    let rt = crewed(&dir, fast(), &["~zod"], "~nec");
    let open = put(&rt, "~zod", "counter", &contents(2 * CHUNK as usize, 1), "");
    say(&rt, "~zod", "counter", &format!("open {}", hex(&open)));
    let closed = put(&rt, "~zod", "counter", &contents(10, 2), "");
    say(&rt, "~zod", "counter", &format!("let nec {}", hex(&closed)));
    let time = |agent: &str, id: &[u8; 32], part: Part, runs: u32| {
        let started = Instant::now();
        for _ in 0..runs {
            rt.serve_file("~zod", "~nec", agent, id, part, &WAITING).unwrap();
        }
        started.elapsed() / runs
    };
    let _ = about(&rt, "counter", &open);
    let open_about = time("counter", &open, Part::About, 50);
    let nobody = time("counter", &[3; 32], Part::About, 50);
    let remembered = time("counter", &closed, Part::About, 50);
    let asked = {
        let mut total = Duration::ZERO;
        for _ in 0..20 {
            age(&rt, Duration::from_secs(60));
            total += time("counter", &closed, Part::About, 1);
        }
        total / 20
    };
    let chunk = time("counter", &open, Part::Chunk(1), 10);
    eprintln!("open: {open_about:?}; no such file: {nobody:?}; remembered: {remembered:?}; asked: {asked:?}; a chunk in all: {chunk:?}");
}

/// The remembered answers: a yes for 30 s and a no for 5 s, at most 4,096 with the oldest going
/// first, kept apart by every part of their key, and a table left poisoned trusted for nothing.
/// (G7, G10)
#[test]
fn remembered_answers_are_bounded_short_lived_and_keyed_by_values_never_reused() {
    let answers = Mutex::new(files::Answers::default());
    let key = |n: u32| files::AnswerKey {
        ship: "zod".into(),
        incarnation: [1; 16],
        module: "m".into(),
        agent: "counter".into(),
        caller: format!("c{n}"),
        id: [2; 32],
        dir: [4; 16],
    };
    let now = Instant::now();
    files::remember(&answers, key(0), true, now);
    files::remember(&answers, key(1), false, now);
    assert_eq!(files::remembered(&answers, &key(0), now + Duration::from_secs(29)), Some(true));
    assert_eq!(files::remembered(&answers, &key(0), now + Duration::from_secs(30)), None);
    assert_eq!(files::remembered(&answers, &key(1), now + Duration::from_millis(4999)), Some(false));
    assert_eq!(files::remembered(&answers, &key(1), now + Duration::from_secs(5)), None);
    // Every part of the key counts: another copy of the ship, module, agent, caller or file.
    files::remember(&answers, key(0), true, now);
    let others = [
        files::AnswerKey { incarnation: [9; 16], ..key(0) },
        files::AnswerKey { module: "n".into(), ..key(0) },
        files::AnswerKey { agent: "keeper".into(), ..key(0) },
        files::AnswerKey { ship: "bus".into(), ..key(0) },
        files::AnswerKey { id: [3; 32], ..key(0) },
        files::AnswerKey { dir: [5; 16], ..key(0) },
        key(7),
    ];
    for other in &others {
        assert_eq!(files::remembered(&answers, other, now), None, "{other:?}");
    }
    // Full: the oldest goes.
    for n in 0..files::MOST_ANSWERS as u32 + 10 {
        files::remember(&answers, key(n), true, now);
    }
    assert_eq!(lock(&answers).len(), files::MOST_ANSWERS);
    assert_eq!(files::remembered(&answers, &key(9), now), None);
    assert_eq!(files::remembered(&answers, &key(10), now), Some(true));
    // Poisoned: no, and nothing remembered is trusted afterwards.
    let _ = std::panic::catch_unwind(|| {
        let _held = answers.lock().unwrap();
        panic!("poisoning the table");
    });
    assert_eq!(files::remembered(&answers, &key(10), now), Some(false));
    assert_eq!(files::remembered(&answers, &key(10), now), None);
    assert_eq!(lock(&answers).len(), 0);
}

/// The kernel lets another ship ask about any installed agent's files, and nobody else: not
/// the owner, not an agent here. (G3)
#[test]
fn only_another_ship_asks_the_kernel_about_a_file() {
    let dir = TempDir::new("kernel");
    let rt = crewed(&dir, fast(), &["~zod"], "~nec");
    let routes = |owner: bool, agent: &str, ship: &str, to: &str| {
        let source = ship_proto::Source { owner, agent: agent.into(), ship: ship.into() };
        rt.inner.with_ship("~zod", |held| Ok(held.routes(&rt.inner, &source, to, ship_proto::Kind::FileAsk))).unwrap()
    };
    assert!(routes(false, "", "nec", "counter") && routes(false, "", "nec", "tally"));
    assert!(!routes(false, "", "nec", "nobody"));
    assert!(!routes(true, "", "", "counter"));
    assert!(!routes(true, "", "nec", "counter"));
    assert!(!routes(false, "tally", "", "counter"));
}

/// A request for a file has `file_timeout` at the ship asked, not `request_timeout`: a part
/// that takes longer than the second is still answered. (G7)
#[test]
fn a_request_for_a_file_has_its_own_time_at_the_ship_asked() {
    let short = NetConfig { request_timeout: Duration::from_secs(1), ..NetConfig::default() };
    let t = two_with("file-time", (fast(), short), (fast(), NetConfig::default()), &["~nec"]);
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    t.lie(|asked, _| matches!(asked, peer_request::Body::FileAbout(_)).then_some(Lie::Slow(Duration::from_millis(2500))));
    let answer = t.get(&t.path("counter", &id, ""), &[]);
    assert_eq!(answer.status, 200, "{}", answer.text());
}

/// Wait for `holds` to be true, checking every 20 ms, for at most `within`; then fail saying
/// `what` and what `state` shows.
fn settle(what: &str, within: Duration, holds: impl Fn() -> bool, state: impl Fn() -> String) {
    let started = Instant::now();
    while !holds() {
        assert!(started.elapsed() < within, "{what}: {}", state());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Fill the runtime's eight places for file requests with unread whole chunks from `ships`,
/// adding one request at a time across the connections until all eight are seen held, and
/// still held 300 ms later. (A chunk that fits its connection's window is taken by QUIC alone
/// and gives its places back, so how many requests that takes is not fixed.)
fn fill_places(net: &Network, a: &super::Shared, ships: &[&str], chunk: peer_request::Body) -> Vec<Vec<(quinn::SendStream, quinn::RecvStream)>> {
    let in_hand = || super::MOST_FILES_ANSWERING - a.files_answering.available_permits();
    let mut held = Vec::new();
    for round in 0..64 {
        if in_hand() == super::MOST_FILES_ANSWERING {
            std::thread::sleep(Duration::from_millis(300));
            if in_hand() == super::MOST_FILES_ANSWERING {
                return held;
            }
        }
        held.push(unread(net, ships[round % ships.len()], "~zod", vec![chunk.clone()]));
        let before = Instant::now();
        while in_hand() < super::MOST_FILES_ANSWERING && before.elapsed() < Duration::from_millis(200) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    panic!("the places never stayed full: {} in hand after 64 requests", in_hand());
}

/// Requests on the connection the network keeps from `from` to `to` (shared with everything
/// else between the two), whose replies are not read until the caller reads them.
fn unread(net: &Network, from: &str, to: &str, bodies: Vec<peer_request::Body>) -> Vec<(quinn::SendStream, quinn::RecvStream)> {
    unread_on(net, from, to, bodies).1
}

/// The same, with the connection they went on.
fn unread_on(net: &Network, from: &str, to: &str, bodies: Vec<peer_request::Body>) -> (quinn::Connection, Vec<(quinn::SendStream, quinn::RecvStream)>) {
    let (from, to) = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    net.threads.get().block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (connection, _) = net.shared.connection(&from, &to, deadline).await.unwrap();
        let mut streams = Vec::new();
        for body in bodies {
            let (mut send, receive) = connection.open_bi().await.unwrap();
            send.write_all(&PeerRequest { body: Some(body) }.encode_to_vec()).await.unwrap();
            send.finish().unwrap();
            streams.push((send, receive));
        }
        (connection, streams)
    })
}

fn chunk_of(id: &[u8; 32], n: u64) -> peer_request::Body {
    peer_request::Body::FileChunk(FileWanted { agent: "counter".into(), id: id.to_vec(), index: n })
}

/// A ship that asks for chunks it may have and never reads the replies holds at most four
/// places on its connection, and all such ships at most eight in the runtime, at every instant
/// of the whole `file_timeout`; a part in hand holds its place until its stream is done with;
/// one that is refused, or turned away, holds no place, nor any room for reading while its
/// refusal waits; and commands and a log between the same two ships go through meanwhile.
/// (G7, G9)
///
/// The replies are whole chunks, so that they fill the asking connection's receive window and
/// cannot be taken by QUIC alone. On ~nec's connection to ~zod nothing more can then come back
/// to ~nec until it reads: a ship that reads nothing stops its own replies, which is its own
/// doing (its commands to ~zod wait for their acknowledgements, and news of its logs for
/// theirs). So the commands are ~zod's, and the log is fetched by ~zod, both on ~zod's own
/// connection to ~nec.
#[test]
fn a_ship_that_never_reads_its_replies_holds_at_most_its_places() {
    let t = two_with("unread", (fast(), NetConfig::default()), (fast(), NetConfig::default()), &["~nec", "~bud", "~wes"]);
    let big = put(&t.a, "~zod", "counter", &contents(CHUNK as usize, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&big)));
    for ship in ["~nec", "~bud", "~wes"] {
        t.b_net.ping(ship, "~zod").unwrap();
    }
    t.a_net.ping("~zod", "~nec").unwrap();
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let rooms = || (shared.cfg.max_reading_bytes - shared.reading.available_permits()) / shared.cfg.max_message_bytes;
    // Refused, and the refusals stuck behind unread chunks: only the chunk that is stuck holds a
    // place. (The first chunk fits the connection's window and is taken by QUIC alone; the
    // second cannot be sent until the first is read.)
    let before = t.a.inner.served_decisions.load(Ordering::SeqCst);
    let mut refused = unread(&t.b_net, "~nec", "~zod", vec![chunk_of(&big, 0), chunk_of(&big, 0)]);
    // The set-up's own end first: both chunks decided, the first taken by QUIC alone and the
    // second stuck. Then the connection has three places free for the three nos, so none of
    // them is turned away before it is decided.
    let set_up = || t.a.inner.served_decisions.load(Ordering::SeqCst) == before + 2;
    settle("the set-up chunks decided, one stuck", Duration::from_secs(5), || set_up() && in_hand() == 1 && rooms() == 1, || format!("{} in hand, {} rooms, set up: {}", in_hand(), rooms(), set_up()));
    refused.extend(unread(&t.b_net, "~nec", "~zod", (0..3).map(|_| every_part("counter", &[9; 32])[3].clone()).collect()));
    // All five decided (two chunks, three nos): only then is what is held looked at.
    let all_decided = || t.a.inner.served_decisions.load(Ordering::SeqCst) == before + 5;
    settle("only the stuck chunk holds a place", Duration::from_secs(5), || all_decided() && in_hand() == 1 && rooms() == 1, || format!("{} in hand, {} rooms, all decided: {}", in_hand(), rooms(), all_decided()));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!((in_hand(), rooms()), (1, 1), "a ship refused holds file places or room");
    drop(refused);
    let dropped = Instant::now();
    while in_hand() > 0 {
        assert!(dropped.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(50));
    }

    // Allowed, and never read: six asked on one connection. At most four in hand, and those
    // stuck behind unread chunks still held.
    let started = Instant::now();
    let mut held = vec![unread(&t.b_net, "~nec", "~zod", (0..6).map(|_| chunk_of(&big, 0)).collect())];
    std::thread::sleep(Duration::from_millis(500));
    while started.elapsed() < Duration::from_secs(2) {
        let hand = in_hand();
        assert!(hand > 0 && hand <= 4, "{hand} in hand on one connection");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Three more on the same connection, now that its window is full: at least two are turned
    // away, and their refusals wait behind the unread chunks holding no room.
    held.push(unread(&t.b_net, "~nec", "~zod", (0..3).map(|_| chunk_of(&big, 0)).collect()));
    std::thread::sleep(Duration::from_millis(500));
    settle("rooms equal to parts in hand, on one connection", Duration::from_secs(5), || { let hand = in_hand(); hand > 0 && hand <= 4 && rooms() == hand }, || format!("{} in hand, {} rooms", in_hand(), rooms()));
    // And six more on each of two more connections: at most eight in all.
    held.extend(["~bud", "~wes"].iter().map(|ship| unread(&t.b_net, ship, "~zod", (0..6).map(|_| chunk_of(&big, 0)).collect())));
    std::thread::sleep(Duration::from_millis(700));
    // Every room for reading held belongs to a part in hand: those turned away hold none while
    // their refusals wait behind the chunks.
    settle("rooms equal to parts in hand", Duration::from_secs(5), || { let hand = in_hand(); hand > 0 && hand <= 8 && rooms() == hand }, || format!("{} in hand, {} rooms", in_hand(), rooms()));
    // Commands from ~zod to ~nec, and a log of ~nec's fetched by ~zod, while those are held.
    say(&t.b, "~nec", "counter", "share zod");
    for round in 1..=3u32 {
        let asked = Instant::now();
        assert_eq!(say(&t.a, "~zod", "tally", "tell nec inc hits"), "sent");
        say(&t.b, "~nec", "counter", "log hits");
        while say(&t.b, "~nec", "counter", "get hits") != (2 * round).to_string() {
            assert!(asked.elapsed() < Duration::from_secs(10), "round {round}");
            assert!(in_hand() <= 8);
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let asked = Instant::now();
    assert_eq!(say(&t.a, "~zod", "tally", "follow-on nec"), "following");
    let seen = || String::from_utf8(t.a.read("~zod", "tally", "tally", b"seen-on nec").unwrap()).unwrap();
    while seen() != "3" {
        assert!(asked.elapsed() < Duration::from_secs(10), "the log: {}", seen());
        std::thread::sleep(Duration::from_millis(20));
    }
    // At every instant until shortly before the time is up, at most eight in hand, and those
    // that are stuck behind unread chunks still held.
    while started.elapsed() < Duration::from_secs(25) {
        let hand = in_hand();
        assert!(hand > 0 && hand <= 8, "{hand} in hand at {:?}", started.elapsed());
        std::thread::sleep(Duration::from_millis(100));
    }
    // Let go of, every place comes back.
    drop(held);
    let ended = Instant::now();
    while in_hand() > 0 {
        assert!(ended.elapsed() < Duration::from_secs(5), "{} still in hand", in_hand());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A blocking job that outlives its request still holds the request's places until it returns,
/// and, given up on, does not go on to read the chunk. (G7)
#[test]
fn a_job_that_outlives_its_request_still_holds_its_places() {
    let quick = NetConfig { file_timeout: Duration::from_secs(1), ..NetConfig::default() };
    let t = two_with("outlives", (fast(), quick), (fast(), NetConfig::default()), &["~nec"]);
    let open = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&open)));
    t.b_net.ping("~nec", "~zod").unwrap();
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    *lock(&t.a.inner.serve_delay) = Some(Duration::from_secs(3));
    let reads = t.a.inner.served_reads.load(Ordering::SeqCst);
    let started = Instant::now();
    let b = t.b.clone();
    let asking = std::thread::spawn(move || b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(chunk_of(&open, 0)) }).unwrap());
    assert!(asking.join().unwrap().is_err(), "a request past its time was answered");
    assert!(started.elapsed() < Duration::from_millis(2500));
    std::thread::sleep(Duration::from_millis(1600).saturating_sub(started.elapsed()));
    assert_eq!(in_hand(), 1, "the job's places were given back before it returned");
    while in_hand() > 0 {
        assert!(started.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert_eq!(t.a.inner.served_reads.load(Ordering::SeqCst), reads, "a job given up on read the chunk");
    // Likewise a group of hashes: given up on, not one batch is read.
    let b = t.b.clone();
    let leaves = peer_request::Body::FileLeaves(FileWanted { agent: "counter".into(), id: open.to_vec(), index: 0 });
    assert!(b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(leaves) }).unwrap().is_err());
    let waited = Instant::now();
    while in_hand() > 0 {
        assert!(waited.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(t.a.inner.served_reads.load(Ordering::SeqCst), reads, "a job given up on read hashes");
    *lock(&t.a.inner.serve_delay) = None;
    let reply = t.b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(chunk_of(&open, 0)) }).unwrap().unwrap();
    assert!(matches!(reply.body, Some(peer_reply::Body::FileChunk(_))));
    assert_eq!(t.a.inner.served_reads.load(Ordering::SeqCst), reads + 1);
}

/// Waits on other ships come out of the same allowance as downloads, so with long polls, slow
/// downloads and waits on other ships together the threads kept for everything else stay free,
/// for every number of workers the README names. (G7, G9)
#[test]
fn waits_on_other_ships_leave_the_threads_kept_for_everything_else() {
    let t = two("workers");
    let id = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    let big = put(&t.b, "~nec", "counter", &contents(8 * CHUNK as usize, 2), "");
    t.lie(|_, _| Some(Lie::Slow(Duration::from_secs(4))));
    let auth = t.auth.clone();
    let remote = t.path("counter", &id, "");
    let remote_chunk = t.path("counter", &id, "/chunks/0");
    let poll = "/ships/nec/logs/counter/counter/entries?wait=6";
    let local = format!("/ships/nec/agents/counter/files/{}/content", hex(&big));
    // A download its client never reads: holds a worker until `io_timeout`.
    let stalled = |server: &Server| {
        let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
        write!(stream, "GET {local} HTTP/1.0\r\nAuthorization: {auth}\r\n\r\n").unwrap();
        stream
    };
    let command = |server: &Server| {
        let started = Instant::now();
        let answer = request(server, "POST", "/ships/nec/agents/counter/command", &[("Authorization", &auth)], b"get hits");
        (answer.status, started.elapsed())
    };
    let quick = |answer: Answer, started: Instant| (answer.status, started.elapsed() < Duration::from_secs(1), answer.header("Retry-After").map(str::to_string));
    let two = Server::start(t.b.clone(), ServerConfig { workers: 2, ..ServerConfig::default() }).unwrap();
    let four = Server::start(t.b.clone(), ServerConfig { workers: 4, ..ServerConfig::default() }).unwrap();
    std::thread::scope(|scope| {
        // Two workers: no download place at all, so no wait on another ship.
        let polling = scope.spawn(|| http(&two, poll, &[("Authorization", &auth)]).status);
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        let refused = http(&two, &remote, &[("Authorization", &auth)]);
        assert!(refused.text().contains("wait on another ship"), "{}", refused.text());
        assert_eq!(quick(refused, started), (503, true, None));
        let started = Instant::now();
        let refused = http(&two, &remote_chunk, &[("Authorization", &auth)]);
        assert!(refused.text().contains("wait on another ship"), "{}", refused.text());
        assert_eq!(quick(refused, started), (503, true, None));
        let (status, took) = command(&two);
        assert!(status == 200 && took < Duration::from_secs(2), "{status} {took:?}");
        assert_eq!(polling.join().unwrap(), 200);

        // Four workers: two may poll, one may download or wait on another ship, one is kept.
        let polls: Vec<_> = (0..2).map(|_| scope.spawn(|| http(&four, poll, &[("Authorization", &auth)]).status)).collect();
        std::thread::sleep(Duration::from_millis(300));
        let _slow = stalled(&four);
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        assert_eq!(quick(http(&four, &remote, &[("Authorization", &auth)]), started), (503, true, Some("1".into())));
        let started = Instant::now();
        assert_eq!(quick(http(&four, &remote_chunk, &[("Authorization", &auth)]), started), (503, true, Some("1".into())));
        let (status, took) = command(&four);
        assert!(status == 200 && took < Duration::from_secs(2), "{status} {took:?}");
        for polled in polls {
            assert_eq!(polled.join().unwrap(), 200);
        }
    });
    std::thread::scope(|scope| {
        // Sixteen workers (the default): eight may poll, four download or wait on other ships
        // (two of them at most waiting), four are kept.
        let server = &t.server;
        let polls: Vec<_> = (0..8).map(|_| scope.spawn(|| http(server, poll, &[("Authorization", &auth)]).status)).collect();
        // One wait of each route that is not a download: what a file is, and one chunk.
        let waits: Vec<_> = [&remote, &remote_chunk].into_iter().map(|path| scope.spawn(|| http(server, path, &[("Authorization", &auth)]).status)).collect();
        std::thread::sleep(Duration::from_millis(400));
        let _slow: Vec<_> = (0..2).map(|_| stalled(server)).collect();
        std::thread::sleep(Duration::from_millis(400));
        let started = Instant::now();
        assert_eq!(quick(http(server, &remote_chunk, &[("Authorization", &auth)]), started), (503, true, Some("1".into())));
        let started = Instant::now();
        assert_eq!(quick(http(server, &local, &[("Authorization", &auth)]), started), (503, true, Some("1".into())));
        let commands: Vec<_> = (0..4).map(|_| scope.spawn(|| command(server))).collect();
        for done in commands {
            let (status, took) = done.join().unwrap();
            assert!(status == 200 && took < Duration::from_secs(2), "{status} {took:?}");
        }
        for waited in waits {
            assert_eq!(waited.join().unwrap(), 200);
        }
        for polled in polls {
            assert_eq!(polled.join().unwrap(), 200);
        }
    });
}

/// Every change through a ship's kernel forgets every answer remembered for that ship, and
/// only that ship: the same module installed again with a grant taken away, a module replaced
/// and put back, another agent installed. (G10)
#[test]
fn an_install_forgets_the_ships_remembered_answers() {
    let dir = TempDir::new("forget");
    let rt = crewed(&dir, fast(), &["~zod", "~bus"], "~nec");
    let (counter, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    let ask = |ship: &str, id: &[u8; 32]| {
        unrest(&rt);
        rt.serve_file(ship, "~nec", "counter", id, Part::About, &WAITING).unwrap()
    };
    let yes = |served: Served| matches!(served, Served::About { .. });
    // An answer that rests on a read of another agent, through a grant.
    let keeper = Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: false }], uses: vec![] };
    let reading = Manifest { uses: vec![Use { ship: String::new(), agent: "keeper".into(), interface: "counter".into(), read: true, send: false }], ..open_counter() };
    rt.install("~zod", "keeper", &counter, &keeper).unwrap();
    rt.install("~zod", "counter", &counter, &reading).unwrap();
    say(&rt, "~zod", "keeper", "inc gate");
    say(&rt, "~zod", "counter", "asks via");
    let via = put(&rt, "~zod", "counter", &contents(10, 1), "");
    assert!(yes(ask("~zod", &via)));
    // The same module, installed again without the grant: asked afresh, and the read refused.
    rt.install("~zod", "counter", &counter, &open_counter()).unwrap();
    assert_eq!(ask("~zod", &via), Served::Denied);
    say(&rt, "~zod", "counter", "asks behave");

    // Replaced and put back.
    let back = put(&rt, "~zod", "counter", &contents(10, 2), "");
    say(&rt, "~zod", "counter", &format!("let nec {}", hex(&back)));
    assert!(yes(ask("~zod", &back)));
    say(&rt, "~zod", "counter", &format!("unlet nec {}", hex(&back)));
    assert!(yes(ask("~zod", &back)), "remembered");
    rt.install("~zod", "counter", &tally, &open_counter()).unwrap();
    rt.install("~zod", "counter", &counter, &open_counter()).unwrap();
    assert_eq!(ask("~zod", &back), Served::Denied);

    // Another agent installed: every answer on the ship goes.
    let other = put(&rt, "~zod", "counter", &contents(10, 3), "");
    say(&rt, "~zod", "counter", &format!("let nec {}", hex(&other)));
    assert!(yes(ask("~zod", &other)));
    say(&rt, "~zod", "counter", &format!("unlet nec {}", hex(&other)));
    rt.install("~zod", "tally", &tally, &following_tally("nec")).unwrap();
    assert_eq!(ask("~zod", &other), Served::Denied);

    // Another ship's answers stay.
    let theirs = put(&rt, "~bus", "counter", &contents(10, 4), "");
    say(&rt, "~bus", "counter", &format!("let nec {}", hex(&theirs)));
    assert!(yes(ask("~bus", &theirs)));
    say(&rt, "~bus", "counter", &format!("unlet nec {}", hex(&theirs)));
    rt.install("~zod", "tally", &tally, &following_tally("nec")).unwrap();
    assert!(yes(ask("~bus", &theirs)), "another ship's remembered answer was forgotten");
}

/// Paths under a data directory with their sizes, but for SQLite's own files beside an open
/// database (`-wal`, `-shm`), which opening a ship makes.
fn kept(root: &Path) -> BTreeMap<String, u64> {
    listing(root).into_iter().filter(|(path, _)| !path.ends_with("-wal") && !path.ends_with("-shm")).collect()
}

/// A stranger's request that is the first thing to wake a ship in a runtime's life sets off
/// the clearing of leftovers owed at first wake, as anything that wakes it does, and nothing
/// more: the recorded leftover goes, no row is added anywhere, nothing new is on disk. (G8)
#[test]
fn a_request_that_first_wakes_a_ship_sets_off_only_the_clearing_owed() {
    let dir = TempDir::new("first-wake");
    let before_rows = {
        let rt = crewed(&dir, fast(), &["~zod"], "~nec");
        let id = put(&rt, "~zod", "counter", &contents(2 * CHUNK as usize, 1), "");
        // The removal after the delete fails: the directory stays, recorded to be removed.
        crate::files::seams::arm("remove");
        rt.file_delete("~zod", "counter", &id).unwrap();
        assert_eq!(rt.files_to_remove("~zod").unwrap().1, 1);
        rows(&rt, "~zod")
    };
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let before = kept(&dir.0);
    let leftover: Vec<&String> = before.keys().filter(|path| path.starts_with("files/zod/")).collect();
    assert_eq!(leftover.len(), 3, "{leftover:?}");
    // The request goes where the network hands a stranger's request.
    assert_eq!(rt.serve_file("~zod", "~bus", "counter", &[9; 32], Part::About, &WAITING).unwrap(), Served::Denied);
    let after = kept(&dir.0);
    assert!(after.keys().all(|path| before.contains_key(path)), "something new on disk: {after:?}");
    assert!(after.keys().all(|path| !path.starts_with("files/zod/")), "the leftover stayed: {after:?}");
    let after_rows = rows(&rt, "~zod");
    for (table, count) in &after_rows {
        let was = before_rows.get(table).copied().unwrap_or(0);
        match table.as_str() {
            "file_trash" => assert_eq!((was, *count), (1, 0)),
            _ => assert_eq!(*count, was, "{table}"),
        }
    }
}

/// However many ships ask, questions take at most about a quarter of a ship's time: after a
/// question that took `t`, the ship asks none for `3 t`. (G7)
#[test]
fn asks_take_a_bounded_share_of_a_ships_time_however_many_ask() {
    let dir = TempDir::new("share");
    let rt = crewed(&dir, fast(), &["~zod"], "~nec");
    let id = put(&rt, "~zod", "counter", &contents(10, 1), "");
    // Each question runs until it is out of fuel, and the answer is no: never remembered as
    // yes, and every caller is new, so every request would need a question.
    say(&rt, "~zod", "counter", "asks spin");
    let name = |n: usize| format!("caller-{}", n.to_string().bytes().map(|b| (b - b'0' + b'a') as char).collect::<String>());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let started = Instant::now();
    let window = Duration::from_secs(2);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                while started.elapsed() < window {
                    let caller = name(next.fetch_add(1, Ordering::SeqCst));
                    assert_eq!(rt.serve_file("~zod", &caller, "counter", &id, Part::About, &WAITING).unwrap(), Served::Denied);
                }
            });
        }
    });
    let elapsed = started.elapsed();
    let asked = lock(&rt.inner.asked).clone();
    let longest = asked.iter().map(|(_, took)| *took).max().unwrap();
    let total: Duration = asked.iter().map(|(_, took)| *took).sum();
    eprintln!("{} questions of {} requests took {total:?} of {elapsed:?}, the longest {longest:?}", asked.len(), next.load(Ordering::SeqCst));
    assert!(asked.len() >= 2);
    assert!(total <= elapsed.mul_f64(0.3) + longest, "questions took {total:?} of {elapsed:?}");
}

/// A table of rests left poisoned by a panic is emptied, and the ship rests: nothing is asked.
#[test]
fn a_poisoned_table_of_rests_asks_nothing() {
    let rests: Mutex<std::collections::HashMap<String, Instant>> = Mutex::default();
    assert!(!files::resting(&rests, "zod", Instant::now()));
    files::rest_after(&rests, "zod", Duration::from_secs(1), Instant::now());
    assert!(files::resting(&rests, "zod", Instant::now()) && !files::resting(&rests, "bus", Instant::now()));
    let _ = std::panic::catch_unwind(|| {
        let _held = rests.lock().unwrap();
        panic!("poisoning the table");
    });
    assert!(files::resting(&rests, "bus", Instant::now()));
    assert!(!files::resting(&rests, "zod", Instant::now()), "emptied");
}

/// File requests that end in a no, never taken by the asking ship, hold nothing of the
/// runtime's: no place and no room for reading; so while several connections stall their
/// refusals, other ships on the same runtime go on: a command, a log fetch and a ping. (G7, G9)
#[test]
fn refusals_never_taken_hold_no_room_and_shut_out_no_one() {
    let dirs = (TempDir::new("stalled-no-a"), TempDir::new("stalled-no-b"));
    let directory = Directory::new();
    let a = crewed(&dirs.0, fast(), &["~zod", "~bus"], "~fen");
    let a_net = Network::start(a.clone(), directory.clone(), NetConfig::default()).unwrap();
    let b = crewed(&dirs.1, fast(), &["~nec", "~bud", "~wes", "~fen"], "~bus");
    let b_net = Network::start(b.clone(), directory.clone(), NetConfig::default()).unwrap();
    for ship in ["~zod", "~bus"] {
        directory.set(ship, a.public_key(ship).unwrap(), a_net.addr()).unwrap();
    }
    for ship in ["~nec", "~bud", "~wes", "~fen"] {
        directory.set(ship, b.public_key(ship).unwrap(), b_net.addr()).unwrap();
    }
    let big = put(&a, "~zod", "counter", &contents(CHUNK as usize, 1), "");
    say(&a, "~zod", "counter", &format!("open {}", hex(&big)));
    let shared = &a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let rooms = || (shared.cfg.max_reading_bytes - shared.reading.available_permits()) / shared.cfg.max_message_bytes;
    for ship in ["~nec", "~bud", "~wes"] {
        b_net.ping(ship, "~zod").unwrap();
    }
    // On each of three connections: two chunks never read (the second is stuck behind the
    // first, which QUIC takes), then nos stuck behind both.
    let before = a.inner.served_decisions.load(Ordering::SeqCst);
    let mut stalled = Vec::new();
    for ship in ["~nec", "~bud", "~wes"] {
        stalled.push(unread(&b_net, ship, "~zod", vec![chunk_of(&big, 0), chunk_of(&big, 0)]));
    }
    // The set-up's own end first: all six chunks decided, one stuck on each connection. Then
    // the runtime has five places free for the five nos, so none is turned away.
    let set_up = || a.inner.served_decisions.load(Ordering::SeqCst) == before + 6;
    settle("the set-up chunks decided, one stuck on each", Duration::from_secs(5), || set_up() && in_hand() == 3 && rooms() == 3, || format!("{} in hand, {} rooms, set up: {}", in_hand(), rooms(), set_up()));
    // Five in all (two, two, one): with the three stuck chunks, the runtime's eight places, so
    // every one is decided (none turned away) and is a no.
    for (ship, nos) in [("~nec", 2), ("~bud", 2), ("~wes", 1)] {
        stalled.push(unread(&b_net, ship, "~zod", (0..nos).map(|_| every_part("counter", &[9; 32])[3].clone()).collect()));
    }
    std::thread::sleep(Duration::from_millis(700));
    // Only the stuck chunks hold anything: one place and one room each.
    // All 11 decided (six chunks, five nos): only then is what is held looked at.
    let all_decided = || a.inner.served_decisions.load(Ordering::SeqCst) == before + 11;
    settle(
        "rooms equal to parts in hand, with 5 nos stalled",
        Duration::from_secs(5),
        || all_decided() && in_hand() <= 3 && rooms() == in_hand(),
        || format!("{} in hand, {} rooms, all decided: {}", in_hand(), rooms(), all_decided()),
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(in_hand() <= 3 && rooms() == in_hand(), "{} in hand, {} rooms, with 5 nos stalled", in_hand(), rooms());
    // Meanwhile, between ~fen and ~bus: a ping, commands, and a log fetched.
    let started = Instant::now();
    b_net.ping("~fen", "~bus").unwrap();
    say(&a, "~bus", "counter", "share fen");
    assert_eq!(say(&b, "~fen", "tally", "follow-on bus"), "following");
    assert_eq!(say(&b, "~fen", "tally", "tell bus inc hits"), "sent");
    say(&a, "~bus", "counter", "log hits");
    let seen = || String::from_utf8(b.read("~fen", "tally", "tally", b"seen-on bus").unwrap()).unwrap();
    while say(&a, "~bus", "counter", "get hits") != "2" || seen() != "1" {
        assert!(started.elapsed() < Duration::from_secs(10), "hits {} seen {}", say(&a, "~bus", "counter", "get hits"), seen());
        assert!(rooms() <= 3 + 2);
        std::thread::sleep(Duration::from_millis(20));
    }
    // Once that traffic has settled, again only the stuck chunks hold room.
    let settling = Instant::now();
    while rooms() != in_hand() {
        assert!(settling.elapsed() < Duration::from_secs(5), "{} rooms, {} in hand: the refusals still stalled hold room", rooms(), in_hand());
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(stalled);
}

/// The asking ship giving up (stopping the stream, or closing the connection) marks the request
/// given up on at once: the job, held after its decision, reads neither the chunk nor a batch
/// of hashes, and the places come back when it returns. (G7)
#[test]
fn the_asking_ship_giving_up_reaches_the_job() {
    let t = two("giving-up");
    let open = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&open)));
    t.b_net.ping("~nec", "~zod").unwrap();
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let leaves = peer_request::Body::FileLeaves(FileWanted { agent: "counter".into(), id: open.to_vec(), index: 0 });
    *lock(&t.a.inner.serve_delay) = Some(Duration::from_secs(2));
    for (part, body) in [("a chunk", chunk_of(&open, 0)), ("hashes", leaves)] {
        for how in ["stops the stream", "closes the connection"] {
            let reads = t.a.inner.served_reads.load(Ordering::SeqCst);
            let decided = t.a.inner.served_decisions.load(Ordering::SeqCst);
            let started = Instant::now();
            let (connection, mut streams) = unread_on(&t.b_net, "~nec", "~zod", vec![body.clone()]);
            // The job is past its decision (made, and counted, under the slot, just before the
            // seam's wait begins), so what follows is the job waiting, not a job not yet begun.
            let past_decision = || t.a.inner.served_decisions.load(Ordering::SeqCst) == decided + 1;
            settle("the job decided and waiting", Duration::from_secs(2), || in_hand() == 1 && past_decision(), || format!("{} in hand, decided: {}", in_hand(), past_decision()));
            match how {
                "stops the stream" => {
                    let (_send, receive) = &mut streams[0];
                    receive.stop(quinn::VarInt::from_u32(0)).unwrap();
                }
                _ => connection.close(quinn::VarInt::from_u32(0), b"giving up"),
            }
            // The job's share stays until it returns, after its wait.
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(in_hand(), 1, "{part}, {how}: the job's share went before it returned");
            while in_hand() > 0 {
                assert!(started.elapsed() < Duration::from_secs(10), "{part}, {how}");
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(started.elapsed() >= Duration::from_secs(2));
            assert_eq!(t.a.inner.served_reads.load(Ordering::SeqCst), reads, "{part}, {how}: read after the asker gave up");
            drop(streams);
            t.b_net.ping("~nec", "~zod").unwrap();
        }
    }
}

/// A request turned away for want of a place has `request_timeout`, not `file_timeout`, to
/// deliver its refusal: stuck behind unread chunks, its stream is reset when that runs out.
/// Seen with `received_reset`, which takes nothing of what waits on the stream. (G7)
#[test]
fn a_refusal_for_want_of_a_place_has_request_timeout_to_be_taken() {
    let short = NetConfig { request_timeout: Duration::from_secs(2), ..NetConfig::default() };
    let t = two_with("turned-away-time", (fast(), short), (fast(), NetConfig::default()), &["~nec"]);
    let big = put(&t.a, "~zod", "counter", &contents(CHUNK as usize, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&big)));
    t.b_net.ping("~nec", "~zod").unwrap();
    let mut held = unread(&t.b_net, "~nec", "~zod", (0..6).map(|_| chunk_of(&big, 0)).collect());
    std::thread::sleep(Duration::from_millis(700));
    // Four more: at most one finds a place; the rest are turned away behind the chunks.
    let sent = Instant::now();
    let mut extra = unread(&t.b_net, "~nec", "~zod", (0..4).map(|_| chunk_of(&big, 0)).collect());
    let resets = t.b_net.threads.get().block_on(async {
        let mut resets = 0;
        for (_send, receive) in extra.iter_mut() {
            let deadline = tokio::time::Instant::from_std(sent + Duration::from_secs(4));
            if let Ok(Ok(Some(_))) = tokio::time::timeout_at(deadline, receive.received_reset()).await {
                resets += 1;
            }
        }
        resets
    });
    assert!(resets >= 3, "{resets} of the refusals reset within 4 s");
    held.append(&mut extra);
    drop(held);
}

/// A request for a part of a file, encoded by hand: `wanted`, with `pad` bytes of a field no
/// message here has (field 15), which a decoder passes over.
fn padded_request(wanted: &FileWanted, pad: usize) -> Vec<u8> {
    fn varint(mut n: usize, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut inner = wanted.encode_to_vec();
    if pad > 0 {
        inner.push((15 << 3) | 2);
        varint(pad, &mut inner);
        inner.extend(std::iter::repeat(b'x').take(pad));
    }
    let mut outer = vec![(7 << 3) | 2];
    varint(inner.len(), &mut outer);
    outer.extend(inner);
    outer
}

/// Send raw requests on the connection the network keeps, without reading the replies.
fn unread_raw(net: &Network, from: &str, to: &str, requests: Vec<Vec<u8>>) -> Vec<(quinn::SendStream, quinn::RecvStream)> {
    let (from, to) = (from.trim_start_matches('~').to_string(), to.trim_start_matches('~').to_string());
    net.threads.get().block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let (connection, _) = net.shared.connection(&from, &to, deadline).await.unwrap();
        let mut streams = Vec::new();
        for request in requests {
            let (mut send, receive) = connection.open_bi().await.unwrap();
            send.write_all(&request).await.unwrap();
            send.finish().unwrap();
            streams.push((send, receive));
        }
        streams
    })
}

/// Send one raw request and read its reply.
fn ask_raw(net: &Network, from: &str, to: &str, request: Vec<u8>) -> PeerReply {
    let mut streams = unread_raw(net, from, to, vec![request]);
    let (_send, receive) = &mut streams[0];
    let bytes = net.threads.get().block_on(receive.read_to_end(4 << 20)).unwrap();
    PeerReply::decode(&*bytes).unwrap()
}

/// A request for a part of a file over 1,024 bytes is refused before anything is looked up or
/// any place taken, the same whatever it names; one within the bound is answered. And with
/// every place held, requests of the largest size allowed that are turned away, their refusals
/// stuck behind unread chunks, hold no room. (G4, G7)
#[test]
fn a_file_request_is_small_and_nothing_it_sized_outlives_its_room() {
    let t = two_with("small", (fast(), NetConfig::default()), (fast(), NetConfig::default()), &["~nec", "~bud", "~wes"]);
    let big = put(&t.a, "~zod", "counter", &contents(CHUNK as usize, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&big)));
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let rooms = || (shared.cfg.max_reading_bytes - shared.reading.available_permits()) / shared.cfg.max_message_bytes;
    let wanted = |id: &[u8; 32]| FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 };
    let decisions = t.a.inner.served_decisions.load(Ordering::SeqCst);
    // Over the bound: refused, the same for a file that is there and open and one that is not.
    let refusals: Vec<Vec<u8>> = [big, [7; 32]].iter().map(|id| ask_raw(&t.b_net, "~nec", "~zod", padded_request(&wanted(id), 1100)).encode_to_vec()).collect();
    assert_eq!(PeerReply::decode(&*refusals[0]).unwrap(), PeerReply { body: None, refused: super::FILE_REQUEST_TOO_LARGE.into() });
    assert_eq!(refusals[0], refusals[1]);
    assert_eq!((in_hand(), t.a.inner.served_decisions.load(Ordering::SeqCst)), (0, decisions), "a request too large was looked into");
    // Within it, the field passed over: answered.
    let largest = |id: &[u8; 32]| {
        let base = padded_request(&wanted(id), 0).len();
        let mut pad = super::MOST_FILE_REQUEST_BYTES - base - 4;
        while padded_request(&wanted(id), pad).len() > super::MOST_FILE_REQUEST_BYTES {
            pad -= 1;
        }
        padded_request(&wanted(id), pad)
    };
    assert!(largest(&big).len() > super::MOST_FILE_REQUEST_BYTES - 8 && largest(&big).len() <= super::MOST_FILE_REQUEST_BYTES);
    assert!(matches!(ask_raw(&t.b_net, "~nec", "~zod", largest(&big)).body, Some(peer_reply::Body::FileAbout(FileFacts { length, .. })) if length == CHUNK));
    // Every place held by unread chunks on three connections; then on one whose window is
    // full, three of the largest allowed size, turned away behind the chunks: no room held.
    let mut held = fill_places(&t.b_net, shared, &["~nec", "~bud", "~wes"], chunk_of(&big, 0));
    held.push(unread_raw(&t.b_net, "~nec", "~zod", (0..3).map(|_| largest(&big)).collect()));
    // The three are refused at once; the rooms come down to the places held, and stay there.
    settle("turned away at the largest size, and holding room", Duration::from_secs(5), || (in_hand(), rooms()) == (8, 8), || format!("{} in hand, {} rooms", in_hand(), rooms()));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!((in_hand(), rooms()), (8, 8), "turned away at the largest size, and holding room");
    drop(held);
}

/// The given-up check is made again under the slot before any row is read: a request given up
/// on while its job waits for the ship's slot, before its decision or before a batch of
/// hashes, reads nothing; and one given up on between two batches reads no more. (G7)
#[test]
fn a_request_given_up_on_while_its_job_waits_for_the_slot_reads_nothing() {
    let t = two("slot-wait");
    let data = contents(3 * CHUNK as usize, 1);
    let id = put(&t.a, "~zod", "counter", &data, "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&id)));
    t.b_net.ping("~nec", "~zod").unwrap();
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let leaves = || peer_request::Body::FileLeaves(FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 });
    let counts = || (t.a.inner.served_decisions.load(Ordering::SeqCst), t.a.inner.served_reads.load(Ordering::SeqCst));
    let hold_slot = |from: Duration, long: Duration| {
        let a = t.a.clone();
        std::thread::spawn(move || {
            std::thread::sleep(from);
            a.inner.with_ship("~zod", |_| {
                std::thread::sleep(long);
                Ok(())
            })
            .unwrap();
        })
    };
    let wait_out = |started: Instant| {
        while in_hand() > 0 {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // Before its decision: the slot is held from the start; the asker stops at 0.5 s.
    let (decided, read) = counts();
    let started = Instant::now();
    let holder = hold_slot(Duration::ZERO, Duration::from_millis(1500));
    std::thread::sleep(Duration::from_millis(100));
    let mut streams = unread(&t.b_net, "~nec", "~zod", vec![leaves()]);
    std::thread::sleep(Duration::from_millis(400));
    streams[0].1.stop(quinn::VarInt::from_u32(0)).unwrap();
    holder.join().unwrap();
    wait_out(started);
    assert_eq!(counts(), (decided, read), "decided or read after the asker gave up");
    drop(streams);

    // Before a batch: decided, then held after the decision for 1 s (past the outer check
    // only once the slot is taken by another, from 0.3 s to 2.3 s); the asker stops at 1.5 s.
    *lock(&t.a.inner.serve_delay) = Some(Duration::from_secs(1));
    let (decided, read) = counts();
    let started = Instant::now();
    let mut streams = unread(&t.b_net, "~nec", "~zod", vec![leaves()]);
    let holder = hold_slot(Duration::from_millis(300), Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(1500));
    streams[0].1.stop(quinn::VarInt::from_u32(0)).unwrap();
    holder.join().unwrap();
    wait_out(started);
    assert_eq!(counts(), (decided + 1, read), "a batch read after the asker gave up");
    drop(streams);
    *lock(&t.a.inner.serve_delay) = None;

    // Between batches: one hash a batch, a second after each; the asker stops during the first
    // wait. One batch read, not three.
    t.a.inner.hash_batch.store(1, Ordering::SeqCst);
    *lock(&t.a.inner.batch_delay) = Some(Duration::from_secs(1));
    let (decided, read) = counts();
    let started = Instant::now();
    let mut streams = unread(&t.b_net, "~nec", "~zod", vec![leaves()]);
    std::thread::sleep(Duration::from_millis(500));
    streams[0].1.stop(quinn::VarInt::from_u32(0)).unwrap();
    wait_out(started);
    assert_eq!(counts(), (decided + 1, read + 1), "batches read after the asker gave up");
    drop(streams);
    // Not given up on, the same request reads all three.
    *lock(&t.a.inner.batch_delay) = None;
    let reply = t.b.ask_for_file("~nec", "~zod", PeerRequest { body: Some(leaves()) }).unwrap().unwrap();
    assert!(matches!(reply.body, Some(peer_reply::Body::FileLeaves(sent)) if sent.hashes.len() == 3 * 32));
    assert_eq!(counts().1, read + 1 + 3);
    t.a.inner.hash_batch.store(0, Ordering::SeqCst);
}

/// Length-delimited fields `(number, contents)`, one after another, encoded by hand.
fn fields(of: &[(u64, Vec<u8>)]) -> Vec<u8> {
    fn varint(mut n: u64, out: &mut Vec<u8>) {
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut out = Vec::new();
    for (number, contents) in of {
        varint((number << 3) | 2, &mut out);
        varint(contents.len() as u64, &mut out);
        out.extend_from_slice(contents);
    }
    out
}

/// An envelope with more than one body field is refused before it is decoded, the same
/// whatever it names, with no place taken and no decision made; and every refusal, of a file
/// kind or of a kind that came before, left untaken holds no room. (G4, G7, G9)
#[test]
fn one_body_a_request_and_no_refusal_holds_room() {
    let t = two_with("one-body", (fast(), NetConfig::default()), (fast(), NetConfig::default()), &["~nec", "~bud"]);
    let big = put(&t.a, "~zod", "counter", &contents(CHUNK as usize, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&big)));
    let shared = &t.a_net.shared;
    let in_hand = || super::MOST_FILES_ANSWERING - shared.files_answering.available_permits();
    let rooms = || (shared.cfg.max_reading_bytes - shared.reading.available_permits()) / shared.cfg.max_message_bytes;
    let wanted = |id: &[u8; 32]| FileWanted { agent: "counter".into(), id: id.to_vec(), index: 0 }.encode_to_vec();
    // A delivery of 257 empty messages: one over its count.
    let crowded = fields(&vec![(1u64, Vec::new()); 257]);
    let envelopes = |id: &[u8; 32]| -> Vec<(&str, Vec<u8>)> {
        vec![
            ("a delivery over its count, then a file kind", fields(&[(2, crowded.clone()), (7, wanted(id))])),
            ("the same, padded past 1,024 bytes", fields(&[(2, crowded.clone()), (7, wanted(id)), (99, vec![b'x'; 2000])])),
            ("two file kinds", fields(&[(7, wanted(id)), (10, wanted(id))])),
            ("the same kind twice", fields(&[(7, wanted(id)), (7, wanted(id))])),
            ("a ping, then a file kind", fields(&[(1, ship_proto::Ping { nonce: vec![1] }.encode_to_vec()), (8, wanted(id))])),
            // A body field given as a number is a body field all the same.
            ("a file kind given as a number, then a file kind", [vec![7 << 3, 1], fields(&[(8, wanted(id))])].concat()),
        ]
    };
    let decided = t.a.inner.served_decisions.load(Ordering::SeqCst);
    for ((why, there), (_, absent)) in envelopes(&big).into_iter().zip(envelopes(&[7; 32])) {
        let (there, absent) = (ask_raw(&t.b_net, "~bud", "~zod", there), ask_raw(&t.b_net, "~bud", "~zod", absent));
        assert_eq!(there, PeerReply { body: None, refused: super::ONE_AT_A_TIME.into() }, "{why}");
        assert_eq!(there.encode_to_vec(), absent.encode_to_vec(), "{why}");
    }
    assert_eq!((in_hand(), t.a.inner.served_decisions.load(Ordering::SeqCst)), (0, decided), "an envelope of two bodies was looked into");
    // One body, and the earlier kinds as before: a delivery over its count, something that is
    // not a request, a request of no kind, and a hello after the first.
    let over = ask_raw(&t.b_net, "~bud", "~zod", fields(&[(2, crowded.clone())]));
    assert_eq!(over.refused, "not a request, or one with too many messages");
    assert_eq!(ask_raw(&t.b_net, "~bud", "~zod", vec![0xff, 0xff, 0xff]).refused, "not a request, or one with too many messages");
    assert_eq!(ask_raw(&t.b_net, "~bud", "~zod", Vec::new()).refused, super::UNKNOWN_REQUEST);
    let hello = fields(&[(6, ship_proto::Hello { ship: "bud".into(), proof: None }.encode_to_vec())]);
    assert_eq!(ask_raw(&t.b_net, "~bud", "~zod", hello.clone()).refused, super::UNKNOWN_REQUEST);
    // Now every one of those left untaken, behind a chunk stuck on ~nec's connection: only the
    // stuck chunk holds room.
    let before_stuck = t.a.inner.served_decisions.load(Ordering::SeqCst);
    let mut stuck = unread(&t.b_net, "~nec", "~zod", vec![chunk_of(&big, 0), chunk_of(&big, 0)]);
    // Both set-up chunks decided, the first taken by QUIC alone and the second stuck: only then
    // is the baseline taken.
    let both_decided = || t.a.inner.served_decisions.load(Ordering::SeqCst) == before_stuck + 2;
    settle("one chunk stuck", Duration::from_secs(5), || both_decided() && in_hand() == 1 && rooms() == 1, || format!("{} in hand, {} rooms, both decided: {}", in_hand(), rooms(), both_decided()));
    let decided = t.a.inner.served_decisions.load(Ordering::SeqCst);
    let mut refusals: Vec<Vec<u8>> = envelopes(&big).into_iter().map(|(_, bytes)| bytes).collect();
    refusals.extend([fields(&[(2, crowded.clone())]), vec![0xff, 0xff, 0xff], Vec::new(), hello, padded_request(&FileWanted { agent: "counter".into(), id: big.to_vec(), index: 0 }, 1100)]);
    let count = refusals.len();
    stuck.extend(unread_raw(&t.b_net, "~nec", "~zod", refusals));
    settle("refusals left untaken holding no room", Duration::from_secs(5), || (in_hand(), rooms()) == (1, 1), || format!("{} in hand, {} rooms", in_hand(), rooms()));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!((in_hand(), rooms()), (1, 1), "{count} refusals left untaken hold room");
    assert_eq!(t.a.inner.served_decisions.load(Ordering::SeqCst), decided);
    drop(stuck);
}

/// The job is given only values of this runtime's own size: a request whose agent's name is
/// given twice (900 bytes, then a real name) is served as the real name, and the decoded request
/// is dropped before the job runs (argued from `serve_file`: the job is given a fresh copy of
/// the checked name and a 32-byte array). A name or an id that does not pass is the same no.
/// That no job is scheduled for one is read from `serve_file`, not shown here: the decision
/// counter below stays put for it, but `Runtime::serve_file` would also return before counting
/// for such a name. (G4, G7)
#[test]
fn the_job_holds_only_values_of_this_runtimes_size() {
    let t = two("own-size");
    let open = put(&t.a, "~zod", "counter", &contents(10, 1), "");
    say(&t.a, "~zod", "counter", &format!("open {}", hex(&open)));
    let twice = fields(&[(1, vec![b'a'; 900]), (1, b"counter".to_vec()), (2, open.to_vec())]);
    let request = fields(&[(7, twice)]);
    assert!(request.len() <= super::MOST_FILE_REQUEST_BYTES);
    let reply = ask_raw(&t.b_net, "~nec", "~zod", request);
    assert!(matches!(reply.body, Some(peer_reply::Body::FileAbout(FileFacts { length: 10, .. }))), "{reply:?}");
    // A bad name, or an id of the wrong length: the same no as any other.
    let decided = t.a.inner.served_decisions.load(Ordering::SeqCst);
    let no = |agent: &[u8], id: &[u8]| ask_raw(&t.b_net, "~nec", "~zod", fields(&[(7, fields(&[(1, agent.to_vec()), (2, id.to_vec())]))])).encode_to_vec();
    let ordinary = no(b"counter", &[7; 32]);
    assert_eq!(t.a.inner.served_decisions.load(Ordering::SeqCst), decided + 1);
    assert_eq!(no(b"Not An Agent", &open), ordinary);
    assert_eq!(no(&[b'a'; 900], &open), ordinary);
    assert_eq!(no(b"counter", &open[..31]), ordinary);
    // No decision for them (which a job given such a name would not have made either).
    assert_eq!(t.a.inner.served_decisions.load(Ordering::SeqCst), decided + 1, "a decision was made for a name or an id that does not pass");
}

/// Files on the ship, part 3: what was opened is kept, and a copy can be saved. Here, so as to
/// use the two runtimes and the liar above.
#[path = "kept_tests.rs"]
mod kept_tests;
