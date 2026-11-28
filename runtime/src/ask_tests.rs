//! Questions between ships ("asks") and receipts that bring the handler's reply back. Real
//! runtimes on this machine, each with its network, keys set by hand. Inside the crate, so that
//! a network can vanish as a machine does (`Network::vanish`), the parts that decide can be
//! reached, and what the ship that answers did can be read off (`Inner::answered`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ship_proto::{peer_reply, peer_request, Ask, Kind, Outcome, PeerReply, PeerRequest, Source};

use super::{Directory, NetConfig, NetError, Network, TOO_BUSY};
use crate::server::{Server, ServerConfig};
use crate::ship::Settled;
use crate::{lock, AskError, Config, Durability, Error, Manifest, Provide, Rejection, Runtime, Use};

fn wasm(name: &str) -> Vec<u8> {
    super::router_tests::wasm(name)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-ask-{label}", std::process::id()));
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

/// The counter agent with its `counter` interface open to questions (`asked`) and to commands
/// (`remote`) as given, and its journal open to neither.
fn counter_with(asked: bool, remote: bool) -> Manifest {
    Manifest {
        provides: vec![
            Provide { interface: "counter".into(), public: false, remote, asked },
            Provide { interface: "journal".into(), public: false, remote: false, asked: false },
        ],
        uses: vec![],
    }
}

/// The tally agent, open to other ships, with leave to send to and ask the counter on `ship`
/// (its counter and journal interfaces), and to send to the tally there.
fn asking_tally(ship: &str) -> Manifest {
    let counter = Use { ship: ship.into(), agent: "counter".into(), interface: "counter".into(), read: true, send: true, ask: true };
    let journal = Use { ship: ship.into(), agent: "counter".into(), interface: "journal".into(), read: false, send: false, ask: true };
    let tally = Use { ship: ship.into(), agent: "tally".into(), interface: "tally".into(), read: false, send: true, ask: false };
    Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true, asked: false }], uses: vec![counter, journal, tally] }
}

/// The same module as tally, under the name `mute`, with leave to send to the counter on
/// `ship` and not to ask it.
fn mute_tally(ship: &str) -> Manifest {
    let counter = Use { ship: ship.into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true, ask: false };
    Manifest { provides: vec![Provide { interface: "mute".into(), public: false, remote: false, asked: false }], uses: vec![counter] }
}

/// A runtime holding `ships`, each with the counter (as `counter` says) and tally (asking
/// `other`), and `mute`.
fn crewed(dir: &Path, cfg: Config, ships: &[&str], counter: &Manifest, other: &str) -> Arc<Runtime> {
    let rt = Arc::new(Runtime::open(dir, cfg).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let (counter_module, tally) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    for ship in ships {
        if rt.create_ship(ship, &kernel).is_ok() {
            rt.install(ship, "counter", &counter_module, counter).unwrap();
            rt.install(ship, "tally", &tally, &asking_tally(other.trim_start_matches('~'))).unwrap();
            rt.install(ship, "mute", &tally, &mute_tally(other.trim_start_matches('~'))).unwrap();
        }
    }
    rt
}

/// ~zod on runtime `a`, answering; ~nec (and any more of `b_ships`) on runtime `b`, asking.
struct Two {
    a: Arc<Runtime>,
    a_net: Option<Network>,
    b: Arc<Runtime>,
    b_net: Option<Network>,
    directory: Arc<Directory>,
    dirs: (TempDir, TempDir),
}

fn two(label: &str, counter: Manifest) -> Two {
    two_with(label, (fast(), NetConfig::default()), (fast(), NetConfig::default()), counter, &["~nec"])
}

fn two_with(label: &str, (a_cfg, a_net): (Config, NetConfig), (b_cfg, b_net): (Config, NetConfig), counter: Manifest, b_ships: &[&str]) -> Two {
    let dirs = (TempDir::new(&format!("{label}-a")), TempDir::new(&format!("{label}-b")));
    let directory = Directory::new();
    let a = crewed(&dirs.0 .0, a_cfg, &["~zod"], &counter, "~nec");
    let a_net = Network::start(a.clone(), directory.clone(), a_net).unwrap();
    directory.set("~zod", a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    let b = crewed(&dirs.1 .0, b_cfg, b_ships, &counter_with(true, true), "~zod");
    let b_net = Network::start(b.clone(), directory.clone(), b_net).unwrap();
    for ship in b_ships {
        directory.set(ship, b.public_key(ship).unwrap(), b_net.addr()).unwrap();
    }
    Two { a, a_net: Some(a_net), b, b_net: Some(b_net), directory, dirs }
}

/// Stop a runtime (dropping `held`, its last handle, after its network) and open its directory
/// again, once the old one has let go of it.
fn reopen(held: &mut Arc<Runtime>, net: &mut Option<Network>, dir: &Path, cfg: Config, scratch: &Path) {
    drop(net.take());
    drop(std::mem::replace(held, Arc::new(Runtime::open(scratch, fast()).unwrap())));
    let started = Instant::now();
    *held = loop {
        match Runtime::open(dir, cfg.clone()) {
            Ok(rt) => break Arc::new(rt),
            Err(Error::DataDirInUse) if started.elapsed() < Duration::from_secs(10) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("{e}"),
        }
    };
}

fn say(rt: &Runtime, ship: &str, agent: &str, command: &str) -> String {
    String::from_utf8(rt.deliver(ship, agent, command.as_bytes()).unwrap().reply).unwrap()
}

fn view(rt: &Runtime, ship: &str, agent: &str, request: &str) -> String {
    String::from_utf8(rt.read(ship, agent, agent, request.as_bytes()).unwrap()).unwrap()
}

/// The answers the tally agent on `ship` has been handed, one to a line.
fn answers(rt: &Runtime, ship: &str) -> Vec<String> {
    view(rt, ship, "tally", "answers").lines().map(str::to_string).collect()
}

/// The answers handed over for the question numbered `n`.
fn answers_to(rt: &Runtime, ship: &str, n: &str) -> Vec<String> {
    answers(rt, ship).into_iter().filter(|line| line.split(' ').next() == Some(n)).collect()
}

fn receipts(rt: &Runtime, ship: &str) -> Vec<String> {
    view(rt, ship, "tally", "receipts").lines().map(str::to_string).collect()
}

/// Start `deliver` of `event` to `agent` on `ship` on a thread of its own, and return once it
/// has begun, with the ship in hand (the runtime says so for the next event it starts), so
/// that what follows meets the ship held.
fn hold_with_event(rt: &Arc<Runtime>, ship: &'static str, agent: &'static str, event: &'static [u8]) -> std::thread::JoinHandle<Result<crate::Outcome, Error>> {
    let (started, has_it) = std::sync::mpsc::channel();
    *lock(&rt.inner.event_started) = Some(started);
    let held = rt.clone();
    let thread = std::thread::spawn(move || held.deliver(ship, agent, event));
    has_it.recv_timeout(Duration::from_secs(10)).expect("the event to begin");
    thread
}

fn eventually(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < within, "waited {within:?} for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Ask from ~nec's owner (or `agent` there) on runtime `b`, giving `within`.
fn ask(t: &Two, agent: Option<&str>, interface: &str, payload: &[u8], within: Duration) -> Result<Vec<u8>, AskError> {
    t.b.ask("~nec", agent, "~zod", "counter", interface, payload, within)
}

/// Every table's row count on a ship.
fn rows(rt: &Runtime, ship: &str) -> BTreeMap<String, i64> {
    rt.inner
        .with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            let mut counts = BTreeMap::new();
            for table in tables {
                counts.insert(table.clone(), conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| r.get(0))?);
            }
            Ok(counts)
        })
        .unwrap()
}

/// The sizes of a ship's file (the runtime's own path for it: it must be there) and of the log
/// SQLite keeps beside it (0 only if there is none).
fn file_sizes(rt: &Runtime, ship: &str) -> (u64, u64) {
    let file = rt.inner.ship_path(&crate::canonical_ship(ship).unwrap());
    let wal = PathBuf::from(format!("{}-wal", file.display()));
    let main = fs::metadata(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display())).len();
    let wal = match fs::metadata(&wal) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => panic!("{}: {e}", wal.display()),
    };
    (main, wal)
}

/// The questions the ship asked has answered so far, by asking ship.
fn answered_from(rt: &Runtime, caller: &str) -> usize {
    lock(&rt.inner.answered).iter().filter(|(_, _, from)| from == caller).count()
}

impl Network {
    /// For tests: send `request` from `from` to `to`, waiting at most `within` (and giving up,
    /// resetting the stream, after that).
    fn ask_raw(&self, from: &str, to: &str, request: PeerRequest, within: Duration) -> Result<PeerReply, NetError> {
        let shared = self.shared.clone();
        let (from, to) = (from.to_string(), to.to_string());
        let (report, outcome) = std::sync::mpsc::channel();
        self.threads.get().spawn(async move {
            let _ = report.send(shared.ask_within(&from, &to, request, within).await.map(|(reply, _)| reply));
        });
        outcome.recv().unwrap()
    }
}

fn question(from_agent: &str, interface: &str, payload: &[u8], within_millis: u64) -> PeerRequest {
    let asked = Ask { from_agent: from_agent.into(), agent: "counter".into(), interface: interface.into(), payload: payload.to_vec(), within_millis };
    PeerRequest { body: Some(peer_request::Body::Ask(asked)) }
}

/// A question is answered through `Runtime::ask`, over HTTP for the owner's device, and to an
/// agent as one `answer` event; the agent asked is told which ship and agent asks, and an
/// owner's question names no agent.
#[test]
fn a_question_is_answered_through_the_api_over_http_and_to_an_agent() {
    let t = two("answered", counter_with(true, false));
    say(&t.a, "~zod", "counter", "inc hits 5");
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"5");
    assert_eq!(ask(&t, None, "counter", b"?who", Duration::from_secs(10)).unwrap(), b"~nec/");
    assert_eq!(ask(&t, Some("tally"), "counter", b"?who", Duration::from_secs(10)).unwrap(), b"~nec/tally");

    // Over HTTP, as the owner of ~nec.
    let server = Server::start(t.b.clone(), ServerConfig::default()).unwrap();
    let code = t.b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", t.b.sign_in("~nec", &code, "test").unwrap().0);
    let answer = http(&server, "POST", "/ships/nec/ask/zod/counter/counter?within=5", &auth, b"?who");
    assert_eq!((answer.0, answer.2.as_slice()), (200, &b"~nec/"[..]));
    assert!(answer.1.contains("X-Content-Type-Options: nosniff") && answer.1.contains("Content-Security-Policy: sandbox; default-src 'none'"), "{}", answer.1);
    // A question to this same ship, or no device: refused before anything is asked.
    assert_eq!(http(&server, "POST", "/ships/nec/ask/nec/counter/counter", &auth, b"hits").0, 400);
    assert_eq!(http(&server, "POST", "/ships/nec/ask/zod/counter/counter?within=0", &auth, b"hits").0, 400);
    assert_eq!(http(&server, "POST", "/ships/nec/ask/zod/counter/counter", "Bearer nobody", b"hits").0, 401);

    // To an agent, which is handed one answer, naming who answered.
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 ?who");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter reply [] ~nec/tally from ~zod/counter counter")]);
}

/// What `http` gives back: the status, the head, and the body.
fn http(server: &Server, method: &str, path: &str, auth: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let head = format!("{method} {path} HTTP/1.0\r\nHost: {}\r\nAuthorization: {auth}\r\nContent-Length: {}\r\n\r\n", server.addr(), body.len());
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let top = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = top.split(' ').nth(1).unwrap().parse().unwrap();
    (status, top, raw[split + 4..].to_vec())
}

/// A question is refused unless the interface is open to questions: not when it is open only
/// to commands, nor when it is open to neither; and an agent whose manifest does not let it ask
/// is refused here, its event with it, and nothing is sent.
#[test]
fn a_question_is_refused_unless_the_interface_is_open_to_questions() {
    // Open to commands only.
    let t = two("refused", counter_with(false, true));
    match ask(&t, None, "counter", b"hits", Duration::from_secs(10)) {
        Err(AskError::Denied(why)) => assert!(why.contains("counter on counter is not open to other ships"), "{why}"),
        other => panic!("{other:?}"),
    }
    // Open to neither.
    assert!(matches!(ask(&t, None, "journal", b"hits", Duration::from_secs(10)), Err(AskError::Denied(_))));
    // An agent is handed the refusal, once: nothing more comes when the question's time runs
    // out after it, nor when the network looks through the ship's questions again (as it does
    // for the next question asked).
    let asked = Instant::now();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1500 hits");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    let next = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1500 hits");
    eventually("the next answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &next).is_empty());
    std::thread::sleep((asked + Duration::from_millis(2500)).saturating_duration_since(Instant::now()));
    assert_eq!(answers_to(&t.b, "~nec", &n).len(), 1, "{:?}", answers(&t.b, "~nec"));
    assert!(answers_to(&t.b, "~nec", &n)[0].contains(" denied [counter on counter is not open to other ships] "), "{:?}", answers(&t.b, "~nec"));
    // Over HTTP: 403, saying so.
    let server = Server::start(t.b.clone(), ServerConfig::default()).unwrap();
    let code = t.b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", t.b.sign_in("~nec", &code, "test").unwrap().0);
    let refused = http(&server, "POST", "/ships/nec/ask/zod/counter/counter", &auth, b"hits");
    assert_eq!(refused.0, 403);
    assert!(String::from_utf8_lossy(&refused.2).contains("not open to other ships"));

    // An agent whose manifest names the ship but not `ask`: its event is refused here, writes
    // no question, and nothing reaches ~zod.
    let before = (rows(&t.b, "~nec")["asks"], answered_from(&t.a, "nec"));
    assert!(matches!(t.b.deliver("~nec", "mute", b"ask-on zod counter counter 5000 hits"), Err(Error::Rejected(Rejection::Denied(_)))));
    // Nor to this same ship, nor with no time at all, nor more time than allowed.
    for asked in ["ask-on nec counter counter 5000 hits", "ask-on zod counter counter 0 hits", "ask-on zod counter counter 60001 hits"] {
        assert!(matches!(t.b.deliver("~nec", "tally", asked.as_bytes()), Err(Error::Rejected(_))), "{asked}");
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!((rows(&t.b, "~nec")["asks"], answered_from(&t.a, "nec")), before);
}

/// The handler answering a question can change nothing: each try to write, send (here or to
/// another ship), emit, append, mark a file, or ask fails it, and nothing of it is kept: the same
/// rows in every table, and the same lengths of the ship's file and of its `-wal` (the ship is
/// awake, so a change could sit in the `-wal`, whose length is compared). Lengths and row counts,
/// not the bytes.
#[test]
fn the_handler_answering_a_question_can_change_nothing() {
    let t = two("meddle", counter_with(true, false));
    let id = crate::files::id_of(b"x");
    let before = rows(&t.a, "~zod");
    let sizes = file_sizes(&t.a, "~zod");
    for probe in ["?write", "?send", "?send-far nec", "?emit", "?append", &format!("?mark {}", hex(&id)), "?ask nec"] {
        assert_eq!(ask(&t, None, "counter", probe.as_bytes(), Duration::from_secs(10)), Err(AskError::Failed), "{probe}");
    }
    assert_eq!(rows(&t.a, "~zod"), before);
    assert_eq!(file_sizes(&t.a, "~zod"), sizes);
    assert_eq!(t.a.log_head("~zod", "counter", "counter").unwrap(), None);
    assert!(t.a.drain_outbox("~zod", 1 << 20).unwrap().is_empty());
    assert_eq!(say(&t.a, "~zod", "counter", "get meddled"), "0");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A handler that traps, or runs out of fuel, or is slow, fails the question within the limits,
/// and the ship goes on answering and running events.
#[test]
fn a_handler_that_traps_runs_out_or_is_slow_fails_in_time() {
    // Little fuel: a handler that spins runs out of it.
    let t = two_with("fail-fuel", (Config { ask_fuel: 2_000_000, ..fast() }, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    assert_eq!(ask(&t, None, "counter", b"?trap", Duration::from_secs(10)), Err(AskError::Failed));
    let started = Instant::now();
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    assert_eq!(say(&t.a, "~zod", "counter", "inc hits"), "1");

    // Fuel without end and 400 ms: a handler that spins is stopped at its time.
    let t = two_with("fail-slow", (Config { ask_fuel: 1 << 50, ask_millis: 400, ..fast() }, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    let started = Instant::now();
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(400) && took < Duration::from_secs(3), "{took:?}");
    let held = lock(&t.a.inner.answered).last().unwrap().1;
    assert!(held < Duration::from_millis(700), "{held:?}");
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    assert_eq!(say(&t.a, "~zod", "counter", "inc hits"), "1");
    // And the asker's own time, if shorter, is the limit: 200 ms here.
    std::thread::sleep(Duration::from_secs(2));
    let asked = t.b_net.as_ref().unwrap().ask_raw("~nec", "~zod", question("", "counter", b"?spin", 200), Duration::from_secs(5));
    let Ok(PeerReply { body: Some(peer_reply::Body::Ask(answer)), .. }) = asked else { panic!("{asked:?}") };
    assert!(matches!(answer.outcome, Some(ship_proto::answer::Outcome::Failed(_))));
    let held = lock(&t.a.inner.answered).last().unwrap().1;
    assert!(held < Duration::from_millis(500), "{held:?}");
}

/// A question or an answer over its limit: a question larger than this runtime asks is
/// refused here; one larger than the ship asked takes is answered `limit` there, with nothing
/// run; an answer larger than the ship asked gives, or than this one takes, is `limit`.
#[test]
fn questions_and_answers_over_their_limits() {
    let a_cfg = Config { max_answer_bytes: 512 << 10, ..fast() };
    let b_cfg = Config { max_ask_bytes: 128 << 10, ..fast() };
    let t = two_with("limits", (a_cfg, NetConfig::default()), (b_cfg, NetConfig::default()), counter_with(true, false), &["~nec"]);
    assert_eq!(ask(&t, None, "counter", &vec![b'q'; (128 << 10) + 1], Duration::from_secs(10)), Err(AskError::TooLarge));
    assert_eq!(ask(&t, None, "counter", &vec![b'q'; 100 << 10], Duration::from_secs(10)), Err(AskError::Limit));
    assert_eq!(answered_from(&t.a, "nec"), 0, "nothing ran for a question too large");
    // ~zod gives up to 512 KiB, ~nec takes 256 KiB.
    assert_eq!(ask(&t, None, "counter", b"?big 300000", Duration::from_secs(10)), Err(AskError::Limit));
    assert_eq!(ask(&t, None, "counter", b"?big 600000", Duration::from_secs(10)), Err(AskError::Limit));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(ask(&t, None, "counter", b"?big 200000", Duration::from_secs(10)).map(|reply| reply.len()), Ok(200000));
    // An agent is handed `limit` for an answer larger than its ship takes.
    std::thread::sleep(Duration::from_millis(300));
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 ?big 300000");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    assert!(answers_to(&t.b, "~nec", &n)[0].contains(" limit [the question or its answer is larger than one of the two ships allows] "), "{:?}", answers(&t.b, "~nec"));
}

/// A flood of questions from one ship holds to the places and allowances, and to the rests,
/// while another ship's questions are still answered. Read off the ship asked: every question
/// it admitted past its look at the rests (each it went on to run; questions refused there are
/// not counted, and are bounded by the start rates instead) began no sooner than three times
/// the last one's length after it ended, and nine times after the last one from the same ship.
#[test]
fn a_flood_of_questions_from_one_ship_is_held_to_its_limits_while_another_is_answered() {
    // Allowances to start questions too large to matter here, so that only the places and the
    // rests hold the flood (the allowances have a test of their own).
    let a_cfg = Config { ask_fuel: 20_000_000, ..fast() };
    let a_net = NetConfig { asks_per_second: 1_000_000, asks_per_second_each: 1_000_000, ..NetConfig::default() };
    let t = two_with("flood", (a_cfg, a_net), (fast(), NetConfig::default()), counter_with(true, false), &["~nec", "~bus"]);
    let flooding = Arc::new(AtomicBool::new(true));
    let (busy, failed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let mut threads = Vec::new();
    for _ in 0..12 {
        let (b, flooding, busy, failed) = (t.b.clone(), flooding.clone(), busy.clone(), failed.clone());
        threads.push(std::thread::spawn(move || {
            while flooding.load(Ordering::SeqCst) {
                match b.ask("~nec", None, "~zod", "counter", "counter", b"?spin", Duration::from_millis(300)) {
                    Err(AskError::Busy) => drop(busy.fetch_add(1, Ordering::SeqCst)),
                    Err(AskError::Failed) => drop(failed.fetch_add(1, Ordering::SeqCst)),
                    // Sent, and not answered in its 300 ms: it waited behind the others.
                    Err(AskError::NoAnswer) => {}
                    other => panic!("{other:?}"),
                }
            }
        }));
    }
    // While it floods, the places held are sampled, and ~bus asks now and then.
    let started = Instant::now();
    let mut served = 0;
    let shared = &t.a_net.as_ref().unwrap().shared;
    while started.elapsed() < Duration::from_secs(4) {
        {
            let questions = lock(&shared.questions);
            assert!(questions.running <= 8 && questions.each.get("nec").copied().unwrap_or(0) <= 2, "{} {:?}", questions.running, questions.each);
        }
        if started.elapsed().as_millis() % 250 < 10 && t.b.ask("~bus", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(2)).is_ok() {
            served += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    flooding.store(false, Ordering::SeqCst);
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(busy.load(Ordering::SeqCst) > 0 && failed.load(Ordering::SeqCst) > 0, "{busy:?} {failed:?}");
    assert!(served > 0, "~bus was never answered");
    // The rests, exactly, by the ship's own clock.
    let answered = lock(&t.a.inner.answered).clone();
    for pair in answered.windows(2) {
        let ((end, took, _), (next_end, next_took, _)) = (&pair[0], &pair[1]);
        assert!(*next_end - *next_took >= *end + *took * 3, "{pair:?}");
    }
    for caller in ["nec", "bus"] {
        let theirs: Vec<_> = answered.iter().filter(|(_, _, from)| from == caller).collect();
        for pair in theirs.windows(2) {
            let ((end, took, _), (next_end, next_took, _)) = (pair[0], pair[1]);
            assert!(*next_end - *next_took >= *end + *took * 9, "{caller} {pair:?}");
        }
    }
}

/// At most `asks_per_second_each` (8) questions a second are started for one ship, as many at
/// a stroke, however fast it asks: read off the ship asked.
#[test]
fn questions_from_one_ship_are_started_only_so_many_a_second() {
    let t = two("rate", counter_with(true, false));
    let asking = Arc::new(AtomicBool::new(true));
    let started = Instant::now();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let (b, asking) = (t.b.clone(), asking.clone());
            std::thread::spawn(move || {
                while asking.load(Ordering::SeqCst) {
                    let _ = b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_millis(200));
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_secs(2));
    asking.store(false, Ordering::SeqCst);
    for thread in threads {
        thread.join().unwrap();
    }
    let ran = answered_from(&t.a, "nec");
    assert!(ran >= 8, "{ran}");
    assert!(ran as f64 <= 8.0 + 8.0 * started.elapsed().as_secs_f64(), "{ran} in {:?}", started.elapsed());
}

/// A question whose asker gives up while it waits for the ship runs nothing; one whose asker
/// gives up while it runs is stopped for time, as any call is (not before its time). The asker
/// gives up by being called off (its task aborted) once the ship asked has said the question is
/// at the point under test (waiting for the ship's slot, the ship held by an event kept at a
/// gate; its handler's deadline set), and the ship asked has said it saw the asker gone ("question
/// given up") before the ship is let go, or (by its records) before the handler's deadline; each
/// job's end is waited for (its place given back) before anything is looked at. For the one given
/// up on while it runs, it checks both that the giving up was seen early and that the handler
/// still ran to its own time: its own stop for time no earlier than its deadline (and less than
/// 300 ms after), and the ship released in under 1.3 s.
#[test]
fn a_question_given_up_on_runs_nothing_more() {
    let a_cfg = Config { fuel_per_event: 1 << 50, max_event_millis: 2500, ask_fuel: 1 << 50, ask_millis: 3000, ..fast() };
    let t = two_with("given-up", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    let b_net = t.b_net.as_ref().unwrap();
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let give_up = |payload: &'static [u8], within: u64| {
        let shared = b_net.shared.clone();
        b_net.threads.get().spawn(async move {
            let _ = shared.ask_within("~nec", "~zod", question("", "counter", payload, within), Duration::from_secs(9)).await;
        })
    };
    let called_off = |asker: tokio::task::JoinHandle<()>| {
        asker.abort();
        assert!(b_net.threads.get().handle().block_on(asker).is_err_and(|e| e.is_cancelled()));
    };
    // The ship is held by an event kept at a gate until the asker's giving up has been seen.
    let from = t.a.inner.notes_len();
    let (holding, release) = hold_ship(&t.a, "~zod");
    let asker = give_up(b"hits", 3000);
    eventually("the question waiting for the ship", Duration::from_secs(5), || !t.a.inner.notes_of("question waiting for its slot", "nec", from).is_empty());
    called_off(asker);
    eventually("the asker's giving up seen", Duration::from_secs(5), || !t.a.inner.notes_of("question given up", "nec", from).is_empty());
    drop(release);
    assert!(holding.join().unwrap().is_ok());
    eventually("the question's job to end", Duration::from_secs(5), || t.a.inner.notes_of("question place given back", "nec", from).len() == 1);
    assert_eq!(answered_from(&t.a, "nec"), 0, "the question given up on was run");

    // Given up on while it runs: it runs until it is stopped for time (a second, its own): by
    // the runtime's record of its one stop, no earlier than its deadline and less than 300 ms
    // after it; and it held the ship less than 1.3 s (test thresholds).
    *lock(&t.a.inner.ask_rests) = Default::default();
    let from = t.a.inner.notes_len();
    let stops = stops_so_far(&t.a);
    let (told, set) = std::sync::mpsc::channel();
    *lock(&t.a.inner.deadline_set_for) = Some(("counter".to_string(), told));
    let asker = give_up(b"?spin", 1000);
    set.recv_timeout(Duration::from_secs(10)).expect("the handler's deadline set");
    called_off(asker);
    eventually("the asker's giving up seen", Duration::from_secs(5), || !t.a.inner.notes_of("question given up", "nec", from).is_empty());
    let seen = t.a.inner.notes_of("question given up", "nec", from)[0].0;
    let deadline = t.a.inner.notes_of("question deadline", "nec", from)[0].0;
    assert!(seen < deadline, "the giving up was seen {:?} after the handler's deadline", seen - deadline);
    eventually("the question's job to end", Duration::from_secs(5), || t.a.inner.notes_of("question place given back", "nec", from).len() == 1);
    assert_eq!(answered_from(&t.a, "nec"), 1);
    stopped_within(&t.a, "counter", stops, Duration::from_millis(300));
    let held = lock(&t.a.inner.answered).last().unwrap().1;
    assert!(held < Duration::from_millis(1300), "{held:?}");
}

/// How long ~zod's counter's one event since note `from` ran, from when it began to when it was
/// done with, by the runtime's own notes (exactly one of each).
fn event_took(rt: &Runtime, from: usize) -> Duration {
    let entered = rt.inner.notes_of("event entered", "zod/counter", from);
    let finished = rt.inner.notes_of("event finished", "zod/counter", from);
    assert!(entered.len() == 1 && finished.len() == 1, "{entered:?} {finished:?}");
    finished[0].0.saturating_duration_since(entered[0].0)
}

/// How many calls the runtime has recorded stopping for time so far: noted before a call, so
/// that only that call's stop is read after it.
fn stops_so_far(rt: &Runtime) -> usize {
    lock(&rt.inner.time_stops).len()
}

/// That exactly one call of `agent` was stopped for time since `from` (as `stops_so_far` said
/// before it), no earlier than its deadline and less than `allowed` after it, by the runtime's
/// own record: the deadline it was given, and the one reading of the clock the stop was decided
/// on.
fn stopped_within(rt: &Runtime, agent: &str, from: usize, allowed: Duration) {
    let fresh: Vec<_> = lock(&rt.inner.time_stops).iter().skip(from).filter(|(of, _, _)| of == agent).cloned().collect();
    assert_eq!(fresh.len(), 1, "stops of {agent} since: {fresh:?}");
    let (_, deadline, stopped) = fresh[0];
    assert!(stopped >= deadline, "stopped {:?} before its deadline", deadline - stopped);
    assert!(stopped - deadline < allowed, "stopped {:?} after its deadline", stopped - deadline);
}

/// The time limits follow the wall clock, not the watchdog's sleeps: with every sleep made
/// 15 ms long in place of 10 (as a system that wakes sleepers late does), an event given a
/// second runs all of it, and its whole run (by the runtime's notes of when the event began and
/// was done with) is under 1,115 ms (a test threshold: the second, one late sleep, 100 ms for
/// scheduling); by the runtime's own record of that call's one stop
/// it was stopped no earlier than its deadline and less than 115 ms after it (the same
/// threshold); and so for a question given a second, read from its own fresh record. (Counting
/// sleeps, as the watchdog once did, the event would run 102 x 15 ms, about 1.5 s.)
#[test]
fn time_limits_hold_when_the_watchdog_wakes_late() {
    let a_cfg = Config { fuel_per_event: 1 << 50, max_event_millis: 1000, ask_fuel: 1 << 50, ask_millis: 1000, ..fast() };
    let t = two_with("late-clock", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    t.a.inner.watching.lag.store(5, Ordering::SeqCst);
    let most = Duration::from_millis(1000 + 15 + 100);
    let from = stops_so_far(&t.a);
    let notes = t.a.inner.notes_len();
    assert!(matches!(t.a.deliver("~zod", "counter", b"spin x"), Err(Error::Rejected(Rejection::Timeout))));
    let took = event_took(&t.a, notes);
    assert!(took >= Duration::from_millis(1000) && took < most, "the event ran {took:?}");
    stopped_within(&t.a, "counter", from, Duration::from_millis(15 + 100));
    let from = stops_so_far(&t.a);
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let held = lock(&t.a.inner.answered).last().unwrap().1;
    assert!(held < most, "the question held its ship {held:?}");
    stopped_within(&t.a, "counter", from, Duration::from_millis(15 + 100));
}

/// A watchdog held up cannot stop a call early: held still for three seconds (as a thread the
/// system does not run for a while), then let go as soon as an event given a second has had its
/// deadline set (the runtime says when), the event still runs its whole second, its whole run
/// (by the runtime's notes) under 1,110 ms (a test threshold, 100 ms of it for scheduling), and
/// by the runtime's record of its one stop no earlier than its deadline and less than 110 ms
/// after it; the same for a question, from its own fresh record. (Catching up on ticks missed,
/// as the watchdog did for a while, stopped such a call at once.)
#[test]
fn a_watchdog_held_up_stops_no_call_early() {
    let a_cfg = Config { fuel_per_event: 1 << 50, max_event_millis: 1000, ask_fuel: 1 << 50, ask_millis: 1000, ..fast() };
    let t = two_with("held-clock", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let most = Duration::from_millis(1000 + 10 + 100);
    let watching = t.a.inner.watching.clone();
    // Held still for three seconds; then the call begun, and the watchdog let go once its
    // handler's deadline is set.
    let held_up_for = |call: Box<dyn FnOnce() + Send>| {
        watching.paused.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(3));
        let (told, set) = std::sync::mpsc::channel();
        *lock(&t.a.inner.deadline_set_for) = Some(("counter".to_string(), told));
        let calling = std::thread::spawn(call);
        set.recv_timeout(Duration::from_secs(10)).expect("the handler's deadline set");
        watching.paused.store(false, Ordering::SeqCst);
        calling.join().unwrap();
    };
    let a = t.a.clone();
    let ran = Arc::new(Mutex::new(None));
    let ran_by = ran.clone();
    let from = stops_so_far(&t.a);
    let notes = t.a.inner.notes_len();
    held_up_for(Box::new(move || {
        *ran_by.lock().unwrap() = Some(a.deliver("~zod", "counter", b"spin x"));
    }));
    let ran = ran.lock().unwrap().take().unwrap();
    assert!(matches!(ran, Err(Error::Rejected(Rejection::Timeout))), "{ran:?}");
    let took = event_took(&t.a, notes);
    assert!(took >= Duration::from_millis(1000) && took < most, "the event ran {took:?}");
    stopped_within(&t.a, "counter", from, Duration::from_millis(10 + 100));
    let b = t.b.clone();
    let asked = Arc::new(Mutex::new(None));
    let asked_by = asked.clone();
    let from = stops_so_far(&t.a);
    held_up_for(Box::new(move || {
        *asked_by.lock().unwrap() = Some(b.ask("~nec", None, "~zod", "counter", "counter", b"?spin", Duration::from_secs(10)));
    }));
    assert_eq!(asked.lock().unwrap().take().unwrap(), Err(AskError::Failed));
    let held = lock(&t.a.inner.answered).last().unwrap().1;
    assert!(held < most, "the question held its ship {held:?}");
    stopped_within(&t.a, "counter", from, Duration::from_millis(10 + 100));
}

/// Hold `ship` with an ordinary event held at its start (the runtime's gate there), until the
/// sender returned is used or dropped. Returns once the event has the ship in hand.
fn hold_ship(rt: &Arc<Runtime>, ship: &'static str) -> (std::thread::JoinHandle<Result<crate::Outcome, Error>>, std::sync::mpsc::Sender<()>) {
    let (entered, release) = rt.inner.gates.arm("event begun");
    let held = rt.clone();
    let thread = std::thread::spawn(move || held.deliver(ship, "counter", b"inc held"));
    entered.recv_timeout(Duration::from_secs(10)).expect("the event to take the ship");
    (thread, release)
}

/// Questions waiting for their ship give their places back as soon as their askers give up,
/// not when what holds the ship lets it go. The ship is held by an event kept at a gate; two
/// askers who would wait nine seconds are both seen (by the runtime's acknowledgements) inside
/// the wait under test, then given up on together; by the runtime's records the last place
/// came back less than 500 ms (a test threshold) after the moment they were given up on, the
/// ship still held. Done for the wait for a ship's slot (both to ~zod, held), and for the wait
/// for a place among the ships kept awake (one place, held by ~wes; one question each to ~zod
/// and ~bus, both asleep, so each is in that wait). And a question that gives up by its own
/// time while it waits (300 ms) gives its place back less than 200 ms (a test threshold) after
/// its recorded deadline, in each kind of wait.
#[test]
fn questions_given_up_on_while_waiting_for_their_ship_give_their_places_back() {
    let a_cfg = Config { ask_millis: 10_000, ..fast() };
    let t = two_with("places-back", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    let questions = t.a_net.as_ref().unwrap().shared.questions.clone();
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    eventually("the first question's place to come back", Duration::from_secs(5), || lock(&questions).running == 0);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let (holding, release) = hold_ship(&t.a, "~zod");
    *lock(&t.a.inner.ask_rests) = Default::default();
    let from = t.a.inner.notes_len();
    let askers = two_askers(t.b_net.as_ref().unwrap(), ["~zod", "~zod"]);
    eventually("both inside the wait for the slot", Duration::from_secs(5), || t.a.inner.notes_of("question waiting for its slot", "nec", from).len() == 2);
    places_come_back(&t.a, t.b_net.as_ref().unwrap(), &questions, askers, "nec", from);
    own_time_gives_back(&t.a, t.b_net.as_ref().unwrap(), &questions, "~zod", ("question waiting for its slot", "nec"));
    assert!(!holding.is_finished(), "the event ended first");
    drop(release);
    assert!(holding.join().unwrap().is_ok());
    drop(t);

    let a_cfg = Config { ask_millis: 10_000, max_awake: 1, ..fast() };
    let dirs = (TempDir::new("places-awake-a"), TempDir::new("places-awake-b"));
    let directory = Directory::new();
    let a = crewed(&dirs.0 .0, a_cfg, &["~zod", "~bus", "~wes"], &counter_with(true, false), "~nec");
    let a_net = Network::start(a.clone(), directory.clone(), NetConfig::default()).unwrap();
    for ship in ["~zod", "~bus", "~wes"] {
        directory.set(ship, a.public_key(ship).unwrap(), a_net.addr()).unwrap();
    }
    let b = crewed(&dirs.1 .0, fast(), &["~nec"], &counter_with(true, true), "~zod");
    let b_net = Network::start(b.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~nec", b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    let questions = a_net.shared.questions.clone();
    assert_eq!(b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    eventually("the start-up look", Duration::from_secs(10), || a_net.shared.started_up.load(Ordering::SeqCst));
    eventually("the first question's place to come back", Duration::from_secs(5), || lock(&questions).running == 0);
    a.inner.recording.store(true, Ordering::SeqCst);
    let (holding, release) = hold_ship(&a, "~wes");
    assert_eq!(a.awake(), 1, "only ~wes is awake");
    *lock(&a.inner.ask_rests) = Default::default();
    let from = a.inner.notes_len();
    let askers = two_askers(&b_net, ["~zod", "~bus"]);
    eventually("each inside the wait for an awake place", Duration::from_secs(5), || {
        a.inner.notes_of("waiting for an awake place", "zod", from).len() == 1 && a.inner.notes_of("waiting for an awake place", "bus", from).len() == 1
    });
    places_come_back(&a, &b_net, &questions, askers, "nec", from);
    own_time_gives_back(&a, &b_net, &questions, "~bus", ("waiting for an awake place", "bus"));
    assert!(!holding.is_finished(), "the event ended first");
    drop(release);
    assert!(holding.join().unwrap().is_ok());
    drop((a_net, b_net));
}

/// Give up on `askers` together, wait for their tasks to be gone, and require every place back
/// less than 500 ms after the moment they were given up on, by the answering runtime's records.
/// That moment is noted once both askers are gone (their tasks aborted and seen to be), so a
/// test thread run late here can only make the interval measured shorter, never longer.
fn places_come_back(a: &Runtime, b_net: &Network, questions: &Mutex<super::Questions>, askers: Vec<tokio::task::JoinHandle<()>>, caller: &str, from: usize) {
    for asker in &askers {
        asker.abort();
    }
    let threads = b_net.threads.get().handle().clone();
    for asker in askers {
        assert!(threads.block_on(asker).is_err_and(|e| e.is_cancelled()));
    }
    a.inner.note("askers given up", caller);
    eventually("the places to come back", Duration::from_secs(15), || lock(questions).running == 0);
    let given_up = a.inner.notes_of("askers given up", caller, from)[0].0;
    let back = a.inner.notes_of("question place given back", caller, from);
    assert_eq!(back.len(), 2, "{back:?}");
    let last = back.iter().map(|(at, _)| *at).max().unwrap();
    assert!(last.saturating_duration_since(given_up) < Duration::from_millis(500), "the last place came back {:?} after", last.saturating_duration_since(given_up));
}

/// A question that runs out of its own time (300 ms) while it waits (in the wait the runtime
/// says it entered: `waiting`, a note and what it is keyed by) gives its place back less than
/// 200 ms after its deadline, by the answering runtime's records (exactly one fresh deadline).
fn own_time_gives_back(a: &Runtime, b_net: &Network, questions: &Mutex<super::Questions>, to: &str, waiting: (&str, &str)) {
    *lock(&a.inner.ask_rests) = Default::default();
    let from = a.inner.notes_len();
    let answered = b_net.ask_raw("~nec", to, question("", "counter", b"hits", 300), Duration::from_secs(3));
    assert!(format!("{answered:?}").contains(crate::ask::TOOK_TOO_LONG), "{answered:?}");
    eventually("its place to come back", Duration::from_secs(5), || lock(questions).running == 0);
    assert_eq!(a.inner.notes_of(waiting.0, waiting.1, from).len(), 1, "the question was not in the wait: {waiting:?}");
    let deadlines = a.inner.notes_of("question deadline", "nec", from);
    assert_eq!(deadlines.len(), 1, "{deadlines:?}");
    let deadline = deadlines[0].0;
    let back = a.inner.notes_of("question place given back", "nec", from);
    assert_eq!(back.len(), 1, "{back:?}");
    assert!(back[0].0 >= deadline && back[0].0 - deadline < Duration::from_millis(200), "its place came back {:?} after its deadline", back[0].0.saturating_duration_since(deadline));
}

/// Two questions from ~nec, to the ships named, each asker willing to wait nine seconds, under
/// way on the asking network's threads.
fn two_askers(net: &Network, to: [&'static str; 2]) -> Vec<tokio::task::JoinHandle<()>> {
    to.iter()
        .map(|to| {
            let (shared, to) = (net.shared.clone(), *to);
            net.threads.get().spawn(async move {
                let _ = shared.ask_within("~nec", to, question("", "counter", b"hits", 9000), Duration::from_secs(9)).await;
            })
        })
        .collect()
}

/// A committed answer is run though the network that wrote it is gone: the asking runtime's
/// network is stopped and a new one started in its place, and the answer is then written as
/// the old network's job would write it (here straight from the test, while the new network's
/// own task for the question is still trying); the network now running hears of it from the
/// ship and runs the answer, with nothing else arriving.
#[test]
fn an_answer_written_outside_the_networks_task_is_still_run() {
    let mut t = two("stranded", counter_with(true, false));
    t.a_net.take().unwrap().vanish();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 60000 hits");
    drop(t.b_net.take());
    let replaced = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), replaced.addr()).unwrap();
    t.b_net = Some(replaced);
    eventually("the new network's task for it", Duration::from_secs(5), || t.b_net.as_ref().unwrap().shared.carrier.putting_count() == 1);
    let mark = t.b.incarnation("~nec").unwrap();
    assert_eq!(t.b.ask_answered("~nec", &mark, n.parse().unwrap(), Outcome::Reply, b"7", "").unwrap(), Settled::Queued);
    eventually("the answer to run", Duration::from_secs(5), || !answers_to(&t.b, "~nec", &n).is_empty());
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter reply [] 7 from ~zod/counter counter")]);
}

/// A thousand questions, answered and refused, keep nothing of theirs on the ship asked: started
/// cold (the ship asked restarted, nothing compiled, not even its kernel, the ship asleep and
/// owed its first look through its files), the first question is too busy while the kernel is
/// compiled off its path; then, after them all, the same rows in every table and the same lengths
/// of the ship's file and of its `-wal` (the ship awake after, so a change could sit in the
/// `-wal`; lengths and row counts, not the bytes), exactly two compiles (the kernel and the agent asked, once
/// each), and a leftover in the ship's files directory still there (no upkeep ran for a
/// question) until an ordinary call.
#[test]
fn a_thousand_questions_write_nothing_on_the_ship_asked() {
    let quick = NetConfig { asks_per_second: 1_000_000, asks_per_second_each: 1_000_000, ..NetConfig::default() };
    let mut t = two_with("nothing-written", (fast(), quick.clone()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    say(&t.a, "~zod", "counter", "inc hits 3");
    let before = rows(&t.a, "~zod");
    // ~zod's runtime starts again: nothing compiled. Its start-up look wakes ~zod (and so
    // compiles its kernel, and looks through its files); then ~zod is put to sleep, owed a look.
    let (dir, scratch) = (t.dirs.0 .0.clone(), t.dirs.1 .0.join("scratch"));
    reopen(&mut t.a, &mut t.a_net, &dir, fast(), &scratch);
    let a_net = Network::start(t.a.clone(), t.directory.clone(), quick).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    let shared = t.a_net.as_ref().unwrap().shared.clone();
    eventually("the start-up look", Duration::from_secs(10), || shared.started_up.load(Ordering::SeqCst));
    assert_eq!(t.a.compiled_modules(), 1);
    assert_eq!(t.a.sleep_idle(Duration::ZERO), 1, "the ship was not put to sleep");
    // And its kernel forgotten too, as if nothing had woken it since the runtime started.
    t.a.inner.forget_modules();
    let compiles = t.a.inner.compiles.load(Ordering::SeqCst);
    assert_eq!(t.a.awake(), 0);
    lock(&t.a.inner.swept).remove("zod");
    let leftover = dir.join("files").join("zod").join("0123456789abcdef0123456789abcdef");
    fs::create_dir_all(&leftover).unwrap();
    let sizes = file_sizes(&t.a, "~zod");
    // The first question finds the ship's kernel not compiled: too busy.
    let first = t.b_net.as_ref().unwrap().ask_raw("~nec", "~zod", question("", "counter", b"hits", 5000), Duration::from_secs(5));
    assert!(matches!(&first, Err(NetError::Refused(why)) if why == TOO_BUSY), "{first:?}");
    // And the ship was not woken for it: its kernel was not there to wake it with.
    assert_eq!(t.a.awake(), 0, "the ship was woken, its kernel compiled, on the question's path");
    let mut seen = BTreeMap::new();
    for i in 0..1000 {
        let (interface, payload): (&str, &[u8]) = match i % 4 {
            0 => ("counter", b"hits"),
            1 => ("journal", b"hits"),
            2 => ("counter", b"?trap"),
            _ => ("counter", b"?big 300000"),
        };
        let outcome = match ask(&t, Some("tally"), interface, payload, Duration::from_secs(10)) {
            Ok(_) => "answered",
            Err(AskError::Denied(_)) => "denied",
            Err(AskError::Failed) => "failed",
            Err(AskError::Limit) => "limit",
            Err(AskError::Busy) => "busy",
            Err(other) => panic!("{other:?}"),
        };
        *seen.entry(outcome).or_insert(0) += 1;
    }
    assert!(["answered", "denied", "failed", "limit"].iter().all(|outcome| seen.contains_key(outcome)), "{seen:?}");
    assert_eq!(file_sizes(&t.a, "~zod"), sizes);
    assert_eq!(t.a.compiled_modules(), 2, "only the kernel and the agent asked");
    assert_eq!(t.a.inner.compiles.load(Ordering::SeqCst) - compiles, 2, "each compiled once");
    assert!(leftover.exists() && !lock(&t.a.inner.swept).contains("zod"), "a question ran the ship's upkeep");
    // An ordinary call does what was owed.
    assert_eq!(rows(&t.a, "~zod"), before);
    assert!(!leftover.exists());
}

/// An agent is handed exactly one answer for a question to a ship this runtime does not know
/// of (unreachable, at once), and for one whose agent fails.
#[test]
fn an_agent_is_handed_one_answer_for_an_unknown_ship_and_a_failure() {
    let t = two("one-each", counter_with(true, false));
    // ~bus is in no directory.
    let mut manifest = asking_tally("bus");
    manifest.uses.extend(asking_tally("zod").uses);
    let tally = t.b.add_module(&wasm("tally")).unwrap();
    t.b.install("~nec", "tally", &tally, &manifest).unwrap();
    let started = Instant::now();
    let unknown = say(&t.b, "~nec", "tally", "ask-on bus counter counter 20000 hits");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &unknown).is_empty());
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let trap = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 ?trap");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &trap).is_empty());
    std::thread::sleep(Duration::from_secs(1));
    assert!(answers_to(&t.b, "~nec", &unknown).len() == 1 && answers_to(&t.b, "~nec", &unknown)[0].contains(" unreachable ["), "{:?}", answers(&t.b, "~nec"));
    assert!(answers_to(&t.b, "~nec", &trap).len() == 1 && answers_to(&t.b, "~nec", &trap)[0].contains(" failed ["), "{:?}", answers(&t.b, "~nec"));
    assert_eq!(rows(&t.b, "~nec")["asks"], 0);
}

/// A question to a ship that has vanished (its network stopped with no goodbye) is answered
/// once, about when its time runs out: by the runtime's records, its answer's handler committed
/// between 1.9 and 3.5 s (test thresholds) after the asking event committed, for 2 s given. (Its
/// ship asleep then: `a_question_whose_ship_sleeps_is_answered_by_the_network_alone`.)
#[test]
fn a_question_to_a_ship_that_vanished_is_answered_once_at_its_time_asleep_or_awake() {
    let mut t = two("vanished", counter_with(true, false));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    t.a_net.take().unwrap().vanish();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 2000 hits");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    let asked = t.b.inner.notes_of("asking event committed", "nec/tally", from)[0].0;
    let handled = t.b.inner.notes_of("answer handled", &format!("nec/{n}"), from);
    assert_eq!(handled.len(), 1, "{handled:?}");
    let took = handled[0].0.saturating_duration_since(asked);
    assert!(took >= Duration::from_millis(1900) && took < Duration::from_millis(3500), "{took:?}");
    let handed = answers_to(&t.b, "~nec", &n);
    assert_eq!(handed.len(), 1, "{handed:?}");
    assert!(handed[0].contains(" unreachable [") || handed[0].contains(" no-answer ["), "{}", handed[0]);
}

/// A question whose ship is put to sleep while it is being put is answered by the network
/// alone, its ship woken for the answer and no sooner. A ship of its own (nothing left over from
/// other questions); the question's task is held just after its read of the question (the
/// runtime's gate there), the question's deadline read from its row, and the ship put to sleep
/// (`sleep_idle` says it parked one ship); then the task is let go. Once its answer's handler
/// has committed (by the runtime's record), the ship is awake, exactly one answer has been
/// handed over and nothing is left queued; and by the runtime's records: the first wake after
/// the ship was put to sleep was for writing what came of the question, exactly one place among
/// the awake ships was reserved for ~nec since (noted where it was taken), no earlier than the
/// row's deadline, and the answer's handler committed exactly once, less than 3.5 s (a test
/// threshold) after its asking event committed (by the runtime's record); the task is let go
/// only with time left to its recorded deadline (else the test says the machine was too slow).
#[test]
fn a_question_whose_ship_sleeps_is_answered_by_the_network_alone() {
    let mut t = two("asleep", counter_with(true, false));
    let shared = t.b_net.as_ref().unwrap().shared.clone();
    eventually("the start-up look", Duration::from_secs(10), || shared.started_up.load(Ordering::SeqCst));
    t.a_net.take().unwrap().vanish();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let (read, let_go) = t.b.inner.gates.arm("question read");
    let start = t.b.inner.notes_len();
    let n: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1500 hits").parse().unwrap();
    let cutoff = t.b.inner.notes_of("asking event committed", "nec/tally", start)[0].0 + Duration::from_millis(3500);
    read.recv_timeout(Duration::from_secs(10)).expect("the task to read its question");
    let deadline_ms = t.b.inner.with_ship("~nec", |ship| Ok(crate::store::ask_get(&lock(&ship.conn), n)?)).unwrap().expect("still waiting").deadline;
    let slept = Instant::now();
    let from = t.b.inner.notes_len();
    assert_eq!(t.b.sleep_idle(Duration::ZERO), 1, "the ship was not put to sleep");
    let task_deadline = t.b.inner.notes_of("question task deadline", &format!("nec/{n}"), start)[0].0;
    assert!(Instant::now() < task_deadline, "the test machine was too slow: the question's time ran out before its task was let go, so the test cannot show what it is for");
    drop(let_go);
    eventually("the answer handled", Duration::from_secs(10), || !t.b.inner.notes_of("answer handled", &format!("nec/{n}"), from).is_empty());
    assert_eq!(t.b.awake(), 1, "nothing woke the ship");
    assert_eq!(answers_to(&t.b, "~nec", &n.to_string()).len(), 1, "{:?}", answers(&t.b, "~nec"));
    assert_eq!(t.b.pending("~nec").unwrap(), 0, "something is left queued");
    let wakes: Vec<_> = lock(&t.b.inner.ship_wakes).iter().filter(|(at, _, ship, _)| *at >= slept && ship == "nec").cloned().collect();
    let (_, _, _, cause) = wakes.first().cloned().expect("the ship woken");
    assert_eq!(cause, "writing what came of a question", "the first wake after it was put to sleep: {wakes:?}");
    let reserved = t.b.inner.notes_of("reserved for a wake", "nec", from);
    assert_eq!(reserved.len(), 1, "{reserved:?}");
    let (_, reserved_ms) = reserved[0];
    assert!(reserved_ms >= deadline_ms, "reserved at {reserved_ms} for a deadline of {deadline_ms}");
    let handled = t.b.inner.notes_of("answer handled", &format!("nec/{n}"), from);
    assert_eq!(handled.len(), 1, "{handled:?}");
    assert!(handled[0].0 <= cutoff, "handed over {:?} after the cutoff", handled[0].0 - cutoff);
}

/// Questions waiting when the asking runtime stops: after it starts again, one whose time is
/// left is asked again and answered, and one whose time has run out is answered as having had
/// no answer. Each once.
#[test]
fn questions_waiting_through_a_restart_are_asked_again_or_answered_no_answer() {
    let mut t = two("restart", counter_with(true, false));
    say(&t.a, "~zod", "counter", "inc hits 7");
    // ~zod is away.
    let a_net = t.a_net.take().unwrap();
    drop(a_net);
    let long = say(&t.b, "~nec", "tally", "ask-on zod counter counter 30000 hits");
    let short = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1500 hits");
    // ~nec's runtime stops, and starts again after the short one's time.
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, fast(), &scratch);
    std::thread::sleep(Duration::from_secs(2));
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    eventually("the short one's answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &short).is_empty());
    assert!(answers_to(&t.b, "~nec", &short)[0].contains(" no-answer ["), "{:?}", answers(&t.b, "~nec"));
    // ~zod comes back: the long one is asked again, and answered.
    let a_net = Network::start(t.a.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    eventually("the long one's answer", Duration::from_secs(25), || !answers_to(&t.b, "~nec", &long).is_empty());
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(answers_to(&t.b, "~nec", &long), [format!("{long} ~zod/counter counter reply [] 7 from ~zod/counter counter")]);
    assert_eq!(answers_to(&t.b, "~nec", &short).len(), 1);
    assert_eq!(rows(&t.b, "~nec")["asks"], 0);
}

/// Questions waiting in an exported ship are answered as having had no answer when it is
/// brought in, without being asked; and numbering carries on past them.
#[test]
fn questions_waiting_in_an_exported_ship_are_answered_no_answer_in_the_import() {
    let mut t = two("exported", counter_with(true, false));
    t.a_net.take().unwrap().vanish();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 60000 hits");
    let out = TempDir::new("exported-copy");
    let code = "test-test-test-test-test-test-test-test";
    t.b.set_recovery_key("~nec", crate::seal::recovery_public(code)).unwrap();
    t.b.export_ship("~nec", out.0.join("copy")).unwrap();
    let other_dir = TempDir::new("exported-into");
    let other = Runtime::open(&other_dir.0, fast()).unwrap();
    other.import_ship(out.0.join("copy"), "~nec", code).unwrap();
    assert_eq!(rows(&other, "~nec")["asks"], 0);
    other.run_pending("~nec", 10).unwrap();
    let handed = answers_to(&other, "~nec", &n);
    assert_eq!(handed.len(), 1, "{:?}", answers(&other, "~nec"));
    assert!(handed[0].contains(" no-answer [this ship was brought in from a copy"), "{handed:?}");
    // The next question is numbered after it.
    let next: u64 = say(&other, "~nec", "tally", "ask-on zod counter counter 5000 hits").parse().unwrap();
    assert!(next > n.parse::<u64>().unwrap());
}

/// An agent that drops a question is handed no answer for it, whether it was still waiting or
/// its answer had arrived and not yet been handed over.
#[test]
fn a_dropped_question_is_never_answered() {
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("dropped", (fast(), NetConfig::default()), (patient, NetConfig::default()), counter_with(true, false), &["~nec"]);
    // Its answer has arrived and is queued, not yet handed over.
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 hits");
    eventually("the answer to be queued", Duration::from_secs(10), || t.b.pending("~nec").unwrap() == 1 && rows(&t.b, "~nec")["asks"] == 0);
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {n}")), "true");
    assert_eq!(t.b.pending("~nec").unwrap(), 0);
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {n}")), "false");
    t.b.run_pending("~nec", 10).unwrap();
    assert!(answers_to(&t.b, "~nec", &n).is_empty());
    // Still waiting, with ~zod gone: dropped, then its time runs out, and nothing is handed over.
    t.a_net.take().unwrap().vanish();
    let m = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1000 hits");
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {m}")), "true");
    std::thread::sleep(Duration::from_secs(2));
    t.b.run_pending("~nec", 10).unwrap();
    assert!(answers_to(&t.b, "~nec", &m).is_empty());
    assert_eq!((rows(&t.b, "~nec")["asks"], t.b.pending("~nec").unwrap()), (0, 0));
}

/// An answer and the time running out at once make one event: the two are written each in a
/// transaction that strikes the question off, so the second finds nothing. Two hundred times.
#[test]
fn an_answer_and_the_time_running_out_together_make_one_event() {
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("race", (fast(), NetConfig::default()), (patient, NetConfig::default()), counter_with(true, false), &["~nec"]);
    t.a_net.take().unwrap().vanish();
    let mark = t.b.incarnation("~nec").unwrap();
    let mut numbers = Vec::new();
    for _ in 0..4 {
        numbers.extend(say(&t.b, "~nec", "tally", "ask-many zod 50 60000").split(' ').map(|n| n.parse::<u64>().unwrap()));
    }
    // Another copy's mark settles nothing, the question still waiting.
    assert_eq!(t.b.ask_answered("~nec", &[9; 16], numbers[0], Outcome::Reply, b"7", "").unwrap(), Settled::Gone);
    assert_eq!(rows(&t.b, "~nec")["asks"], 200);
    assert_eq!(t.b.pending("~nec").unwrap(), 0);
    for &n in &numbers {
        let (one, two) = (t.b.clone(), t.b.clone());
        let replied = std::thread::spawn(move || one.ask_answered("~nec", &mark, n, Outcome::Reply, b"7", ""));
        let timed_out = std::thread::spawn(move || two.ask_answered("~nec", &mark, n, Outcome::NoAnswer, b"", "no answer came in time"));
        let mut both = [replied.join().unwrap().unwrap(), timed_out.join().unwrap().unwrap()];
        both.sort_by_key(|settled| *settled as u8);
        assert_eq!(both, [Settled::Queued, Settled::Gone], "question {n}");
    }
    while t.b.run_pending("~nec", 64).unwrap() > 0 {}
    let handed = answers(&t.b, "~nec");
    assert_eq!(handed.len(), numbers.len());
    for n in numbers {
        assert_eq!(answers_to(&t.b, "~nec", &n.to_string()).len(), 1);
    }
}

/// An event that fails puts no question: nothing is written, and nothing is sent.
#[test]
fn an_event_that_fails_puts_no_question() {
    let t = two("rolled-back", counter_with(true, false));
    assert!(matches!(t.b.deliver("~nec", "tally", b"ask-then-crash zod"), Err(Error::Rejected(_))));
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(rows(&t.b, "~nec")["asks"], 0);
    assert_eq!(answered_from(&t.a, "nec"), 0);
    assert!(answers(&t.b, "~nec").is_empty());
}

/// Only so many questions wait on a ship, counting answers queued and not yet handed over.
#[test]
fn only_so_many_questions_wait() {
    let b_cfg = Config { max_asks_waiting: 4, max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("most", (fast(), NetConfig::default()), (b_cfg, NetConfig::default()), counter_with(true, false), &["~nec"]);
    t.a_net.take().unwrap().vanish();
    let numbers = say(&t.b, "~nec", "tally", "ask-many zod 4 60000");
    assert!(matches!(t.b.deliver("~nec", "tally", b"ask-on zod counter counter 60000 hits"), Err(Error::Rejected(Rejection::Limit(_)))));
    // An answer queued still counts; dropping one makes room.
    let first = numbers.split(' ').next().unwrap();
    let mark = t.b.incarnation("~nec").unwrap();
    assert_eq!(t.b.ask_answered("~nec", &mark, first.parse().unwrap(), Outcome::NoAnswer, b"", "").unwrap(), Settled::Queued);
    assert!(matches!(t.b.deliver("~nec", "tally", b"ask-on zod counter counter 60000 hits"), Err(Error::Rejected(Rejection::Limit(_)))));
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {first}")), "true");
    say(&t.b, "~nec", "tally", "ask-on zod counter counter 60000 hits");
}

/// With no network, questions waiting are answered as unreachable when the ship next runs its
/// queue through `deliver` or `run_pending`.
#[test]
fn with_no_network_a_question_is_answered_unreachable() {
    let dir = TempDir::new("no-network");
    let rt = crewed(&dir.0, fast(), &["~nec"], &counter_with(true, false), "~zod");
    let n = say(&rt, "~nec", "tally", "ask-on zod counter counter 5000 hits");
    assert_eq!(answers_to(&rt, "~nec", &n).len(), 1, "{:?}", answers(&rt, "~nec"));
    assert!(answers_to(&rt, "~nec", &n)[0].contains(" unreachable [this ship is not on the network] "));
    assert_eq!(rt.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(1)), Err(AskError::NoNetwork));
}

/// A receipt carries the handler's reply only when the command asked for it, and only when it
/// ran; a reply larger than the ship that ran it sends undoes the command and says LIMIT.
#[test]
fn a_receipt_carries_the_reply_only_when_asked_and_only_when_it_ran() {
    let a_cfg = Config { max_receipt_reply_bytes: 1024, ..fast() };
    let t = two_with("reply", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(false, true), &["~nec"]);
    say(&t.b, "~nec", "tally", "tell zod inc hits");
    say(&t.b, "~nec", "tally", "tell-reply zod inc hits");
    say(&t.b, "~nec", "tally", "tell-reply zod crash x");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 1024");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 1025");
    eventually("five receipts", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 5);
    let got = receipts(&t.b, "~nec");
    assert_eq!(got[0], "1 ~zod/counter counter ran [] from ~zod/counter counter", "{got:?}");
    assert_eq!(got[1], "2 ~zod/counter counter ran [] from ~zod/counter counter reply 2", "{got:?}");
    assert!(got[2].starts_with("3 ~zod/counter counter failed [the agent failed] from") && !got[2].contains("reply"), "{got:?}");
    assert_eq!(got[3], "4 ~zod/counter counter ran [] from ~zod/counter counter reply of 1024 bytes", "{got:?}");
    assert_eq!(got[4], "5 ~zod/counter counter limit [the reply is larger than that ship sends with a receipt] from ~zod/counter counter", "{got:?}");
    // The command whose reply was too large did not stand.
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "3");
}

/// A command whose answer is lost when two ships fall out of step is handed LOST, with no reply,
/// though it asked for one.
#[test]
fn a_lost_command_has_no_reply() {
    let mut t = two("lost", counter_with(false, true));
    t.a_net.take().unwrap().vanish();
    let n = say(&t.b, "~nec", "tally", "tell-reply zod inc hits");
    // ~zod says it holds that command and owes nothing for it: its answer is gone.
    let theirs = crate::store::Stand { sent: 0, received: n.parse().unwrap(), oldest: 1, owed: Vec::new(), owed_complete: true, mark: 0, epoch: 0 };
    t.b.resync("~nec", "~zod", &theirs, 64, || true).unwrap();
    eventually("the receipt", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 1);
    let got = receipts(&t.b, "~nec");
    assert!(got[0].starts_with(&format!("{n} ~zod/counter counter lost [")) && !got[0].contains("reply"), "{got:?}");
}

/// Exactly once holds for a command that asked for its reply, across a restart of the ship
/// that sent it while it waits unsent, and a restart of the ship that ran it after the command
/// and its receipt committed and before the receipt was taken: it runs once, and its receipt,
/// with the reply from that one run, is handed over once.
#[test]
fn exactly_once_holds_for_a_command_with_its_reply_across_restarts() {
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("reply-restart", (patient, NetConfig::default()), (fast(), NetConfig::default()), counter_with(false, true), &["~nec"]);
    // ~nec is off the network when its agent sends; its runtime stops and starts again.
    drop(t.b_net.take());
    say(&t.b, "~nec", "tally", "tell-reply zod inc hits");
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, fast(), &scratch);
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    // ~zod takes it; ~nec goes off the network; ~zod runs it, and its receipt waits.
    eventually("~zod to hold it", Duration::from_secs(10), || t.a.pending("~zod").unwrap() == 1);
    t.b_net.take().unwrap().vanish();
    assert_eq!(t.a.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "1");
    // ~zod's runtime stops after the command and its receipt committed, and starts again.
    let (a_dir, scratch) = (t.dirs.0 .0.clone(), t.dirs.1 .0.join("scratch"));
    reopen(&mut t.a, &mut t.a_net, &a_dir, fast(), &scratch);
    let a_net = Network::start(t.a.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    eventually("the receipt", Duration::from_secs(20), || receipts(&t.b, "~nec").len() == 1);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(receipts(&t.b, "~nec"), ["1 ~zod/counter counter ran [] from ~zod/counter counter reply 1"]);
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "1");
    assert_eq!(t.b.unanswered("~nec").unwrap(), 0);
}

/// Two ships that have filled up with commands for each other, every one asking for a reply
/// of the largest size a receipt carries, still get everything through, and every command is
/// answered: it ran, with its whole reply, or it did not stand for want of room for the reply.
#[test]
fn two_full_ships_whose_commands_ask_for_replies_at_the_limit_still_get_through() {
    // Only a few audit rows kept, so that the record of every command is not what keeps the two
    // short of room once they have drained.
    let small = Config { max_ship_bytes: 340 << 10, audit_rows: 32, ..fast() };
    let dirs = (TempDir::new("full-replies-a"), TempDir::new("full-replies-b"));
    let directory = Directory::new();
    let counter = counter_with(false, true);
    let zod = crewed(&dirs.0 .0, small.clone(), &["~zod"], &counter, "~nec");
    let nec = crewed(&dirs.1 .0, small.clone(), &["~nec"], &counter, "~zod");
    let reply = small.max_receipt_reply_bytes;
    let padding = "p".repeat(2000);
    let fill = |rt: &Runtime, ship: &str, other: &str| {
        let command = format!("tell-reply {other} inc-big hits {reply} {padding}");
        let mut sent = 0;
        while rt.deliver(ship, "tally", command.as_bytes()).is_ok() {
            sent += 1;
        }
        assert!(sent > 5, "only {sent} were sent");
        sent
    };
    let (from_zod, from_nec) = (fill(&zod, "~zod", "nec"), fill(&nec, "~nec", "zod"));
    let zod_net = Network::start(zod.clone(), directory.clone(), NetConfig::default()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("every command answered", Duration::from_secs(90), || {
        zod.unanswered("~zod").unwrap() == 0 && nec.unanswered("~nec").unwrap() == 0 && zod.pending("~zod").unwrap() == 0 && nec.pending("~nec").unwrap() == 0
    });
    for (rt, ship, other, sent) in [(&zod, "~zod", &nec, from_zod), (&nec, "~nec", &zod, from_nec)] {
        let got = receipts(rt, ship);
        assert_eq!(got.len(), sent, "{ship}");
        let ran = got.iter().filter(|line| line.contains(" ran [] ") && line.ends_with(&format!(" reply of {reply} bytes"))).count();
        let refused = got.iter().filter(|line| line.contains(" limit [that ship had no room to keep the reply] ")).count();
        assert_eq!(ran + refused, sent, "{ship}: {got:?}");
        let other_ship = if ship == "~zod" { "~nec" } else { "~zod" };
        assert_eq!(say(other, other_ship, "counter", "get hits"), ran.to_string(), "{ship}");
    }
    // While the two are full, a reply is never let use the room kept for taking a command back,
    // so those commands may all be LIMIT (in the runs made, all twenty were). Once the two have
    // room again, commands bring their whole replies.
    say(&zod, "~zod", "tally", &format!("tell-reply nec inc-big hits {reply}"));
    say(&nec, "~nec", "tally", &format!("tell-reply zod inc-big hits {reply}"));
    eventually("the two receipts", Duration::from_secs(30), || receipts(&zod, "~zod").len() == from_zod + 1 && receipts(&nec, "~nec").len() == from_nec + 1);
    for (rt, ship) in [(&zod, "~zod"), (&nec, "~nec")] {
        let last = receipts(rt, ship).pop().unwrap();
        assert!(last.contains(" ran [] ") && last.ends_with(&format!(" reply of {reply} bytes")), "{ship}: {last}");
    }
}

/// A network is not started with any limit on questions of nothing (no fuel, no time, no
/// places, no allowance), nor with messages too small for the largest command; and sizes past
/// the most any ship's file, export and the wire carry are held to that most. (That a
/// question, an answer and a receipt with its reply each fit one message, at the largest the
/// settings allow, is shown at that boundary by `deliveries_at_the_boundary_of_one_message`.)
#[test]
fn a_network_is_not_started_with_settings_that_could_wedge() {
    let dir = TempDir::new("settings");
    for (label, cfg, net) in [
        ("fuel", Config { ask_fuel: 0, ..fast() }, NetConfig::default()),
        ("time", Config { ask_millis: 0, ..fast() }, NetConfig::default()),
        ("longest", Config { max_ask_millis: 0, ..fast() }, NetConfig::default()),
        ("places", fast(), NetConfig { max_asks: 0, ..NetConfig::default() }),
        ("each", fast(), NetConfig { max_asks_each: 0, ..NetConfig::default() }),
        ("rate", fast(), NetConfig { asks_per_second: 0, ..NetConfig::default() }),
        ("rate-each", fast(), NetConfig { asks_per_second_each: 0, ..NetConfig::default() }),
    ] {
        let rt = Arc::new(Runtime::open(dir.0.join(label), cfg).unwrap());
        assert!(Network::start(rt, Directory::new(), net).is_err(), "{label}");
    }
    // Nor with messages too small to carry the largest command and its room to spare.
    let rt = Arc::new(Runtime::open(dir.0.join("message"), fast()).unwrap());
    assert!(Network::start(rt.clone(), Directory::new(), NetConfig { max_message_bytes: 64 << 10, ..NetConfig::default() }).is_err());
    drop(rt);
    // And sizes past what a ship's file, an export and the wire carry are held to the most
    // that is allowed, whatever is asked for.
    let rt = Runtime::open(dir.0.join("held"), Config { max_answer_bytes: 1 << 40, max_ask_bytes: 1 << 40, max_receipt_reply_bytes: 1 << 40, ..fast() }).unwrap();
    let held = &rt.inner.cfg;
    assert_eq!((held.max_answer_bytes, held.max_ask_bytes, held.max_receipt_reply_bytes), (crate::store::MOST_ANSWER_BYTES, crate::store::MOST_ASK_BYTES, crate::store::MOST_RECEIPT_REPLY_BYTES));
}

/// The kernel: a read from another ship only to an interface open to questions, and never for
/// the owner; a command from another ship not by `asked` alone; an answer to any installed
/// agent; and an agent's grants to ask exactly what its manifest declares with `ask` and a ship.
#[test]
fn the_kernel_lets_questions_through_only_where_they_are_opened() {
    let dir = TempDir::new("kernel");
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let counter = rt.add_module(&wasm("counter")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    let provides = vec![
        Provide { interface: "asked".into(), public: false, remote: false, asked: true },
        Provide { interface: "remote".into(), public: false, remote: true, asked: false },
        Provide { interface: "public".into(), public: true, remote: false, asked: false },
    ];
    let uses = vec![
        Use { ship: "nec".into(), agent: "a".into(), interface: "x".into(), read: false, send: false, ask: true },
        Use { ship: "*".into(), agent: "b".into(), interface: "y".into(), read: true, send: true, ask: false },
        Use { ship: String::new(), agent: "counter".into(), interface: "asked".into(), read: true, send: false, ask: true },
    ];
    rt.install("~zod", "counter", &counter, &Manifest { provides, uses }).unwrap();
    let route = |source: Source, kind: Kind, interface: &str| rt.inner.with_ship("~zod", |ship| Ok(ship.route_answer(&rt.inner, &source, "counter", kind, interface))).unwrap();
    let from = |owner: bool, agent: &str| Source { owner, agent: agent.into(), ship: "nec".into() };
    assert!(route(from(false, "tally"), Kind::Read, "asked").1.allowed);
    assert!(route(from(false, ""), Kind::Read, "asked").1.allowed);
    assert!(!route(from(true, ""), Kind::Read, "asked").1.allowed);
    assert!(!route(from(false, "tally"), Kind::Read, "remote").1.allowed);
    assert!(!route(from(false, "tally"), Kind::Read, "public").1.allowed);
    assert!(!route(from(false, "tally"), Kind::Command, "asked").1.allowed);
    assert!(route(from(false, "tally"), Kind::Command, "remote").1.allowed);
    assert!(route(from(false, "tally"), Kind::Answer, "x").1.allowed);
    let missing = rt.inner.with_ship("~zod", |ship| Ok(ship.route_answer(&rt.inner, &from(false, "tally"), "nobody", Kind::Answer, "x"))).unwrap();
    assert!(!missing.1.allowed);
    let (_, owner) = route(Source { owner: true, agent: String::new(), ship: String::new() }, Kind::Command, "");
    assert_eq!(owner.asks, vec![ship_proto::Grant { agent: "a".into(), interface: "x".into(), ship: "nec".into() }]);
}

/// The kernel's bound on its answers still holds with grants to ask counted: agents are
/// installed until the kernel refuses one, and every answer it then gives is within 256 KiB.
#[test]
fn the_kernels_bound_on_its_answers_counts_grants_to_ask() {
    let dir = TempDir::new("kernel-bound");
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let counter = rt.add_module(&wasm("counter")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    let long = |what: &str, i: usize, len: usize| format!("{what}{i}-{}", "x".repeat(len)).chars().take(len).collect::<String>();
    // One agent declares as much as it may of other ships' agents, to read, send to and ask.
    let uses = (0..64).map(|i| Use { ship: long("s", i, 64).replace(|c: char| c.is_ascii_digit(), "q"), agent: long("a", i, 64), interface: long("i", i, 128), read: true, send: true, ask: true }).collect();
    rt.install("~zod", "asker", &counter, &Manifest { provides: vec![], uses }).unwrap();
    // Then agents offering many public interfaces, and then agents offering one, until refused.
    let mut installed = vec!["asker".to_string()];
    for (count, per) in [(64usize, 64usize), (256, 1)] {
        for n in 0..count {
            let name = format!("p{per}-{n}");
            let provides = (0..per).map(|i| Provide { interface: long(&format!("{name}-"), i, 128), public: true, remote: false, asked: false }).collect();
            if rt.install("~zod", &name, &counter, &Manifest { provides, uses: vec![] }).is_err() {
                break;
            }
            installed.push(name);
        }
    }
    assert!(installed.len() > 2, "{installed:?}");
    let owner = Source { owner: true, agent: String::new(), ship: String::new() };
    for agent in &installed {
        let (bytes, reply) = rt.inner.with_ship("~zod", |ship| Ok(ship.route_answer(&rt.inner, &owner, agent, Kind::Command, ""))).unwrap();
        assert!(reply.allowed, "{agent}");
        assert!(bytes <= 256 << 10, "{agent}: {bytes}");
    }
}

/// A request whose body is a field a runtime has no name for, as a question (field 11) is to
/// an older runtime, is answered with the bare refusal for a request it does not know (which
/// `put_question` takes as not understood); and "too busy" is a refusal of its own.
#[test]
fn a_kind_of_request_not_known_is_refused_as_such() {
    // Field 12, a message holding nothing: not a body field this runtime counts, and it decodes
    // to a request with no body, as a question decodes in an older runtime.
    let raw = [0x62u8, 0x00];
    assert_eq!(super::body_fields(&raw), Some((0, 0)));
    assert_eq!(super::decode_request(&raw).unwrap(), PeerRequest::default());
    // And a request with no body is answered with the refusal for one not known.
    let t = two("unknown-kind", counter_with(true, false));
    let asked = t.b_net.as_ref().unwrap().ask_raw("~nec", "~zod", PeerRequest::default(), Duration::from_secs(10));
    assert!(matches!(&asked, Err(NetError::Refused(why)) if why == super::UNKNOWN_REQUEST), "{asked:?}");
    assert_eq!(TOO_BUSY, "too busy; try again");
}

/// A question holds room in its ship's queue for its answer from the moment it is put: one is
/// refused here when the queue could never hold that room; an answer with a reply that does not
/// fit is handed over as LIMIT, which always fits; and a ship whose queue is full, with
/// questions waiting, is exported and imported whole under the same settings.
#[test]
fn a_question_holds_room_for_its_answer() {
    // A queue too small for any answer: the question is refused, and nothing is written.
    let tiny = Config { max_inbox_bytes: 300, ..fast() };
    let t = two_with("reserve-tiny", (fast(), NetConfig::default()), (tiny, NetConfig::default()), counter_with(true, false), &["~nec"]);
    assert!(matches!(t.b.deliver("~nec", "tally", b"ask-on zod counter counter 5000 hits"), Err(Error::Rejected(Rejection::Limit(why))) if why.contains("no room for the question's answer")));
    assert_eq!(rows(&t.b, "~nec")["asks"], 0);
    drop(t);

    // Room for the answer without a reply, not for a reply of 2,000 bytes: LIMIT, once.
    let small = Config { max_inbox_bytes: 1500, ..fast() };
    let t = two_with("reserve-small", (fast(), NetConfig::default()), (small, NetConfig::default()), counter_with(true, false), &["~nec"]);
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 ?big 2000");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter limit [no room on this ship for the answer]  from ~zod/counter counter")]);
    drop(t);

    // A full queue, with questions waiting: exported, and imported under the same settings.
    let full = Config { max_inbox_bytes: 64 << 10, max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("reserve-full", (fast(), NetConfig::default()), (full.clone(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    t.a_net.take().unwrap().vanish();
    let asked = say(&t.b, "~nec", "tally", "ask-many zod 3 60000");
    let padding = "p".repeat(2000);
    let mut queued = 0;
    while t.b.deliver("~nec", "tally", format!("later note {padding}").as_bytes()).is_ok() {
        queued += 1;
    }
    assert!(queued > 10, "{queued}");
    // And to the last few bytes, with small ones.
    while t.b.deliver("~nec", "tally", b"later note").is_ok() {}
    // The queue is full: another question is refused for want of room for its answer.
    assert!(matches!(t.b.deliver("~nec", "tally", b"ask-on zod counter counter 60000 hits"), Err(Error::Rejected(Rejection::Limit(_)))));
    let out = TempDir::new("reserve-full-copy");
    let code = "test-test-test-test-test-test-test-test";
    t.b.set_recovery_key("~nec", crate::seal::recovery_public(code)).unwrap();
    t.b.export_ship("~nec", out.0.join("copy")).unwrap();
    let other_dir = TempDir::new("reserve-full-into");
    let other = Runtime::open(&other_dir.0, full).unwrap();
    other.import_ship(out.0.join("copy"), "~nec", code).unwrap();
    while other.run_pending("~nec", 64).unwrap() > 0 {}
    for n in asked.split(' ') {
        assert_eq!(answers_to(&other, "~nec", n).len(), 1, "{n}: {:?}", answers(&other, "~nec"));
    }
    // An export with one more question waiting than its queue has room to hold for: refused.
    let hostile = out.0.join("one-more");
    copy_export(&out.0.join("copy"), &hostile);
    rework(&hostile, "~nec", code, |file| {
        // With the count of questions moved on to match, so that only the room held is wrong.
        file.execute_batch(
            "INSERT INTO asks SELECT seq + 1000, agent, ship, target, interface, payload, within, deadline FROM asks WHERE seq = (SELECT MAX(seq) FROM asks);
             UPDATE meta SET value = (SELECT MAX(seq) FROM asks) WHERE key = 'ask_gen';",
        )
        .unwrap();
    });
    let refused_dir = TempDir::new("reserve-full-refused");
    let refused = Runtime::open(&refused_dir.0, Config { max_inbox_bytes: 64 << 10, max_queued_per_deliver: 0, ..fast() }).unwrap();
    assert!(matches!(refused.import_ship(&hostile, "~nec", code), Err(Error::BadShipFile(_))));
    drop(t);

    // Names at their longest (a comet's, an agent's of 64 bytes, an interface's of 128): the
    // room held is no less than any answer without a reply to that question takes; it is
    // counted in the queue's total as the question is put, given back when it is dropped, and
    // counted the same when the ship is woken afresh.
    let far = "~dozzod-dozzod-dozzod-dozzod--dozzod-dozzod-dozzod-dozzod";
    let (agent, interface) = ("a".repeat(64), "i".repeat(128));
    let t = two("reserve-long", counter_with(true, false));
    t.directory.set(far, ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    let tally = t.b.add_module(&wasm("tally")).unwrap();
    let uses = Use { ship: "*".into(), agent: agent.clone(), interface: interface.clone(), read: false, send: false, ask: true };
    t.b.install("~nec", "asker", &tally, &Manifest { provides: vec![], uses: vec![uses] }).unwrap();
    let held = || t.b.inner.with_ship("~nec", |ship| Ok((ship.inbox_bytes, crate::store::inbox_bytes(&lock(&ship.conn))?))).unwrap();
    let before = held();
    assert_eq!(before.0, before.1);
    let puts = t.b.inner.question_puts.load(Ordering::SeqCst);
    let n: u64 = say(&t.b, "~nec", "asker", &format!("ask-on {far} {agent} {interface} 60000 hits")).parse().unwrap();
    let row = t.b.inner.with_ship("~nec", |ship| Ok(crate::store::ask_get(&lock(&ship.conn), n)?)).unwrap().unwrap();
    let reserve = crate::store::ask_reserve(&row.ship, &row.target, &row.interface);
    for outcome in [Outcome::Denied, Outcome::Failed, Outcome::Limit, Outcome::NoAnswer, Outcome::Unreachable, Outcome::NotUnderstood] {
        let answered = ship_proto::Answered { about: n, ship: row.ship.clone(), agent: row.target.clone(), interface: row.interface.clone(), outcome: outcome as i32, reply: Vec::new(), reason: "x".repeat(crate::store::MAX_REASON_BYTES) };
        assert!(ship_proto::Message::encoded_len(&answered) as u64 + crate::store::MESSAGE_OVERHEAD <= reserve, "{outcome:?}");
    }
    let asked = held();
    assert_eq!(asked, (before.0 + reserve, before.1 + reserve));
    // Once the network has looked at it and its task has read it, nothing takes the ship.
    eventually("its task to be putting it", Duration::from_secs(5), || t.b.inner.question_puts.load(Ordering::SeqCst) > puts);
    t.b.sleep_idle(Duration::ZERO);
    assert_eq!(t.b.awake(), 0);
    assert_eq!(held(), asked, "counted the same once woken afresh");
    assert_eq!(say(&t.b, "~nec", "asker", &format!("drop-ask {n}")), "true");
    assert_eq!(held(), before, "given back when dropped");
}

/// A command carries the largest reply its sender takes, and the ship that runs it holds the
/// reply to that: the sender allows 512 bytes and the other ship 1,024, so 512 comes back with
/// the receipt and 513 does not stand (LIMIT). A reply that is empty is marked as a reply; a
/// ship whose runtime predates replies answers RAN with none marked.
#[test]
fn a_reply_is_held_to_the_senders_bound_and_marked() {
    let (a_cfg, b_cfg) = (Config { max_receipt_reply_bytes: 1024, ..fast() }, Config { max_receipt_reply_bytes: 512, ..fast() });
    let t = two_with("reply-bound", (a_cfg, NetConfig::default()), (b_cfg, NetConfig::default()), counter_with(false, true), &["~nec"]);
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 512");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 513");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 0");
    eventually("three receipts", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 3);
    t.a.inner.replies_unknown.store(true, Ordering::SeqCst);
    say(&t.b, "~nec", "tally", "tell-reply zod inc hits");
    eventually("four receipts", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 4);
    let got = receipts(&t.b, "~nec");
    assert_eq!(got[0], "1 ~zod/counter counter ran [] from ~zod/counter counter reply of 512 bytes", "{got:?}");
    assert_eq!(got[1], "2 ~zod/counter counter limit [the reply is larger than that ship sends with a receipt] from ~zod/counter counter", "{got:?}");
    assert_eq!(got[2], "3 ~zod/counter counter ran [] from ~zod/counter counter reply ", "{got:?}");
    assert_eq!(got[3], "4 ~zod/counter counter ran [] from ~zod/counter counter", "{got:?}");
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "3");
}

/// The reviewer's case: two ships full of large commands for each other each first take two
/// large replies from roomy ships (answers to commands those ran while they were away). A
/// reply handed to an agent keeps nothing of its bytes in the ship's file afterwards (the audit
/// row holds facts only), so the room the two keep for each other's first command is still
/// there, and every command between them is delivered and answered.
#[test]
fn large_replies_taken_first_do_not_wedge_two_full_ships() {
    let big = Config { max_ship_bytes: 1 << 20, max_event_bytes: 64 << 10, max_receipt_reply_bytes: 64 << 10, max_checkpoint_bytes: 64 << 10, ..fast() };
    let patient = Config { max_queued_per_deliver: 0, max_receipt_reply_bytes: 64 << 10, ..fast() };
    let dirs = (TempDir::new("wedge-a"), TempDir::new("wedge-b"), TempDir::new("wedge-c"));
    let directory = Directory::new();
    let counter = counter_with(false, true);
    let zod = crewed(&dirs.0 .0, big.clone(), &["~zod"], &counter, "*");
    let nec = crewed(&dirs.1 .0, big.clone(), &["~nec"], &counter, "*");
    let roomy = crewed(&dirs.2 .0, patient, &["~bus", "~wes"], &counter, "*");
    // Short waits between tries, so that ships coming back are reached soon.
    let quick = NetConfig { max_retry_delay: Duration::from_millis(500), ..NetConfig::default() };
    let roomy_net = Network::start(roomy.clone(), directory.clone(), quick.clone()).unwrap();
    for ship in ["~bus", "~wes"] {
        directory.set(ship, roomy.public_key(ship).unwrap(), roomy_net.addr()).unwrap();
    }
    // Each sends the roomy ships two commands wanting 64 KiB replies, which they take and run
    // while it is away.
    for (rt, ship, far) in [(&zod, "~zod", "bus"), (&nec, "~nec", "wes")] {
        let net = Network::start(rt.clone(), directory.clone(), quick.clone()).unwrap();
        directory.set(ship, rt.public_key(ship).unwrap(), net.addr()).unwrap();
        for _ in 0..2 {
            say(rt, ship, "tally", &format!("tell-reply {far} inc-big hits 65536"));
        }
        let far_ship = format!("~{far}");
        eventually("the roomy ship to hold them", Duration::from_secs(20), || roomy.pending(&far_ship).unwrap() == 2);
        net.vanish();
        assert_eq!(roomy.run_pending(&far_ship, 10).unwrap(), 2);
    }
    // Each fills up with large commands for the other.
    let padding = "p".repeat(60_000);
    let mut sent = Vec::new();
    for (rt, ship, other) in [(&zod, "~zod", "nec"), (&nec, "~nec", "zod")] {
        let mut n = 0;
        while rt.deliver(ship, "tally", format!("tell {other} inc hits 1 {padding}").as_bytes()).is_ok() {
            n += 1;
        }
        assert!(n > 3, "{n}");
        sent.push(n);
    }
    // ~zod comes back first and takes its two large replies; then ~nec comes back and takes its
    // own, and meets ~zod.
    let zod_net = Network::start(zod.clone(), directory.clone(), quick.clone()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("~zod's two replies", Duration::from_secs(30), || receipts(&zod, "~zod").iter().filter(|line| line.ends_with(" reply of 65536 bytes")).count() == 2);
    // Handed over, the replies are nowhere in the audit log: each receipt is there as its
    // facts, within a receipt's 512 bytes, and no row holds any run of a reply's bytes.
    audit_keeps_facts_only(&zod, "~zod", b'r', &[(b"receipt ", " reply of 65536 bytes", 2)]);
    let nec_net = Network::start(nec.clone(), directory.clone(), quick).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("every command between them answered", Duration::from_secs(120), || zod.unanswered("~zod").unwrap() == 0 && nec.unanswered("~nec").unwrap() == 0);
    assert_eq!(count_hits(&nec, "~nec"), sent[0] as u64);
    assert_eq!(count_hits(&zod, "~zod"), sent[1] as u64);
    drop((zod_net, nec_net, roomy_net));
}

fn count_hits(rt: &Runtime, ship: &str) -> u64 {
    say(rt, ship, "counter", "get hits").parse().unwrap()
}

/// What `ship`'s audit log keeps of receipts and answers is their facts only: no row holds 64
/// of a reply's bytes (`byte`) in a row; every row of a receipt's or an answer's facts is
/// within a receipt's bound (512 bytes); and for each `(start, saying, count)`, at least
/// `count` rows begin with `start` and say `saying`.
fn audit_keeps_facts_only(rt: &Runtime, ship: &str, byte: u8, expected: &[(&[u8], &str, usize)]) {
    let rows = rt.audit(ship, 100_000).unwrap();
    let run = vec![byte; 64];
    for entry in &rows {
        assert!(!entry.event.windows(64).any(|window| window == run.as_slice()), "an audit row holds a reply: {:?}", String::from_utf8_lossy(&entry.event[..entry.event.len().min(80)]));
        if entry.event.starts_with(b"receipt ") || entry.event.starts_with(b"answer ") {
            assert!(entry.event.len() <= crate::store::MAX_RECEIPT_BYTES, "{}", entry.event.len());
        }
    }
    for (start, saying, count) in expected {
        let found = rows.iter().filter(|entry| entry.event.starts_with(start) && String::from_utf8_lossy(&entry.event).contains(saying)).count();
        assert!(found >= *count, "{found} rows of {:?} saying {saying:?}", String::from_utf8_lossy(start));
    }
}

/// Open an exported ship's file, change it with `change`, and seal it again, as only someone
/// with the recovery code could: for exports that must be refused.
fn rework(copy: &Path, ship: &str, code: &str, change: impl FnOnce(&rusqlite::Connection)) {
    let name = ship.trim_start_matches('~');
    let path = copy.join(format!("{name}.ship"));
    let (seed, contents) = crate::seal::open_export(code, name, fs::read(&path).unwrap()).unwrap();
    let plain = copy.join("plain");
    fs::write(&plain, &contents).unwrap();
    change(&rusqlite::Connection::open(&plain).unwrap());
    let changed = fs::read(&plain).unwrap();
    fs::remove_file(&plain).unwrap();
    fs::write(&path, crate::seal::seal_export(&crate::seal::recovery_public(code), name, &seed, &changed, [5; 32])).unwrap();
}

/// A copy of the export at `from`, at `to`, to change without touching the first.
fn copy_export(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

/// Exported ships holding each new kind of record at its limit come in under the same settings:
/// a queued answer of 2 MiB (more than the 1 MiB rows otherwise are), a queued receipt with a
/// reply of 1,024 bytes (as large as a command may be), and a question waiting with a payload
/// at `max_ask_bytes`; and again once the answer and the receipt have been handled, when only
/// bounded facts of them are in the audit log.
#[test]
fn an_export_holding_every_new_record_at_its_limit_imports() {
    let cfg = Config { max_event_bytes: 1024, max_receipt_reply_bytes: 1024, max_answer_bytes: 2 << 20, max_ask_bytes: 900, max_queued_per_deliver: 0, ..fast() };
    let net = NetConfig { max_message_bytes: 4 << 20, ..NetConfig::default() };
    let dirs = (TempDir::new("atlimit-a"), TempDir::new("atlimit-b"));
    let directory = Directory::new();
    let zod = crewed(&dirs.0 .0, Config { max_queued_per_deliver: 64, ..cfg.clone() }, &["~zod"], &counter_with(true, true), "*");
    let nec = crewed(&dirs.1 .0, cfg.clone(), &["~nec"], &counter_with(true, true), "*");
    let zod_net = Network::start(zod.clone(), directory.clone(), net.clone()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), net.clone()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    // ~bus is somewhere nothing answers.
    directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    say(&nec, "~nec", "tally", &format!("ask-on zod counter counter 30000 ?big {}", 2 << 20));
    say(&nec, "~nec", "tally", "tell-reply zod inc-big hits 1024");
    say(&nec, "~nec", "tally", &format!("ask-on bus counter counter 60000 {}", "q".repeat(900)));
    eventually("the answer and the receipt queued", Duration::from_secs(30), || nec.pending("~nec").unwrap() == 2);
    let code = "test-test-test-test-test-test-test-test";
    nec.set_recovery_key("~nec", crate::seal::recovery_public(code)).unwrap();
    let out = TempDir::new("atlimit-copy");
    nec.export_ship("~nec", out.0.join("queued")).unwrap();
    let first = TempDir::new("atlimit-first");
    let other = Runtime::open(&first.0, cfg.clone()).unwrap();
    other.import_ship(out.0.join("queued"), "~nec", code).unwrap();
    // Handled: the answer, the receipt, and the question answered NO_ANSWER at import.
    assert_eq!(other.run_pending("~nec", 10).unwrap(), 3);
    assert!(answers(&other, "~nec").iter().any(|line| line.contains(&format!(" reply [] ({} bytes) ", 2 << 20))), "{:?}", answers(&other, "~nec"));
    assert!(receipts(&other, "~nec").iter().any(|line| line.ends_with(" reply of 1024 bytes")));
    audit_keeps_facts_only(&other, "~nec", b'a', &[(b"answer ", &format!(" reply of {} bytes", 2 << 20), 1), (b"receipt ", " reply of 1024 bytes", 1)]);
    audit_keeps_facts_only(&other, "~nec", b'r', &[]);
    other.set_recovery_key("~nec", crate::seal::recovery_public(code)).unwrap();
    other.export_ship("~nec", out.0.join("handled")).unwrap();
    let second = TempDir::new("atlimit-second");
    let again = Runtime::open(&second.0, cfg).unwrap();
    again.import_ship(out.0.join("handled"), "~nec", code).unwrap();
    assert_eq!(answers(&again, "~nec").len(), 2);
    drop((zod_net, nec_net));
}

/// A question dropped while it is being put stops on the wire: thirty times over, a question
/// put to a ship that only says it is too busy (for longer than the test waits) is dropped once
/// a try of it has really gone out and come back refused, and its task ends within three
/// seconds, its payload with it, and sends no more tries.
#[test]
fn a_dropped_question_stops_being_put() {
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 1500, ..fast() };
    let t = two_with("drop-stops", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    // One slow question rests ~zod from ~nec's questions for 9 x 1.5 s.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let putting = || t.b_net.as_ref().unwrap().shared.carrier.putting_count();
    let tries = || t.b.inner.question_tries.load(Ordering::SeqCst);
    for _ in 0..30 {
        let before = tries();
        let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits");
        // A try of it has gone out and come back "too busy" (and its task is told only by the
        // drop that it is dropped).
        eventually("a try on the wire", Duration::from_secs(3), || tries() > before);
        assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {n}")), "true");
        eventually("its task stopped", Duration::from_secs(3), || putting() == 0);
        let after = tries();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(tries(), after, "tries went out after the drop");
    }
    eventually("no task left putting a dropped question", Duration::from_secs(3), || putting() == 0);
    assert!(answers(&t.b, "~nec").is_empty());
}

/// One compute budget pays for the whole of a question: the kernel's decision as well as the
/// handler. Measured once with room to spare (the kernel's part K and all of it T), a ship
/// given T less half of K cannot answer, though the handler alone would fit, and one given T
/// (and one unit more, since a call that ends with no fuel left has run out) can.
#[test]
fn one_budget_pays_for_the_kernels_decision_and_the_handler() {
    let t = two("budget-measure", counter_with(true, false));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    let (kernel, all) = *lock(&t.a.inner.question_fuel).last().unwrap();
    assert!(kernel > 0 && all > kernel, "{kernel} {all}");
    drop(t);
    let short = Config { ask_fuel: all - kernel / 2, ..fast() };
    let t = two_with("budget-short", (short, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)), Err(AskError::Failed));
    drop(t);
    let enough = Config { ask_fuel: all + 1, ..fast() };
    let t = two_with("budget-enough", (enough, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    drop(t);

    // A question whose handler reads another agent: the nested read's routing and handler come
    // out of the same budget. Each part is measured (the two decisions and the nested
    // handler), and all of it is no less than the parts together; and, as above, T less half
    // the nested decision is not enough, and T is.
    let nested = |label: &str, cfg: Config| {
        let t = two_with(label, (cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
        let tally = t.a.add_module(&wasm("tally")).unwrap();
        let reads = Use { ship: String::new(), agent: "counter".into(), interface: "counter".into(), read: true, send: false, ask: false };
        let nest = Manifest { provides: vec![Provide { interface: "nest".into(), public: false, remote: false, asked: true }], uses: vec![reads] };
        t.a.install("~zod", "nest", &tally, &nest).unwrap();
        lock(&t.a.inner.question_parts).clear();
        let asked = t.b.ask("~nec", None, "~zod", "nest", "nest", b"via-counter hits", Duration::from_secs(10));
        let parts = lock(&t.a.inner.question_parts).clone();
        let measured = lock(&t.a.inner.question_fuel).last().copied();
        (asked, parts, measured)
    };
    let (asked, parts, measured) = nested("budget-nested", fast());
    assert_eq!(asked.unwrap(), b"0");
    let (_, all) = measured.unwrap();
    assert_eq!(parts.len(), 3, "the first decision, the nested decision, the nested handler: {parts:?}");
    assert!(all >= parts.iter().sum::<u64>(), "{all} < {parts:?}");
    let short = Config { ask_fuel: all - parts[1] / 2, ..fast() };
    assert_eq!(nested("budget-nested-short", short).0, Err(AskError::Failed));
    let enough = Config { ask_fuel: all + 1, ..fast() };
    assert_eq!(nested("budget-nested-enough", enough).0.unwrap(), b"0");
}

/// A question over HTTP waits as a long poll does, counted with them: with four workers (two
/// may wait), two long polls waiting leave none for a question; and with two workers (one may
/// wait), a question is answered.
#[test]
fn an_http_question_waits_counted_with_long_polls() {
    let t = two("http-waiting", counter_with(true, false));
    say(&t.b, "~nec", "counter", "journal x");
    let server = Server::start(t.b.clone(), ServerConfig { workers: 4, ..ServerConfig::default() }).unwrap();
    let code = t.b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", t.b.sign_in("~nec", &code, "test").unwrap().0);
    let polls: Vec<_> = (0..2)
        .map(|_| {
            let (addr, auth) = (server.addr(), auth.clone());
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "GET /ships/nec/logs/counter/journal/entries?after=1&wait=3 HTTP/1.0\r\nHost: {addr}\r\nAuthorization: {auth}\r\n\r\n").unwrap();
                let mut raw = Vec::new();
                let _ = stream.read_to_end(&mut raw);
            })
        })
        .collect();
    eventually("both long polls waiting", Duration::from_secs(5), || server.waiting() == 2);
    let refused = http(&server, "POST", "/ships/nec/ask/zod/counter/counter", &auth, b"hits");
    assert_eq!(refused.0, 503, "{}", String::from_utf8_lossy(&refused.2));
    for poll in polls {
        poll.join().unwrap();
    }
    assert_eq!(http(&server, "POST", "/ships/nec/ask/zod/counter/counter", &auth, b"hits").0, 200);
    drop(server);
    let two_workers = Server::start(t.b.clone(), ServerConfig { workers: 2, ..ServerConfig::default() }).unwrap();
    assert_eq!(http(&two_workers, "POST", "/ships/nec/ask/zod/counter/counter", &auth, b"hits").0, 200);
    drop(two_workers);

    // And a question counts for as long as it waits: with two workers (one may wait), a long
    // poll made while a slow question waits is answered at once, not held; once the question
    // is answered, a long poll waits its second.
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 2000, ..fast() };
    let t = two_with("http-slow", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    say(&t.b, "~nec", "counter", "journal x");
    let server = Server::start(t.b.clone(), ServerConfig { workers: 2, ..ServerConfig::default() }).unwrap();
    let code = t.b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", t.b.sign_in("~nec", &code, "test").unwrap().0);
    let poll = |wait: u32| {
        let began = Instant::now();
        let (status, _, _) = http(&server, "GET", &format!("/ships/nec/logs/counter/journal/entries?after=1&wait={wait}"), &auth, b"");
        (status, began.elapsed())
    };
    std::thread::scope(|scope| {
        let slow = scope.spawn(|| http(&server, "POST", "/ships/nec/ask/zod/counter/counter?within=5", &auth, b"?spin").0);
        eventually("the slow question counted as waiting", Duration::from_secs(5), || server.waiting() == 1);
        let (status, took) = poll(1);
        assert!(status == 200 && took < Duration::from_millis(500), "a long poll was held while a question waited: {status} {took:?}");
        assert_eq!(slow.join().unwrap(), 502);
    });
    let (status, took) = poll(1);
    assert!(status == 200 && took >= Duration::from_millis(900), "{status} {took:?}");
}

/// At the boundary of what one message carries, with `max_message_bytes` as small as a start
/// allows (the largest command and 4 KiB): a command at its limit asking for a reply at its
/// limit runs and its receipt brings the reply; a question and an answer each held to what a
/// message carries (that less 1 KiB) go, and one byte more does not.
#[test]
fn deliveries_at_the_boundary_of_one_message() {
    let cfg = Config { max_event_bytes: 8192, max_receipt_reply_bytes: 8192, max_checkpoint_bytes: 4096, max_unanswered: 64, ..fast() };
    let net = NetConfig { max_message_bytes: 8192 + 4096, ..NetConfig::default() };
    let t = two_with("boundary", (cfg.clone(), net.clone()), (cfg, net), counter_with(true, true), &["~nec"]);
    // A command of exactly the largest size a command may be (padded by tally to 8,192 bytes),
    // asking for a reply of the largest size, runs and brings its reply back; one byte more is
    // not sent.
    say(&t.b, "~nec", "tally", "tell-reply-sized zod 8192 inc-big hits 8192");
    eventually("the receipt", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 1);
    assert!(receipts(&t.b, "~nec")[0].ends_with(" ran [] from ~zod/counter counter reply of 8192 bytes"), "{:?}", receipts(&t.b, "~nec"));
    assert!(matches!(t.b.deliver("~nec", "tally", b"tell-reply-sized zod 8193 inc-big hits 8192"), Err(Error::Rejected(Rejection::Limit(_)))));
    let most = 8192 + 4096 - 1024;
    assert_eq!(ask(&t, None, "counter", format!("?big {most}").as_bytes(), Duration::from_secs(10)).map(|reply| reply.len()), Ok(most));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(ask(&t, None, "counter", format!("?big {}", most + 1).as_bytes(), Duration::from_secs(10)), Err(AskError::Limit));
    let mut payload = b"?big 1 ".to_vec();
    payload.resize(most, b' ');
    std::thread::sleep(Duration::from_millis(200));
    assert!(ask(&t, None, "counter", &payload, Duration::from_secs(10)).is_ok());
    payload.push(b' ');
    assert_eq!(ask(&t, None, "counter", &payload, Duration::from_secs(10)), Err(AskError::TooLarge));
}

/// A ship that takes back no reply at all does not send a command that wants one, for 0 on the
/// wire means "no reply wanted" and the command would come back RAN without it: refused here,
/// in words of their own, whether its limit on replies is 0 or its queue is too small for any
/// receipt with a reply (592 bytes). A command that wants no reply still goes.
#[test]
fn a_command_wanting_its_reply_is_not_sent_from_a_ship_that_takes_none() {
    for (label, cfg) in [("noreply-zero", Config { max_receipt_reply_bytes: 0, ..fast() }), ("noreply-queue", Config { max_inbox_bytes: 592, ..fast() })] {
        assert_eq!(crate::store::reply_most(&cfg), 0, "{label}");
        let t = two_with(label, (fast(), NetConfig::default()), (cfg, NetConfig::default()), counter_with(false, true), &["~nec"]);
        let refused = t.b.deliver("~nec", "tally", b"tell-reply zod inc hits");
        assert!(matches!(&refused, Err(Error::Rejected(Rejection::Limit(why))) if why == crate::host::NO_REPLY_TAKEN), "{label}: {refused:?}");
        assert_eq!(rows(&t.b, "~nec")["peer_out"], 0, "{label}");
        say(&t.b, "~nec", "tally", "tell zod inc hits");
        eventually("the command without a reply to run", Duration::from_secs(10), || say(&t.a, "~zod", "counter", "get hits") == "1");
    }
}

/// The ship that runs a command holds the reply to its own limit when that is the smaller
/// (sender 1,024, receiver 512): 512 comes back, 513 does not stand. And a command keeps the
/// bound it was sent with: sent allowing 1,024 bytes while the other ship is away, the sender
/// then restarted allowing only 512, its reply of 1,024 bytes still comes back whole.
#[test]
fn a_reply_is_held_to_the_receivers_bound_and_to_the_bound_its_command_was_sent_with() {
    let (a_cfg, b_cfg) = (Config { max_receipt_reply_bytes: 512, ..fast() }, Config { max_receipt_reply_bytes: 1024, ..fast() });
    let t = two_with("reply-receiver", (a_cfg, NetConfig::default()), (b_cfg, NetConfig::default()), counter_with(false, true), &["~nec"]);
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 512");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 513");
    eventually("two receipts", Duration::from_secs(10), || receipts(&t.b, "~nec").len() == 2);
    let got = receipts(&t.b, "~nec");
    assert_eq!(got[0], "1 ~zod/counter counter ran [] from ~zod/counter counter reply of 512 bytes", "{got:?}");
    assert_eq!(got[1], "2 ~zod/counter counter limit [the reply is larger than that ship sends with a receipt] from ~zod/counter counter", "{got:?}");
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "1");
    drop(t);

    let quick = NetConfig { max_retry_delay: Duration::from_millis(500), ..NetConfig::default() };
    let (a_cfg, b_cfg) = (Config { max_receipt_reply_bytes: 2048, ..fast() }, Config { max_receipt_reply_bytes: 1024, ..fast() });
    let mut t = two_with("reply-kept", (a_cfg.clone(), quick.clone()), (b_cfg, quick.clone()), counter_with(false, true), &["~nec"]);
    t.a_net.take().unwrap().vanish();
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 1024");
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, Config { max_receipt_reply_bytes: 512, ..fast() }, &scratch);
    let b_net = Network::start(t.b.clone(), t.directory.clone(), quick.clone()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    let a_net = Network::start(t.a.clone(), t.directory.clone(), quick).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    eventually("the receipt", Duration::from_secs(30), || receipts(&t.b, "~nec").len() == 1);
    assert_eq!(receipts(&t.b, "~nec")[0], "1 ~zod/counter counter ran [] from ~zod/counter counter reply of 1024 bytes");
}

/// A question never waits on the cache of compiled modules: while another call is held part
/// way through a compile (here `add_module` of a module new to the runtime), a question to a
/// warm ship is answered at once.
#[test]
fn a_question_does_not_wait_behind_another_calls_compile() {
    let t = two("compile-behind", counter_with(true, false));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    let (entered, held) = std::sync::mpsc::channel();
    let (release, go_on) = std::sync::mpsc::channel();
    *lock(&t.a.inner.compile_gate) = Some((entered, go_on));
    let a = t.a.clone();
    let module = wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) (i32.const 0)))"#).unwrap();
    let adding = std::thread::spawn(move || a.add_module(&module));
    held.recv_timeout(Duration::from_secs(10)).unwrap();
    let began = Instant::now();
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(3)).unwrap(), b"0");
    assert!(began.elapsed() < Duration::from_secs(1), "{:?}", began.elapsed());
    release.send(()).unwrap();
    assert!(adding.join().unwrap().is_ok());
}

/// A module is compiled once, whoever asks for it: with the agent's module forgotten, a
/// question's compile of it held part way, another question for it (too busy, and not compiling
/// it again) and an ordinary call for it (which waits for that compile) find it being
/// compiled; once let go, it was compiled once and both are answered. And a compile that
/// panics stops nothing: the next one is done.
#[test]
fn a_module_is_compiled_once_whoever_asks_and_a_panic_stops_nothing() {
    let t = two("compile-once", counter_with(true, false));
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    let net = t.b_net.as_ref().unwrap();
    let busy = |within: Duration| matches!(net.ask_raw("~nec", "~zod", question("", "counter", b"hits", 5000), within), Err(NetError::Refused(why)) if why == TOO_BUSY);
    t.a.inner.forget_modules();
    *lock(&t.a.inner.ask_rests) = Default::default();
    let compiles = t.a.inner.compiles.load(Ordering::SeqCst);
    let (entered, held) = std::sync::mpsc::channel();
    let (release, go_on) = std::sync::mpsc::channel();
    *lock(&t.a.inner.compile_gate) = Some((entered, go_on));
    assert!(busy(Duration::from_secs(5)), "the first question");
    held.recv_timeout(Duration::from_secs(10)).unwrap();
    *lock(&t.a.inner.ask_rests) = Default::default();
    assert!(busy(Duration::from_secs(5)), "the second question");
    let a = t.a.clone();
    let ordinary = std::thread::spawn(move || a.read("~zod", "counter", "counter", b"hits"));
    std::thread::sleep(Duration::from_millis(300));
    assert!(!ordinary.is_finished(), "the ordinary call did not wait for the compile under way");
    release.send(()).unwrap();
    assert_eq!(ordinary.join().unwrap().unwrap(), b"0");
    assert_eq!(t.a.inner.compiles.load(Ordering::SeqCst) - compiles, 1, "compiled more than once");
    *lock(&t.a.inner.ask_rests) = Default::default();
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");

    // A panic part way through a compile off a question's path: the next question's compile
    // is still done, and questions are answered again.
    t.a.inner.forget_modules();
    t.a.inner.compile_panics.store(1, Ordering::SeqCst);
    *lock(&t.a.inner.ask_rests) = Default::default();
    assert!(busy(Duration::from_secs(5)));
    eventually("the compile to have panicked", Duration::from_secs(5), || t.a.inner.compile_panics.load(Ordering::SeqCst) == 0 && !t.a.inner.compiling.load(Ordering::SeqCst));
    eventually("questions answered again", Duration::from_secs(10), || {
        *lock(&t.a.inner.ask_rests) = Default::default();
        ask(&t, None, "counter", b"hits", Duration::from_secs(2)) == Ok(b"0".to_vec())
    });
}

/// A question is not started late: held at the start of its ship's wake (the runtime's gate
/// there), a question whose asker gives up meanwhile (given up on, and the runtime saying it
/// has seen that, before the wake is let go), and one whose time passes meanwhile (let go once
/// its recorded deadline has passed), ask no decision of the kernel (counted where a decision
/// begins), the second told "it took too long"; in both, the job's end (its place given back)
/// is waited for before anything is looked at. (If the wake were let go more than 250 ms past
/// the deadline, the network would stop waiting for the job and answer "it took too long" on its
/// own, which would also hide a job that did not look at its time; the test lets it go 1 ms
/// after.)
#[test]
fn a_question_whose_ship_was_slow_to_wake_is_not_started_late() {
    let t = two("slow-wake", counter_with(true, false));
    let shared = t.a_net.as_ref().unwrap().shared.clone();
    eventually("the start-up look", Duration::from_secs(10), || shared.started_up.load(Ordering::SeqCst));
    let questions = t.a_net.as_ref().unwrap().shared.questions.clone();
    assert_eq!(ask(&t, None, "counter", b"hits", Duration::from_secs(10)).unwrap(), b"0");
    eventually("the first question's place to come back", Duration::from_secs(5), || lock(&questions).running == 0);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let net = t.b_net.as_ref().unwrap();
    let decisions = || t.a.inner.decisions_begun.load(Ordering::SeqCst);

    assert_eq!(t.a.sleep_idle(Duration::ZERO), 1);
    *lock(&t.a.inner.ask_rests) = Default::default();
    let (before, from) = (decisions(), t.a.inner.notes_len());
    let (waking, let_go) = t.a.inner.gates.arm("question wake");
    let asker = {
        let shared = net.shared.clone();
        net.threads.get().spawn(async move {
            let _ = shared.ask_within("~nec", "~zod", question("", "counter", b"hits", 5000), Duration::from_secs(9)).await;
        })
    };
    waking.recv_timeout(Duration::from_secs(5)).expect("the job to begin waking the ship");
    asker.abort();
    assert!(net.threads.get().handle().block_on(asker).is_err_and(|e| e.is_cancelled()));
    eventually("the asker's giving up seen", Duration::from_secs(5), || !t.a.inner.notes_of("question given up", "nec", from).is_empty());
    drop(let_go);
    eventually("the question's job to end", Duration::from_secs(5), || t.a.inner.notes_of("question place given back", "nec", from).len() == 1);
    assert_eq!(decisions(), before, "a decision was asked for a question given up on");

    assert_eq!(t.a.sleep_idle(Duration::ZERO), 1);
    *lock(&t.a.inner.ask_rests) = Default::default();
    let (before, from) = (decisions(), t.a.inner.notes_len());
    let (waking, let_go) = t.a.inner.gates.arm("question wake");
    let b = t.b_net.as_ref().unwrap().shared.clone();
    let threads = t.b_net.as_ref().unwrap().threads.get().handle().clone();
    let late = std::thread::spawn(move || threads.block_on(b.ask_within("~nec", "~zod", question("", "counter", b"hits", 400), Duration::from_secs(5))).map(|(reply, _)| reply));
    waking.recv_timeout(Duration::from_secs(5)).expect("the job to begin waking the ship");
    let deadline = t.a.inner.notes_of("question deadline", "nec", from)[0].0;
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    assert!(Instant::now() > deadline);
    drop(let_go);
    let late = late.join().unwrap();
    assert!(format!("{late:?}").contains(crate::ask::TOOK_TOO_LONG), "{late:?}");
    eventually("the question's job to end", Duration::from_secs(5), || t.a.inner.notes_of("question place given back", "nec", from).len() == 1);
    assert_eq!(decisions(), before, "a decision was asked for a question past its time");
}

/// A committed drop reaches the question's task without the ship being taken again:
/// the event that drops it keeps its ship for three seconds after it commits, and the task has
/// stopped, sending no more tries, well before that.
#[test]
fn a_dropped_question_stops_at_once_though_its_ship_is_held() {
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 1500, ..fast() };
    let t = two_with("drop-held", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    // One slow question rests ~zod from ~nec's questions for 9 x 1.5 s.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let tries = || t.b.inner.question_tries.load(Ordering::SeqCst);
    let putting = || t.b_net.as_ref().unwrap().shared.carrier.putting_count();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits");
    eventually("a try on the wire", Duration::from_secs(5), || tries() > 0);
    *lock(&t.b.inner.hold_after_commit) = Some(Duration::from_secs(3));
    let b = t.b.clone();
    let dropping = std::thread::spawn(move || say(&b, "~nec", "tally", &format!("drop-ask {n}")));
    eventually("its task to stop", Duration::from_secs(1), || putting() == 0);
    assert!(!dropping.is_finished(), "the ship was let go first");
    let after = tries();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(tries(), after, "tries went out after the drop");
    assert_eq!(dropping.join().unwrap(), "true");
}

/// What came of a question is written however long the ship's file cannot be written: the
/// write made to fail three times, it goes in on the fourth (its reply let go, LIMIT in its
/// place, after the first failure), and exactly one answer is handed over. A drop while it waits between writes ends that at once, and nothing is ever handed
/// over. A restart while it waits: the question is still waiting there, and is answered once.
#[test]
fn an_answer_that_cannot_be_written_is_written_later_once() {
    let quick = NetConfig { retry_delay: Duration::from_millis(50), max_retry_delay: Duration::from_millis(200), ..NetConfig::default() };
    let t = two_with("write-fails", (fast(), NetConfig::default()), (fast(), quick), counter_with(true, false), &["~nec"]);
    t.b.inner.answer_write_failures.store(3, Ordering::SeqCst);
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 hits");
    eventually("the answer", Duration::from_secs(10), || !answers_to(&t.b, "~nec", &n).is_empty());
    assert_eq!(t.b.inner.answer_write_failures.load(Ordering::SeqCst), 0);
    std::thread::sleep(Duration::from_millis(500));
    // Its reply let go after the first failure, for LIMIT, which takes less room.
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter limit [no room on this ship for the answer]  from ~zod/counter counter")]);
    drop(t);

    let slow = NetConfig { retry_delay: Duration::from_secs(5), max_retry_delay: Duration::from_secs(60), ..NetConfig::default() };
    let t = two_with("write-fails-drop", (fast(), NetConfig::default()), (fast(), slow.clone()), counter_with(true, false), &["~nec"]);
    let failing = u64::MAX / 2;
    t.b.inner.answer_write_failures.store(failing, Ordering::SeqCst);
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 hits");
    eventually("a write to have failed", Duration::from_secs(10), || t.b.inner.answer_write_failures.load(Ordering::SeqCst) < failing);
    let putting = || t.b_net.as_ref().unwrap().shared.carrier.putting_count();
    assert_eq!(putting(), 1);
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {n}")), "true");
    eventually("its task to stop", Duration::from_secs(1), || putting() == 0);
    t.b.inner.answer_write_failures.store(0, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(500));
    assert!(answers_to(&t.b, "~nec", &n).is_empty());
    drop(t);

    let mut t = two_with("write-fails-restart", (fast(), NetConfig::default()), (fast(), slow), counter_with(true, false), &["~nec"]);
    t.b.inner.answer_write_failures.store(failing, Ordering::SeqCst);
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 3000 hits");
    eventually("a write to have failed", Duration::from_secs(10), || t.b.inner.answer_write_failures.load(Ordering::SeqCst) < failing);
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, fast(), &scratch);
    assert_eq!(rows(&t.b, "~nec")["asks"], 1, "still waiting after the restart");
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    eventually("the answer", Duration::from_secs(15), || !answers_to(&t.b, "~nec", &n).is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(answers_to(&t.b, "~nec", &n).len(), 1);
}

/// A ship's own export comes in under its own settings after its limit on replies was lowered
/// (the reviewer's four steps): a command sent allowing 1,024 bytes, the ship reopened allowing
/// 512, exported and imported under 512, with the receipt still awaited; and again with the
/// receipt and its 1,024-byte reply already queued, which is then handed over whole.
#[test]
fn a_ship_exported_after_its_limit_on_replies_was_lowered_imports_under_it() {
    let code = "test-test-test-test-test-test-test-test";
    let lowered = Config { max_receipt_reply_bytes: 512, max_queued_per_deliver: 0, ..fast() };
    for queued in [false, true] {
        let label = if queued { "lowered-queued" } else { "lowered-awaited" };
        let b_cfg = Config { max_receipt_reply_bytes: 1024, max_queued_per_deliver: 0, ..fast() };
        let mut t = two_with(label, (fast(), NetConfig::default()), (b_cfg, NetConfig::default()), counter_with(false, true), &["~nec"]);
        if !queued {
            t.a_net.take().unwrap().vanish();
        }
        say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 1024");
        if queued {
            eventually("the receipt queued", Duration::from_secs(10), || t.b.pending("~nec").unwrap() == 1);
        }
        let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
        reopen(&mut t.b, &mut t.b_net, &dir, lowered.clone(), &scratch);
        t.b.set_recovery_key("~nec", crate::seal::recovery_public(code)).unwrap();
        let out = TempDir::new(&format!("{label}-copy"));
        t.b.export_ship("~nec", out.0.join("copy")).unwrap();
        let into = TempDir::new(&format!("{label}-into"));
        let other = Runtime::open(&into.0, lowered.clone()).unwrap();
        other.import_ship(out.0.join("copy"), "~nec", code).unwrap();
        if queued {
            assert_eq!(other.run_pending("~nec", 10).unwrap(), 1);
            assert_eq!(receipts(&other, "~nec"), ["1 ~zod/counter counter ran [] from ~zod/counter counter reply of 1024 bytes"]);
        } else {
            assert_eq!(rows(&other, "~nec")["peer_wait"], 1);
        }
    }
}

/// The records of commands with replies come in from an export under the same settings: a
/// command to a ship that is away, kept with its bound of 1,024 bytes, and a receipt with a
/// reply of 1,024 bytes this ship owes and has not yet sent. Exports changed to break the rules
/// are refused: a kept bound over the most any configuration allows, a receipt owed marked as
/// carrying a reply with a verdict other than RAN, and one whose reply is over that most.
#[test]
fn records_of_commands_with_replies_import_and_broken_ones_are_refused() {
    let code = "test-test-test-test-test-test-test-test";
    let a_cfg = Config { max_receipt_reply_bytes: 1024, max_queued_per_deliver: 0, ..fast() };
    let mut t = two_with("reply-records", (a_cfg.clone(), NetConfig::default()), (fast(), NetConfig::default()), counter_with(false, true), &["~nec"]);
    // ~bus is somewhere nothing answers.
    t.directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    let tally = t.a.add_module(&wasm("tally")).unwrap();
    let to_bus = Use { ship: "bus".into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true, ask: false };
    t.a.install("~zod", "tally", &tally, &Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true, asked: false }], uses: vec![to_bus] }).unwrap();
    say(&t.a, "~zod", "tally", "tell-reply bus inc-big hits 1024");
    // ~nec's command for a reply waits on ~zod; ~nec goes away; ~zod runs it, and owes the
    // receipt with its reply.
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 1024");
    eventually("the command queued on ~zod", Duration::from_secs(10), || t.a.pending("~zod").unwrap() == 1);
    t.b_net.take().unwrap().vanish();
    assert_eq!(t.a.run_pending("~zod", 10).unwrap(), 1);
    t.a.set_recovery_key("~zod", crate::seal::recovery_public(code)).unwrap();
    let out = TempDir::new("reply-records-copy");
    t.a.export_ship("~zod", out.0.join("copy")).unwrap();
    let into = TempDir::new("reply-records-into");
    let other = Runtime::open(&into.0, a_cfg.clone()).unwrap();
    other.import_ship(out.0.join("copy"), "~zod", code).unwrap();
    let kept = rows(&other, "~zod");
    assert_eq!((kept["peer_wait"], kept["peer_out"]), (1, 2), "the command to ~bus, and it and the receipt owed to ~nec");

    let refused = |label: &str, change: &dyn Fn(&rusqlite::Connection)| {
        let copy = out.0.join(label);
        copy_export(&out.0.join("copy"), &copy);
        rework(&copy, "~zod", code, change);
        let into = TempDir::new(&format!("reply-records-{label}"));
        let rt = Runtime::open(&into.0, a_cfg.clone()).unwrap();
        let imported = rt.import_ship(&copy, "~zod", code);
        assert!(matches!(&imported, Err(Error::BadShipFile(_))), "{label}: {imported:?}");
    };
    let most = crate::store::MOST_RECEIPT_REPLY_BYTES as i64;
    // Both records of the command say the same of it, so that only the bound is wrong.
    refused("bound-over", &|file| file.execute_batch(&format!("UPDATE peer_wait SET reply = {0}; UPDATE peer_out SET reply = {0} WHERE receipt = 0", most + 1)).unwrap());
    let owed = |file: &rusqlite::Connection| -> ship_proto::Receipt {
        let bytes: Vec<u8> = file.query_row("SELECT payload FROM peer_out WHERE receipt != 0", [], |r| r.get(0)).unwrap();
        <ship_proto::Receipt as ship_proto::Message>::decode(&*bytes).unwrap()
    };
    let put = |file: &rusqlite::Connection, receipt: ship_proto::Receipt| {
        file.execute("UPDATE peer_out SET payload = ?1 WHERE receipt != 0", [ship_proto::Message::encode_to_vec(&receipt)]).unwrap();
    };
    refused("marked-not-ran", &|file| {
        let receipt = owed(file);
        put(file, ship_proto::Receipt { verdict: ship_proto::Verdict::Failed as i32, ..receipt });
    });
    refused("reply-over", &|file| {
        let receipt = owed(file);
        put(file, ship_proto::Receipt { reply: vec![b'r'; crate::store::MOST_RECEIPT_REPLY_BYTES + 1], ..receipt });
    });
}

/// Settings at their largest are held to what a ship's file, an export and the wire carry, and
/// import's bounds do not overflow: with `max_answer_bytes` and `max_ask_bytes` at
/// `usize::MAX` (and the largest reply), a ship with nothing new in it, and one with a queued
/// answer and receipt, each export and import under those same settings.
#[test]
fn settings_at_their_largest_are_held_and_ships_import_under_them() {
    let code = "test-test-test-test-test-test-test-test";
    let largest = Config { max_answer_bytes: usize::MAX, max_ask_bytes: usize::MAX, max_receipt_reply_bytes: usize::MAX, max_queued_per_deliver: 0, ..fast() };
    let t = two_with("largest", (fast(), NetConfig::default()), (largest.clone(), NetConfig::default()), counter_with(true, true), &["~nec", "~bus"]);
    let held = &t.b.inner.cfg;
    assert_eq!((held.max_answer_bytes, held.max_ask_bytes, held.max_receipt_reply_bytes), (crate::store::MOST_ANSWER_BYTES, crate::store::MOST_ASK_BYTES, crate::store::MOST_RECEIPT_REPLY_BYTES));
    say(&t.b, "~nec", "tally", "ask-on zod counter counter 5000 hits");
    say(&t.b, "~nec", "tally", "tell-reply zod inc-big hits 100");
    eventually("the answer and the receipt queued", Duration::from_secs(10), || t.b.pending("~nec").unwrap() == 2);
    for ship in ["~bus", "~nec"] {
        t.b.set_recovery_key(ship, crate::seal::recovery_public(code)).unwrap();
        let out = TempDir::new(&format!("largest-{}", ship.trim_start_matches('~')));
        t.b.export_ship(ship, out.0.join("copy")).unwrap();
        let into = TempDir::new(&format!("largest-into-{}", ship.trim_start_matches('~')));
        let other = Runtime::open(&into.0, largest.clone()).unwrap();
        other.import_ship(out.0.join("copy"), ship, code).unwrap();
    }
}

/// A drop that commits between the network's look through a ship's questions (which has
/// registered the question's means to stop) and its starting their tasks (the network held there
/// by a gate), while the dropping event is held just after it commits (by a gate): the task,
/// once started, ends while the ship is still held, by the runtime's records less than one
/// second after the drop committed, and no question was written to a stream.
#[test]
fn a_drop_between_the_networks_look_and_its_tasks_stops_the_question() {
    let t = two("drop-gap", counter_with(true, false));
    let shared = t.b_net.as_ref().unwrap().shared.clone();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let (looked, let_look_go) = t.b.inner.gates.arm_async("questions registered");
    let n: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits").parse().unwrap();
    // The network has looked, seen the question and registered its means to stop; it has not
    // started its task.
    looked.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(shared.carrier.putting_has("nec", n));
    let (committed, let_event_go) = t.b.inner.gates.arm("event committed");
    let b = t.b.clone();
    let dropping = std::thread::spawn(move || say(&b, "~nec", "tally", &format!("drop-ask {n}")));
    committed.recv_timeout(Duration::from_secs(10)).expect("the drop to commit");
    let _ = let_look_go.send(());
    let of = format!("nec/{n}");
    eventually("the dropped question's task to end, its ship still held", Duration::from_secs(3), || !t.b.inner.notes_of("question task ended", &of, from).is_empty());
    assert!(!dropping.is_finished(), "the ship was let go first");
    let dropped_at = t.b.inner.notes_of("drop committed", "nec", from)[0].0;
    let ended_at = t.b.inner.notes_of("question task ended", &of, from)[0].0;
    assert!(ended_at >= dropped_at && ended_at - dropped_at < Duration::from_secs(1), "its task ended {:?} after the drop", ended_at.saturating_duration_since(dropped_at));
    drop(let_event_go);
    assert_eq!(dropping.join().unwrap(), "true");
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst), writes, "the dropped question was written to a stream");
    assert!(!shared.carrier.putting_has("nec", n));
}

/// One look per notice: a drop that commits while the network is between a look at a ship's
/// questions and starting their tasks makes no second look. A question R waits; the network is
/// held after its look at a new question Q (gate), R is dropped in the gap, then the network is
/// let go: Q was registered at the gate, and when the ship's looking has ended there was exactly
/// one look at that ship (by the runtime's notes) since Q was asked; and once R's own task has
/// ended (by its note), R is no longer registered and Q still is.
#[test]
fn a_drop_after_a_look_makes_no_second_look() {
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 1500, ..fast() };
    let t = two_with("one-look", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    // One slow question rests ~zod from ~nec's questions, so those asked here wait.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let shared = t.b_net.as_ref().unwrap().shared.clone();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let r: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits").parse().unwrap();
    eventually("R's task", Duration::from_secs(5), || shared.carrier.putting_has("nec", r) && !shared.carrier.looking_at("nec"));
    let from = t.b.inner.notes_len();
    let (looked, let_go) = t.b.inner.gates.arm_async("questions registered");
    let q: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits").parse().unwrap();
    looked.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(shared.carrier.putting_has("nec", q), "Q not registered at the gate");
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {r}")), "true");
    let _ = let_go.send(());
    eventually("the ship's looking to end", Duration::from_secs(5), || !shared.carrier.looking_at("nec"));
    assert_eq!(t.b.inner.notes_of("looked at questions", "nec", from).len(), 1, "looks at ~nec since Q was asked");
    eventually("R's task to end", Duration::from_secs(5), || !t.b.inner.notes_of("question task ended", &format!("nec/{r}"), from).is_empty());
    assert!(shared.carrier.putting_has("nec", q) && !shared.carrier.putting_has("nec", r));
}

/// A load check: a steady stream of drops does not keep the network from other work. While one
/// question waits unchanged, another agent asks and drops questions as fast as it can for two
/// seconds (only drops that returned true are counted). Once it says it has begun, a question Q
/// is asked and a command sent from another ship of the runtime; by the runtime's records, Q's
/// task is registered less than a second after Q's asking event committed, and the command runs
/// on the other ship less than a second after its sending event committed, and has its effect
/// (the counter counts one). It does not show that a drop committed inside either interval.
#[test]
fn a_stream_of_drops_keeps_no_question_from_its_task() {
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 1500, ..fast() };
    let t = two_with("drop-churn", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, true), &["~nec", "~wes"]);
    // One slow question rests ~zod from ~nec's questions for 9 x 1.5 s.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let tally = t.b.add_module(&wasm("tally")).unwrap();
    t.b.install("~nec", "churn", &tally, &asking_tally("zod")).unwrap();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let (begun, has_begun) = std::sync::mpsc::channel();
    let churn = {
        let b = t.b.clone();
        std::thread::spawn(move || {
            let (began, mut drops) = (Instant::now(), 0usize);
            while began.elapsed() < Duration::from_secs(2) {
                let n = say(&b, "~nec", "churn", "ask-on zod counter counter 20000 hits");
                if say(&b, "~nec", "churn", &format!("drop-ask {n}")) == "true" {
                    drops += 1;
                    if drops == 1 {
                        let _ = begun.send(());
                    }
                }
            }
            drops
        })
    };
    has_begun.recv_timeout(Duration::from_secs(5)).expect("the drops to begin");
    let (from_b, from_a) = (t.b.inner.notes_len(), t.a.inner.notes_len());
    let n: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits").parse().unwrap();
    say(&t.b, "~wes", "tally", "tell zod inc hits");
    let shared = t.b_net.as_ref().unwrap().shared.clone();
    eventually("Q's task", Duration::from_secs(3), || shared.carrier.putting_has("nec", n));
    eventually("~wes's command run", Duration::from_secs(3), || !t.a.inner.notes_of("command run", "zod", from_a).is_empty());
    let drops = churn.join().unwrap();
    assert!(drops > 20, "only {drops} drops");
    let asked = t.b.inner.notes_of("asking event committed", "nec/tally", from_b)[0].0;
    let registered = t.b.inner.notes_of("question registered", &format!("nec/{n}"), from_b)[0].0;
    assert!(registered >= asked && registered - asked < Duration::from_secs(1), "Q's task registered {:?} after it was asked", registered.saturating_duration_since(asked));
    let sent = t.b.inner.notes_of("sending event committed", "wes/tally", from_b)[0].0;
    let ran = t.a.inner.notes_of("command run", "zod", from_a)[0].0;
    assert!(ran >= sent && ran - sent < Duration::from_secs(1), "the command ran {:?} after it was sent", ran.saturating_duration_since(sent));
    assert_eq!(say(&t.a, "~zod", "counter", "get hits"), "1");
}

/// A question to a ship resting from its asker's questions is refused without the ship being
/// taken: with the ship held by a long event, it is told "too busy" at once, not left waiting
/// for the ship until its asker gives up.
#[test]
fn a_question_refused_for_a_rest_does_not_wait_for_the_ship() {
    let a_cfg = Config { fuel_per_event: 1 << 50, max_event_millis: 3000, ask_fuel: 1 << 50, ask_millis: 1000, ..fast() };
    let t = two_with("rest-first", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    // One slow question rests ~zod from ~nec's questions for 9 x 1 s.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    let holding = hold_with_event(&t.a, "~zod", "counter", b"spin x");
    let began = Instant::now();
    let asked = t.b_net.as_ref().unwrap().ask_raw("~nec", "~zod", question("", "counter", b"hits", 5000), Duration::from_secs(2));
    assert!(matches!(&asked, Err(NetError::Refused(why)) if why == TOO_BUSY), "{asked:?}");
    assert!(began.elapsed() < Duration::from_millis(500) && !holding.is_finished(), "{:?}", began.elapsed());
    assert!(matches!(holding.join().unwrap(), Err(Error::Rejected(Rejection::Timeout))));
}

/// A ship that cannot be looked at when the network starts is looked at again until it can be:
/// a question waiting on ~nec from before its runtime stopped, ~nec's inspection at start made
/// to fail once, is answered (asked again, its time not run out), with nothing else done on
/// ~nec meanwhile.
#[test]
fn a_ship_that_cannot_be_looked_at_when_the_network_starts_is_looked_at_again() {
    let mut t = two("start-fault", counter_with(true, false));
    t.a_net.take().unwrap().vanish();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 30000 hits");
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, fast(), &scratch);
    t.b.inner.recording.store(true, Ordering::SeqCst);
    lock(&t.b.inner.inspection_faults).insert("nec".to_string(), 1);
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    let a_net = Network::start(t.a.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    eventually("the answer handed over", Duration::from_secs(20), || !t.b.inner.notes_of("answer handled", &format!("nec/{n}"), 0).is_empty());
    assert_eq!(lock(&t.b.inner.inspection_faults).get("nec").copied(), Some(0), "the inspection did not fail");
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter reply [] 0 from ~zod/counter counter")]);
}

/// A listing of the ships' directory that cannot read one of its entries keeps the names it did
/// read: an entry the listing reports as an error every time (a test's fault) leaves the
/// directory to be listed again and again, and meanwhile a question waiting on ~nec from before
/// its runtime stopped is answered (asked again, its time not run out); ~nec, looked at once, is
/// not looked at again however often the directory is listed.
#[test]
fn a_listing_that_cannot_read_one_entry_keeps_the_ships_it_did_read() {
    let mut t = two("list-fault", counter_with(true, false));
    t.a_net.take().unwrap().vanish();
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 30000 hits");
    let (dir, scratch) = (t.dirs.1 .0.clone(), t.dirs.0 .0.join("scratch"));
    reopen(&mut t.b, &mut t.b_net, &dir, fast(), &scratch);
    t.b.inner.recording.store(true, Ordering::SeqCst);
    fs::write(dir.join("ships").join("unreadable-entry"), b"").unwrap();
    lock(&t.b.inner.listing_faults).insert("unreadable-entry".to_string());
    let b_net = Network::start(t.b.clone(), t.directory.clone(), NetConfig { retry_delay: Duration::from_millis(50), ..NetConfig::default() }).unwrap();
    t.directory.set("~nec", t.b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    t.b_net = Some(b_net);
    let a_net = Network::start(t.a.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~zod", t.a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    t.a_net = Some(a_net);
    eventually("the answer handed over", Duration::from_secs(20), || !t.b.inner.notes_of("answer handled", &format!("nec/{n}"), 0).is_empty());
    assert_eq!(answers_to(&t.b, "~nec", &n), [format!("{n} ~zod/counter counter reply [] 0 from ~zod/counter counter")]);
    eventually("the directory listed three times", Duration::from_secs(20), || t.b.inner.notes_of("ships listed", "", 0).len() >= 3);
    assert_eq!(t.b.inner.notes_of("ship inspected", "nec", 0).len(), 1, "~nec looked at again");
}

/// One ship kept busy holds up no other ship's questions or commands: ~nec's event is held just
/// after it commits a question of its own, and the look at ~nec's questions says, on its own
/// thread, that it is about to wait for ~nec (~nec has no commands waiting, which would hold up
/// finding other ships' commands: Known limits). Only then does ~wes, on the same runtime, ask a
/// question and send a command; while ~nec is still held, by the runtimes' records, ~wes's
/// question arrives at ~zod, its command runs on ~zod, and its answer is handed to ~wes's agent.
#[test]
fn one_busy_ship_holds_up_no_other_ships_questions() {
    let t = two_with("busy-ship", (fast(), NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, true), &["~nec", "~wes"]);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from_b = t.b.inner.notes_len();
    let (committed, release) = t.b.inner.gates.arm("event committed");
    let b = t.b.clone();
    let holding = std::thread::spawn(move || say(&b, "~nec", "tally", "ask-on zod counter counter 20000 hits"));
    committed.recv_timeout(Duration::from_secs(10)).expect("~nec's question to commit");
    eventually("the look at ~nec waiting for ~nec", Duration::from_secs(5), || !t.b.inner.notes_of("look waiting for its ship", "nec", from_b).is_empty());
    let from_a = t.a.inner.notes_len();
    let m = say(&t.b, "~wes", "tally", "ask-on zod counter counter 20000 hits");
    say(&t.b, "~wes", "tally", "tell zod inc hits");
    eventually("~wes's question at ~zod", Duration::from_secs(5), || !t.a.inner.notes_of("question arrived", "wes", from_a).is_empty());
    eventually("~wes's command run on ~zod", Duration::from_secs(5), || !t.a.inner.notes_of("command run", "zod", from_a).is_empty());
    eventually("~wes's answer", Duration::from_secs(5), || !answers_to(&t.b, "~wes", &m).is_empty());
    assert!(!holding.is_finished(), "~nec was let go first");
    drop(release);
    holding.join().unwrap();
}

/// A question's notice does not wait for the carrier's look at another ship's commands: ~nec
/// has a command waiting (its event sent one) and is held just after that event commits; the
/// carrier says, on the thread where it is about to wait for ~nec, that it is finding where
/// ~nec's commands go. Only then does ~wes, on the same runtime, ask a question; it arrives at
/// ~zod (by ~zod's record) while ~nec is still held.
#[test]
fn a_question_does_not_wait_for_another_ships_commands_to_be_found() {
    let t = two_with("command-first", (fast(), NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, true), &["~nec", "~wes"]);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from_b = t.b.inner.notes_len();
    let (committed, release) = t.b.inner.gates.arm("event committed");
    let b = t.b.clone();
    let holding = std::thread::spawn(move || say(&b, "~nec", "tally", "tell zod inc hits"));
    committed.recv_timeout(Duration::from_secs(10)).expect("~nec's command to commit");
    eventually("the carrier waiting for ~nec", Duration::from_secs(5), || !t.b.inner.notes_of("finding where commands go", "nec", from_b).is_empty());
    let from_a = t.a.inner.notes_len();
    say(&t.b, "~wes", "tally", "ask-on zod counter counter 20000 hits");
    eventually("~wes's question at ~zod", Duration::from_secs(5), || !t.a.inner.notes_of("question arrived", "wes", from_a).is_empty());
    assert!(!holding.is_finished(), "~nec was let go first");
    drop(release);
    holding.join().unwrap();
}

/// A question's task stopped when the network stops lets go of everything: its answer came
/// (held at the runtime's gate until its ship is held by an event kept at a gate), so its
/// worker waits for the ship to write it; the network is dropped; by the runtime's records the
/// worker gives up less than a second after the network began stopping, the ship still held;
/// once the event is let go nothing holds the runtime but the test, and the worker wrote
/// nothing (the question is answered once, as unreachable, by the next run of the ship's queue
/// with no network).
#[test]
fn a_settlement_waiting_for_its_ship_ends_when_the_network_stops() {
    let mut t = two("settle-stop", counter_with(true, false));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let (read, let_reply_go) = t.b.inner.gates.arm_async("question reply read");
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits");
    read.recv_timeout(Duration::from_secs(10)).expect("the answer to come");
    let (holding, release) = hold_ship(&t.b, "~nec");
    let from = t.b.inner.notes_len();
    let _ = let_reply_go.send(());
    let of = format!("nec/{n}");
    eventually("the worker waiting for the ship", Duration::from_secs(5), || !t.b.inner.notes_of("settlement waiting for its ship", &of, from).is_empty());
    drop(t.b_net.take());
    eventually("the worker to give up", Duration::from_secs(3), || !t.b.inner.notes_of("settlement given up", &of, from).is_empty());
    let stopping = t.b.inner.notes_of("network stopping", "", from)[0].0;
    let gave_up = t.b.inner.notes_of("settlement given up", &of, from)[0].0;
    assert!(gave_up >= stopping && gave_up - stopping < Duration::from_secs(1), "gave up {:?} after", gave_up.saturating_duration_since(stopping));
    assert!(!holding.is_finished(), "the ship was let go first");
    drop(release);
    assert!(holding.join().unwrap().is_ok());
    eventually("nothing else to hold the runtime", Duration::from_secs(5), || Arc::strong_count(&t.b) == 1);
    // The stopped worker wrote nothing: with no network, the next run of the ship's queue (the
    // held event's own) answered the question as unreachable, once.
    let handed = answers_to(&t.b, "~nec", &n);
    assert!(handed.len() == 1 && handed[0].contains(" unreachable ["), "{handed:?}");
}

/// A look at a ship's questions still waiting for that ship when the network stops keeps no
/// socket bound: with ~nec held just after committing a question, and the look at ~nec's
/// questions saying, on its own thread, that it is about to wait for ~nec, the network is
/// dropped and a new one started on the same address while ~nec is still held. (Dropping a
/// network lets its threads wind down without waiting for them, so the old socket is let go of
/// a moment after the drop returns, as in `tests/lookup.rs`: the start is tried again while the
/// address is in use, for up to five seconds, with ~nec held all the while. A look that held
/// the network would keep the socket until ~nec is let go.)
#[test]
fn a_look_waiting_for_its_ship_keeps_no_socket_bound() {
    let mut t = two("rebind", counter_with(true, false));
    let addr = t.b_net.as_ref().unwrap().addr();
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let (committed, release) = t.b.inner.gates.arm("event committed");
    let b = t.b.clone();
    let holding = std::thread::spawn(move || say(&b, "~nec", "tally", "ask-on zod counter counter 20000 hits"));
    committed.recv_timeout(Duration::from_secs(10)).expect("the question to commit");
    eventually("the look at ~nec waiting for ~nec, on its own thread", Duration::from_secs(5), || !t.b.inner.notes_of("look waiting for its ship", "nec", from).is_empty());
    drop(t.b_net.take());
    let dropped = Instant::now();
    let again = loop {
        match Network::start(t.b.clone(), t.directory.clone(), NetConfig { addr: addr.to_string(), ..NetConfig::default() }) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && dropped.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(20)),
            other => break other,
        }
    };
    assert!(again.is_ok(), "{:?}", again.err());
    assert!(!holding.is_finished(), "~nec was let go first");
    drop(release);
    holding.join().unwrap();
    t.b_net = again.ok();
}

/// A question held where its stream is about to be opened (the runtime's gate there, a wait the
/// task can be dropped in) is dropped meanwhile; once let go, it writes nothing to a stream. (That
/// the stop is looked at before the work on every poll, when both are ready at once, is shown by
/// `a_stop_already_signalled_wins_over_work_that_is_ready`.)
#[test]
fn a_question_dropped_before_its_stream_opens_is_not_written() {
    let t = two("drop-open", counter_with(true, false));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    let (opening, let_go) = t.b.inner.gates.arm_async("question stream to open");
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits");
    opening.recv_timeout(Duration::from_secs(10)).expect("the question to reach its stream");
    let from = t.b.inner.notes_len();
    assert_eq!(say(&t.b, "~nec", "tally", &format!("drop-ask {n}")), "true");
    let _ = let_go.send(());
    eventually("its task to end", Duration::from_secs(5), || !t.b.inner.notes_of("question task ended", &format!("nec/{n}"), from).is_empty());
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst), writes, "the dropped question was written");
}

/// `unless_stopped` looks at the stop before the work, on every poll: with the stop already
/// signalled and the work ready, one poll ends it with nothing, the work never polled.
#[test]
fn a_stop_already_signalled_wins_over_work_that_is_ready() {
    let polled = Arc::new(AtomicUsize::new(0));
    let counted = polled.clone();
    let work = std::future::poll_fn(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(7)
    });
    let cancel = super::Cancel::default();
    cancel.stop();
    let tokio = tokio::runtime::Builder::new_current_thread().build().unwrap();
    assert_eq!(tokio.block_on(super::unless_stopped(Some(&cancel), work)), None);
    assert_eq!(polled.load(Ordering::SeqCst), 0, "the work was polled");
}

/// A wake made for a question's task runs none of the upkeep owed at a ship's first wake: ~nec,
/// asleep and owed its look through its files (a leftover planted), is woken by its question's
/// task reading the question; held just after it lets the ship go (gate), a drop commits and
/// its event is kept (gate); let go, the task's read returns, by the runtime's records, less
/// than a second after the drop committed, the ship still held; and the leftover is removed by
/// the next ordinary call (the dropping event's).
#[test]
fn a_question_tasks_wake_leaves_the_ships_upkeep_owed() {
    let t = two("owed-sweep", counter_with(true, false));
    // The network's own look at every ship when it started is done (it is an ordinary call).
    let shared = t.b_net.as_ref().unwrap().shared.clone();
    eventually("the start-up look", Duration::from_secs(10), || shared.started_up.load(Ordering::SeqCst));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let (registered, let_task_start) = t.b.inner.gates.arm_async("questions registered");
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 20000 hits");
    registered.recv_timeout(Duration::from_secs(10)).expect("the question registered");
    assert_eq!(t.b.sleep_idle(Duration::ZERO), 1);
    lock(&t.b.inner.swept).remove("nec");
    let leftover = t.dirs.1 .0.join("files").join("nec").join("0123456789abcdef0123456789abcdef");
    fs::create_dir_all(&leftover).unwrap();
    let (let_ship_go, release_task) = t.b.inner.gates.arm("task let its ship go");
    let from = t.b.inner.notes_len();
    let _ = let_task_start.send(());
    let_ship_go.recv_timeout(Duration::from_secs(10)).expect("the task's read to wake the ship");
    assert!(leftover.exists(), "the task's wake ran the upkeep");
    let (committed, release_event) = t.b.inner.gates.arm("event committed");
    let (b, of, dropped_n) = (t.b.clone(), format!("nec/{n}"), n.clone());
    let dropping = std::thread::spawn(move || say(&b, "~nec", "tally", &format!("drop-ask {dropped_n}")));
    committed.recv_timeout(Duration::from_secs(10)).expect("the drop to commit");
    drop(release_task);
    eventually("the task's read to return, the ship still held", Duration::from_secs(3), || !t.b.inner.notes_of("question read returned", &of, from).is_empty());
    let dropped = t.b.inner.notes_of("drop committed", "nec", from)[0].0;
    let returned = t.b.inner.notes_of("question read returned", &of, from)[0].0;
    assert!(returned >= dropped && returned - dropped < Duration::from_secs(1), "returned {:?} after the drop", returned.saturating_duration_since(dropped));
    assert!(!dropping.is_finished(), "the ship was let go first");
    drop(release_event);
    assert_eq!(dropping.join().unwrap(), "true");
    assert!(!leftover.exists(), "the next ordinary call did not do the upkeep owed");
}

/// The bytes of a cleanly closed ship's file are the same before and after a question, even the
/// first call ever made on a ship just put in place (in SQLite's older journal mode, the one a
/// ship's file is put in place with): a ship created after the network started, first called by
/// a question to an agent it does not have; and a ship brought in from a copy (never opened
/// since: its file's mode checked, by a connection that only reads, to be the older one before
/// the question), first called by a question that is answered, the file still in the older mode
/// after. And once ordinary work has switched that file to WAL and the ship has been put to
/// sleep, a question to it, answered, the first call since. Each baseline is taken first; each
/// comparison is made once the ship has been put to sleep again (its file closed, so nothing is
/// left in a `-wal` beside it). What it cannot show: a write that is put back before the file is
/// closed, or anything about a file that needs SQLite's crash repair (none here).
#[test]
fn a_cleanly_closed_ships_file_is_the_same_byte_for_byte_after_a_question() {
    let t = two("first-question", counter_with(true, false));
    let shared = t.a_net.as_ref().unwrap().shared.clone();
    eventually("the start-up look", Duration::from_secs(10), || shared.started_up.load(Ordering::SeqCst));
    let kernel = t.a.add_module(&wasm("kernel")).unwrap();
    t.a.create_ship("~bus", &kernel).unwrap();
    t.directory.set("~bus", t.a.public_key("~bus").unwrap(), t.a_net.as_ref().unwrap().addr()).unwrap();
    let file = t.dirs.0 .0.join("ships").join("bus.ship");
    let before = fs::read(&file).unwrap();
    let asked = t.b.ask("~nec", None, "~bus", "counter", "counter", b"hits", Duration::from_secs(10));
    assert!(matches!(asked, Err(AskError::Denied(_))), "{asked:?}");
    // Compared with every ship put to sleep, so that nothing SQLite still holds beside the file
    // (in a `-wal`) is left out of it: closing the last connection moves that into the file.
    assert!(t.a.sleep_idle(Duration::ZERO) >= 1, "no ship was put to sleep");
    assert!(fs::read(&file).unwrap() == before, "a question changed a fresh ship's file");

    // A copy of ~zod, with its counter, brought into a runtime of its own and first called by
    // a question that is answered.
    let code = "test-test-test-test-test-test-test-test";
    t.a.set_recovery_key("~zod", crate::seal::recovery_public(code)).unwrap();
    let out = TempDir::new("first-question-copy");
    t.a.export_ship("~zod", out.0.join("copy")).unwrap();
    let into = TempDir::new("first-question-into");
    let c = Arc::new(Runtime::open(&into.0, fast()).unwrap());
    c.import_ship(out.0.join("copy"), "~zod", code).unwrap();
    let file = into.0.join("ships").join("zod.ship");
    let before = fs::read(&file).unwrap();
    // Whether the file is still in the older mode, by a connection that can only read.
    let older = || {
        let conn = crate::store::open_read_only(&c.inner.ship_path("zod"), &c.inner.file_key("zod")).unwrap();
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        !mode.eq_ignore_ascii_case("wal")
    };
    assert!(older(), "the copy was not put in place in the older mode");
    assert!(fs::read(&file).unwrap() == before, "looking at the mode changed the file");
    // Started with its look at every ship skipped (an ordinary call): ~zod is made to fail
    // inspection, so that the question is the first call.
    lock(&c.inner.inspection_faults).insert("zod".to_string(), u32::MAX);
    let c_net = Network::start(c.clone(), t.directory.clone(), NetConfig::default()).unwrap();
    t.directory.set("~zod", c.public_key("~zod").unwrap(), c_net.addr()).unwrap();
    let asked = t.b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(10));
    assert_eq!(asked.unwrap(), b"0");
    assert_eq!(c.sleep_idle(Duration::ZERO), 1, "the ship was not put to sleep");
    assert!(fs::read(&file).unwrap() == before, "a question changed the file of a ship brought in");
    assert!(older(), "a question switched the file's mode");

    // Ordinary work switches it to WAL; put to sleep (its file closed), then asked again.
    c.inner.with_ship("~zod", |_| Ok(())).unwrap();
    assert!(!older(), "ordinary work did not switch the file to WAL");
    assert_eq!(c.sleep_idle(Duration::ZERO), 1, "the ship was not put to sleep");
    let before = fs::read(&file).unwrap();
    let asked = t.b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(10));
    assert_eq!(asked.unwrap(), b"0");
    assert_eq!(c.sleep_idle(Duration::ZERO), 1, "the ship was not put to sleep");
    assert!(fs::read(&file).unwrap() == before, "a question changed the file of a ship in WAL mode");
    drop(c_net);
}

/// The ship asked counts a question's time from the one moment it took the request up: held
/// (gate) for 100 ms between taking the request up and setting the deadline, the one deadline it
/// recorded is the one moment it recorded taking the request up, plus the shorter of its own
/// limit and the allowance the asker recorded (within 1 ms). That note is the first, provisional
/// allowance, which the first write could lower; with 2 s given against 5 s left, it does not.
#[test]
fn the_answering_ship_counts_a_questions_time_from_one_moment() {
    let t = two("one-moment", counter_with(true, false));
    t.a.inner.recording.store(true, Ordering::SeqCst);
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let (from_a, from_b) = (t.a.inner.notes_len(), t.b.inner.notes_len());
    let (arrived, let_go) = t.a.inner.gates.arm_async("question deadline to set");
    let net = t.b_net.as_ref().unwrap().shared.clone();
    let threads = t.b_net.as_ref().unwrap().threads.get().handle().clone();
    let asking = std::thread::spawn(move || threads.block_on(net.ask_within("~nec", "~zod", question("", "counter", b"hits", 2000), Duration::from_secs(5))).map(|(reply, _)| reply));
    arrived.recv_timeout(Duration::from_secs(10)).expect("the question to arrive");
    std::thread::sleep(Duration::from_millis(100));
    let _ = let_go.send(());
    assert!(asking.join().unwrap().is_ok());
    let took_up = t.a.inner.notes_of("question arrived", "nec", from_a);
    let deadline = t.a.inner.notes_of("question deadline", "nec", from_a);
    let allowance = t.b.inner.notes_of("question allowance", "zod", from_b);
    assert!(took_up.len() == 1 && deadline.len() == 1 && allowance.len() == 1, "{took_up:?} {deadline:?} {allowance:?}");
    let within = Duration::from_millis(allowance[0].1.min(t.a.inner.cfg.ask_millis));
    let expected = took_up[0].0 + within;
    let off = if deadline[0].0 > expected { deadline[0].0 - expected } else { expected - deadline[0].0 };
    assert!(off <= Duration::from_millis(1), "the deadline is {off:?} off what was given (took up + {within:?})");
}

/// The asking side's deadline is taken as `Runtime::ask` is called, before the question is handed
/// to a task: the task held (gate) before it first runs until the deadline the runtime recorded
/// has passed sends nothing, and the caller is told `NoAnswer`.
#[test]
fn a_question_handed_to_a_task_late_sends_nothing_after_its_time() {
    let t = two("asker-late", counter_with(true, false));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    let (begun, let_go) = t.b.inner.gates.arm_async("asking task begun");
    let b = t.b.clone();
    let asking = std::thread::spawn(move || b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(1)));
    begun.recv_timeout(Duration::from_secs(5)).expect("the task to begin");
    let deadline = t.b.inner.notes_of("ask deadline", "~nec", from)[0].0;
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    let _ = let_go.send(());
    assert_eq!(asking.join().unwrap(), Err(AskError::NoAnswer));
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst), writes, "a question was sent after its time");
}

/// The deadline is taken as `Runtime::ask` is called, before anything else it does: held where
/// it is about to hand the question to the network (gate) until that deadline has passed, it
/// sends nothing, and the caller is told `NoAnswer`.
#[test]
fn a_question_held_before_the_network_has_it_sends_nothing_after_its_time() {
    let t = two("ask-entry", counter_with(true, false));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    let (at_hook, let_go) = t.b.inner.gates.arm("ask hook");
    let b = t.b.clone();
    let asking = std::thread::spawn(move || b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_millis(300)));
    at_hook.recv_timeout(Duration::from_secs(5)).expect("the call to reach the network");
    let deadline = t.b.inner.notes_of("ask deadline", "~nec", from)[0].0;
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    drop(let_go);
    assert_eq!(asking.join().unwrap(), Err(AskError::NoAnswer));
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst), writes, "a question was sent after its time");
}

/// An answer that comes after an agent's question's deadline is not accepted as a reply: the
/// answer is held (gate) once read until the steady-clock deadline the question's task recorded
/// has passed, and the agent is handed NO_ANSWER.
#[test]
fn an_answer_after_the_deadline_is_not_taken_as_a_reply() {
    let t = two("late-reply", counter_with(true, false));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let (read, let_go) = t.b.inner.gates.arm_async("question reply read");
    let n: u64 = say(&t.b, "~nec", "tally", "ask-on zod counter counter 1500 hits").parse().unwrap();
    read.recv_timeout(Duration::from_secs(10)).expect("the answer to be read");
    let deadline = t.b.inner.notes_of("question task deadline", &format!("nec/{n}"), from)[0].0;
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    let _ = let_go.send(());
    eventually("the answer handed over", Duration::from_secs(5), || !answers_to(&t.b, "~nec", &n.to_string()).is_empty());
    let handed = answers_to(&t.b, "~nec", &n.to_string());
    assert_eq!(handed.len(), 1, "{handed:?}");
    assert!(handed[0].contains(" no-answer ["), "{}", handed[0]);
}

/// A refusal that comes after the deadline is not taken either: `Runtime::ask` to a ship resting
/// from ~nec's questions is refused as too busy, and the refusal is held (gate) once read until
/// the deadline the runtime recorded has passed: `NoAnswer`, not `Busy`.
#[test]
fn a_refusal_after_the_deadline_is_no_answer() {
    let a_cfg = Config { ask_fuel: 1 << 50, ask_millis: 400, ..fast() };
    let t = two_with("late-refusal", (a_cfg, NetConfig::default()), (fast(), NetConfig::default()), counter_with(true, false), &["~nec"]);
    // One slow question rests ~zod from ~nec's questions for 9 x 0.4 s.
    assert_eq!(ask(&t, None, "counter", b"?spin", Duration::from_secs(10)), Err(AskError::Failed));
    t.b.inner.recording.store(true, Ordering::SeqCst);
    let from = t.b.inner.notes_len();
    let (read, let_go) = t.b.inner.gates.arm_async("question reply read");
    let b = t.b.clone();
    let asking = std::thread::spawn(move || b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(1)));
    read.recv_timeout(Duration::from_secs(10)).expect("the refusal to be read");
    let deadline = t.b.inner.notes_of("ask deadline", "~nec", from)[0].0;
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    let _ = let_go.send(());
    assert_eq!(asking.join().unwrap(), Err(AskError::NoAnswer));
}

/// A switch to WAL that SQLite does not make (it keeps the old mode, with no error, where it
/// cannot use WAL: here, a file held in memory) is not taken as made.
#[test]
fn a_switch_to_wal_that_does_not_take_is_not_taken_as_made() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    assert!(!crate::store::to_wal(&conn).unwrap(), "taken as switched");
}

/// The allowance worked out from a clock sample it is given (`wire_allowance`): what is left,
/// floored to whole milliseconds, never more than the asker gave; less than one whole millisecond
/// left, nothing to send. A flooring test on the sample only: it observes no writer and no moment
/// of acceptance (those are the `a_question_whose_first_write_...` tests).
#[test]
fn a_questions_time_on_the_wire_is_never_more_than_is_left() {
    assert_eq!(super::wire_allowance(1000, Duration::from_micros(999)), None);
    assert_eq!(super::wire_allowance(1000, Duration::ZERO), None);
    assert_eq!(super::wire_allowance(1000, Duration::from_millis(1)), Some(1));
    assert_eq!(super::wire_allowance(1000, Duration::from_micros(1999)), Some(1));
    assert_eq!(super::wire_allowance(300, Duration::from_secs(5)), Some(300));
    assert_eq!(super::wire_allowance(0, Duration::from_millis(1500)), Some(1500));
}

/// A question whose first try reached the other ship is never `Unreachable`, though later tries
/// cannot reach it: the first try's question is held at the ship asked (gate, as its deadline is
/// set) and that ship's network then stops, so the try's connection is lost and no later one
/// can be made; the caller is told `NoAnswer`. This is for a destination that stays listed: if it
/// is taken out of the directory meanwhile, a later try which observes the removal ends the
/// question as `Unreachable` (Known limits).
#[test]
fn a_question_that_reached_its_ship_once_is_not_unreachable() {
    let mut t = two("reached-once", counter_with(true, false));
    let (arrived, let_go) = t.a.inner.gates.arm_async("question deadline to set");
    let b = t.b.clone();
    let asking = std::thread::spawn(move || b.ask("~nec", None, "~zod", "counter", "counter", b"hits", Duration::from_secs(3)));
    arrived.recv_timeout(Duration::from_secs(10)).expect("the question to arrive");
    drop(t.a_net.take());
    assert_eq!(asking.join().unwrap(), Err(AskError::NoAnswer));
    drop(let_go);
}

/// Sizes past what one end reads as one message are told as such, and not tried again: an
/// answer larger than the asking runtime reads, and a question larger than the answering
/// runtime reads, are `Limit` to `Runtime::ask` and LIMIT to an agent; and so is a question so
/// much larger that it cannot all be written before the answering runtime stops reading it
/// (one try each). That last case may take either way (the refusal read while the question is
/// still being written, or after the write failed); it is not made to take either:
/// `a_refusal_that_comes_while_a_question_is_still_written_is_taken` holds the other end so
/// that nothing stops the write.
#[test]
fn messages_too_large_for_one_end_are_told_as_limits() {
    let small = Config { max_event_bytes: 32 << 10, max_checkpoint_bytes: 16 << 10, max_unanswered: 64, ..fast() };
    let small_net = NetConfig { max_message_bytes: 128 << 10, ..NetConfig::default() };
    // ~nec reads at most 128 KiB; ~zod answers 300,000 bytes.
    let a_cfg = Config { max_answer_bytes: 512 << 10, ..fast() };
    let t = two_with("too-large-answer", (a_cfg, NetConfig::default()), (small.clone(), small_net.clone()), counter_with(true, false), &["~nec"]);
    assert_eq!(ask(&t, None, "counter", b"?big 300000", Duration::from_secs(10)), Err(AskError::Limit));
    let n = say(&t.b, "~nec", "tally", "ask-on zod counter counter 10000 ?big 300000");
    eventually("the answer", Duration::from_secs(15), || !answers_to(&t.b, "~nec", &n).is_empty());
    assert!(answers_to(&t.b, "~nec", &n)[0].contains(" limit ["), "{:?}", answers_to(&t.b, "~nec", &n));
    drop(t);
    // ~zod reads at most 128 KiB; ~nec asks 200,000 bytes.
    let b_cfg = Config { max_ask_bytes: 512 << 10, ..fast() };
    let t = two_with("too-large-question", (small.clone(), small_net.clone()), (b_cfg, NetConfig::default()), counter_with(true, false), &["~nec"]);
    let payload = vec![b' '; 200_000];
    assert_eq!(ask(&t, None, "counter", &payload, Duration::from_secs(10)), Err(AskError::Limit));
    drop(t);
    // ~zod reads at most 128 KiB, and lets one stream send it no more than that before it reads;
    // ~nec asks 900,000 bytes, several times that, so the request cannot all be written before
    // ~zod has stopped reading it and refused it. One try each, through `Runtime::ask` and an
    // agent, and each told it is too large.
    let window = super::stream_room(&small_net);
    let payload = vec![b' '; 900_000];
    assert!(payload.len() as u64 > 4 * window, "{} bytes against a window of {window}", payload.len());
    let b_cfg = Config { max_ask_bytes: 1 << 20, ..fast() };
    let b_net = NetConfig { max_message_bytes: 2 << 20, ..NetConfig::default() };
    let t = two_with("too-large-to-write", (small, small_net), (b_cfg, b_net), counter_with(true, false), &["~nec"]);
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    assert_eq!(ask(&t, None, "counter", &payload, Duration::from_secs(10)), Err(AskError::Limit), "a question too large to finish writing");
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst) - writes, 1, "tries");
    let n = say(&t.b, "~nec", "tally", &format!("ask-on zod counter counter 10000 {}", "x".repeat(900_000)));
    eventually("the answer", Duration::from_secs(15), || !answers_to(&t.b, "~nec", &n).is_empty());
    let handed = answers_to(&t.b, "~nec", &n);
    assert!(handed.len() == 1 && handed[0].contains(" limit ["), "{handed:?}");
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst) - writes, 2, "tries");
}

/// A whole refusal that comes while a question is still being written is taken, without
/// waiting for the write to fail: ~zod reads at most 128 KiB (and lets one stream send it no
/// more than that before it reads); ~nec asks 900,000 bytes with ten seconds to spare. ~zod is
/// held (its gate) after sending its refusal and before letting go of the request's receiving
/// side, so nothing tells ~nec to stop writing. ~nec is told `Limit` (one try) before ~zod lets
/// go of the request's receiving side (by ~zod's notes: the request not yet let go of when ~nec
/// has its answer; ~zod's own note that it reached its gate may come after); and the same for an
/// agent, handed LIMIT.
#[test]
fn a_refusal_that_comes_while_a_question_is_still_written_is_taken() {
    let small = Config { max_event_bytes: 32 << 10, max_checkpoint_bytes: 16 << 10, max_unanswered: 64, ..fast() };
    let small_net = NetConfig { max_message_bytes: 128 << 10, ..NetConfig::default() };
    let window = super::stream_room(&small_net);
    let payload = vec![b' '; 900_000];
    assert!(payload.len() as u64 > 4 * window, "{} bytes against a window of {window}", payload.len());
    let b_cfg = Config { max_ask_bytes: 1 << 20, ..fast() };
    let b_net = NetConfig { max_message_bytes: 2 << 20, ..NetConfig::default() };
    let t = two_with("refused-while-written", (small, small_net), (b_cfg, b_net), counter_with(true, false), &["~nec"]);
    t.a.inner.recording.store(true, Ordering::SeqCst);
    let (from, writes) = (t.a.inner.notes_len(), t.b.inner.ask_writes.load(Ordering::SeqCst));
    let (sent, let_go) = t.a.inner.gates.arm_async("refusal sent");
    assert_eq!(ask(&t, None, "counter", &payload, Duration::from_secs(10)), Err(AskError::Limit), "the refusal not taken while the question was written");
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst) - writes, 1, "tries");
    sent.recv_timeout(Duration::from_secs(10)).expect("~zod at its gate");
    assert!(t.a.inner.notes_of("request let go of", "nec", from).is_empty(), "~zod had let go of the request");
    let _ = let_go.send(());
    eventually("~zod to let go of the request", Duration::from_secs(5), || !t.a.inner.notes_of("request let go of", "nec", from).is_empty());
    let from = t.a.inner.notes_len();
    let (sent, let_go) = t.a.inner.gates.arm_async("refusal sent");
    let n = say(&t.b, "~nec", "tally", &format!("ask-on zod counter counter 10000 {}", "x".repeat(900_000)));
    eventually("the answer", Duration::from_secs(9), || !answers_to(&t.b, "~nec", &n).is_empty());
    let handed = answers_to(&t.b, "~nec", &n);
    assert!(handed.len() == 1 && handed[0].contains(" limit ["), "{handed:?}");
    sent.recv_timeout(Duration::from_secs(10)).expect("~zod at its gate");
    assert!(t.a.inner.notes_of("request let go of", "nec", from).is_empty(), "~zod had let go of the request");
    let _ = let_go.send(());
}

/// A clock for `write_question`'s tests: a moment, moved on only by the writer below.
#[derive(Clone)]
struct FakeClock(Arc<Mutex<Instant>>);

impl FakeClock {
    fn now(&self) -> Instant {
        *lock(&self.0)
    }
}

/// A writer that is not ready (pending, moving the fake clock on one millisecond each poll, and
/// asking to be polled again) until the fake clock reaches `ready_at`; then it takes all it is
/// given, and notes what and at which moment of the fake clock.
struct SlowWriter {
    clock: FakeClock,
    ready_at: Instant,
    taken: Vec<u8>,
    taken_at: Option<Instant>,
}

impl tokio::io::AsyncWrite for SlowWriter {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, bytes: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let now = self.clock.now();
        if now < self.ready_at {
            *lock(&self.clock.0) = now + Duration::from_millis(1);
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        if self.taken_at.is_none() {
            self.taken_at = Some(now);
        }
        self.taken.extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Write `request` with `write_question` to a writer ready `ready_after` after the start, with
/// the deadline `deadline_after` after it; the outcome, what was taken and when, the start, and
/// how many times the request was encoded (by the encoder `write_question` was given, which
/// counts its calls and encodes as the network does).
fn write_slowly(request: &mut PeerRequest, ready_after: Duration, deadline_after: Duration) -> (Result<(), super::FirstWrite>, Vec<u8>, Option<Instant>, Instant, usize) {
    let start = Instant::now();
    let clock = FakeClock(Arc::new(Mutex::new(start)));
    let mut writer = SlowWriter { clock: clock.clone(), ready_at: start + ready_after, taken: Vec::new(), taken_at: None };
    let encodings = AtomicUsize::new(0);
    let encode = |request: &PeerRequest| {
        encodings.fetch_add(1, Ordering::SeqCst);
        ship_proto::Message::encode_to_vec(request)
    };
    let tokio = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let wrote = tokio.block_on(super::write_question(&mut writer, request, start + deadline_after, move || clock.now(), encode));
    (wrote, writer.taken, writer.taken_at, start, encodings.load(Ordering::SeqCst))
}

/// The allowance in a question's bytes.
fn allowance_in(bytes: &[u8]) -> u64 {
    match <PeerRequest as ship_proto::Message>::decode(bytes).unwrap().body {
        Some(peer_request::Body::Ask(ask)) => ask.within_millis,
        other => panic!("{other:?}"),
    }
}

/// A question's first write, its connection not ready until past its deadline: it ends as out of
/// time, and the connection took no byte of it.
#[test]
fn a_question_whose_first_write_waits_past_its_deadline_sends_nothing() {
    let mut request = question("", "counter", b"hits", 10);
    let (wrote, taken, _, _, _) = write_slowly(&mut request, Duration::from_millis(15), Duration::from_millis(10));
    assert!(taken.is_empty(), "the connection took {} bytes after the deadline", taken.len());
    assert!(matches!(wrote, Err(super::FirstWrite::TimedOut)), "{wrote:?}");
}

/// A question's first write, its connection not ready until some of its time has gone: the
/// bytes the connection takes carry no more than the whole milliseconds left at the poll in which
/// it took them, less than first encoded.
#[test]
fn a_question_whose_first_write_waits_carries_only_the_time_left() {
    let mut request = question("", "counter", b"hits", 10);
    let (wrote, taken, taken_at, start, encodings) = write_slowly(&mut request, Duration::from_millis(4), Duration::from_millis(10));
    assert!(wrote.is_ok(), "{wrote:?}");
    let left = (start + Duration::from_millis(10)).saturating_duration_since(taken_at.expect("taken"));
    let allowance = allowance_in(&taken);
    assert!(Duration::from_millis(allowance) <= left, "{allowance} ms on the wire with {left:?} left as it was taken");
    assert!(allowance < 10, "{allowance} ms on the wire: not encoded again");
    // Encoded first with 10, then once for each smaller allowance as the clock went on (polls at
    // 0, 1, 2, 3 and 4 ms: 10, 9, 8, 7, 6).
    assert_eq!(encodings, 5, "encodings");
}

/// A question's first write, its connection ready at once: one encoding (counted by the encoder
/// `write_question` is given), the allowance as given (no more than is left).
#[test]
fn a_question_whose_first_write_is_taken_at_once_is_encoded_once() {
    let mut request = question("", "counter", b"hits", 10);
    let first = ship_proto::Message::encode_to_vec(&request);
    let (wrote, taken, _, _, encodings) = write_slowly(&mut request, Duration::ZERO, Duration::from_millis(50));
    assert_eq!(encodings, 1, "encodings");
    assert!(wrote.is_ok(), "{wrote:?}");
    assert_eq!(taken, first);
    assert_eq!(allowance_in(&taken), 10);
}

/// A reply is taken for a bare refusal (`is_refusal`, used for a reply that comes before the
/// request is all written, or after its write failed) only if its outer fields are all the
/// refusal and the last carries a reason. An envelope of unknown fields alone, nothing, a
/// truncated field, a refusal with a body, a refusal with no reason, and every kind of typed reply
/// (all inner fields at their defaults) are not. Nor is a `Fetched` of 300 entries, whether its
/// entries are well-formed or are bytes no decoding could read. That last case establishes only
/// that the buffer is rejected: the old decode-based form also said no for it. That no typed
/// decode and no allocation for the entries happens is by reading the source (`is_refusal` only
/// walks the fields, keeping nothing), not by this test. Nor is a refusal whose key is a ten-byte
/// number with more in its tenth byte than the one bit left of 64.
#[test]
fn only_a_bare_refusal_is_taken_for_a_refusal() {
    use ship_proto::peer_reply::Body;
    let reply = |body: Option<Body>, refused: &str| ship_proto::Message::encode_to_vec(&PeerReply { body, refused: refused.to_string() });
    // Field 20, a varint: not a field of `PeerReply`.
    let unknown: Vec<u8> = vec![0xa0, 0x01, 0x01];
    assert!(!super::is_refusal(&unknown), "unknown fields alone taken for a refusal");
    assert!(super::is_refusal(&reply(None, "too busy; try again")));
    assert!(!super::is_refusal(&[]), "nothing taken for a refusal");
    let refusal = reply(None, "too busy; try again");
    assert!(!super::is_refusal(&refusal[..refusal.len() - 3]), "a truncated field taken for a refusal");
    assert!(!super::is_refusal(&[0x7a, 0x00]), "a refusal with no reason taken for one");
    let mut with_unknown = refusal.clone();
    with_unknown.extend_from_slice(&unknown);
    assert!(!super::is_refusal(&with_unknown), "a refusal with an unknown field taken for one");
    // The refusal's key (field 15, length-delimited: 0x7a) written as ten bytes, the tenth
    // carrying more than the one bit left of 64: a number too large, which prost refuses.
    let overflowing = [0xfa, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7e, 0x04, b'b', b'u', b's', b'y'];
    assert!(<PeerReply as ship_proto::Message>::decode(&overflowing[..]).is_err(), "prost took the overflowing key");
    assert!(!super::is_refusal(&overflowing), "a refusal with an overflowing ten-byte key taken for one");
    assert!(!super::is_refusal(&reply(Some(Body::Pong(Default::default())), "too busy")), "a refusal with a body taken for one");
    for body in [
        Body::Pong(Default::default()),
        Body::Delivered(Default::default()),
        Body::Fetched(Default::default()),
        Body::Heard(Default::default()),
        Body::Resynced(Default::default()),
        Body::Welcome(Default::default()),
        Body::FileAbout(Default::default()),
        Body::FileLeaves(Default::default()),
        Body::FileUpper(Default::default()),
        Body::FileChunk(Default::default()),
        Body::Ask(Default::default()),
    ] {
        let typed = reply(Some(body.clone()), "");
        assert!(!super::is_refusal(&typed), "{body:?} taken for a refusal");
    }
    let many = ship_proto::Fetched { entries: vec![Default::default(); 300], ..Default::default() };
    assert!(!super::is_refusal(&reply(Some(Body::Fetched(many)), "")), "a Fetched of 300 entries taken for a refusal");
    // A `Fetched` (field 3) of 300 entries (its field 1) that are each the byte 0xff: not a
    // message, so decoding this buffer fails.
    let mut entries = Vec::new();
    for _ in 0..300 {
        entries.extend_from_slice(&[0x0a, 0x01, 0xff]);
    }
    let mut unreadable = vec![0x1a];
    let mut len = entries.len();
    while len >= 0x80 {
        unreadable.push((len as u8 & 0x7f) | 0x80);
        len >>= 7;
    }
    unreadable.push(len as u8);
    unreadable.extend_from_slice(&entries);
    // Rejected; the decode-based form rejected this too, so this does not show which way.
    assert!(<PeerReply as ship_proto::Message>::decode(&*unreadable).is_err(), "the buffer can be decoded");
    assert!(!super::is_refusal(&unreadable), "an unreadable Fetched taken for a refusal");
}

/// A `within` given to the HTTP route in any form that is not a whole number of seconds in
/// range, given once, is refused (400), and nothing is asked: given more than once too, even
/// with one good value among them, with the name spelled with escapes (`%77ithin`), and with a
/// `%` not followed by two hexadecimal digits (`label%+1=x`, `within=%+1`).
#[test]
fn a_malformed_within_on_the_http_route_asks_nothing() {
    let t = two("http-within", counter_with(true, false));
    let server = Server::start(t.b.clone(), ServerConfig::default()).unwrap();
    let code = t.b.new_signin_code("~nec", Duration::from_secs(60)).unwrap();
    let auth = format!("Bearer {}", t.b.sign_in("~nec", &code, "test").unwrap().0);
    let writes = t.b.inner.ask_writes.load(Ordering::SeqCst);
    for query in ["within", "within=", "within=%FF", "within=abc", "within=0", "within=61", "within=1.5", "within=-1", "within&within=1", "within=1&within=%FF", "within=1&within=2", "%77ithin=0", "within=1&%77ithin=2", "label%+1=x", "within=%+1"] {
        let (status, _, body) = http(&server, "POST", &format!("/ships/nec/ask/zod/counter/counter?{query}"), &auth, b"hits");
        assert_eq!(status, 400, "?{query}: {}", String::from_utf8_lossy(&body));
    }
    assert_eq!(t.b.inner.ask_writes.load(Ordering::SeqCst), writes, "a question was asked");
    assert_eq!(http(&server, "POST", "/ships/nec/ask/zod/counter/counter?within=5", &auth, b"hits").0, 200);
}

// Refusals: a command its agent turns down on purpose, with a fault. Nothing the command did is
// kept, and the fault reaches whoever sent it. The agents here are written by hand (WAT), each
// export making the host calls it is given, in order, and then calling `refuse` if told to.

use ship_proto::{AppendRequest, AskRequest, Fault, FileMark, FollowRequest, Message, PeerMessage, ReadRequest, Receipt, SendRequest, ShareRequest, Verdict};

/// One thing a hand-written agent does in one of its exports.
enum Step {
    Put(&'static [u8], &'static [u8]),
    Delete(&'static [u8]),
    Emit(&'static [u8]),
    Append(AppendRequest),
    Follow(FollowRequest),
    Share(ShareRequest),
    Send(SendRequest),
    SendTo(SendRequest),
    Ask(AskRequest),
    Drop(u64),
    Mark(FileMark),
    Read(ReadRequest),
    /// Keep what the export was handed under its first two bytes (a receipt's number, while it
    /// is below 128).
    KeepInput,
    /// Answer with what is kept under the bytes the export was handed.
    AnswerKept,
    /// Call `refuse` with these bytes.
    Refuse(Vec<u8>),
    /// Call `refuse` with this pointer and length, whatever is there.
    RefuseAt(u32, u32),
    /// Loop for ever.
    Spin,
}

/// Where a hand-written agent's buffer for what it reads back is, and how large.
const BUFFER: (u64, u64) = (200_000, 50_000);

/// A module whose exports each make the host calls given. Every export answers with nothing
/// unless a step says otherwise. Two names are not exports of their own: steps under `start` make
/// a start function, run as the module is made, and steps under `alloc` run in the allocator
/// before it allocates.
fn hand_agent(exports: &[(&str, Vec<Step>)]) -> Vec<u8> {
    let mut data = String::new();
    let mut at = 16usize;
    let mut place = |bytes: &[u8]| -> String {
        let here = at;
        let escaped: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        data.push_str(&format!("  (data (i32.const {here}) \"{escaped}\")\n"));
        at += bytes.len() + 16;
        assert!(at < 131_072, "too much data for a hand-written agent");
        format!("(i32.const {here}) (i32.const {})", bytes.len())
    };
    let (mut funcs, mut allocating) = (String::new(), String::new());
    for (export, steps) in exports {
        let mut body = String::new();
        for step in steps {
            let line = match step {
                Step::Put(key, value) => format!("(call $kv_put {} {})", place(key), place(value)),
                Step::Delete(key) => format!("(call $kv_delete {})", place(key)),
                Step::Emit(bytes) => format!("(call $emit {})", place(bytes)),
                Step::Append(request) => format!("(drop (call $log_append {}))", place(&request.encode_to_vec())),
                Step::Follow(request) => format!("(call $log_follow {})", place(&request.encode_to_vec())),
                Step::Share(request) => format!("(call $log_share {})", place(&request.encode_to_vec())),
                Step::Send(request) => format!("(call $send {})", place(&request.encode_to_vec())),
                Step::SendTo(request) => format!("(drop (call $send_to {}))", place(&request.encode_to_vec())),
                Step::Ask(request) => format!("(drop (call $ask_to {}))", place(&request.encode_to_vec())),
                Step::Drop(number) => format!("(drop (call $ask_drop (i64.const {number})))"),
                Step::Mark(request) => format!("(drop (call $file_mark {}))", place(&request.encode_to_vec())),
                Step::Read(request) => format!("(drop (call $read {} (i32.const {}) (i32.const {})))", place(&request.encode_to_vec()), BUFFER.0, BUFFER.1),
                Step::KeepInput => "(call $kv_put (local.get 0) (i32.const 2) (local.get 0) (local.get 1))".to_string(),
                Step::AnswerKept => format!(
                    "(local.set $n (call $kv_get (local.get 0) (local.get 1) (i32.const {}) (i32.const {})))\n    (if (i64.lt_s (local.get $n) (i64.const 0)) (then (local.set $n (i64.const 0))))\n    (return (i64.or (i64.const {}) (local.get $n)))",
                    BUFFER.0,
                    BUFFER.1,
                    BUFFER.0 << 32
                ),
                Step::Refuse(bytes) => format!("(call $refuse {})", place(bytes)),
                Step::RefuseAt(ptr, len) => format!("(call $refuse (i32.const {ptr}) (i32.const {len}))"),
                Step::Spin => "(loop $spin (br $spin))".to_string(),
            };
            body.push_str("    ");
            body.push_str(&line);
            body.push('\n');
        }
        match *export {
            "start" => funcs.push_str(&format!("  (func $start (local $n i64)\n{body})\n  (start $start)\n")),
            "alloc" => allocating = body,
            _ => funcs.push_str(&format!("  (func (export \"{export}\") (param i32 i32) (result i64) (local $n i64)\n{body}    (i64.const 0))\n")),
        }
    }
    let source = format!(
        r#"(module
  (import "host" "kv_put" (func $kv_put (param i32 i32 i32 i32)))
  (import "host" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i64)))
  (import "host" "kv_delete" (func $kv_delete (param i32 i32)))
  (import "host" "emit" (func $emit (param i32 i32)))
  (import "host" "read" (func $read (param i32 i32 i32 i32) (result i64)))
  (import "host" "send" (func $send (param i32 i32)))
  (import "host" "send_to" (func $send_to (param i32 i32) (result i64)))
  (import "host" "log_append" (func $log_append (param i32 i32) (result i64)))
  (import "host" "log_follow" (func $log_follow (param i32 i32)))
  (import "host" "log_share" (func $log_share (param i32 i32)))
  (import "host" "ask_to" (func $ask_to (param i32 i32) (result i64)))
  (import "host" "ask_drop" (func $ask_drop (param i64) (result i64)))
  (import "host" "file_mark" (func $file_mark (param i32 i32) (result i64)))
  (import "host" "refuse" (func $refuse (param i32 i32)))
  (memory (export "memory") 4)
  (global $heap (mut i32) (i32.const 131072))
  (func (export "alloc") (param $len i32) (result i32) (local $at i32) (local $n i64)
{allocating}    (local.set $at (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get $len)))
    (local.get $at))
{data}{funcs})"#
    );
    wat::parse_str(&source).unwrap_or_else(|e| panic!("{e}\n{source}"))
}

fn fault(code: &str, message: &str) -> Fault {
    Fault { code: code.into(), message: message.into() }
}

fn fault_bytes(code: &str, message: &str) -> Vec<u8> {
    fault(code, message).encode_to_vec()
}

/// The largest fault there may be: a code of 64 bytes and a message of 200, the message in
/// characters of two bytes.
fn largest_fault() -> Fault {
    fault(&"!".repeat(crate::store::MAX_FAULT_CODE_BYTES), &"\u{e9}".repeat(crate::store::MAX_FAULT_MESSAGE_BYTES / 2))
}

/// An agent offering `interface` (open to other ships' commands), with these uses.
fn offering(interface: &str, uses: Vec<Use>) -> Manifest {
    Manifest { provides: vec![Provide { interface: interface.into(), public: false, remote: true, asked: false }], uses }
}

/// Leave to send to (and ask) `agent`'s `interface` on `ship`.
fn sending_to(ship: &str, agent: &str, interface: &str) -> Use {
    Use { ship: ship.into(), agent: agent.into(), interface: interface.into(), read: false, send: true, ask: true }
}

/// A runtime with one ship, `ship`, and nothing installed.
fn lone(dir: &Path, cfg: Config, ship: &str) -> Arc<Runtime> {
    let rt = Arc::new(Runtime::open(dir, cfg).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    rt.create_ship(ship, &kernel).unwrap();
    rt
}

/// Install (or replace) `agent` on `ship` as a hand-written agent.
fn hand_install(rt: &Runtime, ship: &str, agent: &str, exports: &[(&str, Vec<Step>)], manifest: &Manifest) {
    let module = rt.add_module(&hand_agent(exports)).unwrap();
    rt.install(ship, agent, &module, manifest).unwrap();
}

fn rejected(result: Result<crate::Outcome, Error>) -> Rejection {
    match result {
        Err(Error::Rejected(rejection)) => rejection,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// Every row of every table of a ship's file but the audit log, as text, by table.
fn everything_but_the_audit(rt: &Runtime, ship: &str) -> BTreeMap<String, Vec<String>> {
    rt.inner
        .with_ship(ship, |held| {
            let conn = lock(&held.conn);
            let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'audit'")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            let mut all = BTreeMap::new();
            for table in tables {
                let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
                let columns = stmt.column_count();
                let rows = stmt
                    .query_map([], |row| (0..columns).map(|i| row.get::<_, rusqlite::types::Value>(i).map(|value| format!("{value:?}"))).collect::<rusqlite::Result<Vec<_>>>().map(|values| values.join(" | ")))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                // The audit log's own numbering is the audit log's.
                let rows = rows.into_iter().filter(|row| !(table == "sqlite_sequence" && row.starts_with("Text(\"audit\")"))).collect();
                all.insert(table, rows);
            }
            Ok(all)
        })
        .unwrap()
}

/// The receipt a hand-written recorder (`KeepInput` in its receipt export, `AnswerKept` in its
/// read export) was handed for the command numbered `about`.
fn recorded(rt: &Runtime, ship: &str, agent: &str, about: u8) -> Option<Receipt> {
    let bytes = rt.read(ship, agent, agent, &[0x08, about]).unwrap();
    (!bytes.is_empty()).then(|| Receipt::decode(&*bytes).unwrap())
}

/// A recorder: its command sends `payload` to `agent`'s `interface` on `ship` (wanting the
/// reply as `reply` says), and it keeps each receipt and answers with it.
fn recorder(ship: &str, agent: &str, interface: &str, reply: bool) -> Vec<(&'static str, Vec<Step>)> {
    let send = SendRequest { ship: ship.into(), agent: agent.into(), interface: interface.into(), payload: b"please".to_vec(), reply };
    vec![("handle", vec![Step::SendTo(send)]), ("receipt", vec![Step::KeepInput]), ("read", vec![Step::AnswerKept])]
}

/// A refused command keeps nothing: before it refuses, it writes a key and deletes another, puts
/// out a message, appends to its log, follows a log and shares one, sends a command here and one
/// to another ship, puts a question, drops one it put earlier, and marks a file open. After it,
/// every table of the ship's file but the audit log holds exactly what it held before; the
/// refusal comes back with its code and message; and the audit log has the command, not kept.
#[test]
fn a_refused_command_keeps_nothing_it_did_and_says_why() {
    let dir = TempDir::new("refuse-keeps-nothing");
    let rt = lone(&dir.0, Config { max_queued_per_deliver: 0, ..fast() }, "~zod");
    // As though a network were running, so that a question put waits to be put.
    rt.inner.networked.store(true, Ordering::SeqCst);
    let manifest = offering("evil", vec![sending_to("nec", "counter", "counter")]);
    let question = AskRequest { ship: "nec".into(), agent: "counter".into(), interface: "counter".into(), payload: b"?".to_vec(), within_millis: 60_000 };
    let setup = vec![
        Step::Put(b"kept", b"1"),
        Step::Append(AppendRequest { log: "evil".into(), payload: b"first".to_vec() }),
        Step::Ask(question.clone()),
    ];
    hand_install(&rt, "~zod", "evil", &[("handle", setup)], &manifest);
    rt.deliver("~zod", "evil", b"set up").unwrap();
    let (upload, _) = rt.upload_start("~zod", "evil", 5, "text/plain").unwrap();
    rt.upload_chunk("~zod", "evil", &upload, 0, b"hello".to_vec()).unwrap();
    let id = rt.upload_finish("~zod", "evil", &upload, None).unwrap().id;
    assert!(!rt.file_info("~zod", "evil", &id).unwrap().open);

    let everything = vec![
        Step::Put(b"new", b"2"),
        Step::Delete(b"kept"),
        Step::Emit(b"out"),
        Step::Append(AppendRequest { log: "evil".into(), payload: b"second".to_vec() }),
        Step::Follow(FollowRequest { ship: String::new(), agent: "evil".into(), log: "evil".into() }),
        Step::Share(ShareRequest { log: "evil".into(), ship: "nec".into(), stop: false }),
        Step::Send(SendRequest { ship: String::new(), agent: "evil".into(), interface: "evil".into(), payload: b"again".to_vec(), reply: false }),
        Step::SendTo(SendRequest { ship: "nec".into(), agent: "counter".into(), interface: "counter".into(), payload: b"inc hits".to_vec(), reply: true }),
        Step::Ask(question),
        Step::Drop(1),
        Step::Mark(FileMark { id: id.to_vec(), open: true }),
        Step::Refuse(fault_bytes("not-today", "the book is closed")),
    ];
    hand_install(&rt, "~zod", "evil", &[("handle", everything)], &manifest);
    let before = everything_but_the_audit(&rt, "~zod");
    let audited = rt.audit("~zod", 1000).unwrap().len();
    let refused = rejected(rt.deliver("~zod", "evil", b"do everything"));
    assert_eq!(everything_but_the_audit(&rt, "~zod"), before);
    assert_eq!(refused, Rejection::Refused(fault("not-today", "the book is closed")));
    assert_eq!(Error::Rejected(refused).to_string(), "event rejected: refused: not-today: the book is closed");
    // Looked at one by one as well, through the runtime.
    assert!(!rt.file_info("~zod", "evil", &id).unwrap().open);
    assert_eq!(rt.log_head("~zod", "evil", "evil").unwrap().unwrap().0, 1);
    assert_eq!(rt.log_position("~zod", "evil", "evil", "evil").unwrap(), None);
    assert!(rt.log_shares("~zod", "evil", "evil").unwrap().is_empty());
    assert_eq!((rt.pending("~zod").unwrap(), rt.outbound_pending("~zod").unwrap(), rt.unanswered("~zod").unwrap()), (0, 0, 0));
    assert!(rt.drain_outbox("~zod", 1 << 20).unwrap().is_empty());
    // The audit log has the command, not kept, as for any rejection.
    let audit = rt.audit("~zod", 1000).unwrap();
    assert_eq!(audit.len(), audited + 1);
    assert_eq!((audit[0].agent.as_str(), audit[0].event.as_slice(), audit[0].ok), ("evil", b"do everything".as_slice(), false));
}

/// A refusal counts only in a command's own handler. In a read (asked by the owner, or nested
/// under a command), a notification, a receipt, an answer, a checkpoint request and a file
/// question it is an ordinary failure, with no fault, each its own case; the command is the one
/// place it is taken.
#[test]
fn a_refusal_counts_only_in_a_commands_own_handler() {
    use ship_proto::Kind;
    let dir = TempDir::new("refuse-where");
    let rt = lone(&dir.0, Config { max_queued_per_deliver: 0, checkpoint_min_bytes: 1, ..fast() }, "~zod");
    rt.inner.networked.store(true, Ordering::SeqCst);
    let no = || Step::Refuse(fault_bytes("no", "not here"));
    let manifest = offering("evil", vec![sending_to("nec", "counter", "counter")]);
    let send = SendRequest { ship: "nec".into(), agent: "counter".into(), interface: "counter".into(), payload: b"inc".to_vec(), reply: false };
    let question = AskRequest { ship: "nec".into(), agent: "counter".into(), interface: "counter".into(), payload: b"?".to_vec(), within_millis: 60_000 };
    let mut exports = vec![("handle", vec![
        Step::Follow(FollowRequest { ship: String::new(), agent: "evil".into(), log: "evil".into() }),
        Step::Append(AppendRequest { log: "evil".into(), payload: b"one".to_vec() }),
        Step::SendTo(send),
        Step::Ask(question),
    ])];
    for export in ["read", "notify", "receipt", "answer", "checkpoint", "file_ask"] {
        exports.push((export, vec![no()]));
    }
    hand_install(&rt, "~zod", "evil", &exports, &manifest);
    let reader = vec![("handle", vec![Step::Read(ReadRequest { agent: "evil".into(), interface: "evil".into(), payload: b"look".to_vec() })])];
    hand_install(&rt, "~zod", "reader", &reader, &Manifest { provides: vec![], uses: vec![Use { ship: String::new(), agent: "evil".into(), interface: "evil".into(), read: true, send: false, ask: false }] });
    let taken = |agent: &str, kind: Kind, depth: u32| -> Vec<bool> {
        lock(&rt.inner.refusals).iter().filter(|(who, k, d, _)| who == agent && *k == kind as i32 && *d == depth).map(|(_, _, _, taken)| *taken).collect()
    };

    // A read the owner asks, and one nested under a command: an ordinary failure, each.
    assert!(matches!(rt.read("~zod", "evil", "evil", b"look"), Err(Error::Rejected(Rejection::Trap(_)))));
    assert_eq!(taken("evil", Kind::Read, 0), [false]);
    assert!(matches!(rejected(rt.deliver("~zod", "reader", b"go")), Rejection::Trap(_)));
    assert_eq!(taken("evil", Kind::Read, 1), [false]);

    // The command commits: a follow and an append (so a notification and a checkpoint request
    // are queued), a command to ~nec and a question to it.
    rt.deliver("~zod", "evil", b"set up").unwrap();
    // ~nec's receipt for the command, and the answer to the question, as they would come.
    rt.inner
        .with_ship("~zod", |ship| ship.accept(&rt.inner, "nec", &[PeerMessage { seq: 1, receipt: Some(Receipt { about: 1, verdict: Verdict::Ran as i32, ..Receipt::default() }), ..PeerMessage::default() }]))
        .unwrap();
    let incarnation = rt.incarnation("~zod").unwrap();
    rt.inner.with_ship("~zod", |ship| ship.ask_answered(&rt.inner, &incarnation, 1, Outcome::Reply, b"yes", "")).unwrap();
    let audited = rt.audit("~zod", 1000).unwrap().len();
    // (A notification whose handler fails is prompted again a few times.)
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    for kind in [Kind::Notify, Kind::Checkpoint, Kind::Receipt, Kind::Answer] {
        let seen = taken("evil", kind, 0);
        assert!(!seen.is_empty() && seen.iter().all(|taken| !taken), "{kind:?}: {seen:?}");
    }
    let audit = rt.audit("~zod", 1000).unwrap();
    assert!(audit.len() - audited >= 4 && audit[..audit.len() - audited].iter().all(|entry| entry.agent == "evil" && !entry.ok));

    // A file question: no, as for any failure.
    let (upload, _) = rt.upload_start("~zod", "evil", 2, "").unwrap();
    rt.upload_chunk("~zod", "evil", &upload, 0, b"hi".to_vec()).unwrap();
    let id = rt.upload_finish("~zod", "evil", &upload, None).unwrap().id;
    let permit = rt.inner.with_ship("~zod", |ship| ship.file_permit(&rt.inner, "nec", "evil", &id, None)).unwrap();
    assert!(matches!(permit, crate::ship::Permit::No));
    assert_eq!(taken("evil", Kind::FileAsk, 0), [false]);

    // And a command's own handler: taken.
    hand_install(&rt, "~zod", "evil", &[("handle", vec![no()])], &manifest);
    assert_eq!(rejected(rt.deliver("~zod", "evil", b"now")), Rejection::Refused(fault("no", "not here")));
    assert_eq!(taken("evil", Kind::Command, 0), [true]);
}

/// What a fault may be: a code of 1 to 64 bytes, each printable ASCII other than space, and any
/// message, cut to 200 bytes at a character boundary with each control character turned into a
/// space. A refusal that breaks the rule on the code, or that is not a fault at all, is an
/// ordinary failure, each case its own.
#[test]
fn what_a_fault_may_be_is_held_to_its_rules() {
    let dir = TempDir::new("refuse-rules");
    let rt = lone(&dir.0, fast(), "~zod");
    let manifest = offering("evil", vec![]);
    let refusing = |bytes: Vec<u8>| {
        hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Put(b"k", b"v"), Step::Refuse(bytes)])], &manifest);
        rejected(rt.deliver("~zod", "evil", b"go"))
    };
    let ordinary = |label: &str, bytes: Vec<u8>| {
        let rejection = refusing(bytes);
        assert!(matches!(rejection, Rejection::Trap(_)), "{label}: {rejection:?}");
    };
    ordinary("an empty code", fault_bytes("", "m"));
    ordinary("a code of 65 bytes", fault_bytes(&"a".repeat(65), "m"));
    ordinary("a space", fault_bytes("a b", "m"));
    ordinary("a control byte", fault_bytes("a\u{1}b", "m"));
    ordinary("a byte past ASCII", fault_bytes("caf\u{e9}", "m"));
    ordinary("a delete byte", fault_bytes("a\u{7f}", "m"));
    ordinary("bytes that are not a fault", vec![0xff, 0xff, 0xff]);
    // A message that is not UTF-8 does not decode as a fault either.
    ordinary("a message that is not text", vec![0x0a, 0x01, b'c', 0x12, 0x02, 0xc3, 0x28]);

    // At the bounds: taken whole.
    let whole = fault(&"~".repeat(64), &"m".repeat(200));
    assert_eq!(refusing(whole.encode_to_vec()), Rejection::Refused(whole));
    // Longer: cut at a character boundary. Bytes 199 and 200 are one character, so it goes.
    let straddling = format!("{}\u{e9}tail", "m".repeat(199));
    assert_eq!(refusing(fault_bytes("long", &straddling)), Rejection::Refused(fault("long", &"m".repeat(199))));
    // Control characters (one byte, and two) turned into spaces.
    assert_eq!(refusing(fault_bytes("c", "a\u{7}b\nc\u{85}d\te")), Rejection::Refused(fault("c", "a b c d e")));
    // Every printable byte but space may be in a code: all 94, in two codes of 64 and 30.
    let printable: Vec<char> = (0x21u8..=0x7e).map(char::from).collect();
    assert_eq!(printable.len(), 94);
    for part in printable.chunks(64) {
        let code: String = part.iter().collect();
        assert_eq!(refusing(fault_bytes(&code, "")), Rejection::Refused(fault(&code, "")));
    }
    // Nothing of any of it was kept.
    assert!(rt.inner.with_ship("~zod", |ship| Ok(crate::store::kv_get(&lock(&ship.conn), "evil", b"k", 16)?)).unwrap().is_none());
}

/// A handler that refuses after its deadline is reported as refused, not as out of time: here
/// the refusal is held, inside `refuse`, until well past the deadline. A handler the watchdog
/// stops before it reaches `refuse` is out of time, as before.
#[test]
fn a_refusal_after_the_deadline_is_still_a_refusal() {
    let dir = TempDir::new("refuse-late");
    let rt = lone(&dir.0, Config { max_event_millis: 200, fuel_per_event: 1 << 50, ..fast() }, "~zod");
    let manifest = offering("evil", vec![]);
    hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Put(b"k", b"v"), Step::Refuse(fault_bytes("late", "but said"))])], &manifest);
    let (entered, release) = rt.inner.gates.arm("refusing");
    let held = rt.clone();
    let thread = std::thread::spawn(move || held.deliver("~zod", "evil", b"go"));
    entered.recv_timeout(Duration::from_secs(10)).expect("the handler to refuse");
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    release.send(()).unwrap();
    let result = thread.join().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(rejected(result), Rejection::Refused(fault("late", "but said")));
    assert!(rt.inner.with_ship("~zod", |ship| Ok(crate::store::kv_get(&lock(&ship.conn), "evil", b"k", 16)?)).unwrap().is_none());

    hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Spin, Step::Refuse(fault_bytes("never", "reached"))])], &manifest);
    assert_eq!(rejected(rt.deliver("~zod", "evil", b"go")), Rejection::Timeout);
}

/// A command one agent queues for another on the same ship, which refuses it, is dropped as any
/// rejected queued command is: off the queue, nothing it did kept, recorded as not kept. The
/// command that queued it stands.
#[test]
fn a_queued_command_that_refuses_is_dropped() {
    let dir = TempDir::new("refuse-queued");
    let rt = lone(&dir.0, Config { max_queued_per_deliver: 0, ..fast() }, "~zod");
    hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Put(b"k", b"v"), Step::Refuse(fault_bytes("no", "thanks"))])], &offering("evil", vec![]));
    let send = SendRequest { ship: String::new(), agent: "evil".into(), interface: "evil".into(), payload: b"queued".to_vec(), reply: false };
    let uses = vec![Use { ship: String::new(), agent: "evil".into(), interface: "evil".into(), read: false, send: true, ask: false }];
    hand_install(&rt, "~zod", "sender", &[("handle", vec![Step::Put(b"sent", b"yes"), Step::Send(send)])], &Manifest { provides: vec![], uses });
    rt.deliver("~zod", "sender", b"go").unwrap();
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(rt.pending("~zod").unwrap(), 0);
    let audit = rt.audit("~zod", 10).unwrap();
    assert_eq!((audit[0].agent.as_str(), audit[0].event.as_slice(), audit[0].ok), ("evil", b"queued".as_slice(), false));
    let kept = |agent: &str, key: &[u8]| rt.inner.with_ship("~zod", |ship| Ok(crate::store::kv_get(&lock(&ship.conn), agent, key, 16)?)).unwrap().is_some();
    assert!(kept("sender", b"sent"));
    assert!(!kept("evil", b"k"));
    // Run again: nothing more.
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
}

/// Two ships: a command ~zod's agents send to an agent on ~nec that refuses it comes back with
/// REFUSED and the fault, the fixed words as its reason and no reply, whether or not a reply was
/// asked for; and nothing the command did on ~nec was kept.
#[test]
fn a_refused_command_from_another_ship_brings_its_fault_back_on_the_receipt() {
    let dirs = (TempDir::new("refuse-far-a"), TempDir::new("refuse-far-b"));
    let directory = Directory::new();
    let zod = lone(&dirs.0 .0, fast(), "~zod");
    let nec = lone(&dirs.1 .0, fast(), "~nec");
    let refusal = vec![
        Step::Put(b"k", b"v"),
        Step::Append(AppendRequest { log: "evil".into(), payload: b"entry".to_vec() }),
        Step::Refuse(fault_bytes("closed", "the book is closed \u{1} today")),
    ];
    let open = Manifest { provides: vec![Provide { interface: "evil".into(), public: false, remote: true, asked: true }], uses: vec![] };
    hand_install(&nec, "~nec", "evil", &[("handle", refusal), ("read", vec![Step::Refuse(fault_bytes("no", "not a command"))])], &open);
    for (agent, reply) in [("rec", false), ("rep", true)] {
        hand_install(&zod, "~zod", agent, &recorder("nec", "evil", "evil", reply), &offering(agent, vec![sending_to("nec", "evil", "evil")]));
    }
    let zod_net = Network::start(zod.clone(), directory.clone(), NetConfig::default()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    zod.deliver("~zod", "rec", b"send").unwrap();
    zod.deliver("~zod", "rep", b"send").unwrap();
    eventually("both receipts", Duration::from_secs(30), || recorded(&zod, "~zod", "rec", 1).is_some() && recorded(&zod, "~zod", "rep", 2).is_some());
    for (agent, about) in [("rec", 1), ("rep", 2)] {
        let receipt = recorded(&zod, "~zod", agent, about).unwrap();
        let expected = Receipt {
            about: about as u64,
            verdict: Verdict::Refused as i32,
            reason: crate::store::REFUSED_WORDS.into(),
            ship: "nec".into(),
            agent: "evil".into(),
            interface: "evil".into(),
            reply: Vec::new(),
            replied: false,
            fault: Some(fault("closed", "the book is closed   today")),
        };
        assert_eq!(receipt, expected, "{agent}");
    }
    // Nothing of either command was kept on ~nec, and each is in its audit log, not kept.
    assert!(nec.log_head("~nec", "evil", "evil").unwrap().is_none());
    assert!(nec.inner.with_ship("~nec", |ship| Ok(crate::store::kv_get(&lock(&ship.conn), "evil", b"k", 16)?)).unwrap().is_none());
    assert_eq!(nec.audit("~nec", 100).unwrap().iter().filter(|entry| entry.agent == "evil" && !entry.ok).count(), 2);
    // ~zod's audit log says what became of each, with the agent's words.
    let lines: Vec<String> = zod.audit("~zod", 100).unwrap().into_iter().filter(|entry| !entry.ok && entry.event.starts_with(b"~nec")).map(|entry| String::from_utf8_lossy(&entry.event).into_owned()).collect();
    assert!(lines.contains(&"~nec did not run command 1 to evil evil: the agent refused it: closed: the book is closed   today".to_string()), "{lines:?}");
    assert_eq!(zod.unanswered("~zod").unwrap(), 0);
    // A question from another ship's owner, which the read handler answers by calling `refuse`:
    // an ordinary failure there, told as one.
    assert_eq!(zod.ask("~zod", None, "~nec", "evil", "evil", b"?", Duration::from_secs(10)), Err(AskError::Failed));
    let seen: Vec<_> = lock(&nec.inner.refusals).iter().filter(|(_, kind, _, _)| *kind == ship_proto::Kind::Read as i32).cloned().collect();
    assert_eq!(seen, [("evil".to_string(), ship_proto::Kind::Read as i32, 0, false)]);
    drop((zod_net, nec_net));
}

/// The sending ship takes a fault only with REFUSED, and only one within the rules (its control
/// characters turned into spaces); the agent is then told the fixed words, whatever reason came.
/// A fault with RAN or FAILED, or one too long or with a code that breaks the rule, is let go:
/// the receipt is handed on with its verdict and no fault, and the reason and the audit log say
/// a fault came and was not taken. A REFUSED receipt without a fault keeps its verdict. If it
/// carries a reply, the receiver discards the reply and supplies the reply-discard reason.
#[test]
fn the_sending_ship_takes_a_fault_only_with_refused_and_within_the_rules() {
    let dir = TempDir::new("refuse-taken");
    let rt = lone(&dir.0, Config { max_queued_per_deliver: 0, ..fast() }, "~zod");
    hand_install(&rt, "~zod", "rec", &recorder("nec", "evil", "evil", false), &offering("rec", vec![sending_to("nec", "evil", "evil")]));
    // The same, its commands sent with the reply wanted, for the cases that bring a reply.
    hand_install(&rt, "~zod", "rep", &recorder("nec", "evil", "evil", true), &offering("rep", vec![sending_to("nec", "evil", "evil")]));
    let not_taken = crate::store::FAULT_NOT_TAKEN;
    let refused = Verdict::Refused as i32;
    let cases: Vec<(Receipt, Receipt)> = vec![
        // Taken: the reason that came is replaced, control characters become spaces.
        (Receipt { verdict: refused, reason: "whatever that ship says".into(), fault: Some(fault("no", "line\nbreak")), ..Receipt::default() }, Receipt { verdict: refused, reason: crate::store::REFUSED_WORDS.into(), fault: Some(fault("no", "line break")), ..Receipt::default() }),
        // The largest there may be: taken whole.
        (Receipt { verdict: refused, fault: Some(largest_fault()), ..Receipt::default() }, Receipt { verdict: refused, reason: crate::store::REFUSED_WORDS.into(), fault: Some(largest_fault()), ..Receipt::default() }),
        // With RAN, or FAILED: let go.
        (Receipt { verdict: Verdict::Ran as i32, fault: Some(fault("no", "m")), ..Receipt::default() }, Receipt { verdict: Verdict::Ran as i32, reason: not_taken.into(), ..Receipt::default() }),
        (Receipt { verdict: Verdict::Failed as i32, reason: "the agent failed".into(), fault: Some(fault("no", "m")), ..Receipt::default() }, Receipt { verdict: Verdict::Failed as i32, reason: not_taken.into(), ..Receipt::default() }),
        // Too long, or a code that breaks the rule: let go.
        (Receipt { verdict: refused, fault: Some(fault("no", &"m".repeat(201))), ..Receipt::default() }, Receipt { verdict: refused, reason: not_taken.into(), ..Receipt::default() }),
        (Receipt { verdict: refused, fault: Some(fault("n o", "m")), ..Receipt::default() }, Receipt { verdict: refused, reason: not_taken.into(), ..Receipt::default() }),
        (Receipt { verdict: refused, fault: Some(fault(&"c".repeat(65), "m")), ..Receipt::default() }, Receipt { verdict: refused, reason: not_taken.into(), ..Receipt::default() }),
        // REFUSED with none: handed on as it came.
        (Receipt { verdict: refused, reason: "no reason given".into(), ..Receipt::default() }, Receipt { verdict: refused, reason: "no reason given".into(), ..Receipt::default() }),
        // A reply marked with REFUSED is let go, though the command asked for one (these two are
        // sent by `rep`); a fault beside it within the rules is taken, and the reason is the
        // fault's; one breaking them is let go too, and the reason says so.
        (Receipt { verdict: refused, replied: true, reply: b"r".to_vec(), fault: Some(fault("no", "m")), ..Receipt::default() }, Receipt { verdict: refused, reason: crate::store::REFUSED_WORDS.into(), fault: Some(fault("no", "m")), ..Receipt::default() }),
        (Receipt { verdict: refused, replied: true, reply: b"r".to_vec(), fault: Some(fault("n o", "m")), ..Receipt::default() }, Receipt { verdict: refused, reason: not_taken.into(), ..Receipt::default() }),
    ];
    let sender = |about: u64| if about >= 9 { "rep" } else { "rec" };
    for (n, (came, _)) in cases.iter().enumerate() {
        let about = n as u64 + 1;
        rt.deliver("~zod", sender(about), b"send").unwrap();
        let message = PeerMessage { seq: about, receipt: Some(Receipt { about, ..came.clone() }), ..PeerMessage::default() };
        assert_eq!(rt.inner.with_ship("~zod", |ship| ship.accept(&rt.inner, "nec", &[message])).unwrap(), about);
    }
    assert_eq!(rt.run_pending("~zod", 100).unwrap(), cases.len());
    for (n, (_, told)) in cases.iter().enumerate() {
        let about = n as u64 + 1;
        let expected = Receipt { about, ship: "nec".into(), agent: "evil".into(), interface: "evil".into(), ..told.clone() };
        assert_eq!(recorded(&rt, "~zod", sender(about), about as u8).unwrap(), expected, "case {about}");
    }
    let lines: Vec<String> = rt.audit("~zod", 1000).unwrap().into_iter().filter(|entry| (entry.agent == "rec" || entry.agent == "rep") && !entry.ok && entry.event.starts_with(b"~nec")).map(|entry| String::from_utf8_lossy(&entry.event).into_owned()).collect();
    assert_eq!(lines.len(), cases.len(), "{lines:?}");
    assert!(lines.contains(&"~nec did not run command 1 to evil evil: the agent refused it: no: line break".to_string()), "{lines:?}");
    assert!(lines.contains(&format!("~nec ran command 3 to evil evil: it ran: {not_taken}")), "{lines:?}");
    assert!(lines.contains(&format!("~nec did not run command 4 to evil evil: the agent failed: {not_taken}")), "{lines:?}");
    for about in [5, 6, 7] {
        assert!(lines.contains(&format!("~nec did not run command {about} to evil evil: the agent refused it: {not_taken}")), "{lines:?}");
    }
    assert!(lines.contains(&"~nec did not run command 8 to evil evil: the agent refused it: no reason given".to_string()), "{lines:?}");
    assert!(lines.contains(&"~nec did not run command 9 to evil evil: the agent refused it: no: m".to_string()), "{lines:?}");
    assert!(lines.contains(&format!("~nec did not run command 10 to evil evil: the agent refused it: {not_taken}")), "{lines:?}");
}

/// A module cannot refuse before its handler is entered: one whose start function calls `refuse`
/// with a fault within the rules, and one whose allocator does, each fail as any module that
/// traps there does, with no fault, whether the command is the owner's or another ship's (whose
/// receipt says FAILED and carries no fault). Nothing else of a guest's runs before its handler.
#[test]
fn a_module_cannot_refuse_before_its_handler_is_entered() {
    let dir = TempDir::new("refuse-early");
    let rt = lone(&dir.0, Config { max_queued_per_deliver: 0, ..fast() }, "~zod");
    let early = || vec![Step::Refuse(fault_bytes("early", "before the handler"))];
    let mut about = 0;
    for (label, place) in [("start", "start"), ("allocator", "alloc")] {
        hand_install(&rt, "~zod", "evil", &[(place, early()), ("handle", vec![Step::Refuse(fault_bytes("late", "in the handler"))])], &offering("evil", vec![]));
        let rejection = rejected(rt.deliver("~zod", "evil", b"go"));
        assert!(matches!(rejection, Rejection::Trap(_)), "{label}: {rejection:?}");
        about += 1;
        let command = PeerMessage { seq: about, from_agent: "rec".into(), agent: "evil".into(), interface: "evil".into(), payload: b"go".to_vec(), receipt: None, reply_most: 0 };
        rt.inner.with_ship("~zod", |ship| ship.accept(&rt.inner, "nec", &[command])).unwrap();
        assert_eq!(rt.run_pending("~zod", 10).unwrap(), 1);
        let owed = rt.inner.with_ship("~zod", |ship| Ok(Receipt::decode(&*lock(&ship.conn).query_row("SELECT payload FROM peer_out WHERE receipt != 0 ORDER BY seq DESC LIMIT 1", [], |r| r.get::<_, Vec<u8>>(0))?).unwrap())).unwrap();
        assert_eq!((owed.about, owed.verdict(), owed.reason.as_str(), owed.fault), (about, Verdict::Failed, "the agent failed", None), "{label}");
    }
    // Each call to `refuse` there was an ordinary failure.
    let taken: Vec<bool> = lock(&rt.inner.refusals).iter().map(|(_, _, _, taken)| *taken).collect();
    assert_eq!(taken, [false; 4]);
}

/// The bound on what `refuse` reads stays sound with replies allowed to be as large as there is:
/// with `max_reply_bytes` at `usize::MAX - 1023`, a short fault is a refusal, not a limit.
#[test]
fn a_refusal_is_read_whatever_replies_may_be() {
    let dir = TempDir::new("refuse-bound");
    let rt = lone(&dir.0, Config { max_reply_bytes: usize::MAX - 1023, ..fast() }, "~zod");
    hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Refuse(fault_bytes("short", "m"))])], &offering("evil", vec![]));
    assert_eq!(rejected(rt.deliver("~zod", "evil", b"go")), Rejection::Refused(fault("short", "m")));
}

/// At the host boundary: a pointer out of the guest's memory is an ordinary failure; a refusal
/// larger than `max_reply_bytes` and 1 KiB, with fuel to spare, is a limit; and one the handler
/// has too little fuel left to pay for is out of fuel. None of them is a refusal.
#[test]
fn a_refusal_the_host_cannot_read_or_be_paid_for_is_not_one() {
    let dir = TempDir::new("refuse-boundary");
    let rt = lone(&dir.0, Config { max_reply_bytes: 100, fuel_per_event: 50_000, ..fast() }, "~zod");
    let manifest = offering("evil", vec![]);
    let outcome = |ptr: u32, len: u32| {
        hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::RefuseAt(ptr, len)])], &manifest);
        rejected(rt.deliver("~zod", "evil", b"go"))
    };
    assert!(matches!(outcome(1 << 30, 8), Rejection::Trap(why) if why.contains("refusal pointer is out of bounds")));
    assert!(matches!(outcome(0, 1125), Rejection::Limit(why) if why.contains("refusal is 1125 bytes, limit is 1124")));
    let poor_dir = TempDir::new("refuse-poor");
    let poor = lone(&poor_dir.0, Config { fuel_per_event: 20_000, ..fast() }, "~zod");
    hand_install(&poor, "~zod", "evil", &[("handle", vec![Step::RefuseAt(0, 100_000)])], &manifest);
    assert_eq!(rejected(poor.deliver("~zod", "evil", b"go")), Rejection::OutOfFuel);
}

/// A kernel whose `route` calls `refuse` fails routing as any kernel that traps does: the command
/// is not routed, and nothing is a refusal.
#[test]
fn a_kernel_cannot_refuse() {
    let dir = TempDir::new("refuse-kernel");
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let kernel = rt.add_module(&hand_agent(&[("route", vec![Step::Refuse(fault_bytes("kernel", "no"))]), ("admin", vec![])])).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    assert!(matches!(rejected(rt.deliver("~zod", "anyone", b"go")), Rejection::Trap(_)));
    let seen = lock(&rt.inner.refusals).clone();
    assert!(!seen.is_empty() && seen.iter().all(|(agent, _, _, taken)| agent == "kernel" && !taken), "{seen:?}");
}

/// A ship with a REFUSED receipt waiting to go to another ship, and one with a REFUSED receipt
/// queued for its agent, each with the largest fault, export and import; and exports changed so
/// that what is stored is not what this runtime could have written or taken are refused.
#[test]
fn refused_receipts_waiting_and_queued_export_and_import_and_broken_ones_are_refused() {
    let code = "test-test-test-test-test-test-test-test";
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("refuse-export");
    let rt = lone(&dir.0, cfg.clone(), "~zod");
    let largest = largest_fault();
    hand_install(&rt, "~zod", "evil", &[("handle", vec![Step::Refuse(largest.encode_to_vec())])], &offering("evil", vec![]));
    hand_install(&rt, "~zod", "rec", &recorder("nec", "evil", "evil", false), &offering("rec", vec![sending_to("nec", "evil", "evil")]));
    // ~nec's command to evil, refused here: its receipt waits to go.
    let command = PeerMessage { seq: 1, from_agent: "rec".into(), agent: "evil".into(), interface: "evil".into(), payload: b"please".to_vec(), receipt: None, reply_most: 0 };
    rt.inner.with_ship("~zod", |ship| ship.accept(&rt.inner, "nec", &[command])).unwrap();
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 1);
    // rec's command to ~nec, refused there: its receipt is queued for rec. (It is message 2 to
    // ~nec, after the receipt waiting to go.)
    rt.deliver("~zod", "rec", b"send").unwrap();
    let receipt = Receipt { about: 2, verdict: Verdict::Refused as i32, reason: "anything".into(), fault: Some(largest.clone()), ..Receipt::default() };
    rt.inner.with_ship("~zod", |ship| ship.accept(&rt.inner, "nec", &[PeerMessage { seq: 2, receipt: Some(receipt), ..PeerMessage::default() }])).unwrap();
    let stored = |rt: &Runtime, sql: &str| -> Receipt {
        rt.inner.with_ship("~zod", |ship| Ok(Receipt::decode(&*lock(&ship.conn).query_row(sql, [], |r| r.get::<_, Vec<u8>>(0))?).unwrap())).unwrap()
    };
    let owed = "SELECT payload FROM peer_out WHERE receipt != 0";
    let queued = "SELECT payload FROM inbox WHERE kind = 5";
    assert_eq!(stored(&rt, owed), Receipt { about: 1, verdict: Verdict::Refused as i32, reason: crate::store::REFUSED_WORDS.into(), fault: Some(largest.clone()), ..Receipt::default() });
    let told = stored(&rt, queued);
    assert_eq!(told.fault, Some(largest.clone()));
    rt.set_recovery_key("~zod", crate::seal::recovery_public(code)).unwrap();
    let out = TempDir::new("refuse-export-copy");
    rt.export_ship("~zod", out.0.join("copy")).unwrap();
    let into = TempDir::new("refuse-export-into");
    let other = Runtime::open(&into.0, cfg.clone()).unwrap();
    other.import_ship(out.0.join("copy"), "~zod", code).unwrap();
    assert_eq!(stored(&other, owed).fault, Some(largest.clone()));
    assert_eq!(stored(&other, queued), told);
    // The receipt queued is handed over in the copy.
    assert_eq!(other.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(recorded(&other, "~zod", "rec", 2).unwrap(), told);

    let refused = |label: &str, change: &dyn Fn(&rusqlite::Connection)| {
        let copy = out.0.join(label);
        copy_export(&out.0.join("copy"), &copy);
        rework(&copy, "~zod", code, change);
        let into = TempDir::new(&format!("refuse-export-{label}"));
        let rt = Runtime::open(&into.0, cfg.clone()).unwrap();
        let imported = rt.import_ship(&copy, "~zod", code);
        assert!(matches!(&imported, Err(Error::BadShipFile(_))), "{label}: {imported:?}");
    };
    let change = |sql: &'static str, edit: fn(&mut Receipt)| {
        move |file: &rusqlite::Connection| {
            let bytes: Vec<u8> = file.query_row(sql, [], |r| r.get(0)).unwrap();
            let mut receipt = Receipt::decode(&*bytes).unwrap();
            edit(&mut receipt);
            let (table, which) = if sql.contains("peer_out") { ("peer_out", "receipt != 0") } else { ("inbox", "kind = 5") };
            file.execute(&format!("UPDATE {table} SET payload = ?1 WHERE {which}"), [receipt.encode_to_vec()]).unwrap();
        }
    };
    // Waiting to go: a fault with another verdict; REFUSED with none; a fault breaking the rules;
    // other words beside it.
    refused("owed-failed", &change(owed, |r| r.verdict = Verdict::Failed as i32));
    refused("owed-faultless", &change(owed, |r| r.fault = None));
    refused("owed-spaced", &change(owed, |r| r.fault.as_mut().unwrap().code = "a b".into()));
    refused("owed-words", &change(owed, |r| r.reason = "the agent failed".into()));
    // Queued for the agent: a fault with RAN; a message over the bound; a control character;
    // other words beside it; a code too long.
    refused("queued-ran", &change(queued, |r| r.verdict = Verdict::Ran as i32));
    refused("queued-long", &change(queued, |r| r.fault.as_mut().unwrap().message.push('m')));
    refused("queued-control", &change(queued, |r| r.fault.as_mut().unwrap().message = "a\nb".into()));
    refused("queued-words", &change(queued, |r| r.reason = "anything".into()));
    refused("queued-code", &change(queued, |r| r.fault.as_mut().unwrap().code.push('!')));
    // Either, as it is but with a field this runtime does not know added: a receipt with a fault
    // is taken only as the bytes this runtime writes.
    let padded = |sql: &'static str| {
        move |file: &rusqlite::Connection| {
            let mut bytes: Vec<u8> = file.query_row(sql, [], |r| r.get(0)).unwrap();
            bytes.extend_from_slice(&[0x7a, 0x03, b'p', b'a', b'd']);
            assert!(Receipt::decode(&*bytes).is_ok());
            let (table, which) = if sql.contains("peer_out") { ("peer_out", "receipt != 0") } else { ("inbox", "kind = 5") };
            file.execute(&format!("UPDATE {table} SET payload = ?1 WHERE {which}"), [bytes]).unwrap();
        }
    };
    refused("owed-padded", &padded(owed));
    refused("queued-padded", &padded(queued));
}

/// A ship whose events are small (64 bytes) imports its own export holding a receipt queued for
/// its agent with the largest fault and the largest names (561 bytes for command 1, over
/// `MAX_RECEIPT_BYTES` and inside its allowance), and again once the receipt has been handled and the audit log
/// holds the lines about it, each cut to `MAX_RECEIPT_BYTES` (the bound import holds an audit
/// row to is the larger of that and `max_event_bytes`).
#[test]
fn a_ship_with_small_events_imports_its_own_export_holding_the_largest_fault() {
    let code = "test-test-test-test-test-test-test-test";
    let cfg = Config { max_event_bytes: 64, max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("refuse-small");
    let rt = lone(&dir.0, cfg.clone(), "~zod");
    let (ship, agent, interface) = ("a".repeat(64), "b".repeat(64), "c".repeat(128));
    hand_install(&rt, "~zod", "rec", &recorder(&ship, &agent, &interface, false), &offering("rec", vec![sending_to(&ship, &agent, &interface)]));
    rt.deliver("~zod", "rec", b"send").unwrap();
    let receipt = Receipt { about: 1, verdict: Verdict::Refused as i32, reason: "r".repeat(200), fault: Some(largest_fault()), ..Receipt::default() };
    rt.inner.with_ship("~zod", |held| held.accept(&rt.inner, &ship, &[PeerMessage { seq: 1, receipt: Some(receipt), ..PeerMessage::default() }])).unwrap();
    let told: Vec<u8> = rt.inner.with_ship("~zod", |held| Ok(lock(&held.conn).query_row("SELECT payload FROM inbox WHERE kind = 5", [], |r| r.get(0))?)).unwrap();
    // 569 bytes with the largest command number; this one is number 1, eight bytes fewer.
    assert_eq!(told.len(), 561);
    rt.set_recovery_key("~zod", crate::seal::recovery_public(code)).unwrap();
    let out = TempDir::new("refuse-small-copy");
    rt.export_ship("~zod", out.0.join("queued")).unwrap();
    let first = TempDir::new("refuse-small-first");
    let other = Runtime::open(&first.0, cfg.clone()).unwrap();
    other.import_ship(out.0.join("queued"), "~zod", code).unwrap();
    assert_eq!(other.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(recorded(&other, "~zod", "rec", 1).unwrap().encode_to_vec(), told);
    // The audit log now holds the line about the receipt (cut to 512 bytes, from more) and the
    // facts of the receipt event: each over `max_event_bytes`, none over `MAX_RECEIPT_BYTES`.
    let rows = other.audit("~zod", 100).unwrap();
    let line = rows.iter().find(|entry| entry.event.starts_with(format!("~{ship} did not run command 1").as_bytes())).expect("the line about the receipt");
    assert_eq!(line.event.len(), crate::store::MAX_RECEIPT_BYTES);
    assert!(rows.iter().any(|entry| entry.event.starts_with(b"receipt 1 the agent refused it") && entry.event.len() > 64));
    assert!(rows.iter().all(|entry| entry.event.len() <= crate::store::MAX_RECEIPT_BYTES));
    other.set_recovery_key("~zod", crate::seal::recovery_public(code)).unwrap();
    other.export_ship("~zod", out.0.join("handled")).unwrap();
    let second = TempDir::new("refuse-small-second");
    let again = Runtime::open(&second.0, cfg).unwrap();
    again.import_ship(out.0.join("handled"), "~zod", code).unwrap();
    assert_eq!(recorded(&again, "~zod", "rec", 1).unwrap().encode_to_vec(), told);
}

/// Two ships that have filled up with commands for each other, every one refused there with the
/// largest fault, still get everything through, and every command comes back REFUSED: the
/// receipt each writes, the largest fault and all (306 bytes at the most), is inside the room the
/// two keep for receipts (`MAX_RECEIPT_BYTES` each), which a fault does not move.
#[test]
fn two_full_ships_whose_commands_are_refused_with_the_largest_fault_still_get_through() {
    let small = Config { max_ship_bytes: 340 << 10, audit_rows: 32, ..fast() };
    let dirs = (TempDir::new("full-refused-a"), TempDir::new("full-refused-b"));
    let directory = Directory::new();
    let refusing = hand_agent(&[("handle", vec![Step::Refuse(largest_fault().encode_to_vec())])]);
    let crew = |dir: &Path, ship: &str, other: &str| {
        let rt = lone(dir, small.clone(), ship);
        let (counter, tally) = (rt.add_module(&refusing).unwrap(), rt.add_module(&wasm("tally")).unwrap());
        rt.install(ship, "counter", &counter, &counter_with(false, true)).unwrap();
        rt.install(ship, "tally", &tally, &asking_tally(other)).unwrap();
        rt
    };
    let (zod, nec) = (crew(&dirs.0 .0, "~zod", "nec"), crew(&dirs.1 .0, "~nec", "zod"));
    let padding = "p".repeat(2000);
    let fill = |rt: &Runtime, ship: &str, other: &str| {
        let command = format!("tell {other} {padding}");
        let mut sent = 0;
        let stopped = loop {
            match rt.deliver(ship, "tally", command.as_bytes()) {
                Ok(_) => sent += 1,
                Err(e) => break e,
            }
        };
        // It stopped because the file had no more room to send, and for no other reason.
        assert!(matches!(&stopped, Error::Rejected(Rejection::Limit(why)) if why == "this ship's file is too full to send more to other ships"), "{stopped:?}");
        assert!(sent > 5, "only {sent} were sent");
        sent
    };
    let (from_zod, from_nec) = (fill(&zod, "~zod", "nec"), fill(&nec, "~nec", "zod"));
    let zod_net = Network::start(zod.clone(), directory.clone(), NetConfig::default()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("every command answered", Duration::from_secs(90), || {
        zod.unanswered("~zod").unwrap() == 0 && nec.unanswered("~nec").unwrap() == 0 && zod.pending("~zod").unwrap() == 0 && nec.pending("~nec").unwrap() == 0
    });
    for (rt, ship, sent) in [(&zod, "~zod", from_zod), (&nec, "~nec", from_nec)] {
        let got = receipts(rt, ship);
        assert_eq!(got.len(), sent, "{ship}");
        assert!(got.iter().all(|line| line.contains("/counter counter refused [the agent refused it] from ")), "{ship}: {got:?}");
    }
    // And each receipt tally's handler was handed carried the largest fault, whole: the bytes it
    // was given, decoded, one for each command and none twice.
    for (rt, ship, sent) in [(&zod, "zod", from_zod), (&nec, "nec", from_nec)] {
        let handed: Vec<Receipt> = lock(&rt.inner.receipts_handed).iter().filter(|(on, _)| on == ship).map(|(_, bytes)| Receipt::decode(&**bytes).unwrap()).collect();
        let mut numbers: Vec<u64> = handed.iter().map(|receipt| receipt.about).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (1..=sent as u64).collect::<Vec<_>>(), "{ship}");
        for receipt in &handed {
            let fault = receipt.fault.as_ref().unwrap_or_else(|| panic!("{ship}: receipt {} handed on with no fault", receipt.about));
            assert_eq!((fault.code.as_str(), fault.message.as_str()), (largest_fault().code.as_str(), largest_fault().message.as_str()), "{ship}");
        }
    }
    drop((zod_net, nec_net));
}
