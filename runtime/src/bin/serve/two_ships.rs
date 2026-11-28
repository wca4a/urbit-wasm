//! `serve --two-ships <dir>`: a lookup point and two ships, each a program of its own started
//! from this same binary with ordinary flags, and this program acting as each owner's device
//! over HTTP, the way an app would. It shows the two ships finding each other by name, trading
//! messages, one opening a file the other holds once it is allowed to, opening it again with the
//! other ship off, and the two finding each other again after that ship comes back at a new
//! address. Then two steps more with the guestbook, a typed agent: its owner's device calls it
//! with JSON, and it puts a typed question to the guestbook on the other ship. In each, a command
//! is turned down on purpose, and its reason comes back: at the JSON door, and on a receipt from
//! the other ship.
//!
//! Everything it prints is for someone who is not a developer. The words it reads back from
//! the programs it starts are in `said`, beside the code in `serve` that prints them.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runtime::files::CHUNK;
use runtime::{pretend, Config, Error, Manifest, Provide, Runtime, Use};
use sha2::{Digest, Sha256};
use ship_proto::Message;

use crate::said;

/// The two ships. Valid names of planets, and plainly examples: `~sampel-palnet` is the name
/// Urbit's own documents use for one.
const FIRST: &str = "~sampel-palnet";
const SECOND: &str = "~norsyr-torryn";

/// How long any one thing is waited for before the step is said not to have worked. Generous,
/// since the tests run this while much else is running.
const LIMIT: Duration = Duration::from_secs(60);

/// What the demo's own devices are called in each ship's list of devices, so that a later run
/// can sign out the ones an earlier run left.
const DEVICE_LABEL: &str = "two-ships walk-through";

/// How many steps the walk-through has, before the guestbook's.
const STEPS: usize = 8;

/// How many steps with the guestbook come after those, numbered on their own so that the steps
/// before them read as they always have.
const GUESTBOOK_STEPS: usize = 2;

/// How many lines each program's output keeps, to show when a step fails.
const KEPT_LINES: usize = 2000;

/// How much of one line a program prints is kept; the rest of a longer line is dropped.
const LONGEST_LINE: usize = 4096;

/// What `serve --two-ships` was asked to do.
pub struct Options {
    pub dir: PathBuf,
    pub kernel: PathBuf,
    pub counter: PathBuf,
    pub tally: PathBuf,
    /// The guestbook, a typed agent: by default beside the tally module.
    pub guestbook: PathBuf,
    pub then_stop: bool,
    pub show_output: bool,
    pub ports: Option<u16>,
    pub file: Option<PathBuf>,
    /// Given to the three programs as `--sleep-after`, if given here.
    pub sleep_after: Option<u64>,
}

/// Set when Ctrl-C (or a request to stop) arrives.
static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

/// Why the walk-through stopped short: a step that did not work, or Ctrl-C.
enum Stop {
    Failed(String),
    Interrupted,
}

type Done<T> = Result<T, Stop>;

fn failed<T>(why: impl Into<String>) -> Done<T> {
    Err(Stop::Failed(why.into()))
}

/// A program's output: the lines it has printed, each numbered, the most recent kept.
#[derive(Default)]
struct Output {
    lines: VecDeque<(u64, String)>,
    next: u64,
}

/// One of the three programs: how it is started, and the process while it runs.
struct Program {
    label: String,
    args: Vec<String>,
    child: Option<Child>,
    output: Arc<Mutex<Output>>,
}

impl Program {
    fn new(label: &str, args: Vec<String>) -> Program {
        Program { label: label.into(), args, child: None, output: Arc::default() }
    }

    /// The command line, as it could be typed into a shell.
    fn command(&self, exe: &Path) -> String {
        std::iter::once(exe.display().to_string()).chain(self.args.iter().cloned()).map(|word| quoted(&word)).collect::<Vec<_>>().join(" ")
    }

    /// Start it, and read everything it prints for as long as it runs, so that it never waits
    /// on a full pipe. Each line is kept, and shown at once if asked.
    ///
    /// The child is held here from the moment it exists, before anything else that could fail,
    /// so that whatever happens next it is stopped with the rest. A line longer than
    /// `LONGEST_LINE` is kept cut short. A line shown on a standard output that has been closed
    /// is not shown, and the reading goes on (the parent's own next line to that output fails,
    /// and it stops, stopping the programs).
    fn start(&mut self, exe: &Path, show: bool) -> Done<()> {
        let child = Command::new(exe)
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .or_else(|e| failed(format!("{} could not be started: {e}", self.label)))?;
        let child = self.child.insert(child);
        let streams: Vec<Box<dyn Read + Send>> = [child.stdout.take().map(|out| Box::new(out) as Box<dyn Read + Send>), child.stderr.take().map(|err| Box::new(err) as Box<dyn Read + Send>)].into_iter().flatten().collect();
        for stream in streams {
            let (output, label) = (self.output.clone(), self.label.clone());
            std::thread::Builder::new()
                .name(format!("output of {label}"))
                .spawn(move || read_lines(stream, &label, show, &output))
                .or_else(|e| failed(format!("could not read what {} prints: {e}", self.label)))?;
        }
        Ok(())
    }

    /// The number the next line printed will have.
    fn mark(&self) -> u64 {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).next
    }

    /// Wait for a line printed since `since` that `find` makes something of, for up to the
    /// limit. Fails if the program stops first, or the wait runs out, saying what it waited for.
    fn wait_for<T>(&mut self, since: u64, what: &str, find: impl Fn(&str) -> Option<T>) -> Done<T> {
        self.wait_within(since, what, LIMIT, find)
    }

    /// The same, for up to `limit`.
    fn wait_within<T>(&mut self, since: u64, what: &str, limit: Duration, find: impl Fn(&str) -> Option<T>) -> Done<T> {
        let started = Instant::now();
        loop {
            {
                let output = self.output.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(found) = output.lines.iter().filter(|(number, _)| *number >= since).find_map(|(_, line)| find(line)) {
                    return Ok(found);
                }
            }
            if STOPPING.load(Ordering::SeqCst) {
                return Err(Stop::Interrupted);
            }
            if let Some(status) = self.child.as_mut().and_then(|child| child.try_wait().ok().flatten()) {
                return failed(format!("{} stopped ({status}) before {what}", self.label));
            }
            if started.elapsed() > limit {
                return failed(format!("waited {} seconds for {what}, and it did not happen", limit.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether it has stopped of its own accord, and how.
    fn ended(&mut self) -> Option<std::process::ExitStatus> {
        self.child.as_mut().and_then(|child| child.try_wait().ok().flatten())
    }

    /// Stop it, if it is running, and wait for it to be gone. A failure to stop it, or to see
    /// it gone, is said, not passed over (a program that had already ended is not a failure).
    fn stop(&mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else { return Ok(()) };
        let killed = match child.kill() {
            Err(e) if e.kind() != std::io::ErrorKind::InvalidInput => Err(format!("{} could not be stopped: {e}", self.label)),
            _ => Ok(()),
        };
        let waited = child.wait().map(drop).map_err(|e| format!("{} could not be seen to stop: {e}", self.label));
        killed.and(waited)
    }

    /// The last few lines it printed.
    fn recent(&self, count: usize) -> Vec<String> {
        let output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        output.lines.iter().rev().take(count).rev().map(|(_, line)| line.clone()).collect()
    }
}

/// The three programs, stopped when this goes, however the walk-through ends: done, a step that
/// did not work, Ctrl-C, or a panic.
struct Programs {
    exe: PathBuf,
    show: bool,
    point: Program,
    first: Program,
    second: Program,
}

impl Drop for Programs {
    fn drop(&mut self) {
        for program in [&mut self.point, &mut self.first, &mut self.second] {
            if let Err(why) = program.stop() {
                eprintln!("{why}");
            }
        }
    }
}

/// Read the lines a program prints until it closes its end, keeping each (cut to
/// `LONGEST_LINE`), and showing each if asked.
fn read_lines(stream: Box<dyn Read + Send>, label: &str, show: bool, output: &Mutex<Output>) {
    use std::io::Write;
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        // At most a line's worth taken at a time; the rest of a longer line is read and dropped.
        match (&mut reader).take(LONGEST_LINE as u64).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if !line.ends_with(b"\n") {
            let mut rest = Vec::new();
            loop {
                rest.clear();
                match (&mut reader).take(LONGEST_LINE as u64).read_until(b'\n', &mut rest) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if rest.ends_with(b"\n") => break,
                    Ok(_) => {}
                }
            }
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if show {
            let _ = writeln!(std::io::stdout(), "    [{label}] {text}");
        }
        let mut output = output.lock().unwrap_or_else(|e| e.into_inner());
        let number = output.next;
        output.next += 1;
        output.lines.push_back((number, text));
        if output.lines.len() > KEPT_LINES {
            output.lines.pop_front();
        }
    }
}

/// A word as it would be typed into a shell: as it is if nothing in it means anything to a
/// shell, and otherwise in single quotes.
fn quoted(word: &str) -> String {
    let plain = !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:=,@%+".contains(&b));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

fn bare(ship: &str) -> &str {
    ship.trim_start_matches('~')
}

fn seconds(took: Duration) -> String {
    if took < Duration::from_millis(100) {
        return "less than a tenth of a second".into();
    }
    format!("{:.1} seconds", took.as_secs_f64())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes written the way people read them: 3,158,325.
fn grouped(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// The owner's device for one ship: signed in to it over HTTP, as an app is.
struct Device {
    agent: ureq::Agent,
    ship: &'static str,
    base: String,
    token: String,
    /// When the step under way must be done by. Reading each answer (its headers and its body,
    /// a streamed body and an error's body included) is given at most what is left of it.
    /// Connecting and the writes of a request are not bounded that way (see `agent` and
    /// `limit`): connecting can take a step past its time by up to 5 seconds, and a request
    /// that keeps writing slowly can go on past it, since every write has the same limit, set
    /// once.
    until: std::cell::Cell<Instant>,
}

/// What came of asking for a file on the other ship.
enum Opened {
    /// The whole file: its length and SHA-256.
    Got(u64, [u8; 32]),
    /// Any other answer: its status and words.
    Answer(u16, String),
}

impl Device {
    /// The HTTP client. Connecting has a fixed limit of 5 seconds. No connection is kept for a
    /// later request: in ureq 2.12.1 a connection taken back from its pool has no write limit at
    /// all (its timeouts are cleared when it is returned, `stream.rs` 261 to 267, and not set
    /// again when it is reused, `unit.rs` 355 to 365), while a new one has each write limited
    /// by what was left of the request's own limit when it connected (`stream.rs` 438 to 442).
    /// Every request here has a limit of its own (`limit`), so the agent's own read and write
    /// limits would never be used, and none are set.
    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(5)).max_idle_connections(0).build()
    }

    /// Sign in to the ship at `addr` with its access code, as its owner would.
    fn sign_in(ship: &'static str, addr: SocketAddr, code: &str) -> Done<Device> {
        let base = format!("http://{addr}/ships/{}", bare(ship));
        let mut device = Device { agent: Device::agent(), ship, base, token: String::new(), until: std::cell::Cell::new(Instant::now() + LIMIT) };
        let asked = ship_proto::SignInRequest { code: code.into(), label: DEVICE_LABEL.into() }.encode_to_vec();
        let request = device.limit(device.agent.post(&format!("{}/signin", device.base)))?;
        let body = device.done(request.set("Content-Type", "application/x-protobuf").send_bytes(&asked), |why| format!("{ship} would not let its owner sign in: {why}"))?;
        let reply = ship_proto::SignInReply::decode(&*body).or_else(|_| failed(format!("{ship} answered the sign-in with something that is not a sign-in reply")))?;
        device.token = reply.token;
        Ok(device)
    }

    /// Have the requests from now on done by `deadline`.
    fn until(&self, deadline: Instant) {
        self.until.set(deadline);
    }

    /// A request, if Ctrl-C has not come and there is time left for it, with what is left as
    /// its limit (`Request::timeout`). In ureq 2.12.1 that limit bounds reading the answer,
    /// looked at again before each read. Connecting has its own fixed 5 seconds; each write of
    /// the request is limited by what was left when it connected, set once and not shortened
    /// between writes. So a step can run over: by up to 5 seconds connecting, and by the
    /// writes of a request that keeps going slowly. The other end is always one of this
    /// walk-through's own programs, on this machine.
    fn limit(&self, request: ureq::Request) -> Done<ureq::Request> {
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        let left = self.until.get().saturating_duration_since(Instant::now());
        if left.is_zero() {
            return failed(format!("there was no time left to ask {}", self.ship));
        }
        Ok(request.timeout(left))
    }

    /// The body of an answer to a request made through `limit`, read under the same limit, or
    /// what went wrong, put in words by `said`. Ctrl-C is looked at again once the request is
    /// over: if it has come, that is the stop it is (the ships are stopped by it too, which is
    /// most likely why the request went wrong), and nothing else is said.
    fn done(&self, answer: Result<ureq::Response, ureq::Error>, said: impl FnOnce(String) -> String) -> Done<Vec<u8>> {
        let body = body_of(answer);
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        body.map_err(|why| Stop::Failed(said(why)))
    }

    /// The same device, at the address the ship is served at now.
    fn moved_to(&mut self, addr: SocketAddr) {
        self.base = format!("http://{addr}/ships/{}", bare(self.ship));
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get(&self, path: &str) -> Done<Result<ureq::Response, ureq::Error>> {
        Ok(self.limit(self.agent.get(&format!("{}{path}", self.base)))?.set("Authorization", &self.auth()).call())
    }

    /// Give one of the ship's agents a command, as the owner, and return its answer.
    fn command(&self, agent: &str, text: &str) -> Done<String> {
        let answer = self.limit(self.agent.post(&format!("{}/agents/{agent}/command", self.base)))?.set("Authorization", &self.auth()).send_bytes(text.as_bytes());
        let body = self.done(answer, |why| format!("{} did not take the command \"{text}\": {why}", self.ship))?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Where one of the ship's logs ends now.
    fn head(&self, agent: &str, log: &str) -> Done<u64> {
        let body = self.done(self.get(&format!("/logs/{agent}/{log}/head"))?, |why| format!("{}'s {log} could not be read: {why}", self.ship))?;
        Ok(ship_proto::LogHead::decode(&*body).map(|head| head.seq).unwrap_or(0))
    }

    /// The entries of a log after `after`, waiting up to `wait` seconds for some.
    fn entries(&self, agent: &str, log: &str, after: u64, wait: u64) -> Done<Vec<(u64, Vec<u8>)>> {
        let body = self.done(self.get(&format!("/logs/{agent}/{log}/entries?after={after}&wait={wait}"))?, |why| format!("{}'s {log} could not be read: {why}", self.ship))?;
        let list = ship_proto::EntryList::decode(&*body).or_else(|_| failed(format!("{} answered with something that is not a list of entries", self.ship)))?;
        let mut found = Vec::new();
        for signed in list.entries {
            let entry = ship_proto::EntryBody::decode(&*signed.body).or_else(|_| failed(format!("{} sent an entry that cannot be read", self.ship)))?;
            found.push((entry.seq, entry.payload));
        }
        Ok(found)
    }

    /// Put a file on the ship for one of its agents, a chunk at a time, from `source`, which
    /// holds `length` bytes. Returns the file's id and the SHA-256 of what was sent.
    fn upload(&self, agent: &str, source: &mut dyn Read, length: u64, deadline: Instant) -> Done<([u8; 32], [u8; 32])> {
        self.until(deadline);
        let base = format!("{}/agents/{agent}/files/uploads", self.base);
        let asked = ship_proto::UploadRequest { length, media_type: "application/octet-stream".into() }.encode_to_vec();
        let body = self.done(self.limit(self.agent.post(&base))?.set("Authorization", &self.auth()).send_bytes(&asked), |why| format!("{} would not take a file of {} bytes: {why}", self.ship, grouped(length)))?;
        let upload = ship_proto::UploadReply::decode(&*body).or_else(|_| failed(format!("{} answered with something that is not an upload", self.ship)))?.upload;
        let mut hash = Sha256::new();
        let mut chunk = vec![0u8; CHUNK as usize];
        let mut sent = 0u64;
        let mut n = 0u64;
        while sent < length {
            between(deadline, "the file to be put on the ship")?;
            let size = (length - sent).min(CHUNK) as usize;
            source.read_exact(&mut chunk[..size]).or_else(|e| failed(format!("the file to share could not be read: {e}")))?;
            hash.update(&chunk[..size]);
            let answer = self.limit(self.agent.put(&format!("{base}/{upload}/{n}")))?.set("Authorization", &self.auth()).send_bytes(&chunk[..size]);
            self.done(answer, |why| format!("{} did not take part {n} of the file: {why}", self.ship))?;
            sent += size as u64;
            n += 1;
        }
        let finish = ship_proto::FinishRequest { id: Vec::new() }.encode_to_vec();
        between(deadline, "the file to be put on the ship")?;
        let body = self.done(self.limit(self.agent.post(&format!("{base}/{upload}/finish")))?.set("Authorization", &self.auth()).send_bytes(&finish), |why| format!("{} did not finish taking the file: {why}", self.ship))?;
        let info = ship_proto::FileInfo::decode(&*body).or_else(|_| failed(format!("{} answered with something that does not describe a file", self.ship)))?;
        let id = <[u8; 32]>::try_from(info.id.as_slice()).or_else(|_| failed(format!("{} gave the file an id that is not one", self.ship)))?;
        Ok((id, hash.finalize().into()))
    }

    /// Open, through this ship, a file the other ship's agent holds, and read all of it.
    fn open_from(&self, other: &str, agent: &str, id: &[u8; 32], deadline: Instant) -> Done<Opened> {
        self.until(deadline);
        match self.get(&format!("/files/from/{}/{agent}/{}/content", bare(other), hex(id)))? {
            Ok(answer) => {
                let mut reader = answer.into_reader();
                let (mut hash, mut length, mut buffer) = (Sha256::new(), 0u64, vec![0u8; 64 << 10]);
                loop {
                    between(deadline, "the file to be opened")?;
                    // A read gone wrong with Ctrl-C already in is the stop (it stops the ship
                    // being read from too), as in `done`.
                    let read = reader.read(&mut buffer).or_else(|e| if STOPPING.load(Ordering::SeqCst) { Err(Stop::Interrupted) } else { failed(format!("the file stopped part way, after {} bytes: {e}", grouped(length))) })?;
                    if read == 0 {
                        break;
                    }
                    hash.update(&buffer[..read]);
                    length += read as u64;
                }
                // Looked at once more now that the whole of it is read, as `done` does.
                if STOPPING.load(Ordering::SeqCst) {
                    return Err(Stop::Interrupted);
                }
                Ok(Opened::Got(length, hash.finalize().into()))
            }
            Err(ureq::Error::Status(status, answer)) => {
                let words = answer.into_string().unwrap_or_default();
                between(deadline, "the file to be opened")?;
                Ok(Opened::Answer(status, words))
            }
            Err(e) => {
                between(deadline, "the file to be opened")?;
                failed(format!("{} could not be asked for the file: {e}", self.ship))
            }
        }
    }

    /// Through this ship, ask an agent on the other ship a question, as its owner: the answer's
    /// status and its words (the reply itself, for 200). Ctrl-C is looked at before and after,
    /// as for every request.
    fn ask(&self, other: &str, agent: &str, interface: &str, payload: &str) -> Done<(u16, String)> {
        let request = self.limit(self.agent.post(&format!("{}/ask/{}/{agent}/{interface}?within=10", self.base, bare(other))))?;
        let answer = request.set("Authorization", &self.auth()).send_bytes(payload.as_bytes());
        let said = match answer {
            Ok(answer) => {
                let mut body = Vec::new();
                answer.into_reader().take(1 << 20).read_to_end(&mut body).map(|_| (200, String::from_utf8_lossy(&body).into_owned())).map_err(|e| e.to_string())
            }
            Err(ureq::Error::Status(status, answer)) => Ok((status, answer.into_string().unwrap_or_default())),
            Err(e) => Err(e.to_string()),
        };
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        said.or_else(|why| failed(format!("{} could not be asked to put the question: {why}", self.ship)))
    }

    /// Call a method of one of the ship's typed agents through its JSON door, as the owner, with
    /// `json` as the body: the answer's status, its media type as it said it, and its words.
    fn call_json(&self, agent: &str, interface: &str, method: &str, json: &str) -> Done<(u16, String, String)> {
        let request = self.limit(self.agent.post(&format!("{}/agents/{agent}/api/{interface}/{method}", self.base)))?;
        let answer = request.set("Authorization", &self.auth()).set("Content-Type", "application/json").send_bytes(json.as_bytes());
        let said = match answer {
            Ok(answer) => {
                let (status, kind) = (answer.status(), answer.header("Content-Type").unwrap_or_default().to_string());
                let mut body = Vec::new();
                answer.into_reader().take(1 << 20).read_to_end(&mut body).map(|_| (status, kind, String::from_utf8_lossy(&body).into_owned())).map_err(|e| e.to_string())
            }
            Err(ureq::Error::Status(status, answer)) => {
                let kind = answer.header("Content-Type").unwrap_or_default().to_string();
                Ok((status, kind, answer.into_string().unwrap_or_default()))
            }
            Err(e) => Err(e.to_string()),
        };
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        said.or_else(|why| failed(format!("{}'s {agent} could not be called: {why}", self.ship)))
    }

    /// The same, saying what was sent and what came back, and failing unless it was answered
    /// with `status` and a fault as JSON with `code`, as the door answers a refused command.
    fn show_fault(&self, agent: &str, interface: &str, method: &str, json: &str, status: u16, code: &str) -> Done<serde_json::Value> {
        println!("  Sent to {} as POST /agents/{agent}/api/{interface}/{method}:", self.ship);
        println!("    {json}");
        let (got, kind, words) = self.call_json(agent, interface, method, json)?;
        let value: serde_json::Value = serde_json::from_str(&words).unwrap_or_default();
        if got != status || kind != "application/json" || value["code"].as_str() != Some(code) {
            return failed(format!("{}'s {agent} was expected to refuse {method} with {status} and the code {code}, and answered {got} ({kind}), {}", self.ship, words.trim()));
        }
        println!("  Its answer ({got}, {kind}):");
        println!("    {words}");
        Ok(value)
    }

    /// How many signatures the guestbook `agent` holds, by asking it (a question, which keeps
    /// nothing).
    fn signatures(&self, agent: &str) -> Done<u64> {
        let (status, kind, words) = self.call_json(agent, "guestbook", "Lookup", r#"{"prefix": "", "limit": 0}"#)?;
        let total = serde_json::from_str::<serde_json::Value>(&words).ok().and_then(|page| page["total"].as_str().and_then(|total| total.parse::<u64>().ok()));
        match (status, kind.as_str(), total) {
            (200, "application/json", Some(total)) => Ok(total),
            _ => failed(format!("{}'s {agent} would not say how many signatures it holds: it answered {status} ({kind}), {}", self.ship, words.trim())),
        }
    }

    /// The same, saying what was sent and what came back, and failing unless it was answered
    /// 200 with JSON, as the door answers a reply.
    fn show_json(&self, agent: &str, interface: &str, method: &str, json: &str) -> Done<serde_json::Value> {
        println!("  Sent to {} as POST /agents/{agent}/api/{interface}/{method}:", self.ship);
        println!("    {json}");
        let (status, kind, words) = self.call_json(agent, interface, method, json)?;
        if status != 200 || kind != "application/json" {
            return failed(format!("{}'s {agent} answered {method} with {status} ({kind}), {}", self.ship, words.trim()));
        }
        let value = serde_json::from_str(&words).or_else(|e| failed(format!("{}'s {agent} answered {method} with something that is not JSON: {e}", self.ship)))?;
        println!("  Its answer ({status}, {kind}):");
        println!("    {words}");
        Ok(value)
    }

    /// Sign this device out, so that runs do not pile up devices on the ship. Ctrl-C is looked
    /// at before (by `limit`) and not after: its answer is not used, it is the last request made
    /// with this device, and nothing that follows it would be skipped for a stop.
    fn sign_out(&self) {
        self.until(Instant::now() + LIMIT);
        if let Ok(request) = self.limit(self.agent.post(&format!("{}/signout", self.base))) {
            let _ = request.set("Authorization", &self.auth()).send_bytes(b"");
        }
    }
}

/// Between two pieces of moving a file: stopped if Ctrl-C has come, and failed if the step's
/// overall time is up. (Reading a piece is bounded by what is left of the step; for sending
/// one, see `Device::limit`.)
fn between(deadline: Instant, what: &str) -> Done<()> {
    if STOPPING.load(Ordering::SeqCst) {
        return Err(Stop::Interrupted);
    }
    if Instant::now() > deadline {
        return failed(format!("{what} took longer than it was given"));
    }
    Ok(())
}

/// The time a step that moves `length` bytes of a file is given: the usual minute, and two
/// seconds more for each MiB.
fn moving(length: u64) -> Instant {
    Instant::now() + LIMIT + Duration::from_secs(2 * length.div_ceil(1 << 20))
}

/// The body of a successful answer, or what went wrong.
fn body_of(answer: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, String> {
    match answer {
        Ok(answer) => {
            let mut body = Vec::new();
            answer.into_reader().take(16 << 20).read_to_end(&mut body).map_err(|e| e.to_string())?;
            Ok(body)
        }
        Err(ureq::Error::Status(status, answer)) => Err(format!("it answered {status}, {}", answer.into_string().unwrap_or_default().trim())),
        Err(e) => Err(e.to_string()),
    }
}

/// A made-up file of a few MiB, different every run, so that what one run shared and kept does
/// not stand in for the next.
struct MadeUp {
    state: u64,
    left: u64,
}

impl Read for MadeUp {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = buffer.len().min(self.left as usize);
        for byte in &mut buffer[..count] {
            // xorshift64: not random enough for anything but filling a file.
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            *byte = self.state as u8;
        }
        self.left -= count as u64;
        Ok(count)
    }
}

/// The counter agent: its `counter` interface open to other ships' commands and questions, its
/// journal (open to neither), and leave to send commands to the counter on `other`. Only what
/// the walk-through needs.
fn counter_manifest(other: &str) -> Manifest {
    Manifest {
        provides: vec![Provide { interface: "counter".into(), public: false, remote: true, asked: true }, Provide { interface: "journal".into(), public: false, remote: false, asked: false }],
        uses: vec![Use { ship: bare(other).into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true, ask: false }],
    }
}

/// The tally agent, with leave to send commands to the counter on `other`.
fn tally_manifest(other: &str) -> Manifest {
    Manifest {
        provides: vec![Provide { interface: "tally".into(), public: false, remote: false, asked: false }],
        uses: vec![Use { ship: bare(other).into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true, ask: false }],
    }
}

/// The guestbook agent, as `book`: its two interfaces, `guestbook` open to other ships'
/// commands and questions, and leave to send to and ask the guestbook on `other`.
fn book_manifest(other: &str) -> Manifest {
    Manifest {
        provides: vec![Provide { interface: "guestbook".into(), public: false, remote: true, asked: true }, Provide { interface: "visits".into(), public: false, remote: false, asked: false }],
        uses: vec![Use { ship: bare(other).into(), agent: "book".into(), interface: "guestbook".into(), read: false, send: true, ask: true }],
    }
}

/// Make a ship in its own data directory, or find the one an earlier run made, and make sure it
/// has the counter and tally agents with the manifests above. Returns its key and a new access
/// code. The runtime is closed again before this returns, since a data directory is opened by
/// one runtime at a time and the ship's own program comes next.
fn prepare(dir: &Path, ship: &str, other: &str, modules: &[Vec<u8>; 3]) -> Result<([u8; 32], String, bool), String> {
    let runtime = Runtime::open(dir, Config::default()).map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
    let [kernel, counter, tally] = modules;
    let kernel = runtime.add_module(kernel).map_err(|e| format!("the kernel module does not load: {e}"))?;
    let counter = runtime.add_module(counter).map_err(|e| format!("the counter module does not load: {e}"))?;
    let tally = runtime.add_module(tally).map_err(|e| format!("the tally module does not load: {e}"))?;
    let made = match runtime.create_ship(ship, &kernel) {
        Ok(()) => true,
        Err(Error::ShipExists(_)) => false,
        Err(e) => return Err(format!("cannot make {ship}: {e}")),
    };
    runtime.install(ship, "counter", &counter, &counter_manifest(other)).map_err(|e| format!("cannot install the counter agent on {ship}: {e}"))?;
    runtime.install(ship, "tally", &tally, &tally_manifest(other)).map_err(|e| format!("cannot install the tally agent on {ship}: {e}"))?;
    // Devices an earlier run of this walk-through left signed in.
    for device in runtime.devices(ship).map_err(|e| format!("cannot list {ship}'s devices: {e}"))? {
        if device.label == DEVICE_LABEL {
            runtime.revoke_device(ship, device.id).map_err(|e| format!("cannot sign out an earlier run's device on {ship}: {e}"))?;
        }
    }
    let key = runtime.public_key(ship).map_err(|e| format!("cannot read {ship}'s key: {e}"))?;
    let code = runtime.set_access_code(ship).map_err(|e| format!("cannot give {ship} an access code: {e}"))?;
    Ok((key, code, made))
}

/// Give a ship made by `prepare` the guestbook agent too, as `book`, before its program starts.
/// The runtime is closed again before this returns, as there.
fn give_guestbook(dir: &Path, ship: &str, other: &str, module: &[u8]) -> Result<(), String> {
    let runtime = Runtime::open(dir, Config::default()).map_err(|e| format!("cannot open {}: {e}", dir.display()))?;
    let guestbook = runtime.add_module(module).map_err(|e| format!("the guestbook module does not load: {e}"))?;
    runtime.install(ship, "book", &guestbook, &book_manifest(other)).map_err(|e| format!("cannot install the guestbook agent on {ship}: {e}"))
}

/// Run the walk-through. Returns the exit code: 0 when every step worked, 1 when one did not,
/// 130 when stopped by Ctrl-C part way.
pub fn run(options: Options) -> i32 {
    unsafe {
        libc::signal(libc::SIGINT, on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
    let mut step = 0;
    // Declared first, so that it is let go of last: the directory stays this run's until its
    // programs have been stopped.
    let mut lock: Option<fs::File> = None;
    let mut programs: Option<Programs> = None;
    let outcome = walk(&options, &mut step, &mut lock, &mut programs);
    match outcome {
        Ok(()) => 0,
        Err(stop) => {
            // Said, and the exit code chosen, from what stopped the walk: a stop noticed is
            // reported as one, a failure keeps its words, and a Ctrl-C that comes after a
            // failure changes neither.
            let code = match stop {
                Stop::Failed(_) => 1,
                Stop::Interrupted => 130,
            };
            // The guestbook's steps are numbered on their own, after the others.
            let which = if step > STEPS { format!("guestbook step {} of {GUESTBOOK_STEPS}", step - STEPS) } else { format!("step {step} of {STEPS}") };
            match stop {
                Stop::Failed(why) => {
                    println!();
                    println!("{} did not work: {why}.", capitalised(&which));
                }
                Stop::Interrupted => {
                    println!();
                    println!("Stopped part way through {which}, as asked.");
                }
            }
            if let Some(programs) = &programs {
                for program in [&programs.point, &programs.first, &programs.second] {
                    let recent = program.recent(25);
                    if recent.is_empty() {
                        continue;
                    }
                    println!("What {} said last:", program.label);
                    for line in recent {
                        println!("    [{}] {line}", program.label);
                    }
                }
                println!("Stopping the lookup point and both ships.");
            }
            drop(programs);
            code
        }
    }
}

fn begin(step: &mut usize, what: &str) {
    *step += 1;
    println!();
    if *step > STEPS {
        println!("Guestbook step {} of {GUESTBOOK_STEPS}: {what}", *step - STEPS);
    } else {
        println!("Step {step} of {STEPS}: {what}");
    }
}

fn capitalised(words: &str) -> String {
    let mut chars = words.chars();
    chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// The file in a walk-through's directory that says it is one: a directory that holds other
/// things and not this is refused.
const MARKER: &str = ".two-ships";

/// The file a run holds a lock on for as long as it runs, so that two runs never share one
/// directory.
const LOCK: &str = ".two-ships.lock";

/// Make the walk-through's directory, or check one that is there is a walk-through's, and take
/// it for this run. Returns the directory, as an absolute path, and the open lock file.
fn take_directory(given: &Path) -> Done<(PathBuf, fs::File)> {
    use std::os::unix::io::AsRawFd;
    // The programs' lines are read back one line at a time, and a path holding a line break
    // would break them.
    if given.to_string_lossy().contains(['\n', '\r']) {
        return failed("the directory's name has a line break in it; give one without");
    }
    fs::create_dir_all(given).or_else(|e| failed(format!("cannot make {}: {e}", given.display())))?;
    let dir = fs::canonicalize(given).or_else(|e| failed(format!("cannot find {}: {e}", given.display())))?;
    if dir.to_string_lossy().contains(['\n', '\r']) {
        return failed("the directory's name has a line break in it; give one without");
    }
    let names = || -> Done<Vec<String>> {
        let entries = fs::read_dir(&dir).or_else(|e| failed(format!("cannot read {}: {e}", dir.display())))?;
        Ok(entries.flatten().map(|entry| entry.file_name().to_string_lossy().into_owned()).collect())
    };
    let foreign = |names: &[String]| !names.iter().any(|name| name == MARKER) && names.iter().any(|name| name != LOCK);
    if foreign(&names()?) {
        return failed(format!("{} is not a directory --two-ships made; give it an empty or new one", dir.display()));
    }
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LOCK))
        .or_else(|e| failed(format!("cannot open {}: {e}", dir.join(LOCK).display())))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return failed(format!("another run of --two-ships is using {}; wait for it to end, or give another directory", dir.display()));
    }
    // Looked at again with the lock held: a run that took the directory meanwhile has left its
    // marker, and anything else that appeared is still refused.
    if foreign(&names()?) {
        return failed(format!("{} is not a directory --two-ships made; give it an empty or new one", dir.display()));
    }
    match fs::OpenOptions::new().write(true).create_new(true).open(dir.join(MARKER)) {
        Ok(mut marker) => {
            use std::io::Write;
            marker.write_all(b"This directory is used by serve --two-ships.\n").or_else(|e| failed(format!("cannot write {}: {e}", dir.join(MARKER).display())))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return failed(format!("cannot write {}: {e}", dir.join(MARKER).display())),
    }
    Ok((dir, lock))
}

/// Open a file named on the command line for reading: a regular file (a link to one is
/// followed), never a pipe or a device, and not empty. Returns it and its length.
fn regular(path: &Path, what: &str) -> Done<(fs::File, u64)> {
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path).or_else(|e| failed(format!("cannot open {what} {}: {e}", path.display())))?;
    let facts = file.metadata().or_else(|e| failed(format!("cannot read {what} {}: {e}", path.display())))?;
    if !facts.is_file() {
        return failed(format!("{what} {} is not a regular file", path.display()));
    }
    if facts.len() == 0 {
        return failed(format!("{what} {} is empty", path.display()));
    }
    Ok((file, facts.len()))
}

/// Read a module, at most the size a runtime takes.
fn module(path: &Path) -> Done<Vec<u8>> {
    let most = Config::default().max_module_bytes as u64;
    let built = |e: &dyn std::fmt::Display| Stop::Failed(format!("cannot read {}: {e}\nbuild it first; see the README", path.display()));
    let (file, _) = regular(path, "the module").map_err(|why| match why {
        Stop::Failed(why) => built(&why),
        stop => stop,
    })?;
    let mut bytes = Vec::new();
    file.take(most + 1).read_to_end(&mut bytes).map_err(|e| built(&e))?;
    if bytes.len() as u64 > most {
        return failed(format!("{} is larger than a module may be ({most} bytes)", path.display()));
    }
    Ok(bytes)
}

/// A short word for this run, put in its messages, so that a message found on the other ship is
/// known to be this run's and not one an earlier, interrupted run left waiting.
fn run_word() -> String {
    let mut state = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(7, |since| since.as_nanos() as u64) ^ (u64::from(std::process::id()) << 32) | 1;
    (0..4)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"abcdefghjkmnpqrstuvwxyz23456789"[(state % 31) as usize] as char
        })
        .collect()
}

/// Write `contents` to `path` by a new file beside it and a rename, so that whatever was at
/// `path` (a link included) is replaced, never written through.
fn replace(path: &Path, contents: &str) -> Done<()> {
    use std::io::Write;
    let fresh = path.with_extension("new");
    let _ = fs::remove_file(&fresh);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&fresh).or_else(|e| failed(format!("cannot write {}: {e}", fresh.display())))?;
    file.write_all(contents.as_bytes()).or_else(|e| failed(format!("cannot write {}: {e}", fresh.display())))?;
    drop(file);
    fs::rename(&fresh, path).or_else(|e| failed(format!("cannot write {}: {e}", path.display())))
}

/// The count of introductions acted on that a program has last reported, if any.
fn introduced(program: &Program) -> u64 {
    let output = program.output.lock().unwrap_or_else(|e| e.into_inner());
    output.lines.iter().rev().find_map(|(_, line)| said::introductions_acted(line)).unwrap_or(0)
}

fn walk(options: &Options, step: &mut usize, lock: &mut Option<fs::File>, held: &mut Option<Programs>) -> Done<()> {
    begin(step, "getting the lookup point and the two ships ready.");
    if let Some(first) = options.ports {
        if first == 0 || first > u16::MAX - 5 {
            return failed(format!("--ports {first} leaves no room for six ports counting up from it"));
        }
    }
    // Everything given is looked at before anything is made or started.
    let modules = [module(&options.kernel)?, module(&options.counter)?, module(&options.tally)?];
    let guestbook = module(&options.guestbook)?;
    let shared = options.file.as_ref().map(|path| regular(path, "the file to share")).transpose()?;
    let (dir, taken) = take_directory(&options.dir)?;
    *lock = Some(taken);
    let word = run_word();
    let point_dir = dir.join("point");
    fs::create_dir_all(&point_dir).or_else(|e| failed(format!("cannot make {}: {e}", point_dir.display())))?;
    let mut keys = Vec::new();
    let mut codes = Vec::new();
    for (ship, other) in [(FIRST, SECOND), (SECOND, FIRST)] {
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        let (key, code, made) = prepare(&dir.join(bare(ship)), ship, other, &modules).or_else(failed)?;
        println!("  {ship}: {}, in {}.", if made { "made, with two agents" } else { "already here from an earlier run, and reused" }, dir.join(bare(ship)).display());
        // Said when its steps come: the ship is given the guestbook now, while no program has
        // its directory.
        give_guestbook(&dir.join(bare(ship)), ship, other, &guestbook).or_else(failed)?;
        keys.push(pretend::line(ship, &key));
        codes.push(code);
    }
    let ids = dir.join("pretend-ids.txt");
    let list = format!(
        "# The keys of the two ships of `serve --two-ships`, read instead of Urbit ID.\n# Whoever can write this file can be any ship to the programs that read it.\n{}\n{}\n",
        keys[0], keys[1]
    );
    replace(&ids, &list)?;
    println!("  Their keys are listed in {}.", ids.display());
    println!("  That list stands in for Urbit ID here, so this works with no internet and no real ships.");
    println!("  This run's messages are marked \"run {word}\", to tell them from any an earlier run left.");

    begin(step, "starting the lookup point and the two ships, each as a program of its own.");
    let exe = std::env::current_exe().or_else(|e| failed(format!("cannot find this program's own file: {e}")))?;
    let port = |offset: u16| options.ports.map_or(0, |first| first + offset);
    let common = |dir: &Path, net: u16, http: u16| {
        let mut args = vec!["--dir".to_string(), dir.display().to_string(), "--pretend-ids".into(), ids.display().to_string(), "--net".into(), format!("127.0.0.1:{net}"), "--addr".into(), format!("127.0.0.1:{http}")];
        if let Some(seconds) = options.sleep_after {
            args.extend(["--sleep-after".to_string(), seconds.to_string()]);
        }
        args
    };
    let mut point_args = common(&point_dir, port(0), port(1));
    point_args.extend(["--lookup-point".into(), "all".into(), "--relay".into()]);
    let programs = held.insert(Programs {
        exe: exe.clone(),
        show: options.show_output,
        point: Program::new("the lookup point", point_args),
        first: Program::new(FIRST, Vec::new()),
        second: Program::new(SECOND, Vec::new()),
    });
    println!("  The lookup point, which keeps track of where ships are and holds no ship of its own:");
    println!("    {}", programs.point.command(&exe));
    let since = programs.point.mark();
    programs.point.start(&exe, programs.show)?;
    let point_addr = programs.point.wait_for(since, "the lookup point to start", said::talking_at)?;
    println!("  It is listening at {point_addr}.");
    let mut first_args = common(&dir.join(bare(FIRST)), port(2), port(3));
    first_args.extend(["--lookup-at".into(), point_addr.to_string()]);
    let mut second_args = common(&dir.join(bare(SECOND)), port(4), port(5));
    second_args.extend(["--lookup-at".into(), point_addr.to_string(), "--behind-router".into()]);
    programs.first.args = first_args;
    programs.second.args = second_args;
    println!("  {FIRST}:");
    println!("    {}", programs.first.command(&exe));
    println!("  {SECOND}, set up as if it were behind a home router, so that whoever calls it");
    println!("  first asks the lookup point to introduce them:");
    println!("    {}", programs.second.command(&exe));
    let mut http = Vec::new();
    let mut udp = Vec::new();
    for (ship, introduce) in [(FIRST, false), (SECOND, true)] {
        let program = if ship == FIRST { &mut programs.first } else { &mut programs.second };
        let since = program.mark();
        program.start(&exe, options.show_output)?;
        let addr = program.wait_for(since, &format!("{ship} to start"), said::serving_at)?;
        let (_, seen_at, asks) = program.wait_for(since, &format!("{ship} to be announced to the lookup point"), |line| said::announced_as(line).filter(|(said, _, _)| said == ship))?;
        if asks != introduce {
            return failed(format!("{ship} was announced {} callers to be introduced first, and that is not how it was started", if asks { "asking" } else { "without asking" }));
        }
        println!("  {ship} is running, and the lookup point knows it is at {seen_at}.");
        http.push(addr);
        udp.push(seen_at);
    }
    println!("  Neither ship was told where the other is: each finds out from the lookup point.");

    let mut first_device = Device::sign_in(FIRST, http[0], &codes[0])?;
    let second_device = Device::sign_in(SECOND, http[1], &codes[1])?;

    begin(step, &format!("{FIRST} sends a message to {SECOND}."));
    println!("  The owner of {FIRST} signs in with its access code and tells it to send the message.");
    // What the ship called had reported of introductions before this message, and whether an
    // earlier run's message, carried as the ships started, was introduced already.
    let before = introduced(&programs.second);
    let text = format!("hello from {FIRST} (run {word})");
    let (took, seq) = message(&first_device, &second_device, &text)?;
    println!("  Arrived after {}, as entry {seq} of {SECOND}'s journal: \"{text}\"", seconds(took));
    // The ship called reports, within about a second, the introductions it has been given; five
    // seconds are allowed for it.
    let rose = programs.second.wait_within(0, "an introduction to be reported", Duration::from_secs(5), |line| said::introductions_acted(line).filter(|acted| *acted > before));
    match rose {
        Ok(_) => {
            println!("  {SECOND} has reported that the lookup point introduced {FIRST} to it,");
            println!("  as {SECOND} asks of its callers.");
        }
        Err(Stop::Interrupted) => return Err(Stop::Interrupted),
        Err(Stop::Failed(_)) if before > 0 => {
            println!("  The lookup point had already introduced {FIRST} to {SECOND} as the ships started: a message an");
            println!("  earlier run had left waiting was carried then, and this one went on the connection it made.");
        }
        Err(Stop::Failed(why)) => return failed(format!("the message arrived, but {SECOND} did not report being introduced to its caller ({why})")),
    }

    begin(step, &format!("{SECOND} sends a message back to {FIRST}."));
    let text = format!("hello from {SECOND} (run {word})");
    let (took, seq) = message(&second_device, &first_device, &text)?;
    println!("  Arrived after {}, as entry {seq} of {FIRST}'s journal: \"{text}\"", seconds(took));

    begin(step, &format!("{FIRST} shares a file with {SECOND}."));
    let (mut source, length, what): (Box<dyn Read>, u64, String) = match (shared, &options.file) {
        (Some((file, length)), Some(path)) => (Box::new(file), length, format!("the file {}", path.display())),
        _ => {
            let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |since| since.as_nanos() as u64) | 1;
            let length = 3 * CHUNK + 123_457;
            (Box::new(MadeUp { state: seed, left: length }), length, "a made-up file".to_string())
        }
    };
    let (id, sent_hash) = first_device.upload("counter", &mut source, length, moving(length))?;
    println!("  The owner of {FIRST} puts {what} on it: {} bytes.", grouped(length));
    // A file shared by an earlier run (with --file, the same file) may still be allowed and
    // kept; both are undone first, so that this run shows what it says it shows.
    first_device.until(Instant::now() + LIMIT);
    first_device.command("counter", &format!("unlet {SECOND} {}", hex(&id)))?;
    second_device.until(Instant::now() + LIMIT);
    // Nothing kept is not a failure (the answer is not used), but a stop noticed is a stop.
    if let Err(Stop::Interrupted) = second_device.done(second_device.limit(second_device.agent.delete(&format!("{}/files/kept/{}", second_device.base, hex(&id))))?.set("Authorization", &second_device.auth()).call(), |why| why) {
        return Err(Stop::Interrupted);
    }
    println!("  The owner of {SECOND} tries to open it through {SECOND}.");
    let deadline = moving(length);
    let refusal = loop {
        match second_device.open_from(FIRST, "counter", &id, deadline)? {
            Opened::Answer(404, words) => break words,
            Opened::Got(..) => return failed(format!("{SECOND} was given the file before {FIRST} allowed it")),
            Opened::Answer(503 | 504, _) if Instant::now() < deadline => pause()?,
            Opened::Answer(status, words) => return failed(format!("{SECOND} was expected to be refused, and the answer was {status}, {}", words.trim())),
        }
    };
    println!("  Refused: {SECOND} answered \"{}\".", refusal.trim());
    println!("  That is its answer when the agent on {FIRST} that holds the file has not allowed it.");
    println!("  The owner of {FIRST} allows {SECOND} to have it.");
    first_device.until(Instant::now() + LIMIT);
    let allowed = first_device.command("counter", &format!("let {SECOND} {}", hex(&id)))?;
    if allowed != "ok" {
        return failed(format!("{FIRST}'s agent answered \"{allowed}\" when asked to allow it"));
    }
    println!("  This can take about five seconds: {FIRST} remembers its agent's no for five seconds");
    println!("  before it asks the agent again.");
    let started = Instant::now();
    let deadline = moving(length);
    let (got_length, got_hash) = loop {
        match second_device.open_from(FIRST, "counter", &id, deadline)? {
            Opened::Got(length, hash) => break (length, hash),
            // A refusal is remembered for a few seconds, and the other ship may be busy.
            Opened::Answer(404 | 503 | 504, _) if Instant::now() < deadline => pause()?,
            Opened::Answer(status, words) => return failed(format!("{SECOND} was expected to be given the file, and the answer was {status}, {}", words.trim())),
        }
    };
    println!("  The owner of {SECOND} opens it again, and gets it after {}.", seconds(started.elapsed()));
    println!("  A SHA-256 is a fingerprint of a file's contents: the same fingerprint, the same file.");
    same_file(length, &sent_hash, got_length, &got_hash)?;

    begin(step, &format!("{FIRST} is turned off, and {SECOND} opens the file again."));
    let old_first = (http[0], udp[0]);
    programs.first.stop().or_else(failed)?;
    println!("  {FIRST} is off.");
    let deadline = moving(length);
    let (kept_length, kept_hash) = loop {
        match second_device.open_from(FIRST, "counter", &id, deadline)? {
            Opened::Got(length, hash) => break (length, hash),
            Opened::Answer(503, _) if Instant::now() < deadline => pause()?,
            Opened::Answer(status, words) => return failed(format!("{SECOND} was expected to open what it kept, and the answer was {status}, {}", words.trim())),
        }
    };
    same_file(length, &sent_hash, kept_length, &kept_hash)?;
    println!("  {SECOND} still has every byte, from the copy it kept when it first opened it.");

    begin(step, &format!("{FIRST} comes back, and the two ships trade messages again."));
    let since = programs.first.mark();
    programs.first.start(&exe, options.show_output)?;
    let addr = programs.first.wait_for(since, &format!("{FIRST} to start again"), said::serving_at)?;
    let (_, seen_at, _) = programs.first.wait_for(since, &format!("{FIRST} to be announced again"), |line| said::announced_as(line).filter(|(said, _, _)| said == FIRST))?;
    let moved = seen_at != old_first.1;
    if moved {
        println!("  {FIRST} is running again, now at {seen_at}, a new address (it was at {}).", old_first.1);
    } else {
        println!("  {FIRST} is running again at {seen_at}, the same address as before.");
    }
    if addr != old_first.0 {
        println!("  Its owner's device now reaches it at {addr}, where it was {}.", old_first.0);
    }
    first_device.moved_to(addr);
    let text = format!("hello again from {FIRST} (run {word})");
    let (took, seq) = message(&first_device, &second_device, &text)?;
    println!("  {FIRST} to {SECOND}: arrived after {}, as entry {seq} of {SECOND}'s journal.", seconds(took));
    let text = format!("hello again from {SECOND} (run {word})");
    let (took, seq) = message(&second_device, &first_device, &text)?;
    println!("  {SECOND} to {FIRST}: arrived after {}, as entry {seq} of {FIRST}'s journal.", seconds(took));
    if took > Duration::from_secs(15) {
        println!("  That is slower than it should be. The README says why it can be, under Known limits.");
    }

    begin(step, &format!("{SECOND}'s owner asks {FIRST} a question, and has a command's reply come back."));
    first_device.until(Instant::now() + LIMIT);
    let set = first_device.command("counter", "inc asked")?;
    if set.parse::<u64>().is_err() {
        return failed(format!("{FIRST}'s counter agent answered \"{set}\" when asked to count"));
    }
    println!("  The owner of {FIRST} counts one more on its counter \"asked\", which now stands at {set}.");
    println!("  The owner of {SECOND} asks, through {SECOND}, what {FIRST}'s counter agent says \"asked\" stands at.");
    let started = Instant::now();
    second_device.until(started + LIMIT);
    let answer = loop {
        match second_device.ask(FIRST, "counter", "counter", "asked")? {
            (200, answer) => break answer,
            // Not reached yet, or too busy just then.
            (503 | 504, _) if started.elapsed() < LIMIT => pause()?,
            (status, words) => return failed(format!("{SECOND}'s question was expected to be answered, and the answer was {status}, {}", words.trim())),
        }
    };
    if answer != set {
        return failed(format!("{FIRST}'s counter agent answered \"{answer}\", and the counter stands at {set}"));
    }
    println!("  Answered after {}: \"{answer}\", what the counter on {FIRST} stands at.", seconds(started.elapsed()));
    println!("  Asked the same through the agent's journal interface, which is not open to questions:");
    let refusal = match second_device.ask(FIRST, "counter", "journal", "asked")? {
        (403, words) => words,
        (status, words) => return failed(format!("a question to an interface not open to questions was expected to be refused, and the answer was {status}, {}", words.trim())),
    };
    println!("  Refused: {SECOND} answered \"{}\".", refusal.trim());
    println!("  The owner of {SECOND} has its tally agent send {FIRST}'s counter \"inc asked\", asking for the reply.");
    let started = Instant::now();
    second_device.until(started + LIMIT);
    let number = second_device.command("tally", &format!("tell-reply {} inc asked", bare(FIRST)))?;
    if !number.parse::<u64>().is_ok_and(|number| number > 0) {
        return failed(format!("{SECOND} would not send the command: its agent answered \"{number}\""));
    }
    let prefix = format!("{number} ~{}/counter counter ", bare(FIRST));
    let line = loop {
        let receipts = second_device.command("tally", "receipts")?;
        if let Some(line) = receipts.lines().find(|line| line.starts_with(&prefix)) {
            break line.to_string();
        }
        if started.elapsed() > LIMIT {
            return failed(format!("waited {} seconds for the receipt of command {number}, and it did not come", LIMIT.as_secs()));
        }
        pause()?;
    };
    let reply = match line.split_once(" ran [] ").and_then(|(_, rest)| rest.split_once(" reply ")) {
        Some((_, reply)) => reply.to_string(),
        None => return failed(format!("the receipt of command {number} did not say it ran with a reply: \"{line}\"")),
    };
    let expected = set.parse::<u64>().map(|set| set + 1).unwrap_or(0).to_string();
    if reply != expected {
        return failed(format!("the reply that came with the receipt is \"{reply}\", and {expected} was expected"));
    }
    println!("  The receipt came back after {}, saying the command ran, with its reply: \"{reply}\".", seconds(started.elapsed()));

    println!();
    println!("Two steps more, with the guestbook: an agent whose interfaces are written down once, in a");
    println!("proto file. The proto file defines the handler signatures, the typed calls, and how the");
    println!("guestbook reads and writes JSON. Each ship was given it in step 1, after its two agents and before it");
    println!("started, under the name \"book\".");
    begin(step, &format!("{FIRST}'s owner calls the guestbook on {FIRST} through its JSON door."));
    first_device.until(Instant::now() + LIMIT);
    let name = format!("a visitor from {SECOND} (run {word})");
    let signed = first_device.show_json("book", "guestbook", "Sign", &format!(r#"{{"signature": {{"name": "{name}", "mood": "MOOD_HAPPY", "tags": ["walk-through"], "signedAt": "{}"}}}}"#, now_millis()))?;
    let Some(number) = signed["number"].as_str().and_then(|number| number.parse::<u64>().ok()) else {
        return failed(format!("the guestbook on {FIRST} answered Sign without a signature's number: {signed}"));
    };
    println!("  That is a command: the signature is number {number}, kept by {FIRST}.");
    let page = first_device.show_json("book", "guestbook", "Lookup", &format!(r#"{{"prefix": "{name}", "limit": 1}}"#))?;
    if page["signatures"][0]["number"].as_str() != Some(number.to_string().as_str()) || page["signatures"][0]["name"].as_str() != Some(name.as_str()) {
        return failed(format!("the guestbook on {FIRST} was asked for the signature just made, and answered {page}"));
    }
    println!("  That is a question: it only reads, and found the signature just made.");
    println!("  A command can also turn a call down on purpose, and say why. Signing with no name:");
    let kept = first_device.signatures("book")?;
    let unchanged = |what: &str| -> Done<()> {
        let after = first_device.signatures("book")?;
        if after != kept {
            return failed(format!("the guestbook on {FIRST} held {kept} signatures before {what} and {after} after it, and nothing of {what} was to be kept"));
        }
        Ok(())
    };
    first_device.show_fault("book", "guestbook", "Sign", r#"{"signature": {"name": ""}}"#, 422, "no-name")?;
    unchanged("the nameless Sign")?;
    println!("  Spoil writes a placeholder signature into the book, and then turns itself down:");
    first_device.show_fault("book", "guestbook", "Spoil", "{}", 422, "spoilt")?;
    unchanged("Spoil")?;
    println!("  The book still holds {}: nothing a refused command did was kept.", signatures(kept));

    begin(step, &format!("the guestbook on {FIRST} puts a typed question to the guestbook on {SECOND}."));
    second_device.until(Instant::now() + LIMIT);
    let theirs = format!("kept on {SECOND} (run {word})");
    let (status, kind, words) = second_device.call_json("book", "guestbook", "Sign", &format!(r#"{{"signature": {{"name": "{theirs}"}}}}"#))?;
    let theirs_number = serde_json::from_str::<serde_json::Value>(&words).ok().and_then(|signed| signed["number"].as_str().and_then(|number| number.parse::<u64>().ok()));
    let (200, "application/json", Some(theirs_number)) = (status, kind.as_str(), theirs_number) else {
        return failed(format!("the guestbook on {SECOND} would not take a signature: it answered {status} ({kind}), {}", words.trim()));
    };
    println!("  The owner of {SECOND} signs the guestbook there: signature number {theirs_number}.");
    println!("  The owner of {FIRST} has its guestbook ask {SECOND}'s for it, with a call generated from the proto file:");
    let started = Instant::now();
    first_device.until(started + LIMIT);
    let fetching = first_device.show_json("book", "guestbook", "Fetch", &format!(r#"{{"ship": "{}", "agent": "book", "number": {theirs_number}}}"#, bare(SECOND)))?;
    let Some(question) = fetching["question"].as_str().filter(|question| question.parse::<u64>().is_ok_and(|n| n > 0)).map(str::to_string) else {
        return failed(format!("the guestbook on {FIRST} would not put the question: it answered {fetching}"));
    };
    let line = loop {
        let (status, kind, words) = first_device.call_json("book", "guestbook", "Report", "{}")?;
        let report: serde_json::Value = serde_json::from_str(&words).unwrap_or_default();
        let found = report["answers"].as_array().and_then(|answers| answers.iter().filter_map(|line| line.as_str()).find(|line| line.split(' ').next() == Some(question.as_str())).map(str::to_string));
        if let (200, "application/json", Some(line)) = (status, kind.as_str(), found) {
            break line;
        }
        if started.elapsed() > LIMIT {
            return failed(format!("waited {} seconds for the answer to question {question}, and it did not come", LIMIT.as_secs()));
        }
        pause()?;
    };
    let expected = format!("{question} signature {theirs_number} by {theirs}");
    if line != expected {
        return failed(format!("the answer to question {question} was \"{line}\", and \"{expected}\" was expected"));
    }
    println!("  The answer came after {}, decoded by the guestbook on {FIRST} as the description says:", seconds(started.elapsed()));
    println!("    \"{line}\"");
    println!("  Then the owner of {FIRST} has its guestbook pass its own signature {number} to {SECOND}'s, as a command,");
    println!("  with the name left off, which {SECOND}'s guestbook turns down:");
    let theirs_held = second_device.signatures("book")?;
    let started = Instant::now();
    first_device.until(started + LIMIT);
    second_device.until(started + LIMIT);
    let passing = first_device.show_json("book", "guestbook", "Pass", &format!(r#"{{"number": {number}, "ship": "{}", "agent": "book", "nameless": true}}"#, bare(SECOND)))?;
    let Some(sent_as) = passing["sentAs"].as_str().filter(|sent_as| sent_as.parse::<u64>().is_ok_and(|n| n > 0)).map(str::to_string) else {
        return failed(format!("the guestbook on {FIRST} would not pass the signature: it answered {passing}"));
    };
    let line = loop {
        let (status, kind, words) = first_device.call_json("book", "guestbook", "Report", "{}")?;
        let report: serde_json::Value = serde_json::from_str(&words).unwrap_or_default();
        let found = report["receipts"].as_array().and_then(|receipts| receipts.iter().filter_map(|line| line.as_str()).find(|line| line.split(' ').next() == Some(sent_as.as_str())).map(str::to_string));
        if let (200, "application/json", Some(line)) = (status, kind.as_str(), found) {
            break line;
        }
        if started.elapsed() > LIMIT {
            return failed(format!("waited {} seconds for the receipt of command {sent_as}, and it did not come", LIMIT.as_secs()));
        }
        pause()?;
    };
    let expected = format!("{sent_as} no-name: a signature needs a name");
    if line != expected {
        return failed(format!("the receipt of command {sent_as} said \"{line}\", and \"{expected}\" was expected"));
    }
    println!("  The receipt came back after {}, carrying the reason {SECOND}'s guestbook gave, as {FIRST}'s guestbook read it:", seconds(started.elapsed()));
    println!("    \"{line}\"");
    let theirs_after = second_device.signatures("book")?;
    if theirs_after != theirs_held {
        return failed(format!("the guestbook on {SECOND} held {theirs_held} signatures before it refused the command and {theirs_after} after"));
    }
    println!("  Nothing of the refused command was kept on {SECOND}: its guestbook still holds {}.", signatures(theirs_held));
    first_device.sign_out();
    second_device.sign_out();

    println!();
    println!("Every step worked. What was shown:");
    println!("  Two ships found each other by name alone, through a lookup point, and traded messages.");
    println!("  {SECOND} asks that its callers be introduced by the lookup point, and reported that {FIRST} was.");
    println!("  A file on {FIRST} was refused to {SECOND} until {FIRST}'s owner allowed it,");
    println!("  then arrived whole, checked by its SHA-256.");
    println!("  {SECOND} opened the file again with {FIRST} turned off, from the copy it kept.");
    if moved {
        println!("  {FIRST} came back at a new address and the two found each other again.");
    } else {
        println!("  {FIRST} came back, at the same address, and the two found each other again.");
    }
    println!("  {SECOND}'s owner asked {FIRST} a question and was answered; one to an interface not");
    println!("  open to questions was refused; and a command brought its reply back with its receipt.");
    println!("  The guestbook, whose interfaces are written down once in a proto file, was called with JSON");
    println!("  on {FIRST}, and put a typed question to the guestbook on {SECOND}, whose answer it decoded.");
    println!("  Commands the guestbook turned down came back with their reasons, at the JSON door and on a");
    println!("  receipt from {SECOND}, and nothing they did was kept.");
    println!("What it does not show: these are three programs on one machine, talking over this");
    println!("machine's own loopback address. It does not show two machines, a real home router,");
    println!("the relay carrying anything (nothing on one machine needs it), or real Urbit ID.");

    if options.then_stop {
        println!();
        println!("Stopping the lookup point and both ships.");
        return stop_all(held);
    }
    println!();
    println!("The lookup point and both ships are still running. To look at a ship in a browser,");
    println!("open its address and sign in with its access code:");
    for (ship, (addr, code)) in [FIRST, SECOND].iter().zip(http.iter().zip(&codes)) {
        let addr = if *ship == FIRST { addr_of(&first_device) } else { addr.to_string() };
        println!("  {ship}: http://{addr}/ships/{}/   access code: {code}", bare(ship));
    }
    println!("To start them yourself, stop these first, then run:");
    for program in [&programs.point, &programs.first, &programs.second] {
        println!("  {}", program.command(&programs.exe));
    }
    if options.ports.is_none() {
        println!("The lookup point takes a new port each time it starts unless it is given one, so put");
        println!("its new port after --lookup-at, or run this walk-through with --ports to fix them all.");
    }
    println!("Press Ctrl-C to stop them.");
    loop {
        if STOPPING.load(Ordering::SeqCst) {
            println!();
            println!("Stopping the lookup point and both ships.");
            return stop_all(held);
        }
        for program in [&mut programs.point, &mut programs.first, &mut programs.second] {
            if let Some(status) = program.ended() {
                return failed(format!("{} stopped on its own ({status})", program.label));
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Stop all three programs, saying if any could not be stopped or seen to stop.
fn stop_all(held: &mut Option<Programs>) -> Done<()> {
    let Some(mut programs) = held.take() else { return Ok(()) };
    let mut troubles = Vec::new();
    for program in [&mut programs.point, &mut programs.first, &mut programs.second] {
        if let Err(why) = program.stop() {
            troubles.push(why);
        }
    }
    if troubles.is_empty() {
        Ok(())
    } else {
        failed(troubles.join("; "))
    }
}

/// "1 signature", "2 signatures".
fn signatures(count: u64) -> String {
    format!("{count} signature{}", if count == 1 { "" } else { "s" })
}

/// Half a second, unless Ctrl-C comes first.
fn pause() -> Done<()> {
    std::thread::sleep(Duration::from_millis(500));
    if STOPPING.load(Ordering::SeqCst) {
        return Err(Stop::Interrupted);
    }
    Ok(())
}

/// The time now, in milliseconds since 1970.
fn now_millis() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64)
}

/// The address a device reaches its ship at, as `host:port`.
fn addr_of(device: &Device) -> String {
    device.base.trim_start_matches("http://").split('/').next().unwrap_or_default().to_string()
}

/// Have the owner of one ship tell its counter agent to send a line to the other ship's
/// journal, and read the other ship's journal, as its owner, until the line is there. Returns
/// how long it took to arrive and the number of its entry in that journal.
fn message(from: &Device, to: &Device, text: &str) -> Done<(Duration, u64)> {
    let started = Instant::now();
    from.until(started + LIMIT);
    to.until(started + LIMIT);
    let after = to.head("counter", "journal")?;
    // The agent answers with the number its ship gave the command, counted from one for each
    // other ship.
    let sent = from.command("counter", &format!("pass {} journal {text}", to.ship))?;
    if !sent.parse::<u64>().is_ok_and(|number| number > 0) {
        return failed(format!("{} would not send the message: its agent answered \"{sent}\"", from.ship));
    }
    let mut seen = after;
    loop {
        for (seq, payload) in to.entries("counter", "journal", seen, 1)? {
            seen = seen.max(seq);
            if payload == text.as_bytes() {
                return Ok((started.elapsed(), seq));
            }
        }
        if STOPPING.load(Ordering::SeqCst) {
            return Err(Stop::Interrupted);
        }
        if started.elapsed() > LIMIT {
            return failed(format!("waited {} seconds for \"{text}\" to arrive at {}, and it did not", LIMIT.as_secs(), to.ship));
        }
    }
}

/// Say that what arrived is what was sent, or that it is not.
fn same_file(length: u64, hash: &[u8; 32], got_length: u64, got_hash: &[u8; 32]) -> Done<()> {
    if (got_length, got_hash) != (length, hash) {
        return failed(format!(
            "what arrived is not what was sent: {} bytes with SHA-256 {}, where {} bytes with SHA-256 {} were sent",
            grouped(got_length),
            hex(got_hash),
            grouped(length),
            hex(hash)
        ));
    }
    println!("  Sent:   {} bytes, SHA-256 {}", grouped(length), hex(hash));
    println!("  Opened: {} bytes, SHA-256 {}", grouped(got_length), hex(got_hash));
    println!("  They are the same.");
    Ok(())
}
