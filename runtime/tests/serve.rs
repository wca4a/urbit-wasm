//! The `serve` program, run as an operator runs it: the real binary, started as a process of
//! its own, read only through what it prints and what it answers over HTTP.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use ship_proto::Message;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Build the kernel and test agents once per test run, and return the path of one of them.
fn wasm(name: &str) -> PathBuf {
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
    workspace().join(format!("target/wasm/wasm32-unknown-unknown/release/{name}.wasm"))
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-serve-{label}", std::process::id()));
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

fn serve() -> Command {
    Command::new(env!("CARGO_BIN_EXE_serve"))
}

/// A `serve` this test started, owned for the whole of the test, in a process group of its own:
/// when this goes, however the test ends (a failed assertion and a panic included), the whole
/// group is killed, so whatever it started goes too (the walk-through's programs are started in
/// its group, which they inherit), and it is waited for. The lines it prints are passed on as
/// they come, by threads of their own, so it never waits on a full pipe.
///
/// Its leader is never waited for (reaped) before the group is killed: until it is, its number
/// stays taken, so the group's number cannot be given to another group. Whether it has ended is
/// seen without reaping it (`waitid` with `WNOWAIT`), and once it has been reaped nothing is
/// signalled again.
struct Owned {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    reaped: bool,
}

impl Owned {
    fn start(mut command: Command) -> Owned {
        use std::os::unix::process::CommandExt;
        let child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0).spawn().unwrap();
        let mut owned = Owned { child, lines: mpsc::channel().1, seen: Vec::new(), reaped: false };
        let (sender, lines) = mpsc::channel();
        owned.lines = lines;
        let streams: [Box<dyn Read + Send>; 2] = [Box::new(owned.child.stdout.take().unwrap()), Box::new(owned.child.stderr.take().unwrap())];
        for stream in streams {
            let sender = sender.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { return };
                    if sender.send(line).is_err() {
                        return;
                    }
                }
            });
        }
        owned
    }

    /// The first line, from here on, that `find` makes something of, within 60 seconds.
    fn wait_for<T>(&mut self, what: &str, find: impl Fn(&str) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).unwrap_or_else(|_| panic!("never printed: {what}\n{}", self.seen.join("\n")));
            self.seen.push(line.clone());
            if let Some(found) = find(&line) {
                return found;
            }
        }
    }

    /// Whether the leader has ended, seen without reaping it.
    fn ended(&self) -> bool {
        assert!(!self.reaped);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let options = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
        let looked = unsafe { libc::waitid(libc::P_PID, self.child.id() as libc::id_t, &mut info, options) };
        assert_eq!(looked, 0, "waitid: {}", std::io::Error::last_os_error());
        // With WNOHANG and nothing to report, the process number is left as nought.
        unsafe { info.si_pid() != 0 }
    }

    /// Wait for it to end of its own accord, for up to `limit`, and return everything it printed.
    /// It is not reaped: the caller can look for what it left running first, then `reap` it. If
    /// it has not ended by then it is asked to stop (`SIGTERM`, so that it can stop what it
    /// started), given 30 seconds more, and then the test fails (its group is killed as this
    /// goes).
    fn finish(&mut self, limit: Duration) -> String {
        let deadline = Instant::now() + limit;
        while !self.ended() {
            if Instant::now() > deadline {
                // Not reaped, so the number is still this process's.
                unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
                let polite = Instant::now() + Duration::from_secs(30);
                while !self.ended() && Instant::now() < polite {
                    std::thread::sleep(Duration::from_millis(100));
                }
                panic!("serve was still running after {limit:?}:\n{}", self.drain());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        self.drain()
    }

    /// Kill its group, then reap the leader, and return how the leader ended.
    fn reap(&mut self) -> std::process::ExitStatus {
        assert!(!self.reaped);
        // The leader is not reaped yet, so the group's number is still this group's.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let status = self.child.wait().unwrap();
        self.reaped = true;
        status
    }

    /// Everything printed so far and still to come, now that it has ended.
    fn drain(&mut self) -> String {
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(line);
        }
        self.seen.join("\n") + "\n"
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.reap();
        }
    }
}

/// Run `serve` to its end, for up to `limit`: how it ended, and what it printed. Its group is
/// killed before this returns.
fn finished(command: Command, limit: Duration) -> (std::process::ExitStatus, String) {
    let mut owned = Owned::start(command);
    let said = owned.finish(limit);
    (owned.reap(), said)
}

/// The same, keeping it owned and not yet reaped, so that the caller can look for what it left
/// running before its group is killed (`reap`, or when it is dropped).
fn finished_owned(command: Command, limit: Duration) -> (String, Owned) {
    let mut owned = Owned::start(command);
    let said = owned.finish(limit);
    (said, owned)
}

/// The HTTP server's address in the line `serve` prints when it starts.
fn serving_at(line: &str) -> Option<SocketAddr> {
    line.strip_prefix("Serving the ships in ")?.rsplit_once(" at http://")?.1.parse().ok()
}

/// One HTTP request, and the answer's status and body.
fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.0\r\nHost: {addr}\r\n");
    for (name, value) in headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let status = String::from_utf8_lossy(&raw[..split]).split(' ').nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

/// Sign in to `~zod` with the access code, as its owner's device would, and return the token.
fn sign_in(addr: SocketAddr, code: &str) -> String {
    let asked = ship_proto::SignInRequest { code: code.into(), label: "test".into() }.encode_to_vec();
    let (status, body) = http(addr, "POST", "/ships/zod/signin", &[("Content-Type", "application/x-protobuf")], &asked);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    ship_proto::SignInReply::decode(&*body).unwrap().token
}

/// Start an upload of `length` bytes to `~zod`'s counter agent: the status of the answer.
fn upload_answer(addr: SocketAddr, token: &str, length: u64) -> u16 {
    let asked = ship_proto::UploadRequest { length, media_type: String::new() }.encode_to_vec();
    http(addr, "POST", "/ships/zod/agents/counter/files/uploads", &[("Authorization", &format!("Bearer {token}"))], &asked).0
}

/// The processes now running that name `dir`, or something in it, as a word of their command
/// line (a directory whose name merely begins with the same letters is another directory).
fn any_running_in(dir: &Path) -> Vec<String> {
    let listed = Command::new("ps").args(["-axo", "pid=,command="]).output().unwrap();
    let dir = dir.to_string_lossy().to_string();
    let inside = format!("{dir}/");
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter(|line| line.split_whitespace().any(|word| word == dir || word.starts_with(&inside) || word.ends_with(&dir) || word.contains(&format!("{dir}/"))))
        .map(str::to_string)
        .collect()
}

/// The lines in a ship's journal, read from its data directory with the library once nothing
/// else has it open.
fn journal(dir: &Path, ship: &str) -> Vec<String> {
    let rt = runtime::Runtime::open(dir.join(ship.trim_start_matches('~')), runtime::Config::default()).unwrap();
    let entries = rt.log_entries(ship, "counter", "journal", 0, usize::MAX).unwrap();
    entries.iter().map(|signed| String::from_utf8(ship_proto::EntryBody::decode(&*signed.body).unwrap().payload).unwrap()).collect()
}

/// Each "as entry N of ~ship's journal" the walk-through printed, with the text it said is
/// there: the ship, the entry's number, and the text.
fn entries_said(said: &str, word: &str) -> Vec<(String, u64, String)> {
    let mut found = Vec::new();
    for line in said.lines() {
        let Some((_, rest)) = line.split_once(", as entry ") else { continue };
        let Some((number, rest)) = rest.split_once(" of ") else { continue };
        let Some((ship, rest)) = rest.split_once("'s journal") else { continue };
        let text = match rest.strip_prefix(": \"").and_then(|rest| rest.strip_suffix('"')) {
            Some(text) => text.to_string(),
            // The lines of step 7 say only which ship sent it.
            None => {
                let from = line.trim().split_once(" to ").map(|(from, _)| from.to_string()).unwrap();
                format!("hello again from {from} (run {word})")
            }
        };
        found.push((ship.to_string(), number.parse().unwrap(), text));
    }
    found
}

/// The run's word, as the walk-through printed it.
fn run_word(said: &str) -> String {
    said.split_once("This run's messages are marked \"run ").and_then(|(_, rest)| rest.split_once('"')).map(|(word, _)| word.to_string()).expect("the run's word")
}

/// Every entry the walk-through said a message arrived as is that message, in that ship's own
/// journal, read with the library after it ended: four, one for each message, each marked with
/// this run's word.
fn arrived_as_said(dir: &Path, said: &str) {
    let word = run_word(said);
    let entries = entries_said(said, &word);
    assert_eq!(entries.len(), 4, "{said}");
    for (ship, number, text) in entries {
        assert!(text.ends_with(&format!("(run {word})")), "{text}");
        let lines = journal(dir, &ship);
        assert_eq!(lines.get(number as usize - 1), Some(&text), "entry {number} of {ship}'s journal");
    }
}

fn walk_through(dir: &Path, extra: &[&str]) -> String {
    let mut command = serve();
    command.args(["--two-ships", &dir.to_string_lossy(), "--then-stop"]);
    for (flag, name) in [("--kernel", "kernel"), ("--counter", "counter"), ("--tally", "tally")] {
        command.args([flag, &wasm(name).to_string_lossy()]);
    }
    command.args(extra);
    let (said, mut owned) = finished_owned(command, Duration::from_secs(600));
    // The three programs it started are gone with it. Only looked for here, before its group is
    // killed: any left are killed with its group when it is dropped, at once if this fails.
    let left = any_running_in(dir);
    assert!(left.is_empty(), "still running: {left:?}");
    let status = owned.reap();
    assert!(status.success(), "the walk-through ended {status}:\n{said}");
    // Every step said what it was doing, and each check it makes was made.
    for step in 1..=8 {
        assert!(said.contains(&format!("\nStep {step} of 8: ")), "no step {step}:\n{said}");
    }
    for expected in [
        "Arrived after",
        "~norsyr-torryn has reported that the lookup point introduced ~sampel-palnet to it,\n  as ~norsyr-torryn asks of its callers.",
        "Refused: ~norsyr-torryn answered \"the other ship does not share that file with this one\".",
        "gets it after",
        "~sampel-palnet is off.",
        "still has every byte",
        "~sampel-palnet to ~norsyr-torryn: arrived after",
        "~norsyr-torryn to ~sampel-palnet: arrived after",
        "\n  Answered after ",
        "Refused: ~norsyr-torryn answered \"the other ship would not let it be asked: journal on counter is not open to other ships\".",
        ", saying the command ran, with its reply: \"",
        "\"code\":\"no-name\"",
        ": nothing a refused command did was kept.",
        "carrying the reason ~norsyr-torryn's guestbook gave, as ~sampel-palnet's guestbook read it:",
        " no-name: a signature needs a name\"\n",
        "Nothing of the refused command was kept on ~norsyr-torryn",
        "Every step worked.",
        "It does not show two machines",
        "Stopping the lookup point and both ships.",
    ] {
        assert!(said.contains(expected), "never said {expected:?}:\n{said}");
    }
    assert_eq!(said.matches("\n  They are the same.\n").count(), 2, "{said}");
    // Nothing a person reads has an em dash or an exclamation mark in it.
    assert!(!said.contains('\u{2014}') && !said.contains('!'), "{said}");
    arrived_as_said(dir, &said);
    replied_as_said(dir, &said);
    said
}

/// What step 8 said it was answered, and the reply it said came back with a receipt, are what
/// ~sampel-palnet's counter stood at, read with the library after the walk-through ended: the
/// answer to the question one less than the reply (the command counted one more), and the reply
/// what the counter holds now.
fn replied_as_said(dir: &Path, said: &str) {
    // "Answered after N seconds: \"V\"", and "with its reply: \"R\"".
    let answer: u64 = said.split_once("\n  Answered after ").and_then(|(_, rest)| rest.split('"').nth(1)).unwrap().parse().unwrap();
    let reply: u64 = said.split_once(", saying the command ran, with its reply: \"").and_then(|(_, rest)| rest.split('"').next()).unwrap().parse().unwrap();
    assert_eq!(reply, answer + 1, "{said}");
    let rt = runtime::Runtime::open(dir.join("sampel-palnet"), runtime::Config::default()).unwrap();
    let held: u64 = String::from_utf8(rt.read("~sampel-palnet", "counter", "counter", b"asked").unwrap()).unwrap().parse().unwrap();
    assert_eq!(held, reply, "{said}");
}

#[test]
fn the_two_ship_walk_through_works_and_works_again_on_the_same_directory() {
    let dir = TempDir::new("two-ships");
    let first = walk_through(&dir.0, &[]);
    assert_eq!(first.matches("made, with two agents").count(), 2, "{first}");
    // Again, reusing the ships, sharing a file the test made, and with the three programs given
    // --sleep-after 1, so that a sleeper running beside every step is seen to break nothing
    // (whether a ship was in fact put to sleep is not seen from here).
    let shared = dir.0.join("shared.bin");
    let contents: Vec<u8> = (0..(2 << 20) + 4321u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    fs::write(&shared, &contents).unwrap();
    let second = walk_through(&dir.0, &["--sleep-after", "1", "--file", &shared.to_string_lossy()]);
    assert_eq!(second.matches("already here from an earlier run, and reused").count(), 2, "{second}");
    assert!(second.contains("--sleep-after 1"), "{second}");
    assert_ne!(run_word(&first), run_word(&second));
    // What was sent and what was opened, as the walk-through says them, are the file the test
    // made: once when first opened and once with the other ship off.
    let fingerprint: String = <sha2::Sha256 as sha2::Digest>::digest(&contents).iter().map(|b| format!("{b:02x}")).collect();
    let length = contents.len().to_string();
    let length = format!("{},{},{}", &length[..1], &length[1..4], &length[4..]);
    for side in ["Sent:  ", "Opened:"] {
        let line = format!("\n  {side} {length} bytes, SHA-256 {fingerprint}\n");
        assert_eq!(second.matches(&line).count(), 2, "{line:?} in {second}");
    }
}

#[test]
fn the_walk_through_takes_only_a_directory_of_its_own_and_one_run_at_a_time() {
    let dir = TempDir::new("own-dir");
    let walk = |dir: &Path, extra: &[&str]| {
        let mut command = serve();
        command.args(["--two-ships", &dir.to_string_lossy(), "--then-stop"]);
        for (flag, name) in [("--kernel", "kernel"), ("--counter", "counter"), ("--tally", "tally")] {
            command.args([flag, &wasm(name).to_string_lossy()]);
        }
        command.args(extra);
        command
    };
    // A directory with something in it that is not a walk-through's is refused, and left as it was.
    let foreign = dir.0.join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("notes.txt"), b"mine").unwrap();
    let (status, said) = finished(walk(&foreign, &[]), Duration::from_secs(60));
    assert_eq!(status.code(), Some(1), "{said}");
    assert!(said.contains("is not a directory --two-ships made; give it an empty or new one"), "{said}");
    assert_eq!(fs::read_dir(&foreign).unwrap().count(), 1);
    // A file to share that is empty, or not a regular file, is refused before anything starts.
    let empty = dir.0.join("empty");
    fs::write(&empty, b"").unwrap();
    let fresh = dir.0.join("fresh");
    for (file, words) in [(&empty, "is empty"), (&dir.0, "is not a regular file")] {
        let (status, said) = finished(walk(&fresh, &["--file", &file.to_string_lossy()]), Duration::from_secs(60));
        assert_eq!(status.code(), Some(1), "{said}");
        assert!(said.contains(words) && !said.contains("Step 2 of 8"), "{said}");
    }
    assert!(!fresh.exists(), "a refused run made its directory");
    // While one run holds a directory, another is refused at once.
    let shared = dir.0.join("shared");
    let (status, said) = finished(walk(&shared, &[]), Duration::from_secs(600));
    assert!(status.success(), "{said}");
    let held = std::fs::OpenOptions::new().write(true).open(shared.join(".two-ships.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&held), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    let (status, said) = finished(walk(&shared, &[]), Duration::from_secs(60));
    assert_eq!(status.code(), Some(1), "{said}");
    assert!(said.contains("another run of --two-ships is using"), "{said}");
    drop(held);
    assert!(any_running_in(&dir.0).is_empty());
}

#[test]
fn a_ship_served_with_no_room_for_files_refuses_an_upload_and_one_served_with_room_takes_it() {
    let dir = TempDir::new("max-file-bytes");
    for (allowance, status) in [("0", 403), ("10M", 200)] {
        let mut command = serve();
        command.args(["--dir", &dir.0.to_string_lossy(), "--addr", "127.0.0.1:0", "--demo", "--max-file-bytes", allowance]);
        command.args(["--kernel", &wasm("kernel").to_string_lossy(), "--counter", &wasm("counter").to_string_lossy()]);
        let mut running = Owned::start(command);
        let addr = running.wait_for("where it serves", serving_at);
        let code = running.wait_for("the access code", |line| line.trim().strip_prefix("access code (shown this once): ").map(str::to_string));
        let token = sign_in(addr, &code);
        assert_eq!(upload_answer(addr, &token, 1000), status, "with --max-file-bytes {allowance}");
        // The allowance is the ship's whole: a file larger than it is refused as never fitting.
        if allowance == "10M" {
            assert_eq!(upload_answer(addr, &token, (10 << 20) + 1), 413);
        }
    }
}

#[test]
fn serve_with_a_list_of_keys_says_where_its_keys_come_from_and_never_that_they_come_from_urbit_id() {
    let dir = TempDir::new("pretend");
    let ids = dir.0.join("ids.txt");
    fs::write(&ids, format!("# a pretend list\n~zod {}\n~nec {}\n", "ab".repeat(32), "cd".repeat(32))).unwrap();
    let ships = dir.0.join("ships");
    let mut command = serve();
    command.args(["--dir", &ships.to_string_lossy(), "--addr", "127.0.0.1:0", "--pretend-ids", &ids.to_string_lossy(), "--net", "127.0.0.1:0", "--lookup-point", "all"]);
    let mut running = Owned::start(command);
    running.wait_for("where it serves", serving_at);
    let said = running.seen.join("\n");
    assert!(said.contains(&format!("Keys come from the list in {}, not from Urbit ID: whoever can write that file can be any ship.", ids.display())), "{said}");
    assert!(said.contains(&format!("(UDP), with keys from the list in {}, not from Urbit ID.", ids.display())), "{said}");
    assert!(said.contains("Answering as the lookup point"), "{said}");
    assert!(!said.contains("with keys from Urbit ID"), "{said}");
    drop(running);

    // A lookup answered from the list, with no network at all.
    let mut command = serve();
    command.args(["--pretend-ids", &ids.to_string_lossy(), "--lookup", "~nec", "--lookup", "~bud"]);
    let (status, said) = finished(command, Duration::from_secs(60));
    assert!(status.success(), "{said}");
    assert!(said.contains(&format!("~nec: key {}, revision 1, continuity 0, sponsor none", "cd".repeat(32))), "{said}");
    // A ship not on the list is listed with no key (so that one taken off is no longer believed).
    assert!(said.contains("~bud: key none, revision 1, continuity 0, sponsor none"), "{said}");
}

#[test]
fn serve_refuses_at_start_what_does_not_go_together_naming_the_flag_or_the_line() {
    let dir = TempDir::new("refused");
    let ids = dir.0.join("ids.txt");
    fs::write(&ids, format!("~zod {}\n\n~zod {}\n", "ab".repeat(32), "cd".repeat(32))).unwrap();
    let good = dir.0.join("good.txt");
    fs::write(&good, format!("~zod {}\n", "ab".repeat(32))).unwrap();
    let ships = dir.0.join("ships").to_string_lossy().to_string();
    let (ids, good) = (ids.to_string_lossy().to_string(), good.to_string_lossy().to_string());
    let cases: Vec<(Vec<&str>, String)> = vec![
        (vec!["--dir", &ships, "--pretend-ids", &good, "--ethereum", "http://127.0.0.1:9"], "--pretend-ids reads every ship's key from a file instead of Urbit ID, so it cannot go with".into()),
        (vec!["--dir", &ships, "--pretend-ids", &good, "--azimuth-copy", "x.sqlite"], "cannot go with --ethereum, --roller or any --azimuth- flag".into()),
        (vec!["--dir", &ships, "--pretend-ids", &good, "--roller", "http://127.0.0.1:9"], "cannot go with --ethereum, --roller".into()),
        (vec!["--dir", &ships, "--pretend-ids", &ids, "--net", "127.0.0.1:0"], format!("the list of ships' keys {ids}: line 3: ~zod is listed already, on line 1")),
        (vec!["--dir", &ships, "--net", "127.0.0.1:0", "--lookup-point", "all"], "--lookup-point needs --azimuth-copy".into()),
        (vec!["--dir", &ships, "--max-file-bytes", "1.5G"], "--max-file-bytes 1.5G: not a size".into()),
        (vec!["--dir", &ships, "--max-cache-bytes", "3g"], "--max-cache-bytes 3g: not a size".into()),
        (vec!["--dir", &ships, "--sleep-after", "-1"], "--sleep-after -1: not a whole number of seconds".into()),
        (vec!["--dir", &ships, "--then-stop"], "--then-stop goes with --two-ships".into()),
        (vec!["--two-ships", &ships, "--net", "127.0.0.1:0"], "takes only --kernel, --counter, --tally, --file, --ports, --sleep-after, --then-stop and --show-output, not --net".into()),
        (vec!["--two-ships", &ships, "--ports", "65531"], "--ports 65531: not a port from 1 to 65530".into()),
    ];
    // Nothing an operator names may be in the data directory's tmp, which is emptied at start.
    let scratch = dir.0.join("ships/tmp/x").to_string_lossy().to_string();
    let mut cases = cases;
    for flag in ["--pretend-ids", "--storage-key-file", "--keyfile", "--azimuth-copy", "--azimuth-snapshot", "--azimuth-write-snapshot"] {
        cases.push((vec!["--dir", &ships, flag, &scratch], format!("{flag} {scratch}: that is in the data directory's tmp")));
    }
    for flag in ["--kernel", "--counter"] {
        cases.push((vec!["--dir", &ships, "--demo", flag, &scratch], format!("{flag} {scratch}: that is in the data directory's tmp")));
    }
    for (args, said) in cases {
        let mut command = serve();
        command.args(&args);
        let (status, stderr) = finished(command, Duration::from_secs(60));
        assert_eq!(status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(&said), "{args:?} said: {stderr}");
    }
    // A name in tmp/ that is a link to a file elsewhere: the link would be removed, so it is
    // refused though what it points at is not in tmp/. And a path that goes up through a
    // directory not yet made is refused as one whose place cannot be told.
    let other = dir.0.join("other");
    fs::create_dir_all(other.join("ships/tmp")).unwrap();
    let link = other.join("ships/tmp/ids");
    std::os::unix::fs::symlink(&good, &link).unwrap();
    let other_ships = other.join("ships").to_string_lossy().to_string();
    let up = other.join("new/../ships/tmp/ids").to_string_lossy().to_string();
    let link = link.to_string_lossy().to_string();
    // A link among the directories of the path, in tmp/, to a directory elsewhere: the whole
    // path leads out of tmp/, but the link would be removed, and the file could then no longer
    // be read by that name (the file itself, elsewhere, stays).
    let safe = dir.0.join("safe");
    fs::create_dir_all(&safe).unwrap();
    fs::write(safe.join("ids"), format!("~zod {}\n", "ab".repeat(32))).unwrap();
    std::os::unix::fs::symlink(&safe, other.join("ships/tmp/keys")).unwrap();
    let through = other.join("ships/tmp/keys/ids").to_string_lossy().to_string();
    // A data directory with no tmp/ yet, and the name written in other letters: on a file
    // system that ignores case it would be tmp/ once made, so it is refused on every one.
    let third = dir.0.join("third/ships");
    fs::create_dir_all(&third).unwrap();
    let third_ships = third.to_string_lossy().to_string();
    let shouted = third.join("TMP/ids").to_string_lossy().to_string();
    for (args, said) in [
        (vec!["--dir", other_ships.as_str(), "--pretend-ids", link.as_str()], format!("--pretend-ids {link}: that is in the data directory's tmp")),
        (vec!["--dir", other_ships.as_str(), "--pretend-ids", through.as_str()], format!("--pretend-ids {through}: that is in the data directory's tmp")),
        (vec!["--dir", third_ships.as_str(), "--pretend-ids", shouted.as_str()], format!("--pretend-ids {shouted}: that is in the data directory's tmp")),
        (vec!["--dir", other_ships.as_str(), "--pretend-ids", up.as_str()], format!("--pretend-ids {up}: it goes up (..) through directories that are not there yet")),
    ] {
        let mut command = serve();
        command.args(&args);
        let (status, stderr) = finished(command, Duration::from_secs(60));
        assert_eq!(status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains(&said), "{args:?} said: {stderr}");
    }
    assert!(other.join("ships/tmp/ids").symlink_metadata().is_ok() && !other.join("new").exists());
    assert!(other.join("ships/tmp/keys").symlink_metadata().is_ok() && fs::read_dir(&third).unwrap().next().is_none());
    // None of those made anything.
    assert!(!dir.0.join("ships").exists());
}

/// The UDP address in the line `serve` prints when its network starts.
fn talking_at(line: &str) -> Option<SocketAddr> {
    line.strip_prefix("Talking to other ships at ")?.split(' ').next()?.parse().ok()
}

#[test]
fn a_ship_killed_and_started_again_is_reached_again_within_seconds_not_after_the_idle_timeout() {
    use runtime::lookup::Lookup;
    use runtime::net::{Directory, NetConfig, Network};
    use runtime::{Config, Manifest, Provide, Runtime, Use};
    let dir = TempDir::new("killed");
    let (kernel, counter) = (fs::read(wasm("kernel")).unwrap(), fs::read(wasm("counter")).unwrap());
    let provide = |interface: &str, remote: bool| Provide { interface: interface.into(), public: false, remote, asked: false };
    let to_far = Use { ship: "sampel-palnet".into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true, ask: false };
    let manifest = Manifest { provides: vec![provide("counter", true), provide("journal", false)], uses: vec![to_far] };
    // ~sampel-palnet runs as a program of its own; ~nec and ~bud run here, so that their networks'
    // settings can be chosen.
    let mut ids = String::new();
    let made = |path: &Path, ship: &str| {
        let rt = Runtime::open(path, Config::default()).unwrap();
        let (kernel, counter) = (rt.add_module(&kernel).unwrap(), rt.add_module(&counter).unwrap());
        rt.create_ship(ship, &kernel).unwrap();
        rt.install(ship, "counter", &counter, &manifest).unwrap();
        (rt.public_key(ship).unwrap(), rt)
    };
    let (key, far) = made(&dir.0.join("far"), "~sampel-palnet");
    drop(far);
    ids += &runtime::pretend::line("~sampel-palnet", &key);
    let (key, nec) = made(&dir.0.join("nec"), "~nec");
    ids += &format!("\n{}", runtime::pretend::line("~nec", &key));
    let (key, bud) = made(&dir.0.join("bud"), "~bud");
    ids += &format!("\n{}\n", runtime::pretend::line("~bud", &key));
    let list = dir.0.join("ids.txt");
    fs::write(&list, ids).unwrap();
    let common = |data: &str| {
        let mut command = serve();
        command.args(["--dir", &dir.0.join(data).to_string_lossy(), "--pretend-ids", &list.to_string_lossy(), "--net", "127.0.0.1:0", "--addr", "127.0.0.1:0"]);
        command
    };
    let mut point = common("point");
    point.args(["--lookup-point", "all"]);
    let mut point = Owned::start(point);
    let at = point.wait_for("the point's address", talking_at);
    let far_program = || {
        let mut far = common("far");
        far.args(["--lookup-at", &at.to_string()]);
        let mut far = Owned::start(far);
        far.wait_for("~sampel-palnet to be announced", |line| line.starts_with("~sampel-palnet is announced").then_some(()));
        far
    };
    let far = far_program();
    let keys = Arc::new(runtime::pretend::PretendIds::open(&list).unwrap());
    let lookup = Lookup { at: vec![(None, at)], ..Lookup::default() };
    // Both notice silence after the usual three seconds. ~nec's requests may take 20 seconds,
    // so one request sees all of it; ~bud's run out of time after one, so the silence is noticed
    // across several of them.
    let (nec, bud) = (Arc::new(nec), Arc::new(bud));
    let _nec_net = Network::start(nec.clone(), Directory::reading(keys.clone()), NetConfig { request_timeout: Duration::from_secs(20), lookup: lookup.clone(), ..NetConfig::default() }).unwrap();
    let _bud_net = Network::start(bud.clone(), Directory::reading(keys), NetConfig { request_timeout: Duration::from_secs(1), lookup, ..NetConfig::default() }).unwrap();
    // A command, and how long until ~sampel-palnet has it (its receipt of it is in hand), with
    // when it was handed over: the moment it was first tried.
    let delivered = |rt: &Runtime, ship: &str, text: &str| {
        let started = Instant::now();
        rt.deliver(ship, "counter", format!("pass ~sampel-palnet journal {text}").as_bytes()).unwrap();
        while rt.outbound_pending(ship).unwrap() > 0 {
            assert!(started.elapsed() < Duration::from_secs(60), "{text} never arrived");
            std::thread::sleep(Duration::from_millis(20));
        }
        (started, started.elapsed())
    };
    let mut far = far;
    // A baseline is taken before each try's two priming commands. Each priming command is sent
    // on the kept connection after the baseline, so that connection cannot run out of idle time
    // (30 seconds) before baseline + 30 s, and a caller's first try after the restart that comes
    // by baseline + 15 s finds it still there, if nothing noticed the silence. A first try later
    // than that proves nothing (the old connection might have run out by itself), so the kill
    // and restart are tried again, three times at most.
    let mut tries = 0;
    let both = loop {
        tries += 1;
        assert!(tries <= 3, "this machine was too slow to tell: three times, a first try came more than 15 seconds after the priming commands began");
        let baseline = Instant::now();
        delivered(&nec, "~nec", &format!("before {tries} from ~nec"));
        delivered(&bud, "~bud", &format!("before {tries} from ~bud"));
        // ~sampel-palnet is killed (its group, which is it), so its connections are never closed,
        // and started again, on another port. Each caller's next command goes first over the
        // connection it holds.
        drop(far);
        far = far_program();
        let (nec_took, bud_took) = std::thread::scope(|scope| {
            let nec = scope.spawn(|| delivered(&nec, "~nec", &format!("after {tries} from ~nec")));
            let bud = scope.spawn(|| delivered(&bud, "~bud", &format!("after {tries} from ~bud")));
            (nec.join().unwrap(), bud.join().unwrap())
        });
        if [nec_took.0, bud_took.0].iter().any(|first| first.duration_since(baseline) > Duration::from_secs(15)) {
            continue;
        }
        break (nec_took.1, bud_took.1);
    };
    // Without noticing the silence, each waited out the connection's 30 seconds of idleness.
    assert!(both.0 < Duration::from_secs(15), "~nec's command took {:?}", both.0);
    assert!(both.1 < Duration::from_secs(15), "~bud's command took {:?}", both.1);
    drop(far);
    drop(point);
}

#[test]
fn a_ship_whose_lookup_point_was_killed_and_started_again_is_found_again_before_the_idle_timeout() {
    use runtime::lookup::Lookup;
    use runtime::net::{Directory, NetConfig, Network};
    use runtime::{Config, Manifest, Provide, Runtime};
    let dir = TempDir::new("point-killed");
    let (kernel, counter) = (fs::read(wasm("kernel")).unwrap(), fs::read(wasm("counter")).unwrap());
    let mut ids = String::new();
    for ship in ["~sampel-palnet", "~nec"] {
        let rt = Runtime::open(dir.0.join(ship.trim_start_matches('~')), Config::default()).unwrap();
        let (kernel, counter) = (rt.add_module(&kernel).unwrap(), rt.add_module(&counter).unwrap());
        rt.create_ship(ship, &kernel).unwrap();
        rt.install(ship, "counter", &counter, &Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true, asked: false }], uses: vec![] }).unwrap();
        ids += &format!("{}\n", runtime::pretend::line(ship, &rt.public_key(ship).unwrap()));
    }
    let list = dir.0.join("ids.txt");
    fs::write(&list, ids).unwrap();
    let common = |data: &str, net: &str| {
        let mut command = serve();
        command.args(["--dir", &dir.0.join(data).to_string_lossy(), "--pretend-ids", &list.to_string_lossy(), "--net", net, "--addr", "127.0.0.1:0"]);
        command
    };
    let point_on = |net: &str| {
        let mut point = common("point", net);
        point.args(["--lookup-point", "all"]);
        let mut point = Owned::start(point);
        let at = point.wait_for("the point's address", talking_at);
        (point, at)
    };
    // A machine so slow that more than half of the 30 idle seconds go by between killing the
    // point and having it back would see the old connection time out by itself, and prove
    // nothing: then everything is started afresh and tried again, three times at most.
    for tries in 1..=3 {
        let (point, at) = point_on("127.0.0.1:0");
        let mut far = common("sampel-palnet", "127.0.0.1:0");
        far.args(["--lookup-at", &at.to_string()]);
        let mut far = Owned::start(far);
        far.wait_for("~sampel-palnet to be announced", |line| line.starts_with("~sampel-palnet is announced").then_some(()));
        // The point is killed, so the connection ~sampel-palnet announces over is never closed,
        // and started again, empty, at the same address.
        let killed = Instant::now();
        drop(point);
        let (_point, again) = point_on(&at.to_string());
        assert_eq!(again, at);
        if killed.elapsed() > Duration::from_secs(15) {
            assert!(tries < 3, "this machine was too slow to tell: three times, the point took more than 15 seconds to come back");
            continue;
        }
        let restarted = Instant::now();
        // A ship that never met ~sampel-palnet looks for it through the point.
        let rt = Arc::new(Runtime::open(dir.0.join("nec"), Config::default()).unwrap());
        let keys = Arc::new(runtime::pretend::PretendIds::open(&list).unwrap());
        // ~nec announces nothing of use (an address given by hand that nothing answers at).
        let lookup = Lookup { at: vec![(None, at)], announce: vec!["127.0.0.1:9".parse().unwrap()], ..Lookup::default() };
        let net = Network::start(rt, Directory::reading(keys), NetConfig { lookup, ..NetConfig::default() }).unwrap();
        while net.ping("~nec", "~sampel-palnet").is_err() {
            assert!(restarted.elapsed() < Duration::from_secs(60), "never found");
            std::thread::sleep(Duration::from_millis(200));
        }
        // Without noticing the point's silence, the old connection lasted its 30 idle seconds
        // first. With it: the packet sent every 15 seconds goes unanswered, and 3 seconds later
        // the connection is made again and the ship announced.
        assert!(killed.elapsed() < Duration::from_secs(27), "found again {:?} after the point was killed", killed.elapsed());
        return;
    }
}
