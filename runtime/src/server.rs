//! How clients reach ships: a small HTTP server in front of a runtime.
//!
//! A phone app or a browser signs in to one ship with a sign-in code and is given a token of
//! its own. With that token it acts as the ship's owner: it reads the ship's logs, waits for
//! them to grow, and sends commands. Apps send the token in an `Authorization` header and get
//! Protocol Buffers back; a browser keeps it in a cookie and gets a sign-in page.
//!
//! The server reads HTTP itself, and does only what it needs: one request per connection, a
//! body only with a stated length, and a hard limit on every size and every wait. Anything
//! outside that is refused. It speaks plain HTTP and is meant to sit behind a proxy that
//! provides TLS, limits how fast one caller may ask, and may map a hostname to a ship (see
//! `ServerConfig::ship_host_suffix`). Every ship served on one origin trusts every page on that
//! origin, so nothing that is not the server's own should ever be served there.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ship_proto::{Device, DeviceList, EntryList, LogHead, Message, SignInReply, SignInRequest, Trimmed};

use crate::{canonical_ship, lock, Error, Position, Rejection, Runtime};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Where to listen, such as `127.0.0.1:8080`. Port 0 picks a free one.
    pub addr: String,
    /// With `Some(".example.net")`, a request for host `zod.example.net` is for ship `zod`, and
    /// paths start at the ship. Without it, or for any other host, the ship is named in the
    /// path: `/ships/zod/...`. It must start with a dot.
    pub ship_host_suffix: Option<String>,
    /// Threads handling requests. A request that waits for a log to grow holds one, so at most
    /// half of them may be waiting at once; the rest are answered straight away. Connections
    /// beyond what the threads can take queue up, a few per thread, and past that are dropped.
    pub workers: usize,
    /// Mark the sign-in cookie so browsers only send it over HTTPS. Turn this on whenever the
    /// server is reached through TLS.
    pub secure_cookies: bool,
    /// The longest a request may wait for new log entries.
    pub max_wait: Duration,
    /// The largest request body accepted.
    pub max_body_bytes: usize,
    /// How long a client has to send its whole request, and to take the whole answer. A client
    /// that is slower is cut off, so that slow or silent connections cannot hold the threads.
    pub io_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            addr: "127.0.0.1:0".into(),
            ship_host_suffix: None,
            workers: 16,
            secure_cookies: false,
            max_wait: Duration::from_secs(30),
            max_body_bytes: 1 << 20,
            io_timeout: Duration::from_secs(10),
        }
    }
}

/// The most a request's first line and headers may take.
const MAX_HEAD_BYTES: usize = 16 << 10;
const MAX_HEADERS: usize = 100;

/// A running server. Dropping it stops it, cutting off any connection still open.
pub struct Server {
    addr: SocketAddr,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

struct Shared {
    runtime: Arc<Runtime>,
    cfg: ServerConfig,
    stop: AtomicBool,
    /// Requests currently waiting for a log to grow.
    waiting: AtomicUsize,
    /// The connections being handled, so that stopping the server can cut them off.
    open: Mutex<HashMap<usize, TcpStream>>,
    next: AtomicUsize,
}

impl Server {
    pub fn start(runtime: Arc<Runtime>, cfg: ServerConfig) -> io::Result<Server> {
        // Without the dot, `.net` style matching turns into `evilzod` matching `zod`.
        if cfg.ship_host_suffix.as_deref().is_some_and(|suffix| !suffix.starts_with('.') || suffix.len() < 2) {
            return Err(io::Error::other("ship_host_suffix must start with a dot, as in \".example.net\""));
        }
        let listener = TcpListener::bind(cfg.addr.as_str())?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let workers = cfg.workers.max(2);
        let shared = Arc::new(Shared {
            runtime,
            cfg,
            stop: AtomicBool::new(false),
            waiting: AtomicUsize::new(0),
            open: Mutex::new(HashMap::new()),
            next: AtomicUsize::new(0),
        });
        // Connections wait here for a free thread. When it is full, new ones are dropped.
        let (queue, waiting) = mpsc::sync_channel::<TcpStream>(workers * 4);
        let waiting = Arc::new(Mutex::new(waiting));

        let mut threads = Vec::with_capacity(workers + 1);
        let accepting = shared.clone();
        threads.push(std::thread::spawn(move || {
            while !accepting.stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => drop(queue.try_send(stream)),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        }));
        for _ in 0..workers {
            let (shared, waiting) = (shared.clone(), waiting.clone());
            threads.push(std::thread::spawn(move || {
                while !shared.stop.load(Ordering::Relaxed) {
                    let next = lock(&waiting).recv_timeout(Duration::from_millis(50));
                    match next {
                        Ok(stream) => serve(&shared, stream),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            }));
        }
        Ok(Server { addr, shared, threads })
    }

    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // The flag is set before the list of connections is looked at, and a connection joins
        // that list only while holding its lock and seeing the flag clear. So every connection
        // is either on the list here, and cut off, or never started.
        self.shared.stop.store(true, Ordering::SeqCst);
        // A thread stuck reading from or writing to a client is released by closing the
        // connection under it.
        for stream in lock(&self.shared.open).values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// A connection's place on the list of those being handled, given up however handling ends.
struct Listed<'a> {
    shared: &'a Shared,
    id: usize,
}

impl<'a> Listed<'a> {
    /// `None` if the server is stopping, or the connection cannot be put on the list.
    fn new(shared: &'a Shared, stream: &TcpStream) -> Option<Listed<'a>> {
        let copy = stream.try_clone().ok()?;
        let id = shared.next.fetch_add(1, Ordering::Relaxed);
        let mut open = lock(&shared.open);
        if shared.stop.load(Ordering::SeqCst) {
            return None;
        }
        open.insert(id, copy);
        Some(Listed { shared, id })
    }
}

impl Drop for Listed<'_> {
    fn drop(&mut self) {
        lock(&self.shared.open).remove(&self.id);
    }
}

/// One request, read whole.
struct Request {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// The first header of this name, whatever its capitals.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name)).count()
    }
}

/// Pages tell the browser to say where a request came from only to the ship itself. Other
/// sites then never see the ship's addresses. It must not be `no-referrer`: with that, a
/// browser reports the origin of a form sent from the ship's own page as `null`, and the check
/// in `from_own_page` would refuse the ship's own buttons.
const REFERRER_POLICY: &str = "same-origin";

/// What goes back to the client.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, kind: &str, body: Vec<u8>) -> Reply {
        // Nothing here is for a shared cache, and nothing here should be put in a frame.
        let headers = vec![
            ("Content-Type", kind.to_string()),
            ("Cache-Control", "no-store".to_string()),
            ("X-Content-Type-Options", "nosniff".to_string()),
        ];
        Reply { status, headers, body }
    }

    fn text(status: u16, message: &str) -> Reply {
        Reply::new(status, "text/plain; charset=utf-8", message.as_bytes().to_vec())
    }

    fn proto(status: u16, message: &impl Message) -> Reply {
        Reply::new(status, "application/x-protobuf", message.encode_to_vec())
    }

    fn html(status: u16, page: String) -> Reply {
        Reply::new(status, "text/html; charset=utf-8", page.into_bytes())
            .with("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            .with("Referrer-Policy", REFERRER_POLICY)
    }

    fn redirect(to: &str) -> Reply {
        Reply::text(303, "see other").with("Location", to).with("Referrer-Policy", REFERRER_POLICY)
    }

    fn with(mut self, name: &'static str, value: impl Into<String>) -> Reply {
        self.headers.push((name, value.into()));
        self
    }

    /// The answer as it goes down the wire. The connection always closes after it. An answer
    /// to a HEAD request carries no body, whatever the answer is.
    fn encode(&self, head_only: bool) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            204 => "No Content",
            303 => "See Other",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            417 => "Expectation Failed",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            413 => "Content Too Large",
            422 => "Unprocessable Content",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            501 => "Not Implemented",
            _ => "Error",
        };
        let mut out = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (name, value) in &self.headers {
            // A value can never start a new header line, whatever it was built from.
            if !value.contains(['\r', '\n']) {
                out += &format!("{name}: {value}\r\n");
            }
        }
        // An answer that says there is no content does not also give a length for it.
        if self.status == 204 {
            out += "Connection: close\r\n\r\n";
            return out.into_bytes();
        }
        out += &format!("Content-Length: {}\r\nConnection: close\r\n\r\n", self.body.len());
        let body: &[u8] = if head_only { &[] } else { &self.body };
        [out.as_bytes(), body].concat()
    }
}

/// Handle one connection: read one request, answer it, close.
fn serve(shared: &Shared, mut stream: TcpStream) {
    // The listener does not block, and on some systems a connection it hands over inherits that.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let Some(_listed) = Listed::new(shared, &stream) else { return };
    let deadline = Instant::now() + shared.cfg.io_timeout;
    let mut head_only = false;
    let (reply, refused) = match read_request(shared, &mut stream, deadline, &mut head_only) {
        Ok(request) => (Some(respond(shared, &request)), false),
        Err(reply) => (reply, true),
    };
    if let Some(reply) = reply {
        // The client gets as long again to take the whole answer as it had to send the request.
        let sent = write_by(&mut stream, &reply.encode(head_only), Instant::now() + shared.cfg.io_timeout);
        // A request refused part way may still be arriving. Closing on top of it can make the
        // client's system throw the answer away, so what is left is let through for a moment
        // and discarded: never kept, and only for a short, fixed time.
        if refused && sent.is_ok() && stream.shutdown(Shutdown::Write).is_ok() {
            let (until, mut scrap) = (Instant::now() + Duration::from_millis(500), [0u8; 16 << 10]);
            while read_some(&mut stream, &mut scrap, until).is_some() {}
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// Send all of `bytes` by `deadline`, however slowly the client takes them.
///
/// The connection is switched so that a write never waits: it takes what there is room for and
/// returns. Waiting for room is done here, against the clock. Letting the write itself wait
/// with a time limit would not do, because some systems start that limit afresh every time the
/// client takes a little, so a client that trickles could hold the thread far past the deadline.
fn write_by(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let sent = send_by(stream, bytes, deadline);
    // Reading afterwards relies on waits with a time limit, which need the usual mode back.
    stream.set_nonblocking(false)?;
    sent
}

fn send_by(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut sent = 0;
    while sent < bytes.len() {
        // Looked at before every attempt, not only when one has to wait: a client with room
        // to spare is held to the same deadline as one without.
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(wrote) => sent += wrote,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait_for_room(stream, deadline)?,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Wait until the client can be sent more, or the connection has failed, but not past `deadline`.
fn wait_for_room(stream: &TcpStream, deadline: Instant) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let mut watched = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
    // Rounded up, so that a sliver of time left does not turn into a wait of no time at all.
    let millis = (left.as_millis() + 1).min(i32::MAX as u128) as libc::c_int;
    // SAFETY: `watched` is one valid pollfd, and it outlives the call.
    match unsafe { libc::poll(&mut watched, 1, millis) } {
        0 => Err(io::ErrorKind::TimedOut.into()),
        -1 if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted => Err(io::Error::last_os_error()),
        // Room, a failure the next write will report, or an interruption: look again.
        _ => Ok(()),
    }
}

/// Read from the client until `deadline`, however slowly it sends. `None` once time is up or
/// the client has gone.
fn read_some(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Option<usize> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
        return None;
    }
    stream.read(buf).ok().filter(|read| *read > 0)
}

/// Read one whole request. `Err(Some(reply))` refuses it with a reason; `Err(None)` means the
/// client went away or took too long, and there is nobody to answer. `head_only` is set as
/// soon as the request is seen to be a HEAD, so that even a refusal goes back without a body.
fn read_request(shared: &Shared, stream: &mut TcpStream, deadline: Instant, head_only: &mut bool) -> Result<Request, Option<Reply>> {
    let refuse = |status: u16, why: &str| Err(Some(Reply::text(status, why)));
    let (mut raw, mut chunk, mut scanned) = (Vec::<u8>::new(), [0u8; 4096], 0usize);
    let head_end = loop {
        // Known from the first bytes, so that a refusal on anything after them, even one made
        // before the request can be read as text, still goes back without a body.
        *head_only = raw.starts_with(b"HEAD ");
        // Only what is new is searched, so a request sent a byte at a time costs no more to
        // read. The limit holds however the bytes arrive: in one piece, or a little at a time.
        let from = scanned.saturating_sub(3);
        let end = raw[from..].windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + from);
        scanned = raw.len();
        if end.unwrap_or(raw.len()) > MAX_HEAD_BYTES {
            return refuse(431, "the request's headers are too large");
        }
        if let Some(end) = end {
            break end;
        }
        let read = read_some(stream, &mut chunk, deadline).ok_or(None)?;
        raw.extend_from_slice(&chunk[..read]);
    };
    let Ok(head) = std::str::from_utf8(&raw[..head_end]) else { return refuse(400, "the request is not text") };
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(url), Some(version), None) = (first.next(), first.next(), first.next(), first.next()) else {
        return refuse(400, "not an HTTP request");
    };
    let plain = |text: &str| text.bytes().all(|b| (0x21..0x7f).contains(&b));
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !url.starts_with('/') || !plain(url) || !plain(method) {
        return refuse(400, "not an HTTP request");
    }
    // Header names are plain words and values are plain text. Anything a stricter reader in
    // front of this one might see differently, such as a stray line break, a tab before the
    // colon, or a control character, is refused outright.
    let word = |name: &str| !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    let text = |value: &str| value.chars().all(|c| c == '\t' || !c.is_control());
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { return refuse(400, "a header is malformed") };
        if headers.len() >= MAX_HEADERS || !word(name) || !text(value) {
            return refuse(400, "a header is malformed");
        }
        headers.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    let mut request = Request { method: method.to_string(), url: url.to_string(), headers, body: Vec::new() };

    // A body is taken only when the request says exactly how long it is, once. Anything else
    // leaves room for two readers to disagree about where the request ends.
    if request.count("Transfer-Encoding") > 0 {
        return refuse(501, "send the body with a Content-Length");
    }
    if request.count("Content-Length") > 1 || request.count("Host") > 1 {
        return refuse(400, "a header is given twice");
    }
    if version == "HTTP/1.1" && request.count("Host") == 0 {
        return refuse(400, "the request names no host");
    }
    let length = match request.header("Content-Length") {
        None => 0,
        // Digits only: no sign, no spaces, nothing a different reader might take another way.
        Some(stated) if !stated.is_empty() && stated.bytes().all(|b| b.is_ascii_digit()) => match stated.parse::<u64>() {
            Ok(length) => length,
            // Too many digits to hold is certainly too large.
            Err(_) => return refuse(413, "the request is too large"),
        },
        Some(_) => return refuse(400, "the Content-Length is not a number"),
    };
    let expects = request.header("Expect").map(|expect| expect.eq_ignore_ascii_case("100-continue"));
    if expects == Some(false) {
        return refuse(417, "that expectation is not supported");
    }
    // Refused on what it claims, before a byte of it is read or any room is made for it.
    if length > shared.cfg.max_body_bytes as u64 {
        return refuse(413, "the request is too large");
    }
    let length = length as usize;
    let mut body = raw.split_off(head_end + 4);
    if body.len() > length {
        return refuse(400, "more was sent than the request said");
    }
    if body.len() < length && expects == Some(true) {
        write_by(stream, b"HTTP/1.1 100 Continue\r\n\r\n", deadline).map_err(|_| None)?;
    }
    while body.len() < length {
        let want = (length - body.len()).min(chunk.len());
        let read = read_some(stream, &mut chunk[..want], deadline).ok_or(None)?;
        body.extend_from_slice(&chunk[..read]);
    }
    request.body = body;
    Ok(request)
}

/// Turn `%41` and `+` back into the characters they stand for. `None` if it is not valid text.
fn decode(text: &str, plus_is_space: bool) -> Option<String> {
    let (bytes, mut out, mut i) = (text.as_bytes(), Vec::with_capacity(text.len()), 0);
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = text.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(pair, 16).ok()?);
                i += 2;
            }
            b'+' if plus_is_space => out.push(b' '),
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// The value of `name` in a query string or a submitted form.
fn field(pairs: &str, name: &str) -> Option<String> {
    pairs.split('&').filter_map(|pair| pair.split_once('=')).find(|(key, _)| *key == name).and_then(|(_, value)| decode(value, true))
}

/// The host a request was sent to, without its port, in lower case.
fn host_name(host: &str) -> String {
    let name = host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(name, _)| name);
    name.to_ascii_lowercase()
}

/// Which ship a request is for. Returns its name, the path prefix that leads to it (empty when
/// the hostname names the ship), and the rest of the path.
fn locate(cfg: &ServerConfig, host: Option<&str>, path: &str) -> Option<(String, String, String)> {
    let by_host = host.zip(cfg.ship_host_suffix.as_deref()).and_then(|(host, suffix)| {
        let host = host_name(host);
        let name = host.strip_suffix(&suffix.to_ascii_lowercase())?;
        canonical_ship(name).ok()
    });
    if let Some(ship) = by_host {
        return Some((ship, String::new(), path.to_string()));
    }
    let after = path.strip_prefix("/ships/")?;
    let (segment, rest) = after.split_once('/').map_or((after, "/".to_string()), |(segment, rest)| (segment, format!("/{rest}")));
    // The prefix is rebuilt from the checked name, never echoed from the request.
    let ship = canonical_ship(&decode(segment, false)?).ok()?;
    let root = format!("/ships/{ship}");
    Some((ship, root, rest))
}

/// How a request proved who it is.
#[derive(Clone, Copy, PartialEq)]
enum Via {
    Header,
    Cookie,
}

const COOKIE: &str = "ship_token";

/// The tokens a request offers: the one in an `Authorization` header, or else those in its
/// cookies. A browser can hold several cookies of the same name set for different paths or by
/// a parent domain, and sends them all, so each is tried. Only a few, since each costs a lookup.
fn credentials(request: &Request) -> Option<(Vec<String>, Via)> {
    if let Some(value) = request.header("Authorization") {
        let token = value.strip_prefix("Bearer ").unwrap_or_default().trim().to_string();
        return Some((vec![token], Via::Header));
    }
    let cookies = request.header("Cookie")?;
    let tokens: Vec<String> = cookies
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == COOKIE)
        .map(|(_, token)| token.to_string())
        .take(4)
        .collect();
    (!tokens.is_empty()).then_some((tokens, Via::Cookie))
}

fn cookie(shared: &Shared, root: &str, token: &str, keep: bool) -> String {
    let path = if root.is_empty() { "/" } else { root };
    let age = if keep { 365 * 24 * 60 * 60 } else { 0 };
    let secure = if shared.cfg.secure_cookies { "; Secure" } else { "" };
    format!("{COOKIE}={token}; Path={path}; Max-Age={age}; HttpOnly; SameSite=Strict{secure}")
}

/// Whether a request that came with a cookie was made by one of the ship's own pages. A
/// browser attaches cookies by itself, so without this check any other site the owner has
/// open could send commands to the ship. Browsers say where a request came from in two
/// headers that a page cannot set or change: `Sec-Fetch-Site`, and `Origin`. Either one saying
/// the request is the ship's own is enough; saying nothing is not.
fn from_own_page(request: &Request) -> bool {
    if let Some(site) = request.header("Sec-Fetch-Site") {
        return site.eq_ignore_ascii_case("same-origin");
    }
    let (Some(origin), Some(host)) = (request.header("Origin"), request.header("Host")) else { return false };
    origin.split_once("://").is_some_and(|(_, from)| from.eq_ignore_ascii_case(host))
}

/// What a failed call looks like to a client. Nothing internal is passed on.
fn failure(error: Error) -> Reply {
    match error {
        // A ship that does not exist answers as one the caller is not signed in to.
        Error::NotSignedIn | Error::UnknownShip(_) => Reply::text(401, "not signed in"),
        Error::SignInRefused => Reply::text(401, "that sign-in code is not accepted"),
        Error::SignInLocked(millis) => Reply::text(429, "too many wrong sign-in codes; try again later")
            .with("Retry-After", millis.div_ceil(1000).to_string()),
        Error::TooMany(what) => Reply::text(409, &format!("this ship already has as many {what} as it may")),
        Error::LogTrimmed(base) => Reply::proto(410, &Trimmed { base }),
        Error::InvalidName(_) => Reply::text(400, "not a valid name"),
        Error::UnknownAgent(_) => Reply::text(404, "no such agent"),
        Error::Rejected(rejection) => {
            let why = match rejection {
                Rejection::OutOfFuel => "the command used up its compute budget".to_string(),
                Rejection::Timeout => "the command ran too long".to_string(),
                Rejection::Denied(why) => format!("not permitted: {why}"),
                Rejection::Limit(why) => format!("limit exceeded: {why}"),
                Rejection::Trap(_) => "the command failed".to_string(),
            };
            Reply::text(422, &why)
        }
        _ => Reply::text(500, "the ship could not answer"),
    }
}

fn respond(shared: &Shared, request: &Request) -> Reply {
    let (path, query) = request.url.split_once('?').unwrap_or((&request.url, ""));
    let Some((ship, root, rest)) = locate(&shared.cfg, request.header("Host"), path) else {
        return Reply::text(404, "not found");
    };
    let method = request.method.as_str();
    let runtime = &shared.runtime;
    // Split first and decode after, so that a name holding an encoded slash stays one name.
    let Some(parts) = rest.trim_start_matches('/').split('/').map(|part| decode(part, false)).collect::<Option<Vec<String>>>() else {
        return Reply::text(400, "the address is not valid text");
    };
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    // A method this address does not take is refused, saying which it does take.
    if let Some(allow) = allowed(&parts) {
        if !allow.split(", ").any(|takes| takes == method) {
            return Reply::text(405, "method not allowed").with("Allow", allow);
        }
    }

    // Signing in is the one thing a request can do without a token. The address is the one
    // just split and decoded, the same one the methods above were looked up for.
    if parts.as_slice() == ["signin"] {
        return match method {
            "GET" => match field(query, "code") {
                // A sign-in link: the code is in the address, so only a one-time code will do.
                Some(code) => sign_in(shared, &ship, &root, &code, &field(query, "label").unwrap_or_default(), true, false),
                None => Reply::html(200, signin_page(&ship, &root, None)),
            },
            "POST" if request.header("Content-Type").is_some_and(|kind| kind.starts_with("application/x-protobuf")) => {
                let Ok(asked) = SignInRequest::decode(&*request.body) else { return Reply::text(400, "not a sign-in request") };
                sign_in(shared, &ship, &root, &asked.code, &asked.label, false, true)
            }
            "POST" => {
                let form = String::from_utf8_lossy(&request.body);
                let code = field(&form, "code").unwrap_or_default();
                sign_in(shared, &ship, &root, &code, &field(&form, "label").unwrap_or_default(), true, true)
            }
            _ => Reply::text(405, "method not allowed").with("Allow", "GET, POST"),
        };
    }

    // Everything else is the owner's, so the request must come from a signed-in device.
    let browsing = method == "GET" && parts.as_slice() == [""];
    let signed_out = || if browsing { Reply::redirect(&format!("{root}/signin")) } else { Reply::text(401, "not signed in") };
    let Some((tokens, via)) = credentials(request) else { return signed_out() };
    let mut device = None;
    for token in &tokens {
        match runtime.authenticate(&ship, token) {
            Ok(found) => {
                device = Some(found);
                break;
            }
            Err(Error::NotSignedIn | Error::UnknownShip(_)) => {}
            Err(error) => return failure(error),
        }
    }
    let Some(device) = device else { return signed_out() };
    if via == Via::Cookie && method != "GET" && !from_own_page(request) {
        return Reply::text(403, "this request did not come from the ship's own page");
    }

    let done = |result: Result<Reply, Error>| result.unwrap_or_else(failure);
    match (method, parts.as_slice()) {
        ("GET", [""]) => done(runtime.devices(&ship).map(|devices| Reply::html(200, home_page(&ship, &root, &device, &devices)))),
        ("GET", ["devices"]) => {
            done(runtime.devices(&ship).map(|devices| Reply::proto(200, &DeviceList { devices, current: device.id })))
        }
        ("POST", ["signout"]) => {
            let gone = runtime.revoke_device(&ship, device.id);
            done(gone.map(|_| match via {
                Via::Cookie => Reply::redirect(&format!("{root}/signin")).with("Set-Cookie", cookie(shared, &root, "", false)),
                Via::Header => Reply::text(204, ""),
            }))
        }
        ("POST", ["devices", id, "revoke"]) | ("DELETE", ["devices", id]) => {
            let Ok(id) = id.parse::<u64>() else { return Reply::text(400, "not a device number") };
            done(runtime.revoke_device(&ship, id).map(|gone| match (gone, via) {
                (false, _) => Reply::text(404, "no such device"),
                (true, Via::Cookie) => Reply::redirect(&format!("{root}/")),
                (true, Via::Header) => Reply::text(204, ""),
            }))
        }
        ("GET", ["key"]) => done(runtime.public_key(&ship).map(|key| Reply::new(200, "application/octet-stream", key.to_vec()))),
        ("GET", ["logs", agent, log, "head"]) => done(runtime.log_head(&ship, agent, log).map(|head| Reply::proto(200, &log_head(head)))),
        ("GET", ["logs", agent, log, "checkpoint"]) => done(runtime.log_checkpoint(&ship, agent, log).map(|found| match found {
            Some(checkpoint) => Reply::proto(200, &checkpoint),
            None => Reply::text(404, "this log has no checkpoint"),
        })),
        ("GET", ["logs", agent, log, "entries"]) => done(entries(shared, &ship, agent, log, query)),
        ("POST", ["agents", agent, "command"]) => {
            done(runtime.deliver(&ship, agent, &request.body).map(|outcome| Reply::new(200, "application/octet-stream", outcome.reply)))
        }
        _ => Reply::text(404, "not found"),
    }
}

/// The methods an address takes, if it is one this server has.
fn allowed(parts: &[&str]) -> Option<&'static str> {
    match parts {
        ["signin"] => Some("GET, POST"),
        [""] | ["devices"] | ["key"] | ["logs", _, _, "head" | "checkpoint" | "entries"] => Some("GET"),
        ["signout"] | ["devices", _, "revoke"] | ["agents", _, "command"] => Some("POST"),
        ["devices", _] => Some("DELETE"),
        _ => None,
    }
}

fn log_head(head: Option<Position>) -> LogHead {
    head.map_or_else(LogHead::default, |(seq, hash)| LogHead { seq, hash: hash.to_vec() })
}

/// Counts a request among those waiting for a log to grow, for as long as it is held.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Entries of a log after a given number, optionally waiting a while for there to be some.
fn entries(shared: &Shared, ship: &str, agent: &str, log: &str, query: &str) -> Result<Reply, Error> {
    let number = |name: &str| field(query, name).and_then(|value| value.parse::<u64>().ok());
    let after = number("after").unwrap_or(0);
    let max_bytes = number("max_bytes").unwrap_or(256 << 10).min(1 << 20) as usize;
    let wait = Duration::from_secs(number("wait").unwrap_or(0).min(3600)).min(shared.cfg.max_wait);
    if !wait.is_zero() {
        // Each waiting request holds a thread, so only so many may wait; the rest are answered
        // with what there is, and the client asks again.
        let limit = shared.cfg.workers.max(2) / 2;
        let slot = Waiting(&shared.waiting);
        if shared.waiting.fetch_add(1, Ordering::SeqCst) < limit {
            // In short stretches, so that a server being stopped is not kept waiting.
            let deadline = Instant::now() + wait;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() || shared.stop.load(Ordering::Relaxed) {
                    break;
                }
                let head = shared.runtime.wait_log(ship, agent, log, after, left.min(Duration::from_millis(250)))?;
                if head.is_some_and(|(seq, _)| seq > after) {
                    break;
                }
            }
        }
        drop(slot);
    }
    let entries = shared.runtime.log_entries(ship, agent, log, after, max_bytes)?;
    // Read after the entries, so it is never older than they are. If it is newer, the reader
    // sees it has not caught up and asks again.
    let head = shared.runtime.log_head(ship, agent, log)?;
    Ok(Reply::proto(200, &EntryList { entries, head: Some(log_head(head)) }))
}

/// Trade a sign-in code for a token. `access_code_ok` says whether the ship's reusable access
/// code will do, or only a one-time code.
fn sign_in(shared: &Shared, ship: &str, root: &str, code: &str, label: &str, browser: bool, access_code_ok: bool) -> Reply {
    let label = if label.trim().is_empty() && browser { "Browser" } else { label };
    let runtime = &shared.runtime;
    let attempt = if access_code_ok { runtime.sign_in(ship, code, label) } else { runtime.sign_in_once(ship, code, label) };
    // A ship that does not exist refuses a code as one that does. This keeps a stray guess
    // from learning anything; it does not hide a ship from someone determined, since a ship
    // that exists locks after enough wrong codes and one that does not never will.
    let signed_in = attempt.map_err(|error| match error {
        Error::UnknownShip(_) => Error::SignInRefused,
        other => other,
    });
    match signed_in {
        // Straight on to the ship's page, so the code does not stay in the address bar.
        Ok((token, _)) if browser => Reply::redirect(&format!("{root}/")).with("Set-Cookie", cookie(shared, root, &token, true)),
        Ok((token, device)) => Reply::proto(200, &SignInReply { token, device: Some(device) }),
        Err(error) if browser => {
            let reply = failure(error);
            let message = String::from_utf8_lossy(&reply.body).into_owned();
            let mut page = Reply::html(reply.status, signin_page(ship, root, Some(&message)));
            page.headers.extend(reply.headers.into_iter().filter(|(name, _)| *name == "Retry-After"));
            page
        }
        Err(error) => failure(error),
    }
}

/// Make text safe to put inside a page.
fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            other => other.to_string(),
        })
        .collect()
}

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#222}\
input,button{font:inherit;padding:.4rem .6rem}label{display:block;margin:.8rem 0 .2rem}input{width:100%;box-sizing:border-box}\
button{margin-top:1rem}li{margin:.4rem 0}form.inline{display:inline}.error{color:#a00}.muted{color:#666}";

fn page(title: &str, content: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head><body>{content}</body></html>",
        escape(title)
    )
}

fn signin_page(ship: &str, root: &str, problem: Option<&str>) -> String {
    let problem = problem.map(|why| format!("<p class=\"error\">{}</p>", escape(why))).unwrap_or_default();
    let content = format!(
        "<h1>Sign in to ~{ship}</h1>{problem}\
         <form method=\"post\" action=\"{root}/signin\">\
         <label for=\"code\">Access code</label><input id=\"code\" name=\"code\" type=\"password\" autocomplete=\"current-password\" required autofocus>\
         <label for=\"label\">Name for this browser</label><input id=\"label\" name=\"label\" value=\"Browser\" maxlength=\"64\">\
         <button type=\"submit\">Sign in</button></form>\
         <p class=\"muted\">Use the ship's access code, or a one-time sign-in code.</p>",
        ship = escape(ship),
        root = escape(root),
    );
    page(&format!("Sign in to ~{ship}"), &content)
}

fn home_page(ship: &str, root: &str, current: &Device, devices: &[Device]) -> String {
    let rows: String = devices
        .iter()
        .map(|device| {
            let this = if device.id == current.id { " <span class=\"muted\">(this one)</span>" } else { "" };
            format!(
                "<li>{label}{this} <form class=\"inline\" method=\"post\" action=\"{root}/devices/{id}/revoke\">\
                 <button type=\"submit\">Sign out</button></form></li>",
                label = escape(&device.label),
                root = escape(root),
                id = device.id,
            )
        })
        .collect();
    let content = format!(
        "<h1>~{ship}</h1><p>You are signed in as <strong>{label}</strong>.</p>\
         <h2>Signed-in devices</h2><ul>{rows}</ul>\
         <form method=\"post\" action=\"{root}/signout\"><button type=\"submit\">Sign out of this browser</button></form>",
        ship = escape(ship),
        label = escape(&current.label),
        root = escape(root),
    );
    page(&format!("~{ship}"), &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Once the time is up nothing more is sent, even to a client with room to take it.
    #[test]
    fn nothing_is_sent_once_the_time_is_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server_side, _) = listener.accept().unwrap();
        assert!(write_by(&mut server_side, b"on time", Instant::now() + Duration::from_secs(5)).is_ok());
        let late = write_by(&mut server_side, b"too late", Instant::now());
        assert_eq!(late.unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(server_side);
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"on time");
    }

    /// A client that takes an answer a little at a time is cut off when the time for the whole
    /// answer is up, however steadily it keeps taking.
    #[test]
    fn an_answer_has_one_deadline_however_slowly_it_is_taken() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server_side, _) = listener.accept().unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let reading = finished.clone();
        std::thread::spawn(move || {
            // Slow, but never silent for long, and taking far less each time than one write
            // offers. A time limit on each write alone would never trip, and on some systems
            // neither would one on a write of any size.
            let mut buf = [0u8; 2 << 10];
            while !reading.load(Ordering::Relaxed) && matches!(client.read(&mut buf), Ok(1..)) {
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        // The write runs on a thread of its own, so that if it never gave up this test would
        // fail instead of hanging.
        let (report, outcome) = mpsc::channel();
        std::thread::spawn(move || {
            let answer = vec![7u8; 64 << 20];
            let started = Instant::now();
            let sent = write_by(&mut server_side, &answer, Instant::now() + Duration::from_millis(600));
            // The connection is left in its usual mode for whatever reads come next: a read
            // with a time limit waits that long, where one that never waits would return at once.
            server_side.set_read_timeout(Some(Duration::from_millis(60))).unwrap();
            let waited = Instant::now();
            let usual_mode = server_side.read(&mut [0u8; 1]).is_err() && waited.elapsed() >= Duration::from_millis(50);
            let _ = report.send((sent.is_err(), started.elapsed(), usual_mode));
        });
        let (gave_up, took, usual_mode) = outcome.recv_timeout(Duration::from_secs(10)).expect("the write never gave up");
        finished.store(true, Ordering::Relaxed);
        assert!(gave_up, "the whole answer was taken");
        assert!(took >= Duration::from_millis(550) && took < Duration::from_millis(1500), "took {took:?}");
        assert!(usual_mode);
    }
}
