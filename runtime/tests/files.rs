//! Files on the ship: the store, its HTTP routes, and files in exports.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use runtime::files::{chunk_count, id_of, leaf, CHUNK};
use runtime::server::{Server, ServerConfig};
use runtime::{seal, Config, Durability, Error, FileError, FilesKept, Manifest, Provide, Runtime, StorageKey};
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

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-files-{}-{label}", std::process::id()));
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

const CODE: &str = "test-test-test-test-test-test-test-test";

/// The counter agent offers `counter`. The same module runs twice: as `counter` and `keeper`.
fn manifest() -> Manifest {
    Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: false, asked: false }], uses: vec![] }
}

/// A runtime with `~zod`, running the counter module as `counter` and as `keeper`.
fn boot(dir: &TempDir, cfg: Config) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let (kernel, counter) = (rt.add_module(&wasm("kernel")).unwrap(), rt.add_module(&wasm("counter")).unwrap());
    rt.create_ship("~zod", &kernel).unwrap();
    for agent in ["counter", "keeper"] {
        rt.install("~zod", agent, &counter, &manifest()).unwrap();
    }
    rt
}

fn serve(dir: &TempDir, cfg: Config, server: ServerConfig) -> (Arc<Runtime>, Server) {
    let rt = Arc::new(boot(dir, cfg));
    let server = Server::start(rt.clone(), server).unwrap();
    (rt, server)
}

/// An `Authorization` header for a device newly signed in to `ship`.
fn device(rt: &Runtime, ship: &str) -> String {
    let code = rt.new_signin_code(ship, Duration::from_secs(60)).unwrap();
    format!("Bearer {}", rt.sign_in(ship, &code, "test").unwrap().0)
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

fn http(server: &Server, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Answer {
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.0\r\nHost: {}\r\n", server.addr());
    for (name, value) in headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).unwrap();
    let _ = stream.write_all(body);
    read_answer(stream)
}

fn read_answer(mut stream: std::net::TcpStream) -> Answer {
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let top = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = top.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines.filter_map(|line| line.split_once(": ")).map(|(name, value)| (name.to_string(), value.to_string())).collect();
    Answer { status, headers, body: raw[split + 4..].to_vec() }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Contents that differ in every chunk, made from `seed`.
fn contents(length: usize, seed: u8) -> Vec<u8> {
    (0..length).map(|i| (i as u64).wrapping_mul(2654435761).wrapping_add(seed as u64 * 97) as u8 ^ (i >> 20) as u8).collect()
}

/// Start an upload over HTTP: its name and how many chunks it takes.
fn start(server: &Server, auth: &str, agent: &str, length: u64, media_type: &str) -> Answer {
    let asked = ship_proto::UploadRequest { length, media_type: media_type.into() }.encode_to_vec();
    http(server, "POST", &format!("/ships/zod/agents/{agent}/files/uploads"), &[("Authorization", auth)], &asked)
}

fn started(server: &Server, auth: &str, agent: &str, length: u64, media_type: &str) -> (String, u64) {
    let answer = start(server, auth, agent, length, media_type);
    assert_eq!(answer.status, 200, "{}", answer.text());
    let reply = ship_proto::UploadReply::decode(&*answer.body).unwrap();
    (reply.upload, reply.chunks)
}

fn put(server: &Server, auth: &str, agent: &str, upload: &str, n: u64, chunk: &[u8]) -> Answer {
    http(server, "PUT", &format!("/ships/zod/agents/{agent}/files/uploads/{upload}/{n}"), &[("Authorization", auth)], chunk)
}

fn finish(server: &Server, auth: &str, agent: &str, upload: &str, id: Option<[u8; 32]>) -> Answer {
    let asked = ship_proto::FinishRequest { id: id.map_or(Vec::new(), |id| id.to_vec()) }.encode_to_vec();
    http(server, "POST", &format!("/ships/zod/agents/{agent}/files/uploads/{upload}/finish"), &[("Authorization", auth)], &asked)
}

/// Upload a whole file over HTTP and return its id.
fn upload(server: &Server, auth: &str, agent: &str, data: &[u8], media_type: &str) -> [u8; 32] {
    let (name, chunks) = started(server, auth, agent, data.len() as u64, media_type);
    for (n, chunk) in data.chunks(CHUNK as usize).enumerate() {
        let answer = put(server, auth, agent, &name, n as u64, chunk);
        assert_eq!(answer.status, 204, "{}", answer.text());
    }
    assert_eq!(chunks, chunk_count(data.len() as u64));
    let answer = finish(server, auth, agent, &name, Some(id_of(data)));
    assert_eq!(answer.status, 200, "{}", answer.text());
    id_of(data)
}

fn get(server: &Server, auth: &str, path: &str) -> Answer {
    http(server, "GET", &format!("/ships/zod{path}"), &[("Authorization", auth)], b"")
}

fn content(server: &Server, auth: &str, agent: &str, id: &[u8; 32], range: Option<&str>) -> Answer {
    let path = format!("/ships/zod/agents/{agent}/files/{}/content", hex(id));
    let mut headers = vec![("Authorization", auth)];
    if let Some(range) = range {
        headers.push(("Range", range));
    }
    http(server, "GET", &path, &headers, b"")
}

/// The directories in a ship's files directory.
fn dirs(dir: &TempDir, ship: &str) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir.0.join("files").join(ship))
        .map(|entries| entries.map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect())
        .unwrap_or_default();
    found.sort();
    found
}

#[test]
fn a_device_puts_a_file_on_the_ship_and_takes_it_out_again() {
    let dir = TempDir::new("round-trip");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let auth = device(&rt, "~zod");
    let data = contents(2 * CHUNK as usize + 300_000, 1);
    let id = id_of(&data);
    let piece = |n: usize| &data[n * CHUNK as usize..((n + 1) * CHUNK as usize).min(data.len())];

    let (name, chunks) = started(&server, &auth, "counter", data.len() as u64, "image/png");
    assert_eq!((chunks, name.len()), (3, 32));
    // Out of order, and sent again: the last one sent is the one held.
    assert_eq!(put(&server, &auth, "counter", &name, 2, piece(2)).status, 204);
    assert_eq!(put(&server, &auth, "counter", &name, 0, piece(1)).status, 204);
    assert_eq!(put(&server, &auth, "counter", &name, 0, piece(0)).status, 204);
    // A chunk of the wrong size, or past the end, is refused.
    assert_eq!(put(&server, &auth, "counter", &name, 1, &piece(1)[1..]).status, 400);
    assert_eq!(put(&server, &auth, "counter", &name, 1, piece(2)).status, 400);
    assert_eq!(put(&server, &auth, "counter", &name, 3, piece(2)).status, 400);
    assert_eq!(put(&server, &auth, "counter", &name, 1, b"").status, 400);
    // What is held, compactly, so that a client sends only what is missing.
    let state = get(&server, &auth, &format!("/agents/counter/files/uploads/{name}"));
    let state = ship_proto::UploadState::decode(&*state.body).unwrap();
    let runs: Vec<(u64, u64)> = state.held.iter().map(|run| (run.first, run.count)).collect();
    assert_eq!((state.length, state.chunks, runs, state.more), (data.len() as u64, 3, vec![(0, 1), (2, 1)], false));
    // Not finished while a chunk is missing.
    assert_eq!(finish(&server, &auth, "counter", &name, None).status, 409);
    assert_eq!(put(&server, &auth, "counter", &name, 1, piece(1)).status, 204);
    // Not finished under an id that is not the id of what was sent; the upload stays open.
    let mut wrong = id;
    wrong[0] ^= 1;
    assert_eq!(finish(&server, &auth, "counter", &name, Some(wrong)).status, 422);
    let answer = finish(&server, &auth, "counter", &name, Some(id));
    assert_eq!(answer.status, 200, "{}", answer.text());
    let info = ship_proto::FileInfo::decode(&*answer.body).unwrap();
    assert_eq!((info.id.as_slice(), info.length, info.chunks, info.media_type.as_str()), (&id[..], data.len() as u64, 3, "image/png"));
    // The upload is now a file, and is gone as an upload.
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/uploads/{name}")).status, 404);
    assert_eq!(rt.file_bytes("~zod").unwrap(), (data.len() as u64, 0));
    // One copy of each chunk on disk: the copy sent first and replaced has gone.
    assert_eq!(fs::read_dir(dir.0.join("files/zod").join(dirs(&dir, "zod")[0].clone())).unwrap().count(), 3);
    assert_eq!(rt.files_to_remove("~zod").unwrap(), (0, 0));

    // Out again: the whole, each chunk, what it is, and in the agent's list.
    let whole = content(&server, &auth, "counter", &id, None);
    assert_eq!((whole.status, whole.body.len()), (200, data.len()));
    assert!(whole.body == data);
    assert_eq!(whole.header("Content-Length"), Some(data.len().to_string().as_str()));
    for n in 0..3 {
        let chunk = get(&server, &auth, &format!("/agents/counter/files/{}/chunks/{n}", hex(&id)));
        assert!(chunk.status == 200 && chunk.body == piece(n), "chunk {n}");
        assert_eq!(chunk.header("Content-Disposition"), Some("attachment"));
    }
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/{}/chunks/3", hex(&id))).status, 404);
    let about = ship_proto::FileInfo::decode(&*get(&server, &auth, &format!("/agents/counter/files/{}", hex(&id))).body).unwrap();
    assert_eq!(about, info);
    let list = ship_proto::FileList::decode(&*get(&server, &auth, "/agents/counter/files").body).unwrap();
    assert_eq!(list.files, vec![info.clone()]);
    let after = ship_proto::FileList::decode(&*get(&server, &auth, &format!("/agents/counter/files?after={}", hex(&id))).body).unwrap();
    assert!(after.files.is_empty());

    // One range of bytes, in each of its three forms, across a chunk's end and at the file's.
    let len = data.len() as u64;
    let ranges: [(&str, u64, u64); 5] = [
        ("bytes=0-9", 0, 9),
        ("bytes=1048570-1048585", 1_048_570, 1_048_585),
        ("bytes=-5", len - 5, len - 1),
        ("bytes=2097000-", 2_097_000, len - 1),
        ("bytes=10-99999999999", 10, len - 1),
    ];
    for (range, first, last) in ranges {
        let part = content(&server, &auth, "counter", &id, Some(range));
        assert_eq!(part.status, 206, "{range}");
        assert!(part.body == data[first as usize..=last as usize], "{range}");
        assert_eq!(part.header("Content-Range"), Some(format!("bytes {first}-{last}/{len}").as_str()), "{range}");
    }
    for unsatisfiable in [format!("bytes={len}-"), "bytes=-0".to_string(), format!("bytes={}-{}", len + 5, len + 9)] {
        let refused = content(&server, &auth, "counter", &id, Some(&unsatisfiable));
        assert_eq!(refused.status, 416, "{unsatisfiable}");
        assert_eq!(refused.header("Content-Range"), Some(format!("bytes */{len}").as_str()));
    }
    // Anything fancier is answered with the whole file.
    for fancy in ["bytes=0-1,5-6", "bytes=9-2", "items=0-1", "bytes=-", "bytes= 0-1"] {
        let answer = content(&server, &auth, "counter", &id, Some(fancy));
        assert!(answer.status == 200 && answer.body == data, "{fancy}");
    }
}

#[test]
fn a_served_file_cannot_act_as_a_page_of_the_ship() {
    let dir = TempDir::new("headers");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let auth = device(&rt, "~zod");
    let page = upload(&server, &auth, "counter", b"<script>alert(1)</script>", "text/html");
    let picture = upload(&server, &auth, "counter", b"\x89PNG not really", "image/png");
    let drawing = upload(&server, &auth, "counter", b"<svg onload=alert(1)/>", "image/svg+xml");
    for (id, kind, shown) in [(page, "text/html", "attachment"), (picture, "image/png", "inline"), (drawing, "image/svg+xml", "attachment")] {
        let answer = content(&server, &auth, "counter", &id, None);
        assert_eq!(answer.status, 200);
        assert_eq!(answer.header("Content-Type"), Some(kind));
        assert_eq!(answer.header("Content-Disposition"), Some(shown), "{kind}");
        assert_eq!(answer.header("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(answer.header("Content-Security-Policy"), Some("sandbox; default-src 'none'"), "{kind}");
        let chunk = get(&server, &auth, &format!("/agents/counter/files/{}/chunks/0", hex(&id)));
        assert_eq!((chunk.header("Content-Type"), chunk.header("Content-Disposition")), (Some("application/octet-stream"), Some("attachment")));
        assert_eq!(chunk.header("Content-Security-Policy"), Some("sandbox; default-src 'none'"));
        assert_eq!(chunk.header("X-Content-Type-Options"), Some("nosniff"));
    }
    // A media type is checked and bounded when the upload starts: nothing that could carry a
    // header of its own, or a parameter, or be too long.
    for bad in ["text/html\r\nX-Evil: 1", "text/html; charset=utf-8", "nothing", &format!("a/{}", "b".repeat(200))] {
        assert_eq!(start(&server, &auth, "counter", 1, bad).status, 400, "{bad:?}");
    }
    // None given is a plain download.
    let plain = upload(&server, &auth, "counter", b"bytes", "");
    assert_eq!(content(&server, &auth, "counter", &plain, None).header("Content-Type"), Some("application/octet-stream"));
}

#[test]
fn files_are_the_owners_and_each_is_seen_only_through_an_agent_that_claims_it() {
    let dir = TempDir::new("whose");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    rt.create_ship("~nec", &rt.add_module(&wasm("kernel")).unwrap()).unwrap();
    let (auth, nec_auth) = (device(&rt, "~zod"), device(&rt, "~nec"));
    let data = b"the counter's own file".to_vec();
    let id = upload(&server, &auth, "counter", &data, "");
    let (open, _) = started(&server, &auth, "counter", 10, "");
    let unknown = hex(&id_of(b"a file nobody has"));

    // No device token, a wrong one, and another ship's: nothing, on every route.
    let routes = [
        ("GET", format!("/ships/zod/agents/counter/files/{}/content", hex(&id))),
        ("GET", format!("/ships/zod/agents/counter/files/{}/chunks/0", hex(&id))),
        ("GET", format!("/ships/zod/agents/counter/files/{}", hex(&id))),
        ("GET", "/ships/zod/agents/counter/files".to_string()),
        ("DELETE", format!("/ships/zod/agents/counter/files/{}", hex(&id))),
        ("POST", "/ships/zod/agents/counter/files/uploads".to_string()),
        ("GET", format!("/ships/zod/agents/counter/files/uploads/{open}")),
        ("PUT", format!("/ships/zod/agents/counter/files/uploads/{open}/0")),
        ("POST", format!("/ships/zod/agents/counter/files/uploads/{open}/finish")),
        ("DELETE", format!("/ships/zod/agents/counter/files/uploads/{open}")),
    ];
    let wrong = format!("Bearer {}", "0".repeat(64));
    for (method, path) in &routes {
        assert_eq!(http(&server, method, path, &[], b"").status, 401, "{method} {path}");
        assert_eq!(http(&server, method, path, &[("Authorization", &wrong)], b"").status, 401, "{method} {path}");
        assert_eq!(http(&server, method, path, &[("Authorization", &nec_auth)], b"").status, 401, "{method} {path}");
    }
    // The file is still there, and so is the upload, after all that.
    assert!(content(&server, &auth, "counter", &id, None).body == data);
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/uploads/{open}")).status, 200);

    // Another agent on the same ship sees neither: its own list is empty, and the file and the
    // upload answer exactly as an id nobody holds and an upload nobody started.
    assert!(ship_proto::FileList::decode(&*get(&server, &auth, "/agents/keeper/files").body).unwrap().files.is_empty());
    for path in [format!("/agents/keeper/files/{}", hex(&id)), format!("/agents/keeper/files/{}/content", hex(&id)), format!("/agents/keeper/files/{}/chunks/0", hex(&id))] {
        let theirs = get(&server, &auth, &path);
        let nobodys = get(&server, &auth, &path.replace(&hex(&id), &unknown));
        assert_eq!((theirs.status, theirs.body), (404, nobodys.body.clone()), "{path}");
        assert_eq!(nobodys.status, 404);
    }
    assert_eq!(get(&server, &auth, &format!("/agents/keeper/files/uploads/{open}")).status, 404);
    assert_eq!(put(&server, &auth, "keeper", &open, 0, b"0123456789").status, 404);
    assert_eq!(finish(&server, &auth, "keeper", &open, None).status, 404);
    assert_eq!(http(&server, "DELETE", &format!("/ships/zod/agents/keeper/files/uploads/{open}"), &[("Authorization", &auth)], b"").status, 404);
    assert_eq!(http(&server, "DELETE", &format!("/ships/zod/agents/keeper/files/{}", hex(&id)), &[("Authorization", &auth)], b"").status, 404);
    assert!(content(&server, &auth, "counter", &id, None).body == data);
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/uploads/{open}")).status, 200);

    // An agent that is not installed has no files, and can start no upload.
    assert_eq!(start(&server, &auth, "nobody", 1, "").status, 404);
    assert_eq!(get(&server, &auth, "/agents/nobody/files").status, 404);
    assert_eq!(rt.upload_start("~zod", "nobody", 1, "").unwrap_err().to_string(), "no such agent: nobody");

    // No name in a request becomes a path: upload names and ids are exact lower-case hex, and
    // an agent's name is an agent's name. Nothing appears outside the ship's own directory.
    let before = dirs(&dir, "zod");
    let names = ["..", "%2e%2e", "..%2f..%2fships", &open.to_uppercase(), &open[1..], &format!("{open}0"), "tmp-0", &format!("{open}%2f0")];
    for name in names {
        for (method, path) in [("GET", format!("/agents/counter/files/uploads/{name}")), ("PUT", format!("/agents/counter/files/uploads/{name}/0")), ("GET", format!("/agents/counter/files/{name}"))] {
            let answer = http(&server, method, &format!("/ships/zod{path}"), &[("Authorization", &auth)], b"0123456789");
            assert!(matches!(answer.status, 400 | 404 | 405), "{method} {path}: {}", answer.status);
        }
    }
    for agent in ["..", "%2e%2e%2fkernel", "Counter", "kernel%2f..", "a%2fb"] {
        let answer = http(&server, "POST", &format!("/ships/zod/agents/{agent}/files/uploads"), &[("Authorization", &auth)], b"");
        assert!(matches!(answer.status, 400 | 404), "{agent}: {}", answer.status);
    }
    assert_eq!(dirs(&dir, "zod"), before);
    let top: Vec<String> = fs::read_dir(dir.0.join("files")).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(top, ["zod"]);
    // Another ship's files are under its own name, and reached only through that ship.
    rt.install("~nec", "counter", &rt.add_module(&wasm("counter")).unwrap(), &manifest()).unwrap();
    let asked = ship_proto::UploadRequest { length: 5, media_type: String::new() }.encode_to_vec();
    let answer = http(&server, "POST", "/ships/nec/agents/counter/files/uploads", &[("Authorization", &nec_auth)], &asked);
    let nec_upload = ship_proto::UploadReply::decode(&*answer.body).unwrap().upload;
    let path = format!("/ships/nec/agents/counter/files/uploads/{nec_upload}");
    assert_eq!(http(&server, "PUT", &format!("{path}/0"), &[("Authorization", &nec_auth)], b"nec's").status, 204);
    assert_eq!(http(&server, "POST", &format!("{path}/finish"), &[("Authorization", &nec_auth)], b"").status, 200);
    let nec_file = hex(&id_of(b"nec's"));
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/{nec_file}")).status, 404);
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/uploads/{nec_upload}")).status, 404);
    assert_eq!(http(&server, "GET", &format!("/ships/nec/agents/counter/files/{}", hex(&id)), &[("Authorization", &nec_auth)], b"").status, 404);
    assert_eq!(dirs(&dir, "nec"), [nec_upload]);
    assert_eq!(dirs(&dir, "zod"), before);
}

#[test]
fn identical_files_are_kept_once_and_go_when_the_last_claim_does() {
    let dir = TempDir::new("once");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let auth = device(&rt, "~zod");
    let data = contents(CHUNK as usize + 10, 7);
    let id = upload(&server, &auth, "counter", &data, "");
    let kept = dirs(&dir, "zod");
    assert_eq!(kept.len(), 1);
    // The same bytes again, by another agent and by the same one: one copy on disk, claimed
    // by both, counted once, and nothing left reserved.
    assert_eq!(upload(&server, &auth, "keeper", &data, ""), id);
    assert_eq!(upload(&server, &auth, "counter", &data, ""), id);
    assert_eq!(dirs(&dir, "zod"), kept);
    assert_eq!(rt.file_bytes("~zod").unwrap(), (data.len() as u64, 0));
    assert!(content(&server, &auth, "keeper", &id, None).body == data);
    // The first claim taken back: the other agent keeps the file.
    let delete = |agent: &str| http(&server, "DELETE", &format!("/ships/zod/agents/{agent}/files/{}", hex(&id)), &[("Authorization", &auth)], b"").status;
    assert_eq!(delete("counter"), 204);
    assert_eq!(delete("counter"), 404);
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/{}", hex(&id))).status, 404);
    assert!(content(&server, &auth, "keeper", &id, None).body == data);
    assert_eq!(dirs(&dir, "zod"), kept);
    // The last: its rows go, and its bytes after them.
    assert_eq!(delete("keeper"), 204);
    assert_eq!(get(&server, &auth, &format!("/agents/keeper/files/{}", hex(&id))).status, 404);
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    assert!(dirs(&dir, "zod").is_empty(), "{:?}", dirs(&dir, "zod"));
    // And it can be put back.
    assert_eq!(upload(&server, &auth, "keeper", &data, ""), id);
    assert!(content(&server, &auth, "keeper", &id, None).body == data);
}

/// Put a whole file on a ship through the runtime, as the HTTP routes do.
fn put_file(rt: &Runtime, ship: &str, agent: &str, data: &[u8], media_type: &str) -> [u8; 32] {
    let (upload, _) = rt.upload_start(ship, agent, data.len() as u64, media_type).unwrap();
    for (n, chunk) in data.chunks(CHUNK as usize).enumerate() {
        rt.upload_chunk(ship, agent, &upload, n as u64, chunk.to_vec()).unwrap();
    }
    rt.upload_finish(ship, agent, &upload, Some(id_of(data))).unwrap().id
}

/// The whole of a file, read through the runtime a chunk at a time.
fn file_of(rt: &Runtime, ship: &str, agent: &str, id: &[u8; 32]) -> Vec<u8> {
    let info = rt.file_info(ship, agent, id).unwrap();
    (0..info.chunks).flat_map(|n| rt.file_chunk(ship, agent, id, n).unwrap()).collect()
}

fn file_error(result: Result<impl std::fmt::Debug, Error>) -> FileError {
    match result {
        Err(Error::File(why)) => why,
        other => panic!("expected a file error, got {other:?}"),
    }
}

#[test]
fn held_and_reserved_bytes_never_pass_the_allowance() {
    let dir = TempDir::new("allowance");
    let mib = CHUNK;
    let rt = Arc::new(boot(&dir, Config { max_file_bytes: 3 * mib, ..fast() }));
    // More than the allowance can never fit, and says so, however empty the ship.
    assert_eq!(file_error(rt.upload_start("~zod", "counter", 3 * mib + 1, "")), FileError::TooLarge);
    let (first, _) = rt.upload_start("~zod", "counter", 2 * mib, "").unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 2 * mib));
    // The whole length is reserved when an upload starts, before a byte of it is sent.
    assert_eq!(file_error(rt.upload_start("~zod", "counter", mib + 1, "")), FileError::NoRoom);
    let (second, _) = rt.upload_start("~zod", "keeper", mib, "").unwrap();
    // Full now. What could never fit is still told apart from what has no room now.
    assert_eq!(file_error(rt.upload_start("~zod", "counter", 1, "")), FileError::NoRoom);
    assert_eq!(file_error(rt.upload_start("~zod", "counter", 3 * mib + 1, "")), FileError::TooLarge);
    {
        // And so are they to a device.
        let server = Server::start(rt.clone(), ServerConfig::default()).unwrap();
        let auth = device(&rt, "~zod");
        assert_eq!(start(&server, &auth, "counter", 1, "").status, 507);
        assert_eq!(start(&server, &auth, "counter", 3 * mib + 1, "").status, 413);
    }
    // Giving an upload up gives its reservation back.
    rt.upload_abandon("~zod", "counter", &first).unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, mib));
    let data = contents(2 * mib as usize, 3);
    let id = put_file(&rt, "~zod", "counter", &data, "");
    // Finishing turns what was reserved into what is held, and never adds to the two.
    assert_eq!(rt.file_bytes("~zod").unwrap(), (2 * mib, mib));
    rt.upload_chunk("~zod", "keeper", &second, 0, contents(mib as usize, 4)).unwrap();
    rt.upload_finish("~zod", "keeper", &second, None).unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (3 * mib, 0));
    assert_eq!(file_error(rt.upload_start("~zod", "counter", 1, "")), FileError::NoRoom);
    rt.file_delete("~zod", "counter", &id).unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (mib, 0));

    // However many start at once, those that are let start fit, and the rest are told so.
    let won = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for agent in ["counter", "keeper"].iter().cycle().take(8) {
            let (rt, won) = (&rt, &won);
            scope.spawn(move || match rt.upload_start("~zod", agent, mib / 2, "") {
                Ok(_) => drop(won.fetch_add(1, Ordering::SeqCst)),
                Err(Error::File(FileError::NoRoom)) => {}
                Err(e) => panic!("{e}"),
            });
        }
    });
    assert_eq!(won.load(Ordering::SeqCst), 4);
    assert_eq!(rt.file_bytes("~zod").unwrap(), (mib, 2 * mib));
}

#[test]
fn only_so_many_uploads_are_open_and_forgotten_ones_are_given_up() {
    let dir = TempDir::new("uploads");
    let rt = boot(&dir, Config { max_uploads: 3, upload_keep_millis: 300, ..fast() });
    let mut open: Vec<[u8; 16]> = (0..3).map(|_| rt.upload_start("~zod", "counter", 10, "").unwrap().0).collect();
    assert!(matches!(rt.upload_start("~zod", "counter", 10, ""), Err(Error::TooMany(_))));
    assert_eq!(dirs(&dir, "zod").len(), 3);
    // Sending to one keeps it open; the others are given up once nothing has touched them
    // for `upload_keep_millis`, when the next upload starts, and their reservations with them.
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(450) {
        rt.upload_chunk("~zod", "counter", &open[0], 0, b"0123456789".to_vec()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    let (fresh, _) = rt.upload_start("~zod", "counter", 10, "").unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 20));
    for gone in &open[1..] {
        assert_eq!(file_error(rt.upload_state("~zod", "counter", gone, 0)), FileError::NotFound);
        assert!(!dirs(&dir, "zod").contains(&hex(gone)));
    }
    open.truncate(1);
    open.push(fresh);
    let mut expected: Vec<String> = open.iter().map(|dir| hex(dir)).collect();
    expected.sort();
    assert_eq!(dirs(&dir, "zod"), expected);
    rt.upload_finish("~zod", "counter", &open[0], None).unwrap();
}

/// How much more a ship's file may hold, read beside the runtime, as the runtime counts it.
fn spare(dir: &TempDir, max_ship_bytes: u64) -> u64 {
    let file = live(dir, "zod");
    let number = |name: &str| -> u64 {
        file.query_row(&format!("PRAGMA {name}"), [], |r| match r.get_ref(0)? {
            rusqlite::types::ValueRef::Integer(n) => Ok(n as u64),
            rusqlite::types::ValueRef::Text(t) => Ok(std::str::from_utf8(t).unwrap().parse().unwrap()),
            _ => Ok(0),
        })
        .unwrap()
    };
    let (page, used, free) = (number("page_size"), number("page_count"), number("freelist_count"));
    ((max_ship_bytes / page).saturating_sub(used) + free) * page
}

fn storage_key(dir: &Path) -> StorageKey {
    StorageKey::from_hex(&fs::read_to_string(dir.join("storage.key")).unwrap()).unwrap()
}

/// A ship's file in a data directory, opened with its key, beside whatever runtime has it.
fn live(dir: &TempDir, ship: &str) -> rusqlite::Connection {
    let file = rusqlite::Connection::open(dir.0.join("ships").join(format!("{ship}.ship"))).unwrap();
    let key: String = seal::ship_file_key(&storage_key(&dir.0), ship).iter().map(|byte| format!("{byte:02x}")).collect();
    file.execute_batch(&format!("PRAGMA key = \"x'{key}'\";")).unwrap();
    file
}

#[test]
fn an_upload_never_takes_the_room_a_ship_keeps_in_its_own_file() {
    let dir = TempDir::new("room");
    let max_ship_bytes = 2 << 20;
    // Small events, so that the room kept is small: one event, one receipt, and some pages.
    let cfg = Config { max_ship_bytes, max_event_bytes: 16 << 10, max_file_bytes: 8 << 30, ..fast() };
    let room = (16 << 10) + 64 + 512 + (16 << 10);
    let rt = boot(&dir, cfg);
    let length = 120 * CHUNK;
    let (upload, _) = rt.upload_start("~zod", "counter", length, "").unwrap();
    // Fill the ship's file from outside until less than that room is left.
    {
        let file = live(&dir, "zod");
        let mut n = 0;
        while spare(&dir, max_ship_bytes) >= room {
            file.execute("INSERT INTO kv VALUES ('filler', ?1, zeroblob(2000))", [format!("{n:08}")]).unwrap();
            n += 1;
        }
    }
    // Nothing new starts: its rows would need room the ship does not have to give.
    assert_eq!(file_error(rt.upload_start("~zod", "keeper", 10, "")), FileError::NoRoom);
    // Whatever could never fit is still told so first, however full the file is.
    assert_eq!(file_error(rt.upload_start("~zod", "keeper", (8 << 30) + 1, "")), FileError::TooLarge);
    assert_eq!(file_error(rt.upload_start("~zod", "keeper", (max_ship_bytes / 4 / 128 + 1) * CHUNK, "")), FileError::TooLarge);
    // Chunks of the upload already open go on being taken while their rows fit in the pages
    // the file has, and are refused once one would take more of the room it keeps.
    let chunk = contents(CHUNK as usize, 9);
    let mut refused = 0;
    for n in 0..120 {
        let before = spare(&dir, max_ship_bytes);
        match rt.upload_chunk("~zod", "counter", &upload, n, chunk.clone()) {
            Ok(()) => {
                let after = spare(&dir, max_ship_bytes);
                assert!(after >= before || after >= room, "chunk {n} took the file from {before} to {after}");
            }
            Err(Error::File(FileError::NoRoom)) => refused += 1,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(refused > 0, "inconclusive: every chunk's row fitted in pages the file already had");
    // A chunk refused left nothing behind: no file in its place, no row.
    let held = rt.upload_state("~zod", "counter", &upload, 0).unwrap();
    let on_disk = fs::read_dir(dir.0.join("files/zod").join(hex(&upload))).unwrap().count() as u64;
    assert_eq!(on_disk, held.held.iter().map(|(_, count)| count).sum::<u64>());
}

#[test]
fn bytes_that_are_not_what_was_stored_are_never_served() {
    let dir = TempDir::new("damage");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let auth = device(&rt, "~zod");
    let data = contents(3 * CHUNK as usize, 11);
    let id = upload(&server, &auth, "counter", &data, "");
    let other = upload(&server, &auth, "counter", &contents(CHUNK as usize, 12), "");
    let place = |id: &[u8; 32]| {
        let rows = live(&dir, "zod");
        let dir_bytes: Vec<u8> = rows.query_row("SELECT dir FROM files WHERE id = ?1", [&id[..]], |r| r.get(0)).unwrap();
        dir.0.join("files/zod").join(hex(&dir_bytes))
    };
    let (file_dir, other_dir) = (place(&id), place(&other));
    let chunk = |n: u64| get(&server, &auth, &format!("/agents/counter/files/{}/chunks/{n}", hex(&id)));
    let whole_is_short = || {
        let answer = content(&server, &auth, "counter", &id, None);
        assert_eq!(answer.header("Content-Length"), Some(data.len().to_string().as_str()));
        assert!(answer.body.len() < data.len() && data.starts_with(&answer.body), "{} bytes", answer.body.len());
    };
    // Each chunk is the one copy named `<n>.<gen>` in its file's directory.
    let named = |place: &Path, n: u64| {
        let found: Vec<PathBuf> = fs::read_dir(place).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.file_name().unwrap().to_str().unwrap().starts_with(&format!("{n}."))).collect();
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].clone()
    };
    let (first, second, theirs) = (named(&file_dir, 0), named(&file_dir, 1), named(&other_dir, 0));
    let (zero, one) = (fs::read(&first).unwrap(), fs::read(&second).unwrap());

    // A byte changed on disk: an error, never the changed bytes. The other chunks still serve.
    let mut changed = zero.clone();
    changed[100] ^= 1;
    fs::write(&first, &changed).unwrap();
    assert_eq!(chunk(0).status, 500);
    assert!(chunk(1).status == 200 && chunk(1).body == data[CHUNK as usize..2 * CHUNK as usize]);
    whole_is_short();
    // Chunks swapped with each other, or brought in from another file: each was sealed for
    // its own place, and does not open in another.
    fs::write(&first, &one).unwrap();
    fs::write(&second, &zero).unwrap();
    assert_eq!((chunk(0).status, chunk(1).status), (500, 500));
    fs::write(&first, fs::read(&theirs).unwrap()).unwrap();
    assert_eq!(chunk(0).status, 500);
    // Cut short, gone, or not a file at all.
    fs::write(&first, &zero[..zero.len() - 1]).unwrap();
    assert_eq!(chunk(0).status, 500);
    fs::remove_file(&first).unwrap();
    assert_eq!(chunk(0).status, 500);
    fs::create_dir(&first).unwrap();
    assert_eq!(chunk(0).status, 500);
    fs::remove_dir(&first).unwrap();
    fs::write(&first, &zero).unwrap();
    fs::write(&second, &one).unwrap();
    assert!(content(&server, &auth, "counter", &id, None).body == data);
    // Bytes that open as they were sealed but are not what the ship's file says the chunk is:
    // each chunk is checked against its hash, apart from the seal.
    live(&dir, "zod").execute("UPDATE file_chunks SET hash = ?1 WHERE n = 2 AND dir = (SELECT dir FROM files WHERE id = ?2)", rusqlite::params![&leaf(b"something else")[..], &id[..]]).unwrap();
    assert_eq!(chunk(2).status, 500);
    assert!(chunk(1).status == 200);
    let answer = content(&server, &auth, "counter", &id, None);
    assert!(answer.body.len() == 2 * CHUNK as usize && data.starts_with(&answer.body));
}

/// Every regular file under `root`, read whole, and every name under it.
fn everything_under(root: &Path) -> (Vec<(PathBuf, Vec<u8>)>, Vec<String>) {
    let (mut files, mut names) = (Vec::new(), Vec::new());
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            names.push(entry.file_name().into_string().unwrap());
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                todo.push(entry.path());
            } else if kind.is_file() {
                files.push((entry.path(), fs::read(entry.path()).unwrap()));
            }
        }
    }
    (files, names)
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn nothing_on_disk_shows_what_a_file_holds_or_what_it_is() {
    let (dir, out) = (TempDir::new("unreadable"), TempDir::new("unreadable-out"));
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let auth = device(&rt, "~zod");
    let marker = b"plainsight-file-marker:";
    let data: Vec<u8> = marker.iter().copied().cycle().take(2 * CHUNK as usize + 999).collect();
    let id = upload(&server, &auth, "counter", &data, "application/x-plainsight-kind");
    // An upload half done, as well.
    let (open, _) = started(&server, &auth, "keeper", CHUNK + 5, "application/x-plainsight-open");
    assert_eq!(put(&server, &auth, "keeper", &open, 0, &data[..CHUNK as usize]).status, 204);
    rt.set_recovery_key("~zod", seal::recovery_public(CODE)).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    assert!(out.0.join("zod.files").exists());

    let leaves: Vec<[u8; 32]> = data.chunks(CHUNK as usize).map(leaf).collect();
    let mut shown: Vec<Vec<u8>> = vec![marker.to_vec(), b"plainsight-kind".to_vec(), b"plainsight-open".to_vec(), id.to_vec(), hex(&id).into_bytes()];
    for leaf in &leaves {
        shown.push(leaf.to_vec());
        shown.push(hex(leaf).into_bytes());
    }
    for root in [&dir.0, &out.0] {
        let (files, names) = everything_under(root);
        assert!(files.len() >= 4, "{} files under {}", files.len(), root.display());
        for (path, bytes) in &files {
            for needle in &shown {
                assert!(!holds(bytes, needle), "{} shows {:?}", path.display(), String::from_utf8_lossy(&needle[..needle.len().min(24)]));
            }
        }
        for name in &names {
            assert!(!name.contains(&hex(&id)) && leaves.iter().all(|leaf| !name.contains(&hex(leaf))), "named {name}");
        }
    }
    assert_eq!(fs::read_dir(dir.0.join("tmp")).unwrap().count(), 0);
}

#[test]
fn leftovers_no_row_names_are_cleared_when_the_ship_first_wakes() {
    let (dir, outside) = (TempDir::new("leftovers"), TempDir::new("leftovers-outside"));
    let data = contents(CHUNK as usize + 3, 13);
    let (id, open) = {
        let rt = boot(&dir, fast());
        let id = put_file(&rt, "~zod", "counter", &data, "");
        let (open, _) = rt.upload_start("~zod", "keeper", CHUNK + 1, "").unwrap();
        rt.upload_chunk("~zod", "keeper", &open, 0, data[..CHUNK as usize].to_vec()).unwrap();
        (id, open)
    };
    let named = dirs(&dir, "zod");
    assert_eq!(named.len(), 2);
    // What a crash can leave: a chunk on its way in, and a directory whose rows went and
    // whose bytes had yet to. And things that are not the runtime's at all, which go too,
    // without anything they point to being touched.
    let root = dir.0.join("files/zod");
    fs::write(root.join(format!("tmp-{}", "ab".repeat(16))), b"half a chunk").unwrap();
    let stale = root.join("0f".repeat(16));
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("0"), b"bytes of a file that was deleted").unwrap();
    fs::write(root.join("stray"), b"?").unwrap();
    fs::write(outside.0.join("keep"), b"not the runtime's").unwrap();
    std::os::unix::fs::symlink(&outside.0, root.join("cd".repeat(16))).unwrap();
    std::os::unix::fs::symlink(&outside.0, root.join("link")).unwrap();

    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (data.len() as u64, CHUNK + 1));
    assert_eq!(dirs(&dir, "zod"), named);
    assert!(fs::read(outside.0.join("keep")).unwrap() == b"not the runtime's");
    // What rows name is untouched: the file reads back, and the upload carries on.
    assert!(file_of(&rt, "~zod", "counter", &id) == data);
    assert_eq!(rt.upload_state("~zod", "keeper", &open, 0).unwrap().held, vec![(0, 1)]);
    rt.upload_chunk("~zod", "keeper", &open, 1, vec![7]).unwrap();
    rt.upload_finish("~zod", "keeper", &open, None).unwrap();
}

/// A connection asking for a file's contents that takes the head of the answer and then
/// nothing more, so the server is left waiting to send the rest.
fn stalled(server: &Server, auth: &str, id: &[u8; 32]) -> std::net::TcpStream {
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    let head = format!("GET /ships/zod/agents/counter/files/{}/content HTTP/1.0\r\nHost: x\r\nAuthorization: {auth}\r\n\r\n", hex(id));
    stream.write_all(head.as_bytes()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut first = [0u8; 12];
    stream.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"HTTP/1.1 200", "the download did not start");
    stream
}

#[test]
fn a_slow_reader_holds_no_ship_and_downloads_have_their_own_limit() {
    let dir = TempDir::new("slow");
    let config = ServerConfig { workers: 8, max_downloads: 2, io_timeout: Duration::from_secs(5), ..ServerConfig::default() };
    let (rt, server) = serve(&dir, fast(), config);
    let auth = device(&rt, "~zod");
    // Far more than a connection holds in flight with nobody reading it.
    let data = contents(8 * CHUNK as usize, 17);
    let id = put_file(&rt, "~zod", "counter", &data, "");

    let mut slow = stalled(&server, &auth, &id);
    // The ship goes on answering while the file is on its way: nothing about sending it holds
    // the ship.
    let asked = Instant::now();
    assert_eq!(rt.deliver("~zod", "counter", b"inc hits").unwrap().reply, b"1");
    assert_eq!(get(&server, &auth, "/devices").status, 200);
    assert!(asked.elapsed() < Duration::from_secs(2), "the ship waited {:?} behind a download", asked.elapsed());
    // A second download fills the limit; a third is told to try again, and nothing else is.
    let other = stalled(&server, &auth, &id);
    let third = content(&server, &auth, "counter", &id, None);
    assert_eq!((third.status, third.header("Retry-After")), (503, Some("1")));
    assert_eq!(get(&server, &auth, "/devices").status, 200);
    assert_eq!(get(&server, &auth, &format!("/agents/counter/files/{}/chunks/7", hex(&id))).status, 200);
    // The first download was going all along, and is whole.
    let mut rest = Vec::new();
    slow.read_to_end(&mut rest).unwrap();
    let split = rest.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
    assert!(rest[split..] == data, "{} of {} bytes", rest.len() - split, data.len());
    // Once a download is over, its place is free again.
    drop(other);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let answer = content(&server, &auth, "counter", &id, None);
        if answer.status == 200 {
            assert!(answer.body == data);
            break;
        }
        assert!(Instant::now() < deadline, "a download's place was never given back");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_chunk_is_put_in_place_only_while_its_upload_is_there() {
    let dir = TempDir::new("in-place");
    let rt = boot(&dir, fast());
    let (first, _) = rt.upload_start("~zod", "counter", 10, "").unwrap();
    // Made ready outside the ship; meanwhile the upload is given up and another started.
    let ready = rt.prepare_chunk("~zod", "counter", &first, 0, b"0123456789".to_vec()).unwrap();
    rt.upload_abandon("~zod", "counter", &first).unwrap();
    let (second, _) = rt.upload_start("~zod", "counter", 10, "").unwrap();
    assert_eq!(file_error(ready.commit()), FileError::NotFound);
    // Nothing of it is anywhere: not in the new upload, not on disk.
    assert!(rt.upload_state("~zod", "counter", &second, 0).unwrap().held.is_empty());
    assert_eq!(dirs(&dir, "zod"), [hex(&second)]);
    assert_eq!(fs::read_dir(dir.0.join("files/zod").join(hex(&second))).unwrap().count(), 0);
    // A chunk made ready and dropped leaves nothing either: its copy, written into the
    // upload's directory, goes with it.
    let ready = rt.prepare_chunk("~zod", "counter", &second, 0, b"0123456789".to_vec()).unwrap();
    assert_eq!(fs::read_dir(dir.0.join("files/zod").join(hex(&second))).unwrap().count(), 1);
    drop(ready);
    assert_eq!(dirs(&dir, "zod"), [hex(&second)]);
    assert_eq!(fs::read_dir(dir.0.join("files/zod").join(hex(&second))).unwrap().count(), 0);
    // One finished while a chunk was on its way: the chunk does not land in the file.
    let ready = rt.prepare_chunk("~zod", "counter", &second, 0, b"9876543210".to_vec()).unwrap();
    rt.upload_chunk("~zod", "counter", &second, 0, b"0123456789".to_vec()).unwrap();
    let id = rt.upload_finish("~zod", "counter", &second, None).unwrap().id;
    assert_eq!(file_error(ready.commit()), FileError::NotFound);
    assert_eq!(rt.file_chunk("~zod", "counter", &id, 0).unwrap(), b"0123456789");
    // And a file deleted while its contents were being read is not read on into anything else.
    let dir_of_file = dirs(&dir, "zod");
    rt.file_delete("~zod", "counter", &id).unwrap();
    assert!(dirs(&dir, "zod").is_empty(), "{dir_of_file:?}");
    assert_eq!(file_error(rt.file_chunk("~zod", "counter", &id, 0)), FileError::NotFound);
}

#[test]
fn a_chunk_may_always_be_sent_whole_and_no_more() {
    let dir = TempDir::new("bodies");
    let (rt, server) = serve(&dir, fast(), ServerConfig { max_body_bytes: 1024, ..ServerConfig::default() });
    let auth = device(&rt, "~zod");
    let data = contents(CHUNK as usize + 1, 19);
    let (name, _) = started(&server, &auth, "counter", data.len() as u64, "");
    // A whole chunk, though it is far more than other requests may carry.
    assert_eq!(put(&server, &auth, "counter", &name, 0, &data[..CHUNK as usize]).status, 204);
    assert_eq!(http(&server, "POST", "/ships/zod/agents/counter/command", &[("Authorization", &auth)], &[b'x'; 2048]).status, 413);
    // More than a chunk is refused on what it says it is, before it is read.
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    let head = format!("PUT /ships/zod/agents/counter/files/uploads/{name}/1 HTTP/1.0\r\nHost: x\r\nAuthorization: {auth}\r\nContent-Length: {}\r\n\r\n", CHUNK + 1);
    stream.write_all(head.as_bytes()).unwrap();
    assert_eq!(read_answer(stream).status, 413);
    assert_eq!(put(&server, &auth, "counter", &name, 1, &data[CHUNK as usize..]).status, 204);
    assert_eq!(finish(&server, &auth, "counter", &name, Some(id_of(&data))).status, 200);
    // Nor does a larger limit for other requests let a chunk be longer.
    let roomy = Server::start(rt.clone(), ServerConfig { max_body_bytes: 4 << 20, ..ServerConfig::default() }).unwrap();
    let (name, _) = started(&roomy, &auth, "counter", 2 * CHUNK, "");
    let mut stream = std::net::TcpStream::connect(roomy.addr()).unwrap();
    let head = format!("PUT /ships/zod/agents/counter/files/uploads/{name}/0 HTTP/1.0\r\nHost: x\r\nAuthorization: {auth}\r\nContent-Length: {}\r\n\r\n", CHUNK + 1);
    stream.write_all(head.as_bytes()).unwrap();
    assert_eq!(read_answer(stream).status, 413);
    assert_eq!(http(&roomy, "POST", "/ships/zod/agents/counter/command", &[("Authorization", &auth)], &vec![b'x'; 2 << 20]).status, 422);
}

#[test]
fn a_runtime_can_keep_no_files() {
    let (dir, other, out) = (TempDir::new("off"), TempDir::new("off-other"), TempDir::new("off-out"));
    let (rt, server) = serve(&dir, Config { max_file_bytes: 0, ..fast() }, ServerConfig::default());
    let auth = device(&rt, "~zod");
    assert_eq!(start(&server, &auth, "counter", 1, "").status, 403);
    assert_eq!(get(&server, &auth, "/agents/counter/files").status, 403);
    assert_eq!(file_error(rt.upload_start("~zod", "counter", 0, "")), FileError::Off);
    // A ship that has files is not brought into a runtime that keeps none, not even a ship
    // whose only file is empty.
    let rt = boot(&other, fast());
    put_file(&rt, "~zod", "counter", b"", "");
    rt.set_recovery_key("~zod", seal::recovery_public(CODE)).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    let off = TempDir::new("off-import");
    let off = Runtime::open(&off.0, Config { max_file_bytes: 0, ..fast() }).unwrap();
    assert!(matches!(off.import_ship(&out.0, "~zod", CODE), Err(Error::BadShipFile(_))));
}

#[test]
fn an_agent_holds_a_reference_and_sees_only_its_own_files() {
    let dir = TempDir::new("agent");
    let rt = boot(&dir, fast());
    let data = contents(CHUNK as usize + 1, 23);
    let mine = put_file(&rt, "~zod", "counter", &data, "audio/ogg");
    let theirs = put_file(&rt, "~zod", "keeper", b"keeper's", "");
    let ask = |agent: &str, id: &[u8; 32]| String::from_utf8(rt.deliver("~zod", agent, format!("file {}", hex(id)).as_bytes()).unwrap().reply).unwrap();
    assert_eq!(ask("counter", &mine), format!("{} 2 audio/ogg", data.len()));
    assert_eq!(ask("counter", &theirs), "none");
    assert_eq!(ask("counter", &id_of(b"nobody's")), "none");
    assert_eq!(ask("keeper", &theirs), "8 1 application/octet-stream");
    rt.file_delete("~zod", "counter", &mine).unwrap();
    assert_eq!(ask("counter", &mine), "none");
}

#[test]
fn a_ship_file_from_before_files_does_not_open() {
    let dir = TempDir::new("schema");
    drop(boot(&dir, fast()));
    live(&dir, "zod").execute("UPDATE meta SET value = 9 WHERE key = 'schema'", []).unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert!(matches!(rt.deliver("~zod", "counter", b"get hits"), Err(Error::BadShipFile(why)) if why.contains("schema")));
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// A ship with files of several sizes, one of them claimed by both agents, and an upload half
/// done; exported to `out`. Returns the runtime and each file's (agent, id, contents).
fn exported(dir: &TempDir, out: &TempDir) -> (Runtime, Vec<(&'static str, [u8; 32], Vec<u8>)>) {
    let rt = boot(dir, fast());
    let files = vec![
        ("counter", Vec::new()),
        ("counter", b"x".to_vec()),
        ("keeper", contents(2 * CHUNK as usize + 70_000, 29)),
        ("counter", contents(CHUNK as usize, 31)),
    ];
    let mut made = Vec::new();
    for (agent, data) in files {
        made.push((agent, put_file(&rt, "~zod", agent, &data, "image/webp"), data));
    }
    // The last one is claimed by the other agent too.
    let shared = made[3].2.clone();
    put_file(&rt, "~zod", "keeper", &shared, "");
    let (open, _) = rt.upload_start("~zod", "keeper", CHUNK + 1, "").unwrap();
    rt.upload_chunk("~zod", "keeper", &open, 0, contents(CHUNK as usize, 37)).unwrap();
    send(&rt, "inc hits 5");
    rt.set_recovery_key("~zod", seal::recovery_public(CODE)).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    (rt, made)
}

fn send(rt: &Runtime, command: &str) -> String {
    String::from_utf8(rt.deliver("~zod", "counter", command.as_bytes()).unwrap().reply).unwrap()
}

/// Import `~zod` from `out` into a fresh runtime.
fn import(label: &str, out: &TempDir, cfg: Config) -> (TempDir, Runtime, Result<FilesKept, Error>) {
    let dir = TempDir::new(label);
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let imported = rt.import_ship_counted(&out.0, "~zod", CODE);
    (dir, rt, imported)
}

#[test]
fn a_ship_exported_and_imported_brings_its_files() {
    let (a, out) = (TempDir::new("carry-a"), TempDir::new("carry-out"));
    let (old, made) = exported(&a, &out);
    let mut shown: Vec<String> = fs::read_dir(&out.0).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    shown.sort();
    assert_eq!(shown, ["blobs", "zod.files", "zod.ship"]);

    let (b, rt, imported) = import("carry-b", &out, fast());
    assert_eq!(imported.unwrap(), FilesKept { kept: 4, dropped: 0 });
    for (agent, id, data) in &made {
        assert!(file_of(&rt, "~zod", agent, id) == *data);
        assert_eq!(rt.file_info("~zod", agent, id).unwrap(), old.file_info("~zod", agent, id).unwrap());
    }
    assert!(file_of(&rt, "~zod", "keeper", &made[3].1) == made[3].2);
    let held: u64 = made.iter().map(|(_, _, data)| data.len() as u64).sum();
    // The upload half done did not come: nothing is reserved, and its bytes are not here.
    assert_eq!(rt.file_bytes("~zod").unwrap(), (held, 0));
    assert_eq!(old.file_bytes("~zod").unwrap(), (held, CHUNK + 1));
    assert_eq!(dirs(&b, "zod").len(), 4);
    // Each file has a directory of its own making here, under this runtime's key.
    let theirs = dirs(&a, "zod");
    assert!(dirs(&b, "zod").iter().all(|name| !theirs.contains(name)));
    assert_eq!(send(&rt, "get hits"), "5");
    // And it goes on: files are added and taken out as before.
    let more = put_file(&rt, "~zod", "counter", b"after", "");
    assert_eq!(file_of(&rt, "~zod", "counter", &more), b"after");
    // A ship with no files left has no stream beside its copy, and one left from before goes.
    for (agent, id, _) in &made {
        let _ = rt.file_delete("~zod", agent, id);
    }
    rt.file_delete("~zod", "keeper", &made[3].1).unwrap_or(());
    rt.file_delete("~zod", "counter", &more).unwrap();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    rt.export_ship("~zod", &out.0).unwrap();
    assert!(!out.0.join("zod.files").exists());
}

#[test]
fn a_copy_without_its_files_brings_the_ship_without_them() {
    let (a, out) = (TempDir::new("without-a"), TempDir::new("without-out"));
    let (_, made) = exported(&a, &out);
    fs::remove_file(out.0.join("zod.files")).unwrap();
    let (b, rt, imported) = import("without-b", &out, fast());
    assert_eq!(imported.unwrap(), FilesKept { kept: 0, dropped: 4 });
    assert_eq!(send(&rt, "get hits"), "5");
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    for (agent, id, _) in &made {
        assert_eq!(file_error(rt.file_info("~zod", agent, id)), FileError::NotFound);
        assert!(rt.files("~zod", agent, None, 100).unwrap().is_empty());
    }
    assert!(dirs(&b, "zod").is_empty());
    assert!(live(&b, "zod").query_row("SELECT (SELECT COUNT(*) FROM file_claims) + (SELECT COUNT(*) FROM file_chunks)", [], |r| r.get::<_, i64>(0)).unwrap() == 0);
}

const SEALED_SEGMENT: usize = seal::SEGMENT_BYTES + seal::SEGMENT_TAG_BYTES;

/// The plain stream inside `out/zod.files`.
fn plain_of(out: &TempDir) -> Vec<u8> {
    let sealed = fs::read(out.0.join("zod.files")).unwrap();
    let binding = sha256(&fs::read(out.0.join("zod.ship")).unwrap());
    let mut open = seal::open_files_stream(CODE, "zod", &binding, &sealed[..seal::FILES_HEAD]).unwrap();
    let body = &sealed[seal::FILES_HEAD..];
    let count = body.len().div_ceil(SEALED_SEGMENT);
    let mut plain = Vec::new();
    for (i, piece) in body.chunks(SEALED_SEGMENT).enumerate() {
        let mut piece = piece.to_vec();
        plain.extend_from_slice(open.open(&mut piece, i + 1 == count).unwrap());
    }
    plain
}

/// Seal a plain stream as the stream beside the copy in `out`, sealed properly to the code:
/// anyone who has the recovery key's public half can make one.
fn seal_plain(out: &TempDir, plain: &[u8]) {
    let binding = sha256(&fs::read(out.0.join("zod.ship")).unwrap());
    let (mut sealed, mut stream) = seal::seal_files_stream(&seal::recovery_public(CODE), "zod", &binding, [9; 32]);
    let pieces: Vec<&[u8]> = if plain.is_empty() { vec![&[]] } else { plain.chunks(seal::SEGMENT_BYTES).collect() };
    for (i, piece) in pieces.iter().enumerate() {
        let mut piece = piece.to_vec();
        stream.seal(&mut piece, i + 1 == pieces.len());
        sealed.extend_from_slice(&piece);
    }
    fs::write(out.0.join("zod.files"), sealed).unwrap();
}

/// Where each file's record ends in a plain stream, in order: (id, offset just past it).
fn records(plain: &[u8]) -> Vec<([u8; 32], usize)> {
    let mut at = 0;
    let mut found = Vec::new();
    while plain[at] == 1 {
        let id: [u8; 32] = plain[at + 1..at + 33].try_into().unwrap();
        let length = u64::from_le_bytes(plain[at + 33..at + 41].try_into().unwrap());
        at += 41;
        for n in 0..chunk_count(length) {
            assert_eq!(plain[at], 2);
            at += 1 + (length - n * CHUNK).min(CHUNK) as usize;
        }
        found.push((id, at));
    }
    assert_eq!(plain[at], 0);
    found
}

#[test]
fn a_stream_cut_short_changed_reordered_or_from_another_copy_keeps_only_whole_matching_files() {
    let (a, out) = (TempDir::new("cut-a"), TempDir::new("cut-out"));
    let (rt, made) = exported(&a, &out);
    let sealed = fs::read(out.0.join("zod.files")).unwrap();
    let plain = plain_of(&out);
    let ends = records(&plain);
    assert_eq!(ends.len(), 4);
    let segments = (sealed.len() - seal::FILES_HEAD).div_ceil(SEALED_SEGMENT);
    assert!(segments > 30, "{segments}");
    let check = |label: &str, bytes: Vec<u8>, kept: usize| {
        fs::write(out.0.join("zod.files"), &bytes).unwrap();
        let (b, rt, imported) = import(label, &out, fast());
        assert_eq!(imported.unwrap(), FilesKept { kept: kept as u64, dropped: 4 - kept as u64 }, "{label}");
        // Whatever was kept is whole and right; whatever was not is gone with its claims.
        let mut held = 0;
        for (agent, id, data) in &made {
            match rt.file_info("~zod", agent, id) {
                Ok(_) => {
                    assert!(file_of(&rt, "~zod", agent, id) == *data, "{label}");
                    held += 1;
                }
                Err(Error::File(FileError::NotFound)) => {}
                Err(e) => panic!("{label}: {e}"),
            }
        }
        assert_eq!(held, kept, "{label}");
        assert_eq!(dirs(&b, "zod").len(), kept, "{label}");
        assert_eq!(send(&rt, "get hits"), "5");
    };

    // Cut at points through the stream: a file is kept only if its whole record is in the
    // part that opens. That part is every segment but the last one read, which is taken as
    // the last and was not sealed as the last.
    for cut in [0, 10, seal::FILES_HEAD, seal::FILES_HEAD + 1, seal::FILES_HEAD + SEALED_SEGMENT, seal::FILES_HEAD + 17 * SEALED_SEGMENT + 5, sealed.len() - 1] {
        let full = cut.saturating_sub(seal::FILES_HEAD) / SEALED_SEGMENT;
        let on_boundary = cut >= seal::FILES_HEAD && (cut - seal::FILES_HEAD) % SEALED_SEGMENT == 0;
        let opens = if on_boundary { full.saturating_sub(1) } else { full } * seal::SEGMENT_BYTES;
        let kept = ends.iter().filter(|(_, end)| *end <= opens).count();
        check(&format!("cut-{cut}"), sealed[..cut].to_vec(), kept);
    }
    // A byte changed in the middle of the third file: what came before it is kept.
    let at = seal::FILES_HEAD + (ends[1].1 + 1000) / seal::SEGMENT_BYTES * SEALED_SEGMENT + 77;
    let mut changed = sealed.clone();
    changed[at] ^= 1;
    check("changed", changed, ends.iter().filter(|(_, end)| *end <= (at - seal::FILES_HEAD) / SEALED_SEGMENT * seal::SEGMENT_BYTES).count());
    // Segments swapped, one left out, one twice: none opens past that point.
    let segment = |i: usize| &sealed[seal::FILES_HEAD + i * SEALED_SEGMENT..seal::FILES_HEAD + (i + 1) * SEALED_SEGMENT];
    let head = &sealed[..seal::FILES_HEAD];
    let rest = |from: usize| &sealed[seal::FILES_HEAD + from * SEALED_SEGMENT..];
    check("swapped", [head, segment(1), segment(0), rest(2)].concat(), 0);
    check("dropped", [head, segment(0), rest(2)].concat(), ends.iter().filter(|(_, end)| *end <= seal::SEGMENT_BYTES).count());
    check("repeated", [head, segment(0), segment(0), rest(1)].concat(), ends.iter().filter(|(_, end)| *end <= seal::SEGMENT_BYTES).count());
    // The stream of another copy of the same ship, made a moment later: it is bound to that
    // copy, and opens beside no other.
    let later = TempDir::new("cut-later");
    rt.export_ship("~zod", &later.0).unwrap();
    check("another copy", fs::read(later.0.join("zod.files")).unwrap(), 0);
    // The stream as it was made, to be sure the rest was not luck.
    check("whole", sealed, 4);
}

#[test]
fn a_stream_made_to_mislead_brings_in_nothing_it_should_not() {
    let (a, out) = (TempDir::new("hostile-a"), TempDir::new("hostile-out"));
    let (_, made) = exported(&a, &out);
    let plain = plain_of(&out);
    let ends = records(&plain);
    let start_of = |i: usize| if i == 0 { 0 } else { ends[i - 1].1 };
    let length_of = |i: usize| u64::from_le_bytes(plain[start_of(i) + 33..start_of(i) + 41].try_into().unwrap());
    // The files are in order of id, so where each one is in the stream is looked up.
    let big = (0..4).max_by_key(|i| length_of(*i)).unwrap();
    assert!(length_of(big) > CHUNK);
    let check = |label: &str, plain: Vec<u8>, kept: usize| {
        seal_plain(&out, &plain);
        let (b, rt, imported) = import(label, &out, fast());
        assert_eq!(imported.unwrap().kept, kept as u64, "{label}");
        for (agent, id, data) in &made {
            if rt.file_info("~zod", agent, id).is_ok() {
                assert!(file_of(&rt, "~zod", agent, id) == *data, "{label}");
            }
        }
        assert_eq!(dirs(&b, "zod").len(), kept, "{label}");
    };
    check("resealed as it was", plain.clone(), 4);
    let end = &plain[ends[3].1..];
    // A file of a length other than the ship's file gives it, even an enormous one: reading
    // stops there, and only the files before it are kept.
    for length in [0u64, 1, u64::MAX] {
        let at = (0..4).find(|i| length_of(*i) != length).unwrap();
        let mut wrong = plain.clone();
        wrong[start_of(at) + 33..start_of(at) + 41].copy_from_slice(&length.to_le_bytes());
        check(&format!("length {length}"), wrong, at);
    }
    // A file the ship's file does not list.
    let mut unknown = plain.clone();
    unknown[start_of(2) + 1] ^= 1;
    check("unknown", unknown, 2);
    // A chunk that is not the file's.
    let mut bytes = plain.clone();
    bytes[start_of(big) + 41 + 1 + 500] ^= 1;
    check("bytes", bytes, big);
    // The same file twice: the second time ends it.
    check("twice", [&plain[..ends[1].1], &plain[start_of(1)..ends[1].1], &plain[ends[1].1..]].concat(), 2);
    // A file given up part way is dropped, and the rest still come.
    let given_up = [&plain[start_of(big)..start_of(big) + 41 + 1 + CHUNK as usize], &[3u8][..]].concat();
    check("given up", [&plain[..start_of(big)], &given_up, &plain[ends[big].1..]].concat(), 3);
    // Something that is not a record, and a stream that stops after a file's head.
    check("not a record", [&plain[..start_of(1)], &[7u8][..], end].concat(), 1);
    check("head only", plain[..start_of(big) + 41].to_vec(), big);
    check("empty", Vec::new(), 0);
}

/// Open the copy of `~zod` in `out`, let `change` alter its file, and seal it again.
fn rework(out: &TempDir, change: impl FnOnce(&rusqlite::Connection)) {
    let (seed, contents) = seal::open_export(CODE, "zod", fs::read(out.0.join("zod.ship")).unwrap()).unwrap();
    let plain = out.0.join("zod.plain");
    fs::write(&plain, &contents).unwrap();
    change(&rusqlite::Connection::open(&plain).unwrap());
    let changed = fs::read(&plain).unwrap();
    fs::remove_file(&plain).unwrap();
    fs::write(out.0.join("zod.ship"), seal::seal_export(&seal::recovery_public(CODE), "zod", &seed, &changed, [5; 32])).unwrap();
}

#[test]
fn import_checks_every_file_row_against_every_other() {
    let (a, out) = (TempDir::new("rows-a"), TempDir::new("rows-out"));
    let (_, made) = exported(&a, &out);
    let original = fs::read(out.0.join("zod.ship")).unwrap();
    let big = made[2].1.to_vec();
    let refused = |label: &str, statements: &str, cfg: Config| {
        fs::write(out.0.join("zod.ship"), &original).unwrap();
        rework(&out, |file| {
            file.execute_batch(&statements.replace("BIG", &format!("x'{}'", hex(&big)))).unwrap();
        });
        let (b, rt, imported) = import(label, &out, cfg);
        assert!(matches!(&imported, Err(Error::BadShipFile(_) | Error::InvalidName(_))), "{label}: {imported:?}");
        assert!(matches!(rt.deliver("~zod", "counter", b"get hits"), Err(Error::UnknownShip(_))));
        assert!(dirs(&b, "zod").is_empty(), "{label}: an import refused left files behind");
        assert_eq!(fs::read_dir(b.0.join("tmp")).unwrap().count(), 0, "{label}");
    };
    let chunk_of_big = "(SELECT dir FROM files WHERE id = BIG)";
    refused("hash", &format!("UPDATE file_chunks SET hash = zeroblob(32) WHERE n = 1 AND dir = {chunk_of_big}"), fast());
    refused("missing chunk", &format!("DELETE FROM file_chunks WHERE n = 1 AND dir = {chunk_of_big}"), fast());
    refused("extra chunk", &format!("INSERT INTO file_chunks SELECT dir, 3, gen, hash FROM file_chunks WHERE n = 0 AND dir = {chunk_of_big}"), fast());
    refused("stray chunk", "INSERT INTO file_chunks VALUES (zeroblob(16), 0, zeroblob(16), zeroblob(32))", fast());
    refused("short hash", &format!("UPDATE file_chunks SET hash = x'00' WHERE n = 0 AND dir = {chunk_of_big}"), fast());
    refused("length", "UPDATE files SET length = length + 1 WHERE id = BIG", fast());
    refused("id", "UPDATE files SET id = zeroblob(32) WHERE id = BIG", fast());
    refused("media type", "UPDATE files SET media_type = 'text/html; x=1' WHERE id = BIG", fast());
    refused("empty media type", "UPDATE files SET media_type = '' WHERE id = BIG", fast());
    refused("short dir", &format!("UPDATE file_chunks SET dir = x'00' WHERE dir = {chunk_of_big}; UPDATE files SET dir = x'00' WHERE id = BIG"), fast());
    refused("unclaimed", "DELETE FROM file_claims WHERE id = BIG", fast());
    refused("claim on nothing", "INSERT INTO file_claims VALUES ('counter', zeroblob(32), 0)", fast());
    refused("claim by no agent", "INSERT INTO file_claims VALUES ('Not An Agent', BIG, 0)", fast());
    // A claim is marked open or it is not.
    refused("open mark of 2", "UPDATE file_claims SET open = 2 WHERE id = BIG", fast());
    refused("open mark below 0", "UPDATE file_claims SET open = -1 WHERE id = BIG", fast());
    refused("open mark not a number", "UPDATE file_claims SET open = 'yes' WHERE id = BIG", fast());
    refused("an empty file with a chunk", "INSERT INTO file_chunks SELECT dir, 0, zeroblob(16), zeroblob(32) FROM files WHERE length = 0", fast());
    refused("an empty file under another id", "UPDATE files SET id = zeroblob(32) WHERE length = 0", fast());
    refused("a file with no chunks left", &format!("DELETE FROM file_chunks WHERE dir = {chunk_of_big}"), fast());
    // Every chunk there, under the right hashes, but one in the wrong place: the hashes still
    // come to the id, so only the numbering shows it.
    refused("a chunk out of place", &format!("UPDATE file_chunks SET n = 5 WHERE n = 2 AND dir = {chunk_of_big}"), fast());
    // A file said to be two chunks long, holding one chunk, under the id that one chunk's hash
    // gives for that length: the id checks out, so only the count of chunks shows it.
    let first = leaf(&made[2].2[..CHUNK as usize]);
    let short = hex(&runtime::files::file_id(2 * CHUNK, &first));
    refused(
        "fewer chunks than the length takes",
        &format!(
            "UPDATE files SET length = {}, id = x'{short}' WHERE id = BIG; UPDATE file_claims SET id = x'{short}' WHERE id = BIG;
             DELETE FROM file_chunks WHERE n > 0 AND dir = (SELECT dir FROM files WHERE id = x'{short}')",
            2 * CHUNK
        ),
        fast(),
    );
    // More than this runtime keeps, in bytes or in number.
    let held: u64 = made.iter().map(|(_, _, data)| data.len() as u64).sum();
    refused("too many bytes", "", Config { max_file_bytes: held - 1, ..fast() });
    refused("too many files", "", Config { max_files: 3, ..fast() });
    // As it was, with the limits just met, it comes in, files and all.
    fs::write(out.0.join("zod.ship"), &original).unwrap();
    let (_, _, imported) = import("rows-fine", &out, Config { max_file_bytes: held, max_files: 4, ..fast() });
    assert_eq!(imported.unwrap(), FilesKept { kept: 4, dropped: 0 });
    // A changed copy is still a copy if what changed is only an upload's: those rows are not
    // brought in. (The stream no longer matches the copy, so its files are dropped.)
    rework(&out, |file| file.execute_batch("UPDATE uploads SET media_type = 'nonsense'; INSERT INTO file_chunks SELECT dir, 1, zeroblob(16), zeroblob(32) FROM uploads").unwrap());
    let (b, rt, imported) = import("rows-upload", &out, fast());
    assert_eq!(imported.unwrap(), FilesKept { kept: 0, dropped: 4 });
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    assert!(live(&b, "zod").query_row("SELECT COUNT(*) FROM uploads", [], |r| r.get::<_, i64>(0)).unwrap() == 0);
}

#[test]
fn an_import_clears_what_an_earlier_one_left_and_one_at_a_time_comes_in() {
    let (a, out) = (TempDir::new("one-a"), TempDir::new("one-out"));
    let (_, made) = exported(&a, &out);
    let b = TempDir::new("one-b");
    // What an import that did not finish can leave: files of a ship that never came to be.
    fs::create_dir_all(b.0.join("files/zod").join("aa".repeat(16))).unwrap();
    fs::write(b.0.join("files/zod").join("aa".repeat(16)).join("0"), b"left behind").unwrap();
    let rt = Runtime::open(&b.0, fast()).unwrap();
    let won = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| match rt.import_ship_counted(&out.0, "~zod", CODE) {
                Ok(kept) => {
                    assert_eq!(kept, FilesKept { kept: 4, dropped: 0 });
                    won.fetch_add(1, Ordering::SeqCst);
                }
                Err(Error::ShipExists(_)) => {}
                Err(e) => panic!("{e}"),
            });
        }
    });
    assert_eq!(won.load(Ordering::SeqCst), 1);
    assert_eq!(dirs(&b, "zod").len(), 4);
    assert!(!dirs(&b, "zod").contains(&"aa".repeat(16)));
    for (agent, id, data) in &made {
        assert!(file_of(&rt, "~zod", agent, id) == *data);
    }
}

#[test]
fn finishing_a_ten_gibibyte_upload_reads_no_bytes_and_holds_the_ship_briefly() {
    let dir = TempDir::new("ten");
    // The default durability: every commit synced, as a runtime runs unless told otherwise.
    let rt = boot(&dir, Config::default());
    let length = 10 << 30;
    let chunks = chunk_count(length);
    assert_eq!(chunks, 10_240);
    let (upload, _) = rt.upload_start("~zod", "counter", length, "").unwrap();
    // Rows for every chunk, written beside the runtime, with no bytes behind them at all:
    // finishing works from the hashes the ship holds, and never reads the bytes again.
    let leaves: Vec<[u8; 32]> = (0..chunks).map(|n| leaf(&n.to_le_bytes())).collect();
    {
        let file = live(&dir, "zod");
        file.execute_batch("BEGIN").unwrap();
        for (n, hash) in leaves.iter().enumerate() {
            file.execute("INSERT INTO file_chunks VALUES (?1, ?2, ?3, ?4)", rusqlite::params![&upload[..], n as i64, &[(n as u64).to_le_bytes(), [0u8; 8]].concat()[..], &hash[..]]).unwrap();
        }
        file.execute_batch("COMMIT").unwrap();
    }
    let expected = runtime::files::file_id(length, &runtime::files::root(&leaves));
    let started = Instant::now();
    let info = rt.upload_finish("~zod", "counter", &upload, Some(expected)).unwrap();
    let finishing = started.elapsed();
    assert_eq!((info.id, info.chunks), (expected, chunks));
    assert_eq!(rt.file_bytes("~zod").unwrap(), (length, 0));
    let started = Instant::now();
    rt.file_delete("~zod", "counter", &expected).unwrap();
    let deleting = started.elapsed();
    assert_eq!(rt.file_bytes("~zod").unwrap(), (0, 0));
    eprintln!("with every commit synced, finishing a 10 GiB upload took {finishing:?}; deleting it took {deleting:?}");
    // Each call is one hold of the ship and little else. Generous, for an unoptimised build.
    assert!(finishing < Duration::from_secs(20) && deleting < Duration::from_secs(20));
}

#[test]
fn a_ship_holds_only_so_many_files() {
    let dir = TempDir::new("how-many");
    let rt = boot(&dir, Config { max_files: 2, ..fast() });
    let first = put_file(&rt, "~zod", "counter", b"one", "");
    put_file(&rt, "~zod", "counter", b"two", "");
    let (third, _) = rt.upload_start("~zod", "counter", 5, "").unwrap();
    rt.upload_chunk("~zod", "counter", &third, 0, b"three".to_vec()).unwrap();
    assert!(matches!(rt.upload_finish("~zod", "counter", &third, None), Err(Error::TooMany(_))));
    // A file the ship already holds is no new file: another claim on it is taken.
    assert_eq!(put_file(&rt, "~zod", "keeper", b"one", ""), first);
    rt.file_delete("~zod", "counter", &first).unwrap();
    rt.file_delete("~zod", "keeper", &first).unwrap();
    assert_eq!(rt.upload_finish("~zod", "counter", &third, None).unwrap().id, id_of(b"three"));
}

#[test]
fn a_copy_without_its_stream_is_never_refused_for_its_files() {
    let (a, out) = (TempDir::new("db-only-a"), TempDir::new("db-only-out"));
    let (_, made) = exported(&a, &out);
    let held: u64 = made.iter().map(|(_, _, data)| data.len() as u64).sum();
    let stream = fs::read(out.0.join("zod.files")).unwrap();
    let small = || Config { max_file_bytes: held - 1, ..fast() };
    let none = || Config { max_file_bytes: 0, ..fast() };
    let few = || Config { max_files: 1, ..fast() };
    // With its stream, a ship whose files this runtime would not keep is refused: the runtime
    // does not choose which of them to lose.
    for (label, cfg) in [("stream-small", small()), ("stream-off", none()), ("stream-few", few())] {
        let (b, rt, imported) = import(label, &out, cfg);
        assert!(matches!(&imported, Err(Error::BadShipFile(_))), "{label}: {imported:?}");
        assert!(matches!(rt.deliver("~zod", "counter", b"get hits"), Err(Error::UnknownShip(_))));
        assert!(dirs(&b, "zod").is_empty());
    }
    // Without it, no file can arrive, so none is kept and no limit on files refuses the ship.
    fs::remove_file(out.0.join("zod.files")).unwrap();
    for (label, cfg) in [("db-small", small()), ("db-off", none()), ("db-few", few())] {
        let (b, rt, imported) = import(label, &out, cfg);
        assert_eq!(imported.unwrap(), FilesKept { kept: 0, dropped: 4 }, "{label}");
        assert_eq!(send(&rt, "get hits"), "5");
        assert!(live(&b, "zod").query_row("SELECT (SELECT COUNT(*) FROM files) + (SELECT COUNT(*) FROM file_claims) + (SELECT COUNT(*) FROM file_chunks)", [], |r| r.get::<_, i64>(0)).unwrap() == 0);
        assert!(dirs(&b, "zod").is_empty());
    }
    fs::write(out.0.join("zod.files"), stream).unwrap();
}

#[test]
fn downloads_and_long_polls_never_take_every_thread() {
    let dir = TempDir::new("threads");
    // Four threads and the default `max_downloads` of 4: two may wait for logs, one may
    // download, and one is always left.
    let (rt, server) = serve(&dir, fast(), ServerConfig { workers: 4, io_timeout: Duration::from_secs(5), max_wait: Duration::from_secs(3), ..ServerConfig::default() });
    let auth = device(&rt, "~zod");
    let data = contents(8 * CHUNK as usize, 41);
    let id = put_file(&rt, "~zod", "counter", &data, "");
    let mut slow = stalled(&server, &auth, &id);
    let second = content(&server, &auth, "counter", &id, None);
    assert_eq!((second.status, second.header("Retry-After")), (503, Some("1")));
    // Two long polls on a log that does not grow, each holding a thread for three seconds.
    let started = Instant::now();
    let polls: Vec<_> = (0..2)
        .map(|_| {
            let (addr, auth) = (server.addr(), auth.clone());
            std::thread::spawn(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                let head = format!("GET /ships/zod/logs/counter/counter/entries?after=0&wait=3 HTTP/1.0\r\nHost: x\r\nAuthorization: {auth}\r\n\r\n");
                stream.write_all(head.as_bytes()).unwrap();
                let answer = read_answer(stream);
                (answer.status, started.elapsed())
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    // The thread left answers everything else at once.
    let asked = Instant::now();
    assert_eq!(get(&server, &auth, "/devices").status, 200);
    assert!(asked.elapsed() < Duration::from_secs(1), "waited {:?} for a thread", asked.elapsed());
    for poll in polls {
        let (status, took) = poll.join().unwrap();
        assert_eq!(status, 200);
        assert!(took >= Duration::from_millis(2500), "inconclusive: a long poll did not wait ({took:?})");
    }
    let mut rest = Vec::new();
    slow.read_to_end(&mut rest).unwrap();
    assert!(rest.len() > data.len(), "the download was cut off");

    // With two threads none can be spared for a download: a file's contents are refused, and
    // its chunks still come one at a time.
    let tight = Server::start(rt.clone(), ServerConfig { workers: 2, max_downloads: 100, ..ServerConfig::default() }).unwrap();
    let refused = http(&tight, "GET", &format!("/ships/zod/agents/counter/files/{}/content", hex(&id)), &[("Authorization", &auth)], b"");
    assert_eq!(refused.status, 503, "{}", refused.text());
    assert_eq!(http(&tight, "GET", &format!("/ships/zod/agents/counter/files/{}/chunks/0", hex(&id)), &[("Authorization", &auth)], b"").status, 200);
}

/// A claim's open mark goes with an exported copy, claim by claim, and comes back as it was.
#[test]
fn an_open_mark_goes_with_an_export() {
    let (a, out) = (TempDir::new("mark-a"), TempDir::new("mark-out"));
    let rt = boot(&a, fast());
    let data = contents(CHUNK as usize + 5, 41);
    let id = put_file(&rt, "~zod", "counter", &data, "");
    assert_eq!(put_file(&rt, "~zod", "keeper", &data, ""), id);
    let opened = rt.deliver("~zod", "counter", format!("open {}", hex(&id)).as_bytes()).unwrap().reply;
    assert_eq!(opened, b"true");
    assert!(rt.file_info("~zod", "counter", &id).unwrap().open && !rt.file_info("~zod", "keeper", &id).unwrap().open);
    rt.set_recovery_key("~zod", seal::recovery_public(CODE)).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    let (_b, back, imported) = import("mark-b", &out, fast());
    assert_eq!(imported.unwrap(), FilesKept { kept: 1, dropped: 0 });
    assert!(back.file_info("~zod", "counter", &id).unwrap().open);
    assert!(!back.file_info("~zod", "keeper", &id).unwrap().open);
}

/// Nor one from before claims could be marked open (schema 10).
#[test]
fn a_ship_file_from_before_open_marks_does_not_open() {
    let dir = TempDir::new("schema-10");
    drop(boot(&dir, fast()));
    live(&dir, "zod").execute("UPDATE meta SET value = 10 WHERE key = 'schema'", []).unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert!(matches!(rt.deliver("~zod", "counter", b"get hits"), Err(Error::BadShipFile(why)) if why.contains("schema")));
}

/// Nor one from before a ship kept files fetched from other ships (schema 11).
#[test]
fn a_ship_file_from_before_kept_files_does_not_open() {
    let dir = TempDir::new("schema-11");
    drop(boot(&dir, fast()));
    live(&dir, "zod").execute("UPDATE meta SET value = 11 WHERE key = 'schema'", []).unwrap();
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert!(matches!(rt.deliver("~zod", "counter", b"get hits"), Err(Error::BadShipFile(why)) if why.contains("schema")));
}
