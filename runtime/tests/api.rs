//! Describing an agent's interface once: the typed agents `guestbook` and `kit` run through the
//! runtime, the description a module carries and the checks made on it at install, and the HTTP
//! server's JSON door, whose JSON the agents' generated code reads and writes. The messages are
//! written out by hand here, apart from the generated code, so that the two are checked against
//! each other.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet, MessageOptions, MethodDescriptorProto, ServiceDescriptorProto};
use runtime::api::{CallError, Called, Encoding};
use runtime::net::{Directory, NetConfig, Network};
use runtime::server::{Server, ServerConfig};
use runtime::{seal, Config, Durability, Error, Manifest, Provide, Rejection, Runtime, Use};
use ship_proto::{call_reply, Call, CallReply, Fault, Message};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Build the kernel and the agents once per test run, and return one of them by name.
fn wasm(name: &str) -> Vec<u8> {
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
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-api-{label}", std::process::id()));
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

/// The guestbook's messages, written out by hand from `agents/guestbook/api/guestbook.proto`.
mod gb {
    use std::collections::HashMap;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ship_proto::prost::Enumeration)]
    #[prost(prost_path = "::ship_proto::prost")]
    #[repr(i32)]
    pub enum Mood {
        Unspecified = 0,
        Happy = 1,
        Grumpy = 2,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Address {
        #[prost(string, tag = "1")]
        pub town: String,
        #[prost(string, tag = "2")]
        pub ship: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Oneof)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub enum Contact {
        #[prost(string, tag = "8")]
        Email(String),
        #[prost(string, tag = "9")]
        Ship(String),
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Signature {
        #[prost(uint64, tag = "1")]
        pub number: u64,
        #[prost(string, tag = "2")]
        pub name: String,
        #[prost(bytes = "vec", tag = "3")]
        pub stamp: Vec<u8>,
        #[prost(enumeration = "Mood", tag = "4")]
        pub mood: i32,
        #[prost(message, optional, tag = "5")]
        pub from: Option<Address>,
        #[prost(string, repeated, tag = "6")]
        pub tags: Vec<String>,
        #[prost(map = "string, int64", tag = "7")]
        pub scores: HashMap<String, i64>,
        #[prost(oneof = "Contact", tags = "8, 9")]
        pub contact: Option<Contact>,
        #[prost(int32, optional, tag = "10")]
        pub age: Option<i32>,
        #[prost(uint64, tag = "11")]
        pub signed_at: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct SignRequest {
        #[prost(message, optional, tag = "1")]
        pub signature: Option<Signature>,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Signed {
        #[prost(uint64, tag = "1")]
        pub number: u64,
        #[prost(uint64, tag = "2")]
        pub total: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Number {
        #[prost(uint64, tag = "1")]
        pub number: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct PassRequest {
        #[prost(uint64, tag = "1")]
        pub number: u64,
        #[prost(string, tag = "2")]
        pub ship: String,
        #[prost(string, tag = "3")]
        pub agent: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct FetchRequest {
        #[prost(string, tag = "1")]
        pub ship: String,
        #[prost(string, tag = "2")]
        pub agent: String,
        #[prost(uint64, tag = "3")]
        pub number: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Agent {
        #[prost(string, tag = "1")]
        pub agent: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct ScribbleRequest {
        #[prost(bytes = "vec", tag = "1")]
        pub raw: Vec<u8>,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct LookupRequest {
        #[prost(string, tag = "1")]
        pub prefix: String,
        #[prost(uint32, optional, tag = "2")]
        pub limit: Option<u32>,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Page {
        #[prost(message, repeated, tag = "1")]
        pub signatures: Vec<Signature>,
        #[prost(uint64, tag = "2")]
        pub total: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct PeekRequest {
        #[prost(string, tag = "1")]
        pub agent: String,
        #[prost(uint64, tag = "2")]
        pub number: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Activity {
        #[prost(string, repeated, tag = "1")]
        pub receipts: Vec<String>,
        #[prost(string, repeated, tag = "2")]
        pub answers: Vec<String>,
        #[prost(uint64, repeated, tag = "3")]
        pub taken: Vec<u64>,
        #[prost(uint64, repeated, tag = "4")]
        pub undecoded: Vec<u64>,
        #[prost(uint64, tag = "5")]
        pub checkpoints: u64,
        #[prost(uint64, tag = "6")]
        pub visits: u64,
        #[prost(uint64, tag = "7")]
        pub erase_attempts: u64,
        #[prost(bytes = "vec", repeated, tag = "8")]
        pub undecoded_bytes: Vec<Vec<u8>>,
        #[prost(uint64, tag = "9")]
        pub bad_checkpoints: u64,
        #[prost(message, optional, tag = "10")]
        pub checkpoint: Option<Book>,
        #[prost(uint64, tag = "11")]
        pub checkpoint_seq: u64,
        #[prost(uint64, tag = "12")]
        pub spoils: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Book {
        #[prost(message, repeated, tag = "1")]
        pub signatures: Vec<Signature>,
        #[prost(uint64, tag = "2")]
        pub next: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Visit {
        #[prost(string, tag = "1")]
        pub who: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct VisitCount {
        #[prost(uint64, tag = "1")]
        pub visits: u64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Empty {}

    // The kit's.
    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Name {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub nickname: String,
        #[prost(uint64, repeated, tag = "3")]
        pub counts: Vec<u64>,
        #[prost(int32, tag = "4")]
        pub level: i32,
        #[prost(string, tag = "5")]
        pub odd: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Timestamp {
        #[prost(int64, tag = "1")]
        pub seconds: i64,
        #[prost(int32, tag = "2")]
        pub nanos: i32,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Int64Value {
        #[prost(int64, tag = "1")]
        pub value: i64,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct BoolValue {
        #[prost(bool, tag = "1")]
        pub value: bool,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Stamped {
        #[prost(message, optional, tag = "1")]
        pub at: Option<Timestamp>,
        #[prost(message, optional, tag = "2")]
        pub millis: Option<Int64Value>,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Thing {
        #[prost(string, tag = "1")]
        pub word: String,
    }

    #[derive(Clone, PartialEq, ship_proto::prost::Message)]
    #[prost(prost_path = "::ship_proto::prost")]
    pub struct Haul {
        #[prost(uint64, repeated, tag = "1")]
        pub seqs: Vec<u64>,
        #[prost(bytes = "vec", repeated, tag = "2")]
        pub payloads: Vec<Vec<u8>>,
        #[prost(uint64, tag = "3")]
        pub decoded: u64,
        #[prost(uint64, tag = "4")]
        pub checkpoint_seq: u64,
        #[prost(bytes = "vec", tag = "5")]
        pub checkpoint_bytes: Vec<u8>,
        #[prost(uint64, tag = "6")]
        pub checkpoints_decoded: u64,
    }
}

/// A signature with something in every field that is awkward in JSON.
fn awkward(name: &str) -> gb::Signature {
    gb::Signature {
        number: 0,
        name: name.into(),
        stamp: vec![0, 1, 2, 250, 255],
        mood: gb::Mood::Grumpy as i32,
        from: Some(gb::Address { town: "Lisbon".into(), ship: "~sampel-palnet".into() }),
        tags: vec!["first".into(), "second".into()],
        scores: HashMap::from([("chess".to_string(), 9_007_199_254_740_993i64), ("go".to_string(), -3)]),
        contact: Some(gb::Contact::Email("guest@example.com".into())),
        age: Some(41),
        signed_at: u64::MAX,
    }
}

/// A guestbook's manifest: both interfaces, `guestbook` open to other ships' commands and
/// questions; leave to read and send to the guestbook interface of each agent in `peers` on
/// this ship, and to follow their visits; and leave to send to and ask the agent `book` on
/// `remote`, if given.
fn book_manifest(peers: &[&str], remote: Option<&str>) -> Manifest {
    let mut uses: Vec<Use> = peers
        .iter()
        .flat_map(|peer| {
            [
                Use { agent: peer.to_string(), interface: "guestbook".into(), read: true, send: true, ship: String::new(), ask: false },
                Use { agent: peer.to_string(), interface: "visits".into(), read: true, send: false, ship: String::new(), ask: false },
            ]
        })
        .collect();
    if let Some(ship) = remote {
        uses.push(Use { agent: "book".into(), interface: "guestbook".into(), read: false, send: true, ship: ship.trim_start_matches('~').into(), ask: true });
    }
    Manifest {
        provides: vec![Provide { interface: "guestbook".into(), public: false, remote: true, asked: true }, Provide { interface: "visits".into(), public: false, remote: false, asked: false }],
        uses,
    }
}

/// A runtime with `~zod` and, for each name given, a guestbook installed under it, each allowed
/// to use the others.
fn books(dir: &TempDir, cfg: Config, names: &[&str]) -> Arc<Runtime> {
    let rt = Arc::new(Runtime::open(&dir.0, cfg).unwrap());
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    let book = rt.add_module(&wasm("guestbook")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    for name in names {
        let peers: Vec<&str> = names.iter().copied().filter(|other| other != name).collect();
        rt.install("~zod", name, &book, &book_manifest(&peers, None)).unwrap();
    }
    rt
}

/// A typed call as the owner, with protobuf bodies: the reply decoded, or why there is none.
fn call<R: Message + Default>(rt: &Runtime, agent: &str, interface: &str, method: &str, request: &impl Message) -> Result<R, CallError> {
    match rt.call_method("~zod", agent, interface, method, &request.encode_to_vec(), Encoding::Protobuf)? {
        Called::Reply(body) => Ok(R::decode(&*body).unwrap()),
        Called::Fault(fault) => Err(CallError::BadReply(format!("fault {}: {}", fault.code, fault.message))),
    }
}

/// The fault a typed call answered with, as `(code, message)`; panics on anything else.
fn fault_of(rt: &Runtime, agent: &str, interface: &str, method: &str, request: &impl Message) -> (String, String) {
    match rt.call_method("~zod", agent, interface, method, &request.encode_to_vec(), Encoding::Protobuf) {
        Ok(Called::Fault(fault)) => (fault.code, fault.message),
        other => panic!("expected a fault, got {other:?}"),
    }
}

fn sign(rt: &Runtime, agent: &str, signature: gb::Signature) -> gb::Signed {
    call(rt, agent, "guestbook", "Sign", &gb::SignRequest { signature: Some(signature) }).unwrap()
}

fn report(rt: &Runtime, agent: &str) -> gb::Activity {
    call(rt, agent, "guestbook", "Report", &gb::Empty {}).unwrap()
}

fn page(rt: &Runtime, agent: &str) -> gb::Page {
    call(rt, agent, "guestbook", "Lookup", &gb::LookupRequest::default()).unwrap()
}

/// The `CallReply` a raw read with this payload answers with.
fn raw_read(rt: &Runtime, agent: &str, interface: &str, payload: &[u8]) -> CallReply {
    CallReply::decode(&*rt.read("~zod", agent, interface, payload).unwrap()).unwrap()
}

fn raw_call(method: &str, body: &[u8]) -> Vec<u8> {
    Call { method: method.into(), body: body.to_vec(), json: false }.encode_to_vec()
}

fn fault_code(reply: &CallReply) -> String {
    match &reply.result {
        Some(call_reply::Result::Fault(fault)) => fault.code.clone(),
        other => panic!("expected a fault, got {other:?}"),
    }
}

fn is_trap(result: Result<runtime::Outcome, Error>) -> bool {
    matches!(result, Err(Error::Rejected(Rejection::Trap(_))))
}

fn settle(rt: &Runtime, ship: &str) {
    for _ in 0..1000 {
        if rt.run_pending(ship, 10).unwrap() == 0 {
            return;
        }
    }
    panic!("the ship's queue never emptied");
}

/// The kit's manifest: its four interfaces, and leave to read the guestbook interface of `book`
/// and to follow the counter's log.
fn kit_manifest() -> Manifest {
    Manifest {
        provides: ["api", "command", "files", "kit"].iter().map(|interface| Provide { interface: interface.to_string(), public: false, remote: false, asked: false }).collect(),
        uses: vec![
            Use { agent: "book".into(), interface: "guestbook".into(), read: true, send: false, ship: String::new(), ask: false },
            Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false, ship: String::new(), ask: false },
        ],
    }
}

fn counter_manifest() -> Manifest {
    Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: false, asked: false }], uses: vec![] }
}

#[test]
fn a_typed_command_and_question_round_trip_as_the_owner() {
    let dir = TempDir::new("round-trip");
    let rt = books(&dir, fast(), &["book"]);
    let signed = sign(&rt, "book", awkward("first visitor"));
    assert_eq!(signed, gb::Signed { number: 1, total: 1 });
    assert_eq!(sign(&rt, "book", gb::Signature { name: "second".into(), ..Default::default() }), gb::Signed { number: 2, total: 2 });
    let got: gb::Signature = call(&rt, "book", "guestbook", "Get", &gb::Number { number: 1 }).unwrap();
    assert_eq!(got, gb::Signature { number: 1, ..awkward("first visitor") });
    let listed = page(&rt, "book");
    assert_eq!(listed.total, 2);
    assert_eq!(listed.signatures.iter().map(|s| s.number).collect::<Vec<_>>(), [2, 1]);
    let limited: gb::Page = call(&rt, "book", "guestbook", "Lookup", &gb::LookupRequest { prefix: "first".into(), limit: Some(1) }).unwrap();
    assert_eq!(limited.signatures.len(), 1);
    assert_eq!(limited.signatures[0].name, "first visitor");
    // The second interface is served by the same module and found by the interface the call
    // came through.
    let visited: gb::VisitCount = call(&rt, "book", "visits", "Visit", &gb::Visit { who: "~zod".into() }).unwrap();
    assert_eq!(visited.visits, 1);
    let counted: gb::VisitCount = call(&rt, "book", "visits", "Count", &gb::Empty {}).unwrap();
    assert_eq!(counted.visits, 1);

    // The same, done by hand: a command under the interface (`deliver_on`) with a `Call` as its
    // payload comes back with a `CallReply` holding the output.
    let body = gb::SignRequest { signature: Some(gb::Signature { name: "by hand".into(), ..Default::default() }) }.encode_to_vec();
    let outcome = rt.deliver_on("~zod", "book", "guestbook", &raw_call("Sign", &body)).unwrap();
    match CallReply::decode(&*outcome.reply).unwrap().result {
        Some(call_reply::Result::Body(body)) => assert_eq!(gb::Signed::decode(&*body).unwrap(), gb::Signed { number: 3, total: 3 }),
        other => panic!("{other:?}"),
    }
}

#[test]
fn what_the_generated_dispatch_refuses_and_what_it_keeps() {
    let dir = TempDir::new("refusals");
    let rt = books(&dir, fast(), &["book"]);
    let kit = rt.add_module(&wasm("kit")).unwrap();
    rt.install("~zod", "kit", &kit, &kit_manifest()).unwrap();
    sign(&rt, "book", gb::Signature { name: "kept".into(), ..Default::default() });
    let before = page(&rt, "book");
    let sign_body = gb::SignRequest { signature: Some(gb::Signature { name: "never".into(), ..Default::default() }) }.encode_to_vec();

    // A question to a method the interface does not have, with a body that does not decode, or
    // that is a command, is answered with a fault; the command is not run.
    assert_eq!(fault_code(&raw_read(&rt, "book", "guestbook", &raw_call("Nope", b""))), "ship.no-such-method");
    assert_eq!(fault_code(&raw_read(&rt, "book", "guestbook", &raw_call("Get", &[0xff, 0xff, 0xff]))), "ship.not-understood");
    // A command that changes nothing, reached as a question, is refused, not run (its answer
    // would show it had been); and one that writes.
    assert_eq!(fault_code(&raw_read(&rt, "kit", "kit", &raw_call("Echo", &gb::Name { name: "x".into(), ..Default::default() }.encode_to_vec()))), "ship.wrong-kind");
    assert_eq!(fault_code(&raw_read(&rt, "book", "guestbook", &raw_call("Sign", &sign_body))), "ship.wrong-kind");
    // The log is not a method to call either way.
    assert_eq!(fault_code(&raw_read(&rt, "book", "guestbook", &raw_call("Signatures", b""))), "ship.no-such-method");
    // A payload that is not a call, and an interface the agent does not describe.
    assert_eq!(fault_code(&raw_read(&rt, "book", "guestbook", &[0xff, 0xff])), "ship.not-understood");
    assert_eq!(fault_code(&raw_read(&rt, "book", "nothing-here", &raw_call("Get", b""))), "ship.no-such-interface");
    assert_eq!(page(&rt, "book"), before);

    // On the command path each of those traps, and nothing is kept.
    let count_erases = |rt: &Runtime| report(rt, "book").erase_attempts;
    assert!(is_trap(rt.deliver_on("~zod", "book", "guestbook", &raw_call("Nope", b""))));
    assert!(is_trap(rt.deliver_on("~zod", "book", "guestbook", &raw_call("Erase", &[0xff, 0xff, 0xff]))));
    assert!(is_trap(rt.deliver_on("~zod", "book", "guestbook", &raw_call("Get", &gb::Number { number: 1 }.encode_to_vec()))));
    assert!(is_trap(rt.deliver_on("~zod", "book", "guestbook", &raw_call("Signatures", b""))));
    assert!(is_trap(rt.deliver_on("~zod", "book", "guestbook", &[0xff, 0xff])));
    assert!(is_trap(rt.deliver_on("~zod", "book", "nothing-here", &raw_call("Sign", &sign_body))));
    // An owner's untyped command comes through no interface, and is refused the same way.
    assert!(is_trap(rt.deliver("~zod", "book", &raw_call("Sign", &sign_body))));
    assert_eq!(page(&rt, "book"), before);
    assert_eq!(count_erases(&rt), 0);
}

#[test]
fn a_command_whose_handler_fails_keeps_nothing() {
    let dir = TempDir::new("command-fault");
    let rt = books(&dir, fast(), &["book"]);
    sign(&rt, "book", gb::Signature { name: "one".into(), ..Default::default() });
    let (head, book, activity) = (rt.log_head("~zod", "book", "guestbook").unwrap(), page(&rt, "book"), report(&rt, "book"));
    // Spoil appends an entry to the log, writes the book and a count, and then fails: none of it
    // is kept. What was kept is looked at first, then how the call ended.
    let spoilt = rt.call_method("~zod", "book", "guestbook", "Spoil", &gb::Empty {}.encode_to_vec(), Encoding::Protobuf);
    assert_eq!(rt.log_head("~zod", "book", "guestbook").unwrap(), head);
    assert_eq!(page(&rt, "book"), book);
    assert_eq!(report(&rt, "book"), activity);
    assert!(matches!(spoilt, Err(CallError::Runtime(Error::Rejected(Rejection::Trap(_))))), "{spoilt:?}");
    // Erase counts the attempt and then finds nothing to erase: the count is not kept either.
    let erased = rt.call_method("~zod", "book", "guestbook", "Erase", &gb::Number { number: 9 }.encode_to_vec(), Encoding::Protobuf);
    assert_eq!(report(&rt, "book").erase_attempts, 0);
    assert!(matches!(erased, Err(CallError::Runtime(Error::Rejected(Rejection::Trap(_))))), "{erased:?}");
    // One that works is kept, the count and the log entry with it.
    let erased: gb::Number = call(&rt, "book", "guestbook", "Erase", &gb::Number { number: 1 }).unwrap();
    assert_eq!(erased.number, 0);
    assert_eq!(report(&rt, "book").erase_attempts, 1);
    assert_eq!(rt.log_head("~zod", "book", "guestbook").unwrap().unwrap().0, head.unwrap().0 + 1);
    assert_eq!(page(&rt, "book").total, 0);
}

#[test]
fn a_question_fault_arrives_typed_and_a_handler_cannot_use_the_reserved_codes() {
    let dir = TempDir::new("question-fault");
    let rt = books(&dir, fast(), &["book"]);
    let (code, message) = fault_of(&rt, "book", "guestbook", "Get", &gb::Number { number: 7 });
    assert_eq!((code.as_str(), message.as_str()), ("no-such-signature", "this book has no signature 7"));
    // The handler answers with a code starting with `ship.`, which only the generated code may
    // make: it arrives rewritten.
    let (code, _) = fault_of(&rt, "book", "guestbook", "Lookup", &gb::LookupRequest { prefix: "ship.no-such-method".into(), limit: None });
    assert_eq!(code, "app.ship.no-such-method");
}

#[test]
fn unknown_fields_in_a_body_are_ignored() {
    let dir = TempDir::new("unknown-fields");
    let rt = books(&dir, fast(), &["book"]);
    sign(&rt, "book", gb::Signature { name: "one".into(), ..Default::default() });
    // Field 99, which GetRequest does not have, after the number.
    let mut body = gb::Number { number: 1 }.encode_to_vec();
    body.extend_from_slice(&[0x98, 0x06, 0x05]);
    match rt.call_method("~zod", "book", "guestbook", "Get", &body, Encoding::Protobuf).unwrap() {
        Called::Reply(reply) => assert_eq!(gb::Signature::decode(&*reply).unwrap().name, "one"),
        other => panic!("{other:?}"),
    }
    // And in JSON, read by the agent.
    match rt.call_method("~zod", "book", "guestbook", "Get", br#"{"number": "1", "notAField": [1, {"x": 2}]}"#, Encoding::Json).unwrap() {
        Called::Reply(reply) => assert_eq!(serde_json::from_slice::<serde_json::Value>(&reply).unwrap()["name"], "one"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_typed_read_and_send_of_another_instance_on_the_same_ship() {
    let dir = TempDir::new("same-ship");
    let rt = books(&dir, fast(), &["book", "spare"]);
    sign(&rt, "spare", gb::Signature { name: "in the spare".into(), ..Default::default() });
    // A typed read through the other instance, from a question handler.
    let peeked: gb::Signature = call(&rt, "book", "guestbook", "Peek", &gb::PeekRequest { agent: "spare".into(), number: 1 }).unwrap();
    assert_eq!(peeked.name, "in the spare");
    // The other instance's fault comes through the typed read as it was.
    let (code, message) = fault_of(&rt, "book", "guestbook", "Peek", &gb::PeekRequest { agent: "spare".into(), number: 5 });
    assert_eq!((code.as_str(), message.as_str()), ("no-such-signature", "this book has no signature 5"));
    // A typed send: the book passes one of its signatures to the spare, which signs it in its
    // own event, after the book's commits.
    sign(&rt, "book", awkward("passed on"));
    let passed: gb::Number = call(&rt, "book", "guestbook", "Pass", &gb::PassRequest { number: 1, ship: String::new(), agent: "spare".into() }).unwrap();
    assert_eq!(passed.number, 0);
    settle(&rt, "~zod");
    let spare = page(&rt, "spare");
    assert_eq!(spare.total, 2);
    assert_eq!(spare.signatures[0], gb::Signature { number: 2, ..awkward("passed on") });
}

fn checkpointing() -> Config {
    Config { checkpoint_min_bytes: 500, ..fast() }
}

/// The name the test gives the signature of the given number in the checkpoint test: one, two,
/// then (after entry 3, which is not a signature) three, and visitors.
fn name_of(number: u64) -> String {
    match number {
        1 => "one".into(),
        2 => "two".into(),
        3 => "three".into(),
        n => format!("visitor {} with a name long enough to fill the log", n - 4),
    }
}

#[test]
fn a_typed_log_is_appended_taken_and_summed_up_by_its_checkpoint() {
    let dir = TempDir::new("logs");
    let rt = books(&dir, Config { max_queued_per_deliver: 0, ..checkpointing() }, &["book", "spare", "late"]);
    call::<gb::Empty>(&rt, "spare", "guestbook", "Follow", &gb::Agent { agent: "book".into() }).unwrap();
    sign(&rt, "book", gb::Signature { name: "one".into(), ..Default::default() });
    sign(&rt, "book", gb::Signature { name: "two".into(), ..Default::default() });
    // An entry that is not a signature: handed over as one that does not decode, with its
    // number and its bytes, and the position moves past it as past any other.
    call::<gb::Empty>(&rt, "book", "guestbook", "Scribble", &gb::ScribbleRequest { raw: vec![0xff, 0xff, 0xff] }).unwrap();
    sign(&rt, "book", gb::Signature { name: "three".into(), ..Default::default() });
    for who in ["~zod", "~nec"] {
        call::<gb::VisitCount>(&rt, "book", "visits", "Visit", &gb::Visit { who: who.into() }).unwrap();
    }
    settle(&rt, "~zod");
    let taken = report(&rt, "spare");
    assert_eq!(taken.taken, [1, 2, 4]);
    assert_eq!(taken.undecoded, [3]);
    assert_eq!(taken.undecoded_bytes, [vec![0xff, 0xff, 0xff]]);
    assert_eq!(taken.visits, 2);
    assert_eq!((taken.checkpoints, taken.bad_checkpoints), (0, 0));
    assert_eq!(rt.log_position("~zod", "spare", "book", "guestbook").unwrap(), Some(4));
    // Each entry is the signature, encoded.
    let entries = rt.log_entries("~zod", "book", "guestbook", 0, usize::MAX).unwrap();
    let first = ship_proto::EntryBody::decode(&*entries[0].body).unwrap();
    assert_eq!(gb::Signature::decode(&*first.payload).unwrap().name, "one");

    // Enough signatures for the runtime to ask for a checkpoint, which the generated checkpoint
    // export takes from the typed handler: the whole book.
    for n in 0..30 {
        sign(&rt, "book", gb::Signature { name: format!("visitor {n} with a name long enough to fill the log"), ..Default::default() });
        settle(&rt, "~zod");
    }
    let signed = rt.log_checkpoint("~zod", "book", "guestbook").unwrap().expect("the book's log has a checkpoint");
    let key = rt.public_key("~zod").unwrap();
    let ((seq, _), state) = runtime::verify_checkpoint(&key, "~zod", "book", "guestbook", &signed).unwrap();
    // The book as of entry `seq`, worked out here: entry 3 is not a signature, and every other
    // entry up to `seq` is signature number (entry - 1) after it, (entry) before it.
    let numbers: Vec<u64> = (1..=seq).filter(|entry| *entry != 3).map(|entry| if entry < 3 { entry } else { entry - 1 }).collect();
    let expected = gb::Book { signatures: numbers.iter().map(|n| gb::Signature { number: *n, name: name_of(*n), ..Default::default() }).collect(), next: *numbers.last().unwrap() };
    assert!(seq > 4, "checkpoint at {seq}");
    assert_eq!(gb::Book::decode(&*state).unwrap(), expected);
    assert!(matches!(rt.log_entries("~zod", "book", "guestbook", 0, usize::MAX), Err(Error::LogTrimmed(_))));
    // A follower that comes late is handed the state, decoded, in place of the entries it cannot
    // have, and then the entries after it.
    call::<gb::Empty>(&rt, "late", "guestbook", "Follow", &gb::Agent { agent: "book".into() }).unwrap();
    settle(&rt, "~zod");
    let late = report(&rt, "late");
    assert_eq!((late.checkpoints, late.bad_checkpoints), (1, 0));
    assert_eq!(late.checkpoint_seq, seq);
    assert_eq!(late.checkpoint, Some(expected));
    assert!(late.taken.first().is_some_and(|first| *first == seq + 1), "{:?} after {seq}", late.taken);
    assert_eq!(*late.taken.last().unwrap(), rt.log_head("~zod", "book", "guestbook").unwrap().unwrap().0);
    // The visits are a history: never summed up, kept whole.
    for n in 0..30 {
        call::<gb::VisitCount>(&rt, "book", "visits", "Visit", &gb::Visit { who: format!("visitor {n} with a name long enough to fill the log") }).unwrap();
        settle(&rt, "~zod");
    }
    assert!(rt.log_checkpoint("~zod", "book", "visits").unwrap().is_none());
    assert_eq!(rt.log_entries("~zod", "book", "visits", 0, usize::MAX).unwrap().len(), 32);
}

#[test]
fn entries_and_a_checkpoint_state_that_do_not_decode_are_handed_over_with_their_bytes() {
    // The kit follows the counter's log through stubs of an interface it only calls, whose types
    // the counter's text entries do not decode as.
    let dir = TempDir::new("undecoded");
    let rt = Runtime::open(&dir.0, Config { max_queued_per_deliver: 0, ..checkpointing() }).unwrap();
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    let (counter, kit) = (rt.add_module(&wasm("counter")).unwrap(), rt.add_module(&wasm("kit")).unwrap());
    rt.install("~zod", "counter", &counter, &counter_manifest()).unwrap();
    rt.install("~zod", "kit", &kit, &kit_manifest()).unwrap();
    for _ in 0..20 {
        rt.deliver("~zod", "counter", b"log hits").unwrap();
        settle(&rt, "~zod");
    }
    let signed = rt.log_checkpoint("~zod", "counter", "counter").unwrap().expect("the counter's log has a checkpoint");
    let key = rt.public_key("~zod").unwrap();
    let ((seq, _), state) = runtime::verify_checkpoint(&key, "~zod", "counter", "counter", &signed).unwrap();
    call::<gb::Empty>(&rt, "kit", "kit", "FollowCounter", &gb::Empty {}).unwrap();
    settle(&rt, "~zod");
    let haul: gb::Haul = call(&rt, "kit", "kit", "Taken", &gb::Empty {}).unwrap();
    assert_eq!((haul.decoded, haul.checkpoints_decoded), (0, 0));
    assert_eq!(haul.checkpoint_seq, seq);
    assert_eq!(haul.checkpoint_bytes, state);
    assert_eq!(haul.seqs, (seq + 1..=20).collect::<Vec<u64>>());
    let payloads: Vec<Vec<u8>> = (seq + 1..=20).map(|n| format!("hits={n}").into_bytes()).collect();
    assert_eq!(haul.payloads, payloads);
}

/// Two runtimes on this machine, each with its network, with the book on `~zod` and on `~nec`
/// each allowed to send to and ask the other.
struct Two {
    a: Arc<Runtime>,
    b: Arc<Runtime>,
    _nets: (Network, Network),
    _dirs: (TempDir, TempDir),
}

fn two(label: &str) -> Two {
    let dirs = (TempDir::new(&format!("{label}-a")), TempDir::new(&format!("{label}-b")));
    let directory = Directory::new();
    let make = |dir: &TempDir, ship: &str, other: &str| {
        let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
        let kernel = rt.add_module(&wasm("kernel")).unwrap();
        let book = rt.add_module(&wasm("guestbook")).unwrap();
        rt.create_ship(ship, &kernel).unwrap();
        rt.install(ship, "book", &book, &book_manifest(&[], Some(other))).unwrap();
        rt
    };
    let a = make(&dirs.0, "~zod", "~nec");
    let a_net = Network::start(a.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~zod", a.public_key("~zod").unwrap(), a_net.addr()).unwrap();
    let b = make(&dirs.1, "~nec", "~zod");
    let b_net = Network::start(b.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set("~nec", b.public_key("~nec").unwrap(), b_net.addr()).unwrap();
    Two { a, b, _nets: (a_net, b_net), _dirs: dirs }
}

fn call_on<R: Message + Default>(rt: &Runtime, ship: &str, method: &str, request: &impl Message) -> R {
    match rt.call_method(ship, "book", "guestbook", method, &request.encode_to_vec(), Encoding::Protobuf).unwrap() {
        Called::Reply(body) => R::decode(&*body).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// Wait up to a minute for the book on `ship` to report a line starting with `number`.
fn wait_for_line(rt: &Runtime, ship: &str, number: u64, answers: bool) -> String {
    let started = Instant::now();
    loop {
        let activity: gb::Activity = call_on(rt, ship, "Report", &gb::Empty {});
        let lines = if answers { activity.answers } else { activity.receipts };
        if let Some(line) = lines.into_iter().find(|line| line.split(' ').next() == Some(&number.to_string())) {
            return line;
        }
        assert!(started.elapsed() < Duration::from_secs(60), "nothing came back for {number}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn across_two_ships_a_typed_command_brings_its_reply_and_a_typed_question_its_answer() {
    let t = two("two-ships");
    let signed: gb::Signed = call_on(&t.a, "~zod", "Sign", &gb::SignRequest { signature: Some(awkward("on zod")) });
    assert_eq!(signed.number, 1);
    // ~nec asks ~zod's book for signature 1 with a typed `ask::to`; the answer, decoded by the
    // generated code in its answer handler, is the signature.
    let asked: gb::Number = call_on(&t.b, "~nec", "Fetch", &gb::FetchRequest { ship: "zod".into(), agent: "book".into(), number: 1 });
    assert!(asked.number > 0);
    assert_eq!(wait_for_line(&t.b, "~nec", asked.number, true), format!("{} signature 1 by on zod", asked.number));
    // A question fault comes through the answer, typed.
    let asked: gb::Number = call_on(&t.b, "~nec", "Fetch", &gb::FetchRequest { ship: "zod".into(), agent: "book".into(), number: 42 });
    assert_eq!(wait_for_line(&t.b, "~nec", asked.number, true), format!("{} fault no-such-signature: this book has no signature 42", asked.number));
    // ~zod passes its signature to ~nec's book with a typed `send_to_for_reply`; the receipt
    // carries the reply, which the generated code decodes.
    let passed: gb::Number = call_on(&t.a, "~zod", "Pass", &gb::PassRequest { number: 1, ship: "nec".into(), agent: "book".into() });
    assert!(passed.number > 0);
    assert_eq!(wait_for_line(&t.a, "~zod", passed.number, false), format!("{} signed as 1 of 1", passed.number));
    let on_nec: gb::Page = call_on(&t.b, "~nec", "Lookup", &gb::LookupRequest::default());
    assert_eq!(on_nec.signatures, [gb::Signature { number: 1, ..awkward("on zod") }]);
}

/// The custom sections named `ship.api.v1` in a module, read with `wasmparser`.
fn sections(module: &[u8]) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(module) {
        if let wasmparser::Payload::CustomSection(reader) = payload.unwrap() {
            if reader.name() == "ship.api.v1" {
                found.push(reader.data().to_vec());
            }
        }
    }
    found
}

#[test]
fn the_description_is_in_the_release_module_whole_and_readable() {
    let module = wasm("guestbook");
    let found = sections(&module);
    assert_eq!(found.len(), 1);
    let set = FileDescriptorSet::decode(&*found[0]).unwrap();
    let names: Vec<&str> = set.file.iter().map(|file| file.name()).collect();
    // The served file and what it imports, the import first, so that it stands alone.
    assert_eq!(names, ["google/protobuf/empty.proto", "guestbook.proto"]);
    let ours = &set.file[1];
    assert_eq!(ours.service.iter().map(|service| service.name()).collect::<Vec<_>>(), ["Guestbook", "Visits"]);
    // The comments are kept.
    let info = ours.source_code_info.as_ref().unwrap();
    assert!(info.location.iter().any(|location| location.leading_comments().contains("visitors sign it")));
    assert!(info.location.iter().all(|location| location.leading_comments.is_some() || location.trailing_comments.is_some() || !location.leading_detached_comments.is_empty()));
    // The runtime reads the same bytes, and the same interfaces.
    let dir = TempDir::new("release-module");
    let rt = books(&dir, fast(), &["book"]);
    let description = rt.description("~zod", "book").unwrap().unwrap();
    assert_eq!(description.bytes(), &found[0][..]);
    let interfaces: Vec<(&str, Vec<(&str, runtime::api::MethodKind)>)> =
        description.interfaces().map(|interface| (interface.name.as_str(), interface.methods.iter().map(|(name, kind)| (name.as_str(), *kind)).collect())).collect();
    use runtime::api::MethodKind::{Command, Log, Question};
    assert_eq!(
        interfaces,
        [
            (
                "guestbook",
                vec![
                    ("Erase", Command),
                    ("Fetch", Command),
                    ("Follow", Command),
                    ("Get", Question),
                    ("Lookup", Question),
                    ("Pass", Command),
                    ("Peek", Question),
                    ("Report", Question),
                    ("Scribble", Command),
                    ("Sign", Command),
                    ("Signatures", Log),
                    ("Spoil", Command)
                ]
            ),
            ("visits", vec![("Count", Question), ("History", Log), ("Visit", Command)]),
        ]
    );
    // An untyped agent has none.
    let counter = rt.add_module(&wasm("counter")).unwrap();
    rt.install("~zod", "counter", &counter, &counter_manifest()).unwrap();
    assert!(rt.description("~zod", "counter").unwrap().is_none());
    assert!(matches!(rt.description("~zod", "nobody"), Err(Error::UnknownAgent(_))));
}

#[test]
fn an_imported_files_services_are_left_out_of_the_description() {
    // The kit's file imports `shared.proto` for a message; its service, Ledger, is not the kit's.
    let set = FileDescriptorSet::decode(&*sections(&wasm("kit"))[0]).unwrap();
    let shared = set.file.iter().find(|file| file.name() == "shared.proto").expect("the import is in the description");
    assert!(shared.service.is_empty());
    assert_eq!(shared.message_type.iter().map(|message| message.name()).collect::<Vec<_>>(), ["Thing"]);
    assert!(shared.source_code_info.as_ref().is_none_or(|info| info.location.iter().all(|location| location.path.first() != Some(&6))));
    let services: Vec<&str> = set.file.iter().flat_map(|file| file.service.iter().map(|service| service.name())).collect();
    assert_eq!(services, ["Api", "Command", "Files", "Kit"]);
    // So a manifest providing only the kit's own interfaces is enough.
    let dir = TempDir::new("imported-services");
    let rt = books(&dir, fast(), &["book"]);
    let kit = rt.add_module(&wasm("kit")).unwrap();
    rt.install("~zod", "kit", &kit, &kit_manifest()).unwrap();
    let described: Vec<String> = rt.description("~zod", "kit").unwrap().unwrap().interfaces().map(|interface| interface.name.clone()).collect();
    assert_eq!(described, ["api", "command", "files", "kit"]);
}

/// `module` with a custom section named `name` holding `data` added at its end.
fn with_section(module: &[u8], name: &str, data: &[u8]) -> Vec<u8> {
    fn leb(mut n: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            out.push(if n == 0 { byte } else { byte | 0x80 });
            if n == 0 {
                return;
            }
        }
    }
    let mut body = Vec::new();
    leb(name.len(), &mut body);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    let mut out = module.to_vec();
    out.push(0);
    leb(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

/// `module` with every custom section named `ship.api.v1` taken out.
fn without_sections(module: &[u8]) -> Vec<u8> {
    fn leb(bytes: &[u8], at: &mut usize) -> usize {
        let (mut value, mut shift) = (0usize, 0);
        loop {
            let byte = bytes[*at];
            *at += 1;
            value |= ((byte & 0x7f) as usize) << shift;
            shift += 7;
            if byte < 0x80 {
                return value;
            }
        }
    }
    let mut out = module[..8].to_vec();
    let mut at = 8;
    while at < module.len() {
        let start = at;
        let id = module[at];
        at += 1;
        let size = leb(module, &mut at);
        let end = at + size;
        let named = id == 0 && {
            let mut inside = at;
            let length = leb(module, &mut inside);
            &module[inside..inside + length] == b"ship.api.v1"
        };
        if !named {
            out.extend_from_slice(&module[start..end]);
        }
        at = end;
    }
    out
}

/// A file of the given package holding the services given, each with the methods given as
/// `(name, client streaming, server streaming)`, every method taking and giving `Thing`.
fn made_file(package: &str, services: &[(&str, &[(&str, bool, bool)])]) -> FileDescriptorProto {
    let thing = DescriptorProto { name: Some("Thing".into()), ..Default::default() };
    let service = services
        .iter()
        .map(|(name, methods)| ServiceDescriptorProto {
            name: Some(name.to_string()),
            method: methods
                .iter()
                .map(|(method, client, server)| MethodDescriptorProto {
                    name: Some(method.to_string()),
                    input_type: Some(format!(".{package}.Thing")),
                    output_type: Some(format!(".{package}.Thing")),
                    client_streaming: Some(*client),
                    server_streaming: Some(*server),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .collect();
    FileDescriptorProto { name: Some(format!("{package}.proto")), package: Some(package.into()), message_type: vec![thing], service, syntax: Some("proto3".into()), ..Default::default() }
}

fn made_description(package: &str, services: &[(&str, &[(&str, bool, bool)])]) -> Vec<u8> {
    FileDescriptorSet { file: vec![made_file(package, services)] }.encode_to_vec()
}

fn providing(interfaces: &[&str]) -> Manifest {
    Manifest { provides: interfaces.iter().map(|interface| Provide { interface: interface.to_string(), public: false, remote: false, asked: false }).collect(), uses: vec![] }
}

#[test]
fn an_install_is_refused_for_each_rule_a_description_breaks() {
    let dir = TempDir::new("install-rules");
    let rt = Runtime::open(&dir.0, Config { max_api_bytes: 4096, ..fast() }).unwrap();
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    let counter = wasm("counter");
    let good = made_description("demo", &[("GroupChat", &[("Say", false, false), ("Said", false, true)])]);
    let refused = |module: Vec<u8>, manifest: &Manifest, words: &str| {
        let hash = rt.add_module(&module).unwrap();
        match rt.install("~zod", "typed", &hash, manifest) {
            Err(Error::BadModule(why)) => assert!(why.contains(words), "{why:?} does not say {words:?}"),
            other => panic!("expected the install to be refused for {words:?}, got {other:?}"),
        }
        // Nothing was installed.
        assert!(matches!(rt.description("~zod", "typed"), Err(Error::UnknownAgent(_))));
    };
    let chat = providing(&["group-chat"]);
    refused(with_section(&counter, "ship.api.v1", &[0x55; 5000]), &chat, "this runtime takes at most 4096 (max_api_bytes)");
    refused(with_section(&with_section(&counter, "ship.api.v1", &good), "ship.api.v1", &good), &chat, "more than one ship.api.v1 section");
    refused(with_section(&counter, "ship.api.v1", &[0xff, 0xff, 0xff, 0x0f]), &chat, "is not a FileDescriptorSet");
    // Both spellings a broken conversion could give are provided, so that only the rule refuses.
    refused(with_section(&counter, "ship.api.v1", &made_description("demo", &[("Two__Bars", &[])])), &providing(&["two--bars", "two__bars"]), "service demo.Two__Bars does not turn into a valid interface name");
    refused(with_section(&counter, "ship.api.v1", &made_description("demo", &[("Chat", &[("Upload", true, false)])])), &providing(&["chat"]), "method demo.Chat.Upload streams from its caller");
    refused(with_section(&counter, "ship.api.v1", &made_description("demo", &[("Chat", &[("Talk", true, true)])])), &providing(&["chat"]), "method demo.Chat.Talk streams from its caller");
    refused(with_section(&counter, "ship.api.v1", &made_description("demo", &[("Chat", &[("One", false, true), ("Two", false, true)])])), &providing(&["chat"]), "service demo.Chat has two streaming methods, One and Two");
    refused(with_section(&counter, "ship.api.v1", &made_description("demo", &[("GroupChat", &[]), ("Group_Chat", &[])])), &chat, "are both the interface \"group-chat\"");
    refused(with_section(&counter, "ship.api.v1", &good), &providing(&["other"]), "it describes the interface \"group-chat\" (service demo.GroupChat), which the manifest does not provide");

    // The same description passes with the interface provided, and with more provided than it
    // describes; the rest are untyped.
    let hash = rt.add_module(&with_section(&counter, "ship.api.v1", &good)).unwrap();
    rt.install("~zod", "typed", &hash, &providing(&["group-chat", "counter"])).unwrap();
    let description = rt.description("~zod", "typed").unwrap().unwrap();
    assert_eq!(description.interfaces().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["group-chat"]);
    // An untyped module installs as it always has.
    let plain = rt.add_module(&counter).unwrap();
    rt.install("~zod", "plain", &plain, &providing(&["counter"])).unwrap();
    // And the guestbook, whose description is larger than this runtime takes, does not.
    let book = rt.add_module(&wasm("guestbook")).unwrap();
    assert!(matches!(rt.install("~zod", "book", &book, &book_manifest(&[], None)), Err(Error::BadModule(why)) if why.contains("max_api_bytes")));
}

#[test]
fn a_description_the_runtime_does_not_resolve_installs_when_its_services_follow_the_rules() {
    // The runtime reads only services and method kinds: types that do not resolve, an import
    // cycle, a package of thousands of parts and a broken map entry are carried, not built. Each
    // set has one valid service, and installs at once.
    let dir = TempDir::new("unresolved");
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let kernel = rt.add_module(&wasm("kernel")).unwrap();
    rt.create_ship("~zod", &kernel).unwrap();
    let counter = wasm("counter");
    // A method whose types are nowhere in the set.
    let mut missing = made_file("demo", &[("Chat", &[("Say", false, false)])]);
    missing.message_type.clear();
    missing.service[0].method[0].input_type = Some(".elsewhere.Missing".into());
    // Two files that import each other publicly.
    let mut a = made_file("demo", &[("Chat", &[("Say", false, false)])]);
    a.name = Some("a.proto".into());
    a.dependency = vec!["b.proto".into()];
    a.public_dependency = vec![0];
    let b = FileDescriptorProto { name: Some("b.proto".into()), package: Some("demo".into()), dependency: vec!["a.proto".into()], public_dependency: vec![0], syntax: Some("proto3".into()), ..Default::default() };
    // A package of 5,000 parts.
    let deep = vec!["p"; 5000].join(".");
    let long = made_file(&deep, &[("Chat", &[("Say", false, false)])]);
    // A map field whose entry has a key and no value.
    let mut map = made_file("demo", &[("Chat", &[("Say", false, false)])]);
    let entry = DescriptorProto {
        name: Some("EntriesEntry".into()),
        field: vec![FieldDescriptorProto { name: Some("key".into()), number: Some(1), r#type: Some(9), label: Some(1), ..Default::default() }],
        options: Some(MessageOptions { map_entry: Some(true), ..Default::default() }),
        ..Default::default()
    };
    map.message_type[0].nested_type.push(entry);
    map.message_type[0].field.push(FieldDescriptorProto { name: Some("entries".into()), number: Some(1), r#type: Some(11), label: Some(3), type_name: Some(".demo.Thing.EntriesEntry".into()), ..Default::default() });
    for (label, files) in [("missing", vec![missing]), ("cycle", vec![a, b]), ("deep", vec![long]), ("map", vec![map])] {
        let set = FileDescriptorSet { file: files }.encode_to_vec();
        assert!(set.len() < 256 << 10, "{label}: {} bytes", set.len());
        let hash = rt.add_module(&with_section(&counter, "ship.api.v1", &set)).unwrap();
        let started = Instant::now();
        rt.install("~zod", label, &hash, &providing(&["chat"])).unwrap_or_else(|e| panic!("{label}: {e}"));
        let described = rt.description("~zod", label).unwrap().unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "{label} took {:?}", started.elapsed());
        assert_eq!(described.interfaces().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["chat"], "{label}");
    }
}

/// The recovery code the test ships are given.
const CODE: &str = "test-test-test-test-test-test-test-test";

#[test]
fn a_ship_brought_in_with_a_description_this_runtime_refuses_answers_as_one_with_none() {
    let (a, b, out) = (TempDir::new("import-a"), TempDir::new("import-b"), TempDir::new("import-out"));
    // On the first runtime, which takes descriptions up to a MiB, an agent whose description
    // carries 300 KiB more than it needs (an unknown field, which protobuf ignores).
    let first = books(&a, Config { max_api_bytes: 1 << 20, ..fast() }, &["book"]);
    let mut padded = sections(&wasm("guestbook")).remove(0);
    padded.extend_from_slice(&[0xfa, 0x3f]);
    let pad = 300 << 10;
    let mut length = Vec::new();
    let mut n = pad;
    while n >= 0x80 {
        length.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    length.push(n as u8);
    padded.extend_from_slice(&length);
    padded.extend(std::iter::repeat_n(b'.', pad));
    let module = with_section(&wasm("counter"), "ship.api.v1", &padded);
    let hash = first.add_module(&module).unwrap();
    first.install("~zod", "padded", &hash, &book_manifest(&[], None)).unwrap();
    assert!(first.description("~zod", "padded").unwrap().is_some());
    sign(&first, "book", gb::Signature { name: "before".into(), ..Default::default() });
    first.set_recovery_key("~zod", seal::recovery_public(CODE)).unwrap();
    first.export_ship("~zod", &out.0).unwrap();
    drop(first);
    // The second runtime takes descriptions up to the default 256 KiB. It brings the ship in;
    // the agent with the large description is answered as having none, and the rest of the
    // ship, the typed book among it, is as it was.
    let second = Runtime::open(&b.0, fast()).unwrap();
    second.import_ship(&out.0, "~zod", CODE).unwrap();
    assert!(second.description("~zod", "padded").unwrap().is_none());
    assert!(matches!(second.call_method("~zod", "padded", "guestbook", "Get", b"", Encoding::Protobuf), Err(CallError::NoDescription)));
    assert_eq!(page(&second, "book").signatures[0].name, "before");
}

#[test]
fn the_cache_shows_a_replaced_module_at_once_and_stays_bounded() {
    let dir = TempDir::new("cache");
    let rt = books(&dir, fast(), &["book"]);
    assert!(rt.description("~zod", "book").unwrap().unwrap().interface("visits").is_some());
    // The book's module is replaced by one describing another interface.
    let counter = wasm("counter");
    let replaced = rt.add_module(&with_section(&counter, "ship.api.v1", &made_description("demo", &[("Ledger", &[("Add", false, false)])]))).unwrap();
    rt.install("~zod", "book", &replaced, &providing(&["ledger", "guestbook", "visits"])).unwrap();
    let description = rt.description("~zod", "book").unwrap().unwrap();
    assert_eq!(description.interfaces().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["ledger"]);
    assert!(matches!(rt.call_method("~zod", "book", "visits", "Count", b"", Encoding::Protobuf), Err(CallError::NoSuchInterface(_))));
    // Thirty-four different modules, each asked for: never more than 32 kept.
    for n in 0..34 {
        let service = format!("Many{n}");
        let module = with_section(&counter, "ship.api.v1", &made_description("demo", &[(&service, &[])]));
        let hash = rt.add_module(&module).unwrap();
        let interface = ship_proto::interface_of_service(&service).unwrap();
        rt.install("~zod", &format!("many{n}"), &hash, &providing(&[&interface])).unwrap();
        assert_eq!(rt.description("~zod", &format!("many{n}")).unwrap().unwrap().interfaces().next().unwrap().name, interface);
        assert!(rt.described_modules() <= 32, "{} kept", rt.described_modules());
    }
    assert_eq!(rt.described_modules(), 32);
    // One let go is read again when asked for.
    assert_eq!(rt.description("~zod", "many0").unwrap().unwrap().interfaces().next().unwrap().name, "many0");
}

#[test]
fn a_module_that_cannot_be_read_once_is_not_remembered_as_having_no_description() {
    let dir = TempDir::new("read-failure");
    let rt = books(&dir, fast(), &["book"]);
    let hash = rt.add_module(&wasm("guestbook")).unwrap();
    // The module is compiled and running; its stored bytes go missing for a moment.
    let blob = dir.0.join("blobs").join(format!("{hash}.wasm"));
    let aside = dir.0.join("aside.wasm");
    fs::rename(&blob, &aside).unwrap();
    assert!(matches!(rt.description("~zod", "book"), Err(Error::UnknownModule(_))));
    assert_eq!(rt.described_modules(), 0);
    fs::rename(&aside, &blob).unwrap();
    assert!(rt.description("~zod", "book").unwrap().is_some());
    assert_eq!(rt.described_modules(), 1);
}

#[test]
fn a_module_already_compiled_installs_without_its_stored_bytes() {
    // As before descriptions: reinstalling an untyped agent whose module is compiled needs no
    // read of its stored bytes. And a typed module's description is still checked against the
    // manifest, from what was learnt when it was compiled.
    let dir = TempDir::new("install-compiled");
    let rt = books(&dir, fast(), &["book"]);
    let counter = rt.add_module(&wasm("counter")).unwrap();
    rt.install("~zod", "counter", &counter, &counter_manifest()).unwrap();
    let book = rt.add_module(&wasm("guestbook")).unwrap();
    let aside = |hash: &str| (dir.0.join("blobs").join(format!("{hash}.wasm")), dir.0.join(format!("{hash}.aside")));
    for hash in [&counter, &book] {
        let (blob, away) = aside(hash);
        fs::rename(&blob, &away).unwrap();
    }
    rt.install("~zod", "counter", &counter, &counter_manifest()).unwrap();
    assert_eq!(rt.deliver("~zod", "counter", b"inc hits").unwrap().reply, b"1");
    assert!(matches!(rt.install("~zod", "book", &book, &providing(&["guestbook"])), Err(Error::BadModule(why)) if why.contains("\"visits\"")));
    rt.install("~zod", "book", &book, &book_manifest(&[], None)).unwrap();
    for hash in [&counter, &book] {
        let (blob, away) = aside(hash);
        fs::rename(&away, &blob).unwrap();
    }
}

#[test]
fn a_package_shared_by_many_services_is_kept_once() {
    // Two hundred services in one file whose package is ten thousand bytes long: what the
    // runtime keeps of their names grows with the section, not with the package's length times
    // the number of services.
    let package = vec!["pkg"; 2500].join(".");
    let services: Vec<String> = (0..200).map(|n| format!("Service{n}")).collect();
    let listed: Vec<(&str, &[(&str, bool, bool)])> = services.iter().map(|name| (name.as_str(), [("Do", false, false)].as_slice())).collect();
    let bytes = made_description(&package, &listed);
    let description = runtime::api::describe(&bytes).unwrap();
    assert_eq!(description.interfaces().count(), 200);
    let kept = description.kept_name_bytes();
    assert!(kept < bytes.len(), "{kept} bytes of names kept for a section of {}", bytes.len());
    assert!(kept < package.len() * 2, "{kept}");
    let mut interfaces = description.interfaces();
    let (first, second) = (interfaces.next().unwrap(), interfaces.next().unwrap());
    assert!(Arc::ptr_eq(first.package(), second.package()));
    assert_eq!(first.service(), format!("{package}.{}", first.service().rsplit('.').next().unwrap()));
}

/// One HTTP request to the server; the status, the headers, and the body of the answer.
fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += "\r\n";
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines.filter_map(|line| line.split_once(": ")).map(|(name, value)| (name.to_ascii_lowercase(), value.to_string())).collect();
    (status, headers, raw[split + 4..].to_vec())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

/// A server in front of a runtime holding `~zod` with the book and the kit, and the token of a
/// device signed in to it.
struct Door {
    rt: Arc<Runtime>,
    server: Server,
    token: String,
    _dir: TempDir,
}

impl Door {
    fn new(label: &str, server: ServerConfig) -> Door {
        let dir = TempDir::new(label);
        let rt = books(&dir, fast(), &["book"]);
        let kit = rt.add_module(&wasm("kit")).unwrap();
        rt.install("~zod", "kit", &kit, &kit_manifest()).unwrap();
        let code = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
        let (token, _) = rt.sign_in_once("~zod", &code, "test").unwrap();
        let server = Server::start(rt.clone(), server).unwrap();
        Door { rt, server, token, _dir: dir }
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// A request as the signed-in device, with these headers too.
    fn ask(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let auth = self.auth();
        let mut all = vec![("Authorization", auth.as_str())];
        all.extend_from_slice(headers);
        http(self.server.addr(), method, &format!("/ships/zod{path}"), &all, body)
    }

    fn json(&self, path: &str, body: &str) -> (u16, serde_json::Value) {
        // JSON comes back as JSON; anything else (the server's own words) as a string.
        let (status, headers, body) = self.ask("POST", path, &[("Content-Type", "application/json")], body.as_bytes());
        if header(&headers, "content-type") == Some("application/json") {
            return (status, serde_json::from_slice(&body).unwrap());
        }
        assert_ne!(status, 200, "a reply that is not JSON");
        (status, serde_json::Value::String(String::from_utf8_lossy(&body).into_owned()))
    }

    fn proto(&self, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let (status, headers, body) = self.ask("POST", path, &[("Content-Type", "application/x-protobuf")], body);
        if status == 200 {
            assert_eq!(header(&headers, "content-type"), Some("application/x-protobuf"));
        }
        (status, body)
    }
}

#[test]
fn the_door_hands_out_the_description() {
    let door = Door::new("door-describe", ServerConfig::default());
    let (status, headers, body) = door.ask("GET", "/agents/book/api", &[], b"");
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "content-type"), Some("application/x-protobuf"));
    assert_eq!(body, sections(&wasm("guestbook"))[0]);
    // There is no JSON form: asking for one changes nothing.
    let (status, headers, again) = door.ask("GET", "/agents/book/api", &[("Accept", "application/json")], b"");
    assert_eq!((status, header(&headers, "content-type"), again), (200, Some("application/x-protobuf"), body));
    // An untyped agent has no description, and still takes raw bytes on /command.
    let counter = door.rt.add_module(&wasm("counter")).unwrap();
    door.rt.install("~zod", "counter", &counter, &counter_manifest()).unwrap();
    assert_eq!(door.ask("GET", "/agents/counter/api", &[], b"").0, 404);
    let (status, _, body) = door.ask("POST", "/agents/counter/command", &[], b"inc hits");
    assert_eq!((status, body), (200, b"1".to_vec()));
    assert_eq!(door.ask("GET", "/agents/nobody/api", &[], b"").0, 404);
}

/// The signature `awkward` gives, as JSON, every field spelled as it is written out.
const AWKWARD_JSON: &str = r#"{"signature": {"name": "by JSON", "stamp": "AAEC+v8=", "mood": "MOOD_GRUMPY", "from": {"town": "Lisbon", "ship": "~sampel-palnet"},
  "tags": ["first", "second"], "scores": {"chess": "9007199254740993", "go": -3}, "email": "guest@example.com", "age": 41, "signedAt": "18446744073709551615"}}"#;

#[test]
fn the_door_calls_a_method_with_json_and_with_protobuf_alike() {
    let door = Door::new("door-call", ServerConfig::default());
    let (status, signed) = door.json("/agents/book/api/guestbook/Sign", AWKWARD_JSON);
    assert_eq!(status, 200, "{signed}");
    // 64-bit integers as strings, and every field, those at their defaults included.
    assert_eq!(signed, serde_json::json!({"number": "1", "total": "1"}));
    // The same signature sent as protobuf.
    let (status, reply) = door.proto("/agents/book/api/guestbook/Sign", &gb::SignRequest { signature: Some(awkward("by JSON")) }.encode_to_vec());
    assert_eq!(status, 200);
    assert_eq!(gb::Signed::decode(&*reply).unwrap(), gb::Signed { number: 2, total: 2 });
    // Both read back the same, in both encodings.
    let expected = |number: u64| gb::Signature { number, ..awkward("by JSON") };
    for number in [1u64, 2] {
        let (status, reply) = door.proto("/agents/book/api/guestbook/Get", &gb::Number { number }.encode_to_vec());
        assert_eq!(status, 200);
        assert_eq!(gb::Signature::decode(&*reply).unwrap(), expected(number));
        let (status, json) = door.json("/agents/book/api/guestbook/Get", &format!(r#"{{"number": {number}}}"#));
        assert_eq!(status, 200);
        assert_eq!(
            json,
            serde_json::json!({
                "number": number.to_string(), "name": "by JSON", "stamp": "AAEC+v8=", "mood": "MOOD_GRUMPY",
                "from": {"town": "Lisbon", "ship": "~sampel-palnet"}, "tags": ["first", "second"],
                "scores": {"chess": "9007199254740993", "go": "-3"}, "email": "guest@example.com", "age": 41,
                "signedAt": "18446744073709551615"
            })
        );
    }
    // Fields at their defaults are written too; what a field with presence that is unset gives
    // is as the generated code writes it.
    let (_, plain) = door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": "plain"}}"#);
    let (_, json) = door.json("/agents/book/api/guestbook/Get", &format!(r#"{{"number": {}}}"#, plain["number"].as_str().unwrap()));
    assert_eq!(json, serde_json::json!({"number": "3", "name": "plain", "stamp": "", "mood": "MOOD_UNSPECIFIED", "tags": [], "scores": {}, "signedAt": "0"}));
    // The field's name as written in the file is taken as well as its lowerCamelCase one, and
    // a field the method does not know is ignored.
    let (status, json) = door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": "snake", "signed_at": "5", "ship": "~zod"}, "unheardOf": {"a": [1, 2]}}"#);
    assert_eq!(status, 200, "{json}");
    let (_, json) = door.json("/agents/book/api/guestbook/Get", &format!(r#"{{"number": {}}}"#, json["number"].as_str().unwrap()));
    assert_eq!((json["signedAt"].as_str(), json["ship"].as_str()), (Some("5"), Some("~zod")));
    // An enum given by its number is taken; on the way out a known value goes by its name.
    let (_, json) = door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": "by number", "mood": 1}}"#);
    let (_, json) = door.json("/agents/book/api/guestbook/Get", &format!(r#"{{"number": {}}}"#, json["number"].as_str().unwrap()));
    assert_eq!(json["mood"], "MOOD_HAPPY");
    // A second interface of the same agent.
    let (status, json) = door.json("/agents/book/api/visits/Visit", r#"{"who": "~nec"}"#);
    assert_eq!((status, json), (200, serde_json::json!({"visits": "1"})));
}

/// The kit's `Name` with only its name set, as JSON with every field written.
fn kit_name(name: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "alias": "", "counts": [], "level": "LEVEL_UNSPECIFIED", "::pbjson::alias": ""})
}

#[test]
fn the_door_calls_well_known_types_and_stubs_of_an_interface_only_called() {
    let door = Door::new("door-kit", ServerConfig::default());
    // A timestamp in, a message with a timestamp and a wrapper out, in JSON and in protobuf. The
    // timestamp comes back with its offset written `+00:00`, which is how pbjson-types writes it.
    let (status, json) = door.json("/agents/kit/api/kit/Clock", r#""2026-11-25T12:00:00.250Z""#);
    assert_eq!((status, json), (200, serde_json::json!({"at": "2026-11-25T12:00:00.250+00:00", "millis": "1795608000250"})));
    let (status, reply) = door.proto("/agents/kit/api/kit/Clock", &gb::Timestamp { seconds: 10, nanos: 5_000_000 }.encode_to_vec());
    assert_eq!(status, 200);
    assert_eq!(gb::Stamped::decode(&*reply).unwrap(), gb::Stamped { at: Some(gb::Timestamp { seconds: 10, nanos: 5_000_000 }), millis: Some(gb::Int64Value { value: 10_005 }) });
    // A wrapper in and out: JSON writes it as the bare value.
    assert_eq!(door.json("/agents/kit/api/kit/Flag", "true"), (200, serde_json::json!(false)));
    let (status, reply) = door.proto("/agents/kit/api/kit/Flag", &gb::BoolValue { value: false }.encode_to_vec());
    assert_eq!((status, gb::BoolValue::decode(&*reply).unwrap()), (200, gb::BoolValue { value: true }));
    // A method whose Rust name is a keyword.
    assert_eq!(door.json("/agents/kit/api/kit/Type", r#"{"name": "x"}"#), (200, kit_name("the type of x")));
    // A typed read of the guestbook through stubs generated for an interface the kit only calls.
    door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": "lent"}}"#);
    assert_eq!(door.json("/agents/kit/api/kit/Borrow", r#"{"agent": "book", "number": 1}"#), (200, serde_json::json!({"word": "lent"})));
    let (status, fault) = door.json("/agents/kit/api/kit/Borrow", r#"{"agent": "book", "number": 9}"#);
    assert_eq!((status, fault), (422, serde_json::json!({"code": "no-such-signature", "message": "this book has no signature 9"})));
}

#[test]
fn the_door_answers_each_failure_with_its_status() {
    let door = Door::new("door-failures", ServerConfig { max_body_bytes: 4096, ..ServerConfig::default() });
    let text = |reply: (u16, serde_json::Value)| (reply.0, reply.1.as_str().unwrap_or_default().to_string());
    // A question's fault: 422, in the request's encoding.
    let (status, json) = door.json("/agents/book/api/guestbook/Get", r#"{"number": 9}"#);
    assert_eq!((status, json), (422, serde_json::json!({"code": "no-such-signature", "message": "this book has no signature 9"})));
    let (status, headers, body) = door.ask("POST", "/agents/book/api/guestbook/Get", &[("Content-Type", "application/x-protobuf")], &gb::Number { number: 9 }.encode_to_vec());
    assert_eq!((status, header(&headers, "content-type")), (422, Some("application/x-protobuf")));
    assert_eq!(Fault::decode(&*body).unwrap(), Fault { code: "no-such-signature".into(), message: "this book has no signature 9".into() });
    // A body a question cannot read is the agent's ship.not-understood, 400, with the decoder's
    // words: a field of the wrong type, malformed JSON, JSON with something after it, protobuf
    // that does not decode.
    for body in [r#"{"number": {}}"#, r#"{"number": 1"#, r#"{"number": 1} trailing"#] {
        let (status, json) = door.json("/agents/book/api/guestbook/Get", body);
        assert_eq!((status, json["code"].as_str()), (400, Some("ship.not-understood")), "{body}: {json}");
        assert!(json["message"].as_str().unwrap().contains("line 1 column"), "{json}");
    }
    let (status, headers, body) = door.ask("POST", "/agents/book/api/guestbook/Get", &[("Content-Type", "application/x-protobuf")], &[0x08, 0xff]);
    assert_eq!((status, header(&headers, "content-type")), (400, Some("application/x-protobuf")));
    assert_eq!(Fault::decode(&*body).unwrap().code, "ship.not-understood");
    // A body a command cannot read is a failed command: the event traps, nothing is kept, and the
    // reason does not come back.
    let failed = |door: &Door| door.rt.audit("~zod", 10_000).unwrap().iter().filter(|entry| !entry.ok).count();
    let failed_before = failed(&door);
    let (status, words) = text(door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": 5}}"#));
    assert_eq!((status, words.as_str()), (422, "the command failed"));
    assert_eq!(text(door.json("/agents/book/api/guestbook/Sign", r#"{"signature": "#)), (422, "the command failed".to_string()));
    assert_eq!(door.proto("/agents/book/api/guestbook/Sign", &[0x0a, 0x05, 0xff]).0, 422);
    assert_eq!(failed(&door), failed_before + 3);
    assert_eq!(page_on(&door), 0);
    // A body over the server's limit.
    let big = format!(r#"{{"signature": {{"name": "{}"}}}}"#, "x".repeat(5000));
    assert_eq!(text(door.json("/agents/book/api/guestbook/Sign", &big)).0, 413);
    // A body of any other kind.
    for kind in [Some("text/plain"), Some("application/jsonx"), None] {
        let headers: Vec<(&str, &str)> = kind.map(|kind| vec![("Content-Type", kind)]).unwrap_or_default();
        assert_eq!(door.ask("POST", "/agents/book/api/guestbook/Sign", &headers, b"{}").0, 415, "{kind:?}");
    }
    assert_eq!(door.ask("POST", "/agents/book/api/visits/Count", &[("Content-Type", "Application/JSON; charset=utf-8")], b"{}").0, 200);
    // No such agent, interface or method; the log is not a method to call.
    for path in ["/agents/nobody/api/guestbook/Get", "/agents/book/api/nothing/Get", "/agents/book/api/guestbook/Nope", "/agents/book/api/guestbook/Signatures"] {
        assert_eq!(text(door.json(path, "{}")).0, 404, "{path}");
    }
    // A name that is not one.
    assert_eq!(text(door.json("/agents/Book/api/guestbook/Get", "{}")).0, 400);
    // What deliver can return, as the command route gives it: the handler's own fault, a trap.
    let (status, words) = text(door.json("/agents/book/api/guestbook/Erase", r#"{"number": 3}"#));
    assert_eq!((status, words.as_str()), (422, "the command failed"));
}

/// How many signatures the door's book holds.
fn page_on(door: &Door) -> u64 {
    page(&door.rt, "book").total
}

/// A hand-written agent, in WebAssembly text, whose command writes a key and answers with a
/// fault, and whose question answers with a body that is not JSON (invalid UTF-8) when the call
/// asks for JSON and with one that is not JSON text otherwise.
const ROGUE: &str = r#"(module
  (import "host" "kv_put" (func $kv_put (param i32 i32 i32 i32)))
  (import "host" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\12\06\0a\01\78\12\01\79")
  (data (i32.const 16) "\0a\01\7b")
  (data (i32.const 24) "\0a\03\22\ff\22")
  (data (i32.const 40) "\0a\02\7b\7d")
  (data (i32.const 48) "key")
  (data (i32.const 56) "committed")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  ;; Do: write "committed" under "key", then answer with a fault.
  (func (export "handle") (param i32 i32) (result i64)
    (call $kv_put (i32.const 48) (i32.const 3) (i32.const 56) (i32.const 9))
    (i64.const 8))
  ;; By the first letter of the method's name, just after the Call's tag and length.
  (func (export "read") (param $p i32) (param $l i32) (result i64)
    (local $c i32) (local $n i64)
    (local.set $c (i32.load8_u (i32.add (local.get $p) (i32.const 2))))
    ;; Broken: "{", text that is not JSON.
    (if (i32.eq (local.get $c) (i32.const 66)) (then (return (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 3)))))
    ;; Quoted: a JSON string holding a byte that is not UTF-8.
    (if (i32.eq (local.get $c) (i32.const 81)) (then (return (i64.or (i64.shl (i64.const 24) (i64.const 32)) (i64.const 5)))))
    ;; Valid: {}.
    (if (i32.eq (local.get $c) (i32.const 86)) (then (return (i64.or (i64.shl (i64.const 40) (i64.const 32)) (i64.const 4)))))
    ;; Dump: what is kept under "key", as the reply's body.
    (local.set $n (call $kv_get (i32.const 48) (i32.const 3) (i32.const 2002) (i32.const 64)))
    (i32.store8 (i32.const 2000) (i32.const 10))
    (i32.store8 (i32.const 2001) (i32.wrap_i64 (local.get $n)))
    (i64.or (i64.shl (i64.const 2000) (i64.const 32)) (i64.add (local.get $n) (i64.const 2)))))"#;

#[test]
fn the_door_refuses_replies_that_are_not_what_a_typed_call_answers() {
    let door = Door::new("door-replies", ServerConfig::default());
    // A command that answers with a fault: 502, though it has committed (what it wrote is kept).
    let questions = [("Broken", false, false), ("Quoted", false, false), ("Valid", false, false), ("Dump", false, false)];
    let mut set = FileDescriptorSet::decode(&*made_description("demo", &[("Rogue", &[[("Do", false, false)].as_slice(), &questions].concat())])).unwrap();
    for method in set.file[0].service[0].method.iter_mut().skip(1) {
        method.options = Some(prost_types::MethodOptions { idempotency_level: Some(prost_types::method_options::IdempotencyLevel::NoSideEffects as i32), ..Default::default() });
    }
    let rogue = with_section(&wat::parse_str(ROGUE).unwrap(), "ship.api.v1", &set.encode_to_vec());
    let hash = door.rt.add_module(&rogue).unwrap();
    door.rt.install("~zod", "rogue", &hash, &providing(&["rogue"])).unwrap();
    let (status, headers, words) = door.ask("POST", "/agents/rogue/api/rogue/Do", &[("Content-Type", "application/json")], b"{}");
    assert_eq!((status, String::from_utf8_lossy(&words).as_ref()), (502, "the agent's reply is not what a typed call answers"), "{headers:?}");
    assert_eq!(door.proto("/agents/rogue/api/rogue/Dump", b""), (200, b"committed".to_vec()));
    // A question's body asked for as JSON: text that is not JSON, and a JSON string holding a
    // byte that is not UTF-8, are 502; JSON is passed on. As protobuf each is passed on.
    for (method, status) in [("Broken", 502), ("Quoted", 502), ("Valid", 200)] {
        let (got, headers, _) = door.ask("POST", &format!("/agents/rogue/api/rogue/{method}"), &[("Content-Type", "application/json")], b"{}");
        assert_eq!(got, status, "{method}: {headers:?}");
    }
    assert_eq!(door.proto("/agents/rogue/api/rogue/Quoted", b""), (200, vec![0x22, 0xff, 0x22]));
    // An agent whose replies are not CallReplies at all: the counter, untyped, carrying the
    // guestbook's description.
    let module = with_section(&wasm("counter"), "ship.api.v1", &sections(&wasm("guestbook"))[0]);
    let hash = door.rt.add_module(&module).unwrap();
    door.rt.install("~zod", "fake", &hash, &book_manifest(&[], None)).unwrap();
    assert_eq!(door.json("/agents/fake/api/guestbook/Get", r#"{"number": 1}"#).0, 502);
    assert_eq!(door.proto("/agents/fake/api/visits/Count", b"").0, 502);
}

#[test]
fn a_description_that_disagrees_with_its_code_is_refused_by_the_code() {
    // The guestbook's code, carrying a description that says Sign is a question and Get a
    // command: the door runs each as the description says, and the generated dispatch refuses
    // the wrong kind, a question with ship.wrong-kind (409) and a command by trapping.
    let door = Door::new("door-disagree", ServerConfig::default());
    let mut set = FileDescriptorSet::decode(&*sections(&wasm("guestbook"))[0]).unwrap();
    for method in set.file[1].service[0].method.iter_mut() {
        match method.name() {
            "Sign" => method.options = Some(prost_types::MethodOptions { idempotency_level: Some(prost_types::method_options::IdempotencyLevel::NoSideEffects as i32), ..Default::default() }),
            "Get" => method.options = None,
            _ => {}
        }
    }
    let liar = with_section(&without_sections(&wasm("guestbook")), "ship.api.v1", &set.encode_to_vec());
    let hash = door.rt.add_module(&liar).unwrap();
    door.rt.install("~zod", "liar", &hash, &book_manifest(&[], None)).unwrap();
    let (status, json) = door.json("/agents/liar/api/guestbook/Sign", r#"{"signature": {"name": "x"}}"#);
    assert_eq!((status, json["code"].as_str()), (409, Some("ship.wrong-kind")), "{json}");
    let (status, words) = door.json("/agents/liar/api/guestbook/Get", r#"{"number": 1}"#);
    assert_eq!((status, words.as_str().unwrap()), (422, "the command failed"));
}

#[test]
fn the_door_cannot_be_confused_with_the_other_routes() {
    let door = Door::new("door-paths", ServerConfig::default());
    let kit = door.rt.add_module(&wasm("kit")).unwrap();
    // Interfaces really named api, command and files, each answering with its own name.
    for interface in ["api", "command", "files"] {
        assert_eq!(door.json(&format!("/agents/kit/api/{interface}/Which"), "{}"), (200, kit_name(interface)), "{interface}");
    }
    // Agents literally named api, command and files, running the kit.
    for name in ["api", "command", "files"] {
        door.rt.install("~zod", name, &kit, &kit_manifest()).unwrap();
        let (status, _, body) = door.ask("GET", &format!("/agents/{name}/api"), &[], b"");
        assert_eq!((status, body), (200, sections(&wasm("kit"))[0].clone()), "{name}");
        for interface in ["api", "command", "files"] {
            assert_eq!(door.json(&format!("/agents/{name}/api/{interface}/Which"), "{}"), (200, kit_name(interface)), "{name} {interface}");
        }
        // /command on a typed agent runs with no interface, and its dispatch refuses it.
        let (status, _, body) = door.ask("POST", &format!("/agents/{name}/command"), &[], b"anything");
        assert_eq!((status, String::from_utf8_lossy(&body).as_ref()), (422, "the command failed"), "{name}");
    }
    // The files route is still the files route.
    let (status, _, _) = door.ask("GET", "/agents/book/files", &[], b"");
    assert_eq!(status, 200);
    // Percent-encoding: a segment is decoded after the path is split, so an encoded slash stays
    // in its segment, and an encoded letter is that letter.
    assert_eq!(door.json("/agents/book/api/guestbook%2FGet", "{}").0, 404);
    assert_eq!(door.json("/agents/book/api%2Fguestbook/Get", "{}").0, 404);
    assert_eq!(door.json("/agents/bo%6Fk/api/visits/C%6Funt", "{}").0, 200);
    assert_eq!(door.json("/agents/kit/api/c%6Fmmand/Which", "{}"), (200, kit_name("command")));
    assert_eq!(door.ask("GET", "/agents/bo%6Fk/ap%69", &[], b"").0, 200);
    // A method the address does not take.
    let (status, headers, _) = door.ask("GET", "/agents/book/api/visits/Count", &[], b"");
    assert_eq!((status, header(&headers, "allow")), (405, Some("POST")));
    let (status, headers, _) = door.ask("POST", "/agents/book/api", &[], b"");
    assert_eq!((status, header(&headers, "allow")), (405, Some("GET")));
    assert_eq!(door.ask("GET", "/agents/book/api/visits", &[], b"").0, 404);
}

#[test]
fn the_door_signs_in_and_guards_against_other_sites_as_the_other_routes_do() {
    let door = Door::new("door-auth", ServerConfig::default());
    let addr = door.server.addr();
    let json = [("Content-Type", "application/json")];
    let auth = door.auth();
    // A ship that exists, unsigned or with a wrong token, and a ship that does not exist, signed
    // or not: the same answer, status, body and headers, on both routes.
    for (method, route) in [("POST", "/agents/book/api/visits/Count"), ("GET", "/agents/book/api")] {
        let answers: Vec<(u16, Vec<(String, String)>, Vec<u8>)> = [
            ("zod", vec![json[0]]),
            ("zod", vec![("Authorization", "Bearer nope"), json[0]]),
            ("nec", vec![json[0]]),
            ("nec", vec![("Authorization", auth.as_str()), json[0]]),
        ]
        .into_iter()
        .map(|(ship, headers)| http(addr, method, &format!("/ships/{ship}{route}"), &headers, b"{}"))
        .collect();
        assert_eq!(answers[0].0, 401, "{method} {route}");
        for other in &answers[1..] {
            assert_eq!(other, &answers[0], "{method} {route}");
        }
    }
    // With the browser's cookie: a POST must show it came from the ship's own page, as on the
    // command route; a GET need not.
    let cookie = format!("ship_token={}", door.token);
    let with_cookie = |extra: &[(&str, &str)]| {
        let mut headers = vec![("Cookie", cookie.as_str()), json[0]];
        headers.extend_from_slice(extra);
        http(addr, "POST", "/ships/zod/agents/book/api/visits/Count", &headers, b"{}").0
    };
    assert_eq!(with_cookie(&[]), 403);
    assert_eq!(with_cookie(&[("Sec-Fetch-Site", "cross-site")]), 403);
    assert_eq!(with_cookie(&[("Origin", "http://elsewhere.example")]), 403);
    assert_eq!(with_cookie(&[("Sec-Fetch-Site", "same-origin")]), 200);
    let command = |extra: &[(&str, &str)]| {
        let mut headers = vec![("Cookie", cookie.as_str())];
        headers.extend_from_slice(extra);
        http(addr, "POST", "/ships/zod/agents/book/command", &headers, b"x").0
    };
    assert_eq!(command(&[]), 403);
    assert_eq!(http(addr, "GET", "/ships/zod/agents/book/api", &[("Cookie", &cookie)], b"").0, 200);
}

#[test]
fn the_json_the_generated_code_reads_and_writes_at_its_edges() {
    // What pbjson's generated code does where the proto3 JSON mapping leaves room or the tool
    // differs, as the README states it. Questions answer a body they cannot read with
    // ship.not-understood (400), and the decoder's words.
    let door = Door::new("door-edges", ServerConfig::default());
    let read = |path: &str, body: &str| door.json(path, body);
    let refused = |path: &str, body: &str, words: &str| {
        let (status, json) = read(path, body);
        assert_eq!((status, json["code"].as_str()), (400, Some("ship.not-understood")), "{body}: {json}");
        assert!(json["message"].as_str().unwrap().contains(words), "{body}: {json}");
    };
    let kit = "/agents/kit/api/kit/Type";
    // A declared json_name is what is written, and both it and the name as written are read.
    let named = serde_json::json!({"name": "the type of x", "alias": "y", "counts": ["1", "2"], "level": "LEVEL_HIGH", "::pbjson::alias": ""});
    assert_eq!(read(kit, r#"{"name": "x", "alias": "y", "counts": ["1", 2], "level": "LEVEL_HIGH"}"#), (200, named.clone()));
    assert_eq!(read(kit, r#"{"name": "x", "nickname": "y", "counts": [1, "2"], "level": 1}"#), (200, named));
    // Enums: a known name or number is read; an unknown name or number is refused.
    refused(kit, r#"{"level": 77}"#, "invalid value: integer `77`");
    refused(kit, r#"{"level": "LEVEL_NONE"}"#, "unknown variant `LEVEL_NONE`");
    // An enum number with aliases: the first declared name is written (LEVEL_HIGH, above, for
    // both the name and the number 1), and the later alias is refused as unknown. That it is a
    // declared alias, and not an unknown name, is read from the description the kit hands out.
    let (status, _, section) = door.ask("GET", "/agents/kit/api", &[], b"");
    assert_eq!(status, 200);
    let section = <FileDescriptorSet as ship_proto::prost::Message>::decode(&*section).unwrap();
    let level = section.file.iter().find(|file| file.name() == "kit.proto").unwrap().enum_type.iter().find(|e| e.name() == "Level").unwrap();
    assert_eq!(level.options.as_ref().and_then(|options| options.allow_alias), Some(true));
    let ones: Vec<&str> = level.value.iter().filter(|value| value.number() == 1).map(|value| value.name()).collect();
    assert_eq!(ones, ["LEVEL_HIGH", "LEVEL_TOP"]);
    refused(kit, r#"{"level": "LEVEL_TOP"}"#, "unknown variant `LEVEL_TOP`");
    // null: refused for a scalar, a list and an enum; taken as unset for a field with presence.
    refused(kit, r#"{"name": null}"#, "invalid type: null");
    refused(kit, r#"{"counts": null}"#, "invalid type: null");
    refused(kit, r#"{"level": null}"#, "invalid type: null");
    // With one signature that matches: leaving `limit` out and giving it as null both find it,
    // and an explicit 0 finds none.
    assert_eq!(door.json("/agents/book/api/guestbook/Sign", r#"{"signature": {"name": "a match"}}"#).0, 200);
    let found = |body: &str| read("/agents/book/api/guestbook/Lookup", body).1["signatures"].as_array().map(Vec::len);
    assert_eq!(found(r#"{"prefix": "a"}"#), Some(1));
    assert_eq!(found(r#"{"prefix": "a", "limit": null}"#), Some(1));
    assert_eq!(found(r#"{"prefix": "a", "limit": 0}"#), Some(0));
    // A repeated known field is refused once its first value has set it; an initial null on a
    // field with presence leaves it unset, so a second value is taken (0 here, which finds none,
    // where an unset limit would find the one); unknown keys can repeat.
    refused(kit, r#"{"name": "a", "name": "b"}"#, "duplicate field `name`");
    assert_eq!(found(r#"{"prefix": "a", "limit": null, "limit": 0}"#), Some(0));
    assert_eq!(found(r#"{"prefix": "a", "x": 1, "x": 2}"#), Some(1));
    // A declared JSON name that looks like a Rust path is read and written as it is declared.
    let (status, json) = read(kit, r#"{"::pbjson::alias": "kept"}"#);
    assert_eq!((status, json["::pbjson::alias"].as_str()), (200, Some("kept")), "{json}");
    // Invalid UTF-8 inside the string of a field the message does not know is skipped with the
    // field, and the command runs.
    let mut body = br#"{"signature": {"name": "raw bytes"}, "unknown": ""#.to_vec();
    body.extend_from_slice(&[0xff, 0xfe]);
    body.extend_from_slice(br#""}"#);
    let (status, _, reply) = door.ask("POST", "/agents/book/api/guestbook/Sign", &[("Content-Type", "application/json")], &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&reply));
    assert_eq!(found(r#"{"prefix": "raw bytes"}"#), Some(1));
    // 64-bit integers: decimal digits, as a string or a number, are read; an exponent, a
    // fraction, a negative number for an unsigned field, and one past 64 bits are refused.
    for body in [r#"{"counts": ["1e2"]}"#, r#"{"counts": [1e2]}"#, r#"{"counts": [1.5]}"#, r#"{"counts": [-1]}"#, r#"{"counts": [18446744073709551616]}"#] {
        let (status, json) = read(kit, body);
        assert_eq!((status, json["code"].as_str()), (400, Some("ship.not-understood")), "{body}: {json}");
    }
    refused("/agents/book/api/guestbook/Get", r#"{"number": "18446744073709551616"}"#, "number too large");
    // google.protobuf.Empty takes only {}: a field in it is refused, unknown or not.
    refused("/agents/book/api/visits/Count", r#"{"x": 1}"#, "unknown field `x`");
    // A wrapper is its bare value, and null is refused.
    refused("/agents/kit/api/kit/Flag", "null", "invalid type: null");
    // A timestamp with an offset is read, and written back in UTC with its offset as +00:00.
    assert_eq!(read("/agents/kit/api/kit/Clock", r#""2026-11-25T12:00:00+01:00""#), (200, serde_json::json!({"at": "2026-11-25T11:00:00+00:00", "millis": "1795604400000"})));
    // Inside a field the message does not know, nesting is skipped however deep.
    let deep = format!(r#"{{"unknown": {}{}}}"#, "[".repeat(1000), "]".repeat(1000));
    assert_eq!(read(kit, &deep).0, 200);
    // An enum value the code does not know, stored through protobuf, cannot be written as JSON:
    // the question traps, and is answered as a failed call.
    let mut signature = awkward("odd mood");
    signature.mood = 77;
    let (status, signed) = door.proto("/agents/book/api/guestbook/Sign", &gb::SignRequest { signature: Some(signature) }.encode_to_vec());
    assert_eq!(status, 200);
    let number = gb::Signed::decode(&*signed).unwrap().number;
    assert_eq!(read("/agents/book/api/guestbook/Get", &format!(r#"{{"number": {number}}}"#)), (422, serde_json::Value::String("the command failed".into())));
    let (status, reply) = door.proto("/agents/book/api/guestbook/Get", &gb::Number { number }.encode_to_vec());
    assert_eq!((status, gb::Signature::decode(&*reply).unwrap().mood), (200, 77));
}
