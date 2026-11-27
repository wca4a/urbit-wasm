//! The parts of reading descriptions and of the JSON door that are not reached from outside the
//! crate: the cache's order and what it keeps, an agent whose description was never checked, a
//! module replaced between a typed call's lookup and its run, and the door's statuses for faults.

use std::sync::Arc;

use ship_proto::admin_request::Op;
use ship_proto::{AdminRequest, Install, Manifest, Provide, Use};

use super::*;
use crate::{Config, Durability};

fn wasm(name: &str) -> Vec<u8> {
    crate::net::router_tests::wasm(name)
}

fn manifest(interfaces: &[&str], uses: Vec<Use>) -> Manifest {
    Manifest { provides: interfaces.iter().map(|interface| Provide { interface: interface.to_string(), public: false, remote: false, asked: false }).collect(), uses }
}

/// A runtime in a directory of its own (removed when this goes) with `~zod` and its kernel.
struct Scratch(std::path::PathBuf, Option<Arc<Runtime>>);

impl Scratch {
    fn new(label: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("urbit-wasm-{}-api-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = Arc::new(Runtime::open(&dir, Config { durability: Durability::Normal, ..Config::default() }).unwrap());
        let kernel = rt.add_module(&wasm("kernel")).unwrap();
        rt.create_ship("~zod", &kernel).unwrap();
        Scratch(dir, Some(rt))
    }

    fn rt(&self) -> &Arc<Runtime> {
        self.1.as_ref().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(self.1.take());
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_cache_lets_the_least_recently_used_go() {
    let mut cache = Cache::default();
    for n in 0..CACHE_ENTRIES {
        cache.put(&format!("{n}"), None);
    }
    // The first is used again, so the second is the oldest when one more comes.
    assert!(cache.get("0").is_some());
    cache.put("new", None);
    assert_eq!(cache.len(), CACHE_ENTRIES);
    assert!(cache.get("1").is_none(), "the least recently used was kept");
    assert!(cache.get("0").is_some() && cache.get("new").is_some());
}

#[test]
fn a_section_is_found_once_and_held_to_its_limit() {
    let module = wat::parse_str("(module)").unwrap();
    assert_eq!(section(&module, 10).unwrap(), None);
    let custom = |module: &[u8], name: &str, data: &[u8]| {
        let mut body = vec![name.len() as u8];
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(data);
        let mut out = module.to_vec();
        out.push(0);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out
    };
    let one = custom(&module, SECTION, b"abc");
    assert_eq!(section(&one, 3).unwrap(), Some(&b"abc"[..]));
    assert!(section(&one, 2).unwrap_err().contains("this runtime takes at most 2 (max_api_bytes)"));
    let other = custom(&module, "ship.api.v2", b"abc");
    assert_eq!(section(&other, 10).unwrap(), None);
    assert!(section(&custom(&one, SECTION, b"d"), 10).unwrap_err().contains("more than one"));
    assert!(section(b"not a module", 10).is_err());
}

#[test]
fn an_agent_whose_description_was_never_checked_is_answered_as_having_none_and_read_once() {
    let scratch = Scratch::new("unchecked");
    let rt = scratch.rt();
    let mut module = wasm("counter");
    // A section that is not a description at all, put in through the kernel as an import
    // would leave it, without the check `install` makes.
    let garbage = [0xff_u8; 64];
    module.push(0);
    module.push((1 + SECTION.len() + garbage.len()) as u8);
    module.push(SECTION.len() as u8);
    module.extend_from_slice(SECTION.as_bytes());
    module.extend_from_slice(&garbage);
    let hash = rt.add_module(&module).unwrap();
    let counter = manifest(&["counter"], vec![]);
    assert!(matches!(rt.install("~zod", "checked", &hash, &counter), Err(Error::BadModule(_))));
    let install = Install { agent: "unchecked".into(), module: hash.clone(), manifest: Some(counter) };
    let reply = rt.inner.with_ship("~zod", |ship| ship.admin(&rt.inner, &AdminRequest { op: Some(Op::Install(install)) }, true)).unwrap();
    assert!(reply.ok, "{}", reply.error);
    // Asked for, it has none; called, it is refused as having none; nothing panics, and the
    // agent still runs as it always did.
    assert!(rt.description("~zod", "unchecked").unwrap().is_none());
    assert!(matches!(rt.call_method("~zod", "unchecked", "counter", "Get", b"", Encoding::Json), Err(CallError::NoDescription)));
    assert_eq!(rt.deliver("~zod", "unchecked", b"inc hits").unwrap().reply, b"1");
    // Two description lookups reused one negative cache entry. An ordinary delivery still ran.
    assert_eq!(rt.described_modules(), 1);
    assert_eq!(lock(&rt.inner.described).builds, 1);
}

#[test]
fn a_module_replaced_between_a_calls_lookup_and_its_run_decides_the_call() {
    // A question is looked up on the kit, whose interface `kit` has `Type`; before it runs, the
    // agent is given the guestbook's module, which has no interface `kit`. The guestbook's own
    // dispatch refuses it: the replacement is never run with a call meant for the kit.
    let scratch = Scratch::new("replaced");
    let rt = scratch.rt().clone();
    let (kit, book) = (rt.add_module(&wasm("kit")).unwrap(), rt.add_module(&wasm("guestbook")).unwrap());
    let reads = vec![
        Use { agent: "book".into(), interface: "guestbook".into(), read: true, send: false, ship: String::new(), ask: false },
        Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false, ship: String::new(), ask: false },
    ];
    rt.install("~zod", "agent", &kit, &manifest(&["api", "command", "files", "kit"], reads)).unwrap();
    let (entered, release) = rt.inner.gates.arm("typed call looked up");
    let calling = rt.clone();
    let body = br#"{"name": "x"}"#.to_vec();
    let call = std::thread::spawn(move || calling.call_method("~zod", "agent", "kit", "Type", &body, Encoding::Json));
    entered.recv().unwrap();
    rt.install("~zod", "agent", &book, &manifest(&["guestbook", "visits", "api", "command", "files", "kit"], vec![])).unwrap();
    release.send(()).unwrap();
    match call.join().unwrap() {
        Ok(Called::Fault(fault)) => assert_eq!(fault.code, "ship.no-such-interface"),
        other => panic!("expected the replacement to refuse the call, got {other:?}"),
    }
}

#[test]
fn a_question_fault_is_answered_with_the_status_its_code_means() {
    assert_eq!(fault_status("ship.not-understood"), 400);
    assert_eq!(fault_status("ship.no-such-interface"), 404);
    assert_eq!(fault_status("ship.no-such-method"), 404);
    assert_eq!(fault_status("ship.wrong-kind"), 409);
    assert_eq!(fault_status("app.ship.wrong-kind"), 422);
    assert_eq!(fault_status("no-such-signature"), 422);
}
