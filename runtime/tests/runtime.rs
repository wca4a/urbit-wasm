use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use runtime::{
    verify_checkpoint, verify_log, Config, Durability, Error, Limits, Manifest, Provide, Rejection, Runtime,
    SignedCheckpoint, Use,
};

const NO_LIMIT: usize = usize::MAX;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Build the kernel and test agents once per test run, and return one of them by name. A
/// separate target dir avoids the outer cargo's lock.
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

fn counter_wasm() -> Vec<u8> {
    wasm("counter")
}

fn kernel(rt: &Runtime) -> String {
    rt.add_module(&wasm("kernel")).unwrap()
}

fn nothing() -> Manifest {
    Manifest::default()
}

/// The counter agent offers one interface, `counter`.
fn counter_manifest(public: bool) -> Manifest {
    Manifest { provides: vec![Provide { interface: "counter".into(), public, remote: false }], uses: vec![] }
}

/// The tally agent offers `tally` and, when `uses_counter` is set, declares that it reads from
/// and sends to the counter.
fn tally_manifest(uses_counter: bool) -> Manifest {
    let uses = Use { agent: "counter".into(), interface: "counter".into(), read: true, send: true, ship: String::new() };
    Manifest {
        provides: vec![Provide { interface: "tally".into(), public: false, remote: false }],
        uses: if uses_counter { vec![uses] } else { vec![] },
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!("urbit-wasm-{}-{label}", std::process::id()));
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

/// Tests that are not about power loss skip the per-commit disk sync to stay fast.
fn fast() -> Config {
    Config { durability: Durability::Normal, ..Config::default() }
}

fn small_fuel() -> Config {
    Config { fuel_per_event: 2_000_000, ..fast() }
}

/// A runtime with one ship, `~zod`, running the counter agent as `counter`.
fn boot(dir: &TempDir, cfg: Config) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let hash = rt.add_module(&counter_wasm()).unwrap();
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "counter", &hash, &counter_manifest(false)).unwrap();
    rt
}

/// A runtime with one ship, `~zod`, running both the counter and the tally agent.
fn boot_pair(dir: &TempDir, cfg: Config, counter: Manifest, tally: Manifest) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let (counter_hash, tally_hash) = (rt.add_module(&counter_wasm()).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "counter", &counter_hash, &counter).unwrap();
    rt.install("~zod", "tally", &tally_hash, &tally).unwrap();
    rt
}

fn read(rt: &Runtime, agent: &str, interface: &str, request: &str) -> String {
    String::from_utf8(rt.read("~zod", agent, interface, request.as_bytes()).unwrap()).unwrap()
}

/// A runtime with one ship, `~zod`, running a hand-written module as `evil`.
fn boot_wat(dir: &TempDir, cfg: Config, source: &str) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let hash = rt.add_module(&wat::parse_str(source).unwrap()).unwrap();
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "evil", &hash, &nothing()).unwrap();
    rt
}

fn send(rt: &Runtime, ship: &str, agent: &str, event: &str) -> String {
    String::from_utf8(rt.deliver(ship, agent, event.as_bytes()).unwrap().reply).unwrap()
}

fn rejection(rt: &Runtime, agent: &str, event: &str) -> Rejection {
    match rt.deliver("~zod", agent, event.as_bytes()) {
        Err(Error::Rejected(rejection)) => rejection,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn state_survives_restart() {
    let dir = TempDir::new("restart");
    let rt = boot(&dir, Config::default());
    assert_eq!(send(&rt, "~zod", "counter", "inc hits"), "1");
    assert_eq!(send(&rt, "~zod", "counter", "inc hits 41"), "42");
    drop(rt);

    let rt = Runtime::open(&dir.0, Config::default()).unwrap();
    assert_eq!(send(&rt, "zod", "counter", "get hits"), "42");
}

#[test]
fn crash_rolls_back_state_and_outbox() {
    let dir = TempDir::new("crash");
    let rt = boot(&dir, fast());
    send(&rt, "~zod", "counter", "inc hits 5");

    assert!(matches!(rejection(&rt, "counter", "crash hits"), Rejection::Trap(_)));
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "5");
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());
}

#[test]
fn runaway_event_is_stopped_and_rolled_back() {
    let dir = TempDir::new("fuel");
    let rt = boot(&dir, small_fuel());
    send(&rt, "~zod", "counter", "inc hits 5");

    assert_eq!(rejection(&rt, "counter", "spin hits"), Rejection::OutOfFuel);
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "5");
}

#[test]
fn memory_and_value_limits_are_enforced() {
    let dir = TempDir::new("limits");
    let rt = boot(&dir, Config { max_memory_bytes: 8 << 20, ..fast() });

    assert!(matches!(rejection(&rt, "counter", "hog"), Rejection::Trap(_)));
    assert!(matches!(rejection(&rt, "counter", "big 2000000"), Rejection::Limit(_)));
    assert_eq!(send(&rt, "~zod", "counter", "big 1000"), "ok");

    let huge = vec![b'x'; (1 << 20) + 1];
    assert!(matches!(rt.deliver("~zod", "counter", &huge), Err(Error::Rejected(Rejection::Limit(_)))));
    // The oversized event never ran, but it is on record, cut down to its first bytes.
    let newest = rt.audit("~zod", 1).unwrap().remove(0);
    assert_eq!((newest.event.as_slice(), newest.ok), (&huge[..256], false));
}

#[test]
fn table_growth_cannot_bypass_the_memory_limit() {
    // Tables live outside linear memory. Growth within the limit must work, and growth just past
    // it must be refused by the limiter rather than by the host running out of memory.
    let grow = r#"(module
        (memory (export "memory") 1)
        (table $t 1 funcref)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64)
            (if (i32.eq (table.grow $t (ref.null func) (i32.const 10)) (i32.const -1))
                (then unreachable))
            (if (i32.ne (table.grow $t (ref.null func) (i32.const 2000)) (i32.const -1))
                (then unreachable))
            (i64.const 0)))"#;
    let dir = TempDir::new("table-grow");
    let rt = boot_wat(&dir, Config { max_table_elements: 1000, ..fast() }, grow);
    assert_eq!(rt.deliver("~zod", "evil", b"x").unwrap().reply, b"");

    let huge_initial = r#"(module
        (memory (export "memory") 1)
        (table 50000000 funcref)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))"#;
    let dir = TempDir::new("table-initial");
    let rt = boot_wat(&dir, fast(), huge_initial);
    assert!(matches!(rejection(&rt, "evil", "x"), Rejection::Trap(_)));
}

#[test]
fn host_calls_are_paid_for_with_fuel() {
    // A short loop of host calls. The guest instructions alone cost a few thousand units of fuel,
    // so the loop only runs out if the host calls themselves are charged.
    let looping = |calls: u32| {
        format!(
            r#"(module
                (import "host" "kv_get" (func $get (param i32 i32 i32 i32) (result i64)))
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "handle") (param i32 i32) (result i64)
                    (local $i i32)
                    (loop $again
                        (drop (call $get (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $again (i32.lt_u (local.get $i) (i32.const {calls}))))
                    (i64.const 0)))"#
        )
    };
    let dir = TempDir::new("host-fuel-ok");
    let rt = boot_wat(&dir, small_fuel(), &looping(100));
    assert_eq!(rt.deliver("~zod", "evil", b"x").unwrap().reply, b"");

    let dir = TempDir::new("host-fuel-out");
    let rt = boot_wat(&dir, small_fuel(), &looping(1000));
    assert_eq!(rejection(&rt, "evil", "x"), Rejection::OutOfFuel);
}

#[test]
fn bulk_memory_work_is_stopped_by_the_time_limit() {
    // memory.fill costs one unit of fuel however much it writes, so fuel alone would let this
    // loop write petabytes.
    let source = r#"(module
        (memory (export "memory") 1024)
        (func (export "alloc") (param i32) (result i32) (i32.const 0))
        (func (export "handle") (param i32 i32) (result i64)
            (loop $again
                (memory.fill (i32.const 0) (i32.const 1) (i32.const 67108864))
                (br $again))
            (i64.const 0)))"#;
    let dir = TempDir::new("timeout");
    let rt = boot_wat(&dir, Config { max_event_millis: 200, ..fast() }, source);

    let started = Instant::now();
    assert_eq!(rejection(&rt, "evil", "x"), Rejection::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5), "the time limit did not stop the event");
}

#[test]
fn straight_line_code_cannot_overrun_fuel_and_commit() {
    // Fuel is checked at loops and calls. This handler has neither after its emit, so it can
    // overrun the budget and return normally; the result must still be thrown away.
    let source = format!(
        r#"(module
            (import "host" "emit" (func $emit (param i32 i32)))
            (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) (i32.const 1024))
            (func (export "handle") (param i32 i32) (result i64)
                (call $emit (i32.const 0) (i32.const 1))
                {}
                (i64.const 0)))"#,
        "(drop (i32.const 0))".repeat(10_000)
    );
    let dir = TempDir::new("overrun");
    let rt = boot_wat(&dir, Config { fuel_per_event: 6_000, ..fast() }, &source);
    assert_eq!(rejection(&rt, "evil", "x"), Rejection::OutOfFuel);
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());
}

#[test]
fn start_function_shares_the_event_budget() {
    // The start function emits once and the handler emits once: two effects in one event.
    let source = r#"(module
        (import "host" "emit" (func $emit (param i32 i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "x")
        (func $start (call $emit (i32.const 0) (i32.const 1)))
        (start $start)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64)
            (call $emit (i32.const 0) (i32.const 1))
            (i64.const 0)))"#;
    let limits = |max_effects_per_event| Limits { max_effects_per_event, ..Config::default().limits };

    let dir = TempDir::new("start-one");
    let rt = boot_wat(&dir, Config { limits: limits(1), ..fast() }, source);
    assert!(matches!(rejection(&rt, "evil", "x"), Rejection::Limit(_)));
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());

    let dir = TempDir::new("start-two");
    let rt = boot_wat(&dir, Config { limits: limits(2), ..fast() }, source);
    assert_eq!(rt.deliver("~zod", "evil", b"x").unwrap().effects, 2);
    assert_eq!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().len(), 2);
}

#[test]
fn agent_memory_does_not_outlive_an_event() {
    // The handler bumps a global and replies with it. If memory survived, the second reply would be 2.
    let source = r#"(module
        (memory (export "memory") 1)
        (global $count (mut i32) (i32.const 0))
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64)
            (global.set $count (i32.add (global.get $count) (i32.const 1)))
            (i32.store8 (i32.const 0) (global.get $count))
            (i64.const 1)))"#;
    let dir = TempDir::new("no-memory");
    let rt = boot_wat(&dir, fast(), source);
    for _ in 0..3 {
        assert_eq!(rt.deliver("~zod", "evil", b"x").unwrap().reply, [1]);
    }
}

#[test]
fn effects_are_released_only_on_commit() {
    let dir = TempDir::new("effects");
    let rt = boot(&dir, fast());

    let outcome = rt.deliver("~zod", "counter", b"say hello there").unwrap();
    assert_eq!((outcome.reply.as_slice(), outcome.effects), (&b"sent"[..], 1));
    send(&rt, "~zod", "counter", "say second");

    let effects = rt.drain_outbox("~zod", NO_LIMIT).unwrap();
    let payloads: Vec<&[u8]> = effects.iter().map(|e| e.payload.as_slice()).collect();
    assert_eq!(payloads, [&b"hello there"[..], &b"second"[..]]);
    assert!(effects[0].seq < effects[1].seq);
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());
}

#[test]
fn outbox_is_bounded_and_drains_in_batches() {
    let dir = TempDir::new("outbox");
    // Each message counts as its 10-byte payload plus 64 bytes of overhead, so two fit.
    let rt = boot(&dir, Config { max_outbox_bytes: 2 * 74 + 10, ..fast() });
    for _ in 0..2 {
        send(&rt, "~zod", "counter", "say 0123456789");
    }
    assert!(matches!(rejection(&rt, "counter", "say 0123456789"), Rejection::Limit(_)));

    // The quota is tracked across a sleep and wake.
    rt.sleep_idle(Duration::ZERO);
    assert!(matches!(rejection(&rt, "counter", "say 0123456789"), Rejection::Limit(_)));

    assert_eq!(rt.drain_outbox("~zod", 15).unwrap().len(), 1);
    send(&rt, "~zod", "counter", "say 0123456789");
    // A message bigger than the batch size is still handed over, one at a time.
    assert_eq!(rt.drain_outbox("~zod", 1).unwrap().len(), 1);
    assert_eq!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().len(), 1);
}

#[test]
fn ships_and_agents_are_isolated() {
    let dir = TempDir::new("isolation");
    let rt = boot(&dir, fast());
    let hash = rt.add_module(&counter_wasm()).unwrap();
    rt.create_ship("~bus", &kernel(&rt)).unwrap();
    rt.install("~bus", "counter", &hash, &nothing()).unwrap();
    rt.install("~zod", "other", &hash, &nothing()).unwrap();

    send(&rt, "~zod", "counter", "inc hits 7");
    assert_eq!(send(&rt, "~bus", "counter", "get hits"), "0");
    assert_eq!(send(&rt, "~zod", "other", "get hits"), "0");
    // One kernel and one agent module, however many ships and agents use them.
    assert_eq!(rt.compiled_modules(), 2);
}

#[test]
fn bad_names_and_unknown_targets_are_refused() {
    let dir = TempDir::new("names");
    let rt = boot(&dir, fast());

    for name in ["../zod", "zod/../../etc", "", "ZOD", "zod.ship", "-zod"] {
        assert!(matches!(rt.create_ship(name, &kernel(&rt)), Err(Error::InvalidName(_))), "{name:?}");
    }
    assert!(matches!(rt.create_ship("zod", &kernel(&rt)), Err(Error::ShipExists(_))));
    assert!(matches!(rt.deliver("~nec", "counter", b"get x"), Err(Error::UnknownShip(_))));
    assert!(matches!(rt.deliver("~zod", "nope", b"get x"), Err(Error::Rejected(Rejection::Denied(_)))));
    assert!(matches!(rt.deliver("~zod", "../x", b"get x"), Err(Error::InvalidName(_))));
    assert!(matches!(rt.install("~zod", "x", &"0".repeat(64), &nothing()), Err(Error::UnknownModule(_))));
    // The kernel's own keys live under this name, so no agent may take it.
    let counter = rt.add_module(&counter_wasm()).unwrap();
    assert!(matches!(rt.install("~zod", "kernel", &counter, &nothing()), Err(Error::InstallRefused(_))));
    // An agent module is not a kernel, and a kernel is not an agent.
    assert!(matches!(rt.create_ship("~nec", &counter), Err(Error::BadModule(_))));
    // A creation that failed leaves nothing behind, so the name can still be used.
    rt.create_ship("~nec", &kernel(&rt)).unwrap();
    assert!(matches!(rt.create_ship("~nec", &kernel(&rt)), Err(Error::ShipExists(_))));
    assert!(matches!(rt.install("~zod", "x", &kernel(&rt), &nothing()), Err(Error::BadModule(_))));
    assert!(matches!(rt.add_module(b"not wasm"), Err(Error::BadModule(_))));
}

#[test]
fn export_then_import_into_another_runtime() {
    let (a, b, out) = (TempDir::new("export-a"), TempDir::new("export-b"), TempDir::new("export-out"));
    let rt = boot(&a, fast());
    send(&rt, "~zod", "counter", "inc hits 9");
    send(&rt, "~zod", "counter", "say one");
    send(&rt, "~zod", "counter", "say two");
    let last = rt.drain_outbox("~zod", NO_LIMIT).unwrap().pop().unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    // Changes after the export must not leak into it.
    send(&rt, "~zod", "counter", "inc hits");

    let other = Runtime::open(&b.0, fast()).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(send(&other, "~zod", "counter", "get hits"), "9");
    send(&other, "~zod", "counter", "say after import");
    let seqs: Vec<i64> = other.drain_outbox("~zod", NO_LIMIT).unwrap().iter().map(|e| e.seq).collect();
    // The exported outbox was empty, so only the carried-over counter keeps numbers from being reused.
    assert_eq!(seqs, [last.seq + 1]);
    assert!(matches!(other.import_ship(&out.0, "~zod"), Err(Error::ShipExists(_))));
    assert!(matches!(other.import_ship(&out.0, "~bus"), Err(Error::UnknownShip(_))));
}

#[test]
fn import_refuses_a_tampered_module_and_heals_a_damaged_local_copy() {
    let (a, b, c, out) =
        (TempDir::new("tamper-a"), TempDir::new("tamper-b"), TempDir::new("tamper-c"), TempDir::new("tamper-out"));
    let rt = boot(&a, fast());
    send(&rt, "~zod", "counter", "inc hits 4");
    rt.export_ship("~zod", &out.0).unwrap();
    let blob = fs::read_dir(out.0.join("blobs")).unwrap().next().unwrap().unwrap().path();

    // The destination already holds a damaged blob under the right name: import must replace it.
    let healed = Runtime::open(&c.0, fast()).unwrap();
    fs::write(c.0.join("blobs").join(blob.file_name().unwrap()), b"damaged").unwrap();
    healed.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(send(&healed, "~zod", "counter", "get hits"), "4");

    fs::write(&blob, b"tampered").unwrap();
    let other = Runtime::open(&b.0, fast()).unwrap();
    assert!(matches!(other.import_ship(&out.0, "~zod"), Err(Error::BadModule(_))));
    assert!(matches!(other.deliver("~zod", "counter", b"get hits"), Err(Error::UnknownShip(_))));
}

#[test]
fn import_refuses_a_ship_file_carrying_triggers() {
    let (a, b, out) = (TempDir::new("trigger-a"), TempDir::new("trigger-b"), TempDir::new("trigger-out"));
    let rt = boot(&a, fast());
    rt.export_ship("~zod", &out.0).unwrap();

    // A trigger like this would let one agent's ordinary write rewrite another agent's data.
    let conn = rusqlite::Connection::open(out.0.join("zod.ship")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER steal AFTER INSERT ON kv BEGIN
             UPDATE kv SET value = x'00' WHERE agent <> NEW.agent;
         END;",
    )
    .unwrap();
    drop(conn);

    let other = Runtime::open(&b.0, fast()).unwrap();
    assert!(matches!(other.import_ship(&out.0, "~zod"), Err(Error::BadShipFile(_))));
    assert!(matches!(other.deliver("~zod", "counter", b"get hits"), Err(Error::UnknownShip(_))));
}

#[test]
fn concurrent_imports_of_one_ship_admit_exactly_one() {
    let (a, b, out) = (TempDir::new("race-a"), TempDir::new("race-b"), TempDir::new("race-out"));
    let rt = boot(&a, fast());
    send(&rt, "~zod", "counter", "inc hits 6");
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, fast()).unwrap();
    let won = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| match other.import_ship(&out.0, "~zod") {
                Ok(()) => drop(won.fetch_add(1, Ordering::SeqCst)),
                Err(Error::ShipExists(_)) => {}
                Err(e) => panic!("unexpected import error: {e}"),
            });
        }
    });
    assert_eq!(won.load(Ordering::SeqCst), 1);
    assert_eq!(send(&other, "~zod", "counter", "get hits"), "6");
    assert_eq!(fs::read_dir(b.0.join("tmp")).unwrap().count(), 0, "import left scratch files behind");
}

#[test]
fn one_event_at_a_time_per_ship_under_contention() {
    let dir = TempDir::new("contention");
    let rt = boot(&dir, fast());
    let (threads, per_thread) = (8, 200);

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                for _ in 0..per_thread {
                    rt.deliver("~zod", "counter", b"inc hits").unwrap();
                }
            });
        }
    });
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), (threads * per_thread).to_string());
}

#[test]
fn idle_ships_sleep_and_wake_with_their_state() {
    let dir = TempDir::new("sleep");
    let rt = Runtime::open(&dir.0, Config { max_awake: 4, ..fast() }).unwrap();
    let hash = rt.add_module(&counter_wasm()).unwrap();
    let names: Vec<String> = (0..12).map(|i| format!("ship-{}", (b'a' + i) as char)).collect();
    for name in &names {
        rt.create_ship(name, &kernel(&rt)).unwrap();
        rt.install(name, "counter", &hash, &nothing()).unwrap();
        send(&rt, name, "counter", "inc hits 3");
        assert!(rt.awake() <= 4, "awake ships exceeded the cap");
    }

    let awake = rt.awake();
    assert_eq!(awake, 4);
    assert_eq!(rt.sleep_idle(Duration::ZERO), awake);
    assert_eq!(rt.awake(), 0);
    for name in &names {
        assert_eq!(send(&rt, name, "counter", "get hits"), "3");
    }
}

#[test]
fn awake_cap_holds_while_many_ships_are_busy_at_once() {
    let dir = TempDir::new("cap");
    let rt = Runtime::open(&dir.0, Config { max_awake: 2, ..fast() }).unwrap();
    let hash = rt.add_module(&counter_wasm()).unwrap();
    let names: Vec<String> = (0..8).map(|i| format!("ship-{}", (b'a' + i) as char)).collect();
    for name in &names {
        rt.create_ship(name, &kernel(&rt)).unwrap();
        rt.install(name, "counter", &hash, &nothing()).unwrap();
    }

    // Count real open connections, not just the runtime's own bookkeeping: an open ship keeps a
    // shared-memory file next to its database, which SQLite removes when the ship is closed.
    let open_files = || {
        let entries = fs::read_dir(dir.0.join("ships")).unwrap();
        entries.flatten().filter(|e| e.file_name().to_string_lossy().ends_with("-shm")).count()
    };
    let (done, worst, worst_open) = (AtomicBool::new(false), AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                worst.fetch_max(rt.awake(), Ordering::SeqCst);
                worst_open.fetch_max(open_files(), Ordering::SeqCst);
            }
        });
        let workers: Vec<_> = names
            .iter()
            .map(|name| {
                let rt = &rt;
                scope.spawn(move || {
                    for _ in 0..50 {
                        rt.deliver(name, "counter", b"inc hits").unwrap();
                    }
                })
            })
            .collect();
        // Stop the sampler before reporting a worker failure, or it would spin forever.
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        done.store(true, Ordering::SeqCst);
        assert!(results.iter().all(|result| result.is_ok()), "a worker failed");
    });

    assert!(worst.load(Ordering::SeqCst) <= 2, "more than max_awake ships were open at once");
    assert!(worst_open.load(Ordering::SeqCst) <= 2, "more than max_awake ship files were open at once");
    assert!(worst_open.load(Ordering::SeqCst) >= 1, "the open-file sampler saw nothing");
    for name in &names {
        assert_eq!(send(&rt, name, "counter", "get hits"), "50");
    }
}

#[test]
fn audit_log_is_bounded_and_records_failures() {
    let dir = TempDir::new("audit");
    let rt = boot(&dir, Config { audit_rows: 5, ..small_fuel() });
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "inc hits");
    }
    let entries = rt.audit("~zod", 100).unwrap();
    assert_eq!(entries.len(), 5);
    assert!(entries.iter().all(|entry| entry.ok && entry.event == b"inc hits"));

    rejection(&rt, "counter", "spin");
    let entries = rt.audit("~zod", 100).unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!((entries[0].event.as_slice(), entries[0].ok), (&b"spin"[..], false));
}

#[test]
fn empty_messages_still_count_against_the_outbox() {
    let source = r#"(module
        (import "host" "emit" (func $emit (param i32 i32)))
        (memory (export "memory") 1)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64)
            (call $emit (i32.const 0) (i32.const 0))
            (i64.const 0)))"#;
    let dir = TempDir::new("empty-messages");
    let rt = boot_wat(&dir, Config { max_outbox_bytes: 130, ..fast() }, source);
    rt.deliver("~zod", "evil", b"x").unwrap();
    rt.deliver("~zod", "evil", b"x").unwrap();
    assert!(matches!(rejection(&rt, "evil", "x"), Rejection::Limit(_)));
}

#[test]
fn a_data_directory_has_one_runtime_at_a_time() {
    let dir = TempDir::new("exclusive");
    let rt = boot(&dir, fast());
    assert!(matches!(Runtime::open(&dir.0, fast()), Err(Error::DataDirInUse)));
    assert!(locked_for_another_process(&dir.0));
    drop(rt);
    assert!(!locked_for_another_process(&dir.0));
    assert!(Runtime::open(&dir.0, fast()).is_ok());
}

#[test]
fn export_into_the_runtimes_own_directory_keeps_modules_intact() {
    let dir = TempDir::new("self-export");
    let rt = boot(&dir, fast());
    send(&rt, "~zod", "counter", "inc hits 2");
    rt.export_ship("~zod", &dir.0).unwrap();
    drop(rt);

    // A restart reloads the module from disk, which would fail if the export had truncated it.
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "2");
}

/// Export `~zod`, let `tamper` edit the exported file, and return the result of importing it.
fn import_tampered(label: &str, tamper: &str) -> Result<(), Error> {
    let (a, b, out) = (
        TempDir::new(&format!("{label}-a")),
        TempDir::new(&format!("{label}-b")),
        TempDir::new(&format!("{label}-out")),
    );
    let rt = boot(&a, fast());
    send(&rt, "~zod", "counter", "inc hits");
    rt.export_ship("~zod", &out.0).unwrap();
    rusqlite::Connection::open(out.0.join("zod.ship")).unwrap().execute_batch(tamper).unwrap();

    let other = Runtime::open(&b.0, fast()).unwrap();
    let result = other.import_ship(&out.0, "~zod");
    if result.is_err() {
        assert!(matches!(other.deliver("~zod", "counter", b"get hits"), Err(Error::UnknownShip(_))));
        assert_eq!(fs::read_dir(b.0.join("tmp")).unwrap().count(), 0, "import left scratch files behind");
    }
    result
}

#[test]
fn import_refuses_oversized_values_and_poisoned_counters() {
    assert!(import_tampered("control", "SELECT 1").is_ok());
    assert!(import_tampered("big-value", "INSERT INTO kv VALUES ('counter', x'01', zeroblob(3000000))").is_err());
    assert!(import_tampered("bad-agent", "INSERT INTO kv VALUES ('../x', x'01', x'02')").is_err());
    let exhausted = "UPDATE sqlite_sequence SET seq = 9223372036854775807 WHERE name = 'audit'";
    assert!(matches!(import_tampered("counter", exhausted), Err(Error::BadShipFile(_))));
    let stray = "INSERT INTO sqlite_sequence VALUES ('kv', 5)";
    assert!(matches!(import_tampered("stray-counter", stray), Err(Error::BadShipFile(_))));
    assert!(matches!(import_tampered("extra-table", "CREATE TABLE extra (x)"), Err(Error::BadShipFile(_))));
}

#[test]
fn loop_free_bulk_work_is_capped_and_a_late_result_is_not_committed() {
    // No loop and no call after the emit. The check the runtime adds before each fill is what
    // stops this; without it the event would run to the end and come back late.
    let unrolled = |fills: usize| {
        format!(
            r#"(module
                (import "host" "emit" (func $emit (param i32 i32)))
                (memory (export "memory") 1024)
                (func (export "alloc") (param i32) (result i32) (i32.const 0))
                (func (export "handle") (param i32 i32) (result i64)
                    (call $emit (i32.const 0) (i32.const 1))
                    {}
                    (i64.const 0)))"#,
            "(memory.fill (i32.const 0) (i32.const 1) (i32.const 67108864))".repeat(fills)
        )
    };
    let dir = TempDir::new("late");
    let rt = boot_wat(&dir, Config { max_event_millis: 100, ..fast() }, &unrolled(2000));
    let started = Instant::now();
    assert_eq!(rejection(&rt, "evil", "x"), Rejection::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5), "loop-free bulk work ran far past the limit");
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());
}

#[test]
fn bulk_work_while_returning_from_recursion_is_stopped() {
    // Each frame does its fills after its recursive call returns. Time checks happen on the way
    // down, at function entry, and none happen on the way back up, so without a check before
    // each fill this would write about two terabytes.
    let source = format!(
        r#"(module
            (memory (export "memory") 1024)
            (func $deep (param $n i32)
                (if (local.get $n) (then (call $deep (i32.sub (local.get $n) (i32.const 1)))))
                {})
            (func (export "alloc") (param i32) (result i32) (i32.const 0))
            (func (export "handle") (param i32 i32) (result i64)
                (call $deep (i32.const 500))
                (i64.const 0)))"#,
        "(memory.fill (i32.const 0) (i32.const 1) (i32.const 67108864))".repeat(64)
    );
    let dir = TempDir::new("unwind");
    let rt = boot_wat(&dir, Config { max_event_millis: 100, ..fast() }, &source);
    let started = Instant::now();
    assert_eq!(rejection(&rt, "evil", "x"), Rejection::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5), "bulk work during unwinding ran far past the limit");
}

/// Not a test of its own: when the variable is set, this process probes a directory's lock and
/// reports through its exit code. Lets other tests check the lock from a separate process.
#[test]
fn helper_probe_directory_lock() {
    let Ok(dir) = std::env::var("URBIT_WASM_LOCK_PROBE") else { return };
    std::process::exit(match Runtime::open(&dir, fast()) {
        Err(Error::DataDirInUse) => 10,
        Ok(_) => 11,
        Err(_) => 12,
    });
}

fn locked_for_another_process(dir: &Path) -> bool {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["helper_probe_directory_lock", "--exact", "--nocapture"])
        .env("URBIT_WASM_LOCK_PROBE", dir)
        .status()
        .unwrap();
    match status.code() {
        Some(10) => true,
        Some(11) => false,
        other => panic!("lock probe failed: {other:?}"),
    }
}

#[test]
fn import_cannot_be_pointed_at_devices_or_the_lock_file() {
    let (a, b, out) = (TempDir::new("alias-a"), TempDir::new("alias-b"), TempDir::new("alias-out"));
    let rt = boot(&a, fast());
    rt.export_ship("~zod", &out.0).unwrap();
    let blob = fs::read_dir(out.0.join("blobs")).unwrap().next().unwrap().unwrap().path();
    let other = Runtime::open(&b.0, fast()).unwrap();

    // A module "file" that is really an endless device must be refused, not read.
    fs::remove_file(&blob).unwrap();
    std::os::unix::fs::symlink("/dev/zero", &blob).unwrap();
    assert!(other.import_ship(&out.0, "~zod").is_err());

    // A module file that is a second name for the runtime's lock file: reading and closing it
    // must not release the lock.
    fs::remove_file(&blob).unwrap();
    fs::hard_link(b.0.join("runtime.lock"), &blob).unwrap();
    assert!(other.import_ship(&out.0, "~zod").is_err());
    assert!(matches!(Runtime::open(&b.0, fast()), Err(Error::DataDirInUse)));
    assert!(locked_for_another_process(&b.0));

    // The ship file itself as an endless device.
    fs::remove_file(out.0.join("zod.ship")).unwrap();
    std::os::unix::fs::symlink("/dev/zero", out.0.join("zod.ship")).unwrap();
    assert!(other.import_ship(&out.0, "~zod").is_err());
    assert_eq!(fs::read_dir(b.0.join("tmp")).unwrap().count(), 0, "import left scratch files behind");
}

#[test]
fn every_kind_of_bulk_operation_still_works_after_the_rewrite() {
    // The runtime rewrites modules to add a check before each bulk operation. This module uses
    // all six kinds, with passive data and element segments, and must behave exactly as written.
    let source = r#"(module
        (memory (export "memory") 1)
        (table $t 4 funcref)
        (elem $e func $f)
        (data $d "hello")
        (func $f)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64)
            (memory.init $d (i32.const 0) (i32.const 0) (i32.const 5))
            (memory.copy (i32.const 5) (i32.const 0) (i32.const 5))
            (memory.fill (i32.const 10) (i32.const 33) (i32.const 1))
            (table.init $t $e (i32.const 0) (i32.const 0) (i32.const 1))
            (table.copy $t $t (i32.const 1) (i32.const 0) (i32.const 1))
            (table.fill $t (i32.const 2) (ref.null func) (i32.const 2))
            (i64.const 11)))"#;
    let dir = TempDir::new("all-bulk");
    let rt = boot_wat(&dir, fast(), source);
    assert_eq!(rt.deliver("~zod", "evil", b"x").unwrap().reply, b"hellohello!");
}

#[test]
fn import_refuses_a_damaged_file() {
    let (a, b, out) = (TempDir::new("damaged-a"), TempDir::new("damaged-b"), TempDir::new("damaged-out"));
    let rt = boot(&a, fast());
    for key in 0..200 {
        send(&rt, "~zod", "counter", &format!("inc key{key}"));
    }
    rt.export_ship("~zod", &out.0).unwrap();

    // Leave page one (the schema) alone and wreck every page after it.
    let path = out.0.join("zod.ship");
    let mut bytes = fs::read(&path).unwrap();
    let page_size = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    assert!(bytes.len() > 2 * page_size, "expected the export to span several pages");
    bytes[page_size..].fill(0xff);
    fs::write(&path, bytes).unwrap();

    let other = Runtime::open(&b.0, fast()).unwrap();
    assert!(other.import_ship(&out.0, "~zod").is_err());
    assert!(matches!(other.deliver("~zod", "counter", b"get key1"), Err(Error::UnknownShip(_))));
}

#[test]
fn agents_need_permission_to_use_each_other() {
    // The tally agent reads the counter and sends it a command. Without a declared use it gets nothing.
    let dir = TempDir::new("perm-none");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(false));
    send(&rt, "~zod", "counter", "inc hits 5");
    assert!(matches!(rejection(&rt, "tally", "bump hits"), Rejection::Denied(_)));
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "5");

    // With the use declared, the read answers at once and the command runs afterwards.
    let dir = TempDir::new("perm-declared");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "inc hits 5");
    let outcome = rt.deliver("~zod", "tally", b"bump hits").unwrap();
    assert_eq!((outcome.reply.as_slice(), outcome.queued), (&b"5"[..], 1));
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "6");
    assert_eq!(read(&rt, "tally", "tally", "last-seen"), "5");

    // A public interface needs no declaration.
    let dir = TempDir::new("perm-public");
    let rt = boot_pair(&dir, fast(), counter_manifest(true), tally_manifest(false));
    assert_eq!(send(&rt, "~zod", "tally", "bump hits"), "0");
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "1");

    // A declared use of something the other agent does not offer grants nothing.
    let dir = TempDir::new("perm-unoffered");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(true));
    assert!(matches!(rejection(&rt, "tally", "bump hits"), Rejection::Denied(_)));
}

#[test]
fn a_command_sent_by_a_failed_event_never_runs() {
    let dir = TempDir::new("queued-rollback");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    assert!(matches!(rejection(&rt, "tally", "bump-then-crash hits"), Rejection::Trap(_)));
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "0");
}

#[test]
fn reads_answer_at_once_and_cannot_change_anything() {
    let dir = TempDir::new("reads");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "inc hits 3");
    send(&rt, "~zod", "tally", "bump hits");

    assert_eq!(read(&rt, "counter", "counter", "hits"), "4");
    // A read that itself reads another agent.
    assert_eq!(read(&rt, "tally", "tally", "via-counter hits"), "4");

    // A read handler that tries to write is stopped, and what it wrote is not kept.
    let attempt = rt.read("~zod", "tally", "tally", b"write");
    assert!(matches!(attempt, Err(Error::Rejected(Rejection::Denied(_)))), "{attempt:?}");
    assert_eq!(read(&rt, "tally", "tally", "last-seen"), "3");

    // The counter has no declared use of the tally agent, so a module with no read handler, or
    // an agent that does not exist, is simply refused.
    assert!(rt.read("~zod", "nope", "x", b"").is_err());
}

#[test]
fn agents_that_keep_sending_cannot_hold_the_ship() {
    // Each ping sends the next one. Only a fixed number run after the delivery; the rest wait.
    let dir = TempDir::new("chain");
    let rt = boot_pair(&dir, Config { max_queued_per_deliver: 5, ..fast() }, nothing(), tally_manifest(false));
    assert_eq!(send(&rt, "~zod", "tally", "ping 0"), "0");
    assert_eq!(read(&rt, "tally", "tally", "pings"), "5");
    assert_eq!(rt.run_pending("~zod", 3).unwrap(), 3);
    assert_eq!(read(&rt, "tally", "tally", "pings"), "8");
}

#[test]
fn an_agent_is_told_who_is_calling() {
    let dir = TempDir::new("who");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    assert_eq!(send(&rt, "~zod", "tally", "who"), "owner ");
}

#[test]
fn queued_commands_survive_export_and_import() {
    let (a, b, out) = (TempDir::new("queue-a"), TempDir::new("queue-b"), TempDir::new("queue-out"));
    // With nothing run after delivery, the command the tally agent sends stays queued.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "bump hits");
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(send(&other, "~zod", "counter", "get hits"), "0");
    assert_eq!(other.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(send(&other, "~zod", "counter", "get hits"), "1");
}

/// A kernel that gives the same fixed answers to every question. A ship brings its own kernel
/// when it is imported, so the runtime cannot assume a kernel is well behaved.
fn fixed_kernel(route: &ship_proto::RouteReply, admin: &ship_proto::AdminReply) -> Vec<u8> {
    use ship_proto::Message;
    let escaped = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let (route, admin) = (route.encode_to_vec(), admin.encode_to_vec());
    assert!(route.len() < 512 && admin.len() < 512);
    let source = format!(
        r#"(module
            (memory (export "memory") 1)
            (data (i32.const 0) "{}")
            (data (i32.const 512) "{}")
            (func (export "alloc") (param i32) (result i32) (i32.const 1024))
            (func (export "route") (param i32 i32) (result i64) (i64.const {}))
            (func (export "admin") (param i32 i32) (result i64) (i64.const {})))"#,
        escaped(&route),
        escaped(&admin),
        route.len(),
        (512u64 << 32) | admin.len() as u64,
    );
    wat::parse_str(&source).unwrap()
}

#[test]
fn a_hostile_kernel_cannot_point_the_runtime_at_other_files() {
    use ship_proto::{AdminReply, RouteReply};
    // This kernel approves everything, and names "modules" that would escape the module store
    // if they were used as file names.
    let outside = "../../../../etc/passwd".to_string();
    let route = RouteReply { allowed: true, module: outside.clone(), ..Default::default() };
    let admin = AdminReply { ok: true, modules: vec![outside], ..Default::default() };
    let dir = TempDir::new("hostile-paths");
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let hostile = rt.add_module(&fixed_kernel(&route, &admin)).unwrap();
    rt.create_ship("~zod", &hostile).unwrap();

    // Both must be refused for not being a hash, which happens before any file is touched,
    // and not merely because the file turned out to be missing.
    match rt.deliver("~zod", "anything", b"x") {
        Err(Error::Rejected(Rejection::Trap(why))) => assert!(why.contains("is not a module hash"), "{why}"),
        other => panic!("expected a rejection, got {other:?}"),
    }
    let out = TempDir::new("hostile-paths-out");
    match rt.export_ship("~zod", &out.0) {
        Err(Error::BadModule(why)) => assert!(why.contains("is not a module hash"), "{why}"),
        other => panic!("expected the export to be refused, got {other:?}"),
    }
}

#[test]
fn a_hostile_kernel_cannot_run_an_agent_under_the_kernels_own_name() {
    use ship_proto::{AdminReply, RouteReply};
    // The kernel's keys are stored under the name `kernel`. A kernel that routes an ordinary
    // agent under that name would let the agent rewrite the registry, so the runtime refuses
    // the name itself, whatever the kernel says.
    let dir = TempDir::new("hostile-name");
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let counter = rt.add_module(&counter_wasm()).unwrap();
    let route = RouteReply { allowed: true, module: counter, ..Default::default() };
    let hostile = rt.add_module(&fixed_kernel(&route, &AdminReply { ok: true, ..Default::default() })).unwrap();
    rt.create_ship("~zod", &hostile).unwrap();

    assert_eq!(send(&rt, "~zod", "counter", "inc hits"), "1");
    assert!(matches!(rt.deliver("~zod", "kernel", b"inc hits"), Err(Error::Rejected(Rejection::Denied(_)))));
    assert!(matches!(rt.read("~zod", "kernel", "counter", b"hits"), Err(Error::Rejected(Rejection::Denied(_)))));
}

#[test]
fn deeply_nested_reads_do_not_overflow_the_thread_stack() {
    // Each level uses a good part of its WASM stack allowance, then reads itself. Every nested
    // read is a fresh instance with its own allowance on the same thread, so without care the
    // levels together overrun the thread's stack and take the whole process down.
    let nesting = |at_the_bottom: &str| {
        format!(
            r#"(module
                (import "host" "read" (func $read (param i32 i32 i32 i32) (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\0a\04evil\12\01x\1a\01\00")
                (func $deep (param $n i32) (param $level i32)
                    (if (local.get $n)
                        (then (call $deep (i32.sub (local.get $n) (i32.const 1)) (local.get $level)))
                        (else
                            (i32.store8 (i32.const 11) (i32.sub (local.get $level) (i32.const 1)))
                            (drop (call $read (i32.const 0) (i32.const 12) (i32.const 2048) (i32.const 16))))))
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "handle") (param i32 i32) (result i64) (i64.const 0))
                (func (export "read") (param i32 i32) (result i64)
                    (if (i32.load8_u (i32.const 1024))
                        (then (call $deep (i32.const 6000) (i32.load8_u (i32.const 1024))))
                        (else {at_the_bottom}))
                    (i64.const 0)))"#
        )
    };
    let dir = TempDir::new("stack");
    let rt = Runtime::open(&dir.0, fast()).unwrap();
    let offers_x = Manifest { provides: vec![Provide { interface: "x".into(), public: false, remote: false }], uses: vec![] };
    for (ship, at_the_bottom) in [("~zod", "nop"), ("~bus", "unreachable")] {
        let hash = rt.add_module(&wat::parse_str(nesting(at_the_bottom)).unwrap()).unwrap();
        rt.create_ship(ship, &kernel(&rt)).unwrap();
        rt.install(ship, "evil", &hash, &offers_x).unwrap();
    }

    // A deliberately small thread stack, as a caller of the runtime might well have.
    let (failed, worked) = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(512 << 10)
            .spawn_scoped(scope, || {
                // A failure at the deepest level has to unwind back up through every stack
                // segment, and leave the thread usable for the next call.
                let failed = rt.read("~bus", "evil", "x", &[7]);
                (failed, rt.read("~zod", "evil", "x", &[7]))
            })
            .unwrap()
            .join()
            .unwrap()
    });
    assert!(matches!(failed, Err(Error::Rejected(Rejection::Trap(_)))), "{failed:?}");
    assert_eq!(worked.unwrap(), b"");
}

#[test]
fn reading_and_sending_are_separate_permissions() {
    let uses = |read, send| Manifest {
        provides: vec![Provide { interface: "tally".into(), public: false, remote: false }],
        uses: vec![Use { agent: "counter".into(), interface: "counter".into(), read, send, ship: String::new() }],
    };
    let dir = TempDir::new("read-only-grant");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), uses(true, false));
    assert_eq!(send(&rt, "~zod", "tally", "peek hits"), "0");
    assert!(matches!(rejection(&rt, "tally", "poke hits"), Rejection::Denied(_)));

    let dir = TempDir::new("send-only-grant");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), uses(false, true));
    assert_eq!(send(&rt, "~zod", "tally", "poke hits"), "sent");
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "1");
    assert!(matches!(rejection(&rt, "tally", "peek hits"), Rejection::Denied(_)));
}

#[test]
fn queued_commands_and_nested_reads_carry_their_real_sender() {
    let dir = TempDir::new("sender");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    // A command the tally agent sent itself arrives marked as coming from it, not from the owner.
    send(&rt, "~zod", "tally", "relay");
    assert_eq!(read(&rt, "tally", "tally", "note"), "tally tally");
    assert_eq!(read(&rt, "tally", "tally", "who"), "owner tally");
    assert_eq!(read(&rt, "tally", "tally", "via-self"), "tally tally");
}

#[test]
fn a_queued_command_that_fails_is_dropped_and_recorded() {
    let dir = TempDir::new("queued-failure");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    assert_eq!(send(&rt, "~zod", "tally", "poke-bad"), "sent");
    // It ran once, failed, and is gone: nothing is left to retry.
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
    assert_eq!(send(&rt, "~zod", "counter", "get x"), "0");
    let failed: Vec<_> = rt.audit("~zod", 10).unwrap().into_iter().filter(|entry| !entry.ok).collect();
    assert_eq!(failed.len(), 1);
    assert_eq!((failed[0].agent.as_str(), failed[0].event.as_slice()), ("counter", &b"crash x"[..]));
}

#[test]
fn the_queue_is_bounded_and_a_running_command_frees_its_own_room() {
    // Room for exactly one queued ping: 6 bytes of payload plus 64 of overhead.
    let cfg = Config { max_inbox_bytes: 70, max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("queue-room");
    let rt = boot_pair(&dir, cfg, nothing(), tally_manifest(false));
    send(&rt, "~zod", "tally", "ping 0");
    assert!(matches!(rejection(&rt, "tally", "ping 0"), Rejection::Limit(_)));
    // The count of what is queued survives a sleep and wake.
    rt.sleep_idle(Duration::ZERO);
    assert!(matches!(rejection(&rt, "tally", "ping 0"), Rejection::Limit(_)));

    // Running the queued ping takes it off the queue, which makes room for the one it sends.
    for expected in 1..=4 {
        assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
        assert_eq!(read(&rt, "tally", "tally", "pings"), expected.to_string());
    }
}

#[test]
fn large_replies_and_misbehaving_read_handlers() {
    let dir = TempDir::new("read-edges");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    // Bigger than the first buffer the SDK offers, directly and through a nested read.
    assert_eq!(rt.read("~zod", "tally", "tally", b"big").unwrap().len(), 10_000);
    assert_eq!(rt.read("~zod", "tally", "tally", b"via-big").unwrap(), vec![b'x'; 10_000]);

    // A read handler may not queue outgoing messages either.
    assert!(matches!(rt.read("~zod", "tally", "tally", b"emit"), Err(Error::Rejected(Rejection::Denied(_)))));
    assert!(rt.drain_outbox("~zod", NO_LIMIT).unwrap().is_empty());

    // An agent with no read handler at all.
    let commands_only = r#"(module
        (memory (export "memory") 1)
        (func (export "alloc") (param i32) (result i32) (i32.const 1024))
        (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))"#;
    let hash = rt.add_module(&wat::parse_str(commands_only).unwrap()).unwrap();
    rt.install("~zod", "mute", &hash, &nothing()).unwrap();
    match rt.read("~zod", "mute", "x", b"") {
        Err(Error::Rejected(Rejection::Trap(why))) => assert!(why.contains("no `read` handler"), "{why}"),
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn nothing_runs_once_the_time_limit_has_passed() {
    let dir = TempDir::new("no-time");
    let rt = boot(&dir, fast());
    send(&rt, "~zod", "counter", "inc hits");
    drop(rt);

    // With no time allowed at all, commands, reads, and installs are all refused.
    let rt = Runtime::open(&dir.0, Config { max_event_millis: 0, ..fast() }).unwrap();
    assert_eq!(rejection(&rt, "counter", "inc hits"), Rejection::Timeout);
    assert!(matches!(rt.read("~zod", "counter", "counter", b"hits"), Err(Error::Rejected(Rejection::Timeout))));
    let hash = rt.add_module(&counter_wasm()).unwrap();
    assert!(matches!(rt.install("~zod", "other", &hash, &nothing()), Err(Error::Rejected(Rejection::Timeout))));
}

#[test]
fn the_kernel_refuses_manifests_that_would_leave_the_ship_unroutable() {
    let dir = TempDir::new("manifest-limits");
    let rt = boot(&dir, fast());
    let hash = rt.add_module(&counter_wasm()).unwrap();

    // The same interface listed twice, once private and once public.
    let twice = Manifest {
        provides: vec![
            Provide { interface: "x".into(), public: false, remote: false },
            Provide { interface: "x".into(), public: true, remote: false },
        ],
        uses: vec![],
    };
    assert!(matches!(rt.install("~zod", "twice", &hash, &twice), Err(Error::InstallRefused(_))));
    let same_use = Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false, ship: String::new() };
    let twice = Manifest { provides: vec![], uses: vec![same_use.clone(), Use { send: true, ..same_use }] };
    assert!(matches!(rt.install("~zod", "twice", &hash, &twice), Err(Error::InstallRefused(_))));

    // Every public interface is visible to every agent. Keep adding agents that each offer many
    // until the kernel says no, then check that what it accepted still works.
    let wide = |agent: usize| Manifest {
        provides: (0..64).map(|i| Provide { interface: format!("{}-{agent}-{i}", "x".repeat(100)), public: true, remote: false }).collect(),
        uses: vec![],
    };
    let mut accepted = 0;
    for agent in 0..60 {
        match rt.install("~zod", &format!("wide{agent}"), &hash, &wide(agent)) {
            Ok(()) => accepted += 1,
            Err(Error::InstallRefused(_)) => break,
            Err(e) => panic!("unexpected install error: {e}"),
        }
    }
    assert!(accepted > 0 && accepted < 60, "expected the kernel to refuse at some point, accepted {accepted}");
    assert_eq!(send(&rt, "~zod", "wide0", "inc hits"), "1");
    assert_eq!(send(&rt, "~zod", "counter", "inc hits"), "1");

    // Private interfaces are visible to nobody else, so they never make an answer large. They
    // still take room in the registry, which has a limit of its own.
    let dir = TempDir::new("registry-limit");
    let rt = boot(&dir, fast());
    let private = |agent: usize| Manifest {
        provides: (0..64).map(|i| Provide { interface: format!("{}-{agent}-{i}", "x".repeat(100)), public: false, remote: false }).collect(),
        uses: vec![],
    };
    let mut accepted = 0;
    for agent in 0..200 {
        match rt.install("~zod", &format!("private{agent}"), &hash, &private(agent)) {
            Ok(()) => accepted += 1,
            Err(Error::InstallRefused(_)) => break,
            Err(e) => panic!("unexpected install error: {e}"),
        }
    }
    assert!(accepted > 30 && accepted < 200, "expected the registry limit to apply, accepted {accepted}");
    assert_eq!(send(&rt, "~zod", "private0", "inc hits"), "1");
}

#[test]
fn a_read_whose_answer_is_large_still_runs_only_once() {
    // The `slow` agent's read burns a lot of compute and returns more than the caller's first
    // buffer holds. If collecting the answer re-ran the read, it would cost twice as much.
    let slow = r#"(module
        (memory (export "memory") 1)
        (func (export "alloc") (param i32) (result i32) (i32.const 20000))
        (func (export "handle") (param i32 i32) (result i64) (i64.const 0))
        (func (export "read") (param i32 i32) (result i64)
            (local $i i32)
            (loop $again
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $again (i32.lt_u (local.get $i) (i32.const 300000))))
            (i64.const 10000)))"#;
    let dir = TempDir::new("read-once");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    let hash = rt.add_module(&wat::parse_str(slow).unwrap()).unwrap();
    let public = Manifest { provides: vec![Provide { interface: "slow".into(), public: true, remote: false }], uses: vec![] };
    rt.install("~zod", "slow", &hash, &public).unwrap();
    drop(rt);

    let with_fuel = |fuel_per_event| Runtime::open(&dir.0, Config { fuel_per_event, ..fast() }).unwrap();
    // Find the least compute budget under which the slow read succeeds when called directly.
    let (mut too_little, mut enough) = (0u64, 64_000_000u64);
    while enough - too_little > enough / 50 {
        let middle = (too_little + enough) / 2;
        if with_fuel(middle).read("~zod", "slow", "slow", b"").is_ok() {
            enough = middle;
        } else {
            too_little = middle;
        }
    }
    assert!(enough > 500_000, "the slow read is too cheap to tell one run from two: {enough}");

    // Enough for one run plus the caller's own work, but nowhere near enough for two.
    let rt = with_fuel(enough * 8 / 5 + 200_000);
    assert_eq!(rt.read("~zod", "tally", "tally", b"via-slow").unwrap().len(), 10_000);
}

#[test]
fn the_runtime_keeps_its_own_bounds_whatever_a_kernel_grants() {
    use ship_proto::{AdminReply, Grant, Message, ReadRequest, RouteReply, SendRequest};
    // The agent's command sends when its input is 1 and reads when it is 2, using requests
    // prepared here. This kernel grants both, so only the runtime's own checks stand in the way.
    let send_request = SendRequest { agent: "../up".into(), interface: "x".into(), payload: b"p".to_vec(), ship: String::new() }.encode_to_vec();
    let read_request = ReadRequest { agent: "other".into(), interface: "x".into(), payload: vec![0; 100] }.encode_to_vec();
    // A log name one byte longer than the runtime allows.
    let long_name = "x".repeat(129);
    let append_request = ship_proto::AppendRequest { log: long_name.clone(), payload: b"p".to_vec() }.encode_to_vec();
    let escaped = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let agent = format!(
        r#"(module
            (import "host" "send" (func $send (param i32 i32)))
            (import "host" "read" (func $read (param i32 i32 i32 i32) (result i64)))
            (import "host" "log_append" (func $append (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{}")
            (data (i32.const 512) "{}")
            (data (i32.const 1024) "{}")
            (func (export "alloc") (param i32) (result i32) (i32.const 2048))
            (func (export "handle") (param i32 i32) (result i64)
                (if (i32.eq (i32.load8_u (i32.const 2048)) (i32.const 1))
                    (then (call $send (i32.const 0) (i32.const {}))))
                (if (i32.eq (i32.load8_u (i32.const 2048)) (i32.const 2))
                    (then (drop (call $read (i32.const 512) (i32.const {}) (i32.const 4096) (i32.const 16)))))
                (if (i32.eq (i32.load8_u (i32.const 2048)) (i32.const 3))
                    (then (drop (call $append (i32.const 1024) (i32.const {})))))
                (i64.const 0)))"#,
        escaped(&send_request),
        escaped(&read_request),
        escaped(&append_request),
        send_request.len(),
        read_request.len(),
        append_request.len(),
    );
    let dir = TempDir::new("host-bounds");
    let rt = Runtime::open(&dir.0, Config { max_event_bytes: 16, ..fast() }).unwrap();
    let hash = rt.add_module(&wat::parse_str(&agent).unwrap()).unwrap();
    let route = RouteReply {
        allowed: true,
        module: hash,
        reads: vec![Grant { agent: "other".into(), interface: "x".into(), ship: String::new() }, Grant { agent: "evil".into(), interface: long_name, ship: String::new() }],
        sends: vec![Grant { agent: "../up".into(), interface: "x".into(), ship: String::new() }],
        ..Default::default()
    };
    let permissive = rt.add_module(&fixed_kernel(&route, &AdminReply { ok: true, ..Default::default() })).unwrap();
    rt.create_ship("~zod", &permissive).unwrap();

    // A command addressed to a name the runtime would refuse to import later.
    assert!(matches!(rt.deliver("~zod", "evil", &[1]), Err(Error::Rejected(Rejection::Denied(_)))));
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
    // A read request larger than an event may be.
    assert!(matches!(rt.deliver("~zod", "evil", &[2]), Err(Error::Rejected(Rejection::Limit(_)))));
    // A log under a name too long for the runtime ever to read back or import.
    assert!(matches!(rt.deliver("~zod", "evil", &[3]), Err(Error::Rejected(Rejection::Denied(_)))));
}

#[test]
fn small_limits_do_not_break_routing_or_the_ships_own_export() {
    // A reply limit for agents far below the size of a kernel's answer.
    let dir = TempDir::new("small-reply");
    let rt = boot(&dir, Config { max_reply_bytes: 100, ..fast() });
    assert_eq!(send(&rt, "~zod", "counter", "inc hits"), "1");

    // An oversized event is kept in the audit log cut down to what an event may hold, so the
    // ship can still be exported and imported under the same settings.
    let (a, b, out) = (TempDir::new("small-event-a"), TempDir::new("small-event-b"), TempDir::new("small-event-out"));
    let cfg = Config { max_event_bytes: 4, ..fast() };
    let rt = boot(&a, cfg.clone());
    assert!(matches!(rt.deliver("~zod", "counter", b"far too long"), Err(Error::Rejected(Rejection::Limit(_)))));
    assert_eq!(rt.audit("~zod", 1).unwrap()[0].event, b"far ");
    rt.export_ship("~zod", &out.0).unwrap();
    Runtime::open(&b.0, cfg).unwrap().import_ship(&out.0, "~zod").unwrap();
}

#[test]
fn a_full_ship_rejects_growth_and_stays_consistent() {
    // A small storage limit, so that a big write makes the database itself report "full" in the
    // middle of an event. This is the same path any storage error takes.
    let cfg = Config { max_ship_bytes: 128 << 10, ..fast() };
    let dir = TempDir::new("full");
    let rt = boot_pair(&dir, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "inc hits 3");
    assert_eq!(send(&rt, "~zod", "counter", "big 20000"), "ok");

    match rejection(&rt, "counter", "big 200000") {
        Rejection::Limit(why) => assert!(why.contains("storage is full"), "{why}"),
        other => panic!("expected the storage limit, got {other:?}"),
    }
    // Nothing from the rejected event stuck, and the ship carries on.
    assert_eq!(send(&rt, "~zod", "counter", "inc hits"), "4");
    assert_eq!(read(&rt, "counter", "counter", "hits"), "4");

    // The same failure inside a queued command: it is dropped, recorded, and not retried, and
    // the queue still works afterwards.
    assert_eq!(send(&rt, "~zod", "tally", "forward big 200000"), "sent");
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
    let newest = rt.audit("~zod", 1).unwrap().remove(0);
    assert_eq!((newest.agent.as_str(), newest.event.as_slice(), newest.ok), ("counter", &b"big 200000"[..], false));
    assert_eq!(send(&rt, "~zod", "tally", "poke hits"), "sent");
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "5");

    // Freeing space makes room again, and all of it survives a restart.
    assert_eq!(send(&rt, "~zod", "counter", "del big"), "ok");
    assert_eq!(send(&rt, "~zod", "counter", "big 20000"), "ok");
    drop(rt);
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "5");
}

#[test]
fn an_uncollected_reply_cannot_be_collected_after_another_read() {
    use ship_proto::{Message, ReadRequest};
    // This agent reads a large answer into a buffer too small for it and does not collect it,
    // then makes a second, small read. Collecting afterwards must find nothing, not the first
    // answer. It replies 1 if that is what happened.
    let request = |payload: &str| {
        ReadRequest { agent: "tally".into(), interface: "tally".into(), payload: payload.into() }.encode_to_vec()
    };
    let (large, small) = (request("big"), request("pings"));
    let escaped = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let source = format!(
        r#"(module
            (import "host" "read" (func $read (param i32 i32 i32 i32) (result i64)))
            (import "host" "take_reply" (func $take (param i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{}")
            (data (i32.const 256) "{}")
            (func (export "alloc") (param i32) (result i32) (i32.const 512))
            (func (export "handle") (param i32 i32) (result i64)
                (if (i64.ne (call $read (i32.const 0) (i32.const {}) (i32.const 8192) (i32.const 16)) (i64.const 10000))
                    (then unreachable))
                (drop (call $read (i32.const 256) (i32.const {}) (i32.const 8192) (i32.const 64)))
                (i32.store8 (i32.const 1024)
                    (i64.eq (call $take (i32.const 8192) (i32.const 20000)) (i64.const -1)))
                (i64.const 4398046511105)))"#,
        escaped(&large),
        escaped(&small),
        large.len(),
        small.len(),
    );
    let dir = TempDir::new("stale-reply");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    let hash = rt.add_module(&wat::parse_str(&source).unwrap()).unwrap();
    let reads_tally = Manifest {
        provides: vec![],
        uses: vec![Use { agent: "tally".into(), interface: "tally".into(), read: true, send: false, ship: String::new() }],
    };
    rt.install("~zod", "picky", &hash, &reads_tally).unwrap();
    assert_eq!(rt.deliver("~zod", "picky", b"x").unwrap().reply, [1]);
}

/// The payloads of a run of log entries, as text.
fn payloads(entries: &[runtime::SignedEntry]) -> Vec<String> {
    use ship_proto::Message;
    entries
        .iter()
        .map(|entry| String::from_utf8(runtime::EntryBody::decode(&*entry.body).unwrap().payload).unwrap())
        .collect()
}

#[test]
fn a_follower_gets_every_entry_once_and_in_order() {
    let dir = TempDir::new("log-follow");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    assert_eq!(send(&rt, "~zod", "tally", "follow"), "following");
    for expected in 1..=7 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), expected.to_string());
    }
    // The tally agent takes three entries a round and checks their numbers as it goes.
    assert_eq!(read(&rt, "tally", "tally", "seen"), "7");
    assert_eq!(read(&rt, "tally", "tally", "last"), "hits=7");
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);

    // An agent that starts following later is simply behind by the whole log.
    let dir = TempDir::new("log-late");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    for _ in 0..5 {
        send(&rt, "~zod", "counter", "log hits");
    }
    send(&rt, "~zod", "tally", "follow");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "5");
}

#[test]
fn entries_a_failed_round_took_are_offered_again() {
    let dir = TempDir::new("log-retry");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "counter", "log poison");
    // The round that met the poisoned entry failed, so the follower's position did not move.
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");

    // Once it can cope, the next new entry prompts it and it works through all it missed.
    send(&rt, "~zod", "tally", "tolerate");
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "4");
    assert_eq!(read(&rt, "tally", "tally", "last"), "hits=3");
}

#[test]
fn logs_need_the_same_permissions_as_reads() {
    // Without a declared use of the counter's interface, the tally agent may not follow its log.
    let dir = TempDir::new("log-perm");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(false));
    assert!(matches!(rejection(&rt, "tally", "follow"), Rejection::Denied(_)));

    // An agent can only append to a log named after an interface it offers.
    let dir = TempDir::new("log-own");
    let rt = boot_pair(&dir, fast(), nothing(), tally_manifest(false));
    assert!(matches!(rejection(&rt, "counter", "log hits"), Rejection::Denied(_)));

    // A follower whose permission is taken away stops being told about new entries.
    let dir = TempDir::new("log-revoked");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
    let tally = rt.add_module(&wasm("tally")).unwrap();
    rt.install("~zod", "tally", &tally, &tally_manifest(false)).unwrap();
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
}

#[test]
fn a_client_can_read_a_log_and_check_it() {
    let dir = TempDir::new("log-verify");
    let rt = boot(&dir, fast());
    for _ in 0..6 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let key = rt.public_key("~zod").unwrap();
    let all = rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap();
    assert_eq!(payloads(&all), ["hits=1", "hits=2", "hits=3", "hits=4", "hits=5", "hits=6"]);
    let check = |after, entries: &[runtime::SignedEntry]| verify_log(&key, "~zod", "counter", "counter", after, entries);
    // Checking from the start leaves the reader at the log's current end.
    let end = check(None, &all).unwrap();
    assert_eq!(end.map(|(seq, _)| seq), Some(6));
    assert_eq!(rt.log_head("~zod", "counter", "counter").unwrap(), end);

    // Reading on from a known position, in pieces.
    let at_four = check(None, &all[..4]).unwrap();
    let rest = rt.log_entries("~zod", "counter", "counter", 4, NO_LIMIT).unwrap();
    assert_eq!(payloads(&rest), ["hits=5", "hits=6"]);
    assert_eq!(check(at_four, &rest).unwrap(), end);
    assert_eq!(rt.log_entries("~zod", "counter", "counter", 0, 1).unwrap().len(), 1);
    assert!(rt.log_entries("~zod", "counter", "counter", 6, NO_LIMIT).unwrap().is_empty());
    assert!(rt.log_entries("~zod", "counter", "counter", u64::MAX, NO_LIMIT).unwrap().is_empty());

    // Entries that do not carry on from where the reader is: a run that starts later than it
    // should, one that starts again from entry 1, and one handed over twice.
    assert!(check(None, &rest).is_err());
    assert!(check(at_four, &all).is_err());
    assert!(check(end, &rest).is_err());

    // A changed entry, a missing entry, a reordering, the wrong log, and the wrong key all fail.
    let mut changed = all.clone();
    let last = changed[2].body.len() - 1;
    changed[2].body[last] ^= 1;
    assert!(check(None, &changed).is_err());
    let mut missing = all.clone();
    missing.remove(3);
    assert!(check(None, &missing).is_err());
    let mut swapped = all.clone();
    swapped.swap(1, 2);
    assert!(check(None, &swapped).is_err());
    assert!(verify_log(&key, "~zod", "counter", "other", None, &all).is_err());
    assert!(verify_log(&key, "~bus", "counter", "counter", None, &all).is_err());
    let mut other_key = key;
    other_key[0] ^= 1;
    assert!(verify_log(&other_key, "~zod", "counter", "counter", None, &all).is_err());
}

#[test]
fn verification_covers_the_link_to_the_previous_entry_and_the_exact_bytes() {
    use ed25519_dalek::{Signer, SigningKey};
    use ship_proto::Message;
    let (dir, out) = (TempDir::new("log-forge"), TempDir::new("log-forge-out"));
    let rt = boot(&dir, fast());
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let key = rt.public_key("~zod").unwrap();
    let all = rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap();
    let check = |entries: &[runtime::SignedEntry]| verify_log(&key, "~zod", "counter", "counter", None, entries);
    let (_, end_hash) = check(&all).unwrap().unwrap();

    // Sign new entries with the ship's real key, as someone holding an export could.
    rt.export_ship("~zod", &out.0).unwrap();
    let seed: [u8; 32] = fs::read(out.0.join("zod.key")).unwrap().try_into().unwrap();
    let signer = SigningKey::from_bytes(&seed);
    let fourth = |prev: Vec<u8>| {
        let body = runtime::EntryBody {
            ship: "zod".into(),
            agent: "counter".into(),
            log: "counter".into(),
            seq: 4,
            prev,
            payload: b"hits=4".to_vec(),
        }
        .encode_to_vec();
        // What is signed is a label for the kind of message, then the message.
        let signature = signer.sign(&[b"ship.v1.entry\n".as_slice(), &body].concat()).to_bytes().to_vec();
        runtime::SignedEntry { signature, body }
    };
    // Properly signed, properly numbered, and linked to the real third entry: accepted.
    let mut extended = all.clone();
    extended.push(fourth(end_hash.to_vec()));
    assert!(check(&extended).is_ok());
    // The same, but linked to something else: only the link check can catch this.
    *extended.last_mut().unwrap() = fourth(vec![9; 32]);
    assert!(check(&extended).is_err());

    // A field added to an entry after signing still decodes to the same content, so it is only
    // caught because the signature is checked against the bytes exactly as they arrive.
    let mut padded = all.clone();
    padded.last_mut().unwrap().body.extend([0x38, 0x01]);
    assert!(runtime::EntryBody::decode(&*padded.last().unwrap().body).is_ok());
    assert!(check(&padded).is_err());
}

#[test]
fn logs_followers_and_the_key_survive_export_and_import() {
    let (a, b, out) = (TempDir::new("log-export-a"), TempDir::new("log-export-b"), TempDir::new("log-export-out"));
    // Nothing queued is run after a delivery, so the follower is still behind at export time.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let key = rt.public_key("~zod").unwrap();
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(other.public_key("~zod").unwrap(), key);
    // The follower is prompted afresh and catches up.
    assert_eq!(read(&other, "tally", "tally", "seen"), "0");
    while other.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&other, "tally", "tally", "seen"), "3");

    // New entries carry on the same chain, under the same key.
    send(&other, "~zod", "counter", "log hits");
    let all = other.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap();
    assert_eq!(payloads(&all), ["hits=1", "hits=2", "hits=3", "hits=4"]);
    verify_log(&key, "~zod", "counter", "counter", None, &all).unwrap();
}

#[test]
fn import_refuses_logs_that_do_not_check_out() {
    let import = |label: &str, damage: &dyn Fn(&Path)| -> Result<(), Error> {
        let (a, b, out) = (
            TempDir::new(&format!("{label}-a")),
            TempDir::new(&format!("{label}-b")),
            TempDir::new(&format!("{label}-out")),
        );
        let rt = boot(&a, fast());
        for _ in 0..4 {
            send(&rt, "~zod", "counter", "log hits");
        }
        rt.export_ship("~zod", &out.0).unwrap();
        damage(&out.0);
        Runtime::open(&b.0, fast()).unwrap().import_ship(&out.0, "~zod")
    };
    let sql = |statement: &'static str| {
        move |out: &Path| rusqlite::Connection::open(out.join("zod.ship")).unwrap().execute_batch(statement).unwrap()
    };
    assert!(import("log-intact", &|_| {}).is_ok());
    // An entry removed from the middle, an entry altered, and a log that claims the wrong owner.
    assert!(matches!(import("log-gap", &sql("DELETE FROM log_entries WHERE seq = 2")), Err(Error::BadShipFile(_))));
    // The last byte of an entry is the last byte of its payload, so this changes the content
    // while leaving something that still decodes. Only the signature gives it away.
    let altered = "UPDATE log_entries SET body = CAST(substr(body, 1, length(body) - 1) || x'7a' AS BLOB) WHERE seq = 3";
    assert!(matches!(import("log-altered", &sql(altered)), Err(Error::BadShipFile(_))));
    let padded = "UPDATE log_entries SET body = CAST(body || x'3801' AS BLOB) WHERE seq = 4";
    assert!(matches!(import("log-padded", &sql(padded)), Err(Error::BadShipFile(_))));
    // The newest entry removed, and every entry removed: each run that is left is genuine, but
    // it does not reach where the log says it ends.
    assert!(matches!(import("log-cut", &sql("DELETE FROM log_entries WHERE seq = 4")), Err(Error::BadShipFile(_))));
    assert!(matches!(import("log-emptied", &sql("DELETE FROM log_entries")), Err(Error::BadShipFile(_))));
    assert!(matches!(import("log-renamed", &sql("UPDATE log_entries SET agent = 'other'")), Err(Error::BadShipFile(_))));
    // The right log with the wrong key, and no key at all.
    assert!(matches!(import("log-wrong-key", &|out| fs::write(out.join("zod.key"), [7u8; 32]).unwrap()), Err(Error::BadShipFile(_))));
    assert!(matches!(import("log-no-key", &|out| fs::remove_file(out.join("zod.key")).unwrap()), Err(Error::BadShipFile(_))));
}

#[test]
fn logs_are_bounded() {
    // The journal is a log whose entries no checkpoint can stand in for, so it can only fill.
    let dir = TempDir::new("log-quota");
    let rt = boot_with_journal(&dir, Config { max_log_bytes: 600, ..fast() });
    let mut accepted = 0;
    let refused = loop {
        assert!(accepted < 100, "the log never filled");
        match rt.deliver("~zod", "counter", b"journal a line") {
            Ok(_) => accepted += 1,
            Err(Error::Rejected(rejection)) => break rejection,
            Err(e) => panic!("unexpected error: {e}"),
        }
    };
    assert!(matches!(refused, Rejection::Limit(_)), "{refused:?}");
    assert!((1..10).contains(&accepted), "accepted {accepted}");
    // The refused append left nothing behind, and the count survives a sleep and wake.
    assert_eq!(rt.log_entries("~zod", "counter", "journal", 0, NO_LIMIT).unwrap().len(), accepted);
    rt.sleep_idle(Duration::ZERO);
    assert!(matches!(rejection(&rt, "counter", "journal a line"), Rejection::Limit(_)));
    assert_eq!(rt.log_entries("~zod", "counter", "journal", 0, NO_LIMIT).unwrap().len(), accepted);
}

#[test]
fn many_new_entries_queue_one_notification_not_many() {
    // Nothing queued runs after a delivery, so five appends pile up before the follower is run.
    let dir = TempDir::new("log-coalesce");
    let rt = boot_pair(&dir, Config { max_queued_per_deliver: 0, ..fast() }, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..5 {
        send(&rt, "~zod", "counter", "log hits");
    }
    // The follower takes three entries a round, so five entries need two rounds, not five.
    assert_eq!(rt.run_pending("~zod", 100).unwrap(), 2);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "5");
}

#[test]
fn a_follower_that_fails_is_tried_again_and_then_left_until_it_asks() {
    // A passing failure: by the time the notification is retried, the cause has gone. The
    // tolerate command is queued behind the notification, so the first try fails and the retry,
    // which goes to the back of the queue, succeeds. No new entry is needed.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("log-transient");
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log poison");
    send(&rt, "~zod", "tally", "later tolerate");
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");

    // A lasting failure: after a few tries the runtime stops, rather than retry for ever.
    let dir = TempDir::new("log-suspended");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log poison");
    assert_eq!(rt.run_pending("~zod", 100).unwrap(), 0);
    let failed = rt.audit("~zod", 100).unwrap().iter().filter(|entry| entry.agent == "tally" && !entry.ok).count();
    assert_eq!(failed, 3);
    // Fixing the cause does nothing by itself, but asking to follow again starts it off.
    send(&rt, "~zod", "tally", "tolerate");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "0");
    send(&rt, "~zod", "tally", "follow");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
}

#[test]
fn an_append_by_a_failed_event_leaves_nothing() {
    let dir = TempDir::new("log-rollback");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    assert!(matches!(rejection(&rt, "counter", "log-then-crash hits"), Rejection::Trap(_)));
    // No entry, no notification, no change to the counter, and no number used up.
    assert!(rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap().is_empty());
    assert_eq!(rt.log_head("~zod", "counter", "counter").unwrap(), None);
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 0);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "0");
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "1");
    assert_eq!(payloads(&rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap()), ["hits=1"]);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
}

#[test]
fn large_entries_reach_a_follower_whole() {
    // Three entries of 3,000 bytes are more than the follower's first buffer holds, so they are
    // collected in a second step. Its position must move only once it has them.
    // Nothing queued runs after a delivery, so all four are waiting when the follower first runs
    // and its first round really does take three at once.
    let dir = TempDir::new("log-large");
    let rt = boot_pair(&dir, Config { max_queued_per_deliver: 0, ..fast() }, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..4 {
        send(&rt, "~zod", "counter", "log-big 3000");
    }
    assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(3));
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&rt, "tally", "tally", "seen"), "4");
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(4));
    assert_eq!(rt.read("~zod", "tally", "tally", b"last").unwrap(), vec![b'x'; 3000]);
}

#[test]
fn a_follower_part_way_through_keeps_its_place() {
    let (a, b, out) = (TempDir::new("log-part-a"), TempDir::new("log-part-b"), TempDir::new("log-part-out"));
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..5 {
        send(&rt, "~zod", "counter", "log hits");
    }
    // One round takes three of the five.
    assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "3");
    // Its place survives the ship being closed and reopened, and a move to another runtime.
    rt.sleep_idle(Duration::ZERO);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "3");
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(read(&other, "tally", "tally", "seen"), "3");
    while other.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&other, "tally", "tally", "seen"), "5");
    assert_eq!(read(&other, "tally", "tally", "last"), "hits=5");
}

#[test]
fn the_kernel_decides_who_is_told_about_new_entries() {
    use ship_proto::{FollowRequest, Message};
    // This follower's notify handler only records that it was called. It never asks for the
    // entries, so the only thing that can stop it being called is the kernel's own check.
    let request = FollowRequest { agent: "counter".into(), log: "counter".into(), ship: String::new() }.encode_to_vec();
    let source = format!(
        r#"(module
            (import "host" "log_follow" (func $follow (param i32 i32)))
            (import "host" "kv_put" (func $put (param i32 i32 i32 i32)))
            (import "host" "kv_get" (func $get (param i32 i32 i32 i32) (result i64)))
            (memory (export "memory") 1)
            (data (i32.const 0) "{}")
            (data (i32.const 256) "p")
            (func (export "alloc") (param i32) (result i32) (i32.const 1024))
            (func (export "handle") (param i32 i32) (result i64)
                (call $follow (i32.const 0) (i32.const {}))
                (i64.const 0))
            (func (export "notify") (param i32 i32) (result i64)
                (call $put (i32.const 256) (i32.const 1) (i32.const 256) (i32.const 1))
                (i64.const 0))
            (func (export "read") (param i32 i32) (result i64)
                (if (result i64) (i64.eq (call $get (i32.const 256) (i32.const 1) (i32.const 512) (i32.const 8)) (i64.const 1))
                    (then (i64.const 2199023255553))
                    (else (i64.const 0)))))"#,
        request.iter().map(|b| format!("\\{b:02x}")).collect::<String>(),
        request.len(),
    );
    let may_read = |allowed| Manifest {
        provides: vec![],
        uses: if allowed { vec![Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false, ship: String::new() }] } else { vec![] },
    };
    for (label, still_allowed) in [("notify-allowed", true), ("notify-revoked", false)] {
        let dir = TempDir::new(label);
        let rt = boot(&dir, fast());
        let hash = rt.add_module(&wat::parse_str(&source).unwrap()).unwrap();
        rt.install("~zod", "watcher", &hash, &may_read(true)).unwrap();
        rt.deliver("~zod", "watcher", b"x").unwrap();
        // Replace its manifest before anything is published.
        rt.install("~zod", "watcher", &hash, &may_read(still_allowed)).unwrap();
        send(&rt, "~zod", "counter", "log hits");
        let told = !rt.read("~zod", "watcher", "", b"").unwrap().is_empty();
        assert_eq!(told, still_allowed, "{label}");
    }
}

#[test]
fn two_ships_with_the_same_name_cannot_be_mixed_up_on_import() {
    // Two different ships that happen to share a name, each with its own key and its own log.
    let (out_a, out_b, dest) = (TempDir::new("mix-out-a"), TempDir::new("mix-out-b"), TempDir::new("mix-dest"));
    for (label, out, entries) in [("mix-a", &out_a, 2), ("mix-b", &out_b, 5)] {
        let dir = TempDir::new(label);
        let rt = boot(&dir, fast());
        for _ in 0..entries {
            send(&rt, "~zod", "counter", "log hits");
        }
        rt.export_ship("~zod", &out.0).unwrap();
    }
    let rt = Runtime::open(&dest.0, fast()).unwrap();
    let won = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for attempt in 0..8 {
            let (rt, won) = (&rt, &won);
            let out = if attempt % 2 == 0 { &out_a } else { &out_b };
            scope.spawn(move || match rt.import_ship(&out.0, "~zod") {
                Ok(()) => drop(won.fetch_add(1, Ordering::SeqCst)),
                Err(Error::ShipExists(_)) => {}
                Err(e) => panic!("unexpected import error: {e}"),
            });
        }
    });
    assert_eq!(won.load(Ordering::SeqCst), 1);
    // Whichever ship won, its entries check out against the key that was installed with it,
    // and it can go on publishing under that key.
    send(&rt, "~zod", "counter", "log hits");
    let all = rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap();
    assert!(all.len() == 3 || all.len() == 6, "{}", all.len());
    verify_log(&rt.public_key("~zod").unwrap(), "~zod", "counter", "counter", None, &all).unwrap();
}

#[test]
fn an_exported_key_is_private_whatever_was_there_before() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, out) = (TempDir::new("key-perms"), TempDir::new("key-perms-out"));
    let rt = boot(&dir, fast());
    // Something already sits where the key will go, readable by everyone.
    let key_file = out.0.join("zod.key");
    fs::write(&key_file, b"old").unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
    rt.export_ship("~zod", &out.0).unwrap();
    assert_eq!(fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&key_file).unwrap().len(), 32);
    assert_eq!(fs::read_dir(&out.0).unwrap().count(), 3, "export left scratch files behind");
}

#[test]
fn a_new_entry_gives_a_stopped_follower_a_full_set_of_tries() {
    // Stop the follower with an entry it cannot handle.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("log-revive");
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log poison");
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&rt, "tally", "tally", "seen"), "0");

    // A new entry prompts it again. The fix is two steps behind that prompt in the queue, so
    // the first two tries fail and only the third can succeed. It gets a third only because the
    // new entry restored its full set of tries.
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "tally", "later later tolerate");
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(read(&rt, "tally", "tally", "seen"), "2");
}

#[test]
fn notifications_do_not_use_the_command_queues_room() {
    // No room at all for commands between agents. Followers are still told about new entries.
    let dir = TempDir::new("log-no-inbox");
    let rt = boot_pair(&dir, Config { max_inbox_bytes: 0, ..fast() }, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
    assert!(matches!(rejection(&rt, "tally", "poke hits"), Rejection::Limit(_)));

    // Room for exactly two queued pings (6 bytes plus 64 each), with a notification waiting too.
    let cfg = Config { max_inbox_bytes: 141, max_queued_per_deliver: 0, ..fast() };
    let dir = TempDir::new("log-inbox-room");
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "tally", "ping 0");
    assert_eq!(rt.pending("~zod").unwrap(), 2);
    // The count is worked out again when the ship is reopened. If it wrongly included the
    // waiting notification, this second ping would not fit.
    rt.sleep_idle(Duration::ZERO);
    send(&rt, "~zod", "tally", "ping 0");
    assert_eq!(rt.pending("~zod").unwrap(), 3);
    assert!(matches!(rejection(&rt, "tally", "later x"), Rejection::Limit(_)));
    // Running the notification frees no room, because it never took any.
    assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
    assert!(matches!(rejection(&rt, "tally", "later x"), Rejection::Limit(_)));
    // Running a ping frees its room, which the ping it sends then takes.
    assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
    assert_eq!(read(&rt, "tally", "tally", "pings"), "1");
    assert_eq!(rt.pending("~zod").unwrap(), 2);
}

#[test]
fn a_followers_place_moves_only_when_it_has_the_entries() {
    use ship_proto::{FollowRequest, Message, NextRequest};
    // This follower asks for entries with a buffer of no size at all, so they can never fit.
    // One version stops there; the other goes on to collect what it asked for.
    let follow = FollowRequest { agent: "counter".into(), log: "counter".into(), ship: String::new() }.encode_to_vec();
    let next = NextRequest { agent: "counter".into(), log: "counter".into(), max: 10, checkpoints: false, ship: String::new() }.encode_to_vec();
    let escaped = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let follower = |then: &str| {
        format!(
            r#"(module
                (import "host" "log_follow" (func $follow (param i32 i32)))
                (import "host" "log_next" (func $next (param i32 i32 i32 i32) (result i64)))
                (import "host" "take_reply" (func $take (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{}")
                (data (i32.const 256) "{}")
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "handle") (param i32 i32) (result i64)
                    (call $follow (i32.const 0) (i32.const {}))
                    (i64.const 0))
                (func (export "notify") (param i32 i32) (result i64)
                    (if (i64.le_s (call $next (i32.const 256) (i32.const {}) (i32.const 4096) (i32.const 0)) (i64.const 0))
                        (then unreachable))
                    {then}
                    (i64.const 0)))"#,
            escaped(&follow),
            escaped(&next),
            follow.len(),
            next.len(),
        )
    };
    let reads_counter = Manifest {
        provides: vec![],
        uses: vec![Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false, ship: String::new() }],
    };
    let collect = "(drop (call $take (i32.const 4096) (i32.const 60000)))";
    for (label, then, expected) in [("place-uncollected", "", 0), ("place-collected", collect, 4)] {
        let dir = TempDir::new(label);
        let rt = boot(&dir, fast());
        let hash = rt.add_module(&wat::parse_str(follower(then)).unwrap()).unwrap();
        rt.install("~zod", "lazy", &hash, &reads_counter).unwrap();
        rt.deliver("~zod", "lazy", b"x").unwrap();
        for _ in 0..4 {
            send(&rt, "~zod", "counter", "log hits");
        }
        // Whatever it did, the runtime stops prompting it: either it caught up, or it kept
        // finishing without taking anything.
        assert_eq!(rt.run_pending("~zod", 100).unwrap(), 0);
        assert_eq!(rt.log_position("~zod", "lazy", "counter", "counter").unwrap(), Some(expected), "{label}");
    }
}

#[test]
fn a_followers_own_handler_cannot_pile_up_notifications() {
    use ship_proto::{AppendRequest, FollowRequest, Message};
    // This agent follows its own log. When prompted it takes no entries; instead it either asks
    // to follow again or appends another entry. Both would queue a second prompt on top of the
    // one the runtime queues for a round that made no progress.
    let follow = FollowRequest { agent: "echo".into(), log: "e".into(), ship: String::new() }.encode_to_vec();
    let append = AppendRequest { log: "e".into(), payload: b"x".to_vec() }.encode_to_vec();
    let escaped = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let echo = |when_prompted: &str| {
        format!(
            r#"(module
                (import "host" "log_follow" (func $follow (param i32 i32)))
                (import "host" "log_append" (func $append (param i32 i32) (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{}")
                (data (i32.const 256) "{}")
                (func $refollow (call $follow (i32.const 0) (i32.const {})))
                (func $again (drop (call $append (i32.const 256) (i32.const {}))))
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "handle") (param i32 i32) (result i64)
                    (call $refollow)
                    (call $again)
                    (i64.const 0))
                (func (export "notify") (param i32 i32) (result i64)
                    (call {when_prompted})
                    (i64.const 0)))"#,
            escaped(&follow),
            escaped(&append),
            follow.len(),
            append.len(),
        )
    };
    let offers_e = Manifest { provides: vec![Provide { interface: "e".into(), public: false, remote: false }], uses: vec![] };
    for (label, when_prompted) in [("pile-refollow", "$refollow"), ("pile-append", "$again")] {
        let dir = TempDir::new(label);
        let rt = boot(&dir, Config { max_queued_per_deliver: 0, ..fast() });
        let hash = rt.add_module(&wat::parse_str(echo(when_prompted)).unwrap()).unwrap();
        rt.install("~zod", "echo", &hash, &offers_e).unwrap();
        rt.deliver("~zod", "echo", b"x").unwrap();
        assert_eq!(rt.pending("~zod").unwrap(), 1, "{label}");
        // However many rounds run, there is always exactly one prompt waiting: never two, and
        // never none, since this follower keeps asking for more.
        for round in 0..8 {
            assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1, "{label}: round {round}");
            assert_eq!(rt.pending("~zod").unwrap(), 1, "{label}: round {round}");
        }
    }

    // The same follower, except that after asking to follow again its handler fails. The
    // failure undoes that request along with everything else, so it is retried three times and
    // then left alone, with nothing waiting.
    let failing = echo("$refollow").replace("(call $refollow)\n                    (i64.const 0)))", "(call $refollow)\n                    unreachable))");
    assert!(failing.contains("unreachable"), "the failing variant was not built");
    let dir = TempDir::new("pile-trap");
    let rt = boot(&dir, Config { max_queued_per_deliver: 0, ..fast() });
    let hash = rt.add_module(&wat::parse_str(&failing).unwrap()).unwrap();
    rt.install("~zod", "echo", &hash, &offers_e).unwrap();
    rt.deliver("~zod", "echo", b"x").unwrap();
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    assert_eq!(rt.run_pending("~zod", 100).unwrap(), 3);
    assert_eq!(rt.pending("~zod").unwrap(), 0);
    let failed = rt.audit("~zod", 100).unwrap().iter().filter(|entry| entry.agent == "echo" && !entry.ok).count();
    assert_eq!(failed, 3);
}

#[test]
fn asking_a_log_for_no_entries_takes_none() {
    let dir = TempDir::new("log-none");
    let rt = boot_pair(&dir, Config { max_queued_per_deliver: 0, ..fast() }, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    assert_eq!(send(&rt, "~zod", "tally", "glance"), "0 false");
    send(&rt, "~zod", "counter", "log hits");
    // One entry is waiting. Asking for none returns none, says more remain, and moves nothing.
    assert_eq!(send(&rt, "~zod", "tally", "glance"), "0 true");
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(0));
    while rt.run_pending("~zod", 10).unwrap() > 0 {}
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(1));
}

/// Small enough that a checkpoint is asked for every few entries.
fn checkpointing() -> Config {
    Config { checkpoint_min_bytes: 500, ..fast() }
}

/// The counter agent offering both its state log and its journal, which is a history.
fn counter_with_journal() -> Manifest {
    let provide = |interface: &str| Provide { interface: interface.into(), public: false, remote: false };
    Manifest { provides: vec![provide("counter"), provide("journal")], uses: vec![] }
}

/// A runtime with one ship, `~zod`, running the counter agent with both of its logs.
fn boot_with_journal(dir: &TempDir, cfg: Config) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let hash = rt.add_module(&counter_wasm()).unwrap();
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "counter", &hash, &counter_with_journal()).unwrap();
    rt
}

/// Run everything queued on the ship. Bounded, so that a regression fails instead of hanging.
fn settle(rt: &Runtime) {
    for _ in 0..1000 {
        if rt.run_pending("~zod", 10).unwrap() == 0 {
            return;
        }
    }
    panic!("the ship's queue never emptied");
}

/// Sign a checkpoint the way the runtime does, with a ship's key read from `key_file`.
fn sign_checkpoint(key_file: &Path, body: &ship_proto::CheckpointBody) -> SignedCheckpoint {
    use ed25519_dalek::Signer;
    use ship_proto::Message;
    let key = ed25519_dalek::SigningKey::from_bytes(&fs::read(key_file).unwrap().try_into().unwrap());
    let body = body.encode_to_vec();
    let signature = key.sign(&[b"ship.v1.checkpoint\n".as_slice(), &body].concat()).to_bytes().to_vec();
    SignedCheckpoint { body, signature }
}

/// How many of the counter log's early entries have been dropped.
fn dropped(rt: &Runtime) -> u64 {
    match rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT) {
        Err(Error::LogTrimmed(base)) => base,
        Ok(_) => 0,
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// The counter log's checkpoint, checked: the entry it stands for, that entry's hash, the state.
fn checkpoint(rt: &Runtime) -> (u64, [u8; 32], String) {
    let key = rt.public_key("~zod").unwrap();
    let signed = rt.log_checkpoint("~zod", "counter", "counter").unwrap().expect("the log has a checkpoint");
    let ((seq, hash), state) = verify_checkpoint(&key, "~zod", "counter", "counter", &signed).unwrap();
    (seq, hash, String::from_utf8(state).unwrap())
}

/// How many times an event with exactly this payload is in the audit log, by outcome.
fn audited(rt: &Runtime, event: &[u8], ok: bool) -> usize {
    rt.audit("~zod", 10_000).unwrap().iter().filter(|entry| entry.event == event && entry.ok == ok).count()
}

#[test]
fn old_entries_are_dropped_once_a_checkpoint_can_stand_in_for_them() {
    let dir = TempDir::new("cp-trim");
    let rt = boot(&dir, checkpointing());
    for expected in 1..=20 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), expected.to_string());
    }
    // The log's start is gone, and a reader that asks for it is told so rather than being
    // handed entries with a gap before them.
    let base = dropped(&rt);
    assert!(base > 0, "nothing was dropped");
    assert!(matches!(rt.log_entries("~zod", "counter", "counter", base - 1, NO_LIMIT), Err(Error::LogTrimmed(b)) if b == base));

    // The checkpoint is the state as of one entry, newer than anything dropped.
    let key = rt.public_key("~zod").unwrap();
    let (seq, hash, state) = checkpoint(&rt);
    assert!(seq > base && seq <= 20, "checkpoint at {seq}, entries dropped up to {base}");
    assert_eq!(state, format!("hits={seq}"));

    // What is left runs from just after the dropped part to the same end as before.
    let kept = rt.log_entries("~zod", "counter", "counter", base, NO_LIMIT).unwrap();
    let expected: Vec<String> = (base + 1..=20).map(|n| format!("hits={n}")).collect();
    assert_eq!(payloads(&kept), expected);
    assert!(kept.len() < 10, "{} entries are still held", kept.len());

    // A reader carries on from the checkpoint, and the entries after it check out against it.
    let after = rt.log_entries("~zod", "counter", "counter", seq, NO_LIMIT).unwrap();
    let end = verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &after).unwrap();
    assert_eq!(end, rt.log_head("~zod", "counter", "counter").unwrap());
    assert_eq!(end.unwrap().0, 20);
    // A reader holding a wrong idea of the checkpointed entry is caught at the next one.
    assert!(!after.is_empty(), "the checkpoint is at the log's end, so this would show nothing");
    assert!(verify_log(&key, "~zod", "counter", "counter", Some((seq, [9; 32])), &after).is_err());

    // Numbering carries on across a sleep and wake.
    rt.sleep_idle(Duration::ZERO);
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "21");
    assert!(dropped(&rt) >= base);
    drop(rt);

    // The dropped entries are really gone from the file, not merely hidden.
    let file = rusqlite::Connection::open(dir.0.join("ships").join("zod.ship")).unwrap();
    let hidden: i64 = file
        .query_row(
            "SELECT COUNT(*) FROM log_entries e JOIN logs l ON l.agent = e.agent AND l.name = e.name WHERE e.seq <= l.base",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(hidden, 0);
}

#[test]
fn a_checkpoint_is_checked_like_an_entry() {
    let dir = TempDir::new("cp-verify");
    let rt = boot(&dir, checkpointing());
    for _ in 0..8 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let key = rt.public_key("~zod").unwrap();
    let signed = rt.log_checkpoint("~zod", "counter", "counter").unwrap().unwrap();
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &signed).is_ok());

    // The wrong key, the wrong log, the wrong ship.
    assert!(verify_checkpoint(&[7; 32], "~zod", "counter", "counter", &signed).is_err());
    assert!(verify_checkpoint(&key, "~zod", "counter", "journal", &signed).is_err());
    assert!(verify_checkpoint(&key, "~zod", "tally", "counter", &signed).is_err());
    assert!(verify_checkpoint(&key, "~nec", "counter", "counter", &signed).is_err());
    // The state changed, extra bytes added, and the signature changed.
    let mut altered = signed.clone();
    *altered.body.last_mut().unwrap() ^= 1;
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &altered).is_err());
    let mut padded = signed.clone();
    padded.body.extend_from_slice(&[0x38, 0x01]);
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &padded).is_err());
    let mut resigned = signed.clone();
    resigned.signature[0] ^= 1;
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &resigned).is_err());
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &SignedCheckpoint::default()).is_err());

    // Signed with the ship's own key, but naming no entry, or giving no usable hash for it.
    use ship_proto::Message;
    let key_file = dir.0.join("keys").join("zod.key");
    let genuine = ship_proto::CheckpointBody::decode(&*signed.body).unwrap();
    let resign = |body: &ship_proto::CheckpointBody| sign_checkpoint(&key_file, body);
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &resign(&genuine)).is_ok());
    let nowhere = ship_proto::CheckpointBody { seq: 0, ..genuine.clone() };
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &resign(&nowhere)).is_err());
    let unhashed = ship_proto::CheckpointBody { hash: vec![1; 5], ..genuine.clone() };
    assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &resign(&unhashed)).is_err());

    // A log with no checkpoint has none to give, and nor does a log that does not exist.
    let dir = TempDir::new("cp-none");
    let rt = boot(&dir, fast());
    send(&rt, "~zod", "counter", "log hits");
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    assert!(rt.log_checkpoint("~zod", "counter", "nothing").unwrap().is_none());
    assert_eq!(dropped(&rt), 0);
}

#[test]
fn a_follower_too_far_behind_is_handed_the_checkpoint() {
    // Nothing queued runs by itself, so the test decides when the follower gets its turn.
    let dir = TempDir::new("cp-follow");
    let cfg = Config { max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot_pair(&dir, cfg.clone(), counter_manifest(false), tally_manifest(true));
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
        settle(&rt);
    }
    let base = dropped(&rt);
    let (seq, _, state) = checkpoint(&rt);
    assert!(base > 0 && seq < 20, "dropped up to {base}, checkpoint at {seq}");

    send(&rt, "~zod", "tally", "follow");
    // Asking for nothing takes nothing, even from a log whose start is gone.
    assert_eq!(send(&rt, "~zod", "tally", "glance"), "0 true");
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(0));

    // Its first round cannot be given entry 1. It gets the state as of the checkpoint's entry,
    // and its place moves there in the same step.
    assert_eq!(rt.run_pending("~zod", 1).unwrap(), 1);
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "1");
    assert_eq!(read(&rt, "tally", "tally", "seen"), seq.to_string());
    assert_eq!(read(&rt, "tally", "tally", "last"), state);
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(seq));

    // From there it takes the remaining entries one by one, in order, as usual.
    settle(&rt);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "20");
    assert_eq!(read(&rt, "tally", "tally", "last"), "hits=20");
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "1");

    // A follower that keeps up never needs a checkpoint: it sees every entry.
    let dir = TempDir::new("cp-keeping-up");
    let rt = boot_pair(&dir, checkpointing(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
    }
    assert!(dropped(&rt) > 0);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "20");
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "0");
}

#[test]
fn a_history_log_is_kept_whole_and_asked_about_once() {
    let (dir, b, out) = (TempDir::new("cp-history"), TempDir::new("cp-history-b"), TempDir::new("cp-history-out"));
    let rt = boot_with_journal(&dir, checkpointing());
    for n in 1..=20 {
        assert_eq!(send(&rt, "~zod", "counter", &format!("journal line {n}")), n.to_string());
    }
    // The agent said this log has no state that could stand in for its entries.
    assert_eq!(rt.log_entries("~zod", "counter", "journal", 0, NO_LIMIT).unwrap().len(), 20);
    assert!(rt.log_checkpoint("~zod", "counter", "journal").unwrap().is_none());
    // A checkpoint request is recorded with the log's name as its event. One was enough.
    assert_eq!((audited(&rt, b"journal", true), audited(&rt, b"journal", false)), (1, 0));

    // Its other log, on the same ship, is still trimmed.
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
    }
    assert!(dropped(&rt) > 0);
    assert_eq!(rt.log_entries("~zod", "counter", "journal", 0, NO_LIMIT).unwrap().len(), 20);

    // The agent's answer goes with the ship: an imported copy does not ask again either.
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&b.0, checkpointing()).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    for n in 21..=40 {
        assert_eq!(send(&other, "~zod", "counter", &format!("journal line {n}")), n.to_string());
    }
    assert_eq!(other.log_entries("~zod", "counter", "journal", 0, NO_LIMIT).unwrap().len(), 40);
    assert_eq!((audited(&other, b"journal", true), audited(&other, b"journal", false)), (1, 0));
}

#[test]
fn a_checkpoint_that_cannot_be_taken_leaves_the_log_whole() {
    let dir = TempDir::new("cp-failing");
    let cfg = Config { max_queued_per_deliver: 0, max_checkpoint_bytes: 1000, ..checkpointing() };
    let rt = boot(&dir, cfg);
    let settle = || settle(&rt);

    // A handler that fails: every entry is still there, and no checkpoint exists.
    send(&rt, "~zod", "counter", "checkpoints broken");
    for _ in 0..10 {
        send(&rt, "~zod", "counter", "log hits");
        settle();
    }
    assert!(audited(&rt, b"counter", false) >= 2, "the failed requests are on record");
    assert_eq!(audited(&rt, b"counter", true), 0);
    assert_eq!(dropped(&rt), 0);
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());

    // A handler that tries to change something while describing its state is refused.
    send(&rt, "~zod", "counter", "checkpoints meddling");
    send(&rt, "~zod", "counter", "log hits");
    settle();
    // Had the write been allowed, the request would have succeeded and left a checkpoint.
    assert_eq!(audited(&rt, b"counter", true), 0);
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());

    // A state just larger than a checkpoint may carry. The request is queued by the append,
    // and the state grows before the request runs.
    send(&rt, "~zod", "counter", "checkpoints fine");
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "counter", "state 1005");
    settle();
    assert_eq!(audited(&rt, b"counter", true), 0);
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    assert_eq!(rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap().len(), 12);

    // None of that stops a later request from working.
    send(&rt, "~zod", "counter", "log hits");
    settle();
    assert_eq!(checkpoint(&rt), (13, rt.log_head("~zod", "counter", "counter").unwrap().unwrap().1, "hits=13".into()));
    assert_eq!(audited(&rt, b"counter", true), 1);
}

#[test]
fn a_log_with_checkpoints_does_not_fill_up() {
    let dir = TempDir::new("cp-quota");
    let rt = boot_with_journal(&dir, Config { max_log_bytes: 4000, ..checkpointing() });

    // Without checkpoints about twenty of these entries would fit.
    for expected in 1..=200 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), expected.to_string());
    }
    // A log that is never trimmed does fill, and what it is recorded as holding survives a
    // sleep and wake: it takes not one entry more afterwards.
    let fill = |rt: &Runtime| {
        let mut accepted = 0;
        while accepted < 100 && rt.deliver("~zod", "counter", b"journal a line of history").is_ok() {
            accepted += 1;
        }
        accepted
    };
    let accepted = fill(&rt);
    assert!((5..30).contains(&accepted), "the journal took {accepted} entries");
    settle(&rt);
    rt.sleep_idle(Duration::ZERO);
    assert_eq!(fill(&rt), 0);
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "201");
    drop(rt);

    // What each log is recorded as holding is exactly the entries that are there, and within
    // the limit. Checkpoints are not counted as entries.
    let file = rusqlite::Connection::open(dir.0.join("ships").join("zod.ship")).unwrap();
    let total = |sql: &str| file.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
    let wrong = total(
        "SELECT COUNT(*) FROM logs l WHERE l.bytes !=
           (SELECT COALESCE(SUM(LENGTH(body) + 128), 0) FROM log_entries e WHERE e.agent = l.agent AND e.name = l.name)",
    );
    assert_eq!((wrong, total("SELECT COUNT(*) FROM logs")), (0, 2));
    assert!(total("SELECT MAX(bytes) FROM logs") <= 4000);
    assert_eq!(total("SELECT COUNT(*) FROM checkpoints"), 1);
    assert_eq!(total("SELECT COUNT(*) FROM inbox"), 0);
}

#[test]
fn a_trimmed_log_survives_export_and_import() {
    let (a, b, out) = (TempDir::new("cp-export-a"), TempDir::new("cp-export-b"), TempDir::new("cp-export-out"));
    let cfg = Config { max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
        settle(&rt);
    }
    // A follower that has not had a turn yet, so it is behind the dropped part at export time.
    send(&rt, "~zod", "tally", "follow");
    let (key, base, taken) = (rt.public_key("~zod").unwrap(), dropped(&rt), checkpoint(&rt));
    let signed = rt.log_checkpoint("~zod", "counter", "counter").unwrap();
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(dropped(&other), base);
    assert_eq!(other.log_checkpoint("~zod", "counter", "counter").unwrap(), signed);
    assert_eq!(other.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 20);

    // The follower is prompted afresh, takes the checkpoint, and catches up.
    settle(&other);
    assert_eq!(read(&other, "tally", "tally", "seen"), "20");
    assert_eq!(read(&other, "tally", "tally", "jumps"), "1");

    // Trimming picks up exactly where it left off: the copy takes its next checkpoint after the
    // same number of new entries as the original does.
    assert!(taken.0 < 20, "the log had nothing since its checkpoint, so this would show nothing");
    let until_next_checkpoint = |rt: &Runtime| {
        let (before, mut added) = (checkpoint(rt).0, 0);
        while checkpoint(rt).0 == before {
            assert!(added < 20, "no further checkpoint was taken");
            send(rt, "~zod", "counter", "log hits");
            settle(&rt);
            added += 1;
        }
        added
    };
    let added = until_next_checkpoint(&other);
    assert_eq!(added, until_next_checkpoint(&rt));

    // The log carries on: same numbering, same chain.
    for _ in 0..10 {
        send(&other, "~zod", "counter", "log hits");
        settle(&other);
    }
    let head = 20 + added + 10;
    assert!(dropped(&other) > base);
    let (seq, hash, state) = checkpoint(&other);
    assert!(seq > taken.0 && state == format!("hits={seq}"), "checkpoint at {seq} says {state}");
    let rest = other.log_entries("~zod", "counter", "counter", seq, NO_LIMIT).unwrap();
    let end = verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &rest).unwrap();
    assert_eq!(end.unwrap().0, head);
    assert_eq!(read(&other, "tally", "tally", "seen"), head.to_string());
}

#[test]
fn import_refuses_a_trimmed_log_that_does_not_check_out() {
    // Export a ship whose counter log has been trimmed, damage the export, and import it.
    let import = |label: &str, damage: &dyn Fn(&Path)| -> Result<(), Error> {
        let (a, b, out, early) = (
            TempDir::new(&format!("{label}-a")),
            TempDir::new(&format!("{label}-b")),
            TempDir::new(&format!("{label}-out")),
            TempDir::new(&format!("{label}-early")),
        );
        let rt = boot(&a, checkpointing());
        for _ in 0..8 {
            send(&rt, "~zod", "counter", "log hits");
        }
        // An earlier export of the same ship, kept beside the later one as `early.ship`.
        rt.export_ship("~zod", &early.0).unwrap();
        for _ in 0..12 {
            send(&rt, "~zod", "counter", "log hits");
        }
        rt.export_ship("~zod", &out.0).unwrap();
        fs::copy(early.0.join("zod.ship"), out.0.join("early.ship")).unwrap();
        damage(&out.0);
        fs::remove_file(out.0.join("early.ship")).unwrap();
        Runtime::open(&b.0, checkpointing()).unwrap().import_ship(&out.0, "~zod")
    };
    let sql = |statement: &'static str| {
        move |out: &Path| {
            let file = rusqlite::Connection::open(out.join("zod.ship")).unwrap();
            file.execute("ATTACH ?1 AS early", [out.join("early.ship").to_str().unwrap()]).unwrap();
            file.execute_batch(statement).unwrap();
        }
    };
    let refused = |label: &str, statement: &'static str| {
        let result = import(label, &sql(statement));
        assert!(matches!(result, Err(Error::BadShipFile(_))), "{label}: {result:?}");
    };
    assert!(import("cp-intact", &|_| {}).is_ok());

    // The checkpoint removed: entries are missing with nothing to stand in for them.
    refused("cp-removed", "DELETE FROM checkpoints");
    // Its state altered. The last byte of the body is the last byte of the state.
    refused("cp-altered", "UPDATE checkpoints SET body = CAST(substr(body, 1, length(body) - 1) || x'7a' AS BLOB)");
    // Filed under a different entry than the one it was signed for.
    refused("cp-moved", "UPDATE checkpoints SET seq = seq - 1");
    // A genuine but older checkpoint of the same log put in its place. It stands for an entry
    // that has since been dropped, so it cannot be tied to what is left.
    refused("cp-stale", "DELETE FROM checkpoints; INSERT INTO checkpoints SELECT * FROM early.checkpoints");
    // More dropped than the log admits to, less than it admits to, and more than the
    // checkpoint covers.
    refused("cp-short", "DELETE FROM log_entries WHERE seq = (SELECT MIN(seq) FROM log_entries)");
    refused("cp-base", "UPDATE logs SET base = base - 1");
    refused(
        "cp-past",
        "UPDATE logs SET base = (SELECT seq + 1 FROM checkpoints);
         DELETE FROM log_entries WHERE seq <= (SELECT seq + 1 FROM checkpoints)",
    );
    // Everything the checkpoint covers dropped, and no more, is a state a ship gets into by
    // itself when it is short of room. The entries left link straight back to the checkpoint.
    let tight = import(
        "cp-all",
        &sql("UPDATE logs SET base = (SELECT seq FROM checkpoints);
              DELETE FROM log_entries WHERE seq <= (SELECT seq FROM checkpoints)"),
    );
    assert!(tight.is_ok(), "{tight:?}");
    // The same, with a checkpoint that is signed but gives its entry the wrong hash. The entry
    // itself is gone, so what shows it is the next entry's link back.
    let unlinked = import("cp-all-forged", &|out| {
        use ship_proto::Message;
        let file = rusqlite::Connection::open(out.join("zod.ship")).unwrap();
        let body: Vec<u8> = file.query_row("SELECT body FROM checkpoints", [], |row| row.get(0)).unwrap();
        let wrong = ship_proto::CheckpointBody { hash: vec![9; 32], ..ship_proto::CheckpointBody::decode(&*body).unwrap() };
        let signed = sign_checkpoint(&out.join("zod.key"), &wrong);
        file.execute("UPDATE checkpoints SET body = ?1, signature = ?2", rusqlite::params![signed.body, signed.signature]).unwrap();
        file.execute_batch(
            "UPDATE logs SET base = (SELECT seq FROM checkpoints);
             DELETE FROM log_entries WHERE seq <= (SELECT seq FROM checkpoints)",
        )
        .unwrap();
    });
    assert!(matches!(unlinked, Err(Error::BadShipFile(_))), "{unlinked:?}");
    // Every entry dropped. A log may hold none, but only when its checkpoint stands for its
    // newest entry, which this one does not.
    refused("cp-empty", "DELETE FROM log_entries");
    refused("cp-emptied", "UPDATE logs SET base = head; DELETE FROM log_entries");
    // A checkpoint that really is signed by the ship, for the right entry, but giving that
    // entry a hash it does not have. Only comparing it with the entry itself shows this.
    let forged = import("cp-forged", &|out| {
        use ship_proto::Message;
        let file = rusqlite::Connection::open(out.join("zod.ship")).unwrap();
        let body: Vec<u8> = file.query_row("SELECT body FROM checkpoints", [], |row| row.get(0)).unwrap();
        let wrong = ship_proto::CheckpointBody { hash: vec![9; 32], ..ship_proto::CheckpointBody::decode(&*body).unwrap() };
        let signed = sign_checkpoint(&out.join("zod.key"), &wrong);
        file.execute("UPDATE checkpoints SET body = ?1, signature = ?2", rusqlite::params![signed.body, signed.signature]).unwrap();
    });
    assert!(matches!(forged, Err(Error::BadShipFile(_))), "{forged:?}");
    // The newest entries removed.
    refused("cp-cut", "DELETE FROM log_entries WHERE seq > (SELECT seq FROM checkpoints)");
    // Flags that are not flags.
    refused("cp-flag", "UPDATE logs SET history = 2");
}

#[test]
fn a_signature_for_one_kind_of_message_does_not_pass_for_another() {
    let dir = TempDir::new("cp-kinds");
    let rt = boot(&dir, checkpointing());
    for _ in 0..8 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let key = rt.public_key("~zod").unwrap();
    let entries = rt.log_entries("~zod", "counter", "counter", dropped(&rt), NO_LIMIT).unwrap();
    assert!(entries.len() >= 2);

    // An entry and a checkpoint are laid out alike: an entry's link to the one before sits
    // where a checkpoint keeps its hash, and its payload where a checkpoint keeps its state.
    // So a genuine entry, handed over as a checkpoint, decodes perfectly well.
    for entry in &entries {
        let posing = SignedCheckpoint { body: entry.body.clone(), signature: entry.signature.clone() };
        assert!(verify_checkpoint(&key, "~zod", "counter", "counter", &posing).is_err());
    }
    // And the reverse: the checkpoint handed over as the entry after a position made to fit it.
    use ship_proto::Message;
    let signed = rt.log_checkpoint("~zod", "counter", "counter").unwrap().unwrap();
    let stated = ship_proto::CheckpointBody::decode(&*signed.body).unwrap();
    let before = (stated.seq - 1, <[u8; 32]>::try_from(stated.hash).unwrap());
    let posing = runtime::SignedEntry { body: signed.body, signature: signed.signature };
    assert!(verify_log(&key, "~zod", "counter", "counter", Some(before), &[posing]).is_err());
}

#[test]
fn a_follower_that_cannot_take_a_checkpoint_is_not_moved_past_one() {
    let dir = TempDir::new("cp-old");
    let cfg = Config { max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
        settle(&rt);
    }
    assert!(dropped(&rt) > 0);

    // A follower built before checkpoints existed would not notice one in a reply. Rather than
    // move it past entries it never saw, its rounds fail and its place stays where it was.
    send(&rt, "~zod", "tally", "old");
    send(&rt, "~zod", "tally", "follow");
    settle(&rt);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "0");
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(0));
    assert!(audited(&rt, b"", false) >= 1, "the failed rounds are on record");

    // Once it can take a checkpoint, asking to follow again starts it off and it catches up.
    send(&rt, "~zod", "tally", "modern");
    send(&rt, "~zod", "tally", "follow");
    settle(&rt);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "20");
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "1");

    // Such a follower is fine for as long as it keeps up.
    let dir = TempDir::new("cp-old-keeping-up");
    let rt = boot_pair(&dir, checkpointing(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "old");
    send(&rt, "~zod", "tally", "follow");
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
    }
    assert!(dropped(&rt) > 0);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "20");
}

#[test]
fn a_tight_log_limit_cannot_wedge_a_checkpointed_log() {
    // Three entries fit. A checkpoint by itself drops nothing the first time, so without more
    // help no entry could ever be added again, and with no new entry no checkpoint would ever
    // be asked for.
    let dir = TempDir::new("cp-tight");
    // The usual threshold for a checkpoint is far above what this log may hold, so one is only
    // ever asked for because room is short.
    let rt = boot_pair(&dir, Config { max_log_bytes: 600, ..fast() }, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "follow");
    for expected in 1..=60 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), expected.to_string());
    }
    // A follower that keeps up is, again and again, exactly at the point up to which entries
    // have just been dropped. It still gets every entry, and never needs a checkpoint.
    assert!(dropped(&rt) > 50);
    assert_eq!(read(&rt, "tally", "tally", "seen"), "60");
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "0");
    rt.sleep_idle(Duration::ZERO);
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "61");
    let cfg = Config { max_log_bytes: 600, ..checkpointing() };
    // A reader can still get from the checkpoint to the log's end.
    let key = rt.public_key("~zod").unwrap();
    let (seq, hash, state) = checkpoint(&rt);
    assert_eq!(state, format!("hits={seq}"));
    let rest = rt.log_entries("~zod", "counter", "counter", seq, NO_LIMIT).unwrap();
    let end = verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &rest).unwrap();
    assert_eq!(end.unwrap().0, 61);

    // A log that filled up while no checkpoint could be taken recovers once one can.
    let dir = TempDir::new("cp-recover");
    let rt = boot(&dir, Config { max_queued_per_deliver: 0, ..cfg });
    send(&rt, "~zod", "counter", "checkpoints broken");
    let mut accepted = 0;
    while accepted < 10 && rt.deliver("~zod", "counter", b"log hits").is_ok() {
        accepted += 1;
        settle(&rt);
    }
    assert!((1..10).contains(&accepted), "accepted {accepted}");
    settle(&rt);
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    send(&rt, "~zod", "counter", "checkpoints fine");
    assert_eq!(rt.pending("~zod").unwrap(), 0);
    // The append is still refused, but being refused is what asks for the checkpoint that
    // makes room for the next one.
    assert!(matches!(rejection(&rt, "counter", "log hits"), Rejection::Limit(_)));
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    settle(&rt);
    for n in 1..=20 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), (accepted + n).to_string());
        settle(&rt);
    }

    // Nobody has to run the queue by hand for that. An entry too big for the room that is
    // left is refused, and simply trying again works, because the refused call also ran the
    // checkpoint request it gave rise to.
    let dir = TempDir::new("cp-retry");
    let rt = boot(&dir, Config { max_log_bytes: 600, ..checkpointing() });
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "counter", "log hits");
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    assert!(matches!(rejection(&rt, "counter", "log-big 150"), Rejection::Limit(_)));
    assert_eq!(send(&rt, "~zod", "counter", "log-big 150"), "3");
}

#[test]
fn a_checkpoint_request_for_a_module_that_cannot_answer_is_dropped() {
    let dir = TempDir::new("cp-replaced");
    let rt = boot(&dir, Config { max_queued_per_deliver: 0, ..checkpointing() });
    for _ in 0..4 {
        send(&rt, "~zod", "counter", "log hits");
    }
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    // The agent is replaced, before the request runs, by a module with no checkpoint handler.
    let tally = rt.add_module(&wasm("tally")).unwrap();
    rt.install("~zod", "counter", &tally, &counter_manifest(false)).unwrap();
    settle(&rt);
    // The request is done with, without anything having failed, and the log is whole.
    assert_eq!((audited(&rt, b"counter", true), audited(&rt, b"counter", false)), (1, 0));
    assert!(rt.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    assert_eq!(rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap().len(), 4);

    // Nothing was left behind by that: with a module that can answer back in place, the next
    // entry asks again and the checkpoint is taken.
    let counter = rt.add_module(&counter_wasm()).unwrap();
    rt.install("~zod", "counter", &counter, &counter_manifest(false)).unwrap();
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "5");
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    settle(&rt);
    assert_eq!(checkpoint(&rt).0, 5);
}

#[test]
fn a_waiting_checkpoint_request_survives_export_and_import() {
    let (a, b, out) = (TempDir::new("cp-due-a"), TempDir::new("cp-due-b"), TempDir::new("cp-due-out"));
    let cfg = Config { max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot(&a, cfg.clone());
    // Enough entries for a checkpoint to be asked for, and the request left waiting.
    for _ in 0..4 {
        send(&rt, "~zod", "counter", "log hits");
    }
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    rt.export_ship("~zod", &out.0).unwrap();

    // The request goes with the ship, like anything else that is waiting.
    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert!(other.log_checkpoint("~zod", "counter", "counter").unwrap().is_none());
    assert_eq!(other.pending("~zod").unwrap(), 1);
    // And the copy knows it is waiting: another entry does not ask a second time.
    send(&other, "~zod", "counter", "log hits");
    assert_eq!(other.pending("~zod").unwrap(), 1);
    settle(&other);
    assert_eq!(checkpoint(&other), (5, other.log_head("~zod", "counter", "counter").unwrap().unwrap().1, "hits=5".into()));

    // The same for a request made because room was short, well before the usual threshold: one
    // entry that takes more than half of what the log may hold.
    let (a, b, out) = (TempDir::new("cp-short-a"), TempDir::new("cp-short-b"), TempDir::new("cp-short-out"));
    let cfg = Config { max_log_bytes: 600, max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot(&a, cfg.clone());
    send(&rt, "~zod", "counter", "log-big 150");
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(other.pending("~zod").unwrap(), 1);
    settle(&other);
    assert_eq!(send(&other, "~zod", "counter", "log-big 150"), "2");
}

#[test]
fn a_ship_has_a_bounded_number_of_logs() {
    let dir = TempDir::new("cp-count");
    let rt = boot_with_journal(&dir, Config { max_logs: 1, ..fast() });
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "1");
    assert!(matches!(rejection(&rt, "counter", "journal a second log"), Rejection::Limit(_)));
    // The log that exists carries on.
    assert_eq!(send(&rt, "~zod", "counter", "log hits"), "2");

    // A file with more logs than a runtime allows is turned away on import.
    let (a, b, out) = (TempDir::new("cp-count-a"), TempDir::new("cp-count-b"), TempDir::new("cp-count-out"));
    let rt = boot_with_journal(&a, fast());
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "counter", "journal a second log");
    rt.export_ship("~zod", &out.0).unwrap();
    let strict = Runtime::open(&b.0, Config { max_logs: 1, ..fast() }).unwrap();
    assert!(matches!(strict.import_ship(&out.0, "~zod"), Err(Error::BadShipFile(_))));
}

#[test]
fn a_large_checkpoint_at_the_logs_end_reaches_a_follower_whole() {
    let dir = TempDir::new("cp-large");
    let cfg = Config { max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    // Each checkpoint's state is some ten thousand bytes, more than the first buffer a
    // follower offers. Stop at the moment a checkpoint has just dropped the log's start.
    send(&rt, "~zod", "counter", "checkpoints padded");
    let mut head = 0;
    while dropped(&rt) == 0 {
        assert!(head < 400, "nothing was ever dropped");
        send(&rt, "~zod", "counter", "log hits");
        settle(&rt);
        head += 1;
    }
    let (seq, _, state) = checkpoint(&rt);
    assert_eq!(seq, head, "the checkpoint is not at the log's end");
    assert_eq!(state.len(), format!("hits={head}").len() + 10_000);

    // One round takes the whole state and leaves the follower with nothing more to do.
    send(&rt, "~zod", "tally", "follow");
    assert_eq!(rt.run_pending("~zod", 10).unwrap(), 1);
    assert_eq!(read(&rt, "tally", "tally", "jumps"), "1");
    assert_eq!(read(&rt, "tally", "tally", "seen"), head.to_string());
    assert_eq!(read(&rt, "tally", "tally", "last"), state);
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(head));
    assert_eq!(rt.pending("~zod").unwrap(), 0);
}

#[test]
fn a_large_checkpoint_does_not_take_room_from_entries() {
    let dir = TempDir::new("cp-roomy");
    let rt = boot(&dir, Config { max_log_bytes: 1000, ..checkpointing() });
    send(&rt, "~zod", "counter", "checkpoints padded");
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }
    // The checkpoint is ten times what the log may hold in entries, and is not counted as any.
    assert!(checkpoint(&rt).2.len() > 10_000);
    // The next entry does not fit beside the three that are there. They are covered by the
    // checkpoint, so they go, and it does fit.
    assert_eq!(send(&rt, "~zod", "counter", "log-big 400"), "4");
    // That entry left too little room for another like it, so a checkpoint was asked for at
    // once. It covers everything, so an entry that needs nearly the whole log goes straight in.
    assert_eq!(checkpoint(&rt).0, 4);
    assert_eq!(send(&rt, "~zod", "counter", "log-big 800"), "5");
    // An entry that could never fit is refused however often it is tried.
    for _ in 0..3 {
        assert!(matches!(rejection(&rt, "counter", "log-big 1000"), Rejection::Limit(_)));
    }
    assert_eq!(rt.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 5);

    // Nor does refusing it ask for a checkpoint, which could not help.
    let dir = TempDir::new("cp-oversized");
    let rt = boot(&dir, Config { max_log_bytes: 1000, max_queued_per_deliver: 0, ..fast() });
    send(&rt, "~zod", "counter", "log hits");
    assert!(matches!(rejection(&rt, "counter", "log-big 1000"), Rejection::Limit(_)));
    assert_eq!(rt.pending("~zod").unwrap(), 0);
}

#[test]
fn one_full_log_takes_no_room_from_another() {
    let dir = TempDir::new("cp-separate");
    let rt = boot_with_journal(&dir, Config { max_log_bytes: 600, ..fast() });
    let mut accepted = 0;
    while accepted < 100 && rt.deliver("~zod", "counter", b"journal a line").is_ok() {
        accepted += 1;
    }
    assert!((1..10).contains(&accepted), "accepted {accepted}");
    // The journal is full for good. The agent's other log is untouched by that.
    for expected in 1..=10 {
        assert_eq!(send(&rt, "~zod", "counter", "log hits"), expected.to_string());
    }
    assert!(matches!(rejection(&rt, "counter", "journal a line"), Rejection::Limit(_)));
}

#[test]
fn import_keeps_the_queue_in_its_order() {
    let (a, b, out) = (TempDir::new("cp-order-a"), TempDir::new("cp-order-b"), TempDir::new("cp-order-out"));
    let cfg = Config { checkpoint_min_bytes: 0, max_log_bytes: 1000, max_queued_per_deliver: 0, ..fast() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "log hits");
    settle(&rt);
    assert_eq!(checkpoint(&rt).0, 1);
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }
    // Waiting, in this order: a checkpoint request, then a command that appends an entry too
    // big to fit unless that checkpoint has been taken first.
    send(&rt, "~zod", "tally", "forward log-big 600");
    assert_eq!(rt.pending("~zod").unwrap(), 2);
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(other.pending("~zod").unwrap(), 2);
    // A queued command that is refused is dropped for good, so the order matters. The copy
    // ends up exactly where the original does.
    for ship in [&rt, &other] {
        settle(ship);
        assert_eq!(ship.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 5);
    }

    // A checkpoint request between two commands. The first command's entry is covered by the
    // checkpoint only because the request runs after it, and the second only fits because the
    // first's entry is covered. Moving the request either way would lose the second command.
    let (a, b, out) = (TempDir::new("cp-between-a"), TempDir::new("cp-between-b"), TempDir::new("cp-between-out"));
    let cfg = Config { checkpoint_min_bytes: 0, max_log_bytes: 1000, max_queued_per_deliver: 0, ..fast() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "log hits");
    settle(&rt);
    send(&rt, "~zod", "tally", "forward log-big 150");
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }
    send(&rt, "~zod", "tally", "forward log-big 600");
    assert_eq!(rt.pending("~zod").unwrap(), 3);
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    for ship in [&rt, &other] {
        settle(ship);
        assert_eq!(ship.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 6);
    }

    // A request that exists only because an entry was refused for lack of room. Nothing about
    // the log itself says one is wanted, so it has to be carried over, not worked out.
    let (a, b, out) = (TempDir::new("cp-refused-a"), TempDir::new("cp-refused-b"), TempDir::new("cp-refused-out"));
    let cfg = Config { max_log_bytes: 600, max_queued_per_deliver: 0, ..checkpointing() };
    let rt = boot_pair(&a, cfg.clone(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "log hits");
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(rt.pending("~zod").unwrap(), 0);
    assert!(matches!(rejection(&rt, "counter", "log-big 150"), Rejection::Limit(_)));
    send(&rt, "~zod", "tally", "forward log-big 150");
    assert_eq!(rt.pending("~zod").unwrap(), 2);
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&b.0, cfg).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    for ship in [&rt, &other] {
        settle(ship);
        assert_eq!(ship.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 3);
    }
}

#[test]
fn a_checkpoint_is_asked_for_only_once_new_entries_outweigh_the_last_one() {
    let dir = TempDir::new("cp-threshold");
    let rt = boot(&dir, Config { checkpoint_min_bytes: 0, max_queued_per_deliver: 0, ..fast() });
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(rt.pending("~zod").unwrap(), 1);
    settle(&rt);
    assert_eq!(checkpoint(&rt).0, 1);
    // One more entry counts for exactly what that checkpoint does, which is not more than it.
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(rt.pending("~zod").unwrap(), 0);
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(rt.pending("~zod").unwrap(), 1);
}

#[test]
fn a_rejected_command_still_lets_queued_events_run() {
    // One queued event runs after each delivery. The tally agent keeps one waiting.
    let dir = TempDir::new("deliver-rejected");
    let cfg = Config { max_queued_per_deliver: 1, ..fast() };
    let rt = boot_pair(&dir, cfg, counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "tally", "ping 1");
    assert_eq!(read(&rt, "tally", "tally", "pings"), "2");
    // The rejected command changed nothing itself, but the call it came in on did run the
    // event that was waiting. A rejection says the command did nothing, not that nothing ran.
    assert!(matches!(rejection(&rt, "counter", "crash hits"), Rejection::Trap(_)));
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "0");
    assert_eq!(read(&rt, "tally", "tally", "pings"), "4");
}

#[test]
fn import_refuses_queued_events_the_ship_would_not_have_made() {
    // A ship with one log, one follower that is up to date, and nothing waiting.
    let import = |label: &str, statement: &str| -> (Result<(), Error>, Runtime, TempDir) {
        let (a, b, out) = (
            TempDir::new(&format!("{label}-a")),
            TempDir::new(&format!("{label}-b")),
            TempDir::new(&format!("{label}-out")),
        );
        let rt = boot_pair(&a, fast(), counter_manifest(false), tally_manifest(true));
        send(&rt, "~zod", "tally", "follow");
        for _ in 0..3 {
            send(&rt, "~zod", "counter", "log hits");
        }
        assert_eq!(rt.pending("~zod").unwrap(), 0);
        rt.export_ship("~zod", &out.0).unwrap();
        rusqlite::Connection::open(out.0.join("zod.ship")).unwrap().execute_batch(statement).unwrap();
        let other = Runtime::open(&b.0, Config { max_queued_per_deliver: 0, ..fast() }).unwrap();
        (other.import_ship(&out.0, "~zod"), other, b)
    };
    let queue = |rows: &str| format!("INSERT INTO inbox (kind, source, agent, interface, payload) VALUES {rows}");
    let refused = |label: &str, rows: &str| {
        let (result, _, _) = import(label, &queue(rows));
        assert!(matches!(result, Err(Error::BadShipFile(_))), "{label}: {result:?}");
    };
    // A checkpoint request for a log that does not exist, one that does not come from the
    // log's own publisher, and two for the same log.
    refused("q-no-log", "(4, 'counter', 'counter', 'nothing', x'')");
    refused("q-not-own", "(4, 'tally', 'counter', 'counter', x'')");
    refused("q-twice", "(4, 'counter', 'counter', 'counter', x''), (4, 'counter', 'counter', 'counter', x'')");
    // A notification for something the agent does not follow, and two for the same log.
    refused("q-no-follow", "(3, 'counter', 'tally', 'nothing', x'')");
    refused("q-told-twice", "(3, 'counter', 'tally', 'counter', x''), (3, 'counter', 'tally', 'counter', x'')");
    // A kind of event this runtime does not have.
    refused("q-unknown", "(9, 'counter', 'counter', 'counter', x'')");

    // One of each that the ship could have made is accepted, with whatever payload it carried
    // replaced by what the runtime would have written, and runs.
    let (result, other, _dir) =
        import("q-fine", &queue("(4, 'counter', 'counter', 'counter', x'ffff'), (3, 'counter', 'tally', 'counter', x'ffff')"));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(other.pending("~zod").unwrap(), 2);
    // The copy knows both are waiting: a new entry does not queue a second notification.
    assert_eq!(send(&other, "~zod", "counter", "log hits"), "4");
    assert_eq!(other.pending("~zod").unwrap(), 2);
    settle(&other);
    assert_eq!(checkpoint(&other).0, 4);
    assert_eq!(audited(&other, b"counter", false) + audited(&other, b"", false), 0);
    assert_eq!(read(&other, "tally", "tally", "seen"), "4");
}

#[test]
fn a_full_ship_lets_go_of_log_entries_a_checkpoint_covers() {
    // Entries are big and the usual threshold applies, so between checkpoints the log holds
    // more than this ship's file has room for. Some of that is already covered by a checkpoint
    // and only kept for followers that are a little behind.
    let dir = TempDir::new("cp-storage");
    let rt = boot(&dir, Config { max_ship_bytes: 200 << 10, ..fast() });
    let mut refused = 0;
    for expected in 1..=40 {
        match rt.deliver("~zod", "counter", b"log-big 30000") {
            Ok(outcome) => assert_eq!(outcome.reply, expected.to_string().into_bytes()),
            Err(Error::Rejected(Rejection::Limit(why))) => {
                assert!(why.contains("storage is full"), "{why}");
                refused += 1;
                // Being refused for want of room is what lets the covered entries go, so the
                // same entry fits when it is tried again.
                assert_eq!(send(&rt, "~zod", "counter", "log-big 30000"), expected.to_string());
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(refused > 0, "the ship's file never filled, so this shows nothing");
    // What is left still checks out from the checkpoint to the end.
    let key = rt.public_key("~zod").unwrap();
    let (seq, hash, _) = checkpoint(&rt);
    let rest = rt.log_entries("~zod", "counter", "counter", seq, NO_LIMIT).unwrap();
    assert_eq!(verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &rest).unwrap().unwrap().0, 40);
}

#[test]
fn a_full_ship_can_let_go_of_a_logs_only_entry() {
    // One big entry, covered by a checkpoint taken straight after it. A second entry would fit
    // in the log many times over, but not in what is left of this ship's file.
    let (dir, b, out) = (TempDir::new("cp-last"), TempDir::new("cp-last-b"), TempDir::new("cp-last-out"));
    let cfg = Config { max_ship_bytes: 168 << 10, checkpoint_min_bytes: 0, ..fast() };
    let rt = boot(&dir, cfg.clone());
    assert_eq!(send(&rt, "~zod", "counter", "log-big 60000"), "1");
    let key = rt.public_key("~zod").unwrap();
    let (seq, hash, _) = checkpoint(&rt);
    assert_eq!(seq, 1);

    match rejection(&rt, "counter", "log-big 30000") {
        Rejection::Limit(why) => assert!(why.contains("storage is full"), "{why}"),
        other => panic!("expected the storage limit, got {other:?}"),
    }
    // Being refused let the covered entry go, which leaves the log with no entries at all. It
    // still knows where it ends, and that is where its checkpoint says.
    assert_eq!(dropped(&rt), 1);
    assert!(rt.log_entries("~zod", "counter", "counter", 1, NO_LIMIT).unwrap().is_empty());
    assert_eq!(rt.log_head("~zod", "counter", "counter").unwrap(), Some((1, hash)));

    // A ship in that state can be exported and imported, and both carry on the same chain.
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&b.0, cfg.clone()).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    for ship in [&rt, &other] {
        assert_eq!(send(ship, "~zod", "counter", "log-big 30000"), "2");
        let rest = ship.log_entries("~zod", "counter", "counter", seq, NO_LIMIT).unwrap();
        assert_eq!(verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &rest).unwrap().unwrap().0, 2);
    }

    // An entry-less log whose recorded end is not the one its checkpoint signed for is refused.
    let c = TempDir::new("cp-last-c");
    rusqlite::Connection::open(out.0.join("zod.ship")).unwrap().execute_batch("UPDATE logs SET head_hash = zeroblob(32)").unwrap();
    assert!(matches!(Runtime::open(&c.0, cfg).unwrap().import_ship(&out.0, "~zod"), Err(Error::BadShipFile(_))));
}

// Signing in, and reaching a ship over HTTP.

use runtime::server::{Server, ServerConfig};
use ship_proto::Message as _;
use std::sync::Arc;

/// Sign a new device in with a fresh one-time code, and return its token.
fn sign_in(rt: &Runtime, label: &str) -> String {
    let code = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    rt.sign_in("~zod", &code, label).unwrap().0
}

#[test]
fn each_device_signs_in_with_a_code_and_gets_its_own_token() {
    let dir = TempDir::new("signin");
    let rt = boot(&dir, fast());
    rt.create_ship("~nec", &kernel(&rt)).unwrap();

    let code = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let (phone, device) = rt.sign_in("~zod", &code, "Bill's phone").unwrap();
    assert_eq!(device.label, "Bill's phone");
    assert_eq!(rt.authenticate("~zod", &phone).unwrap(), device);
    // The code was good for one use.
    assert!(matches!(rt.sign_in("~zod", &code, "again"), Err(Error::SignInRefused)));

    let laptop = sign_in(&rt, "Laptop");
    assert_ne!(phone, laptop);
    let labels: Vec<String> = rt.devices("~zod").unwrap().into_iter().map(|device| device.label).collect();
    assert_eq!(labels, ["Bill's phone", "Laptop"]);

    // One device signed out leaves the other signed in.
    assert!(rt.revoke_device("~zod", device.id).unwrap());
    assert!(matches!(rt.authenticate("~zod", &phone), Err(Error::NotSignedIn)));
    assert!(rt.authenticate("~zod", &laptop).is_ok());
    assert!(!rt.revoke_device("~zod", device.id).unwrap());
    assert!(!rt.revoke_device("~zod", u64::MAX).unwrap());

    // A token is for one ship, a token is not a sign-in code, and a code is not a token.
    assert!(matches!(rt.authenticate("~nec", &laptop), Err(Error::NotSignedIn)));
    assert!(matches!(rt.sign_in("~zod", &laptop, "token as code"), Err(Error::SignInRefused)));
    let unused = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert!(matches!(rt.authenticate("~zod", &unused), Err(Error::NotSignedIn)));
    assert!(matches!(rt.sign_in("~nec", &unused, "wrong ship"), Err(Error::SignInRefused)));

    // A code that has run out of time is refused, and tokens survive a sleep and wake.
    let brief = rt.new_signin_code("~zod", Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert!(matches!(rt.sign_in("~zod", &brief, "late"), Err(Error::SignInRefused)));
    rt.sleep_idle(Duration::ZERO);
    assert_eq!(rt.authenticate("~zod", &laptop).unwrap().label, "Laptop");

    // A label is cleaned up before it is kept: no control characters, not too long, not empty.
    let odd = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let (_, device) = rt.sign_in("~zod", &odd, &format!("  tab\there\n{}", "x".repeat(200))).unwrap();
    assert!(device.label.starts_with("tabherexxx") && device.label.len() == 64, "{:?}", device.label);
    let blank = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert_eq!(rt.sign_in("~zod", &blank, " \n ").unwrap().1.label, "device");
}

#[test]
fn a_ships_access_code_can_be_used_again_and_changed() {
    let dir = TempDir::new("access-code");
    let rt = boot(&dir, fast());
    // No access code until one is set.
    assert!(matches!(rt.sign_in("~zod", "", "nothing"), Err(Error::SignInRefused)));

    let code = rt.set_access_code("~zod").unwrap();
    let groups: Vec<&str> = code.split('-').collect();
    assert!(groups.len() == 4 && groups.iter().all(|group| group.len() == 5), "{code}");
    // It works any number of times, and however it is typed.
    let (first, _) = rt.sign_in("~zod", &code, "one").unwrap();
    let (second, _) = rt.sign_in("~zod", &code.to_uppercase().replace('-', " "), "two").unwrap();
    assert!(matches!(rt.sign_in("~zod", &code[1..], "wrong"), Err(Error::SignInRefused)));
    // It is this ship's code and no other's.
    rt.create_ship("~nec", &kernel(&rt)).unwrap();
    assert!(matches!(rt.sign_in("~nec", &code, "wrong ship"), Err(Error::SignInRefused)));
    // Where only a one-time code will do, it is refused like any wrong code.
    assert!(matches!(rt.sign_in_once("~zod", &code, "as a link"), Err(Error::SignInRefused)));
    let once = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert!(rt.sign_in_once("~zod", &once, "by link").is_ok());
    assert!(rt.revoke_device("~zod", 3).unwrap());

    // Changing it stops the old one. Devices that are signed in stay signed in.
    let changed = rt.set_access_code("~zod").unwrap();
    assert_ne!(code, changed);
    assert!(matches!(rt.sign_in("~zod", &code, "old code"), Err(Error::SignInRefused)));
    assert!(rt.sign_in("~zod", &changed, "three").is_ok());
    assert!(rt.authenticate("~zod", &first).is_ok() && rt.authenticate("~zod", &second).is_ok());

    // With none set, one-time codes still work.
    rt.clear_access_code("~zod").unwrap();
    assert!(matches!(rt.sign_in("~zod", &changed, "cleared"), Err(Error::SignInRefused)));
    sign_in(&rt, "four");
    assert_eq!(rt.devices("~zod").unwrap().len(), 4);
}

#[test]
fn wrong_sign_in_codes_lock_sign_in_for_a_while() {
    let dir = TempDir::new("signin-lock");
    let rt = boot(&dir, Config { signin_max_failures: 3, signin_lock_millis: 400, ..fast() });
    let device = sign_in(&rt, "already here");
    let code = rt.set_access_code("~zod").unwrap();

    // A good code in between wrong ones starts the count again.
    for _ in 0..2 {
        assert!(matches!(rt.sign_in("~zod", "guess", "x"), Err(Error::SignInRefused)));
    }
    rt.sign_in("~zod", &code, "good").unwrap();
    for _ in 0..3 {
        assert!(matches!(rt.sign_in("~zod", "guess", "x"), Err(Error::SignInRefused)));
    }
    // Locked: even the right code is refused, and a one-time code offered now is not used up.
    let once = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert!(matches!(rt.sign_in("~zod", &code, "x"), Err(Error::SignInLocked(left)) if left <= 400));
    assert!(matches!(rt.sign_in("~zod", &once, "x"), Err(Error::SignInLocked(_))));
    // A device that is already signed in is not affected, and the lock survives a sleep.
    assert!(rt.authenticate("~zod", &device).is_ok());
    rt.sleep_idle(Duration::ZERO);
    assert!(matches!(rt.sign_in("~zod", &code, "x"), Err(Error::SignInLocked(_))));

    std::thread::sleep(Duration::from_millis(450));
    rt.sign_in("~zod", &once, "after the lock").unwrap();
    rt.sign_in("~zod", &code, "after the lock").unwrap();
}

#[test]
fn devices_and_waiting_codes_are_bounded() {
    let dir = TempDir::new("signin-bounds");
    let rt = boot(&dir, Config { max_devices: 2, max_signin_codes: 2, ..fast() });
    let first = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let second = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert!(matches!(rt.new_signin_code("~zod", Duration::from_secs(60)), Err(Error::TooMany(_))));
    // A code that is used or has run out makes room for another.
    let (token, device) = rt.sign_in("~zod", &first, "one").unwrap();
    let brief = rt.new_signin_code("~zod", Duration::from_millis(1)).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let third = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    assert!(matches!(rt.sign_in("~zod", &brief, "late"), Err(Error::SignInRefused)));

    rt.sign_in("~zod", &second, "two").unwrap();
    // With the ship full of devices a good code is turned away, but not used up or counted as
    // a wrong guess.
    for _ in 0..10 {
        assert!(matches!(rt.sign_in("~zod", &third, "three"), Err(Error::TooMany(_))));
    }
    // Only a good code is told so. A guess learns nothing about how full the ship is.
    assert!(matches!(rt.sign_in("~zod", "guess", "x"), Err(Error::SignInRefused)));
    assert!(rt.revoke_device("~zod", device.id).unwrap());
    assert!(matches!(rt.authenticate("~zod", &token), Err(Error::NotSignedIn)));
    rt.sign_in("~zod", &third, "three").unwrap();
}

#[test]
fn signed_in_devices_go_with_the_ship() {
    let (a, b, c, out) = (TempDir::new("dev-a"), TempDir::new("dev-b"), TempDir::new("dev-c"), TempDir::new("dev-out"));
    let cfg = Config { signin_max_failures: 1, signin_lock_millis: 60_000, ..fast() };
    let rt = boot(&a, cfg.clone());
    let (phone, laptop) = (sign_in(&rt, "phone"), sign_in(&rt, "laptop"));
    // A third device, signed out again before the ship moves. Its number must stay retired.
    let gone = sign_in(&rt, "gone");
    assert!(rt.revoke_device("~zod", 3).unwrap());
    let code = rt.set_access_code("~zod").unwrap();
    let once = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    // Lock sign-in on the original. That is about guesses made against it, and stays behind.
    assert!(matches!(rt.sign_in("~zod", "guess", "x"), Err(Error::SignInRefused)));
    assert!(matches!(rt.sign_in("~zod", &code, "x"), Err(Error::SignInLocked(_))));
    rt.export_ship("~zod", &out.0).unwrap();

    let other = Runtime::open(&b.0, cfg.clone()).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(other.authenticate("~zod", &phone).unwrap().label, "phone");
    assert_eq!(other.authenticate("~zod", &laptop).unwrap().label, "laptop");
    let (_, third) = other.sign_in("~zod", &code, "tablet").unwrap();
    let (_, fourth) = other.sign_in("~zod", &once, "watch").unwrap();
    // Device numbers carry on from where the original left off, so none is ever reused, not
    // even that of a device that had been signed out.
    assert_eq!((third.id, fourth.id), (4, 5));
    assert!(matches!(other.authenticate("~zod", &gone), Err(Error::NotSignedIn)));

    // A file that records devices or codes wrongly is not a ship file.
    let tampered = |label: &str, statement: &str, cfg: Config| {
        let dir = TempDir::new(label);
        fs::remove_dir_all(&c.0).ok();
        fs::create_dir_all(&c.0).unwrap();
        rt.export_ship("~zod", &c.0).unwrap();
        rusqlite::Connection::open(c.0.join("zod.ship")).unwrap().execute_batch(statement).unwrap();
        let result = Runtime::open(&dir.0, cfg).unwrap().import_ship(&c.0, "~zod");
        assert!(matches!(result, Err(Error::BadShipFile(_))), "{label}: {result:?}");
    };
    tampered("dev-short", "UPDATE devices SET token_hash = x'0102030405' WHERE seq = 1", cfg.clone());
    tampered("dev-label", "UPDATE devices SET label = hex(zeroblob(100)) WHERE seq = 1", cfg.clone());
    tampered("dev-many", "SELECT 1", Config { max_devices: 1, ..cfg.clone() });
    tampered("code-short", "UPDATE signin_codes SET code_hash = x'0102' WHERE reusable = 1", cfg.clone());
    tampered("code-two", "INSERT INTO signin_codes VALUES (zeroblob(32), 0, 1)", cfg.clone());
    tampered("code-flag", "UPDATE signin_codes SET reusable = 2", cfg.clone());
    tampered("code-many", "SELECT 1", Config { max_signin_codes: 0, ..cfg.clone() });
    // The access code is not counted among the one-time codes, nor they in its place.
    tampered("code-once", "DELETE FROM signin_codes WHERE reusable = 1", Config { max_signin_codes: 0, ..cfg });
}

#[test]
fn waiting_for_a_log_returns_as_soon_as_it_grows() {
    let dir = TempDir::new("wait-log");
    let rt = boot_with_journal(&dir, fast());
    send(&rt, "~zod", "counter", "log hits");

    // Nothing new: the wait runs its course and reports where the log still ends.
    let started = Instant::now();
    let head = rt.wait_log("~zod", "counter", "counter", 1, Duration::from_millis(300)).unwrap();
    assert_eq!(head.unwrap().0, 1);
    assert!(started.elapsed() >= Duration::from_millis(300));
    // Already past what was asked for: no waiting at all.
    let started = Instant::now();
    assert_eq!(rt.wait_log("~zod", "counter", "counter", 0, Duration::from_secs(10)).unwrap().unwrap().0, 1);
    assert!(started.elapsed() < Duration::from_secs(2));

    // A waiter is woken by the entry it was waiting for, long before its time is up. Growth in
    // another of the ship's logs wakes it too, and it goes back to waiting.
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            let started = Instant::now();
            let head = rt.wait_log("~zod", "counter", "counter", 1, Duration::from_secs(20)).unwrap();
            (head.unwrap().0, started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(send(&rt, "~zod", "counter", "journal a line elsewhere"), "1");
        std::thread::sleep(Duration::from_millis(300));
        assert!(!waiter.is_finished(), "growth in another log ended the wait");
        send(&rt, "~zod", "counter", "log hits");
        let (seq, took) = waiter.join().unwrap();
        assert_eq!(seq, 2);
        assert!(took < Duration::from_secs(10), "took {took:?}");
    });
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

/// Make one HTTP request and read the whole answer.
fn http(server: &Server, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Answer {
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    // HTTP/1.0, so the answer is never sent in chunks and the connection closes after it.
    let mut head = format!("{method} {path} HTTP/1.0\r\n");
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        head += &format!("Host: {}\r\n", server.addr());
    }
    for (name, value) in headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).unwrap();
    // A server may refuse a request on its headers and stop listening to the rest of it.
    let _ = stream.write_all(body);
    read_answer(stream)
}

fn read_answer(mut stream: std::net::TcpStream) -> Answer {
    use std::io::Read;
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n").expect("an HTTP answer");
    let top = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = top.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines.filter_map(|line| line.split_once(": ")).map(|(name, value)| (name.to_string(), value.to_string())).collect();
    Answer { status, headers, body: raw[split + 4..].to_vec() }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// A runtime with `~zod` running the counter agent, and a server in front of it.
fn serve(dir: &TempDir, cfg: Config, server: ServerConfig) -> (Arc<Runtime>, Server) {
    let rt = Arc::new(boot(dir, cfg));
    let server = Server::start(rt.clone(), server).unwrap();
    (rt, server)
}

#[test]
fn an_app_signs_in_over_http_reads_a_log_and_sends_commands() {
    let dir = TempDir::new("http-app");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    rt.create_ship("~nec", &kernel(&rt)).unwrap();
    for _ in 0..3 {
        send(&rt, "~zod", "counter", "log hits");
    }

    // Sign in with a one-time code, as an app would.
    let code = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let asked = ship_proto::SignInRequest { code, label: "Phone".into() }.encode_to_vec();
    let proto = [("Content-Type", "application/x-protobuf")];
    let answer = http(&server, "POST", "/ships/zod/signin", &proto, &asked);
    assert_eq!(answer.status, 200, "{}", answer.text());
    let signed_in = ship_proto::SignInReply::decode(&*answer.body).unwrap();
    assert_eq!(signed_in.device.unwrap().label, "Phone");
    assert!(answer.header("Set-Cookie").is_none());
    // The same code again is refused.
    assert_eq!(http(&server, "POST", "/ships/zod/signin", &proto, &asked).status, 401);
    let auth = bearer(&signed_in.token);
    let auth = [("Authorization", auth.as_str())];

    // Read the log and check it against the ship's key, all over HTTP.
    let key: [u8; 32] = http(&server, "GET", "/ships/zod/key", &auth, b"").body.try_into().unwrap();
    assert_eq!(key, rt.public_key("~zod").unwrap());
    let answer = http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=0", &auth, b"");
    assert_eq!(answer.status, 200);
    let list = ship_proto::EntryList::decode(&*answer.body).unwrap();
    assert_eq!(payloads(&list.entries), ["hits=1", "hits=2", "hits=3"]);
    let position = verify_log(&key, "~zod", "counter", "counter", None, &list.entries).unwrap().unwrap();
    let head = list.head.unwrap();
    assert_eq!((head.seq, &head.hash[..]), (position.0, &position.1[..]));
    let head = http(&server, "GET", "/ships/zod/logs/counter/counter/head", &auth, b"");
    assert_eq!(ship_proto::LogHead::decode(&*head.body).unwrap().seq, 3);
    // A name in an address may be written with escapes. It is the same name.
    let head = http(&server, "GET", "/ships/zod/logs/c%6Funter/coun%74er/head", &auth, b"");
    assert_eq!(ship_proto::LogHead::decode(&*head.body).unwrap().seq, 3);
    // An escaped slash is part of a name, not a way to change which thing is asked for.
    assert_eq!(http(&server, "GET", "/ships/zod/logs/counter%2Fcounter/head", &auth, b"").status, 404);
    assert_eq!(http(&server, "GET", "/ships/zod/logs/counter/counter/he%ZZad", &auth, b"").status, 400);

    // Send a command as the owner, then read on from where the reader had got to.
    let answer = http(&server, "POST", "/ships/zod/agents/counter/command", &auth, b"log hits");
    assert_eq!((answer.status, answer.text().as_str()), (200, "4"));
    let answer = http(&server, "GET", "/ships/~zod/logs/counter/counter/entries?after=3", &auth, b"");
    let more = ship_proto::EntryList::decode(&*answer.body).unwrap().entries;
    assert_eq!(payloads(&more), ["hits=4"]);
    assert_eq!(verify_log(&key, "~zod", "counter", "counter", Some(position), &more).unwrap().unwrap().0, 4);
    // A command the agent rejects says so, without saying how it failed inside.
    let answer = http(&server, "POST", "/ships/zod/agents/counter/command", &auth, b"crash hits");
    assert_eq!((answer.status, answer.text().as_str()), (422, "the command failed"));
    assert_eq!(http(&server, "GET", "/ships/zod/logs/counter/counter/checkpoint", &auth, b"").status, 404);

    // Without a token, with a wrong one, with this ship's token on another ship, and on a ship
    // that does not exist: all the same answer, so nothing is learned about which ships exist.
    let wrong = bearer(&"0".repeat(64));
    for (path, headers) in [
        ("/ships/zod/logs/counter/counter/head", &[][..]),
        ("/ships/zod/logs/counter/counter/head", &[("Authorization", wrong.as_str())][..]),
        ("/ships/nec/logs/counter/counter/head", &auth[..]),
        ("/ships/bus/logs/counter/counter/head", &auth[..]),
    ] {
        let answer = http(&server, "GET", path, headers, b"");
        assert_eq!((answer.status, answer.text().as_str()), (401, "not signed in"), "{path}");
    }
    let nowhere = http(&server, "POST", "/ships/bus/signin", &proto, &asked);
    assert_eq!((nowhere.status, nowhere.text()), (401, "that sign-in code is not accepted".to_string()));
    assert_eq!(http(&server, "POST", "/ships/zod/agents/counter/command", &[], b"log hits").status, 401);

    // Other things a request can get wrong.
    assert_eq!(http(&server, "GET", "/ships/zod/nothing/here", &auth, b"").status, 404);
    assert_eq!(http(&server, "GET", "/elsewhere", &auth, b"").status, 404);
    assert_eq!(http(&server, "GET", "/ships/Not%20A%20Ship/key", &auth, b"").status, 404);
    assert_eq!(http(&server, "GET", "/ships/zod/logs/Bad%20Name/counter/head", &auth, b"").status, 400);
    assert_eq!(http(&server, "PUT", "/ships/zod/key", &auth, b"").status, 405);
    let huge = vec![b'x'; (1 << 20) + 1];
    assert_eq!(http(&server, "POST", "/ships/zod/agents/counter/command", &auth, &huge).status, 413);
    assert_eq!(rt.log_head("~zod", "counter", "counter").unwrap().unwrap().0, 4);
}

#[test]
fn devices_are_listed_and_signed_out_over_http() {
    let dir = TempDir::new("http-devices");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let (phone, laptop) = (sign_in(&rt, "Phone"), sign_in(&rt, "Laptop"));
    let (phone_auth, laptop_auth) = (bearer(&phone), bearer(&laptop));
    let (phone_auth, laptop_auth) = ([("Authorization", phone_auth.as_str())], [("Authorization", laptop_auth.as_str())]);

    let answer = http(&server, "GET", "/ships/zod/devices", &laptop_auth, b"");
    let list = ship_proto::DeviceList::decode(&*answer.body).unwrap();
    let labels: Vec<&str> = list.devices.iter().map(|device| device.label.as_str()).collect();
    assert_eq!((labels, list.current), (vec!["Phone", "Laptop"], 2));

    // The laptop signs the phone out. The phone's token stops working; the laptop's does not.
    assert_eq!(http(&server, "DELETE", "/ships/zod/devices/1", &laptop_auth, b"").status, 204);
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &phone_auth, b"").status, 401);
    assert_eq!(http(&server, "DELETE", "/ships/zod/devices/1", &laptop_auth, b"").status, 404);
    assert_eq!(http(&server, "DELETE", "/ships/zod/devices/one", &laptop_auth, b"").status, 400);
    // And then signs itself out.
    assert_eq!(http(&server, "POST", "/ships/zod/signout", &laptop_auth, b"").status, 204);
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &laptop_auth, b"").status, 401);
    assert!(rt.devices("~zod").unwrap().is_empty());
}

#[test]
fn a_trimmed_log_is_read_over_http_from_its_checkpoint() {
    let dir = TempDir::new("http-trimmed");
    let (rt, server) = serve(&dir, checkpointing(), ServerConfig::default());
    for _ in 0..20 {
        send(&rt, "~zod", "counter", "log hits");
    }
    let token = bearer(&sign_in(&rt, "Phone"));
    let auth = [("Authorization", token.as_str())];
    let key = rt.public_key("~zod").unwrap();

    // Asking for the start is answered with where the log now starts, not with a gap.
    let answer = http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=0", &auth, b"");
    assert_eq!(answer.status, 410);
    assert_eq!(ship_proto::Trimmed::decode(&*answer.body).unwrap().base, dropped(&rt));

    let answer = http(&server, "GET", "/ships/zod/logs/counter/counter/checkpoint", &auth, b"");
    let signed = SignedCheckpoint::decode(&*answer.body).unwrap();
    let ((seq, hash), state) = verify_checkpoint(&key, "~zod", "counter", "counter", &signed).unwrap();
    assert_eq!(state, format!("hits={seq}").into_bytes());
    let answer = http(&server, "GET", &format!("/ships/zod/logs/counter/counter/entries?after={seq}"), &auth, b"");
    let list = ship_proto::EntryList::decode(&*answer.body).unwrap();
    let end = verify_log(&key, "~zod", "counter", "counter", Some((seq, hash)), &list.entries).unwrap().unwrap();
    assert_eq!((end.0, list.head.unwrap().seq), (20, 20));

    // A reader can ask for a little at a time.
    let answer = http(&server, "GET", &format!("/ships/zod/logs/counter/counter/entries?after={seq}&max_bytes=1"), &auth, b"");
    assert!(seq < 19, "the checkpoint is too near the end for this to show anything");
    let list = ship_proto::EntryList::decode(&*answer.body).unwrap();
    assert_eq!((list.entries.len(), list.head.unwrap().seq), (1, 20));
}

#[test]
fn a_reader_can_wait_over_http_for_new_entries() {
    let dir = TempDir::new("http-wait");
    let (rt, server) = serve(&dir, fast(), ServerConfig { workers: 4, max_wait: Duration::from_secs(20), ..ServerConfig::default() });
    send(&rt, "~zod", "counter", "log hits");
    let token = bearer(&sign_in(&rt, "Phone"));
    let auth = [("Authorization", token.as_str())];
    let entries = |answer: &Answer| payloads(&ship_proto::EntryList::decode(&*answer.body).unwrap().entries);

    // Nothing new within the time asked for: an empty answer, after about that long.
    let started = Instant::now();
    let answer = http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=1&wait=1", &auth, b"");
    assert!(entries(&answer).is_empty());
    assert!(started.elapsed() >= Duration::from_millis(900), "{:?}", started.elapsed());

    // The answer comes as soon as there is an entry, well inside the time asked for.
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            let started = Instant::now();
            let answer = http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=1&wait=20", &auth, b"");
            (entries(&answer), started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(http(&server, "POST", "/ships/zod/agents/counter/command", &auth, b"log hits").text(), "2");
        let (seen, took) = waiter.join().unwrap();
        assert_eq!(seen, ["hits=2"]);
        assert!(took < Duration::from_secs(10), "took {took:?}");
    });

    // Only half the server's threads may be held by waiters. With two already waiting, a third
    // is answered at once with what there is, and other requests are still served.
    std::thread::scope(|scope| {
        let waiters: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| entries(&http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=2&wait=15", &auth, b""))))
            .collect();
        std::thread::sleep(Duration::from_millis(500));
        let started = Instant::now();
        let third = http(&server, "GET", "/ships/zod/logs/counter/counter/entries?after=2&wait=15", &auth, b"");
        assert!(entries(&third).is_empty());
        assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
        assert_eq!(http(&server, "GET", "/ships/zod/logs/counter/counter/head", &auth, b"").status, 200);
        // Both of the first two were let wait: each is still there to be handed the next entry.
        assert!(waiters.iter().all(|waiter| !waiter.is_finished()));
        assert_eq!(http(&server, "POST", "/ships/zod/agents/counter/command", &auth, b"log hits").text(), "3");
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), ["hits=3"]);
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    });
}

#[test]
fn a_browser_signs_in_with_the_access_code_and_keeps_a_cookie() {
    let dir = TempDir::new("http-browser");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let code = rt.set_access_code("~zod").unwrap();
    let form = [("Content-Type", "application/x-www-form-urlencoded")];

    // Opening the ship without being signed in leads to its sign-in page.
    let answer = http(&server, "GET", "/ships/zod/", &[], b"");
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/ships/zod/signin")));
    let page = http(&server, "GET", "/ships/zod/signin", &[], b"");
    assert!(page.status == 200 && page.text().contains("Sign in to ~zod"));
    assert!(page.header("Content-Security-Policy").is_some_and(|policy| policy.contains("frame-ancestors 'none'")));
    // With `no-referrer` a browser would report the page's own forms as coming from nowhere,
    // and the ship would refuse its own buttons.
    assert_eq!(page.header("Referrer-Policy"), Some("same-origin"));

    // A wrong code shows the page again and says why.
    let answer = http(&server, "POST", "/ships/zod/signin", &form, b"code=nope&label=Laptop");
    assert!(answer.status == 401 && answer.text().contains("not accepted") && answer.header("Set-Cookie").is_none());

    // The right one, typed with spaces, sets a cookie the page's scripts cannot read and that
    // is sent only to this ship, then moves on to the ship's page.
    let typed = format!("code={}&label=%3Cscript%3Ealert(1)%3C%2Fscript%3E", code.replace('-', "+"));
    let answer = http(&server, "POST", "/ships/zod/signin", &form, typed.as_bytes());
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/ships/zod/")));
    let set = answer.header("Set-Cookie").unwrap().to_string();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict") && set.contains("Path=/ships/zod;"), "{set}");
    assert!(!set.contains("Secure"));
    let cookie = set.split(';').next().unwrap().to_string();
    let cookies = [("Cookie", cookie.as_str())];

    // The ship's page lists the device. Its label is shown as text, never run as markup.
    let home = http(&server, "GET", "/ships/zod/", &cookies, b"");
    assert_eq!(home.status, 200);
    assert!(home.text().contains("&lt;script&gt;alert(1)&lt;/script&gt;") && !home.text().contains("<script>"), "{}", home.text());
    // The cookie works for reading, like a token in a header.
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &cookies, b"").status, 200);

    // A browser can hold several cookies of this name, from other paths or a parent domain,
    // and sends them all. The good one is found among them.
    let several = format!("other=1; ship_token=stale; {cookie}");
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &[("Cookie", several.as_str())], b"").status, 200);

    // The access code is for typing into the page. Put in an address it would stay in
    // histories and logs for as long as it works, so there it is refused like a wrong code.
    let link = format!("/ships/zod/signin?code={code}");
    let answer = http(&server, "GET", &link, &[], b"");
    assert!(answer.status == 401 && answer.header("Set-Cookie").is_none());
    assert_eq!(rt.devices("~zod").unwrap().len(), 1);

    // A one-time sign-in link does the same in one step.
    let once = rt.new_signin_code("~zod", Duration::from_secs(60)).unwrap();
    let answer = http(&server, "GET", &format!("/ships/zod/signin?code={once}"), &[], b"");
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/ships/zod/")));
    assert!(answer.header("Set-Cookie").is_some());
    let again = http(&server, "GET", &format!("/ships/zod/signin?code={once}"), &[], b"");
    assert!(again.status == 401 && again.header("Set-Cookie").is_none());
    let labels: Vec<String> = rt.devices("~zod").unwrap().into_iter().map(|device| device.label).collect();
    assert_eq!(labels, ["<script>alert(1)</script>", "Browser"]);

    // The ship's page signs another device out with a button.
    let origin = format!("http://{}", server.addr());
    let own = [("Cookie", cookie.as_str()), ("Origin", origin.as_str())];
    let answer = http(&server, "POST", "/ships/zod/devices/2/revoke", &own, b"");
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/ships/zod/")));
    assert_eq!(rt.devices("~zod").unwrap().len(), 1);

    // Signing out forgets the device and tells the browser to drop the cookie.
    let answer = http(&server, "POST", "/ships/zod/signout", &own, b"");
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/ships/zod/signin")));
    assert!(answer.header("Set-Cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(http(&server, "GET", "/ships/zod/", &cookies, b"").status, 303);
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &cookies, b"").status, 401);
}

#[test]
fn another_site_cannot_use_a_browsers_cookie_to_act_on_the_ship() {
    let dir = TempDir::new("http-csrf");
    let (rt, server) = serve(&dir, fast(), ServerConfig::default());
    let token = sign_in(&rt, "Browser");
    let cookie = format!("ship_token={token}");
    let own = format!("http://{}", server.addr());
    let command = |headers: &[(&str, &str)]| http(&server, "POST", "/ships/zod/agents/counter/command", headers, b"inc hits");

    // A browser attaches the cookie to any request for the ship, whoever's page asked for it.
    // Only a request that says it came from the ship's own page may change anything.
    assert_eq!(command(&[("Cookie", &cookie)]).status, 403);
    assert_eq!(command(&[("Cookie", &cookie), ("Origin", "http://elsewhere.example")]).status, 403);
    assert_eq!(command(&[("Cookie", &cookie), ("Origin", "null")]).status, 403);
    assert_eq!(http(&server, "POST", "/ships/zod/signout", &[("Cookie", &cookie)], b"").status, 403);
    assert_eq!(http(&server, "DELETE", "/ships/zod/devices/1", &[("Cookie", &cookie)], b"").status, 403);
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "0");
    assert_eq!(rt.devices("~zod").unwrap().len(), 1);

    // A browser that says outright whether the request is the ship's own is believed, either way.
    assert_eq!(command(&[("Cookie", &cookie), ("Sec-Fetch-Site", "cross-site")]).status, 403);
    assert_eq!(command(&[("Cookie", &cookie), ("Sec-Fetch-Site", "same-site"), ("Origin", &own)]).status, 403);
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "0");

    let answer = command(&[("Cookie", &cookie), ("Origin", &own)]);
    assert_eq!((answer.status, answer.text().as_str()), (200, "1"));
    assert_eq!(command(&[("Cookie", &cookie), ("Sec-Fetch-Site", "same-origin"), ("Origin", "null")]).text(), "2");
    // An app sends its token itself, in a header no other site can add, so it needs no such check.
    let auth = bearer(&token);
    assert_eq!(command(&[("Authorization", &auth)]).text(), "3");
    // A header wins over a cookie, so a bad header is not rescued by a good cookie.
    assert_eq!(command(&[("Authorization", "Bearer nope"), ("Cookie", &cookie), ("Origin", &own)]).status, 401);
}

#[test]
fn a_hostname_can_name_the_ship() {
    let dir = TempDir::new("http-host");
    let config = ServerConfig { ship_host_suffix: Some(".ships.test".into()), secure_cookies: true, ..ServerConfig::default() };
    let (rt, server) = serve(&dir, fast(), config);
    let code = rt.set_access_code("~zod").unwrap();
    let host = [("Host", "zod.ships.test:8443"), ("Content-Type", "application/x-www-form-urlencoded")];

    // The ship is the first part of the hostname, and paths start at the ship.
    let answer = http(&server, "GET", "/", &host, b"");
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/signin")));
    let answer = http(&server, "POST", "/signin", &host, format!("code={code}").as_bytes());
    assert_eq!((answer.status, answer.header("Location")), (303, Some("/")));
    let set = answer.header("Set-Cookie").unwrap();
    assert!(set.contains("Path=/;") && set.contains("; Secure"), "{set}");
    let cookie = set.split(';').next().unwrap().to_string();
    let with_cookie = [("Host", "ZOD.ships.test"), ("Cookie", cookie.as_str())];
    assert!(http(&server, "GET", "/", &with_cookie, b"").text().contains("~zod"));

    // A name that merely ends in the ship's is a different ship, here one that does not exist.
    assert_eq!(http(&server, "GET", "/devices", &[("Host", "evilzod.ships.test"), ("Cookie", cookie.as_str())], b"").status, 401);
    // Without its dot the suffix would match in the middle of a name, so it is not accepted.
    let dotless = ServerConfig { ship_host_suffix: Some("ships.test".into()), ..ServerConfig::default() };
    assert!(Server::start(rt.clone(), dotless).is_err());

    // A hostname that names no ship, and one outside the suffix, fall back to the path.
    assert_eq!(http(&server, "GET", "/signin", &[("Host", "nec.ships.test")], b"").status, 200);
    assert_eq!(http(&server, "GET", "/devices", &[("Host", "nec.ships.test"), ("Cookie", cookie.as_str())], b"").status, 401);
    assert_eq!(http(&server, "GET", "/signin", &[("Host", "zod.elsewhere.test")], b"").status, 404);
    assert_eq!(http(&server, "GET", "/ships/zod/signin", &[("Host", "zod.elsewhere.test")], b"").status, 200);
}

#[test]
fn guessing_sign_in_codes_over_http_is_slowed_down() {
    let dir = TempDir::new("http-lock");
    let (rt, server) = serve(&dir, Config { signin_max_failures: 3, signin_lock_millis: 60_000, ..fast() }, ServerConfig::default());
    let code = rt.set_access_code("~zod").unwrap();
    let form = [("Content-Type", "application/x-www-form-urlencoded")];
    for _ in 0..3 {
        assert_eq!(http(&server, "POST", "/ships/zod/signin", &form, b"code=guess").status, 401);
    }
    let answer = http(&server, "POST", "/ships/zod/signin", &form, format!("code={code}").as_bytes());
    assert_eq!(answer.status, 429);
    let wait: u64 = answer.header("Retry-After").unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert!(answer.header("Set-Cookie").is_none() && answer.text().contains("too many"));
    let asked = ship_proto::SignInRequest { code, label: "Phone".into() }.encode_to_vec();
    assert_eq!(http(&server, "POST", "/ships/zod/signin", &[("Content-Type", "application/x-protobuf")], &asked).status, 429);
    assert!(rt.devices("~zod").unwrap().is_empty());
}

/// Send bytes exactly as given and read whatever comes back.
fn raw_http(server: &Server, request: &[u8]) -> Answer {
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let _ = stream.write_all(request);
    read_answer(stream)
}

#[test]
fn requests_the_server_will_not_take_are_refused_without_harm() {
    let dir = TempDir::new("http-refused");
    let (rt, server) = serve(&dir, fast(), ServerConfig { workers: 4, ..ServerConfig::default() });
    let token = bearer(&sign_in(&rt, "Phone"));
    let auth = [("Authorization", token.as_str())];

    // A request that claims an enormous body is refused on the claim, before anything is read
    // or set aside for it, and without being signed in. Far more of them than there are
    // threads leave the server working.
    for _ in 0..40 {
        let claim = b"GET /ships/zod/devices HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n\r\n";
        assert_eq!(raw_http(&server, claim).status, 413);
    }
    assert_eq!(raw_http(&server, b"POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 1048577\r\n\r\n").status, 413);
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &auth, b"").status, 200);

    // A body is taken only with one plain statement of its length.
    let refused = |request: &str| raw_http(&server, request.as_bytes()).status;
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), 501);
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"), 400);
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: many\r\n\r\n"), 400);
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: +0\r\n\r\n"), 400);
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999999\r\n\r\n"), 413);
    assert_eq!(refused("POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\n\r\n"), 417);
    // Other things that are not a request this server reads.
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.7\r\nHost: x\r\n\r\n"), 400);
    assert_eq!(refused("hello there\r\n\r\n"), 400);
    assert_eq!(refused("GET ships/zod/signin HTTP/1.1\r\nHost: x\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\nno colon here\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Tab\t: 1\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Break: a\nb\r\n\r\n"), 400);
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Null: a\0b\r\n\r\n"), 400);
    assert_eq!(refused(&format!("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Padding: {}\r\n\r\n", "x".repeat(20_000))), 431);

    // An answer to a method this server does not have says which it does, and an answer to
    // HEAD carries nothing after its headers.
    let head = raw_http(&server, b"HEAD /ships/zod/signin HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!((head.status, head.header("Allow"), head.body.len()), (405, Some("GET, POST"), 0));
    // That holds when the request is refused before it is even looked at closely.
    let head = raw_http(&server, b"HEAD /ships/zod/signin HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\n\r\n");
    assert_eq!((head.status, head.body.len()), (417, 0));
    let head = raw_http(&server, b"HEAD /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n");
    assert_eq!((head.status, head.body.len()), (413, 0));
    let padded = format!("HEAD /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Padding: {}\r\n\r\n", "x".repeat(20_000));
    let head = raw_http(&server, padded.as_bytes());
    assert_eq!((head.status, head.body.len()), (431, 0));
    let head = raw_http(&server, b"HEAD /ships/zod/signin HTTP/1.1\r\nHost: x\r\nX-Odd: \xff\xfe\r\n\r\n");
    assert_eq!((head.status, head.body.len()), (400, 0));
    // An address written with escapes is the same address for every purpose: which methods it
    // takes, and what it does.
    let escaped = http(&server, "DELETE", "/ships/zod/s%69gnin", &[], b"");
    assert_eq!((escaped.status, escaped.header("Allow")), (405, Some("GET, POST")));
    let escaped = http(&server, "GET", "/ships/zod/s%69gnin", &[], b"");
    assert!(escaped.status == 200 && escaped.text().contains("Sign in to ~zod"));
    // The methods named are the ones that address takes, not every method the server knows.
    assert_eq!(http(&server, "PUT", "/ships/zod/key", &auth, b"").header("Allow"), Some("GET"));
    let wrong = http(&server, "DELETE", "/ships/zod/signin", &[], b"");
    assert_eq!((wrong.status, wrong.header("Allow")), (405, Some("GET, POST")));
    let wrong = http(&server, "GET", "/ships/zod/agents/counter/command", &auth, b"");
    assert_eq!((wrong.status, wrong.header("Allow")), (405, Some("POST")));
    // An answer that says there is no content does not give a length for it either.
    let extra = sign_in(&rt, "Extra");
    let gone = http(&server, "POST", "/ships/zod/signout", &[("Authorization", bearer(&extra).as_str())], b"");
    assert_eq!((gone.status, gone.header("Content-Length"), gone.body.len()), (204, None, 0));

    // Whatever follows a request on the same connection is never run as another request.
    let both = format!(
        "GET /ships/zod/key HTTP/1.1\r\nHost: x\r\nAuthorization: {token}\r\n\r\n\
         POST /ships/zod/agents/counter/command HTTP/1.1\r\nHost: x\r\nAuthorization: {token}\r\nContent-Length: 8\r\n\r\ninc hits"
    );
    assert!(matches!(refused(&both), 200 | 400));
    assert_eq!(send(&rt, "~zod", "counter", "get hits"), "0");

    // A name that an address cannot carry is not a name. A browser rewrites `..` away, so a
    // log called that could never be asked for; the runtime does not let one exist.
    assert!(matches!(rt.log_head("~zod", "counter", ".."), Err(Error::InvalidName(_))));
    assert_eq!(http(&server, "GET", "/ships/zod/logs/counter/%2E%2E/head", &auth, b"").status, 400);
    assert_eq!(http(&server, "GET", "/ships/zod/logs/counter/%2E/head", &auth, b"").status, 400);
    // And one that is, to show the ones above did no lasting harm.
    assert_eq!(refused("GET /ships/zod/signin HTTP/1.1\r\nHost: x\r\n\r\n"), 200);
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &auth, b"").status, 200);
}

#[test]
fn silent_clients_cannot_hold_the_server_or_stop_it_closing() {
    use std::io::Write;
    let dir = TempDir::new("http-stalled");
    let config = ServerConfig { workers: 2, io_timeout: Duration::from_millis(400), ..ServerConfig::default() };
    let (rt, server) = serve(&dir, fast(), config);
    let token = bearer(&sign_in(&rt, "Phone"));
    let auth = [("Authorization", token.as_str())];

    // More clients than there are threads, each of which starts a request and then says
    // nothing more: some stop in the headers, some promise a body and never send it.
    let stalled: Vec<std::net::TcpStream> = (0..6)
        .map(|n| {
            let mut stream = std::net::TcpStream::connect(server.addr()).unwrap();
            let start: &[u8] = if n % 2 == 0 { b"GET /ships/zod/devices HTTP/1.1\r\nHost: x\r\n" } else { b"POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 2048\r\n\r\n" };
            stream.write_all(start).unwrap();
            stream
        })
        .collect();
    // Each is given up on after its allowance, so a real request gets through soon after.
    let started = Instant::now();
    assert_eq!(http(&server, "GET", "/ships/zod/devices", &auth, b"").status, 200);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    drop(stalled);
    drop(server);

    // The allowance is for the whole request, not for each piece of it. A client that keeps
    // sending, a byte at a time, is given up on just the same.
    let server = Server::start(rt.clone(), ServerConfig { workers: 2, io_timeout: Duration::from_millis(400), ..ServerConfig::default() }).unwrap();
    let mut trickle = std::net::TcpStream::connect(server.addr()).unwrap();
    trickle.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
    let (started, mut cut_off) = (Instant::now(), None);
    for byte in b"GET /ships/zod/devices HTTP/1.1\r\nHost: x\r\nX-Slow: ".iter().chain([b'x'; 200].iter()) {
        use std::io::Read;
        // Closed from the other end: a write fails, or a read finds the end of the stream.
        if trickle.write_all(&[*byte]).is_err() || matches!(trickle.read(&mut [0u8; 1]), Ok(0)) {
            cut_off = Some(started.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let cut_off = cut_off.expect("a client that never finished its request was never given up on");
    assert!(cut_off < Duration::from_secs(3), "{cut_off:?}");

    // More waiting connections than the threads and their queue can hold are turned away at
    // the door, not kept. With two threads there is room for ten; of sixteen, some are closed
    // straight away, long before any allowance runs out.
    let patient = Server::start(rt.clone(), ServerConfig { workers: 2, io_timeout: Duration::from_secs(30), ..ServerConfig::default() }).unwrap();
    let crowd: Vec<std::net::TcpStream> = (0..16).map(|_| std::net::TcpStream::connect(patient.addr()).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(500));
    let closed = crowd
        .iter()
        .filter(|stream| {
            use std::io::Read;
            stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
            let mut stream: &std::net::TcpStream = stream;
            !matches!(stream.read(&mut [0u8; 1]), Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
        })
        .count();
    assert!((4..=8).contains(&closed), "{closed} of sixteen were turned away");
    drop(crowd);
    drop(patient);
    drop(server);

    // A server with a long allowance, stopped while clients are silent mid-request, and while
    // a reader is waiting on a log, still stops at once: it cuts them off.
    let server = Server::start(rt.clone(), ServerConfig { workers: 4, io_timeout: Duration::from_secs(60), ..ServerConfig::default() }).unwrap();
    let addr = server.addr();
    let _stalled: Vec<std::net::TcpStream> = (0..2)
        .map(|_| {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream.write_all(b"POST /ships/zod/signin HTTP/1.1\r\nHost: x\r\nContent-Length: 2048\r\n\r\n").unwrap();
            stream
        })
        .collect();
    let mut waiting = std::net::TcpStream::connect(addr).unwrap();
    waiting.write_all(format!("GET /ships/zod/logs/counter/counter/entries?wait=30 HTTP/1.1\r\nHost: x\r\nAuthorization: {token}\r\n\r\n").as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    drop(server);
    assert!(started.elapsed() < Duration::from_secs(5), "stopping took {:?}", started.elapsed());
}

// Ships reaching each other over the network.

use runtime::net::{Directory, NetConfig, NetError, Network};

/// A runtime holding one ship, on the network and listed in the directory.
fn networked(dir: &TempDir, ship: &str, directory: &Arc<Directory>) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, fast()).unwrap());
    rt.create_ship(ship, &kernel(&rt)).unwrap();
    let net = Network::start(rt.clone(), directory.clone(), NetConfig::default()).unwrap();
    directory.set(ship, rt.public_key(ship).unwrap(), net.addr()).unwrap();
    (rt, net)
}

/// The same, with a say in how the network is set up.
fn networked_with(dir: &TempDir, ship: &str, directory: &Arc<Directory>, cfg: NetConfig) -> (Arc<Runtime>, Network) {
    // A network has to be able to carry the largest command its ships may send, so a test
    // that makes messages small makes events small to match.
    // (And likewise the largest checkpoint a log there may have.)
    let most = cfg.max_message_bytes.saturating_sub(4096).min(1 << 20);
    let events = Config { max_event_bytes: most, max_checkpoint_bytes: most, ..fast() };
    let rt = Arc::new(Runtime::open(&dir.0, events).unwrap());
    rt.create_ship(ship, &kernel(&rt)).unwrap();
    let net = Network::start(rt.clone(), directory.clone(), cfg).unwrap();
    directory.set(ship, rt.public_key(ship).unwrap(), net.addr()).unwrap();
    (rt, net)
}

/// A network that gives up quickly, for tests where a call is meant to fail.
fn impatient() -> NetConfig {
    NetConfig { request_timeout: Duration::from_millis(1500), ..NetConfig::default() }
}

#[test]
fn two_ships_reach_each_other_and_each_knows_who_the_other_is() {
    let (a, b) = (TempDir::new("net-a"), TempDir::new("net-b"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked(&a, "~zod", &directory);
    let (_nec, nec_net) = networked(&b, "~nec", &directory);

    // Each end was shown proof of the other's key: the caller reached the ship it meant to,
    // and the ship that answered knows which ship called.
    let answered = zod_net.ping("~zod", "~nec").unwrap();
    assert_eq!((answered.ship.as_str(), answered.seen_as.as_str()), ("nec", "zod"));
    let answered = nec_net.ping("~nec", "~zod").unwrap();
    assert_eq!((answered.ship.as_str(), answered.seen_as.as_str()), ("zod", "nec"));

    // A connection is kept and used again: more calls, no more connections.
    let open = zod_net.open_connections();
    for _ in 0..5 {
        zod_net.ping("zod", "nec").unwrap();
    }
    assert_eq!(zod_net.open_connections(), open);

    // What cannot be asked at all.
    assert!(matches!(zod_net.ping("~nec", "~zod"), Err(NetError::NotHere(_))), "a ship can only call from its own runtime");
    assert!(matches!(zod_net.ping("~zod", "~bus"), Err(NetError::Unlisted(_))));
    assert!(matches!(zod_net.ping("Not A Ship", "~nec"), Err(NetError::NotHere(_))));
}

#[test]
fn two_ships_in_one_runtime_talk_over_the_network_like_any_others() {
    let dir = TempDir::new("net-shared");
    let directory = Directory::new();
    let (rt, net) = networked(&dir, "~zod", &directory);
    rt.create_ship("~nec", &kernel(&rt)).unwrap();
    directory.set("~nec", rt.public_key("~nec").unwrap(), net.addr()).unwrap();

    // One address answers as whichever of its ships is asked for.
    let answered = net.ping("~zod", "~nec").unwrap();
    assert_eq!((answered.ship.as_str(), answered.seen_as.as_str()), ("nec", "zod"));
    let answered = net.ping("~nec", "~zod").unwrap();
    assert_eq!((answered.ship.as_str(), answered.seen_as.as_str()), ("zod", "nec"));
    // A ship listed at this address that the runtime does not hold has no key to show.
    directory.set("~bus", [7; 32], net.addr()).unwrap();
    assert!(matches!(net.ping("~zod", "~bus"), Err(NetError::Unreachable(_))));
}

#[test]
fn a_ship_that_cannot_prove_its_key_is_not_believed() {
    let (a, b, c) = (TempDir::new("net-imp-a"), TempDir::new("net-imp-b"), TempDir::new("net-imp-c"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked_with(&a, "~zod", &directory, impatient());
    let (nec, nec_net) = networked_with(&b, "~nec", &directory, impatient());
    let nec_key = nec.public_key("~nec").unwrap();

    // Another runtime holds a ship it also calls ~nec, with a key of its own. It is not the
    // ship the directory lists, whatever it calls itself.
    let apart = Directory::new();
    let (fake, fake_net) = networked_with(&c, "~nec", &apart, impatient());
    apart.set("~zod", zod_net_key(&directory), zod_net.addr()).unwrap();
    assert_ne!(fake.public_key("~nec").unwrap(), nec_key);

    // Answering as ~nec: traffic for ~nec is sent to the impostor's address. It cannot show
    // the listed key, so the caller does not take it for ~nec.
    directory.set("~nec", nec_key, fake_net.addr()).unwrap();
    assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_))));
    directory.set("~nec", nec_key, nec_net.addr()).unwrap();
    assert_eq!(zod_net.ping("~zod", "~nec").unwrap().ship, "nec");

    // Calling as ~nec: the impostor dials ~zod. Its key is listed for no ship, so ~zod does
    // not answer it.
    assert!(fake_net.ping("~nec", "~zod").is_err());
    // A key is what a caller is known by. Listed under another name, the same runtime is
    // answered, and is taken for that name, not the one it gives its own ship.
    directory.set("~bus", fake.public_key("~nec").unwrap(), fake_net.addr()).unwrap();
    assert_eq!(fake_net.ping("~nec", "~zod").unwrap().seen_as, "bus");
    // One key cannot be listed for two ships.
    assert!(directory.set("~doz", nec_key, nec_net.addr()).is_err());
}

/// The key the directory lists for ~zod.
fn zod_net_key(directory: &Directory) -> [u8; 32] {
    directory.lookup("~zod").unwrap().key
}

#[test]
fn a_change_in_the_directory_ends_what_was_proved_before_it() {
    let (a, b) = (TempDir::new("net-chg-a"), TempDir::new("net-chg-b"));
    let directory = Directory::new();
    let (zod, zod_net) = networked_with(&a, "~zod", &directory, impatient());
    let (nec, nec_net) = networked_with(&b, "~nec", &directory, impatient());
    let (zod_key, nec_key) = (zod.public_key("~zod").unwrap(), nec.public_key("~nec").unwrap());
    zod_net.ping("~zod", "~nec").unwrap();

    // The directory now lists a different key for ~nec. The connection already open was made
    // with the old one, and is not used again: ~nec can no longer be reached as itself.
    directory.set("~nec", [9; 32], nec_net.addr()).unwrap();
    assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_))));
    directory.set("~nec", nec_key, nec_net.addr()).unwrap();
    zod_net.ping("~zod", "~nec").unwrap();

    // The directory drops the caller. Its open connection stops being answered.
    directory.remove("~zod");
    assert!(zod_net.ping("~zod", "~nec").is_err());
    directory.set("~zod", zod_key, zod_net.addr()).unwrap();
    assert_eq!(zod_net.ping("~zod", "~nec").unwrap().seen_as, "zod");
}

#[test]
fn a_ship_that_went_away_and_came_back_is_reached_again() {
    let (a, b) = (TempDir::new("net-back-a"), TempDir::new("net-back-b"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked_with(&a, "~zod", &directory, impatient());
    let (nec, nec_net) = networked_with(&b, "~nec", &directory, impatient());
    zod_net.ping("~zod", "~nec").unwrap();

    // Stopping is prompt, and a ship that is not there is given up on in the time allowed.
    let started = Instant::now();
    drop(nec_net);
    assert!(started.elapsed() < Duration::from_secs(3), "stopping took {:?}", started.elapsed());
    let started = Instant::now();
    assert!(zod_net.ping("~zod", "~nec").is_err());
    assert!(started.elapsed() < Duration::from_secs(4), "giving up took {:?}", started.elapsed());

    // Back at a new address, with the same key.
    let nec_net = Network::start(nec.clone(), directory.clone(), impatient()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    assert_eq!(zod_net.ping("~zod", "~nec").unwrap().ship, "nec");
    assert_eq!(nec_net.ping("~nec", "~zod").unwrap().ship, "zod");
}

#[test]
fn the_network_keeps_working_through_noise_and_refuses_what_is_too_big() {
    let (a, b) = (TempDir::new("net-noise-a"), TempDir::new("net-noise-b"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked_with(&a, "~zod", &directory, impatient());
    let (_nec, nec_net) = networked_with(&b, "~nec", &directory, impatient());

    // Packets that are not from this protocol at all.
    let stray = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for size in [0usize, 1, 20, 1200, 1500] {
        let noise: Vec<u8> = (0..size).map(|n| (n * 31 + size) as u8).collect();
        for _ in 0..20 {
            stray.send_to(&noise, nec_net.addr()).unwrap();
        }
    }
    assert_eq!(zod_net.ping("~zod", "~nec").unwrap().ship, "nec");

    // A ship that takes only small messages refuses a request that is larger, and says so.
    let c = TempDir::new("net-noise-c");
    let (_bus, bus_net) = networked_with(&c, "~bus", &directory, NetConfig { max_message_bytes: 4096, ..impatient() });
    assert_eq!(zod_net.ping("~zod", "~bus").unwrap().ship, "bus");
    let (doz, pad) = ([5u8; 32], [9u8; 32]);
    let public = |seed: &[u8; 32]| ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    directory.set("~doz", public(&doz), "127.0.0.1:9".parse().unwrap()).unwrap();
    let large = ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Ping(ship_proto::Ping { nonce: vec![1; 6000] })) }.encode_to_vec();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let reply = tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((doz, doz)), b"ship/1"), bus_net.addr(), "bus").unwrap().await.unwrap();
        exchange(&connection, &large).await.unwrap()
    });
    assert!(reply.body.is_none() && reply.refused.contains("too large"), "{reply:?}");
    // And a reply larger than the caller takes is not taken. ~pad answers at great length:
    // a caller with room for that hears it, and ~bus does not.
    let (addr, _running, _) = stand_in(pad, pad, true, 8000);
    directory.set("~pad", public(&pad), addr).unwrap();
    assert!(zod_net.ping("~zod", "~pad").is_ok());
    assert!(bus_net.ping("~bus", "~pad").is_err());
    assert_eq!(zod_net.ping("~zod", "~nec").unwrap().ship, "nec");
}

/// What one end of a connection shows of itself: the public key of `shown`, with the means to
/// sign held for `held`. An honest party holds the key it shows.
fn shown_key(provider: &rustls::crypto::CryptoProvider, shown: [u8; 32], held: [u8; 32]) -> Arc<rustls::sign::CertifiedKey> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let (shown, held) = (ed25519_dalek::SigningKey::from_bytes(&shown), ed25519_dalek::SigningKey::from_bytes(&held));
    let mut der = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&held.to_bytes());
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(&held.verifying_key().to_bytes());
    let signer = provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(der).into()).unwrap();
    let public = [&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00][..], &shown.verifying_key().to_bytes()].concat();
    Arc::new(rustls::sign::CertifiedKey::new(vec![CertificateDer::from(public)], signer))
}

/// Whether a caller from outside gets an answer from a ship. The caller speaks QUIC and TLS
/// correctly and accepts whatever key the ship shows; what it shows of itself, and which
/// protocol it asks for, are up to the test.
fn stranger_is_answered(ship_addr: std::net::SocketAddr, shows: Option<[u8; 32]>, protocol: &[u8]) -> bool {
    stranger_showing(ship_addr, shows.map(|seed| (seed, seed)), protocol)
}

/// How a caller from outside connects: it speaks QUIC and TLS correctly and accepts whatever
/// key the ship shows. What it shows of itself (the public key of one seed, signing with
/// another), and which protocol it asks for, are up to the test.
fn stranger_client(shows: Option<([u8; 32], [u8; 32])>, protocol: &[u8]) -> quinn::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};

    #[derive(Debug)]
    struct AnyKey(rustls::crypto::WebPkiSupportedAlgorithms);
    impl ServerCertVerifier for AnyKey {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("only TLS 1.3".into()))
        }
        fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let wants = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyKey(provider.signature_verification_algorithms)));
    let mut tls = match shows {
        None => wants.with_no_client_auth(),
        Some((shown, held)) => {
            let shown = shown_key(&provider, shown, held);
            wants.with_client_cert_resolver(Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(shown)))
        }
    };
    tls.alpn_protocols = vec![protocol.to_vec()];
    quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()))
}

/// A ping, as it goes over the wire.
fn ping_bytes() -> Vec<u8> {
    ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Ping(ship_proto::Ping { nonce: vec![1, 2, 3] })) }.encode_to_vec()
}

/// Send a request on a new stream of a connection and read the reply, if one comes in time.
async fn exchange(connection: &quinn::Connection, request: &[u8]) -> Option<ship_proto::PeerReply> {
    let attempt = async {
        let (mut send, mut receive) = connection.open_bi().await.ok()?;
        send.write_all(request).await.ok()?;
        send.finish().ok()?;
        ship_proto::PeerReply::decode(&*receive.read_to_end(4096).await.ok()?).ok()
    };
    tokio::time::timeout(Duration::from_secs(3), attempt).await.ok().flatten()
}

/// The same, where the caller may show the public key of one seed while signing with another.
fn stranger_showing(ship_addr: std::net::SocketAddr, shows: Option<([u8; 32], [u8; 32])>, protocol: &[u8]) -> bool {
    let client = stranger_client(shows, protocol);
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let attempt = async {
            let connection = endpoint.connect_with(client, ship_addr, "nec").ok()?.await.ok()?;
            exchange(&connection, &ping_bytes()).await?.body
        };
        matches!(tokio::time::timeout(Duration::from_secs(3), attempt).await, Ok(Some(_)))
    })
}

#[test]
fn a_caller_is_answered_only_if_the_directory_lists_its_key() {
    let dir = TempDir::new("net-stranger");
    let directory = Directory::new();
    let (_nec, nec_net) = networked(&dir, "~nec", &directory);
    let seed = [5u8; 32];

    // A caller that shows no key, and one that shows a key the directory does not list.
    assert!(!stranger_is_answered(nec_net.addr(), None, b"ship/1"));
    assert!(!stranger_is_answered(nec_net.addr(), Some(seed), b"ship/1"));
    // Once that key is listed for a ship, the same caller is answered: the key is the whole
    // of what it had to prove.
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    directory.set("~bus", public, "127.0.0.1:9".parse().unwrap()).unwrap();
    assert!(stranger_is_answered(nec_net.addr(), Some(seed), b"ship/1"));
    // A listed caller that asks for some other protocol is not speaking to ships.
    assert!(!stranger_is_answered(nec_net.addr(), Some(seed), b"h3"));
    // Showing a listed key is not enough. The caller has to sign with it, and one that shows
    // that key while holding a different one is found out.
    assert!(!stranger_showing(nec_net.addr(), Some((seed, [6; 32])), b"ship/1"));
}

/// Something at an address that answers as a ship would, showing the public key of `shown`
/// and signing with `held`. It runs until the returned handle is dropped.
fn stand_in_ship(shown: [u8; 32], held: [u8; 32]) -> (std::net::SocketAddr, tokio::runtime::Runtime, Arc<AtomicBool>) {
    stand_in_ship_that(shown, held, true)
}

/// The same, where the stand-in may take requests and never answer them.
fn stand_in_ship_that(shown: [u8; 32], held: [u8; 32], answers: bool) -> (std::net::SocketAddr, tokio::runtime::Runtime, Arc<AtomicBool>) {
    stand_in(shown, held, answers, 0)
}

/// The same, saying when commands are delivered to it that it holds every one up to `claims`.
fn stand_in(shown: [u8; 32], held: [u8; 32], answers: bool, claims: u64) -> (std::net::SocketAddr, tokio::runtime::Runtime, Arc<AtomicBool>) {
    stand_in_with(shown, held, answers, claims, None)
}

/// How a stand-in answers the requests about logs: what it is asked, and what it says back.
type LogAnswers = Arc<dyn Fn(ship_proto::peer_request::Body) -> Option<ship_proto::peer_reply::Body> + Send + Sync>;

/// The same, answering requests about logs as `logs` says.
fn stand_in_with(shown: [u8; 32], held: [u8; 32], answers: bool, claims: u64, logs: Option<LogAnswers>) -> (std::net::SocketAddr, tokio::runtime::Runtime, Arc<AtomicBool>) {
    use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

    /// Takes any caller that holds the key it shows, listed or not.
    #[derive(Debug)]
    struct AnyCaller(rustls::crypto::WebPkiSupportedAlgorithms);
    impl ClientCertVerifier for AnyCaller {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }
        fn verify_client_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("only TLS 1.3".into()))
        }
        fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyCaller(provider.signature_verification_algorithms)))
        .with_cert_resolver(Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(shown_key(&provider, shown, held))));
    tls.alpn_protocols = vec![b"ship/1".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let endpoint = {
        let _entered = tokio.enter();
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    };
    let addr = endpoint.local_addr().unwrap();
    // Set if the stand-in manages to start a request of its own on a connection made to it.
    let started_one = Arc::new(AtomicBool::new(false));
    let started = started_one.clone();
    tokio.spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (started, logs) = (started.clone(), logs.clone());
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else { return };
                let back = connection.clone();
                tokio::spawn(async move {
                    if let Ok(Ok((mut send, _))) = tokio::time::timeout(Duration::from_millis(600), back.open_bi()).await {
                        started.store(send.write_all(b"unasked").await.is_ok(), Ordering::SeqCst);
                    }
                });
                while let Ok((mut send, mut receive)) = connection.accept_bi().await {
                    let Ok(bytes) = receive.read_to_end(4096).await else { return };
                    if !answers {
                        // Keep the stream open and say nothing.
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            drop(send);
                        });
                        continue;
                    }
                    let body = match ship_proto::PeerRequest::decode(&*bytes).ok().and_then(|request| request.body) {
                        Some(ship_proto::peer_request::Body::Ping(ping)) => {
                            // (`claims` also sets how much longer than need be the answer to a ping is.)
                            let ship = format!("nec{}", "x".repeat(claims as usize));
                            ship_proto::peer_reply::Body::Pong(ship_proto::Pong { nonce: ping.nonce, ship, caller: "zod".into() })
                        }
                        Some(ship_proto::peer_request::Body::Deliver(_)) => ship_proto::peer_reply::Body::Delivered(ship_proto::Delivered { last: claims }),
                        Some(about_logs) => match logs.as_ref().and_then(|logs| logs(about_logs)) {
                            Some(body) => body,
                            None => return,
                        },
                        None => return,
                    };
                    let reply = ship_proto::PeerReply { body: Some(body), refused: String::new() };
                    let _ = send.write_all(&reply.encode_to_vec()).await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                }
            });
        }
    });
    (addr, tokio, started_one)
}

#[test]
fn a_ship_that_answers_must_hold_the_key_it_shows() {
    let dir = TempDir::new("net-held");
    let directory = Directory::new();
    let (_zod, zod_net) = networked_with(&dir, "~zod", &directory, impatient());
    let (listed, other) = ([5u8; 32], [6u8; 32]);
    let public = ed25519_dalek::SigningKey::from_bytes(&listed).verifying_key().to_bytes();

    // Something answers at ~nec's address and shows ~nec's listed key, which anyone can copy
    // out of the directory. It signs with a key of its own. The caller does not take it for ~nec.
    let (addr, _running, _) = stand_in_ship(listed, other);
    directory.set("~nec", public, addr).unwrap();
    assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_))));

    // The same stand-in holding the listed key is taken for ~nec. So what made the difference
    // above was the signature, and nothing else about the stand-in.
    let (addr, _running, started_one) = stand_in_ship(listed, listed);
    directory.set("~nec", public, addr).unwrap();
    let answered = zod_net.ping("~zod", "~nec").unwrap();
    // The ship that answered is known for certain. What it says about who called is its word:
    // this stand-in always says ~zod.
    assert_eq!((answered.ship.as_str(), answered.seen_as.as_str()), ("nec", "zod"));
    // Requests go one way on a connection. The ship that was called cannot start any of its
    // own on it, which nothing here would be reading.
    std::thread::sleep(Duration::from_millis(900));
    assert!(!started_one.load(Ordering::SeqCst), "the ship that was called started a request of its own");
}

#[test]
fn only_so_many_ships_may_be_connected_at_once() {
    let (a, b, c) = (TempDir::new("net-cap-a"), TempDir::new("net-cap-b"), TempDir::new("net-cap-c"));
    let directory = Directory::new();
    let (_nec, nec_net) = networked_with(&a, "~nec", &directory, NetConfig { max_connections: 1, ..impatient() });
    let (_zod, zod_net) = networked_with(&b, "~zod", &directory, impatient());
    let (_bus, bus_net) = networked_with(&c, "~bus", &directory, impatient());

    // The first caller takes the one place. The second is turned away while it is taken.
    zod_net.ping("~zod", "~nec").unwrap();
    assert!(bus_net.ping("~bus", "~nec").is_err());
    zod_net.ping("~zod", "~nec").unwrap();
    // When the first goes, the place is free again.
    drop(zod_net);
    let freed = (0..20).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        bus_net.ping("~bus", "~nec").is_ok()
    });
    assert!(freed, "the place was never given up");
    assert_eq!(nec_net.open_connections(), 1);
}

#[test]
fn each_calling_ship_has_its_own_connection_and_is_seen_as_itself() {
    let (a, b) = (TempDir::new("net-two-a"), TempDir::new("net-two-b"));
    let directory = Directory::new();
    let (rt, net) = networked(&a, "~zod", &directory);
    rt.create_ship("~bus", &kernel(&rt)).unwrap();
    directory.set("~bus", rt.public_key("~bus").unwrap(), net.addr()).unwrap();
    let (_nec, _nec_net) = networked(&b, "~nec", &directory);

    // Two ships of one runtime call the same ship. Each is known there by its own key, and a
    // connection made for one is never used for the other.
    for _ in 0..3 {
        assert_eq!(net.ping("~zod", "~nec").unwrap().seen_as, "zod");
        assert_eq!(net.ping("~bus", "~nec").unwrap().seen_as, "bus");
    }
    assert_eq!(net.open_connections(), 2);
}

#[test]
fn a_request_is_not_acted_on_once_its_sender_is_no_longer_listed() {
    let dir = TempDir::new("net-late");
    let directory = Directory::new();
    let (_nec, nec_net) = networked(&dir, "~nec", &directory);
    let seed = [5u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    directory.set("~bus", public, "127.0.0.1:9".parse().unwrap()).unwrap();

    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap().await.unwrap();
        assert!(exchange(&connection, &ping_bytes()).await.is_some_and(|reply| reply.body.is_some()));

        // A request is begun while its sender is listed, and finished after it has been
        // dropped from the directory. It is the whole request that is acted on, so it is at
        // that moment that the sender has to be listed.
        let request = ping_bytes();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(&request[..1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        directory.remove("~bus");
        let _ = send.write_all(&request[1..]).await;
        let _ = send.finish();
        let late = tokio::time::timeout(Duration::from_secs(3), receive.read_to_end(4096)).await;
        let answered = matches!(late, Ok(Ok(bytes)) if ship_proto::PeerReply::decode(&*bytes).is_ok_and(|reply| reply.body.is_some()));
        assert!(!answered, "a request from a ship no longer listed was answered");
        // And the connection it came on is closed.
        assert!(exchange(&connection, &ping_bytes()).await.is_none());
    });
}

#[test]
fn callers_arriving_together_cannot_get_past_the_limit() {
    let dir = TempDir::new("net-rush");
    let directory = Directory::new();
    let (_nec, nec_net) = networked_with(&dir, "~nec", &directory, NetConfig { max_connections: 2, ..NetConfig::default() });
    let names = ["bus", "doz", "fen", "hul", "lyn", "mer", "nup", "pes"];
    for (n, name) in names.iter().enumerate() {
        let public = ed25519_dalek::SigningKey::from_bytes(&[n as u8 + 10; 32]).verifying_key().to_bytes();
        directory.set(name, public, "127.0.0.1:9".parse().unwrap()).unwrap();
    }
    // Eight ships call at the same moment and each holds on to its connection. Two are let in.
    let (addr, gate) = (nec_net.addr(), std::sync::Barrier::new(names.len()));
    let answered: usize = std::thread::scope(|scope| {
        let callers: Vec<_> = (0..names.len())
            .map(|n| {
                let gate = &gate;
                scope.spawn(move || {
                    let seed = [n as u8 + 10; 32];
                    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                    tokio.block_on(async {
                        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                        gate.wait();
                        let connecting = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), addr, "nec").unwrap();
                        let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(3), connecting).await else { return false };
                        let answered = exchange(&connection, &ping_bytes()).await.is_some_and(|reply| reply.body.is_some());
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        answered
                    })
                })
            })
            .collect();
        callers.into_iter().map(|caller| caller.join().unwrap() as usize).sum()
    });
    assert_eq!(answered, 2, "{answered} callers were answered with room for two");
}

#[test]
fn a_ship_reads_only_so_many_requests_at_once() {
    let dir = TempDir::new("net-busy");
    let directory = Directory::new();
    // Room to read one request at a time.
    let cfg = NetConfig { max_message_bytes: 4096, max_reading_bytes: 4096, ..NetConfig::default() };
    let (_nec, nec_net) = networked_with(&dir, "~nec", &directory, cfg);
    let seed = [5u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    directory.set("~bus", public, "127.0.0.1:9".parse().unwrap()).unwrap();

    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap().await.unwrap();
        // One request is begun and left unfinished. It holds the room.
        let request = ping_bytes();
        let (mut slow, mut slow_reply) = connection.open_bi().await.unwrap();
        slow.write_all(&request[..1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // A second is told to try again, at once, and is not read.
        let busy = exchange(&connection, &request).await.expect("an answer");
        assert!(busy.body.is_none() && busy.refused.contains("busy"), "{busy:?}");
        // When the first is finished it is answered, and then there is room again.
        slow.write_all(&request[1..]).await.unwrap();
        slow.finish().unwrap();
        let answer = slow_reply.read_to_end(4096).await.unwrap();
        assert!(ship_proto::PeerReply::decode(&*answer).unwrap().body.is_some());
        assert!(exchange(&connection, &request).await.is_some_and(|reply| reply.body.is_some()));
    });

    // A request that arrives a byte at a time is the same request, and one that is too long
    // is refused however it arrives.
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap().await.unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        for byte in ping_bytes() {
            send.write_all(&[byte]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        send.finish().unwrap();
        assert!(ship_proto::PeerReply::decode(&*receive.read_to_end(4096).await.unwrap()).unwrap().body.is_some());

        let long = ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Ping(ship_proto::Ping { nonce: vec![0; 5000] })) };
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        for piece in long.encode_to_vec().chunks(700) {
            if send.write_all(piece).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = send.finish();
        let reply = tokio::time::timeout(Duration::from_secs(3), receive.read_to_end(4096)).await;
        let answered = matches!(reply, Ok(Ok(bytes)) if ship_proto::PeerReply::decode(&*bytes).is_ok_and(|reply| reply.body.is_some()));
        assert!(!answered, "a request over the limit was answered");
    });

    // Limits that cannot hold are refused when the network starts, without bringing it down.
    let impossible = NetConfig { max_message_bytes: 4096, max_reading_bytes: 100, ..NetConfig::default() };
    assert!(Network::start(_nec.clone(), directory.clone(), impossible).is_err());
    let absurd = NetConfig { max_reading_bytes: usize::MAX, ..NetConfig::default() };
    assert!(Network::start(_nec.clone(), directory.clone(), absurd).is_err());
    // A time limit has to be one a clock can keep: not none, not endless, and not so long that
    // it is no limit.
    for limit in [Duration::ZERO, Duration::MAX, Duration::from_secs(100 * 365 * 24 * 60 * 60), Duration::from_secs(24 * 60 * 60 + 1)] {
        let request = NetConfig { request_timeout: limit, ..NetConfig::default() };
        assert!(Network::start(_nec.clone(), directory.clone(), request).is_err(), "{limit:?}");
        let idle = NetConfig { idle_timeout: limit, ..NetConfig::default() };
        assert!(Network::start(_nec.clone(), directory.clone(), idle).is_err(), "{limit:?}");
    }
    // (On a runtime of its own: this one starts, and a runtime has one network at a time.)
    let spare_dir = TempDir::new("net-day");
    let spare = Arc::new(Runtime::open(&spare_dir.0, fast()).unwrap());
    let day = NetConfig { request_timeout: Duration::from_secs(24 * 60 * 60), ..NetConfig::default() };
    assert!(Network::start(spare, directory.clone(), day).is_ok());
}

#[test]
fn the_network_can_be_used_and_stopped_from_inside_async_code() {
    let (a, b) = (TempDir::new("net-async-a"), TempDir::new("net-async-b"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked(&a, "~zod", &directory);
    let (_nec, nec_net) = networked(&b, "~nec", &directory);
    // Code that is itself running on an async runtime, of its own, calls and then lets go of
    // the network. Neither may bring that code down.
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (taken, zod) = (nec_net.addr().to_string(), _zod.clone());
    tokio.block_on(async move {
        assert_eq!(zod_net.ping("~zod", "~nec").unwrap().ship, "nec");
        // A network that fails to start, here because its address is in use, fails with an
        // error. It has threads of its own by then, and giving them up must not bring this
        // code down either.
        let clash = Network::start(zod, directory.clone(), NetConfig { addr: taken, ..NetConfig::default() });
        assert!(clash.is_err());
        drop(zod_net);
        drop(nec_net);
    });
}

#[test]
fn a_ship_that_never_answers_is_given_up_on_and_cannot_tie_up_every_request() {
    let dir = TempDir::new("net-mute");
    let directory = Directory::new();
    let cfg = NetConfig { max_requests: 2, request_timeout: Duration::from_millis(1500), ..NetConfig::default() };
    let (_zod, zod_net) = networked_with(&dir, "~zod", &directory, cfg);
    let listed = [5u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&listed).verifying_key().to_bytes();
    // A ship that proves who it is, takes requests, and never answers them.
    let (addr, _running, _) = stand_in_ship_that(listed, listed, false);
    directory.set("~nec", public, addr).unwrap();

    std::thread::scope(|scope| {
        // Two requests go out and wait. That is as many as this runtime may have out at once.
        let waiting: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let started = Instant::now();
                    (zod_net.ping("~zod", "~nec"), started.elapsed())
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(500));
        // A third is turned down at once, without waiting its turn behind them.
        let started = Instant::now();
        assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::Unreachable(_))));
        assert!(started.elapsed() < Duration::from_millis(400), "{:?}", started.elapsed());
        // The two are given up on when their time is up, and not before or long after.
        for request in waiting {
            let (outcome, took) = request.join().unwrap();
            assert!(matches!(outcome, Err(NetError::TimedOut)), "{outcome:?}");
            assert!(took >= Duration::from_millis(1400) && took < Duration::from_secs(4), "{took:?}");
        }
    });
    // Their places are free again once they have ended.
    assert!(matches!(zod_net.ping("~zod", "~nec"), Err(NetError::TimedOut)));

    // With room for one request at a time, one after another is always in turn: the place is
    // given up before the caller hears its answer.
    let (b, c) = (TempDir::new("net-turn-b"), TempDir::new("net-turn-c"));
    let (_bus, bus_net) = networked_with(&b, "~bus", &directory, NetConfig { max_requests: 1, ..NetConfig::default() });
    let (_doz, _doz_net) = networked(&c, "~doz", &directory);
    for _ in 0..200 {
        bus_net.ping("~bus", "~doz").unwrap();
    }
}

#[test]
fn a_newer_connection_from_a_ship_takes_the_place_of_its_older_one() {
    let dir = TempDir::new("net-replace");
    let directory = Directory::new();
    let (_nec, nec_net) = networked(&dir, "~nec", &directory);
    let seed = [5u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    directory.set("~bus", public, "127.0.0.1:9".parse().unwrap()).unwrap();

    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connect = || endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap();
        let first = connect().await.unwrap();
        assert!(exchange(&first, &ping_bytes()).await.is_some());
        // The same ship connects again, to the same ship. It holds one place, not two: the
        // first connection is closed, so connecting over and over gains it nothing.
        let second = connect().await.unwrap();
        assert!(exchange(&second, &ping_bytes()).await.is_some());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(first.close_reason().is_some(), "the older connection was left open");
        assert!(exchange(&second, &ping_bytes()).await.is_some());
        // And again. The first connection's ending must not have upset the record of the
        // second, or the second would now be left open beside the third.
        let third = connect().await.unwrap();
        assert!(exchange(&third, &ping_bytes()).await.is_some());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(second.close_reason().is_some(), "the second connection was left open beside the third");
        assert!(exchange(&third, &ping_bytes()).await.is_some());
        assert_eq!(nec_net.open_connections(), 1);
    });
}

#[test]
fn a_runtime_calls_only_so_many_ships_at_once() {
    let (a, b, c) = (TempDir::new("net-calls-a"), TempDir::new("net-calls-b"), TempDir::new("net-calls-c"));
    let directory = Directory::new();
    let (_zod, zod_net) = networked_with(&a, "~zod", &directory, NetConfig { max_calls: 1, ..impatient() });
    let (_nec, nec_net) = networked_with(&b, "~nec", &directory, impatient());
    let (_bus, _bus_net) = networked_with(&c, "~bus", &directory, impatient());

    // One ship may be called at a time. A second is not, while the first connection lives.
    zod_net.ping("~zod", "~nec").unwrap();
    assert!(matches!(zod_net.ping("~zod", "~bus"), Err(NetError::Unreachable(_))));
    zod_net.ping("~zod", "~nec").unwrap();
    // Once that connection has closed, its place is free for another.
    drop(nec_net);
    let freed = (0..20).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        zod_net.ping("~zod", "~bus").is_ok()
    });
    assert!(freed, "the place was never given up");

    // A ship dropped from the directory gives up its place at once, though its connection is
    // still open and the ship itself is still there.
    let d = TempDir::new("net-calls-d");
    let (_doz, _doz_net) = networked_with(&d, "~doz", &directory, impatient());
    directory.remove("~bus");
    assert_eq!(zod_net.ping("~zod", "~doz").unwrap().ship, "doz");
    // Asking for the ship that was dropped says so, and closes what was open to it.
    assert!(matches!(zod_net.ping("~zod", "~bus"), Err(NetError::Unlisted(_))));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(zod_net.open_connections(), 1);
}

// Commands from one ship to another.

/// The counter agent, with its interface open to commands from other ships.
fn open_counter() -> Manifest {
    Manifest { provides: vec![Provide { interface: "counter".into(), public: false, remote: true }], uses: vec![] }
}

/// The tally agent, open to other ships, and allowed to send to the counter and tally agents
/// on `ship`: one ship by name, or "*" for any.
fn far_tally(ship: &str) -> Manifest {
    let to = |agent: &str| Use { ship: ship.into(), agent: agent.into(), interface: agent.into(), read: false, send: true };
    Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true }], uses: vec![to("counter"), to("tally")] }
}

/// A network that tries again soon, for tests where ships come and go.
fn eager() -> NetConfig {
    NetConfig {
        request_timeout: Duration::from_millis(1500),
        retry_delay: Duration::from_millis(50),
        max_retry_delay: Duration::from_millis(300),
        ..NetConfig::default()
    }
}

/// A runtime with one ship running the counter and tally agents, on the network.
fn crewed(dir: &TempDir, ship: &str, directory: &Arc<Directory>, cfg: Config, counter: Manifest, tally: Manifest) -> (Arc<Runtime>, Network) {
    crewed_on(dir, ship, directory, cfg, eager(), counter, tally)
}

/// The same, with a say in how the network is set up.
fn crewed_on(dir: &TempDir, ship: &str, directory: &Arc<Directory>, cfg: Config, net: NetConfig, counter: Manifest, tally: Manifest) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, cfg).unwrap());
    let (counter_hash, tally_hash) = (rt.add_module(&counter_wasm()).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship(ship, &kernel(&rt)).unwrap();
    rt.install(ship, "counter", &counter_hash, &counter).unwrap();
    rt.install(ship, "tally", &tally_hash, &tally).unwrap();
    let net = Network::start(rt.clone(), directory.clone(), net).unwrap();
    directory.set(ship, rt.public_key(ship).unwrap(), net.addr()).unwrap();
    (rt, net)
}

/// Wait for something that happens on its own time, such as a command reaching another ship.
fn eventually(what: &str, holds: impl Fn() -> bool) {
    let started = Instant::now();
    while !holds() {
        assert!(started.elapsed() < Duration::from_secs(15), "never happened: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The value of one of a ship's counters.
fn count(rt: &Runtime, ship: &str, key: &str) -> String {
    String::from_utf8(rt.read(ship, "counter", "counter", key.as_bytes()).unwrap()).unwrap()
}

/// Stop a runtime and its network, and wait until nothing of them is left running, so that
/// the data directory can be opened again.
fn stopped(net: Network, rt: Arc<Runtime>) {
    drop(net);
    eventually("the network lets go of the runtime", || Arc::strong_count(&rt) == 1);
}

/// What one of a ship's agents answers to a read.
fn view(rt: &Runtime, ship: &str, agent: &str, what: &str) -> String {
    String::from_utf8(rt.read(ship, agent, agent, what.as_bytes()).unwrap()).unwrap()
}

/// What a ship's audit log says other ships refused of the commands `agent` sent them,
/// oldest first.
fn refusals(rt: &Runtime, ship: &str, agent: &str) -> Vec<String> {
    let mut found: Vec<String> = rt
        .audit(ship, 1000)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.agent == agent && !entry.ok)
        .map(|entry| String::from_utf8_lossy(&entry.event).into_owned())
        .filter(|line| line.starts_with('~'))
        .collect();
    found.reverse();
    found
}

/// A receipt as it travels: message `seq`, about the command numbered `about`.
fn receipt(seq: u64, about: u64, verdict: ship_proto::Verdict, reason: &str) -> ship_proto::PeerMessage {
    let receipt = ship_proto::Receipt { about, verdict: verdict as i32, reason: reason.into(), ..Default::default() };
    ship_proto::PeerMessage { seq, receipt: Some(receipt), ..Default::default() }
}

/// Deliver messages to the ship `called` at `addr` as whoever holds `seed`, and return the
/// number it says it now holds up to.
fn hand_over(addr: std::net::SocketAddr, called: &str, seed: [u8; 32], messages: Vec<ship_proto::PeerMessage>) -> u64 {
    let request = ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Deliver(ship_proto::Deliver { messages })) }.encode_to_vec();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), addr, called).unwrap().await.unwrap();
        match exchange(&connection, &request).await.and_then(|reply| reply.body) {
            Some(ship_proto::peer_reply::Body::Delivered(delivered)) => delivered.last,
            other => panic!("not a delivery receipt: {other:?}"),
        }
    })
}

/// What a stand-in caller sends to deliver commands: each `(number, target agent, payload)`.
fn delivery(messages: &[(u64, &str, &str)]) -> Vec<u8> {
    let messages = messages
        .iter()
        .map(|(seq, agent, payload)| ship_proto::PeerMessage {
            seq: *seq,
            from_agent: "tally".into(),
            agent: agent.to_string(),
            interface: "counter".into(),
            payload: payload.as_bytes().to_vec(),
            receipt: None,
        })
        .collect();
    ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Deliver(ship_proto::Deliver { messages })) }.encode_to_vec()
}

#[test]
fn a_command_sent_to_another_ship_arrives_once_and_in_order() {
    let (a, b) = (TempDir::new("cmd-a"), TempDir::new("cmd-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));

    // An agent on ~zod sends commands to an agent on ~nec. Each makes the counter there add
    // one and publish the new value, so order and count both show.
    for _ in 0..12 {
        assert_eq!(send(&zod, "~zod", "tally", "tell nec log hits"), "sent");
    }
    eventually("the commands reach ~nec", || nec.log_head("~nec", "counter", "counter").unwrap().is_some_and(|(seq, _)| seq == 12));
    let published = nec.log_entries("~nec", "counter", "counter", 0, NO_LIMIT).unwrap();
    let expected: Vec<String> = (1..=12).map(|n| format!("hits={n}")).collect();
    assert_eq!(payloads(&published), expected);
    // Once the other ship has them, the sender lets go of them.
    eventually("~zod lets go of what was delivered", || zod.outbound_pending("~zod").unwrap() == 0);
    assert_eq!(count(&zod, "~zod", "hits"), "0", "the command ran on the wrong ship");

    // The agent that receives a command is told which ship and which agent sent it.
    send(&zod, "~zod", "tally", "hail nec");
    eventually("the hail reaches ~nec", || nec.read("~nec", "tally", "tally", b"note").unwrap() == b"~zod/tally tally");
    // And the other way.
    send(&nec, "~nec", "tally", "hail zod");
    eventually("the hail reaches ~zod", || zod.read("~zod", "tally", "tally", b"note").unwrap() == b"~nec/tally tally");
}

#[test]
fn commands_wait_for_a_ship_that_is_away_and_arrive_once_when_it_is_back() {
    let (a, b) = (TempDir::new("cmd-away-a"), TempDir::new("cmd-away-b"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the first command arrives", || count(&nec, "~nec", "hits") == "1");

    // ~nec goes away. Commands for it are kept, however many tries fail.
    drop(nec_net);
    for _ in 0..5 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 5);
    // It comes back, at a new address. They arrive, each once.
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("the kept commands arrive", || count(&nec, "~nec", "hits") == "6");
    eventually("~zod lets go of them", || zod.outbound_pending("~zod").unwrap() == 0);

    // The sender goes away with commands still in hand: its whole runtime stops. They are in
    // the ship's file, so a new runtime finds them when its network starts.
    drop(nec_net);
    for _ in 0..3 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    stopped(zod_net, zod);
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    let zod = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 3);
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("the commands a stopped runtime left arrive", || count(&nec, "~nec", "hits") == "9");
    eventually("the new runtime lets go of them", || zod.outbound_pending("~zod").unwrap() == 0);
    // Nothing arrives late or twice.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(count(&nec, "~nec", "hits"), "9");
}

#[test]
fn a_command_delivered_twice_is_taken_once_and_one_out_of_turn_is_not_taken() {
    let dir = TempDir::new("cmd-twice");
    let directory = Directory::new();
    let (nec, nec_net) = crewed(&dir, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    let seed = [5u8; 32];
    directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();

    // A caller that is ~bus, as far as its key goes, delivers commands by hand.
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let deliver = |messages: &[(u64, &str, &str)]| {
        let request = delivery(messages);
        tokio.block_on(async {
            let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap().await.unwrap();
            match exchange(&connection, &request).await.and_then(|reply| reply.body) {
                Some(ship_proto::peer_reply::Body::Delivered(delivered)) => delivered.last,
                other => panic!("not a delivery receipt: {other:?}"),
            }
        })
    };
    let hits = || count(&nec, "~nec", "hits");

    assert_eq!(deliver(&[(1, "counter", "inc hits"), (2, "counter", "inc hits")]), 2);
    eventually("the first two run", || hits() == "2");
    // The same two again, as after a lost receipt. They are passed over.
    assert_eq!(deliver(&[(1, "counter", "inc hits"), (2, "counter", "inc hits")]), 2);
    // One from further ahead. Something is missing before it, so it is not taken.
    assert_eq!(deliver(&[(5, "counter", "inc hits")]), 2);
    // The next in turn is taken. Then a batch that overlaps what is held: only the new one.
    assert_eq!(deliver(&[(3, "counter", "inc hits")]), 3);
    assert_eq!(deliver(&[(2, "counter", "inc hits"), (3, "counter", "inc hits"), (4, "counter", "inc hits")]), 4);
    eventually("four have run", || hits() == "4");

    // A command that could never be run, here for an agent whose name is not a name. It is
    // taken off the sender's hands and dropped, on record, so it cannot hold up what follows.
    assert_eq!(deliver(&[(5, "Not A Name", "inc hits"), (6, "counter", "inc hits")]), 6);
    eventually("the one after it runs", || hits() == "5");
    assert!(nec.audit("~nec", 100).unwrap().iter().any(|entry| entry.agent == "network" && !entry.ok));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(hits(), "5");
    // Each of the six is owed one receipt, the one that could not be run included. ~bus is
    // not there to take them, so they wait.
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 6);

    // What ~bus has delivered survives a sleep and wake: an old command is still old.
    nec.sleep_idle(Duration::ZERO);
    assert_eq!(deliver(&[(6, "counter", "inc hits")]), 6);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(hits(), "5");
}

#[test]
fn sending_to_another_ship_needs_both_owners_to_have_agreed() {
    // The sender's manifest has to name the other ship and agent.
    let (a, b) = (TempDir::new("cmd-perm-a"), TempDir::new("cmd-perm-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), tally_manifest(true));
    assert!(matches!(rejection(&zod, "tally", "tell nec inc hits"), Rejection::Denied(_)));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 0);

    // Naming one ship is not naming another.
    let tally = zod.add_module(&wasm("tally")).unwrap();
    zod.install("~zod", "tally", &tally, &far_tally("bus")).unwrap();
    assert!(matches!(rejection(&zod, "tally", "tell nec inc hits"), Rejection::Denied(_)));
    assert_eq!(send(&zod, "~zod", "tally", "tell bus inc hits"), "sent");
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 1);
    // Being allowed to send to an agent on other ships says nothing about the agent of that
    // name on this one.
    assert!(matches!(rejection(&zod, "tally", "poke hits"), Rejection::Denied(_)));
    // A ship's own name means the ship itself, so that is a local send, and needs local leave.
    zod.install("~zod", "tally", &tally, &far_tally("*")).unwrap();
    assert!(matches!(rejection(&zod, "tally", "tell zod inc hits"), Rejection::Denied(_)));
    assert!(matches!(rejection(&zod, "tally", "tell Not-A-Ship inc hits"), Rejection::Denied(_)));

    // The receiver's manifest has to open the interface to other ships. Without that the
    // command still arrives, is refused when its turn comes, and is on record there. And
    // the sender is told: the refusal, with the reason, is in its own audit log too.
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), counter_manifest(false), far_tally("*"));
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the refused command is on record", || nec.audit("~nec", 100).unwrap().iter().any(|entry| entry.event == b"inc hits" && !entry.ok));
    assert_eq!(count(&nec, "~nec", "hits"), "0");
    eventually("~zod is done with it", || zod.outbound_pending("~zod").unwrap() == 1);
    eventually("~zod is told", || {
        refusals(&zod, "~zod", "tally") == ["~nec did not run command 1 to counter counter: it was not allowed: counter on counter is not open to other ships"]
    });
    // Once the owner of ~nec opens it, later commands run.
    let counter = nec.add_module(&counter_wasm()).unwrap();
    nec.install("~nec", "counter", &counter, &open_counter()).unwrap();
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the command runs", || count(&nec, "~nec", "hits") == "1");
}

#[test]
fn a_ship_with_no_room_holds_commands_back_without_losing_any() {
    let (a, b) = (TempDir::new("cmd-room-a"), TempDir::new("cmd-room-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // ~nec has room for two or three commands in its queue, and runs none by itself.
    let cramped = Config { max_inbox_bytes: 200, max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cramped, open_counter(), far_tally("*"));

    for _ in 0..30 {
        send(&zod, "~zod", "tally", "tell nec log hits");
    }
    // Only what fits is taken. The rest stay with the sender.
    std::thread::sleep(Duration::from_millis(600));
    let taken = nec.pending("~nec").unwrap();
    assert!((1..=3).contains(&taken), "{taken} were taken");
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 30 - taken);
    // As ~nec works through its queue, the rest follow, in order, none twice.
    eventually("all thirty arrive", || {
        nec.run_pending("~nec", 10).unwrap();
        nec.log_head("~nec", "counter", "counter").unwrap().is_some_and(|(seq, _)| seq == 30)
    });
    let expected: Vec<String> = (1..=30).map(|n| format!("hits={n}")).collect();
    assert_eq!(payloads(&nec.log_entries("~nec", "counter", "counter", 0, NO_LIMIT).unwrap()), expected);
    eventually("~zod lets go of them all", || zod.outbound_pending("~zod").unwrap() == 0);
}

#[test]
fn only_so_much_may_wait_to_go_to_one_ship() {
    let dir = TempDir::new("cmd-quota");
    let directory = Directory::new();
    let cfg = Config { max_peer_out_bytes: 300, max_peers: 2, ..fast() };
    let (zod, _zod_net) = crewed(&dir, "~zod", &directory, cfg, open_counter(), far_tally("*"));

    // ~nec is not listed, so nothing sent to it can go.
    let mut kept = 0;
    while kept < 50 && zod.deliver("~zod", "tally", b"tell nec inc hits").is_ok() {
        kept += 1;
    }
    assert!((2..6).contains(&kept), "{kept} were kept");
    assert!(matches!(rejection(&zod, "tally", "tell nec inc hits"), Rejection::Limit(_)));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), kept);
    // Another ship has its own allowance, so one that cannot be reached does not block it.
    assert_eq!(send(&zod, "~zod", "tally", "tell bus inc hits"), "sent");
    // But only so many other ships.
    assert!(matches!(rejection(&zod, "tally", "tell doz inc hits"), Rejection::Limit(_)));
    // A command for another ship goes only if the event that sent it commits.
    assert!(matches!(rejection(&zod, "tally", "tell-then-crash bus"), Rejection::Trap(_)));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), kept + 1);
    // The count survives a sleep and wake.
    zod.sleep_idle(Duration::ZERO);
    assert!(matches!(rejection(&zod, "tally", "tell nec inc hits"), Rejection::Limit(_)));
}

#[test]
fn two_ships_in_one_runtime_send_each_other_commands() {
    let dir = TempDir::new("cmd-shared");
    let directory = Directory::new();
    let (rt, net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (counter, tally) = (rt.add_module(&counter_wasm()).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship("~nec", &kernel(&rt)).unwrap();
    rt.install("~nec", "counter", &counter, &open_counter()).unwrap();
    rt.install("~nec", "tally", &tally, &far_tally("*")).unwrap();
    directory.set("~nec", rt.public_key("~nec").unwrap(), net.addr()).unwrap();

    send(&rt, "~zod", "tally", "tell nec inc hits 3");
    send(&rt, "~nec", "tally", "tell zod inc hits 5");
    eventually("each has the other's command", || count(&rt, "~nec", "hits") == "3" && count(&rt, "~zod", "hits") == "5");
}

#[test]
fn ships_that_disagree_about_what_has_passed_between_them_stop_and_say_so() {
    let (a, b) = (TempDir::new("cmd-step-a"), TempDir::new("cmd-step-b"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let listed = [5u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&listed).verifying_key().to_bytes();

    // Something that is ~nec, as far as its key goes, says it already holds ninety-nine
    // commands from ~zod, which has sent one. One of the two has lost its place. Carrying on
    // would lose commands, so ~zod stops, keeps what it has, and says so.
    let (addr, _running, _) = stand_in(listed, listed, true, 99);
    directory.set("~nec", public, addr).unwrap();
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("~zod notices", || zod_net.stalled() == [("zod".to_string(), "nec".to_string())]);
    send(&zod, "~zod", "tally", "tell nec inc hits");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 2);

    // The other way round: a ship that says it holds fewer than have been delivered and let
    // go of. ~bus first delivers three to a real ship, then finds a stand-in in its place
    // that says it holds none.
    let (bus, bus_net) = crewed(&b, "~bus", &directory, fast(), open_counter(), far_tally("*"));
    let c = TempDir::new("cmd-step-c");
    let (doz, doz_net) = crewed(&c, "~doz", &directory, fast(), open_counter(), far_tally("*"));
    for _ in 0..3 {
        send(&bus, "~bus", "tally", "tell doz inc hits");
    }
    eventually("three arrive", || count(&doz, "~doz", "hits") == "3");
    eventually("~bus lets go of them", || bus.outbound_pending("~bus").unwrap() == 0);
    let doz_key = doz.public_key("~doz").unwrap();
    drop(doz_net);
    drop(doz);
    let seed: [u8; 32] = fs::read(c.0.join("keys").join("doz.key")).unwrap().try_into().unwrap();
    let (addr, _stand_in, _) = stand_in(seed, seed, true, 0);
    directory.set("~doz", doz_key, addr).unwrap();
    send(&bus, "~bus", "tally", "tell doz inc hits");
    eventually("~bus notices", || bus_net.stalled() == [("bus".to_string(), "doz".to_string())]);
    assert_eq!(bus.outbound_pending("~bus").unwrap(), 1);
}

#[test]
fn commands_in_hand_and_what_has_been_taken_go_with_a_ship_that_moves() {
    let (a, b, c, out) = (TempDir::new("cmd-move-a"), TempDir::new("cmd-move-b"), TempDir::new("cmd-move-c"), TempDir::new("cmd-move-out"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    for _ in 0..2 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    eventually("two arrive", || count(&nec, "~nec", "hits") == "2");
    eventually("~zod lets go of them", || zod.outbound_pending("~zod").unwrap() == 0);
    eventually("~zod has both receipts", || zod.unanswered("~zod").unwrap() == 0);
    // (~zod's counter also has a log, for the checks on tampered files further down.)
    send(&zod, "~zod", "counter", "log local");
    // ~nec goes away, and ~zod is moved to another runtime with three commands still in hand.
    drop(nec_net);
    for _ in 0..3 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    drop(zod_net);
    zod.export_ship("~zod", &out.0).unwrap();
    drop(zod);

    // The runtime it moves to has its network up and running already, with nothing to carry.
    // Importing the ship is what tells the network there is now something.
    let moved = Arc::new(Runtime::open(&c.0, fast()).unwrap());
    let moved_net = Network::start(moved.clone(), directory.clone(), eager()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    moved.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(moved.outbound_pending("~zod").unwrap(), 3);
    assert_eq!(moved.unanswered("~zod").unwrap(), 3);
    directory.set("~zod", moved.public_key("~zod").unwrap(), moved_net.addr()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    // They arrive from the ship's new home, and its numbering carries on from where it was:
    // ~nec, which has taken two, takes these as the third to fifth, and the next as the sixth.
    eventually("the three arrive", || count(&nec, "~nec", "hits") == "5");
    send(&moved, "~zod", "tally", "tell nec inc hits");
    eventually("and one more", || count(&nec, "~nec", "hits") == "6");
    eventually("the moved ship lets go of them", || moved.outbound_pending("~zod").unwrap() == 0);
    // The receipts for commands sent before the move find the ship in its new home: all six
    // are answered, each once.
    eventually("every command is answered", || moved.unanswered("~zod").unwrap() == 0 && view(&moved, "~zod", "tally", "receipts").lines().count() == 6);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(count(&nec, "~nec", "hits"), "6");
    let answers = view(&moved, "~zod", "tally", "receipts");
    let about: Vec<&str> = answers.lines().map(|line| line.split(' ').next().unwrap()).collect();
    assert_eq!(about, ["1", "2", "3", "4", "5", "6"], "{answers}");

    // A file that records what has passed between ships wrongly is not a ship file.
    let tampered_in = |label: &str, statement: &str, cfg: Config| {
        let (dir, copy) = (TempDir::new(label), TempDir::new(&format!("{label}-out")));
        for entry in fs::read_dir(&out.0).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), copy.0.join(entry.file_name())).unwrap();
            }
        }
        fs::create_dir_all(copy.0.join("blobs")).unwrap();
        for entry in fs::read_dir(out.0.join("blobs")).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), copy.0.join("blobs").join(entry.file_name())).unwrap();
        }
        rusqlite::Connection::open(copy.0.join("zod.ship")).unwrap().execute_batch(statement).unwrap();
        let rt = Runtime::open(&dir.0, cfg).unwrap();
        let imported = rt.import_ship(&copy.0, "~zod");
        (rt, dir, imported)
    };
    let tampered_for = |label: &str, statement: &str, cfg: Config| tampered_in(label, statement, cfg).2;
    let tampered = |label: &str, statement: &str| tampered_for(label, statement, fast());
    let refused = |label: &str, statement: &str| {
        let result = tampered(label, statement);
        assert!(matches!(result, Err(Error::BadShipFile(_))), "{label}: {result:?}");
    };
    let accepted = |label: &str, statement: &str| {
        let result = tampered(label, statement);
        assert!(result.is_ok(), "{label}: {result:?}");
    };
    accepted("cmd-intact", "SELECT 1");
    // What is recorded as waiting is counted afresh, so a wrong figure there does no harm.
    assert!(tampered("cmd-recount", "UPDATE peers SET out_bytes = 0").is_ok());
    // A command numbered past the last one sent, a gap in the numbers, the newest missing,
    // and one for a ship there is no record of.
    refused("cmd-ahead", "UPDATE peer_out SET seq = seq + 10");
    refused("cmd-gap", "DELETE FROM peer_out WHERE seq = 4");
    refused("cmd-short", "DELETE FROM peer_out WHERE seq = 5");
    refused("cmd-nowhere", "UPDATE peer_out SET peer = 'bus'");
    let renamed = |name: &str| format!("UPDATE peers SET peer = '{name}'; UPDATE peer_out SET peer = '{name}'; UPDATE peer_wait SET peer = '{name}'");
    accepted("cmd-renamed", &renamed("bus"));
    refused("cmd-name", &renamed("Not A Ship"));
    refused("cmd-self", &renamed("zod"));
    // A queued command from another ship carries the number that ship gave it. ~zod has taken
    // two messages from ~nec, so the number is 1 or 2, and no two queued commands share one.
    let queued = |ship: &str, kind: u8, number: u64| {
        format!("INSERT INTO inbox (kind, source, agent, interface, payload, ship, ship_seq) VALUES ({kind}, 'tally', 'counter', 'counter', x'', '{ship}', {number});")
    };
    accepted("cmd-queued", &queued("nec", 1, 1));
    refused("cmd-from", &queued("bus", 1, 1));
    // Something queued from another ship that is neither a command nor a receipt: here a
    // checkpoint request, which is in order when it is said to come from this ship.
    let asking = |ship: &str| format!("INSERT INTO inbox (kind, source, agent, interface, payload, ship) VALUES (4, 'counter', 'counter', 'counter', x'', '{ship}')");
    accepted("cmd-asking", &asking(""));
    refused("cmd-kind", &asking("nec"));
    refused("cmd-unnumbered", &queued("nec", 1, 0));
    refused("cmd-not-taken", &queued("nec", 1, 3));
    refused("cmd-same-number", &[queued("nec", 1, 1), queued("nec", 1, 1)].concat());
    // Commands from one ship are queued in the order that ship numbered them.
    accepted("cmd-in-order", &[queued("nec", 1, 1), queued("nec", 1, 2)].concat());
    refused("cmd-out-of-order", &[queued("nec", 1, 2), queued("nec", 1, 1)].concat());
    // With the receipts waiting to go, no more than the ship would have let itself owe.
    let four = ["UPDATE peers SET received = 4 WHERE peer = 'nec';".to_string(), queued("nec", 1, 1), queued("nec", 1, 2), queued("nec", 1, 3), queued("nec", 1, 4)].concat();
    accepted("cmd-owed", &four);
    let result = tampered_for("cmd-owed-too-many", &four, Config { max_unanswered: 3, ..fast() });
    assert!(matches!(result, Err(Error::BadShipFile(_))), "{result:?}");
    refused("cmd-numbered-local", &queued("", 1, 1));

    // A command recorded as awaiting its receipt is one this ship sent.
    refused("wait-ahead", "UPDATE peer_wait SET seq = seq + 10");
    refused("wait-nowhere", "UPDATE peer_wait SET peer = 'bus'");
    refused("wait-tell", "UPDATE peer_wait SET tell = 2");
    accepted("wait-none", "DELETE FROM peer_wait");
    // And where the command is still waiting to go, the two records agree about it.
    refused("wait-other-sender", "UPDATE peer_wait SET source = 'counter'");
    refused("wait-other-target", "UPDATE peer_wait SET agent = 'tally', interface = 'tally'");

    // A receipt waiting to go is about a command taken from that ship, says what became of
    // it, and names no agent. There is one for a command, and none for one still queued.
    let receipt_out = |seq: u64, payload: &str, source: &str, flag: u8| {
        format!("INSERT INTO peer_out VALUES ('nec', {seq}, '{source}', '', '', x'{payload}', {flag}); UPDATE peers SET sent = {seq} WHERE peer = 'nec';")
    };
    accepted("receipt-out", &receipt_out(6, "08011001", "", 1));
    refused("receipt-about", &receipt_out(6, "08091001", "", 1));
    refused("receipt-verdict", &receipt_out(6, "0801", "", 1));
    refused("receipt-garbage", &receipt_out(6, "ff", "", 1));
    refused("receipt-source", &receipt_out(6, "08011001", "tally", 1));
    refused("receipt-flag", &receipt_out(6, "08011001", "", 2));
    refused("receipt-twice", &[receipt_out(6, "08011001", "", 1), receipt_out(7, "08011001", "", 1)].concat());
    refused("receipt-queued", &[receipt_out(6, "08011001", "", 1), queued("nec", 1, 1)].concat());
    refused("receipt-awaited", &[receipt_out(6, "08011001", "", 1), "INSERT INTO peer_wait VALUES ('nec', 6, 'tally', 'counter', 'counter', 1);".to_string()].concat());
    // A verdict this runtime has no name for is not one it would have given.
    refused("receipt-strange", &receipt_out(6, "0801104d", "", 1));
    // A receipt has a size limit of its own, apart from the one on what agents send.
    let wordy = format!("080110021a28{}", "78".repeat(40));
    let result = tampered_for("receipt-small-events", &receipt_out(6, &wordy, "", 1), Config { max_event_bytes: 30, ..fast() });
    assert!(result.is_ok(), "{result:?}");
    // A command waiting to go is still held to the size of an event.
    let result = tampered_for("cmd-large", "UPDATE peer_out SET payload = zeroblob(40) WHERE seq = 5", Config { max_event_bytes: 30, ..fast() });
    assert!(matches!(result, Err(Error::BadShipFile(_))), "{result:?}");

    // The numbers of messages have a ceiling, and a file is let in only with numbers no more
    // than half way to it, so that a running ship never gets there.
    let numbered = |column: &str, n: u64| format!("DELETE FROM peer_out; DELETE FROM peer_wait; UPDATE peers SET {column} = {n}");
    accepted("cmd-far-along", &numbered("sent", 1 << 61));
    refused("cmd-sent-ceiling", &numbered("sent", (1 << 61) + 1));
    refused("cmd-taken-ceiling", &numbered("received", (1 << 61) + 1));

    // A receipt queued for an agent says where the command went, in step with its own row.
    let told = |ship: &str, payload: &str| {
        format!("INSERT INTO inbox (kind, source, agent, interface, payload, ship) VALUES (5, 'counter', 'tally', 'counter', x'{payload}', '{ship}')")
    };
    let (of_nec, of_bus) = ("0801100122036e65632a07636f756e7465723207636f756e746572", "0801100122036275732a07636f756e7465723207636f756e746572");
    accepted("receipt-told", &told("nec", of_nec));
    refused("receipt-told-ship", &told("nec", of_bus));
    refused("receipt-told-from", &told("bus", of_bus));
    refused("receipt-told-bare", &told("nec", "08011001"));
    // One receipt for a command, about a command this ship sent, and not one it still
    // records as awaited.
    refused("receipt-told-twice", &[told("nec", of_nec), ";".to_string(), told("nec", of_nec)].concat());
    refused("receipt-told-unsent", &told("nec", "0809100122036e65632a07636f756e7465723207636f756e746572"));
    refused("receipt-told-awaited", &told("nec", "0803100122036e65632a07636f756e7465723207636f756e746572"));
    // The verdict is the other ship's word, kept as it came, even one this runtime cannot name.
    accepted("receipt-told-strange", &told("nec", "0801104d22036e65632a07636f756e7465723207636f756e746572"));
    // A receipt may be queued while the command it answers is still waiting to go (the other
    // ship answered early). The two must then be about the same command: sent by the agent
    // the receipt is for, and a command, not a receipt.
    let early = "DELETE FROM peer_wait WHERE seq = 3;";
    let about_3 = "0803100122036e65632a07636f756e7465723207636f756e746572";
    accepted("receipt-early", &[early, &told("nec", about_3)].concat());
    let for_another = format!("INSERT INTO inbox (kind, source, agent, interface, payload, ship) VALUES (5, 'counter', 'counter', 'counter', x'{about_3}', 'nec')");
    refused("receipt-early-other", &[early, &for_another].concat());
    let about_6 = "0806100122036e65632a07636f756e7465723207636f756e746572";
    refused("receipt-about-receipt", &[receipt_out(6, "08011001", "", 1), told("nec", about_6)].concat());
}

// Receipts: what became of a command on the ship it was sent to.

#[test]
fn every_command_sent_to_another_ship_is_answered_once() {
    let (a, b) = (TempDir::new("receipt-a"), TempDir::new("receipt-b"));
    let directory = Directory::new();
    // ~zod's tally agent may send to three agents on other ships. ~nec has the first open to
    // other ships, the second closed, and no third.
    let to = |agent: &str| Use { ship: "*".into(), agent: agent.into(), interface: agent.into(), read: false, send: true };
    let sender = Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: false }], uses: vec![to("counter"), to("tally"), to("ghost")] };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), sender);
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), tally_manifest(true));

    // One that runs, one whose handler fails, one to a closed interface, one to no agent.
    send(&zod, "~zod", "tally", "tell nec inc hits");
    assert_eq!(view(&zod, "~zod", "tally", "last-sent"), "1");
    assert_eq!(send(&zod, "~zod", "tally", "far nec counter crash x"), "2");
    assert_eq!(send(&zod, "~zod", "tally", "far nec tally note"), "3");
    assert_eq!(send(&zod, "~zod", "tally", "far nec ghost boo"), "4");

    // The agent is handed one receipt for each, in order, saying which command it is about,
    // where that went, and what became of it. What a kernel said is passed on. How an agent
    // failed is not. The receipt is filed as coming from the agent the command was sent to.
    eventually("every command is answered", || zod.unanswered("~zod").unwrap() == 0 && view(&zod, "~zod", "tally", "receipts").lines().count() == 4);
    let expected = "\
1 ~nec/counter counter ran [] from ~nec/counter counter
2 ~nec/counter counter failed [the agent failed] from ~nec/counter counter
3 ~nec/tally tally denied [tally on tally is not open to other ships] from ~nec/tally tally
4 ~nec/ghost ghost denied [no agent named ghost] from ~nec/ghost ghost
";
    assert_eq!(view(&zod, "~zod", "tally", "receipts"), expected);
    assert_eq!(count(&nec, "~nec", "hits"), "1");
    assert_eq!(count(&nec, "~nec", "x"), "0");
    // Each one that did not run is in the sender's audit log, against the agent that sent it.
    assert_eq!(
        refusals(&zod, "~zod", "tally"),
        [
            "~nec did not run command 2 to counter counter: the agent failed: the agent failed",
            "~nec did not run command 3 to tally tally: it was not allowed: tally on tally is not open to other ships",
            "~nec did not run command 4 to ghost ghost: it was not allowed: no agent named ghost",
        ]
    );
    // How the handler on ~nec failed stays on ~nec.
    assert!(!view(&zod, "~zod", "tally", "receipts").contains("crash requested"));
    // Nothing is left over at either end, and nothing comes twice.
    eventually("nothing is left to go", || zod.outbound_pending("~zod").unwrap() == 0 && nec.outbound_pending("~nec").unwrap() == 0);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(view(&zod, "~zod", "tally", "receipts"), expected);

    // A command that runs out of fuel there is answered too.
    send(&zod, "~zod", "tally", "far nec counter spin");
    eventually("the fifth is answered", || view(&zod, "~zod", "tally", "receipts").lines().count() == 5);
    let answers = view(&zod, "~zod", "tally", "receipts");
    let last = answers.lines().last().unwrap();
    assert!(last.starts_with("5 ~nec/counter counter failed [it "), "{last}");
}

#[test]
fn an_agent_with_no_receipt_handler_is_not_run_for_one() {
    let (a, b) = (TempDir::new("receipt-none-a"), TempDir::new("receipt-none-b"));
    let directory = Directory::new();
    // The counter agent has no receipt handler. Here it may send to counters on other ships.
    let passing = Manifest {
        provides: vec![Provide { interface: "counter".into(), public: false, remote: true }],
        uses: vec![Use { ship: "*".into(), agent: "counter".into(), interface: "counter".into(), read: false, send: true }],
    };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), passing, far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));

    assert_eq!(send(&zod, "~zod", "counter", "pass nec inc hits"), "1");
    eventually("it runs", || count(&nec, "~nec", "hits") == "1");
    eventually("and is answered", || zod.unanswered("~zod").unwrap() == 0);
    // The receipt closed the record of the command, and that is all: no event ran on ~zod.
    assert_eq!(zod.pending("~zod").unwrap(), 0);
    assert_eq!(zod.audit("~zod", 100).unwrap().len(), 1);

    // A refusal is still written down, against the agent that sent the command.
    let counter = nec.add_module(&counter_wasm()).unwrap();
    nec.install("~nec", "counter", &counter, &counter_manifest(false)).unwrap();
    assert_eq!(send(&zod, "~zod", "counter", "pass nec inc hits"), "2");
    eventually("the refusal is on record", || {
        refusals(&zod, "~zod", "counter") == ["~nec did not run command 2 to counter counter: it was not allowed: counter on counter is not open to other ships"]
    });
    assert_eq!(zod.unanswered("~zod").unwrap(), 0);
    assert_eq!(zod.pending("~zod").unwrap(), 0);
    assert_eq!(zod.audit("~zod", 100).unwrap().len(), 3);
}

#[test]
fn a_receipt_waits_for_a_ship_that_is_away() {
    let (a, b) = (TempDir::new("receipt-away-a"), TempDir::new("receipt-away-b"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // ~nec takes commands but runs them only when told to.
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let (nec, nec_net) = crewed(&b, "~nec", &directory, patient.clone(), open_counter(), far_tally("*"));

    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("~nec has the command", || nec.pending("~nec").unwrap() == 1);
    eventually("~zod knows it does", || zod.outbound_pending("~zod").unwrap() == 0);
    // Delivered, but not yet run: no receipt yet.
    assert_eq!(zod.unanswered("~zod").unwrap(), 1);
    assert_eq!(view(&zod, "~zod", "tally", "receipts"), "");

    // ~zod goes away. ~nec runs the command and has a receipt it cannot deliver. Then ~nec
    // stops too. The receipt is in its file.
    drop(zod_net);
    nec.run_pending("~nec", 10).unwrap();
    assert_eq!(count(&nec, "~nec", "hits"), "1");
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 1);
    stopped(nec_net, nec);

    // Both come back, at new addresses. The receipt arrives, once.
    let nec = Arc::new(Runtime::open(&b.0, patient).unwrap());
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 1);
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("the receipt arrives", || view(&zod, "~zod", "tally", "receipts") == "1 ~nec/counter counter ran [] from ~nec/counter counter\n");
    eventually("and ~nec lets go of it", || nec.outbound_pending("~nec").unwrap() == 0);
    assert_eq!(zod.unanswered("~zod").unwrap(), 0);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(view(&zod, "~zod", "tally", "receipts").lines().count(), 1);
    assert_eq!(count(&nec, "~nec", "hits"), "1");
}

#[test]
fn a_receipt_is_believed_only_for_a_command_that_was_sent_to_that_ship() {
    let dir = TempDir::new("receipt-false");
    let directory = Directory::new();
    let (nec, nec_net) = crewed(&dir, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    let (bus, doz) = ([5u8; 32], [6u8; 32]);
    let public = |seed: &[u8; 32]| ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    directory.set("~bus", public(&bus), "127.0.0.1:9".parse().unwrap()).unwrap();
    directory.set("~doz", public(&doz), "127.0.0.1:9".parse().unwrap()).unwrap();
    use ship_proto::Verdict;
    let receipts = || view(&nec, "~nec", "tally", "receipts");

    // ~nec has sent one command to ~bus. It cannot be delivered, but it has been sent.
    send(&nec, "~nec", "tally", "tell bus inc hits");
    assert_eq!(nec.unanswered("~nec").unwrap(), 1);

    // ~doz says command 1 ran. ~nec sent ~doz nothing, so that answers nothing. It is taken,
    // so that it does not hold up what ~doz sends next, and dropped.
    assert_eq!(hand_over(nec_net.addr(), "nec", doz, vec![receipt(1, 1, Verdict::Ran, "")]), 1);
    // ~bus answers a command ~nec never sent it.
    assert_eq!(hand_over(nec_net.addr(), "nec", bus, vec![receipt(1, 7, Verdict::Ran, "")]), 1);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(nec.unanswered("~nec").unwrap(), 1);
    assert_eq!(receipts(), "");
    assert_eq!(nec.pending("~nec").unwrap(), 0);

    // ~bus answers the command it was sent. The reason is the other ship's words: it is cut
    // to length and anything that is not plain text is taken out before it is kept.
    let long = format!("no\u{7}\nway {}", "x".repeat(500));
    assert_eq!(hand_over(nec_net.addr(), "nec", bus, vec![receipt(2, 1, Verdict::Denied, &long)]), 2);
    eventually("the agent is told", || receipts().lines().count() == 1);
    let told = receipts();
    assert!(told.starts_with("1 ~bus/counter counter denied [no  way xxx"), "{told}");
    assert_eq!(told.find(']').unwrap() - told.find('[').unwrap() - 1, 200, "{told}");
    assert_eq!(nec.unanswered("~nec").unwrap(), 0);
    let noted = refusals(&nec, "~nec", "tally");
    assert_eq!(noted.len(), 1);
    assert!(noted[0].starts_with("~bus did not run command 1 to counter counter: it was not allowed: no  way xxx"), "{noted:?}");

    // A second answer to the same command, and the first one sent again, change nothing.
    assert_eq!(hand_over(nec_net.addr(), "nec", bus, vec![receipt(2, 1, Verdict::Denied, "again"), receipt(3, 1, Verdict::Ran, "")]), 3);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(receipts(), told);
    assert_eq!(refusals(&nec, "~nec", "tally").len(), 1);

    // A verdict this runtime has no name for is passed on as it is, and counts as not run.
    send(&nec, "~nec", "tally", "tell bus inc hits");
    let mut strange = receipt(4, 2, Verdict::Ran, "");
    strange.receipt.as_mut().unwrap().verdict = 77;
    assert_eq!(hand_over(nec_net.addr(), "nec", bus, vec![strange]), 4);
    eventually("the agent is told", || receipts().lines().count() == 2);
    assert!(receipts().lines().last().unwrap().starts_with("2 ~bus/counter counter unknown []"), "{}", receipts());
    assert_eq!(refusals(&nec, "~nec", "tally").len(), 2);
}

#[test]
fn only_so_many_commands_may_be_unanswered() {
    // The sender's side: a ship that does not answer is sent only so many.
    let (a, b) = (TempDir::new("unanswered-a"), TempDir::new("unanswered-b"));
    let directory = Directory::new();
    let cfg = Config { max_unanswered: 3, ..fast() };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, cfg, open_counter(), far_tally("*"));
    for _ in 0..3 {
        send(&zod, "~zod", "tally", "tell bus inc hits");
    }
    assert!(matches!(rejection(&zod, "tally", "tell bus inc hits"), Rejection::Limit(_)));
    assert_eq!(zod.unanswered("~zod").unwrap(), 3);
    // Another ship has its own count.
    send(&zod, "~zod", "tally", "tell doz inc hits");

    // The receiver's side: a ship that sends commands but will not take the receipts for
    // them gets no more commands taken. ~bus hands over five. ~nec takes two.
    let cfg = Config { max_unanswered: 2, max_queued_per_deliver: 0, ..fast() };
    let (nec, nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), far_tally("*"));
    let seed = [5u8; 32];
    directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    let five: Vec<(u64, &str, &str)> = (1..=5).map(|n| (n, "counter", "inc hits")).collect();
    let hand = || {
        let request = ship_proto::PeerRequest::decode(&*delivery(&five)).unwrap();
        let Some(ship_proto::peer_request::Body::Deliver(deliver)) = request.body else { unreachable!() };
        hand_over(nec_net.addr(), "nec", seed, deliver.messages)
    };
    assert_eq!(hand(), 2);
    // Sent again, the rest are still not taken: the two that are queued count as owed.
    assert_eq!(hand(), 2);
    // Running them does not change that: the two receipts are still owed, since ~bus is not
    // there to take them.
    nec.run_pending("~nec", 10).unwrap();
    assert_eq!(count(&nec, "~nec", "hits"), "2");
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 2);
    assert_eq!(hand(), 2);
    assert_eq!(nec.pending("~nec").unwrap(), 0);
}

#[test]
fn receipts_wait_for_room_and_none_is_lost() {
    let (a, b) = (TempDir::new("receipt-room-a"), TempDir::new("receipt-room-b"));
    let directory = Directory::new();
    // ~zod has room in its queue for one receipt at a time, and runs none by itself.
    let cramped = Config { max_inbox_bytes: 160, max_queued_per_deliver: 0, ..fast() };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, cramped, open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    for _ in 0..8 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    eventually("all eight run", || count(&nec, "~nec", "hits") == "8");
    // ~nec has eight receipts. ~zod takes what it has room for, and the rest stay with ~nec.
    std::thread::sleep(Duration::from_millis(600));
    let taken = zod.pending("~zod").unwrap();
    assert!((1..=2).contains(&taken), "{taken} were taken");
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 8 - taken);
    // As ~zod works through its queue the rest follow, in order, each once.
    eventually("all eight receipts arrive", || {
        zod.run_pending("~zod", 10).unwrap();
        view(&zod, "~zod", "tally", "receipts").lines().count() == 8
    });
    let answers = view(&zod, "~zod", "tally", "receipts");
    let about: Vec<&str> = answers.lines().map(|line| line.split(' ').next().unwrap()).collect();
    assert_eq!(about, ["1", "2", "3", "4", "5", "6", "7", "8"]);
    eventually("~nec lets go of them", || nec.outbound_pending("~nec").unwrap() == 0);
    assert_eq!(zod.unanswered("~zod").unwrap(), 0);
}

#[test]
fn a_receipt_for_an_agent_that_no_longer_takes_them_is_let_go() {
    let (a, b) = (TempDir::new("receipt-gone-a"), TempDir::new("receipt-gone-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, patient, open_counter(), far_tally("*"));

    // The tally agent sends a command, and asks to be told what becomes of it. Before the
    // answer comes, its module is replaced by one that has no receipt handler.
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("~nec has the command", || nec.pending("~nec").unwrap() == 1);
    let other = zod.add_module(&counter_wasm()).unwrap();
    zod.install("~zod", "tally", &other, &far_tally("*")).unwrap();
    nec.run_pending("~nec", 10).unwrap();

    // The receipt closes the record of the command. There is nobody to hand it to, and that
    // is not a failure.
    eventually("the receipt is dealt with", || zod.unanswered("~zod").unwrap() == 0 && zod.pending("~zod").unwrap() == 0);
    std::thread::sleep(Duration::from_millis(200));
    assert!(zod.audit("~zod", 100).unwrap().iter().all(|entry| entry.ok));
}

#[test]
fn a_delivery_holds_only_so_many_messages() {
    let dir = TempDir::new("cmd-many");
    let directory = Directory::new();
    let (nec, nec_net) = crewed(&dir, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    let seed = [5u8; 32];
    directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();
    let deliver = |count: u64| {
        let messages = (1..=count).map(|seq| ship_proto::PeerMessage { seq, ..Default::default() }).collect();
        let request = ship_proto::PeerRequest { body: Some(ship_proto::peer_request::Body::Deliver(ship_proto::Deliver { messages })) }.encode_to_vec();
        let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio.block_on(async {
            let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), nec_net.addr(), "nec").unwrap().await.unwrap();
            exchange(&connection, &request).await.unwrap()
        })
    };
    // A megabyte holds a great many empty messages, each of which would cost far more to
    // unpack than to send. One more than a delivery may hold, and the request is refused
    // before any of it is unpacked.
    for count in [257, 150_000] {
        let reply = deliver(count);
        assert!(reply.body.is_none() && reply.refused.contains("too many"), "{reply:?}");
    }
    assert_eq!(nec.pending("~nec").unwrap(), 0);
    // As many as a delivery may hold are taken. These are not commands that could be run, so
    // each is refused, up to as many receipts as ~nec will owe one ship.
    let reply = deliver(256);
    assert!(matches!(reply.body, Some(ship_proto::peer_reply::Body::Delivered(ship_proto::Delivered { last: 256 }))), "{reply:?}");
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 256);
}

#[test]
fn what_an_agent_ran_into_is_not_told_to_the_ship_that_asked() {
    let (a, b) = (TempDir::new("receipt-quiet-a"), TempDir::new("receipt-quiet-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // ~nec's tally agent is open to other ships. It may send to other ships, but may not read
    // the counter. ~nec lets any one ship have a single command unanswered.
    let cfg = Config { max_unanswered: 1, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), far_tally("*"));

    // Asked to read the counter, it is refused by its own ship. Asked twice to send to a
    // third ship, the second runs into ~nec's limit. Both refusals name things that are
    // ~nec's own business: what its agent tried to read, and which ship it talks to.
    send(&zod, "~zod", "tally", "far nec tally peek hits");
    send(&zod, "~zod", "tally", "far nec tally tell doz inc hits");
    send(&zod, "~zod", "tally", "far nec tally tell doz inc hits");
    eventually("all three are answered", || view(&zod, "~zod", "tally", "receipts").lines().count() == 3);
    let expected = "\
1 ~nec/tally tally failed [the agent failed] from ~nec/tally tally
2 ~nec/tally tally ran [] from ~nec/tally tally
3 ~nec/tally tally limit [a limit on that ship was reached] from ~nec/tally tally
";
    assert_eq!(view(&zod, "~zod", "tally", "receipts"), expected);
    // ~nec's own record has the particulars.
    assert_eq!(nec.unanswered("~nec").unwrap(), 1);
    assert_eq!(nec.audit("~nec", 100).unwrap().iter().filter(|entry| entry.agent == "tally" && !entry.ok).count(), 2);
    // ~zod's has only what it was told.
    let told = refusals(&zod, "~zod", "tally").join("\n");
    assert!(!told.contains("doz") && !told.contains("may not") && !told.contains("counter"), "{told}");
}

#[test]
fn a_message_too_large_to_ever_queue_does_not_block_what_follows() {
    let (a, b) = (TempDir::new("cmd-large-a"), TempDir::new("cmd-large-b"));
    let directory = Directory::new();
    // ~zod's queue is too small for a receipt that carries a reason. ~nec's is too small for
    // a command of two hundred bytes. Both hold shorter things.
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, Config { max_inbox_bytes: 100, ..fast() }, open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, Config { max_inbox_bytes: 200, ..fast() }, open_counter(), far_tally("*"));

    // A command ~nec could never queue. Waiting for room would mean waiting for ever, with
    // everything after it held up behind. It is refused, and the next one runs.
    send(&zod, "~zod", "tally", &format!("tell nec inc {}", "k".repeat(200)));
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the one after it runs", || count(&nec, "~nec", "hits") == "1");
    // The refusal carries a reason, so its receipt is more than ~zod's queue could ever hold.
    // The record of the command is closed all the same, and the audit log says the agent
    // went untold. The receipt after it, which is short, reaches the agent.
    eventually("both are answered", || zod.unanswered("~zod").unwrap() == 0);
    eventually("the agent has the second", || view(&zod, "~zod", "tally", "receipts") == "2 ~nec/counter counter ran [] from ~nec/counter counter\n");
    assert_eq!(
        refusals(&zod, "~zod", "tally"),
        ["~nec did not run command 1 to counter counter: a limit was reached: larger than that ship can hold (the receipt is too large for this ship's queue, so the agent was not told)"]
    );
}

#[test]
fn a_runtime_has_one_network_and_one_slow_ship_does_not_hold_up_the_rest() {
    let (a, b) = (TempDir::new("net-one-a"), TempDir::new("net-one-b"));
    let directory = Directory::new();
    let rt = Arc::new(Runtime::open(&a.0, fast()).unwrap());
    let (counter, tally) = (rt.add_module(&counter_wasm()).unwrap(), rt.add_module(&wasm("tally")).unwrap());
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "counter", &counter, &open_counter()).unwrap();
    rt.install("~zod", "tally", &tally, &far_tally("*")).unwrap();
    assert!(Network::start(rt.clone(), directory.clone(), NetConfig { max_carrying: 0, ..eager() }).is_err());
    // Nor does a network start for ships whose files may be so small that, once what every
    // ship file needs is taken off, the largest command they accept could never fit.
    let tiny_dir = TempDir::new("net-one-tiny");
    let tiny = Arc::new(Runtime::open(&tiny_dir.0, Config { max_ship_bytes: 96 << 10, ..fast() }).unwrap());
    assert!(Network::start(tiny.clone(), directory.clone(), eager()).is_err());
    let enough_dir = TempDir::new("net-one-enough");
    let enough = Arc::new(Runtime::open(&enough_dir.0, Config { max_ship_bytes: 256 << 10, ..fast() }).unwrap());
    assert!(Network::start(enough, directory.clone(), eager()).is_ok());

    // One delivery at a time. Starting a second network while the first runs is refused, and
    // that refusal does not disturb the first. Once the first has stopped, another may start.
    let one = NetConfig { max_carrying: 1, ..eager() };
    let first = Network::start(rt.clone(), directory.clone(), one.clone()).unwrap();
    assert!(Network::start(rt.clone(), directory.clone(), one.clone()).is_err());
    drop(first);
    let net = Network::start(rt.clone(), directory.clone(), one).unwrap();
    assert!(Network::start(rt.clone(), directory.clone(), eager()).is_err());
    directory.set("~zod", rt.public_key("~zod").unwrap(), net.addr()).unwrap();

    // ~bus is listed at an address where nothing answers, so every try at it runs out of
    // time. ~nec is there. With one delivery at a time, ~nec still gets its command.
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    directory.set("~bus", [7u8; 32], "127.0.0.1:9".parse().unwrap()).unwrap();
    for _ in 0..3 {
        send(&rt, "~zod", "tally", "tell bus inc hits");
    }
    send(&rt, "~zod", "tally", "tell nec inc hits");
    eventually("~nec has its command", || count(&nec, "~nec", "hits") == "1");
    eventually("and ~zod its receipt", || view(&rt, "~zod", "tally", "receipts").lines().count() == 1);
    assert_eq!(rt.outbound_pending("~zod").unwrap(), 3);
}

#[test]
fn every_command_that_is_taken_is_run_however_many_arrive_at_once() {
    let (a, b) = (TempDir::new("cmd-all-a"), TempDir::new("cmd-all-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));

    // A hundred and fifty commands pile up while ~nec is away, and arrive together when it
    // is back. ~nec runs a ship's queue sixty-four events at a time. It has said it holds
    // them all, so nobody will send them again: it has to keep going until all have run.
    drop(nec_net);
    for _ in 0..150 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("all of them run", || count(&nec, "~nec", "hits") == "150");
    eventually("and are answered", || zod.unanswered("~zod").unwrap() == 0 && view(&zod, "~zod", "tally", "receipts").lines().count() == 150);

    // Commands that were taken and not yet run when a runtime stopped are run when its
    // network next starts, with nothing new arriving to prompt it. Here ~nec first takes
    // three without running them.
    stopped(nec_net, nec);
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let nec = Arc::new(Runtime::open(&b.0, patient).unwrap());
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    for _ in 0..3 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    eventually("~nec takes them", || nec.pending("~nec").unwrap() == 3 && zod.outbound_pending("~zod").unwrap() == 0);
    assert_eq!(count(&nec, "~nec", "hits"), "150");
    stopped(nec_net, nec);
    let nec = Arc::new(Runtime::open(&b.0, fast()).unwrap());
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("they run", || count(&nec, "~nec", "hits") == "153");
    eventually("and are answered", || zod.unanswered("~zod").unwrap() == 0);

    // The same holds for a ship that moves with commands taken and not yet run: the runtime
    // it arrives in runs them, though its network was already up and nothing new arrives.
    stopped(nec_net, nec);
    let nec = Arc::new(Runtime::open(&b.0, Config { max_queued_per_deliver: 0, ..fast() }).unwrap());
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    for _ in 0..2 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    eventually("~nec takes them", || nec.pending("~nec").unwrap() == 2 && zod.outbound_pending("~zod").unwrap() == 0);
    let (c, out) = (TempDir::new("cmd-all-c"), TempDir::new("cmd-all-out"));
    drop(nec_net);
    nec.export_ship("~nec", &out.0).unwrap();
    drop(nec);
    let moved = Arc::new(Runtime::open(&c.0, fast()).unwrap());
    let moved_net = Network::start(moved.clone(), directory.clone(), eager()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    moved.import_ship(&out.0, "~nec").unwrap();
    directory.set("~nec", moved.public_key("~nec").unwrap(), moved_net.addr()).unwrap();
    eventually("they run in the ship's new home", || count(&moved, "~nec", "hits") == "155");
    eventually("and are answered", || zod.unanswered("~zod").unwrap() == 0);
}

#[test]
fn a_ship_with_small_events_that_has_had_receipts_can_still_move() {
    let (a, b, c, out) = (TempDir::new("receipt-small-a"), TempDir::new("receipt-small-b"), TempDir::new("receipt-small-c"), TempDir::new("receipt-small-out"));
    let directory = Directory::new();
    // ~zod takes no event of more than thirty bytes. A receipt is the runtime's own record
    // and may be larger than that, and so may what the audit log says about it.
    let small = Config { max_event_bytes: 30, max_checkpoint_bytes: 30, ..fast() };
    let to = |agent: &str| Use { ship: "*".into(), agent: agent.into(), interface: agent.into(), read: false, send: true };
    let sender = Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: false }], uses: vec![to("ghost")] };
    let rt = Arc::new(Runtime::open(&a.0, small.clone()).unwrap());
    let tally = rt.add_module(&wasm("tally")).unwrap();
    rt.create_ship("~zod", &kernel(&rt)).unwrap();
    rt.install("~zod", "tally", &tally, &sender).unwrap();
    let relaxed = NetConfig { max_message_bytes: 8192, max_reading_bytes: 1 << 20, ..eager() };
    let net = Network::start(rt.clone(), directory.clone(), relaxed).unwrap();
    directory.set("~zod", rt.public_key("~zod").unwrap(), net.addr()).unwrap();
    let (_nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));

    send(&rt, "~zod", "tally", "far nec ghost boo");
    eventually("the refusal comes back", || view(&rt, "~zod", "tally", "receipts").lines().count() == 1);
    assert!(rt.audit("~zod", 100).unwrap().iter().any(|entry| entry.event.len() > 30));
    drop(net);
    rt.export_ship("~zod", &out.0).unwrap();
    let other = Runtime::open(&c.0, small).unwrap();
    other.import_ship(&out.0, "~zod").unwrap();
    assert_eq!(view(&other, "~zod", "tally", "receipts"), view(&rt, "~zod", "tally", "receipts"));

    // A network that could not carry the largest command its ships may send does not start.
    let d = TempDir::new("receipt-small-d");
    let spare = Arc::new(Runtime::open(&d.0, fast()).unwrap());
    let cramped = NetConfig { max_message_bytes: 1 << 20, ..eager() };
    assert!(Network::start(spare.clone(), directory.clone(), cramped).is_err());
    // With room for the largest command and what goes round it, it does.
    let roomy = NetConfig { max_message_bytes: (1 << 20) + 4096, ..eager() };
    assert!(Network::start(spare, directory.clone(), roomy).is_ok());
}

#[test]
fn one_command_from_outside_cannot_keep_a_ship_running_for_ever() {
    let (a, b) = (TempDir::new("cmd-chain-a"), TempDir::new("cmd-chain-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));

    // ~nec's tally agent answers a ping by sending itself the next one, without end. ~zod
    // sets it off. The command from outside is run, and so is one round of what follows
    // from it: sixty-four events. The rest wait in the queue like any others.
    send(&zod, "~zod", "tally", "far nec tally ping 0");
    eventually("the chain runs its round", || view(&nec, "~nec", "tally", "pings") == "64");
    eventually("~zod has its receipt", || zod.unanswered("~zod").unwrap() == 0);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(view(&nec, "~nec", "tally", "pings"), "64");
    assert_eq!(nec.pending("~nec").unwrap(), 1);
}

#[test]
fn a_ship_whose_file_is_nearly_full_takes_no_commands_until_it_has_room() {
    let (a, b) = (TempDir::new("cmd-full-a"), TempDir::new("cmd-full-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let provide = |interface: &str, remote: bool| Provide { interface: interface.into(), public: false, remote };
    let counter = Manifest { provides: vec![provide("counter", true), provide("journal", false)], uses: vec![] };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, Config { max_ship_bytes: 400 << 10, ..fast() }, counter, far_tally("*"));

    // ~nec's file is filled to within a few pages of its limit. Part of that is one value
    // that can be deleted later.
    send(&nec, "~nec", "counter", "big 60000");
    let entry = format!("journal {}", "x".repeat(6000));
    while nec.deliver("~nec", "counter", entry.as_bytes()).is_ok() {}

    // Taking a command means the sender lets go of it, so ~nec must be able to finish with
    // it: run it, and keep the receipt. With no room to be sure of that, it takes nothing,
    // and the command stays with ~zod.
    send(&zod, "~zod", "tally", "tell nec inc hits");
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(nec.pending("~nec").unwrap(), 0);
    assert_eq!(count(&nec, "~nec", "hits"), "0");
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 1);

    // Room is made. The command is taken, runs, and is answered.
    send(&nec, "~nec", "counter", "del big");
    eventually("the command runs", || count(&nec, "~nec", "hits") == "1");
    eventually("and is answered", || zod.unanswered("~zod").unwrap() == 0);

    // A command larger than ~nec's whole file could ever hold is another matter. No amount
    // of waiting would make room for it, so it is refused at once, and what follows it runs.
    send(&zod, "~zod", "tally", &format!("tell nec inc {}", "k".repeat(500 << 10)));
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the one after it runs", || count(&nec, "~nec", "hits") == "2");
    eventually("both are answered", || zod.unanswered("~zod").unwrap() == 0 && view(&zod, "~zod", "tally", "receipts").lines().count() == 3);
    let answers = view(&zod, "~zod", "tally", "receipts");
    let last_two: Vec<&str> = answers.lines().skip(1).collect();
    assert_eq!(
        last_two,
        ["2 ~nec/counter counter limit [larger than that ship can hold] from ~nec/counter counter", "3 ~nec/counter counter ran [] from ~nec/counter counter"]
    );
}

#[test]
fn a_batch_is_sized_by_what_is_sent_names_and_all() {
    let (a, b) = (TempDir::new("cmd-names-a"), TempDir::new("cmd-names-b"));
    let directory = Directory::new();
    // Both runtimes carry small messages: room for the largest command and little more.
    let small = Config { max_event_bytes: 200, max_checkpoint_bytes: 200, ..fast() };
    let net = NetConfig { max_message_bytes: 200 + 4096, ..eager() };
    // ~zod's tally agent may send to an agent with as long a name as a name may be.
    let long = "a".repeat(64);
    let sender = Manifest {
        provides: vec![Provide { interface: "tally".into(), public: false, remote: false }],
        uses: vec![Use { ship: "*".into(), agent: long.clone(), interface: long.clone(), read: false, send: true }],
    };
    let (zod, _zod_net) = crewed_on(&a, "~zod", &directory, small.clone(), net.clone(), open_counter(), sender);

    // Forty commands with nothing in them but names wait for ~nec, which is not there yet.
    // Counted by their payloads they would all go in one batch, which would be far larger
    // than either ship takes, and would be refused every time it was tried.
    for _ in 0..40 {
        send(&zod, "~zod", "tally", &format!("far nec {long} x"));
    }
    let (_nec, _nec_net) = crewed_on(&b, "~nec", &directory, small, net, open_counter(), far_tally("*"));
    eventually("all forty are delivered and answered", || zod.unanswered("~zod").unwrap() == 0 && view(&zod, "~zod", "tally", "receipts").lines().count() == 40);
    let answers = view(&zod, "~zod", "tally", "receipts");
    assert_eq!(answers.lines().count(), 40);
    assert!(answers.lines().all(|line| line.contains(" denied [no agent named aaaa")), "{answers}");
}

#[test]
fn receipts_that_do_not_all_fit_are_taken_as_far_as_they_do() {
    let (a, b) = (TempDir::new("receipt-part-a"), TempDir::new("receipt-part-b"));
    let directory = Directory::new();
    let provide = |interface: &str, remote: bool| Provide { interface: interface.into(), public: false, remote };
    let counter = Manifest { provides: vec![provide("counter", true), provide("journal", false)], uses: vec![] };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, Config { max_ship_bytes: 600 << 10, ..fast() }, counter, far_tally("*"));
    let patient = Config { max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, patient, open_counter(), far_tally("*"));

    // ~zod sends two hundred commands, which ~nec takes and holds without running. ~zod's
    // tally agent keeps a large value that it lets go of when a receipt comes.
    send(&zod, "~zod", "tally", "ballast 80000");
    for _ in 0..200 {
        send(&zod, "~zod", "tally", "tell nec inc hits");
    }
    eventually("~nec has them all", || nec.pending("~nec").unwrap() == 200 && zod.outbound_pending("~zod").unwrap() == 0);
    // Then ~zod's file is filled until nothing more goes in.
    for size in [6000, 500, 50] {
        let entry = format!("journal {}", "x".repeat(size));
        while zod.deliver("~zod", "counter", entry.as_bytes()).is_ok() {}
    }

    // ~nec runs the commands, and two hundred receipts come back together. There is no room
    // for them all. Refused as a whole they would be sent again and again for ever, because
    // what would make room is the first of them reaching the agent. Taken as far as they
    // fit, the first few get through, the agent lets its large value go, and the rest follow.
    nec.run_pending("~nec", 300).unwrap();
    eventually("every receipt arrives", || zod.unanswered("~zod").unwrap() == 0 && view(&zod, "~zod", "tally", "receipts").lines().count() == 200);
    let answers = view(&zod, "~zod", "tally", "receipts");
    let about: Vec<u64> = answers.lines().map(|line| line.split(' ').next().unwrap().parse().unwrap()).collect();
    assert_eq!(about, (1..=200).collect::<Vec<u64>>());
}

#[test]
fn two_ships_that_have_filled_up_with_commands_for_each_other_still_get_through() {
    let (a, b) = (TempDir::new("cmd-both-a"), TempDir::new("cmd-both-b"));
    let directory = Directory::new();
    // Two ships with small files. Each sends the other as much as it is let, while the
    // other is not there to take any of it.
    let small = Config { max_ship_bytes: 288 << 10, ..fast() };
    let padding = "p".repeat(2000);
    let fill = |rt: &Runtime, ship: &str, other: &str| {
        let command = format!("tell {other} inc hits 1 {padding}");
        let mut sent = 0;
        let stopped_by = loop {
            match rt.deliver(ship, "tally", command.as_bytes()) {
                Ok(_) => sent += 1,
                Err(e) => break e,
            }
        };
        // What stops it is not the file running out. It is the rule that sending must leave
        // room to take a command back: without that, neither ship could take the other's
        // first command, neither would then let go of anything, and both would wait for ever.
        assert!(matches!(&stopped_by, Error::Rejected(Rejection::Limit(why)) if why.contains("too full to send")), "{stopped_by:?}");
        assert!(sent > 10, "only {sent} were sent");
        // Trying again and again changes nothing. In particular the record of each refusal,
        // which would otherwise be kept with the whole command in it, is not what fills
        // the file in the end.
        for _ in 0..150 {
            assert!(rt.deliver(ship, "tally", command.as_bytes()).is_err());
        }
        sent
    };
    let (zod, zod_net) = crewed(&a, "~zod", &directory, small.clone(), open_counter(), far_tally("*"));
    drop(zod_net);
    let from_zod = fill(&zod, "~zod", "nec");
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, small, open_counter(), far_tally("*"));
    let from_nec = fill(&nec, "~nec", "zod");

    // They meet. Everything gets through, both ways, and is answered.
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("~nec has run all of ~zod's", || count(&nec, "~nec", "hits") == from_zod.to_string());
    eventually("~zod has run all of ~nec's", || count(&zod, "~zod", "hits") == from_nec.to_string());
    eventually("and every one is answered", || zod.unanswered("~zod").unwrap() == 0 && nec.unanswered("~nec").unwrap() == 0);
}

#[test]
fn receipts_already_written_do_not_keep_a_small_ship_from_taking_more() {
    let dir = TempDir::new("receipt-written");
    let directory = Directory::new();
    let (nec, nec_net) = crewed(&dir, "~nec", &directory, Config { max_ship_bytes: 256 << 10, ..fast() }, open_counter(), far_tally("*"));
    let seed = [5u8; 32];
    directory.set("~bus", ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(), "127.0.0.1:9".parse().unwrap()).unwrap();

    // ~bus hands ~nec commands and is never there to take the receipts. ~nec keeps room for
    // each receipt it has yet to write. A receipt it has written has its room already, and
    // is not counted again: several hundred of them take a few pages of a small file, and
    // counting them twice over would leave ~nec refusing commands it has plenty of room for.
    for batch in 0..10u64 {
        let messages: Vec<(u64, &str, &str)> = (1..=64).map(|n| (batch * 64 + n, "counter", "inc hits")).collect();
        let request = ship_proto::PeerRequest::decode(&*delivery(&messages)).unwrap();
        let Some(ship_proto::peer_request::Body::Deliver(deliver)) = request.body else { unreachable!() };
        assert_eq!(hand_over(nec_net.addr(), "nec", seed, deliver.messages), (batch + 1) * 64);
        eventually("the batch runs", || count(&nec, "~nec", "hits") == ((batch + 1) * 64).to_string());
    }
    assert_eq!(nec.outbound_pending("~nec").unwrap(), 640);
}

// Following a log on another ship.

use ship_proto::peer_reply::Body as Answered;
use ship_proto::peer_request::Body as Asked;

/// The tally agent, open to other ships, allowed to follow the counter's log on `ship` and to
/// send to the counter and tally agents there: one ship by name, or "*" for any.
fn following_tally(ship: &str) -> Manifest {
    let counter = Use { ship: ship.into(), agent: "counter".into(), interface: "counter".into(), read: true, send: true };
    let tally = Use { ship: ship.into(), agent: "tally".into(), interface: "tally".into(), read: false, send: true };
    Manifest { provides: vec![Provide { interface: "tally".into(), public: false, remote: true }], uses: vec![counter, tally] }
}

/// How many entries of the counter's log on `publisher` the tally agent on `ship` has taken.
fn seen_on(rt: &Runtime, ship: &str, publisher: &str) -> u64 {
    view(rt, ship, "tally", &format!("seen-on {publisher}")).parse().unwrap()
}

/// What the tally agent on `ship` was last told about that log having stopped, if anything.
fn stopped_on(rt: &Runtime, ship: &str, publisher: &str) -> String {
    view(rt, ship, "tally", &format!("stopped-on {publisher}"))
}

/// The one log on another ship that a ship's agents follow.
fn followed(rt: &Runtime, ship: &str) -> runtime::RemoteFollow {
    let mut all = rt.remote_follows(ship).unwrap();
    assert_eq!(all.len(), 1, "{all:?}");
    all.remove(0)
}

/// Give a ship's tally agent a different manifest, as its owner might.
fn reinstall_tally(rt: &Runtime, ship: &str, manifest: &Manifest) {
    rt.install(ship, "tally", &rt.add_module(&wasm("tally")).unwrap(), manifest).unwrap();
}

/// Put a ship that was stopped back on the network, in a runtime opened on its directory.
fn back(dir: &TempDir, ship: &str, directory: &Arc<Directory>, cfg: Config) -> (Arc<Runtime>, Network) {
    let rt = Arc::new(Runtime::open(&dir.0, cfg).unwrap());
    let net = Network::start(rt.clone(), directory.clone(), eager()).unwrap();
    directory.set(ship, rt.public_key(ship).unwrap(), net.addr()).unwrap();
    (rt, net)
}

/// Send one request to the ship `called` at `addr` as whoever holds `seed`, and return its answer.
fn ask_ship(addr: std::net::SocketAddr, called: &str, seed: [u8; 32], request: Asked) -> Option<Answered> {
    let request = ship_proto::PeerRequest { body: Some(request) }.encode_to_vec();
    let tokio = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connection = endpoint.connect_with(stranger_client(Some((seed, seed)), b"ship/1"), addr, called).unwrap().await.unwrap();
        exchange(&connection, &request).await.and_then(|reply| reply.body)
    })
}

/// A request for the entries of a log after `after`.
fn fetch(agent: &str, log: &str, after: u64, joining: bool) -> Asked {
    Asked::Fetch(ship_proto::Fetch { agent: agent.into(), log: log.into(), after, max_bytes: 1 << 20, joining })
}

fn public_of(seed: [u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

/// A log as a ship holding `seed` would publish it: each entry signed and linked to the one
/// before. Returns the entries and where the log ends.
fn signed_log(seed: [u8; 32], ship: &str, agent: &str, log: &str, payloads: &[&str]) -> (Vec<runtime::SignedEntry>, ship_proto::LogHead) {
    use ed25519_dalek::Signer;
    use sha2::Digest;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let (mut entries, mut prev) = (Vec::new(), Vec::new());
    for (index, payload) in payloads.iter().enumerate() {
        let body = runtime::EntryBody {
            ship: ship.into(),
            agent: agent.into(),
            log: log.into(),
            seq: index as u64 + 1,
            prev: prev.clone(),
            payload: payload.as_bytes().to_vec(),
        }
        .encode_to_vec();
        let signature = key.sign(&[b"ship.v1.entry\n".as_slice(), &body].concat()).to_bytes().to_vec();
        prev = sha2::Sha256::digest(&body).to_vec();
        entries.push(runtime::SignedEntry { body, signature });
    }
    (entries, ship_proto::LogHead { seq: payloads.len() as u64, hash: prev })
}

/// Where a run of entries ends.
fn end_of(entries: &[runtime::SignedEntry]) -> ship_proto::LogHead {
    use sha2::Digest;
    let hash = entries.last().map_or(Vec::new(), |entry| sha2::Sha256::digest(&entry.body).to_vec());
    ship_proto::LogHead { seq: entries.len() as u64, hash }
}

/// An answer to a request for entries.
fn fetched(entries: Vec<runtime::SignedEntry>, head: ship_proto::LogHead) -> Option<Answered> {
    Some(Answered::Fetched(ship_proto::Fetched { entries, head: Some(head), ..Default::default() }))
}

/// A stand-in that publishes a log honestly: whatever is asked for, it sends what comes after.
fn serving(entries: Vec<runtime::SignedEntry>) -> LogAnswers {
    Arc::new(move |asked| match asked {
        Asked::Fetch(fetch) => fetched(entries.iter().skip(fetch.after as usize).cloned().collect(), end_of(&entries)),
        _ => None,
    })
}

const BUS: [u8; 32] = [7u8; 32];

/// A ship ~nec whose tally agent follows the counter's log on ~bus, where ~bus is a stand-in
/// that answers as `answers` says. Whatever is returned must be kept for as long as it is used.
fn fed_by(label: &str, answers: LogAnswers) -> (Arc<Runtime>, (TempDir, Network, tokio::runtime::Runtime)) {
    let dir = TempDir::new(label);
    let directory = Directory::new();
    let (addr, running, _) = stand_in_with(BUS, BUS, true, 0, Some(answers));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    let (nec, net) = crewed(&dir, "~nec", &directory, fast(), open_counter(), following_tally("*"));
    assert_eq!(send(&nec, "~nec", "tally", "follow-on bus"), "following");
    (nec, (dir, net, running))
}

#[test]
fn a_log_on_another_ship_is_followed_entry_by_entry() {
    let (a, b) = (TempDir::new("flw-a"), TempDir::new("flw-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));

    // ~zod's counter publishes a log and lets ~nec follow it. ~nec's tally agent follows it
    // and is handed every entry, once and in order: the agent itself fails on any other.
    for _ in 0..12 {
        send(&zod, "~zod", "counter", "log hits");
    }
    assert_eq!(send(&zod, "~zod", "counter", "share nec"), "ok");
    assert_eq!(send(&nec, "~nec", "tally", "follow-on zod"), "following");
    eventually("~nec's agent has every entry", || seen_on(&nec, "~nec", "zod") == 12);
    assert_eq!(view(&nec, "~nec", "tally", "last-on zod"), "hits=12");
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);

    // New entries reach it without its asking again: ~zod says the log has grown, and ~nec
    // fetches what is new.
    for _ in 0..5 {
        send(&zod, "~zod", "counter", "log hits");
    }
    eventually("the new entries arrive", || seen_on(&nec, "~nec", "zod") == 17);
    eventually("and ~nec knows it has them all", || {
        let log = followed(&nec, "~nec");
        (log.taken, log.fetched, log.announced, log.stopped.clone()) == (17, 17, 17, None)
    });
    let log = followed(&nec, "~nec");
    assert_eq!((log.follower.as_str(), log.ship.as_str(), log.agent.as_str(), log.log.as_str()), ("tally", "zod", "counter", "counter"));

    // With nothing new, nothing happens: the agent is prompted when there are entries, and
    // not otherwise.
    let rounds = view(&nec, "~nec", "tally", "rounds-on zod");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(view(&nec, "~nec", "tally", "rounds-on zod"), rounds);
    // The log on ~nec's own ship, of the same name, is another log altogether.
    assert_eq!(nec.log_head("~nec", "counter", "counter").unwrap(), None);
    assert_eq!(view(&nec, "~nec", "tally", "seen"), "0");
}

#[test]
fn following_a_log_elsewhere_needs_the_followers_owner_to_have_agreed() {
    let (a, b) = (TempDir::new("flw-own-a"), TempDir::new("flw-own-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // ~nec's tally agent may send to other ships, and may not follow their logs.
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), far_tally("*"));
    for _ in 0..3 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&zod, "~zod", "counter", "share *");

    let denied = |command: &str| match nec.deliver("~nec", "tally", command.as_bytes()) {
        Err(Error::Rejected(Rejection::Denied(why))) => assert!(why.contains("may not follow"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    };
    denied("follow-on zod");
    assert!(nec.remote_follows("~nec").unwrap().is_empty());
    // Being allowed to follow the log on one ship says nothing about another.
    reinstall_tally(&nec, "~nec", &following_tally("bus"));
    denied("follow-on zod");
    // Nor does being allowed to follow the log of that name on its own ship.
    reinstall_tally(&nec, "~nec", &tally_manifest(true));
    denied("follow-on zod");
    assert!(nec.remote_follows("~nec").unwrap().is_empty());
    std::thread::sleep(Duration::from_millis(300));
    assert!(zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());

    reinstall_tally(&nec, "~nec", &following_tally("*"));
    assert_eq!(send(&nec, "~nec", "tally", "follow-on zod"), "following");
    eventually("the entries arrive", || seen_on(&nec, "~nec", "zod") == 3);

    // The owner takes the permission away again. What ~zod publishes next is still fetched,
    // since the ship was following, but the agent is not handed it and cannot ask for it.
    reinstall_tally(&nec, "~nec", &far_tally("*"));
    send(&zod, "~zod", "counter", "log hits");
    eventually("the new entry is fetched", || followed(&nec, "~nec").fetched == 4);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(seen_on(&nec, "~nec", "zod"), 3);
    denied("take-on zod");
    // Given it back, the agent asks again and is handed what was waiting.
    reinstall_tally(&nec, "~nec", &following_tally("zod"));
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the waiting entry is handed over", || seen_on(&nec, "~nec", "zod") == 4);

    // While it has no leave to follow, the agent is not so much as prompted about the log.
    // (This agent now notes each prompt and takes nothing, so a prompt would show.)
    send(&nec, "~nec", "tally", "lazy");
    reinstall_tally(&nec, "~nec", &far_tally("*"));
    send(&zod, "~zod", "counter", "log hits");
    eventually("the new entry is fetched", || followed(&nec, "~nec").fetched == 5);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(view(&nec, "~nec", "tally", "poked"), "0");
    // With leave, it is.
    reinstall_tally(&nec, "~nec", &following_tally("zod"));
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the agent is prompted", || view(&nec, "~nec", "tally", "poked") != "0");
}

#[test]
fn only_the_ships_its_publisher_lets_in_may_follow_a_log() {
    let (a, b, c) = (TempDir::new("flw-share-a"), TempDir::new("flw-share-b"), TempDir::new("flw-share-c"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("*"));
    let (bus, _bus_net) = crewed(&c, "~bus", &directory, fast(), open_counter(), following_tally("*"));
    for _ in 0..4 {
        send(&zod, "~zod", "counter", "log hits");
    }

    // Nobody has been let in. ~nec asks, is refused, and its agent is told why.
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec is told", || stopped_on(&nec, "~nec", "zod").contains("does not share"));
    assert_eq!(seen_on(&nec, "~nec", "zod"), 0);
    assert!(zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());
    // A ship that is not let in is told the same whether or not there is such a log.
    let dev = [9u8; 32];
    directory.set("~dev", public_of(dev), "127.0.0.1:9".parse().unwrap()).unwrap();
    let ask = |agent: &str, log: &str| match ask_ship(zod_net.addr(), "zod", dev, fetch(agent, log, 0, true)) {
        Some(Answered::Fetched(answer)) => answer,
        other => panic!("not an answer about a log: {other:?}"),
    };
    let (real, none) = (ask("counter", "counter"), ask("ghost", "nothing"));
    assert!(!real.denied.is_empty() && real.entries.is_empty() && real.head.is_none() && real.checkpoint.is_none(), "{real:?}");
    assert_eq!(real, none);
    assert!(zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());

    // The counter lets ~nec in by name. ~nec's agent asks again and gets the log. ~bus does not.
    send(&zod, "~zod", "counter", "share nec");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec has the log", || seen_on(&nec, "~nec", "zod") == 4);
    assert_eq!(stopped_on(&nec, "~nec", "zod"), "");
    send(&bus, "~bus", "tally", "follow-on zod");
    eventually("~bus is told", || stopped_on(&bus, "~bus", "zod").contains("does not share"));
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);

    // Every ship is let in, and ~bus gets it on asking again.
    send(&zod, "~zod", "counter", "share *");
    assert_eq!(zod.log_shares("~zod", "counter", "counter").unwrap(), ["*", "nec"]);
    send(&bus, "~bus", "tally", "follow-on zod");
    eventually("~bus has the log", || seen_on(&bus, "~bus", "zod") == 4);
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["bus", "nec"]);

    // That is taken back. ~bus, no longer covered, is told the log is closed to it, asks,
    // is refused, and gets no more. ~nec was let in by name and carries on.
    send(&zod, "~zod", "counter", "unshare *");
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    eventually("~bus is told", || stopped_on(&bus, "~bus", "zod").contains("does not share"));
    send(&zod, "~zod", "counter", "log hits");
    eventually("~nec has the new entry", || seen_on(&nec, "~nec", "zod") == 5);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(seen_on(&bus, "~bus", "zod"), 4);
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    // Asking again gets ~bus the same answer.
    let rounds = view(&bus, "~bus", "tally", "rounds-on zod");
    send(&bus, "~bus", "tally", "follow-on zod");
    eventually("~bus is refused again", || view(&bus, "~bus", "tally", "rounds-on zod") != rounds);
    assert!(stopped_on(&bus, "~bus", "zod").contains("does not share"));
    assert_eq!(followed(&bus, "~bus").fetched, 4);

    // Let back in, it picks up where it was, with nothing handed over twice.
    send(&zod, "~zod", "counter", "share bus");
    send(&bus, "~bus", "tally", "follow-on zod");
    eventually("~bus catches up", || seen_on(&bus, "~bus", "zod") == 5);
    assert_eq!(stopped_on(&bus, "~bus", "zod"), "");
}

#[test]
fn a_follower_or_a_publisher_that_was_away_picks_up_where_it_left_off() {
    let (a, b) = (TempDir::new("flw-away-a"), TempDir::new("flw-away-b"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    for _ in 0..3 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&zod, "~zod", "counter", "share nec");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the first entries arrive", || seen_on(&nec, "~nec", "zod") == 3);

    // ~nec goes away, and ~zod's log grows. ~zod cannot tell it. That it has yet to be told
    // is kept in ~zod's file: ~zod is stopped and started again, and still knows.
    drop(nec_net);
    for _ in 0..4 {
        send(&zod, "~zod", "counter", "log hits");
    }
    std::thread::sleep(Duration::from_millis(400));
    stopped(zod_net, zod);
    let (zod, zod_net) = back(&a, "~zod", &directory, fast());
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("~nec is told and catches up", || seen_on(&nec, "~nec", "zod") == 7);

    // ~zod is off the network while its log grows, and says so when it is back.
    drop(zod_net);
    for _ in 0..2 {
        send(&zod, "~zod", "counter", "log hits");
    }
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("~nec catches up again", || seen_on(&nec, "~nec", "zod") == 9);

    // ~nec is stopped part way through a long run of entries and started again.
    for _ in 0..40 {
        send(&zod, "~zod", "counter", "log hits");
    }
    eventually("~nec is under way", || seen_on(&nec, "~nec", "zod") > 12);
    stopped(nec_net, nec);
    let (nec, _nec_net) = back(&b, "~nec", &directory, fast());
    eventually("~nec has them all, each once", || seen_on(&nec, "~nec", "zod") == 49);
    assert_eq!(view(&nec, "~nec", "tally", "last-on zod"), "hits=49");
}

#[test]
fn what_another_ship_sends_is_checked_before_any_of_it_is_kept() {
    let good = || signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3"]).0;
    let refused = |label: &str, entries: Vec<runtime::SignedEntry>, taken: u64| {
        let (nec, _kept) = fed_by(label, serving(entries));
        eventually(label, || stopped_on(&nec, "~nec", "bus").contains("does not carry on"));
        assert_eq!(seen_on(&nec, "~nec", "bus"), taken, "{label}");
        let log = followed(&nec, "~nec");
        assert_eq!((log.fetched, log.stopped.is_some()), (taken, true), "{label}");
    };

    // Entries signed with ~bus's key, each linked to the one before, are taken.
    let (nec, _kept) = fed_by("flw-check-good", serving(good()));
    eventually("the entries are taken", || seen_on(&nec, "~nec", "bus") == 3);
    assert_eq!(view(&nec, "~nec", "tally", "last-on bus"), "a=3");
    assert_eq!(followed(&nec, "~nec").stopped, None);

    // Signed with another key. Anyone can write entries that say they are ~bus's.
    refused("flw-check-key", signed_log([8u8; 32], "bus", "counter", "counter", &["a=1"]).0, 0);
    // Genuinely ~bus's, but entries of another log, another agent's log, or a log of that
    // name on another ship.
    refused("flw-check-log", signed_log(BUS, "bus", "counter", "journal", &["a=1"]).0, 0);
    refused("flw-check-agent", signed_log(BUS, "bus", "tally", "counter", &["a=1"]).0, 0);
    refused("flw-check-ship", signed_log(BUS, "zod", "counter", "counter", &["a=1"]).0, 0);
    // Changed after it was signed.
    let mut altered = good();
    let last = altered[0].body.len() - 1;
    altered[0].body[last] ^= 1;
    refused("flw-check-altered", altered, 0);
    // The first entry left out, so that what comes does not start where it should.
    let (nec, _kept) = fed_by("flw-check-gap", Arc::new(move |asked| match asked {
        Asked::Fetch(_) => fetched(good()[1..].to_vec(), end_of(&good())),
        _ => None,
    }));
    eventually("a gap", || stopped_on(&nec, "~nec", "bus").contains("does not carry on"));
    assert_eq!(seen_on(&nec, "~nec", "bus"), 0);
    // Two good entries and then one from a different history: genuine, numbered three, but
    // not linked to the second. The two are kept and handed over. The third is not.
    let other = signed_log(BUS, "bus", "counter", "counter", &["b=1", "b=2", "b=3"]).0;
    refused("flw-check-fork", vec![good()[0].clone(), good()[1].clone(), other[2].clone()], 2);
}

#[test]
fn a_publisher_whose_log_is_no_longer_the_one_followed_is_noticed() {
    let (entries, head) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3"]);
    // Each of these stand-ins gives the log honestly the first time it is asked, and
    // something else from then on: what a ship would say that had gone back to an earlier
    // state, or had written something different since.
    let later = |label: &str, then: ship_proto::Fetched, why: &str| {
        let (asked, first) = (Arc::new(AtomicUsize::new(0)), entries.clone());
        let (count, head) = (asked.clone(), head.clone());
        let (nec, _kept) = fed_by(label, Arc::new(move |request| match request {
            Asked::Fetch(_) if count.fetch_add(1, Ordering::SeqCst) == 0 => fetched(first.clone(), head.clone()),
            Asked::Fetch(_) => Some(Answered::Fetched(then.clone())),
            _ => None,
        }));
        eventually("the log is taken", || seen_on(&nec, "~nec", "bus") == 3);
        assert_eq!(stopped_on(&nec, "~nec", "bus"), "");
        // The agent asks afresh, which is when ~nec next hears from ~bus.
        send(&nec, "~nec", "tally", "follow-on bus");
        eventually(label, || stopped_on(&nec, "~nec", "bus").contains(why));
        assert_eq!(seen_on(&nec, "~nec", "bus"), 3, "{label}");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(asked.load(Ordering::SeqCst), 2, "{label}: it went on asking");
    };
    let says = |head: ship_proto::LogHead| ship_proto::Fetched { head: Some(head), ..Default::default() };
    // Its log is shorter than the copy ~nec holds.
    later("flw-back-short", says(end_of(&entries[..2])), "does not carry on");
    // As long, and ending in a different entry.
    let other = signed_log(BUS, "bus", "counter", "counter", &["b=1", "b=2", "b=3"]);
    later("flw-back-fork", says(other.1), "does not carry on");
    // It says there is more and sends none.
    later("flw-back-none", says(ship_proto::LogHead { seq: 9, hash: vec![1; 32] }), "sent none");
    // Asked again when nothing has changed, an honest publisher says the same as before,
    // and nothing stops.
    let (nec, _kept) = fed_by("flw-back-same", serving(entries.clone()));
    eventually("the log is taken", || seen_on(&nec, "~nec", "bus") == 3);
    send(&nec, "~nec", "tally", "follow-on bus");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!((stopped_on(&nec, "~nec", "bus"), followed(&nec, "~nec").stopped), (String::new(), None));
}

#[test]
fn a_publisher_that_says_there_is_more_than_it_has_is_asked_afresh_and_no_more() {
    let (entries, head) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3", "a=4", "a=5"]);
    // The first answer has two entries and says the log has five. After that the log ends
    // at the second: this ship went back to an earlier state between the two answers. ~nec
    // asks for the rest, is given none, and so asks afresh where the log stands. That is
    // three questions. It does not stop, and it does not go on asking.
    let asked = Arc::new(AtomicUsize::new(0));
    let (count, short) = (asked.clone(), entries[..2].to_vec());
    let (nec, _kept) = fed_by("flw-less", Arc::new(move |request| match request {
        Asked::Fetch(_) if count.fetch_add(1, Ordering::SeqCst) == 0 => fetched(short.clone(), head.clone()),
        Asked::Fetch(asked) => fetched(Vec::new(), end_of(&short)).filter(|_| asked.after == 2),
        _ => None,
    }));
    eventually("the two entries are taken", || seen_on(&nec, "~nec", "bus") == 2);
    eventually("~nec has asked afresh", || asked.load(Ordering::SeqCst) == 3);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(asked.load(Ordering::SeqCst), 3, "it went on asking");
    let log = followed(&nec, "~nec");
    assert_eq!((log.taken, log.fetched, log.announced, log.stopped), (2, 2, 2, None));
}

#[test]
fn a_follower_too_far_behind_another_ships_log_is_handed_its_checkpoint() {
    let (a, b, c) = (TempDir::new("flw-cp-a"), TempDir::new("flw-cp-b"), TempDir::new("flw-cp-c"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, checkpointing(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share *");
    for _ in 0..4 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec has the first entries", || seen_on(&nec, "~nec", "zod") == 4);
    assert_eq!(view(&nec, "~nec", "tally", "jumps-on zod"), "0");

    // ~nec is away while ~zod's log grows far enough that its early entries are dropped.
    drop(nec_net);
    for _ in 0..30 {
        send(&zod, "~zod", "counter", "log hits");
    }
    let base = match zod.log_entries("~zod", "counter", "counter", 0, NO_LIMIT) {
        Err(Error::LogTrimmed(base)) => base,
        other => panic!("nothing was dropped: {other:?}"),
    };
    assert!(base > 4, "only {base} were dropped");
    // Back, it cannot be given entry 5. It is given ~zod's state as of a later entry, which
    // it checks like an entry, and the entries after that.
    let nec_net = Network::start(nec.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", nec.public_key("~nec").unwrap(), nec_net.addr()).unwrap();
    eventually("~nec is level with ~zod", || seen_on(&nec, "~nec", "zod") == 34);
    assert_eq!(view(&nec, "~nec", "tally", "jumps-on zod"), "1");
    assert_eq!(view(&nec, "~nec", "tally", "last-on zod"), "hits=34");

    // A ship that starts following now begins from the checkpoint too.
    let (bus, _bus_net) = crewed(&c, "~bus", &directory, fast(), open_counter(), following_tally("*"));
    send(&bus, "~bus", "tally", "follow-on zod");
    eventually("~bus is level with ~zod", || seen_on(&bus, "~bus", "zod") == 34);
    assert_eq!(view(&bus, "~bus", "tally", "jumps-on zod"), "1");
}

#[test]
fn a_checkpoint_from_another_ship_is_checked_like_an_entry() {
    use ed25519_dalek::Signer;
    let (entries, _) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3", "a=4"]);
    let checkpoint = |seed: [u8; 32], log: &str, seq: u64, state: &[u8]| {
        let hash = if seq as usize <= entries.len() { end_of(&entries[..seq as usize]).hash } else { vec![3; 32] };
        let body = ship_proto::CheckpointBody { ship: "bus".into(), agent: "counter".into(), log: log.into(), seq, hash, state: state.to_vec() };
        let body = body.encode_to_vec();
        let signature = ed25519_dalek::SigningKey::from_bytes(&seed).sign(&[b"ship.v1.checkpoint\n".as_slice(), &body].concat()).to_bytes().to_vec();
        SignedCheckpoint { body, signature }
    };
    // A stand-in whose log starts at entry 3: asked for anything earlier it sends `given`.
    let from_three = |label: &str, given: SignedCheckpoint| {
        let entries = entries.clone();
        fed_by(label, Arc::new(move |asked| match asked {
            Asked::Fetch(fetch) if fetch.after < 2 => {
                Some(Answered::Fetched(ship_proto::Fetched { head: Some(end_of(&entries)), checkpoint: Some(given.clone()), ..Default::default() }))
            }
            Asked::Fetch(fetch) => fetched(entries.iter().skip(fetch.after as usize).cloned().collect(), end_of(&entries)),
            _ => None,
        }))
    };
    // Signed by ~bus, for this log: the state is handed over, then the entries after it,
    // which must link back to the entry the checkpoint names.
    let (nec, _kept) = from_three("flw-cpx-good", checkpoint(BUS, "counter", 2, b"a=2"));
    eventually("the checkpoint and what follows are taken", || seen_on(&nec, "~nec", "bus") == 4);
    assert_eq!(view(&nec, "~nec", "tally", "jumps-on bus"), "1");
    assert_eq!(followed(&nec, "~nec").stopped, None);

    let refused = |label: &str, given: SignedCheckpoint, why: &str| {
        let (nec, _kept) = from_three(label, given);
        eventually(label, || stopped_on(&nec, "~nec", "bus").contains(why));
        assert_eq!((seen_on(&nec, "~nec", "bus"), view(&nec, "~nec", "tally", "jumps-on bus")), (0, "0".to_string()), "{label}");
    };
    // Signed with another key, or for another log.
    refused("flw-cpx-key", checkpoint([8u8; 32], "counter", 2, b"a=2"), "does not carry on");
    refused("flw-cpx-log", checkpoint(BUS, "journal", 2, b"a=2"), "does not carry on");
    // Larger than this ship takes.
    refused("flw-cpx-big", checkpoint(BUS, "counter", 2, &vec![b's'; (1 << 20) + 1]), "larger than this ship takes");
    // An entry signed by ~bus passed off as a checkpoint: the two are signed differently.
    let passed_off = SignedCheckpoint { body: entries[1].body.clone(), signature: entries[1].signature.clone() };
    refused("flw-cpx-entry", passed_off, "does not carry on");
    // Genuine, but for an entry numbered beyond anything a log could reach.
    refused("flw-cpx-far", checkpoint(BUS, "counter", (1 << 62) + 1, b"a=2"), "does not carry on");

    // A checkpoint for the highest entry number there can be, and then a genuine entry
    // that follows it. The checkpoint is taken. The entry is one too far.
    let limit = 1u64 << 61;
    let (edge, link) = (checkpoint(BUS, "counter", limit, b"a=2"), vec![3u8; 32]);
    let body = runtime::EntryBody { ship: "bus".into(), agent: "counter".into(), log: "counter".into(), seq: limit + 1, prev: link, payload: b"a=3".to_vec() };
    let body = body.encode_to_vec();
    let signature = ed25519_dalek::SigningKey::from_bytes(&BUS).sign(&[b"ship.v1.entry\n".as_slice(), &body].concat()).to_bytes().to_vec();
    let beyond = runtime::SignedEntry { body, signature };
    let (nec, _kept) = fed_by("flw-cpx-edge", Arc::new(move |asked| match asked {
        Asked::Fetch(fetch) if fetch.after < limit => {
            let head = Some(ship_proto::LogHead { seq: limit, hash: vec![3; 32] });
            Some(Answered::Fetched(ship_proto::Fetched { head, checkpoint: Some(edge.clone()), ..Default::default() }))
        }
        Asked::Fetch(_) => fetched(vec![beyond.clone()], end_of(std::slice::from_ref(&beyond))),
        _ => None,
    }));
    eventually("the checkpoint is taken", || view(&nec, "~nec", "tally", "jumps-on bus") == "1");
    // (Nothing is believed to lie beyond the limit, so ~nec asks for more only when its
    // agent asks afresh.)
    send(&nec, "~nec", "tally", "follow-on bus");
    eventually("the entry beyond the limit is refused", || stopped_on(&nec, "~nec", "bus").contains("does not carry on"));
    assert_eq!((followed(&nec, "~nec").fetched, view(&nec, "~nec", "tally", "jumps-on bus")), (limit, "1".to_string()));

    // A checkpoint moves a follower forward. A stand-in that answers every question with
    // the same one is believed the first time and not the second, when it stands for an
    // entry ~nec already holds.
    let again = checkpoint(BUS, "counter", 2, b"a=2");
    let end = end_of(&entries);
    let (nec, _kept) = fed_by("flw-cpx-again", Arc::new(move |asked| match asked {
        Asked::Fetch(_) => Some(Answered::Fetched(ship_proto::Fetched { head: Some(end.clone()), checkpoint: Some(again.clone()), ..Default::default() })),
        _ => None,
    }));
    eventually("the second is refused", || stopped_on(&nec, "~nec", "bus").contains("does not carry on"));
    assert_eq!((seen_on(&nec, "~nec", "bus"), view(&nec, "~nec", "tally", "jumps-on bus")), (2, "1".to_string()));
}

#[test]
fn a_number_no_log_could_reach_is_not_believed() {
    let (entries, _) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3"]);
    let (nec, kept) = fed_by("flw-far", serving(entries));
    eventually("the log is taken", || seen_on(&nec, "~nec", "bus") == 3);

    // ~bus says its log has reached an entry numbered in the quintillions. A number like
    // that is only a prompt to ask, and this one is not even that: kept, it would be a
    // number ~nec's own file could not be read back with.
    let far = ship_proto::LogNews { agent: "counter".into(), log: "counter".into(), head: (1 << 62) + 5, closed: false };
    let heard = ask_ship(kept.1.addr(), "nec", BUS, Asked::News(ship_proto::News { logs: vec![far] }));
    assert_eq!(heard, Some(Answered::Heard(ship_proto::Heard { unknown: vec![false] })));
    assert_eq!(followed(&nec, "~nec").announced, 3);
    let (out, other) = (TempDir::new("flw-far-out"), TempDir::new("flw-far-other"));
    nec.export_ship("~nec", &out.0).unwrap();
    Runtime::open(&other.0, fast()).unwrap().import_ship(&out.0, "~nec").unwrap();
}

#[test]
fn a_follower_is_told_again_when_the_log_grew_while_it_was_being_told() {
    let dir = TempDir::new("flw-told");
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    send(&zod, "~zod", "counter", "share *");
    // ~bus is a stand-in that takes its time over each piece of news, and notes where it
    // was told the log ends.
    let told = Arc::new(std::sync::Mutex::new(Vec::new()));
    let heads = told.clone();
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 0, Some(Arc::new(move |asked| match asked {
        Asked::News(news) => {
            heads.lock().unwrap().extend(news.logs.iter().map(|log| log.head));
            std::thread::sleep(Duration::from_millis(500));
            Some(Answered::Heard(ship_proto::Heard { unknown: vec![false; news.logs.len()] }))
        }
        _ => None,
    })));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    assert!(matches!(ask_ship(zod_net.addr(), "zod", BUS, fetch("counter", "counter", 0, true)), Some(Answered::Fetched(_))));

    // The log gets its first entry, and ~bus is told. While ~bus is still taking that in,
    // the log gets a second. ~bus's answer is to news of the first, so it is told again.
    send(&zod, "~zod", "counter", "log hits");
    eventually("~bus is told of the first", || told.lock().unwrap().len() == 1);
    send(&zod, "~zod", "counter", "log hits");
    eventually("and of the second", || *told.lock().unwrap() == [1, 2]);
    // And then no more, since nothing has changed.
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(*told.lock().unwrap(), [1, 2]);
}

#[test]
fn a_ship_shut_out_and_let_back_in_before_it_was_told_carries_on() {
    let (a, b) = (TempDir::new("flw-back-in-a"), TempDir::new("flw-back-in-b"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    for _ in 0..2 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entries arrive", || seen_on(&nec, "~nec", "zod") == 2);

    // While ~zod is off the network, its counter shuts ~nec out and then thinks better of
    // it. ~nec was never told, and need not be: it goes on following as if nothing happened.
    drop(zod_net);
    send(&zod, "~zod", "counter", "unshare nec");
    assert!(zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());
    send(&zod, "~zod", "counter", "share nec");
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    send(&zod, "~zod", "counter", "log hits");
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("the new entry arrives", || seen_on(&nec, "~nec", "zod") == 3);
    assert_eq!((stopped_on(&nec, "~nec", "zod"), followed(&nec, "~nec").stopped), (String::new(), None));
}

#[test]
fn a_network_that_could_not_carry_a_logs_checkpoint_does_not_start() {
    let dir = TempDir::new("flw-cp-size");
    let directory = Directory::new();
    // A ship that follows a log may be sent its checkpoint whole. A network with no room
    // for the largest one a log here may have would leave such a follower stuck for good.
    let cfg = Config { max_event_bytes: 1000, max_checkpoint_bytes: 100_000, ..fast() };
    let rt = Arc::new(Runtime::open(&dir.0, cfg).unwrap());
    let cramped = NetConfig { max_message_bytes: 50_000, ..eager() };
    assert!(Network::start(rt.clone(), directory.clone(), cramped).is_err());
    let roomy = NetConfig { max_message_bytes: 100_000 + 4096, ..eager() };
    assert!(Network::start(rt, directory, roomy).is_ok());
}

#[test]
fn a_follower_that_falls_behind_is_not_sent_the_whole_log_to_keep() {
    let (a, b) = (TempDir::new("flw-slow-a"), TempDir::new("flw-slow-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // ~nec holds at most about a thousand bytes of another ship's log for an agent.
    let cfg = Config { max_follow_bytes: 1000, ..fast() };
    let (nec, nec_net) = crewed(&b, "~nec", &directory, cfg.clone(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    // The first entry is one ~nec's agent refuses to handle, so it takes nothing.
    send(&zod, "~zod", "counter", "log poison");
    for _ in 0..60 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec has fetched what it will hold", || followed(&nec, "~nec").fetched >= 14);
    std::thread::sleep(Duration::from_millis(600));
    // Each entry counts as its payload plus 64 bytes: fourteen or fifteen of them. Not 61.
    let log = followed(&nec, "~nec");
    assert!((log.taken, log.announced) == (0, 61) && log.fetched <= 15, "{log:?}");
    assert_eq!(seen_on(&nec, "~nec", "zod"), 0);

    // The same holds through a restart: nothing more is fetched, and nothing is lost.
    stopped(nec_net, nec);
    let (nec, _nec_net) = back(&b, "~nec", &directory, cfg);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(followed(&nec, "~nec").fetched, log.fetched);

    // The agent comes round to handling that entry. As it takes entries, room is made, and
    // more are fetched, until it has them all.
    send(&nec, "~nec", "tally", "tolerate");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec's agent has every entry", || seen_on(&nec, "~nec", "zod") == 61);
    assert_eq!(view(&nec, "~nec", "tally", "last-on zod"), "hits=60");
}

#[test]
fn what_is_fetched_from_other_ships_logs_leaves_room_to_take_their_commands() {
    let (a, b) = (TempDir::new("flw-room-a"), TempDir::new("flw-room-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // A small file, and no limit to speak of on what is held of another ship's log.
    let cfg = Config { max_ship_bytes: 420 << 10, max_follow_bytes: 64 << 20, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    // (~zod's counter never manages a checkpoint, so its log keeps every entry, and the
    // first is one ~nec's agent refuses to handle.)
    send(&zod, "~zod", "counter", "checkpoints broken");
    send(&zod, "~zod", "counter", "log poison");
    for _ in 0..12 {
        send(&zod, "~zod", "counter", "log-big 30000");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec has fetched some", || followed(&nec, "~nec").fetched >= 3);
    std::thread::sleep(Duration::from_millis(900));
    let held = followed(&nec, "~nec").fetched;
    assert!(held < 13, "everything was fetched, into a file with no room for it: {:?} seen {}", followed(&nec, "~nec"), seen_on(&nec, "~nec", "zod"));

    // What it stopped short for: a command from ~zod is still taken, run, and answered.
    send(&zod, "~zod", "tally", "tell nec inc hits");
    eventually("the command runs on ~nec", || count(&nec, "~nec", "hits") == "1");
    eventually("and is answered", || zod.unanswered("~zod").unwrap() == 0);

    // Once the agent takes what is held, the rest is fetched.
    send(&nec, "~nec", "tally", "tolerate");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec's agent has every entry", || seen_on(&nec, "~nec", "zod") == 13);
}

#[test]
fn an_agent_can_stop_following_and_start_again_from_the_beginning() {
    let (a, b) = (TempDir::new("flw-stop-a"), TempDir::new("flw-stop-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    for _ in 0..6 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entries arrive", || seen_on(&nec, "~nec", "zod") == 6);

    // It stops. Nothing of the log is held any more, and ~zod, on next telling ~nec that
    // the log has grown, learns that nobody there follows it and stops telling it.
    assert_eq!(send(&nec, "~nec", "tally", "unfollow-on zod"), "stopped");
    assert!(nec.remote_follows("~nec").unwrap().is_empty());
    send(&zod, "~zod", "counter", "log hits");
    eventually("~zod stops telling ~nec", || zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());
    assert_eq!(seen_on(&nec, "~nec", "zod"), 0);
    // An agent that does not follow a log cannot take from it.
    assert!(matches!(nec.deliver("~nec", "tally", b"take-on zod"), Err(Error::Rejected(Rejection::Denied(_)))));

    // Following again starts from the first entry, and ~zod notes it as a follower again.
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("all seven arrive", || seen_on(&nec, "~nec", "zod") == 7);
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    send(&zod, "~zod", "counter", "log hits");
    eventually("and it is told of the eighth", || seen_on(&nec, "~nec", "zod") == 8);
}

#[test]
fn stopping_while_entries_wait_lets_go_of_them_and_of_the_notice() {
    let (a, b) = (TempDir::new("flw-drop-a"), TempDir::new("flw-drop-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // Nothing queued on ~nec runs by itself, so its agent's notice waits in the queue.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    for _ in 0..3 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entries are fetched", || followed(&nec, "~nec").fetched == 3);
    eventually("and the agent's notice is queued", || nec.pending("~nec").unwrap() == 1);

    send(&nec, "~nec", "tally", "unfollow-on zod");
    assert_eq!(nec.pending("~nec").unwrap(), 0);
    assert!(nec.remote_follows("~nec").unwrap().is_empty());
    // The same for a log on its own ship.
    reinstall_tally(&nec, "~nec", &tally_manifest(true));
    send(&nec, "~nec", "tally", "follow");
    send(&nec, "~nec", "counter", "log hits");
    assert_eq!(nec.pending("~nec").unwrap(), 1);
    send(&nec, "~nec", "tally", "unfollow");
    assert_eq!((nec.pending("~nec").unwrap(), nec.log_position("~nec", "tally", "counter", "counter").unwrap()), (0, None));
}

#[test]
fn a_log_is_shared_by_its_own_publisher_with_other_ships_and_only_so_many() {
    let dir = TempDir::new("flw-limits");
    let directory = Directory::new();
    let cfg = Config { max_log_shares: 3, ..fast() };
    let (zod, _zod_net) = crewed(&dir, "~zod", &directory, cfg, open_counter(), far_tally("*"));
    let refused = |command: &str| match zod.deliver("~zod", "counter", command.as_bytes()) {
        Err(Error::Rejected(rejection)) => rejection,
        other => panic!("{command}: expected a refusal, got {other:?}"),
    };
    // An agent shares its own logs, not another agent's.
    assert!(matches!(refused("share-other nec"), Rejection::Denied(why) if why.contains("offers no interface")));
    // With other ships, by name. Its own ship's agents follow its logs another way.
    assert!(matches!(refused("share zod"), Rejection::Denied(why) if why.contains("other ships")));
    assert!(matches!(refused("share Not-A-Ship"), Rejection::Denied(why) if why.contains("not a ship's name")));
    assert!(zod.log_shares("~zod", "counter", "counter").unwrap().is_empty());

    // Three names, of which "*" is one, and no more. Saying one again is not one more.
    for ship in ["nec", "bus", "*", "nec", "~bus"] {
        assert_eq!(send(&zod, "~zod", "counter", &format!("share {ship}")), "ok");
    }
    assert!(matches!(refused("share doz"), Rejection::Limit(why) if why.contains("at most 3")));
    assert_eq!(zod.log_shares("~zod", "counter", "counter").unwrap(), ["*", "bus", "nec"]);
    send(&zod, "~zod", "counter", "unshare bus");
    assert_eq!(send(&zod, "~zod", "counter", "share doz"), "ok");
    assert_eq!(zod.log_shares("~zod", "counter", "counter").unwrap(), ["*", "doz", "nec"]);
}

#[test]
fn a_log_has_only_so_many_followers_and_one_more_waits() {
    let (a, b, c) = (TempDir::new("flw-many-a"), TempDir::new("flw-many-b"), TempDir::new("flw-many-c"));
    let directory = Directory::new();
    let cfg = Config { max_log_followers: 1, ..fast() };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, cfg, open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("*"));
    let (bus, _bus_net) = crewed(&c, "~bus", &directory, fast(), open_counter(), following_tally("*"));
    send(&zod, "~zod", "counter", "share *");
    send(&zod, "~zod", "counter", "log hits");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec follows", || seen_on(&nec, "~nec", "zod") == 1);

    // ~bus is let in, but the log has the one follower it may. ~bus is not refused for
    // good: it goes on asking, and its agent is told nothing.
    send(&bus, "~bus", "tally", "follow-on zod");
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!((followed(&bus, "~bus").fetched, followed(&bus, "~bus").stopped, stopped_on(&bus, "~bus", "zod")), (0, None, String::new()));
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);

    // ~nec stops following, ~zod finds out on next telling it, and ~bus gets in.
    send(&nec, "~nec", "tally", "unfollow-on zod");
    send(&zod, "~zod", "counter", "log hits");
    eventually("~bus follows", || seen_on(&bus, "~bus", "zod") == 2);
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["bus"]);
}

#[test]
fn an_answer_to_old_news_does_not_strike_off_a_ship_that_has_asked_afresh() {
    let dir = TempDir::new("flw-gen");
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    send(&zod, "~zod", "counter", "share *");
    send(&zod, "~zod", "counter", "log hits");

    // ~bus is a stand-in. Told that the log has grown, it answers that it does not follow
    // it. But the first time, before answering, it asks to follow afresh: the answer is
    // then to news from before that, and ~zod must not take it as ~bus leaving.
    let (addr_of_zod, told) = (zod_net.addr(), Arc::new(AtomicUsize::new(0)));
    let count = told.clone();
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 0, Some(Arc::new(move |asked| match asked {
        Asked::News(news) => {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::spawn(move || ask_ship(addr_of_zod, "zod", BUS, fetch("counter", "counter", 0, true))).join().unwrap();
            }
            Some(Answered::Heard(ship_proto::Heard { unknown: vec![true; news.logs.len()] }))
        }
        _ => None,
    })));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    assert!(matches!(ask_ship(zod_net.addr(), "zod", BUS, fetch("counter", "counter", 0, true)), Some(Answered::Fetched(_))));
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["bus"]);

    send(&zod, "~zod", "counter", "log hits");
    eventually("~bus is told once, and again", || told.load(Ordering::SeqCst) >= 2);
    // The second answer is to news that nothing has overtaken, and ~bus is struck off.
    eventually("~bus is struck off", || zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());
    assert_eq!(told.load(Ordering::SeqCst), 2);
}

#[test]
fn ships_that_disagree_about_commands_still_follow_each_others_logs() {
    let dir = TempDir::new("flw-stalled");
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), following_tally("*"));
    // ~bus says it holds ninety-nine commands from ~zod, which has sent one. Commands
    // between the two stop there. ~bus's log is another matter.
    let (entries, _) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2"]);
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 99, Some(serving(entries)));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    send(&zod, "~zod", "tally", "tell bus inc hits");
    eventually("~zod notices", || zod_net.stalled() == [("zod".to_string(), "bus".to_string())]);

    send(&zod, "~zod", "tally", "follow-on bus");
    eventually("~zod's agent has ~bus's log", || seen_on(&zod, "~zod", "bus") == 2);
    assert_eq!(zod_net.stalled(), [("zod".to_string(), "bus".to_string())]);
    assert_eq!(zod.outbound_pending("~zod").unwrap(), 1);
}

#[test]
fn naming_ones_own_ship_follows_the_log_there_as_any_agent_would() {
    let dir = TempDir::new("flw-self");
    let rt = boot_pair(&dir, fast(), counter_manifest(false), tally_manifest(true));
    send(&rt, "~zod", "counter", "log hits");
    assert_eq!(send(&rt, "~zod", "tally", "follow-on zod"), "following");
    assert_eq!(rt.log_position("~zod", "tally", "counter", "counter").unwrap(), Some(1));
    assert_eq!(read(&rt, "tally", "tally", "seen"), "1");
    assert!(rt.remote_follows("~zod").unwrap().is_empty());
}

#[test]
fn followed_logs_go_with_a_ship_that_is_moved() {
    let (a, b, c, out) = (TempDir::new("flw-move-a"), TempDir::new("flw-move-b"), TempDir::new("flw-move-c"), TempDir::new("flw-move-out"));
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "log poison");
    for _ in 0..5 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    // ~nec has fetched six entries and its agent has taken none of them.
    eventually("the entries are fetched", || followed(&nec, "~nec").fetched == 6);
    eventually("the agent has given up on them", || nec.pending("~nec").unwrap() == 0);

    // ~nec moves to another runtime with what it holds, and carries on from there.
    nec.export_ship("~nec", &out.0).unwrap();
    stopped(nec_net, nec);
    let other = Arc::new(Runtime::open(&c.0, fast()).unwrap());
    let other_net = Network::start(other.clone(), directory.clone(), eager()).unwrap();
    other.import_ship(&out.0, "~nec").unwrap();
    directory.set("~nec", other.public_key("~nec").unwrap(), other_net.addr()).unwrap();
    let log = followed(&other, "~nec");
    assert_eq!((log.taken, log.fetched), (0, 6));
    send(&zod, "~zod", "counter", "log hits");
    send(&other, "~nec", "tally", "tolerate");
    send(&other, "~nec", "tally", "follow-on zod");
    eventually("the agent has every entry, each once", || seen_on(&other, "~nec", "zod") == 7);

    // ~zod moves too. Whoever follows its logs is told afresh where they stand, so ~nec
    // hears of an entry written just before the move that it had not been told of.
    drop(other_net);
    send(&zod, "~zod", "counter", "log hits");
    std::thread::sleep(Duration::from_millis(300));
    let (d, zod_out) = (TempDir::new("flw-move-d"), TempDir::new("flw-move-zod-out"));
    zod.export_ship("~zod", &zod_out.0).unwrap();
    stopped(zod_net, zod);
    let moved = Arc::new(Runtime::open(&d.0, fast()).unwrap());
    let moved_net = Network::start(moved.clone(), directory.clone(), eager()).unwrap();
    moved.import_ship(&zod_out.0, "~zod").unwrap();
    directory.set("~zod", moved.public_key("~zod").unwrap(), moved_net.addr()).unwrap();
    let other_net = Network::start(other.clone(), directory.clone(), eager()).unwrap();
    directory.set("~nec", other.public_key("~nec").unwrap(), other_net.addr()).unwrap();
    eventually("~nec hears of the eighth entry", || seen_on(&other, "~nec", "zod") == 8);
    assert_eq!(moved.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    assert_eq!(moved.log_shares("~zod", "counter", "counter").unwrap(), ["nec"]);
}

#[test]
fn news_and_answers_with_too_many_parts_are_not_taken_in() {
    let dir = TempDir::new("flw-count");
    let directory = Directory::new();
    let (_zod, zod_net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let dev = [9u8; 32];
    directory.set("~dev", public_of(dev), "127.0.0.1:9".parse().unwrap()).unwrap();
    // A piece of news may name a few hundred logs. One that names more is refused whole,
    // before any of it is unpacked.
    let news = |logs: usize| Asked::News(ship_proto::News { logs: vec![ship_proto::LogNews::default(); logs] });
    match ask_ship(zod_net.addr(), "zod", dev, news(256)) {
        Some(Answered::Heard(heard)) => assert_eq!(heard.unknown, vec![true; 256]),
        other => panic!("not an answer to news: {other:?}"),
    }
    assert_eq!(ask_ship(zod_net.addr(), "zod", dev, news(257)), None);

    // Likewise an answer with more entries than are ever sent at once. It is not looked at,
    // so nothing in it can stop the log or be kept: the ship asks again later.
    let (nec, _kept) = fed_by("flw-count-b", Arc::new(|asked| match asked {
        Asked::Fetch(_) => fetched(vec![runtime::SignedEntry::default(); 257], ship_proto::LogHead::default()),
        _ => None,
    }));
    std::thread::sleep(Duration::from_millis(700));
    let log = followed(&nec, "~nec");
    assert_eq!((log.fetched, log.stopped, stopped_on(&nec, "~nec", "bus")), (0, None, String::new()));
}

#[test]
fn import_checks_what_a_ship_holds_of_other_ships_logs_and_who_follows_its_own() {
    let (a, b, out) = (TempDir::new("flw-imp-a"), TempDir::new("flw-imp-b"), TempDir::new("flw-imp-out"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("*"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "checkpoints broken");
    send(&zod, "~zod", "counter", "log poison");
    for _ in 0..5 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    // ~nec holds six entries of ~zod's log, and its agent has taken none of them.
    eventually("the entries are fetched", || followed(&nec, "~nec").fetched == 6);
    eventually("the agent has given up on them", || nec.pending("~nec").unwrap() == 0);

    // Export a ship, change its file, and import it under the given limits.
    let tampered = |rt: &Runtime, ship: &str, label: &str, statement: &str, cfg: Config| {
        let dir = TempDir::new(label);
        fs::remove_dir_all(&out.0).ok();
        fs::create_dir_all(&out.0).unwrap();
        rt.export_ship(ship, &out.0).unwrap();
        rusqlite::Connection::open(out.0.join(format!("{}.ship", ship.trim_start_matches('~')))).unwrap().execute_batch(statement).unwrap();
        let other = Runtime::open(&dir.0, cfg).unwrap();
        let result = other.import_ship(&out.0, ship);
        (result, other, dir)
    };
    let held = |label: &str, statement: &str| tampered(&nec, "~nec", label, statement, fast()).0;
    let refused = |label: &str, result: Result<(), Error>| assert!(result.is_err(), "{label} was let in");

    // As it stands, the file is let in, with what it held. The ship it follows is asked
    // afresh where its log stands, since an import may be a return to an earlier state.
    let (result, other, dir) = tampered(&nec, "~nec", "held-intact", "SELECT 1", fast());
    result.unwrap();
    let log = followed(&other, "~nec");
    assert_eq!((log.taken, log.fetched, log.announced), (0, 6, 6));
    drop(other);
    let file = rusqlite::Connection::open(dir.0.join("ships").join("nec.ship")).unwrap();
    assert_eq!(file.query_row("SELECT joined FROM remote_logs", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    // How much is held is counted afresh, so a wrong figure there does no harm.
    held("held-recount", "UPDATE remote_logs SET bytes = 999999").unwrap();

    // What is held must be exactly the entries between the agent's place and the newest
    // one fetched: none missing in the middle, at the end, or at the start, and none beyond.
    for (label, statement) in [
        ("held-gap", "DELETE FROM remote_entries WHERE seq = 3"),
        ("held-short", "DELETE FROM remote_entries WHERE seq = 6"),
        ("held-early", "DELETE FROM remote_entries WHERE seq = 1"),
        ("held-none", "DELETE FROM remote_entries"),
        ("held-beyond", "INSERT INTO remote_entries VALUES ('zod', 'counter', 'counter', 'tally', 7, x'00')"),
        ("held-ahead", "UPDATE follows SET cursor = 7 WHERE ship = 'zod'"),
        ("held-passed", "UPDATE follows SET cursor = 2 WHERE ship = 'zod'"),
        // Entries of a log nobody follows, a copy with no follower, and a follower with no copy.
        ("held-orphan", "INSERT INTO remote_entries VALUES ('bus', 'counter', 'counter', 'tally', 1, x'00')"),
        ("held-unfollowed", "DELETE FROM follows WHERE ship = 'zod'"),
        ("held-nothing", "DELETE FROM remote_logs; DELETE FROM remote_entries"),
        // The hash the next entry must link to is 32 bytes, and a reason is a few words.
        ("held-hash", "UPDATE remote_logs SET head_hash = x'0102'"),
        ("held-nohash", "UPDATE remote_logs SET head_hash = x''"),
        ("held-reason", "UPDATE remote_logs SET stopped = hex(zeroblob(101))"),
        // No entry is numbered beyond what any log could reach, held or only heard of.
        ("held-far", "UPDATE follows SET cursor = 2305843009213693953 WHERE ship = 'zod'; UPDATE remote_logs SET head = 2305843009213693953; DELETE FROM remote_entries"),
        ("held-far-heard", "UPDATE remote_logs SET announced = 2305843009213693953"),
    ] {
        refused(label, held(label, statement));
    }
    held("held-taken", "UPDATE follows SET cursor = 2 WHERE ship = 'zod'; DELETE FROM remote_entries WHERE seq <= 2").unwrap();
    held("held-stopped", "UPDATE remote_logs SET stopped = 'for a reason'").unwrap();
    // The other ship is a ship, and not this one.
    let renamed = |name: &str| {
        format!("UPDATE follows SET ship = '{name}' WHERE ship = 'zod'; UPDATE remote_logs SET peer = '{name}'; UPDATE remote_entries SET peer = '{name}'")
    };
    held("held-renamed", &renamed("bus")).unwrap();
    refused("held-name", held("held-name", &renamed("Not A Ship")));
    refused("held-self", held("held-self", &renamed("nec")));

    // A checkpoint held in place of dropped entries comes after the agent's place and no
    // later than the newest entry fetched, and the entries held start straight after it.
    let checkpoint = |seq: u64, also: &str| format!("INSERT INTO remote_checkpoints VALUES ('zod', 'counter', 'counter', 'tally', {seq}, x'aa'); {also}");
    held("held-cp", &checkpoint(3, "DELETE FROM remote_entries WHERE seq <= 3")).unwrap();
    refused("held-cp-over", held("held-cp-over", &checkpoint(3, "")));
    refused("held-cp-passed", held("held-cp-passed", &checkpoint(3, "DELETE FROM remote_entries WHERE seq <= 3; UPDATE follows SET cursor = 3 WHERE ship = 'zod'")));
    refused("held-cp-beyond", held("held-cp-beyond", &checkpoint(7, "DELETE FROM remote_entries")));
    refused("held-cp-orphan", held("held-cp-orphan", "INSERT INTO remote_checkpoints VALUES ('bus', 'counter', 'counter', 'tally', 1, x'aa')"));

    // No more is held than this runtime would have let it grow to, in all or in one entry.
    refused("held-much", tampered(&nec, "~nec", "held-much", "SELECT 1", Config { max_follow_bytes: 100, ..fast() }).0);
    tampered(&nec, "~nec", "held-enough", "SELECT 1", Config { max_follow_bytes: 400, ..fast() }).0.unwrap();
    refused("held-large", tampered(&nec, "~nec", "held-large", "SELECT 1", Config { max_event_bytes: 4, max_checkpoint_bytes: 4, ..fast() }).0);

    // A notice queued for the agent is about a log it follows on that ship, there is one
    // at most, and it carries no number.
    let notice = |ship: &str, number: u64| {
        format!("INSERT INTO inbox (kind, source, agent, interface, payload, ship, ship_seq) VALUES (3, 'counter', 'tally', 'counter', x'', '{ship}', {number});")
    };
    let (result, other, _dir) = tampered(&nec, "~nec", "held-notice", &notice("zod", 0), fast());
    result.unwrap();
    assert_eq!(other.pending("~nec").unwrap(), 1);
    refused("held-notice-twice", held("held-notice-twice", &[notice("zod", 0), notice("zod", 0)].concat()));
    refused("held-notice-stray", held("held-notice-stray", &notice("bus", 0)));
    refused("held-notice-numbered", held("held-notice-numbered", &notice("zod", 1)));

    // The publisher's side. ~zod's file says who may follow its log and who does. Let in
    // as it stands, every follower is marked to be told afresh where the log ends.
    let shared = |label: &str, statement: &str| tampered(&zod, "~zod", label, statement, fast()).0;
    let (result, other, dir) = tampered(&zod, "~zod", "pub-intact", "SELECT 1", fast());
    result.unwrap();
    assert_eq!(other.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
    drop(other);
    let file = rusqlite::Connection::open(dir.0.join("ships").join("zod.ship")).unwrap();
    assert_eq!(file.query_row("SELECT due FROM log_peers", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    shared("pub-everyone", "INSERT INTO log_shares VALUES ('counter', 'counter', '*')").unwrap();
    for (label, statement) in [
        // A log is shared with other ships, by name or with "*".
        ("pub-share-name", "INSERT INTO log_shares VALUES ('counter', 'counter', 'Not A Ship')"),
        ("pub-share-self", "INSERT INTO log_shares VALUES ('counter', 'counter', 'zod')"),
        ("pub-share-agent", "INSERT INTO log_shares VALUES ('Not An Agent', 'counter', 'bus')"),
        // A ship that follows a log is another ship, and one the log is shared with,
        // unless it has been shut out and is waiting to be told.
        ("pub-follower-uncovered", "DELETE FROM log_shares"),
        ("pub-follower-flag", "UPDATE log_peers SET kicked = 2"),
        ("pub-follower-self", "INSERT INTO log_shares VALUES ('counter', 'counter', '*'); INSERT INTO log_peers VALUES ('counter', 'counter', 'zod', 0, 0, 0)"),
        ("pub-follower-name", "INSERT INTO log_shares VALUES ('counter', 'counter', '*'); INSERT INTO log_peers VALUES ('counter', 'counter', 'Not A Ship', 0, 0, 0)"),
    ] {
        refused(label, shared(label, statement));
    }
    shared("pub-follower-kicked", "DELETE FROM log_shares; UPDATE log_peers SET kicked = 1").unwrap();
    // And only so many of each.
    refused("pub-share-many", tampered(&zod, "~zod", "pub-share-many", "SELECT 1", Config { max_log_shares: 0, ..fast() }).0);
    refused("pub-follower-many", tampered(&zod, "~zod", "pub-follower-many", "SELECT 1", Config { max_log_followers: 0, ..fast() }).0);
}

#[test]
fn an_answer_to_an_earlier_asking_is_not_taken_for_a_later_one() {
    let (entries, head) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3"]);
    // ~bus is slow to answer the first time it is asked, and says then that its log is
    // empty. By the time that answer arrives, ~nec's agent has stopped following and
    // started again. The answer is to the first asking. Taken for the second, it would
    // leave ~nec sure that it had asked, been answered, and had nothing to wait for.
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let (nec, _kept) = fed_by("flw-stale", Arc::new(move |request| match request {
        Asked::Fetch(_) if count.fetch_add(1, Ordering::SeqCst) == 0 => {
            std::thread::sleep(Duration::from_millis(700));
            fetched(Vec::new(), ship_proto::LogHead::default())
        }
        Asked::Fetch(fetch) => fetched(entries.iter().skip(fetch.after as usize).cloned().collect(), head.clone()),
        _ => None,
    }));
    eventually("the first question is put", || asked.load(Ordering::SeqCst) == 1);
    send(&nec, "~nec", "tally", "unfollow-on bus");
    send(&nec, "~nec", "tally", "follow-on bus");
    eventually("the second asking gets its own answer", || seen_on(&nec, "~nec", "bus") == 3);

    // The same when the agent asks again without having stopped: asking again is asking
    // afresh, and the answer to the asking before is not the answer to this one.
    let (entries, head) = signed_log(BUS, "bus", "counter", "counter", &["a=1", "a=2", "a=3"]);
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let (nec, _kept) = fed_by("flw-stale-again", Arc::new(move |request| match request {
        Asked::Fetch(_) if count.fetch_add(1, Ordering::SeqCst) == 0 => {
            std::thread::sleep(Duration::from_millis(700));
            fetched(Vec::new(), ship_proto::LogHead::default())
        }
        Asked::Fetch(fetch) => fetched(entries.iter().skip(fetch.after as usize).cloned().collect(), head.clone()),
        _ => None,
    }));
    eventually("the first question is put", || asked.load(Ordering::SeqCst) == 1);
    send(&nec, "~nec", "tally", "follow-on bus");
    eventually("the second asking gets its own answer", || seen_on(&nec, "~nec", "bus") == 3);
}

#[test]
fn an_answer_is_sized_by_what_is_sent_signatures_and_all() {
    let (a, b) = (TempDir::new("flw-size-a"), TempDir::new("flw-size-b"));
    let directory = Directory::new();
    // Two runtimes set up alike, with small messages. Many small entries are waiting. An
    // answer is filled by the size it will have on the wire, so it is one the other ship
    // will read. Counted by the entries alone it would be too large, be refused, and be
    // sent again just the same.
    let small = Config { max_event_bytes: 200, max_checkpoint_bytes: 200, ..fast() };
    let net = NetConfig { max_message_bytes: 200 + 4096, ..eager() };
    let (zod, _zod_net) = crewed_on(&a, "~zod", &directory, small.clone(), net.clone(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed_on(&b, "~nec", &directory, small, net, open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "checkpoints broken");
    for _ in 0..64 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("every entry arrives", || seen_on(&nec, "~nec", "zod") == 64);
}

#[test]
fn entries_asked_for_before_stopping_cannot_be_collected_after_starting_again() {
    let (a, b) = (TempDir::new("flw-sneak-a"), TempDir::new("flw-sneak-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // Nothing queued on ~nec runs by itself, so what is fetched stays held.
    let cfg = Config { max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    for _ in 0..3 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entries are fetched", || followed(&nec, "~nec").fetched == 3);

    // In one event the agent asks for entries without room to be handed them, stops
    // following, follows again, and tries to collect what it asked for before. There is
    // nothing to collect. Were there, its place in the new following would move past
    // entries it has never been given.
    assert_eq!(send(&nec, "~nec", "tally", "sneak-on zod"), "true -1");
    assert_eq!(followed(&nec, "~nec").taken, 0);
    eventually("the log is fetched again from the start", || followed(&nec, "~nec").fetched == 3);
    let (out, other) = (TempDir::new("flw-sneak-out"), TempDir::new("flw-sneak-other"));
    nec.export_ship("~nec", &out.0).unwrap();
    Runtime::open(&other.0, fast()).unwrap().import_ship(&out.0, "~nec").unwrap();
}

#[test]
fn an_agent_far_behind_works_through_the_whole_log_without_further_prompting() {
    let (a, b) = (TempDir::new("flw-long-a"), TempDir::new("flw-long-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "checkpoints broken");
    for _ in 0..1000 {
        send(&zod, "~zod", "counter", "log hits");
    }
    // ~nec fetches all thousand in four goes. Its agent takes three each time it is
    // prompted, which is over three hundred rounds: more than are run on the strength of
    // four things arriving from outside. Nothing else happens on either ship, and it
    // finishes.
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the agent has every entry", || seen_on(&nec, "~nec", "zod") == 1000);
}

#[test]
fn being_told_a_log_is_closed_is_a_reason_to_ask_and_no_more() {
    let (a, b) = (TempDir::new("flw-closed-a"), TempDir::new("flw-closed-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "log hits");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entry arrives", || seen_on(&nec, "~nec", "zod") == 1);

    // News that the log is closed to ~nec reaches it late: sent while ~nec was shut out,
    // arriving after it was let back in. (Here it is sent by hand, as ~zod.) ~nec does not
    // stop on the strength of it. It asks ~zod, which shares the log, and carries on.
    let seed: [u8; 32] = fs::read(a.0.join("keys").join("zod.key")).unwrap().try_into().unwrap();
    let closed = ship_proto::LogNews { agent: "counter".into(), log: "counter".into(), head: 0, closed: true };
    let heard = ask_ship(nec_net.addr(), "nec", seed, Asked::News(ship_proto::News { logs: vec![closed] }));
    assert_eq!(heard, Some(Answered::Heard(ship_proto::Heard { unknown: vec![false] })));
    send(&zod, "~zod", "counter", "log hits");
    eventually("~nec carries on", || seen_on(&nec, "~nec", "zod") == 2);
    assert_eq!((stopped_on(&nec, "~nec", "zod"), followed(&nec, "~nec").stopped), (String::new(), None));
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
}

#[test]
fn an_agent_that_asks_again_whenever_it_is_refused_is_held_to_a_slow_pace() {
    // ~bus refuses every time. ~nec's agent answers each refusal by asking again, at once.
    // Each refusal counts as a try that failed, and tries that fail are spaced out, so the
    // two ships are not kept busy for as long as the agent cares to go on.
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let dir = TempDir::new("flw-stubborn");
    let directory = Directory::new();
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 0, Some(Arc::new(move |request| match request {
        Asked::Fetch(_) => {
            count.fetch_add(1, Ordering::SeqCst);
            Some(Answered::Fetched(ship_proto::Fetched { denied: "no".into(), ..Default::default() }))
        }
        _ => None,
    })));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    let (nec, _nec_net) = crewed(&dir, "~nec", &directory, fast(), open_counter(), following_tally("*"));
    send(&nec, "~nec", "tally", "stubborn");
    send(&nec, "~nec", "tally", "follow-on bus");
    std::thread::sleep(Duration::from_millis(2500));
    // Tries are at most 300ms apart here, so there have been a handful. Not hundreds.
    let tries = asked.load(Ordering::SeqCst);
    assert!((3..=40).contains(&tries), "asked {tries} times in two and a half seconds");
}

#[test]
fn an_answer_given_before_a_log_was_closed_does_not_call_off_the_asking() {
    // ~bus answers the first question slowly: its log is shared, and empty. Before that
    // answer arrives, ~nec is told the log is closed to it, which makes it ask afresh. The
    // slow answer is to the question from before. Taken as the answer to the new one, it
    // would leave ~nec following a log it has been shut out of, and never told so.
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    let (nec, kept) = fed_by("flw-closed-late", Arc::new(move |request| match request {
        Asked::Fetch(_) if count.fetch_add(1, Ordering::SeqCst) == 0 => {
            std::thread::sleep(Duration::from_millis(700));
            fetched(Vec::new(), ship_proto::LogHead::default())
        }
        Asked::Fetch(_) => Some(Answered::Fetched(ship_proto::Fetched { denied: "no".into(), ..Default::default() })),
        _ => None,
    }));
    eventually("the first question is put", || asked.load(Ordering::SeqCst) == 1);
    let closed = ship_proto::LogNews { agent: "counter".into(), log: "counter".into(), head: 0, closed: true };
    let heard = ask_ship(kept.1.addr(), "nec", BUS, Asked::News(ship_proto::News { logs: vec![closed] }));
    assert_eq!(heard, Some(Answered::Heard(ship_proto::Heard { unknown: vec![false] })));
    eventually("~nec asks again and is told the log has stopped", || stopped_on(&nec, "~nec", "bus").contains("does not share"));
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

#[test]
fn looking_at_a_followed_log_without_taking_anything_keeps_nothing_running() {
    let (a, b) = (TempDir::new("flw-idle-a"), TempDir::new("flw-idle-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "log hits");
    // ~nec's agent is prompted about the entry and never takes it.
    send(&nec, "~nec", "tally", "lazy");
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("the entry is fetched", || followed(&nec, "~nec").fetched == 1);
    eventually("the agent has given up on it", || nec.pending("~nec").unwrap() == 0);

    // Now it sends itself a command that looks at the log, takes nothing, and sends itself
    // the same again. Taking entries from another ship's log is a reason to keep a ship's
    // queue running. Looking is not: the chain is run as far as any chain of commands is,
    // and then waits.
    send(&nec, "~nec", "tally", "idle-on zod");
    std::thread::sleep(Duration::from_millis(1500));
    let idles: usize = view(&nec, "~nec", "tally", "idles").parse().unwrap();
    assert!(idles <= 200, "the chain ran {idles} times");
    let pending = nec.pending("~nec").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!((nec.pending("~nec").unwrap(), followed(&nec, "~nec").taken), (pending, 0));
}

#[test]
fn a_ship_short_of_room_takes_on_no_new_followers_until_it_has_some() {
    let (a, b) = (TempDir::new("flw-tight-a"), TempDir::new("flw-tight-b"));
    let directory = Directory::new();
    // ~zod's file is small and its counter has nearly filled it: less is free than ~zod
    // keeps for taking a command from another ship.
    let cfg = Config { max_ship_bytes: 420 << 10, ..fast() };
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, cfg, open_counter(), far_tally("*"));
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, fast(), open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    send(&zod, "~zod", "counter", "log hits");
    assert_eq!(send(&zod, "~zod", "counter", "big 200000"), "ok");

    // Noting ~nec as a follower would be one more record written because another ship
    // asked. ~zod does not write it. ~nec is not refused for good: it goes on asking.
    send(&nec, "~nec", "tally", "follow-on zod");
    std::thread::sleep(Duration::from_millis(700));
    assert!(zod.log_followers("~zod", "counter", "counter").unwrap().is_empty());
    assert_eq!((followed(&nec, "~nec").fetched, followed(&nec, "~nec").stopped), (0, None));
    // ~zod can still take a command, which is what the room is kept for.
    send(&nec, "~nec", "tally", "tell zod inc hits");
    eventually("the command runs on ~zod", || count(&zod, "~zod", "hits") == "1");

    // Its counter lets go of what it was holding, and ~nec gets in.
    send(&zod, "~zod", "counter", "del big");
    eventually("~nec follows", || seen_on(&nec, "~nec", "zod") == 1);
    assert_eq!(zod.log_followers("~zod", "counter", "counter").unwrap(), ["nec"]);
}

#[test]
fn a_ship_shut_out_of_a_log_is_not_told_how_far_it_has_got_since() {
    let dir = TempDir::new("flw-closed-head");
    let directory = Directory::new();
    let (zod, zod_net) = crewed(&dir, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    send(&zod, "~zod", "counter", "share *");
    // ~bus is a stand-in that notes whatever it is told about ~zod's logs.
    let told = Arc::new(std::sync::Mutex::new(Vec::new()));
    let noted = told.clone();
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 0, Some(Arc::new(move |asked| match asked {
        Asked::News(news) => {
            noted.lock().unwrap().extend(news.logs.iter().map(|log| (log.closed, log.head)));
            Some(Answered::Heard(ship_proto::Heard { unknown: vec![false; news.logs.len()] }))
        }
        _ => None,
    })));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    assert!(matches!(ask_ship(zod_net.addr(), "zod", BUS, fetch("counter", "counter", 0, true)), Some(Answered::Fetched(_))));

    // While ~zod is off the network, its counter shuts ~bus out, and then the log grows.
    // Back on, ~zod tells ~bus the log is closed to it. It does not say where the log has
    // got to: that happened after ~bus was shut out.
    drop(zod_net);
    send(&zod, "~zod", "counter", "unshare *");
    for _ in 0..3 {
        send(&zod, "~zod", "counter", "log hits");
    }
    let zod_net = Network::start(zod.clone(), directory.clone(), eager()).unwrap();
    directory.set("~zod", zod.public_key("~zod").unwrap(), zod_net.addr()).unwrap();
    eventually("~bus is told the log is closed", || !told.lock().unwrap().is_empty());
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(*told.lock().unwrap(), [(true, 0)]);
}

#[test]
fn a_ship_holds_only_so_much_of_a_log_however_much_it_is_sent() {
    // ~bus sends all forty entries of its log at once, whatever it is asked for. ~nec keeps
    // what it has room to hold for its agent, which has yet to take any, and lets the rest
    // go by: it will ask for them when there is room.
    let payloads: Vec<String> = (1..=40).map(|n| format!("a={n}")).collect();
    let (entries, _) = signed_log(BUS, "bus", "counter", "counter", &payloads.iter().map(String::as_str).collect::<Vec<_>>());
    let dir = TempDir::new("flw-hold");
    let directory = Directory::new();
    let (addr, _running, _) = stand_in_with(BUS, BUS, true, 0, Some(serving(entries)));
    directory.set("~bus", public_of(BUS), addr).unwrap();
    let cfg = Config { max_follow_bytes: 400, max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&dir, "~nec", &directory, cfg, open_counter(), following_tally("*"));
    send(&nec, "~nec", "tally", "follow-on bus");
    eventually("~nec has fetched what it will hold", || followed(&nec, "~nec").fetched >= 6);
    std::thread::sleep(Duration::from_millis(500));
    let log = followed(&nec, "~nec");
    assert!((log.taken, log.announced) == (0, 40) && log.fetched <= 7, "{log:?}");
}

#[test]
fn an_agent_taking_entries_makes_room_and_more_are_fetched() {
    let (a, b) = (TempDir::new("flw-refill-a"), TempDir::new("flw-refill-b"));
    let directory = Directory::new();
    let (zod, _zod_net) = crewed(&a, "~zod", &directory, fast(), open_counter(), far_tally("*"));
    // Nothing queued on ~nec runs by itself, and it holds about a thousand bytes of a log.
    let cfg = Config { max_follow_bytes: 1000, max_queued_per_deliver: 0, ..fast() };
    let (nec, _nec_net) = crewed(&b, "~nec", &directory, cfg, open_counter(), following_tally("zod"));
    send(&zod, "~zod", "counter", "share nec");
    for _ in 0..60 {
        send(&zod, "~zod", "counter", "log hits");
    }
    send(&nec, "~nec", "tally", "follow-on zod");
    eventually("~nec has fetched what it will hold", || followed(&nec, "~nec").fetched >= 14);
    std::thread::sleep(Duration::from_millis(500));
    let held = followed(&nec, "~nec").fetched;
    assert!(held <= 15, "{held}");

    // The agent is given its turn once, and takes three entries. That alone is what makes
    // ~nec ask for more: nothing else is happening on either ship.
    assert_eq!(nec.run_pending("~nec", 1).unwrap(), 1);
    assert_eq!(followed(&nec, "~nec").taken, 3);
    eventually("more is fetched", || followed(&nec, "~nec").fetched > held);
}
