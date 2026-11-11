use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use runtime::{verify_log, Config, Durability, Error, Limits, Manifest, Provide, Rejection, Runtime, Use};

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
    Manifest { provides: vec![Provide { interface: "counter".into(), public }], uses: vec![] }
}

/// The tally agent offers `tally` and, when `uses_counter` is set, declares that it reads from
/// and sends to the counter.
fn tally_manifest(uses_counter: bool) -> Manifest {
    let uses = Use { agent: "counter".into(), interface: "counter".into(), read: true, send: true };
    Manifest {
        provides: vec![Provide { interface: "tally".into(), public: false }],
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
    let offers_x = Manifest { provides: vec![Provide { interface: "x".into(), public: false }], uses: vec![] };
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
        provides: vec![Provide { interface: "tally".into(), public: false }],
        uses: vec![Use { agent: "counter".into(), interface: "counter".into(), read, send }],
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
            Provide { interface: "x".into(), public: false },
            Provide { interface: "x".into(), public: true },
        ],
        uses: vec![],
    };
    assert!(matches!(rt.install("~zod", "twice", &hash, &twice), Err(Error::InstallRefused(_))));
    let same_use = Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false };
    let twice = Manifest { provides: vec![], uses: vec![same_use.clone(), Use { send: true, ..same_use }] };
    assert!(matches!(rt.install("~zod", "twice", &hash, &twice), Err(Error::InstallRefused(_))));

    // Every public interface is visible to every agent. Keep adding agents that each offer many
    // until the kernel says no, then check that what it accepted still works.
    let wide = |agent: usize| Manifest {
        provides: (0..64).map(|i| Provide { interface: format!("{}-{agent}-{i}", "x".repeat(100)), public: true }).collect(),
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
        provides: (0..64).map(|i| Provide { interface: format!("{}-{agent}-{i}", "x".repeat(100)), public: false }).collect(),
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
    let public = Manifest { provides: vec![Provide { interface: "slow".into(), public: true }], uses: vec![] };
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
    let send_request = SendRequest { agent: "../up".into(), interface: "x".into(), payload: b"p".to_vec() }.encode_to_vec();
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
        reads: vec![Grant { agent: "other".into(), interface: "x".into() }, Grant { agent: "evil".into(), interface: long_name }],
        sends: vec![Grant { agent: "../up".into(), interface: "x".into() }],
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
    let cfg = Config { max_ship_bytes: 96 << 10, ..fast() };
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
        uses: vec![Use { agent: "tally".into(), interface: "tally".into(), read: true, send: false }],
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
        runtime::SignedEntry { signature: signer.sign(&body).to_bytes().to_vec(), body }
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
    let dir = TempDir::new("log-quota");
    let rt = boot(&dir, Config { max_log_bytes: 600, ..fast() });
    let mut accepted = 0;
    let refused = loop {
        match rt.deliver("~zod", "counter", b"log hits") {
            Ok(_) => accepted += 1,
            Err(Error::Rejected(rejection)) => break rejection,
            Err(e) => panic!("unexpected error: {e}"),
        }
    };
    assert!(matches!(refused, Rejection::Limit(_)), "{refused:?}");
    assert!((1..10).contains(&accepted), "accepted {accepted}");
    // The refused append left nothing behind, and the count survives a sleep and wake.
    assert_eq!(rt.log_entries("~zod", "counter", "counter", 0, NO_LIMIT).unwrap().len(), accepted);
    rt.sleep_idle(Duration::ZERO);
    assert!(matches!(rejection(&rt, "counter", "log hits"), Rejection::Limit(_)));
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
    let request = FollowRequest { agent: "counter".into(), log: "counter".into() }.encode_to_vec();
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
        uses: if allowed { vec![Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false }] } else { vec![] },
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
    let follow = FollowRequest { agent: "counter".into(), log: "counter".into() }.encode_to_vec();
    let next = NextRequest { agent: "counter".into(), log: "counter".into(), max: 10 }.encode_to_vec();
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
        uses: vec![Use { agent: "counter".into(), interface: "counter".into(), read: true, send: false }],
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
    let follow = FollowRequest { agent: "echo".into(), log: "e".into() }.encode_to_vec();
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
    let offers_e = Manifest { provides: vec![Provide { interface: "e".into(), public: false }], uses: vec![] };
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
