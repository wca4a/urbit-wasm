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
    let next = NextRequest { agent: "counter".into(), log: "counter".into(), max: 10, checkpoints: false }.encode_to_vec();
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

/// Small enough that a checkpoint is asked for every few entries.
fn checkpointing() -> Config {
    Config { checkpoint_min_bytes: 500, ..fast() }
}

/// The counter agent offering both its state log and its journal, which is a history.
fn counter_with_journal() -> Manifest {
    let provide = |interface: &str| Provide { interface: interface.into(), public: false };
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
    let cfg = Config { max_ship_bytes: 128 << 10, checkpoint_min_bytes: 0, ..fast() };
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
