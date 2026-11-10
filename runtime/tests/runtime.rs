use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use runtime::{Config, Durability, Error, Limits, Rejection, Runtime};

const NO_LIMIT: usize = usize::MAX;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// Build the counter agent once per test run. A separate target dir avoids the outer cargo's lock.
fn counter_wasm() -> &'static [u8] {
    static WASM: OnceLock<Vec<u8>> = OnceLock::new();
    WASM.get_or_init(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .current_dir(workspace())
            .args(["build", "-p", "counter", "--release", "--target", "wasm32-unknown-unknown"])
            .args(["--target-dir", "target/wasm"])
            .status()
            .expect("run cargo");
        assert!(status.success(), "building the counter agent failed");
        fs::read(workspace().join("target/wasm/wasm32-unknown-unknown/release/counter.wasm")).unwrap()
    })
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
    let hash = rt.add_module(counter_wasm()).unwrap();
    rt.create_ship("~zod").unwrap();
    rt.install("~zod", "counter", &hash).unwrap();
    rt
}

/// A runtime with one ship, `~zod`, running a hand-written module as `evil`.
fn boot_wat(dir: &TempDir, cfg: Config, source: &str) -> Runtime {
    let rt = Runtime::open(&dir.0, cfg).unwrap();
    let hash = rt.add_module(&wat::parse_str(source).unwrap()).unwrap();
    rt.create_ship("~zod").unwrap();
    rt.install("~zod", "evil", &hash).unwrap();
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
    let hash = rt.add_module(counter_wasm()).unwrap();
    rt.create_ship("~bus").unwrap();
    rt.install("~bus", "counter", &hash).unwrap();
    rt.install("~zod", "other", &hash).unwrap();

    send(&rt, "~zod", "counter", "inc hits 7");
    assert_eq!(send(&rt, "~bus", "counter", "get hits"), "0");
    assert_eq!(send(&rt, "~zod", "other", "get hits"), "0");
    assert_eq!(rt.compiled_modules(), 1);
}

#[test]
fn bad_names_and_unknown_targets_are_refused() {
    let dir = TempDir::new("names");
    let rt = boot(&dir, fast());

    for name in ["../zod", "zod/../../etc", "", "ZOD", "zod.ship", "-zod"] {
        assert!(matches!(rt.create_ship(name), Err(Error::InvalidName(_))), "{name:?}");
    }
    assert!(matches!(rt.create_ship("zod"), Err(Error::ShipExists(_))));
    assert!(matches!(rt.deliver("~nec", "counter", b"get x"), Err(Error::UnknownShip(_))));
    assert!(matches!(rt.deliver("~zod", "nope", b"get x"), Err(Error::UnknownAgent(_))));
    assert!(matches!(rt.install("~zod", "x", &"0".repeat(64)), Err(Error::UnknownModule(_))));
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
    let hash = rt.add_module(counter_wasm()).unwrap();
    let names: Vec<String> = (0..12).map(|i| format!("ship-{}", (b'a' + i) as char)).collect();
    for name in &names {
        rt.create_ship(name).unwrap();
        rt.install(name, "counter", &hash).unwrap();
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
    let hash = rt.add_module(counter_wasm()).unwrap();
    let names: Vec<String> = (0..8).map(|i| format!("ship-{}", (b'a' + i) as char)).collect();
    for name in &names {
        rt.create_ship(name).unwrap();
        rt.install(name, "counter", &hash).unwrap();
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
    // No loop and no call after the emit, so nothing interrupts these fills. The event comes back
    // late and must be thrown away.
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
