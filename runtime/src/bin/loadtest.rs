//! Simulated load: many ships in one runtime, a subset of them busy.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use runtime::{Config, Durability, Runtime};

struct Args {
    ships: usize,
    active: usize,
    events: u64,
    threads: usize,
    max_awake: usize,
    durability: Durability,
    wasm: PathBuf,
    dir: PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        ships: 500,
        active: 50,
        events: 20_000,
        threads: 8,
        max_awake: 64,
        durability: Durability::Full,
        wasm: PathBuf::from("target/wasm/wasm32-unknown-unknown/release/counter.wasm"),
        dir: std::env::temp_dir().join(format!("urbit-wasm-loadtest-{}", std::process::id())),
    };
    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        let value = raw.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        let number = || value.parse::<usize>().unwrap_or_else(|_| panic!("{flag} needs a number"));
        match flag.as_str() {
            "--ships" => args.ships = number(),
            "--active" => args.active = number(),
            "--events" => args.events = number() as u64,
            "--threads" => args.threads = number(),
            "--max-awake" => args.max_awake = number(),
            "--sync" => {
                args.durability = match value.as_str() {
                    "full" => Durability::Full,
                    "normal" => Durability::Normal,
                    _ => panic!("--sync is full or normal"),
                }
            }
            "--wasm" => args.wasm = PathBuf::from(&value),
            "--dir" => args.dir = PathBuf::from(&value),
            _ => panic!("unknown flag {flag}"),
        }
    }
    args.active = args.active.min(args.ships);
    args
}

fn rss_mb() -> f64 {
    let out = Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output();
    out.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map_or(f64::NAN, |kib| kib / 1024.0)
}

fn dir_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|entries| entries.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

fn ship_name(index: usize) -> String {
    let mut name = String::from("ship-");
    let mut n = index;
    loop {
        name.push((b'a' + (n % 26) as u8) as char);
        n /= 26;
        if n == 0 {
            return name;
        }
    }
}

fn percentile(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index] as f64 / 1000.0
}

fn main() {
    let args = parse_args();
    let wasm = std::fs::read(&args.wasm).unwrap_or_else(|_| {
        panic!(
            "agent not found at {}; build it with: cargo build -p counter --release \
             --target wasm32-unknown-unknown --target-dir target/wasm",
            args.wasm.display()
        )
    });
    // Only ever delete a directory this run created.
    std::fs::create_dir(&args.dir)
        .unwrap_or_else(|e| panic!("{} must not already exist: {e}", args.dir.display()));
    let cfg = Config { max_awake: args.max_awake, durability: args.durability, ..Config::default() };
    let rt = Runtime::open(&args.dir, cfg).expect("open runtime");
    let rss_empty = rss_mb();

    let started = Instant::now();
    let hash = rt.add_module(&wasm).expect("add module");
    let names: Vec<String> = (0..args.ships).map(ship_name).collect();
    for name in &names {
        rt.create_ship(name).expect("create ship");
        rt.install(name, "counter", &hash).expect("install");
    }
    let setup = started.elapsed();
    rt.sleep_idle(Duration::ZERO);
    let rss_asleep = rss_mb();

    // Cold path: every delivery wakes a sleeping ship.
    let mut cold: Vec<u32> = names
        .iter()
        .take(200)
        .map(|name| {
            let at = Instant::now();
            rt.deliver(name, "counter", b"inc cold").expect("deliver");
            at.elapsed().as_micros() as u32
        })
        .collect();
    cold.sort_unstable();
    rt.sleep_idle(Duration::ZERO);

    // Busy path: threads hammer a subset of ships.
    let remaining = AtomicU64::new(args.events);
    let started = Instant::now();
    let mut warm: Vec<u32> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..args.threads)
            .map(|worker| {
                let (rt, names, remaining) = (&rt, &names, &remaining);
                scope.spawn(move || {
                    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ ((worker as u64 + 1) << 32);
                    let mut latencies = Vec::new();
                    while remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                        .is_ok()
                    {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        let name = &names[(seed % args.active as u64) as usize];
                        let at = Instant::now();
                        rt.deliver(name, "counter", b"inc hits").expect("deliver");
                        latencies.push(at.elapsed().as_micros() as u32);
                    }
                    latencies
                })
            })
            .collect();
        workers.into_iter().flat_map(|w| w.join().expect("worker")).collect()
    });
    let busy = started.elapsed();
    let rss_busy = rss_mb();
    let awake_busy = rt.awake();
    warm.sort_unstable();

    // Every event must be accounted for: nothing lost, nothing applied twice.
    let total: u64 = names
        .iter()
        .take(args.active)
        .map(|name| {
            let reply = rt.deliver(name, "counter", b"get hits").expect("deliver").reply;
            String::from_utf8(reply).unwrap().parse::<u64>().unwrap()
        })
        .sum();
    assert_eq!(total, args.events, "event count mismatch");

    rt.sleep_idle(Duration::ZERO);
    let disk = dir_bytes(&args.dir.join("ships"));

    println!("ships {}  active {}  threads {}  max awake {}", args.ships, args.active, args.threads, args.max_awake);
    println!("durability {:?}", args.durability);
    println!("setup            {:.2} s ({:.2} ms per ship)", setup.as_secs_f64(), setup.as_secs_f64() * 1000.0 / args.ships as f64);
    println!("memory empty     {rss_empty:.1} MB");
    println!("memory asleep    {rss_asleep:.1} MB with all {} ships asleep", args.ships);
    println!("memory busy      {rss_busy:.1} MB with {awake_busy} ships awake");
    println!("throughput       {:.0} events/s over {} events", args.events as f64 / busy.as_secs_f64(), args.events);
    println!("busy latency     p50 {:.2} ms  p99 {:.2} ms  p99.9 {:.2} ms  max {:.2} ms", percentile(&warm, 0.5), percentile(&warm, 0.99), percentile(&warm, 0.999), percentile(&warm, 1.0));
    println!("cold wake        p50 {:.2} ms  p99 {:.2} ms  max {:.2} ms", percentile(&cold, 0.5), percentile(&cold, 0.99), percentile(&cold, 1.0));
    println!("disk             {:.1} KB per ship", disk as f64 / 1024.0 / args.ships as f64);
    println!("events verified  {total}");

    drop(rt);
    let _ = std::fs::remove_dir_all(&args.dir);
}
