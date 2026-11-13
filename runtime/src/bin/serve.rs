//! Serve the ships in a data directory over HTTP, so that apps and browsers can sign in.
//!
//! With `--demo` it also makes a ship, `~zod`, running the toy counter agent, and prints an
//! access code and a one-time sign-in link for it.
//!
//! With `--net` the ships also talk to ships on other runtimes, each known by the key Urbit
//! ID lists for its name, read from Azimuth through the Ethereum node given with
//! `--ethereum`. `--lookup` prints what Urbit ID lists for a ship, and stops.
//!
//! With `--azimuth-copy` those keys come from a copy of Azimuth kept in a file and worked
//! out from Ethereum alone, in place of asking the roller about ships on layer 2.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use runtime::azimuth::{Azimuth, AzimuthConfig, Keys};
use runtime::replica::{Replica, ReplicaConfig, TroubleWatch};
use runtime::net::{Directory, NetConfig, Network};
use runtime::server::{Server, ServerConfig};
use runtime::urbit_id::ob;
use runtime::{Config, Error, Manifest, Provide, Runtime, StorageKey};

const USAGE: &str = "usage: serve --dir <data directory> [--addr 127.0.0.1:8080] [--host-suffix .example.net]
             [--storage-key-file <file>] [--secure-cookies] [--access-code <ship>] [--signin-link <ship>]
             [--demo [--kernel <kernel.wasm>] [--counter <counter.wasm>]]
             [--ethereum <url> [--roller <url> | --azimuth-copy <file>]] [--net <address>]
             [--peer <ship>=<address>]...
             [--keyfile <file>] [--lookup <ship>]...

  --storage-key-file <file>
                         the key the ships' files are encrypted under, as 64 hexadecimal digits,
                         kept somewhere other than the data directory. Without it the key is
                         made and kept in the data directory, as storage.key
  --access-code <ship>   give the ship a new reusable access code and print it
  --signin-link <ship>   print a one-time sign-in link for the ship, good for ten minutes
  --demo                 make a ship ~zod with the counter agent, if there is none, and print
                         an access code and a sign-in link for it
  --ethereum <url>       an Ethereum node to read Urbit ID (Azimuth) through
  --roller <url>         the service to ask about ships on layer 2; Urbit's own if not given
  --azimuth-copy <file>  keep a copy of Azimuth in this file, worked out from what was written
                         to Ethereum, and read keys from it instead of asking the roller. The
                         first time, reading all of Azimuth's history takes a while; the node
                         must answer eth_getLogs for old blocks
  --net <address>        talk to ships on other runtimes, listening here (UDP), each ship
                         known by the key Urbit ID lists for it. Needs --ethereum
  --peer <ship>=<addr>   where another ship is to be found. Its key comes from Urbit ID
  --keyfile <file>       start the ship this keyfile is for, if it is not here already
  --lookup <ship>        print what Urbit ID lists for a ship, and stop. Needs --ethereum";

fn fail(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(2)
}

/// Say, on a thread of its own, when the copy of Azimuth runs into trouble and when it is out
/// of it, once each, for as long as the copy is open.
fn watch(replica: std::sync::Weak<Replica>) {
    std::thread::spawn(move || {
        let mut watch = TroubleWatch::default();
        while let Some(replica) = replica.upgrade() {
            if let Some(said) = watch.notice(&replica.status()) {
                eprintln!("{said}");
            }
            drop(replica);
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

/// Wait until the copy of Azimuth answers lookups, saying how far along it is.
fn wait_for(replica: &Replica) {
    let started = std::time::Instant::now();
    let mut said = std::time::Instant::now();
    loop {
        let status = replica.status();
        if replica.caught_up() {
            let counts = status.counts;
            eprintln!(
                "The copy of Azimuth has read every block up to {}, the newest final one, in {} seconds. It has read {} logs and {} batches, {} of them unreadable. Of the layer 2 transactions, {} were done, {} were refused by the rules, and {} were not properly signed.",
                status.read_to,
                started.elapsed().as_secs(),
                counts.logs,
                counts.batches,
                counts.unreadable,
                counts.applied,
                counts.failed,
                counts.unsigned
            );
            return;
        }
        if said.elapsed() >= Duration::from_secs(10) {
            said = std::time::Instant::now();
            let trouble = status.trouble.map_or(String::new(), |why| format!(" Last trouble: {why}."));
            let of = status.finalized.map_or(String::new(), |finalized| format!(" of {finalized}"));
            eprintln!("Reading Azimuth: block {}{of}, {} logs and {} batches so far.{trouble}", status.read_to, status.counts.logs, status.counts.batches);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn main() {
    let (mut dir, mut addr, mut host_suffix) = (None, "127.0.0.1:8080".to_string(), None);
    let (mut secure_cookies, mut demo) = (false, false);
    let mut storage_key_file = None;
    let (mut access_codes, mut signin_links) = (Vec::new(), Vec::new());
    let (mut ethereum, mut roller, mut net, mut peers, mut keyfile, mut lookups) = (None, None, None, Vec::new(), None, Vec::new());
    let mut azimuth_copy = None;
    let mut kernel = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/kernel.wasm");
    let mut counter = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/counter.wasm");

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        let mut value = || raw.next().unwrap_or_else(|| fail(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(value())),
            "--addr" => addr = value(),
            "--host-suffix" => host_suffix = Some(value()),
            "--storage-key-file" => storage_key_file = Some(PathBuf::from(value())),
            "--secure-cookies" => secure_cookies = true,
            "--demo" => demo = true,
            "--access-code" => access_codes.push(value()),
            "--signin-link" => signin_links.push(value()),
            "--kernel" => kernel = PathBuf::from(value()),
            "--counter" => counter = PathBuf::from(value()),
            "--ethereum" => ethereum = Some(value()),
            "--roller" => roller = Some(value()),
            "--azimuth-copy" => azimuth_copy = Some(PathBuf::from(value())),
            "--net" => net = Some(value()),
            "--peer" => peers.push(value()),
            "--keyfile" => keyfile = Some(PathBuf::from(value())),
            "--lookup" => lookups.push(value()),
            _ => fail(&format!("unknown flag {flag}")),
        }
    }
    if azimuth_copy.is_some() && roller.is_some() {
        fail("--azimuth-copy needs no roller");
    }
    let azimuth: Option<Arc<dyn Keys>> = match (ethereum, azimuth_copy) {
        (None, Some(_)) => fail("--azimuth-copy needs --ethereum"),
        (None, None) => None,
        (Some(ethereum), None) => {
            let mut cfg = AzimuthConfig::mainnet(&ethereum);
            if let Some(roller) = roller {
                cfg.roller = Some(roller);
            }
            Some(Arc::new(Azimuth::new(cfg)))
        }
        (Some(ethereum), Some(file)) => {
            let replica = Replica::open(&file, ReplicaConfig::mainnet(&ethereum)).unwrap_or_else(|e| fail(&format!("cannot open {}: {e}", file.display())));
            replica.keep_up();
            let replica = Arc::new(replica);
            if !lookups.is_empty() {
                wait_for(&replica);
            } else {
                watch(Arc::downgrade(&replica));
            }
            Some(replica)
        }
    };
    if !lookups.is_empty() {
        let azimuth = azimuth.unwrap_or_else(|| fail("--lookup needs --ethereum"));
        for ship in &lookups {
            let Some(number) = ob::ship_number(ship) else {
                println!("{ship}: not the name of a galaxy, star or planet. (A moon's key is its parent's to give.)");
                continue;
            };
            match azimuth.listing(number) {
                Ok(Some(listing)) => {
                    let key = listing.key.map_or("none".to_string(), |key| key.iter().map(|byte| format!("{byte:02x}")).collect());
                    let sponsor = listing.sponsor.map_or("none".to_string(), ob::ship_name);
                    println!("{}: key {key}, revision {}, continuity {}, sponsor {sponsor}", ob::ship_name(number), listing.revision, listing.continuity);
                }
                Ok(None) => println!("{}: there is no such ship.", ob::ship_name(number)),
                Err(why) => println!("{}: could not be looked up: {why}", ob::ship_name(number)),
            }
        }
        return;
    }
    let dir = dir.unwrap_or_else(|| fail("--dir is required"));

    let storage_key = storage_key_file.map(|file| {
        let written = std::fs::read_to_string(&file).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", file.display())));
        StorageKey::from_hex(&written).unwrap_or_else(|| fail(&format!("{} does not hold 64 hexadecimal digits", file.display())))
    });
    let runtime = Arc::new(Runtime::open(&dir, Config { storage_key, ..Config::default() }).unwrap_or_else(|e| fail(&format!("cannot open {}: {e}", dir.display()))));
    if demo {
        let read = |path: &PathBuf| {
            std::fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}\nbuild it first; see the README", path.display())))
        };
        let kernel = runtime.add_module(&read(&kernel)).expect("the kernel module loads");
        let counter = runtime.add_module(&read(&counter)).expect("the counter module loads");
        match runtime.create_ship("~zod", &kernel) {
            Ok(()) => {
                let provide = |interface: &str| Provide { interface: interface.into(), public: false, remote: false };
                let manifest = Manifest { provides: vec![provide("counter"), provide("journal")], uses: vec![] };
                runtime.install("~zod", "counter", &counter, &manifest).expect("the counter agent installs");
            }
            Err(Error::ShipExists(_)) => {}
            Err(e) => fail(&format!("cannot create ~zod: {e}")),
        }
        access_codes.push("zod".into());
        signin_links.push("zod".into());
    }
    if let Some(file) = keyfile {
        let written = std::fs::read_to_string(&file).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}", file.display())));
        let module = std::fs::read(&kernel).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}\nbuild it first; see the README", kernel.display())));
        let kernel = runtime.add_module(&module).expect("the kernel module loads");
        match runtime.create_ship_from_keyfile(&kernel, &written) {
            Ok(name) => println!("Started ~{name} from its keyfile."),
            Err(Error::ShipExists(name)) => println!("~{name} is here already."),
            Err(e) => fail(&format!("cannot start the ship in {}: {e}", file.display())),
        }
    }
    // Held for as long as the program runs.
    let _network = net.map(|addr| {
        let azimuth = azimuth.unwrap_or_else(|| fail("--net needs --ethereum, to read other ships' keys from Urbit ID"));
        let directory = Directory::reading(azimuth);
        for peer in &peers {
            let placed = peer.split_once('=').and_then(|(ship, addr)| Some((ship, addr.parse().ok()?)));
            let Some((ship, addr)) = placed else { fail(&format!("--peer {peer}: not <ship>=<address>")) };
            directory.place(ship, addr).unwrap_or_else(|e| fail(&format!("--peer {peer}: {e}")));
        }
        let network = Network::start(runtime.clone(), directory, NetConfig { addr, ..NetConfig::default() }).unwrap_or_else(|e| fail(&format!("cannot start the network: {e}")));
        println!("Talking to other ships at {} (UDP), with keys from Urbit ID.", network.addr());
        network
    });

    let cfg = ServerConfig { addr, ship_host_suffix: host_suffix, secure_cookies, ..ServerConfig::default() };
    let server = Server::start(runtime.clone(), cfg).unwrap_or_else(|e| fail(&format!("cannot listen: {e}")));
    let base = format!("http://{}", server.addr());
    println!("Serving the ships in {} at {base}", dir.display());

    for ship in &access_codes {
        match runtime.set_access_code(ship) {
            Ok(code) => {
                println!("\n{ship}: {base}/ships/{}/", ship.trim_start_matches('~'));
                println!("  access code (shown this once): {code}");
            }
            Err(e) => eprintln!("{ship}: no access code: {e}"),
        }
    }
    for ship in &signin_links {
        match runtime.new_signin_code(ship, Duration::from_secs(600)) {
            Ok(code) => println!("  one-time sign-in link for {ship}, good for ten minutes:\n    {base}/ships/{}/signin?code={code}", ship.trim_start_matches('~')),
            Err(e) => eprintln!("{ship}: no sign-in link: {e}"),
        }
    }
    println!("\nPress Ctrl-C to stop.");
    loop {
        std::thread::park();
    }
}
