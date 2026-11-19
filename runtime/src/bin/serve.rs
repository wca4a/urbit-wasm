//! Serve the ships in a data directory over HTTP, so that apps and browsers can sign in.
//!
//! With `--demo` it also makes a ship, `~zod`, running the toy counter agent, and prints an
//! access code and a one-time sign-in link for it.
//!
//! With `--net` the ships also talk to ships on other runtimes, each known by the key Urbit
//! ID lists for its name, read from Azimuth through the Ethereum node given with
//! `--ethereum`. `--lookup` prints what Urbit ID lists for a ship, and stops.
//!
//! With `--lookup-at` or `--lookup-domain` the ships are also found by name alone: each of
//! this runtime's ships is announced, with a record of where it is that it signs, to the
//! lookup point for its galaxy, and a ship with no `--peer` address is looked for there.
//! Unless `--announce` says where the runtime is reached, it announces the address the point
//! sees it at, which works behind a home router too. `--lookup-point` makes this runtime a
//! lookup point itself, and `--relay` has it carry the packets of the ships it serves that
//! cannot be reached directly, within byte allowances that bound what that costs.
//!
//! With `--azimuth-copy` those keys come from a copy of Azimuth kept in a file and worked
//! out from Ethereum alone, in place of asking the roller about ships on layer 2. The copy
//! can be started from a snapshot (`--azimuth-snapshot`), and a snapshot written of it
//! (`--azimuth-write-snapshot`), if need be at a given block (`--azimuth-until`).
//!
//! With `--pretend-ids` every ship's key comes from a list in a file instead of Urbit ID, for
//! trying things out on machines one controls: whoever can write that file can be any ship.
//!
//! `--two-ships` starts a lookup point and two ships as programs of their own, from this same
//! binary, and walks through what they can do, acting as each owner's device (`two_ships`).

#[path = "serve/said.rs"]
mod said;
#[path = "serve/two_ships.rs"]
mod two_ships;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use runtime::azimuth::{Azimuth, AzimuthConfig, Keys};
use runtime::lookup::{Lookup, PointBounds, PointConfig};
use runtime::replica::snapshot::{self, Summary};
use runtime::replica::{Replica, ReplicaConfig, Restored, TroubleWatch};
use runtime::net::{Directory, NetConfig, Network};
use runtime::pretend::PretendIds;
use runtime::relay::RelayBounds;
use runtime::server::{Server, ServerConfig};
use runtime::urbit_id::ob;
use runtime::{parse_size, Config, Error, Manifest, Provide, Runtime, StorageKey};

const USAGE: &str = "usage: serve --dir <data directory> [--addr 127.0.0.1:8080] [--host-suffix .example.net]
             [--storage-key-file <file>] [--secure-cookies] [--access-code <ship>] [--signin-link <ship>]
             [--demo [--kernel <kernel.wasm>] [--counter <counter.wasm>]]
             [--sleep-after <seconds>] [--max-file-bytes <size>] [--max-cache-bytes <size>]
             [--ethereum <url> [--roller <url> | --azimuth-copy <file>] | --pretend-ids <file>]
             [--net <address>]
             [--azimuth-snapshot <file> [--azimuth-snapshot-sha256 <hex>]]
             [--azimuth-until <block>] [--azimuth-write-snapshot <file>]
             [--peer <ship>=<address>]...
             [--lookup-at [<galaxy>=]<address>]... [--lookup-domain <domain>:<port>]
             [--announce <address>]... [--behind-router] [--lookup-point <all | galaxy,galaxy,...>]
             [--relay [--relay-ship-rate <bytes>] [--relay-point-rate <bytes>]]
             [--keyfile <file>] [--lookup <ship>]...
       serve --two-ships <directory> [--then-stop] [--show-output] [--ports <first>] [--file <file>]
             [--sleep-after <seconds>] [--kernel <kernel.wasm>] [--counter <counter.wasm>]
             [--tally <tally.wasm>]

  --storage-key-file <file>
                         the key the ships' files are encrypted under, as 64 hexadecimal digits,
                         kept somewhere other than the data directory. Without it the key is
                         made and kept in the data directory, as storage.key
  --access-code <ship>   give the ship a new reusable access code and print it
  --signin-link <ship>   print a one-time sign-in link for the ship, good for ten minutes
  --demo                 make a ship ~zod with the counter agent, if there is none, and print
                         an access code and a sign-in link for it
  --sleep-after <seconds>
                         close a ship's file once it has been idle this long; it opens again for
                         the next thing it is asked. 300 if not given; 0 keeps every ship open
                         once it has been woken, until 64 others push it out. With --two-ships,
                         given to the three programs it starts
  --max-file-bytes <size>
                         how much each ship's files may take together: a whole number of bytes,
                         or with K, M or G after it for KiB, MiB or GiB (10G). 10G if not given;
                         0 turns the store of files off
  --max-cache-bytes <size>
                         how much each ship may keep of files opened from other ships, written
                         the same way. 3G if not given; 0 keeps nothing
  --ethereum <url>       an Ethereum node to read Urbit ID (Azimuth) through
  --roller <url>         the service to ask about ships on layer 2; Urbit's own if not given
  --azimuth-copy <file>  keep a copy of Azimuth in this file, worked out from what was written
                         to Ethereum, and read keys from it instead of asking the roller. The
                         first time, reading all of Azimuth's history takes a while; the node
                         must answer eth_getLogs for old blocks
  --azimuth-snapshot <file>
                         if there is no copy yet, make it from this snapshot, then read on from
                         the snapshot's block. A copy that is there is never replaced, and the
                         snapshot is then not used. macOS and Linux only
  --azimuth-snapshot-sha256 <hex>
                         the fingerprint the snapshot must have, as 64 hexadecimal digits. Take
                         it from somewhere other than where the snapshot came from
  --azimuth-until <block>
                         read the copy to this block and no further, then stop (with
                         --azimuth-write-snapshot, write a snapshot there first). Needs
                         --ethereum. A copy stopped short answers no lookups
  --azimuth-write-snapshot <file>
                         write a snapshot of the copy to this new file, and its fingerprint and
                         block to the same name with .txt added, then stop. The node is not asked
                         anything unless --azimuth-until is given. macOS and Linux only
  --pretend-ids <file>   read every ship's key from this file instead of Urbit ID: one ship to a
                         line, its name and its key as 64 hexadecimal digits (# starts a comment).
                         Whoever can write the file can be any ship, so this is for trying things
                         out on machines you control. It stands in for --ethereum and
                         --azimuth-copy wherever they are needed, and cannot go with --ethereum,
                         --roller or any --azimuth- flag
  --net <address>        talk to ships on other runtimes, listening here (UDP), each ship
                         known by the key Urbit ID lists for it. Needs --ethereum or --pretend-ids
  --peer <ship>=<addr>   where another ship is to be found. Its key comes from Urbit ID. A ship
                         given here is always called here, and never looked for elsewhere
  --lookup-at [<galaxy>=]<address>
                         where the lookup point for a galaxy is, or without a galaxy, for every
                         galaxy. Ships with no --peer address are looked for there, and this
                         runtime's ships are announced there. Wins over --lookup-domain
  --lookup-domain <domain>:<port>
                         find the lookup point for each galaxy by name, as <galaxy>.<domain>
                         (the point for ~zod is zod.<domain>), through this machine's resolver
  --announce <address>   the address other ships reach this runtime at, to announce its ships
                         at; up to four. Without it, the address the lookup point of each ship's
                         galaxy sees this runtime at, and if that is not the address given to
                         --net, callers are asked to be introduced first, so that a home router
                         lets them in. Needs --lookup-at or --lookup-domain
  --behind-router        ask callers to be introduced first even with --announce: for a runtime
                         whose outside address is known but whose router lets nothing in that
                         it has not sent to first. Needs --lookup-at or --lookup-domain
  --lookup-point <all | galaxy,galaxy,...>
                         also be the lookup point for the ships of these galaxies (all, or a
                         list such as ~zod,~nec): keep the signed records of where they are
                         that are given here, checked against the copy of Azimuth, and hand
                         them to whoever asks. Needs --net, and --azimuth-copy or --pretend-ids
  --relay                carry the packets of a ship this point serves and a ship calling it,
                         when the two cannot reach each other directly (a router that gives a
                         different outside port for each destination defeats sending at the
                         same moment). The point sees only encrypted packets. Needs
                         --lookup-point
  --relay-ship-rate <bytes>
                         bytes a second carried for any one ship called, both ways, all its
                         sessions together, with a burst of twice that; 131072 if not given
  --relay-point-rate <bytes>
                         bytes a second carried in all, with a burst of twice that; 4194304 if
                         not given. These two bound what relaying costs whoever runs the point
  --keyfile <file>       start the ship this keyfile is for, if it is not here already
  --lookup <ship>        print what Urbit ID lists for a ship, and stop. Needs --ethereum or
                         --pretend-ids
  --two-ships <directory>
                         start a lookup point and two ships, ~sampel-palnet and ~norsyr-torryn,
                         as three programs on this machine, with keys from a list in the
                         directory, and walk through what they can do: messages both ways, a
                         file refused and then allowed, opened again with the other ship off,
                         and messages again after that ship comes back. Everything is kept in
                         the directory, and a later run reuses it. Then leave them running until
                         Ctrl-C. Takes only the flags on its line above
  --then-stop            stop the three programs once the walk-through is over
  --show-output          show what the three programs print, each line marked with which said it
                         (it is shown anyway if a step does not work)
  --ports <first>        start the three programs on six ports counting up from this one, so that
                         their addresses are the same every run; without it each takes any free port
  --file <file>          the file the first ship shares, in place of a made-up one
  --tally <tally.wasm>   the tally module, for --two-ships";

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

/// Wait until the copy of Azimuth has read to `until`, where it was told to stop, and this run
/// has found the file's block hash to be the node's: a copy that was already there when it was
/// opened is not taken as there until the node has agreed with it.
fn wait_until(replica: &Replica, until: u64) {
    let started = std::time::Instant::now();
    let mut said = std::time::Instant::now();
    loop {
        let status = replica.status();
        if replica.reached_until() {
            eprintln!("The copy of Azimuth has read every block up to {until}, where it was told to stop, in {} seconds.", started.elapsed().as_secs());
            return;
        }
        if said.elapsed() >= Duration::from_secs(10) {
            said = std::time::Instant::now();
            let trouble = status.trouble.map_or(String::new(), |why| format!(" Last trouble: {why}."));
            eprintln!("Reading Azimuth: block {} of {until}, {} logs and {} batches so far.{trouble}", status.read_to, status.counts.logs, status.counts.batches);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Say what snapshot was written, in the same lines as are written beside it.
fn print_written(out: &std::path::Path, summary: &Summary) {
    println!("Wrote {}, and the same lines to {}.txt:\n{}", out.display(), out.display(), summary.lines());
}

/// A galaxy, by name or number of a galaxy.
fn galaxy(written: &str) -> Option<u8> {
    ob::ship_number(written).and_then(|number| u8::try_from(number).ok())
}

/// The settings for finding ships through lookup points, announcing to them, and being one,
/// from what was given on the command line.
fn lookup_settings(at: &[String], domain: Option<&str>, announce: &[String], behind_router: bool, point: Option<&str>, relay: Option<RelayBounds>, keys: &Arc<dyn Keys>) -> Lookup {
    let at = at
        .iter()
        .map(|given| {
            let (galaxy_written, addr) = match given.split_once('=') {
                Some((galaxy_written, addr)) => (Some(galaxy_written), addr),
                None => (None, given.as_str()),
            };
            let of = galaxy_written.map(|written| galaxy(written).unwrap_or_else(|| fail(&format!("--lookup-at {given}: {written} is not a galaxy"))));
            let addr = addr.parse().unwrap_or_else(|_| fail(&format!("--lookup-at {given}: not [<galaxy>=]<address>")));
            (of, addr)
        })
        .collect();
    let domain = domain.map(|given| {
        let (name, port) = given.rsplit_once(':').unwrap_or_else(|| fail(&format!("--lookup-domain {given}: not <domain>:<port>")));
        (name.to_string(), port.parse().unwrap_or_else(|_| fail(&format!("--lookup-domain {given}: not <domain>:<port>"))))
    });
    let announce = announce.iter().map(|given| given.parse().unwrap_or_else(|_| fail(&format!("--announce {given}: not an address")))).collect();
    let serve = point.map(|given| {
        let galaxies = match given {
            "all" => None,
            list => Some(list.split(',').map(|written| galaxy(written).unwrap_or_else(|| fail(&format!("--lookup-point {given}: {written} is not a galaxy")))).collect()),
        };
        PointConfig { keys: keys.clone(), galaxies, bounds: PointBounds::default(), relay }
    });
    Lookup { serve, at, domain, announce, behind_router, ..Lookup::default() }
}

/// A path made absolute.
fn absolute(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        Some(std::env::current_dir().ok()?.join(path))
    }
}

/// A path as absolute as can be told: the part of it that exists, through every link, and the
/// names after that, which do not exist yet, as written.
struct Resolved {
    real: PathBuf,
    unmade: Vec<std::ffi::OsString>,
}

/// `path` resolved. `None` if the names that do not exist yet go up with `..`: where that leads
/// depends on what is made later, so it cannot be told now.
fn resolved(path: &Path) -> Option<Resolved> {
    let absolute = absolute(path)?;
    let mut existing = absolute.as_path();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(existing) {
            rest.reverse();
            return rest.iter().all(|part| part != "..").then_some(Resolved { real, unmade: rest });
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            (Some(parent), None) => {
                rest.push("..".into());
                existing = parent;
            }
            _ => return None,
        }
    }
}

impl Resolved {
    /// The same, with one more name on the end, as written (and so, like a name not made yet,
    /// compared ignoring case below: written `TMP`, it may name an existing `tmp`).
    fn join(mut self, name: &std::ffi::OsStr) -> Resolved {
        self.unmade.push(name.to_os_string());
        self
    }

    /// Whether this is `outer` or inside it. A name taken as written, on either side (one that
    /// does not exist yet, or an entry's own name), is compared ignoring ASCII case: on a file
    /// system that ignores case, `TMP` is the same entry as `tmp`, and which kind of file system
    /// it is cannot be told from here. That is conservative: on one that does not, a separate
    /// `TMP` beside `tmp` is refused as well.
    fn within(&self, outer: &Resolved) -> bool {
        let parts = |of: &Resolved| -> Vec<(std::ffi::OsString, bool)> {
            of.real.components().map(|part| (part.as_os_str().to_os_string(), false)).chain(of.unmade.iter().map(|name| (name.clone(), true))).collect()
        };
        let (inner, outer) = (parts(self), parts(outer));
        inner.len() >= outer.len()
            && inner.iter().zip(&outer).all(|((a, a_unmade), (b, b_unmade))| {
                a == b || ((*a_unmade || *b_unmade) && a.to_str().zip(b.to_str()).is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)))
            })
    }
}

/// Refuse a file an operator names that would be in the data directory's `tmp/`, all of which
/// is the runtime's own (it empties it every time it starts).
///
/// What is covered: every entry of the path as written, each placed where it itself lives (its
/// directory through every link, and its own name), and what the whole path finally leads to.
/// So `tmp/keys/ids` is refused when `tmp/keys` links out of `tmp/`; that link, directly inside
/// `tmp/`, would be removed at start, so the file could no longer be read by that name (the
/// file itself, elsewhere, stays). Deeper down, `tmp/a/b -> /safe` is
/// refused too, but only because it is in `tmp/`: start-up leaves directories there and never
/// looks inside them, so nothing would be removed.
///
/// What is not: a path outside `tmp/` whose own links lead through a link inside it
/// (`/safe/alias -> <data>/tmp/keys/ids` with `<data>/tmp/keys -> /safe`). Nothing as written
/// is in `tmp/` and it finally leads to `/safe/ids`, so it is taken. Start-up then removes the
/// link `tmp/keys` (which only an operator could have put there; the runtime makes no links),
/// nothing else of the operator's is removed, and the file can no longer be read by that name.
fn not_in_scratch(dir: &Path, flag: &str, path: &Path) {
    let ambiguous = || fail(&format!("{flag} {}: it goes up (..) through directories that are not there yet, so where it leads cannot be told", path.display()));
    let Some(scratch) = resolved(&dir.join("tmp")) else {
        fail(&format!("--dir {}: it goes up (..) through directories that are not there yet, so where it leads cannot be told", dir.display()))
    };
    let Some(written) = absolute(path) else { ambiguous() };
    // Every entry the path goes through, the last included, where it itself lives.
    for entry in written.ancestors() {
        let (Some(parent), Some(name)) = (entry.parent(), entry.file_name()) else { continue };
        let Some(place) = resolved(parent) else { ambiguous() };
        if place.join(name).within(&scratch) {
            fail(&format!("{flag} {}: that is in the data directory's tmp, which is the runtime's own and is emptied every time it starts", path.display()));
        }
    }
    let Some(target) = resolved(path) else { ambiguous() };
    if target.within(&scratch) {
        fail(&format!("{flag} {}: that is in the data directory's tmp, which is the runtime's own and is emptied every time it starts", path.display()));
    }
}

/// The ships in a data directory, by name, as its `ships/` directory lists them.
fn ships_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir.join("ships")) else { return Vec::new() };
    entries.flatten().filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".ship").map(str::to_string)).collect()
}

/// Above this many ships, `watch_network` says how many are announced instead of naming each.
const NAMED_SHIPS: usize = 16;

/// Say, on a thread of its own, for as long as the network runs: when each ship here is
/// announced to its lookup point, and at what address, again whenever that changes (or, with
/// more than `NAMED_SHIPS` ships, how many are announced, whenever that changes); and how many
/// callers the lookup points have introduced to this runtime's ships, the first five times that
/// changes and then at most once every ten seconds. It looks once a second, and lists `ships/`
/// once every ten looks (a ship made meanwhile is seen at the next listing); ships gone from the
/// listing are forgotten.
fn watch_network(network: Weak<Network>, dir: PathBuf) {
    std::thread::spawn(move || {
        let mut ships = Vec::new();
        let mut shown: HashMap<String, (Vec<std::net::SocketAddr>, bool)> = HashMap::new();
        let mut counted = None;
        let (mut introduced, mut told, mut last_told) = ((0, 0), 0, None::<Instant>);
        let mut look = 0u64;
        while let Some(network) = network.upgrade() {
            if look % 10 == 0 {
                ships = ships_in(&dir);
                shown.retain(|ship, _| ships.contains(ship));
            }
            look += 1;
            if ships.len() <= NAMED_SHIPS {
                for ship in &ships {
                    if let Some(now) = network.announced_as(ship) {
                        if shown.get(ship) != Some(&now) {
                            println!("{}", said::announced(ship, &now.0, now.1));
                            shown.insert(ship.clone(), now);
                        }
                    }
                }
            } else {
                let announced = ships.iter().filter(|ship| network.announced_as(ship).is_some()).count();
                if counted != Some((announced, ships.len())) {
                    println!("{}", said::announced_count(announced, ships.len()));
                    counted = Some((announced, ships.len()));
                }
            }
            let counts = network.introductions();
            let now = (counts.heard, counts.acted);
            if now != introduced && (told < 5 || last_told.is_none_or(|at| at.elapsed() >= Duration::from_secs(10))) {
                println!("{}", said::introductions(now.0, now.1));
                (introduced, told, last_told) = (now, told + 1, Some(Instant::now()));
            }
            drop(network);
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

fn main() {
    let (mut dir, mut addr, mut host_suffix) = (None, "127.0.0.1:8080".to_string(), None);
    let (mut secure_cookies, mut demo) = (false, false);
    let mut storage_key_file = None;
    let (mut access_codes, mut signin_links) = (Vec::new(), Vec::new());
    let (mut ethereum, mut roller, mut net, mut peers, mut keyfile, mut lookups) = (None, None, None, Vec::new(), None, Vec::new());
    let mut azimuth_copy = None;
    let (mut lookup_at, mut lookup_domain, mut announce, mut lookup_point) = (Vec::new(), None, Vec::new(), None);
    let mut behind_router = false;
    let (mut relay, mut relay_ship_rate, mut relay_point_rate) = (false, None, None);
    let (mut azimuth_snapshot, mut snapshot_sha256, mut azimuth_until, mut write_snapshot) = (None, None, None, None);
    let mut kernel = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/kernel.wasm");
    let mut counter = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/counter.wasm");
    let mut tally = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/tally.wasm");
    let mut pretend_ids = None;
    let (mut sleep_after, mut max_file_bytes, mut max_cache_bytes) = (None, None, None);
    let (mut two_ships, mut then_stop, mut show_output, mut ports, mut share) = (None, false, false, None, None);
    let mut given = Vec::new();

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        given.push(flag.clone());
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
            "--tally" => tally = PathBuf::from(value()),
            "--pretend-ids" => pretend_ids = Some(PathBuf::from(value())),
            "--sleep-after" => {
                let written = value();
                sleep_after = Some(written.parse::<u64>().unwrap_or_else(|_| fail(&format!("--sleep-after {written}: not a whole number of seconds"))));
            }
            "--max-file-bytes" => {
                let written = value();
                max_file_bytes = Some(parse_size(&written).unwrap_or_else(|| fail(&format!("--max-file-bytes {written}: not a size (a whole number of bytes, or with K, M or G after it)"))));
            }
            "--max-cache-bytes" => {
                let written = value();
                max_cache_bytes = Some(parse_size(&written).unwrap_or_else(|| fail(&format!("--max-cache-bytes {written}: not a size (a whole number of bytes, or with K, M or G after it)"))));
            }
            "--two-ships" => two_ships = Some(PathBuf::from(value())),
            "--then-stop" => then_stop = true,
            "--show-output" => show_output = true,
            "--ports" => {
                let written = value();
                ports = Some(written.parse::<u16>().ok().filter(|first| *first > 0 && *first <= u16::MAX - 5).unwrap_or_else(|| fail(&format!("--ports {written}: not a port from 1 to 65530"))));
            }
            "--file" => share = Some(PathBuf::from(value())),
            "--ethereum" => ethereum = Some(value()),
            "--roller" => roller = Some(value()),
            "--azimuth-copy" => azimuth_copy = Some(PathBuf::from(value())),
            "--azimuth-snapshot" => azimuth_snapshot = Some(PathBuf::from(value())),
            "--azimuth-snapshot-sha256" => {
                let written = value();
                snapshot_sha256 = Some(snapshot::fingerprint(&written).unwrap_or_else(|| fail(&format!("--azimuth-snapshot-sha256 {written}: not 64 hexadecimal digits"))));
            }
            "--azimuth-until" => {
                let written = value();
                azimuth_until = Some(written.parse::<u64>().unwrap_or_else(|_| fail(&format!("--azimuth-until {written}: not a block number"))));
            }
            "--azimuth-write-snapshot" => write_snapshot = Some(PathBuf::from(value())),
            "--net" => net = Some(value()),
            "--peer" => peers.push(value()),
            "--lookup-at" => lookup_at.push(value()),
            "--lookup-domain" => lookup_domain = Some(value()),
            "--announce" => announce.push(value()),
            "--behind-router" => behind_router = true,
            "--lookup-point" => lookup_point = Some(value()),
            "--relay" => relay = true,
            "--relay-ship-rate" => relay_ship_rate = Some(value()),
            "--relay-point-rate" => relay_point_rate = Some(value()),
            "--keyfile" => keyfile = Some(PathBuf::from(value())),
            "--lookup" => lookups.push(value()),
            _ => fail(&format!("unknown flag {flag}")),
        }
    }
    let demo_only = ["--then-stop", "--show-output", "--ports", "--file", "--tally"];
    if let Some(dir) = two_ships {
        let takes = ["--two-ships", "--kernel", "--counter", "--sleep-after"];
        if let Some(other) = given.iter().find(|flag| flag.starts_with("--") && !takes.contains(&flag.as_str()) && !demo_only.contains(&flag.as_str())) {
            fail(&format!("--two-ships starts its own lookup point and ships, and takes only --kernel, --counter, --tally, --file, --ports, --sleep-after, --then-stop and --show-output, not {other}"));
        }
        let options = two_ships::Options { dir, kernel, counter, tally, then_stop, show_output, ports, file: share, sleep_after };
        std::process::exit(two_ships::run(options));
    }
    if let Some(flag) = given.iter().find(|flag| demo_only.contains(&flag.as_str())) {
        fail(&format!("{flag} goes with --two-ships"));
    }
    if let Some(dir) = &dir {
        let named = [
            ("--azimuth-copy", &azimuth_copy),
            ("--azimuth-snapshot", &azimuth_snapshot),
            ("--azimuth-write-snapshot", &write_snapshot),
            ("--pretend-ids", &pretend_ids),
            ("--storage-key-file", &storage_key_file),
            ("--keyfile", &keyfile),
        ];
        for (flag, path) in named {
            if let Some(path) = path {
                not_in_scratch(dir, flag, path);
            }
        }
        // The modules are read once the runtime has opened, so after `tmp/` is emptied. (`--tally`
        // goes only with `--two-ships`, which takes no data directory.)
        for (flag, path) in [("--kernel", &kernel), ("--counter", &counter)] {
            not_in_scratch(dir, flag, path);
        }
    }
    // A list of keys in place of Urbit ID: it would be a second answer to the same question,
    // and nothing says which to believe.
    if pretend_ids.is_some()
        && (ethereum.is_some() || roller.is_some() || azimuth_copy.is_some() || azimuth_snapshot.is_some() || snapshot_sha256.is_some() || azimuth_until.is_some() || write_snapshot.is_some())
    {
        fail("--pretend-ids reads every ship's key from a file instead of Urbit ID, so it cannot go with --ethereum, --roller or any --azimuth- flag");
    }
    let finds = !lookup_at.is_empty() || lookup_domain.is_some();
    if net.is_none() && (finds || lookup_point.is_some() || !announce.is_empty() || behind_router) {
        fail("--lookup-at, --lookup-domain, --announce, --behind-router and --lookup-point need --net");
    }
    if (!announce.is_empty() || behind_router) && !finds {
        fail("--announce and --behind-router need somewhere to announce: --lookup-at or --lookup-domain");
    }
    // A lookup point checks every record it is given against Urbit ID. Asking an Ethereum
    // node or the roller for each would let anyone who announces have this runtime ask them
    // as fast as it can be given records; a copy answers from a file.
    // The list given with --pretend-ids is read from a file too.
    if lookup_point.is_some() && azimuth_copy.is_none() && pretend_ids.is_none() {
        fail("--lookup-point needs --azimuth-copy, to check records against a copy of Azimuth kept here (or --pretend-ids, to check them against a list)");
    }
    if (relay || relay_ship_rate.is_some() || relay_point_rate.is_some()) && lookup_point.is_none() {
        fail("--relay, --relay-ship-rate and --relay-point-rate need --lookup-point: a point relays only for the ships that attend on it");
    }
    if (relay_ship_rate.is_some() || relay_point_rate.is_some()) && !relay {
        fail("--relay-ship-rate and --relay-point-rate need --relay");
    }
    // A rate given in bytes a second, with a burst of twice that.
    let rate = |flag: &str, given: Option<String>, otherwise: u64| -> (u64, u64) {
        let rate = given.map_or(otherwise, |given| given.parse::<u64>().ok().filter(|rate| *rate >= 1024 && *rate <= 1 << 40).unwrap_or_else(|| fail(&format!("{flag} {given}: not a number of bytes a second from 1024 to 2^40"))));
        (rate, rate.saturating_mul(2))
    };
    let relay = relay.then(|| {
        let defaults = RelayBounds::default();
        let (ship_rate, ship_burst) = rate("--relay-ship-rate", relay_ship_rate, defaults.ship_rate);
        let (point_rate, point_burst) = rate("--relay-point-rate", relay_point_rate, defaults.point_rate);
        RelayBounds { ship_rate, ship_burst, point_rate, point_burst, ..defaults }
    });
    if azimuth_copy.is_some() && roller.is_some() {
        fail("--azimuth-copy needs no roller");
    }
    if azimuth_copy.is_none() && (azimuth_snapshot.is_some() || azimuth_until.is_some() || write_snapshot.is_some()) {
        fail("--azimuth-snapshot, --azimuth-until and --azimuth-write-snapshot need --azimuth-copy");
    }
    if snapshot_sha256.is_some() && azimuth_snapshot.is_none() {
        fail("--azimuth-snapshot-sha256 needs --azimuth-snapshot");
    }
    // Where snapshots are neither written nor restored, either flag is refused here, before
    // the copy is opened or anything is made: a copy read to a block only to be refused a
    // snapshot of would be work for nothing.
    if azimuth_snapshot.is_some() || write_snapshot.is_some() {
        snapshot::supported().unwrap_or_else(|why| fail(&why));
    }
    if azimuth_until.is_some() && (!lookups.is_empty() || net.is_some()) {
        fail("--azimuth-until stops the copy short of the end of the chain, so it answers no lookups: it cannot go with --lookup or --net");
    }
    // A snapshot of the copy as it is: no node is asked anything.
    if let (Some(out), Some(file), None) = (&write_snapshot, &azimuth_copy, azimuth_until) {
        if azimuth_snapshot.is_some() {
            fail("--azimuth-snapshot with --azimuth-write-snapshot needs --azimuth-until: a copy only just made from a snapshot would be written back as the same snapshot");
        }
        let cfg = ReplicaConfig::mainnet(ethereum.as_deref().unwrap_or_default());
        let summary = snapshot::write(file, &cfg, out).unwrap_or_else(|e| fail(&format!("cannot write a snapshot of {} to {}: {e}", file.display(), out.display())));
        print_written(out, &summary);
        return;
    }
    let azimuth: Option<Arc<dyn Keys>> = match (ethereum, azimuth_copy) {
        (None, Some(_)) => fail("--azimuth-copy needs --ethereum"),
        (None, None) => pretend_ids.as_ref().map(|file| {
            let ids = PretendIds::open(file).unwrap_or_else(|why| fail(&why));
            println!("Keys come from the list in {}, not from Urbit ID: whoever can write that file can be any ship.", file.display());
            println!("This is for trying things out on machines you control.");
            Arc::new(ids) as Arc<dyn Keys>
        }),
        (Some(ethereum), None) => {
            let mut cfg = AzimuthConfig::mainnet(&ethereum);
            if let Some(roller) = roller {
                cfg.roller = Some(roller);
            }
            Some(Arc::new(Azimuth::new(cfg)))
        }
        (Some(ethereum), Some(file)) => {
            let cfg = ReplicaConfig { until: azimuth_until, ..ReplicaConfig::mainnet(&ethereum) };
            let opened = match &azimuth_snapshot {
                None => Replica::open(&file, cfg.clone()),
                Some(from) => Replica::open_from_snapshot(&file, cfg.clone(), from, snapshot_sha256).map(|(replica, restored)| {
                    match restored {
                        Restored::Made(summary) => eprintln!(
                            "Made the copy of Azimuth {} from the snapshot {}: block {}, {} points, fingerprint (sha256) {}. It reads on from there.",
                            file.display(),
                            from.display(),
                            summary.block,
                            summary.points,
                            snapshot::plain_hex(&summary.sha256)
                        ),
                        Restored::Ignored => eprintln!("There is a copy of Azimuth at {} already, so the snapshot {} is not used: a copy is never replaced.", file.display(), from.display()),
                    }
                    replica
                }),
            };
            let replica = opened.unwrap_or_else(|e| fail(&format!("cannot open {}: {e}", file.display())));
            if let Some(until) = azimuth_until {
                let read_to = replica.status().read_to;
                if read_to > until {
                    fail(&format!("{} has read to block {read_to} already, past block {until}; a copy cannot go back", file.display()));
                }
                replica.keep_up();
                wait_until(&replica, until);
                if let Some(out) = &write_snapshot {
                    let summary = snapshot::write(&file, &cfg, out).unwrap_or_else(|e| fail(&format!("cannot write a snapshot of {} to {}: {e}", file.display(), out.display())));
                    print_written(out, &summary);
                }
                return;
            }
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
        let azimuth = azimuth.unwrap_or_else(|| fail("--lookup needs --ethereum or --pretend-ids"));
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
    let defaults = Config::default();
    let cfg = Config {
        storage_key,
        max_file_bytes: max_file_bytes.unwrap_or(defaults.max_file_bytes),
        max_cache_bytes: max_cache_bytes.unwrap_or(defaults.max_cache_bytes),
        ..defaults
    };
    let runtime = Arc::new(Runtime::open(&dir, cfg).unwrap_or_else(|e| fail(&format!("cannot open {}: {e}", dir.display()))));
    // Held weakly by its thread, which ends with the runtime.
    match sleep_after.unwrap_or(300) {
        0 => {}
        seconds => drop(Runtime::sleep_when_idle(&runtime, Duration::from_secs(seconds))),
    }
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
        let azimuth = azimuth.unwrap_or_else(|| fail("--net needs --ethereum, to read other ships' keys from Urbit ID (or --pretend-ids, to read them from a list)"));
        let directory = Directory::reading(azimuth.clone());
        for peer in &peers {
            let placed = peer.split_once('=').and_then(|(ship, addr)| Some((ship, addr.parse().ok()?)));
            let Some((ship, addr)) = placed else { fail(&format!("--peer {peer}: not <ship>=<address>")) };
            directory.place(ship, addr).unwrap_or_else(|e| fail(&format!("--peer {peer}: {e}")));
        }
        let lookup = lookup_settings(&lookup_at, lookup_domain.as_deref(), &announce, behind_router, lookup_point.as_deref(), relay, &azimuth);
        let network = Network::start(runtime.clone(), directory, NetConfig { addr, lookup, ..NetConfig::default() }).unwrap_or_else(|e| fail(&format!("cannot start the network: {e}")));
        let keys = match &pretend_ids {
            Some(file) => format!("with keys from the list in {}, not from Urbit ID.", file.display()),
            None => "with keys from Urbit ID.".to_string(),
        };
        println!("{}", said::talking(network.addr(), &keys));
        if let Some(galaxies) = &lookup_point {
            println!("Answering as the lookup point for the ships of {galaxies} galaxies, on the same address.");
            if let Some(relay) = &relay {
                println!("Carrying the packets of those ships and their callers where they cannot reach each other directly: {} bytes a second for any one ship, {} in all.", relay.ship_rate, relay.point_rate);
            }
        }
        if let Some(why) = network.lookup_trouble() {
            eprintln!("{why}");
        }
        let network = Arc::new(network);
        // Only a runtime that announces its ships, or is a point, has anything to say here.
        if finds || lookup_point.is_some() {
            watch_network(Arc::downgrade(&network), dir.clone());
        }
        network
    });

    let cfg = ServerConfig { addr, ship_host_suffix: host_suffix, secure_cookies, ..ServerConfig::default() };
    let server = Server::start(runtime.clone(), cfg).unwrap_or_else(|e| fail(&format!("cannot listen: {e}")));
    let base = format!("http://{}", server.addr());
    println!("{}", said::serving(&dir.display().to_string(), server.addr()));

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
