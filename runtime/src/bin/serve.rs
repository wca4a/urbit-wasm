//! Serve the ships in a data directory over HTTP, so that apps and browsers can sign in.
//!
//! With `--demo` it also makes a ship, `~zod`, running the toy counter agent, and prints an
//! access code and a one-time sign-in link for it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use runtime::server::{Server, ServerConfig};
use runtime::{Config, Error, Manifest, Provide, Runtime};

const USAGE: &str = "usage: serve --dir <data directory> [--addr 127.0.0.1:8080] [--host-suffix .example.net]
             [--secure-cookies] [--access-code <ship>] [--signin-link <ship>]
             [--demo [--kernel <kernel.wasm>] [--counter <counter.wasm>]]

  --access-code <ship>   give the ship a new reusable access code and print it
  --signin-link <ship>   print a one-time sign-in link for the ship, good for ten minutes
  --demo                 make a ship ~zod with the counter agent, if there is none, and print
                         an access code and a sign-in link for it";

fn fail(why: &str) -> ! {
    eprintln!("{why}\n\n{USAGE}");
    std::process::exit(2)
}

fn main() {
    let (mut dir, mut addr, mut host_suffix) = (None, "127.0.0.1:8080".to_string(), None);
    let (mut secure_cookies, mut demo) = (false, false);
    let (mut access_codes, mut signin_links) = (Vec::new(), Vec::new());
    let mut kernel = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/kernel.wasm");
    let mut counter = PathBuf::from("target/wasm/wasm32-unknown-unknown/release/counter.wasm");

    let mut raw = std::env::args().skip(1);
    while let Some(flag) = raw.next() {
        let mut value = || raw.next().unwrap_or_else(|| fail(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(value())),
            "--addr" => addr = value(),
            "--host-suffix" => host_suffix = Some(value()),
            "--secure-cookies" => secure_cookies = true,
            "--demo" => demo = true,
            "--access-code" => access_codes.push(value()),
            "--signin-link" => signin_links.push(value()),
            "--kernel" => kernel = PathBuf::from(value()),
            "--counter" => counter = PathBuf::from(value()),
            _ => fail(&format!("unknown flag {flag}")),
        }
    }
    let dir = dir.unwrap_or_else(|| fail("--dir is required"));

    let runtime = Arc::new(Runtime::open(&dir, Config::default()).unwrap_or_else(|e| fail(&format!("cannot open {}: {e}", dir.display()))));
    if demo {
        let read = |path: &PathBuf| {
            std::fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {e}\nbuild it first; see the README", path.display())))
        };
        let kernel = runtime.add_module(&read(&kernel)).expect("the kernel module loads");
        let counter = runtime.add_module(&read(&counter)).expect("the counter module loads");
        match runtime.create_ship("~zod", &kernel) {
            Ok(()) => {
                let provide = |interface: &str| Provide { interface: interface.into(), public: false };
                let manifest = Manifest { provides: vec![provide("counter"), provide("journal")], uses: vec![] };
                runtime.install("~zod", "counter", &counter, &manifest).expect("the counter agent installs");
            }
            Err(Error::ShipExists(_)) => {}
            Err(e) => fail(&format!("cannot create ~zod: {e}")),
        }
        access_codes.push("zod".into());
        signin_links.push("zod".into());
    }

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
