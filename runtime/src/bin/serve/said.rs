//! The lines `serve` prints that `serve --two-ships` reads back from the copies of `serve` it
//! starts: each made and read here, in one place, so that a change of wording changes both and
//! cannot quietly leave the demo waiting for words that never come.

use std::net::SocketAddr;

const TALKING: &str = "Talking to other ships at ";
const TALKING_END: &str = " (UDP), ";
const SERVING: &str = "Serving the ships in ";
const SERVING_AT: &str = " at http://";
const ANNOUNCED: &str = " is announced to its lookup point at ";
const INTRODUCE_FIRST: &str = ", asking callers to be introduced by the point first.";
const INTRODUCTIONS: &str = "Callers introduced to this runtime's ships by their lookup points so far: ";

/// Where the ship network listens, and where the keys come from (said in `keys`).
pub fn talking(addr: SocketAddr, keys: &str) -> String {
    format!("{TALKING}{addr}{TALKING_END}{keys}")
}

/// The address in a line made by `talking`.
pub fn talking_at(line: &str) -> Option<SocketAddr> {
    line.strip_prefix(TALKING)?.split_once(TALKING_END)?.0.parse().ok()
}

/// Where the HTTP server is, for the ships in `dir`.
pub fn serving(dir: &str, addr: SocketAddr) -> String {
    format!("{SERVING}{dir}{SERVING_AT}{addr}")
}

/// The HTTP server's address in a line made by `serving`.
pub fn serving_at(line: &str) -> Option<SocketAddr> {
    line.strip_prefix(SERVING)?.rsplit_once(SERVING_AT)?.1.parse().ok()
}

/// That a ship's record was taken by its lookup point, at these addresses, and whether it asks
/// its callers to be introduced first.
pub fn announced(ship: &str, addrs: &[SocketAddr], introduce: bool) -> String {
    let addrs: Vec<String> = addrs.iter().map(SocketAddr::to_string).collect();
    format!("~{}{ANNOUNCED}{}{}", ship.trim_start_matches('~'), addrs.join(" and "), if introduce { INTRODUCE_FIRST } else { "." })
}

/// The ship, the first address, and whether callers are asked to be introduced, in a line made
/// by `announced`.
pub fn announced_as(line: &str) -> Option<(String, SocketAddr, bool)> {
    let (ship, rest) = line.split_once(ANNOUNCED)?;
    let (addrs, introduce) = match rest.strip_suffix(INTRODUCE_FIRST) {
        Some(addrs) => (addrs, true),
        None => (rest.strip_suffix('.')?, false),
    };
    let first = addrs.split(" and ").next()?.parse().ok()?;
    Some((ship.to_string(), first, introduce))
}

/// How many of this runtime's ships their lookup points have taken records of, of how many.
pub fn announced_count(announced: usize, of: usize) -> String {
    format!("{announced} of this runtime's {of} ships are announced to their lookup points.")
}

/// How many introductions of callers this runtime has been passed, and how many it acted on.
pub fn introductions(heard: u64, acted: u64) -> String {
    format!("{INTRODUCTIONS}{heard}, of which {acted} were let in.")
}

/// The count of introductions acted on, in a line made by `introductions`.
pub fn introductions_acted(line: &str) -> Option<u64> {
    let rest = line.strip_prefix(INTRODUCTIONS)?;
    rest.split_once(", of which ")?.1.strip_suffix(" were let in.")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_reads_back_as_what_it_was_made_from() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let other: SocketAddr = "[::1]:9".parse().unwrap();
        assert_eq!(talking_at(&talking(addr, "with keys from Urbit ID.")), Some(addr));
        assert_eq!(serving_at(&serving("/tmp/a at http://x", addr)), Some(addr));
        assert_eq!(announced_as(&announced("~sampel-palnet", &[addr, other], true)), Some(("~sampel-palnet".into(), addr, true)));
        assert_eq!(announced_as(&announced("zod", &[other], false)), Some(("~zod".into(), other, false)));
        assert_eq!(introductions_acted(&introductions(3, 2)), Some(2));
        assert_eq!(talking_at("Talking to nobody"), None);
    }
}
