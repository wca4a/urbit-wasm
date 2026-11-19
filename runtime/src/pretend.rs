//! Keys from a list kept in a file, in place of Urbit ID: for trying ships out on machines one
//! controls, with no internet and no real ship's keys.
//!
//! The file names each ship and its key, one to a line: `~sampel-palnet` and then the 64
//! hexadecimal digits of the ship's public key, as `Runtime::public_key` gives it. Blank lines,
//! and lines whose first character that is not a space is `#`, are skipped. Every ship listed is
//! a galaxy, a star or a planet (a moon's key is its parent's to give, as everywhere else), and is
//! listed at revision 1, continuity 0, with no sponsor: nothing in the runtime reads a sponsor
//! but `serve --lookup`, which prints it.
//!
//! Whoever can write the file can be any ship to whoever reads it. That is the point of it, and
//! why it is only for trying things out.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use urbit_id::ob;

use crate::azimuth::{Keys, Listing};

/// The largest list read. A line is under a hundred bytes, so this is room for over ten
/// thousand ships, and a file that is not a list is turned away after reading this much.
pub const MOST_BYTES: u64 = 1 << 20;

/// Ships' keys as a list in a file gives them. The file is read again at every question, so a
/// ship added to it is found without restarting anything; what asks (a runtime's directory, or a
/// lookup point) decides how often it asks.
#[derive(Clone, Debug)]
pub struct PretendIds {
    path: PathBuf,
}

impl PretendIds {
    /// The list in `path`, read and checked whole now, so that a start with a list that is not
    /// one fails at once, saying which line is wrong.
    pub fn open(path: impl AsRef<Path>) -> Result<PretendIds, String> {
        let path = path.as_ref().to_path_buf();
        read(&path)?;
        Ok(PretendIds { path })
    }

    /// The file the list is read from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Keys for PretendIds {
    /// What the list says now. A file that cannot be read, or no longer reads as a list, is an
    /// error that says why: never an answer from an earlier reading, and never a guess.
    ///
    /// A ship not on the list is answered as listed at revision 1 with no key, not as no ship
    /// at all. Keys count upwards in Urbit ID, and a directory never takes an answer of an
    /// earlier revision than the one it holds; "no such ship" counts as revision 0, so a ship
    /// taken off the list would keep the key it had until the directory stopped believing it (a
    /// day). Revision 1 with no key is not earlier, so taking a ship off the list, or changing
    /// its key, holds from the directory's next reading of it (once what it holds is five
    /// minutes old). A ship never listed is treated as one with no key: nothing is kept for it,
    /// and it can neither be called nor announce.
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
        let listed = read(&self.path)?;
        Ok(Some(Listing { key: listed.get(&ship).copied(), revision: 1, continuity: 0, sponsor: None }))
    }
}

/// Read the list in `path`: a regular file (a link to one is followed, as for any file an
/// operator names), never a pipe or a device, of at most `MOST_BYTES`.
pub fn read(path: &Path) -> Result<HashMap<u32, [u8; 32]>, String> {
    let shown = path.display();
    // Not blocking on a pipe while finding out that it is one.
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path).map_err(|e| format!("cannot read the list of ships' keys {shown}: {e}"))?;
    let facts = file.metadata().map_err(|e| format!("cannot read the list of ships' keys {shown}: {e}"))?;
    if !facts.is_file() {
        return Err(format!("the list of ships' keys {shown} is not a regular file"));
    }
    let mut written = Vec::new();
    file.take(MOST_BYTES + 1).read_to_end(&mut written).map_err(|e| format!("cannot read the list of ships' keys {shown}: {e}"))?;
    if written.len() as u64 > MOST_BYTES {
        return Err(format!("the list of ships' keys {shown} is larger than {MOST_BYTES} bytes"));
    }
    let written = String::from_utf8(written).map_err(|_| format!("the list of ships' keys {shown} is not text"))?;
    parse(&written).map_err(|why| format!("the list of ships' keys {shown}: {why}"))
}

/// The ships and keys a list holds, or the first line that is wrong and why.
pub fn parse(written: &str) -> Result<HashMap<u32, [u8; 32]>, String> {
    let mut listed: HashMap<u32, [u8; 32]> = HashMap::new();
    let mut lines_of: HashMap<u32, usize> = HashMap::new();
    let mut keys_of: HashMap<[u8; 32], usize> = HashMap::new();
    for (index, line) in written.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let [name, digits] = words[..] else {
            return Err(format!("line {number} is not a ship's name and 64 hexadecimal digits"));
        };
        if !name.starts_with('~') {
            return Err(format!("line {number}: {name} does not start with ~"));
        }
        let Some(ship) = ob::ship_number(name) else {
            return Err(format!("line {number}: {name} is not the name of a galaxy, star or planet (a moon's key is its parent's to give)"));
        };
        let Some(key) = key_of(digits) else {
            return Err(format!("line {number}: the key of {name} is not 64 hexadecimal digits"));
        };
        if let Some(first) = lines_of.insert(ship, number) {
            return Err(format!("line {number}: {name} is listed already, on line {first}"));
        }
        if let Some(first) = keys_of.insert(key, number) {
            return Err(format!("line {number}: the key of {name} is the key on line {first} already; a key is one ship's"));
        }
        listed.insert(ship, key);
    }
    Ok(listed)
}

/// A key written as 64 hexadecimal digits.
fn key_of(digits: &str) -> Option<[u8; 32]> {
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).ok()).collect::<Option<_>>()?;
    bytes.try_into().ok()
}

/// One line of a list: the ship's name and its key.
pub fn line(ship: &str, key: &[u8; 32]) -> String {
    let digits: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("~{} {digits}", ship.trim_start_matches('~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!("urbit-wasm-{}-pretend-{label}", std::process::id()));
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

    fn number(name: &str) -> u32 {
        ob::ship_number(name).unwrap()
    }

    #[test]
    fn the_names_the_demo_uses_are_planets() {
        for name in ["~sampel-palnet", "~norsyr-torryn"] {
            assert!(number(name) > 0xffff, "{name}");
        }
    }

    #[test]
    fn a_list_names_each_ship_with_its_key_skipping_blank_lines_and_comments() {
        let written = format!("# two ships\n\n{}\n   # indented comment\n{}  \n", line("~sampel-palnet", &[1; 32]), line("zod", &[0xab; 32]).to_uppercase().replacen("~ZOD", "~zod", 1));
        let listed = parse(&written).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[&number("~sampel-palnet")], [1; 32]);
        assert_eq!(listed[&number("~zod")], [0xab; 32]);
        assert_eq!(parse("").unwrap().len(), 0);
    }

    #[test]
    fn a_line_that_is_not_a_ship_and_its_key_fails_saying_which_line() {
        let good = line("~zod", &[1; 32]);
        let key = good.split(' ').nth(1).unwrap().to_string();
        let cases = [
            (format!("{good}\n~nec"), "line 2 is not a ship's name and 64 hexadecimal digits"),
            (format!("{good}\n~nec {key} extra"), "line 2 is not"),
            (format!("nec {key}"), "line 1: nec does not start with ~"),
            (format!("{good}\n\n~nec {}", &key[1..]), "line 3: the key of ~nec is not 64 hexadecimal digits"),
            (format!("~nec {}g", &key[1..]), "line 1: the key of ~nec is not 64"),
            (format!("~nec {key}0"), "line 1: the key of ~nec is not 64"),
            (format!("~notaname {key}"), "line 1: ~notaname is not the name of a galaxy, star or planet"),
            // A moon of ~sampel-palnet.
            (format!("~dozzod-dozzod-sampel-palnet {key}"), "line 1: ~dozzod-dozzod-sampel-palnet is not the name"),
            // A planet written with a star's number in it.
            (format!("~dozzod-marzod {key}"), "line 1: ~dozzod-marzod is not the name"),
        ];
        for (written, said) in cases {
            let why = parse(&written).unwrap_err();
            assert!(why.starts_with(said), "{written:?}: {why}");
        }
    }

    #[test]
    fn a_ship_listed_twice_fails_naming_both_lines() {
        let written = format!("{}\n{}\n{}", line("~zod", &[1; 32]), line("~nec", &[2; 32]), line("~zod", &[3; 32]));
        assert_eq!(parse(&written).unwrap_err(), "line 3: ~zod is listed already, on line 1");
        // The same ship written once with its ~ and once in capitals is still the same ship,
        // and capitals are not a name.
        let written = format!("{}\n~ZOD {}", line("~zod", &[1; 32]), "03".repeat(32));
        assert!(parse(&written).unwrap_err().starts_with("line 2: ~ZOD is not the name"));
    }

    #[test]
    fn one_key_under_two_ships_fails_naming_both_lines() {
        let written = format!("{}\n\n{}", line("~zod", &[7; 32]), line("~sampel-palnet", &[7; 32]));
        assert_eq!(parse(&written).unwrap_err(), "line 3: the key of ~sampel-palnet is the key on line 1 already; a key is one ship's");
    }

    #[test]
    fn the_list_is_read_again_at_every_question() {
        let dir = TempDir::new("again");
        let path = dir.0.join("ids.txt");
        fs::write(&path, line("~zod", &[1; 32])).unwrap();
        let ids = PretendIds::open(&path).unwrap();
        let listed = |name: &str| ids.listing(number(name));
        assert_eq!(listed("~zod").unwrap(), Some(Listing { key: Some([1; 32]), revision: 1, continuity: 0, sponsor: None }));
        assert_eq!(listed("~nec").unwrap(), Some(Listing { key: None, revision: 1, continuity: 0, sponsor: None }));
        // A ship added is found, and a key changed is the new key, with nothing restarted.
        fs::write(&path, format!("{}\n{}", line("~zod", &[9; 32]), line("~nec", &[2; 32]))).unwrap();
        assert_eq!(listed("~zod").unwrap().unwrap().key, Some([9; 32]));
        assert_eq!(listed("~nec").unwrap().unwrap().key, Some([2; 32]));
        // A ship taken off is listed with no key, at the same revision.
        fs::write(&path, line("~nec", &[2; 32])).unwrap();
        assert_eq!(listed("~zod").unwrap(), Some(Listing { key: None, revision: 1, continuity: 0, sponsor: None }));
    }

    #[test]
    fn a_list_that_cannot_be_read_or_no_longer_parses_is_an_error_never_an_old_answer() {
        let dir = TempDir::new("broken");
        let path = dir.0.join("ids.txt");
        fs::write(&path, line("~zod", &[1; 32])).unwrap();
        let ids = PretendIds::open(&path).unwrap();
        assert!(ids.listing(number("~zod")).unwrap().is_some());
        fs::write(&path, format!("{}\n~zod", line("~zod", &[1; 32]))).unwrap();
        let why = ids.listing(number("~zod")).unwrap_err();
        assert!(why.contains("line 2 is not a ship's name"), "{why}");
        fs::remove_file(&path).unwrap();
        let why = ids.listing(number("~zod")).unwrap_err();
        assert!(why.starts_with("cannot read the list of ships' keys"), "{why}");
        // Something that is not a regular file, and something too large, are refused.
        fs::create_dir(&path).unwrap();
        assert!(ids.listing(number("~zod")).unwrap_err().ends_with("is not a regular file"));
        fs::remove_dir(&path).unwrap();
        let mut large = line("~zod", &[1; 32]);
        large.push('\n');
        while large.len() as u64 <= MOST_BYTES {
            large.push_str("# padding padding padding padding padding padding padding padding\n");
        }
        fs::write(&path, &large).unwrap();
        assert!(ids.listing(number("~zod")).unwrap_err().contains("is larger than"));
        assert!(PretendIds::open(&path).is_err());
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(ids.listing(number("~zod")).unwrap_err().ends_with("is not text"));
    }

    #[test]
    fn a_list_that_is_wrong_at_start_is_refused_at_start() {
        let dir = TempDir::new("start");
        let path = dir.0.join("ids.txt");
        assert!(PretendIds::open(&path).is_err());
        fs::write(&path, format!("{}\n{}", line("~zod", &[1; 32]), line("~zod", &[2; 32]))).unwrap();
        assert_eq!(PretendIds::open(&path).unwrap_err(), format!("the list of ships' keys {}: line 2: ~zod is listed already, on line 1", path.display()));
    }
}
