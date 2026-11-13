//! Names. Urbit writes a ship's number as a name (`~sampel-palnet`) and a master ticket's
//! bytes as something that looks like one (`~marbud-tidsev-litsut-hidfep`), both out of the
//! same 512 syllables.

use crate::syllables::{PREFIXES, SUFFIXES};

/// A `~`, twenty-four words of six letters, and the dashes between them.
const MOST_LETTERS: usize = 1 + 24 * 6 + 23;

fn syllable(table: &str, byte: u8) -> &str {
    &table[3 * byte as usize..3 * byte as usize + 3]
}

fn byte_of(table: &str, syllable: &str) -> Option<u8> {
    (0..=255u8).find(|byte| self::syllable(table, *byte) == syllable)
}

/// The words of a name: what is between the dashes, after the `~` if there is one. Each is
/// one syllable or two.
fn words(name: &str) -> Option<Vec<&str>> {
    // The longest thing written this way is a ticket of forty-eight bytes.
    if name.len() > MOST_LETTERS {
        return None;
    }
    let name = name.strip_prefix('~').unwrap_or(name);
    let words: Vec<&str> = name.split('-').collect();
    let sound = words.iter().all(|word| word.is_ascii() && (word.len() == 3 || word.len() == 6));
    sound.then_some(words)
}

/// The bytes of a master ticket, as written. A ticket is 8, 16 or 48 bytes.
pub fn ticket_bytes(ticket: &str) -> Option<Vec<u8>> {
    written_bytes(ticket).filter(|bytes| matches!(bytes.len(), 8 | 16 | 48))
}

/// The bytes that syllables stand for, however many there are.
pub(crate) fn written_bytes(written: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for word in words(written)? {
        // A word of one syllable can only come first, and stands for one byte.
        if word.len() == 3 {
            if !bytes.is_empty() {
                return None;
            }
            bytes.push(byte_of(SUFFIXES, word)?);
        } else {
            bytes.push(byte_of(PREFIXES, &word[..3])?);
            bytes.push(byte_of(SUFFIXES, &word[3..])?);
        }
    }
    Some(bytes)
}

/// A master ticket as it is written, from its bytes.
pub fn ticket(bytes: &[u8]) -> Option<String> {
    if !matches!(bytes.len(), 8 | 16 | 48) {
        return None;
    }
    let words: Vec<String> = bytes.chunks(2).map(|pair| format!("{}{}", syllable(PREFIXES, pair[0]), syllable(SUFFIXES, pair[1]))).collect();
    Some(format!("~{}", words.join("-")))
}

/// The number of the galaxy, star or planet with this name. `None` for anything else,
/// including names written in a way Urbit would not write them.
pub fn ship_number(name: &str) -> Option<u32> {
    let words = words(name)?;
    let written = match words[..] {
        // A galaxy: one syllable, one byte.
        [galaxy] if galaxy.len() == 3 => byte_of(SUFFIXES, galaxy)? as u32,
        // A star: two bytes.
        [star] => u32::from_be_bytes([0, 0, byte_of(PREFIXES, &star[..3])?, byte_of(SUFFIXES, &star[3..])?]),
        // A planet: four.
        [high, low] if high.len() == 6 && low.len() == 6 => u32::from_be_bytes([
            byte_of(PREFIXES, &high[..3])?,
            byte_of(SUFFIXES, &high[3..])?,
            byte_of(PREFIXES, &low[..3])?,
            byte_of(SUFFIXES, &low[3..])?,
        ]),
        _ => return None,
    };
    let number = unscramble(written);
    // One name for one number: a planet written with a star's or a galaxy's number in it
    // is not how that number is written.
    (ship_name(number).trim_start_matches('~') == name.trim_start_matches('~')).then_some(number)
}

/// The name of the galaxy, star or planet with this number.
pub fn ship_name(number: u32) -> String {
    let [a, b, c, d] = scramble(number).to_be_bytes();
    match number {
        0..=0xff => format!("~{}", syllable(SUFFIXES, d)),
        0x100..=0xffff => format!("~{}", pair(c, d)),
        _ => format!("~{}-{}", pair(a, b), pair(c, d)),
    }
}

fn pair(high: u8, low: u8) -> String {
    format!("{}{}", syllable(PREFIXES, high), syllable(SUFFIXES, low))
}

/// The smallest number that is a moon's. Below it are the galaxies, stars and planets.
pub const FIRST_MOON: u64 = 1 << 32;

/// The ship a moon belongs to: the low half of the moon's number is that ship's number.
/// It is a planet as a rule, though a star or a galaxy can have moons too.
pub fn moon_parent(moon: u64) -> u32 {
    moon as u32
}

/// The number of the moon with this name. `None` for anything else.
///
/// A moon's name is its own two or four syllables, then its parent's name written at a
/// planet's length: `~doznec-sampel-palnet` is a moon of `~sampel-palnet`.
pub fn moon_number(name: &str) -> Option<u64> {
    let words = words(name)?;
    if !matches!(words.len(), 3 | 4) || words.iter().any(|word| word.len() != 6) {
        return None;
    }
    let mut written = 0u64;
    for word in &words {
        written = written << 16 | (byte_of(PREFIXES, &word[..3])? as u64) << 8 | byte_of(SUFFIXES, &word[3..])? as u64;
    }
    let number = written & !0xffff_ffff | unscramble(written as u32) as u64;
    (moon_name(number)?.trim_start_matches('~') == name.trim_start_matches('~')).then_some(number)
}

/// The name of the moon with this number. `None` if the number is not a moon's.
pub fn moon_name(number: u64) -> Option<String> {
    if number < FIRST_MOON {
        return None;
    }
    // Only the parent's half is shuffled, and it is shuffled as the parent's own number is.
    let [a, b, c, d, e, f, g, h] = (number & !0xffff_ffff | scramble(number as u32) as u64).to_be_bytes();
    let parent = format!("{}-{}", pair(e, f), pair(g, h));
    Some(if number >> 48 == 0 { format!("~{}-{parent}", pair(c, d)) } else { format!("~{}-{}-{parent}", pair(a, b), pair(c, d)) })
}

/// The number of any ship Urbit ID has a place for, a moon included, from its name.
pub fn any_number(name: &str) -> Option<u64> {
    ship_number(name).map(u64::from).or_else(|| moon_number(name))
}

/// The name of any ship Urbit ID has a place for, a moon included.
pub fn any_name(number: u64) -> String {
    match u32::try_from(number) {
        Ok(number) => ship_name(number),
        Err(_) => moon_name(number).expect("past the planets, every number is a moon's"),
    }
}

/// Planets' numbers are shuffled before they are written, so that a planet's name does not
/// show which star it came from. Galaxies' and stars' are written as they are.
fn scramble(number: u32) -> u32 {
    if number < 0x1_0000 {
        return number;
    }
    let within = number as u64 - 0x1_0000;
    let once = feistel(within);
    // The shuffle is over a range a little larger than there are planets. A result that
    // falls outside is shuffled again.
    let shuffled = if once < 0xffff_ffff { once } else { feistel(once) };
    (0x1_0000 + shuffled) as u32
}

fn unscramble(written: u32) -> u32 {
    if written < 0x1_0000 {
        return written;
    }
    let within = written as u64 - 0x1_0000;
    let once = unfeistel(within);
    let restored = if once < 0xffff_ffff { once } else { unfeistel(once) };
    (0x1_0000 + restored) as u32
}

const A: u64 = 65535;
const B: u64 = 65536;
const ROUNDS: u32 = 4;

/// A cipher over the numbers below 65535 times 65536, in four rounds (Black and Rogaway,
/// "Ciphers with arbitrary finite domains", as Urbit adjusted it).
fn feistel(number: u64) -> u64 {
    let (mut left, mut right) = (number % A, number / A);
    for round in 1..=ROUNDS {
        let mixed = round_hash(round - 1, right);
        let next = if round % 2 != 0 { (left + mixed) % A } else { (left + mixed) % B };
        (left, right) = (right, next);
    }
    if right == A { A * right + left } else { A * left + right }
}

fn unfeistel(number: u64) -> u64 {
    let (high, low) = (number / A, number % A);
    let (mut left, mut right) = if high == A { (low, high) } else { (high, low) };
    for round in (1..=ROUNDS).rev() {
        let mixed = round_hash(round - 1, left);
        let before = if round % 2 != 0 { (right + A - mixed % A) % A } else { (right + B - mixed % B) % B };
        (left, right) = (before, left);
    }
    A * right + left
}

/// What each round mixes in: a hash (MurmurHash3) of the low two bytes of the half it is
/// given, with a different seed for each round.
fn round_hash(round: u32, half: u64) -> u64 {
    const SEEDS: [u32; 4] = [0xb76d_5eed, 0xee28_1300, 0x85bc_ae01, 0x4b38_7af7];
    let key = (half & 0xffff) as u32;
    let mut k = key.wrapping_mul(0xcc9e_2d51);
    k = k.rotate_left(15).wrapping_mul(0x1b87_3593);
    let mut h = SEEDS[round as usize] ^ k;
    // Two bytes were hashed.
    h ^= 2;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_are_named_as_urbit_names_them() {
        // From the test wallets of Urbit's key-generation library, and Urbit's own example.
        let known = [(0, "~zod"), (1, "~nec"), (222, "~ryl"), (255, "~fes"), (256, "~marzod"), (65012, "~matbyr"), (16_777_215, "~taswen-dabmyr"), (1_624_961_343, "~sampel-palnet")];
        for (number, name) in known {
            assert_eq!(ship_name(number), name);
            assert_eq!(ship_number(name), Some(number), "{name}");
            assert_eq!(ship_number(name.trim_start_matches('~')), Some(number), "{name}");
        }
        // Every number has one name, and the name gives the number back.
        for number in (0..=u32::MAX).step_by(65_521).chain([0xffff, 0x1_0000, 0x1_0001, u32::MAX - 1, u32::MAX]) {
            assert_eq!(ship_number(&ship_name(number)), Some(number), "{number}");
        }
        // Not names: nonsense, capitals, a moon, a galaxy's number written as a planet.
        assert_eq!(any_number("~sampel-palnet"), Some(1_624_961_343));
        assert_eq!(any_name(1_624_961_343), "~sampel-palnet");
        for not in ["", "~", "zo", "~zodd", "~ZOD", "~xxx", "~zod-nec", "~sampel-palnet-sampel-palnet", "~dozzod-dozzod", "~dozzod-doznec", "~sampel--palnet", "~sampel-palne\u{e9}"] {
            assert_eq!(ship_number(not), None, "{not:?}");
        }
    }

    #[test]
    fn moons_are_named_after_the_ship_they_belong_to() {
        // `~doznec-bannux-nopfen` is the moon in the tests of Urbit's own naming library: the
        // first moon of the planet `~bannux-nopfen`.
        let planet = ship_number("~bannux-nopfen").unwrap();
        let known = [(1 << 32 | planet as u64, "~doznec-bannux-nopfen".to_string())];
        // A moon with more in front is written with four words: its own two, which are
        // not shuffled, then its parent's two, exactly as the parent writes them.
        let long = [(0xbeef_0001 << 32 | planet as u64, format!("~{}-{}-bannux-nopfen", pair(0xbe, 0xef), pair(0x00, 0x01))), (0x0001_0000 << 32 | planet as u64, "~doznec-dozzod-bannux-nopfen".to_string())];
        for (number, name) in known.iter().chain(&long) {
            let (number, name) = (*number, name.as_str());
            assert_eq!(moon_name(number).as_deref(), Some(name));
            assert_eq!(moon_number(name), Some(number), "{name}");
            assert_eq!(any_number(name.trim_start_matches('~')), Some(number));
            assert_eq!(any_name(number), name);
            assert_eq!(ship_number(name), None);
            assert_eq!(ship_name(moon_parent(number)), "~bannux-nopfen");
        }
        // The first moon of all, a moon of a star, and the last moon of all: a parent that
        // is not a planet is written at a planet's length, unshuffled.
        assert_eq!(moon_name(1 << 32).as_deref(), Some("~doznec-dozzod-dozzod"));
        let of_a_star = moon_name(7 << 32 | 256).unwrap();
        assert!(of_a_star.ends_with("-dozzod-marzod") && of_a_star.len() == 21, "{of_a_star}");
        assert_eq!(moon_number(&of_a_star), Some(7 << 32 | 256));
        assert_eq!(moon_parent(7 << 32 | 256), 256);
        assert!(moon_name(u64::MAX).unwrap().starts_with("~fipfes-fipfes-"));
        // Every moon has one name, and the name gives the number back.
        for high in [1u64, 2, 0xffff, 0x1_0000, 0xdead_beef, u32::MAX as u64] {
            for low in (0..=u32::MAX).step_by(429_496_729).chain([0xff, 0x100, 0xffff, 0x1_0000, u32::MAX]) {
                let number = high << 32 | low as u64;
                assert_eq!(moon_number(&moon_name(number).unwrap()), Some(number), "{number:x}");
            }
        }
        // Not moons: a planet, a planet written long, a moon written longer than it need
        // be, a comet's length, and nonsense.
        assert_eq!(moon_name(u32::MAX as u64), None);
        for not in ["~sampel-palnet", "~dozzod-sampel-palnet", "~dozzod-doznec-sampel-palnet", "~dozzod-dozzod-dozzod-dozzod", "~doznec-dozzod-dozzod-dozzod-dozzod", "~nec-sampel-palnet", "~doznec-sampel", "~doznec-sampel-palne\u{e9}", ""] {
            assert_eq!(moon_number(not), None, "{not:?}");
            assert_eq!(any_number(not).filter(|number| *number >= FIRST_MOON), None, "{not:?}");
        }
    }

    #[test]
    fn a_ticket_is_read_as_urbit_writes_it() {
        assert_eq!(ticket_bytes("~doznec-marbud"), None, "a ticket of four bytes is too short to be one");
        assert_eq!(ticket_bytes("~marbud-tidsev-litsut-hidfep").unwrap().len(), 8);
        let bytes: Vec<u8> = (0..16).collect();
        let written = ticket(&bytes).unwrap();
        assert_eq!(written, "~doznec-binwes-samper-siglet-fidpen-sogdur-wacser-wissun");
        assert_eq!(ticket_bytes(&written), Some(bytes.clone()));
        assert_eq!(ticket_bytes(written.trim_start_matches('~')), Some(bytes));
        for length in [8, 16, 48] {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(ticket_bytes(&ticket(&bytes).unwrap()), Some(bytes));
        }
        assert_eq!(ticket(&[0; 4]), None);
        assert_eq!(ticket_bytes(&"-".repeat(1 << 20)), None);
        assert_eq!(ship_number(&"-".repeat(1 << 20)), None);
        let longest = ticket(&[0x5a; 48]).unwrap();
        assert_eq!(longest.len(), MOST_LETTERS);
        assert!(ticket_bytes(&longest).is_some() && ticket_bytes(&format!("{longest}-marbud")).is_none());
        for not in ["", "~marbud-tidsev-litsut", "~marbud-tidsev-litsut-hidfep-marbud", "~marbud-tidsev-litsut-hidfe", "~marbud-tidsev-litsut-hidfepp", "~MARBUD-tidsev-litsut-hidfep", "~budmar-tidsev-litsut-hidfep"] {
            assert_eq!(ticket_bytes(not), None, "{not:?}");
        }
    }
}
