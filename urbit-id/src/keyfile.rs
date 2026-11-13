//! The keyfile: what a ship is started from. It holds the ship's number, the revision of
//! its networking keys, and the keys themselves, and nothing else of the wallet. So it is
//! what the machine a ship runs on is given, and the master ticket need never be.
//!
//! It is a noun, Urbit's one kind of data (a number, or a pair of nouns), packed into a
//! single number ("jam") and written in base 64 the way Urbit writes it (`0w...`). Two
//! shapes are in use and both are read: the older `[ship revision keys signature]`, which is
//! what is written here, and the newer one that can list several revisions.
//!
//! The older shape has a place for a signature, which Urbit leaves empty. Here a moon's
//! keyfile carries its parent's signature there: a moon is in no public list, so that
//! signature is what it shows other ships to prove whose moon it is.

use std::collections::HashMap;
use std::rc::Rc;

use crate::wallet::NetworkKeys;

/// What a keyfile says.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keyfile {
    /// The ship's number: a galaxy's, star's or planet's, or a moon's, which is longer.
    pub ship: u64,
    /// Which revision of the ship's networking keys these are (Azimuth's key revision
    /// number, counted from one once keys have been set).
    pub revision: u32,
    pub keys: NetworkKeys,
    /// For a moon, its parent's signature over its name, this revision and its key.
    pub signed: Option<[u8; 64]>,
}

impl Keyfile {
    /// Read a keyfile. `None` if it is not one, or holds keys of a kind not known here.
    pub fn parse(text: &str) -> Option<Keyfile> {
        // A keyfile is a hundred or so letters. Anything much longer is not looked at.
        if text.len() > MOST_LETTERS {
            return None;
        }
        let noun = cue(&from_base64(text.trim())?)?;
        let (first, rest) = noun.pair()?;
        // The newer shape begins with a version, itself a pair: [[2 0] ship rift keys].
        if let Some((version, _)) = first.pair() {
            if version.number()? != 2 {
                return None;
            }
            let (ship, rest) = rest.pair()?;
            let (_rift, list) = rest.pair()?;
            // The keys are a list, newest wanted: the highest revision in it.
            let (mut list, mut newest) = (list, None);
            while let Some((entry, more)) = list.pair() {
                let (revision, ring) = entry.pair()?;
                let revision = revision.number()?;
                if newest.as_ref().is_none_or(|(highest, _)| revision > *highest) {
                    newest = Some((revision, keys_of(ring)?));
                }
                list = more;
            }
            let (revision, keys) = newest?;
            return Some(Keyfile { ship: ship.wide()?, revision, keys, signed: None });
        }
        let (revision, rest) = rest.pair()?;
        let (ring, signature) = rest.pair()?;
        // Nothing, which is nought; or something, which is a pair of nought and the thing.
        let signed = match signature.pair() {
            None if signature.number() == Some(0) => None,
            Some((nought, Noun::Atom(bytes))) if nought.number() == Some(0) && bytes.len() <= 64 => {
                let mut whole = [0u8; 64];
                whole[..bytes.len()].copy_from_slice(bytes);
                Some(whole)
            }
            _ => return None,
        };
        Some(Keyfile { ship: first.wide()?, revision: revision.number()?, keys: keys_of(ring)?, signed })
    }

    /// Write a keyfile, in the older shape, which every runtime reads.
    pub fn write(&self) -> String {
        let ring = [&[SUITE_B][..], &self.keys.auth, &self.keys.crypt].concat();
        let atom = |number: u64| Noun::Atom(trimmed(number.to_le_bytes().to_vec()));
        let cell = |head: Noun, tail: Noun| Noun::Cell(Rc::new(head), Rc::new(tail));
        let signature = match &self.signed {
            None => atom(0),
            Some(signed) => cell(atom(0), Noun::Atom(trimmed(signed.to_vec()))),
        };
        to_base64(&jam(&cell(atom(self.ship), cell(atom(self.revision as u64), cell(Noun::Atom(trimmed(ring)), signature)))))
    }
}

/// The longest text read as a keyfile. One for a ship with thirty revisions of its keys
/// listed fits several times over.
const MOST_LETTERS: usize = 4096;

/// The letter Urbit puts at the front of a pair of private keys of the only kind there is.
const SUITE_B: u8 = b'B';

/// The two keys in a "ring": the letter, then the authentication key, then the encryption
/// key, as bytes from the lowest.
fn keys_of(ring: &Noun) -> Option<NetworkKeys> {
    let Noun::Atom(bytes) = ring else { return None };
    // Keys that end in zero bytes are shorter as numbers. No more than 65 bytes in all.
    if bytes.len() > 65 || bytes.first() != Some(&SUITE_B) {
        return None;
    }
    let mut whole = [0u8; 65];
    whole[..bytes.len()].copy_from_slice(bytes);
    Some(NetworkKeys { auth: whole[1..33].try_into().ok()?, crypt: whole[33..65].try_into().ok()? })
}

/// A noun. A number of any size is kept as its bytes from the lowest, with no zero bytes
/// at the high end.
///
/// The halves of a pair are shared, not owned. A packed noun can say "the same as that
/// part, again" as often as it likes, each time in a few bits, so one of a hundred letters
/// can stand for billions of parts. Shared, each part is still there once.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Noun {
    Atom(Vec<u8>),
    Cell(Rc<Noun>, Rc<Noun>),
}

impl Noun {
    fn pair(&self) -> Option<(&Noun, &Noun)> {
        match self {
            Noun::Cell(head, tail) => Some((head, tail)),
            Noun::Atom(_) => None,
        }
    }

    /// A number that fits in thirty-two bits.
    fn number(&self) -> Option<u32> {
        match self {
            Noun::Atom(bytes) if bytes.len() <= 4 => Some(bytes.iter().rev().fold(0u32, |number, byte| number << 8 | *byte as u32)),
            _ => None,
        }
    }

    /// A number that fits in sixty-four bits.
    fn wide(&self) -> Option<u64> {
        match self {
            Noun::Atom(bytes) if bytes.len() <= 8 => Some(bytes.iter().rev().fold(0u64, |number, byte| number << 8 | *byte as u64)),
            _ => None,
        }
    }
}

fn trimmed(mut bytes: Vec<u8>) -> Vec<u8> {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    bytes
}

/// How many bits a number takes.
fn bit_length(bytes: &[u8]) -> usize {
    bytes.last().map_or(0, |high| 8 * bytes.len() - high.leading_zeros() as usize)
}

/// Bits, written and read from the lowest.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    length: usize,
}

impl Bits {
    fn push(&mut self, bit: bool) {
        if self.length % 8 == 0 {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[self.length / 8] |= 1 << (self.length % 8);
        }
        self.length += 1;
    }

    /// The lowest `count` bits of a number.
    fn push_number(&mut self, bytes: &[u8], count: usize) {
        (0..count).for_each(|at| self.push(bytes.get(at / 8).is_some_and(|byte| byte >> (at % 8) & 1 == 1)));
    }

    /// A number with its own length in front ("mat"): the length of its length as that
    /// many zeros and a one, then its length less the top bit, then the number.
    fn push_sized(&mut self, bytes: &[u8]) {
        let length = bit_length(bytes);
        if length == 0 {
            return self.push(true);
        }
        let length_bytes = (length as u64).to_le_bytes();
        let length_length = bit_length(&trimmed(length_bytes.to_vec()));
        (0..length_length).for_each(|_| self.push(false));
        self.push(true);
        self.push_number(&length_bytes, length_length - 1);
        self.push_number(bytes, length);
    }
}

/// Pack a noun into one number. A part that appears twice is written once and pointed
/// back to, unless it is a number shorter than the pointer would be.
fn jam(noun: &Noun) -> Vec<u8> {
    fn pack<'a>(noun: &'a Noun, out: &mut Bits, seen: &mut HashMap<&'a Noun, usize>) {
        if let Some(at) = seen.get(noun).copied() {
            let pointer = trimmed((at as u64).to_le_bytes().to_vec());
            match noun {
                Noun::Atom(bytes) if bit_length(bytes) <= bit_length(&pointer) => {
                    out.push(false);
                    out.push_sized(bytes);
                }
                _ => {
                    out.push(true);
                    out.push(true);
                    out.push_sized(&pointer);
                }
            }
            return;
        }
        seen.insert(noun, out.length);
        match noun {
            Noun::Atom(bytes) => {
                out.push(false);
                out.push_sized(bytes);
            }
            Noun::Cell(head, tail) => {
                out.push(true);
                out.push(false);
                pack(head, out, seen);
                pack(tail, out, seen);
            }
        }
    }
    let mut out = Bits::default();
    pack(noun, &mut out, &mut HashMap::new());
    trimmed(out.bytes)
}

/// Unpack a number made by `jam`. `None` if it is not one. Keyfiles are small, so anything
/// large or deep is refused rather than followed.
fn cue(packed: &[u8]) -> Option<Noun> {
    const MOST_BITS: usize = 8 * 4096;
    const DEEPEST: usize = 64;
    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
        seen: HashMap<usize, Rc<Noun>>,
    }
    impl Reader<'_> {
        fn bit(&mut self) -> Option<bool> {
            // Past the end of the number there are only zeros, and none of them mean anything.
            let byte = self.bytes.get(self.at / 8)?;
            let bit = byte >> (self.at % 8) & 1 == 1;
            self.at += 1;
            Some(bit)
        }

        fn number(&mut self, count: usize) -> Option<Vec<u8>> {
            let mut bits = Bits::default();
            for _ in 0..count {
                // The top bits of the last number may be the zeros past the end.
                let bit = self.bit().unwrap_or(false);
                bits.push(bit);
            }
            Some(trimmed(bits.bytes))
        }

        fn sized(&mut self) -> Option<Vec<u8>> {
            let mut length_length = 0;
            while !self.bit()? {
                length_length += 1;
                if length_length > 16 {
                    return None;
                }
            }
            if length_length == 0 {
                return Some(Vec::new());
            }
            let low = self.number(length_length - 1)?;
            let length = low.iter().rev().fold(0usize, |number, byte| number << 8 | *byte as usize) | 1 << (length_length - 1);
            if length > MOST_BITS {
                return None;
            }
            self.number(length)
        }

        fn noun(&mut self, depth: usize) -> Option<Rc<Noun>> {
            if depth > DEEPEST {
                return None;
            }
            let start = self.at;
            let noun = if !self.bit()? {
                Noun::Atom(self.sized()?)
            } else if !self.bit()? {
                let head = self.noun(depth + 1)?;
                let tail = self.noun(depth + 1)?;
                Noun::Cell(head, tail)
            } else {
                let pointer = self.sized()?;
                // A pointer is to somewhere in the number, which is small.
                if pointer.len() > 2 {
                    return None;
                }
                let at = pointer.iter().rev().fold(0usize, |number, byte| number << 8 | *byte as usize);
                // The part pointed at, itself, and not a copy of it.
                return self.seen.get(&at).cloned();
            };
            let noun = Rc::new(noun);
            self.seen.insert(start, noun.clone());
            Some(noun)
        }
    }
    if 8 * packed.len() > MOST_BITS {
        return None;
    }
    let mut reader = Reader { bytes: packed, at: 0, seen: HashMap::new() };
    let noun = reader.noun(0)?;
    // Nothing but zeros may follow.
    (reader.at >= bit_length(packed)).then(|| Rc::unwrap_or_clone(noun))
}

/// The sixty-four digits Urbit writes base 64 in.
const DIGITS: &[u8; 64] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-~";

/// A number as Urbit writes it in base 64: `0w`, then digits from the highest, with a dot
/// between every five counted from the low end.
fn to_base64(number: &[u8]) -> String {
    let digits = bit_length(number).div_ceil(6).max(1);
    let digit = |at: usize| (0..6).fold(0usize, |value, bit| value | (number.get((6 * at + bit) / 8).is_some_and(|byte| byte >> ((6 * at + bit) % 8) & 1 == 1) as usize) << bit);
    let mut out = String::from("0w");
    for at in (0..digits).rev() {
        out.push(DIGITS[digit(at)] as char);
        if at != 0 && at % 5 == 0 {
            out.push('.');
        }
    }
    out
}

fn from_base64(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0w")?;
    if digits.len() > MOST_LETTERS {
        return None;
    }
    let mut bits = Bits::default();
    let values: Vec<usize> = digits.bytes().filter(|byte| *byte != b'.').map(|byte| DIGITS.iter().position(|digit| *digit == byte)).collect::<Option<_>>()?;
    if values.is_empty() {
        return None;
    }
    for value in values.iter().rev() {
        (0..6).for_each(|bit| bits.push(value >> bit & 1 == 1));
    }
    Some(trimmed(bits.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The vectors of `generateKeyfile` in Urbit's key-generation library.
    #[test]
    fn a_keyfile_is_written_and_read_as_urbit_does() {
        let keys = NetworkKeys::from_seed(&unhex("88359ba61d766e1c2ec9598831668d4233b0f8f58b29da8cf33d25b2590d62a0"));
        let known = [
            (0, 1, "0w5ea.9Qhfa.yzIMA.qtR2v.sLQJz.kndZE.Rimev.3-RVV.Gtvkn.qBA66.q0jio.OPbL5.AIvkh.cpsmA.XHyjP.zViwm.m2onG.oqZ8g.8w0sp"),
            (0, 2, "0wFNh.ey9Vk.ktC4z.jKEjX.B-BIq.yVLJ6.GiNPU.vSLfd.jHWyX.kIwMP.g2qj6.mptUI.BzWy9.zbyQD.tsius.vak2O.Mj2Zj.3nF21.4038p"),
            (1_000_000, 1, "0w2D5.4W8DB.hhSoi.deWxf.KnWmN.GbC-Q.qFb7f.x~qYY.ReLGb.JiO33.d09Fc.ppBTy.OmfG8.CcKbi.tRN9V.NYFgb.b1cbR.cduA8.4g0ef.Ei0A1"),
            (1_000_000, 2, "0wkUE.Dh4YG.aeP2h.FTk9Z.O~iSd.hsTSz.l9oVY.fXnDC.FRZht.Gmgop.E1d9z.bcKYm.iNZh4.NBNqj.KK9fe.fBa1p.o9xuF.xHQx0.y01Af.Ei0A1"),
        ];
        for (ship, revision, text) in known {
            let keyfile = Keyfile { ship, revision, keys: keys.clone(), signed: None };
            assert_eq!(keyfile.write(), text, "{ship} at {revision}");
            assert_eq!(Keyfile::parse(text), Some(keyfile.clone()), "{ship} at {revision}");
            assert_eq!(Keyfile::parse(&format!("  {text}\n")), Some(keyfile));
        }
    }

    #[test]
    fn any_keys_survive_a_keyfile_and_what_is_not_one_is_refused() {
        // Keys that end in zeros are shorter as numbers; ships and revisions at both ends.
        let mut ending_in_zeros = NetworkKeys { auth: [7; 32], crypt: [9; 32] };
        ending_in_zeros.crypt[20..].fill(0);
        // (A key of nothing but zeros is still a key, as far as a keyfile goes.)
        for keys in [NetworkKeys { auth: [0xff; 32], crypt: [0xff; 32] }, NetworkKeys { auth: [0; 32], crypt: [1; 32] }, NetworkKeys { auth: [1; 32], crypt: [0; 32] }, ending_in_zeros] {
            for (ship, revision) in [(0, 0), (1, 1), (255, 7), (65_536, 300), (u32::MAX as u64, u32::MAX), (1 << 32, 1), (u64::MAX, 9)] {
                // With no signature, and with one: any one, a signature that ends in zeros
                // included, which is shorter as a number.
                let mut ending_in_zeros = [0x5a; 64];
                ending_in_zeros[40..].fill(0);
                for signed in [None, Some([0xff; 64]), Some(ending_in_zeros), Some([0; 64])] {
                    let keyfile = Keyfile { ship, revision, keys: keys.clone(), signed };
                    assert_eq!(Keyfile::parse(&keyfile.write()), Some(keyfile), "{ship} at {revision}");
                }
            }
        }
        // The newer shape, which lists revisions: [[2 0] ship rift [[1 ring] [3 ring] 0]].
        let ring = |keys: &NetworkKeys| Noun::Atom(trimmed([&[SUITE_B][..], &keys.auth, &keys.crypt].concat()));
        let atom = |number: u32| Noun::Atom(trimmed(number.to_le_bytes().to_vec()));
        let cell = |head: Noun, tail: Noun| Noun::Cell(Rc::new(head), Rc::new(tail));
        let (older, newer) = (NetworkKeys { auth: [1; 32], crypt: [2; 32] }, NetworkKeys { auth: [3; 32], crypt: [4; 32] });
        let listed = cell(cell(atom(1), ring(&older)), cell(cell(atom(3), ring(&newer)), atom(0)));
        let feed = cell(cell(atom(2), atom(0)), cell(atom(1_000_000), cell(atom(5), listed)));
        assert_eq!(Keyfile::parse(&to_base64(&jam(&feed))), Some(Keyfile { ship: 1_000_000, revision: 3, keys: newer, signed: None }));
        assert_eq!(cue(&jam(&feed)), Some(feed));

        let good = Keyfile { ship: 5, revision: 1, keys: older.clone(), signed: None }.write();
        // Not base 64 as Urbit writes it, not a packed noun, not the right shape, not keys.
        for not in ["", "0w", "5ea.9Qhfa", "0w5ea.9Qh!a", &good[..good.len() - 30], &format!("{good}0")] {
            assert_eq!(Keyfile::parse(not), None, "{not:?}");
        }
        let shapes = [
            atom(5),
            cell(atom(5), atom(1)),
            cell(atom(5), cell(atom(1), atom(0))),
            cell(ring(&older), cell(atom(1), cell(ring(&older), atom(0)))),
            cell(atom(5), cell(atom(1), cell(atom(67), atom(0)))),
            cell(atom(5), cell(atom(1), cell(Noun::Atom([&[b'C'][..], &[1; 64]].concat()), atom(0)))),
            cell(atom(5), cell(atom(1), cell(Noun::Atom([&[SUITE_B][..], &[1; 65]].concat()), atom(0)))),
            cell(cell(atom(3), atom(0)), cell(atom(5), cell(atom(0), cell(cell(atom(1), ring(&older)), atom(0))))),
            cell(cell(atom(2), atom(0)), cell(atom(5), cell(atom(0), atom(0)))),
            // In the place for a signature: a number that is not nought, a pair that does
            // not begin with nought, a signature too long to be one, a pair where one goes.
            cell(atom(5), cell(atom(1), cell(ring(&older), atom(7)))),
            cell(atom(5), cell(atom(1), cell(ring(&older), cell(atom(1), atom(9))))),
            cell(atom(5), cell(atom(1), cell(ring(&older), cell(atom(0), Noun::Atom(vec![1; 65]))))),
            cell(atom(5), cell(atom(1), cell(ring(&older), cell(atom(0), cell(atom(1), atom(2)))))),
            // A ship's number too long to be even a moon's.
            cell(Noun::Atom(vec![1; 9]), cell(atom(1), cell(ring(&older), atom(0)))),
        ];
        for shape in shapes {
            assert_eq!(Keyfile::parse(&to_base64(&jam(&shape))), None, "{shape:?}");
        }
        // A noun that points back at itself, or at nothing, or goes too deep, is not followed.
        let mut deep = atom(0);
        for _ in 0..80 {
            deep = cell(atom(1), deep);
        }
        assert_eq!(cue(&jam(&deep)), None);
        assert_eq!(cue(&[0b0000_0111]), None);

        // A pair of a pair of a pair, forty deep, each the same thing twice. Written out it
        // has a million million parts. Packed it is a few hundred bits, and it is read
        // without being written out: this returns at once, and says it is not a keyfile.
        // (Packed by hand: forty times "a pair, whose first half follows", then nought, then
        // forty times "and whose second half is the same as the first", from the inside out.)
        let mut doubled = Bits::default();
        for _ in 0..40 {
            doubled.push(true);
            doubled.push(false);
        }
        doubled.push(false);
        doubled.push_sized(&[]);
        for level in 1..=40u64 {
            doubled.push(true);
            doubled.push(true);
            doubled.push_sized(&trimmed((2 * (40 - level + 1)).to_le_bytes().to_vec()));
        }
        let packed = trimmed(doubled.bytes);
        assert!(packed.len() < 100, "{} bytes", packed.len());
        let read = cue(&packed).unwrap();
        // It is what it was said to be, as far down as anyone would care to look.
        let mut part = &read;
        for _ in 0..40 {
            let (head, tail) = part.pair().unwrap();
            assert!(std::ptr::eq(head, tail));
            part = head;
        }
        assert_eq!(part.number(), Some(0));
        assert_eq!(Keyfile::parse(&to_base64(&packed)), None);
        // Nor is anything long looked at, however it is made up.
        assert_eq!(Keyfile::parse(&format!("0w{}", "1".repeat(MOST_LETTERS))), None);
        assert_eq!(Keyfile::parse(&".".repeat(1 << 20)), None);
        let padded = format!("{}{good}", " ".repeat(MOST_LETTERS));
        assert_eq!(Keyfile::parse(&padded), None);
    }
}
