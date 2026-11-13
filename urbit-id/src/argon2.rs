//! Argon2, the slow hash a master ticket is put through, in the variant Urbit uses.
//!
//! A master ticket is short enough to write on paper, so the step from ticket to keys is made
//! slow and memory-hungry on purpose: each guess at a ticket costs half a gigabyte and a
//! good part of a second. Argon2 is the standard way to do that.
//!
//! Urbit's wallet uses a variant of its own, "Argon2u", which no library has. It differs
//! from the standard Argon2id in two small ways, both in `Kind` below. The standard kind is
//! kept here too, only so that this code can be checked against a library before its Urbit
//! variant is trusted.
//!
//! Follows RFC 9106 and the reference implementation (version 0x13).

use std::sync::Mutex;

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};

/// Which Argon2. The kinds differ in when the choice of which earlier block to mix in
/// depends on the secret and when it does not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// The standard Argon2id: independent of the secret for the first half of the first
    /// pass.
    Id,
    /// Urbit's: independent of the secret for the first three quarters of the first pass,
    /// and with a number of its own, so its output never matches another kind's.
    U,
}

impl Kind {
    fn number(self) -> u32 {
        match self {
            Kind::Id => 2,
            Kind::U => 10,
        }
    }

    fn independent_of_the_secret(self, pass: u32, slice: u32) -> bool {
        pass == 0
            && match self {
                Kind::Id => slice < SLICES / 2,
                Kind::U => slice <= SLICES / 2,
            }
    }
}

pub struct Cost {
    /// How many lanes the memory is divided into. They can be filled side by side; here
    /// they are filled one after another, which gives the same answer.
    pub lanes: u32,
    /// How much memory to fill, in blocks of 1024 bytes.
    pub memory_blocks: u32,
    /// How many times to go over it.
    pub passes: u32,
}

/// A lane is filled in four slices. Within a slice, a lane may only look at what other
/// lanes had finished before the slice began.
const SLICES: u32 = 4;
/// The most this will do: four gibibytes of memory, a megabyte in, 1024 bytes out.
const MOST_BLOCKS: u32 = 1 << 22;
const MOST_LANES: u32 = 1 << 16;
const MOST_IN: usize = 1 << 20;
const MOST_OUT: usize = 1024;
const WORDS: usize = 128;
const VERSION: u32 = 0x13;

type Block = [u64; WORDS];

/// One at a time. Each run holds all of its memory at once, and a process asked for several
/// together should not need several times that.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Hash `password` with `salt` into `out_len` bytes. `None` if the costs are ones Argon2
/// does not allow.
pub fn hash(kind: Kind, password: &[u8], salt: &[u8], cost: &Cost, out_len: usize) -> Option<Vec<u8>> {
    let lanes = cost.lanes;
    if lanes == 0 || lanes > MOST_LANES || cost.passes == 0 || cost.memory_blocks < 8 * lanes || salt.len() < 8 {
        return None;
    }
    // Nothing is asked for here that needs more than these, and beyond them the sizes
    // stop fitting in the numbers that hold them.
    if !(4..=MOST_OUT).contains(&out_len) || cost.memory_blocks > MOST_BLOCKS || password.len() > MOST_IN || salt.len() > MOST_IN {
        return None;
    }
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // Memory is rounded down to a whole number of slices in every lane.
    let lane_len = cost.memory_blocks / (SLICES * lanes) * SLICES;
    let slice_len = lane_len / SLICES;
    let blocks = (lane_len * lanes) as usize;
    // More than this machine can hold in one piece (on one with small addresses).
    if blocks > isize::MAX as usize / size_of::<Block>() {
        return None;
    }

    // Everything that goes in, hashed together. Every later step starts from this.
    let mut start = Blake2b512::new();
    for number in [lanes, out_len as u32, cost.memory_blocks, cost.passes, VERSION, kind.number()] {
        Digest::update(&mut start, number.to_le_bytes());
    }
    for part in [password, salt, &[], &[]] {
        Digest::update(&mut start, (part.len() as u32).to_le_bytes());
        Digest::update(&mut start, part);
    }
    let start: [u8; 64] = start.finalize().into();

    let mut memory: Vec<Block> = vec![[0u64; WORDS]; blocks];
    // The first two blocks of each lane come straight from the starting hash.
    for lane in 0..lanes {
        for first in 0..2u32 {
            let mut bytes = [0u8; 8 * WORDS];
            long_hash(&mut bytes, &[&start, &first.to_le_bytes(), &lane.to_le_bytes()]);
            memory[(lane * lane_len + first) as usize] = words(&bytes);
        }
    }

    let shape = Shape { kind, lanes, lane_len, slice_len, blocks: blocks as u32, passes: cost.passes };
    for pass in 0..cost.passes {
        for slice in 0..SLICES {
            for lane in 0..lanes {
                fill_slice(&mut memory, &shape, pass, slice, lane);
            }
        }
    }

    // The last block of every lane, mixed together and hashed down to the length asked for.
    let mut last = memory[(lane_len - 1) as usize];
    for lane in 1..lanes {
        let other = &memory[(lane * lane_len + lane_len - 1) as usize];
        last.iter_mut().zip(other).for_each(|(word, other)| *word ^= other);
    }
    let mut out = vec![0u8; out_len];
    long_hash(&mut out, &[&bytes(&last)]);
    Some(out)
}

struct Shape {
    kind: Kind,
    lanes: u32,
    lane_len: u32,
    slice_len: u32,
    blocks: u32,
    passes: u32,
}

fn fill_slice(memory: &mut [Block], shape: &Shape, pass: u32, slice: u32, lane: u32) {
    let independent = shape.kind.independent_of_the_secret(pass, slice);
    // Where the choice is independent of the secret, it comes from a counter run through
    // the same mixing, 128 choices at a time.
    let mut counter: Block = [0; WORDS];
    let mut choices: Block = [0; WORDS];
    if independent {
        let about = [pass, lane, slice, shape.blocks, shape.passes, shape.kind.number()];
        about.iter().zip(counter.iter_mut()).for_each(|(value, word)| *word = *value as u64);
    }
    let next_choices = |counter: &mut Block, choices: &mut Block| {
        counter[6] += 1;
        let zero = [0u64; WORDS];
        let once = mix(&zero, counter);
        *choices = mix(&zero, &once);
    };

    // The first two blocks of the first slice are already there.
    let begin = if pass == 0 && slice == 0 { 2 } else { 0 };
    if begin == 2 && independent {
        next_choices(&mut counter, &mut choices);
    }
    for index in begin..shape.slice_len {
        let in_lane = slice * shape.slice_len + index;
        let here = (lane * shape.lane_len + in_lane) as usize;
        // The block before this one in the lane, going round to the lane's end from its start.
        let before = if in_lane == 0 { here + shape.lane_len as usize - 1 } else { here - 1 };

        let chosen = if independent {
            if index % WORDS as u32 == 0 {
                next_choices(&mut counter, &mut choices);
            }
            choices[index as usize % WORDS]
        } else {
            memory[before][0]
        };
        // Which lane to take a block from, and which of the blocks it may take.
        let from_lane = if pass == 0 && slice == 0 { lane } else { ((chosen >> 32) % shape.lanes as u64) as u32 };
        let same_lane = from_lane == lane;
        let finished = if pass == 0 { slice * shape.slice_len } else { shape.lane_len - shape.slice_len };
        let allowed = (if same_lane {
            finished + index - 1
        } else if index == 0 {
            finished - 1
        } else {
            finished
        }) as u64;
        // Weighted towards the newest blocks.
        let spread = chosen & 0xffff_ffff;
        let spread = (spread * spread) >> 32;
        let back = allowed - 1 - ((allowed * spread) >> 32);
        let first = (if pass == 0 || slice == SLICES - 1 { 0 } else { (slice + 1) * shape.slice_len }) as u64;
        let from = (from_lane * shape.lane_len) as usize + ((first + back) % shape.lane_len as u64) as usize;

        let mut made = mix(&memory[before], &memory[from]);
        // On later passes the new block is laid over what was there.
        if pass > 0 {
            made.iter_mut().zip(&memory[here]).for_each(|(word, old)| *word ^= old);
        }
        memory[here] = made;
    }
}

/// Argon2's compression: two blocks in, one out.
fn mix(one: &Block, other: &Block) -> Block {
    let mut both = [0u64; WORDS];
    for ((word, a), b) in both.iter_mut().zip(one).zip(other) {
        *word = a ^ b;
    }
    let mut mixed = both;
    // Across each row of sixteen words, then down each column.
    for row in 0..8 {
        let at: [usize; 16] = std::array::from_fn(|i| 16 * row + i);
        round(&mut mixed, &at);
    }
    for column in 0..8 {
        let at: [usize; 16] = std::array::from_fn(|i| 2 * column + 16 * (i / 2) + i % 2);
        round(&mut mixed, &at);
    }
    for (word, before) in mixed.iter_mut().zip(&both) {
        *word ^= before;
    }
    mixed
}

/// One round of BLAKE2b's mixing over sixteen words, with a multiplication added.
fn round(block: &mut Block, at: &[usize; 16]) {
    const QUARTERS: [[usize; 4]; 8] =
        [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15], [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
    let add = |x: u64, y: u64| x.wrapping_add(y).wrapping_add(2u64.wrapping_mul(x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff));
    for [a, b, c, d] in QUARTERS {
        let (a, b, c, d) = (at[a], at[b], at[c], at[d]);
        block[a] = add(block[a], block[b]);
        block[d] = (block[d] ^ block[a]).rotate_right(32);
        block[c] = add(block[c], block[d]);
        block[b] = (block[b] ^ block[c]).rotate_right(24);
        block[a] = add(block[a], block[b]);
        block[d] = (block[d] ^ block[a]).rotate_right(16);
        block[c] = add(block[c], block[d]);
        block[b] = (block[b] ^ block[c]).rotate_right(63);
    }
}

/// BLAKE2b stretched to any length: the hash of the hash of the hash, half of each kept.
fn long_hash(out: &mut [u8], parts: &[&[u8]]) {
    let length = (out.len() as u32).to_le_bytes();
    if out.len() <= 64 {
        let mut hash = Blake2bVar::new(out.len()).expect("a length BLAKE2b can give");
        hash.update(&length);
        parts.iter().for_each(|part| hash.update(part));
        hash.finalize_variable(out).expect("the length it was made for");
        return;
    }
    let mut hash = Blake2b512::new();
    Digest::update(&mut hash, length);
    parts.iter().for_each(|part| Digest::update(&mut hash, part));
    let mut link: [u8; 64] = hash.finalize().into();
    let mut at = 0;
    while out.len() - at > 64 {
        out[at..at + 32].copy_from_slice(&link[..32]);
        at += 32;
        if out.len() - at > 64 {
            link = Blake2b512::digest(link).into();
        }
    }
    let mut hash = Blake2bVar::new(out.len() - at).expect("a length BLAKE2b can give");
    hash.update(&link);
    hash.finalize_variable(&mut out[at..]).expect("the length it was made for");
}

fn words(bytes: &[u8; 8 * WORDS]) -> Block {
    std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().expect("eight bytes")))
}

fn bytes(block: &Block) -> [u8; 8 * WORDS] {
    let mut out = [0u8; 8 * WORDS];
    block.iter().enumerate().for_each(|(i, word)| out[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The standard kind, against a library, over shapes that reach every branch: one lane
    /// and several, one pass and several, memory that is and is not a round number, short
    /// and long outputs.
    #[test]
    fn the_standard_kind_matches_a_library() {
        let cases: [(u32, u32, u32, usize); 7] =
            [(1, 8, 1, 32), (1, 64, 3, 32), (4, 32, 1, 32), (4, 67, 2, 32), (3, 1024, 2, 64), (2, 256, 4, 4), (4, 4096, 1, 137)];
        for (lanes, memory_blocks, passes, out_len) in cases {
            let cost = Cost { lanes, memory_blocks, passes };
            let ours = hash(Kind::Id, b"a password", b"some salt that is long", &cost, out_len).unwrap();
            let params = argon2::Params::new(memory_blocks, passes, lanes, Some(out_len)).unwrap();
            let library = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut theirs = vec![0u8; out_len];
            library.hash_password_into(b"a password", b"some salt that is long", &mut theirs).unwrap();
            assert_eq!(ours, theirs, "{lanes} lanes, {memory_blocks} blocks, {passes} passes, {out_len} bytes out");
        }
    }

    #[test]
    fn urbits_kind_is_its_own_and_costs_are_checked() {
        let cost = Cost { lanes: 4, memory_blocks: 256, passes: 1 };
        let urbit = hash(Kind::U, b"a password", b"some salt", &cost, 32).unwrap();
        assert_ne!(urbit, hash(Kind::Id, b"a password", b"some salt", &cost, 32).unwrap());
        // The same in gives the same out; anything different in gives something different out.
        assert_eq!(urbit, hash(Kind::U, b"a password", b"some salt", &cost, 32).unwrap());
        assert_ne!(urbit, hash(Kind::U, b"a passwore", b"some salt", &cost, 32).unwrap());
        assert_ne!(urbit, hash(Kind::U, b"a password", b"some salu", &cost, 32).unwrap());
        // Costs Argon2 does not allow.
        for (lanes, memory_blocks, passes, out_len) in [(0, 256, 1, 32), (4, 31, 1, 32), (4, 256, 0, 32), (4, 256, 1, 3)] {
            assert!(hash(Kind::U, b"a password", b"some salt", &Cost { lanes, memory_blocks, passes }, out_len).is_none());
        }
        assert!(hash(Kind::U, b"a password", b"short", &cost, 32).is_none());
        // Sizes past what this will do are refused before anything is set aside for them.
        assert!(hash(Kind::U, b"a password", b"some salt", &cost, usize::MAX).is_none());
        assert!(hash(Kind::U, b"a password", b"some salt", &cost, MOST_OUT + 1).is_none());
        assert!(hash(Kind::U, b"a password", b"some salt", &cost, MOST_OUT).is_some());
        assert!(hash(Kind::U, b"a password", b"some salt", &Cost { lanes: 1, memory_blocks: u32::MAX, passes: 1 }, 32).is_none());
        assert!(hash(Kind::U, b"a password", b"some salt", &Cost { lanes: MOST_LANES + 1, memory_blocks: MOST_BLOCKS, passes: 1 }, 32).is_none());
        assert!(hash(Kind::U, &vec![0; MOST_IN + 1], b"some salt", &cost, 32).is_none());
        assert!(hash(Kind::U, b"a password", &vec![0; MOST_IN + 1], &cost, 32).is_none());
    }
}
