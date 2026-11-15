//! Where a ship is: a small record, signed by the ship, of the addresses it can be reached at.
//!
//! Urbit ID says which key belongs to which ship. It does not say where the ship is, and
//! cannot: addresses change far more often than anything worth writing to Ethereum. So a ship
//! says where it is itself. It signs a record of its addresses, with the time it made the
//! record, using its networking key, and hands the record to the lookup point for its galaxy
//! (see `crate::lookup`). Whoever wants to call the ship asks the point, and checks the
//! signature against the key Urbit ID lists for the ship, just as it would check the ship
//! itself when it connects. So the point, or anyone in between, can keep a record back, or
//! hand out one that has not run out yet, but cannot make one up or change one.
//!
//! A record is good for ten minutes from the time it says it was signed, and a ship makes a
//! new one every two. A record dated more than two minutes ahead of this machine's clock is
//! not taken, so a ship cannot make one that lasts much longer by dating it ahead; one dated
//! up to two minutes ahead is good for up to twelve minutes from when it is taken. Between two good records for
//! one ship, the newer wins, and an older one is refused once a newer has been seen, until
//! the newer has run out, even if this clock has since stepped back behind it.
//!
//! What is signed is never the protobuf encoding. It is a fixed layout written out by hand
//! here: a label that says what it is, then every field at a fixed width in a fixed order. So
//! a record is checked against exactly the bytes its ship signed, and a signature on a record
//! can never be taken for a signature on anything else a ship signs, such as a log entry or a
//! moon's key. A moon's key and its parent's word for that key travel beside the record and
//! are not signed: the signature is checked with the key, and the word with the parent's key.
//!
//! A record decides only where a call is sent. Whatever answers there must still prove it
//! holds the ship's key, as on any connection, so a wrong address can lose a call but cannot
//! pass anyone off as the ship.
//!
//! `check` weighs a record by the clock it is given. Whoever keeps a record weighs its time
//! again with the clock read where it is kept, under the lock that guards what is kept.
//!
//! A record carries one more thing its ship says, under the same signature: whether callers
//! should ask the ship's lookup point to introduce them before they call. A ship behind a home
//! router sets it, since its router lets nothing in from an address it has not sent to first.
//! A point cannot set it or clear it.
//!
//! Presence. A record says where a ship is, and anyone can read one from a point and hand it
//! on. So when a ship gives its record to a point, it also signs, with the same key, a short
//! statement that names the ship, the record's time, and a value that both ends of that one
//! connection work out from its handshake and nobody else can (`presence`, `present`). The
//! point keeps a record only with that, so a record cannot be announced by anyone but its
//! ship, and the point knows which connection the ship itself is on. The value is TLS's
//! exporter for the connection: it comes from the secrets of that one handshake, which both
//! ends make afresh for every connection (nothing is resumed), so it is never the same on two
//! connections, and someone in the middle of two handshakes cannot make them agree on it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ship_proto::{Message, MoonProof, Whereabouts};
use urbit_id::ob;

use crate::moon;

/// What goes in front of what is signed, so that a signature on a record can never be taken
/// for a signature on anything else a ship signs.
const LABEL: &[u8] = b"ship.v1.where\n";

/// What goes in front of a ship's presence on a connection, so that it can never be taken for
/// anything else the ship signs.
const PRESENCE_LABEL: &[u8] = b"ship.v1.here\n";

/// What the value both ends of a connection work out from its handshake is asked for under.
pub(crate) const BINDING_LABEL: &[u8] = b"ship.v1.here";

/// The value both ends of one connection work out from its handshake, and nobody else can:
/// TLS's exporter for the connection, asked for under `ship.v1.here` with no context.
pub type Binding = [u8; 32];

/// The most addresses one record may name. A caller tries each, so this bounds how many
/// places a record can have callers send to.
pub const MOST_ADDRESSES: usize = 4;

/// How long a record is good for after it was made, in milliseconds. A ship makes a new one
/// every two minutes, so this leaves room for a few to go astray. It is also how long a point
/// can go on handing out a record after the ship has moved.
pub const LIFETIME_MS: u64 = 10 * 60 * 1000;

/// How far ahead of this machine's clock a record may say it was made, in milliseconds.
/// Clocks differ a little; past this, a record is taken to be dated ahead to last longer.
pub const MOST_AHEAD_MS: u64 = 2 * 60 * 1000;

/// The most an encoded record may come to. A real one, a moon's with four IPv6 addresses,
/// is under three hundred bytes.
pub const MOST_RECORD_BYTES: usize = 512;

/// How one address is written in the fixed layout: what kind it is (four or six, or nothing
/// for an empty slot), sixteen bytes of address (an IPv4 address in the first four, the rest
/// zeros), and the port.
const SLOT_BYTES: usize = 1 + 16 + 2;

/// The length of what is signed: the label, the ship, when it was made, whether callers should
/// be introduced, how many addresses, and a slot for each of the most there may be.
const STATEMENT_BYTES: usize = LABEL.len() + 8 + 8 + 1 + 1 + MOST_ADDRESSES * SLOT_BYTES;

/// What a record says, once it is believed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Believed {
    /// The ship, by name, without the `~`.
    pub ship: String,
    pub number: u64,
    pub addresses: Vec<SocketAddr>,
    /// When the ship made it, in milliseconds since 1970.
    pub issued: u64,
    /// For a moon: the revision of its parent's word, and the key that word was for.
    pub moon: Option<(u32, [u8; 32])>,
    /// For a moon: its parent's word itself, for whoever keeps the moon's keys to take in.
    pub proof: Option<moon::Proof>,
    /// The ship's word that callers should ask to be introduced before they call.
    pub introduce: bool,
    /// The key that signed it: the ship's own, or for a moon the key its parent vouched for.
    /// Its presence on a connection is checked against this.
    pub signer: [u8; 32],
}

/// What is already known of a ship, against which a new record of it is weighed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Known {
    /// When the newest record believed for the ship was made. It holds older records off
    /// until it has run out (see `holds_off`).
    pub issued: Option<u64>,
    /// For a moon: the latest revision of its parent's word seen for it, and the key that
    /// word was for.
    pub moon: Option<(u32, [u8; 32])>,
}

/// Whether a record made at `issued` is good at `now`, both in milliseconds since 1970: made
/// no more than `MOST_AHEAD_MS` ahead of now, and less than `LIFETIME_MS` ago. Nothing here
/// can overflow: a clock that is wrong makes records refused, never believed.
pub fn fresh(issued: u64, now: u64) -> bool {
    issued <= now.saturating_add(MOST_AHEAD_MS) && now.saturating_sub(issued) < LIFETIME_MS
}

/// Whether a record made at `seen`, already believed, still holds off records made no later
/// than it, at `now`: until it has run out. Whether it is dated ahead of this clock does not
/// matter here: a clock that has stepped back must make new records refused, never let an
/// older record take the place of a newer one.
pub fn holds_off(seen: u64, now: u64) -> bool {
    now.saturating_sub(seen) < LIFETIME_MS
}

/// The galaxy at the top of a ship's name: a planet's star's galaxy, a moon's parent's.
pub fn galaxy_of(number: u64) -> u8 {
    (number & 0xff) as u8
}

/// The name of a ship, without the `~`, if the number is one Urbit ID has a place for.
pub(crate) fn name_of(number: u64) -> Option<String> {
    let name = match u32::try_from(number) {
        Ok(ship) => ob::ship_name(ship),
        Err(_) => ob::moon_name(number)?,
    };
    Some(name.trim_start_matches('~').to_string())
}

/// Whether an address is one a ship could be reached at at all. An address that means "any",
/// a group of machines, everyone on the local network, or no port is not; nor is an IPv4
/// address written as IPv6, which would be the same address under a second name.
fn reachable(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && match addr.ip() {
            IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none(),
        }
}

/// Whether a list of addresses is one a record may carry: one to four, each reachable, no
/// two the same.
pub fn fits(addresses: &[SocketAddr]) -> Result<(), &'static str> {
    if addresses.is_empty() || addresses.len() > MOST_ADDRESSES {
        return Err("a record names one to four addresses");
    }
    if !addresses.iter().all(reachable) {
        return Err("a record names an address no ship could be reached at");
    }
    if addresses.iter().enumerate().any(|(n, addr)| addresses[..n].contains(addr)) {
        return Err("a record names the same address twice");
    }
    Ok(())
}

/// An address as it travels in a record.
pub(crate) fn address_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut bytes = match addr.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

/// An address as it travelled, if it is one.
pub(crate) fn address_read(bytes: &[u8]) -> Option<SocketAddr> {
    let port = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    match bytes.len() {
        6 => Some(SocketAddr::new(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into(), port(4))),
        18 => Some(SocketAddr::new(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).ok()?).into(), port(16))),
        _ => None,
    }
}

/// What a ship signs: the label, then its number, when it made the record, whether callers
/// should ask to be introduced (one byte, one or nought), how many addresses, and each address
/// in a slot of its own, with empty slots after.
fn statement(ship: u64, issued: u64, introduce: bool, addresses: &[SocketAddr]) -> [u8; STATEMENT_BYTES] {
    let mut out = [0u8; STATEMENT_BYTES];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(LABEL);
    put(&ship.to_be_bytes());
    put(&issued.to_be_bytes());
    put(&[u8::from(introduce)]);
    put(&[addresses.len().min(MOST_ADDRESSES) as u8]);
    for slot in 0..MOST_ADDRESSES {
        let mut written = [0u8; SLOT_BYTES];
        if let Some(addr) = addresses.get(slot) {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    written[0] = 4;
                    written[1..5].copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    written[0] = 6;
                    written[1..17].copy_from_slice(&ip.octets());
                }
            }
            written[17..].copy_from_slice(&addr.port().to_be_bytes());
        }
        put(&written);
    }
    out
}

/// A ship's record of where it is, signed with its networking key, as it travels. For a
/// moon, `proof` is its parent's word for the key, and is required; for any other ship it
/// must be absent. Callers are not asked to be introduced first (see `sign_flagged`).
pub fn sign(ship: &str, addresses: &[SocketAddr], issued: u64, key: &SigningKey, proof: Option<moon::Proof>) -> Result<Vec<u8>, String> {
    sign_flagged(ship, addresses, issued, false, key, proof)
}

/// The same, saying whether callers should ask the ship's lookup point to introduce them first.
pub fn sign_flagged(ship: &str, addresses: &[SocketAddr], issued: u64, introduce: bool, key: &SigningKey, proof: Option<moon::Proof>) -> Result<Vec<u8>, String> {
    let number = ob::any_number(ship).ok_or_else(|| format!("{ship} is not the name of a ship"))?;
    // Only the address and port go in a record: whatever else an IPv6 address carries is
    // left behind, so that what is signed is what is sent.
    let addresses: Vec<SocketAddr> = addresses.iter().map(|addr| SocketAddr::new(addr.ip(), addr.port())).collect();
    fits(&addresses).map_err(|why| format!("{ship}: {why}"))?;
    let (moon_key, proof) = match (number > u64::from(u32::MAX), proof) {
        (true, Some(proof)) => (key.verifying_key().to_bytes().to_vec(), Some(MoonProof { revision: proof.revision, signed: proof.signed.to_vec() })),
        (false, None) => (Vec::new(), None),
        (true, None) => return Err(format!("{ship} is a moon, and its record needs its parent's word for its key")),
        (false, Some(_)) => return Err(format!("{ship} is not a moon, and has no parent's word to show")),
    };
    let signature = key.sign(&statement(number, issued, introduce, &addresses)).to_bytes().to_vec();
    let record = Whereabouts { ship: number, addresses: addresses.iter().map(address_bytes).collect(), issued, moon_key, proof, signature, introduce };
    Ok(record.encode_to_vec())
}

/// What a ship signs to say it is on a connection: the label, then its number, the time of the
/// record it gives over that connection, and the value both ends work out from the
/// connection's handshake.
fn presence_statement(ship: u64, issued: u64, binding: &Binding) -> Vec<u8> {
    [PRESENCE_LABEL, &ship.to_be_bytes()[..], &issued.to_be_bytes()[..], &binding[..]].concat()
}

/// A ship's presence on a connection, for the record it made at `issued`, signed with the key
/// that signed the record.
pub fn presence(ship: u64, issued: u64, binding: &Binding, key: &SigningKey) -> Vec<u8> {
    key.sign(&presence_statement(ship, issued, binding)).to_bytes().to_vec()
}

/// Whether `signature` is the presence, on the connection `binding` stands for, of the ship
/// whose believed record this is: signed by the key that signed the record, over the record's
/// ship and time and this connection's value.
pub(crate) fn present(believed: &Believed, binding: &Binding, signature: &[u8]) -> Result<(), &'static str> {
    let signature = Signature::from_slice(signature).map_err(|_| "the record came without the ship's presence on this connection")?;
    let signer = VerifyingKey::from_bytes(&believed.signer).map_err(|_| "the key that signed is not a key")?;
    signer.verify_strict(&presence_statement(believed.number, believed.issued, binding), &signature).map_err(|_| "the ship's presence is not for this connection")
}

/// The ship a record is for, by number, if it is a record at all. Nothing is checked: this
/// is for deciding whom to weigh the record against before checking it.
pub fn ship_of(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > MOST_RECORD_BYTES {
        return None;
    }
    Whereabouts::decode(bytes).ok().map(|record| record.ship)
}

/// Check a record as it travelled, and what it says if it is believed. The one check, used by
/// lookup points and by ships that ask them, each with its own source of keys.
///
/// `key_of` gives the key Urbit ID lists for a galaxy, star or planet, by name: for a
/// moon it is asked about the moon's parent. `known` is what is already believed of the
/// ship. `now` is this machine's clock, in milliseconds since 1970.
///
/// A record is believed only if all of these hold:
/// - it is within size, and decoding it and encoding it again gives the same bytes, so that
///   nothing unknown, repeated, or padded is in it;
/// - it names a ship Urbit ID has a place for, and one to four addresses, each one a ship
///   could be reached at, no two the same;
/// - it was made no more than two minutes ahead of now and less than ten minutes ago;
/// - it is newer than the newest record already believed for the ship that has not yet run
///   out (whether or not that record is dated ahead of this clock);
/// - it is signed by the key Urbit ID lists for the ship, or for a moon, by the key in the
///   record, which its parent (by the key Urbit ID lists for the parent) vouches for, at no
///   earlier a revision than any already seen for the moon, and at the same revision only
///   for the same key. (What has been seen of a moon is for the caller to keep and give
///   here; at a ship it is the directory's one memory of the moon's keys.)
pub fn check(bytes: &[u8], key_of: &dyn Fn(&str) -> Option<[u8; 32]>, known: Known, now: u64) -> Result<Believed, &'static str> {
    if bytes.len() > MOST_RECORD_BYTES {
        return Err("the record is too large to be one");
    }
    let record = Whereabouts::decode(bytes).map_err(|_| "not a record")?;
    if record.encode_to_vec() != bytes {
        return Err("the record carries something it should not, or is not written the one way it can be");
    }
    let name = name_of(record.ship).ok_or("the record names no ship")?;
    let addresses: Vec<SocketAddr> = record.addresses.iter().map(|bytes| address_read(bytes)).collect::<Option<_>>().ok_or("the record names something that is not an address")?;
    fits(&addresses)?;
    if record.issued > now.saturating_add(MOST_AHEAD_MS) {
        return Err("the record says it was made later than now");
    }
    if now.saturating_sub(record.issued) >= LIFETIME_MS {
        return Err("the record has run out");
    }
    if known.issued.is_some_and(|seen| holds_off(seen, now) && record.issued <= seen) {
        return Err("a record of the ship as new or newer is already held");
    }
    let signature = Signature::from_slice(&record.signature).map_err(|_| "the record is not signed")?;
    let is_moon = record.ship > u64::from(u32::MAX);
    let (signer, moon) = if is_moon {
        let key: [u8; 32] = record.moon_key.as_slice().try_into().map_err(|_| "the moon's record does not carry its key")?;
        let proof = record.proof.as_ref().ok_or("the moon's record does not carry its parent's word for its key")?;
        let proof = moon::Proof { revision: proof.revision, signed: proof.signed.as_slice().try_into().map_err(|_| "the moon's parent's word is not the right shape")? };
        let parent = ob::ship_name(ob::moon_parent(record.ship));
        let parent_key = key_of(parent.trim_start_matches('~')).ok_or("no key is listed for the moon's parent")?;
        if !moon::holds(&parent_key, record.ship, &key, &proof) {
            return Err("the moon's parent has not given its word for the key that signed");
        }
        match known.moon {
            Some((seen, _)) if proof.revision < seen => return Err("a later revision of the moon's key has been seen"),
            Some((seen, seen_key)) if proof.revision == seen && seen_key != key => return Err("another key has been seen for the moon at this revision"),
            _ => {}
        }
        (key, Some((proof.revision, key, proof)))
    } else {
        if !record.moon_key.is_empty() || record.proof.is_some() {
            return Err("the record carries a moon's key for a ship that is not a moon");
        }
        (key_of(&name).ok_or("no key is listed for the ship")?, None)
    };
    let signed_by = signer;
    let signer = VerifyingKey::from_bytes(&signer).map_err(|_| "the key that signed is not a key")?;
    signer.verify_strict(&statement(record.ship, record.issued, record.introduce, &addresses), &signature).map_err(|_| "the record is not signed by the ship's key")?;
    Ok(Believed {
        ship: name,
        number: record.ship,
        addresses,
        issued: record.issued,
        moon: moon.map(|(revision, key, _)| (revision, key)),
        proof: moon.map(|(_, _, proof)| proof),
        introduce: record.introduce,
        signer: signed_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn planet() -> (u64, String) {
        let number = 0x4142_4344u64;
        (number, name_of(number).unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A source of keys that lists one ship's.
    fn listing(name: &str, key: &SigningKey) -> impl Fn(&str) -> Option<[u8; 32]> {
        let (name, public) = (name.to_string(), key.verifying_key().to_bytes());
        move |asked: &str| (asked == name).then_some(public)
    }

    /// Sign the fixed layout for any fields at all, even ones `sign` would refuse, and wrap
    /// them as a record.
    fn forged(ship: u64, addresses: &[Vec<u8>], issued: u64, signer: &SigningKey, read_as: &[SocketAddr]) -> Whereabouts {
        let signature = signer.sign(&statement(ship, issued, false, read_as)).to_bytes().to_vec();
        Whereabouts { ship, addresses: addresses.to_vec(), issued, moon_key: Vec::new(), proof: None, signature, introduce: false }
    }

    #[test]
    fn a_good_record_is_believed_and_says_what_was_signed() {
        let (number, name) = (planet().0, planet().1);
        let addresses = [at("203.0.113.7:4433"), at("[2001:db8::1]:4433")];
        let record = sign(&name, &addresses, NOW, &key(1), None).unwrap();
        let believed = check(&record, &listing(&name, &key(1)), Known::default(), NOW).unwrap();
        let signer = key(1).verifying_key().to_bytes();
        assert_eq!(believed, Believed { ship: name.clone(), number, addresses: addresses.to_vec(), issued: NOW, moon: None, proof: None, introduce: false, signer });
        assert_eq!(ship_of(&record), Some(number));
        assert!(record.len() < 300);
        // By another key, or with no key listed for the ship, it is not.
        assert_eq!(check(&record, &listing(&name, &key(2)), Known::default(), NOW), Err("the record is not signed by the ship's key"));
        assert_eq!(check(&record, &|_: &str| None, Known::default(), NOW), Err("no key is listed for the ship"));
        // What is signed has the label in front and is the same length whatever is in it.
        assert_eq!(&statement(number, NOW, false, &addresses)[..LABEL.len()], LABEL);
        assert_eq!(statement(number, NOW, false, &addresses[..1]).len(), STATEMENT_BYTES);
    }

    #[test]
    fn every_field_is_under_the_signature() {
        let (number, name) = planet();
        // The same key is listed for the next ship too, so that a record moved to that ship
        // fails on its signature, not for want of a key.
        let (one, other, public) = (name.clone(), name_of(number + 1).unwrap(), key(1).verifying_key().to_bytes());
        let keys = move |asked: &str| (asked == one || asked == other).then_some(public);
        let addresses = vec![at("203.0.113.7:4433"), at("[2001:db8::1]:4433")];
        let good = Whereabouts::decode(&*sign(&name, &addresses, NOW, &key(1), None).unwrap()).unwrap();
        let checked = |record: &Whereabouts| check(&record.encode_to_vec(), &keys, Known::default(), NOW);
        assert!(checked(&good).is_ok());
        assert_eq!(checked(&Whereabouts { ship: number + 1, ..good.clone() }), Err("the record is not signed by the ship's key"));
        // Another ship, another time, an address changed, its port changed, the order of the
        // addresses, one left out, one added.
        let changes: Vec<Box<dyn Fn(&mut Whereabouts)>> = vec![
            Box::new(|record| record.ship = number + 1),
            Box::new(|record| record.issued -= 1),
            Box::new(|record| record.addresses[0][3] ^= 1),
            Box::new(|record| record.addresses[1][17] ^= 1),
            Box::new(|record| record.addresses.swap(0, 1)),
            Box::new(|record| drop(record.addresses.pop())),
            Box::new(|record| record.addresses.push(address_bytes(&at("198.51.100.1:1")))),
            Box::new(|record| record.signature[5] ^= 1),
            // Whether callers should be introduced is under the signature too.
            Box::new(|record| record.introduce = !record.introduce),
        ];
        for (n, change) in changes.iter().enumerate() {
            let mut record = good.clone();
            change(&mut record);
            assert!(checked(&record).is_err(), "change {n} went unnoticed");
        }
        // The same fields signed without the label, or under another label, are not a record.
        let bare = key(1).sign(&statement(number, NOW, false, &addresses)[LABEL.len()..]).to_bytes().to_vec();
        assert!(checked(&Whereabouts { signature: bare, ..good.clone() }).is_err());
        let mut moon_label = statement(number, NOW, false, &addresses);
        moon_label[..LABEL.len()].copy_from_slice(b"ship.v1.moon\n\n");
        assert!(checked(&Whereabouts { signature: key(1).sign(&moon_label).to_bytes().to_vec(), ..good.clone() }).is_err());
        // Each slot is written at its place: an address moved to another slot is another
        // statement.
        let one = [at("203.0.113.7:4433")];
        assert_ne!(statement(number, NOW, false, &one), statement(number, NOW, false, &[at("203.0.113.7:4434")]));
        assert_ne!(statement(number, NOW, false, &addresses), statement(number, NOW, false, &[addresses[1], addresses[0]]));
        assert_ne!(statement(number, NOW, false, &one), statement(number, NOW, true, &one));
    }

    #[test]
    fn whether_callers_are_to_be_introduced_is_the_ships_own_word() {
        let (number, name) = planet();
        let keys = listing(&name, &key(1));
        let addresses = [at("203.0.113.7:4433")];
        // Signed with the flag, a record says so, and without, it does not.
        let flagged = sign_flagged(&name, &addresses, NOW, true, &key(1), None).unwrap();
        assert!(check(&flagged, &keys, Known::default(), NOW).unwrap().introduce);
        assert!(!check(&sign(&name, &addresses, NOW, &key(1), None).unwrap(), &keys, Known::default(), NOW).unwrap().introduce);
        // Whoever passes the record on cannot clear it, or set it on a record without it.
        let mut cleared = Whereabouts::decode(&*flagged).unwrap();
        cleared.introduce = false;
        assert_eq!(check(&cleared.encode_to_vec(), &keys, Known::default(), NOW), Err("the record is not signed by the ship's key"));
        let mut set = Whereabouts::decode(&*sign(&name, &addresses, NOW, &key(1), None).unwrap()).unwrap();
        set.introduce = true;
        assert_eq!(check(&set.encode_to_vec(), &keys, Known::default(), NOW), Err("the record is not signed by the ship's key"));
        // The flag is written one way only: as one, when set.
        let mut twice = flagged.clone();
        let at = twice.len() - 1;
        assert_eq!(&twice[at - 1..], &[0x38, 0x01]);
        twice[at] = 0x02;
        assert!(Whereabouts::decode(&*twice).unwrap().introduce);
        assert!(check(&twice, &keys, Known::default(), NOW).is_err());
        let _ = number;
    }

    #[test]
    fn a_ships_presence_is_for_one_ship_one_record_one_connection_and_one_key() {
        let (number, name) = planet();
        let keys = listing(&name, &key(1));
        let record = sign(&name, &[at("203.0.113.7:4433")], NOW, &key(1), None).unwrap();
        let believed = check(&record, &keys, Known::default(), NOW).unwrap();
        let (here, there) = ([7u8; 32], [8u8; 32]);
        assert_eq!(present(&believed, &here, &presence(number, NOW, &here, &key(1))), Ok(()));
        // Made for another connection, another ship, another time, by another key; nothing.
        let not = Err("the ship's presence is not for this connection");
        assert_eq!(present(&believed, &here, &presence(number, NOW, &there, &key(1))), not);
        assert_eq!(present(&believed, &here, &presence(number + 1, NOW, &here, &key(1))), not);
        assert_eq!(present(&believed, &here, &presence(number, NOW + 1, &here, &key(1))), not);
        assert_eq!(present(&believed, &here, &presence(number, NOW, &here, &key(2))), not);
        assert_eq!(present(&believed, &here, &[]), Err("the record came without the ship's presence on this connection"));
        // A record's own signature is not a presence, nor the other way round.
        let signature = Whereabouts::decode(&*record).unwrap().signature;
        assert_eq!(present(&believed, &here, &signature), not);
        // A moon's presence is by the key its record carries, which its parent vouched for.
        let moon = 7u64 << 32 | number;
        let moon_key = key(5);
        let word = moon::vouch(&key(1), moon, 1, &moon_key.verifying_key().to_bytes());
        let moons = check(&sign(&name_of(moon).unwrap(), &[at("203.0.113.7:4433")], NOW, &moon_key, Some(word)).unwrap(), &keys, Known::default(), NOW).unwrap();
        assert_eq!(moons.signer, moon_key.verifying_key().to_bytes());
        assert_eq!(present(&moons, &here, &presence(moon, NOW, &here, &moon_key)), Ok(()));
        assert_eq!(present(&moons, &here, &presence(moon, NOW, &here, &key(1))), not);
        // What is signed has its own label in front, and nothing else a ship signs has it.
        assert_eq!(&presence_statement(number, NOW, &here)[..PRESENCE_LABEL.len()], PRESENCE_LABEL);
        assert_ne!(PRESENCE_LABEL, LABEL);
    }

    #[test]
    fn times_are_held_to_the_clock_at_both_ends() {
        let (_, name) = planet();
        let keys = listing(&name, &key(1));
        let made = |issued: u64| sign(&name, &[at("203.0.113.7:4433")], issued, &key(1), None).unwrap();
        let checked = |issued: u64, now: u64| check(&made(issued), &keys, Known::default(), now);
        // Up to two minutes ahead, and not a moment more.
        assert!(checked(NOW + MOST_AHEAD_MS, NOW).is_ok());
        assert_eq!(checked(NOW + MOST_AHEAD_MS + 1, NOW), Err("the record says it was made later than now"));
        // Good for less than ten minutes.
        assert!(checked(NOW - LIFETIME_MS + 1, NOW).is_ok());
        assert_eq!(checked(NOW - LIFETIME_MS, NOW), Err("the record has run out"));
        // A clock that is wrong refuses records, whichever way it is wrong, and nothing
        // overflows at the ends of the range.
        assert!(checked(NOW, 0).is_err());
        assert!(checked(NOW, u64::MAX).is_err());
        assert!(checked(u64::MAX, NOW).is_err());
        assert!(checked(u64::MAX, u64::MAX).is_ok());
        assert!(checked(0, 0).is_ok());
        assert!(!fresh(u64::MAX, 0) && fresh(u64::MAX, u64::MAX) && !fresh(0, u64::MAX));
    }

    #[test]
    fn only_a_newer_record_takes_the_place_of_one_still_good() {
        let (_, name) = planet();
        let keys = listing(&name, &key(1));
        let made = |issued: u64| sign(&name, &[at("203.0.113.7:4433")], issued, &key(1), None).unwrap();
        let seen = Known { issued: Some(NOW), moon: None };
        assert!(check(&made(NOW + 1), &keys, seen, NOW).is_ok());
        assert_eq!(check(&made(NOW), &keys, seen, NOW), Err("a record of the ship as new or newer is already held"));
        assert!(check(&made(NOW - 1), &keys, seen, NOW).is_err());
        // One that has run out holds nothing off: an older record still good is taken.
        let gone = Known { issued: Some(NOW - LIFETIME_MS), moon: None };
        assert!(check(&made(NOW - LIFETIME_MS + 5), &keys, gone, NOW).is_ok());
        // A record held that is dated ahead of a clock that has since stepped back still
        // holds older ones off: the clock going back never lets an older record in.
        let ahead = Known { issued: Some(NOW + LIFETIME_MS), moon: None };
        assert_eq!(check(&made(NOW), &keys, ahead, NOW), Err("a record of the ship as new or newer is already held"));
        assert!(holds_off(u64::MAX, 0) && !holds_off(0, u64::MAX) && holds_off(NOW, NOW + LIFETIME_MS - 1));
    }

    #[test]
    fn a_moons_record_stands_on_its_parents_word() {
        let (planet_number, planet_name) = planet();
        let moon = 7u64 << 32 | planet_number;
        let moon_name = name_of(moon).unwrap();
        let (parent, moon_key, other) = (key(1), key(5), key(6));
        let keys = listing(&planet_name, &parent);
        let word = |revision: u32, key: &SigningKey| moon::vouch(&parent, moon, revision, &key.verifying_key().to_bytes());
        let made = |signer: &SigningKey, proof: moon::Proof| sign(&moon_name, &[at("203.0.113.7:4433")], NOW, signer, Some(proof)).unwrap();
        let believed = check(&made(&moon_key, word(3, &moon_key)), &keys, Known::default(), NOW).unwrap();
        assert_eq!(believed.moon, Some((3, moon_key.verifying_key().to_bytes())));
        assert_eq!(believed.ship, moon_name);
        assert_eq!(galaxy_of(moon), galaxy_of(planet_number));
        // The parent's word for another key, or for another moon.
        assert!(check(&made(&moon_key, word(3, &other)), &keys, Known::default(), NOW).is_err());
        let elsewhere = moon::vouch(&parent, moon + (1 << 32), 3, &moon_key.verifying_key().to_bytes());
        assert!(check(&made(&moon_key, elsewhere), &keys, Known::default(), NOW).is_err());
        // Signed by a key the parent did vouch for, but carrying another: the key carried is
        // the one the signature is checked with.
        let mut swapped = Whereabouts::decode(&*made(&moon_key, word(3, &moon_key))).unwrap();
        swapped.moon_key = other.verifying_key().to_bytes().to_vec();
        swapped.proof = Some(MoonProof { revision: 3, signed: word(3, &other).signed.to_vec() });
        assert!(check(&swapped.encode_to_vec(), &keys, Known::default(), NOW).is_err());
        // A parent not listed, or listed with another key.
        assert!(check(&made(&moon_key, word(3, &moon_key)), &listing(&planet_name, &other), Known::default(), NOW).is_err());
        // An earlier revision than one seen, and another key at the revision seen.
        let seen = Known { issued: None, moon: Some((4, other.verifying_key().to_bytes())) };
        assert_eq!(check(&made(&moon_key, word(3, &moon_key)), &keys, seen, NOW), Err("a later revision of the moon's key has been seen"));
        assert_eq!(check(&made(&moon_key, word(4, &moon_key)), &keys, seen, NOW), Err("another key has been seen for the moon at this revision"));
        assert!(check(&made(&moon_key, word(5, &moon_key)), &keys, seen, NOW).is_ok());
        assert!(check(&made(&other, word(4, &other)), &keys, seen, NOW).is_ok());
        // A moon's record without its key or its parent's word.
        let mut bare = Whereabouts::decode(&*made(&moon_key, word(3, &moon_key))).unwrap();
        bare.proof = None;
        assert!(check(&bare.encode_to_vec(), &keys, Known::default(), NOW).is_err());
        bare.moon_key.clear();
        assert!(check(&bare.encode_to_vec(), &keys, Known::default(), NOW).is_err());
        // And a planet's record carrying a moon's word.
        let mut planets = Whereabouts::decode(&*sign(&planet_name, &[at("203.0.113.7:4433")], NOW, &parent, None).unwrap()).unwrap();
        planets.moon_key = moon_key.verifying_key().to_bytes().to_vec();
        assert!(check(&planets.encode_to_vec(), &keys, Known::default(), NOW).is_err());
        assert!(sign(&planet_name, &[at("203.0.113.7:4433")], NOW, &parent, Some(word(1, &parent))).is_err());
        assert!(sign(&moon_name, &[at("203.0.113.7:4433")], NOW, &moon_key, None).is_err());
    }

    #[test]
    fn a_record_names_one_to_four_addresses_a_ship_could_have() {
        let (number, name) = planet();
        let keys = listing(&name, &key(1));
        let checked = |addresses: &[SocketAddr]| {
            let record = forged(number, &addresses.iter().map(address_bytes).collect::<Vec<_>>(), NOW, &key(1), addresses);
            check(&record.encode_to_vec(), &keys, Known::default(), NOW)
        };
        let four: Vec<SocketAddr> = (1..=4).map(|n| at(&format!("203.0.113.{n}:4433"))).collect();
        assert!(checked(&four).is_ok());
        assert!(sign(&name, &four, NOW, &key(1), None).is_ok());
        let five: Vec<SocketAddr> = (1..=5).map(|n| at(&format!("203.0.113.{n}:4433"))).collect();
        assert_eq!(checked(&five), Err("a record names one to four addresses"));
        assert_eq!(checked(&[]), Err("a record names one to four addresses"));
        assert!(sign(&name, &five, NOW, &key(1), None).is_err());
        assert!(sign(&name, &[], NOW, &key(1), None).is_err());
        for bad in ["0.0.0.0:4433", "[::]:4433", "224.0.0.1:4433", "[ff02::1]:4433", "255.255.255.255:4433", "203.0.113.7:0", "[::ffff:203.0.113.7]:4433"] {
            assert_eq!(checked(&[at(bad)]), Err("a record names an address no ship could be reached at"), "{bad}");
            assert!(sign(&name, &[at(bad)], NOW, &key(1), None).is_err(), "{bad}");
        }
        assert_eq!(checked(&[four[0], four[1], four[0]]), Err("a record names the same address twice"));
        // Something that is not an address, signed as if it were.
        let odd = forged(number, &[vec![1, 2, 3, 4, 5]], NOW, &key(1), &[]);
        assert_eq!(check(&odd.encode_to_vec(), &keys, Known::default(), NOW), Err("the record names something that is not an address"));
    }

    #[test]
    fn a_record_is_written_one_way_and_carries_nothing_else() {
        let (_, name) = planet();
        let keys = listing(&name, &key(1));
        let record = sign(&name, &[at("203.0.113.7:4433")], NOW, &key(1), None).unwrap();
        // A field this runtime does not know, padding at the end, a field given twice: each
        // decodes to the same record, and none is taken.
        let unknown = [record.clone(), vec![0x78, 0x05]].concat();
        let twice = [record.clone(), vec![0x18, 0x01]].concat();
        let longer = {
            // The ship's number written with a byte more than it needs.
            let mut bytes = record.clone();
            let at = bytes.iter().position(|&b| b == 0x08).unwrap();
            let end = at + 1 + bytes[at + 1..].iter().position(|&b| b & 0x80 == 0).unwrap();
            bytes[end] |= 0x80;
            bytes.insert(end + 1, 0x00);
            bytes
        };
        for (what, bytes) in [("unknown", &unknown), ("twice", &twice), ("longer", &longer)] {
            assert!(Whereabouts::decode(&**bytes).is_ok(), "{what}");
            assert!(check(bytes, &keys, Known::default(), NOW).is_err(), "{what}");
        }
        // Rubbish, and too much of it.
        assert_eq!(check(&[0xff; 40], &keys, Known::default(), NOW), Err("not a record"));
        assert_eq!(check(&vec![0; MOST_RECORD_BYTES + 1], &keys, Known::default(), NOW), Err("the record is too large to be one"));
        assert_eq!(ship_of(&vec![0; MOST_RECORD_BYTES + 1]), None);
        // Every number past a planet's is a moon's, and is held to a moon's rules: a record
        // for one with no moon's key is not taken, however it is signed.
        let moonish = forged(u64::MAX, &[address_bytes(&at("203.0.113.7:4433"))], NOW, &key(1), &[at("203.0.113.7:4433")]);
        assert_eq!(check(&moonish.encode_to_vec(), &keys, Known::default(), NOW), Err("the moon's record does not carry its key"));
    }
}
