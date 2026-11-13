//! Azimuth's state, worked out from what was written to Ethereum, the way Urbit works it out.
//!
//! Azimuth is a contract on Ethereum that lists every galaxy, star and planet: who owns it,
//! who may act for it, its networking keys, and its sponsor. Changes made there directly
//! ("layer 1") are announced by the contract as logs. Most planets are changed somewhere
//! cheaper ("layer 2"): their owners sign small transactions, and a service, the roller,
//! packs many of them into one Ethereum transaction, a batch, sent to a contract that does
//! nothing but note that it was sent. Ethereum never checks what is in a batch. Everyone who
//! wants to know the state of layer 2 reads every batch and checks every signature in it
//! for themselves, under the same rules.
//!
//! Those rules are Urbit's `naive.hoon`, and this file is a port of it. Where this file and
//! `naive.hoon` could be read to disagree, `naive.hoon` is right. Its names are kept in the
//! comments, so that each rule here can be found there.
//!
//! The state is a table of points, one per ship. A ship that has never been written to the
//! table still has a point, worked out from the ship above it ([`point_of`]). Two inputs
//! change the table, and they must be given in the order Ethereum has them, layer 1 logs and
//! layer 2 batches interleaved, because a layer 2 transaction is judged by what layer 1 said
//! at that moment:
//!
//! - [`receive_log`]: one log from the Azimuth contract.
//! - [`receive_batch`]: one batch, which is the whole input of the Ethereum transaction that
//!   was sent to the layer 2 contract.
//!
//! Nothing here reads or writes anything but the table it is given ([`Points`]).

use std::collections::HashMap;
use std::sync::OnceLock;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// An Ethereum address.
pub type Address = [u8; 20];

/// The address that owns, on Ethereum, every ship that has been moved to layer 2. Nobody
/// holds its key. Giving a ship to it, or giving it a star's right to make ships, is how a
/// ship or its children move to layer 2, for good. (`deposit-address`)
pub const DEPOSIT: Address = [0x11; 20];

/// Where a ship is kept. (`dominion`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dominion {
    /// On Ethereum, in the Azimuth contract itself. (`%l1`)
    L1,
    /// On layer 2. (`%l2`)
    L2,
    /// On Ethereum, but it makes its ships on layer 2. Only a galaxy or a star can be here.
    /// (`%spawn`)
    Spawn,
}

/// Someone who may sign for a ship in one role, and how many of their transactions on
/// layer 2 have been counted. The count is part of what is signed, so that a transaction
/// cannot be sent twice. (`[=address =nonce]`)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Holder {
    pub address: Address,
    /// Urbit's nonce. Only its low 32 bits are ever signed, so it is kept in 32 bits, and
    /// would go round to zero after four billion transactions.
    pub nonce: u32,
}

/// A ship's networking keys. (`keys`)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetKeys {
    /// How many times the keys have been set, taking them away included. (`life`)
    pub revision: u32,
    /// What kind of keys they are. 1 is the only kind in use. (`suite`)
    pub suite: u32,
    /// The authentication key, as Azimuth keeps it: a number, here written as 32 bytes
    /// with the most significant first. That is the ed25519 key's bytes reversed. (`auth`)
    pub authentication: [u8; 32],
    /// The encryption key, kept the same way. (`crypt`)
    pub encryption: [u8; 32],
}

/// Everything Azimuth's state has for one ship. (`point`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub dominion: Dominion,
    /// Who owns it, and the four who may act for it in narrower ways: make its children
    /// (spawn), set its keys and its sponsor (management), vote (voting, a galaxy's), and
    /// give it to someone else (transfer).
    pub owner: Holder,
    pub spawn_proxy: Holder,
    pub management_proxy: Holder,
    pub voting_proxy: Holder,
    pub transfer_proxy: Holder,
    /// How many times the ship has started afresh, forgetting what it knew. (`rift`)
    pub continuity: u32,
    pub keys: NetKeys,
    /// Whether the ship has a sponsor, and which ship is or was its sponsor. The second is
    /// kept when the first is lost, and some rules look at it. (`sponsor=[has who]`)
    pub has_sponsor: bool,
    pub sponsor: u32,
    /// The ship it has asked to have as its sponsor instead, if it has asked. (`escape`)
    pub escape: Option<u32>,
}

impl Point {
    fn holder(&self, proxy: Proxy) -> &Holder {
        match proxy {
            Proxy::Owner => &self.owner,
            Proxy::Spawn => &self.spawn_proxy,
            Proxy::Management => &self.management_proxy,
            Proxy::Voting => &self.voting_proxy,
            Proxy::Transfer => &self.transfer_proxy,
        }
    }

    fn holder_mut(&mut self, proxy: Proxy) -> &mut Holder {
        match proxy {
            Proxy::Owner => &mut self.owner,
            Proxy::Spawn => &mut self.spawn_proxy,
            Proxy::Management => &mut self.management_proxy,
            Proxy::Voting => &mut self.voting_proxy,
            Proxy::Transfer => &mut self.transfer_proxy,
        }
    }
}

/// The table of points: where the state is kept. A `HashMap` in tests, a database in use.
///
/// Whether a ship is in the table matters, and is not the same as what [`point_of`] says
/// of it: a layer 2 spawn is refused for a ship that is in the table.
pub trait Points {
    /// The ship's point, if it has ever been written to the table.
    fn get(&self, ship: u32) -> Result<Option<Point>, String>;
    fn put(&mut self, ship: u32, point: &Point) -> Result<(), String>;
}

impl Points for HashMap<u32, Point> {
    fn get(&self, ship: u32) -> Result<Option<Point>, String> {
        Ok(HashMap::get(self, &ship).copied())
    }

    fn put(&mut self, ship: u32, point: &Point) -> Result<(), String> {
        self.insert(ship, *point);
        Ok(())
    }
}

/// 0 for a galaxy, 1 for a star, 2 for a planet. (`ship-rank`; a ship's number here is 32
/// bits, so the higher ranks, moons and comets, cannot occur.)
pub fn rank(ship: u32) -> u8 {
    match ship {
        0..=0xff => 0,
        0x100..=0xffff => 1,
        _ => 2,
    }
}

/// The ship above this one: a star's galaxy, a planet's star. A galaxy is its own. A
/// planet's number has the ship above it in its low sixteen bits, which can be a galaxy's
/// number. (`sein`)
pub fn parent(ship: u32) -> u32 {
    match rank(ship) {
        0 => ship,
        1 => ship & 0xff,
        _ => ship & 0xffff,
    }
}

/// The ship's point: what the table has, or, for a ship never written to it, what it would
/// start as. That has the ship above it as its sponsor, and is kept where the ship above it
/// makes its ships: on layer 1 under a ship on layer 1, otherwise on layer 2. A galaxy
/// starts on layer 1. Everything else is zero. (`get-point`)
pub fn point_of(points: &impl Points, ship: u32) -> Result<Point, String> {
    if let Some(point) = points.get(ship)? {
        return Ok(point);
    }
    let dominion = match rank(ship) {
        0 => Dominion::L1,
        _ => match point_of(points, parent(ship))?.dominion {
            Dominion::L1 => Dominion::L1,
            Dominion::L2 | Dominion::Spawn => Dominion::L2,
        },
    };
    Ok(Point {
        dominion,
        owner: Holder::default(),
        spawn_proxy: Holder::default(),
        management_proxy: Holder::default(),
        voting_proxy: Holder::default(),
        transfer_proxy: Holder::default(),
        continuity: 0,
        keys: NetKeys::default(),
        // Hoon's default for a yes-or-no is yes.
        has_sponsor: true,
        sponsor: parent(ship),
        escape: None,
    })
}

/// The first topic of each kind of log the Azimuth contract writes: the Keccak-256 hash of
/// the event's name and arguments. (`log-names`)
struct Topics {
    owner_changed: [u8; 32],
    activated: [u8; 32],
    spawned: [u8; 32],
    ownership_transferred: [u8; 32],
    escape_requested: [u8; 32],
    escape_canceled: [u8; 32],
    escape_accepted: [u8; 32],
    lost_sponsor: [u8; 32],
    changed_keys: [u8; 32],
    broke_continuity: [u8; 32],
    changed_spawn_proxy: [u8; 32],
    changed_transfer_proxy: [u8; 32],
    changed_management_proxy: [u8; 32],
    changed_voting_proxy: [u8; 32],
    changed_dns: [u8; 32],
    approval_for_all: [u8; 32],
}

fn topics() -> &'static Topics {
    static TOPICS: OnceLock<Topics> = OnceLock::new();
    TOPICS.get_or_init(|| Topics {
        owner_changed: keccak(b"OwnerChanged(uint32,address)"),
        activated: keccak(b"Activated(uint32)"),
        spawned: keccak(b"Spawned(uint32,uint32)"),
        ownership_transferred: keccak(b"OwnershipTransferred(address,address)"),
        escape_requested: keccak(b"EscapeRequested(uint32,uint32)"),
        escape_canceled: keccak(b"EscapeCanceled(uint32,uint32)"),
        escape_accepted: keccak(b"EscapeAccepted(uint32,uint32)"),
        lost_sponsor: keccak(b"LostSponsor(uint32,uint32)"),
        changed_keys: keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)"),
        broke_continuity: keccak(b"BrokeContinuity(uint32,uint32)"),
        changed_spawn_proxy: keccak(b"ChangedSpawnProxy(uint32,address)"),
        changed_transfer_proxy: keccak(b"ChangedTransferProxy(uint32,address)"),
        changed_management_proxy: keccak(b"ChangedManagementProxy(uint32,address)"),
        changed_voting_proxy: keccak(b"ChangedVotingProxy(uint32,address)"),
        changed_dns: keccak(b"ChangedDns(string,string,string)"),
        approval_for_all: keccak(b"ApprovalForAll(address,address,bool)"),
    })
}

/// The first topic of the log the layer 2 contract writes for each batch it is sent.
pub fn batch_topic() -> [u8; 32] {
    keccak(b"Batch()")
}

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// A word of a log read as a number that must fit in 32 bits, as a ship's number must.
/// `None` if it does not.
fn small(word: &[u8; 32]) -> Option<u32> {
    (word[..28] == [0; 28]).then(|| u32::from_be_bytes([word[28], word[29], word[30], word[31]]))
}

/// A word of a log read as an address: twelve zeros, then twenty bytes.
fn address(word: &[u8; 32]) -> Result<Address, String> {
    if word[..12] != [0; 12] {
        return Err("a log's address is longer than an address".into());
    }
    let mut out = [0; 20];
    out.copy_from_slice(&word[12..]);
    Ok(out)
}

/// The `at`th word of 32 bytes counting from the end of a log's data, which is how
/// `naive.hoon` reads it (as one number, from its low end). A word before the start of the
/// data is zeros.
fn word_from_end(data: &[u8], at: usize) -> [u8; 32] {
    let mut word = [0; 32];
    for (i, byte) in word.iter_mut().enumerate() {
        let back = 32 * at + (32 - i);
        if back <= data.len() {
            *byte = data[data.len() - back];
        }
    }
    word
}

/// Apply one log from the Azimuth contract. (`receive-log`)
///
/// Where `naive.hoon` would stop on a log that is not shaped as the contract makes it (a
/// missing topic, a ship's number that is not 32 bits), this returns `Err` and changes
/// nothing: such a log did not come from the contract.
pub fn receive_log(points: &mut impl Points, topics: &[[u8; 32]], data: &[u8]) -> Result<(), String> {
    let known = self::topics();
    let name = topics.first().ok_or("a log with no topics")?;
    if [known.activated, known.spawned, known.ownership_transferred].contains(name) {
        return Ok(());
    }
    // Two more kinds that `naive.hoon` keeps, and that say nothing about any ship: the
    // contract's domain names, and who may act for whom across all their ships (an
    // "operator"). Nothing that looks up a ship's keys needs them, so they are skipped.
    if [known.changed_dns, known.approval_for_all].contains(name) {
        return Ok(());
    }
    // Every other kind is about one ship, the second topic.
    let ship = topics.get(1).ok_or("a log about a ship that does not say which")?;
    let ship = small(ship).ok_or("a log about a ship whose number is too big to be one")?;
    let point = point_of(points, ship)?;
    // Whatever a log does is done to the point whole, and put back only if it did
    // something, so that a log that does nothing does not add the ship to the table.
    let changed = change(points, &point, topics, data)?;
    if let Some(changed) = changed {
        points.put(ship, &changed)?;
    }
    Ok(())
}

fn change(points: &impl Points, point: &Point, topics: &[[u8; 32]], data: &[u8]) -> Result<Option<Point>, String> {
    let known = self::topics();
    let name = &topics[0];
    // The topic after the ship, for the kinds that have exactly one.
    let third = || match topics {
        [_, _, third] => Ok(third),
        _ => Err("a log with the wrong number of topics".to_string()),
    };
    let no_third = || match topics {
        [_, _] => Ok(()),
        _ => Err("a log with the wrong number of topics".to_string()),
    };
    // A ship named in a third topic, which must be one that can have a point.
    let other_ship = |word: &[u8; 32]| small(word).ok_or("a log names a ship whose number is too big to be one".to_string());
    let mut point = *point;

    if *name == known.changed_spawn_proxy {
        // Only a ship on layer 1 can change this on layer 1.
        if point.dominion != Dominion::L1 {
            return Ok(None);
        }
        let to = address(third()?)?;
        // Giving the right to make ships to the deposit address is how a ship moves its
        // children to layer 2. It is not a spawn proxy anyone holds.
        if to == DEPOSIT {
            point.dominion = Dominion::Spawn;
        } else {
            point.spawn_proxy.address = to;
        }
        return Ok(Some(point));
    }

    // These two are about a ship's sponsor, and still reach a ship that is on layer 2, as
    // long as the sponsor is not.
    if *name == known.escape_accepted {
        let sponsor = other_ship(third()?)?;
        if point_of(points, sponsor)?.dominion == Dominion::L2 {
            return Ok(None);
        }
        point.escape = None;
        point.has_sponsor = true;
        point.sponsor = sponsor;
        return Ok(Some(point));
    }
    if *name == known.lost_sponsor {
        // Losing a sponsor that was not the ship's sponsor loses nothing. A number too big
        // to be a ship's is not its sponsor either.
        if small(third()?) != Some(point.sponsor) {
            return Ok(None);
        }
        if point_of(points, point.sponsor)?.dominion == Dominion::L2 {
            return Ok(None);
        }
        point.has_sponsor = false;
        return Ok(Some(point));
    }

    // Everything else is done on layer 1 only by a ship that is there. A ship whose
    // children are made on layer 2 is still there itself.
    if point.dominion == Dominion::L2 {
        return Ok(None);
    }

    if *name == known.escape_requested {
        point.escape = Some(other_ship(third()?)?);
    } else if *name == known.escape_canceled {
        other_ship(third()?)?;
        point.escape = None;
    } else if *name == known.broke_continuity {
        no_third()?;
        // The data is the new count, as one number.
        let count = data.iter().rev().skip(4).all(|byte| *byte == 0).then(|| word_from_end(data, 0));
        point.continuity = count.as_ref().and_then(small).ok_or("a count of new starts too big to be one")?;
    } else if *name == known.changed_keys {
        no_third()?;
        // From the end of the data: the revision, the kind, the authentication key, the
        // encryption key. (The contract writes them in the opposite order.)
        let revision = small(&word_from_end(data, 0)).ok_or("a key revision too big to be one")?;
        let suite = small(&word_from_end(data, 1)).ok_or("a kind of key too big to be one")?;
        point.keys = NetKeys { revision, suite, authentication: word_from_end(data, 2), encryption: word_from_end(data, 3) };
    } else if *name == known.owner_changed {
        let to = address(third()?)?;
        // Giving a ship to the deposit address moves it to layer 2. Its owner there is
        // whoever owned it on layer 1.
        if to == DEPOSIT {
            point.dominion = Dominion::L2;
        } else {
            point.owner.address = to;
        }
    } else if *name == known.changed_transfer_proxy {
        point.transfer_proxy.address = address(third()?)?;
    } else if *name == known.changed_management_proxy {
        point.management_proxy.address = address(third()?)?;
    } else if *name == known.changed_voting_proxy {
        point.voting_proxy.address = address(third()?)?;
    } else {
        // A kind of log `naive.hoon` does not know. It changes nothing.
        return Ok(None);
    }
    Ok(Some(point))
}

/// In what role a layer 2 transaction is signed. (`proxy`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proxy {
    Owner,
    Spawn,
    Management,
    Voting,
    Transfer,
}

/// What a layer 2 transaction asks for. (`skim-tx`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Give the ship to `to`. With `reset`, also take away its keys and proxies, as for a
    /// new owner who should start afresh.
    TransferPoint { to: Address, reset: bool },
    /// Make a child of the ship, for `to`.
    Spawn { ship: u32, to: Address },
    /// Set the ship's networking keys. With `breach`, it also starts afresh.
    ConfigureKeys { encryption: [u8; 32], authentication: [u8; 32], suite: u32, breach: bool },
    /// Ask this ship to be the ship's sponsor.
    Escape(u32),
    CancelEscape(u32),
    /// Become the sponsor of this ship, which asked. (Sent by the sponsor.)
    Adopt(u32),
    /// Refuse to be the sponsor of this ship, which asked. (Sent by the sponsor.)
    Reject(u32),
    /// Stop being the sponsor of this ship. (Sent by the sponsor.)
    Detach(u32),
    SetManagementProxy(Address),
    SetSpawnProxy(Address),
    SetTransferProxy(Address),
}

/// One layer 2 transaction, as it was found in a batch. (`raw-tx`)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// The signature, in the order it is written: r, s, then v.
    pub signature: [u8; 65],
    /// Everything else, in the order it is written. Bytes that were missing at the front
    /// of the batch are here as zeros.
    pub raw: Vec<u8>,
    /// The ship it is sent as, and in what role.
    pub ship: u32,
    pub proxy: Proxy,
    pub action: Action,
}

/// Reads a batch from its end towards its start, which is the order `naive.hoon` reads it
/// in: it takes the batch as one number and reads that from its low end. Past the start,
/// what is read is zeros, as the high end of a number is.
struct Backwards<'a> {
    bytes: &'a [u8],
    /// How many bytes have been read, counting back from the end. It can pass the start.
    taken: usize,
}

impl Backwards<'_> {
    /// The next `N` bytes back, in the order they are written.
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.taken += N;
        for (i, byte) in out.iter_mut().enumerate() {
            // How far from the end this byte is, counting the last as 1.
            let back = self.taken - i;
            if back <= self.bytes.len() {
                *byte = self.bytes[self.bytes.len() - back];
            }
        }
        out
    }

    fn ship(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    /// The bytes read since `then`, in the order they are written, zeros for any before
    /// the start.
    fn since(&self, then: usize) -> Vec<u8> {
        (0..self.taken - then).map(|i| self.taken - i).map(|back| if back <= self.bytes.len() { self.bytes[self.bytes.len() - back] } else { 0 }).collect()
    }
}

/// The transactions in a batch, in the order they are applied, which is from the end of
/// the batch to its start. `None` if any of them cannot be read: then none of them count.
/// (`parse-roll`)
pub fn parse_batch(batch: &[u8]) -> Option<Vec<Transaction>> {
    // Zeros at the very start are not part of the number, so they are not read as a
    // transaction. Zeros a transaction needs at its front are made up again by reading
    // past the start.
    let start = batch.iter().position(|byte| *byte != 0).unwrap_or(batch.len());
    let mut reader = Backwards { bytes: &batch[start..], taken: 0 };
    let mut found = Vec::new();
    while reader.taken < reader.bytes.len() {
        found.push(parse_transaction(&mut reader)?);
    }
    Some(found)
}

/// One transaction, from the end back: the signature (65 bytes), a byte whose low three
/// bits say the role, the ship (4 bytes), a byte whose low seven bits say what is asked and
/// whose top bit is a flag, then what is asked, each part written with its most
/// significant byte first. (`parse-raw-tx`)
fn parse_transaction(reader: &mut Backwards) -> Option<Transaction> {
    let signature = reader.take::<65>();
    let mark = reader.taken;
    let [role] = reader.take::<1>();
    // The five bits above the role are padding.
    let proxy = match role & 0b111 {
        0 => Proxy::Owner,
        1 => Proxy::Spawn,
        2 => Proxy::Management,
        3 => Proxy::Voting,
        4 => Proxy::Transfer,
        _ => return None,
    };
    let ship = reader.ship();
    let [asked] = reader.take::<1>();
    // The flag is on when the bit is zero. Only two kinds of transaction use it; for the
    // rest the bit is padding.
    let flag = asked & 0x80 == 0;
    let action = match asked & 0x7f {
        0 => Action::TransferPoint { to: reader.take(), reset: flag },
        1 => {
            let ship = reader.ship();
            Action::Spawn { ship, to: reader.take() }
        }
        2 => {
            let encryption = reader.take();
            let authentication = reader.take();
            Action::ConfigureKeys { encryption, authentication, suite: u32::from_be_bytes(reader.take()), breach: flag }
        }
        3 => Action::Escape(reader.ship()),
        4 => Action::CancelEscape(reader.ship()),
        5 => Action::Adopt(reader.ship()),
        6 => Action::Reject(reader.ship()),
        7 => Action::Detach(reader.ship()),
        8 => Action::SetManagementProxy(reader.take()),
        9 => Action::SetSpawnProxy(reader.take()),
        10 => Action::SetTransferProxy(reader.take()),
        _ => return None,
    };
    Some(Transaction { signature, raw: reader.since(mark), ship, proxy, action })
}

/// A transaction's bytes as they are written in a batch, all but the signature, which goes
/// after them. The inverse of reading one; what a wallet signs (see [`signed_message`]).
pub fn written(ship: u32, proxy: Proxy, action: &Action) -> Vec<u8> {
    let role = match proxy {
        Proxy::Owner => 0,
        Proxy::Spawn => 1,
        Proxy::Management => 2,
        Proxy::Voting => 3,
        Proxy::Transfer => 4,
    };
    // A flag is on when its bit is zero.
    let flagged = |kind: u8, flag: bool| if flag { kind } else { kind | 0x80 };
    // The parts in the order they are read, from the end back. Each part's own bytes are
    // written most significant first.
    let mut parts: Vec<Vec<u8>> = vec![vec![role], ship.to_be_bytes().to_vec()];
    match *action {
        Action::TransferPoint { to, reset } => parts.extend([vec![flagged(0, reset)], to.to_vec()]),
        Action::Spawn { ship, to } => parts.extend([vec![1], ship.to_be_bytes().to_vec(), to.to_vec()]),
        Action::ConfigureKeys { encryption, authentication, suite, breach } => {
            parts.extend([vec![flagged(2, breach)], encryption.to_vec(), authentication.to_vec(), suite.to_be_bytes().to_vec()])
        }
        Action::Escape(other) => parts.extend([vec![3], other.to_be_bytes().to_vec()]),
        Action::CancelEscape(other) => parts.extend([vec![4], other.to_be_bytes().to_vec()]),
        Action::Adopt(other) => parts.extend([vec![5], other.to_be_bytes().to_vec()]),
        Action::Reject(other) => parts.extend([vec![6], other.to_be_bytes().to_vec()]),
        Action::Detach(other) => parts.extend([vec![7], other.to_be_bytes().to_vec()]),
        Action::SetManagementProxy(to) => parts.extend([vec![8], to.to_vec()]),
        Action::SetSpawnProxy(to) => parts.extend([vec![9], to.to_vec()]),
        Action::SetTransferProxy(to) => parts.extend([vec![10], to.to_vec()]),
    }
    parts.iter().rev().flatten().copied().collect()
}

/// What was signed: the transaction's bytes, after a label that keeps the signature from
/// meaning anything anywhere else, the chain, and the count of the signer's transactions so
/// far; all wrapped the way Ethereum wallets wrap a message they are asked to sign, so that
/// it can never be taken for an Ethereum transaction. Its Keccak-256 hash is what the
/// signature is over.
pub fn signed_message(chain: u64, nonce: u32, raw: &[u8]) -> Vec<u8> {
    let mut prepared = b"UrbitIDV1Chain".to_vec();
    prepared.extend_from_slice(chain.to_string().as_bytes());
    prepared.push(b':');
    prepared.extend_from_slice(&nonce.to_le_bytes());
    // `naive.hoon` lays bytes out from the low end of a number, so the transaction's
    // bytes go in backwards.
    prepared.extend(raw.iter().rev());
    let mut signed = b"\x19Ethereum Signed Message:\n".to_vec();
    signed.extend_from_slice(prepared.len().to_string().as_bytes());
    signed.extend_from_slice(&prepared);
    signed
}

/// The address whose key made this signature over this message, as Ethereum works it out.
/// `None` if the signature is not one. (The `verifier` `naive.hoon` is given.)
pub fn signer(message: &[u8], signature: &[u8; 65]) -> Option<Address> {
    // Wallets add 27 to the last byte, and some do not. Either is taken.
    let mut v = signature[64];
    if v >= 27 {
        v -= 27;
    }
    if v > 3 {
        return None;
    }
    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..64]);
    let mut signature = Signature::from_scalars(r, s).ok()?;
    // Ethereum accepts either of the two values of s that make a signature good, and this
    // library only the lower. The other one is the same signature with the point it was
    // made from turned over, so the bit that says which way up that point is turns over.
    if let Some(lower) = signature.normalize_s() {
        signature = lower;
        v ^= 1;
    }
    let key = VerifyingKey::recover_from_prehash(&keccak(message), &signature, RecoveryId::from_byte(v)?).ok()?;
    Some(address_of(&key))
}

/// The Ethereum address of a public key: the last twenty bytes of the hash of the key.
pub fn address_of(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    let mut out = [0; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// What became of one layer 2 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Done.
    Applied,
    /// Signed by the right key, and counted as sent, but against the rules, so it changed
    /// nothing else.
    Failed,
    /// Not signed by whoever it would have to be signed by, with the count they are at. It
    /// changed nothing at all.
    Unsigned,
}

/// What became of a batch: `None` if it could not be read, and then none of it counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received {
    pub outcomes: Option<Vec<Outcome>>,
}

/// Apply one batch: the whole input of the Ethereum transaction that the layer 2 contract
/// logged. `chain` is Ethereum's chain number, which is part of what is signed (1 for the
/// main network). (`receive-batch`)
pub fn receive_batch(points: &mut impl Points, chain: u64, batch: &[u8]) -> Result<Received, String> {
    let Some(transactions) = parse_batch(batch) else {
        return Ok(Received { outcomes: None });
    };
    let mut outcomes = Vec::with_capacity(transactions.len());
    for transaction in &transactions {
        outcomes.push(receive_transaction(points, chain, transaction)?);
    }
    Ok(Received { outcomes: Some(outcomes) })
}

fn receive_transaction(points: &mut impl Points, chain: u64, transaction: &Transaction) -> Result<Outcome, String> {
    // The signature must be by whoever holds the role now, with the count they are at now.
    // (`verify-sig-and-nonce`)
    let mut sender = point_of(points, transaction.ship)?;
    let holder = *sender.holder(transaction.proxy);
    let message = signed_message(chain, holder.nonce, &transaction.raw);
    if signer(&message, &transaction.signature) != Some(holder.address) {
        return Ok(Outcome::Unsigned);
    }
    // Counted as sent even if it then breaks a rule, so that it cannot be sent again.
    // (`increment-nonce`)
    sender.holder_mut(transaction.proxy).nonce = holder.nonce.wrapping_add(1);
    points.put(transaction.ship, &sender)?;
    Ok(if apply(points, transaction)? { Outcome::Applied } else { Outcome::Failed })
}

/// Where a ship must be for a transaction to act on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Must {
    /// On layer 2. (`w-point`)
    BeOnL2,
    /// Anywhere but layer 1 proper: on layer 2, or a ship that makes its children there.
    /// (`w-point-spawn`)
    MakeShipsOnL2,
    /// Anywhere. (`w-point-esc`)
    BeAnywhere,
}

/// Do what a signed transaction asks, if the rules allow it. Returns whether they did. A
/// transaction the rules refuse changes nothing. (`receive-tx`)
fn apply(points: &mut impl Points, transaction: &Transaction) -> Result<bool, String> {
    let (from, proxy) = (transaction.ship, transaction.proxy);
    let either = |one: Proxy, other: Proxy| proxy == one || proxy == other;
    match transaction.action {
        Action::Spawn { ship, to } => spawn(points, from, proxy, ship, to),
        Action::TransferPoint { to, reset } => with(points, from, Must::BeOnL2, |point| {
            if !either(Proxy::Owner, Proxy::Transfer) {
                return false;
            }
            point.owner.address = to;
            point.transfer_proxy.address = [0; 20];
            if reset {
                // Keys that are already gone are not taken away again.
                let keys = point.keys;
                if (keys.suite, keys.authentication, keys.encryption) != (0, [0; 32], [0; 32]) {
                    point.keys = NetKeys { revision: keys.revision.wrapping_add(1), ..NetKeys::default() };
                }
                // A ship that has had keys starts afresh.
                if point.keys.revision != 0 {
                    point.continuity = point.continuity.wrapping_add(1);
                }
                point.spawn_proxy.address = [0; 20];
                point.management_proxy.address = [0; 20];
                point.voting_proxy.address = [0; 20];
                point.transfer_proxy.address = [0; 20];
            }
            true
        }),
        Action::ConfigureKeys { encryption, authentication, suite, breach } => with(points, from, Must::BeOnL2, |point| {
            if !either(Proxy::Owner, Proxy::Management) {
                return false;
            }
            if breach {
                point.continuity = point.continuity.wrapping_add(1);
            }
            // Setting the keys a ship already has does not count as setting them again.
            let keys = point.keys;
            if (keys.suite, keys.authentication, keys.encryption) != (suite, authentication, encryption) {
                point.keys = NetKeys { revision: keys.revision.wrapping_add(1), suite, authentication, encryption };
            }
            true
        }),
        Action::Escape(sponsor) => with(points, from, Must::BeAnywhere, |point| {
            if !either(Proxy::Owner, Proxy::Management) || rank(sponsor) + 1 != rank(from) {
                return false;
            }
            point.escape = Some(sponsor);
            true
        }),
        Action::CancelEscape(_) => with(points, from, Must::BeAnywhere, |point| {
            if !either(Proxy::Owner, Proxy::Management) {
                return false;
            }
            point.escape = None;
            true
        }),
        // These three are sent by a sponsor, and change the ship they name.
        Action::Adopt(ship) => with(points, ship, Must::BeAnywhere, |point| {
            if !either(Proxy::Owner, Proxy::Management) || point.escape != Some(from) {
                return false;
            }
            point.escape = None;
            point.has_sponsor = true;
            point.sponsor = from;
            true
        }),
        Action::Reject(ship) => with(points, ship, Must::BeAnywhere, |point| {
            if !either(Proxy::Owner, Proxy::Management) || point.escape != Some(from) {
                return false;
            }
            point.escape = None;
            true
        }),
        Action::Detach(ship) => with(points, ship, Must::BeAnywhere, |point| {
            // Whether or not it still has a sponsor: the sponsor it had.
            if !either(Proxy::Owner, Proxy::Management) || point.sponsor != from {
                return false;
            }
            point.has_sponsor = false;
            true
        }),
        Action::SetManagementProxy(to) => with(points, from, Must::BeOnL2, |point| {
            if !either(Proxy::Owner, Proxy::Management) {
                return false;
            }
            point.management_proxy.address = to;
            true
        }),
        Action::SetSpawnProxy(to) => with(points, from, Must::MakeShipsOnL2, |point| {
            // A planet makes no ships.
            if !either(Proxy::Owner, Proxy::Spawn) || rank(from) >= 2 {
                return false;
            }
            point.spawn_proxy.address = to;
            true
        }),
        Action::SetTransferProxy(to) => with(points, from, Must::BeOnL2, |point| {
            if !either(Proxy::Owner, Proxy::Transfer) {
                return false;
            }
            point.transfer_proxy.address = to;
            true
        }),
    }
}

/// Change one ship's point, if it is where it must be and `change` says the rules allow
/// it; otherwise change nothing, and do not add the ship to the table.
fn with(points: &mut impl Points, ship: u32, must: Must, change: impl FnOnce(&mut Point) -> bool) -> Result<bool, String> {
    let mut point = point_of(points, ship)?;
    let allowed = match must {
        Must::BeOnL2 => point.dominion == Dominion::L2,
        Must::MakeShipsOnL2 => point.dominion != Dominion::L1,
        Must::BeAnywhere => true,
    };
    if !allowed || !change(&mut point) {
        return Ok(false);
    }
    points.put(ship, &point)?;
    Ok(true)
}

/// Make a child of `from` on layer 2. (`process-spawn`)
fn spawn(points: &mut impl Points, from: u32, proxy: Proxy, ship: u32, to: Address) -> Result<bool, String> {
    let above = parent(ship);
    let above_point = point_of(points, above)?;
    // The ship above must make its ships on layer 2, and be the one sending, as its owner
    // or the one it has let make its ships.
    if above_point.dominion == Dominion::L1 {
        return Ok(false);
    }
    if above != from || !(proxy == Proxy::Owner || proxy == Proxy::Spawn) {
        return Ok(false);
    }
    // The child must not be in the table yet, and must be one rank down.
    if points.get(ship)?.is_some() || rank(above) + 1 != rank(ship) {
        return Ok(false);
    }
    let mut point = point_of(points, ship)?;
    // Made for the sender itself: it is theirs at once. Made for anyone else: it is the
    // owner's of the ship above until whoever it is made for takes it, which they may.
    let for_self = (proxy == Proxy::Owner && to == above_point.owner.address) || (proxy == Proxy::Spawn && to == above_point.spawn_proxy.address);
    if for_self {
        point.owner.address = to;
    } else {
        point.owner.address = above_point.owner.address;
        point.transfer_proxy.address = to;
    }
    points.put(ship, &point)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn unhex(text: &str) -> Vec<u8> {
        let text = text.trim_start_matches("0x");
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    fn word(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        out
    }

    fn number(n: u32) -> [u8; 32] {
        word(&n.to_be_bytes())
    }

    /// Someone who signs: a secp256k1 key and its address.
    struct Wallet(SigningKey);

    impl Wallet {
        fn new(seed: u8) -> Wallet {
            Wallet(SigningKey::from_slice(&[seed; 32]).unwrap())
        }

        fn address(&self) -> Address {
            address_of(self.0.verifying_key())
        }

        /// A signature as it is written in a batch: r, s, then v with 27 added.
        fn sign(&self, message: &[u8]) -> [u8; 65] {
            let (signature, id) = self.0.sign_prehash_recoverable(&keccak(message)).unwrap();
            let mut out = [0; 65];
            out[..64].copy_from_slice(&signature.to_bytes());
            out[64] = 27 + id.to_byte();
            out
        }
    }

    /// One transaction as it is written in a batch, signed by `wallet` with count `nonce`.
    fn written(wallet: &Wallet, nonce: u32, ship: u32, proxy: Proxy, action: Action) -> Vec<u8> {
        let raw = super::written(ship, proxy, &action);
        let mut out = raw.clone();
        out.extend_from_slice(&wallet.sign(&signed_message(1, nonce, &raw)));
        out
    }

    /// A batch of transactions, applied in the order given (so written in the opposite).
    fn batch(transactions: &[Vec<u8>]) -> Vec<u8> {
        transactions.iter().rev().flatten().copied().collect()
    }

    fn outcomes(points: &mut HashMap<u32, Point>, transactions: &[Vec<u8>]) -> Vec<Outcome> {
        receive_batch(points, 1, &batch(transactions)).unwrap().outcomes.unwrap()
    }

    const STAR: u32 = 0x0100;
    const PLANET: u32 = 0x0001_0100;

    /// A star on layer 2 owned by `owner`, under a galaxy on layer 1.
    fn star_on_l2(owner: &Wallet) -> HashMap<u32, Point> {
        let mut points = HashMap::new();
        let mut star = point_of(&points, STAR).unwrap();
        star.dominion = Dominion::L2;
        star.owner.address = owner.address();
        points.insert(STAR, star);
        points
    }

    fn log(points: &mut HashMap<u32, Point>, name: &[u8], ship: u32, third: Option<[u8; 32]>, data: &[u8]) {
        let mut topics = vec![keccak(name), number(ship)];
        topics.extend(third);
        receive_log(points, &topics, data).unwrap();
    }

    #[test]
    fn the_names_of_logs_are_the_ones_naive_hoon_lists() {
        let known = topics();
        let listed = [
            (known.owner_changed, "16d0f539d49c6cad822b767a9445bfb1cf7ea6f2a6c2b120a7ea4cc7660d8fda"),
            (known.activated, "e74c03809d0769e1b1f706cc8414258cd1f3b6fe020cd15d0165c210ba503a0f"),
            (known.spawned, "b2d3a6e7a339f5c8ff96265e2f03a010a8541070f3744a247090964415081546"),
            (known.ownership_transferred, "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"),
            (known.escape_requested, "b4d4850b8f218218141c5665cba379e53e9bb015b51e8d934be70210aead874a"),
            (known.escape_canceled, "d653bb0e0bb7ce8393e624d98fbf17cda5902c8328ed0cd09988f36890d9932a"),
            (known.escape_accepted, "7e447c9b1bda4b174b0796e100bf7f34ebf36dbb7fe665490b1bfce6246a9da5"),
            (known.lost_sponsor, "d7704f9a25193dbd0b0cb4a809feffffa7f19d1aae8817a71346c194448210d5"),
            (known.changed_keys, "aa10e7a0117d4323f1d99d630ec169bebb3a988e895770e351987e01ff5423d5"),
            (known.broke_continuity, "29294799f1c21a37ef838e15f79dd91bcee2df99d63cd1c18ac968b129514e6e"),
            (known.changed_spawn_proxy, "902736af7b3cefe10d9e840aed0d687e35c84095122b25051a20ead8866f006d"),
            (known.changed_transfer_proxy, "cfe369b7197e7f0cf06793ae2472a9b13583fecbed2f78dfa14d1f10796b847c"),
            (known.changed_management_proxy, "ab9c9327cffd2acc168fafedbe06139f5f55cb84c761df05e0511c251e2ee9bf"),
            (known.changed_voting_proxy, "cbd6269ec71457f2c7b1a22774f246f6c5a2eae3795ed7300db517680c61c805"),
            (known.changed_dns, "fafd04ade1daae2e1fdb0fc1cc6a899fd424063ed5c92120e67e073053b94898"),
            (known.approval_for_all, "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"),
        ];
        for (computed, listed) in listed {
            assert_eq!(computed.to_vec(), unhex(listed));
        }
        // And the one the layer 2 contract writes, as seen on Ethereum.
        assert_eq!(batch_topic().to_vec(), unhex("cca739c72762deed05941b38d4aa82f2718c74457d5e2d8c5b1d7642caf22196"));
    }

    #[test]
    fn a_ship_never_seen_starts_from_the_ship_above_it() {
        let mut points = HashMap::new();
        // A galaxy is on layer 1, its own sponsor. A star and a planet under it are on
        // layer 1 too, each with the ship above as its sponsor, and nothing else.
        let galaxy = point_of(&points, 7).unwrap();
        assert_eq!((galaxy.dominion, galaxy.has_sponsor, galaxy.sponsor), (Dominion::L1, true, 7));
        let planet = point_of(&points, 0x0002_0107).unwrap();
        assert_eq!((planet.dominion, planet.sponsor, planet.keys, planet.owner), (Dominion::L1, 0x0107, NetKeys::default(), Holder::default()));
        assert!(points.is_empty(), "looking does not add anything to the table");
        // A star that makes its ships on layer 2: its unseen planets are there. So are the
        // planets of a star that is itself there, and of a star made under a galaxy that
        // makes its stars there.
        let mut star = point_of(&points, 0x0107).unwrap();
        star.dominion = Dominion::Spawn;
        points.insert(0x0107, star);
        assert_eq!(point_of(&points, 0x0002_0107).unwrap().dominion, Dominion::L2);
        assert_eq!(point_of(&points, 0x0107).unwrap().dominion, Dominion::Spawn);
        star.dominion = Dominion::L2;
        points.insert(0x0107, star);
        assert_eq!(point_of(&points, 0x0002_0107).unwrap().dominion, Dominion::L2);
        points.clear();
        let mut galaxy = point_of(&points, 7).unwrap();
        galaxy.dominion = Dominion::Spawn;
        points.insert(7, galaxy);
        assert_eq!(point_of(&points, 0x0107).unwrap().dominion, Dominion::L2);
        assert_eq!(point_of(&points, 0x0002_0107).unwrap().dominion, Dominion::L2);
        // A planet with a galaxy's number in its low half has that galaxy above it.
        let odd = point_of(&points, 0x0002_0007).unwrap();
        assert_eq!((odd.dominion, odd.sponsor), (Dominion::L2, 7));
        assert_eq!((rank(0), rank(0xff), rank(0x100), rank(0xffff), rank(0x1_0000), rank(u32::MAX)), (0, 0, 1, 1, 2, 2));
    }

    #[test]
    fn logs_from_layer_one_change_ships_on_layer_one() {
        let mut points = HashMap::new();
        let (alice, bob) = ([0xa1; 20], [0xb0; 20]);
        // What the contract does not say about one ship, and what this does not keep, does
        // nothing, and does not add the ship to the table.
        log(&mut points, b"Activated(uint32)", STAR, None, &[]);
        log(&mut points, b"Spawned(uint32,uint32)", 1, Some(number(STAR)), &[]);
        receive_log(&mut points, &[keccak(b"ChangedDns(string,string,string)")], &[1; 96]).unwrap();
        log(&mut points, b"SomethingElse(uint32)", STAR, None, &[]);
        assert!(points.is_empty());

        log(&mut points, b"OwnerChanged(uint32,address)", STAR, Some(word(&alice)), &[]);
        log(&mut points, b"ChangedManagementProxy(uint32,address)", STAR, Some(word(&bob)), &[]);
        log(&mut points, b"ChangedVotingProxy(uint32,address)", STAR, Some(word(&[3; 20])), &[]);
        log(&mut points, b"ChangedTransferProxy(uint32,address)", STAR, Some(word(&[4; 20])), &[]);
        log(&mut points, b"ChangedSpawnProxy(uint32,address)", STAR, Some(word(&[5; 20])), &[]);
        let mut data = Vec::new();
        data.extend_from_slice(&[0xee; 32]);
        data.extend_from_slice(&[0xaa; 32]);
        data.extend_from_slice(&number(1));
        data.extend_from_slice(&number(3));
        log(&mut points, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, &data);
        log(&mut points, b"BrokeContinuity(uint32,uint32)", STAR, None, &number(2));
        log(&mut points, b"EscapeRequested(uint32,uint32)", STAR, Some(number(9)), &[]);
        let star = points[&STAR];
        assert_eq!(star.owner.address, alice);
        assert_eq!((star.management_proxy.address, star.voting_proxy.address, star.transfer_proxy.address, star.spawn_proxy.address), (bob, [3; 20], [4; 20], [5; 20]));
        assert_eq!(star.keys, NetKeys { revision: 3, suite: 1, authentication: [0xaa; 32], encryption: [0xee; 32] });
        assert_eq!((star.continuity, star.escape), (2, Some(9)));
        log(&mut points, b"EscapeCanceled(uint32,uint32)", STAR, Some(number(9)), &[]);
        assert_eq!(points[&STAR].escape, None);
        log(&mut points, b"EscapeRequested(uint32,uint32)", STAR, Some(number(9)), &[]);
        log(&mut points, b"EscapeAccepted(uint32,uint32)", STAR, Some(number(9)), &[]);
        assert_eq!((points[&STAR].escape, points[&STAR].sponsor, points[&STAR].has_sponsor), (None, 9, true));
        // Losing a sponsor that is not the ship's loses nothing; losing its own does.
        log(&mut points, b"LostSponsor(uint32,uint32)", STAR, Some(number(1)), &[]);
        assert!(points[&STAR].has_sponsor);
        log(&mut points, b"LostSponsor(uint32,uint32)", STAR, Some(number(9)), &[]);
        assert_eq!((points[&STAR].has_sponsor, points[&STAR].sponsor), (false, 9));

        // Giving its children to the deposit address moves where they are made, and is no
        // spawn proxy. After that its spawn proxy cannot change on layer 1, but the rest
        // still can.
        log(&mut points, b"ChangedSpawnProxy(uint32,address)", STAR, Some(word(&DEPOSIT)), &[]);
        assert_eq!((points[&STAR].dominion, points[&STAR].spawn_proxy.address), (Dominion::Spawn, [5; 20]));
        log(&mut points, b"ChangedSpawnProxy(uint32,address)", STAR, Some(word(&[6; 20])), &[]);
        assert_eq!(points[&STAR].spawn_proxy.address, [5; 20]);
        log(&mut points, b"ChangedVotingProxy(uint32,address)", STAR, Some(word(&[7; 20])), &[]);
        assert_eq!(points[&STAR].voting_proxy.address, [7; 20]);
        // Giving the ship itself to the deposit address moves it to layer 2, still owned
        // by whoever owned it.
        log(&mut points, b"OwnerChanged(uint32,address)", STAR, Some(word(&DEPOSIT)), &[]);
        assert_eq!((points[&STAR].dominion, points[&STAR].owner.address), (Dominion::L2, alice));
        let before = points[&STAR];
        // Now nothing on layer 1 changes it, but its sponsor's doings.
        for (name, third) in [
            (&b"OwnerChanged(uint32,address)"[..], Some(word(&bob))),
            (b"ChangedManagementProxy(uint32,address)", Some(word(&bob))),
            (b"ChangedVotingProxy(uint32,address)", Some(word(&bob))),
            (b"ChangedTransferProxy(uint32,address)", Some(word(&bob))),
            (b"ChangedSpawnProxy(uint32,address)", Some(word(&bob))),
            (b"EscapeRequested(uint32,uint32)", Some(number(2))),
            (b"BrokeContinuity(uint32,uint32)", None),
        ] {
            log(&mut points, name, STAR, third, &number(5));
            assert_eq!(points[&STAR], before, "{}", String::from_utf8_lossy(name));
        }
        log(&mut points, b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)", STAR, None, &data);
        assert_eq!(points[&STAR], before);
        // A sponsor on layer 1 can still take it in, or let it go.
        log(&mut points, b"EscapeAccepted(uint32,uint32)", STAR, Some(number(2)), &[]);
        assert_eq!((points[&STAR].sponsor, points[&STAR].has_sponsor), (2, true));
        log(&mut points, b"LostSponsor(uint32,uint32)", STAR, Some(number(2)), &[]);
        assert!(!points[&STAR].has_sponsor);
        // A sponsor on layer 2 cannot do either through layer 1: not take it in, and not let
        // it go while it still has it.
        let mut sponsor = point_of(&points, 2).unwrap();
        sponsor.dominion = Dominion::L2;
        points.insert(2, sponsor);
        let mut held = points[&STAR];
        held.has_sponsor = true;
        points.insert(STAR, held);
        let before = points[&STAR];
        log(&mut points, b"EscapeAccepted(uint32,uint32)", STAR, Some(number(2)), &[]);
        log(&mut points, b"LostSponsor(uint32,uint32)", STAR, Some(number(2)), &[]);
        assert_eq!(points[&STAR], before);
    }

    #[test]
    fn a_log_not_shaped_as_the_contract_makes_them_is_refused_and_changes_nothing() {
        let mut points = HashMap::new();
        let owner = keccak(b"OwnerChanged(uint32,address)");
        let keys = keccak(b"ChangedKeys(uint32,bytes32,bytes32,uint32,uint32)");
        let refused: Vec<(Vec<[u8; 32]>, Vec<u8>)> = vec![
            (vec![], vec![]),
            (vec![owner], vec![]),
            (vec![owner, [1; 32], word(&[1; 20])], vec![]),
            (vec![owner, number(STAR)], vec![]),
            (vec![owner, number(STAR), word(&[1; 20]), [0; 32]], vec![]),
            (vec![owner, number(STAR), [1; 32]], vec![]),
            (vec![keys, number(STAR), [0; 32]], vec![0; 128]),
            (vec![keys, number(STAR)], [vec![0; 96], vec![1; 32]].concat()),
            (vec![keccak(b"EscapeRequested(uint32,uint32)"), number(STAR), [1; 32]], vec![]),
            (vec![keccak(b"BrokeContinuity(uint32,uint32)"), number(STAR)], vec![1, 0, 0, 0, 0]),
        ];
        for (topics, data) in refused {
            assert!(receive_log(&mut points, &topics, &data).is_err(), "{topics:?}");
        }
        assert!(points.is_empty());
        // A count written short, or with zeros in front, is the same number.
        receive_log(&mut points, &[keccak(b"BrokeContinuity(uint32,uint32)"), number(STAR)], &[0, 0, 7]).unwrap();
        assert_eq!(points[&STAR].continuity, 7);
    }

    #[test]
    fn a_batch_is_read_from_its_end_and_applied_in_that_order() {
        let owner = Wallet::new(1);
        let mut points = star_on_l2(&owner);
        let (manager, someone) = (Wallet::new(2), Wallet::new(3));
        // The owner sets a management proxy, which then sets keys. The second is signed
        // by a key that was given its role by the first, so the order matters.
        let first = written(&owner, 0, STAR, Proxy::Owner, Action::SetManagementProxy(manager.address()));
        let second = written(&manager, 0, STAR, Proxy::Management, Action::ConfigureKeys { encryption: [1; 32], authentication: [2; 32], suite: 1, breach: false });
        let parsed = parse_batch(&batch(&[first.clone(), second.clone()])).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[0].ship, parsed[0].proxy, parsed[0].action), (STAR, Proxy::Owner, Action::SetManagementProxy(manager.address())));
        assert_eq!(parsed[0].raw, first[..first.len() - 65]);
        assert_eq!(outcomes(&mut points, &[first, second]), [Outcome::Applied, Outcome::Applied]);
        let star = points[&STAR];
        assert_eq!(star.keys, NetKeys { revision: 1, suite: 1, authentication: [2; 32], encryption: [1; 32] });
        assert_eq!((star.owner.nonce, star.management_proxy.nonce), (1, 1));
        // Sent again, both are refused: the counts have moved on.
        let again = [written(&owner, 0, STAR, Proxy::Owner, Action::SetManagementProxy(someone.address()))];
        assert_eq!(outcomes(&mut points, &again), [Outcome::Unsigned]);
        assert_eq!(points[&STAR], star);
    }

    #[test]
    fn every_kind_of_transaction_reads_back_as_written() {
        let actions = [
            Action::TransferPoint { to: [1; 20], reset: true },
            Action::TransferPoint { to: [1; 20], reset: false },
            Action::Spawn { ship: 0x0102_0304, to: [2; 20] },
            Action::ConfigureKeys { encryption: [3; 32], authentication: [4; 32], suite: 0x0506_0708, breach: true },
            Action::ConfigureKeys { encryption: [3; 32], authentication: [4; 32], suite: 1, breach: false },
            Action::Escape(5),
            Action::CancelEscape(6),
            Action::Adopt(7),
            Action::Reject(8),
            Action::Detach(9),
            Action::SetManagementProxy([10; 20]),
            Action::SetSpawnProxy([11; 20]),
            Action::SetTransferProxy([12; 20]),
        ];
        let proxies = [Proxy::Owner, Proxy::Spawn, Proxy::Management, Proxy::Voting, Proxy::Transfer];
        let mut whole = Vec::new();
        for (at, action) in actions.iter().enumerate() {
            let raw = super::written(0xdead_beef, proxies[at % 5], action);
            let mut sent = raw.clone();
            sent.extend_from_slice(&[0x5a; 65]);
            let parsed = parse_batch(&sent).unwrap();
            assert_eq!(parsed, [Transaction { signature: [0x5a; 65], raw, ship: 0xdead_beef, proxy: proxies[at % 5], action: *action }]);
            whole = [sent, whole].concat();
        }
        let parsed = parse_batch(&whole).unwrap();
        assert_eq!(parsed.iter().map(|transaction| transaction.action).collect::<Vec<_>>(), actions);
    }

    #[test]
    fn a_signed_transaction_that_breaks_a_rule_is_counted_and_one_badly_signed_is_not() {
        let owner = Wallet::new(1);
        let mut points = star_on_l2(&owner);
        let stranger = Wallet::new(9);
        // Signed by someone who is not the owner, or by the owner with the wrong count, or
        // claiming a role nobody holds: nothing at all happens.
        let keys = Action::ConfigureKeys { encryption: [1; 32], authentication: [2; 32], suite: 1, breach: false };
        for unsigned in [written(&stranger, 0, STAR, Proxy::Owner, keys), written(&owner, 1, STAR, Proxy::Owner, keys), written(&owner, 0, STAR, Proxy::Spawn, keys)] {
            let before = points.clone();
            assert_eq!(outcomes(&mut points, &[unsigned]), [Outcome::Unsigned]);
            assert_eq!(points, before);
        }
        // Signed by the owner as owner, but asking for what an owner may not do (a star
        // escaping to a planet): counted, and nothing else.
        assert_eq!(outcomes(&mut points, &[written(&owner, 0, STAR, Proxy::Owner, Action::Escape(PLANET))]), [Outcome::Failed]);
        assert_eq!(points[&STAR].owner.nonce, 1);
        assert_eq!(points[&STAR].escape, None);
        // A different signature on the same message from a high s is still the owner's.
        let mut sent = written(&owner, 1, STAR, Proxy::Owner, Action::Escape(4));
        let at = sent.len() - 65;
        let signature = Signature::from_slice(&sent[at..at + 64]).unwrap();
        let (r, s) = signature.split_scalars();
        let high = Signature::from_scalars((*r).to_bytes(), (-*s).to_bytes()).unwrap();
        sent[at..at + 64].copy_from_slice(&high.to_bytes());
        sent[at + 64] = 27 + ((sent[at + 64] - 27) ^ 1);
        assert!(high.normalize_s().is_some());
        assert_eq!(outcomes(&mut points, &[sent.clone()]), [Outcome::Applied]);
        assert_eq!(points[&STAR].escape, Some(4));
        // A v without the 27 added is taken; one that is neither is not.
        let mut sent = written(&owner, 2, STAR, Proxy::Owner, Action::CancelEscape(4));
        let last = sent.len() - 1;
        for v in [sent[last] + 2, 31, 4, 26] {
            let mut bad = sent.clone();
            bad[last] = v;
            assert_eq!(outcomes(&mut points, &[bad]), [Outcome::Unsigned], "{v}");
        }
        sent[last] -= 27;
        assert_eq!(outcomes(&mut points, &[sent]), [Outcome::Applied]);
        assert_eq!((points[&STAR].escape, points[&STAR].owner.nonce), (None, 3));
        // On another chain, a signature made for this one is no good.
        let elsewhere = batch(&[written(&owner, 3, STAR, Proxy::Owner, Action::Escape(4))]);
        assert_eq!(receive_batch(&mut points, 5, &elsewhere).unwrap().outcomes.unwrap(), [Outcome::Unsigned]);
    }

    #[test]
    fn one_unreadable_transaction_voids_its_whole_batch() {
        let owner = Wallet::new(1);
        let mut points = star_on_l2(&owner);
        let good = written(&owner, 0, STAR, Proxy::Owner, Action::SetTransferProxy([7; 20]));
        // A role above 4, or a kind of transaction above 10, cannot be read. The high bits
        // of the role's byte are padding, and do not matter.
        let mut bad_role = written(&owner, 1, STAR, Proxy::Owner, Action::SetTransferProxy([8; 20]));
        let at = bad_role.len() - 66;
        bad_role[at] = 5;
        let mut bad_kind = written(&owner, 1, STAR, Proxy::Owner, Action::SetTransferProxy([8; 20]));
        bad_kind[at - 5] = 11;
        for bad in [bad_role, bad_kind] {
            let received = receive_batch(&mut points, 1, &batch(&[good.clone(), bad.clone()])).unwrap();
            assert_eq!(received.outcomes, None);
            let received = receive_batch(&mut points, 1, &batch(&[bad, good.clone()])).unwrap();
            assert_eq!(received.outcomes, None);
            assert_eq!(points[&STAR].owner.nonce, 0);
        }
        let mut padded = good.clone();
        padded[at] |= 0xf8;
        let parsed = parse_batch(&padded).unwrap();
        assert_eq!(parsed[0].proxy, Proxy::Owner);
        // Padding is part of what was signed, so this one no longer verifies, and the good
        // one does.
        assert_eq!(outcomes(&mut points, &[padded]), [Outcome::Unsigned]);
        assert_eq!(outcomes(&mut points, &[good]), [Outcome::Applied]);
        // An empty batch, or one of zeros, has nothing in it.
        assert_eq!(receive_batch(&mut points, 1, &[]).unwrap().outcomes, Some(vec![]));
        assert_eq!(receive_batch(&mut points, 1, &[0; 40]).unwrap().outcomes, Some(vec![]));
    }

    #[test]
    fn zeros_at_the_front_of_a_batch_are_left_off_and_made_up_again() {
        // A transaction that begins with zero bytes, first in the batch, can be sent
        // without them. They are still part of what was signed.
        let owner = Wallet::new(1);
        let mut points = HashMap::new();
        let ship = 0x0000_0102u32;
        let mut star = point_of(&points, ship).unwrap();
        star.dominion = Dominion::L2;
        star.owner.address = owner.address();
        points.insert(ship, star);
        // An escape to galaxy 1 begins with three zero bytes (0x00000001).
        let full = written(&owner, 0, ship, Proxy::Owner, Action::Escape(1));
        assert_eq!(full[..3], [0, 0, 0]);
        let short = full[3..].to_vec();
        let parsed = parse_batch(&short).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].raw, full[..full.len() - 65]);
        assert_eq!(receive_batch(&mut points.clone(), 1, &short).unwrap().outcomes.unwrap(), [Outcome::Applied]);
        // The batch is read up to its first bit that is not zero, so one byte left over in
        // front is one more transaction, the rest of it zeros from past the start, and so
        // not signed by anyone.
        let mut stray = vec![1];
        stray.extend_from_slice(&full);
        assert_eq!(receive_batch(&mut points.clone(), 1, &stray).unwrap().outcomes.unwrap(), [Outcome::Applied, Outcome::Unsigned]);
        // Sent with them, or with more zeros in front still, it is the same batch: zeros
        // at the start are not another transaction.
        let mut longer = vec![0; 10];
        longer.extend_from_slice(&full);
        assert_eq!(parse_batch(&longer).unwrap(), parsed);
        assert_eq!(receive_batch(&mut points, 1, &longer).unwrap().outcomes.unwrap(), [Outcome::Applied]);
        assert_eq!(points[&ship].escape, Some(1));
        // Bytes that run out part way through a signature are zeros, which is no
        // signature. go-azimuth's own example of something that is not a batch reads,
        // under naive.hoon's rules, as one such transaction.
        let not_a_batch = unhex("7e7369636465762d70696c6e7570207761732068657265");
        assert_eq!(receive_batch(&mut points, 1, &not_a_batch).unwrap().outcomes.unwrap(), [Outcome::Unsigned]);
    }

    #[test]
    fn spawning_on_layer_two() {
        let owner = Wallet::new(1);
        let spawner = Wallet::new(2);
        let (alice, bob) = (Wallet::new(3), Wallet::new(4));
        let mut points = star_on_l2(&owner);
        // Made by the owner for itself: its own at once.
        let mine = written(&owner, 0, STAR, Proxy::Owner, Action::Spawn { ship: PLANET, to: owner.address() });
        assert_eq!(outcomes(&mut points, &[mine]), [Outcome::Applied]);
        let planet = points[&PLANET];
        assert_eq!((planet.dominion, planet.owner.address, planet.transfer_proxy.address), (Dominion::L2, owner.address(), [0; 20]));
        assert_eq!((planet.has_sponsor, planet.sponsor), (true, STAR));
        // Made for someone else: the owner's until they take it.
        let theirs = written(&owner, 1, STAR, Proxy::Owner, Action::Spawn { ship: 0x0002_0100, to: alice.address() });
        assert_eq!(outcomes(&mut points, &[theirs]), [Outcome::Applied]);
        assert_eq!((points[&0x0002_0100].owner.address, points[&0x0002_0100].transfer_proxy.address), (owner.address(), alice.address()));
        // Taken: the transfer proxy gives it to themselves.
        let take = written(&alice, 0, 0x0002_0100, Proxy::Transfer, Action::TransferPoint { to: alice.address(), reset: true });
        assert_eq!(outcomes(&mut points, &[take]), [Outcome::Applied]);
        assert_eq!((points[&0x0002_0100].owner.address, points[&0x0002_0100].transfer_proxy.address), (alice.address(), [0; 20]));

        // The spawn proxy can make ships too, and for itself they are its own.
        let set = written(&owner, 2, STAR, Proxy::Owner, Action::SetSpawnProxy(spawner.address()));
        let made = written(&spawner, 0, STAR, Proxy::Spawn, Action::Spawn { ship: 0x0003_0100, to: spawner.address() });
        assert_eq!(outcomes(&mut points, &[set, made]), [Outcome::Applied, Outcome::Applied]);
        assert_eq!(points[&0x0003_0100].owner.address, spawner.address());
        // Refused: a ship that exists; a ship not one rank down (a star, a planet whose low
        // half is a galaxy); a planet of another star, on layer 1 or making its ships on
        // layer 2; made, or a spawn proxy set, by a proxy that may not.
        let manager = Wallet::new(5);
        let management = written(&owner, 3, STAR, Proxy::Owner, Action::SetManagementProxy(manager.address()));
        assert_eq!(outcomes(&mut points, &[management]), [Outcome::Applied]);
        let mut neighbour = point_of(&points, 0x0200).unwrap();
        neighbour.dominion = Dominion::L2;
        points.insert(0x0200, neighbour);
        let refused = [
            written(&owner, 4, STAR, Proxy::Owner, Action::Spawn { ship: PLANET, to: bob.address() }),
            written(&owner, 5, STAR, Proxy::Owner, Action::Spawn { ship: 0x0101, to: bob.address() }),
            written(&owner, 6, STAR, Proxy::Owner, Action::Spawn { ship: 0x0004_0001, to: bob.address() }),
            written(&owner, 7, STAR, Proxy::Owner, Action::Spawn { ship: 0x0004_0101, to: bob.address() }),
            written(&owner, 8, STAR, Proxy::Owner, Action::Spawn { ship: 0x0004_0200, to: bob.address() }),
            written(&manager, 0, STAR, Proxy::Management, Action::Spawn { ship: 0x0004_0100, to: bob.address() }),
            written(&manager, 1, STAR, Proxy::Management, Action::SetSpawnProxy(bob.address())),
        ];
        let before: HashMap<_, _> = points.iter().filter(|(ship, _)| **ship != STAR).map(|(ship, point)| (*ship, *point)).collect();
        assert_eq!(outcomes(&mut points, &refused), [Outcome::Failed; 7]);
        points.remove(&STAR);
        assert_eq!(points, before);

        // A star on layer 1 makes no ships on layer 2; one that makes them there does.
        let mut points = HashMap::new();
        let mut star = point_of(&points, STAR).unwrap();
        star.owner.address = owner.address();
        points.insert(STAR, star);
        let spawn = |nonce| written(&owner, nonce, STAR, Proxy::Owner, Action::Spawn { ship: PLANET, to: owner.address() });
        assert_eq!(outcomes(&mut points, &[spawn(0)]), [Outcome::Failed]);
        assert!(!points.contains_key(&PLANET));
        log(&mut points, b"ChangedSpawnProxy(uint32,address)", STAR, Some(word(&DEPOSIT)), &[]);
        assert_eq!(outcomes(&mut points, &[spawn(1)]), [Outcome::Applied]);
        assert_eq!(points[&PLANET].dominion, Dominion::L2);
        // The star itself stays on layer 1: it cannot set its keys on layer 2.
        let keys = written(&owner, 2, STAR, Proxy::Owner, Action::ConfigureKeys { encryption: [1; 32], authentication: [1; 32], suite: 1, breach: false });
        assert_eq!(outcomes(&mut points, &[keys]), [Outcome::Failed]);
        // But it can set its spawn proxy there; a planet cannot, anywhere.
        let set = written(&owner, 3, STAR, Proxy::Owner, Action::SetSpawnProxy([9; 20]));
        let planet_sets = written(&owner, 0, PLANET, Proxy::Owner, Action::SetSpawnProxy([9; 20]));
        assert_eq!(outcomes(&mut points, &[set, planet_sets]), [Outcome::Applied, Outcome::Failed]);
        assert_eq!((points[&STAR].spawn_proxy.address, points[&PLANET].spawn_proxy.address), ([9; 20], [0; 20]));
    }

    #[test]
    fn keys_transfers_and_proxies_on_layer_two() {
        let owner = Wallet::new(1);
        let (manager, transferer, voter) = (Wallet::new(2), Wallet::new(3), Wallet::new(4));
        let mut points = star_on_l2(&owner);
        let keys = |breach| Action::ConfigureKeys { encryption: [1; 32], authentication: [2; 32], suite: 1, breach };
        let sent = [
            written(&owner, 0, STAR, Proxy::Owner, Action::SetManagementProxy(manager.address())),
            written(&owner, 1, STAR, Proxy::Owner, Action::SetTransferProxy(transferer.address())),
            written(&manager, 0, STAR, Proxy::Management, keys(false)),
            // The same keys again: not set again. With a breach, a new start, and still the
            // same keys.
            written(&manager, 1, STAR, Proxy::Management, keys(false)),
            written(&owner, 2, STAR, Proxy::Owner, keys(true)),
        ];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Applied; 5]);
        let star = points[&STAR];
        assert_eq!((star.keys.revision, star.continuity), (1, 1));
        assert_eq!((star.management_proxy.address, star.transfer_proxy.address), (manager.address(), transferer.address()));
        // Roles that may not: management cannot transfer or set the transfer proxy, the
        // transfer proxy cannot set keys or the management proxy, nobody can vote here.
        let mut voted = star;
        voted.voting_proxy.address = voter.address();
        voted.spawn_proxy.address = [5; 20];
        points.insert(STAR, voted);
        let refused = [
            written(&manager, 2, STAR, Proxy::Management, Action::TransferPoint { to: [9; 20], reset: false }),
            written(&manager, 3, STAR, Proxy::Management, Action::SetTransferProxy([9; 20])),
            written(&transferer, 0, STAR, Proxy::Transfer, keys(false)),
            written(&transferer, 1, STAR, Proxy::Transfer, Action::SetManagementProxy([9; 20])),
            written(&voter, 0, STAR, Proxy::Voting, Action::SetManagementProxy([9; 20])),
            written(&transferer, 2, STAR, Proxy::Transfer, Action::Escape(1)),
            written(&transferer, 3, STAR, Proxy::Transfer, Action::CancelEscape(1)),
        ];
        assert_eq!(outcomes(&mut points, &refused), [Outcome::Failed; 7]);
        let after = points[&STAR];
        assert_eq!((after.keys, after.continuity, after.owner.address), (voted.keys, voted.continuity, voted.owner.address));
        assert_eq!((after.management_proxy.nonce, after.transfer_proxy.nonce, after.voting_proxy.nonce), (4, 4, 1));

        // A transfer without reset keeps keys and proxies but the transfer proxy; with one,
        // takes keys away (a new revision), starts afresh, and clears every proxy.
        let alice = Wallet::new(6);
        let plain = written(&transferer, 4, STAR, Proxy::Transfer, Action::TransferPoint { to: alice.address(), reset: false });
        assert_eq!(outcomes(&mut points, &[plain]), [Outcome::Applied]);
        let star = points[&STAR];
        assert_eq!((star.owner.address, star.transfer_proxy.address, star.management_proxy.address, star.keys.revision), (alice.address(), [0; 20], manager.address(), 1));
        let reset = written(&alice, 3, STAR, Proxy::Owner, Action::TransferPoint { to: owner.address(), reset: true });
        assert_eq!(outcomes(&mut points, &[reset]), [Outcome::Applied]);
        let star = points[&STAR];
        assert_eq!(star.keys, NetKeys { revision: 2, ..NetKeys::default() });
        assert_eq!(star.continuity, 2);
        assert_eq!([star.spawn_proxy.address, star.management_proxy.address, star.voting_proxy.address, star.transfer_proxy.address], [[0; 20]; 4]);
        // The counts stay with the roles.
        assert_eq!((star.owner.nonce, star.management_proxy.nonce), (4, 4));
        // Reset again with no keys: no new revision, but a new start, as it has had keys.
        let again = written(&owner, 4, STAR, Proxy::Owner, Action::TransferPoint { to: owner.address(), reset: true });
        assert_eq!(outcomes(&mut points, &[again]), [Outcome::Applied]);
        assert_eq!((points[&STAR].keys.revision, points[&STAR].continuity), (2, 3));
        // A ship that has never had keys does not start afresh.
        let fresh = written(&owner, 0, PLANET, Proxy::Owner, Action::TransferPoint { to: owner.address(), reset: true });
        let mut planet = point_of(&points, PLANET).unwrap();
        planet.owner.address = owner.address();
        points.insert(PLANET, planet);
        assert_eq!(outcomes(&mut points, &[fresh]), [Outcome::Applied]);
        assert_eq!((points[&PLANET].keys.revision, points[&PLANET].continuity), (0, 0));

        // A ship on layer 1 can do none of these on layer 2.
        let mut l1 = points[&PLANET];
        l1.dominion = Dominion::L1;
        points.insert(PLANET, l1);
        let refused = [
            written(&owner, 1, PLANET, Proxy::Owner, keys(false)),
            written(&owner, 2, PLANET, Proxy::Owner, Action::TransferPoint { to: [9; 20], reset: false }),
            written(&owner, 3, PLANET, Proxy::Owner, Action::SetManagementProxy([9; 20])),
            written(&owner, 4, PLANET, Proxy::Owner, Action::SetTransferProxy([9; 20])),
        ];
        assert_eq!(outcomes(&mut points, &refused), [Outcome::Failed; 4]);
        assert_eq!(points[&PLANET].owner.nonce, 5);
    }

    #[test]
    fn sponsors_on_layer_two() {
        let (planet_owner, star_owner, other_owner) = (Wallet::new(1), Wallet::new(2), Wallet::new(3));
        // The transfer proxy of both stars, which may not adopt, reject or detach for them:
        // only the owner and the management proxy may.
        let mover = Wallet::new(4);
        let other = 0x0200u32;
        let mut points = star_on_l2(&star_owner);
        let mut ours = points[&STAR];
        ours.transfer_proxy.address = mover.address();
        points.insert(STAR, ours);
        let mut planet = point_of(&points, PLANET).unwrap();
        planet.owner.address = planet_owner.address();
        points.insert(PLANET, planet);
        let mut star = point_of(&points, other).unwrap();
        star.owner.address = other_owner.address();
        star.transfer_proxy.address = mover.address();
        points.insert(other, star);
        // Escape only to a ship one rank up. Adopt and reject only a ship that asked.
        let sent = [
            written(&planet_owner, 0, PLANET, Proxy::Owner, Action::Escape(0x0001_0200)),
            written(&planet_owner, 1, PLANET, Proxy::Owner, Action::Escape(2)),
            written(&other_owner, 0, other, Proxy::Owner, Action::Adopt(PLANET)),
            written(&planet_owner, 2, PLANET, Proxy::Owner, Action::Escape(other)),
            written(&mover, 0, other, Proxy::Transfer, Action::Adopt(PLANET)),
            written(&star_owner, 0, STAR, Proxy::Owner, Action::Adopt(PLANET)),
            written(&star_owner, 1, STAR, Proxy::Owner, Action::Reject(PLANET)),
            written(&other_owner, 1, other, Proxy::Owner, Action::Adopt(PLANET)),
        ];
        assert_eq!(
            outcomes(&mut points, &sent),
            [Outcome::Failed, Outcome::Failed, Outcome::Failed, Outcome::Applied, Outcome::Failed, Outcome::Failed, Outcome::Failed, Outcome::Applied]
        );
        assert_eq!((points[&PLANET].sponsor, points[&PLANET].has_sponsor, points[&PLANET].escape), (other, true, None));
        // Rejected, and cancelled.
        let sent = [
            written(&planet_owner, 3, PLANET, Proxy::Owner, Action::Escape(STAR)),
            written(&mover, 0, STAR, Proxy::Transfer, Action::Reject(PLANET)),
            written(&other_owner, 2, other, Proxy::Owner, Action::Reject(PLANET)),
            written(&star_owner, 2, STAR, Proxy::Owner, Action::Reject(PLANET)),
            written(&planet_owner, 4, PLANET, Proxy::Owner, Action::Escape(STAR)),
            written(&planet_owner, 5, PLANET, Proxy::Owner, Action::CancelEscape(STAR)),
        ];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Applied, Outcome::Failed, Outcome::Failed, Outcome::Applied, Outcome::Applied, Outcome::Applied]);
        assert_eq!((points[&PLANET].sponsor, points[&PLANET].escape), (other, None));
        // Detached only by its sponsor; it keeps the number of the sponsor it had.
        let sent = [
            written(&star_owner, 3, STAR, Proxy::Owner, Action::Detach(PLANET)),
            written(&mover, 1, other, Proxy::Transfer, Action::Detach(PLANET)),
            written(&other_owner, 3, other, Proxy::Owner, Action::Detach(PLANET)),
        ];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Failed, Outcome::Failed, Outcome::Applied]);
        assert_eq!((points[&PLANET].sponsor, points[&PLANET].has_sponsor), (other, false));
        // A ship on layer 1 can escape and be adopted through layer 2: naive.hoon does not
        // ask where either is for these.
        let mut l1 = points[&PLANET];
        l1.dominion = Dominion::L1;
        points.insert(PLANET, l1);
        let sent = [written(&planet_owner, 6, PLANET, Proxy::Owner, Action::Escape(STAR)), written(&star_owner, 4, STAR, Proxy::Owner, Action::Adopt(PLANET))];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Applied, Outcome::Applied]);
        assert_eq!((points[&PLANET].sponsor, points[&PLANET].has_sponsor), (STAR, true));
        // A star can detach a planet nobody has made yet, which puts it in the table, so
        // that it can then not be made.
        let unmade = 0x0009_0100u32;
        let sent = [
            written(&star_owner, 5, STAR, Proxy::Owner, Action::Detach(unmade)),
            written(&star_owner, 6, STAR, Proxy::Owner, Action::Spawn { ship: unmade, to: star_owner.address() }),
        ];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Applied, Outcome::Failed]);
        assert_eq!(points[&unmade].owner.address, [0; 20]);
        // One that is refused does not put the ship it names in the table, so that ship can
        // still be made.
        let never = 0x0008_0100u32;
        let sent = [written(&star_owner, 7, STAR, Proxy::Owner, Action::Adopt(never))];
        assert_eq!(outcomes(&mut points, &sent), [Outcome::Failed]);
        assert!(!points.contains_key(&never));
    }

    #[test]
    fn rules_that_only_one_check_stands_between() {
        let owner = Wallet::new(1);
        // A galaxy that makes its stars on layer 2, sending as itself: a planet whose low half
        // is the galaxy's number has the galaxy above it, so only the rank check refuses it.
        let mut points = HashMap::new();
        let mut galaxy = point_of(&points, 1).unwrap();
        galaxy.dominion = Dominion::Spawn;
        galaxy.owner.address = owner.address();
        points.insert(1, galaxy);
        assert_eq!(parent(0x0004_0001), 1);
        let skip = written(&owner, 0, 1, Proxy::Owner, Action::Spawn { ship: 0x0004_0001, to: owner.address() });
        let star = written(&owner, 1, 1, Proxy::Owner, Action::Spawn { ship: 0x0201, to: owner.address() });
        assert_eq!(outcomes(&mut points, &[skip, star]), [Outcome::Failed, Outcome::Applied]);
        assert!(!points.contains_key(&0x0004_0001));
        assert_eq!(points[&0x0201].dominion, Dominion::L2);

        // A star still on layer 1 cannot set its spawn proxy on layer 2.
        let mut points = HashMap::new();
        let mut star = point_of(&points, STAR).unwrap();
        star.owner.address = owner.address();
        points.insert(STAR, star);
        let set = written(&owner, 0, STAR, Proxy::Owner, Action::SetSpawnProxy([9; 20]));
        assert_eq!(outcomes(&mut points, &[set]), [Outcome::Failed]);
        assert_eq!((points[&STAR].spawn_proxy.address, points[&STAR].owner.nonce), ([0; 20], 1));

        // A galaxy is its own sponsor, so it can detach itself. The ship sent as and the ship
        // changed are the same point: the count taken for sending is kept.
        let mut points = HashMap::new();
        let mut galaxy = point_of(&points, 2).unwrap();
        galaxy.owner.address = owner.address();
        points.insert(2, galaxy);
        let detach = written(&owner, 0, 2, Proxy::Owner, Action::Detach(2));
        assert_eq!(outcomes(&mut points, &[detach]), [Outcome::Applied]);
        assert_eq!((points[&2].has_sponsor, points[&2].sponsor, points[&2].owner.nonce), (false, 2, 1));
        // A star is not its own sponsor, and detaching itself fails, counted all the same.
        let mut star = point_of(&points, STAR).unwrap();
        star.owner.address = owner.address();
        points.insert(STAR, star);
        let detach = written(&owner, 0, STAR, Proxy::Owner, Action::Detach(STAR));
        assert_eq!(outcomes(&mut points, &[detach]), [Outcome::Failed]);
        assert_eq!((points[&STAR].has_sponsor, points[&STAR].owner.nonce), (true, 1));

        // A reset of a ship whose keys were set without a revision (which only layer 1 can
        // write): the keys go, which is a revision, and so it also starts afresh.
        let mut points = star_on_l2(&owner);
        let mut star = points[&STAR];
        star.keys = NetKeys { revision: 0, suite: 1, authentication: [3; 32], encryption: [4; 32] };
        points.insert(STAR, star);
        let reset = written(&owner, 0, STAR, Proxy::Owner, Action::TransferPoint { to: owner.address(), reset: true });
        assert_eq!(outcomes(&mut points, &[reset]), [Outcome::Applied]);
        assert_eq!((points[&STAR].keys, points[&STAR].continuity), (NetKeys { revision: 1, ..NetKeys::default() }, 1));
    }

    /// A signature whose point has an x past the curve's order, so that r is x less the order
    /// and v says so (2 or 3). Real wallets almost never make one (about once in 2^128), so
    /// one is made here by working backwards: pick such a point and a signature, and find
    /// the key that would have made it.
    #[test]
    fn a_signature_from_a_point_past_the_order_is_recovered() {
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::DecompressPoint;
        use k256::elliptic_curve::subtle::Choice;
        use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256};

        let order = unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let message = signed_message(1, 0, &super::written(STAR, Proxy::Owner, &Action::Escape(1)));
        let digest = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(keccak(&message)));
        let s = Scalar::from(0x1234_5678u64);
        let mut found = 0;
        for small in 1u8..=60 {
            // x is the order plus a small number, still below the field's prime.
            let mut x = order.clone();
            let (low, carry) = x[31].overflowing_add(small);
            x[31] = low;
            if carry {
                x[30] += 1;
            }
            for odd in [false, true] {
                let point = AffinePoint::decompress(FieldBytes::from_slice(&x), Choice::from(odd as u8));
                let Some(point) = Option::<AffinePoint>::from(point) else { continue };
                let r = Scalar::from(small as u64);
                let r_inverse = Option::<Scalar>::from(r.invert()).unwrap();
                let key = (ProjectivePoint::from(point) * s - ProjectivePoint::GENERATOR * digest) * r_inverse;
                let key = VerifyingKey::from_affine(key.to_affine()).unwrap();
                let mut signature = [0; 65];
                signature[31] = small;
                signature[32..64].copy_from_slice(&s.to_bytes());
                signature[64] = 27 + 2 + odd as u8;
                assert_eq!(signer(&message, &signature), Some(address_of(&key)), "x = order + {small}");
                // The same with the other s, which turns the point over.
                let mut high = signature;
                high[32..64].copy_from_slice(&(-s).to_bytes());
                high[64] = 27 + 2 + !odd as u8;
                assert_eq!(signer(&message, &high), Some(address_of(&key)));
                // Read as an ordinary v, it is someone else's signature, or none.
                let mut plain = signature;
                plain[64] -= 2;
                assert_ne!(signer(&message, &plain), Some(address_of(&key)));
                found += 1;
            }
        }
        assert!(found > 0);
    }

    /// go-azimuth's own examples of batches found on Ethereum, with what it read from
    /// them, and its examples of signatures on them with who made them.
    #[test]
    fn go_azimuths_examples_from_the_main_network() {
        let first = unhex(
            "671738dada5c209c12b6501e80c62e091c27b14a8022d601a20473fdca35f685fa61153a73bef738ebfbf4cf95cca253dd39343ad3ae287e156228693b06f7a66defb761109e1d3c3bc5be348c28b22ae272d83709ea8a9acf031c671738dada5c209c12b6501e80c62e091c27b14a0a22d601a2000ef75011770757f561b40f3ba2dea676af739795101800457a19b68698bbdfde653437558121965eef535c95f967801c4e3a7928cb9d06a6fa66b4e97ca43e9500",
        );
        let target: Address = unhex("671738dada5c209c12b6501e80c62e091c27b14a").try_into().unwrap();
        let parsed = parse_batch(&first).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].signature.to_vec(), unhex("0ef75011770757f561b40f3ba2dea676af739795101800457a19b68698bbdfde653437558121965eef535c95f967801c4e3a7928cb9d06a6fa66b4e97ca43e9500"));
        assert_eq!(parsed[0].raw, unhex("671738dada5c209c12b6501e80c62e091c27b14a0a22d601a200"));
        assert_eq!((parsed[0].ship, parsed[0].proxy, parsed[0].action), (584450466, Proxy::Owner, Action::SetTransferProxy(target)));
        assert_eq!(parsed[1].raw, unhex("671738dada5c209c12b6501e80c62e091c27b14a8022d601a204"));
        assert_eq!((parsed[1].ship, parsed[1].proxy, parsed[1].action), (584450466, Proxy::Transfer, Action::TransferPoint { to: target, reset: false }));

        // Applied to the planet as it was: the owner set a transfer proxy, which then took
        // the planet.
        let ship = 584450466;
        let mut points = HashMap::new();
        let mut planet = point_of(&points, ship).unwrap();
        planet.dominion = Dominion::L2;
        planet.owner.address = unhex("942cc0b03f531bb7359347c4f272babb2eaf0c99").try_into().unwrap();
        points.insert(ship, planet);
        assert_eq!(receive_batch(&mut points, 1, &first).unwrap().outcomes.unwrap(), [Outcome::Applied, Outcome::Applied]);
        assert_eq!((points[&ship].owner.address, points[&ship].transfer_proxy.address, points[&ship].owner.nonce, points[&ship].transfer_proxy.nonce), (target, [0; 20], 1, 1));

        let second = unhex(
            "01f9900aa356eb818275c9bc58c355d075570094503a01a510270c78f30724fd7ef387f5c96dad3a565e78dcfda556e4d36a8257e187d7106ea5ecabd2f6b5fd82820342050000566725a9b02227bfc58d82218061a28d17d750b32e1828b7dc0d32675431a27e4d50b943315d9dcaf335e0a1c4418be025df934786f937e7e973d22e07d4e60601",
        );
        let parsed = parse_batch(&second).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].raw, unhex("00000001f9900aa356eb818275c9bc58c355d075570094503a01a510270c78f30724fd7ef387f5c96dad3a565e78dcfda556e4d36a8257e187d7106ea5ecabd2f6b5fd82820342050000"));
        let keys = Action::ConfigureKeys {
            encryption: unhex("f387f5c96dad3a565e78dcfda556e4d36a8257e187d7106ea5ecabd2f6b5fd82").try_into().unwrap(),
            authentication: unhex("f9900aa356eb818275c9bc58c355d075570094503a01a510270c78f30724fd7e").try_into().unwrap(),
            suite: 1,
            breach: false,
        };
        assert_eq!((parsed[0].ship, parsed[0].proxy, parsed[0].action), (54658304, Proxy::Owner, keys));
        let message = signed_message(1, 0, &parsed[0].raw);
        assert_eq!(signer(&message, &parsed[0].signature).unwrap().to_vec(), unhex("46b24384f42c324e71b60e7a5c24ad20ee6faa20"));

        // Two escapes, the first of them short at the front.
        let third = unhex(
            "3eb303beccfeac00594a127b1ea1a880de4c446971932d15b1b021ad13be5e09f98ebb71f45f06967f17bacca27d84b448ec5809c15ca48ff73d47a541e94be994ef774fe9b56ba01b00003eb30321cdfeac00845adadfb162528b3df3d407b8177060b5284f9d9257cee641b143e4cfd30af74ca01325ef50be6349d4ae69698992fcf74ef544e63ae1461d7ce1913000a3ef1c",
        );
        let parsed = parse_batch(&third).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[0].raw.clone(), parsed[0].ship, parsed[0].action), (unhex("00003eb30321cdfeac00"), 567148204, Action::Escape(16051)));
        assert_eq!((parsed[1].raw.clone(), parsed[1].ship, parsed[1].action), (unhex("00003eb303beccfeac00"), 3201105580, Action::Escape(16051)));

        let fourth = unhex("661803651AC018009399A8A143B21FCA343109128370BD9575B17F97BE491985D4932F309B4088BA5B9E2666ED5FF6322B0594AD31F6BD966B7D5A0B55738C43FA2E80517858F27C00");
        let parsed = parse_batch(&fourth).unwrap();
        assert_eq!((parsed[0].raw.clone(), parsed[0].ship, parsed[0].action), (unhex("0000661803651ac01800"), 1696251928, Action::Escape(26136)));

        let fifth = unhex("000000010A56E0A92352BF6723E518122DCE95A0EAAFBA3B3028B8806D5E7AD6AC56FF1E6A753FC18CC1BA858A4F344A164098247B607482812D6D5F75A8987EF62F9F3D82651AC018004962588F587083D2044965626440CB2281FE6DD413CF4F9EA90587BB98444DE5473DFF657EB3B0D6E03B67FA6367C483543AD7C2C8B678FF96A05E071B2F680200");
        let parsed = parse_batch(&fifth).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(matches!(parsed[0].action, Action::ConfigureKeys { suite: 1, breach: false, .. }));
        assert_eq!(parsed[0].raw.len(), 4 + 32 + 32 + 1 + 4 + 1);

        // A spawn signed with a count of one.
        let raw = unhex("bad132bf9c1269ee4fbc3affc537d3de3adb169b0001fbea010000fbea00");
        let signature: [u8; 65] = unhex("cc9dba6a6c90616dac53c1cff8e224e02ce9601fcec85c68f73a77bb5970354a523842d5335d847f0f76c95b7cbb735f0847b0e22c9040da1dd1ed3ac4c2b09900").try_into().unwrap();
        let parsed = parse_batch(&[raw.clone(), signature.to_vec()].concat()).unwrap();
        assert_eq!((parsed[0].ship, parsed[0].action), (64490, Action::Spawn { ship: 130026, to: unhex("bad132bf9c1269ee4fbc3affc537d3de3adb169b").try_into().unwrap() }));
        assert_eq!(signer(&signed_message(1, 1, &raw), &signature).unwrap().to_vec(), unhex("bad132bf9c1269ee4fbc3affc537d3de3adb169b"));
        assert_ne!(signer(&signed_message(1, 0, &raw), &signature).unwrap().to_vec(), unhex("bad132bf9c1269ee4fbc3affc537d3de3adb169b"));
    }
}
