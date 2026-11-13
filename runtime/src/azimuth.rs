//! Reading Urbit ID: which key belongs to which ship, as Azimuth has it.
//!
//! Azimuth is a contract on Ethereum that lists, for every galaxy, star and planet, who owns
//! it, its networking keys, and its sponsor. Some ships are kept there directly ("layer 1").
//! Most planets are not: their owners moved them, or their star made them, on "layer 2",
//! where changes are batched up and only the batches are written to Ethereum. The state of a
//! layer 2 ship is what those batches add up to. Urbit runs a service, the roller, that adds
//! them up and answers questions about the result.
//!
//! What is done here is to ask, one ship at a time:
//!
//! 1. Ethereum, for the ship's owner. The contract is the authority on which layer a ship
//!    is on: a ship moved to layer 2 is owned, on Ethereum, by a fixed address that nobody
//!    holds, and a ship that Ethereum has never heard of can exist on layer 2 only if its
//!    star (or galaxy) has handed its right to make ships to that same address. Both are
//!    for good: there is no way back.
//! 2. If the ship is on layer 1, Ethereum again, for its keys. The roller is not asked.
//! 3. If Ethereum says the ship is, or can only be, on layer 2, the roller, for its keys.
//!
//! So the roller's word is taken only for ships that Ethereum itself places on layer 2, and
//! for those it is taken whole: nothing here adds up the batches to check it. Whoever runs
//! the Ethereum endpoint is trusted for everything. Running one's own node, and reading
//! layer 2 from Ethereum without the roller, are what would remove that trust.
//!
//! Moons are not in Azimuth. A moon's key is vouched for by its parent: see `crate::moon`.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use serde_json::{json, Value};
use urbit_id::ob;

/// What Urbit ID lists for a ship.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The ship's authentication key (ed25519), the public half, if it has one it can be
    /// reached by. A ship whose keys have never been set, or have been taken away, or are
    /// of a kind not known here, has none.
    pub key: Option<[u8; 32]>,
    /// How many times the ship's keys have been set, taking them away included. It only
    /// ever goes up, which is how an old answer is told from a new one. Urbit calls this
    /// the ship's life.
    pub revision: u32,
    /// How many times the ship has started afresh, forgetting what it knew. Urbit calls
    /// this its rift.
    pub continuity: u32,
    /// The ship's sponsor, if it has one. A galaxy is its own.
    pub sponsor: Option<u32>,
}

/// Somewhere to learn which key belongs to which galaxy, star or planet.
pub trait Keys: Send + Sync {
    /// What is listed for the ship with this number. `Ok(None)` means the answer is known,
    /// and it is that there is no such ship. `Err` means the answer could not be had, and
    /// says why.
    ///
    /// This may take as long as asking over a network takes. It is never called from a
    /// thread that must not wait.
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String>;
}

/// Where Azimuth is, and whom to ask about it.
#[derive(Clone, Debug)]
pub struct AzimuthConfig {
    /// An Ethereum node's JSON-RPC address, such as `https://ethereum.publicnode.com`.
    pub ethereum: String,
    /// The roller's JSON-RPC address, for ships on layer 2. Without one, those ships
    /// cannot be looked up.
    pub roller: Option<String>,
    /// The Azimuth contract. It has never moved.
    pub contract: [u8; 20],
    /// The address that owns, on Ethereum, every ship that is on layer 2.
    pub deposit: [u8; 20],
    /// How long one question to either may take.
    pub timeout: Duration,
}

/// The roller Urbit runs.
pub const ROLLER: &str = "https://roller.urbit.org/v1/roller";

impl AzimuthConfig {
    /// Azimuth on Ethereum's main network, asked through `ethereum`, with Urbit's roller.
    pub fn mainnet(ethereum: &str) -> AzimuthConfig {
        AzimuthConfig {
            ethereum: ethereum.to_string(),
            roller: Some(ROLLER.to_string()),
            contract: [0x22, 0x3c, 0x06, 0x7f, 0x8c, 0xf2, 0x8a, 0xe1, 0x73, 0xee, 0x5c, 0xaf, 0xea, 0x60, 0xca, 0x44, 0xc3, 0x35, 0xfe, 0xcb],
            deposit: [0x11; 20],
            timeout: Duration::from_secs(10),
        }
    }
}

/// Azimuth, asked over the network.
pub struct Azimuth {
    cfg: AzimuthConfig,
    agent: ureq::Agent,
}

impl fmt::Debug for Azimuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Azimuth")
    }
}

/// The first four bytes of the hash of `points(uint32)` and of `rights(uint32)`, which is
/// how a contract is told which of its tables is being read.
const POINTS: [u8; 4] = [0x63, 0xfa, 0x9a, 0x87];
const RIGHTS: [u8; 4] = [0x04, 0xbc, 0x94, 0xe5];

/// What the roller says of a ship it has never heard of.
const NOT_FOUND: &str = "Resource not found";

/// The most that is read of any answer. A real one is under two thousand bytes.
const MOST_ANSWER_BYTES: u64 = 64 << 10;

/// Who has rights over a ship on Ethereum: the two that say which layer it is on.
struct Rights {
    owner: [u8; 20],
    spawner: [u8; 20],
}

impl Azimuth {
    pub fn new(cfg: AzimuthConfig) -> Azimuth {
        // No redirects: an answer is taken only from the address that was asked.
        // The limit covers the whole of a question, and the connecting on its own, which
        // would otherwise have a longer limit of its own.
        let agent = ureq::AgentBuilder::new().timeout(cfg.timeout).timeout_connect(cfg.timeout).redirects(0).build();
        Azimuth { cfg, agent }
    }

    /// Send one question and read the answer's `result`. `Ok(None)` if the answer is that
    /// there is no such thing as was asked about.
    fn ask(&self, url: &str, method: &str, params: Value) -> Result<Option<Value>, String> {
        // The roller answers only a question whose number is written as text.
        let question = json!({ "jsonrpc": "2.0", "id": "1", "method": method, "params": params }).to_string();
        let sent = self.agent.post(url).set("Content-Type", "application/json").send_string(&question);
        let answer = sent.map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("{method} was answered with HTTP status {code}"),
            ureq::Error::Transport(e) => format!("{method} could not be asked: {e}"),
        })?;
        let mut text = Vec::new();
        answer.into_reader().take(MOST_ANSWER_BYTES + 1).read_to_end(&mut text).map_err(|e| format!("the answer to {method} could not be read: {e}"))?;
        if text.len() as u64 > MOST_ANSWER_BYTES {
            return Err(format!("the answer to {method} was too long to be one"));
        }
        let mut answer: Value = serde_json::from_slice(&text).map_err(|_| format!("the answer to {method} made no sense"))?;
        if let Some(error) = answer.get("error").filter(|error| !error.is_null()) {
            let why = error.get("message").and_then(Value::as_str).unwrap_or("no reason given");
            if why == NOT_FOUND {
                return Ok(None);
            }
            return Err(format!("{method} was refused: {}", why.chars().take(200).collect::<String>()));
        }
        match answer.get_mut("result").map(Value::take) {
            Some(result) if !result.is_null() => Ok(Some(result)),
            _ => Err(format!("the answer to {method} made no sense")),
        }
    }

    /// Read one row of one of the contract's tables: so many words of thirty-two bytes.
    fn read(&self, table: [u8; 4], ship: u32, words: usize) -> Result<Vec<[u8; 32]>, String> {
        let mut data = table.to_vec();
        data.extend_from_slice(&[0; 28]);
        data.extend_from_slice(&ship.to_be_bytes());
        let call = json!([{ "to": hex(&self.cfg.contract), "data": hex(&data) }, "latest"]);
        let result = self.ask(&self.cfg.ethereum, "eth_call", call)?.ok_or("Ethereum's answer was not a row of Azimuth's")?;
        let bytes = result.as_str().and_then(unhex).filter(|bytes| bytes.len() == 32 * words);
        let bytes = bytes.ok_or("Ethereum's answer was not a row of Azimuth's")?;
        Ok(bytes.chunks(32).map(|word| word.try_into().expect("thirty-two bytes")).collect())
    }

    fn rights(&self, ship: u32) -> Result<Rights, String> {
        let row = self.read(RIGHTS, ship, 5)?;
        Ok(Rights { owner: address(&row[0])?, spawner: address(&row[2])? })
    }

    /// The keys Ethereum holds for a ship that is on layer 1.
    fn on_ethereum(&self, ship: u32) -> Result<Option<Listing>, String> {
        let row = self.read(POINTS, ship, 10)?;
        // In the order the contract keeps them: encryption key, authentication key, has a
        // sponsor, active, escape requested, sponsor, escape requested to, kind of keys,
        // key revision, continuity.
        let (has_sponsor, sponsor) = (flag(&row[2])?, number(&row[5])?);
        let (suite, revision, continuity) = (number(&row[7])?, number(&row[8])?, number(&row[9])?);
        Ok(Some(listed(&row[1], suite, revision, continuity, has_sponsor.then_some(sponsor))))
    }

    /// What the roller has for a ship on layer 2. `None` if it does not have the ship on
    /// layer 2 at all.
    fn on_roller(&self, ship: u32) -> Result<Option<Listing>, String> {
        let name = ob::ship_name(ship);
        let Some(roller) = &self.cfg.roller else {
            return Err(format!("{name} is on layer 2, and there is no roller to ask about it"));
        };
        let senseless = || "the roller's answer made no sense".to_string();
        // A ship the roller has never heard of is not on layer 2.
        let Some(point) = self.ask(roller, "getPoint", json!({ "ship": name }))? else {
            return Ok(None);
        };
        // The roller knows three places a ship can be. An answer that names none of them
        // is no answer.
        match point.get("dominion").and_then(Value::as_str) {
            Some("l2") => {}
            Some("l1" | "spawn") => return Ok(None),
            _ => return Err(senseless()),
        }
        let network = point.get("network").ok_or_else(senseless)?;
        let keys = network.get("keys").ok_or_else(senseless)?;
        let counted = |value: Option<&Value>| value.and_then(Value::as_str).and_then(|digits| digits.parse::<u32>().ok()).ok_or_else(senseless);
        // The key is written as a number, so one that begins with zeros is written short.
        let digits = keys.get("auth").and_then(Value::as_str).and_then(|key| key.strip_prefix("0x")).filter(|digits| digits.len() <= 64).ok_or_else(senseless)?;
        let key: [u8; 32] = unhex(&format!("0x{digits:0>64}")).and_then(|key| key.try_into().ok()).ok_or_else(senseless)?;
        let sponsor = network.get("sponsor").ok_or_else(senseless)?;
        let has_sponsor = sponsor.get("has").and_then(Value::as_bool).ok_or_else(senseless)?;
        let who = sponsor.get("who").and_then(Value::as_u64).and_then(|who| u32::try_from(who).ok()).ok_or_else(senseless)?;
        let (suite, revision, continuity) = (counted(keys.get("suite"))?, counted(keys.get("life"))?, counted(network.get("rift"))?);
        Ok(Some(listed(&key, suite, revision, continuity, has_sponsor.then_some(who))))
    }
}

impl Keys for Azimuth {
    fn listing(&self, ship: u32) -> Result<Option<Listing>, String> {
        let rights = self.rights(ship)?;
        if rights.owner == self.cfg.deposit {
            // Moved to layer 2, for good. The roller must know it.
            let listing = self.on_roller(ship)?;
            return listing.map(Some).ok_or_else(|| format!("{} is on layer 2, and the roller says it is not", ob::ship_name(ship)));
        }
        if rights.owner != [0; 20] {
            return self.on_ethereum(ship);
        }
        // A planet's number has its star's in its low half. One with a galaxy's there has
        // no star, and nothing can make it.
        if ship > 0xffff && ship & 0xffff < 0x100 {
            return Ok(None);
        }
        // Ethereum has never heard of it. It can still exist, on layer 2, if the ship above
        // it makes its ships there. And if Ethereum has never heard of that one either, it
        // too may have been made on layer 2, by the galaxy above it. A galaxy has nothing
        // above it, and is always on Ethereum.
        let mut above = ship;
        while above > 0xff {
            above = if above > 0xffff { above & 0xffff } else { above & 0xff };
            let makes = self.rights(above)?;
            if makes.owner == self.cfg.deposit || makes.spawner == self.cfg.deposit {
                return self.on_roller(ship);
            }
            if makes.owner != [0; 20] {
                // It is on Ethereum and makes its ships there, where this one is not.
                break;
            }
        }
        Ok(None)
    }
}

/// A ship's listing. It has a key if its keys have been set and are of the one kind
/// there is.
///
/// Azimuth keeps a key as a number, which is the key's bytes in the opposite order to the
/// one everything else uses.
pub(crate) fn listed(key: &[u8; 32], suite: u32, revision: u32, continuity: u32, sponsor: Option<u32>) -> Listing {
    let usable = suite == 1 && revision != 0 && *key != [0; 32];
    let key = usable.then(|| {
        let mut key = *key;
        key.reverse();
        key
    });
    Listing { key, revision, continuity, sponsor }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    bytes.iter().for_each(|byte| out.push_str(&format!("{byte:02x}")));
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    if digits.len() % 2 != 0 {
        return None;
    }
    let digit = |byte: u8| (byte as char).to_digit(16).map(|digit| digit as u8);
    digits.chunks(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

/// A word that holds a number of thirty-two bits: the rest of it is zeros.
fn number(word: &[u8; 32]) -> Result<u32, String> {
    if word[..28] != [0; 28] {
        return Err("Ethereum's answer was not a row of Azimuth's".into());
    }
    Ok(u32::from_be_bytes(word[28..].try_into().expect("four bytes")))
}

fn flag(word: &[u8; 32]) -> Result<bool, String> {
    match number(word)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("Ethereum's answer was not a row of Azimuth's".into()),
    }
}

/// A word that holds an address: twelve zeros, then its twenty bytes.
fn address(word: &[u8; 32]) -> Result<[u8; 20], String> {
    if word[..12] != [0; 12] {
        return Err("Ethereum's answer was not a row of Azimuth's".into());
    }
    Ok(word[12..].try_into().expect("twenty bytes"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A stand-in for an Ethereum node and a roller, on this machine. It answers each
    /// question with whatever it was told to, by what the question contains, and counts
    /// the questions.
    pub(crate) struct Answers {
        pub url: String,
        pub asked: Arc<AtomicUsize>,
        said: Arc<Mutex<HashMap<String, String>>>,
    }

    impl Answers {
        pub(crate) fn start() -> Answers {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (asked, said) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(HashMap::<String, String>::new())));
            let (counting, saying) = (asked.clone(), said.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let (mut length, mut line) = (0usize, String::new());
                    while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                        line.clear();
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let body = String::from_utf8(body).unwrap();
                    counting.fetch_add(1, Ordering::SeqCst);
                    // As the real roller does, turn away a question numbered with a number.
                    let numbered = body.contains(r#""id":"1""#) || !body.contains("getPoint");
                    let answer = saying.lock().unwrap().iter().find(|(asked, _)| numbered && body.contains(asked.as_str())).map(|(_, answer)| answer.clone());
                    let (status, answer) = match answer {
                        Some(answer) => ("200 OK", answer),
                        None => ("500 Internal Server Error", String::new()),
                    };
                    let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len());
                }
            });
            Answers { url, asked, said }
        }

        /// Answer any question that contains `asked` with `answer`, whole.
        pub(crate) fn say(&self, asked: &str, answer: &str) {
            self.said.lock().unwrap().insert(asked.to_string(), answer.to_string());
        }

        pub(crate) fn forget(&self, asked: &str) {
            self.said.lock().unwrap().remove(asked);
        }

        fn row(table: [u8; 4], ship: u32) -> String {
            format!("{}{:064x}", hex(&table), ship)
        }

        /// Who owns a ship on Ethereum, and who may make its ships.
        pub(crate) fn owned(&self, ship: u32, owner: [u8; 20], spawner: [u8; 20]) {
            let word = |address: [u8; 20]| format!("{:0>64}", &hex(&address)[2..]);
            let row = format!("0x{}{}{}{}{}", word(owner), word([0; 20]), word(spawner), word([0; 20]), word([0; 20]));
            self.say(&Self::row(RIGHTS, ship), &format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{row}"}}"#));
        }

        /// A ship's keys on Ethereum.
        pub(crate) fn keyed(&self, ship: u32, key: &[u8; 32], revision: u32, sponsor: u32) {
            let mut written = *key;
            written.reverse();
            let word = |number: u32| format!("{number:064x}");
            let row = format!("0x{}{}{}{}{}{}{}{}{}{}", &hex(&[9; 32])[2..], &hex(&written)[2..], word(1), word(1), word(0), word(sponsor), word(0), word(1), word(revision), word(0));
            self.say(&Self::row(POINTS, ship), &format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{row}"}}"#));
        }

        /// A ship's keys on the roller, as a ship on layer 2.
        pub(crate) fn rolled(&self, ship: u32, key: &[u8; 32], revision: u32, sponsor: u32) {
            let mut written = *key;
            written.reverse();
            // As the roller writes a number: no zeros in front.
            let digits = hex(&written)[2..].trim_start_matches('0').to_string();
            let point = format!(
                r#"{{"id":"1","jsonrpc":"2.0","result":{{"dominion":"l2","ownership":{{}},"network":{{"keys":{{"life":"{revision}","suite":"1","auth":"0x{digits}","crypt":"0x9"}},"sponsor":{{"has":true,"who":{sponsor}}},"rift":"0"}}}}}}"#
            );
            self.say(&format!(r#""ship":"{}""#, ob::ship_name(ship)), &point);
        }

        pub(crate) fn azimuth(&self) -> Azimuth {
            Azimuth::new(self.config())
        }

        pub(crate) fn config(&self) -> AzimuthConfig {
            AzimuthConfig { roller: Some(self.url.clone()), timeout: Duration::from_secs(5), ..AzimuthConfig::mainnet(&self.url) }
        }
    }

    const OWNER: [u8; 20] = [0xab; 20];
    const DEPOSIT: [u8; 20] = [0x11; 20];
    const NOBODY: [u8; 20] = [0; 20];

    /// What Ethereum and the roller really said about ~zod on 13 November 2026.
    const ZOD_RIGHTS: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000009f57c77b1095bd5db0558b9cb9b8e6fc67375e3c0000000000000000000000005eb03d359e6815d6407771ab69e80af5644104b90000000000000000000000009f57c77b1095bd5db0558b9cb9b8e6fc67375e3c0000000000000000000000009f57c77b1095bd5db0558b9cb9b8e6fc67375e3c0000000000000000000000000000000000000000000000000000000000000000"}"#;
    const ZOD_POINT: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0xa5f1a3a6662b675c109be8ce642c1b4add53df18609738b8d59bbc1d8d508831bd44cee24b74632e65d842ce0fc0bf6e109675e6aca4a9d94c33657e1cc2423100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000002"}"#;
    const ZOD_ROLLED: &str = r#"{"id":"1","jsonrpc":"2.0","result":{"dominion":"l1","ownership":{"transferProxy":{"address":"0x0000000000000000000000000000000000000000","nonce":0},"votingProxy":{"address":"0x9f57c77b1095bd5db0558b9cb9b8e6fc67375e3c","nonce":0},"spawnProxy":{"address":"0x9f57c77b1095bd5db0558b9cb9b8e6fc67375e3c","nonce":0},"managementProxy":{"address":"0x5eb03d359e6815d6407771ab69e80af5644104b9","nonce":0},"owner":{"address":"0x9f57c77b1095bd5db0558b9cb9b8e6fc67375e3c","nonce":0}},"network":{"keys":{"life":"6","suite":"1","auth":"0xbd44cee24b74632e65d842ce0fc0bf6e109675e6aca4a9d94c33657e1cc24231","crypt":"0xa5f1a3a6662b675c109be8ce642c1b4add53df18609738b8d59bbc1d8d508831"},"sponsor":{"has":true,"who":0},"rift":"2"}}}"#;

    const NEVER_HEARD: &str = r#"{"id":"1","error":{"code":-32000,"message":"Resource not found"},"jsonrpc":"2.0"}"#;

    /// The key a ship is listed with, if it is listed with one.
    fn key_of(azimuth: &Azimuth, ship: u32) -> Option<[u8; 32]> {
        azimuth.listing(ship).unwrap().and_then(|listing| listing.key)
    }

    fn zod_key() -> [u8; 32] {
        let mut key: [u8; 32] = unhex("0xbd44cee24b74632e65d842ce0fc0bf6e109675e6aca4a9d94c33657e1cc24231").unwrap().try_into().unwrap();
        key.reverse();
        key
    }

    #[test]
    fn a_ship_on_ethereum_is_read_from_ethereum_as_it_really_answers() {
        let answers = Answers::start();
        answers.say(&Answers::row(RIGHTS, 0), ZOD_RIGHTS);
        answers.say(&Answers::row(POINTS, 0), ZOD_POINT);
        let listing = answers.azimuth().listing(0).unwrap().unwrap();
        assert_eq!(listing, Listing { key: Some(zod_key()), revision: 6, continuity: 2, sponsor: Some(0) });
        // The key is one a ship could hold: turned the right way round, it is a point on
        // the curve. Turned the other way it is not.
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&zod_key()).is_ok());
        let mut backwards = zod_key();
        backwards.reverse();
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&backwards).is_err());
        // Two questions, both to Ethereum. The roller was not asked, and its having another
        // answer ready changes nothing.
        assert_eq!(answers.asked.load(Ordering::SeqCst), 2);
        answers.rolled(0, &[7; 32], 9, 0);
        assert_eq!(key_of(&answers.azimuth(), 0), Some(zod_key()));
    }

    #[test]
    fn a_ship_on_layer_two_is_read_from_the_roller_and_only_when_ethereum_says_it_is_there() {
        let answers = Answers::start();
        let azimuth = answers.azimuth();
        let (star, planet, born_there, key) = (0x0100u32, 0x0001_0100u32, 0x0002_0100u32, [0x42; 32]);
        // Moved to layer 2: Ethereum has it owned by the address nobody holds. What
        // Ethereum still has for its keys is from before, and is not used.
        answers.owned(planet, DEPOSIT, NOBODY);
        answers.keyed(planet, &[1; 32], 3, star);
        answers.rolled(planet, &key, 5, star);
        assert_eq!(azimuth.listing(planet).unwrap(), Some(Listing { key: Some(key), revision: 5, continuity: 0, sponsor: Some(star) }));

        // Made on layer 2: Ethereum has never heard of it, and its star makes ships there.
        answers.owned(born_there, NOBODY, NOBODY);
        answers.owned(star, OWNER, DEPOSIT);
        let mut short = [0x33; 32];
        short[29..].fill(0);
        answers.rolled(born_there, &short, 1, star);
        assert_eq!(key_of(&azimuth, born_there), Some(short), "a key the roller writes short");
        // Or the star itself has been moved there.
        answers.owned(star, DEPOSIT, NOBODY);
        assert_eq!(azimuth.listing(born_there).unwrap().unwrap().revision, 1);

        // A star that makes its ships on Ethereum: a planet Ethereum has not heard of does
        // not exist, whatever the roller would say.
        answers.owned(star, OWNER, OWNER);
        let before = answers.asked.load(Ordering::SeqCst);
        assert_eq!(azimuth.listing(born_there).unwrap(), None);
        assert_eq!(answers.asked.load(Ordering::SeqCst), before + 2, "its rights, and its star's");
        // And a planet that is on Ethereum is read from Ethereum, whatever the roller says.
        answers.owned(planet, OWNER, NOBODY);
        assert_eq!(key_of(&azimuth, planet), Some([1; 32]));

        // The roller has what Ethereum says is on layer 2 as not there: no answer, which
        // is not the same as "no such ship".
        answers.owned(planet, DEPOSIT, NOBODY);
        answers.say(&format!(r#""ship":"{}""#, ob::ship_name(planet)), ZOD_ROLLED);
        assert!(azimuth.listing(planet).unwrap_err().contains("the roller says it is not"));
        // A star that was itself made on layer 2, by a galaxy that makes its stars there:
        // Ethereum has heard of neither the star nor its planet.
        answers.owned(star, NOBODY, NOBODY);
        answers.owned(0, OWNER, DEPOSIT);
        assert_eq!(azimuth.listing(born_there).unwrap().unwrap().revision, 1);
        // A galaxy that makes its stars on Ethereum: a star Ethereum has not heard of does
        // not exist, and neither do its planets.
        answers.owned(0, OWNER, OWNER);
        assert_eq!(azimuth.listing(born_there).unwrap(), None);

        // A ship that could have been made on layer 2 and was not: the roller has never
        // heard of it, or has it as something else.
        answers.owned(star, OWNER, DEPOSIT);
        for said in [NEVER_HEARD, ZOD_ROLLED] {
            answers.say(&format!(r#""ship":"{}""#, ob::ship_name(born_there)), said);
            assert_eq!(azimuth.listing(born_there).unwrap(), None);
        }

        // An answer from the roller that makes no sense is no answer either way. It is not
        // taken to mean the ship does not exist, which would have its key dropped.
        let asked = format!(r#""ship":"{}""#, ob::ship_name(born_there));
        for said in [r#"{"id":"1","jsonrpc":"2.0","result":{}}"#, r#"{"id":"1","jsonrpc":"2.0","result":{"dominion":"l3"}}"#, r#"{"id":"1","jsonrpc":"2.0","result":{"dominion":7}}"#] {
            answers.say(&asked, said);
            assert!(azimuth.listing(born_there).is_err(), "{said}");
        }
        answers.say(&asked, r#"{"id":"1","jsonrpc":"2.0","result":{"dominion":"spawn"}}"#);
        assert_eq!(azimuth.listing(born_there).unwrap(), None);

        // With no roller to ask, a ship on layer 2 cannot be looked up, and one on
        // Ethereum can.
        let alone = Azimuth::new(AzimuthConfig { roller: None, ..answers.config() });
        assert!(alone.listing(planet).unwrap_err().contains("no roller"));
        answers.owned(0, OWNER, OWNER);
        answers.keyed(0, &[5; 32], 2, 0);
        assert_eq!(key_of(&alone, 0), Some([5; 32]));
    }

    #[test]
    fn a_ship_without_keys_has_no_listing_and_an_answer_that_makes_no_sense_is_not_one() {
        let answers = Answers::start();
        let azimuth = answers.azimuth();
        // A galaxy nobody owns is no ship. One that is owned and has never set keys is a
        // ship with no key, and so is one whose keys have been taken away: and that one
        // still says how many times its keys have been set, which is what tells an answer
        // from before they were taken away from one after.
        answers.owned(7, NOBODY, NOBODY);
        assert_eq!(azimuth.listing(7).unwrap(), None);
        answers.owned(7, OWNER, NOBODY);
        answers.keyed(7, &[4; 32], 0, 7);
        assert_eq!(azimuth.listing(7).unwrap(), Some(Listing { key: None, revision: 0, continuity: 0, sponsor: Some(7) }));
        answers.keyed(7, &[0; 32], 3, 7);
        assert_eq!(azimuth.listing(7).unwrap(), Some(Listing { key: None, revision: 3, continuity: 0, sponsor: Some(7) }));
        answers.keyed(7, &[4; 32], 1, 7);
        assert_eq!(key_of(&azimuth, 7), Some([4; 32]));
        // Keys of a kind not known here.
        let row = Answers::row(POINTS, 7);
        let good = answers.said.lock().unwrap()[&row].clone();
        let words: Vec<String> = good.split("0x").nth(1).unwrap().trim_end_matches("\"}").as_bytes().chunks(64).map(|word| String::from_utf8(word.to_vec()).unwrap()).collect();
        let with = |at: usize, word: &str| {
            let mut words = words.clone();
            words[at] = word.to_string();
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, words.concat())
        };
        answers.say(&row, &with(7, &format!("{:064x}", 2)));
        assert_eq!(key_of(&azimuth, 7), None);

        // An answer that is a good row with a great deal of nothing after it is not read to
        // the end, and is refused for its length.
        let long = format!("{}{}", good, " ".repeat(MOST_ANSWER_BYTES as usize));
        answers.say(&row, &long);
        assert!(azimuth.listing(7).unwrap_err().contains("too long"));
        answers.say(&row, &format!("{}{}", good, " ".repeat(1000)));
        assert!(key_of(&azimuth, 7).is_some());

        // Not rows: too short, too long, a number too big for its place, a flag that is
        // neither yes nor no, not hex, not JSON, an error, nothing.
        let not = [
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, words[..9].concat()),
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}00"}}"#, words.concat()),
            with(8, &format!("{:064x}", 1u64 << 32)),
            with(2, &format!("{:064x}", 2)),
            with(1, &"z".repeat(64)),
            "not an answer".to_string(),
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"execution reverted"}}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string(),
            r#"{"jsonrpc":"2.0","id":1}"#.to_string(),
        ];
        for answer in not {
            answers.say(&row, &answer);
            assert!(azimuth.listing(7).is_err(), "{}", &answer[..answer.len().min(120)]);
        }
        answers.say(&row, &good);
        assert!(key_of(&azimuth, 7).is_some());
        // An owner that is not an address.
        let rights = Answers::row(RIGHTS, 7);
        let was = answers.said.lock().unwrap()[&rights].clone();
        answers.say(&rights, &was.replacen("0x0", "0x1", 1));
        assert!(azimuth.listing(7).is_err());
        // Nobody answering at all, and an answer that is a refusal.
        answers.forget(&rights);
        assert!(azimuth.listing(7).unwrap_err().contains("500"));
        let nowhere = Azimuth::new(AzimuthConfig { timeout: Duration::from_millis(300), ..AzimuthConfig::mainnet("http://127.0.0.1:1") });
        assert!(nowhere.listing(7).is_err());
        // Something that takes the question and never answers is given up on in the time
        // allowed, and not in whatever time it likes.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let unanswered = Azimuth::new(AzimuthConfig { timeout: Duration::from_millis(400), ..AzimuthConfig::mainnet(&format!("http://{}", silent.local_addr().unwrap())) });
        let started = std::time::Instant::now();
        assert!(unanswered.listing(7).is_err());
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        drop(silent);

        // The roller's answers are held to the same standard.
        let (planet, star) = (0x0001_0100u32, 0x0100u32);
        answers.owned(planet, DEPOSIT, NOBODY);
        answers.rolled(planet, &[6; 32], 2, star);
        let asked = format!(r#""ship":"{}""#, ob::ship_name(planet));
        let good = answers.said.lock().unwrap()[&asked].clone();
        assert!(key_of(&azimuth, planet).is_some());
        let not = [
            good.replace(r#""life":"2""#, r#""life":2"#),
            good.replace(r#""life":"2""#, r#""life":"-2""#),
            good.replace(r#""auth":"0x"#, r#""auth":""#),
            good.replace(r#""auth":"0x"#, r#""auth":"0x1234567"#),
            good.replace(r#""who":256"#, r#""who":4294967296"#),
            good.replace(r#""has":true"#, r#""has":"yes""#),
            good.replace(r#""rift":"0""#, r#""rift":"""#),
            good.replace(r#""network""#, r#""notwork""#),
            // A ship that is nowhere the roller knows of, or is said to be nowhere at all.
            good.replace(r#""dominion":"l2""#, r#""dominion":"l3""#),
            good.replace(r#""dominion":"l2","#, ""),
            r#"{"id":"1","jsonrpc":"2.0","result":{}}"#.to_string(),
            r#"{"id":"1","jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"}}"#.to_string(),
            // What the real roller says of a ship it has never heard of. Ethereum has this
            // one on layer 2, so that is no answer.
            NEVER_HEARD.to_string(),
        ];
        for answer in not {
            answers.say(&asked, &answer);
            assert!(azimuth.listing(planet).is_err(), "{answer}");
        }
        // No keys there yet, or keys of another kind: a ship with no key.
        for answer in [good.replace(r#""life":"2""#, r#""life":"0""#), good.replace(r#""suite":"1""#, r#""suite":"2""#)] {
            answers.say(&asked, &answer);
            assert!(azimuth.listing(planet).unwrap().is_some_and(|listing| listing.key.is_none()), "{answer}");
        }
        // A planet with a galaxy's number where its star's should be cannot have been
        // made by anything, on either layer, and nobody is asked about what made it.
        answers.owned(0x0003_0007, NOBODY, NOBODY);
        answers.owned(7, OWNER, DEPOSIT);
        let before = answers.asked.load(Ordering::SeqCst);
        assert_eq!(azimuth.listing(0x0003_0007).unwrap(), None);
        assert_eq!(answers.asked.load(Ordering::SeqCst), before + 1);

        // An answer that goes on and on without ending is cut off at the most an answer
        // may be, and refused for its length, without waiting for the rest.
        let endless = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = endless.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = endless.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                line.clear();
            }
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}", " ".repeat(MOST_ANSWER_BYTES as usize + 4096));
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(4));
        });
        let patient = Azimuth::new(AzimuthConfig { timeout: Duration::from_secs(3), ..AzimuthConfig::mainnet(&format!("http://{address}")) });
        let started = std::time::Instant::now();
        assert!(patient.listing(7).unwrap_err().contains("too long"));
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    /// Asks the real Ethereum and the real roller. Not run with the rest: it needs the
    /// network, and an endpoint that may be busy. `cargo test -p runtime --lib -- --ignored`.
    #[test]
    #[ignore]
    fn the_real_azimuth_answers() {
        let ethereum = std::env::var("ETHEREUM_RPC").unwrap_or_else(|_| "https://ethereum.publicnode.com".into());
        let azimuth = Azimuth::new(AzimuthConfig::mainnet(&ethereum));
        for name in ["~zod", "~marzod"] {
            let listing = azimuth.listing(ob::ship_number(name).unwrap()).unwrap().unwrap();
            assert!(ed25519_dalek::VerifyingKey::from_bytes(&listing.key.unwrap()).is_ok(), "{name}");
            println!("{name}: revision {}, continuity {}, sponsor {:?}", listing.revision, listing.continuity, listing.sponsor.map(ob::ship_name));
        }
        // ~pocwet is a star on Ethereum that makes its planets on layer 2. The first of
        // its planets found with keys is one Ethereum has never heard of, read from the
        // roller.
        let star = ob::ship_number("~pocwet").unwrap();
        assert_eq!(azimuth.rights(star).unwrap().spawner, DEPOSIT);
        let found = (1..=64u32).map(|nth| nth << 16 | star).find_map(|planet| {
            let listing = azimuth.listing(planet);
            println!("a planet of ~pocwet: {:?}", listing.as_ref().map(|listing| listing.map(|listing| listing.revision)));
            listing.ok().flatten().filter(|listing| listing.key.is_some()).map(|listing| (planet, listing))
        });
        let (planet, listing) = found.expect("one of the star's first planets has keys");
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&listing.key.unwrap()).is_ok());
        let owner = azimuth.rights(planet).unwrap().owner;
        assert!(owner == NOBODY || owner == DEPOSIT);
        println!("a planet of ~pocwet, on layer 2: revision {}, sponsor {:?}", listing.revision, listing.sponsor.map(ob::ship_name));
        // Without the roller it cannot be looked up, and is not taken for a ship with no keys.
        let alone = Azimuth::new(AzimuthConfig { roller: None, ..AzimuthConfig::mainnet(&ethereum) });
        assert!(alone.listing(planet).is_err());
    }
}
