//! Reading what was written to Ethereum: how far the chain goes, a contract's logs over a
//! range of blocks, and the input of a transaction. This is what the local copy of Azimuth
//! (`crate::replica`) is built from.
//!
//! Ethereum nodes that anyone may use differ in what they allow: how many blocks one
//! question may cover, how many logs one answer may hold, how often they may be asked, and
//! whether several questions may go in one request. This file asks plainly and says what
//! went wrong; `crate::replica` decides how to ask again.
//!
//! The node is trusted to tell the truth about the chain. It is not trusted to be well
//! made: every answer is bounded in size and checked to be what was asked for (logs of the
//! contract asked about, from the blocks asked about, in order; the transaction asked for),
//! and anything else is an error, never an empty answer.
//!
//! Every field read from a node, and what each is checked against. Two fields that are read
//! and contradict each other are an error; a field not in this list is not read at all, and
//! nothing depends on it. ("A range" is the blocks read in one step: both contracts' logs for
//! them, and the batches' transactions. Some checks are made here, some in `crate::replica`,
//! marked so.)
//!
//! Of every answer:
//! - `jsonrpc`: text, "2.0" (checked on every answer that is not a refusal).
//! - `id`: the number of the question asked, as text. A refusal may carry another number,
//!   however written, or `null` (a node that could not read a question cannot say which it
//!   was). Among answers to questions asked at once, a refusal is taken before the others are
//!   counted or matched to their questions.
//! - `result`: of the shape asked for. `null` is an answer with nothing in it: an error.
//! - `error`: when there, an object, never `null`; its `message` is text or `null`, and only
//!   reported. A refusal never becomes state. An answer with an error and a result that is
//!   not `null` is refused.
//! Every value is read only as the kind listed: an object as an object (never its fields in
//! order as a list), text as text, a list as a list, a yes or no as one, and `null` nowhere
//! but where this list says so. Numbers and hashes are text, written as Ethereum writes them.
//!
//! Of the final block (`eth_getBlockByNumber("finalized")`): `number`, a quantity, never
//! behind the final block heard of before or behind what the file has read (replica). Not
//! read: its hash, its parent, its transactions, and the rest.
//!
//! Of a log (`eth_getLogs`):
//! - `address`: the contract asked about.
//! - `removed`: absent or false (not `null`).
//! - `blockNumber`: a quantity, within the blocks asked about; with `logIndex`, strictly
//!   increasing through an answer; in a range, one hash for each number and one number for
//!   each hash, both contracts' logs together (replica).
//! - `blockHash`: 32 bytes; as above (replica); the same as the block hash of a batch's
//!   transaction.
//! - `logIndex`: a quantity; with `blockNumber`, strictly increasing through an answer, and
//!   never the same as another log's in a range, both contracts' logs together (replica).
//! - `transactionHash`: 32 bytes; in a range, in one block only, and its logs together in its
//!   block, never on both sides of another transaction's (replica); for a batch, the hash of
//!   the transaction asked for.
//! - `transactionIndex`: a quantity; in a block, one for each transaction and one transaction
//!   for each, never going down as `logIndex` goes up (replica); for a batch, the same as its
//!   transaction's.
//! - `topics`: one to four, each 32 bytes; the first one of the kinds asked for; as many as
//!   the contract's event of that kind has, each no wider than its type (replica).
//! - `data`: bytes, at most 16 KiB; as long as the event of its kind has, each word no wider
//!   than its type (replica).
//! Not read: `blockTimestamp` and any other field.
//!
//! Of a batch's transaction (`eth_getTransactionByHash`):
//! - `hash`: the hash asked for.
//! - `blockNumber`, `blockHash`, `transactionIndex`: those of the batch's log (not `null`, as
//!   for a transaction not yet in a block).
//! - `input`: bytes, at most the limit for one transaction's input; for one transaction at
//!   one place, the same in every answer (replica).
//! Not read: `from`, `to`, `value`, `gas`, `nonce`, the signature, and the rest. In
//! particular `to` is not compared with the layer 2 contract: a batch may be sent through
//! another contract, and its input is taken as Urbit's own software takes it.
//!
//! Not compared across ranges: that a transaction or a block hash read in one range does not
//! appear again in a later one. Ranges cover different blocks, so an honest node cannot give
//! one; catching a node that does would take a record of every transaction ever read.

use std::io::{self, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use std::marker::PhantomData;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};

/// Where a transaction is: its block's number and hash, and its place among the block's
/// transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Placed {
    pub block: u64,
    pub hash: [u8; 32],
    pub index: u64,
}

/// One log, as written by a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub block: u64,
    /// The hash of its block. One block number with two hashes, or a transaction in a block
    /// of another hash than its log's, is a node contradicting itself.
    pub block_hash: [u8; 32],
    /// Where in its block the log is. Logs are applied in order of block, then this.
    pub index: u64,
    /// The transaction that wrote it, and that transaction's place in the block.
    pub transaction: [u8; 32],
    pub transaction_index: u64,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Why a question got no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trouble {
    /// The node asks to be asked less often. Ask again later, the same question.
    Busy(String),
    /// Refused: a JSON-RPC error, or an HTTP status that says the question was at fault.
    Refused(String),
    /// The answer was longer than is read of it.
    TooLong(String),
    /// Anything else: unanswered, an HTTP status that says the node was at fault, or not an
    /// answer to the question.
    Failed(String),
    /// Not asked, because whoever was asking is stopping.
    Stopped,
    /// An answer that cannot be right, such as a log not shaped as its contract writes it,
    /// or one transaction in two blocks. Asking again about fewer blocks could hide what is
    /// wrong with it, so it is not asked again.
    Wrong(String),
}

impl Trouble {
    pub fn why(&self) -> &str {
        match self {
            Trouble::Busy(why) | Trouble::Refused(why) | Trouble::TooLong(why) | Trouble::Failed(why) | Trouble::Wrong(why) => why,
            Trouble::Stopped => "stopped before the question was asked",
        }
    }
}

/// A switch that says to stop, and wakes anyone waiting when it is thrown.
#[derive(Debug, Default)]
pub struct Stop {
    stopped: Mutex<bool>,
    woken: Condvar,
}

impl Stop {
    pub fn stop(&self) {
        *self.stopped.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        self.woken.notify_all();
    }

    pub fn stopped(&self) -> bool {
        *self.stopped.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Wait this long, or until stopped. Returns whether it was stopped.
    pub fn wait(&self, time: Duration) -> bool {
        let deadline = Instant::now() + time;
        let mut stopped = self.stopped.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !*stopped {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            stopped = self.woken.wait_timeout(stopped, left).unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
        true
    }
}

/// How much of a node's answers is read. These bound memory against a node that is broken
/// or hostile; they are not a judgement of what Ethereum may hold. Each is sized from
/// Ethereum's own limits with room to spare, so that no block Ethereum allows is ever too big
/// to read: anyone can write logs to the layer 2 contract (it logs a batch for any call), so
/// a block at Ethereum's limits can be made on purpose, and one too big to read would stop
/// every copy for good. The `range_` limits are where a range of blocks is read in smaller
/// pieces instead; the `block_` ones are for one block alone, which cannot be split, and only
/// a broken node can pass them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Logs in one answer about a range of blocks. A range with more is read in pieces.
    pub range_logs: usize,
    /// Bytes of an answer about a range of blocks.
    pub range_log_bytes: u64,
    /// Logs in one answer about one block. The cheapest log a contract can be made to write
    /// is a `Batch` from a call to the layer 2 contract: 750 gas for the log and about 100
    /// for each call after the first. 250,000 of them would take over 210 million gas,
    /// several times what a block may use.
    pub block_logs: usize,
    /// Bytes of an answer about one block: 250,000 such logs, at about 450 bytes each as a
    /// node writes them, with room to spare.
    pub block_log_bytes: u64,
    /// The input of one transaction. Every byte of a transaction's input costs gas, at least
    /// 4 for a zero byte, so a transaction's input is at most a quarter of its gas in bytes:
    /// 15 MB at a block limit of 60 million gas (and Ethereum's newer rules cap a whole
    /// block at 10 MiB). Twice that, for limits that grow.
    pub input_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { range_logs: 10_000, range_log_bytes: 16 << 20, block_logs: 250_000, block_log_bytes: 256 << 20, input_bytes: 32 << 20 }
    }
}

/// The most data one log may hold. Only kinds of log that are applied are asked for, and the
/// longest of them (`ChangedKeys`) has 128 bytes; a `Batch` has none.
const MOST_LOG_DATA_BYTES: usize = 16 << 10;
/// How many transactions are asked about in one request, where the node allows it, and the
/// most read of the answer to that. An answer that would be longer is asked for one by one,
/// each up to what one transaction's input may be.
pub const TRANSACTIONS_AT_ONCE: usize = 20;
const MOST_TRANSACTIONS_ANSWER_BYTES: u64 = 8 << 20;
/// The most read of the answer about a block: the block, with the hash of every transaction
/// in it. A transaction takes at least 21,000 gas, and each hash is 69 bytes as written, so
/// this covers blocks of over five billion gas.
const MOST_BLOCK_ANSWER_BYTES: u64 = 16 << 20;
/// How many times longer than an ordinary question one about a single block or a single
/// transaction may take, since its answer may be much longer.
const LONG_ANSWER_TIMES: u32 = 10;

/// An Ethereum node, asked over JSON-RPC.
pub struct Ethereum {
    url: String,
    agent: ureq::Agent,
    /// The least time between two requests, so as not to ask a public node too often.
    pause: Duration,
    last: Mutex<Option<Instant>>,
    /// Whether the node takes several questions in one request. Assumed until it refuses.
    together: AtomicBool,
    /// Once thrown, no more requests are sent, and a pause between them ends at once.
    stop: Arc<Stop>,
    limits: Limits,
    timeout: Duration,
}

impl std::fmt::Debug for Ethereum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ethereum")
    }
}

impl Ethereum {
    pub fn new(url: &str, timeout: Duration, pause: Duration, stop: Arc<Stop>) -> Ethereum {
        Ethereum::resolving(url, timeout, pause, stop, Arc::new(|name: &str| name.to_socket_addrs().map(Iterator::collect)))
    }

    /// The same, finding the node's address with `look_up` instead of the system's resolver.
    pub fn resolving(url: &str, timeout: Duration, pause: Duration, stop: Arc<Stop>, look_up: Arc<LookUp>) -> Ethereum {
        // No redirects: an answer is taken only from the address that was asked. The limit
        // covers the whole of a question, and the connecting on its own. It does not cover
        // finding the node's address, which ureq does without a limit, so that is done here,
        // with the same limit.
        let resolver = Bounded { look_up, timeout, stop: stop.clone(), running: Mutex::new(None) };
        let agent = ureq::AgentBuilder::new().timeout(timeout).timeout_connect(timeout).redirects(0).resolver(resolver).build();
        Ethereum { url: url.to_string(), agent, pause, last: Mutex::new(None), together: AtomicBool::new(true), stop, limits: Limits::default(), timeout }
    }

    /// The same, reading answers up to other limits.
    pub fn with_limits(self, limits: Limits) -> Ethereum {
        Ethereum { limits, ..self }
    }

    /// Send a request and read the answer's bytes, up to `most`, within `timeout`. The
    /// request is made on a thread of its own and waited on, so that a stop ends the wait at
    /// once even while the node is slow to answer or stalls part way: the thread is left to
    /// end by itself at its own limit. Requests are made one after another, so at most one is
    /// left behind like that.
    ///
    /// `read` makes what is wanted of the answer's bytes, on that same thread, so that a stop
    /// also ends the wait while a long answer is being read.
    fn send<T: Send + 'static>(&self, what: &str, request: &Value, most: u64, timeout: Duration, read: impl FnOnce(Vec<u8>) -> Result<T, Trouble> + Send + 'static) -> Result<T, Trouble> {
        {
            let mut last = self.last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.stop.stopped() {
                return Err(Trouble::Stopped);
            }
            if let Some(then) = *last {
                let wait = self.pause.saturating_sub(then.elapsed());
                if !wait.is_zero() && self.stop.wait(wait) {
                    return Err(Trouble::Stopped);
                }
            }
            *last = Some(Instant::now());
        }
        let (agent, url, body, what_owned) = (self.agent.clone(), self.url.clone(), request.to_string(), what.to_string());
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("ask the Ethereum node".into())
            .spawn(move || {
                let _ = done.send(send_now(&agent, &url, &body, &what_owned, most, timeout).and_then(read));
            })
            .map_err(|e| Trouble::Failed(format!("{what} could not be asked: cannot start a thread to ask it: {e}")))?;
        loop {
            match answer.recv_timeout(Duration::from_millis(50)) {
                Ok(answered) => return answered,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(Trouble::Failed(format!("{what} could not be asked"))),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if self.stop.stopped() {
                return Err(Trouble::Stopped);
            }
        }
    }

    /// Ask one question, numbered "1", take the answer's `result`, read as `seed` says, and
    /// make of it what `then` makes: all on the thread that asks.
    fn ask<S, V, T, F>(&self, method: &str, params: Value, seed: S, most: u64, timeout: Duration, then: F) -> Result<T, Trouble>
    where
        S: for<'de> DeserializeSeed<'de, Value = V> + Send + 'static,
        F: FnOnce(V) -> Result<T, Trouble> + Send + 'static,
        T: Send + 'static,
    {
        let named = method.to_string();
        let request = json!({ "jsonrpc": "2.0", "id": "1", "method": method, "params": params });
        self.send(method, &request, most, timeout, move |text| {
            let answer = parse(&named, &text, AnswerSeed(seed))?;
            drop(text);
            then(take(&named, answer, "1")?)
        })
    }

    /// The newest block the chain has finalised: Ethereum's word that it will never be
    /// replaced (unless a third of all that is staked is destroyed).
    pub fn finalized(&self) -> Result<u64, Trouble> {
        self.ask("eth_getBlockByNumber", json!(["finalized", false]), PhantomData::<Object<RawBlock>>, MOST_BLOCK_ANSWER_BYTES, self.timeout, |block| {
            quantity(&block.0.number).ok_or_else(|| Trouble::Failed("the finalised block has no number".into()))
        })
    }

    /// Every log `contract` wrote in blocks `from` to `to`, both included, in order, whose
    /// first topic is one of `kinds`. A range with more than is read of one answer is
    /// `TooLong`, to be read in pieces; one block is read up to the larger limits for one
    /// block, and given longer.
    ///
    /// At most about five times the answer's size is held while it is read: its bytes, the
    /// logs read from them (each field held apart costs more than it does as text, at most
    /// about twice as much for logs of empty fields), and the logs made of those. The count
    /// of logs is held to its limit while the answer is read, not after.
    pub fn logs(&self, contract: &[u8; 20], kinds: &[[u8; 32]], from: u64, to: u64) -> Result<Vec<Log>, Trouble> {
        let kinds_written: Vec<String> = kinds.iter().map(|kind| hex(kind)).collect();
        let filter = json!([{ "address": hex(contract), "topics": [kinds_written], "fromBlock": format!("{from:#x}"), "toBlock": format!("{to:#x}") }]);
        let (most_logs, most_bytes, timeout) = if from == to {
            (self.limits.block_logs, self.limits.block_log_bytes, self.timeout.saturating_mul(LONG_ANSWER_TIMES))
        } else {
            (self.limits.range_logs, self.limits.range_log_bytes, self.timeout)
        };
        let (contract, kinds) = (*contract, kinds.to_vec());
        let read = move |logs: Vec<RawLog>| logs_of(logs, &contract, &kinds, from, to);
        self.ask("eth_getLogs", filter, LogsSeed { most: most_logs }, most_bytes, timeout, read).map_err(|trouble| match trouble {
            Trouble::TooLong(_) => Trouble::TooLong(format!("eth_getLogs for blocks {from} to {to}: more logs, or more bytes, than are taken in one answer")),
            trouble => trouble,
        })
    }

    /// Fetch the input of each transaction asked for, each named by its hash and the block it
    /// is in, and hand each to `admit` as it comes, which may refuse it (and so stop the
    /// fetching) when there is no room for it. Asked one at a time, only one input is in hand
    /// at once beyond what `admit` has taken; asked several at a time, the answer to the lot
    /// is at most 8 MiB.
    pub fn inputs(&self, wanted: &[([u8; 32], Placed)], admit: &mut dyn FnMut([u8; 32], Placed, Vec<u8>) -> Result<(), Trouble>) -> Result<(), Trouble> {
        for group in wanted.chunks(TRANSACTIONS_AT_ONCE) {
            if group.len() > 1 && self.together.load(Ordering::Relaxed) {
                match self.inputs_together(group) {
                    Ok(Some(inputs)) => {
                        for ((hash, placed), input) in group.iter().zip(inputs) {
                            admit(*hash, *placed, input)?;
                        }
                        continue;
                    }
                    // Asked one by one from here on.
                    Ok(None) => self.together.store(false, Ordering::Relaxed),
                    // Asked one by one this once.
                    Err(Trouble::TooLong(_)) => {}
                    Err(trouble) => return Err(trouble),
                }
            }
            for (hash, placed) in group {
                // Its input written in hex, and the rest.
                let most = 2 * self.limits.input_bytes as u64 + (64 << 10);
                let (asked, at, most_input) = (*hash, *placed, self.limits.input_bytes);
                let read = move |found: Object<RawTransaction>| input_of(found.0, &asked, &at, most_input);
                let input = self.ask("eth_getTransactionByHash", json!([hex(hash)]), PhantomData::<Object<RawTransaction>>, most, self.timeout.saturating_mul(LONG_ANSWER_TIMES), read)?;
                admit(*hash, *placed, input)?;
            }
        }
        Ok(())
    }

    /// The inputs of several transactions asked for in one request. `None` if the node
    /// does not take several questions at once.
    fn inputs_together(&self, group: &[([u8; 32], Placed)]) -> Result<Option<Vec<Vec<u8>>>, Trouble> {
        let questions: Vec<Value> =
            group.iter().enumerate().map(|(at, (hash, _))| json!({ "jsonrpc": "2.0", "id": at.to_string(), "method": "eth_getTransactionByHash", "params": [hex(hash)] })).collect();
        let (asked, most_input) = (group.to_vec(), self.limits.input_bytes);
        let read = move |text: Vec<u8>| inputs_of(text, &asked, most_input);
        match self.send("eth_getTransactionByHash", &Value::Array(questions), MOST_TRANSACTIONS_ANSWER_BYTES, self.timeout, read) {
            Err(Trouble::Refused(_)) => Ok(None),
            read => read,
        }
    }
}

/// The logs in an answer about blocks `from` to `to`, each checked to be one `contract`
/// wrote, of a kind asked for, in those blocks, in order.
fn logs_of(logs: Vec<RawLog>, contract: &[u8; 20], kinds: &[[u8; 32]], from: u64, to: u64) -> Result<Vec<Log>, Trouble> {
    let bad = |why: &str| Trouble::Failed(format!("eth_getLogs for blocks {from} to {to}: {why}"));
    let mut out: Vec<Log> = Vec::with_capacity(logs.len());
    for log in logs {
        if bytes(&log.address).as_deref() != Some(&contract[..]) {
            return Err(bad("a log from another contract"));
        }
        // A log from a block that has been replaced is not one.
        if log.removed {
            return Err(bad("a log from a replaced block"));
        }
        let block = quantity(&log.block_number).ok_or_else(|| bad("a log with no block"))?;
        let block_hash = word(&log.block_hash).ok_or_else(|| bad("a log whose block has no hash"))?;
        let index = quantity(&log.log_index).ok_or_else(|| bad("a log with no place in its block"))?;
        if block < from || block > to {
            return Err(bad("a log from a block not asked about"));
        }
        if out.last().is_some_and(|last| (last.block, last.index) >= (block, index)) {
            return Err(bad("logs out of order"));
        }
        let transaction = word(&log.transaction_hash).ok_or_else(|| bad("a log with no transaction"))?;
        let transaction_index = quantity(&log.transaction_index).ok_or_else(|| bad("a log whose transaction has no place in its block"))?;
        // A log has one to four topics. (Zero is possible on Ethereum, but neither contract
        // read here writes one.)
        if log.topics.is_empty() {
            return Err(bad("a log with no topics"));
        }
        let topics = log.topics.iter().map(|topic| word(topic)).collect::<Option<Vec<_>>>().ok_or_else(|| bad("a topic that is not 32 bytes"))?;
        if !kinds.contains(&topics[0]) {
            return Err(bad("a log of a kind not asked for"));
        }
        if log.data.len() > 2 + 2 * MOST_LOG_DATA_BYTES {
            return Err(bad("a log with more data than any log read here has"));
        }
        let data = bytes(&log.data).ok_or_else(|| bad("a log whose data is not bytes"))?;
        out.push(Log { block, block_hash, index, transaction, transaction_index, topics, data });
    }
    Ok(out)
}

/// The inputs in the answer to several questions asked at once, in the order asked. `None`
/// if it is one answer for the lot: the node does not take several questions at once.
fn inputs_of(text: Vec<u8>, group: &[([u8; 32], Placed)], most_input: usize) -> Result<Option<Vec<Vec<u8>>>, Trouble> {
    let what = "eth_getTransactionByHash";
    let answers = match parse(what, &text, BatchSeed { most: group.len() })? {
        // One answer for the lot. If it says the node is busy, it is; otherwise this node
        // does not take several questions at once.
        Batched::One(answer) => {
            return match take(what, answer, "1") {
                Err(Trouble::Busy(why)) => Err(Trouble::Busy(why)),
                _ => Ok(None),
            };
        }
        Batched::Many(answers) => answers,
    };
    drop(text);
    // A refusal among the answers is taken first, whatever it says it answers, so that a
    // node asking to be asked less often is heard, and one refusing several questions at
    // once is asked one at a time.
    if let Some(at) = answers.iter().position(|answer| answer.error.is_some()) {
        let mut answers = answers;
        let refusal = answers.swap_remove(at);
        return Err(take(what, refusal, "").err().unwrap_or_else(|| Trouble::Failed("a refusal that was not one".into())));
    }
    if answers.len() != group.len() {
        return Err(Trouble::Failed("the node did not answer every question sent at once".into()));
    }
    // The answers may come in any order; each says which question it answers.
    let mut found: Vec<Option<RawTransaction>> = (0..group.len()).map(|_| None).collect();
    for answer in answers {
        let at = match &answer.id {
            Id::Text(id) => id.parse::<usize>().ok().filter(|at| *at < group.len()),
            _ => None,
        };
        let at = at.ok_or_else(|| Trouble::Failed("an answer to a question that was not asked".into()))?;
        if found[at].is_some() {
            return Err(Trouble::Failed("two answers to one question".into()));
        }
        found[at] = Some(take(what, answer, &at.to_string())?.0);
    }
    let mut inputs = Vec::with_capacity(group.len());
    for ((hash, placed), found) in group.iter().zip(found) {
        let found = found.ok_or_else(|| Trouble::Failed("the node did not answer every question sent at once".into()))?;
        inputs.push(input_of(found, hash, placed, most_input)?);
    }
    Ok(Some(inputs))
}

/// Make one request and read the answer's bytes, up to `most`. Run on a thread of its own.
fn send_now(agent: &ureq::Agent, url: &str, body: &str, what: &str, most: u64, timeout: Duration) -> Result<Vec<u8>, Trouble> {
    let sent = agent.post(url).timeout(timeout).set("Content-Type", "application/json").send_string(body);
    let answer = sent.map_err(|e| match e {
        ureq::Error::Status(429, _) => Trouble::Busy(format!("{what} was answered with HTTP status 429, asking to be asked less often")),
        ureq::Error::Status(code @ 400..=499, _) => Trouble::Refused(format!("{what} was answered with HTTP status {code}")),
        ureq::Error::Status(code, _) => Trouble::Failed(format!("{what} was answered with HTTP status {code}")),
        ureq::Error::Transport(e) => Trouble::Failed(format!("{what} could not be asked: {e}")),
    })?;
    let mut text = Vec::new();
    answer.into_reader().take(most + 1).read_to_end(&mut text).map_err(|e| Trouble::Failed(format!("the answer to {what} could not be read: {e}")))?;
    if text.len() as u64 > most {
        return Err(Trouble::TooLong(format!("the answer to {what} was longer than {most} bytes")));
    }
    Ok(text)
}

/// Read an answer's bytes as `seed` says. An answer not of the shape asked for fails at the
/// first thing in it that is not; fields not asked for are passed over without being kept.
fn parse<S, V>(what: &str, text: &[u8], seed: S) -> Result<V, Trouble>
where
    S: for<'de> DeserializeSeed<'de, Value = V>,
{
    let mut reading = serde_json::Deserializer::from_slice(text);
    let read = seed.deserialize(&mut reading).and_then(|read| reading.end().map(|()| read));
    read.map_err(|e| {
        if e.to_string().contains(TOO_MANY) {
            Trouble::TooLong(format!("the answer to {what} had more in it than is taken in one answer"))
        } else {
            Trouble::Failed(format!("the answer to {what} made no sense"))
        }
    })
}

/// What a list too long to be taken says, so that it is told apart from one that is wrong.
const TOO_MANY: &str = "more than are taken in one answer";

/// A JSON-RPC answer: which version and question it says it answers, and its result or why
/// there is none.
struct Answer<T> {
    version: Option<String>,
    id: Id,
    result: Option<T>,
    error: Option<Object<RpcError>>,
}

/// Which question an answer says it answers.
enum Id {
    Missing,
    Text(String),
    /// A number, however written, or nothing: never the number of a question asked here,
    /// which are text.
    Other,
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Id, D::Error> {
        struct IdVisitor;
        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a question's number")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Id, E> {
                Ok(Id::Text(text.to_string()))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Id, E> {
                Ok(Id::Other)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Id, E> {
                Ok(Id::Other)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Id, E> {
                Ok(Id::Other)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Id, E> {
                Ok(Id::Other)
            }
        }
        deserializer.deserialize_any(IdVisitor)
    }
}

#[derive(Deserialize)]
struct RpcError {
    message: Option<String>,
}

/// A value read only from a JSON object. serde's own reading of a struct also takes its
/// fields in order as a list, which no node writes and which is not the shape asked for.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Object<T>, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Object<T>, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

/// Reads an answer whose result is read by the seed it holds.
struct AnswerSeed<S>(S);

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for AnswerSeed<S> {
    type Value = Answer<S::Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(AnswerVisitor(self.0))
    }
}

struct AnswerVisitor<S>(S);

impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for AnswerVisitor<S> {
    type Value = Answer<S::Value>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON-RPC answer")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        read_answer(self.0, map)
    }
}

/// The fields of an answer, the result read by `seed`. Each field once; any other is passed
/// over. `jsonrpc`, when there, is text; `id` is text, or a number or `null`, which no
/// question here is numbered with (and which a refusal may carry, a node that could not read
/// a question being unable to say which it was); `result` is of its shape, or `null`, which
/// is an answer with nothing in it; `error`, when there, is an object, and is never `null`.
/// An answer with both an error and a result that is not `null` is not one.
fn read_answer<'de, S: DeserializeSeed<'de>, M: MapAccess<'de>>(seed: S, mut map: M) -> Result<Answer<S::Value>, M::Error> {
    let mut seed = Some(seed);
    let mut answer = Answer { version: None, id: Id::Missing, result: None, error: None };
    let (mut saw_version, mut saw_id, mut saw_error) = (false, false, false);
    while let Some(key) = map.next_key::<String>()? {
        let twice = |saw: &mut bool| if std::mem::replace(saw, true) { Err(de::Error::custom("a field given twice")) } else { Ok(()) };
        match key.as_str() {
            "jsonrpc" => {
                twice(&mut saw_version)?;
                answer.version = Some(map.next_value::<String>()?);
            }
            "id" => {
                twice(&mut saw_id)?;
                answer.id = map.next_value()?;
            }
            "error" => {
                twice(&mut saw_error)?;
                answer.error = Some(map.next_value::<Object<RpcError>>()?);
            }
            "result" => {
                let seed = seed.take().ok_or_else(|| de::Error::custom("a field given twice"))?;
                answer.result = map.next_value_seed(Nullable(seed))?;
            }
            _ => {
                map.next_value::<IgnoredAny>()?;
            }
        }
    }
    if answer.error.is_some() && answer.result.is_some() {
        return Err(de::Error::custom("an answer with both a result and an error"));
    }
    Ok(answer)
}

/// A value read by a seed, or `null`.
struct Nullable<S>(S);

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Nullable<S> {
    type Value = Option<S::Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct NullableVisitor<S>(S);
        impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for NullableVisitor<S> {
            type Value = Option<S::Value>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a result, or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
                self.0.deserialize(deserializer).map(Some)
            }
        }
        deserializer.deserialize_option(NullableVisitor(self.0))
    }
}

/// A list of logs, refused as soon as it is longer than `most`.
struct LogsSeed {
    most: usize,
}

impl<'de> DeserializeSeed<'de> for LogsSeed {
    type Value = Vec<RawLog>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct LogsVisitor(usize);
        impl<'de> Visitor<'de> for LogsVisitor {
            type Value = Vec<RawLog>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of logs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut logs = Vec::new();
                while let Some(log) = seq.next_element::<Object<RawLog>>()? {
                    if logs.len() == self.0 {
                        return Err(de::Error::custom(TOO_MANY));
                    }
                    logs.push(log.0);
                }
                Ok(logs)
            }
        }
        deserializer.deserialize_seq(LogsVisitor(self.most))
    }
}

/// A log as a node writes it: only the fields read here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLog {
    address: String,
    #[serde(deserialize_with = "four_at_most")]
    topics: Vec<String>,
    data: String,
    block_number: String,
    block_hash: String,
    transaction_hash: String,
    transaction_index: String,
    log_index: String,
    /// Absent or false. `null` is neither, and is refused.
    #[serde(default)]
    removed: bool,
}

/// A log's topics: four at most, as Ethereum allows, refused at the fifth.
fn four_at_most<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    struct Topics;
    impl<'de> Visitor<'de> for Topics {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("up to four topics")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut topics = Vec::new();
            while let Some(topic) = seq.next_element::<String>()? {
                if topics.len() == 4 {
                    return Err(de::Error::custom("a log with more than four topics"));
                }
                topics.push(topic);
            }
            Ok(topics)
        }
    }
    deserializer.deserialize_seq(Topics)
}

/// A block as a node writes it: only its number. The hashes of its transactions are passed
/// over.
#[derive(Deserialize)]
struct RawBlock {
    number: String,
}

/// A transaction as a node writes it: only the fields read here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTransaction {
    hash: String,
    /// Where it is. A transaction not yet in a block has these `null`, and is refused: a batch
    /// is read only from blocks that are final.
    block_number: String,
    block_hash: String,
    transaction_index: String,
    input: String,
}

/// The answer to several questions at once: a list of answers, or one answer for the lot.
enum Batched {
    Many(Vec<Answer<Object<RawTransaction>>>),
    One(Answer<IgnoredAny>),
}

struct BatchSeed {
    most: usize,
}

impl<'de> DeserializeSeed<'de> for BatchSeed {
    type Value = Batched;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct BatchVisitor(usize);
        impl<'de> Visitor<'de> for BatchVisitor {
            type Value = Batched;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("answers to questions asked at once")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut answers = Vec::new();
                while let Some(answer) = seq.next_element_seed(AnswerSeed(PhantomData::<Object<RawTransaction>>))? {
                    if answers.len() == self.0 {
                        return Err(de::Error::custom("more answers than questions"));
                    }
                    answers.push(answer);
                }
                Ok(Batched::Many(answers))
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                read_answer(PhantomData::<IgnoredAny>, map).map(Batched::One)
            }
        }
        deserializer.deserialize_any(BatchVisitor(self.most))
    }
}

/// An answer's result, once it is known to answer the question numbered `id`, or why there
/// is none. A refusal is taken whatever question it says it answers: a node that could not
/// read a question cannot say which it was, and a refusal never becomes state.
fn take<T>(method: &str, answer: Answer<T>, id: &str) -> Result<T, Trouble> {
    if let Some(error) = answer.error {
        let why: String = error.0.message.as_deref().unwrap_or("no reason given").chars().take(200).collect();
        let lower = why.to_lowercase();
        let busy = ["rate limit", "rate-limit", "too many requests", "throttl"].iter().any(|said| lower.contains(said));
        let refused = format!("{method} was refused: {why}");
        return Err(if busy { Trouble::Busy(refused) } else { Trouble::Refused(refused) });
    }
    let ours = answer.version.as_deref() == Some("2.0") && matches!(&answer.id, Id::Text(said) if said == id);
    if !ours {
        return Err(Trouble::Failed(format!("the answer to {method} was not an answer to the question asked")));
    }
    answer.result.ok_or_else(|| Trouble::Failed(format!("the answer to {method} had nothing in it")))
}

fn input_of(transaction: RawTransaction, hash: &[u8; 32], placed: &Placed, most_input: usize) -> Result<Vec<u8>, Trouble> {
    let bad = |why: &str| Trouble::Failed(format!("transaction {}: {why}", hex(hash)));
    if word(&transaction.hash).as_ref() != Some(hash) {
        return Err(bad("the node answered with another transaction, or none"));
    }
    // In another block than its log, by number or by hash, or at another place in it: the
    // node contradicts itself.
    let block = quantity(&transaction.block_number);
    let block_hash = word(&transaction.block_hash);
    let index = quantity(&transaction.transaction_index);
    if (block, block_hash, index) != (Some(placed.block), Some(placed.hash), Some(placed.index)) {
        return Err(Trouble::Wrong(format!("transaction {}: the node has it in another block than its log, or at another place in it", hex(hash))));
    }
    if transaction.input.len() > 2 + 2 * most_input {
        return Err(bad("an input longer than any transaction's could be"));
    }
    bytes(&transaction.input).ok_or_else(|| bad("an input that is not bytes"))
}

/// A way to find the addresses of a host, given as `name:port`.
pub type LookUp = dyn Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync;

/// Finding an address on a thread of its own, given up on after the time a question may take,
/// or at once when the asker is stopping. Only one look-up runs at a time: a thread left
/// waiting on a resolver that does not answer is waited on again by the next question, up
/// to that question's own limit, and no other is started while it runs. So a resolver that
/// never answers holds one thread, however often the node is asked.
struct Bounded {
    look_up: Arc<LookUp>,
    timeout: Duration,
    stop: Arc<Stop>,
    /// The answer to the look-up that is running, if one is.
    running: Mutex<Option<std::sync::mpsc::Receiver<io::Result<Vec<SocketAddr>>>>>,
}

impl ureq::Resolver for Bounded {
    fn resolve(&self, name: &str) -> io::Result<Vec<SocketAddr>> {
        let mut running = self.running.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if running.is_none() {
            let (found, answer) = std::sync::mpsc::channel();
            let (look_up, asked) = (self.look_up.clone(), name.to_string());
            std::thread::Builder::new()
                .name("look up the Ethereum node".into())
                .spawn(move || {
                    let _ = found.send(look_up(&asked));
                })
                .map_err(|e| io::Error::other(format!("cannot start looking up the node's address: {e}")))?;
            *running = Some(answer);
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            let answer = running.as_ref().expect("a look-up is running").recv_timeout(Duration::from_millis(50));
            match answer {
                Ok(found) => {
                    *running = None;
                    return found;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    *running = None;
                    return Err(io::Error::other("looking up the node's address went wrong"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if self.stop.stopped() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "stopped while looking up the node's address"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "looking up the node's address took too long"));
            }
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Bytes written as `0x` and an even number of hexadecimal digits.
pub fn bytes(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    if digits.len() % 2 != 0 {
        return None;
    }
    let digit = |byte: u8| (byte as char).to_digit(16).map(|digit| digit as u8);
    digits.chunks(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

fn word(text: &str) -> Option<[u8; 32]> {
    bytes(text)?.try_into().ok()
}

/// A number written as `0x` and hexadecimal digits, as JSON-RPC writes block numbers. One
/// too big for SQLite to keep as a number (above 2^63 - 1) is not taken: the copy of Azimuth
/// writes block numbers down, and no chain is anywhere near that long.
///
/// Only as Ethereum writes a quantity: hexadecimal digits, in either case, and no zero in
/// front but the single digit `0`. (Rust's own reading would also take a `+` in front.)
fn quantity(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|digit| digit.is_ascii_hexdigit()) || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok().filter(|number| *number <= i64::MAX as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_written(index: u64) -> String {
        let word = format!("0x{}", "11".repeat(32));
        format!(r#"{{"address":"0x{}","topics":["{word}"],"data":"0x","blockNumber":"0x1","blockHash":"{word}","transactionHash":"{word}","transactionIndex":"0x0","logIndex":"{index:#x}","removed":false,"extra":{{"a":[1,2,3]}}}}"#, "aa".repeat(20))
    }

    #[test]
    fn answers_are_read_as_the_shape_asked_for() {
        let answer = |result: &str| format!(r#"{{"jsonrpc":"2.0","id":"1","result":{result}}}"#);
        let logs = |text: &str, most: usize| parse("eth_getLogs", text.as_bytes(), AnswerSeed(LogsSeed { most })).and_then(|answer| take("eth_getLogs", answer, "1"));
        // Logs as a node writes them, with fields not asked for passed over.
        let two = answer(&format!("[{},{}]", log_written(0), log_written(1)));
        assert_eq!(logs(&two, 2).unwrap().len(), 2);
        // One log more than is taken is refused as too long while it is read: what comes
        // after it is not read at all, even when it is not a log.
        let three_then_junk = answer(&format!("[{},{},{},0]", log_written(0), log_written(1), log_written(2)));
        assert!(matches!(logs(&three_then_junk, 2), Err(Trouble::TooLong(_))));
        // Something that is not a log is refused at once, wherever it is.
        assert!(matches!(logs(&answer("[0,0,0]"), 10), Err(Trouble::Failed(_))));
        assert!(matches!(logs(&answer(&format!("[{},{{}}]", log_written(0))), 10), Err(Trouble::Failed(_))));
        let five_topics = log_written(0).replacen(r#""topics":["#, r#""topics":["0x1","0x1","0x1","0x1","#, 1);
        assert!(matches!(logs(&answer(&format!("[{five_topics}]")), 10), Err(Trouble::Failed(_))));
        // A result given twice, an answer to another question, a refusal, nothing.
        assert!(logs(&format!(r#"{{"jsonrpc":"2.0","id":"1","result":[],"result":[]}}"#), 10).is_err());
        assert!(logs(&format!(r#"{{"jsonrpc":"2.0","id":2,"result":[]}}"#), 10).unwrap_err().why().contains("not an answer to the question"));
        assert!(matches!(logs(r#"{"jsonrpc":"2.0","id":null,"error":{"message":"rate limit exceeded"}}"#, 10), Err(Trouble::Busy(_))));
        assert!(logs(r#"{"jsonrpc":"2.0","id":"1","result":null}"#, 10).unwrap_err().why().contains("nothing in it"));
        // A block's transactions are passed over.
        let hashes: Vec<String> = (0..3000).map(|at| format!("\"0x{at:064x}\"")).collect();
        let block = answer(&format!(r#"{{"number":"0x2a","transactions":[{}]}}"#, hashes.join(",")));
        let read = parse("eth_getBlockByNumber", block.as_bytes(), AnswerSeed(PhantomData::<Object<RawBlock>>)).and_then(|answer| take("eth_getBlockByNumber", answer, "1"));
        assert_eq!(read.unwrap().0.number, "0x2a");
        // Several answers where fewer questions were asked.
        let many = format!("[{},{}]", answer("null"), answer("null"));
        assert!(parse("eth_getTransactionByHash", many.as_bytes(), BatchSeed { most: 1 }).is_err());
    }

    #[test]
    fn a_refusal_is_heard_whatever_it_says_it_answers() {
        let group = [([1; 32], Placed { block: 1, hash: [2; 32], index: 0 }), ([3; 32], Placed { block: 1, hash: [2; 32], index: 1 })];
        // Among answers to questions asked at once, one refusal, numbered with nothing or a
        // number, and fewer answers than questions: the refusal is what is heard.
        let busy = r#"[{"jsonrpc":"2.0","id":null,"error":{"message":"rate limit exceeded"}}]"#;
        assert!(matches!(inputs_of(busy.as_bytes().to_vec(), &group, 1 << 20), Err(Trouble::Busy(_))));
        let refused = r#"[{"jsonrpc":"2.0","id":"0","result":null},{"jsonrpc":"2.0","id":7,"error":{"message":"batch too large"}}]"#;
        assert!(matches!(inputs_of(refused.as_bytes().to_vec(), &group, 1 << 20), Err(Trouble::Refused(_))));
        // A refusal's number may be written in any way a number can be.
        let logs = |text: &str| parse("eth_getLogs", text.as_bytes(), AnswerSeed(LogsSeed { most: 10 })).and_then(|answer| take("eth_getLogs", answer, "1"));
        for id in ["1", "1.0", "1e0", "-1", "null"] {
            let refusal = format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"message":"rate limit exceeded"}}}}"#);
            assert!(matches!(logs(&refusal), Err(Trouble::Busy(_))), "{id}");
        }
    }

    /// A node that takes a question and then says nothing, or stops part way through its
    /// answer: a stop ends the wait at once, though the question may take a minute.
    #[test]
    fn a_stop_ends_a_wait_on_a_node_that_has_stopped_answering() {
        use std::io::{BufRead, BufReader, Write};
        for stalls_in_body in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                let Ok((mut stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                    line.clear();
                }
                if stalls_in_body {
                    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{\"jsonrpc\":");
                    let _ = stream.flush();
                }
                std::thread::sleep(Duration::from_secs(30));
            });
            let stop = Arc::new(Stop::default());
            let ethereum = Arc::new(Ethereum::new(&format!("http://{address}"), Duration::from_secs(60), Duration::ZERO, stop.clone()));
            let asking = ethereum.clone();
            let (done, answer) = std::sync::mpsc::channel();
            std::thread::spawn(move || done.send(asking.finalized()));
            std::thread::sleep(Duration::from_millis(300));
            let started = Instant::now();
            stop.stop();
            let answered = answer.recv_timeout(Duration::from_secs(5));
            assert!(answered.as_ref().is_ok_and(|answered| matches!(answered, Err(Trouble::Stopped))), "{answered:?}");
            assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        }
    }

    /// An answer that takes seconds to read (a log with millions of fields not asked for):
    /// a stop ends the wait while it is being read, as it does while it is being fetched.
    #[test]
    fn a_stop_ends_a_wait_while_a_long_answer_is_being_read() {
        use std::io::{BufRead, BufReader, Write};
        let text = format!(r#"{{"jsonrpc":"2.0","id":"1","result":[{{{}"address":"0x"}}]}}"#, r#""x":0,"#.repeat(12_000_000));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sent = Arc::new(AtomicBool::new(false));
        let sending = sent.clone();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (mut length, mut line) = (0usize, String::new());
            while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                line.clear();
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", text.len());
            let _ = stream.write_all(text.as_bytes());
            let _ = stream.flush();
            sending.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(10));
        });
        let stop = Arc::new(Stop::default());
        let limits = Limits { block_log_bytes: 128 << 20, ..Limits::default() };
        let ethereum = Arc::new(Ethereum::new(&format!("http://{address}"), Duration::from_secs(60), Duration::ZERO, stop.clone()).with_limits(limits));
        let asking = ethereum.clone();
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(asking.logs(&[0xaa; 20], &[[0x11; 32]], 41, 41)));
        let begun = Instant::now();
        while !sent.load(Ordering::SeqCst) {
            assert!(begun.elapsed() < Duration::from_secs(20));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        stop.stop();
        let answered = answer.recv_timeout(Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert!(answered.as_ref().is_ok_and(|answered| matches!(answered, Err(Trouble::Stopped))), "{answered:?}");
    }

    /// Every value of the kind listed, and no other: an object where an object is listed (not
    /// its fields in order as a list), text where text is, a list where a list is, a yes or
    /// no where one is, and `null` only where it is allowed.
    #[test]
    fn every_field_is_read_only_as_the_kind_listed() {
        let logs = |text: &str| parse("eth_getLogs", text.as_bytes(), AnswerSeed(LogsSeed { most: 10 })).and_then(|answer| take("eth_getLogs", answer, "1"));
        let answer = |result: &str| format!(r#"{{"jsonrpc":"2.0","id":"1","result":{result}}}"#);
        let good = log_written(0);
        assert!(logs(&answer(&format!("[{good}]"))).is_ok());
        let word = format!("\"0x{}\"", "11".repeat(32));
        // A log as its fields in order, not an object.
        let listed = format!(r#"["0x{}",[{word}],"0x","0x1",{word},{word},"0x0","0x0",false]"#, "aa".repeat(20));
        assert!(logs(&answer(&format!("[{listed}]"))).is_err());
        // Each field of a log, of another kind than listed.
        for (field, written) in [
            ("blockNumber", "41"),
            ("blockNumber", "null"),
            ("address", "null"),
            ("address", r#"{"a":1}"#),
            ("data", r#"["0x"]"#),
            ("topics", &word),
            ("topics", "null"),
            ("transactionIndex", "0"),
            ("removed", "null"),
            ("removed", r#""false""#),
            ("removed", "0"),
        ] {
            let mut log: serde_json::Map<String, Value> = serde_json::from_str(&good).unwrap();
            log.insert(field.into(), serde_json::from_str(written).unwrap());
            assert!(logs(&answer(&format!("[{}]", Value::Object(log)))).is_err(), "{field}: {written}");
        }
        // `removed` absent, or false, is a log; true is a log from a replaced block.
        let mut absent: serde_json::Map<String, Value> = serde_json::from_str(&good).unwrap();
        absent.remove("removed");
        assert!(logs(&answer(&format!("[{}]", Value::Object(absent.clone())))).is_ok());
        absent.insert("removed".into(), Value::Bool(true));
        let read = logs(&answer(&format!("[{}]", Value::Object(absent)))).unwrap();
        assert!(logs_of(read, &[0xaa; 20], &[[0x11; 32]], 1, 1).unwrap_err().why().contains("replaced"));

        // The final block as a list, its number as a number.
        let block = |text: &str| parse("eth_getBlockByNumber", text.as_bytes(), AnswerSeed(PhantomData::<Object<RawBlock>>)).and_then(|answer| take("eth_getBlockByNumber", answer, "1"));
        assert!(block(&answer(r#"{"number":"0x29"}"#)).is_ok());
        for not in [r#"["0x29"]"#, r#"{"number":41}"#, r#"{"number":null}"#, r#""0x29""#] {
            assert!(block(&answer(not)).is_err(), "{not}");
        }
        // A transaction as a list, its place as a number, not yet in a block.
        let hash = format!("0x{}", "22".repeat(32));
        let transaction = |text: &str| parse("eth_getTransactionByHash", text.as_bytes(), AnswerSeed(PhantomData::<Object<RawTransaction>>)).and_then(|answer| take("eth_getTransactionByHash", answer, "1"));
        let whole = format!(r#"{{"hash":"{hash}","blockNumber":"0x1","blockHash":"{hash}","transactionIndex":"0x0","input":"0x"}}"#);
        assert!(transaction(&answer(&whole)).is_ok());
        for not in [
            format!(r#"["{hash}","0x1","{hash}","0x0","0x"]"#),
            whole.replace(r#""blockNumber":"0x1""#, r#""blockNumber":null"#),
            whole.replace(r#""transactionIndex":"0x0""#, r#""transactionIndex":0"#),
            whole.replace(r#""input":"0x""#, r#""input":["0x"]"#),
        ] {
            assert!(transaction(&answer(&not)).is_err(), "{not}");
        }
        // The same, among answers to questions asked at once.
        let batched = format!(r#"[{{"jsonrpc":"2.0","id":"0","result":["{hash}","0x1","{hash}","0x0","0x"]}}]"#);
        assert!(parse("eth_getTransactionByHash", batched.as_bytes(), BatchSeed { most: 1 }).is_err());
        // The parts of an answer, of other kinds than listed: a version that is a number, a
        // question's number that is a fraction, a refusal as a list.
        // An error that is `null` beside a good result, a version that is `null`, an error
        // beside a result that is not `null`.
        for not in [
            r#"{"jsonrpc":2.0,"id":"1","result":[]}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"result":[]}"#,
            r#"{"jsonrpc":"2.0","id":"1","error":["rate limit"]}"#,
            r#"["jsonrpc","2.0"]"#,
            r#"{"jsonrpc":"2.0","id":"1","error":null,"result":[]}"#,
            r#"{"jsonrpc":null,"id":"1","result":[]}"#,
            r#"{"jsonrpc":null,"id":"1","error":{"message":"rate limit exceeded"}}"#,
            r#"{"jsonrpc":"2.0","id":"1","result":[],"error":{"message":"no"}}"#,
            r#"{"jsonrpc":"2.0","id":"1","error":{"message":7}}"#,
        ] {
            assert!(matches!(logs(not), Err(Trouble::Failed(_))), "{not}");
        }
    }

    #[test]
    fn a_quantity_is_only_as_ethereum_writes_one() {
        for (written, number) in [("0x0", 0), ("0x1", 1), ("0xA", 10), ("0xabc", 0xabc), ("0x192f08a", 26_407_050)] {
            assert_eq!(quantity(written), Some(number), "{written}");
        }
        for not in ["0x+29", "0x01", "0x00", "0x-1", "0x 1", "0x1 ", "0X1", "0xg", "1"] {
            assert_eq!(quantity(not), None, "{not}");
        }
        for not in ["0x+1", "0x0g", "0x\u{e9}0"] {
            assert_eq!(bytes(not), None, "{not}");
        }
        assert_eq!(bytes("0xAbCd"), Some(vec![0xab, 0xcd]));
    }

    #[test]
    fn numbers_and_bytes_as_json_rpc_writes_them() {
        assert_eq!(quantity("0x0"), Some(0));
        assert_eq!(quantity("0x192f08a"), Some(26_407_050));
        assert_eq!(quantity("0x7fffffffffffffff"), Some(i64::MAX as u64));
        for not in ["", "0x", "192f08a", "0xg", "0x10000000000000000", "0x8000000000000000", "-0x1"] {
            assert_eq!(quantity(not), None, "{not}");
        }
        assert_eq!(bytes("0x"), Some(vec![]));
        assert_eq!(bytes("0x00ff"), Some(vec![0, 255]));
        assert_eq!(bytes("0x0"), None);
        assert_eq!(bytes("00"), None);
        assert_eq!(hex(&[0, 0xab]), "0x00ab");
    }

    /// Finding the node's address is held to the time a question may take, and given up on
    /// when stopping, though the system's resolver may take as long as it likes.
    #[test]
    fn finding_the_nodes_address_is_bounded_and_stops() {
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = asked.clone();
        let stuck: Arc<LookUp> = Arc::new(move |_: &str| {
            counting.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(30));
            Ok(vec![])
        });
        let ethereum = Ethereum::resolving("http://node.invalid:8545", Duration::from_millis(300), Duration::ZERO, Arc::new(Stop::default()), stuck.clone());
        let started = Instant::now();
        assert!(ethereum.finalized().is_err());
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert_eq!(asked.load(Ordering::SeqCst), 1, "the address was looked up the way given");

        let stop = Arc::new(Stop::default());
        let ethereum = Arc::new(Ethereum::resolving("http://node.invalid:8545", Duration::from_secs(60), Duration::ZERO, stop.clone(), stuck));
        let asking = ethereum.clone();
        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(asking.finalized()));
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        stop.stop();
        let answered = answer.recv_timeout(Duration::from_secs(2));
        assert!(answered.as_ref().is_ok_and(|answered| answered.is_err()), "{answered:?}");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(asked.load(Ordering::SeqCst), 2);

        // An address found in time is used: here, a node on this machine that says the
        // chain is final to block 42.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
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
                let _ = reader.read_exact(&mut body);
                let answer = r#"{"jsonrpc":"2.0","id":"1","result":{"number":"0x2a"}}"#;
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len());
            }
        });
        let found: Arc<LookUp> = Arc::new(move |_: &str| Ok(vec![address]));
        let ethereum = Ethereum::resolving("http://node.invalid:8545", Duration::from_secs(2), Duration::ZERO, Arc::new(Stop::default()), found);
        assert_eq!(ethereum.finalized().unwrap(), 42);
    }

    /// A resolver that never answers holds one thread, however many questions are asked.
    #[test]
    fn only_one_look_up_runs_at_a_time() {
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let most = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let look_up: Arc<LookUp> = {
            let (started, running, most, gate) = (started.clone(), running.clone(), most.clone(), gate.clone());
            Arc::new(move |_: &str| {
                started.fetch_add(1, Ordering::SeqCst);
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
                running.fetch_sub(1, Ordering::SeqCst);
                Ok(vec![])
            })
        };
        let ethereum = Ethereum::resolving("http://node.invalid:8545", Duration::from_millis(100), Duration::ZERO, Arc::new(Stop::default()), look_up);
        for _ in 0..10 {
            assert!(ethereum.finalized().is_err());
        }
        assert_eq!((started.load(Ordering::SeqCst), most.load(Ordering::SeqCst)), (1, 1));
        // Once it answers, its answer is taken by the next question, and the one after
        // that looks up afresh.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        let begun = Instant::now();
        while running.load(Ordering::SeqCst) > 0 {
            assert!(begun.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ethereum.finalized().is_err());
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(ethereum.finalized().is_err());
        assert_eq!((started.load(Ordering::SeqCst), most.load(Ordering::SeqCst)), (2, 1));
    }
}
