//! Typed calls: what the code `ship-sdk-build` generates from an agent's description stands on.
//!
//! An agent's interface is described once, in a proto3 file: each `service` is one interface,
//! each unary method a command, or a question when it is marked `idempotency_level =
//! NO_SIDE_EFFECTS`, and a server-streaming method the interface's log. `ship-sdk-build` turns
//! that into typed handlers, dispatch, calling stubs, typed logs, and the proto3 JSON form of
//! every message, all built on what is here.
//!
//! On the wire a typed call is an ordinary payload: a `Call` (the method's name and its input,
//! encoded, or written as proto3 JSON when `json` is set), and what comes back is a `CallReply`
//! (the output, in the same form, or a `Fault`). The runtime knows nothing of either: it reads
//! no message types. JSON is read and written here, inside the agent, within the event's fuel,
//! time and memory. The interface is the one the call is made through, which the kernel has
//! already checked, so it is not in the envelope.
//!
//! A question's fault reaches its caller. A command's does not, in this version: a command
//! handler that returns `Err`, and every refusal the generated code makes on the command path (a
//! body that does not decode among them), traps, so the event is rolled back as any failed
//! handler's is, and nothing the handler did is kept. The caller sees what it sees for any failed
//! handler (a rejection, or a FAILED receipt). An error must never leave half a change behind,
//! and carrying the reason back needs the runtime's help, which is not here yet.

use serde::de::DeserializeOwned;
use serde::Serialize;
use ship_proto::call_reply::Result as Replied;
pub use ship_proto::{Call, CallReply, Fault};
use ship_proto::{Message, NextReply, NextRequest};

use crate::ask::{Answered, Outcome};
use crate::{Receipt, Verdict};

/// No interface of this agent is described under the name the call came through (an owner's
/// command through `/agents/<agent>/command` comes through no interface at all).
pub const NO_SUCH_INTERFACE: &str = "ship.no-such-interface";
/// The interface has no method of that name to call (its log is not a method to call either).
pub const NO_SUCH_METHOD: &str = "ship.no-such-method";
/// The call is not a `Call`, or its body does not decode as the method's input (as protobuf, or
/// as proto3 JSON when the call says JSON).
pub const NOT_UNDERSTOOD: &str = "ship.not-understood";
/// A command reached as a question, or a question reached as a command.
pub const WRONG_KIND: &str = "ship.wrong-kind";

/// What a handler's fault code is put under when it starts with `ship.`, which only the
/// generated code may use: `ship.x` from a handler arrives as `app.ship.x`.
pub const REWRITTEN_PREFIX: &str = "app.";

/// A fault with this code and message.
pub fn fault(code: &str, message: &str) -> Fault {
    Fault { code: code.into(), message: message.into() }
}

/// Why a typed call to another agent has no typed result.
#[derive(Clone, Debug, PartialEq)]
pub enum CallError {
    /// The method answered with a fault: the application's own, or one the generated code in
    /// the agent called made (`ship.no-such-method` and the rest).
    Fault(Fault),
    /// What came back is not a `CallReply`, or its body does not decode as the method's output.
    /// The agent called is not typed, speaks another version of the interface, or broke it.
    NotUnderstood(String),
    /// A question to another ship has no reply: what came of it instead, and the reason.
    Unanswered(Outcome, String),
    /// A command sent to another ship did not run: the receipt says it was refused, failed, was
    /// too large, or was malformed. The verdict and the reason.
    NotRun(Verdict, String),
    /// A command sent to another ship is lost: one of the two ships went back to an earlier
    /// state, and nobody can tell whether it ran. The reason the receipt gives.
    Lost(String),
    /// A command sent to another ship ran, and its receipt carries no reply: the other ship's
    /// runtime predates replies or broke the protocol, or the command was not sent with its
    /// reply wanted. The reason the receipt gives, if any.
    NoReply(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Fault(fault) => write!(f, "{}: {}", fault.code, fault.message),
            CallError::NotUnderstood(why) => write!(f, "the reply is not understood: {why}"),
            CallError::Unanswered(outcome, why) => write!(f, "no reply ({}): {why}", outcome.as_str_name()),
            CallError::NotRun(verdict, why) => write!(f, "the command did not run ({}): {why}", verdict.as_str_name()),
            CallError::Lost(why) => write!(f, "the command is lost, and nobody can tell whether it ran: {why}"),
            CallError::NoReply(why) => write!(f, "the command ran and no reply came back: {why}"),
        }
    }
}

/// A typed handler's own dispatch: given a method's name, its input (encoded, or as proto3
/// JSON when the flag says so), the output in the same form, or a fault.
pub type Dispatch = fn(&str, &[u8], bool) -> Result<Vec<u8>, Fault>;

/// One interface an agent serves, with `H` the type that implements its handlers. The code
/// `ship-sdk-build` generates implements this for each served interface's `Interface` type;
/// `typed_agent!` wires them into the module's exports.
pub trait Serve<H> {
    /// The interface's name: the service's name in lower-case words joined by `-`.
    const INTERFACE: &'static str;
    /// Run a command method. `json` says the input is, and the output is wanted as, proto3 JSON.
    fn command(method: &str, body: &[u8], json: bool) -> Result<Vec<u8>, Fault>;
    /// Run a question method, the same way.
    fn read(method: &str, body: &[u8], json: bool) -> Result<Vec<u8>, Fault>;
    /// The state behind the interface's log, encoded, for a checkpoint; `None` for a log that is
    /// a history kept whole, or no log.
    fn checkpoint() -> Option<Vec<u8>>;
}

/// Whether the interfaces wired into `typed_agent!` are exactly those the description serves:
/// as many wired as served, each served one wired, and each wired one served (so, since the
/// served names are distinct, none wired twice). Evaluated at compile time by the macro. It
/// compares names only: it cannot tell that a `Serve` implementation of the same name from
/// another module implements the same schema.
#[doc(hidden)]
pub const fn __same_interfaces(served: &[&str], wired: &[&str]) -> bool {
    const fn same(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut i = 0;
        while i < a.len() {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }
    const fn within(name: &str, names: &[&str]) -> bool {
        let mut i = 0;
        while i < names.len() {
            if same(name, names[i]) {
                return true;
            }
            i += 1;
        }
        false
    }
    if served.len() != wired.len() {
        return false;
    }
    let mut i = 0;
    while i < served.len() {
        if !within(served[i], wired) {
            return false;
        }
        i += 1;
    }
    let mut i = 0;
    while i < wired.len() {
        if !within(wired[i], served) {
            return false;
        }
        i += 1;
    }
    true
}

/// The encoded `Call` of `method` with `request` as its body, encoded.
#[doc(hidden)]
pub fn __call<M: Message>(method: &str, request: &M) -> Vec<u8> {
    Call { method: method.into(), body: request.encode_to_vec(), json: false }.encode_to_vec()
}

/// A method's input, read from a call's body (protobuf, or proto3 JSON with `json`), or the
/// fault that says it does not decode, with the decoder's own words. Protobuf ignores fields it
/// does not know; how JSON treats them is set when the code is generated (see the README).
#[doc(hidden)]
pub fn __request<M: Message + Default + DeserializeOwned>(method: &str, body: &[u8], json: bool) -> Result<M, Fault> {
    if json {
        return serde_json::from_slice(body).map_err(|e| fault(NOT_UNDERSTOOD, &format!("the body of {method} is not its input written as JSON: {e}")));
    }
    M::decode(body).map_err(|e| fault(NOT_UNDERSTOOD, &format!("the body of {method} does not decode as its input: {e}")))
}

/// What a handler returned, encoded (or written as proto3 JSON with `json`). A fault whose code
/// starts with `ship.` is rewritten (`REWRITTEN_PREFIX`), since only the generated code may make
/// those. A reply that cannot be written as JSON traps: it is a fault in the agent.
#[doc(hidden)]
pub fn __reply<M: Message + Serialize>(returned: Result<M, Fault>, json: bool) -> Result<Vec<u8>, Fault> {
    match returned {
        Ok(reply) if json => Ok(serde_json::to_vec(&reply).unwrap_or_else(|e| panic!("the reply cannot be written as JSON: {e}"))),
        Ok(reply) => Ok(reply.encode_to_vec()),
        Err(mut fault) => {
            if fault.code.starts_with("ship.") {
                fault.code = format!("{REWRITTEN_PREFIX}{}", fault.code);
            }
            Err(fault)
        }
    }
}

/// The fault for a method reached as the other kind.
#[doc(hidden)]
pub fn __wrong_kind(interface: &str, method: &str, is: &str) -> Fault {
    fault(WRONG_KIND, &format!("{method} on {interface} is {is}"))
}

/// The fault for a method the interface does not have.
#[doc(hidden)]
pub fn __no_such_method(interface: &str, method: &str) -> Fault {
    fault(NO_SUCH_METHOD, &format!("{interface} has no method {method:?}"))
}

/// The served interface a call came through, and its `Call`, or the fault that says why not.
fn called<'a, T>(payload: &[u8], served: &'a [(&'static str, T)]) -> Result<(&'a T, Call), Fault> {
    let interface = crate::invocation().interface;
    let Some((_, entry)) = served.iter().find(|(name, _)| *name == interface) else {
        return Err(fault(NO_SUCH_INTERFACE, &format!("no interface {interface:?} is described by this agent")));
    };
    let call = Call::decode(payload).map_err(|e| fault(NOT_UNDERSTOOD, &format!("the payload is not a call: {e}")))?;
    Ok((entry, call))
}

/// Stop the event with a fault: on the command path a fault rolls the event back, so nothing
/// the handler did is kept, and its words do not reach the caller.
fn trap(fault: Fault) -> ! {
    panic!("{}: {}", fault.code, fault.message)
}

/// The `handle` export of a typed agent: run the command a `Call` names on the interface it
/// came through, and answer with a `CallReply`. Any fault traps.
#[doc(hidden)]
pub fn __command(payload: &[u8], served: &[(&'static str, (Dispatch, Dispatch))]) -> Vec<u8> {
    let outcome = called(payload, served).and_then(|((command, _), call)| command(&call.method, &call.body, call.json));
    match outcome {
        Ok(body) => CallReply { result: Some(Replied::Body(body)) }.encode_to_vec(),
        Err(fault) => trap(fault),
    }
}

/// The `read` export of a typed agent: run the question a `Call` names, and answer with a
/// `CallReply` holding its reply or its fault. Nothing a read does is kept either way.
#[doc(hidden)]
pub fn __read(payload: &[u8], served: &[(&'static str, (Dispatch, Dispatch))]) -> Vec<u8> {
    let outcome = called(payload, served).and_then(|((_, read), call)| read(&call.method, &call.body, call.json));
    let result = match outcome {
        Ok(body) => Replied::Body(body),
        Err(fault) => Replied::Fault(fault),
    };
    CallReply { result: Some(result) }.encode_to_vec()
}

/// The `checkpoint` export of a typed agent: the state behind the log named, from the
/// interface of that name. A log that is a history, or not one of this agent's, has none.
#[doc(hidden)]
pub fn __checkpoint(log: &[u8], served: &[(&'static str, fn() -> Option<Vec<u8>>)]) -> Vec<u8> {
    let state = served.iter().find(|(name, _)| name.as_bytes() == log).and_then(|(_, state)| state());
    ship_proto::CheckpointReply { state }.encode_to_vec()
}

/// What a typed reply's bytes say: the output, decoded, or why there is none.
#[doc(hidden)]
pub fn __decode_reply<R: Message + Default>(bytes: &[u8]) -> Result<R, CallError> {
    let reply = CallReply::decode(bytes).map_err(|e| CallError::NotUnderstood(format!("not a call reply: {e}")))?;
    match reply.result {
        Some(Replied::Body(body)) => R::decode(&*body).map_err(|e| CallError::NotUnderstood(format!("the reply does not decode as the method's output: {e}"))),
        Some(Replied::Fault(fault)) => Err(CallError::Fault(fault)),
        None => Err(CallError::NotUnderstood("a call reply with neither a body nor a fault".into())),
    }
}

/// What a receipt says of a typed command sent with its reply wanted.
#[doc(hidden)]
pub fn __receipt<R: Message + Default>(receipt: &Receipt) -> Result<R, CallError> {
    match receipt.verdict() {
        Verdict::Ran => {}
        Verdict::Lost => return Err(CallError::Lost(receipt.reason.clone())),
        other => return Err(CallError::NotRun(other, receipt.reason.clone())),
    }
    if !receipt.replied {
        return Err(CallError::NoReply(receipt.reason.clone()));
    }
    __decode_reply(&receipt.reply)
}

/// What an answer says of a typed question put to another ship.
#[doc(hidden)]
pub fn __answered<R: Message + Default>(answered: &Answered) -> Result<R, CallError> {
    if answered.outcome() != Outcome::Reply {
        return Err(CallError::Unanswered(answered.outcome(), answered.reason.clone()));
    }
    __decode_reply(&answered.reply)
}

/// One entry of a typed log, or a checkpoint's state, decoded.
#[derive(Clone, Debug, PartialEq)]
pub struct Logged<T> {
    /// The entry number, or the last entry represented by the checkpoint.
    pub seq: u64,
    /// The entry, or the state, decoded.
    pub value: T,
}

/// An entry, or a checkpoint's state, that does not decode as the log's type. It is handed
/// over all the same, as any entry is: the position in the log moves past it exactly as it would
/// past one that decodes.
#[derive(Clone, Debug, PartialEq)]
pub struct Undecoded {
    /// The entry number, or the last entry represented by the checkpoint.
    pub seq: u64,
    /// The payload exactly as stored.
    pub bytes: Vec<u8>,
    /// What the decoder said.
    pub why: String,
}

/// What a typed log's `next` hands over: as `log::Batch`, with each entry and the checkpoint's
/// state decoded, or handed over as `Undecoded` where it does not decode.
#[derive(Clone, Debug, PartialEq)]
pub struct Batch<E, S> {
    /// Set when this agent was so far behind that the entries it needed have been dropped:
    /// replace whatever was built from this log with this state, as of entry `seq`.
    pub checkpoint: Option<Result<Logged<S>, Undecoded>>,
    /// Entries in order, each carrying its decoded value or its original bytes.
    pub entries: Vec<Result<Logged<E>, Undecoded>>,
    /// Whether the log has more beyond this batch.
    pub more: bool,
    /// For a log on another ship: set when no more of it will come, with a few words on why.
    pub stopped: Option<String>,
}

fn decoded<T: Message + Default>(seq: u64, bytes: Vec<u8>) -> Result<Logged<T>, Undecoded> {
    match T::decode(&*bytes) {
        Ok(value) => Ok(Logged { seq, value }),
        Err(e) => Err(Undecoded { seq, bytes, why: e.to_string() }),
    }
}

/// Take up to `max` entries of the log `log` of `agent` on `ship` (empty for this ship), each
/// decoded as `E`, and a checkpoint's state as `S`. The position moves exactly as for
/// `log::next_on`, whatever decodes.
#[doc(hidden)]
pub fn __next<E: Message + Default, S: Message + Default>(ship: &str, agent: &str, log: &str, max: u32) -> Batch<E, S> {
    let request = NextRequest { ship: ship.into(), agent: agent.into(), log: log.into(), max, checkpoints: true }.encode_to_vec();
    let bytes = crate::once(|buf, cap| unsafe { crate::host_log_next(request.as_ptr(), request.len() as u32, buf, cap) });
    let reply = NextReply::decode(&*bytes).expect("the runtime sent a malformed log reply");
    Batch {
        checkpoint: reply.checkpoint.map(|checkpoint| decoded(checkpoint.seq, checkpoint.state)),
        entries: reply.entries.into_iter().map(|entry| decoded(entry.seq, entry.payload)).collect(),
        more: reply.more,
        stopped: (!reply.stopped.is_empty()).then_some(reply.stopped),
    }
}

#[cfg(test)]
mod tests;
