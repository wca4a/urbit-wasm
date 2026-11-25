//! Questions between ships ("asks"): what the pieces in `ship.rs`, `net.rs`, `server.rs` and
//! `lib.rs` share. A question only reads: the agent asked answers it with its read handler,
//! read-only, inside a transaction that is always rolled back, and the ship that answers keeps
//! nothing of it. See the README, "Questions between ships".

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ship_proto::{answer, Answer, Outcome};

/// What came of answering one question, on the ship that answers it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// The agent's read handler answered this.
    Reply(Vec<u8>),
    /// The kernel would not let the question be asked: its reason.
    Denied(String),
    /// The handler trapped, or ran out of fuel or time: fixed words.
    Failed(&'static str),
    /// The question or the reply was larger than this ship allows: fixed words.
    Limit(&'static str),
    /// The ship is resting from questions (see `AskRests`): too busy, try again.
    Busy,
    /// Whoever asked had given up by the time the ship was free: nothing was run.
    GivenUp,
    /// A module the question needs (the ship's kernel, the agent asked, or one it reads) is not
    /// compiled yet: too busy, try again; it is compiled off the question's path.
    Cold(String),
}

impl Asked {
    /// The answer as it goes on the wire, or `None` for one that goes as a bare refusal, or
    /// not at all.
    pub(crate) fn sent(self) -> Option<Answer> {
        let outcome = match self {
            Asked::Reply(reply) => answer::Outcome::Reply(reply),
            Asked::Denied(why) => answer::Outcome::Denied(crate::store::short_reason(&why).to_string()),
            Asked::Failed(why) => answer::Outcome::Failed(why.into()),
            Asked::Limit(why) => answer::Outcome::Limit(why.into()),
            Asked::Busy | Asked::GivenUp | Asked::Cold(_) => return None,
        };
        Some(Answer { outcome: Some(outcome) })
    }
}

/// The fixed words a ship that answers says when it will not take a question that large.
pub(crate) const QUESTION_TOO_LARGE: &str = "the question is larger than that ship takes";
/// The fixed words for an answer larger than the ship that answers gives.
pub(crate) const ANSWER_TOO_LARGE: &str = "the answer is larger than that ship gives";
/// The fixed words for an answer larger than the ship that asked takes.
pub(crate) const ANSWER_TOO_LARGE_HERE: &str = "the answer is larger than this ship takes";
/// The fixed words for an answer with a reply that the asking ship had no room for.
pub(crate) const NO_ROOM_FOR_ANSWER: &str = "no room on this ship for the answer";
/// The fixed words for a question whose time ran out on the ship that answers it.
pub(crate) const TOOK_TOO_LONG: &str = "it took too long";

/// Why `Runtime::ask` got no answer.
#[derive(Debug, PartialEq, Eq)]
pub enum AskError {
    /// The other ship would not let the question be asked: its kernel's reason, as it gave it
    /// (cut to a receipt's length; for reading, not for parsing).
    Denied(String),
    /// The agent there failed: it trapped, or ran out of fuel or time.
    Failed,
    /// The question or the answer was larger than one of the two ships allows.
    Limit,
    /// The last try before the time ran out was refused as too busy, whatever earlier tries met
    /// (a busy refusal is asked again; any other refusal ends the question), or this runtime had
    /// as many requests out as it may; asking again later may work.
    Busy,
    /// No answer came within the time given: some try reached the other ship (or none could be
    /// begun for want of a place among this runtime's requests out), and no answer was taken
    /// in time; whatever it said after the time is not taken either.
    NoAnswer,
    /// No try reached the other ship within the time given, or it is not known. A try that finds
    /// the destination absent from the directory ends the question as `Unreachable`, even if an
    /// earlier try reached it, while a try already awaiting its reply can still complete.
    Unreachable,
    /// The other ship does not understand questions: it runs an older runtime, or answered with
    /// something that is not an answer.
    NotUnderstood,
    /// This runtime has no network running.
    NoNetwork,
    /// The question is larger than `max_ask_bytes`.
    TooLarge,
    /// The time given is nothing, or more than `max_ask_millis`.
    BadWithin,
    /// A name is not one: the asking ship is not one of this runtime's, the ship asked is this
    /// same ship (its agents are read, not asked), or an agent's or interface's name is not one.
    BadName,
}

impl fmt::Display for AskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AskError::Denied(why) => write!(f, "the other ship would not let it be asked: {why}"),
            AskError::Failed => write!(f, "the agent asked failed to answer"),
            AskError::Limit => write!(f, "the question or its answer is larger than one of the two ships allows"),
            AskError::Busy => write!(f, "the other ship is too busy; try again"),
            AskError::NoAnswer => write!(f, "no answer came in time"),
            AskError::Unreachable => write!(f, "the other ship could not be reached"),
            AskError::NotUnderstood => write!(f, "the other ship does not understand questions"),
            AskError::NoNetwork => write!(f, "this runtime is not on the network"),
            AskError::TooLarge => write!(f, "the question is larger than this runtime asks"),
            AskError::BadWithin => write!(f, "the time given to answer is nothing, or more than this runtime allows"),
            AskError::BadName => write!(f, "not a ship, agent or interface that can be asked"),
        }
    }
}

impl std::error::Error for AskError {}

impl AskError {
    /// The outcome an agent is handed for this, with this runtime's own words beside the other
    /// ship's reason.
    pub(crate) fn outcome(&self) -> (Outcome, String) {
        match self {
            AskError::Denied(why) => (Outcome::Denied, crate::store::short_reason(why).to_string()),
            AskError::Failed => (Outcome::Failed, "the agent asked failed to answer".into()),
            AskError::Limit => (Outcome::Limit, "the question or its answer is larger than one of the two ships allows".into()),
            // An agent's question is asked again while it is too busy; if its time runs out
            // meanwhile, no answer came.
            AskError::Busy | AskError::NoAnswer => (Outcome::NoAnswer, "no answer came in time".into()),
            AskError::Unreachable => (Outcome::Unreachable, "the other ship could not be reached".into()),
            AskError::NotUnderstood => (Outcome::NotUnderstood, "the other ship does not understand questions".into()),
            AskError::NoNetwork => (Outcome::Unreachable, "this ship is not on the network".into()),
            AskError::TooLarge | AskError::BadWithin | AskError::BadName => (Outcome::Limit, self.to_string()),
        }
    }
}

/// An answer that came over the wire, as `Runtime::ask` hands it on.
pub(crate) fn taken(answer: Answer, most: usize) -> Result<Vec<u8>, AskError> {
    match answer.outcome {
        Some(answer::Outcome::Reply(reply)) if reply.len() <= most => Ok(reply),
        Some(answer::Outcome::Reply(_)) | Some(answer::Outcome::Limit(_)) => Err(AskError::Limit),
        Some(answer::Outcome::Denied(why)) => {
            // The other ship's words: cut short, and nothing in them that is not plain text.
            let why: String = crate::store::short_reason(&why).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
            Err(AskError::Denied(why))
        }
        Some(answer::Outcome::Failed(_)) => Err(AskError::Failed),
        None => Err(AskError::NotUnderstood),
    }
}

/// A question put through `Runtime::ask`, as the network is handed it.
pub(crate) struct Question {
    pub from: String,
    /// Empty when the ship's owner asks.
    pub from_agent: String,
    pub to: String,
    pub agent: String,
    pub interface: String,
    pub payload: Vec<u8>,
    /// Its one deadline, taken as `Runtime::ask` was called.
    pub deadline: Instant,
}

/// How many times as long as a question took the ship that answered it rests from questions
/// from every ship, and from that ship's questions. So questions admitted past the look at the
/// rests (those that go on to wake the ship or run) take at most a quarter of any stretch of
/// the ship's time, all ships together, and from any one ship a tenth, plus the length of one
/// question each (a question that began just before the stretch ended). A question's time is
/// counted from the look at the rests that admits it under the slot (`Inner::with_ship_question`).
/// A question turned away before the under-lock check admits it holds the ship only for its
/// looks (no wake, no WASM), is charged nothing, and is bounded by the start rates (a token is
/// charged at the rate limiter before the job waits for the slot), not by this; how long such a
/// hold lasts has no fixed bound (lock contention, scheduling). One admitted under the lock that
/// then cannot be woken because a module it needs is not compiled (`Asked::Cold`) is told it is
/// too busy, and is charged its rest like any admitted question.
pub(crate) const REST_ALL: u32 = 3;
pub(crate) const REST_EACH: u32 = 9;

/// How many ships' rests are kept, all ships of this runtime together, before those that have
/// ended are forgotten.
const MOST_RESTING: usize = 1024;

/// Until when each ship of this runtime rests from questions: from all ships, and from each one
/// ship. In memory only. Set under the ship's slot, and looked at there too, so two questions to
/// one ship are never both let in; also looked at before the slot is taken, so that a question
/// refused for a rest normally never takes the ship (`Inner::with_ship_question`).
#[derive(Default)]
pub(crate) struct AskRests {
    all: HashMap<String, Instant>,
    each: HashMap<(String, String), Instant>,
}

/// Whether `ship` is resting from `caller`'s questions now. A table left poisoned by a panic is
/// emptied, and the ship taken to be resting (too busy: the caller tries again).
pub(crate) fn resting(rests: &Mutex<AskRests>, ship: &str, caller: &str, now: Instant) -> bool {
    match rests.lock() {
        Ok(rests) => {
            rests.all.get(ship).is_some_and(|until| now < *until) || rests.each.get(&(ship.to_string(), caller.to_string())).is_some_and(|until| now < *until)
        }
        Err(poisoned) => {
            *poisoned.into_inner() = AskRests::default();
            rests.clear_poison();
            true
        }
    }
}

/// Rest `ship` after a question from `caller` that held it for `took`, ending at `now`.
pub(crate) fn rest_after(rests: &Mutex<AskRests>, ship: &str, caller: &str, took: Duration, now: Instant) {
    let mut rests = rests.lock().unwrap_or_else(|poisoned| {
        let mut rests = poisoned.into_inner();
        *rests = AskRests::default();
        rests
    });
    // A rest is only ever made longer: a shorter question's rest, set later, does not cut an
    // earlier, longer one short. (Only questions admitted past the look at the rests are
    // charged, a cold one told it is too busy after that included; one turned away before the
    // under-lock check admits it is not.)
    let later = |until: &mut Instant, new: Instant| *until = (*until).max(new);
    let all = now + took.saturating_mul(REST_ALL);
    rests.all.entry(ship.to_string()).and_modify(|until| later(until, all)).or_insert(all);
    // Those whose rest has ended are forgotten once there are many. What is left are ships
    // resting now, each after a question it put in the last `REST_EACH` question-lengths, so
    // there are no more of them than questions can be started in that time (see the rates in
    // `NetConfig`).
    if rests.each.len() >= MOST_RESTING {
        rests.each.retain(|_, until| now < *until);
    }
    let each = now + took.saturating_mul(REST_EACH);
    rests.each.entry((ship.to_string(), caller.to_string())).and_modify(|until| later(until, each)).or_insert(each);
}
