//! A typed agent: its interfaces are written down once, in `api/guestbook.proto`, and its
//! handlers, its calls to other guestbooks, and the reading and writing of its logs are generated
//! from that by `ship-sdk-build`, the proto3 JSON its owner's devices send it included. The tests and the two-ship walk-through use it; `counter` and
//! `tally` stay untyped.
//!
//! It serves two interfaces: `guestbook` (signatures, with a log whose checkpoint is the whole
//! book) and `visits` (a log that is a history). It calls other guestbooks, on this ship and on
//! others, through the same description.

use ship_sdk::api::{fault, CallError, Fault};
use ship_sdk::pbjson_types::Empty;
use ship_sdk::prost::Message;
use ship_sdk::{ask, invocation, kv, Receipt};

ship_sdk::include_api!();

use api::guestbook::_interfaces::{guestbook_api, visits_api};
use api::guestbook::{
    Activity, Book, EraseRequest, Erased, FetchRequest, Fetching, FollowRequest, GetRequest, LookupRequest, Page, PassRequest, Passed, PeekRequest,
    ScribbleRequest, SignRequest, Signature, Signed, VisitCount, VisitRequest,
};

/// The type that implements both interfaces' handlers. The agent keeps nothing in memory: the
/// book, the visits and what came back are all in its keys.
struct Keeper;

fn load<M: Message + Default>(key: &str) -> M {
    kv::get(key.as_bytes()).and_then(|bytes| M::decode(&*bytes).ok()).unwrap_or_default()
}

fn keep<M: Message>(key: &str, value: &M) {
    kv::put(key.as_bytes(), &value.encode_to_vec());
}

fn no_such(number: u64) -> Fault {
    fault("no-such-signature", &format!("this book has no signature {number}"))
}

/// The book's signatures, erased ones taken out.
fn signed(book: &Book) -> impl DoubleEndedIterator<Item = &Signature> {
    book.signatures.iter().filter(|signature| !signature.name.is_empty())
}

impl guestbook_api::Handlers for Keeper {
    fn sign(request: SignRequest) -> Result<Signed, Fault> {
        let mut signature = request.signature.unwrap_or_default();
        if signature.name.is_empty() {
            return Err(fault("no-name", "a signature needs a name"));
        }
        let mut book: Book = load("book");
        book.next += 1;
        signature.number = book.next;
        // The state behind the log changes in the same event as the entry describing it.
        guestbook_api::log::append(&signature);
        book.signatures.push(signature);
        keep("book", &book);
        Ok(Signed { number: book.next, total: signed(&book).count() as u64 })
    }

    fn erase(request: EraseRequest) -> Result<Erased, Fault> {
        // Counted before looking, so that a fault can be seen to keep nothing.
        let mut activity: Activity = load("activity");
        activity.erase_attempts += 1;
        keep("activity", &activity);
        let mut book: Book = load("book");
        let Some(found) = book.signatures.iter_mut().find(|signature| signature.number == request.number && !signature.name.is_empty()) else {
            return Err(no_such(request.number));
        };
        // An erased signature stays as its number with no name, and the log says so the same way.
        *found = Signature { number: request.number, ..Default::default() };
        guestbook_api::log::append(found);
        keep("book", &book);
        Ok(Erased { total: signed(&book).count() as u64 })
    }

    fn pass(request: PassRequest) -> Result<Passed, Fault> {
        let book: Book = load("book");
        let signature = signed(&book).find(|signature| signature.number == request.number).cloned().ok_or_else(|| no_such(request.number))?;
        let signing = SignRequest { signature: Some(Signature { number: 0, ..signature }) };
        if request.ship.is_empty() {
            guestbook_api::call::sign::send(&request.agent, &signing);
            return Ok(Passed { sent_as: 0 });
        }
        Ok(Passed { sent_as: guestbook_api::call::sign::send_to_for_reply(&request.ship, &request.agent, &signing) })
    }

    fn fetch(request: FetchRequest) -> Result<Fetching, Fault> {
        let question = guestbook_api::call::get::ask(&request.ship, &request.agent, &GetRequest { number: request.number }, ask::DEFAULT_WITHIN_MILLIS);
        Ok(Fetching { question })
    }

    fn follow(request: FollowRequest) -> Result<Empty, Fault> {
        guestbook_api::log::follow(&request.agent);
        visits_api::log::follow(&request.agent);
        Ok(Empty {})
    }

    fn scribble(request: ScribbleRequest) -> Result<Empty, Fault> {
        ship_sdk::log::append(guestbook_api::INTERFACE, &request.raw);
        Ok(Empty {})
    }

    fn spoil(_: Empty) -> Result<Empty, Fault> {
        let mut book: Book = load("book");
        book.next += 1;
        let placeholder = Signature { number: book.next, name: "spoilt".into(), ..Default::default() };
        guestbook_api::log::append(&placeholder);
        book.signatures.push(placeholder);
        keep("book", &book);
        let mut activity: Activity = load("activity");
        activity.spoils += 1;
        keep("activity", &activity);
        Err(fault("spoilt", "this command always fails, after it has changed things"))
    }

    fn lookup(request: LookupRequest) -> Result<Page, Fault> {
        if request.prefix.starts_with("ship.") {
            return Err(fault(&request.prefix, "a code only the generated code may use"));
        }
        let book: Book = load("book");
        let total = signed(&book).count() as u64;
        let limit = request.limit.map_or(usize::MAX, |limit| limit as usize);
        let signatures = signed(&book).rev().filter(|signature| signature.name.starts_with(&request.prefix)).take(limit).cloned().collect();
        Ok(Page { signatures, total })
    }

    fn get(request: GetRequest) -> Result<Signature, Fault> {
        let book: Book = load("book");
        let found = signed(&book).find(|signature| signature.number == request.number).cloned();
        found.ok_or_else(|| no_such(request.number))
    }

    fn peek(request: PeekRequest) -> Result<Signature, Fault> {
        // A fault from the other book is passed on as it came; anything else is said in this
        // book's own words.
        guestbook_api::call::get::read(&request.agent, &GetRequest { number: request.number }).map_err(|failed| match failed {
            CallError::Fault(fault) => fault,
            other => fault("peek-failed", &other.to_string()),
        })
    }

    fn report(_: Empty) -> Result<Activity, Fault> {
        Ok(load("activity"))
    }
}

impl guestbook_api::Checkpoint for Keeper {
    fn state() -> Option<Book> {
        Some(load("book"))
    }
}

impl visits_api::Handlers for Keeper {
    fn visit(request: VisitRequest) -> Result<VisitCount, Fault> {
        let mut count: VisitCount = load("visits");
        count.visits += 1;
        visits_api::log::append(&request);
        keep("visits", &count);
        Ok(count)
    }

    fn count(_: Empty) -> Result<VisitCount, Fault> {
        Ok(load("visits"))
    }
}

/// A log this agent follows has entries for it: take them, typed, and note what was taken.
fn notified(_: &[u8]) -> Vec<u8> {
    let call = invocation();
    let source = call.source.unwrap_or_default();
    let mut activity: Activity = load("activity");
    if call.interface == guestbook_api::INTERFACE {
        let batch = guestbook_api::log::next_on(&source.ship, &source.agent, 16);
        match batch.checkpoint {
            Some(Ok(logged)) => {
                activity.checkpoints += 1;
                activity.checkpoint_seq = logged.seq;
                activity.checkpoint = Some(logged.value);
            }
            Some(Err(_)) => activity.bad_checkpoints += 1,
            None => {}
        }
        for entry in batch.entries {
            match entry {
                Ok(logged) => activity.taken.push(logged.seq),
                Err(undecoded) => {
                    activity.undecoded.push(undecoded.seq);
                    activity.undecoded_bytes.push(undecoded.bytes);
                }
            }
        }
    } else if call.interface == visits_api::INTERFACE {
        let batch = visits_api::log::next_on(&source.ship, &source.agent, 16);
        activity.visits += batch.entries.len() as u64;
    }
    keep("activity", &activity);
    Vec::new()
}

/// What became of a signature passed to a guestbook on another ship: the reply, decoded.
fn receipted(receipt: &Receipt) {
    let line = match guestbook_api::call::sign::receipt(receipt) {
        Ok(signed) => format!("{} signed as {} of {}", receipt.about, signed.number, signed.total),
        Err(failed) => format!("{} {failed}", receipt.about),
    };
    let mut activity: Activity = load("activity");
    activity.receipts.push(line);
    keep("activity", &activity);
}

/// What came of a signature asked of a guestbook on another ship: the signature, or the fault,
/// or why there is no answer.
fn answered(answered: &ask::Answered) {
    let line = match guestbook_api::call::get::answered(answered) {
        Ok(signature) => format!("{} signature {} by {}", answered.about, signature.number, signature.name),
        Err(CallError::Fault(fault)) => format!("{} fault {}: {}", answered.about, fault.code, fault.message),
        Err(other) => format!("{} {other}", answered.about),
    };
    let mut activity: Activity = load("activity");
    activity.answers.push(line);
    keep("activity", &activity);
}

ship_sdk::typed_agent!(
    api = api,
    serve = [guestbook_api::Interface => Keeper, visits_api::Interface => Keeper],
    notify = notified,
    receipt = receipted,
    answer = answered,
);
