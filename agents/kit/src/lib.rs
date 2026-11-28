//! A typed agent for the tests: its interfaces are the awkward cases for the code
//! `ship-sdk-build` generates, which cargo must compile. It serves `api`, `command`, `files` and
//! `kit` from `api/kit.proto`, and calls interfaces of other files: the guestbook's, a nested
//! package's, a package named `type.v1`, one named `ship_api`, the counter's log (described with
//! types its entries do not decode as), and three whose names a service's module could once have
//! clashed with: a message `BookApi` with an `optional` field, one with a nested message, and a
//! child package `book_api`, each beside a service `Book`.

use ship_sdk::api::{fault, CallError, Fault};
use ship_sdk::pbjson_types::{BoolValue, Empty, Int64Value, Timestamp};
use ship_sdk::prost::Message;
use ship_sdk::{invocation, kv};

ship_sdk::include_api!();

use api::kit::_interfaces::{api_api, command_api, files_api, kit_api};
use api::kit::{BorrowRequest, Haul, Name, Stamped};

/// The type that implements every interface the kit serves.
struct Kit;

impl api_api::Handlers for Kit {
    fn which(_: Empty) -> Result<Name, Fault> {
        Ok(Name { name: "api".into(), ..Default::default() })
    }
}

impl command_api::Handlers for Kit {
    fn which(_: Empty) -> Result<Name, Fault> {
        Ok(Name { name: "command".into(), ..Default::default() })
    }
}

impl files_api::Handlers for Kit {
    fn which(_: Empty) -> Result<Name, Fault> {
        Ok(Name { name: "files".into(), ..Default::default() })
    }
}

fn taken() -> Haul {
    kv::get(b"taken").and_then(|bytes| Haul::decode(&*bytes).ok()).unwrap_or_default()
}

impl kit_api::Handlers for Kit {
    fn echo(request: Name) -> Result<Name, Fault> {
        Ok(request)
    }

    fn clock(at: Timestamp) -> Result<Stamped, Fault> {
        let millis = at.seconds * 1000 + i64::from(at.nanos / 1_000_000);
        Ok(Stamped { at: Some(at), millis: Some(Int64Value { value: millis }) })
    }

    fn flag(flag: BoolValue) -> Result<BoolValue, Fault> {
        Ok(BoolValue { value: !flag.value })
    }

    fn r#type(request: Name) -> Result<Name, Fault> {
        Ok(Name { name: format!("the type of {}", request.name), ..request })
    }

    fn borrow(request: BorrowRequest) -> Result<api::shared::Thing, Fault> {
        // A typed read through stubs generated for an interface the kit only calls.
        let signature = api::guestbook::_interfaces::guestbook_api::call::get::read(&request.agent, &api::guestbook::GetRequest { number: request.number }).map_err(|failed| match failed {
            CallError::Fault(fault) => fault,
            other => fault("borrow-failed", &other.to_string()),
        })?;
        Ok(api::shared::Thing { word: signature.name })
    }

    fn follow_counter(_: Empty) -> Result<Empty, Fault> {
        api::counterlog::_interfaces::counter_api::log::follow("counter");
        Ok(Empty {})
    }

    fn taken(_: Empty) -> Result<Haul, Fault> {
        Ok(taken())
    }

    fn refuse(request: Name) -> Result<Name, Fault> {
        Err(fault(&request.name, &request.nickname))
    }
}

/// The counter's log has entries for the kit: take them through the typed log of an interface
/// the kit only calls, and keep what did not decode, with its number and bytes.
fn notified(_: &[u8]) -> Vec<u8> {
    let source = invocation().source.unwrap_or_default();
    let batch = api::counterlog::_interfaces::counter_api::log::next_on(&source.ship, &source.agent, 16);
    let mut kept = taken();
    match batch.checkpoint {
        Some(Ok(_)) => kept.checkpoints_decoded += 1,
        Some(Err(undecoded)) => {
            kept.checkpoint_seq = undecoded.seq;
            kept.checkpoint_bytes = undecoded.bytes;
        }
        None => {}
    }
    for entry in batch.entries {
        match entry {
            Ok(_) => kept.decoded += 1,
            Err(undecoded) => {
                kept.seqs.push(undecoded.seq);
                kept.payloads.push(undecoded.bytes);
            }
        }
    }
    kv::put(b"taken", &kept.encode_to_vec());
    Vec::new()
}

ship_sdk::typed_agent!(
    api = api,
    serve = [api_api::Interface => Kit, command_api::Interface => Kit, files_api::Interface => Kit, kit_api::Interface => Kit],
    notify = notified,
);
