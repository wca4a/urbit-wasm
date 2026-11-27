//! What the SDK makes of receipts and answers, and the check `typed_agent!` makes at compile
//! time. These parts call no host function, so they run on the machine doing the build.

use super::*;
use crate::{Receipt, Verdict};

fn receipt(verdict: Verdict, replied: bool, reply: Vec<u8>) -> Receipt {
    Receipt { verdict: verdict as i32, replied, reply, reason: "why".into(), ..Default::default() }
}

#[test]
fn a_lost_a_failed_and_a_replyless_receipt_are_told_apart() {
    let lost = __receipt::<Fault>(&receipt(Verdict::Lost, false, vec![]));
    let failed = __receipt::<Fault>(&receipt(Verdict::Failed, false, vec![]));
    let replyless = __receipt::<Fault>(&receipt(Verdict::Ran, false, vec![]));
    assert_eq!(lost, Err(CallError::Lost("why".into())));
    assert_eq!(failed, Err(CallError::NotRun(Verdict::Failed, "why".into())));
    assert_eq!(replyless, Err(CallError::NoReply("why".into())));
    assert_eq!(lost.unwrap_err().to_string(), "the command is lost, and nobody can tell whether it ran: why");
    assert_eq!(failed.unwrap_err().to_string(), "the command did not run (VERDICT_FAILED): why");
    // With a reply, it is decoded.
    let reply = CallReply { result: Some(Replied::Body(fault("a", "b").encode_to_vec())) }.encode_to_vec();
    assert_eq!(__receipt::<Fault>(&receipt(Verdict::Ran, true, reply)), Ok(fault("a", "b")));
}

#[test]
fn the_compile_time_check_wants_the_same_interfaces_both_ways() {
    assert!(__same_interfaces(&["a", "b"], &["b", "a"]));
    assert!(!__same_interfaces(&["a", "b"], &["a"]));
    assert!(!__same_interfaces(&["a"], &["a", "b"]));
    assert!(!__same_interfaces(&["ab"], &["a"]));
    assert!(__same_interfaces(&[], &[]));
    // One wired twice, with every served one wired.
    assert!(!__same_interfaces(&["a", "b"], &["a", "a", "b"]));
}

#[test]
fn a_reply_is_written_in_the_form_the_call_asked_for_and_reserved_codes_are_rewritten() {
    use pbjson_types::Int64Value;
    let five = Int64Value { value: 5 };
    assert_eq!(__reply(Ok(five.clone()), false), Ok(five.encode_to_vec()));
    assert_eq!(__reply(Ok(five), true), Ok(b"\"5\"".to_vec()));
    assert_eq!(__reply::<Int64Value>(Err(fault("ship.no-such-method", "m")), true), Err(fault("app.ship.no-such-method", "m")));
    assert_eq!(__reply::<Int64Value>(Err(fault("mine", "m")), true), Err(fault("mine", "m")));
}
