//! A test agent that depends on the counter agent: it reads a counter, and asks for it to be
//! incremented. Used to exercise permissions and queued commands.

use ship_sdk::proto::{Message, NextReply, NextRequest};
use ship_sdk::{agent, ask, emit, invocation, kv, log, read, send};

#[link(wasm_import_module = "host")]
extern "C" {
    #[link_name = "log_next"]
    fn raw_log_next(req: *const u8, req_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "take_reply"]
    fn raw_take_reply(buf: *mut u8, buf_cap: u32) -> i64;
}

/// Take entries the way an agent built before checkpoints existed would: its request does not
/// say it can take a checkpoint, and it would not notice one in the reply.
fn old_next(agent: &str, log: &str, max: u32) -> log::Batch {
    let request = NextRequest { agent: agent.into(), log: log.into(), max, checkpoints: false, ship: String::new() }.encode_to_vec();
    let mut buf = vec![0u8; 64 << 10];
    let len = unsafe { raw_log_next(request.as_ptr(), request.len() as u32, buf.as_mut_ptr(), buf.len() as u32) };
    let reply = NextReply::decode(&buf[..len as usize]).expect("the runtime sent a malformed log reply");
    log::Batch { checkpoint: None, entries: reply.entries, more: reply.more, stopped: None }
}

/// Who is calling and through which interface, as the runtime reports it.
fn caller() -> String {
    let call = invocation();
    let source = call.source.unwrap_or_default();
    let who = match (source.owner, source.ship.is_empty()) {
        (true, _) => "owner".to_string(),
        (false, true) => source.agent,
        // An agent on another ship.
        (false, false) => format!("~{}/{}", source.ship, source.agent),
    };
    format!("{who} {}", call.interface)
}

fn handle(event: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(event);
    let mut words = text.split_whitespace();
    let reply = match (words.next(), words.next()) {
        // Read the counter's current value, ask the counter to add one, and remember what we saw.
        (Some("bump"), Some(key)) => {
            let seen = read("counter", "counter", key.as_bytes());
            send("counter", "counter", format!("inc {key}").as_bytes());
            kv::put(b"last-seen", &seen);
            String::from_utf8_lossy(&seen).into_owned()
        }
        (Some("bump-then-crash"), Some(key)) => {
            send("counter", "counter", format!("inc {key}").as_bytes());
            panic!("crash requested");
        }
        // Commands that keep sending each other, to check that a chain cannot run forever.
        (Some("ping"), Some(n)) => {
            let n: u32 = n.parse().unwrap_or(0);
            kv::put(b"pings", &n.to_le_bytes());
            send("tally", "tally", format!("ping {}", n + 1).as_bytes());
            n.to_string()
        }
        (Some("who"), None) => caller(),
        // Only read, or only send, to check that the two permissions are separate.
        (Some("peek"), Some(key)) => String::from_utf8_lossy(&read("counter", "counter", key.as_bytes())).into_owned(),
        (Some("poke"), Some(key)) => {
            send("counter", "counter", format!("inc {key}").as_bytes());
            "sent".to_string()
        }
        // Send the counter a command that will fail when it runs.
        (Some("poke-bad"), None) => {
            send("counter", "counter", b"crash x");
            "sent".to_string()
        }
        // Follow the counter's log. From now on `notified` is called when it has new entries.
        (Some("follow"), None) => {
            log::follow("counter", "counter");
            "following".to_string()
        }
        // Follow the counter's log on another ship, or stop.
        (Some("follow-on"), Some(ship)) => {
            log::follow_on(ship, "counter", "counter");
            "following".to_string()
        }
        // Stopping also forgets what was counted, so that following again starts from one.
        (Some("unfollow-on"), Some(ship)) => {
            log::unfollow_on(ship, "counter", "counter");
            for name in ["seen", "last", "jumps", "stopped", "rounds"] {
                kv::delete(&key(name, ship));
            }
            "stopped".to_string()
        }
        // Stop following the counter's log on this ship.
        (Some("unfollow"), None) => {
            log::unfollow_on("", "counter", "counter");
            "stopped".to_string()
        }
        // Ask for entries of the counter's log on another ship with no room to be handed
        // them, stop following it, follow it again, and then try to collect what was asked
        // for before. Reports what each of the two calls answered.
        (Some("sneak-on"), Some(ship)) => {
            let request = NextRequest { ship: ship.into(), agent: "counter".into(), log: "counter".into(), max: 3, checkpoints: true }.encode_to_vec();
            let mut buf = vec![0u8; 64 << 10];
            let asked = unsafe { raw_log_next(request.as_ptr(), request.len() as u32, buf.as_mut_ptr(), 0) };
            log::unfollow_on(ship, "counter", "counter");
            log::follow_on(ship, "counter", "counter");
            let collected = unsafe { raw_take_reply(buf.as_mut_ptr(), buf.len() as u32) };
            format!("{} {collected}", asked > 0)
        }
        // Ask for no entries of the counter's log on another ship, with no room to be handed
        // the answer, collect the answer, and send ourselves the same command again.
        (Some("idle-on"), Some(ship)) => {
            let request = NextRequest { ship: ship.into(), agent: "counter".into(), log: "counter".into(), max: 0, checkpoints: true }.encode_to_vec();
            let mut buf = vec![0u8; 4096];
            unsafe {
                raw_log_next(request.as_ptr(), request.len() as u32, buf.as_mut_ptr(), 0);
                raw_take_reply(buf.as_mut_ptr(), buf.len() as u32);
            }
            let mut idles = kv::get(b"idles").unwrap_or_default();
            idles.push(b'i');
            kv::put(b"idles", &idles);
            send("tally", "tally", text.trim().as_bytes());
            "ok".to_string()
        }
        (Some("stubborn"), None) => {
            kv::put(b"stubborn", b"yes");
            "ok".to_string()
        }
        // From now on, note being prompted about a followed log and take nothing.
        (Some("lazy"), None) => {
            kv::put(b"lazy", b"yes");
            "ok".to_string()
        }
        // Take entries of the counter's log on another ship outside a notification.
        (Some("take-on"), Some(ship)) => {
            let batch = log::next_on(ship, "counter", "counter", 3);
            format!("{} {}", batch.entries.len() + batch.checkpoint.iter().count(), batch.more)
        }
        // Send ourselves whatever follows, as a command to run later.
        (Some("later"), Some(_)) => {
            send("tally", "tally", text.trim_start()["later".len()..].trim().as_bytes());
            "sent".to_string()
        }
        // Ask the counter's log for no entries at all: how many came back, and whether more remain.
        (Some("glance"), None) => {
            let batch = log::next("counter", "counter", 0);
            format!("{} {}", batch.entries.len() + batch.checkpoint.iter().count(), batch.more)
        }
        // Send the counter on another ship whatever follows the ship's name, as a command.
        (Some("tell"), Some(ship)) => {
            let rest = text.trim_start()["tell".len()..].trim_start()[ship.len()..].trim();
            let number = ship_sdk::send_to(ship, "counter", "counter", rest.as_bytes());
            kv::put(b"last-sent", number.to_string().as_bytes());
            "sent".to_string()
        }
        // Send any agent on another ship whatever follows its name, through the interface
        // named after it.
        (Some("far"), Some(ship)) => {
            let rest = text.trim_start()["far".len()..].trim_start()[ship.len()..].trim_start();
            let (agent, rest) = rest.split_once(' ').unwrap_or((rest, ""));
            ship_sdk::send_to(ship, agent, agent, rest.trim().as_bytes()).to_string()
        }
        // Keep a value of a given size, which is let go of when the next receipt comes.
        (Some("ballast"), Some(len)) => {
            kv::put(b"ballast", &vec![b'b'; len.parse().unwrap_or(0)]);
            "ok".to_string()
        }
        // Send the counter on another ship whatever follows the ship's name, as a command whose
        // reply is to come back with its receipt.
        (Some("tell-reply"), Some(ship)) => {
            let rest = text.trim_start()["tell-reply".len()..].trim_start()[ship.len()..].trim();
            let number = ship_sdk::send_to_for_reply(ship, "counter", "counter", rest.as_bytes());
            kv::put(b"last-sent", number.to_string().as_bytes());
            number.to_string()
        }
        // The same, the command padded with spaces to exactly `size` bytes: `tell-reply-sized
        // <ship> <size> <command>`, for a command of a size the owner's own input cannot carry.
        (Some("tell-reply-sized"), Some(ship)) => {
            let rest: Vec<&str> = text.split_whitespace().skip(2).collect();
            let size: usize = rest.first().and_then(|n| n.parse().ok()).unwrap_or(0);
            let mut command = rest.get(1..).map(|words| words.join(" ")).unwrap_or_default().into_bytes();
            command.resize(size.max(command.len()), b' ');
            let number = ship_sdk::send_to_for_reply(ship, "counter", "counter", &command);
            kv::put(b"last-sent", number.to_string().as_bytes());
            number.to_string()
        }
        // Every receipt that has come back, as a command, for an owner's device to read.
        (Some("receipts"), None) => String::from_utf8_lossy(&kv::get(b"receipts").unwrap_or_default()).into_owned(),
        // Put a question to an agent on another ship: `ask-on <ship> <agent> <interface>
        // <within millis> <payload>`. Answers with the number the question goes under.
        (Some("ask-on"), Some(ship)) => {
            let rest: Vec<&str> = text.split_whitespace().skip(2).collect();
            let (agent, interface) = (rest.first().copied().unwrap_or("counter"), rest.get(1).copied().unwrap_or("counter"));
            let within = rest.get(2).and_then(|n| n.parse().ok()).unwrap_or(ask::DEFAULT_WITHIN_MILLIS);
            let payload = rest.get(3..).map(|words| words.join(" ")).unwrap_or_default();
            let number = ask::to(ship, agent, interface, payload.as_bytes(), within);
            kv::put(b"last-asked", number.to_string().as_bytes());
            number.to_string()
        }
        // Put the same question several times in one event: `ask-many <ship> <count> <within>`.
        (Some("ask-many"), Some(ship)) => {
            let rest: Vec<&str> = text.split_whitespace().skip(2).collect();
            let count: u32 = rest.first().and_then(|n| n.parse().ok()).unwrap_or(1);
            let within = rest.get(1).and_then(|n| n.parse().ok()).unwrap_or(ask::DEFAULT_WITHIN_MILLIS);
            (0..count).map(|_| ask::to(ship, "counter", "counter", b"hits", within).to_string()).collect::<Vec<_>>().join(" ")
        }
        // Put a question and then fail, to check the question goes with everything else.
        (Some("ask-then-crash"), Some(ship)) => {
            ask::to(ship, "counter", "counter", b"hits", ask::DEFAULT_WITHIN_MILLIS);
            panic!("crash requested");
        }
        // Give up on a question.
        (Some("drop-ask"), Some(number)) => ask::drop(number.parse().unwrap_or(0)).to_string(),
        // Every answer that has come back, as a command.
        (Some("answers"), None) => String::from_utf8_lossy(&kv::get(b"answers").unwrap_or_default()).into_owned(),
        // Send the tally agent on another ship a command that records who it came from.
        (Some("hail"), Some(ship)) => {
            ship_sdk::send_to(ship, "tally", "tally", b"note");
            "sent".to_string()
        }
        // Send to another ship and then fail, to check the command goes with everything else.
        (Some("tell-then-crash"), Some(ship)) => {
            ship_sdk::send_to(ship, "counter", "counter", b"inc hits");
            panic!("crash requested");
        }
        // Behave like an agent built before checkpoints existed, or stop doing so.
        (Some("old"), None) => {
            kv::put(b"old", b"yes");
            "ok".to_string()
        }
        (Some("modern"), None) => {
            kv::delete(b"old");
            "ok".to_string()
        }
        // Stop refusing entries that mention poison.
        (Some("tolerate"), None) => {
            kv::put(b"tolerate", b"yes");
            "ok".to_string()
        }
        // Send the counter whatever follows, as a command.
        (Some("forward"), Some(_)) => {
            send("counter", "counter", text.trim_start()["forward".len()..].trim().as_bytes());
            "sent".to_string()
        }
        // Send ourselves a command that records who it came from.
        (Some("relay"), None) => {
            send("tally", "tally", b"note");
            "sent".to_string()
        }
        (Some("note"), None) => {
            kv::put(b"note", caller().as_bytes());
            "noted".to_string()
        }
        _ => "error: unknown command".to_string(),
    };
    reply.into_bytes()
}

/// Read handler. `last-seen` returns what `bump` last read; `write` tries to break the rule
/// that reads cannot change anything; `via-counter <key>` reads through to the counter.
fn view(request: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(request);
    let mut words = text.split_whitespace();
    match (words.next(), words.next()) {
        (Some("last-seen"), None) => kv::get(b"last-seen").unwrap_or_default(),
        (Some("pings"), None) => {
            let bytes = kv::get(b"pings").unwrap_or_default();
            u32::from_le_bytes(bytes.try_into().unwrap_or_default()).to_string().into_bytes()
        }
        (Some("write"), None) => {
            kv::put(b"last-seen", b"changed by a read");
            Vec::new()
        }
        (Some("via-counter"), Some(key)) => read("counter", "counter", key.as_bytes()),
        // How many log entries this agent has taken, and the latest one.
        (Some("seen"), None) => seen("").to_string().into_bytes(),
        (Some("last"), None) => kv::get(b"last").unwrap_or_default(),
        // The same for the counter's log on another ship, and why it stopped, if it has.
        (Some("seen-on"), Some(ship)) => seen(ship).to_string().into_bytes(),
        (Some("last-on"), Some(ship)) => kv::get(&key("last", ship)).unwrap_or_default(),
        (Some("jumps-on"), Some(ship)) => kv::get(&key("jumps", ship)).map_or(0, |jumps| jumps.len()).to_string().into_bytes(),
        (Some("stopped-on"), Some(ship)) => kv::get(&key("stopped", ship)).unwrap_or_default(),
        (Some("idles"), None) => kv::get(b"idles").map_or(0, |idles| idles.len()).to_string().into_bytes(),
        (Some("poked"), None) => kv::get(b"poked").map_or(0, |poked| poked.len()).to_string().into_bytes(),
        (Some("rounds-on"), Some(ship)) => kv::get(&key("rounds", ship)).map_or(0, |rounds| rounds.len()).to_string().into_bytes(),
        // How many times this agent was handed a checkpoint in place of entries.
        (Some("jumps"), None) => kv::get(b"jumps").map_or(0, |jumps| jumps.len()).to_string().into_bytes(),
        (Some("note"), None) => kv::get(b"note").unwrap_or_default(),
        // The number the last command sent to another ship went under, and every receipt
        // that has come back, one to a line.
        (Some("last-sent"), None) => kv::get(b"last-sent").unwrap_or_default(),
        (Some("receipts"), None) => kv::get(b"receipts").unwrap_or_default(),
        // Every answer to a question this agent put to another ship, one to a line.
        (Some("answers"), None) => kv::get(b"answers").unwrap_or_default(),
        (Some("who"), None) => caller().into_bytes(),
        // A read of ourselves, to see what a nested read is told about its caller.
        (Some("via-self"), None) => read("tally", "tally", b"who"),
        // A reply larger than the first buffer the SDK offers, directly and through a nested read.
        (Some("big"), None) => vec![b'x'; 10_000],
        (Some("via-big"), None) => read("tally", "tally", b"big"),
        // Read an agent the tests install as `slow`, whose answer is costly to produce.
        (Some("via-slow"), None) => read("slow", "slow", b""),
        (Some("emit"), None) => {
            emit(b"sent by a read");
            Vec::new()
        }
        _ => b"error: unknown read".to_vec(),
    }
}

/// Where something about a followed log is kept: under its plain name for a log on this
/// ship, and with the ship's name added for one on another ship.
fn key(name: &str, ship: &str) -> Vec<u8> {
    let ship = ship.trim_start_matches('~');
    if ship.is_empty() { name.as_bytes().to_vec() } else { format!("{name}@{ship}").into_bytes() }
}

fn seen(ship: &str) -> u32 {
    u32::from_le_bytes(kv::get(&key("seen", ship)).unwrap_or_default().try_into().unwrap_or_default())
}

/// Called when a log this agent follows has new entries. It takes a few at a time on purpose,
/// so that a longer log needs several rounds. An entry mentioning poison makes it fail until
/// told to tolerate that, to show that entries a failed round took are offered again.
fn notified(_: &[u8]) -> Vec<u8> {
    let call = invocation();
    let source = call.source.unwrap_or_default();
    let (ship, publisher) = (source.ship.as_str(), source.agent);
    if kv::get(b"lazy").is_some() {
        let mut poked = kv::get(b"poked").unwrap_or_default();
        poked.push(b'p');
        kv::put(b"poked", &poked);
        return Vec::new();
    }
    let batch = match kv::get(b"old") {
        Some(_) => old_next(&publisher, &call.interface, 3),
        None => log::next_on(ship, &publisher, &call.interface, 3),
    };
    let mut count = seen(ship);
    // Too far behind for the entries to still exist: take the publisher's state as of the
    // entry the checkpoint stands for, and carry on counting from there.
    if let Some(checkpoint) = &batch.checkpoint {
        count = checkpoint.seq as u32;
        kv::put(&key("last", ship), &checkpoint.state);
        let mut jumps = kv::get(&key("jumps", ship)).unwrap_or_default();
        jumps.push(b'j');
        kv::put(&key("jumps", ship), &jumps);
    }
    for entry in &batch.entries {
        if entry.payload.starts_with(b"poison") && kv::get(b"tolerate").is_none() {
            panic!("refusing a poisoned entry");
        }
        count += 1;
        assert_eq!(entry.seq, count as u64, "entries arrived out of order");
        kv::put(&key("last", ship), &entry.payload);
    }
    kv::put(&key("seen", ship), &count.to_le_bytes());
    // An agent that will not take no for an answer: told a log has stopped, it asks again.
    if batch.stopped.is_some() && kv::get(b"stubborn").is_some() {
        log::follow_on(ship, &publisher, &call.interface);
    }
    if !ship.is_empty() {
        // How many times this agent was prompted about that ship's log, and what it was
        // told about the log having stopped.
        let mut rounds = kv::get(&key("rounds", ship)).unwrap_or_default();
        rounds.push(b'r');
        kv::put(&key("rounds", ship), &rounds);
        match &batch.stopped {
            Some(why) => kv::put(&key("stopped", ship), why.as_bytes()),
            None => kv::delete(&key("stopped", ship)),
        }
    }
    Vec::new()
}

/// Called with what became of each command this agent sent to another ship. Keeps them all,
/// with who the runtime says the receipt is from.
fn receipted(receipt: &ship_sdk::Receipt) {
    let verdict = match receipt.verdict() {
        ship_sdk::Verdict::Ran => "ran",
        ship_sdk::Verdict::Denied => "denied",
        ship_sdk::Verdict::Failed => "failed",
        ship_sdk::Verdict::Limit => "limit",
        ship_sdk::Verdict::Malformed => "malformed",
        ship_sdk::Verdict::Lost => "lost",
        ship_sdk::Verdict::Refused => "refused",
        ship_sdk::Verdict::Unspecified => "unknown",
    };
    // A long reply is noted by its length, so that the list stays small.
    // A reply, even an empty one, is marked; RAN with no reply marked says nothing more.
    let reply = match receipt.reply.len() {
        _ if !receipt.replied => String::new(),
        len if len > 64 => format!(" reply of {len} bytes"),
        _ => format!(" reply {}", String::from_utf8_lossy(&receipt.reply)),
    };
    let line = format!(
        "{} ~{}/{} {} {verdict} [{}] from {}{reply}\n",
        receipt.about,
        receipt.ship,
        receipt.agent,
        receipt.interface,
        receipt.reason,
        caller()
    );
    kv::delete(b"ballast");
    let mut all = kv::get(b"receipts").unwrap_or_default();
    all.extend_from_slice(line.as_bytes());
    kv::put(b"receipts", &all);
}

/// Called with what came of each question this agent put to another ship. Keeps them all, one
/// to a line: the number, where it was put, the outcome, the reason, the reply, and who the
/// runtime says the answer is from.
fn answered(answer: &ask::Answered) {
    let outcome = match answer.outcome() {
        ask::Outcome::Reply => "reply",
        ask::Outcome::Denied => "denied",
        ask::Outcome::Failed => "failed",
        ask::Outcome::Limit => "limit",
        ask::Outcome::NoAnswer => "no-answer",
        ask::Outcome::Unreachable => "unreachable",
        ask::Outcome::NotUnderstood => "not-understood",
        ask::Outcome::Unspecified => "unknown",
    };
    let line = format!(
        "{} ~{}/{} {} {outcome} [{}] {} from {}\n",
        answer.about,
        answer.ship,
        answer.agent,
        answer.interface,
        answer.reason,
        if answer.reply.len() > 64 { format!("({} bytes)", answer.reply.len()) } else { String::from_utf8_lossy(&answer.reply).into_owned() },
        caller()
    );
    let mut all = kv::get(b"answers").unwrap_or_default();
    all.extend_from_slice(line.as_bytes());
    kv::put(b"answers", &all);
}

agent!(handle, read = view, notify = notified, receipt = receipted, answer = answered);
