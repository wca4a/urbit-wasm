//! A test agent that depends on the counter agent: it reads a counter, and asks for it to be
//! incremented. Used to exercise permissions and queued commands.

use ship_sdk::{agent, emit, invocation, kv, log, read, send};

/// Who is calling and through which interface, as the runtime reports it.
fn caller() -> String {
    let call = invocation();
    let source = call.source.unwrap_or_default();
    format!("{} {}", if source.owner { "owner" } else { source.agent.as_str() }, call.interface)
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
        // Send ourselves whatever follows, as a command to run later.
        (Some("later"), Some(_)) => {
            send("tally", "tally", text.trim_start()["later".len()..].trim().as_bytes());
            "sent".to_string()
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
        (Some("seen"), None) => seen().to_string().into_bytes(),
        (Some("last"), None) => kv::get(b"last").unwrap_or_default(),
        (Some("note"), None) => kv::get(b"note").unwrap_or_default(),
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

fn seen() -> u32 {
    u32::from_le_bytes(kv::get(b"seen").unwrap_or_default().try_into().unwrap_or_default())
}

/// Called when a log this agent follows has new entries. It takes a few at a time on purpose,
/// so that a longer log needs several rounds. An entry mentioning poison makes it fail until
/// told to tolerate that, to show that entries a failed round took are offered again.
fn notified(_: &[u8]) -> Vec<u8> {
    let call = invocation();
    let publisher = call.source.unwrap_or_default().agent;
    let (entries, _more) = log::next(&publisher, &call.interface, 3);
    let mut count = seen();
    for entry in &entries {
        if entry.payload.starts_with(b"poison") && kv::get(b"tolerate").is_none() {
            panic!("refusing a poisoned entry");
        }
        count += 1;
        assert_eq!(entry.seq, count as u64, "entries arrived out of order");
        kv::put(b"last", &entry.payload);
    }
    kv::put(b"seen", &count.to_le_bytes());
    Vec::new()
}

agent!(handle, read = view, notify = notified);
