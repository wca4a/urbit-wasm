use ship_sdk::{agent, emit, files, kv, log};

fn read(key: &str) -> i64 {
    kv::get(key.as_bytes())
        .and_then(|bytes| bytes.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(0)
}

fn write(key: &str, value: i64) {
    kv::put(key.as_bytes(), &value.to_le_bytes());
}

/// A file id written in hexadecimal, if it is one.
fn file_id(text: &str) -> Option<[u8; 32]> {
    let bytes: Vec<u8> = (0..text.len() / 2).filter_map(|i| text.get(2 * i..2 * i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok())).collect();
    <[u8; 32]>::try_from(bytes).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key under which this agent notes that a ship may have a file.
fn let_key(ship: &str, id: &[u8; 32]) -> Vec<u8> {
    format!("let {} {}", ship.trim_start_matches('~'), hex(id)).into_bytes()
}

fn handle(event: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(event);
    let mut words = text.split_whitespace();
    let reply = match (words.next(), words.next(), words.next()) {
        (Some("inc"), Some(key), by) => {
            let value = read(key) + by.and_then(|n| n.parse().ok()).unwrap_or(1);
            write(key, value);
            value.to_string()
        }
        (Some("get"), Some(key), None) => read(key).to_string(),
        // What the ship holds of a file this agent claims, by its id in hexadecimal.
        (Some("file"), Some(id), None) => match file_id(id).and_then(|id| files::info(&id)) {
            Some(info) => format!("{} {} {}{}", info.length, info.chunks, info.media_type, if info.open { " open" } else { "" }),
            None => "none".to_string(),
        },
        // Mark a file this agent claims open to every ship, or take the mark off.
        (Some("open"), Some(id), None) => file_id(id).map_or(false, |id| files::open(&id)).to_string(),
        (Some("close"), Some(id), None) => file_id(id).map_or(false, |id| files::close(&id)).to_string(),
        // Let one ship have a file, or stop letting it: what the file_ask handler goes by.
        (Some("let"), Some(ship), Some(id)) => match file_id(id) {
            Some(id) => {
                kv::put(&let_key(ship, &id), b"yes");
                "ok".to_string()
            }
            None => "error: not a file id".to_string(),
        },
        (Some("unlet"), Some(ship), Some(id)) => match file_id(id) {
            Some(id) => {
                kv::delete(&let_key(ship, &id));
                "ok".to_string()
            }
            None => "error: not a file id".to_string(),
        },
        // How the file_ask handler behaves: `trap` makes it fail, `spin` makes it run until it
        // is stopped, `meddle` makes it try to change something, `mark` makes it try to mark
        // the file open, `via` makes it go by the keeper's `gate` counter, anything else
        // makes it behave.
        (Some("asks"), Some(mode), None) => {
            kv::put(b"asks", mode.as_bytes());
            "ok".to_string()
        }
        // Publish an entry and then fail, to check that the entry goes with everything else.
        (Some("log-then-crash"), Some(key), None) => {
            write(key, read(key) + 1);
            log::append("counter", b"must never be seen");
            panic!("crash requested");
        }
        // Publish an entry of a given size.
        (Some("log-big"), Some(len), None) => {
            kv::put(b"latest", format!("big {len}").as_bytes());
            log::append("counter", &vec![b'x'; len.parse().unwrap_or(0)]).to_string()
        }
        // Add one, and publish the new value in this agent's log for anyone following it. The
        // latest entry is also what this log's state amounts to, so it is kept for checkpoints.
        (Some("log"), Some(key), None) => {
            let value = read(key) + 1;
            write(key, value);
            let entry = format!("{key}={value}");
            kv::put(b"latest", entry.as_bytes());
            log::append("counter", entry.as_bytes()).to_string()
        }
        // Add a line to the journal: a log that is a history, never summed up by a checkpoint.
        (Some("journal"), Some(_), _) => {
            log::append("journal", text.trim_start()["journal".len()..].trim().as_bytes()).to_string()
        }
        // Make this log's state a given size.
        (Some("state"), Some(len), None) => {
            kv::put(b"latest", &vec![b's'; len.parse().unwrap_or(0)]);
            "ok".to_string()
        }
        // How the checkpoint handler behaves: `broken` makes it fail, `meddling` makes it try
        // to change something, `padded` makes its answer large, anything else makes it behave.
        (Some("checkpoints"), Some(mode), None) => {
            kv::put(b"checkpoints", mode.as_bytes());
            "ok".to_string()
        }
        // Send the counter on another ship whatever follows the ship's name, as a command.
        // This agent has no receipt handler, so it is never told what became of it.
        (Some("pass"), Some(ship), _) => {
            let rest = text.trim_start()["pass".len()..].trim_start()[ship.len()..].trim();
            ship_sdk::send_to(ship, "counter", "counter", rest.as_bytes()).to_string()
        }
        // Let another ship follow this agent's log, or every ship with "*", or stop.
        (Some("share"), Some(ship), None) => {
            log::share("counter", ship);
            "ok".to_string()
        }
        (Some("unshare"), Some(ship), None) => {
            log::unshare("counter", ship);
            "ok".to_string()
        }
        // Try to share a log this agent does not have.
        (Some("share-other"), Some(ship), None) => {
            log::share("tally", ship);
            "ok".to_string()
        }
        (Some("del"), Some(key), None) => {
            kv::delete(key.as_bytes());
            "ok".to_string()
        }
        (Some("say"), Some(_), _) => {
            emit(text.trim_start()["say".len()..].trim().as_bytes());
            "sent".to_string()
        }
        // The remaining commands exist to exercise the runtime's failure paths.
        (Some("crash"), Some(key), None) => {
            write(key, 999);
            emit(b"must never be delivered");
            panic!("crash requested");
        }
        (Some("spin"), key, None) => {
            if let Some(key) = key {
                write(key, 999);
            }
            loop {
                std::hint::black_box(0u8);
            }
        }
        (Some("hog"), None, None) => {
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            loop {
                chunks.push(vec![1u8; 1 << 20]);
            }
        }
        (Some("big"), Some(len), None) => {
            kv::put(b"big", &vec![7u8; len.parse().unwrap_or(0)]);
            "ok".to_string()
        }
        _ => "error: unknown command".to_string(),
    };
    reply.into_bytes()
}

/// Read handler: the payload is a key, the reply its current value.
fn value(key: &[u8]) -> Vec<u8> {
    read(&String::from_utf8_lossy(key)).to_string().into_bytes()
}

/// Checkpoint handler: the state behind the `counter` log is its latest entry. The journal is
/// a history, so it has no state that could stand in for its entries.
fn state(log: &str) -> Option<Vec<u8>> {
    match kv::get(b"checkpoints").as_deref() {
        Some(b"broken") => panic!("checkpoints are broken"),
        Some(b"meddling") => kv::put(b"latest", b"changed while describing it"),
        _ => {}
    }
    let latest = kv::get(b"latest").unwrap_or_default();
    match (log, kv::get(b"checkpoints").as_deref()) {
        ("counter", Some(b"padded")) => Some([latest, vec![b'.'; 10_000]].concat()),
        ("counter", _) => Some(latest),
        _ => None,
    }
}

/// Whether another ship may have a file this agent claims: only if it has been let.
fn asked(question: &files::FileAsk) -> bool {
    match kv::get(b"asks").as_deref() {
        Some(b"trap") => panic!("asked to fail"),
        Some(b"spin") => loop {
            std::hint::black_box(0u8);
        },
        Some(b"meddle") => {
            write("meddled", 1);
            return true;
        }
        // Yes if the keeper agent's `gate` counter is set: an answer that rests on a read of
        // another agent, which needs a grant.
        Some(b"via") => return ship_sdk::read("keeper", "counter", b"gate") != b"0",
        _ => {}
    }
    let Ok(id) = <[u8; 32]>::try_from(question.id.as_slice()) else { return false };
    // Try to mark the file open while answering, and say yes if that worked.
    if kv::get(b"asks").as_deref() == Some(b"mark") {
        return files::open(&id);
    }
    kv::get(&let_key(&question.ship, &id)).is_some()
}

agent!(handle, read = value, checkpoint = state, file_ask = asked);
