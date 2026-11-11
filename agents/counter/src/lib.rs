use ship_sdk::{agent, emit, kv};

fn read(key: &str) -> i64 {
    kv::get(key.as_bytes())
        .and_then(|bytes| bytes.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(0)
}

fn write(key: &str, value: i64) {
    kv::put(key.as_bytes(), &value.to_le_bytes());
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

agent!(handle, read = value);
