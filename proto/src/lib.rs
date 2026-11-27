//! Message types shared by the runtime, the kernel, and agents, generated from `ship.proto`.

pub use prost;
pub use prost::Message;

include!(concat!(env!("OUT_DIR"), "/ship.v1.rs"));

/// The longest interface name the kernel and the runtime accept.
pub const MAX_INTERFACE_BYTES: usize = 128;

/// The interface a `service` in an agent's description stands for: the service's name turned
/// from CamelCase into lower-case words joined by `-` (`GroupChat` is `group-chat`), or `None`
/// if that does not give a name every ship accepts for an interface. Shared by the code
/// generator and the runtime, so that the two never disagree.
///
/// A word starts at a capital that follows a small letter or a digit (`Chat2Go` is
/// `chat2-go`), and at the last capital of a run of them that is followed by a small letter
/// (`HTTPServer` is `http-server`); an underscore also ends a word, and is dropped (`foo_bar` is
/// `foo-bar`). The name must come out starting with a letter, with no empty word (so no leading,
/// trailing or doubled underscore), and at most `MAX_INTERFACE_BYTES` long: then it is one the
/// default kernel accepts (lower-case letters, digits, `-`, `.` and `_`) and the runtime too.
pub fn interface_of_service(name: &str) -> Option<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let chars: Vec<char> = name.chars().collect();
    let mut words: Vec<String> = vec![String::new()];
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            words.push(String::new());
            continue;
        }
        if c.is_ascii_uppercase() && i > 0 {
            let before = chars[i - 1];
            let after = chars.get(i + 1).copied();
            let starts = before.is_ascii_lowercase() || before.is_ascii_digit() || (before.is_ascii_uppercase() && after.is_some_and(|a| a.is_ascii_lowercase()));
            if starts && !words.last().is_some_and(String::is_empty) {
                words.push(String::new());
            }
        }
        words.last_mut().expect("there is always a word").push(c.to_ascii_lowercase());
    }
    if words.iter().any(String::is_empty) {
        return None;
    }
    let joined = words.join("-");
    let ok = joined.len() <= MAX_INTERFACE_BYTES && joined.as_bytes()[0].is_ascii_lowercase();
    ok.then_some(joined)
}

#[cfg(test)]
mod tests {
    use super::interface_of_service as of;

    #[test]
    fn service_names_turn_into_interface_names() {
        for (service, interface) in [
            ("Guestbook", "guestbook"),
            ("GroupChat", "group-chat"),
            ("HTTPServer", "http-server"),
            ("ServeHTTP", "serve-http"),
            ("Chat2Go", "chat2-go"),
            ("V2", "v2"),
            ("guestbook", "guestbook"),
            ("foo_bar", "foo-bar"),
            ("Foo_Bar", "foo-bar"),
            ("ABC", "abc"),
        ] {
            assert_eq!(of(service).as_deref(), Some(interface), "{service}");
        }
        for service in ["", "_Hidden", "Trailing_", "Two__Bars", "9Lives", "With-Dash", "Café", &format!("A{}", "b".repeat(128))] {
            assert_eq!(of(service), None, "{service}");
        }
        assert_eq!(of(&format!("A{}", "b".repeat(127))).map(|name| name.len()), Some(128));
    }
}
