//! Guest-side bindings for agents. State lives in the host store, never in agent memory.

use std::cell::RefCell;

pub use ship_proto as proto;
use ship_proto::{
    AppendRequest, CheckpointReply, FollowRequest, Invocation, Message, NextReply, NextRequest, ReadRequest, SendRequest,
};

#[link(wasm_import_module = "host")]
extern "C" {
    fn kv_get(key: *const u8, key_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    fn kv_put(key: *const u8, key_len: u32, val: *const u8, val_len: u32);
    fn kv_delete(key: *const u8, key_len: u32);
    #[link_name = "emit"]
    fn host_emit(ptr: *const u8, len: u32);
    #[link_name = "invocation"]
    fn host_invocation(buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "read"]
    fn host_read(req: *const u8, req_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "take_reply"]
    fn host_take_reply(buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "send"]
    fn host_send(req: *const u8, req_len: u32);
    #[link_name = "log_append"]
    fn host_log_append(req: *const u8, req_len: u32) -> i64;
    #[link_name = "log_follow"]
    fn host_log_follow(req: *const u8, req_len: u32);
    #[link_name = "log_next"]
    fn host_log_next(req: *const u8, req_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
}

/// Call a host function that fills a buffer and reports the full length, growing the buffer and
/// calling again when the answer did not fit. `None` when the host reports nothing there.
fn fetch(first_guess: usize, mut call: impl FnMut(*mut u8, u32) -> i64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; first_guess];
    loop {
        let len = call(buf.as_mut_ptr(), buf.len() as u32);
        if len < 0 {
            return None;
        }
        let len = len as usize;
        if len <= buf.len() {
            buf.truncate(len);
            return Some(buf);
        }
        buf.resize(len, 0);
    }
}

/// This agent's own keys. No other agent can see or change them.
pub mod kv {
    pub fn get(key: &[u8]) -> Option<Vec<u8>> {
        super::fetch(256, |buf, cap| unsafe { super::kv_get(key.as_ptr(), key.len() as u32, buf, cap) })
    }

    pub fn put(key: &[u8], value: &[u8]) {
        unsafe { super::kv_put(key.as_ptr(), key.len() as u32, value.as_ptr(), value.len() as u32) }
    }

    pub fn delete(key: &[u8]) {
        unsafe { super::kv_delete(key.as_ptr(), key.len() as u32) }
    }
}

/// Queue an outgoing message. It is only released if this event commits.
pub fn emit(payload: &[u8]) {
    unsafe { host_emit(payload.as_ptr(), payload.len() as u32) }
}

/// Who is calling, and through which interface.
pub fn invocation() -> Invocation {
    let bytes = fetch(256, |buf, cap| unsafe { host_invocation(buf, cap) }).unwrap_or_default();
    Invocation::decode(&*bytes).expect("the runtime sent a malformed invocation")
}

/// Read from another agent on this ship. It answers immediately and cannot change anything.
/// The event is rejected if this agent has no permission for that interface.
pub fn read(agent: &str, interface: &str, payload: &[u8]) -> Vec<u8> {
    let request =
        ReadRequest { agent: agent.into(), interface: interface.into(), payload: payload.to_vec() }.encode_to_vec();
    once(|buf, cap| unsafe { host_read(request.as_ptr(), request.len() as u32, buf, cap) })
}

/// Make a host call that must run exactly once and returns a buffer. If its answer is bigger
/// than the first buffer, the runtime keeps it and a second call only collects it.
fn once(mut call: impl FnMut(*mut u8, u32) -> i64) -> Vec<u8> {
    let mut first = true;
    fetch(4096, |buf, cap| if std::mem::take(&mut first) { call(buf, cap) } else { unsafe { host_take_reply(buf, cap) } })
        .unwrap_or_default()
}

/// Logs: append-only, numbered lists that other agents, other ships, and the owner's clients
/// follow. An agent has one log per interface it offers, named after that interface.
pub mod log {
    use super::*;
    pub use ship_proto::{Checkpoint, Entry};

    /// What `next` hands over.
    pub struct Batch {
        /// Set when this agent was so far behind that the entries it needed have been dropped.
        /// Replace whatever was built from this log with `state`, which is the publisher's
        /// state as of entry `seq`. `entries` is then empty, and the next call carries on from
        /// there.
        pub checkpoint: Option<Checkpoint>,
        pub entries: Vec<Entry>,
        /// Whether the log has more beyond this batch.
        pub more: bool,
    }

    /// Add an entry to one of this agent's own logs and return its number. The runtime signs
    /// it and tells every follower. Kept only if this event commits.
    pub fn append(log: &str, payload: &[u8]) -> u64 {
        let request = AppendRequest { log: log.into(), payload: payload.to_vec() }.encode_to_vec();
        unsafe { host_log_append(request.as_ptr(), request.len() as u32) as u64 }
    }

    /// Start following another agent's log from its first entry. The agent's notify handler is
    /// then called whenever the log has entries it has not taken. Following twice is harmless.
    pub fn follow(agent: &str, log: &str) {
        let request = FollowRequest { agent: agent.into(), log: log.into() }.encode_to_vec();
        unsafe { host_log_follow(request.as_ptr(), request.len() as u32) }
    }

    /// Take up to `max` entries after this agent's position in a log it follows. The position
    /// moves past them only if this event commits, so an entry is never lost and never handled
    /// twice.
    pub fn next(agent: &str, log: &str, max: u32) -> Batch {
        let request = NextRequest { agent: agent.into(), log: log.into(), max, checkpoints: true }.encode_to_vec();
        let bytes = once(|buf, cap| unsafe { host_log_next(request.as_ptr(), request.len() as u32, buf, cap) });
        let reply = NextReply::decode(&*bytes).expect("the runtime sent a malformed log reply");
        Batch { checkpoint: reply.checkpoint, entries: reply.entries, more: reply.more }
    }
}

/// Send a command to another agent on this ship. It runs later, as that agent's own event, and
/// only if this event commits. The event is rejected if this agent has no permission.
pub fn send(agent: &str, interface: &str, payload: &[u8]) {
    let request =
        SendRequest { agent: agent.into(), interface: interface.into(), payload: payload.to_vec() }.encode_to_vec();
    unsafe { host_send(request.as_ptr(), request.len() as u32) }
}

thread_local! {
    static REPLY: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[doc(hidden)]
pub fn __alloc(len: u32) -> *mut u8 {
    Box::into_raw(vec![0u8; len as usize].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` must come from `__alloc(len)` and must not be used again by the caller.
#[doc(hidden)]
pub unsafe fn __handle(ptr: *mut u8, len: u32, handler: fn(&[u8]) -> Vec<u8>) -> u64 {
    let input = Vec::from_raw_parts(ptr, len as usize, len as usize);
    let reply = handler(&input);
    REPLY.with(|slot| {
        *slot.borrow_mut() = reply;
        let reply = slot.borrow();
        ((reply.as_ptr() as u64) << 32) | reply.len() as u64
    })
}

#[doc(hidden)]
pub fn __checkpoint(log: &[u8], handler: fn(&str) -> Option<Vec<u8>>) -> Vec<u8> {
    CheckpointReply { state: handler(&String::from_utf8_lossy(log)) }.encode_to_vec()
}

/// Export the allocator the runtime uses to hand input to this module.
#[macro_export]
macro_rules! export_alloc {
    () => {
        const _: () = {
            #[export_name = "alloc"]
            pub extern "C" fn __ship_alloc(len: u32) -> *mut u8 {
                $crate::__alloc(len)
            }
        };
    };
}

/// Export `handler: fn(&[u8]) -> Vec<u8>` under `name`.
#[macro_export]
macro_rules! export_fn {
    ($name:literal, $handler:path) => {
        // The internal name differs from the exported one so it cannot clash with the module's own.
        const _: () = {
            #[export_name = $name]
            pub unsafe extern "C" fn __ship_export(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, $handler)
            }
        };
    };
}

/// Declare an agent: a command handler, then any of `read = f`, `notify = f`, `checkpoint = f`.
///
/// The command, read, and notify handlers are `fn(&[u8]) -> Vec<u8>`. A read handler cannot
/// write, send, or emit. The notify handler is called when a log this agent follows has new
/// entries; `invocation()` says which.
///
/// The checkpoint handler is `fn(&str) -> Option<Vec<u8>>`. The runtime calls it with the name
/// of one of this agent's logs once that log has grown enough, and it can only read. Returning
/// the present state behind the log lets the runtime drop old entries: a follower that is far
/// behind is handed that state in place of them. The runtime signs what is returned as the
/// state as of the log's newest entry, and has no way to check that it is. So an agent must
/// only change the state behind a log in the same event that appends the entry describing the
/// change, and the state must be one a follower can use in place of every entry before it. Returning `None` says the log is a history
/// whose every entry matters, and it is then kept whole. An agent with no checkpoint handler is
/// never asked, and its logs are kept whole.
#[macro_export]
macro_rules! agent {
    ($command:path $(, $role:ident = $handler:path)* $(,)?) => {
        $crate::export_alloc!();
        $crate::export_fn!("handle", $command);
        $($crate::__export_role!($role, $handler);)*
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __export_role {
    (read, $handler:path) => {
        $crate::export_fn!("read", $handler);
    };
    (notify, $handler:path) => {
        $crate::export_fn!("notify", $handler);
    };
    (checkpoint, $handler:path) => {
        const _: () = {
            #[export_name = "checkpoint"]
            pub unsafe extern "C" fn __ship_export(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, |log| $crate::__checkpoint(log, $handler))
            }
        };
    };
}
