//! Guest-side bindings for agents. State lives in the host store, never in agent memory.

use std::cell::RefCell;

pub use ship_proto as proto;
use ship_proto::{Invocation, Message, ReadRequest, SendRequest};

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
    // The read runs once. If its answer is bigger than the first buffer, the runtime keeps it
    // and the second call only collects it.
    let mut first = true;
    fetch(4096, |buf, cap| unsafe {
        if std::mem::take(&mut first) {
            host_read(request.as_ptr(), request.len() as u32, buf, cap)
        } else {
            host_take_reply(buf, cap)
        }
    })
    .unwrap_or_default()
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

/// Declare an agent: a command handler, and optionally a read handler. Both are
/// `fn(&[u8]) -> Vec<u8>`. A read handler cannot write, send, or emit.
#[macro_export]
macro_rules! agent {
    ($command:path) => {
        $crate::export_alloc!();
        $crate::export_fn!("handle", $command);
    };
    ($command:path, read = $read:path) => {
        $crate::agent!($command);
        $crate::export_fn!("read", $read);
    };
}
