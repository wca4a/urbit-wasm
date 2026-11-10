//! Guest-side bindings for agents. State lives in the host store, never in agent memory.

use std::cell::RefCell;

#[link(wasm_import_module = "host")]
extern "C" {
    fn kv_get(key: *const u8, key_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    fn kv_put(key: *const u8, key_len: u32, val: *const u8, val_len: u32);
    fn kv_delete(key: *const u8, key_len: u32);
    #[link_name = "emit"]
    fn host_emit(ptr: *const u8, len: u32);
}

pub mod kv {
    pub fn get(key: &[u8]) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 256];
        loop {
            let len = unsafe {
                super::kv_get(key.as_ptr(), key.len() as u32, buf.as_mut_ptr(), buf.len() as u32)
            };
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
    let event = Vec::from_raw_parts(ptr, len as usize, len as usize);
    let reply = handler(&event);
    REPLY.with(|slot| {
        *slot.borrow_mut() = reply;
        let reply = slot.borrow();
        ((reply.as_ptr() as u64) << 32) | reply.len() as u64
    })
}

/// Export `handler: fn(&[u8]) -> Vec<u8>` as this module's event handler.
#[macro_export]
macro_rules! agent {
    ($handler:path) => {
        // Internal names differ from the exported ones so they cannot clash with the agent's own.
        const _: () = {
            #[export_name = "alloc"]
            pub extern "C" fn __ship_alloc(len: u32) -> *mut u8 {
                $crate::__alloc(len)
            }

            #[export_name = "handle"]
            pub unsafe extern "C" fn __ship_handle(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, $handler)
            }
        };
    };
}
