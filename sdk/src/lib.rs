//! Guest-side bindings for agents. State lives in the host store, never in agent memory.

use std::cell::RefCell;

pub use ship_proto as proto;
use ship_proto::{
    AppendRequest, CheckpointReply, FollowRequest, Invocation, Message, NextReply, NextRequest, ReadRequest, SendRequest,
    ShareRequest,
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
    #[link_name = "send_to"]
    fn host_send_to(req: *const u8, req_len: u32) -> i64;
    #[link_name = "log_append"]
    fn host_log_append(req: *const u8, req_len: u32) -> i64;
    #[link_name = "log_follow"]
    fn host_log_follow(req: *const u8, req_len: u32);
    #[link_name = "log_next"]
    fn host_log_next(req: *const u8, req_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "log_unfollow"]
    fn host_log_unfollow(req: *const u8, req_len: u32);
    #[link_name = "log_share"]
    fn host_log_share(req: *const u8, req_len: u32);
    #[link_name = "file_info"]
    fn host_file_info(id: *const u8, id_len: u32, buf: *mut u8, buf_cap: u32) -> i64;
    #[link_name = "file_mark"]
    fn host_file_mark(req: *const u8, req_len: u32) -> i64;
    #[link_name = "ask_to"]
    fn host_ask_to(req: *const u8, req_len: u32) -> i64;
    #[link_name = "ask_drop"]
    fn host_ask_drop(number: u64) -> i64;
}

/// Questions to agents on other ships. A question only reads: the other agent's read handler
/// answers it, nothing it does there is kept, and a question stores no application data on the
/// other ship. (Opening that ship for it, or putting another ship to sleep to make room for it,
/// can recover a transaction that a crash interrupted, copy pages that ordinary work had already
/// committed from the log beside the file into the file, and create or remove the files SQLite
/// keeps beside the ship's file; see the README.) An event is one transaction and cannot wait,
/// so the answer comes later, as an event of its own: an agent declared with `answer = f` is
/// handed an `Answered` for each question, exactly once, unless it dropped the question first.
pub mod ask {
    pub use ship_proto::{Answered, Outcome};
    use ship_proto::{AskRequest, Message};

    /// How long a question is given if the agent has no better idea: ten seconds.
    pub const DEFAULT_WITHIN_MILLIS: u64 = 10_000;

    /// Put a question to `agent`'s `interface` on another ship, and return the number its answer
    /// will carry. It is sent only if this event commits. Its time, `within_millis`, is stamped
    /// just before the event commits (whole milliseconds of the runtime's wall clock, so a slow
    /// commit uses some of it) and turned into a steady-clock deadline once, when the question's
    /// task starts, before it reads the row; a later change of the clock does not move it, though a
    /// restart reads the stamped time afresh. Only the network's giving up keeps that time: writing
    /// the answer down needs the ship (a busy ship delays it), and the `answer` handler runs when
    /// the ship next runs its queue, behind what is queued before it. The event is rejected if this
    /// agent's manifest does not name that ship (or "*"), agent, and interface with `ask` set, if
    /// `ship` is empty or this ship, if `within_millis` is 0 or more than the runtime allows, if
    /// the payload is larger than it allows, or if the ship has as many questions waiting as it
    /// may.
    ///
    /// The answer, or why there is none (the other ship refused, its agent failed or the question
    /// could not be routed there, it or its answer was too large or this ship had no room for the
    /// reply, no answer came in time, no try ever reached it, or what came back was not understood:
    /// see `Outcome`), is handed to the `answer` handler. A try that finds the destination absent
    /// from the directory ends the question as `Unreachable`, even if an earlier try reached it,
    /// while a try already awaiting its reply can still complete. Each try tells the other ship
    /// what is left of the time: at the poll in which the connection accepts a question's first
    /// bytes, the allowance in those bytes is no more than the whole milliseconds left to the
    /// asker's deadline by the clock reading taken in that poll, and no first bytes are accepted in
    /// a poll whose clock reading leaves less than a millisecond. The first-write rule uses the
    /// clock reading taken in the accepting poll, and time spent encoding, waiting inside the
    /// writer, or descheduled after that reading can carry actual acceptance past the deadline.
    /// Asking is harmless to repeat, so the runtime asks again, within the time, if the connection
    /// fails, and after a restart if the time has not run out.
    pub fn to(ship: &str, agent: &str, interface: &str, payload: &[u8], within_millis: u64) -> u64 {
        let request = AskRequest { ship: ship.into(), agent: agent.into(), interface: interface.into(), payload: payload.to_vec(), within_millis };
        let request = request.encode_to_vec();
        unsafe { super::host_ask_to(request.as_ptr(), request.len() as u32) as u64 }
    }

    /// Give up on a question. True if it was still waiting (or its answer was queued and had not
    /// yet been handed over); from the moment this event commits, no answer for it is handed to
    /// this agent, whatever arrives. False if there was nothing to drop.
    pub fn drop(number: u64) -> bool {
        unsafe { super::host_ask_drop(number) > 0 }
    }
}

/// Files on the ship. An agent keeps a reference to a file (`FileRef`: the ship, the file's
/// id, its length, and the agent there that claims it) and never its bytes: the owner's
/// devices put files in and take them out over HTTP, under the agent that claims them.
///
/// Another ship's owner can open a file through their own ship. Whether that ship may have it
/// is this agent's decision alone: an agent declared with `file_ask = f` is asked, and says
/// yes or no, unless it has marked the file open with `open`, which lets every ship that
/// names it have it without asking. Without a `file_ask` handler, and without the mark, no
/// other ship may have the agent's files.
pub mod files {
    pub use ship_proto::{FileAnswer, FileAsk, FileInfo, FileRef};
    use ship_proto::{FileMark, Message};

    /// What this ship holds of a file this agent claims: its length, chunks, media type, and
    /// whether it is marked open. `None` for any other id, whether the ship holds that file or
    /// not.
    pub fn info(id: &[u8; 32]) -> Option<FileInfo> {
        let bytes = super::fetch(128, |buf, cap| unsafe { super::host_file_info(id.as_ptr(), 32, buf, cap) })?;
        Some(FileInfo::decode(&*bytes).expect("the runtime sent a malformed file info"))
    }

    /// Mark a file this agent claims open: any ship that names it may have it, and this agent
    /// is not asked. Returns false, and changes nothing, if this agent claims no such file.
    /// Kept only if this event commits. Another agent's claim on the same file is its own,
    /// and is not marked.
    pub fn open(id: &[u8; 32]) -> bool {
        mark(id, true)
    }

    /// Take the mark off: from the next request on, other ships are asked about again. A
    /// request already allowed finishes the one part it asked for.
    pub fn close(id: &[u8; 32]) -> bool {
        mark(id, false)
    }

    fn mark(id: &[u8; 32], open: bool) -> bool {
        let request = FileMark { id: id.to_vec(), open }.encode_to_vec();
        unsafe { super::host_file_mark(request.as_ptr(), request.len() as u32) > 0 }
    }
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
        /// For a log on another ship: set when no more of it will come, with a few words on
        /// why. That ship has stopped sharing the log with this one, or never did, or what
        /// it sends no longer carries on from what this ship holds. Entries already held
        /// are still handed over. Following the log again asks afresh.
        pub stopped: Option<String>,
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
        follow_on("", agent, log)
    }

    /// Start following a log published by an agent on another ship, from its first entry.
    /// This ship fetches the entries, checks that each is signed by that ship and follows on
    /// from the one before, and keeps them until this agent takes them. The notify handler
    /// is called whenever there are some to take; `invocation()` then names the ship, the
    /// agent, and the log, and `next_on` hands them over.
    ///
    /// The event is rejected if this agent's manifest does not name that ship, agent, and
    /// log. Whether the other ship shares the log with this one is up to the agent that
    /// publishes it. If it does not, the notify handler is called once and `next_on`
    /// reports the log as stopped. Following again asks afresh; that is also how to pick up
    /// a log that had stopped. An empty ship name means this ship.
    pub fn follow_on(ship: &str, agent: &str, log: &str) {
        let request = FollowRequest { ship: ship.into(), agent: agent.into(), log: log.into() }.encode_to_vec();
        unsafe { host_log_follow(request.as_ptr(), request.len() as u32) }
    }

    /// Stop following a log, on this ship (an empty ship name) or another. Whatever was being
    /// held of it for this agent is let go. Following it again starts from its first entry.
    pub fn unfollow_on(ship: &str, agent: &str, log: &str) {
        let request = FollowRequest { ship: ship.into(), agent: agent.into(), log: log.into() }.encode_to_vec();
        unsafe { host_log_unfollow(request.as_ptr(), request.len() as u32) }
    }

    /// Take up to `max` entries after this agent's position in a log it follows. The position
    /// moves past them only if this event commits, so an entry is never lost and never handled
    /// twice.
    pub fn next(agent: &str, log: &str, max: u32) -> Batch {
        next_on("", agent, log, max)
    }

    /// The same, for a log on another ship, or with an empty ship name for one on this ship.
    pub fn next_on(ship: &str, agent: &str, log: &str, max: u32) -> Batch {
        let request = NextRequest { ship: ship.into(), agent: agent.into(), log: log.into(), max, checkpoints: true }.encode_to_vec();
        let bytes = once(|buf, cap| unsafe { host_log_next(request.as_ptr(), request.len() as u32, buf, cap) });
        let reply = NextReply::decode(&*bytes).expect("the runtime sent a malformed log reply");
        let stopped = (!reply.stopped.is_empty()).then_some(reply.stopped);
        Batch { checkpoint: reply.checkpoint, entries: reply.entries, more: reply.more, stopped }
    }

    /// Let another ship follow one of this agent's own logs. `ship` is a ship's name, or "*"
    /// for every ship. Who may follow a log is this agent's decision alone: nothing at
    /// install says which ships it may share with. A ship may ask before it is let in; it is
    /// refused, and asks again when its own agent follows again. Kept only if this event
    /// commits.
    pub fn share(log: &str, ship: &str) {
        let request = ShareRequest { log: log.into(), ship: ship.into(), stop: false }.encode_to_vec();
        unsafe { host_log_share(request.as_ptr(), request.len() as u32) }
    }

    /// Stop letting a ship follow one of this agent's logs. `ship` is whatever was given to
    /// `share`: taking back "*" leaves the ships that were named one by one. A ship that was
    /// following and is no longer covered is told the log is closed to it, and gets no more.
    /// What it already has, it keeps.
    pub fn unshare(log: &str, ship: &str) {
        let request = ShareRequest { log: log.into(), ship: ship.into(), stop: true }.encode_to_vec();
        unsafe { host_log_share(request.as_ptr(), request.len() as u32) }
    }
}

/// Send a command to another agent on this ship. It runs later, as that agent's own event, and
/// only if this event commits. The event is rejected if this agent has no permission.
pub fn send(agent: &str, interface: &str, payload: &[u8]) {
    let request = SendRequest { ship: String::new(), agent: agent.into(), interface: interface.into(), payload: payload.to_vec(), reply: false };
    let request = request.encode_to_vec();
    unsafe { host_send(request.as_ptr(), request.len() as u32) }
}

/// Send a command to an agent on another ship, and return the number it goes under. It is
/// kept until that ship has it, through restarts and lost connections at either end, and
/// reaches that ship exactly once, in the order sent. It is only sent if this event commits.
/// The event is rejected if this agent's manifest does not name that ship and agent.
///
/// Reaching the other ship is not the same as running there: the other agent may refuse the
/// command, or fail. Either way that ship sends back one receipt, which also arrives exactly
/// once. A refusal is written to this ship's audit log. An agent declared with `receipt = f`
/// is also handed each receipt, carrying the number returned here.
///
/// One other thing can become of a command. If either ship goes back to an earlier state,
/// such as a restored backup, the record of the command or of its answer may go with it.
/// The two ships find that out when they next talk, and the receipt then says the command
/// is lost: it may have run, and nobody can say.
///
/// Naming this ship itself is the same as `send`: the command is queued here, the number
/// returned is 0, and there is no receipt.
pub fn send_to(ship: &str, agent: &str, interface: &str, payload: &[u8]) -> u64 {
    send_to_as(ship, agent, interface, payload, false)
}

/// The same, and the handler's reply comes back with the receipt (`Receipt.reply`, with
/// `Receipt.replied` set) if the command runs. The command carries the largest reply this
/// ship takes back; if the reply is larger than that or than the other ship allows, or that
/// ship has no room just then to keep it, the command does not stand: its effects are undone
/// there, and the receipt says LIMIT. So the receipt says RAN with the whole reply, or the
/// command did not run, from a ship that follows the protocol.
/// This holds while neither ship makes its message, inbox or reply limits smaller while the
/// command or its receipt is outstanding.
///
/// The whole reply comes back with RAN from a receiving ship that follows the protocol. A
/// receipt can say RAN with `Receipt.replied` unset when the other ship's runtime predates
/// replies, or when it broke the protocol (a reply over the bound the command was sent with, or
/// a reply not marked): the command is still reported as run, because the other ship said so;
/// no reply is handed on; and when a reply came and was let go, the reason says so. An agent
/// that needs the reply checks `Receipt.replied`.
///
/// On a ship that takes back no reply at all (its `max_receipt_reply_bytes` is 0, or its queue
/// is too small for any receipt with a reply), this is refused here and the event with it,
/// as a send past a limit is: the command is not sent.
pub fn send_to_for_reply(ship: &str, agent: &str, interface: &str, payload: &[u8]) -> u64 {
    send_to_as(ship, agent, interface, payload, true)
}

fn send_to_as(ship: &str, agent: &str, interface: &str, payload: &[u8], reply: bool) -> u64 {
    let request = SendRequest { ship: ship.into(), agent: agent.into(), interface: interface.into(), payload: payload.to_vec(), reply };
    let request = request.encode_to_vec();
    unsafe { host_send_to(request.as_ptr(), request.len() as u32) as u64 }
}

pub use ship_proto::{Receipt, Verdict};

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
pub fn __receipt(bytes: &[u8], handler: fn(&Receipt)) -> Vec<u8> {
    handler(&Receipt::decode(bytes).expect("the runtime sent a malformed receipt"));
    Vec::new()
}

#[doc(hidden)]
pub fn __answer(bytes: &[u8], handler: fn(&ask::Answered)) -> Vec<u8> {
    handler(&ask::Answered::decode(bytes).expect("the runtime sent a malformed answer"));
    Vec::new()
}

#[doc(hidden)]
pub fn __file_ask(bytes: &[u8], handler: fn(&files::FileAsk) -> bool) -> Vec<u8> {
    let asked = files::FileAsk::decode(bytes).expect("the runtime sent a malformed file question");
    files::FileAnswer { allow: handler(&asked) }.encode_to_vec()
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

/// Declare an agent: a command handler, then any of `read = f`, `notify = f`, `checkpoint = f`,
/// `receipt = f`, `answer = f`, `file_ask = f`.
///
/// The answer handler is `fn(&ask::Answered)`. It is called once for each question this agent
/// put to another ship with `ask::to` and did not drop, with the number `ask::to` returned and
/// what came of it: the other agent's reply, or why there is none. It runs as an event of its
/// own and may do anything a command handler may. An agent with no answer handler is never
/// told; its questions are still answered and forgotten.
///
/// A read handler answers questions from other ships too, if the manifest opens its interface
/// to them (`Provide.asked`): `invocation()` then names the asking ship, and the asking agent
/// (empty when that ship's owner asks). What each ship may be told is the agent's to decide.
///
/// The file_ask handler is `fn(&files::FileAsk) -> bool`. It is called when another ship asks
/// for a file this agent claims and has not marked open: `FileAsk.ship` is the ship asking,
/// which proved who it is on its connection, and `FileAsk.id` the file. Returning true lets
/// that ship have it. It can only read, as a read handler, and nothing it does is kept. It has
/// a small budget of its own (10,000,000 fuel and 500 ms by default); a handler that fails, runs
/// out of either, or answers anything but a FileAnswer of at most 64 bytes is taken as no.
/// The runtime remembers the answer for a while (a yes for 30 s, a no for 5 s), so a change of
/// mind takes effect within that time.
///
/// The receipt handler is `fn(&Receipt)`. It is called once for each command this agent sent
/// to another ship with `send_to`, when that ship says what became of it: whether it ran, and
/// if not, why. It runs as an event of its own and may do anything a command handler may. For a
/// command sent with `send_to_for_reply`, a receipt saying RAN carries the handler's reply in
/// `Receipt.reply`, with `Receipt.replied` set (so an empty reply is told from none).
/// The whole reply comes back with RAN from a receiving ship that follows the protocol. A
/// receipt can say RAN with `Receipt.replied` unset when the other ship's runtime predates
/// replies, or when it broke the protocol (a reply over the bound the command was sent with, or
/// a reply not marked): the command is still reported as run, because the other ship said so;
/// no reply is handed on; and when a reply came and was let go, the reason says so. An agent
/// that needs the reply checks `Receipt.replied`.
/// This holds while neither ship makes its message, inbox or reply limits smaller while the
/// command or its receipt is outstanding.
///
/// The command, read, and notify handlers are `fn(&[u8]) -> Vec<u8>`. A read handler cannot
/// write, send, or emit. The notify handler is called when a log this agent follows has new
/// entries; `invocation()` says which.
///
/// The checkpoint handler is `fn(&str) -> Option<Vec<u8>>`. The runtime calls it with the name of
/// one of this agent's logs once that log has grown enough, and it can only read. Returning the
/// present state behind the log lets the runtime drop old entries: a follower that is far behind is
/// handed that state in place of them. The runtime signs what is returned as the state as of the
/// log's newest entry, and has no way to check that it is. So an agent must only change the state
/// behind a log in the same event that appends the entry describing the change, and the state must
/// be one a follower can use in place of every entry before it. Returning `None` says the log is a
/// history whose every entry matters, and it is then kept whole. An agent with no checkpoint
/// handler is never asked, and its logs are kept whole.
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
    (file_ask, $handler:path) => {
        const _: () = {
            #[export_name = "file_ask"]
            pub unsafe extern "C" fn __ship_export(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, |asked| $crate::__file_ask(asked, $handler))
            }
        };
    };
    (answer, $handler:path) => {
        const _: () = {
            #[export_name = "answer"]
            pub unsafe extern "C" fn __ship_export(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, |answered| $crate::__answer(answered, $handler))
            }
        };
    };
    (receipt, $handler:path) => {
        const _: () = {
            #[export_name = "receipt"]
            pub unsafe extern "C" fn __ship_export(ptr: *mut u8, len: u32) -> u64 {
                $crate::__handle(ptr, len, |receipt| $crate::__receipt(receipt, $handler))
            }
        };
    };
}
