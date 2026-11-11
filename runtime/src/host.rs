//! The interface agents import: a key-value store scoped to the calling agent, an outbox, and
//! calls to other agents on the same ship.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use ed25519_dalek::{Signer, SigningKey};
use ship_proto::{
    AppendRequest, Entry, EntryBody, FollowRequest, Grant, Kind, Message, NextReply, NextRequest, ReadRequest,
    SendRequest, Source,
};
use wasmtime::{Caller, Engine, Linker, Memory, StoreLimits, Trap};

use crate::ship::{self, Env};
use crate::{check_target, lock, sha256, store, AgentModule, Inner};

/// Fuel charged per host call, plus one unit per byte moved, so host work is paid for like
/// guest work and a cheap guest loop cannot buy unbounded host effort.
const HOST_CALL_FUEL: u64 = 5_000;

/// How many reads may be in progress at once: A reads B, whose handler reads C, and so on.
const MAX_READ_DEPTH: u32 = 8;

/// Room for the names in a read or send request, on top of its payload.
const REQUEST_ENVELOPE_BYTES: usize = 1024;

/// Extra fuel for appending to a log, which signs the entry.
const SIGN_FUEL: u64 = 50_000;

/// The most a single `log_next` call hands over.
const MAX_NEXT_ENTRIES: usize = 256;
const MAX_NEXT_BYTES: usize = 256 << 10;

pub struct Ctx {
    pub rt: Arc<Inner>,
    pub kernel: Arc<AgentModule>,
    pub conn: Arc<Mutex<Connection>>,
    pub ship: Arc<str>,
    /// The ship's signing key. Agents never see it; the runtime signs log entries for them.
    pub key: Arc<SigningKey>,
    pub agent: Arc<str>,
    pub store_limits: StoreLimits,
    /// Set while handling a read: nothing may be written, sent, or emitted.
    pub read_only: bool,
    pub depth: u32,
    pub deadline: Instant,
    /// The encoded `Invocation` describing this call.
    pub invocation: Vec<u8>,
    /// What the kernel allows this agent to read and send during this call.
    pub reads: Vec<Grant>,
    pub sends: Vec<Grant>,
    /// A read's reply that did not fit the caller's buffer, kept so the read is not run twice.
    pub pending_reply: Option<Vec<u8>>,
    /// With a pending `log_next` reply: the follower's new position, as (publisher, log, entry
    /// number). It is only applied once the reply has actually been collected.
    pub pending_cursor: Option<(String, String, u64)>,
    pub effects: u32,
    /// Outbox quota used by this event: payload bytes plus a fixed amount per message.
    pub effect_bytes: u64,
    /// Bytes the ship's outbox can still take before it is full.
    pub outbox_room: u64,
    pub queued: u32,
    pub queued_bytes: u64,
    pub inbox_room: u64,
    pub appended: u32,
    pub log_bytes: u64,
    pub log_room: u64,
}

#[derive(Debug)]
pub struct LimitExceeded(pub String);

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "limit exceeded: {}", self.0)
    }
}

impl std::error::Error for LimitExceeded {}

#[derive(Debug)]
pub struct Denied(pub String);

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not permitted: {}", self.0)
    }
}

impl std::error::Error for Denied {}

fn charge(caller: &mut Caller<'_, Ctx>, bytes: u64) -> Result<()> {
    let cost = HOST_CALL_FUEL + bytes;
    let left = caller.get_fuel()?;
    if left < cost {
        caller.set_fuel(0)?;
        return Err(Trap::OutOfFuel.into());
    }
    caller.set_fuel(left - cost)
}

fn writable(caller: &Caller<'_, Ctx>) -> Result<()> {
    if caller.data().read_only {
        return Err(Denied("a read handler cannot change anything".into()).into());
    }
    Ok(())
}

fn granted(grants: &[Grant], agent: &str, interface: &str) -> bool {
    grants.iter().any(|grant| grant.agent == agent && grant.interface == interface)
}

fn memory(caller: &mut Caller<'_, Ctx>) -> Result<Memory> {
    caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| anyhow!("agent exports no memory"))
}

fn read_guest(caller: &mut Caller<'_, Ctx>, ptr: u32, len: u32, max: usize, what: &str) -> Result<Vec<u8>> {
    if len as usize > max {
        return Err(LimitExceeded(format!("{what} is {len} bytes, limit is {max}")).into());
    }
    let memory = memory(caller)?;
    let (start, len) = (ptr as usize, len as usize);
    memory
        .data(&*caller)
        .get(start..start + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("{what} pointer is out of bounds"))
}

/// Hand `bytes` to the guest if they fit its buffer, and report their length either way. The
/// guest calls again with a bigger buffer when they did not fit.
fn fill(caller: &mut Caller<'_, Ctx>, buf_ptr: u32, buf_cap: u32, bytes: &[u8]) -> Result<i64> {
    if bytes.len() <= buf_cap as usize {
        charge(caller, bytes.len() as u64)?;
        memory(caller)?.write(&mut *caller, buf_ptr as usize, bytes)?;
    }
    Ok(bytes.len() as i64)
}

pub fn linker(engine: &Engine) -> Result<Linker<Ctx>> {
    let mut linker = Linker::new(engine);

    linker.func_wrap(
        "host",
        "kv_get",
        |mut caller: Caller<'_, Ctx>, key_ptr: u32, key_len: u32, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
            charge(&mut caller, key_len as u64)?;
            let max_key = caller.data().rt.cfg.limits.max_key_bytes;
            let key = read_guest(&mut caller, key_ptr, key_len, max_key, "key")?;
            let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
            // A value that does not fit the guest's buffer is never loaded.
            let Some((len, value)) = store::kv_get(&lock(&conn), &agent, &key, buf_cap as usize)? else {
                return Ok(-1);
            };
            match value {
                Some(value) => fill(&mut caller, buf_ptr, buf_cap, &value),
                None => Ok(len as i64),
            }
        },
    )?;

    linker.func_wrap(
        "host",
        "kv_put",
        |mut caller: Caller<'_, Ctx>, key_ptr: u32, key_len: u32, val_ptr: u32, val_len: u32| -> Result<()> {
            charge(&mut caller, key_len as u64 + val_len as u64)?;
            writable(&caller)?;
            let limits = caller.data().rt.cfg.limits;
            let key = read_guest(&mut caller, key_ptr, key_len, limits.max_key_bytes, "key")?;
            let value = read_guest(&mut caller, val_ptr, val_len, limits.max_value_bytes, "value")?;
            let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
            store::kv_put(&lock(&conn), &agent, &key, &value)?;
            Ok(())
        },
    )?;

    linker.func_wrap(
        "host",
        "kv_delete",
        |mut caller: Caller<'_, Ctx>, key_ptr: u32, key_len: u32| -> Result<()> {
            charge(&mut caller, key_len as u64)?;
            writable(&caller)?;
            let max_key = caller.data().rt.cfg.limits.max_key_bytes;
            let key = read_guest(&mut caller, key_ptr, key_len, max_key, "key")?;
            let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
            store::kv_delete(&lock(&conn), &agent, &key)?;
            Ok(())
        },
    )?;

    linker.func_wrap("host", "emit", |mut caller: Caller<'_, Ctx>, ptr: u32, len: u32| -> Result<()> {
        charge(&mut caller, len as u64)?;
        writable(&caller)?;
        let limits = caller.data().rt.cfg.limits;
        if caller.data().effects >= limits.max_effects_per_event {
            return Err(LimitExceeded(format!("more than {} effects in one event", limits.max_effects_per_event)).into());
        }
        let cost = len as u64 + store::MESSAGE_OVERHEAD;
        if caller.data().effect_bytes + cost > caller.data().outbox_room {
            return Err(LimitExceeded("the ship's outbox is full".into()).into());
        }
        let payload = read_guest(&mut caller, ptr, len, limits.max_effect_bytes, "effect")?;
        let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
        store::outbox_push(&lock(&conn), &agent, &payload)?;
        let ctx = caller.data_mut();
        ctx.effects += 1;
        ctx.effect_bytes += cost;
        Ok(())
    })?;

    linker.func_wrap("host", "invocation", |mut caller: Caller<'_, Ctx>, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
        charge(&mut caller, 0)?;
        let invocation = caller.data().invocation.clone();
        fill(&mut caller, buf_ptr, buf_cap, &invocation)
    })?;

    // Read from another agent: it runs now, in a fresh instance, and cannot change anything.
    linker.func_wrap(
        "host",
        "read",
        |mut caller: Caller<'_, Ctx>, req_ptr: u32, req_len: u32, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
            charge(&mut caller, req_len as u64)?;
            // Only the answer to the most recent read can be collected.
            caller.data_mut().pending_reply = None;
            caller.data_mut().pending_cursor = None;
            let max = caller.data().rt.cfg.max_event_bytes + REQUEST_ENVELOPE_BYTES;
            let request = ReadRequest::decode(&*read_guest(&mut caller, req_ptr, req_len, max, "read request")?)?;
            let ctx = caller.data();
            if !granted(&ctx.reads, &request.agent, &request.interface) {
                return Err(Denied(format!("{} may not read {} on {}", ctx.agent, request.interface, request.agent)).into());
            }
            if request.payload.len() > ctx.rt.cfg.max_event_bytes {
                return Err(LimitExceeded(format!("read request is {} bytes", request.payload.len())).into());
            }
            if ctx.depth >= MAX_READ_DEPTH {
                return Err(LimitExceeded(format!("reads nested more than {MAX_READ_DEPTH} deep")).into());
            }
            let (rt, kernel, conn) = (ctx.rt.clone(), ctx.kernel.clone(), ctx.conn.clone());
            let (ship, key) = (ctx.ship.clone(), ctx.key.clone());
            let (source, depth) = (Source { owner: false, agent: ctx.agent.to_string() }, ctx.depth + 1);
            let env = Env { rt: &rt, ship: &ship, kernel: &kernel, conn: &conn, key: &key, deadline: ctx.deadline };
            // The reader's remaining fuel pays for the read, and what is left comes back.
            let fuel = caller.get_fuel()?;
            let (reply, fuel_left) =
                ship::read_agent(&env, &source, &request.agent, &request.interface, &request.payload, fuel, depth)?;
            caller.set_fuel(fuel_left)?;
            let len = fill(&mut caller, buf_ptr, buf_cap, &reply)?;
            if reply.len() > buf_cap as usize {
                caller.data_mut().pending_reply = Some(reply);
            }
            Ok(len)
        },
    )?;

    // Collect the reply of a read whose answer did not fit the first buffer.
    linker.func_wrap("host", "take_reply", |mut caller: Caller<'_, Ctx>, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
        charge(&mut caller, 0)?;
        let Some(reply) = caller.data_mut().pending_reply.take() else {
            return Ok(-1);
        };
        let len = fill(&mut caller, buf_ptr, buf_cap, &reply)?;
        if reply.len() > buf_cap as usize {
            caller.data_mut().pending_reply = Some(reply);
            return Ok(len);
        }
        // The answer has been handed over. If it was log entries, this is the moment the
        // follower's position moves past them.
        if let Some((publisher, log, last)) = caller.data_mut().pending_cursor.take() {
            let (conn, follower) = (caller.data().conn.clone(), caller.data().agent.clone());
            store::set_cursor(&lock(&conn), &follower, &publisher, &log, last)?;
        }
        Ok(len)
    })?;

    // Send a command to another agent: it is queued, and runs as its own event after this one commits.
    linker.func_wrap("host", "send", |mut caller: Caller<'_, Ctx>, req_ptr: u32, req_len: u32| -> Result<()> {
        charge(&mut caller, req_len as u64)?;
        writable(&caller)?;
        let cfg = &caller.data().rt.cfg;
        let (max_payload, max_queued) = (cfg.max_event_bytes, cfg.limits.max_effects_per_event);
        let request = read_guest(&mut caller, req_ptr, req_len, max_payload + REQUEST_ENVELOPE_BYTES, "send request")?;
        let request = SendRequest::decode(&*request)?;
        let ctx = caller.data();
        if !granted(&ctx.sends, &request.agent, &request.interface) {
            return Err(Denied(format!("{} may not send {} to {}", ctx.agent, request.interface, request.agent)).into());
        }
        // The runtime's own bounds on names, so what it stores is always something it will import.
        if check_target(&request.agent, &request.interface).is_err() {
            return Err(Denied(format!("{:?} cannot be sent to", request.agent)).into());
        }
        if request.payload.len() > max_payload {
            return Err(LimitExceeded(format!("command is {} bytes, limit is {max_payload}", request.payload.len())).into());
        }
        let cost = request.payload.len() as u64 + store::MESSAGE_OVERHEAD;
        if ctx.queued >= max_queued || ctx.queued_bytes + cost > ctx.inbox_room {
            return Err(LimitExceeded("too many commands are queued on this ship".into()).into());
        }
        let (conn, agent) = (ctx.conn.clone(), ctx.agent.clone());
        store::inbox_push(&lock(&conn), Kind::Command, &agent, &request.agent, &request.interface, &request.payload)?;
        let ctx = caller.data_mut();
        ctx.queued += 1;
        ctx.queued_bytes += cost;
        Ok(())
    })?;

    // Add an entry to one of this agent's own logs. The runtime numbers it, links it to the
    // entry before, signs it, and queues a notification for each follower. Returns its number.
    linker.func_wrap("host", "log_append", |mut caller: Caller<'_, Ctx>, req_ptr: u32, req_len: u32| -> Result<i64> {
        charge(&mut caller, req_len as u64 + SIGN_FUEL)?;
        writable(&caller)?;
        let cfg = &caller.data().rt.cfg;
        let (max_payload, max_appends) = (cfg.max_event_bytes, cfg.limits.max_effects_per_event);
        let request = read_guest(&mut caller, req_ptr, req_len, max_payload + REQUEST_ENVELOPE_BYTES, "append request")?;
        let request = AppendRequest::decode(&*request)?;
        let ctx = caller.data();
        // An agent's own interfaces are among its read grants, and a log is named after one. The
        // name must also be one the runtime itself accepts, whatever a kernel granted, or the
        // log could be written but never read or imported.
        if !granted(&ctx.reads, &ctx.agent, &request.log) || check_target(&ctx.agent, &request.log).is_err() {
            return Err(Denied(format!("{} offers no interface named {:?}", ctx.agent, request.log)).into());
        }
        if request.payload.len() > max_payload {
            return Err(LimitExceeded(format!("log entry is {} bytes, limit is {max_payload}", request.payload.len())).into());
        }
        let (conn, agent, ship, key) = (ctx.conn.clone(), ctx.agent.clone(), ctx.ship.clone(), ctx.key.clone());
        let (appended, used, room) = (ctx.appended, ctx.log_bytes, ctx.log_room);
        let conn = lock(&conn);
        let (head, prev) = store::log_head(&conn, &agent, &request.log)?;
        let body = EntryBody {
            ship: ship.to_string(),
            agent: agent.to_string(),
            log: request.log.clone(),
            seq: head + 1,
            prev,
            payload: request.payload,
        }
        .encode_to_vec();
        let cost = store::entry_cost(body.len());
        if appended >= max_appends || used + cost > room {
            return Err(LimitExceeded("the ship's logs are full".into()).into());
        }
        let signature = key.sign(&body).to_bytes();
        store::log_append(&conn, &agent, &request.log, head + 1, &body, &signature, &sha256(&body))?;
        store::notify_followers(&conn, &agent, &request.log)?;
        drop(conn);
        let ctx = caller.data_mut();
        ctx.appended += 1;
        ctx.log_bytes += cost;
        Ok((head + 1) as i64)
    })?;

    // Start following another agent's log from its first entry.
    linker.func_wrap("host", "log_follow", |mut caller: Caller<'_, Ctx>, req_ptr: u32, req_len: u32| -> Result<()> {
        charge(&mut caller, req_len as u64)?;
        writable(&caller)?;
        let request = FollowRequest::decode(&*read_guest(&mut caller, req_ptr, req_len, REQUEST_ENVELOPE_BYTES, "follow request")?)?;
        let ctx = caller.data();
        if !granted(&ctx.reads, &request.agent, &request.log) || check_target(&request.agent, &request.log).is_err() {
            return Err(Denied(format!("{} may not follow {} on {}", ctx.agent, request.log, request.agent)).into());
        }
        let (conn, follower) = (ctx.conn.clone(), ctx.agent.clone());
        let conn = lock(&conn);
        if store::cursor(&conn, &follower, &request.agent, &request.log)?.is_none() {
            if store::follow_count(&conn, &follower)? >= store::MAX_FOLLOWS {
                return Err(LimitExceeded(format!("an agent may follow at most {} logs", store::MAX_FOLLOWS)).into());
            }
            store::follow(&conn, &follower, &request.agent, &request.log)?;
        }
        // A new follower is simply one that is behind by the whole log. For an existing one,
        // asking again is how it says it is ready to be prompted after repeated failures.
        store::resume(&conn, &follower, &request.agent, &request.log)?;
        Ok(())
    })?;

    // Take the entries after this agent's position in a log it follows, and move its position
    // past them. The move is part of this event: if the event fails, the entries come again.
    linker.func_wrap(
        "host",
        "log_next",
        |mut caller: Caller<'_, Ctx>, req_ptr: u32, req_len: u32, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
            charge(&mut caller, req_len as u64)?;
            writable(&caller)?;
            caller.data_mut().pending_reply = None;
            caller.data_mut().pending_cursor = None;
            let request = NextRequest::decode(&*read_guest(&mut caller, req_ptr, req_len, REQUEST_ENVELOPE_BYTES, "next request")?)?;
            let ctx = caller.data();
            if !granted(&ctx.reads, &request.agent, &request.log) {
                return Err(Denied(format!("{} may not follow {} on {}", ctx.agent, request.log, request.agent)).into());
            }
            let (conn, follower) = (ctx.conn.clone(), ctx.agent.clone());
            let (reply, cursor, last) = {
                let conn = lock(&conn);
                let Some(cursor) = store::cursor(&conn, &follower, &request.agent, &request.log)? else {
                    return Err(Denied(format!("{} does not follow {} on {}", follower, request.log, request.agent)).into());
                };
                let max = (request.max as usize).clamp(1, MAX_NEXT_ENTRIES);
                let stored = store::log_range(&conn, &request.agent, &request.log, cursor, max, MAX_NEXT_BYTES)?;
                let (head, _) = store::log_head(&conn, &request.agent, &request.log)?;
                let last = stored.last().map_or(cursor, |entry| entry.seq);
                let entries = stored
                    .iter()
                    .map(|entry| Ok(Entry { seq: entry.seq, payload: EntryBody::decode(&*entry.body)?.payload }))
                    .collect::<Result<Vec<_>>>()?;
                (NextReply { entries, more: last < head }.encode_to_vec(), cursor, last)
            };
            // The position moves only once the entries have been handed over. If they do not fit
            // the caller's buffer, that happens when the caller collects them, and never if it
            // does not.
            let len = fill(&mut caller, buf_ptr, buf_cap, &reply)?;
            if reply.len() > buf_cap as usize {
                let ctx = caller.data_mut();
                ctx.pending_reply = Some(reply);
                ctx.pending_cursor = Some((request.agent, request.log, last));
            } else if last != cursor {
                store::set_cursor(&lock(&conn), &follower, &request.agent, &request.log, last)?;
            }
            Ok(len)
        },
    )?;

    Ok(linker)
}
