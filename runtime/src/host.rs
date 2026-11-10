//! The interface agents import: a key-value store scoped to the calling agent, and an outbox.

use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use wasmtime::{Caller, Engine, Linker, Memory, StoreLimits, Trap};

use crate::{lock, store, Limits};

/// Fuel charged per host call, plus one unit per byte moved, so host work is paid for like
/// guest work and a cheap guest loop cannot buy unbounded host effort.
const HOST_CALL_FUEL: u64 = 5_000;

pub struct Ctx {
    pub conn: Arc<Mutex<Connection>>,
    pub agent: Arc<str>,
    pub limits: Limits,
    pub store_limits: StoreLimits,
    pub effects: u32,
    /// Outbox quota used by this event: payload bytes plus a fixed amount per message.
    pub effect_bytes: u64,
    /// Bytes the ship's outbox can still take before it is full.
    pub outbox_room: u64,
}

#[derive(Debug)]
pub struct LimitExceeded(pub String);

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "limit exceeded: {}", self.0)
    }
}

impl std::error::Error for LimitExceeded {}

fn charge(caller: &mut Caller<'_, Ctx>, bytes: u64) -> Result<()> {
    let cost = HOST_CALL_FUEL + bytes;
    let left = caller.get_fuel()?;
    if left < cost {
        caller.set_fuel(0)?;
        return Err(Trap::OutOfFuel.into());
    }
    caller.set_fuel(left - cost)
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

pub fn linker(engine: &Engine) -> Result<Linker<Ctx>> {
    let mut linker = Linker::new(engine);

    linker.func_wrap(
        "host",
        "kv_get",
        |mut caller: Caller<'_, Ctx>, key_ptr: u32, key_len: u32, buf_ptr: u32, buf_cap: u32| -> Result<i64> {
            charge(&mut caller, key_len as u64)?;
            let max_key = caller.data().limits.max_key_bytes;
            let key = read_guest(&mut caller, key_ptr, key_len, max_key, "key")?;
            let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
            // The guest retries with a bigger buffer when the value does not fit, so a value that
            // does not fit is never loaded.
            let Some((len, value)) = store::kv_get(&lock(&conn), &agent, &key, buf_cap as usize)? else {
                return Ok(-1);
            };
            if let Some(value) = value {
                charge(&mut caller, value.len() as u64)?;
                memory(&mut caller)?.write(&mut caller, buf_ptr as usize, &value)?;
            }
            Ok(len as i64)
        },
    )?;

    linker.func_wrap(
        "host",
        "kv_put",
        |mut caller: Caller<'_, Ctx>, key_ptr: u32, key_len: u32, val_ptr: u32, val_len: u32| -> Result<()> {
            charge(&mut caller, key_len as u64 + val_len as u64)?;
            let limits = caller.data().limits;
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
            let max_key = caller.data().limits.max_key_bytes;
            let key = read_guest(&mut caller, key_ptr, key_len, max_key, "key")?;
            let (conn, agent) = (caller.data().conn.clone(), caller.data().agent.clone());
            store::kv_delete(&lock(&conn), &agent, &key)?;
            Ok(())
        },
    )?;

    linker.func_wrap("host", "emit", |mut caller: Caller<'_, Ctx>, ptr: u32, len: u32| -> Result<()> {
        charge(&mut caller, len as u64)?;
        let limits = caller.data().limits;
        if caller.data().effects >= limits.max_effects_per_event {
            return Err(LimitExceeded(format!("more than {} effects in one event", limits.max_effects_per_event)).into());
        }
        let cost = len as u64 + store::OUTBOX_MESSAGE_OVERHEAD;
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

    Ok(linker)
}
