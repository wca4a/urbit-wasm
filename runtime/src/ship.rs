//! An awake ship: its open store and the agents installed on it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use rusqlite::Connection;
use wasmtime::{Store, StoreLimitsBuilder, Trap};

use crate::host::{Ctx, LimitExceeded};
use crate::{lock, store, AgentModule, Error, Inner, Outcome, Rejection};

pub struct Ship {
    pub conn: Arc<Mutex<Connection>>,
    pub agents: HashMap<String, Arc<AgentModule>>,
    /// Bytes waiting in the outbox, kept in step with the file so the quota check is cheap.
    pub outbox_bytes: u64,
}

struct Done {
    reply: Vec<u8>,
    effects: u32,
    effect_bytes: u64,
}

impl Ship {
    /// Run one event as one transaction: state, outbox, and audit row land together or not at all.
    ///
    /// A rejected event changes no state and queues no messages. It is recorded in the audit
    /// log as a separate, best-effort write, so that failures can be investigated.
    pub fn run(&mut self, rt: &Inner, agent: &str, event: &[u8]) -> Result<Outcome, Error> {
        let module = self.agents.get(agent).ok_or_else(|| Error::UnknownAgent(agent.to_string()))?.clone();
        let deadline = Instant::now() + Duration::from_millis(rt.cfg.max_event_millis);
        {
            let conn = lock(&self.conn);
            if !conn.is_autocommit() {
                conn.execute_batch("ROLLBACK")?;
            }
            conn.execute_batch("BEGIN IMMEDIATE")?;
        }

        let called = self.call(rt, agent, &module, event).and_then(|done| {
            store::audit(&lock(&self.conn), agent, event, true, rt.cfg.audit_rows)?;
            // Checked last, so the limit covers everything up to the commit itself. The deadline
            // inside the guest is only checked at loops, calls, and bulk operations.
            if Instant::now() > deadline {
                return Err(Trap::Interrupt.into());
            }
            Ok(done)
        });

        let conn = lock(&self.conn);
        match called {
            Ok(done) => {
                if let Err(e) = conn.execute_batch("COMMIT") {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e.into());
                }
                drop(conn);
                self.outbox_bytes += done.effect_bytes;
                Ok(Outcome { reply: done.reply, effects: done.effects })
            }
            Err(e) => {
                // SQLite rolls back by itself after some errors, such as a full disk.
                if !conn.is_autocommit() {
                    conn.execute_batch("ROLLBACK")?;
                }
                store::audit_failure(&conn, agent, event, rt.cfg.audit_rows);
                Err(Error::Rejected(classify(&e)))
            }
        }
    }

    /// Every event gets a fresh instance, so nothing an agent keeps in memory outlives the event.
    fn call(&self, rt: &Inner, agent: &str, module: &AgentModule, event: &[u8]) -> anyhow::Result<Done> {
        let ctx = Ctx {
            conn: self.conn.clone(),
            agent: agent.into(),
            limits: rt.cfg.limits,
            store_limits: StoreLimitsBuilder::new()
                .memory_size(rt.cfg.max_memory_bytes)
                .table_elements(rt.cfg.max_table_elements)
                .instances(1)
                .memories(1)
                .tables(1)
                .build(),
            effects: 0,
            effect_bytes: 0,
            outbox_room: rt.cfg.max_outbox_bytes.saturating_sub(self.outbox_bytes),
        };
        let mut store = Store::new(&rt.engine, ctx);
        store.limiter(|ctx| &mut ctx.store_limits);
        // One budget covers the whole event, including any start function run by instantiation.
        store.set_fuel(rt.cfg.fuel_per_event)?;
        // Fuel does not see the size of bulk operations such as memory.fill, so time is capped too.
        store.set_epoch_deadline(rt.cfg.max_event_millis / crate::EPOCH_TICK_MILLIS + 2);

        let instance = module.pre.instantiate(&mut store)?;
        let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| anyhow!("agent exports no memory"))?;
        let alloc = instance.get_typed_func::<u32, u32>(&mut store, "alloc")?;
        let handle = instance.get_typed_func::<(u32, u32), u64>(&mut store, "handle")?;

        let len = event.len() as u32;
        let ptr = alloc.call(&mut store, len)?;
        memory.write(&mut store, ptr as usize, event)?;
        let packed = handle.call(&mut store, (ptr, len))?;
        // Fuel is only checked at loops and calls, so straight-line code can overrun and return.
        if store.get_fuel()? == 0 {
            return Err(Trap::OutOfFuel.into());
        }

        let (start, len) = ((packed >> 32) as usize, (packed & 0xffff_ffff) as usize);
        if len > rt.cfg.max_reply_bytes {
            return Err(LimitExceeded(format!("reply is {len} bytes, limit is {}", rt.cfg.max_reply_bytes)).into());
        }
        let reply = memory
            .data(&store)
            .get(start..start + len)
            .ok_or_else(|| anyhow!("reply pointer is out of bounds"))?
            .to_vec();
        let ctx = store.data();
        Ok(Done { reply, effects: ctx.effects, effect_bytes: ctx.effect_bytes })
    }
}

fn classify(err: &anyhow::Error) -> Rejection {
    if let Some(limit) = err.chain().find_map(|cause| cause.downcast_ref::<LimitExceeded>()) {
        return Rejection::Limit(limit.0.clone());
    }
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => Rejection::OutOfFuel,
        Some(Trap::Interrupt) => Rejection::Timeout,
        _ => Rejection::Trap(format!("{err:#}")),
    }
}
