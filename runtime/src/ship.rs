//! An awake ship: its open store and its kernel. The kernel decides what may run and with what
//! permissions; this module runs it and enforces the limits.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use ship_proto::admin_request::Op;
use ship_proto::{
    AdminReply, AdminRequest, CheckpointBody, CheckpointReply, Grant, Invocation, Kind, Message, RouteReply, RouteRequest,
    Source,
};
use wasmtime::{Store, StoreLimitsBuilder, Trap};

use crate::host::{Ctx, Denied, LimitExceeded, LogsFull};
use crate::{
    check_target, lock, signed_bytes, store, AgentModule, Error, Inner, Outcome, Rejection, CHECKPOINT_DOMAIN,
    EPOCH_TICK_MILLIS, WASM_STACK_BYTES,
};

pub struct Ship {
    pub name: Arc<str>,
    pub conn: Arc<Mutex<Connection>>,
    pub kernel: Arc<AgentModule>,
    /// Signs this ship's log entries.
    pub key: Arc<SigningKey>,
    /// Bytes held in the outbox and inbox, kept in step with the file so quota checks are
    /// cheap.
    pub outbox_bytes: u64,
    pub inbox_bytes: u64,
}

/// What every call on a ship needs, whether it is the event itself or a read nested inside it.
pub(crate) struct Env<'a> {
    pub rt: &'a Arc<Inner>,
    pub ship: &'a Arc<str>,
    pub kernel: &'a Arc<AgentModule>,
    pub conn: &'a Arc<Mutex<Connection>>,
    pub key: &'a Arc<SigningKey>,
    pub deadline: Instant,
}

/// One thing for an agent to handle: a command, a notice that a log it follows has grown, or a
/// request for a checkpoint of one of its own logs.
struct Event<'a> {
    kind: Kind,
    source: &'a Source,
    agent: &'a str,
    interface: &'a str,
    payload: &'a [u8],
    /// The queue entry this came from, if it was queued.
    queued: Option<i64>,
}

struct Invoke<'a> {
    module: &'a AgentModule,
    export: &'a str,
    agent: &'a str,
    invocation: Vec<u8>,
    input: &'a [u8],
    read_only: bool,
    depth: u32,
    reads: Vec<Grant>,
    sends: Vec<Grant>,
    fuel: u64,
    outbox_room: u64,
    inbox_room: u64,
    max_reply: usize,
}

/// The largest answer the runtime accepts from a kernel. Fixed, and above what the kernel
/// limits itself to, so a small `max_reply_bytes` for agents cannot make a ship unroutable.
const KERNEL_REPLY_BYTES: usize = 1 << 20;

#[derive(Default)]
struct Returned {
    /// How many log entries the event added.
    appended: u32,
    reply: Vec<u8>,
    fuel_left: u64,
    effects: u32,
    effect_bytes: u64,
    queued: u32,
    queued_bytes: u64,
}

/// Run one exported handler in a fresh instance, so nothing kept in memory outlives the call.
///
/// Each instance may use up to `WASM_STACK_BYTES` of native stack, measured from wherever the
/// stack pointer is when it starts. A read nested inside another call starts further down the
/// same stack, so several levels could together run off the end of the thread's stack and abort
/// the process. Moving to a fresh stack segment whenever too little is left prevents that.
fn invoke(env: &Env, call: Invoke) -> anyhow::Result<Returned> {
    const HOST_MARGIN: usize = 256 << 10;
    stacker::maybe_grow(WASM_STACK_BYTES + HOST_MARGIN, WASM_STACK_BYTES + 4 * HOST_MARGIN, || invoke_here(env, call))
}

fn invoke_here(env: &Env, call: Invoke) -> anyhow::Result<Returned> {
    let cfg = &env.rt.cfg;
    if Instant::now() >= env.deadline {
        return Err(Trap::Interrupt.into());
    }
    let ctx = Ctx {
        rt: env.rt.clone(),
        kernel: env.kernel.clone(),
        conn: env.conn.clone(),
        ship: env.ship.clone(),
        key: env.key.clone(),
        agent: call.agent.into(),
        store_limits: StoreLimitsBuilder::new()
            .memory_size(cfg.max_memory_bytes)
            .table_elements(cfg.max_table_elements)
            .instances(1)
            .memories(1)
            .tables(1)
            .build(),
        read_only: call.read_only,
        depth: call.depth,
        deadline: env.deadline,
        invocation: call.invocation,
        reads: call.reads,
        sends: call.sends,
        pending_reply: None,
        pending_cursor: None,
        effects: 0,
        effect_bytes: 0,
        outbox_room: call.outbox_room,
        queued: 0,
        queued_bytes: 0,
        inbox_room: call.inbox_room,
        appended: 0,
        can_checkpoint: call.module.pre.module().get_export("checkpoint").is_some(),
    };
    let mut store = Store::new(&env.rt.engine, ctx);
    store.limiter(|ctx| &mut ctx.store_limits);
    // One budget covers the whole call, including any start function run by instantiation.
    store.set_fuel(call.fuel)?;
    // Fuel does not see the size of bulk operations such as memory.fill, so time is capped too.
    let left = env.deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
    store.set_epoch_deadline(left / EPOCH_TICK_MILLIS + 2);

    let instance = call.module.pre.instantiate(&mut store)?;
    let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| anyhow!("module exports no memory"))?;
    let alloc = instance.get_typed_func::<u32, u32>(&mut store, "alloc")?;
    let handler = instance
        .get_typed_func::<(u32, u32), u64>(&mut store, call.export)
        .map_err(|_| anyhow!("module has no `{}` handler", call.export))?;

    let len = call.input.len() as u32;
    let ptr = alloc.call(&mut store, len)?;
    memory.write(&mut store, ptr as usize, call.input)?;
    let packed = handler.call(&mut store, (ptr, len))?;
    // Fuel is only checked at loops and calls, so straight-line code can overrun and return.
    let fuel_left = store.get_fuel()?;
    if fuel_left == 0 {
        return Err(Trap::OutOfFuel.into());
    }
    // Likewise the deadline: a result that arrives late is not used.
    if Instant::now() >= env.deadline {
        return Err(Trap::Interrupt.into());
    }

    let (start, len) = ((packed >> 32) as usize, (packed & 0xffff_ffff) as usize);
    if len > call.max_reply {
        return Err(LimitExceeded(format!("reply is {len} bytes, limit is {}", call.max_reply)).into());
    }
    let reply = memory
        .data(&store)
        .get(start..start + len)
        .ok_or_else(|| anyhow!("reply pointer is out of bounds"))?
        .to_vec();
    let ctx = store.into_data();
    Ok(Returned {
        appended: ctx.appended,
        reply,
        fuel_left,
        effects: ctx.effects,
        effect_bytes: ctx.effect_bytes,
        queued: ctx.queued,
        queued_bytes: ctx.queued_bytes,
    })
}

/// Call the kernel. It has its own compute budget, and sees only its own keys.
fn kernel_call(env: &Env, export: &str, input: &[u8], read_only: bool) -> anyhow::Result<Vec<u8>> {
    let call = Invoke {
        module: env.kernel,
        export,
        agent: "kernel",
        invocation: Vec::new(),
        input,
        read_only,
        depth: 0,
        reads: Vec::new(),
        sends: Vec::new(),
        fuel: env.rt.cfg.kernel_fuel,
        outbox_room: 0,
        inbox_room: 0,
        max_reply: KERNEL_REPLY_BYTES,
    };
    Ok(invoke(env, call)?.reply)
}

/// Ask the kernel whether a call may go ahead. On yes, returns the module to run and the
/// permissions the called agent holds while handling it.
fn route(env: &Env, source: &Source, agent: &str, kind: Kind, interface: &str) -> anyhow::Result<(Arc<AgentModule>, RouteReply)> {
    check_target(agent, interface).map_err(|_| Denied(format!("{agent:?} cannot be called")))?;
    let request =
        RouteRequest { source: Some(source.clone()), agent: agent.into(), kind: kind as i32, interface: interface.into() };
    let reply = RouteReply::decode(&*kernel_call(env, "route", &request.encode_to_vec(), true)?)?;
    if !reply.allowed {
        return Err(Denied(reply.reason).into());
    }
    let module = env.rt.module(&reply.module).map_err(|e| anyhow!("the kernel named an unusable module: {e}"))?;
    Ok((module, reply))
}

/// Run an agent's read handler. Returns its reply and the fuel that is left.
pub(crate) fn read_agent(
    env: &Env,
    source: &Source,
    agent: &str,
    interface: &str,
    payload: &[u8],
    fuel: u64,
    depth: u32,
) -> anyhow::Result<(Vec<u8>, u64)> {
    let (module, grants) = route(env, source, agent, Kind::Read, interface)?;
    let invocation = Invocation { kind: Kind::Read as i32, interface: interface.into(), source: Some(source.clone()) };
    let returned = invoke(
        env,
        Invoke {
            module: &module,
            export: "read",
            agent,
            invocation: invocation.encode_to_vec(),
            input: payload,
            read_only: true,
            depth,
            reads: grants.reads,
            sends: Vec::new(),
            fuel,
            outbox_room: 0,
            inbox_room: 0,
            max_reply: env.rt.cfg.max_reply_bytes,
        },
    )?;
    Ok((returned.reply, returned.fuel_left))
}

/// Store what an agent answered when asked for a checkpoint of one of its logs.
fn keep_checkpoint(env: &Env, conn: &Connection, agent: &str, log: &str, reply: &[u8]) -> anyhow::Result<()> {
    let Some(state) = CheckpointReply::decode(reply)?.state else {
        // The agent says every entry of this log matters. It is never trimmed or asked again.
        store::mark_history(conn, agent, log)?;
        return Ok(());
    };
    let max = env.rt.cfg.max_checkpoint_bytes;
    if state.len() > max {
        return Err(LimitExceeded(format!("checkpoint is {} bytes, limit is {max}", state.len())).into());
    }
    // The agent answered inside this transaction, so its state is the state as of the log's
    // present end. Nothing to do if there is already a checkpoint for exactly that entry.
    let (head, hash) = store::log_head(conn, agent, log)?;
    if head == 0 || store::checkpoint_seq(conn, agent, log)? == Some(head) {
        return Ok(());
    }
    let body = CheckpointBody { ship: env.ship.to_string(), agent: agent.into(), log: log.into(), seq: head, hash, state }
        .encode_to_vec();
    let signature = env.key.sign(&signed_bytes(CHECKPOINT_DOMAIN, &body)).to_bytes();
    store::checkpoint_write(conn, agent, log, head, &body, &signature)?;
    Ok(())
}

impl Ship {
    /// Start a transaction, first discarding one left open by an earlier failure.
    fn begin(&self, sql: &str) -> Result<(), Error> {
        let conn = lock(&self.conn);
        if !conn.is_autocommit() {
            conn.execute_batch("ROLLBACK")?;
        }
        Ok(conn.execute_batch(sql)?)
    }

    /// Leave no transaction open. Every path that does not commit ends here, so the next
    /// operation never inherits a half-finished one. (`begin` checks again, in case this failed.)
    fn rollback(&self) {
        let conn = lock(&self.conn);
        // SQLite rolls back by itself after some errors, such as a full disk.
        if !conn.is_autocommit() {
            let _ = conn.execute_batch("ROLLBACK");
        }
    }

    /// Run `work` as a transaction of its own, outside any event: all of it is kept, or none.
    pub fn transact<R>(&mut self, work: impl FnOnce(&Connection) -> Result<R, Error>) -> Result<R, Error> {
        self.begin("BEGIN IMMEDIATE")?;
        // Each lock is taken in a statement of its own, so it is released before the next.
        let ran = {
            let conn = lock(&self.conn);
            work(&conn)
        };
        let done = ran.and_then(|value| {
            let committed = lock(&self.conn).execute_batch("COMMIT");
            committed.map(|()| value).map_err(Error::from)
        });
        if done.is_err() {
            self.rollback();
        }
        done
    }

    /// The setting for one operation, with its time limit starting now.
    fn env<'a>(&'a self, rt: &'a Arc<Inner>) -> Env<'a> {
        let deadline = Instant::now() + Duration::from_millis(rt.cfg.max_event_millis);
        Env { rt, ship: &self.name, kernel: &self.kernel, conn: &self.conn, key: &self.key, deadline }
    }

    /// Run one command as one transaction: state, outbox, queued commands, and audit row land
    /// together or not at all.
    ///
    /// A rejected command changes no state and queues nothing. It is recorded in the audit log
    /// as a separate, best-effort write, so that failures can be investigated.
    pub fn command(&mut self, rt: &Arc<Inner>, source: &Source, agent: &str, interface: &str, payload: &[u8]) -> Result<Outcome, Error> {
        self.begin("BEGIN IMMEDIATE")?;
        self.execute(rt, Event { kind: Kind::Command, source, agent, interface, payload, queued: None })
    }

    /// The body of an event. Expects a transaction to be open, and ends it.
    ///
    /// The handler's work happens inside a savepoint. On rejection only that work is undone, so
    /// whatever the caller did first in the same transaction (taking a queued command off the
    /// queue) is committed together with the audit row that records the rejection.
    ///
    /// `Error::Rejected` is only returned once the rejection is settled: for a queued event,
    /// that means it is off the queue for good. Any other error means nothing was committed.
    fn execute(&mut self, rt: &Arc<Inner>, event: Event) -> Result<Outcome, Error> {
        let Event { kind, source, agent, interface, payload, queued } = event;
        // For a notification: which log it is about, as (publisher, name).
        let notice = (kind == Kind::Notify).then_some((source.agent.as_str(), interface));
        // For a checkpoint request: the log, one of the agent's own, that it is about.
        let asking = (kind == Kind::Checkpoint).then_some(interface);
        // Each lock below is taken in a statement of its own, so it is released before
        // `rollback` takes it again.
        let opened = {
            let conn = lock(&self.conn);
            // The notification is off the queue, so the next new entry may queue another. This
            // sits outside the savepoint: it holds whether or not the handler succeeds.
            // Likewise a checkpoint request: once it is off the queue, another may be asked for.
            asking
                .map_or(Ok(()), |log| store::checkpoint_answered(&conn, agent, log))
                .and_then(|()| {
                    notice.map_or(Ok(None), |(publisher, log)| {
                        store::clear_notified(&conn, agent, publisher, log)?;
                        store::cursor(&conn, agent, publisher, log)
                    })
                })
                .and_then(|before| conn.execute_batch("SAVEPOINT handler").map(|()| before))
        };
        // For a notification: where the follower had got to before its handler ran.
        let before = match opened {
            Ok(before) => before,
            Err(e) => {
                self.rollback();
                return Err(e.into());
            }
        };
        let env = self.env(rt);
        // Whether the agent's module can be asked for a checkpoint, once that is known.
        let mut can_checkpoint = false;
        let ran = (|| -> anyhow::Result<Returned> {
            let (module, grants) = route(&env, source, agent, kind, interface)?;
            can_checkpoint = module.pre.module().get_export("checkpoint").is_some();
            let invocation = Invocation { kind: kind as i32, interface: interface.into(), source: Some(source.clone()) };
            // A checkpoint request for a module with no checkpoint handler is nothing to do. It
            // can come about when the module is replaced, or a ship is imported, after asking.
            let skipped = asking.is_some() && !can_checkpoint;
            let mut returned = if skipped { Returned::default() } else { invoke(
                &env,
                Invoke {
                    module: &module,
                    export: match kind {
                        Kind::Notify => "notify",
                        Kind::Checkpoint => "checkpoint",
                        _ => "handle",
                    },
                    agent,
                    invocation: invocation.encode_to_vec(),
                    input: payload,
                    // An agent describing its state must not change it while doing so.
                    read_only: asking.is_some(),
                    depth: 0,
                    reads: grants.reads,
                    sends: if asking.is_some() { Vec::new() } else { grants.sends },
                    fuel: rt.cfg.fuel_per_event,
                    outbox_room: rt.cfg.max_outbox_bytes.saturating_sub(self.outbox_bytes),
                    inbox_room: rt.cfg.max_inbox_bytes.saturating_sub(self.inbox_bytes),
                    // Room for the state itself plus the few bytes that wrap it.
                    max_reply: if asking.is_some() { rt.cfg.max_checkpoint_bytes + 16 } else { rt.cfg.max_reply_bytes },
                },
            )? };
            let conn = lock(&self.conn);
            // The checkpoint, and the entries it lets go of, land with the rest of this event.
            if let Some(log) = asking.filter(|_| !skipped) {
                keep_checkpoint(&env, &conn, agent, log, &returned.reply)?;
                returned.reply.clear();
            }
            // A follower that did not take everything is notified again, so it works through a
            // long log one event at a time without anyone having to prompt it.
            if let Some((publisher, log)) = notice {
                store::notify_handled(&conn, agent, publisher, log, before)?;
            }
            store::audit(&conn, agent, payload, true, rt.cfg.audit_rows)?;
            // Checked last, so the limit covers everything up to the commit itself. The deadline
            // inside the guest is only checked at loops, calls, and bulk operations.
            if Instant::now() > env.deadline {
                return Err(Trap::Interrupt.into());
            }
            Ok(returned)
        })();

        match ran {
            Ok(done) => {
                let committed = lock(&self.conn).execute_batch("RELEASE handler; COMMIT");
                if let Err(e) = committed {
                    self.rollback();
                    return Err(e.into());
                }
                // Anything waiting for one of this ship's logs to grow can look again.
                if done.appended > 0 {
                    rt.logs_grew(&self.name);
                }
                self.outbox_bytes += done.effect_bytes;
                self.inbox_bytes += done.queued_bytes;
                Ok(Outcome { reply: done.reply, effects: done.effects, queued: done.queued })
            }
            Err(e) => {
                let rejection = Error::Rejected(classify(&e));
                // An append found the logs full. The append itself is undone like the rest of
                // the event, but a checkpoint of that log is what would make room, and only an
                // append ever asks for one. So ask here, or a full log could never recover.
                let full = e.chain().find_map(|cause| cause.downcast_ref::<LogsFull>()).filter(|_| can_checkpoint);
                let full = full.map(|full| full.0.as_str());
                // The ship's file is full. Its logs may be holding entries they no longer need.
                let storage_full = storage_full(&e);
                let recorded = {
                    let conn = lock(&self.conn);
                    // SQLite abandons the whole transaction after some errors, such as a full disk.
                    // A follower whose handler failed is still behind, so it is prompted again a
                    // limited number of times, in the same transaction as everything else.
                    !conn.is_autocommit()
                        && conn.execute_batch("ROLLBACK TO handler; RELEASE handler").is_ok()
                        && notice.is_none_or(|(publisher, log)| store::notify_failed(&conn, agent, publisher, log).is_ok())
                        && (!storage_full || store::reclaim(&conn).is_ok())
                        && full.is_none_or(|log| store::ask_checkpoint_when_full(&conn, agent, log).is_ok())
                        && store::audit(&conn, agent, payload, false, rt.cfg.audit_rows).is_ok()
                        && conn.execute_batch("COMMIT").is_ok()
                };
                if recorded {
                    return Err(rejection);
                }
                // The transaction was lost. Record the rejection in a new one, and for a queued
                // command take it off the queue in that same transaction.
                self.rollback();
                let retried = store::record_rejection(
                    &lock(&self.conn),
                    queued,
                    notice,
                    asking,
                    full,
                    storage_full,
                    agent,
                    payload,
                    rt.cfg.audit_rows,
                );
                match (retried, queued) {
                    (Ok(()), _) | (Err(_), None) => Err(rejection),
                    // Its removal could not be saved, so the command is still queued. Say so,
                    // rather than report a rejection that did not stick.
                    (Err(e), Some(_)) => Err(e.into()),
                }
            }
        }
    }

    /// Run the oldest queued command, if there is one. Taking it off the queue and its effects
    /// are one transaction. A queued command that is rejected is dropped, not retried.
    pub fn run_queued(&mut self, rt: &Arc<Inner>) -> Result<bool, Error> {
        self.begin("BEGIN IMMEDIATE")?;
        let popped = store::inbox_pop(&lock(&self.conn));
        let queued = match popped {
            Ok(Some(queued)) => queued,
            Ok(None) => {
                self.rollback();
                return Ok(false);
            }
            Err(e) => {
                self.rollback();
                return Err(e.into());
            }
        };
        // The command is off the queue for the rest of this transaction, so the room it took is
        // free for whatever its handler sends.
        self.inbox_bytes = self.inbox_bytes.saturating_sub(queued.cost());
        let source = Source { owner: false, agent: queued.source.clone() };
        // Anything else is run as a command, which is also the safe reading of a kind this
        // runtime does not know.
        let kind = match Kind::try_from(queued.kind) {
            Ok(kind @ (Kind::Notify | Kind::Checkpoint)) => kind,
            _ => Kind::Command,
        };
        let event = Event {
            kind,
            source: &source,
            agent: &queued.agent,
            interface: &queued.interface,
            payload: &queued.payload,
            queued: Some(queued.seq),
        };
        match self.execute(rt, event) {
            // Run, or rejected and removed: either way it is off the queue.
            Ok(_) | Err(Error::Rejected(_)) => Ok(true),
            // Nothing was committed, so it is still queued and still takes its room.
            Err(e) => {
                self.inbox_bytes += queued.cost();
                Err(e)
            }
        }
    }

    /// Run a read on the owner's behalf. Nothing it does is kept.
    pub fn read(&mut self, rt: &Arc<Inner>, agent: &str, interface: &str, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.begin("BEGIN")?;
        let env = self.env(rt);
        let source = Source { owner: true, agent: String::new() };
        let result = read_agent(&env, &source, agent, interface, payload, rt.cfg.fuel_per_event, 0);
        self.rollback();
        result.map(|(reply, _)| reply).map_err(|e| Error::Rejected(classify(&e)))
    }

    /// The content hashes of the modules this ship's agents run, as its kernel reports them.
    pub fn modules(&mut self, rt: &Arc<Inner>) -> Result<Vec<String>, Error> {
        let request = AdminRequest { op: Some(Op::ListModules(true)) };
        let reply = self.admin(rt, &request, false)?;
        if reply.ok { Ok(reply.modules) } else { Err(Error::BadShipFile(format!("kernel: {}", reply.error))) }
    }

    /// Put a request to the kernel on the owner's behalf. Its changes are kept only when `write`
    /// is set and the kernel accepts the request.
    pub fn admin(&mut self, rt: &Arc<Inner>, request: &AdminRequest, write: bool) -> Result<AdminReply, Error> {
        self.begin(if write { "BEGIN IMMEDIATE" } else { "BEGIN" })?;
        let env = self.env(rt);
        let reply = kernel_call(&env, "admin", &request.encode_to_vec(), !write)
            .and_then(|bytes| Ok(AdminReply::decode(&*bytes)?));
        match reply {
            Ok(reply) if write && reply.ok => {
                let committed = lock(&self.conn).execute_batch("COMMIT");
                if let Err(e) = committed {
                    self.rollback();
                    return Err(e.into());
                }
                Ok(reply)
            }
            Ok(reply) => {
                self.rollback();
                Ok(reply)
            }
            Err(e) => {
                self.rollback();
                Err(Error::Rejected(classify(&e)))
            }
        }
    }
}

/// Whether an event failed because the ship's file could not grow.
fn storage_full(err: &anyhow::Error) -> bool {
    let full = |cause: &rusqlite::Error| cause.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull);
    err.chain().filter_map(|cause| cause.downcast_ref::<rusqlite::Error>()).any(full)
}

fn classify(err: &anyhow::Error) -> Rejection {
    if let Some(denied) = err.chain().find_map(|cause| cause.downcast_ref::<Denied>()) {
        return Rejection::Denied(denied.0.clone());
    }
    if let Some(limit) = err.chain().find_map(|cause| cause.downcast_ref::<LimitExceeded>()) {
        return Rejection::Limit(limit.0.clone());
    }
    if err.chain().any(|cause| cause.downcast_ref::<LogsFull>().is_some()) {
        return Rejection::Limit("the log is full".into());
    }
    if storage_full(err) {
        return Rejection::Limit("the ship's storage is full".into());
    }
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => Rejection::OutOfFuel,
        Some(Trap::Interrupt) => Rejection::Timeout,
        _ => Rejection::Trap(format!("{err:#}")),
    }
}
