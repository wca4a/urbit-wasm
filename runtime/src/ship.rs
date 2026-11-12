//! An awake ship: its open store and its kernel. The kernel decides what may run and with what
//! permissions; this module runs it and enforces the limits.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use ship_proto::admin_request::Op;
use ship_proto::{
    AdminReply, AdminRequest, CheckpointBody, CheckpointReply, EntryBody, Fetch, Fetched, Grant, Invocation, Kind, LogHead,
    LogNews, Message, RouteReply, RouteRequest, SignedCheckpoint, SignedEntry, Source, Verdict,
};
use wasmtime::{Store, StoreLimitsBuilder, Trap};

use crate::host::{Ctx, Denied, LimitExceeded, LogsFull};
use crate::store::{FetchJob, Followed, Replica};
use crate::{
    check_target, lock, signed_bytes, store, AgentModule, ChainCheck, Error, Inner, Outcome, Rejection, CHECKPOINT_DOMAIN,
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
    /// For a command from another ship: that ship, and the number it gave the command. It is
    /// owed a receipt saying what became of it.
    owed: Option<(&'a str, u64)>,
    /// For a notification about a log on another ship: how much room the file had before
    /// the notification was taken off the queue.
    spare_before: Option<u64>,
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
    /// How many commands the event queued for other ships.
    sent: u32,
    /// How many other things the event did that the network has to act on.
    net: u32,
    /// How many times the event took entries held from a log on another ship.
    took: u32,
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
        sent: 0,
        net: 0,
        took: 0,
        can_checkpoint: call.module.pre.module().get_export("checkpoint").is_some(),
        takes_receipts: call.module.pre.module().get_export("receipt").is_some(),
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
        sent: ctx.sent,
        net: ctx.net,
        took: ctx.took,
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

    /// Run `work` as a transaction of its own, on behalf of another ship: answering what it
    /// asks, or taking in what it sends about logs. Whatever is written for another ship
    /// must leave room in the file to take a command from a ship and finish with it. If the
    /// work has used up room and too little is left, none of it is kept, and the other
    /// ship is told to try again later. Work that uses no room is kept however little
    /// room there is: a ship short of room still answers, it only takes nothing on.
    ///
    /// This is measured over everything the work wrote, down to the smallest record: a
    /// number that grows by a digit can be what tips a full page into a new one.
    pub(crate) fn transact_for_peer<R>(&mut self, cfg: &crate::Config, work: impl FnOnce(&Connection) -> Result<R, Error>) -> Result<R, Error> {
        self.transact(|conn| {
            let before = store::spare_bytes(conn)?;
            let done = work(conn)?;
            let after = store::spare_bytes(conn)?;
            if after < before && after < room_to_take_one(cfg) {
                return Err(Error::TooMany("records kept for other ships for the room it has"));
            }
            Ok(done)
        })
    }

    /// Take messages another ship has sent to this one, each once and in order. Returns the
    /// number of the last one this ship now holds from that ship.
    ///
    /// A message is taken only if it is the very next after the last one taken. One with an
    /// earlier number has been taken already and is passed over; that is what makes a message
    /// sent twice arrive once. One further ahead means something is missing, so nothing from
    /// there on is taken. The number and what the message leads to are saved together.
    ///
    /// A command goes into the queue, to run in its turn. A receipt answers a command one of
    /// this ship's agents sent: the record of that command is closed, a refusal is written to
    /// the audit log, and the agent is told if it asked to be.
    pub fn accept(&mut self, rt: &Arc<Inner>, peer: &str, messages: &[ship_proto::PeerMessage]) -> Result<u64, Error> {
        let whole = self.accept_batch(rt, peer, messages);
        if whole.is_ok() || messages.len() < 2 {
            return whole;
        }
        // The batch could not be saved as a whole, most likely because the ship's file has
        // no room for all of it. Taking it one message at a time saves as many as there is
        // room for, so that those can run. One of them may be what makes room for the rest,
        // and a batch that is only ever tried whole would never get that far.
        let mut held = None;
        for message in messages {
            match self.accept_batch(rt, peer, std::slice::from_ref(message)) {
                // Not taken, so nothing after it will be either.
                Ok(received) if received < message.seq => return Ok(received),
                Ok(received) => held = Some(received),
                Err(e) => return held.ok_or(e),
            }
        }
        whole.or(held.ok_or(Error::TooMany("messages that could not be taken")))
    }

    /// Take a batch in one transaction: all that can be taken of it, or on an error none.
    fn accept_batch(&mut self, rt: &Arc<Inner>, peer: &str, messages: &[ship_proto::PeerMessage]) -> Result<u64, Error> {
        let (cfg, room) = (&rt.cfg, rt.cfg.max_inbox_bytes.saturating_sub(self.inbox_bytes));
        let (received, added, answered) = self.transact(|conn| {
            if !store::peer_known(conn, peer)? && store::peer_count(conn)? >= cfg.max_peers {
                return Err(Error::TooMany("other ships it exchanges commands with"));
            }
            let (mut received, mut added, mut answered) = (store::peer_received(conn, peer)?, 0u64, false);
            // Receipts this ship owes that one: those written and waiting to go, and those it
            // will owe once the commands queued from that ship have run.
            let (written, mut unrun) = store::peer_owed(conn, peer)?;
            let mut owed = written + unrun;
            // How much more the ship's file can hold. A command is taken only while there is
            // room for it and for every receipt owed, with some to spare: once it is taken
            // the other ship lets go of it, so this ship must be able to finish with it.
            // (Nothing can set that room aside for good. If the ship's own agents fill the
            // file before the command runs, it stays queued until there is room again.)
            let mut spare = store::spare_bytes(conn)?;
            for message in messages {
                if message.seq <= received {
                    continue;
                }
                // Not the next one: stop here. The sender has it still.
                if message.seq != received + 1 {
                    break;
                }
                if let Some(receipt) = &message.receipt {
                    // One that answers nothing this ship is waiting on is taken and dropped.
                    if let Some(sent) = store::peer_wait_get(conn, peer, receipt.about)? {
                        let reason: String = store::short_reason(&receipt.reason).chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
                        let mut unqueued = false;
                        if sent.tell {
                            let told = ship_proto::Receipt {
                                about: receipt.about,
                                verdict: receipt.verdict,
                                reason: reason.clone(),
                                ship: peer.to_string(),
                                agent: sent.agent.clone(),
                                interface: sent.interface.clone(),
                            }
                            .encode_to_vec();
                            let cost = told.len() as u64 + store::MESSAGE_OVERHEAD;
                            if cost > cfg.max_inbox_bytes {
                                // This ship's queue could never hold it, however empty. Waiting
                                // for room would hold up everything behind it for good, so the
                                // agent goes untold, and that is written down.
                                unqueued = true;
                            } else if added + cost > room {
                                // No room to tell the agent yet. The other ship keeps the receipt.
                                break;
                            } else {
                                store::inbox_push_receipt(conn, peer, &sent.agent, &sent.source, &sent.interface, &told)?;
                                added += cost;
                            }
                        }
                        if receipt.verdict != Verdict::Ran as i32 || unqueued {
                            let ran = receipt.verdict == Verdict::Ran as i32;
                            let why = if reason.is_empty() { String::new() } else { format!(": {reason}") };
                            let untold = if unqueued { " (the receipt is too large for this ship's queue, so the agent was not told)" } else { "" };
                            let line = format!(
                                "~{peer} {} command {} to {} {}: {}{why}{untold}",
                                if ran { "ran" } else { "did not run" },
                                receipt.about,
                                sent.agent,
                                sent.interface,
                                verdict_words(receipt.verdict)
                            );
                            store::audit(conn, &sent.source, audit_line(line.as_bytes()), false, cfg.audit_rows)?;
                        }
                        store::peer_wait_done(conn, peer, receipt.about)?;
                    }
                    received += 1;
                    continue;
                }
                let cost = message.payload.len() as u64 + store::MESSAGE_OVERHEAD;
                // That ship is not taking the receipts it is owed already: stop here.
                if owed >= cfg.max_unanswered {
                    break;
                }
                // Room in the ship's file for every receipt not yet written, this one
                // included, with some to spare. Anything taken from another ship needs at
                // least that. (Receipts already written have their room already.)
                let finishing = (unrun as u64 + 1) * store::MAX_RECEIPT_BYTES as u64 + STORAGE_SLACK_BYTES;
                // The other ship is known for who it is, but what it sends is still checked. A
                // command that could never be run, or that this ship will never queue, is
                // taken off the sender's hands and refused, on record, so that it does not
                // hold up everything behind it. That is decided first: such a command must
                // not be left waiting for room it will never have. The line has to be one
                // that does not depend on how full the ship is today, so it is drawn well
                // inside what the file can hold: no one command may be more than a quarter
                // of it. A ship too full for a command within that line is short of room for
                // now, and the command waits.
                let sound = crate::check_agent_name(&message.from_agent).is_ok()
                    && check_target(&message.agent, &message.interface).is_ok()
                    && message.payload.len() <= cfg.max_event_bytes;
                let fits = cost <= largest_taken(cfg);
                if sound && fits {
                    // No room for it just now, in the queue or in the file: stop here.
                    if added + cost > room || spare < cost + finishing {
                        break;
                    }
                    store::inbox_push_from(conn, peer, message.seq, &message.from_agent, &message.agent, &message.interface, &message.payload)?;
                    added += cost;
                    spare -= cost;
                    unrun += 1;
                } else {
                    // No room just now even to refuse it on record: stop here.
                    if spare < finishing {
                        break;
                    }
                    store::audit(conn, "network", audit_line(&message.payload), false, cfg.audit_rows)?;
                    let (verdict, why) = if sound {
                        (Verdict::Limit, "larger than that ship can hold")
                    } else {
                        (Verdict::Malformed, "not a command that could be run")
                    };
                    store::receipt_push(conn, peer, message.seq, verdict, why)?;
                    spare = spare.saturating_sub(store::MAX_RECEIPT_BYTES as u64);
                    answered = true;
                }
                owed += 1;
                received += 1;
            }
            store::peer_set_received(conn, peer, received)?;
            Ok((received, added, answered))
        })?;
        self.inbox_bytes += added;
        if answered {
            rt.outbound_ready(&self.name);
        }
        Ok(received)
    }

    /// Answer another ship that asks for entries of one of this ship's logs.
    ///
    /// Whether it may have them is up to the agent that publishes the log, which says so
    /// with `share`. A ship that may not is told so in the same words whether or not there
    /// is such a log. One that may is noted as a follower, so that it is told when the log
    /// grows, and given the entries after the one it names: as they were signed, so that it
    /// can check them for itself. If those have been dropped it is given the log's
    /// checkpoint, and asks again from there.
    pub fn serve_log(&mut self, rt: &Arc<Inner>, peer: &str, fetch: &Fetch, most: usize) -> Result<Fetched, Error> {
        let (cfg, name) = (&rt.cfg, self.name.clone());
        self.transact_for_peer(cfg, |conn| {
            let (agent, log) = (fetch.agent.as_str(), fetch.log.as_str());
            if check_target(agent, log).is_err() || !store::shared_with(conn, agent, log, peer)? {
                return Ok(Fetched { denied: format!("~{name} does not share that log with ~{peer}"), ..Fetched::default() });
            }
            match store::log_peer_join(conn, agent, log, peer, fetch.joining, cfg.max_log_followers)? {
                store::Joined::Full => return Err(Error::TooMany("ships following that log")),
                // A new follower is a new record in this ship's file, written because
                // another ship asked. A ship that is already short of the room it keeps
                // for taking a command takes on no new followers, whether or not this one
                // record would use any: the ship that asked is told to try again later.
                store::Joined::New if store::spare_bytes(conn)? < room_to_take_one(cfg) => {
                    return Err(Error::TooMany("ships following its logs for the room it has"));
                }
                store::Joined::New | store::Joined::Known => {}
            }
            let (seq, hash) = store::log_head(conn, agent, log)?;
            let head = Some(LogHead { seq, hash });
            if fetch.after < store::log_base(conn, agent, log)? {
                let stored = store::checkpoint(conn, agent, log)?
                    .ok_or_else(|| Error::BadShipFile("a log has lost its early entries but has no checkpoint".into()))?;
                let checkpoint = Some(SignedCheckpoint { body: stored.body, signature: stored.signature });
                return Ok(Fetched { head, checkpoint, ..Fetched::default() });
            }
            // As many as fit in `budget` bytes as they will be sent, signatures and framing
            // included, and always one. Counting the entries' bodies alone would let many
            // small ones carry the answer past what the other ship will read, and it would
            // ask for the same ones, and be sent the same answer, for ever.
            let budget = (fetch.max_bytes as usize).min(most);
            let (mut entries, mut bytes) = (Vec::new(), 0usize);
            for stored in store::log_range(conn, agent, log, fetch.after, store::MAX_FETCH_ENTRIES, budget)? {
                let entry = SignedEntry { body: stored.body, signature: stored.signature };
                let len = entry.encoded_len() + 8;
                if !entries.is_empty() && bytes + len > budget {
                    break;
                }
                bytes += len;
                entries.push(entry);
            }
            Ok(Fetched { entries, head, ..Fetched::default() })
        })
    }

    /// Take in what another ship answered when asked for entries of a log one of this
    /// ship's agents follows. Returns what is left to do, and whether the agent was queued a
    /// notification.
    ///
    /// Nothing is taken on that ship's word. Each entry must be signed by its key, belong to
    /// that log, and follow directly on from the last one this ship holds, by number and by
    /// hash; a checkpoint must be signed the same way. What passes is kept for the agent,
    /// which is prompted to take it. An entry is taken whenever less than
    /// `max_follow_bytes` is held, so a fetch always gets somewhere, and what is held never
    /// passes that limit by more than one entry.
    ///
    /// If what came is not a continuation of what this ship holds, the log is stopped, and
    /// the agent is told when it next asks for entries. That happens when the other ship
    /// has gone back to an earlier state and written something different since. Nothing
    /// here sorts that out: the agent can stop following and start again from the beginning.
    pub fn take_entries(
        &mut self,
        rt: &Arc<Inner>,
        peer: &str,
        key: &[u8; 32],
        job: &FetchJob,
        fetched: &Fetched,
    ) -> Result<(Taken, bool), Error> {
        let cfg = &rt.cfg;
        // What is fetched must leave room in the ship's file to take a command from another
        // ship and finish with it, as sending must. The room is measured, after each entry
        // is written: how much a row takes in the file depends on more than its payload.
        //
        // Beyond that room, what is taken here leads to a notification for the agent, and
        // a notification has to be seen through, whether or not the agent ever handles it:
        // taken off the queue, and if it is refused, recorded. A command taken from another
        // ship is allowed some room for that, and so is this: `STORAGE_SLACK_BYTES` must be
        // left over when the notification is queued. Entries are held to the same again on
        // top, so that what is written after them here cannot be what crosses that line.
        let after_notice = room_to_take_one(cfg) + STORAGE_SLACK_BYTES;
        let floor = after_notice + STORAGE_SLACK_BYTES;
        self.transact_for_peer(cfg, |conn| {
            let (follower, log) = (job.follower.as_str(), Followed { ship: peer, agent: &job.agent, name: &job.name });
            // The agent may have stopped following since this was asked for.
            let Some(mut held) = store::replica(conn, follower, log)? else { return Ok((Taken::Done, false)) };
            // Or the log has stopped, or the agent has asked to follow afresh since, or this
            // ship's copy is no longer where it was when it asked. In each case the answer is
            // to a question no longer being put. Taking it would be wrong: an answer to an
            // earlier asking says nothing about whether that ship knows of this one.
            if !held.stopped.is_empty() || held.gen != job.gen || held.head != job.after {
                return Ok((left(&held, job, cfg), false));
            }
            let (mut took, mut no_room) = (false, false);
            let mut spare = store::spare_bytes(conn)?;
            let nothing = fetched.entries.is_empty() && fetched.checkpoint.is_none();
            let their = fetched.head.clone().unwrap_or_default();
            let anchor = <[u8; 32]>::try_from(&held.head_hash[..]).ok();
            let verifier = ed25519_dalek::VerifyingKey::from_bytes(key).ok();
            if !fetched.denied.is_empty() {
                held.stopped = format!("~{peer} does not share this log with this ship");
            } else if let Some(checkpoint) = &fetched.checkpoint {
                // The entries after this ship's copy have been dropped over there. The
                // checkpoint stands in for them, and for everything held here before it.
                match crate::verify_checkpoint(key, peer, &job.agent, &job.name, checkpoint) {
                    Ok(((seq, hash), state)) if seq > held.head && seq <= store::MAX_LOG_SEQ && fetched.entries.is_empty() => {
                        let cost = state.len() as u64 + store::MESSAGE_OVERHEAD;
                        if state.len() > cfg.max_checkpoint_bytes {
                            held.stopped = "the log's checkpoint is larger than this ship takes".into();
                        } else if spare < cost + floor {
                            no_room = true;
                        } else {
                            conn.execute_batch("SAVEPOINT fetched")?;
                            store::replica_checkpoint_set(conn, follower, log, seq, &state)?;
                            if store::spare_bytes(conn)? < floor {
                                conn.execute_batch("ROLLBACK TO fetched; RELEASE fetched")?;
                                no_room = true;
                            } else {
                                conn.execute_batch("RELEASE fetched")?;
                                (held.head, held.head_hash, held.bytes, took) = (seq, hash.to_vec(), cost, true);
                            }
                        }
                    }
                    _ => held.stopped = NOT_A_CONTINUATION.into(),
                }
            } else if let (Some(verifier), true) = (verifier, held.head == 0 || anchor.is_some()) {
                let mut chain = ChainCheck::new(&verifier, peer, &job.agent, &job.name, anchor.filter(|_| held.head > 0).map(|hash| (held.head, hash)));
                for entry in fetched.entries.iter().take(store::MAX_FETCH_ENTRIES) {
                    if held.bytes >= cfg.max_follow_bytes {
                        break;
                    }
                    let Ok((seq, hash, payload_len)) = chain.accept(&entry.body, &entry.signature) else {
                        held.stopped = NOT_A_CONTINUATION.into();
                        break;
                    };
                    // Signed and in its place, but numbered beyond any log this ship will
                    // keep track of. It can only follow a checkpoint at the very limit.
                    if seq > store::MAX_LOG_SEQ {
                        held.stopped = NOT_A_CONTINUATION.into();
                        break;
                    }
                    if payload_len > cfg.max_event_bytes {
                        held.stopped = "an entry of the log is larger than this ship takes".into();
                        break;
                    }
                    let cost = payload_len as u64 + store::MESSAGE_OVERHEAD;
                    if spare < cost + floor {
                        no_room = true;
                        break;
                    }
                    // It decoded a moment ago, when it was checked.
                    let payload = EntryBody::decode(&*entry.body).map(|body| body.payload).unwrap_or_default();
                    conn.execute_batch("SAVEPOINT fetched")?;
                    store::replica_push(conn, follower, log, seq, &payload)?;
                    spare = store::spare_bytes(conn)?;
                    if spare < floor {
                        // Writing it took more room than there was to give. It is not kept.
                        conn.execute_batch("ROLLBACK TO fetched; RELEASE fetched")?;
                        no_room = true;
                        break;
                    }
                    conn.execute_batch("RELEASE fetched")?;
                    (held.head, held.head_hash, held.bytes, took) = (seq, hash.to_vec(), held.bytes + cost, true);
                }
            } else {
                held.stopped = NOT_A_CONTINUATION.into();
            }
            if held.stopped.is_empty() {
                // Where that ship says its log ends, against what this ship now holds.
                let same_end = their.seq == held.head && (held.head == 0 || their.hash == held.head_hash);
                if their.seq < held.head || (their.seq == held.head && !same_end) {
                    // Its log is shorter than this ship's copy, or ends differently.
                    held.stopped = NOT_A_CONTINUATION.into();
                } else if nothing && their.seq > held.head {
                    held.stopped = format!("~{peer} says the log has more entries but sent none");
                } else if nothing && held.joined && held.head < held.announced {
                    // This ship asked because it had been told of more, and there is no
                    // more: that ship is not where it said it was. Forget what was said
                    // and ask afresh, so that anything written since is not missed.
                    (held.announced, held.joined) = (held.head, false);
                } else {
                    (held.announced, held.joined) = (held.announced.max(their.seq.min(store::MAX_LOG_SEQ)).max(held.head), true);
                }
            }
            let stopped = !held.stopped.is_empty();
            store::replica_save(conn, follower, log, &held)?;
            if took {
                // Something new to take starts the follower off afresh, as a new entry
                // does for a follower of a log on this ship.
                store::resume(conn, follower, log)?;
            }
            if stopped {
                // Told even with nothing to take: its next look says why no more will come.
                store::notify(conn, follower, log)?;
            }
            // See `after_notice` above. If the room is not there, none of this is kept, and
            // it is tried again later.
            if (took || stopped) && store::spare_bytes(conn)? < after_notice {
                return Err(Error::TooMany("notices waiting for the room it has"));
            }
            let taken = match (stopped, no_room && !took) {
                (true, _) => Taken::Stopped,
                (false, true) => Taken::NoRoom,
                (false, false) => left(&held, job, cfg),
            };
            Ok((taken, took || stopped))
        })
    }

    /// Take in what another ship says about logs of its own that agents here follow: that
    /// they have grown, or are closed to this ship. Returns, for each, whether no agent here
    /// follows it.
    ///
    /// All of it is only a prompt to ask. A number is not believed: entries are taken as
    /// they are fetched and checked. Nor is being told a log is closed, which may have been
    /// overtaken on its way by the log being shared and followed again: the ship asks, and
    /// the answer to that is what says the log has stopped.
    pub fn hear_news(&mut self, cfg: &crate::Config, peer: &str, news: &[LogNews]) -> Result<Vec<bool>, Error> {
        self.transact_for_peer(cfg, |conn| {
            let mut unknown = Vec::with_capacity(news.len().min(store::MAX_NEWS_LOGS));
            for item in news.iter().take(store::MAX_NEWS_LOGS) {
                let named = check_target(&item.agent, &item.log).is_ok();
                unknown.push(!named || store::replica_followers(conn, peer, &item.agent, &item.log)?.is_empty());
                if item.closed {
                    store::replica_recheck(conn, peer, &item.agent, &item.log)?;
                } else if item.head <= store::MAX_LOG_SEQ {
                    store::replica_heard(conn, peer, &item.agent, &item.log, item.head)?;
                }
            }
            Ok(unknown)
        })
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
        self.execute(rt, Event { kind: Kind::Command, source, agent, interface, payload, queued: None, owed: None, spare_before: None })
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
        let Event { kind, source, agent, interface, payload, queued, owed, spare_before } = event;
        // For a notification: which log it is about. Its publisher may be on another ship.
        let notice = (kind == Kind::Notify).then_some(Followed { ship: &source.ship, agent: &source.agent, name: interface });
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
                    notice.map_or(Ok(None), |log| {
                        store::clear_notified(&conn, agent, log)?;
                        store::cursor(&conn, agent, log)
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
        // A notification about a log on another ship is there because of what that ship
        // sent. If the agent never gets to handle it, settling it must not cost the file
        // room it keeps for taking a command, so the room is measured before it comes off
        // the queue and again after.
        let frugal = notice.is_some_and(|log| !log.ship.is_empty());
        let env = self.env(rt);
        // Whether the agent's module can be asked for a checkpoint, once that is known.
        let mut can_checkpoint = false;
        // Whether the kernel let the event through to the agent.
        let mut routed = false;
        let ran = (|| -> anyhow::Result<Returned> {
            let (module, grants) = route(&env, source, agent, kind, interface)?;
            routed = true;
            can_checkpoint = module.pre.module().get_export("checkpoint").is_some();
            let invocation = Invocation { kind: kind as i32, interface: interface.into(), source: Some(source.clone()) };
            // A checkpoint request for a module with no checkpoint handler is nothing to do. It
            // can come about when the module is replaced, or a ship is imported, after asking.
            // Likewise a receipt for a module with no receipt handler.
            let skipped = (asking.is_some() && !can_checkpoint)
                || (kind == Kind::Receipt && module.pre.module().get_export("receipt").is_none());
            let mut returned = if skipped { Returned::default() } else { invoke(
                &env,
                Invoke {
                    module: &module,
                    export: match kind {
                        Kind::Notify => "notify",
                        Kind::Checkpoint => "checkpoint",
                        Kind::Receipt => "receipt",
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
            if let Some(log) = notice {
                store::notify_handled(&conn, agent, log, before)?;
            }
            store::audit(&conn, agent, payload, true, rt.cfg.audit_rows)?;
            // The ship that sent this command is told it ran. That is saved with what the
            // command did, so the two cannot come apart.
            if let Some((peer, about)) = owed {
                store::receipt_push(&conn, peer, about, Verdict::Ran, "")?;
            }
            // An event that queues commands for other ships must leave room in the ship's
            // file to take one command back and finish with it. Otherwise two ships that had
            // each filled up with commands for the other could neither take the other's
            // first, and both would wait for ever. Checked after everything the event wrote.
            if returned.sent > 0 && store::spare_bytes(&conn)? < room_to_take_one(&rt.cfg) {
                return Err(NoRoomToSend.into());
            }
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
                // And the network can be told there is something to carry to other ships.
                if done.took > 0 {
                    // An agent has taken entries held from another ship's log. There is
                    // room to fetch more, and if it has not taken them all it has been
                    // prompted again. Seeing that the prompt runs is up to whoever runs
                    // this ship's queue, and that may be the network: an agent working
                    // through a long log a few entries at a time must not be left part way
                    // because nothing else happened. Each such round uses up entries that
                    // came from another ship, so there are only as many as that ship sent.
                    rt.work_ready(&self.name);
                } else if done.sent > 0 || done.net > 0 || owed.is_some() {
                    rt.outbound_ready(&self.name);
                }
                self.outbox_bytes += done.effect_bytes;
                self.inbox_bytes += done.queued_bytes;
                Ok(Outcome { reply: done.reply, effects: done.effects, queued: done.queued })
            }
            Err(e) => {
                let rejection = classify(&e);
                // An event turned away so that sending does not fill the ship's file is not
                // written to the audit log: an agent that keeps trying would fill the file
                // with the record of being told it is too full.
                let unrecorded = e.chain().any(|cause| cause.downcast_ref::<NoRoomToSend>().is_some());
                // What the ship that sent this command is told: it did not run, and why.
                let (verdict, reason) = verdict_of(&rejection, routed);
                let owed = owed.map(|(peer, about)| (peer, about, verdict, reason.as_str()));
                let rejection = Error::Rejected(rejection);
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
                        && (!frugal || conn.execute_batch("SAVEPOINT settling").is_ok())
                        && notice.is_none_or(|log| store::notify_failed(&conn, agent, log).is_ok())
                        && (!storage_full || store::reclaim(&conn).is_ok())
                        && full.is_none_or(|log| store::ask_checkpoint_when_full(&conn, agent, log).is_ok())
                        && owed.is_none_or(|(peer, about, verdict, reason)| store::receipt_push(&conn, peer, about, verdict, reason).is_ok())
                        && (unrecorded || store::audit(&conn, agent, payload, false, rt.cfg.audit_rows).is_ok())
                        && (!frugal || settled_within(&conn, spare_before, &rt.cfg))
                        && conn.execute_batch("COMMIT").is_ok()
                };
                if recorded {
                    if owed.is_some() {
                        rt.outbound_ready(&self.name);
                    }
                    return Err(rejection);
                }
                // The transaction was lost. Record the rejection in a new one, and for a queued
                // command take it off the queue in that same transaction.
                self.rollback();
                let retried = store::record_rejection(
                    &lock(&self.conn),
                    // (Settling a notification about another ship's log in a transaction of
                    // its own, after the first was lost, is kept to the least there is to
                    // do: it comes off the queue, and that is all.)
                    !unrecorded && !frugal,
                    queued,
                    owed,
                    notice.map(|log| (log, !frugal)),
                    asking,
                    full,
                    storage_full,
                    agent,
                    payload,
                    rt.cfg.audit_rows,
                );
                if retried.is_ok() && owed.is_some() {
                    rt.outbound_ready(&self.name);
                }
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
        let (queued, spare_before) = match popped {
            Ok(Some(popped)) => popped,
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
        let source = Source { owner: false, agent: queued.source.clone(), ship: queued.ship.clone() };
        // Anything else is run as a command, which is also the safe reading of a kind this
        // runtime does not know.
        let kind = match Kind::try_from(queued.kind) {
            Ok(kind @ (Kind::Notify | Kind::Checkpoint | Kind::Receipt)) => kind,
            _ => Kind::Command,
        };
        let owed = (kind == Kind::Command && !queued.ship.is_empty() && queued.ship_seq > 0).then_some((queued.ship.as_str(), queued.ship_seq));
        let event = Event {
            kind,
            source: &source,
            agent: &queued.agent,
            interface: &queued.interface,
            payload: &queued.payload,
            queued: Some(queued.seq),
            owed,
            spare_before,
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
        let source = Source { owner: true, agent: String::new(), ship: String::new() };
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

/// The record of a rejected notification about another ship's log has been written inside
/// the savepoint `settling`: the failure counted, the agent prompted again, the audit row.
/// Keep it if it used no room, or left as much as the ship keeps for taking a command. If
/// not, undo it: the notification then simply comes off the queue, and the agent is next
/// prompted when more of the log arrives or it asks to follow again. Returns false only if
/// neither could be done.
fn settled_within(conn: &Connection, spare_before: Option<u64>, cfg: &crate::Config) -> bool {
    let within = match (spare_before, store::spare_bytes(conn)) {
        (Some(before), Ok(now)) => now >= before || now >= room_to_take_one(cfg),
        _ => false,
    };
    conn.execute_batch(if within { "RELEASE settling" } else { "ROLLBACK TO settling; RELEASE settling" }).is_ok()
}

/// What is left to do for a log followed on another ship, after an answer about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Ask again: this is what to ask for now.
    More(FetchJob),
    /// Nothing more to ask for, until that ship says the log has grown or the agent makes room.
    Done,
    /// The log has stopped: that ship will not give it, or what it gives does not carry on.
    Stopped,
    /// The ship's file has no room for what came. Try again after a while.
    NoRoom,
}

/// What a log followed on another ship stops with when what that ship sends cannot be a
/// continuation of what this ship holds.
const NOT_A_CONTINUATION: &str = "what that ship sends does not carry on from the log this ship has been following";

/// Whether there is more to ask the other ship for, and if so what.
fn left(held: &Replica, job: &FetchJob, cfg: &crate::Config) -> Taken {
    let wanted = held.stopped.is_empty() && (!held.joined || held.head < held.announced) && held.bytes < cfg.max_follow_bytes;
    if !wanted {
        return Taken::Done;
    }
    Taken::More(FetchJob { after: held.head, room: cfg.max_follow_bytes - held.bytes, joining: !held.joined, gen: held.gen, ..job.clone() })
}

/// What the ship that sent a command is told when it was rejected here.
///
/// If the kernel turned the command away, its reason is passed on: it is about the request
/// itself, such as there being no such agent, and is what the other side needs to put things
/// right. Once the command has reached the agent (`routed`), only the kind of failure is
/// told, in fixed words. Whatever the agent ran into is the agent's own business, and an
/// error from inside a handler can name things the other ship has no right to know, such as
/// another agent it tried to read or another ship it tried to send to. The details stay in
/// this ship's audit log.
fn verdict_of(rejection: &Rejection, routed: bool) -> (Verdict, String) {
    let (verdict, words) = match rejection {
        Rejection::Denied(why) if !routed => return (Verdict::Denied, why.clone()),
        Rejection::Denied(_) => (Verdict::Failed, "the agent failed"),
        Rejection::Limit(_) => (Verdict::Limit, "a limit on that ship was reached"),
        Rejection::OutOfFuel => (Verdict::Failed, "it ran out of fuel"),
        Rejection::Timeout => (Verdict::Failed, "it took too long"),
        Rejection::Trap(_) if !routed => (Verdict::Failed, "that ship could not route it"),
        Rejection::Trap(_) => (Verdict::Failed, "the agent failed"),
    };
    (verdict, words.to_string())
}

/// The largest command, counted with its overhead, that a ship takes from another ship.
/// Anything larger is refused outright. See `Ship::accept_batch`.
fn largest_taken(cfg: &crate::Config) -> u64 {
    cfg.max_inbox_bytes.min(cfg.max_ship_bytes / 4)
}

/// Room in a ship's file to take the largest command another ship may send it, and to finish
/// with it.
pub(crate) fn room_to_take_one(cfg: &crate::Config) -> u64 {
    let largest = largest_taken(cfg).min(cfg.max_event_bytes as u64 + store::MESSAGE_OVERHEAD);
    largest + store::MAX_RECEIPT_BYTES as u64 + STORAGE_SLACK_BYTES
}

/// Room kept free in a ship's file, beyond what its owed receipts need, when taking a command
/// from another ship: a few pages, for the bookkeeping of running it.
const STORAGE_SLACK_BYTES: u64 = 16 << 10;

/// As much of a line the runtime writes as may go in the audit log, which holds nothing
/// larger than an event or a receipt.
fn audit_line(line: &[u8]) -> &[u8] {
    &line[..line.len().min(store::MAX_RECEIPT_BYTES)]
}

/// A verdict in words, for the audit log.
fn verdict_words(verdict: i32) -> &'static str {
    match Verdict::try_from(verdict) {
        Ok(Verdict::Ran) => "it ran",
        Ok(Verdict::Denied) => "it was not allowed",
        Ok(Verdict::Failed) => "the agent failed",
        Ok(Verdict::Limit) => "a limit was reached",
        Ok(Verdict::Malformed) => "it could not be run",
        Ok(Verdict::Unspecified) | Err(_) => "for a reason this runtime does not know",
    }
}

/// Whether an event failed because the ship's file could not grow.
fn storage_full(err: &anyhow::Error) -> bool {
    let full = |cause: &rusqlite::Error| cause.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull);
    err.chain().filter_map(|cause| cause.downcast_ref::<rusqlite::Error>()).any(full)
}

/// An event queued commands for other ships and would have left the ship's file without room
/// to take one back. See `room_to_take_one`.
#[derive(Debug)]
struct NoRoomToSend;

impl std::fmt::Display for NoRoomToSend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this ship's file is too full to send more to other ships")
    }
}

impl std::error::Error for NoRoomToSend {}

fn classify(err: &anyhow::Error) -> Rejection {
    if err.chain().any(|cause| cause.downcast_ref::<NoRoomToSend>().is_some()) {
        return Rejection::Limit(NoRoomToSend.to_string());
    }
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
