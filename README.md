# urbit-wasm

A prototype event-based runtime. Multiple ships can run in one
process. Each ship is one SQLite file, a kernel, and agents, all WASM modules
written in Rust.

Experimental. There is a runtime, a kernel, logs that agents can follow, an
HTTP server that lets an app or a browser sign in to a ship, and an encrypted
link over which ships send each other commands and follow each other's logs.
A ship's file is encrypted on disk. There is no identity or update mechanism
yet.

## What it does

- One event is one transaction: state, outgoing messages, and an audit entry
  are saved together or not at all.
- Every call gets a fresh WASM instance, so the file is the only state.
- Idle ships are closed files, with a cap on how many are open at once.
- Each event has limits on compute, time, and memory.
- A ship's file and its signing key are encrypted on disk, under a key held by
  whoever runs the runtime.
- A ship can be exported as one sealed file and imported into another runtime.
  Only the owner's recovery code opens the file.
- The kernel is itself a WASM module. It keeps the list of installed agents and
  decides what each may do; the runtime enforces it.
- Agents declare what they offer and what they use in a manifest. Without a
  grant, one agent cannot reach another.
- An agent reads another agent's data directly, and a read cannot change
  anything. A command to another agent is queued and runs as its own event.
- Messages are Protocol Buffers, so fields can be added without breaking older
  versions.
- An agent can publish a log: a numbered, append-only list of entries. Other
  agents follow it and are handed each entry exactly once, in order.
- Every log entry is signed with the ship's key and carries the hash of the
  entry before it, so anyone holding a copy can check that nothing was forged,
  altered, or left out.
- A log does not grow for ever. Once it has grown enough, the runtime asks the
  agent for a checkpoint: its state as of the newest entry. Older entries are
  then dropped, and a follower that is far behind is handed the checkpoint in
  their place. An agent can say a log is a history, and it is then kept whole.
- A phone app or a browser signs in to a ship over HTTP with a sign-in code and
  gets a token of its own. With it, the device reads the ship's logs, waits for
  new entries, and sends commands as the owner. Each device can be signed out
  alone.
- A sign-in code is either a one-time code issued on the machine the ship runs
  on, or the ship's reusable access code, which the owner types into the ship's
  sign-in page. The ship stores only hashes of codes and tokens.
- Two ships reach each other over QUIC, which is encrypted. There is no
  certificate authority: each end shows its key and proves it holds it, and the
  other end checks that key against a directory of ships. The directory is a
  fixed list for now, standing in for Urbit ID.
- An agent can send a command to an agent on another ship. The command is saved
  with the event that sent it and kept until the other ship has it, through
  restarts and lost connections at either end. It arrives exactly once, in the
  order sent.
- Both owners have to agree. The sender's manifest names the ship and agent it
  may send to, and the receiver's manifest opens an interface to other ships.
  The receiving agent is told which ship and agent the command came from.
- Every command sent to another ship is answered with one receipt: it ran, or
  it did not and why. A refusal is written to the sender's audit log, and an
  agent can ask to be handed its receipts.
- An agent can follow a log published on another ship. Its ship fetches the
  entries, checks each against the publishing ship's key and against the entry
  before it, and keeps them until the agent takes them: each once, in order,
  through restarts and lost connections at either end.
- The agent that publishes a log decides which ships may follow it, by name or
  all of them, and can change its mind. The owner of the ship that follows
  agrees at install that the agent may follow logs on other ships.
- The publishing ship tells its followers when a log has grown, and they ask
  for what is new when they have room for it. A follower that falls behind is
  not sent the whole log to hold, and one that is too far behind is handed the
  log's checkpoint.
- If what a ship sends stops being a continuation of what a follower holds, as
  it would after that ship went back to an old backup and wrote something
  different, the follower stops and its agent is told. The agent can stop
  following and start again from the beginning.
- A ship can go back to an earlier state: a backup brought in with import.
  What happened after the backup was taken is gone from it and cannot be
  brought back, but the ships it deals with carry on. Every copy of a ship
  has a mark that changes when it is imported. A ship that follows its logs
  notices the new mark and asks afresh, so a publisher that no longer
  remembers a follower hears from it again.
- Two ships whose counts of the commands between them no longer agree tell
  each other where they stand and bring their numbering into line, so new
  commands flow both ways. A command whose answer can no longer come is given
  up: that is written to the sender's audit log, and its agent is handed a
  receipt saying the command is lost and may or may not have run.

## Layout

| Path | Contents |
| --- | --- |
| `runtime/` | The runtime, its tests, and a load test |
| `kernel/` | The kernel module |
| `proto/` | Message definitions (`ship.proto`) |
| `sdk/` | What an agent links against |
| `agents/` | Two toy agents used by the tests |

## Run

Requires Rust, the WASM target, and the Protocol Buffers compiler:

```sh
rustup target add wasm32-unknown-unknown
brew install protobuf
```

The first build also compiles SQLCipher and a private copy of OpenSSL, which
needs a C compiler, `perl`, and `make`. On a Mac these come with the Xcode
command line tools.

Tests (these build the kernel and agents themselves):

```sh
cargo test -p runtime
```

Load test:

```sh
cargo build -p kernel -p counter --release --target wasm32-unknown-unknown --target-dir target/wasm
cargo run -p runtime --release --bin loadtest -- --ships 500 --active 50 --sync normal
```

Serve a demo ship over HTTP. This prints an access code and a one-time sign-in
link; open the link in a browser:

```sh
cargo build -p kernel -p counter --release --target wasm32-unknown-unknown --target-dir target/wasm
cargo run -p runtime --release --bin serve -- --dir /tmp/ships --demo
```

The server speaks plain HTTP on localhost. Before reaching it from anywhere
else, put it behind a proxy that provides TLS, buffers request bodies, passes
addresses through unchanged, and limits how fast one caller may ask. Serve
nothing else on the same origin.

On a Mac laptop with a toy agent, 5,000 idle ships take about 80 MB of memory,
and busy ships handle about 15,000 events per second in total.

# How it works

The rest of this file is for engineers who want to know what the code actually
does. Every name, number, and default below is taken from the source as it
stands. Where a section says "the code says", it is repeating a comment in the
source rather than something the tests prove.

## Source map

| File | What it holds |
| --- | --- |
| `runtime/src/lib.rs` | `Runtime`: the public API, `Config` and its defaults, ship lifecycle (create, wake, sleep, export, import), sign-in, log verification for clients (`verify_log`, `verify_checkpoint`), module compilation |
| `runtime/src/ship.rs` | An awake ship: runs one event as one transaction, calls the kernel, runs handlers in fresh instances, takes commands and log entries from other ships, settles a ship that has fallen out of step |
| `runtime/src/host.rs` | The host functions agents import, and the fuel each costs |
| `runtime/src/store.rs` | The SQLite schema and every query; import validation |
| `runtime/src/seal.rs` | Keys: the storage key, the keys derived from it, the recovery code, and sealing and opening an exported copy |
| `runtime/src/net.rs` | QUIC transport, identity checks against the directory, carrying commands and log entries between ships |
| `runtime/src/server.rs` | The HTTP server for apps and browsers |
| `runtime/src/bin/serve.rs` | Command-line wrapper around the HTTP server, with a demo ship |
| `runtime/src/bin/loadtest.rs` | Load test |
| `runtime/tests/runtime.rs` | Integration tests |
| `kernel/src/lib.rs` | The default kernel: agent registry and routing policy |
| `proto/ship.proto` | Every message: runtime and kernel, runtime and agent, client and ship, ship and ship |
| `sdk/src/lib.rs` | Guest-side bindings and the `agent!` macro |
| `agents/counter`, `agents/tally` | Toy agents. `counter` keeps counters and publishes a log; `tally` reads and sends to `counter`, follows logs, and takes receipts |

The workspace's default member is `runtime`, so a plain `cargo build` or
`cargo test` covers only the runtime. The SDK, kernel, and agents only link for
`wasm32-unknown-unknown`.

## Data directory

`Runtime::open(dir, config)` uses this layout:

| Path | Contents |
| --- | --- |
| `ships/<name>.ship` | One SQLite file per ship, every page encrypted (SQLCipher) |
| `keys/<name>.key` | The ship's ed25519 signing key seed, encrypted: 60 bytes, mode 0600, kept beside the ship file and not in it |
| `storage.key` | The storage key as 64 hexadecimal digits, mode 0600. Only there if the runtime was not handed a key and made its own |
| `storage.check` | A value derived from the storage key, by which the directory tells its own key. It is not the key and opens nothing |
| `blobs/<sha256>.wasm` | Module bytes, named by content hash and re-verified against that hash on every load. Not encrypted: they are code, shared between ships |
| `tmp/` | Scratch files. New and imported ships are built here and then hard-linked into `ships/`, so a failure never leaves a half-made ship under its real name |
| `runtime.lock` | Held with an exclusive `flock` for the life of the runtime. A second runtime on the same directory fails with `Error::DataDirInUse` |

Ship names are lowercase letters and hyphens, at most 64 bytes, with an
optional leading `~`, not starting or ending with a hyphen. Agent names start
with a lowercase letter, then lowercase letters, digits, and hyphens, at most
64 bytes. The name `kernel` is reserved: it is where the kernel keeps its own
keys, so nothing else may run under it.

## Events

The goal is that a ship's file is always a consistent picture of the ship:
either everything an event did is saved, or none of it is. So every event is
one SQLite transaction, and agents keep no state in memory between events.

### What happens when an event runs

1. The ship is woken if it is asleep (see below), and the event takes the
   ship's lock. Events on one ship run one at a time; different ships run in
   parallel on whatever threads call the runtime.
2. `BEGIN IMMEDIATE`. For a queued event, the row is taken off the `inbox`
   table inside this transaction.
3. `SAVEPOINT handler`. Everything the agent causes happens inside it.
4. The runtime asks the ship's kernel (`route`) whether the call may go ahead.
   The kernel answers with the module hash to run and the agent's grants: the
   interfaces it may read and send to while handling this call.
5. The agent's handler runs in a fresh wasmtime instance, so nothing kept in
   WASM memory outlives the call. Its writes, outgoing messages, queued
   commands, and log appends go straight into the open transaction.
6. The runtime writes an audit row, and, for a command that came from another
   ship, a `RAN` receipt for that ship. Saving the receipt with the command's
   effects means the two cannot come apart.
7. If the event queued commands for other ships, the file must still have
   room to take one command back and finish with it. Otherwise two ships full
   of commands for each other could deadlock. The deadline is checked once
   more, then `RELEASE handler; COMMIT`.

If anything fails, the runtime rolls back to the savepoint, so the event's
effects are gone but the work around it (taking a queued command off the
queue) stays. It then records the failure in the same transaction: an audit
row with `ok = 0`, a receipt with a failure verdict if another ship is owed
one, a checkpoint request if a log was full, and, if SQLite reported the file
full, dropping log entries that checkpoints already cover. If that
transaction is lost too, the rejection is recorded in a new one. A queued
command that is rejected is dropped, not retried.

A rejected event surfaces as `Error::Rejected` with one of `OutOfFuel`,
`Timeout`, `Denied`, `Limit`, or `Trap`.

`Runtime::deliver` runs the owner's command and then up to
`max_queued_per_deliver` queued events, so agents that keep sending each
other commands cannot hold a ship. The rest wait for `run_pending` (or, with a
network running, for the network to run them). `Runtime::read` runs a read
handler inside a `BEGIN` that is always rolled back.

### Kinds of call

Each queued or delivered call has a kind, which picks the export the runtime
calls:

| Kind | Export | Notes |
| --- | --- | --- |
| `KIND_COMMAND` | `handle` | Changes state. Runs as its own event |
| `KIND_READ` | `read` | Runs read-only: any write, send, emit, or log change is denied |
| `KIND_NOTIFY` | `notify` | A log the agent follows has entries for it. No payload |
| `KIND_CHECKPOINT` | `checkpoint` | The runtime asks for the state behind one of the agent's logs. Read-only, with no send grants |
| `KIND_RECEIPT` | `receipt` | What became of a command the agent sent to another ship. Skipped if the module has no `receipt` export |

### Compute, time, and memory limits

These stop a hostile or buggy agent from stalling a ship or the process.

- Fuel. Every event gets `fuel_per_event` units. Each host call costs 5,000
  plus one per byte moved, so a cheap guest loop cannot buy unlimited host
  work. Appending to a log costs 50,000 more, for the signature. A nested read
  is paid from the reader's remaining fuel. Fuel is also checked after the
  handler returns, so straight-line code that overran cannot commit.
- Time. Fuel cannot see how large a bulk memory operation is, so each event
  also has a wall-clock deadline of `max_event_millis`. A watchdog thread
  advances wasmtime's epoch every 10 ms, and the deadline is checked again
  just before commit, so a late result is not used. Before compiling, the
  runtime rewrites each module so that every `memory.fill`, `memory.copy`,
  `memory.init`, `table.fill`, `table.copy`, and `table.init` is preceded by an
  empty loop. Wasmtime checks fuel and epochs at loop headers, so this forces a
  check before each bulk operation.
- Memory. Each instance may have one memory of at most `max_memory_bytes`, one
  table of at most `max_table_elements`, and 512 KiB of native stack. Reads can
  nest up to 8 deep; before each instance the runtime moves to a fresh stack
  segment if too little native stack is left, so deep nesting cannot overflow
  the thread.
- The kernel's own calls have a separate budget, `kernel_fuel`, so an agent
  cannot exhaust it.

### Awake and asleep

So that thousands of ships can share a process, a ship is only an open file
while it is in use. At most `max_awake` ships are open at once. Opening one
more closes the least recently used idle ship; if every open ship is mid-event,
the caller waits. `Runtime::sleep_idle(d)` closes every ship idle for at least
`d`. Waking a ship opens its file, checks the schema version and that the file
belongs to that ship, loads its kernel, and reads its key. Compiled modules are
shared across ships through a cache keyed by content hash.

## The kernel and permissions

The point of the kernel is to keep policy (who may call what) out of the
runtime. It is an ordinary WASM module, chosen per ship at creation by its
hash, that exports `route` and `admin`. It can only read and write its own keys
in the `kv` table; the runtime enforces whatever it decides. The kernel in
`kernel/` is the default one.

`admin` handles `Install` (add or replace an agent with its module hash and
manifest) and `ListModules`. `Runtime::install` passes the owner's manifest to
`admin`; passing it is the owner's approval, and the kernel has the final say.
The default kernel keeps a `Registry` under the key `registry`, and refuses an
install that would exceed 256 agents, 64 manifest entries per list, 512 KiB of
registry, or a possible `route` answer over 256 KiB.

A manifest lists what an agent offers and what it uses:

| Field | Meaning |
| --- | --- |
| `Provide.interface` | An interface this agent offers. A log is named after one |
| `Provide.public` | Any agent on the ship may use it without declaring it |
| `Provide.remote` | Agents on other ships may send commands to it |
| `Use.agent`, `Use.interface` | Something this agent uses |
| `Use.read`, `Use.send` | Whether it reads (or follows a log), sends commands, or both |
| `Use.ship` | Empty for this ship; otherwise a ship name or `*` for any ship |

The default kernel's `route` rules:

- The owner may call any installed agent.
- An agent on this ship may use an interface that the target provides and that
  is public, its own, or declared in its manifest with the matching `read` or
  `send` flag.
- An agent on another ship may only send a `KIND_COMMAND`, and only to an
  interface marked `remote`. What each ship may then do is up to the agent,
  which is told the calling ship in `Invocation.source`.
- A notification about a local log needs the follower to be allowed to read
  the publisher's interface. One about a log on another ship needs a `Use`
  naming that ship (or `*`), agent, and log with `read` set.
- A checkpoint request must be for one of the agent's own interfaces.
- On success, the reply carries the agent's grants: its own and every public
  interface, its declared local uses, and its declared remote uses.

Whatever a kernel grants, the runtime also enforces its own name rules, and
never runs anything under the name `kernel`. A ship imported from elsewhere
brings its own kernel, which decides policy for that ship only.

## The agent interface

### Module shape

An agent module exports `memory`, `alloc(len: u32) -> u32`, and
`handle(ptr: u32, len: u32) -> u64`, plus any of `read`, `notify`,
`checkpoint`, and `receipt` with the same signature. The runtime calls `alloc`,
writes the input there, calls the handler, and reads the reply from the
returned value: pointer in the high 32 bits, length in the low 32.

### Host functions

Agents import these from the module `host`. Requests and replies are encoded
Protocol Buffers messages from `proto/ship.proto`. Functions that fill a buffer
return the full length; if the answer did not fit, the guest calls again with a
bigger buffer.

| Function | Purpose |
| --- | --- |
| `kv_get(key, key_len, buf, cap) -> i64` | Read one of this agent's own keys. `-1` if absent. A value too big for the buffer is not loaded |
| `kv_put(key, key_len, val, val_len)` | Write one of this agent's keys |
| `kv_delete(key, key_len)` | Delete one |
| `emit(ptr, len)` | Queue an outgoing message in the ship's outbox, released only on commit |
| `invocation(buf, cap) -> i64` | The `Invocation`: kind, interface, and `Source` (owner, or agent and ship) |
| `read(req, req_len, buf, cap) -> i64` | `ReadRequest`. Runs another agent's read handler now, in a fresh instance, read-only |
| `take_reply(buf, cap) -> i64` | Collect a read or `log_next` reply that did not fit the first buffer, so the call is not run twice |
| `send(req, req_len)` | `SendRequest`. Queue a command for another agent, run after this event commits |
| `send_to(req, req_len) -> i64` | The same; for another ship, returns the number the command goes under, which its receipt will carry |
| `log_append(req, req_len) -> i64` | `AppendRequest`. Add a signed entry to one of this agent's own logs; returns its number |
| `log_follow(req, req_len)` | `FollowRequest`. Follow a log, on this ship or another, from entry 1 |
| `log_unfollow(req, req_len)` | Stop following. No permission needed |
| `log_share(req, req_len)` | `ShareRequest`. Let a named ship, or `*`, follow one of this agent's logs, or stop |
| `log_next(req, req_len, buf, cap) -> i64` | `NextRequest`. Take entries after this agent's position, at most 256 entries or 256 KiB per call |

The calls that change something are refused during a read or a checkpoint.

### SDK

`sdk/` wraps the host functions for Rust agents:

- `kv::get`, `kv::put`, `kv::delete`; `emit`; `invocation`; `read`; `send`;
  `send_to`.
- `log::append`, `log::follow`, `log::follow_on(ship, ..)`, `log::unfollow_on`,
  `log::next`, `log::next_on(ship, ..)`, `log::share`, `log::unshare`.
  `next` returns a `Batch` with `entries`, `more`, an optional `checkpoint` to
  replace local state with, and an optional `stopped` reason for a log on
  another ship.
- `Receipt` and `Verdict`, re-exported from the protocol.
- `agent!(handle, read = f, notify = f, checkpoint = f, receipt = f)` exports
  `alloc`, `handle`, and whichever roles are named. Command, read, and notify
  handlers are `fn(&[u8]) -> Vec<u8>`; a checkpoint handler is
  `fn(&str) -> Option<Vec<u8>>`; a receipt handler is `fn(&Receipt)`.

## Storage

Each ship is one SQLite file, and the file is the ship's source of truth. The
schema version is `9`, stored in the `meta` table; a file with any other
version is refused.

| Table | Purpose |
| --- | --- |
| `meta` | Schema version, ship name, kernel module hash, and the ship's incarnation mark |
| `kv` | Agent state, keyed by (agent, key). The kernel's registry lives here under agent `kernel` |
| `outbox` | Messages agents emitted, waiting for whatever embeds the runtime to drain them |
| `inbox` | Queued events: commands between agents, commands from other ships (with that ship's number for them), notifications, checkpoint requests, receipts |
| `peers` | Per other ship: last number sent, last number received, bytes waiting, whether it needs to hear where this ship stands, and which round of comparing notes this is |
| `peer_out` | Commands and receipts waiting to go to other ships, numbered per ship |
| `peer_wait` | Commands sent to other ships that have no receipt yet |
| `logs` | Per log: newest entry number and hash, bytes held, how many early entries are dropped, bytes since the last checkpoint, and flags for a pending checkpoint request and for history logs |
| `log_entries` | Signed entries, as signed |
| `checkpoints` | The newest signed checkpoint of each log |
| `follows` | Per follower and log (on this ship or another): its position, whether a notification is queued, and how many times in a row its handler failed |
| `remote_logs` | Per log followed on another ship: how far it has been fetched and checked, what the publisher last announced, bytes held, why it stopped (if it did), and the publisher's last seen incarnation mark |
| `remote_entries`, `remote_checkpoints` | Payloads and checkpoint state fetched from other ships and checked, held until the follower takes them |
| `log_shares` | Which ships each log is shared with, by name or `*` |
| `log_peers` | Which other ships follow each log, and whether they need to be told it has grown |
| `audit` | Recent events and runtime notes, with time, agent, payload, and success. Trimmed to the newest `audit_rows` |
| `devices` | Signed-in devices: a hash of each token, a label, and when it signed in |
| `signin_codes` | Hashes of one-time codes and of the reusable access code, with expiry |

Files are opened with `journal_mode = WAL` and `trusted_schema = OFF`. With
`Durability::Full` (the default), SQLite uses `synchronous = FULL` and
`fullfsync = ON`; with `Durability::Normal`, `synchronous = NORMAL`, which can
lose the last few events on power loss but not corrupt the file. A ship's size
limit is enforced with `max_page_count`, so a write past `max_ship_bytes`
fails like any other limit. Every queued or outgoing message counts its
payload plus 64 bytes against the relevant quota.

### Encryption at rest

There are two keys, held by two different people (`runtime/src/seal.rs`).

The **storage key** belongs to whoever runs the runtime. It is 32 bytes, handed
over as `Config::storage_key`. From it the runtime derives, with HKDF-SHA256
and a separate label for each use:

- a file key per ship, from the storage key and the ship's name. It is given to
  SQLCipher as a raw key (`PRAGMA key`) straight after the file is opened and
  before anything else touches it, so every page of the ship's file, its WAL,
  and its rollback journal is encrypted. Temporary storage is kept in memory.
- a key per ship for its signing key file. The file holds a random 12-byte
  nonce and the seed sealed with ChaCha20-Poly1305, bound to the ship's name.

So one ship's file or key file is of no use under another ship's name or in
another runtime's directory. If no storage key is handed over, the runtime
makes one the first time it opens a new directory and keeps it there as
`storage.key`. That protects a ship's file copied off on its own; it does
nothing for a disk stolen whole, since the key is on it. An operator who wants
that keeps the key somewhere else and hands it over at start.

A directory remembers which key it was made with (`storage.check`).
`Runtime::open` refuses any other key, refuses to make a new key for a
directory that has been used, and refuses a used directory with nothing to
check a key against (`Error::BadStorageKey`). A ship file its key does not open
fails with `Error::BadShipFile`.

The storage key does not hide a ship from whoever runs it. A ship cannot run
unless its file can be read, so that person has to hold the key.

The **recovery code** belongs to the ship's owner. It is 160 random bits
written as 32 letters and digits in eight groups. The ship keeps only the
public half of an X25519 key pair derived from the code (in `meta`), which can
seal a copy and cannot open one:

- `set_recovery_key(ship, public)` takes the public half, so an owner's device
  can make the code (`seal::recovery_code`, `seal::recovery_public`) and never
  show it to the machine the ship runs on. Keys that would be unsafe or that
  the code could not open are refused.
- `new_recovery_code(ship)` is the simple way: the runtime makes the code, sets
  the key, returns the code once, and keeps no copy.

### Export and import

Export and import are how a ship moves between runtimes or is restored from a
backup.

`export_ship(ship, dest)` writes `dest/<ship>.ship`, mode 0600, and
`dest/blobs/<hash>.wasm` for the kernel and every module the kernel lists. It
fails with `Error::NoRecoveryKey` if the ship has no recovery key. The file is
`ship.v1.export\n`, then an X25519 public key made for that copy alone, then
the ship's signing key and the whole contents of its file sealed with
ChaCha20-Poly1305. The sealing key comes from the agreement between that
copy's key and the recovery key, bound to both public keys and the ship's
name. The contents are copied out in memory (about twice the ship's size while
the copy is made) and are never written to disk unsealed. The modules are
written first and the sealed file last, in one rename, so an export that fails
leaves any earlier copy as it was. A ship cannot be exported into the
directory its runtime keeps ships in.

Because the copy is sealed to a public key, it can be made with nobody
present, for example by a host on a schedule, and the host cannot read what it
made. The seal keeps a copy secret. It does not prove who made it: anyone who
knows a ship's recovery public key can seal something to it. That is why
import still checks everything.

`import_ship(src, ship, code)` opens the copy with the recovery code and then
treats what is inside as untrusted:

- It reads only regular files, without following symlinks, up to
  `max_import_bytes`, and the whole import must finish within
  `max_import_millis`. The copy is opened and read in memory (up to about
  twice `max_import_bytes` for a moment). A copy that has been changed in any
  way, is for another ship, or was sealed to another code is refused before
  any of it is read as a database.
- The source's schema must match this runtime's exactly, so it cannot carry
  triggers or views. The schema entries are first counted straight from the
  file's pages, before SQLite parses them, and SQLite length limits are set
  before the first query. `PRAGMA quick_check` must pass.
- Rows are copied into a freshly created file, each re-validated: names,
  sizes, and counts against this runtime's limits. Every log entry and
  checkpoint is verified against the ship's public key and the hash chain, and
  each log's summary row is rebuilt from what is actually there, so a file
  with its newest entries cut off is refused. Queues, numbered messages to and
  from other ships, and copies of other ships' logs must all be consistent
  with each other. AUTOINCREMENT counters are carried across so numbers are
  never reused.
- Devices and sign-in codes travel with the ship; the count of wrong sign-in
  codes does not.
- Every module is verified against its hash before it is stored.
- The copy gets a new incarnation mark, every other ship it exchanged
  commands with is marked to compare notes, and every follower of its logs is
  told afresh where they stand. See "After a restore" below.
- The new ship's file is written under the importing runtime's storage key,
  and the ship keeps the recovery key of the code that opened the copy,
  whatever the copy itself says. The same code opens copies made of it from
  then on.

## Logs

A log lets an agent publish a sequence of facts that others can follow and
check without trusting the ship that serves them.

### Entries

An agent has one log per interface it offers, named after that interface. Each
entry's signed part is an `EntryBody`: ship, agent, log, `seq` (numbered from
1 with no gaps), `prev` (SHA-256 of the previous entry's body, empty for entry
1), and payload. The ship signs it with ed25519 over a domain label followed by
the body: `ship.v1.entry\n` for entries, `ship.v1.checkpoint\n` for
checkpoints. The label means a signature for one kind of message can never be
passed off as the other. Signatures are always checked over the bytes as
stored, never over a re-encoding.

`verify_log(public_key, ship, agent, log, after, entries)` and
`verify_checkpoint(...)` are public, for clients. They prove the entries are
genuine and that none is missing between them; to know a reader has all of
them, it also needs the log's current head from somewhere it trusts.

### Followers on the same ship

A follower has a position in the `follows` table. When a log grows, each
follower without a notification already waiting gets one, so a burst of
entries queues one notification, not many. Notifications and checkpoint
requests do not count against the inbox quota; an agent may follow at most 64
logs, which bounds them. A follower that has not taken everything is notified
again. If its notify handler fails 3 times in a row, it is left alone until the
log grows again or it follows again. `log_next` moves the position only when
the entries have actually been handed over and the event commits, so an entry
is never lost or handled twice.

### Checkpoints and trimming

So a log does not grow without bound, the runtime asks the publishing agent
for a checkpoint: its state as of the log's newest entry, which the runtime
signs as a `CheckpointBody` (ship, agent, log, `seq`, the hash of entry `seq`,
and the state).

- A request is queued once the bytes appended since the last checkpoint exceed
  both `checkpoint_min_bytes` and the size of that checkpoint, or early when
  the next entry of the same size would not fit in `max_log_bytes`. At most one
  request per log is queued.
- When a new checkpoint is written, entries up to the previous checkpoint are
  dropped. Entries the newest checkpoint covers are kept a while for followers
  that are only a little behind.
- When an append would pass `max_log_bytes`, entries the newest checkpoint
  covers are dropped at once. If that is not enough, the append is refused.
- When SQLite reports the file full, every log lets go of the entries its
  checkpoint covers.
- A follower whose next entry has been dropped is handed the checkpoint in its
  place, if it said it can take one (`NextRequest.checkpoints`, which the SDK
  sets). Otherwise its request fails rather than skipping entries.
- A checkpoint handler that returns `None` marks the log as a history: it is
  never trimmed and never asked again. An agent with no `checkpoint` export is
  never asked, and its logs are kept whole.

The runtime cannot check that the state an agent returns is true. The SDK
documentation says an agent must only change the state behind a log in the
same event that appends the entry describing the change.

## Networking

Ships on different runtimes (or the same one) talk so that agents can send
each other commands and follow each other's logs. The network is optional: a
`Runtime` works without one. `Network::start(runtime, directory, net_config)`
starts it, and a runtime has at most one.

### Transport and identity

- QUIC via `quinn`, with TLS 1.3 from `rustls` (the `ring` provider). ALPN is
  `ship/1`. One UDP address serves every ship in the runtime.
- There is no certificate authority. Both ends present raw ed25519 public keys
  (no certificates) and prove they hold the private half by signing the
  handshake. The caller names the ship it wants in the TLS server name, and the
  answering runtime shows that ship's key. The caller accepts only the key the
  directory lists for that ship; the answerer accepts only a caller whose key
  the directory lists, and knows from it which ship is calling.
- The `Directory` maps ship name to (public key, socket address). It is a
  fixed list handed in by whoever starts the network, standing in for Urbit ID.
  One key can be listed for only one ship. If the directory changes, existing
  connections made under the old listing are closed.
- Session resumption is off, so every connection proves its keys afresh.
  Connection migration is off.
- Each request and its reply travel on one bidirectional stream. Unidirectional
  streams and datagrams are not accepted. There is one connection per (calling
  ship, called ship); a newer one replaces the older.
- The code says an observer still sees which ship is being called, that this
  protocol is in use, the addresses, and the size and timing of traffic.
- Before a request or reply is decoded, the runtime counts its repeated fields
  without allocating: at most 256 messages in a `Deliver`, 256 logs in a
  `News`, and 256 entries in a `Fetched`.

### Wire messages

A `PeerRequest` holds one of the following, and the `PeerReply` holds the
matching answer, or only `refused` with a reason.

| Request | Reply | Purpose |
| --- | --- | --- |
| `Ping { nonce }` | `Pong { nonce, ship, caller, incarnation }` | Who are you, who do you take me for, and which copy of yourself are you |
| `Deliver { messages }` | `Delivered { last }` | Numbered commands and receipts, in order. `last` is the highest number the receiver now holds |
| `Fetch { agent, log, after, max_bytes, joining }` | `Fetched { entries, head, checkpoint, denied, incarnation }` | Entries of a log after `after`, as signed; or the checkpoint if they were dropped; or a refusal |
| `News { logs }` | `Heard { unknown }` | The publisher says these logs grew (or are closed to you). The follower says which it no longer follows |
| `Resync { standing }` | `Resynced { standing }` | Two ships say where each stands, to get back in step after a restore |

### Commands between ships, exactly once

The aim is that a command an agent sends to another ship arrives exactly once,
in order, through restarts and lost connections at either end, and that the
sender always learns what became of it.

- Both owners must agree. The sending agent's manifest names the ship (or `*`),
  agent, and interface with `send` set; the receiving agent's interface is
  marked `remote`.
- `send_to` writes the command into `peer_out`, numbered from 1 per destination
  ship, in the same transaction as the event that sent it, and records it in
  `peer_wait`. It is sent only if that event commits.
- The network carries batches of up to half of `max_message_bytes` (and 256
  messages) per `Deliver`. The receiver takes a message only if it is the next
  number after the last it took; one with a lower number is skipped as a
  duplicate, and one further ahead stops the batch. The new number and the
  queued command are saved together. The sender drops what `Delivered.last`
  covers.
- When the command has run, or been refused, the receiving ship sends one
  `Receipt` back the same way, in the same numbered stream. The sending agent
  gets it as a `KIND_RECEIPT` event if it exports `receipt`. A receipt that is
  not `RAN`, or that could not be queued, is written to the sender's audit log.
- Back-pressure: a sender may have at most `max_unanswered` commands without a
  receipt to one ship, at most `max_peer_out_bytes` waiting for it, and deal
  with at most `max_peers` ships. A receiver stops taking commands from a ship
  while it owes it `max_unanswered` receipts, and only takes a command when its
  file has room for it, for every receipt it owes, and 16 KiB more. A command
  that could never be run, or that is larger than `max_inbox_bytes` or a
  quarter of `max_ship_bytes`, is refused with a receipt instead of blocking
  everything behind it.
- After a failed attempt, the next one waits `retry_delay`, doubling up to
  `max_retry_delay`.

| Verdict | Meaning |
| --- | --- |
| `RAN` | It ran, and what it did is saved |
| `DENIED` | Not allowed: no such agent, or the interface is not open to other ships. The kernel's reason is passed on |
| `FAILED` | The handler crashed, ran out of fuel, or took too long. Only fixed words are sent; details stay in the receiving ship's audit log |
| `LIMIT` | It hit one of the receiving ship's limits |
| `MALFORMED` | It could not be run at all |
| `LOST` | Made up by the sender's own ship after a restore, when nobody can say whether it ran |

### Following a log on another ship

The design is "tell, then ask": the publisher only says a log has grown, and
the follower fetches entries when it has room, so a slow follower is never
sent the whole log to hold.

- The publishing agent decides who may follow, with `log::share(log, ship)` or
  `"*"`, and can take it back. The following agent's manifest must name that
  ship (or `*`), agent, and log with `read` set.
- The follower's ship sends `Fetch`. The publisher refuses with the same words
  whether or not the log exists, otherwise records the follower (at most
  `max_log_followers` per log) and returns entries as signed, or its
  checkpoint if the entries asked for were dropped.
- The follower checks every entry against the key the publisher proved on the
  connection, the log's identity, and the hash of the entry before. It holds
  checked payloads in `remote_entries` until its agent takes them with
  `log::next_on`. It fetches only while it holds less than
  `max_follow_bytes`, so it can pass that by at most one entry.
- When the log grows, the publisher marks each following ship and sends it
  `News`. A follower that does not follow that log any more says so in `Heard`,
  and is no longer told.
- The log stops for that follower if the publisher refuses, or what it sends
  does not carry on from what the follower holds (a broken chain, or a head
  that is shorter or ends differently), or an entry or checkpoint is larger
  than the follower takes. The agent is notified and `next_on` reports why.
  Following again asks afresh from the beginning.

### After a restore

A ship can be brought back from a backup with import. What happened after the
backup is gone, but other ships should carry on with it.

- Every copy of a ship has an incarnation mark: 16 random bytes, new on
  creation and on every import. `Pong` and `Fetched` carry it. Every
  `follow_check` (default 600 s), a ship that follows logs on another pings it;
  if the mark changed, it asks afresh with `joining` set, so a restored
  publisher that has forgotten its followers learns of them again.
- For commands, each ship can describe where it stands with another in a
  `Standing`: last number sent, last received, oldest still waiting, and the
  numbers of the other's commands it holds and has not yet answered. The two
  exchange `Resync`/`Resynced`, and each brings its own numbering into line,
  believing the other only about the other's own side. A command whose answer
  can no longer come is given up: the sender's agent gets a `LOST` receipt and
  the sender's audit log records it.
- Comparing notes happens after an import, when a `Delivered` acknowledgement
  cannot be squared with what the sender remembers, and every `follow_check`
  while a ship has commands another has not answered. Each round of comparing
  notes has a number, and acknowledgements from an earlier round are ignored.
  If two ships are still out of step after one resync, commands between them
  stop (logs carry on), and `Network::stalled()` lists the pair.

## HTTP server for clients

The server lets a phone app or a browser act as the ship's owner without
running a ship of its own. `Server::start(runtime, server_config)` starts it.
It reads HTTP itself: one request per connection, a body only with
`Content-Length`, and a hard limit on every size and wait (16 KiB of head, 100
headers).

A ship is named in the path, `/ships/<ship>/...`, or by hostname when
`ship_host_suffix` is set (so `zod.example.net` is ship `zod` with paths
starting at `/`).

| Method and path | Auth | Answer |
| --- | --- | --- |
| `GET /signin` | none | Sign-in page; with `?code=`, a sign-in link that accepts only a one-time code |
| `POST /signin` | none | Protobuf `SignInRequest` gets a `SignInReply` with a token; a form post sets a cookie |
| `GET /` | device | The ship's page (HTML), listing devices |
| `GET /devices` | device | `DeviceList` |
| `POST /signout` | device | Signs this device out |
| `POST /devices/<id>/revoke`, `DELETE /devices/<id>` | device | Signs another device out |
| `GET /key` | device | The ship's 32-byte public key |
| `GET /logs/<agent>/<log>/head` | device | `LogHead` |
| `GET /logs/<agent>/<log>/entries?after=&max_bytes=&wait=` | device | `EntryList` with the current head. `max_bytes` defaults to 256 KiB, at most 1 MiB. `wait` (seconds) long-polls up to `max_wait`. Gone entries answer 410 with `Trimmed` |
| `GET /logs/<agent>/<log>/checkpoint` | device | `SignedCheckpoint`, or 404 |
| `POST /agents/<agent>/command` | device | Runs the body as an owner command; the agent's reply as the body |

- Codes. A one-time code is 128 random bits in hex, made by
  `new_signin_code` on the machine the ship runs on. The reusable access code
  is 100 random bits written as twenty characters in four groups, from an
  alphabet without i, l, o, or u. Only domain-separated SHA-256 hashes of codes
  and tokens are stored. After `signin_max_failures` wrong codes in a row, all
  sign-in is locked for `signin_lock_millis` (HTTP 429 with `Retry-After`).
- Tokens. Apps send `Authorization: Bearer <token>`. Browsers get a cookie,
  `ship_token`, that is `HttpOnly` and `SameSite=Strict`, and `Secure` when
  `secure_cookies` is on. A cookie-authenticated request other than `GET` must
  show, through `Sec-Fetch-Site` or `Origin`, that it came from the ship's own
  page.
- HTML answers carry a strict `Content-Security-Policy`, and every answer
  carries `Cache-Control: no-store`. A ship that does not exist answers like
  one the caller is not signed in to.
- Long polls hold a worker thread, so at most half the workers may be waiting
  at once; the rest are answered straight away.

`serve` takes `--dir` (required), `--addr` (default `127.0.0.1:8080`),
`--host-suffix`, `--storage-key-file <file>` (the storage key as 64
hexadecimal digits; without it the key is made and kept in the data
directory), `--secure-cookies`, `--access-code <ship>`,
`--signin-link <ship>` (a one-time link good for ten minutes), and `--demo`
with optional `--kernel` and `--counter` paths. `--demo` creates `~zod` with
the counter agent offering `counter` and `journal`, if it does not exist.

## Configuration

### `Config` (runtime)

| Field | Default | Meaning |
| --- | --- | --- |
| `fuel_per_event` | 100,000,000 | Compute budget for one event |
| `kernel_fuel` | 50,000,000 | Budget for each kernel decision |
| `max_event_millis` | 5,000 | Wall-clock cap on one event |
| `max_memory_bytes` | 64 MiB | WASM memory per instance |
| `max_ship_bytes` | 1 GiB | Largest a ship's file may grow |
| `max_module_bytes` | 16 MiB | Largest module accepted |
| `max_import_bytes` | 256 MiB | Largest exported copy `import_ship` reads |
| `max_import_millis` | 60,000 | Longest an import may take |
| `max_table_elements` | 100,000 | WASM table size per instance |
| `max_event_bytes` | 1 MiB | Largest command, read request, or log entry payload |
| `max_reply_bytes` | 1 MiB | Largest handler reply |
| `max_outbox_bytes` | 64 MiB | Undelivered outbox messages per ship |
| `max_inbox_bytes` | 64 MiB | Queued commands and receipts per ship |
| `max_peer_out_bytes` | 16 MiB | Commands waiting to go to any one other ship |
| `max_peers` | 4,096 | Other ships one ship may exchange commands with |
| `max_unanswered` | 4,096 | Commands to one ship without a receipt; also receipts one ship may owe another |
| `max_log_bytes` | 64 MiB | Entries one log may hold |
| `max_logs` | 16,384 | Logs per ship |
| `max_follow_bytes` | 4 MiB | How much of a log on another ship is held for one follower |
| `max_log_shares` | 4,096 | Ships one log may be shared with by name |
| `max_log_followers` | 4,096 | Other ships following one log at once |
| `checkpoint_min_bytes` | 64 KiB | Growth since the last checkpoint before asking for another |
| `max_checkpoint_bytes` | 1 MiB | Largest checkpoint state |
| `max_queued_per_deliver` | 64 | Queued events run after each `deliver` |
| `max_awake` | 64 | Ships open at once |
| `audit_rows` | 10,000 | Audit rows kept per ship |
| `max_devices` | 64 | Devices signed in per ship |
| `max_signin_codes` | 32 | One-time codes waiting per ship |
| `signin_max_failures` | 5 | Wrong codes in a row before sign-in locks |
| `signin_lock_millis` | 60,000 | How long it stays locked |
| `durability` | `Full` | `Full` or `Normal` (see Storage) |
| `storage_key` | none | The key everything kept on disk for ships is encrypted under. If none, one is made and kept in the data directory (see Encryption at rest) |
| `limits.max_key_bytes` | 1,024 | Largest `kv` key |
| `limits.max_value_bytes` | 1 MiB | Largest `kv` value |
| `limits.max_effect_bytes` | 1 MiB | Largest emitted message |
| `limits.max_effects_per_event` | 1,024 | Emits per event; also caps commands sent and log appends per event |

### `NetConfig` (network)

| Field | Default | Meaning |
| --- | --- | --- |
| `addr` | `127.0.0.1:0` | UDP address to listen on; port 0 picks one |
| `request_timeout` | 10 s | One request to another ship, connecting included |
| `idle_timeout` | 30 s | A connection with no traffic is closed |
| `max_connections` | 1,024 | Incoming connections at once |
| `max_calls` | 1,024 | Other ships this runtime's ships may be connected to at once |
| `max_streams` | 8 | Requests in progress on one incoming connection |
| `max_message_bytes` | 1 MiB + 64 KiB | Largest request or reply taken |
| `max_reading_bytes` | 64 MiB | Room for incoming requests being read, all connections together |
| `max_requests` | 64 | Outgoing requests at once |
| `max_working` | 16 | Pieces of ship work the network has in hand at once, each on a thread |
| `max_carrying` | 16 | Deliveries to other ships in hand at once |
| `retry_delay` | 200 ms | First wait after a failed delivery, doubling |
| `max_retry_delay` | 30 s | Longest wait between tries |
| `follow_check` | 600 s | How often to check other ships' incarnation marks and compare notes on unanswered commands |

`Network::start` refuses settings that could wedge a ship: `max_ship_bytes`
below 256 KiB, a `max_message_bytes` without room for the largest command or
checkpoint plus 4 KiB, or without room for `max_unanswered` command numbers
twice over, and any time limit that is zero or over a day.

### `ServerConfig` (HTTP)

| Field | Default | Meaning |
| --- | --- | --- |
| `addr` | `127.0.0.1:0` | TCP address to listen on |
| `ship_host_suffix` | none | Such as `.example.net`; must start with a dot |
| `workers` | 16 | Request threads (at least 2). Connections queue, four per worker, and past that are dropped |
| `secure_cookies` | false | Mark the cookie `Secure` |
| `max_wait` | 30 s | Longest long poll |
| `max_body_bytes` | 1 MiB | Largest request body |
| `io_timeout` | 10 s | Time to send the whole request, and again to take the whole answer |

## Tests

`cargo test -p runtime` runs:

- Integration tests in `runtime/tests/runtime.rs`. The first test to need a
  module runs `cargo build -p kernel -p counter -p tally --release --target
  wasm32-unknown-unknown --target-dir target/wasm` once per run; the separate
  target directory avoids the outer cargo's lock. Hostile modules are written
  inline in WebAssembly text and compiled with the `wat` crate. Each test uses
  its own temporary data directory, and most use `Durability::Normal` to skip
  per-commit syncs.
- Unit tests in `net.rs`, `seal.rs`, `server.rs`, and `store.rs`.

The integration tests are grouped roughly in this order: transactions and
rollback; fuel, time, memory, table, and stack limits, including bulk memory
tricks; isolation and permissions; export and import, including tampered,
damaged, and hostile files; sleeping, waking, and the awake cap; queued
commands; logs, followers, and checkpoints; sign-in and devices; the HTTP
server over real sockets, including slow and malformed clients; the QUIC
network with two runtimes on localhost, including directory changes and
connection limits; commands and receipts between ships; following logs on
other ships; recovery after one ship is restored from a backup; and
encryption at rest and sealed copies.

The load test (`runtime/src/bin/loadtest.rs`) takes `--ships` (500),
`--active` (50), `--events` (20,000), `--threads` (8), `--max-awake` (64),
`--sync full|normal` (full), `--wasm`, `--kernel`, and `--dir` (a new
temporary directory, which must not exist and is deleted at the end). It
creates the ships with the counter agent, puts them all to sleep, delivers to
200 sleeping ships to time cold wakes, then has the threads deliver
`inc hits` to random ships among the active ones. It checks that the counters
add up to exactly the number of events, and reports setup time per ship,
resident memory (empty, all asleep, and busy), throughput, busy latency (p50,
p99, p99.9, max), cold wake latency (p50, p99, max), and disk per ship.

## Known limits

These are stated in the source.

- There is no identity or update mechanism. The directory of ships is a fixed
  list standing in for Urbit ID, and a ship's key does not change while its
  runtime runs.
- Encryption at rest does not hide a ship from whoever runs it, and a storage
  key kept in the data directory does not protect a stolen disk. Ship names,
  file sizes, and which modules exist are not hidden. Keys are not wiped from
  memory, and the storage key cannot be changed for a directory once made.
- There is no way yet for an owner's device to hand its recovery public key to
  a ship over HTTP; it is a runtime call. Changing a ship's recovery key is
  not recorded in its audit log. A recovery code is not slowed against
  guessing, so one a person makes up is as weak as they make it.
- An exported copy holds the ship's private key, inside the seal. Running both
  the original and an imported copy gives two writers of the same logs, which
  nothing prevents yet.
- Data directories and exports from before encryption do not open. There is
  no migration.
- Which modules a ship needs is known only to its kernel. A kernel that leaves
  one out of `ListModules` produces an export that imports cleanly and fails
  when that agent is first called.
- A kernel rewrites its whole registry, dropping fields it does not know, so a
  kernel must never run against a registry written by a newer one.
- The runtime signs whatever state a checkpoint handler returns; it cannot
  check it.
- `verify_log` shows that entries are genuine and contiguous, not that they
  are all there is; that needs the head from a trusted source.
- Two ships still out of step after one resync stop exchanging commands. The
  commands are kept, and nothing sorts it out yet.
- A followed log that stops because the publisher's history changed is not
  repaired; the agent has to unfollow and follow again.
- Two runtimes with different size limits can still disagree about what fits
  in a message.
- The HTTP server speaks plain HTTP and expects a proxy in front of it (see
  Run).

## License

MIT
