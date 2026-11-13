# urbit-wasm

A prototype event-based runtime. Multiple ships can run in one
process. Each ship is one SQLite file, a kernel, and agents, all WASM modules
written in Rust.

Experimental. There is a runtime, a kernel, logs that agents can follow, an
HTTP server that lets an app or a browser sign in to a ship, and an encrypted
link over which ships send each other commands and follow each other's logs.
A ship's file is encrypted on disk. A ship's keys can be derived from its Urbit
ID master ticket, but ships do not yet look each other up in Azimuth, and there
is no update mechanism yet.

## What it does

- One event is one transaction: state, outgoing messages, and an audit entry
  are saved together or not at all.
- Every call gets a fresh WASM instance, so the file is the only state.
- Idle ships are closed files, with a cap on how many are open at once.
- Each event has limits on compute, time, and memory.
- A ship's file and its signing key are encrypted on disk, under a key held by
  whoever runs the runtime.
- A ship can be made from its Urbit ID master ticket or its keyfile, and then
  runs with the networking key Urbit's own wallet derives for it.
- A ship can be exported as one sealed file and imported into another runtime.
  Only the owner opens the file, with the master ticket.
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
  other end checks that key against Urbit ID: the key Azimuth lists for the
  ship's name, read from Ethereum, and for a ship on layer 2 from the roller.
  Or, without the roller: from a copy of all of Azimuth kept in a local file,
  worked out from Ethereum under Urbit's own rules, layer 2 included. A moon,
  which Azimuth does not list, shows its parent's signed word for its key.
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
cargo test
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

Look a ship up in Urbit ID, through any Ethereum node. This is read-only and
needs no data directory:

```sh
cargo run -p runtime --release --bin serve -- --ethereum https://ethereum.publicnode.com --lookup '~zod'
```

The same from a copy of Azimuth kept in a file, worked out from Ethereum
without the roller. The first run reads all of Azimuth's history, which took
under ten minutes through a free public node; after that it starts at once. The
node must answer `eth_getLogs` for old blocks (many free ones do not; see
Reading Azimuth):

```sh
cargo run -p runtime --release --bin serve -- --ethereum https://gateway.tenderly.co/public/mainnet \
  --azimuth-copy /tmp/azimuth.sqlite --lookup '~zod'
```

Run a real ship on the network, from its keyfile, with other ships' keys read
from Urbit ID. `--peer` says where another ship is to be found (add
`--azimuth-copy <file>` to read keys from a copy instead of the roller):

```sh
cargo run -p runtime --release --bin serve -- --dir /tmp/ships --keyfile my-planet.key \
  --ethereum https://ethereum.publicnode.com --net 0.0.0.0:4433 --peer '~sampel-palnet=203.0.113.7:4433'
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
| `runtime/src/seal.rs` | Keys: the storage key, the keys derived from it, the recovery key, and sealing and opening an exported copy |
| `urbit-id/src/` | Urbit ID's keys as Urbit derives them: `wallet.rs` (master ticket to networking keys, UP 8), `argon2.rs` (Urbit's Argon2 variant), `ob.rs` (ship and moon names, tickets), `keyfile.rs` (reading and writing keyfiles), `naive.rs` (Azimuth's state worked out from its logs and layer 2 batches: a port of Urbit's `naive.hoon`) |
| `runtime/src/azimuth.rs` | Reading Urbit ID: a ship's key from the Azimuth contract on Ethereum, or from the roller for a ship on layer 2 |
| `runtime/src/chain.rs` | Reading Ethereum's history over JSON-RPC: logs over a range of blocks, transaction inputs, the finalised block |
| `runtime/src/replica.rs` | A copy of Azimuth in a local SQLite file, kept up to date from Ethereum alone, answering the same lookups as `azimuth.rs` |
| `runtime/src/moon.rs` | A parent's signed word for its moon's key |
| `runtime/src/net.rs` | QUIC transport, the directory of keys and addresses, identity checks against it, carrying commands and log entries between ships |
| `runtime/src/server.rs` | The HTTP server for apps and browsers |
| `runtime/src/bin/serve.rs` | Command-line wrapper around the HTTP server, with a demo ship |
| `runtime/src/bin/loadtest.rs` | Load test |
| `runtime/tests/runtime.rs` | Integration tests |
| `kernel/src/lib.rs` | The default kernel: agent registry and routing policy |
| `proto/ship.proto` | Every message: runtime and kernel, runtime and agent, client and ship, ship and ship |
| `sdk/src/lib.rs` | Guest-side bindings and the `agent!` macro |
| `agents/counter`, `agents/tally` | Toy agents. `counter` keeps counters and publishes a log; `tally` reads and sends to `counter`, follows logs, and takes receipts |

The workspace's default members are `runtime` and `urbit-id`, so a plain
`cargo build` or `cargo test` covers those two. The SDK, kernel, and agents only link for
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

The **recovery key** belongs to the ship's owner, and comes from the master
ticket the owner already holds (see "Keys from Urbit ID" below), so there is
no second secret to keep. The ticket gives a code, the code gives an X25519
key pair, and the ship keeps only the public half (in `meta`), which can seal
a copy and cannot open one:

- A ship made with `create_ship_from_ticket` has its recovery key from the
  start.
- `set_recovery_key(ship, public)` takes just the public half, which
  `Runtime::recovery_key_of_ticket(ship, ticket)` works out. So whoever holds
  the ticket can give a ship its recovery key without showing the ticket to
  the machine the ship runs on. Keys that would be unsafe or that the code
  could not open are refused.

### Keys from Urbit ID

A planet's owner holds one secret, the master ticket. Urbit's HD wallet
(proposal UP 8) derives everything else from it. The `urbit-id` crate does the
part a ship needs, and is checked against the test vectors of Urbit's own
key-generation library, so a real planet's ticket gives here the keys it gives
there:

| Step | How |
| --- | --- |
| Ticket and ship number to master seed | Argon2u, salt `urbitkeygen<number>`, 4 lanes, 512,000 KiB, 1 pass. Argon2u is Urbit's own variant, so it is implemented here (`argon2.rs`) and its engine is tested against a standard Argon2id library |
| Master seed to a branch | SHA-256 of the seed and the branch's name, written as a 24-word phrase (BIP39). Branches: ownership, transfer, spawn, voting, management |
| Management phrase to network seed | SHA-256 of the phrase's BIP39 seed, `network`, and the revision number; hashed once more for revisions above 0 |
| Network seed to networking keys | SHA-512 of the seed; the first half is the authentication key, the second the encryption key, both ed25519 |
| Master seed to backup code | SHA-256 of the seed and `ship.v1.backup`. This branch is this runtime's own, not part of UP 8 |

- `create_ship_from_ticket(name, kernel, ticket, revision)` makes a ship that
  proves who it is with the ticket's authentication key for that revision,
  which is the key Azimuth lists for the planet. The ticket is used and not
  kept. Deriving from a ticket takes about half a gigabyte of memory and under
  a second, by design, and one derivation runs at a time.
- `create_ship_from_keyfile(kernel, keyfile)` makes a ship from an Urbit
  keyfile, which names the ship and holds only its networking keys. This is
  how a ship is started by someone who is not given the ticket. Both keyfile
  shapes in use are read. `Runtime::keyfile(name, revision, keys)` writes one.
- `import_ship_with_ticket(src, ship, ticket)` opens an exported copy with the
  ticket.
- `create_ship(name, kernel)` still makes a ship with a random key, for trying
  things out.
- The planet's encryption key is not used and not kept. Traffic between ships
  is encrypted with keys made for each connection (TLS 1.3 inside QUIC); the
  Urbit key only proves who each ship is.
- Names are galaxies, stars, planets, and moons. A moon is started from the
  keyfile its parent makes for it (see Moons). Comets are refused.

### Reading Azimuth

`runtime/src/azimuth.rs` answers one question: which key does Urbit ID list
for this galaxy, star, or planet. It asks one ship at a time, over JSON-RPC,
and keeps nothing itself (the network's directory keeps the answers).

1. It asks an Ethereum node for the ship's row in the Azimuth contract's
   `rights` table, which gives the owner.
2. If the owner is an ordinary address, the ship is on layer 1, and its keys
   are read from the contract's `points` table. The roller is not asked.
3. If the owner is the deposit address (`0x1111...1111`), the ship has been
   moved to layer 2. If Ethereum has no owner for it, and the star or galaxy
   above it has given its ownership or its right to spawn to the deposit
   address, the ship may have been made on layer 2. In both cases the keys
   are asked of the roller (`getPoint`). If Ethereum has no owner for that
   star either, the galaxy above it is checked the same way. The contract
   makes both conditions permanent, and refuses a layer 1 spawn under a star
   in either state.
4. Otherwise the ship does not exist.

A ship has a usable key only if its key revision is above zero, its crypto
suite is 1, and its key is not zero. Otherwise the answer is "a ship with no
key, as of revision N", which is different from "no such ship". Azimuth stores a key as a number, which is the
key's bytes reversed. The roller answers only requests whose JSON-RPC `id` is
a string, and says `Resource not found` for a ship it has never heard of.
Answers are read up to 64 KiB, redirects are not followed, and each question
has a 10 second limit.

Who is trusted: the Ethereum endpoint, for everything; and the roller, for
ships Ethereum places on layer 2 and for nothing else. This file does not
replay the layer 2 batches to check the roller; the copy below does. The
block asked about is `latest`.

`serve --ethereum <url> --lookup <ship>` prints what is listed for a ship.

### A copy of Azimuth, without the roller

`runtime/src/replica.rs` answers the same question from a copy of Azimuth's
whole state, kept in a local file and worked out from Ethereum alone, the way
every Urbit ship works it out for itself. Only the Ethereum node is trusted.
`serve --azimuth-copy <file> --ethereum <url>` uses it in place of the roller,
for `--net` and for `--lookup`.

What it reads:

- Every log of the Azimuth contract
  (`0x223c067F8CF28ae173EE5CafEa60cA44C335fecB`, from block 6,784,880) of a
  kind `naive.hoon` applies: owner, proxies, keys, continuity, escapes and
  sponsors. The node is asked for those kinds alone. `Activated`, `Spawned`
  (a ship starts from the ship above it, so `naive.hoon` ignores them),
  `OwnershipTransferred` (who owns the contract itself) and `ChangedDns` (the
  network's domain names, whose data can be of any length) are not asked
  for.
- Every `Batch` log of the layer 2 contract
  (`0xeb70029cfb3c53c778eaf68cd28de725390a1fe9`, from block 13,369,829), and
  for each, the input of the transaction that made it
  (`eth_getTransactionByHash`). That input, whole, is the batch.
- Both in Ethereum's order, by block and then place in the block, layer 1
  and layer 2 interleaved. A layer 2 transaction is judged by what layer 1
  said at that moment: a proxy changed on layer 1 after a layer 2 transaction
  does not undo it.

The rules are Urbit's `naive.hoon`, ported to `urbit-id/src/naive.rs`, which
says in its comments which part of `naive.hoon` each piece follows:

- A layer 1 log changes the ship it names. Once a ship is on layer 2, only
  its sponsor's doings on layer 1 (accepting an escape, letting it go) still
  reach it. Giving a ship, or a star's right to spawn, to the deposit address
  `0x1111...1111` moves it, or where its children are made, to layer 2.
- A batch is read as one number, from its low end, which is from the end of
  the input back to its start. Zero bytes at the very start are not part of
  it, and a transaction that runs past the start reads zeros there. Each
  transaction, from its end back: a 65-byte signature (r, s, v as written), a
  byte whose low 3 bits say in which role it is signed, the ship (4 bytes), a
  byte whose low 7 bits say what is asked and whose top bit is a flag (on when
  zero), then what is asked. One transaction that cannot be read voids the
  whole batch.
- What is signed is `UrbitIDV1Chain1:`, the signer's count of transactions so
  far (4 bytes, least significant first), and the transaction's bytes in
  reverse, wrapped as Ethereum wallets wrap a message. The signature must
  recover to whoever holds that role for that ship at that moment. A
  transaction that is not so signed changes nothing. One that is counts as
  sent (its count goes up) even if the rules then refuse it.
- Signatures are recovered with the `k256` crate, taking either value of `s`
  as Ethereum does, and `v` with or without 27 added.

The file is plain SQLite (public data, not encrypted): a `points` table, one
row per ship, and a `meta` table with the last block read, counts of what was
read, and which chain and contracts the file is a copy of (a file is never
opened as a copy of another). Each step forward, a range of blocks applied and
the new last block, is one transaction: a crash or a failed question leaves
the file where it was, and the next poll carries on from there. Only one copy
may have the file open at a time: it holds an exclusive lock on
`<file>.lock` for as long as it is open, and a second opener, in the same
program or another (such as `serve --lookup` on the file a running server
uses), is refused at once with a message saying so. Links are followed first,
so the file is locked under one name however it is reached; a file with a
second name of its own (a hard link) is refused; and SQLite opens the file
without following a link, so a link put in its place after its name was
worked out is refused too.

A lookup decides that the copy may answer and reads its answer in one step,
holding the copy's status throughout, so it never reads a file part way
through catching up. A poll holds the status only for a moment, never while
asking the node anything.

Only blocks Ethereum has finalised (`eth_getBlockByNumber("finalized")`) are
read, and lookups are answered from the file alone. So a change on Ethereum is
seen once its block is final, about 15 minutes after it lands, and a layer 2
change about 15 minutes after the roller has put its batch on Ethereum (which
the roller itself does only every so often). The newest blocks are not read
because they can still be replaced, and a copy that never has to undo
anything is simpler to trust: an answer is never older than one given before
it, so a ship's key revision as looked up never goes down, which the
network's directory relies on when it refuses a lower revision than it has
seen. The copy asks how far the chain is final once a minute, and asks for
nothing else when that has not moved.

Lookups are refused until the file has reached the newest finalised block
heard of in this run, with no allowance: a file part way through its history
would hand out keys that have since changed. (So for the second or so after
each new final block is heard of, while it is read, lookups are refused and
the directory goes on with what it had.) After that, if the node goes away,
lookups go on being answered from what the copy has. A node whose final block
goes back, behind one it gave before or behind what the file has read, is not
followed. A ship has a listing if it is in the table; its key follows the same
rules as above.

Ethereum nodes differ, and the code copes:

- A range of blocks starts at 10,000, is cut to an eighth whenever a question
  about it is refused, fails, or has too long an answer, and doubles whenever
  an answer holds fewer than 1,000 events, up to 100,000.
- A node that asks to be asked less often (HTTP 429, or a message saying so)
  is asked the same again after a wait that starts at the pause between
  questions (500 ms) and doubles up to a minute. After 8 tries in a row
  without an answer, the poll gives up until the next.
- Transaction inputs are asked for 20 to a request where the node takes
  several questions at once, and one at a time where it does not. An input,
  once had, is kept until its block is in the file, so a range that is tried
  again does not ask for it again.
- A failed question is never taken as an empty answer, and how much is read
  of an answer is bounded (table below). Answers are read straight into the
  shapes asked for, passing over fields not asked for without keeping them:
  something not of the shape asked for is refused where it is met, and a list
  of logs longer than is taken is refused as it is read. So reading one answer
  holds at most about five times its size (its bytes, the logs read from them,
  and the logs made of those), and an answer that is all small pieces cannot
  grow into gigabytes. Inputs of transactions are taken in one by one as they
  come, against the room there is, so that no more than one is in hand beyond
  it; and before a range is fetched, inputs kept from before that it does not
  want are let go. A transaction is asked for once
  however many batches it logged, and two different inputs for one
  transaction in one block are refused. Every answer must be JSON-RPC 2.0 and
  carry the number of the question it answers. Logs must be from the contract, of a kind asked
  for, from the blocks asked about, in order, not removed, and shaped as the
  contract declares their kind: as many topics and bytes of data
  (`ChangedKeys` 128 bytes, `BrokeContinuity` 32, `Batch()` one topic and
  none), and every argument no wider than its type (a `uint32` with 28 zero
  bytes in front of it, an address with 12). This is checked before
  `naive.hoon`'s rules run, since some of them return before reading every
  argument. A transaction must be the one asked for, in the block its log
  says (by number and by hash), and in only one block across a range; and a
  block number must have only one hash across a range, both contracts'
  logs together, and a block hash only one number. An input is kept for, and
  used for, the one block (number and hash) it was had for. Block numbers must fit in what
  SQLite keeps. Anything else is an error that stops the step, and nothing is
  written; an answer that cannot be right (a wrong shape, one transaction in
  two blocks) is not asked for again in smaller pieces, which could hide it.
- Dropping the copy stops it at once: no question is asked after that, a
  pause between questions ends, a step being applied gives up before its next
  event and between one layer 2 transaction and the next, and nothing of that
  step is written.
  Each question to the node is asked on a thread of its own and waited on,
  so a stop ends the wait at once even while the node says nothing or stalls
  part way through its answer; the thread left behind ends by itself at the
  question's own limit, which also covers finding the node's address (the
  HTTP library itself does not limit that). Only one look-up of the node's address runs at a
  time: one that does not answer is waited on again by the next question, and
  no other is started, so a resolver that never answers holds one thread.

What is read from the node, and what each field is checked against (the list is also at
the top of `runtime/src/chain.rs`). Two fields that are read and contradict each other are
an error; any field not listed is not read. A range is the blocks read in one step.

| Answer | Field | Checked against |
| --- | --- | --- |
| Every answer | `jsonrpc` | text, "2.0" (on every answer that is not a refusal) |
| Every answer | `id` | the number of the question asked, as text; a refusal may carry another number, however written, or `null`, and among answers to questions asked at once a refusal is taken first |
| Every answer | `result` | the shape asked for; `null` is an answer with nothing in it, an error |
| Every answer | `error` | when there, an object, never `null`; its `message` text or `null`, only reported; never beside a result that is not `null` |
| Final block | `number` | never behind a final block heard of before, or behind the file |
| Log | `address` | the contract asked about |
| Log | `removed` | absent or false (not `null`) |
| Log | `blockNumber` | within the blocks asked; with `logIndex`, strictly increasing; one hash per number and one number per hash in a range |
| Log | `blockHash` | as above; the same as a batch's transaction's |
| Log | `logIndex` | with `blockNumber`, strictly increasing; never the same as another log's in a range |
| Log | `transactionHash` | in one block in a range; its logs together in its block; for a batch, the transaction asked for |
| Log | `transactionIndex` | in a block, one per transaction and one transaction per index, never going down as `logIndex` goes up; for a batch, the same as its transaction's |
| Log | `topics` | one to four, 32 bytes each; the first a kind asked for; as many as its event has, each no wider than its type |
| Log | `data` | at most 16 KiB; as long as its event's, each word no wider than its type |
| Transaction | `hash` | the hash asked for |
| Transaction | `blockNumber`, `blockHash`, `transactionIndex` | those of its batch's log |
| Transaction | `input` | at most the limit for one input; the same in every answer for one transaction at one place |

Not read: a final block's hash, parent and transactions; a log's `blockTimestamp`; a
transaction's `from`, `to`, `value`, `gas`, `nonce` and signature (a batch may be sent
through another contract, and its input is taken as Urbit's own software takes it). Not
compared across ranges: that a transaction or block hash read in one range does not come
again in a later one, which an honest node cannot give, since ranges cover different blocks.
Numbers must be written as Ethereum writes a quantity (hexadecimal digits, no zero in front
but `0` itself), and bytes as an even number of hexadecimal digits. Every value is read only
as the kind listed: an object as an object (never its fields in order as a list), text as
text, a list as a list, and `null` nowhere but where the table says: a refusal's `id` and
`message`, and an answer's `result` (which is then an error).

No block Ethereum allows may stop the copy. Anyone can call the layer 2
contract (it logs a batch for any call), so anyone willing to pay for the gas
can put a block at Ethereum's limits on chain, and one too big to read would
stop every copy for good. So the limits on what is read are there to bound
memory against a broken node, are sized from Ethereum's limits with room to
spare, and are used to read a range of blocks in smaller pieces, never to
refuse a single block. A single block is refused only past what Ethereum
could ever put in one, which only a broken node can claim. All are settings
(`ReplicaConfig`, `Limits`):

| Limit | For a range (read in pieces past it) | For one block (refused past it) | Sized against |
| --- | --- | --- | --- |
| Logs in one answer | 10,000 | 250,000 | The cheapest log is a `Batch` from a call to the layer 2 contract, about 850 gas each: 250,000 is over 210 million gas, several times a block's limit |
| Bytes of an answer of logs | 16 MiB | 256 MiB | 250,000 logs at about 450 bytes each as written |
| Input of one transaction | 32 MiB | same | Input costs at least 4 gas a byte, so at most a quarter of a block's gas in bytes (15 MB at 60 million gas; newer rules cap a block at 10 MiB) |
| Batches held in memory, each input once | 64 MiB | 128 MiB | A block's inputs together are under a quarter of its gas in bytes |
| Batches applied, each logged batch counted | 64 MiB | none: one block is applied whatever its work, and a stop is noticed between events and between transactions | One transaction can log its input many times over |
| Data of one log | 16 KiB | same | Only applied kinds are asked for; the longest has 128 bytes |
| Topics of one log | 4 | same | Ethereum's own maximum |
| The answer about the final block | 16 MiB | | Every transaction's hash, 69 bytes each, at 21,000 gas a transaction: blocks of over five billion gas |
| Several transactions asked for in one request | 20, and 8 MiB of answer | | Past either, they are asked for one at a time |
| Time for one question | 30 s | ten times that, for one block's logs or one transaction | Longer answers |

Measured in November 2026: `ethereum.publicnode.com` refuses old ranges
("Archive requests require a personal token"); `gateway.tenderly.co/public/mainnet`
takes 100,000 blocks to a question and several questions to a request, and
answers HTTP 429 when asked too often; flashbots takes 2,000 blocks,
Cloudflare 800; drpc's free plan refuses. A full read of the main network
through Tenderly is described under Tests.

### Moons

A moon's number is its parent's with 32 more bits in front, and its name ends
with its parent's name (`~doznec-sampel-palnet` is a moon of
`~sampel-palnet`). Azimuth does not list moons. On Urbit, other ships learn a
moon's key by asking its parent, so the parent must be running. Here the
parent signs a statement and the moon carries it:

- `moon_keyfile(parent, moon, revision)` makes new keys for the moon, has the
  parent sign `ship.v1.moon\n`, the moon's number, the revision, and the
  moon's public key, and returns a keyfile. The keyfile is Urbit's older
  shape, with the signature in the slot that shape has for one (Urbit leaves
  it empty). The parent must be on this runtime, and keeps no list of its
  moons.
- `create_ship_from_keyfile` starts the moon on any runtime. The signature
  and revision (68 bytes, not secret) are kept in the moon's ship file, so
  they travel with an exported copy.
- When the moon calls a ship, it sends the proof with its name. When a ship
  calls the moon without holding its current key, the moon sends the proof in
  its answer. Either way the other ship checks the signature against the
  parent's key from the directory, and checks that the key in the statement
  is the one the connection proved.
- A ship remembers the highest revision it has seen for each moon, and
  refuses a lower one, or a different key at the same revision. When the
  parent's own key changes, every proof it signed stops being accepted.

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

`import_ship(src, ship, code)` opens the copy with the recovery code (the one
`import_ship_with_ticket` derives from the master ticket) and then
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
  directory holds for that ship (for a moon, any key, which is then checked
  against the moon's proof before anything is asked of it).
- Urbit ID is looked up by name, not by key, so the answerer cannot tell who
  is calling from the key alone. The first stream of every connection carries
  a `Hello` with the caller's name (and a moon's proof). The answerer looks
  the name up and goes on only if the key the handshake proved is the one
  listed for it. No other request on the connection is read before that, and
  the check is made again before each request is acted on.
- The `Directory` holds, for each ship, its key and where it is. Keys come
  from one of three places: Urbit ID (`Directory::reading(keys)`, where `keys`
  is an `Azimuth` or anything else that implements `Keys`); a moon's proof; or
  `set(ship, key, addr)`, by hand, which is how the tests run and which is
  never overwritten by the other two.
- A key read from Urbit ID is used for 5 minutes without asking again. After
  that it is still used, and read again in the background. If it cannot be
  read again it is believed for a day and then no longer. A ship that shows a
  key other than the one held causes one fresh read, at most every 5 seconds
  per ship. A failed read is retried no sooner than 5 seconds later.
- Azimuth counts how many times a ship's keys have been set, and the count
  only goes up. The directory keeps the count with the key. An answer with a
  lower count than the one still believed is refused, whatever it says, so an
  Ethereum node that is behind cannot put back a key that has been replaced.
  When a ship's keys are taken away, the count is kept in the key's place for
  the same reason.
- Only one question about a ship is out at a time, and everyone who wants the
  answer waits on that one. At most 8 questions run at once and at most 64
  ships are waiting to be asked about; half of those places are kept for
  ships this runtime's own ships want to call. At most 32 callers a second
  that nothing is known of are looked up. The rest are turned away unasked.
- A ship that has proved its key on a connection, or whose key a moon's proof
  was checked against, is kept for as long as what is held for it is believed,
  through any later change of its keys. There is room for 65,536 such ships,
  moons included (at most 32,768 moons, 256 per parent). When that is full, a
  new ship cannot be met until entries lapse. Keys that were looked up only
  because someone said a name have their own allowance of 4,096, and the
  older half are dropped when it fills. A connection is taken only on a key
  that has been proved.
- Where a ship is (its socket address) is not in Urbit ID. It is given with
  `place(ship, addr)`. A wrong address cannot pass one ship off as another,
  since whatever answers must still prove the key.
- If what the directory holds for a ship changes, connections made under the
  old listing are closed.
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
| `Hello { ship, proof }` | `Welcome { proof }` | First on every connection: which ship is calling. Each side sends its moon proof if it is a moon |

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

For talking to other ships it takes `--ethereum <url>` (an Ethereum JSON-RPC
node to read Azimuth through), `--roller <url>` (default: Urbit's roller),
`--azimuth-copy <file>` (keep a copy of Azimuth in this file, worked out from
Ethereum, and read keys from it instead of the roller; with `--lookup` it
first waits for the copy to catch up, saying how far along it is; otherwise
it says on standard error, once each, when the copy runs into trouble and
when it is out of it, and a lookup refused while the copy is held up says
why),
`--net <address>` (start the ship network on this UDP address, with keys from
Urbit ID), `--peer <ship>=<address>` (where another ship is; repeatable),
`--keyfile <file>` (start the ship that keyfile is for, if it is not there),
and `--lookup <ship>` (print what Urbit ID lists for the ship and exit).

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

### `ReplicaConfig` (copy of Azimuth)

`ReplicaConfig::mainnet(ethereum)` gives:

| Field | Default | Meaning |
| --- | --- | --- |
| `ethereum` | given | The Ethereum node's JSON-RPC address |
| `azimuth`, `azimuth_from` | `0x223c...fecb`, 6,784,880 | The Azimuth contract and the block it was made in |
| `naive`, `naive_from` | `0xeb70...1fe9`, 13,369,829 | The layer 2 contract and the block it was made in |
| `chain` | 1 | Ethereum's chain number, part of every layer 2 signature |
| `timeout` | 30 s | One question to the node, connecting included |
| `every` | 60 s | How often to ask whether more blocks are final |
| `pause` | 500 ms | Least time between two questions, and the first wait after one goes unanswered |
| `widest` | 100,000 | Most blocks asked about in one question |
| `limits` | `Limits::default()` | How much of the node's answers is read, for a range and for one block (table under Reading Azimuth) |
| `most_batch_bytes` | 64 MiB | Most bytes of batches held in memory for a range of blocks, each input once |
| `most_block_batch_bytes` | 128 MiB | The same for one block, which cannot be split |
| `most_work_bytes` | 64 MiB | Most work for a range of blocks, each logged batch counted; one block is applied whatever its work |
| `tries` | 8 | Questions in a row that may go unanswered before a poll gives up |

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

`cargo test` runs:

- Integration tests in `runtime/tests/runtime.rs`. The first test to need a
  module runs `cargo build -p kernel -p counter -p tally --release --target
  wasm32-unknown-unknown --target-dir target/wasm` once per run; the separate
  target directory avoids the outer cargo's lock. Hostile modules are written
  inline in WebAssembly text and compiled with the `wat` crate. Each test uses
  its own temporary data directory, and most use `Durability::Normal` to skip
  per-commit syncs.
- Unit tests in `net.rs`, `seal.rs`, `server.rs`, `store.rs`, `moon.rs`, and
  `azimuth.rs`. The Azimuth tests run against a stand-in JSON-RPC server on
  localhost that replays what Ethereum and the roller really answered for
  `~zod`, and answers like them for made-up ships. One more test asks the real
  Ethereum and the real roller; it is not run by default
  (`cargo test -p runtime --lib -- --ignored`, with `ETHEREUM_RPC` to choose
  the node).
- Unit tests of `urbit-id/src/naive.rs`, written from the rules of
  `naive.hoon`: every kind of layer 2 transaction and every check of role,
  rank, and where a ship is; counts going up for a signed transaction the
  rules refuse and not for a badly signed one; a high `s` and a `v` without
  27; one unreadable transaction voiding its batch; zeros left off the front
  of a batch; ships never seen taking where they are from the ship above;
  every layer 1 log, including the two that still reach a ship on layer 2;
  logs not shaped as the contract makes them. Transactions are signed with
  real secp256k1 keys, and a signature whose point lies past the curve's
  order (v of 2 or 3) is made by working backwards from a chosen point and
  recovered. go-azimuth's examples of batches from the main network
  are read, and their signatures recovered to the addresses go-azimuth gives.
- Unit tests in `replica.rs`, against a stand-in Ethereum node on localhost
  that answers from a made-up chain: both contracts interleaved (a layer 2
  spawn signed just before a layer 1 change of owner fails, one just after
  works), a node that takes only 7 blocks to a question, fails, and asks to be
  asked less often, inputs not asked for twice, a file closed and opened
  again carrying on where it was, lookups refused while the file is even one
  block short of the final block and answered after the node goes away,
  blocks past the final one never read and a revision that never goes down
  across polls, a second opener of the file refused, logs of the wrong shape,
  answers to another question or not in JSON-RPC 2.0 (one at a time and
  several at once), a final block that goes back or is too big to write
  down, a step whose second log fails after its first was applied (nothing
  of it in the file when opened again), batches too big to hold at once, a
  node that takes one question per request, and dropping the copy while it
  is reading.
- Unit tests in `urbit-id`, against the test vectors of Urbit's key-generation
  library (wallets, networking keys, keyfiles, ship names) and against a
  standard Argon2 library. Moon names are checked against the example in
  Urbit's naming library.

The copy of Azimuth was also checked against the real main network, by hand
and not as part of `cargo test` (13 November 2026). Read from nothing through
Tenderly's public node it took 560 seconds (30 seconds of it computing), 974
requests of which 112 were answered "too many requests" and asked again, and
69 MB of memory at most. To block 26,407,242 it read 355,837 Azimuth logs
(of every kind, as it then asked for) and 7,035 batches (none unreadable):
276,132 layer 2 transactions done, none refused by the rules, 898 not
properly signed. Of those 898, 886 are in 262
batches that repeat an earlier batch byte for byte (their counts were already
used), 10 are ten calls to the layer 2 contract that are not batches at all
(68 bytes each, an Ethereum function call), 1 is a note written to the
contract as a batch, and 1 is an adopt whose signature does not match the
proxy and count the star holds at that point (the roller has not counted it
either). The result was compared with:

- go-azimuth, another reading of the same rules, fed the very same answers
  from the node (recorded on the way): all 144,503 points the same in every
  field (where each ship is, owner and every proxy with its count, keys and
  their revision, kind, continuity, sponsor, escape). go-azimuth reports one
  failed signature fewer: it drops the note as not a batch, where
  `naive.hoon` reads it as one transaction with a missing signature.
- Urbit's roller (`getPoint`), for every star not on layer 1 (106), 50 planets
  on layer 1, and 749 planets on layer 2 from all 132 stars that have any:
  every field the same.
- The Azimuth contract itself (`points` and `rights`, read at the same block)
  for all 256 galaxies, 100 stars and 100 planets on layer 1, and the 46 ships
  that make their children on layer 2. The differences are ones `naive.hoon`
  makes on purpose, and the roller agrees with the copy on each: a planet made
  on layer 1 for someone who has not yet taken it is not active in the
  contract and has no sponsor there, where `naive.hoon` gives it its star
  from the start (14 of the 100 planets); a ship that moved its children to
  layer 2 keeps the spawn proxy it had, where the contract has the deposit
  address (all 46); and ships whose sponsor took them in through layer 2 have
  that sponsor, where the contract still has the old one and the escape
  outstanding (8).

After lookups were limited to final blocks and the checks on answers were
tightened, the same recorded answers were replayed to the copy through a
local stand-in for the node, and the file came out the same as before, row
for row (144,503 points, and the same counts). A fresh read from Tenderly
then reached block 26,407,625 in 553 seconds: the same rows again, and one
planet more, made on layer 1 after the earlier read, which matches the
contract.

Since then the copy asks for Azimuth's logs by kind, only the kinds it applies.
Replayed from the same recording it again came out the same, row for row; it
now reads 193,701 logs, which is exactly how many of the 355,837 logs in the
recording (made without asking by kind) are of the kinds applied. The rest
are 82,160 `Spawned`, 79,968 `Activated`, 6 `OwnershipTransferred` and 2
`ChangedDns`, and no kind it does not know of. A fresh read from Tenderly,
asking by kind, reached block 26,407,753 in 512 seconds: every row of the
earlier fresh read the same, and one planet more, which again matches the
contract.

The integration tests are grouped roughly in this order: transactions and
rollback; fuel, time, memory, table, and stack limits, including bulk memory
tricks; isolation and permissions; export and import, including tampered,
damaged, and hostile files; sleeping, waking, and the awake cap; queued
commands; logs, followers, and checkpoints; sign-in and devices; the HTTP
server over real sockets, including slow and malformed clients; the QUIC
network with two runtimes on localhost, including directory changes and
connection limits; commands and receipts between ships; following logs on
other ships; recovery after one ship is restored from a backup; encryption
at rest and sealed copies; ships made from a master ticket or a keyfile; a
directory that reads keys from a stand-in for Urbit ID (key changes, removed
keys, outages, impostors, the limit on unknown callers); and moons.

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

- Reading Azimuth with `azimuth.rs` trusts the Ethereum endpoint for
  everything and the roller for ships on layer 2, and uses the `latest` block,
  so a reorganised block can briefly show a key that does not last. The copy
  (`replica.rs`) needs no roller but still trusts the Ethereum endpoint for
  everything; removing that trust means running one's own node. The copy sees
  a change only once its block is final, about 15 minutes after it lands.
- The copy's first read of all of Azimuth takes about ten minutes through a
  free public node, and needs one that answers `eth_getLogs` for old blocks. It
  then asks the node once a minute how far the chain is final, and more only
  when that has moved.
- A hard link to the copy's file made by someone else at the moment it is
  opened, after its name has been checked, is not caught. It takes someone
  who can already write to the directory.
- The copy skips Azimuth's domain names and the operators of `ApprovalForAll`,
  which `naive.hoon` keeps and nothing here needs. Counts of transactions, key
  revisions and continuity are kept in 32 bits, where `naive.hoon`'s have no
  limit; each would take four billion signed transactions on Ethereum to go
  round.
- Where a ship is to be found is still a list handed in. Nothing finds a ship
  through its sponsor yet.
- A moon's key cannot be taken back at once. A ship that has not seen a later
  proof goes on accepting an earlier one until the parent changes its own
  key. A parent keeps no list of its moons.
- What a directory has learned (keys, key revisions, moon revisions) is kept
  in memory only. It is lost when the runtime restarts, and for a ship whose
  key has not been readable for a day.
- The directory is bounded and never drops a ship that has proved its key
  while that key is believed. Someone with tens of thousands of real ships,
  or enough ships to vouch for 32,768 moons, could fill it and keep new ships
  from being met until entries lapse.
- A ship's own key does not change while its runtime runs. The planet's keys
  on Ethereum (ownership and the rest) are derived only as phrases. There is
  no update mechanism.
- Whoever holds a ship's master ticket can open its backups and controls the
  planet. A host that makes the ticket holds it until the owner takes over,
  and that handover is not built.
- Encryption at rest does not hide a ship from whoever runs it, and a storage
  key kept in the data directory does not protect a stolen disk. Ship names,
  file sizes, and which modules exist are not hidden. Keys are not wiped from
  memory, and the storage key cannot be changed for a directory once made.
- There is no way yet for an owner's device to hand its recovery public key to
  a ship over HTTP; it is a runtime call. Changing a ship's recovery key is
  not recorded in its audit log. A ship started from a keyfile has no
  recovery key until it is given one.
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
