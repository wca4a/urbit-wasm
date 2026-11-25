# urbit-wasm

A prototype event-based runtime. Multiple ships can run in one
process. Each ship is one SQLite file, a kernel, and agents, all WASM modules
written in Rust.

Experimental. There is a runtime, a kernel, logs that agents can follow, an
HTTP server that lets an app or a browser sign in to a ship, a store of files
of any size on each ship for the owner's devices, and an encrypted link over
which ships send each other commands, ask each other questions, follow each
other's logs, and fetch each other's files.
A ship's file is encrypted on disk. A ship's keys can be derived from its Urbit
ID master ticket, ships check each other's keys against Azimuth and find each
other's addresses through lookup points, and there is no update mechanism yet.

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
- A ship can be exported as one sealed file (and, if it holds files, a second
  sealed file beside it with them) and imported into another runtime. Only the
  owner opens these, with the master ticket. The sealed file also lists what
  the owner had kept from other ships (which files, not their contents); an
  import leaves that list behind.
- A ship keeps files of any size beside its own file, up to an allowance the
  operator sets (10 GiB by default). The owner's signed-in devices upload a
  file a chunk at a time, can stop and carry on where they left off, and
  download it whole or in part. Each file belongs to the agents that claim it,
  and only a device asking through one of those agents sees it. An agent keeps
  only a reference to a file, never its bytes.
- The owner of one ship can open a file kept on another, through their own
  ship, if the agent that holds it there allows it: the agent is asked, or
  has marked the file open to every ship. The owner's ship checks every piece
  against the file's id before passing it on, so a ship that lies can make a
  fetch fail but never hand over a wrong byte.
- What the owner opens is kept for a while, so opening it again needs no
  network, even if the other ship is off or has taken the file back. The
  owner can see what is kept and clear it. Up to an allowance the operator
  sets (3 GiB by default); when that is full the least recently opened goes,
  and anything not opened for 30 days. The owner can also save a copy for
  good: it then becomes one of their own files, as if they had uploaded it.
- A file is known by a hash over its contents, checked chunk by chunk, so
  every byte served is checked against what was stored, and identical files
  are kept once. Files are encrypted on disk like everything else, and go
  with an exported copy in a second sealed file; an import keeps only files
  that arrive whole and unchanged.
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
- A command can ask for the handler's reply, which then comes back with its
  receipt: from a ship that follows the protocol, the receipt says it ran and
  carries the whole reply, or the command did not stand (an agent that needs
  the reply checks `Receipt.replied`; see Commands between ships).
- An agent, or a ship's owner through one of their devices, can ask an agent
  on another ship a question. A question only reads: the other agent's read
  handler answers it, nothing it does there is kept, and the ship that answers
  stores no data of the question (SQLite's own housekeeping of the file aside:
  see Questions between ships). Both owners agree, as for commands. The answer
  comes within a time limit, or a clear reason why not: refused, failed, too
  large, no answer in time, not reachable. An agent cannot wait inside an
  event, so it is handed the answer later, as an event of its own, exactly once
  for each question unless it gave the question up.
- A ship asked questions by other ships rests from them for a few times as
  long as each takes, so the measured times of the questions it lets in past
  its look at the rests add up to at most a quarter of any stretch of its
  time, all asking ships together, and a tenth for any one ship, each plus the
  length of one such question (see Questions between ships for what is and is
  not counted).
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

### Two ships on one machine

One command starts a lookup point and two ships, `~sampel-palnet` and
`~norsyr-torryn`, as three programs on this machine, and walks through what
they can do, acting as each owner's phone or browser would:

```sh
cargo build -p kernel -p counter -p tally --release --target wasm32-unknown-unknown --target-dir target/wasm
cargo run -p runtime --release --bin serve -- --two-ships /tmp/two-ships
```

It shows the two ships finding each other by name alone and trading messages,
the second ship reporting that the lookup point introduced the first to it, as
the second asks of its callers; a file on the first ship refused to the second
until the first's owner allows it, then arriving whole, checked by its
SHA-256; the second opening it again with the first ship turned off, from the
copy it kept; the two finding each other again after the first comes back;
and, in an eighth step, the second ship's owner asking the first ship's
counter agent a question over HTTP and being answered (the answer checked
against what the first ship's owner was told the counter stands at, and how
long the question took printed), a question to an interface not open to
questions refused in the second ship's own words with the first ship's reason,
and a command sent with its reply wanted coming back with the reply on its
receipt (checked to be one more than the answer).
Each step says what it is doing, and says no more than it has checked: each
message carries a word for this run and is reported with the number of the
entry it became in the other ship's journal. The three command lines are
printed as they could be typed. Waiting for a program to print something, and
for a message to arrive, gives up after a minute; refusing, allowing and
moving the file give up after a minute and two seconds for each MiB of it;
each says what it waited for. Reading the answer to each HTTP request it
makes (its headers and body, an error's body included) is given at most what
is left of its step's time. Connecting has a fixed limit of its own, so it
can take a step past its time by up to 5 seconds; and each write of a request
is limited by what was left when it connected, the same limit for every write,
set once, so a request that keeps writing slowly can go on past it. Every
request is to one of its own programs on this machine. Ctrl-C is looked at
before and after each request (signing out looks before and not after), while
a file is read, between the pieces of a file, and in every wait. A request
that went wrong with Ctrl-C already in is reported as the stop, since Ctrl-C
stops the ships too and the two cannot be told apart; a step that failed with
no Ctrl-C keeps its words. Then it leaves the three running, prints each
ship's address and access code for a browser, and stops them on Ctrl-C
(`--then-stop` stops them at once instead); stopping a program is a kill and
then a wait for it to end, which has no time limit. A second run on the same
directory reuses the ships. A run takes a lock on its directory, so two runs
never share one. A directory that is not empty and does not hold the
walk-through's marker file is refused; one that holds the marker is taken as
its own, whatever else is in it. Keys come from a list it writes in that
directory (`--pretend-ids`; see Keys from a list, for trying things out), so
it needs no internet and no real ship.

It does not show two machines, a real home router, the relay carrying anything
(nothing on one machine needs it), or real Urbit ID: the three programs talk
over this machine's loopback address. In its seventh step the second ship's
message to the first, which came back, took 6.5 seconds in each of five runs on one
machine (3.3 with `--ports`): the second ship's connection to the first has
gone quiet, its watcher gives it up after three seconds, and a new one is made
(see Finding a ship by its name for what makes that longer).

Its other flags: `--show-output` (what the three programs print, each line
marked with which said it; shown anyway when a step does not work), `--ports
<first>` (six fixed ports counting up from it, so the addresses stay the same
between runs), `--file <file>` (share this file instead of a made-up one),
`--sleep-after <seconds>` (given to the three programs), and `--kernel`,
`--counter` and `--tally` for the modules.

### Other ways to run it

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

Start the copy from a snapshot instead, and read on from its block (see
Starting the copy from a snapshot; nothing is published yet, so the snapshot
here is one you wrote yourself or were handed):

```sh
cargo run -p runtime --release --bin serve -- --ethereum https://gateway.tenderly.co/public/mainnet \
  --azimuth-copy /tmp/azimuth.sqlite --azimuth-snapshot azimuth.snapshot \
  --azimuth-snapshot-sha256 <64 hexadecimal digits> --lookup '~zod'
```

Write a snapshot of a copy (no node needed), or rebuild one at a given block
to check someone else's fingerprint:

```sh
cargo run -p runtime --release --bin serve -- --azimuth-copy /tmp/azimuth.sqlite --azimuth-write-snapshot azimuth.snapshot
cargo run -p runtime --release --bin serve -- --ethereum https://gateway.tenderly.co/public/mainnet \
  --azimuth-copy /tmp/check.sqlite --azimuth-until 26407242 --azimuth-write-snapshot check.snapshot
```

Run a real ship on the network, from its keyfile, with other ships' keys read
from Urbit ID. `--peer` says where another ship is to be found (add
`--azimuth-copy <file>` to read keys from a copy instead of the roller):

```sh
cargo run -p runtime --release --bin serve -- --dir /tmp/ships --keyfile my-planet.key \
  --ethereum https://ethereum.publicnode.com --net 0.0.0.0:4433 --peer '~sampel-palnet=203.0.113.7:4433'
```

Or find other ships by name alone, through lookup points (see Finding a ship by
its name). Nobody runs public lookup points yet, so this is for a network of
your own: one runtime is the point, with a copy of Azimuth to check records
against, and the others are told where it is. Each of the others asks the
point what address it is seen at, and announces that, so it works from a cloud
machine or from behind a home router alike (the point itself needs an address
others can reach):

```sh
cargo run -p runtime --release --bin serve -- --dir /tmp/point --ethereum <node> \
  --azimuth-copy /tmp/azimuth.sqlite --net 0.0.0.0:4433 --lookup-point all
cargo run -p runtime --release --bin serve -- --dir /tmp/ships --keyfile my-planet.key \
  --ethereum <node> --azimuth-copy /tmp/azimuth.sqlite --net 0.0.0.0:4433 \
  --lookup-at 198.51.100.4:4433
```

To state the address yourself instead, add `--announce 203.0.113.7:4433`; and if
that address is a router that lets nothing in unasked, `--behind-router` too.

To try ships out on machines you control, with no internet, `--pretend-ids
<file>` reads every ship's key from a list in a file instead of Urbit ID, in
place of `--ethereum` and `--azimuth-copy` (see Keys from a list, for trying
things out). Whoever can write that file can be any ship, so it is never for a
real network.

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
| `runtime/src/ship.rs` | An awake ship: runs one event as one transaction, calls the kernel, runs handlers in fresh instances, takes commands and log entries from other ships, settles a ship that has fallen out of step, answers other ships' questions and writes down what came of its own |
| `runtime/src/ask.rs` | Questions between ships: what the ship that answers and the ship that asks share, the outcomes, `AskError`, and the rests |
| `runtime/src/host.rs` | The host functions agents import, and the fuel each costs |
| `runtime/src/store.rs` | The SQLite schema and every query; import validation |
| `runtime/src/seal.rs` | Keys: the storage key, the keys derived from it, the recovery key, and sealing and opening an exported copy and its stream of files |
| `runtime/src/files.rs` | Files on the ship: the file id format, uploads and downloads, reading chunks back checked, clearing leftovers, serving a file to another ship and the answers agents gave about it, and the stream of files beside an exported copy |
| `runtime/src/remote.rs` | Fetching a file from another ship for the owner's devices, and checking every part of it against the file's id |
| `runtime/src/kept.rs` | Keeping what was fetched from another ship (the cache), clearing it, and saving a copy as a file of the ship's own |
| `urbit-id/src/` | Urbit ID's keys as Urbit derives them: `wallet.rs` (master ticket to networking keys, UP 8), `argon2.rs` (Urbit's Argon2 variant), `ob.rs` (ship and moon names, tickets), `keyfile.rs` (reading and writing keyfiles), `naive.rs` (Azimuth's state worked out from its logs and layer 2 batches: a port of Urbit's `naive.hoon`) |
| `runtime/src/azimuth.rs` | Reading Urbit ID: a ship's key from the Azimuth contract on Ethereum, or from the roller for a ship on layer 2 |
| `runtime/src/chain.rs` | Reading Ethereum's history over JSON-RPC: logs over a range of blocks, transaction inputs, the finalised block |
| `runtime/src/replica.rs` | A copy of Azimuth in a local SQLite file, kept up to date from Ethereum alone, answering the same lookups as `azimuth.rs` |
| `runtime/src/moon.rs` | A parent's signed word for its moon's key |
| `runtime/src/net.rs` | QUIC transport, the directory of keys and addresses, identity checks against it, carrying commands and log entries between ships |
| `runtime/src/whereabouts.rs` | A ship's signed record of where it is, and the one check of such a record |
| `runtime/src/lookup.rs` | Lookup points: being one, finding the one for a galaxy, asking it where a ship is, and announcing this runtime's ships to it |
| `runtime/src/relay.rs` | The relay: the framing of relayed packets, the socket wrapper (sessions and made-up addresses at a ship, carrying at a point), and the point's sessions and byte allowances |
| `runtime/src/server.rs` | The HTTP server for apps and browsers |
| `runtime/src/pretend.rs` | Ships' keys from a list in a file, in place of Urbit ID, for trying things out |
| `runtime/src/bin/serve.rs` | Command-line wrapper around the HTTP server, with a demo ship; `serve/two_ships.rs` is the two-ship walk-through, and `serve/said.rs` the lines it reads back from the programs it starts |
| `runtime/src/bin/loadtest.rs` | Load test |
| `runtime/tests/runtime.rs` | Integration tests |
| `runtime/tests/files.rs` | Integration tests of files on the ship |
| `runtime/tests/lookup.rs` | Integration tests of finding ships through lookup points |
| `runtime/tests/serve.rs` | Tests of the `serve` program, run as a process of its own |
| `runtime/src/remote_tests.rs` | Tests of fetching a file from another ship, inside the crate so that the ship answering can be made to lie |
| `runtime/src/kept_tests.rs` | Tests of keeping what was fetched and saving a copy, with the same runtimes and liar, and failures made to happen at chosen points |
| `runtime/src/ask_tests.rs` | Tests of questions between ships and of receipts that bring a reply, with two real runtimes, inside the crate so that a network can vanish and the parts that decide can be read |
| `kernel/src/lib.rs` | The default kernel: agent registry and routing policy |
| `proto/ship.proto` | Every message: runtime and kernel, runtime and agent, client and ship, ship and ship |
| `sdk/src/lib.rs` | Guest-side bindings and the `agent!` macro |
| `agents/counter`, `agents/tally` | Toy agents. `counter` keeps counters, publishes a log, and answers questions with its read handler; `tally` reads and sends to `counter`, follows logs, takes receipts, asks questions of other ships and takes their answers |

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
| `files/<ship>/<dir>/<n>.<gen>` | The ship's files: one directory per upload, kept under the same name when the upload becomes a file, and one per file kept from another ship, kept under the same name if it is saved; each named with 16 random bytes in hex that are never used again; in each, copy `gen` (16 random bytes in hex) of chunk `n`, encrypted. Nothing here is named by a hash of what it holds (see Files on the ship) |
| `tmp/` | The runtime's own scratch files, emptied every time it starts. New and imported ships are built here and then hard-linked into `ships/`, so a failure never leaves a half-made ship under its real name. Cleared when a runtime opens the directory, once it holds `runtime.lock` and its storage key has been checked (so a start that is refused removes nothing), and only if `tmp` is itself a directory and not a link to one: the regular files and symbolic links directly inside it are removed (a link as a link, never what it points at; a second name of a ship's file leaves the ship's own), and directories are left. A removal that fails is passed over, and that entry stays until a later start. Nothing an operator names may be kept here, since all of `tmp/` is the runtime's own: `serve` refuses each of its file flags and module paths whose path as written goes through any entry here (each entry of the path placed where it itself lives) or whose whole path leads here, and a path that goes up (`..`) through directories not there yet, whose place cannot be told. So `tmp/keys/ids` is refused when `tmp/keys` links out of `tmp/`: a link directly inside `tmp/` is removed at start, so the file can no longer be read by that name (the file itself, elsewhere, stays). Deeper down (`tmp/a/b -> /safe`) nothing is removed, since start-up leaves directories in `tmp/` and never looks inside them; that is refused only because it is in `tmp/`. Not covered: a path outside `tmp/` whose own links lead through a link inside `tmp/` (`/safe/alias -> <data>/tmp/keys/ids` with `<data>/tmp/keys -> /safe`) is taken; start-up then removes that link in `tmp/` (which only an operator could have put there; the runtime makes no links), nothing else of the operator's is removed, and the file can no longer be read by that name. Names compared as written (an entry's own name, or one not made yet) are compared ignoring case, so `TMP/x` is refused like `tmp/x` on every file system, since on one that ignores case it is the same entry. `export_ship` refuses `tmp/`, anything under it, and such a `..`, before making any directory, and looks again just after making the destination (which narrows, and does not close, the gap in which a part of it could be swapped for a link into `tmp/`) |
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
| `KIND_READ` | `read` | Runs read-only: any write, send, emit, ask, or log change is denied. Also answers questions from other ships (see Questions between ships) |
| `KIND_NOTIFY` | `notify` | A log the agent follows has entries for it. No payload |
| `KIND_CHECKPOINT` | `checkpoint` | The runtime asks for the state behind one of the agent's logs. Read-only, with no send grants |
| `KIND_RECEIPT` | `receipt` | What became of a command the agent sent to another ship. Skipped if the module has no `receipt` export |
| `KIND_FILE_ASK` | `file_ask` | Another ship asks for a file the agent claims. Read-only, with no send grants, a budget of its own, and never queued or kept; see Fetching a file from another ship |
| `KIND_ANSWER` | `answer` | What came of a question the agent put to another ship with `ask_to`. Skipped if the module has no `answer` export (the question is forgotten all the same) |

### Compute, time, and memory limits

These stop a hostile or buggy agent from stalling a ship or the process.

- Fuel. Every event gets `fuel_per_event` units. Each host call costs 5,000
  plus one per byte moved, so a cheap guest loop cannot buy unlimited host
  work. Appending to a log costs 50,000 more, for the signature. A nested read
  is paid from the reader's remaining fuel. Fuel is also checked after the
  handler returns, so straight-line code that overran cannot commit.
- Time. Fuel cannot see how large a bulk memory operation is, so each event
  also has a wall-clock deadline of `max_event_millis`. A watchdog thread
  advances wasmtime's epoch by one each time it has slept 10 ms. The epoch is
  only a prompt to look at the clock, never the measure of time: when a call's
  running code next looks after a tick (`Store::epoch_deadline_callback`), it
  compares the real time with its own deadline, carrying on until the next
  tick if it has time left and stopping, as a call out of time always has, if
  not. Several ticks can pass before running code looks. So a
  watchdog the system wakes late (macOS has been seen stretching a 10 ms sleep
  to 13 ms), or does not run for a while, can make a call stop late, but never
  early, and never by a sum of sleeps.
  A call is never stopped for time before its deadline. After its deadline it
  is stopped at the first point where the running code looks (a loop turn, a
  function entry, a bulk memory step) and finds both that the watchdog has
  ticked since the call was last allowed on and that the deadline has passed.
  The watchdog ticks about every 10 ms; the system can run it, and the call's
  own thread, late; and after a look that came just before the deadline the
  call can run on until a later tick; so no number is promised for the
  overrun. A host call under way is not cut short. Whatever a call returns
  after its deadline is not kept.
  (The deadline is checked again just before commit.) Before compiling, the
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

`Runtime::sleep_when_idle(&runtime, idle)` starts a thread that does this for
`idle` every tenth of `idle` (but no more often than every 10 ms nor less
often than every 30 seconds), so a ship left alone sleeps once it has been
idle for `idle`, at the first look after that: one such wait later at most,
plus however late the thread is scheduled and however long a look takes. It
holds the runtime only weakly, and only while it looks; once every other
holder has let the runtime go, the runtime is closed at the end of the
sleeper's current look, or at its next, and the thread then ends. A ship part
way through an event is never put to sleep. `serve` starts one with
`--sleep-after <seconds>`: 300 by default, and 0 for none, which leaves a ship
open once woken until `max_awake` others push it out. As the code reads,
nothing a served ship does needs it to stay awake: the network holds every
ship's key in memory once it starts, a command from another ship wakes the
ship it is for, and a device waiting on a log waits on a count the runtime
keeps in memory, not on the ship's file. The second run of the walk-through in
`tests/serve.rs` gives the three programs `--sleep-after 1` and every step
still works; how often a ship was in fact put to sleep during it is not seen
from outside, so that shows only that the sleeper breaks nothing there.

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
| `Provide.asked` | Agents on other ships, and other ships' owners, may ask it questions. Apart from `remote` |
| `Use.agent`, `Use.interface` | Something this agent uses |
| `Use.read`, `Use.send` | Whether it reads (or follows a log), sends commands, or both |
| `Use.ask` | With `ship` set: whether it may ask that interface on that ship questions. Apart from `read` and `send` |
| `Use.ship` | Empty for this ship; otherwise a ship name or `*` for any ship |

The default kernel's `route` rules:

- The owner may call any installed agent.
- An agent on this ship may use an interface that the target provides and that
  is public, its own, or declared in its manifest with the matching `read` or
  `send` flag.
- An agent on another ship may send a `KIND_COMMAND` only to an interface
  marked `remote`, and an agent on another ship or another ship's owner may
  put a question (a `KIND_READ`) only to an interface marked `asked`; either
  with `owner` set is refused, as is any other kind from another ship that the
  rules in this list do not let through. The refusal says the interface "is
  not open to other ships", and is passed back to the ship that asked. What
  each ship may then do is up to the agent, which is told the calling ship in
  `Invocation.source`.
- Another ship (not the owner, not an agent here) may put a `KIND_FILE_ASK`
  to any installed agent. As with sharing a log, who may have a file is the
  agent's decision alone, and nothing at install names ships. A kernel from
  before this kind decodes it as `KIND_UNSPECIFIED` and refuses it, which is
  read as no.
- A notification about a local log needs the follower to be allowed to read
  the publisher's interface. One about a log on another ship needs a `Use`
  naming that ship (or `*`), agent, and log with `read` set.
- A checkpoint request must be for one of the agent's own interfaces.
- A `KIND_ANSWER`, like a `KIND_RECEIPT`, goes to any installed agent: the
  runtime only hands on an answer to a question it holds a record of.
- On success, the reply carries the agent's grants: its own and every public
  interface, its declared local uses, and its declared remote uses; and in
  `RouteReply.asks`, the interfaces on other ships it may ask, exactly the
  declared uses with `ask` and a ship. The bound the kernel keeps on its
  answer counts every grant three times (to read, to send, to ask).

Whatever a kernel grants, the runtime also enforces its own name rules, and
never runs anything under the name `kernel`. A ship imported from elsewhere
brings its own kernel, which decides policy for that ship only.

## The agent interface

### Module shape

An agent module exports `memory`, `alloc(len: u32) -> u32`, and
`handle(ptr: u32, len: u32) -> u64`, plus any of `read`, `notify`,
`checkpoint`, `receipt`, `answer`, and `file_ask` with the same signature. The runtime calls `alloc`,
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
| `send_to(req, req_len) -> i64` | The same; for another ship, returns the number the command goes under, which its receipt will carry. With `SendRequest.reply` set, the handler's reply comes back on the receipt (see Commands between ships, exactly once) |
| `ask_to(req, req_len) -> i64` | `AskRequest {ship, agent, interface, payload, within_millis}`. Put a question to an agent on another ship; returns the number its answer will carry. Written down in this event's transaction and put only if it commits; the answer comes as a `KIND_ANSWER` event (see Questions between ships). A change, so refused while reading |
| `ask_drop(number) -> i64` | Give up on one of this agent's questions: `1` if it was waiting or its answer was queued and not yet handed over (that answer is taken off the queue), else `0`. From the moment the event commits no answer for it is handed over |
| `log_append(req, req_len) -> i64` | `AppendRequest`. Add a signed entry to one of this agent's own logs; returns its number |
| `log_follow(req, req_len)` | `FollowRequest`. Follow a log, on this ship or another, from entry 1 |
| `log_unfollow(req, req_len)` | Stop following. No permission needed |
| `log_share(req, req_len)` | `ShareRequest`. Let a named ship, or `*`, follow one of this agent's logs, or stop |
| `log_next(req, req_len, buf, cap) -> i64` | `NextRequest`. Take entries after this agent's position, at most 256 entries or 256 KiB per call |
| `file_info(id, id_len, buf, cap) -> i64` | `FileInfo` of a file this agent claims on this ship, by its 32-byte id, with whether its claim is marked open. `-1` for any other id, whether the ship holds it or not. Read-only, and no grant is needed: it is the agent's own data. No host function reads or writes a file's bytes |
| `file_mark(req, req_len) -> i64` | `FileMark {id, open}`. Mark this agent's own claim on a file open to every ship, or take the mark off. `1` if the agent claims that file, else `0` and nothing changes (not an error). A change, so refused while reading, and kept only if the event commits |

The calls that change something are refused during a read, a checkpoint, a
file question, or a question from another ship.

### SDK

`sdk/` wraps the host functions for Rust agents:

- `kv::get`, `kv::put`, `kv::delete`; `emit`; `invocation`; `read`; `send`;
  `send_to`; `send_to_for_reply`, the same with the reply wanted back.
- `ask::to(ship, agent, interface, payload, within_millis)`, returning the
  question's number, and `ask::drop(number)`; `Answered` and `Outcome` from the
  protocol, and `ask::DEFAULT_WITHIN_MILLIS` (10,000).
- `log::append`, `log::follow`, `log::follow_on(ship, ..)`, `log::unfollow_on`,
  `log::next`, `log::next_on(ship, ..)`, `log::share`, `log::unshare`.
  `next` returns a `Batch` with `entries`, `more`, an optional `checkpoint` to
  replace local state with, and an optional `stopped` reason for a log on
  another ship.
- `Receipt` (with `reply`) and `Verdict`, re-exported from the protocol.
- `files::info(id)`, `files::open(id)`, `files::close(id)`, and `FileRef`,
  `FileInfo`, `FileAsk` and `FileAnswer` from the protocol. A `FileRef` (ship,
  id, length, agent) is plain data an agent keeps in place of a file: the id
  fixes the bytes and the length, and the ship and agent say where to ask.
- `agent!(handle, read = f, notify = f, checkpoint = f, receipt = f,
  answer = f, file_ask = f)` exports `alloc`, `handle`, and whichever roles
  are named. Command, read, and notify handlers are `fn(&[u8]) -> Vec<u8>`; a
  checkpoint handler is `fn(&str) -> Option<Vec<u8>>`; a receipt handler is
  `fn(&Receipt)`; an answer handler is `fn(&ask::Answered)`; a file_ask
  handler is `fn(&FileAsk) -> bool`. A read handler answers other ships'
  questions with nothing new: `invocation()` names the asking ship and agent.

## Storage

Each ship is one SQLite file, and the file is the ship's source of truth. The
schema version is `13`, stored in the `meta` table; a file with any other
version is refused. There is no migration: ship files and exports made before
version 13 (before questions between ships and replies on receipts) do not
open.

| Table | Purpose |
| --- | --- |
| `meta` | Schema version, ship name, kernel module hash, and the ship's incarnation mark |
| `kv` | Agent state, keyed by (agent, key). The kernel's registry lives here under agent `kernel` |
| `outbox` | Messages agents emitted, waiting for whatever embeds the runtime to drain them |
| `inbox` | Queued events: commands between agents, commands from other ships (with that ship's number for them, and whether it wants the reply back), notifications, checkpoint requests, receipts, answers to questions (with the question's number, found by an index of their own) |
| `peers` | Per other ship: last number sent, last number received, bytes waiting, whether it needs to hear where this ship stands, and which round of comparing notes this is |
| `peer_out` | Commands and receipts waiting to go to other ships, numbered per ship, each command with whether it wants its reply back |
| `peer_wait` | Commands sent to other ships that have no receipt yet, and whether each wants its reply |
| `asks` | Questions this ship's agents have put to other ships and that have no answer yet: the asking agent, where it was put, the payload, the time it was given, and when that runs out (milliseconds since 1970). Numbered from `meta.ask_gen` |
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
| `uploads` | Open uploads: directory, agent, length, media type, and when last sent to |
| `files` | Files held: id, directory, length, media type, when added. `meta.file_bytes` is the sum of their lengths |
| `file_claims` | Which agents claim which files, and whether each claim is marked open to every ship (`open`, 0 or 1) |
| `file_chunks` | The copy and hash of each chunk held, for uploads and files alike, by directory and chunk number |
| `file_trash` | What no row names any more and is still to be removed from disk: whole directories and single chunk copies, with the bytes each holds and the allowance it counts against (`pool`: 0 the file allowance, 1 the cache of kept files) |
| `kept` | Files fetched from other ships that the ship keeps: id, directory, length, media type, when last opened (`used`), and the bytes of pieces held (`held`) |
| `kept_chunks` | Every chunk of a kept file, by directory and chunk number: its hash, from the moment the file is kept, and the copy's generation once the piece is held (NULL until then) |
| `saves` | Which agents are saving which kept file, and when each last called (`touched`) |

Files are opened with `trusted_schema = OFF` and, for ordinary work, in
`journal_mode = WAL` (a file still in SQLite's older rollback mode, as a ship
is when it is first published, is switched on that open). A file opened only
for another ship's question is left in the mode it is in: switching writes the
file's header, which a question does not do (see Questions between ships for
what opening a file for a question can do); the switch is made by the first
ordinary work on that ship. With
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
row per ship, and a `meta` table with the last block read and its hash, counts
of what was read, and which chain and contracts the file is a copy of (a file
is never opened as a copy of another). Each step forward, a range of blocks
applied and the new last block with its hash, is one transaction: a crash or a failed question leaves
the file where it was, and the next poll carries on from there. Only one copy
may have the file open at a time: it holds an exclusive lock on
`<file>.lock` for as long as it is open, and a second opener, in the same
program or another (such as `serve --lookup` on the file a running server
uses), is refused at once with a message saying so. Links are followed first,
so the file is locked under one name however it is reached; a file with a
second name of its own (a hard link) is refused; and SQLite opens the file
without following a link, so a link put in its place after its name was
worked out is refused too. A file that is not there is not made while a file
SQLite would take as part of it is there (the same name with `-wal`, `-shm` or
`-journal` added, left by an earlier copy whose file was removed): SQLite would
play its old pages over the new file. The copy refuses, names them, and leaves
them for the operator to remove. A file that is there is handed to SQLite only
if it is a plain file, and only if each of those three that is beside it is a
plain file with one name, SQLite's own: SQLite writes to them even when it only
reads the database, so through a link, a second name of some other file, or
something that is not a plain file, it would write to something else. Anything
else is refused and left alone, when the copy is opened and when a snapshot is
written of it.

Every number in `meta` (the last block read and the six counts) is a whole
number from 0 to 2^63 - 1, kept as an SQLite integer. A count that reaches
2^63 - 1 stays there, so copies that read the same history keep the same
counts however often they are reopened. Anything else under one of those names
(a number below zero, text, bytes, a fraction) is a damaged file, and the copy
is not opened; nothing is clamped or taken to be zero. A count that is missing
is damage too, except in a file that has read nothing yet: copies made before
the counts were written from the start kept none until their first step.

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
goes back, behind one it gave in a poll that succeeded, is not followed (one
given only in a poll that then failed may have been the wrong answer, and is
not held against later ones); one whose final block
is behind what the file has read (a node not yet caught up, or a copy made
from a newer snapshot) is waited for. A ship has a listing if it is in the table; its key follows the same
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
| Block, the final one or one asked for by number | `number` | the number asked for; for the final one, never behind the final block of the last poll that succeeded, and waited for while behind the file |
| Block | `hash` | 32 bytes; asked only of a block at or before the final one heard of in the same poll. Of a range's last block, kept with the file's last block in the same step; of the file's last block, asked at the start of each run, the same as the one kept |
| Block and log | number with hash | in a poll, one chain: the final block, the final block of the last poll that succeeded, the file's last block asked at the start of a run, a range's last block, and the block of every log in that range (so of every batch's transaction) never give one number two hashes or one hash two numbers |
| Log | `address` | the contract asked about |
| Log | `removed` | absent or false (not `null`) |
| Log | `blockNumber` | within the blocks asked; with `logIndex`, strictly increasing; with `blockHash`, one chain with the range's other logs and the poll's block answers (row above) |
| Log | `blockHash` | as above; the same as a batch's transaction's |
| Log | `logIndex` | with `blockNumber`, strictly increasing; never the same as another log's in a range |
| Log | `transactionHash` | in one block in a range; its logs together in its block; for a batch, the transaction asked for |
| Log | `transactionIndex` | in a block, one per transaction and one transaction per index, never going down as `logIndex` goes up; for a batch, the same as its transaction's |
| Log | `topics` | one to four, 32 bytes each; the first a kind asked for; as many as its event has, each no wider than its type |
| Log | `data` | at most 16 KiB; as long as its event's, each word no wider than its type |
| Transaction | `hash` | the hash asked for |
| Transaction | `blockNumber`, `blockHash`, `transactionIndex` | those of its batch's log |
| Transaction | `input` | at most the limit for one input; the same in every answer for one transaction at one place |

Not read: a block's parent and transactions; a log's `blockTimestamp`; a
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
| The answer about a block | 16 MiB | | Every transaction's hash, 69 bytes each, at 21,000 gas a transaction: blocks of over five billion gas |
| Several transactions asked for in one request | 20, and 8 MiB of answer | | Past either, they are asked for one at a time |
| Time for one question | 30 s | ten times that, for one block's logs or one transaction | Longer answers |

Measured in November 2026: `ethereum.publicnode.com` refuses old ranges
("Archive requests require a personal token"); `gateway.tenderly.co/public/mainnet`
takes 100,000 blocks to a question and several questions to a request, and
answers HTTP 429 when asked too often; flashbots takes 2,000 blocks,
Cloudflare 800; drpc's free plan refuses. A full read of the main network
through Tenderly is described under Tests.

### Starting the copy from a snapshot

A copy read from nothing reads all of Azimuth's history, which needs a node
that answers questions about wide ranges of old blocks: Tenderly's public node
takes 100,000 blocks to a question, but many free plans take ten, which would
mean millions of questions. A copy can instead start from a snapshot, a flat
file of the table at some block, and read only what came after it, which any
node can answer. The idea is taken from latter-bolden/azimuth-resolver, whose
bundled snapshot matched this copy's table on every point not changed since
its block; none of its code is used.

**The block's hash.** Beside the number of the block it has read to, the copy
keeps that block's hash, written in the same step as the number. The hash is
the node's answer for a block it has said is final: the final block itself
when a step ends there, or the block asked for by number otherwise (one more
question for each step). Within a poll, every block number and hash the node
gives (the final block, the final block of the last poll that succeeded, the
block asked for at the start of the run, each range's last block, and the
block of every log in the range) must be one chain: no number with two hashes,
no hash of two numbers. Only a poll that succeeded is remembered for the next,
so a wrong answer in one that failed never holds back a right one. At the start
of every run, before anything is applied and before any lookup is answered, the
copy asks the node for the hash of the block it has read to. If it differs from the one kept, the node follows
another chain or the file is wrong: nothing is read, written or answered, the
trouble says so (and says that a copy made from a snapshot can be removed,
with any file of the same name with `-wal`, `-shm` or `-journal` added, to try
another), and every later poll asks again, so the copy carries on once the
node answers as before. A node that cannot answer is ordinary trouble, tried
again. A file made before the hash was kept has none; it is used as before,
learns the hash the next time it moves forward, and is checked from the next
run on. A copy made from a snapshot always has one.

**Writing a snapshot.** `serve --azimuth-copy <file> --azimuth-write-snapshot
<out>` writes a snapshot of the copy as it is and stops; no node is asked
anything. Snapshots are written and restored only on macOS and Linux (see
Known limits); elsewhere `serve` refuses either snapshot flag before the copy
is opened or anything is made. Everything is read in one read transaction, so
the points, the block, its hash and the counts belong together, even while a running server
moves the copy on. A copy with no hash kept is refused: a snapshot nobody can
place on the chain is not made, as is one with a change a crash left unfinished
beside it (a hot `-journal`), which the writer, reading only, cannot undo: it
says to open the copy once first, which undoes that change unless the file is
damaged as well. The copy, and each file beside it, must be a plain file with
one name, as when a copy is opened. A write-ahead log not yet written back is
read as part of the copy. The file is described at the top of
`runtime/src/replica/snapshot.rs`: a 176-byte header (a magic, the format, the
version of the rules, the chain and both contracts with their first blocks,
the block and its hash, the six counts, the number of points), then one
211-byte record per point in ascending order of ship, every number written
most significant byte first, a yes or no as 0 or 1, and a field with nothing
in it as zeros. There is one way to write a given table, so the same table at
the same block, by the same rules, gives the same bytes however it was
reached; about 30 MB for the main network today. Its fingerprint is the
SHA-256 of the whole file. The writer prints the block, its hash, the number
of points, the size and the fingerprint, and writes the same lines to
`<out>.txt`. It never replaces a file and never follows a link at either name:
each is written under a name of its own beside it, put on disk, and given its
name only if that name is still free.

The version of the rules (`RULES` in `snapshot.rs`) is raised whenever
`naive.rs` or the way the copy reads and applies the history changes what a
given history gives, so that a snapshot worked out by other rules is never
taken.

**Starting from one.** `serve --azimuth-copy <file> --azimuth-snapshot
<snapshot> [--azimuth-snapshot-sha256 <hex>]` makes the copy from the snapshot
if there is no copy yet, then reads on as usual. What is at the copy's name
decides what happens, and is looked at before anything is written:

- Nothing: the copy is made from the snapshot, as below, unless something
  SQLite would take as part of a new copy (the same name with `-wal`, `-shm`
  or `-journal` added) is there, which is refused and left for the operator
  to remove.
- A copy: it is opened as it is, the snapshot is not read, and a line says so.
- Something that is not a copy (an empty file, a file whose first start was
  cut short, another database, a file that is not a database): refused, with a
  message saying to remove it, and any `-wal`, `-shm` or `-journal` beside it,
  for the snapshot to be used, and, where an ordinary start could make a copy
  of it, that starting once without `--azimuth-snapshot` finishes it as a copy
  read from the beginning. Without a snapshot asked for, an empty file or one
  whose first start was cut short is set up that way, as before.
- Something that cannot be read to tell: refused with SQLite's own error, never
  taken for "not a copy". The message says that an ordinary start will finish
  it if the trouble is a change a crash left unfinished, and that otherwise the
  file is damaged and must be removed, with what is beside it.
- Something that is not a plain file with one name (once a symbolic link to it
  has been followed, which is done on purpose), or a file beside it that is a
  link, a second name or not a plain file: refused, as when any copy is opened.

What is there is left as it is, with one exception: a database with a change a
crash left unfinished beside it (a hot `-journal`) cannot be read by a
connection that may only read, so a file that begins as every SQLite database
does is then opened once to write, without the right to make a file, so that
SQLite undoes that change as any opening would, and is looked at again. If it
then turns out not to be a copy, or still cannot be read, the message says so,
and says that SQLite undid that change and nothing else was changed. If the
change could not be undone (the file may not be written to, say), the message
says that, with the error, and that nothing was changed; it claims neither that
the change was undone nor that the file is damaged. A file that is not an
SQLite database is never handed to a connection that may write.

The snapshot is read as hostile: its length must be exactly what its header's
count of points says before any point is believed; it is read through a buffer
of fixed size, so memory does not depend on what it claims; every point must be
in the one form allowed (ships strictly ascending, each yes or no 0 or 1, an
absent escape all zeros, a place one of the three), which also keeps to every
check of the `points` table; and it must have been made for the same chain and
contracts, by the same version of the rules, with the fingerprint given, if one
is. Anything else refuses it, and no copy is made.

The copy is made by the same code as any copy (the same schema, the same lock,
the same refusal of links), with every point, the block, its hash and the
counts in one transaction, under a name of its own beside the copy's, with
nothing of SQLite's beside that name. It is then put in the copy's usual
journal (write-ahead) and closed; nothing of SQLite's may be left beside it; it
is put on disk; and only then is it given the copy's name, only if that name is
still free. So once named it is whole on its own, and opening it changes
nothing. What a crash at each point leaves is listed at the top of
`snapshot.rs`: at every point the next start finds no copy and makes it again,
or finds a whole one, never a part of one, and never an empty copy that would
quietly read from the beginning. (A crash part way can leave the file under its
own name, ending in `.part`, beside the copy; it is never taken for the copy.)

Once named, the copy is opened without the right to make a file, and read back
before anything is written to it: its tables, its journal, what it is a copy
of, its block, the block's hash, its counts and its number of points must be
what was made, or it is not used; an error reading it back is said as an error.
Then the copy reads on, starting with the check of the block's hash. Lookups
stay refused until that check has passed and the copy has reached the final
block heard of in this run. A snapshot newer than what the node has finalised
waits. If the node disagrees about the snapshot's block, the copy stays refused
and says to remove the file, and any `-wal`, `-shm` or `-journal` beside it, to
try another snapshot; it does not remove them itself.

**Stopping at a block.** `--azimuth-until <block>` reads the copy to that block
and no further (once it is final; until then it reads as far as is final and
waits), then stops, writing a snapshot there first with
`--azimuth-write-snapshot`. A copy that is already at that block when it is
opened is taken as there only once this run's check of its block hash has
passed. That is how a second party rebuilds a publisher's snapshot to compare
fingerprints. A copy told to stop never counts as caught
up and answers no lookups, so it cannot go with `--lookup` or `--net`.

What a snapshot does and does not prove:

- The fingerprint shows the file is the one somebody named. It does not show
  that it is right.
- The check of the block's hash shows that the snapshot's block is on the
  chain the node follows.
- Whether the table is what Azimuth's history gives is the publisher's word,
  until a second party reads to the same block (`--azimuth-until`) and gets the
  same fingerprint. Then it is two parties' word, and anyone with a node that
  answers wide ranges can make it their own.
- A wrong snapshot could list a wrong key for a ship that does not change
  afterwards. Reading on does not repair that. This is the risk taken by
  whoever starts from someone else's snapshot, and why the fingerprint should
  come from somewhere other than the place the file came from.

Not in this increment: fetching a snapshot from an address; compression (the
fingerprint is of the plain bytes, so a snapshot can be compressed to carry
it and nothing else changes); keeping the raw events and batch inputs beside
the table so that it can be rebuilt without a node; checking a sample of the
table against the layer 1 contract; and publishing a snapshot anywhere.

### Keys from a list, for trying things out

`runtime/src/pretend.rs` (`PretendIds`, `serve --pretend-ids <file>`) answers
the same question as `azimuth.rs`, from a list kept in a file: one ship to a
line, `~name` and then the 64 hexadecimal digits of its public key, as
`Runtime::public_key` and `GET /ships/<ship>/key` give it. Blank lines, and
lines whose first character that is not a space is `#`, are skipped. Each ship
is listed at revision 1, continuity 0, with no sponsor (nothing reads a
sponsor but `serve --lookup`, which prints it). Galaxies, stars and planets
only: a moon's key is its parent's to give, as everywhere else.

- The list is checked whole when it is opened: a line that is not of that
  shape, a name that is not a galaxy, star or planet, a ship listed twice, or
  one key under two ships stops the start, naming the line. It is read only as
  a regular file (a link to one is followed, as for any file an operator
  names), never a pipe or a device, of at most 1 MiB, and as UTF-8 text.
- It is read again at every question, so a ship added to it is found without
  restarting anything. What asks decides how often: a runtime's directory
  reads a ship's key again once what it holds is five minutes old, when the
  key is next wanted (a call, a caller), and goes on using the old answer
  while the new one is read; a lookup point asks for every record it checks. A
  ship not on the list is answered as listed at revision 1 with no key, not as
  no ship at all: a directory never takes an answer of an earlier revision
  than one it holds, and "no such ship" counts as revision 0. So taking a ship
  off the list, or changing its key, is used at a runtime from the next
  reading of that ship there after what it holds is five minutes old (a ship
  never listed has nothing kept for it, and `serve --lookup` shows it as "key
  none"). A list that can no longer be read, or no longer parses, is an error
  that says why, never an earlier answer.
- `serve` takes it in place of `--ethereum` for `--net` and `--lookup`, and in
  place of `--azimuth-copy` for `--lookup-point` (a point wants a copy so that
  it answers from a local file, and this is one). It cannot go with
  `--ethereum`, `--roller` or any `--azimuth-` flag. At start `serve` says
  that keys come from the list and not from Urbit ID, that whoever can write
  the file can be any ship, and that this is for trying things out on machines
  you control; its line about the network says the list, never "with keys from
  Urbit ID".
- Whoever can write the file can be any ship to every runtime that reads it.
  That is what it is for, and why it is only for trying things out. A runtime
  started without it is not changed, and there is no other way round Urbit ID.

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

A copy is 95 bytes larger than the plain contents of the ship's file it holds
(`seal::EXPORT_OVERHEAD`: the label, the key made for the copy, the ship's
signing key and the tag). Those contents are the file's rows written afresh by
SQLite into a plain database: a whole number of 4,096-byte pages, with no free
pages and no room set aside on any page for encryption. The default
`max_import_bytes` is the default `max_ship_bytes` and a margin that
measurements support but do not prove (see the `Config` table).

Because the copy is sealed to a public key, it can be made with nobody
present, for example by a host on a schedule, and the host cannot read what it
made. The seal keeps a copy secret. It does not prove who made it: anyone who
knows a ship's recovery public key can seal something to it. That is why
import still checks everything.

`import_ship(src, ship, code)` opens the copy with the recovery code (the one
`import_ship_with_ticket` derives from the master ticket) and then
treats what is inside as untrusted:

- It reads only regular files, without following symlinks, up to
  `max_import_bytes`, and gives up once `max_import_millis` has passed: the
  clock is looked at between steps (before each row is copied, before the
  packing of the new file, and from inside the packing statement every
  thousand of SQLite's steps, which stops it there). So one step that blocks,
  such as reading or opening the copy, can take it past that; one of SQLite's
  steps can copy a whole row, so with very large rows a great deal can be
  copied between two of its looks (how much was not measured); two parts of
  packing cannot be stopped at all (SQLite's copy of the packed database back
  over the file, which runs no steps, and the file's sync after it); and the
  stream of files beside the copy is not under it (see Files and export). The
  copy is opened and read in memory: about twice its size for a moment, so
  about 2 GiB for a ship at the default `max_ship_bytes` of 1 GiB, and at most
  about twice `max_import_bytes`. A copy that has been changed in any way, is
  for another ship, or was sealed to another code is refused before any of it
  is read as a database.
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
- The fresh file is built with room to spare (up to twice `max_ship_bytes`):
  rows put in one at a time, in key order, can pack SQLite's pages less
  tightly than the file they came from (a ship's small kv rows, put in in key
  order, took 926 pages where its original had them in 894). Audit rows are
  put in oldest first, since newest first left each of their pages about half
  full (187 pages where the original had 97); with `audit_rows` 0 none is read
  at all. Then the file is packed as tightly as SQLite packs anything
  (`VACUUM`, with nothing journalled, since the file is nobody's yet; the
  packed copy is built in memory, about the packed size), every time, not only
  when it is over. In each of the five ways of filling a ship tried (see
  Tests), the packed file had no more pages than the original; that is
  measured for those five, not claimed for every file. Only then is it held to
  `max_ship_bytes`. A ship still larger than that, measured once packed, is
  refused as `Error::ShipTooLarge`, which names that size and the limit. A
  ship whose file does not fit even in the room it is built with is refused as
  `Error::NotBuilt`, which says only that: it did not fit in that room (it
  names it), so either it is far too large for this runtime or the disk is
  full (SQLite reports the two alike), and it claims no size for a finished
  file. `NotBuilt` covers SQLite reporting the file full while rows are copied
  in; running out of disk at another moment (making the scratch file, or the
  copy back after packing) comes through as the operating system's or
  SQLite's own error. A runtime with a larger `max_ship_bytes` helps only when
  the ship was too large; a full disk needs room on the disk. On a
  failure before the ship is put in place, no ship, key or files directory is
  left, and removing the scratch file is attempted (a removal that fails is
  passed over, as for any scratch file); a failure while it is put in place
  (its key written and the link failing, or the directory's sync failing after
  the link) can leave what that has always left. Disk taken at the same time:
  the file as built, up to twice `max_ship_bytes`; SQLite's rollback journal
  while the rows are copied; the files brought in beside it; and any module
  stored. There is no HTTP route for import; it is a runtime call.
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

## Files on the ship

A ship's own file holds nothing larger than 1 MiB. Files of any size are kept
beside it, in `files/<ship>/`, and the ship's file holds the truth about them:
which files there are, which agents claim each, and the hash of every chunk.
The owner's signed-in devices put files in and take them out over HTTP, under
an agent. An agent keeps only a reference (`FileRef`: ship, id, length,
agent) and never loads a file; no host function reads or writes file bytes.
Another ship's owner can fetch a file through their own ship, which checks it
chunk by chunk against its id in chunks of at most 1 MiB (see Fetching a
file from another ship). What is fetched is kept for a while, and a copy can
be saved for good (see Keeping what was opened, and saving a copy).

### The file id (format 1)

- A file of `length` bytes is cut into chunks of `CHUNK = 1 MiB`: every chunk
  is exactly 1 MiB but the last, which holds the rest (1 byte to 1 MiB). An
  empty file has no chunks.
- `leaf(i) = SHA-256("ship.v1.chunk\n" || chunk i)`.
- `FANOUT = 32768`. While the list of hashes has more than one, each run of up
  to 32,768 is replaced by `SHA-256("ship.v1.index\n" || the hashes in it)`.
  The one left is the root. One chunk's root is its own leaf; no chunks' root
  is `SHA-256("ship.v1.chunk\n")`.
- `id = SHA-256("ship.v1.stored\n" || length as 8 bytes, low byte first ||
  root)`, written as 64 lower-case hex digits in addresses.

`runtime::files` has `leaf`, `root`, `file_id`, and `id_of(contents)` for
clients. Its tests hold numbers worked out apart from this code, for 0 bytes,
1 byte, exactly 1 MiB, 1 MiB and a byte, and 32,769 made-up hashes, which take
two rounds to come down to one.

### On disk

Each upload gets a directory named with 16 random bytes in hex, made when the
upload starts and never used again; when the upload becomes a file it keeps
that directory. Each copy of chunk `n` is the file `<dir>/<n>.<gen>`, where
`gen` is 16 more random bytes chosen when that copy is written, and recorded in
the chunk's row: sending a chunk again writes a new copy beside the old one,
never over it. The one exception is an import, which writes each chunk once
into a fresh directory and gives every copy the same all-zero `gen`. A copy is a random 12-byte nonce, then the chunk sealed with
ChaCha20-Poly1305 under a key derived from the storage key with the label
`ship.v1.files\n`, the ship's name, and the directory, with the ship's name,
the directory, `n` and `gen` bound in as associated data. A chunk copied to
another number, copy, directory, or ship does not open. Nothing on disk is
named by a hash, and no content, media type, or hash appears unencrypted.

The ship's file and the directory are two stores, and either can move without
the other (a crash, a failed sync, a failed commit, a power cut). One rule,
stated at the top of `files.rs`, keeps them in step:

- Bytes are written and durable before any row names them: a chunk copy is
  written and synced, and the directory it is in synced, before the
  transaction that names it; a directory is made and the directory it is in
  synced before the row that names it.
- Bytes are removed only after the transaction that stopped naming them is
  durable. Every transaction that stops naming bytes or records something to
  remove (a chunk's commit, finish, abandon, expiry, delete) is committed with
  the log synced, whatever `durability` says (under `Durability::Normal` the
  connection switches to `synchronous = FULL` and `fullfsync` for that one
  commit, so the commit record is on disk when it returns; in WAL mode that is
  what makes a commit survive a power cut). The same transaction records what it
  stopped naming in `file_trash`. Making an upload is not synced: losing that
  commit loses only a directory no row names, which the first ordinary use tries
  to remove.
- A name on disk is never used for other bytes: directories and chunk copies
  are named with random bytes when they are made, and nothing is written over.
- After a failure, only what can be shown never to be named, and never to come
  to be named, is removed. A chunk upload refused or failing before its commit
  is tried removes its own copy, which its own exclusive create made (a
  generation already taken is an error that touches nothing). If the commit
  itself reports an error, nothing is removed: SQLite may have written the
  commit to its log before the error, and a crash would then bring it back,
  naming the new copy. The leftover goes when the upload finishes, after a
  synced commit has settled what is named, or with its directory. The same
  holds for a new upload's directory.
- If anything unwinds while the ship is held, the ship's connection is closed
  before anything else can use it (`with_ship`), which rolls back whatever
  transaction was open: nothing reads, or acts on, rows never committed.
- Anything no row names is rubbish that a later step is sure to try again. What
  is in `file_trash` is removed after every operation that puts something there
  (a chunk's commit, finish, abandon, an upload start that expires others,
  delete), at the start of upload start, finish and delete, and at the next
  ordinary use of the ship after it first wakes in the life of a runtime, 16
  things at a time: a wake for a question (one from another ship, or the asking
  ship's own task reading its question's row or writing what came of it) leaves
  it owed (see Who looks, and when, under Questions between ships). An entry is
  struck off only after its removal is durable: the directory it was in is
  synced first. A whole directory durably removed takes with it every record of
  what was in it. Until then its bytes count against the allowance.
- One mechanism covers chunk copies no row names in a file's directory (left
  by a chunk upload whose commit failed, or that could not remove its own
  copy). A copy's name is made under the ship's slot, and only while its
  upload is open, so no name can appear in a directory after its upload
  finishes. Finish records, in its own synced commit, that the directory is to
  be swept; the drain sweeps it, and strikes the record off only after the
  whole directory was listed without error, every copy no row names was
  removed, and the directory was synced. A crash or a failure at any point
  leaves the record, and the next drain tries again. A sweep of a directory
  no row owns any more (its file deleted) is struck off as done, since the
  directory itself is to go, unless the whole directory is recorded to go and
  has not yet: then the sweep stays, with what it is counted at, until that
  removal works, which strikes off every record of the directory. (An
  upload's sweep is counted at nothing, so for it this changes only when the
  record goes.) An upload given up or
  expired takes its directory with it. Copies swept this way are of unknown
  size and are not counted against the allowance; they arise only from failed
  disk operations, at most one chunk per failed operation. A directory no row
  names is looked for on the first ordinary use, and the ship is looked through
  again at its next wake unless every such removal worked. An entry a row names is
  kept on its name alone, whatever else is odd about it; for any other entry,
  an error reading the listing or the entry's type makes that look remove
  nothing, and the ship is looked at again at its next wake. An entry no row
  names, a name that does not parse included, is rubbish and is removed. No
  error or failed lookup is ever taken as leave to remove something a row
  names or a ship already here owns: an import that cannot tell whether a ship
  of its name exists stops, rather than clear that name's files.

Every chunk read is checked twice before any of it is served: it must open
under its key for its place, and what opens must hash to the leaf the ship's
file holds for it. Damaged or missing bytes are an error to the client
(HTTP 500), never wrong bytes.

### How a file gets in and out

All routes are under the ship and an agent, need a signed-in device as every
other route does, and the agent must be installed (the kernel must route an
owner's command to it). Messages are in `proto/ship.proto`.

| Method and path | Answer |
| --- | --- |
| `POST /agents/<a>/files/uploads` | `UploadRequest {length, media_type}` gets `UploadReply {upload, chunks}`. Expired uploads are swept first; the whole length is reserved |
| `PUT /agents/<a>/files/uploads/<upload>/<n>` | The chunk as the body, exactly the size chunk `n` must be. Any order; sending `n` again replaces it until the upload is finished. 204 |
| `GET /agents/<a>/files/uploads/<upload>?from=` | `UploadState`: the chunks held, as runs (first, count), at most 16,384 chunk numbers per answer, with `next` to carry on |
| `POST /agents/<a>/files/uploads/<upload>/finish` | Optional `FinishRequest {id}`. Every chunk must be held (409). The id is worked out from the hashes held, without reading the bytes again; a stated id that differs is refused (422). Gets `FileInfo` |
| `DELETE /agents/<a>/files/uploads/<upload>` | Gives the upload up, and its reservation. 204 |
| `GET /agents/<a>/files?after=&max=` | `FileList` of the agent's files in order of id, at most 256 (100 by default) per page |
| `GET /agents/<a>/files/<id>` | `FileInfo {id, length, chunks, media_type, added_ms}` |
| `GET /agents/<a>/files/<id>/chunks/<n>` | One chunk |
| `GET /agents/<a>/files/<id>/content` | The whole file, sent a chunk at a time with `Content-Length`. One `Range: bytes=a-b`, `a-` or `-n` gets 206 with `Content-Range`; one that is not in the file gets 416 with `Content-Range: bytes */<length>`; anything else in `Range` gets the whole file |
| `DELETE /agents/<a>/files/<id>` | Takes back the agent's claim. When no claim is left, the file's rows go in that transaction, and its directory once that is durable. 204 |

An agent sees only files it claims: an id it does not claim answers exactly as
an id nobody holds (404). Upload names and ids must be exact lower-case hex,
and become paths only as the ship's own directory names, never as given. When
an upload finishes with an id the ship already holds, the agent's claim is
added to that file and the upload's bytes go with its reservation: a ship
keeps identical files once.

Every file answer carries `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox; default-src 'none'`. Contents carry the
stored media type and `Content-Disposition: attachment`, or `inline` for a
fixed list of pictures, sound, and video (PNG, JPEG, GIF, WebP, AVIF; MPEG,
Ogg, WAV, WebM, AAC, FLAC and MP4 audio; MP4, WebM and Ogg video). Nothing
scriptable is shown inline: no SVG, HTML, or PDF. A single chunk is always
`application/octet-stream` and an attachment. A media type is checked at
upload: `type/subtype` of plain lower-case words, no parameters, at most 127
bytes; none given is `application/octet-stream`.

`Runtime` has the same operations for code that embeds it: `upload_start`,
`upload_chunk` (or `prepare_chunk` then `PreparedChunk::commit`),
`upload_state`, `upload_finish`, `upload_abandon`, `files`, `file_info`,
`file_chunk`, `file_delete`, `file_bytes` (held, reserved), and
`files_to_remove` (bytes and things no row names yet still on disk).

### What holds, and how

HARD means decided under the ship's slot and in its transaction, so true
however requests interleave. BEST EFFORT means decided by reading again
elsewhere.

- HARD. Held, reserved, and still-to-be-removed bytes together never pass
  `max_file_bytes` (10 GiB; 0 turns the store off) because of a new upload,
  and never pass it by more than one chunk (1 MiB) at all, but for what part 3
  adds (see What holds, and how, under Keeping what was opened: pieces given
  up from files being saved, and up to 2 MiB counted for a file made from a
  kept file until its sweep works). An upload reserves
  its whole length when it starts, and only if all three together leave room.
  Finishing moves that from reserved to held, or to be removed when the file
  was already held; abandoning, expiry, and deletion move bytes to be removed;
  removal takes them off. The one thing that adds is sending a chunk again:
  the copy it replaces is to be removed, and a replacement is refused while
  the three together are already over the allowance, so concurrent
  replacements, taken one at a time under the slot, pass it by one chunk at
  most. Whether a file could ever fit is decided first, by a rule that does not
  look at how full the ship is (longer than `max_file_bytes`, or rows needing
  more than a quarter of `max_ship_bytes` at 128 bytes a chunk plus 1 KiB):
  that is 413, and only then is "no room now" (507) considered.
- HARD. A chunk's row names its bytes, and only bytes already durable. The
  chunk is hashed and encrypted outside the slot; then, under the slot, if the
  upload is still open, its copy's name `<n>.<gen>` is made by an exclusive
  create (the one file operation done while the ship is held for a chunk);
  the bytes are written and synced outside the slot. Then, under the slot and in
  one synced transaction, the upload must still be there (looked up by its
  directory, a value never used again, so an upload given up and another
  started in between is never mistaken for it), and the row is made to name the
  new copy, recording the copy it replaces to be removed. If it is refused or
  fails before its commit is tried, that copy, and only that copy, is removed;
  if the commit itself fails, nothing is removed (see above). No failure can
  touch bytes another upload of the same chunk put there, whatever the order.
- HARD. At most `max_uploads` (16) uploads open per ship, and at most
  `max_files` (100,000) files.
- HARD. Nothing about files takes the room a ship keeps in its own file to go
  on working: every write is kept only if it leaves `room_to_take_one` free or
  used no new room, the rule already kept for what is written on other ships'
  behalf. Starting an upload also needs room for all its rows then (BEST
  EFFORT: the room may be used by other things meanwhile, and each chunk's row
  is checked again).
- BEST EFFORT. The agent being installed is asked of the kernel at the start
  of each request. Nothing uninstalls an agent, so there is nothing to race.
- BEST EFFORT. A download looks the file up again for each batch of 4,096
  chunks, by its id and its directory, and stops if the claim has gone. An
  export looks each file up again the same way, and marks it given up if it
  has gone.

Bounds, with their working:

- Disk. Held, reserved, and to-be-removed bytes are within `max_file_bytes`
  plus one chunk (with part 3's additions, under Keeping what was opened).
  Beyond them: 28 bytes per chunk copy (280 KiB for 10 GiB);
  one new chunk copy (1 MiB and 28 bytes) per chunk upload in progress, and
  over HTTP each one holds a worker, so at most `workers` (16) per server,
  about 16 MiB; and, after a crash or a failure that could not clean up after
  itself, at most one copy no row names per chunk upload that was in progress,
  until its upload finishes or its directory goes, and directories made for
  uploads whose rows never committed, until cleanup succeeds on an ordinary use
  of the ship.
- Memory per request is about one chunk, never a file: a chunk upload is read
  whole (a `PUT` carries at most one chunk, 1 MiB, whatever `max_body_bytes`
  says, and is refused before it is read if it says it is longer) and sealed
  where it lies; a chunk read is opened where it lies; a download holds one
  chunk and at most 4,096 hashes with their copies' generations (192 KiB);
  import and export hold one 64 KiB segment and one chunk of file content.
  Finishing holds the names of the file's chunk copies as a set of strings:
  about 40 bytes of text a chunk, and with each string's and the set's own
  overhead roughly 100 bytes a chunk (about 1 MiB for 10 GiB); an estimate, not
  measured.
- Per-file bookkeeping, apart from content. Import keeps about 160 bytes per
  file while it checks the ship's file (a small record and two maps, by id and
  by directory; the root over a file's hashes is worked out one file at a
  time), then, only if a stream is given and opens, about 100 bytes per file
  while it reads it, and the list of kept files: about 25 MB at the default
  `max_files` of 100,000, in the worst case of 100,000 small files. An export
  lists its files, 56 bytes each (5.6 MB at 100,000). These are estimates of the
  data held, not measured allocations.
- Downloads of contents are limited apart from the long polls, and neither
  may take the threads kept for everything else. Of `workers` threads (at
  least 2), half may wait for logs; of the other half, a quarter of all the
  threads (at least one) are never taken by downloads, whatever
  `max_downloads` says. With 16 workers: 8 may wait, 4 may download (the
  default), and 4 are always left; with 4: 2, 1, and 1; with 2: 1, none, and 1,
  and a file's contents are refused (503) while its chunks can still be
  fetched one at a time. Requests for files on other ships take the same
  download places, whichever route (see Fetching a file from another ship). Past the limit, 503 with `Retry-After: 1`. A client
  gets `io_timeout` (10 s) to take each chunk, not the whole file: a stalled
  reader is cut off after 10 s; one that keeps taking a little holds its worker
  for at most 10 s a chunk.
- Rows per file: one per chunk (10,240 for 10 GiB), one for the file, one per
  claim, and one per copy waiting to be removed.
- How long a call holds the ship, for a 10 GiB file (10,240 chunks), on a Mac
  laptop in an unoptimised build, with every commit synced (the default
  durability): finishing took 38 ms in all and deleting 31 ms, each including
  its kernel check and, for deleting, removing the empty directory afterwards.
  The rows were written beside the runtime and there were no bytes on disk, so
  this shows finishing reads no bytes and that the hold for 10,240 rows is tens
  of milliseconds; it does not show the cost of listing and removing a full
  directory (done outside the hold), a release build, or another machine.

### Files and export

`export_ship` writes, beside `<ship>.ship`, `<ship>.files`: the ship's files,
read from disk outside the slot and checked as they are read, as a stream
sealed to the same recovery key. It is `ship.v1.files\n`, a public key made for
that stream, and then segments of 64 KiB each sealed with ChaCha20-Poly1305
under a key agreed with the recovery key and bound to the hash of the sealed
copy beside it. A segment's nonce is its number and whether it is the last, so
a stream cut short, reordered, with a segment dropped or repeated, or made for
another copy does not open past that point. Inside, each file is its id and
length and then its chunks; a file deleted while the stream was written is
marked given up. The bytes of open uploads are not exported; their rows are
in the copy of the ship's file, as everything in it is, and an import leaves
them out. A ship with no files gets no stream, and one left in the directory
from an earlier export is removed. The stream is written before the copy, and
the copy last, so a failure leaves at worst an older copy with a newer stream,
which no longer matches it. One export of a ship runs at a time (a lock of its
own, not the ship's slot, which is let go while files are read), so two
exports into one place always leave a copy and a stream from the same export.

`import_ship_counted` (and `import_ship`, which drops the count) looks first
for `<ship>.files` beside the copy. Without it, no file can arrive: the ship
comes in with none, its files are counted as dropped, and no limit on files
(nor a runtime that keeps none) can refuse it. With it, the ship's file comes
in with every file row checked against every other: each file's chunks are
all there once, in order, as many as its length takes, and its id is the id of
its length and their hashes; every claim is by a valid agent name on a file
that is there, with an open mark of exactly 0 or 1, which comes in as it was;
every file is claimed; media types are valid; and the files fit
`max_file_bytes` and `max_files`, or the import is refused (the runtime does
not choose which of the owner's files to lose). Each file is given a new
directory, so nothing in a copy becomes a path; upload rows and their chunks,
and what was waiting to be removed, are not brought in. Then, if the stream
opens with the code beside this copy, each file in it is checked chunk by
chunk against the hashes now in the new ship's file and stored under this
runtime's key. A file is kept only if every chunk arrived and matched; reading
stops at the first thing that is not as it should be, and what was kept by
then stays. Every other file is struck off with its claims, and the count of
kept and dropped files is returned. A copy without its stream is therefore
still a copy, of the ship without its files.

What a hostile stream can do is bounded: it can only name files the new
ship's file lists, once each, at the length listed there, so what is read is
bounded by those lengths, already held to `max_file_bytes`, and content in
memory by a segment and a chunk. The files take as long as their bytes take to
read; they are not under `max_import_millis`. The ship's appearance under
`ships/` is still the moment an import is done. Its files are written to
`files/<ship>/`, and every directory made there synced into the one above,
before that; a `files/<ship>/` with no ship is left from an import that did
not finish, and the next import of that name clears it first. From the hard
link on the files are the ship's: an error after it (making `ships/` durable,
say) is reported and removes nothing. Making or importing a ship takes its name
for the duration, so two imports of one name run one after the other. An
import reading a directory that something outside this runtime is exporting
into at the same moment can find a copy and a stream from different exports;
the stream then does not open beside the copy, and the ship comes in without
its files, which the count says.


### Fetching a file from another ship

The owner of ship B opens a file that lives on ship A. B's device asks B over
HTTP; B asks A over the ship-to-ship connection; A checks that B may have the
file; B checks every piece against the file's id and passes it straight to
the device. With keeping off (`max_cache_bytes` 0) B keeps nothing: no file,
no directory, no row. With it on, B keeps what it was given, once checked (see
Keeping what was opened, and saving a copy); what follows here is what happens
for a file B does not keep. Code: serving in `files.rs`
(`Runtime::serve_file`) and `ship.rs` (`Ship::file_permit`), the wire in
`net.rs`, checking in `remote.rs`, keeping in `kept.rs`, routes in
`server.rs`.

**Who may have a file** is decided by the agent on A that claims it, never at
install. Closed by default: the agent is asked, as a `KIND_FILE_ASK` call
(`FileAsk {ship, id}` in, `FileAnswer {allow}` out), and says yes or no. It can
instead mark its claim open (`files::open(id)`, host `file_mark`; `close` takes
the mark off), and then any ship that names the file gets it and the agent is
not asked. The mark is per agent and per file, a column of `file_claims`, and
goes with the claim. "Any ship" means a ship that proved its Urbit ID on the
connection; there is no public web link.

**The question** runs like a read: read-only (every write, send, emit, log
change and `file_mark` is refused), no send grants, the agent's ordinary read
grants (it may read another agent here, to see who is in a group, say), inside
a transaction that is always rolled back. It has its own budget,
`file_ask_fuel` (10,000,000) and `file_ask_millis` (500 ms, the kernel's
decision included), not the event budget. No `file_ask` export, a trap, out of
fuel, out of time, a reply over 64 bytes, a reply that does not decode, a
kernel refusal: each is no.

**On A, before each request** (what the file is, one group of hashes, the
upper hashes, one chunk), in one hold of the ship's slot and one read
transaction: the agent is installed (the kernel routes the owner's command to
it, which also gives the module it runs) and claims the file; then the claim is
open, or the answer remembered for exactly this key is still fresh, or the
agent is asked now and its answer remembered. Anything that fails on the way
is no. Every no is the same in-body refusal, `denied: "~A does not share that
file with ~B"`, whether the store is off, the agent or the file does not
exist, the agent does not claim it, the agent said no, or the agent failed.
Once the answer is yes, hashes are read in batches of 4,096 rows (each batch
under the slot, looked up again by the claim and the file's directory) and
hashed outside the slot, and a chunk's row is read with the decision and the
chunk read, opened and checked against it outside the slot (`read_chunk`). A
damaged or vanished chunk is a refusal at the transport level ("the file could
not be read; try again"), never bytes. Serving writes nothing of its own and
keeps nothing: no row, no file. A request that is the first thing to wake a
ship in a runtime's life sets off the clearing of leftovers part 1 owes at
first wake, as the next ordinary use of the ship does (a command or a log fetch
from another ship already did); a wake for a question (one from another ship,
or the asking ship's own task reading its question's row or writing what came
of it) leaves it owed for the next ordinary use (see Who looks, and when, under
Questions between ships). That clearing removes what the ship had recorded
to be removed and directories under `files/<ship>/` that no row names (such
as an upload's directory whose row never committed); it only ever removes,
and is the one thing a stranger's request can change.

**Remembered answers** are in memory only, per runtime: a yes for 30 s, a no
for 5 s, at most 4,096, the oldest going first when full (which only costs an
extra ask). The key is the ship, its incarnation mark (new at every import),
the module the kernel routes the agent to, the agent, the calling ship, the
file's id, and the file's directory (random, never used again). So an import
or a file deleted and put back is never answered from an earlier answer. A
module hash is not an installation: every successful change made through a
ship's kernel (an install, the same module installed again with other grants,
a module replaced and put back) forgets every answer remembered for that ship,
all agents (one agent's answer can rest on a read of another), under the same
hold of the slot as the change, so no request is decided between the change
and the forgetting. Other ships' answers stay. A table left poisoned by a panic
is emptied, and that lookup is no. Questions to one ship are asked one at a
time, under its slot.

**A ship rests from asking.** After a question to an agent that took `t`, the
ship asks no agent about a file for `3t`. So over any stretch of time, however
many ships ask (one owner can prove many ships: a planet and its moons),
questions take at most a quarter of it plus the length of one question: every
question but the last that falls in the stretch is followed, inside the
stretch, by a rest three times as long. A single question is cut off at
`file_ask_millis` (500 ms), as any call is stopped for time (see Time, above:
never before it; after it, at the first point where the running code looks and
finds the watchdog has ticked since it was last allowed on, with no number
promised for the overrun), or when it returns. A request that
would need a fresh question during that
rest is answered exactly as any no (the same `denied`, and not remembered); a
remembered answer and an open mark are honoured as always. In memory only, one
entry per ship. The cost: under such a flood, a ship that would be allowed may
be told no and must try again.

**The wire**: four kinds from field 7 on (see Wire messages), each naming the
agent and the id. A chunk reply is 1 MiB and a few bytes, inside the default
`max_message_bytes` (1 MiB + 64 KiB); a runtime whose `max_message_bytes` is
below 1 MiB + 1 KiB refuses to ask for files and to serve them, saying so, and
starts and carries everything else as before. File requests have their own
deadline at both ends, `file_timeout` (30 s), in place of `request_timeout`.
On A the request is still read within `request_timeout`, and only then given
the longer time.

**On B, in this order, before one byte or one number goes to the device:**

1. Ask A what the file is: its length `L` and media type. A length whose
   hashes could not come to the root in two levels (more than 2^30 chunks) is
   refused before anything else is asked.
2. For at most 32,768 chunks, ask for group 0's hashes: exactly as many as
   `L` takes, and with `L` they must give exactly the id in the address. For
   more, ask for every group's index hash: exactly as many groups as `L`
   takes, and with `L` they must give the id; then each group of chunk hashes
   needed is fetched when needed, counted, and must hash to its index hash.
   Only now is `L` believed, and only now is the head (`Content-Length`,
   `Content-Range`) sent. For a file of more than 32,768 chunks every group of
   chunk hashes needed, the first included, is fetched after the head of the
   contents: the index hashes already tie `L` to the id, so nothing believed
   comes later (a group that fails its check ends the answer short), but this
   is not the plan's literal order.
3. Each chunk: exactly as long as `L` says chunk `n` is, and hashing to its
   checked hash; then written to the device.

The media type is the one thing A says that the id does not cover. It goes
through the check made at upload (anything it refuses becomes
`application/octet-stream`), and the answer carries every header a local file's
does: `nosniff`, `Content-Security-Policy: sandbox; default-src 'none'`, and
`inline` only for the same fixed list. No text A sends reaches the device: A's
`denied` is read only as "not empty means no", and B answers every refusal
with its own fixed sentence; reasons for a refusal at the transport level are
not passed on either. Every answer the signed-in remote handler gives,
errors included, carries `nosniff`, the sandbox policy and a
`Content-Disposition`. A request without a valid device is answered 401 by the
server before that handler, and that answer carries nothing of A's.

Routes, under the ship, signed in as every route, and not under an agent:

| Method and path | Answer |
| --- | --- |
| `GET /files/from/<ship>/<agent>/<id>` | `FileInfo {id, length, chunks, media_type}` (`added_ms` and `open` unset) |
| `GET /files/from/<ship>/<agent>/<id>/chunks/<n>` | One chunk, `application/octet-stream`, an attachment |
| `GET /files/from/<ship>/<agent>/<id>/content` | The file, or one `Range`, streamed, with the same rules as the local route |

`<ship>` must be a valid ship name other than this ship, `<agent>` a valid agent
name, `<id>` 64 lower-case hex digits; otherwise 400. They only go into the
request to the other ship; none becomes a path. Before the head: 404 for A's
refusal ("the other ship does not share that file with this one"), 502 when
A's answer fails a check, does not decode,
is of the wrong kind, or is a refusal at the transport level, 504 when A
cannot be reached or does not answer within `file_timeout`, 503 with
`Retry-After` when B or A is too busy (B: `Retry-After: 1`) or B has no network
running (`Retry-After: 5`), and 503 without it when B's messages are too small
for a chunk or B's server has no download places (two workers). After the head, anything wrong ends the answer short, never padded
and never with unchecked bytes; the device carries on with `Range`. For a file
B does not keep, hashes are fetched again for each HTTP request: nothing learned
from one answer of A's is used in another request. A file B keeps is read
from B's own rows, which were checked against the id when it was first kept.

Over a relayed connection files go at the relay's existing limits with no
special handling: about 128 KiB/s at most, shared with everything else sent to
that ship through its point, so a chunk takes eight seconds or more. Only a
small file has been fetched this way in the tests.

#### What holds, and how

- HARD. A gives a file only to a ship allowed now: the caller is the ship
  proved on the connection, checked again before each request as for every
  request, and the claim, its mark and the agent's install are read under the
  ship's slot for each request. A request whose decision begins after the
  event that closed the file or removed the claim has committed is not
  answered from the mark; one that begins after any change made through the
  ship's kernel is not answered from anything remembered before it. Nothing
  uninstalls an agent, as in part 1, so there is nothing more to race.
- BEST EFFORT. An agent's own change of mind takes effect within 30 s (a
  remembered yes) or 5 s (a remembered no). A request already allowed finishes
  its one part: hashes are read after the decision, by claim and directory,
  and a claim gone meanwhile ends that request with a refusal.
- HARD. An error is never a yes, at every place a yes or no is decided (the
  agent's install, the claim, the mark, the remembered answer, the kernel, the
  agent's answer and its decoding), and every no on A is the same reply. The
  replies to a ship that may not have a file are the same bytes whatever the
  reason; how long they take is not made equal.
- HARD on B: every byte and the length given to the device are fixed by the
  id. A lying, broken or replaced A can cause an error or a short answer.

Bounds, with their working:

- On A, file places: a request for a part of a file is at most 1,024 bytes,
  encoded (an agent's name and a 32-byte id need far less); a larger one is
  refused at once, the same whatever it names, before it is decoded, so no
  decoded request is ever made for it; its raw bytes are read into a buffer
  that its room for reading covers until the buffer is dropped, before the
  refusal is written (see Wire messages for the order of the checks). Otherwise it takes one of its connection's 4 places and one
  of the runtime's 8 before anything is looked up, or is turned away ("too
  busy; try again"). Refused or turned away, it holds no place, gives back the
  room it was read into before it replies, and has what is left of
  `request_timeout` to deliver the refusal. A part sent (a yes)
  holds both places until its blocking job has returned and its stream is done
  with (the reply wholly taken, or the stream reset at `file_timeout`),
  whichever is later; a no or any other refusal gives back both places and its
  room for reading as soon as it is decided and its job has returned, before
  it is written, and is sent within `request_timeout`. A request given up on
  (out of time, or the asking ship stopping the stream or losing its
  connection) is marked so at once: its own share of the places and its room
  go, and its blocking job, still holding its share, stops before its next
  batch of hashes or before reading the chunk; the check is made again inside
  each hold of the ship's slot, before its decision and before each batch of
  hashes is read, so a job that was waiting for the slot when its request was
  given up on reads nothing. The job is given only values of this runtime's
  own size: the agent's name once it passes the runtime's check, copied to
  exactly its length (at most 64 bytes), the id as 32 bytes, and the number of
  the part; the decoded request is dropped before the job is scheduled, and a
  name or an id that does not pass is the same no, made without a job.
  Whenever a request's room goes back before its reply is written, what the
  asking ship sized of it goes first (the bytes it sent, and the decoded
  request if there is one): it then holds only its own small reply, and its
  job, if one still runs, those values of its own. So at every instant at most 4 of
  a connection's 8 streams and at most 8 requests in the runtime are file
  parts in hand.
- On A, what those hold: a `work` place for the whole blocking job (waiting
  for the slot, the decision with any question, reading and hashing hashes,
  reading and checking a chunk), so at most 8 of the network's 16; a place
  among the about 60 for requests being read (64 MiB over 1 MiB + 64 KiB) for
  as long as the request is being decided, and for a part sent until its
  stream is done with. Bare refusals, of any kind of request, and a file's no
  give their room back before they are written, so a ship that never takes
  those holds no room for them; a reply of an earlier kind that carries a
  body (a log fetch's `denied` among them) keeps its room until it is taken or
  timed out, as before. At most 8 rooms are held by file parts being sent. (Waiting for their
  decision, file requests hold at most 8 more.) Memory: one chunk or one list of 32,768 hashes (1 MiB) per part
  in hand, and its encoded reply, about 2 MiB each, 16 MiB at most. The
  remembered answers: 4,096 entries of about 250 bytes, about 1 MiB.
- Slot time on A, measured in a test on a Mac laptop in an unoptimised build
  with the default kernel and the counter agent, for one caller: about 0.15 ms
  to decide for an open file or a file that is not there, 0.07 ms from a
  remembered answer, 0.5 ms with a fresh question to the counter agent. A ship
  holding no reference never reaches an agent: each request costs the kernel's
  decision and one lookup, at most 4 at a time on its connection. Questions to
  agents, from however many callers, take at most a quarter of any stretch of
  the ship's time plus one question, by the rest above; a single question at
  most `file_ask_millis` (500 ms) with the kernel's decision, and however far
  past that it runs before it is stopped, for which no number is promised (see
  Time). These were not measured on other machines or in a release build.
- On B, threads: each of the three routes that waits on A does so holding a
  worker, so it holds a place among the downloads, as a local file's contents
  do, and of those places requests to other ships may hold at most half, and
  at least one. Long polls, downloads and waits on other ships together
  therefore never take the threads kept for everything else. With 16 workers
  (the default): 8 may wait for logs, 4 download or wait on other ships (2 of
  them at most waiting on other ships), 4 are always left; with 4: 2, 1 (which
  may be a wait on another ship), 1; with 2: 1, none (no route can wait on
  another ship, 503), 1. Past a limit: 503 with `Retry-After: 1`. Since part
  3 these places are taken at a request's first question to A, not before:
  what B keeps of a file is read without them (see Keeping what was opened,
  and saving a copy).
- On B, memory per request: one list of index hashes, one group of chunk
  hashes and one chunk (1 MiB each) and one reply being read and decoded
  (about 2 MiB): about 5 MiB, 10 MiB with the defaults. A piece kept is
  sealed where it lies, and needs no copy. Each wait on A is
  within `file_timeout` (and 2 s more on the waiting thread), each write to
  the device within `io_timeout`. There is no deadline for a whole download, as
  for a local one.

### Keeping what was opened, and saving a copy

After part 2, opening a file on ship A from ship B fetched it every time, and
a file A had taken back, or A switched off, could not be opened at all. Now B
keeps what it was given, up to an allowance, so opening it again needs no
network; and B's owner can ask for a file to be kept for good, as one of B's
own files. Nothing changes on A or on the wire. Code: `runtime/src/kept.rs`,
with the shared chunk-copy path in `files.rs` and the routes in `server.rs`.

**A kept file** is a file of another ship's that B holds some or all of, known
by its id. It has a row in `kept` (its directory, 16 random bytes never used
again, as for an upload; its length and media type; when it was last opened;
the bytes of its pieces held) and a row in `kept_chunks` for every chunk, with
the chunk's hash from the moment it is kept and the copy's generation once the
piece is held. Only a file of at most `FANOUT` chunks (32 GiB) is kept, and
only once its length and every hash have been checked against its id as part 2
checks them; a larger file is passed through as in part 2. A kept file is in
one of two states:

- **In the cache**: no agent is saving it. Its held bytes count against
  `max_cache_bytes` (3 GiB; 0 turns keeping off, and the three routes are then
  exactly part 2's). It may be thrown away at any time.
- **Being saved**: one or more rows in `saves`. Its whole length is reserved
  against `max_file_bytes`, as an upload's is, its held bytes do not count
  against the cache, and it is not thrown away. When every piece is held it
  becomes a file of B's.

**Opening** (the three routes of part 2, same addresses). If B keeps the file,
its length, media type and hashes come from B's own rows, with no question to
A, whatever ship and agent the address names: what B was given, B has. The
hashes are checked against the id again each time they are read, and rows
that no longer come to it are not used (the file is then opened as part 2
opens it). When it was last opened is written at most once a minute. For each
piece wanted: if it is held it is read from disk and checked against its hash,
as every chunk is. A copy that is certainly not the piece (missing, the wrong
size, not opening under its key for its place, not matching) is given up: in
one synced transaction its row stops naming it and it is recorded in the trash,
counted where the file's bytes are counted, and the drain removes it. A copy
that could not be read for some other reason (a failed read that says nothing
about the copy) is not given up. Either way the piece is then fetched from A
as in part 2, checked, kept if it can be, and given to the device. A file B
does not keep is opened as part 2 opens it, and then, if keeping is on and
there is room for its rows, begins to be kept.

The device gets a piece before the ship tries to keep it, and keeping is best
effort: whatever stops a piece being kept (no room, a full ship file, a disk
error, the kept file thrown away meanwhile, no place free for keeping) the
checked piece goes to the device all the same, and no sooner or later because
of it. In a contents answer each piece fetched is written to the device, then
kept, then the next is fetched; a piece whose write fails is not kept. The
answer of one chunk, and the last piece of a contents answer, are kept only
after the device has the whole answer and the connection is closed, and after
the request has given back its places; at most two pieces are kept like this
at once in a runtime (`MOST_KEEPING_AFTER`), taken without waiting, and with
neither free the piece is not kept. One keep of a whole 1 MiB piece (seal,
write, sync the copy and its directory, one synced commit) took 41 ms at the
median and 46 ms at worst, in three runs of 50 on a Mac laptop in an
unoptimised build with the default durability. That is a measurement of one
keep on that machine, not a bound on what keeping can add between two pieces
of a contents answer: a keep can also wait for the ship's slot, throw others
away, drain the trash, or sit on a disk that is slow or stuck. Not measured
elsewhere.

**Room in the cache.** A piece goes into a file in the cache only if the
cache, with it, stays within `max_cache_bytes`, decided in the transaction
that names the piece. The cache counts the held bytes of kept files in the
cache and what was thrown away from it and is still on disk (`file_trash`
rows with `pool` 1), so throwing away makes room only once the drain has
removed the bytes. If the piece does not fit, the least recently opened kept
files in the cache, never the one being read, are thrown away in one synced
transaction until what is left with the piece would fit or the request's
budget is spent; the trash is drained, whether or not anything new was thrown
away (what was thrown away before and could not be removed then may go now);
and the piece is tried once more. If it still does not fit it is not kept.

The rows of files in the cache have an allowance of their own, a sixteenth of
`max_ship_bytes` (64 MiB by default), counted by the rule an upload's rows are
counted by (128 bytes a chunk and 1 KiB a file), whether or not a byte of the
file is held: a ship that answers what its files are, and nothing else, can
make B keep their rows and no bytes. Beginning to keep a file in the cache
throws away the least recently opened ones until its rows fit, within the
request's budget, and keeps nothing if they still do not; a file whose own
rows pass the allowance (more than about half a million chunks' worth with
the defaults; a 32 GiB file's rows are 4 MiB and 1 KiB, so 15 of them fit, in
62,929,920 bytes: 62.9 MB, 60.0 MiB) is never kept in the cache. A save is not
counted here: its rows are bounded by its reservation against
`max_file_bytes` (see Bounds below). A save that stops goes back to the
cache only if its rows fit too.

Kept files in the cache not opened for `cache_keep_millis` (30 days) are thrown
away, and so are the least recently opened while the cache holds more bytes
than its allowance, more rows than its allowance, or more than `max_kept`
files are kept (any of which can be after a setting is lowered), when an
upload starts, when a file begins to be kept, and when a save call starts. At
most `max_kept` (1,024) files are kept, in the cache and being saved together;
a new one throws away the least recently opened in the cache to make its
place, and is not kept if every one is being saved. A kept file's rows must
also fit the room the ship keeps in its own file, as an upload's must.
Throwing away is rows first, in a synced transaction that records the
directory in the trash, and bytes after, as a file's deletion is.

Everything one request throws away under the ship's slot shares one budget:
at most 64 kept files, and at most 65,538 rows counting each file's chunk rows
and its own row (two whole files of 32,768 chunks). That covers the saves that
ran out and are stopped, the sweep of the cache, room made for bytes, for rows
and in the count, a second sweep in the same request, and the request's own
target: a save call keeps back room in its budget, from its first throwing
away, to throw away its own kept file (a redundant copy at its finish, or one
whose rows are damaged), and stopping a save keeps back room for the file it
stops. What does not fit waits for a later request; a request that finds it
must throw away its own target and cannot is refused (503, try again later)
and throws nothing away. Clearing everything is the one exception: it takes
one budget for each of its transactions, letting the ship go between them.

A request's opening sweep (saves run out, stale files, files over a lowered
setting, files in the cache with strays) is a synced transaction of its own,
run only when there is something to sweep, and drained after; what it throws
away stays thrown away even if the request is then refused. What a request
throws away only to make room for the very file it is about to keep (rows
and the count, in beginning to keep it) is in that file's transaction, and
goes back with it if the file is refused.

**Seeing and clearing the cache** (signed in, under the ship, not under an
agent):

| Method and path | Answer |
| --- | --- |
| `GET /files/kept?after=&max=` | `KeptList` of `KeptInfo {id, length, held, used_ms, saving}`, in order of id, at most 256 (100 by default) per page |
| `DELETE /files/kept/<id>` | Throws that file away from the cache. `Cleared {thrown_away, being_saved}`: a file being saved is left alone and counted in `being_saved`. 404 for an id not kept |
| `DELETE /files/kept` | Throws away every file in the cache: every kept file is listed by id, 256 at a time, until there are no more (whatever `max_kept` now is), and those in the cache thrown away in transactions with one budget each, letting the ship go between them. `being_saved` counts the kept files left alone because some agent was saving them when their batch ran, counted inside those transactions |

When a clear returns, no row names the files it threw away, they are not read
back from B (opening one again asks A afresh), and their bytes are in the trash
or gone; they are gone once the trash has drained, which the call does before
it returns unless a removal fails, in which case the next file operation tries
again. Files being saved are untouched.

**Saving a copy** (signed in, under the agent that is to claim the file, which
must be installed):

| Method and path | Answer |
| --- | --- |
| `POST /agents/<a>/files/save` | `SaveRequest {ship, agent, id}` gets `SaveReply {done, held, chunks}`. Call again until `done`; each call carries on where the last left off |
| `GET /agents/<a>/files/saves` | `SaveList` of `SaveInfo {id, length, held, chunks, touched_ms}`: the agent's saves in progress |
| `DELETE /agents/<a>/files/saves/<id>` | Stops the agent's save. 204, or 404 if it has none |

- If B already holds a file with that id, the claim for `<a>` is added and the
  answer is done, with nothing asked of A. A save of it `<a>` had begun is
  ended, and if no other agent is saving the kept copy, it is thrown away.
- Otherwise saves and kept files gone stale are swept first, in a synced
  transaction of their own when there is anything to sweep, so that what is
  thrown away there stays thrown away whatever the call then finds; the file becomes
  kept if it is not (asking A, as opening does); and a save for `<a>` is added,
  with the whole length reserved against the file allowance, in one synced
  transaction. It is refused as an upload would be: 403 if the store is off,
  413 if the file could never be one of B's, 507 if there is no room, 409 if
  B already holds, with the files being saved, `max_files` files.
- Then missing pieces are fetched from the ship and agent the request names,
  checked against the kept hashes, and kept, one at a time, until none is
  missing or `save_slice_millis` (10 s) has passed since the call began; a
  fetch begun before then is let finish. A's failures answer as on the
  remote routes (404, 502, 503, 504), and what was kept by then stays. A kept
  file whose directory holds as many strays as it may (see On disk) answers
  503, try again later.
- When no piece is missing, one synced transaction makes the file: its rows
  from the kept rows under the same directory (no byte is moved or written
  again), a claim for every agent saving it, the kept and saves rows gone, the
  reservation become held bytes, and the directory recorded to be swept of
  copies no row names. The held count and every hash are checked inside that
  transaction: a piece given up meanwhile makes it refuse (409), and the next
  call fetches the piece. The id is worked out from the stored hashes and must
  be the id asked for. If a file with that id has appeared meanwhile (the same
  bytes uploaded), every agent saving it claims that one instead and the kept
  copy is thrown away, with the room the call kept back for it.
- Stopping the last save of a kept file returns its reservation. The file goes
  back to the cache if its held bytes and rows fit there, after the least
  recently opened others are thrown away to make room (done first, while the
  file is still reserved, within the request's budget, keeping back enough to
  throw this one away), and its directory has no strays; it is thrown away if
  not. A save not called for `upload_keep_millis` (24 h) is stopped when an
  upload, a keeping or a save starts, without throwing others away for it: it
  goes back to the cache only if it fits as the cache is.
- A save call that finds the file's stored hashes certainly do not vouch for
  its id (read without error, and not as many as its length takes, or not
  coming to the id) ends its own save in that call: the agent's save is
  removed, and if no other agent is saving the file it is thrown away, never
  returned to the cache, with the room the call kept back, in one synced
  transaction. The call answers 500 (damaged) once; made again, it starts
  afresh. Another agent still saving it keeps its save, and its next call does
  the same. An error reading decides nothing. A save stopped or run out
  without such a call leaves the file as it is, and the next open or save call
  finds it (an open throws a file in the cache with such rows away).
- The saved file is an ordinary file of part 1 from then on: closed (`open`
  0), listed, downloadable, deletable, and exported with the ship.

A kept file is never a file as far as serving goes: B never serves it, or any
piece of it, to another ship, and no agent sees it (no host function reaches
it, and `files::info` answers as for a file the agent does not claim). An
exported ship carries, inside its sealed copy, the rows of `kept`,
`kept_chunks`, `saves` and the trash: the ids, lengths, media types and hashes
of what was opened from other ships, and no bytes of them, as it already
carries `uploads`. The rows of files in the cache are bounded by their
allowance above, which bounds what they add to an export. An import brings
none of these rows in and looks at none of them. The first look at a ship's
files when it wakes counts a kept file's directory as named.

#### On disk

A piece is put on disk by the same code as an upload's chunk
(`Runtime::prepare_copy` and `PreparedChunk`, with a `Holder` that is either
an upload or a kept file): hashed and sealed outside the ship's slot, its name
made by an exclusive create under the slot only while the kept file is still
there under the same directory and does not hold the piece, written and synced
outside, and named in a transaction committed synced only if the kept file is
still there under the same directory, does not hold the piece, and the row's
hash is the hash of what was written. A copy refused, or failing before its
commit, is removed by the call that made it. The trash, its drain, and the
sealing are part 1's. Every transaction that names bytes or records something
to remove (keeping a piece, giving one up, throwing away, clearing, beginning
to keep a file, a save beginning, stopping and finishing) is committed synced.

Copies no row names in a kept directory are bounded and cleared:

The runtime keeps one record, in memory, for each kept directory it keeps
into: whether it has been looked through, its strays, its copies on their
way, and whether it is retired.

- After a crash. The first time in a runtime's life that a copy is about to be
  made in a kept directory, under the ship's slot and before that copy's name
  is made, the directory is marked looked and then listed, and every entry
  that no `kept_chunks` row names by its exact generation, and that the trash
  does not record, is removed. The safety of this rests on one thing: the
  first look precedes every copy this life makes in that directory (all of
  them are made under the slot, after it). A second look would not, and could
  remove a copy made and not yet named; so a directory is looked through once
  in a life whatever comes of the look. An error reading the rows or listing
  the directory, or a removal that fails, removes nothing more, and what the
  look left stays until the next life's first copy there, or until the
  directory goes. Each look lists one directory: at most its 32,768 named
  copies and whatever a crash left in it.
- In a running runtime. A copy is on its way from when its place is taken,
  under the slot, before its name is made, until it ends, exactly once: named
  by a commit known to have landed, removed, or become a stray (a commit of
  unknown outcome, or a removal that failed). A directory takes a new copy only
  while its strays and copies on their way are fewer than two
  (`MOST_STRAYS`): so at most two pieces are kept at once into one kept
  directory, a third request passes its piece through unkept (an open) or
  answers 503, try again later (a save call), and strays and copies on their
  way together never pass two. A file in the cache with a stray is thrown away
  at the first chance (the request that made the stray tries once, and the
  sweep tries again); a spent budget or a failed transaction can put that off.
  A file being saved goes on up to the cap; when it is saved, the sweep of its
  directory clears its strays; when its last save stops or runs out it is
  thrown away, not returned to the cache.
- Retirement. When the transaction that throws a kept directory away, or makes
  it a file's, is known to have landed, its record goes; with copies still on
  their way it is marked retired, counts no more strays, and goes when the
  last of them ends. A late completion never brings a record back. Each sweep
  also drops up to 64 records of the ship whose directory no `kept` row names
  and that have nothing on their way (a throwing away that landed and
  reported an error leaves such a record), carrying on from where the last
  one stopped. So the records number at most the kept directories kept into
  in this life, and those with copies on their way.
- Charging. A kept directory thrown away is recorded in the trash at its held
  bytes and 1 MiB more for each stray and each copy on its way into it then,
  so what cannot be removed stays counted against its pool until the
  directory is durably gone. The sweep recorded for a directory made a file's
  is charged the same way, against the file allowance, until it is done; if
  the file is deleted first, the sweep and its charge stay until the whole
  directory is removed.

A drain that runs after a transaction failed, or after one whose commit's
outcome is unknown, reads the trash afresh and acts only on rows the ship's
file holds as committed when it reads them: after a rolled-back transaction it
finds nothing that transaction wrote. Every transaction that records trash is
committed with its log synced, and the bundled SQLite makes a commit visible to
readers only after that sync; so the drain never acts on rows a commit that
reported an error may yet lose. That last step is SQLite's, and was not tried
with a failing disk.

#### What holds, and how

- HARD. Every byte handed on from a kept file hashes to the hash the request
  checked against the id, read back and checked on every read; a piece that
  fails is never served. A saved file's id is the id asked for.
- HARD. A piece is named only by the very kept file it was fetched for: the
  directory, never used again, is compared under the slot when the copy's name
  is made and again in the transaction that names it. A file thrown away and
  kept again meanwhile has another directory.
- HARD. The cache, held and to be removed, is within `max_cache_bytes` at
  every instant, but for one thing: a kept file in the cache that is thrown
  away is recorded to be removed at its held bytes and 1 MiB more for each
  stray and copy on its way into it, so that what may not be removable stays
  counted; that can take the count over by at most 2 MiB for each such
  directory until it is gone. A piece is kept only if it fits with what is
  to be removed counted. The rows of files in the cache are within their
  allowance against everything the runtime does: no file is admitted to the
  cache, and no save returned to it, while the cache's rows are, or would be,
  over. A setting lowered between runs (`max_cache_bytes`, `max_ship_bytes`,
  `max_kept`) is not something the runtime does: the cache may then be over
  until sweeps bring it down within their budgets. While its rows are over,
  no new file is kept in it, and pieces of files already in it may still be
  kept (they add no rows). While its bytes, with what is to be removed, are
  over a lowered `max_cache_bytes` and its rows and count are not, a new file
  may still be begun in the cache (its rows, no bytes), and no piece is kept
  in the cache, its file's or another's, until they fit. Held and reserved
  file bytes, saves included, are within `max_file_bytes`: a save is begun
  only if held, reserved and to-be-removed bytes leave room for its whole
  length. What is to be removed can take that count over it by the bytes of
  pieces given up from files being saved whose removal has not worked yet,
  each one a copy found certainly bad on disk, and by what a file made from a
  kept file is charged until its sweep works: 1 MiB for each stray and copy on
  its way into its directory when it was made, at most 2 MiB, also kept when
  the file is deleted until the directory itself is gone. While it is over,
  nothing is reserved and no piece is taken for a file being saved.
- HARD. At most `max_kept` kept files. Every write about kept files leaves the
  ship's file the room it keeps (`room_to_take_one`) or used none.
- HARD. Only signed-in devices reach these routes; a saved file is reached
  only through an agent that claims it; names in an address or a body are
  checked before use and none becomes a path.
- BEST EFFORT. Beginning to keep needs room for all of a kept file's rows
  then, and a save needs room for the file's rows to come; others may use the
  room meanwhile, and every write is checked again.

#### Bounds, with their working

- Disk beyond the two allowances, while running: one sealed piece (1 MiB and
  28 bytes) between its create and its commit per keep in progress, at most
  two into one kept directory. Over HTTP, keeps in progress are those of
  requests waiting on other ships (at most other ships' share of the download
  places: 2 with the default 16 workers) and of pieces kept after their answer
  (at most 2 a runtime): about 4 MiB. Then 28 bytes per piece held. Strays,
  with copies on their way, at most two per kept directory: in a file being
  saved, at most 2 MiB beyond its reservation; in a file in the cache, at most
  2 MiB until the file is thrown away (at the first chance, which a spent
  budget or a failed transaction can put off), and counted against the cache
  from that moment until the directory is durably gone. After a crash, what it
  left in a kept directory (at most one copy per keep that was in progress)
  stays until the next life's first keep into that directory looks it
  through, or until the directory goes; a look that fails leaves it until the
  life after. A directory made for a kept file whose row never committed stays
  until cleanup succeeds on an ordinary use of the ship.
- Throwing away under the slot, per request: at most 64 kept files and 65,538
  rows, in the request's transactions; clearing everything, the same per
  transaction, letting the ship go between them. Not measured.
- The rows of files being saved are not in the cache's allowance. They are
  bounded by the reservation together with `max_kept`, `max_files`, and the
  working room each save's row leaves: for N saves of positive length whose
  reservations total S, the rows their files will need are at most
  128 x (floor((S - N) / 1 MiB) + N) + 1,024 x N bytes by the estimate, which
  with the defaults (N at most 1,024, S at most 10 GiB) is at most 11,263
  chunk rows, about 2.5 MB.
- A save call is network waits plus local work, not a deadline. The waits: at
  most the longer of `save_slice_millis` and the time to ask A what the file
  is (two waits, each within `file_timeout` and 2 s more), plus one more wait
  for a piece begun before the slice ran out: with the defaults at most about
  96 s, and 10 s and one piece when A answers at once. The local work, not
  bounded by that figure: waiting for the ship's slot, keeping each piece
  fetched (one keep took 41 ms at the median on the machine above, which is
  not a bound), throwing away and draining within the budget, and finishing.
- Memory per request on B: a kept file's hashes (at most 1 MiB, as a group in
  part 2), one piece (1 MiB), and one reply being read (about 2 MiB). A piece
  is sealed where it lies, so keeping it needs no copy; a piece kept after its
  answer is the answer's own body, held until it is kept, by at most two
  requests at once.
- Places. A file's contents take a place among the downloads first, as a file
  of B's own does, whatever comes of them. Nothing else is taken until a
  question is about to go to A: then a place among other ships' share of the
  downloads (and, for what a file is and for one chunk, a place among the
  downloads too), held until the request is done with A. So what B keeps is
  read under the ordinary places only: a file B holds whole opens with other
  ships' share taken by stalled requests, and on a server of two workers what
  it is and its chunks are had (its whole contents are refused, as a file of
  B's own would be). If the place cannot be had at the first question, the
  answer of what a file is or of one chunk is 503, and a contents answer
  already begun ends short. A save call takes both places before anything,
  and holds them for the whole call. The cache routes, the saves list and
  stopping a save wait on nothing and take none.

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
  `place(ship, addr)`, or for a ship with no address given, found through the
  lookup point for its galaxy if the runtime has lookup settings (see Finding
  a ship by its name). An address given by hand is always used, and nothing
  else is tried. Two kinds of promise hold when an address is given while
  calls are going on. A call that begins after `place` (or `set`) has returned
  never uses a record, and no connection made through a record is kept or
  used again once an address is given (this is settled under the directory's
  lock). A call already under way when the address is given stops at its next
  check (before each address it tries, before asking a point, when a kept
  connection is proved again) if that re-read sees the address. Until then it
  may go on: an attempt or question it had begun goes on, and it may begin one
  more after the address is given, following its last check; such a call may
  fairly be taken as having come before the address was given. Setting an
  address does not go and close idle connections found through a point: each
  is refused the next time it would be used, or dropped when room is made. A wrong address cannot pass one ship off as
  another, since whatever answers must still prove the key.
- If what the directory holds for a ship changes, connections made under the
  old listing are closed.
- Session resumption is off, so every connection proves its keys afresh.
  Connection migration is off.
- Each request and its reply travel on one bidirectional stream. Unidirectional
  streams and datagrams are not accepted. There is one connection per (calling
  ship, called ship); a newer one replaces the older. (On the connection a
  runtime keeps to a lookup point, the point may open up to 4 small streams of
  its own, to pass introductions; see Finding a ship by its name.)
- The code says an observer still sees which ship is being called, that this
  protocol is in use, the addresses, and the size and timing of traffic.
- Before a request or reply is decoded, the runtime counts its repeated fields
  without allocating: at most 256 messages in a `Deliver`, 256 logs in a
  `News`, and 256 entries in a `Fetched`.

### Finding a ship by its name

Without this, a runtime has to be told by hand where every other ship is. Keys
come from Urbit ID; addresses do not, and cannot: they change far more often
than anything worth writing to Ethereum. So a ship says where it is itself, in
a record it signs, and anyone can check that record against the key Urbit ID
lists for it, the same key the ship must prove when it is called.

- The record (`Whereabouts`, `runtime/src/whereabouts.rs`) names the ship by
  number, one to four addresses (IPv4 or IPv6, each with a port), and when it
  was made, in milliseconds since 1970. A moon's record also carries its key
  and its parent's word for that key, as a `Hello` does. And it says whether
  callers should ask to be introduced before they call (see Home routers,
  below). The ship signs, with its networking key, a fixed layout written out
  by hand: the label `ship.v1.where\n`, the ship as 8 bytes, the time as 8,
  whether to be introduced as 1 (one or nought), the number of addresses as 1,
  then four slots of 19 bytes (kind, 16 bytes of address, the port), empty
  slots zero. Never the protobuf encoding. So the flag is the ship's own word:
  a point can neither set it nor clear it.
- A record is believed only if all of these hold: decoding it and encoding it
  again gives the same bytes (nothing unknown, repeated, or padded), and it is
  at most 512 bytes; it names one to four addresses, none that means "any"
  (`0.0.0.0`, `::`), a group, the broadcast address, port 0, or an IPv4
  address written as IPv6, and no two the same; it was made no more than 2
  minutes ahead of this machine's clock and less than 10 minutes before it (so
  good for 10 minutes from the time it says it was signed, which is up to 12
  minutes from when it is taken); it is
  newer than the newest record already believed for the ship that has not yet
  run out (a record held keeps older ones off until then, even if it is dated
  ahead of a clock that has since stepped back); and it is signed by the key
  Urbit ID lists for the ship, or for a moon by the key it carries, which its
  parent (by the parent's key from Urbit ID) vouches for, at no earlier a
  revision than any already seen for the moon, and at the same revision only
  for the same key. One function makes this check, for lookup points and for
  the ships that ask them, each with its own source of keys. Times are worked
  out without overflow: a wrong clock makes records refused, never believed.
- A lookup point is a role any runtime can play (`Lookup::serve`, `serve
  --lookup-point`). It answers on the same UDP port as the ships, under its own
  ALPN, `ship-where/1`, which a runtime that is not a point does not offer. It
  shows a key made when it starts, and its callers accept any key: nothing a
  point says about who anyone is, or about what a ship's record says, is
  taken on its word. (The one thing a ship does take from its own galaxy's
  point is where that point sees it from; see the announcing bullet below,
  and the limits.) Its callers show a key made when their
  network starts, which names nobody, because the ship protocol on the same
  port needs every caller to show some key.
- Presence. Anyone can read a record from a point and hand it on, so a record
  alone does not show that its ship is the one giving it. When a ship gives
  its record to a point, it also signs, with the same key, a short statement:
  the label `ship.v1.here\n`, the ship as 8 bytes, the record's time as 8, and
  32 bytes that both ends of that one connection work out from its handshake
  and nobody else can (TLS's exporter for the connection, asked for under
  `ship.v1.here`). Those bytes come from secrets both ends make afresh for
  every connection, and nothing is ever resumed, so they are never the same on
  two connections, and someone between two handshakes cannot make them agree.
  A point keeps a record only with its presence on the connection it came on.
  So nobody but the ship can announce its record, and the point knows, for
  each record it holds, the connection the ship itself is on: where the ship
  attends. That stops when the connection closes, when the record runs out, or
  when a newer record of the ship is kept, which names its own connection.
- A point answers five requests. `Announce` carries up to 16 records, each with
  its presence; each is
  checked against the point's own source of keys (in `serve`, the copy of
  Azimuth, which `--lookup-point` needs, or the list `--pretend-ids` gives),
  read on threads that may wait (8 at
  once), and kept in the place of the ship's last if it is believed. The
  clock is read again after the check, which may have waited on the source of
  keys: a record that ran out meanwhile, or that a newer one took over from
  meanwhile, is not kept. The reply says, for each, kept or why not. `Where` names a ship by number; the reply is
  its record if one is held and still good, or nothing. `Seen` is answered
  with the address the point sees the connection coming from. `Introduce`
  asks the point to pass the caller's record to a ship (see Home routers), and
  `Relay` to carry the caller's packets to a ship (see The relay). The
  point keeps records, and who attends where, in memory only, for all
  galaxies or a list, and refuses records of ships of other galaxies.
- A point's bounds (`PointBounds`): 65,536 records, 16,384 moons, 64 moons of
  any one ship; a record still good is never dropped to make room, so a full
  point refuses new ships and says so, and records that have run out are swept
  out when it is full, at most once a second. 256 connections under its
  protocol, apart from the ships' own `max_connections`. 64 requests in hand
  at once, all connections together (`MOST_IN_HAND`: being read, waiting for a
  thread, or being checked; about 1.5 MiB in all), counted before a byte of a
  request is read: past it a request is refused at once, unread. 16 KiB at
  most for a request or reply. Records checked: on one connection 256 at a
  stroke and 256 earned back each `rate_period` (a second unless set
  otherwise), and in all 2,048 at a stroke and 2,048 each `rate_period`,
  counted as a request arrives, before it waits for a thread; questions: 64
  at a stroke and 64 a second on one connection. When a connection closes, whatever its
  requests left waiting stops and gives up its place; a question to the source
  of keys already under way cannot be stopped, is one of the 8, and its answer
  is thrown away. Once a connection has gone, its announcement keeps nothing
  (a record is kept only with the table and a mark of whether the caller is
  still there both held), and asks the source of keys nothing more except at
  most the one question that was already begun, or beginning, as it went. An announcement that is empty, or all of whose records the rates
  refused, is answered at once without waiting for a thread. Once the
  handshake is over, credit given to a lookup connection from then on is held
  to 4 requests in progress and 64 KiB of room to receive; the credit given at
  the handshake (the ships' transport allowance: `max_streams`, and room for a
  whole message on each) stays usable after it, since QUIC cannot take credit
  back. What bounds a point's work is the count of requests in hand and the
  sizes above, not the stream limit.
- A runtime with lookup settings (`Lookup::at`, `Lookup::domain`) announces
  each ship it holds to the point for that ship's galaxy (a planet's star's
  galaxy, a moon's parent's) at start, every `announce_every` (2 minutes), and
  any ship that is new at once, over one connection per point however many
  ships. Which address it announces:
  - Addresses given by hand (`Lookup::announce`, `serve --announce`): exactly
    those. The point is not even asked where it sees the runtime.
  - None given: before each round it asks the point (`Seen`), over the very
    connection it announces on, where it sees that connection come from, and
    announces that address alone. This is what makes `--announce` unneeded on
    most cloud machines and behind home routers: such a machine listens on
    one address and is reached at another, and only something outside can say
    which. The answer is believed only from the point of those ships' own
    galaxy, only over the connection it was asked on, only for that galaxy's
    ships, and only if it is an address a record may carry. If the point does
    not say, or names something a record may not carry, nothing is announced
    that round, the runtime says why (`Network::lookup_trouble`), and it tries
    again after the usual wait. A runtime whose ships sit under two galaxies
    may announce different addresses to each.

  A point that is down or refuses is tried again after `retry_delay`, doubling
  to `max_retry_delay`. The connection the ships are announced over is kept
  open, with a small packet every `keep_alive` (15 seconds), and if it drops
  it is made again and the ships are announced again at once, since a point
  keeps a record only with presence on the connection it came on. A point that
  stops without closing it (killed, or its machine gone) never answers that
  packet; it is watched as every kept connection is (below), so once the
  packet has gone unanswered by anything for `silence_timeout` (3 seconds) the
  connection is closed and made again. Measured on one machine, on loopback: a
  point killed and started again at its address had a ship announced to it and
  found 18.5 seconds after it came back (46 before this was noticed); that is
  about one `keep_alive`, the silence and the announcing, and longer if the
  point is not back by then, since the tries after it follow `retry_delay`.
- A connection this runtime keeps to another ship is watched for as long as it
  is open, by one watcher for it, and given up once nothing comes from the
  other end while something waits on it, not only when it has been idle for
  `idle_timeout`. The watcher reads QUIC's own counters for the connection
  every quarter of a second: what was heard (every frame in a packet that
  decrypted and was not a repeat, acknowledgements included; a packet that
  does not authenticate, or one replayed, counts for nothing) and what was
  asked (every frame built to be sent that the other end must acknowledge:
  everything but acknowledgements and the frame that closes a connection;
  stream data, pings, resets, flow control, and QUIC's own loss probes; a
  socket that cannot send for that long ends the connection too, if nothing
  is heard either: a peer that is still heard from keeps it). Once
  something asked has gone `silence_timeout` (3 seconds) with nothing heard,
  the connection is closed, and every request on it fails at once, saying
  nothing was heard from the ship for that long. The watcher can be late by up
  to two looks (the sending is seen at the look after it, the end at the first
  look after the time is up), plus however late it is scheduled, plus QUIC's
  current probe timeout if a reply and a new request crossed between two
  looks. There is no bound that holds whatever happens: if nothing can be sent
  at all (every stream held, everything sent acknowledged, nothing left to
  send), the clock does not start until something is, such as when a waiting
  request runs out of time and resets its streams, or until `idle_timeout`
  ends the connection. A request that runs out of time never closes a
  connection itself, so a request with almost no time left cannot take a
  working connection down with it. With `request_timeout` shorter than
  `silence_timeout`, a request to a ship that has gone can run out of time
  more than once on the same connection before the watcher closes it. A ship asked something it is slow to answer
  has acknowledged the question and has nothing more waiting on it, so
  slowness alone closes nothing. But a connection that works is closed if
  nothing at all arrives for three seconds while something waits: a link that
  drops everything for that long, or a peer whose process is stopped or not
  scheduled for that long. The cost is a new connection and the request tried
  again; commands are still delivered exactly once. A relay carries only what
  each end sends, so a connection through one is watched the same way, and
  three seconds with nothing from the far ship or from the relay between gives
  it up. Closing fails every request then in flight on it, as any lost
  connection does; a relayed connection lets its session go; a try at going
  direct that began from it finds the entry changed and makes no change. The
  next call makes a new connection, trying the addresses of the record held
  and then asking the point. Measured on one machine, on loopback, with a lane
  not in backoff and one address in the record: a command queued for a ship
  that was killed and is back at another address arrived 6.5 seconds after it
  was queued (in each of five runs), and 3.3 seconds when the ship was back at
  the same address. That is the silence (3 seconds and up to two looks of a
  quarter of a second, plus QUIC's current probe timeout if a reply and a new
  request crossed between two looks), `retry_delay` (200 ms), one try at the address
  in the record held (3 seconds) and a question to the point. What makes it
  longer: a lane already in backoff waits out its current delay first
  (doubling up to `max_retry_delay`, 30 seconds); a record may list up to four
  addresses, each tried for up to 3 seconds; the point answers only once the
  ship has announced to it again; and a relay adds its own share of the call.
- Calling a ship with no address given: first the addresses of the record
  already held for it, if it is still good; then, if there is none or none of
  its addresses answered as the ship, the point for its galaxy is asked, the
  answer checked with keys from this runtime's own directory, kept, and its
  addresses tried. Immediately before each address is tried, and before a new
  question to the point, the directory is read again, in one step, and nothing
  waits between that reading and the attempt: if the re-read sees an address
  given by hand, or a changed key for a galaxy, star or planet, nothing more
  from the record is tried and the point is not asked. A call that overlaps
  the change may still begin one more attempt or question after it, following
  its last check (an attempt already begun cannot be called back, and what it
  makes is refused when it is proved, in one step with the directory). For a
  moon, the key held may have come from the very record being tried, so
  whatever key is held then is let through to the attempt; what decides is the
  parent's word, checked against the parent's key held now when the moon shows
  it on the connection, the key the moon proves, and the check after the
  handshake. If the point's answer is not believed, or no record of it can be
  kept, the call's error says why. Each
  address gets at most 3 seconds, and never more than half the time left (a
  record that asks callers to be introduced is tried as Home routers, below,
  says). All
  of it is within the request's own `request_timeout`. A record none of whose
  addresses answered is not tried again, but holds older records off until it
  runs out. Only the record that was tried is marked so (each record kept is
  named by a number never used for another (when the numbers run out, which
  takes 2^64 records, no more records are kept), so two records made at the same
  moment are not taken for each other); a newer one that took its place while
  the old one's addresses were being tried is left as it is, and is used by
  the next round of this call, if there is one, or by the next call. A
  record's content is kept in two places, and freshness is weighed at each by
  the clock read there under its lock: the record itself, with the records
  held, and a moon's word in it, with the directory held. A clock that moved
  while the record was checked keeps neither if the move made the record no
  longer good; but a genuine word taken while the record was still good stays,
  even if the record is then refused.
  The newest record believed for each ship is kept, for up to 65,536
  ships, and is never dropped for room before it has run out, whether its
  addresses answered or not; when every place holds a record still good, a
  record of a new ship is not believed, and the call says why. A ship is asked
  about at most once every `ask_again` (3 seconds) whatever the answer, one
  question about a ship is out at a time, and at most 16 are out at once. A
  connection made this way is tied to the address that worked. Each time it is
  used again it is proved again in one step with the directory, and that step
  refuses it if an address has been given by hand for the ship: it is closed,
  that call fails as the directory having changed, and the next call goes by
  the address given. A request already under way over it when the address is
  given may finish; none is begun on it after the directory has the address.
  (Between that proof and the first byte of a request there is no lock; that
  interval, which can include waiting for room to open a stream, is the one
  this cannot close.)
- A moon's record carries its parent's word for its key. When a ship believes
  such a record, the word is taken into its directory in the same step, by the
  rules any moon's word is taken by (signed with the key held for the parent,
  only forwards, one key to a revision, a key set by hand never changed); if
  the directory will not take it, the record is not believed. The directory is
  the one memory of a moon's keys at a ship, so a later word seen in a record
  holds at once for calls made, callers taken, and connections already open,
  whether or not any address in the record ever answers. The moon is not
  marked as having proved anything; its parent is kept. The word counts
  against the directory's moon bounds, is never dropped for room or when the
  record runs out, and goes only when the parent's key it stands on is no
  longer believed.
- The point for a galaxy is at the address given for that galaxy, else at the
  one given for all galaxies, else found by looking up `<galaxy>.<domain>`
  (`zod.example.net` for `~zod`) through the system's resolver, or a stand-in
  (`Resolve`) given by a test or a private network. A lookup runs on a thread
  that may wait, at most 4 at once; a caller waits for it 5 seconds at most,
  and a resolver that hangs keeps its thread, and one of the 4 places, until it
  returns. At most 8 addresses
  are taken from an answer and each is tried in turn; an answer is used for
  `resolved_for` (5 minutes), a failure for `ask_again`.
- Home routers. Most homes reach the internet through a router that shares
  one public address among all the machines inside. When a machine inside
  sends a packet out, the router picks an outside port for it and remembers,
  for a while after the last packet (some tens of seconds), that packets
  coming back from that destination to that port go to that machine. A packet
  from anyone else is dropped: the router cannot tell which machine inside it
  would be for, and strangers knocking are not wanted anyway. So a ship at
  home can call out, but nobody can call it, even at the outside address its
  point told it and it announced.

  The way through is for the ship at home to send something toward its caller
  first. Then its router has seen a packet go from that port to the caller, and
  takes the caller's packets as answers to it. That needs the ship to know, at
  the right moment, that someone wants to call it and from where, and that is
  what its point is for: the ship keeps a connection open to its point, which
  its router keeps open because packets keep going out on it, and the point
  can say over it "this caller wants you". This is why two ships sending at
  about the same moment get through where either alone would not.
- How a call to such a ship goes:
  1. A runtime that announces the address its point saw, and listens on a
     different one (behind a router, the router's outside port is not the
     machine's own), puts the flag in its records asking callers to be
     introduced first. With addresses given by hand the flag is clear, since
     whoever runs the runtime has said the ship can be reached, unless
     `Lookup::behind_router` (`serve --behind-router`) says otherwise.
  2. A caller about to try a record with the flag first asks that ship's point
     to introduce it (`Introduce`), sending its own record, signed just then
     at the addresses it announces itself at, and its presence on that
     connection. The point checks both as it checks an announcement (the same
     admission, threads and rates) and keeps nothing. If the ship attends on
     a connection that is open, the point passes the caller's record to it
     over that connection, on a stream of its own, and answers "passed on"
     without waiting for the ship. It never sends anything to an address out
     of a record. The caller's own announcer signs records from the same
     clock and sends them over another connection, so one signed a moment
     after the request's may reach the point first, and the point then
     refuses the request: it already holds a record of the caller as new or
     newer. On that refusal alone, in those words, and only if the call's time
     has not run out, the point is asked once more, the record signed afresh
     (later than any this runtime has signed) with its presence on the
     connection it then goes over, within the same wait for the point's
     answer, and with no pause first. Never more than two rounds of asking,
     each as one question to a point has always gone: its addresses tried in
     turn until one answers. With one address, the usual case, that is two
     requests, and a point that always answers so gets two; with a list of N
     addresses that does not change between the rounds it can be up to 2N
     requests, each with a record of its own signed, all within that same
     wait (the list is read again for each round, so in general as many as
     the two lists hold together). The second round starts again at the first
     address of the list as it then is, so one that failed in the first round
     may spend part of the wait before the one that refused is reached again.
     Whatever the second round brings is the answer. Each request faces the
     same allowances at the point as any does, in the same order (a question,
     a record against the record rates, one of its allowance of introductions
     or of sessions made, each charged only if the one before let it by); the
     caller's own allowance is charged for the first only if it was refused
     after its presence was checked, because the record the point held
     changed meanwhile. Any of these still empty when the second request
     reaches it (the caller's last token, a point that is busy, or limits set
     as low as one; they fill again with time) can have the second refused
     for that limit. An announcement that overtakes the second request too
     leaves the call where a refusal leaves it.
  3. The ship checks the caller's record itself, as it would any record: keys
     from its own directory, fresh by its own clock. If it believes it, it
     sends three packets of four bytes from its own port to each address in
     the record, a quarter of a second apart, and nothing else. It keeps
     nothing of the introduction and does not call the caller.
  4. The caller does not wait for that. It dials the ship's address as for any
     record. Its first packet may reach the router before the ship's packets
     have opened the way, and is then lost, but QUIC sends it again about a
     second later, and by then the way is open. So an attempt at such a record
     is given 4 seconds, not 3 (and never more than three quarters of the time
     left), and the caller waits for the point's "passed on" for at most a
     second (and at most a quarter of the time left). A point that refuses, or
     says nothing, does not stop the attempt.
  5. Everything after the connection is made is as for any connection: the key
     the ship proves, a moon's word, the checks against the directory. Nothing
     on the way (the point's word, the introduction, the four-byte packets) is
     believed about who anyone is. The four-byte packet is no QUIC packet:
     any QUIC endpoint drops it without answering, and nothing is done on
     receiving one.
  6. A router forgets an idle opening sooner than a connection with nothing on
     it is closed. So a connection made on a record with the flag also sends a
     small packet every `keep_alive`, and the routers keep the way open for as
     long as it lasts.

  Two ships each at home can call each other this way when their routers are
  of the usual kind, which give a machine inside the same outside port
  whoever it sends to. Routers of a stricter kind give a different outside
  port for each destination: the port the point saw is not the one the ship's
  packets toward the caller leave from, and the caller's packets arrive at a
  port that lets in only the point. No amount of sending at the same moment
  opens such a router to a caller, because the caller can never learn the port
  that would be opened. Such a ship is reached through its point's relay,
  below, where the point relays; where it does not, the call fails in its
  time, saying the ship could not be reached directly and that its point does
  not relay.
- The relay. What every ship can always reach is its own point: it keeps a
  connection open to it, which its router keeps open. So when the direct way
  fails, the point can carry the two ships' packets between them. The
  connection between the two ships is still an ordinary ship-to-ship QUIC
  connection, end to end, with every key check there is (the key the ship
  called proves, the caller's `Hello`, a moon's word, the checks against the
  directory). The point sees only encrypted packets: it can drop, delay,
  repeat or misdeliver them, and nothing more. Nothing it says about a session
  is believed about who anyone is (`runtime/src/relay.rs`).

  On the wire a relayed packet is one UDP datagram to or from the point's
  ordinary port: one byte, `0x15`, the 16 bytes that name the session, then the
  ships' QUIC packet as it is. The first byte has neither of its two top bits
  set. A QUIC packet's first byte always has one of them (the long-header bit,
  or the "fixed bit"), unless the fixed bit has been cleared as a "grease",
  which QUIC does only toward a peer that has said it takes such packets. A
  runtime with lookup settings tells QUIC not to grease: it then never says it
  takes them, no peer clears the bit toward it, and its endpoint refuses any
  packet with the bit clear. So nothing its QUIC endpoint would take can be
  taken for a relayed packet, by construction and not by odds. (The four-byte
  packet that opens a router begins with a nought, which `0x15` is not.) A
  runtime with no lookup settings keeps QUIC's settings and its socket exactly
  as they were.

  The work is done by a wrapper around the runtime's UDP socket, there
  whenever the runtime has lookup settings. At a ship, each session has a
  made-up address: QUIC is told to dial it, or sees the other ship's packets
  come from it. A packet QUIC sends there is wrapped and sent to the session's
  point; with no session for it, it goes nowhere. A made-up address is never
  handed to the real socket. A datagram that carries the first byte and a
  session this ship registered, from that session's point, is unwrapped and
  shown to QUIC as from the made-up address; one that names no session here,
  or comes from anywhere but its point, goes no further, and nothing is sent
  in answer. A datagram that says it comes from a made-up address is dropped
  too: none can arrive from a real network, and it must not pass for a
  session's. Everything else passes as it always did, the ship's own
  connection to that same point included. The made-up addresses are the IPv4
  limited broadcast address, `255.255.255.255`, for a socket on IPv4, and
  `ff00::1` (a multicast address of the reserved scope nought, which nodes
  must not send to) for one on IPv6, each with a port that tells one session
  from another: no record may carry either (records refuse broadcast and
  multicast), routers never pass either on, and a socket that has not asked
  for broadcast cannot even send to the first. QUIC will not dial an IPv6
  address on an IPv4 socket, which is why the family follows the socket's. A
  made-up address is never handed to the real socket, whatever asks for it (a
  packet for one is dropped at the one place anything is sent), is never taken
  as a session's point, never connected to as a lookup point, and never dialed
  for a ship whose address is set by hand ("an address no ship can be at"). An
  address let go of is not given to another session while the handle of the
  session that had it lives, and then not until nothing has been sent to it or
  come from it for the idle time and a minute more (a send by QUIC counts).
  That is all it establishes: QUIC's closing and draining take three probe
  timeouts, which depend on the path. A stale packet that did cross a reuse
  would be another connection's packet to the far ship, which cannot decrypt
  it, and no check of who anyone is depends on it.
- How a relayed call goes:
  1. The caller tries as above: the introduction, then the record's addresses.
     When a relay may follow (the record asks for introductions, and the
     caller has a record of its own to show), all of that direct work ends five
     seconds into the call, or half way through it, whichever is sooner, so
     that the relay always has room. A hole that opens does so within about one
     Retry round trip and one resending of the first packet, about a second;
     five seconds leaves room for real distances.
  2. If nothing answered, the directory is read again (an address set by hand
     wins, as before every question), and the caller asks the ship's point to
     relay (`Relay`): the ship's name, its own record signed just then, and its
     presence on that connection, exactly as for an introduction, and asked
     once more on the same refusal, in at most two rounds, as an introduction
     is. It waits at most a second, and at most a quarter of the time left,
     for both rounds together.
  3. The point refuses, saying so, if it does not relay. Otherwise it checks
     the record and presence as it checks an introduction (the same admission,
     threads and rates, keeping nothing), and with its table held makes a
     session: sixteen bytes from the system's randomness, and two addresses
     pinned then and never changed: the remote address of the connection the
     ship called attends on, and the remote address of the connection the
     request came on. It refuses unless the ship attends there at that moment
     and its own record asks callers to be introduced: a ship that says it can
     be reached directly is not relayed for. It passes the caller's record and
     the session to the ship over the connection it attends on (the same way,
     and within the same bounds, as an introduction), and answers the caller
     with the session. It does not wait for the ship.
  4. The ship called weighs the caller's record exactly as it weighs an
     introduction (its own directory and clock, what it already believes of
     the caller, a moon's word by its own rules, nothing kept), under the same
     allowance for weighing, and only for a ship of its own last announced
     asking for introductions. Then it registers the session, bound to the
     point at the other end of the connection the push came on: at most 8 for
     any one caller ship and 64 in all, dropped when nothing has passed for 30
     seconds and when that connection closes. It sends nothing.
  5. The caller reads the directory again, registers the session (at most 256
     of its own), and dials its made-up address with the rest of the time, on
     a connection that keeps itself alive and keeps its packets small enough
     for the header. The ship called answers it as any caller: with a Retry,
     the handshake, the `Hello`, every limit on callers. Whatever answers must
     prove the ship's key. A connection made this way is marked as relayed
     where it is kept, and holds its session for as long as it is kept.
  6. If the point refuses or says nothing, or nothing answers through it, the
     call fails in its time, saying what was tried and why (the point does not
     relay, refused for a limit, did not answer, or nothing answered through
     it).

  A record whose addresses did not answer and whose ship the relay did reach
  is remembered (by the number it was kept under, for 1,024 records), and the
  next call on it goes straight to the relay, asking for no introduction; when
  the record is replaced, the next call tries the direct way first again.
- At the point, a relayed datagram whose session is live, from exactly one of
  its two pinned addresses, is sent on to the other unchanged, and only if
  that side is still there: toward the ship called only while it still
  attends on the connection the session was made toward (weighed as passing
  an introduction weighs it); toward the caller only if the caller has itself
  sent on the session from its pinned address in the last 30 seconds (or the
  session was made in the last 5). A session nothing has been carried on for
  30 seconds is dropped, and so are the sessions toward a ship whose
  connection closes or whose newer record names another connection. Anything
  else is dropped, and none of it reaches the point's QUIC. This is done where
  the datagram is received, with a send that never waits: nothing is queued,
  and nothing waits; the work is a look in the table and a few counts, with
  the table held, so no packet is carried on a session after the point has let
  it go. What goes out is exactly what came in. So nobody can aim a point at
  an address: it sends only to the two addresses of a session, each the remote
  address of a connection to the point that has answered from there (the point
  sends a Retry to every new caller), the caller's the one it asked from, and
  only while whoever is there is still asking for it.
- A point relays only if whoever runs it says so (`PointConfig::relay`,
  `serve --relay`), and only within bounds (`RelayBounds`), which are what
  bound the bill. A packet over an allowance is dropped, and the ships' QUIC
  slows down as it does for any loss.
  - Bytes carried for any one ship called, in both directions of all its
    sessions together: 256 KiB at a stroke, and 128 KiB earned back each
    second, up to 256 KiB again (`serve --relay-ship-rate`, with a burst of
    twice that).
  - Bytes carried in all: 8 MiB at a stroke, and 4 MiB earned back each
    second, up to 8 MiB again (`serve --relay-point-rate`, the same way).
  - Sessions live: 16 for any one ship called, 16 for any one caller, 2 for
    any one caller and ship called together (so that a caller that lost its
    session can make another before the old one idles out), 1,024 in all.
    Sessions made: 4 for any one caller at a stroke and 4 earned back each
    `rate_period`, and 512 at a stroke and 512 each `rate_period` in all. For
    the caller's counts and allowance, a moon counts as its planet: moons are
    free to whoever has a planet. A moon called is its own ship.

  So in any span of T seconds the point sends at most 8 MiB + 4 MiB x T in
  all, and at most 256 KiB + 128 KiB x T on behalf of any one ship called. A
  packet is sent only once both allowances have been charged with it, and
  after the send, with the table still held, the clock is read again and both
  allowances' refill stamps are moved up to it, so nothing is earned for the
  time the send took. Then for a span [a, a + T]: an allowance holds at most
  its burst B when the span begins and earns at most its rate r times T within
  it; a packet charged before a and sent after it was paid for out of what the
  allowance held when it was charged, with nothing earned between its charge
  and its send, so it and what follows come to at most B + r x T. Toward any one pinned address, what goes out is at
  most what the session's other address sent in, and at most 256 KiB + 128
  KiB x T for each ship called that has a session pinning that address; since
  several ships may sit behind one address, the overall figure is the only
  bound for an address as such. A request to relay is weighed cheapest and
  narrowest first: whether the point relays; the connection's allowance of
  questions; whether the ship attends; the record rates; the point's
  allowance of sessions made; then, on a thread, the record and presence, the
  caller's own allowance, and with the table held the rest. A refusal says
  which limit it met. The allowances of sessions made are charged as requests
  are admitted, before the checking work, which is what they are there to
  bound; so the sessions actually made in any span of T seconds are at most
  the burst plus the refill times T plus those admitted and not yet made. In
  all, those are the requests in hand, at most `MOST_IN_HAND` (64): at most
  512 + 512 x T/`rate_period` + 64. For one caller, its own allowance is
  charged on a checking thread, after its presence is checked, so those not
  yet made are at most the 8 checking threads: at most 4 + 4 x
  T/`rate_period` + 8. The caps on sessions live are what bound the bill;
  these bound how fast sessions come and go. `PointStatus` shows the sessions live, the requests to
  relay heard and the sessions made, the bytes carried and dropped for each
  reason (no such session, from a stranger, toward a side that is not there,
  over the ship's allowance, over the point's), and the bytes carried for each
  ship called while it has a session.
- What it costs a call: a ship behind a strict router, or two such ships, is
  reached after the direct share (five seconds, or half the call) and one more
  trip to the point, through which the connection then runs, by way of the
  point, at every packet. The next call on the same record goes straight to
  the relay.
- Going direct again. While a kept connection goes through a relay and is in
  use, the caller tries the direct way again every `direct_again` (60
  seconds, at least 2), by the path any call takes (the record, an
  introduction, each address, the directory read again before each), at most
  one try for a pair at a time and 16 in all. The ship called takes the
  direct connection as it takes any newer connection from the same calling
  ship: it replaces the older at once, so the relayed connection is closed
  from that end as soon as the direct one is taken. So a connection a try
  makes takes the relayed one's place, with the pair's slot held (waited for
  no longer than the try's own deadline), if the entry kept is still the very
  one the try began from (whether or not it has closed since), the route still
  fits, and it is proved again in one step with the directory, as any kept
  connection is; the relayed connection is then closed here too, and its
  session let go of. A request under way on the relayed connection at that
  moment fails as any request on a closed connection does; commands are
  delivered exactly once all the same, by the redelivery that already exists.
  A try that fails before the ship called has taken its connection changes
  nothing (no record is marked failed, no key doubted) and costs only its
  packets. One that fails after (its last proof fails because an address was
  set by hand or the key changed meanwhile, or someone else remade the kept
  connection meanwhile) closes its candidate, and if the ship called had
  already closed the relayed connection, the pair has no working kept
  connection until the next call makes one. The point's and the ship called's
  ends of the session go idle and are dropped after 30 seconds.
- A ship that announces no record of its own (on a runtime that announces
  nothing, or whose point has not taken its record) cannot be introduced or
  relayed: it tries the addresses anyway, which works only if the ship it calls
  can be reached without.
- Bounds on introductions, at the point (`PointBounds`): `introductions`
  (512) passed on at a stroke and 512 earned back each `rate_period`, in all,
  and `introductions_each` (4 at a stroke, 4 each `rate_period`) for any one
  caller, which only that caller can spend, since it takes the caller's
  presence; the caller's record also counts against the record
  rates, as an announcement's does. A request to introduce is weighed in this
  order, cheapest and narrowest first: the connection's own allowance of
  questions (as for `Where`), before the point looks at who attends; then
  whether the ship attends; then the record rates, the connection's and then
  the point's; then the point's allowance of introductions. 4 introductions
  waiting for any one ship
  and 16 for any one connection, each for at most 3 seconds; one passed at a
  time over a connection, each given at most a second; counts kept for 4,096
  callers. A refusal says which limit it met. At a ship: the point may have at
  most 4 streams open on the connection at once, each read for at most 2
  seconds and 576 bytes; 8 introductions wait to be weighed and the rest are
  dropped; each is weighed within 5 seconds, a question to Urbit ID included;
  32 are weighed at a stroke and 32 earned back a second. The packets are sent
  only for a ship of this runtime's last announced asking for introductions.
  What limits the packets: an introduction is acted on only once it holds one
  of 16 places among those under way, taken first and kept until its last
  packet, and then only within an allowance for its caller ship (2 at a
  stroke and 2 earned back a second) and one in all (16 at a stroke and 16 a
  second). The allowance is per full ship name, so each moon has its own.
  Each introduction acted on sends three packets to each of the caller's
  addresses (at most four, so at most twelve), a quarter of a second apart.
  So the packets in any span of T seconds come from introductions holding a
  place when the span begins (at most 16) or charged within it (at most
  2 + 2T for one caller ship, 16 + 16T in all), however busy the machine is:
  at most 12 x (16 + 2 + 2T) = 216 + 24T packets attributable to one caller
  ship, and 12 x (16 + 16 + 16T) = 384 + 192T in all. Kept up, that is 24 and
  192 packets a second, but not in every single second. Each record may name
  four new addresses, so the distinct addresses reached are at most 72 + 8T
  for one caller ship and 128 + 64T in all (8 and 64 a second, kept up).
  Several ships may name the same addresses, so what any one address can
  receive is bounded only by the figures in all. Counts are kept for 1,024
  callers. A caller's
  key is looked up as any caller's is, under the same limits. The record is
  weighed against what this runtime already believes of the caller (the
  newest record it holds for it, and for a moon its parent's word by the
  directory's own rules, a key set by hand for the moon included), as an
  ordinary lookup would, and nothing of it is kept. Where it differs from an
  ordinary lookup: an introduction of a caller whose address this runtime has
  set by hand is still acted on, and the packets go to the addresses in the
  caller's own signed record, while every call to that caller still goes to
  the address set by hand, and nothing is kept; since nothing is kept, an
  introduction is not refused for want of room to remember a moon or a
  record, as a lookup would be; its freshness is weighed once, not again where
  something is kept; and there is no limit in time on when a job's packets go,
  only the limits stated above.
  `Network::introductions` says how many introductions were heard, how many
  were weighed, how many acted on, and how many packets sent.
- With none of these settings, as by default, nothing of this is sent,
  listened for, or kept.

### Wire messages

A `PeerRequest` holds one of the following, and the `PeerReply` holds the
matching answer, or only `refused` with a reason.

| Request | Reply | Purpose |
| --- | --- | --- |
| `Ping { nonce }` | `Pong { nonce, ship, caller, incarnation }` | Who are you, who do you take me for, and which copy of yourself are you |
| `Deliver { messages }` | `Delivered { last }` | Numbered commands and receipts, in order. `last` is the highest number the receiver now holds. A command with `reply` set wants the handler's reply on its receipt (`Receipt.reply`) |
| `Fetch { agent, log, after, max_bytes, joining }` | `Fetched { entries, head, checkpoint, denied, incarnation }` | Entries of a log after `after`, as signed; or the checkpoint if they were dropped; or a refusal |
| `News { logs }` | `Heard { unknown }` | The publisher says these logs grew (or are closed to you). The follower says which it no longer follows |
| `Resync { standing }` | `Resynced { standing }` | Two ships say where each stands, to get back in step after a restore |
| `Hello { ship, proof }` | `Welcome { proof }` | First on every connection: which ship is calling. Each side sends its moon proof if it is a moon |
| `file_about: FileWanted { agent, id }` | `file_about: FileFacts { denied, length, media_type }` | What a file is |
| `file_leaves: FileWanted { agent, id, index }` | `file_leaves: FileHashes { denied, hashes }` | The chunk hashes of group `index` (chunks `index * 32768` on), 32 bytes each, one after another |
| `file_upper: FileWanted { agent, id }` | `file_upper: FileHashes { denied, hashes }` | The index hash of every group, for a file of more than 32,768 chunks |
| `file_chunk: FileWanted { agent, id, index }` | `file_chunk: FileBytes { denied, data }` | Chunk `index`, whole |
| `ask: Ask { from_agent, agent, interface, payload, within_millis }` | `ask: Answer { reply \| denied \| failed \| limit }` | A question for an agent's read handler, from an agent on the asking ship (or, with `from_agent` empty, its owner). Exactly one of the four in the answer; see Questions between ships |

A refusal of a file is `denied` alone, the same words whatever the reason. An
older runtime answers the four file kinds with `refused`, as any kind it does
not know, and a question (field 11) the same way, which the asker reports as
not understood. A ship too busy for a question answers the bare `refused: "too
busy; try again"`.

A request holds one body, of one kind. For every request after the greeting
(the first stream's `Hello`, which is read and bounded on its own, at most
1,024 bytes), before anything is decoded, in this order: room to read it into (else "too busy; try again"); the whole request
read within `max_message_bytes` (else "the request could not be read, or was too
large"); the caller checked again (else the connection is closed); its body
fields counted by walking the encoded fields, without decoding or keeping
anything, and a request with more than one (two kinds, or one kind twice) is
answered `refused: "one request at a time"`, whatever the kinds; and a request
for a part of a file over 1,024 bytes is answered `refused` there and then.
Only then are an earlier kind's repeated messages counted (at most 256 in a
delivery, 256 logs in a piece of news) and the request decoded. Every bare
`refused`, of any kind and for any reason, and every file's `denied`, is written
only after the request's room for reading, and everything of it the asking
ship sized, have been given back. An earlier kind's reply that carries a body (a
log fetch's `denied` among them) is written with its room held, as before.

To a lookup point, under `ship-where/1`, a `WhereRequest` holds one of these,
and the `WhereReply` the matching answer, or only `refused` with a reason.

| Request | Reply | Purpose |
| --- | --- | --- |
| `Announce { records, presence }` | `Announced { outcomes }` | Up to 16 encoded `Whereabouts`, each with its ship's presence on this connection. For each, empty if kept, or why not |
| `Where { ship }` | `Found { record }` | The ship's record as the point holds it, or empty if it holds none still good |
| `Seen {}` | `Saw { address }` | The address the point sees this connection coming from |
| `Introduce { callee, record, presence }` | `Introduced {}` | Pass the caller's record, with its presence on this connection, to the ship named, over the connection it attends on |
| `Relay { callee, record, presence }` | `Relaying { session }` | Carry the caller's packets to the ship named and back, under a session of 16 bytes; the caller's record and the session are passed to the ship |

From a point to a ship, on a stream the point opens on the connection the ship
attends on: `Introduction { callee, record, session }`, the caller's record for
the ship named, and for a relay the session. Nothing in it is taken on the
point's word.

A relayed packet is not a message: it is a UDP datagram of the byte `0x15`, the
16 bytes of the session, and the ships' QUIC packet (see The relay).

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
- A command can ask for the handler's reply (`SendRequest.reply`; the SDK's
  `send_to_for_reply`). It then carries the largest reply its sender takes
  (`PeerMessage.reply_most`, the sender's `store::reply_most` when it sent it,
  kept with the waiting command so a later change of settings cannot shrink
  it; this, and the receipt fitting one delivery below, hold while the limits
  in force are not made smaller than they were when the command was sent: see
  Known limits). The ship that runs it holds the reply to the smaller of that and its own
  limit. Its receipt then says `RAN` and carries the whole reply, marked as one
  (`Receipt.reply` and `Receipt.replied`, so an empty reply and no reply are
  told apart), or the command did not stand: the event is rejected like any
  other that breaks a limit (everything it did undone) and the receipt says
  `LIMIT`, in fixed words, when the reply is larger than either ship allows
  ("the reply is larger than that ship sends with a receipt") or would have
  left its file without the room it keeps for taking a command back and
  finishing with it ("that ship had no room to keep the reply"). Every other
  verdict, and `LOST`, carries no reply.
  The whole reply comes back with RAN from a receiving ship that follows the
  protocol. A receipt can say RAN with `Receipt.replied` unset when the other
  ship's runtime predates replies, or when it broke the protocol (a reply over
  the bound the command was sent with, or a reply not marked): the command is
  still reported as run, because the other ship said so; no reply is handed
  on; and when a reply came and was let go, the reason says so. An agent that
  needs the reply checks `Receipt.replied`.
  A ship that takes back no reply at all (`max_receipt_reply_bytes` 0, or a
  queue too small for any receipt with a reply, 592 bytes or less) does not
  send a command that wants one, since 0 in `reply_most` means no reply is
  wanted; the send is refused there ("this ship takes back no reply ..."),
  and the event with it. A command without `reply` is the same bytes on the wire as before,
  apart from the absent field.

Room for a receipt with a reply, with its working:

- How large: the reply is held to `max_receipt_reply_bytes` (16 KiB), and to
  no more than a command may carry (`max_event_bytes`) or than a ship takes
  from another as one message (its queue, and a quarter of its file, less the
  receipt and 64 bytes) (`store::reply_most`), on both ships (the bound the
  command carries). So a receipt with its reply is at most 528 bytes more than
  the reply, never larger than the largest command with its own receipt.
- On the ship that runs the command: the room it keeps for every receipt it
  owes is unchanged (512 bytes each), because a reply goes with a receipt only
  if, after the receipt is written, the file still has the room it keeps for
  taking one command back and finishing with it (`room_to_take_one`), or the
  receipt took no room. So reply bytes never use that room, and the working
  that keeps two ships full of commands for each other moving is as it was.
  The cost: a ship short of room answers commands that want replies with
  `LIMIT` until it has room again.
- In a `Deliver`: a batch always carries at least one message, and the largest
  receipt is no larger than the largest command, which `Network::start` sees
  fits one message with room to spare (4 KiB), so a receipt fits one, as long
  as the limits are not made smaller while it is outstanding (Known limits).
- On the ship that sent the command: the receipt is taken as every receipt is,
  queued for its agent as a `KIND_RECEIPT` event within the queue's room (one
  that does not fit waits with the other ship). Its reply takes room in the
  file only while that event waits: running it, or refusing it, removes its
  row, and its audit row keeps bounded facts only (its number, verdict, where
  it went, and the reply's length, at most 512 bytes), on the success path and
  on every rejection path; the same holds for an answer to a question
  (`KIND_ANSWER`). (What the agent's handler keeps is the agent's, as for any
  event.) So replies taken use the sender's file only while queued, at most a
  queue's worth (`max_inbox_bytes`) at once, and give it back when run. Two
  ships full of commands for each other each keep, by the rule on sending, the
  room to take the other's first command; replies taken from third ships can
  use it only until their events run, which needs nothing from either ship,
  so it comes back and the two meet as before. A receipt whose reply breaks the
  protocol (not `RAN`, not asked for, or over the bound the command carried)
  is handed on without it, with a reason saying so, and that is written to the
  audit log; a ship that keeps to the protocol never sends one.
- Export and import: a command keeps the bound it was sent with, which a
  later, lower setting does not shrink, so import checks kept bounds, and
  receipts with replies (queued, or owed to another ship), against a fixed
  ceiling that no configuration may pass (`store::MOST_RECEIPT_REPLY_BYTES`,
  1 MiB; `max_receipt_reply_bytes` is held to it when a runtime opens) and
  against the queue's total, not against the setting of the day. So a ship's
  own export, written by this version, comes in under its own settings after
  its limit on replies was lowered (though delivering a receipt held over
  such a change is not supported: Known limits). (Files written by earlier, uncommitted
  versions of this schema are not supported.) Import's row bound covers the
  ceiling, so it is at least 4 MiB and 64 KiB whatever the settings. In the same way a queued
  answer is checked against `store::MOST_ANSWER_BYTES` (4 MiB) and a
  question's payload against `store::MOST_ASK_BYTES` (1 MiB), the ceilings
  `max_answer_bytes` and `max_ask_bytes` are held to; every bound import works
  out is worked out without overflowing, whatever the settings. Comparing
  notes after a restore and `LOST` make receipts of their own, with no reply.

| Verdict | Meaning |
| --- | --- |
| `RAN` | It ran, and what it did is saved |
| `DENIED` | Not allowed: no such agent, or the interface is not open to other ships. The kernel's reason is passed on |
| `FAILED` | The handler crashed, ran out of fuel, or took too long. Only fixed words are sent; details stay in the receiving ship's audit log |
| `LIMIT` | It hit one of the receiving ship's limits |
| `MALFORMED` | It could not be run at all |
| `LOST` | Made up by the sender's own ship after a restore, when nobody can say whether it ran |

### Questions between ships

A command changes things, runs exactly once, and answers with a verdict (and,
if asked, the handler's reply). A question is the other kind of call: it only
reads, may be asked any number of times, and answers within a time limit or
says why not. Code: answering in `ship.rs` (`Ship::answer_ask`) and `net.rs`
(`answer_question`), asking in `net.rs` (`put_question`, `pursue`), writing down
what came of an agent's question in `ship.rs` (`Ship::ask_answered`), shared
pieces in `ask.rs`, the route in `server.rs`.

**Who may ask.** Both owners agree. The interface asked must be marked
`Provide.asked`, apart from `remote` (commands): an owner can open one without
the other. An agent that asks needs a `Use` naming the ship (or `*`), agent and
interface with `ask` set. Another ship's owner, asking through one of their
devices, needs only `asked`. What each ship may be told is then the agent's to
decide: its read handler is told who asks in `Invocation.source` (`ship` the
asking ship, proved on the connection; `agent` the asking agent, empty for an
owner; `owner` never set).

**Answering.** On the ship asked, in `answer_question`, after the checks every
request has (see Wire messages): a question whose payload is larger than
`max_ask_bytes` (and than one message carries) is answered `limit`, and one
whose names are not names `denied`, before anything is looked up; then it
takes a place and an allowance (below) or is told "too busy; try again". The
request's room for reading is given back, and a blocking job answers it. Its
deadline is the moment it arrived (one reading of the clock, taken when its
stream is taken up, before it is read) plus the shorter of `ask_millis` (2,000 ms) and the
asker's `within_millis`, so waiting for the ship and the kernel's decision are
inside it, and however late the job is run, the deadline is never earlier
than that.

Waiting for the ship (`Inner::with_ship_question`): the job does not block on
the ship's lock. It tries for it, and for a place among the ships kept awake
if the ship is asleep, every 5 ms (`QUESTION_LOOK`), and gives up, with
nothing run, at the first of those looks that finds the question's time has
passed ("it took too long") or the asker has given up (it stopped the stream, or its connection was lost:
nothing is said). With the ship in hand, it checks both again, and whether the
ship is resting from questions (below): too busy. Then, if the ship was
asleep, it is woken for the question alone: its file opened and checked and
its kernel loaded, and nothing else. The upkeep owed when a ship is first woken
(clearing what an earlier run left in its directory, and a batch of its trash)
is not done on a question's path; it is left for the next ordinary call on that
ship, or the startup look. Waking can be slow, so the asker's giving up and the
question's time are looked at once more just before the handler would start:
either, and no handler runs. However the question ends (an answer, an error,
or a panic), the ship is let go as an ordinary call lets it go: a place among
the awake ships taken for a ship that was not woken is given back, a
connection left in a transaction is closed, and, for a question admitted past
the look at the rests, the time from that look is charged to the rests
(below). Questions are given no turn against ordinary work: a ship
kept busy by ordinary calls leaves its questions waiting until their time,
when they end "it took too long" (or, refused before, "too busy").

No module is compiled on a question's path either, and a question waits for
no compile. If the ship's kernel, or a module the kernel has let the question
reach (the agent asked, or an agent it reads from in turn), is not already
compiled, or is being compiled by another caller, the question is answered "too
busy; try again", which the asker already retries within its time; so is a
question that finds the cache of compiled modules held by another caller just
then (only ever briefly: nothing is compiled, and no module file read or
written, while it is held). This is the side that answers questions: the
owner's own question over HTTP is first signed in by an ordinary call on its
own ship, which, like any ordinary call, waits for that ship and for its
kernel to be compiled. A module not compiled is then compiled off the
path, in a job of its own (`Runtime::compile_cold`): at most one such compile
at a time in the runtime (another met meanwhile is not done, and is met again
by the next question that needs it).

Every caller shares one record of what is compiled and what is being compiled
(`Modules` in `lib.rs`): an ordinary call, `add_module`, or a compile off a
question's path. One module is compiled by one caller at a time, whoever asks;
an ordinary call that needs a module another caller is compiling waits for
that compile (it would have compiled the module itself), and a question or a
compile off a question's path goes without. Whoever wins the right to compile
looks again first, so a module compiled meanwhile is not compiled twice, and
the right is given back by a guard however the compile ends, a panic included.
A module whose file is read and checked against its hash and then fails to
compile is remembered as failing, with why, and is not compiled again by an
ordinary call or a question in the runtime's life (an ordinary call for it
fails at once, in the same words); only the owner's explicit `add_module` of
those bytes tries it again. A failure for want of memory is remembered the
same way, until a restart or such an `add_module`. One whose file cannot be
read is not remembered, since that costs a failed read, not a compile. What is remembered is therefore bounded by the module files
stored. The cache of compiled modules is never emptied, so what another ship
can cause is this: each module stored that its questions reach, the kernel
first, compiled at most once in the runtime's life, one at a time, and a read
of a file that is not there for each question that names one.

Then the agent's read handler runs as a `KIND_READ` call from that ship,
through the kernel, read-only (every write, send, emit, ask, log change and
`file_mark` is refused), with its ordinary read grants and none to send or ask,
and that time, inside a transaction that is always rolled back. One compute
budget, `ask_fuel` (100,000,000), pays for the whole question: the kernel's
decision (each at most `kernel_fuel`, as always), the handler, and every nested
read with its own decision. The answer is the reply (at most
`max_answer_bytes`, 256 KiB, and what one message carries), or `denied` with
the kernel's reason, or `failed` or `limit` in fixed words: a handler that
traps, runs out of fuel or time, or tries to change something is "the agent
failed", "it ran out of fuel" or "it took too long"; a reply too large is "the
answer is larger than that ship gives". The answer is written with nothing of
the request held, and the ship rests.

**Nothing is kept on the ship asked.** No row, no audit row: not for an
answer, nor for a refusal or a failure, as for a file question. So a failure's
details are kept nowhere (see Known limits). Nor does a question change
anything a ship does when it is first woken: that upkeep waits, as above.

What a question does leave behind. In memory: the asking ship's allowances and
the ship's rests (above); its place while it runs; the ship it woke, kept awake
like any ship woken until it is put to sleep; and a module compiled for it off
its path, or a compile failure remembered (above). On disk. A question stores no
application data. Opening a ship for it, or putting another ship to sleep to
make room for it, can recover a transaction that a crash interrupted, copy pages
that ordinary work had already committed from the log beside the file into the
file, and create or remove the files SQLite keeps beside the ship's file. Beyond
that housekeeping, which any open of the file would do, a question changes
nothing in the file: on the ship asked it executes no statement that changes a
page (no reservation, counter, audit row or rest is written to the file; its
rests and allowances are in memory), and its transaction is rolled back. A ship
never opened by ordinary work since it was published is still in SQLite's older
rollback mode, and a question's open leaves it so (switching would write the
header; the first ordinary work switches it). A ship in WAL mode has SQLite's
two files beside its own, `-wal` and `-shm`, while any connection has it open:
on a clean file the question's connection reads through them and adds nothing to
the `-wal`, for the reason above. When the last connection on a ship closes,
SQLite copies what the `-wal` holds into the file and removes both: what is
copied then is what ordinary work committed before, not anything of the
question's. The tests compare the whole file, byte for byte, before a question
and after it with the ship put to sleep again (its file closed, so nothing is
left in a `-wal`): for a ship just created and for one brought in from a copy,
each first called by a question (in the older mode, never opened by ordinary
work, and still in it after), and for that copy once ordinary work had switched
it to WAL. That shows the bytes of a cleanly closed file are the same after; it
cannot see a write that is put back before the file closes, and it does not
cover a file that needs crash repair.

**Bounds on the ship asked, with their working.** A caller must not be able to
hold a ship, or its threads, or the runtime's room for reading requests:

- Places: at most `max_asks_each` (2) questions from any one other ship and
  `max_asks` (8) in all are being answered at once, running or waiting for
  their ship, all ships of the runtime together. Each holds one of the
  network's `max_working` (16) places for work on ships while its job runs or
  waits, so questions hold at most 8 of the 16, and commands, receipts and
  logs keep the rest. A question's place is given back when its job has
  returned and its answer has been sent or its stream reset, whichever is
  later. A question given up on gives its place back within one look (5 ms,
  and the time the thread takes to be scheduled) of the asker giving up while
  it waits for its ship or for a place among the awake ships; once it has the
  ship, its handler runs until it is stopped for time (never before its time,
  and no number promised for how far past it; see Time) or returns. So a place
  is held for the question's time (at most `ask_millis`), however far past it
  the handler runs before it is stopped, and then `request_timeout` to send
  the answer; and its job keeps it through what cannot be cut short (a host
  call under way when its time comes, and opening a ship's file for it),
  however long that takes. (The network stops waiting for the job
  250 ms after its time and answers "it took too long"; the job's place is
  given back when the job does return.) The tests see places come back within
  500 ms of the askers giving up.
- Allowances: questions are started (an allowance charged at the rate limiter,
  before the question's job waits for the ship) for any one other ship at most
  `asks_per_second_each` (8) at a stroke and then 8 more for each second, and
  `asks_per_second` (32) at a stroke and 32 a second in all: over any `T`
  seconds, at most `8 + 8T` starts from any one ship and `32 + 32T` in all. Past a
  place or an allowance: "too busy; try again", before any WASM runs. Allowances
  are kept for 1,024 asking ships at most; past that, those that are whole are
  forgotten, and a new caller is told it is too busy if none is.
- Rests: counting alone would let a slow handler hold a ship: at the rate the
  allowances let through (`8 + 8T` from one caller over `T` seconds), each
  question of up to `ask_millis` (2 s), that is about 16 seconds of the ship's
  time a second from one caller, and 64 from all. So after a question that held
  the ship for `t`, the ship rests from every ship's questions for `3t` and from
  that ship's for `9t`, and a question that would begin in a rest is too busy:
  that is looked at before the ship is taken (each time the question looks
  whether it can have the ship), so a question refused for a rest normally never
  holds the ship at all, and once more after it is taken, since a rest can begin
  while it waits. `t` is measured from the look at the rests that admits the
  question once it has taken the ship's lock (the one reading of the clock that
  look is decided on) to just before its rest is written (the lock is let go a
  moment after that), so waking the ship, the kernel's decision and the handler
  are all in it, no part of a rest it was admitted after is, and it is charged
  however the question ends from then on (an answer, an error, a panic, or "too
  busy" because a module it needs is not compiled). A
  question refused before that look admits it (given up, past its time, or in a
  rest) is charged nothing for the time it held the lock. A rest is only ever
  made longer.

  The bound, once, and what it is true of: the measured times `t` of the
  questions admitted past the look at the rests (those that go on to wake the
  ship or run) add up to at most a quarter of any stretch of the ship's time,
  all asking ships together, and a tenth for questions from any one ship, each
  bound plus the length of one such measured time. It is a bound on those
  measured times, not on every moment the ship's lock is held: the moments
  before the measurement starts and after it ends, while the lock is still held,
  are not in it, and the system can run the thread late in them. A measured time
  is the question's time (`ask_millis`) and however far past it the handler runs
  before it is stopped (see Time under limits: never before its time, and no
  number promised for the overrun) and, for a ship woken for it, the opening of
  the file, which is not cut short. Apart from that, a question refused after it
  has taken the ship (a rest begun while it waited, or the asker gone or its
  time passed by then) holds the lock only for those looks: it wakes nothing and
  runs no WASM, is not charged to the rests, and has no time promised for it
  (lock contention and the system's scheduling have no fixed bound); the
  fraction above does not cover it. The bound on such refusals is the start
  rate: a question's allowance is charged at the rate limiter, before its job
  waits for the slot, so over any `T` seconds at most `8 + 8T` questions from
  any one ship and `32 + 32T` in all are started (a burst and then a rate,
  `asks_per_second_each` and `asks_per_second`); questions already waiting when
  such a stretch begins can also end in it, at most `max_asks_each` (2) from one
  ship and `max_asks` (8) in all by default, the places they hold. One owner can
  prove many ships (a planet and its moons), and each counts apart. The rests
  are in memory only.
- Room for reading: a question holds the request's room only until it is
  checked and decided to be taken; its payload is then within the runtime's own
  limit, and its names checked.
- Memory: a question's payload and its reply are held only while it holds its
  place (above), so at most 8 at once. Each holds its payload (at most 64 KiB)
  while its job runs; its reply (at most 256 KiB) as the handler's reply, and
  for a moment also encoded for the wire (two copies), after which the first
  is let go before anything is awaited, so one copy is held while it is sent
  (`reply_owned` in `net.rs`). So at most 8 x (64 KiB + 2 x 256 KiB) = 4.5 MiB,
  and 8 x 256 KiB = 2 MiB once all are being sent, besides what a read
  handler's instance takes (as for any read) and what QUIC buffers for a
  stream (its send window).

**Asking: three ways in.**

1. `Runtime::ask(from, from_agent, to, agent, interface, payload, within)`
   blocks for the answer, and needs the network. `within` is more than nothing
   and at most `max_ask_millis` (60 s); `request_timeout` does not apply to it,
   but making the connection for each try has at most `request_timeout` of what
   is left, so a try at an address nothing answers at does not take all of it.
   Within it, a connection that fails or goes silent (see Finding a ship by its
   name) is made again, and a ship that says it is too busy asked again, sooner
   after "too busy" (from 20 ms) than after a lost connection (from
   `retry_delay`), doubling up to a second; asking twice is harmless. Any answer
   from the other ship ends it, a refusal included, except a refusal as too
   busy, which is asked again as above. It returns the reply, or `AskError`:
   `Denied(reason)`, `Failed`, `Limit`, `Busy` (the last try before the time ran
   out was refused as too busy, whatever earlier tries met, or this runtime had
   as many requests out as it may),
   `NoAnswer` (some try reached the other ship and no answer was taken in time),
   `Unreachable` (no try ever had a connection in time, or the
   directory does not list the ship; a try that finds the destination absent
   from the directory ends the question as `Unreachable`, even if an earlier try
   reached it, while a try already awaiting its reply can still complete),
   `NotUnderstood` (an older runtime, or an answer that is not one); or, before
   anything is sent, `NoNetwork`, `TooLarge` (more than `max_ask_bytes`),
   `BadWithin`, `BadName` (the asking ship not this runtime's, the ship asked
   this same ship, or a name not one). It takes one of the runtime's
   `max_requests` places for the whole of it. Its time is one deadline, taken
   first thing when the call is made (before the asking ship's file is looked
   for or the payload copied), and carried through every try: a task the system
   runs late has only what is left of it, begins no write of the question once
   it has passed, and takes nothing the other ship says after it, a reply or a
   refusal (that is `NoAnswer`). The time the other ship is told
   (`within_millis`) is in whole milliseconds, never rounded up, and is looked
   at again, with the deadline, on every poll of the write before the connection
   has taken any of the question's bytes: at the poll in which the connection
   accepts a question's first bytes, the allowance in those bytes is no more
   than the whole milliseconds left to the asker's deadline by the clock reading
   taken in that poll, and no first bytes are accepted in a poll whose clock
   reading leaves less than a millisecond. The first-write rule uses the clock
   reading taken in the accepting poll, and time spent encoding, waiting inside
   the writer, or descheduled after that reading can carry actual acceptance
   past the deadline. (When the other ship has them is not promised.) The
   question ends within its time on the network's threads; the caller waits for
   that until two seconds past the deadline at most, is told `NoAnswer` if
   nothing came by then (`NoNetwork` if the network stopped), and what it gave
   up on is called off. The reply side is read while the request is still being
   written: a whole refusal that comes before the request is all written (the
   other ship stopped reading it, as too large, say) ends it, and is `Limit` for
   a size refusal; any other reply that comes before the request is all written
   is not taken. If the write fails, a whole refusal read after it is taken in
   the same way; anything else leaves the write's error, if the reply read
   completes before the exchange's deadline; otherwise the exchange ends at its
   deadline. A completed reply whose outer fields parse as a refusal but which is
   malformed (a reason that is not valid UTF-8 in a structurally valid refusal,
   say) ends the exchange as not understood, replacing the write's error; a
   reply whose outer fields do not parse is not taken as a refusal, and the
   write's error stands.
2. `POST /ask/<ship>/<agent>/<interface>`, under the ship and signed in as
   every route, asks as the ship's owner (`from_agent` empty). The body is the
   payload; `?within=<seconds>`, given once, is how long it is given, in whole
   seconds, from 1 to `max_ask_millis` rounded down to whole seconds. Left out,
   it is the shorter of 10 seconds and `max_ask_millis`; given more than once
   (even with one good value among them) or in any other form (`?within` with
   no value, empty, not decodable, not a whole number, 0 or past the most), it
   is refused with 400 and nothing is asked. So with
   `max_ask_millis` under one second, leaving it out still works (with that
   time), and no value may be given. Answers: 200 with the reply
   (`application/octet-stream`, an attachment); 403 for a refusal, "the other
   ship would not let it be asked: " and the other ship's reason (cut to 200
   bytes, control characters made spaces); 502 for a failure or an answer too
   large, each in words of its own; 501 for an older runtime; 503 with
   `Retry-After: 1` when too busy, 503 without it when the other ship could not
   be reached, 503 with `Retry-After: 5` with no network; 504 when no answer
   came in time; 413 for a payload larger than `max_ask_bytes`, 400 for a name,
   a `within`, or this same ship. Every answer past the sign-in and origin
   checks carries `nosniff` and `Content-Security-Policy: sandbox;
   default-src 'none'`; a refusal at those checks (401, or 403 for the origin)
   carries `nosniff`, as every answer of the server does. It waits holding a
   worker, as a long poll does, so it counts among the requests waiting (at
   most half the workers at once) for as long as it waits; past that, 503 "too
   many requests waiting at once; try again shortly" with `Retry-After: 1`. Its
   answer is bounded and buffered whole before it is sent, as any small answer
   is, so it takes no download place.
3. From inside an agent's handler, `ask_to` (the SDK's `ask::to`): an event is
   one transaction and cannot wait, so the answer comes later, as below.

**An agent's questions.** `ask_to` is checked against `RouteReply.asks`, and
refused (and the event with it, as `send_to` past its limits) for this ship or
an empty name (agents here are read), a payload over `max_ask_bytes`, a
`within_millis` of 0 or over `max_ask_millis`, more than
`limits.max_effects_per_event` questions in one event, or a ship that already
has `max_asks_waiting` (256) questions waiting, counting answers queued and not
yet handed over, or when the queue cannot hold room for its answer ("this
ship's queue has no room for the question's answer"; below). It is refused
while reading, as every call that changes something is. The question is written to `asks` in the event's own
transaction, with its time, and is put only if the event commits; an event that
asks, as one that sends, must leave the room the file keeps for taking a
command. Its time is wall-clock, stamped as the event commits: just before
`COMMIT`, every question the event wrote is given `now + within_millis` as its
deadline, in whole milliseconds since 1970, so it holds across a restart, the
ship sleeping, and an export (and a slow commit uses some of it; see Who
looks, and when, for how the network keeps it).

Exactly one `KIND_ANSWER` event for each question, unless the agent dropped it.
The event calls the agent's `answer` export with an `Answered {about, ship,
agent, interface, outcome, reply, reason}`; the outcome is `REPLY` (with the
reply), `DENIED` (with the other ship's reason), `FAILED`, `LIMIT`,
`NO_ANSWER`, `UNREACHABLE` or `NOT_UNDERSTOOD`. Whatever comes of a question,
an answer, its time running out, or no network, it is written down by striking
the question off `asks` and queueing the event in one transaction
(`Ship::ask_answered`), and only if the question is still there, on the copy
of the ship that put it (its incarnation mark). So an answer and the time
running out at once make one event, not two and not none, and after a dropped
question nothing is queued, whatever arrives. Once the event is queued, the
network running now is told there is work, from inside `Ship::ask_answered`
through the runtime's own hook, so an answer written by a task of a network
since stopped and replaced still runs. A module with no `answer` export has
the event skipped, as for a receipt.

Room for the answer, with its working. Every question waiting holds room in
the ship's queue (`max_inbox_bytes`) for its answer, from the moment the event
that asked commits until its answer is queued: as much as an answer to it with
no reply takes, counted as the queue counts (`store::ask_reserve`: an
`Answered` with that question's names, the largest number, the largest
outcome, a reason of 200 bytes, the most any reason is cut to, and the 64
bytes every queued message counts for). It is counted in the queue's total
wherever that is counted (`store::inbox_bytes`), by the running ship and by
import alike. So:

- `ask_to` is refused when the room cannot be had now (with what the event has
  queued so far), or never could be (a queue too small), as above.
- Writing down what came of a question gives that room back and queues the
  answer in one step. An answer with no reply always fits in it. One with a
  reply that does not fit in the queue's room with the reservation given back,
  or that is larger than this ship takes (`max_answer_bytes`), is handed over
  as `LIMIT` ("no room on this ship for the answer", or "the answer is larger
  than this ship takes"), which does. An answer with a reply must also leave
  the room the file keeps for taking a command, as anything written because of
  another ship does; if it would not, it too is handed over as `LIMIT` with no
  room. So a question's answer is never held back for want of room in the
  queue.
- The file itself is the exception: nothing holds pages of the file for an
  answer. The room the file keeps for taking a command (`room_to_take_one`) is
  checked only for events that send commands or ask questions; events that
  only write state (and receipts owed, answers without replies, comparing
  notes, `LOST`) can use it up. So the write of what came of a question can
  fail, as any write can, for any storage reason: no page to be had (for the
  queue's rows, an index, or a split of either), or an I/O error. Then nothing
  is kept, the question stays waiting, and its task writes what came of it
  again (a reply let go, `LIMIT` in its place, as that takes less room), with
  waits growing from `retry_delay` to `max_retry_delay`. It does not spin, it
  stops when the question is dropped (above), and a restart meanwhile finds
  the question still waiting (and answers it then, `NO_ANSWER` if its time has
  run out). There is no bound on how long this takes: the answer is written
  when the file can be written again. What makes that happen is the owner's to
  do: let the ship's agents run what is queued and drop state they keep,
  delete files or empty the trash, or move the ship to a runtime with a larger
  `max_ship_bytes` (see Known limits).
- Import: the `NO_ANSWER` made for every question waiting in a copy takes the
  room its question held, so the answers never keep a ship's own export,
  written by this version, from being imported under the same settings, full
  queue and questions waiting included. (That is the answer queue's room only:
  the import's own time limit and its limit on the packed file still apply, as
  for any import; see Export and import, and Known limits.)

Who looks, and when: each question waiting has one task of its own in the
network, started when the event that asked commits (the event says so to the
network) or, for questions waiting when the network starts, from the one look
through every ship's file the network makes then (as for commands). The task
puts the question as `Runtime::ask` does, but each try takes a place among the
requests agents' questions may hold (a quarter of `max_requests`, and at least
one) and then one among all, and gives both back when the try ends, so agents'
questions never hold the places every other request needs. (With
`max_requests` at 1 those are the same one place, and an agent's question
waiting can hold it: the owner's own question is then told it is too busy. The
place kept for the owner is there from 2 up.)

The notices that a ship may have questions waiting are taken by a task of the
network's own (`start_looks`), beside the carrier that finds where commands go,
so a notice is acted on at once whatever the carrier is waiting for. (The
carrier still finds which ships a ship's commands are for one ship at a time;
see Known limits.) The network looks at each ship's questions on its own: one
look per ship at a time (a ship told of again while it is being looked at is
looked at once more after), each waiting for its own ship on a thread of the
blocking pool, holding none of the network's working places. So a ship kept busy
for a long while (running a long queue, say) does not keep another ship's
question from being registered. Question notices and registration proceed
independently of command discovery, but reading a registered question needs a
shared working place, so it can expire unsent while those places are occupied.
And each ship with a look outstanding can occupy one thread of a shared pool of
blocking threads until the ship, or room to wake it, becomes available, and that
wait is not cut short when the network stops. Enough such waits at once can
delay work for other ships. A look holds the ship for as long as it takes to go
through that ship's own questions. A question dropped (`ask_drop`) stops being
put once the dropping event commits: the event tells the network the question's
number and the copy of the ship it is on, straight from the commit, and its task
is told to stop by that, without the ship being taken again (`Ready::Dropped`).
The look through a ship's questions registers each task's means to stop while it
still holds the ship, and starts the tasks after; a drop is told from inside the
dropping event, with its ship held. So a drop that commits after the look finds
the means to stop, whether or not the task has started yet, and stops it; one
that committed before the look is not in it. One look, however many drops come
meanwhile: a steady stream of them cannot keep the network looking. The stop is
signalled at the commit, and each wait notices it as follows: waiting for a
connection or an answer, and every wait between tries, end as soon as it is
signalled; waiting for one of the places agents' questions may hold ends then
too, and waiting for one among all requests out notices at its next look (it
looks every 20 ms); a question whose drop commits is stopped at its task's next
poll: a write that poll had already begun may still go out, but nothing comes of
its answer (a stream already opened for it is reset, not finished); and waiting
for the ship (to read the question, or to write what came of it) notices within
one look (the ship is tried every 5 ms, not waited on, and given up on when the
question is dropped or, for the read, when its time has passed). What is let
finish: a read or write of the ship already under way on a worker thread, which
keeps its working place, and for a write the reply it holds, until it ends;
there are at most `max_working` (16) of those, and the write checks, in its own
transaction, that the question is still there on that copy of the ship, so a
drop and an answer at once make no event. So does any task of a question that is
no longer waiting when its ship's questions are next looked through stop. When
the network stops, every task is stopped the same way, and a write of what came
of a question that is waiting for its ship then gives up within one look,
without writing (the question stays waiting, for the next network or for
`deliver`, below). Neither an individual task's row read nor its settlement
write (writing down what came of its question) does the upkeep a ship owes when
it is first woken (as for a question asked of the ship): that waits for its next
ordinary use. The look through all of a ship's waiting questions is an ordinary
call, and can do it.

Its time is stamped in the asking event's transaction just before `COMMIT`, in
whole milliseconds of the wall clock, so a commit that takes long uses some of
it. The task turns that into a deadline of the machine's steady clock once, when
the question's task starts, before it reads the row (the steady clock read
first, then the wall clock, so a pause between the two can only make it
earlier), so changing the wall clock afterwards does not move it (a restart
reads the stamped time afresh). When its time runs out, its own timer ends it:
what came of it is written then, or, with no answer heard, `NO_ANSWER` (some try
reached the other ship, or the last was refused as too busy, or no try could be
begun for want of a place among the requests out on this runtime) or
`UNREACHABLE` (tries were begun and none ever reached the other ship, except as
follows: a try that finds the destination absent from the directory ends the
question as `Unreachable`, even if an earlier try reached it, while a try
already awaiting its reply can still complete.) Whatever the other ship says
after the time (a reply, or a refusal of any kind) is not taken: `NO_ANSWER`.
The allowance on the wire and the deadline are looked at on every poll of a
try's write before any of its bytes are taken: at the poll in which the
connection accepts a question's first bytes, the allowance in those bytes is no
more than the whole milliseconds left to the asker's deadline by the clock
reading taken in that poll, and no first bytes are accepted in a poll whose
clock reading leaves less than a millisecond. The first-write rule uses the
clock reading taken in the accepting poll, and time spent encoding, waiting
inside the writer, or descheduled after that reading can carry actual acceptance
past the deadline. A question to a ship the directory does not list is
`UNREACHABLE`: that try sends no request. That ends the network's part; two more
steps follow, each with no time limit of its own. Writing what came of it down
(queueing the answer event) needs a working place, the ship, and, if it is
asleep, room among the awake ships, so a ship kept busy (or full, as above)
delays it; and the agent's `answer` handler runs only when the ship runs its
queue, behind what is queued before it, and within the number of queued events
one `deliver` runs (`max_queued_per_deliver`, 64). The network does no periodic
question scan of sleeping ships, but an outstanding notice can wake a ship after
its last question was dropped, and a queued answer can wake it again to run its
queue or check for outbound work. Questions are also looked for, waiting or not,
by the network's one look through every ship's file when it starts (among its
other work), by the check for waiting questions when a ship runs its queue with
no network, and, with the questions table read whether or not it is empty, by an
ordinary wake of a ship and by an import. (A look that could not read a ship's
file is tried again with growing waits, as is a start-up inspection that could
not: retries of work already begun, not a scan.) The network can wake a sleeping
asking ship to list its waiting questions, to read a question before sending it,
and to queue its outcome. In the tests a question given 2 s to a ship that had
vanished was answered between 1.9 and 3.5 seconds after it was put (the test's
bounds), and one given 1.5 s to a ship put to sleep meanwhile had the ship woken
for its answer no earlier than its time, and the answer handed over (by the
runtime's own records) less than 3.5 seconds after it was put.

After a restart, each question waiting is asked again if its time has not run
out, and is answered `NO_ANSWER` without being asked if it has. A ship whose
file cannot be opened or read when the network starts (or a directory that
cannot be listed, or an entry of it that cannot be read) is looked at again,
with growing waits, for as long as the network runs, for its questions as for
its commands and receipts: nothing is taken to be empty because it could not
be read. The ships already looked at are not looked at again, however often
the directory is listed. After an
import (a new incarnation), every question waiting in the copy is answered
`NO_ANSWER` there and then, as the copy is brought in ("this ship was brought
in from a copy, and questions waiting in it are not asked again"), and the
numbering carries on from the copy's (`meta.ask_gen`). Question numbers are
unique within one incarnation's history, not across a restore: a copy brought
in from an export carries on from that export's numbering, so numbers the
original gave out after the export was made can be given again. With no network running, every question waiting is
answered `UNREACHABLE` ("this ship is not on the network") when the ship next
runs its queue through `Runtime::deliver` or `run_pending`, before what is
queued runs. Offline queue processing settles the questions outstanding when
the pass starts. Their answer handlers run when the queue reaches them,
possibly on a later call.

`ask_drop(number)` strikes the question off, and its answer too if that is
queued and not yet handed over (giving back its room in the queue, or the room
the question held): 1 if either was there, else 0. Once the event commits, the
question stops being put, as above.

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
| `/agents/<agent>/files/...` | device | The agent's files (see Files on the ship), and saving a copy of a file on another ship for the agent (`POST .../files/save`, `GET .../files/saves`, `DELETE .../files/saves/<id>`; see Keeping what was opened, and saving a copy) |
| `GET /files/from/<ship>/<agent>/<id>...` | device | A file on another ship (see Fetching a file from another ship) |
| `GET /files/kept`, `DELETE /files/kept`, `DELETE /files/kept/<id>` | device | What the ship keeps of files fetched from other ships, and clearing it (see Keeping what was opened, and saving a copy) |
| `POST /ask/<ship>/<agent>/<interface>?within=` | device | A question for an agent on another ship, as this ship's owner; the reply as the body (see Questions between ships) |

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

`--pretend-ids <file>` reads every ship's key from a list in a file instead of
Urbit ID (see Keys from a list, for trying things out): it stands in for
`--ethereum` with `--net` and `--lookup`, and for `--azimuth-copy` with
`--lookup-point`, cannot go with `--ethereum`, `--roller` or any `--azimuth-`
flag, and is said when `serve` starts, with the warning that whoever can write
the file can be any ship. With lookup settings (`--lookup-at`,
`--lookup-domain` or `--lookup-point`), `serve` says, looking once a second
and listing `ships/` every ten seconds, when each of its ships is announced
and at what address, again whenever that changes (with more than 16 ships, one
line with how many are announced instead), and how many callers the points
have introduced to its ships (the first five times that changes, then at most
once every ten seconds). None of the files it is named (`--azimuth-copy`,
`--azimuth-snapshot`, `--azimuth-write-snapshot`, `--pretend-ids`,
`--storage-key-file`, `--keyfile`) may be in the data directory's `tmp/`,
which the runtime empties at every start.

`--sleep-after <seconds>` (300 by default; 0 for never) closes a ship's file
once it has been idle that long (see Awake and asleep). `--max-file-bytes
<size>` and `--max-cache-bytes <size>` set `Config::max_file_bytes` and
`max_cache_bytes`: a whole number of bytes, or with `K`, `M` or `G` after it
for KiB, MiB or GiB (`10G`); 0 means what it means there (the file store off;
nothing kept), and anything else stops the start, naming the flag
(`runtime::parse_size`).

`--two-ships <dir>`, with `--then-stop`, `--show-output`, `--ports <first>`,
`--file <file>`, `--sleep-after`, `--kernel`, `--counter` and `--tally
<file>`, is the walk-through under Run, and takes no other flag. It starts
copies of the very binary it runs from (`std::env::current_exe`), and learns
where each listens from the lines they print, whose words are kept in one
place (`runtime/src/bin/serve/said.rs`) for the code that prints them and the
code that reads them. It reads everything they print for as long as they run,
and stops them (a kill, then a wait for each to end, with no time limit)
however it ends that it can control: done, a step that does not work (it then
says which step, what was expected and what happened, and shows what they said
last), Ctrl-C, or a panic. It exits 0 when every step worked, 1 when one did
not, and 130 when stopped part way.

## Configuration

### `Config` (runtime)

| Field | Default | Meaning |
| --- | --- | --- |
| `fuel_per_event` | 100,000,000 | Compute budget for one event |
| `kernel_fuel` | 50,000,000 | Budget for each kernel decision |
| `max_event_millis` | 5,000 | Wall-clock deadline for one event: never stopped before it, stopped after it as under Time (no number promised for the overrun), and nothing it returns after it kept |
| `max_memory_bytes` | 64 MiB | WASM memory per instance |
| `max_ship_bytes` | 1 GiB | Largest a ship's file may grow |
| `max_module_bytes` | 16 MiB | Largest module accepted |
| `max_import_bytes` | 1 GiB + 64 MiB + 95 bytes | Largest exported copy `import_ship` reads, `Config::import_bytes_for(max_ship_bytes)`: the ship limit, a measured margin, and the seal. A copy is the plain contents of the ship's file and 95 bytes of seal. In five ships each filled to a 4 MiB limit in a different way, the contents came to 0.77 to 0.99 of that limit; that is measured, not proved, so a sixteenth is added and a larger copy is not shown to be impossible. A lower setting is a fair choice (it bounds the memory an untrusted file can take), and nothing refuses one |
| `max_import_millis` | 300,000 | How long an import may spend bringing a ship's file in, looked at between steps (see Export and import). Measured on a Mac laptop, release build, packing included: copies of 300 MiB of kv rows came in at 28 to 75 MiB a second (14 to 36 seconds a GiB), 100,000 small log entries (a 19 MiB copy), each checked against the ship's key, at about 7 MiB a second (about 145 seconds a GiB), so a minute would not do for a full ship of those |
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
| `max_file_bytes` | 10 GiB | Files per ship, held and reserved together; 0 turns the file store off |
| `max_files` | 100,000 | Files per ship |
| `max_uploads` | 16 | Uploads open per ship |
| `upload_keep_millis` | 86,400,000 (24 h) | An upload not sent to for this long is given up when the next one starts; a save not called for this long is stopped |
| `max_cache_bytes` | 3 GiB | Pieces of files fetched from other ships that a ship keeps, counting what was thrown away from them and is still on disk; 0 keeps nothing |
| `cache_keep_millis` | 2,592,000,000 (30 days) | A kept file not opened for this long is thrown away when an upload, a keeping or a save next starts |
| `max_kept` | 1,024 | Files kept from other ships per ship, in the cache and being saved together |
| `save_slice_millis` | 10,000 | How long one call to save a copy fetches missing pieces before it answers (one fetch begun is let finish) |
| `file_ask_fuel` | 10,000,000 | Compute budget for asking an agent whether another ship may have a file |
| `file_ask_millis` | 500 | Wall-clock deadline for that question, the kernel's decision included, kept as under Time |
| `ask_fuel` | 100,000,000 | Compute budget for answering one question from another ship: the kernel's decisions, the handler and every nested read together, apart from the event budget (the same number as `fuel_per_event`) |
| `ask_millis` | 2,000 | Wall-clock deadline for answering one question, counted from one reading of the clock when it arrived: waiting for the ship and the kernel's decision included, kept as under Time. The asker's `within_millis`, if shorter, is the deadline |
| `max_ask_bytes` | 64 KiB | Largest question (payload) a ship asks or answers; also held to what one message carries, less 1 KiB, and to 1 MiB (`store::MOST_ASK_BYTES`) when the runtime opens |
| `max_answer_bytes` | 256 KiB | Largest answer (reply) a ship gives or takes; held the same way, and to 4 MiB (`store::MOST_ANSWER_BYTES`) when the runtime opens |
| `max_ask_millis` | 60,000 | Longest time a question may be given, by `Runtime::ask`, the HTTP route or `ask_to` |
| `max_asks_waiting` | 256 | Questions a ship's agents may have waiting, counting answers queued and not yet handed over |
| `max_receipt_reply_bytes` | 16 KiB | Largest reply a receipt carries; also held to `max_event_bytes` and to what a ship takes as one message (see Commands between ships, exactly once), and to 1 MiB (`store::MOST_RECEIPT_REPLY_BYTES`) when the runtime opens. At 0 (or with a queue too small for any receipt with a reply) a command that wants its reply is refused |
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
| `request_timeout` | 10 s | One request to another ship, connecting included. A request that runs out of time never closes its connection; set shorter than `silence_timeout`, a request to a ship that has gone can run out of time more than once on the same connection before its watcher closes it |
| `file_timeout` | 30 s | The same for a request for a part of a file, at both ends, in place of `request_timeout` |
| `idle_timeout` | 30 s | A connection with no traffic is closed |
| `silence_timeout` | 3 s | A connection this runtime keeps (to a ship, or to a lookup point) on which something sent has waited this long with nothing at all heard from the other end is closed by its watcher, so that the next call makes a new one (see Finding a ship by its name). A working connection that hears nothing for this long while something waits (a link that drops everything, a peer stopped) is closed too. The watcher can be up to two quarter-second looks late, plus scheduling, plus QUIC's current probe timeout in one case, and its clock starts only once something is sent (see Finding a ship by its name). More than nothing and at most a day |
| `max_asks_each` | 2 | Questions from any one other ship being answered at once (running, or waiting for their ship), all ships of the runtime together |
| `max_asks` | 8 | Questions from other ships being answered at once, in all |
| `asks_per_second_each` | 8 | Questions from any one other ship started a second, as many at a stroke |
| `asks_per_second` | 32 | The same for all other ships together |

`Lookup` (`runtime/src/lookup.rs`):

| Field | Default | Meaning |
| --- | --- | --- |
| `serve` | none | Be a lookup point: `PointConfig { keys, galaxies, bounds, relay }` |
| `at` | none | Lookup points' addresses, each for one galaxy or (`None`) for all |
| `domain` | none | `(domain, port)`: the point for `~zod` is `zod.<domain>` |
| `resolver` | the system's | What names are looked up through |
| `announce` | none | Addresses to announce this runtime's ships at, up to 4. With none, the address each ship's galaxy's point sees this runtime at |
| `behind_router` | false | Ask callers to be introduced first even with addresses given by hand |
| `keep_alive` | 15 s | How often a packet goes over the connection to each point announced to, and over a connection made to a ship that asks for introductions. 1 to 25 seconds, and less than `idle_timeout` |
| `announce_every` | 120 s | How often each ship is announced again; at most 5 minutes |
| `ask_again` | 3 s | Least time between questions about one ship, and how long a failed name lookup is remembered |
| `resolved_for` | 300 s | How long an answer from the resolver is used |
| `direct_again` | 60 s | While a connection goes through a relay and is in use, how often the direct way is tried again; 2 seconds to a day |

`PointConfig { keys, galaxies, bounds, relay }`. `PointBounds`: `records`
65,536, `moons` 16,384, `moons_each` 64, `connections` 256, `per_connection`
256 and `in_all` 2,048 records each `rate_period` (1 s), and `introductions`
512 and `introductions_each` 4 introductions passed on each `rate_period`.
`relay` is `None` (the point relays nothing, and says so) unless given
`RelayBounds` (`runtime/src/relay.rs`): `ship_rate` 128 KiB and `ship_burst`
256 KiB a ship, `point_rate` 4 MiB and `point_burst` 8 MiB in all, bytes a
second and at a stroke; `sessions_each` 16, `sessions_from` 16,
`sessions_pair` 2, `sessions` 1,024 live; `made_each` 4 and `made` 512 sessions made each `rate_period`.

`Network::start` refuses settings that could wedge a ship: `max_ship_bytes`
below 256 KiB, a `max_message_bytes` without room for the largest command or
checkpoint plus 4 KiB, or without room for `max_unanswered` command numbers
twice over, and any time limit that is zero or over a day (`ask_millis` and
`max_ask_millis` among them); and an `ask_fuel`, `max_asks`, `max_asks_each`,
`asks_per_second` or `asks_per_second_each` of zero. A question, an answer or a
receipt's reply larger than one message carries is not refused at start: each
is held to what fits (see their rows above), so none can be what waits for
ever. A `max_message_bytes` below
1 MiB + 1 KiB is allowed, and then files are neither fetched nor served.

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
| `until` | none | The last block to read, to stop short of the end of the chain (to make a snapshot at that block); a copy told to stop answers no lookups |

### `ServerConfig` (HTTP)

| Field | Default | Meaning |
| --- | --- | --- |
| `addr` | `127.0.0.1:0` | TCP address to listen on |
| `ship_host_suffix` | none | Such as `.example.net`; must start with a dot |
| `workers` | 16 | Request threads (at least 2). Connections queue, four per worker, and past that are dropped |
| `secure_cookies` | false | Mark the cookie `Secure` |
| `max_wait` | 30 s | Longest long poll |
| `max_body_bytes` | 1 MiB | Largest request body. A `PUT` of a file's chunk is always allowed exactly 1 MiB, never more |
| `io_timeout` | 10 s | Time to send the whole request, and again to take the whole answer; for a file's contents, to take each chunk |
| `max_downloads` | 4 | Files' contents being sent, and requests for files on other ships being answered, at once, apart from long polls; never more than half the workers less a quarter of them (at least one), so some are always left. Requests for other ships' files may hold at most half of these places (at least one), and with no places (two workers) are refused |

## Tests

`cargo test` runs:

- Integration tests in `runtime/tests/runtime.rs`. The first test to need a
  module runs `cargo build -p kernel -p counter -p tally --release --target
  wasm32-unknown-unknown --target-dir target/wasm` once per run; the separate
  target directory avoids the outer cargo's lock. Hostile modules are written
  inline in WebAssembly text and compiled with the `wat` crate. Each test uses
  its own temporary data directory, and most use `Durability::Normal` to skip
  per-commit syncs.
- Unit tests in `net.rs`, `seal.rs`, `files.rs`, `remote.rs`, `server.rs`, `store.rs`, `moon.rs`,
  `whereabouts.rs`, `lookup.rs`, `pretend.rs`, `lib.rs`, and `azimuth.rs`. The Azimuth tests run against a stand-in JSON-RPC server on
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
- Unit tests of snapshots, in `replica.rs` and `replica/snapshot.rs`, against
  the same stand-in node, some with hooks that step into a restore or a write
  part way:
  - The same bytes: a snapshot made into a copy and written again; copies read
    to one block a block at a time and all at once; a copy made from a snapshot
    part way and read on, against one read straight there; copies from the same
    snapshot with a count at 2^63 - 1, reopened at different times.
  - Snapshots refused, making no copy and leaving nothing behind: one byte too
    many or too few, shorter than a header, a count of points that does not
    match, a byte changed with the fingerprint given, each form not allowed,
    ships out of order or twice, another chain, contract or first block, other
    rules, another format, numbers too big to write down, a snapshot that grows
    while it is read.
  - What is at the copy's name: a file that is there, or a link, is never
    replaced or followed, by a restore or by the writer; no copy is made beside
    a `-wal`, `-shm` or `-journal` left there; a file beside a copy that is a
    link, a second name or a directory, or a copy that is a pipe, is refused by
    opening, by restoring and by writing a snapshot, with the other file left as
    it was; something that is not a copy (empty, another database, not a
    database) is refused when a snapshot is asked for and left as it was, and a
    first start cut short is finished by an ordinary open and refused with a
    true message when a snapshot is asked for; a copy with a change a crash left
    unfinished is recovered and used by the same start again, while a file that
    is not a database with such a journal beside it is left exactly as it was,
    and another database with one is refused saying what SQLite undid; a file
    that cannot be read is refused with SQLite's own error, promising an
    ordinary start only for a change a crash left unfinished; and one whose
    unfinished change cannot be undone (it may not be written to) says so,
    claiming neither that the change was undone nor that it is damaged.
  - Making a copy: a restore that crashes part way leaves no copy and is made
    again whole; a restored copy is in its usual journal with nothing beside it
    when named, and opening it changes no byte of it; a restore that would leave
    anything beside the file it makes makes no copy; a copy just made is read
    back, so one swapped for another, emptied or changed in any one thing is
    refused, one that cannot be read back says so, and one taken away is not
    made anew; nothing is written through a link put where a new file is first
    made.
  - Writing a snapshot: of the copy as it was when it began, while something
    else adds to it; refused for a copy with no hash, for another Azimuth's,
    and for one with a change a crash left unfinished, saying to open it once.
  - The node: one that disagrees about the file's block (a copy read from the
    start, and one made from a snapshot) stops it, writes nothing and answers
    nothing, until it answers as before; every block number and hash it gives
    in a poll is one chain; a wrong final block in a poll that failed does not
    hold back a right one; a snapshot newer than its final block waits.
  - The file and stopping: a file kept before the hash learns one and is then
    checked; a damaged hash, or a number in `meta` that is not a whole number in
    range, is damage; a copy told to stop stops exactly there and answers
    nothing, and one already at its block has not reached it until the node
    agrees with its hash; snapshots are supported on this system.
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

Snapshots were checked against the main network's history by hand the same
day. From the recording above, replayed through a local stand-in that also
answers blocks by number (with the recorded hash for the last block and for
every block with logs, and a made-up one for the rest): a copy read from
nothing to block 26,407,242 took 520 seconds (one more question for each step
than before) and wrote snapshot A, 30,490,309 bytes for 144,503 points, with
the fingerprint `48945e929b859f7321998b54dd2045f375239bbd4800dd662258ae2826b2375f`.
A copy read only to block 20,000,000 wrote a snapshot of 137,853 points; a
copy made from it, with its fingerprint, read on to 26,407,242 in 178 seconds
and wrote snapshot B, the same bytes as A. Both tables were the same as the
earlier read's, row for row. Against Tenderly's public node, a copy made from
a snapshot at block 25,400,470 (one whose real hash the recording holds) read
on about a million blocks to block 26,409,414: 40 seconds from start to its
first answer and 74 requests (14 for blocks, 26 for logs, 34 for transactions
asked several at a time; 9 were answered "too many requests" and asked again).
A copy made from snapshot A got there in under 3 seconds with 4 requests. The
two wrote the same snapshot, byte for byte, and `~zod`, `~marzod` and `~pocwet`
looked up from them were the same as looked up through the roller. The
snapshot at block 20,000,000, whose hash the stand-in had made up, was refused
by the real chain: the copy read nothing, answered nothing, and its file was
left as it was made.

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

`runtime/tests/files.rs` covers files on the ship: a file put in a chunk at a
time, out of order and sent again, and taken out whole, by chunk, and by range;
the headers that keep a file from acting as a page; that only the owner's
devices, through an agent that claims a file, see it, and that no name in a
request becomes a path; identical files kept once and removed with their last
claim; the allowance under eight uploads starting at once, and "never fits"
told apart from "no room now" on a full ship; open uploads and files limited,
and forgotten uploads swept; the room a ship keeps in its own file, filled from
outside until chunk rows are refused; bytes changed, swapped, cut short, gone,
or not matching their hash, never served; nothing on disk or in an export
showing a file's contents, media type, hashes, or id; leftovers cleared when a
ship first wakes, without following links; a slow reader holding no ship, and
downloads limited apart; a chunk made ready while its upload was given up or
finished landing nowhere; files carried by export and import; a copy without
its stream, a stream cut short at many points, changed, reordered, with
segments dropped or repeated, or from another copy; a stream sealed properly
but made to mislead; every file row checked against every other on import;
an import clearing what an earlier one left, and one import at a time per
name; a copy without its stream never refused for its files, and one with it
refused when they would not fit; downloads and long polls leaving a thread
free with four workers, and contents refused with two; and finishing a 10 GiB
upload from its hashes alone, timed with every commit synced. It also has a
claim's open mark carried by export and import, a mark that is not 0 or 1
refused on import, and a ship file of schema 10 refused.

`files.rs` also has unit tests that make the file store fail at chosen points,
through checks compiled only into the crate's own tests: a chunk's commit
failing with the new copy on disk (the old copy stays served, the new one
goes); such a failure racing a good upload of the same chunk, in both orders;
a failure that cannot even remove its own copy, cleared when the upload
finishes; a removal that fails, stays counted against the allowance, and goes
at the next operation; a leftover whose removal fails, looked for again at the
next wake; a failure after an import's hard link, which leaves the ship its
files; two exports into one place, the first held between its stream and
its copy, the second unable to get between them; a commit that fails, undone
or kept, after which nothing is removed until finishing settles it; a
generation already taken, which leaves the copy that has it; a directory sync
that fails once and is done on the next try, for a ship's directory and at
start; a panic inside a transaction, after which the next operation does not
act on its rows; a removal kept on record until the sync after it works; a
failed sweep at finish, kept and done at the next operation; a chunk upload
made ready before finish and reaching its name after it, refused with no name
made; a sweep cut off between finish's commit and the drain, or whose listing
fails, done by a later drain; a directory removed taking the records of what
was in it; a sweep entry for an open upload, written by hand, left alone; a named
directory whose type cannot be read, kept, and a leftover whose type cannot be
read, kept until the next look; an import that cannot tell whether its ship
exists, stopped without clearing anything; and a relative data directory
synced into the current one.

`runtime/src/remote_tests.rs` covers fetching a file from another ship, with
two real runtimes on localhost, the fetching one with its HTTP server. The
ship answering can be made to lie through a door only the crate's own code can
use: a reply put in place of the true one, held back, or cut off. Files of 0
bytes, 1 byte, one chunk, one chunk and a byte, and several chunks, had whole,
by range and by chunk, byte for byte, with every header; every no answering
the same, on the wire and to the device, for a file closed and not let, no
such file, no such agent, an agent that does not claim it, one with no
handler, one whose handler fails, a kernel that does not know the question, an
open claim by an agent that is not installed, a row that cannot be read, and a
ship resting from asking, and on the wire alone an agent name that is not one,
an id of the wrong length or none, and a ship whose runtime keeps no files,
byte for byte on the wire for all four parts; a question that traps, runs out of fuel or of time, answers
rubbish or more than 64 bytes, or tries to change something, each no, with
nothing kept; let and then not let, refused once the remembered yes runs out,
and open and then closed, refused on the next request; a claim taken back, a
file put back, and a module replaced, none answered from an earlier answer; a
file open under one agent and not under another; every lie (bytes, a chunk
short or long, the length, a hash, too few or too many hashes, the wrong kind
of reply, a refusal, media types) caught before the head where it can be, and
ending the answer short where it cannot, with nothing the lying ship says (words
of refusal full of markup and control characters) reaching the device; a ship
too slow, or gone; four requests for files at once on one connection and eight
in all, and on the ship fetching two of the four places for downloads with a
file of its own still had; a ship that asks for whole chunks and never reads
them holding at most four places on its connection and eight in all (counted
every 50 ms from 0.5 s to 2 s after the first six requests, with one
connection asking; then, after more requests, the rooms checked and commands
and a log fetched, every 100 ms until 25 s on the same clock, with three: samples,
not every instant), with no room held for those turned away, while commands and
a log between the same ships go through; a request over 1,024 bytes refused
before it is looked into, the same whatever it names, and requests of the
largest size allowed, turned away with every place held, holding no room;
a request given up on while its job waits for the ship's slot (before its
decision, or before a batch of hashes) or between two batches reading
nothing more; envelopes of two bodies (a delivery over its count then a
file kind, the same padded past 1,024 bytes, two file kinds, one kind twice, a
ping then a file kind) refused before they are decoded, the same whatever they
name, and these and the earlier kinds' refusals left untaken holding no room; a
name given twice (900 bytes, then a real one) served as the real name, and a
bad name or id answered with the same no (that no job is made for it is read
from the code, not shown by the test);
refusals never taken, on three connections, holding no place and no room
while a ping, commands and a log between other ships on the same runtime go
through; the asking ship stopping the stream or closing the connection while
a job waits, and the job reading neither the chunk nor hashes; a refusal for
want of a place reset when `request_timeout` runs out, seen without reading
it; a job that outlives its
request holding its places until it returns, and not reading the chunk; long
polls, slow downloads and waits on other ships leaving the kept threads free
with 2, 4 and 16 workers, for what a file is and for a chunk; an install, the same module installed again without
a grant, a module replaced and put back, and another agent installed, each
forgetting the ship's remembered answers and no other ship's; a stranger's
request that first wakes a ship setting off only the clearing owed at first
wake; questions from many callers taking at most about a quarter of a ship's
time;
every name in the address checked, no device, no network, messages too small
at either end; nothing written at either end by serving, by listing both
runtimes' directories and counting the rows of both ships (both ships already
awake, so no first-wake clearing is set off); commands and a log between
the same two ships going through while files are pulled as fast as they are
let; how long serving holds the ship; the remembered answers' bounds and
times; and the kernel letting only another ship ask. `remote.rs` checks a file
of 32,768 chunks and one more on made-up hashes, so nothing of 32 GiB is
hashed, and lies about the level above. `router_tests.rs` fetches a small file
over a relayed connection. Five of these tests are about B keeping nothing and
asking A every time (a file had only while its agent allows it, open under
one agent and not another, every lie caught, no network, nothing written);
with keeping on, B rightly serves what it already holds without asking, so
those five run with keeping off on B (`max_cache_bytes` 0), which is when
part 2's behaviour is promised.

`runtime/src/kept_tests.rs` covers keeping what was opened and saving a copy,
with the same two runtimes and liar, and failures made to happen at chosen
points on the test's own thread: a file opened is kept and opens again with
nothing asked and with the other ship gone, what is not held still fetched; a
piece damaged, missing or cut short given up and fetched again, one only not
read left alone, and with the other ship gone a damaged piece ending the
answer short and never wrong; a kept file's rows changed in the ship's file
not believed; lies about the length, the hashes and chunks (a wrong byte, cut
short, cut off) never kept; a failure at each step of keeping a piece (making
its name, writing, syncing it, syncing its directory, before the commit, a
commit of unknown outcome, a commit that lands and reports failure, an
unwind) leaving no row naming wrong bytes, the piece passed on all the same,
and what was left going with the kept file or when it is saved; bytes that
are not the piece never named; a piece never going into a kept file thrown
away and kept again meanwhile, at three points; the cache sampled throughout
many concurrent opens and never over its allowance, least recently opened
thrown away first and never the file being read, when it was opened written
at most once a minute, stale files swept, a lowered allowance kept to, what
was thrown away counted until it is gone, and at most 64 files or 65,538 rows
thrown away per request; saves counting against the file allowance and the
count of files; kept files bounded in number and by the room in the ship's
file; a save call bounded in time, carrying on where it left off, and holding
its places; a saved file an ordinary file (closed, listed, exported and
imported, seen only through the agents that saved it, had with the other ship
gone, deleted from disk), in the kept file's directory; a save meeting the
same file uploaded meanwhile; stopping a save, back to the cache, with room
made, or thrown away, and a save not called for a day stopped; clearing one
and all, saves left alone, cleared files asked afresh, a failed removal
counted and done later, a failed or uncertain clear changing nothing; only
signed-in devices, checked names, never to another ship or an agent; nothing
readable on disk; the file headers and stored media types; the first look
counting a kept file's directory as named; leftovers of keeping and throwing
away cleared; a failure while saving finished by the next call; kept files and
saves not imported, rows of them that make no sense refusing nothing; and with
keeping off nothing kept, nothing read from a file left in the cache, and a
save still works. Also: the rows of files in the cache held to their
allowance (driven through the call the route makes once part 2's checks pass,
since the test liar stands in only for parts the asked ship allows), oldest
first, an upload starting after, and a file whose rows pass the allowance
never kept and nothing thrown away for it, and a stopped save going back to the cache only if its rows fit;
copies a crash left removed at the next keep into their directory
in a new life, nothing a row names or the trash records touched, and an error
listing removing nothing; strays capped at two a directory, a save call then
answering 503 while an open passes the file through, and the file thrown away
when its save stops; a cached file left with a stray thrown away by the sweep; the device having its piece while the keep is held at
its sync (by a gate on the copy's sync), with another request answered
meanwhile; one keep timed, 50 times; a held file opening with other ships'
share taken by stalled requests and on two workers; the trash drained when a
piece finds no room though nothing new is thrown away; 64 saves run out
stopped one budget at a time; clearing everything whatever `max_kept` now is,
past one page, and the sweep bringing the count down; a save begun between
clearing's listing and its batch left alone and counted; a piece given up
before a save's finish making the finish refuse; a file being saved taking no
piece while the ship is over its allowance; part 2's whole liar matrix with
keeping on, nothing it says kept; nothing written on the ship asked with
keeping on; the rows of kept files and saves in an export's sealed copy, and
none in the import; and a kept file in the cache whose rows do not come to its
id thrown away and kept afresh, and one being saved ended by the save call
that finds it: the call answers 500 once, the file is thrown away (not
returned to the cache) when no other agent saves it, and the next call starts
afresh. Also, for the per-directory record: a directory looked through once
in a life whatever comes of the look (a failed listing, a failed removal),
so a copy made and not yet named is never removed by a second look; copies
on their way counted with strays against the cap of two, a third request
held off while two copies are between their name and their commit; a copy
refused at its commit whose removal fails counted a stray, and its cached
file thrown away for it; a stray's
directory thrown away charging 1 MiB for it in the trash until it is gone;
a retired directory's record gone once its last copy ends, a late
completion bringing nothing back, and the sweep pruning records left by a
throwing away that landed and reported an error; a save's finish throwing
away its redundant copy with the room the call kept back, never past the
budget; and while the cache's rows are over after a lowered setting, no
new file admitted and no stopped save returned to it, pieces of files
already kept still kept, and sweeps bringing it down; a deleted file's
sweep, with a stray's charge, kept until its directory is gone; a save
call's sweep landing though the call is refused, the next call then saving
the file; and a file refused keeping for the count leaving the stale file its
sweep threw away gone. Each step that must be
durable is shown to make a synced commit by a counter only tests have; that a
synced commit survives a power cut is SQLite's, and was not tried.

`runtime/tests/lookup.rs` runs real runtimes on localhost with keys from a
stand-in for Urbit ID and no address given by hand: ships finding each other
through a point and trading commands; two galaxies with two points; a moon; a
ship that comes back on another port; a point that starts late, goes away, and
comes back; many ships announced over one connection; an address given by
hand winning; the limit on asking about one ship; a stand-in point that lies
(another ship's record, a forged or altered one, one run out or dated ahead,
rubbish, an answer that never ends or is too large, an older record after a
newer one) and an impostor at a signed address that would take the caller; a
record that has run out not being used even where it would still work; a
moon's later key seen in a record holding for calls made, callers taken, and
an open connection; an address given by hand while the point is answering
being the only one tried; a point's bounds against a raw client, its count of
requests in hand against slow keys and reconnecting callers; seventeen
questions at once; a caller offering both protocols or neither; a connection
made to an address given by hand not being used once the ship is looked for;
a runtime that is no point refusing the protocol; points found by name
through a stand-in resolver (a dead first address, no addresses, a ninth
address, a resolver that hangs, or hangs once, answers looked up again once
old); and stopping promptly with a point that never answers.

For the outside address, presence and introductions, `runtime/tests/lookup.rs`
also has: a record with no presence, or presence for another connection, ship,
time or key, not kept, and a moon's presence by its own key; a record read from
one point and announced to another by someone else, refused, with an
introduction to the ship still reaching only the ship's own connection; what a
runtime announces with nothing given (bound where it is reached, bound to
"any address"), with addresses given, and with `behind_router`; a point that
reports a refused kind of address, rubbish, a refusal or nothing, and nothing
announced; introductions at a point refused for a ship not attending, one whose
connection has just closed, a caller's record forged, run out or shown with
another connection's presence, and each limit, each saying which (an
introduction's record counting against its connection's record rates too); a
caller that goes while its introduction is checked having nothing asked or
passed on for it; a ship that
takes nothing passed to it, or reads nothing of it, holding up only its own
introductions, and only so long; a stand-in point passing a ship forged, run
out and oversized introductions, its own record, rubbish, one that never ends,
with the packets counted at a socket; a ship answering an ordinary call while
an introduction is in hand (its caller's key held back), and every call
succeeding while floods of introductions are pushed and weighed; at most four streams
open from a point; a point that never answers an introduction not delaying
the call; an address given by hand meaning no introduction is asked for; the
four-byte packet drawing no answer from QUIC, beside a version negotiation
that does, and a flood of them changing nothing; stopping promptly with an
introduction in hand at the caller, the point and the ship; an introduction of a
record older than one already believed sending nothing; a stranger's requests
to introduce metered by its own connection before the point looks at who
attends; a ship whose record is taken introduced though another ship of its
galaxy is refused; a point writing an IPv4 address as IPv6; introductions
weighed only so many a second, and none for a ship that asked for none; an
address set by hand while an answer asking for an introduction is held back,
with no introduction asked for after; a ship letting go of its connection
to a point its name no longer leads to; a moon with its key set by hand,
introduced under another key its parent vouches for (nothing sent) and under
the key set by hand (acted on); and a galaxy of seventeen ships whose second
chunk is answered with rubbish, the first chunk's outcomes still recorded. Unit tests in `lookup.rs` cover an
introduction weighed again against the caller's history where it is passed on,
introductions that waited too long, the time given to introductions and their
attempts, room made among kept connections from those no lane uses, with 65
live points, and a lane whose point moves finding room when every place is
used by a lane. In `router_tests.rs`, an introduction's weighing called
directly shows each of its limits on its own: a caller's allowance, the
places under way (taken before any allowance is charged), and the overall
allowance.

Ships behind home routers are tested in `runtime/src/router_tests.rs`, inside
the crate, because the stand-in router takes the place of a runtime's UDP
socket through a door only the crate's own code can use. The stand-in comes in
two kinds: one outside port that lets in only addresses the inside has sent to
lately, and one with a port for each destination. With real runtimes and a
real point: a ship behind the first kind called by name from a public address
and from behind a router of its own, with commands and receipts both ways; the
same call failing without the introduction; two ships behind the second kind
failing in time, saying they could not reach each other directly, where the
point does not relay; and a connection through a router that forgets idle
openings after two seconds still answering at once after five idle seconds.

For the relay, `router_tests.rs` also has, with real runtimes and a real
point that relays: two ships behind strict routers calling each other by name,
each direction relayed, commands and receipts both ways, the ships' own
connections to the point working meanwhile, the next call on the same record
going straight to the relay, and all three stopping promptly with sessions
live; a ship at a public address and one behind a strict router calling each
other (relayed one way, direct the other); a pair behind ordinary routers
relayed with the introduction made to fail, tries at the direct way counted
(none before one is due, none while one is under way for the pair), a try begun
from another kept connection not taking its place, then moving to the direct
way while commands keep going, with nothing lost or delivered twice, nothing
more carried, and the session ending at all three; a try held at the pair's
slot while an address is set by hand or the key changes (its candidate closed,
the kept entry untouched), held past its deadline (it gives up then), and
committing though the relayed connection has closed meanwhile; a command held
under way on the relayed connection as the pair goes direct, delivered exactly
once; a ship set by hand at a live session's made-up address, refused without
anything sent; an address set by hand while
the point holds a request to relay (the call stops before it uses the
session), and with one set, no relay asked for; no lookup settings meaning no
wrapper and QUIC's settings as they were; a relayed connection idle past its
routers' memory still answering at once, and QUIC's packets for a made-up
address whose session is gone reaching no router; a point's rules counted at
the routers (from a pinned address carried, from a stranger or naming no
session not, and nothing after the ship called's connection closes); and
ordinary lookups and calls completing while relayed packets and requests to
relay flood a point and a ship. With a point at one address, a request to be
introduced or relayed that the caller's own announcement overtakes (a stand-in
between the signing and the sending has the announcer's newer record kept
first, every time) is made once more and goes through, after exactly two
requests, the second's record later than the announcement; a point that always
says a newer record is held gets two requests, and any other refusal one, the
words out the same as before; and with the deadline passed, none is made again,
while with time left and the second never answered, both rounds are given
exactly the caller's deadline. Unit tests in `relay.rs` cover the first byte
against QUIC's and the punch's, segmented sends split each with its header,
received batches split and rebuilt, a relayed datagram reaching QUIC only for
a session here from its point (and nothing sent in answer, nor for a session
gone idle), a made-up destination never reaching the real socket whatever asks
for it, a stale session handle releasing only its own session and its address
not given again while it lives, nothing earned for the time a send takes, a flood of relayed datagrams letting the endpoint go on with its
other work after so many rounds, the bounds on a
ship's sessions and their end with the connection they came on, and a made-up
address not given again while anything may remember it; in `lookup.rs`, the
point carrying only between a live session's two pinned addresses, toward a
caller only while it has sent lately (by a clock the test moves), dropping a
session left idle and one whose ship called closes, moves or runs out,
refusing requests to relay for each reason and bound (a session made only with
room for its push), two sessions at most for a pair with a moon counted as its
planet, a session whose every send fails going idle all the same, a lookup
point at a made-up address never connected to, holding both byte
allowances over every measured interval at a load that would break them, one
ship at its allowance not stopping another, and sending out exactly what came
in; and in `tests/lookup.rs`, a point refusing requests to relay saying why
and answering a genuine one with a session passed to the ship, and a lying
point registering no session at a ship beyond what the ship believes and
allows, with stray relayed packets drawing no answer.

`runtime/tests/runtime.rs` also has: five ships, each filled to a 4 MiB limit
in a different way (journal lines of about 2,000 bytes, many small kv rows, kv
rows and journal lines of 20 to 8,019 bytes, small journal lines, journal
lines of about 60,000 bytes), exported and imported into a runtime with the
same settings (and the import limit `Config::import_bytes_for` gives at that
size), each holding all it held, no larger than the limit, with no more used
pages than the original, and nothing left in `tmp/`; a ship too large for a
runtime of 2 MiB refused, once packed, with `Error::ShipTooLarge`, naming the
size and the limit, and for one of 1 MiB with `Error::NotBuilt`, which names
the room it did not fit in and claims no size, neither ever saying "database
or disk is full", leaving no ship, key, files or scratch; an import limit of
the largest number taking a ship without overflow; leftovers in `tmp/` removed
at start (scratch files and SQLite's files beside them), a second name of a
ship's file there removed with the ship left whole and working, symbolic links
there removed without touching what they point at (a file, a directory,
nothing), a directory there left, a second runtime refused the lock removing
nothing, a start refused for the wrong storage key removing nothing, and a
`tmp` that is a link to `ships/` not cleared; a ship refused as an export into
`tmp/`, into two levels below it not there yet, and through `..` past a
directory not there yet, with nothing made; and the idle sleeper putting an
idle ship to sleep no sooner than its idle time and the ship answering the
next call, never putting to sleep a ship used every 300 ms with an idle time
of 3 seconds (looks made late, by the test's own clock read before each call,
are not judged, and the test goes on until ten are), and ending once the
runtime is let go.

`runtime/src/ask_tests.rs` covers questions between ships and receipts that
bring a reply, with two real runtimes on localhost, keys set by hand, inside the
crate so that a network can vanish (stopped with no goodbye) and what the ship
asked ran can be read off it (each question it ran, when it ended, how long it
held the ship, and who asked: compiled only into the crate's tests). A question
answered through `Runtime::ask`, over HTTP for the owner's device (with
`nosniff` and the sandbox policy; this same ship, a `within` of 0 and no device
refused) and to an agent as one `answer` event; the handler told the asking ship
and agent, and an owner's question naming no agent; refused when the interface
is open only to commands or to neither (over the API, to an agent, over HTTP as
403 with the other ship's reason), and an agent whose manifest does not let it
ask refused here with its event, nothing written and nothing reaching the other
ship (nor a question to this same ship, with no time, or with more than
allowed); the handler unable to write, send here or to another ship, emit,
append, mark a file or ask, each a failure with every row count of the ship
asked, and the lengths of its file and of its `-wal` (the ship awake, so a
change could sit in the `-wal`), the same (lengths and counts, not the bytes),
no log entry and nothing emitted; a handler that traps, runs out of fuel (in
under 2 s) or spins past its time (400 ms; it held the ship under 700 ms)
failing, the asker's own shorter time (200 ms) being the cut-off, and the ship
answering and running events after; a question larger than this runtime asks
refused here, one larger than the ship asked takes answered `limit` with nothing
run, answers larger than the ship asked gives or than this one takes `limit`,
and an agent handed `limit`; a flood from one ship (twelve threads for four
seconds, with the allowances to start questions set too large to matter) never
holding more than 2 places from that ship or 8 in all (sampled every 5 ms), some
of it too busy, another ship still answered meanwhile, and every question the
ship admitted past its look at the rests (each one it went on to run; not those
refused there) beginning no sooner than three times the last one's length after
it ended and nine times after the last from the same ship (exactly, by the
ship's own clock); four threads asking as fast as they can for two seconds with
the default allowances, the ship asked admitting past its look at the rests no
more than 8 a second of them and as many again at a stroke (it counts those it
went on to run, not every start an allowance was charged for); a question given
up on while it waits for the ship (held by an event kept at a gate, let go only
once the ship asked has seen the asker gone) running nothing, and one given up
on while it runs (the giving up seen before its deadline) still stopped for time
by its own stop record no earlier than its deadline (and less than 300 ms
after), the ship released in under 1.3 s; questions given up on while they wait
for their ship's slot (held by an event kept at a gate), and others while they
wait for a place among the awake ships (the one place held by another ship's
event kept at a gate), each asker seen inside that wait by the runtime before it
gives up, giving their places back less than 500 ms (a test threshold) after a
moment noted once both askers were gone, by the runtime's records, while the
ship is still held, and a question that runs out of its own time (300 ms) in
each kind of wait (seen by the runtime in that wait) giving its place back less
than 200 ms after its one recorded deadline; a question held at the start of its
ship's wake (the runtime's gate there) whose asker gives up meanwhile, and one
whose time passes meanwhile, asking no decision of the kernel (counted where a
decision begins), the second told "it took too long"; with the watchdog's sleeps
made 15 ms long, an event and a question each given a second, by the runtime's
own record of that call's one stop (taken after the call began, so an earlier
call's record cannot stand in for it) stopped no earlier than the deadline it
was given and less than 115 ms after it (and the event's whole run, by the
runtime's notes of when it began and was done with, under 1,115 ms); with the
watchdog held still for three seconds and let go as soon as such a call's
handler had its deadline set, the call not stopped at once by the ticks missed,
but no earlier than its deadline and less than 110 ms after it (each figure a
test threshold, and each includes 100 ms for scheduling); the ship asked
counting a question's time from the one moment it took the request up (held 100
ms between that and setting the deadline, the deadline it recorded that moment
plus the shorter of its own limit and the allowance the asker recorded as it set
it (the first, provisional one, which its first write could have lowered; with
two seconds against five here, it does not), within 1 ms); the asking side's
deadline taken as `Runtime::ask` is called (held before the network has the
question, or with its task held before it first runs, until the recorded
deadline has passed: nothing sent, and `NoAnswer`); the allowance worked out
from a clock sample it is given floored to whole milliseconds and never more
than the asker gave (a sample with 999 µs left: nothing to send; this observes
no writer and no moment of acceptance); an answer read after an agent's
question's deadline (held by a gate until the task's recorded deadline passed)
handed over as `NO_ANSWER`, not as a reply, and a refusal as too busy held the
same way past `Runtime::ask`'s deadline `NoAnswer`, not `Busy`; a question whose
first try reached its ship (held there) and whose later tries could not (that
ship's network stopped, its entry still listed) `NoAnswer`, not `Unreachable`;
an answer larger than the asking runtime reads, and a question larger than the
answering runtime reads, each `Limit` to `Runtime::ask` and `LIMIT` to an agent,
not tried again, and so a question several times the answering runtime's stream
window (so it cannot all be written before that runtime stops reading it), one
try each (that case may take either way: the refusal read while the question is
still being written, or after the write failed; it is not made to take the
second), and, with the answering runtime held after sending its refusal and
before letting go of the request (so nothing stops the write), `Limit` before
that runtime lets go of the request's receiving side, by its notes, through
`Runtime::ask` and an agent; a reply taken for a refusal only if its outer
fields are all the refusal with a reason (unknown fields alone, nothing, a
truncated field, a refusal with a body or with no reason, every kind of typed
reply, and a `Fetched` of 300 entries even when they could not be decoded, are
not); a question's first write (to a stand-in connection, on a stand-in clock)
sending no byte when the connection is not ready until after the deadline,
carrying no more than the whole milliseconds left by the clock reading of the
poll in which the connection takes it when it is ready late (encoded again, once
for each smaller allowance), and encoded once (counted by the encoder it is
given) when it is ready at once (the rule is against the clock reading taken in
the accepting poll; time spent after that reading, encoding, waiting inside the
writer or descheduled, is not in it); a question's first call on a ship just
created after the network started (to an agent it does not have), and on one
brought in from a copy (answered; checked, by a connection that only reads, to
be in the older journal mode before, and still in it after), and a question to
that copy once ordinary work had switched it to WAL and it was put to sleep,
each leaving the bytes of the cleanly closed file the same, each baseline taken
first and each compared once the ship is put to sleep again (it cannot see a
write put back before the file closes, and covers no file needing crash repair);
a `within` on the HTTP route with no value, empty, not decodable, not a number,
0, past the most, or given more than once (`within&within=1`,
`within=1&within=%FF`, `within=1&within=2`), or with its name spelled with
escapes (`%77ithin=0`, `within=1&%77ithin=2`), or with a `%` not followed by two
hexadecimal digits (`label%+1=x`, `within=%+1`), each refused with 400, no
question written; a thousand questions (answered, refused, failed, too large,
too busy), begun (once the network's start-up look is done) with the ship asked
put to sleep and nothing compiled, not even its kernel, leaving every row count
of the ship asked, and the lengths of its file and of its `-wal`, as they were
(lengths and counts, not the bytes), the first told it is too busy while its
kernel is compiled off its path, exactly two compiles in all (counted: the
kernel and the agent asked, once each), and a leftover file in the ship's
directory still there until an ordinary call wakes it; a question to a warm ship
answered at once while another call is held part way through a compile; one
module compiled once while two questions and an ordinary call ask for it (the
second question too busy, the ordinary call waiting for that compile), and a
compile that panics stopping no later one; exactly one answer for a question to
a ship no directory lists (within 5 s) and for one whose handler traps; a
question to a ship that vanished answered once, its answer's handler committing
between 1.9 and 3.5 s after its asking event committed (by the runtime's
records) for 2 s given; another, its task held just after reading the question
(a gate) while its asking ship is put to sleep, answered once with no other wake
of the ship: by the runtime's own records, the ship's first wake after being put
to sleep was for writing what came of the question, exactly one place among the
awake ships reserved for it since (noted where it was taken), no earlier than
the question's time as its row has it, and the answer's handler committed once,
less than 3.5 s after its asking event committed (the task let go only with time
left to its recorded deadline); a question waiting on a ship whose inspection is
made to fail once when the network starts asked again and answered, nothing else
done on that ship; questions waiting through a restart of the asking runtime,
one with time left asked again and answered once the other ship is back, one
whose time ran out meanwhile answered `NO_ANSWER`, each once; a question waiting
in an exported ship answered `NO_ANSWER` once in the import, no question left
waiting there, and the next numbered after it; a question holding room in a full
queue for its answer (refused when there is none, handed over as `LIMIT` with no
room for its reply, and a ship with a full queue and questions waiting exported
and imported under the same settings, and one with a question more than its
queue has room for refused); with names at their longest (a comet's, an agent's
of 64 bytes, an interface's of 128), the room held no less than any answer with
no reply takes, counted in the queue's total as the question is put, the same
when the ship is woken afresh, and given back when it is dropped; an answer
written as an old network's job would write it, after the asking runtime's
network was stopped and a new one started, still run with nothing more arriving;
the write of what came of a question made to fail three times, then written, one
answer handed over; a drop while it waits between writes ending its task within
a second, nothing handed over; a restart while it waits, the question still
there and answered once; a dropped question never answered, whether its answer
was queued (taken off the queue, dropping again saying so) or it was still
waiting when its time ran out; an answer and the time running out written at
once from two threads two hundred times, one queued and the other finding
nothing every time, and another copy's mark settling nothing; an event that
fails putting no question; `max_asks_waiting` held to, an answer queued still
counting and a drop making room; with no network, a question answered
`UNREACHABLE` in the same `deliver`, and `Runtime::ask` refused. For receipts: a
reply only when asked for and only with `RAN` (a command without it, one that
fails, one with a reply at the limit and one a byte over, which is `LIMIT` and
whose effects are not kept); `LOST`, made by comparing notes, with no reply
though one was asked for; exactly once across a restart of the sending runtime
while its command waited unsent, and a restart of the other ship's runtime after
the command and its receipt committed there (they are one commit) and before the
receipt was taken, the reply from the one run handed over once; a ship that
takes back no reply refusing to send a command that wants one (its limit on
replies 0, or its queue 592 bytes), and sending one that wants none; two ships
that filled up with commands for each other, every one wanting a reply of 16
KiB, getting every command answered (ran with the whole reply, or `LIMIT` for
want of room for it), each counter counting exactly the commands that ran, and,
once their queues are run, more such commands coming back `RAN` with their
replies; a reply held to the smaller of the sender's bound and the receiver's
own, either way round (512 and 1,024), an empty reply marked as one, and a
receiver that predates replies answering `RAN` with `replied` unset, which the
agent is told is a run without a reply; a command sent allowing 1,024 bytes, its
sender then restarted allowing 512, still bringing back its 1,024; two ships
full of commands for each other, each having first taken two 64 KiB replies from
third ships, getting every command delivered, each receipt kept in the audit log
as its facts (within 512 bytes) and no audit row holding any run of a reply's
bytes; deliveries at the boundary of one message (a command of exactly the
largest size with a reply of the largest size, and one byte over not sent; a
question and an answer each at the largest the settings allow) arriving whole;
an export holding a queued answer of 2 MiB, a queued receipt with a reply at its
limit and a question at `max_ask_bytes` imported under the same settings, and
again once they were handled (their audit rows facts only); an export holding a
command kept with its reply bound and a receipt with its reply owed to another
ship imported, and versions of it changed to hold a bound over the ceiling, a
receipt owed marked as carrying a reply with a verdict other than `RAN`, or a
reply over the ceiling, refused; a ship exported after its limit on replies was
lowered (from 1,024 to 512), with its receipt awaited and with it queued,
imported under the lowered settings, the queued reply handed over whole;
settings at `usize::MAX` held to their ceilings, and a ship with nothing new and
one with queued records exported and imported under them; thirty questions
dropped once a try of each had gone out and come back refused, leaving no task
putting any of them and no try after; a dropped question's task stopped within a
second though the dropping event keeps its ship for three; a drop committed
while the network was held between looking through the ship's questions (which
registered the question's means to stop) and starting their tasks, the task
ending, by the runtime's records, less than a second after the drop committed,
the ship still held, and nothing of it written to a stream; a drop in that same
gap making no second look at the ship; a question held where its stream is about
to be opened, dropped meanwhile, writing nothing once let go (and, apart,
`unless_stopped` with its stop already signalled and its work ready ending at
its first poll with the work never polled); a load check: while another agent
asked and dropped questions as fast as it could for two seconds, a question
asked meanwhile registered, and another ship's command run on the ship it was
for (and counted there), each less than a second after its event committed by
the runtime's records (it does not show a drop committing inside either
interval); one ship held by an event just after it asked a question of its own
(and with no commands waiting), its look said to be waiting for it on its own
thread, and then another ship of the same runtime's question arriving at the
ship asked, its command run, and its answer handed over, all while the first is
still held; one ship held by an event just after it sent a command, the carrier
said to be waiting for it on its own thread to find where that command goes, and
then another ship of the same runtime's question arriving at the ship asked
while the first is still held; a listing of the ships' directory that reports
one entry as an error every time, the directory listed again and again, a
question waiting in a ship it did read answered meanwhile, and that ship looked
at once; a settlement waiting for its ship (held by an event) when the network
stops giving up less than a second after, by the runtime's records, the ship
still held, the runtime then held by nothing but the test, and the question
answered once, as unreachable, by the next run of the ship's queue; the network
started again on the same address while a look, said to be waiting on its own
thread, still waits for its ship (it binds while the ship is still held); a ship
owed its first-wake upkeep woken by a question's task reading the question, a
drop committing meanwhile and its event kept: the read returning less than a
second after the drop committed, the ship still held, and the upkeep done by the
next ordinary call; one budget paying for the kernel's decision and the handler
(a ship given less than both together failing though the handler alone would
fit), and for a nested read's decision and handler too (all of it no less than
the parts, and less than all by half the nested decision failing); an HTTP
question counted with long polls (refused 503 when they hold every waiting
place), and a slow one holding its count while it waits (a long poll answered at
once meanwhile, and waiting its second after); and `Network::start` refusing an
`ask_fuel`, `ask_millis` or `max_ask_millis` of 0, places or allowances of 0,
and messages too small for the largest command, with sizes past their ceilings
held to them. A request of a kind a runtime does not know (a body field it has
no name for, as a question is to an older runtime) is answered with the bare
refusal for an unknown request. The kernel: a read from another ship only to an
interface open to questions, for an agent or an owner on that ship and never
with `owner` set, not to one only `remote` or only public, a command from
another ship not let through by `asked`, an answer to any installed agent and
not to one that is not, and grants to ask exactly the declared uses with `ask`
and a ship; and agents installed until the kernel refuses one (one declaring 64
uses of other ships with read, send and ask, then agents offering public
interfaces), every answer it then gives within its 256 KiB. In `store.rs`, a
command without a reply wanted, its receipt, and a `SendRequest` without `reply`
encoded to the same bytes as written out by hand from the fields that existed
before, and the reply, when wanted, one field more; and a receipt's reply held
to a command's size.

`runtime/tests/serve.rs` runs the real `serve` binary as a process of its own
(`CARGO_BIN_EXE_serve`), and knows it only by what it prints and what it
answers over HTTP. Each program it starts is in a process group of its own,
owned for the whole test, and the whole group is killed however the test ends,
so the walk-through's three programs go with it even if it is killed outright.
The group's leader is never reaped before the group is killed (that it has
ended is seen with `waitid` and `WNOWAIT`), so the group's number cannot have
been given to another group by then, and nothing is signalled after it is
reaped. Nothing is ever killed because its command line matched (the list of
running processes is only read, to show that nothing was left). The walk-through
(`--two-ships --then-stop`) exits 0, says each of its eight steps and each
check it makes (the introduction the ship called reports, the refusal in that
ship's own words, both lengths and fingerprints, the first ship off, both
messages after it comes back, the question answered, the question to the
journal refused with the first ship's reason, and the reply on the receipt),
prints no em dash and no exclamation mark, and leaves none of its programs
running. The answer step 8 says it was given and the reply it says came back
are then checked against the first ship's counter, read with the library: the
reply one more than the answer, and what the counter holds. Each of the four messages it says
arrived, as entry N of a ship's journal, is then read with the library from
that journal: entry N is that message, with this run's word. A second run on
the same directory reuses the ships, has a word of its own, shares a file the
test made, whose length and SHA-256 the test checks against both lines the
walk-through prints for it, and gives the three programs `--sleep-after 1`
(whether a ship was in fact put to sleep during it is not seen). The
walk-through refuses a directory that holds something else, an empty file to
share and one that is not a regular file before it starts anything, and a
directory another run holds. A ship killed and started again on another port
is reached again within 15 seconds by two callers in this process, one whose
requests may take 20 seconds and one whose run out of time after one (each
took the 30 idle seconds before); and a ship whose lookup point is killed and
started again at its address is found again within 27 seconds of the kill (46
before). The ship test times each command from when it was handed over to
when it arrived (under 15 seconds); it takes a baseline before each try's two
priming commands, which are sent on the kept connections after it, and a
caller's first try after the restart more than 15 seconds after that baseline
could have found the old connection run out by itself, so the try proves
nothing. The point test times from just before the kill to the ship being
found again, and a restart more than 15 seconds after the kill proves
nothing. Either test then starts over, three times at most, and then fails
saying the machine was too slow to tell. Also: a ship served with `--max-file-bytes 0` refusing an
upload (403), and one served with `10M` taking one and refusing one larger
than that (413); `--pretend-ids` saying where keys come from and never "with
keys from Urbit ID", and `--lookup` answered from the list with no network;
and flags that do not go together refused at start, naming the flag or the
list's line, with nothing made, including each file flag and module path
naming a path in the data directory's `tmp/`, a name there that links to a
file elsewhere, a path through a link there to a directory elsewhere, a path
through `TMP` where `tmp` is not made yet, and a path that goes up through a
directory not there yet.
They do not show two machines, a real router, the relay carrying anything,
Linux, or a release build (they run the debug build), nor `--max-cache-bytes`
reaching a ship: it is read by the same function as `--max-file-bytes` and set
beside it, and is not tried.

Unit tests for this part: in `pretend.rs`, a list's shape, a ship listed twice
and one key under two ships, each naming the line, the list read again at
every question (a ship taken off answered as listed with no key), and a list
that can no longer be read, is not a regular file, is too large or is not text
answered with an error and never an earlier answer; in `net.rs`, a directory
reading a pretend list taking a ship off it, and a new key, at its next
reading, though it believed the old key for an hour, and keeping nothing for a
ship never listed; in `remote_tests.rs`, with two real runtimes, a ship slow
to answer (five and a half seconds, where silence is noticed after two)
answering on the same connection while other requests on it go through (begun
once the slow one is known to be held at the other ship), a request that runs
out of time on a working connection (a command's delivery held past its time)
closing nothing while a slow request on the same connection finishes, a
request that runs out of time having heard nothing at all since it was sent
(everything from the other ship held back by a stand-in for the path between,
the caller's count of what it heard still for half a second before the
request and checked unchanged after it, the hold ending a second and a half
after the request) closing nothing, the same connection answering the next
request; a ship that vanishes (its network stopped with no goodbye) while slow
requests hold every stream it allows, after the caller's counters have not
moved for a second (which makes it very likely, and does not prove, that
nothing sent before is still waiting to be acknowledged; on a machine that
held both ships' network threads for that second, the mutation that counts
only stream data and pings could be caught by a retransmission instead),
given up after the silence, a
request waiting for room told that nothing was heard, and the next call making
a new connection when it is back elsewhere; and datagrams that do not
authenticate, sent every 50 ms by the stand-in from the vanished ship's
address with the connection's own ID, so that they do reach the connection
(at least ten counted), not keeping it; in `store.rs`, packing a new file stopped from inside
the statement when the question "is time up" is answered yes at its third
asking (and asked no more), and not started when it is answered yes at once,
audit rows brought in oldest first filling their pages, none read when
`audit_rows` is 0 (with a row at the largest number and the count brought
down, which read would refuse the copy), and a packed file over the limit
refused naming both sizes; in `lib.rs`, a ship part way through a call (held
at a gate inside the call) not put to sleep by a sleeper or a forced look, the
default import limit being at least the ship limit and the seal, and sizes as
`--max-file-bytes` takes them; in `seal.rs`, a sealed copy being its contents
and 95 bytes; and in the `serve` binary, every line `said.rs` makes reading
back as what it was made from.

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
- The directory that holds the copy of Azimuth is taken to be the operator's
  own. What is found there when the copy is opened is checked (no file SQLite
  would take as part of a new copy, nothing that is not a plain file with one
  name at the copy's name once a symbolic link to it has been followed, and no
  link, second name or other thing that is not a plain file beside it);
  another program writing in the directory while the copy runs is not
  defended against: it could replace the copy at any time, and nothing stops it
  changing the files a restore makes there while the restore works.
- Snapshots are written and restored only on macOS (`renamex_np` with
  `RENAME_EXCL`) and Linux (`renameat2` with `RENAME_NOREPLACE`): putting a
  file in place without the risk of replacing one needs such a call. The Linux
  path has not been compiled or run. On other systems `serve` refuses either
  snapshot flag before the copy is opened or anything is made, and the copy
  can still be made by reading Azimuth from the start.
- A copy started from a snapshot takes the snapshot's word for every point
  that has not changed since its block, until someone reads to that block
  themselves and gets the same fingerprint (see Starting the copy from a
  snapshot). Keeping the hash of each step's last block costs one more question
  to the node for each step.
- A hard link to the copy's file made by someone else at the moment it is
  opened, after its name has been checked, is not caught. It takes someone
  who can already write to the directory.
- The copy skips Azimuth's domain names and the operators of `ApprovalForAll`,
  which `naive.hoon` keeps and nothing here needs. Counts of transactions, key
  revisions and continuity are kept in 32 bits, where `naive.hoon`'s have no
  limit; each would take four billion signed transactions on Ethereum to go
  round.
- When an address is given by hand, or a ship's key changes, while calls are
  going on, the promise is in two parts. What is kept (records, keys, connections
  kept for reuse) is decided under the lock that guards it, and never on a
  reading that lock would show to be out of date. A call already under way only
  notices at its next check, if that re-read sees the change, so an attempt or
  a question it began before may go on, and it may begin one more after the
  change, following its last check; nothing short of holding the directory
  across network work could stop that.
- A record believed just before a ship's key changes still stands as that
  ship's newest record at this runtime, and refuses the ship's records dated no
  later than it, until this runtime's clock reaches its date plus ten minutes.
  Its addresses are still tried; whatever answers must prove the key now held,
  so a call succeeds if the ship itself is still at one of them, and fails
  otherwise. A record may be dated at most two minutes ahead of this runtime's
  clock when it is taken, so if both clocks agree and neither is set back
  afterwards, the ship's own later records are dated past it within two
  minutes. If a clock is set back, or the ship's clock runs behind, it is
  longer, up to the record's remaining life. How soon the newer record actually
  arrives also depends on when the ship next announces and when a caller next
  asks.
- A lookup point can keep a record back, or hand out one that has not
  run out (up to 10 minutes after the time the record says it was signed, which
  can be 12 minutes after the point took it); it cannot make one up or
  change one. That is about records; what a point says of where it sees a
  runtime is taken on its word, as the next limit says. A ship can name any address in its own record, so callers may be
  sent to try connecting there: at most 4 addresses, and one question about a
  ship every few seconds. A point learns which address asks about which ship.
  A point does not prove it is the galaxy, and the names points are found
  under are not authenticated.
- With no address given by hand, a runtime announces the address its point
  says it sees. A point that lies can make a ship announce a wrong address.
  That makes the ship unfindable (a point could already keep its record back)
  and sends its callers' first packets to an address of the point's choosing,
  as a ship naming any address in its own record already could, within the
  same bounds. An address given by hand is never replaced or added to by what
  a point says.
- A ship behind a router that gives each destination a port of its own is
  reached only where its point relays. Where it does not, calls to it fail in
  their time and say so.
- The relay is the lookup point of the galaxy at the top of a ship's name,
  and nothing else relays: stars do not relay for their planets. It is not the
  ship's sponsor in Urbit ID; the two differ for a ship that has changed
  sponsors.
- With the defaults, eight ships of different owners (or one owner of eight
  planets) can hold all sixteen of a ship's sessions at its point, two each,
  which stops other relayed calls to that ship and nothing else. A moon counts
  as its planet, so moons do not add to that. The numbers are settings.
- A point that relays learns who talks to whom, when, and how much. It cannot
  read or forge what is carried, but it can drop, delay, repeat or misdeliver
  it, and refuse to relay at all.
- A point at its overall allowance slows every relayed pair it carries; one at
  a ship's allowance slows every pair calling that ship. Rubbish requests to
  relay, past their own connection's allowances and naming a ship that
  attends, spend the point's allowance of sessions made, as rubbish
  introductions spend the allowance of introductions; and a caller's own
  allowance is charged once its presence checks, even if the table then
  refuses (as for introductions).
- A relayed pair whose ship called remakes its connection to the point loses
  its sessions, and the caller's connection through it goes quiet until it is
  found dead (its idle time); the next call is relayed afresh.
- The relay costs every call to a ship behind a strict router the direct
  share (five seconds, or half the call) first; the next call on the same
  record goes straight to the relay. Going direct again costs a try every
  `direct_again` while relayed, which for a pair behind strict routers never
  succeeds.
- At a ship, a point the ship attends on can push sessions for any genuine
  record still good that it has seen, within the ship's bounds (8 per caller
  ship, a moon counted as its planet, 64 in all, for 30 idle seconds each);
  filling them stops relayed calls to that ship, which that point could stop
  anyway by not relaying. The 65,535 made-up addresses of a runtime are kept
  from reuse while a handle to their session lives and for the idle time and a
  minute more after; a runtime that made sessions faster than that could run
  out, and is then refused new ones until some are free.
- When a relayed pair goes direct, a request under way on the relayed
  connection at that moment fails (the ship called closes it as it takes the
  direct one), and commands on it are delivered by the usual redelivery.
- Relayed packets are 17 bytes larger. A caller keeps its packets small enough
  for that; the ship called finds the size by QUIC's own search, which treats
  a packet too large as lost.
- An introduction names the caller, and the caller's addresses, to the
  ship's point and to the ship, which a question (`Where`) does not. That is
  why only records that ask for it cost their callers one.
- A runtime asks callers to be introduced whenever the address its point sees
  is not the one it listens on. A machine listening on "any address" that can
  in fact be reached directly (many cloud machines) asks too; that costs its
  callers an introduction and nothing else, and `--announce` turns it off.
- Introductions let a ship's owner have other ships send a few small packets
  to any address it puts in its own record: at most 12 per introduction (three
  to each of four addresses), held to the limits on introductions per caller
  and in all, at the point and at each ship. A point that lies can have a
  ship send them for any genuine record still good that it has seen and that
  is newer than any that ship already holds of the caller, within the same
  limits.
- Two ships behind the same router are not helped by the direct way or an
  introduction: each is announced at the router's outside address, and whether
  a router passes packets from inside back inside through its own outside
  address varies. A point that relays does reach them, through itself. Local network addresses
  are not found or announced. An address given by hand, or the one a point
  sees, may itself be a private or loopback address, and is announced as it
  is.
- The timing of introductions (4 seconds an attempt, a second for the point's
  answer, the packets a quarter of a second apart, the limits on passing and
  reading an introduction) was judged from how QUIC behaves on this machine,
  over loopback, not measured over real distances.
- A point holds the streams it opens on a ship's connection to pass
  introductions; the ship stops reading one after 2 seconds, but its place
  comes back only when the point ends it. A point that never does holds all 4
  places, and so holds up only its own introductions to that ship.
- A connection made through a router that an introduction opened stays open
  only while its packets keep the router's memory of it fresh. A router that
  forgets an idle opening in less than `keep_alive` (15 seconds) loses it; the
  connection is then noticed dead only at the idle timeout.
- The stand-in router is a program in the tests. No real home router has been
  tried, nor hole punching or relaying over IPv6. `--behind-router` has had a
  run from end to end only over one machine's loopback address, where the ship
  called is introduced to its caller and acts on it, but would have been
  reached without. `--relay` has been started there and carried nothing, and
  its rates have had no run. The relay's timing (the direct share, the wait
  for the point's answer) was judged on loopback only.
- A point keeps a moon's latest revision only while it holds that moon's
  record, and builds no history of its own beyond that. The point is not
  trusted and its table is in memory only, so nothing it remembered could be a
  guarantee: a point that lies or restarts can hand out an old moon's record
  anyway. What decides is the caller's own memory of the moon's keys, in its
  directory. So a caller that has never met a moon cannot tell its parent's
  latest word from an earlier one, with lookup points or without; and while
  the real moon is not announcing, the holder of an earlier key the parent
  once vouched for can announce under the moon's name and be believed by such
  a caller. That comes of moon keys living off chain, not of lookup points.
- Several addresses for one point, given or found by name, are tried in turn
  as stand-ins for each other, not kept in step: a ship announces to the first
  that answers.
- A connection under the lookup protocol takes a place among the ships'
  `max_connections` while its handshake runs, and gives it up as soon as the
  protocol is known.
- A stranger can hold all 64 places among a point's requests in hand with
  requests it never finishes, each until its `request_timeout`, and while it
  does there is no fairness for honest callers of the point. Ships whose
  addresses are already known, set by hand or found earlier, are not affected.
- Records that are rubbish use up a point's overall allowance of records per
  second before they are checked, so one caller can spend it for everyone.
  Introductions that are rubbish do the same, to the overall allowances of
  records and of introductions, once they are past their own connection's
  allowances and name a ship that attends.
- Lookup points and the `serve` flags have been run only on macOS.
  `--lookup-at`, `--behind-router` and `--lookup-point` (with `--pretend-ids`
  in place of a copy of Azimuth) have had a run from end to end, in the
  walk-through, as three programs on one machine; `--lookup-domain` and
  `--announce` have only been checked for what they refuse. The system's
  resolver is not exercised by the tests, which look names up through a
  stand-in.
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
  no migration. Nor do ship files and exports from before files on the ship
  (schema 9 and earlier), nor from before a claim could be marked open
  (schema 10), nor from before files fetched from other ships were kept
  (schema 11).
- A file fetched from another ship is kept only if it has at most 32,768
  chunks (32 GiB); a larger one is passed through and fetched again each time.
  A piece is kept whole or not at all, and pieces are fetched one at a time,
  for opening and saving alike. An agent cannot start a save or see what is
  kept; a save goes on only while a device calls; the owner is not told when
  the other ship has taken a file back (what is kept still opens); there are
  no thumbnails. "Least recently opened" is to within a minute, since when a
  file was opened is written at most once a minute. A save not called for a
  day stops without throwing others away for it. Lowering `max_cache_bytes`,
  `max_ship_bytes` or `max_kept` between runs throws nothing away at once: the
  cache may be over until sweeps bring it down, a budget at a time. While its
  rows are over, no new file is kept in it (pieces of files already kept may
  be); while only its bytes are over, a new file may be begun with no bytes,
  and no piece is kept until the bytes fit.
  Copies no row names in a kept file's directory count against no allowance
  until their directory is thrown away: with copies on their way, at most two
  per directory at once, and after a crash what it left there until the next
  life's first keep into that directory (see On disk under Keeping what was
  opened, and saving a copy). Uploads and saves do not throw away kept files
  when the ship's own file is short of room: the rows of files in the cache
  are held to a sixteenth of it instead. A slow disk can delay the next piece
  of a contents answer by the time one keep takes (one took 41 ms at the
  median on a Mac laptop; a keep can also wait for the slot, throw away and
  drain), and a disk that hangs inside a commit holds the ship's slot, as it would
  for anything else; at most two pieces are kept after their answer at once
  in a runtime, and others are then not kept. On a server of two workers, a
  kept file's whole contents are refused, as a file of the ship's own would
  be; what it is and its chunks are had. A save call that finds its file's
  stored hashes do not vouch for its id answers 500 once, ending its own save.
  The drain takes the trash 16 records at a time from its front, and stops
  when a batch strikes nothing off. Records whose removal keeps failing stay
  at the front, and so does a deleted file's sweep waiting for its directory
  to go; when such records fill a batch (16 removals that fail, or 8
  directories that will not go, each with its waiting sweep), the records
  behind them are not reached until one of them goes. What is not removed
  stays counted, so this costs room and never removes or releases anything
  wrongly; it takes a disk that refuses removals.
  For a file the ship does not keep, the
  hashes are fetched again for every HTTP request.
  Only the owner's devices fetch: an agent cannot start a fetch, and there is
  no public web link. A chunk is the smallest piece
  asked for, a range is not resumed inside a chunk, and chunks are fetched one
  at a time. Nobody is told who fetched what. The time it takes to say no is
  not made the same for every reason. Closing a file under
  `Durability::Normal` is as durable as any event, no more (as for
  `log::unshare`). A file of more than 2^30 chunks is not served. Agents
  cannot read a file's bytes.
- Two ships that are allowed a file (any two ships, if they know of an open
  file on some ship of this runtime) can hold all eight of a runtime's places
  for file requests by reading their replies slowly, each for up to
  `file_timeout`; other ships' file requests are then told to try again.
  Commands and logs are not affected. There is no fairness between callers
  beyond the 4 per connection and the 8 in all. A ship that reads nothing on
  its own connection stops everything coming back to it on that connection,
  its own commands' acknowledgements included. A bare refusal, of any kind of
  request, and a file's no hold no room once decided (nor anything of the
  request), so such replies left untaken shut out nobody else; an allowed part
  whose asker stops taking it keeps its room and its places until
  `file_timeout`, which is the limit stated just above. The replies of the kinds
  that came before files that carry a body (a ping's answer, an acknowledgement
  of commands, a log fetch's answer, its `denied` included) still hold their
  room for reading until they are taken or `request_timeout` runs out, so a
  ship that takes none of those can, with enough connections, use up the room
  other ships' requests are read into, for that long. Bare refusals and file
  requests do not add to that.
- Under a flood of fresh questions (many callers, each with a reference), a
  ship rests from asking for three times as long as each question took, and
  an allowed ship may be told no meanwhile and must try again.
- Identical files are kept once per ship, not across ships, and chunks are not
  shared between different files. The HTTP server keeps no connection open
  between requests, so each chunk is its own connection. An import that stops
  part way does not carry on where it left off.
- The files of an import are not under `max_import_millis`; they take as long
  as their bytes take to read, bounded by the lengths in the ship's file.
- When a files stream is supplied with a copy, a runtime with a smaller
  `max_file_bytes` or `max_files` than the ship's files need refuses that
  ship's import, rather than bringing it in without some files, and a runtime
  with the store off refuses any ship that has files. Without a stream, the
  ship comes in without its files, whatever those limits.
- The runtime syncs its data directory, and the data directory's name into its
  parent, every time it starts, and the names of any ancestors it made itself
  in that start. If making a deeper ancestor was cut off before its sync, in an
  earlier start, making that path durable is the operator's to do.
- What happens to the files on a power cut is argued from the order of syncs
  (bytes and their directory names synced before the commit that names them;
  bytes removed only after a synced commit), not tested: a power cut cannot be
  made to happen in the tests. Failures at chosen points are tested through
  checks compiled only into the tests: a failure before a chunk's commit is
  tried, a commit that fails (undone, or kept and then reporting an error), a
  generation already taken, a directory sync that fails once, a panic inside a
  transaction, a failed removal, a failed sync after removals, and a failure
  after an import's hard link. A real `COMMIT` failing inside SQLite is not
  made to happen; the code treats every error from it as of unknown outcome.
- An exported copy and its stream of files are two files, not one atomic step:
  a failure between them leaves an older copy beside a newer stream, and an
  import of the two keeps the ship and drops its files.
- Which modules a ship needs is known only to its kernel. A kernel that leaves
  one out of `ListModules` produces an export that imports cleanly and fails
  when that agent is first called.
- A kernel rewrites its whole registry, dropping fields it does not know, so a
  kernel must never run against a registry written by a newer one.
- The runtime signs whatever state a checkpoint handler returns; it cannot
  check it.
- `verify_log` shows that entries are genuine and contiguous, not that they
  are all there is; that needs the head from a trusted source.
- Questions between ships: a question that failed on the ship asked (a trap,
  out of fuel or time) leaves no row or audit row there, so its details are
  kept nowhere: writing them would let an asker fill the audit log. (It does
  leave what any call leaves in memory: the rests and allowances, and a module
  compiled for it, or a compile failure remembered with its reason, retried
  only by the owner's `add_module`, as under Answering.) Fairness between
  asking ships is per name, so one owner of many ships (a planet and its
  moons) gets each ship's share; the rests and allowances are in memory, so a
  restart of the ship asked forgets them. Questions are not queued on the ship
  asked: one that finds it busy, or a module it needs not compiled, is told so
  and asked again by the asker. Questions have no turn against ordinary work:
  a ship kept busy by ordinary calls leaves them to end "too busy" or "it took
  too long" at their time. A question given up on once it has its ship runs on
  until it is stopped for time (below) or returns. An agent's question is put
  as long as its time lasts, so questions to ships that do not answer hold one
  of the requests agents' questions may hold (a quarter of `max_requests`) for
  as long as each try lasts (up to `request_timeout` to connect, and then what
  is left of its time), and questions to ships that do answer can wait for
  those places meanwhile (and be answered `NO_ANSWER` if their own time runs
  out first, as is one that never got a place for a first try). With
  `max_requests` at 1, an agent's question waiting can hold the only place,
  and the owner's own question is told it is too busy.
- An agent's question's time is stamped from this runtime's wall clock just
  before the asking event commits, in whole milliseconds, so a slow commit uses
  some of it; the network's task turns it into a steady-clock deadline once,
  when the question's task starts, before it reads the row (the steady clock
  read first, then the wall clock, so a pause between the two can only make
  it earlier), so a clock set back or forward afterwards does not move that
  task's deadline, though a restart reads the stamped time afresh against the
  clock as it then is. Three steps follow a question and
  only the first keeps its time. The network gives up at the deadline (as in
  Who looks, and when). Writing down what came of it (queueing the answer
  event) needs a working place, the ship, and, if it is asleep, room among the
  awake ships: a busy but healthy ship delays it, with no limit of its own,
  and a ship whose file cannot be written (full, the room it keeps used up by
  ordinary events, or an I/O error) has the write tried again with no bound on
  how long, until it goes in (see Room for the answer); the owner makes room.
  And the agent's `answer` handler runs when the ship next runs its queue,
  behind what is already queued and within the queued events one `deliver`
  runs (`max_queued_per_deliver`). Questions waiting in a ship whose file could
  not be read when the network started (or that a listing of the ships'
  directory could not read) are looked for again, with growing waits, until it
  can be read. The look through every ship's file when the network starts is
  one piece of work in one working place, as at the base, and what it finds is
  handed on when the whole look returns: one ship held for a long while in it
  holds up the handing on of what was found in every ship of that look, those
  looked at before it too.
- A question stores no application data on the ship asked. Opening a ship for
  it, or putting another ship to sleep to make room for it, can recover a
  transaction that a crash interrupted, copy pages that ordinary work had
  already committed from the log beside the file into the file, and create or
  remove the files SQLite keeps beside the ship's file (see What a question
  does leave behind). The tests show the bytes of a cleanly closed file are
  the same after a question; they do not cover a file that needs crash repair.
- A call is never stopped for time before its deadline. After its deadline it
  is stopped at the first point where the running code looks (a loop turn, a
  function entry, a bulk memory step) and finds both that the watchdog has
  ticked since the call was last allowed on and that the deadline has passed.
  The watchdog ticks about every 10 ms; the system can run it, and the call's
  own thread, late; and after a look that came just before the deadline the
  call can run on until a later tick; so no number is promised for the
  overrun. A host call under way is not cut short. Whatever a call returns
  after its deadline is not kept. The opening of a ship's file for a question
  is not cut short either. The tests' own figures (a stop within 110 ms or
  115 ms of a deadline, with the watchdog woken late or held still) are
  thresholds the tests allow on one machine, not promises.
- The network finds which other ships a ship's commands are for one ship at a
  time, waiting for each ship in turn (`carry` in `net.rs`): a ship kept busy
  (a long event, or a long queue) that has commands waiting holds up finding
  other ships' new commands for as long; lanes already running carry on.
  Questions are not held up this way: their notices are taken by a task of
  their own beside the carrier (`start_looks`), and each ship's questions are
  looked at by a look of their own (see Who looks, and when).
- Question notices and registration proceed independently of command discovery,
  but reading a registered question needs a shared working place, so it can
  expire unsent while those places are occupied.
- The network does no periodic question scan of sleeping ships, but an
  outstanding notice can wake a ship after its last question was dropped, and a
  queued answer can wake it again to run its queue or check for outbound work.
- The network can wake a sleeping asking ship to list its waiting questions, to
  read a question before sending it, and to queue its outcome.
- A try that finds the destination absent from the directory ends the question
  as `Unreachable`, even if an earlier try reached it, while a try already
  awaiting its reply can still complete.
- The first-write rule uses the clock reading taken in the accepting poll, and
  time spent encoding, waiting inside the writer, or descheduled after that
  reading can carry actual acceptance past the deadline.
- Each ship with a look at its questions outstanding can occupy one thread of
  a shared pool of blocking threads until the ship, or room to wake it,
  becomes available, and that wait is not cut short when the network stops.
  Enough such waits at once can delay work for other ships.
- The rule that a whole reply comes back with its receipt, and that a receipt
  always fits one delivery, holds while the limits in force are not made
  smaller than they were when the command was sent. Making `max_message_bytes`,
  `max_inbox_bytes` or the reply limits smaller while commands or receipts are
  outstanding is not supported in this prototype. What can happen: the lane
  between the two ships held at that receipt, which no longer fits one
  delivery, retried ahead of everything behind it; or, if only the sending
  ship's queue limit shrank, the command closed with the reply not handed on
  and an audit line saying why. (The same is true, as before, of any message
  queued that is larger than a newly smaller limit.)
- The watchdog tests' figures (110 ms and 115 ms past a deadline, 1,110 ms and
  1,115 ms for a whole event) include 100 ms they allow for the system to
  schedule threads (`ask_tests.rs`); the
  version-13 ship files exclude files written by earlier, uncommitted versions
  of that schema (see Commands between ships, exactly once, under Export and
  import); and a module whose compile failed is remembered as failing
  until the owner's `add_module` of it (see Answering).
- A command that wants its reply, run on a ship short of room, does not stand
  (`LIMIT`) though it would have run without the reply: the reply is never
  allowed to use the room the ship keeps for taking a command back.
  The whole reply comes back with RAN from a receiving ship that follows the
  protocol. A receipt can say RAN with `Receipt.replied` unset when the other
  ship's runtime predates replies, or when it broke the protocol (a reply over
  the bound the command was sent with, or a reply not marked): the command is
  still reported as run, because the other ship said so; no reply is handed
  on; and when a reply came and was let go, the reason says so. An agent that
  needs the reply checks `Receipt.replied`.
  A ship that takes back no reply at all refuses to send a command that wants
  one.
- Ship files and exports from before version 13 do not open. Ships near their
  size limit have two pages fewer for everything else than before, the price
  of the table of questions and the index on queued answers.
- Two ships still out of step after one resync stop exchanging commands. The
  commands are kept, and nothing sorts it out yet.
- A followed log that stops because the publisher's history changed is not
  repaired; the agent has to unfollow and follow again.
- Two runtimes with different size limits can still disagree about what fits
  in a message.
- The HTTP server speaks plain HTTP and expects a proxy in front of it (see
  Run).
- `serve` refuses a file flag or module path in the data directory's `tmp/`
  as written or as it finally leads, but not a path outside `tmp/` whose own
  links lead through a link inside `tmp/`. If that link is directly inside
  `tmp/`, start-up removes it (only an operator could have made it), and the
  file can no longer be read by that name; deeper down nothing is removed.
  See the `tmp/` row under Data directory.
- `serve` reads its arguments as UTF-8, so a path that is not valid UTF-8
  stops it at start with Rust's own message.
- A ship that stops without closing its connections (its process killed, its
  machine gone) is noticed by a ship holding a connection to it only once
  something sent on that connection goes unanswered for `silence_timeout` (3
  seconds), and the watcher can be up to two quarter-second looks late, plus
  scheduling, plus QUIC's current probe timeout in one case. There is no bound
  that holds whatever happens: if nothing can be sent at all (every stream
  held, everything sent acknowledged, nothing left to send), the clock does not
  start until something is, such as when a waiting request runs out of time
  and resets its streams, or until `idle_timeout` ends the connection. A
  connection with nothing waiting on it is not judged, so it is noticed when
  it is next used. A connection that works is given up too if
  nothing at all arrives on it for three seconds while something waits (a link
  that drops everything for that long, a peer whose process is stopped or not
  scheduled, a laptop asleep): the requests on it fail and are tried again on
  a new one, and commands are still delivered exactly once. The figures
  measured (6.5 seconds for a command to reach a ship that came back
  elsewhere, 3.3 at the same address, 18.5 seconds for a ship to be found
  after its point came back) are from one machine, on loopback, with a lane
  not in backoff and one address in the record; a lane in backoff (up to 30
  seconds more), up to four addresses in a record (3 seconds each), a point's
  announcing and a relay all make it longer. They are not bounds.
- Every import packs the new file (`VACUUM`), which takes time (about 1.4
  seconds more for a 300 MiB copy of large kv rows, in a release build),
  memory about the size of the packed file for a moment (after the copy itself
  is let go of), and disk up to twice `max_ship_bytes` for the file while it
  is built, besides SQLite's rollback journal while rows are copied and any
  files and modules brought in. Before packing was added, three of the five
  ways of filling a 4 MiB ship did not come in to a runtime with the same
  limit; now all five do, at 942 to 1,021 pages of 1,024, each with no more
  pages than its original. That is what was measured for those five fills,
  and no more: that a ship within `max_ship_bytes` always comes in is not
  proved, and how much room is left for what it writes next was not measured.
  A ship that SQLite cannot pack within the limit is refused as
  `Error::ShipTooLarge`, and one that does not fit even the room it is built
  with as `Error::NotBuilt`.
- The walk-through (`serve --two-ships`) is three programs on one machine,
  over its loopback address. It has not been run across two machines, behind a
  real home router, or on Linux, and nothing in it makes the relay carry a
  packet. It has been run in a debug build by the tests and by hand, and once
  by hand in a release build (before silence was noticed). The first message
  to a ship took 2.1 to 3.6 seconds in runs of the debug build and 0.2 seconds
  in the release build (where the time goes in the debug build was not
  measured); a file allowed just after it was refused opens about 5.5 seconds
  later, since the ship that holds it remembers its agent's no for five
  seconds. Its directory lock is held only by the walk-through itself: the
  runtimes it starts each lock their own data directory, as always.
- A scratch file in `tmp/` that cannot be removed when a runtime starts stays
  there. Scratch names hold the process id, which the system can give again,
  so a later runtime may make a scratch file of the same name; every scratch
  file is made new (`create_new`), so nothing is written through it, and
  making or bringing in a ship, or storing a module, then fails (making a ship
  says the ship exists, though it may not).
- A lookup point given `--pretend-ids` reads and parses the whole list (up to
  1 MiB) for every record it checks, within its usual allowances of records a
  second. That is for a list on machines one controls, not for a point anyone
  can reach.
- Imports of ships of different names may run at once, with no cap on how
  many, each holding about twice its copy in memory for a moment. There is no
  HTTP route for import; a program that calls the runtime decides.

## License

MIT
