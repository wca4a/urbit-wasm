# urbit-wasm

A prototype event-based runtime. Multiple ships can run in one
process. Each ship is one SQLite file, a kernel, and agents, all WASM modules
written in Rust.

Experimental. There is a runtime, a kernel, logs that agents can follow, an
HTTP server that lets an app or a browser sign in to a ship, and an encrypted
link over which ships send each other commands and follow each other's logs.
A ship's file is not yet encrypted on disk, and there is no identity or update
mechanism yet.

## What it does

- One event is one transaction: state, outgoing messages, and an audit entry
  are saved together or not at all.
- Every call gets a fresh WASM instance, so the file is the only state.
- Idle ships are closed files, with a cap on how many are open at once.
- Each event has limits on compute, time, and memory.
- A ship can be exported as a file and imported into another runtime.
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

## License

MIT
