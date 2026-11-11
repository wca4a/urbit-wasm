# urbit-wasm

A prototype event-based runtime. Multiple ships can run in one
process. Each ship is one SQLite file, a kernel, and agents, all WASM modules
written in Rust.

Experimental. There is a runtime, a kernel, and logs that agents on one ship
can follow. There is no networking, identity, or update mechanism yet.

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

On a Mac laptop with a toy agent, 5,000 idle ships take about 80 MB of memory,
and busy ships handle about 15,000 events per second in total.

## License

MIT
