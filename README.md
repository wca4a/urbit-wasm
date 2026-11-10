# urbit-wasm

A prototype runtime for an Urbit-like process without Hoon or Nock. Multiple ships can run in one
process. Each ship is one SQLite file plus WASM agents written in Rust.

Experimental. This is the runtime only: there is no kernel, networking,
identity, or update mechanism yet.

## What it does

- One event is one transaction: state, outgoing messages, and an audit entry
  are saved together or not at all.
- Every event gets a fresh WASM instance, so the file is the only state.
- Idle ships are closed files, with a cap on how many are open at once.
- Each event has limits on compute, time, and memory.
- A ship can be exported as a file and imported into another runtime.

## Layout

| Path | Contents |
| --- | --- |
| `runtime/` | The runtime, its tests, and a load test |
| `sdk/` | What an agent links against |
| `agents/counter/` | A toy agent |

## Run

Requires Rust and the WASM target:

```sh
rustup target add wasm32-unknown-unknown
```

Tests (these build the toy agent themselves):

```sh
cargo test -p runtime
```

Load test:

```sh
cargo build -p counter --release --target wasm32-unknown-unknown --target-dir target/wasm
cargo run -p runtime --release --bin loadtest -- --ships 500 --active 50 --sync normal
```

On a Mac laptop with the toy agent, 5,000 idle ships take about 75 MB of
memory.

## License

MIT
