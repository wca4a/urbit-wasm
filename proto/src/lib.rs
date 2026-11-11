//! Message types shared by the runtime, the kernel, and agents, generated from `ship.proto`.

pub use prost::Message;

include!(concat!(env!("OUT_DIR"), "/ship.v1.rs"));
