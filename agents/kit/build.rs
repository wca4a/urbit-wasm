// The kit serves one file and calls others, each a layout the generated code must compile for:
// the guestbook's interfaces (called only), a nested package, a package that is a Rust keyword, a
// package named like the generated file, the counter's log, and three neighbours of a service
// `Book`: a message `BookApi` with an `optional` field, one with a nested message, and a child
// package `book_api`; and every well-known type the SDK supplies, with a custom option.
fn main() -> std::io::Result<()> {
    ship_sdk_build::Api::new()
        .serve("api/kit.proto")
        .call("../guestbook/api/guestbook.proto")
        .call("api/deep.proto")
        .call("api/keyword.proto")
        .call("api/ship_api.proto")
        .call("api/optional.proto")
        .call("api/nested.proto")
        .call("api/parent.proto")
        .call("api/parent_child.proto")
        .call("api/counterlog.proto")
        .call("api/wellknown.proto")
        .compile()
}
