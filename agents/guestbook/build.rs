fn main() -> std::io::Result<()> {
    ship_sdk_build::Api::new().serve("api/guestbook.proto").compile()
}
