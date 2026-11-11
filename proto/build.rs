fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=ship.proto");
    prost_build::compile_protos(&["ship.proto"], &["."])
}
