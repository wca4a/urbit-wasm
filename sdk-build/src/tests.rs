//! The generator, run over proto files written here: what it makes of each kind of method, the
//! files it refuses and why, and what it writes.

use super::*;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto};

/// A directory of its own for one test, with these files written in it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str, files: &[(&str, &str)]) -> Scratch {
        let dir = std::env::temp_dir().join(format!("ship-sdk-build-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        for (name, text) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const HEAD: &str = "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/empty.proto\";\nmessage Thing { string word = 1; }\n";

/// What the generator says of one file served, or why it refuses it.
fn describe(label: &str, services: &str) -> io::Result<Vec<Interface>> {
    let scratch = Scratch::new(label, &[("api/demo.proto", &format!("{HEAD}{services}"))]);
    Api::new().serve(scratch.path("api/demo.proto")).describe()
}

fn refused(label: &str, services: &str) -> String {
    describe(label, services).expect_err("the file was taken").to_string()
}

#[test]
fn each_kind_of_method_is_told_apart() {
    let interfaces = describe(
        "kinds",
        "// A chat.\nservice GroupChat {\n  rpc Say(Thing) returns (Thing);\n  rpc Idem(Thing) returns (Thing) { option idempotency_level = IDEMPOTENT; }\n  rpc Hear(Thing) returns (Thing) { option idempotency_level = NO_SIDE_EFFECTS; }\n  rpc Said(Thing) returns (stream Thing);\n}\nservice HTTPServer {\n  rpc History(google.protobuf.Empty) returns (stream Thing);\n}\nservice Quiet {}\n",
    )
    .unwrap();
    assert_eq!(
        interfaces,
        [
            Interface {
                service: "demo.GroupChat".into(),
                name: "group-chat".into(),
                served: true,
                methods: vec![("Say".into(), Kind::Command), ("Idem".into(), Kind::Command), ("Hear".into(), Kind::Question), ("Said".into(), Kind::Log)],
                log: Some(("demo.Thing".into(), Some("demo.Thing".into()))),
            },
            Interface { service: "demo.HTTPServer".into(), name: "http-server".into(), served: true, methods: vec![("History".into(), Kind::Log)], log: Some(("demo.Thing".into(), None)) },
            Interface { service: "demo.Quiet".into(), name: "quiet".into(), served: true, methods: vec![], log: None },
        ]
    );
}

#[test]
fn a_file_that_breaks_a_rule_is_refused_naming_what_breaks_it() {
    let said = refused("client-streaming", "service Chat { rpc Upload(stream Thing) returns (Thing); }\n");
    assert!(said.contains("method demo.Chat.Upload streams from its caller"), "{said}");
    let said = refused("two-way", "service Chat { rpc Talk(stream Thing) returns (stream Thing); }\n");
    assert!(said.contains("method demo.Chat.Talk streams from its caller"), "{said}");
    let said = refused("two-logs", "service Chat { rpc One(Thing) returns (stream Thing); rpc Two(Thing) returns (stream Thing); }\n");
    assert!(said.contains("service demo.Chat has two streaming methods, One and Two"), "{said}");
    let said = refused("bad-name", "service Two__Bars { rpc Say(Thing) returns (Thing); }\n");
    assert!(said.contains("service demo.Two__Bars does not turn into a valid interface name"), "{said}");
    let said = refused("trailing", "service Trailing_ {}\n");
    assert!(said.contains("service demo.Trailing_ does not turn"), "{said}");
    let said = refused("same-interface", "service GroupChat {}\nservice Group_Chat {}\n");
    assert!(said.contains("services demo.GroupChat and demo.Group_Chat are both the interface \"group-chat\""), "{said}");
    // The same two names in a file only called would make one Rust module twice.
    let scratch = Scratch::new("same-called", &[("demo.proto", &format!("{HEAD}service GroupChat {{}}\nservice Group_Chat {{}}\n"))]);
    let said = Api::new().call(scratch.path("demo.proto")).describe().unwrap_err().to_string();
    assert!(said.contains("service demo.GroupChat and service demo.Group_Chat would both make the Rust module group_chat_api in package \"demo\""), "{said}");
    // Two spellings of a package that prost makes into one Rust module are refused, even with
    // services of different names and one file only imported, naming both files and spellings.
    let scratch = Scratch::new("same-module-path", &[("upper.proto", "syntax = \"proto3\";\npackage demo.Two;\nservice Remote {}\n"), ("lower.proto", "syntax = \"proto3\";\npackage demo.two;\nimport \"upper.proto\";\nservice Local {}\n")]);
    let said = Api::new().serve(scratch.path("lower.proto")).describe().unwrap_err().to_string();
    assert!(said.contains("upper.proto has package demo.Two and lower.proto has package demo.two, which make the one Rust module demo::two"), "{said}");
    // A package part that makes a module the generated code takes for itself is refused.
    let scratch = Scratch::new("taken-module", &[("taken.proto", "syntax = \"proto3\";\npackage demo.serde;\nservice Chat {}\n")]);
    let said = Api::new().serve(scratch.path("taken.proto")).describe().unwrap_err().to_string();
    assert!(said.contains("taken.proto: package demo.serde makes a Rust module named serde, a name the generated code takes for itself"), "{said}");
    // A declared JSON name the generated code cannot hold between Rust quotes as it is (here a
    // backslash and a `t`, which Rust would read as a tab) is refused.
    let said = refused("json-name", r#"message Odd { string a = 1 [json_name = "a\\tb"]; }"#);
    assert!(said.contains(r#"demo.proto: field demo.Odd.a has the JSON name "a\\tb", which holds a backslash"#), "{said}");
    // A message named as a service's module is no clash: the services' modules are apart, in
    // `_interfaces` (the kit compiles such neighbours).
    assert_eq!(describe("module-apart", "message BookApi { message Row {} optional string title = 1; }\nservice Book {}\n").unwrap().len(), 1);
    // A file with no package, served, called, or only imported.
    for (label, serve) in [("no-package-served", true), ("no-package-called", false)] {
        let scratch = Scratch::new(label, &[("bare.proto", "syntax = \"proto3\";\nmessage Bare { string word = 1; }\nservice Plain { rpc Wrap(Bare) returns (Bare); }\n")]);
        let api = if serve { Api::new().serve(scratch.path("bare.proto")) } else { Api::new().call(scratch.path("bare.proto")) };
        let said = api.describe().unwrap_err().to_string();
        assert!(said.contains("bare.proto has no package: give it one, with a line such as `package bare;` near its top"), "{said}");
    }
    let scratch = Scratch::new("no-package-imported", &[("bare.proto", "syntax = \"proto3\";\nmessage Bare { string word = 1; }\n"), ("demo.proto", &format!("{HEAD}import \"bare.proto\";\nservice Chat {{ rpc Say(Bare) returns (Bare); }}\n"))]);
    let said = Api::new().serve(scratch.path("demo.proto")).describe().unwrap_err().to_string();
    assert!(said.contains("bare.proto has no package"), "{said}");
    // Two methods whose Rust names are the same.
    let scratch = Scratch::new("same-snake", &[("demo.proto", &format!("{HEAD}service Chat {{ rpc Say(Thing) returns (Thing); rpc say(Thing) returns (Thing); }}\n"))]);
    let said = Api::new().serve(scratch.path("demo.proto")).out_dir(scratch.path("out")).compile().unwrap_err().to_string();
    assert!(said.contains("service demo.Chat has two methods whose Rust name is say"), "{said}");
    // An application file that is not proto3, served or only called.
    let proto2 = "syntax = \"proto2\";\npackage demo;\nmessage Thing { required string word = 1; }\nservice Chat { rpc Say(Thing) returns (Thing); }\n";
    let scratch = Scratch::new("proto2", &[("demo.proto", proto2)]);
    for api in [Api::new().serve(scratch.path("demo.proto")), Api::new().call(scratch.path("demo.proto"))] {
        let said = api.describe().unwrap_err().to_string();
        assert!(said.contains("demo.proto is proto2: every application file, served, called or imported, must be syntax = \"proto3\""), "{said}");
    }
    // Nothing given.
    assert!(Api::new().describe().is_err());
}

#[test]
fn names_turn_into_interfaces_as_the_runtime_turns_them() {
    for (service, interface) in [("Guestbook", Some("guestbook")), ("GroupChat", Some("group-chat")), ("HTTPServer", Some("http-server")), ("Chat2Go", Some("chat2-go")), ("foo_bar", Some("foo-bar")), ("_Hidden", None), ("Two__Bars", None)] {
        assert_eq!(interface_of_service(service).as_deref(), interface, "{service}");
    }
}

#[test]
fn what_is_written_serves_the_served_and_only_calls_the_called() {
    let scratch = Scratch::new(
        "written",
        &[
            ("api/book.proto", "syntax = \"proto3\";\npackage book.v1;\nimport \"shared.proto\";\n// Signatures.\nservice Book {\n  // Sign it.\n  rpc Sign(shared.Thing) returns (shared.Thing);\n  rpc Look(shared.Thing) returns (shared.Thing) { option idempotency_level = NO_SIDE_EFFECTS; }\n  rpc Log(shared.Thing) returns (stream shared.Thing);\n}\n"),
            ("api/shared.proto", "syntax = \"proto3\";\npackage shared;\n// Not the book's.\nservice Ledger { rpc Add(Thing) returns (Thing); }\nmessage Thing { string word = 1; }\n"),
            ("other/ledger.proto", "syntax = \"proto3\";\npackage ledger;\nservice Ledger { rpc Add(Entry) returns (Entry); rpc Entries(Entry) returns (stream Entry); }\nmessage Entry { int64 amount = 1; }\n"),
        ],
    );
    let out = scratch.path("out");
    Api::new().serve(scratch.path("api/book.proto")).call(scratch.path("other/ledger.proto")).out_dir(&out).compile().unwrap();
    // The description holds the served file and what it imports, the import first, and not
    // the file only called; comments are kept; the import keeps its message and loses its
    // service and the comment on it.
    let bytes = std::fs::read(out.join("ship_api.bin")).unwrap();
    let set = FileDescriptorSet::decode(&*bytes).unwrap();
    assert_eq!(set.file.iter().map(|file| file.name()).collect::<Vec<_>>(), ["shared.proto", "book.proto"]);
    assert!(set.file[0].service.is_empty());
    assert_eq!(set.file[0].message_type.iter().map(|message| message.name()).collect::<Vec<_>>(), ["Thing"]);
    let shared_comments: Vec<&str> = set.file[0].source_code_info.iter().flat_map(|info| info.location.iter().map(|location| location.leading_comments())).collect();
    assert!(!shared_comments.contains(&" Not the book's.\n"), "{shared_comments:?}");
    let comments: Vec<&str> = set.file[1].source_code_info.as_ref().unwrap().location.iter().map(|location| location.leading_comments()).collect();
    assert!(comments.contains(&" Signatures.\n") && comments.contains(&" Sign it.\n"), "{comments:?}");
    let included = std::fs::read_to_string(out.join("ship_api.rs")).unwrap();
    assert!(included.contains(&format!("pub const DESCRIPTION: [u8; {}]", bytes.len())), "{included}");
    assert!(included.contains("pub const SERVED: &[&str] = &[\"book\"];"), "{included}");
    assert!(included.contains("pub mod book {") && included.contains("pub mod v1 {") && included.contains("pub mod ledger {") && included.contains("pub mod shared {"), "{included}");
    // A package with messages has their JSON forms beside them; book.v1 has none.
    assert!(included.contains("/ship_api/prost/book.v1.rs") && !included.contains("/ship_api/serde/book.v1.rs") && included.contains("/ship_api/serde/shared.rs"), "{included}");
    // The served interface has handlers, dispatch reading JSON, and a log it appends to; the
    // called one has stubs and the reading of its log only. (That they compile is shown by the
    // agents built from such files, `guestbook` and `kit`.)
    let book = std::fs::read_to_string(out.join("ship_api/prost/book.v1.rs")).unwrap();
    for wanted in ["pub mod book_api {", "pub const INTERFACE: &str = \"book\";", "pub trait Handlers {", "fn sign(", "fn look(", "pub trait Checkpoint {", "impl<H: Handlers + Checkpoint> ::ship_sdk::api::Serve<H> for Interface", "__request(method, body, json)", "pub fn append(entry: &Entry) -> u64", "pub mod sign {", "pub fn send_to_for_reply(", "pub fn receipt(", "pub mod look {", "pub fn ask(", "pub fn answered(", "pub type Entry = super::super::super::super::super::shared::Thing;", "pub mod _interfaces {"] {
        assert!(book.contains(wanted), "{wanted:?} not in\n{book}");
    }
    let ledger = std::fs::read_to_string(out.join("ship_api/prost/ledger.rs")).unwrap();
    assert!(ledger.contains("pub mod ledger_api {") && ledger.contains("pub mod add {") && ledger.contains("pub fn next_on("), "{ledger}");
    for unwanted in ["pub trait Handlers", "Serve<H>", "pub fn append(", "pub fn share("] {
        assert!(!ledger.contains(unwanted), "{unwanted:?} in\n{ledger}");
    }
    // Every message has its JSON form, beside it.
    assert!(std::fs::read_to_string(out.join("ship_api/serde/shared.rs")).unwrap().contains("impl serde::Serialize for Thing"));
}

/// A small agent crate outside the workspace, built for wasm32 as an agent is, in a directory of
/// its own under `target/` (kept between runs, so that only the first build is slow). Its build
/// output, and whether it built.
fn build_agent(label: &str, proto: &str, lib: &str) -> (bool, String) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let dir = workspace.join("target").join("compile-checks").join(label);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let manifest = format!(
        "[package]\nname = \"{label}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nship-sdk = {{ path = {sdk:?} }}\n\n[build-dependencies]\nship-sdk-build = {{ path = {build:?} }}\n\n[workspace]\n",
        sdk = workspace.join("sdk").display().to_string(),
        build = workspace.join("sdk-build").display().to_string(),
    );
    std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
    std::fs::copy(workspace.join("Cargo.lock"), dir.join("Cargo.lock")).unwrap();
    std::fs::write(dir.join("api.proto"), proto).unwrap();
    std::fs::write(dir.join("build.rs"), "fn main() -> std::io::Result<()> {\n    ship_sdk_build::Api::new().serve(\"api.proto\").compile()\n}\n").unwrap();
    std::fs::write(dir.join("src/lib.rs"), lib).unwrap();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let built = std::process::Command::new(cargo)
        .current_dir(&dir)
        .args(["build", "--offline", "--target", "wasm32-unknown-unknown", "--target-dir"])
        .arg(workspace.join("target").join("compile-checks").join("target"))
        .output()
        .expect("run cargo");
    (built.status.success(), String::from_utf8_lossy(&built.stderr).into_owned())
}

const TWO_SERVICES: &str = "syntax = \"proto3\";\npackage two;\nimport \"google/protobuf/empty.proto\";\nservice One { rpc A(google.protobuf.Empty) returns (google.protobuf.Empty); }\nservice Other { rpc B(google.protobuf.Empty) returns (google.protobuf.Empty); }\n";

#[test]
fn a_typed_agent_must_wire_exactly_the_interfaces_its_description_serves() {
    let handlers = "use ship_sdk::api::Fault;\nuse ship_sdk::pbjson_types::Empty;\nship_sdk::include_api!();\nstruct H;\nimpl api::two::_interfaces::one_api::Handlers for H {\n    fn a(_: Empty) -> Result<Empty, Fault> {\n        Ok(Empty {})\n    }\n}\nimpl api::two::_interfaces::other_api::Handlers for H {\n    fn b(_: Empty) -> Result<Empty, Fault> {\n        Ok(Empty {})\n    }\n}\n";
    // Both wired: it builds, without a warning.
    let both = format!("{handlers}ship_sdk::typed_agent!(api = api, serve = [api::two::_interfaces::one_api::Interface => H, api::two::_interfaces::other_api::Interface => H]);\n");
    let (built, said) = build_agent("wires-both", TWO_SERVICES, &both);
    assert!(built && !said.contains("warning"), "{said}");
    // One left out: a compile error saying so.
    let one = format!("{handlers}ship_sdk::typed_agent!(api = api, serve = [api::two::_interfaces::one_api::Interface => H]);\n");
    let (built, said) = build_agent("wires-one", TWO_SERVICES, &one);
    assert!(!built, "it built with an interface left out");
    assert!(said.contains("typed_agent!: serve = [...] must wire exactly the interfaces the description serves (api::SERVED)"), "{said}");
    // One wired twice, beside the other: a compile error too.
    let twice = format!("{handlers}ship_sdk::typed_agent!(api = api, serve = [api::two::_interfaces::one_api::Interface => H, api::two::_interfaces::one_api::Interface => H, api::two::_interfaces::other_api::Interface => H]);\n");
    let (built, said) = build_agent("wires-twice", TWO_SERVICES, &twice);
    assert!(!built, "it built with an interface wired twice");
    assert!(said.contains("typed_agent!: serve = [...] must wire exactly the interfaces the description serves (api::SERVED)"), "{said}");
}

#[test]
fn a_rewrite_of_the_generated_json_code_leaves_string_literals_alone() {
    let code = r##"let a = ::pbjson::private::x; let b = "::pbjson::alias"; let c = r#"::pbjson::raw"#; let d = "\"::pbjson::q"; let e = ::pbjson::y;"##;
    assert_eq!(
        outside_literals(code, "::pbjson::", "pbjson::"),
        r##"let a = pbjson::private::x; let b = "::pbjson::alias"; let c = r#"::pbjson::raw"#; let d = "\"::pbjson::q"; let e = pbjson::y;"##
    );
    // Only where a path starts: not after an identifier character or `::`.
    // (`a::::pbjson::b` is not Rust, but it is the one text where the `::` half of the rule
    // decides.)
    let code = "let f: super::pbjson::Kind = mypbjson::x(); let g = <::pbjson::z>; a::::pbjson::b; π::pbjson::Kind";
    assert_eq!(outside_literals(code, "::pbjson::", "pbjson::"), "let f: super::pbjson::Kind = mypbjson::x(); let g = <pbjson::z>; a::::pbjson::b; π::pbjson::Kind");
}


/// A file that uses every supported well-known type as a field and, the messages among them, as
/// a method's input and output.
const EVERY_WELL_KNOWN: &str = "syntax = \"proto3\";
package demo;
import \"google/protobuf/any.proto\";
import \"google/protobuf/duration.proto\";
import \"google/protobuf/empty.proto\";
import \"google/protobuf/field_mask.proto\";
import \"google/protobuf/struct.proto\";
import \"google/protobuf/timestamp.proto\";
import \"google/protobuf/wrappers.proto\";
message Every {
  google.protobuf.Empty empty = 1;
  google.protobuf.Timestamp timestamp = 2;
  google.protobuf.Duration duration = 3;
  google.protobuf.Any any = 4;
  google.protobuf.FieldMask field_mask = 5;
  google.protobuf.Struct struct = 6;
  google.protobuf.Value value = 7;
  google.protobuf.ListValue list_value = 8;
  google.protobuf.NullValue null_value = 9;
  google.protobuf.DoubleValue double_value = 10;
  google.protobuf.FloatValue float_value = 11;
  google.protobuf.Int64Value int64_value = 12;
  google.protobuf.UInt64Value uint64_value = 13;
  google.protobuf.Int32Value int32_value = 14;
  google.protobuf.UInt32Value uint32_value = 15;
  google.protobuf.BoolValue bool_value = 16;
  google.protobuf.StringValue string_value = 17;
  google.protobuf.BytesValue bytes_value = 18;
}
service Chat {
  rpc Empty(google.protobuf.Empty) returns (google.protobuf.Empty);
  rpc Timestamp(google.protobuf.Timestamp) returns (google.protobuf.Timestamp);
  rpc Duration(google.protobuf.Duration) returns (google.protobuf.Duration);
  rpc Any(google.protobuf.Any) returns (google.protobuf.Any);
  rpc FieldMask(google.protobuf.FieldMask) returns (google.protobuf.FieldMask);
  rpc Struct(google.protobuf.Struct) returns (google.protobuf.Struct);
  rpc Value(google.protobuf.Value) returns (google.protobuf.Value);
  rpc ListValue(google.protobuf.ListValue) returns (google.protobuf.ListValue);
  rpc DoubleValue(google.protobuf.DoubleValue) returns (google.protobuf.DoubleValue);
  rpc FloatValue(google.protobuf.FloatValue) returns (google.protobuf.FloatValue);
  rpc Int64Value(google.protobuf.Int64Value) returns (google.protobuf.Int64Value);
  rpc UInt64Value(google.protobuf.UInt64Value) returns (google.protobuf.UInt64Value);
  rpc Int32Value(google.protobuf.Int32Value) returns (google.protobuf.Int32Value);
  rpc UInt32Value(google.protobuf.UInt32Value) returns (google.protobuf.UInt32Value);
  rpc BoolValue(google.protobuf.BoolValue) returns (google.protobuf.BoolValue);
  rpc StringValue(google.protobuf.StringValue) returns (google.protobuf.StringValue);
  rpc BytesValue(google.protobuf.BytesValue) returns (google.protobuf.BytesValue);
  rpc All(Every) returns (Every);
}
";

/// What the generator says of one served file, given these other files beside it.
fn refused_with(label: &str, files: &[(&str, &str)]) -> String {
    let scratch = Scratch::new(label, files);
    Api::new().serve(scratch.path("demo.proto")).describe().expect_err("the files were taken").to_string()
}

#[test]
fn only_the_well_known_types_the_sdk_supplies_may_be_used() {
    // Every supported type, as protoc on this machine defines it, is taken.
    let scratch = Scratch::new("every-well-known", &[("demo.proto", EVERY_WELL_KNOWN)]);
    assert_eq!(Api::new().serve(scratch.path("demo.proto")).describe().unwrap().len(), 1);
    // A type in a package under google.protobuf, which the generated code would take for the
    // SDK's type of that name (here one with a field the SDK's has not), is refused.
    let said = refused_with(
        "sub-package",
        &[
            ("custom.proto", "syntax = \"proto3\";\npackage google.protobuf.descriptor_proto;\nmessage ReservedRange { string note = 3; }\n"),
            ("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"custom.proto\";\nservice Chat { rpc Echo(google.protobuf.descriptor_proto.ReservedRange) returns (google.protobuf.descriptor_proto.ReservedRange); }\n"),
        ],
    );
    assert!(said.contains("demo.proto: method demo.Chat.Echo refers to google.protobuf.descriptor_proto.ReservedRange, which is not supported in agent interfaces: the well-known types an agent may use are google.protobuf.Empty, google.protobuf.Timestamp"), "{said}");
    // A stock type of the package that is not supported, as a method's payload and as a field.
    let said = refused_with("feature-set", &[("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nservice Chat { rpc Echo(google.protobuf.FeatureSet) returns (google.protobuf.FeatureSet); }\n")]);
    assert!(said.contains("method demo.Chat.Echo refers to google.protobuf.FeatureSet, which is not supported in agent interfaces"), "{said}");
    let said = refused_with("descriptor-field", &[("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nmessage Holder { message Inner { google.protobuf.DescriptorProto d = 1; } }\n")]);
    assert!(said.contains("field demo.Holder.Inner.d refers to google.protobuf.DescriptorProto, which is not supported in agent interfaces"), "{said}");
    // An author's own Empty, with a field, in package google.protobuf, is not the SDK's.
    let said = refused_with(
        "own-empty",
        &[
            ("custom.proto", "syntax = \"proto3\";\npackage google.protobuf;\nmessage Empty { string note = 1; }\n"),
            ("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"custom.proto\";\nservice Chat { rpc Echo(google.protobuf.Empty) returns (google.protobuf.Empty); }\n"),
        ],
    );
    assert!(said.contains("custom.proto: google.protobuf.Empty is not the definition the SDK implements (google.protobuf.Empty has an extra field note (number 1)): the well-known types are supplied by the SDK"), "{said}");
    // A type not supported on one side of a method only, each way.
    let one_side = |input: &str, output: &str| format!("syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nmessage Local {{ string word = 1; }}\nservice Chat {{ rpc Echo({input}) returns ({output}); }}\n");
    let said = refused_with("feature-set-out", &[("demo.proto", &one_side("Local", "google.protobuf.FeatureSet"))]);
    assert!(said.contains("method demo.Chat.Echo refers to google.protobuf.FeatureSet, which is not supported in agent interfaces"), "{said}");
    let said = refused_with("feature-set-in", &[("demo.proto", &one_side("google.protobuf.FeatureSet", "Local"))]);
    assert!(said.contains("method demo.Chat.Echo refers to google.protobuf.FeatureSet, which is not supported in agent interfaces"), "{said}");
    // A well-known file declares no service: here a served file of package google.protobuf
    // whose service would take the SDK's Empty for the Empty it declares.
    let said = refused_with("well-known-service", &[("demo.proto", "syntax = \"proto3\";\npackage google.protobuf;\nmessage Empty { string note = 1; }\nservice Echo { rpc Get(Empty) returns (Empty); }\n")]);
    assert!(said.contains("demo.proto: package google.protobuf declares service Echo: a file in google.protobuf or under it may not declare a service"), "{said}");
    // A used well-known type defined in a proto2 file, though its fields match the table.
    let said = refused_with(
        "proto2-wrapper",
        &[
            ("custom.proto", "syntax = \"proto2\";\npackage google.protobuf;\nmessage Int32Value { optional int32 value = 1; }\n"),
            ("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"custom.proto\";\nservice Chat { rpc Echo(google.protobuf.Int32Value) returns (google.protobuf.Int32Value); }\n"),
        ],
    );
    assert!(said.contains("custom.proto: google.protobuf.Int32Value is defined in a proto2 file: a well-known type an agent uses must be defined in a proto3 file"), "{said}");
    // An imported application file that is proto2, here with a data extension on its message.
    let said = refused_with(
        "proto2-extension",
        &[
            ("bag.proto", "syntax = \"proto2\";\npackage demo.bag;\nmessage Bag { extensions 100 to 199; }\nextend Bag { optional string note = 100; }\n"),
            ("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"bag.proto\";\nservice Chat { rpc Echo(demo.bag.Bag) returns (demo.bag.Bag); }\n"),
        ],
    );
    assert!(said.contains("bag.proto is proto2: every application file, served, called or imported, must be syntax = \"proto3\""), "{said}");
    // An extension's type goes through the same check as a field's, at file level and nested.
    let said = refused_with("extension-type", &[("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nextend google.protobuf.MethodOptions { google.protobuf.DescriptorProto payload = 50001; }\n")]);
    assert!(said.contains("demo.proto: extension demo.payload refers to google.protobuf.DescriptorProto, which is not supported in agent interfaces"), "{said}");
    let said = refused_with("nested-extension-type", &[("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nmessage Holder { extend google.protobuf.MethodOptions { google.protobuf.DescriptorProto inner = 50002; } }\n")]);
    assert!(said.contains("demo.proto: extension demo.Holder.inner refers to google.protobuf.DescriptorProto"), "{said}");
    // Importing descriptor.proto only to declare and use a custom option builds.
    let option = "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nextend google.protobuf.MethodOptions { string tag = 50000; }\nmessage Thing { string word = 1; }\nservice Chat { rpc Say(Thing) returns (Thing) { option (tag) = \"x\"; } }\n";
    let scratch = Scratch::new("custom-option", &[("demo.proto", option)]);
    Api::new().serve(scratch.path("demo.proto")).out_dir(scratch.path("out")).compile().unwrap();
}

#[test]
fn a_well_known_definition_that_differs_from_the_sdks_is_refused() {
    // protoc's own definitions, read as it reads them, then changed in memory: what protoc came
    // to read, and how, does not matter to the check, only what the set holds.
    let scratch = Scratch::new("changed-well-known", &[("demo.proto", EVERY_WELL_KNOWN)]);
    let loaded = Api::new().serve(scratch.path("demo.proto")).load().unwrap();
    let refused = |label: &str, change: &dyn Fn(&mut DescriptorProto)| -> String {
        let mut fds = loaded.fds.clone();
        let mut touched = false;
        for file in fds.file.iter_mut().filter(|file| file.package() == "google.protobuf") {
            for message in &mut file.message_type {
                let before = message.clone();
                change(message);
                touched |= *message != before;
            }
        }
        assert!(touched, "the change touched nothing");
        match interfaces(&fds, &loaded.served, &loaded.called) {
            Ok(_) => panic!("{label}: the changed set was taken"),
            Err(e) => e.to_string(),
        }
    };
    let field = |message: &mut DescriptorProto, name: &str| -> FieldDescriptorProto { message.field.iter().find(|field| field.name() == name).unwrap().clone() };
    // A field's number.
    let said = refused("a field's number", &|message| {
        if message.name() == "Duration" {
            message.field[1].number = Some(3);
        }
    });
    assert!(said.contains("google/protobuf/duration.proto: google.protobuf.Duration is not the definition the SDK implements (field google.protobuf.Duration.nanos is number 3, not 2)"), "{said}");
    // A field's type.
    let said = refused("a field's type", &|message| {
        if message.name() == "Timestamp" {
            message.field[0].set_type(Type::Int32);
        }
    });
    assert!(said.contains("field google.protobuf.Timestamp.seconds is of type TYPE_INT32, not TYPE_INT64"), "{said}");
    // An extra field, here in Empty: an Empty with a field, however protoc came to read it.
    let said = refused("an extra field in Empty", &|message| {
        if message.name() == "Empty" {
            message.field.push(FieldDescriptorProto { name: Some("note".into()), number: Some(1), label: Some(Label::Optional as i32), r#type: Some(Type::String as i32), json_name: Some("note".into()), ..Default::default() });
        }
    });
    assert!(said.contains("google/protobuf/empty.proto: google.protobuf.Empty is not the definition the SDK implements (google.protobuf.Empty has an extra field note (number 1))"), "{said}");
    // A oneof member missing, and one moved out of its oneof.
    let said = refused("a oneof member missing", &|message| {
        if message.name() == "Value" {
            message.field.retain(|field| field.name() != "bool_value");
        }
    });
    assert!(said.contains("google.protobuf.Value has no field bool_value"), "{said}");
    let said = refused("a oneof member moved out", &|message| {
        if message.name() == "Value" {
            let mut moved = field(message, "bool_value");
            moved.oneof_index = None;
            message.field.retain(|field| field.name() != "bool_value");
            message.field.push(moved);
        }
    });
    assert!(said.contains("field google.protobuf.Value.bool_value is in oneof None, not Some(\"kind\")"), "{said}");
    // The map entry nested in Struct, reached only through Struct.
    let said = refused("the map entry's options", &|message| {
        if message.name() == "Struct" {
            message.nested_type[0].options = None;
        }
    });
    assert!(said.contains("google.protobuf.Struct.FieldsEntry has message options None"), "{said}");
    // A type reached only through another: a file that uses Struct alone, with Value changed.
    let scratch = Scratch::new("reached-well-known", &[("demo.proto", "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/struct.proto\";\nservice Chat { rpc Echo(google.protobuf.Struct) returns (google.protobuf.Struct); }\n")]);
    let only_struct = Api::new().serve(scratch.path("demo.proto")).load().unwrap();
    assert!(interfaces(&only_struct.fds, &only_struct.served, &only_struct.called).is_ok());
    let mut fds = only_struct.fds.clone();
    for file in fds.file.iter_mut().filter(|file| file.package() == "google.protobuf") {
        for message in file.message_type.iter_mut().filter(|message| message.name() == "Value") {
            message.field[3].number = Some(40);
        }
    }
    let said = interfaces(&fds, &only_struct.served, &only_struct.called).expect_err("a changed Value reached through Struct was taken").to_string();
    assert!(said.contains("google/protobuf/struct.proto: google.protobuf.Value is not the definition the SDK implements (field google.protobuf.Value.bool_value is number 40, not 4)"), "{said}");
}

/// The fields of one protobuf message, as (number, wire type, payload) for each.
fn wire_fields(mut bytes: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
    fn varint(bytes: &mut &[u8]) -> u64 {
        let (mut value, mut shift) = (0u64, 0);
        loop {
            let byte = bytes[0];
            *bytes = &bytes[1..];
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes);
        let (number, wire) = (key >> 3, key & 7);
        let payload = match wire {
            0 => {
                let start = bytes;
                varint(&mut bytes);
                start[..start.len() - bytes.len()].to_vec()
            }
            1 | 5 => {
                let len = if wire == 1 { 8 } else { 4 };
                let (payload, rest) = bytes.split_at(len);
                bytes = rest;
                payload.to_vec()
            }
            2 => {
                let len = usize::try_from(varint(&mut bytes)).unwrap();
                let (payload, rest) = bytes.split_at(len);
                bytes = rest;
                payload.to_vec()
            }
            other => panic!("wire type {other}"),
        };
        out.push((number, wire, payload));
    }
    out
}

/// The wire type a field of this table type is written with.
fn wire_of(ty: Type) -> u64 {
    match ty {
        Type::Double | Type::Fixed64 | Type::Sfixed64 => 1,
        Type::Float | Type::Fixed32 | Type::Sfixed32 => 5,
        Type::String | Type::Bytes | Type::Message => 2,
        _ => 0,
    }
}

/// The table's entry for a well-known message.
fn table_message(name: &str) -> &'static well_known::Message {
    match well_known::SUPPORTED.iter().find(|(known, _)| *known == name).map(|(_, kind)| kind) {
        Some(well_known::Kind::Message(message)) => message,
        _ => panic!("{name} is not a message of the table"),
    }
}

#[test]
fn the_table_of_well_known_definitions_is_what_the_sdks_types_encode() {
    // Each field of the table set alone in the SDK's type (each member of Value's oneof in turn)
    // and encoded by the SDK: the one field written must have that field's number in the table,
    // and the wire type its table type gives. Every field of the table has a sample.
    use pbjson_types::value::Kind as V;
    use pbjson_types::{Any, BoolValue, BytesValue, DoubleValue, Duration, Empty, FieldMask, FloatValue, Int32Value, Int64Value, ListValue, NullValue, StringValue, Struct, Timestamp, UInt32Value, UInt64Value, Value};
    let value = |kind: V| Value { kind: Some(kind) };
    let entry_value = value(V::NumberValue(1.0));
    let one_entry = Struct { fields: [("k".to_string(), entry_value.clone())].into_iter().collect() };
    let samples: Vec<(&str, &str, Vec<u8>)> = vec![
        ("Timestamp", "seconds", Timestamp { seconds: 1, nanos: 0 }.encode_to_vec()),
        ("Timestamp", "nanos", Timestamp { seconds: 0, nanos: 1 }.encode_to_vec()),
        ("Duration", "seconds", Duration { seconds: 1, nanos: 0 }.encode_to_vec()),
        ("Duration", "nanos", Duration { seconds: 0, nanos: 1 }.encode_to_vec()),
        ("Any", "type_url", Any { type_url: "t".into(), value: Default::default() }.encode_to_vec()),
        ("Any", "value", Any { type_url: String::new(), value: vec![1].into() }.encode_to_vec()),
        ("FieldMask", "paths", FieldMask { paths: vec!["a".into()] }.encode_to_vec()),
        ("Struct", "fields", one_entry.encode_to_vec()),
        ("Value", "null_value", value(V::NullValue(0)).encode_to_vec()),
        ("Value", "number_value", value(V::NumberValue(1.5)).encode_to_vec()),
        ("Value", "string_value", value(V::StringValue("s".into())).encode_to_vec()),
        ("Value", "bool_value", value(V::BoolValue(true)).encode_to_vec()),
        ("Value", "struct_value", value(V::StructValue(Struct::default())).encode_to_vec()),
        ("Value", "list_value", value(V::ListValue(ListValue::default())).encode_to_vec()),
        ("ListValue", "values", ListValue { values: vec![value(V::BoolValue(true))] }.encode_to_vec()),
        ("DoubleValue", "value", DoubleValue { value: 1.5 }.encode_to_vec()),
        ("FloatValue", "value", FloatValue { value: 1.5 }.encode_to_vec()),
        ("Int64Value", "value", Int64Value { value: 1 }.encode_to_vec()),
        ("UInt64Value", "value", UInt64Value { value: 1 }.encode_to_vec()),
        ("Int32Value", "value", Int32Value { value: 1 }.encode_to_vec()),
        ("UInt32Value", "value", UInt32Value { value: 1 }.encode_to_vec()),
        ("BoolValue", "value", BoolValue { value: true }.encode_to_vec()),
        ("StringValue", "value", StringValue { value: "s".into() }.encode_to_vec()),
        ("BytesValue", "value", BytesValue { value: vec![1].into() }.encode_to_vec()),
    ];
    let mut seen = HashSet::new();
    for (message, field, bytes) in &samples {
        let want = table_message(message).fields.iter().find(|candidate| candidate.name == *field).unwrap_or_else(|| panic!("{message}.{field} is not in the table"));
        let written = wire_fields(bytes);
        assert_eq!(written.len(), 1, "google.protobuf.{message}.{field}: {written:?}");
        let (number, wire, _) = &written[0];
        assert_eq!((*number, *wire), (want.number as u64, wire_of(want.ty)), "google.protobuf.{message}.{field}: number and wire type");
        seen.insert(format!("{message}.{field}"));
    }
    // The map entry of Struct.fields always holds both its key and its value, so each is told
    // apart by what it holds: the key "k", and the value as the SDK encodes it alone.
    let entry = &table_message("Struct").nested[0];
    let (key, val) = (entry.fields.iter().find(|f| f.name == "key").unwrap(), entry.fields.iter().find(|f| f.name == "value").unwrap());
    let entry_bytes = wire_fields(&one_entry.encode_to_vec()).remove(0).2;
    let written = wire_fields(&entry_bytes);
    let keys: Vec<_> = written.iter().filter(|(_, _, payload)| payload.as_slice() == b"k").collect();
    let values: Vec<_> = written.iter().filter(|(_, _, payload)| *payload == entry_value.encode_to_vec()).collect();
    assert_eq!((keys.len(), values.len(), written.len()), (1, 1, 2), "Struct.FieldsEntry: exactly one key and one value, in either order: {written:?}");
    assert_eq!((keys[0].0, keys[0].1), (key.number as u64, wire_of(key.ty)), "Struct.FieldsEntry.key");
    seen.insert("Struct.FieldsEntry.key".to_string());
    assert_eq!((values[0].0, values[0].1), (val.number as u64, wire_of(val.ty)), "Struct.FieldsEntry.value");
    seen.insert("Struct.FieldsEntry.value".to_string());
    // Empty has no fields, and writes nothing.
    assert!(table_message("Empty").fields.is_empty() && Empty {}.encode_to_vec().is_empty());
    let mut every = HashSet::new();
    for (name, kind) in &well_known::SUPPORTED {
        if let well_known::Kind::Message(message) = kind {
            every.extend(message.fields.iter().map(|field| format!("{name}.{}", field.name)));
            for nested in message.nested {
                every.extend(nested.fields.iter().map(|field| format!("{name}.{}.{}", nested.name, field.name)));
            }
        }
    }
    let mut missing: Vec<&String> = every.difference(&seen).collect();
    missing.sort();
    assert!(missing.is_empty(), "fields of the table with no sample: {missing:?}");
    // The one enum.
    let Some((_, well_known::Kind::Enum(values))) = well_known::SUPPORTED.iter().find(|(name, _)| *name == "NullValue") else { panic!("NullValue") };
    assert_eq!(values.to_vec(), vec![(NullValue::NullValue.as_str_name(), NullValue::NullValue as i32)]);
}

#[test]
fn an_extend_may_only_declare_a_custom_option() {
    // protoc itself refuses, in proto3, an extend of anything but an option message, so the
    // extendee is changed in memory on what protoc read: the generator refuses it all the same.
    let option = "syntax = \"proto3\";\npackage demo;\nimport \"google/protobuf/descriptor.proto\";\nextend google.protobuf.MethodOptions { string tag = 50000; }\nmessage Thing { string word = 1; }\nservice Chat { rpc Say(Thing) returns (Thing) { option (tag) = \"x\"; } }\n";
    let scratch = Scratch::new("extendee", &[("demo.proto", option)]);
    let loaded = Api::new().serve(scratch.path("demo.proto")).load().unwrap();
    assert!(interfaces(&loaded.fds, &loaded.served, &loaded.called).is_ok());
    let mut fds = loaded.fds.clone();
    let demo = fds.file.iter_mut().find(|file| file.name() == "demo.proto").unwrap();
    demo.extension[0].extendee = Some(".demo.Thing".into());
    let said = interfaces(&fds, &loaded.served, &loaded.called).expect_err("an extend of an application message was taken").to_string();
    assert!(said.contains("demo.proto: extension demo.tag extends demo.Thing: an application file may only extend the standard option messages of google.protobuf"), "{said}");
}

#[cfg(unix)]
#[test]
fn a_file_given_is_named_as_protoc_names_it_not_by_its_link() {
    // second/api.proto is a link to second/payload.proto, which declares Wanted and imports
    // "payload.proto"; with `first` given first, protoc reads that import from first/payload.proto,
    // which declares Other. protoc names the file served api.proto, from the path as given, so
    // Wanted is served, and Other, though first/payload.proto is "payload.proto", is not.
    let scratch = Scratch::new(
        "linked",
        &[
            ("first/payload.proto", "syntax = \"proto3\";\npackage first;\nmessage Payload { string word = 1; }\nservice Other { rpc Take(Payload) returns (Payload); }\n"),
            ("second/payload.proto", "syntax = \"proto3\";\npackage second;\nimport \"payload.proto\";\nservice Wanted { rpc Give(first.Payload) returns (first.Payload); }\n"),
        ],
    );
    std::os::unix::fs::symlink("payload.proto", scratch.path("second/api.proto")).unwrap();
    let described = Api::new().include(scratch.path("first")).serve(scratch.path("second/api.proto")).describe().unwrap();
    let served: Vec<&str> = described.iter().filter(|interface| interface.served).map(|interface| interface.name.as_str()).collect();
    assert_eq!(served, ["wanted"]);
}

#[test]
fn protoc_puts_a_file_given_alone_after_everything_it_imports() {
    // The generator names each file given by loading it alone and taking the last file protoc
    // returns. That holds because protoc's set is in dependency order; here an input with
    // several imports, one of them nested and two sharing an import of their own.
    let scratch = Scratch::new(
        "last",
        &[
            ("a.proto", "syntax = \"proto3\";\npackage a;\nimport \"b.proto\";\nimport \"sub/c.proto\";\nmessage A { b.B b = 1; c.C c = 2; }\nservice Top { rpc Go(A) returns (A); }\n"),
            ("b.proto", "syntax = \"proto3\";\npackage b;\nimport \"sub/d.proto\";\nmessage B { d.D d = 1; }\n"),
            ("sub/c.proto", "syntax = \"proto3\";\npackage c;\nimport \"sub/d.proto\";\nmessage C { d.D d = 1; }\n"),
            ("sub/d.proto", "syntax = \"proto3\";\npackage d;\nmessage D { string word = 1; }\n"),
        ],
    );
    let alone = prost_build::Config::new().load_fds(&[scratch.path("a.proto")], &[scratch.0.clone()]).unwrap();
    let names: Vec<&str> = alone.file.iter().map(|file| file.name()).collect();
    assert_eq!(names.len(), 4, "{names:?}");
    assert_eq!(names.last(), Some(&"a.proto"), "{names:?}");
    let loaded = Api::new().serve(scratch.path("a.proto")).load().unwrap();
    assert_eq!(loaded.served, HashSet::from(["a.proto".to_string()]));
}

#[test]
fn a_file_given_through_an_include_is_named_by_protoc() {
    // The review's layout: `api/x.proto`, given as written from this crate's directory (which
    // has no `api/x.proto`), is found by protoc under `schemas` and named `api/x.proto`. It imports
    // "x.proto", whose service Other must not be taken for the one served.
    let scratch = Scratch::new(
        "through-include",
        &[
            ("schemas/api/x.proto", "syntax = \"proto3\";\npackage api;\nimport \"x.proto\";\nservice Wanted { rpc Give(top.Payload) returns (top.Payload); }\n"),
            ("schemas/x.proto", "syntax = \"proto3\";\npackage top;\nmessage Payload { string word = 1; }\nservice Other { rpc Take(Payload) returns (Payload); }\n"),
        ],
    );
    assert!(!Path::new("api/x.proto").exists(), "this crate's directory must not have an api/x.proto for the test");
    let api = || Api::new().include(scratch.path("schemas")).serve("api/x.proto");
    let served: Vec<String> = api().describe().unwrap().into_iter().filter(|interface| interface.served).map(|interface| interface.name).collect();
    assert_eq!(served, ["wanted"]);
    api().out_dir(scratch.path("out")).compile().unwrap();
    let description = FileDescriptorSet::decode(&*std::fs::read(scratch.path("out/ship_api.bin")).unwrap()).unwrap();
    let services: Vec<&str> = description.file.iter().flat_map(|file| file.service.iter().map(|service| service.name())).collect();
    assert_eq!(services, ["Wanted"]);
}

#[test]
fn paths_the_old_naming_refused_are_named_by_protoc() {
    // An earlier include of "." beside an absolute input, and a path with `..` in it under an
    // earlier include: both are named as protoc names them, and build.
    let scratch = Scratch::new(
        "odd-paths",
        &[
            ("demo.proto", "syntax = \"proto3\";\npackage demo;\nmessage Thing { string word = 1; }\nservice Chat { rpc Say(Thing) returns (Thing); }\n"),
            ("api/sub/keep.txt", ""),
            ("api/v1/x.proto", "syntax = \"proto3\";\npackage v1;\nmessage Thing { string word = 1; }\nservice Chat { rpc Say(Thing) returns (Thing); }\n"),
        ],
    );
    let loaded = Api::new().include(".").serve(scratch.path("demo.proto")).load().unwrap();
    assert_eq!(loaded.served, HashSet::from(["demo.proto".to_string()]));
    std::fs::create_dir_all(scratch.path("out-absolute")).unwrap();
    Api::new().include(".").serve(scratch.path("demo.proto")).out_dir(scratch.path("out-absolute")).compile().unwrap();
    let loaded = Api::new().include(scratch.path("api")).serve(scratch.path("api/sub/../v1/x.proto")).load().unwrap();
    assert_eq!(loaded.served, HashSet::from(["x.proto".to_string()]));
    assert_eq!(Api::new().include(scratch.path("api")).serve(scratch.path("api/sub/../v1/x.proto")).describe().unwrap().len(), 1);
    std::fs::create_dir_all(scratch.path("out-dots")).unwrap();
    Api::new().include(scratch.path("api")).serve(scratch.path("api/sub/../v1/x.proto")).out_dir(scratch.path("out-dots")).compile().unwrap();
}
