//! Turns the proto3 files that describe an agent's interfaces into typed Rust for the agent,
//! from its build script:
//!
//! ```no_run
//! fn main() -> std::io::Result<()> {
//!     ship_sdk_build::Api::new().serve("api/guestbook.proto").call("../other/api/other.proto").compile()
//! }
//! ```
//!
//! Each `service` is one interface, named after the service in lower-case words joined by `-`
//! (`GroupChat` is `group-chat`). A unary method is a command, or a question when it says
//! `option idempotency_level = NO_SIDE_EFFECTS;`. A server-streaming method is the interface's
//! log: its output is the type of every entry, and its input the type of the state a checkpoint
//! carries, or `google.protobuf.Empty` for a log that is a history kept whole. An interface has at
//! most one log, and a method that streams from its caller is refused.
//!
//! For the files the agent serves it generates handler traits, dispatch and logs it can append
//! to, and it writes their compiled description, with the messages they import, for
//! `ship_sdk::typed_agent!` to embed in the module. A file passed only to `call` gets client
//! stubs for its services. If a served file imports it directly or transitively, its
//! declarations are also embedded with its services removed. Every message also gets its proto3
//! JSON form (with `pbjson-build`), which the generated dispatch uses when a call asks for JSON,
//! so JSON is read and written inside the agent. Every application file must be
//! `syntax = "proto3"`. The files go to `OUT_DIR`; the agent includes them with
//! `ship_sdk::include_api!()`.
//!
//! It needs `protoc`, the Protocol Buffers compiler, on the path (or named by `PROTOC`), as the
//! rest of this workspace does.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use prost::Message;
use prost_types::method_options::IdempotencyLevel;
use prost_types::{FileDescriptorProto, FileDescriptorSet};

pub use ship_proto::interface_of_service;

mod well_known;
use well_known::check_well_known;

/// The name of the custom section the description goes in, in the agent's module.
pub const SECTION: &str = "ship.api.v1";

/// A description larger than this is said at build time: it is the runtime's default
/// `max_api_bytes`, and a runtime with that default refuses to install the agent.
pub const DEFAULT_MAX_API_BYTES: usize = 256 << 10;

/// What a method is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A unary method with no option: it changes state, through the `handle` export.
    Command,
    /// A unary method marked `idempotency_level = NO_SIDE_EFFECTS`: it only reads, through the
    /// `read` export, which also answers other ships' questions.
    Question,
    /// The server-streaming method: the interface's log.
    Log,
}

/// One interface, as the generator understood it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// The service's full name, with its package.
    pub service: String,
    /// The interface's name.
    pub name: String,
    /// Whether the agent serves it (and so whether it goes in the description).
    pub served: bool,
    /// Each method's name as written, and what it is, in the order written.
    pub methods: Vec<(String, Kind)>,
    /// The log's entry type and, unless it is a history, its state type (full proto names).
    pub log: Option<(String, Option<String>)>,
}

/// The files an agent serves and calls, and where `protoc` looks for what they import.
#[derive(Clone, Debug, Default)]
pub struct Api {
    served: Vec<PathBuf>,
    called: Vec<PathBuf>,
    includes: Vec<PathBuf>,
    out_dir: Option<PathBuf>,
}

fn invalid(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

impl Api {
    /// Nothing served or called yet.
    pub fn new() -> Api {
        Api::default()
    }

    /// A file of interfaces this agent serves: it gets handler traits, dispatch and logs, and
    /// goes in the embedded description.
    pub fn serve(mut self, path: impl AsRef<Path>) -> Api {
        self.served.push(path.as_ref().to_path_buf());
        self
    }

    /// A file of interfaces this agent only calls on other agents. A file passed only to `call`
    /// gets client stubs for its services. If a served file imports it directly or transitively,
    /// its declarations are also embedded with its services removed.
    pub fn call(mut self, path: impl AsRef<Path>) -> Api {
        self.called.push(path.as_ref().to_path_buf());
        self
    }

    /// A directory `protoc` looks in for imports, before the directories of the files given,
    /// which it always looks in.
    pub fn include(mut self, dir: impl AsRef<Path>) -> Api {
        self.includes.push(dir.as_ref().to_path_buf());
        self
    }

    /// Where the generated files go, in place of `OUT_DIR`.
    pub fn out_dir(mut self, dir: impl AsRef<Path>) -> Api {
        self.out_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Read and check the files, and say what each interface is, without writing anything.
    pub fn describe(&self) -> io::Result<Vec<Interface>> {
        let loaded = self.load()?;
        interfaces(&loaded.fds, &loaded.served, &loaded.called)
    }

    /// Read and check the files, and write the generated Rust (`ship_api.rs`, and the files it
    /// includes, in `ship_api/`) and the description (`ship_api.bin`) to `OUT_DIR`. A file that
    /// breaks a rule of the description is an error naming the service, method or file.
    pub fn compile(&self) -> io::Result<()> {
        let out = match &self.out_dir {
            Some(dir) => dir.clone(),
            None => PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| invalid("OUT_DIR is not set: compile is for a build script".into()))?),
        };
        let loaded = self.load()?;
        let described = interfaces(&loaded.fds, &loaded.served, &loaded.called)?;
        for dir in &loaded.includes {
            println!("cargo:rerun-if-changed={}", dir.display());
        }
        let description = description(&loaded.fds, &loaded.served);
        let bytes = description.encode_to_vec();
        if bytes.len() > DEFAULT_MAX_API_BYTES {
            println!("cargo:warning=the description is {} bytes, more than a runtime takes by default ({DEFAULT_MAX_API_BYTES}, max_api_bytes)", bytes.len());
        }
        std::fs::write(out.join("ship_api.bin"), &bytes)?;

        // The packages' files go in a directory of their own, apart from `ship_api.rs`, so that
        // no package's file can be taken for it; prost's in one directory and the JSON forms in
        // another, so that no file of one can be taken for the other's. Emptied first, so that a
        // file an earlier build left cannot be taken for this build's.
        let packages_dir = out.join("ship_api");
        let (prost_dir, serde_dir) = (packages_dir.join("prost"), packages_dir.join("serde"));
        let _ = std::fs::remove_dir_all(&packages_dir);
        std::fs::create_dir_all(&prost_dir)?;
        std::fs::create_dir_all(&serde_dir)?;
        let by_service: HashMap<(String, String), Interface> = described
            .iter()
            .map(|interface| {
                let (package, name) = split_name(&interface.service);
                ((package.to_string(), name.to_string()), interface.clone())
            })
            .collect();
        let troubles = Rc::new(RefCell::new(Vec::new()));
        let generator = Generator { interfaces: by_service, troubles: troubles.clone(), pending: HashMap::new() };
        prost_build::Config::new()
            .prost_path("::ship_sdk::prost")
            // The well-known types come from `ship-sdk`, with their JSON forms.
            .compile_well_known_types()
            .extern_path(".google.protobuf", "::ship_sdk::pbjson_types")
            .service_generator(Box::new(generator))
            .out_dir(&prost_dir)
            .compile_fds(loaded.fds.clone())?;
        if let Some(trouble) = troubles.borrow().first() {
            return Err(invalid(trouble.clone()));
        }
        // The proto3 JSON form of every message and enum, but the well-known types', which
        // `ship-sdk` brings. Fields a message does not know are ignored when it is read; every
        // field is written, those at their default included.
        let mut json = pbjson_build::Builder::new();
        json.register_descriptors(&loaded.fds.encode_to_vec())?
            .extern_path(".google.protobuf", "::ship_sdk::pbjson_types")
            .exclude([".google.protobuf"])
            .ignore_unknown_fields()
            .emit_fields();
        let written = json.generate(&["."], |_| Ok(Vec::<u8>::new()))?;
        // Package spellings that would share a Rust output path have already been rejected.
        let mut serde_texts: BTreeMap<String, String> = BTreeMap::new();
        let mut serde_files: HashMap<String, String> = HashMap::new();
        for (package, text) in written {
            let proto_package = package.path().iter().map(|part| part.to_string()).collect::<Vec<_>>().join(".");
            let file = file_of(&proto_package);
            // The generated code names `pbjson` and `serde`; each package's module brings both
            // in from `ship-sdk`, so the agent needs no dependency of its own on them. Its paths
            // that start `::pbjson::` are made to start `pbjson::`, outside string literals only,
            // so that no JSON name it reads or writes is touched.
            let text = outside_literals(&String::from_utf8(text).map_err(|e| invalid(e.to_string()))?, "::pbjson::", "pbjson::");
            serde_texts.entry(file.clone()).or_default().push_str(&text);
            serde_files.insert(proto_package, file);
        }
        for (file, text) in &serde_texts {
            std::fs::write(serde_dir.join(file), text)?;
        }
        let mut packages: Vec<String> = loaded.fds.file.iter().map(|file| file.package().to_string()).collect();
        packages.sort();
        packages.dedup();
        let generated: Vec<(Vec<String>, Vec<String>)> = packages
            .iter()
            .filter_map(|package| {
                let mut files = Vec::new();
                if prost_dir.join(file_of(package)).exists() {
                    files.push(format!("prost/{}", file_of(package)));
                }
                if let Some(file) = serde_files.get(package) {
                    files.push(format!("serde/{file}"));
                }
                let parts = prost_build::Module::from_protobuf_package_name(package).parts().map(str::to_string).collect();
                (!files.is_empty()).then_some((parts, files))
            })
            .collect();
        let served: Vec<&str> = described.iter().filter(|interface| interface.served).map(|interface| interface.name.as_str()).collect();
        std::fs::write(out.join("ship_api.rs"), include_file(&generated, bytes.len(), &loaded.served, &served))?;
        Ok(())
    }

    /// Run `protoc` over every file given, and ask it the name it gives each.
    fn load(&self) -> io::Result<Loaded> {
        let mut includes: Vec<PathBuf> = self.includes.clone();
        for file in self.served.iter().chain(&self.called) {
            let dir = file.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
            if !includes.iter().any(|known| known == dir) {
                includes.push(dir.to_path_buf());
            }
        }
        let files: Vec<&PathBuf> = self.served.iter().chain(&self.called).collect();
        if self.served.is_empty() && self.called.is_empty() {
            return Err(invalid("no proto file was given to serve or to call".into()));
        }
        let fds = prost_build::Config::new().load_fds(&files, &includes)?;
        // The name a file given has in the set is the one protoc gives it, so protoc is asked:
        // each file given is loaded alone, with the same directories, and its name is that of the
        // last file protoc returns. This relies on protoc's set being in dependency order, each
        // file after the files it imports, so that for one file given the last is that file (a
        // test pins it, with an input that has several imports, some nested).
        let named = |file: &PathBuf| -> io::Result<String> {
            let alone = prost_build::Config::new().load_fds(&[file], &includes)?;
            let last = alone.file.last().ok_or_else(|| invalid(format!("protoc returned no file for {}", file.display())))?;
            Ok(last.name().to_string())
        };
        let served: HashSet<String> = self.served.iter().map(named).collect::<io::Result<_>>()?;
        // A file both served and called is served.
        let called: HashSet<String> = self.called.iter().map(named).collect::<io::Result<HashSet<_>>>()?.difference(&served).cloned().collect();
        Ok(Loaded { fds, served, called, includes })
    }
}

/// What `protoc` made of the files, and which of them are served and called, by the names it
/// gave them.
struct Loaded {
    fds: FileDescriptorSet,
    served: HashSet<String>,
    called: HashSet<String>,
    includes: Vec<PathBuf>,
}

/// The file prost writes a package's code to.
fn file_of(package: &str) -> String {
    prost_build::Module::from_protobuf_package_name(package).to_file_name_or("_")
}

/// `text` with `from` put as `to` wherever a path starts with it outside a string literal
/// (`"..."`, with its escapes, or a raw string `r"..."`, `r#"..."#`). A path starts there only
/// when the text before is neither an identifier character (any character outside ASCII counts
/// as one) nor `::`, so `super::pbjson::Kind`, `π::pbjson::Kind` and `mypbjson::x` are left
/// alone.
///
/// This is a partial Rust lexer, enough for what pbjson-build's templates emit. It does not know
/// a quote inside a byte raw string (`br#"a"b"#`), a char literal such as `'"'`, or a comment
/// holding an unmatched quote; any of these could make it skip a real path or rewrite text
/// inside the next string. The templates do not emit them.
fn outside_literals(text: &str, from: &str, to: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        // A byte that is not ASCII is taken as part of an identifier (such as `π`), to be safe.
        let starts_word = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || !bytes[i - 1].is_ascii());
        if bytes[i] == b'r' && starts_word {
            let hashes = bytes[i + 1..].iter().take_while(|b| **b == b'#').count();
            if bytes.get(i + 1 + hashes) == Some(&b'"') {
                let close = format!("\"{}", "#".repeat(hashes));
                let start = i + 2 + hashes;
                let end = text[start..].find(&close).map_or(bytes.len(), |at| start + at + close.len());
                out.push_str(&text[i..end]);
                i = end;
                continue;
            }
        }
        if bytes[i] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(bytes.len());
            out.push_str(&text[i..end]);
            i = end;
            continue;
        }
        let starts_path = starts_word && !text[..i].ends_with("::");
        if starts_path && text[i..].starts_with(from) {
            out.push_str(to);
            i += from.len();
            continue;
        }
        let ch = text[i..].chars().next().expect("a character");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `package.Name` split at the last dot.
fn split_name(full: &str) -> (&str, &str) {
    full.rsplit_once('.').unwrap_or(("", full))
}

/// Check every service in the files served and called against the rules, and say what each is.
fn interfaces(fds: &FileDescriptorSet, served: &HashSet<String>, called: &HashSet<String>) -> io::Result<Vec<Interface>> {
    let mut out = Vec::new();
    let mut names: HashMap<String, String> = HashMap::new();
    // The services' modules are in `_interfaces` in their package's module, which no package or
    // message can make (prost's names never start with an underscore before a letter), so the
    // one clash left is two services making one module there: refused here, naming both.
    let mut modules: HashMap<(String, String), String> = HashMap::new();
    let mut claim = |package: &str, module: String, source: String| -> io::Result<()> {
        let path = prost_build::Module::from_protobuf_package_name(package).parts().collect::<Vec<_>>().join("::");
        match modules.get(&(path.clone(), module.clone())) {
            Some(first) => Err(invalid(format!("{first} and {source} would both make the Rust module {module} in package {package:?}: rename one"))),
            None => {
                modules.insert((path, module), source);
                Ok(())
            }
        }
    };
    // Every file is made into Rust in a package's module, and the JSON generator needs a package
    // to name the types in it.
    if let Some(file) = fds.file.iter().find(|file| file.package().is_empty()) {
        let stem = file.name().rsplit('/').next().unwrap_or("name").trim_end_matches(".proto").replace(['-', '.'], "_");
        return Err(invalid(format!("{} has no package: give it one, with a line such as `package {stem};` near its top", file.name())));
    }
    // Every application file, served, called or only imported, is proto3: so no proto2
    // presence, groups, required fields, defaults or extension ranges reach a payload.
    if let Some(file) = fds.file.iter().find(|file| !well_known::is_well_known_file(file) && file.syntax() != "proto3") {
        let syntax = if file.syntax().is_empty() { "proto2" } else { file.syntax() };
        return Err(invalid(format!("{} is {syntax}: every application file, served, called or imported, must be syntax = \"proto3\"", file.name())));
    }
    check_well_known(fds)?;
    check_packages(fds)?;
    check_json_names(fds)?;
    for file in &fds.file {
        let is_served = served.contains(file.name());
        if !is_served && !called.contains(file.name()) {
            continue;
        }
        for service in &file.service {
            let interface = check_service(file, service)?;
            if is_served {
                if let Some(other) = names.insert(interface.name.clone(), interface.service.clone()) {
                    return Err(invalid(format!("services {other} and {} are both the interface {:?}: an agent serves each interface once", interface.service, interface.name)));
                }
            }
            claim(file.package(), format!("{}_api", interface.name.replace('-', "_")), format!("service {}", interface.service))?;
            out.push(Interface { served: is_served, ..interface });
        }
    }
    Ok(out)
}

/// Module names the generated code takes for itself in every package's module: the crates it
/// names, brought in from `ship-sdk`.
const TAKEN_MODULES: [&str; 5] = ["pbjson", "pbjson_types", "serde", "serde_json", "prost"];

/// The packages of every file, served, called or only imported, against two rules. Prost makes
/// one Rust module of two spellings such as `demo.Two` and `demo.two`, but finishes its code under
/// one of them and can leave out what the other holds, so two spellings of one module are refused.
/// And no part of a package may make a module the generated code takes for itself.
fn check_packages(fds: &FileDescriptorSet) -> io::Result<()> {
    let mut spellings: HashMap<String, (&str, &str)> = HashMap::new();
    for file in &fds.file {
        let module = prost_build::Module::from_protobuf_package_name(file.package());
        if let Some(part) = module.parts().find(|part| TAKEN_MODULES.contains(part)) {
            return Err(invalid(format!(
                "{}: package {} makes a Rust module named {part}, a name the generated code takes for itself ({}): rename that part",
                file.name(),
                file.package(),
                TAKEN_MODULES.join(", ")
            )));
        }
        let path = module.parts().collect::<Vec<_>>().join("::");
        match spellings.get(&path) {
            Some((other_file, other)) if *other != file.package() => {
                return Err(invalid(format!(
                    "{other_file} has package {other} and {} has package {}, which make the one Rust module {path}: spell them the same",
                    file.name(),
                    file.package()
                )));
            }
            Some(_) => {}
            None => {
                spellings.insert(path, (file.name(), file.package()));
            }
        }
    }
    Ok(())
}

/// Every field's declared JSON name, in every file, must be one the JSON generator can write
/// between Rust quotes as it is, since it puts the name there without escaping it: a backslash
/// would be read as an escape, and a double quote or a control character would break or change
/// the literal. Such a name is refused before anything is generated.
fn check_json_names(fds: &FileDescriptorSet) -> io::Result<()> {
    fn walk(file: &str, scope: &str, messages: &[prost_types::DescriptorProto]) -> io::Result<()> {
        for message in messages {
            let full = format!("{scope}.{}", message.name());
            for field in &message.field {
                for (what, name) in [("name", field.name()), ("JSON name", field.json_name())] {
                    if name.chars().any(|c| c == '\\' || c == '"' || c.is_control()) {
                        return Err(invalid(format!(
                            "{file}: field {full}.{} has the {what} {name:?}, which holds a backslash, a double quote or a control character: the generated JSON code cannot hold it as it is",
                            field.name()
                        )));
                    }
                }
            }
            walk(file, &full, &message.nested_type)?;
        }
        Ok(())
    }
    for file in &fds.file {
        walk(file.name(), file.package(), &file.message_type)?;
    }
    Ok(())
}

/// One service against the rules of a description.
/// A name with its package in front, if it has one.
fn qualified(package: &str, name: &str) -> String {
    if package.is_empty() { name.to_string() } else { format!("{package}.{name}") }
}

fn check_service(file: &FileDescriptorProto, service: &prost_types::ServiceDescriptorProto) -> io::Result<Interface> {
    let full = qualified(file.package(), service.name());
    let Some(name) = interface_of_service(service.name()) else {
        return Err(invalid(format!(
            "service {full} does not turn into a valid interface name: written in CamelCase, it must give lower-case words joined by '-', starting with a letter, with no leading, trailing or doubled underscore, at most {} bytes",
            ship_proto::MAX_INTERFACE_BYTES
        )));
    };
    let mut methods = Vec::new();
    let mut log: Option<(String, (String, Option<String>))> = None;
    for method in &service.method {
        if method.client_streaming() {
            return Err(invalid(format!("method {full}.{} streams from its caller, which an interface cannot do: a method is a command, a question, or the interface's log", method.name())));
        }
        let kind = if method.server_streaming() {
            let entry = method.output_type().trim_start_matches('.').to_string();
            let state = Some(method.input_type().trim_start_matches('.').to_string()).filter(|state| state != "google.protobuf.Empty");
            if let Some((first, _)) = &log {
                return Err(invalid(format!("service {full} has two streaming methods, {first} and {}: an interface has at most one log", method.name())));
            }
            log = Some((method.name().to_string(), (entry, state)));
            Kind::Log
        } else if method.options.as_ref().is_some_and(|options| options.idempotency_level() == IdempotencyLevel::NoSideEffects) {
            Kind::Question
        } else {
            Kind::Command
        };
        methods.push((method.name().to_string(), kind));
    }
    Ok(Interface { service: full, name, served: false, methods, log: log.map(|(_, log)| log) })
}

/// The description of what is served: the served files and everything they import, so that it
/// stands alone, in an order where each file comes after what it imports. A file imported and
/// not served keeps its messages and enums and loses its services (and the comments on them), so
/// that the description names only interfaces the agent serves. Comments are kept (for documents
/// made from it later); the places in the source that carry no comment are not.
fn description(fds: &FileDescriptorSet, served: &HashSet<String>) -> FileDescriptorSet {
    let mut wanted: HashSet<String> = served.clone();
    let mut grew = true;
    while grew {
        grew = false;
        for file in &fds.file {
            if wanted.contains(file.name()) {
                for dependency in &file.dependency {
                    grew |= wanted.insert(dependency.clone());
                }
            }
        }
    }
    // protoc lists each file after the files it imports.
    let file = fds
        .file
        .iter()
        .filter(|file| wanted.contains(file.name()))
        .cloned()
        .map(|mut file| {
            // Field 6 of a FileDescriptorProto is its services.
            const SERVICES: i32 = 6;
            let imported = !served.contains(file.name());
            if imported {
                file.service.clear();
            }
            if let Some(info) = file.source_code_info.as_mut() {
                info.location.retain(|location| location.leading_comments.is_some() || location.trailing_comments.is_some() || !location.leading_detached_comments.is_empty());
                if imported {
                    info.location.retain(|location| location.path.first() != Some(&SERVICES));
                }
            }
            file
        })
        .collect();
    FileDescriptorSet { file }
}

/// `ship_api.rs` includes the generated package modules, and `ship_api.bin` holds the embedded
/// description. Every input file must declare a package. Each package's module (by prost's own
/// names for the parts) holds its messages, their JSON forms and its interfaces; at the top are
/// the description and the names of the interfaces served.
fn include_file(packages: &[(Vec<String>, Vec<String>)], description_len: usize, served_files: &HashSet<String>, served: &[&str]) -> String {
    #[derive(Default)]
    struct Node {
        files: Vec<String>,
        children: BTreeMap<String, Node>,
    }
    let mut root = Node::default();
    for (parts, files) in packages {
        let mut node = &mut root;
        for part in parts {
            node = node.children.entry(part.clone()).or_default();
        }
        node.files.extend(files.iter().cloned());
    }
    fn write(node: &Node, depth: usize, out: &mut String) {
        let indent = "    ".repeat(depth);
        if !node.files.is_empty() {
            let _ = writeln!(out, "{indent}#[allow(unused_imports)]\n{indent}use ::ship_sdk::{{pbjson, serde}};");
        }
        for file in &node.files {
            let _ = writeln!(out, "{indent}include!(concat!(env!(\"OUT_DIR\"), \"/ship_api/{file}\"));");
        }
        for (name, child) in &node.children {
            let _ = writeln!(out, "{indent}pub mod {name} {{");
            write(child, depth + 1, out);
            let _ = writeln!(out, "{indent}}}");
        }
    }
    let mut files: Vec<&String> = served_files.iter().collect();
    files.sort();
    let mut out = String::new();
    let _ = writeln!(out, "// Generated by ship-sdk-build. Include it with `ship_sdk::include_api!()`, which puts it in a");
    let _ = writeln!(out, "// module named `api`.");
    write(&root, 0, &mut out);
    let _ = writeln!(out, "/// The compiled description of the interfaces this agent serves ({}): a `FileDescriptorSet`", if files.is_empty() { "none".to_string() } else { files.iter().map(|name| name.as_str()).collect::<Vec<_>>().join(", ") });
    let _ = writeln!(out, "/// holding those files and the messages they import, for `ship_sdk::typed_agent!` to embed in");
    let _ = writeln!(out, "/// the module as the custom section `{SECTION}`.");
    let _ = writeln!(out, "pub const DESCRIPTION: [u8; {description_len}] = *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/ship_api.bin\"));");
    let _ = writeln!(out, "/// The interfaces the description serves: `ship_sdk::typed_agent!` must wire exactly these.");
    let _ = writeln!(out, "pub const SERVED: &[&str] = &{served:?};");
    out
}

/// Writes the Rust for each service, into its package's file.
struct Generator {
    interfaces: HashMap<(String, String), Interface>,
    troubles: Rc<RefCell<Vec<String>>>,
    /// The services' modules written so far, by package, put in `_interfaces` when the package
    /// is finished.
    pending: HashMap<String, String>,
}

/// A Rust type named in a package's file, as seen from `depth` modules further in.
fn from_inside(path: &str, depth: usize) -> String {
    if path.starts_with("::") || path == "()" {
        path.to_string()
    } else {
        format!("{}{path}", "super::".repeat(depth))
    }
}

/// Comments as doc comments, at an indent.
fn docs(comments: &prost_build::Comments, depth: u8, out: &mut String) {
    comments.append_with_indent(depth, out);
}

impl prost_build::ServiceGenerator for Generator {
    fn finalize_package(&mut self, package: &str, buf: &mut String) {
        let Some(services) = self.pending.remove(package) else { return };
        let _ = writeln!(buf);
        let _ = writeln!(buf, "/// The interfaces of this package's services, one module for each, apart from the package's own");
        let _ = writeln!(buf, "/// names. Generated by ship-sdk-build.");
        let _ = writeln!(buf, "pub mod _interfaces {{");
        buf.push_str(&services);
        let _ = writeln!(buf, "}}");
    }

    fn generate(&mut self, service: prost_build::Service, _: &mut String) {
        let Some(interface) = self.interfaces.get(&(service.package.clone(), service.proto_name.clone())) else { return };
        let buf = self.pending.entry(service.package.clone()).or_default();
        let mut snakes = HashSet::new();
        for method in &service.methods {
            if !snakes.insert(method.name.clone()) {
                self.troubles.borrow_mut().push(format!("service {} has two methods whose Rust name is {}: rename one", interface.service, method.name));
            }
        }
        let name = &interface.name;
        let module = format!("{}_api", name.replace('-', "_"));
        let kind_of = |method: &prost_build::Method| interface.methods.iter().find(|(name, _)| *name == method.proto_name).map(|(_, kind)| kind.clone()).unwrap_or(Kind::Command);
        let commands: Vec<&prost_build::Method> = service.methods.iter().filter(|m| kind_of(m) == Kind::Command).collect();
        let questions: Vec<&prost_build::Method> = service.methods.iter().filter(|m| kind_of(m) == Kind::Question).collect();
        let log = service.methods.iter().find(|m| kind_of(m) == Kind::Log);
        let stateful = log.is_some_and(|_| interface.log.as_ref().is_some_and(|(_, state)| state.is_some()));
        let fault = "::ship_sdk::api::Fault";
        let result = "::core::result::Result";

        let out = buf;
        let _ = writeln!(out);
        docs(&service.comments, 0, out);
        if !service.comments.leading.is_empty() {
            let _ = writeln!(out, "///");
        }
        let _ = writeln!(out, "/// The interface `{name}`, from the service `{}`. Generated by ship-sdk-build.", interface.service);
        let _ = writeln!(out, "pub mod {module} {{");
        let _ = writeln!(out, "    /// The interface's name, as the manifest and the calls name it.");
        let _ = writeln!(out, "    pub const INTERFACE: &str = {name:?};");

        if interface.served {
            let _ = writeln!(out);
            let _ = writeln!(out, "    /// The handlers of `{name}`: one for each command and each question. Each is given the");
            let _ = writeln!(out, "    /// decoded input and returns the output or a fault; `ship_sdk::invocation()` still says");
            let _ = writeln!(out, "    /// who is calling. Generated dispatch passes a returned command fault to `refuse`. An");
            let _ = writeln!(out, "    /// accepted refusal rolls back the handler's changes and carries the fault in the owner's");
            let _ = writeln!(out, "    /// result or in a receipt sent to another ship. An invalid code produces an ordinary failure.");
            let _ = writeln!(out, "    pub trait Handlers {{");
            for method in commands.iter().chain(&questions) {
                docs(&method.comments, 2, out);
                if !method.comments.leading.is_empty() {
                    let _ = writeln!(out, "        ///");
                }
                let what = if kind_of(method) == Kind::Command { "A command: it may change state, and a fault rolls it back" } else { "A question: it only reads, and also answers other ships' questions" };
                let _ = writeln!(out, "        /// {what} (`{}`).", method.proto_name);
                let _ = writeln!(out, "        fn {}(request: {}) -> {result}<{}, {fault}>;", method.name, from_inside(&method.input_type, 2), from_inside(&method.output_type, 2));
            }
            let _ = writeln!(out, "    }}");
            if let (true, Some(log)) = (stateful, log) {
                let _ = writeln!(out);
                let _ = writeln!(out, "    /// The state behind the log `{name}`, for a checkpoint: the state as of the log's newest");
                let _ = writeln!(out, "    /// entry, which a follower far behind is handed in place of the entries before it. Change");
                let _ = writeln!(out, "    /// that state only in the event that appends the entry describing the change. `None` keeps");
                let _ = writeln!(out, "    /// the log whole.");
                let _ = writeln!(out, "    pub trait Checkpoint {{");
                let _ = writeln!(out, "        fn state() -> ::core::option::Option<{}>;", from_inside(&log.input_type, 2));
                let _ = writeln!(out, "    }}");
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "    /// `{name}` as `ship_sdk::typed_agent!` takes it, with the type that implements its handlers.");
            let _ = writeln!(out, "    pub struct Interface;");
            let bound = if stateful { "Handlers + Checkpoint" } else { "Handlers" };
            let _ = writeln!(out, "    impl<H: {bound}> ::ship_sdk::api::Serve<H> for Interface {{");
            let _ = writeln!(out, "        const INTERFACE: &'static str = INTERFACE;");
            for (export, own, other, other_is) in [("command", &commands, &questions, "a question"), ("read", &questions, &commands, "a command")] {
                let _ = writeln!(out, "        fn {export}(method: &str, body: &[u8], json: bool) -> {result}<::std::vec::Vec<u8>, {fault}> {{");
                let _ = writeln!(out, "            let _ = (body, json);");
                let _ = writeln!(out, "            match method {{");
                for method in own.iter() {
                    let _ = writeln!(out, "                {:?} => ::ship_sdk::api::__reply(<H as Handlers>::{}(::ship_sdk::api::__request(method, body, json)?), json),", method.proto_name, method.name);
                }
                for method in other.iter() {
                    let _ = writeln!(out, "                {:?} => {result}::Err(::ship_sdk::api::__wrong_kind(INTERFACE, method, {other_is:?})),", method.proto_name);
                }
                let _ = writeln!(out, "                _ => {result}::Err(::ship_sdk::api::__no_such_method(INTERFACE, method)),");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "        }}");
            }
            let _ = writeln!(out, "        fn checkpoint() -> ::core::option::Option<::std::vec::Vec<u8>> {{");
            if stateful {
                let _ = writeln!(out, "            <H as Checkpoint>::state().map(|state| ::ship_sdk::prost::Message::encode_to_vec(&state))");
            } else {
                let _ = writeln!(out, "            ::core::option::Option::None");
            }
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "    }}");
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "    /// Calling `{name}` on an agent: one module for each method, with a function for each way");
        let _ = writeln!(out, "    /// there is to reach it, and one that turns what comes back into the typed reply.");
        let _ = writeln!(out, "    pub mod call {{");
        for method in commands.iter().chain(&questions) {
            let input = from_inside(&method.input_type, 4);
            let output = from_inside(&method.output_type, 4);
            let call = "::ship_sdk::api::__call(METHOD, request)";
            docs(&method.comments, 2, out);
            if !method.comments.leading.is_empty() {
                let _ = writeln!(out, "        ///");
            }
            let _ = writeln!(out, "        /// `{}`, a {}.", method.proto_name, if kind_of(method) == Kind::Command { "command" } else { "question" });
            let _ = writeln!(out, "        pub mod {} {{", method.name);
            let _ = writeln!(out, "            /// The method's name, as the call carries it.");
            let _ = writeln!(out, "            pub const METHOD: &str = {:?};", method.proto_name);
            if kind_of(method) == Kind::Command {
                let _ = writeln!(out, "            /// Send it to `agent` on this ship. It runs after this event commits, as that agent's own event; nothing comes back.");
                let _ = writeln!(out, "            pub fn send(agent: &str, request: &{input}) {{");
                let _ = writeln!(out, "                ::ship_sdk::send(agent, super::super::INTERFACE, &{call})");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "            /// Send it to `agent` on another ship (see `ship_sdk::send_to`), returning the number its receipt will carry.");
                let _ = writeln!(out, "            pub fn send_to(ship: &str, agent: &str, request: &{input}) -> u64 {{");
                let _ = writeln!(out, "                ::ship_sdk::send_to(ship, agent, super::super::INTERFACE, &{call})");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "            /// The same, with the reply wanted back on the receipt (see `ship_sdk::send_to_for_reply`); `receipt` reads it.");
                let _ = writeln!(out, "            pub fn send_to_for_reply(ship: &str, agent: &str, request: &{input}) -> u64 {{");
                let _ = writeln!(out, "                ::ship_sdk::send_to_for_reply(ship, agent, super::super::INTERFACE, &{call})");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "            /// The typed reply a receipt carries, the fault the command was refused with, or why there is none.");
                let _ = writeln!(out, "            pub fn receipt(receipt: &::ship_sdk::Receipt) -> {result}<{output}, ::ship_sdk::api::CallError> {{");
                let _ = writeln!(out, "                ::ship_sdk::api::__receipt(receipt)");
                let _ = writeln!(out, "            }}");
            } else {
                let _ = writeln!(out, "            /// Ask `agent` on this ship now: the typed reply, or the fault, or why what came back is not understood.");
                let _ = writeln!(out, "            pub fn read(agent: &str, request: &{input}) -> {result}<{output}, ::ship_sdk::api::CallError> {{");
                let _ = writeln!(out, "                ::ship_sdk::api::__decode_reply(&::ship_sdk::read(agent, super::super::INTERFACE, &{call}))");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "            /// Put it to `agent` on another ship (see `ship_sdk::ask::to`), returning the number its answer will carry.");
                let _ = writeln!(out, "            pub fn ask(ship: &str, agent: &str, request: &{input}, within_millis: u64) -> u64 {{");
                let _ = writeln!(out, "                ::ship_sdk::ask::to(ship, agent, super::super::INTERFACE, &{call}, within_millis)");
                let _ = writeln!(out, "            }}");
                let _ = writeln!(out, "            /// The typed reply an answer carries, the fault, or the outcome that is not a reply.");
                let _ = writeln!(out, "            pub fn answered(answered: &::ship_sdk::ask::Answered) -> {result}<{output}, ::ship_sdk::api::CallError> {{");
                let _ = writeln!(out, "                ::ship_sdk::api::__answered(answered)");
                let _ = writeln!(out, "            }}");
            }
            let _ = writeln!(out, "        }}");
        }
        let _ = writeln!(out, "    }}");

        if let Some(log) = log {
            let entry = from_inside(&log.output_type, 3);
            let state = if stateful { from_inside(&log.input_type, 3) } else { "()".to_string() };
            let _ = writeln!(out);
            docs(&log.comments, 1, out);
            if !log.comments.leading.is_empty() {
                let _ = writeln!(out, "    ///");
            }
            let _ = writeln!(out, "    /// The log `{name}` (`{}`): every entry is an `Entry`{}.", log.proto_name, if stateful { ", and a checkpoint carries a `State`" } else { ", and it is a history, kept whole" });
            let _ = writeln!(out, "    pub mod log {{");
            let _ = writeln!(out, "        /// The type of every entry in the log.");
            let _ = writeln!(out, "        pub type Entry = {entry};");
            let _ = writeln!(out, "        /// The type of the state a checkpoint of the log carries (`()` for a history, which has none).");
            let _ = writeln!(out, "        pub type State = {state};");
            let _ = writeln!(out, "        /// What `next` hands over: each entry decoded, or handed over undecoded with its number.");
            let _ = writeln!(out, "        pub type Batch = ::ship_sdk::api::Batch<Entry, State>;");
            if interface.served {
                let _ = writeln!(out, "        /// Add an entry to this agent's own log `{name}` and return its number. Kept only if this event commits.");
                let _ = writeln!(out, "        pub fn append(entry: &Entry) -> u64 {{");
                let _ = writeln!(out, "            ::ship_sdk::log::append(super::INTERFACE, &::ship_sdk::prost::Message::encode_to_vec(entry))");
                let _ = writeln!(out, "        }}");
                let _ = writeln!(out, "        /// Let another ship (or every ship, \"*\") follow this agent's log `{name}` (see `ship_sdk::log::share`).");
                let _ = writeln!(out, "        pub fn share(ship: &str) {{");
                let _ = writeln!(out, "            ::ship_sdk::log::share(super::INTERFACE, ship)");
                let _ = writeln!(out, "        }}");
                let _ = writeln!(out, "        /// Stop letting it (see `ship_sdk::log::unshare`).");
                let _ = writeln!(out, "        pub fn unshare(ship: &str) {{");
                let _ = writeln!(out, "            ::ship_sdk::log::unshare(super::INTERFACE, ship)");
                let _ = writeln!(out, "        }}");
            }
            let _ = writeln!(out, "        /// Follow `agent`'s log `{name}` on this ship, from its first entry.");
            let _ = writeln!(out, "        pub fn follow(agent: &str) {{");
            let _ = writeln!(out, "            ::ship_sdk::log::follow(agent, super::INTERFACE)");
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "        /// Follow it on another ship (see `ship_sdk::log::follow_on`).");
            let _ = writeln!(out, "        pub fn follow_on(ship: &str, agent: &str) {{");
            let _ = writeln!(out, "            ::ship_sdk::log::follow_on(ship, agent, super::INTERFACE)");
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "        /// Stop following it, on this ship (an empty ship name) or another.");
            let _ = writeln!(out, "        pub fn unfollow_on(ship: &str, agent: &str) {{");
            let _ = writeln!(out, "            ::ship_sdk::log::unfollow_on(ship, agent, super::INTERFACE)");
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "        /// Take up to `max` entries after this agent's position in `agent`'s log on this ship.");
            let _ = writeln!(out, "        pub fn next(agent: &str, max: u32) -> Batch {{");
            let _ = writeln!(out, "            next_on(\"\", agent, max)");
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "        /// The same for a log on another ship (or this one, with an empty ship name).");
            let _ = writeln!(out, "        pub fn next_on(ship: &str, agent: &str, max: u32) -> Batch {{");
            let _ = writeln!(out, "            ::ship_sdk::api::__next(ship, agent, super::INTERFACE, max)");
            let _ = writeln!(out, "        }}");
            let _ = writeln!(out, "    }}");
        }
        let _ = writeln!(out, "}}");
    }
}

#[cfg(test)]
mod tests;
