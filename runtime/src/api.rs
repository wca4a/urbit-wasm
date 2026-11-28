//! Descriptions of agents' interfaces, and typed calls through them.
//!
//! An agent built with `ship-sdk-build` carries the description of the interfaces it serves in
//! its own module: a `FileDescriptorSet` in a custom section named `ship.api.v1`. Nothing on the
//! event path reads it. A typed call is an ordinary payload (a `Call`, answered by a
//! `CallReply`), and the runtime runs it as it runs any other.
//!
//! The runtime reads no message types. Of a description it reads only the services and their
//! methods, to learn each interface's name and each method's kind, with a plain decode of the
//! descriptor messages and a walk over them: no types are resolved, and nothing is built from
//! them. Bodies, in protobuf or in proto3 JSON, are read and written by the code generated into
//! the agent. Message bodies are decoded and encoded inside the agent's event limits. Native code
//! extracts the section during compilation and decodes its services during installation and on
//! a description-cache miss.
//!
//! Two things here read descriptions. Installing an agent checks the one its module carries
//! against the rules and the manifest. And the HTTP server's JSON door uses the method's kind to
//! run a call as a command or as a question, and hands the description to whoever asks.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost_types::method_options::IdempotencyLevel;
use prost_types::FileDescriptorSet;
use ship_proto::call_reply::Result as Replied;
use ship_proto::{interface_of_service, Call, CallReply, Fault, Manifest, Message};
use wasmparser::{Parser, Payload};

use crate::{check_agent_name, check_target, lock, Error, Runtime};

/// The custom section a module carries its description in.
pub const SECTION: &str = "ship.api.v1";

/// The most `Config::max_api_bytes` may be: a larger setting is held to this when the runtime
/// opens. A description is the text of a few proto files compiled; this is far beyond any.
pub const MOST_API_BYTES: usize = 1 << 20;

/// How many descriptions are kept, one for each module, the least recently used let go first.
pub const CACHE_ENTRIES: usize = 32;

/// What a method is, by how it is declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodKind {
    /// Unary, no option: run with `KIND_COMMAND`, through the `handle` export.
    Command,
    /// Unary, `idempotency_level = NO_SIDE_EFFECTS`: run with `KIND_READ`, through `read`.
    Question,
    /// Server-streaming: the interface's log, not a method to call.
    Log,
}

/// One described interface: a `service` of the description, its methods by name with their
/// kinds. The package is kept once for its file and shared by its services, and the service's
/// full name is made only when asked for, so that what is kept grows with the section and not
/// with the package's length times the number of services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    package: Arc<str>,
    local: String,
    pub methods: BTreeMap<String, MethodKind>,
}

impl Interface {
    /// The service's full name, with its package, made now.
    pub fn service(&self) -> String {
        qualified(&self.package, &self.local)
    }

    /// The package of the service's file, shared with every other service of that file.
    pub fn package(&self) -> &Arc<str> {
        &self.package
    }
}

/// A name with its package in front, if it has one.
fn qualified(package: &str, name: &str) -> String {
    if package.is_empty() { name.to_string() } else { format!("{package}.{name}") }
}

/// A module's description, as the runtime reads it: the bytes as the module carries them, and
/// each interface.
#[derive(Debug)]
pub struct Description {
    bytes: Vec<u8>,
    interfaces: BTreeMap<String, Interface>,
}

impl Description {
    /// The `FileDescriptorSet`, byte for byte as the module carries it.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn interfaces(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.values()
    }

    pub fn interface(&self, name: &str) -> Option<&Interface> {
        self.interfaces.get(name)
    }

    /// The bytes of the names it keeps: each package once, however many services share it, and
    /// each interface's name (in the map's key and in the interface), service and method name.
    pub fn kept_name_bytes(&self) -> usize {
        let mut packages: std::collections::HashSet<*const u8> = std::collections::HashSet::new();
        let mut total = 0;
        for (key, interface) in &self.interfaces {
            if packages.insert(interface.package.as_ptr()) {
                total += interface.package.len();
            }
            total += key.len() + interface.name.len() + interface.local.len() + interface.methods.keys().map(String::len).sum::<usize>();
        }
        total
    }
}

/// The bytes of a module's `ship.api.v1` section: `None` if it has none, and an error if it
/// has more than one, if the section is larger than `limit`, or if the module cannot be read.
pub fn section(module: &[u8], limit: usize) -> Result<Option<&[u8]>, String> {
    let mut found = None;
    for payload in Parser::new(0).parse_all(module) {
        let payload = payload.map_err(|e| format!("the module cannot be read: {e}"))?;
        if let Payload::CustomSection(reader) = payload {
            if reader.name() != SECTION {
                continue;
            }
            if found.is_some() {
                return Err(format!("the module has more than one {SECTION} section"));
            }
            if reader.data().len() > limit {
                return Err(format!("its description is {} bytes, and this runtime takes at most {limit} (max_api_bytes)", reader.data().len()));
            }
            found = Some(reader.data());
        }
    }
    Ok(found)
}

/// Read a description's services and check them against the rules: it decodes as a
/// `FileDescriptorSet` (prost's own decoder, with its limit on nesting); every service's name
/// turns into an interface name; no method streams from its caller; a service has at most one
/// streaming method (its log); and no two services are the same interface. Nothing else in it is
/// looked at: whether its types resolve, its messages, options and extensions. It is one pass
/// over the section, with a sorted insert per service and method.
pub fn describe(bytes: &[u8]) -> Result<Description, String> {
    let set = FileDescriptorSet::decode(bytes).map_err(|e| format!("the description is not a FileDescriptorSet: {e}"))?;
    let mut interfaces = BTreeMap::new();
    for file in &set.file {
        // Kept once for the file, and shared by its services.
        let package: Arc<str> = Arc::from(file.package());
        for service in &file.service {
            let full = || qualified(&package, service.name());
            let Some(name) = interface_of_service(service.name()) else {
                return Err(format!("service {} does not turn into a valid interface name", full()));
            };
            let mut methods = BTreeMap::new();
            let mut log: Option<&str> = None;
            for method in &service.method {
                if method.client_streaming() {
                    return Err(format!("method {}.{} streams from its caller", full(), method.name()));
                }
                let kind = if method.server_streaming() {
                    if let Some(first) = log {
                        return Err(format!("service {} has two streaming methods, {first} and {}: an interface has at most one log", full(), method.name()));
                    }
                    log = Some(method.name());
                    MethodKind::Log
                } else if method.options.as_ref().is_some_and(|options| options.idempotency_level() == IdempotencyLevel::NoSideEffects) {
                    MethodKind::Question
                } else {
                    MethodKind::Command
                };
                methods.insert(method.name().to_string(), kind);
            }
            if let Some(other) = interfaces.get(&name).map(Interface::service) {
                return Err(format!("services {other} and {} are both the interface {name:?}", full()));
            }
            interfaces.insert(name.clone(), Interface { name, package: package.clone(), local: service.name().to_string(), methods });
        }
    }
    Ok(Description { bytes: bytes.to_vec(), interfaces })
}

/// The check made when an agent is installed: a module with no description is untyped and
/// passes; one with a description must follow the rules (`section`, `describe`), and every
/// interface it describes must be one the manifest provides. Describing fewer is fine: the rest
/// are untyped. This is a check that the two agree, not a permission: the owner may call any
/// interface of an installed agent.
///
/// `found` is what `section` found in the module's verified bytes when it was compiled (see
/// `AgentModule::api`), so that installing a module already compiled reads nothing more.
pub(crate) fn check_install(found: &Result<Option<Vec<u8>>, String>, manifest: &Manifest) -> Result<(), Error> {
    let refused = |why: String| Error::BadModule(format!("{SECTION}: {why}"));
    let bytes = match found {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(()),
        Err(why) => return Err(refused(why.clone())),
    };
    let description = describe(bytes).map_err(refused)?;
    // The names the manifest provides, looked up once each.
    let provided: std::collections::HashSet<&str> = manifest.provides.iter().map(|provide| provide.interface.as_str()).collect();
    for interface in description.interfaces() {
        if !provided.contains(interface.name.as_str()) {
            return Err(refused(format!("it describes the interface {:?} (service {}), which the manifest does not provide", interface.name, interface.service())));
        }
    }
    Ok(())
}

/// Descriptions read, by the content hash of the module they came from, and the modules found
/// to have none (or none that can be used). Bounded: past `CACHE_ENTRIES` the least recently
/// used is let go. A module's content fixes its description, so an entry never goes stale: an
/// agent given a new module has a new hash. Only what was learnt from the module's bytes is
/// kept; a failure to read the bytes is not.
#[derive(Default)]
pub(crate) struct Cache {
    entries: std::collections::HashMap<String, (Option<Arc<Description>>, u64)>,
    clock: u64,
    /// How many descriptions have been read from modules' bytes and finished (built, or found
    /// unusable), for the tests: completed builds, not attempts.
    pub(crate) builds: u64,
}

impl Cache {
    fn get(&mut self, hash: &str) -> Option<Option<Arc<Description>>> {
        self.clock += 1;
        let clock = self.clock;
        self.entries.get_mut(hash).map(|(found, used)| {
            *used = clock;
            found.clone()
        })
    }

    fn put(&mut self, hash: &str, found: Option<Arc<Description>>) {
        self.clock += 1;
        self.entries.insert(hash.to_string(), (found, self.clock));
        while self.entries.len() > CACHE_ENTRIES {
            let oldest = self.entries.iter().min_by_key(|(_, (_, used))| *used).map(|(hash, _)| hash.clone());
            match oldest {
                Some(oldest) => self.entries.remove(&oldest),
                None => break,
            };
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl crate::Inner {
    /// The description of the module with this hash, read once and then kept (see `Cache`).
    /// `None` for a module with no description, or with one that does not follow the rules: a
    /// module that never passed the install check is answered this way. An error, and nothing
    /// kept, when the module's bytes cannot be read.
    pub(crate) fn described(&self, hash: &str) -> Result<Option<Arc<Description>>, Error> {
        if let Some(found) = lock(&self.described).get(hash) {
            return Ok(found);
        }
        // Read with the cache let go: two callers may read the same one at once, and the second
        // to finish replaces the first's, which is the same.
        let module = self.read_blob(hash)?;
        let built = match section(&module, self.cfg.max_api_bytes) {
            Ok(Some(bytes)) => describe(bytes).ok().map(Arc::new),
            _ => None,
        };
        let mut cache = lock(&self.described);
        cache.builds += 1;
        cache.put(hash, built.clone());
        Ok(built)
    }
}

/// How a body, and the reply, are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Proto3 JSON, read and written by the agent.
    Json,
    /// The method's message, encoded.
    Protobuf,
}

impl Encoding {
    /// The media type it goes under.
    pub fn media_type(self) -> &'static str {
        match self {
            Encoding::Json => "application/json",
            Encoding::Protobuf => "application/x-protobuf",
        }
    }
}

/// What a typed call came to: the reply's body as the agent wrote it, or a fault.
#[derive(Debug, PartialEq, Eq)]
pub enum Called {
    Reply(Vec<u8>),
    /// A question's fault, from its reply, or a command's, which the command refused with:
    /// nothing the command did was kept. Its code and message.
    Fault(Fault),
}

/// Why a typed call has no result.
#[derive(Debug)]
pub enum CallError {
    /// The ship has no agent of that name.
    NoSuchAgent,
    /// The agent's module carries no description, or none that follows the rules.
    NoDescription,
    /// The description has no interface of that name.
    NoSuchInterface(String),
    /// The interface has no method of that name to call (its log is not one).
    NoSuchMethod(String),
    /// What the agent answered is not a `CallReply`, has neither a body nor a fault, is a fault
    /// a command answered with instead of refusing (it may have committed), or, asked for JSON,
    /// is not JSON.
    BadReply(String),
    /// Whatever `Runtime::deliver_on` or `Runtime::read` returned, and a ship that does not
    /// exist, a name that is not valid, or a module whose bytes cannot be read.
    Runtime(Error),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::NoSuchAgent => write!(f, "no such agent"),
            CallError::NoDescription => write!(f, "the agent does not describe its interfaces"),
            CallError::NoSuchInterface(name) => write!(f, "the agent describes no interface {name:?}"),
            CallError::NoSuchMethod(name) => write!(f, "the interface has no method {name:?}"),
            CallError::BadReply(why) => write!(f, "the agent's reply is not what a typed call answers: {why}"),
            CallError::Runtime(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CallError {}

impl From<Error> for CallError {
    fn from(error: Error) -> Self {
        match error {
            Error::UnknownAgent(_) => CallError::NoSuchAgent,
            other => CallError::Runtime(other),
        }
    }
}

/// Whether bytes are UTF-8 text that is JSON. Valid UTF-8 is checked first, over the whole
/// body, since skipping a value does not look inside its strings.
fn is_json(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok())
}

impl Runtime {
    /// The description an agent's module carries (kept: see `Cache`). `Ok(None)` for an agent
    /// whose module has none, or none that follows the rules. `Error::UnknownAgent` for an agent
    /// that is not installed. The agent's module is the one the kernel names when it routes an
    /// owner's command to it, in a transaction that is rolled back; getting the ship can wait for
    /// its lock, wake it, run its usual upkeep on waking, and compile a module not yet compiled.
    pub fn description(&self, ship: &str, agent: &str) -> Result<Option<Arc<Description>>, Error> {
        check_agent_name(agent)?;
        let hash = self.inner.with_ship(ship, |ship| ship.module_of(&self.inner, agent))?;
        let Some(hash) = hash else { return Err(Error::UnknownAgent(agent.to_string())) };
        self.inner.described(&hash)
    }

    /// Call one method of an agent's described interface as the ship's owner. The body goes to
    /// the agent untouched, in a `Call` saying whether it is proto3 JSON; the agent's generated
    /// code reads it and writes the reply in the same form. The method's kind, from the
    /// description, says how it runs: a command as an owner command under the interface
    /// (`deliver_on`), with what is queued after it; a question as an owner read (`read`), which
    /// keeps nothing.
    ///
    /// The kind is read from the module the agent has when the call is looked up. If the agent's
    /// module is replaced before the call runs, the new module's generated dispatch decides: a
    /// method of another kind there is refused (`ship.wrong-kind`), and one it lacks too.
    ///
    /// A question's fault comes back from its reply. A command produces `Called::Fault` when
    /// `deliver_on` returns `Rejection::Refused`: nothing the command did is kept. An invalid
    /// refusal code produces `CallError::Runtime`. A command that answers with a fault in its
    /// `CallReply` without refusing (no generated code does) is `CallError::BadReply`, since it
    /// may already have committed.
    pub fn call_method(&self, ship: &str, agent: &str, interface: &str, method: &str, body: &[u8], encoding: Encoding) -> Result<Called, CallError> {
        check_target(agent, interface).map_err(CallError::Runtime)?;
        let description = self.description(ship, agent)?.ok_or(CallError::NoDescription)?;
        let described = description.interface(interface).ok_or_else(|| CallError::NoSuchInterface(interface.to_string()))?;
        let kind = described.methods.get(method).copied().filter(|kind| *kind != MethodKind::Log).ok_or_else(|| CallError::NoSuchMethod(method.to_string()))?;
        #[cfg(test)]
        self.inner.gates.pass("typed call looked up");
        let call = Call { method: method.to_string(), body: body.to_vec(), json: encoding == Encoding::Json }.encode_to_vec();
        let reply = match kind {
            MethodKind::Command => match self.deliver_on(ship, agent, interface, &call) {
                Ok(outcome) => outcome.reply,
                Err(Error::Rejected(crate::Rejection::Refused(fault))) => return Ok(Called::Fault(fault)),
                Err(error) => return Err(error.into()),
            },
            _ => self.read(ship, agent, interface, &call)?,
        };
        let reply = CallReply::decode(&*reply).map_err(|e| CallError::BadReply(format!("it is not a CallReply: {e}")))?;
        match reply.result {
            Some(Replied::Body(body)) if encoding == Encoding::Json && !is_json(&body) => Err(CallError::BadReply("JSON was asked for, and the reply's body is not JSON".into())),
            Some(Replied::Body(body)) => Ok(Called::Reply(body)),
            Some(Replied::Fault(fault)) if kind == MethodKind::Command => Err(CallError::BadReply(format!("a command answered with a fault ({}), after it may have committed", fault.code))),
            Some(Replied::Fault(fault)) => Ok(Called::Fault(fault)),
            None => Err(CallError::BadReply("it is a CallReply with neither a body nor a fault".into())),
        }
    }

    /// How many modules' descriptions (or lack of one) are kept now.
    pub fn described_modules(&self) -> usize {
        lock(&self.inner.described).len()
    }
}

/// An answer at the JSON door, before the server dresses it.
pub(crate) struct Answer {
    pub status: u16,
    pub kind: &'static str,
    pub body: Vec<u8>,
}

impl Answer {
    fn text(status: u16, words: &str) -> Answer {
        Answer { status, kind: "text/plain; charset=utf-8", body: words.as_bytes().to_vec() }
    }
}

/// The encoding a request's media type names, ignoring its parameters and capitals.
pub(crate) fn encoding_of(media_type: Option<&str>) -> Option<Encoding> {
    let named = media_type?.split(';').next()?.trim();
    if named.eq_ignore_ascii_case("application/json") {
        Some(Encoding::Json)
    } else if named.eq_ignore_ascii_case("application/x-protobuf") {
        Some(Encoding::Protobuf)
    } else {
        None
    }
}

/// The status a fault is answered with at the door. The door selects the HTTP status from the
/// fault code for both questions and refused commands.
pub(crate) fn fault_status(code: &str) -> u16 {
    match code {
        "ship.not-understood" => 400,
        "ship.no-such-interface" | "ship.no-such-method" => 404,
        // The method's kind was read from one module and the call ran on another (see
        // `Runtime::call_method`), or the description disagrees with the code it came with.
        "ship.wrong-kind" => 409,
        _ => 422,
    }
}

/// What a typed call's failure looks like at the door. `Err` for what `deliver` and `read`
/// return, which the server answers as it answers its command route.
fn door_failure(failed: CallError) -> Result<Answer, Error> {
    Ok(match failed {
        CallError::NoSuchAgent => Answer::text(404, "no such agent"),
        CallError::NoDescription => Answer::text(404, "this agent does not describe its interfaces"),
        CallError::NoSuchInterface(_) => Answer::text(404, "this agent describes no such interface"),
        CallError::NoSuchMethod(_) => Answer::text(404, "this interface has no such method"),
        CallError::BadReply(_) => Answer::text(502, "the agent's reply is not what a typed call answers"),
        CallError::Runtime(error) => return Err(error),
    })
}

/// `GET /agents/<agent>/api`: the description, byte for byte.
pub(crate) fn door_describe(runtime: &Runtime, ship: &str, agent: &str) -> Result<Answer, Error> {
    match runtime.description(ship, agent) {
        Ok(Some(description)) => Ok(Answer { status: 200, kind: "application/x-protobuf", body: description.bytes().to_vec() }),
        Ok(None) => door_failure(CallError::NoDescription),
        Err(error) => door_failure(error.into()),
    }
}

/// `POST /agents/<agent>/api/<interface>/<method>`: the method called as the owner. The body is
/// passed on untouched; the agent's own decoder is the only judge of it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn door_call(runtime: &Runtime, ship: &str, agent: &str, interface: &str, method: &str, media_type: Option<&str>, body: &[u8]) -> Result<Answer, Error> {
    let Some(encoding) = encoding_of(media_type) else {
        return Ok(Answer::text(415, "send the body as application/json or application/x-protobuf"));
    };
    match runtime.call_method(ship, agent, interface, method, body, encoding) {
        Ok(Called::Reply(body)) => Ok(Answer { status: 200, kind: encoding.media_type(), body }),
        Ok(Called::Fault(fault)) => {
            let body = match encoding {
                Encoding::Json => serde_json::to_vec(&serde_json::json!({ "code": fault.code, "message": fault.message })).unwrap_or_default(),
                Encoding::Protobuf => fault.encode_to_vec(),
            };
            Ok(Answer { status: fault_status(&fault.code), kind: encoding.media_type(), body })
        }
        Err(failed) => door_failure(failed),
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
