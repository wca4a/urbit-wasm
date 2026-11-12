//! The kernel: the ship's policy. It keeps the registry of installed agents and their manifests,
//! and decides for every call whether it may go ahead and with what permissions. The runtime
//! enforces what the kernel decides; the kernel itself can do nothing but read and write its
//! own keys.

use ship_proto::admin_request::Op;
use ship_proto::{
    AdminReply, AdminRequest, Grant, Install, Kind, Message, Provide, Registered, Registry, RouteReply,
    RouteRequest, Use,
};
use ship_sdk::kv;

const REGISTRY: &[u8] = b"registry";
const MAX_AGENTS: usize = 256;
const MAX_MANIFEST_ENTRIES: usize = 64;
/// Limits on what the kernel stores and on any one answer to the runtime, so that an install
/// which is accepted can never leave the ship unable to route.
const MAX_REGISTRY_BYTES: usize = 512 << 10;
const MAX_ROUTE_BYTES: usize = 256 << 10;

fn load() -> Registry {
    match kv::get(REGISTRY) {
        // Failing loudly beats treating a damaged registry as empty and then overwriting it.
        Some(bytes) => Registry::decode(&*bytes).expect("the agent registry is damaged"),
        None => Registry::default(),
    }
}

fn provides(agent: &Registered) -> &[Provide] {
    agent.manifest.as_ref().map_or(&[], |manifest| &manifest.provides)
}

fn uses(agent: &Registered) -> &[Use] {
    agent.manifest.as_ref().map_or(&[], |manifest| &manifest.uses)
}

/// Whether a manifest declares a use of an agent on this ship. A use that names another ship
/// is about that ship's agent, and says nothing about a local agent of the same name.
fn declares(uses: &[Use], agent: &str, interface: &str, wants: fn(&Use) -> bool) -> bool {
    uses.iter().any(|u| u.ship.is_empty() && u.agent == agent && u.interface == interface && wants(u))
}

/// Everything `agent` may use: its own interfaces, and each interface another agent provides
/// that is either public or declared in `agent`'s manifest.
fn grants(registry: &Registry, agent: &Registered, wants: fn(&Use) -> bool) -> Vec<Grant> {
    let mut out = Vec::new();
    for other in &registry.agents {
        let own = other.name == agent.name;
        for provide in provides(other) {
            if own || provide.public || declares(uses(agent), &other.name, &provide.interface, wants) {
                out.push(Grant { agent: other.name.clone(), interface: provide.interface.clone(), ship: String::new() });
            }
        }
    }
    out
}

/// What `agent` may send to agents on other ships: exactly what its manifest declares. Nothing
/// on another ship is reachable without being named there, and the owner approved the
/// manifest at install.
fn remote_sends(agent: &Registered) -> Vec<Grant> {
    let declared = uses(agent).iter().filter(|u| !u.ship.is_empty() && u.send);
    declared.map(|u| Grant { agent: u.agent.clone(), interface: u.interface.clone(), ship: u.ship.clone() }).collect()
}

/// The logs on other ships that `agent` may follow: exactly what its manifest declares, in the
/// same way.
fn remote_reads(agent: &Registered) -> Vec<Grant> {
    let declared = uses(agent).iter().filter(|u| !u.ship.is_empty() && u.read);
    declared.map(|u| Grant { agent: u.agent.clone(), interface: u.interface.clone(), ship: u.ship.clone() }).collect()
}

/// More than the encoded size of one grant, so sums of it are safe upper bounds.
fn grant_bytes(agent: &str, interface: &str) -> usize {
    agent.len() + interface.len() + 16
}

/// An upper bound on the largest answer `route` could give for any agent in `registry`. Each
/// agent is granted every public interface, its own, and at most what it declares, once for
/// reading and once for sending.
fn largest_route(registry: &Registry) -> usize {
    let public: usize = registry
        .agents
        .iter()
        .flat_map(|agent| provides(agent).iter().filter(|p| p.public).map(|p| grant_bytes(&agent.name, &p.interface)))
        .sum();
    let most_private = registry
        .agents
        .iter()
        .map(|agent| {
            let own: usize = provides(agent).iter().map(|p| grant_bytes(&agent.name, &p.interface)).sum();
            let declared: usize = uses(agent).iter().map(|u| grant_bytes(&u.agent, &u.interface) + u.ship.len() + 2).sum();
            own + declared
        })
        .max()
        .unwrap_or(0);
    2 * (public + most_private) + 256
}

fn deny(reason: impl Into<String>) -> RouteReply {
    RouteReply { allowed: false, reason: reason.into(), ..Default::default() }
}

fn decide(request: &RouteRequest) -> RouteReply {
    let registry = load();
    let Some(target) = registry.agents.iter().find(|a| a.name == request.agent) else {
        return deny(format!("no agent named {}", request.agent));
    };
    let source = request.source.clone().unwrap_or_default();
    // The runtime tells an agent what became of a command it sent to another ship. The
    // runtime keeps a record of each such command and only passes on an answer to one of
    // them, so there is nothing to decide here beyond the agent still being installed.
    if request.kind() == Kind::Receipt {
        return allow(&registry, target);
    }
    // The runtime tells an agent that a log it follows on another ship has entries for it.
    // The agent must still be allowed to follow that log: its manifest names that ship, or
    // any ship, with that agent and log.
    if !source.ship.is_empty() && request.kind() == Kind::Notify {
        let declared = uses(target).iter().any(|u| {
            (u.ship == source.ship || u.ship == "*") && u.agent == source.agent && u.interface == request.interface && u.read
        });
        if source.owner || !declared {
            return deny(format!("{} does not follow {} on {} on another ship", target.name, request.interface, source.agent));
        }
        return allow(&registry, target);
    }
    // A request from an agent on another ship. Only a command, and only to an interface that
    // is open to other ships. Which ships may do what is then up to the agent, which is told
    // who is asking. Nothing is known here about the other ship's agents, so nothing is
    // looked up about the one that sent it.
    if !source.ship.is_empty() {
        let open = request.kind() == Kind::Command
            && !source.owner
            && provides(target).iter().any(|provide| provide.interface == request.interface && provide.remote);
        if !open {
            return deny(format!("{} on {} is not open to other ships", request.interface, target.name));
        }
        return allow(&registry, target);
    }
    let wants: fn(&Use) -> bool = match request.kind() {
        Kind::Command => |u| u.send,
        Kind::Read => |u| u.read,
        // A notification goes from a log's publisher to one of its followers, so the question
        // is the other way round: may the receiver read that interface of the sender?
        Kind::Notify => {
            let publisher = registry.agents.iter().find(|a| a.name == source.agent);
            let allowed = publisher.is_some_and(|publisher| {
                provides(publisher).iter().find(|p| p.interface == request.interface).is_some_and(|provide| {
                    provide.public
                        || publisher.name == target.name
                        || declares(uses(target), &publisher.name, &request.interface, |u| u.read)
                })
            });
            if !allowed {
                return deny(format!("{} does not follow {} on {}", target.name, request.interface, source.agent));
            }
            return allow(&registry, target);
        }
        // The runtime asks an agent about one of its own logs.
        Kind::Checkpoint => {
            let own = source.owner || source.agent == target.name;
            if !own || !provides(target).iter().any(|p| p.interface == request.interface) {
                return deny(format!("{} has no log named {}", target.name, request.interface));
            }
            return allow(&registry, target);
        }
        // An unrecognised kind must be refused, never treated as something harmless.
        // (A receipt was answered above.)
        Kind::Receipt | Kind::Unspecified => return deny("unknown kind of call"),
    };
    // The owner may call anything on their own ship. An agent needs the target to provide the
    // interface, and needs it to be public, its own, or a declared use.
    if !source.owner {
        let Some(caller) = registry.agents.iter().find(|a| a.name == source.agent) else {
            return deny(format!("no agent named {}", source.agent));
        };
        let allowed = provides(target).iter().find(|p| p.interface == request.interface).is_some_and(|provide| {
            provide.public
                || caller.name == target.name
                || declares(uses(caller), &target.name, &request.interface, wants)
        });
        if !allowed {
            return deny(format!("{} may not use {} on {}", caller.name, request.interface, target.name));
        }
    }
    allow(&registry, target)
}

fn allow(registry: &Registry, target: &Registered) -> RouteReply {
    RouteReply {
        allowed: true,
        reason: String::new(),
        module: target.module.clone(),
        reads: grants(registry, target, |u| u.read).into_iter().chain(remote_reads(target)).collect(),
        sends: grants(registry, target, |u| u.send).into_iter().chain(remote_sends(target)).collect(),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_lowercase()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}

/// Where a use points: this ship (empty), any ship ("*"), or one ship by name.
fn valid_ship(name: &str) -> bool {
    let named = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    name.is_empty() || name == "*" || named
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True if any item appears more than once.
fn repeats<T: Ord>(mut items: Vec<T>) -> bool {
    let before = items.len();
    items.sort_unstable();
    items.dedup();
    items.len() != before
}

fn install(install: Install) -> Result<(), String> {
    // The kernel's own keys live under this name.
    if !valid_name(&install.agent) || install.agent == "kernel" {
        return Err(format!("invalid agent name {:?}", install.agent));
    }
    if !valid_hash(&install.module) {
        return Err("invalid module hash".into());
    }
    let manifest = install.manifest.unwrap_or_default();
    if manifest.provides.len() > MAX_MANIFEST_ENTRIES || manifest.uses.len() > MAX_MANIFEST_ENTRIES {
        return Err("manifest has too many entries".into());
    }
    let names_ok = manifest.provides.iter().all(|p| valid_interface(&p.interface))
        && manifest.uses.iter().all(|u| valid_name(&u.agent) && valid_interface(&u.interface) && valid_ship(&u.ship));
    if !names_ok {
        return Err("manifest contains an invalid name".into());
    }
    // Two entries for the same thing could disagree, for example private and public.
    if repeats(manifest.provides.iter().map(|p| &p.interface).collect())
        || repeats(manifest.uses.iter().map(|u| (&u.ship, &u.agent, &u.interface)).collect())
    {
        return Err("manifest lists the same interface twice".into());
    }

    let mut registry = load();
    let entry = Registered { name: install.agent, module: install.module, manifest: Some(manifest) };
    match registry.agents.iter().position(|a| a.name == entry.name) {
        Some(index) => registry.agents[index] = entry,
        None if registry.agents.len() >= MAX_AGENTS => return Err("too many agents on this ship".into()),
        None => registry.agents.push(entry),
    }
    if registry.encoded_len() > MAX_REGISTRY_BYTES || largest_route(&registry) > MAX_ROUTE_BYTES {
        return Err("too many agents and interfaces on this ship".into());
    }
    kv::put(REGISTRY, &registry.encode_to_vec());
    Ok(())
}

fn route(input: &[u8]) -> Vec<u8> {
    let reply = match RouteRequest::decode(input) {
        Ok(request) => decide(&request),
        Err(_) => deny("malformed route request"),
    };
    reply.encode_to_vec()
}

fn admin(input: &[u8]) -> Vec<u8> {
    let refuse = |error: String| AdminReply { ok: false, error, ..Default::default() };
    let reply = match AdminRequest::decode(input).map(|request| request.op) {
        Ok(Some(Op::Install(request))) => match install(request) {
            Ok(()) => AdminReply { ok: true, ..Default::default() },
            Err(error) => refuse(error),
        },
        Ok(Some(Op::ListModules(_))) => {
            let mut modules: Vec<String> = load().agents.into_iter().map(|a| a.module).collect();
            modules.sort();
            modules.dedup();
            AdminReply { ok: true, modules, ..Default::default() }
        }
        Ok(None) => refuse("unknown admin request".into()),
        Err(_) => refuse("malformed admin request".into()),
    };
    reply.encode_to_vec()
}

ship_sdk::export_alloc!();
ship_sdk::export_fn!("route", route);
ship_sdk::export_fn!("admin", admin);
