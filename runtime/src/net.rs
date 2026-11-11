//! How ships reach each other: an encrypted link in which each end has proved who it is.
//!
//! Two ships talk over QUIC, which is encrypted and runs over UDP. There is no certificate
//! authority. Each ship has a key, and a directory says which key belongs to which ship and
//! where that ship can be reached. When a connection is made, each end shows its key and
//! proves it holds the private half by signing with it, and the other end checks that key
//! against the directory: the caller checks it reached the ship it meant to, and the ship
//! called learns which ship is calling.
//!
//! What is sent, and the keys each end shows, are encrypted. Someone watching the network
//! still sees which ship is being called, that this protocol is in use, the addresses at each
//! end, and how much is sent and when.
//!
//! One runtime has one address for all the ships it holds, and answers as whichever of them
//! the caller names. Two ships in the same runtime talk this way too.
//!
//! The directory here is a fixed list handed in by whoever starts the network. In time it
//! will be Urbit ID: names, keys, and sponsors from Azimuth. A ship's own key does not change
//! while its runtime runs.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, IdleTimeout, Incoming, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::crypto::{verify_tls13_signature_with_raw_key, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use ship_proto::{peer_reply, peer_request, Message, PeerReply, PeerRequest, Ping, Pong};
use tokio::sync::Semaphore;

use crate::{canonical_ship, lock, Error, Runtime};

/// The name of this protocol, agreed while connecting. A connection that does not ask for it
/// is not one of ours.
const PROTOCOL: &[u8] = b"ship/1";

/// The longest any time limit here may be set to.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

/// What the directory knows about a ship: its key and where to reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub key: [u8; 32],
    pub addr: SocketAddr,
}

/// Which key belongs to which ship, and where each ship is. A stand-in for Urbit ID.
#[derive(Default)]
pub struct Directory {
    peers: RwLock<HashMap<String, Peer>>,
}

impl fmt::Debug for Directory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Directory")
    }
}

impl Directory {
    pub fn new() -> Arc<Directory> {
        Arc::new(Directory::default())
    }

    /// List a ship, or change what is listed for it. A key can stand for only one ship: a
    /// caller is recognised by its key alone, so two ships with one key could not be told apart.
    pub fn set(&self, ship: &str, key: [u8; 32], addr: SocketAddr) -> Result<(), Error> {
        let name = canonical_ship(ship)?;
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        if peers.iter().any(|(other, peer)| *other != name && peer.key == key) {
            return Err(Error::InvalidName(format!("{name}: its key is already listed for another ship")));
        }
        peers.insert(name, Peer { key, addr });
        Ok(())
    }

    pub fn remove(&self, ship: &str) {
        if let Ok(name) = canonical_ship(ship) {
            self.peers.write().unwrap_or_else(|e| e.into_inner()).remove(&name);
        }
    }

    pub fn lookup(&self, ship: &str) -> Option<Peer> {
        let name = canonical_ship(ship).ok()?;
        self.peers.read().unwrap_or_else(|e| e.into_inner()).get(&name).copied()
    }

    /// The ship a key is listed for, if any.
    pub fn who(&self, key: &[u8; 32]) -> Option<String> {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        peers.iter().find(|(_, peer)| peer.key == *key).map(|(name, _)| name.clone())
    }
}

#[derive(Clone, Debug)]
pub struct NetConfig {
    /// The UDP address to listen on, such as `0.0.0.0:4433`. Port 0 picks a free one.
    pub addr: String,
    /// How long one request to another ship may take, connecting included.
    pub request_timeout: Duration,
    /// A connection with nothing on it for this long is closed.
    pub idle_timeout: Duration,
    /// How many connections from other ships may be open at once, counting those still being
    /// set up. More are turned away. A calling ship has one connection to each ship it calls
    /// here; a newer one from the same ship replaces the older.
    pub max_connections: usize,
    /// How many other ships this runtime's ships may have connections to at once.
    pub max_calls: usize,
    /// How many requests one connection from another ship may have in progress at once.
    pub max_streams: u32,
    /// The largest request or reply this runtime will take from another ship.
    pub max_message_bytes: usize,
    /// Room for the requests being read from other ships at any moment, all connections
    /// together. Each request being read holds room for the largest it could be, so this over
    /// `max_message_bytes` is how many are read at once. Past that, a request is told to try
    /// again.
    pub max_reading_bytes: usize,
    /// How many requests this runtime's ships may have out to other ships at once. Each may be
    /// holding a reply as large as `max_message_bytes`. Past this, a new request fails at once.
    pub max_requests: usize,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            addr: "127.0.0.1:0".into(),
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            max_connections: 1024,
            max_calls: 1024,
            max_streams: 8,
            max_message_bytes: 1 << 20,
            max_reading_bytes: 64 << 20,
            max_requests: 64,
        }
    }
}

/// Why a request to another ship did not get an answer.
#[derive(Debug)]
pub enum NetError {
    /// The ship asking is not one this runtime holds.
    NotHere(String),
    /// The directory does not list the ship being called.
    Unlisted(String),
    /// No connection could be made, or it was lost. This includes the other end failing to
    /// prove it is the ship that was called.
    Unreachable(String),
    /// The other ship would not answer the request.
    Refused(String),
    /// No answer in the time allowed.
    TimedOut,
    /// The other ship answered with something that makes no sense.
    Garbled,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::NotHere(ship) => write!(f, "{ship} is not a ship on this runtime"),
            NetError::Unlisted(ship) => write!(f, "{ship} is not listed in the directory"),
            NetError::Unreachable(why) => write!(f, "could not reach the ship: {why}"),
            NetError::Refused(why) => write!(f, "the ship refused: {why}"),
            NetError::TimedOut => write!(f, "the ship did not answer in time"),
            NetError::Garbled => write!(f, "the ship's answer made no sense"),
        }
    }
}

impl std::error::Error for NetError {}

/// What came of asking a ship who it is.
#[derive(Debug, PartialEq, Eq)]
pub struct Answered {
    /// The ship that answered. This is known for certain: it is the ship that was called, and
    /// the other end proved it holds the key the directory lists for that ship.
    pub ship: String,
    /// The ship the answerer says it was shown proof of at this end. This is its word, and
    /// cannot be checked from here. An honest ship gives the name the directory lists for the
    /// caller's key.
    pub seen_as: String,
    pub took: Duration,
}

/// A runtime's presence on the network. Dropping it closes every connection.
///
/// Its calls wait for an answer, so they are for ordinary threads. Called from inside async
/// code they still work, but hold up that code's thread while they wait.
pub struct Network {
    shared: Arc<Shared>,
    threads: Threads,
}

/// The threads the network runs on. Letting go of them never waits, so it is safe wherever it
/// happens: in ordinary code, inside async code, or part way through a start that failed.
struct Threads(Option<tokio::runtime::Runtime>);

impl Threads {
    fn get(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("held until dropped")
    }
}

impl Drop for Threads {
    fn drop(&mut self) {
        if let Some(tokio) = self.0.take() {
            tokio.shutdown_background();
        }
    }
}

/// A connection this runtime made, with what it was made against. It is good for as long as
/// those still hold.
struct Made {
    connection: Connection,
    /// What the directory listed for the ship called.
    peer: Peer,
    /// The key the calling ship showed.
    shown: [u8; 32],
}

type Pair = (String, String);

struct Shared {
    runtime: Arc<Runtime>,
    directory: Arc<Directory>,
    cfg: NetConfig,
    endpoint: Endpoint,
    provider: Arc<CryptoProvider>,
    /// Connections this runtime has made, by (calling ship, called ship). Each pair has a
    /// lock of its own, held while its connection is being made, so that two calls to one
    /// ship share one connection and a slow ship holds up only calls to itself.
    made: Mutex<HashMap<Pair, Arc<tokio::sync::Mutex<Option<Made>>>>>,
    /// Connections from other ships, counting those still being set up.
    taken: AtomicUsize,
    /// The newest connection from each (calling ship, called ship).
    callers: Mutex<HashMap<Pair, Connection>>,
    /// Room left for requests being read. See `NetConfig::max_reading_bytes`.
    reading: Arc<Semaphore>,
    /// Requests this runtime may still send. See `NetConfig::max_requests`.
    asking: Arc<Semaphore>,
}

impl Network {
    pub fn start(runtime: Arc<Runtime>, directory: Arc<Directory>, cfg: NetConfig) -> io::Result<Network> {
        let addr: SocketAddr = cfg.addr.parse().map_err(|_| io::Error::other("not an address to listen on"))?;
        if cfg.max_message_bytes == 0 || cfg.max_message_bytes > u32::MAX as usize || cfg.max_reading_bytes < cfg.max_message_bytes {
            return Err(io::Error::other("max_reading_bytes must have room for at least one message"));
        }
        if cfg.max_reading_bytes > Semaphore::MAX_PERMITS || cfg.max_requests == 0 || cfg.max_requests > Semaphore::MAX_PERMITS {
            return Err(io::Error::other("max_reading_bytes or max_requests is out of range"));
        }
        // A time limit has to be one a clock can keep. Far beyond a day it is no limit at all,
        // and near the largest a clock can hold, working out when it ends goes wrong.
        if cfg.request_timeout.is_zero() || cfg.request_timeout > MAX_TIMEOUT || cfg.idle_timeout.is_zero() || cfg.idle_timeout > MAX_TIMEOUT {
            return Err(io::Error::other("request_timeout and idle_timeout must be more than nothing and at most a day"));
        }
        // The ships' keys are read into memory now, and never from inside a connection being
        // made. If they cannot be read, there is no network.
        runtime.load_identities().map_err(io::Error::other)?;
        let threads = Threads(Some(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("ship-net").build()?));
        let tokio = threads.get();
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // The side that answers: it shows the key of whichever ship was asked for, and wants
        // proof of a key the directory lists.
        let mut answering = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_client_cert_verifier(Arc::new(ListedCallers { directory: directory.clone(), supported: provider.signature_verification_algorithms }))
            .with_cert_resolver(Arc::new(ShipKeys { runtime: runtime.clone(), provider: provider.clone() }));
        answering.alpn_protocols = vec![PROTOCOL.to_vec()];
        // Every connection proves its keys afresh. None picks up where an earlier one left off.
        answering.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        answering.send_tls13_tickets = 0;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(answering).map_err(io::Error::other)?));
        server.transport_config(Arc::new(transport(&cfg, cfg.max_streams)?));
        // A ship stays where it was first reached: a connection does not follow a caller that
        // turns up at a new address.
        server.migration(false);
        // Connections waiting for this runtime to decide whether to take them.
        server.max_incoming(256);

        let endpoint = {
            let _entered = tokio.enter();
            Endpoint::server(server, addr)?
        };
        let reading = Arc::new(Semaphore::new(cfg.max_reading_bytes));
        let asking = Arc::new(Semaphore::new(cfg.max_requests));
        let shared = Arc::new(Shared {
            runtime,
            directory,
            cfg,
            endpoint,
            provider,
            made: Mutex::new(HashMap::new()),
            taken: AtomicUsize::new(0),
            callers: Mutex::new(HashMap::new()),
            reading,
            asking,
        });
        tokio.spawn(answer_calls(shared.clone()));
        Ok(Network { shared, threads })
    }

    /// The address other ships reach this runtime at.
    pub fn addr(&self) -> SocketAddr {
        self.shared.endpoint.local_addr().expect("the endpoint is bound")
    }

    /// How many connections are open, made or taken.
    pub fn open_connections(&self) -> usize {
        self.shared.endpoint.open_connections()
    }

    /// From one of this runtime's ships, ask another ship who it is. An answer means this end
    /// was shown proof of the key the directory lists for the ship called, so it is that ship.
    /// The answer also carries who that ship says is calling.
    pub fn ping(&self, from: &str, to: &str) -> Result<Answered, NetError> {
        let started = Instant::now();
        let nonce = crate::store::now_ms().to_le_bytes().to_vec();
        let asked = PeerRequest { body: Some(peer_request::Body::Ping(Ping { nonce: nonce.clone() })) };
        match self.ask(from, to, asked)?.body {
            Some(peer_reply::Body::Pong(Pong { nonce: echoed, caller, .. })) if echoed == nonce => {
                let ship = canonical_ship(to).map_err(|_| NetError::Garbled)?;
                Ok(Answered { ship, seen_as: caller, took: started.elapsed() })
            }
            _ => Err(NetError::Garbled),
        }
    }

    /// Send one request from one of this runtime's ships to another ship and wait for its reply.
    fn ask(&self, from: &str, to: &str, request: PeerRequest) -> Result<PeerReply, NetError> {
        let shared = self.shared.clone();
        let (from, to) = (from.to_string(), to.to_string());
        // Each request out may be holding a whole reply, so only so many go out at once.
        let Ok(turn) = shared.asking.clone().try_acquire_owned() else {
            return Err(NetError::Unreachable("this runtime already has as many requests out as it may".into()));
        };
        // Handed to the network's own threads and waited for here. Unlike running it in
        // place, this is safe wherever it is called from.
        let (report, outcome) = std::sync::mpsc::channel();
        self.threads.get().spawn(async move {
            let answer = shared.ask(&from, &to, request).await;
            // Given up before the caller hears, so that its very next request finds it free.
            drop(turn);
            let _ = report.send(answer);
        });
        outcome.recv().unwrap_or_else(|_| Err(NetError::Unreachable("the network has stopped".into())))
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.shared.endpoint.close(VarInt::from_u32(0), b"stopping");
        // Give the goodbyes a moment to go out, so the ships at the other end know at once and
        // do not hold a dead connection until it times out. Only a moment: a ship that is not
        // listening must not be able to keep this one from stopping. The threads themselves
        // are let go of straight after, without waiting.
        let (done, waited) = std::sync::mpsc::channel();
        let endpoint = self.shared.endpoint.clone();
        self.threads.get().spawn(async move {
            endpoint.wait_idle().await;
            let _ = done.send(());
        });
        let _ = waited.recv_timeout(Duration::from_millis(500));
    }
}

/// How a connection carries data. `streams` is how many requests the other end may have in
/// progress on it at once.
fn transport(cfg: &NetConfig, streams: u32) -> io::Result<TransportConfig> {
    // The other end may send this much on one stream before this end has read any of it: a
    // whole message, or a small fixed amount where messages are smaller than that. How large
    // a message is taken is checked separately, as it is read.
    let stream_room = cfg.max_message_bytes.clamp(16 << 10, u32::MAX as usize) as u64;
    let room = |bytes: u64| VarInt::from_u64(bytes).map_err(io::Error::other);
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(VarInt::from_u32(streams));
    // Everything is a request and its reply on one stream. Nothing else is taken.
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    transport.datagram_receive_buffer_size(None);
    transport.stream_receive_window(room(stream_room)?);
    transport.receive_window(room(stream_room.saturating_mul(u64::from(streams.max(1))))?);
    transport.max_idle_timeout(Some(IdleTimeout::try_from(cfg.idle_timeout).map_err(io::Error::other)?));
    Ok(transport)
}

/// The public half of an ed25519 key, in the wrapping TLS carries bare keys in.
fn wrapped(key: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    [&PREFIX[..], key].concat()
}

/// The key inside that wrapping, if it is an ed25519 key and nothing else.
fn unwrapped(wrapped_key: &[u8]) -> Option<[u8; 32]> {
    let key = <[u8; 32]>::try_from(wrapped_key.get(12..)?).ok()?;
    (wrapped(&key) == wrapped_key).then_some(key)
}

/// What a ship shows to prove who it is: its public key, and the means to sign with the
/// private half. The private half stays in this process.
fn proof(key: &ed25519_dalek::SigningKey, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, rustls::Error> {
    // The private key in the standard wrapping (PKCS#8 version 2) the TLS library reads.
    let mut der = vec![0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&key.to_bytes());
    der.extend_from_slice(&[0x81, 0x21, 0x00]);
    der.extend_from_slice(&key.verifying_key().to_bytes());
    let signer = provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(der).into())?;
    let shown = CertificateDer::from(wrapped(&key.verifying_key().to_bytes()));
    Ok(Arc::new(CertifiedKey::new(vec![shown], signer)))
}

/// Whether the other end signed the connection's handshake with the key it showed. Showing a
/// key proves nothing, since public keys are public; signing with it is the proof.
fn signed_with(
    shown: &CertificateDer<'_>,
    message: &[u8],
    signed: &DigitallySignedStruct,
    supported: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    verify_tls13_signature_with_raw_key(message, &SubjectPublicKeyInfoDer::from(shown.as_ref()), signed, supported)
}

fn refuse(why: &str) -> rustls::Error {
    rustls::Error::General(why.to_string())
}

/// For the side that answers: which key to show. It is the key of the ship the caller asked
/// for, if this runtime holds that ship. Keys are held in memory, so this never waits on disk.
struct ShipKeys {
    runtime: Arc<Runtime>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for ShipKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShipKeys")
    }
}

impl ResolvesServerCert for ShipKeys {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let key = self.runtime.signing_key(hello.server_name()?).ok()?;
        proof(&key, &self.provider).ok()
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// For the side that answers: whether a caller's key is one the directory lists.
#[derive(Debug)]
struct ListedCallers {
    directory: Arc<Directory>,
    supported: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for ListedCallers {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, shown: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        let key = unwrapped(shown.as_ref()).ok_or_else(|| refuse("the caller did not show a ship's key"))?;
        match self.directory.who(&key) {
            Some(_) => Ok(ClientCertVerified::assertion()),
            None => Err(refuse("the caller's key is not listed for any ship")),
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refuse("only TLS 1.3 is spoken"))
    }

    fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed_with(shown, message, signed, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// For the side that calls: whether the ship that answered showed the key listed for the ship
/// that was called.
#[derive(Debug)]
struct ListedKey {
    expected: Vec<u8>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ListedKey {
    fn verify_server_cert(
        &self,
        shown: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if shown.as_ref() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refuse("the ship that answered did not show the key listed for the ship that was called"))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refuse("only TLS 1.3 is spoken"))
    }

    fn verify_tls13_signature(&self, message: &[u8], shown: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        signed_with(shown, message, signed, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl Shared {
    /// Send one request and read its reply, over a connection made for this pair of ships,
    /// all within the time allowed for a request.
    async fn ask(&self, from: &str, to: &str, request: PeerRequest) -> Result<PeerReply, NetError> {
        let from = canonical_ship(from).map_err(|_| NetError::NotHere(from.to_string()))?;
        let to = canonical_ship(to).map_err(|_| NetError::Unlisted(to.to_string()))?;
        let deadline = tokio::time::Instant::now().checked_add(self.cfg.request_timeout).ok_or(NetError::TimedOut)?;
        let lost = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        let connection = tokio::time::timeout_at(deadline, self.connection(&from, &to)).await.map_err(|_| NetError::TimedOut)??;
        let opened = tokio::time::timeout_at(deadline, connection.open_bi()).await.map_err(|_| NetError::TimedOut)?;
        let (mut send, mut receive) = opened.map_err(|e| lost(&e))?;
        // The streams are held out here, so that if time runs out part way they can be told
        // to stop. Merely letting go of them would leave the request to go on being sent.
        let exchanged = tokio::time::timeout_at(deadline, async {
            send.write_all(&request.encode_to_vec()).await.map_err(|e| lost(&e))?;
            send.finish().map_err(|e| lost(&e))?;
            read_whole(&mut receive, self.cfg.max_message_bytes).await.ok_or_else(|| lost(&"the reply could not be read, or was too large"))
        })
        .await;
        let Ok(answer) = exchanged else {
            let _ = send.reset(VarInt::from_u32(3));
            let _ = receive.stop(VarInt::from_u32(3));
            return Err(NetError::TimedOut);
        };
        let reply = PeerReply::decode(&*answer?).map_err(|_| NetError::Garbled)?;
        if reply.body.is_none() {
            return Err(NetError::Refused(reply.refused));
        }
        Ok(reply)
    }

    /// The place where the connection for a pair of ships is kept, making one if the pair is new.
    fn slot(&self, pair: &Pair) -> Result<Arc<tokio::sync::Mutex<Option<Made>>>, NetError> {
        let mut made = lock(&self.made);
        if !made.contains_key(pair) && made.len() >= self.cfg.max_calls {
            // Forget the pairs whose connections have closed. A pair that some call is holding
            // is left alone, whatever state it is in: that call got its place while this lock
            // was held, and is about to use it. Only this map can hand a place out, so with
            // the lock held, a place nobody else holds cannot be taken up meanwhile.
            // A connection to a ship the directory no longer lists, or lists differently, goes
            // too: it would never be used again, and must not hold a place another ship needs.
            made.retain(|(_, to), kept| {
                let in_use = Arc::strong_count(kept) > 1;
                in_use || kept.try_lock().map_or(true, |held| {
                    let keep = held.as_ref().is_some_and(|made| made.connection.close_reason().is_none() && self.directory.lookup(to) == Some(made.peer));
                    if let Some(made) = held.as_ref().filter(|_| !keep) {
                        made.connection.close(VarInt::from_u32(2), b"no longer needed");
                    }
                    keep
                })
            });
            if made.len() >= self.cfg.max_calls {
                return Err(NetError::Unreachable("this runtime is already calling as many ships as it may".into()));
            }
        }
        Ok(made.entry(pair.clone()).or_default().clone())
    }

    /// The connection from one of this runtime's ships to another ship, made if there is none.
    async fn connection(&self, from: &str, to: &str) -> Result<Connection, NetError> {
        let key = self.runtime.signing_key(from).map_err(|_| NetError::NotHere(from.to_string()))?;
        let shown = key.verifying_key().to_bytes();
        let pair = (from.to_string(), to.to_string());
        if self.directory.lookup(to).is_none() {
            // Not listed, so not called, whatever room there is for calls. A connection made
            // while it was listed is closed, unless some call is still holding it.
            let mut made = lock(&self.made);
            if made.get(&pair).is_some_and(|kept| Arc::strong_count(kept) == 1) {
                let kept = made.remove(&pair).expect("found above");
                if let Some(made) = kept.try_lock().ok().and_then(|mut held| held.take()) {
                    made.connection.close(VarInt::from_u32(2), b"the directory changed");
                }
            }
            return Err(NetError::Unlisted(to.to_string()));
        }
        let slot = self.slot(&pair)?;
        // Held while connecting, so a second call to the same ship waits for this connection
        // and does not make another. Calls to other ships have their own.
        let mut kept = slot.lock().await;
        // Read after any wait, so it is what the directory says now.
        let Some(peer) = self.directory.lookup(to) else {
            // The ship is no longer listed. A connection made while it was is closed, not left
            // open with nothing to use it.
            if let Some(made) = kept.take() {
                made.connection.close(VarInt::from_u32(2), b"the directory changed");
            }
            return Err(NetError::Unlisted(to.to_string()));
        };
        if let Some(made) = kept.take() {
            // A connection proves what was true when it was made. If the directory now lists
            // a different key or address for the ship, or the calling ship would now show a
            // different key, that proof is stale: start again.
            if made.connection.close_reason().is_none() && made.peer == peer && made.shown == shown {
                let connection = made.connection.clone();
                *kept = Some(made);
                return Ok(connection);
            }
            made.connection.close(VarInt::from_u32(2), b"the directory changed");
        }

        let unreachable = |why: &dyn fmt::Display| NetError::Unreachable(why.to_string());
        // This side shows the calling ship's key, and accepts only the key listed for the ship
        // being called.
        let shows = proof(&key, &self.provider).map_err(|e| unreachable(&e))?;
        let expects = ListedKey { expected: wrapped(&peer.key), supported: self.provider.signature_verification_algorithms };
        let mut calling = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| unreachable(&e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(expects))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(shows)));
        calling.alpn_protocols = vec![PROTOCOL.to_vec()];
        calling.resumption = rustls::client::Resumption::disabled();
        let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(calling).map_err(|e| unreachable(&e))?));
        // Requests go one way on a connection this runtime made. The ship called may not
        // start any of its own on it.
        client.transport_config(Arc::new(transport(&self.cfg, 0).map_err(|e| unreachable(&e))?));

        let connecting = self.endpoint.connect_with(client, peer.addr, to).map_err(|e| unreachable(&e))?;
        let connection = connecting.await.map_err(|e| unreachable(&e))?;
        // Connecting took time. If the directory changed meanwhile, what was just proved is
        // already out of date.
        if self.directory.lookup(to) != Some(peer) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return Err(NetError::Unreachable("the directory changed while connecting".into()));
        }
        *kept = Some(Made { connection: connection.clone(), peer, shown });
        Ok(connection)
    }
}

/// A place among the connections from other ships, given up when the connection ends.
struct Place(Arc<Shared>);

impl Place {
    /// Take a place, if one is free. Counted in one step, so that however many callers arrive
    /// at once, no more than the limit get in.
    fn take(shared: &Arc<Shared>) -> Option<Place> {
        if shared.taken.fetch_add(1, Ordering::SeqCst) >= shared.cfg.max_connections {
            shared.taken.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Place(shared.clone()))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.0.taken.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Take connections from other ships for as long as the network runs.
async fn answer_calls(shared: Arc<Shared>) {
    while let Some(incoming) = shared.endpoint.accept().await {
        // Before doing any work for a caller, make it show that it really is at the address
        // it claims. Otherwise anyone could have this runtime send replies to a third party.
        if !incoming.remote_address_validated() && incoming.may_retry() {
            let _ = incoming.retry();
            continue;
        }
        let Some(place) = Place::take(&shared) else {
            incoming.refuse();
            continue;
        };
        tokio::spawn(answer_caller(shared.clone(), incoming, place));
    }
}

/// One connection from another ship: learn who is calling and which ship they called, then
/// answer their requests until the connection closes.
async fn answer_caller(shared: Arc<Shared>, incoming: Incoming, _place: Place) {
    let Ok(connecting) = incoming.accept() else { return };
    let Ok(Ok(connection)) = tokio::time::timeout(shared.cfg.request_timeout, connecting).await else { return };
    let Some(pair) = parties(&shared, &connection) else {
        connection.close(VarInt::from_u32(1), b"not a ship this runtime knows");
        return;
    };
    // One connection from each calling ship to each ship here. A newer one takes the place
    // of the older, so a ship cannot use up the places by connecting over and over.
    if let Some(older) = lock(&shared.callers).insert(pair.clone(), connection.clone()) {
        older.close(VarInt::from_u32(5), b"replaced by a newer connection");
    }
    while let Ok((send, receive)) = connection.accept_bi().await {
        tokio::spawn(answer_request(shared.clone(), connection.clone(), pair.clone(), send, receive));
    }
    let mut callers = lock(&shared.callers);
    if callers.get(&pair).is_some_and(|kept| kept.stable_id() == connection.stable_id()) {
        callers.remove(&pair);
    }
}

/// One request on a connection from another ship.
async fn answer_request(shared: Arc<Shared>, connection: Connection, pair: Pair, mut send: SendStream, mut receive: RecvStream) {
    let limit = shared.cfg.request_timeout;
    let served = tokio::time::timeout(limit, async {
        // Room is set aside before a byte is read. With none to spare, the request is told so
        // at once, and nothing of it is taken in.
        let Ok(_room) = shared.reading.clone().try_acquire_many_owned(shared.cfg.max_message_bytes as u32) else {
            let _ = receive.stop(VarInt::from_u32(4));
            return reply(&mut send, &refused("too busy; try again")).await;
        };
        let Some(bytes) = read_whole(&mut receive, shared.cfg.max_message_bytes).await else {
            return reply(&mut send, &refused("the request could not be read, or was too large")).await;
        };
        // Who is calling was settled when the connection was made. It is checked again here,
        // with the whole request in hand and just before acting on it: the directory may
        // since have given that ship a new key or dropped it. A request that began arriving
        // while its sender was still listed is not acted on once it is not.
        if parties(&shared, &connection).as_ref() != Some(&pair) {
            connection.close(VarInt::from_u32(2), b"the directory changed");
            return;
        }
        reply(&mut send, &answer(&pair.0, &pair.1, &bytes)).await;
    })
    .await;
    if served.is_err() {
        // Out of time. Say so on the wire, so nothing of this request lingers at either end.
        let _ = send.reset(VarInt::from_u32(3));
        let _ = receive.stop(VarInt::from_u32(3));
    }
}

/// Read a whole message from a stream, up to `max` bytes. `None` if it is longer, or the
/// stream fails.
///
/// What arrives is copied straight into one buffer that never holds more than `max`. Keeping
/// the pieces as they arrive would not do: each piece can keep alive the whole packet it came
/// in, so a message sent a byte at a time could hold many times its own size in memory.
async fn read_whole(receive: &mut RecvStream, max: usize) -> Option<Vec<u8>> {
    let (mut whole, mut piece) = (Vec::new(), [0u8; 8192]);
    loop {
        match receive.read(&mut piece).await.ok()? {
            None => return Some(whole),
            Some(read) if whole.len() + read > max => return None,
            Some(read) => whole.extend_from_slice(&piece[..read]),
        }
    }
}

async fn reply(send: &mut SendStream, reply: &PeerReply) {
    let _ = send.write_all(&reply.encode_to_vec()).await;
    let _ = send.finish();
    // Wait for the caller to take the reply, so closing does not cut it short.
    let _ = send.stopped().await;
}

/// Who is at each end of a connection from another ship, as things stand now: the calling
/// ship, known by the key it proved it holds, and the ship of this runtime that it asked for.
fn parties(shared: &Shared, connection: &Connection) -> Option<Pair> {
    let shown = connection.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let caller = shared.directory.who(&unwrapped(shown.first()?.as_ref())?)?;
    let handshake = connection.handshake_data()?.downcast::<HandshakeData>().ok()?;
    let called = canonical_ship(handshake.server_name.as_deref()?).ok()?;
    // The ship is one this runtime holds, or no key could have been shown for it.
    shared.runtime.signing_key(&called).ok()?;
    Some((caller, called))
}

fn refused(why: &str) -> PeerReply {
    PeerReply { body: None, refused: why.to_string() }
}

/// Answer one request from `caller` to `called`.
fn answer(caller: &str, called: &str, request: &[u8]) -> PeerReply {
    let Ok(request) = PeerRequest::decode(request) else { return refused("not a request") };
    match request.body {
        Some(peer_request::Body::Ping(Ping { nonce })) if nonce.len() <= 64 => {
            let pong = Pong { nonce, ship: called.to_string(), caller: caller.to_string() };
            PeerReply { body: Some(peer_reply::Body::Pong(pong)), refused: String::new() }
        }
        _ => refused("not a request this ship answers"),
    }
}
