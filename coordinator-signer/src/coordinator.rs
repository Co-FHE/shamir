use crate::behaviour::{
    CoorBehaviour, CoorBehaviourEvent, CoorToSigRequest, SigToCoorRequest, SigToCoorResponse,
    ValidatorIdentityRequest,
};
use crate::utils::*;
use common::Settings;
use futures::StreamExt;
use libp2p::identify::Behaviour;
use libp2p::identity::PublicKey;
use libp2p::request_response::{OutboundRequestId, ProtocolSupport};
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use std::any;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task;
#[derive(Debug)]
pub struct RegistryInfo {
    pub(crate) signer_p2p_peer_id: PeerId,
    pub(crate) msg_to_sign: Vec<u8>,
}
pub struct Coordinator {
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<CoorBehaviour>,
    signer_keypairs: BTreeMap<u16, Multiaddr>,
    ipc_path: PathBuf,
    registry_info: HashMap<OutboundRequestId, RegistryInfo>,
    valid_validators: HashMap<PeerId, ValidValidator>,
    p2ppeerid_2_endpoint: HashMap<PeerId, Multiaddr>,
}
enum Command {
    PeerId,
    Help,
    ListSignerAddr,
    Unknown(String),
}

impl Command {
    fn parse(input: &str) -> Self {
        match input
            .trim()
            .to_lowercase()
            .replace("-", " ")
            .replace("_", " ")
            .as_str()
        {
            "peer id" => Command::PeerId,
            "help" => Command::Help,
            "list signer addr" => Command::ListSignerAddr,
            other => Command::Unknown(other.to_string()),
        }
    }

    fn help_text() -> &'static str {
        "Available commands:
        - peer id: Show the peer ID
        - help: Show this help message
        - list signer addr: List signer addresses"
    }
}
struct ValidValidator {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: PeerId,
    pub(crate) validator_public_key: PublicKey,
    pub(crate) nonce: u64,
}
impl Coordinator {
    pub fn new(p2p_keypair: libp2p::identity::Keypair) -> anyhow::Result<Self> {
        let swarm = libp2p::SwarmBuilder::with_existing_identity(p2p_keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| CoorBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".to_string(),
                    key.public(),
                )),
                ping: ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(1)),
                ),
                rendezvous: rendezvous::server::Behaviour::new(
                    rendezvous::server::Config::default(),
                ),
                sig2coor: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/sig2coor"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(10)),
                ),
                coor2sig: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/coor2sig"), ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(100)),
                ),
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(5)))
            .build();
        Ok(Self {
            p2p_keypair,
            swarm,
            signer_keypairs: BTreeMap::new(),
            ipc_path: Settings::global().coordinator.ipc_socket_path.into(),
            registry_info: HashMap::new(),
            valid_validators: HashMap::new(),
            p2ppeerid_2_endpoint: HashMap::new(),
        })
    }

    pub async fn start_listening(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on(
            format!("/ip4/0.0.0.0/tcp/{}", Settings::global().coordinator.port).parse()?,
        )?;
        let listener = self.start_ipc_listening().await?;
        loop {
            tokio::select! {
                    event = self.swarm.select_next_some()=> {
                        if let Err(e) = self.handle_swarm_event(event).await{
                            tracing::error!("Error handling swarm event: {}", e);
                        }
                    },
                    command_result = listener.accept()=> {
                        if let Err(e) = self.handle_command(command_result).await {
                            tracing::error!("Error handling command: {}", e);
                        }
                }
            }
        }
    }

    pub async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<CoorBehaviourEvent>,
    ) -> Result<(), anyhow::Error> {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::info!("Connected to {}", peer_id);
                self.p2ppeerid_2_endpoint
                    .insert(peer_id, endpoint.get_remote_address().clone());
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::warn!("Disconnected from {}", peer_id);
                self.p2ppeerid_2_endpoint.remove(&peer_id);
            }
            SwarmEvent::Behaviour(CoorBehaviourEvent::Rendezvous(
                rendezvous::server::Event::PeerRegistered { peer, registration },
            )) => {
                tracing::debug!(
                    "Peer {} registered for namespace '{}'",
                    peer,
                    registration.namespace
                );
            }
            SwarmEvent::Behaviour(CoorBehaviourEvent::Rendezvous(
                rendezvous::server::Event::DiscoverServed {
                    enquirer,
                    registrations,
                },
            )) => {
                tracing::debug!(
                    "Served peer {} with {} registrations",
                    enquirer,
                    registrations.len()
                );
            }
            SwarmEvent::Behaviour(CoorBehaviourEvent::Sig2coor(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                },
            )) => {
                tracing::info!(
                    "Received request from {:?} with request_id {:?}",
                    peer,
                    request_id
                );
                match request {
                    SigToCoorRequest::ValidatorIndentity(ValidatorIdentityRequest {
                        signature,
                        public_key,
                        nonce,
                    }) => {
                        // Reconstruct the hash that was signed by concatenating the same strings
                        let public_key = PublicKey::try_decode_protobuf(public_key.as_slice())
                            .inspect_err(|e| tracing::error!("Invalid public key: {}", e))?;
                        let validator_peer = public_key.to_peer_id();
                        if !Settings::global()
                            .coordinator
                            .peer_id_whitelist
                            .contains(&validator_peer.to_base58())
                        {
                            tracing::warn!(
                                "Validator peerid {} is not in whitelist",
                                validator_peer
                            );
                            let _ = self.swarm.behaviour_mut().sig2coor.send_response(
                                channel,
                                SigToCoorResponse::Failure(
                                    "Validator peerid is not in whitelist".to_string(),
                                )
                                .into(),
                            );
                            return Ok(());
                        }
                        let hash = concat_string_hash(&[
                            "register".as_bytes(),
                            validator_peer.to_bytes().as_slice(),
                            peer.to_bytes().as_slice(),
                            self.p2p_keypair.public().to_peer_id().to_bytes().as_slice(),
                        ]);
                        // Verify the signature
                        if public_key.verify(&hash, &signature) {
                            tracing::info!(
                                "Valid signature from validator peerid : {} p2p peerid : {}",
                                validator_peer,
                                peer
                            );
                            let existing_validator = self.valid_validators.get(&validator_peer);
                            let new_validator = ValidValidator {
                                p2p_peer_id: peer,
                                validator_peer_id: validator_peer,
                                validator_public_key: public_key,
                                nonce: nonce,
                            };
                            if existing_validator.is_none()
                                || existing_validator.unwrap().nonce < nonce
                            {
                                self.valid_validators.insert(validator_peer, new_validator);
                            }
                            let addr = self.p2ppeerid_2_endpoint.get(&peer);
                            if let Some(addr) = addr {
                                self.swarm.add_peer_address(peer, addr.clone());
                            }
                            // Send success response
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .sig2coor
                                .send_response(channel, SigToCoorResponse::Success.into());
                        } else {
                            tracing::error!("Invalid signature from validator {}", validator_peer);
                            return Err(anyhow::anyhow!(
                                "Invalid signature from validator {}",
                                validator_peer
                            ));
                        }
                    }
                }
            }
            other => {
                tracing::debug!("Unhandled {:?}", other);
            }
        }
        Ok(())
    }
    pub async fn handle_command(
        &mut self,
        command_result: Result<(UnixStream, SocketAddr), std::io::Error>,
    ) -> Result<(), anyhow::Error> {
        match command_result {
            Ok((stream, _addr)) => {
                tracing::info!("IPC accept success");
                // Spawn a new task to handle the stream
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).await?;
                let writer = reader.get_mut();
                if bytes_read == 0 {
                    return Ok(());
                }
                let command = Command::parse(&line);
                match command {
                    Command::PeerId => {
                        writer
                            .write_all(
                                self.p2p_keypair
                                    .public()
                                    .to_peer_id()
                                    .to_base58()
                                    .as_bytes(),
                            )
                            .await?;
                        writer.write_all(b"\n").await?;
                    }
                    Command::Help => {
                        reader
                            .get_mut()
                            .write_all(Command::help_text().as_bytes())
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::ListSignerAddr => {
                        let addresses = self
                            .signer_keypairs
                            .keys()
                            .map(|k| k.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        reader.get_mut().write_all(addresses.as_bytes()).await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::Unknown(cmd) => {
                        let msg = format!("Unknown command: {}\n", cmd);
                        reader.get_mut().write_all(msg.as_bytes()).await?;
                        reader
                            .get_mut()
                            .write_all(Command::help_text().as_bytes())
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                }
            }
            Err(e) => {
                tracing::error!("IPC accept error: {}", e);
            }
        };
        Ok(())
    }
    pub async fn start_ipc_listening(&mut self) -> anyhow::Result<UnixListener> {
        // Remove existing IPC socket file if it exists
        if self.ipc_path.exists() {
            std::fs::remove_file(&self.ipc_path)?;
        }

        let listener = UnixListener::bind(&self.ipc_path)?;
        tracing::info!("IPC Listening on {:?}", self.ipc_path);
        return Ok(listener);
    }
}
