use libp2p::identity::ed25519;
use libp2p::request_response::ProtocolSupport;
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{any, time};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task;

use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self, Behaviour},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::behaviour::{
    SigBehaviour, SigBehaviourEvent, SigToCoorRequest, SigToCoorResponse, ValidatorIdentityRequest,
};
use crate::utils::{self, concat_string_hash};

pub struct Signer {
    validator_keypair: libp2p::identity::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<SigBehaviour>,
    coordinator_addr: Multiaddr,
    ipc_path: PathBuf,
    coordinator_peer_id: PeerId,
    register_request_id: Option<request_response::OutboundRequestId>,
}
enum Command {
    PeerId,
    ValidatorPeerId,
    CoordinatorPeerId,
    P2pPeerId,
    Help,
    PingCoordinator,
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
            "peer id" | "id" | "pid" => Command::PeerId,
            "validator peer id" | "vpid" => Command::ValidatorPeerId,
            "coordinator peer id" | "cpid" => Command::CoordinatorPeerId,
            "p2p peer id" | "ppid" => Command::P2pPeerId,
            "help" | "h" => Command::Help,
            "ping coordinator" | "pc" => Command::PingCoordinator,
            other => Command::Unknown(other.to_string()),
        }
    }
    fn help_text() -> &'static str {
        "Available commands:
        - `peer id`/`id`/`pid`: Show the peer ID
            - `validator peer id`/`vpid`: Show the validator peer ID
            - `coordinator peer id`/`cpid`: Show the coordinator peer ID
            - `p2p peer id`/`ppid`: Show the p2p peer ID
        - `help`/`h`: Show this help message
        - `ping coordinator`/`pc`: Ping the coordinator"
    }
}

impl Signer {
    pub fn new(validator_keypair: libp2p::identity::Keypair) -> Result<Self, anyhow::Error> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| SigBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".to_string(),
                    key.public(),
                )),
                ping: ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(1)),
                ),
                sig2coor: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/sig2coor"), ProtocolSupport::Full)],
                    request_response::Config::default(),
                ),
                coor2sig: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/coor2sig"), ProtocolSupport::Full)],
                    request_response::Config::default(),
                ),
                rendezvous: rendezvous::client::Behaviour::new(key.clone()),
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(5)))
            .build();
        let coordinator_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}/p2p/{}",
            Settings::global().coordinator.remote_addr,
            Settings::global().coordinator.port,
            Settings::global().coordinator.peer_id
        )
        .parse()?;
        let coordinator_peer_id =
            PeerId::from_str(&Settings::global().coordinator.peer_id).unwrap();
        swarm.add_peer_address(coordinator_peer_id, coordinator_addr.clone());
        Ok(Self {
            validator_keypair: validator_keypair.clone(),
            p2p_keypair: keypair,
            swarm,
            coordinator_addr,
            ipc_path: PathBuf::from(Settings::global().signer.ipc_socket_path).join(format!(
                "signer_{}.sock",
                validator_keypair.public().to_peer_id().to_string()
            )),
            coordinator_peer_id: PeerId::from_str(&Settings::global().coordinator.peer_id).unwrap(),
            register_request_id: None,
        })
    }
    pub(crate) async fn start_listening(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let listener = self.start_ipc_listening().await?;
        self.dial_coordinator()?;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some()=> {
                    if let Err(e) = self.handle_swarm_event(event).await {
                        tracing::error!("Error handling behaviour event: {}", e);
                    }
                },
                event = listener.accept()=> {
                    if let Err(e) = self.handle_command(event).await {
                        tracing::error!("Error handling command: {}", e);
                    }
                }
            }
        }
    }
    pub(crate) fn dial_coordinator(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.dial(self.coordinator_addr.clone())?;
        Ok(())
    }
    pub(crate) async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<SigBehaviourEvent>,
    ) -> Result<(), anyhow::Error> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if Settings::global().signer.allow_external_address {
                    self.swarm.add_external_address(address.clone());
                }
                tracing::info!("Listening on {address:?}")
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                cause: Some(error),
                ..
            } if peer_id == self.coordinator_peer_id => {
                tracing::warn!("Lost connection to rendezvous point {}", error);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::error!("Outgoing connection to {:?} error: {:?}", peer_id, error);
                tracing::info!("Dialing coordinator after 3 seconds");
                tokio::time::sleep(Duration::from_secs(3)).await;
                self.dial_coordinator()?;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. }
                if peer_id == self.coordinator_peer_id =>
            {
                if let Err(error) = self.swarm.behaviour_mut().rendezvous.register(
                    rendezvous::Namespace::from_static("rendezvous_coorsig"),
                    self.coordinator_peer_id,
                    None,
                ) {
                    tracing::error!("Failed to register: {error}");
                    return Err(anyhow::anyhow!("Failed to register: {error}"));
                }
                tracing::info!("Connection established with coordinator {}", peer_id);
                let hash = concat_string_hash(&[
                    "register".as_bytes(),
                    self.validator_keypair
                        .public()
                        .to_peer_id()
                        .to_bytes()
                        .as_slice(),
                    self.p2p_keypair.public().to_peer_id().to_bytes().as_slice(),
                    self.coordinator_peer_id.to_bytes().as_slice(),
                ]);
                let signature = self.validator_keypair.sign(hash.as_slice()).unwrap();
                let request = ValidatorIdentityRequest {
                    signature: signature,
                    public_key: self.validator_keypair.public().encode_protobuf(),
                    nonce: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                let request_id = self.swarm.behaviour_mut().sig2coor.send_request(
                    &self.coordinator_peer_id,
                    SigToCoorRequest::ValidatorIndentity(request.clone()),
                );
                tracing::info!(
                    "Sent registration request to coordinator with request_id: {:?}, pk: {}, validator_peer_id: {:?}, nonce: {:?}",
                    request_id,
                    utils::to_hex(request.public_key),
                    self.validator_keypair.public().to_peer_id().to_base58(),
                    request.nonce,
                );
                self.register_request_id = Some(request_id);
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Rendezvous(
                rendezvous::client::Event::Registered {
                    namespace,
                    ttl,
                    rendezvous_node,
                },
            )) => {
                tracing::info!(
                    "Registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                    namespace,
                    rendezvous_node,
                    ttl
                );
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Rendezvous(
                rendezvous::client::Event::RegisterFailed {
                    rendezvous_node,
                    namespace,
                    error,
                },
            )) => {
                tracing::error!(
                    "Failed to register: rendezvous_node={}, namespace={}, error_code={:?}",
                    rendezvous_node,
                    namespace,
                    error
                );
                return Err(anyhow::anyhow!("Failed to register: {error:?}"));
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Ping(ping::Event {
                peer,
                result: Ok(rtt),
                ..
            })) if peer != self.coordinator_peer_id => {
                tracing::info!("Ping to {} is {}ms", peer, rtt.as_millis())
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Identify(identify::Event::Received {
                ..
            })) => {
                if let Err(error) = self.swarm.behaviour_mut().rendezvous.register(
                    rendezvous::Namespace::from_static("rendezvous_coorsig"),
                    self.coordinator_peer_id,
                    None,
                ) {
                    tracing::error!("Failed to register: {error}");
                    return Err(anyhow::anyhow!("Failed to register: {error}"));
                }
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Sig2coor(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                },
            )) => {
                if Some(request_id) == self.register_request_id {
                    if peer != self.coordinator_peer_id {
                        tracing::error!("Received response from invalid peer: {}", peer);
                        return Err(anyhow::anyhow!(
                            "Received response from invalid peer: {}",
                            peer
                        ));
                    }
                    self.register_request_id = None;
                    match response {
                        SigToCoorResponse::Success => {
                            tracing::info!("Registered with coordinator");
                        }
                        SigToCoorResponse::Failure(error) => {
                            tracing::error!("Failed to register: {}", error);
                            return Err(anyhow::anyhow!("Failed to register: {}", error));
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(SigBehaviourEvent::Coor2sig(
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
                    "Received request from {:?} with request {:?}",
                    peer,
                    request
                );
            }
            other => {
                tracing::debug!("Unhandled {:?}", other);
            }
        }
        Ok(())
    }
    pub(crate) async fn handle_command(
        &mut self,
        command_result: Result<(UnixStream, SocketAddr), std::io::Error>,
    ) -> Result<(), anyhow::Error> {
        match command_result {
            Ok((stream, _addr)) => {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).await?;
                if bytes_read == 0 {
                    return Ok(());
                }
                tracing::info!("Received command: {}", line);
                let command = Command::parse(&line);
                match command {
                    Command::PeerId => {
                        tracing::info!("Sending peer id");
                        reader.get_mut().write_all(format!("p2p peer id: {}\nvalidator peer id: {}\ncoordinator peer id: {}", self.p2p_keypair.public().to_peer_id().to_base58(), self.validator_keypair.public().to_peer_id().to_base58(), self.coordinator_addr.to_string()).as_bytes()).await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::Help => {
                        tracing::info!("Sending help text");
                        reader
                            .get_mut()
                            .write_all(Command::help_text().as_bytes())
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::ValidatorPeerId => {
                        reader
                            .get_mut()
                            .write_all(
                                self.validator_keypair
                                    .public()
                                    .to_peer_id()
                                    .to_base58()
                                    .as_bytes(),
                            )
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::CoordinatorPeerId => {
                        tracing::info!("Sending coordinator peer id");
                        reader
                            .get_mut()
                            .write_all(self.coordinator_addr.to_string().as_bytes())
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::P2pPeerId => {
                        tracing::info!("Sending p2p peer id");
                        reader
                            .get_mut()
                            .write_all(
                                self.p2p_keypair
                                    .public()
                                    .to_peer_id()
                                    .to_base58()
                                    .as_bytes(),
                            )
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::PingCoordinator => {
                        tracing::info!("Pinging coordinator");
                        if let Err(e) = self.dial_coordinator() {
                            reader.get_mut().write_all(e.to_string().as_bytes()).await?;
                        } else {
                            reader.get_mut().write_all(b"Coordinator pinged\n").await?;
                        }
                    }
                    Command::Unknown(cmd) => {
                        tracing::info!("Unknown command: {}", cmd);
                        let msg = format!("Unknown command: {}\n", cmd);
                        reader.get_mut().write_all(msg.as_bytes()).await?;
                        reader
                            .get_mut()
                            .write_all(Command::help_text().as_bytes())
                            .await?;
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
