use libp2p::request_response::ProtocolSupport;
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::u64;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};

use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use tokio::io::AsyncWriteExt;

use crate::behaviour::{
    CoorToSigRequest, CoorToSigResponse, SigBehaviour, SigBehaviourEvent, SigToCoorRequest,
    SigToCoorResponse, ValidatorIdentityRequest,
};
use crate::crypto::subsession::PKID;
use crate::crypto::{
    DKGSingleRequest, DKGSingleResponse, SessionId, SignerSession, SigningSignerSession,
    SingleRequest, ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};
mod command;
use crate::utils::{self, concat_string_hash};
use command::Command;

pub struct Signer<VI: ValidatorIdentity> {
    validator_keypair: VI::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<SigBehaviour<VI::Identity>>,
    coordinator_addr: Multiaddr,
    sessions: HashMap<SessionId<VI::Identity>, SignerSession<VI>>,
    signing_sessions: HashMap<PKID, SigningSignerSession<VI>>,
    ipc_path: PathBuf,
    coordinator_peer_id: PeerId,
    register_request_id: Option<request_response::OutboundRequestId>,
}

impl<VI: ValidatorIdentity> Signer<VI> {
    pub fn new(validator_keypair: VI::Keypair) -> Result<Self, anyhow::Error> {
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
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(1000)))
            .build();
        let coordinator_addr: Multiaddr = format!(
            "/ip4/{}/tcp/{}/p2p/{}",
            Settings::global().coordinator.remote_addr,
            Settings::global().coordinator.port,
            Settings::global().coordinator.peer_id
        )
        .parse()?;
        let coordinator_peer_id =
            <PeerId as FromStr>::from_str(&Settings::global().coordinator.peer_id).unwrap();
        swarm.add_peer_address(coordinator_peer_id, coordinator_addr.clone());
        Ok(Self {
            validator_keypair: validator_keypair.clone(),
            p2p_keypair: keypair,
            swarm,
            coordinator_addr,
            ipc_path: PathBuf::from(Settings::global().signer.ipc_socket_path).join(format!(
                "signer_{}.sock",
                validator_keypair
                    .to_public_key()
                    .to_identity()
                    .to_fmt_string()
            )),
            sessions: HashMap::new(),
            signing_sessions: HashMap::new(),
            coordinator_peer_id: <PeerId as FromStr>::from_str(
                &Settings::global().coordinator.peer_id,
            )
            .unwrap(),
            register_request_id: None,
        })
    }
    pub(crate) async fn start_listening(mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let listener = self.start_ipc_listening().await?;
        self.dial_coordinator()?;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some()=> {
                    // tracing::info!("{:?}",event);
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
        event: SwarmEvent<SigBehaviourEvent<VI::Identity>>,
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
                self.dial_coordinator()?;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::error!("Outgoing connection to {:?} error: {:?}", peer_id, error);
                // self.dial_coordinator()?;
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
                        .to_public_key()
                        .to_identity()
                        .to_bytes()
                        .as_slice(),
                    self.p2p_keypair.public().to_peer_id().to_bytes().as_slice(),
                    self.coordinator_peer_id.to_bytes().as_slice(),
                ]);
                let signature = self.validator_keypair.sign(hash.as_slice()).unwrap();
                let request = ValidatorIdentityRequest {
                    signature: signature,
                    public_key: self.validator_keypair.to_public_key().to_bytes(),
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
                    self.validator_keypair.to_public_key().to_identity().to_fmt_string(),
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
            SwarmEvent::Behaviour(SigBehaviourEvent::Coor2sig(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                    connection_id,
                },
            )) => {
                if peer != self.coordinator_peer_id {
                    tracing::warn!("Received request from invalid peer: {}", peer);
                    return Ok(());
                }
                tracing::info!(
                    "Received request from {:?} with request {:?}",
                    peer,
                    request
                );
                match request {
                    CoorToSigRequest::DKGRequest(request) => {
                        let session_id = request.get_session_id();
                        if let Some(existing_session) = self.sessions.get_mut(&session_id) {
                            match existing_session.update_from_request(request) {
                                Ok(response) => {
                                    if let Some(signing_session) = existing_session.is_completed() {
                                        tracing::info!("DKG is completed");
                                        match signing_session {
                                            Ok(signing_session) => {
                                                tracing::info!("Signing session is completed");
                                                self.signing_sessions.insert(
                                                    signing_session.pkid.clone(),
                                                    signing_session,
                                                );
                                                self.sessions.remove(&session_id);
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "Failed to create signing session: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    tracing::info!("Sent {:?} to coordinator", response);
                                    if let Err(e) =
                                        self.swarm.behaviour_mut().coor2sig.send_response(
                                            channel,
                                            CoorToSigResponse::DKGResponse(response.clone()),
                                        )
                                    {
                                        tracing::error!("Failed to send response: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Failed to send response: {:?}",
                                            e
                                        ));
                                    }
                                    return Ok(());
                                }
                                Err(e) => {
                                    tracing::error!("Failed to update session: {}", e);
                                    if let Err(e) =
                                        self.swarm.behaviour_mut().coor2sig.send_response(
                                            channel,
                                            CoorToSigResponse::DKGResponse(
                                                DKGSingleResponse::Failure(format!(
                                                    "Failed to update session: {}",
                                                    e
                                                )),
                                            ),
                                        )
                                    {
                                        tracing::error!("Failed to send response: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Failed to send response: {:?}",
                                            e
                                        ));
                                    }
                                    return Ok(());
                                }
                            }
                        } else {
                            match SignerSession::new_from_request(request) {
                                Ok((session, response)) => {
                                    self.sessions.insert(session_id.clone(), session);
                                    if let Err(e) =
                                        self.swarm.behaviour_mut().coor2sig.send_response(
                                            channel,
                                            CoorToSigResponse::DKGResponse(response.clone()),
                                        )
                                    {
                                        tracing::error!("Failed to send response: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Failed to send response: {:?}",
                                            e
                                        ));
                                    }
                                    tracing::info!("Sent {:?} to coordinator", response);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to create session: {}", e);
                                    if let Err(e) =
                                        self.swarm.behaviour_mut().coor2sig.send_response(
                                            channel,
                                            CoorToSigResponse::DKGResponse(
                                                DKGSingleResponse::Failure(format!(
                                                    "Failed to create session: {}",
                                                    e
                                                )),
                                            ),
                                        )
                                    {
                                        tracing::error!("Failed to send response: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Failed to send response: {:?}",
                                            e
                                        ));
                                    }
                                    return Ok(());
                                }
                            }
                        }
                    }
                    CoorToSigRequest::SigningRequest(request) => {
                        tracing::info!("Received signing request: {:?}", request);
                        let pkid = request.get_pkid();
                        if let Some(existing_session) = self.signing_sessions.get_mut(&pkid) {
                            match existing_session.apply_request(request) {
                                Ok(response) => {
                                    if let Err(e) =
                                        self.swarm.behaviour_mut().coor2sig.send_response(
                                            channel,
                                            CoorToSigResponse::SigningResponse(response.clone()),
                                        )
                                    {
                                        tracing::error!("Failed to send response: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Failed to send response: {:?}",
                                            e
                                        ));
                                    }
                                    tracing::info!("Sent {:?} to coordinator", response);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to apply request: {}", e);
                                }
                            }
                        }
                    }
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
                    connection_id,
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
                        reader.get_mut().write_all(format!("p2p peer id: {}\nvalidator peer id: {}\ncoordinator peer id: {}", self.p2p_keypair.public().to_peer_id().to_base58(), self.validator_keypair.to_public_key().to_identity().to_fmt_string(), self.coordinator_addr.to_string()).as_bytes()).await?;
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
                                    .to_public_key()
                                    .to_identity()
                                    .to_fmt_string()
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
