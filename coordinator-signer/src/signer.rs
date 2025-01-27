mod command;
mod manager;
mod session;
use futures::stream::FuturesUnordered;
use libp2p::request_response::{InboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use manager::{Request, SessionManagerError};
use session::SessionWrap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use tokio::io::AsyncWriteExt;

use crate::crypto::PkId;
use crate::crypto::{
    ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};
use crate::keystore;
use crate::types::message::{
    CoorToSigRequest, CoorToSigResponse, DKGResponseWrap, SigBehaviour, SigBehaviourEvent,
    SigToCoorRequest, SigToCoorResponse, SigningResponseWrap, ValidatorIdentityRequest,
};
use crate::types::ConnectionState;
use crate::utils::list_hash;
use command::Command;

pub struct Signer<VI: ValidatorIdentity> {
    validator_keypair: VI::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<SigBehaviour<VI::Identity>>,
    coordinator_addr: Multiaddr,
    ipc_path: PathBuf,
    coordinator_peer_id: PeerId,
    register_request_id: Option<request_response::OutboundRequestId>,
    request_sender: UnboundedSender<Request<VI::Identity>>,
    dkg_response_futures: FuturesUnordered<
        oneshot::Receiver<(
            InboundRequestId,
            Result<DKGResponseWrap<VI::Identity>, SessionManagerError>,
        )>,
    >,
    signing_response_futures: FuturesUnordered<
        oneshot::Receiver<(
            InboundRequestId,
            Result<SigningResponseWrap<VI::Identity>, SessionManagerError>,
        )>,
    >,
    channel_mapping: HashMap<InboundRequestId, ResponseChannel<CoorToSigResponse<VI::Identity>>>,
    connection_state: ConnectionState,
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
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(1000))
                    .with_max_negotiating_inbound_streams(100000)
            })
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
        let (request_sender, request_receiver) = tokio::sync::mpsc::unbounded_channel();
        manager::SignerSessionManager::new(
            request_receiver,
            Arc::new(keystore::Keystore::new(
                validator_keypair.derive_key(b"keystore"),
                None,
            )?),
        )?
        .listening();
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
            coordinator_peer_id: <PeerId as FromStr>::from_str(
                &Settings::global().coordinator.peer_id,
            )
            .unwrap(),
            register_request_id: None,
            request_sender,
            dkg_response_futures: FuturesUnordered::new(),
            signing_response_futures: FuturesUnordered::new(),
            channel_mapping: HashMap::new(),
            connection_state: ConnectionState::Disconnected(None),
        })
    }
    pub async fn start_listening(mut self) -> Result<(), anyhow::Error> {
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let listener = self.start_ipc_listening().await?;
        loop {
            match self.connection_state {
                ConnectionState::Disconnected(None) => {
                    self.dial_coordinator()?;
                    self.connection_state =
                        ConnectionState::Connecting(tokio::time::Instant::now());
                }
                ConnectionState::Disconnected(Some(last_connecting_time)) => {
                    let elapsed = last_connecting_time.elapsed();
                    if elapsed
                        > Duration::from_secs(common::Settings::global().signer.connection_timeout)
                    {
                        self.dial_coordinator()?;
                        self.connection_state =
                            ConnectionState::Connecting(tokio::time::Instant::now());
                    } else {
                        tokio::time::sleep(
                            Duration::from_secs(
                                common::Settings::global().signer.connection_timeout,
                            ) - elapsed,
                        )
                        .await;
                        self.dial_coordinator()?;
                        self.connection_state =
                            ConnectionState::Connecting(tokio::time::Instant::now());
                    }
                }
                ConnectionState::Connecting(start_time) => {
                    if start_time.elapsed()
                        > Duration::from_secs(common::Settings::global().signer.connection_timeout)
                    {
                        self.dial_coordinator()?;
                        self.connection_state =
                            ConnectionState::Connecting(tokio::time::Instant::now());
                    }
                }
                ConnectionState::Connected => {}
            }
            if self.connection_state == ConnectionState::Connected {
                println!("Connected");
                tokio::select! {
                    event = self.swarm.select_next_some()=> {
                        tracing::debug!("Received swarm event");
                        println!("Received swarm event");
                        if let Err(e) = self.handle_swarm_event(event).await {
                            tracing::error!("Error handling behaviour event: {}", e);
                        }
                    },
                    event = listener.accept()=> {
                        tracing::debug!("Received command");
                        println!("Received command");
                        if let Err(e) = self.handle_command(event).await {
                            tracing::error!("Error handling command: {}", e);
                        }
                    }
                    Some(Result::Ok(dkg_request)) = self.dkg_response_futures.next() => {
                        tracing::debug!("Received dkg request");
                        println!("Received dkg request");
                        if let Err(e) = self.dkg_handle_response(dkg_request).await {
                            tracing::error!("Error handling dkg response: {}", e);
                        }
                    }
                    Some(Result::Ok(signing_request)) = self.signing_response_futures.next() => {
                        tracing::debug!("Received signing request");
                        println!("Received signing request");
                        if let Err(e) = self.signing_handle_response(signing_request).await {
                            tracing::error!("Error handling signing response: {}", e);
                        }
                    }
                }
            } else {
                let event = self.swarm.select_next_some().await;
                tracing::info!("{:?}", event);
                if let Err(e) = self.handle_swarm_event(event).await {
                    tracing::error!("Error handling behaviour event: {}", e);
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
                self.connection_state = ConnectionState::Disconnected(None);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if peer_id == Some(self.coordinator_peer_id) {
                    tracing::error!("Outgoing connection to {:?} error: {:?}", peer_id, error);
                    if let ConnectionState::Connecting(last_connecting_time) = self.connection_state
                    {
                        self.connection_state =
                            ConnectionState::Disconnected(Some(last_connecting_time));
                    }
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. }
                if peer_id == self.coordinator_peer_id =>
            {
                self.connection_state = ConnectionState::Connected;
                if let Err(error) = self.swarm.behaviour_mut().rendezvous.register(
                    rendezvous::Namespace::from_static("rendezvous_coorsig"),
                    self.coordinator_peer_id,
                    None,
                ) {
                    tracing::error!("Failed to register: {error}");
                    return Err(anyhow::anyhow!("Failed to register: {error}"));
                }
                tracing::info!("Connection established with coordinator {}", peer_id);
                let hash = list_hash(&[
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
                    hex::encode(request.public_key),
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
                    ..
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
                        tracing::info!("Received dkg request: {:?}", request);
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.dkg_response_futures.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        self.request_sender
                            .send(Request::DKG((request_id, request), tx))
                            .unwrap();
                    }
                    CoorToSigRequest::SigningRequest(request) => {
                        tracing::info!("Received signing request: {:?}", request);
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.signing_response_futures.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        self.request_sender
                            .send(Request::Signing((request_id, request), tx))
                            .unwrap();
                    }
                    CoorToSigRequest::Empty => {
                        tracing::info!("Received empty request");
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
                        tracing::error!(
                            "Received response from invalid peer: {}, {}",
                            peer,
                            connection_id
                        );
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
    pub(crate) async fn dkg_handle_response(
        &mut self,
        response: (
            InboundRequestId,
            Result<DKGResponseWrap<VI::Identity>, SessionManagerError>,
        ),
    ) -> Result<(), anyhow::Error> {
        let id = response.0;
        match response.1 {
            Ok(response) => {
                let channel = self.channel_mapping.remove(&id).unwrap();
                let r = self
                    .swarm
                    .behaviour_mut()
                    .coor2sig
                    .send_response(channel, CoorToSigResponse::DKGResponse(response.clone()));
                match r {
                    Ok(_) => {
                        tracing::info!("Sent dkg response to coordinator");
                    }
                    Err(e) => {
                        tracing::error!("Failed to send dkg response to coordinator: {:?}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to handle response: {:?}", e);
            }
        }
        Ok(())
    }
    pub(crate) async fn signing_handle_response(
        &mut self,
        response: (
            InboundRequestId,
            Result<SigningResponseWrap<VI::Identity>, SessionManagerError>,
        ),
    ) -> Result<(), anyhow::Error> {
        let request_id = response.0;
        match response.1 {
            Ok(response) => {
                let channel = self.channel_mapping.remove(&request_id).unwrap();
                let r = self.swarm.behaviour_mut().coor2sig.send_response(
                    channel,
                    CoorToSigResponse::SigningResponse(response.clone()),
                );
                match r {
                    Ok(_) => {
                        tracing::info!("Sent signing response to coordinator");
                    }
                    Err(e) => {
                        tracing::error!("Failed to send signing response to coordinator: {:?}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to handle response: {:?}", e);
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
