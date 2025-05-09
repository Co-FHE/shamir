mod command;
mod manager;
mod session;
use futures::stream::FuturesUnordered;
use libp2p::request_response::{
    InboundRequestId, OutboundRequestId, ProtocolSupport, ResponseChannel,
};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use manager::{
    ManagerRequestWithInboundRequestId, Request, RequestEx, RequestExWithInboundRequestId,
};
use session::SessionWrap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
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
use crate::types::error::SessionError;
use crate::types::message::{
    CoorToSigRequest, CoorToSigResponse, DKGResponseWrap, DKGResponseWrapEx, DKGStageEx,
    SigBehaviour, SigBehaviourEvent, SigToCoorRequest, SigToCoorResponse, SigningResponseWrap,
    SigningResponseWrapEx, ValidatorIdentityRequest, ValidatorIdentityResponse,
};
use crate::types::ConnectionState;
use crate::utils::list_hash;
use command::Command;

pub struct Signer<VI: ValidatorIdentity> {
    validator_keypair: VI::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<SigBehaviour<VI::Identity>>,
    coordinator_multiaddr: Multiaddr,
    ipc_path: PathBuf,
    coordinator_peer_id: PeerId,
    register_request_id: Option<request_response::OutboundRequestId>,
    coor2signer_request_sender: UnboundedSender<ManagerRequestWithInboundRequestId<VI::Identity>>,
    signer2coor_request_receiver: UnboundedReceiver<RequestEx<VI::Identity>>,

    dkg_response_futures: FuturesUnordered<
        oneshot::Receiver<(
            InboundRequestId,
            Result<DKGResponseWrap<VI::Identity>, SessionError>,
        )>,
    >,
    signing_response_futures: FuturesUnordered<
        oneshot::Receiver<(
            InboundRequestId,
            Result<SigningResponseWrap<VI::Identity>, SessionError>,
        )>,
    >,
    dkg_response_futures_ex: FuturesUnordered<
        oneshot::Receiver<(InboundRequestId, Result<DKGResponseWrapEx, SessionError>)>,
    >,
    signing_response_futures_ex: FuturesUnordered<
        oneshot::Receiver<(
            InboundRequestId,
            Result<SigningResponseWrapEx, SessionError>,
        )>,
    >,
    dkg_out_response_channels_mapping:
        HashMap<OutboundRequestId, oneshot::Sender<Result<DKGResponseWrapEx, SessionError>>>,
    signing_out_response_channels_mapping:
        HashMap<OutboundRequestId, oneshot::Sender<Result<SigningResponseWrapEx, SessionError>>>,

    channel_mapping: HashMap<InboundRequestId, ResponseChannel<CoorToSigResponse<VI::Identity>>>,
    connection_state: ConnectionState,
    verify_message_fn: Box<dyn Fn(&VI::Identity, &[u8]) -> bool + Send + Sync>,
}

impl<VI: ValidatorIdentity> Signer<VI> {
    pub fn new<F: Fn(&VI::Identity, &[u8]) -> bool + Send + Sync + 'static>(
        validator_keypair: VI::Keypair,
        base_path: PathBuf,
        coordinator_multiaddr: Multiaddr,
        coordinator_peer_id: PeerId,
        verify_message_fn: F,
    ) -> Result<Self, anyhow::Error> {
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
                    request_response::Config::default().with_request_timeout(Duration::from_secs(
                        Settings::global().connection.sig2coor_request_timeout,
                    )),
                ),
                coor2sig: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/coor2sig"), ProtocolSupport::Full)],
                    request_response::Config::default().with_request_timeout(Duration::from_secs(
                        Settings::global().connection.coor2sig_request_timeout,
                    )),
                ),
                rendezvous: rendezvous::client::Behaviour::new(key.clone()),
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(1000))
                    .with_max_negotiating_inbound_streams(100000)
            })
            .build();
        swarm.add_peer_address(coordinator_peer_id, coordinator_multiaddr.clone());
        let (coor2signer_request_sender, coor2signer_request_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let (signer2coor_request_sender, signer2coor_request_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        manager::SignerSessionManager::new(
            coor2signer_request_receiver,
            signer2coor_request_sender,
            Arc::new(keystore::Keystore::new(
                validator_keypair.derive_key(b"keystore"),
                None,
            )?),
            &base_path,
        )?
        .listening();
        let fmt_string = validator_keypair
            .to_public_key()
            .to_identity()
            .to_fmt_string();
        Ok(Self {
            validator_keypair: validator_keypair.clone(),
            p2p_keypair: keypair,
            swarm,
            coordinator_multiaddr,
            ipc_path: base_path
                .join(Settings::global().signer.ipc_socket_path)
                .join(format!(
                    "signer_{}.sock",
                    fmt_string.get(..10).unwrap_or(&fmt_string)
                )),
            coordinator_peer_id,
            register_request_id: None,
            coor2signer_request_sender,
            signer2coor_request_receiver,
            dkg_response_futures: FuturesUnordered::new(),
            signing_response_futures: FuturesUnordered::new(),
            dkg_response_futures_ex: FuturesUnordered::new(),
            signing_response_futures_ex: FuturesUnordered::new(),

            channel_mapping: HashMap::new(),
            dkg_out_response_channels_mapping: HashMap::new(),
            signing_out_response_channels_mapping: HashMap::new(),
            connection_state: ConnectionState::Disconnected(None),
            verify_message_fn: Box::new(verify_message_fn),
        })
    }
    pub async fn start_listening(mut self) -> Result<(), anyhow::Error> {
        tracing::info!(
            "Signer {} start listening",
            self.validator_keypair
                .to_public_key()
                .to_identity()
                .to_fmt_string()
        );
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let listener = self.start_ipc_listening().await?;
        loop {
            match self.connection_state {
                ConnectionState::Disconnected(None) => {
                    tracing::info!(
                        "Signer {}'s connection state is disconnected, start dialing coordinator {}",
                        self.validator_keypair
                            .to_public_key()
                            .to_identity()
                            .to_fmt_string(),
                        self.coordinator_multiaddr
                    );
                    self.dial_coordinator()?;
                    self.connection_state =
                        ConnectionState::Connecting(tokio::time::Instant::now());
                }
                ConnectionState::Disconnected(Some(last_connecting_time)) => {
                    tracing::info!(
                        "Signer {}'s connection state is disconnected, last connecting time: {:?} seconds ago, start dialing coordinator {}",
                        self.validator_keypair
                            .to_public_key()
                            .to_identity()
                            .to_fmt_string(),
                        last_connecting_time.elapsed().as_secs_f64(),
                        self.coordinator_multiaddr
                    );
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
                    tracing::info!(
                        "Signer {}'s connection state is connecting, start connecting time: {:?} seconds ago",
                        self.validator_keypair
                            .to_public_key()
                            .to_identity()
                            .to_fmt_string(),
                        start_time.elapsed().as_secs_f64(),
                    );
                    if start_time.elapsed()
                        > Duration::from_secs(common::Settings::global().signer.connection_timeout)
                    {
                        tracing::info!(
                            "Signer {} connecting timeout, start dialing coordinator {}",
                            self.validator_keypair
                                .to_public_key()
                                .to_identity()
                                .to_fmt_string(),
                            self.coordinator_multiaddr
                        );
                        self.dial_coordinator()?;
                        self.connection_state =
                            ConnectionState::Connecting(tokio::time::Instant::now());
                    }
                }
                ConnectionState::Connected => {}
            }
            if self.connection_state == ConnectionState::Connected {
                tokio::select! {
                    event = self.swarm.select_next_some()=> {
                        tracing::debug!("Received swarm event");
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
                    Some(Result::Ok(dkg_request_ex)) = self.dkg_response_futures_ex.next() => {
                        tracing::debug!("Received dkg request ex");
                        if let Err(e) = self.dkg_handle_response_ex(dkg_request_ex).await {
                            tracing::error!("Error handling dkg response ex: {}", e);
                        }
                    }
                    Some(Result::Ok(signing_request_ex)) = self.signing_response_futures_ex.next() => {
                        tracing::debug!("Received signing request ex");
                        if let Err(e) = self.signing_handle_response_ex(signing_request_ex).await {
                            tracing::error!("Error handling signing response ex: {}", e);
                        }
                    }
                    Some(request) = self.signer2coor_request_receiver.recv() => {
                        tracing::debug!("Received signer2coor request");
                        if let Err(e) = self.handle_signer2coor_request(request).await {
                            tracing::error!("Error handling signer2coor request: {}", e);
                        }
                    }
                }
            } else {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(common::Settings::global().signer.connection_timeout)) => {
                            if let ConnectionState::Connecting(start_time) = self.connection_state {
                                if start_time.elapsed()
                                    > Duration::from_secs(common::Settings::global().signer.connection_timeout)
                                {
                                    tracing::warn!("Timeout reached while connecting. Retrying...");
                                    self.dial_coordinator()?;
                                    self.connection_state = ConnectionState::Connecting(tokio::time::Instant::now());
                                }
                            } else if let ConnectionState::Disconnected(last) = self.connection_state {
                                if last.map(|t| t.elapsed().as_secs_f64()).unwrap_or(f64::INFINITY)
                                    > common::Settings::global().signer.connection_timeout as f64
                                {
                                    self.dial_coordinator()?;
                                    self.connection_state = ConnectionState::Connecting(tokio::time::Instant::now());
                                }
                            }
                            continue;
                        }
                        event = self.swarm.select_next_some() => {
                            tracing::debug!("Signer received swarm event: {:?}", event);
                            if let Err(e) = self.handle_swarm_event(event).await {
                                tracing::error!("Error handling swarm event: {}", e);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    pub(crate) fn dial_coordinator(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.dial(self.coordinator_multiaddr.clone())?;
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
                tracing::info!("Signer listening on {address:?}")
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
                    tracing::error!(
                        "Signer outgoing connection error, peer_id:{:?}, coordinator_peer_id:{:?}, error: {:?}",
                        peer_id,
                        self.coordinator_peer_id,
                        error
                    );
                    if let ConnectionState::Connecting(last_connecting_time) = self.connection_state
                    {
                        tracing::info!(
                            "Signer outgoing connection error, set connection state to disconnected with last connecting time: {:.3} seconds ago",
                            last_connecting_time.elapsed().as_secs_f64()
                        );
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
                    "Signer sent registration request to coordinator with request_id: {:?}, pk: {}, validator_peer_id: {:?}, nonce: {:?}",
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
                tracing::debug!(
                    "Signer registered for namespace '{}' at rendezvous point {} for the next {} seconds",
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
                tracing::debug!("Ping to {} is {}ms", peer, rtt.as_millis())
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
                match request {
                    CoorToSigRequest::DKGRequest(request) => {
                        tracing::info!(
                                                            "Signer received dkg request: crypto_type: {}, from identity: {}, request_id: {}",
                                                            request.crypto_type(),
                                                            request.identity().to_fmt_string(),
                                                            request_id
                                                        );
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.dkg_response_futures.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        self.coor2signer_request_sender
                            .send(ManagerRequestWithInboundRequestId::Request(Request::DKG(
                                (request_id, request),
                                tx,
                            )))
                            .unwrap();
                    }
                    CoorToSigRequest::SigningRequest(request) => {
                        tracing::info!(
                                                            "Signer received signing request: crypto_type: {}, from identity: {}, message: {:?}, request_id: {}",
                                                            request.crypto_type(),
                                                            request.identity().to_fmt_string(),
                                                            request.message().map(|m| hex::encode(m)),
                                                            request_id
                                                        );
                        if let Some(message) = request.message() {
                            // TODO: verifying message may take a long time, we need to do it in a separate thread
                            // TODO: should response rejecting the request if the message is invalid instead of discarding the request
                            if !(*self.verify_message_fn)(request.identity(), message.as_ref()) {
                                tracing::warn!("Invalid message for signing request, reject to sign the message");
                                return Ok(());
                            }
                        }
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.signing_response_futures.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        // send request to manager
                        self.coor2signer_request_sender
                            .send(ManagerRequestWithInboundRequestId::Request(
                                Request::Signing((request_id, request), tx),
                            ))
                            .unwrap();
                    }
                    CoorToSigRequest::Empty => {
                        tracing::info!("Signer received an empty request");
                    }
                    CoorToSigRequest::DKGRequestEx(dkgrequest_wrap_ex) => {
                        tracing::info!(
                            "Signer received dkg ex request: crypto_type: {}, from identity: {}, request_id: {}, stage: {}",
                            dkgrequest_wrap_ex.crypto_type(),
                            dkgrequest_wrap_ex.identity().to_fmt_string(),
                            request_id,
                            match dkgrequest_wrap_ex.dkg_request_ex().unwrap().stage {
                                DKGStageEx::Init => "Init".to_string(),
                                DKGStageEx::Intermediate(message_ex) => {
                                    format!("Intermediate {:?}", message_ex.target)
                                }
                                DKGStageEx::Final(_) => "Final".to_string(),
                            }
                        );
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.dkg_response_futures_ex.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        self.coor2signer_request_sender
                            .send(ManagerRequestWithInboundRequestId::RequestEx(
                                RequestExWithInboundRequestId::DKGEx(
                                    (request_id, dkgrequest_wrap_ex),
                                    tx,
                                ),
                            ))
                            .unwrap();
                    }
                    CoorToSigRequest::SigningRequestEx(signing_request_wrap_ex) => {
                        tracing::info!(
                            "Signer received signing ex request: crypto_type: {}, from identity: {}, request_id: {}",
                            signing_request_wrap_ex.crypto_type(),
                            signing_request_wrap_ex.identity().to_fmt_string(),
                            request_id
                        );
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        self.signing_response_futures_ex.push(rx);
                        self.channel_mapping.insert(request_id, channel);
                        self.coor2signer_request_sender
                            .send(ManagerRequestWithInboundRequestId::RequestEx(
                                RequestExWithInboundRequestId::SigningEx(
                                    (request_id, signing_request_wrap_ex),
                                    tx,
                                ),
                            ))
                            .unwrap();
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
                        SigToCoorResponse::ValidatorIdentityResponse(
                            ValidatorIdentityResponse::Success,
                        ) => {
                            tracing::info!("Signer registered with coordinator successfully");
                        }
                        SigToCoorResponse::ValidatorIdentityResponse(
                            ValidatorIdentityResponse::Failure(error),
                        ) => {
                            tracing::error!("Failed to register: {}", error);
                            return Err(anyhow::anyhow!("Failed to register: {}", error));
                        }
                        SigToCoorResponse::DKGResponseEx(dkg_response_wrap_ex) => {
                            tracing::info!(
                                "Signer received dkg ex response: {:?}",
                                dkg_response_wrap_ex
                            );
                        }
                        SigToCoorResponse::SigningResponseEx(signing_response_wrap_ex) => {
                            tracing::info!(
                                "Signer received signing ex response: {:?}",
                                signing_response_wrap_ex
                            );
                        }
                    }
                } else {
                    if self
                        .dkg_out_response_channels_mapping
                        .contains_key(&request_id)
                    {
                        let r = self
                            .dkg_out_response_channels_mapping
                            .remove(&request_id)
                            .unwrap();
                        // convert SigToCoorResponse to DKGResponseWrapEx
                        if let SigToCoorResponse::DKGResponseEx(dkg_response_wrap_ex) = response {
                            r.send(Ok(dkg_response_wrap_ex)).unwrap();
                        } else {
                            r.send(Err(SessionError::InvalidResponse(format!(
                                "Received invalid response type: {:?}",
                                response
                            ))))
                            .unwrap();
                        }
                    } else if self
                        .signing_out_response_channels_mapping
                        .contains_key(&request_id)
                    {
                        let r = self
                            .signing_out_response_channels_mapping
                            .remove(&request_id)
                            .unwrap();
                        // convert SigToCoorResponse to SigningResponseWrapEx
                        if let SigToCoorResponse::SigningResponseEx(signing_response_wrap_ex) =
                            response
                        {
                            r.send(Ok(signing_response_wrap_ex)).unwrap();
                        } else {
                            r.send(Err(SessionError::InvalidResponse(format!(
                                "Received invalid response type: {:?}",
                                response
                            ))))
                            .unwrap();
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
            Result<DKGResponseWrap<VI::Identity>, SessionError>,
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
                        tracing::info!(
                            "Signer sent dkg response to coordinator successfully with request_id: {}",
                            id
                        );
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
    pub(crate) async fn dkg_handle_response_ex(
        &mut self,
        response: (InboundRequestId, Result<DKGResponseWrapEx, SessionError>),
    ) -> Result<(), anyhow::Error> {
        let request_id = response.0;
        match response.1 {
            Ok(response) => {
                let channel = self.channel_mapping.remove(&request_id).unwrap();
                let r = self
                    .swarm
                    .behaviour_mut()
                    .coor2sig
                    .send_response(channel, CoorToSigResponse::DKGResponseEx(response.clone()));
                match r {
                    Ok(_) => {
                        tracing::info!(
                            "Signer sent dkg ex response to coordinator successfully with request_id: {}",
                            request_id
                        );
                    }
                    Err(e) => {
                        tracing::error!("Failed to send dkg ex response to coordinator: {:?}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to handle response: {:?}", e);
            }
        }
        Ok(())
    }
    pub(crate) async fn signing_handle_response_ex(
        &mut self,
        response: (
            InboundRequestId,
            Result<SigningResponseWrapEx, SessionError>,
        ),
    ) -> Result<(), anyhow::Error> {
        let request_id = response.0;
        match response.1 {
            Ok(response) => {
                let channel = self.channel_mapping.remove(&request_id).unwrap();
                let r = self.swarm.behaviour_mut().coor2sig.send_response(
                    channel,
                    CoorToSigResponse::SigningResponseEx(response.clone()),
                );
                match r {
                    Ok(_) => {
                        tracing::info!(
                            "Signer sent signing ex response to coordinator successfully with request_id: {}",
                            request_id
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to send signing ex response to coordinator: {:?}",
                            e
                        );
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
            Result<SigningResponseWrap<VI::Identity>, SessionError>,
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
                        tracing::info!(
                            "Signer sent signing response to coordinator successfully with request_id: {}",
                            request_id
                        );
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
    pub(crate) async fn handle_signer2coor_request(
        &mut self,
        request: RequestEx<VI::Identity>,
    ) -> Result<OutboundRequestId, anyhow::Error> {
        match request {
            RequestEx::DKGEx(request, response_sender) => {
                let request_id = self.swarm.behaviour_mut().sig2coor.send_request(
                    &self.coordinator_peer_id,
                    SigToCoorRequest::DKGRequestEx(request),
                );
                self.dkg_out_response_channels_mapping
                    .insert(request_id, response_sender);
                return Ok(request_id);
            }
            RequestEx::SigningEx(request, response_sender) => {
                let request_id = self.swarm.behaviour_mut().sig2coor.send_request(
                    &self.coordinator_peer_id,
                    SigToCoorRequest::SigningRequestEx(request),
                );
                self.signing_out_response_channels_mapping
                    .insert(request_id, response_sender);
                return Ok(request_id);
            }
        }
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
                tracing::debug!("Received command: {}", line);
                let command = Command::parse(&line);
                match command {
                    Command::PeerId => {
                        tracing::debug!("Sending peer id");
                        reader.get_mut().write_all(format!("p2p peer id: {}\nvalidator peer id: {}\ncoordinator peer id: {}", self.p2p_keypair.public().to_peer_id().to_base58(), self.validator_keypair.to_public_key().to_identity().to_fmt_string(), self.coordinator_multiaddr.to_string()).as_bytes()).await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::Help => {
                        tracing::debug!("Sending help text");
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
                        tracing::debug!("Sending coordinator peer id");
                        reader
                            .get_mut()
                            .write_all(self.coordinator_multiaddr.to_string().as_bytes())
                            .await?;
                        reader.get_mut().write_all(b"\n").await?;
                    }
                    Command::P2pPeerId => {
                        tracing::debug!("Sending p2p peer id");
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
                        tracing::debug!("Pinging coordinator");
                        if let Err(e) = self.dial_coordinator() {
                            reader.get_mut().write_all(e.to_string().as_bytes()).await?;
                        } else {
                            reader.get_mut().write_all(b"Coordinator pinged\n").await?;
                        }
                    }
                    Command::Unknown(cmd) => {
                        tracing::debug!("Unknown command: {}", cmd);
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
        tracing::info!("Signer IPC Listening on {:?}", self.ipc_path);
        if self.ipc_path.exists() {
            std::fs::remove_file(&self.ipc_path)?;
        } else {
            std::fs::create_dir_all(
                self.ipc_path
                    .parent()
                    .ok_or(anyhow::anyhow!("Failed to get parent dir"))?,
            )?;
        }

        let listener = UnixListener::bind(&self.ipc_path)?;
        return Ok(listener);
    }
}
