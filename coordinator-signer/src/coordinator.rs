use crate::behaviour::{
    CoorBehaviour, CoorBehaviourEvent, CoorToSigRequest, CoorToSigResponse, SigToCoorRequest,
    SigToCoorResponse, ValidatorIdentityRequest,
};
use crate::crypto::*;
use crate::utils::*;
use common::Settings;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hex::{FromHex, ToHex};
use libp2p::request_response::{OutboundFailure, OutboundRequestId, ProtocolSupport};
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subsession::{SignatureSuite, SubSessionId, PKID};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, RwLock};
mod command;
use command::Command;
pub struct Coordinator<VI: ValidatorIdentity> {
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<CoorBehaviour<VI::Identity>>,
    ipc_path: PathBuf,
    sessions: HashMap<SessionId<VI::Identity>, Session<VI>>,
    valid_validators: HashMap<VI::Identity, ValidValidator<VI>>,
    p2ppeerid_2_endpoint: HashMap<PeerId, Multiaddr>,
    dkg_request_mapping:
        HashMap<OutboundRequestId, (oneshot::Sender<DKGSingleResponse<VI::Identity>>, PeerId)>,
    signing_request_mapping:
        HashMap<OutboundRequestId, (oneshot::Sender<SigningSingleResponse<VI::Identity>>, PeerId)>,
    signing_session_futures:
        futures::stream::FuturesUnordered<oneshot::Receiver<SigningSession<VI>>>,
    session_receiver: UnboundedReceiver<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKGSingleResponse<VI::Identity>>,
    )>,
    session_sender: UnboundedSender<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKGSingleResponse<VI::Identity>>,
    )>,
    signing_session_sender: UnboundedSender<(
        SigningSingleRequest<VI::Identity>,
        oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    )>,
    signing_session_receiver: UnboundedReceiver<(
        SigningSingleRequest<VI::Identity>,
        oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    )>,
    signing_sessions: HashMap<PKID, SigningSession<VI>>,
    signature_sender: UnboundedSender<SignatureSuite<VI>>,
    signature_receiver: UnboundedReceiver<SignatureSuite<VI>>,

    reply_sender: HashMap<SubSessionId<VI::Identity>, oneshot::Sender<SignatureSuite<VI>>>,
}
impl<VI: ValidatorIdentity> Coordinator<VI> {
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
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(1000)))
            .build();
        let (session_sender, session_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (signing_session_sender, signing_session_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let (signature_sender, signature_receiver) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            p2p_keypair,
            swarm,
            ipc_path: Settings::global().coordinator.ipc_socket_path.into(),
            sessions: HashMap::new(),
            valid_validators: HashMap::new(),
            p2ppeerid_2_endpoint: HashMap::new(),
            dkg_request_mapping: HashMap::new(),
            signing_request_mapping: HashMap::new(),
            session_sender,
            session_receiver,
            signing_session_sender,
            signing_session_receiver,
            signing_session_futures: FuturesUnordered::new(),
            signing_sessions: HashMap::new(),
            signature_sender,
            signature_receiver,
            reply_sender: HashMap::new(),
        })
    }

    pub async fn start_listening(mut self) -> Result<(), anyhow::Error> {
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
                recv_data = self.session_receiver.recv()=> {
                    tracing::info!("Received DKG request from session");
                    if let Some((request, sender)) = recv_data {
                        if let Err(e) = self.handle_dkg_request(request, sender).await {
                            tracing::error!("Error handling DKG request: {}", e);
                        }
                    } else {
                        tracing::error!("Error receiving DKG request");
                    }
                }
                recv_data = self.signing_session_receiver.recv()=> {
                    if let Some((request, sender)) = recv_data {
                        if let Err(e) = self.handle_signing_request(request, sender).await {
                            tracing::error!("Error handling signing request: {}", e);
                        }
                    } else {
                        tracing::error!("Error receiving signing request");
                    }
                }
                command_result = listener.accept()=> {
                    if let Err(e) = self.handle_command(command_result).await {
                        tracing::error!("Error handling command: {}", e);
                    }
                }
                signature_result = self.signature_receiver.recv() => {
                    if let Some(signature_suite) = signature_result {
                        tracing::info!("Received signature suite {}", signature_suite);
                        self.reply_sender.remove(&signature_suite.subsession_id).unwrap().send(signature_suite).unwrap();

                    }
                }
                signing_session_future = self.signing_session_futures.next() => {
                    if let Some(signing_session) = signing_session_future {
                        match signing_session {
                            Ok(signing_session) => {
                                tracing::info!("Received signing session {:?}", signing_session.pkid.clone());
                                self.signing_sessions.insert(signing_session.pkid.clone(), signing_session);
                            }
                            Err(e) => {
                                tracing::error!("Error receiving signing session: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
    pub async fn handle_dkg_request(
        &mut self,
        request: DKGSingleRequest<VI::Identity>,
        sender: oneshot::Sender<DKGSingleResponse<VI::Identity>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Received DKG request From Session: {:?}", request);
        let peer = request.get_identity();
        let validator = self.valid_validators.get(peer).cloned();
        match validator {
            Some(validator) => {
                tracing::info!(
                    "Sending DKG request to validator: {:?}",
                    validator.p2p_peer_id
                );
                if let Some(addr) = validator.address {
                    self.swarm
                        .behaviour_mut()
                        .sig2coor
                        .add_address(&validator.p2p_peer_id, addr);
                }
                let outbound_request_id = self.swarm.behaviour_mut().coor2sig.send_request(
                    &validator.p2p_peer_id,
                    CoorToSigRequest::DKGRequest(request),
                );
                tracing::info!("Outbound request id: {:?}", outbound_request_id);
                self.dkg_request_mapping
                    .insert(outbound_request_id, (sender, validator.p2p_peer_id.clone()));
            }
            None => {
                tracing::error!("Validator not found");
                if let Err(e) = sender.send(DKGSingleResponse::Failure(format!(
                    "Validator not found: {}",
                    peer.to_fmt_string()
                ))) {
                    tracing::error!("Error sending failure response: {:?}", e);
                    return Err(anyhow::anyhow!("Error sending failure response: {:?}", e));
                }
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn handle_signing_request(
        &mut self,
        request: SigningSingleRequest<VI::Identity>,
        sender: oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Received Signing request From Session: {:?}", request);
        let peer = request.get_identity();
        let validator = self.valid_validators.get(peer).cloned();
        match validator {
            Some(validator) => {
                tracing::info!(
                    "Sending Signing request to validator: {:?}",
                    validator.p2p_peer_id
                );
                if let Some(addr) = validator.address {
                    self.swarm
                        .behaviour_mut()
                        .sig2coor
                        .add_address(&validator.p2p_peer_id, addr);
                }
                let outbound_request_id = self.swarm.behaviour_mut().coor2sig.send_request(
                    &validator.p2p_peer_id,
                    CoorToSigRequest::SigningRequest(request),
                );
                tracing::info!("Outbound request id: {:?}", outbound_request_id);
                self.signing_request_mapping
                    .insert(outbound_request_id, (sender, validator.p2p_peer_id.clone()));
            }
            None => {
                tracing::error!("Validator not found");
                if let Err(e) = sender.send(SigningSingleResponse::Failure(format!(
                    "Validator not found: {}",
                    peer.to_fmt_string()
                ))) {
                    tracing::error!("Error sending failure response: {:?}", e);
                    return Err(anyhow::anyhow!("Error sending failure response: {:?}", e));
                }
                return Ok(());
            }
        }
        Ok(())
    }

    pub async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<CoorBehaviourEvent<VI::Identity>>,
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
                // self.p2ppeerid_2_endpoint.remove(&peer_id);
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => {
                tracing::error!("Outgoing connection error: {:?}", error);
            }
            SwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
            } => {
                tracing::error!("Incoming connection error: {:?}", error);
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                tracing::error!("Listener error: {:?}", error);
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
            SwarmEvent::Behaviour(CoorBehaviourEvent::Coor2sig(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    connection_id,
                },
            )) => match response {
                CoorToSigResponse::DKGResponse(response) => {
                    tracing::info!(
                        "Received response from {:?} with request_id {:?}",
                        peer,
                        request_id
                    );
                    let (_, validator_peer_id) = self.dkg_request_mapping.get(&request_id).unwrap();
                    if *validator_peer_id != peer {
                        tracing::warn!("Invalid validator peer id: {:?}", validator_peer_id);
                        return Ok(());
                    }
                    if let Some((sender, _)) = self.dkg_request_mapping.remove(&request_id) {
                        tracing::info!("Sending response {:?} to session", response);
                        if let Err(e) = sender.send(response) {
                            tracing::error!("Error sending response: {:?}", e);
                        } else {
                            tracing::info!("Sent response to session");
                        }
                    } else {
                        tracing::error!("Request id {:?} not found in request mapping", request_id);
                    }
                }
                CoorToSigResponse::SigningResponse(response) => {
                    tracing::info!(
                        "Received response from {:?} with request_id {:?}",
                        peer,
                        request_id
                    );
                    let (_, validator_peer_id) =
                        self.signing_request_mapping.get(&request_id).unwrap();
                    if *validator_peer_id != peer {
                        tracing::warn!("Invalid validator peer id: {:?}", validator_peer_id);
                        return Ok(());
                    }
                    if let Some((sender, _)) = self.signing_request_mapping.remove(&request_id) {
                        tracing::info!("Sending response {:?} to session", response);
                        if let Err(e) = sender.send(response) {
                            tracing::error!("Error sending response: {:?}", e);
                        }
                    }
                }
            },
            SwarmEvent::Behaviour(CoorBehaviourEvent::Sig2coor(
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
                tracing::debug!(
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
                        let public_key = VI::PublicKey::from_bytes(public_key)
                            .inspect_err(|e| tracing::error!("Invalid public key: {}", e))?;
                        let validator_peer = public_key.to_identity();
                        if !Settings::global()
                            .coordinator
                            .peer_id_whitelist
                            .contains(&validator_peer.to_fmt_string())
                        {
                            tracing::warn!(
                                "Validator peerid {} is not in whitelist",
                                validator_peer.to_fmt_string()
                            );
                            let _ = self.swarm.behaviour_mut().sig2coor.send_response(
                                channel,
                                SigToCoorResponse::Failure(format!(
                                    "Validator peerid {} is not in whitelist",
                                    validator_peer.to_fmt_string()
                                ))
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
                            let address = self.p2ppeerid_2_endpoint.get(&peer).cloned();
                            let new_validator = ValidValidator {
                                p2p_peer_id: peer,
                                validator_peer_id: validator_peer.clone(),
                                validator_public_key: public_key,
                                nonce,
                                address,
                            };

                            let old_validator = self.valid_validators.get(&validator_peer).cloned();

                            let should_insert = match &old_validator {
                                Some(v) => v.nonce < nonce,
                                None => true,
                            };

                            if should_insert {
                                self.valid_validators
                                    .insert(validator_peer.clone(), new_validator.clone());
                            }

                            tracing::info!(
                                "Validator_peerid: {}, p2p_peerid : {}, total validators: {}",
                                validator_peer.to_fmt_string(),
                                peer,
                                self.valid_validators.len()
                            );

                            if old_validator.is_none() {
                                tracing::info!("{:#?}", new_validator);
                            } else {
                                tracing::info!("{:#?}", old_validator.unwrap());
                                tracing::info!("{:#?}", new_validator);
                            }

                            if let Some(addr) = self.p2ppeerid_2_endpoint.get(&peer) {
                                self.swarm.add_peer_address(peer, addr.clone());
                            }

                            // Send success response
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .sig2coor
                                .send_response(channel, SigToCoorResponse::Success.into());
                        } else {
                            tracing::error!(
                                "Invalid signature from validator {}",
                                validator_peer.to_fmt_string()
                            );
                            return Err(anyhow::anyhow!(
                                "Invalid signature from validator {}",
                                validator_peer.to_fmt_string()
                            ));
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id,
                connection_id,
                error,
            } => {
                tracing::error!("Outbound failure: {:?}", error);
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
                        // dump the validators info
                        for validator in self.valid_validators.values() {
                            reader
                                .get_mut()
                                .write_all(format!("{:#?}", validator).as_bytes())
                                .await?;
                            reader.get_mut().write_all(b"\n").await?;
                        }
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
                    Command::Dial(peer_id) => {
                        tracing::info!("Dialing to peer {}", peer_id);
                        if let Ok(peer_id) = PeerId::from_str(&peer_id) {
                            if let Err(e) = self.swarm.dial(peer_id) {
                                tracing::error!("Error dialing to peer {}: {}", peer_id, e);
                            }
                        } else if let Ok(address) = Multiaddr::from_str(&peer_id) {
                            if let Err(e) = self.swarm.dial(address) {
                                tracing::error!("Error dialing to peer {}: {}", peer_id, e);
                            }
                        } else {
                            tracing::error!("Invalid peer id: {}", peer_id);
                        }
                    }
                    Command::Sign(pkid, msg) => {
                        tracing::info!("Received sign request: {}", msg);
                        let pkid = PKID::from(pkid);
                        let (sender, receiver) = oneshot::channel();
                        if let Some(session) = self.signing_sessions.get_mut(&pkid) {
                            match session.start_new_signing(msg).await {
                                Ok(subsession_id) => {
                                    reader
                                        .get_mut()
                                        .write_all(
                                            format!("Subsession id: {}", subsession_id.to_string())
                                                .as_bytes(),
                                        )
                                        .await?;
                                    self.reply_sender.insert(subsession_id, sender);
                                    tokio::spawn(async move {
                                        let recv = receiver.await.unwrap();
                                        reader
                                            .get_mut()
                                            .write_all(recv.to_string().as_bytes())
                                            .await
                                            .unwrap();
                                        reader.get_mut().write_all(b"\n").await.unwrap();
                                    });
                                }
                                Err(e) => {
                                    reader
                                        .get_mut()
                                        .write_all(
                                            format!("Error starting new signing: {}", e).as_bytes(),
                                        )
                                        .await?;
                                }
                            }
                        } else {
                            reader.get_mut().write_all(b"Session not found\n").await?;
                        }
                    }
                    Command::ListPkId => {
                        tracing::info!("Received list pkid request");
                        for pkid in self.signing_sessions.keys() {
                            tracing::info!("PKID: {}", pkid);
                        }
                    }
                    Command::StartDkg(min_signers, crypto_type) => {
                        tracing::debug!(
                            "Starting DKG with min_signers: {}, crypto_type: {:?}",
                            min_signers,
                            crypto_type
                        );
                        let mut participants = Vec::new();
                        if min_signers > self.valid_validators.len() as u16 {
                            let msg = format!(
                                "Not enough validators to start DKG, min_signers: {}, validators: {}",
                                min_signers,
                                self.valid_validators.len()
                            );
                            tracing::debug!("{}", msg);
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        if self.valid_validators.len() > 255 {
                            let msg = format!(
                                "Too many validators to start DKG, max is 255, got {}",
                                self.valid_validators.len()
                            );
                            tracing::debug!("{}", msg);
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        if min_signers < (self.valid_validators.len() as u16 + 1) / 2
                            || min_signers == 0
                        {
                            let msg = format!(
                                "Min signers is too low, min_signers: {}, validators: {}",
                                min_signers,
                                self.valid_validators.len()
                            );
                            tracing::debug!("{}", msg);
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        tracing::debug!(
                            "Adding {} validators as participants",
                            self.valid_validators.len()
                        );
                        for (i, validator) in self.valid_validators.values().enumerate() {
                            tracing::debug!(
                                "Adding validator {} with peer id {}",
                                i + 1,
                                validator.validator_peer_id.to_fmt_string()
                            );
                            participants
                                .push(((i + 1) as u16, validator.validator_peer_id.clone()));
                        }
                        tracing::debug!("Creating new session");
                        let session = Session::<VI>::new(
                            crypto_type,
                            participants.clone(),
                            min_signers,
                            self.session_sender.clone(),
                        );

                        if let Err(e) = session {
                            let msg = format!("Error creating session: {}", e);
                            tracing::debug!("{}", msg);
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        let session = session.unwrap();
                        tracing::debug!("Starting session");
                        let (tx, rx) = oneshot::channel();
                        self.signing_session_futures.push(rx);
                        session
                            .start(
                                tx,
                                self.signing_session_sender.clone(),
                                self.signature_sender.clone(),
                            )
                            .await;
                        // accept ctrl+c to stop
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
