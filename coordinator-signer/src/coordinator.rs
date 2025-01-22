mod command;
mod manager;
mod session;
use crate::crypto::*;
use crate::types::message::{
    CoorBehaviour, CoorBehaviourEvent, CoorToSigRequest, CoorToSigResponse, DKGRequestWrap,
    DKGResponseWrap, SigToCoorRequest, SigToCoorResponse, SigningRequestWrap, SigningResponseWrap,
    ValidatorIdentityRequest,
};
use crate::types::Validator;
use crate::utils::*;
use command::Command;
use common::Settings;
use futures::StreamExt;
use libp2p::request_response::{OutboundRequestId, ProtocolSupport};
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use manager::Instruction;
use session::SessionWrap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::SocketAddr;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
pub struct Coordinator<VI: ValidatorIdentity> {
    p2p_keypair: libp2p::identity::Keypair,
    swarm: libp2p::Swarm<CoorBehaviour<VI::Identity>>,
    ipc_path: PathBuf,
    valid_validators: HashMap<VI::Identity, Validator<VI>>,
    p2ppeerid_2_endpoint: HashMap<PeerId, Multiaddr>,
    dkg_request_mapping:
        HashMap<OutboundRequestId, (oneshot::Sender<DKGResponseWrap<VI::Identity>>, PeerId)>,
    signing_request_mapping:
        HashMap<OutboundRequestId, (oneshot::Sender<SigningResponseWrap<VI::Identity>>, PeerId)>,

    dkg_session_receiver: UnboundedReceiver<(
        DKGRequestWrap<VI::Identity>,
        oneshot::Sender<DKGResponseWrap<VI::Identity>>,
    )>,
    signing_session_receiver: UnboundedReceiver<(
        SigningRequestWrap<VI::Identity>,
        oneshot::Sender<SigningResponseWrap<VI::Identity>>,
    )>,
    instruction_sender: UnboundedSender<Instruction<VI::Identity>>,
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
        let (dkg_session_sender, dkg_session_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (signing_session_sender, signing_session_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let (instruction_sender, instruction_receiver) = tokio::sync::mpsc::unbounded_channel();
        manager::CoordiantorSessionManager::new(
            instruction_receiver,
            dkg_session_sender,
            signing_session_sender,
        )
        .listening();
        Ok(Self {
            p2p_keypair,
            swarm,
            ipc_path: Settings::global().coordinator.ipc_socket_path.into(),
            valid_validators: HashMap::new(),
            p2ppeerid_2_endpoint: HashMap::new(),
            dkg_request_mapping: HashMap::new(),
            signing_request_mapping: HashMap::new(),
            dkg_session_receiver,
            signing_session_receiver,
            instruction_sender,
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
                recv_data = self.dkg_session_receiver.recv()=> {
                    tracing::info!("Received DKG request from session {:?}", recv_data);
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
            }
        }
    }
    pub async fn handle_dkg_request(
        &mut self,
        request: DKGRequestWrap<VI::Identity>,
        sender: oneshot::Sender<DKGResponseWrap<VI::Identity>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Received DKG request From Session: {:?}", request);
        let peer = request.identity();
        let validator = self.valid_validators.get(peer).cloned();
        match validator {
            Some(validator) => {
                tracing::info!(
                    "Sending DKG request to validator: {:?}",
                    validator.p2p_peer_id
                );
                if let Some(addr) = validator.address {
                    self.swarm.add_peer_address(validator.p2p_peer_id, addr);
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
                if let Err(e) = sender
                    .send(request.failure(format!("Validator not found: {}", peer.to_fmt_string())))
                {
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
        request: SigningRequestWrap<VI::Identity>,
        sender: oneshot::Sender<SigningResponseWrap<VI::Identity>>,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("Received Signing request From Session: {:?}", request);
        let peer = request.identity();
        let validator = self.valid_validators.get(peer).cloned();
        match validator {
            Some(validator) => {
                tracing::info!(
                    "Sending Signing request to validator: {:?}",
                    validator.p2p_peer_id
                );
                if let Some(addr) = validator.address {
                    self.swarm.add_peer_address(validator.p2p_peer_id, addr);
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
                if let Err(e) = sender
                    .send(request.failure(format!("Validator not found: {}", peer.to_fmt_string())))
                {
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
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                tracing::error!("Outgoing connection error: {:?}", error);
            }
            SwarmEvent::IncomingConnectionError { error, .. } => {
                tracing::error!("Incoming connection error: {:?}", error);
            }
            SwarmEvent::ListenerError { error, .. } => {
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
                    ..
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
                    ..
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
                            let new_validator = Validator {
                                p2p_peer_id: peer,
                                validator_peer_id: validator_peer.clone(),
                                _validator_public_key: public_key,
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
                        let pkid = PkId::from(pkid);
                        let (sender, receiver) = oneshot::channel();
                        self.instruction_sender
                            .send(Instruction::Sign {
                                pkid,
                                msg: msg.as_bytes().to_vec(),
                                signature_response_oneshot: sender,
                            })
                            .unwrap();
                        tokio::spawn(async move {
                            let result = receiver.await.unwrap();
                            match result {
                                Ok(signature) => {
                                    reader
                                        .get_mut()
                                        .write_all(signature.pretty_print_original().as_bytes())
                                        .await
                                        .unwrap();
                                    reader.get_mut().write_all(b"\n").await.unwrap();
                                }
                                Err(e) => {
                                    tracing::error!("Error signing: {}", e);
                                    reader
                                        .get_mut()
                                        .write_all(e.to_string().as_bytes())
                                        .await
                                        .unwrap();
                                    reader.get_mut().write_all(b"\n").await.unwrap();
                                }
                            }
                        });
                    }
                    Command::ListPkId => {
                        tracing::info!("Received list pkid request");
                        let (sender, receiver) = oneshot::channel();
                        self.instruction_sender
                            .send(Instruction::ListPkIds {
                                list_pkids_response_oneshot: sender,
                            })
                            .unwrap();
                        let pkids = receiver.await.unwrap();
                        for (crypto_type, pkids) in pkids {
                            reader
                                .get_mut()
                                .write_all(format!("{:?}: {:?}\n", crypto_type, pkids).as_bytes())
                                .await?;
                        }
                    }
                    Command::StartDkg(min_signers, crypto_type) => {
                        let mut participants = Vec::new();
                        for (i, validator) in self.valid_validators.values().enumerate() {
                            tracing::debug!(
                                "Adding validator {} with peer id {}",
                                i + 1,
                                validator.validator_peer_id.to_fmt_string()
                            );
                            participants
                                .push(((i + 1) as u16, validator.validator_peer_id.clone()));
                        }
                        let (sender, receiver) = oneshot::channel();
                        self.instruction_sender
                            .send(Instruction::NewKey {
                                min_signers,
                                crypto_type,
                                participants,
                                pkid_response_oneshot: sender,
                            })
                            .unwrap();
                        tokio::spawn(async move {
                            let result = receiver.await.unwrap();
                            match result {
                                Ok(pkid) => {
                                    reader.get_mut().write_all(b"Success\n").await.unwrap();
                                    reader
                                        .get_mut()
                                        .write_all(pkid.to_string().as_bytes())
                                        .await
                                        .unwrap();
                                    reader.get_mut().write_all(b"\n").await.unwrap();
                                }
                                Err(e) => {
                                    let msg = format!("Error starting DKG: {}", e);
                                    tracing::debug!("{}", msg);
                                    reader.get_mut().write_all(msg.as_bytes()).await.unwrap();
                                    reader.get_mut().write_all(b"\n").await.unwrap();
                                }
                            }
                        });
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
