use crate::behaviour::{
    CoorBehaviour, CoorBehaviourEvent, CoorToSigRequest, SigToCoorRequest, SigToCoorResponse,
    ValidatorIdentityRequest,
};
use crate::crypto::*;
use crate::utils::*;
use common::Settings;
use futures::StreamExt;
use libp2p::request_response::ProtocolSupport;
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};
use libp2p::{ping, rendezvous, request_response, PeerId, StreamProtocol};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
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
    swarm: libp2p::Swarm<CoorBehaviour>,
    ipc_path: PathBuf,
    sessions: HashMap<SessionId<VI::Identity>, Session<VI>>,
    valid_validators: HashMap<VI::Identity, ValidValidator<VI>>,
    p2ppeerid_2_endpoint: HashMap<PeerId, Multiaddr>,
    session_receiver: UnboundedReceiver<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKSingleResponse<VI::Identity>>,
    )>,
    session_sender: UnboundedSender<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKSingleResponse<VI::Identity>>,
    )>,
}
impl<VI: ValidatorIdentity + 'static> Coordinator<VI> {
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
        let (session_sender, session_receiver) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            p2p_keypair,
            swarm,
            ipc_path: Settings::global().coordinator.ipc_socket_path.into(),
            sessions: HashMap::new(),
            valid_validators: HashMap::new(),
            p2ppeerid_2_endpoint: HashMap::new(),
            session_sender,
            session_receiver,
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
                    Command::StartDkg(min_signers, crypto_type) => {
                        let mut participants = Vec::new();
                        if min_signers > self.valid_validators.len() as u16 {
                            let msg = format!(
                                "Not enough validators to start DKG, min_signers: {}, validators: {}",
                                min_signers,
                                self.valid_validators.len()
                            );
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        if self.valid_validators.len() > 255 {
                            let msg = format!(
                                "Too many validators to start DKG, max is 255, got {}",
                                self.valid_validators.len()
                            );
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
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        for (i, validator) in self.valid_validators.values().enumerate() {
                            participants
                                .push(((i + 1) as u16, validator.validator_peer_id.clone()));
                        }
                        let session = Session::<VI>::new(
                            crypto_type,
                            participants.clone(),
                            min_signers,
                            self.session_sender.clone(),
                        );

                        if let Err(e) = session {
                            let msg = format!("Error creating session: {}", e);
                            reader.get_mut().write_all(msg.as_bytes()).await?;
                            reader.get_mut().write_all(b"\n").await?;
                            return Err(anyhow::anyhow!(msg));
                        }
                        let session = session.unwrap();
                        session.start().await;
                        for validator in self.valid_validators.values() {
                            self.swarm
                                .behaviour_mut()
                                .coor2sig
                                .send_request(&validator.p2p_peer_id, CoorToSigRequest::StartDkg);
                        }
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
