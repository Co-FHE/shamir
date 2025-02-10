use dashmap::DashMap;
use libp2p::request_response::{OutboundRequestId, ProtocolSupport};
use libp2p::{request_response, PeerId, StreamProtocol};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot;

use common::Settings;
use futures::StreamExt;
use libp2p::{
    identify::{self},
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr,
};

use crate::crypto::{CryptoType, PkId};
use crate::crypto::{
    ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};
use crate::types::message::{
    NodeBehaviour, NodeBehaviourEvent, NodeToCoorRequest, NodeToCoorResponse,
    ValidatorIdentityRequest,
};
use crate::types::{AutoDKG, ConnectionState, GroupPublicKeyInfo, SignatureSuiteInfo};
use crate::utils::list_hash;

pub(crate) struct NodeSwarm<VI: ValidatorIdentity> {
    swarm: libp2p::Swarm<NodeBehaviour<VI::Identity>>,
    coordinator_addr: Multiaddr,
    dkg_response_mapping: DashMap<OutboundRequestId, oneshot::Sender<Result<PkId, String>>>,
    signing_response_mapping: DashMap<
        OutboundRequestId,
        oneshot::Sender<Result<SignatureSuiteInfo<VI::Identity>, String>>,
    >,
    coordinator_peer_id: PeerId,
    dkg_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<PkId, String>>,
    )>,
    auto_dkg_response_mapping:
        DashMap<OutboundRequestId, oneshot::Sender<Result<AutoDKG<VI::Identity>, String>>>,
    lspk_response_mapping:
        DashMap<OutboundRequestId, oneshot::Sender<Result<HashMap<CryptoType, Vec<PkId>>, String>>>,
    pk_response_mapping:
        DashMap<OutboundRequestId, oneshot::Sender<Result<GroupPublicKeyInfo, String>>>,
    signing_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<SignatureSuiteInfo<VI::Identity>, String>>,
    )>,
    lspk_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<HashMap<CryptoType, Vec<PkId>>, String>>,
    )>,
    pk_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<GroupPublicKeyInfo, String>>,
    )>,
    auto_dkg_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<AutoDKG<VI::Identity>, String>>,
    )>,
    connection_state: ConnectionState,
}
impl<VI: ValidatorIdentity> NodeSwarm<VI> {
    pub fn new(
        p2p_keypair: libp2p::identity::Keypair,
        coordinator_addr: Multiaddr,
        coordinator_peer_id: PeerId,
        dkg_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
            NodeToCoorRequest<VI::Identity>,
            oneshot::Sender<Result<PkId, String>>,
        )>,
        signing_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
            NodeToCoorRequest<VI::Identity>,
            oneshot::Sender<Result<SignatureSuiteInfo<VI::Identity>, String>>,
        )>,
        lspk_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
            NodeToCoorRequest<VI::Identity>,
            oneshot::Sender<Result<HashMap<CryptoType, Vec<PkId>>, String>>,
        )>,
        auto_dkg_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
            NodeToCoorRequest<VI::Identity>,
            oneshot::Sender<Result<AutoDKG<VI::Identity>, String>>,
        )>,
        pk_request_receiver: tokio::sync::mpsc::UnboundedReceiver<(
            NodeToCoorRequest<VI::Identity>,
            oneshot::Sender<Result<GroupPublicKeyInfo, String>>,
        )>,
    ) -> Result<Self, anyhow::Error> {
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(p2p_keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| NodeBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    "/ipfs/id/1.0.0".to_string(),
                    key.public(),
                )),
                // rendezvous: rendezvous::client::Behaviour::new(key.clone()),
                node2coor: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/node2coor"), ProtocolSupport::Full)],
                    request_response::Config::default(),
                ),
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(1000)))
            .build();
        swarm.add_peer_address(coordinator_peer_id, coordinator_addr.clone());
        swarm.dial(coordinator_addr.clone())?;

        return Ok(Self {
            swarm,
            coordinator_addr,
            coordinator_peer_id,
            dkg_response_mapping: DashMap::new(),
            auto_dkg_response_mapping: DashMap::new(),
            signing_response_mapping: DashMap::new(),
            lspk_response_mapping: DashMap::new(),
            pk_response_mapping: DashMap::new(),
            dkg_request_receiver: dkg_request_receiver,
            auto_dkg_request_receiver: auto_dkg_request_receiver,
            signing_request_receiver: signing_request_receiver,
            lspk_request_receiver: lspk_request_receiver,
            pk_request_receiver: pk_request_receiver,
            connection_state: ConnectionState::Disconnected(None),
        });
    }
    async fn start_listening(mut self) {
        tokio::spawn(async move {
            loop {
                match self.connection_state {
                    ConnectionState::Disconnected(None) => {
                        if let Err(e) = self.dial_coordinator() {
                            tracing::error!("Failed to dial coordinator: {}", e);
                        }
                        self.connection_state =
                            ConnectionState::Connecting(tokio::time::Instant::now());
                    }
                    ConnectionState::Disconnected(Some(last_connecting_time)) => {
                        let elapsed = last_connecting_time.elapsed();
                        if elapsed
                            > Duration::from_secs(
                                common::Settings::global().signer.connection_timeout,
                            )
                        {
                            if let Err(e) = self.dial_coordinator() {
                                tracing::error!("Failed to dial coordinator: {}", e);
                            }
                            self.connection_state =
                                ConnectionState::Connecting(tokio::time::Instant::now());
                        } else {
                            tokio::time::sleep(
                                Duration::from_secs(
                                    common::Settings::global().signer.connection_timeout,
                                ) - elapsed,
                            )
                            .await;
                            if let Err(e) = self.dial_coordinator() {
                                tracing::error!("Failed to dial coordinator: {}", e);
                            }
                            self.connection_state =
                                ConnectionState::Connecting(tokio::time::Instant::now());
                        }
                    }
                    ConnectionState::Connecting(start_time) => {
                        if start_time.elapsed()
                            > Duration::from_secs(
                                common::Settings::global().signer.connection_timeout,
                            )
                        {
                            if let Err(e) = self.dial_coordinator() {
                                tracing::error!("Failed to dial coordinator: {}", e);
                            }
                            self.connection_state =
                                ConnectionState::Connecting(tokio::time::Instant::now());
                        }
                    }
                    ConnectionState::Connected => {}
                }
                if self.connection_state == ConnectionState::Connected {
                    tokio::select! {
                            event = self.swarm.select_next_some()=> {
                                tracing::debug!("{:?}",event);
                            if let Err(e) = self.handle_swarm_event(event).await {
                                tracing::error!("Error handling behaviour event: {}", e);
                            }
                        },
                        Some((request, sender)) = self.dkg_request_receiver.recv()=>{
                            if self.connection_state != ConnectionState::Connected {
                            }
                            self.dkg_handle_request(request, sender);
                        }
                        Some((request, sender)) = self.signing_request_receiver.recv()=>{
                            self.signing_handle_request(request, sender);
                        }
                        Some((request, sender)) = self.lspk_request_receiver.recv()=>{
                            self.handle_lspk_request(request, sender);
                        }
                        Some((request, sender)) = self.pk_request_receiver.recv()=>{
                            self.handle_pk_request(request, sender);
                        }
                        Some((request, sender)) = self.auto_dkg_request_receiver.recv()=>{
                            self.handle_auto_dkg_request(request, sender);
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
        });
    }
    pub(crate) fn dial_coordinator(&mut self) -> Result<(), anyhow::Error> {
        self.swarm.dial(self.coordinator_addr.clone())?;
        Ok(())
    }
    pub(crate) fn dkg_handle_request(
        &mut self,
        request: NodeToCoorRequest<VI::Identity>,
        sender: oneshot::Sender<Result<PkId, String>>,
    ) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .node2coor
            .send_request(&self.coordinator_peer_id, request);
        self.dkg_response_mapping.insert(request_id, sender);
    }
    pub(crate) fn signing_handle_request(
        &mut self,
        request: NodeToCoorRequest<VI::Identity>,
        sender: oneshot::Sender<Result<SignatureSuiteInfo<VI::Identity>, String>>,
    ) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .node2coor
            .send_request(&self.coordinator_peer_id, request);
        self.signing_response_mapping.insert(request_id, sender);
    }
    pub(crate) fn handle_lspk_request(
        &mut self,
        request: NodeToCoorRequest<VI::Identity>,
        sender: oneshot::Sender<Result<HashMap<CryptoType, Vec<PkId>>, String>>,
    ) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .node2coor
            .send_request(&self.coordinator_peer_id, request);
        self.lspk_response_mapping.insert(request_id, sender);
    }
    pub(crate) fn handle_auto_dkg_request(
        &mut self,
        request: NodeToCoorRequest<VI::Identity>,
        sender: oneshot::Sender<Result<AutoDKG<VI::Identity>, String>>,
    ) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .node2coor
            .send_request(&self.coordinator_peer_id, request);
        self.auto_dkg_response_mapping.insert(request_id, sender);
    }
    pub(crate) fn handle_pk_request(
        &mut self,
        request: NodeToCoorRequest<VI::Identity>,
        sender: oneshot::Sender<Result<GroupPublicKeyInfo, String>>,
    ) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .node2coor
            .send_request(&self.coordinator_peer_id, request);
        self.pk_response_mapping.insert(request_id, sender);
    }
    pub(crate) async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<NodeBehaviourEvent<VI::Identity>>,
    ) -> Result<(), anyhow::Error> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
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
                tracing::error!("Outgoing connection to {:?} error: {:?}", peer_id, error);
                if let ConnectionState::Connecting(start_time) = self.connection_state {
                    self.connection_state = ConnectionState::Disconnected(Some(start_time));
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. }
                if peer_id == self.coordinator_peer_id =>
            {
                self.connection_state = ConnectionState::Connected;
                // if let Err(error) = self.swarm.behaviour_mut().rendezvous.register(
                //     rendezvous::Namespace::from_static("rendezvous_coorsig"),
                //     self.coordinator_peer_id,
                //     None,
                // ) {
                //     tracing::error!("Failed to register: {error}");
                //     return Err(anyhow::anyhow!("Failed to register: {error}"));
                // }
                // tracing::info!("Connection established with coordinator {}", peer_id);
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify::Event::Received {
                ..
            })) => {
                // if let Err(error) = self.swarm.behaviour_mut().rendezvous.register(
                //     rendezvous::Namespace::from_static("rendezvous_coorsig"),
                //     self.coordinator_peer_id,
                //     None,
                // ) {
                //     tracing::error!("Failed to register: {error}");
                //     return Err(anyhow::anyhow!("Failed to register: {error}"));
                // }
            }
            SwarmEvent::Behaviour(NodeBehaviourEvent::Node2coor(
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
                match response {
                    NodeToCoorResponse::DKGResponse { pkid } => {
                        if let Some((_, response_oneshot)) =
                            self.dkg_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Ok(pkid)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        } else {
                            tracing::error!(
                                "No response mapping found for request id: {}",
                                request_id
                            );
                        }
                    }
                    NodeToCoorResponse::SigningResponse {
                        signature_suite_info,
                    } => {
                        if let Some((_, response_oneshot)) =
                            self.signing_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Ok(signature_suite_info)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        } else {
                            tracing::error!(
                                "No response mapping found for request id: {}",
                                request_id
                            );
                        }
                    }
                    NodeToCoorResponse::LsPkResponse { pkids } => {
                        if let Some((_, response_oneshot)) =
                            self.lspk_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Ok(pkids)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        }
                    }
                    NodeToCoorResponse::AutoDKGResponse { auto_dkg_result } => {
                        if let Some((_, response_oneshot)) =
                            self.auto_dkg_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Ok(auto_dkg_result)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        }
                    }
                    NodeToCoorResponse::PkTweakResponse {
                        group_public_key_info,
                    } => {
                        if let Some((_, response_oneshot)) =
                            self.pk_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Ok(group_public_key_info)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        }
                    }
                    NodeToCoorResponse::Failure(error) => {
                        if let Some((_, response_oneshot)) =
                            self.dkg_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Err(error)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        } else if let Some((_, response_oneshot)) =
                            self.signing_response_mapping.remove(&request_id)
                        {
                            if let Err(e) = response_oneshot.send(Err(error)) {
                                tracing::error!("Failed to send response: {:?}", e);
                            }
                        } else {
                            tracing::error!(
                                "No response mapping found for request id: {}",
                                request_id
                            );
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
}
pub struct Node<VI: ValidatorIdentity> {
    node_keypair: VI::Keypair,
    p2p_keypair: libp2p::identity::Keypair,
    coordinator_addr: Multiaddr,
    coordinator_peer_id: PeerId,
    dkg_request_sender: UnboundedSender<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<PkId, String>>,
    )>,
    signing_request_sender: UnboundedSender<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<SignatureSuiteInfo<VI::Identity>, String>>,
    )>,
    lspk_request_sender: UnboundedSender<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<HashMap<CryptoType, Vec<PkId>>, String>>,
    )>,
    auto_dkg_request_sender: UnboundedSender<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<AutoDKG<VI::Identity>, String>>,
    )>,
    pk_request_sender: UnboundedSender<(
        NodeToCoorRequest<VI::Identity>,
        oneshot::Sender<Result<GroupPublicKeyInfo, String>>,
    )>,
}

impl<VI: ValidatorIdentity> Node<VI> {
    pub fn new(
        node_keypair: VI::Keypair,
        base_path: PathBuf,
        coordinator_multiaddr: Multiaddr,
        coordinator_peer_id: PeerId,
    ) -> Result<Self, anyhow::Error> {
        let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
        let fmt_string = node_keypair.to_public_key().to_identity().to_fmt_string();
        let ipc_path = base_path
            .join(Settings::global().node.ipc_socket_path)
            .join(format!(
                "node_{}.sock",
                fmt_string.get(..10).unwrap_or(&fmt_string)
            ));
        if ipc_path.exists() {
            std::fs::remove_file(&ipc_path)?;
        }

        tracing::info!("IPC Listening on {:?}", ipc_path);
        let (dkg_request_sender, dkg_request_receiver) = unbounded_channel();
        let (signing_request_sender, signing_request_receiver) = unbounded_channel();
        let (lspk_request_sender, lspk_request_receiver) = unbounded_channel();
        let (pk_request_sender, pk_request_receiver) = unbounded_channel();
        let (auto_dkg_request_sender, auto_dkg_request_receiver) = unbounded_channel();
        let swarm_node = NodeSwarm::<VI>::new(
            p2p_keypair.clone(),
            coordinator_multiaddr.clone(),
            coordinator_peer_id,
            dkg_request_receiver,
            signing_request_receiver,
            lspk_request_receiver,
            auto_dkg_request_receiver,
            pk_request_receiver,
        )?;
        tokio::spawn(async move {
            swarm_node.start_listening().await;
        });
        Ok(Self {
            node_keypair: node_keypair,
            p2p_keypair: p2p_keypair,
            coordinator_addr: coordinator_multiaddr,
            coordinator_peer_id: coordinator_peer_id,
            dkg_request_sender: dkg_request_sender,
            signing_request_sender: signing_request_sender,
            lspk_request_sender: lspk_request_sender,
            auto_dkg_request_sender: auto_dkg_request_sender,
            pk_request_sender: pk_request_sender,
        })
    }

    pub(crate) fn generate_validator_identity(&self) -> ValidatorIdentityRequest {
        let hash = list_hash(&[
            "register".as_bytes(),
            self.node_keypair
                .to_public_key()
                .to_identity()
                .to_bytes()
                .as_slice(),
            self.p2p_keypair.public().to_peer_id().to_bytes().as_slice(),
            self.coordinator_peer_id.to_bytes().as_slice(),
        ]);
        let signature = self.node_keypair.sign(hash.as_slice()).unwrap();
        let request = ValidatorIdentityRequest {
            signature: signature,
            public_key: self.node_keypair.to_public_key().to_bytes(),
            nonce: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        return request;
    }
    pub fn key_generate(
        &self,
        crypto_type: CryptoType,
        participants: Vec<VI::Identity>,
        min_signers: u16,
    ) -> Result<oneshot::Receiver<Result<PkId, String>>, anyhow::Error> {
        let request = self.generate_validator_identity();
        let (sender, receiver) = oneshot::channel();
        self.dkg_request_sender.send((
            NodeToCoorRequest::DKGRequest {
                validator_identity: request,
                crypto_type,
                participants,
                min_signers,
            },
            sender,
        ))?;
        return Ok(receiver);
    }
    pub async fn key_generate_async(
        &self,
        crypto_type: CryptoType,
        participants: Vec<VI::Identity>,
        min_signers: u16,
    ) -> Result<PkId, anyhow::Error> {
        let r = self.key_generate(crypto_type, participants, min_signers)?;
        let timeout = tokio::time::timeout(
            Duration::from_secs(Settings::global().node.connection_timeout),
            r,
        )
        .await?;
        let timeout = timeout.map_err(|e| anyhow::anyhow!("Timeout: {:?}", e))?;
        return timeout.map_err(|e| anyhow::anyhow!("kdg error: {:?}", e));
    }

    pub fn lspk(
        &self,
    ) -> Result<oneshot::Receiver<Result<HashMap<CryptoType, Vec<PkId>>, String>>, anyhow::Error>
    {
        let request = self.generate_validator_identity();
        let (sender, receiver) = oneshot::channel();
        self.lspk_request_sender.send((
            NodeToCoorRequest::LsPkRequest {
                validator_identity: request,
            },
            sender,
        ))?;
        return Ok(receiver);
    }
    pub async fn lspk_async(&self) -> Result<HashMap<CryptoType, Vec<PkId>>, anyhow::Error> {
        let r = self.lspk()?;
        let timeout = tokio::time::timeout(
            Duration::from_secs(Settings::global().node.connection_timeout),
            r,
        )
        .await?;
        let timeout = timeout.map_err(|e| anyhow::anyhow!("Timeout: {:?}", e))?;
        return timeout.map_err(|e| anyhow::anyhow!("lspk error: {:?}", e));
    }
    pub fn auto_dkg(
        &self,
    ) -> Result<oneshot::Receiver<Result<AutoDKG<VI::Identity>, String>>, anyhow::Error> {
        let request = self.generate_validator_identity();
        let (sender, receiver) = oneshot::channel();
        self.auto_dkg_request_sender.send((
            NodeToCoorRequest::AutoDKGRequest {
                validator_identity: request,
            },
            sender,
        ))?;
        return Ok(receiver);
    }
    pub async fn auto_dkg_async(
        &self,
        timeout: Option<Duration>,
    ) -> Result<AutoDKG<VI::Identity>, anyhow::Error> {
        let r = self.auto_dkg()?;
        if timeout.is_none() {
            let r = r.await?;
            return r.map_err(|e| anyhow::anyhow!("auto_dkg error: {:?}", e));
        }
        let timeout = tokio::time::timeout(timeout.unwrap(), r).await?;
        let timeout = timeout.map_err(|e| anyhow::anyhow!("Timeout: {:?}", e))?;
        return timeout.map_err(|e| anyhow::anyhow!("auto_dkg error: {:?}", e));
    }
    pub fn pk(
        &self,
        pkid: PkId,
        tweak_data: Option<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Result<GroupPublicKeyInfo, String>>, anyhow::Error> {
        let request = self.generate_validator_identity();
        let (sender, receiver) = oneshot::channel();
        self.pk_request_sender.send((
            NodeToCoorRequest::PkTweakRequest {
                pkid,
                tweak_data,
                validator_identity: request,
            },
            sender,
        ))?;
        return Ok(receiver);
    }
    pub async fn pk_async(
        &self,
        pkid: PkId,
        tweak_data: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<GroupPublicKeyInfo, anyhow::Error> {
        let r = self.pk(pkid, tweak_data)?;
        if timeout.is_none() {
            let r = r.await?;
            return r.map_err(|e| anyhow::anyhow!("pk error: {:?}", e));
        }
        let timeout = tokio::time::timeout(timeout.unwrap(), r).await?;
        let timeout = timeout.map_err(|e| anyhow::anyhow!("Timeout: {:?}", e))?;
        return timeout.map_err(|e| anyhow::anyhow!("pk error: {:?}", e));
    }
    pub fn sign(
        &self,
        pkid: PkId,
        msg: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Result<SignatureSuiteInfo<VI::Identity>, String>>, anyhow::Error>
    {
        let request = self.generate_validator_identity();
        let (sender, receiver) = oneshot::channel();
        self.signing_request_sender.send((
            NodeToCoorRequest::SigningRequest {
                pkid,
                msg,
                tweak_data,
                validator_identity: request,
            },
            sender,
        ))?;
        return Ok(receiver);
    }
    pub async fn sign_async(
        &self,
        pkid: PkId,
        msg: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<SignatureSuiteInfo<VI::Identity>, anyhow::Error> {
        let r = self.sign(pkid, msg, tweak_data)?;
        if timeout.is_none() {
            let r = r.await?;
            return r.map_err(|e| anyhow::anyhow!("sign error: {:?}", e));
        }
        let timeout = tokio::time::timeout(timeout.unwrap(), r).await?;
        let timeout = timeout.map_err(|e| anyhow::anyhow!("sign error: {:?}", e))?;
        return timeout.map_err(|e| anyhow::anyhow!("sign error: {:?}", e));
    }
    pub fn print_info(&self) -> Result<(), anyhow::Error> {
        tracing::info!(
            "p2p peer id: {}",
            self.p2p_keypair.public().to_peer_id().to_base58()
        );
        tracing::info!(
            "validator peer id: {}",
            self.node_keypair
                .to_public_key()
                .to_identity()
                .to_fmt_string()
        );
        tracing::info!("coordinator peer id: {}", self.coordinator_addr.to_string());

        Ok(())
    }
}
