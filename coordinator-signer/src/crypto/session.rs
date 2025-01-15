mod error;
mod session_id;
use super::ValidatorIdentityIdentity;
use crate::crypto::dkg::*;
use crate::crypto::{CryptoType, ValidatorIdentity};
use common::Settings;
pub(crate) use error::SessionError;
use frost_ed25519::keys::dkg::part1;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
pub(crate) use session_id::SessionId;
use sha2::{Digest, Sha256};
use std::thread;
use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};
use tokio::sync::mpsc::{self, unbounded_channel, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum SigningState {
    Round1,
    PreRound2,
    Round2,
}

#[derive(Debug, Clone)]
pub(crate) enum TSSState<VI: ValidatorIdentity> {
    DKG(DKGState<VI::Identity>),
    Signing(HashMap<Uuid, SigningState>),
}

pub(crate) struct Session<VI: ValidatorIdentity> {
    session_id: SessionId<VI::Identity>,
    crypto_type: CryptoType,
    min_signers: u16,
    dkg_state: DKGState<VI::Identity>,
    participants: BTreeMap<u16, VI::Identity>,
    signing_state: HashMap<Uuid, SigningState>,
    dkg_sender: UnboundedSender<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKSingleResponse<VI::Identity>>,
    )>,
}

impl<VI: ValidatorIdentity + 'static> Session<VI> {
    pub fn new(
        crypto_type: CryptoType,
        participants: Vec<(u16, VI::Identity)>,
        min_signers: u16,
        dkg_sender: UnboundedSender<(
            DKGSingleRequest<VI::Identity>,
            oneshot::Sender<DKSingleResponse<VI::Identity>>,
        )>,
    ) -> Result<Self, SessionError> {
        let mut participants_map = BTreeMap::new();
        for (id, identity) in participants {
            if participants_map.contains_key(&id) {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant id: {}",
                    id
                )));
            }
            // Identity must be different
            if participants_map
                .values()
                .any(|identity| identity == identity)
            {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant identity: {}",
                    identity.to_fmt_string()
                )));
            }
            participants_map.insert(id, identity);
        }
        if participants_map.len() < min_signers as usize {
            return Err(SessionError::InvalidMinSigners(
                min_signers,
                participants_map.len() as u16,
            ));
        }
        if participants_map.len() > 255 {
            return Err(SessionError::InvalidParticipants(format!(
                "max signers is 255, got {}",
                participants_map.len()
            )));
        }
        let session_id = SessionId::new(crypto_type, min_signers, &participants_map)?;
        let dkg_state = DKGState::new(min_signers, participants_map.clone());

        Ok(Session {
            session_id,
            crypto_type,
            min_signers,
            dkg_state,
            participants: participants_map,
            signing_state: HashMap::new(),
            dkg_sender,
        })
    }
    pub(crate) async fn start(mut self) {
        tokio::spawn(async move {
            loop {
                if self.dkg_state.completed() {
                    break;
                }
                let mut futures = FuturesUnordered::new();
                for request in self.dkg_state.split_into_single_requests() {
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    if let Err(e) = self.dkg_sender.send((request, tx)) {
                        tracing::error!("Error sending DKG state: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            Settings::global().session.state_channel_retry_interval,
                        ))
                        .await;
                    }
                }
                let mut responses = BTreeMap::new();
                for _ in 0..self.participants.len() {
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            responses.insert(response.get_identifier(), response);
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            break;
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            break;
                        }
                    }
                }
                if responses.len() == self.participants.len() {
                    let result = self.dkg_state.handle_response(responses);
                    match result {
                        Ok(next_state) => self.dkg_state = next_state,
                        Err(e) => {
                            tracing::error!("Error handling DKG state: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                Settings::global().session.state_channel_retry_interval,
                            ))
                            .await;
                            continue;
                        }
                    }
                } else {
                    tracing::error!("DKG state is not completed");
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        Settings::global().session.state_channel_retry_interval,
                    ))
                    .await;
                    continue;
                }
            }
        });
    }

    pub(crate) fn session_id(&self) -> SessionId<VI::Identity> {
        self.session_id.clone()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidValidator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
