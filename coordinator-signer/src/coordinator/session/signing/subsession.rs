use std::collections::BTreeMap;

use common::Settings;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    crypto::*,
    types::message::{SigningBaseMessage, SigningRequestStage, SigningResponseStage},
};

use super::{
    Cipher, Participants, PkId, SessionError, SessionId, SignatureSuite, SigningRequest,
    SigningResponse, SubsessionId, ValidatorIdentity,
};

#[derive(Debug, Clone)]
pub(crate) enum CoordinatorSigningState<C: Cipher> {
    Round1,
    Round2 { signing_package: C::SigningPackage },
    Completed { signature: C::Signature },
}
pub(crate) struct CoordinatorSubsession<VI: ValidatorIdentity, C: Cipher> {
    message: Vec<u8>,
    subsession_id: SubsessionId,
    min_signers: u16,
    participants: Participants<VI::Identity, C>,
    state: CoordinatorSigningState<C>,
    public_key: C::PublicKeyPackage,
    pkid: PkId,
    signing_sender: UnboundedSender<(
        SigningRequest<VI::Identity, C>,
        oneshot::Sender<SigningResponse<VI::Identity, C>>,
    )>,
    signature_sender: UnboundedSender<SignatureSuite<VI::Identity, C>>,
}
impl<VI: ValidatorIdentity, C: Cipher> CoordinatorSubsession<VI, C> {
    pub(crate) fn new(
        pkid: PkId,
        public_key: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VI::Identity, C>,
        sign_message: Vec<u8>,
        sender: UnboundedSender<(
            SigningRequest<VI::Identity, C>,
            oneshot::Sender<SigningResponse<VI::Identity, C>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI::Identity, C>>,
    ) -> Result<Self, SessionError<C>> {
        let subsession_id = SubsessionId::new(
            C::get_crypto_type(),
            min_signers,
            &participants,
            sign_message.clone(),
            pkid.clone(),
        )?;
        Ok(Self {
            subsession_id: subsession_id.clone(),
            min_signers,
            participants: participants.clone(),
            pkid: pkid.clone(),
            public_key: public_key.clone(),
            signature_sender,
            state: CoordinatorSigningState::Round1,
            signing_sender: sender,
            message: sign_message,
        })
    }
    pub(crate) async fn start_signing<T: AsRef<[u8]>>(mut self, msg: T) {
        tracing::debug!("Starting Signing session with id: {:?}", self.subsession_id);
        let msg_v = msg.as_ref().to_vec();
        tokio::spawn(async move {
            let signature = loop {
                if let Some(signature) = self.state.completed() {
                    break signature;
                }
                tracing::info!("Starting new Signing round");
                let mut futures = FuturesUnordered::new();
                for request in self.split_into_single_requests() {
                    tracing::debug!("Sending DKG request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    if let Err(e) = self.signing_sender.send((request.clone(), tx)) {
                        tracing::error!("Error sending DKG state: {}", e);
                        tracing::debug!("Failed request was: {:?}", request);
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            Settings::global().session.state_channel_retry_interval,
                        ))
                        .await;
                    }
                }
                let mut responses = BTreeMap::new();
                tracing::info!("Waiting for {} responses", self.participants.len());
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            tracing::debug!("Received valid response: {:?}", response.clone());
                            responses.insert(response.base_info.identifier.clone(), response);
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            tracing::debug!("Breaking out of response collection loop");
                            break;
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            tracing::debug!(
                                "Received None response, breaking out of collection loop"
                            );
                            break;
                        }
                    }
                }
                if responses.len() == self.participants.len() {
                    tracing::debug!("Received all {} responses, handling them", responses.len());
                    let result = self.handle_response(responses);
                    match result {
                        Ok(next_state) => {
                            tracing::debug!("Successfully transitioned to next DKG state");
                            self.state = next_state;
                        }
                        Err(e) => {
                            tracing::error!("Error handling DKG state: {}", e);
                            tracing::debug!("Retrying after interval");
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                Settings::global().session.state_channel_retry_interval,
                            ))
                            .await;
                            continue;
                        }
                    }
                } else {
                    tracing::error!(
                        "DKG state is not completed, got {}/{} responses",
                        responses.len(),
                        self.participants.len()
                    );
                    tracing::debug!("Retrying after interval");
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        Settings::global().session.state_channel_retry_interval,
                    ))
                    .await;
                    continue;
                }
            };
            if let Err(e) = self.signature_sender.send(SignatureSuite {
                signature,
                pk: self.public_key.clone(),
                subsession_id: self.subsession_id.clone(),
                pkid: self.pkid.clone(),
                message: msg_v,
                participants: self.participants.clone(),
            }) {
                tracing::error!("Error sending signing session: {:?}", e);
            }
        });
    }

    pub(crate) fn get_subsession_id(&self) -> SubsessionId {
        self.subsession_id.clone()
    }
    pub(crate) fn split_into_single_requests(&self) -> Vec<SigningRequest<VI::Identity, C>> {
        match self.state.clone() {
            CoordinatorSigningState::Round1 => self
                .participants
                .iter()
                .map(|(id, identity)| SigningRequest {
                    base_info: SigningBaseMessage {
                        participants: self.participants.clone(),
                        pkid: self.pkid.clone(),
                        subsession_id: self.subsession_id.clone(),
                        identifier: id.clone(),
                        identity: identity.clone(),
                        public_key: self.public_key.clone(),
                    },
                    stage: SigningRequestStage::Round1,
                })
                .collect(),
            CoordinatorSigningState::Round2 { signing_package } => self
                .participants
                .iter()
                .map(|(id, identity)| SigningRequest {
                    base_info: SigningBaseMessage {
                        participants: self.participants.clone(),
                        pkid: self.pkid.clone(),
                        subsession_id: self.subsession_id.clone(),
                        identifier: id.clone(),
                        identity: identity.clone(),
                        public_key: self.public_key.clone(),
                    },
                    stage: SigningRequestStage::Round2 {
                        signing_package: signing_package.clone(),
                    },
                })
                .collect(),
            CoordinatorSigningState::Completed { .. } => vec![],
        }
    }

    pub(crate) fn handle_response(
        &self,
        response: BTreeMap<C::Identifier, SigningResponse<VI::Identity, C>>,
    ) -> Result<CoordinatorSigningState<C>, SessionError<C>> {
        match self.state.clone() {
            CoordinatorSigningState::Round1 => {
                for (id, _) in self.participants.iter() {
                    let _ = response
                        .get(id)
                        .ok_or(SessionError::InvalidResponse(format!(
                            "response not found for id: {}",
                            id.to_string()
                        )))?;
                }
                let commitments_map = response
                    .iter()
                    .map(|(id, resp)| {
                        if let SigningResponseStage::Round1 { ref commitments } = resp.stage {
                            Ok((id.clone(), commitments.clone()))
                        } else {
                            Err(SessionError::<C>::InvalidResponse(format!(
                                "expected round 1 response but got round 2 response"
                            )))
                        }
                    })
                    .collect::<Result<BTreeMap<C::Identifier, C::SigningCommitments>, SessionError<C>>>()?;
                let signing_package = C::SigningPackage::new(commitments_map, &self.message)
                    .map_err(|e| SessionError::CryptoError(e))?;
                Ok(CoordinatorSigningState::Round2 { signing_package })
            }
            CoordinatorSigningState::Round2 { signing_package } => {
                for (id, _) in self.participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(SessionError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id.to_string()
                            )))?;
                }
                let mut signature_shares = BTreeMap::new();
                for (id, resp) in response.iter() {
                    if let SigningResponseStage::Round2 {
                        ref signature_share,
                        ..
                    } = resp.stage
                    {
                        signature_shares.insert(id.clone(), signature_share.clone());
                    } else {
                        return Err(SessionError::InvalidResponse(format!(
                            "need round 2 package but got round 1 package"
                        )));
                    }
                }
                let signature = C::aggregate(&signing_package, &signature_shares, &self.public_key)
                    .map_err(|e| SessionError::CryptoError(e))?;
                Ok(CoordinatorSigningState::Completed { signature })
            }
            CoordinatorSigningState::Completed { .. } => {
                return Err(SessionError::InvalidResponse(format!(
                    "signing already completed"
                )));
            }
        }
    }
}

impl<C: Cipher> CoordinatorSigningState<C> {
    pub(crate) fn completed(&self) -> Option<C::Signature> {
        match self {
            CoordinatorSigningState::Completed { signature } => Some(signature.clone()),
            _ => None,
        }
    }
}
