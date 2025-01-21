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
    SigningRequestWrap, SigningResponse, SigningResponseWrap, SubsessionId, ValidatorIdentity,
};

#[derive(Debug, Clone)]
pub(crate) enum CoordinatorSigningState<C: Cipher> {
    Round1,
    Round2 { signing_package: C::SigningPackage },
    Completed { signature: C::Signature },
}
pub(crate) struct CoordinatorSubsession<VII: ValidatorIdentityIdentity, C: Cipher> {
    message: Vec<u8>,
    subsession_id: SubsessionId,
    min_signers: u16,
    participants: Participants<VII, C>,
    state: CoordinatorSigningState<C>,
    public_key: C::PublicKeyPackage,
    pkid: PkId,
    signing_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> CoordinatorSubsession<VII, C> {
    pub(crate) fn new(
        pkid: PkId,
        public_key: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VII, C>,
        sign_message: Vec<u8>,
        sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Result<Self, SessionError<C>> {
        let subsession_id = SubsessionId::new(
            C::crypto_type(),
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
            state: CoordinatorSigningState::Round1,
            signing_sender: sender,
            message: sign_message,
        })
    }
    pub(crate) async fn start_signing<T: AsRef<[u8]>>(
        mut self,
        msg: T,
        response_sender: oneshot::Sender<
            Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError<C>)>,
        >,
    ) {
        tracing::debug!("Starting Signing session with id: {:?}", self.subsession_id);
        let msg = msg.as_ref().to_vec();
        tokio::spawn(async move {
            let result = 'out: loop {
                if let Some(signature) = self.state.completed() {
                    break Ok(signature);
                }
                tracing::info!("Starting new Signing round");
                let mut futures = FuturesUnordered::new();
                for request in self.split_into_single_requests() {
                    tracing::debug!("Sending Signing request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    let request_wrap = SigningRequestWrap::from(request);
                    match request_wrap {
                        Ok(request_wrap) => {
                            if let Err(e) = self.signing_sender.send((request_wrap, tx)) {
                                break 'out Err(SessionError::CoordinatorSessionError(
                                    e.to_string(),
                                ));
                            }
                        }
                        Err(e) => {
                            break 'out Err(e);
                        }
                    }
                }
                let mut responses = BTreeMap::new();
                tracing::info!("Waiting for {} responses", self.participants.len());
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            let response = SigningResponse::<VII, C>::from(response);
                            match response {
                                Ok(response) => {
                                    tracing::debug!(
                                        "Received valid response: {:?}",
                                        response.clone()
                                    );
                                    responses
                                        .insert(response.base_info.identifier.clone(), response);
                                }
                                Err(e) => {
                                    break 'out Err(e);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving Signing state: {}", e);
                            break 'out Err(SessionError::CoordinatorSessionError(e.to_string()));
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            tracing::debug!(
                                "Received None response, breaking out of collection loop"
                            );
                            break 'out Err(SessionError::CoordinatorSessionError(
                                "DKG state is not completed".to_string(),
                            ));
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
                            break 'out Err(e);
                        }
                    }
                } else {
                    tracing::error!(
                        "DKG state is not completed, got {}/{} responses",
                        responses.len(),
                        self.participants.len()
                    );
                    break 'out Err(SessionError::CoordinatorSessionError(format!(
                        "DKG state is not completed, got {}/{} responses",
                        responses.len(),
                        self.participants.len()
                    )));
                }
            }
            .map(|signature| SignatureSuite {
                signature,
                pk: self.public_key.clone(),
                subsession_id: self.subsession_id.clone(),
                pkid: self.pkid.clone(),
                message: msg,
                participants: self.participants.clone(),
            });
            if let Err(e) = response_sender.send(result.map_err(|e| (Some(self.subsession_id), e)))
            {
                tracing::error!("Failed to send response: {:?}", e);
            }
        });
    }

    pub(crate) fn subsession_id(&self) -> SubsessionId {
        self.subsession_id.clone()
    }
    pub(crate) fn split_into_single_requests(&self) -> Vec<SigningRequest<VII, C>> {
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
                    stage: SigningRequestStage::Round1 {
                        message: self.message.clone(),
                    },
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

    fn match_base_info(
        &self,
        base_info: &SigningBaseMessage<VII, C>,
    ) -> Result<(), SessionError<C>> {
        if self.subsession_id != base_info.subsession_id {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "subsession id does not match: {:?} vs {:?}",
                self.subsession_id, base_info.subsession_id
            )));
        }
        if self.pkid != base_info.pkid {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "pkid does not match: {:?} vs {:?}",
                self.pkid, base_info.pkid
            )));
        }
        if self.participants != base_info.participants {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "participants does not match: {:?} vs {:?}",
                self.participants, base_info.participants
            )));
        }
        if self.public_key != base_info.public_key {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "public key does not match: {:?} vs {:?}",
                self.public_key, base_info.public_key
            )));
        }

        Ok(())
    }
    pub(crate) fn handle_response(
        &self,
        response: BTreeMap<C::Identifier, SigningResponse<VII, C>>,
    ) -> Result<CoordinatorSigningState<C>, SessionError<C>> {
        for (_, response) in response.iter() {
            self.match_base_info(&response.base_info)?;
        }
        self.participants.check_keys_equal(&response)?;
        match self.state.clone() {
            CoordinatorSigningState::Round1 => {
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
