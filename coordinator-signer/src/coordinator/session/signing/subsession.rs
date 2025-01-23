use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use common::Settings;
use futures::stream::{Abortable, FuturesUnordered};
use futures::StreamExt;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    oneshot,
};

use crate::{
    crypto::*,
    types::message::{SigningBaseMessage, SigningRequestStage, SigningResponseStage},
};

use super::{
    Cipher, Participants, PkId, SessionError, SignatureSuite, SigningRequest, SigningRequestWrap,
    SigningResponse, SigningResponseWrap, SubsessionId,
};

#[derive(Debug, Clone)]
pub(crate) enum CoordinatorSigningState<VII: ValidatorIdentityIdentity, C: Cipher> {
    Round1,
    Round2 {
        joined_participants: Participants<VII, C>,
        signing_package: C::SigningPackage,
    },
    Completed {
        signature: C::Signature,
        joined_participants: Participants<VII, C>,
    },
}
pub(crate) struct CoordinatorSubsession<VII: ValidatorIdentityIdentity, C: Cipher> {
    message: Vec<u8>,
    tweak_data: Option<Vec<u8>>,
    subsession_id: SubsessionId,
    min_signers: u16,
    participants: Participants<VII, C>,
    state: CoordinatorSigningState<VII, C>,
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
        tweak_data: Option<Vec<u8>>,
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
            tweak_data.clone(),
            pkid.clone(),
        )?;
        Ok(Self {
            tweak_data,
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
    pub(crate) async fn start_signing(
        mut self,
        response_sender: oneshot::Sender<
            Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError<C>)>,
        >,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting Signing session with id: {:?}", self.subsession_id);

            let mut futures = FuturesUnordered::new();
            let mut round1_sent = 0;
            for request in self.split_into_single_requests() {
                tracing::debug!("Sending Signing request: {:?}", request);
                let (tx, rx) = oneshot::channel();
                futures.push(rx);
                let request_wrap = SigningRequestWrap::from(request);
                match request_wrap {
                    Ok(request_wrap) => {
                        if let Err(e) = self.signing_sender.send((request_wrap, tx)) {
                            tracing::error!(
                                "Failed to send signing request: {:?}, but continue",
                                e
                            );
                        } else {
                            round1_sent += 1;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get signing request: {:?}", e);
                    }
                }
            }
            tracing::info!("Sent {} round 1 requests", round1_sent);
            let (event_channel_tx, mut event_channel_rx) = unbounded_channel();
            // round1 thread
            let handle = tokio::spawn(async move {
                for _ in 0..round1_sent {
                    let response = tokio::select! {
                        response = futures.next() => response.unwrap(),
                        _ = tokio::time::sleep(Duration::from_secs(Settings::global().session.signing_round1_timeout)) => {
                            tracing::warn!("Signing round 1 timeout,retry");
                            break;
                        }
                    };
                    match response {
                        Ok(response) => {
                            let response = SigningResponse::<VII, C>::from(response);
                            match response {
                                Ok(response) => {
                                    tracing::debug!(
                                        "Received valid round 1 response: {:?}",
                                        response
                                    );
                                    event_channel_tx.send(Some(response)).unwrap();
                                }
                                Err(e) => {
                                    tracing::error!("Error receiving Signing state: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving Signing state: {}", e);
                        }
                    }
                }
                tracing::debug!("Round 1 thread completed, sending None");
                event_channel_tx.send(None).unwrap();
                event_channel_tx.closed().await;
            });
            let mut round1_responses_pool = BTreeMap::new();
            let original_state = self.state.clone();
            let selected_responses: Result<SignatureSuite<VII, C>, SessionError<C>> = 'out: loop {
                self.state = original_state.clone();
                // if round1 response is None and no enough participants, break
                if round1_responses_pool.len() >= self.min_signers as usize {
                    tracing::debug!(
                        "Have enough round 1 responses: {}",
                        round1_responses_pool.len()
                    );
                } else {
                    let response = event_channel_rx.recv().await.unwrap();
                    match response {
                        Some(response) => {
                            tracing::debug!(
                                "Adding response to pool from: {:?}",
                                response.base_info.identifier
                            );
                            round1_responses_pool
                                .insert(response.base_info.identifier.clone(), response);
                            continue 'out;
                        }
                        None => {
                            tracing::error!("Not enough responses for round 1, breaking");
                            break 'out Err(SessionError::CoordinatorSessionError(
                                "not enough responses for round 1".to_string(),
                            ));
                        }
                    }
                }
                // select first min_signers responses
                let round1_responses = round1_responses_pool
                    .clone()
                    .into_iter()
                    .take(self.min_signers as usize)
                    .collect::<BTreeMap<_, _>>();
                tracing::debug!("Selected {} responses for round 1", round1_responses.len());
                let mut error_ids: BTreeSet<C::Identifier> =
                    round1_responses.keys().cloned().collect();
                let result = self.handle_response(round1_responses);
                // check result if not ok, remove id and continue
                match result {
                    Ok(next_state) => {
                        tracing::debug!("Successfully handled round 1 responses");
                        self.state = next_state;
                    }
                    Err((e, Some(id))) => {
                        tracing::warn!(
                            "Error handling Signing state: {},remove id: {}, retry",
                            e,
                            id.to_string()
                        );
                        round1_responses_pool.remove(&id);
                        continue 'out;
                    }
                    Err((e, None)) => {
                        tracing::error!("Error handling Signing state: {}, retry", e);
                        break 'out Err(e);
                    }
                }
                // generate round2 requests
                let mut futures = FuturesUnordered::new();
                // check if the number of split requests equals min_signers
                let round2_requests = self.split_into_single_requests();
                tracing::debug!("Generated {} round 2 requests", round2_requests.len());
                if round2_requests.len() != self.min_signers as usize {
                    tracing::error!(
                        "Round 2 requests count {} doesn't match min_signers {}",
                        round2_requests.len(),
                        self.min_signers
                    );
                    response_sender
                        .send(Err((
                            Some(self.subsession_id),
                            SessionError::CoordinatorSessionError(
                                "not enough responses for round 1".to_string(),
                            ),
                        )))
                        .unwrap();
                    handle.abort();
                    return;
                }
                //check round2 request is valid, if valid send to signer
                for request in round2_requests {
                    tracing::debug!("Sending round 2 request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    let request_wrap = SigningRequestWrap::from(request.clone());
                    match request_wrap {
                        Ok(request_wrap) => {
                            self.signing_sender.send((request_wrap, tx)).unwrap();
                        }
                        Err(e) => {
                            tracing::error!("Failed to get signing request: {:?}", e);
                            round1_responses_pool.remove(&request.base_info.identifier.clone());
                            continue 'out;
                        }
                    }
                }
                // receive round2 response
                let mut round2_responses = BTreeMap::new();
                for i in 0..self.min_signers as usize {
                    tracing::debug!(
                        "Waiting for round 2 response {}/{}",
                        i + 1,
                        self.min_signers
                    );
                    let response = tokio::select! {
                        response = futures.next() => response.unwrap(),
                        _ = tokio::time::sleep(Duration::from_secs(Settings::global().session.signing_round2_timeout)) => {
                            tracing::warn!("Signing round 2 timeout,retry");
                            break;
                        }
                    };
                    match response {
                        Ok(response) => {
                            let response = SigningResponse::<VII, C>::from(response);
                            match response {
                                Ok(response) => {
                                    let id = response.base_info.identifier.clone();
                                    tracing::debug!(
                                        "Received valid round 2 response from: {:?}",
                                        id
                                    );
                                    round2_responses.insert(id.clone(), response);
                                    error_ids.remove(&id);
                                }
                                Err(e) => {
                                    tracing::warn!("Error receiving Signing state: {}, retry", e);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Error receiving Signing state: {}, retry", e);
                            continue;
                        }
                    }
                }
                // remove all response error ids
                if !error_ids.is_empty() {
                    tracing::warn!("Found {} error IDs to remove", error_ids.len());
                    for id in error_ids {
                        round2_responses.remove(&id);
                    }
                    continue 'out;
                }
                // handle round2 response
                let result = self.handle_response(round2_responses.clone());
                match result {
                    Ok(next_state) => {
                        self.state = next_state;
                        if let Some((signature, joined_participants)) = self.state.completed() {
                            tracing::info!("Signing completed successfully");
                            break 'out Ok(SignatureSuite {
                                signature,
                                pk: self.public_key.clone(),
                                tweak_data: self.tweak_data.clone(),
                                subsession_id: self.subsession_id.clone(),
                                pkid: self.pkid.clone(),
                                message: self.message.clone(),
                                participants: self.participants.clone(),
                                joined_participants: joined_participants.clone(),
                            });
                        } else {
                            tracing::error!("Signing state not completed after round 2");
                            break 'out Err(SessionError::CoordinatorSessionError(
                                "signing state is not completed after round 2".to_string(),
                            ));
                        }
                    }
                    Err((e, id)) => match id {
                        Some(id) => {
                            tracing::error!(
                                "Error handling Signing state: {},remove id: {}",
                                e,
                                id.to_string()
                            );
                            round2_responses.remove(&id);
                            continue 'out;
                        }
                        None => {
                            tracing::error!("Error handling Signing state: {}", e);
                            response_sender
                                .send(Err((Some(self.subsession_id), e)))
                                .unwrap();
                            handle.abort();
                            return;
                        }
                    },
                }
            };
            handle.abort();
            if let Err(e) =
                response_sender.send(selected_responses.map_err(|e| (Some(self.subsession_id), e)))
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
                    stage: SigningRequestStage::Round1 {},
                })
                .collect(),
            CoordinatorSigningState::Round2 {
                joined_participants,
                signing_package,
            } => joined_participants
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
                        message: self.message.clone(),
                        tweak_data: self.tweak_data.clone(),
                        joined_participants: joined_participants.clone(),
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
    // return which participants error
    pub(crate) fn handle_response(
        &self,
        response: BTreeMap<C::Identifier, SigningResponse<VII, C>>,
    ) -> Result<CoordinatorSigningState<VII, C>, (SessionError<C>, Option<C::Identifier>)> {
        for (id, response) in response.iter() {
            self.match_base_info(&response.base_info)
                .map_err(|e| (e, Some(id.clone())))?;
        }
        self.participants
            .check_keys_includes(&response, self.min_signers as u16)
            .map_err(|e| (e, None))?;

        let joined_participants = self
            .participants
            .extract_identifiers(&response)
            .map_err(|e| (e, None))?;
        match self.state.clone() {
            CoordinatorSigningState::Round1 => {
                let commitments_map = response
                    .iter()
                    .map(|(id, resp)| {
                        if let SigningResponseStage::Round1 { ref commitments } = resp.stage {
                            Ok((id.clone(), commitments.clone()))
                        } else {
                            Err((
                                SessionError::<C>::InvalidResponse(format!(
                                    "expected round 1 response but got round 2 response"
                                )),
                                Some(id.clone()),
                            ))
                        }
                    })
                    .collect::<Result<BTreeMap<C::Identifier, C::SigningCommitments>, _>>()?;
                let signing_package = C::SigningPackage::new(commitments_map, &self.message)
                    .map_err(|e| (SessionError::CryptoError(e), None))?;
                Ok(CoordinatorSigningState::Round2 {
                    signing_package,
                    joined_participants,
                })
            }
            CoordinatorSigningState::Round2 {
                signing_package,
                joined_participants,
            } => {
                let mut signature_shares = BTreeMap::new();
                for (id, resp) in response.iter() {
                    if let SigningResponseStage::Round2 {
                        ref signature_share,
                        ..
                    } = resp.stage
                    {
                        signature_shares.insert(id.clone(), signature_share.clone());
                    } else {
                        return Err((
                            SessionError::InvalidResponse(format!(
                                "need round 2 package but got round 1 package"
                            )),
                            Some(id.clone()),
                        ));
                    }
                }
                let signature = C::aggregate_with_tweak(
                    &signing_package,
                    &signature_shares,
                    &self.public_key,
                    self.tweak_data.clone(),
                )
                .map_err(|e| (SessionError::CryptoError(e), None))?;
                Ok(CoordinatorSigningState::Completed {
                    signature,
                    joined_participants,
                })
            }
            CoordinatorSigningState::Completed { .. } => {
                return Err((
                    SessionError::InvalidResponse(format!("signing already completed")),
                    None,
                ));
            }
        }
    }
}

impl<VII: ValidatorIdentityIdentity, C: Cipher> CoordinatorSigningState<VII, C> {
    pub(crate) fn completed(&self) -> Option<(C::Signature, Participants<VII, C>)> {
        match self {
            CoordinatorSigningState::Completed {
                signature,
                joined_participants,
            } => Some((signature.clone(), joined_participants.clone())),
            _ => None,
        }
    }
}
