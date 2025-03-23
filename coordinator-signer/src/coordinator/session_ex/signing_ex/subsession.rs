use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};

use crate::{
    coordinator::CoordinatorStateEx,
    crypto::*,
    types::message::{
        SigningBaseMessage, SigningRequestEx, SigningRequestWrapEx, SigningResponseWrapEx,
        SigningStageEx,
    },
    SignatureSuiteInfo,
};
use common::Settings;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use super::{CoordinatorSigningSessionInfo, Participants, SessionError, SubsessionId};

#[derive(Debug, Clone)]
pub(crate) struct CoordinatorSigningFinalState<VII: ValidatorIdentityIdentity> {
    _joined_participants: Participants<VII, u16>,
    _signature: Vec<u8>,
}
pub(crate) struct CoordinatorSubsessionEx<VII: ValidatorIdentityIdentity> {
    base_info: CoordinatorSigningSessionInfo<VII, u16>,
    message: Vec<u8>,
    tweak_data: Option<Vec<u8>>,
    subsession_id: SubsessionId,
    state: CoordinatorStateEx<CoordinatorSigningFinalState<VII>>,
    out_init_signing_sender: UnboundedSender<(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<SigningResponseWrapEx>,
    )>,
}
impl<VII: ValidatorIdentityIdentity> CoordinatorSubsessionEx<VII> {
    pub(crate) fn new(
        base_info: CoordinatorSigningSessionInfo<VII, u16>,
        sign_message: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
        out_init_signing_sender: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    ) -> Result<Self, SessionError> {
        let subsession_id = SubsessionId::new(
            base_info.crypto_type,
            base_info.min_signers,
            &base_info.participants,
            sign_message.clone(),
            tweak_data.clone(),
            base_info.pkid.clone(),
        )?;
        Ok(Self {
            tweak_data,
            subsession_id: subsession_id.clone(),
            base_info,
            state: CoordinatorStateEx::Init,
            out_init_signing_sender: out_init_signing_sender,
            message: sign_message,
        })
    }
    pub(crate) async fn start_signing(
        self,
        mut in_final_rx: UnboundedReceiver<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
        participants_candidates: Vec<u16>,
        response_sender: oneshot::Sender<
            // first is subsession id, second is error ids, third is error
            Result<SignatureSuiteInfo<VII>, (Option<SubsessionId>, Vec<u16>, SessionError)>,
        >,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting Signing session with id: {:?}", self.subsession_id);

            if participants_candidates.len() < self.base_info.min_signers as usize {
                tracing::error!("Not enough participants for signing");
                response_sender
                    .send(Err((
                        Some(self.subsession_id),
                        Vec::new(),
                        SessionError::CoordinatorSessionError(
                            "not enough participants for signing".to_string(),
                        ),
                    )))
                    .unwrap();
                return;
            }
            let mut futures = Vec::new();

            let request_list =
                self.split_into_single_requests(&participants_candidates.into_iter().collect());
            let mut error_ids: BTreeSet<u16> = BTreeSet::new();
            for request in request_list {
                let (tx, rx) = oneshot::channel();
                let (tx_with_id, rx_with_id) = oneshot::channel();
                let base_info = request.base_info.clone();
                let request_wrap = SigningRequestWrapEx::from(request);
                match request_wrap {
                    Ok(request_wrap) => {
                        self.out_init_signing_sender
                            .send((request_wrap, tx))
                            .unwrap();
                        futures.push(rx_with_id);
                        tokio::spawn(async move {
                            // if timeout or recevive rx, send tx_with_id
                            let response = tokio::select! {
                                Ok(response) = rx => response,
                                _ = tokio::time::sleep(Duration::from_secs(Settings::global().session.signing_round1_timeout)) => {
                                        tracing::warn!("Signing round 1 timeout,retry");
                                        SigningResponseWrapEx::Failure(format!("Signing init timeout,retry"))
                                }
                            };
                            tx_with_id.send((base_info.identifier, response)).unwrap();
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to get signing request: {:?}", e);
                        error_ids.insert(base_info.identifier);
                    }
                }
            }
            for future in futures {
                let (id, response) = future.await.unwrap();
                if let SigningResponseWrapEx::Failure(msg) = response {
                    tracing::error!("Signing round 1 error: {}", msg);
                    error_ids.insert(id);
                }
            }
            if error_ids.len() > 0 {
                tracing::error!("Found {} error ids: {:?}", error_ids.len(), error_ids);
                response_sender
                    .send(Err((
                        Some(self.subsession_id),
                        error_ids.clone().into_iter().collect(),
                        SessionError::CoordinatorSessionError(format!(
                            "Found {} error ids: {:?}",
                            error_ids.len(),
                            error_ids
                        )),
                    )))
                    .unwrap();
                return;
            }
            let mut results = BTreeMap::new();
            for i in 0..self.base_info.participants.len() {
                tracing::debug!(
                    "Waiting for response {}/{}",
                    i + 1,
                    self.base_info.participants.len()
                );
                let response = in_final_rx.recv().await;
                match response {
                    Some((request, response_chan)) => {
                        let request_ex = request.signing_request_ex();
                        match request_ex {
                            Ok(request_ex) => {
                                tracing::debug!("Received valid response: {:?}", request_ex);
                                response_chan.send(SigningResponseWrapEx::Success).unwrap();
                                results.insert(request_ex.base_info.identifier, request_ex);
                            }
                            Err(e) => {
                                tracing::error!("Error receiving Signing state: {}", e);
                                response_chan
                                    .send(SigningResponseWrapEx::Failure(e.to_string()))
                                    .unwrap();
                                break;
                            }
                        }
                    }
                    None => {
                        tracing::error!("response channel is closed");
                        break;
                    }
                }
            }
            let result = self.handle_result(results);
            response_sender
                .send(result.map_err(|e| (Some(self.subsession_id), Vec::new(), e)))
                .unwrap();
        });
        //         let mut error_ids: BTreeSet<u16> = BTreeSet::new();
        //         let mut init_sent = 0;
        //         let mut round1_responses_pool = BTreeMap::new();
        //         let mut round2_requests = Vec::new();
        //         let mut round2_responses = BTreeMap::new();
        //         let mut error_ids: BTreeSet<u16> = BTreeSet::new();

        //         }
        //         tokio::select! {
        //             Some(response) = futures.next() => {
        //                 let response = response.unwrap();
        //                 let response_wrap = SigningResponseWrapEx::from(response);
        //                 match response_wrap {
        //                     SigningStageEx::Init(response) => {
        //                         tracing::debug!("Received round 1 response: {:?}", response);
        //                     }
        //                     _ => {
        //                         tracing::error!("Invalid response stage: {:?}", response_wrap.stage);
        //                     }
        //                 }
        //             }
        //         }
        //     }
        //     let original_state = self.state.clone();
        //     let selected_responses: Result<SignatureSuite<VII, C>, SessionError> = 'out: loop {
        //         self.state = original_state.clone();
        //         // if round1 response is None and no enough participants, break
        //         if round1_responses_pool.len() >= self.min_signers as usize {
        //             tracing::debug!(
        //                 "Have enough round 1 responses: {}",
        //                 round1_responses_pool.len()
        //             );
        //         } else {
        //             let response = event_channel_rx.recv().await.unwrap();
        //             match response {
        //                 Some(response) => {
        //                     tracing::debug!(
        //                         "Adding response to pool from: {:?}",
        //                         response.base_info.identifier
        //                     );
        //                     round1_responses_pool
        //                         .insert(response.base_info.identifier.clone(), response);
        //                     continue 'out;
        //                 }
        //                 None => {
        //                     tracing::error!("Not enough responses for round 1, breaking");
        //                     break 'out Err(SessionError::CoordinatorSessionError(
        //                         "not enough responses for round 1".to_string(),
        //                     ));
        //                 }
        //             }
        //         }
        //         // select first min_signers responses
        //         let round1_responses = round1_responses_pool
        //             .clone()
        //             .into_iter()
        //             .take(self.min_signers as usize)
        //             .collect::<BTreeMap<_, _>>();
        //         tracing::debug!("Selected {} responses for round 1", round1_responses.len());
        //         let mut error_ids: BTreeSet<C::Identifier> =
        //             round1_responses.keys().cloned().collect();
        //         let result = self.handle_response(round1_responses);
        //         // check result if not ok, remove id and continue
        //         match result {
        //             Ok(next_state) => {
        //                 tracing::debug!("Successfully handled round 1 responses");
        //                 self.state = next_state;
        //             }
        //             Err((e, Some(id))) => {
        //                 tracing::warn!(
        //                     "Error handling Signing state: {},remove id: {}, retry",
        //                     e,
        //                     id.to_string()
        //                 );
        //                 round1_responses_pool.remove(&id);
        //                 continue 'out;
        //             }
        //             Err((e, None)) => {
        //                 tracing::error!("Error handling Signing state: {}, retry", e);
        //                 break 'out Err(e);
        //             }
        //         }
        //         // generate round2 requests
        //         let mut futures = FuturesUnordered::new();
        //         // check if the number of split requests equals min_signers
        //         let round2_requests = self.split_into_single_requests();
        //         tracing::debug!("Generated {} round 2 requests", round2_requests.len());
        //         if round2_requests.len() != self.min_signers as usize {
        //             tracing::error!(
        //                 "Round 2 requests count {} doesn't match min_signers {}",
        //                 round2_requests.len(),
        //                 self.min_signers
        //             );
        //             response_sender
        //                 .send(Err((
        //                     Some(self.subsession_id),
        //                     SessionError::CoordinatorSessionError(
        //                         "not enough responses for round 1".to_string(),
        //                     ),
        //                 )))
        //                 .unwrap();
        //             handle.abort();
        //             return;
        //         }
        //         //check round2 request is valid, if valid send to signer
        //         for request in round2_requests {
        //             tracing::debug!("Sending round 2 request: {:?}", request);
        //             let (tx, rx) = oneshot::channel();
        //             futures.push(rx);
        //             let request_wrap = SigningRequestWrap::from(request.clone());
        //             match request_wrap {
        //                 Ok(request_wrap) => {
        //                     self.signing_sender.send((request_wrap, tx)).unwrap();
        //                 }
        //                 Err(e) => {
        //                     tracing::error!("Failed to get signing request: {:?}", e);
        //                     round1_responses_pool.remove(&request.base_info.identifier.clone());
        //                     continue 'out;
        //                 }
        //             }
        //         }
        //         // receive round2 response
        //         let mut round2_responses = BTreeMap::new();
        //         for i in 0..self.min_signers as usize {
        //             tracing::debug!(
        //                 "Waiting for round 2 response {}/{}",
        //                 i + 1,
        //                 self.min_signers
        //             );
        //             let response = tokio::select! {
        //                 response = futures.next() => response.unwrap(),
        //                 _ = tokio::time::sleep(Duration::from_secs(Settings::global().session.signing_round2_timeout)) => {
        //                     tracing::warn!("Signing round 2 timeout,retry");
        //                     break;
        //                 }
        //             };
        //             match response {
        //                 Ok(response) => {
        //                     let response = SigningResponse::<VII, C>::from(response);
        //                     match response {
        //                         Ok(response) => {
        //                             let id = response.base_info.identifier.clone();
        //                             tracing::debug!(
        //                                 "Received valid round 2 response from: {:?}",
        //                                 id
        //                             );
        //                             round2_responses.insert(id.clone(), response);
        //                             error_ids.remove(&id);
        //                         }
        //                         Err(e) => {
        //                             tracing::warn!("Error receiving Signing state: {}, retry", e);
        //                             continue;
        //                         }
        //                     }
        //                 }
        //                 Err(e) => {
        //                     tracing::warn!("Error receiving Signing state: {}, retry", e);
        //                     continue;
        //                 }
        //             }
        //         }
        //         // remove all response error ids
        //         if !error_ids.is_empty() {
        //             tracing::warn!("Found {} error IDs to remove", error_ids.len());
        //             for id in error_ids {
        //                 round1_responses_pool.remove(&id);
        //             }
        //             continue 'out;
        //         }
        //         // handle round2 response
        //         let result = self.handle_response(round2_responses.clone());
        //         match result {
        //             Ok(next_state) => {
        //                 self.state = next_state;
        //                 if let Some((signature, joined_participants)) = self.state.completed() {
        //                     tracing::debug!("Signing completed successfully");
        //                     break 'out Ok(SignatureSuite {
        //                         signature,
        //                         pk: self.public_key.clone(),
        //                         tweak_data: self.tweak_data.clone(),
        //                         subsession_id: self.subsession_id.clone(),
        //                         pkid: self.pkid.clone(),
        //                         message: self.message.clone(),
        //                         participants: self.participants.clone(),
        //                         joined_participants: joined_participants.clone(),
        //                     });
        //                 } else {
        //                     tracing::error!("Signing state not completed after round 2");
        //                     break 'out Err(SessionError::CoordinatorSessionError(
        //                         "signing state is not completed after round 2".to_string(),
        //                     ));
        //                 }
        //             }
        //             Err((e, id)) => match id {
        //                 Some(id) => {
        //                     tracing::error!(
        //                         "Error handling Signing state: {},remove id: {}",
        //                         e,
        //                         id.to_string()
        //                     );
        //                     round1_responses_pool.remove(&id);
        //                     continue 'out;
        //                 }
        //                 None => {
        //                     tracing::error!("Error handling Signing state: {}", e);
        //                     response_sender
        //                         .send(Err((Some(self.subsession_id), e)))
        //                         .unwrap();
        //                     handle.abort();
        //                     return;
        //                 }
        //             },
        //         }
        //     };
        //     handle.abort();
        //     if let Err(e) =
        //         response_sender.send(selected_responses.map_err(|e| (Some(self.subsession_id), e)))
        //     {
        //         tracing::error!("Failed to send response: {:?}", e);
        //     }
        // });
    }
    pub(crate) fn subsession_id(&self) -> SubsessionId {
        self.subsession_id.clone()
    }
    pub(crate) fn split_into_single_requests(
        &self,
        joined_participants: &HashSet<u16>,
    ) -> Vec<SigningRequestEx<VII>> {
        match self.state.clone() {
            CoordinatorStateEx::Init => {
                let joined_participants = self
                    .base_info
                    .participants
                    .iter()
                    .filter(|(id, _)| joined_participants.contains(id))
                    .collect::<BTreeMap<_, _>>();

                joined_participants
                    .into_iter()
                    .map(|(id, identity)| SigningRequestEx {
                        base_info: SigningBaseMessage {
                            crypto_type: self.base_info.crypto_type,
                            min_signers: self.base_info.min_signers,
                            participants: self.base_info.participants.clone(),
                            pkid: self.base_info.pkid.clone(),
                            subsession_id: self.subsession_id.clone(),
                            identifier: id.clone(),
                            identity: identity.clone(),
                            public_key: self.base_info.public_key_package.clone(),
                        },
                        stage: SigningStageEx::Init(self.message.clone(), self.tweak_data.clone()),
                    })
                    .collect()
            }
            CoordinatorStateEx::Final { .. } => vec![],
        }
    }

    fn match_base_info(
        &self,
        base_info: &SigningBaseMessage<VII, u16, Vec<u8>>,
    ) -> Result<(), SessionError> {
        if self.base_info.crypto_type != base_info.crypto_type {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "crypto type does not match: {:?} vs {:?}",
                self.base_info.crypto_type, base_info.crypto_type
            )));
        }
        if self.base_info.min_signers != base_info.min_signers {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "min signers does not match: {:?} vs {:?}",
                self.base_info.min_signers, base_info.min_signers
            )));
        }
        if self.subsession_id != base_info.subsession_id {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "subsession id does not match: {:?} vs {:?}",
                self.subsession_id, base_info.subsession_id
            )));
        }
        if self.base_info.pkid != base_info.pkid {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "pkid does not match: {:?} vs {:?}",
                self.base_info.pkid, base_info.pkid
            )));
        }
        for (id, identity_req) in base_info.participants.iter() {
            if let Some(identity_self) = self.base_info.participants.get(id) {
                if identity_req != identity_self {
                    return Err(SessionError::BaseInfoNotMatch(format!(
                        "participants does not match: {:?} vs {:?}",
                        identity_req, identity_self
                    )));
                }
            } else {
                return Err(SessionError::BaseInfoNotMatch(format!(
                    "participants does not match: {:?} vs {:?}",
                    self.base_info.participants, base_info.participants
                )));
            }
        }
        if base_info.participants.len() < self.base_info.min_signers as usize {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "participants count {} is less than min_signers {}",
                base_info.participants.len(),
                self.base_info.min_signers
            )));
        }
        if self.base_info.public_key_package != base_info.public_key {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "public key does not match: {:?} vs {:?}",
                self.base_info.public_key_package, base_info.public_key
            )));
        }

        Ok(())
    }
    // return which participants error and which participants not match
    pub(crate) fn handle_result(
        &self,
        response: BTreeMap<u16, SigningRequestEx<VII>>,
    ) -> Result<SignatureSuiteInfo<VII>, SessionError> {
        for (id, response) in response.iter() {
            self.match_base_info(&response.base_info)?;
            if *id != response.base_info.identifier {
                return Err(SessionError::InvalidResponse(format!(
                    "id does not match: {:?} vs {:?}",
                    id, response.base_info.identifier
                )));
            }
        }
        self.base_info
            .participants
            .check_keys_includes(&response, self.base_info.min_signers as u16)?;

        let joined_participants = self.base_info.participants.extract_identifiers(&response)?;
        match self.state.clone() {
            CoordinatorStateEx::Init => {
                let mut packages = BTreeMap::new();
                for (id, _) in response.iter() {
                    let response = response.get(id).ok_or(
                        crate::types::error::SessionError::InvalidResponse(format!(
                            "response not found for id in part 1: {}",
                            id
                        )),
                    )?;
                    match &response.stage {
                        SigningStageEx::Final(signature) => {
                            packages.insert(id.clone(), signature.clone());
                        }
                        _ => {
                            return Err(SessionError::InvalidResponse(
                                "invalid response stage".to_string(),
                            ));
                        }
                    }
                }
                let first_package = packages.values().next().unwrap();
                if packages.values().any(|package| package != first_package) {
                    return Err(SessionError::InvalidResponse(
                        "packages are not the same".to_string(),
                    ));
                }
                Ok(SignatureSuiteInfo {
                    signature: first_package.signature.clone(),
                    pk: self.base_info.public_key_package.clone(),
                    tweak_data: self.tweak_data.clone(),
                    subsession_id: self.subsession_id.clone(),
                    pkid: self.base_info.pkid.clone(),
                    message: self.message.clone(),
                    participants: self
                        .base_info
                        .participants
                        .iter()
                        .map(|(k, v)| (k.to_bytes(), v.clone()))
                        .collect::<BTreeMap<_, _>>(),
                    joined_participants: joined_participants
                        .iter()
                        .map(|(k, v)| (k.to_bytes(), v.clone()))
                        .collect::<BTreeMap<_, _>>(),
                    pk_tweak: first_package.public_key_derived.clone(),
                    pk_verifying_key: first_package.public_key.clone(),
                    pk_verifying_key_tweak: first_package.public_key_derived.clone(),
                    crypto_type: self.base_info.crypto_type,
                    original_serialized: "".to_string(),
                })
            }
            CoordinatorStateEx::Final { .. } => {
                return Err(SessionError::InvalidResponse(format!(
                    "signing already completed"
                )));
            }
        }
    }
}
