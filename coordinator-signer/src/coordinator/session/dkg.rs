use std::collections::BTreeMap;

use common::Settings;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use super::{signing::CoordinatorSigningSession, SessionId, ValidatorIdentity};
use super::{DKGRequestWrap, DKGResponseWrap};
use crate::crypto::*;
use crate::{
    crypto::{Cipher, CryptoType},
    types::{
        error::SessionError,
        message::{
            DKGBaseMessage, DKGRequest, DKGRequestStage, DKGResponse, DKGResponseStage,
            SigningRequest, SigningResponse,
        },
        Participants, SignatureSuite,
    },
};

#[derive(Debug, Clone)]
pub(crate) enum CoordinatorDKGState<C: Cipher> {
    Part1,
    Part2 {
        round1_package_map: BTreeMap<C::Identifier, C::DKGRound1Package>,
    },
    GenPublicKey {
        round1_package_map: BTreeMap<C::Identifier, C::DKGRound1Package>,
        round2_package_map_map:
            BTreeMap<C::Identifier, BTreeMap<C::Identifier, C::DKGRound2Package>>,
    },
    Completed {
        public_key: C::PublicKeyPackage,
    },
}

pub(crate) struct CoordinatorDKGSession<VII: ValidatorIdentityIdentity, C: Cipher> {
    session_id: SessionId,
    min_signers: u16,
    dkg_state: CoordinatorDKGState<C>,
    participants: Participants<VII, C>,
    dkg_sender: UnboundedSender<(DKGRequestWrap<VII>, oneshot::Sender<DKGResponseWrap<VII>>)>,
}
#[derive(Debug, Clone)]
pub(crate) struct DKGInfo<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) session_id: SessionId,
    pub(crate) public_key_package: C::PublicKeyPackage,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher + PartialEq + Eq> CoordinatorDKGSession<VII, C> {
    pub fn new(
        participants: Participants<VII, C>,
        min_signers: u16,
        dkg_sender: UnboundedSender<(DKGRequestWrap<VII>, oneshot::Sender<DKGResponseWrap<VII>>)>,
    ) -> Result<Self, SessionError<C>> {
        participants.check_min_signers(min_signers)?;
        let session_id = SessionId::new(C::crypto_type(), min_signers, &participants)?;
        let dkg_state = CoordinatorDKGState::new();

        Ok(Self {
            session_id,
            min_signers,
            dkg_state,
            participants: participants,
            dkg_sender,
        })
    }
    fn match_base_info(&self, base_info: &DKGBaseMessage<VII, C>) -> Result<(), SessionError<C>> {
        if self.session_id != base_info.session_id {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "session id does not match: {:?} vs {:?}",
                self.session_id, base_info.session_id
            )));
        }
        if self.min_signers != base_info.min_signers {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "min signers does not match: {:?} vs {:?}",
                self.min_signers, base_info.min_signers
            )));
        }
        if self.participants != base_info.participants {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "participants does not match: {:?} vs {:?}",
                self.participants, base_info.participants
            )));
        }

        Ok(())
    }
    pub(crate) fn session_id(&self) -> SessionId {
        self.session_id.clone()
    }
    pub(crate) async fn start_dkg(
        mut self,
        response_sender: oneshot::Sender<Result<DKGInfo<VII, C>, (SessionId, SessionError<C>)>>,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting DKG session with id: {:?}", self.session_id);
            let result = 'out: loop {
                if let Some(public_key_package) = self.dkg_state.completed() {
                    break 'out Ok(DKGInfo {
                        session_id: self.session_id.clone(),
                        min_signers: self.min_signers,
                        participants: self.participants.clone(),
                        public_key_package,
                    });
                }
                tracing::info!("Starting new DKG round");
                let mut futures = FuturesUnordered::new();
                match self.split_into_single_requests() {
                    Ok(requests) => {
                        for request in requests {
                            tracing::debug!("Sending DKG request: {:?}", request);
                            let (tx, rx) = oneshot::channel();
                            futures.push(rx);
                            let request_wrap = DKGRequestWrap::from(request);
                            match request_wrap {
                                Ok(request_wrap) => {
                                    if let Err(e) = self.dkg_sender.send((request_wrap.clone(), tx))
                                    {
                                        tracing::error!("Error sending DKG request: {}", e);
                                        break 'out Err(SessionError::CoordinatorSessionError(
                                            format!("Error sending DKG request: {}", e),
                                        ));
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("{}", e);
                                    break 'out Err(e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error splitting into single requests: {}", e);
                        break 'out Err(e);
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
                            match DKGResponse::<VII, C>::from(response) {
                                Ok(response) => {
                                    responses
                                        .insert(response.base_info.identifier.clone(), response);
                                }
                                Err(e) => {
                                    tracing::error!("Error transforming DKG response: {}", e);
                                    break 'out Err(e);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            break 'out Err(SessionError::CoordinatorSessionError(format!(
                                "Error receiving DKG state: {}",
                                e
                            )));
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
                            self.dkg_state = next_state;
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
            };
            if let Err(e) = response_sender.send(result.map_err(|e| (self.session_id.clone(), e))) {
                tracing::error!("Failed to send response: {:?}", e);
            }
        });
    }
    fn split_into_single_requests(&self) -> Result<Vec<DKGRequest<VII, C>>, SessionError<C>> {
        match self.dkg_state.clone() {
            CoordinatorDKGState::Part1 => self
                .participants
                .iter()
                .map(|(id, identity)| {
                    Ok(DKGRequest {
                        base_info: DKGBaseMessage {
                            min_signers: self.min_signers,
                            participants: self.participants.clone(),
                            identifier: id.clone(),
                            identity: identity.clone(),
                            session_id: self.session_id.clone(),
                        },
                        stage: DKGRequestStage::Part1,
                    })
                })
                .collect(),
            CoordinatorDKGState::Part2 { round1_package_map } => self
                .participants
                .iter()
                .map(|(id, identity)| {
                    Ok(DKGRequest {
                        base_info: DKGBaseMessage {
                            min_signers: self.min_signers,
                            participants: self.participants.clone(),
                            identifier: id.clone(),
                            identity: identity.clone(),
                            session_id: self.session_id.clone(),
                        },
                        stage: DKGRequestStage::Part2 {
                            round1_package_map: round1_package_map.clone(),
                        },
                    })
                })
                .collect(),
            CoordinatorDKGState::GenPublicKey {
                round1_package_map,
                round2_package_map_map,
            } => {
                self.participants
                    .iter()
                    .map(|(id, identity)| {
                        let mut round2_packages = BTreeMap::new();
                        for (oid, round2_package_map) in round2_package_map_map.iter() {
                            if oid == id {
                                continue;
                            }
                            let value = round2_package_map.get(&oid);
                            match value {
                                Some(round2_package) => {
                                    round2_packages.insert(oid.clone(), round2_package.clone());
                                }
                                None => {
                                    return Err(SessionError::MissingDataForSplitIntoRequest(
                                        format!("response not found for id: {}", id.to_string()),
                                    ));
                                }
                            }
                        }
                        Ok(DKGRequest {
                            base_info: DKGBaseMessage {
                                min_signers: self.min_signers,
                                participants: self.participants.clone(),
                                identifier: id.clone(),
                                identity: identity.clone(),
                                session_id: self.session_id.clone(),
                            },
                            stage: DKGRequestStage::GenPublicKey {
                                round1_package_map: round1_package_map.clone(),
                                round2_package_map: round2_packages.clone(),
                            },
                        })
                    })
                    .collect()
            }
            CoordinatorDKGState::Completed { .. } => Ok(vec![]),
        }
    }
    fn handle_response(
        &self,
        response: BTreeMap<C::Identifier, DKGResponse<VII, C>>,
    ) -> Result<CoordinatorDKGState<C>, SessionError<C>> {
        for (_, response) in response.iter() {
            self.match_base_info(&response.base_info)?;
        }
        self.participants.check_keys_equal(&response)?;
        match self.dkg_state.clone() {
            CoordinatorDKGState::Part1 => {
                let mut packages = BTreeMap::new();
                for (id, _) in self.participants.iter() {
                    // find in response
                    let response = response.get(id).ok_or(
                        crate::types::error::SessionError::<C>::InvalidResponse(format!(
                            "response not found for id: {}",
                            id.to_string()
                        )),
                    )?;
                    match response.stage.clone() {
                        DKGResponseStage::Part1 { round1_package } => {
                            packages.insert(id.clone(), round1_package);
                        }
                        _ => {
                            return Err(SessionError::InvalidResponse(format!(
                                "need round 1 package but got round 2 package"
                            )));
                        }
                    }
                }
                Ok(CoordinatorDKGState::Part2 {
                    round1_package_map: packages,
                })
            }
            CoordinatorDKGState::Part2 { round1_package_map } => {
                let mut packagess = BTreeMap::new();
                for (id, _) in self.participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(SessionError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id.to_string()
                            )))?;
                    // TODO: need more checks
                    match response.stage.clone() {
                        DKGResponseStage::Part2 { round2_package_map } => {
                            packagess.insert(id.clone(), round2_package_map);
                        }
                        _ => {
                            return Err(SessionError::InvalidResponse(format!(
                                "need round 1 package but got round 2 package"
                            )));
                        }
                    }
                }
                Ok(CoordinatorDKGState::GenPublicKey {
                    round1_package_map: round1_package_map.clone(),
                    round2_package_map_map: packagess,
                })
            }
            CoordinatorDKGState::GenPublicKey {
                round1_package_map,
                round2_package_map_map,
            } => {
                let mut public_key = None;
                for (id, _) in self.participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(SessionError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id.to_string()
                            )))?;
                    match response.stage.clone() {
                        DKGResponseStage::GenPublicKey { public_key_package } => match public_key {
                            None => public_key = Some(public_key_package.clone()),
                            Some(ref pk) => {
                                if &public_key_package != pk {
                                    return Err(SessionError::InvalidResponse(format!(
                                        "public key packages do not match {:?}, {:?}",
                                        pk, public_key_package
                                    )));
                                }
                            }
                        },
                        _ => {
                            return Err(SessionError::InvalidResponse(format!(
                                "need public key package but got round 2 package"
                            )));
                        }
                    }
                    // TODO: check public key package is the same
                }
                if let Some(public_key) = public_key {
                    tracing::info!("DKG state completed, public key: {:?}", public_key);
                    Ok(CoordinatorDKGState::Completed { public_key })
                } else {
                    Err(SessionError::InvalidResponse(
                        "public key package not found".to_string(),
                    ))
                }
            }
            CoordinatorDKGState::Completed { .. } => Ok(self.dkg_state.clone()),
        }
    }
}

impl<C: Cipher> CoordinatorDKGState<C> {
    pub(crate) fn new() -> Self {
        Self::Part1 {}
    }
    fn completed(&self) -> Option<C::PublicKeyPackage> {
        match self {
            CoordinatorDKGState::Completed { public_key } => Some(public_key.clone()),
            _ => None,
        }
    }
}
