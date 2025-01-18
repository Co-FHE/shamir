use std::collections::BTreeMap;

use common::Settings;
use futures::stream::FuturesUnordered;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    crypto::{Cipher, CryptoType, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{DKGRequest, DKGResponse, DKGResponseStage, SigningRequest, SigningResponse},
        Participants, SignatureSuite,
    },
};

use super::{signing::CoordinatorSigningSession, SessionId, ValidatorIdentity};

#[derive(Debug, Clone)]
pub(crate) enum CoordinatorDKGState<C: Cipher> {
    Part1,
    Part2 {
        round1_package_map: C::DKGRound1PackageMap,
    },
    GenPublicKey {
        round1_package_map: C::DKGRound1PackageMap,
        round2_package_map_map: C::DKGRound2PackageMapMap,
    },
    Completed {
        public_key: C::PublicKeyPackage,
    },
}

pub(crate) struct CoordinatorSession<VI: ValidatorIdentity, C: Cipher> {
    session_id: SessionId<VI::Identity>,
    min_signers: u16,
    dkg_state: CoordinatorDKGState<C>,
    participants: Participants<VI::Identity, C>,
    dkg_sender: UnboundedSender<(
        DKGRequest<VI::Identity, C>,
        oneshot::Sender<DKGResponse<VI::Identity, C>>,
    )>,
}

impl<VI: ValidatorIdentity, C: Cipher> CoordinatorSession<VI, C> {
    pub fn new(
        crypto_type: CryptoType,
        participants: Vec<(u16, VI::Identity)>,
        min_signers: u16,
        dkg_sender: UnboundedSender<(
            DKGRequest<VI::Identity, C>,
            oneshot::Sender<DKGResponse<VI::Identity, C>>,
        )>,
    ) -> Result<Self, SessionError<C>> {
        let participants = Participants::new(participants)?;
        participants.check_min_signers(min_signers)?;
        let session_id = SessionId::new(crypto_type, min_signers, &participants)?;
        let dkg_state = CoordinatorDKGState::new();

        Ok(Self {
            session_id,
            min_signers,
            dkg_state,
            participants: participants,
            dkg_sender,
        })
    }
    pub(crate) async fn start(
        mut self,
        completed_sender: oneshot::Sender<CoordinatorSigningSession<VI, C>>,
        signing_sender: UnboundedSender<(
            SigningRequest<VI::Identity, C>,
            oneshot::Sender<SigningResponse<VI::Identity, C>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI, C>>,
    ) {
        tracing::debug!("Starting DKG session with id: {:?}", self.session_id);
        tokio::spawn(async move {
            let signing_session = loop {
                if let Some(public_key_package) = self.dkg_state.completed() {
                    let signing_session = CoordinatorSigningSession::<VI>::new(
                        self.session_id.clone(),
                        public_key_package,
                        self.min_signers,
                        self.participants.clone(),
                        signing_sender,
                        signature_sender,
                    );
                    if let Err(e) = signing_session {
                        return Err(e);
                    }
                    let signing_session = signing_session.unwrap();
                    break signing_session;
                }
                tracing::info!("Starting new DKG round");
                let mut futures = FuturesUnordered::new();
                for request in self.dkg_state.split_into_single_requests() {
                    tracing::debug!("Sending DKG request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    if let Err(e) = self.dkg_sender.send((request.clone(), tx)) {
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
                            tracing::debug!("Received valid response: {:?}", response);
                            responses.insert(response.get_identifier(), response);
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
                    let result = self.dkg_state.handle_response(responses);
                    match result {
                        Ok(next_state) => {
                            tracing::debug!("Successfully transitioned to next DKG state");
                            self.dkg_state = next_state;
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
            if let Err(e) = completed_sender.send(signing_session) {
                tracing::error!("Error sending signing session: {:?}", e.pkid);
            }
            return Ok(());
        });
    }
    fn split_into_single_requests(
        &self,
    ) -> Result<Vec<DKGRequest<VI::Identity, C>>, SessionError<C>> {
        match self.dkg_state {
            CoordinatorDKGState::Part1 => self
                .participants
                .iter()
                .map(|(id, identity)| DKGRequest::Part1 {
                    min_signers: self.min_signers,
                    participants: self.participants.clone(),
                    identifier: *id,
                    identity: identity.clone(),
                    session_id: self.session_id.clone(),
                    crypto_type: *self.crypto_type,
                })
                .collect(),
            CoordinatorDKGState::Part2 { round1_package_map } => self
                .participants
                .iter()
                .map(|(id, identity)| DKGRequest::Part2 {
                    min_signers: self.min_signers,
                    max_signers: self.participants.len() as u16,
                    identifier: *id,
                    identity: identity.clone(),
                    round1_packages: round1_package_map.clone(),
                    session_id: self.session_id.clone(),
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
                            let value = round2_package_map.get(id).unwrap();
                            match value {
                                Some(round2_package) => {
                                    round2_packages.insert(*oid, round2_package.clone());
                                }
                                None => {
                                    return Err(SessionError::MissingDataForSplitIntoRequest(
                                        format!("response not found for id: {}", id),
                                    ));
                                }
                            }
                        }
                        DKGRequest::GenPublicKey {
                            min_signers: self.min_signers,
                            max_signers: self.participants.len() as u16,
                            identifier: *id,
                            identity: identity.clone(),
                            round1_packages: round1_package_map.clone(),
                            round2_packages: round2_packages.clone(),
                            crypto_type: *self.crypto_type,
                            session_id: self.session_id.clone(),
                        }
                    })
                    .collect()
            }
            CoordinatorDKGState::Completed { .. } => Ok(vec![]),
        }
    }
    fn handle_response(
        &self,
        response: BTreeMap<C::Identifier, DKGResponse<VI::Identity, C>>,
    ) -> Result<CoordinatorDKGState<C>, SessionError<C>> {
        match self.dkg_state {
            CoordinatorDKGState::Part1 => {
                let mut packages = BTreeMap::new();
                for (id, _) in self.participants.iter() {
                    // find in response
                    let response = response.get(id).ok_or(
                        crate::types::error::SessionError::InvalidResponse(format!(
                            "response not found for id: {}",
                            id
                        ))
                        .into(),
                    )?;
                    match response.stage {
                        DKGResponseStage::Round1(package) => {
                            packages.insert(*id, package);
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
                                id
                            )))?;
                    // TODO: need more checks
                    match response.stage {
                        DKGResponseStage::Part2(packages) => {
                            packagess.insert(*id, packages);
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
                                id
                            )))?;
                    match response.stage {
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
            CoordinatorDKGState::Completed { .. } => Ok(self.clone()),
        }
    }
}

impl<C: Cipher> CoordinatorDKGState<C> {
    pub(crate) fn new() -> Self {
        Self::Part1 {}
    }
    fn completed(&self) -> Option<C::PublicKeyPackage> {
        match self.dkg_state {
            CoordinatorDKGState::Completed { public_key } => Some(public_key.clone()),
            _ => None,
        }
    }
}
