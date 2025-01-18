use std::collections::BTreeMap;

use common::Settings;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    crypto::ValidatorIdentityIdentity,
    types::message::{SigningBaseMessage, SigningRequestStage},
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
    subsession_id: SubsessionId<VI::Identity>,
    min_signers: u16,
    participants: Participants<VI::Identity, C>,
    state: CoordinatorSigningState<C>,
    pk: C::PublicKeyPackage,
    pkid: PkId,
    signing_sender: UnboundedSender<(
        SigningRequest<VI::Identity, C>,
        oneshot::Sender<SigningResponse<VI::Identity, C>>,
    )>,
    signature_sender: UnboundedSender<SignatureSuite<VI, C>>,
}
impl<VI: ValidatorIdentity, C: Cipher> CoordinatorSubsession<VI, C> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        pkid: PkId,
        pk: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VI::Identity, C>,
        sign_message: Vec<u8>,
        sender: UnboundedSender<(
            SigningRequest<VI::Identity, C>,
            oneshot::Sender<SigningResponse<VI::Identity, C>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI, C>>,
    ) -> Result<Self, SessionError<C>> {
        let subsession_id = SubsessionId::new(
            C::get_crypto_type(),
            min_signers,
            &participants,
            sign_message.clone(),
            &session_id,
            pkid.clone(),
        )?;
        Ok(Self {
            subsession_id: subsession_id.clone(),
            min_signers,
            participants: participants.clone(),
            pkid: pkid.clone(),
            pk: pk.clone(),
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
                            tracing::debug!("Received valid response: {:?}", response);
                            responses.insert(response.base_info.identifier, response);
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
                pk: self.pk.clone(),
                subsession_id: self.subsession_id.clone(),
                pkid: self.pkid.clone(),
                message: msg_v,
            }) {
                tracing::error!("Error sending signing session: {:?}", e);
            }
        });
    }

    pub(crate) fn get_subsession_id(&self) -> SubsessionId<VI::Identity> {
        self.subsession_id.clone()
    }
    pub(crate) fn split_into_single_requests(&self) -> Vec<SigningRequest<VI::Identity, C>> {
        match self.state {
            CoordinatorSigningState::Round1 => self
                .participants
                .iter()
                .map(|(id, identity)| SigningRequest::Round1 {
                    base_info: SigningBaseMessage {
                        participants: self.participants.clone(),
                        pkid: self.pkid.clone(),
                        subsession_id: self.subsession_id.clone(),
                        identifier: *id,
                        identity: identity.clone(),
                        public_key: self.pk.clone(),
                    },
                    stage: SigningRequestStage::Round1,
                })
                .collect(),
            CoordinatorSigningState::Round2 { signing_package } => self
                .participants
                .iter()
                .map(|(id, identity)| SigningRequest::Round2 {
                    base_info: SigningBaseMessage {
                        participants: self.participants.clone(),
                        pkid: self.pkid.clone(),
                        subsession_id: self.subsession_id.clone(),
                        identifier: *id,
                        identity: identity.clone(),
                        public_key: self.pk.clone(),
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
        response: BTreeMap<u16, SigningSingleResponse<VII>>,
    ) -> Result<Self, CryptoError> {
        match self {
            SigningState::Round1 {
                crypto_type,
                message,
                min_signers,
                pkid,
                subsession_id,
                pk,
                participants,
            } => {
                for (id, _) in participants.iter() {
                    let _ = response
                        .get(id)
                        .ok_or(CryptoError::InvalidResponse(format!(
                            "response not found for id: {}",
                            id
                        )))?;
                }
                let signing_package = match crypto_type {
                    CryptoType::Ed25519 => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Ed25519(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_ed25519::SigningPackage::new(commitmentss, message);
                        SigningPackage::Ed25519(signature_packge)
                    }
                    CryptoType::Secp256k1 => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Secp256k1(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_secp256k1::SigningPackage::new(commitmentss, message);
                        SigningPackage::Secp256k1(signature_packge)
                    }
                    CryptoType::Secp256k1Tr => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Secp256k1Tr(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_secp256k1_tr::SigningPackage::new(commitmentss, message);
                        SigningPackage::Secp256k1Tr(signature_packge)
                    }
                };
                Ok(SigningState::Round2 {
                    crypto_type: *crypto_type,
                    message: message.clone(),
                    pkid: pkid.clone(),
                    subsession_id: subsession_id.clone(),
                    min_signers: *min_signers,
                    participants: participants.clone(),
                    pk: pk.clone(),
                    signing_package,
                })
            }
            SigningState::Round2 {
                crypto_type,
                message,
                pkid,
                subsession_id,
                min_signers,
                participants,
                pk,
                signing_package,
            } => {
                for (id, _) in participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(CryptoError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id
                            )))?;
                }
                let signature = match crypto_type {
                    CryptoType::Ed25519 => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Ed25519(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Ed25519(public_package) = pk {
                            if let SigningPackage::Ed25519(signing_package) = signing_package {
                                let group_signature = frost_ed25519::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Ed25519(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Ed25519,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Ed25519,
                                crypto_type
                            )));
                        }
                    }
                    CryptoType::Secp256k1 => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Secp256k1(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Secp256k1(public_package) = pk {
                            if let SigningPackage::Secp256k1(signing_package) = signing_package {
                                let group_signature = frost_secp256k1::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Secp256k1(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Secp256k1,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Secp256k1,
                                crypto_type
                            )));
                        }
                    }
                    CryptoType::Secp256k1Tr => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Secp256k1Tr(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Secp256k1Tr(public_package) = pk {
                            if let SigningPackage::Secp256k1Tr(signing_package) = signing_package {
                                let group_signature = frost_secp256k1_tr::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Secp256k1Tr(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Secp256k1Tr,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Secp256k1Tr,
                                crypto_type
                            )));
                        }
                    }
                };
                Ok(SigningState::Completed {
                    signature,
                    pk: pk.clone(),
                    subsession_id: subsession_id.clone(),
                })
            }
            SigningState::Completed { .. } => {
                return Err(CryptoError::InvalidResponse(format!(
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
