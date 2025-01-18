use crate::crypto::{
    traits::ValidatorIdentity, Signature, SignatureShare, SignerSigningState, SigningCommitments,
    SigningNonces, SigningPackage, SigningState, ValidatorIdentityIdentity,
};
use std::collections::BTreeMap;
mod pkid;
pub(crate) use pkid::PKID;
mod signature_suite;
mod subsession_id;
use super::{
    CryptoType, KeyPackage, PublicKeyPackage, SessionError, SessionId, SigningSingleRequest,
    SigningSingleResponse,
};
use common::Settings;
use futures::{stream::FuturesUnordered, StreamExt};
use rand::{rngs::ThreadRng, thread_rng};
pub(crate) use signature_suite::SignatureSuite;
pub(crate) use subsession_id::SubSessionId;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
pub(crate) struct SubSession<VI: ValidatorIdentity> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    pub(crate) state: SigningState<VI::Identity>,
    pub(crate) pk: PublicKeyPackage,
    pub(crate) pkid: PKID,
    pub(crate) signing_sender: UnboundedSender<(
        SigningSingleRequest<VI::Identity>,
        oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    )>,
    pub(crate) signature_sender: UnboundedSender<SignatureSuite<VI>>,
}
impl<VI: ValidatorIdentity> SubSession<VI> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        pkid: PKID,
        pk: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VI::Identity>,
        crypto_type: CryptoType,
        sign_message: Vec<u8>,
        sender: UnboundedSender<(
            SigningSingleRequest<VI::Identity>,
            oneshot::Sender<SigningSingleResponse<VI::Identity>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI>>,
    ) -> Result<Self, SessionError> {
        let subsession_id = SubSessionId::new(
            crypto_type,
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
            crypto_type,
            pkid: pkid.clone(),
            pk: pk.clone(),
            signature_sender,
            state: SigningState::Round1 {
                crypto_type,
                message: sign_message,
                min_signers,
                pkid: pkid,
                subsession_id,
                pk: pk,
                participants,
            },
            signing_sender: sender,
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
                for request in self.state.split_into_single_requests() {
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
                            responses.insert(response.get_identity(), response);
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
                    let result = self.state.handle_response(responses);
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

    pub(crate) fn get_subsession_id(&self) -> SubSessionId<VI::Identity> {
        self.subsession_id.clone()
    }
}

pub(crate) struct SignerSubsession<VI: ValidatorIdentity> {
    pub(crate) pk: PublicKeyPackage,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) pkid: PKID,
    key_package: KeyPackage,
    pub(crate) crypto_type: CryptoType,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    pub(crate) signing_state: SignerSigningState<VI::Identity>,
    pub(crate) identity: VI::Identity,
    pub(crate) message: Vec<u8>,
    identifier: u16,
    rng: ThreadRng,
}
impl<VI: ValidatorIdentity> SignerSubsession<VI> {
    pub(crate) fn new_from_request(
        request: SigningSingleRequest<VI::Identity>,
        pk: PublicKeyPackage,
        _pkid: PKID,
        key_package: KeyPackage,
        _identity: VI::Identity,
        _identifier: u16,
        participants: BTreeMap<u16, VI::Identity>,
        min_signers: u16,
        crypto_type: CryptoType,
    ) -> Result<(Self, SigningSingleResponse<VI::Identity>), SessionError> {
        if let SigningSingleRequest::Round1 {
            pkid,
            message,
            subsession_id,
            identity,
            identifier,
        } = request
        {
            assert_eq!(identity, _identity);
            assert_eq!(pkid, _pkid);
            assert_eq!(identifier, _identifier);
            let _identity =
                participants
                    .get(&identifier)
                    .ok_or(SessionError::InvalidParticipants(format!(
                        "identifier {} not found in participants",
                        identifier
                    )))?;
            if _identity != &identity {
                return Err(SessionError::InvalidParticipants(format!(
                    "identity {} does not match identity {}",
                    _identity.to_fmt_string(),
                    identity.to_fmt_string()
                )));
            }
            if identifier == 0 {
                return Err(SessionError::InvalidParticipants(format!(
                    "identifier {} is invalid",
                    identifier
                )));
            }
            let mut rng = thread_rng();
            let (nonces, commitments) = match crypto_type {
                CryptoType::Ed25519 => {
                    if let KeyPackage::Ed25519(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Ed25519(nonces),
                            SigningCommitments::Ed25519(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package
                        )));
                    }
                }
                CryptoType::Secp256k1 => {
                    if let KeyPackage::Secp256k1(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Secp256k1(nonces),
                            SigningCommitments::Secp256k1(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package
                        )));
                    }
                }
                CryptoType::Secp256k1Tr => {
                    if let KeyPackage::Secp256k1Tr(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Secp256k1Tr(nonces),
                            SigningCommitments::Secp256k1Tr(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package.clone()
                        )));
                    }
                }
            };
            let response = SigningSingleResponse::Round1 {
                pkid: pkid.clone(),
                subsession_id: subsession_id.clone(),
                commitments: commitments.clone(),
                identifier: identifier.clone(),
            };
            Ok((
                Self {
                    pk: pk.clone(),
                    subsession_id: subsession_id.clone(),
                    pkid: pkid.clone(),
                    key_package: key_package.clone(),
                    crypto_type,
                    min_signers,
                    participants: participants.clone(),
                    signing_state: SignerSigningState::Round1 {
                        pkid,
                        message: message.clone(),
                        crypto_type,
                        key_package,
                        public_key_package: pk.clone(),
                        min_signers,
                        participants: participants.clone(),
                        identifier: identifier.clone(),
                        identity: identity.clone(),
                        signing_commitments: commitments.clone(),
                        nonces,
                    },
                    identity: identity.clone(),
                    message: message.clone(),
                    identifier: identifier.clone(),
                    rng,
                },
                response,
            ))
        } else {
            Err(SessionError::InvalidRequest(format!(
                "invalid request: {:?}",
                request
            )))
        }
    }
    pub(crate) fn update_from_request(
        &mut self,
        request: SigningSingleRequest<VI::Identity>,
    ) -> Result<SigningSingleResponse<VI::Identity>, SessionError> {
        match request.clone() {
            SigningSingleRequest::Round1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from part1: {:?}",
                    request
                )));
            }
            SigningSingleRequest::Round2 {
                pkid: _pkid,
                subsession_id,
                signing_package,
                identifier: _identifier,
                identity: _identity,
            } => {
                if let SignerSigningState::Round1 {
                    key_package,
                    pkid,
                    message,
                    crypto_type,
                    public_key_package,
                    min_signers,
                    participants,
                    identifier,
                    identity,
                    signing_commitments,
                    nonces,
                } = &self.signing_state
                {
                    assert_eq!(identity, &_identity);
                    assert_eq!(pkid, &_pkid);
                    assert_eq!(identifier, &_identifier);
                    let _identity = self.participants.get(&identifier).ok_or(
                        SessionError::InvalidParticipants(format!(
                            "identifier {} not found in participants",
                            identifier
                        )),
                    )?;
                    if _identity != identity {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identity {} does not match identity {}",
                            _identity.to_fmt_string(),
                            identity.to_fmt_string()
                        )));
                    }
                    if *identifier == 0 {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identifier {} is invalid",
                            identifier
                        )));
                    }
                    let tmp_signing_package = signing_package.clone();
                    let signature_share = match self.crypto_type {
                        CryptoType::Ed25519 => {
                            if let SigningNonces::Ed25519(nonces) = nonces {
                                if let SigningPackage::Ed25519(signing_package) = signing_package {
                                    if let KeyPackage::Ed25519(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Ed25519(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                        CryptoType::Secp256k1 => {
                            if let SigningNonces::Secp256k1(nonces) = nonces {
                                if let SigningPackage::Secp256k1(signing_package) = signing_package
                                {
                                    if let KeyPackage::Secp256k1(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Secp256k1(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                        CryptoType::Secp256k1Tr => {
                            if let SigningNonces::Secp256k1Tr(nonces) = nonces {
                                if let SigningPackage::Secp256k1Tr(signing_package) =
                                    signing_package
                                {
                                    if let KeyPackage::Secp256k1Tr(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Secp256k1Tr(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                    };
                    let response = SigningSingleResponse::Round2 {
                        pkid: pkid.clone(),
                        subsession_id: subsession_id.clone(),
                        signature_share: signature_share.clone(),
                        identifier: self.identifier.clone(),
                    };
                    // TODO: cannot update directly, need to judge whether coordinator is in part1 or part2
                    self.signing_state = SignerSigningState::Round2 {
                        pkid: pkid.clone(),
                        message: self.message.clone(),
                        crypto_type: self.crypto_type,
                        key_package: self.key_package.clone(),
                        public_key_package: self.pk.clone(),
                        min_signers: self.min_signers,
                        participants: self.participants.clone(),
                        identifier: self.identifier.clone(),
                        identity: self.identity.clone(),
                        signing_package: tmp_signing_package,
                        nonces: nonces.clone(),
                        signature_share: signature_share.clone(),
                    };
                    Ok(response)
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from part2: {:?}",
                        request
                    )));
                }
            }
        }
    }
    pub(crate) fn get_subsession_id(&self) -> SubSessionId<VI::Identity> {
        self.subsession_id.clone()
    }
}
