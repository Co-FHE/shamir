use std::{any::Any, collections::BTreeMap};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, CryptoType, Ed25519Sha512, Ed448Shake256, Identifier, P256Sha256, PkId,
        Ristretto255Sha512, Secp256K1Sha256, Secp256K1Sha256TR, ValidatorIdentityIdentity,
    },
    types::{error::SessionError, Participants, SubsessionId},
};
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct SigningBaseMessage<VII: ValidatorIdentityIdentity, CI: Identifier, PK> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) participants: Participants<VII, CI>,
    pub(crate) min_signers: u16,
    pub(crate) pkid: PkId,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) identifier: CI,
    pub(crate) identity: VII,
    pub(crate) public_key: PK,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SigningMessage<VII: ValidatorIdentityIdentity, CI: Identifier, PK, S> {
    pub(crate) base_info: SigningBaseMessage<VII, CI, PK>,
    pub(crate) stage: S,
}
pub(crate) type SigningResponse<VII, C> = SigningMessage<
    VII,
    <C as Cipher>::Identifier,
    <C as Cipher>::PublicKeyPackage,
    SigningResponseStage<C>,
>;
pub(crate) type SigningRequest<VII, C> = SigningMessage<
    VII,
    <C as Cipher>::Identifier,
    <C as Cipher>::PublicKeyPackage,
    SigningRequestStage<VII, C>,
>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningRequestStage<VII: ValidatorIdentityIdentity, C: Cipher> {
    Round1 {},
    Round2 {
        tweak_data: Option<Vec<u8>>,
        joined_participants: Participants<VII, C::Identifier>,
        signing_commitments_map: BTreeMap<C::Identifier, C::SigningCommitments>,
        message: Vec<u8>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningRequestWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(SigningRequest<VII, Ed25519Sha512>),
    Secp256k1(SigningRequest<VII, Secp256K1Sha256>),
    Secp256k1Tr(SigningRequest<VII, Secp256K1Sha256TR>),
    P256(SigningRequest<VII, P256Sha256>),
    Ed448(SigningRequest<VII, Ed448Shake256>),
    Ristretto255(SigningRequest<VII, Ristretto255Sha512>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningResponseStage<C: Cipher> {
    Round1 { commitments: C::SigningCommitments },
    Round2 { signature_share: C::SignatureShare },
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningResponseWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(SigningResponse<VII, Ed25519Sha512>),
    Secp256k1(SigningResponse<VII, Secp256K1Sha256>),
    Secp256k1Tr(SigningResponse<VII, Secp256K1Sha256TR>),
    P256(SigningResponse<VII, P256Sha256>),
    Ed448(SigningResponse<VII, Ed448Shake256>),
    Ristretto255(SigningResponse<VII, Ristretto255Sha512>),
}
fn try_cast_response<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&SigningResponse<VII, T>> {
    r.downcast_ref::<SigningResponse<VII, T>>()
}
fn try_cast_request<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&SigningRequest<VII, T>> {
    r.downcast_ref::<SigningRequest<VII, T>>()
}

impl<VII: ValidatorIdentityIdentity> SigningResponseWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: SigningResponse<VII, C>) -> Result<Self, SessionError> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(SigningResponseWrap::Ed25519(
                try_cast_response::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(SigningResponseWrap::Secp256k1(
                try_cast_response::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(SigningResponseWrap::Secp256k1Tr(
                try_cast_response::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::P256 => Ok(SigningResponseWrap::P256(
                try_cast_response::<VII, C, P256Sha256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ed448 => Ok(SigningResponseWrap::Ed448(
                try_cast_response::<VII, C, Ed448Shake256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ristretto255 => Ok(SigningResponseWrap::Ristretto255(
                try_cast_response::<VII, C, Ristretto255Sha512>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            _ => Err(SessionError::TransformWrapingMessageError(
                "non-schnorr signature is not supported".to_string(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> SigningRequestWrap<VII> {
    pub(crate) fn identity(&self) -> &VII {
        match self {
            SigningRequestWrap::Ed25519(r) => &r.base_info.identity,
            SigningRequestWrap::Secp256k1(r) => &r.base_info.identity,
            SigningRequestWrap::Secp256k1Tr(r) => &r.base_info.identity,
            SigningRequestWrap::P256(r) => &r.base_info.identity,
            SigningRequestWrap::Ed448(r) => &r.base_info.identity,
            SigningRequestWrap::Ristretto255(r) => &r.base_info.identity,
        }
    }
    pub(crate) fn message(&self) -> Option<Vec<u8>> {
        match self {
            SigningRequestWrap::Ed25519(r) => r.message(),
            SigningRequestWrap::Secp256k1(r) => r.message(),
            SigningRequestWrap::Secp256k1Tr(r) => r.message(),
            SigningRequestWrap::P256(r) => r.message(),
            SigningRequestWrap::Ed448(r) => r.message(),
            SigningRequestWrap::Ristretto255(r) => r.message(),
        }
    }
    pub(crate) fn crypto_type(&self) -> CryptoType {
        match self {
            SigningRequestWrap::Ed25519(_) => CryptoType::Ed25519,
            SigningRequestWrap::Secp256k1(_) => CryptoType::Secp256k1,
            SigningRequestWrap::Secp256k1Tr(_) => CryptoType::Secp256k1Tr,
            SigningRequestWrap::P256(_) => CryptoType::P256,
            SigningRequestWrap::Ed448(_) => CryptoType::Ed448,
            SigningRequestWrap::Ristretto255(_) => CryptoType::Ristretto255,
        }
    }

    pub(crate) fn failure(&self, msg: String) -> SigningResponseWrap<VII> {
        match self {
            SigningRequestWrap::Ed25519(r) => SigningResponseWrap::Ed25519(SigningResponse {
                base_info: SigningBaseMessage {
                    crypto_type: self.crypto_type(),
                    pkid: r.base_info.pkid.clone(),
                    min_signers: r.base_info.min_signers,
                    subsession_id: r.base_info.subsession_id,
                    public_key: r.base_info.public_key.clone(),
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: SigningResponseStage::Failure(msg),
            }),
            SigningRequestWrap::Secp256k1(r) => SigningResponseWrap::Secp256k1(SigningResponse {
                base_info: SigningBaseMessage {
                    crypto_type: self.crypto_type(),
                    pkid: r.base_info.pkid.clone(),
                    min_signers: r.base_info.min_signers,
                    subsession_id: r.base_info.subsession_id,
                    public_key: r.base_info.public_key.clone(),
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: SigningResponseStage::Failure(msg),
            }),
            SigningRequestWrap::Secp256k1Tr(r) => {
                SigningResponseWrap::Secp256k1Tr(SigningResponse {
                    base_info: SigningBaseMessage {
                        crypto_type: self.crypto_type(),
                        pkid: r.base_info.pkid.clone(),
                        min_signers: r.base_info.min_signers,
                        subsession_id: r.base_info.subsession_id,
                        public_key: r.base_info.public_key.clone(),
                        participants: r.base_info.participants.clone(),
                        identifier: r.base_info.identifier,
                        identity: r.base_info.identity.clone(),
                    },
                    stage: SigningResponseStage::Failure(msg),
                })
            }
            SigningRequestWrap::P256(r) => SigningResponseWrap::P256(SigningResponse {
                base_info: SigningBaseMessage {
                    crypto_type: self.crypto_type(),
                    pkid: r.base_info.pkid.clone(),
                    min_signers: r.base_info.min_signers,
                    subsession_id: r.base_info.subsession_id,
                    public_key: r.base_info.public_key.clone(),
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: SigningResponseStage::Failure(msg),
            }),
            SigningRequestWrap::Ed448(r) => SigningResponseWrap::Ed448(SigningResponse {
                base_info: SigningBaseMessage {
                    crypto_type: self.crypto_type(),
                    pkid: r.base_info.pkid.clone(),
                    min_signers: r.base_info.min_signers,
                    subsession_id: r.base_info.subsession_id,
                    public_key: r.base_info.public_key.clone(),
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: SigningResponseStage::Failure(msg),
            }),
            SigningRequestWrap::Ristretto255(r) => {
                SigningResponseWrap::Ristretto255(SigningResponse {
                    base_info: SigningBaseMessage {
                        crypto_type: self.crypto_type(),
                        pkid: r.base_info.pkid.clone(),
                        min_signers: r.base_info.min_signers,
                        subsession_id: r.base_info.subsession_id,
                        public_key: r.base_info.public_key.clone(),
                        participants: r.base_info.participants.clone(),
                        identifier: r.base_info.identifier,
                        identity: r.base_info.identity.clone(),
                    },
                    stage: SigningResponseStage::Failure(msg),
                })
            }
        }
    }
    pub(crate) fn from<C: Cipher>(r: SigningRequest<VII, C>) -> Result<Self, SessionError> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(SigningRequestWrap::Ed25519(
                try_cast_request::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(SigningRequestWrap::Secp256k1(
                try_cast_request::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(SigningRequestWrap::Secp256k1Tr(
                try_cast_request::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::P256 => Ok(SigningRequestWrap::P256(
                try_cast_request::<VII, C, P256Sha256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ed448 => Ok(SigningRequestWrap::Ed448(
                try_cast_request::<VII, C, Ed448Shake256>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ristretto255 => Ok(SigningRequestWrap::Ristretto255(
                try_cast_request::<VII, C, Ristretto255Sha512>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            _ => Err(SessionError::TransformWrapingMessageError(
                "non-schnorr signature is not supported".to_string(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningRequest<VII, C> {
    pub(crate) fn message(&self) -> Option<Vec<u8>> {
        if let SigningRequestStage::Round2 { message, .. } = &self.stage {
            return Some(message.clone());
        }
        None
    }
    pub(crate) fn from(r: SigningRequestWrap<VII>) -> Result<SigningRequest<VII, C>, SessionError> {
        match r {
            SigningRequestWrap::Ed25519(r) => Ok(try_cast_request::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Secp256k1(r) => Ok(try_cast_request::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Secp256k1Tr(r) => {
                Ok(try_cast_request::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing requestWrap to SigningRequest".to_string(),
                    ))?
                    .clone())
            }
            SigningRequestWrap::P256(r) => Ok(try_cast_request::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Ed448(r) => Ok(try_cast_request::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Ristretto255(r) => {
                Ok(try_cast_request::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing requestWrap to SigningRequest".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningResponse<VII, C> {
    pub(crate) fn from(
        r: SigningResponseWrap<VII>,
    ) -> Result<SigningResponse<VII, C>, SessionError> {
        match r {
            SigningResponseWrap::Ed25519(r) => Ok(try_cast_response::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing responseWrap to SigningResponse".to_string(),
                ))?
                .clone()),
            SigningResponseWrap::Secp256k1(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing responseWrap to SigningResponse".to_string(),
                    ))?
                    .clone())
            }
            SigningResponseWrap::Secp256k1Tr(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing responseWrap to SigningResponse".to_string(),
                    ))?
                    .clone())
            }
            SigningResponseWrap::P256(r) => Ok(try_cast_response::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing responseWrap to SigningResponse".to_string(),
                ))?
                .clone()),
            SigningResponseWrap::Ed448(r) => Ok(try_cast_response::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming Signing responseWrap to SigningResponse".to_string(),
                ))?
                .clone()),
            SigningResponseWrap::Ristretto255(r) => {
                Ok(try_cast_response::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming Signing responseWrap to SigningResponse".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
