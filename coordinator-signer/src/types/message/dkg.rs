use std::{any::Any, collections::BTreeMap};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, CryptoType, Ed25519Sha512, Ed448Shake256, P256Sha256, Ristretto255Sha512,
        Secp256K1Sha256, Secp256K1Sha256TR, ValidatorIdentityIdentity,
    },
    types::{error::SessionError, Participants, SessionId},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGBaseMessage<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) session_id: SessionId,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) identifier: C::Identifier,
    pub(crate) identity: VII,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGRequest<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: DKGBaseMessage<VII, C>,
    pub(crate) stage: DKGRequestStage<C>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestStage<C: Cipher> {
    Part1,
    Part2 {
        round1_package_map: BTreeMap<C::Identifier, C::DKGRound1Package>,
    },
    GenPublicKey {
        round1_package_map: BTreeMap<C::Identifier, C::DKGRound1Package>,
        round2_package_map: BTreeMap<C::Identifier, C::DKGRound2Package>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(DKGRequest<VII, Ed25519Sha512>),
    Secp256k1(DKGRequest<VII, Secp256K1Sha256>),
    Secp256k1Tr(DKGRequest<VII, Secp256K1Sha256TR>),
    P256(DKGRequest<VII, P256Sha256>),
    Ed448(DKGRequest<VII, Ed448Shake256>),
    Ristretto255(DKGRequest<VII, Ristretto255Sha512>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGResponse<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: DKGBaseMessage<VII, C>,
    pub(crate) stage: DKGResponseStage<C>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGResponseStage<C: Cipher> {
    Part1 {
        round1_package: C::DKGRound1Package,
    },
    Part2 {
        round2_package_map: BTreeMap<C::Identifier, C::DKGRound2Package>,
    },
    GenPublicKey {
        public_key_package: C::PublicKeyPackage,
    },
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGResponseWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(DKGResponse<VII, Ed25519Sha512>),
    Secp256k1(DKGResponse<VII, Secp256K1Sha256>),
    Secp256k1Tr(DKGResponse<VII, Secp256K1Sha256TR>),
    P256(DKGResponse<VII, P256Sha256>),
    Ed448(DKGResponse<VII, Ed448Shake256>),
    Ristretto255(DKGResponse<VII, Ristretto255Sha512>),
}
fn try_cast_response<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&DKGResponse<VII, T>> {
    r.downcast_ref::<DKGResponse<VII, T>>()
}
fn try_cast_request<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&DKGRequest<VII, T>> {
    r.downcast_ref::<DKGRequest<VII, T>>()
}

impl<VII: ValidatorIdentityIdentity> DKGResponseWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: DKGResponse<VII, C>) -> Result<Self, SessionError<C>> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(DKGResponseWrap::Ed25519(
                try_cast_response::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(DKGResponseWrap::Secp256k1(
                try_cast_response::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(DKGResponseWrap::Secp256k1Tr(
                try_cast_response::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::P256 => Ok(DKGResponseWrap::P256(
                try_cast_response::<VII, C, P256Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ed448 => Ok(DKGResponseWrap::Ed448(
                try_cast_response::<VII, C, Ed448Shake256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ristretto255 => Ok(DKGResponseWrap::Ristretto255(
                try_cast_response::<VII, C, Ristretto255Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG response to DKGResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> DKGRequestWrap<VII> {
    pub(crate) fn identity(&self) -> &VII {
        match self {
            DKGRequestWrap::Ed25519(r) => &r.base_info.identity,
            DKGRequestWrap::Secp256k1(r) => &r.base_info.identity,
            DKGRequestWrap::Secp256k1Tr(r) => &r.base_info.identity,
            DKGRequestWrap::P256(r) => &r.base_info.identity,
            DKGRequestWrap::Ed448(r) => &r.base_info.identity,
            DKGRequestWrap::Ristretto255(r) => &r.base_info.identity,
        }
    }
    pub(crate) fn crypto_type(&self) -> CryptoType {
        match self {
            DKGRequestWrap::Ed25519(_) => CryptoType::Ed25519,
            DKGRequestWrap::Secp256k1(_) => CryptoType::Secp256k1,
            DKGRequestWrap::Secp256k1Tr(_) => CryptoType::Secp256k1Tr,
            DKGRequestWrap::P256(_) => CryptoType::P256,
            DKGRequestWrap::Ed448(_) => CryptoType::Ed448,
            DKGRequestWrap::Ristretto255(_) => CryptoType::Ristretto255,
        }
    }
    pub(crate) fn failure(&self, msg: String) -> DKGResponseWrap<VII> {
        match self {
            DKGRequestWrap::Ed25519(r) => DKGResponseWrap::Ed25519(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
            DKGRequestWrap::Secp256k1(r) => DKGResponseWrap::Secp256k1(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
            DKGRequestWrap::Secp256k1Tr(r) => DKGResponseWrap::Secp256k1Tr(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
            DKGRequestWrap::P256(r) => DKGResponseWrap::P256(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
            DKGRequestWrap::Ed448(r) => DKGResponseWrap::Ed448(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
            DKGRequestWrap::Ristretto255(r) => DKGResponseWrap::Ristretto255(DKGResponse {
                base_info: DKGBaseMessage {
                    session_id: r.base_info.session_id.clone(),
                    min_signers: r.base_info.min_signers,
                    participants: r.base_info.participants.clone(),
                    identifier: r.base_info.identifier,
                    identity: r.base_info.identity.clone(),
                },
                stage: DKGResponseStage::Failure(msg),
            }),
        }
    }
    pub(crate) fn from<C: Cipher>(r: DKGRequest<VII, C>) -> Result<Self, SessionError<C>> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(DKGRequestWrap::Ed25519(
                try_cast_request::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(DKGRequestWrap::Secp256k1(
                try_cast_request::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(DKGRequestWrap::Secp256k1Tr(
                try_cast_request::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::P256 => Ok(DKGRequestWrap::P256(
                try_cast_request::<VII, C, P256Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ed448 => Ok(DKGRequestWrap::Ed448(
                try_cast_request::<VII, C, Ed448Shake256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Ristretto255 => Ok(DKGRequestWrap::Ristretto255(
                try_cast_request::<VII, C, Ristretto255Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG request to DKGRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> DKGRequest<VII, C> {
    pub(crate) fn from(r: DKGRequestWrap<VII>) -> Result<DKGRequest<VII, C>, SessionError<C>> {
        match r {
            DKGRequestWrap::Ed25519(r) => Ok(try_cast_request::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Secp256k1(r) => Ok(try_cast_request::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Secp256k1Tr(r) => Ok(try_cast_request::<VII, Secp256K1Sha256TR, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::P256(r) => Ok(try_cast_request::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Ed448(r) => Ok(try_cast_request::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Ristretto255(r) => {
                Ok(try_cast_request::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG requestWrap to DKGRequest".to_string(),
                    ))?
                    .clone())
            }
        }
    }
    pub(crate) fn session_id(&self) -> SessionId {
        self.base_info.session_id
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> DKGResponse<VII, C> {
    pub(crate) fn from(r: DKGResponseWrap<VII>) -> Result<DKGResponse<VII, C>, SessionError<C>> {
        match r {
            DKGResponseWrap::Ed25519(r) => Ok(try_cast_response::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Secp256k1(r) => Ok(try_cast_response::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Secp256k1Tr(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG responseWrap to DKGResponse".to_string(),
                    ))?
                    .clone())
            }
            DKGResponseWrap::P256(r) => Ok(try_cast_response::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Ed448(r) => Ok(try_cast_response::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Ristretto255(r) => {
                Ok(try_cast_response::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming DKG responseWrap to DKGResponse".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
