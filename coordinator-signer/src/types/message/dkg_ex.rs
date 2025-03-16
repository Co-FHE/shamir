use std::{any::Any, collections::BTreeMap};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, CryptoType, Ed25519Sha512, Ed448Shake256, Identifier, P256Sha256,
        Ristretto255Sha512, Secp256K1Sha256, Secp256K1Sha256TR, ValidatorIdentityIdentity,
    },
    types::{error::SessionError, Participants, SessionId},
};

use super::DKGMessage;
pub(crate) type DKGRequestEx<VII: ValidatorIdentityIdentity> =
    DKGMessage<VII, u16, DKGStageEx<u16, Vec<u8>>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestWrapEx<VII: ValidatorIdentityIdentity> {
    EcdsaSecp256k1(DKGRequestEx<VII>),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum DKGResponseWrapEx {
    Success,
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGStageEx<CI: Identifier, R> {
    Init,
    Intermediate(super::MessageEx<CI, Vec<u8>>),
    Final(R),
}

impl<VII: ValidatorIdentityIdentity> DKGRequestWrapEx<VII> {
    pub(crate) fn identity(&self) -> &VII {
        match self {
            DKGRequestWrapEx::EcdsaSecp256k1(r) => &r.base_info.identity,
        }
    }
    pub(crate) fn crypto_type(&self) -> CryptoType {
        match self {
            DKGRequestWrapEx::EcdsaSecp256k1(_) => CryptoType::EcdsaSecp256k1,
        }
    }
    pub(crate) fn failure(&self, msg: String) -> DKGResponseWrapEx {
        return DKGResponseWrapEx::Failure(msg);
    }
    pub(crate) fn from(
        r: DKGRequestEx<VII>,
        crypto_type: CryptoType,
    ) -> Result<Self, SessionError> {
        match crypto_type {
            CryptoType::EcdsaSecp256k1 => Ok(DKGRequestWrapEx::EcdsaSecp256k1(r)),
            _ => Err(SessionError::CryptoError(format!(
                "Unsupported crypto type for DKGRequestWrapEx: {}",
                crypto_type
            ))),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> DKGRequestEx<VII> {
    pub(crate) fn from(r: DKGRequestWrapEx<VII>) -> Result<DKGRequest<VII, C>, SessionError> {
        match r {
            DKGRequestWrap::Ed25519(r) => Ok(try_cast_request::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Secp256k1(r) => Ok(try_cast_request::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Secp256k1Tr(r) => Ok(try_cast_request::<VII, Secp256K1Sha256TR, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::P256(r) => Ok(try_cast_request::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Ed448(r) => Ok(try_cast_request::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG requestWrap to DKGRequest".to_string(),
                ))?
                .clone()),
            DKGRequestWrap::Ristretto255(r) => {
                Ok(try_cast_request::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
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
    pub(crate) fn from(r: DKGResponseWrap<VII>) -> Result<DKGResponse<VII, C>, SessionError> {
        match r {
            DKGResponseWrap::Ed25519(r) => Ok(try_cast_response::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Secp256k1(r) => Ok(try_cast_response::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Secp256k1Tr(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming DKG responseWrap to DKGResponse".to_string(),
                    ))?
                    .clone())
            }
            DKGResponseWrap::P256(r) => Ok(try_cast_response::<VII, P256Sha256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Ed448(r) => Ok(try_cast_response::<VII, Ed448Shake256, C>(&r)
                .ok_or(SessionError::TransformWrapingMessageError(
                    "Error transforming DKG responseWrap to DKGResponse".to_string(),
                ))?
                .clone()),
            DKGResponseWrap::Ristretto255(r) => {
                Ok(try_cast_response::<VII, Ristretto255Sha512, C>(&r)
                    .ok_or(SessionError::TransformWrapingMessageError(
                        "Error transforming DKG responseWrap to DKGResponse".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
