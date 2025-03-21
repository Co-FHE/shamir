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
    DKGMessage<VII, u16, DKGStageEx<u16, DKGFinal>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGFinal {
    pub(crate) key_package: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
}
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
            _ => Err(SessionError::CryptoTypeError(crypto_type)),
        }
    }
    pub(crate) fn dkg_request_ex(&self) -> Result<DKGRequestEx<VII>, SessionError> {
        DKGRequestEx::from(self)
    }
}
impl<VII: ValidatorIdentityIdentity> DKGRequestEx<VII> {
    pub(crate) fn from(r: &DKGRequestWrapEx<VII>) -> Result<DKGRequestEx<VII>, SessionError> {
        match r {
            DKGRequestWrapEx::EcdsaSecp256k1(r) => {
                if r.base_info.crypto_type != CryptoType::EcdsaSecp256k1 {
                    return Err(SessionError::CryptoTypeError(r.base_info.crypto_type));
                }
                Ok(r.clone())
            }
        }
    }
    pub(crate) fn into_request_wrap(self) -> Result<DKGRequestWrapEx<VII>, SessionError> {
        match self.base_info.crypto_type {
            CryptoType::EcdsaSecp256k1 => Ok(DKGRequestWrapEx::EcdsaSecp256k1(self)),
            _ => Err(SessionError::CryptoTypeError(self.base_info.crypto_type)),
        }
    }
    pub(crate) fn session_id(&self) -> SessionId {
        self.base_info.session_id
    }
}
