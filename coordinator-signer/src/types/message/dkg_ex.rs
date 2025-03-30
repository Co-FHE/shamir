use serde::{Deserialize, Serialize};

use crate::{
    crypto::{CryptoType, Identifier, ValidatorIdentityIdentity},
    types::{error::SessionError, SessionId},
};

use super::DKGMessage;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DKGResult {
    pub(crate) public_key: Vec<u8>,
    pub(crate) key_package: Vec<u8>,
}
pub(crate) type DKGRequestEx<VII> = DKGMessage<VII, u16, DKGStageEx<u16, DKGResult>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestWrapEx<VII: ValidatorIdentityIdentity> {
    EcdsaSecp256k1(DKGRequestEx<VII>),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum DKGResponseWrapEx {
    Success,
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DKGFinal {
    pub(crate) key_package: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
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
    pub(crate) fn from(r: DKGRequestEx<VII>) -> Result<Self, SessionError> {
        match r.base_info.crypto_type {
            CryptoType::EcdsaSecp256k1 => Ok(DKGRequestWrapEx::EcdsaSecp256k1(r)),
            _ => Err(SessionError::CryptoTypeError(r.base_info.crypto_type)),
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
    pub(crate) fn _session_id(&self) -> SessionId {
        self.base_info.session_id
    }
}
