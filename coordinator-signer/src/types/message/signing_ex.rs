use serde::{Deserialize, Serialize};

use crate::crypto::Identifier;
use crate::types::message::SigningMessage;
use crate::{
    crypto::{CryptoType, ValidatorIdentityIdentity},
    types::{error::SessionError, SubsessionId},
};
pub(crate) type SigningRequestEx<VII> =
    SigningMessage<VII, u16, Vec<u8>, SigningStageEx<u16, SignatureEx>>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningStageEx<CI: Identifier, R> {
    // message, tweak_data
    Init(Vec<u8>, Option<Vec<u8>>),
    Intermediate(super::MessageEx<CI, Vec<u8>>),
    Final(R),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SignatureEx {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) public_key_derived: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningRequestWrapEx<VII: ValidatorIdentityIdentity> {
    EcdsaSecp256k1(SigningRequestEx<VII>),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum SigningResponseWrapEx {
    Success,
    Failure(String),
}

impl<VII: ValidatorIdentityIdentity> SigningRequestWrapEx<VII> {
    pub(crate) fn identity(&self) -> &VII {
        match self {
            SigningRequestWrapEx::EcdsaSecp256k1(r) => &r.base_info.identity,
        }
    }
    pub(crate) fn crypto_type(&self) -> CryptoType {
        match self {
            SigningRequestWrapEx::EcdsaSecp256k1(_) => CryptoType::EcdsaSecp256k1,
        }
    }
    pub(crate) fn failure(&self, msg: String) -> SigningResponseWrapEx {
        return SigningResponseWrapEx::Failure(msg);
    }
    pub(crate) fn from(r: SigningRequestEx<VII>) -> Result<Self, SessionError> {
        match r.base_info.crypto_type {
            CryptoType::EcdsaSecp256k1 => Ok(SigningRequestWrapEx::EcdsaSecp256k1(r)),
            _ => Err(SessionError::CryptoTypeError(r.base_info.crypto_type)),
        }
    }
    pub(crate) fn signing_request_ex(&self) -> Result<SigningRequestEx<VII>, SessionError> {
        SigningRequestEx::from(self)
    }
}
impl<VII: ValidatorIdentityIdentity> SigningRequestEx<VII> {
    pub(crate) fn from(
        r: &SigningRequestWrapEx<VII>,
    ) -> Result<SigningRequestEx<VII>, SessionError> {
        match r {
            SigningRequestWrapEx::EcdsaSecp256k1(r) => {
                if r.base_info.crypto_type != CryptoType::EcdsaSecp256k1 {
                    return Err(SessionError::CryptoTypeError(r.base_info.crypto_type));
                }
                Ok(r.clone())
            }
        }
    }
    pub(crate) fn into_request_wrap(self) -> Result<SigningRequestWrapEx<VII>, SessionError> {
        match self.base_info.crypto_type {
            CryptoType::EcdsaSecp256k1 => Ok(SigningRequestWrapEx::EcdsaSecp256k1(self)),
            _ => Err(SessionError::CryptoTypeError(self.base_info.crypto_type)),
        }
    }
    pub(crate) fn _subsession_id(&self) -> SubsessionId {
        self.base_info.subsession_id
    }
}
