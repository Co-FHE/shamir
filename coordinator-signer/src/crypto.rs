mod cipher;
mod pkid;
pub mod validator_identity;

pub use cipher::*;
use serde::{Deserialize, Serialize};

pub use pkid::*;
use strum::{Display, EnumCount, EnumString};
pub use validator_identity::*;

//todo pk.hash()->pkid

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, EnumString, Display, EnumCount, Eq, Hash,
)]
pub enum CryptoType {
    #[strum(serialize = "ed25519")]
    Ed25519,
    #[strum(serialize = "secp256k1")]
    Secp256k1,
    #[strum(serialize = "secp256k1-tr")]
    Secp256k1Tr,
}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoTypeError {
    #[error("Invalid crypto type: {0}")]
    InvalidCryptoType(u8),
    #[error("PkId length is 0")]
    PkIdLengthIs0,
}
impl TryFrom<u8> for CryptoType {
    type Error = CryptoTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ed25519),
            1 => Ok(Self::Secp256k1),
            2 => Ok(Self::Secp256k1Tr),
            _ => Err(CryptoTypeError::InvalidCryptoType(value)),
        }
    }
}
impl From<CryptoType> for u8 {
    fn from(value: CryptoType) -> Self {
        match value {
            CryptoType::Ed25519 => 0,
            CryptoType::Secp256k1 => 1,
            CryptoType::Secp256k1Tr => 2,
        }
    }
}
