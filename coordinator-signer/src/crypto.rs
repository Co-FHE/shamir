mod cipher;
mod identifier;
pub(crate) use identifier::*;
mod pkid;
pub mod validator_identity;

pub use cipher::*;
use serde::{Deserialize, Serialize};

pub use pkid::*;
use strum::{Display, EnumCount, EnumIter, EnumString};
pub use validator_identity::*;

//todo pk.hash()->pkid

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    EnumString,
    Display,
    EnumCount,
    Eq,
    Hash,
    EnumIter,
)]
pub enum CryptoType {
    #[strum(serialize = "p256")]
    P256,
    #[strum(serialize = "ed25519")]
    Ed25519,
    #[strum(serialize = "secp256k1")]
    Secp256k1,
    #[strum(serialize = "secp256k1-tr")]
    Secp256k1Tr,
    #[strum(serialize = "ed448")]
    Ed448,
    #[strum(serialize = "ristretto255")]
    Ristretto255,
    #[strum(serialize = "ecdsa-secp256k1")]
    EcdsaSecp256k1,
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
            0 => Ok(Self::P256),
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Secp256k1),
            3 => Ok(Self::Secp256k1Tr),
            4 => Ok(Self::Ed448),
            5 => Ok(Self::Ristretto255),
            6 => Ok(Self::EcdsaSecp256k1),
            _ => Err(CryptoTypeError::InvalidCryptoType(value)),
        }
    }
}
impl From<CryptoType> for u8 {
    fn from(value: CryptoType) -> Self {
        match value {
            CryptoType::P256 => 0,
            CryptoType::Ed25519 => 1,
            CryptoType::Secp256k1 => 2,
            CryptoType::Secp256k1Tr => 3,
            CryptoType::Ed448 => 4,
            CryptoType::Ristretto255 => 5,
            CryptoType::EcdsaSecp256k1 => 6,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_crypto_type() {
        let a: u8 = CryptoType::P256.into();
        println!("{:?}", a);
    }
}
