use frost_core::Ciphersuite;

use super::{CryptoType, PkId};
mod ed25519;
mod secp256k1;
mod secp256k1_tr;

pub use ed25519::*;
pub use secp256k1::*;
pub use secp256k1_tr::*;

pub trait Cipher: Ciphersuite + Clone + std::fmt::Debug + Send + Sync + 'static {
    type Identifier;
    type Signature;
    type SigningCommitments;
    type SigningNonces;
    type SignatureShare;

    type KeyPackage;
    type SigningPackage;
    type PublicKeyPackage: Into<PkId>;

    type DKGRound1SecretPackage;
    type DKGRound1Package;
    type DKGRound2SecretPackage;
    type DKGRound2Package;
    type DKGRound2PackageMap: IntoIterator<Item = (Self::Identifier, Self::DKGRound2Package)>;

    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn get_crypto_type() -> CryptoType;
}
