mod dkg;
mod session;
mod traits;
pub(crate) use crate::crypto::traits::*;
pub(crate) use dkg::*;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_secp256k1::Secp256K1Sha256;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
pub(crate) use session::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum CryptoError {
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Ed25519 error: {0}")]
    Ed25519(frost_ed25519::Error),
    #[error("Secp256k1 error: {0}")]
    Secp256k1(frost_secp256k1::Error),
    #[error("Secp256k1Tr error: {0}")]
    Secp256k1Tr(frost_secp256k1_tr::Error),
}
impl From<frost_ed25519::Error> for CryptoError {
    fn from(e: frost_ed25519::Error) -> Self {
        Self::Ed25519(e)
    }
}
impl From<frost_secp256k1::Error> for CryptoError {
    fn from(e: frost_secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}
impl From<frost_secp256k1_tr::Error> for CryptoError {
    fn from(e: frost_secp256k1_tr::Error) -> Self {
        Self::Secp256k1Tr(e)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CryptoRound1<C: Ciphersuite> {
    ciphersuite: C,
    dkg_round1_package: Option<frost_core::keys::dkg::round1::Package<C>>,
}
#[derive(Debug, Clone)]
pub(crate) struct CryptoRound2<C: Ciphersuite> {
    ciphersuite: C,
    dkg_round2_package: Option<frost_core::keys::dkg::round2::Package<C>>,
}
#[derive(Debug, Clone)]
pub(crate) enum CryptoRound1Package {
    Ed25519(CryptoRound1<Ed25519Sha512>),
    Secp256k1(CryptoRound1<Secp256K1Sha256>),
    Secp256k1Tr(CryptoRound1<Secp256K1Sha256TR>),
}
#[derive(Debug, Clone)]
pub(crate) enum CryptoRound2Package {
    Ed25519(CryptoRound2<Ed25519Sha512>),
    Secp256k1(CryptoRound2<Secp256K1Sha256>),
    Secp256k1Tr(CryptoRound2<Secp256K1Sha256TR>),
}
impl CryptoRound1Package {
    pub(crate) fn is_crypto_type(&self, crypto_type: CryptoType) -> bool {
        match crypto_type {
            CryptoType::Ed25519 => matches!(self, CryptoRound1Package::Ed25519(_)),
            CryptoType::Secp256k1 => matches!(self, CryptoRound1Package::Secp256k1(_)),
            CryptoType::Secp256k1Tr => matches!(self, CryptoRound1Package::Secp256k1Tr(_)),
        }
    }
    pub(crate) fn get_crypto_type(&self) -> CryptoType {
        match self {
            CryptoRound1Package::Ed25519(_) => CryptoType::Ed25519,
            CryptoRound1Package::Secp256k1(_) => CryptoType::Secp256k1,
            CryptoRound1Package::Secp256k1Tr(_) => CryptoType::Secp256k1Tr,
        }
    }
}

impl CryptoRound2Package {
    pub(crate) fn is_crypto_type(&self, crypto_type: CryptoType) -> bool {
        match crypto_type {
            CryptoType::Ed25519 => matches!(self, CryptoRound2Package::Ed25519(_)),
            CryptoType::Secp256k1 => matches!(self, CryptoRound2Package::Secp256k1(_)),
            CryptoType::Secp256k1Tr => matches!(self, CryptoRound2Package::Secp256k1Tr(_)),
        }
    }

    pub(crate) fn get_crypto_type(&self) -> CryptoType {
        match self {
            CryptoRound2Package::Ed25519(_) => CryptoType::Ed25519,
            CryptoRound2Package::Secp256k1(_) => CryptoType::Secp256k1,
            CryptoRound2Package::Secp256k1Tr(_) => CryptoType::Secp256k1Tr,
        }
    }
}

pub(crate) struct Validator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
