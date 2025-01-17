mod dkg;
mod session;
mod signing;
mod signing_session;
mod traits;
use std::{collections::BTreeMap, fmt};

pub(crate) use crate::crypto::traits::*;
pub(crate) use dkg::*;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
pub(crate) use session::*;
pub(crate) use signing::*;
pub(crate) use signing_session::*;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGPackage {
    Round1(DKGRound1Package),
    Round2(DKGRound2Packages),
    PublicKey(PublicKeyPackage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningPackage {
    Ed25519(frost_ed25519::SigningPackage),
    Secp256k1(frost_secp256k1::SigningPackage),
    Secp256k1Tr(frost_secp256k1_tr::SigningPackage),
}
pub(crate) trait CryptoPackageTrait {
    fn get_crypto_type(&self) -> CryptoType;
    fn is_crypto_type(&self, crypto_type: CryptoType) -> bool {
        self.get_crypto_type() == crypto_type
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRound1Package {
    Ed25519(frost_ed25519::keys::dkg::round1::Package),
    Secp256k1(frost_secp256k1::keys::dkg::round1::Package),
    Secp256k1Tr(frost_secp256k1_tr::keys::dkg::round1::Package),
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum PublicKeyPackage {
    Ed25519(frost_ed25519::keys::PublicKeyPackage),
    Secp256k1(frost_secp256k1::keys::PublicKeyPackage),
    Secp256k1Tr(frost_secp256k1_tr::keys::PublicKeyPackage),
}
impl PublicKeyPackage {
    pub(crate) fn public_key(&self) -> Vec<u8> {
        match self {
            PublicKeyPackage::Ed25519(pk) => pk.serialize().unwrap(),
            PublicKeyPackage::Secp256k1(pk) => pk.serialize().unwrap(),
            PublicKeyPackage::Secp256k1Tr(pk) => pk.serialize().unwrap(),
        }
    }
}
// pub trait Cipher: Ciphersuite + Clone + fmt::Debug + Send + Sync + 'static {
//     type KeyPackage;
//     type DKGRound1Package;
//     type DKGRound2Package;
//     type SigningPackage;
//     fn get_crypto_type() -> CryptoType;
// }
// impl Cipher for frost_ed25519::Ed25519Sha512 {
//     type KeyPackage = frost_ed25519::keys::KeyPackage;
//     type DKGRound1Package = frost_ed25519::keys::dkg::round1::Package;
//     type DKGRound2Package = frost_ed25519::keys::dkg::round2::Package;
//     type SigningPackage = frost_ed25519::SigningPackage;
//     fn get_crypto_type() -> CryptoType {
//         CryptoType::Ed25519
//     }
// }
// impl Cipher for frost_secp256k1::Secp256K1Sha256 {
//     type KeyPackage = frost_secp256k1::keys::KeyPackage;
//     type DKGRound1Package = frost_secp256k1::keys::dkg::round1::Package;
//     type DKGRound2Package = frost_secp256k1::keys::dkg::round2::Package;
//     type SigningPackage = frost_secp256k1::SigningPackage;
//     fn get_crypto_type() -> CryptoType {
//         CryptoType::Secp256k1
//     }
// }
// impl Cipher for frost_secp256k1_tr::Secp256K1Sha256TR {
//     type KeyPackage = frost_secp256k1_tr::keys::KeyPackage;
//     type DKGRound1Package = frost_secp256k1_tr::keys::dkg::round1::Package;
//     type DKGRound2Package = frost_secp256k1_tr::keys::dkg::round2::Package;
//     type SigningPackage = frost_secp256k1_tr::SigningPackage;
//     fn get_crypto_type() -> CryptoType {
//         CryptoType::Secp256k1Tr
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum KeyPackage {
    Ed25519(frost_ed25519::keys::KeyPackage),
    Secp256k1(frost_secp256k1::keys::KeyPackage),
    Secp256k1Tr(frost_secp256k1_tr::keys::KeyPackage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRound2Package {
    Ed25519(frost_ed25519::keys::dkg::round2::Package),
    Secp256k1(frost_secp256k1::keys::dkg::round2::Package),
    Secp256k1Tr(frost_secp256k1_tr::keys::dkg::round2::Package),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRound2Packages {
    Ed25519(BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::dkg::round2::Package>),
    Secp256k1(BTreeMap<frost_secp256k1::Identifier, frost_secp256k1::keys::dkg::round2::Package>),
    Secp256k1Tr(
        BTreeMap<frost_secp256k1_tr::Identifier, frost_secp256k1_tr::keys::dkg::round2::Package>,
    ),
}
#[derive(Debug, Clone)]
pub(crate) enum DKGRound1SecretPackage {
    Ed25519(frost_ed25519::keys::dkg::round1::SecretPackage),
    Secp256k1(frost_secp256k1::keys::dkg::round1::SecretPackage),
    Secp256k1Tr(frost_secp256k1_tr::keys::dkg::round1::SecretPackage),
}
#[derive(Debug, Clone)]
pub(crate) enum DKGRound2SecretPackage {
    Ed25519(frost_ed25519::keys::dkg::round2::SecretPackage),
    Secp256k1(frost_secp256k1::keys::dkg::round2::SecretPackage),
    Secp256k1Tr(frost_secp256k1_tr::keys::dkg::round2::SecretPackage),
}
impl CryptoPackageTrait for DKGPackage {
    fn get_crypto_type(&self) -> CryptoType {
        match self {
            DKGPackage::Round1(DKGRound1Package::Ed25519(_)) => CryptoType::Ed25519,
            DKGPackage::Round1(DKGRound1Package::Secp256k1(_)) => CryptoType::Secp256k1,
            DKGPackage::Round1(DKGRound1Package::Secp256k1Tr(_)) => CryptoType::Secp256k1Tr,
            DKGPackage::Round2(DKGRound2Packages::Ed25519(_)) => CryptoType::Ed25519,
            DKGPackage::Round2(DKGRound2Packages::Secp256k1(_)) => CryptoType::Secp256k1,
            DKGPackage::Round2(DKGRound2Packages::Secp256k1Tr(_)) => CryptoType::Secp256k1Tr,
            DKGPackage::PublicKey(PublicKeyPackage::Ed25519(_)) => CryptoType::Ed25519,
            DKGPackage::PublicKey(PublicKeyPackage::Secp256k1(_)) => CryptoType::Secp256k1,
            DKGPackage::PublicKey(PublicKeyPackage::Secp256k1Tr(_)) => CryptoType::Secp256k1Tr,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Signature {
    Ed25519(frost_ed25519::Signature),
    Secp256k1(frost_secp256k1::Signature),
    Secp256k1Tr(frost_secp256k1_tr::Signature),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningCommitments {
    Ed25519(frost_ed25519::round1::SigningCommitments),
    Secp256k1(frost_secp256k1::round1::SigningCommitments),
    Secp256k1Tr(frost_secp256k1_tr::round1::SigningCommitments),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningNonces {
    Ed25519(frost_ed25519::round1::SigningNonces),
    Secp256k1(frost_secp256k1::round1::SigningNonces),
    Secp256k1Tr(frost_secp256k1_tr::round1::SigningNonces),
}

pub(crate) struct Validator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SignatureShare {
    Ed25519(frost_ed25519::round2::SignatureShare),
    Secp256k1(frost_secp256k1::round2::SignatureShare),
    Secp256k1Tr(frost_secp256k1_tr::round2::SignatureShare),
}
