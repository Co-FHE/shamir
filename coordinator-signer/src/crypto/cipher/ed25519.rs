use std::collections::BTreeMap;

use super::{Cipher, CryptoType, PkId};

impl Cipher for frost_ed25519::Ed25519Sha512 {
    type Identifier = frost_ed25519::Identifier;
    type Signature = frost_ed25519::Signature;
    type SigningCommitments = frost_ed25519::round1::SigningCommitments;
    type SigningNonces = frost_ed25519::round1::SigningNonces;
    type SignatureShare = frost_ed25519::round2::SignatureShare;

    type KeyPackage = frost_ed25519::keys::KeyPackage;
    type SigningPackage = frost_ed25519::SigningPackage;
    type PublicKeyPackage = frost_ed25519::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_ed25519::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_ed25519::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_ed25519::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_ed25519::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_ed25519::Error;
    fn get_crypto_type() -> CryptoType {
        CryptoType::Ed25519
    }
}

impl From<frost_ed25519::keys::PublicKeyPackage> for PkId {
    fn from(pk: frost_ed25519::keys::PublicKeyPackage) -> Self {
        PkId::new(pk.pkid().to_bytes())
    }
}
