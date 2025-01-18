use super::{Cipher, CryptoType, PkId};
use std::collections::BTreeMap;

impl Cipher for frost_secp256k1::Secp256K1Sha256 {
    type Identifier = frost_secp256k1::Identifier;
    type Signature = frost_secp256k1::Signature;
    type SigningCommitments = frost_secp256k1::round1::SigningCommitments;
    type SigningNonces = frost_secp256k1::round1::SigningNonces;
    type SignatureShare = frost_secp256k1::round2::SignatureShare;

    type KeyPackage = frost_secp256k1::keys::KeyPackage;
    type SigningPackage = frost_secp256k1::SigningPackage;
    type PublicKeyPackage = frost_secp256k1::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_secp256k1::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_secp256k1::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_secp256k1::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_secp256k1::Error;
    fn get_crypto_type() -> CryptoType {
        CryptoType::Secp256k1
    }
}

impl From<frost_secp256k1::keys::PublicKeyPackage> for PkId {
    fn from(pk: frost_secp256k1::keys::PublicKeyPackage) -> Self {
        PkId::new(pk.pkid().to_bytes())
    }
}
