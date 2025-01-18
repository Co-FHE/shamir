use sha2::{Digest, Sha256};

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
    type DKGRound1PackageMap = BTreeMap<Self::Identifier, Self::DKGRound1Package>;
    type DKGRound2SecretPackage = frost_secp256k1::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_secp256k1::Error;
    fn get_crypto_type() -> CryptoType {
        CryptoType::Secp256k1
    }

    type DKGRound2PackageMapMap = BTreeMap<Self::Identifier, Self::DKGRound2PackageMap>;
}

impl TryFrom<frost_secp256k1::keys::PublicKeyPackage> for PkId {
    type Error = frost_secp256k1::Error;
    fn try_from(pk: frost_secp256k1::keys::PublicKeyPackage) -> Result<Self, Self::Error> {
        Ok(PkId::new(
            Sha256::digest(&pk.serialize()?.to_vec()).to_vec(),
        ))
    }
}
