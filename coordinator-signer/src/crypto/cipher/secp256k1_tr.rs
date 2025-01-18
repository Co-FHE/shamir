use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{Cipher, CryptoType, PkId};
impl Cipher for frost_secp256k1_tr::Secp256K1Sha256TR {
    type Identifier = frost_secp256k1_tr::Identifier;
    type Signature = frost_secp256k1_tr::Signature;
    type SigningCommitments = frost_secp256k1_tr::round1::SigningCommitments;
    type SigningNonces = frost_secp256k1_tr::round1::SigningNonces;
    type SignatureShare = frost_secp256k1_tr::round2::SignatureShare;

    type KeyPackage = frost_secp256k1_tr::keys::KeyPackage;
    type SigningPackage = frost_secp256k1_tr::SigningPackage;
    type PublicKeyPackage = frost_secp256k1_tr::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_secp256k1_tr::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_secp256k1_tr::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_secp256k1_tr::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1_tr::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_secp256k1_tr::Error;
    fn get_crypto_type() -> CryptoType {
        CryptoType::Secp256k1Tr
    }
}
impl TryFrom<frost_secp256k1_tr::keys::PublicKeyPackage> for PkId {
    type Error = frost_secp256k1_tr::Error;
    fn try_from(pk: frost_secp256k1_tr::keys::PublicKeyPackage) -> Result<Self, Self::Error> {
        Ok(PkId::new(
            Sha256::digest(&pk.serialize()?.to_vec()).to_vec(),
        ))
    }
}
