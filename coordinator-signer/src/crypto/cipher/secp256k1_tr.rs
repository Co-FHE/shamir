use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Cipher, CryptoType, Identifier, PackageMap, PkId, PublicKeyPackage, Signature, SigningPackage,
    VerifyingKey,
};
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Secp256K1Sha256TR;

impl Cipher for Secp256K1Sha256TR {
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
    type DKGRound1PackageMap = BTreeMap<Self::Identifier, Self::DKGRound1Package>;
    type DKGRound2SecretPackage = frost_secp256k1_tr::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1_tr::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_secp256k1_tr::Error;
    fn crypto_type() -> CryptoType {
        CryptoType::Secp256k1Tr
    }
    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError> {
        frost_secp256k1_tr::aggregate(signing_package, signature_shares, public_key)
    }

    type DKGRound2PackageMapMap = BTreeMap<Self::Identifier, Self::DKGRound2PackageMap>;

    type VerifyingKey = frost_secp256k1_tr::VerifyingKey;
}
impl Signature for frost_secp256k1_tr::Signature {
    type CryptoError = frost_secp256k1_tr::Error;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes.as_ref())
    }
}

impl SigningPackage for frost_secp256k1_tr::SigningPackage {
    type Identifier = frost_secp256k1_tr::Identifier;
    type SigningCommitments = frost_secp256k1_tr::round1::SigningCommitments;
    type CryptoError = frost_secp256k1_tr::Error;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError> {
        Ok(Self::new(commitments, message))
    }
}
impl Identifier for frost_secp256k1_tr::Identifier {
    type CryptoError = frost_secp256k1_tr::Error;
    fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes.as_ref())
    }

    fn from_u16(n: u16) -> Result<Self, Self::CryptoError> {
        Ok(n.try_into()?)
    }
}
impl PublicKeyPackage for frost_secp256k1_tr::keys::PublicKeyPackage {
    type Signature = frost_secp256k1_tr::Signature;
    type CryptoError = frost_secp256k1_tr::Error;
    type VerifyingKey = frost_secp256k1_tr::VerifyingKey;
    fn verifying_key(&self) -> &Self::VerifyingKey {
        self.verifying_key()
    }

    fn serialize(&self) -> Result<Vec<u8>, Self::CryptoError> {
        Ok(self.serialize()?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::CryptoError> {
        Ok(Self::deserialize(bytes)?)
    }
}

impl VerifyingKey for frost_secp256k1_tr::VerifyingKey {
    type Signature = frost_secp256k1_tr::Signature;
    type CryptoError = frost_secp256k1_tr::Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError> {
        self.verify(msg, signature)
    }
}
