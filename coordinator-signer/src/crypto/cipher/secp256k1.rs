use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Cipher, CryptoType, Identifier, PackageMap, PkId, PublicKeyPackage, Signature, SigningPackage,
    VerifyingKey,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Secp256K1Sha256;
impl Cipher for Secp256K1Sha256 {
    type Identifier = frost_secp256k1::Identifier;
    type Signature = frost_secp256k1::Signature;
    type SigningCommitments = frost_secp256k1::round1::SigningCommitments;
    type SigningNonces = frost_secp256k1::round1::SigningNonces;
    type SignatureShare = frost_secp256k1::round2::SignatureShare;

    type KeyPackage = frost_secp256k1::keys::KeyPackage;
    type SigningPackage = frost_secp256k1::SigningPackage;
    type PublicKeyPackage = frost_secp256k1::keys::PublicKeyPackage;

    type VerifyingKey = frost_secp256k1::VerifyingKey;

    type DKGRound1SecretPackage = frost_secp256k1::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_secp256k1::keys::dkg::round1::Package;
    type DKGRound1PackageMap = BTreeMap<Self::Identifier, Self::DKGRound1Package>;
    type DKGRound2SecretPackage = frost_secp256k1::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_secp256k1::Error;
    fn crypto_type() -> CryptoType {
        CryptoType::Secp256k1
    }

    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError> {
        frost_secp256k1::aggregate(signing_package, signature_shares, public_key)
    }
    type DKGRound2PackageMapMap = BTreeMap<Self::Identifier, Self::DKGRound2PackageMap>;
}

impl Signature for frost_secp256k1::Signature {
    type CryptoError = frost_secp256k1::Error;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes.as_ref())
    }
}
impl SigningPackage for frost_secp256k1::SigningPackage {
    type Identifier = frost_secp256k1::Identifier;
    type SigningCommitments = frost_secp256k1::round1::SigningCommitments;
    type CryptoError = frost_secp256k1::Error;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError> {
        Ok(Self::new(commitments, message))
    }
}
impl Identifier for frost_secp256k1::Identifier {
    type CryptoError = frost_secp256k1::Error;
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

impl PublicKeyPackage for frost_secp256k1::keys::PublicKeyPackage {
    type Signature = frost_secp256k1::Signature;
    type CryptoError = frost_secp256k1::Error;
    type VerifyingKey = frost_secp256k1::VerifyingKey;
    type VerifyingShare = frost_secp256k1::keys::VerifyingShare;
    type Identifier = frost_secp256k1::Identifier;

    fn verifying_key(&self) -> &Self::VerifyingKey {
        self.verifying_key()
    }

    fn serialize(&self) -> Result<Vec<u8>, Self::CryptoError> {
        Ok(self.serialize()?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::CryptoError> {
        Ok(Self::deserialize(bytes)?)
    }

    fn verifying_shares(&self) -> &BTreeMap<Self::Identifier, Self::VerifyingShare> {
        self.verifying_shares()
    }
}

impl VerifyingKey for frost_secp256k1::VerifyingKey {
    type Signature = frost_secp256k1::Signature;
    type CryptoError = frost_secp256k1::Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError> {
        self.verify(msg, signature)
    }
    fn serialize(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes)
    }
}
