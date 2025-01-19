use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::error::SessionError;

use super::{
    Cipher, CryptoType, Identifier, PackageMap, PkId, PublicKeyPackage, SigningPackage,
    VerifyingKey,
};
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ed25519Sha512;
impl Cipher for Ed25519Sha512 {
    type Identifier = frost_ed25519::Identifier;
    type Signature = frost_ed25519::Signature;
    type SigningCommitments = frost_ed25519::round1::SigningCommitments;
    type SigningNonces = frost_ed25519::round1::SigningNonces;
    type SignatureShare = frost_ed25519::round2::SignatureShare;

    type KeyPackage = frost_ed25519::keys::KeyPackage;
    type SigningPackage = frost_ed25519::SigningPackage;
    type VerifyingKey = frost_ed25519::VerifyingKey;
    type PublicKeyPackage = frost_ed25519::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_ed25519::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_ed25519::keys::dkg::round1::Package;
    type DKGRound1PackageMap = BTreeMap<Self::Identifier, Self::DKGRound1Package>;
    type DKGRound2SecretPackage = frost_ed25519::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_ed25519::keys::dkg::round2::Package;
    type DKGRound2PackageMap = BTreeMap<Self::Identifier, Self::DKGRound2Package>;

    type CryptoError = frost_ed25519::Error;
    fn get_crypto_type() -> CryptoType {
        CryptoType::Ed25519
    }

    type DKGRound2PackageMapMap = BTreeMap<Self::Identifier, Self::DKGRound2PackageMap>;

    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError> {
        frost_ed25519::aggregate(signing_package, signature_shares, public_key)
    }
}
impl SigningPackage for frost_ed25519::SigningPackage {
    type Identifier = frost_ed25519::Identifier;
    type SigningCommitments = frost_ed25519::round1::SigningCommitments;
    type CryptoError = frost_ed25519::Error;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError> {
        Ok(Self::new(commitments, message))
    }
}

impl Identifier for frost_ed25519::Identifier {
    type CryptoError = frost_ed25519::Error;
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

impl PublicKeyPackage for frost_ed25519::keys::PublicKeyPackage {
    type Signature = frost_ed25519::Signature;
    type CryptoError = frost_ed25519::Error;
    type VerifyingKey = frost_ed25519::VerifyingKey;
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

impl VerifyingKey for frost_ed25519::VerifyingKey {
    type Signature = frost_ed25519::Signature;
    type CryptoError = frost_ed25519::Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError> {
        self.verify(msg, signature)
    }
}
