use std::collections::BTreeMap;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    Cipher, CryptoType, Identifier, KeyPackage, PublicKeyPackage, Signature, SigningPackage, Tweak,
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
    type VerifyingKey = frost_secp256k1_tr::VerifyingKey;
    type DKGRound1SecretPackage = frost_secp256k1_tr::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_secp256k1_tr::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_secp256k1_tr::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1_tr::keys::dkg::round2::Package;

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

    fn dkg_part1<R: rand::RngCore + rand::CryptoRng>(
        identifier: Self::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut R,
    ) -> Result<(Self::DKGRound1SecretPackage, Self::DKGRound1Package), Self::CryptoError> {
        frost_secp256k1_tr::keys::dkg::part1(identifier, max_signers, min_signers, rng)
    }

    fn dkg_part2(
        secret_package: Self::DKGRound1SecretPackage,
        round1_package_map: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
    ) -> Result<
        (
            Self::DKGRound2SecretPackage,
            BTreeMap<Self::Identifier, Self::DKGRound2Package>,
        ),
        Self::CryptoError,
    > {
        frost_secp256k1_tr::keys::dkg::part2(secret_package, round1_package_map)
    }

    fn dkg_part3(
        secret_package: &Self::DKGRound2SecretPackage,
        round1_package_map: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
        round2_package_map: &BTreeMap<Self::Identifier, Self::DKGRound2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Self::CryptoError> {
        frost_secp256k1_tr::keys::dkg::part3(secret_package, round1_package_map, round2_package_map)
    }

    fn sign(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        frost_secp256k1_tr::round2::sign(signing_package, nonces, key_package)
    }

    fn commit<R: RngCore + CryptoRng>(
        key_package: &Self::KeyPackage,
        rng: &mut R,
    ) -> (Self::SigningNonces, Self::SigningCommitments) {
        frost_secp256k1_tr::round1::commit(key_package.signing_share(), rng)
    }
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
    type VerifyingShare = frost_secp256k1_tr::keys::VerifyingShare;
    type Identifier = frost_secp256k1_tr::Identifier;

    fn verifying_key(&self) -> &Self::VerifyingKey {
        self.verifying_key()
    }

    fn serialize_binary(&self) -> Result<Vec<u8>, Self::CryptoError> {
        Ok(self.serialize()?)
    }

    fn deserialize_binary(bytes: &[u8]) -> Result<Self, Self::CryptoError> {
        Ok(Self::deserialize(bytes)?)
    }

    fn verifying_shares(&self) -> &BTreeMap<Self::Identifier, Self::VerifyingShare> {
        self.verifying_shares()
    }

    fn crypto_type() -> CryptoType {
        CryptoType::Secp256k1Tr
    }
}
impl KeyPackage for frost_secp256k1_tr::keys::KeyPackage {
    type CryptoError = frost_secp256k1_tr::Error;
}
impl VerifyingKey for frost_secp256k1_tr::VerifyingKey {
    type Signature = frost_secp256k1_tr::Signature;
    type CryptoError = frost_secp256k1_tr::Error;
    fn verify(&self, msg: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError> {
        self.verify(msg, signature)
    }

    fn serialize_frost(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }

    fn deserialize_frost(bytes: &[u8]) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes)
    }
}

impl Tweak for frost_secp256k1_tr::keys::PublicKeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        frost_secp256k1_tr::keys::Tweak::tweak(self, data)
    }
}
impl Tweak for frost_secp256k1_tr::keys::KeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        frost_secp256k1_tr::keys::Tweak::tweak(self, data)
    }
}
