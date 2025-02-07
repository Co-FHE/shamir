use std::collections::BTreeMap;

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use super::{
    Cipher, CryptoType, Identifier, KeyPackage, PublicKeyPackage, Signature, SigningPackage, Tweak,
    VerifyingKey,
};
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ristretto255Sha512;
impl Cipher for Ristretto255Sha512 {
    type Identifier = frost_ristretto255::Identifier;
    type Signature = frost_ristretto255::Signature;
    type SigningCommitments = frost_ristretto255::round1::SigningCommitments;
    type SigningNonces = frost_ristretto255::round1::SigningNonces;
    type SignatureShare = frost_ristretto255::round2::SignatureShare;

    type KeyPackage = frost_ristretto255::keys::KeyPackage;
    type SigningPackage = frost_ristretto255::SigningPackage;
    type VerifyingKey = frost_ristretto255::VerifyingKey;
    type PublicKeyPackage = frost_ristretto255::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_ristretto255::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_ristretto255::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_ristretto255::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_ristretto255::keys::dkg::round2::Package;

    type CryptoError = frost_ristretto255::Error;
    fn crypto_type() -> CryptoType {
        CryptoType::Ristretto255
    }

    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError> {
        frost_ristretto255::aggregate(signing_package, signature_shares, public_key)
    }

    fn dkg_part1<R: rand::RngCore + rand::CryptoRng>(
        identifier: Self::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut R,
    ) -> Result<(Self::DKGRound1SecretPackage, Self::DKGRound1Package), Self::CryptoError> {
        frost_ristretto255::keys::dkg::part1(identifier, max_signers, min_signers, rng)
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
        frost_ristretto255::keys::dkg::part2(secret_package, round1_package_map)
    }

    fn dkg_part3(
        secret_package: &Self::DKGRound2SecretPackage,
        round1_package_map: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
        round2_package_map: &BTreeMap<Self::Identifier, Self::DKGRound2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Self::CryptoError> {
        frost_ristretto255::keys::dkg::part3(secret_package, round1_package_map, round2_package_map)
    }

    fn sign(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        frost_ristretto255::round2::sign(signing_package, nonces, key_package)
    }

    fn commit<R: RngCore + CryptoRng>(
        key_package: &Self::KeyPackage,
        rng: &mut R,
    ) -> (Self::SigningNonces, Self::SigningCommitments) {
        frost_ristretto255::round1::commit(key_package.signing_share(), rng)
    }
}

impl Signature for frost_ristretto255::Signature {
    type CryptoError = frost_ristretto255::Error;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes.as_ref())
    }
}
impl SigningPackage for frost_ristretto255::SigningPackage {
    type Identifier = frost_ristretto255::Identifier;
    type SigningCommitments = frost_ristretto255::round1::SigningCommitments;
    type CryptoError = frost_ristretto255::Error;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError> {
        Ok(Self::new(commitments, message))
    }
}

impl Identifier for frost_ristretto255::Identifier {
    type CryptoError = frost_ristretto255::Error;
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

impl PublicKeyPackage for frost_ristretto255::keys::PublicKeyPackage {
    type Signature = frost_ristretto255::Signature;
    type CryptoError = frost_ristretto255::Error;
    type VerifyingKey = frost_ristretto255::VerifyingKey;
    type VerifyingShare = frost_ristretto255::keys::VerifyingShare;
    type Identifier = frost_ristretto255::Identifier;
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
        CryptoType::Ristretto255
    }
}
impl KeyPackage for frost_ristretto255::keys::KeyPackage {
    type CryptoError = frost_ristretto255::Error;
}
impl VerifyingKey for frost_ristretto255::VerifyingKey {
    type Signature = frost_ristretto255::Signature;
    type CryptoError = frost_ristretto255::Error;
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
fn tagged_hash(tag: &str) -> Sha512 {
    let mut hasher = Sha512::new();
    let mut tag_hasher = Sha512::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}
fn tweak<T: AsRef<[u8]>>(
    public_key: &RistrettoPoint,
    data: Option<T>,
) -> frost_core::Scalar<frost_ristretto255::Ristretto255Sha512> {
    let mut hasher = tagged_hash("tss/ristretto255/tweak");
    hasher.update(public_key.compress().to_bytes());
    if let Some(data) = data {
        hasher.update(data.as_ref());
    }
    let mut output = [0u8; 64];
    output.copy_from_slice(hasher.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&output)
}
impl Tweak for frost_ristretto255::keys::KeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = <<frost_ristretto255::Ristretto255Sha512 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator() * t;
        let key_package = self;
        let verifying_key =
            frost_ristretto255::VerifyingKey::new(key_package.verifying_key().to_element() + tp);
        let signing_share = frost_ristretto255::keys::SigningShare::new(
            key_package.signing_share().to_scalar() + t,
        );
        let verifying_share = frost_ristretto255::keys::VerifyingShare::new(
            key_package.verifying_share().to_element() + tp,
        );
        frost_ristretto255::keys::KeyPackage::new(
            *key_package.identifier(),
            signing_share,
            verifying_share,
            verifying_key,
            *key_package.min_signers(),
        )
    }
}
impl Tweak for frost_ristretto255::keys::PublicKeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = <<frost_ristretto255::Ristretto255Sha512 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator() * t;
        let public_key_package = self;
        let verifying_key = frost_ristretto255::VerifyingKey::new(
            public_key_package.verifying_key().to_element() + tp,
        );
        // Recreate verifying share map with negated VerifyingShares
        // values.
        let verifying_shares: BTreeMap<_, _> = public_key_package
            .verifying_shares()
            .iter()
            .map(|(i, vs)| {
                let vs = frost_ristretto255::keys::VerifyingShare::new(vs.to_element() + tp);
                (*i, vs)
            })
            .collect();
        frost_ristretto255::keys::PublicKeyPackage::new(verifying_shares, verifying_key)
    }
}
