use super::{
    Cipher, CryptoType, Identifier, KeyPackage, PublicKeyPackage, Signature, SigningPackage, Tweak,
    VerifyingKey,
};
use k256::elliptic_curve::ops::Reduce;
use k256::{
    elliptic_curve::{bigint::U256, point::AffineCoordinates},
    ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::digest::Digest;
use sha2::Sha256;
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
    type DKGRound2SecretPackage = frost_secp256k1::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_secp256k1::keys::dkg::round2::Package;

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
    fn dkg_part1<R: rand::RngCore + rand::CryptoRng>(
        identifier: Self::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut R,
    ) -> Result<(Self::DKGRound1SecretPackage, Self::DKGRound1Package), Self::CryptoError> {
        frost_secp256k1::keys::dkg::part1(identifier, max_signers, min_signers, rng)
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
        frost_secp256k1::keys::dkg::part2(secret_package, round1_package_map)
    }

    fn dkg_part3(
        secret_package: &Self::DKGRound2SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
        round2_packages: &BTreeMap<Self::Identifier, Self::DKGRound2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Self::CryptoError> {
        frost_secp256k1::keys::dkg::part3(secret_package, round1_packages, round2_packages)
    }

    fn sign(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        frost_secp256k1::round2::sign(signing_package, nonces, key_package)
    }

    fn commit<R: RngCore + CryptoRng>(
        key_package: &Self::KeyPackage,
        rng: &mut R,
    ) -> (Self::SigningNonces, Self::SigningCommitments) {
        frost_secp256k1::round1::commit(key_package.signing_share(), rng)
    }
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
        CryptoType::Secp256k1
    }
}
impl KeyPackage for frost_secp256k1::keys::KeyPackage {
    type CryptoError = frost_secp256k1::Error;
}
impl VerifyingKey for frost_secp256k1::VerifyingKey {
    type Signature = frost_secp256k1::Signature;
    type CryptoError = frost_secp256k1::Error;
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

/// Digest the hasher to a Scalar
fn hasher_to_scalar(hasher: Sha256) -> Scalar {
    // This is acceptable because secp256k1 curve order is close to 2^256,
    // and the input is uniformly random since it is a hash output, therefore
    // the bias is negligibly small.
    Scalar::reduce(U256::from_be_slice(&hasher.finalize()))
}

fn tagged_hash(tag: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}
fn tweak<T: AsRef<[u8]>>(
    public_key: &<<frost_secp256k1::Secp256K1Sha256 as frost_core::Ciphersuite>::Group as frost_core::Group>::Element,
    data: Option<T>,
) -> frost_core::Scalar<frost_secp256k1::Secp256K1Sha256> {
    let mut hasher = tagged_hash("veritss/secp256k1/tweak");
    hasher.update(public_key.to_affine().x());
    if let Some(data) = data {
        hasher.update(data.as_ref());
    }
    hasher_to_scalar(hasher)
}
impl Tweak for frost_secp256k1::keys::KeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = ProjectivePoint::GENERATOR * t;
        let key_package = self;
        let verifying_key =
            frost_secp256k1::VerifyingKey::new(key_package.verifying_key().to_element() + tp);
        let signing_share =
            frost_secp256k1::keys::SigningShare::new(key_package.signing_share().to_scalar() + t);
        let verifying_share = frost_secp256k1::keys::VerifyingShare::new(
            key_package.verifying_share().to_element() + tp,
        );
        frost_secp256k1::keys::KeyPackage::new(
            *key_package.identifier(),
            signing_share,
            verifying_share,
            verifying_key,
            *key_package.min_signers(),
        )
    }
}
impl Tweak for frost_secp256k1::keys::PublicKeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = ProjectivePoint::GENERATOR * t;
        let public_key_package = self;
        let verifying_key = frost_secp256k1::VerifyingKey::new(
            public_key_package.verifying_key().to_element() + tp,
        );
        // Recreate verifying share map with negated VerifyingShares
        // values.
        let verifying_shares: BTreeMap<_, _> = public_key_package
            .verifying_shares()
            .iter()
            .map(|(i, vs)| {
                let vs = frost_secp256k1::keys::VerifyingShare::new(vs.to_element() + tp);
                (*i, vs)
            })
            .collect();
        frost_secp256k1::keys::PublicKeyPackage::new(verifying_shares, verifying_key)
    }
}
