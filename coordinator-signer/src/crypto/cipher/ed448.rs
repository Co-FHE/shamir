use std::collections::BTreeMap;

use ed448_goldilocks::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    Cipher, CryptoType, Identifier, KeyPackage, PublicKeyPackage, Signature, SigningPackage, Tweak,
    VerifyingKey,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ed448Shake256;
impl Cipher for Ed448Shake256 {
    type Identifier = frost_ed448::Identifier;
    type Signature = frost_ed448::Signature;
    type SigningCommitments = frost_ed448::round1::SigningCommitments;
    type SigningNonces = frost_ed448::round1::SigningNonces;
    type SignatureShare = frost_ed448::round2::SignatureShare;

    type KeyPackage = frost_ed448::keys::KeyPackage;
    type SigningPackage = frost_ed448::SigningPackage;
    type VerifyingKey = frost_ed448::VerifyingKey;
    type PublicKeyPackage = frost_ed448::keys::PublicKeyPackage;

    type DKGRound1SecretPackage = frost_ed448::keys::dkg::round1::SecretPackage;
    type DKGRound1Package = frost_ed448::keys::dkg::round1::Package;
    type DKGRound2SecretPackage = frost_ed448::keys::dkg::round2::SecretPackage;
    type DKGRound2Package = frost_ed448::keys::dkg::round2::Package;

    type CryptoError = frost_ed448::Error;
    fn crypto_type() -> CryptoType {
        CryptoType::Ed448
    }

    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError> {
        frost_ed448::aggregate(signing_package, signature_shares, public_key)
    }

    fn dkg_part1<R: rand::RngCore + rand::CryptoRng>(
        identifier: Self::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut R,
    ) -> Result<(Self::DKGRound1SecretPackage, Self::DKGRound1Package), Self::CryptoError> {
        frost_ed448::keys::dkg::part1(identifier, max_signers, min_signers, rng)
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
        frost_ed448::keys::dkg::part2(secret_package, round1_package_map)
    }

    fn dkg_part3(
        secret_package: &Self::DKGRound2SecretPackage,
        round1_package_map: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
        round2_package_map: &BTreeMap<Self::Identifier, Self::DKGRound2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Self::CryptoError> {
        frost_ed448::keys::dkg::part3(secret_package, round1_package_map, round2_package_map)
    }

    fn sign(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        frost_ed448::round2::sign(signing_package, nonces, key_package)
    }

    fn commit<R: RngCore + CryptoRng>(
        key_package: &Self::KeyPackage,
        rng: &mut R,
    ) -> (Self::SigningNonces, Self::SigningCommitments) {
        frost_ed448::round1::commit(key_package.signing_share(), rng)
    }
}

impl Signature for frost_ed448::Signature {
    type CryptoError = frost_ed448::Error;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError> {
        self.serialize()
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        Self::deserialize(bytes.as_ref())
    }
}
impl SigningPackage for frost_ed448::SigningPackage {
    type Identifier = frost_ed448::Identifier;
    type SigningCommitments = frost_ed448::round1::SigningCommitments;
    type CryptoError = frost_ed448::Error;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError> {
        Ok(Self::new(commitments, message))
    }
}

impl Identifier for frost_ed448::Identifier {
    type CryptoError = frost_ed448::Error;
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

impl PublicKeyPackage for frost_ed448::keys::PublicKeyPackage {
    type Signature = frost_ed448::Signature;
    type CryptoError = frost_ed448::Error;
    type VerifyingKey = frost_ed448::VerifyingKey;
    type VerifyingShare = frost_ed448::keys::VerifyingShare;
    type Identifier = frost_ed448::Identifier;
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
        CryptoType::Ed448
    }
}
impl KeyPackage for frost_ed448::keys::KeyPackage {
    type CryptoError = frost_ed448::Error;
}
impl VerifyingKey for frost_ed448::VerifyingKey {
    type Signature = frost_ed448::Signature;
    type CryptoError = frost_ed448::Error;
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

fn hash_to_array(inputs: &[&[u8]]) -> [u8; 114] {
    let mut h = Shake256::default();
    for i in inputs {
        h.update(i);
    }
    let mut reader = h.finalize_xof();
    let mut output = [0u8; 114];
    reader.read(&mut output);
    output
}

fn tweak<T: AsRef<[u8]>>(
    public_key: &ed448_goldilocks::curve::ExtendedPoint,
    data: Option<T>,
) -> frost_core::Scalar<frost_ed448::Ed448Shake256> {
    match data {
        Some(data) => {
            let output = hash_to_array(&[
                b"tss",
                b"ed448",
                b"tweak",
                public_key.compress().0.as_slice(),
                data.as_ref(),
            ]);
            Scalar::from_bytes_mod_order_wide(&output)
        }
        None => {
            let output = hash_to_array(&[
                b"tss",
                b"ed448",
                b"tweak",
                public_key.compress().0.as_slice(),
            ]);
            Scalar::from_bytes_mod_order_wide(&output)
        }
    }
}
impl Tweak for frost_ed448::keys::KeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = <<frost_ed448::Ed448Shake256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator() * t;
        let key_package = self;
        let verifying_key =
            frost_ed448::VerifyingKey::new(key_package.verifying_key().to_element() + tp);
        let signing_share =
            frost_ed448::keys::SigningShare::new(key_package.signing_share().to_scalar() + t);
        let verifying_share =
            frost_ed448::keys::VerifyingShare::new(key_package.verifying_share().to_element() + tp);
        frost_ed448::keys::KeyPackage::new(
            *key_package.identifier(),
            signing_share,
            verifying_share,
            verifying_key,
            *key_package.min_signers(),
        )
    }
}
impl Tweak for frost_ed448::keys::PublicKeyPackage {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self {
        let t = tweak(&self.verifying_key().to_element(), data);
        let tp = <<frost_ed448::Ed448Shake256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator() * t;
        let public_key_package = self;
        let verifying_key =
            frost_ed448::VerifyingKey::new(public_key_package.verifying_key().to_element() + tp);
        // Recreate verifying share map with negated VerifyingShares
        // values.
        let verifying_shares: BTreeMap<_, _> = public_key_package
            .verifying_shares()
            .iter()
            .map(|(i, vs)| {
                let vs = frost_ed448::keys::VerifyingShare::new(vs.to_element() + tp);
                (*i, vs)
            })
            .collect();
        frost_ed448::keys::PublicKeyPackage::new(verifying_shares, verifying_key)
    }
}
