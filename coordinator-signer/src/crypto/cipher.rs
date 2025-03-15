use std::{collections::BTreeMap, fmt};

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{CryptoType, Identifier, PkId};
mod ed25519;
mod ed448;
mod p256;
mod ristretto255;
mod secp256k1;
mod secp256k1_tr;

pub use ed25519::*;
pub use ed448::*;
pub use p256::*;
pub use ristretto255::*;
pub use secp256k1::*;
pub use secp256k1_tr::*;

pub trait Cipher: Clone + std::fmt::Debug + Send + Sync + 'static + PartialEq + Eq {
    type Identifier: Identifier<CryptoError = Self::CryptoError>
        + Serialize
        + serde::de::DeserializeOwned;
    type Signature: Signature<CryptoError = Self::CryptoError>;
    type SigningCommitments: Serialize
        + for<'de> Deserialize<'de>
        + fmt::Debug
        + Clone
        + Send
        + Sync;
    type SigningNonces: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;
    type SignatureShare: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;

    type KeyPackage: KeyPackage;
    type SigningPackage: SigningPackage<
        Identifier = Self::Identifier,
        SigningCommitments = Self::SigningCommitments,
        CryptoError = Self::CryptoError,
    >;
    type VerifyingKey: VerifyingKey<Signature = Self::Signature, CryptoError = Self::CryptoError>;
    type PublicKeyPackage: PublicKeyPackage<
        Signature = Self::Signature,
        CryptoError = Self::CryptoError,
        VerifyingKey = Self::VerifyingKey,
    >;

    type DKGRound1SecretPackage: fmt::Debug + Clone + Send + Sync;
    type DKGRound1Package: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;
    type DKGRound2SecretPackage: fmt::Debug + Clone + Send + Sync;
    type DKGRound2Package: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;
    type CryptoError: std::error::Error
        + std::marker::Send
        + std::marker::Sync
        + 'static
        + Clone
        + Sized;
    fn crypto_type() -> CryptoType;
    fn aggregate(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Self::CryptoError>;
    fn dkg_part1<R: RngCore + CryptoRng>(
        identifier: Self::Identifier,
        max_signers: u16,
        min_signers: u16,
        rng: &mut R,
    ) -> Result<(Self::DKGRound1SecretPackage, Self::DKGRound1Package), Self::CryptoError>;
    fn dkg_part2(
        secret_package: Self::DKGRound1SecretPackage,
        round1_package_map: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
    ) -> Result<
        (
            Self::DKGRound2SecretPackage,
            BTreeMap<Self::Identifier, Self::DKGRound2Package>,
        ),
        Self::CryptoError,
    >;
    fn dkg_part3(
        secret_package: &Self::DKGRound2SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::DKGRound1Package>,
        round2_packages: &BTreeMap<Self::Identifier, Self::DKGRound2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Self::CryptoError>;
    fn sign(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Self::CryptoError>;
    fn commit<R: RngCore + CryptoRng>(
        key_package: &Self::KeyPackage,
        rng: &mut R,
    ) -> (Self::SigningNonces, Self::SigningCommitments);
    fn sign_with_tweak<T: AsRef<[u8]>>(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
        data: Option<T>,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        let key_package = key_package.clone().tweak(data);
        Self::sign(signing_package, nonces, &key_package)
    }
    fn aggregate_with_tweak<T: AsRef<[u8]>>(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
        data: Option<T>,
    ) -> Result<Self::Signature, Self::CryptoError> {
        let public_key = public_key.clone().tweak(data);
        Self::aggregate(signing_package, signature_shares, &public_key)
    }
}

pub trait KeyPackage:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync + Tweak
{
    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        Ok(bincode::serialize(&self).map_err(|e| e.to_string())?)
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, String> {
        Ok(bincode::deserialize(bytes.as_ref()).map_err(|e| e.to_string())?)
    }
}
pub trait Signature:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync
{
    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError>;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError>;
}

pub trait SigningPackage:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync
{
    type Identifier;
    type SigningCommitments;
    type CryptoError;
    fn new(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self, Self::CryptoError>;
}
pub trait PublicKeyPackage:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync + PartialEq + Eq + Tweak
{
    type Signature;
    type CryptoError;
    type VerifyingKey: VerifyingKey<Signature = Self::Signature, CryptoError = Self::CryptoError>;
    type VerifyingShare;
    type Identifier;
    fn verifying_key(&self) -> &Self::VerifyingKey;
    fn serialize_binary(&self) -> Result<Vec<u8>, Self::CryptoError>;
    fn deserialize_binary(bytes: &[u8]) -> Result<Self, Self::CryptoError>;
    fn crypto_type() -> CryptoType;
    fn pkid(&self) -> Result<PkId, Self::CryptoError> {
        let mut bytes = vec![<Self as PublicKeyPackage>::crypto_type().into()];
        bytes.extend(Sha256::digest(
            <Self as PublicKeyPackage>::serialize_binary(&self)?,
        ));
        Ok(PkId::new(bytes))
    }
    fn verifying_shares(&self) -> &BTreeMap<Self::Identifier, Self::VerifyingShare>;
    // fn has_even_y(&self) -> bool {
    //     let verifying_key = self.verifying_key();
    //     (!verifying_key.to_element().to_affine().y_is_odd()).into()
    // }

    // fn into_even_y(self, is_even: Option<bool>) -> Self {
    //     let is_even = is_even.unwrap_or_else(|| self.has_even_y());
    //     if !is_even {
    //         // Negate verifying key
    //         let verifying_key = Self::VerifyingKey::new(-self.verifying_key().to_element());
    //         // Recreate verifying share map with negated VerifyingShares
    //         // values.
    //         let verifying_shares: BTreeMap<_, _> = self
    //             .verifying_shares()
    //             .iter()
    //             .map(|(i, vs)| {
    //                 let vs = Self::VerifyingShare::new(-vs.to_element());
    //                 (*i, vs)
    //             })
    //             .collect();
    //         PublicKeyPackage::new(verifying_shares, verifying_key)
    //     } else {
    //         self
    //     }
    // }
}
pub trait VerifyingKey: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone {
    type Signature;
    type CryptoError;
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError>;
    fn serialize_frost(&self) -> Result<Vec<u8>, Self::CryptoError>;
    fn deserialize_frost(bytes: &[u8]) -> Result<Self, Self::CryptoError>;
}
pub trait Tweak {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self;
}
