use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::error::SessionError;

use super::{CryptoType, PkId};
mod ed25519;
mod secp256k1;
mod secp256k1_tr;

pub use ed25519::*;
pub use secp256k1::*;
pub use secp256k1_tr::*;

pub trait Cipher: Clone + std::fmt::Debug + Send + Sync + 'static {
    type Identifier: Identifier<CryptoError = Self::CryptoError>;
    type Signature: Signature<CryptoError = Self::CryptoError>;
    type SigningCommitments: Serialize
        + for<'de> Deserialize<'de>
        + fmt::Debug
        + Clone
        + Send
        + Sync;
    type SigningNonces: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone;
    type SignatureShare: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;

    type KeyPackage: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone;
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

    type DKGRound1SecretPackage: fmt::Debug + Clone;
    type DKGRound1Package: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;
    type DKGRound1PackageMap: PackageMap<Key = Self::Identifier, Value = Self::DKGRound1Package>
        + Serialize
        + for<'de> Deserialize<'de>;
    type DKGRound2SecretPackage: fmt::Debug + Clone;
    type DKGRound2Package: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync;
    type DKGRound2PackageMap: PackageMap<Key = Self::Identifier, Value = Self::DKGRound2Package>
        + Serialize
        + for<'de> Deserialize<'de>;
    type DKGRound2PackageMapMap: PackageMap<Key = Self::Identifier, Value = Self::DKGRound2PackageMap>
        + Serialize
        + for<'de> Deserialize<'de>;

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
}

pub trait Signature:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync
{
    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_bytes(&self) -> Result<Vec<u8>, Self::CryptoError>;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError>;
}
pub trait Identifier:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + TryFrom<u16> + Ord + Send + Sync
{
    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError>;
    fn from_u16(n: u16) -> Result<Self, Self::CryptoError>;
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
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
pub trait PackageMap:
    IntoIterator<Item = (Self::Key, Self::Value)> + fmt::Debug + Clone + Send + Sync
{
    type Key: Clone + fmt::Debug;
    type Value: Clone + fmt::Debug;
    type Iter<'a>: Iterator<Item = (&'a Self::Key, &'a Self::Value)>
    where
        Self: 'a;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
    fn insert(&mut self, key: Self::Key, value: Self::Value);
    fn new() -> Self;
    fn len(&self) -> usize;
    fn iter(&self) -> Self::Iter<'_>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<K, V> PackageMap for BTreeMap<K, V>
where
    K: Clone + fmt::Debug + Sync + Send + Ord,
    V: Clone + fmt::Debug + Sync + Send,
{
    type Key = K;
    type Value = V;
    type Iter<'a>
        = std::collections::btree_map::Iter<'a, K, V>
    where
        Self: 'a;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        BTreeMap::get(self, key)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        BTreeMap::insert(self, key, value);
    }
    fn iter(&self) -> Self::Iter<'_> {
        self.iter()
    }
    fn new() -> Self {
        BTreeMap::new()
    }

    fn len(&self) -> usize {
        BTreeMap::len(self)
    }

    fn is_empty(&self) -> bool {
        BTreeMap::is_empty(self)
    }
}
pub trait PublicKeyPackage:
    Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone + Send + Sync + PartialEq + Eq
{
    type Signature;
    type CryptoError;
    type VerifyingKey: VerifyingKey<Signature = Self::Signature, CryptoError = Self::CryptoError>;
    fn verifying_key(&self) -> &Self::VerifyingKey;
    fn serialize(&self) -> Result<Vec<u8>, Self::CryptoError>;
    fn deserialize(bytes: &[u8]) -> Result<Self, Self::CryptoError>;
    fn pkid(&self) -> Result<PkId, Self::CryptoError> {
        Ok(PkId::new(
            Sha256::digest(<Self as PublicKeyPackage>::serialize(&self)?).to_vec(),
        ))
    }
}

pub trait VerifyingKey: Serialize + for<'de> Deserialize<'de> + fmt::Debug + Clone {
    type Signature;
    type CryptoError;
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), Self::CryptoError>;
}
