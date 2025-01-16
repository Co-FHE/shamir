use libp2p::identity::ParseError;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::str::FromStr;
mod ed25519;
mod p2p_identity;
pub(crate) use ed25519::*;
pub(crate) use p2p_identity::*;
use std::{cmp, fmt};
pub trait ValidatorIdentity: fmt::Debug + Clone {
    type Keypair: ValidatorIdentityKeypair<PublicKey = Self::PublicKey>;
    type PublicKey: ValidatorIdentityPublicKey<Identity = Self::Identity, Keypair = Self::Keypair>;
    type Identity: ValidatorIdentityIdentity<PublicKey = Self::PublicKey>
        + Serialize
        + for<'de> Deserialize<'de>
        + 'static;
}
pub trait ValidatorIdentityPublicKey
where
    Self: Sized + fmt::Debug + Clone,
{
    type Identity: ValidatorIdentityIdentity;
    type Keypair: ValidatorIdentityKeypair;
    type DecodeError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_identity(&self) -> Self::Identity;
    #[allow(unused)]
    fn from_keypair(keypair: Self::Keypair) -> Self;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError>;
    fn to_bytes(&self) -> Vec<u8>;
    fn verify<M: AsRef<[u8]>, S: AsRef<[u8]>>(&self, message: M, signature: S) -> bool;
}
pub trait ValidatorIdentityKeypair
where
    Self: Clone,
{
    type PublicKey: ValidatorIdentityPublicKey;
    type SignError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_public_key(&self) -> Self::PublicKey;
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError>;
}
pub trait ValidatorIdentityIdentity
where
    Self: Sized + Hash + cmp::Eq + cmp::Ord + Send + Sync + Clone + fmt::Debug,
{
    type PublicKey: ValidatorIdentityPublicKey;
    type DecodeError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    #[allow(unused)]
    fn from_public_key(public_key: Self::PublicKey) -> Self;
    // to_bytes is not same as to_string.to_bytes(), this is for the purpose of serialization
    fn to_fmt_string(&self) -> String;
    fn to_bytes(&self) -> Vec<u8>;
    #[allow(unused)]
    fn from_fmt_str(s: &str) -> Result<Self, Self::DecodeError>;
    #[allow(unused)]
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError>;
}
