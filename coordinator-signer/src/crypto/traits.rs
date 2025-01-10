use libp2p::identity::ParseError;
use std::{cmp, fmt};
pub trait ValidatorIdentity: fmt::Debug + Clone {
    type Keypair: Clone + ValidatorIdentityKeypair<PublicKey = Self::PublicKey>;
    type PublicKey: fmt::Debug
        + Clone
        + ValidatorIdentityPublicKey<Identity = Self::Identity, Keypair = Self::Keypair>;
    type Identity: fmt::Debug
        + Clone
        + ValidatorIdentityIdentity<PublicKey = Self::PublicKey>
        + Hash
        + cmp::Eq;
}
pub trait ValidatorIdentityPublicKey
where
    Self: Sized,
{
    type Identity: ValidatorIdentityIdentity;
    type Keypair: ValidatorIdentityKeypair;
    type DecodeError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_identity(&self) -> Self::Identity;
    #[allow(unused)]
    fn from_keypair(keypair: Self::Keypair) -> Self;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError>;
    fn to_bytes(&self) -> Vec<u8>;
    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: T) -> bool;
}
pub trait ValidatorIdentityKeypair {
    type PublicKey: ValidatorIdentityPublicKey;
    type SignError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_public_key(&self) -> Self::PublicKey;
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError>;
}
pub trait ValidatorIdentityIdentity
where
    Self: Sized,
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
use std::hash::Hash;
use std::str::FromStr;
#[derive(Debug, Clone)]
pub struct P2pIdentity;
impl ValidatorIdentity for P2pIdentity {
    type Keypair = libp2p::identity::Keypair;
    type PublicKey = libp2p::identity::PublicKey;
    type Identity = libp2p::identity::PeerId;
}
impl ValidatorIdentityKeypair for libp2p::identity::Keypair {
    type PublicKey = libp2p::identity::PublicKey;
    fn to_public_key(&self) -> libp2p::identity::PublicKey {
        self.public()
    }
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError> {
        self.sign(message.as_ref())
    }

    type SignError = libp2p::identity::SigningError;
}
impl ValidatorIdentityIdentity for libp2p::identity::PeerId {
    type PublicKey = libp2p::identity::PublicKey;
    type DecodeError = ParseError;
    fn from_public_key(public_key: libp2p::identity::PublicKey) -> Self {
        public_key.to_peer_id()
    }

    fn to_fmt_string(&self) -> String {
        self.to_base58()
    }

    fn from_fmt_str(s: &str) -> Result<Self, Self::DecodeError> {
        libp2p::identity::PeerId::from_str(s)
    }
    fn to_bytes(&self) -> Vec<u8> {
        libp2p::identity::PeerId::to_bytes(*self)
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError> {
        libp2p::identity::PeerId::from_bytes(bytes.as_ref())
    }
}
impl ValidatorIdentityPublicKey for libp2p::identity::PublicKey {
    type Identity = libp2p::identity::PeerId;

    type Keypair = libp2p::identity::Keypair;

    type DecodeError = libp2p::identity::DecodingError;
    fn to_identity(&self) -> libp2p::identity::PeerId {
        self.to_peer_id()
    }
    fn from_keypair(keypair: libp2p::identity::Keypair) -> Self {
        keypair.public()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.encode_protobuf()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, libp2p::identity::DecodingError> {
        libp2p::identity::PublicKey::try_decode_protobuf(bytes.as_ref())
    }

    fn verify<T: AsRef<[u8]>>(&self, message: T, signature: T) -> bool {
        self.verify(message.as_ref(), signature.as_ref())
    }
}
