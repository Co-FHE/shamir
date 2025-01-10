use std::str::FromStr;

use libp2p::identity::ParseError;

use super::{
    ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};

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

    fn verify<T: AsRef<[u8]>, U: AsRef<[u8]>>(&self, message: T, signature: U) -> bool {
        self.verify(message.as_ref(), signature.as_ref())
    }
}
