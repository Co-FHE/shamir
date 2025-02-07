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
    fn derive_key(&self, salt: &[u8]) -> Vec<u8> {
        libp2p::identity::Keypair::derive_secret(&self, salt)
            .unwrap()
            .to_vec()
    }
    #[cfg(test)]
    fn random_generate_keypair() -> Self {
        libp2p::identity::Keypair::generate_ed25519()
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
    fn from_keypair(keypair: &libp2p::identity::Keypair) -> Self {
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
#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::{Keypair, PeerId};

    #[test]
    fn test_peer_id() {
        // Generate a random keypair
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();

        // Test to/from bytes
        let bytes = peer_id.to_bytes();
        let decoded = PeerId::from_bytes(&bytes).unwrap();
        assert_eq!(peer_id, decoded);

        // Test to/from string format
        let str_repr = peer_id.to_fmt_string();
        let decoded = PeerId::from_fmt_str(&str_repr).unwrap();
        assert_eq!(peer_id, decoded);

        // Test invalid string format
        let result = PeerId::from_fmt_str("invalid peer id");
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key() {
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public();

        // Test to/from bytes
        let bytes = public_key.to_bytes();
        let decoded = libp2p::identity::PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, decoded);

        // Test to_identity
        let peer_id = public_key.to_identity();
        assert_eq!(peer_id, public_key.to_peer_id());

        // Test from_keypair
        let public_key2 = libp2p::identity::PublicKey::from_keypair(&keypair);
        assert_eq!(public_key, public_key2);

        // Test verify
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();
        assert!(public_key.verify(message, &signature));

        // Test invalid signature
        let mut bad_sig = signature.to_vec();
        if !bad_sig.is_empty() {
            bad_sig[0] ^= 1;
            assert!(!public_key.verify(message, &bad_sig));
        }
    }

    #[test]
    fn test_keypair() {
        let keypair = Keypair::generate_ed25519();

        // Test to_public_key
        let public_key = keypair.to_public_key();
        assert_eq!(public_key, keypair.public());

        // Test sign
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.public().verify(message, &signature));

        // Test derive_key
        let salt = b"test salt";
        let derived_key = keypair.derive_key(salt);
        assert!(!derived_key.is_empty());

        // Test random_generate_keypair
        #[cfg(test)]
        let random_key = Keypair::random_generate_keypair();
        #[cfg(test)]
        assert_ne!(random_key.public(), keypair.public());
    }
}
