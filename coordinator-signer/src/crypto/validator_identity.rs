use serde::{Deserialize, Serialize};
use std::hash::Hash;
pub mod ed25519_identity;
pub mod p2p_identity;
pub mod sr25519_identity;
use std::{cmp, fmt};
pub trait ValidatorIdentity: fmt::Debug + Clone + 'static {
    type Keypair: ValidatorIdentityKeypair<PublicKey = Self::PublicKey>;
    type PublicKey: ValidatorIdentityPublicKey<Identity = Self::Identity, Keypair = Self::Keypair>;
    type Identity: ValidatorIdentityIdentity<PublicKey = Self::PublicKey>
        + Serialize
        + for<'de> Deserialize<'de>;
}
pub trait ValidatorIdentityPublicKey
where
    Self: Sized + fmt::Debug + Clone + std::marker::Send + std::marker::Sync + 'static + PartialEq,
{
    type Identity: ValidatorIdentityIdentity;
    type Keypair: ValidatorIdentityKeypair;
    type DecodeError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_identity(&self) -> Self::Identity;
    fn from_keypair(keypair: &Self::Keypair) -> Self;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError>;
    fn to_bytes(&self) -> Vec<u8>;
    fn verify<M: AsRef<[u8]>, S: AsRef<[u8]>>(&self, message: M, signature: S) -> bool;
}
pub trait ValidatorIdentityKeypair
where
    Self: Clone + std::marker::Send + std::marker::Sync + 'static,
{
    type PublicKey: ValidatorIdentityPublicKey;
    type SignError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_public_key(&self) -> Self::PublicKey;
    // use for keystore, must be sure if salt is same, the derived key is same. else, it will be different.
    fn derive_key(&self, salt: &[u8]) -> Vec<u8>;
    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError>;
    #[cfg(test)]
    fn random_generate_keypair() -> Self;
}
pub trait ValidatorIdentityIdentity
where
    Self: Sized + Hash + cmp::Eq + cmp::Ord + Send + Sync + Clone + fmt::Debug + 'static,
{
    type PublicKey: ValidatorIdentityPublicKey;
    type DecodeError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn from_public_key(public_key: Self::PublicKey) -> Self;
    // to_bytes is not same as to_string.to_bytes(), this is for the purpose of serialization
    fn to_fmt_string(&self) -> String;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_fmt_str(s: &str) -> Result<Self, Self::DecodeError>;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError>;
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test() {
        test_single::<p2p_identity::P2pIdentity>();
        println!("p2p_identity test done");
        test_single::<sr25519_identity::Sr25519Identity>();
        println!("sr25519 test done");
        test_single::<ed25519_identity::Ed25519Identity>();
        println!("ed25519 test done");
    }
    fn test_single<T: ValidatorIdentity>() {
        let keypair = T::Keypair::random_generate_keypair();
        // test to_public_key
        let public_key = keypair.clone().to_public_key();
        let public_key1 = T::PublicKey::from_keypair(&keypair);
        assert_eq!(public_key, public_key1);
        // test derive_key
        let salt = b"test";
        let derived_key = keypair.derive_key(salt);
        let derived_key1 = keypair.clone().derive_key(salt);
        assert_eq!(derived_key, derived_key1);
        let another_salt = b"test2";
        let derived_key2 = keypair.derive_key(another_salt);
        assert_ne!(derived_key, derived_key2);

        // test sign
        let message = b"test";
        let signature = keypair.sign(message).unwrap();
        assert!(public_key.verify(message, &signature));
        assert!(!public_key.verify("test2", &signature));
        let new_keypair = T::Keypair::random_generate_keypair();
        let signature2 = new_keypair.sign("test").unwrap();
        assert!(!public_key.verify("test", &signature2));

        // test public key
        let public_key2 = T::PublicKey::from_keypair(&new_keypair);
        assert_ne!(public_key, public_key2);
        // test from_bytes and to_bytes
        let bytes = public_key.to_bytes();
        let public_key3 = T::PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key, public_key3);
        assert_ne!(public_key3, public_key2);

        //test to_identity
        let identity = public_key.to_identity();
        let identity2 = public_key2.to_identity();
        let identity3 = public_key3.to_identity();
        assert_ne!(identity, identity2);
        assert_eq!(identity, identity3);
        assert_ne!(identity2, identity3);

        //test from_public_key
        let identity_from = T::Identity::from_public_key(public_key);
        assert_eq!(identity, identity_from);
        let identity_from2 = T::Identity::from_public_key(public_key2);
        assert_ne!(identity, identity_from2);
        let identity_from3 = T::Identity::from_public_key(public_key3);
        assert_eq!(identity, identity_from3);

        //test to_fmt_string
        let fmt_str = identity.to_fmt_string();
        let identity4 = T::Identity::from_fmt_str(&fmt_str).unwrap();
        assert_eq!(identity, identity4);

        let bytes = identity.to_bytes();
        let identity5 = T::Identity::from_bytes(&bytes).unwrap();
        assert_eq!(identity, identity5);
    }
}
