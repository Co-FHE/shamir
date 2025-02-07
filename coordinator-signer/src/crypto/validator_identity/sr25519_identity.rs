use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_core::crypto::AccountId32;
use sp_core::crypto::Pair as CryptoPair;
use sp_core::sr25519::{Pair, Public, Signature};
use sp_core::{ByteArray, DeriveJunction};
use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use crate::utils;

use super::{
    ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};

#[derive(Debug, Clone)]
pub struct Sr25519Identity;

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Sr25519Id(pub [u8; 32]); // SHA256 hash of public key

impl ValidatorIdentity for Sr25519Identity {
    type Keypair = Pair;
    type PublicKey = Public;
    type Identity = AccountId32;
}
#[derive(Debug)]
pub struct Sr25519SignError;
impl fmt::Display for Sr25519SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sr25519SignError")
    }
}
impl StdError for Sr25519SignError {}
impl ValidatorIdentityKeypair for Pair {
    type PublicKey = Public;
    type SignError = Sr25519SignError;

    fn to_public_key(&self) -> Public {
        self.public()
    }

    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError> {
        Ok(<Pair as CryptoPair>::sign(self, message.as_ref()).to_raw_vec())
    }

    fn derive_key(&self, salt: &[u8]) -> Vec<u8> {
        let sha256 = Sha256::digest(salt);
        let (p, _) = self
            .derive(Some(DeriveJunction::hard(1)).into_iter(), None)
            .unwrap();
        return utils::list_hash(&[p.public().to_bytes(), sha256.to_vec()]);
    }
    fn random_generate_keypair() -> Self {
        Pair::generate().0
    }
}

#[derive(Debug)]
pub enum IdentityDecodeError {
    InvalidLength,
    InvalidAccountId32(String),
}

impl fmt::Display for IdentityDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid identity length"),
            Self::InvalidAccountId32(e) => write!(f, "Invalid account id32: {}", e),
        }
    }
}

impl StdError for IdentityDecodeError {}

impl ValidatorIdentityIdentity for AccountId32 {
    type PublicKey = Public;
    type DecodeError = IdentityDecodeError;

    fn from_public_key(public_key: Public) -> Self {
        AccountId32::from(public_key)
    }

    fn to_fmt_string(&self) -> String {
        self.to_string()
    }

    fn from_fmt_str(s: &str) -> Result<Self, Self::DecodeError> {
        Ok(AccountId32::from_str(s)
            .map_err(|_| Self::DecodeError::InvalidAccountId32(s.to_string()))?)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_raw_vec()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(IdentityDecodeError::InvalidLength);
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(AccountId32::from(result))
    }
}

impl ValidatorIdentityPublicKey for Public {
    type Identity = AccountId32;
    type Keypair = Pair;
    type DecodeError = IdentityDecodeError;

    fn to_identity(&self) -> Self::Identity {
        AccountId32::from(self.clone())
    }

    fn from_keypair(keypair: &Pair) -> Self {
        keypair.public()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_raw_vec()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(IdentityDecodeError::InvalidLength);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Public::from_raw(array))
    }

    fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(&self, message: T, signature: S) -> bool {
        if let Ok(sig) = Signature::from_slice(signature.as_ref()) {
            <Pair as CryptoPair>::verify(&sig, message.as_ref(), &self)
        } else {
            false
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::sr25519::{Pair, Public};
    use sp_core::Pair as CryptoPair;

    #[test]
    fn test_account_id32() {
        let id = AccountId32::from([1u8; 32]);
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), 32);
        let decoded = AccountId32::from_bytes(bytes).unwrap();
        assert_eq!(id, decoded);

        let str_repr = id.to_fmt_string();
        let decoded = AccountId32::from_fmt_str(&str_repr).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_public_key() {
        let (pair, _) = Pair::generate();
        let public = pair.public();

        // Test to/from bytes
        let bytes = public.to_bytes();
        let decoded = Public::from_bytes(&bytes).unwrap();
        assert_eq!(public, decoded);

        // Test verify
        let message = b"test message";
        let signature = <Pair as CryptoPair>::sign(&pair, message.as_ref()).to_raw_vec();
        assert!(<Public as ValidatorIdentityPublicKey>::verify(
            &public,
            message,
            signature.clone()
        ));

        // Test invalid signature
        let mut bad_sig = signature.to_vec();
        bad_sig[0] ^= 1;
        assert!(!public.verify(message, bad_sig));
    }

    #[test]
    fn test_identity_from_public_key() {
        let (pair, _) = Pair::generate();
        let public = pair.public();

        let id = public.to_identity();
        assert_eq!(id.to_bytes().len(), 32);
    }

    #[test]
    fn test_signing_key() {
        let (pair, _) = Pair::generate();

        // Test to_public_key
        let public_key = pair.to_public_key();
        assert_eq!(public_key, pair.public());

        // Test sign
        let message = b"test message";
        let signature = <Pair as CryptoPair>::sign(&pair, message.as_ref()).to_raw_vec();
        assert_eq!(signature.len(), 64);

        // Test derive_key
        let salt = b"test salt";
        let derived_key = pair.derive_key(salt);
        assert!(!derived_key.is_empty());

        // Test random_generate_keypair
        #[cfg(test)]
        let random_key = Pair::random_generate_keypair();
        #[cfg(test)]
        assert_ne!(random_key.public(), pair.public());
    }

    #[test]
    fn test_identity_decode_error() {
        // Test InvalidLength error
        let bytes = vec![0u8; 16];
        let result = AccountId32::from_bytes(bytes);
        assert!(matches!(result, Err(IdentityDecodeError::InvalidLength)));

        // Test HexError
        let invalid_hex = "invalid hex string";
        let result = AccountId32::from_fmt_str(invalid_hex);
        assert!(matches!(
            result,
            Err(IdentityDecodeError::InvalidAccountId32(_))
        ));

        // Test error formatting
        let invalid_length_error = IdentityDecodeError::InvalidLength;
        assert_eq!(invalid_length_error.to_string(), "Invalid identity length");

        let hex_error = IdentityDecodeError::InvalidAccountId32(invalid_hex.to_string());
        assert!(hex_error.to_string().contains("Invalid account id32"));
    }
}
