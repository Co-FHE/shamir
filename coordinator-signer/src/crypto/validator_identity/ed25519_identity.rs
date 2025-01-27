use ed25519_dalek::{Signature, SignatureError, SigningKey, VerifyingKey};
#[cfg(test)]
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fmt;

use crate::utils;

use super::{
    ValidatorIdentity, ValidatorIdentityIdentity, ValidatorIdentityKeypair,
    ValidatorIdentityPublicKey,
};

#[derive(Debug, Clone)]
pub struct Ed25519Identity;

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ed25519Id(pub [u8; 32]); // SHA256 hash of public key

impl ValidatorIdentity for Ed25519Identity {
    type Keypair = SigningKey;
    type PublicKey = VerifyingKey;
    type Identity = Ed25519Id;
}

impl ValidatorIdentityKeypair for SigningKey {
    type PublicKey = VerifyingKey;
    type SignError = ed25519_dalek::SignatureError;

    fn to_public_key(&self) -> VerifyingKey {
        self.verifying_key()
    }

    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Vec<u8>, Self::SignError> {
        Ok(
            <SigningKey as ed25519_dalek::Signer<ed25519_dalek::Signature>>::try_sign(
                self,
                message.as_ref(),
            )
            .unwrap()
            .to_bytes()
            .to_vec(),
        )
    }

    fn derive_key(&self, salt: &[u8]) -> Vec<u8> {
        utils::list_hash(&[self.to_bytes().as_slice(), salt])
    }
    #[cfg(test)]
    fn random_generate_keypair() -> Self {
        SigningKey::generate(&mut OsRng)
    }
}

#[derive(Debug)]
pub enum IdentityDecodeError {
    InvalidLength,
    HexError(hex::FromHexError),
}

impl fmt::Display for IdentityDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Invalid identity length"),
            Self::HexError(e) => write!(f, "Hex decode error: {}", e),
        }
    }
}

impl StdError for IdentityDecodeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::HexError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<hex::FromHexError> for IdentityDecodeError {
    fn from(e: hex::FromHexError) -> Self {
        Self::HexError(e)
    }
}

impl ValidatorIdentityIdentity for Ed25519Id {
    type PublicKey = VerifyingKey;
    type DecodeError = IdentityDecodeError;

    fn from_public_key(public_key: VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        Ed25519Id(hasher.finalize().into())
    }

    fn to_fmt_string(&self) -> String {
        hex::encode(self.0)
    }

    fn from_fmt_str(s: &str) -> Result<Self, Self::DecodeError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(IdentityDecodeError::InvalidLength);
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(Ed25519Id(result))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(IdentityDecodeError::InvalidLength);
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(Ed25519Id(result))
    }
}

impl ValidatorIdentityPublicKey for VerifyingKey {
    type Identity = Ed25519Id;
    type Keypair = SigningKey;
    type DecodeError = ed25519_dalek::SignatureError;

    fn to_identity(&self) -> Self::Identity {
        let mut hasher = Sha256::new();
        hasher.update(self.as_bytes());
        Ed25519Id(hasher.finalize().into())
    }

    fn from_keypair(keypair: &SigningKey) -> Self {
        keypair.verifying_key()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::DecodeError> {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            return Err(SignatureError::new());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        VerifyingKey::from_bytes(&array)
    }

    fn verify<T: AsRef<[u8]>, S: AsRef<[u8]>>(&self, message: T, signature: S) -> bool {
        if let Ok(sig) = Signature::from_slice(signature.as_ref()) {
            <VerifyingKey as ed25519_dalek::Verifier<Signature>>::verify(
                self,
                message.as_ref(),
                &sig,
            )
            .is_ok()
        } else {
            false
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_ed25519_id() {
        let id = Ed25519Id([1u8; 32]);
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), 32);
        let decoded = Ed25519Id::from_bytes(bytes).unwrap();
        assert_eq!(id.0, decoded.0);

        let str_repr = id.to_fmt_string();
        let decoded = Ed25519Id::from_fmt_str(&str_repr).unwrap();
        assert_eq!(id.0, decoded.0);
    }

    #[test]
    fn test_verifying_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Test to/from bytes
        let bytes = verifying_key.to_bytes();
        let decoded = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(verifying_key.as_bytes(), decoded.as_bytes());

        // Test verify
        let message = b"test message";
        let signature = signing_key.sign(message).unwrap();
        assert!(verifying_key.verify(message, signature.clone()));

        // Test invalid signature
        let mut bad_sig = signature.clone();
        bad_sig[0] ^= 1;
        assert!(verifying_key.verify(message, bad_sig,));
    }

    #[test]
    fn test_identity_from_public_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let id = verifying_key.to_identity();
        assert_eq!(id.0.len(), 32);
    }
}
