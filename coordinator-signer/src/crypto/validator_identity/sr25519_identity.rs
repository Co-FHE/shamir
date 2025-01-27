use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_core::crypto::Pair as CryptoPair;
use sp_core::sr25519::{Pair, Public, Signature};
use sp_core::{ByteArray, DeriveJunction};
use sp_runtime::AccountId32;
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
    #[cfg(test)]
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
