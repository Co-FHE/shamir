use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};

use crate::types::error::SessionError;

use super::{CryptoType, CryptoTypeError};

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PkId(Vec<u8>);
impl Serialize for PkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for PkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(PkId::from(s))
    }
}
impl PkId {
    pub fn new(pkid: Vec<u8>) -> Self {
        Self(pkid)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn crypto_type(&self) -> Result<CryptoType, CryptoTypeError> {
        if self.0.len() == 0 {
            return Err(CryptoTypeError::PkIdLengthIs0);
        }
        let crypto_type = CryptoType::try_from(self.0[0])?;
        Ok(crypto_type)
    }
}

pub(crate) fn pk_to_pkid(
    crypto_type: CryptoType,
    public_key_package: &Vec<u8>,
) -> Result<PkId, SessionError> {
    let mut pkid = vec![crypto_type.into()];
    pkid.extend(Sha256::digest(public_key_package.clone()));
    let pkid = PkId::from(pkid);
    Ok(pkid)
}
impl Display for PkId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

impl From<String> for PkId {
    fn from(s: String) -> Self {
        PkId::new(hex::decode(&s).unwrap())
    }
}

impl From<Vec<u8>> for PkId {
    fn from(v: Vec<u8>) -> Self {
        PkId::new(v)
    }
}
