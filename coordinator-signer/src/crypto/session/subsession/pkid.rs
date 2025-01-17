use hex::encode as hex_encode;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) struct PKID(Vec<u8>);

impl PKID {
    pub fn new(pkid: Vec<u8>) -> Self {
        Self(pkid)
    }
}

impl Display for PKID {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for PKID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(PKID::new(
            hex::decode(&s).map_err(serde::de::Error::custom)?,
        ))
    }
}
impl From<String> for PKID {
    fn from(s: String) -> Self {
        PKID::new(hex::decode(&s).unwrap())
    }
}
