use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) struct PkId(Vec<u8>);

impl PkId {
    pub fn new(pkid: Vec<u8>) -> Self {
        Self(pkid)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Display for PkId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
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
