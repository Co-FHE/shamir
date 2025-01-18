use hex::encode as hex_encode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) struct PkId(Vec<u8>);

impl PkId {
    pub fn new(pkid: Vec<u8>) -> Self {
        Self(pkid)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkid_serde() {
        let original_bytes = vec![1, 2, 3, 4, 5];
        let pkid = PkId::new(original_bytes.clone());
        tracing::info!("PKID: {}", pkid);
        // Test serialization
        let serialized = serde_json::to_string(&pkid).unwrap();
        println!("Serialized: {}", serialized);
        // Test deserialization
        let deserialized: PkId = serde_json::from_str(&serialized).unwrap();
        println!("Deserialized: {}", deserialized);
        // Verify the bytes are preserved through serde
        assert_eq!(deserialized.0, original_bytes);
    }

    #[test]
    fn test_pkid_display() {
        let pkid = PkId::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(pkid.to_string(), "deadbeef");
    }

    #[test]
    fn test_pkid_from_string() {
        let hex_str = "deadbeef".to_string();
        let pkid = PkId::from(hex_str);
        assert_eq!(pkid.0, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_pkid_equality() {
        let pkid1 = PkId::new(vec![1, 2, 3]);
        let pkid2 = PkId::new(vec![1, 2, 3]);
        let pkid3 = PkId::new(vec![4, 5, 6]);

        assert_eq!(pkid1, pkid2);
        assert_ne!(pkid1, pkid3);
    }
}
