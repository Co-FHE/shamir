use std::fmt;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierError(String);
impl std::error::Error for IdentifierError {}
impl std::fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Identifier: fmt::Debug + Clone + TryFrom<u16> + Ord + Send + Sync {
    type CryptoError: std::error::Error + std::marker::Send + std::marker::Sync + 'static;
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError>;
    fn from_u16(n: u16) -> Result<Self, Self::CryptoError>;
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
}
impl Identifier for u16 {
    type CryptoError = IdentifierError;
    fn to_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::CryptoError> {
        let bytes = bytes.as_ref();
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }
    fn from_u16(n: u16) -> Result<Self, Self::CryptoError> {
        Ok(n)
    }
}
