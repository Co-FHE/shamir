mod keystore;
mod management;
pub(crate) use keystore::Keystore;
pub(crate) use management::KeystoreManagement;
use thiserror::Error;
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeystoreError {
    #[error("Key Error")]
    KeyError(String),
    #[error("IO Error")]
    IoError(String),
    #[error("Backup file exists: {0}")]
    BackupFileExists(String),
}

impl From<std::io::Error> for KeystoreError {
    fn from(e: std::io::Error) -> Self {
        KeystoreError::IoError(e.to_string())
    }
}
