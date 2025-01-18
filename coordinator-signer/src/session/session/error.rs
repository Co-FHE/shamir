#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid crypto type: {0}")]
    InvalidCryptoType(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Invalid session id format: {0}, {1}")]
    InvalidSessionIdFormat(String, String),
    #[error("Invalid subsession id format: {0}, {1}")]
    InvalidSubSessionIdFormat(String, String),
    #[error("Frost error: {0}")]
    FrostErrorEd25519(#[from] frost_ed25519::Error),
    #[error("Frost error: {0}")]
    FrostErrorSecp256k1(#[from] frost_secp256k1::Error),
    #[error("Frost error: {0}")]
    FrostErrorSecp256k1TR(#[from] frost_secp256k1_tr::Error),
}
