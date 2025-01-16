#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Invalid session id format: {0}, {1}")]
    InvalidSessionIdFormat(String, String),
}
