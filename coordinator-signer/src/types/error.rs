use crate::crypto::Cipher;
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionError<C: Cipher> {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Missing data for split into request: {0}")]
    MissingDataForSplitIntoRequest(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Frost error: {0}")]
    CryptoError(C::CryptoError),
    #[error("Session id error: {0}")]
    SessionIdError(#[from] SessionIdError),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Coordinator session error: {0}")]
    CoordinatorSessionError(String),
    #[error("Signer session error: {0}")]
    SignerSessionError(String),
    #[error("Transform Wraping Message Error: {0}")]
    TransformWrapingMessageError(String),
    #[error("Send oneshot error: {0}")]
    SendOneshotError(String),
    #[error("Base info does not match: {0}")]
    BaseInfoNotMatch(String),
    #[error("Session not found: {0}")]
    SessionNotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionIdError {
    #[error("Invalid session id format: {0}")]
    InvalidSessionIdFormat(String),
    #[error("Invalid subsession id format: {0}")]
    InvalidSubSessionIdFormat(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Invalid pkid length: {0}")]
    InvalidPkIdLength(usize),
}
