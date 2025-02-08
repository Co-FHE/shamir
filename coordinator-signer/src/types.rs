pub(crate) mod auto_dkg;
pub use auto_dkg::*;
pub(crate) mod error;
pub(crate) mod message;
mod session;
mod signature_suite;
mod validator;

pub(crate) use session::{Participants, SessionId, SubsessionId};
pub use signature_suite::GroupPublicKeyInfo;
pub(crate) use signature_suite::SignatureSuite;
pub use signature_suite::SignatureSuiteInfo;
pub(crate) use validator::Validator;

use crate::crypto::{Cipher, ValidatorIdentityIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectionState {
    Connected,
    Disconnected(Option<tokio::time::Instant>),
    Connecting(tokio::time::Instant),
}
