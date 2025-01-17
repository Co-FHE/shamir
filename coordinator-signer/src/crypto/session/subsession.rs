use crate::crypto::traits::ValidatorIdentity;
use std::collections::BTreeMap;
mod subsession_id;
use super::{CryptoType, SessionError, SessionId};
pub(crate) use subsession_id::SubSessionId;
pub(crate) struct SubSession<VI: ValidatorIdentity> {
    crypto_type: CryptoType,
    subsession_id: SubSessionId<VI::Identity>,
    min_signers: u16,
    participants: BTreeMap<u16, VI::Identity>,
    state: SubSessionState,
}
pub(crate) enum SubSessionState {
    Round1,
    Round2,
}
impl<VI: ValidatorIdentity> SubSession<VI> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        min_signers: u16,
        participants: BTreeMap<u16, VI::Identity>,
        crypto_type: CryptoType,
        sign_message: &[u8],
    ) -> Result<Self, SessionError> {
        let subsession_id = SubSessionId::new(
            crypto_type,
            min_signers,
            &participants,
            sign_message,
            &session_id,
        )?;
        Ok(Self {
            subsession_id,
            min_signers,
            participants,
            crypto_type,
            state: SubSessionState::Round1,
        })
    }
}
