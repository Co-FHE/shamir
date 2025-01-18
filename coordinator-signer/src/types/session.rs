mod session_id;
mod subsession_id;
use std::collections::BTreeMap;

pub(crate) use session_id::SessionId;
pub(crate) use subsession_id::SubsessionId;

use crate::crypto::PkId;

use super::{error::SessionError, Cipher, ValidatorIdentityIdentity};

pub(crate) struct Participants<VII: ValidatorIdentityIdentity, C: Cipher>(
    BTreeMap<C::Identifier, VII>,
);

pub(crate) struct DKGBaseState<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) session_id: SessionId<VII>,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) min_signers: u16,
}

pub(crate) struct SigningBaseState<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) participants: Participants<VII, C>,
    pub(crate) pkid: PkId,
    pub(crate) subsession_id: SubsessionId<VII>,
    pub(crate) public_key: C::PublicKeyPackage,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> Participants<VII, C> {
    pub(crate) fn new<T: IntoIterator<Item = (u16, VII)>>(
        participants: T,
    ) -> Result<Self, SessionError<C>> {
        let mut participants_map: BTreeMap<C::Identifier, VII> = BTreeMap::new();
        if participants.len() < 1 {
            return Err(SessionError::InvalidParticipants(format!(
                "min signers is 1, got {}",
                participants.len()
            )));
        }
        for (id, identity) in participants {
            if participants_map.contains_key(&id) {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant id: {}",
                    id
                )));
            }
            // Identity must be different
            if participants_map
                .values()
                .any(|_identity| _identity == &identity)
            {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant identity: {}",
                    identity.to_fmt_string()
                )));
            }
            participants_map.insert(id, identity);
        }
        if participants_map.len() > 255 {
            return Err(SessionError::InvalidParticipants(format!(
                "max signers is 255, got {}",
                participants_map.len()
            )));
        }
        Ok(Self(participants_map))
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn check_min_signers(&self, min_signers: u16) -> Result<(), SessionError<C>> {
        if self.len() < min_signers as usize {
            return Err(SessionError::InvalidMinSigners(
                min_signers,
                self.len() as u16,
            ));
        }
        Ok(())
    }
}
