mod session_id;
mod subsession_id;
use std::{collections::BTreeMap, ops::Deref};

use serde::{Deserialize, Serialize};
pub(crate) use session_id::SessionId;
pub(crate) use subsession_id::SubsessionId;

use crate::crypto::{Identifier, PkId};

use super::{error::SessionError, Cipher, ValidatorIdentityIdentity};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Participants<VII: ValidatorIdentityIdentity, C: Cipher>(
    BTreeMap<C::Identifier, VII>,
);

pub(crate) struct DKGBaseState<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) session_id: SessionId,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) min_signers: u16,
}

pub(crate) struct SigningBaseState<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) participants: Participants<VII, C>,
    pub(crate) pkid: PkId,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) public_key: C::PublicKeyPackage,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> Participants<VII, C> {
    pub(crate) fn new<T: IntoIterator<Item = (C::Identifier, VII)>>(
        participants: T,
    ) -> Result<Self, SessionError<C>> {
        let mut participants_map: BTreeMap<C::Identifier, VII> = BTreeMap::new();
        for (id, identity) in participants {
            if participants_map.contains_key(&id.clone().try_into().unwrap()) {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant id: {}",
                    id.to_string()
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
        if participants_map.len() < 1 {
            return Err(SessionError::InvalidParticipants(format!(
                "min signers is 1, got {}",
                participants_map.len()
            )));
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
    pub(crate) fn check_identifier_identity_exists(
        &self,
        identifier: &C::Identifier,
        identity: &VII,
    ) -> Result<(), SessionError<C>> {
        match self.get(identifier) {
            Some(_identity) => {
                if _identity != identity {
                    return Err(SessionError::InvalidParticipants(format!(
                        "identity does not match: {:?} vs {:?}",
                        _identity, identity
                    )));
                }
            }
            None => {
                return Err(SessionError::InvalidParticipants(format!(
                    "identity not found for identifier: {:?}",
                    identifier
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn check_keys_equal<V>(
        &self,
        other: &BTreeMap<C::Identifier, V>,
    ) -> Result<(), SessionError<C>> {
        if self.len() != other.len() {
            return Err(SessionError::InvalidParticipants(format!(
                "participants length does not match: {:?} vs {:?}",
                self.len(),
                other.len()
            )));
        }
        for (key, _) in self.iter() {
            if !other.contains_key(key) {
                return Err(SessionError::InvalidParticipants(format!(
                    "participants keys do not match: {:?} vs {:?}",
                    self.keys(),
                    other.keys()
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn check_min_signers(&self, min_signers: u16) -> Result<(), SessionError<C>> {
        if self.len() < min_signers as usize {
            return Err(SessionError::InvalidParticipants(format!(
                "min signers is {}, got {}",
                min_signers,
                self.len() as u16
            )));
        }

        if min_signers < (self.len() as u16 + 1) / 2 || min_signers == 0 {
            let msg = format!(
                "Min signers is too low, min_signers: {}, validators: {}",
                min_signers,
                self.len()
            );
            return Err(SessionError::InvalidParticipants(msg));
        }
        Ok(())
    }
}

impl<VII: ValidatorIdentityIdentity, C: Cipher> Deref for Participants<VII, C> {
    type Target = BTreeMap<C::Identifier, VII>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
