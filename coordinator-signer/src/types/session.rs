mod session_id;
mod subsession_id;
use std::{collections::BTreeMap, ops::Deref};

use serde::{Deserialize, Serialize};
pub(crate) use session_id::SessionId;
pub(crate) use subsession_id::SubsessionId;

use crate::crypto::Identifier;

use super::{error::SessionError, Cipher, ValidatorIdentityIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Participants<VII: ValidatorIdentityIdentity, CI: Identifier>(BTreeMap<CI, VII>);
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParticipantsError {
    #[error("duplicate participant id: {0}")]
    DuplicateParticipantId(String),
    #[error("duplicate participant identity: {0}")]
    DuplicateParticipantIdentity(String),
    #[error("invalid min signers: {0}")]
    MinSigners(String),
    #[error("max signers is 255, got {0}")]
    MaxSigners(usize),
    #[error("serialize error: {0}")]
    SerializeError(String),
    #[error("deserialize error: {0}")]
    DeserializeError(String),
    #[error("identity does not match: {0} vs {1}")]
    IdentityDoesNotMatch(String, String),
    #[error("identity not found for identifier: {0}")]
    IdentityNotFound(String),
    #[error("participants not match: {0}")]
    ParticipantsNotMatch(String),
}
impl<VII: ValidatorIdentityIdentity, CI: Identifier> Participants<VII, CI> {
    pub(crate) fn new<T: IntoIterator<Item = (CI, VII)>>(
        participants: T,
    ) -> Result<Self, ParticipantsError> {
        let mut participants_map: BTreeMap<CI, VII> = BTreeMap::new();
        for (id, identity) in participants {
            if participants_map.contains_key(&id.clone()) {
                return Err(ParticipantsError::DuplicateParticipantId(id.to_string()));
            }
            // Identity must be different
            if participants_map
                .values()
                .any(|_identity| _identity == &identity)
            {
                return Err(ParticipantsError::DuplicateParticipantIdentity(
                    identity.to_fmt_string(),
                ));
            }
            participants_map.insert(id, identity);
        }
        if participants_map.len() < 1 {
            return Err(ParticipantsError::MinSigners(format!(
                "min signers is {}, got {}",
                1,
                participants_map.len()
            )));
        }
        if participants_map.len() > 255 {
            return Err(ParticipantsError::MaxSigners(participants_map.len()));
        }

        Ok(Self(participants_map))
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, ParticipantsError> {
        let mut vec = Vec::new();
        for (id, identity) in self.0.iter() {
            vec.push((id.to_bytes(), identity.to_bytes()));
        }
        Ok(bincode::serialize(&vec)
            .map_err(|e| ParticipantsError::SerializeError(e.to_string()))?)
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, ParticipantsError> {
        let vec = bincode::deserialize::<Vec<(Vec<u8>, Vec<u8>)>>(bytes)
            .map_err(|e| ParticipantsError::DeserializeError(e.to_string()))?;
        let mut participants_map = BTreeMap::new();
        for (id, identity) in vec {
            participants_map.insert(
                CI::from_bytes(&id)
                    .map_err(|e| ParticipantsError::DeserializeError(e.to_string()))?,
                VII::from_bytes(&identity)
                    .map_err(|e| ParticipantsError::DeserializeError(e.to_string()))?,
            );
        }
        Ok(Self(participants_map))
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn filter(&self, filter: &Vec<CI>) -> Result<Self, ParticipantsError> {
        let participants = self
            .0
            .iter()
            .filter(|(id, _)| filter.contains(id))
            .map(|(id, identity)| (id.clone(), identity.clone()))
            .collect::<Vec<(CI, VII)>>();
        if participants.len() != filter.len() {
            return Err(ParticipantsError::ParticipantsNotMatch(format!(
                "participants length does not match: {:?} vs {:?}",
                participants.len(),
                filter.len()
            )));
        }
        Participants::new(participants)
    }
    pub(crate) fn check_identifier_identity_exists(
        &self,
        identifier: &CI,
        identity: &VII,
    ) -> Result<(), ParticipantsError> {
        match self.get(identifier) {
            Some(_identity) => {
                if _identity != identity {
                    return Err(ParticipantsError::IdentityDoesNotMatch(
                        _identity.to_fmt_string(),
                        identity.to_fmt_string(),
                    ));
                }
            }
            None => {
                return Err(ParticipantsError::IdentityNotFound(identifier.to_string()));
            }
        }
        Ok(())
    }
    pub(crate) fn check_keys_equal<V>(
        &self,
        other: &BTreeMap<CI, V>,
    ) -> Result<(), ParticipantsError> {
        if self.len() != other.len() {
            return Err(ParticipantsError::ParticipantsNotMatch(format!(
                "length: {:?} vs {:?}",
                self.len(),
                other.len()
            )));
        }
        for (key, _) in self.iter() {
            if !other.contains_key(key) {
                return Err(ParticipantsError::ParticipantsNotMatch(format!(
                    "key: {:?} not included in {:?}",
                    key.to_string(),
                    other
                        .keys()
                        .map(|k| k.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn check_keys_includes<V>(
        &self,
        other: &BTreeMap<CI, V>,
        min_signers: u16,
    ) -> Result<(), ParticipantsError> {
        if self.len() < min_signers as usize {
            return Err(ParticipantsError::ParticipantsNotMatch(format!(
                "participants length does not match: {:?} vs {:?}",
                self.len(),
                other.len()
            )));
        }
        for (key, _) in other.iter() {
            if !self.contains_key(key) {
                return Err(ParticipantsError::ParticipantsNotMatch(format!(
                    "participants key not included: p:{:?} vs o:{:?}",
                    self.keys()
                        .map(|k| k.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                    other
                        .keys()
                        .map(|k| k.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn extract_identifiers<V>(
        &self,
        other: &BTreeMap<CI, V>,
    ) -> Result<Participants<VII, CI>, ParticipantsError> {
        let o = other
            .iter()
            .map(|(id, _)| match self.get(&id) {
                Some(v) => Ok((id.clone(), v.clone())),
                None => {
                    return Err(ParticipantsError::ParticipantsNotMatch(format!(
                        "participants key not included: p:{:?} vs o:{:?}",
                        self.keys(),
                        other.keys()
                    )));
                }
            })
            .collect::<Result<Vec<(CI, VII)>, ParticipantsError>>()?;

        let participants = Participants::new(o)?;
        participants.check_keys_equal(other)?;
        Ok(participants)
    }
    pub(crate) fn check_keys_equal_except_self<V>(
        &self,
        identifier: &CI,
        other: &BTreeMap<CI, V>,
    ) -> Result<(), ParticipantsError> {
        if self.len() != other.len() + 1 {
            return Err(ParticipantsError::ParticipantsNotMatch(format!(
                "participants length does not match except self: {:?} vs {:?}",
                self.len(),
                other.len()
            )));
        }
        for (key, _) in self.iter() {
            if key == identifier {
                continue;
            }
            if !other.contains_key(key) {
                return Err(ParticipantsError::ParticipantsNotMatch(format!(
                    "participants keys do not match except self: {:?} vs {:?}",
                    self.keys(),
                    other.keys()
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn check_min_signers(&self, min_signers: u16) -> Result<(), ParticipantsError> {
        if self.len() < min_signers as usize {
            return Err(ParticipantsError::MinSigners(format!(
                "total participants is {}, min signers is {}",
                self.len(),
                min_signers
            )));
        }

        if min_signers < (self.len() as u16 + 1) / 2 || min_signers == 0 {
            return Err(ParticipantsError::MinSigners(format!(
                "Min signers is too low, min_signers: {}, validators: {}",
                min_signers,
                self.len()
            )));
        }
        Ok(())
    }
}

impl<VII: ValidatorIdentityIdentity, CI: Identifier> Deref for Participants<VII, CI> {
    type Target = BTreeMap<CI, VII>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
use serde::de::Error as DeError;
use serde::{Deserializer, Serializer};

impl<VII: ValidatorIdentityIdentity, CI: Identifier> Serialize for Participants<VII, CI> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.serialize().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, VII: ValidatorIdentityIdentity, CI: Identifier> Deserialize<'de>
    for Participants<VII, CI>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = <&[u8]>::deserialize(deserializer)?;
        Participants::deserialize(bytes).map_err(DeError::custom)
    }
}
