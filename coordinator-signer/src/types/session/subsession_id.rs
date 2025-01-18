use crate::crypto::{CryptoType, PkId, ValidatorIdentityIdentity};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, marker::PhantomData};
use uuid::Uuid;

use super::SessionId;
use crate::types::error::SessionIdError;

// SubSessionId format:
// 1 byte: crypto type
// 2 byte: min signers
// 2 byte: max signers (length of participants)
// 8 bytes: hash of participants (ordered by VI::Identity) (leading 8 bytes)
// 8 bytes: hash of TSS::Identity of participants (ordered by VI::Identity) (leading 8 bytes)
// 32 bytes: signing session pkid
// 32 bytes: sign message hash
// 16 bytes: uuid of subsession
// The SessionId cannot be used in any consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct SubsessionId<VI: ValidatorIdentityIdentity>([u8; 101], PhantomData<VI>);

impl<VII: ValidatorIdentityIdentity> Serialize for SubsessionId<VII> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, VII: ValidatorIdentityIdentity> Deserialize<'de> for SubsessionId<VII> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SubsessionId::from_string(&s).map_err(serde::de::Error::custom)
    }
}

impl<VII: ValidatorIdentityIdentity> SubsessionId<VII> {
    pub fn new(
        crypto_type: CryptoType,
        min_signers: u16,
        participants: &BTreeMap<u16, VII>,
        sign_message: Vec<u8>,
        session_id: &SessionId<VII>,
        pkid: PkId,
    ) -> Result<Self, SessionIdError> {
        let mut bytes = [0u8; 85];

        // 1 byte crypto type
        bytes[0] = crypto_type as u8;

        // 2 bytes min signers
        bytes[1..3].copy_from_slice(&min_signers.to_be_bytes());

        // 2 bytes max signers (participants length)
        let max_signers = participants.len() as u16;
        bytes[3..5].copy_from_slice(&max_signers.to_be_bytes());
        if max_signers < min_signers {
            return Err(SessionIdError::InvalidMinSigners(min_signers, max_signers));
        }

        // Sort participants by identity first, then by key
        let mut sorted_entries: Vec<_> = participants.iter().collect();
        sorted_entries.sort_by(|(key1, id1), (key2, id2)| id1.cmp(&id2).then(key1.cmp(key2)));

        // Calculate hash of sorted entries
        let mut hasher = Sha256::new();
        for (_, identity) in &sorted_entries {
            hasher.update(&identity.to_bytes());
        }
        let hash = hasher.finalize();
        bytes[5..13].copy_from_slice(&hash[0..8]);

        let mut hasher = Sha256::new();
        for (key, _) in &sorted_entries {
            hasher.update(&key.to_be_bytes());
        }
        let hash = hasher.finalize();
        bytes[13..21].copy_from_slice(&hash[0..8]);

        bytes[21..53].copy_from_slice(&pkid[..]);

        // Calculate sign message hash
        let mut hasher = Sha256::new();
        hasher.update(sign_message);
        let hash = hasher.finalize();
        bytes[53..85].copy_from_slice(&hash[..]);

        // Generate random UUID for subsession
        let subsession_uuid = Uuid::new_v4();
        bytes[86..101].copy_from_slice(subsession_uuid.as_bytes());

        Ok(SubsessionId(bytes, PhantomData))
    }

    pub fn to_string(&self) -> String {
        let crypto_type = format!("{:02x}", self.0[0]);
        let min_signers = format!("{:04x}", u16::from_be_bytes([self.0[1], self.0[2]]));
        let max_signers = format!("{:04x}", u16::from_be_bytes([self.0[3], self.0[4]]));
        let hash1 = hex::encode(&self.0[5..13]);
        let hash2 = hex::encode(&self.0[13..21]);
        let pkid = hex::encode(&self.0[21..53]);
        let message_hash = hex::encode(&self.0[53..69]);
        let uuid = hex::encode(&self.0[69..85]);
        format!(
            "subsession-{}-{}-{}-{}-{}-{}-{}-{}",
            crypto_type, min_signers, max_signers, hash1, hash2, pkid, message_hash, uuid
        )
    }

    pub fn from_string(s: &str) -> Result<Self, SessionIdError> {
        if !s.starts_with("subsession-") {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} must start with 'subsession-'",
                s
            )));
        }

        let parts: Vec<&str> = s[11..].split('-').collect();
        if parts.len() != 8 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} must have 8 parts",
                s
            )));
        }

        let mut bytes = [0u8; 85];

        // Parse crypto type (1 byte)
        let crypto_type = u8::from_str_radix(parts[0], 16).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid crypto type: {}",
                s, e
            ))
        })?;
        bytes[0] = crypto_type;

        // Parse min signers (2 bytes)
        let min_signers = u16::from_str_radix(parts[1], 16).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid min signers: {}",
                s, e
            ))
        })?;
        bytes[1..3].copy_from_slice(&min_signers.to_be_bytes());

        // Parse max signers (2 bytes)
        let max_signers = u16::from_str_radix(parts[2], 16).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid max signers: {}",
                s, e
            ))
        })?;
        bytes[3..5].copy_from_slice(&max_signers.to_be_bytes());
        if max_signers < min_signers {
            return Err(SessionIdError::InvalidMinSigners(min_signers, max_signers));
        }

        // Parse validators_hash (8 bytes)
        let validators_hash = hex::decode(parts[3]).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid validators_hash: {}",
                s, e
            ))
        })?;
        if validators_hash.len() != 8 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid validators_hash length: {}",
                s,
                validators_hash.len(),
            )));
        }
        bytes[5..13].copy_from_slice(&validators_hash);

        // Parse identifiers_hash (8 bytes)
        let identifiers_hash = hex::decode(parts[4]).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid identifiers_hash: {}",
                s, e
            ))
        })?;
        if identifiers_hash.len() != 8 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid identifiers_hash length: {}",
                s,
                identifiers_hash.len(),
            )));
        }
        bytes[13..21].copy_from_slice(&identifiers_hash);

        // Parse pkid (32 bytes)
        let pkid = hex::decode(parts[5]).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid pkid: {}",
                s, e
            ))
        })?;
        if pkid.len() != 32 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid pkid length: {}",
                s,
                pkid.len(),
            )));
        }
        bytes[21..53].copy_from_slice(&pkid);

        // Parse message hash (16 bytes)
        let message_hash = hex::decode(parts[6]).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid message hash: {}",
                s, e
            ))
        })?;
        if message_hash.len() != 32 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid message hash length: {}",
                s,
                message_hash.len(),
            )));
        }
        bytes[86..101].copy_from_slice(&message_hash);

        // Parse UUID (16 bytes)
        let uuid = hex::decode(parts[7]).map_err(|e| {
            SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid uuid: {}",
                s, e
            ))
        })?;
        if uuid.len() != 16 {
            return Err(SessionIdError::InvalidSubSessionIdFormat(format!(
                "subsession id {} invalid uuid length: {}",
                s,
                uuid.len(),
            )));
        }
        bytes[69..85].copy_from_slice(&uuid);

        Ok(SubsessionId(bytes, PhantomData))
    }
}
