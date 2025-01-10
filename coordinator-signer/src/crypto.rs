mod traits;
pub(crate) use crate::crypto::traits::*;
use frost_ed25519::keys::dkg::part1;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum DKGState {
    Part1,
    PrePart2,
    Part2,
    PrePart3,
    Part3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum SigningState {
    Round1,
    PreRound2,
    Round2,
}

#[derive(Debug, Clone)]
pub(crate) enum TSSState {
    DKG(DKGState),
    Signing(HashMap<Uuid, SigningState>),
}
// SessionId format:
// 1 byte: crypto type
// 2 byte: min signers
// 2 byte: max signers (length of participants)
// 8 bytes: hash of participants (ordered by VI::Identity) (leading 8 bytes)
// 8 bytes: hash of TSS::Identity of participants (ordered by VI::Identity) (leading 8 bytes)
// 16 bytes: uuid of session
// the SessionId cannot used in any consensus
pub(crate) struct SessionId([u8; 37]); // 1 + 2 + 2 + 8 + 8 + 16 = 37 bytes

impl SessionId {
    pub fn new(
        crypto_type: CryptoType,
        min_signers: u16,
        participants: &BTreeMap<u16, impl ValidatorIdentityIdentity>,
    ) -> Result<Self, SessionError> {
        let mut bytes = [0u8; 37];

        // 1 byte crypto type
        bytes[0] = crypto_type as u8;

        // 2 bytes min signers
        bytes[1..3].copy_from_slice(&min_signers.to_be_bytes());

        // 2 bytes max signers (participants length)
        let max_signers = participants.len() as u16;
        bytes[3..5].copy_from_slice(&max_signers.to_be_bytes());
        if max_signers < min_signers {
            return Err(SessionError::InvalidMinSigners(min_signers, max_signers));
        }
        // Sort participants by identity first, then by key
        let mut sorted_entries: Vec<_> = participants.iter().collect();
        sorted_entries.sort_by(|(key1, id1), (key2, id2)| {
            id1.to_bytes().cmp(&id2.to_bytes()).then(key1.cmp(key2))
        });

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

        // Generate random UUID for session
        let session_uuid = Uuid::new_v4();
        bytes[21..37].copy_from_slice(session_uuid.as_bytes());

        Ok(SessionId(bytes))
    }

    pub fn to_string(&self) -> String {
        let crypto_type = format!("{:02x}", self.0[0]);
        let min_signers = format!("{:04x}", u16::from_be_bytes([self.0[1], self.0[2]]));
        let max_signers = format!("{:04x}", u16::from_be_bytes([self.0[3], self.0[4]]));
        let hash1 = hex::encode(&self.0[5..13]);
        let hash2 = hex::encode(&self.0[13..21]);
        let uuid = hex::encode(&self.0[21..37]);
        format!(
            "session-{}-{}-{}-{}-{}-{}",
            crypto_type, min_signers, max_signers, hash1, hash2, uuid
        )
    }

    pub fn from_string(s: &str) -> Result<Self, SessionError> {
        if !s.starts_with("session-") {
            return Err(SessionError::InvalidSessionIdFormat(
                s.to_string(),
                "session id must start with 'session-'".to_string(),
            ));
        }
        let parts: Vec<&str> = s[8..].split('-').collect();
        if parts.len() != 6 {
            return Err(SessionError::InvalidSessionIdFormat(
                s.to_string(),
                "session id must have 6 parts".to_string(),
            ));
        }
        let mut bytes = [0u8; 37];

        // Parse crypto type (1 byte)
        let crypto_type = u8::from_str_radix(parts[0], 16)
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        bytes[0] = crypto_type;

        // Parse min signers (2 bytes)
        let min_signers = u16::from_str_radix(parts[1], 16)
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        bytes[1..3].copy_from_slice(&min_signers.to_be_bytes());

        // Parse max signers (2 bytes)
        let max_signers = u16::from_str_radix(parts[2], 16)
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        bytes[3..5].copy_from_slice(&max_signers.to_be_bytes());
        if max_signers < min_signers {
            return Err(SessionError::InvalidMinSigners(min_signers, max_signers));
        }
        // Parse hash1 (8 bytes)
        let hash1 = hex::decode(parts[3])
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        if hash1.len() != 8 {
            return Err(SessionError::InvalidSessionIdFormat(
                s.to_string(),
                "Invalid hash1 length".to_string(),
            ));
        }
        bytes[5..13].copy_from_slice(&hash1);

        // Parse hash2 (8 bytes)
        let hash2 = hex::decode(parts[4])
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        if hash2.len() != 8 {
            return Err(SessionError::InvalidSessionIdFormat(
                s.to_string(),
                "Invalid hash2 length".to_string(),
            ));
        }
        bytes[13..21].copy_from_slice(&hash2);

        // Parse UUID (16 bytes)
        let uuid = hex::decode(parts[5])
            .map_err(|e| SessionError::InvalidSessionIdFormat(s.to_string(), e.to_string()))?;
        if uuid.len() != 16 {
            return Err(SessionError::InvalidSessionIdFormat(
                s.to_string(),
                "Invalid UUID length".to_string(),
            ));
        }
        bytes[21..37].copy_from_slice(&uuid);

        Ok(SessionId(bytes))
    }
}

pub(crate) struct Session<VI: ValidatorIdentity> {
    session_id: SessionId,
    pub(crate) crypto_type: CryptoType,
    pub(crate) min_signers: u16,
    pub(crate) state: TSSState,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Invalid session id format: {0}, {1}")]
    InvalidSessionIdFormat(String, String),
}

impl<VI: ValidatorIdentity> Session<VI> {
    pub fn new(
        crypto_type: CryptoType,
        participants: Vec<(u16, VI::Identity)>,
        min_signers: u16,
    ) -> Result<Self, SessionError> {
        let mut participants_map = BTreeMap::new();
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
                .any(|identity| identity == identity)
            {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant identity: {}",
                    identity.to_fmt_string()
                )));
            }
            participants_map.insert(id, identity);
        }
        if participants_map.len() < min_signers as usize {
            return Err(SessionError::InvalidMinSigners(
                min_signers,
                participants_map.len() as u16,
            ));
        }
        if participants_map.len() > 255 {
            return Err(SessionError::InvalidParticipants(format!(
                "max signers is 255, got {}",
                participants_map.len()
            )));
        }
        let session_id = SessionId::new(crypto_type, min_signers, &participants_map)?;

        Ok(Session {
            session_id,
            crypto_type,
            min_signers,
            state: TSSState::DKG(DKGState::Part1),
            participants: participants_map,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidValidator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::crypto::traits::Ed25519Identity;
//     use ed25519_dalek::SigningKey;
//     use proptest::prelude::*;
//     use rand_core::OsRng;
//     use std::collections::BTreeMap;

//     fn generate_random_ed25519_id() -> Ed25519Id {
//         let signing_key = SigningKey::generate(&mut OsRng);
//         signing_key.verifying_key().to_identity()
//     }

//     prop_compose! {
//         fn arb_participants()(n in 3..10usize) -> BTreeMap<u16, Ed25519Id> {
//             let mut map = BTreeMap::new();
//             for i in 0..n {
//                 map.insert(i as u16, generate_random_ed25519_id());
//             }
//             map
//         }
//     }

//     proptest! {
//         #[test]
//         fn test_session_id_creation(
//             crypto_type in prop_oneof![
//                 Just(CryptoType::Ed25519),
//                 Just(CryptoType::Secp256k1),
//                 Just(CryptoType::Secp256k1Tr)
//             ],
//             participants in arb_participants(),
//             min_signers in 2u16..10u16
//         ) {
//             let session_id = SessionId::new(crypto_type, min_signers, &participants);

//             // Verify first byte is crypto type
//             prop_assert_eq!(session_id.0[0], crypto_type as u8);

//             // Verify min_signers bytes
//             let stored_min_signers = u16::from_be_bytes([session_id.0[1], session_id.0[2]]);
//             prop_assert_eq!(stored_min_signers, min_signers);

//             // Verify max_signers (participants length) bytes
//             let stored_max_signers = u16::from_be_bytes([session_id.0[3], session_id.0[4]]);
//             prop_assert_eq!(stored_max_signers, participants.len() as u16);

//             // Verify total length
//             prop_assert_eq!(session_id.0.len(), 37);
//         }

//         #[test]
//         fn test_session_creation_with_valid_participants(
//             participants_count in 3..10usize
//         ) {
//             let participants: Vec<(u16, Ed25519Id)> = (0..participants_count)
//                 .map(|i| (i as u16, generate_random_ed25519_id()))
//                 .collect();

//             let session = Session::<Ed25519Identity>::new(CryptoType::Ed25519, participants.clone());

//             // Verify participants are stored correctly
//             prop_assert_eq!(session.participants.len(), participants_count);

//             // Verify min_signers calculation
//             prop_assert_eq!(session.min_signers, (participants_count as u16 + 1) / 2);

//             // Verify initial state
//             match session.state {
//                 TSSState::DKG(DKGState::Part1) => prop_assert!(true),
//                 _ => prop_assert!(false, "Initial state should be DKG Part1"),
//             }
//         }
//     }
// }
