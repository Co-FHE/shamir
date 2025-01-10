mod traits;
pub(crate) use crate::crypto::traits::*;
use frost_ed25519::keys::dkg::part1;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
pub(crate) enum SignState {
    Round1,
    PreRound2,
    Round2,
    PreRound3,
    Round3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum TSSState {
    DKG(DKGState),
    Sign(SignState),
    ReadyToSign,
}

pub(crate) struct Session<VI: ValidatorIdentity> {
    pub(crate) id: uuid::Uuid,
    pub(crate) state: TSSState,
    pub(crate) participants: HashMap<u16, VI::Identity>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidValidator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
