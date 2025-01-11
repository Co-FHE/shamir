mod dkg;
mod session;
mod traits;
pub(crate) use crate::crypto::traits::*;
pub(crate) use dkg::*;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
pub(crate) use session::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidValidator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
