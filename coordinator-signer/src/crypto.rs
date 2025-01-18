mod cipher;
mod pkid;
mod validator_identity;

pub(crate) use cipher::*;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

pub(crate) use pkid::*;
pub(crate) use validator_identity::*;

//todo pk.hash()->pkid

pub(crate) struct Validator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}
