mod cipher;
mod pkid;
mod validator_identity;

pub(crate) use cipher::*;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

pub(crate) use pkid::*;
pub(crate) use validator_identity::*;

//todo pk.hash()->pkid

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}
