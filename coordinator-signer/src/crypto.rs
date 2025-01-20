mod cipher;
mod pkid;
mod validator_identity;

pub(crate) use cipher::*;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

pub(crate) use pkid::*;
use strum::{Display, EnumCount, EnumIter, EnumString};
pub(crate) use validator_identity::*;

//todo pk.hash()->pkid

#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    EnumString,
    Display,
    EnumCount,
    EnumIter,
    Eq,
    Hash,
)]
pub(crate) enum CryptoType {
    #[strum(serialize = "ed25519")]
    Ed25519,
    #[strum(serialize = "secp256k1")]
    Secp256k1,
    #[strum(serialize = "secp256k1-tr")]
    Secp256k1Tr,
}
