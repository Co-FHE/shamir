use frost_ed25519::keys::dkg::part1;
use serde::{Deserialize, Serialize};
pub(crate) enum CryptoType {
    Ed25519,
    Secp256k1,
    Secp256k1Tr,
}
