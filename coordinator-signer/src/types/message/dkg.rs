use std::collections::BTreeMap;

use frost_ed25519::Ed25519Sha512;
use frost_secp256k1::Secp256K1Sha256;
use frost_secp256k1_tr::Secp256K1Sha256TR;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{Cipher, ValidatorIdentityIdentity},
    types::{Participants, SessionId},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGBaseMessage<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) session_id: SessionId<VII>,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) identifier: C::Identifier,
    pub(crate) identity: VII,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGRequest<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: DKGBaseMessage<VII, C>,
    pub(crate) stage: DKGRequestStage<C>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestStage<C: Cipher> {
    Part1,
    Part2 {
        round1_package: C::DKGRound2PackageMap,
    },
    GenPublicKey {
        round1_packages: C::DKGRound1PackageMap,
        round2_packages: C::DKGRound2PackageMap,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGRequestWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(DKGRequest<VII, Ed25519Sha512>),
    Secp256k1(DKGRequest<VII, Secp256K1Sha256>),
    Secp256k1Tr(DKGRequest<VII, Secp256K1Sha256TR>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGResponse<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: DKGBaseMessage<VII, C>,
    pub(crate) stage: DKGResponseStage<C>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGResponseStage<C: Cipher> {
    Part1 {
        round1_package: C::DKGRound1Package,
    },
    Part2 {
        round2_package_map: C::DKGRound2PackageMap,
    },
    GenPublicKey {
        public_key_package: C::PublicKeyPackage,
    },
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGResponseWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(DKGResponse<VII, Ed25519Sha512>),
    Secp256k1(DKGResponse<VII, Secp256K1Sha256>),
    Secp256k1Tr(DKGResponse<VII, Secp256K1Sha256TR>),
}
