use std::any::Any;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, CryptoType, Ed25519Sha512, Secp256K1Sha256, Secp256K1Sha256TR,
        ValidatorIdentityIdentity,
    },
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
        round1_package_map: C::DKGRound1PackageMap,
    },
    GenPublicKey {
        round1_package_map: C::DKGRound1PackageMap,
        round2_package_map: C::DKGRound2PackageMap,
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
fn try_cast_response<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&DKGResponse<VII, T>> {
    r.downcast_ref::<DKGResponse<VII, T>>()
}
fn try_cast_request<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&DKGRequest<VII, T>> {
    r.downcast_ref::<DKGRequest<VII, T>>()
}
impl<VII: ValidatorIdentityIdentity> DKGResponseWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: DKGResponse<VII, C>) -> Option<Self> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Some(DKGResponseWrap::Ed25519(
                try_cast_response::<VII, C, Ed25519Sha512>(&r)
                    .unwrap()
                    .clone(),
            )),
            CryptoType::Secp256k1 => Some(DKGResponseWrap::Secp256k1(
                try_cast_response::<VII, C, Secp256K1Sha256>(&r)
                    .unwrap()
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Some(DKGResponseWrap::Secp256k1Tr(
                try_cast_response::<VII, C, Secp256K1Sha256TR>(&r)
                    .unwrap()
                    .clone(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> DKGRequestWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: DKGRequest<VII, C>) -> Option<Self> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Some(DKGRequestWrap::Ed25519(
                try_cast_request::<VII, C, Ed25519Sha512>(&r)
                    .unwrap()
                    .clone(),
            )),
            CryptoType::Secp256k1 => Some(DKGRequestWrap::Secp256k1(
                try_cast_request::<VII, C, Secp256K1Sha256>(&r)
                    .unwrap()
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Some(DKGRequestWrap::Secp256k1Tr(
                try_cast_request::<VII, C, Secp256K1Sha256TR>(&r)
                    .unwrap()
                    .clone(),
            )),
        }
    }
}
