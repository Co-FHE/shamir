use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, Ed25519Sha512, PkId, Secp256K1Sha256, Secp256K1Sha256TR, ValidatorIdentityIdentity,
    },
    types::{Participants, SubsessionId},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SigningBaseMessage<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) participants: Participants<VII, C>,
    pub(crate) pkid: PkId,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) identifier: C::Identifier,
    pub(crate) identity: VII,
    pub(crate) public_key: C::PublicKeyPackage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SigningRequest<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: SigningBaseMessage<VII, C>,
    pub(crate) stage: SigningRequestStage<C>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningRequestStage<C: Cipher> {
    Round1,
    Round2 { signing_package: C::SigningPackage },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningRequestWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(SigningRequest<VII, Ed25519Sha512>),
    Secp256k1(SigningRequest<VII, Secp256K1Sha256>),
    Secp256k1Tr(SigningRequest<VII, Secp256K1Sha256TR>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SigningResponse<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) base_info: SigningBaseMessage<VII, C>,
    pub(crate) stage: SigningResponseStage<C>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningResponseStage<C: Cipher> {
    Round1 { commitments: C::SigningCommitments },
    Round2 { signature_share: C::SignatureShare },
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningResponseWrap<VII: ValidatorIdentityIdentity> {
    Ed25519(SigningResponse<VII, Ed25519Sha512>),
    Secp256k1(SigningResponse<VII, Secp256K1Sha256>),
    Secp256k1Tr(SigningResponse<VII, Secp256K1Sha256TR>),
}
