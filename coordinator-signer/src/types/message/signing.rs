use std::any::Any;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        Cipher, CryptoType, Ed25519Sha512, PkId, Secp256K1Sha256, Secp256K1Sha256TR,
        ValidatorIdentityIdentity,
    },
    types::{error::SessionError, Participants, SubsessionId},
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
fn try_cast_response<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&SigningResponse<VII, T>> {
    r.downcast_ref::<SigningResponse<VII, T>>()
}
fn try_cast_request<VII: ValidatorIdentityIdentity, C: Cipher, T: Cipher>(
    r: &dyn Any,
) -> Option<&SigningRequest<VII, T>> {
    r.downcast_ref::<SigningRequest<VII, T>>()
}

impl<VII: ValidatorIdentityIdentity> SigningResponseWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: SigningResponse<VII, C>) -> Result<Self, SessionError<C>> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(SigningResponseWrap::Ed25519(
                try_cast_response::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(SigningResponseWrap::Secp256k1(
                try_cast_response::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(SigningResponseWrap::Secp256k1Tr(
                try_cast_response::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing response to SigningResponseWrap".to_string(),
                    ))?
                    .clone(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> SigningRequestWrap<VII> {
    pub(crate) fn from<C: Cipher>(r: SigningRequest<VII, C>) -> Result<Self, SessionError<C>> {
        match C::crypto_type() {
            CryptoType::Ed25519 => Ok(SigningRequestWrap::Ed25519(
                try_cast_request::<VII, C, Ed25519Sha512>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1 => Ok(SigningRequestWrap::Secp256k1(
                try_cast_request::<VII, C, Secp256K1Sha256>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
            CryptoType::Secp256k1Tr => Ok(SigningRequestWrap::Secp256k1Tr(
                try_cast_request::<VII, C, Secp256K1Sha256TR>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing request to SigningRequestWrap".to_string(),
                    ))?
                    .clone(),
            )),
        }
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningRequest<VII, C> {
    pub(crate) fn from(
        r: SigningRequestWrap<VII>,
    ) -> Result<SigningRequest<VII, C>, SessionError<C>> {
        match r {
            SigningRequestWrap::Ed25519(r) => Ok(try_cast_request::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Secp256k1(r) => Ok(try_cast_request::<VII, Secp256K1Sha256, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming Signing requestWrap to SigningRequest".to_string(),
                ))?
                .clone()),
            SigningRequestWrap::Secp256k1Tr(r) => {
                Ok(try_cast_request::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing requestWrap to SigningRequest".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningResponse<VII, C> {
    pub(crate) fn from(
        r: SigningResponseWrap<VII>,
    ) -> Result<SigningResponse<VII, C>, SessionError<C>> {
        match r {
            SigningResponseWrap::Ed25519(r) => Ok(try_cast_response::<VII, Ed25519Sha512, C>(&r)
                .ok_or(SessionError::<C>::TransformWrapingMessageError(
                    "Error transforming Signing responseWrap to SigningResponse".to_string(),
                ))?
                .clone()),
            SigningResponseWrap::Secp256k1(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing responseWrap to SigningResponse".to_string(),
                    ))?
                    .clone())
            }
            SigningResponseWrap::Secp256k1Tr(r) => {
                Ok(try_cast_response::<VII, Secp256K1Sha256TR, C>(&r)
                    .ok_or(SessionError::<C>::TransformWrapingMessageError(
                        "Error transforming Signing responseWrap to SigningResponse".to_string(),
                    ))?
                    .clone())
            }
        }
    }
}
