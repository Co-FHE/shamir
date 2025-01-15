use crate::crypto::ValidatorIdentityIdentity;
use frost_core::keys::KeyPackage;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::oneshot;

use super::{CryptoError, CryptoPackage, CryptoType, Session, SessionId, ValidatorIdentity};

#[derive(Debug, Clone)]
pub(crate) enum DKGState<VII: ValidatorIdentityIdentity> {
    Part1 {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
    },
    Part2 {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        round1_packages: BTreeMap<u16, CryptoPackage>,
    },
    Part3 {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        packages: BTreeMap<u16, CryptoPackage>,
    },
    Completed,
}
pub(crate) enum DKGSingleRequest<VII: ValidatorIdentityIdentity> {
    Part1 {
        crypto_type: CryptoType,
        session_id: SessionId<VII>,
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
    },
    Part2,
    Part3,
}
pub(crate) enum DKSingleResponse<VII: ValidatorIdentityIdentity> {
    Part1 {
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        crypto_package: CryptoPackage,
    },
    Part2,
    Part3,
}
impl<VII: ValidatorIdentityIdentity> SingleRequest for DKGSingleRequest<VII> {
    type Response = DKSingleResponse<VII>;
    fn response_channel(self) -> oneshot::Sender<DKSingleResponse<VII>> {
        todo!()
    }
}
impl<VII: ValidatorIdentityIdentity> SingleResponse for DKSingleResponse<VII> {
    type Error = CryptoError;
    fn get_identifier(&self) -> u16 {
        match self {
            DKSingleResponse::Part1 { identifier, .. } => *identifier,
            DKSingleResponse::Part2 => 0,
            DKSingleResponse::Part3 => 0,
        }
    }

    fn get_crypto_package(&self) -> CryptoPackage {
        todo!()
    }
}
pub(crate) trait State<VII: ValidatorIdentityIdentity> {
    type SingleRequest: SingleRequest;
    type NextState: State<VII>;
    type Error: std::error::Error;
    type Response: SingleResponse;
    fn split_into_single_requests(&self) -> Vec<Self::SingleRequest>;
    fn handle_response(
        &self,
        response: BTreeMap<u16, Self::Response>,
    ) -> Result<Self::NextState, Self::Error>;
    fn completed(&self) -> bool;
}
pub(crate) trait SingleRequest {
    type Response;
    fn response_channel(self) -> oneshot::Sender<Self::Response>;
}
pub(crate) trait SingleResponse
where
    Self: Sized,
{
    type Error: std::error::Error;
    fn get_identifier(&self) -> u16;
    fn get_crypto_package(&self) -> CryptoPackage;
}

pub(crate) struct DKGPart1SingleRequest<VII: ValidatorIdentityIdentity> {
    pub(crate) min_signers: u16,
    pub(crate) max_signers: u16,
    pub(crate) identifier: u16,
    pub(crate) identity: VII,
}
impl<VII: ValidatorIdentityIdentity> DKGState<VII> {
    pub(crate) fn new(
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        session_id: SessionId<VII>,
        crypto_type: CryptoType,
    ) -> Self {
        Self::Part1 {
            min_signers,
            participants,
            session_id,
            crypto_type,
        }
    }
}
impl<VII: ValidatorIdentityIdentity> State<VII> for DKGState<VII> {
    type SingleRequest = DKGSingleRequest<VII>;
    type NextState = DKGState<VII>;
    type Error = CryptoError;
    type Response = DKSingleResponse<VII>;
    fn split_into_single_requests(&self) -> Vec<DKGSingleRequest<VII>> {
        match self {
            DKGState::Part1 {
                min_signers,
                participants,
                session_id,
                crypto_type,
            } => participants
                .iter()
                .map(|(id, identity)| DKGSingleRequest::Part1 {
                    min_signers: *min_signers,
                    max_signers: participants.len() as u16,
                    identifier: *id,
                    identity: identity.clone(),
                    session_id: session_id.clone(),
                    crypto_type: *crypto_type,
                })
                .collect(),
            _ => vec![],
        }
    }
    fn completed(&self) -> bool {
        matches!(self, DKGState::Completed)
    }

    fn handle_response(
        &self,
        response: BTreeMap<u16, Self::Response>,
    ) -> Result<Self::NextState, Self::Error> {
        match self {
            DKGState::Part1 {
                min_signers,
                participants,
                session_id,
                crypto_type,
            } => {
                let mut packages = BTreeMap::new();
                for (id, _) in participants.iter() {
                    // find in response
                    let response =
                        response
                            .get(id)
                            .ok_or(CryptoError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id
                            )))?;
                    let package = response.get_crypto_package();
                    if !package.is_crypto_type(*crypto_type) {
                        return Err(CryptoError::InvalidResponse(format!(
                            "crypto type mismatch: expected {:?}, got {:?}",
                            crypto_type,
                            package.get_crypto_type()
                        )));
                    }
                    packages.insert(*id, package);
                }
                Ok(DKGState::Part2 {
                    min_signers: *min_signers,
                    session_id: session_id.clone(),
                    participants: participants.clone(),
                    packages,
                    crypto_type: *crypto_type,
                })
            }
            _ => todo!(),
        }
    }
}
