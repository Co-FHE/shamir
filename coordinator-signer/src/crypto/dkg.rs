use crate::crypto::ValidatorIdentityIdentity;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::oneshot;

use super::{
    CryptoError, CryptoPackageTrait, CryptoType, DKGPackage, DKGRound1Package,
    DKGRound1SecretPackage, DKGRound2Package, DKGRound2Packages, DKGRound2SecretPackage,
    KeyPackage, PublicKeyPackage, Session, SessionId, ValidatorIdentity,
};

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
        round1_packages: BTreeMap<u16, DKGRound1Package>,
    },
    GenPublicKey {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        round1_packages: BTreeMap<u16, DKGRound1Package>,
        round2_packagess: BTreeMap<u16, DKGRound2Packages>,
    },
    Completed {
        public_key: PublicKeyPackage,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum DKGSignerState<VII: ValidatorIdentityIdentity> {
    Part1 {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
        round1_secret_package: DKGRound1SecretPackage,
        // round1_package: DKGRound1Package,
    },
    Part2 {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
        // round1_secret_package: DKGRound1SecretPackage,
        // round1_package: DKGRound1Package,
        round1_packages: BTreeMap<u16, DKGRound1Package>,
        round2_secret_package: DKGRound2SecretPackage,
        // round2_packages: DKGRound2Packages,
    },
    Completed {
        crypto_type: CryptoType,
        min_signers: u16,
        session_id: SessionId<VII>,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGSingleRequest<VII: ValidatorIdentityIdentity> {
    Part1 {
        crypto_type: CryptoType,
        session_id: SessionId<VII>,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
    },
    Part2 {
        crypto_type: CryptoType,
        session_id: SessionId<VII>,
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        round1_packages: BTreeMap<u16, DKGRound1Package>,
    },
    GenPublicKey {
        crypto_type: CryptoType,
        session_id: SessionId<VII>,
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        round1_packages: BTreeMap<u16, DKGRound1Package>,
        round2_packages: BTreeMap<u16, DKGRound2Package>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGSingleResponse<VII: ValidatorIdentityIdentity> {
    Part1 {
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        crypto_package: DKGPackage,
    },
    Part2 {
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        crypto_package: DKGPackage,
    },
    GenPublicKey {
        min_signers: u16,
        max_signers: u16,
        identifier: u16,
        identity: VII,
        crypto_package: DKGPackage,
    },
    Failure(String),
}
impl<VII: ValidatorIdentityIdentity> SingleRequest for DKGSingleRequest<VII> {
    type Identity = VII;
    type Response = DKGSingleResponse<VII>;
    fn get_identity(&self) -> &Self::Identity {
        match self {
            DKGSingleRequest::Part1 { identity, .. } => identity,
            DKGSingleRequest::Part2 { identity, .. } => identity,
            DKGSingleRequest::GenPublicKey { identity, .. } => identity,
        }
    }

    fn get_session_id(&self) -> SessionId<Self::Identity> {
        match self {
            DKGSingleRequest::Part1 { session_id, .. } => session_id.clone(),
            DKGSingleRequest::Part2 { session_id, .. } => session_id.clone(),
            DKGSingleRequest::GenPublicKey { session_id, .. } => session_id.clone(),
        }
    }
}
impl<VII: ValidatorIdentityIdentity> SingleResponse for DKGSingleResponse<VII> {
    type Error = CryptoError;
    type CryptoPackage = DKGPackage;
    fn get_identifier(&self) -> u16 {
        match self {
            DKGSingleResponse::Part1 { identifier, .. } => *identifier,
            DKGSingleResponse::Part2 { identifier, .. } => *identifier,
            DKGSingleResponse::GenPublicKey { identifier, .. } => *identifier,
            DKGSingleResponse::Failure(_) => todo!(),
        }
    }

    fn get_crypto_package(&self) -> Self::CryptoPackage {
        match self {
            DKGSingleResponse::Part1 { crypto_package, .. } => crypto_package.clone(),
            DKGSingleResponse::Part2 { crypto_package, .. } => crypto_package.clone(),
            DKGSingleResponse::GenPublicKey { crypto_package, .. } => crypto_package.clone(),
            DKGSingleResponse::Failure(_) => todo!(),
        }
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
    type Identity: ValidatorIdentityIdentity;
    fn get_session_id(&self) -> SessionId<Self::Identity>;
    fn get_identity(&self) -> &Self::Identity;
}
pub(crate) trait SingleResponse
where
    Self: Sized,
{
    type Error: std::error::Error;
    type CryptoPackage: CryptoPackageTrait;
    fn get_identifier(&self) -> u16;
    fn get_crypto_package(&self) -> Self::CryptoPackage;
}

pub(crate) struct DKGPart1SingleRequest<VII: ValidatorIdentityIdentity> {
    pub(crate) min_signers: u16,
    pub(crate) max_signers: u16,
    pub(crate) identifier: u16,
    pub(crate) identity: VII,
}
impl<VII: ValidatorIdentityIdentity> DKGState<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        session_id: SessionId<VII>,
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
    type Response = DKGSingleResponse<VII>;
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
                    participants: participants.clone(),
                    identifier: *id,
                    identity: identity.clone(),
                    session_id: session_id.clone(),
                    crypto_type: *crypto_type,
                })
                .collect(),
            DKGState::Part2 {
                min_signers,
                participants,
                session_id,
                crypto_type,
                round1_packages,
            } => participants
                .iter()
                .map(|(id, identity)| DKGSingleRequest::Part2 {
                    min_signers: *min_signers,
                    max_signers: participants.len() as u16,
                    identifier: *id,
                    identity: identity.clone(),
                    round1_packages: round1_packages.clone(),
                    crypto_type: *crypto_type,
                    session_id: session_id.clone(),
                })
                .collect(),
            DKGState::GenPublicKey {
                min_signers,
                participants,
                session_id,
                crypto_type,
                round1_packages,
                round2_packagess,
            } => participants
                .iter()
                .map(|(id, identity)| {
                    let mut round2_packages = BTreeMap::new();
                    for (oid, round2_package) in round2_packagess.iter() {
                        if oid == id {
                            continue;
                        }
                        let package = match round2_package {
                            DKGRound2Packages::Ed25519(package) => {
                                let tid = frost_ed25519::Identifier::try_from(*id).unwrap();
                                let package = package.get(&tid).unwrap();
                                DKGRound2Package::Ed25519(package.clone())
                            }
                            DKGRound2Packages::Secp256k1(package) => {
                                let tid = frost_secp256k1::Identifier::try_from(*id).unwrap();
                                let package = package.get(&tid).unwrap();
                                DKGRound2Package::Secp256k1(package.clone())
                            }
                            DKGRound2Packages::Secp256k1Tr(package) => {
                                let tid = frost_secp256k1_tr::Identifier::try_from(*id).unwrap();
                                let package = package.get(&tid).unwrap();
                                DKGRound2Package::Secp256k1Tr(package.clone())
                            }
                        };
                        round2_packages.insert(*oid, package);
                    }
                    DKGSingleRequest::GenPublicKey {
                        min_signers: *min_signers,
                        max_signers: participants.len() as u16,
                        identifier: *id,
                        identity: identity.clone(),
                        round1_packages: round1_packages.clone(),
                        round2_packages: round2_packages.clone(),
                        crypto_type: *crypto_type,
                        session_id: session_id.clone(),
                    }
                })
                .collect(),
            DKGState::Completed { .. } => vec![],
        }
    }
    fn completed(&self) -> bool {
        matches!(self, DKGState::Completed { .. })
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
                    match package {
                        DKGPackage::Round1(package) => {
                            packages.insert(*id, package);
                        }
                        _ => {
                            return Err(CryptoError::InvalidResponse(format!(
                                "need round 1 package but got round 2 package"
                            )));
                        }
                    }
                }
                Ok(DKGState::Part2 {
                    min_signers: *min_signers,
                    session_id: session_id.clone(),
                    participants: participants.clone(),
                    round1_packages: packages,
                    crypto_type: *crypto_type,
                })
            }
            DKGState::Part2 {
                crypto_type,
                min_signers,
                session_id,
                participants,
                round1_packages,
            } => {
                let mut packagess = BTreeMap::new();
                for (id, _) in participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(CryptoError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id
                            )))?;
                    // TODO: need more checks
                    let package = response.get_crypto_package();
                    if !package.is_crypto_type(*crypto_type) {
                        return Err(CryptoError::InvalidResponse(format!(
                            "crypto type mismatch: expected {:?}, got {:?}",
                            crypto_type,
                            package.get_crypto_type()
                        )));
                    }
                    match package {
                        DKGPackage::Round2(packages) => {
                            packagess.insert(*id, packages);
                        }
                        _ => {
                            return Err(CryptoError::InvalidResponse(format!(
                                "need round 1 package but got round 2 package"
                            )));
                        }
                    }
                }
                Ok(DKGState::GenPublicKey {
                    crypto_type: *crypto_type,
                    min_signers: *min_signers,
                    session_id: session_id.clone(),
                    participants: participants.clone(),
                    round1_packages: round1_packages.clone(),
                    round2_packagess: packagess,
                })
            }
            DKGState::GenPublicKey {
                crypto_type,
                min_signers,
                session_id,
                participants,
                round1_packages,
                round2_packagess,
            } => {
                let mut public_key = None;
                for (id, _) in participants.iter() {
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
                    match package {
                        DKGPackage::PublicKey(package) => match public_key {
                            None => public_key = Some(package.clone()),
                            Some(ref pk) => {
                                if &package != pk {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "public key packages do not match {:?}, {:?}",
                                        pk, package
                                    )));
                                }
                            }
                        },
                        _ => {
                            return Err(CryptoError::InvalidResponse(format!(
                                "need public key package but got round 2 package"
                            )));
                        }
                    }
                    // TODO: check public key package is the same
                }
                if let Some(public_key) = public_key {
                    tracing::info!("DKG state completed, public key: {:?}", public_key);
                    Ok(DKGState::Completed { public_key })
                } else {
                    Err(CryptoError::InvalidResponse(
                        "public key package not found".to_string(),
                    ))
                }
            }
            DKGState::Completed { .. } => Ok(self.clone()),
        }
    }
}
