use crate::crypto::ValidatorIdentityIdentity;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::oneshot;

use super::{
    subsession::SubSessionId, CryptoError, CryptoPackageTrait, CryptoType, DKGPackage,
    DKGRound1Package, DKGRound1SecretPackage, DKGRound2Package, DKGRound2Packages,
    DKGRound2SecretPackage, KeyPackage, PublicKeyPackage, Session, SessionId, Signature,
    SignatureShare, SigningCommitments, SigningNonces, SigningPackage, State, ValidatorIdentity,
};

#[derive(Debug, Clone)]
pub(crate) enum SigningState<VII: ValidatorIdentityIdentity> {
    Round1 {
        crypto_type: CryptoType,
        message: Vec<u8>,
        min_signers: u16,
        pkid: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        pk: PublicKeyPackage,
        participants: BTreeMap<u16, VII>,
    },
    Round2 {
        crypto_type: CryptoType,
        message: Vec<u8>,
        pkid: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        pk: PublicKeyPackage,
        signing_commitments: BTreeMap<u16, SigningCommitments>,
    },
    Completed {
        signature: Signature,
        pk: PublicKeyPackage,
        subsession_id: SubSessionId<VII>,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum SignerSigningState<VII: ValidatorIdentityIdentity> {
    Round1 {
        pkid: Vec<u8>,
        message: Vec<u8>,
        crypto_type: CryptoType,
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
        signing_commitments: SigningCommitments,
        nonces: SigningNonces,
    },
    Round2 {
        pkid: Vec<u8>,
        message: Vec<u8>,
        crypto_type: CryptoType,
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        identifier: u16,
        identity: VII,
        signing_package: SigningPackage,
        nonces: SigningNonces,
        signature_share: SignatureShare,
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
        signature: Signature,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningSingleRequest<VII: ValidatorIdentityIdentity> {
    Round1 {
        pkid: Vec<u8>,
        message: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        identity: VII,
    },
    Round2 {
        pkid: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        signing_package: SigningPackage,
        identity: VII,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SigningSingleResponse<VII: ValidatorIdentityIdentity> {
    Round1 {
        pkid: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        commitments: SigningCommitments,
    },
    Round2 {
        pkid: Vec<u8>,
        subsession_id: SubSessionId<VII>,
        signature_share: SignatureShare,
    },
    Failure(String),
}
impl<VII: ValidatorIdentityIdentity> SigningSingleRequest<VII> {
    pub(crate) fn get_identity(&self) -> &VII {
        match self {
            SigningSingleRequest::Round1 { identity, .. } => identity,
            SigningSingleRequest::Round2 { identity, .. } => identity,
        }
    }
    pub(crate) fn get_subsession_id(&self) -> SubSessionId<VII> {
        match self {
            SigningSingleRequest::Round1 { subsession_id, .. } => subsession_id.clone(),
            SigningSingleRequest::Round2 { subsession_id, .. } => subsession_id.clone(),
        }
    }
}

impl<VII: ValidatorIdentityIdentity> SigningState<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        message: Vec<u8>,
        min_signers: u16,
        pkid: Vec<u8>,
        pk: PublicKeyPackage,
        subsession_id: SubSessionId<VII>,
        participants: BTreeMap<u16, VII>,
    ) -> Self {
        Self::Round1 {
            crypto_type,
            message,
            min_signers,
            pkid,
            subsession_id,
            pk,
            participants,
        }
    }
}
impl<VII: ValidatorIdentityIdentity> State<VII> for SigningState<VII> {
    type SingleRequest = SigningSingleRequest<VII>;
    type NextState = SigningState<VII>;
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
    fn completed(&self) -> Option<PublicKeyPackage> {
        match self {
            DKGState::Completed { public_key, .. } => Some(public_key.clone()),
            _ => None,
        }
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
