mod error;
mod session_id;
pub(crate) mod subsession;
use super::signing_session::SigningSession;
use super::{
    DKGPackage, DKGRound1Package, DKGRound1SecretPackage, DKGRound2Package, DKGRound2Packages,
    DKGRound2SecretPackage, KeyPackage, PublicKeyPackage, SigningSignerSession,
    SigningSingleRequest, SigningSingleResponse, ValidatorIdentityIdentity,
};
use crate::crypto::dkg::*;
use crate::crypto::{CryptoType, ValidatorIdentity};
use common::Settings;
pub(crate) use error::SessionError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::{Multiaddr, PeerId};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
pub(crate) use session_id::SessionId;
use std::collections::{BTreeMap, HashMap};
use subsession::{SignatureSuite, SubSession, SubSessionId};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use uuid::Uuid;

pub(crate) struct SignerSession<VI: ValidatorIdentity> {
    session_id: SessionId<VI::Identity>,
    crypto_type: CryptoType,
    min_signers: u16,
    participants: BTreeMap<u16, VI::Identity>,
    dkg_state: DKGSignerState<VI::Identity>,
    identity: VI::Identity,
    identifier: u16,
    rng: ThreadRng,
}
impl<VI: ValidatorIdentity> SignerSession<VI> {
    pub(crate) fn new_from_request(
        request: DKGSingleRequest<VI::Identity>,
    ) -> Result<(Self, DKGSingleResponse<VI::Identity>), SessionError> {
        if let DKGSingleRequest::Part1 {
            crypto_type,
            session_id,
            min_signers,
            participants,
            identifier,
            identity,
        } = request
        {
            let _identity =
                participants
                    .get(&identifier)
                    .ok_or(SessionError::InvalidParticipants(format!(
                        "identifier {} not found in participants",
                        identifier
                    )))?;
            if _identity != &identity {
                return Err(SessionError::InvalidParticipants(format!(
                    "identity {} does not match identity {}",
                    _identity.to_fmt_string(),
                    identity.to_fmt_string()
                )));
            }
            if identifier == 0 {
                return Err(SessionError::InvalidParticipants(format!(
                    "identifier {} is invalid",
                    identifier
                )));
            }
            let mut rng = thread_rng();
            let (round1_secret_package, round1_package) = match crypto_type {
                CryptoType::Ed25519 => {
                    let package_result = frost_ed25519::keys::dkg::part1(
                        frost_core::Identifier::try_from(identifier).unwrap(),
                        participants.len() as u16,
                        min_signers,
                        &mut rng,
                    );
                    match package_result {
                        Ok((secret_package, package)) => (
                            DKGRound1SecretPackage::Ed25519(secret_package),
                            DKGRound1Package::Ed25519(package),
                        ),
                        Err(e) => {
                            return Err(SessionError::InvalidParticipants(format!(
                                "error generating package: {}",
                                e
                            )));
                        }
                    }
                }
                CryptoType::Secp256k1 => {
                    let package_result = frost_secp256k1::keys::dkg::part1(
                        frost_core::Identifier::try_from(identifier).unwrap(),
                        participants.len() as u16,
                        min_signers,
                        &mut rng,
                    );
                    match package_result {
                        Ok((secret_package, package)) => (
                            DKGRound1SecretPackage::Secp256k1(secret_package),
                            DKGRound1Package::Secp256k1(package),
                        ),
                        Err(e) => {
                            return Err(SessionError::InvalidParticipants(format!(
                                "error generating package: {}",
                                e
                            )));
                        }
                    }
                }
                CryptoType::Secp256k1Tr => {
                    let package_result = frost_secp256k1_tr::keys::dkg::part1(
                        frost_core::Identifier::try_from(identifier).unwrap(),
                        participants.len() as u16,
                        min_signers,
                        &mut rng,
                    );
                    match package_result {
                        Ok((secret_package, package)) => (
                            DKGRound1SecretPackage::Secp256k1Tr(secret_package),
                            DKGRound1Package::Secp256k1Tr(package),
                        ),
                        Err(e) => {
                            return Err(SessionError::InvalidParticipants(format!(
                                "error generating package: {}",
                                e
                            )));
                        }
                    }
                }
            };
            let response = DKGSingleResponse::Part1 {
                min_signers,
                max_signers: participants.len() as u16,
                identifier,
                identity: identity.clone(),
                crypto_package: DKGPackage::Round1(round1_package.clone()),
            };
            Ok((
                Self {
                    session_id: session_id.clone(),
                    crypto_type,
                    min_signers,
                    dkg_state: DKGSignerState::Part1 {
                        crypto_type,
                        min_signers,
                        session_id: session_id.clone(),
                        participants: participants.clone(),
                        identifier,
                        identity: identity.clone(),
                        round1_secret_package,
                    },
                    participants: participants.clone(),
                    identity: identity.clone(),
                    identifier,
                    rng,
                },
                response,
            ))
        } else {
            Err(SessionError::InvalidRequest(format!(
                "invalid request: {:?}",
                request
            )))
        }
    }
    pub(crate) fn update_from_request(
        &mut self,
        request: DKGSingleRequest<VI::Identity>,
    ) -> Result<DKGSingleResponse<VI::Identity>, SessionError> {
        match request.clone() {
            DKGSingleRequest::Part1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from part1: {:?}",
                    request
                )));
            }
            DKGSingleRequest::Part2 {
                session_id,
                crypto_type,
                min_signers,
                max_signers,
                identifier,
                identity,
                round1_packages,
            } => {
                let tmp_round1_packages = round1_packages.clone();
                if let DKGSignerState::Part1 {
                    round1_secret_package,
                    // round1_package,
                    ..
                } = &self.dkg_state
                {
                    let _identity = self.participants.get(&identifier).ok_or(
                        SessionError::InvalidParticipants(format!(
                            "identifier {} not found in participants",
                            identifier
                        )),
                    )?;
                    if _identity != &identity {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identity {} does not match identity {}",
                            _identity.to_fmt_string(),
                            identity.to_fmt_string()
                        )));
                    }
                    if identifier == 0 {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identifier {} is invalid",
                            identifier
                        )));
                    }
                    let (round2_secret_package, round2_package) = match crypto_type {
                        CryptoType::Ed25519 => {
                            // convert round1_secret_package to frost_core::keys::dkg::round1::SecretPackage
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Ed25519(package) = package {
                                    round1_packages_map.insert(
                                        frost_ed25519::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let round1_secret_package = match round1_secret_package {
                                DKGRound1SecretPackage::Ed25519(secret_package) => secret_package,
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round1_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_ed25519::keys::dkg::part2(
                                round1_secret_package,
                                &round1_packages_map,
                            );
                            match package_result {
                                Ok((secret_package, package)) => (
                                    DKGRound2SecretPackage::Ed25519(secret_package),
                                    DKGRound2Packages::Ed25519(package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InternalError(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        CryptoType::Secp256k1 => {
                            // convert round1_secret_package to frost_core::keys::dkg::round1::SecretPackage
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Secp256k1(package) = package {
                                    round1_packages_map.insert(
                                        frost_secp256k1::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let round1_secret_package = match round1_secret_package {
                                DKGRound1SecretPackage::Secp256k1(secret_package) => secret_package,
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round1_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_secp256k1::keys::dkg::part2(
                                round1_secret_package,
                                &round1_packages_map,
                            );
                            match package_result {
                                Ok((secret_package, package)) => (
                                    DKGRound2SecretPackage::Secp256k1(secret_package),
                                    DKGRound2Packages::Secp256k1(package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InternalError(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        CryptoType::Secp256k1Tr => {
                            // convert round1_secret_package to frost_core::keys::dkg::round1::SecretPackage
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Secp256k1Tr(package) = package {
                                    round1_packages_map.insert(
                                        frost_secp256k1_tr::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let round1_secret_package = match round1_secret_package {
                                DKGRound1SecretPackage::Secp256k1Tr(secret_package) => {
                                    secret_package
                                }
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round1_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_secp256k1_tr::keys::dkg::part2(
                                round1_secret_package,
                                &round1_packages_map,
                            )
                            .clone();
                            match package_result {
                                Ok((secret_package, package)) => (
                                    DKGRound2SecretPackage::Secp256k1Tr(secret_package),
                                    DKGRound2Packages::Secp256k1Tr(package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InternalError(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                    };
                    let response = DKGSingleResponse::Part2 {
                        min_signers,
                        max_signers,
                        identifier,
                        identity: identity.clone(),
                        crypto_package: DKGPackage::Round2(round2_package.clone()),
                    };
                    // TODO: cannot update directly, need to judge whether coordinator is in part1 or part2
                    self.dkg_state = DKGSignerState::Part2 {
                        crypto_type,
                        min_signers,
                        session_id: session_id.clone(),
                        participants: self.participants.clone(),
                        identifier,
                        identity: identity.clone(),
                        // round1_secret_package: round1_secret_package.clone(),
                        // round1_package: round1_package.clone(),
                        round1_packages: tmp_round1_packages,
                        round2_secret_package: round2_secret_package.clone(),
                        // round2_packages: round2_package.clone(),
                    };
                    Ok(response)
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from part2: {:?}",
                        request
                    )));
                }
            }
            DKGSingleRequest::GenPublicKey {
                session_id,
                crypto_type,
                min_signers,
                max_signers,
                identifier,
                identity,
                round1_packages,
                round2_packages,
            } => {
                let tmp_round1_packages = round1_packages.clone();
                if let DKGSignerState::Part2 {
                    // round1_secret_package,
                    round2_secret_package,
                    ..
                } = &self.dkg_state
                {
                    let _identity = self.participants.get(&identifier).ok_or(
                        SessionError::InvalidParticipants(format!(
                            "identifier {} not found in participants",
                            identifier
                        )),
                    )?;
                    if _identity != &identity {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identity {} does not match identity {}",
                            _identity.to_fmt_string(),
                            identity.to_fmt_string()
                        )));
                    }
                    if identifier == 0 {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identifier {} is invalid",
                            identifier
                        )));
                    }
                    let (key_package, public_key_package) = match crypto_type {
                        CryptoType::Ed25519 => {
                            // convert round1_secret_package to frost_core::keys::dkg::round1::SecretPackage
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Ed25519(package) = package {
                                    round1_packages_map.insert(
                                        frost_ed25519::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let mut round2_packages_map = BTreeMap::new();
                            for (id, package) in round2_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound2Package::Ed25519(package) = package {
                                    round2_packages_map.insert(
                                        frost_ed25519::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                }
                            }
                            let round2secret_package = match round2_secret_package {
                                DKGRound2SecretPackage::Ed25519(secret_package) => secret_package,
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round2_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_ed25519::keys::dkg::part3(
                                &round2secret_package,
                                &round1_packages_map,
                                &round2_packages_map,
                            );
                            match package_result {
                                Ok((key_package, public_key_package)) => (
                                    KeyPackage::Ed25519(key_package),
                                    PublicKeyPackage::Ed25519(public_key_package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        CryptoType::Secp256k1 => {
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Secp256k1(package) = package {
                                    round1_packages_map.insert(
                                        frost_secp256k1::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let mut round2_packages_map = BTreeMap::new();
                            for (id, package) in round2_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound2Package::Secp256k1(package) = package {
                                    round2_packages_map.insert(
                                        frost_secp256k1::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                }
                            }
                            let round2secret_package = match round2_secret_package {
                                DKGRound2SecretPackage::Secp256k1(secret_package) => secret_package,
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round2_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_secp256k1::keys::dkg::part3(
                                &round2secret_package,
                                &round1_packages_map,
                                &round2_packages_map,
                            );
                            match package_result {
                                Ok((key_package, public_key_package)) => (
                                    KeyPackage::Secp256k1(key_package),
                                    PublicKeyPackage::Secp256k1(public_key_package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        CryptoType::Secp256k1Tr => {
                            let mut round1_packages_map = BTreeMap::new();
                            for (id, package) in round1_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound1Package::Secp256k1Tr(package) = package {
                                    round1_packages_map.insert(
                                        frost_secp256k1_tr::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                } else {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid package type: {:?}",
                                        package
                                    )));
                                }
                            }
                            let mut round2_packages_map = BTreeMap::new();
                            for (id, package) in round2_packages {
                                if id == self.identifier {
                                    continue;
                                }
                                if let DKGRound2Package::Secp256k1Tr(package) = package {
                                    round2_packages_map.insert(
                                        frost_secp256k1_tr::Identifier::try_from(id).unwrap(),
                                        package.clone(),
                                    );
                                }
                            }
                            let round2secret_package = match round2_secret_package {
                                DKGRound2SecretPackage::Secp256k1Tr(secret_package) => {
                                    secret_package
                                }
                                _ => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "invalid secret package type: {:?}",
                                        round2_secret_package
                                    )));
                                }
                            }
                            .clone();
                            let package_result = frost_secp256k1_tr::keys::dkg::part3(
                                &round2secret_package,
                                &round1_packages_map,
                                &round2_packages_map,
                            );
                            match package_result {
                                Ok((key_package, public_key_package)) => (
                                    KeyPackage::Secp256k1Tr(key_package),
                                    PublicKeyPackage::Secp256k1Tr(public_key_package),
                                ),
                                Err(e) => {
                                    return Err(SessionError::InvalidParticipants(format!(
                                        "error generating package: {}",
                                        e
                                    )));
                                }
                            }
                        }
                    };
                    let response = DKGSingleResponse::Part2 {
                        min_signers,
                        max_signers,
                        identifier,
                        identity: identity.clone(),
                        crypto_package: DKGPackage::PublicKey(public_key_package.clone()),
                    };
                    // TODO: cannot update directly, need to judge whether coordinator is in part1 or part2
                    self.dkg_state = DKGSignerState::Completed {
                        key_package,
                        public_key_package,
                        crypto_type,
                        min_signers,
                        session_id,
                        participants: self.participants.clone(),
                        identifier,
                        identity,
                    };
                    Ok(response)
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from part2: {:?}",
                        request
                    )));
                }
            }
        }
    }
    pub(crate) fn is_completed(&self) -> Option<Result<SigningSignerSession<VI>, SessionError>> {
        match self.dkg_state.clone() {
            DKGSignerState::Completed {
                key_package,
                public_key_package,
                ..
            } => Some(SigningSignerSession::new(
                self.session_id.clone(),
                public_key_package,
                self.min_signers,
                self.participants.clone(),
                self.crypto_type,
                key_package,
                self.identifier,
                self.identity.clone(),
            )),
            _ => None,
        }
    }
}

pub(crate) struct Session<VI: ValidatorIdentity> {
    session_id: SessionId<VI::Identity>,
    crypto_type: CryptoType,
    min_signers: u16,
    dkg_state: DKGState<VI::Identity>,
    participants: BTreeMap<u16, VI::Identity>,
    dkg_sender: UnboundedSender<(
        DKGSingleRequest<VI::Identity>,
        oneshot::Sender<DKGSingleResponse<VI::Identity>>,
    )>,
    subsessions: BTreeMap<SubSessionId<VI::Identity>, SubSession<VI>>,
}

impl<VI: ValidatorIdentity> Session<VI> {
    pub fn new(
        crypto_type: CryptoType,
        participants: Vec<(u16, VI::Identity)>,
        min_signers: u16,
        dkg_sender: UnboundedSender<(
            DKGSingleRequest<VI::Identity>,
            oneshot::Sender<DKGSingleResponse<VI::Identity>>,
        )>,
    ) -> Result<Self, SessionError> {
        let mut participants_map = BTreeMap::new();
        for (id, identity) in participants {
            if participants_map.contains_key(&id) {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant id: {}",
                    id
                )));
            }
            // Identity must be different
            if participants_map
                .values()
                .any(|_identity| _identity == &identity)
            {
                return Err(SessionError::InvalidParticipants(format!(
                    "duplicate participant identity: {}",
                    identity.to_fmt_string()
                )));
            }
            participants_map.insert(id, identity);
        }
        if participants_map.len() < min_signers as usize {
            return Err(SessionError::InvalidMinSigners(
                min_signers,
                participants_map.len() as u16,
            ));
        }
        if participants_map.len() > 255 {
            return Err(SessionError::InvalidParticipants(format!(
                "max signers is 255, got {}",
                participants_map.len()
            )));
        }
        let session_id = SessionId::new(crypto_type, min_signers, &participants_map)?;
        let dkg_state = DKGState::new(
            crypto_type,
            min_signers,
            participants_map.clone(),
            session_id.clone(),
        );

        Ok(Session {
            session_id,
            crypto_type,
            min_signers,
            dkg_state,
            participants: participants_map,
            dkg_sender,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) async fn start(
        mut self,
        sender: oneshot::Sender<SigningSession<VI>>,
        signing_sender: UnboundedSender<(
            SigningSingleRequest<VI::Identity>,
            oneshot::Sender<SigningSingleResponse<VI::Identity>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI>>,
    ) {
        tracing::debug!("Starting DKG session with id: {:?}", self.session_id);
        tokio::spawn(async move {
            let signing_session = loop {
                if let Some(public_key_package) = self.dkg_state.completed() {
                    let signing_session = SigningSession::<VI>::new(
                        self.session_id.clone(),
                        public_key_package,
                        self.min_signers,
                        self.participants.clone(),
                        self.crypto_type,
                        signing_sender,
                        signature_sender,
                    );
                    if let Err(e) = signing_session {
                        return Err(e);
                    }
                    let signing_session = signing_session.unwrap();
                    break signing_session;
                }
                tracing::info!("Starting new DKG round");
                let mut futures = FuturesUnordered::new();
                for request in self.dkg_state.split_into_single_requests() {
                    tracing::debug!("Sending DKG request: {:?}", request);
                    let (tx, rx) = oneshot::channel();
                    futures.push(rx);
                    if let Err(e) = self.dkg_sender.send((request.clone(), tx)) {
                        tracing::error!("Error sending DKG state: {}", e);
                        tracing::debug!("Failed request was: {:?}", request);
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            Settings::global().session.state_channel_retry_interval,
                        ))
                        .await;
                    }
                }
                let mut responses = BTreeMap::new();
                tracing::info!("Waiting for {} responses", self.participants.len());
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            tracing::debug!("Received valid response: {:?}", response);
                            responses.insert(response.get_identifier(), response);
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            tracing::debug!("Breaking out of response collection loop");
                            break;
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            tracing::debug!(
                                "Received None response, breaking out of collection loop"
                            );
                            break;
                        }
                    }
                }
                if responses.len() == self.participants.len() {
                    tracing::debug!("Received all {} responses, handling them", responses.len());
                    let result = self.dkg_state.handle_response(responses);
                    match result {
                        Ok(next_state) => {
                            tracing::debug!("Successfully transitioned to next DKG state");
                            self.dkg_state = next_state;
                        }
                        Err(e) => {
                            tracing::error!("Error handling DKG state: {}", e);
                            tracing::debug!("Retrying after interval");
                            tokio::time::sleep(tokio::time::Duration::from_secs(
                                Settings::global().session.state_channel_retry_interval,
                            ))
                            .await;
                            continue;
                        }
                    }
                } else {
                    tracing::error!(
                        "DKG state is not completed, got {}/{} responses",
                        responses.len(),
                        self.participants.len()
                    );
                    tracing::debug!("Retrying after interval");
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        Settings::global().session.state_channel_retry_interval,
                    ))
                    .await;
                    continue;
                }
            };
            if let Err(e) = sender.send(signing_session) {
                tracing::error!("Error sending signing session: {:?}", e.pkid);
            }
            return Ok(());
        });
    }

    pub(crate) fn session_id(&self) -> SessionId<VI::Identity> {
        self.session_id.clone()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidValidator<VI: ValidatorIdentity> {
    pub(crate) p2p_peer_id: PeerId,
    pub(crate) validator_peer_id: VI::Identity,
    pub(crate) validator_public_key: VI::PublicKey,
    pub(crate) nonce: u64,
    pub(crate) address: Option<Multiaddr>,
}
