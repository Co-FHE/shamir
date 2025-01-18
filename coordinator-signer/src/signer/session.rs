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
