pub(crate) struct SignerSubsession<VI: ValidatorIdentity> {
    pub(crate) pk: PublicKeyPackage,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) pkid: PKID,
    key_package: KeyPackage,
    pub(crate) crypto_type: CryptoType,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    pub(crate) signing_state: SignerSigningState<VI::Identity>,
    pub(crate) identity: VI::Identity,
    pub(crate) message: Vec<u8>,
    identifier: u16,
    rng: ThreadRng,
}
impl<VI: ValidatorIdentity> SignerSubsession<VI> {
    pub(crate) fn new_from_request(
        request: SigningSingleRequest<VI::Identity>,
        pk: PublicKeyPackage,
        _pkid: PKID,
        key_package: KeyPackage,
        _identity: VI::Identity,
        _identifier: u16,
        participants: BTreeMap<u16, VI::Identity>,
        min_signers: u16,
        crypto_type: CryptoType,
    ) -> Result<(Self, SigningSingleResponse<VI::Identity>), SessionError> {
        if let SigningSingleRequest::Round1 {
            pkid,
            message,
            subsession_id,
            identity,
            identifier,
        } = request
        {
            assert_eq!(identity, _identity);
            assert_eq!(pkid, _pkid);
            assert_eq!(identifier, _identifier);
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
            let (nonces, commitments) = match crypto_type {
                CryptoType::Ed25519 => {
                    if let KeyPackage::Ed25519(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Ed25519(nonces),
                            SigningCommitments::Ed25519(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package
                        )));
                    }
                }
                CryptoType::Secp256k1 => {
                    if let KeyPackage::Secp256k1(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Secp256k1(nonces),
                            SigningCommitments::Secp256k1(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package
                        )));
                    }
                }
                CryptoType::Secp256k1Tr => {
                    if let KeyPackage::Secp256k1Tr(key_package) = &key_package {
                        let (nonces, commitments) =
                            frost_core::round1::commit(key_package.signing_share(), &mut rng);
                        (
                            SigningNonces::Secp256k1Tr(nonces),
                            SigningCommitments::Secp256k1Tr(commitments),
                        )
                    } else {
                        return Err(SessionError::InvalidCryptoType(format!(
                            "invalid key package type: {:?}",
                            key_package.clone()
                        )));
                    }
                }
            };
            let response = SigningSingleResponse::Round1 {
                pkid: pkid.clone(),
                subsession_id: subsession_id.clone(),
                commitments: commitments.clone(),
                identifier: identifier.clone(),
            };
            Ok((
                Self {
                    pk: pk.clone(),
                    subsession_id: subsession_id.clone(),
                    pkid: pkid.clone(),
                    key_package: key_package.clone(),
                    crypto_type,
                    min_signers,
                    participants: participants.clone(),
                    signing_state: SignerSigningState::Round1 {
                        pkid,
                        message: message.clone(),
                        crypto_type,
                        key_package,
                        public_key_package: pk.clone(),
                        min_signers,
                        participants: participants.clone(),
                        identifier: identifier.clone(),
                        identity: identity.clone(),
                        signing_commitments: commitments.clone(),
                        nonces,
                    },
                    identity: identity.clone(),
                    message: message.clone(),
                    identifier: identifier.clone(),
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
        request: SigningSingleRequest<VI::Identity>,
    ) -> Result<SigningSingleResponse<VI::Identity>, SessionError> {
        match request.clone() {
            SigningSingleRequest::Round1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from part1: {:?}",
                    request
                )));
            }
            SigningSingleRequest::Round2 {
                pkid: _pkid,
                subsession_id,
                signing_package,
                identifier: _identifier,
                identity: _identity,
            } => {
                if let SignerSigningState::Round1 {
                    key_package,
                    pkid,
                    message,
                    crypto_type,
                    public_key_package,
                    min_signers,
                    participants,
                    identifier,
                    identity,
                    signing_commitments,
                    nonces,
                } = &self.signing_state
                {
                    assert_eq!(identity, &_identity);
                    assert_eq!(pkid, &_pkid);
                    assert_eq!(identifier, &_identifier);
                    let _identity = self.participants.get(&identifier).ok_or(
                        SessionError::InvalidParticipants(format!(
                            "identifier {} not found in participants",
                            identifier
                        )),
                    )?;
                    if _identity != identity {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identity {} does not match identity {}",
                            _identity.to_fmt_string(),
                            identity.to_fmt_string()
                        )));
                    }
                    if *identifier == 0 {
                        return Err(SessionError::InvalidParticipants(format!(
                            "identifier {} is invalid",
                            identifier
                        )));
                    }
                    let tmp_signing_package = signing_package.clone();
                    let signature_share = match self.crypto_type {
                        CryptoType::Ed25519 => {
                            if let SigningNonces::Ed25519(nonces) = nonces {
                                if let SigningPackage::Ed25519(signing_package) = signing_package {
                                    if let KeyPackage::Ed25519(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Ed25519(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                        CryptoType::Secp256k1 => {
                            if let SigningNonces::Secp256k1(nonces) = nonces {
                                if let SigningPackage::Secp256k1(signing_package) = signing_package
                                {
                                    if let KeyPackage::Secp256k1(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Secp256k1(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                        CryptoType::Secp256k1Tr => {
                            if let SigningNonces::Secp256k1Tr(nonces) = nonces {
                                if let SigningPackage::Secp256k1Tr(signing_package) =
                                    signing_package
                                {
                                    if let KeyPackage::Secp256k1Tr(key_package) = key_package {
                                        let signature_share = frost_core::round2::sign(
                                            &signing_package,
                                            nonces,
                                            key_package,
                                        )?;
                                        SignatureShare::Secp256k1Tr(signature_share)
                                    } else {
                                        return Err(SessionError::InvalidCryptoType(format!(
                                            "invalid key package type: {:?}",
                                            key_package
                                        )));
                                    }
                                } else {
                                    return Err(SessionError::InvalidCryptoType(format!(
                                        "invalid signing package type: {:?}",
                                        signing_package
                                    )));
                                }
                            } else {
                                return Err(SessionError::InvalidCryptoType(format!(
                                    "invalid nonces type: {:?}",
                                    nonces
                                )));
                            }
                        }
                    };
                    let response = SigningSingleResponse::Round2 {
                        pkid: pkid.clone(),
                        subsession_id: subsession_id.clone(),
                        signature_share: signature_share.clone(),
                        identifier: self.identifier.clone(),
                    };
                    // TODO: cannot update directly, need to judge whether coordinator is in part1 or part2
                    self.signing_state = SignerSigningState::Round2 {
                        pkid: pkid.clone(),
                        message: self.message.clone(),
                        crypto_type: self.crypto_type,
                        key_package: self.key_package.clone(),
                        public_key_package: self.pk.clone(),
                        min_signers: self.min_signers,
                        participants: self.participants.clone(),
                        identifier: self.identifier.clone(),
                        identity: self.identity.clone(),
                        signing_package: tmp_signing_package,
                        nonces: nonces.clone(),
                        signature_share: signature_share.clone(),
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
    pub(crate) fn get_subsession_id(&self) -> SubSessionId<VI::Identity> {
        self.subsession_id.clone()
    }
}
