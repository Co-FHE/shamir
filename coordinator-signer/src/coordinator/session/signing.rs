mod subsession;
#[derive(Debug, Clone)]
pub(crate) enum SigningState<VII: ValidatorIdentityIdentity> {
    Round1 {
        crypto_type: CryptoType,
        message: Vec<u8>,
        min_signers: u16,
        pkid: PKID,
        subsession_id: SubSessionId<VII>,
        pk: PublicKeyPackage,
        participants: BTreeMap<u16, VII>,
    },
    Round2 {
        crypto_type: CryptoType,
        message: Vec<u8>,
        pkid: PKID,
        subsession_id: SubSessionId<VII>,
        min_signers: u16,
        participants: BTreeMap<u16, VII>,
        pk: PublicKeyPackage,
        signing_package: SigningPackage,
    },
    Completed {
        signature: Signature,
        pk: PublicKeyPackage,
        subsession_id: SubSessionId<VII>,
    },
}
pub(crate) struct CoordinatorSigningSession<VI: ValidatorIdentity> {
    pub(crate) pkid: PKID,
    pub(crate) session_id: SessionId<VI::Identity>,
    pub(crate) crypto_type: CryptoType,
    pub(crate) public_key_package: PublicKeyPackage,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    signing_sender: UnboundedSender<(
        SigningSingleRequest<VI::Identity>,
        oneshot::Sender<SigningSingleResponse<VI::Identity>>,
    )>,
    signature_sender: UnboundedSender<SignatureSuite<VI>>,
}
impl<VI: ValidatorIdentity> SigningSession<VI> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VI::Identity>,
        crypto_type: CryptoType,
        signing_sender: UnboundedSender<(
            SigningSingleRequest<VI::Identity>,
            oneshot::Sender<SigningSingleResponse<VI::Identity>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI>>,
    ) -> Result<Self, SessionError> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key_package.public_key());
        let pkid = hasher.finalize().to_vec();
        Ok(Self {
            pkid: PKID::new(pkid),
            session_id,
            crypto_type,
            public_key_package,
            min_signers,
            participants,
            signing_sender,
            signature_sender,
        })
    }
    pub(crate) async fn start_new_signing<T: AsRef<[u8]>>(
        &mut self,
        msg: T,
    ) -> Result<SubSessionId<VI::Identity>, SessionError> {
        let msg = msg.as_ref().to_vec();
        let subsession = SubSession::<VI>::new(
            self.session_id.clone(),
            self.pkid.clone(),
            self.public_key_package.clone(),
            self.min_signers,
            self.participants.clone(),
            self.crypto_type,
            msg.clone(),
            self.signing_sender.clone(),
            self.signature_sender.clone(),
        )?;
        let subsession_id = subsession.get_subsession_id();
        subsession.start_signing(msg).await;
        Ok(subsession_id)
    }
}

impl<VII: ValidatorIdentityIdentity> CoordinatorSigningState<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        message: Vec<u8>,
        min_signers: u16,
        pkid: PKID,
        pk: PublicKeyPackage,
        subsession_id: SubSessionId<VII>,
        participants: BTreeMap<u16, VII>,
        identity: VII,
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

impl<VII: ValidatorIdentityIdentity> CoordinatorSigningState<VII> {
    pub(crate) fn split_into_single_requests(&self) -> Vec<SigningSingleRequest<VII>> {
        match self {
            SigningState::Round1 {
                crypto_type,
                message,c
                min_signers,
                pkid,
                subsession_id,
                pk,
                participants,
            } => participants
                .iter()
                .map(|(id, identity)| SigningSingleRequest::Round1 {
                    pkid: pkid.clone(),
                    message: message.clone(),
                    subsession_id: subsession_id.clone(),
                    identifier: *id,
                    identity: identity.clone(),
                })
                .collect(),
            SigningState::Round2 {
                crypto_type,
                message,
                pkid,
                subsession_id,
                min_signers,
                participants,
                pk,
                signing_package,
            } => participants
                .iter()
                .map(|(id, identity)| SigningSingleRequest::Round2 {
                    pkid: pkid.clone(),
                    subsession_id: subsession_id.clone(),
                    signing_package: signing_package.clone(),
                    identifier: *id,
                    identity: identity.clone(),
                })
                .collect(),
            SigningState::Completed { .. } => vec![],
        }
    }
    pub(crate) fn completed(&self) -> Option<Signature> {
        match self {
            SigningState::Completed {
                signature,
                pk,
                subsession_id,
            } => Some(signature.clone()),
            _ => None,
        }
    }

    pub(crate) fn handle_response(
        &self,
        response: BTreeMap<u16, SigningSingleResponse<VII>>,
    ) -> Result<Self, CryptoError> {
        match self {
            SigningState::Round1 {
                crypto_type,
                message,
                min_signers,
                pkid,
                subsession_id,
                pk,
                participants,
            } => {
                for (id, _) in participants.iter() {
                    let _ = response
                        .get(id)
                        .ok_or(CryptoError::InvalidResponse(format!(
                            "response not found for id: {}",
                            id
                        )))?;
                }
                let signing_package = match crypto_type {
                    CryptoType::Ed25519 => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Ed25519(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_ed25519::SigningPackage::new(commitmentss, message);
                        SigningPackage::Ed25519(signature_packge)
                    }
                    CryptoType::Secp256k1 => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Secp256k1(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_secp256k1::SigningPackage::new(commitmentss, message);
                        SigningPackage::Secp256k1(signature_packge)
                    }
                    CryptoType::Secp256k1Tr => {
                        let mut commitmentss = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            let identifier =
                                frost_core::Identifier::try_from(*id).expect("should be nonzero");
                            if let SigningSingleResponse::Round1 { commitments, .. } = resp {
                                if let SigningCommitments::Secp256k1Tr(signing_commitments) =
                                    commitments
                                {
                                    commitmentss.insert(identifier, signing_commitments.clone());
                                }
                            }
                        }
                        let signature_packge =
                            frost_secp256k1_tr::SigningPackage::new(commitmentss, message);
                        SigningPackage::Secp256k1Tr(signature_packge)
                    }
                };
                Ok(SigningState::Round2 {
                    crypto_type: *crypto_type,
                    message: message.clone(),
                    pkid: pkid.clone(),
                    subsession_id: subsession_id.clone(),
                    min_signers: *min_signers,
                    participants: participants.clone(),
                    pk: pk.clone(),
                    signing_package,
                })
            }
            SigningState::Round2 {
                crypto_type,
                message,
                pkid,
                subsession_id,
                min_signers,
                participants,
                pk,
                signing_package,
            } => {
                for (id, _) in participants.iter() {
                    let response =
                        response
                            .get(id)
                            .ok_or(CryptoError::InvalidResponse(format!(
                                "response not found for id: {}",
                                id
                            )))?;
                }
                let signature = match crypto_type {
                    CryptoType::Ed25519 => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Ed25519(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Ed25519(public_package) = pk {
                            if let SigningPackage::Ed25519(signing_package) = signing_package {
                                let group_signature = frost_ed25519::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Ed25519(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Ed25519,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Ed25519,
                                crypto_type
                            )));
                        }
                    }
                    CryptoType::Secp256k1 => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Secp256k1(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Secp256k1(public_package) = pk {
                            if let SigningPackage::Secp256k1(signing_package) = signing_package {
                                let group_signature = frost_secp256k1::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Secp256k1(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Secp256k1,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Secp256k1,
                                crypto_type
                            )));
                        }
                    }
                    CryptoType::Secp256k1Tr => {
                        let mut signature_shares = BTreeMap::new();
                        for (id, resp) in response.iter() {
                            match resp {
                                SigningSingleResponse::Round2 {
                                    signature_share, ..
                                } => {
                                    let identifier = frost_core::Identifier::try_from(*id)
                                        .expect("should be nonzero");
                                    if let SignatureShare::Secp256k1Tr(signature_share) =
                                        signature_share
                                    {
                                        signature_shares
                                            .insert(identifier, signature_share.clone());
                                    }
                                }
                                _ => {
                                    return Err(CryptoError::InvalidResponse(format!(
                                        "need round 2 package but got round 1 package"
                                    )));
                                }
                            }
                        }
                        if let PublicKeyPackage::Secp256k1Tr(public_package) = pk {
                            if let SigningPackage::Secp256k1Tr(signing_package) = signing_package {
                                let group_signature = frost_secp256k1_tr::aggregate(
                                    &signing_package,
                                    &signature_shares,
                                    &public_package,
                                )?;
                                Signature::Secp256k1Tr(group_signature)
                            } else {
                                return Err(CryptoError::InvalidResponse(format!(
                                    "crypto type mismatch: expected {:?}, got {:?}",
                                    CryptoType::Secp256k1Tr,
                                    crypto_type
                                )));
                            }
                        } else {
                            return Err(CryptoError::InvalidResponse(format!(
                                "crypto type mismatch: expected {:?}, got {:?}",
                                CryptoType::Secp256k1Tr,
                                crypto_type
                            )));
                        }
                    }
                };
                Ok(SigningState::Completed {
                    signature,
                    pk: pk.clone(),
                    subsession_id: subsession_id.clone(),
                })
            }
            SigningState::Completed { .. } => {
                return Err(CryptoError::InvalidResponse(format!(
                    "signing already completed"
                )));
            }
        }
    }
}
