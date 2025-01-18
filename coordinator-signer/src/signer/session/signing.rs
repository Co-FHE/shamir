#[derive(Debug, Clone)]
pub(crate) enum SignerSigningState<VII: ValidatorIdentityIdentity> {
    Round1 {
        pkid: PKID,
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
        pkid: PKID,
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
pub(crate) struct SigningSignerSession<VI: ValidatorIdentity> {
    pub(crate) pkid: PKID,
    pub(crate) session_id: SessionId<VI::Identity>,
    pub(crate) crypto_type: CryptoType,
    pub(crate) key_package: KeyPackage,
    pub(crate) public_key_package: PublicKeyPackage,
    pub(crate) min_signers: u16,
    pub(crate) participants: BTreeMap<u16, VI::Identity>,
    pub(crate) identifier: u16,
    pub(crate) identity: VI::Identity,
    subsessions: BTreeMap<SubSessionId<VI::Identity>, SignerSubsession<VI>>,
}
impl<VI: ValidatorIdentity> SigningSignerSession<VI> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        public_key_package: PublicKeyPackage,
        min_signers: u16,
        participants: BTreeMap<u16, VI::Identity>,
        crypto_type: CryptoType,
        key_package: KeyPackage,
        identifier: u16,
        identity: VI::Identity,
    ) -> Result<Self, SessionError> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key_package.public_key());
        let pkid = hasher.finalize().to_vec();
        Ok(Self {
            pkid: PKID::new(pkid),
            session_id,
            crypto_type,
            key_package,
            public_key_package,
            min_signers,
            participants,
            identifier,
            identity,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) fn apply_request(
        &mut self,
        request: SigningSingleRequest<VI::Identity>,
    ) -> Result<SigningSingleResponse<VI::Identity>, SessionError> {
        let subsession_id = request.get_subsession_id();
        let subsession = self.subsessions.get_mut(&subsession_id);
        if let Some(subsession) = subsession {
            Ok(subsession.update_from_request(request)?)
        } else {
            let (subsession, response) = SignerSubsession::<VI>::new_from_request(
                request,
                self.public_key_package.clone(),
                self.pkid.clone(),
                self.key_package.clone(),
                self.identity.clone(),
                self.identifier,
                self.participants.clone(),
                self.min_signers,
                self.crypto_type,
            )?;
            self.subsessions.insert(subsession_id, subsession);
            Ok(response)
        }
    }
}
