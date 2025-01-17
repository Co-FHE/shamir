use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

use super::subsession::{SignatureSuite, SignerSubsession};
use super::{
    CryptoType, KeyPackage, PublicKeyPackage, SessionError, SessionId, Signature,
    SigningSingleRequest, SigningSingleResponse,
};
use crate::crypto::session::subsession::{SubSession, SubSessionId};
use crate::crypto::traits::ValidatorIdentity;
use std::collections::{BTreeMap, HashMap};
pub(crate) struct SigningSession<VI: ValidatorIdentity> {
    pub(crate) pkid: Vec<u8>,
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
            pkid,
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
    ) -> Result<(), SessionError> {
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
        subsession.start_signing(msg).await;
        Ok(())
    }
}

pub(crate) struct SigningSignerSession<VI: ValidatorIdentity> {
    pub(crate) pkid: Vec<u8>,
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
            pkid,
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
    ) -> Result<(), SessionError> {
        let subsession_id = request.get_subsession_id();
        let subsession = self.subsessions.get_mut(&subsession_id);
        if let Some(subsession) = subsession {
            subsession.update_from_request(request);
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
        }
        Ok(())
    }
}
