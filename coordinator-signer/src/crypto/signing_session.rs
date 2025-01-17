use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

use super::{
    CryptoType, PublicKeyPackage, SessionError, SessionId, Signature, SigningSingleRequest,
    SigningSingleResponse,
};
use crate::crypto::session::subsession::{SubSession, SubSessionId, SubSessionState};
use crate::crypto::traits::ValidatorIdentity;
use std::collections::BTreeMap;
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
        })
    }
    pub(crate) fn start_new_signing<T: AsRef<[u8]>>(
        &self,
        msg: T,
        sender_id: u16,
    ) -> Result<oneshot::Receiver<Signature>, SessionError> {
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let signing_key = SigningKey::new(&mut rng);
            let signature = signing_key.sign(rng, msg.as_ref());
            sender.send(signature).unwrap();
        });
        Ok(receiver)
    }
}
