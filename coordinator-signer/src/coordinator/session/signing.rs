use subsession::CoordinatorSubsession;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    crypto::{PkId, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{SigningRequest, SigningResponse},
        Participants, SignatureSuite, SubsessionId,
    },
};

use super::{Cipher, SessionId, ValidatorIdentity};

mod subsession;
pub(crate) struct CoordinatorSigningSession<VI: ValidatorIdentity, C: Cipher> {
    pub(crate) pkid: PkId,
    pub(crate) session_id: SessionId<VI::Identity>,
    pub(crate) public_key_package: C::PublicKeyPackage,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VI::Identity, C>,
    signing_sender: UnboundedSender<(
        SigningRequest<VI::Identity, C>,
        oneshot::Sender<SigningResponse<VI::Identity, C>>,
    )>,
    signature_sender: UnboundedSender<SignatureSuite<VI, C>>,
}
impl<VI: ValidatorIdentity, C: Cipher> CoordinatorSigningSession<VI, C> {
    pub(crate) fn new(
        session_id: SessionId<VI::Identity>,
        public_key_package: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VI::Identity, C>,
        signing_sender: UnboundedSender<(
            SigningRequest<VI::Identity, C>,
            oneshot::Sender<SigningResponse<VI::Identity, C>>,
        )>,
        signature_sender: UnboundedSender<SignatureSuite<VI, C>>,
    ) -> Result<Self, SessionError<C>> {
        Ok(Self {
            pkid: public_key_package.into(),
            session_id,
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
    ) -> Result<SubsessionId<VI::Identity>, SessionError> {
        let msg = msg.as_ref().to_vec();
        let subsession = CoordinatorSubsession::<VI, C>::new(
            self.session_id.clone(),
            self.pkid.clone(),
            self.public_key_package.clone(),
            self.min_signers,
            self.participants.clone(),
            msg.clone(),
            self.signing_sender.clone(),
            self.signature_sender.clone(),
        )?;
        let subsession_id = subsession.get_subsession_id();
        subsession.start_signing(msg).await;
        Ok(subsession_id)
    }
}
