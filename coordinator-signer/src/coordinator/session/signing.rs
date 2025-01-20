use std::collections::HashMap;

use subsession::CoordinatorSubsession;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use crate::{
    crypto::{PkId, PublicKeyPackage, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{SigningRequest, SigningResponse},
        Participants, SignatureSuite, SubsessionId,
    },
};

use super::{Cipher, SessionId, SigningRequestWrap, SigningResponseWrap, ValidatorIdentity};

mod subsession;
pub(crate) struct CoordinatorSigningSession<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) pkid: PkId,
    pub(crate) public_key_package: C::PublicKeyPackage,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, C>,
    signing_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> CoordinatorSigningSession<VII, C> {
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VII, C>,
        signing_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Result<Self, SessionError<C>> {
        Ok(Self {
            pkid: public_key_package
                .pkid()
                .map_err(|e| SessionError::CryptoError(e))?,
            public_key_package,
            min_signers,
            participants,
            signing_sender,
        })
    }
    pub(crate) async fn start_new_signing<T: AsRef<[u8]>>(
        &mut self,
        msg: T,
        response: oneshot::Sender<
            Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError<C>)>,
        >,
        callback: impl FnOnce(SubsessionId),
    ) {
        let msg = msg.as_ref().to_vec();
        let subsession_result = CoordinatorSubsession::<VII, C>::new(
            self.pkid.clone(),
            self.public_key_package.clone(),
            self.min_signers,
            self.participants.clone(),
            msg.clone(),
            self.signing_sender.clone(),
        );
        match subsession_result {
            Ok(subsession) => {
                let subsession_id = subsession.subsession_id();
                callback(subsession_id);
                subsession.start_signing(msg, response).await
            }
            Err(e) => {
                if let Err(e) = response.send(Err((None, e))) {
                    tracing::error!("Failed to send error response: {:?}", e);
                }
            }
        };
    }
}
