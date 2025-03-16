use serde::{Deserialize, Serialize};
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
#[derive(Serialize, Deserialize)]
struct CoordinatorSigningSessionInfo {
    pub(crate) pkid: PkId,
    pub(crate) public_key_package: Vec<u8>,
    pub(crate) min_signers: u16,
    pub(crate) participants: Vec<u8>,
}

use super::{Cipher, SigningRequestWrap, SigningResponseWrap};

mod subsession;
pub(crate) struct CoordinatorSigningSession<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) pkid: PkId,
    pub(crate) public_key_package: C::PublicKeyPackage,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, C::Identifier>,
    signing_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> CoordinatorSigningSession<VII, C> {
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VII, C::Identifier>,
        signing_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Result<Self, SessionError> {
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
    fn info(&self) -> Result<CoordinatorSigningSessionInfo, SessionError> {
        Ok(CoordinatorSigningSessionInfo {
            pkid: self.pkid.clone(),
            public_key_package: self
                .public_key_package
                .serialize_binary()
                .map_err(|e| SessionError::CryptoError(e))?,
            min_signers: self.min_signers,
            participants: self.participants.serialize()?,
        })
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        Ok(bincode::serialize(&self.info()?).unwrap())
    }
    pub(crate) fn deserialize(
        bytes: &[u8],
        signing_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Result<Self, SessionError> {
        let info: CoordinatorSigningSessionInfo = bincode::deserialize(bytes)
            .map_err(|e| SessionError::CoordinatorSessionError(e.to_string()))?;
        Ok(Self {
            pkid: info.pkid,
            public_key_package: C::PublicKeyPackage::deserialize_binary(&info.public_key_package)
                .map_err(|e| SessionError::CryptoError(e))?,
            min_signers: info.min_signers,
            participants: Participants::deserialize(&info.participants)?,
            signing_sender,
        })
    }
    pub(crate) async fn start_new_signing<T: AsRef<[u8]>>(
        &mut self,
        msg: T,
        tweak_data: Option<T>,
        response: oneshot::Sender<
            Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError)>,
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
            tweak_data.map(|s| s.as_ref().to_vec()),
            self.signing_sender.clone(),
        );
        match subsession_result {
            Ok(subsession) => {
                let subsession_id = subsession.subsession_id();
                callback(subsession_id);
                subsession.start_signing(response).await
            }
            Err(e) => {
                if let Err(e) = response.send(Err((None, e))) {
                    tracing::error!("Failed to send error response: {:?}", e);
                }
            }
        };
    }
}
