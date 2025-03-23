use serde::{Deserialize, Serialize};
use subsession::CoordinatorSubsessionEx;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{
    crypto::{pk_to_pkid, CryptoType, Identifier, PkId, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{SigningRequestWrapEx, SigningResponseWrapEx},
        Participants, SubsessionId,
    },
    SignatureSuiteInfo,
};
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorSigningSessionInfo<VII: ValidatorIdentityIdentity, CI: Identifier> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) pkid: PkId,
    pub(crate) public_key_package: Vec<u8>,
    pub(crate) min_signers: CI,
    pub(crate) participants: Participants<VII, CI>,
}

impl<VII: ValidatorIdentityIdentity, CI: Identifier> CoordinatorSigningSessionInfo<VII, CI> {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        let data = (
            self.crypto_type,
            self.pkid.clone(),
            self.public_key_package.clone(),
            self.min_signers.to_bytes(),
            self.participants.serialize()?,
        );
        Ok(bincode::serialize(&data).unwrap())
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, SessionError> {
        let data: (CryptoType, PkId, Vec<u8>, Vec<u8>, Vec<u8>) = bincode::deserialize(bytes)
            .map_err(|e| SessionError::DeserializationError(e.to_string()))?;
        Ok(Self {
            crypto_type: data.0,
            pkid: data.1,
            public_key_package: data.2,
            min_signers: CI::from_bytes(&data.3)
                .map_err(|e| SessionError::DeserializationError(e.to_string()))?,
            participants: Participants::deserialize(&data.4)
                .map_err(|e| SessionError::DeserializationError(e.to_string()))?,
        })
    }
}

mod subsession;
pub(crate) struct CoordinatorSigningSessionEx<VII: ValidatorIdentityIdentity> {
    pub(crate) base_info: CoordinatorSigningSessionInfo<VII, u16>,
    out_init_signing_sender: UnboundedSender<(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<SigningResponseWrapEx>,
    )>,
}
impl<VII: ValidatorIdentityIdentity> CoordinatorSigningSessionEx<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        public_key_package: Vec<u8>,
        min_signers: u16,
        participants: Participants<VII, u16>,
        out_init_signing_sender: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    ) -> Result<Self, SessionError> {
        let pkid = pk_to_pkid(crypto_type, &public_key_package)?;
        participants.check_min_signers(min_signers)?;

        Ok(Self {
            base_info: CoordinatorSigningSessionInfo {
                crypto_type,
                pkid,
                public_key_package,
                min_signers,
                participants,
            },
            out_init_signing_sender,
        })
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        self.base_info.serialize()
    }
    pub(crate) fn deserialize(
        bytes: &[u8],
        signing_sender: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    ) -> Result<Self, SessionError> {
        let info: CoordinatorSigningSessionInfo<VII, u16> =
            CoordinatorSigningSessionInfo::deserialize(bytes)
                .map_err(|e| SessionError::CoordinatorSessionError(e.to_string()))?;
        Ok(Self {
            base_info: info,
            out_init_signing_sender: signing_sender,
        })
    }
    pub(crate) async fn start_new_signing<T: AsRef<[u8]>>(
        &mut self,
        msg: T,
        tweak_data: Option<T>,
        response: oneshot::Sender<
            Result<SignatureSuiteInfo<VII>, (Option<SubsessionId>, Vec<u16>, SessionError)>,
        >,
        participants_candidates: Vec<u16>,

        in_final_rx: UnboundedReceiver<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    ) -> Result<SubsessionId, SessionError> {
        let mut base_info = self.base_info.clone();
        // check all participants candidates are in the participants
        for participant in participants_candidates.iter() {
            if !base_info.participants.contains_key(participant) {
                return Err(SessionError::CoordinatorSessionError(format!(
                    "Participant {} not found",
                    participant
                )));
            }
        }
        base_info.participants = base_info.participants.filter(&participants_candidates)?;
        let msg = msg.as_ref().to_vec();
        let tweak_data = tweak_data.map(|s| s.as_ref().to_vec());
        let subssesion = CoordinatorSubsessionEx::<VII>::new(
            base_info.clone(),
            msg.clone(),
            tweak_data.clone(),
            self.out_init_signing_sender.clone(),
        );
        match subssesion {
            Ok(subsession) => {
                let subsession_id = subsession.subsession_id();
                subsession
                    .start_signing(in_final_rx, participants_candidates, response)
                    .await;
                Ok(subsession_id)
            }
            Err(e) => {
                response.send(Err((None, Vec::new(), e.clone()))).unwrap();
                Err(e)
            }
        }
    }
}
