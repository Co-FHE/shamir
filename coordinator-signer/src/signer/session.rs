mod dkg;
mod signing;
use std::{collections::HashMap, sync::Arc};

use common::Settings;
use dkg::DKGSession;
use rand::thread_rng;
use signing::SigningSession;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{
    crypto::Cipher,
    keystore::KeystoreManagement,
    types::{
        error::SessionError,
        message::{
            DKGRequest, DKGRequestWrap, DKGResponseWrap, SigningRequest, SigningRequestWrap,
            SigningResponseWrap,
        },
        SessionId,
    },
};

use super::{manager::SessionManagerError, PkId, Request, ValidatorIdentityIdentity};

pub(crate) struct SessionWrap<VII: ValidatorIdentityIdentity, C: Cipher> {
    dkg_sessions: HashMap<SessionId, DKGSession<VII, C>>,
    signing_sessions: HashMap<PkId, SigningSession<VII, C>>,
    request_receiver: UnboundedReceiver<Request<VII>>,
    keystore_management: KeystoreManagement,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn dkg_apply_request(
        &mut self,
        request: DKGRequestWrap<VII>,
    ) -> Result<DKGResponseWrap<VII>, SessionManagerError> {
        let rng = thread_rng();
        let request = DKGRequest::<VII, C>::from(request)?;
        let session_id = request.session_id();
        match self.dkg_sessions.get_mut(&session_id) {
            Some(session) => {
                let response = session.update_from_request(request)?;
                if let Some(session) = session.is_completed()? {
                    self.dkg_sessions.remove(&session_id);
                    self.signing_sessions.insert(session.pkid(), session);
                    self.keystore_management
                        .write(self.serialize_sessions()?.as_slice())?;
                }
                Ok(DKGResponseWrap::from(response)?)
            }
            None => {
                let (session, response) = DKGSession::new_from_request(request.clone(), rng)?;
                self.dkg_sessions.insert(session_id, session);
                Ok(DKGResponseWrap::from(response)?)
            }
        }
    }
    pub(crate) fn signing_apply_request(
        &mut self,
        request: SigningRequestWrap<VII>,
    ) -> Result<SigningResponseWrap<VII>, SessionManagerError> {
        let mut rng = thread_rng();
        let request = SigningRequest::<VII, C>::from(request)?;
        let pkid = request.base_info.pkid.clone();
        let response = match self.signing_sessions.get_mut(&pkid) {
            Some(session) => Ok(session.apply_request(request, &mut rng)?),
            None => Err(SessionManagerError::SessionError(
                SessionError::<C>::PkIdNotFound(pkid.to_string()).to_string(),
            )),
        }?;
        Ok(SigningResponseWrap::from(response)?)
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn new(
        request_receiver: UnboundedReceiver<Request<VII>>,
        keystore: Arc<crate::keystore::Keystore>,
    ) -> Result<Self, SessionError<C>> {
        let path = Settings::global()
            .signer
            .keystore_path
            .join(C::crypto_type().to_string());
        let (keystore_management, data) =
            crate::keystore::KeystoreManagement::new(keystore, path).unwrap();
        let signing_sessions = match data {
            Some(data) => Self::deserialize_sessions(data.as_slice())?,
            None => HashMap::new(),
        };
        Ok(Self {
            dkg_sessions: HashMap::new(),
            signing_sessions,
            request_receiver,
            keystore_management,
        })
    }
    fn deserialize_sessions(
        bytes: &[u8],
    ) -> Result<HashMap<PkId, SigningSession<VII, C>>, SessionError<C>> {
        let sessions: HashMap<PkId, Vec<u8>> = bincode::deserialize(bytes)
            .map_err(|e| SessionError::SignerSessionError(e.to_string()))?;
        let mut signing_sessions = HashMap::new();
        for (pkid, data) in sessions {
            let session = SigningSession::deserialize(&data)?;
            signing_sessions.insert(pkid, session);
        }
        Ok(signing_sessions)
    }
    fn serialize_sessions(&self) -> Result<Vec<u8>, SessionError<C>> {
        let sessions = self
            .signing_sessions
            .iter()
            .map(|(pkid, session)| match session.serialize() {
                Ok(data) => Ok((pkid.clone(), data)),
                Err(e) => Err(e),
            })
            .collect::<Result<HashMap<PkId, Vec<u8>>, SessionError<C>>>()?;
        Ok(bincode::serialize(&sessions).unwrap())
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                if let Some(request) = request {
                    match request {
                        Request::DKG((request_id, request), response_oneshot) => {
                            let result = self.dkg_apply_request(request);
                            response_oneshot.send((request_id, result)).unwrap();
                        }
                        Request::Signing((request_id, request), response_oneshot) => {
                            let result = self.signing_apply_request(request);

                            response_oneshot.send((request_id, result)).unwrap();
                        }
                    }
                }
            }
        });
    }
}
