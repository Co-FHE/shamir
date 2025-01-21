mod dkg;
mod signing;
use std::collections::HashMap;

use dkg::DKGSession;
use futures::StreamExt;
use libp2p::request_response::InboundRequestId;
use rand::{rngs::ThreadRng, thread_rng, CryptoRng, RngCore};
use signing::SigningSession;
use tokio::sync::{broadcast, mpsc::UnboundedReceiver, oneshot};

use crate::{
    crypto::Cipher,
    types::{
        error::SessionError,
        message::{
            DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest,
            SigningRequestWrap, SigningResponse, SigningResponseWrap,
        },
        SessionId,
    },
};

use super::{manager::SessionManagerError, PkId, Request, ValidatorIdentityIdentity};

pub(crate) struct SessionWrap<VII: ValidatorIdentityIdentity, C: Cipher> {
    dkg_sessions: HashMap<SessionId, DKGSession<VII, C>>,
    signing_sessions: HashMap<PkId, SigningSession<VII, C>>,
    request_receiver: UnboundedReceiver<Request<VII>>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn pkid_exists(&self, pkid: PkId) -> bool {
        self.signing_sessions.contains_key(&pkid)
    }
    pub(crate) fn dkg_apply_request(
        &mut self,
        request: DKGRequestWrap<VII>,
    ) -> Result<DKGResponseWrap<VII>, SessionManagerError> {
        let rng = thread_rng();
        let request = DKGRequest::<VII, C>::from(request)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
        let session_id = request.session_id();
        match self.dkg_sessions.get_mut(&session_id) {
            Some(session) => {
                let response = session
                    .update_from_request(request, rng)
                    .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
                if let Some(session) = session
                    .is_completed()
                    .map_err(|e| SessionManagerError::SessionError(e.to_string()))?
                {
                    self.dkg_sessions.remove(&session_id);
                    self.signing_sessions.insert(session.pkid(), session);
                }
                Ok(DKGResponseWrap::from(response)
                    .map_err(|e| SessionManagerError::SessionError(e.to_string()))?)
            }
            None => {
                let (session, response) = DKGSession::new_from_request(request.clone(), rng)
                    .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
                self.dkg_sessions.insert(session_id, session);
                Ok(DKGResponseWrap::from(response)
                    .map_err(|e| SessionManagerError::SessionError(e.to_string()))?)
            }
        }
    }
    pub(crate) fn signing_apply_request(
        &mut self,
        request: SigningRequestWrap<VII>,
    ) -> Result<SigningResponseWrap<VII>, SessionManagerError> {
        let mut rng = thread_rng();
        let request = SigningRequest::<VII, C>::from(request)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
        let pkid = request.base_info.pkid.clone();
        let response = match self.signing_sessions.get_mut(&pkid) {
            Some(session) => Ok(session
                .apply_request(request, &mut rng)
                .map_err(|e| SessionManagerError::SessionError(e.to_string()))?),
            None => Err(SessionManagerError::SessionError(
                SessionError::<C>::SessionNotFound(pkid.to_string()).to_string(),
            )),
        }?;
        Ok(SigningResponseWrap::from(response)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?)
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn new(request_receiver: UnboundedReceiver<Request<VII>>) -> Self {
        Self {
            dkg_sessions: HashMap::new(),
            signing_sessions: HashMap::new(),
            request_receiver,
        }
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
