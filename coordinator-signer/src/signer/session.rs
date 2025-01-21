mod dkg;
mod signing;
use std::collections::HashMap;

use dkg::DKGSession;
use futures::StreamExt;
use rand::{CryptoRng, RngCore};
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

use super::{manager::SessionManagerError, PkId, ValidatorIdentityIdentity};

pub(crate) trait SessionWrapTrait {
    type R: CryptoRng + RngCore + Clone;
    type VII: ValidatorIdentityIdentity;
    fn dkg_apply_request(
        &mut self,
        request: DKGRequestWrap<Self::VII>,
    ) -> Result<DKGResponseWrap<Self::VII>, SessionManagerError>;
    fn signing_apply_request(
        &mut self,
        request: SigningRequestWrap<Self::VII>,
    ) -> Result<SigningResponseWrap<Self::VII>, SessionManagerError>;
    fn pkid_exists(&self, pkid: PkId) -> bool;
}
pub(crate) enum RequestCipher<VII: ValidatorIdentityIdentity> {
    DKG(
        DKGRequestWrap<VII>,
        oneshot::Sender<Result<DKGResponseWrap<VII>, SessionManagerError>>,
    ),
    Signing(
        SigningRequestWrap<VII>,
        oneshot::Sender<Result<SigningResponseWrap<VII>, SessionManagerError>>,
    ),
}
pub(crate) struct SessionWrap<
    VII: ValidatorIdentityIdentity,
    C: Cipher,
    R: CryptoRng + RngCore + Clone + Send + 'static,
> {
    dkg_sessions: HashMap<SessionId, DKGSession<VII, C, R>>,
    signing_sessions: HashMap<PkId, SigningSession<VII, C, R>>,
    request_receiver: UnboundedReceiver<RequestCipher<VII>>,
    rng: R,
}
impl<
        VII: ValidatorIdentityIdentity,
        C: Cipher,
        R: CryptoRng + RngCore + Clone + Send + 'static,
    > SessionWrap<VII, C, R>
{
    pub(crate) fn pkid_exists(&self, pkid: PkId) -> bool {
        self.signing_sessions.contains_key(&pkid)
    }
    pub(crate) fn dkg_apply_request(
        &mut self,
        request: DKGRequestWrap<VII>,
    ) -> Result<DKGResponseWrap<VII>, SessionManagerError> {
        let request = DKGRequest::<VII, C>::from(request)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
        let session_id = request.session_id();
        match self.dkg_sessions.get_mut(&session_id) {
            Some(session) => {
                let response = session
                    .update_from_request(request)
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
                let (session, response) =
                    DKGSession::new_from_request(request.clone(), self.rng.clone())
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
        let request = SigningRequest::<VII, C>::from(request)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?;
        let pkid = request.base_info.pkid.clone();
        let response = match self.signing_sessions.get_mut(&pkid) {
            Some(session) => Ok(session
                .apply_request(request)
                .map_err(|e| SessionManagerError::SessionError(e.to_string()))?),
            None => Err(SessionManagerError::SessionError(
                SessionError::<C>::SessionNotFound(pkid.to_string()).to_string(),
            )),
        }?;
        Ok(SigningResponseWrap::from(response)
            .map_err(|e| SessionManagerError::SessionError(e.to_string()))?)
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher, R: CryptoRng + RngCore + Clone + Send>
    SessionWrap<VII, C, R>
{
    pub(crate) fn new(request_receiver: UnboundedReceiver<RequestCipher<VII>>, rng: R) -> Self {
        Self {
            dkg_sessions: HashMap::new(),
            signing_sessions: HashMap::new(),
            request_receiver,
            rng,
        }
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                if let Some(request) = request {
                    match request {
                        RequestCipher::DKG(request, response_oneshot) => {
                            let result = self.dkg_apply_request(request);
                            response_oneshot.send(result).unwrap();
                        }
                        RequestCipher::Signing(request, response_oneshot) => {
                            let result = self.signing_apply_request(request);

                            response_oneshot.send(result).unwrap();
                        }
                    }
                }
            }
        });
    }
}
