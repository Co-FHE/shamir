mod dkg;
mod dkg_ex;
mod signing;
mod signing_ex;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use common::Settings;
use dkg::DKGSession;
use dkg_ex::DKGSessionEx;
use ecdsa_tss::signer_rpc::CoordinatorToSignerMsg;
use rand::thread_rng;
use signing::SigningSession;
use signing_ex::SigningSessionEx;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{
    crypto::{Cipher, CryptoType, Secp256K1Sha256},
    keystore::KeystoreManagement,
    types::{
        error::SessionError,
        message::{
            message_ex_to_coordinator_to_signer_msg, DKGRequest, DKGRequestEx, DKGRequestWrap,
            DKGRequestWrapEx, DKGResponseWrap, DKGResponseWrapEx, SigningRequest, SigningRequestEx,
            SigningRequestWrap, SigningRequestWrapEx, SigningResponseWrap, SigningResponseWrapEx,
            SigningStageEx,
        },
        SessionId,
    },
    utils,
};

use super::{
    manager::{ManagerRequest, RequestEx, RequestExWithInboundRequestId},
    PkId, Request, ValidatorIdentityIdentity,
};

pub(crate) enum SignerStateEx<F> {
    Init,
    Final(F),
}
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
    ) -> Result<DKGResponseWrap<VII>, SessionError> {
        let rng = thread_rng();
        let request = DKGRequest::<VII, C>::from(request)?;
        let session_id = request.session_id();
        match self.dkg_sessions.get_mut(&session_id) {
            Some(session) => {
                tracing::debug!(
                    "dkg_apply_request in {:?} session {:?}",
                    C::crypto_type(),
                    session_id
                );
                let response = session.update_from_request(request)?;
                tracing::debug!("1");
                if let Some(session) = session.is_completed()? {
                    tracing::debug!("2");
                    self.dkg_sessions.remove(&session_id);
                    self.signing_sessions.insert(session.pkid(), session);
                    tracing::debug!("3");
                    self.keystore_management
                        .write(self.serialize_sessions()?.as_slice())?;
                    tracing::debug!("4");
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
    ) -> Result<SigningResponseWrap<VII>, SessionError> {
        let mut rng = thread_rng();
        let request = SigningRequest::<VII, C>::from(request)?;
        let pkid = request.base_info.pkid.clone();
        let response = match self.signing_sessions.get_mut(&pkid) {
            Some(session) => Ok(session.apply_request(request, &mut rng)?),
            None => Err(SessionError::PkIdNotFound(pkid.to_string())),
        }?;
        Ok(SigningResponseWrap::from(response)?)
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn new(
        request_receiver: UnboundedReceiver<Request<VII>>,
        keystore: Arc<crate::keystore::Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let path = base_path
            .join(Settings::global().signer.keystore_path)
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
    ) -> Result<HashMap<PkId, SigningSession<VII, C>>, SessionError> {
        let sessions: HashMap<PkId, Vec<u8>> = bincode::deserialize(bytes)
            .map_err(|e| SessionError::SignerSessionError(e.to_string()))?;
        let mut signing_sessions = HashMap::new();
        for (pkid, data) in sessions {
            let session = SigningSession::deserialize(&data)?;
            signing_sessions.insert(pkid, session);
        }
        Ok(signing_sessions)
    }
    fn serialize_sessions(&self) -> Result<Vec<u8>, SessionError> {
        tracing::debug!("serialize_sessions");
        let sessions = self
            .signing_sessions
            .iter()
            .map(|(pkid, session)| {
                session.check_serialize_deserialize()?;
                match session.serialize() {
                    Ok(data) => Ok((pkid.clone(), data)),
                    Err(e) => Err(e),
                }
            })
            .collect::<Result<HashMap<PkId, Vec<u8>>, SessionError>>()?;
        tracing::debug!("serialize_sessions complete");
        Ok(bincode::serialize(&sessions).unwrap())
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                tracing::debug!(
                    "Received request in {:?} session {:?}",
                    C::crypto_type(),
                    request
                );
                if let Some(request) = request {
                    match request {
                        Request::DKG((request_id, request), response_oneshot) => {
                            tracing::debug!(
                                "process DKG response in {:?} session {:?}",
                                C::crypto_type(),
                                request_id
                            );
                            let result = self.dkg_apply_request(request);
                            tracing::debug!(
                                "Sent DKG response in {:?} session {:?}",
                                C::crypto_type(),
                                result
                            );
                            response_oneshot.send((request_id, result)).unwrap();
                        }
                        Request::Signing((request_id, request), response_oneshot) => {
                            let result = self.signing_apply_request(request);
                            tracing::debug!(
                                "Sent Signing response in {:?} session {:?}",
                                C::crypto_type(),
                                result
                            );

                            response_oneshot.send((request_id, result)).unwrap();
                        }
                    }
                }
            }
        });
    }
}

pub(crate) struct SessionWrapEx<VII: ValidatorIdentityIdentity> {
    crypto_type: CryptoType,
    dkg_sessions_ex: HashMap<SessionId, UnboundedSender<DKGRequestEx<VII>>>,
    signing_sessions_ex: HashMap<PkId, SigningSessionEx<VII>>,
    in_rx: UnboundedReceiver<RequestExWithInboundRequestId<VII>>,
    out_tx: UnboundedSender<RequestEx<VII>>,
    keystore_management: KeystoreManagement,

    dkg_results_tx: UnboundedSender<Result<DKGRequestWrapEx<VII>, SessionError>>,
    dkg_results_rx: UnboundedReceiver<Result<DKGRequestWrapEx<VII>, SessionError>>,
    signing_results_tx: UnboundedSender<Result<SigningRequestWrapEx<VII>, SessionError>>,
    signing_results_rx: UnboundedReceiver<Result<SigningRequestWrapEx<VII>, SessionError>>,
}
impl<VII: ValidatorIdentityIdentity> SessionWrapEx<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        in_rx: UnboundedReceiver<RequestExWithInboundRequestId<VII>>,
        out_tx: UnboundedSender<RequestEx<VII>>,
        keystore: Arc<crate::keystore::Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let path = base_path
            .join(Settings::global().signer.keystore_path)
            .join(crypto_type.to_string());
        let (keystore_management, data) =
            crate::keystore::KeystoreManagement::new(keystore, path).unwrap();
        let signing_sessions = match data {
            Some(data) => Self::deserialize_sessions(data.as_slice())?,
            None => HashMap::new(),
        };
        let (dkg_results_tx, dkg_results_rx) = tokio::sync::mpsc::unbounded_channel();
        let (signing_results_tx, signing_results_rx) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            crypto_type,
            dkg_sessions_ex: HashMap::new(),
            signing_sessions_ex: signing_sessions,
            in_rx,
            out_tx,
            keystore_management,
            dkg_results_tx,
            dkg_results_rx,
            signing_results_tx,
            signing_results_rx,
        })
    }
    pub(crate) fn dkg_apply_request(
        &mut self,
        request: DKGRequestEx<VII>,
    ) -> Result<(), SessionError> {
        let session_id = request.base_info.session_id;
        match self.dkg_sessions_ex.get_mut(&session_id) {
            Some(in_tx) => {
                tracing::debug!(
                    "dkg_apply_request in {:?} session {:?}",
                    self.crypto_type,
                    session_id
                );
                if request.base_info.crypto_type != self.crypto_type {
                    return Err(SessionError::BaseInfoNotMatch(format!(
                        "crypto type does not match: {:?} vs {:?}",
                        request.base_info.crypto_type, self.crypto_type
                    )));
                }
                in_tx.send(request).map_err(|e| {
                    SessionError::ExternalError(format!("Failed to send DKG request: {:?}", e))
                })?;
            }
            None => {
                let (in_tx_internal, in_rx_internal) =
                    tokio::sync::mpsc::unbounded_channel::<DKGRequestEx<VII>>();
                self.dkg_sessions_ex.insert(session_id, in_tx_internal);
                let dkg_results_tx = self.dkg_results_tx.clone();
                let out_tx = self.out_tx.clone();
                tokio::spawn(async move {
                    let result =
                        DKGSessionEx::new_from_request(request.clone(), in_rx_internal, out_tx)
                            .await;
                    dkg_results_tx.send(result).unwrap();
                });
                return Ok(());
            }
        }
        Ok(())
    }
    pub(crate) fn signing_apply_request(
        &mut self,
        request: SigningRequestEx<VII>,
    ) -> Result<(), SessionError> {
        let pkid = request.base_info.pkid.clone();
        if let Some(session) = self.signing_sessions_ex.get_mut(&pkid) {
            let subsession_id = request.base_info.subsession_id.clone();
            match session.subsessions.get(&subsession_id) {
                Some(tx) => {
                    if let SigningStageEx::Intermediate(msg) = request.stage {
                        tx.send(message_ex_to_coordinator_to_signer_msg(msg))
                            .map_err(|e| {
                                SessionError::ExternalError(format!(
                                    "Failed to send Signing request: {:?}",
                                    e
                                ))
                            })?;
                    } else {
                        return Err(SessionError::InvalidRequest(format!(
                            "invalid stage: {:?}",
                            request.stage
                        )));
                    }
                }
                None => {
                    let out_tx = self.out_tx.clone();
                    let signing_results_tx = self.signing_results_tx.clone();
                    let in_rx = session.new_subsession_in_channel(subsession_id);
                    if let Some(in_rx) = in_rx {
                        let base = session.base.clone();
                        tokio::spawn(async move {
                            let result =
                                SigningSessionEx::new_from_request(request, base, out_tx, in_rx)
                                    .await;
                            signing_results_tx.send(result).unwrap();
                        });
                    } else {
                        return Err(SessionError::InvalidRequest(format!(
                            "subsession {:?} already exists",
                            subsession_id
                        )));
                    }
                }
            }
        } else {
            return Err(SessionError::PkIdNotFound(pkid.to_string()));
        }
        Ok(())
    }
    fn deserialize_sessions(
        bytes: &[u8],
    ) -> Result<HashMap<PkId, SigningSessionEx<VII>>, SessionError> {
        let sessions: HashMap<PkId, Vec<u8>> = bincode::deserialize(bytes)
            .map_err(|e| SessionError::SignerSessionError(e.to_string()))?;
        let mut signing_sessions = HashMap::new();
        for (pkid, data) in sessions {
            let session = SigningSessionEx::deserialize(&data)?;
            signing_sessions.insert(pkid, session);
        }
        Ok(signing_sessions)
    }
    fn serialize_sessions(&self) -> Result<Vec<u8>, SessionError> {
        tracing::debug!("serialize_sessions");
        let sessions = self
            .signing_sessions_ex
            .iter()
            .map(|(pkid, session)| {
                session.check_serialize_deserialize()?;
                match session.serialize() {
                    Ok(data) => Ok((pkid.clone(), data)),
                    Err(e) => Err(e),
                }
            })
            .collect::<Result<HashMap<PkId, Vec<u8>>, SessionError>>()?;
        tracing::debug!("serialize_sessions complete");
        Ok(bincode::serialize(&sessions).unwrap())
    }
    pub(crate) fn dkg_apply_response(
        &mut self,
        request: DKGRequestWrapEx<VII>,
    ) -> Result<(), SessionError> {
        Ok(())
    }
    pub(crate) fn signing_apply_response(
        &mut self,
        request: SigningRequestWrapEx<VII>,
    ) -> Result<(), SessionError> {
        Ok(())
    }
    pub(crate) fn handle_dkg_result(
        &mut self,
        request: Result<DKGRequestWrapEx<VII>, SessionError>,
    ) {
        match request {
            Ok(request) => {
                self.out_tx
                    .send(RequestEx::DKGEx(
                        request,
                        utils::new_oneshot_to_receive_success_or_error(),
                    ))
                    .unwrap();
            }
            Err(e) => {
                tracing::error!("Failed to receive DKG response: {:?}", e);
            }
        }
    }
    pub(crate) fn handle_signing_result(
        &mut self,
        request: Result<SigningRequestWrapEx<VII>, SessionError>,
    ) {
        match request {
            Ok(request) => {
                self.out_tx
                    .send(RequestEx::SigningEx(
                        request,
                        utils::new_oneshot_to_receive_success_or_error(),
                    ))
                    .unwrap();
            }
            Err(e) => {
                tracing::error!("Failed to receive Signing response: {:?}", e);
            }
        }
    }
    pub(crate) fn handle_in_tx(&mut self, request: RequestExWithInboundRequestId<VII>) {
        match request {
            RequestExWithInboundRequestId::DKGEx((request_id, request), response_oneshot) => {
                tracing::debug!(
                    "process DKG response in {:?} session {:?}",
                    self.crypto_type,
                    request_id
                );
                match request.dkg_request_ex() {
                    Ok(request_single) => {
                        let result = self
                            .dkg_apply_request(request_single)
                            .map(|_| DKGResponseWrapEx::Success);
                        tracing::debug!(
                            "Sent DKG response in {:?} session {:?}",
                            self.crypto_type,
                            result
                        );
                        response_oneshot.send((request_id, result)).unwrap();
                    }
                    Err(e) => {
                        response_oneshot.send((request_id, Err(e))).unwrap();
                    }
                }
            }
            RequestExWithInboundRequestId::SigningEx((request_id, request), response_oneshot) => {
                tracing::debug!(
                    "process Signing response in {:?} session {:?}",
                    self.crypto_type,
                    request_id
                );
                match request.signing_request_ex() {
                    Ok(request_single) => {
                        let result = self
                            .signing_apply_request(request_single)
                            .map(|_| SigningResponseWrapEx::Success);
                        tracing::debug!(
                            "Sent Signing response in {:?} session {:?}",
                            self.crypto_type,
                            result
                        );
                        response_oneshot.send((request_id, result)).unwrap();
                    }
                    Err(e) => {
                        response_oneshot.send((request_id, Err(e))).unwrap();
                    }
                }
            }
        }
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(request) = self.dkg_results_rx.recv() => {
                        self.handle_dkg_result(request);
                    }
                    Some(request) = self.signing_results_rx.recv() => {
                        self.handle_signing_result(request);
                    }
                    Some(request) = self.in_rx.recv() => {
                        self.handle_in_tx(request);
                    }
                }
            }
        });
    }
}
