use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::keystore::Keystore;
use crate::signer::session::SessionWrapEx;
use crate::types::error::SessionError;
use crate::types::message::{
    DKGRequestWrap, DKGRequestWrapEx, DKGResponseWrap, DKGResponseWrapEx, SigningRequestWrap,
    SigningRequestWrapEx, SigningResponseWrap, SigningResponseWrapEx,
};
use libp2p::request_response::InboundRequestId;
use strum::EnumCount;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::crypto::*;

use super::SessionWrap;

#[derive(Debug)]
pub(crate) enum Request<VII: ValidatorIdentityIdentity> {
    DKG(
        (InboundRequestId, DKGRequestWrap<VII>),
        oneshot::Sender<(InboundRequestId, Result<DKGResponseWrap<VII>, SessionError>)>,
    ),
    Signing(
        (InboundRequestId, SigningRequestWrap<VII>),
        oneshot::Sender<(
            InboundRequestId,
            Result<SigningResponseWrap<VII>, SessionError>,
        )>,
    ),
}
#[derive(Debug)]
pub(crate) enum RequestExWithInboundRequestId<VII: ValidatorIdentityIdentity> {
    DKGEx(
        (InboundRequestId, DKGRequestWrapEx<VII>),
        oneshot::Sender<(InboundRequestId, Result<DKGResponseWrapEx, SessionError>)>,
    ),
    SigningEx(
        (InboundRequestId, SigningRequestWrapEx<VII>),
        oneshot::Sender<(
            InboundRequestId,
            Result<SigningResponseWrapEx, SessionError>,
        )>,
    ),
}
#[derive(Debug)]
pub(crate) enum RequestEx<VII: ValidatorIdentityIdentity> {
    DKGEx(
        DKGRequestWrapEx<VII>,
        oneshot::Sender<Result<DKGResponseWrapEx, SessionError>>,
    ),
    SigningEx(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<Result<SigningResponseWrapEx, SessionError>>,
    ),
}
#[derive(Debug)]
pub(crate) enum ManagerRequestWithInboundRequestId<VII: ValidatorIdentityIdentity> {
    Request(Request<VII>),
    RequestEx(RequestExWithInboundRequestId<VII>),
}
pub(crate) enum ManagerRequest<VII: ValidatorIdentityIdentity> {
    #[allow(dead_code)]
    RequestEx(RequestEx<VII>),
}
macro_rules! new_session_wrap {
    ($session_inst_channels:expr, $generic_type:ty, $crypto_variant:ident, $keystore:expr, $base_path:expr) => {{
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        $session_inst_channels.insert(CryptoType::$crypto_variant, tx);
        SessionWrap::<VII, $generic_type>::new(rx, $keystore, $base_path)?.listening();
    }};
}
pub(crate) struct SignerSessionManager<VII: ValidatorIdentityIdentity + Sized> {
    session_inst_channels: HashMap<CryptoType, UnboundedSender<Request<VII>>>,
    session_inst_channels_ex:
        HashMap<CryptoType, UnboundedSender<RequestExWithInboundRequestId<VII>>>,
    request_receiver: UnboundedReceiver<ManagerRequestWithInboundRequestId<VII>>,
}
impl<VII: ValidatorIdentityIdentity> SignerSessionManager<VII> {
    pub(crate) fn new(
        request_receiver: UnboundedReceiver<ManagerRequestWithInboundRequestId<VII>>,
        request_sender: UnboundedSender<RequestEx<VII>>,
        keystore: Arc<Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let mut session_inst_channels = HashMap::new();
        let mut session_inst_channels_ex = HashMap::new();
        new_session_wrap!(
            session_inst_channels,
            Ed25519Sha512,
            Ed25519,
            keystore.clone(),
            base_path
        );
        new_session_wrap!(
            session_inst_channels,
            Secp256K1Sha256,
            Secp256k1,
            keystore.clone(),
            base_path
        );
        new_session_wrap!(
            session_inst_channels,
            Secp256K1Sha256TR,
            Secp256k1Tr,
            keystore.clone(),
            base_path
        );
        new_session_wrap!(
            session_inst_channels,
            Ed448Shake256,
            Ed448,
            keystore.clone(),
            base_path
        );
        new_session_wrap!(
            session_inst_channels,
            Ristretto255Sha512,
            Ristretto255,
            keystore.clone(),
            base_path
        );
        new_session_wrap!(
            session_inst_channels,
            P256Sha256,
            P256,
            keystore.clone(),
            base_path
        );

        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
        session_inst_channels_ex.insert(CryptoType::EcdsaSecp256k1, in_tx);
        SessionWrapEx::<VII>::new(
            CryptoType::EcdsaSecp256k1,
            in_rx,
            request_sender.clone(),
            keystore.clone(),
            base_path,
        )?
        .listening();
        assert!(session_inst_channels.len() + session_inst_channels_ex.len() == CryptoType::COUNT);

        Ok(Self {
            request_receiver,
            session_inst_channels,
            session_inst_channels_ex,
        })
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                tracing::debug!("Received request in manager {:?}", request);
                if let Some(request) = request {
                    match request {
                        ManagerRequestWithInboundRequestId::Request(Request::DKG(
                            (request_id, dkg_request_wrap),
                            sender,
                        )) => {
                            let session_inst_channel = self
                                .session_inst_channels
                                .get(&dkg_request_wrap.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
                                session_inst_channel
                                    .send(Request::DKG((request_id, dkg_request_wrap), sender))
                                    .unwrap();
                            } else {
                                sender
                                    .send((
                                        request_id,
                                        Err(SessionError::CryptoTypeError(
                                            dkg_request_wrap.crypto_type(),
                                        )),
                                    ))
                                    .unwrap();
                            }
                        }
                        ManagerRequestWithInboundRequestId::RequestEx(
                            RequestExWithInboundRequestId::DKGEx(
                                (request_id, dkg_request_wrap_ex),
                                sender,
                            ),
                        ) => {
                            if let Some(session_inst_channel) = self
                                .session_inst_channels_ex
                                .get(&dkg_request_wrap_ex.crypto_type())
                            {
                                session_inst_channel
                                    .send(RequestExWithInboundRequestId::DKGEx(
                                        (request_id, dkg_request_wrap_ex),
                                        sender,
                                    ))
                                    .unwrap();
                            } else {
                                sender
                                    .send((
                                        request_id,
                                        Err(SessionError::CryptoTypeError(
                                            dkg_request_wrap_ex.crypto_type(),
                                        )),
                                    ))
                                    .unwrap();
                            }
                        }
                        ManagerRequestWithInboundRequestId::RequestEx(
                            RequestExWithInboundRequestId::SigningEx(
                                (request_id, signing_request_wrap_ex),
                                sender,
                            ),
                        ) => {
                            let session_inst_channel = self
                                .session_inst_channels_ex
                                .get(&signing_request_wrap_ex.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
                                session_inst_channel
                                    .send(RequestExWithInboundRequestId::SigningEx(
                                        (request_id, signing_request_wrap_ex),
                                        sender,
                                    ))
                                    .unwrap();
                            } else {
                                sender
                                    .send((
                                        request_id,
                                        Err(SessionError::CryptoTypeError(
                                            signing_request_wrap_ex.crypto_type(),
                                        )),
                                    ))
                                    .unwrap();
                            }
                        }
                        ManagerRequestWithInboundRequestId::Request(Request::Signing(
                            (request_id, signing_request_wrap),
                            sender,
                        )) => {
                            let session_inst_channel = self
                                .session_inst_channels
                                .get(&signing_request_wrap.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
                                tracing::debug!("sending signing request");
                                session_inst_channel
                                    .send(Request::Signing(
                                        (request_id, signing_request_wrap),
                                        sender,
                                    ))
                                    .unwrap();
                            }
                        }
                    }
                }
            }
        });
    }
}
