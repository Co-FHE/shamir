use std::collections::HashMap;

use crate::crypto::CryptoTypeError;
use crate::types::message::{
    DKGRequestWrap, DKGResponseWrap, SigningRequestWrap, SigningResponseWrap,
};
use libp2p::request_response::InboundRequestId;
use strum::IntoEnumIterator;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::crypto::*;

use super::SessionWrap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionManagerError {
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("crypto type not supported: {0}")]
    CryptoTypeError(#[from] CryptoTypeError),
}
#[derive(Debug)]
pub(crate) enum Request<VII: ValidatorIdentityIdentity> {
    DKG(
        (InboundRequestId, DKGRequestWrap<VII>),
        oneshot::Sender<(
            InboundRequestId,
            Result<DKGResponseWrap<VII>, SessionManagerError>,
        )>,
    ),
    Signing(
        (InboundRequestId, SigningRequestWrap<VII>),
        oneshot::Sender<(
            InboundRequestId,
            Result<SigningResponseWrap<VII>, SessionManagerError>,
        )>,
    ),
}
macro_rules! new_session_wrap {
    ($session_inst_channels:expr, $generic_type:ty, $crypto_variant:ident) => {{
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        $session_inst_channels.insert(CryptoType::$crypto_variant, tx);
        SessionWrap::<VII, $generic_type>::new(rx).listening();
    }};
}
pub(crate) struct SignerSessionManager<VII: ValidatorIdentityIdentity + Sized> {
    session_inst_channels: HashMap<CryptoType, UnboundedSender<Request<VII>>>,
    request_receiver: UnboundedReceiver<Request<VII>>,
}
impl<VII: ValidatorIdentityIdentity> SignerSessionManager<VII> {
    pub(crate) fn new(request_receiver: UnboundedReceiver<Request<VII>>) -> Self {
        let mut session_inst_channels = HashMap::new();
        new_session_wrap!(session_inst_channels, Ed25519Sha512, Ed25519);
        new_session_wrap!(session_inst_channels, Secp256K1Sha256, Secp256k1);
        new_session_wrap!(session_inst_channels, Secp256K1Sha256TR, Secp256k1Tr);
        assert!(session_inst_channels.len() == CryptoType::iter().len());

        Self {
            request_receiver,
            session_inst_channels,
        }
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                if let Some(request) = request {
                    match request {
                        Request::DKG((request_id, dkg_request_wrap), sender) => {
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
                                        Err(SessionManagerError::SessionError(format!(
                                            "no channel for crypto type {} found",
                                            dkg_request_wrap.crypto_type()
                                        ))),
                                    ))
                                    .unwrap();
                            }
                        }
                        Request::Signing((request_id, signing_request_wrap), sender) => {
                            let session_inst_channel = self
                                .session_inst_channels
                                .get(&signing_request_wrap.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
                                tracing::info!("sending signing request");
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
