use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;

use crate::crypto::CryptoTypeError;
use crate::types::{
    message::{
        DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest,
        SigningRequestWrap, SigningResponse, SigningResponseWrap,
    },
    SignatureSuiteInfo,
};
use libp2p::request_response::{InboundRequestId, ResponseChannel};
use rand::{CryptoRng, RngCore};
use strum::IntoEnumIterator;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::crypto::*;

use super::CoorToSigResponse;
use super::{session::SessionWrapTrait, SessionWrap};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionManagerError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("crypto type not supported: {0}")]
    CryptoTypeError(#[from] CryptoTypeError),
}
pub(crate) enum Request<VII: ValidatorIdentityIdentity> {
    DKG(DKGRequestWrap<VII>, ResponseChannel<CoorToSigResponse<VII>>),
    Signing(
        SigningRequestWrap<VII>,
        ResponseChannel<CoorToSigResponse<VII>>,
    ),
}
macro_rules! new_session_wrap {
    ($session_inst_channels:expr, $generic_type:ty, $crypto_variant:ident, $rng:expr,$callback:expr) => {{
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        $session_inst_channels.insert(CryptoType::$crypto_variant, tx);
        SessionWrap::<VII, $generic_type, R>::new(rx, $rng.clone()).listening($callback);
    }};
}
pub(crate) struct SignerSessionManager<
    VII: ValidatorIdentityIdentity + Sized,
    R: CryptoRng + RngCore + Clone + Sized,
> {
    session_inst_channels: HashMap<CryptoType, UnboundedSender<Request<VII>>>,
    request_receiver: UnboundedReceiver<Request<VII>>,
    _phantom: PhantomData<R>,
}
impl<VII: ValidatorIdentityIdentity, R: CryptoRng + RngCore + Clone + Send + Sync + 'static>
    SignerSessionManager<VII, R>
{
    pub(crate) fn new<F: FnMut(ResponseChannel<CoorToSigResponse<VII>>, CoorToSigResponse<VII>)>(
        request_receiver: UnboundedReceiver<Request<VII>>,
        rng: R,
        callback: F,
    ) -> Self {
        let mut session_inst_channels = HashMap::new();
        new_session_wrap!(session_inst_channels, Ed25519Sha512, Ed25519, rng, callback);
        new_session_wrap!(
            session_inst_channels,
            Secp256K1Sha256,
            Secp256k1,
            rng,
            callback
        );
        new_session_wrap!(
            session_inst_channels,
            Secp256K1Sha256TR,
            Secp256k1Tr,
            rng,
            callback
        );
        assert!(session_inst_channels.len() == CryptoType::iter().len());

        Self {
            request_receiver,
            session_inst_channels,
            _phantom: PhantomData,
        }
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let request = self.request_receiver.recv().await;
                if let Some(request) = request {
                    match request {
                        Request::DKG(dkg_request_wrap, sender) => {
                            let session_inst_channel = self
                                .session_inst_channels
                                .get(&dkg_request_wrap.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
                                session_inst_channel
                                    .send(Request::DKG((request_id, dkg_request_wrap), sender))
                                    .unwrap();
                            } else {
                                sender
                                    .send(Err(SessionManagerError::SessionError(format!(
                                        "no channel for crypto type {} found",
                                        dkg_request_wrap.crypto_type()
                                    ))))
                                    .unwrap();
                            }
                        }
                        Request::Signing((request_id, signing_request_wrap), sender) => {
                            let session_inst_channel = self
                                .session_inst_channels
                                .get(&signing_request_wrap.crypto_type());
                            if let Some(session_inst_channel) = session_inst_channel {
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
