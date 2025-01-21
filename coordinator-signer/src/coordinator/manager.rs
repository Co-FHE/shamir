use std::collections::{BTreeMap, HashMap};

use strum::IntoEnumIterator;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::types::{
    error::SessionError,
    message::{
        DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest,
        SigningRequestWrap, SigningResponse, SigningResponseWrap,
    },
    SignatureSuiteInfo,
};

use crate::crypto::*;

use super::{
    session::{self, InstructionCipher},
    SessionWrap,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionManagerError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("crypto type Error: {0}")]
    CryptoTypeError(#[from] CryptoTypeError),
}
pub(crate) enum Instruction<VII: ValidatorIdentityIdentity> {
    NewKey {
        crypto_type: CryptoType,
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_oneshot: oneshot::Sender<Result<PkId, SessionManagerError>>,
    },
    Sign {
        pkid: PkId,
        msg: Vec<u8>,
        signature_response_oneshot:
            oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionManagerError>>,
    },
    ListPkIds {
        list_pkids_response_oneshot: oneshot::Sender<HashMap<CryptoType, Vec<PkId>>>,
    },
}
macro_rules! new_session_wrap {
    ($generic_type:ty, $crypto_variant:ident, $dkg_session_sender:expr, $signing_session_sender:expr, $session_inst_channels:expr) => {{
        let (instruction_sender_cipher, instruction_receiver_cipher) =
            tokio::sync::mpsc::unbounded_channel();

        let session_wrap = SessionWrap::<VII, $generic_type>::new(
            $dkg_session_sender.clone(),
            $signing_session_sender.clone(),
            instruction_receiver_cipher,
        );

        $session_inst_channels.insert(CryptoType::$crypto_variant, instruction_sender_cipher);

        session_wrap.listening();
    }};
}
pub(crate) struct CoordiantorSessionManager<VII: ValidatorIdentityIdentity> {
    session_inst_channels: HashMap<CryptoType, UnboundedSender<InstructionCipher<VII>>>,
    instructions_receiver: UnboundedReceiver<Instruction<VII>>,
}
impl<VII: ValidatorIdentityIdentity> CoordiantorSessionManager<VII> {
    pub(crate) fn new(
        instructions_receiver: UnboundedReceiver<Instruction<VII>>,
        dkg_session_sender: UnboundedSender<(
            DKGRequestWrap<VII>,
            oneshot::Sender<DKGResponseWrap<VII>>,
        )>,
        signing_session_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Self {
        let mut session_inst_channels = HashMap::new();
        new_session_wrap!(
            Ed25519Sha512,
            Ed25519,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels
        );
        new_session_wrap!(
            Secp256K1Sha256,
            Secp256k1,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels
        );
        new_session_wrap!(
            Secp256K1Sha256TR,
            Secp256k1Tr,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels
        );

        assert!(session_inst_channels.len() == CryptoType::iter().len());
        Self {
            session_inst_channels,
            instructions_receiver,
        }
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                let instruction = self.instructions_receiver.recv().await;
                if let Some(instruction) = instruction {
                    match instruction {
                        Instruction::NewKey {
                            crypto_type,
                            participants,
                            min_signers,
                            pkid_response_oneshot,
                        } => {
                            let session_inst_channel =
                                self.session_inst_channels.get(&crypto_type).unwrap();
                            session_inst_channel
                                .send(InstructionCipher::NewKey {
                                    participants,
                                    min_signers,
                                    pkid_response_oneshot,
                                })
                                .unwrap();
                        }
                        Instruction::Sign {
                            pkid,
                            msg,
                            signature_response_oneshot,
                        } => {
                            let crypto_type = pkid.to_crypto_type();
                            if let Err(e) = crypto_type {
                                tracing::error!("Error getting crypto type: {:?}", e);
                                signature_response_oneshot
                                    .send(Err(SessionManagerError::CryptoTypeError(e)))
                                    .unwrap();
                                continue;
                            }
                            let crypto_type = crypto_type.unwrap();
                            let session_inst_channel = self.session_inst_channels.get(&crypto_type);
                            match session_inst_channel {
                                Some(session_inst_channel) => {
                                    session_inst_channel
                                        .send(InstructionCipher::Sign {
                                            pkid: pkid.clone(),
                                            msg: msg.clone(),
                                            signature_response_oneshot,
                                        })
                                        .unwrap();
                                }
                                None => {
                                    tracing::error!(
                                        "Session not found for crypto type: {:?}",
                                        crypto_type
                                    );
                                    signature_response_oneshot
                                        .send(Err(SessionManagerError::SessionError(format!(
                                            "crypto type not found: {:?}",
                                            crypto_type
                                        ))))
                                        .unwrap();
                                }
                            }
                        }
                        Instruction::ListPkIds {
                            list_pkids_response_oneshot,
                        } => {
                            let mut pkids = HashMap::new();
                            for (crypto_type, inst_chan) in self.session_inst_channels.iter() {
                                let (tx, rx) = oneshot::channel();
                                inst_chan
                                    .send(InstructionCipher::ListPkIds {
                                        list_pkids_response_oneshot: tx,
                                    })
                                    .unwrap();
                                let result = rx.await.unwrap();
                                pkids.insert(crypto_type.clone(), result);
                            }
                            if let Err(e) = list_pkids_response_oneshot.send(pkids) {
                                tracing::error!("Error sending pkids response: {:?}", e);
                            }
                        }
                    }
                }
            }
        });
    }
}
