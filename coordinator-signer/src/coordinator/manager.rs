use std::collections::{BTreeMap, HashMap};

use strum::IntoEnumIterator;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::types::{
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
    #[error("crypto type not supported: {0}")]
    CryptoTypeNotSupported(String),
}
pub(crate) enum Instruction<VII: ValidatorIdentityIdentity> {
    NewKey {
        crypto_type: CryptoType,
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_onshot: oneshot::Sender<Result<PkId, SessionManagerError>>,
    },
    Sign {
        pkid: PkId,
        msg: Vec<u8>,
        signature_response_onshot:
            oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionManagerError>>,
    },
    ListPkIds {
        list_pkids_response_onshot: oneshot::Sender<HashMap<CryptoType, Vec<PkId>>>,
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
            'outer: loop {
                let instruction = self.instructions_receiver.recv().await;
                if let Some(instruction) = instruction {
                    match instruction {
                        Instruction::NewKey {
                            crypto_type,
                            participants,
                            min_signers,
                            pkid_response_onshot,
                        } => {
                            let session_inst_channel =
                                self.session_inst_channels.get(&crypto_type).unwrap();
                            let (tx, rx) = oneshot::channel();
                            session_inst_channel
                                .send(InstructionCipher::IsCryptoType {
                                    crypto_type,
                                    response_onshot: tx,
                                })
                                .unwrap();
                            let result = rx.await.unwrap();
                            if !result {
                                pkid_response_onshot
                                    .send(Err(SessionManagerError::CryptoTypeNotSupported(
                                        format!("{:?}", crypto_type),
                                    )))
                                    .unwrap();
                                continue;
                            }
                            session_inst_channel
                                .send(InstructionCipher::NewKey {
                                    participants,
                                    min_signers,
                                    pkid_response_onshot,
                                })
                                .unwrap();
                        }
                        Instruction::Sign {
                            pkid,
                            msg,
                            signature_response_onshot,
                        } => {
                            let mut found = None;
                            for (_, inst_chan) in self.session_inst_channels.iter_mut() {
                                let (tx, rx) = oneshot::channel();
                                inst_chan
                                    .send(InstructionCipher::PkIdExists {
                                        pkid: pkid.clone(),
                                        response_onshot: tx,
                                    })
                                    .unwrap();
                                let result = rx.await.unwrap();
                                if result && found.is_none() {
                                    found = Some(inst_chan);
                                }
                                if result && found.is_some() {
                                    signature_response_onshot
                                        .send(Err(SessionManagerError::SessionError(format!(
                                            "PKID exists in multiple sessions: {:?}",
                                            pkid
                                        ))))
                                        .unwrap();
                                    continue 'outer;
                                }
                            }
                            if found.is_none() {
                                signature_response_onshot
                                    .send(Err(SessionManagerError::SessionError(format!(
                                        "PKID not found: {:?}",
                                        pkid
                                    ))))
                                    .unwrap();
                                continue 'outer;
                            }
                            let inst_chan = found.unwrap();
                            inst_chan
                                .send(InstructionCipher::Sign {
                                    pkid: pkid.clone(),
                                    msg: msg.clone(),
                                    signature_response_onshot,
                                })
                                .unwrap();
                        }
                        Instruction::ListPkIds {
                            list_pkids_response_onshot,
                        } => {
                            let mut pkids = HashMap::new();
                            for (crypto_type, inst_chan) in self.session_inst_channels.iter() {
                                let (tx, rx) = oneshot::channel();
                                inst_chan
                                    .send(InstructionCipher::ListPkIds {
                                        list_pkids_response_onshot: tx,
                                    })
                                    .unwrap();
                                let result = rx.await.unwrap();
                                pkids.insert(crypto_type.clone(), result);
                            }
                            if let Err(e) = list_pkids_response_onshot.send(pkids) {
                                tracing::error!("Error sending pkids response: {:?}", e);
                            }
                        }
                    }
                }
            }
        });
    }
}
