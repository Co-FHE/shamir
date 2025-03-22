use std::{collections::HashMap, path::PathBuf, sync::Arc};

use strum::EnumCount;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{
    coordinator::session_ex::SessionWrapEx,
    keystore::Keystore,
    types::{
        error::SessionError,
        message::{
            DKGRequestWrap, DKGRequestWrapEx, DKGResponseWrap, DKGResponseWrapEx,
            SigningRequestWrap, SigningRequestWrapEx, SigningResponseWrap, SigningResponseWrapEx,
        },
        GroupPublicKeyInfo, SignatureSuiteInfo,
    },
};

use crate::crypto::*;

use super::SessionWrap;

#[derive(Debug)]
pub(crate) enum InstructionCipher<VII: ValidatorIdentityIdentity> {
    NewKey {
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_oneshot: oneshot::Sender<Result<PkId, SessionError>>,
    },
    Sign {
        pkid: PkId,
        msg: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
        signature_response_oneshot: oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionError>>,
    },
    ListPkIds {
        list_pkids_response_oneshot: oneshot::Sender<Vec<PkId>>,
    },
    PkTweakRequest {
        pkid: PkId,
        tweak_data: Option<Vec<u8>>,
        pk_response_oneshot: oneshot::Sender<Result<GroupPublicKeyInfo, SessionError>>,
    },
}
#[derive(Clone, Debug)]
pub(crate) enum CoordinatorStateEx<F> {
    Init,
    Final(F),
}

#[derive(Debug)]
pub(crate) enum Instruction<VII: ValidatorIdentityIdentity> {
    NewKey {
        crypto_type: CryptoType,
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_oneshot: oneshot::Sender<Result<PkId, SessionError>>,
    },
    Sign {
        pkid: PkId,
        msg: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
        signature_response_oneshot: oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionError>>,
    },
    ListPkIds {
        list_pkids_response_oneshot: oneshot::Sender<HashMap<CryptoType, Vec<PkId>>>,
    },
    PkTweakRequest {
        pkid: PkId,
        tweak_data: Option<Vec<u8>>,
        pk_response_oneshot: oneshot::Sender<Result<GroupPublicKeyInfo, SessionError>>,
    },
}
macro_rules! new_session_wrap {
    ($generic_type:ty, $crypto_variant:ident, $dkg_session_sender:expr, $signing_session_sender:expr, $session_inst_channels:expr, $keystore:expr, $base_path:expr) => {{
        let (instruction_sender_cipher, instruction_receiver_cipher) =
            tokio::sync::mpsc::unbounded_channel();

        let session_wrap = SessionWrap::<VII, $generic_type>::new(
            $dkg_session_sender.clone(),
            $signing_session_sender.clone(),
            instruction_receiver_cipher,
            $keystore.clone(),
            $base_path,
        )?;
        assert!(session_wrap.check_serialize_deserialize().is_ok());

        $session_inst_channels.insert(CryptoType::$crypto_variant, instruction_sender_cipher);
        session_wrap.listening();
    }};
}
pub(crate) struct CoordiantorSessionManager<VII: ValidatorIdentityIdentity> {
    session_inst_channels: HashMap<CryptoType, UnboundedSender<InstructionCipher<VII>>>,
    instructions_receiver: UnboundedReceiver<Instruction<VII>>,

    signing_in_final_channel_receiver: UnboundedReceiver<(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<SigningResponseWrapEx>,
    )>,
    dkg_in_final_channel_receiver:
        UnboundedReceiver<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,

    dkg_in_final_channel_mapping: HashMap<
        CryptoType,
        UnboundedSender<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
    >,
    signing_in_final_channel_mapping: HashMap<
        CryptoType,
        UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    >,
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
        dkg_session_sender_ex: UnboundedSender<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
        signing_session_sender_ex: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
        dkg_in_final_channel_receiver_wrap: UnboundedReceiver<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
        signing_in_final_channel_receiver_wrap: UnboundedReceiver<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,

        keystore: Arc<Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let mut session_inst_channels = HashMap::new();
        let mut dkg_in_final_channel_mapping = HashMap::new();
        let mut signing_in_final_channel_mapping = HashMap::new();
        new_session_wrap!(
            Ed25519Sha512,
            Ed25519,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        new_session_wrap!(
            Secp256K1Sha256,
            Secp256k1,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        new_session_wrap!(
            Secp256K1Sha256TR,
            Secp256k1Tr,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        new_session_wrap!(
            Ed448Shake256,
            Ed448,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        new_session_wrap!(
            Ristretto255Sha512,
            Ristretto255,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        new_session_wrap!(
            P256Sha256,
            P256,
            dkg_session_sender,
            signing_session_sender,
            session_inst_channels,
            keystore,
            base_path
        );
        let (instruction_sender_cipher, instruction_receiver_cipher) =
            tokio::sync::mpsc::unbounded_channel();
        let (dkg_in_final_channel_sender, dkg_in_final_channel_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let (signing_in_final_channel_sender, signing_in_final_channel_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        dkg_in_final_channel_mapping
            .insert(CryptoType::EcdsaSecp256k1, dkg_in_final_channel_sender);
        signing_in_final_channel_mapping
            .insert(CryptoType::EcdsaSecp256k1, signing_in_final_channel_sender);
        let session_wrap = SessionWrapEx::<VII>::new(
            CryptoType::EcdsaSecp256k1,
            dkg_session_sender_ex,
            signing_session_sender_ex,
            dkg_in_final_channel_receiver,
            signing_in_final_channel_receiver,
            instruction_receiver_cipher,
            keystore.clone(),
            base_path,
        )?;
        assert!(session_wrap.check_serialize_deserialize().is_ok());

        session_inst_channels.insert(CryptoType::EcdsaSecp256k1, instruction_sender_cipher);
        session_wrap.listening();
        assert!(session_inst_channels.len() == CryptoType::COUNT);
        Ok(Self {
            session_inst_channels,
            instructions_receiver,
            signing_in_final_channel_mapping: dkg_in_final_channel_mapping,
            dkg_in_final_channel_mapping: signing_in_final_channel_mapping,
            signing_in_final_channel_receiver: signing_in_final_channel_receiver_wrap,
            dkg_in_final_channel_receiver: dkg_in_final_channel_receiver_wrap,
        })
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                if let Some((dkg_request, response_sender)) =
                    self.dkg_in_final_channel_receiver.recv().await
                {
                    let crypto_type = dkg_request.crypto_type();
                    self.dkg_in_final_channel_mapping
                        .get_mut(&crypto_type)
                        .unwrap()
                        .send((dkg_request, response_sender))
                        .unwrap();
                }
                if let Some((signing_request, response_sender)) =
                    self.signing_in_final_channel_receiver.recv().await
                {
                    let crypto_type = signing_request.crypto_type();
                    self.signing_in_final_channel_mapping
                        .get_mut(&crypto_type)
                        .unwrap()
                        .send((signing_request, response_sender))
                        .unwrap();
                }
            }
        });
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
                            tweak_data,
                            signature_response_oneshot,
                        } => {
                            let crypto_type = pkid.crypto_type();
                            if let Err(e) = crypto_type {
                                tracing::error!("Error getting crypto type: {:?}", e);
                                signature_response_oneshot
                                    .send(Err(SessionError::CryptoTypeErrorNative(e)))
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
                                            tweak_data,
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
                                        .send(Err(SessionError::CryptoTypeError(crypto_type)))
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
                        Instruction::PkTweakRequest {
                            pkid,
                            tweak_data,
                            pk_response_oneshot,
                        } => {
                            let crypto_type = pkid.crypto_type();
                            if let Err(e) = crypto_type {
                                tracing::error!("Error getting crypto type: {:?}", e);
                                if let Err(e) = pk_response_oneshot
                                    .send(Err(SessionError::CryptoTypeErrorNative(e)))
                                {
                                    tracing::error!("Error sending pk response: {:?}", e);
                                }
                                continue;
                            }
                            let crypto_type = crypto_type.unwrap();
                            let session_inst_channel = self.session_inst_channels.get(&crypto_type);
                            match session_inst_channel {
                                Some(session_inst_channel) => {
                                    session_inst_channel
                                        .send(InstructionCipher::PkTweakRequest {
                                            pkid: pkid.clone(),
                                            tweak_data,
                                            pk_response_oneshot,
                                        })
                                        .unwrap();
                                }
                                None => {
                                    tracing::error!(
                                        "Session not found for crypto type: {:?}",
                                        crypto_type
                                    );
                                    if let Err(e) = pk_response_oneshot
                                        .send(Err(SessionError::CryptoTypeError(crypto_type)))
                                    {
                                        tracing::error!("Error sending pk response: {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}
