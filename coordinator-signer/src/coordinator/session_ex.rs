mod combinations;
mod dkg_ex;
mod signing_ex;
use super::manager::InstructionCipher;
use super::{PkId, ValidatorIdentityIdentity};
use crate::crypto::{pk_to_pkid, CryptoType};
use crate::keystore::KeystoreManagement;
use crate::types::message::{
    DKGRequestWrapEx, DKGResponseWrapEx, SigningRequestWrapEx, SigningResponseWrapEx,
};
use crate::types::{error::SessionError, Participants, SessionId};
use crate::types::{GroupPublicKeyInfo, SignatureSuiteInfo, SubsessionId};
use crate::utils;
use combinations::Combinations;
use common::Settings;
use dkg_ex::{CoordinatorDKGSessionEx, DKGInfo};
use ecdsa_tss::signer_rpc::CheckPkRequest;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use signing_ex::CoordinatorSigningSessionEx;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};

pub(crate) struct SessionWrapEx<VII: ValidatorIdentityIdentity> {
    crypto_type: CryptoType,
    signing_sessions: HashMap<PkId, CoordinatorSigningSessionEx<VII>>,

    out_init_dkg_sender:
        UnboundedSender<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
    out_init_signing_sender: UnboundedSender<(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<SigningResponseWrapEx>,
    )>,

    session_id_key_map: HashMap<SessionId, oneshot::Sender<Result<PkId, SessionError>>>,
    subsession_id_signaturesuite_map:
        HashMap<SubsessionId, oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionError>>>,

    dkg_futures:
        FuturesUnordered<oneshot::Receiver<Result<DKGInfo<VII>, (SessionId, SessionError)>>>,
    signing_futures: FuturesUnordered<
        oneshot::Receiver<
            Result<
                SignatureSuiteInfo<VII>,
                (
                    Option<SubsessionId>,
                    // pkid, msg, tweak_data, combinations
                    (PkId, Vec<u8>, Option<Vec<u8>>, Combinations),
                    SessionError,
                ),
            >,
        >,
    >,
    dkg_in_final_channel_receiver:
        UnboundedReceiver<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
    signing_in_final_channel_receiver: UnboundedReceiver<(
        SigningRequestWrapEx<VII>,
        oneshot::Sender<SigningResponseWrapEx>,
    )>,

    dkg_in_final_channel_mapping: HashMap<
        SessionId,
        UnboundedSender<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
    >,
    signing_in_final_channel_mapping: HashMap<
        SubsessionId,
        UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    >,
    combinations_cache: Option<Combinations>,

    instruction_receiver: UnboundedReceiver<InstructionCipher<VII>>,
    keystore_management: KeystoreManagement,
}
impl<VII: ValidatorIdentityIdentity> SessionWrapEx<VII> {
    pub(crate) fn new(
        crypto_type: CryptoType,
        out_init_dkg_sender: UnboundedSender<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
        out_init_signing_sender: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
        signing_in_final_channel_receiver: UnboundedReceiver<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
        dkg_in_final_channel_receiver: UnboundedReceiver<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
        instruction_receiver: UnboundedReceiver<InstructionCipher<VII>>,
        keystore: Arc<crate::keystore::Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let path = base_path
            .join(Settings::global().coordinator.keystore_path)
            .join(crypto_type.to_string());
        let (keystore_management, data) =
            crate::keystore::KeystoreManagement::new(keystore, path).unwrap();
        let signing_sessions = match data {
            Some(data) => {
                Self::deserialize_sessions(data.as_slice(), out_init_signing_sender.clone())?
            }
            None => HashMap::new(),
        };
        for (pkid, _) in signing_sessions.iter() {
            tracing::info!("Coordinator restored pkid: {} from local keystore", pkid);
        }
        Ok(Self {
            crypto_type,
            signing_sessions,
            out_init_dkg_sender,
            out_init_signing_sender,
            session_id_key_map: HashMap::new(),
            dkg_futures: FuturesUnordered::new(),
            instruction_receiver,
            combinations_cache: None,
            signing_futures: FuturesUnordered::new(),
            subsession_id_signaturesuite_map: HashMap::new(),
            dkg_in_final_channel_mapping: HashMap::new(),
            signing_in_final_channel_mapping: HashMap::new(),
            dkg_in_final_channel_receiver,
            signing_in_final_channel_receiver,
            keystore_management,
        })
    }
    pub(crate) fn check_serialize_deserialize(&self) -> Result<(), SessionError> {
        let serialized = self.serialize_sessions()?;
        let deserialized = Self::deserialize_sessions(
            serialized.as_slice(),
            self.out_init_signing_sender.clone(),
        )?;
        assert_eq!(self.signing_sessions.len(), deserialized.len());
        for (pkid, session) in self.signing_sessions.iter() {
            assert_eq!(
                session.base_info,
                deserialized.get(&pkid).unwrap().base_info
            );
            assert_eq!(pkid, &deserialized.get(&pkid).unwrap().base_info.pkid);
        }
        Ok(())
    }
    fn deserialize_sessions(
        bytes: &[u8],
        signing_session_sender: UnboundedSender<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
    ) -> Result<HashMap<PkId, CoordinatorSigningSessionEx<VII>>, SessionError> {
        let sessions: HashMap<PkId, Vec<u8>> = bincode::deserialize(bytes)
            .map_err(|e| SessionError::CoordinatorSessionError(e.to_string()))?;
        let mut signing_sessions = HashMap::new();
        for (pkid, data) in sessions {
            let session =
                CoordinatorSigningSessionEx::deserialize(&data, signing_session_sender.clone())?;
            signing_sessions.insert(pkid, session);
        }
        Ok(signing_sessions)
    }
    fn serialize_sessions(&self) -> Result<Vec<u8>, SessionError> {
        let sessions = self
            .signing_sessions
            .iter()
            .map(|(pkid, session)| match session.serialize() {
                Ok(data) => Ok((pkid.clone(), data)),
                Err(e) => Err(e),
            })
            .collect::<Result<HashMap<PkId, Vec<u8>>, SessionError>>()?;
        Ok(bincode::serialize(&sessions).unwrap())
    }
    async fn new_key(
        &mut self,
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        in_final_rx: UnboundedReceiver<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
    ) -> Result<SessionId, SessionError> {
        //TODO: remove the following participants judgement
        let participants = participants
            .into_iter()
            .map(|(id, validator)| Ok((id, validator)))
            .collect::<Result<Vec<(u16, VII)>, SessionError>>()
            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
        let participants = Participants::new(participants)?;
        participants.check_min_signers(min_signers)?;
        let session = CoordinatorDKGSessionEx::<VII>::new(
            self.crypto_type,
            participants.clone(),
            min_signers,
            self.out_init_dkg_sender.clone(),
        )?;
        let session_id = session.session_id().clone();
        let (tx, rx) = oneshot::channel();
        self.dkg_futures.push(rx);
        session.start_dkg(in_final_rx, tx).await;
        return Ok(session_id);
    }
    async fn sign<T: AsRef<[u8]>>(
        &mut self,
        pkid_raw: T,
        msg: T,
        tweak_data: Option<T>,
        in_final_rx: UnboundedReceiver<(
            SigningRequestWrapEx<VII>,
            oneshot::Sender<SigningResponseWrapEx>,
        )>,
        mut combinations: Combinations,
    ) -> Result<SubsessionId, SessionError> {
        if msg.as_ref().len() != 32 {
            return Err(SessionError::SignerSessionError(
                "Message length must be 32".to_string(),
            ));
        }
        let pkid = PkId::new(pkid_raw.as_ref().to_vec());
        let signing_session =
            self.signing_sessions
                .get_mut(&pkid)
                .ok_or(SessionError::SignerSessionError(
                    "Signing session not found".to_string(),
                ));
        let signing_session = match signing_session {
            Ok(signing_session) => signing_session,
            Err(e) => {
                return Err(e);
            }
        };
        let participants_candidates: Vec<u16> = combinations
            .pop()
            .ok_or(SessionError::SignerSessionError(
                "No participants candidates".to_string(),
            ))?
            .iter()
            .map(|id| *id)
            .collect::<Vec<_>>();
        let (tx, rx) = oneshot::channel();
        self.signing_futures.push(rx);
        return signing_session
            .start_new_signing(
                msg,
                tweak_data,
                tx,
                participants_candidates,
                combinations,
                in_final_rx,
            )
            .await;
    }
    pub(crate) fn handle_dkg_final_channel_request(
        &mut self,
        dkg_request: DKGRequestWrapEx<VII>,
        response_sender: oneshot::Sender<DKGResponseWrapEx>,
    ) -> Result<(), SessionError> {
        tracing::debug!(
            "Coordinator received dkg final channel request: {:?}",
            dkg_request
        );
        let session_id = dkg_request.dkg_request_ex()?.base_info.session_id;
        let sender = self.dkg_in_final_channel_mapping.get_mut(&session_id);
        if let Some(sender) = sender {
            sender
                .send((dkg_request, response_sender))
                .map_err(|e| SessionError::SendOneshotError(e.to_string()))?;
        } else {
            tracing::error!("Coordinator dkg session not found: {:?}", session_id);
            return Err(SessionError::SignerSessionError(
                "Coordinator dkg session not found".to_string(),
            ));
        }
        Ok(())
    }
    pub(crate) fn handle_signing_final_channel_request(
        &mut self,
        signing_request: SigningRequestWrapEx<VII>,
        response_sender: oneshot::Sender<SigningResponseWrapEx>,
    ) -> Result<(), SessionError> {
        let subsession_id = signing_request
            .signing_request_ex()?
            .base_info
            .subsession_id;
        let sender = self
            .signing_in_final_channel_mapping
            .get_mut(&subsession_id);
        if let Some(sender) = sender {
            sender
                .send((signing_request, response_sender))
                .map_err(|e| SessionError::SendOneshotError(e.to_string()))?;
        } else {
            tracing::error!("Coordinator signing session not found: {:?}", subsession_id);
            return Err(SessionError::SignerSessionError(
                "Coordinator signing session not found".to_string(),
            ));
        }
        Ok(())
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(instruction) = self.instruction_receiver.recv() => {
                        self.handle_instruction(instruction).await;
                    }
                     Some(Result::Ok(dkg_info))= self.dkg_futures.next() => {
                        let r = self.handle_dkg_future(dkg_info).await;
                        if let Err(e) = r {
                            tracing::error!("Error in DKG future: {:?}", e);
                        }
                    }
                    Some(Result::Ok(signing_session)) = self.signing_futures.next() => {
                        let r = self.handle_signing_future(signing_session).await;
                        if let Err(e) = r {
                            tracing::error!("Error in signing future: {:?}", e);
                        }
                    }
                    Some((dkg_request, response_sender)) = self.dkg_in_final_channel_receiver.recv() => {
                        let r = self.handle_dkg_final_channel_request(dkg_request, response_sender);
                        if let Err(e) = r {
                            tracing::error!("Error in DKG request: {:?}", e);
                        }
                    }
                    Some((signing_request, response_sender)) = self.signing_in_final_channel_receiver.recv() => {
                        let r = self.handle_signing_final_channel_request(signing_request, response_sender);
                        if let Err(e) = r {
                            tracing::error!("Error in signing request: {:?}", e);
                        }
                    }
                }
            }
        });
    }
    async fn handle_instruction(&mut self, instruction: InstructionCipher<VII>) {
        tracing::debug!("Coordinator received instruction: {:?}", instruction);
        match instruction {
            InstructionCipher::NewKey {
                participants,
                min_signers,
                pkid_response_oneshot,
            } => {
                let (in_final_tx, in_final_rx) = tokio::sync::mpsc::unbounded_channel();
                let session_id = self.new_key(participants, min_signers, in_final_rx).await;
                match session_id {
                    Ok(session_id) => {
                        self.session_id_key_map
                            .insert(session_id, pkid_response_oneshot);
                        self.dkg_in_final_channel_mapping
                            .insert(session_id, in_final_tx);
                    }
                    Err(e) => {
                        if let Err(e) = pkid_response_oneshot.send(Err(e)) {
                            tracing::error!("Error sending pkid response: {:?}", e);
                        }
                    }
                }
            }
            InstructionCipher::Sign {
                pkid,
                msg,
                tweak_data,
                signature_response_oneshot,
            } => {
                let (in_final_tx, in_final_rx) = tokio::sync::mpsc::unbounded_channel();
                let sessions = self.signing_sessions.get(&pkid);
                let combinations = match sessions {
                    Some(sessions) => Combinations::new(
                        sessions.base_info.participants.keys().cloned().collect(),
                        sessions.base_info.min_signers,
                        &self.combinations_cache,
                    ),
                    None => {
                        signature_response_oneshot
                            .send(Err(SessionError::SignerSessionError(format!(
                                "Signing session with pkid {} not found",
                                pkid.to_string()
                            ))))
                            .unwrap();
                        return;
                    }
                };
                let subsession_id = self
                    .sign(pkid.to_bytes(), msg, tweak_data, in_final_rx, combinations)
                    .await;
                match subsession_id {
                    Ok(subsession_id) => {
                        self.subsession_id_signaturesuite_map
                            .insert(subsession_id, signature_response_oneshot);
                        self.signing_in_final_channel_mapping
                            .insert(subsession_id, in_final_tx);
                    }
                    Err(e) => {
                        if let Err(e) = signature_response_oneshot.send(Err(e)) {
                            tracing::error!("Error sending signature response: {:?}", e);
                        }
                    }
                }
            }
            InstructionCipher::ListPkIds {
                list_pkids_response_oneshot,
            } => {
                let pkids = self.signing_sessions.keys().cloned().collect::<Vec<_>>();
                if let Err(e) = list_pkids_response_oneshot.send(pkids) {
                    tracing::error!("Error sending pkids response: {:?}", e);
                }
            }
            InstructionCipher::PkTweakRequest {
                pkid,
                tweak_data,
                pk_response_oneshot,
            } => {
                let r = self
                    .signing_sessions
                    .get(&pkid)
                    .ok_or(SessionError::SignerSessionError(
                        "Signing session not found".to_string(),
                    ));
                let response = match r {
                    Ok(session) => {
                        let client = ecdsa_tss::EcdsaTssSignerClient::new(
                            common::Settings::global().signer.ecdsa_port,
                        )
                        .await;
                        if let Ok(client) = client {
                            let curve_id = match session.base_info.crypto_type {
                                CryptoType::EcdsaSecp256k1 => 0,
                                _ => 1,
                            };
                            let r = client
                                .derive_pk_from_pk(
                                    curve_id,
                                    session.base_info.public_key_package.clone(),
                                    utils::derived_data(tweak_data.clone()),
                                )
                                .await
                                .map_err(|e| SessionError::CryptoError(e.to_string()));
                            match r {
                                Ok((pk, derived_pk)) => {
                                    let base_info = session.base_info.clone();
                                    let derived_pk_c = derived_pk.clone();
                                    let tweak_data_c = tweak_data.clone();
                                    tokio::spawn(async move {
                                        let client = ecdsa_tss::EcdsaTssSignerClient::new(
                                            common::Settings::global().signer.ecdsa_port,
                                        )
                                        .await
                                        .unwrap();
                                        // for debug/log
                                        let result = client
                                            .check_pk(CheckPkRequest {
                                                crypto_type: curve_id as u32,
                                                pkid: pkid.to_bytes(),
                                                public_key: pk,
                                                public_key_derived: derived_pk_c,
                                                delta: utils::derived_data(tweak_data_c),
                                                signer_id: base_info
                                                    .public_key_info
                                                    .iter()
                                                    .map(|(id, _)| id.clone() as u32)
                                                    .collect(),
                                                public_key_info: base_info
                                                    .public_key_info
                                                    .iter()
                                                    .map(|(_, info)| info.key_package.clone())
                                                    .collect(),
                                            })
                                            .await;
                                        tracing::info!("check_pk result: {:?}", result);
                                    });

                                    Ok(GroupPublicKeyInfo::new(derived_pk, tweak_data))
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            Err(SessionError::CryptoError(
                                "Failed to create client".to_string(),
                            ))
                        }
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = pk_response_oneshot.send(response) {
                    tracing::error!("Error sending pk response: {:?}", e);
                }
            }
        }
    }
    async fn handle_dkg_future(
        &mut self,
        dkg_info: Result<DKGInfo<VII>, (SessionId, SessionError)>,
    ) -> Result<(), SessionError> {
        tracing::debug!("Coordinator received dkg future: {:?}", dkg_info);
        match dkg_info {
            Ok(dkg_info) => {
                let pkid = pk_to_pkid(dkg_info.crypto_type, &dkg_info.public_key_package)?;
                self.signing_sessions.insert(
                    pkid,
                    CoordinatorSigningSessionEx::new(
                        dkg_info.crypto_type,
                        dkg_info.public_key_package.clone(),
                        dkg_info.min_signers,
                        dkg_info.participants.clone(),
                        dkg_info.public_key_info.clone(),
                        self.out_init_signing_sender.clone(),
                    )?,
                );
                let sessions = self.serialize_sessions()?;
                self.keystore_management.write(sessions.as_slice())?;
                let oneshot = self.session_id_key_map.remove(&dkg_info.session_id);
                self.dkg_in_final_channel_mapping
                    .remove(&dkg_info.session_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(pk_to_pkid(
                        dkg_info.crypto_type,
                        &dkg_info.public_key_package,
                    )) {
                        tracing::error!("Error sending pkid response: {:?}", e);
                        return Err(SessionError::SendOneshotError(format!(
                            "Error sending pkid response: {:?}",
                            e
                        )));
                    }
                }
            }
            Err((session_id, e)) => {
                tracing::error!("Error in DKG future: {:?}", e);
                let oneshot = self.session_id_key_map.remove(&session_id);
                self.dkg_in_final_channel_mapping.remove(&session_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(Err(e)) {
                        tracing::error!("Error sending pkid response: {:?}", e);
                        return Err(SessionError::SendOneshotError(format!(
                            "Error sending pkid response: {:?}",
                            e
                        )));
                    }
                }
            }
        }
        return Ok(());
        //TODO find in instruction and response
    }
    async fn handle_signing_future(
        &mut self,
        signing_session: Result<
            SignatureSuiteInfo<VII>,
            (
                Option<SubsessionId>,
                (PkId, Vec<u8>, Option<Vec<u8>>, Combinations),
                SessionError,
            ),
        >,
    ) -> Result<(), SessionError> {
        match signing_session {
            Ok(signature_suite) => {
                tracing::info!("signature_suite: {:?}", signature_suite);
                let session = self.signing_sessions.get(&signature_suite.pkid).unwrap();
                let data = (signature_suite.clone(), session.base_info.clone());
                tokio::spawn(async move {
                    let (signature_suite, base_info) = data;
                    let client = ecdsa_tss::EcdsaTssSignerClient::new(
                        common::Settings::global().signer.ecdsa_port,
                    )
                    .await
                    .unwrap();
                    // for debug/log
                    let result = client
                        .check_pk(CheckPkRequest {
                            crypto_type: signature_suite.crypto_type as u32,
                            pkid: signature_suite.pkid.to_bytes(),
                            public_key: signature_suite.pk,
                            public_key_derived: signature_suite.pk_tweak,
                            delta: utils::derived_data(signature_suite.tweak_data),
                            signer_id: base_info
                                .public_key_info
                                .iter()
                                .map(|(id, _)| id.clone() as u32)
                                .collect(),
                            public_key_info: base_info
                                .public_key_info
                                .iter()
                                .map(|(_, info)| info.key_package.clone())
                                .collect(),
                        })
                        .await;
                    tracing::info!("check_pk result: {:?}", result);
                });
                let subsession_id = signature_suite.subsession_id;
                let oneshot = self.subsession_id_signaturesuite_map.remove(&subsession_id);
                self.signing_in_final_channel_mapping.remove(&subsession_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(Ok(signature_suite)) {
                        tracing::error!("Error sending signature response: {:?}", e);
                        return Err(SessionError::SendOneshotError(format!(
                            "Error sending signature response: {:?}",
                            e
                        )));
                    }
                } else {
                    tracing::error!("Subsession id not found: {:?}", subsession_id);
                    return Err(SessionError::SignerSessionError(format!(
                        "Subsession id not found: {:?}",
                        subsession_id
                    )));
                }
            }
            Err((Some(subsession_id), (pkid, msg, tweak_data, combinations), e)) => {
                tracing::error!("Error in signing future: {:?}", e);
                let oneshot = self.subsession_id_signaturesuite_map.remove(&subsession_id);
                self.signing_in_final_channel_mapping.remove(&subsession_id);
                if let Some(oneshot) = oneshot {
                    if combinations.is_empty() {
                        self.combinations_cache = None;
                        if let Err(e) = oneshot.send(Err(e)) {
                            tracing::error!("Error sending signature response: {:?}", e);
                            return Err(SessionError::SendOneshotError(format!(
                                "Error sending signature response: {:?}",
                                e
                            )));
                        }
                    } else {
                        // have another try to sign
                        self.combinations_cache = Some(combinations.clone());
                        let (in_final_tx, in_final_rx) = tokio::sync::mpsc::unbounded_channel();
                        let subsession_id = self
                            .sign(pkid.to_bytes(), msg, tweak_data, in_final_rx, combinations)
                            .await;
                        match subsession_id {
                            Ok(subsession_id) => {
                                self.subsession_id_signaturesuite_map
                                    .insert(subsession_id, oneshot);
                                self.signing_in_final_channel_mapping
                                    .insert(subsession_id, in_final_tx);
                            }
                            Err(e) => {
                                if let Err(e) = oneshot.send(Err(e)) {
                                    tracing::error!("Error sending signature response: {:?}", e);
                                    return Err(SessionError::SendOneshotError(format!(
                                        "Error sending signature response: {:?}",
                                        e
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            Err((None, _, e)) => {
                tracing::error!(
                    "Error in signing future before generating subsession id: {:?}",
                    e
                );
                return Err(SessionError::SignerSessionError(format!(
                    "Error in signing future before generating subsession id: {:?}",
                    e
                )));
            }
        }
        Ok(())
    }
}
