mod dkg;
mod signing;
use super::manager::InstructionCipher;
use super::{Cipher, PkId, PublicKeyPackage, ValidatorIdentityIdentity};
use crate::crypto::{Identifier, Tweak, VerifyingKey};
use crate::keystore::KeystoreManagement;
use crate::types::{
    error::SessionError,
    message::{DKGRequestWrap, DKGResponseWrap, SigningRequestWrap, SigningResponseWrap},
    Participants, SessionId, SignatureSuite,
};
use crate::types::{GroupPublicKeyInfo, SignatureSuiteInfo, SubsessionId};
use common::Settings;
use dkg::{CoordinatorDKGSession as DkgSession, DKGInfo};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use signing::CoordinatorSigningSession as SigningSession;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
pub(crate) struct SessionWrap<VII: ValidatorIdentityIdentity, C: Cipher> {
    signing_sessions: HashMap<PkId, SigningSession<VII, C>>,

    dkg_session_sender:
        UnboundedSender<(DKGRequestWrap<VII>, oneshot::Sender<DKGResponseWrap<VII>>)>,
    signing_session_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,

    session_id_key_map: HashMap<SessionId, oneshot::Sender<Result<PkId, SessionError>>>,
    subsession_id_signaturesuite_map:
        HashMap<SubsessionId, oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionError>>>,

    dkg_futures:
        FuturesUnordered<oneshot::Receiver<Result<DKGInfo<VII, C>, (SessionId, SessionError)>>>,
    signing_futures: FuturesUnordered<
        oneshot::Receiver<Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError)>>,
    >,

    instruction_receiver: UnboundedReceiver<InstructionCipher<VII>>,
    keystore_management: KeystoreManagement,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SessionWrap<VII, C> {
    pub(crate) fn new(
        dkg_session_sender: UnboundedSender<(
            DKGRequestWrap<VII>,
            oneshot::Sender<DKGResponseWrap<VII>>,
        )>,
        signing_session_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
        instruction_receiver: UnboundedReceiver<InstructionCipher<VII>>,
        keystore: Arc<crate::keystore::Keystore>,
        base_path: &PathBuf,
    ) -> Result<Self, SessionError> {
        let path = base_path
            .join(Settings::global().coordinator.keystore_path)
            .join(C::crypto_type().to_string());
        let (keystore_management, data) =
            crate::keystore::KeystoreManagement::new(keystore, path).unwrap();
        let signing_sessions = match data {
            Some(data) => {
                Self::deserialize_sessions(data.as_slice(), signing_session_sender.clone())?
            }
            None => HashMap::new(),
        };
        for (pkid, _) in signing_sessions.iter() {
            tracing::info!("Coordinator restored pkid: {} from local keystore", pkid);
        }
        Ok(Self {
            signing_sessions,
            dkg_session_sender,
            signing_session_sender,
            session_id_key_map: HashMap::new(),
            dkg_futures: FuturesUnordered::new(),
            instruction_receiver,
            signing_futures: FuturesUnordered::new(),
            subsession_id_signaturesuite_map: HashMap::new(),
            keystore_management,
        })
    }
    pub(crate) fn check_serialize_deserialize(&self) -> Result<(), SessionError> {
        let serialized = self.serialize_sessions()?;
        let deserialized =
            Self::deserialize_sessions(serialized.as_slice(), self.signing_session_sender.clone())?;
        assert_eq!(self.signing_sessions.len(), deserialized.len());
        for (pkid, session) in self.signing_sessions.iter() {
            assert_eq!(session.pkid, deserialized.get(&pkid).unwrap().pkid);
            assert_eq!(
                session.min_signers,
                deserialized.get(&pkid).unwrap().min_signers
            );
            assert_eq!(
                session.participants,
                deserialized.get(&pkid).unwrap().participants
            );
            assert_eq!(
                session.public_key_package,
                deserialized.get(&pkid).unwrap().public_key_package
            );
            assert_eq!(pkid, &deserialized.get(&pkid).unwrap().pkid);
        }
        Ok(())
    }
    fn deserialize_sessions(
        bytes: &[u8],
        signing_session_sender: UnboundedSender<(
            SigningRequestWrap<VII>,
            oneshot::Sender<SigningResponseWrap<VII>>,
        )>,
    ) -> Result<HashMap<PkId, SigningSession<VII, C>>, SessionError> {
        let sessions: HashMap<PkId, Vec<u8>> = bincode::deserialize(bytes)
            .map_err(|e| SessionError::CoordinatorSessionError(e.to_string()))?;
        let mut signing_sessions = HashMap::new();
        for (pkid, data) in sessions {
            let session = SigningSession::deserialize(&data, signing_session_sender.clone())?;
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
    async fn new_key<IT>(
        &mut self,
        participants: Vec<(IT, VII)>,
        min_signers: u16,
        identifier_transform: impl Fn(IT) -> Result<C::Identifier, C::CryptoError> + 'static,
    ) -> Result<SessionId, SessionError> {
        //TODO: remove the following participants judgement
        let participants = participants
            .into_iter()
            .map(|(id, validator)| {
                let id = (identifier_transform)(id)?;
                Ok((id, validator))
            })
            .collect::<Result<Vec<(C::Identifier, VII)>, C::CryptoError>>()
            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
        let participants = Participants::new(participants)?;
        participants.check_min_signers(min_signers)?;
        let session = DkgSession::<VII, C>::new(
            participants.clone(),
            min_signers,
            self.dkg_session_sender.clone(),
        )?;
        let session_id = session.session_id().clone();
        let (tx, rx) = oneshot::channel();
        self.dkg_futures.push(rx);
        session.start_dkg(tx).await;
        return Ok(session_id);
    }
    async fn sign<T: AsRef<[u8]>>(
        &mut self,
        pkid_raw: T,
        msg: T,
        tweak_data: Option<T>,
        signature_response_oneshot: oneshot::Sender<Result<SignatureSuiteInfo<VII>, SessionError>>,
    ) {
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
                if let Err(e) = signature_response_oneshot.send(Err(e)) {
                    tracing::error!("Error sending signature response: {:?}", e);
                }
                return;
            }
        };
        let (tx, rx) = oneshot::channel();
        self.signing_futures.push(rx);
        signing_session
            .start_new_signing(msg, tweak_data, tx, |subsession_id| {
                self.subsession_id_signaturesuite_map
                    .insert(subsession_id, signature_response_oneshot);
            })
            .await;
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
                let session_id = self
                    .new_key(participants, min_signers, |id| C::Identifier::from_u16(id))
                    .await;
                match session_id {
                    Ok(session_id) => {
                        self.session_id_key_map
                            .insert(session_id, pkid_response_oneshot);
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
                self.sign(pkid.to_bytes(), msg, tweak_data, signature_response_oneshot)
                    .await;
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
                    ))
                    .and_then(|session| {
                        let group_public_key_tweak = session
                            .public_key_package
                            .clone()
                            .tweak(tweak_data.clone())
                            .verifying_key()
                            .serialize_frost()
                            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
                        Ok(GroupPublicKeyInfo::new(group_public_key_tweak, tweak_data))
                    });
                if let Err(e) = pk_response_oneshot.send(r) {
                    tracing::error!("Error sending pk response: {:?}", e);
                }
            }
        }
    }
    async fn handle_dkg_future(
        &mut self,
        dkg_info: Result<DKGInfo<VII, C>, (SessionId, SessionError)>,
    ) -> Result<(), SessionError> {
        match dkg_info {
            Ok(dkg_info) => {
                self.signing_sessions.insert(
                    dkg_info
                        .public_key_package
                        .pkid()
                        .map_err(|e| SessionError::CryptoError(e.to_string()))?,
                    SigningSession::new(
                        dkg_info.public_key_package.clone(),
                        dkg_info.min_signers,
                        dkg_info.participants.clone(),
                        self.signing_session_sender.clone(),
                    )?,
                );
                let sessions = self.serialize_sessions()?;
                self.keystore_management.write(sessions.as_slice())?;
                let oneshot = self.session_id_key_map.remove(&dkg_info.session_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(
                        dkg_info
                            .public_key_package
                            .pkid()
                            .map_err(|e| SessionError::CryptoError(e.to_string())),
                    ) {
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
        signing_session: Result<SignatureSuite<VII, C>, (Option<SubsessionId>, SessionError)>,
    ) -> Result<(), SessionError> {
        match signing_session {
            Ok(signature_suite) => {
                let subsession_id = signature_suite.subsession_id;
                let oneshot = self.subsession_id_signaturesuite_map.remove(&subsession_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(
                        signature_suite
                            .to_signature_info()
                            .map_err(|e| SessionError::SignatureSuiteError(e.to_string())),
                    ) {
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
            Err((Some(subsession_id), e)) => {
                tracing::error!("Error in signing future: {:?}", e);
                let oneshot = self.subsession_id_signaturesuite_map.remove(&subsession_id);
                if let Some(oneshot) = oneshot {
                    if let Err(e) = oneshot.send(Err(e)) {
                        tracing::error!("Error sending signature response: {:?}", e);
                        return Err(SessionError::SendOneshotError(format!(
                            "Error sending signature response: {:?}",
                            e
                        )));
                    }
                }
            }
            Err((None, e)) => {
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
