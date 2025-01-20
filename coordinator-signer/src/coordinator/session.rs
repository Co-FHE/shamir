mod dkg;
mod signing;
use super::{
    Cipher, CryptoType, Ed25519Sha512, PkId, PublicKeyPackage, Secp256K1Sha256, Secp256K1Sha256TR,
    Signature, ValidatorIdentity, ValidatorIdentityIdentity,
};
use crate::crypto::Identifier;
use crate::crypto::*;
use crate::types::{
    error::SessionError,
    message::{
        DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest,
        SigningRequestWrap, SigningResponse, SigningResponseWrap,
    },
    Participants, SessionId, SignatureSuite,
};
use dkg::{CoordinatorDKGSession as DkgSession, DKGInfo};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use signing::CoordinatorSigningSession as SigningSession;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

pub(crate) enum InstructionCipher<VII: ValidatorIdentityIdentity> {
    IsCryptoType {
        crypto_type: CryptoType,
        response_onshot: oneshot::Sender<bool>,
    },
    PkIdExists {
        pkid: PkId,
        response_onshot: oneshot::Sender<bool>,
    },
    NewKey {
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_onshot: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    Sign {
        pkid: Vec<u8>,
        msg: Vec<u8>,
        signature_response_onshot: oneshot::Sender<Result<Vec<u8>, String>>,
    },
}
struct SessionWrap<VII: ValidatorIdentityIdentity, C: Cipher> {
    signing_sessions: HashMap<PkId, SigningSession<VII, C>>,

    dkg_session_sender:
        UnboundedSender<(DKGRequestWrap<VII>, oneshot::Sender<DKGResponseWrap<VII>>)>,
    signing_session_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,

    session_id_key_map: HashMap<SessionId<VII>, oneshot::Sender<Result<Vec<u8>, String>>>,
    pkid_signaturesuite_map: HashMap<PkId, oneshot::Sender<Result<Vec<u8>, String>>>,

    dkg_futures: FuturesUnordered<
        oneshot::Receiver<Result<DKGInfo<VII, C>, (SessionId<VII>, SessionError<C>)>>,
    >,
    signing_futures:
        FuturesUnordered<oneshot::Receiver<Result<SignatureSuite<VII, C>, SessionError<C>>>>,

    instruction_receiver: UnboundedReceiver<InstructionCipher<VII>>,

    cipher_dkg_session_receiver:
        UnboundedReceiver<(DKGRequest<VII, C>, oneshot::Sender<DKGResponse<VII, C>>)>,
    cipher_dkg_session_sender:
        UnboundedSender<(DKGRequest<VII, C>, oneshot::Sender<DKGResponse<VII, C>>)>,
    cipher_signing_session_sender: UnboundedSender<(
        SigningRequest<VII, C>,
        oneshot::Sender<SigningResponse<VII, C>>,
    )>,
    cipher_signing_session_receiver: UnboundedReceiver<(
        SigningRequest<VII, C>,
        oneshot::Sender<SigningResponse<VII, C>>,
    )>,

    cipher_dkg_oneshot_mapping: HashMap<SessionId<VII>, oneshot::Sender<DKGResponse<VII, C>>>,
    cipher_signing_oneshot_mapping:
        HashMap<SessionId<VII>, oneshot::Sender<SigningResponse<VII, C>>>,
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
    ) -> Self {
        let (cipher_dkg_session_sender, cipher_dkg_session_receiver) = unbounded_channel();
        let (cipher_signing_session_sender, cipher_signing_session_receiver) = unbounded_channel();
        Self {
            signing_sessions: HashMap::new(),
            dkg_session_sender,
            signing_session_sender,
            cipher_dkg_session_sender,
            cipher_dkg_session_receiver,
            cipher_signing_session_sender,
            cipher_signing_session_receiver,
            session_id_key_map: HashMap::new(),
            dkg_futures: FuturesUnordered::new(),
            instruction_receiver,
            signing_futures: FuturesUnordered::new(),
            pkid_signaturesuite_map: HashMap::new(),
        }
    }
    pub(crate) async fn new_key<IT>(
        &mut self,
        participants: Vec<(IT, VII)>,
        min_signers: u16,
        identifier_transform: impl Fn(IT) -> Result<C::Identifier, C::CryptoError> + 'static,
    ) -> Result<SessionId<VII>, SessionError<C>> {
        //TODO: remove the following participants judgement
        let participants = participants
            .into_iter()
            .map(|(id, validator)| {
                let id = (identifier_transform)(id)?;
                Ok((id, validator))
            })
            .collect::<Result<Vec<(C::Identifier, VII)>, C::CryptoError>>()
            .map_err(|e| SessionError::CryptoError(e))?;
        let participants = Participants::new(participants)?;
        participants.check_min_signers(min_signers)?;
        let session = DkgSession::<VII, C>::new(
            participants.clone(),
            min_signers,
            self.cipher_dkg_session_sender.clone(),
        )?;
        let session_id = session.session_id().clone();
        let (tx, rx) = oneshot::channel();
        self.dkg_futures.push(rx);
        session.start_dkg(tx).await;
        return Ok(session_id);
    }
    pub(crate) async fn sign<T: AsRef<[u8]>>(
        &mut self,
        pkid_raw: T,
        msg: Vec<u8>,
    ) -> Result<(), SessionError<C>> {
        let pkid = PkId::new(pkid_raw.as_ref().to_vec());
        let signing_session =
            self.signing_sessions
                .get_mut(&pkid)
                .ok_or(SessionError::SignerSessionError(
                    "Signing session not found".to_string(),
                ))?;
        let (tx, rx) = oneshot::channel();
        self.signing_futures.push(rx);
        signing_session.start_new_signing(msg, tx).await;
        return Ok(());
    }
    pub(crate) fn find_pkid(&self, pkid: PkId) -> bool {
        self.signing_sessions.contains_key(&pkid)
    }
    pub(crate) fn listening(mut self) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(instruction) = self.instruction_receiver.recv() => {
                        self.handle_instruction(instruction).await;
                    }
                     Some(Result::Ok(dkg_info))= self.dkg_futures.next() => {
                        self.handle_dkg_future(dkg_info).await;
                    }
                    Some(Result::Ok(signing_session))= self.signing_futures.next() => {
                        self.handle_signing_future(signing_session).await;
                    }
                    Some(cipher_dkg_request) = self.cipher_dkg_session_receiver.recv() => {
                        self.handle_cipher_dkg_request(cipher_dkg_request).await;
                    }
                    Some(cipher_signing_request) = self.cipher_signing_session_receiver.recv() => {
                        self.handle_cipher_signing_request(cipher_signing_request).await;
                    }

                }
            }
        });
    }
    async fn handle_cipher_dkg_request(
        &mut self,
        dkg_request: DKGRequest<VII, C>,
    ) -> Result<(), SessionError<C>> {
        let session_id = dkg_request.session_id();
        let dkg_request = DKGResponseWrap::from(dkg_request.0);
        return Ok(());
    }
    async fn handle_instruction(&mut self, instruction: InstructionCipher<VII>) {
        match instruction {
            InstructionCipher::IsCryptoType {
                crypto_type,
                response_onshot,
            } => {
                if crypto_type == C::crypto_type() {
                    response_onshot.send(true).unwrap();
                } else {
                    response_onshot.send(false).unwrap();
                }
            }
            InstructionCipher::PkIdExists {
                pkid,
                response_onshot,
            } => {
                let exists = self.find_pkid(pkid);
                response_onshot.send(exists).unwrap();
            }
            InstructionCipher::NewKey {
                participants,
                min_signers,
                pkid_response_onshot,
            } => {
                let session_id = self
                    .new_key(participants, min_signers, |id| C::Identifier::from_u16(id))
                    .await;
                match session_id {
                    Ok(session_id) => {
                        self.session_id_key_map
                            .insert(session_id, pkid_response_onshot);
                    }
                    Err(e) => {
                        if let Err(e) = pkid_response_onshot.send(Err(e.to_string())) {
                            tracing::error!("Error sending pkid response: {:?}", e);
                        }
                    }
                }
            }
            InstructionCipher::Sign {
                pkid,
                msg,
                signature_response_onshot,
            } => {
                let pkid = PkId::new(pkid);
                let session = self
                    .signing_sessions
                    .get_mut(&pkid)
                    .ok_or("Signing session not found".to_string());

                match session {
                    Ok(session) => {
                        let (tx, rx) = oneshot::channel();
                        self.signing_futures.push(rx);
                        self.pkid_signaturesuite_map
                            .insert(pkid, signature_response_onshot);
                        session.start_new_signing(msg, tx).await;
                    }
                    Err(e) => {
                        if let Err(e) = signature_response_onshot.send(Err(e.to_string())) {
                            tracing::error!("Error sending signature response: {:?}", e);
                        }
                    }
                }
            }
        }
    }
    async fn handle_dkg_future(
        &mut self,
        dkg_info: Result<DKGInfo<VII, C>, (SessionId<VII>, SessionError<C>)>,
    ) -> Result<(), SessionError<C>> {
        match dkg_info {
            Ok(dkg_info) => {
                // signing
                // dkg_info.public_key_package.pkid()
                self.signing_sessions.insert(
                    dkg_info
                        .public_key_package
                        .pkid()
                        .map_err(|e| SessionError::CryptoError(e))?,
                    SigningSession::new(
                        dkg_info.public_key_package.clone(),
                        dkg_info.min_signers,
                        dkg_info.participants.clone(),
                        self.cipher_signing_session_sender.clone(),
                    )?,
                );
                let oneshot = self.session_id_key_map.remove(&dkg_info.session_id);
                if let Some(oneshot) = oneshot {
                    oneshot
                        .send(
                            dkg_info
                                .public_key_package
                                .pkid()
                                .map(|pkid| pkid.to_bytes().to_vec())
                                .map_err(|e| e.to_string()),
                        )
                        .unwrap();
                }
            }
            Err(e) => {
                tracing::error!("Error in DKG future: {:?}", e);
                let oneshot = self.session_id_key_map.remove(&e.0);
                if let Some(oneshot) = oneshot {
                    oneshot.send(Err(e.1.to_string())).unwrap();
                }
            }
        }
        return Ok(());
        //TODO find in instruction and response
    }
    async fn handle_signing_future(
        &mut self,
        signing_session: Result<SignatureSuite<VII, C>, SessionError<C>>,
    ) -> Result<(), SessionError<C>> {
        return Ok(());
    }
}
