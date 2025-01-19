mod dkg;
mod signing;
use crate::crypto::Identifier;
use crate::types::{
    error::SessionError,
    message::{
        DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest,
        SigningRequestWrap, SigningResponse, SigningResponseWrap,
    },
    Participants, SessionId, SignatureSuite,
};
use dkg::CoordinatorDKGSession as DkgSession;
use signing::CoordinatorSigningSession as SigningSession;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use super::{
    Cipher, CryptoType, Ed25519Sha512, PkId, Secp256K1Sha256, Secp256K1Sha256TR, Signature,
    ValidatorIdentity, ValidatorIdentityIdentity,
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
pub(crate) fn start_listening<VII: ValidatorIdentityIdentity, C: Cipher>(
    instructions_receiver: UnboundedReceiver<InstructionCipher<VII>>,
    dkg_session_sender: UnboundedSender<(
        DKGRequestWrap<VII>,
        oneshot::Sender<DKGResponseWrap<VII>>,
    )>,
    signing_session_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,
) {
    tokio::spawn(async move {
        let (dkg_session_sender_cipher, dkg_session_receiver_cipher) = unbounded_channel();
        let (signing_session_sender_cipher, signing_session_receiver_cipher) = unbounded_channel();
        SessionWrap::<VII, C, u16>::new(
            dkg_session_sender_cipher,
            signing_session_sender_cipher,
            |id| C::Identifier::from_u16(id),
        );
    });
}
struct SessionWrap<VII: ValidatorIdentityIdentity, C: Cipher, IT> {
    signing_sessions: HashMap<PkId, SigningSession<VII, C>>,

    dkg_session_sender: UnboundedSender<(DKGRequest<VII, C>, oneshot::Sender<DKGResponse<VII, C>>)>,
    signing_session_sender: UnboundedSender<(
        SigningRequest<VII, C>,
        oneshot::Sender<SigningResponse<VII, C>>,
    )>,
    identifier_transform: Box<dyn Fn(IT) -> Result<C::Identifier, C::CryptoError>>,
}

impl<VII: ValidatorIdentityIdentity, C: Cipher, IT> SessionWrap<VII, C, IT> {
    pub(crate) fn new(
        dkg_session_sender: UnboundedSender<(
            DKGRequest<VII, C>,
            oneshot::Sender<DKGResponse<VII, C>>,
        )>,
        signing_session_sender: UnboundedSender<(
            SigningRequest<VII, C>,
            oneshot::Sender<SigningResponse<VII, C>>,
        )>,
        transform: impl Fn(IT) -> Result<C::Identifier, C::CryptoError> + 'static,
    ) -> Self {
        Self {
            signing_sessions: HashMap::new(),
            dkg_session_sender,
            signing_session_sender,
            identifier_transform: Box::new(transform),
        }
    }
    pub(crate) async fn new_key(
        &mut self,
        participants: Vec<(IT, VII)>,
        min_signers: u16,
    ) -> Result<PkId, SessionError<C>> {
        let pn = participants.len();
        //TODO: remove the following participants judgement
        let participants = participants
            .into_iter()
            .map(|(id, validator)| {
                let id = (self.identifier_transform)(id)?;
                Ok((id, validator))
            })
            .collect::<Result<Vec<(C::Identifier, VII)>, C::CryptoError>>()
            .map_err(|e| SessionError::CryptoError(e))?;
        if participants.len() != pn {
            let msg = format!(
                "Invalid participants, expected number of participants {} got {}",
                pn,
                participants.len()
            );
            return Err(SessionError::InvalidParticipants(msg));
        }
        if min_signers > participants.len() as u16 {
            let msg = format!(
                "Not enough validators to start DKG, min_signers: {}, validators: {}",
                min_signers,
                participants.len()
            );
            tracing::debug!("{}", msg);
            return Err(SessionError::InvalidParticipants(msg));
        }
        if participants.len() > 255 {
            let msg = format!(
                "Too many validators to start DKG, max is 255, got {}",
                participants.len()
            );
            return Err(SessionError::InvalidParticipants(msg));
        }
        if min_signers < (participants.len() as u16 + 1) / 2 || min_signers == 0 {
            let msg = format!(
                "Min signers is too low, min_signers: {}, validators: {}",
                min_signers,
                participants.len()
            );
            return Err(SessionError::InvalidParticipants(msg));
        }
        let participants = Participants::new(participants)?;
        let session = DkgSession::<VII, C>::new(
            participants.clone(),
            min_signers,
            self.dkg_session_sender.clone(),
        )?;
        let public_key_package = session.start_dkg().await?;
        let signing_session = SigningSession::<VII, C>::new(
            public_key_package,
            min_signers,
            participants,
            self.signing_session_sender.clone(),
        )?;
        let pkid = signing_session.pkid.clone();
        self.signing_sessions
            .insert(signing_session.pkid.clone(), signing_session);
        Ok(pkid)
    }
    pub(crate) async fn sign<T: AsRef<[u8]>>(
        &mut self,
        pkid_raw: T,
        msg: Vec<u8>,
    ) -> Result<SignatureSuite<VII, C>, SessionError<C>> {
        let pkid = PkId::new(pkid_raw.as_ref().to_vec());
        let signing_session =
            self.signing_sessions
                .get_mut(&pkid)
                .ok_or(SessionError::SignerSessionError(
                    "Signing session not found".to_string(),
                ))?;
        let signature_suite = signing_session.start_new_signing(msg).await;
        Ok(signature_suite)
    }
    pub(crate) fn find_pkid(&self, pkid: PkId) -> bool {
        self.signing_sessions.contains_key(&pkid)
    }
}
