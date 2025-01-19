use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::types::message::{
    DKGRequest, DKGRequestWrap, DKGResponse, DKGResponseWrap, SigningRequest, SigningRequestWrap,
    SigningResponse, SigningResponseWrap,
};

use crate::crypto::*;

use super::SessionWrap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionManagerError {
    #[error("Invalid participants: {0}")]
    InvalidParticipants(String),
    #[error("Invalid min signers: {0}, max signers: {1}")]
    InvalidMinSigners(u16, u16),
    #[error("Session error: {0}")]
    SessionError(String),
}
pub(crate) enum Instruction<VII: ValidatorIdentityIdentity> {
    NewKey {
        crypto_type: CryptoType,
        participants: Vec<(u16, VII)>,
        min_signers: u16,
        pkid_response_onshot: oneshot::Sender<Result<Vec<u8>, SessionManagerError>>,
    },
    Sign {
        pkid: Vec<u8>,
        msg: Vec<u8>,
        signature_response_onshot: oneshot::Sender<Result<Vec<u8>, SessionManagerError>>,
    },
}
pub(crate) async fn new_key<VII: ValidatorIdentityIdentity, C: Cipher>(
    session_wrap: &mut SessionWrap<VII, C, u16>,
    participants: Vec<(u16, VII)>,
    min_signers: u16,
    pkid_response_onshot: oneshot::Sender<Result<Vec<u8>, SessionManagerError>>,
) {
    tokio::spawn(async move {
        let pkid = session_wrap
            .new_key(participants, min_signers)
            .await
            .map(|pkid| pkid.to_bytes())
            .map_err(|e| SessionManagerError::SessionError(e.to_string()));
        pkid_response_onshot.send(pkid);
    });
}
pub(crate) fn new<VII: ValidatorIdentityIdentity>(
    instructions_receiver: UnboundedReceiver<Instruction<VII>>,
    dkg_session_sender: UnboundedSender<(
        DKGRequestWrap<VII>,
        oneshot::Sender<DKGResponseWrap<VII>>,
    )>,
    signing_request_sender: UnboundedSender<(
        SigningRequestWrap<VII>,
        oneshot::Sender<SigningResponseWrap<VII>>,
    )>,
) {
    let (dkg_session_sender_cipher, dkg_session_receiver_cipher) = unbounded_channel();
    let (signing_session_sender_cipher, signing_session_receiver_cipher) = unbounded_channel();
    let transform = |id: u16| <Ed25519Sha512 as Cipher>::Identifier::from_u16(id);
    let session_wrap = SessionWrap::new(
        dkg_session_sender_cipher.clone(),
        signing_session_sender_cipher.clone(),
        transform,
    );
    tokio::spawn(async move {
        loop {
            let request = dkg_session_receiver_cipher.recv().await;
            if let Some((request, response_onshot)) = request {
                let request_wrapper = DKGRequestWrap::Ed25519(request);
                let (response_wrapper_sender, response_wrapper_receiver) = oneshot::channel();
                dkg_session_sender
                    .send((request_wrapper, response_wrapper_sender))
                    .unwrap();
                let response = response_wrapper_receiver.await.unwrap();
                match response {
                    DKGResponseWrap::Ed25519(response) => {
                        response_onshot.send(response).unwrap();
                    }
                    _ => {
                        tracing::error!("Invalid response");
                    }
                }
            } else {
                tracing::error!("DKG session receiver closed");
                continue;
            }
            let instruction = instructions_receiver.recv().await;
            if let Some(instruction) = instruction {
                match instruction {
                    Instruction::NewKey {
                        crypto_type,
                        participants,
                        min_signers,
                        pkid_response_onshot,
                    } => match crypto_type {
                        CryptoType::Ed25519 => {}
                        CryptoType::Secp256k1 => {
                            session_wrap.new_key(participants, min_signers).await;
                        }
                        CryptoType::Secp256k1Tr => {
                            session_wrap.new_key(participants, min_signers).await;
                        }
                    },
                    Instruction::Sign { pkid, msg } => {
                        session_wrap.sign(pkid, msg).await;
                    }
                }
            } else {
                tracing::error!("Instructions receiver closed");
                continue;
            }
            tokio::select! {
                request = dkg_session_receiver.recv() => {
                    if let Some(request) = request {
                        session_wrap.handle_dkg_request(request).await;
                    } else {
                        tracing::error!("DKG session receiver closed");
                        continue;
                    }
                }
                request = signing_session_receiver.recv() => {
                    if let Some(request) = request {
                        session_wrap.handle_signing_request(request).await;
                    } else {
                        tracing::error!("Signing session receiver closed");
                        continue;
                    }
                }
                instruction = instructions_receiver.recv() => {
                    if let Some(instruction) = instruction {

                    } else {
                        tracing::error!("Instructions receiver closed");
                        continue;
                    }
                }
            }
        }
    });
}
pub(crate) struct CoordiantorSessionManager<VII: ValidatorIdentityIdentity> {
    ed25519_session_wrap: SessionWrap<VII, Ed25519Sha512, u16>,
    ed25519_dkg_session_receiver: UnboundedReceiver<(
        DKGRequest<VII, Ed25519Sha512>,
        oneshot::Sender<DKGResponse<VII, Ed25519Sha512>>,
    )>,
    ed25519_signing_session_receiver: UnboundedReceiver<(
        SigningRequest<VII, Ed25519Sha512>,
        oneshot::Sender<SigningResponse<VII, Ed25519Sha512>>,
    )>,
}
// impl<VII: ValidatorIdentityIdentity> CoordiantorSessionManager<VII> {
//     }
//     pub(crate) fn new_key(
//         &mut self,
//         crypto_type: CryptoType,
//         participants: BTreeMap<u16, VII>,
//         min_signers: u16,
//     ) -> Result<Vec<u8>, SessionManagerError> {
//         Ok(())
//     }
//     pub(crate) fn sign<T: AsRef<[u8]>>(
//         &mut self,
//         pkid_raw: T,
//         msg: Vec<u8>,
//     ) -> Result<Vec<u8>, SessionManagerError> {
//         Ok(())
//     }
// }
