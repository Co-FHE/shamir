use std::collections::BTreeMap;
use std::collections::HashMap;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

use super::SessionId;
use super::{DKGRequestWrap, DKGResponseWrap};
use crate::coordinator::CoordinatorStateEx;
use crate::crypto::*;
use crate::types::message::DKGRequestEx;
use crate::types::message::DKGRequestWrapEx;
use crate::types::message::DKGResponseWrapEx;
use crate::types::message::DKGStageEx;
use crate::{
    crypto::Cipher,
    types::{
        error::SessionError,
        message::{DKGBaseMessage, DKGRequest, DKGRequestStage, DKGResponse, DKGResponseStage},
        Participants,
    },
};
pub(crate) struct CoordinatorDKGSessionEx<VII: ValidatorIdentityIdentity> {
    crypto_type: CryptoType,
    min_signers: u16,
    participants: Participants<VII, u16>,
    session_id: SessionId,
    dkg_state: CoordinatorStateEx<Vec<u8>>,
    out_init_dkg_sender:
        UnboundedSender<(DKGRequestWrapEx<VII>, oneshot::Sender<DKGResponseWrapEx>)>,
}
#[derive(Debug, Clone)]
pub(crate) struct DKGInfo<VII: ValidatorIdentityIdentity> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) min_signers: u16,
    pub(crate) participants: Participants<VII, u16>,
    pub(crate) session_id: SessionId,
    pub(crate) public_key_package: Vec<u8>,
}
impl<VII: ValidatorIdentityIdentity> CoordinatorDKGSessionEx<VII> {
    pub fn new(
        crypto_type: CryptoType,
        participants: Participants<VII, u16>,
        min_signers: u16,
        out_init_dkg_sender: UnboundedSender<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
    ) -> Result<Self, SessionError> {
        participants.check_min_signers(min_signers)?;
        let session_id = SessionId::new(crypto_type, min_signers, &participants)?;
        let dkg_state = CoordinatorStateEx::Init;

        Ok(Self {
            crypto_type,
            session_id,
            min_signers,
            participants,
            dkg_state,
            out_init_dkg_sender,
        })
    }
    fn match_base_info(&self, base_info: &DKGBaseMessage<VII, u16>) -> Result<(), SessionError> {
        if self.crypto_type != base_info.crypto_type {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "crypto type does not match: {:?} vs {:?}",
                self.crypto_type, base_info.crypto_type
            )));
        }
        if self.session_id != base_info.session_id {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "session id does not match: {:?} vs {:?}",
                self.session_id, base_info.session_id
            )));
        }
        if self.min_signers != base_info.min_signers {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "min signers does not match: {:?} vs {:?}",
                self.min_signers, base_info.min_signers
            )));
        }
        if self.participants != base_info.participants {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "participants does not match: {:?} vs {:?}",
                self.participants, base_info.participants
            )));
        }

        Ok(())
    }
    pub(crate) fn session_id(&self) -> SessionId {
        self.session_id.clone()
    }
    pub(crate) async fn start_dkg(
        self,
        mut in_final_rx: UnboundedReceiver<(
            DKGRequestWrapEx<VII>,
            oneshot::Sender<DKGResponseWrapEx>,
        )>,
        response_sender: oneshot::Sender<Result<DKGInfo<VII>, (SessionId, SessionError)>>,
    ) {
        tokio::spawn(async move {
            tracing::debug!("Starting DKG session with id: {:?}", self.session_id);
            let result = 'out: loop {
                // if let Some(public_key_package) = self.dkg_state.completed() {
                //     break 'out Ok(DKGInfo {
                //         session_id: self.session_id.clone(),
                //         min_signers: self.min_signers,
                //         participants: self.participants.clone(),
                //         public_key_package,
                //     });
                // }
                tracing::debug!("Starting new DKG round");
                let mut futures = FuturesUnordered::new();
                match self.split_into_single_requests() {
                    Ok(requests) => {
                        for request in requests {
                            tracing::debug!("Sending DKG request: {:?}", request);
                            let (tx, rx) = oneshot::channel();
                            futures.push(rx);
                            let request_wrap = DKGRequestWrapEx::from(request);
                            match request_wrap {
                                Ok(request_wrap) => {
                                    if let Err(e) =
                                        self.out_init_dkg_sender.send((request_wrap.clone(), tx))
                                    {
                                        tracing::error!("Error sending DKG request: {}", e);
                                        break 'out Err(SessionError::CoordinatorSessionError(
                                            format!("Error sending DKG request: {}", e),
                                        ));
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("{}", e);
                                    break 'out Err(e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error splitting into single requests: {}", e);
                        break 'out Err(e);
                    }
                }
                tracing::debug!("Waiting for {} responses", self.participants.len());
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = futures.next().await;
                    match response {
                        Some(Ok(response)) => {
                            tracing::debug!("Received valid response: {:?}", response.clone());
                            match response {
                                DKGResponseWrapEx::Success => {}
                                DKGResponseWrapEx::Failure(e) => {
                                    tracing::error!("Received failure response: {}", e);
                                    break 'out Err(SessionError::CoordinatorSessionError(e));
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving DKG state: {}", e);
                            break 'out Err(SessionError::CoordinatorSessionError(format!(
                                "Error receiving DKG state: {}",
                                e
                            )));
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            tracing::debug!(
                                "Received None response, breaking out of collection loop"
                            );
                            break 'out Err(SessionError::CoordinatorSessionError(
                                "DKG state is not completed".to_string(),
                            ));
                        }
                    }
                }
                let mut results = BTreeMap::new();
                for i in 0..self.participants.len() {
                    tracing::debug!("Waiting for response {}/{}", i + 1, self.participants.len());
                    let response = in_final_rx.recv().await;
                    match response {
                        Some((request, response_chan)) => {
                            let request_ex = request.dkg_request_ex();
                            match request_ex {
                                Ok(request_ex) => {
                                    tracing::debug!(
                                        "Received valid response: {:?}",
                                        request_ex.clone()
                                    );
                                    response_chan.send(DKGResponseWrapEx::Success);
                                    results.insert(request_ex.base_info.identifier, request_ex);
                                }
                                Err(e) => {
                                    tracing::error!("Error receiving DKG state: {}", e);
                                    response_chan.send(DKGResponseWrapEx::Failure(e.to_string()));
                                    break 'out Err(e);
                                }
                            }
                        }
                        None => {
                            tracing::error!("DKG state is not completed");
                            break 'out Err(SessionError::CoordinatorSessionError(
                                "DKG state is not completed".to_string(),
                            ));
                        }
                    }
                }
                break 'out self.handle_result(results);
            };
            if let Err(e) = response_sender.send(result.map_err(|e| (self.session_id.clone(), e))) {
                tracing::error!("Failed to send response: {:?}", e);
            }
        });
    }
    fn split_into_single_requests(&self) -> Result<Vec<DKGRequestEx<VII>>, SessionError> {
        match self.dkg_state.clone() {
            CoordinatorStateEx::Init => self
                .participants
                .iter()
                .map(|(id, identity)| {
                    Ok(DKGRequestEx {
                        base_info: DKGBaseMessage {
                            crypto_type: self.crypto_type,
                            min_signers: self.min_signers,
                            participants: self.participants.clone(),
                            identifier: id.clone(),
                            identity: identity.clone(),
                            session_id: self.session_id.clone(),
                        },
                        stage: DKGStageEx::Init,
                    })
                })
                .collect(),
            CoordinatorStateEx::Final { .. } => Ok(vec![]),
        }
    }
    fn handle_result(
        &self,
        response: BTreeMap<u16, DKGRequestEx<VII>>,
    ) -> Result<DKGInfo<VII>, SessionError> {
        self.participants.check_keys_equal(&response)?;
        match self.dkg_state.clone() {
            CoordinatorStateEx::Init => {
                let mut packages = BTreeMap::new();
                for (id, _) in self.participants.iter() {
                    // find in response
                    self.participants.check_keys_equal(&response)?;
                    let response = response.get(id).ok_or(
                        crate::types::error::SessionError::InvalidResponse(format!(
                            "response not found for id in part 1: {}",
                            id
                        )),
                    )?;
                    self.match_base_info(&response.base_info)?;
                    match response.stage.clone() {
                        DKGStageEx::Final(public_key_package) => {
                            packages.insert(id.clone(), public_key_package.clone());
                        }
                        _ => {
                            return Err(SessionError::InvalidResponse(format!(
                                "need round 1 package but got round 2 package"
                            )));
                        }
                    }
                }
                // check all packages are same
                let first_package = packages.values().next().unwrap();
                if packages.values().any(|package| package != first_package) {
                    return Err(SessionError::InvalidResponse(
                        "packages are not the same".to_string(),
                    ));
                }
                Ok(DKGInfo {
                    crypto_type: self.crypto_type,
                    min_signers: self.min_signers,
                    participants: self.participants.clone(),
                    session_id: self.session_id.clone(),
                    public_key_package: first_package.clone(),
                })
            }
            CoordinatorStateEx::Final { .. } => {
                return Err(SessionError::InvalidResponse(format!(
                    "DKG session {} has already completed",
                    self.session_id.to_string()
                )));
            }
        }
    }
}
