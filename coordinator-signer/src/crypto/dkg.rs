use crate::crypto::ValidatorIdentityIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::oneshot;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGState<VII: ValidatorIdentityIdentity> {
    Part1(DKGPart1State<VII>),
    PrePart2,
    Part2,
    PrePart3,
    Part3,
    Completed,
}
pub(crate) trait PartState {
    type SingleRequest: SingleRequest;
    fn split_into_single_requests(&self) -> Vec<Self::SingleRequest>;
}
pub(crate) trait SingleRequest {
    type Response;
    fn response_channel(self) -> oneshot::Sender<Self::Response>;
}

pub(crate) struct DKGPart1SingleRequest<VII: ValidatorIdentityIdentity> {
    pub(crate) min_signers: u16,
    pub(crate) max_signers: u16,
    pub(crate) identifier: u16,
    pub(crate) identity: VII,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DKGPart1State<VII: ValidatorIdentityIdentity> {
    min_signers: u16,
    participants: BTreeMap<u16, VII>,
}
impl<VII: ValidatorIdentityIdentity> DKGPart1State<VII> {
    pub(crate) fn new(min_signers: u16, participants: BTreeMap<u16, VII>) -> Self {
        Self {
            min_signers,
            participants,
        }
    }
}
impl<VII: ValidatorIdentityIdentity> DKGState<VII> {
    pub(crate) fn split_into_single_requests(&self) -> Vec<DKGPart1SingleRequest<VII>> {
        match self {
            DKGState::Part1(state) => state
                .participants
                .iter()
                .map(|(id, identity)| DKGPart1SingleRequest::<VII> {
                    min_signers: state.min_signers,
                    max_signers: state.participants.len() as u16,
                    identifier: *id,
                    identity: identity.clone(),
                })
                .collect(),
            _ => vec![],
        }
    }
    pub(crate) fn completed(&self) -> bool {
        matches!(self, DKGState::Completed)
    }
}
