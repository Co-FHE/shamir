use crate::crypto::ValidatorIdentityIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DKGState<VII: ValidatorIdentityIdentity> {
    Part1(DKGPart1State<VII>),
    PrePart2,
    Part2,
    PrePart3,
    Part3,
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
