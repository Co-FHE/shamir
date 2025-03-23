mod behaviour;
mod dkg;
mod dkg_ex;
mod signing;
mod signing_ex;

pub(crate) use behaviour::*;
pub(crate) use dkg::*;
pub(crate) use dkg_ex::*;
use ecdsa_tss::signer_rpc::{CoordinatorToSignerMsg, SignerToCoordinatorMsg};
use serde::{Deserialize, Serialize};
pub(crate) use signing::*;
pub(crate) use signing_ex::*;

use crate::crypto::Identifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MessageEx<CI: Identifier, M: Sized + Send + Sync + Clone + 'static> {
    pub(crate) from: CI,
    pub(crate) target: TargetOrBroadcast<CI>,
    pub(crate) message: M,
}
pub(crate) fn message_ex_to_coordinator_to_signer_msg(
    message_ex: MessageEx<u16, Vec<u8>>,
) -> CoordinatorToSignerMsg {
    CoordinatorToSignerMsg {
        msg: message_ex.message,
        is_broadcast: message_ex.target == TargetOrBroadcast::<u16>::Broadcast,
        from: message_ex.from as u32,
    }
}
pub(crate) fn _message_ex_to_signer_to_coordinator_msg(
    message_ex: MessageEx<u16, Vec<u8>>,
) -> SignerToCoordinatorMsg {
    SignerToCoordinatorMsg {
        msg: message_ex.message,
        is_broadcast: message_ex.target == TargetOrBroadcast::<u16>::Broadcast,
        to: message_ex.from as u32,
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum TargetOrBroadcast<CI: Identifier> {
    Target { to: CI },
    Broadcast,
}
