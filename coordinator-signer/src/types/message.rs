mod behaviour;
mod dkg;
mod dkg_ex;
mod signing;

pub(crate) use behaviour::*;
pub(crate) use dkg::*;
pub(crate) use dkg_ex::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub(crate) use signing::*;

use crate::crypto::{Identifier, ValidatorIdentityIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MessageEx<CI: Identifier, M: Sized + Send + Sync + Clone + 'static> {
    from: CI,
    target: TargetOrBroadcast<CI>,
    message: M,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum TargetOrBroadcast<CI: Identifier> {
    Target { to: CI },
    Broadcast,
}
