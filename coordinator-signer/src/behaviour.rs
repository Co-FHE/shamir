use libp2p::{
    identify, ping, rendezvous,
    request_response::{self, Codec},
    swarm::NetworkBehaviour,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    DKGSingleRequest, DKGSingleResponse, ValidatorIdentity, ValidatorIdentityIdentity,
};

#[derive(NetworkBehaviour)]
pub(crate) struct CoorBehaviour<
    VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>,
> {
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) sig2coor: request_response::cbor::Behaviour<SigToCoorRequest, SigToCoorResponse>,
    pub(crate) coor2sig:
        request_response::cbor::Behaviour<CoorToSigRequest<VII>, CoorToSigResponse<VII>>,
    pub(crate) rendezvous: rendezvous::server::Behaviour,
}

#[derive(NetworkBehaviour)]
pub(crate) struct SigBehaviour<
    VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>,
> {
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) sig2coor: request_response::cbor::Behaviour<SigToCoorRequest, SigToCoorResponse>,
    pub(crate) coor2sig:
        request_response::cbor::Behaviour<CoorToSigRequest<VII>, CoorToSigResponse<VII>>,
    pub(crate) rendezvous: rendezvous::client::Behaviour,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SigToCoorRequest {
    ValidatorIndentity(ValidatorIdentityRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SigToCoorResponse {
    Success,
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum CoorToSigRequest<VII: ValidatorIdentityIdentity> {
    DKGRequest(DKGSingleRequest<VII>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum CoorToSigResponse<VII: ValidatorIdentityIdentity> {
    DKGResponse(DKGSingleResponse<VII>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValidatorIdentityRequest {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) nonce: u64,
}
