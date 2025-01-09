use libp2p::{identify, ping, rendezvous, request_response, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

#[derive(NetworkBehaviour)]
pub(crate) struct CoorBehaviour {
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) sig2coor: request_response::cbor::Behaviour<SigToCoorRequest, SigToCoorResponse>,
    pub(crate) coor2sig: request_response::cbor::Behaviour<CoorToSigRequest, CoorToSigResponse>,
    pub(crate) rendezvous: rendezvous::server::Behaviour,
}
#[derive(NetworkBehaviour)]
pub(crate) struct SigBehaviour {
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) sig2coor: request_response::cbor::Behaviour<SigToCoorRequest, SigToCoorResponse>,
    pub(crate) coor2sig: request_response::cbor::Behaviour<CoorToSigRequest, CoorToSigResponse>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CoorToSigRequest {
    ValidatorIdentity(Vec<u8>),
    StartDkg,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CoorToSigResponse {
    Success,
    Failure(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValidatorIdentityRequest {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) nonce: u64,
}
