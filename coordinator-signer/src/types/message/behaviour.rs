use libp2p::{
    identify, ping, rendezvous,
    request_response::{self},
    swarm::NetworkBehaviour,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{CryptoType, PkId, ValidatorIdentityIdentity},
    types::SignatureSuiteInfo,
};

use super::{DKGRequestWrap, DKGResponseWrap, SigningRequestWrap, SigningResponseWrap};

#[derive(NetworkBehaviour)]
pub(crate) struct CoorBehaviour<
    VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>,
> {
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) sig2coor: request_response::cbor::Behaviour<SigToCoorRequest, SigToCoorResponse>,
    pub(crate) coor2sig:
        request_response::cbor::Behaviour<CoorToSigRequest<VII>, CoorToSigResponse<VII>>,
    pub(crate) node2coor:
        request_response::cbor::Behaviour<NodeToCoorRequest<VII>, NodeToCoorResponse<VII>>,
    pub(crate) rendezvous: rendezvous::server::Behaviour,
}

#[derive(NetworkBehaviour)]
pub(crate) struct NodeBehaviour<
    VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>,
> {
    pub(crate) identify: identify::Behaviour,
    pub(crate) node2coor:
        request_response::cbor::Behaviour<NodeToCoorRequest<VII>, NodeToCoorResponse<VII>>,
    // pub(crate) rendezvous: rendezvous::client::Behaviour,
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
pub(crate) enum NodeToCoorRequest<VII: ValidatorIdentityIdentity> {
    DKGRequest {
        crypto_type: CryptoType,
        participants: Vec<VII>,
        min_signers: u16,
        validator_identity: ValidatorIdentityRequest,
    },
    SigningRequest {
        pkid: PkId,
        msg: Vec<u8>,
        tweak_data: Option<Vec<u8>>,
        validator_identity: ValidatorIdentityRequest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NodeToCoorResponse<VII: ValidatorIdentityIdentity> {
    DKGResponse {
        pkid: PkId,
    },
    SigningResponse {
        signature_suite_info: SignatureSuiteInfo<VII>,
    },
    Failure(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SigToCoorResponse {
    Success,
    Failure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum CoorToSigRequest<VII: ValidatorIdentityIdentity> {
    DKGRequest(DKGRequestWrap<VII>),
    SigningRequest(SigningRequestWrap<VII>),
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum CoorToSigResponse<VII: ValidatorIdentityIdentity> {
    DKGResponse(DKGResponseWrap<VII>),
    SigningResponse(SigningResponseWrap<VII>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValidatorIdentityRequest {
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DKGInstructionRequest<VII: ValidatorIdentityIdentity> {
    pub(crate) crypto_type: CryptoType,
    pub(crate) participants: Vec<(u16, VII)>,
    pub(crate) min_signers: u16,
    pub(crate) validator_identity: ValidatorIdentityRequest,
}
