use rand::{CryptoRng, RngCore};

use super::{Cipher, SessionError, SubsessionId, ValidatorIdentityIdentity};
use crate::crypto::SigningPackage;
use crate::signer::session::SignerStateEx;
use crate::types::message::{
    SigningRequest, SigningRequestStage, SigningResponse, SigningResponseStage,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{Participants, PkId, PublicKeyPackage};
use crate::crypto::*;
use crate::types::message::dkg_base_message_serde;
use crate::types::message::DKGBaseMessage;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SigningSignerExBase<VII: ValidatorIdentityIdentity> {
    pub(crate) pkid: PkId,
    pub(crate) key_package: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    #[serde(with = "dkg_base_message_serde")]
    pub(crate) base_info: DKGBaseMessage<VII, u16>,
}
impl<VII: ValidatorIdentityIdentity> SigningSignerExBase<VII> {
    pub(crate) fn new(
        public_key: Vec<u8>,
        key_package: Vec<u8>,
        base_info: DKGBaseMessage<VII, u16>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            pkid: PkId::new(public_key.clone()),
            key_package,
            public_key,
            base_info,
        })
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        Ok(bincode::serialize(self).unwrap())
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, SessionError> {
        let base_info: Self = bincode::deserialize(bytes).unwrap();
        Ok(base_info)
    }
}

pub(crate) struct SignerSubsessionEx<VII: ValidatorIdentityIdentity> {
    pub(crate) _subsession_id: SubsessionId,
    pub(crate) base: SigningSignerExBase<VII>,
    pub(crate) signing_state: SignerStateEx<ecdsa_tss::signer_rpc::Signature>,
}
impl<VII: ValidatorIdentityIdentity> SignerSubsessionEx<VII> {
    pub(crate) fn new_from_request(
        request: SigningRequestEx<VII>,
        base: SigningSignerExBase<VII>,
    ) -> Result<(Self, SigningResponse<VII, C>), SessionError> {
        if let SigningRequestStage::Round1 {} = request.stage.clone() {
            base.check_request(&request)?;
            tracing::debug!("round1 {:?}", base.key_package);
            let (nonces, commitments) = C::commit(&base.key_package, &mut rng);
            let response = SigningResponse {
                base_info: request.base_info.clone(),
                stage: SigningResponseStage::Round1 {
                    commitments: commitments.clone(),
                },
            };
            Ok((
                Self {
                    _subsession_id: request.base_info.subsession_id.clone(),
                    base: base,
                    signing_state: SignerSigningState::Round1 {
                        _signing_commitments: commitments.clone(),
                        nonces,
                    },
                },
                response,
            ))
        } else {
            Err(SessionError::InvalidRequest(format!(
                "invalid request: {:?}",
                request
            )))
        }
    }
}
