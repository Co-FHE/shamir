use rand::{CryptoRng, RngCore};

use super::{Cipher, SessionError, SigningSignerBase, SubsessionId, ValidatorIdentityIdentity};
use crate::crypto::SigningPackage;
use crate::types::message::{
    SigningRequest, SigningRequestStage, SigningResponse, SigningResponseStage,
};

#[derive(Debug, Clone)]
pub(crate) enum SignerSigningState<C: Cipher> {
    Round1 {
        _signing_commitments: C::SigningCommitments,
        nonces: C::SigningNonces,
    },
    _Round2 {
        _signing_package: C::SigningPackage,
        _nonces: C::SigningNonces,
        _signature_share: C::SignatureShare,
    },
    _Completed {
        signature: C::Signature,
    },
}
pub(crate) struct SignerSubsession<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) _subsession_id: SubsessionId,
    pub(crate) base: SigningSignerBase<VII, C>,
    pub(crate) signing_state: SignerSigningState<C>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignerSubsession<VII, C> {
    pub(crate) fn new_from_request<R: RngCore + CryptoRng>(
        request: SigningRequest<VII, C>,
        base: SigningSignerBase<VII, C>,
        mut rng: R,
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
    pub(crate) fn update_from_request(
        &mut self,
        request: SigningRequest<VII, C>,
    ) -> Result<SigningResponse<VII, C>, SessionError> {
        self.base.check_request(&request)?;
        match request.stage.clone() {
            SigningRequestStage::Round1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from round1: {:?}",
                    request
                )));
            }
            SigningRequestStage::Round2 {
                signing_commitments_map,
                message,
                tweak_data,
                ..
            } => {
                if let SignerSigningState::Round1 { nonces, .. } = &self.signing_state {
                    let signing_package =
                        C::SigningPackage::new(signing_commitments_map, message.as_ref())
                            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
                    let signature_share = C::sign_with_tweak(
                        &signing_package,
                        &nonces,
                        &self.base.key_package,
                        tweak_data,
                    )
                    .map_err(|e| SessionError::CryptoError(e.to_string()))?;
                    let response = SigningResponse {
                        base_info: request.base_info.clone(),
                        stage: SigningResponseStage::Round2 {
                            signature_share: signature_share.clone(),
                        },
                    };
                    // self.signing_state = SignerSigningState::Round2 {
                    //     _signing_package: signing_package.clone(),
                    //     _nonces: nonces.clone(),
                    //     _signature_share: signature_share.clone(),
                    // };
                    Ok(response)
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from part2: {:?}",
                        request
                    )));
                }
            }
        }
    }
    pub(crate) fn is_completed(&self) -> bool {
        match &self.signing_state {
            SignerSigningState::_Completed { .. } => true,
            _ => false,
        }
    }
}
