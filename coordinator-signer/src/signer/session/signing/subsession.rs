use rand::{CryptoRng, RngCore};

use crate::types::message::{
    SigningRequest, SigningRequestStage, SigningResponse, SigningResponseStage,
};

use super::{Cipher, SessionError, SigningSignerBase, SubsessionId, ValidatorIdentityIdentity};

#[derive(Debug, Clone)]
pub(crate) enum SignerSigningState<C: Cipher> {
    Round1 {
        signing_commitments: C::SigningCommitments,
        nonces: C::SigningNonces,
    },
    Round2 {
        signing_package: C::SigningPackage,
        nonces: C::SigningNonces,
        signature_share: C::SignatureShare,
    },
    Completed {
        signature: C::Signature,
    },
}
pub(crate) struct SignerSubsession<
    VII: ValidatorIdentityIdentity,
    C: Cipher,
    R: CryptoRng + RngCore,
> {
    pub(crate) subsession_id: SubsessionId,
    pub(crate) base: SigningSignerBase<VII, C>,
    pub(crate) signing_state: SignerSigningState<C>,
    pub(crate) message: Vec<u8>,
    pub(crate) rng: R,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher, R: CryptoRng + RngCore>
    SignerSubsession<VII, C, R>
{
    pub(crate) fn new_from_request(
        request: SigningRequest<VII, C>,
        base: SigningSignerBase<VII, C>,
        mut rng: R,
    ) -> Result<(Self, SigningResponse<VII, C>), SessionError<C>> {
        if let SigningRequestStage::Round1 { message } = request.stage.clone() {
            base.check_request(&request)?;
            let (nonces, commitments) = C::commit(&base.key_package, &mut rng);
            let response = SigningResponse {
                base_info: request.base_info.clone(),
                stage: SigningResponseStage::Round1 {
                    commitments: commitments.clone(),
                },
            };
            Ok((
                Self {
                    subsession_id: request.base_info.subsession_id.clone(),
                    base: base,
                    signing_state: SignerSigningState::Round1 {
                        signing_commitments: commitments.clone(),
                        nonces,
                    },
                    message: message,
                    rng,
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
    ) -> Result<SigningResponse<VII, C>, SessionError<C>> {
        self.base.check_request(&request)?;
        match request.stage.clone() {
            SigningRequestStage::Round1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from round1: {:?}",
                    request
                )));
            }
            SigningRequestStage::Round2 { signing_package } => {
                if let SignerSigningState::Round1 { nonces, .. } = &self.signing_state {
                    let signature_share =
                        C::sign(&signing_package, &nonces, &self.base.key_package)
                            .map_err(|e| SessionError::CryptoError(e))?;
                    let response = SigningResponse {
                        base_info: request.base_info.clone(),
                        stage: SigningResponseStage::Round2 {
                            signature_share: signature_share.clone(),
                        },
                    };
                    self.signing_state = SignerSigningState::Round2 {
                        signing_package: signing_package.clone(),
                        nonces: nonces.clone(),
                        signature_share: signature_share.clone(),
                    };
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
            SignerSigningState::Completed { .. } => true,
            _ => false,
        }
    }
}
