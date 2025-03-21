use rand::CryptoRng;

use crate::{
    crypto::*,
    types::{
        error::SessionError,
        message::{DKGBaseMessage, DKGRequest, DKGRequestStage, DKGResponse, DKGResponseStage},
    },
};
use rand_core::RngCore;
use std::collections::BTreeMap;

use super::SigningSession;

#[derive(Debug, Clone)]
enum DKGSignerState<C: Cipher> {
    Part1 {
        round1_secret_package: C::DKGRound1SecretPackage,
    },
    Part2 {
        _round1_package_map: BTreeMap<C::Identifier, C::DKGRound1Package>,
        round2_secret_package: C::DKGRound2SecretPackage,
    },
    Completed {
        key_package: C::KeyPackage,
        public_key_package: C::PublicKeyPackage,
    },
}
pub(crate) struct DKGSession<VII: ValidatorIdentityIdentity, C: Cipher> {
    base_info: DKGBaseMessage<VII, C::Identifier>,
    dkg_state: DKGSignerState<C>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher + PartialEq + Eq> DKGSession<VII, C> {
    pub(crate) fn new_from_request<R: RngCore + CryptoRng>(
        request: DKGRequest<VII, C>,
        mut rng: R,
    ) -> Result<(Self, DKGResponse<VII, C>), SessionError> {
        let DKGBaseMessage {
            crypto_type,
            min_signers,
            participants,
            identifier,
            identity,
            ..
        } = request.base_info.clone();
        if crypto_type != C::crypto_type() {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "crypto type does not match: {:?} vs {:?}",
                crypto_type,
                C::crypto_type()
            )));
        }
        participants.check_identifier_identity_exists(&identifier, &identity)?;
        if let DKGRequestStage::Part1 {} = request.stage.clone() {
            participants.check_identifier_identity_exists(&identifier, &identity)?;
            let (round1_secret_package, round1_package) = C::dkg_part1(
                identifier.clone(),
                participants.len() as u16,
                min_signers,
                &mut rng,
            )
            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
            let response = DKGResponse {
                base_info: request.base_info.clone(),
                stage: DKGResponseStage::Part1 {
                    round1_package: round1_package.clone(),
                },
            };
            Ok((
                Self {
                    dkg_state: DKGSignerState::Part1 {
                        round1_secret_package,
                    },
                    base_info: request.base_info.clone(),
                },
                response,
            ))
        } else {
            Err(SessionError::InvalidRequest(format!(
                "new request is not DKGRequest::Part1: {:?}",
                request
            )))
        }
    }
    pub(crate) fn update_from_request(
        &mut self,
        request: DKGRequest<VII, C>,
    ) -> Result<DKGResponse<VII, C>, SessionError> {
        let DKGBaseMessage {
            identifier,
            identity,
            ..
        } = request.base_info.clone();
        if self.base_info != request.base_info {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "base info does not match: {:?} vs {:?}",
                self.base_info, request.base_info
            )));
        }
        self.base_info
            .participants
            .check_identifier_identity_exists(&identifier, &identity)?;
        let resp = match request.stage.clone() {
            DKGRequestStage::Part1 { .. } => {
                return Err(SessionError::InvalidRequest(format!(
                    "invalid request for update from part1: {:?}",
                    request
                )));
            }
            DKGRequestStage::Part2 { round1_package_map } => {
                if let DKGSignerState::Part1 {
                    round1_secret_package,
                } = &self.dkg_state
                {
                    let mut round1_package_map = round1_package_map.clone();
                    self.base_info.participants.check_keys_equal_except_self(
                        &self.base_info.identifier,
                        &round1_package_map,
                    )?;
                    round1_package_map.remove(&self.base_info.identifier);
                    let (round2_secret_package, round2_package_map) =
                        C::dkg_part2(round1_secret_package.clone(), &round1_package_map)
                            .map_err(|e| SessionError::CryptoError(e.to_string()))?;
                    let response = DKGResponse {
                        base_info: request.base_info.clone(),
                        stage: DKGResponseStage::Part2 {
                            round2_package_map: round2_package_map.clone(),
                        },
                    };
                    // TODO: cannot update directly, need to judge whether coordinator is in part1 or part2
                    self.dkg_state = DKGSignerState::Part2 {
                        _round1_package_map: round1_package_map.clone(),
                        round2_secret_package: round2_secret_package.clone(),
                    };
                    response
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from part2: {:?}",
                        request
                    )));
                }
            }
            DKGRequestStage::GenPublicKey {
                round1_package_map,
                round2_package_map,
            } => {
                if let DKGSignerState::Part2 {
                    round2_secret_package,
                    ..
                } = &self.dkg_state
                {
                    self.base_info.participants.check_keys_equal_except_self(
                        &self.base_info.identifier,
                        &round1_package_map,
                    )?;
                    // let mut round1_package_map = round1_package_map.clone();
                    // round1_package_map.remove(&self.identifier);
                    self.base_info.participants.check_keys_equal_except_self(
                        &self.base_info.identifier,
                        &round2_package_map,
                    )?;
                    // let mut round2_package_map = round2_package_map.clone();
                    // round2_package_map.remove(&self.identifier);
                    let (key_package, public_key_package) = C::dkg_part3(
                        &round2_secret_package,
                        &round1_package_map,
                        &round2_package_map,
                    )
                    .map_err(|e| SessionError::CryptoError(e.to_string()))?;
                    let response = DKGResponse {
                        base_info: request.base_info.clone(),
                        stage: DKGResponseStage::GenPublicKey {
                            public_key_package: public_key_package.clone(),
                        },
                    };
                    self.dkg_state = DKGSignerState::Completed {
                        key_package: key_package.clone(),
                        public_key_package: public_key_package.clone(),
                    };
                    response
                } else {
                    return Err(SessionError::InvalidRequest(format!(
                        "invalid request for update from gen public key: {:?}",
                        request
                    )));
                }
            }
        };
        Ok(resp)
    }
    pub(crate) fn is_completed(&self) -> Result<Option<SigningSession<VII, C>>, SessionError> {
        match self.dkg_state.clone() {
            DKGSignerState::Completed {
                key_package,
                public_key_package,
            } => Ok(Some(SigningSession::new(
                public_key_package,
                self.base_info.min_signers,
                self.base_info.participants.clone(),
                key_package,
                self.base_info.identifier.clone(),
                self.base_info.identity.clone(),
            )?)),
            _ => Ok(None),
        }
    }
}
