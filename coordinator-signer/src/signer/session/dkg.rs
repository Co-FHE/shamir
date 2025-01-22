use rand::CryptoRng;

use crate::{
    crypto::*,
    types::{
        error::SessionError,
        message::{DKGBaseMessage, DKGRequest, DKGRequestStage, DKGResponse, DKGResponseStage},
        Participants, SessionId,
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
    session_id: SessionId,
    min_signers: u16,
    participants: Participants<VII, C>,
    dkg_state: DKGSignerState<C>,
    identity: VII,
    identifier: C::Identifier,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher + PartialEq + Eq> DKGSession<VII, C> {
    fn match_base_info(&self, base_info: &DKGBaseMessage<VII, C>) -> Result<(), SessionError<C>> {
        if self.session_id != base_info.session_id {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "session id does not match: {:?} vs {:?}",
                self.session_id, base_info.session_id
            )));
        }
        if self.min_signers != base_info.min_signers {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "min signers does not match: {:?} vs {:?}",
                self.min_signers, base_info.min_signers
            )));
        }
        if self.participants != base_info.participants {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "participants does not match: {:?} vs {:?}",
                self.participants, base_info.participants
            )));
        }
        if self.identifier != base_info.identifier {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "identifier does not match: {:?} vs {:?}",
                self.identifier, base_info.identifier
            )));
        }
        if self.identity != base_info.identity {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "identity does not match: {:?} vs {:?}",
                self.identity, base_info.identity
            )));
        }

        Ok(())
    }
    pub(crate) fn new_from_request<R: RngCore + CryptoRng>(
        request: DKGRequest<VII, C>,
        mut rng: R,
    ) -> Result<(Self, DKGResponse<VII, C>), SessionError<C>> {
        let DKGBaseMessage {
            session_id,
            min_signers,
            participants,
            identifier,
            identity,
        } = request.base_info.clone();
        participants.check_identifier_identity_exists(&identifier, &identity)?;
        if let DKGRequestStage::Part1 {} = request.stage.clone() {
            participants.check_identifier_identity_exists(&identifier, &identity)?;
            let (round1_secret_package, round1_package) = C::dkg_part1(
                identifier.clone(),
                participants.len() as u16,
                min_signers,
                &mut rng,
            )
            .map_err(|e| SessionError::CryptoError(e))?;
            let response = DKGResponse {
                base_info: request.base_info.clone(),
                stage: DKGResponseStage::Part1 {
                    round1_package: round1_package.clone(),
                },
            };
            Ok((
                Self {
                    session_id: session_id.clone(),
                    min_signers,
                    dkg_state: DKGSignerState::Part1 {
                        round1_secret_package,
                    },
                    participants: participants.clone(),
                    identity: identity.clone(),
                    identifier: identifier,
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
    ) -> Result<DKGResponse<VII, C>, SessionError<C>> {
        let DKGBaseMessage {
            identifier,
            identity,
            ..
        } = request.base_info.clone();
        self.match_base_info(&request.base_info)?;
        self.participants
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
                    self.participants
                        .check_keys_equal_except_self(&self.identifier, &round1_package_map)?;
                    round1_package_map.remove(&self.identifier);
                    let (round2_secret_package, round2_package_map) =
                        C::dkg_part2(round1_secret_package.clone(), &round1_package_map)
                            .map_err(|e| SessionError::CryptoError(e))?;
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
                    self.participants
                        .check_keys_equal_except_self(&self.identifier, &round1_package_map)?;
                    // let mut round1_package_map = round1_package_map.clone();
                    // round1_package_map.remove(&self.identifier);
                    self.participants
                        .check_keys_equal_except_self(&self.identifier, &round2_package_map)?;
                    // let mut round2_package_map = round2_package_map.clone();
                    // round2_package_map.remove(&self.identifier);
                    let (key_package, public_key_package) = C::dkg_part3(
                        &round2_secret_package,
                        &round1_package_map,
                        &round2_package_map,
                    )
                    .map_err(|e| SessionError::CryptoError(e))?;
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
    pub(crate) fn is_completed(&self) -> Result<Option<SigningSession<VII, C>>, SessionError<C>> {
        match self.dkg_state.clone() {
            DKGSignerState::Completed {
                key_package,
                public_key_package,
            } => Ok(Some(SigningSession::new(
                public_key_package,
                self.min_signers,
                self.participants.clone(),
                key_package,
                self.identifier.clone(),
                self.identity.clone(),
            )?)),
            _ => Ok(None),
        }
    }
}
