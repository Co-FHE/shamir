use super::{
    Cipher, Participants, PkId, PublicKeyPackage, SessionError, ValidatorIdentityIdentity,
};
use crate::crypto::*;
use crate::types::message::SigningRequest;

#[derive(Debug, Clone)]
pub(crate) struct SigningSignerBase<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) pkid: PkId,
    pub(crate) key_package: C::KeyPackage,
    pub(crate) _public_key_package: C::PublicKeyPackage,
    pub(crate) _min_signers: u16,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) identifier: C::Identifier,
    pub(crate) identity: VII,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningSignerBase<VII, C> {
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        key_package: C::KeyPackage,
        min_signers: u16,
        participants: Participants<VII, C>,
        identifier: C::Identifier,
        identity: VII,
    ) -> Result<Self, SessionError<C>> {
        Ok(Self {
            pkid: public_key_package
                .pkid()
                .map_err(|e| SessionError::CryptoError(e))?,
            key_package,
            _public_key_package: public_key_package,
            _min_signers: min_signers,
            participants,
            identifier,
            identity,
        })
    }
    pub(crate) fn check_request(
        &self,
        request: &SigningRequest<VII, C>,
    ) -> Result<(), SessionError<C>> {
        if request.base_info.identifier != self.identifier {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "Identifier mismatch: expected {}, got {}",
                self.identifier.to_string(),
                request.base_info.identifier.to_string()
            )));
        }
        if request.base_info.pkid != self.pkid {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "PKID mismatch: expected {}, got {}",
                self.pkid.to_string(),
                request.base_info.pkid.to_string()
            )));
        }
        if request.base_info.participants != self.participants {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "Participants mismatch: expected {:?}, got {:?}",
                self.participants, request.base_info.participants
            )));
        }
        if request.base_info.identity != self.identity {
            return Err(SessionError::BaseInfoNotMatch(format!(
                "Identity mismatch: expected {:?}, got {:?}",
                self.identity, request.base_info.identity
            )));
        }
        self.participants.check_identifier_identity_exists(
            &request.base_info.identifier,
            &request.base_info.identity,
        )?;
        Ok(())
    }
}
