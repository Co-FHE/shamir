use serde::{Deserialize, Serialize};

use super::{
    Cipher, Participants, PkId, PublicKeyPackage, SessionError, ValidatorIdentityIdentity,
};
use crate::crypto::*;
use crate::types::message::SigningRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SigningSignerBaseInfo {
    pub(crate) pkid: PkId,
    pub(crate) key_package: Vec<u8>,
    pub(crate) _public_key_package: Vec<u8>,
    pub(crate) _min_signers: u16,
    pub(crate) participants: Vec<u8>,
    pub(crate) identifier: Vec<u8>,
    pub(crate) identity: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SigningSignerBase<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) pkid: PkId,
    pub(crate) key_package: C::KeyPackage,
    pub(crate) _public_key_package: C::PublicKeyPackage,
    pub(crate) _min_signers: u16,
    pub(crate) participants: Participants<VII, C::Identifier>,
    pub(crate) identifier: C::Identifier,
    pub(crate) identity: VII,
}

impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningSignerBase<VII, C> {
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        key_package: C::KeyPackage,
        min_signers: u16,
        participants: Participants<VII, C::Identifier>,
        identifier: C::Identifier,
        identity: VII,
    ) -> Result<Self, SessionError> {
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
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError> {
        let base_info = SigningSignerBaseInfo {
            pkid: self.pkid.clone(),
            key_package: self
                .key_package
                .to_bytes()
                .map_err(|e| SessionError::SignerSessionError(e))?,
            _public_key_package: self
                ._public_key_package
                .serialize_binary()
                .map_err(|e| SessionError::SignerSessionError(e.to_string()))?,
            _min_signers: self._min_signers,
            participants: self.participants.serialize()?,
            identifier: self.identifier.to_bytes(),
            identity: self.identity.to_bytes(),
        };
        Ok(bincode::serialize(&base_info).unwrap())
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, SessionError> {
        let base_info: SigningSignerBaseInfo = bincode::deserialize(bytes).unwrap();
        Ok(Self {
            pkid: base_info.pkid,
            key_package: C::KeyPackage::from_bytes(&base_info.key_package)
                .map_err(|e| SessionError::SignerSessionError(e.to_string()))?,
            _public_key_package: C::PublicKeyPackage::deserialize_binary(
                &base_info._public_key_package,
            )
            .map_err(|e| SessionError::SignerSessionError(e.to_string()))?,
            _min_signers: base_info._min_signers,
            participants: Participants::deserialize(&base_info.participants)?,
            identifier: C::Identifier::from_bytes(&base_info.identifier)
                .map_err(|e| SessionError::SignerSessionError(e.to_string()))?,
            identity: VII::from_bytes(&base_info.identity)
                .map_err(|e| SessionError::SignerSessionError(e.to_string()))?,
        })
    }
    pub(crate) fn check_request(
        &self,
        request: &SigningRequest<VII, C>,
    ) -> Result<(), SessionError> {
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
