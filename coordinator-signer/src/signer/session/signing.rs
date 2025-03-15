mod base;
use base::SigningSignerBase;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use subsession::SignerSubsession;

use crate::{
    crypto::{Cipher, KeyPackage, PublicKeyPackage},
    signer::{PkId, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{SigningRequest, SigningResponse},
        Participants, SubsessionId,
    },
};

mod subsession;
pub(crate) struct SigningSession<VII: ValidatorIdentityIdentity, C: Cipher> {
    base: SigningSignerBase<VII, C>,
    subsessions: BTreeMap<SubsessionId, SignerSubsession<VII, C>>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SigningSession<VII, C> {
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VII, C::Identifier>,
        key_package: C::KeyPackage,
        identifier: C::Identifier,
        identity: VII,
    ) -> Result<Self, SessionError<C>> {
        Ok(Self {
            base: SigningSignerBase::new(
                public_key_package,
                key_package,
                min_signers,
                participants,
                identifier,
                identity,
            )?,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, SessionError<C>> {
        let base = SigningSignerBase::deserialize(bytes)?;
        Ok(Self {
            base,
            subsessions: BTreeMap::new(),
        })
    }
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, SessionError<C>> {
        self.base.serialize()
    }
    pub(crate) fn check_serialize_deserialize(&self) -> Result<(), SessionError<C>> {
        let serialized = self.serialize()?;
        let deserialized = Self::deserialize(&serialized)?;
        assert_eq!(self.base.pkid, deserialized.base.pkid);
        assert_eq!(
            self.base.key_package.to_bytes(),
            deserialized.base.key_package.to_bytes()
        );
        assert_eq!(self.base.participants, deserialized.base.participants);
        assert_eq!(self.base.identifier, deserialized.base.identifier);
        assert_eq!(self.base.identity, deserialized.base.identity);
        assert_eq!(self.base._min_signers, deserialized.base._min_signers);
        assert_eq!(
            self.base._public_key_package,
            deserialized.base._public_key_package
        );
        Ok(())
    }
    pub(crate) fn apply_request<R: RngCore + CryptoRng>(
        &mut self,
        request: SigningRequest<VII, C>,
        rng: &mut R,
    ) -> Result<SigningResponse<VII, C>, SessionError<C>> {
        let subsession_id = request.base_info.subsession_id.clone();
        let subsession = self.subsessions.get_mut(&subsession_id);
        if let Some(subsession) = subsession {
            let response = subsession.update_from_request(request)?;
            if subsession.is_completed() {
                self.subsessions.remove(&subsession_id);
            }
            Ok(response)
        } else {
            let (subsession, response) =
                SignerSubsession::<VII, C>::new_from_request(request, self.base.clone(), rng)?;
            self.subsessions.insert(subsession_id, subsession);
            Ok(response)
        }
    }
    pub(crate) fn pkid(&self) -> PkId {
        self.base.pkid.clone()
    }
}
