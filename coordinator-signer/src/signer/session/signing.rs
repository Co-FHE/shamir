mod base;
use base::SigningSignerBase;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use subsession::SignerSubsession;

use crate::{
    crypto::{Cipher, PublicKeyPackage},
    signer::{PkId, ValidatorIdentityIdentity},
    types::{
        error::SessionError,
        message::{SigningRequest, SigningResponse},
        Participants, SubsessionId,
    },
};

mod subsession;
pub(crate) struct SigningSession<
    VII: ValidatorIdentityIdentity,
    C: Cipher,
    R: CryptoRng + RngCore + Clone,
> {
    base: SigningSignerBase<VII, C>,
    subsessions: BTreeMap<SubsessionId, SignerSubsession<VII, C, R>>,
    rng: R,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher, R: CryptoRng + RngCore + Clone>
    SigningSession<VII, C, R>
{
    pub(crate) fn new(
        public_key_package: C::PublicKeyPackage,
        min_signers: u16,
        participants: Participants<VII, C>,
        key_package: C::KeyPackage,
        identifier: C::Identifier,
        identity: VII,
        rng: R,
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
            rng,
        })
    }
    pub(crate) fn apply_request(
        &mut self,
        request: SigningRequest<VII, C>,
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
            let (subsession, response) = SignerSubsession::<VII, C, R>::new_from_request(
                request,
                self.base.clone(),
                self.rng.clone(),
            )?;
            self.subsessions.insert(subsession_id, subsession);
            Ok(response)
        }
    }
    pub(crate) fn pkid(&self) -> PkId {
        self.base.pkid.clone()
    }
}
