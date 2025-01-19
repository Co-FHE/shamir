use crate::crypto::{Cipher, PkId, PublicKeyPackage, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{Display, Formatter, Result};

use super::{Participants, SessionId, SubsessionId, ValidatorIdentityIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureSuite<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) signature: C::Signature,
    pub(crate) pk: C::PublicKeyPackage,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) participants: Participants<VII, C>,
    pub(crate) pkid: PkId,
    pub(crate) message: Vec<u8>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignatureSuite<VII, C> {
    pub(crate) fn pretty_print(&self) -> String {
        format!(
            "Signature: {}\nPK: {}\nSubsession ID: {}\nPKID: \"{}\"\nMessage: \"{}\"\nVerification: {}",
            serde_json::to_string_pretty(&self.signature).unwrap(),
            serde_json::to_string_pretty(&self.pk).unwrap(),
            serde_json::to_string_pretty(&self.subsession_id).unwrap(),
            self.pkid,
            String::from_utf8_lossy(&self.message),
            self.verify(&self.message)
        )
    }
}

impl<VII: ValidatorIdentityIdentity, C: Cipher> Display for SignatureSuite<VII, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.pretty_print())
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignatureSuite<VII, C> {
    pub fn verify(&self, message: &[u8]) -> bool {
        self.pk
            .verifying_key()
            .verify(message, &self.signature)
            .is_ok()
    }
}
