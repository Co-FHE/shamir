use crate::crypto::{Cipher, PkId, ValidatorIdentity};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{Display, Formatter, Result};

use super::{SessionId, SubsessionId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureSuite<VI: ValidatorIdentity, C: Cipher> {
    pub(crate) signature: C::Signature,
    pub(crate) pk: C::PublicKeyPackage,
    pub(crate) subsession_id: SubsessionId<VI::Identity>,
    pub(crate) pkid: PkId,
    pub(crate) message: Vec<u8>,
}
impl<VI: ValidatorIdentity, C: Cipher> SignatureSuite<VI, C> {
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

impl<VI: ValidatorIdentity, C: Cipher> Display for SignatureSuite<VI, C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.pretty_print())
    }
}
impl<VI: ValidatorIdentity, C: Cipher> SignatureSuite<VI, C> {
    pub fn verify(&self, message: &[u8]) -> bool {
        self.pk
            .verifying_key()
            .verify(message, &self.signature)
            .is_ok()
    }
}
