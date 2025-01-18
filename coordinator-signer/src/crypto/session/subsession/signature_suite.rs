use crate::crypto::ValidatorIdentity;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{Display, Formatter, Result};

use super::{pkid::PKID, PublicKeyPackage, Signature, SubSessionId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureSuite<VI: ValidatorIdentity> {
    pub(crate) signature: Signature,
    pub(crate) pk: PublicKeyPackage,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) pkid: PKID,
}
impl<VI: ValidatorIdentity> SignatureSuite<VI> {
    pub(crate) fn pretty_print(&self) -> String {
        format!(
            "Signature: {}\nPK: {}\nSubsession ID: {}\nPKID: \"{}\"",
            serde_json::to_string_pretty(&self.signature).unwrap(),
            serde_json::to_string_pretty(&self.pk).unwrap(),
            serde_json::to_string_pretty(&self.subsession_id).unwrap(),
            self.pkid
        )
    }
}

impl<VI: ValidatorIdentity> Display for SignatureSuite<VI> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.pretty_print())
    }
}
impl<VI: ValidatorIdentity> SignatureSuite<VI> {
    pub fn verify(&self, message: &[u8]) -> bool {
        match &self.pk {
            PublicKeyPackage::Ed25519(pk) => {
                if let Signature::Ed25519(sig) = &self.signature {
                    pk.verifying_key().verify(message, sig).is_ok()
                } else {
                    false
                }
            }
            PublicKeyPackage::Secp256k1(public_key_package) => {
                if let Signature::Secp256k1(sig) = self.signature {
                    public_key_package
                        .verifying_key()
                        .verify(message, &sig)
                        .is_ok()
                } else {
                    false
                }
            }
            PublicKeyPackage::Secp256k1Tr(public_key_package) => {
                if let Signature::Secp256k1Tr(sig) = self.signature {
                    public_key_package
                        .verifying_key()
                        .verify(message, &sig)
                        .is_ok()
                } else {
                    false
                }
            }
        }
    }
}
