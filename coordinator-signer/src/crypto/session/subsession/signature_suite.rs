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
        let json = serde_json::to_string_pretty(&self).unwrap();
        json
    }
}

impl<VI: ValidatorIdentity> Display for SignatureSuite<VI> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.pretty_print())
    }
}
