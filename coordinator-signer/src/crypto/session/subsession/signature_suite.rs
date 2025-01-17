use crate::crypto::ValidatorIdentity;

use super::{PublicKeyPackage, Signature, SubSessionId};

pub(crate) struct SignatureSuite<VI: ValidatorIdentity> {
    pub(crate) signature: Signature,
    pub(crate) pk: PublicKeyPackage,
    pub(crate) subsession_id: SubSessionId<VI::Identity>,
    pub(crate) pkid: Vec<u8>,
}
