mod dkg;
mod signing;
use std::collections::{BTreeMap, HashMap};

use crate::types::SessionId;
use dkg::CoordinatorDKGSession as DkgSession;
use signing::CoordinatorSigningSession as SigningSession;

use super::{Cipher, Ed25519Sha512, PkId, ValidatorIdentity};
struct DkgSessionWrap<VI: ValidatorIdentity> {
    dkg_sessions: HashMap<SessionId<VI::Identity>, DkgSession<VI, Ed25519Sha512>>,
}
struct SigningSessionWrap<VI: ValidatorIdentity> {
    signing_sessions: HashMap<PkId, SigningSession<VI, Ed25519Sha512>>,
}
pub(crate) struct CoordiantorSessionManager<VI: ValidatorIdentity> {
    dkg_sessions: DkgSessionWrap<VI>,
    signing_sessions: SigningSessionWrap<VI>,
}
impl<VI: ValidatorIdentity> CoordiantorSessionManager<VI> {
    pub(crate) fn new() -> Self {
        Self {
            dkg_sessions: DkgSessionWrap::new(participants, min_signers),
            signing_sessions: SigningSessionWrap::new(),
        }
    }
    pub(crate) fn new_key<T: AsRef<[u8]>>(&mut self) -> Result<(), SessionError<Ed25519Sha512>> {}
    pub(crate) fn sign<T: AsRef<[u8]>>(
        &mut self,
        pkid_raw: T,
        msg: Vec<u8>,
    ) -> Result<(), SessionError<Ed25519Sha512>> {
    }
}
