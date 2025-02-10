use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoType, PkId, ValidatorIdentityIdentity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoDKG<VII: ValidatorIdentityIdentity> {
    pub min_signers: u16,
    state: AutoDKGState<VII>,
}

impl<VII: ValidatorIdentityIdentity> std::fmt::Display for AutoDKG<VII> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AutoDKG {{ min_signers: {}, state: {} }}",
            self.min_signers, self.state
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoDKGState<VII: ValidatorIdentityIdentity> {
    WaitingForSignersRegistration(HashMap<VII, bool>),
    WaitingForSignersDKG(HashMap<CryptoType, PkId>),
    Done(HashMap<CryptoType, PkId>),
}

impl<VII: ValidatorIdentityIdentity> std::fmt::Display for AutoDKGState<VII> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoDKGState::WaitingForSignersRegistration(map) => {
                write!(
                    f,
                    "WaitingForSignersRegistration {{ registered: {} }}",
                    map.values().filter(|v| **v).count()
                )
            }
            AutoDKGState::WaitingForSignersDKG(map) => {
                write!(f, "WaitingForSignersDKG {{ ")?;
                for (crypto_type, pkid) in map {
                    write!(f, "{:?}: {}, ", crypto_type, pkid.to_string())?;
                }
                write!(f, "}}")
            }
            AutoDKGState::Done(map) => {
                write!(f, "Done {{ ")?;
                for (crypto_type, pkid) in map {
                    write!(f, "{:?}: {}, ", crypto_type, pkid.to_string())?;
                }
                write!(f, "}}")
            }
        }
    }
}
impl<VII: ValidatorIdentityIdentity> AutoDKG<VII> {
    pub(crate) fn new(min_signers: u16, signers: HashSet<VII>) -> Self {
        Self {
            min_signers,
            state: AutoDKGState::WaitingForSignersRegistration(
                signers.into_iter().map(|signer| (signer, false)).collect(),
            ),
        }
    }
    pub(crate) fn register_signer(&mut self, signer: VII) -> Option<Vec<(u16, VII)>> {
        if let AutoDKGState::WaitingForSignersRegistration(state) = &mut self.state {
            if state.contains_key(&signer) {
                state.insert(signer, true);
            }
            // if all is true, then start dkg
            if state.values().all(|v| *v) {
                let r = Some(
                    state
                        .iter()
                        .enumerate()
                        .map(|(i, (signer, _))| ((i + 1) as u16, signer.clone()))
                        .collect(),
                );
                self.state = AutoDKGState::WaitingForSignersDKG(HashMap::new());
                return r;
            }
        }
        None
    }
    pub(crate) fn update_new_dkg_result(&mut self, crypto_type: CryptoType, pkid: PkId) {
        if let AutoDKGState::WaitingForSignersDKG(state) = &mut self.state {
            if !state.contains_key(&crypto_type) {
                state.insert(crypto_type, pkid);
            }
            if state.len() == <CryptoType as strum::EnumCount>::COUNT {
                self.state = AutoDKGState::Done(state.clone());
            }
        }
    }
    pub fn get_pkid_by_crypto_type(&self, crypto_type: CryptoType) -> Result<PkId, String> {
        if let AutoDKGState::Done(state) = &self.state {
            return state
                .get(&crypto_type)
                .cloned()
                .ok_or(format!("crypto_type {} not found", crypto_type));
        }
        Err(format!("auto dkg not done"))
    }
}
