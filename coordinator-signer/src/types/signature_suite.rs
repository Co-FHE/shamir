use crate::crypto::{
    Cipher, Ed25519Sha512, PkId, PublicKeyPackage, Secp256K1Sha256, Secp256K1Sha256TR, Signature,
    VerifyingKey,
};
use crate::crypto::{CryptoType, Identifier};
use frost_secp256k1::Secp256K1Group;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

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
pub(crate) trait SignatureSuiteTrait<VII: ValidatorIdentityIdentity> {
    // fn pretty_print(&self) -> String;
    // fn verify<C: Cipher>(&self) -> Result<bool, C::CryptoError>;
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignatureSuite<VII, C> {
    fn pretty_print(&self) -> String {
        format!(
            "Crypto Type: {}\nSignature: {}\nParticipants: {}\nPK: {}\nSubsession ID: {}\nPKID: \"{}\"\nMessage: \"{}\"\nVerification: {}",
            C::crypto_type(),
            serde_json::to_string_pretty(&self.signature).unwrap(),
            serde_json::to_string_pretty(&self.participants.iter().map(|(k, v)| (k.to_string(), v.to_fmt_string())).collect::<BTreeMap<_,_>>()).unwrap(),
            serde_json::to_string_pretty(&self.pk).unwrap(),
            serde_json::to_string_pretty(&self.subsession_id).unwrap(),
            self.pkid,
            String::from_utf8_lossy(&self.message),
            self.verify().map_or_else(|e| e.to_string(), |_| "OK".to_string())
        )
    }
    fn verify(&self) -> Result<(), C::CryptoError> {
        self.pk
            .verifying_key()
            .verify(&self.message, &self.signature)
    }
}

impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>, C: Cipher> Display
    for SignatureSuite<VII, C>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.pretty_print())
    }
}

impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>> Display
    for SignatureSuiteInfo<VII>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.pretty_print_original())
    }
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignatureSuite<VII, C> {
    pub(crate) fn to_signature_info(&self) -> Result<SignatureSuiteInfo<VII>, String> {
        Ok(SignatureSuiteInfo {
            signature: self.signature.to_bytes().map_err(|e| e.to_string())?,
            pk: PublicKeyPackage::serialize(&self.pk).map_err(|e| e.to_string())?,
            subsession_id: self.subsession_id,
            participants: self
                .participants
                .iter()
                .map(|(k, v)| (k.to_bytes(), v.clone()))
                .collect(),
            pkid: self.pkid.clone(),
            message: self.message.clone(),
            crypto_type: C::crypto_type(),
            original_serialized: self.pretty_print(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureSuiteInfo<VII: ValidatorIdentityIdentity> {
    pub(crate) signature: Vec<u8>,
    pub(crate) pk: Vec<u8>,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) participants: BTreeMap<Vec<u8>, VII>,
    pub(crate) pkid: PkId,
    pub(crate) message: Vec<u8>,
    pub(crate) crypto_type: CryptoType,
    pub(crate) original_serialized: String,
}
impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>>
    SignatureSuiteInfo<VII>
{
    fn pretty_print(&self) -> String {
        format!(
            "Crypto Type: {}\nSignature: {}\nParticipants: {}\nPK: {}\nSubsession ID: {}\nPKID: \"{}\"\nMessage: \"{}\"",
            self.crypto_type,
            serde_json::to_string_pretty(&self.signature).unwrap(),
            serde_json::to_string_pretty(&self.participants).unwrap(),
            serde_json::to_string_pretty(&self.pk).unwrap(),
            serde_json::to_string_pretty(&self.subsession_id).unwrap(),
            self.pkid,
            String::from_utf8_lossy(&self.message),
        )
    }
    fn verify<C: Cipher>(&self) -> Result<(), C::CryptoError> {
        let pk = <<C as Cipher>::PublicKeyPackage as PublicKeyPackage>::deserialize(&self.pk)?;
        let signature = C::Signature::from_bytes(&self.signature)?;
        pk.verifying_key().verify(&self.message, &signature)
    }
}
impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>>
    SignatureSuiteInfo<VII>
{
    pub(crate) fn pretty_print_original(&self) -> String {
        format!(
            "{}\nOriginal: {}\nVerification: {}",
            self.pretty_print(),
            self.original_serialized,
            self.try_verify()
                .map_or_else(|e| e.to_string(), |_| "OK".to_string())
        )
    }
    pub(crate) fn try_verify(&self) -> Result<(), String> {
        match self.crypto_type {
            CryptoType::Ed25519 => self.verify::<Ed25519Sha512>().map_err(|e| e.to_string()),
            CryptoType::Secp256k1 => self.verify::<Secp256K1Sha256>().map_err(|e| e.to_string()),
            CryptoType::Secp256k1Tr => self
                .verify::<Secp256K1Sha256TR>()
                .map_err(|e| e.to_string()),
        }
    }
}
