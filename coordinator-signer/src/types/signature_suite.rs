use super::{Participants, SubsessionId, ValidatorIdentityIdentity};
use crate::crypto::{
    Cipher, Ed25519Sha512, PkId, PublicKeyPackage, Secp256K1Sha256, Secp256K1Sha256TR, Signature,
    VerifyingKey,
};
use crate::crypto::{CryptoType, Identifier};
use crate::crypto::{Ed448Shake256, P256Sha256, Ristretto255Sha512, Tweak};
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignatureSuite<VII: ValidatorIdentityIdentity, C: Cipher> {
    pub(crate) signature: C::Signature,
    pub(crate) pk: C::PublicKeyPackage,
    pub(crate) tweak_data: Option<Vec<u8>>,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) participants: Participants<VII, C::Identifier>,
    pub(crate) pkid: PkId,
    pub(crate) message: Vec<u8>,
    pub(crate) joined_participants: Participants<VII, C::Identifier>,
}
impl<VII: ValidatorIdentityIdentity, C: Cipher> SignatureSuite<VII, C> {
    fn pretty_print(&self) -> String {
        format!(
            "Crypto Type: {}\nSignature: {}\nParticipants: {}\nJoined Participants: {}\nPK: {},\nPK TWEAK: {}\nSubsession ID: {}\nPKID: \"{}\"\nMessage: \"{}\"\nVerification: {}",
            C::crypto_type(),
            serde_json::to_string_pretty(&self.signature).unwrap(),
            serde_json::to_string_pretty(&self.participants.iter().map(|(k, v)| (k.to_string(), v.to_fmt_string())).collect::<BTreeMap<_,_>>()).unwrap(),
            serde_json::to_string_pretty(&self.joined_participants.iter().map(|(k, v)| (k.to_string(), v.to_fmt_string())).collect::<BTreeMap<_,_>>()).unwrap(),
            serde_json::to_string_pretty(&self.pk).unwrap(),
            self.tweak_data.clone().map(|s| hex::encode(s)).unwrap_or_default(),
            serde_json::to_string_pretty(&self.subsession_id).unwrap(),
            self.pkid,
            String::from_utf8_lossy(&self.message),
            self.verify().map_or_else(|e| e.to_string(), |_| "OK".to_string())
        )
    }
    fn verify(&self) -> Result<(), C::CryptoError> {
        self.pk
            .clone()
            .tweak(self.tweak_data.clone())
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
        let pk = PublicKeyPackage::serialize_binary(&self.pk).map_err(|e| e.to_string())?;
        let pk_tweak = self.pk.clone().tweak(self.tweak_data.clone());
        let pk_tweak = PublicKeyPackage::serialize_binary(&pk_tweak).map_err(|e| e.to_string())?;
        Ok(SignatureSuiteInfo {
            signature: self.signature.to_bytes().map_err(|e| e.to_string())?,
            pk: pk,
            pk_tweak: pk_tweak,
            pk_verifying_key: self
                .pk
                .verifying_key()
                .serialize_frost()
                .map_err(|e| e.to_string())?,
            pk_verifying_key_tweak: self
                .pk
                .clone()
                .tweak(self.tweak_data.clone())
                .verifying_key()
                .serialize_frost()
                .map_err(|e| e.to_string())?,
            tweak_data: self.tweak_data.clone(),
            subsession_id: self.subsession_id,
            participants: self
                .participants
                .iter()
                .map(|(k, v)| (k.to_bytes(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
            joined_participants: self
                .joined_participants
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupPublicKeyInfo {
    pub group_public_key_tweak: Vec<u8>,
    pub tweak_data: Option<Vec<u8>>,
}
use k256::elliptic_curve::sec1::ToEncodedPoint;
impl GroupPublicKeyInfo {
    pub(crate) fn new(group_public_key_tweak: Vec<u8>, tweak_data: Option<Vec<u8>>) -> Self {
        Self {
            group_public_key_tweak,
            tweak_data,
        }
    }
    pub fn compressed_pk_k256(&self) -> Result<Vec<u8>, String> {
        if self.group_public_key_tweak.len() == 33 {
            return Ok(self.group_public_key_tweak.clone());
        }
        if self.group_public_key_tweak.len() == 65 {
            let pk = k256::PublicKey::from_sec1_bytes(&self.group_public_key_tweak).unwrap();
            return Ok(pk.to_encoded_point(true).as_bytes().to_vec());
        }
        return Err(format!("Invalid public key length"));
    }
    pub fn uncompressed_pk_k256(&self) -> Result<Vec<u8>, String> {
        match self.group_public_key_tweak.len() {
            65 => Ok(self.group_public_key_tweak.clone()),
            33 => {
                let pk = k256::PublicKey::from_sec1_bytes(&self.group_public_key_tweak)
                    .map_err(|e| format!("Invalid compressed public key: {}", e))?;
                Ok(pk.to_encoded_point(false).as_bytes().to_vec())
            }
            _ => Err("Invalid public key length".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureSuiteInfo<VII: ValidatorIdentityIdentity> {
    pub(crate) signature: Vec<u8>,
    pub(crate) pk: Vec<u8>,
    pub(crate) pk_tweak: Vec<u8>,
    pub(crate) pk_verifying_key: Vec<u8>,
    pub(crate) pk_verifying_key_tweak: Vec<u8>,
    pub(crate) tweak_data: Option<Vec<u8>>,
    pub(crate) subsession_id: SubsessionId,
    pub(crate) participants: BTreeMap<Vec<u8>, VII>,
    pub(crate) joined_participants: BTreeMap<Vec<u8>, VII>,
    pub(crate) pkid: PkId,
    pub(crate) message: Vec<u8>,
    pub(crate) crypto_type: CryptoType,
    pub(crate) original_serialized: String,
}
impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>>
    SignatureSuiteInfo<VII>
{
    pub fn pretty_print(&self) -> String {
        let mut pretty_map = serde_json::Map::new();
        pretty_map.insert(
            "signature".to_string(),
            serde_json::Value::String(hex::encode(&self.signature)),
        );
        pretty_map.insert(
            "pk".to_string(),
            serde_json::Value::String(hex::encode(&self.pk)),
        );
        pretty_map.insert(
            "pk_tweak".to_string(),
            serde_json::Value::String(hex::encode(&self.pk_tweak)),
        );
        pretty_map.insert(
            "pk_verifying_key".to_string(),
            serde_json::Value::String(hex::encode(&self.pk_verifying_key)),
        );
        pretty_map.insert(
            "pk_verifying_key_tweak".to_string(),
            serde_json::Value::String(hex::encode(&self.pk_verifying_key_tweak)),
        );
        if let Some(tweak_data) = &self.tweak_data {
            pretty_map.insert(
                "tweak_data".to_string(),
                serde_json::Value::String(hex::encode(tweak_data)),
            );
        } else {
            pretty_map.insert(
                "tweak_data".to_string(),
                serde_json::Value::String("None".to_string()),
            );
        }
        pretty_map.insert(
            "subsession_id".to_string(),
            serde_json::Value::String(self.subsession_id.to_string()),
        );

        let mut participants_map = serde_json::Map::new();
        for (k, v) in &self.participants {
            participants_map.insert(hex::encode(k), serde_json::Value::String(v.to_fmt_string()));
        }
        pretty_map.insert(
            "participants".to_string(),
            serde_json::Value::Object(participants_map),
        );

        let mut joined_participants_map = serde_json::Map::new();
        for (k, v) in &self.joined_participants {
            joined_participants_map
                .insert(hex::encode(k), serde_json::Value::String(v.to_fmt_string()));
        }
        pretty_map.insert(
            "joined_participants".to_string(),
            serde_json::Value::Object(joined_participants_map),
        );

        pretty_map.insert(
            "pkid".to_string(),
            serde_json::Value::String(self.pkid.to_string()),
        );
        pretty_map.insert(
            "message".to_string(),
            serde_json::Value::String(hex::encode(&self.message)),
        );
        pretty_map.insert(
            "crypto_type".to_string(),
            serde_json::Value::String(format!("{:?}", self.crypto_type)),
        );

        serde_json::to_string_pretty(&serde_json::Value::Object(pretty_map)).unwrap()
    }
    pub fn _verify(&self) -> Result<(), String> {
        match self.crypto_type {
            CryptoType::P256 => self.verify::<crate::crypto::P256Sha256>(),
            CryptoType::Ed25519 => self.verify::<crate::crypto::Ed25519Sha512>(),
            CryptoType::Ed448 => self.verify::<crate::crypto::Ed448Shake256>(),
            CryptoType::Ristretto255 => self.verify::<crate::crypto::Ristretto255Sha512>(),
            CryptoType::Secp256k1 => self.verify::<crate::crypto::Secp256K1Sha256>(),
            CryptoType::Secp256k1Tr => self.verify::<crate::crypto::Secp256K1Sha256TR>(),
            CryptoType::EcdsaSecp256k1 => self.verify_ecdsa(),
        }
    }
    pub fn verify_ecdsa(&self) -> Result<(), String> {
        if self.crypto_type != CryptoType::EcdsaSecp256k1 {
            return Err(format!("Crypto type is not ecdsa-secp256k1"));
        }
        // signature must be 64 bytes
        if self.signature.len() != 64 {
            return Err(format!("Signature must be 64 bytes"));
        }
        let signature =
            ecdsa::Signature::from_compact(&self.signature).map_err(|e| e.to_string())?;
        if self.message.len() != 32 {
            return Err(format!("Message must be 32 bytes"));
        }
        let message = Message::from_digest(self.message.as_slice().try_into().unwrap());
        let secp = Secp256k1::verification_only();
        // pubkey must be 33 bytes or 65 bytes
        if self.pk.len() != 33 && self.pk.len() != 65 {
            return Err(format!("Public key must be 33 bytes or 65 bytes"));
        }
        let pubkey = PublicKey::from_slice(&self.pk_tweak).map_err(|e| e.to_string())?;
        if !secp.verify_ecdsa(&message, &signature, &pubkey).is_ok() {
            return Err(format!("Signature is invalid"));
        }
        Ok(())
    }
    pub fn verify<C: Cipher>(&self) -> Result<(), String> {
        let pk =
            <<C as Cipher>::PublicKeyPackage as PublicKeyPackage>::deserialize_binary(&self.pk)
                .map_err(|e| e.to_string())?;
        let pk_tweak = <<C as Cipher>::PublicKeyPackage as PublicKeyPackage>::deserialize_binary(
            &self.pk_tweak,
        )
        .map_err(|e| e.to_string())?;
        let signature = C::Signature::from_bytes(&self.signature).map_err(|e| e.to_string())?;
        let message = self.message.clone();
        let tweak_data = match self.tweak_data.clone() {
            Some(data) => Some(data),
            None => None,
        };
        if pk_tweak.pkid().unwrap() != pk.clone().tweak(tweak_data).pkid().unwrap() {
            return Err(format!("pk_tweak != pk"));
        }
        if self.pk_verifying_key_tweak
            != pk_tweak
                .verifying_key()
                .serialize_frost()
                .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "pk_verifying_key_tweak != pk_tweak.verifying_key()"
            ));
        }
        let pk_verifying_key_tweak =
            <<C as Cipher>::VerifyingKey as VerifyingKey>::deserialize_frost(
                &self.pk_verifying_key_tweak,
            )
            .map_err(|e| e.to_string())?;
        pk_verifying_key_tweak
            .verify(&message, &signature)
            .map_err(|e| e.to_string())
    }
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
    pub fn signature_with_rsv(&self) -> Result<Vec<u8>, String> {
        if self.signature.len() != 64 {
            return Err(format!("Signature must be 64 bytes"));
        }
        let signature = secp256k1::ecdsa::Signature::from_compact(&self.signature)
            .map_err(|e| e.to_string())?;
        let message = secp256k1::Message::from_digest(
            self.message
                .clone()
                .try_into()
                .map_err(|e| format!("Message must be 32 bytes: {:?}", e))?,
        );
        let secp = secp256k1::Secp256k1::verification_only();
        let pubkey = secp256k1::PublicKey::from_slice(&self.pk_tweak).map_err(|e| e.to_string())?;
        if !secp.verify_ecdsa(&message, &signature, &pubkey).is_ok() {
            return Err(format!("Signature is invalid"));
        }
        let recovery_id = (0..=1)
            .find_map(|v| {
                let rec_id = secp256k1::ecdsa::RecoveryId::try_from(v as i32).ok()?;
                let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                    &signature.serialize_compact(),
                    rec_id,
                )
                .ok()?;
                secp.recover_ecdsa(&message, &recoverable_sig).ok()?;
                Some(v as u8)
            })
            .ok_or(format!("Failed to recover signature"))?;
        let mut signature_with_rsv = self.signature.clone();
        signature_with_rsv.push(recovery_id);
        Ok(signature_with_rsv)
    }
}
impl<VII: ValidatorIdentityIdentity + Serialize + for<'de> Deserialize<'de>>
    SignatureSuiteInfo<VII>
{
    pub(crate) fn pretty_print_original(&self) -> String {
        format!(
            "{}\nVerification with encoded message: {}",
            self.pretty_print(),
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
            CryptoType::P256 => self.verify::<P256Sha256>().map_err(|e| e.to_string()),
            CryptoType::Ed448 => self.verify::<Ed448Shake256>().map_err(|e| e.to_string()),
            CryptoType::Ristretto255 => self
                .verify::<Ristretto255Sha512>()
                .map_err(|e| e.to_string()),
            CryptoType::EcdsaSecp256k1 => self.verify_ecdsa().map_err(|e| e.to_string()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ecdsa::SigningKey, SecretKey};
    use rand_core::OsRng;

    #[test]
    fn test_compressed_pk_k256() {
        let sk = SecretKey::random(&mut OsRng);
        let public_key = sk.public_key();
        let pk_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        let pk = GroupPublicKeyInfo::new(pk_bytes, None);
        let compressed_pk = pk.compressed_pk_k256().unwrap();
        assert_eq!(compressed_pk.len(), 33);
        let new_pk = GroupPublicKeyInfo::new(compressed_pk, None);
        let uncompressed_pk = new_pk.uncompressed_pk_k256().unwrap();
        assert_eq!(uncompressed_pk.len(), 65);
        assert_eq!(pk.group_public_key_tweak, uncompressed_pk);
    }
    #[test]
    fn test_signature_with_rsv() {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(secret_key.clone());
        let verify_key = k256::ecdsa::VerifyingKey::from(&signing_key);

        let public_key_bytes = verify_key.to_encoded_point(false).as_bytes().to_vec();

        let message = b"testtesttesttesttesttesttesttest";
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(message).unwrap();
        let mut sb = signature.to_vec();
        sb.push(recovery_id.to_byte() as u8);
        let suite = SignatureSuiteInfo::<sp_core::crypto::AccountId32> {
            signature: signature.to_vec(),
            pk: vec![],
            pk_tweak: public_key_bytes.clone(),
            pk_verifying_key: vec![],
            pk_verifying_key_tweak: vec![],
            tweak_data: None,
            subsession_id: SubsessionId::new(
                CryptoType::EcdsaSecp256k1,
                1,
                &Participants::<libp2p::PeerId, u16>::new(vec![(1, libp2p::PeerId::random())])
                    .unwrap(),
                message.to_vec(),
                None,
                PkId::new(vec![0x06; 33]),
            )
            .unwrap(),
            participants: BTreeMap::new(),
            joined_participants: BTreeMap::new(),
            pkid: PkId::new(vec![]),
            message: message.to_vec(),
            crypto_type: CryptoType::Secp256k1,
            original_serialized: "".to_string(),
        };
        let signature = suite.signature_with_rsv().unwrap();
        assert_eq!(signature.len(), 65);
        let signature_with_rsv = suite.signature_with_rsv();
        assert!(signature_with_rsv.is_ok());
        let signature_with_rsv = signature_with_rsv.unwrap();
        assert!(signature_with_rsv.len() == 65);
        // signature +cover_id must equal to signature_with_rsv
        let signature_with_rsv_bytes = signature_with_rsv.to_vec();

        assert_eq!(sb, signature_with_rsv_bytes);
    }
}
