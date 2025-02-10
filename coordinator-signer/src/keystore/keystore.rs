use super::KeystoreError;
use ring::{
    aead::{self, Aad, LessSafeKey, UnboundKey, CHACHA20_POLY1305},
    hkdf::{self, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use sha2::Digest;
use zeroize::Zeroize;
pub(crate) struct Keystore {
    salt: [u8; 16],
    derived_key: [u8; 32],
    origin_key: Vec<u8>,
}
impl Keystore {
    pub(crate) fn new<T: AsRef<[u8]>>(
        key: T,
        salt: Option<[u8; 16]>,
    ) -> Result<Self, KeystoreError> {
        let rng = SystemRandom::new();
        let salt_output = match salt {
            Some(s) => s,
            None => {
                let mut s = [0u8; 16];
                rng.fill(&mut s)
                    .map_err(|_| KeystoreError::KeyError("Failed to generate salt".to_string()))?;
                s
            }
        };

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_output);
        let prk = salt.extract(key.as_ref());
        let mut derived_key = [0u8; 32];
        let info = b"tss keystore";
        let binding = [info.as_ref()];
        let okm = prk
            .expand(&binding, HKDF_SHA256)
            .map_err(|_| KeystoreError::KeyError("Failed to derive key".to_string()))?;
        okm.fill(&mut derived_key)
            .map_err(|_| KeystoreError::KeyError("Failed to fill key".to_string()))?;
        Ok(Self {
            salt: salt_output,
            derived_key,
            origin_key: key.as_ref().to_vec(),
        })
    }
    #[cfg(test)]
    fn derived_key_equal(&self, other: [u8; 32]) -> bool {
        self.derived_key == other
    }
    pub(crate) fn original_hash(&self) -> [u8; 32] {
        sha2::Sha256::digest(&self.origin_key).into()
    }
    pub(crate) fn encrypt<T: AsRef<[u8]>>(&self, plaintext: T) -> Result<Vec<u8>, KeystoreError> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &self.derived_key)
            .map_err(|e| KeystoreError::KeyError(format!("Failed to create unbound key: {}", e)))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let mut nonce_bytes = [0u8; 12];
        let rng = SystemRandom::new();
        rng.fill(&mut nonce_bytes)
            .map_err(|_| KeystoreError::KeyError("Failed to generate salt".to_string()))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.as_ref().to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(b"tss keystore"), &mut in_out)
            .map_err(|e| KeystoreError::KeyError(format!("Failed to encrypt: {}", e)))?;
        let mut result = Vec::with_capacity(16 + 12 + in_out.len());
        result.extend_from_slice(&self.salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        Ok(result)
    }

    pub(crate) fn decrypt<T: AsRef<[u8]>>(&self, ciphertext: T) -> Result<Vec<u8>, KeystoreError> {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.len() < 28 {
            return Err(KeystoreError::KeyError("Ciphertext too short".to_string()));
        }
        let salt = ciphertext[..16].try_into().unwrap();
        let nonce_bytes = ciphertext[16..28].try_into().unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = ciphertext[28..].to_vec();
        // let mut ciphertext = ciphertext[28..ciphertext.len() - 16].to_vec();
        let key = Self::new(&self.origin_key, Some(salt))?;
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key.derived_key.as_ref())
            .map_err(|e| KeystoreError::KeyError(format!("Failed to create unbound key: {}", e)))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        less_safe_key
            .open_in_place(nonce, Aad::from(b"tss keystore"), &mut in_out)
            .map_err(|e| KeystoreError::KeyError(format!("Failed to decrypt: {}", e)))?;
        if in_out.len() < 16 {
            return Err(KeystoreError::KeyError("Failed to decrypt".to_string()));
        }
        Ok(in_out[..in_out.len() - 16].to_vec())
    }
}
impl Zeroize for Keystore {
    fn zeroize(&mut self) {
        self.derived_key.zeroize();
        self.salt.zeroize();
        self.origin_key.zeroize();
    }
}
#[cfg(test)]
mod tests {

    use crate::utils;
    use proptest::prelude::*;

    use super::*;
    #[test]
    fn test_keystore_new() {
        let key = b"key";
        let salt = Some([0; 16]);
        let keystore = Keystore::new(key, salt).unwrap();
        assert!(keystore.derived_key_equal([
            138, 244, 237, 242, 121, 188, 209, 107, 106, 146, 139, 103, 194, 158, 73, 103, 154, 94,
            39, 63, 98, 61, 108, 99, 139, 99, 155, 218, 24, 179, 245, 183
        ]));
        let encrypted = keystore.encrypt("aaa").unwrap();
        let decrypted = keystore.decrypt(encrypted).unwrap();
        assert_eq!(b"aaa", decrypted.as_slice());
    }
    proptest! {
        #[test]
        fn test_encrypt_decrypt_proptest(
            key_len in 1..50000usize,
            plaintext_len in prop_oneof![0usize..1, 1..100000usize],
        ) {
            let key = utils::random_readable_string(key_len);
            let keystore = Keystore::new(key.clone(), None).unwrap();
            let plaintext = utils::random_readable_string(plaintext_len);
            let encrypted = keystore.encrypt(plaintext.clone()).unwrap();
            let decrypted = keystore.decrypt(encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }
}
