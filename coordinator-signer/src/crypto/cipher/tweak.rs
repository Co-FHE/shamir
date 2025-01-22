use std::collections::BTreeMap;

use super::{Cipher, KeyPackage, PublicKeyPackage, Signature};

pub trait Tweak {
    fn tweak<T: AsRef<[u8]>>(self, data: Option<T>) -> Self;
}
pub trait TweakCipher: Cipher
where
    Self::KeyPackage: Tweak,
    Self::PublicKeyPackage: Tweak,
{
    fn sign_with_tweak<T: AsRef<[u8]>, KeyPackageWithTweak: KeyPackage + Tweak>(
        signing_package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
        data: Option<T>,
    ) -> Result<Self::SignatureShare, Self::CryptoError> {
        let key_package = key_package.clone().tweak(data);
        Self::sign(signing_package, nonces, &key_package)
    }
    fn aggregate_with_tweak<T: AsRef<[u8]>>(
        signing_package: &Self::SigningPackage,
        signature_shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key: &Self::PublicKeyPackage,
        data: Option<T>,
    ) -> Result<Self::Signature, Self::CryptoError> {
        let public_key = public_key.clone().tweak(data);
        Self::aggregate(signing_package, signature_shares, &public_key)
    }
}
