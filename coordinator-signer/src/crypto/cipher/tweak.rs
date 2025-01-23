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
}
