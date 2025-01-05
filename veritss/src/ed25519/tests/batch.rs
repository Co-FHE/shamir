use rand::thread_rng;

use crate::*;
use ed25519::Ed25519Sha512;

#[test]
fn check_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::batch_verify::<Ed25519Sha512, _>(rng);
}

#[test]
fn check_bad_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::bad_batch_verify::<Ed25519Sha512, _>(rng);
}

#[test]
fn empty_batch_verify() {
    let rng = thread_rng();

    frost_core::tests::batch::empty_batch_verify::<Ed25519Sha512, _>(rng);
}
