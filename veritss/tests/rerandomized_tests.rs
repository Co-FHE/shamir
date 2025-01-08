use rand::thread_rng;
use veritss::ed25519::Ed25519Sha512;

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (_msg, _group_signature, _group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<Ed25519Sha512, _>(rng);
}
