use frost_core::{Ciphersuite, Identifier};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use veritss::ed25519::Ed25519Sha512;
use veritss::secp256k1::Secp256K1Sha256;
// pub struct Coordinator {
//     identifiers: Vec<>
// }
// pub struct Session<C: frost_core::Ciphersuite> {
//     round1_packages: BTreeMap<Identifier<C>, frost_core::keys::dkg::round1::Package<C>>,
//     round2_packages: BTreeMap<Identifier<C>, frost_core::keys::dkg::round2::Package<C>>,
// }

// impl<C: frost_core::Ciphersuite> Session<C> {
//     fn handle_round1(&self) -> Result<(), Error> {
//         Ok(())
//     }
//     fn handle_round2(&self, package: Self::PackageRound2) -> Result<(), Error> {
//         Ok(())
//     }
// }

// pub enum SessionWrapper {
//     Ed25519Sha512(Session<Ed25519Sha512>),
//     Secp256K1Sha256(Session<Secp256K1Sha256>),
// }
