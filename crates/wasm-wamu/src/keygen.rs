use k256::ecdsa::{signature::Signer, SigningKey};
use rand::prelude::*;
use wamu_cggmp::AugmentedKeyGen;
use wamu_core::crypto::VerifyingKey;
use wamu_core::test_utils::MockECDSAIdentityProvider;
use wamu_core::IdentityProvider;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn keygen(threshold: u16, n_parties: u16) -> String {
    let mut v: Vec<AugmentedKeyGen<MockECDSAIdentityProvider>> = Vec::new();

    // Creates identity providers for all other parties.
    let identity_providers: Vec<MockECDSAIdentityProvider> = (1..=n_parties)
        .map(|_| MockECDSAIdentityProvider::generate())
        .collect();

    // Creates a list of verifying keys for all parties.
    let verifying_keys: Vec<VerifyingKey> = identity_providers
        .iter()
        .map(IdentityProvider::verifying_key)
        .collect();

    // Adds parties to simulation.
    // for (idx, identity_provider) in identity_providers.iter().enumerate() {
    //     v.push(
    //         AugmentedKeyGen::new(
    //             identity_provider,
    //             &verifying_keys,
    //             (idx + 1) as u16,
    //             threshold,
    //             n_parties,
    //         )
    //         .unwrap(),
    //     )
    // }
    // Runs simulation and returns output.
    "a".to_string()
}
