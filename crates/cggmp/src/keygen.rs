//! Augmented key generation implementation.
//!
//! Ref: <https://wamu.tech/specification#key-generation>.

use curv::arithmetic::Converter;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::KeyGenBroadcastMessage1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, M};
use round_based::{Msg, StateMachine};
use std::ops::Deref;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::IdentityProvider;

use crate::augmented_state_machine;
use crate::augmented_state_machine::Error;
use crate::augmented_state_machine::{
    AugmentedStateMachine, AugmentedType, IdentityAuthParams, SubShareOutput,
};

/// A wrapper around the [`cggmp-threshold-ecdsa` Key Generation StateMachine](https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/src/protocols/multi_party_ecdsa/gg_2020/state_machine/keygen.rs) that [augments key generation as described by the Wamu protocol](https://wamu.tech/specification#key-generation).
pub struct AugmentedKeyGen<'a, I: IdentityProvider> {
    /// Wrapped `cggmp-threshold-ecdsa` Key Generation `StateMachine`.
    state_machine: Keygen,
    /// An augmented message queue.
    message_queue:
        Vec<Msg<AugmentedType<<Keygen as StateMachine>::MessageBody, IdentityAuthParams>>>,
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    parties: &'a [VerifyingKey],
}

impl<'a, I: IdentityProvider> AugmentedKeyGen<'a, I> {
    /// Initializes party for the augmented key generation protocol.
    pub fn new(
        identity_provider: &'a I,
        parties: &'a [VerifyingKey],
        idx: u16,
        threshold: u16,
        n_parties: u16,
    ) -> Result<Self, Error<<Keygen as StateMachine>::Err>> {
        // Initializes state machine.
        let mut aug_key_gen = Self {
            state_machine: Keygen::new(idx, threshold, n_parties)?,
            message_queue: Vec::new(),
            identity_provider,
            parties,
        };

        // Retrieves messages from immediate state transitions (if any) and augments them.
        aug_key_gen.update_augmented_message_queue()?;

        // Returns augmented state machine.
        Ok(aug_key_gen)
    }

    // For `cggmp-threshold-ecdsa`, key generation uses the GG20 implementation from ZenGo's `multi-party-ecdsa`.
    // So we hash parameters from Round 1 to achieve a similar commitment to V_i in CGGMP20.
    // Ref: <https://github.com/ZenGo-X/multi-party-ecdsa/>.
    // Ref: <https://eprint.iacr.org/2020/540.pdf>.
    fn parameter_hash(sender: u16, msg: &KeyGenBroadcastMessage1) -> Vec<u8> {
        use sha2::{digest::Update, Digest};
        let hasher = sha2::Sha256::new();
        hasher
            .chain(sender.to_be_bytes())
            .chain(msg.com.to_bytes())
            .chain(msg.e.n.to_bytes())
            .finalize()
            .deref()
            .to_vec()
    }
}

impl<'a, I: IdentityProvider> AugmentedStateMachine for AugmentedKeyGen<'a, I> {
    type StateMachineType = Keygen;
    type AdditionalParams = IdentityAuthParams;
    type AdditionalOutput = SubShareOutput;

    // Implements all required `AugmentedStateMachine` methods.
    impl_required_augmented_state_machine_methods!(state_machine, message_queue);

    fn pre_handle_incoming(
        &mut self,
        msg: &Msg<
            AugmentedType<
                <Self::StateMachineType as StateMachine>::MessageBody,
                Self::AdditionalParams,
            >,
        >,
    ) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        match &msg.body.base.0 {
            // Verifies the expected additional parameters from Round 1.
            M::Round1(out_msg) => match msg.body.extra.as_ref() {
                // Verifies that signer is an expected party/signatory and the signature is valid.
                Some(params) => Ok(wamu_core::wrappers::verify_request_with_signature(
                    &Self::parameter_hash(msg.sender, out_msg),
                    &params.verifying_key,
                    &params.verifying_signature,
                    self.parties,
                )?),
                // Returns an error if expected additional parameters are missing.
                None => Err(Error::MissingParams {
                    bad_actors: vec![msg.sender as usize],
                }),
            },
            // No modifications for other rounds.
            _ => Ok(()),
        }
    }

    fn augment_outgoing_message(
        &self,
        sender: u16,
        msg_body: &<Self::StateMachineType as StateMachine>::MessageBody,
    ) -> Result<Option<Self::AdditionalParams>, Error<<Self::StateMachineType as StateMachine>::Err>>
    {
        match &msg_body.0 {
            // Adds additional parameters to Round 1 messages.
            M::Round1(out_msg) => {
                let (verifying_key, verifying_signature) =
                    wamu_core::wrappers::initiate_request_with_signature(
                        &Self::parameter_hash(sender, out_msg),
                        self.identity_provider,
                    );
                Ok(Some(IdentityAuthParams {
                    verifying_key,
                    verifying_signature,
                }))
            }
            // No modifications for other rounds.
            _ => Ok(None),
        }
    }

    fn augment_output(
        &self,
        output: <Self::StateMachineType as StateMachine>::Output,
    ) -> Result<
        AugmentedType<<Self::StateMachineType as StateMachine>::Output, Self::AdditionalOutput>,
        Error<<Self::StateMachineType as StateMachine>::Err>,
    > {
        Ok(augmented_state_machine::split_key_output(
            self.identity_provider,
            output,
        )?)
    }
}

// Implements `StateMachine` trait for `AugmentedKeyGen`.
impl_state_machine_for_augmented_state_machine!(
    AugmentedKeyGen,
    Keygen,
    IdentityAuthParams,
    SubShareOutput
);

// Implement `Debug` trait for `AugmentedKeyGen` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for AugmentedKeyGen<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Augmented KeyGen")
    }
}

#[cfg(any(test, feature = "dev"))]
pub mod tests {
    use super::*;
    use curv::elliptic::curves::{Scalar, Secp256k1};
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    pub fn simulate_keygen(
        threshold: u16,
        n_parties: u16,
    ) -> (
        Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
        Vec<MockECDSAIdentityProvider>,
    ) {
        // Creates simulation.
        let mut simulation = Simulation::new();

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
        for (idx, identity_provider) in identity_providers.iter().enumerate() {
            simulation.add_party(
                AugmentedKeyGen::new(
                    identity_provider,
                    &verifying_keys,
                    (idx + 1) as u16,
                    threshold,
                    n_parties,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        (simulation.run().unwrap(), identity_providers)
    }

    #[test]
    fn keygen_works() {
        // Iterates over parameters for creating test cases with different thresholds and number of parties.
        // NOTE: Quorum size = threshold + 1
        for (threshold, n_parties) in [
            // 2/2 signing keys.
            (1, 2),
            // 3/4 signing keys.
            (2, 4),
        ] {
            // Runs keygen simulation for test parameters.
            let (keys, _) = simulate_keygen(threshold, n_parties);

            // Create copy of public key for later verification.
            let pub_key = keys[0].base.public_key();

            // Verifies the generated keys and configuration for all parties.
            assert_eq!(keys.len(), n_parties as usize);
            for key in keys {
                // Verifies threshold and number of parties.
                assert_eq!(key.base.t, threshold);
                assert_eq!(key.base.n, n_parties);
                // Verifies that the secret share was cleared/zerorized.
                assert_eq!(key.base.keys_linear.x_i, Scalar::<Secp256k1>::zero());
                // Verifies that the public key is the same for all parties.
                assert_eq!(key.base.public_key(), pub_key);
            }
        }
    }
}
