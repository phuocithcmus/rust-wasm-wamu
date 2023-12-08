//! Augmented key refresh implementation.
//!
//! Ref: <https://wamu.tech/specification#key-refresh>.

use cggmp_threshold_ecdsa::refresh::state_machine::{KeyRefresh, M};
use cggmp_threshold_ecdsa::utilities::sha2::Sha256;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Scalar, Secp256k1};
use fs_dkr::add_party_message::JoinMessage;
use fs_dkr::refresh_message::RefreshMessage;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use round_based::{Msg, StateMachine};
use std::collections::HashMap;
use std::ops::Deref;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::{IdentityProvider, SigningShare, SubShare};

use crate::augmented_state_machine;
use crate::augmented_state_machine::Error;
use crate::augmented_state_machine::{
    AugmentedStateMachine, AugmentedType, IdentityAuthParams, SubShareOutput,
};

/// A wrapper around the [`cggmp-threshold-ecdsa` Key Refresh StateMachine](https://github.com/webb-tools/cggmp-threshold-ecdsa/blob/main/src/refresh/state_machine.rs) that [augments key refresh as described by the Wamu protocol](https://wamu.tech/specification#key-refresh).
pub struct AugmentedKeyRefresh<'a, I: IdentityProvider> {
    /// Wrapped `cggmp-threshold-ecdsa` Key Refresh `StateMachine`.
    state_machine: KeyRefresh,
    /// An augmented message queue.
    message_queue:
        Vec<Msg<AugmentedType<<KeyRefresh as StateMachine>::MessageBody, IdentityAuthParams>>>,
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// Indexes of existing parties.
    existing_parties: Vec<u16>,
}

impl<'a, I: IdentityProvider> AugmentedKeyRefresh<'a, I> {
    /// Initializes party for the augmented key refresh protocol.
    pub fn new(
        signing_share_option: Option<&SigningShare>,
        sub_share_option: Option<&SubShare>,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        // `LocalKey<Secp256k1>` with secret share set to zero.
        mut local_key_option: Option<LocalKey<Secp256k1>>,
        new_party_index_option: Option<u16>,
        old_to_new_map: &HashMap<u16, u16>,
        // NOTE: FS-DKR operates in the honest majority setting, so threshold <= n_parties/2 must hold.
        new_threshold: u16,
        n_parties: u16,
        current_threshold_option: Option<u16>,
    ) -> Result<Self, Error<<KeyRefresh as StateMachine>::Err>> {
        // For `cggmp-threshold-ecdsa`, key refresh is based on FS-DKR,
        // which is a modified version of FS-DKG (Fouque-Stern Distributed Key Generation).
        // FS-DKR operates in the honest majority setting, so threshold <= n_parties/2 must hold.
        // Ref: <https://github.com/ZenGo-X/fs-dkr#adjusting-fs-dkg-to-dkr-and-threshold-ecdsa>.
        // Ref: <https://inria.hal.science/inria-00565274/document>.
        if new_threshold > n_parties / 2 {
            return Err(Error::BadFSDKRThreshold);
        }

        // Reconstruct secret share if "signing share" and "sub-share" are provided and update `LocalKey<Secp256k1>` (if provided) with the reconstructed secret share.
        if let Some((local_key, (signing_share, sub_share))) = local_key_option
            .as_mut()
            .zip(signing_share_option.zip(sub_share_option))
        {
            // Reconstructs secret share.
            let secret_share = wamu_core::share_split_reconstruct::reconstruct(
                signing_share,
                sub_share,
                identity_provider,
            )?;
            // Sets the reconstructed secret share.
            local_key.keys_linear.x_i =
                Scalar::<Secp256k1>::from_bytes(&secret_share.to_be_bytes())
                    .map_err(|_| Error::Core(wamu_core::Error::Encoding))?;
        }

        // Initializes state machine.
        let mut aug_key_refresh = Self {
            state_machine: KeyRefresh::new(
                local_key_option,
                new_party_index_option,
                old_to_new_map,
                new_threshold,
                n_parties,
                current_threshold_option,
            )?,
            message_queue: Vec::new(),
            identity_provider,
            verified_parties,
            existing_parties: old_to_new_map.values().copied().collect::<Vec<u16>>(),
        };

        // Retrieves messages from immediate state transitions (if any) and augments them.
        aug_key_refresh.update_augmented_message_queue()?;

        // Returns augmented state machine.
        Ok(aug_key_refresh)
    }

    // For `cggmp-threshold-ecdsa`, key refresh is based on FS-DKR,
    // which is a modified version of FS-DKG (Fouque-Stern Distributed Key Generation).
    // So we hash parameters from Round 1 (for new parties) or Round 2 (for existing parties)
    // to achieve a similar commitment to V_i in CGGMP20.
    // Ref: <https://github.com/ZenGo-X/fs-dkr#adjusting-fs-dkg-to-dkr-and-threshold-ecdsa>.
    // Ref: <https://inria.hal.science/inria-00565274/document>.
    fn parameter_hash(sender: u16, msg: InitiationMessage) -> Vec<u8> {
        let (ek_n, rp_n, rp_s, rp_t) = match msg {
            InitiationMessage::Join(inner_msg) => (
                &inner_msg.ek.n,
                &inner_msg.ring_pedersen_statement.N,
                &inner_msg.ring_pedersen_statement.S,
                &inner_msg.ring_pedersen_statement.T,
            ),
            InitiationMessage::Refresh(inner_msg) => (
                &inner_msg.ek.n,
                &inner_msg.ring_pedersen_statement.N,
                &inner_msg.ring_pedersen_statement.S,
                &inner_msg.ring_pedersen_statement.T,
            ),
        };
        use sha2::{digest::Update, Digest};
        let hasher = sha2::Sha256::new();
        hasher
            .chain(sender.to_be_bytes())
            .chain(ek_n.to_bytes())
            .chain(rp_n.to_bytes())
            .chain(rp_s.to_bytes())
            .chain(rp_t.to_bytes())
            .finalize()
            .deref()
            .to_vec()
    }
}

enum InitiationMessage<'a> {
    Join(&'a JoinMessage<Secp256k1, Sha256, 80>),
    Refresh(&'a RefreshMessage<Secp256k1, Sha256, 80>),
}

impl<'a, I: IdentityProvider> AugmentedStateMachine for AugmentedKeyRefresh<'a, I> {
    type StateMachineType = KeyRefresh;
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
            // Verifies the expected additional parameters from Round 1 for new parties.
            M::Round1(out_msg_option) => {
                if !self.existing_parties.contains(&msg.sender) {
                    match out_msg_option.as_ref().zip(msg.body.extra.as_ref()) {
                        // Verifies that signer is an expected party/signatory and the signature is valid.
                        Some((out_msg, params)) => {
                            Ok(wamu_core::wrappers::verify_request_with_signature(
                                &Self::parameter_hash(msg.sender, InitiationMessage::Join(out_msg)),
                                &params.verifying_key,
                                &params.verifying_signature,
                                self.verified_parties,
                            )?)
                        }
                        // Returns an error if expected additional parameters are missing for new parties.
                        None => Err(Error::MissingParams {
                            bad_actors: vec![msg.sender as usize],
                        }),
                    }
                } else {
                    // No Round 1 augmentations expected for existing parties.
                    Ok(())
                }
            }
            // Verifies the expected additional parameters from Round 2 for existing parties.
            M::Round2(out_msg_option) => {
                if self.existing_parties.contains(&msg.sender) {
                    match out_msg_option.as_ref().zip(msg.body.extra.as_ref()) {
                        // Verifies that signer is an expected party/signatory and the signature is valid.
                        Some((out_msg, params)) => {
                            Ok(wamu_core::wrappers::verify_request_with_signature(
                                &Self::parameter_hash(
                                    msg.sender,
                                    InitiationMessage::Refresh(out_msg),
                                ),
                                &params.verifying_key,
                                &params.verifying_signature,
                                self.verified_parties,
                            )?)
                        }
                        // Returns an error if expected additional parameters are missing for existing parties.
                        None => Err(Error::MissingParams {
                            bad_actors: vec![msg.sender as usize],
                        }),
                    }
                } else {
                    // No Round 2 augmentations expected for new parties.
                    Ok(())
                }
            }
        }
    }

    fn augment_outgoing_message(
        &self,
        sender: u16,
        msg_body: &<Self::StateMachineType as StateMachine>::MessageBody,
    ) -> Result<Option<Self::AdditionalParams>, Error<<Self::StateMachineType as StateMachine>::Err>>
    {
        match &msg_body.0 {
            // Adds additional parameters to Round 1 messages for new parties.
            M::Round1(it) => {
                if !self.existing_parties.contains(&sender) {
                    Ok(it.as_ref().map(|out_msg| {
                        let (verifying_key, verifying_signature) =
                            wamu_core::wrappers::initiate_request_with_signature(
                                &Self::parameter_hash(sender, InitiationMessage::Join(out_msg)),
                                self.identity_provider,
                            );
                        IdentityAuthParams {
                            verifying_key,
                            verifying_signature,
                        }
                    }))
                } else {
                    // No Round 1 augmentations expected for existing parties.
                    Ok(None)
                }
            }
            // Adds additional parameters to Round 2 messages for existing parties.
            M::Round2(it) => {
                if self.existing_parties.contains(&sender) {
                    Ok(it.as_ref().map(|out_msg| {
                        let (verifying_key, verifying_signature) =
                            wamu_core::wrappers::initiate_request_with_signature(
                                &Self::parameter_hash(sender, InitiationMessage::Refresh(out_msg)),
                                self.identity_provider,
                            );
                        IdentityAuthParams {
                            verifying_key,
                            verifying_signature,
                        }
                    }))
                } else {
                    // No Round 2 augmentations expected for new parties.
                    Ok(None)
                }
            }
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

// Implements `StateMachine` trait for `AugmentedKeyRefresh`.
impl_state_machine_for_augmented_state_machine!(
    AugmentedKeyRefresh,
    KeyRefresh,
    IdentityAuthParams,
    SubShareOutput
);

// Implement `Debug` trait for `AugmentedKeyRefresh` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for AugmentedKeyRefresh<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Augmented KeyRefresh")
    }
}

#[cfg(any(test, feature = "dev"))]
pub mod tests {
    use super::*;
    use crate::keygen;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    pub fn simulate_key_refresh(
        // Party key configs including the "signing share", "sub-share", identity provider and
        // `LocalKey<Secp256k1>` from `multi-party-ecdsa` with the secret share cleared/zerorized.
        party_key_configs: Vec<(
            Option<&SigningShare>,
            Option<&SubShare>,
            &impl IdentityProvider,
            Option<LocalKey<Secp256k1>>,
            Option<u16>, // new party index,
            Option<u16>, // current threshold (needed by new parties),
        )>,
        current_to_new_idx_map: &HashMap<u16, u16>,
        // NOTE: Quorum size = threshold + 1
        threshold: u16,
        n_parties: u16,
    ) -> Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = party_key_configs
            .iter()
            .map(|(_, _, identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (
            signing_share,
            sub_share,
            identity_provider,
            local_key,
            new_party_index,
            current_threshold_option,
        ) in party_key_configs
        {
            simulation.add_party(
                AugmentedKeyRefresh::new(
                    signing_share,
                    sub_share,
                    identity_provider,
                    &verifying_keys,
                    local_key,
                    new_party_index,
                    current_to_new_idx_map,
                    threshold,
                    n_parties,
                    current_threshold_option,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    // NOTE: FS-DKR operates in the honest majority setting, so t <= n/2 must hold.
    // NOTE: Quorum size = threshold + 1
    pub fn generate_parties_and_simulate_key_refresh(
        threshold_init: u16,
        n_parties_init: u16,
        threshold_new: u16,
        n_parties_new: u16,
    ) -> (
        (
            Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
            Vec<MockECDSAIdentityProvider>,
        ),
        (
            Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
            Vec<MockECDSAIdentityProvider>,
        ),
    ) {
        // Runs keygen simulation for test parameters.
        let (mut keys, mut identity_providers) =
            keygen::tests::simulate_keygen(threshold_init, n_parties_init);
        // Verifies that we got enough keys and identities for "existing" parties from keygen.
        assert_eq!(keys.len(), identity_providers.len());
        assert_eq!(keys.len(), n_parties_init as usize);

        // Keep copy of initial keys, identity providers and current public key for later verification.
        let keys_init = keys.clone();
        let identity_providers_init = identity_providers.clone();
        let pub_key_init = keys[0].base.public_key();

        // Removes some existing parties (if necessary).
        if n_parties_new < n_parties_init {
            keys.truncate(n_parties_new as usize);
            identity_providers.truncate(n_parties_new as usize);
        }

        // Creates identity providers for new parties (if necessary).
        if n_parties_new > n_parties_init {
            identity_providers.extend(
                (1..=(n_parties_new - n_parties_init))
                    .map(|_| MockECDSAIdentityProvider::generate()),
            );
        }

        // Creates key configs and party indices for continuing/existing parties.
        let mut party_key_configs = Vec::new();
        let mut current_to_new_idx_map = HashMap::new();
        for (i, identity_provider) in identity_providers.iter().enumerate() {
            // Create party key config and index entry.
            let idx = i as u16 + 1;
            let key_option = keys.get(i);
            let local_key_option = key_option.map(|key| key.base.clone());
            let share_output_option = key_option.map(|key| key.extra.as_ref().unwrap());
            let signing_share_option = share_output_option.map(|(signing_share, _)| signing_share);
            let sub_share_option = share_output_option.map(|(_, sub_share)| sub_share);
            if let Some(local_key) = local_key_option.as_ref() {
                current_to_new_idx_map.insert(local_key.i, idx);
            }
            party_key_configs.push((
                signing_share_option,
                sub_share_option,
                identity_provider,
                local_key_option,
                key_option.is_none().then_some(idx),
                key_option.is_none().then_some(threshold_init),
            ));
        }

        // Runs key refresh simulation for test parameters.
        let keys_new = simulate_key_refresh(
            party_key_configs,
            &current_to_new_idx_map,
            threshold_new,
            n_parties_new,
        );

        // Verifies the refreshed/generated keys and configuration for all parties.
        assert_eq!(keys_new.len(), n_parties_new as usize);
        for key in keys_new.iter() {
            // Verifies threshold and number of parties.
            assert_eq!(key.base.t, threshold_new);
            assert_eq!(key.base.n, n_parties_new);
            // Verifies that the secret share was cleared/zerorized.
            assert_eq!(key.base.keys_linear.x_i, Scalar::<Secp256k1>::zero());
            // Verifies that the public key hasn't changed.
            assert_eq!(key.base.public_key(), pub_key_init);
        }

        (
            (keys_init, identity_providers_init),
            (keys_new, identity_providers),
        )
    }

    // Same parties, same threshold.
    #[test]
    fn key_refresh_same_parties_same_threshold_works() {
        generate_parties_and_simulate_key_refresh(1, 2, 1, 2);
    }

    // Same parties, new threshold.
    #[test]
    fn key_refresh_same_parties_new_threshold_works() {
        generate_parties_and_simulate_key_refresh(1, 4, 2, 4);
    }

    // New parties, same threshold.
    #[test]
    fn key_refresh_new_parties_same_threshold_works() {
        generate_parties_and_simulate_key_refresh(1, 2, 1, 3);
    }

    // New parties, new threshold.
    #[test]
    fn key_refresh_new_parties_new_threshold_works() {
        generate_parties_and_simulate_key_refresh(1, 2, 2, 4);
    }

    // Remove parties, same threshold.
    #[test]
    fn key_refresh_remove_parties_same_threshold_works() {
        generate_parties_and_simulate_key_refresh(1, 3, 1, 2);
    }

    // Remove parties, new threshold.
    #[test]
    fn key_refresh_remove_parties_new_threshold_works() {
        generate_parties_and_simulate_key_refresh(2, 4, 1, 3);
    }
}
