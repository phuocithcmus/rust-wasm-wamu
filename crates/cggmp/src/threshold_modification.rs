//! Threshold modification implementation.
//!
//! Ref: <https://wamu.tech/specification#threshold-modification>.

use curv::elliptic::curves::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use round_based::{Msg, StateMachine};
use std::collections::HashMap;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::{IdentityProvider, SigningShare, SubShare};

use crate::authorized_key_refresh::{AuthorizedKeyRefresh, Error, Message};
use crate::key_refresh::AugmentedKeyRefresh;
use crate::quorum_approval;
use crate::quorum_approval::QuorumApproval;

const THRESHOLD_MODIFICATION: &str = "threshold-modification";

/// A [StateMachine](StateMachine) that implements [threshold modification as described by the Wamu protocol](https://wamu.tech/specification#threshold-modification).
pub struct ThresholdModification<'a, I: IdentityProvider> {
    // Quorum approval.
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// Party index.
    idx: u16,
    /// The new threshold.
    // NOTE: Quorum size = threshold + 1
    new_threshold: u16,
    /// Total number of parties.
    n_parties: u16,

    // Key refresh.
    /// The "signing share" of the party
    /// (only `None` for the new parties, `Some` for all other parties).
    signing_share: &'a SigningShare,
    /// The "sub-share" of the party
    /// (only `None` for the new party, `Some` for all other parties).
    sub_share: &'a SubShare,
    /// Local key of the party (with secret share cleared/zerorized).
    local_key: LocalKey<Secp256k1>,
    /// Maps existing indices to new ones for refreshing parties.
    old_to_new_map: &'a HashMap<u16, u16>,

    // State machine management.
    /// Outgoing message queue.
    message_queue: Vec<Msg<Message<'a, I, quorum_approval::Message>>>,
    /// Quorum approval state machine (must succeed before key refresh is performed).
    auth_state_machine: QuorumApproval<'a, I>,
    /// Key refresh state machine (activated after successful quorum approval).
    refresh_state_machine: Option<AugmentedKeyRefresh<'a, I>>,
    /// Stores "out of order" messages.
    out_of_order_buffer: Vec<Msg<Message<'a, I, quorum_approval::Message>>>,
}

impl<'a, I: IdentityProvider> ThresholdModification<'a, I> {
    /// Initializes party for the threshold modification protocol.
    pub fn new(
        signing_share: &'a SigningShare,
        sub_share: &'a SubShare,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        // `LocalKey<Secp256k1>` with secret share set to zero.
        local_key: LocalKey<Secp256k1>,
        // NOTE: Quorum size = threshold + 1
        new_threshold: u16,
        old_to_new_map: &'a HashMap<u16, u16>,
        is_initiator: bool,
    ) -> Result<
        ThresholdModification<'a, I>,
        Error<'a, I, <QuorumApproval<'a, I> as StateMachine>::Err>,
    > {
        // Initializes quorum approval state machine.
        let auth_state_machine = QuorumApproval::new(
            THRESHOLD_MODIFICATION,
            identity_provider,
            verified_parties,
            local_key.i,
            local_key.t,
            local_key.n,
            is_initiator,
            false,
        );

        // Initializes threshold modification state machine.
        let mut threshold_modification = Self {
            // Quorum approval.
            identity_provider,
            verified_parties,
            idx: local_key.i,
            new_threshold,
            n_parties: local_key.n,
            // Key refresh.
            signing_share,
            sub_share,
            local_key,
            old_to_new_map,
            // State machine management.
            message_queue: Vec::new(),
            auth_state_machine,
            refresh_state_machine: None,
            out_of_order_buffer: Vec::new(),
        };

        // Retrieves messages from immediate state transitions (if any) and wraps them.
        threshold_modification.update_composite_message_queue()?;

        // Returns threshold modification machine.
        Ok(threshold_modification)
    }
}

impl<'a, I: IdentityProvider> AuthorizedKeyRefresh<'a, I> for ThresholdModification<'a, I> {
    type InitStateMachineType = QuorumApproval<'a, I>;

    impl_required_authorized_key_refresh_getters!(
        auth_state_machine,
        refresh_state_machine,
        message_queue,
        out_of_order_buffer
    );

    fn create_key_refresh(
        &mut self,
    ) -> Result<
        AugmentedKeyRefresh<'a, I>,
        Error<'a, I, <Self::InitStateMachineType as StateMachine>::Err>,
    > {
        // Initializes key refresh state machine.
        Ok(AugmentedKeyRefresh::new(
            Some(self.signing_share),
            Some(self.sub_share),
            self.identity_provider,
            self.verified_parties,
            Some(self.local_key.clone()),
            None,
            self.old_to_new_map,
            self.new_threshold,
            self.local_key.n,
            None,
        )?)
    }
}

impl_state_machine_for_authorized_key_refresh!(ThresholdModification, idx, n_parties);

// Implement `Debug` trait for `ThresholdModification` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for ThresholdModification<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share Addition")
    }
}

#[cfg(any(test, feature = "dev"))]
pub mod tests {
    use super::*;
    use crate::augmented_state_machine::{AugmentedType, SubShareOutput};
    use crate::keygen::tests::simulate_keygen;
    use curv::elliptic::curves::Scalar;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    pub fn simulate_threshold_modification(
        // Party key configs including the "signing share", "sub-share", identity provider and
        // `LocalKey<Secp256k1>` from `multi-party-ecdsa` with the secret share cleared/zerorized.
        party_key_configs: Vec<(
            &SigningShare,
            &SubShare,
            &impl IdentityProvider,
            LocalKey<Secp256k1>,
            bool, // Whether or not this party is the initiator.
        )>,
        current_to_new_idx_map: &HashMap<u16, u16>,
        new_threshold: u16,
    ) -> Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = party_key_configs
            .iter()
            .map(|(_, _, identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (signing_share, sub_share, identity_provider, local_key, is_initiator) in
            party_key_configs
        {
            simulation.add_party(
                ThresholdModification::new(
                    signing_share,
                    sub_share,
                    identity_provider,
                    &verifying_keys,
                    local_key,
                    new_threshold,
                    current_to_new_idx_map,
                    is_initiator,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    pub fn generate_parties_and_simulate_threshold_modification(
        threshold_init: u16,
        threshold_new: u16,
        n_parties: u16,
        initiating_party_idx: u16,
    ) -> (
        Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
        Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
        Vec<MockECDSAIdentityProvider>,
    ) {
        // Verifies parameter invariants.
        assert!(threshold_init >= 1, "minimum threshold is one");
        assert!(
            n_parties > threshold_init,
            "threshold must be less than the total number of parties"
        );
        assert!(
            n_parties > threshold_new,
            "threshold must be less than the total number of parties"
        );

        // Runs key gen simulation for test parameters.
        let (keys, identity_providers) = simulate_keygen(threshold_init, n_parties);
        // Verifies that we got enough keys and identities for "existing" parties from keygen.
        assert_eq!(keys.len(), identity_providers.len());
        assert_eq!(keys.len(), n_parties as usize);

        // Keep copy of current public key for later verification.
        let pub_key_init = keys[0].base.public_key();

        // Creates key configs and party indices for continuing/existing parties.
        let mut party_key_configs = Vec::new();
        let mut current_to_new_idx_map = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            // Create party key config and index entry.
            let idx = i as u16 + 1;
            let (signing_share, sub_share) = key.extra.as_ref().unwrap();
            let local_key = key.base.clone();
            current_to_new_idx_map.insert(local_key.i, idx);
            party_key_configs.push((
                signing_share,
                sub_share,
                &identity_providers[i],
                local_key,
                idx == initiating_party_idx,
            ));
        }

        // Runs threshold modification simulation for test parameters.
        let new_keys = simulate_threshold_modification(
            party_key_configs,
            &current_to_new_idx_map,
            threshold_new,
        );

        // Verifies the refreshed/generated keys and configuration for all parties.
        assert_eq!(new_keys.len(), n_parties as usize);
        for (i, new_key) in new_keys.iter().enumerate() {
            // Verifies threshold and number of parties.
            assert_eq!(new_key.base.t, threshold_new);
            assert_eq!(new_key.base.n, n_parties);
            // Verifies that the secret share was cleared/zerorized.
            assert_eq!(new_key.base.keys_linear.x_i, Scalar::<Secp256k1>::zero());
            // Verifies that the public key hasn't changed.
            assert_eq!(new_key.base.public_key(), pub_key_init);
            // Verifies that the "signing share" and "sub-share" have changed for existing/continuing parties.
            if let Some(prev_key) = keys.get(i) {
                let (prev_signing_share, prev_sub_share) = prev_key.extra.as_ref().unwrap();
                let (new_signing_share, new_sub_share) = new_key.extra.as_ref().unwrap();
                assert_ne!(
                    new_signing_share.to_be_bytes(),
                    prev_signing_share.to_be_bytes()
                );
                assert_ne!(new_sub_share.as_tuple(), prev_sub_share.as_tuple());
            }
        }

        (keys, new_keys, identity_providers)
    }

    #[test]
    fn threshold_modification_works() {
        generate_parties_and_simulate_threshold_modification(1, 2, 4, 2);
    }
}
