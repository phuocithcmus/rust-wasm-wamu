//! Augmented signing implementation.
//!
//! Ref: <https://wamu.tech/specification#signing>.

use cggmp_threshold_ecdsa::presign::state_machine::PreSigning;
use cggmp_threshold_ecdsa::presign::{
    PreSigningSecrets, PresigningOutput, PresigningTranscript, SSID,
};
use cggmp_threshold_ecdsa::sign::state_machine::{Signing, M};
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Scalar, Secp256k1};
use curv::BigInt;
use round_based::{Msg, StateMachine};
use std::collections::HashMap;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::{IdentityProvider, SigningShare, SubShare};

use crate::augmented_state_machine::Error;
use crate::augmented_state_machine::{AugmentedStateMachine, AugmentedType, IdentityAuthParams};

/// A wrapper around the [`cggmp-threshold-ecdsa` Signing StateMachine](https://github.com/webb-tools/cggmp-threshold-ecdsa/blob/main/src/sign/state_machine.rs) that [augments signing as described by the Wamu protocol](https://wamu.tech/specification#signing).
pub struct AugmentedSigning<'a, I: IdentityProvider> {
    /// Wrapped `cggmp-threshold-ecdsa` Signing `StateMachine`.
    state_machine: Signing,
    /// An augmented message queue.
    message_queue:
        Vec<Msg<AugmentedType<<Signing as StateMachine>::MessageBody, IdentityAuthParams>>>,
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// A byte representation of the message to be signed.
    message: &'a [u8],
}

impl<'a, I: IdentityProvider> AugmentedSigning<'a, I> {
    /// Initializes party for the augmented signing protocol.
    pub fn new(
        signing_share: &SigningShare,
        sub_share: &SubShare,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        message: &'a [u8],
        mut ssid: SSID<Secp256k1>,
        presigning_data: HashMap<
            u16,
            (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>),
        >,
        // l in the CGGMP20 paper.
        pre_signing_output_idx: usize,
    ) -> Result<Self, Error<<Signing as StateMachine>::Err>> {
        // Reconstructs secret share.
        let secret_share = wamu_core::share_split_reconstruct::reconstruct(
            signing_share,
            sub_share,
            identity_provider,
        )?;
        // Sets the reconstructed secret share.
        ssid.X.keys_linear.x_i = Scalar::<Secp256k1>::from_bytes(&secret_share.to_be_bytes())
            .map_err(|_| Error::Core(wamu_core::Error::Encoding))?;

        // Creates a SHA256 message digest.
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        let message_digest = hasher.finalize();

        // Initializes state machine.
        let mut aug_signing = Self {
            state_machine: Signing::new(
                ssid,
                pre_signing_output_idx,
                BigInt::from_bytes(&message_digest),
                presigning_data,
            )?,
            message_queue: Vec::new(),
            identity_provider,
            verified_parties,
            message,
        };

        // Retrieves messages from immediate state transitions (if any) and augments them.
        aug_signing.update_augmented_message_queue()?;

        // Returns augmented state machine.
        Ok(aug_signing)
    }
}

impl<'a, I: IdentityProvider> AugmentedStateMachine for AugmentedSigning<'a, I> {
    type StateMachineType = Signing;
    type AdditionalParams = IdentityAuthParams;
    type AdditionalOutput = AdditionalOutput;

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
        match msg.body.base.0 {
            // Verifies the expected additional parameters from Round 1.
            // Round 2 of `cggmp-threshold-ecdsa` Signing is the Output phase,
            M::Round1(_) => match msg.body.extra.as_ref() {
                // Verifies that signer is an expected party/signatory and the signature is valid.
                Some(params) => Ok(wamu_core::wrappers::verify_request_with_signature(
                    self.message,
                    &params.verifying_key,
                    &params.verifying_signature,
                    self.verified_parties,
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
        _: u16,
        msg_body: &<Self::StateMachineType as StateMachine>::MessageBody,
    ) -> Result<Option<Self::AdditionalParams>, Error<<Self::StateMachineType as StateMachine>::Err>>
    {
        match msg_body.0 {
            // Adds additional parameters to Round 1 messages.
            M::Round1(_) => {
                let (verifying_key, verifying_signature) =
                    wamu_core::wrappers::initiate_request_with_signature(
                        self.message,
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
}

// No additional output.
type AdditionalOutput = ();

// Implements `StateMachine` trait for `AugmentedSigning`.
impl_state_machine_for_augmented_state_machine!(
    AugmentedSigning,
    Signing,
    IdentityAuthParams,
    AdditionalOutput
);

/// A wrapper around the [`cggmp-threshold-ecdsa` PreSigning StateMachine](https://github.com/webb-tools/cggmp-threshold-ecdsa/blob/main/src/presign/state_machine.rs) that [augments pre-signing as described by the Wamu protocol](https://wamu.tech/specification#signing).
pub struct AugmentedPreSigning<'a, I: IdentityProvider> {
    /// Wrapped `cggmp-threshold-ecdsa` PreSigning `StateMachine`.
    state_machine: PreSigning,
    /// An augmented message queue.
    message_queue:
        Vec<Msg<AugmentedType<<PreSigning as StateMachine>::MessageBody, AdditionalParams>>>,
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
}

impl<'a, I: IdentityProvider> AugmentedPreSigning<'a, I> {
    /// Initializes party for the augmented pre-signing protocol.
    pub fn new(
        signing_share: &SigningShare,
        sub_share: &SubShare,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        mut ssid: SSID<Secp256k1>,
        secrets: PreSigningSecrets,
        aux_ring_pedersen_s_values: HashMap<u16, BigInt>,
        aux_ring_pedersen_t_values: HashMap<u16, BigInt>,
        aux_ring_pedersen_n_hat_values: HashMap<u16, BigInt>,
        // l in the CGGMP20 paper.
        pre_signing_output_idx: usize,
    ) -> Result<Self, Error<<PreSigning as StateMachine>::Err>> {
        // Reconstructs secret share.
        let secret_share = wamu_core::share_split_reconstruct::reconstruct(
            signing_share,
            sub_share,
            identity_provider,
        )?;
        // Sets the reconstructed secret share.
        ssid.X.keys_linear.x_i = Scalar::<Secp256k1>::from_bytes(&secret_share.to_be_bytes())
            .map_err(|_| Error::Core(wamu_core::Error::Encoding))?;

        // Initializes state machine.
        let mut aug_signing = Self {
            state_machine: PreSigning::new(
                ssid,
                secrets,
                aux_ring_pedersen_s_values,
                aux_ring_pedersen_t_values,
                aux_ring_pedersen_n_hat_values,
                pre_signing_output_idx,
            )?,
            message_queue: Vec::new(),
            identity_provider,
            verified_parties,
        };

        // Retrieves messages from immediate state transitions (if any) and augments them.
        aug_signing.update_augmented_message_queue()?;

        // Returns augmented state machine.
        Ok(aug_signing)
    }
}

impl<'a, I: IdentityProvider> AugmentedStateMachine for AugmentedPreSigning<'a, I> {
    type StateMachineType = PreSigning;
    type AdditionalParams = ();
    type AdditionalOutput = ();

    // Implements all required `AugmentedStateMachine` methods.
    impl_required_augmented_state_machine_methods!(state_machine, message_queue);
}

// No additional params.
type AdditionalParams = ();

// Implements `StateMachine` trait for `AugmentedSigning`.
impl_state_machine_for_augmented_state_machine!(
    AugmentedPreSigning,
    PreSigning,
    AdditionalParams,
    AdditionalOutput
);

// Implement `Debug` trait for `AugmentedSigning` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for AugmentedSigning<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Augmented Signing")
    }
}

// Implement `Debug` trait for `AugmentedPreSigning` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for AugmentedPreSigning<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Augmented Pre-signing")
    }
}

#[cfg(any(test, feature = "dev"))]
pub mod tests {
    use crate::augmented_state_machine::SubShareOutput;
    use cggmp_threshold_ecdsa::sign::SigningOutput;
    use cggmp_threshold_ecdsa::utilities::sha2::Sha256;
    use curv::arithmetic::traits::{Modulo, One, Samplable};
    use curv::arithmetic::Integer;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::{Point, Scalar};
    use fs_dkr::ring_pedersen_proof::RingPedersenStatement;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    use super::*;
    use crate::keygen::tests::simulate_keygen;

    pub fn simulate_sign(
        keys_and_pre_signing_output: Vec<(
            &SigningShare,
            &SubShare,
            &MockECDSAIdentityProvider,
            SSID<Secp256k1>,
            HashMap<u16, (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
        )>,
        message: &[u8],
        pre_signing_output_idx: usize,
    ) -> Vec<AugmentedType<Option<SigningOutput<Secp256k1>>, AdditionalOutput>> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = keys_and_pre_signing_output
            .iter()
            .map(|(_, _, identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (signing_share, sub_share, identity_provider, ssid, pre_signing_data) in
            keys_and_pre_signing_output.into_iter()
        {
            // Add party to simulation.
            simulation.add_party(
                AugmentedSigning::new(
                    signing_share,
                    sub_share,
                    identity_provider,
                    &verifying_keys,
                    message,
                    ssid.clone(),
                    pre_signing_data.clone(),
                    pre_signing_output_idx,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    pub fn simulate_pre_sign(
        inputs: Vec<(
            &SigningShare,
            &SubShare,
            &MockECDSAIdentityProvider,
            SSID<Secp256k1>,
            PreSigningSecrets,
            HashMap<u16, BigInt>,
            HashMap<u16, BigInt>,
            HashMap<u16, BigInt>,
        )>,
        pre_signing_output_idx: usize,
    ) -> Vec<
        AugmentedType<
            Option<(PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
            AdditionalOutput,
        >,
    > {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = inputs
            .iter()
            .map(|(_, _, identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (
            signing_share,
            sub_share,
            identity_provider,
            ssid,
            secrets,
            aux_ring_pedersen_n_hat_values,
            aux_ring_pedersen_s_values,
            aux_ring_pedersen_t_values,
        ) in inputs.into_iter()
        {
            // Add party to simulation.
            simulation.add_party(
                AugmentedPreSigning::new(
                    signing_share,
                    sub_share,
                    identity_provider,
                    &verifying_keys,
                    ssid,
                    secrets,
                    aux_ring_pedersen_s_values,
                    aux_ring_pedersen_t_values,
                    aux_ring_pedersen_n_hat_values,
                    pre_signing_output_idx,
                )
                .unwrap(),
            );
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    pub fn generate_pre_sign_input<'a, 'b>(
        aug_keys: &'a [AugmentedType<LocalKey<Secp256k1>, SubShareOutput>],
        identity_providers: &'b [MockECDSAIdentityProvider],
        n_participants: u16,
    ) -> Vec<(
        &'a SigningShare,
        &'a SubShare,
        &'b MockECDSAIdentityProvider,
        SSID<Secp256k1>,
        PreSigningSecrets,
        HashMap<u16, BigInt>,
        HashMap<u16, BigInt>,
        HashMap<u16, BigInt>,
    )> {
        // Generates auxiliary "ring" Pedersen parameters for all participants.
        let mut aux_ring_pedersen_n_hat_values = HashMap::with_capacity(aug_keys.len());
        let mut aux_ring_pedersen_s_values = HashMap::with_capacity(aug_keys.len());
        let mut aux_ring_pedersen_t_values = HashMap::with_capacity(aug_keys.len());
        for idx in 1..=n_participants {
            let (ring_pedersen_params, _) = RingPedersenStatement::<Secp256k1, Sha256>::generate();
            aux_ring_pedersen_n_hat_values.insert(idx, ring_pedersen_params.N);
            aux_ring_pedersen_s_values.insert(idx, ring_pedersen_params.S);
            aux_ring_pedersen_t_values.insert(idx, ring_pedersen_params.T);
        }
        // Reconstructs secret shares, creates pre-signing inputs and auxiliary parameters for ZK proofs.
        let generator = Point::<Secp256k1>::generator().to_point();
        let group_order = Scalar::<Secp256k1>::group_order();
        let party_indices: Vec<u16> = (1..=n_participants).collect();
        aug_keys[0..n_participants as usize]
            .iter()
            .enumerate()
            .map(|(i, aug_key)| {
                // Creates SSID and pre-signing secrets.
                // Extracts "signing share", "sub-share" and local key.
                let (signing_share, sub_share) = aug_key.extra.as_ref().unwrap();
                let secret_share = wamu_core::share_split_reconstruct::reconstruct(
                    signing_share,
                    sub_share,
                    &identity_providers[i],
                )
                .unwrap();
                let local_key = aug_key.base.clone();
                // We already have Paillier keys from GG20 key gen or FS-DKR so we just reuse them.
                let paillier_ek = local_key.paillier_key_vec[local_key.i as usize - 1].clone();
                let paillier_dk = local_key.paillier_dk.clone();
                // See Figure 6, Round 1.
                // Ref: <https://eprint.iacr.org/2021/060.pdf>.
                let phi = (&paillier_dk.p - BigInt::one()) * (&paillier_dk.q - BigInt::one());
                let r = BigInt::sample_below(&paillier_ek.n);
                let lambda = BigInt::sample_below(&phi);
                let t = BigInt::mod_pow(&r, &BigInt::from(2), &paillier_ek.n);
                let s = BigInt::mod_pow(&t, &lambda, &paillier_ek.n);
                // Composes SSID.
                let ssid = SSID {
                    g: generator.clone(),
                    q: group_order.clone(),
                    P: party_indices.clone(),
                    rid: wamu_core::crypto::Random32Bytes::generate().to_be_bytes(),
                    X: local_key,
                    Y: None, // Y is not needed for 4-round signing.
                    N: paillier_ek.n.clone(),
                    S: s,
                    T: t,
                };
                // Composes pre-signing secrets.
                let pre_sign_secrets = PreSigningSecrets {
                    x_i: BigInt::from_bytes(&secret_share.to_be_bytes()),
                    y_i: None, // Y is not needed for 4-round signing.
                    ek: paillier_ek,
                    dk: paillier_dk,
                };

                (
                    signing_share,
                    sub_share,
                    &identity_providers[i],
                    ssid,
                    pre_sign_secrets,
                    aux_ring_pedersen_n_hat_values.clone(),
                    aux_ring_pedersen_s_values.clone(),
                    aux_ring_pedersen_t_values.clone(),
                )
            })
            .collect()
    }

    // NOTE: Quorum size = threshold + 1
    pub fn generate_parties_and_simulate_signing(
        threshold: u16,
        n_parties: u16,
        n_participants: u16,
    ) -> (
        Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
        Vec<MockECDSAIdentityProvider>,
        Vec<AugmentedType<Option<SigningOutput<Secp256k1>>, AdditionalOutput>>,
    ) {
        // Verifies parameter invariants.
        assert!(threshold >= 1, "minimum threshold is one");
        assert!(
            n_parties > threshold,
            "threshold must be less than the total number of parties"
        );
        assert!(
            n_participants > threshold,
            "number of participants must be a valid quorum, quorum size = threshold + 1"
        );
        assert!(
            n_parties >= n_participants,
            "number of participants must be less than or equal to the total number of parties"
        );

        // Runs key gen simulation for test parameters.
        let (keys, identity_providers) = simulate_keygen(threshold, n_parties);
        // Verifies that we got enough keys and identities for "existing" parties from keygen.
        assert_eq!(keys.len(), identity_providers.len());
        assert_eq!(keys.len(), n_parties as usize);

        // Extracts and verifies the shared secret key.
        let secret_shares: Vec<Scalar<Secp256k1>> = keys
            .iter()
            .enumerate()
            .map(|(idx, it)| {
                let (signing_share, sub_share) = it.extra.as_ref().unwrap();
                Scalar::<Secp256k1>::from_bytes(
                    &wamu_core::share_split_reconstruct::reconstruct(
                        signing_share,
                        sub_share,
                        &identity_providers[idx],
                    )
                    .unwrap()
                    .to_be_bytes(),
                )
                .unwrap()
            })
            .collect();
        let sec_key = keys[0].base.vss_scheme.reconstruct(
            &(0..n_parties).collect::<Vec<u16>>(),
            &secret_shares.clone(),
        );
        let pub_key = keys[0].base.public_key();
        assert_eq!(Point::<Secp256k1>::generator() * &sec_key, pub_key);

        // Verifies that transforming of x_i, which is a (t,n) share of x, into a (t,t+1) share omega_i using
        // an appropriate lagrangian coefficient lambda_{i,S} as defined by GG18 and GG20 works.
        // Ref: https://eprint.iacr.org/2021/060.pdf (Section 1.2.8)
        // Ref: https://eprint.iacr.org/2019/114.pdf (Section 4.2)
        // Ref: https://eprint.iacr.org/2020/540.pdf (Section 3.2)
        let omega_shares: Vec<Scalar<Secp256k1>> = keys[0..n_participants as usize]
            .iter()
            .enumerate()
            .map(|(idx, it)| {
                let x_i = secret_shares[idx].clone();
                let lambda_i_s = VerifiableSS::<Secp256k1, Sha256>::map_share_to_new_params(
                    &it.base.vss_scheme.parameters,
                    it.base.i - 1,
                    &(0..n_participants).collect::<Vec<u16>>(),
                );
                lambda_i_s * x_i
            })
            .collect();
        let omega_sec_key = omega_shares
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        assert_eq!(omega_sec_key, sec_key);

        // Runs pre-signing simulation for test parameters and verifies the results.
        let pre_signing_output_idx = 1; // l in the CGGMP20 paper.
        let pre_sign_inputs = generate_pre_sign_input(&keys, &identity_providers, n_participants);
        let ssids: Vec<SSID<Secp256k1>> = pre_sign_inputs
            .iter()
            .map(|(_, _, _, ssid, ..)| ssid.clone())
            .collect();
        let pre_sign_results = simulate_pre_sign(pre_sign_inputs, pre_signing_output_idx);
        // Verifies that r, the x projection of R = g^k-1 is computed correctly.
        let q = Scalar::<Secp256k1>::group_order();
        let r_dist = pre_sign_results[0]
            .base
            .as_ref()
            .unwrap()
            .0
            .R
            .x_coord()
            .unwrap();
        let k = Scalar::<Secp256k1>::from_bigint(
            &pre_sign_results
                .iter()
                .filter_map(|it| it.base.as_ref().map(|(output, _)| output.k_i.clone()))
                .fold(BigInt::from(0), |acc, x| BigInt::mod_add(&acc, &x, q)),
        );
        let r_direct = (Point::<Secp256k1>::generator() * k.invert().unwrap())
            .x_coord()
            .unwrap();
        assert_eq!(r_dist, r_direct);
        // Verifies that chi_i are additive shares of kx.
        let k_x = &k * &sec_key;
        let chi_i_sum = Scalar::<Secp256k1>::from_bigint(
            &pre_sign_results
                .iter()
                .filter_map(|it| it.base.as_ref().map(|(output, _)| output.chi_i.clone()))
                .fold(BigInt::from(0), |acc, x| BigInt::mod_add(&acc, &x, q)),
        );
        assert_eq!(k_x, chi_i_sum);

        // Creates inputs for signing simulation based on test parameters and pre-signing outputs.
        let message = b"Hello, world!";
        // Creates signing parameters.
        let signing_keys_and_pre_signing_output: Vec<(
            &SigningShare,
            &SubShare,
            &MockECDSAIdentityProvider,
            SSID<Secp256k1>,
            HashMap<u16, (PresigningOutput<Secp256k1>, PresigningTranscript<Secp256k1>)>,
        )> = pre_sign_results
            .into_iter()
            .filter_map(|it| {
                it.base.map(|(output, transcript)| {
                    let idx = output.i as usize - 1;
                    let aug_key = &keys[idx];
                    let (signing_share, sub_share) = aug_key.extra.as_ref().unwrap();
                    (
                        signing_share,
                        sub_share,
                        &identity_providers[idx],
                        ssids[idx].clone(),
                        HashMap::from([(pre_signing_output_idx as u16, (output, transcript))]),
                    )
                })
            })
            .collect();

        // Runs signing simulation for test parameters and verifies the output signature.
        let results = simulate_sign(
            signing_keys_and_pre_signing_output,
            message,
            pre_signing_output_idx,
        );
        // Extracts signature from results.
        let signature = results[0]
            .base
            .as_ref()
            .map(|it| (it.r.clone(), it.sigma.clone()))
            .unwrap();
        // Create SHA256 message digest.
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(message);
        let message_digest = BigInt::from_bytes(&hasher.finalize());
        // Verifies against expected signature.
        let s_direct =
            (k.to_bigint() * (message_digest + (&r_direct * &sec_key.to_bigint()))).mod_floor(q);
        let expected_signature = (r_direct, s_direct);
        assert_eq!(signature, expected_signature);

        (keys, identity_providers, results)
    }

    // All parties (2/2 signing).
    #[test]
    fn sign_all_parties_works() {
        generate_parties_and_simulate_signing(1, 2, 2);
    }

    // Threshold signing (subset of parties) - (3/4 signing).
    #[test]
    fn sign_threshold_works() {
        generate_parties_and_simulate_signing(2, 4, 3);
    }
}
