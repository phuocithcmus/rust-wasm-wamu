//! Identity rotation implementation.
//!
//! Ref: <https://wamu.tech/specification#identity-rotation>.

use round_based::{IsCritical, Msg, StateMachine};
use std::collections::HashMap;
use std::time::Duration;
use wamu_core::crypto::{Random32Bytes, VerifyingKey};
use wamu_core::{
    IdentityAuthedRequestError, IdentityAuthedRequestPayload, IdentityProvider,
    IdentityRotationChallengeResponsePayload, SigningShare, SubShare,
};

/// A [StateMachine](StateMachine) that implements [identity rotation as described by the Wamu protocol](https://wamu.tech/specification#identity-rotation).
pub struct IdentityRotation<'a, I: IdentityProvider> {
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// Party index.
    idx: u16,
    /// Total number of parties.
    n_parties: u16,
    /// The new decentralized identity provider of the party
    /// (only `Some` for the rotating party, `None` for all other parties).
    new_identity_provider_option: Option<&'a I>,
    /// The "signing share" of the party
    /// (only `Some` for the rotating party, `None` for all other parties).
    signing_share_option: Option<&'a SigningShare>,
    /// The "sub-share" of the party
    /// (only `Some` for the rotating party, `None` for all other parties).
    sub_share_option: Option<&'a SubShare>,
    /// Current round.
    round: Round,
    /// Outgoing message queue.
    message_queue: Vec<Msg<Message>>,
    /// Challenge fragments.
    challenge_fragments: HashMap<u16, Random32Bytes>,
    /// Outcome of the identity rotation.
    outcome: Option<bool>,
    /// Outcome of the identity rotation.
    received_outcomes: HashMap<u16, Option<bool>>,
    /// Verifying keys for other the parties.
    output_verified_parties_option: Option<Vec<VerifyingKey>>,
}

impl<'a, I: IdentityProvider> IdentityRotation<'a, I> {
    /// Initializes party for the identity rotation protocol.
    pub fn new(
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        idx: u16,
        n_parties: u16,
        new_identity_provider_option: Option<&'a I>,
        signing_share_option: Option<&'a SigningShare>,
        sub_share_option: Option<&'a SubShare>,
    ) -> IdentityRotation<'a, I> {
        // Generates initiation payload for rotating party and moves it to round 2.
        let mut message_queue = Vec::new();
        let mut round = Round::One;
        if new_identity_provider_option.is_some() {
            let request = wamu_core::identity_rotation::initiate(identity_provider);
            message_queue.push(Msg {
                sender: idx,
                receiver: None,
                body: Message::Round1(request),
            });
            round = Round::Two;
        }

        // Returns identity rotation machine.
        Self {
            identity_provider,
            verified_parties,
            idx,
            n_parties,
            new_identity_provider_option,
            signing_share_option,
            sub_share_option,
            round,
            message_queue,
            challenge_fragments: HashMap::new(),
            outcome: None,
            received_outcomes: HashMap::new(),
            output_verified_parties_option: None,
        }
    }
}

impl<'a, I: IdentityProvider> StateMachine for IdentityRotation<'a, I> {
    type MessageBody = Message;
    type Err = Error;
    type Output = (Option<(SigningShare, SubShare)>, Option<Vec<VerifyingKey>>);

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        match msg.body {
            // All other parties verify the identity rotation request.
            Message::Round1(request) => {
                // The rotating party doesn't need to do anything further for this round,
                // while other parties verify the identity rotation request
                // and immediately process the next round if the identity rotation request verification is successful.
                if self.new_identity_provider_option.is_none() {
                    let challenge_fragment =
                        wamu_core::identity_rotation::verify_request_and_initiate_challenge(
                            &request,
                            self.verified_parties,
                        )?;

                    // Moves on to the next round.
                    self.round = Round::Two;
                    // Stores the party's own challenge fragment.
                    self.challenge_fragments
                        .insert(self.idx, challenge_fragment);
                    // Adds challenge fragment to the message queue for Round 2.
                    self.message_queue.push(Msg {
                        sender: self.idx,
                        receiver: None,
                        body: Message::Round2(challenge_fragment),
                    });
                }
            }
            // All parties store the received identity challenges.
            Message::Round2(challenge_fragment) => {
                self.challenge_fragments
                    .insert(msg.sender, challenge_fragment);
            }
            // All other parties verify the identity challenge response from the rotating party.
            Message::Round3(response) => {
                // The rotating party doesn't need to do anything further for this round,
                // while other parties verify the challenge response
                // and immediately process the next round if the challenge response verification is successful.
                if self.new_identity_provider_option.is_none() {
                    wamu_core::identity_rotation::verify_challenge_response(
                        &response,
                        &self
                            .challenge_fragments
                            .values()
                            .copied()
                            .collect::<Vec<Random32Bytes>>(),
                        &self.verified_parties[msg.sender as usize - 1],
                    )?;

                    // Moves on the next round.
                    self.round = Round::Four;
                    // Replaces the sender verifying key.
                    let mut output_verified_parties = self.verified_parties.to_vec();
                    output_verified_parties[msg.sender as usize - 1] = response.new_verifying_key;
                    self.output_verified_parties_option = Some(output_verified_parties);
                    // Adds confirmation of successful rotation to the message for Round 4.
                    self.message_queue.push(Msg {
                        sender: self.idx,
                        receiver: Some(msg.sender),
                        body: Message::Round4(Some(true)),
                    });
                }
            }
            // Rotating party stores the received identity rotation confirmations.
            Message::Round4(outcome) => {
                self.received_outcomes.insert(msg.sender, outcome);
            }
        }
        Ok(())
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        self.message_queue.as_mut()
    }

    fn wants_to_proceed(&self) -> bool {
        match &self.round {
            // Rotating party is immediately ready to proceed from Round 1 after initialization,
            // while other parties need to prepare their challenge fragments first before they can proceed.
            Round::One => {
                if self.new_identity_provider_option.is_some() {
                    true
                } else {
                    self.challenge_fragments.contains_key(&self.idx)
                }
            }
            // Rotating party needs to receive challenge fragments from all other parties (i.e n_parties - 1),
            // while other parties need receive challenge fragments from all other parties except the rotating party and themselves (i.e n_parties - 2).
            Round::Two => {
                self.challenge_fragments.len()
                    == self.n_parties as usize
                        - if self.new_identity_provider_option.is_some() {
                            1
                        } else {
                            2
                        }
            }
            // Rotating party is immediately ready to proceed from Round 3 after initialization,
            // while other parties need to receive the challenge response and either accept it or reject it before they can proceed.
            Round::Three => {
                if self.new_identity_provider_option.is_some() {
                    true
                } else {
                    self.outcome.is_some()
                }
            }
            // Rotating party needs to receive outcomes from all other parties (i.e n_parties - 1),
            // while other parties don't need to do anything for this round.
            Round::Four => {
                if self.new_identity_provider_option.is_some() {
                    self.received_outcomes.len() == self.n_parties as usize - 1
                } else {
                    true
                }
            }
            // The protocol is completed at this point and output should be picked.
            Round::Final | Round::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        match self.round {
            // Round 1 is already handled by `handle_incoming` or during initialization for the rotating party.
            Round::One => {
                // Everyone moves on to the next round.
                self.round = Round::Two;
            }
            Round::Two => {
                // Only the rotating party needs to respond to the challenge.
                if let Some(new_identity_provider) = self.new_identity_provider_option {
                    let payload = wamu_core::identity_rotation::challenge_response(
                        &self
                            .challenge_fragments
                            .values()
                            .copied()
                            .collect::<Vec<Random32Bytes>>(),
                        self.identity_provider,
                        new_identity_provider,
                    );
                    self.message_queue.push(Msg {
                        sender: self.idx,
                        receiver: None,
                        body: Message::Round3(payload),
                    })
                }
                // Everyone moves on to the next round.
                self.round = Round::Three;
            }
            // Round 3 is handled by `handle_incoming` or during initialization for the rotating party.
            Round::Three => {
                // Everyone moves on to the next round.
                self.round = Round::Four;
            }
            // Rotating party simply confirms that it received enough confirmations from other parties in this round,
            // while other parties are already done at this point.
            Round::Four => {
                // Everyone moves on to the final round.
                self.round = Round::Final;
            }
            // All that's left to do is producing/picking output.
            Round::Final | Round::Gone => (),
        }
        Ok(())
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, Round::Final)
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        // Return an error if output was already picked.
        if self.round == Round::Gone {
            return Some(Err(Error::AlreadyPicked));
        }

        self.is_finished().then(|| {
            // Picking output is infallible after this, so we set output to gone.
            self.round = Round::Gone;

            // For the rotating party, we attempt to construct a new "signing share" and "sub-share",
            // Any failures to construct a new "signing share" and "sub-share" are ignored
            // and simply indicated by an `Some(Ok((None, None)))`
            // which tells the rotating party that the multi-party protocol was successful
            // and it should independently retry rotating it's "signing share" and "sub-share".
            if let Some(new_identity_provider) = self.new_identity_provider_option {
                if let Some((signing_share, sub_share)) =
                    self.signing_share_option.zip(self.sub_share_option)
                {
                    if let Ok((new_signing_share, new_sub_share)) =
                        wamu_core::identity_rotation::rotate_signing_and_sub_share(
                            signing_share,
                            sub_share,
                            self.identity_provider,
                            new_identity_provider,
                        )
                    {
                        return Ok((Some((new_signing_share, new_sub_share)), None));
                    }
                }
                Ok((None, None))
            } else {
                // For all other parties, we return a new list of `verified_parties` in Round 4,
                // so no output is necessary apart from an indicator that something change (i.e output is `Some`).
                Ok((None, self.output_verified_parties_option.clone()))
            }
        })
    }

    fn current_round(&self) -> u16 {
        match self.round {
            Round::One => 1,
            Round::Two => 2,
            Round::Three => 3,
            Round::Four => 4,
            Round::Final | Round::Gone => 5,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(5)
    }

    fn party_ind(&self) -> u16 {
        self.idx
    }

    fn parties(&self) -> u16 {
        self.n_parties
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Round {
    One,
    Two,
    Three,
    Four,
    Final,
    Gone,
}

#[derive(Debug, Clone)]
pub enum Message {
    Round1(IdentityAuthedRequestPayload),
    Round2(Random32Bytes),
    Round3(IdentityRotationChallengeResponsePayload),
    Round4(Option<bool>),
}

#[derive(Debug)]
pub enum Error {
    Core(IdentityAuthedRequestError),
    AlreadyPicked,
}

impl From<IdentityAuthedRequestError> for Error {
    fn from(error: IdentityAuthedRequestError) -> Self {
        Self::Core(error)
    }
}

impl From<wamu_core::Error> for Error {
    fn from(error: wamu_core::Error) -> Self {
        Self::Core(IdentityAuthedRequestError::Unauthorized(error))
    }
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        true
    }
}

// Implement `Debug` trait for `IdentityRotation` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for IdentityRotation<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity Rotation")
    }
}

#[cfg(any(test, feature = "dev"))]
pub mod tests {
    use super::*;
    use crate::augmented_state_machine::{AugmentedType, SubShareOutput};
    use crate::keygen::tests::simulate_keygen;
    use curv::elliptic::curves::Secp256k1;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    pub fn simulate_identity_rotation(
        idx: u16,
        n_parties: u16,
        identity_providers: &[MockECDSAIdentityProvider],
        new_identity_provider: &MockECDSAIdentityProvider,
        signing_share: &SigningShare,
        sub_share: &SubShare,
    ) -> Vec<(Option<(SigningShare, SubShare)>, Option<Vec<VerifyingKey>>)> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = identity_providers
            .iter()
            .map(IdentityProvider::verifying_key)
            .collect();

        // Adds parties to simulation.
        for (i, identity_provider) in identity_providers.iter().enumerate() {
            let party_idx = i as u16 + 1;
            let is_rotating_party = party_idx == idx;
            let new_identity_provider_option = is_rotating_party.then_some(new_identity_provider);
            let signing_share_option = is_rotating_party.then_some(signing_share);
            let sub_share_option = is_rotating_party.then_some(sub_share);
            simulation.add_party(IdentityRotation::new(
                identity_provider,
                &verifying_keys,
                party_idx,
                n_parties,
                new_identity_provider_option,
                signing_share_option,
                sub_share_option,
            ));
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    pub fn generate_parties_and_simulate_identity_rotation(
        threshold: u16,
        n_parties: u16,
        rotating_party_idx: u16,
    ) -> (
        Vec<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>>,
        Vec<MockECDSAIdentityProvider>,
        MockECDSAIdentityProvider,
    ) {
        // Runs key gen simulation for test parameters.
        let (keys, identity_providers) = simulate_keygen(threshold, n_parties);
        // Verifies that we got enough keys and identities for "existing" parties from keygen.
        assert_eq!(keys.len(), identity_providers.len());
        assert_eq!(keys.len(), n_parties as usize);

        // Creates new identity provider for rotating party.
        let new_identity_provider = MockECDSAIdentityProvider::generate();

        // Retrieves "signing share" and "sub-share" for rotating party.
        let (signing_share, sub_share) = keys[rotating_party_idx as usize - 1]
            .extra
            .as_ref()
            .unwrap();

        // Runs identity rotation simulation for test parameters.
        let results = simulate_identity_rotation(
            rotating_party_idx,
            identity_providers.len() as u16,
            &identity_providers,
            &new_identity_provider,
            signing_share,
            sub_share,
        );

        // Verifies the output for all parties.
        assert_eq!(results.len(), n_parties as usize);
        for (i, (share_option, verified_keys_option)) in results.iter().enumerate() {
            let party_idx = i as u16 + 1;
            if party_idx == rotating_party_idx {
                // Verifies that the rotating party has a new "signing share" and "sub-share"
                // that reconstruct the same "secret share" as the previous "signing share" and "sub-share".
                assert!(share_option.is_some());
                assert!(verified_keys_option.is_none());
                let prev_identity_provider = &identity_providers[rotating_party_idx as usize - 1];
                let prev_secret_share = wamu_core::share_split_reconstruct::reconstruct(
                    signing_share,
                    sub_share,
                    prev_identity_provider,
                )
                .unwrap();
                let (new_signing_share, new_sub_share) = share_option.as_ref().unwrap();
                let new_secret_share = wamu_core::share_split_reconstruct::reconstruct(
                    new_signing_share,
                    new_sub_share,
                    &new_identity_provider,
                )
                .unwrap();
                assert_eq!(
                    new_secret_share.to_be_bytes(),
                    prev_secret_share.to_be_bytes()
                );
            } else {
                // Verifies that all other parties change the rotating parties verifying keys to the expected one.
                assert!(share_option.is_none());
                assert!(verified_keys_option.is_some());
                assert_eq!(
                    verified_keys_option.as_ref().unwrap()[rotating_party_idx as usize - 1],
                    new_identity_provider.verifying_key()
                );
            }
        }

        (keys, identity_providers, new_identity_provider)
    }

    #[test]
    fn identity_rotation_works() {
        generate_parties_and_simulate_identity_rotation(2, 4, 2);
    }
}
