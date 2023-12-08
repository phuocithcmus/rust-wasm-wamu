//! Quorum approval [StateMachine](StateMachine) implementation.
//!
//! Ref: <https://wamu.tech/specification#quorum-approved-request>.

use round_based::{IsCritical, Msg, StateMachine};
use std::collections::HashMap;
use std::time::Duration;
use wamu_core::crypto::VerifyingKey;
use wamu_core::{
    CommandApprovalPayload, IdentityAuthedRequestError, IdentityAuthedRequestPayload,
    IdentityProvider, QuorumApprovedChallengeResponsePayload, QuorumApprovedRequestError,
};

/// A [StateMachine](StateMachine) that implements [quorum approval as described by the Wamu protocol](https://wamu.tech/specification#quorum-approved-request).
pub struct QuorumApproval<'a, I: IdentityProvider> {
    /// The command for the request being initiated.
    command: &'static str,
    /// The decentralized identity provider of the party.
    identity_provider: &'a I,
    /// Verifying keys for other the parties.
    verified_parties: &'a [VerifyingKey],
    /// Party index.
    idx: u16,
    /// The threshold.
    threshold: u16,
    /// Total number of parties.
    n_parties: u16,
    /// Whether or not this party is the request initiator.
    is_initiator: bool,
    /// Current round.
    round: Round,
    /// Outgoing message queue.
    message_queue: Vec<Msg<Message>>,
    /// The identity authed request.
    request: Option<IdentityAuthedRequestPayload>,
    /// Command approvals.
    command_approvals: HashMap<u16, CommandApprovalPayload>,
    /// Outcome of the identity authentication verification.
    verification_outcome: Option<bool>,
    /// Outcome of the identity authentication verification.
    received_verification_outcomes: HashMap<u16, Option<bool>>,
    // Hack for composite protocols (e.g share addition) where some parties (e.g new parties in the case of share additional) are dormant during the quorum approval.
    // Whether or not this party actively participates in the protocol.
    is_dormant: bool,
}

impl<'a, I: IdentityProvider> QuorumApproval<'a, I> {
    /// Initializes party for the identity authentication protocol.
    pub fn new(
        command: &'static str,
        identity_provider: &'a I,
        verified_parties: &'a [VerifyingKey],
        idx: u16,
        // NOTE: Quorum size = threshold + 1
        threshold: u16,
        n_parties: u16,
        is_initiator: bool,
        is_dormant: bool,
    ) -> QuorumApproval<'a, I> {
        // Generates initiation payload for initiating party and moves it to round 2.
        let mut message_queue = Vec::new();
        let mut round = Round::One;
        let mut request_option = None;
        if is_initiator {
            let request = wamu_core::quorum_approved_request::initiate(command, identity_provider);

            message_queue.push(Msg {
                sender: idx,
                receiver: None,
                body: Message::Round1(request.clone()),
            });

            request_option = Some(request);
            round = Round::Two;
        }

        // Returns quorum approval machine.
        Self {
            command,
            identity_provider,
            verified_parties,
            is_initiator,
            idx,
            threshold,
            n_parties,
            round,
            message_queue,
            request: request_option,
            command_approvals: HashMap::new(),
            verification_outcome: None,
            received_verification_outcomes: HashMap::new(),
            is_dormant,
        }
    }
}

impl<'a, I: IdentityProvider> StateMachine for QuorumApproval<'a, I> {
    type MessageBody = Message;
    type Err = Error;
    type Output = bool;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        match msg.body {
            // All other parties verify the identity authentication request.
            Message::Round1(request) => {
                // The initiating party doesn't need to do anything further for this round,
                // while other parties verify the identity authentication request
                // and immediately process the next round if the identity authentication request verification is successful.
                if !self.is_initiator && !self.is_dormant {
                    let command_approval =
                        wamu_core::quorum_approved_request::verify_request_and_initiate_challenge(
                            self.command,
                            &request,
                            self.identity_provider,
                            self.verified_parties,
                        )?;
                    // Saves the request payload.
                    self.request = Some(request);

                    // Moves on to the next round.
                    self.round = Round::Two;
                    // Stores the party's own challenge fragment.
                    self.command_approvals
                        .insert(self.idx, command_approval.clone());
                    // Adds challenge fragment to the message queue for Round 2.
                    self.message_queue.push(Msg {
                        sender: self.idx,
                        receiver: None,
                        body: Message::Round2(command_approval),
                    });
                }
            }
            // All parties store the received identity challenges.
            Message::Round2(challenge_fragment) => {
                self.command_approvals
                    .insert(msg.sender, challenge_fragment);
            }
            // All other parties verify the identity challenge response from the initiating party.
            Message::Round3(response) => {
                // The initiating party doesn't need to do anything further for this round,
                // while other parties verify the challenge response
                // and immediately process the next round if the challenge response verification is successful.
                if !self.is_initiator && !self.is_dormant {
                    let request = self.request.as_ref().ok_or(Error::InvalidState)?;
                    wamu_core::quorum_approved_request::verify_challenge_response(
                        &response,
                        &self
                            .command_approvals
                            .values()
                            .cloned()
                            .collect::<Vec<CommandApprovalPayload>>(),
                        &self.verified_parties[msg.sender as usize - 1],
                        request,
                        self.threshold as usize, // In this case threshold is enough since the initiator is an implicit approval.
                        self.verified_parties,
                    )?;

                    // Moves on the next round.
                    self.round = Round::Four;
                    // Adds confirmation of successful identity authentication request verification to the message for Round 4.
                    self.message_queue.push(Msg {
                        sender: self.idx,
                        receiver: None,
                        body: Message::Round4(Some(true)),
                    });
                }
            }
            // All parties store the received identity authentication request confirmations.
            Message::Round4(outcome) => {
                self.received_verification_outcomes
                    .insert(msg.sender, outcome);
            }
        }
        Ok(())
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        self.message_queue.as_mut()
    }

    fn wants_to_proceed(&self) -> bool {
        match &self.round {
            // Initiating party is immediately ready to proceed from Round 1 after initialization,
            // while other parties need to prepare their challenge fragments first before they can proceed.
            Round::One => {
                if self.is_initiator || self.is_dormant {
                    true
                } else {
                    self.command_approvals.contains_key(&self.idx)
                }
            }
            // Initiating party needs to receive challenge fragments from at least the threshold (i.e >= threshold) since its also an approval (i.e quorum size = threshold + 1),
            // while other parties need to receive challenge fragments from at least the threshold - 1 (i.e >= threshold - 1) since they can be the final approval.
            Round::Two => {
                self.command_approvals.len()
                    >= self.threshold as usize
                        - if self.is_initiator || self.is_dormant {
                            0
                        } else {
                            1
                        }
            }
            // Initiating party is immediately ready to proceed from Round 3 after initialization,
            // while other parties need to receive the challenge response and either accept it or reject it before they can proceed.
            Round::Three => {
                if self.is_initiator || self.is_dormant {
                    true
                } else {
                    self.verification_outcome.is_some()
                }
            }
            // Initiating party needs to receive outcomes from at least the threshold (i.e >= threshold) since its also an approval (i.e quorum size = threshold + 1),
            // while other parties need to receive outcomes from at least the threshold - 1 (i.e >= threshold - 1) since they can be the final approval.
            Round::Four => {
                self.command_approvals.len()
                    >= self.threshold as usize
                        - if self.is_initiator || self.is_dormant {
                            0
                        } else {
                            1
                        }
            }
            // The protocol is completed at this point and output should be picked.
            Round::Final | Round::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        match self.round {
            // Round 1 is already handled by `handle_incoming` or during initialization for the initiating party.
            Round::One => {
                // Everyone moves on to the next round.
                self.round = Round::Two;
            }
            Round::Two => {
                // Only the initiating party needs to respond to the challenge.
                if self.is_initiator {
                    let request = self.request.as_ref().ok_or(Error::InvalidState)?;
                    let result = wamu_core::quorum_approved_request::challenge_response(
                        &self
                            .command_approvals
                            .values()
                            .cloned()
                            .collect::<Vec<CommandApprovalPayload>>(),
                        self.identity_provider,
                        request,
                        self.threshold as usize + 1, // quorum size = threshold + 1.
                        self.verified_parties,
                    );
                    match result {
                        Ok(quorum_challenge_response) => {
                            // Moves on to the next round if the quorum challenge response was verified successfully.
                            self.round = Round::Three;
                            self.message_queue.push(Msg {
                                sender: self.idx,
                                receiver: None,
                                body: Message::Round3(quorum_challenge_response),
                            });
                        }
                        Err(error) => {
                            // Keep try if there aren't enough approvals but messages haven't been received from all parties, otherwise return an error.
                            return if matches!(
                                error,
                                QuorumApprovedRequestError::InsufficientApprovals
                            ) && self.command_approvals.len() < self.n_parties as usize
                            {
                                Ok(())
                            } else {
                                Err(Error::Quorum(error))
                            };
                        }
                    }
                } else {
                    // Everyone else moves on to the next round.
                    self.round = Round::Three;
                }
            }
            // Round 3 is handled by `handle_incoming` or during initialization for the initiating party.
            Round::Three => {
                // Everyone moves on to the next round.
                self.round = Round::Four;
            }
            // Initiating party simply confirms that it received enough confirmations from other parties in this round,
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

            Ok(true)
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
        Some(4)
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
    Round2(CommandApprovalPayload),
    Round3(QuorumApprovedChallengeResponsePayload),
    Round4(Option<bool>),
}

#[derive(Debug)]
pub enum Error {
    Quorum(QuorumApprovedRequestError),
    Identity(IdentityAuthedRequestError),
    AlreadyPicked,
    InvalidState,
}

impl From<QuorumApprovedRequestError> for Error {
    fn from(error: QuorumApprovedRequestError) -> Self {
        Self::Quorum(error)
    }
}

impl From<IdentityAuthedRequestError> for Error {
    fn from(error: IdentityAuthedRequestError) -> Self {
        Self::Identity(error)
    }
}

impl From<wamu_core::Error> for Error {
    fn from(error: wamu_core::Error) -> Self {
        Self::Quorum(QuorumApprovedRequestError::Unauthorized(error))
    }
}

impl From<wamu_core::CryptoError> for Error {
    fn from(error: wamu_core::CryptoError) -> Self {
        Self::Quorum(QuorumApprovedRequestError::Unauthorized(
            wamu_core::Error::Crypto(error),
        ))
    }
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        true
    }
}

// Implement `Debug` trait for `QuorumApproval` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider> std::fmt::Debug for QuorumApproval<'a, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Quorum Approval")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use round_based::dev::Simulation;
    use wamu_core::test_utils::MockECDSAIdentityProvider;

    pub fn simulate_quorum_approval(
        // Party key configs including the "signing share", "sub-share", identity provider and
        // `LocalKey<Secp256k1>` from `multi-party-ecdsa` with the secret share cleared/zerorized.
        party_key_configs: Vec<(
            &impl IdentityProvider,
            u16,  // party index.
            bool, // whether the party is the request initiator.
        )>,
        // NOTE: Quorum size = threshold + 1
        threshold: u16,
        n_parties: u16,
    ) -> Vec<bool> {
        // Creates simulation.
        let mut simulation = Simulation::new();

        // Creates a list of verifying keys for all parties.
        let verifying_keys: Vec<VerifyingKey> = party_key_configs
            .iter()
            .map(|(identity_provider, ..)| identity_provider.verifying_key())
            .collect();

        // Adds parties to simulation.
        for (identity_provider, idx, is_initiator) in party_key_configs {
            simulation.add_party(QuorumApproval::new(
                "command",
                identity_provider,
                &verifying_keys,
                idx,
                threshold,
                n_parties,
                is_initiator,
                false,
            ));
        }

        // Runs simulation and returns output.
        simulation.run().unwrap()
    }

    #[test]
    fn quorum_approval_works() {
        let threshold = 2;
        let n_parties = 4;
        let n_participants = 3;
        let initiating_party_idx = 2u16;

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

        // Creates identity providers for all other parties.
        let identity_providers: Vec<MockECDSAIdentityProvider> = (1..=n_participants)
            .map(|_| MockECDSAIdentityProvider::generate())
            .collect();

        // Creates key configs and party indices for all parties.
        let mut party_key_configs = Vec::new();
        for (i, identity_provider) in identity_providers.iter().enumerate() {
            // Create party key config and index entry.
            let idx = i as u16 + 1;
            party_key_configs.push((identity_provider, idx, idx == initiating_party_idx));
        }

        // Runs identity authentication simulation for test parameters.
        let results = simulate_quorum_approval(party_key_configs, threshold, n_parties);

        // Verifies the outcome for all parties.
        assert_eq!(results.len(), n_participants as usize);
        for outcome in results {
            assert!(outcome);
        }
    }
}
