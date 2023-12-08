//! Quorum approved request initiation and verification implementation.
//!
//! Ref: <https://wamu.tech/specification#quorum-approved-request>.

use crate::crypto::{Random32Bytes, VerifyingKey};
use crate::errors::{IdentityAuthedRequestError, QuorumApprovedRequestError};
use crate::payloads::{
    CommandApprovalPayload, IdentityAuthedRequestPayload, QuorumApprovedChallengeResponsePayload,
};
use crate::traits::IdentityProvider;
use crate::{crypto, identity_authed_request, identity_challenge, utils, wrappers};

/// Given a "command" and an identity provider, returns the payload for initiating an quorum approved request.
pub fn initiate(
    command: &'static str,
    identity_provider: &impl IdentityProvider,
) -> IdentityAuthedRequestPayload {
    identity_authed_request::initiate(command, identity_provider)
}

/// Given a "command" a quorum approved request initialization payload, an identity provider and a list of verifying keys for the other parties,
/// returns an ok result with a "command" approval payload for initiating an identity challenge and approval acknowledgement for a valid request
/// or an appropriate error result for an invalid request.
pub fn verify_request_and_initiate_challenge(
    command: &str,
    request: &IdentityAuthedRequestPayload,
    identity_provider: &impl IdentityProvider,
    verified_parties: &[VerifyingKey],
) -> Result<CommandApprovalPayload, IdentityAuthedRequestError> {
    let challenge_fragment = wrappers::verify_identity_authed_request_and_initiate_challenge(
        command,
        request,
        verified_parties,
    )?;
    let signature = identity_provider.sign(&command_approval_message_bytes(
        &challenge_fragment,
        request.command,
        request.timestamp,
    ));
    Ok(CommandApprovalPayload {
        challenge_fragment,
        verifying_key: identity_provider.verifying_key(),
        signature,
    })
}

/// Given a list of command approval payloads, an identity provider, a quorum approved request initialization payload,
/// a quorum size and a list of verifying keys for the other parties,
/// returns an ok result with a quorum approved challenge response payload
/// or an appropriate error result for an invalid request.
pub fn challenge_response(
    approvals: &[CommandApprovalPayload],
    identity_provider: &impl IdentityProvider,
    request: &IdentityAuthedRequestPayload,
    quorum_size: usize,
    verified_parties: &[VerifyingKey],
) -> Result<QuorumApprovedChallengeResponsePayload, QuorumApprovedRequestError> {
    // quorum_size - 1 because of implicit approval from initiator.
    let valid_approvals = verify_approvals(approvals, request, quorum_size - 1, verified_parties)?;
    let approving_quorum = valid_approvals
        .iter()
        .map(|approval| approval.verifying_key.clone())
        .collect();
    Ok(QuorumApprovedChallengeResponsePayload {
        signature: identity_challenge::respond(
            &extract_challenge_fragments(&valid_approvals).collect::<Vec<Random32Bytes>>(),
            identity_provider,
        ),
        approving_quorum,
    })
}

/// Given a quorum approved challenge response payload, a list of command approval payloads,
/// a verifying key for challenged party, a quorum approved request initialization payload,
/// a quorum size and a list of verifying keys for the other parties,
/// returns an `Ok` result for valid quorum approved challenge response, or an appropriate `Err` result otherwise.
pub fn verify_challenge_response(
    response: &QuorumApprovedChallengeResponsePayload,
    approvals: &[CommandApprovalPayload],
    verifying_key: &VerifyingKey,
    request: &IdentityAuthedRequestPayload,
    quorum_size: usize,
    verified_parties: &[VerifyingKey],
) -> Result<(), QuorumApprovedRequestError> {
    let initiator_acknowledged_approvals: Vec<CommandApprovalPayload> = approvals
        .iter()
        .filter(|approval| response.approving_quorum.contains(&approval.verifying_key))
        .cloned()
        .collect();
    verify_approvals(
        &initiator_acknowledged_approvals,
        request,
        // quorum_size - 1 because of implicit approval from initiator.
        quorum_size - 1,
        verified_parties,
    )?;
    Ok(identity_challenge::verify(
        &response.signature,
        &extract_challenge_fragments(&initiator_acknowledged_approvals)
            .collect::<Vec<Random32Bytes>>(),
        verifying_key,
    )?)
}

/// Given a list of command approval payloads, a quorum approved request initialization payload,
/// a quorum size and a list of verifying keys for the other parties,
/// returns an ok result with a list of valid command approval payloads if there are enough valid command approvals
/// to form a quorum or an appropriate error result otherwise.
fn verify_approvals(
    approvals: &[CommandApprovalPayload],
    request: &IdentityAuthedRequestPayload,
    quorum_size: usize,
    verified_parties: &[VerifyingKey],
) -> Result<Vec<CommandApprovalPayload>, QuorumApprovedRequestError> {
    let valid_approvals = filter_valid_approvals(approvals, request, verified_parties);
    if valid_approvals.len() < quorum_size {
        Err(QuorumApprovedRequestError::InsufficientApprovals)
    } else {
        Ok(valid_approvals)
    }
}

/// Given a list of command approval payloads, a quorum approved request initialization payload
/// and a list of verifying keys for the other parties, returns a list of valid command approval payloads.
fn filter_valid_approvals(
    approvals: &[CommandApprovalPayload],
    request: &IdentityAuthedRequestPayload,
    verified_parties: &[VerifyingKey],
) -> Vec<CommandApprovalPayload> {
    approvals
        .iter()
        .filter(|approval| {
            verified_parties.contains(&approval.verifying_key)
                && crypto::verify_signature(
                    &approval.verifying_key,
                    &command_approval_message_bytes(
                        &approval.challenge_fragment,
                        request.command,
                        request.timestamp,
                    ),
                    &approval.signature,
                )
                .is_ok()
        })
        .cloned()
        .collect()
}

/// Returns sign-able message bytes for the command approval.
fn command_approval_message_bytes(
    challenge_fragment: &Random32Bytes,
    command: &str,
    timestamp: u64,
) -> Vec<u8> {
    utils::prefix_message_bytes(
        format!("{}{}{}", challenge_fragment, command, timestamp).as_bytes(),
    )
}

/// Given a list of command approval payloads and an identity provider, returns a list of wrapped challenge fragments.
fn extract_challenge_fragments(
    approvals: &[CommandApprovalPayload],
) -> impl Iterator<Item = Random32Bytes> + '_ {
    approvals.iter().map(|item| item.challenge_fragment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{CryptoError, Error};
    use crate::test_utils::MockECDSAIdentityProvider;
    use crypto_bigint::U256;

    #[test]
    fn quorum_approved_request_initiation_and_verification_works() {
        // Generates current identity provider.
        let initiator_identity_provider = MockECDSAIdentityProvider::generate();

        // Creates identity providers for all other parties.
        let approver_identity_providers: Vec<MockECDSAIdentityProvider> = (0..5)
            .map(|_| MockECDSAIdentityProvider::generate())
            .collect();

        // Sets quorum.
        let quorum_size = 5;

        // Creates a list of verifying keys for all parties.
        let verified_parties: Vec<VerifyingKey> = approver_identity_providers
            .iter()
            .map(|identity_provider| identity_provider.verifying_key())
            .chain([initiator_identity_provider.verifying_key()])
            .collect();

        // Sets the command.
        let command = "command";

        // Generates quorum approved request initialization payload.
        let init_payload = initiate(command, &initiator_identity_provider);

        // Verifies quorum approved request and initiates challenge.
        let init_results: Vec<Result<CommandApprovalPayload, IdentityAuthedRequestError>> =
            approver_identity_providers
                .iter()
                .map(|identity_provider| {
                    verify_request_and_initiate_challenge(
                        command,
                        &init_payload,
                        identity_provider,
                        &verified_parties,
                    )
                })
                .collect();

        // Verifies expected result.
        assert!(!init_results.iter().any(|result| result.is_err()));

        // Unwrap challenge fragments.
        let approvals: Vec<CommandApprovalPayload> = init_results
            .into_iter()
            .map(|result| result.unwrap())
            .collect();

        for (
            actual_current_signer,
            approvals_to_sign,
            quorum_size_to_sign,
            expected_challenge_result,
        ) in [
            // Valid challenge response should be accepted.
            (
                &initiator_identity_provider,
                &approvals,
                quorum_size,
                Ok(()),
            ),
            (
                &initiator_identity_provider,
                &approvals[0..4].to_vec(), // initiator + 4 approvals is a valid quorum (i.e 5 parties)
                quorum_size,
                Ok(()),
            ),
            // Challenge response from the wrong signer should be rejected.
            (
                &MockECDSAIdentityProvider::generate(),
                &approvals,
                quorum_size,
                Err(QuorumApprovedRequestError::Unauthorized(Error::Crypto(
                    CryptoError::InvalidSignature,
                ))),
            ),
            // Challenge response signing an insufficient number of approvals should be rejected.
            (
                &initiator_identity_provider,
                &approvals[0..3].to_vec(), // initiator + 3 approvals is an insufficient quorum.
                4, // Allows initiator to successfully sign only 3 approvals (i.e quorum_size - 1).
                Err(QuorumApprovedRequestError::InsufficientApprovals),
            ),
            // Challenge response signing the wrong challenge fragments should be rejected.
            (
                &initiator_identity_provider,
                &approver_identity_providers
                    .iter()
                    .map(|identity_provider| {
                        let challenge_fragment = Random32Bytes::from(U256::ONE);
                        let signature = identity_provider.sign(&command_approval_message_bytes(
                            &challenge_fragment,
                            init_payload.command,
                            init_payload.timestamp,
                        ));
                        CommandApprovalPayload {
                            challenge_fragment,
                            verifying_key: identity_provider.verifying_key(),
                            signature,
                        }
                    })
                    .collect(),
                quorum_size,
                Err(QuorumApprovedRequestError::Unauthorized(Error::Crypto(
                    CryptoError::InvalidSignature,
                ))),
            ),
        ] {
            // Generates quorum approved challenge response using the "actual signer" and "signing approvals" for this test case.
            let challenge_response_result = challenge_response(
                approvals_to_sign,
                actual_current_signer,
                &init_payload,
                quorum_size_to_sign,
                &verified_parties,
            );

            // Verifies expected challenge response result.
            assert!(challenge_response_result.is_ok());

            // Unwraps challenge payload.
            let challenge_payload = challenge_response_result.unwrap();

            // Verifies quorum approved challenge response using the challenged identity provider and "verification approvals" for this test case.
            let challenge_result = verify_challenge_response(
                &challenge_payload,
                &approvals,
                &initiator_identity_provider.verifying_key(),
                &init_payload,
                quorum_size,
                &verified_parties,
            );

            // Verifies expected result.
            assert_eq!(challenge_result, expected_challenge_result);
        }
    }
}
