//! Identity authenticated request initiation and verification implementation.
//!
//! Ref: <https://wamu.tech/specification#identity-authed-request>.

use crate::crypto::VerifyingKey;
use crate::errors::{Error, IdentityAuthedRequestError};
use crate::payloads::IdentityAuthedRequestPayload;
use crate::traits::IdentityProvider;
use crate::{crypto, utils};

/// How long a request remains valid.
const EXPIRY_TIMEOUT: u64 = 60 * 60; // 1 hour.

/// How far in the future a request is allowed to be (e.g due to out of sync clocks between parties).
const FUTURE_TIMESTAMP_TOLERANCE: u64 = 5 * 60; // 5 minutes.

/// Given a "command" and an identity provider, returns the payload for initiating an identity authenticated request.
///
/// Ref: <https://wamu.tech/specification#identity-authed-request-initiation>.
pub fn initiate(
    command: &'static str,
    identity_provider: &impl IdentityProvider,
) -> IdentityAuthedRequestPayload {
    let timestamp = utils::unix_timestamp();
    let signature = identity_provider.sign(&command_message_bytes(command, timestamp));

    IdentityAuthedRequestPayload {
        command,
        verifying_key: identity_provider.verifying_key(),
        timestamp,
        signature,
    }
}

/// Given a "command", an identity authenticated request payload and a list of verifying keys for the other parties,
/// returns an ok result for a valid request or an appropriate error result for an invalid request.
///
/// Ref: <https://wamu.tech/specification#identity-authed-request-verification>.
pub fn verify(
    request: &IdentityAuthedRequestPayload,
    verified_parties: &[VerifyingKey],
) -> Result<(), IdentityAuthedRequestError> {
    if !verified_parties.contains(&request.verifying_key) {
        // Sender must be a verified party.
        Err(IdentityAuthedRequestError::Unauthorized(
            Error::UnauthorizedParty,
        ))
    } else if request.timestamp + EXPIRY_TIMEOUT < utils::unix_timestamp() {
        // Request should be initiated during the current epoch.
        Err(IdentityAuthedRequestError::Expired)
    } else if utils::unix_timestamp() + FUTURE_TIMESTAMP_TOLERANCE < request.timestamp {
        // Request can't be too far into the future (i.e clocks can't be exactly synchronized but tolerance should be reasonable).
        Err(IdentityAuthedRequestError::InvalidTimestamp)
    } else {
        // Command signature must be valid.
        Ok(crypto::verify_signature(
            &request.verifying_key,
            &command_message_bytes(request.command, request.timestamp),
            &request.signature,
        )?)
    }
}

/// Returns sign-able message bytes for the command and timestamp.
fn command_message_bytes(command: &str, timestamp: u64) -> Vec<u8> {
    utils::prefix_message_bytes(format!("{}{}", command, timestamp).as_bytes())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::errors::CryptoError;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn identity_authed_request_initiation_and_verification_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Generates identity authenticated request payload.
        let payload = initiate("command", &identity_provider);

        for (verified_parties, timestamp_modification, signature_modification, expected_result) in [
            // Valid request from a verified party should be ok.
            (vec![identity_provider.verifying_key()], None, None, Ok(())),
            // Request from an unverified party should fail.
            (
                vec![],
                None,
                None,
                Err(IdentityAuthedRequestError::Unauthorized(
                    Error::UnauthorizedParty,
                )),
            ),
            // Request with a timestamp set to a past value outside the expiry timeout should fail.
            (
                vec![identity_provider.verifying_key()],
                Some(-(EXPIRY_TIMEOUT as i64 + 1)),
                None,
                Err(IdentityAuthedRequestError::Expired),
            ),
            // Request with a timestamp set to a future value outside the future timestamp tolerance should fail.
            (
                vec![identity_provider.verifying_key()],
                Some(FUTURE_TIMESTAMP_TOLERANCE as i64 + 1),
                None,
                Err(IdentityAuthedRequestError::InvalidTimestamp),
            ),
            // Request with an invalid signature should fail.
            (
                vec![identity_provider.verifying_key()],
                None,
                Some(identity_provider.sign(b"Hello, world!")),
                Err(IdentityAuthedRequestError::Unauthorized(Error::Crypto(
                    CryptoError::InvalidSignature,
                ))),
            ),
        ] {
            // Creates a copy of payload for this test case.
            let mut modified_payload = payload.clone();

            // Applies test case timestamp modification (if any).
            if let Some(delta) = timestamp_modification {
                modified_payload.timestamp = (modified_payload.timestamp as i64 + delta) as u64;
            }

            // Applies test case signature modification (if any).
            if let Some(modified_signature) = signature_modification {
                modified_payload.signature = modified_signature;
            }

            // Verifies identity authenticated request payload.
            let result = verify(&modified_payload, &verified_parties);

            // Verifies expected result.
            assert_eq!(result, expected_result);
        }
    }
}
