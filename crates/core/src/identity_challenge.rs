//! Identity challenge implementation.
//!
//! Ref: <https://wamu.tech/specification#identity-challenge>.

use crate::crypto::{Random32Bytes, Signature, VerifyingKey};
use crate::errors::CryptoError;
use crate::traits::IdentityProvider;
use crate::{crypto, utils};

/// Returns a challenge fragment for initiating an identity challenge.
///
/// Ref: <https://wamu.tech/specification#identity-challenge-initiation>.
pub fn initiate() -> Random32Bytes {
    Random32Bytes::generate()
}

/// Given a list of identity challenge fragments and an identity provider, returns the response signature for an identity challenge.
///
/// Ref: <https://wamu.tech/specification#identity-challenge-response>.
pub fn respond(
    challenge_fragments: &[Random32Bytes],
    identity_provider: &impl IdentityProvider,
) -> Signature {
    identity_provider.sign(&challenge_message_bytes(challenge_fragments))
}

/// Given an identity challenge response signature, a list of identity challenge fragments and
/// a verifying key for challenged party,
/// returns an `Ok` result for valid identity challenge response signature, or an appropriate `Err` result otherwise.
///
/// Ref: <https://wamu.tech/specification#identity-challenge-verification>.
pub fn verify(
    signature: &Signature,
    challenge_fragments: &[Random32Bytes],
    verifying_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    crypto::verify_signature(
        verifying_key,
        &challenge_message_bytes(challenge_fragments),
        signature,
    )
}

/// Returns sign-able message bytes for the identity challenge fragments.
fn challenge_message_bytes(challenge_fragments: &[Random32Bytes]) -> Vec<u8> {
    // Sort the challenge fragments so that we always get the same challenge regardless of order of receiving challenges.
    let mut sorted_challenge_fragments = challenge_fragments.to_owned();
    sorted_challenge_fragments.sort();
    utils::prefix_message_bytes(&sorted_challenge_fragments.iter().fold(
        Vec::<u8>::new(),
        |mut acc, n| {
            acc.append(&mut n.to_be_bytes().to_vec());
            acc
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockECDSAIdentityProvider;
    use crypto_bigint::U256;

    #[test]
    fn identity_challenge_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Generates identity challenge fragments.
        let challenge_fragments: Vec<Random32Bytes> = (0..5).map(|_| initiate()).collect();

        for (actual_signer, fragments_to_sign, fragments_to_verify, expected_result) in [
            // Valid response should be accepted.
            (
                &identity_provider,
                &challenge_fragments,
                &challenge_fragments,
                Ok(()),
            ),
            // Response from the wrong signer should be rejected.
            (
                &MockECDSAIdentityProvider::generate(),
                &challenge_fragments,
                &challenge_fragments,
                Err(CryptoError::InvalidSignature),
            ),
            // Response signing the wrong challenge fragments should be rejected.
            (
                &identity_provider,
                &(0..3u8)
                    .map(|n| Random32Bytes::from(U256::from(n)))
                    .collect(),
                &challenge_fragments,
                Err(CryptoError::InvalidSignature),
            ),
        ] {
            // Generates an identity challenge response using the "actual signer" and "signing challenge fragments" for this test case.
            let challenge_response = respond(fragments_to_sign, actual_signer);

            // Verifies identity challenge response using the challenged identity provider and "verification challenge fragments" for this test case.
            let result = verify(
                &challenge_response,
                fragments_to_verify,
                &identity_provider.verifying_key(),
            );

            // Verifies expected result.
            assert_eq!(result, expected_result);
        }
    }
}
