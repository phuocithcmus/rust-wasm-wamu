//! Convenience wrappers around core sub-protocols.

use crate::crypto::{Random32Bytes, Signature, VerifyingKey};
use crate::errors::{Error, IdentityAuthedRequestError};
use crate::identity_authed_request;
use crate::identity_challenge;
use crate::payloads::IdentityAuthedRequestPayload;
use crate::traits::IdentityProvider;
use crate::{crypto, utils};

/// Given random bytes and an identity provider, returns the verifying key and a signature of the random bytes.
///
/// **NOTE:** random bytes are prefixed with a predefined phrase before signing.
pub fn initiate_request_with_signature(
    random_bytes: &[u8],
    identity_provider: &impl IdentityProvider,
) -> (VerifyingKey, Signature) {
    let signature = identity_provider.sign(&utils::prefix_message_bytes(random_bytes));
    (identity_provider.verifying_key(), signature)
}

/// Given random bytes, a verifying key for the sending party, a signature of the random bytes and
/// a list of verifying keys for the other parties,
/// returns an ok result for a valid request or an appropriate error result for an invalid request.
///
/// **NOTE:** random bytes are prefixed with a predefined phrase before signing.
pub fn verify_request_with_signature(
    random_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
    verified_parties: &[VerifyingKey],
) -> Result<(), Error> {
    if !verified_parties.contains(verifying_key) {
        // Sender must be a verified party.
        Err(Error::UnauthorizedParty)
    } else {
        // Signature must be valid.
        Ok(crypto::verify_signature(
            verifying_key,
            &utils::prefix_message_bytes(random_bytes),
            signature,
        )?)
    }
}

/// Given a "command", an identity authenticated request payload and a list of verifying keys for the other parties,
/// returns an ok result with a challenge fragment for initiating an identity challenge for a valid request
/// or an appropriate error result for an invalid request.s
pub fn verify_identity_authed_request_and_initiate_challenge(
    command: &str,
    request: &IdentityAuthedRequestPayload,
    verified_parties: &[VerifyingKey],
) -> Result<Random32Bytes, IdentityAuthedRequestError> {
    if command != request.command {
        // Command doesn't match request payload.
        Err(IdentityAuthedRequestError::CommandMismatch)
    } else {
        identity_authed_request::verify(request, verified_parties)?;
        Ok(identity_challenge::initiate())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CryptoError;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn initiate_and_verify_request_with_signature_works() {
        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Sets the random bytes.
        let random_bytes = b"random";

        // Generates verifying key and random bytes signature.
        let (verifying_key, signature) =
            initiate_request_with_signature(random_bytes, &identity_provider);

        for (verified_parties, signature_to_verify, expected_result) in [
            // Valid request from a verified party should be ok.
            (vec![identity_provider.verifying_key()], &signature, Ok(())),
            // Request from an unverified party should fail.
            (vec![], &signature, Err(Error::UnauthorizedParty)),
            // Request with an invalid signature should fail.
            (
                vec![identity_provider.verifying_key()],
                &identity_provider.sign(b"Hello, world!"),
                Err(Error::Crypto(CryptoError::InvalidSignature)),
            ),
        ] {
            // Verifies random bytes signature using verifying key.
            let result = verify_request_with_signature(
                random_bytes,
                &verifying_key,
                signature_to_verify,
                &verified_parties,
            );

            // Verifies expected result.
            assert_eq!(result, expected_result);
        }
    }
}
