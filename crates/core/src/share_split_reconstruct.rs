//! Share splitting and reconstruction implementation.
//!
//! Ref: <https://wamu.tech/specification#share-splitting-and-reconstruction>.

use crypto_bigint::{Encoding, U256};

use crate::errors::Error;
use crate::share::{SecretShare, SigningShare, SubShare, SubShareInterpolator};
use crate::traits::IdentityProvider;

/// Given a "secret share" and an identity provider, returns "signing share" and "sub-share"
/// that can be used to reconstruct the "secret share" given the same identity provider.
///
/// Ref: <https://wamu.tech/specification#share-splitting>.
pub fn split(
    secret_share: &SecretShare,
    identity_provider: &impl IdentityProvider,
) -> Result<(SigningShare, SubShare), Error> {
    // Generates "signing share".
    let signing_share = SigningShare::generate();

    // Computes "sub-share" a from "signing share".
    let (r, s) = identity_provider.sign_message_share(&signing_share.to_be_bytes());
    let sub_share_a = SubShare::new(U256::from_be_bytes(r), U256::from_be_bytes(s))?;

    // Initializes the "sub-share" interpolator.
    let sub_share_interpolator = SubShareInterpolator::new(
        // The "secret share" is the constant term, so x = 0.
        &SubShare::new(U256::ZERO, secret_share.as_u256())?,
        &sub_share_a,
    );

    // Computes "sub-share" b.
    let sub_share_b = sub_share_interpolator.sub_share(U256::ONE)?;

    // Returns "signing share" and "sub-share" b.
    Ok((signing_share, sub_share_b))
}

/// Returns "secret share" associated with "signing share", "sub-share" and identity provider.
///
/// Ref: <https://wamu.tech/specification#share-reconstruction>.
pub fn reconstruct(
    signing_share: &SigningShare,
    sub_share_b: &SubShare,
    identity_provider: &impl IdentityProvider,
) -> Result<SecretShare, Error> {
    // Computes "sub-share" a from "signing share".
    let (r, s) = identity_provider.sign_message_share(&signing_share.to_be_bytes());
    let sub_share_a = SubShare::new(U256::from_be_bytes(r), U256::from_be_bytes(s))?;

    // Initializes the "sub-share" interpolator.
    let sub_share_interpolator = SubShareInterpolator::new(&sub_share_a, sub_share_b);

    // Returns "secret share".
    Ok(sub_share_interpolator.secret().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Random32Bytes;
    use crate::test_utils::MockECDSAIdentityProvider;

    #[test]
    fn share_splitting_and_reconstruction_works() {
        // Generates secret share.
        let secret_share = SecretShare::from(Random32Bytes::generate_mod_q());

        // Generates identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Computes "signing share" and "sub-share".
        let (signing_share, sub_share_b) = split(&secret_share, &identity_provider).unwrap();

        // Reconstructs "secret share" from "signing share" and "sub-share".
        let reconstructed_secret_share =
            reconstruct(&signing_share, &sub_share_b, &identity_provider).unwrap();

        // Verifies reconstructed "secret share".
        assert_eq!(
            &reconstructed_secret_share.to_be_bytes(),
            &secret_share.to_be_bytes()
        );
    }
}
