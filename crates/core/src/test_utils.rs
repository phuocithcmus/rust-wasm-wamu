//! Test utilities.

use k256::ecdsa::{signature::Signer, SigningKey};

use crate::crypto::{
    EllipticCurve, KeyEncoding, MessageDigest, Signature, SignatureAlgorithm, SignatureEncoding,
    VerifyingKey,
};
use crate::IdentityProvider;

/// A mock ECDSA/Secp256k1/SHA-256 based identity provider.
#[derive(Debug, Clone)]
pub struct MockECDSAIdentityProvider {
    secret: SigningKey,
}

impl MockECDSAIdentityProvider {
    /// Generates an ECDSA/Secp256k1/SHA-256 signing key.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            // `k256::ecdsa::SigningKey` uses `Secp256k1` and `SHA-256`.
            secret: SigningKey::random(&mut rng),
        }
    }
}

impl IdentityProvider for MockECDSAIdentityProvider {
    /// Computes and serializes the ECDSA/Secp256k1 verifying key (in SEC1 format).
    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            // `k256::ecdsa::SigningKey` uses `Secp256k1` and `SHA-256`.
            key: k256::ecdsa::VerifyingKey::from(&self.secret)
                .to_sec1_bytes()
                .to_vec(),
            algo: SignatureAlgorithm::ECDSA,
            curve: EllipticCurve::Secp256k1,
            enc: KeyEncoding::SEC1,
        }
    }

    /// Computes and serializes (in DER format) the ECDSA/Secp256k1/SHA-256 signature of a message .
    fn sign(&self, msg: &[u8]) -> Signature {
        // `k256::ecdsa::SigningKey` uses `Secp256k1` and `SHA-256`.
        let signature: k256::ecdsa::Signature = self.secret.sign(msg);
        Signature {
            sig: signature.to_der().as_bytes().to_vec(),
            algo: SignatureAlgorithm::ECDSA,
            curve: EllipticCurve::Secp256k1,
            hash: MessageDigest::SHA256,
            enc: SignatureEncoding::DER,
        }
    }

    /// Computes the ECDSA/Secp256k1/SHA-256 signature for a message and returns (`r`, `s`) as (`[u8; 32]`, `[u8; 32]`).
    fn sign_message_share(&self, msg: &[u8]) -> ([u8; 32], [u8; 32]) {
        // `k256::ecdsa::SigningKey` uses `Secp256k1` and `SHA-256`.
        let signature: k256::ecdsa::Signature = self.secret.sign(msg);
        let (r, s) = signature.split_bytes();
        (r.into(), s.into())
    }
}

impl MockECDSAIdentityProvider {
    /// Returns the byte representation of the secret key.
    // Used only for testing and demos.
    pub fn export(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn local_identity_provider_works() {
        // Message to sign.
        let msg = b"Hello, world!";

        // Generate identity provider.
        let identity_provider = MockECDSAIdentityProvider::generate();

        // Signing.
        let signature = identity_provider.sign(msg);

        // Verifying.
        assert!(
            crypto::verify_signature(&identity_provider.verifying_key(), msg, &signature).is_ok()
        );
    }
}
