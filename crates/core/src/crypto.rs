//! Types, abstractions and utilities for lower-level cryptography.

use crypto_bigint::modular::constant_mod::ResidueParams;
use crypto_bigint::{impl_modulus, Encoding, NonZero, Random, RandomMod, U256};
use std::fmt;
use zeroize::Zeroize;

use crate::errors::{CryptoError, Error};

// Order of the `Secp256k1` elliptic curve as a `crypto-bigint` modulus type.
// Ref: <https://www.secg.org/sec2-v2.pdf>.
// Ref: <https://en.bitcoin.it/wiki/Secp256k1>.
impl_modulus!(
    Secp256k1Order,
    U256,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

/// A convenience wrapper for generating and encoding/decoding cryptographically secure random values.
// No `ZeroizeOnDrop` because we want `Random32Bytes` to be `Copy` like `U256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct Random32Bytes(U256);

impl Random32Bytes {
    /// Generates a cryptographically secure random value.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(U256::random(&mut rng))
    }

    /// Generates a cryptographically secure random value which is less than the order of the `Secp256k1` elliptic curve.
    pub fn generate_mod_q() -> Self {
        let mut rng = rand::thread_rng();

        // The order of the `Secp256k1` curve should be non-zero.
        let modulus = NonZero::new(Secp256k1Order::MODULUS).unwrap();
        Self(U256::random_mod(&mut rng, &modulus))
    }

    /// Returns the underlying `U256` random value.
    pub fn as_u256(&self) -> U256 {
        self.0
    }

    /// Returns 32 bytes representation of the "secret share".
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }
}

impl From<U256> for Random32Bytes {
    /// Converts a U256 into a `RandomBytes` representation.
    fn from(value: U256) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for Random32Bytes {
    /// Converts a 32 byte slice into a `RandomBytes` representation.
    fn from(value: [u8; 32]) -> Self {
        Self(U256::from_be_slice(&value))
    }
}

impl TryFrom<&[u8]> for Random32Bytes {
    type Error = Error;

    /// Converts a slice of bytes into a `RandomBytes` representation.
    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        // Input slice must be 32 bytes long.
        if slice.len() == 32 {
            Ok(Self(U256::from_be_slice(slice)))
        } else {
            Err(Error::Encoding)
        }
    }
}

impl fmt::Display for Random32Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_u256())
    }
}

/// Returns an `Ok` result for valid signature for the message, or an appropriate `Err` result otherwise.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if (verifying_key.algo, verifying_key.curve) != (signature.algo, signature.curve) {
        // Signature algorithm and elliptic curve for the verifying key and signature should match.
        Err(CryptoError::SchemeMismatch)
    } else {
        // Matches signature scheme (algorithm + curve).
        match (verifying_key.algo, verifying_key.curve) {
            // Verifies ECDSA/Secp256k1 signatures.
            // SEC1 encoded verifying key and SHA-256 digest and DER encoded signature.
            (SignatureAlgorithm::ECDSA, EllipticCurve::Secp256k1) => {
                // Matches the message digest/hash function.
                match signature.hash {
                    // Verifies ECDSA/Secp256k1/SHA-256 signatures.
                    MessageDigest::SHA256 => {
                        // Matches verifying key and signature encoding.
                        match (verifying_key.enc, signature.enc) {
                            // Verifies DER encoded ECDSA/Secp256k1/SHA-256 signatures with SEC1 encoded verifying key.
                            (KeyEncoding::SEC1, SignatureEncoding::DER) => {
                                // Deserialize verifying key.
                                // `k256::ecdsa::VerifyingKey` uses `Secp256k1` and `SHA-256`.
                                let ver_key =
                                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&verifying_key.key);
                                // Deserialize signature.
                                let sig = k256::ecdsa::Signature::from_der(&signature.sig)
                                    .map_err(|_| CryptoError::InvalidSignature)?;
                                // Verify ECDSA/Secp256k1/SHA-256 signature.
                                use k256::ecdsa::signature::Verifier;
                                ver_key
                                    .map_err(|_| CryptoError::InvalidVerifyingKey)?
                                    .verify(msg, &sig)
                                    .map_err(|_| CryptoError::InvalidSignature)
                            }
                            _ => Err(CryptoError::UnsupportedEncoding),
                        }
                    }
                    _ => Err(CryptoError::UnsupportedDigest),
                }
            }
            _ => Err(CryptoError::UnsupportedScheme),
        }
    }
}

/// A verifying key (e.g an ECDSA/secp256k1 public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The verifying key as a sequence of bytes.
    pub key: Vec<u8>,
    /// The signature algorithm.
    pub algo: SignatureAlgorithm,
    /// The elliptic curve.
    pub curve: EllipticCurve,
    /// The encoding standard used for the verifying key.
    pub enc: KeyEncoding,
}

/// A signature (e.g a ECDSA/secp256k1/SHA-256 signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The signature as a sequence of bytes.
    pub sig: Vec<u8>,
    /// The signature algorithm.
    pub algo: SignatureAlgorithm,
    /// The elliptic curve.
    pub curve: EllipticCurve,
    /// The hash function.
    pub hash: MessageDigest,
    /// The encoding standard used for the signature.
    pub enc: SignatureEncoding,
}

/// A signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ref: <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>.
    ECDSA,
    /// Ref: <https://en.wikipedia.org/wiki/EdDSA>.
    EdDSA,
}

/// An elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    /// Ref: <https://www.secg.org/sec2-v2.pdf>.
    Secp256k1,
    /// Ref: <https://en.wikipedia.org/wiki/Curve25519>.
    Curve25519,
}

/// A cryptographic message digest/hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDigest {
    /// Ref: <https://en.wikipedia.org/wiki/SHA-2>.
    SHA256,
    /// Ref: <https://en.wikipedia.org/wiki/SHA-3>.
    Keccak256,
}

/// A key encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEncoding {
    /// Ref: <https://www.secg.org/sec1-v2.pdf>.
    SEC1,
    /// Ref: <https://eips.ethereum.org/EIPS/eip-55>.
    EIP55,
}

/// A signature encoding format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureEncoding {
    /// Ref: <https://en.wikipedia.org/wiki/X.690#DER_encoding>.
    DER,
    /// Ref: <https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/>.
    RLP,
}
