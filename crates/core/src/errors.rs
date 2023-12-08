//! Types and abstractions for protocol errors.

/// A protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Arithmetic error.
    Arithmetic(ArithmeticError),
    /// A cryptography error.
    Crypto(CryptoError),
    /// Encoding error.
    Encoding,
    /// A signature from an unauthorized party.
    UnauthorizedParty,
}

/// An arithmetic error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticError {
    /// The provided value is larger than the modulus
    /// (e.g values larger than the curve order for elliptic curve operations).
    ModulusOverflow,
}

impl From<ArithmeticError> for Error {
    fn from(error: ArithmeticError) -> Self {
        Self::Arithmetic(error)
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// A low-level cryptography error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// An invalid signature for the message.
    InvalidSignature,
    /// An invalid verifying key.
    InvalidVerifyingKey,
    /// A signature algorithm and/or elliptic curve mismatch between the verifying key and signature.
    SchemeMismatch,
    /// An unsupported cryptographic scheme algorithm (e.g unsupported combination of signature algorithm and elliptic curve).
    UnsupportedScheme,
    /// An unsupported hash function.
    UnsupportedDigest,
    /// An unsupported encoding standard (e.g for either the verifying key or the signature).
    UnsupportedEncoding,
}

/// An identity authenticated request verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAuthedRequestError {
    /// Not the expected command.
    CommandMismatch,
    /// An expired request i.e initiated too far in the past.
    Expired,
    /// A request with an invalid timestamp i.e a timestamp too far in the future.
    InvalidTimestamp,
    /// A request with either an invalid signature or an unauthorized signer.
    Unauthorized(Error),
}

/// Implements `From<Error>` and `From<CryptoError>` for the error type.
macro_rules! impl_from_error {
    ($error_type:path) => {
        impl From<Error> for $error_type {
            fn from(error: Error) -> Self {
                Self::Unauthorized(error)
            }
        }

        impl From<CryptoError> for $error_type {
            fn from(error: CryptoError) -> Self {
                Self::Unauthorized(Error::Crypto(error))
            }
        }
    };
}

// Implements `From<Error>` and `From<CryptoError>` for `IdentityAuthedRequestError`.
impl_from_error!(IdentityAuthedRequestError);

/// An identity authenticated request verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumApprovedRequestError {
    /// Not enough approvals to form a quorum.
    InsufficientApprovals,
    /// A request with either an invalid signature or an unauthorized signer.
    Unauthorized(Error),
}

// Implements `From<Error>` and `From<CryptoError>` for `QuorumApprovedRequestError`.
impl_from_error!(QuorumApprovedRequestError);

/// A share backup or recovery error.
#[derive(Debug)]
pub enum ShareBackupRecoveryError {
    /// Encrypted data can't be converted into a valid signing share e.g decrypted output that's not 32 bytes long.
    InvalidSigningShare,
    /// Encrypted data can't be converted into a valid sub share e.g decrypted output that's not 32 bytes long.
    InvalidSubShare,
    /// An encryption/decryption error.
    EncryptionError(aes_gcm::Error),
}

impl From<aes_gcm::Error> for ShareBackupRecoveryError {
    fn from(error: aes_gcm::Error) -> Self {
        ShareBackupRecoveryError::EncryptionError(error)
    }
}
