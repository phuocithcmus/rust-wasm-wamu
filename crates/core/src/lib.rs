//! A Rust implementation of the core [Wamu protocol](https://wamu.tech/specification) for computation of [threshold signatures](https://en.wikipedia.org/wiki/Threshold_cryptosystem#Methodology) by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/#what-are-decentralized-identifiers).

#![feature(doc_cfg)]

pub use self::{
    errors::{
        CryptoError, Error, IdentityAuthedRequestError, QuorumApprovedRequestError,
        ShareBackupRecoveryError,
    },
    payloads::{
        CommandApprovalPayload, EncryptedShareBackup, IdentityAuthedRequestPayload,
        IdentityRotationChallengeResponsePayload, QuorumApprovedChallengeResponsePayload,
    },
    share::{SecretShare, SigningShare, SubShare},
    traits::IdentityProvider,
};

pub mod crypto;
mod errors;
pub mod identity_authed_request;
pub mod identity_challenge;
pub mod identity_rotation;
mod payloads;
pub mod quorum_approved_request;
mod share;
pub mod share_recovery_backup;
pub mod share_split_reconstruct;
mod traits;
pub mod utils;
pub mod wrappers;

#[cfg(any(test, feature = "dev"))]
#[doc(cfg(feature = "dev"))]
pub mod test_utils;
