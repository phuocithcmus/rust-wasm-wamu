//! Types and abstractions for request payloads.

use crate::crypto::{Random32Bytes, Signature, VerifyingKey};

/// An identity authenticated request payload.
#[derive(Debug, Clone)]
pub struct IdentityAuthedRequestPayload {
    /// The command to execute.
    pub command: &'static str,
    /// The verifying key of the initiating party.
    pub verifying_key: VerifyingKey,
    /// The UTC timestamp at which the request was initiated.
    pub timestamp: u64,
    /// A signature of the command and timestamp by the initiating party.
    pub signature: Signature,
}

/// An identity rotation challenge response payload.
#[derive(Debug, Clone)]
pub struct IdentityRotationChallengeResponsePayload {
    /// The new verifying key of the initiating party.
    pub new_verifying_key: VerifyingKey,
    /// A signature of the identity challenge using the initiating party's current decentralized identity.
    pub current_signature: Signature,
    /// A signature of the identity challenge using the initiating party's new decentralized identity.
    pub new_signature: Signature,
}

/// A command approval payload.
#[derive(Debug, Clone)]
pub struct CommandApprovalPayload {
    /// An identity challenge fragment from an approving party.
    pub challenge_fragment: Random32Bytes,
    /// The verifying key of the approving party.
    pub verifying_key: VerifyingKey,
    /// A signature of the identity challenge fragment by the approving party.
    pub signature: Signature,
}

/// A command approval payload.
#[derive(Debug, Clone)]
pub struct QuorumApprovedChallengeResponsePayload {
    /// A signature of the identity challenge from a quorum of approving parties by the initiating party.
    pub signature: Signature,
    /// The verifying keys of the approving parties that jointly form a quorum with the initiating party.
    pub approving_quorum: Vec<VerifyingKey>,
}

/// An encrypted share backup (i.e an encrypted "signing share" and "sub-share", and a random nonce).
pub struct EncryptedShareBackup {
    /// An encrypted "signing share".
    pub signing_share: Vec<u8>,
    /// An encrypted "sub-share".
    pub sub_share: (Vec<u8>, Vec<u8>),
    /// The encryption/decryption nonce.
    pub nonce: Vec<u8>,
}
