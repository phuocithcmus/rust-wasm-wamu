//! A Rust implementation of [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification) for computation of threshold signatures by multiple decentralized identities.

#![feature(doc_cfg)]

pub use self::{
    identity_auth::IdentityAuthentication, identity_rotation::IdentityRotation,
    key_refresh::AugmentedKeyRefresh, keygen::AugmentedKeyGen, quorum_approval::QuorumApproval,
    share_addition::ShareAddition, share_recovery_quorum::ShareRecoveryQuorum,
    share_removal::ShareRemoval, sign::AugmentedPreSigning, sign::AugmentedSigning,
    threshold_modification::ThresholdModification,
};

#[cfg(feature = "dev")]
#[doc(cfg(feature = "dev"))]
pub use self::{
    identity_rotation::tests::{
        generate_parties_and_simulate_identity_rotation, simulate_identity_rotation,
    },
    key_refresh::tests::{generate_parties_and_simulate_key_refresh, simulate_key_refresh},
    keygen::tests::simulate_keygen,
    share_addition::tests::{
        generate_parties_and_simulate_share_addition, simulate_share_addition,
    },
    share_recovery_quorum::tests::{
        generate_parties_and_simulate_share_recovery_quorum, simulate_share_recovery_quorum,
    },
    share_removal::tests::{generate_parties_and_simulate_share_removal, simulate_share_removal},
    sign::tests::{
        generate_parties_and_simulate_signing, generate_pre_sign_input, simulate_pre_sign,
        simulate_sign,
    },
    threshold_modification::tests::{
        generate_parties_and_simulate_threshold_modification, simulate_threshold_modification,
    },
};

#[macro_use]
pub mod augmented_state_machine;
#[macro_use]
pub mod authorized_key_refresh;
mod identity_auth;
mod identity_rotation;
mod key_refresh;
mod keygen;
mod quorum_approval;
mod share_addition;
mod share_recovery_quorum;
mod share_removal;
mod sign;
mod threshold_modification;
