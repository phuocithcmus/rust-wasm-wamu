//! Types, traits, abstractions and utilities for augmenting a [`StateMachine`](StateMachine).

use curv::elliptic::curves::{ECScalar, Scalar, Secp256k1};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use round_based::{IsCritical, Msg, StateMachine};
use std::ops::Deref;
use wamu_core::crypto::{Signature, VerifyingKey};
use wamu_core::{IdentityProvider, SecretShare, SigningShare, SubShare};
use zeroize::Zeroize;

/// A [`StateMachine`](StateMachine) that wraps and augments another [`StateMachine`](StateMachine).
pub trait AugmentedStateMachine {
    /// The type of the wrapped `StateMachine`.
    type StateMachineType: StateMachine;
    /// Additional message parameters from augmentations.
    type AdditionalParams;
    /// Additional output from augmentations.
    type AdditionalOutput;

    /// Returns an immutable reference to the wrapped state machine.
    fn state_machine(&self) -> &Self::StateMachineType;

    /// Returns a mutable reference to the wrapped state machine.
    fn state_machine_mut(&mut self) -> &mut Self::StateMachineType;

    /// Returns an immutable reference to the augmented message queue.
    fn augmented_message_queue(
        &self,
    ) -> &Vec<
        Msg<
            AugmentedType<
                <Self::StateMachineType as StateMachine>::MessageBody,
                Self::AdditionalParams,
            >,
        >,
    >;

    /// Returns a mutable reference to the augmented message queue.
    fn augmented_message_queue_mut(
        &mut self,
    ) -> &mut Vec<
        Msg<
            AugmentedType<
                <Self::StateMachineType as StateMachine>::MessageBody,
                Self::AdditionalParams,
            >,
        >,
    >;

    /// Augmentations to run before calling `handle_incoming` on the wrapped `StateMachine`.
    fn pre_handle_incoming(
        &mut self,
        _msg: &Msg<
            AugmentedType<
                <Self::StateMachineType as StateMachine>::MessageBody,
                Self::AdditionalParams,
            >,
        >,
    ) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        Ok(())
    }

    /// Augmentations to run before calling `proceed` on the wrapped `StateMachine`.
    fn pre_proceed(&mut self) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        Ok(())
    }

    /// Returns additional parameters (if any) that should be added to an outgoing message.
    fn augment_outgoing_message(
        &self,
        _sender: u16,
        _msg_body: &<Self::StateMachineType as StateMachine>::MessageBody,
    ) -> Result<Option<Self::AdditionalParams>, Error<<Self::StateMachineType as StateMachine>::Err>>
    {
        Ok(None)
    }

    /// Returns additional parameters (if any) that should be added the protocol output.
    fn augment_output(
        &self,
        output: <Self::StateMachineType as StateMachine>::Output,
    ) -> Result<
        AugmentedType<<Self::StateMachineType as StateMachine>::Output, Self::AdditionalOutput>,
        Error<<Self::StateMachineType as StateMachine>::Err>,
    > {
        Ok(AugmentedType {
            base: output,
            extra: None,
        })
    }

    /// Updates the augmented message queue by
    /// retrieving the message queue from the wrapped state machines and processing augmentations (if any) for all the messages in the queue.
    ///
    /// **NOTE:** This method is called at the end of both [`augmented_handle_incoming`](Self::augmented_handle_incoming) and [`augmented_proceed`](Self::augmented_proceed).
    fn update_augmented_message_queue(
        &mut self,
    ) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        let new_messages = self.state_machine_mut().message_queue().split_off(0);
        if !new_messages.is_empty() {
            let mut augmented_new_messages: Vec<
                Msg<
                    AugmentedType<
                        <Self::StateMachineType as StateMachine>::MessageBody,
                        Self::AdditionalParams,
                    >,
                >,
            > = Vec::with_capacity(new_messages.len());

            for msg in new_messages {
                augmented_new_messages.push(Msg {
                    sender: msg.sender,
                    receiver: msg.receiver,
                    body: AugmentedType {
                        // Adds augmentations (if any) or bail on error (if any).
                        extra: self.augment_outgoing_message(msg.sender, &msg.body)?,
                        base: msg.body,
                    },
                });
            }

            // Update augmented message queue.
            self.augmented_message_queue_mut()
                .extend(augmented_new_messages);
        }

        Ok(())
    }

    /// Handles incoming messages.
    fn augmented_handle_incoming(
        &mut self,
        msg: Msg<
            AugmentedType<
                <Self::StateMachineType as StateMachine>::MessageBody,
                Self::AdditionalParams,
            >,
        >,
    ) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        // Hook to run augmentations before calling `handle_incoming`.
        self.pre_handle_incoming(&msg)?;

        // Forwards all incoming messages to wrapped state machine.
        self.state_machine_mut()
            .handle_incoming(msg.map_body(|msg_body| msg_body.base))
            .map_err(Error::StateMachine)?;

        // Updates the augmented message queue.
        self.update_augmented_message_queue()
    }

    /// Performs some expensive computation.
    fn augmented_proceed(
        &mut self,
    ) -> Result<(), Error<<Self::StateMachineType as StateMachine>::Err>> {
        // Hook to run augmentations before calling `proceed`.
        self.pre_proceed()?;

        // Call `proceed` on the wrapped state machine.
        self.state_machine_mut()
            .proceed()
            .map_err(Error::StateMachine)?;

        // Updates the augmented message queue.
        self.update_augmented_message_queue()
    }

    /// Indicates whether protocol is ready to finish and output can be obtained by calling the [`augmented_pick_output`](Self::augmented_pick_output) method.
    fn augmented_is_finished(&self) -> bool {
        // We're ready to finish if the wrapped state machine is finished.
        self.state_machine().is_finished()
    }

    /// Returns protocol output i.e
    /// `None` if protocol is not yet finished (i.e. [`augmented_is_finished`](Self::augmented_is_finished) is false),
    /// `Some(Err(_))` if protocol terminated with an error and
    /// `Some(Ok(_))` if protocol finished successfully.
    fn augmented_pick_output(
        &mut self,
    ) -> Option<
        Result<
            AugmentedType<<Self::StateMachineType as StateMachine>::Output, Self::AdditionalOutput>,
            Error<<Self::StateMachineType as StateMachine>::Err>,
        >,
    > {
        // Picks output result from wrapped state machine, or returns None if protocol isn't finished yet.
        let result = self.state_machine_mut().pick_output()?;

        // Augments output with additional parameters or returns wrapped state machine error.
        Some(match result {
            Ok(output) => {
                match self.augment_output(output) {
                    // Adds augmentations (if any).
                    Ok(augmented_output) => Ok(augmented_output),
                    // Otherwise returns an appropriate error.
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(Error::StateMachine(error)),
        })
    }
}

/// A generic augmented type.
#[derive(Clone)]
pub struct AugmentedType<T, E> {
    /// Base parameters.
    pub base: T,
    /// Additional parameters.
    pub extra: Option<E>,
}

/// Additional parameters for identity authentication.
#[derive(Debug, Clone)]
pub struct IdentityAuthParams {
    /// Verifying key of the party (i.e `sk_i`).
    pub verifying_key: VerifyingKey,
    /// Verifying signature (e.g `varphi_i` or `psi`).
    pub verifying_signature: Signature,
}

/// Additional output as "signing share" and "sub-share" tuple.
pub type SubShareOutput = (SigningShare, SubShare);

/// A generic augmented state machine error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<T: IsCritical> {
    /// A wrapped error from `wamu-core`.
    Core(wamu_core::Error),
    /// A wrapped state machine error from `cggmp_threshold_ecdsa`.
    StateMachine(T),
    /// Missing augmentation parameters.
    MissingParams { bad_actors: Vec<usize> },
    /// An insecure FS-DKR threshold (i.e t > n/2, breaking the honest majority assumption).
    BadFSDKRThreshold,
}

impl<T: IsCritical> IsCritical for Error<T> {
    fn is_critical(&self) -> bool {
        match self {
            // All core errors are critical.
            Error::Core(_) => true,
            // Wrapped state machine errors call the wrapped implementation.
            Error::StateMachine(error) => error.is_critical(),
            // Augmentation parameters can't be skipped.
            Error::MissingParams { .. } => true,
            // FS-DKR assumptions can't be broken for key refresh.
            Error::BadFSDKRThreshold => true,
        }
    }
}

impl<T: IsCritical> From<wamu_core::Error> for Error<T> {
    fn from(error: wamu_core::Error) -> Self {
        Self::Core(error)
    }
}

impl<T: IsCritical> From<wamu_core::CryptoError> for Error<T> {
    fn from(error: wamu_core::CryptoError) -> Self {
        Self::Core(wamu_core::Error::Crypto(error))
    }
}

/// Implements `StateMachine` trait for types that implement `AugmentedStateMachine`.
///
/// Requires the types of the `AugmentedStateMachine`, the wrapped `StateMachine`, additional parameters and additional output.
macro_rules! impl_state_machine_for_augmented_state_machine {
    ($name:ident, $state_machine:path, $params:path, $output:path) => {
        impl<'a, I: wamu_core::IdentityProvider> StateMachine for $name<'a, I> {
            type MessageBody =
                AugmentedType<<$state_machine as StateMachine>::MessageBody, $params>;
            type Err = Error<<$state_machine as StateMachine>::Err>;
            type Output = AugmentedType<<$state_machine as StateMachine>::Output, $output>;

            fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
                self.augmented_handle_incoming(msg)
            }

            fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
                self.augmented_message_queue_mut()
            }

            fn wants_to_proceed(&self) -> bool {
                self.state_machine().wants_to_proceed()
            }

            fn proceed(&mut self) -> Result<(), Self::Err> {
                self.augmented_proceed()
            }

            fn round_timeout(&self) -> Option<Duration> {
                self.state_machine().round_timeout()
            }

            fn round_timeout_reached(&mut self) -> Self::Err {
                self.state_machine_mut().round_timeout_reached().into()
            }

            fn is_finished(&self) -> bool {
                self.augmented_is_finished()
            }

            fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
                self.augmented_pick_output()
            }

            fn current_round(&self) -> u16 {
                self.state_machine().current_round()
            }

            fn total_rounds(&self) -> Option<u16> {
                self.state_machine().total_rounds()
            }

            fn party_ind(&self) -> u16 {
                self.state_machine().party_ind()
            }

            fn parties(&self) -> u16 {
                self.state_machine().parties()
            }
        }
    };
}

/// Implements all required `AugmentedStateMachine` methods (i.e methods with no default implementation).
///
/// Requires names of the fields that store the wrapped `StateMachine` and the augment message queue.
macro_rules! impl_required_augmented_state_machine_methods {
    ($state_machine:ident, $message_queue:ident) => {
        /// Returns an immutable reference to the wrapped state machine.
        fn state_machine(&self) -> &Self::StateMachineType {
            &self.$state_machine
        }

        /// Returns a mutable reference to the wrapped state machine.
        fn state_machine_mut(&mut self) -> &mut Self::StateMachineType {
            &mut self.$state_machine
        }

        /// Returns an immutable reference to the augmented message queue.
        fn augmented_message_queue(
            &self,
        ) -> &Vec<
            Msg<
                AugmentedType<
                    <Self::StateMachineType as StateMachine>::MessageBody,
                    Self::AdditionalParams,
                >,
            >,
        > {
            &self.$message_queue
        }

        /// Returns a mutable reference to the augmented message queue.
        fn augmented_message_queue_mut(
            &mut self,
        ) -> &mut Vec<
            Msg<
                AugmentedType<
                    <Self::StateMachineType as StateMachine>::MessageBody,
                    Self::AdditionalParams,
                >,
            >,
        > {
            &mut self.$message_queue
        }
    };
}

/// Implements `From` trait for `StateMachine` associated error types.
macro_rules! from_state_machine_error {
    ($($module_path:path => ($module_alias:ident, $state_machine_type:ident)),*$(,)?) => {
        $(
        use $module_path as $module_alias;
        impl From<$module_alias::Error> for Error<<$module_alias::$state_machine_type as StateMachine>::Err> {
            fn from(error: $module_alias::Error) -> Self {
                Self::StateMachine(error)
            }
        }
        )*
    }
}

// Implements `From` trait for all upstream `StateMachine` associated error types from `cggmp-threshold-ecdsa` and `multi-party-ecdsa`.
from_state_machine_error! {
    cggmp_threshold_ecdsa::presign::state_machine => (presign_state_machine, PreSigning),
    cggmp_threshold_ecdsa::sign::state_machine => (sign_state_machine, Signing),
    cggmp_threshold_ecdsa::refresh::state_machine => (key_refresh_state_machine, KeyRefresh),
    multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen => (key_gen_state_machine, Keygen),
}

/// Given an identity provider and key output (e.g from key generation or key refresh),
/// returns augmented key output with the secret share cleared/zerorized,
/// along with its split "signing share" and "sub-share"
/// as described by [Wamu's share splitting protocol](https://wamu.tech/specification#share-splitting).
///
/// Ref: <https://wamu.tech/specification#share-splitting>.
pub fn split_key_output(
    identity_provider: &impl IdentityProvider,
    mut output: LocalKey<Secp256k1>,
) -> Result<AugmentedType<LocalKey<Secp256k1>, SubShareOutput>, wamu_core::Error> {
    // Retrieves secret share.
    let secret_share = SecretShare::try_from(output.keys_linear.x_i.to_bytes().deref())?;
    // Splits the secret share or returns appropriate error.
    let sub_shares = wamu_core::share_split_reconstruct::split(&secret_share, identity_provider)?;
    // Zerorize the secret share in `LocalKey<Secp256k1>` output.
    // NOTE: `wamu_core::SecretShare` implements `ZerorizeOnDrop` so we don't need to zerorize it explicitly.
    if let Some(raw_x_i) = output.keys_linear.x_i.into_raw().underlying_mut() {
        raw_x_i.zeroize();
    }
    output.keys_linear.x_i = Scalar::<Secp256k1>::zero();
    // Return augmented key output.
    Ok(AugmentedType {
        base: output,
        extra: Some(sub_shares),
    })
}

// Implement `Debug` trait for `AugmentedType` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<T, E> std::fmt::Debug for AugmentedType<T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Augmented Type")
    }
}
