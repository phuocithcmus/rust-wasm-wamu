//! Types, traits, abstractions and utilities for authorized (i.e initiated by identity authentication or quorum approval) key refresh.
//!
//! NOTE: Used by share addition, share removal, threshold modification and share recovery with quorum protocols.

use round_based::{IsCritical, Msg, StateMachine};
use wamu_core::IdentityProvider;

use crate::key_refresh::AugmentedKeyRefresh;
use crate::{IdentityAuthentication, QuorumApproval};

/// A [`StateMachine`](StateMachine) that executes an authorization state machine (e.g. identity authenticated or quorum approved) and then a key refresh state machine in sequence.
pub trait AuthorizedKeyRefresh<'a, I: IdentityProvider + 'a>: StateMachine {
    /// The type of the authorization state machine.
    type InitStateMachineType: StateMachine;

    /// Returns an immutable reference to the authorization state machine.
    fn auth_state_machine(&self) -> &Self::InitStateMachineType;

    /// Returns a mutable reference to the authorization state machine.
    fn auth_state_machine_mut(&mut self) -> &mut Self::InitStateMachineType;

    /// Returns an immutable reference to the key refresh state machine.
    fn refresh_state_machine(&self) -> Option<&AugmentedKeyRefresh<'a, I>>;

    /// Returns a mutable reference to the key refresh state machine.
    fn refresh_state_machine_mut(&mut self) -> Option<&mut AugmentedKeyRefresh<'a, I>>;

    /// Sets the key refresh state machine.
    fn set_refresh_state_machine(&mut self, state_machine: AugmentedKeyRefresh<'a, I>);

    /// Returns an immutable reference to the composite message queue.
    fn composite_message_queue(
        &self,
    ) -> &Vec<Msg<Message<'a, I, <Self::InitStateMachineType as StateMachine>::MessageBody>>>;

    /// Returns a mutable reference to the composite message queue.
    fn composite_message_queue_mut(
        &mut self,
    ) -> &mut Vec<Msg<Message<'a, I, <Self::InitStateMachineType as StateMachine>::MessageBody>>>;

    /// Returns an immutable reference to an "out of order" message buffer.
    fn out_of_order_buffer(
        &self,
    ) -> &Vec<Msg<Message<'a, I, <Self::InitStateMachineType as StateMachine>::MessageBody>>>;

    /// Returns a mutable reference to an "out of order" message buffer.
    fn out_of_order_buffer_mut(
        &mut self,
    ) -> &mut Vec<Msg<Message<'a, I, <Self::InitStateMachineType as StateMachine>::MessageBody>>>;

    /// Returns an initialized key refresh state machine (if possible).
    fn create_key_refresh(
        &mut self,
    ) -> Result<
        AugmentedKeyRefresh<'a, I>,
        Error<'a, I, <Self::InitStateMachineType as StateMachine>::Err>,
    >;

    /// Updates the composite message queue by
    /// retrieving the message queue from the currently active wrapped state machines (i.e initialization or key refresh).
    ///
    /// **NOTE:** This method is called at the end of both [`handle_incoming`](StateMachine::handle_incoming) and [`proceed`](StateMachine::proceed).
    fn update_composite_message_queue(
        &mut self,
    ) -> Result<(), Error<'a, I, <Self::InitStateMachineType as StateMachine>::Err>> {
        match self.refresh_state_machine_mut() {
            // Retrieves initialization phase messages.
            None => {
                let new_messages = self.auth_state_machine_mut().message_queue().split_off(0);
                if !new_messages.is_empty() {
                    // Update composite message queue.
                    self.composite_message_queue_mut().extend(
                        &mut new_messages
                            .into_iter()
                            .map(|msg| msg.map_body(|msg_body| Message::Init(msg_body))),
                    );
                }
            }
            Some(refresh_state_machine) => {
                let new_messages = refresh_state_machine.message_queue().split_off(0);
                if !new_messages.is_empty() {
                    // Update composite message queue.
                    self.composite_message_queue_mut().extend(
                        &mut new_messages.into_iter().map(|msg| {
                            msg.map_body(|msg_body| Message::Refresh(Box::new(msg_body)))
                        }),
                    );
                }
            }
        }

        Ok(())
    }

    /// Transitions to the key refresh state machine if the initialization state machine is finished and the key refresh state machine is not yet active.
    ///
    /// **NOTE:** This method is called at the end of both [`handle_incoming`](StateMachine::handle_incoming) and [`proceed`](StateMachine::proceed).
    fn perform_transition(
        &mut self,
    ) -> Result<(), Error<'a, I, <Self::InitStateMachineType as StateMachine>::Err>> {
        if self.refresh_state_machine().is_none() && self.auth_state_machine().is_finished() {
            // Create a key refresh state machine.
            let mut key_refresh = self.create_key_refresh()?;

            // Forwards any "out of order" refresh messages to the key refresh state machine.
            let out_of_order_messages = self.out_of_order_buffer_mut().split_off(0);
            if !out_of_order_messages.is_empty() {
                for msg in out_of_order_messages {
                    if let Message::Refresh(msg_body) = msg.body {
                        key_refresh.handle_incoming(Msg {
                            sender: msg.sender,
                            receiver: msg.receiver,
                            body: *msg_body,
                        })?;
                    }
                }
            }

            // Sets key refresh as the active state machine.
            self.set_refresh_state_machine(key_refresh);

            // Retrieves messages from state transitions (if any) and wraps them.
            self.update_composite_message_queue()?;
        }

        Ok(())
    }
}

/// A generic authorized key refresh message.
#[derive(Clone)]
pub enum Message<'a, I: IdentityProvider, T> {
    Init(T),
    Refresh(Box<<AugmentedKeyRefresh<'a, I> as StateMachine>::MessageBody>),
}

/// A generic authorized key refresh error.
#[derive(Debug)]
pub enum Error<'a, I: IdentityProvider, E> {
    Init(E),
    Refresh(<AugmentedKeyRefresh<'a, I> as StateMachine>::Err),
    AlreadyPicked,
    InvalidInput,
    OutOfOrderMessage,
}

impl<'a, I: IdentityProvider, E> IsCritical for Error<'a, I, E> {
    fn is_critical(&self) -> bool {
        // Out of order messages are not critical errors, while all other errors are critical.
        !matches!(self, Error::OutOfOrderMessage)
    }
}

impl<'a, I: IdentityProvider, E> From<<AugmentedKeyRefresh<'a, I> as StateMachine>::Err>
    for Error<'a, I, E>
{
    fn from(error: <AugmentedKeyRefresh<'a, I> as StateMachine>::Err) -> Self {
        Self::Refresh(error)
    }
}

/// Implements `StateMachine` trait for types that implement `AuthorizedKeyRefresh`.
///
/// Requires the types of the `AugmentedStateMachine`, the wrapped `StateMachine`, additional parameters and additional output.
macro_rules! impl_state_machine_for_authorized_key_refresh {
    ($name:ident, $idx:ident, $n_parties:ident) => {
        impl<'a, I: IdentityProvider> StateMachine for $name<'a, I> {
            type MessageBody = Message<
                'a,
                I,
                <<Self as AuthorizedKeyRefresh<'a, I>>::InitStateMachineType as StateMachine>::MessageBody,
            >;
            type Err = Error<'a, I, <<Self as AuthorizedKeyRefresh<'a, I>>::InitStateMachineType as StateMachine>::Err>;
            type Output = <AugmentedKeyRefresh<'a, I> as StateMachine>::Output;

            fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
                match msg.body {
                    // Initialization messages are forwarded to the initialization state machine if it's still active,
                    // otherwise an error is returned.
                    Message::Init(id_msg) => match self.refresh_state_machine() {
                        None => {
                            self.auth_state_machine_mut().handle_incoming(Msg {
                                sender: msg.sender,
                                receiver: msg.receiver,
                                body: id_msg,
                            })?;
                        }
                        Some(_) => {
                            self.out_of_order_buffer_mut().push(Msg {
                                sender: msg.sender,
                                receiver: msg.receiver,
                                body: Message::Init(id_msg),
                            });
                            return Err(Error::OutOfOrderMessage);
                        }
                    },
                    // Refresh messages are forwarded to the refresh state machine if it's active,
                    // otherwise an error is returned.
                    Message::Refresh(refresh_msg) => {
                        match self.refresh_state_machine_mut() {
                            Some(refresh_state_machine) => {
                                refresh_state_machine.handle_incoming(Msg {
                                    sender: msg.sender,
                                    receiver: msg.receiver,
                                    body: *refresh_msg,
                                })?;
                            }
                            None => {
                                self.out_of_order_buffer_mut().push(Msg {
                                    sender: msg.sender,
                                    receiver: msg.receiver,
                                    body: Message::Refresh(refresh_msg),
                                });
                                return Err(Error::OutOfOrderMessage);
                            }
                        }
                    }
                }

                // Updates the composite message queue.
                self.update_composite_message_queue()?;

                // Attempts to transition to the next state machine.
                self.perform_transition()
            }

            fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
                self.composite_message_queue_mut()
            }

            fn wants_to_proceed(&self) -> bool {
                // `wants_to_proceed` is forwarded to the active state machine.
                match self.refresh_state_machine() {
                    None => self.auth_state_machine().wants_to_proceed(),
                    Some(refresh_state_machine) => refresh_state_machine.wants_to_proceed(),
                }
            }

            fn proceed(&mut self) -> Result<(), Self::Err> {
                // `proceed` is forwarded to the active state machine.
                match self.refresh_state_machine_mut() {
                    None => self.auth_state_machine_mut().proceed()?,
                    Some(refresh_state_machine) => refresh_state_machine.proceed()?,
                }

                // Updates the composite message queue.
                self.update_composite_message_queue()?;

                // Attempts to transition to the next state machine.
                self.perform_transition()
            }

            fn round_timeout(&self) -> Option<Duration> {
                None
            }

            fn round_timeout_reached(&mut self) -> Self::Err {
                panic!("no timeout was set")
            }

            fn is_finished(&self) -> bool {
                // Is finished is true if both state machines are finished.
                self.auth_state_machine().is_finished()
                    && self
                        .refresh_state_machine()
                        .map_or(false, |refresh_state_machine| {
                            refresh_state_machine.is_finished()
                        })
            }

            fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
                // Picks output from key refresh state machine (if possible).
                self.is_finished().then(|| {
                    self.refresh_state_machine_mut()
                        .and_then(|refresh_state_machine| refresh_state_machine.pick_output())
                        .map(|it| it.map_err(|error| Error::Refresh(error)))
                })?
            }

            fn current_round(&self) -> u16 {
                // Computes current round as an aggregate based on active state machine.
                match self.refresh_state_machine() {
                    None => self.auth_state_machine().current_round(),
                    Some(refresh_state_machine) => {
                        self.auth_state_machine().total_rounds().unwrap_or(0)
                            + refresh_state_machine.current_round()
                    }
                }
            }

            fn total_rounds(&self) -> Option<u16> {
                None
            }

            fn party_ind(&self) -> u16 {
                self.$idx
            }

            fn parties(&self) -> u16 {
                self.$n_parties
            }
        }
    };
}

/// Implements all required `AuthorizedKeyRefresh` getters.
///
/// Requires names of the associated fields
/// (.ie the authorization and key refresh `StateMachine` and the composite message queue).
macro_rules! impl_required_authorized_key_refresh_getters {
    ($auth_state_machine:ident, $refresh_state_machine:ident, $message_queue:ident, $out_of_order_buffer:ident) => {
        fn auth_state_machine(&self) -> &Self::InitStateMachineType {
            &self.$auth_state_machine
        }

        fn auth_state_machine_mut(&mut self) -> &mut Self::InitStateMachineType {
            &mut self.$auth_state_machine
        }

        fn refresh_state_machine(&self) -> Option<&AugmentedKeyRefresh<'a, I>> {
            self.$refresh_state_machine.as_ref()
        }

        fn refresh_state_machine_mut(&mut self) -> Option<&mut AugmentedKeyRefresh<'a, I>> {
            self.$refresh_state_machine.as_mut()
        }

        fn set_refresh_state_machine(&mut self, state_machine: AugmentedKeyRefresh<'a, I>) {
            self.$refresh_state_machine = Some(state_machine);
        }

        fn composite_message_queue(
            &self,
        ) -> &Vec<
            Msg<
                Message<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            &self.$message_queue
        }

        fn composite_message_queue_mut(
            &mut self,
        ) -> &mut Vec<
            Msg<
                Message<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            self.$message_queue.as_mut()
        }

        fn out_of_order_buffer(
            &self,
        ) -> &Vec<
            Msg<
                Message<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            &self.$out_of_order_buffer
        }

        fn out_of_order_buffer_mut(
            &mut self,
        ) -> &mut Vec<
            Msg<
                Message<
                    'a,
                    I,
                    <Self::InitStateMachineType as StateMachine>::MessageBody,
                >,
            >,
        > {
            self.$out_of_order_buffer.as_mut()
        }
    };
}

/// Implements `From` trait for `StateMachine` associated error types.
macro_rules! from_state_machine_error {
    ($($state_machine_type:ident),*$(,)?) => {
        $(
        impl<'a, I: IdentityProvider> From<<$state_machine_type<'a, I> as StateMachine>::Err> for Error<'a, I, <$state_machine_type<'a, I> as StateMachine>::Err> {
            fn from(error: <$state_machine_type<'a, I> as StateMachine>::Err) -> Self {
                Self::Init(error)
            }
        }
        )*
    }
}

// Implements `From` trait for `IdentityAuthentication` and `QuorumApproval` state machine error types.
from_state_machine_error! {
    IdentityAuthentication,
    QuorumApproval,
}

// Implement `Debug` trait for `Message` for test simulations.
#[cfg(any(test, feature = "dev"))]
impl<'a, I: IdentityProvider, T> std::fmt::Debug for Message<'a, I, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authorized Key Refresh Message")
    }
}
