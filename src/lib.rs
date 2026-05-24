#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # Bellare-Micali 1-out-of-2 Oblivious Transfer (OT)
//!
//! A high-assurance, panic-free, `#![no_std]` implementation of the classic Bellare-Micali
//! Oblivious Transfer protocol.
//!
//! ## Protocol Architecture
//! This implementation utilizes a strongly typed state machine to enforce compile-time sequential
//! integrity:
//! 1. `SenderSetup` initializes the public parameters.
//! 2. `ReceiverKeys` generates blinded public requests selecting message index `0` or `1`.
//! 3. `SenderTransmit` computes blind symmetric keys to encrypt payloads.
//!
//! ## Cryptographic Primitives
//! * **Asymmetric Layer:** Abstracted over `generic-ec::Curve` (typically `Secp256k1`).
//! * **Key Derivation:** HKDF-SHA256 handles key extraction and domain separation.
//! * **Symmetric Layer:** ChaCha20-Poly1305 AEAD ensures confidentiality and ciphertext integrity.

extern crate alloc;

/// Core authenticated encryption and key derivation routines.
pub mod crypto;

/// Protocol error types.
pub mod errors;

/// Strongly typed protocol state machines for the Sender and Receiver.
pub mod states;

pub use errors::OtError;
pub use states::{CiphertextPair, ReceiverKeys, SenderSetup, SenderTransmit};
