use crate::crypto;
use crate::errors::OtError;
use alloc::vec::Vec;
use generic_ec::{Curve, Point, SecretScalar};
use rand::{CryptoRng, Rng};

/// The structure managing a simple Ciphertext payload pair.
pub struct CiphertextPair {
    pub c0: Vec<u8>,
    pub c1: Vec<u8>,
}

// =========================================================================
// SENDER STATE ACTIONS
// =========================================================================

pub struct SenderSetup<E: Curve> {
    pub secret_c: SecretScalar<E>,
    pub public_c: Point<E>,
}

impl<E: Curve> SenderSetup<E> {
    /// Step 1: Initialize Sender, generate random scalar `c`, and compute `C = c * G`
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        // 1. Sample a cryptographically secure random scalar element c
        let secret_c = SecretScalar::<E>::random(rng);

        // 2. Perform scalar multiplication on the base generator: C = c * G
        // In generic-ec, multiplying a Point by a SecretScalar reference
        // yields the resulting Point.
        let public_c = Point::<E>::generator() * &secret_c;

        Self { secret_c, public_c }
    }
    /// Step 2: Receive the Receiver's public point `PK_0`, and transition to Transmission phase
    pub fn transition(self, pk0: Point<E>) -> Result<SenderTransmit<E>, OtError> {
        Ok(SenderTransmit {
            secret_c: self.secret_c,
            public_c: self.public_c,
            pk0,
        })
    }
}

pub struct SenderTransmit<E: Curve> {
    secret_c: SecretScalar<E>,
    public_c: Point<E>,
    pk0: Point<E>,
}

impl<E: Curve> SenderTransmit<E> {
    /// Step 4: Compute K0 and K1 using the Sender secret `c`, encrypt both messages, and return them
    pub fn transmit(self, m0: &[u8], m1: &[u8]) -> CiphertextPair {
        // 1. Calculate Point_0 = c * PK_0
        // In generic-ec, we use the scalar on the right side of the multiplication
        let point_0 = self.pk0 * &self.secret_c;

        // 2. Calculate Point_1 = c * (C - PK_0)
        let pk1 = self.public_c - self.pk0;
        let point_1 = pk1 * &self.secret_c;

        // 3. Pass these elliptic curve points to our crypto module to get 32-byte keys
        let k0 = crypto::derive_symmetric_key(&point_0);
        let k1 = crypto::derive_symmetric_key(&point_1);

        // 4. Encrypt both payloads using their respective keys
        let c0 = crypto::encrypt_payload(&k0, m0);
        let c1 = crypto::encrypt_payload(&k1, m1);

        CiphertextPair { c0, c1 }
    }
}

// =========================================================================
// RECEIVER STATE ACTIONS
// =========================================================================

pub struct ReceiverKeys<E: Curve> {
    choice: bool,
    secret_x: SecretScalar<E>,
    sender_c: Point<E>,
}

impl<E: Curve> ReceiverKeys<E> {
    /// Step 3: Receive Sender's `C`, process choice bit `b`, generate secret `x`, and output `PK_0`
    pub fn new<R: Rng + CryptoRng>(
        rng: &mut R,
        choice: bool,
        sender_c: Point<E>,
    ) -> (Self, Point<E>) {
        // 1. Generate the private scalar secret x
        let secret_x = SecretScalar::<E>::random(rng);

        // 2. Compute g^x = x * G
        let g_to_x = Point::<E>::generator() * secret_x.as_ref();

        // 3. Conditional branch according to selection bit b
        // If choice is 0 (false), PK_0 = g^x
        // If choice is 1 (true),  PK_0 = C - g^x
        let pk0 = if choice { sender_c - g_to_x } else { g_to_x };

        let receiver = Self {
            choice,
            secret_x,
            sender_c,
        };

        // Return the state tracker and the public PK_0 to be transmitted across the network
        (receiver, pk0)
    }

    /// Step 5: Derive receiver decryption key and decrypt targeted ciphertext payload
    pub fn decrypt(self, ciphertexts: CiphertextPair) -> Result<Vec<u8>, OtError> {
        // 1. Calculate the shared Diffie-Hellman point: Point_R = x * C
        let point_r = self.sender_c * &self.secret_x;

        // 2. Derive the 32-byte symmetric decryption key from the point
        let target_key = crypto::derive_symmetric_key(&point_r);

        // 3. Conditional branch: select the ciphertext that matches our choice bit
        if self.choice {
            // Choice was 1 (true) -> decrypt c1
            crypto::decrypt_payload(&target_key, &ciphertexts.c1)
        } else {
            // Choice was 0 (false) -> decrypt c0
            crypto::decrypt_payload(&target_key, &ciphertexts.c0)
        }
    }
}
