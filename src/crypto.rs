use crate::errors::OtError;
use alloc::vec::Vec;
use generic_ec::{Curve, Point};

/// Prototype KDF: Converts an abstract curve point into a 32-byte symmetric key.
pub fn derive_symmetric_key<E: Curve>(_point: &Point<E>) -> [u8; 32] {
    // TODO: Implement real HKDF-SHA256 here later
    [0u8; 32]
}

/// Prototype Cipher: Encrypts a message buffer using our derived symmetric key.
pub fn encrypt_payload(_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    // TODO: Implement real ChaCha20-Poly1305 authenticated encryption here later
    plaintext.to_vec()
}

/// Prototype Cipher: Decrypts a message buffer using our derived symmetric key.
pub fn decrypt_payload(_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, OtError> {
    // TODO: Implement real ChaCha20-Poly1305 decryption verification here later
    Ok(ciphertext.to_vec())
}
