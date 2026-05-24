use crate::errors::OtError;
use alloc::vec::Vec;
use chacha20poly1305::{
    AeadCore,
    aead::{Aead, KeyInit, OsRng},
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use core::convert::TryInto; // Safe core conversion for no_std
use generic_ec::{Curve, Point};
use hkdf::Hkdf;
use sha2::Sha256;

/// Domain separation string to bind these keys explicitly to our OT implementation.
const HKDF_INFO_TAG: &[u8] = b"Bellare-Micali-1-out-of-2-OT-v1-SymmetricKey";

/// Converts an abstract curve point into a uniformly distributed 32-byte symmetric key.
pub fn derive_symmetric_key<E: Curve>(point: &Point<E>) -> Result<[u8; 32], OtError> {
    let serialized_point = point.to_bytes(true);
    let hk = Hkdf::<Sha256>::new(None, serialized_point.as_ref());

    let mut okm = [0u8; 32];

    // Bubble up the error instead of panicking on HKDF expansion failure
    hk.expand(HKDF_INFO_TAG, &mut okm)
        .map_err(|_| OtError::KeyDerivationFailed)?;

    Ok(okm)
}

/// Encrypts a message buffer using ChaCha20Poly1305 AEAD.
/// The 12-byte random nonce is prepended directly to the returned ciphertext vector.
pub fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, OtError> {
    // Convert our fixed-size array safely and infallibly into the Key layout container.
    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);

    // Generate a fresh, unique 12-byte random nonce
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Encrypt the plaintext. Map any underlying hardware/state failures to our explicit error.
    let mut ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| OtError::EncryptionFailed)?;

    // Combine nonce and ciphertext cleanly
    let mut complete_payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    complete_payload.extend_from_slice(&nonce);
    complete_payload.append(&mut ciphertext);

    Ok(complete_payload)
}

/// Decrypts and authenticates a payload buffer using ChaCha20Poly1305 AEAD.
pub fn decrypt_payload(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, OtError> {
    // 1. Guard against short inputs using our specific granular error.
    if ciphertext_with_nonce.len() < 12 {
        return Err(OtError::PayloadTooShort);
    }

    // 2. Safely extract the 12-byte nonce using standard core trait conversion.
    let nonce_bytes: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .map_err(|_| OtError::PayloadTooShort)?;

    let nonce = Nonce::from(nonce_bytes);
    let actual_ciphertext = &ciphertext_with_nonce[12..];

    // 3. Convert our fixed-size key array infallibly into the exact Key wrapper.
    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);

    // 4. Perform decryption and MAC authentication.
    // If decryption fails here, it is directly caused by a bad MAC tag (tampering/wrong key).
    cipher
        .decrypt(&nonce, actual_ciphertext)
        .map_err(|_| OtError::InvalidMacTag)
}
