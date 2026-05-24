use core::fmt;

/// Errors that can occur during the execution of the Oblivious Transfer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtError {
    /// Raised when generic ciphertext authentication or decryption fails.
    DecryptionFailed,
    /// Raised if an elliptic curve Point does not correspond to a valid curve coordinate.
    InvalidPoint,
    /// Raised if a protocol state is reached which is invalid or executed out of order.
    InvalidState,
    /// The incoming network payload does not contain enough bytes to extract a valid 12-byte nonce.
    PayloadTooShort,
    /// The ChaCha20-Poly1305 MAC tag verification failed (tampered data or incorrect key).
    InvalidMacTag,
    /// Internal cryptographic hardware or cipher state failed during encryption processing.
    EncryptionFailed,
    /// HKDF expansion failed due to invalid buffer length constraints.
    KeyDerivationFailed,
    /// The provided elliptic curve point is the identity point (point at infinity), which is insecure.
    IdentityPointNotAllowed,
}

impl fmt::Display for OtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecryptionFailed => write!(f, "Symmetric payload decryption failed"),
            Self::InvalidPoint => write!(f, "Invalid elliptic curve point encountered"),
            Self::InvalidState => write!(
                f,
                "The protocol state encountered is invalid or out of order"
            ),
            Self::PayloadTooShort => write!(
                f,
                "Incoming network payload is too short to extract a valid nonce"
            ),
            Self::InvalidMacTag => write!(
                f,
                "ChaCha20-Poly1305 cryptographic MAC tag verification failed"
            ),
            Self::EncryptionFailed => write!(f, "Symmetric encryption operation failed internally"),
            Self::KeyDerivationFailed => {
                write!(f, "HKDF expansion failed due to output length constraints")
            }
            Self::IdentityPointNotAllowed => write!(
                f,
                "Insecure elliptic curve identity point (point at infinity) rejected"
            ),
        }
    }
}

// Implements the standard error trait for seamless integration with downstream error management crates
impl core::error::Error for OtError {}
