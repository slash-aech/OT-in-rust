use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtError {
    /// The public key or point sent by the counterparty is invalid.
    InvalidPoint,
    /// The final message decryption failed.
    DecryptionFailed,
}

impl fmt::Display for OtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint => write!(f, "Invalid elliptic curve point encountered"),
            Self::DecryptionFailed => write!(f, "Symmetric payload decryption failed"),
        }
    }
}
