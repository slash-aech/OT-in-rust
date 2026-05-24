#![no_std]

extern crate alloc;

pub mod crypto;
pub mod errors;
pub mod states;

pub use errors::OtError;
pub use states::{CiphertextPair, ReceiverKeys, SenderSetup, SenderTransmit};

#[cfg(test)]
mod tests {
    use super::*;
    use generic_ec::curves::Secp256k1; // Using Secp256k1 curve for testing out our architecture
    use rand::rngs::OsRng;

    #[test]
    fn verify_skeleton_pipeline() {
        let mut rng = OsRng;

        let message_0 = b"First Message Payload";
        let message_1 = b"Second Message Payload";

        // 1. Sender initializes session
        let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
        let global_c = sender_setup.public_c;

        // 2. Receiver sets up their keys with a choice bit (e.g., choice = true for message_1)
        let choice = true;
        let (receiver, public_pk0) = ReceiverKeys::new(&mut rng, choice, global_c);

        // 3. Sender receives Receiver's public point, transitions, and encrypts payloads
        let sender_transmit = sender_setup.transition(public_pk0).unwrap();
        let ciphertexts = sender_transmit.transmit(message_0, message_1);

        // 4. Receiver decrypts the ciphertext package
        let decrypted_result = receiver.decrypt(ciphertexts).unwrap();

        // Right now this passes because our fake stubs just mirror data back!
        assert_eq!(decrypted_result, message_1);
    }
}
