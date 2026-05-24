use generic_ec::{Point, curves::Secp256k1};
use ot_in_rust::{CiphertextPair, OtError, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;

#[test]
fn test_entire_error_matrix() -> Result<(), OtError> {
    let mut rng = OsRng;

    // --- 1. Test: IdentityPointNotAllowed (Sender transition) ---
    // The scope block `{}` ensures sender_setup is dropped after this block
    {
        let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
        let result = sender_setup.transition(Point::<Secp256k1>::zero());
        assert_eq!(result.err(), Some(OtError::IdentityPointNotAllowed));
    } // sender_setup is consumed here.

    // --- 2. Test: IdentityPointNotAllowed (Receiver setup) ---
    {
        let result_rec = ReceiverKeys::new(&mut rng, false, Point::<Secp256k1>::zero());
        assert_eq!(result_rec.err(), Some(OtError::IdentityPointNotAllowed));
    }

    // --- 3. Test: PayloadTooShort ---
    {
        let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
        let (receiver, _) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c)?;
        let broken_pair = CiphertextPair {
            c0: vec![0u8; 5],
            c1: vec![0u8; 5],
        };
        let result_short = receiver.decrypt(broken_pair);
        assert_eq!(result_short.err(), Some(OtError::PayloadTooShort));
    }

    // --- 4. Test: InvalidMacTag (Tampering) ---
    {
        let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
        let (receiver, pk0) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c)?;
        let sender_transmit = sender_setup.transition(pk0)?;
        let mut valid_ciphertexts = sender_transmit.transmit(b"msg0", b"msg1")?;

        // Tamper
        if valid_ciphertexts.c0.len() > 13 {
            valid_ciphertexts.c0[13] ^= 0x01;
        }

        let result_tamper = receiver.decrypt(valid_ciphertexts);
        assert_eq!(result_tamper.err(), Some(OtError::InvalidMacTag));
    }

    Ok(())
}
