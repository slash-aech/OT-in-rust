use generic_ec::{Point, curves::Secp256k1}; // Standard high-security curve
use ot_in_rust::{CiphertextPair, OtError, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;

/// Test 1: Verify the happy path for choice 0 (m0) works seamlessly.
/// Notice how returning Result<(), OtError> allows us to use `?` instead of `.unwrap()`.
#[test]
fn test_happy_path_choice_0() -> Result<(), OtError> {
    let mut rng = OsRng;
    let m0 = b"Confidential Data A";
    let m1 = b"Confidential Data B";

    // 1. Sender initializes session
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let global_c = sender_setup.public_c;

    // 2. Receiver requests message 0
    let (receiver, public_pk0) = ReceiverKeys::new(&mut rng, false, global_c)?;

    // 3. Sender transmits
    let sender_transmit = sender_setup.transition(public_pk0)?;
    let ciphertexts = sender_transmit.transmit(m0, m1)?;

    // 4. Receiver decrypts
    let decrypted = receiver.decrypt(ciphertexts)?;
    assert_eq!(decrypted, m0);

    Ok(())
}

/// Test 2: Verify that an active attacker tampering with the ciphertext
/// over the network triggers an authentication failure instead of panicking.
#[test]
fn test_ciphertext_tampering_fails_gracefully() -> Result<(), OtError> {
    let mut rng = OsRng;
    let m0 = b"Secure Mint Instructions";
    let m1 = b"Alternative Payload";

    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let (receiver, public_pk0) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c)?;
    let sender_transmit = sender_setup.transition(public_pk0)?;

    // We mark this mutable so we can tamper with the bytes directly
    let mut ciphertexts = sender_transmit.transmit(m0, m1)?;

    // Simulate an attacker flipping a single bit in the c0 payload buffer.
    // 13 is past the 12-byte nonce, guaranteeing we hit the authenticated ciphertext.
    if ciphertexts.c0.len() > 13 {
        ciphertexts.c0[13] ^= 0x01;
    }

    // Decryption must explicitly return our new granular Error variant
    let result = receiver.decrypt(ciphertexts);

    // Check against the highly specific InvalidMacTag error
    assert_eq!(result, Err(OtError::InvalidMacTag));

    Ok(())
}

/// Test 3: Verify that an attacker truncating or dropping payload bytes
/// completely causes a safe error return rather than an out-of-bounds slice panic.
#[test]
fn test_malformed_short_ciphertext_payload() -> Result<(), OtError> {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let (receiver, _) = ReceiverKeys::new(&mut rng, true, sender_setup.public_c)?;

    // Create a completely truncated ciphertext payload (under the 12-byte nonce minimum)
    let broken_ciphertexts = CiphertextPair {
        c0: vec![0u8; 5],
        c1: vec![0u8; 8],
    };

    let result = receiver.decrypt(broken_ciphertexts);

    // Check against the new highly specific PayloadTooShort error
    assert_eq!(result, Err(OtError::PayloadTooShort));

    Ok(())
}

/// Test 4: Verify that empty plaintexts are handled perfectly and
/// authenticated properly by the underlying AEAD layer.
#[test]
fn test_empty_messages() -> Result<(), OtError> {
    let mut rng = OsRng;
    let empty_m0 = b"";
    let empty_m1 = b"";

    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let (receiver, public_pk0) = ReceiverKeys::new(&mut rng, true, sender_setup.public_c)?;
    let sender_transmit = sender_setup.transition(public_pk0)?;
    let ciphertexts = sender_transmit.transmit(empty_m0, empty_m1)?;

    let decrypted = receiver.decrypt(ciphertexts)?;
    assert_eq!(decrypted, empty_m1);

    Ok(())
}

/// Test 5: Verify our new Identity Point guard protects against rogue network payloads.
#[test]
fn test_rogue_identity_point_rejected() -> Result<(), OtError> {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);

    // Simulate an attacker trying to force the point at infinity across the network
    let identity_point = Point::<Secp256k1>::zero();

    // The sender's transition phase MUST reject this mathematically insecure point
    let result = sender_setup.transition(identity_point);

    assert_eq!(result.err(), Some(OtError::IdentityPointNotAllowed));

    Ok(())
}
