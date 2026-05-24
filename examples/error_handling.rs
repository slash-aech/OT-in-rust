use generic_ec::{Point, curves::Secp256k1};
use ot_in_rust::{CiphertextPair, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;

fn main() {
    println!("--- Starting Exhaustive Adversarial Error Trace ---");

    run_identity_point_test();
    run_short_payload_test();
    run_tampering_test();
    run_wrong_secret_test();

    println!("--- Exhaustive trace complete. ---");
}

fn run_identity_point_test() {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);

    // Test: Identity Point (Zero) as PK0
    let result = sender_setup.transition(Point::<Secp256k1>::zero());

    match result {
        Err(e) => println!("[Expected Failure] Identity Point: {}", e),
        Ok(_) => println!("[SECURITY VULNERABILITY] Identity point was accepted!"),
    }
}

fn run_short_payload_test() {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let (receiver, _) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c).unwrap();

    let broken_pair = CiphertextPair {
        c0: vec![0u8; 5], // Too short (min 12 for nonce)
        c1: vec![0u8; 5],
    };

    let result = receiver.decrypt(broken_pair);

    match result {
        Err(e) => println!("[Expected Failure] Short Payload: {}", e),
        Ok(_) => println!("[SECURITY VULNERABILITY] Truncated payload was accepted!"),
    }
}

fn run_tampering_test() {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let (receiver, pk0) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c).unwrap();
    let sender_transmit = sender_setup.transition(pk0).unwrap();

    let mut ciphertexts = sender_transmit
        .transmit(b"sensitive_data", b"other_data")
        .unwrap();

    // Tamper with ciphertext at index 13
    if ciphertexts.c0.len() > 13 {
        ciphertexts.c0[13] ^= 0x01;
    }

    let result = receiver.decrypt(ciphertexts);

    match result {
        Err(e) => println!("[Expected Failure] Tampering: {}", e),
        Ok(_) => println!("[SECURITY VULNERABILITY] Tampered ciphertext was accepted!"),
    }
}

fn run_wrong_secret_test() {
    let mut rng = OsRng;
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);

    // Setup for receiver 1
    let (_receiver1, pk0) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c).unwrap();

    // Setup for receiver 2 (Impostor)
    let (receiver2, _) = ReceiverKeys::new(&mut rng, false, sender_setup.public_c).unwrap();

    let sender_transmit = sender_setup.transition(pk0).unwrap();
    let ciphertexts = sender_transmit.transmit(b"SecretA", b"SecretB").unwrap();

    // Attempt decryption with wrong key
    let result = receiver2.decrypt(ciphertexts);

    match result {
        Err(e) => println!("[Expected Failure] Wrong Key/State: {}", e),
        Ok(_) => println!("[SECURITY VULNERABILITY] Decryption with wrong key succeeded!"),
    }
}
