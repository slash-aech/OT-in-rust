//! This example shows how to pass raw byte vectors and structured cryptographic material
//! safely through the Oblivious Transfer protocol layers.

use generic_ec::curves::Secp256k1;
use ot_in_rust::{OtError, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;

fn main() -> Result<(), OtError> {
    let mut rng = OsRng;

    println!("==================================================");
    println!("     Example: Transferring Raw Cryptographic Data ");
    println!("==================================================");

    // 1. Imagine the Sender holds two high-entropy raw byte payloads (e.g., AES-256 keys)
    let private_key_alpha: [u8; 32] = [0xAA; 32];
    let private_key_beta: [u8; 32] = [0xBB; 32];

    // 2. Sender computes global parameter C
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let public_c = sender_setup.public_c;
    println!("[Sender] Global parameter C generated.");

    // 3. Receiver wants to download the second key (index 1) without leaking their choice
    let choice_bit = true; // true = index 1 (private_key_beta)
    let (receiver, public_pk0) = ReceiverKeys::<Secp256k1>::new(&mut rng, choice_bit, public_c)?;
    println!("[Receiver] Blinded public key request for index 1 transmitted.");

    // 4. Sender executes transmission over the raw buffers
    let sender_transmit = sender_setup.transition(public_pk0)?;
    let ciphertexts = sender_transmit.transmit(&private_key_alpha, &private_key_beta);
    println!("[Sender] Both keys encrypted via ChaCha20-Poly1305 and sent.");

    // 5. Receiver recovers the requested key
    let decrypted_bytes = receiver.decrypt(ciphertexts.unwrap())?;

    println!("\n--- Verification ---");
    println!(
        "[Receiver] Successfully retrieved payload size: {} bytes",
        decrypted_bytes.len()
    );
    print!("[Receiver] Data content hex: ");
    for byte in &decrypted_bytes {
        print!("{:02X}", byte);
    }
    println!();

    // Verify it matches private_key_beta perfectly
    assert_eq!(decrypted_bytes, private_key_beta.to_vec());
    println!("[Success] Recovered bytes match the requested secret key perfectly!");

    Ok(())
}
