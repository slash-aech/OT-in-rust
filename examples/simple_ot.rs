use generic_ec::curves::Secp256k1;
use ot_in_rust::{OtError, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;

fn main() -> Result<(), OtError> {
    let mut rng = OsRng;

    println!("--- Initializing Bellare-Micali 1-out-of-2 OT ---");

    // 1. Secret inputs owned by the Sender
    let message_0 = b"Top-secret asset coordinates: 45.109, -122.680";
    let message_1 = b"Decoy asset coordinates: 0.000, 0.000";

    // 2. Sender Setup
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);
    let public_c = sender_setup.public_c;
    println!("[Sender] Generated global blinding factor C.");

    // 3. Receiver choice selection (We want to securely fetch message_0)
    let choice_bit = false; // false = message_0, true = message_1
    let (receiver, public_pk0) = ReceiverKeys::<Secp256k1>::new(&mut rng, choice_bit, public_c)?;
    println!("[Receiver] Generated blinded choice key PK0.");

    // 4. Sender generates ciphertexts bound to the receiver's choice
    let sender_transmit = sender_setup.transition(public_pk0)?;
    let ciphertexts = sender_transmit.transmit(message_0, message_1);
    println!("[Sender] Encrypted payloads using derived symmetric keys.");

    // 5. Receiver attempts decryption of their chosen message path
    let decrypted_payload = receiver.decrypt(ciphertexts.unwrap()).unwrap();

    println!("\n--- Protocol Execution Successful ---");
    println!(
        "[Receiver] Decrypted Message: \"{}\"",
        String::from_utf8_lossy(&decrypted_payload)
    );

    Ok(())
}
