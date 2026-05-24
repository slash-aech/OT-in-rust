//! This example simulates serializing and passing the protocol payloads across an
//! abstract network layer, mimicking a real TCP or WebSocket service connection.

use generic_ec::{Point, curves::Secp256k1};
use ot_in_rust::{CiphertextPair, OtError, ReceiverKeys, SenderSetup};
use rand::rngs::OsRng;
extern crate alloc;
use alloc::vec::Vec;

/// A mock network buffer used to pass raw byte payloads between parties.
struct MockNetworkChannel {
    buffer: Vec<u8>,
}

impl MockNetworkChannel {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Simulates sending bytes over the wire.
    fn send(&mut self, data: &[u8]) {
        self.buffer = data.to_vec();
    }

    /// Simulates reading incoming bytes from the wire.
    fn receive(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buffer)
    }
}

fn main() -> Result<(), OtError> {
    let mut rng = OsRng;
    let mut channel = MockNetworkChannel::new();

    println!("==================================================");
    println!("     Example: Simulating a Network OT Connection  ");
    println!("==================================================");

    // --- PHASE 1: SENDER SETUP ---
    let sender_setup = SenderSetup::<Secp256k1>::new(&mut rng);

    // Serialize the global parameter public_c to bytes to send to the receiver
    let serialized_c = sender_setup.public_c.to_bytes(true);
    channel.send(serialized_c.as_ref());
    println!(
        "[Wire] Sent global parameter public_c ({} bytes)",
        serialized_c.as_ref().len()
    );

    // --- PHASE 2: RECEIVER SELECTION ---
    // Receiver reads parameter C from the wire
    let incoming_c_bytes = channel.receive();
    let received_c =
        Point::<Secp256k1>::from_bytes(&incoming_c_bytes).map_err(|_| OtError::InvalidState)?;

    // Receiver picks choice 0 and computes public_pk0
    let choice = false; // Choice 0
    let (receiver, public_pk0) = ReceiverKeys::<Secp256k1>::new(&mut rng, choice, received_c)?;

    // Serialize public_pk0 to pass back to the sender
    let serialized_pk0 = public_pk0.to_bytes(true);
    channel.send(serialized_pk0.as_ref());
    println!(
        "[Wire] Sent blinded public_pk0 request ({} bytes)",
        serialized_pk0.as_ref().len()
    );

    // --- PHASE 3: SENDER TRANSMISSION ---
    // Sender reads public_pk0 from the wire
    let incoming_pk0_bytes = channel.receive();
    let received_pk0 =
        Point::<Secp256k1>::from_bytes(&incoming_pk0_bytes).map_err(|_| OtError::InvalidState)?;

    let message_0 = b"Symmetric Key Alpha for Database Access";
    let message_1 = b"Symmetric Key Beta for Database Access";

    let sender_transmit = sender_setup.transition(received_pk0)?;
    let ciphertexts = sender_transmit.transmit(message_0, message_1);

    // To send the CiphertextPair across the wire, we send lengths and byte packets
    let mut network_payload = Vec::new();
    network_payload
        .extend_from_slice(&(ciphertexts.as_ref().unwrap().c0.len() as u32).to_be_bytes());
    network_payload.extend_from_slice(&ciphertexts.as_ref().unwrap().c0);
    network_payload.extend_from_slice(&ciphertexts.unwrap().c1);

    channel.send(&network_payload);
    println!(
        "[Wire] Sent combined CiphertextPair payload ({} bytes)",
        network_payload.len()
    );

    // --- PHASE 4: RECEIVER DECRYPTION ---
    // Receiver parses the network packet stream
    let incoming_payload = channel.receive();
    if incoming_payload.len() < 4 {
        return Err(OtError::DecryptionFailed);
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&incoming_payload[..4]);
    let c0_len = u32::from_be_bytes(len_bytes) as usize;

    let c0 = incoming_payload[4..4 + c0_len].to_vec();
    let c1 = incoming_payload[4 + c0_len..].to_vec();
    let wire_ciphertexts = CiphertextPair { c0, c1 };

    // Decrypt the selected stream
    let decrypted = receiver.decrypt(wire_ciphertexts)?;
    println!("\n[Success] Network packet parsed and processed securely.");
    println!(
        "[Receiver] Final Output: \"{}\"",
        String::from_utf8_lossy(&decrypted)
    );

    Ok(())
}
