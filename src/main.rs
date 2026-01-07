use hex::{decode, encode};
use rand::seq::SliceRandom;
use rand::thread_rng;
use raptorq::{Decoder, Encoder, EncodingPacket};

const SYMBOL_SIZE: u16 = 128;                   // Optimal for Kaspa headers/hashes
const REPAIR_PACKETS_PER_BLOCK: u32 = 10;       // Extra repair per source block (very robust)
const SIMULATED_LOSS: usize = 8;                // Test with higher loss if you want

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example Kaspa block hashes (add real ones from your node/logs)
    let block_hashes_hex = vec![
        "2f8bce2a7a4f7e4d8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2",
        "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4f1f2f3f40102030405060708",
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    ];

    println!("=== Kaspa Block Hash RaptorQ FEC Demo (Working & Robust) ===\n");
    println!("Symbol size: {} bytes", SYMBOL_SIZE);
    println!("Repair packets per block: {}", REPAIR_PACKETS_PER_BLOCK);
    println!("Simulated loss: {} packets\n", SIMULATED_LOSS);

    // Concatenate hashes
    let mut data_bytes = Vec::new();
    for (i, hash_hex) in block_hashes_hex.iter().enumerate() {
        let bytes = decode(hash_hex)?;
        assert_eq!(bytes.len(), 32);
        data_bytes.extend_from_slice(&bytes);
        println!("Original hash {}: {}", i + 1, hash_hex);
    }

    let data_len = data_bytes.len();
    println!("\nTotal data: {} bytes ({} hashes)\n", data_len, block_hashes_hex.len());

    // Encoder
    let encoder = Encoder::with_defaults(&data_bytes, SYMBOL_SIZE);

    // Get config for decoder
    let oti = encoder.get_config();

    // Generate packets: all source + repair_packets_per_block * num_blocks
    let packets: Vec<EncodingPacket> = encoder.get_encoded_packets(REPAIR_PACKETS_PER_BLOCK);

    let total_generated = packets.len();
    println!("Generated {} total packets (source + repair)\n", total_generated);

    // Preview first few
    for (i, pkt) in packets.iter().enumerate().take(8) {
        let preview = &pkt.data()[..std::cmp::min(8, pkt.data().len())];
        println!(
            "Packet {:2} | SBN {:2} ESI {:6} | {}...",
            i,
            pkt.payload_id().source_block_number(),
            pkt.payload_id().encoding_symbol_id(),
            encode(preview)
        );
    }

    // Simulate loss
    let mut rng = thread_rng();
    let mut received_packets = packets;
    received_packets.shuffle(&mut rng);
    received_packets.truncate(received_packets.len().saturating_sub(SIMULATED_LOSS));

    println!("\nLost {} packets → {} remaining", SIMULATED_LOSS, received_packets.len());

    // Decoder
    let mut decoder = Decoder::new(oti);

    // Feed packets incrementally
    let mut reconstructed: Option<Vec<u8>> = None;
    for packet in received_packets {
        if let Some(data) = decoder.decode(packet) {
            reconstructed = Some(data);
            println!("\nEarly reconstruction success after feeding some packets!");
            break;  // Optional: stop early on success
        }
    }

    match reconstructed {
        Some(recovered) => {
            println!("\nFULL SUCCESS! Recovered {} bytes\n", recovered.len());

            for (i, chunk) in recovered.chunks_exact(32).enumerate() {
                println!("Recovered hash {}: {}", i + 1, encode(chunk));
            }
        }
        None => {
            println!("\nFailed – need more packets (increase REPAIR_PACKETS_PER_BLOCK).");
        }
    }

    Ok(())
}
