use clap::{Parser, Subcommand};
use katzen_airgapped::{fragment_payload, render_qr_terminal, KpagChunk, MsgType, Reassembler, DEFAULT_CHUNK_SIZE};
use katzen_airgapped::pigeonhole::write_private_atomic;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Parser)]
#[command(name = "katzen-hot")]
#[command(about = "Katzenpost Hot Station (Networked Relay & Blind Forwarder)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ingest optical air-gap stream from stdin (one QR string per line)
    Ingest {
        /// Optional path to kpclientd Unix domain socket
        #[arg(short, long, default_value = "/run/katzenpost/client.sock")]
        socket: PathBuf,

        /// Optional TCP endpoint for kpclientd
        #[arg(short, long)]
        tcp: Option<String>,

        /// Directory to spool outbound Sphinx packets if daemon is offline
        #[arg(long, default_value = "/tmp/katzen-hot-spool")]
        spool_dir: PathBuf,
    },

    /// Ingest optical air-gap stream directly from a webcam via zbarcam
    Scan {
        /// Video device path
        #[arg(short, long, default_value = "/dev/video0")]
        device: String,

        /// Optional path to kpclientd Unix domain socket
        #[arg(short, long, default_value = "/run/katzenpost/client.sock")]
        socket: PathBuf,

        /// Optional TCP endpoint for kpclientd
        #[arg(short, long)]
        tcp: Option<String>,

        /// Directory to spool outbound Sphinx packets if daemon is offline
        #[arg(long, default_value = "/tmp/katzen-hot-spool")]
        spool_dir: PathBuf,
    },

    /// Ingest acoustic air-gap stream directly from microphone via ggwave
    Listen {
        /// Optional path to kpclientd Unix domain socket
        #[arg(short, long, default_value = "/run/katzenpost/client.sock")]
        socket: PathBuf,

        /// Optional TCP endpoint for kpclientd
        #[arg(short, long)]
        tcp: Option<String>,

        /// Directory to spool outbound Sphinx packets if daemon is offline
        #[arg(long, default_value = "/tmp/katzen-hot-spool")]
        spool_dir: PathBuf,

        /// Timeout in seconds waiting for an audio chunk (default 20s)
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,
    },

    /// Encapsulate a received mixnet response into a QR code for the Cold Terminal to scan
    SendReply {
        /// Plaintext or raw encrypted reply bytes from mixnet
        #[arg(short, long)]
        data: String,

        /// Sequence ID to correlate
        #[arg(short, long, default_value_t = 1001)]
        seq_id: u32,

        /// Transmit reply over sound via ggwave acoustic modulation
        #[arg(long, default_value_t = false)]
        sound: bool,
    },
}

fn forward_or_spool_packet(
    seq_id: u32,
    msg_type: MsgType,
    payload: &[u8],
    socket_path: &Path,
    tcp_addr: Option<&str>,
    spool_dir: &Path,
) {
    println!("\n=======================================================");
    println!(" [SUCCESS] FULL PACKET REASSEMBLED OVER AIR-GAP!");
    println!("=======================================================");
    println!("Sequence ID:     {}", seq_id);
    println!("Message Type:    {:?}", msg_type);
    println!("Assembled Size:  {} bytes", payload.len());
    println!("=======================================================");
    if msg_type != MsgType::SphinxOut || payload.len() != 1024 {
        eprintln!("[-] Unexpected packet type {:?} or size {}; refusing dispatch", msg_type, payload.len());
        return;
    }

    println!("[*] Attempting live mixnet dispatch via kpclientd...");
    match katzen_airgapped::thinclient::dispatch_via_kpclientd(payload, "courier", socket_path, tcp_addr) {
        Ok(receipt) => {
            println!("[✓] Live mixnet dispatch confirmed by kpclientd!");
            println!("    Epoch:             {}", receipt.epoch);
            println!("    Destination:       {}", receipt.destination_service);
            println!("    Destination Node:  {}", receipt.destination_node_hex);
            println!("    Forward Route:     {}", receipt.forward_route.join(" -> "));
            println!("    Return Route:      {}", receipt.return_route.join(" -> "));
            println!("    Reply ETA:         {} ms", receipt.reply_eta_ms);

            let sent_dir = spool_dir.join("sent");
            if let Err(e) = std::fs::create_dir_all(&sent_dir) {
                eprintln!("[-] Warning: could not create sent directory: {}", e);
            } else {
                let receipt_file = sent_dir.join(format!("receipt_{}.json", seq_id));
                if let Ok(json_bytes) = serde_json::to_vec_pretty(&receipt) {
                    if let Err(e) = write_private_atomic(&receipt_file, &json_bytes) {
                        eprintln!("[-] Warning: failed to record delivery receipt: {}", e);
                    } else {
                        println!("[i] Delivery receipt recorded: {}", receipt_file.display());
                    }
                }
            }
        }
        Err(err) => {
            println!("[-] kpclientd dispatch failed or daemon offline: {}", err);
            println!("[*] Durable spool fallback: saving packet to outbox for deferred transmission...");

            let outbox_dir = spool_dir.join("outbox");
            if let Err(e) = std::fs::create_dir_all(&outbox_dir) {
                eprintln!("[-] Failed to create outbox directory: {}", e);
                return;
            }

            let spool_file = outbox_dir.join(format!("sphinx_outbound_{}.bin", seq_id));
            match write_private_atomic(&spool_file, payload) {
                Ok(_) => {
                    println!("[✓] Packet durably spooled to: {}", spool_file.display());
                }
                Err(e) => {
                    eprintln!("[-] Failed to spool packet to outbox: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_forward_or_spool_handling() {
        let root = std::env::temp_dir().join(format!("katzen-hot-test-{}", rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("nonexistent_daemon.sock");
        let spool = root.join("spool");

        forward_or_spool_packet(1, MsgType::SphinxOut, &[0x42u8; 1024], &socket, None, &spool);

        let spooled = spool.join("outbox").join("sphinx_outbound_1.bin");
        let receipt = spool.join("sent").join("receipt_1.json");

        // Either live dispatch succeeded (recording receipt) or durable outbox spool took over
        if receipt.exists() {
            let data = fs::read_to_string(&receipt).unwrap();
            assert!(data.contains("destination_service") || data.contains("epoch"));
            println!("Verified live dispatch receipt generation!");
        } else {
            assert!(spooled.exists(), "Expected outbox spool file to exist upon daemon offline");
            assert_eq!(fs::metadata(&spooled).unwrap().permissions().mode() & 0o777, 0o600);
            let contents = fs::read(&spooled).unwrap();
            assert_eq!(contents.len(), 1024);
            assert_eq!(contents[0], 0x42);
            println!("Verified durable spooling fallback!");
        }

        // Non-SphinxOut message type should be rejected without spooling or dispatch
        forward_or_spool_packet(2, MsgType::ReplyIn, &[0x42u8; 1024], &socket, None, &spool);
        assert!(!spool.join("outbox").join("sphinx_outbound_2.bin").exists());
        assert!(!spool.join("sent").join("receipt_2.json").exists());

        fs::remove_dir_all(&root).unwrap();
    }
}

fn process_stream<R: BufRead>(
    reader: R,
    socket_path: &Path,
    tcp_addr: Option<&str>,
    spool_dir: &Path,
) {
    let mut reassembler = Reassembler::new();

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match KpagChunk::from_qr_string(trimmed) {
            Ok(chunk) => {
                let seq = chunk.header.seq_id;
                let part = chunk.header.part_index + 1;
                let total = chunk.header.total_parts;

                println!("[+] Validated chunk {}/{} for Seq #{} (BLAKE3 checksum OK)", part, total, seq);

                match reassembler.add_chunk(chunk) {
                    Ok(Some((reconstructed_type, seq_id, payload))) => {
                        forward_or_spool_packet(
                            seq_id,
                            reconstructed_type,
                            &payload,
                            socket_path,
                            tcp_addr,
                            spool_dir,
                        );
                        break;
                    }
                    Ok(None) => {
                        if let Some((current, total)) = reassembler.progress(seq) {
                            println!("    Progress: {}/{} chunks received.", current, total);
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] Reassembly error: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] Invalid chunk rejected: {}", e);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ingest {
            socket,
            tcp,
            spool_dir,
        } => {
            println!("=======================================================");
            println!(" KATZENPOST HOT STATION: BLIND RELAY FORWARDER ");
            println!("=======================================================");
            println!("Status: ONLINE (Waiting for optical air-gap stream on stdin)");
            println!("Paste or pipe 'kpag://...' QR tokens line by line.");
            println!("Press Ctrl+D when finished.\n");

            let stdin = io::stdin();
            process_stream(stdin.lock(), &socket, tcp.as_deref(), &spool_dir);
        }

        Commands::Scan {
            device,
            socket,
            tcp,
            spool_dir,
        } => {
            println!("=======================================================");
            println!(" KATZENPOST HOT STATION: WEBCAM LIVE SCANNER ");
            println!("=======================================================");
            println!("Starting zbarcam on device: {}", device);
            println!("Point your webcam at the Cold Terminal QR carousel.\n");

            let mut child = match Command::new("zbarcam")
                .arg("-q")
                .arg("--raw")
                .arg(&device)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[-] Failed to launch zbarcam: {}. Ensure zbarcam is installed.", e);
                    std::process::exit(1);
                }
            };

            let stdout = child.stdout.take().unwrap();
            let reader = BufReader::new(stdout);
            process_stream(reader, &socket, tcp.as_deref(), &spool_dir);

            let _ = child.kill();
        }

        Commands::Listen {
            socket,
            tcp,
            spool_dir,
            timeout_secs,
        } => {
            println!("=======================================================");
            println!(" KATZENPOST HOT STATION: ACOUSTIC GGWAVE RECEIVER ");
            println!("=======================================================");
            println!("Listening on microphone for acoustic air-gap transmission...");
            println!("Hold speaker of Cold Terminal near this microphone.\n");

            match katzen_airgapped::audio::listen_for_message(
                ggwave::Protocol::AudibleFast,
                std::time::Duration::from_secs(timeout_secs),
            ) {
                Ok((msg_type, seq_id, payload)) => {
                    forward_or_spool_packet(
                        seq_id,
                        msg_type,
                        &payload,
                        &socket,
                        tcp.as_deref(),
                        &spool_dir,
                    );
                }
                Err(e) => {
                    eprintln!("[-] Acoustic reception failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::SendReply { data, seq_id, sound } => {
            if sound {
                println!("=======================================================");
                println!(" KATZENPOST HOT STATION: BROADCASTING REPLY OVER SOUND ");
                println!("=======================================================");
                katzen_airgapped::audio::transmit_message(
                    MsgType::ReplyIn,
                    seq_id,
                    data.as_bytes(),
                    katzen_airgapped::audio::DEFAULT_AUDIO_CHUNK_SIZE,
                    ggwave::Protocol::AudibleFast,
                    katzen_airgapped::audio::DEFAULT_AUDIO_VOLUME,
                    150,
                )?;
                println!("Acoustic reply broadcast complete.");
                return Ok(());
            }

            let chunks = fragment_payload(
                MsgType::ReplyIn,
                seq_id,
                data.as_bytes(),
                DEFAULT_CHUNK_SIZE,
            )?;

            println!("=======================================================");
            println!(" KATZENPOST HOT STATION: PRESENTING REPLY TO COLD ");
            println!("=======================================================");
            println!("Presenting encrypted reply QR for Cold Terminal to scan.");

            for (i, chunk) in chunks.iter().enumerate() {
                let qr_str = chunk.to_qr_string();
                let rendered = render_qr_terminal(&qr_str).unwrap();

                println!("\n--- [Frame {}/{}] ---", i + 1, chunks.len());
                println!("{}", rendered);
                println!("Token: {}", qr_str);
            }
        }
    }

    Ok(())
}
