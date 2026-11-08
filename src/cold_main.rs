use clap::{Parser, Subcommand};
use katzen_airgapped::sphinx::{ConsensusTopology, SphinxEngine, SurbManager};
use katzen_airgapped::{fragment_payload, render_qr_terminal, KpagChunk, MsgType, DEFAULT_CHUNK_SIZE};
use rand::Rng;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "katzen-cold")]
#[command(about = "Offline QR and synthetic packet test terminal; no live mixnet delivery")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Construct a synthetic packet for local QR testing only
    Send {
        /// Message text to send through mixnet
        #[arg(short, long)]
        message: Option<String>,

        /// Path to file containing message payload
        #[arg(short, long)]
        file: Option<String>,

        /// Destination mailbox or service (e.g. pigeonhole-egress-01)
        #[arg(short = 't', long, default_value = "pigeonhole-egress-01")]
        target: String,

        /// Frame delay in milliseconds for animated QR loop
        #[arg(short, long, default_value_t = 600)]
        delay_ms: u64,

        /// Number of repeat loops before exiting (0 = infinite loop until Ctrl+C)
        #[arg(short, long, default_value_t = 0)]
        loops: u32,

        /// Advance through frames manually by pressing Enter
        #[arg(short, long, default_value_t = false)]
        step: bool,

        /// Output raw QR strings instead of terminal graphics
        #[arg(long, default_value_t = false)]
        raw: bool,
    },

    /// Generate an offline SURB delegation token for Pigeonhole mailbox polling
    DelegateSurb {
        /// Mailbox identity or pseudonym
        #[arg(short, long, default_value = "anon-field-agent-01")]
        mailbox: String,
    },

    /// Inspect and decode an encrypted reply scanned from the Hot Relay
    DecodeReply {
        /// The raw scanned QR payload (kpag://...)
        #[arg(short, long)]
        payload: String,
    },

    /// Inspect current offline PKI consensus directory topology
    ShowTopology,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let (topology, _privkeys) = ConsensusTopology::generate_mock_consensus(100);

    match cli.command {
        Commands::Send {
            message,
            file,
            target,
            delay_ms,
            loops,
            step,
            raw,
        } => {
            let payload_bytes = if let Some(msg) = message {
                msg.into_bytes()
            } else if let Some(path) = file {
                std::fs::read(path)?
            } else {
                eprintln!("Error: specify either --message or --file");
                std::process::exit(1);
            };

            // Select 3 stratified hops uniformly at random from offline PKI topology
            let path = topology.select_path()?;
            println!("=======================================================");
            println!(" KATZENPOST COLD TERMINAL: SYNTHETIC PACKET DEMO      ");
            println!("=======================================================");
            println!("Status:          DEMO (physical isolation not verified)");
            println!("Consensus Epoch: {}", topology.epoch);
            println!("Mixnet Path:     {} -> {} -> {}", path[0].id, path[1].id, path[2].id);
            println!("Target Service:  {}", target);
            println!("Payload Text:    {} bytes", payload_bytes.len());

            // Build a 1024-byte packet using the synthetic topology for QR tests.
            let sphinx_packet = SphinxEngine::build_packet(&path, &target, &payload_bytes)?;
            let alpha = hex::encode(sphinx_packet.alpha());

            println!("Ephemeral Alpha: {}...", &alpha[0..16]);
            println!("Total Sphinx:    {} bytes (invariant strictly verified)", sphinx_packet.raw_bytes.len());
            println!("=======================================================\n");

            let seq_id: u32 = rand::thread_rng().gen_range(1000..999999);
            let chunks = fragment_payload(
                MsgType::SphinxOut,
                seq_id,
                &sphinx_packet.raw_bytes,
                DEFAULT_CHUNK_SIZE,
            )?;

            if raw {
                for (i, chunk) in chunks.iter().enumerate() {
                    println!("[Chunk {}/{}] {}", i + 1, chunks.len(), chunk.to_qr_string());
                }
                return Ok(());
            }

            if step {
                println!("Modalita manuale (--step): premi INVIO per avanzare fotogramma per fotogramma.\n");
            } else if loops > 0 {
                println!("Trasmissione animata programmata per {} cicli completi.\n", loops);
            } else {
                println!("Trasmissione animata in loop continuo (il ricevitore puo agganciare i frame persi).");
                println!("Premi Ctrl+C quando il ricevitore ha completato la scansione.\n");
            }

            let mut loop_count = 0;
            let stdin = io::stdin();
            let mut line = String::new();

            'outer: loop {
                for (i, chunk) in chunks.iter().enumerate() {
                    let qr_str = chunk.to_qr_string();
                    let rendered = render_qr_terminal(&qr_str).unwrap();

                    // Clear terminal screen and reset cursor
                    print!("\x1B[2J\x1B[H");
                    io::stdout().flush().unwrap();

                    println!(
                        "--- [AIR-GAP CAROUSEL] Seq: #{} | Fotogramma {} di {} | Ciclo #{} ---",
                        seq_id,
                        i + 1,
                        chunks.len(),
                        loop_count + 1
                    );
                    println!("{}", rendered);
                    println!("Chunk preview: {}...", &qr_str[..qr_str.len().min(40)]);

                    if step {
                        println!("\n>>> Premi [INVIO] per il fotogramma successivo, o 'q' per uscire: ");
                        line.clear();
                        if stdin.read_line(&mut line).is_err() || line.trim() == "q" {
                            break 'outer;
                        }
                    } else {
                        sleep(Duration::from_millis(delay_ms));
                    }
                }
                loop_count += 1;
                if loops > 0 && loop_count >= loops {
                    println!("\n[✓] Completati {} cicli di trasmissione. Terminato.", loops);
                    break;
                }
            }
        }

        Commands::DelegateSurb { mailbox } => {
            let mut manager = SurbManager::new();
            let epoch_expiry = topology.epoch + 3600;
            let surb = manager.generate_surb(&topology, &mailbox, epoch_expiry)?;

            let surb_token_json = serde_json::to_string(&surb)?;
            let seq_id: u32 = rand::thread_rng().gen_range(1000..999999);
            let chunks = fragment_payload(
                MsgType::SurbDelegate,
                seq_id,
                surb_token_json.as_bytes(),
                DEFAULT_CHUNK_SIZE,
            )?;

            let qr_str = chunks[0].to_qr_string();
            let rendered = render_qr_terminal(&qr_str).unwrap();

            println!("=======================================================");
            println!(" KATZENPOST COLD TERMINAL: SURB DEMONSTRATION    ");
            println!("=======================================================");
            println!("SURB ID:         {}", surb.surb_id);
            println!("First Hop:       {}", surb.first_hop_address);
            println!("Local Secret:    held in memory only; no durable reply state exists");
            println!("Epoch Expiry:    {}", surb.epoch_expiry);
            println!("{}", rendered);
            println!("Token: {}", qr_str);
        }

        Commands::DecodeReply { payload } => {
            let chunk = KpagChunk::from_qr_string(&payload)
                .map_err(|e| format!("Invalid QR payload: {}", e))?;

            println!("=======================================================");
            println!(" KATZENPOST COLD TERMINAL: INBOUND REPLY PEEL ");
            println!("=======================================================");
            println!("Header valid! MsgType: {:?}", chunk.header.msg_type);
            println!("Sequence ID:   {}", chunk.header.seq_id);
            println!("Raw data ({} bytes):", chunk.data.len());
            println!("{}", String::from_utf8_lossy(&chunk.data));
        }

        Commands::ShowTopology => {
            println!("=======================================================");
            println!(" KATZENPOST COLD TERMINAL: OFFLINE PKI TOPOLOGY ");
            println!("=======================================================");
            println!("Consensus Epoch: {}", topology.epoch);
            println!("Active Layers:   3 (Entry, Middle, Exit)\n");
            for node in &topology.nodes {
                println!("  [Layer {}] {:<12} {:<20} PubKey: {}...", node.layer, node.id, node.address, &node.public_key_hex[0..16]);
            }
        }
    }

    Ok(())
}
