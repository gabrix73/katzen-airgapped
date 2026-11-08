use clap::{Parser, Subcommand};
use katzen_airgapped::identicon::Identicon;
use katzen_airgapped::pigeonhole::{
    default_spool_dir, default_vault_mailbox_path, MailboxMessage,
    MessageDirection, ReplicaRead, ReplicaReadReply, VaultMailbox, write_private_atomic,
};
use katzen_airgapped::sandbox::{apply_network_isolation, SandboxStatus};
use katzen_airgapped::sphinx::{ConsensusTopology, SphinxEngine, SurbManager};
use katzen_airgapped::thinclient::{
    fetch_pigeonhole_box,
    PigeonholeBoxReceipt,
};
use katzen_airgapped::ui::run_gui;
use katzen_airgapped::virtual_keyboard::VirtualKeyboardState;
use katzen_airgapped::{
    fragment_payload, render_qr_terminal, KpagChunk, MsgType, Reassembler, DEFAULT_CHUNK_SIZE,
};
use rand::Rng;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "katzen")]
#[command(author = "Gabriel Virebent <gabrix73>")]
#[command(version = "0.1.0")]
#[command(about = "Experimental Katzenpost offline QR workflow and local vault")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a synthetic local packet and save it for QR tests
    Standalone {
        /// Message text to send
        #[arg(short, long)]
        message: Option<String>,

        /// Destination mailbox or service
        #[arg(short = 't', long, default_value = "courier")]
        target: String,

        /// Optional removable media spool directory (defaults to <usb_root>/spool)
        #[arg(long)]
        spool_dir: Option<PathBuf>,

        /// Require kernel-enforced network isolation or fail
        #[arg(long, default_value_t = false)]
        sandbox: bool,

    },

    /// Retrieve and decrypt messages from the live Katzenpost Pigeonhole mixnet replica or USB spool
    #[command(alias = "read", alias = "fetch")]
    Receive {
        /// Optional BACAP Read Capability (136-byte hex). Defaults to latest receipt in spool/sent/pigeonhole_box_latest.json
        #[arg(long)]
        read_cap: Option<String>,

        /// Optional BACAP Message Box Index (104-byte hex). Defaults to latest receipt in spool/sent/pigeonhole_box_latest.json
        #[arg(long)]
        index: Option<String>,

        /// Path to a specific receipt JSON file
        #[arg(short, long)]
        receipt: Option<PathBuf>,

        /// Path or abstract name of kpclientd Unix domain socket
        #[arg(short, long, default_value = "@katzenpost")]
        socket: PathBuf,

        /// Removable media spool directory (defaults to <usb_root>/spool)
        #[arg(long)]
        spool_dir: Option<PathBuf>,
    },

    /// Offline Vault mode: compose, encrypt Sphinx packets & decrypt inbound replies
    #[command(alias = "cold")]
    Vault {
        #[command(subcommand)]
        action: VaultCommands,
    },

    /// QR and file spool demonstration; synthetic packets are not transmitted
    #[command(alias = "hot")]
    Spooler {
        #[command(subcommand)]
        action: SpoolerCommands,
    },

    /// Launch Sovereign Vault graphical user interface (Slint UI with grouped virtual keyboard)
    Gui,

    /// Check system environment, kernel sandbox capabilities and removable media
    Status,
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Sovereign Pigeonhole Mailbox: manage encrypted offline inbox, outbox, and BACAP drafts
    Mailbox {
        #[command(subcommand)]
        action: MailboxCommands,
    },

    /// Construct a 3-hop Sphinx packet offline (export to USB spool or display QR)
    Send {
        /// Message text to send through mixnet
        #[arg(short, long)]
        message: Option<String>,

        /// Path to file containing message payload
        #[arg(short, long)]
        file: Option<String>,

        /// Destination mailbox or service
        #[arg(short = 't', long, default_value = "pigeonhole-egress-01")]
        target: String,

        /// Export directly to a removable media spool folder (e.g. /media/usb/spool)
        #[arg(long)]
        spool_dir: Option<PathBuf>,

        /// Frame delay in milliseconds for animated QR loop
        #[arg(short, long, default_value_t = 600)]
        delay_ms: u64,

        /// Number of repeat loops before exiting (0 = infinite loop)
        #[arg(short, long, default_value_t = 0)]
        loops: u32,

        /// Advance through frames manually by pressing Enter
        #[arg(short, long, default_value_t = false)]
        step: bool,

        /// Output raw QR strings instead of terminal graphics
        #[arg(long, default_value_t = false)]
        raw: bool,
    },

    /// Read and decrypt inbound reply packets from a removable media spool folder
    Receive {
        /// Removable media spool folder containing inbound packets (e.g. /media/usb/spool)
        #[arg(long, default_value = "/tmp/katzen-spool")]
        spool_dir: PathBuf,
    },

    /// Generate an offline SURB delegation token for Pigeonhole mailbox polling
    DelegateSurb {
        /// Mailbox identity or pseudonym
        #[arg(short, long, default_value = "anon-field-agent-01")]
        mailbox: String,
    },

    /// Decode an encrypted reply scanned from the Hot Relay
    DecodeReply {
        /// The raw scanned QR payload (kpag://...)
        #[arg(short, long)]
        payload: String,
    },

    /// Manage permanent cryptographic profiles and recipient contact identicons
    Profile {
        #[command(subcommand)]
        action: ProfileCommands,
    },

    /// Inspect current offline PKI consensus directory topology
    ShowTopology,
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// Show local operator profile and deterministic ANSI identicon
    Show,
    /// Add or update a recipient contact profile and generate their unique identicon
    Add {
        /// Human-readable username or alias for the recipient
        #[arg(short, long)]
        username: String,
        /// Recipient permanent Box ID (32-byte hex public key)
        #[arg(short, long)]
        recipient: String,
    },
    /// List all saved contact profiles and their visual identicons
    List,
    /// Export an SVG identicon for a given username and public key
    ExportSvg {
        /// Username
        #[arg(short, long)]
        username: String,
        /// Recipient or public key hex
        #[arg(short, long)]
        recipient: String,
        /// Output file path (e.g. identicon.svg)
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum MailboxCommands {
    /// List all messages stored in local offline Vault mailbox
    List,
    /// Display sovereign Box ID address
    Identity,
    /// Deposit a new encrypted message to a recipient's Box ID
    Deposit {
        /// Recipient 32-byte hex Box ID
        #[arg(short, long)]
        recipient: Option<String>,
        /// Plaintext message payload
        #[arg(short, long)]
        message: Option<String>,
        /// Use grouped virtual keyboard (anti-keylogger, elevates Secrecy Score to 5 stars ⭐⭐⭐⭐⭐)
        #[arg(long, default_value_t = false)]
        virtual_keyboard: bool,
    },
    /// Generate a BACAP ReplicaRead query with SURB for anonymous mailbox polling
    Poll,
    /// Ingest and decrypt an inbound ReplicaReadReply envelope into the mailbox
    Ingest {
        /// Path to reply envelope file
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// Hex-encoded reply envelope
        #[arg(short = 'x', long)]
        hex: Option<String>,
    },
}

#[derive(Subcommand)]
enum SpoolerCommands {
    /// Watch a removable media spool directory and dispatch queued Sphinx packets
    Run {
        /// Removable media spool directory to monitor (e.g. /media/usb/spool)
        #[arg(long, default_value = "/tmp/katzen-spool")]
        spool_dir: PathBuf,

        /// Path to kpclientd Unix domain socket
        #[arg(short, long, default_value = "/run/katzenpost/client.sock")]
        socket: PathBuf,

        /// Optional TCP endpoint for kpclientd
        #[arg(short, long)]
        tcp: Option<String>,
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

        /// Directory to spool outbound Sphinx packets
        #[arg(long, default_value = "/tmp/katzen-spool/outbox")]
        spool_dir: PathBuf,
    },

    /// Ingest optical air-gap stream from stdin (one QR string per line)
    Ingest {
        /// Optional path to kpclientd Unix domain socket
        #[arg(short, long, default_value = "/run/katzenpost/client.sock")]
        socket: PathBuf,

        /// Optional TCP endpoint for kpclientd
        #[arg(short, long)]
        tcp: Option<String>,

        /// Directory to spool outbound Sphinx packets
        #[arg(long, default_value = "/tmp/katzen-spool/outbox")]
        spool_dir: PathBuf,
    },

    /// Encapsulate a received mixnet response into a QR code for the Vault
    SendReply {
        /// Plaintext or raw encrypted reply bytes from mixnet
        #[arg(short, long)]
        data: String,

        /// Sequence ID to correlate
        #[arg(short, long, default_value_t = 1001)]
        seq_id: u32,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("    /\\_/\\   ");
            println!("   ( o.o )   KATZENPOST OFFLINE WORKFLOW PROTOTYPE");
            println!("    > ^ <    Synthetic packets are not sent to the live mixnet");
            println!("=======================================================");
            println!(" ENVIRONMENT & KERNEL AIR-GAP STATUS                  ");
            println!("=======================================================");
            let sandbox_res = apply_network_isolation();
            match sandbox_res {
                Ok(SandboxStatus::KernelEnforced(desc)) => {
                    println!("[✓] Kernel Sandbox: ENFORCED ({})", desc);
                }
                Ok(SandboxStatus::Restricted(desc)) => {
                    println!("[i] Kernel Sandbox: RESTRICTED ({})", desc);
                }
                Err(e) => {
                    println!("[!] Kernel Sandbox error: {}", e);
                }
            }
            println!("[i] Physical air gap requires independent verification of the device and radios.");
            println!("=======================================================");

            let mbox_path = default_vault_mailbox_path();
            println!(" Vault path: {}", mbox_path.display());
            println!(" Vault file exists: {}", mbox_path.exists());
            println!("[i] Status does not unlock or create a vault.");
            println!("=======================================================");

            println!(" SECURITY LIMITATIONS                                  ");
            println!("=======================================================");
            println!("[i] No numerical secrecy score is a security guarantee.");
            println!("[i] A virtual keyboard does not establish physical air-gap isolation.");
            println!("=======================================================");
        }

        Commands::Gui => {
            println!("[*] Launching Katzen Vault sovereign interface...");
            run_gui().map_err(|e| format!("Interface error: {}", e))?;
        }

        Commands::Standalone {
            message,
            target,
            spool_dir,
            sandbox,
        } => {
            println!("=======================================================");
            println!(" KATZENPOST LOCAL PACKET DEMONSTRATION                  ");
            println!("=======================================================");

            let payload_text = message.unwrap_or_else(|| {
                print!("Enter message payload to encrypt: ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                input.trim().to_string()
            });

            if sandbox {
                println!("[*] Enforcing kernel-level network isolation...");
                match apply_network_isolation() {
                    Ok(SandboxStatus::KernelEnforced(desc)) => {
                        println!("[✓] Network isolation active: {}", desc);
                    }
                    Ok(SandboxStatus::Restricted(desc)) => {
                        return Err(format!("Network isolation unavailable: {desc}").into());
                    }
                    Err(e) => {
                        return Err(format!("Network isolation failed: {e}").into());
                    }
                }
            }

            let (topology, _privkeys) = ConsensusTopology::generate_mock_consensus(100);
            let path = topology.select_path()?;
            let sphinx_packet = SphinxEngine::build_packet(&path, &target, payload_text.as_bytes())?;
            let packet_bytes = sphinx_packet.raw_bytes;

            println!("[i] Synthetic 1024-byte packet constructed for offline testing only");

            // Record in portable VaultMailbox (<usb_root>/vault_data/vault_mailbox.json)
            let mbox_path = default_vault_mailbox_path();
            let mut mbox = VaultMailbox::new_or_load(&mbox_path)?;
            let recip_hex = mbox.identity.box_id_hex.clone();
            mbox.deposit_draft(&recip_hex, &payload_text, 0, "Standalone CLI")?;
            mbox.save(&mbox_path)?;
            println!("[✓] Message recorded in encrypted vault: {}", mbox_path.display());

            // Persist a private demo artifact for local QR tests.
            let active_spool = spool_dir.unwrap_or_else(default_spool_dir);
            let outbox = active_spool.join("outbox");

            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let rand_id: u16 = rand::thread_rng().gen();
            let file_name = format!("packet_{}_{:04x}.demo", ts, rand_id);
            let file_path = outbox.join(&file_name);
            write_private_atomic(&file_path, &packet_bytes)?;
            println!(
                "[i] Demo packet saved to USB spool: {}",
                file_path.display()
            );

            if sandbox {
                println!(
                    "[i] Sandbox active (offline mode). Packet stays queued at: {}",
                    file_path.display()
                );
                return Ok(());
            }

            println!("[i] Synthetic consensus packet retained locally. Live dispatch is disabled.");

        }

        Commands::Receive {
            read_cap,
            index,
            receipt,
            socket,
            spool_dir,
        } => {
            let active_spool = spool_dir.unwrap_or_else(default_spool_dir);
            execute_receive(
                read_cap.as_deref(),
                index.as_deref(),
                receipt.as_deref(),
                &socket,
                &active_spool,
            )?;
        }

        Commands::Vault { action } => match action {
            VaultCommands::Mailbox { action } => match action {
                MailboxCommands::List => {
                    let mbox_path = default_vault_mailbox_path();
                    let mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    println!("================================================================================");
                    println!(" KATZENPOST VAULT MAILBOX: {} COMMITTED MESSAGES", mbox.messages.len());
                    println!(" Box ID Identity: {}", mbox.identity.box_id_hex);
                    println!("================================================================================");
                    if mbox.messages.is_empty() {
                        println!("[i] No messages stored in local vault mailbox.");
                        println!("    Use `katzen vault mailbox deposit` or the graphical GUI to compose one.");
                    } else {
                        for (idx, msg) in mbox.messages.iter().enumerate() {
                            let dir_tag = match msg.direction {
                                MessageDirection::Inbound => "INBOUND  [↓]",
                                MessageDirection::Outbound => "OUTBOUND [↑]",
                            };
                            println!(
                                "#{} | {} | {} | {} stars ({})\n    Sender/Dest: {} -> {}\n    State: {}\n    Preview: {}\n",
                                idx + 1,
                                dir_tag,
                                msg.id,
                                msg.secrecy_stars,
                                msg.input_method,
                                &msg.sender[0..12.min(msg.sender.len())],
                                &msg.recipient[0..12.min(msg.recipient.len())],
                                msg.quantum_state,
                                if msg.plaintext.len() > 60 { format!("{}...", &msg.plaintext[0..60]) } else { msg.plaintext.clone() }
                            );
                        }
                    }
                }

                MailboxCommands::Identity => {
                    let mbox_path = default_vault_mailbox_path();
                    let mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let identicon = mbox.identity.identicon();
                    println!("=======================================================");
                    println!(" KATZENPOST PIGEONHOLE SOVEREIGN IDENTITY & AVATAR     ");
                    println!("=======================================================");
                    println!("Username:                    {}", mbox.identity.username);
                    println!("Box ID (Public Address):     {}", mbox.identity.box_id_hex);
                    println!("Created At (Unix Epoch):     {}", mbox.identity.created_at);
                    println!("Local Archive Path:          {}", mbox_path.display());
                    println!("\nProfile Identicon (Deterministic cryptographic avatar):");
                    println!("{}", identicon.render_terminal());
                    println!("=======================================================");
                }

                MailboxCommands::Deposit { recipient, message, virtual_keyboard } => {
                    let mbox_path = default_vault_mailbox_path();
                    let mut mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let mut kbd = VirtualKeyboardState::new();

                    let raw_target = recipient.unwrap_or_else(|| {
                        print!("Enter recipient Box ID or username: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        input.trim().to_string()
                    });

                    // Resolve contact or raw hex
                    let (recip_hex, contact_opt) = {
                        let trimmed = raw_target.trim();
                        if let Some(c) = mbox.find_contact(trimmed).or_else(|| mbox.contacts.iter().find(|c| c.username.eq_ignore_ascii_case(trimmed))) {
                            (c.box_id_hex.clone(), Some(c.clone()))
                        } else {
                            (trimmed.to_string(), None)
                        }
                    };

                    if let Some(ref c) = contact_opt {
                        println!("\n[✓] Contact verified in addressbook: {}", c.username);
                        println!("{}", c.identicon().render_terminal());
                    } else {
                        let temp_identicon = Identicon::new("recipient", &recip_hex);
                        println!("\n[i] Identicon generated for recipient:");
                        println!("{}", temp_identicon.render_terminal());
                    }

                    let use_virtual = if virtual_keyboard {
                        true
                    } else {
                        println!("The partitioned virtual keyboard boosts your secrecy score from 3 to 5 stars ⭐⭐⭐⭐⭐.");
                        print!("Use virtual keyboard for message composition? [y/N]: ");
                        io::stdout().flush().unwrap();
                        let mut ans = String::new();
                        io::stdin().read_line(&mut ans).unwrap();
                        ans.trim().eq_ignore_ascii_case("y") || ans.trim().eq_ignore_ascii_case("s")
                    };

                    let (score, method) = if use_virtual {
                        kbd.is_enabled = true;
                        kbd.used_for_composition = true;
                        let boosted = kbd.compute_secrecy_score();
                        println!("\n[OK] Anti-keylogger virtual keyboard activated!");
                        println!("Partitioned layout for intuitive input (shuffled within group boundaries only):");
                        println!(" [NUMBERS] : {:?}", kbd.numbers);
                        println!(" [LETTERS] : {:?}", kbd.letters);
                        println!(" [SYMBOLS] : {:?}", kbd.symbols);
                        (boosted.stars, "Virtual Keyboard (Partitioned Anti-Keylogger)")
                    } else {
                        let std_score = kbd.compute_secrecy_score();
                        (std_score.stars, "Physical Keyboard")
                    };

                    let body_text = message.unwrap_or_else(|| {
                        print!("\nEnter message payload: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).unwrap();
                        input.trim().to_string()
                    });

                    println!("\n[*] Pigeonhole asymmetric encryption and BLAKE3 envelope signing...");
                    let write_msg = mbox.deposit_draft(&recip_hex, &body_text, score, method)?;
                    mbox.save(&mbox_path)?;

                    println!("[✓] Message encrypted and committed to local vault mailbox!");
                    println!("    Ciphertext payload length: {} bytes", write_msg.payload.len());
                    println!("    Secrecy Score: {} stars ({})", score, method);
                    println!("    Quantum State: Superposition (Schrödinger vault sealed)");
                    println!("    Ready for USB spool export or optical QR projection.");
                }

                MailboxCommands::Poll => {
                    let mbox_path = default_vault_mailbox_path();
                    let mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let box_id_bytes = mbox.identity.box_id()?;
                    let read_query = ReplicaRead::new(box_id_bytes);
                    let wire = read_query.encode();

                    println!("=======================================================");
                    println!(" KATZENPOST PIGEONHOLE: ASYNCHRONOUS QUERY            ");
                    println!("=======================================================");
                    println!("Target Box ID: {}", mbox.identity.box_id_hex);
                    println!("ReplicaRead query size: {} bytes", wire.len());
                    println!("Instructions: The blind spooler forwards this query to the Pigeonhole replica");
                    println!("              using a delegated SURB to receive replies with zero sender metadata.");
                    println!("=======================================================");
                }

                MailboxCommands::Ingest { file, hex } => {
                    let mbox_path = default_vault_mailbox_path();
                    let mut mbox = VaultMailbox::new_or_load(&mbox_path)?;

                    let raw_bytes = if let Some(path) = file {
                        fs::read(path)?
                    } else if let Some(hex_str) = hex {
                        hex::decode(hex_str)?
                    } else {
                        eprintln!("Specify either --file or --hex for inbound reply ingestion.");
                        std::process::exit(1);
                    };

                    let reply = ReplicaReadReply::decode(&raw_bytes)?;
                    let plaintext = mbox.ingest_reply(&reply)?;
                    mbox.save(&mbox_path)?;

                    println!("=======================================================");
                    println!(" KATZENPOST VAULT: QUANTUM DECOHERENCE & OBSERVATION   ");
                    println!("=======================================================");
                    println!("[✓] Pigeonhole reply envelope decrypted and verified successfully!");
                    println!("[*] State: Quantum decoherence (Plaintext observed)");
                    println!("[*] Decrypted Plaintext:");
                    println!("{}", plaintext);
                    println!("=======================================================");
                }
            },

            VaultCommands::Profile { action } => match action {
                ProfileCommands::Show => {
                    let mbox_path = default_vault_mailbox_path();
                    let mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let identicon = mbox.identity.identicon();
                    println!("=======================================================");
                    println!(" LOCAL SOVEREIGN PROFILE                              ");
                    println!("=======================================================");
                    println!("Username: {}", mbox.identity.username);
                    println!("Box ID:   {}", mbox.identity.box_id_hex);
                    println!("\nProfile Identicon (Deterministic cryptographic avatar):");
                    println!("{}", identicon.render_terminal());
                    println!("=======================================================");
                }

                ProfileCommands::Add { username, recipient } => {
                    let mbox_path = default_vault_mailbox_path();
                    let mut mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let profile = mbox.add_contact(&username, &recipient)?;
                    mbox.save(&mbox_path)?;
                    let identicon = profile.identicon();

                    println!("=======================================================");
                    println!(" CONTACT PROFILE CREATED / UPDATED                    ");
                    println!("=======================================================");
                    println!("Username:  {}", profile.username);
                    println!("Recipient: {}", profile.box_id_hex);
                    println!("\nRecipient Profile Identicon:");
                    println!("{}", identicon.render_terminal());
                    println!("\n[✓] Committed to Vault contacts database!");
                    println!("=======================================================");
                }

                ProfileCommands::List => {
                    let mbox_path = default_vault_mailbox_path();
                    let mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    println!("================================================================================");
                    println!(" SOVEREIGN CONTACTS DATABASE: {} PROFILES SAVED", mbox.contacts.len());
                    println!("================================================================================");
                    if mbox.contacts.is_empty() {
                        println!("[i] No contacts in addressbook.");
                        println!("    Add one with: `katzen vault profile add --username <name> --recipient <box-id>`");
                    } else {
                        for (i, c) in mbox.contacts.iter().enumerate() {
                            let identicon = c.identicon();
                            println!("#{} Contact: {} (Box ID: {})", i + 1, c.username, c.box_id_hex);
                            println!("{}", identicon.render_terminal());
                        }
                    }
                    println!("================================================================================");
                }

                ProfileCommands::ExportSvg { username, recipient, output } => {
                    let identicon = Identicon::new(&username, &recipient);
                    let svg = identicon.render_svg(256);
                    fs::write(&output, svg)?;
                    println!("[✓] Identicon SVG exported successfully to {:?}", output);
                }
            },
            VaultCommands::Send {
                message,
                file,
                target,
                spool_dir,
                delay_ms,
                loops,
                step,
                raw,
            } => {
                let payload_bytes = if let Some(msg) = message {
                    msg.into_bytes()
                } else if let Some(path) = file {
                    fs::read(path)?
                } else {
                    eprintln!("Specify either --message or --file");
                    std::process::exit(1);
                };

                let (topology, _privkeys) = ConsensusTopology::generate_mock_consensus(100);
                let path = topology.select_path()?;
                let sphinx_packet = SphinxEngine::build_packet(&path, &target, &payload_bytes)?;
                let packet = sphinx_packet.raw_bytes;

                println!("=======================================================");
                println!(" KATZENPOST VAULT: SYNTHETIC PACKET DEMO               ");
                println!("=======================================================");
                println!("State:           DEMO (physical isolation not verified)");
                println!("Mix Route:       {} -> {} -> {}", path[0].id, path[1].id, path[2].id);
                println!("Target Service:  {}", target);
                println!("Size:            {} bytes (synthetic packet)", packet.len());

                if let Some(ref dir) = spool_dir {
                    let outbox = dir.join("outbox");
                    let file_path = outbox.join(format!("packet_{}.demo", rand::thread_rng().gen::<u32>()));
                    write_private_atomic(&file_path, &packet)?;
                    println!("\n[✓] Packet written to removable spool: {:?}", file_path);
                    println!(
                        "[i] OPSEC Tip: To prevent host-to-media writes, use SD cards with physical write-lock \
                         sliders or bridge via animated optical QR diodes."
                    );
                    return Ok(());
                }

                // Default: Display terminal QR carousel
                let seq_id = rand::thread_rng().gen::<u32>();
                let chunks = fragment_payload(MsgType::SphinxOut, seq_id, &packet, DEFAULT_CHUNK_SIZE)?;

                println!("\n[>] Optical transmission: carousel of {} QR chunks...", chunks.len());
                run_qr_carousel(&chunks, delay_ms, loops, step, raw)?;
            }

            VaultCommands::Receive { spool_dir } => {
                let active_spool = if spool_dir == Path::new("/tmp/katzen-spool") {
                    default_spool_dir()
                } else {
                    spool_dir
                };
                execute_receive(
                    None,
                    None,
                    None,
                    Path::new("@katzenpost"),
                    &active_spool,
                )?;
            }

            VaultCommands::DelegateSurb { mailbox } => {
                let (topology, _privkeys) = ConsensusTopology::generate_mock_consensus(100);
                let mut manager = SurbManager::new();
                let epoch_expiry = topology.epoch + 3600;
                let surb = manager.generate_surb(&topology, &mailbox, epoch_expiry)?;
                println!("Delegated SURB token generated successfully: {}", hex::encode(surb.surb_id));
            }

            VaultCommands::DecodeReply { payload } => {
                let chunk = KpagChunk::from_qr_string(&payload)?;
                println!("[✓] QR chunk decoded successfully: Sequence {}", chunk.header.seq_id);
            }

            VaultCommands::ShowTopology => {
                let (topology, _) = ConsensusTopology::generate_mock_consensus(100);
                println!("Consensus Epoch: {}", topology.epoch);
                println!("Active nodes in consensus: {}", topology.nodes.len());
            }
        },

        Commands::Spooler { action } => match action {
            SpoolerCommands::Run { .. } => {
                return Err("Live spooler disabled: synthetic packets are incompatible with kpclientd".into());
            }

            SpoolerCommands::Scan {
                device,
                socket,
                tcp,
                spool_dir: _spool_dir,
            } => {
                println!("[*] Starting optical scanner via zbarcam on {}...", device);
                run_camera_scan(&device, &socket, tcp.as_deref(), &_spool_dir)?;
            }

            SpoolerCommands::Ingest {
                socket,
                tcp,
                spool_dir: _spool_dir,
            } => {
                println!("[*] Ingesting chunks from stdin...");
                run_stdin_ingest(&socket, tcp.as_deref(), &_spool_dir)?;
            }

            SpoolerCommands::SendReply { data, seq_id } => {
                let chunks = fragment_payload(MsgType::ReplyIn, seq_id, data.as_bytes(), DEFAULT_CHUNK_SIZE)?;
                println!("[*] Projecting encrypted reply via {} QR chunks...", chunks.len());
                run_qr_carousel(&chunks, 600, 0, false, false)?;
            }
        },
    }

    Ok(())
}

fn execute_receive(
    read_cap_opt: Option<&str>,
    index_opt: Option<&str>,
    receipt_path_opt: Option<&Path>,
    socket_path: &Path,
    spool_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=======================================================");
    println!(" KATZENPOST CLIENT: PIGEONHOLE MIXNET RECEIVER         ");
    println!("=======================================================");

    let inbox = spool_dir.join("inbox");
    let sent_dir = spool_dir.join("sent");

    let default_receipt_path = sent_dir.join("pigeonhole_box_latest.json");
    let active_receipt_path = receipt_path_opt.unwrap_or(&default_receipt_path);

    let resolved: Option<(String, String, Option<PigeonholeBoxReceipt>)> =
        if let (Some(rc), Some(idx)) = (read_cap_opt, index_opt) {
            Some((rc.trim().to_string(), idx.trim().to_string(), None))
        } else if active_receipt_path.exists() {
            let raw = fs::read_to_string(active_receipt_path)?;
            let parsed: PigeonholeBoxReceipt = serde_json::from_str(&raw)?;
            Some((
                parsed.read_cap_hex.clone(),
                parsed.message_box_index_hex.clone(),
                Some(parsed),
            ))
        } else {
            None
        };

    if let Some((rc_hex, idx_hex, receipt_meta)) = resolved {
        if let Some(ref meta) = receipt_meta {
            println!("[*] Loaded BACAP Capability Receipt: {}", active_receipt_path.display());
            println!(
                "    • Courier Replica : {}...",
                &meta.courier_node_hex[..16.min(meta.courier_node_hex.len())]
            );
            println!(
                "    • Envelope Hash   : {}...",
                &meta.envelope_hash_hex[..32.min(meta.envelope_hash_hex.len())]
            );
            println!(
                "    • Box Index       : {}...",
                &meta.message_box_index_hex[..32.min(meta.message_box_index_hex.len())]
            );
        }

        let rc_bytes = hex::decode(&rc_hex)?;
        let idx_bytes = hex::decode(&idx_hex)?;

        match fetch_pigeonhole_box(&rc_bytes, &idx_bytes, socket_path, None) {
            Ok((plaintext_bytes, live_epoch)) => {
                let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // Persist only in the encrypted vault; never write an inbound plaintext file.
                let mbox_path = default_vault_mailbox_path();
                {
                    let mut mbox = VaultMailbox::new_or_load(&mbox_path)?;
                    let mut updated_existing = false;
                    for m in mbox.messages.iter_mut() {
                        if m.plaintext == plaintext {
                            m.quantum_state =
                                "Decoherence: Retrieved & Decrypted from Live Mixnet Replica"
                                    .to_string();
                            m.epoch = live_epoch;
                            updated_existing = true;
                        }
                    }
                    if !updated_existing {
                        let mut id_seed = [0u8; 8];
                        rand::thread_rng().fill(&mut id_seed);
                        mbox.messages.push(MailboxMessage {
                            id: hex::encode(id_seed),
                            sender: idx_hex[..32.min(idx_hex.len())].to_string(),
                            recipient: mbox.identity.box_id_hex.clone(),
                            epoch: live_epoch,
                            plaintext: plaintext.clone(),
                            timestamp: ts,
                            direction: MessageDirection::Inbound,
                            quantum_state:
                                "Decoherence: Retrieved & Decrypted from Live Mixnet Replica"
                                    .to_string(),
                            secrecy_stars: 5,
                            input_method: "Pigeonhole BACAP Mixnet SURB".to_string(),
                        });
                    }
                    mbox.save(&mbox_path)?;
                }

                println!("=======================================================");
                println!("[✓] MESSAGE RETRIEVED & DECRYPTED FROM KATZENPOST MIXNET");
                println!("=======================================================");
                println!("    • Consensus Epoch : {}", live_epoch);
                println!("    • Quantum State   : Decoherence (Plaintext Observed)");
                println!("    • Saved in encrypted vault: {}", mbox_path.display());
                println!("-------------------------------------------------------");
                println!("    DECRYPTED PAYLOAD : {}", plaintext);
                println!("=======================================================");
                return Ok(());
            }
            Err(e) => {
                println!("[!] Live mixnet retrieval error: {}", e);
            }
        }
    } else {
        println!(
            "[i] No BACAP receipt found at {}. Checking local inbox folder...",
            active_receipt_path.display()
        );
    }

    if inbox.exists() {
        println!("[!] Legacy plaintext inbox exists at {}; review and migrate it separately.", inbox.display());
    }
    Ok(())
}


fn forward_packet_to_gateway(payload: &[u8], socket_path: &Path, tcp_addr: Option<&str>) {
    println!("\n=======================================================");
    println!(" [SUCCESS] SPHINX PACKET REASSEMBLED OVER AIR-GAP!");
    println!("=======================================================");
    println!("Assembled Size:  {} bytes", payload.len());

    if payload.len() != 1024 {
        eprintln!("[-] Unexpected packet size {}; refusing dispatch", payload.len());
        return;
    }

    println!("[*] Attempting live mixnet dispatch via kpclientd...");
    match katzen_airgapped::thinclient::dispatch_via_kpclientd(payload, "courier", socket_path, tcp_addr) {
        Ok(receipt) => {
            println!("[✓] Live mixnet dispatch confirmed by kpclientd!");
            println!("    • Epoch           : {}", receipt.epoch);
            println!("    • Destination     : {}", receipt.destination_service);
            println!("    • Forward Route   : {}", receipt.forward_route.join(" -> "));
            println!("    • Return Route    : {}", receipt.return_route.join(" -> "));
            println!("    • Reply ETA       : {} ms", receipt.reply_eta_ms);

            let sent_dir = default_spool_dir().join("sent");
            if let Ok(_) = std::fs::create_dir_all(&sent_dir) {
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let receipt_file = sent_dir.join(format!("receipt_{}.json", ts));
                if let Ok(json_bytes) = serde_json::to_vec_pretty(&receipt) {
                    let _ = write_private_atomic(&receipt_file, &json_bytes);
                    println!("[i] Delivery receipt recorded: {}", receipt_file.display());
                }
            }
        }
        Err(err) => {
            println!("[-] kpclientd dispatch failed or daemon offline: {}", err);
            println!("[*] Spooling packet to outbox for deferred transmission...");
            let outbox = default_spool_dir().join("outbox");
            if let Ok(_) = std::fs::create_dir_all(&outbox) {
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let spool_file = outbox.join(format!("sphinx_outbound_{}.bin", ts));
                if let Ok(_) = write_private_atomic(&spool_file, payload) {
                    println!("[✓] Packet durably spooled to: {}", spool_file.display());
                }
            }
        }
    }
}

fn run_qr_carousel(
    chunks: &[KpagChunk],
    delay_ms: u64,
    loops: u32,
    step: bool,
    raw: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_loop = 0;
    loop {
        for (i, chunk) in chunks.iter().enumerate() {
            let qr_string = chunk.to_qr_string();
            if raw {
                println!("{}", qr_string);
            } else {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen
                println!(
                    "--- [KPAG FRAME {}/{}] (Seq ID: {}) ---",
                    i + 1,
                    chunks.len(),
                    chunk.header.seq_id
                );
                let rendered = render_qr_terminal(&qr_string).unwrap_or_else(|e| format!("QR Render Error: {}", e));
                println!("{}", rendered);
                println!("--- [Align camera of hot connected device with this QR] ---");
            }

            if step {
                print!("Press Enter for next frame...");
                io::stdout().flush()?;
                let mut buf = String::new();
                io::stdin().read_line(&mut buf)?;
            } else {
                sleep(Duration::from_millis(delay_ms));
            }
        }
        current_loop += 1;
        if loops > 0 && current_loop >= loops {
            break;
        }
    }
    Ok(())
}

fn run_camera_scan(
    device: &str,
    socket: &Path,
    tcp: Option<&str>,
    _spool_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("zbarcam")
        .arg("--nodisplay")
        .arg("--raw")
        .arg(device)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().ok_or("Failed to open stdout of zbarcam")?;
    let reader = BufReader::new(stdout);
    let mut reassembler = Reassembler::new();

    for line in reader.lines() {
        if let Ok(l) = line {
            let trimmed = l.trim();
            if trimmed.starts_with("kpag://") || trimmed.starts_with("KPAG://") {
                if let Ok(chunk) = KpagChunk::from_qr_string(trimmed) {
                    if let Ok(Some((_mtype, _seq, full_payload))) = reassembler.add_chunk(chunk) {
                        forward_packet_to_gateway(&full_payload, socket, tcp);
                    }
                }
            }
        }
    }
    Ok(())
}

fn run_stdin_ingest(
    socket: &Path,
    tcp: Option<&str>,
    _spool_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut reassembler = Reassembler::new();

    for line in reader.lines() {
        let l = line?;
        let trimmed = l.trim();
        if trimmed.starts_with("kpag://") || trimmed.starts_with("KPAG://") {
            if let Ok(chunk) = KpagChunk::from_qr_string(trimmed) {
                if let Ok(Some((_mtype, _seq, full_payload))) = reassembler.add_chunk(chunk) {
                    forward_packet_to_gateway(&full_payload, socket, tcp);
                }
            }
        }
    }
    Ok(())
}
