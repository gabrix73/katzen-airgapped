# katzen-airgapped

Experimental Rust client for studying a split offline/online Katzenpost workflow. The cold and hot commands support local QR framing and packet reassembly tests. They do **not** yet provide a working end-to-end mixnet delivery path.

The current repository review and release blockers are in [docs/REVIEW_2026-10-30.md](docs/REVIEW_2026-10-30.md). This project does not implement a P2P network.

## Current security boundary

- The local mailbox is encrypted with XChaCha20-Poly1305. A passphrase entered in a terminal derives the key with Argon2id (64 MiB, three passes). The passphrase is requested once per process. Keep a separate, protected backup and retain the passphrase: there is no recovery mechanism.
- The first successful unlock of a legacy JSON mailbox migrates it to the encrypted `KAV1` format using an atomic replacement. A failed unlock leaves the legacy file intact. Old backups, filesystem snapshots, swap, and existing `spool/inbox/*.inbound` files may still contain plaintext; this program does not remove them.
- The local demonstration box envelope uses ephemeral X25519 and XChaCha20-Poly1305 (`KPB2`), authenticating the envelope version, ephemeral public key, recipient ID, nonce, and ciphertext. Old unauthenticated envelopes are rejected. The demonstration BLAKE3 tag is **not** a verifiable asymmetric signature and is not a BACAP wire signature.
- `--sandbox` fails if the kernel cannot enforce network isolation. A failed connectivity probe is not evidence of an air gap. Physical isolation must be established by the operator and checked independently.
- `katzen-hot` implements live mixnet dispatch via `kpclientd` thin-client CBOR wire contract, verifying epoch, service endpoint, and forward/return routes with delivery receipt logging (`receipt_<seq>.json`). If the local daemon is offline or unreachable, outbound packets are durably spooled to `outbox/` for deferred dispatch.
- Authentic Katzenpost PKI consensus documents are decoded via `ConsensusTopology::from_pki_document`, extracting verified mix nodes, layers, addresses, and epoch Sphinx keys.
- The Slint desktop GUI provides a native in-window passphrase unlock and vault initialization flow with an on-screen anti-keylogger virtual keyboard and inline error reporting, removing any dependency on terminal `rpassword` prompts.

## Local checks

```bash
cargo test --locked
katzen status
katzen-cold send --message test --raw
katzen-cold send --message test --sound
katzen-hot listen
```

The QR and acoustic paths can be tested on one machine with synthetic data. A two-device test should use a dedicated offline laptop for the cold side, with radios and Ethernet disabled, and an online machine for the hot side. Treat every QR, audio burst, or removable-media import as untrusted input. Android airplane mode is useful for interface experiments but is not the reference air-gap configuration because Wi-Fi and Bluetooth can remain enabled.

## Verification & Live Delivery Architecture

1. **PKI Consensus Validation**: The cold vault and client topology decoder parses Katzenpost CBOR consensus documents, extracting epoch, verified layer assignments (1..=3), and Sphinx public keys.
2. **Wire Contract Dispatch**: `katzen-hot` reassembles air-gap chunks (`KPAG`), binds to `kpclientd` via Unix domain or abstract socket (`@katzenpost`), submits thin-client CBOR frames, and verifies `MessageSentEvent` delivery receipts.
3. **Durable Deferred Spooling**: When network connectivity or local mixnet daemons are unavailable, packets are saved with private permissions (`0o600`) to `spool/outbox/` for queueing.
4. **Native GUI Unlock Flow**: Slint desktop interface features in-window Argon2id decryption, password masking, on-screen key scrambling, and non-blocking initialization.
5. **Acoustic Out-of-Band Channel**: Support for `ggwave` FSK audio modulation over physical speakers and microphones (`katzen-cold send --sound` and `katzen-hot listen`), enabling air-gap data transfer on camera-less or headless hardware.
