# Security test plan for katzen-airgapped

Status: local unit tests cover the new vault and envelope formats. No two-device or live mixnet test has yet passed.

## Gate 1: local regression

- New vault: encrypted `KAV1` content, no private key or plaintext in file, file mode 0600 and directory mode 0700.
- Legacy JSON: explicit backup before first real unlock, then one-time migration; verify readback, metadata, and that no new plaintext file is created. Do not use the existing personal mailbox in an automated test.
- Wrong passphrase, truncated file, changed salt, nonce, ciphertext, and format header must fail without replacing the original file.
- `KPB2` envelope: roundtrip and bit changes in version, ephemeral key, nonce, ciphertext and tag must fail; all-zero X25519 public key must fail.
- Sandbox: when namespaces are denied, `--sandbox` exits with an error before writing a packet. When namespace creation succeeds, inspect `/proc/<pid>/ns/net` and routes from an independent test process. A failed connection to one host is insufficient proof.
- Hot transport: reassemble synthetic QR frames with a fake Unix daemon listening; assert no daemon connection and only a 0600 `.demo` file is created. Invalid type and size must not be spooled.
- QR and CBOR parsers: malformed lengths, zero or excessive part counts, conflicting duplicates, too many pending sequences, deep nesting, invalid UTF-8, missing terminators, and trailing bytes must fail. Add fuzz targets before release.
- Daemon connection: reject non-loopback TCP destinations; separately verify Unix socket permissions and daemon identity on the target systems.
- SURB demo export: no reply decryption key in JSON or QR; oversized demo messages and destinations fail instead of being truncated.

## Gate 2: two-device cold/hot demonstration

1. Prepare a dedicated laptop with known OS image and no active Wi-Fi, Bluetooth, mobile modem, or Ethernet. Record radio and route state before and after each run.
2. Use only synthetic test messages and a separate online machine. Transfer via QR first; test missing, repeated, reordered, corrupted, and oversized frames.
3. Repeat with removable media. Treat imported media as untrusted and verify no secrets or unexpected writes cross back to the cold device.
4. Power-cycle both devices and verify queue recovery and clear error reporting.

## Gate 3: live Katzenpost compatibility (blocked by implementation)

- Import signed, fresh PKI material on the cold device and reject expired or forged material.
- Generate protocol-compatible Sphinx packets and BACAP requests from actual service descriptors.
- Verify daemon framing and service registration with a controlled `kpclientd`; test successful delivery and authenticated reply on a real network.
- Test key binding, replay, expiry, crash recovery, duplicated delivery, receipt handling, and network failures.
- Repeat security review after replacing the demonstration signature/tag with the actual protocol construction.

A successful QR transfer or passing local unit tests does not complete Gate 3.
