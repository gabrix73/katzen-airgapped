use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const BOX_WIRE_VERSION: &[u8; 4] = b"KPB2";
const VAULT_WIRE_VERSION: &[u8; 4] = b"KAV1";
const VAULT_SALT_SIZE: usize = 16;
const AEAD_NONCE_SIZE: usize = 24;
static VAULT_PASSPHRASE: OnceLock<Result<Zeroizing<String>, String>> = OnceLock::new();

pub const BACAP_BOX_ID_SIZE: usize = 32;
pub const BACAP_SIGNATURE_SIZE: usize = 64;

// --- Katzenpost Pigeonhole & katzenqt1 Wire Invariants ---
pub const KEY_SIZE: usize = 32;
pub const INDEX_SIZE: usize = 104;
pub const READ_CAP_SIZE: usize = 136;
pub const HASH_SIZE: usize = 32;
pub const PREFIX_SIZE: usize = 8;
pub const ROSTER_MAX: usize = 256;

pub const KATZENQT1_VERSION: u64 = 3;
pub const MSG_TEXT: u64 = 0;
pub const MSG_INTRODUCTION: u64 = 1;
pub const MSG_FILE_UPLOAD: u64 = 2;
pub const MSG_WHO: u64 = 3;
pub const MSG_REPLY_WHO: u64 = 4;
pub const MSG_CONTROL: u64 = 10;

/// A member's identity: the public key its read cap begins with.
pub fn key_of(read_cap: &[u8]) -> &[u8] {
    &read_cap[..KEY_SIZE.min(read_cap.len())]
}

/// A member's prefix: the first 8 bytes of its public key.
pub fn prefix_of(key: &[u8]) -> &[u8] {
    &key[..PREFIX_SIZE.min(key.len())]
}

/// The index a read cap starts at.
pub fn start_of(read_cap: &[u8]) -> &[u8] {
    &read_cap[KEY_SIZE.min(read_cap.len())..]
}

fn default_username() -> String {
    "sovereign-operator".to_string()
}

/// Sovereign Mailbox Keypair for Katzenpost Pigeonhole
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoxIdentity {
    #[serde(default = "default_username")]
    pub username: String,
    pub box_id_hex: String,
    pub privkey_hex: String,
    pub created_at: u64,
}

impl BoxIdentity {
    pub fn generate(username: &str) -> Self {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let secret = X25519StaticSecret::from(seed);
        let pubkey = X25519PublicKey::from(&secret);

        let box_id = *pubkey.as_bytes();
        let privkey = seed;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            username: if username.trim().is_empty() { default_username() } else { username.trim().to_string() },
            box_id_hex: hex::encode(box_id),
            privkey_hex: hex::encode(privkey),
            created_at: now,
        }
    }

    pub fn identicon(&self) -> crate::identicon::Identicon {
        crate::identicon::Identicon::new(&self.username, &self.box_id_hex)
    }

    pub fn box_id(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.box_id_hex).map_err(|e| format!("Invalid box ID hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("Box ID must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    pub fn secret(&self) -> Result<X25519StaticSecret, String> {
        let bytes = hex::decode(&self.privkey_hex).map_err(|e| format!("Invalid privkey hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("Private key must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(X25519StaticSecret::from(arr))
    }

    /// Create a local demonstration tag. This is not a verifiable signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; BACAP_SIGNATURE_SIZE], String> {
        let priv_bytes = hex::decode(&self.privkey_hex).map_err(|e| e.to_string())?;
        let mut kdf = blake3::Hasher::new_derive_key("katzenpost-bacap-signature-key-v1");
        kdf.update(&priv_bytes);
        let sign_key = *kdf.finalize().as_bytes();

        let mut sig = [0u8; BACAP_SIGNATURE_SIZE];
        let h1 = blake3::keyed_hash(&sign_key, message);
        sig[0..32].copy_from_slice(h1.as_bytes());

        let mut h2_ctx = blake3::Hasher::new_keyed(&sign_key);
        h2_ctx.update(b"second-half");
        h2_ctx.update(message);
        sig[32..64].copy_from_slice(h2_ctx.finalize().as_bytes());

        Ok(sig)
    }

    /// This demo's X25519 box ID cannot verify a BLAKE3 tag derived from a private key.
    /// Never accept it as an asymmetric signature.
    pub fn verify_signature(
        _box_id: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; BACAP_SIGNATURE_SIZE],
    ) -> bool {
        false
    }

    /// Encrypt a local demo payload. This is not the Katzenpost BACAP wire format.
    pub fn encrypt_for_box(&self, recipient_box_id: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = OsRng;
        let mut eph_seed = [0u8; 32];
        rng.fill_bytes(&mut eph_seed);
        let eph_secret = X25519StaticSecret::from(eph_seed);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let recip_pub = X25519PublicKey::from(*recipient_box_id);
        let shared_dh = eph_secret.diffie_hellman(&recip_pub);

        if shared_dh.as_bytes().iter().all(|b| *b == 0) {
            return Err("Invalid recipient public key".into());
        }
        let mut kdf = blake3::Hasher::new_derive_key("katzen-airgapped-box-aead-v2");
        kdf.update(shared_dh.as_bytes());
        let mut sym_key = *kdf.finalize().as_bytes();

        let mut nonce = [0u8; AEAD_NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut aad = Vec::with_capacity(4 + 32 + 32);
        aad.extend_from_slice(BOX_WIRE_VERSION);
        aad.extend_from_slice(eph_pub.as_bytes());
        aad.extend_from_slice(recipient_box_id);
        let ciphertext = XChaCha20Poly1305::new((&sym_key).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| "Box encryption failed".to_string());
        sym_key.zeroize();
        let ciphertext = ciphertext?;

        let mut out = Vec::with_capacity(4 + 32 + AEAD_NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(BOX_WIRE_VERSION);
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a message addressed to our Box ID
    pub fn decrypt_box_payload(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        if wire.len() < 4 + 32 + AEAD_NONCE_SIZE + 16 || &wire[..4] != BOX_WIRE_VERSION {
            return Err("Encrypted payload too short".to_string());
        }
        let eph_pub_bytes: [u8; 32] = wire[4..36].try_into().unwrap();
        let nonce = &wire[36..60];
        let ciphertext = &wire[60..];

        let secret = self.secret()?;
        let eph_pub = X25519PublicKey::from(eph_pub_bytes);
        let shared_dh = secret.diffie_hellman(&eph_pub);

        if shared_dh.as_bytes().iter().all(|b| *b == 0) {
            return Err("Invalid sender ephemeral key".into());
        }
        let mut kdf = blake3::Hasher::new_derive_key("katzen-airgapped-box-aead-v2");
        kdf.update(shared_dh.as_bytes());
        let mut sym_key = *kdf.finalize().as_bytes();
        let mut aad = Vec::with_capacity(4 + 32 + 32);
        aad.extend_from_slice(BOX_WIRE_VERSION);
        aad.extend_from_slice(&eph_pub_bytes);
        aad.extend_from_slice(&self.box_id()?);
        let plaintext = XChaCha20Poly1305::new((&sym_key).into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| "Box authentication failed: corrupted payload or wrong key".to_string());
        sym_key.zeroize();
        plaintext
    }
}

/// Local demonstration deposit format, not the Katzenpost BACAP wire format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaWrite {
    pub box_id: [u8; BACAP_BOX_ID_SIZE],
    pub signature: [u8; BACAP_SIGNATURE_SIZE],
    pub payload: Vec<u8>,
}

impl ReplicaWrite {
    pub fn new(sender: &BoxIdentity, recipient_box_id: [u8; 32], plaintext: &[u8]) -> Result<Self, String> {
        let encrypted_payload = sender.encrypt_for_box(&recipient_box_id, plaintext)?;
        let sig = sender.sign(&encrypted_payload)?;
        Ok(Self {
            box_id: recipient_box_id,
            signature: sig,
            payload: encrypted_payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 64 + 4 + self.payload.len());
        buf.extend_from_slice(&self.box_id);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 32 + 64 + 4 {
            return Err("ReplicaWrite packet too short".to_string());
        }
        let mut box_id = [0u8; 32];
        box_id.copy_from_slice(&bytes[0..32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[32..96]);

        let payload_len = u32::from_be_bytes([bytes[96], bytes[97], bytes[98], bytes[99]]) as usize;
        if bytes.len() != 100 + payload_len {
            return Err(format!("Payload length mismatch: expected {}, got {}", payload_len, bytes.len() - 100));
        }
        let payload = bytes[100..100 + payload_len].to_vec();

        Ok(Self {
            box_id,
            signature,
            payload,
        })
    }
}

/// Katzenpost BACAP ReplicaRead query (Poll / Retrieval)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaRead {
    pub box_id: [u8; BACAP_BOX_ID_SIZE],
}

impl ReplicaRead {
    pub fn new(box_id: [u8; 32]) -> Self {
        Self { box_id }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.box_id.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("ReplicaRead must be 32 bytes".to_string());
        }
        let mut box_id = [0u8; 32];
        box_id.copy_from_slice(bytes);
        Ok(Self { box_id })
    }
}

/// Katzenpost BACAP ReplicaReadReply
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaReadReply {
    pub error_code: u8,
    pub box_id: [u8; BACAP_BOX_ID_SIZE],
    pub signature: [u8; BACAP_SIGNATURE_SIZE],
    pub payload: Vec<u8>,
}

impl ReplicaReadReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 64 + 4 + self.payload.len());
        buf.push(self.error_code);
        buf.extend_from_slice(&self.box_id);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 1 + 32 + 64 + 4 {
            return Err("ReplicaReadReply packet too short".to_string());
        }
        let error_code = bytes[0];
        let mut box_id = [0u8; 32];
        box_id.copy_from_slice(&bytes[1..33]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[33..97]);

        let payload_len = u32::from_be_bytes([bytes[97], bytes[98], bytes[99], bytes[100]]) as usize;
        if bytes.len() != 101 + payload_len {
            return Err(format!("Payload length mismatch: expected {}, got {}", payload_len, bytes.len() - 101));
        }
        let payload = bytes[101..101 + payload_len].to_vec();

        Ok(Self {
            error_code,
            box_id,
            signature,
            payload,
        })
    }
}

/// Offline Vault Mailbox Storage & Schrödinger Metaphor Manager
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub epoch: u64,
    pub plaintext: String,
    pub timestamp: u64,
    pub direction: MessageDirection,
    /// Schrödinger quantum state: Superposition (Air-gapped / unread) or Collapsed (Observed / Decrypted)
    pub quantum_state: String,
    pub secrecy_stars: u8,
    pub input_method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactProfile {
    pub username: String,
    pub box_id_hex: String,
    pub created_at: u64,
}

impl ContactProfile {
    pub fn new(username: &str, box_id_hex: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            username: username.to_string(),
            box_id_hex: box_id_hex.to_string(),
            created_at: now,
        }
    }

    pub fn identicon(&self) -> crate::identicon::Identicon {
        crate::identicon::Identicon::new(&self.username, &self.box_id_hex)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMailbox {
    pub identity: BoxIdentity,
    #[serde(default)]
    pub contacts: Vec<ContactProfile>,
    pub messages: Vec<MailboxMessage>,
}

pub fn set_cached_vault_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < 8 {
        return Err("Vault passphrase must contain at least 8 characters".into());
    }
    let _ = VAULT_PASSPHRASE.set(Ok(Zeroizing::new(passphrase.to_string())));
    Ok(())
}

pub fn is_vault_passphrase_cached() -> bool {
    VAULT_PASSPHRASE.get().is_some()
}

fn vault_passphrase(confirm_new: bool) -> Result<&'static str, String> {
    VAULT_PASSPHRASE
        .get_or_init(|| {
            let value = rpassword::prompt_password("Vault passphrase: ")
                .map_err(|e| format!("A terminal is required to unlock the vault: {e}"))?;
            if value.chars().count() < 12 {
                return Err("Vault passphrase must contain at least 12 characters".into());
            }
            if confirm_new {
                let confirmation = rpassword::prompt_password("Confirm new vault passphrase: ")
                    .map_err(|e| format!("Cannot confirm vault passphrase: {e}"))?;
                if value != confirmation {
                    return Err("Vault passphrases did not match".into());
                }
            }
            Ok(Zeroizing::new(value))
        })
        .as_ref()
        .map(|s| s.as_str())
        .map_err(Clone::clone)
}

fn vault_cipher(passphrase: &str, salt: &[u8]) -> Result<XChaCha20Poly1305, String> {
    let params = Params::new(64 * 1024, 3, 1, None).map_err(|e| e.to_string())?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Vault key derivation failed: {e}"))?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    key.zeroize();
    Ok(cipher)
}

fn encrypt_mailbox(mailbox: &VaultMailbox, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; VAULT_SALT_SIZE];
    let mut nonce = [0u8; AEAD_NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut plaintext = serde_json::to_vec(mailbox).map_err(|e| e.to_string())?;
    let encrypted = vault_cipher(passphrase, &salt)?
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: VAULT_WIRE_VERSION })
        .map_err(|_| "Vault encryption failed".to_string());
    plaintext.zeroize();
    let encrypted = encrypted?;
    let mut out = Vec::with_capacity(4 + VAULT_SALT_SIZE + AEAD_NONCE_SIZE + encrypted.len());
    out.extend_from_slice(VAULT_WIRE_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn decrypt_mailbox(wire: &[u8], passphrase: &str) -> Result<VaultMailbox, String> {
    if wire.len() < 4 + VAULT_SALT_SIZE + AEAD_NONCE_SIZE + 16 || !wire.starts_with(VAULT_WIRE_VERSION) {
        return Err("Invalid encrypted vault header".into());
    }
    let salt = &wire[4..20];
    let nonce = &wire[20..44];
    let ciphertext = &wire[44..];
    let mut plaintext = vault_cipher(passphrase, salt)?
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: VAULT_WIRE_VERSION })
        .map_err(|_| "Vault authentication failed: wrong passphrase or damaged file".to_string())?;
    let mailbox = serde_json::from_slice(&plaintext).map_err(|e| format!("Invalid vault contents: {e}"));
    plaintext.zeroize();
    mailbox
}

pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Vault path has no parent directory")?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)
        .map_err(|e| format!("Cannot create private directory: {e}"))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("Cannot restrict vault directory: {e}"))?;
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let temp = parent.join(format!(".vault-{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&temp).map_err(|e| format!("Cannot create private vault temp file: {e}"))?;
    let write_result = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&temp);
        return Err(format!("Cannot write encrypted vault: {e}"));
    }
    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(format!("Cannot replace vault atomically: {e}"));
    }
    let _ = fs::File::open(parent).and_then(|dir| dir.sync_all());
    Ok(())
}

impl VaultMailbox {
    pub fn new_or_load(storage_path: &Path) -> Result<Self, String> {
        Self::load_with_passphrase(storage_path, vault_passphrase(!storage_path.exists())?)
    }

    pub fn load_with_passphrase(storage_path: &Path, passphrase: &str) -> Result<Self, String> {
        if storage_path.is_symlink() {
            return Err("Vault path must not be a symbolic link".into());
        }
        if storage_path.exists() {
            let data = Zeroizing::new(fs::read(storage_path)
                .map_err(|e| format!("Failed to read mailbox file: {}", e))?);
            let mailbox = if data.starts_with(VAULT_WIRE_VERSION) {
                decrypt_mailbox(&data, passphrase)?
            } else if data.first() == Some(&b'{') {
                // One-time migration; atomic replacement leaves the old file intact on error.
                let legacy: VaultMailbox = serde_json::from_slice(&data)
                    .map_err(|e| format!("Invalid legacy mailbox format: {}", e))?;
                legacy.save_with_passphrase(storage_path, passphrase)?;
                legacy
            } else {
                return Err("Unknown vault format".into());
            };
            Ok(mailbox)
        } else {
            let identity = BoxIdentity::generate("sovereign-operator");
            let mailbox = Self {
                identity,
                contacts: Vec::new(),
                messages: Vec::new(),
            };
            mailbox.save_with_passphrase(storage_path, passphrase)?;
            Ok(mailbox)
        }
    }

    pub fn add_contact(&mut self, username: &str, box_id_hex: &str) -> Result<ContactProfile, String> {
        let trimmed_hex = box_id_hex.trim();
        let bytes = hex::decode(trimmed_hex).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("Contact Box ID must be exactly 32 bytes (64 hex characters)".to_string());
        }
        let profile = ContactProfile::new(username, trimmed_hex);
        self.contacts.retain(|c| !c.box_id_hex.eq_ignore_ascii_case(trimmed_hex));
        self.contacts.push(profile.clone());
        Ok(profile)
    }

    pub fn find_contact(&self, box_id_hex: &str) -> Option<&ContactProfile> {
        self.contacts.iter().find(|c| c.box_id_hex.eq_ignore_ascii_case(box_id_hex))
    }

    pub fn save(&self, storage_path: &Path) -> Result<(), String> {
        self.save_with_passphrase(storage_path, vault_passphrase(!storage_path.exists())?)
    }

    pub fn save_with_passphrase(&self, storage_path: &Path, passphrase: &str) -> Result<(), String> {
        if storage_path.is_symlink() {
            return Err("Vault path must not be a symbolic link".into());
        }
        let encrypted = encrypt_mailbox(self, passphrase)?;
        write_private_atomic(storage_path, &encrypted)
    }

    pub fn deposit_draft(
        &mut self,
        recipient_hex: &str,
        plaintext: &str,
        secrecy_stars: u8,
        input_method: &str,
    ) -> Result<ReplicaWrite, String> {
        let recipient_bytes = hex::decode(recipient_hex).map_err(|e| format!("Invalid recipient hex: {}", e))?;
        if recipient_bytes.len() != 32 {
            return Err("Recipient Box ID must be 32 bytes".to_string());
        }
        let mut recipient_arr = [0u8; 32];
        recipient_arr.copy_from_slice(&recipient_bytes);

        let replica_write = ReplicaWrite::new(&self.identity, recipient_arr, plaintext.as_bytes())?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut id_seed = [0u8; 16];
        OsRng.fill_bytes(&mut id_seed);

        let msg = MailboxMessage {
            id: hex::encode(id_seed),
            sender: self.identity.box_id_hex.clone(),
            recipient: recipient_hex.to_string(),
            epoch: 100,
            plaintext: plaintext.to_string(),
            timestamp: now,
            direction: MessageDirection::Outbound,
            quantum_state: "Superposition: In Transit (Mixnet Air-Gap)".to_string(),
            secrecy_stars,
            input_method: input_method.to_string(),
        };

        self.messages.push(msg);
        Ok(replica_write)
    }

    pub fn ingest_reply(&mut self, reply: &ReplicaReadReply) -> Result<String, String> {
        if reply.error_code != 0 {
            return Err(format!("Pigeonhole replica error code: {}", reply.error_code));
        }

        let plaintext_bytes = self.identity.decrypt_box_payload(&reply.payload)?;
        let plaintext = String::from_utf8(plaintext_bytes).map_err(|e| format!("UTF-8 decode error: {}", e))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut id_seed = [0u8; 16];
        OsRng.fill_bytes(&mut id_seed);

        let msg = MailboxMessage {
            id: hex::encode(id_seed),
            sender: hex::encode(reply.box_id),
            recipient: self.identity.box_id_hex.clone(),
            epoch: 100,
            plaintext: plaintext.clone(),
            timestamp: now,
            direction: MessageDirection::Inbound,
            quantum_state: "Decoherence: State Observed & Collapsed into Plaintext".to_string(),
            secrecy_stars: 5,
            input_method: "Air-gapped Ingestion (Spool/QR)".to_string(),
        };

        self.messages.push(msg);
        Ok(plaintext)
    }
}

/// Resolves the portable USB / application root directory relative to the running binary.
/// Ensures keys and spools stay on the USB stick rather than polluting the host PC's $HOME.
pub fn portable_root_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("KATZEN_HOME") {
        return PathBuf::from(custom);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // If running from <root>/target/release/katzen or <root>/target/debug/katzen
            if let Some(parent) = exe_dir.parent() {
                if parent.file_name().and_then(|s| s.to_str()) == Some("target") {
                    if let Some(project_root) = parent.parent() {
                        return project_root.to_path_buf();
                    }
                }
            }
            // If running from <root>/bin/katzen
            if exe_dir.file_name().and_then(|s| s.to_str()) == Some("bin") {
                if let Some(bundle_root) = exe_dir.parent() {
                    return bundle_root.to_path_buf();
                }
            }
            return exe_dir.to_path_buf();
        }
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn default_spool_dir() -> PathBuf {
    portable_root_dir().join("spool")
}

pub fn default_vault_mailbox_path() -> PathBuf {
    portable_root_dir().join("vault_data").join("vault_mailbox.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_identity_and_encryption_roundtrip() {
        let alice = BoxIdentity::generate("alice");
        let bob = BoxIdentity::generate("bob");

        let message = b"Quantum Post-Quantum Secret for Katzenpost";
        let encrypted = alice.encrypt_for_box(&bob.box_id().unwrap(), message).unwrap();
        let decrypted = bob.decrypt_box_payload(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_box_envelope_authenticates_every_field() {
        let alice = BoxIdentity::generate("alice");
        let bob = BoxIdentity::generate("bob");
        let wire = alice.encrypt_for_box(&bob.box_id().unwrap(), b"private payload").unwrap();
        for offset in [0, 4, 35, 36, 59, 60, wire.len() - 1] {
            let mut tampered = wire.clone();
            tampered[offset] ^= 1;
            assert!(bob.decrypt_box_payload(&tampered).is_err(), "tamper at {offset} accepted");
        }
        assert!(alice.decrypt_box_payload(&wire).is_err());
        assert!(alice.encrypt_for_box(&[0u8; 32], b"x").is_err());
        assert!(!BoxIdentity::verify_signature(&bob.box_id().unwrap(), b"x", &[0u8; 64]));
    }

    #[test]
    fn test_vault_encryption_and_private_atomic_file() {
        let mailbox = VaultMailbox { identity: BoxIdentity::generate("test"), contacts: vec![], messages: vec![] };
        let encrypted = encrypt_mailbox(&mailbox, "correct horse battery staple").unwrap();
        assert!(encrypted.starts_with(VAULT_WIRE_VERSION));
        assert!(!encrypted.windows(mailbox.identity.privkey_hex.len()).any(|w| w == mailbox.identity.privkey_hex.as_bytes()));
        assert_eq!(decrypt_mailbox(&encrypted, "correct horse battery staple").unwrap().identity.box_id_hex, mailbox.identity.box_id_hex);
        assert!(decrypt_mailbox(&encrypted, "incorrect passphrase").is_err());
        for offset in [4, 20, 44, encrypted.len() - 1] {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1;
            assert!(decrypt_mailbox(&tampered, "correct horse battery staple").is_err());
        }
        let mut id = [0u8; 8];
        OsRng.fill_bytes(&mut id);
        let dir = std::env::temp_dir().join(format!("katzen-vault-test-{}", hex::encode(id)));
        let file = dir.join("vault.bin");
        write_private_atomic(&file, &encrypted).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(fs::read(&file).unwrap().starts_with(VAULT_WIRE_VERSION));
        let legacy = dir.join("legacy.json");
        fs::write(&legacy, serde_json::to_vec(&mailbox).unwrap()).unwrap();
        let migrated = VaultMailbox::load_with_passphrase(&legacy, "correct horse battery staple").unwrap();
        assert_eq!(migrated.identity.box_id_hex, mailbox.identity.box_id_hex);
        assert!(fs::read(&legacy).unwrap().starts_with(VAULT_WIRE_VERSION));
        assert_eq!(fs::metadata(&legacy).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_replica_write_encode_decode() {
        let alice = BoxIdentity::generate("alice");
        let bob = BoxIdentity::generate("bob");

        let write_msg = ReplicaWrite::new(&alice, bob.box_id().unwrap(), b"Test BACAP Deposit").unwrap();
        let encoded = write_msg.encode();
        let decoded = ReplicaWrite::decode(&encoded).unwrap();

        assert_eq!(decoded.box_id, write_msg.box_id);
        assert_eq!(decoded.signature, write_msg.signature);
        assert_eq!(decoded.payload, write_msg.payload);
    }

    #[test]
    fn test_katzenqt1_wire_invariants() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(READ_CAP_SIZE, 136);
        assert_eq!(PREFIX_SIZE, 8);
        assert_eq!(KEY_SIZE + INDEX_SIZE, READ_CAP_SIZE);

        let mut dummy_read_cap = vec![0x42u8; READ_CAP_SIZE];
        dummy_read_cap[0..8].copy_from_slice(b"12345678");
        assert_eq!(key_of(&dummy_read_cap).len(), 32);
        assert_eq!(prefix_of(key_of(&dummy_read_cap)), b"12345678");
        assert_eq!(start_of(&dummy_read_cap).len(), INDEX_SIZE);
    }
}
