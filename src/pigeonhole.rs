use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

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

    /// Sign payload using BLAKE3 keyed hash derived from private key
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

    /// Verify signature for a given box_id
    pub fn verify_signature(
        _box_id: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; BACAP_SIGNATURE_SIZE],
    ) -> bool {
        // In local demo model, signature verification is stubbed
        // (Production uses asymmetric BLAKE3/Ed25519 verification)
        true
    }

    /// Encrypt a message payload for a recipient Box ID using ephemeral ECDH + ChaCha20
    pub fn encrypt_for_box(&self, recipient_box_id: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = OsRng;
        let mut eph_seed = [0u8; 32];
        rng.fill_bytes(&mut eph_seed);
        let eph_secret = X25519StaticSecret::from(eph_seed);
        let eph_pub = X25519PublicKey::from(&eph_secret);

        let recip_pub = X25519PublicKey::from(*recipient_box_id);
        let shared_dh = eph_secret.diffie_hellman(&recip_pub);

        let mut kdf = blake3::Hasher::new_derive_key("katzenpost-pigeonhole-box-encrypt-v1");
        kdf.update(shared_dh.as_bytes());
        let sym_key = *kdf.finalize().as_bytes();

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let mut ciphertext = plaintext.to_vec();
        let key = chacha20::Key::from_slice(&sym_key);
        let chacha_nonce = chacha20::Nonce::from_slice(&nonce);
        let mut cipher = ChaCha20::new(key, chacha_nonce);
        cipher.apply_keystream(&mut ciphertext);

        let mac = blake3::keyed_hash(&sym_key, &ciphertext);

        // Result wire: [eph_pub (32B) | nonce (12B) | mac (16B) | ciphertext]
        let mut out = Vec::with_capacity(32 + 12 + 16 + ciphertext.len());
        out.extend_from_slice(eph_pub.as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&mac.as_bytes()[0..16]);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a message addressed to our Box ID
    pub fn decrypt_box_payload(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        if wire.len() < 32 + 12 + 16 {
            return Err("Encrypted payload too short".to_string());
        }
        let eph_pub_bytes: [u8; 32] = wire[0..32].try_into().unwrap();
        let nonce: [u8; 12] = wire[32..44].try_into().unwrap();
        let expected_mac = &wire[44..60];
        let ciphertext = &wire[60..];

        let secret = self.secret()?;
        let eph_pub = X25519PublicKey::from(eph_pub_bytes);
        let shared_dh = secret.diffie_hellman(&eph_pub);

        let mut kdf = blake3::Hasher::new_derive_key("katzenpost-pigeonhole-box-encrypt-v1");
        kdf.update(shared_dh.as_bytes());
        let sym_key = *kdf.finalize().as_bytes();

        let mac = blake3::keyed_hash(&sym_key, ciphertext);
        if &mac.as_bytes()[0..16] != expected_mac {
            return Err("Pigeonhole MAC verification failed: corrupted or wrong key".to_string());
        }

        let mut plaintext = ciphertext.to_vec();
        let key = chacha20::Key::from_slice(&sym_key);
        let chacha_nonce = chacha20::Nonce::from_slice(&nonce);
        let mut cipher = ChaCha20::new(key, chacha_nonce);
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }
}

/// Katzenpost BACAP ReplicaWrite message (Deposit)
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

impl VaultMailbox {
    pub fn new_or_load(storage_path: &Path) -> Result<Self, String> {
        if storage_path.exists() {
            let data = fs::read_to_string(storage_path).map_err(|e| format!("Failed to read mailbox file: {}", e))?;
            let mailbox: VaultMailbox = serde_json::from_str(&data).map_err(|e| format!("Invalid mailbox format: {}", e))?;
            Ok(mailbox)
        } else {
            let identity = BoxIdentity::generate("sovereign-operator");
            let mailbox = Self {
                identity,
                contacts: Vec::new(),
                messages: Vec::new(),
            };
            if let Some(parent) = storage_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            mailbox.save(storage_path)?;
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
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(storage_path, json).map_err(|e| format!("Failed to write mailbox file: {}", e))?;
        Ok(())
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

pub fn default_vault_mailbox_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".katzen").join("vault_mailbox.json")
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
