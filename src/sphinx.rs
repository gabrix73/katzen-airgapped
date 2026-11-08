use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::thinclient::CborValue;

pub const NUM_HOPS: usize = 3;
pub const HOP_ROUTING_SIZE: usize = 64; // Routing command + Delay + flags + MAC
pub const ROUTING_INFO_SIZE: usize = NUM_HOPS * HOP_ROUTING_SIZE; // 192 bytes
pub const SPHINX_HEADER_SIZE: usize = 32 + ROUTING_INFO_SIZE; // 224 bytes (32-byte Alpha + 192-byte Routing)
pub const TOTAL_SPHINX_PACKET_SIZE: usize = 1024; // Katzenpost standard constant length
pub const SPHINX_PAYLOAD_SIZE: usize = TOTAL_SPHINX_PACKET_SIZE - SPHINX_HEADER_SIZE; // 800 bytes

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MixNodeDescriptor {
    pub id: String,
    pub address: String,
    pub public_key_hex: String,
    pub layer: u8,
}

impl MixNodeDescriptor {
    pub fn new(id: &str, address: &str, pubkey: &PublicKey, layer: u8) -> Self {
        Self {
            id: id.to_string(),
            address: address.to_string(),
            public_key_hex: hex::encode(pubkey.as_bytes()),
            layer,
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, String> {
        let bytes = hex::decode(&self.public_key_hex).map_err(|e| format!("Invalid hex pubkey: {}", e))?;
        if bytes.len() != 32 {
            return Err("Public key must be 32 bytes".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusTopology {
    pub epoch: u64,
    pub nodes: Vec<MixNodeDescriptor>,
}

impl ConsensusTopology {
    /// Parse and validate authentic MixNodes and layers from a Katzenpost PKI consensus CBOR document
    pub fn from_pki_document(pki_bytes: &[u8]) -> Result<Self, String> {
        let doc = CborValue::decode(pki_bytes)?;
        let epoch = doc.get("Epoch").and_then(|v| v.as_u64()).unwrap_or(0);

        let mut nodes = Vec::new();

        // 1. Primary Katzenpost consensus topology: Topology is an array of layers (array of arrays)
        if let Some(topo_layers) = doc.get("Topology").and_then(|v| v.as_array()) {
            for (layer_idx, layer_val) in topo_layers.iter().enumerate() {
                let layer_num = (layer_idx + 1) as u8;
                if let Some(layer_nodes) = layer_val.as_array() {
                    for raw_node in layer_nodes {
                        if let Some(desc) = Self::parse_mix_descriptor(raw_node, layer_num, epoch) {
                            nodes.push(desc);
                        }
                    }
                }
            }
        }

        // 2. Fallback / Alternative: flattened MixNodes list
        if nodes.is_empty() {
            if let Some(mix_nodes) = doc.get("MixNodes").and_then(|v| v.as_array()) {
                for (idx, raw_node) in mix_nodes.iter().enumerate() {
                    let fallback_layer = ((idx % NUM_HOPS) + 1) as u8;
                    if let Some(desc) = Self::parse_mix_descriptor(raw_node, fallback_layer, epoch) {
                        nodes.push(desc);
                    }
                }
            }
        }

        if nodes.is_empty() {
            return Err("PKI consensus document contains no valid mix nodes in topology".into());
        }

        // Verify that we have at least one node per layer required by Sphinx
        for layer in 1..=(NUM_HOPS as u8) {
            if !nodes.iter().any(|n| n.layer == layer) {
                return Err(format!(
                    "Incomplete topology from PKI: missing mix nodes in layer {}",
                    layer
                ));
            }
        }

        Ok(Self { epoch, nodes })
    }

    fn parse_mix_descriptor(val: &CborValue, default_layer: u8, epoch: u64) -> Option<MixNodeDescriptor> {
        let node_map_val = if let Some(bytes) = val.as_bytes() {
            CborValue::decode(bytes).ok()?
        } else {
            val.clone()
        };

        let name = node_map_val
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or("mixnode")
            .to_string();

        let layer = node_map_val
            .get("Layer")
            .and_then(|v| v.as_u64())
            .map(|l| l as u8)
            .unwrap_or(default_layer);

        let mut address = format!("{}:1789", name);
        if let Some(addrs_map) = node_map_val.get("Addresses").and_then(|v| v.as_map()) {
            for (_, v) in addrs_map {
                if let Some(arr) = v.as_array() {
                    if let Some(first) = arr.first().and_then(|a| a.as_str()) {
                        address = first.to_string();
                        break;
                    }
                } else if let Some(s) = v.as_str() {
                    address = s.to_string();
                    break;
                }
            }
        } else if let Some(s) = node_map_val.get("Address").and_then(|v| v.as_str()) {
            address = s.to_string();
        }

        let mut pubkey_bytes: Option<[u8; 32]> = None;

        if let Some(mix_keys) = node_map_val.get("MixKeys").and_then(|v| v.as_map()) {
            for (k, v) in mix_keys {
                if let (Some(k_epoch), Some(bytes)) = (k.as_u64(), v.as_bytes()) {
                    if k_epoch == epoch && bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(bytes);
                        pubkey_bytes = Some(arr);
                        break;
                    }
                }
            }
            if pubkey_bytes.is_none() {
                for (_, v) in mix_keys {
                    if let Some(bytes) = v.as_bytes() {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(bytes);
                            pubkey_bytes = Some(arr);
                            break;
                        }
                    }
                }
            }
        }

        if pubkey_bytes.is_none() {
            if let Some(link) = node_map_val.get("LinkKey").and_then(|v| v.as_bytes()) {
                if link.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(link);
                    pubkey_bytes = Some(arr);
                }
            }
        }

        if pubkey_bytes.is_none() {
            if let Some(id_key) = node_map_val.get("IdentityKey").and_then(|v| v.as_bytes()) {
                if id_key.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(id_key);
                    pubkey_bytes = Some(arr);
                }
            }
        }

        let key_32 = pubkey_bytes?;
        let pubkey = PublicKey::from(key_32);
        Some(MixNodeDescriptor::new(&name, &address, &pubkey, layer))
    }

    pub fn generate_mock_consensus(epoch: u64) -> (Self, Vec<StaticSecret>) {
        let mut nodes = Vec::new();
        let mut privkeys = Vec::new();

        for layer in 1..=3 {
            for idx in 1..=3 {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let privkey = StaticSecret::from(seed);
                let pubkey = PublicKey::from(&privkey);
                let id = format!("mix-L{}-N{}", layer, idx);
                let addr = format!("10.1.{}.{}:1789", layer, idx);
                nodes.push(MixNodeDescriptor::new(&id, &addr, &pubkey, layer));
                privkeys.push(privkey);
            }
        }

        (Self { epoch, nodes }, privkeys)
    }

    pub fn select_path(&self) -> Result<Vec<MixNodeDescriptor>, String> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        let l1_nodes: Vec<_> = self.nodes.iter().filter(|n| n.layer == 1).collect();
        let l2_nodes: Vec<_> = self.nodes.iter().filter(|n| n.layer == 2).collect();
        let l3_nodes: Vec<_> = self.nodes.iter().filter(|n| n.layer == 3).collect();

        if l1_nodes.is_empty() || l2_nodes.is_empty() || l3_nodes.is_empty() {
            return Err("Incomplete topology: missing nodes in one or more layers".to_string());
        }

        let n1 = (*l1_nodes.choose(&mut rng).unwrap()).clone();
        let n2 = (*l2_nodes.choose(&mut rng).unwrap()).clone();
        let n3 = (*l3_nodes.choose(&mut rng).unwrap()).clone();

        Ok(vec![n1, n2, n3])
    }
}

pub struct DerivedHopKeys {
    pub shared_secret: [u8; 32],
    pub rho_key: [u8; 32],      // Routing encryption
    pub gamma_key: [u8; 32],    // MAC key
    pub pi_key: [u8; 32],       // Payload encryption
    pub blinding_factor: [u8; 32],
}

impl DerivedHopKeys {
    pub fn derive(shared_secret: [u8; 32], alpha: &[u8; 32]) -> Self {
        let mut b_ctx = blake3::Hasher::new_derive_key("katzenpost-sphinx-blind-v1");
        b_ctx.update(&shared_secret);
        b_ctx.update(alpha);
        let blinding_factor = *b_ctx.finalize().as_bytes();

        let mut r_ctx = blake3::Hasher::new_derive_key("katzenpost-sphinx-rho-v1");
        r_ctx.update(&shared_secret);
        let rho_key = *r_ctx.finalize().as_bytes();

        let mut g_ctx = blake3::Hasher::new_derive_key("katzenpost-sphinx-gamma-v1");
        g_ctx.update(&shared_secret);
        let gamma_key = *g_ctx.finalize().as_bytes();

        let mut p_ctx = blake3::Hasher::new_derive_key("katzenpost-sphinx-pi-v1");
        p_ctx.update(&shared_secret);
        let pi_key = *p_ctx.finalize().as_bytes();

        Self {
            shared_secret,
            rho_key,
            gamma_key,
            pi_key,
            blinding_factor,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SphinxPacket {
    pub raw_bytes: Vec<u8>,
}

impl SphinxPacket {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != TOTAL_SPHINX_PACKET_SIZE {
            return Err(format!(
                "Invalid Sphinx packet size: expected {} bytes, got {}",
                TOTAL_SPHINX_PACKET_SIZE,
                bytes.len()
            ));
        }
        Ok(Self {
            raw_bytes: bytes.to_vec(),
        })
    }

    pub fn alpha(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&self.raw_bytes[0..32]);
        a
    }

    pub fn routing_info(&self) -> &[u8] {
        &self.raw_bytes[32..SPHINX_HEADER_SIZE]
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw_bytes[SPHINX_HEADER_SIZE..]
    }
}

pub struct SphinxEngine;

impl SphinxEngine {
    pub fn build_packet(
        path: &[MixNodeDescriptor],
        destination: &str,
        message: &[u8],
    ) -> Result<SphinxPacket, String> {
        if path.len() != NUM_HOPS {
            return Err(format!("Path must contain exactly {} hops", NUM_HOPS));
        }

        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let ephemeral_secret = StaticSecret::from(seed);
        let alpha_0 = PublicKey::from(&ephemeral_secret);
        let alpha_0_bytes = *alpha_0.as_bytes();

        let mut alphas = Vec::with_capacity(NUM_HOPS);
        let mut shared_secrets = Vec::with_capacity(NUM_HOPS);
        let mut hop_keys = Vec::with_capacity(NUM_HOPS);

        let mut current_alpha = alpha_0_bytes;
        let mut current_dh_secret = ephemeral_secret;

        for (i, node) in path.iter().enumerate() {
            let node_pubkey = node.public_key()?;
            let ss = current_dh_secret.diffie_hellman(&node_pubkey);
            let ss_hash = *blake3::hash(ss.as_bytes()).as_bytes();

            let keys = DerivedHopKeys::derive(ss_hash, &current_alpha);
            alphas.push(current_alpha);
            shared_secrets.push(ss_hash);

            if i < NUM_HOPS - 1 {
                current_alpha = *blake3::hash(&[&current_alpha[..], &keys.blinding_factor[..]].concat()).as_bytes();
                let mut next_seed = [0u8; 32];
                rng.fill_bytes(&mut next_seed);
                current_dh_secret = StaticSecret::from(next_seed);
            }

            hop_keys.push(keys);
        }

        // Build Payload with reverse multi-layer encryption
        let mut padded_payload = vec![0u8; SPHINX_PAYLOAD_SIZE];
        if message.len() > SPHINX_PAYLOAD_SIZE - 4 {
            return Err("Demo packet payload exceeds capacity".into());
        }
        let copy_len = message.len();
        padded_payload[0..4].copy_from_slice(&(copy_len as u32).to_be_bytes());
        padded_payload[4..4 + copy_len].copy_from_slice(&message[..copy_len]);

        for i in (0..NUM_HOPS).rev() {
            let key = chacha20::Key::from_slice(&hop_keys[i].pi_key);
            let nonce = chacha20::Nonce::from_slice(&[0u8; 12]);
            let mut cipher = ChaCha20::new(key, nonce);
            cipher.apply_keystream(&mut padded_payload);
        }

        // Build Sphinx Routing Info
        let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
        let mut dest_bytes = [0u8; 32];
        let dest_raw = destination.as_bytes();
        if dest_raw.len() > 32 {
            return Err("Demo destination exceeds 32-byte routing field".into());
        }
        let dest_copy = dest_raw.len();
        dest_bytes[..dest_copy].copy_from_slice(&dest_raw[..dest_copy]);

        for i in (0..NUM_HOPS).rev() {
            let next_addr = if i == NUM_HOPS - 1 {
                dest_bytes
            } else {
                let mut addr = [0u8; 32];
                let raw_addr = path[i + 1].address.as_bytes();
                let clen = raw_addr.len().min(32);
                addr[..clen].copy_from_slice(&raw_addr[..clen]);
                addr
            };

            let mut hop_cmd = [0u8; HOP_ROUTING_SIZE];
            hop_cmd[0..32].copy_from_slice(&next_addr);
            hop_cmd[32..36].copy_from_slice(&100u32.to_be_bytes()); // Delay parameter mu

            // Compute 16-byte MAC over next hop commands + remainder
            let tag = blake3::keyed_hash(&hop_keys[i].gamma_key, &hop_cmd[0..48]);
            hop_cmd[48..64].copy_from_slice(&tag.as_bytes()[0..16]);

            let shift_end = ROUTING_INFO_SIZE - HOP_ROUTING_SIZE;
            routing_info.copy_within(0..shift_end, HOP_ROUTING_SIZE);
            routing_info[0..HOP_ROUTING_SIZE].copy_from_slice(&hop_cmd);

            // Encrypt routing info with rho key
            let key = chacha20::Key::from_slice(&hop_keys[i].rho_key);
            let nonce = chacha20::Nonce::from_slice(&[0u8; 12]);
            let mut cipher = ChaCha20::new(key, nonce);
            cipher.apply_keystream(&mut routing_info);
        }

        let mut packet_bytes = Vec::with_capacity(TOTAL_SPHINX_PACKET_SIZE);
        packet_bytes.extend_from_slice(&alpha_0_bytes);
        packet_bytes.extend_from_slice(&routing_info);
        packet_bytes.extend_from_slice(&padded_payload);

        SphinxPacket::from_bytes(&packet_bytes)
    }

    pub fn peel_hop(
        mix_privkey: &StaticSecret,
        packet: &SphinxPacket,
    ) -> Result<(String, u32, Vec<u8>), String> {
        let alpha = PublicKey::from(packet.alpha());
        let shared_secret = mix_privkey.diffie_hellman(&alpha);
        let ss_hash = *blake3::hash(shared_secret.as_bytes()).as_bytes();
        let hop_keys = DerivedHopKeys::derive(ss_hash, &packet.alpha());

        let mut routing_info = packet.routing_info().to_vec();
        let key = chacha20::Key::from_slice(&hop_keys.rho_key);
        let nonce = chacha20::Nonce::from_slice(&[0u8; 12]);
        let mut cipher = ChaCha20::new(key, nonce);
        cipher.apply_keystream(&mut routing_info);

        let mut hop_cmd = [0u8; HOP_ROUTING_SIZE];
        hop_cmd.copy_from_slice(&routing_info[0..HOP_ROUTING_SIZE]);

        let mut next_addr_bytes = [0u8; 32];
        next_addr_bytes.copy_from_slice(&hop_cmd[0..32]);
        let next_addr = String::from_utf8_lossy(&next_addr_bytes).trim_matches(char::from(0)).to_string();

        let delay = u32::from_be_bytes([hop_cmd[32], hop_cmd[33], hop_cmd[34], hop_cmd[35]]);

        // Verify 16-byte MAC
        let expected_tag = blake3::keyed_hash(&hop_keys.gamma_key, &hop_cmd[0..48]);
        if &hop_cmd[48..64] != &expected_tag.as_bytes()[0..16] {
            return Err("Sphinx MAC verification failed for hop".to_string());
        }

        // Decrypt payload layer
        let mut payload = packet.payload().to_vec();
        let p_key = chacha20::Key::from_slice(&hop_keys.pi_key);
        let p_nonce = chacha20::Nonce::from_slice(&[0u8; 12]);
        let mut p_cipher = ChaCha20::new(p_key, p_nonce);
        p_cipher.apply_keystream(&mut payload);

        Ok((next_addr, delay, payload))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurbPackage {
    pub surb_id: String,
    pub first_hop_address: String,
    pub header_hex: String,
    pub epoch_expiry: u64,
}

pub struct SurbManager {
    surb_keys: HashMap<String, [u8; 32]>,
}

impl SurbManager {
    pub fn new() -> Self {
        Self {
            surb_keys: HashMap::new(),
        }
    }

    pub fn generate_surb(
        &mut self,
        topology: &ConsensusTopology,
        client_address: &str,
        epoch_expiry: u64,
    ) -> Result<SurbPackage, String> {
        let return_path = topology.select_path()?;
        let mut k_surb = [0u8; 32];
        OsRng.fill_bytes(&mut k_surb);

        let mut surb_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut surb_id_bytes);
        let surb_id = hex::encode(surb_id_bytes);

        let dummy_payload = vec![0u8; SPHINX_PAYLOAD_SIZE - 4];
        let packet = SphinxEngine::build_packet(&return_path, client_address, &dummy_payload)?;

        self.surb_keys.insert(surb_id.clone(), k_surb);

        Ok(SurbPackage {
            surb_id,
            first_hop_address: return_path[0].address.clone(),
            header_hex: hex::encode(&packet.raw_bytes[0..SPHINX_HEADER_SIZE]),
            epoch_expiry,
        })
    }

    pub fn get_key(&self, surb_id: &str) -> Option<&[u8; 32]> {
        self.surb_keys.get(surb_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphinx_packet_construction_and_hop_peeling() {
        let (topology, privkeys) = ConsensusTopology::generate_mock_consensus(100);
        let path = topology.select_path().unwrap();
        let message = b"Katzenpost Airgapped Secure Message Over 3 Hops";
        let destination = "pigeonhole-mailbox-service-01";

        let packet = SphinxEngine::build_packet(&path, destination, message).unwrap();
        assert_eq!(packet.raw_bytes.len(), TOTAL_SPHINX_PACKET_SIZE);

        // Hop 1 (Mix 1)
        let n1_key = privkeys.iter().find(|k| PublicKey::from(*k) == path[0].public_key().unwrap()).unwrap();
        let (next1, _delay1, _p1) = SphinxEngine::peel_hop(n1_key, &packet).unwrap();
        assert_eq!(next1, path[1].address);

        println!("Hop 1 peeled successfully: next is {}", next1);
    }

    #[test]
    fn demo_packet_rejects_truncation() {
        let (topology, _) = ConsensusTopology::generate_mock_consensus(103);
        let path = topology.select_path().unwrap();
        assert!(SphinxEngine::build_packet(&path, "courier", &vec![0u8; SPHINX_PAYLOAD_SIZE - 3]).is_err());
        assert!(SphinxEngine::build_packet(&path, &"x".repeat(33), b"hi").is_err());
    }

    #[test]
    fn test_from_pki_document_parsing() {
        // Construct authentic CBOR PKI Document with 3 layers
        let epoch = 42u64;
        let mut layers = Vec::new();

        for layer_idx in 0..3 {
            let mut layer_nodes = Vec::new();
            for n_idx in 0..2 {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let privkey = StaticSecret::from(seed);
                let pubkey = PublicKey::from(&privkey);

                let node_map = CborValue::Map(vec![
                    (CborValue::Text("Name".into()), CborValue::Text(format!("node-L{}-{}", layer_idx + 1, n_idx))),
                    (CborValue::Text("Addresses".into()), CborValue::Map(vec![
                        (CborValue::Text("tcp".into()), CborValue::Array(vec![
                            CborValue::Text(format!("192.168.10.{}:1789", (layer_idx + 1) * 10 + n_idx)),
                        ])),
                    ])),
                    (CborValue::Text("MixKeys".into()), CborValue::Map(vec![
                        (CborValue::UInt(epoch), CborValue::Bytes(pubkey.as_bytes().to_vec())),
                    ])),
                ]);

                // Katzenpost embeds raw CBOR bytes for descriptors
                layer_nodes.push(CborValue::Bytes(node_map.encode()));
            }
            layers.push(CborValue::Array(layer_nodes));
        }

        let pki_doc = CborValue::Map(vec![
            (CborValue::Text("Epoch".into()), CborValue::UInt(epoch)),
            (CborValue::Text("Topology".into()), CborValue::Array(layers)),
        ]);

        let pki_bytes = pki_doc.encode();
        let topo = ConsensusTopology::from_pki_document(&pki_bytes).expect("Failed to parse valid PKI CBOR");
        assert_eq!(topo.epoch, epoch);
        assert_eq!(topo.nodes.len(), 6);

        let path = topo.select_path().expect("Failed to select path from parsed PKI");
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].layer, 1);
        assert_eq!(path[1].layer, 2);
        assert_eq!(path[2].layer, 3);

        // Verify Sphinx packet builds successfully with nodes from PKI
        let pkt = SphinxEngine::build_packet(&path, "courier", b"PKI Test Message").unwrap();
        assert_eq!(pkt.raw_bytes.len(), TOTAL_SPHINX_PACKET_SIZE);
    }

    #[test]
    fn test_from_pki_document_missing_layer_rejected() {
        let pki_doc = CborValue::Map(vec![
            (CborValue::Text("Epoch".into()), CborValue::UInt(1)),
            (CborValue::Text("Topology".into()), CborValue::Array(vec![
                CborValue::Array(vec![]), // Layer 1 empty!
                CborValue::Array(vec![]),
            ])),
        ]);
        let err = ConsensusTopology::from_pki_document(&pki_doc.encode()).unwrap_err();
        assert!(err.contains("no valid mix nodes") || err.contains("missing mix nodes"));
    }
}
