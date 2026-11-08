use std::collections::HashMap;

pub mod identicon;
pub mod pigeonhole;
pub mod sandbox;
pub mod sphinx;
pub mod thinclient;
pub mod ui;
pub mod virtual_keyboard;

pub const MAGIC: [u8; 4] = *b"KPAG";
pub const PROTOCOL_VERSION: u8 = 1;
pub const DEFAULT_CHUNK_SIZE: usize = 90; // Compact Version 4-5 QR code: ~37x20 chars in terminal
pub const MAX_QR_CHUNK_SIZE: usize = 1024;
pub const MAX_QR_PARTS: usize = 256;
pub const MAX_QR_MESSAGE_SIZE: usize = 64 * 1024;
pub const MAX_PENDING_SEQUENCES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    SphinxOut = 0x01,
    SurbDelegate = 0x02,
    ReplyIn = 0x03,
    PkiConsensusUpdate = 0x04,
    HotStatus = 0x05,
    PigeonholeDeposit = 0x06,
    PigeonholePoll = 0x07,
    PigeonholeReply = 0x08,
}

impl MsgType {
    pub fn from_u8(b: u8) -> Result<Self, String> {
        match b {
            0x01 => Ok(Self::SphinxOut),
            0x02 => Ok(Self::SurbDelegate),
            0x03 => Ok(Self::ReplyIn),
            0x04 => Ok(Self::PkiConsensusUpdate),
            0x05 => Ok(Self::HotStatus),
            0x06 => Ok(Self::PigeonholeDeposit),
            0x07 => Ok(Self::PigeonholePoll),
            0x08 => Ok(Self::PigeonholeReply),
            other => Err(format!("Unknown MsgType: 0x{:02x}", other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpagHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub msg_type: MsgType,
    pub seq_id: u32,
    pub part_index: u16,
    pub total_parts: u16,
    pub payload_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpagChunk {
    pub header: KpagHeader,
    pub data: Vec<u8>,
    pub checksum: [u8; 4],
}

impl KpagChunk {
    pub fn encode_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.data.len() + 4);
        buf.extend_from_slice(&self.header.magic);
        buf.push(self.header.version);
        buf.push(self.header.msg_type as u8);
        buf.extend_from_slice(&self.header.seq_id.to_be_bytes());
        buf.extend_from_slice(&self.header.part_index.to_be_bytes());
        buf.extend_from_slice(&self.header.total_parts.to_be_bytes());
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        let hash = blake3::hash(&buf);
        let checksum: [u8; 4] = hash.as_bytes()[0..4].try_into().unwrap();
        buf.extend_from_slice(&checksum);
        buf
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 20 {
            return Err("Packet too short (minimum 20 bytes for header + checksum)".to_string());
        }

        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != MAGIC {
            return Err("Invalid magic bytes, expected 'KPAG'".to_string());
        }

        let version = bytes[4];
        if version != PROTOCOL_VERSION {
            return Err(format!("Unsupported protocol version: {}", version));
        }

        let msg_type = MsgType::from_u8(bytes[5])?;
        let seq_id = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let part_index = u16::from_be_bytes([bytes[10], bytes[11]]);
        let total_parts = u16::from_be_bytes([bytes[12], bytes[13]]);
        let payload_len = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
        if total_parts == 0 || total_parts as usize > MAX_QR_PARTS || part_index >= total_parts {
            return Err("Invalid QR part index or count".into());
        }
        if payload_len > MAX_QR_CHUNK_SIZE {
            return Err("QR chunk exceeds size limit".into());
        }

        if bytes.len() != 16 + payload_len + 4 {
            return Err(format!(
                "Payload length mismatch: header says {} bytes, total packet size is {}",
                payload_len,
                bytes.len()
            ));
        }

        let data = bytes[16..16 + payload_len].to_vec();
        let expected_checksum = &bytes[16 + payload_len..];

        let hash = blake3::hash(&bytes[0..16 + payload_len]);
        let calculated_checksum = &hash.as_bytes()[0..4];

        if expected_checksum != calculated_checksum {
            return Err("BLAKE3 checksum validation failed".to_string());
        }

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(expected_checksum);

        Ok(Self {
            header: KpagHeader {
                magic,
                version,
                msg_type,
                seq_id,
                part_index,
                total_parts,
                payload_len: payload_len as u16,
            },
            data,
            checksum,
        })
    }

    pub fn to_qr_string(&self) -> String {
        format!("kpag://{}", hex::encode(self.encode_bytes()))
    }

    pub fn from_qr_string(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let raw = if let Some(stripped) = s.strip_prefix("kpag://") {
            stripped
        } else if let Some(stripped) = s.strip_prefix("KPAG://") {
            stripped
        } else {
            s
        };

        let bytes = hex::decode(raw).map_err(|e| format!("Hex decode error: {}", e))?;
        Self::decode_bytes(&bytes)
    }
}

pub fn fragment_payload(
    msg_type: MsgType,
    seq_id: u32,
    payload: &[u8],
    chunk_size: usize,
) -> Result<Vec<KpagChunk>, String> {
    if chunk_size == 0 || chunk_size > MAX_QR_CHUNK_SIZE || payload.len() > MAX_QR_MESSAGE_SIZE {
        return Err("Invalid QR chunk or message size".into());
    }
    if payload.is_empty() {
        let chunk = KpagChunk {
            header: KpagHeader {
                magic: MAGIC,
                version: PROTOCOL_VERSION,
                msg_type,
                seq_id,
                part_index: 0,
                total_parts: 1,
                payload_len: 0,
            },
            data: Vec::new(),
            checksum: [0; 4],
        };
        return Ok(vec![chunk]);
    }

    let chunks: Vec<&[u8]> = payload.chunks(chunk_size).collect();
    if chunks.len() > MAX_QR_PARTS {
        return Err("QR message requires too many parts".into());
    }
    let total_parts = chunks.len() as u16;

    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(i, slice)| {
            let mut chunk = KpagChunk {
                header: KpagHeader {
                    magic: MAGIC,
                    version: PROTOCOL_VERSION,
                    msg_type,
                    seq_id,
                    part_index: i as u16,
                    total_parts,
                    payload_len: slice.len() as u16,
                },
                data: slice.to_vec(),
                checksum: [0; 4],
            };
            // compute checksum
            let bytes = chunk.encode_bytes();
            chunk.checksum.copy_from_slice(&bytes[bytes.len() - 4..]);
            chunk
        })
        .collect())
}

pub struct Reassembler {
    pending: HashMap<u32, (MsgType, u16, HashMap<u16, Vec<u8>>)>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    pub fn add_chunk(&mut self, chunk: KpagChunk) -> Result<Option<(MsgType, u32, Vec<u8>)>, String> {
        let seq = chunk.header.seq_id;
        let total = chunk.header.total_parts;
        let idx = chunk.header.part_index;
        let mtype = chunk.header.msg_type;
        if total == 0 || total as usize > MAX_QR_PARTS || idx >= total || chunk.data.len() > MAX_QR_CHUNK_SIZE || chunk.header.payload_len as usize != chunk.data.len() {
            return Err("Invalid QR chunk metadata".into());
        }
        if !self.pending.contains_key(&seq) && self.pending.len() >= MAX_PENDING_SEQUENCES {
            return Err("Too many pending QR sequences".into());
        }

        let entry = self
            .pending
            .entry(seq)
            .or_insert_with(|| (mtype, total, HashMap::new()));

        if entry.1 != total || entry.0 != mtype {
            return Err(format!(
                "Inconsistent chunk metadata for sequence ID {}",
                seq
            ));
        }

        if let Some(previous) = entry.2.get(&idx) {
            if previous != &chunk.data {
                return Err("Conflicting duplicate QR part".into());
            }
        } else {
            let current_size: usize = entry.2.values().map(Vec::len).sum();
            if current_size + chunk.data.len() > MAX_QR_MESSAGE_SIZE {
                return Err("Reassembled QR message exceeds size limit".into());
            }
            entry.2.insert(idx, chunk.data);
        }

        if entry.2.len() == total as usize {
            let mut full_payload = Vec::new();
            for i in 0..total {
                if let Some(part) = entry.2.get(&i) {
                    full_payload.extend_from_slice(part);
                } else {
                    return Err(format!("Missing chunk {} for sequence {}", i, seq));
                }
            }
            self.pending.remove(&seq);
            Ok(Some((mtype, seq, full_payload)))
        } else {
            Ok(None)
        }
    }

    pub fn progress(&self, seq_id: u32) -> Option<(usize, usize)> {
        self.pending.get(&seq_id).map(|(_, total, parts)| (parts.len(), *total as usize))
    }
}

pub fn render_qr_terminal(content: &str) -> Result<String, String> {
    use qrcode::QrCode;
    use qrcode::render::unicode::Dense1x2;
    let code = QrCode::new(content.as_bytes()).map_err(|e| format!("QR generation error: {}", e))?;
    let string = code
        .render::<Dense1x2>()
        .quiet_zone(true)
        .build();
    Ok(string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_encode_decode() {
        let data = b"Sphinx packet payload 1024 bytes dummy test";
        let chunks = fragment_payload(MsgType::SphinxOut, 42, data, 16).unwrap();
        assert_eq!(chunks.len(), 3);

        let mut reassembler = Reassembler::new();
        let mut completed = None;

        for chunk in chunks {
            let encoded = chunk.encode_bytes();
            let decoded = KpagChunk::decode_bytes(&encoded).unwrap();
            if let Some(res) = reassembler.add_chunk(decoded).unwrap() {
                completed = Some(res);
            }
        }

        let (mtype, seq, reassembled) = completed.expect("Should reassemble");
        assert_eq!(mtype, MsgType::SphinxOut);
        assert_eq!(seq, 42);
        assert_eq!(reassembled, data);
    }

    #[test]
    fn qr_limits_and_conflicting_parts() {
        assert!(fragment_payload(MsgType::SphinxOut, 1, b"x", 0).is_err());
        assert!(fragment_payload(MsgType::SphinxOut, 1, &vec![0; MAX_QR_MESSAGE_SIZE + 1], 90).is_err());
        assert!(fragment_payload(MsgType::SphinxOut, 1, &vec![0; 300], 1).is_err());
        let parts = fragment_payload(MsgType::SphinxOut, 7, b"abcd", 2).unwrap();
        let mut reassembler = Reassembler::new();
        assert!(reassembler.add_chunk(parts[0].clone()).unwrap().is_none());
        let mut changed = parts[0].clone();
        changed.data[0] ^= 1;
        assert!(reassembler.add_chunk(changed).is_err());
        assert!(reassembler.add_chunk(parts[1].clone()).unwrap().is_some());
        let mut invalid = parts[0].clone();
        invalid.header.part_index = invalid.header.total_parts;
        assert!(KpagChunk::decode_bytes(&invalid.encode_bytes()).is_err());
        let mut pending = Reassembler::new();
        for seq in 0..MAX_PENDING_SEQUENCES as u32 {
            let first = fragment_payload(MsgType::SphinxOut, seq, b"xy", 1).unwrap().remove(0);
            assert!(pending.add_chunk(first).unwrap().is_none());
        }
        let extra = fragment_payload(MsgType::SphinxOut, 999, b"xy", 1).unwrap().remove(0);
        assert!(pending.add_chunk(extra).is_err());
    }
}
