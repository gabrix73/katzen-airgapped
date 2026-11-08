use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::pigeonhole::portable_root_dir;
use crate::sandbox::is_network_blocked;

/// RFC 7693 BLAKE2b-256 implementation for computing Katzenpost ServiceNode IdentityKey hashes
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(h);
        v[8..16].copy_from_slice(&IV);
        v[12] ^= t as u64;
        v[13] ^= (t >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    let mut h = IV;
    // Parameter block: fanout=1, depth=1, digest_length=32 (0x01010020)
    h[0] ^= 0x01010020;

    let mut offset = 0usize;
    let total = input.len();

    while total - offset > 128 {
        let block: &[u8; 128] = input[offset..offset + 128].try_into().unwrap();
        offset += 128;
        compress(&mut h, block, offset as u128, false);
    }

    let mut final_block = [0u8; 128];
    let rem = total - offset;
    final_block[..rem].copy_from_slice(&input[offset..]);
    compress(&mut h, &final_block, total as u128, true);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

/// Minimal RFC 8949 CBOR AST for communicating with kpclientd thin-client IPC
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    UInt(u64),
    NegInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl CborValue {
    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            CborValue::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&CborValue> {
        let map = self.as_map()?;
        for (k, v) in map {
            if let CborValue::Text(s) = k {
                if s == key {
                    return Some(v);
                }
            }
        }
        None
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            CborValue::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            CborValue::UInt(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            CborValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[CborValue]> {
        match self {
            CborValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn write_type_and_len(out: &mut Vec<u8>, major: u8, len: u64) {
        let mt = major << 5;
        if len < 24 {
            out.push(mt | (len as u8));
        } else if len <= 0xff {
            out.push(mt | 24);
            out.push(len as u8);
        } else if len <= 0xffff {
            out.push(mt | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else if len <= 0xffff_ffff {
            out.push(mt | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            out.push(mt | 27);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            CborValue::UInt(n) => Self::write_type_and_len(out, 0, *n),
            CborValue::NegInt(n) => {
                let val = (-1 - *n) as u64;
                Self::write_type_and_len(out, 1, val);
            }
            CborValue::Bytes(b) => {
                Self::write_type_and_len(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            CborValue::Text(s) => {
                let b = s.as_bytes();
                Self::write_type_and_len(out, 3, b.len() as u64);
                out.extend_from_slice(b);
            }
            CborValue::Array(items) => {
                Self::write_type_and_len(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            CborValue::Map(entries) => {
                Self::write_type_and_len(out, 5, entries.len() as u64);
                for (k, v) in entries {
                    k.encode_into(out);
                    v.encode_into(out);
                }
            }
            CborValue::Bool(false) => out.push(0xf4),
            CborValue::Bool(true) => out.push(0xf5),
            CborValue::Null => out.push(0xf6),
            CborValue::Float(f) => {
                out.push(0xfb);
                out.extend_from_slice(&f.to_bits().to_be_bytes());
            }
        }
    }

    pub fn decode(data: &[u8]) -> Result<CborValue, String> {
        if data.len() > 16 * 1024 * 1024 {
            return Err("CBOR value exceeds size limit".into());
        }
        let mut pos = 0;
        let mut budget = 100_000usize;
        let value = Self::decode_at(data, &mut pos, 0, &mut budget)?;
        if pos != data.len() {
            return Err("Trailing data after CBOR value".into());
        }
        Ok(value)
    }

    fn read_len(data: &[u8], pos: &mut usize, ai: u8) -> Result<Option<u64>, String> {
        match ai {
            0..=23 => Ok(Some(ai as u64)),
            24 => {
                if *pos >= data.len() {
                    return Err("Unexpected EOF reading 1-byte length".into());
                }
                let v = data[*pos] as u64;
                *pos += 1;
                Ok(Some(v))
            }
            25 => {
                if *pos + 2 > data.len() {
                    return Err("Unexpected EOF reading 2-byte length".into());
                }
                let v = u16::from_be_bytes(data[*pos..*pos + 2].try_into().unwrap()) as u64;
                *pos += 2;
                Ok(Some(v))
            }
            26 => {
                if *pos + 4 > data.len() {
                    return Err("Unexpected EOF reading 4-byte length".into());
                }
                let v = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap()) as u64;
                *pos += 4;
                Ok(Some(v))
            }
            27 => {
                if *pos + 8 > data.len() {
                    return Err("Unexpected EOF reading 8-byte length".into());
                }
                let v = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
                *pos += 8;
                Ok(Some(v))
            }
            31 => Ok(None), // Indefinite length
            _ => Err(format!("Unsupported CBOR additional info: {}", ai)),
        }
    }

    fn consume_break(data: &[u8], pos: &mut usize) -> Result<(), String> {
        if data.get(*pos) != Some(&0xff) {
            return Err("Missing CBOR indefinite-length terminator".into());
        }
        *pos += 1;
        Ok(())
    }

    fn decode_at(data: &[u8], pos: &mut usize, depth: usize, budget: &mut usize) -> Result<CborValue, String> {
        if depth > 32 || *budget == 0 {
            return Err("CBOR nesting or item limit exceeded".into());
        }
        *budget -= 1;
        if *pos >= data.len() {
            return Err("Unexpected EOF in CBOR decode".into());
        }
        let initial = data[*pos];
        *pos += 1;
        let major = initial >> 5;
        let ai = initial & 0x1f;

        match major {
            0 => {
                let n = Self::read_len(data, pos, ai)?.ok_or("Indefinite uint invalid")?;
                Ok(CborValue::UInt(n))
            }
            1 => {
                let n = Self::read_len(data, pos, ai)?.ok_or("Indefinite negint invalid")?;
                if n > i64::MAX as u64 {
                    return Err("CBOR negative integer exceeds supported range".into());
                }
                Ok(CborValue::NegInt(-1 - (n as i64)))
            }
            2 => {
                if let Some(len) = Self::read_len(data, pos, ai)? {
                    let l = usize::try_from(len).map_err(|_| "CBOR byte length overflow")?;
                    if *pos + l > data.len() {
                        return Err("Unexpected EOF in CBOR bytes".into());
                    }
                    let b = data[*pos..*pos + l].to_vec();
                    *pos += l;
                    Ok(CborValue::Bytes(b))
                } else {
                    let mut buf = Vec::new();
                    while *pos < data.len() && data[*pos] != 0xff {
                        if let CborValue::Bytes(chunk) = Self::decode_at(data, pos, depth + 1, budget)? {
                            buf.extend_from_slice(&chunk);
                        } else {
                            return Err("Expected byte chunk in indefinite bytes".into());
                        }
                    }
                    Self::consume_break(data, pos)?;
                    Ok(CborValue::Bytes(buf))
                }
            }
            3 => {
                if let Some(len) = Self::read_len(data, pos, ai)? {
                    let l = usize::try_from(len).map_err(|_| "CBOR text length overflow")?;
                    if *pos + l > data.len() {
                        return Err("Unexpected EOF in CBOR text".into());
                    }
                    let s = std::str::from_utf8(&data[*pos..*pos + l])
                        .map_err(|_| "Invalid UTF-8 in CBOR text")?.to_string();
                    *pos += l;
                    Ok(CborValue::Text(s))
                } else {
                    let mut s = String::new();
                    while *pos < data.len() && data[*pos] != 0xff {
                        if let CborValue::Text(chunk) = Self::decode_at(data, pos, depth + 1, budget)? {
                            s.push_str(&chunk);
                        } else {
                            return Err("Expected text chunk in indefinite text".into());
                        }
                    }
                    Self::consume_break(data, pos)?;
                    Ok(CborValue::Text(s))
                }
            }
            4 => {
                let mut arr = Vec::new();
                if let Some(len) = Self::read_len(data, pos, ai)? {
                    for _ in 0..len {
                        arr.push(Self::decode_at(data, pos, depth + 1, budget)?);
                    }
                } else {
                    while *pos < data.len() && data[*pos] != 0xff {
                        arr.push(Self::decode_at(data, pos, depth + 1, budget)?);
                    }
                    Self::consume_break(data, pos)?;
                }
                Ok(CborValue::Array(arr))
            }
            5 => {
                let mut map = Vec::new();
                if let Some(len) = Self::read_len(data, pos, ai)? {
                    for _ in 0..len {
                        let k = Self::decode_at(data, pos, depth + 1, budget)?;
                        let v = Self::decode_at(data, pos, depth + 1, budget)?;
                        map.push((k, v));
                    }
                } else {
                    while *pos < data.len() && data[*pos] != 0xff {
                        let k = Self::decode_at(data, pos, depth + 1, budget)?;
                        let v = Self::decode_at(data, pos, depth + 1, budget)?;
                        map.push((k, v));
                    }
                    Self::consume_break(data, pos)?;
                }
                Ok(CborValue::Map(map))
            }
            6 => {
                let _tag = Self::read_len(data, pos, ai)?.ok_or("Indefinite CBOR tag invalid")?;
                Self::decode_at(data, pos, depth + 1, budget)
            }
            7 => match ai {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 | 23 => Ok(CborValue::Null),
                24 => {
                    if *pos >= data.len() { return Err("Unexpected EOF in CBOR simple value".into()); }
                    *pos += 1;
                    Ok(CborValue::Null)
                }
                25 => {
                    if *pos + 2 > data.len() { return Err("Unexpected EOF in CBOR float16".into()); }
                    *pos += 2;
                    Ok(CborValue::Float(0.0))
                }
                26 => {
                    if *pos + 4 > data.len() {
                        return Err("Unexpected EOF in float32".into());
                    }
                    let bits = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
                    *pos += 4;
                    Ok(CborValue::Float(f32::from_bits(bits) as f64))
                }
                27 => {
                    if *pos + 8 > data.len() {
                        return Err("Unexpected EOF in float64".into());
                    }
                    let bits = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
                    *pos += 8;
                    Ok(CborValue::Float(f64::from_bits(bits)))
                }
                _ => Err("Unsupported CBOR simple value".into()),
            },
            _ => Err("Invalid CBOR major type".into()),
        }
    }
}

/// Receipt returned when kpclientd dispatches a packet over the live Katzenpost mixnet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixnetDeliveryReceipt {
    pub epoch: u64,
    pub destination_service: String,
    pub destination_node_hex: String,
    pub forward_route: Vec<String>,
    pub return_route: Vec<String>,
    pub reply_eta_ms: u64,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn send_cbor_frame(stream: &mut dyn ReadWrite, val: &CborValue) -> Result<(), String> {
    let raw = val.encode();
    let len_prefix = (raw.len() as u32).to_be_bytes();
    stream
        .write_all(&len_prefix)
        .map_err(|e| format!("Failed writing frame length: {}", e))?;
    stream
        .write_all(&raw)
        .map_err(|e| format!("Failed writing frame payload: {}", e))?;
    stream.flush().map_err(|e| format!("Flush error: {}", e))?;
    Ok(())
}

fn recv_cbor_frame(stream: &mut dyn ReadWrite) -> Result<CborValue, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("Socket read length error: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(format!("CBOR frame too large: {} bytes", len));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("Socket read payload error: {}", e))?;
    CborValue::decode(&payload)
}

fn parse_local_daemon_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    let parsed: std::net::SocketAddr = addr.parse()
        .map_err(|_| "Daemon TCP address must be a numeric loopback IP and port".to_string())?;
    if !parsed.ip().is_loopback() {
        return Err("Remote TCP daemon endpoints are disabled: use a local authenticated socket".into());
    }
    Ok(parsed)
}

/// Try to open a socket connection to kpclientd (supports @katzenpost abstract socket, filesystem socket, or TCP)
fn connect_daemon_stream(
    socket_path: &Path,
    tcp_addr: Option<&str>,
) -> Result<(Box<dyn ReadWrite>, String), String> {
    let sock_str = socket_path.to_string_lossy();

    // 1. If user specified an explicit @abstract socket
    #[cfg(target_os = "linux")]
    if let Some(abstract_name) = sock_str.strip_prefix('@') {
        if let Ok(addr) = SocketAddr::from_abstract_name(abstract_name.as_bytes()) {
            if let Ok(stream) = UnixStream::connect_addr(&addr) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                return Ok((Box::new(stream), format!("unix:@{}", abstract_name)));
            }
        }
    }

    // 2. If filesystem socket exists
    if socket_path.exists() {
        if let Ok(stream) = UnixStream::connect(socket_path) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            return Ok((Box::new(stream), format!("unix:{}", sock_str)));
        }
    }

    // 3. Try Linux abstract socket @katzenpost automatically (default in kpclientd client.toml)
    #[cfg(target_os = "linux")]
    if let Ok(addr) = SocketAddr::from_abstract_name(b"katzenpost") {
        if let Ok(stream) = UnixStream::connect_addr(&addr) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            return Ok((Box::new(stream), "unix:@katzenpost".to_string()));
        }
    }

    // 4. Try portable spool socket <portable_root>/spool/kpclientd.sock
    let portable_sock = portable_root_dir().join("spool").join("kpclientd.sock");
    if portable_sock.exists() {
        if let Ok(stream) = UnixStream::connect(&portable_sock) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            return Ok((
                Box::new(stream),
                format!("unix:{}", portable_sock.display()),
            ));
        }
    }

    // 5. Try TCP if specified
    if let Some(addr) = tcp_addr {
        let local_addr = parse_local_daemon_addr(addr)?;
        if let Ok(stream) = TcpStream::connect_timeout(&local_addr, Duration::from_secs(5)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            return Ok((Box::new(stream), format!("tcp://{}", addr)));
        }
    }

    Err("No active kpclientd daemon socket found".into())
}

/// Find bundled kpclientd binary and client.toml on the portable USB / project directory
pub fn find_bundled_kpclientd() -> Option<(PathBuf, PathBuf)> {
    let root = portable_root_dir();
    let bin_candidates = [
        root.join("bin").join("kpclientd"),
        root.join("kpclientd"),
        PathBuf::from("/home/gabriel1/.codex/work/katzenpost-kpclientd-namenlos/kpclientd"),
    ];
    let cfg_candidates = [
        root.join("config").join("client.toml"),
        root.join("client.toml"),
        PathBuf::from("/home/gabriel1/.codex/work/katzenqt-namenlos/config/client.toml"),
    ];

    let bin = bin_candidates.into_iter().find(|p| p.exists())?;
    let cfg = cfg_candidates.into_iter().find(|p| p.exists())?;
    Some((bin, cfg))
}

/// Automatically start portable kpclientd from the USB stick if host has network access
pub fn try_autostart_portable_kpclientd() -> Result<(), String> {
    if is_network_blocked() {
        return Err("Host is network-isolated (air-gapped)".into());
    }

    let (bin_path, cfg_path) = find_bundled_kpclientd().ok_or_else(|| {
        format!(
            "Bundled kpclientd not found in {}/bin/kpclientd",
            portable_root_dir().display()
        )
    })?;

    let spool_dir = portable_root_dir().join("spool");
    let _ = fs::create_dir_all(&spool_dir);
    let log_path = spool_dir.join("kpclientd.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("Failed opening kpclientd log: {}", e))?;
    let err_file = log_file
        .try_clone()
        .map_err(|e| format!("Failed cloning log handle: {}", e))?;

    println!(
        "[*] Auto-starting portable kpclientd from USB bundle ({})...",
        bin_path.display()
    );

    Command::new(&bin_path)
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .map_err(|e| format!("Failed to spawn portable kpclientd: {}", e))?;

    // Wait up to 12 seconds for @katzenpost socket to come online
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(12) {
        sleep(Duration::from_millis(400));
        if connect_daemon_stream(Path::new("@katzenpost"), None).is_ok() {
            println!("[✓] Portable kpclientd daemon online (log: {})", log_path.display());
            return Ok(());
        }
    }

    Err("Timed out waiting for portable kpclientd socket".into())
}

/// Extract (ServiceNode IdentityKey BLAKE2b-256 hash, recipient_queue_id, capability_name) from PKI CBOR
fn extract_service_from_pki(
    pki_bytes: &[u8],
    preferred_target: &str,
) -> Result<(u64, [u8; 32], Vec<u8>, String), String> {
    let doc = CborValue::decode(pki_bytes)?;
    let epoch = doc.get("Epoch").and_then(|v| v.as_u64()).unwrap_or(0);
    let service_nodes = doc
        .get("ServiceNodes")
        .and_then(|v| v.as_array())
        .ok_or("PKI document missing ServiceNodes array")?;

    let want_cap = if preferred_target.contains("echo") {
        "echo"
    } else {
        "courier"
    };

    let mut fallback: Option<([u8; 32], Vec<u8>, String)> = None;

    for raw_node in service_nodes {
        let node_bytes = match raw_node.as_bytes() {
            Some(b) => b,
            None => continue,
        };
        let node = match CborValue::decode(node_bytes) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let id_key = match node.get("IdentityKey").and_then(|v| v.as_bytes()) {
            Some(k) => k,
            None => continue,
        };
        let dest_hash = blake2b_256(id_key);

        if let Some(kaetzchen) = node.get("Kaetzchen").and_then(|v| v.as_map()) {
            for (k, v) in kaetzchen {
                if let Some(cap_name) = k.as_str() {
                    let endpoint = v
                        .get("endpoint")
                        .and_then(|e| e.as_str())
                        .unwrap_or(cap_name);
                    if cap_name == want_cap {
                        return Ok((
                            epoch,
                            dest_hash,
                            endpoint.as_bytes().to_vec(),
                            format!("{}:{}", cap_name, endpoint),
                        ));
                    }
                    if fallback.is_none() {
                        fallback = Some((
                            dest_hash,
                            endpoint.as_bytes().to_vec(),
                            format!("{}:{}", cap_name, endpoint),
                        ));
                    }
                }
            }
        }
    }

    if let Some((hash, qid, desc)) = fallback {
        return Ok((epoch, hash, qid, desc));
    }

    Err("No active ServiceNodes with Kaetzchen endpoints found in PKI document".into())
}

/// Connect to kpclientd (auto-starting from USB if needed), run the CBOR handshake, and dispatch payload
pub fn dispatch_via_kpclientd(
    payload: &[u8],
    target: &str,
    socket_path: &Path,
    tcp_addr: Option<&str>,
) -> Result<MixnetDeliveryReceipt, String> {
    let (mut stream, endpoint_label) = match connect_daemon_stream(socket_path, tcp_addr) {
        Ok(s) => s,
        Err(_) => {
            // Try auto-starting bundled kpclientd from the portable directory if online
            try_autostart_portable_kpclientd()?;
            connect_daemon_stream(socket_path, tcp_addr)?
        }
    };

    println!("[*] Connected to kpclientd via {}", endpoint_label);

    // Wait up to 15s for daemon mixnet connection + PKI document
    let mut is_connected = false;
    let mut pki_payload: Option<Vec<u8>> = None;

    // Frame 0: ConnectionStatusEvent
    let frame0 = recv_cbor_frame(&mut *stream)?;
    if let Some(status_ev) = frame0.get("connection_status_event") {
        is_connected = status_ev
            .get("is_connected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }

    // Frame 1: NewPKIDocumentEvent
    let frame1 = recv_cbor_frame(&mut *stream)?;
    if let Some(pki_ev) = frame1.get("new_pki_document_event") {
        if let Some(bytes) = pki_ev.get("payload").and_then(|v| v.as_bytes()) {
            if !bytes.is_empty() {
                pki_payload = Some(bytes.to_vec());
            }
        }
    }

    // Step 3: Send SessionToken request
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    let session_req = CborValue::Map(vec![(
        CborValue::Text("session_token".into()),
        CborValue::Map(vec![(
            CborValue::Text("client_instance_token".into()),
            CborValue::Bytes(token.to_vec()),
        )]),
    )]);
    send_cbor_frame(&mut *stream, &session_req)?;

    // Drain until session_token_reply (capturing any updated connection_status or pki_doc along the way)
    for _ in 0..8 {
        let resp = recv_cbor_frame(&mut *stream)?;
        if let Some(status_ev) = resp.get("connection_status_event") {
            if let Some(c) = status_ev.get("is_connected").and_then(|v| v.as_bool()) {
                is_connected = c;
            }
        }
        if let Some(pki_ev) = resp.get("new_pki_document_event") {
            if let Some(bytes) = pki_ev.get("payload").and_then(|v| v.as_bytes()) {
                if !bytes.is_empty() {
                    pki_payload = Some(bytes.to_vec());
                }
            }
        }
        if let Some(reply) = resp.get("session_token_reply") {
            if *reply != CborValue::Null {
                break;
            }
        }
    }

    // If daemon just started and hasn't finished fetching PKI yet, wait briefly for PKI event
    let wait_start = Instant::now();
    while (!is_connected || pki_payload.is_none()) && wait_start.elapsed() < Duration::from_secs(12)
    {
        if let Ok(resp) = recv_cbor_frame(&mut *stream) {
            if let Some(status_ev) = resp.get("connection_status_event") {
                if let Some(c) = status_ev.get("is_connected").and_then(|v| v.as_bool()) {
                    is_connected = c;
                }
            }
            if let Some(pki_ev) = resp.get("new_pki_document_event") {
                if let Some(bytes) = pki_ev.get("payload").and_then(|v| v.as_bytes()) {
                    if !bytes.is_empty() {
                        pki_payload = Some(bytes.to_vec());
                    }
                }
            }
        } else {
            break;
        }
    }

    if !is_connected {
        return Err("kpclientd daemon is running locally, but mixnet connection is currently offline".into());
    }

    let pki_bytes = pki_payload.ok_or("kpclientd has not received PKI consensus document yet")?;
    let (epoch, dest_hash, queue_id, service_desc) = extract_service_from_pki(&pki_bytes, target)?;

    // Build SendMessage request (thin client protocol)
    let mut msg_id = [0u8; 16];
    let mut surb_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut msg_id);
    rand::thread_rng().fill_bytes(&mut surb_id);

    let send_req = CborValue::Map(vec![(
        CborValue::Text("send_message".into()),
        CborValue::Map(vec![
            (
                CborValue::Text("id".into()),
                CborValue::Bytes(msg_id.to_vec()),
            ),
            (CborValue::Text("with_surb".into()), CborValue::Bool(true)),
            (
                CborValue::Text("surbid".into()),
                CborValue::Bytes(surb_id.to_vec()),
            ),
            (
                CborValue::Text("destination_id_hash".into()),
                CborValue::Bytes(dest_hash.to_vec()),
            ),
            (
                CborValue::Text("recipient_queue_id".into()),
                CborValue::Bytes(queue_id),
            ),
            (
                CborValue::Text("payload".into()),
                CborValue::Bytes(payload.to_vec()),
            ),
        ]),
    )]);

    send_cbor_frame(&mut *stream, &send_req)?;

    // Wait for MessageSentEvent confirmation from kpclientd
    for _ in 0..8 {
        let ev = recv_cbor_frame(&mut *stream)?;
        if let Some(sent_ev) = ev.get("message_sent_event") {
            if *sent_ev != CborValue::Null {
                let forward_route = sent_ev
                    .get("forward_route")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let return_route = sent_ev
                    .get("return_route")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let reply_eta_ns = sent_ev
                    .get("reply_eta")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                return Ok(MixnetDeliveryReceipt {
                    epoch,
                    destination_service: service_desc,
                    destination_node_hex: hex::encode(&dest_hash[..8]),
                    forward_route,
                    return_route,
                    reply_eta_ms: reply_eta_ns / 1_000_000,
                });
            }
        }
    }

    Err("Packet sent to kpclientd, but did not receive MessageSentEvent confirmation".into())
}

/// Receipt & Capability Token for retrieving a BACAP-encrypted Pigeonhole Box from the mixnet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PigeonholeBoxReceipt {
    pub timestamp: u64,
    pub epoch: u64,
    pub read_cap_hex: String,
    pub write_cap_hex: String,
    pub message_box_index_hex: String,
    pub next_message_box_index_hex: String,
    pub envelope_hash_hex: String,
    pub courier_node_hex: String,
}

fn cbor_rpc(
    stream: &mut dyn ReadWrite,
    req_key: &str,
    mut fields: Vec<(CborValue, CborValue)>,
) -> Result<CborValue, String> {
    let mut query_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut query_id);
    fields.insert(
        0,
        (
            CborValue::Text("query_id".into()),
            CborValue::Bytes(query_id.to_vec()),
        ),
    );
    let req = CborValue::Map(vec![(
        CborValue::Text(req_key.into()),
        CborValue::Map(fields),
    )]);
    send_cbor_frame(stream, &req)?;

    let reply_key = format!("{}_reply", req_key);
    loop {
        let ev = recv_cbor_frame(stream)?;
        if let Some(rep) = ev.get(&reply_key) {
            if *rep != CborValue::Null {
                if let Some(qid) = rep.get("query_id").and_then(|v| v.as_bytes()) {
                    if qid == query_id {
                        let err_code = rep.get("error_code").and_then(|v| v.as_u64()).unwrap_or(0);
                        if err_code != 0 {
                            return Err(format!(
                                "{} returned thin-client error code {}",
                                req_key, err_code
                            ));
                        }
                        return Ok(rep.clone());
                    }
                }
            }
        }
    }
}

fn open_and_handshake(
    socket_path: &Path,
    tcp_addr: Option<&str>,
) -> Result<(Box<dyn ReadWrite>, u64), String> {
    let (mut stream, _label) = match connect_daemon_stream(socket_path, tcp_addr) {
        Ok(s) => s,
        Err(_) => {
            try_autostart_portable_kpclientd()?;
            connect_daemon_stream(socket_path, tcp_addr)?
        }
    };

    let _f0 = recv_cbor_frame(&mut *stream)?;
    let f1 = recv_cbor_frame(&mut *stream)?;
    let mut epoch = 0u64;
    if let Some(pki_ev) = f1.get("new_pki_document_event") {
        if let Some(bytes) = pki_ev.get("payload").and_then(|v| v.as_bytes()) {
            if let Ok(doc) = CborValue::decode(bytes) {
                epoch = doc.get("Epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            }
        }
    }

    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    let session_req = CborValue::Map(vec![(
        CborValue::Text("session_token".into()),
        CborValue::Map(vec![(
            CborValue::Text("client_instance_token".into()),
            CborValue::Bytes(token.to_vec()),
        )]),
    )]);
    send_cbor_frame(&mut *stream, &session_req)?;

    for _ in 0..8 {
        let resp = recv_cbor_frame(&mut *stream)?;
        if let Some(reply) = resp.get("session_token_reply") {
            if *reply != CborValue::Null {
                break;
            }
        }
    }

    Ok((stream, epoch))
}

/// Deposit a plaintext message into a live Pigeonhole BACAP replica on the Katzenpost mixnet
pub fn deposit_pigeonhole_box(
    plaintext: &[u8],
    socket_path: &Path,
    tcp_addr: Option<&str>,
) -> Result<PigeonholeBoxReceipt, String> {
    let (mut stream, epoch) = open_and_handshake(socket_path, tcp_addr)?;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    let kp_rep = cbor_rpc(
        &mut *stream,
        "new_keypair",
        vec![(CborValue::Text("seed".into()), CborValue::Bytes(seed.to_vec()))],
    )?;

    let write_cap = kp_rep
        .get("write_cap")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing write_cap")?
        .to_vec();
    let read_cap = kp_rep
        .get("read_cap")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing read_cap")?
        .to_vec();
    let first_idx = kp_rep
        .get("first_message_index")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing first_message_index")?
        .to_vec();

    let ew_rep = cbor_rpc(
        &mut *stream,
        "encrypt_write",
        vec![
            (
                CborValue::Text("plaintext".into()),
                CborValue::Bytes(plaintext.to_vec()),
            ),
            (
                CborValue::Text("write_cap".into()),
                CborValue::Bytes(write_cap.clone()),
            ),
            (
                CborValue::Text("message_box_index".into()),
                CborValue::Bytes(first_idx.clone()),
            ),
        ],
    )?;

    let ciphertext = ew_rep
        .get("message_ciphertext")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing message_ciphertext")?
        .to_vec();
    let env_desc = ew_rep
        .get("envelope_descriptor")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing envelope_descriptor")?
        .to_vec();
    let env_hash = ew_rep
        .get("envelope_hash")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing envelope_hash")?
        .to_vec();
    let next_idx = ew_rep
        .get("next_message_box_index")
        .and_then(|v| v.as_bytes())
        .unwrap_or(&[])
        .to_vec();

    println!("[*] Storing BACAP encrypted box (2000 B) on live Pigeonhole mixnet replica (waiting for Courier ACK)...");
    let send_rep = cbor_rpc(
        &mut *stream,
        "start_resending_encrypted_message",
        vec![
            (CborValue::Text("read_cap".into()), CborValue::Null),
            (
                CborValue::Text("write_cap".into()),
                CborValue::Bytes(write_cap.clone()),
            ),
            (
                CborValue::Text("message_box_index".into()),
                CborValue::Bytes(first_idx.clone()),
            ),
            (CborValue::Text("reply_index".into()), CborValue::Null),
            (
                CborValue::Text("envelope_descriptor".into()),
                CborValue::Bytes(env_desc),
            ),
            (
                CborValue::Text("message_ciphertext".into()),
                CborValue::Bytes(ciphertext),
            ),
            (
                CborValue::Text("envelope_hash".into()),
                CborValue::Bytes(env_hash.clone()),
            ),
            (
                CborValue::Text("no_retry_on_box_id_not_found".into()),
                CborValue::Bool(false),
            ),
            (
                CborValue::Text("no_idempotent_box_already_exists".into()),
                CborValue::Bool(false),
            ),
        ],
    )?;

    let courier_hash = send_rep
        .get("courier_identity_hash")
        .and_then(|v| v.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(PigeonholeBoxReceipt {
        timestamp: ts,
        epoch,
        read_cap_hex: hex::encode(&read_cap),
        write_cap_hex: hex::encode(&write_cap),
        message_box_index_hex: hex::encode(&first_idx),
        next_message_box_index_hex: hex::encode(&next_idx),
        envelope_hash_hex: hex::encode(&env_hash),
        courier_node_hex: courier_hash,
    })
}

/// Retrieve and decrypt a message from a live Pigeonhole BACAP replica using ReadCap + MessageBoxIndex
pub fn fetch_pigeonhole_box(
    read_cap: &[u8],
    message_box_index: &[u8],
    socket_path: &Path,
    tcp_addr: Option<&str>,
) -> Result<(Vec<u8>, u64), String> {
    let (mut stream, epoch) = open_and_handshake(socket_path, tcp_addr)?;

    let er_rep = cbor_rpc(
        &mut *stream,
        "encrypt_read",
        vec![
            (
                CborValue::Text("read_cap".into()),
                CborValue::Bytes(read_cap.to_vec()),
            ),
            (
                CborValue::Text("message_box_index".into()),
                CborValue::Bytes(message_box_index.to_vec()),
            ),
        ],
    )?;

    let ciphertext = er_rep
        .get("message_ciphertext")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing message_ciphertext in encrypt_read")?
        .to_vec();
    let env_desc = er_rep
        .get("envelope_descriptor")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing envelope_descriptor in encrypt_read")?
        .to_vec();
    let env_hash = er_rep
        .get("envelope_hash")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing envelope_hash in encrypt_read")?
        .to_vec();

    println!("[*] Querying live Pigeonhole mixnet replica via anonymous SURB (waiting for mixnet roundtrip)...");
    let read_rep = cbor_rpc(
        &mut *stream,
        "start_resending_encrypted_message",
        vec![
            (
                CborValue::Text("read_cap".into()),
                CborValue::Bytes(read_cap.to_vec()),
            ),
            (CborValue::Text("write_cap".into()), CborValue::Null),
            (
                CborValue::Text("message_box_index".into()),
                CborValue::Bytes(message_box_index.to_vec()),
            ),
            (CborValue::Text("reply_index".into()), CborValue::Null),
            (
                CborValue::Text("envelope_descriptor".into()),
                CborValue::Bytes(env_desc),
            ),
            (
                CborValue::Text("message_ciphertext".into()),
                CborValue::Bytes(ciphertext),
            ),
            (
                CborValue::Text("envelope_hash".into()),
                CborValue::Bytes(env_hash),
            ),
            (
                CborValue::Text("no_retry_on_box_id_not_found".into()),
                CborValue::Bool(true),
            ),
            (
                CborValue::Text("no_idempotent_box_already_exists".into()),
                CborValue::Bool(false),
            ),
        ],
    )?;

    let plaintext = read_rep
        .get("plaintext")
        .and_then(|v| v.as_bytes())
        .ok_or("Missing plaintext in start_resending_encrypted_message_reply")?
        .to_vec();

    Ok((plaintext, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_256_vector() {
        // Empty input BLAKE2b-256 RFC vector:
        // 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
        let hash = blake2b_256(b"");
        assert_eq!(
            hex::encode(hash),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn test_cbor_roundtrip() {
        let orig = CborValue::Map(vec![
            (
                CborValue::Text("session_token".into()),
                CborValue::Bytes(vec![1, 2, 3, 4]),
            ),
            (CborValue::Text("ok".into()), CborValue::Bool(true)),
            (CborValue::Text("epoch".into()), CborValue::UInt(246936)),
        ]);
        let bytes = orig.encode();
        let decoded = CborValue::decode(&bytes).unwrap();
        assert_eq!(orig, decoded);
    }

    #[test]
    fn cbor_rejects_malformed_and_unbounded_values() {
        assert!(CborValue::decode(&[0xf6, 0xf6]).is_err());
        assert!(CborValue::decode(&[0x61, 0xff]).is_err());
        assert!(CborValue::decode(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(CborValue::decode(&[0xf8]).is_err());
        assert!(CborValue::decode(&[0xf9, 0]).is_err());
        assert!(CborValue::decode(&[0x9f, 0x01]).is_err());
        let mut nested = vec![0x81; 34];
        nested.push(0xf6);
        assert!(CborValue::decode(&nested).is_err());
    }

    #[test]
    fn daemon_tcp_requires_loopback() {
        assert!(parse_local_daemon_addr("127.0.0.1:64331").is_ok());
        assert!(parse_local_daemon_addr("[::1]:64331").is_ok());
        assert!(parse_local_daemon_addr("192.0.2.10:64331").is_err());
        assert!(parse_local_daemon_addr("example.org:64331").is_err());
    }
}
