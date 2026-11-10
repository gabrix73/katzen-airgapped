//! Acoustic out-of-band data transmission module using ggwave FSK audio modulation.
//!
//! Provides sound-based communication between air-gapped nodes (e.g. `katzen-cold` speaker)
//! and networked relays (e.g. `katzen-hot` microphone) as a resilient alternative to optical
//! QR codes on hardware lacking cameras or displays.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{FromSample, SampleFormat, SizedSample};
use ggwave::{Decoder, Encoder, Parameters, Protocol, MAX_LENGTH_VARIABLE};

use crate::{fragment_payload, KpagChunk, MsgType, Reassembler};

/// Default payload data length per audio chunk (excluding 20 bytes of header/checksum).
/// 64 + 20 = 84 bytes total on the wire, well below ggwave's 140-byte variable limit.
pub const DEFAULT_AUDIO_CHUNK_SIZE: usize = 64;

/// Default transmission volume (peaks at 25% full scale, audible for near-field desk use).
pub const DEFAULT_AUDIO_VOLUME: u8 = 25;

/// Default timeout when listening for an incoming audio chunk.
pub const DEFAULT_LISTEN_TIMEOUT: Duration = Duration::from_secs(15);

/// Constructs ggwave parameters tuned for sample rate `fs` with variable-length payloads.
pub fn audio_params(fs: u32) -> Parameters {
    Parameters {
        sample_rate_inp: fs as f32,
        sample_rate_out: fs as f32,
        ..Parameters::default()
    }
}

/// Encodes a `KpagChunk` into audio waveform samples (`f32`) at sample rate `fs`.
pub fn encode_chunk_to_samples(
    chunk: &KpagChunk,
    protocol: Protocol,
    volume: u8,
    fs: u32,
) -> Result<Vec<f32>, String> {
    let wire_bytes = chunk.encode_bytes();
    if wire_bytes.len() > MAX_LENGTH_VARIABLE {
        return Err(format!(
            "Chunk wire size {} exceeds ggwave maximum {}",
            wire_bytes.len(),
            MAX_LENGTH_VARIABLE
        ));
    }

    let encoder = Encoder::new(audio_params(fs))
        .map_err(|e| format!("ggwave encoder init failed: {}", e))?;
    let tones = encoder
        .encode(&wire_bytes, protocol, volume)
        .map_err(|e| format!("ggwave encode failed at {} Hz: {}", fs, e))?;

    // Add 0.1s leading silence and 0.2s trailing silence to let DAC settle
    let lead_samples = (fs as usize) / 10;
    let trail_samples = (fs as usize) / 5;
    let mut out = Vec::with_capacity(lead_samples + tones.len() + trail_samples);
    out.resize(lead_samples, 0.0f32);
    out.extend(tones);
    out.resize(out.len() + trail_samples, 0.0f32);
    Ok(out)
}

/// Decodes audio waveform samples (`f32`) at sample rate `fs` into a `KpagChunk` if recognized.
pub fn decode_chunk_from_samples(
    samples: &[f32],
    protocol: Protocol,
    fs: u32,
) -> Result<Option<KpagChunk>, String> {
    let mut decoder = Decoder::with_protocols(audio_params(fs), &[protocol])
        .map_err(|e| format!("ggwave decoder init failed: {}", e))?;

    if let Some(payload) = decoder.push(samples) {
        let chunk = KpagChunk::decode_bytes(&payload)
            .map_err(|e| format!("Decoded audio payload is not a valid KPAG chunk: {}", e))?;
        Ok(Some(chunk))
    } else {
        Ok(None)
    }
}

/// Helper to play audio samples on the default system speaker.
pub fn play_samples(samples: &[f32]) -> Result<(), String> {
    let host = cpal::default_host();
    let dev = host
        .default_output_device()
        .ok_or_else(|| "No audio output device found".to_string())?;
    let cfg = dev
        .default_output_config()
        .map_err(|e| format!("Failed to get default output config: {}", e))?;

    let format = cfg.sample_format();
    let stream_cfg = cfg.config();
    let clip = Arc::new(samples.to_vec());
    let at = Arc::new(AtomicUsize::new(0));

    let stream = match format {
        SampleFormat::F32 => build_play_stream::<f32>(&dev, &stream_cfg, clip.clone(), at.clone()),
        SampleFormat::I16 => build_play_stream::<i16>(&dev, &stream_cfg, clip.clone(), at.clone()),
        SampleFormat::U16 => build_play_stream::<u16>(&dev, &stream_cfg, clip.clone(), at.clone()),
        SampleFormat::I32 => build_play_stream::<i32>(&dev, &stream_cfg, clip.clone(), at.clone()),
        f => return Err(format!("Unsupported output sample format: {:?}", f)),
    }?;

    stream
        .play()
        .map_err(|e| format!("Failed to start playback stream: {}", e))?;

    let fs = stream_cfg.sample_rate.max(1);
    let total_samples = clip.len();
    let playback_duration = Duration::from_secs_f64((total_samples as f64) / (fs as f64));
    let timeout = Instant::now() + playback_duration + Duration::from_secs(2);

    while at.load(Ordering::Relaxed) < total_samples {
        if Instant::now() > timeout {
            return Err("Audio playback timed out".to_string());
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    Ok(())
}

fn build_play_stream<T: SizedSample + FromSample<f32>>(
    dev: &cpal::Device,
    cfg: &cpal::StreamConfig,
    clip: Arc<Vec<f32>>,
    at: Arc<AtomicUsize>,
) -> Result<cpal::Stream, String> {
    let channels = cfg.channels.max(1) as usize;
    dev.build_output_stream(
        cfg,
        move |data: &mut [T], _| {
            for frame in data.chunks_mut(channels) {
                let idx = at.fetch_add(1, Ordering::Relaxed);
                let val = clip.get(idx).copied().unwrap_or(0.0);
                frame.fill(T::from_sample(val));
            }
        },
        |err| eprintln!("Audio speaker error: {}", err),
        None,
    )
    .map_err(|e| format!("Failed to build output stream: {}", e))
}

/// Transmits a single `KpagChunk` over sound using the default audio output device.
pub fn transmit_chunk(chunk: &KpagChunk, protocol: Protocol, volume: u8) -> Result<(), String> {
    let host = cpal::default_host();
    let dev = host
        .default_output_device()
        .ok_or_else(|| "No audio output device found".to_string())?;
    let cfg = dev
        .default_output_config()
        .map_err(|e| format!("Failed to get audio output config: {}", e))?;
    let fs = cfg.sample_rate();

    let samples = encode_chunk_to_samples(chunk, protocol, volume, fs)?;
    play_samples(&samples)
}

/// Listens on the default microphone for a single `KpagChunk` up to `timeout`.
pub fn listen_for_chunk(protocol: Protocol, timeout: Duration) -> Result<KpagChunk, String> {
    let host = cpal::default_host();
    let dev = host
        .default_input_device()
        .ok_or_else(|| "No audio microphone device found".to_string())?;
    let cfg = dev
        .default_input_config()
        .map_err(|e| format!("Failed to get audio input config: {}", e))?;

    let fs = cfg.sample_rate();
    let format = cfg.sample_format();
    let stream_cfg = cfg.config();

    let heard = Arc::new(Mutex::new(Vec::<f32>::new()));
    let stream = match format {
        SampleFormat::F32 => build_record_stream::<f32>(&dev, &stream_cfg, heard.clone()),
        SampleFormat::I16 => build_record_stream::<i16>(&dev, &stream_cfg, heard.clone()),
        SampleFormat::U16 => build_record_stream::<u16>(&dev, &stream_cfg, heard.clone()),
        SampleFormat::I32 => build_record_stream::<i32>(&dev, &stream_cfg, heard.clone()),
        f => return Err(format!("Unsupported input sample format: {:?}", f)),
    }?;

    stream
        .play()
        .map_err(|e| format!("Failed to start microphone stream: {}", e))?;

    let mut decoder = Decoder::with_protocols(audio_params(fs), &[protocol])
        .map_err(|e| format!("Decoder init failed: {}", e))?;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        let chunk_data = {
            let mut guard = heard
                .lock()
                .map_err(|_| "Microphone buffer poisoned".to_string())?;
            std::mem::take(&mut *guard)
        };

        if !chunk_data.is_empty() {
            if let Some(payload) = decoder.push(&chunk_data) {
                let chunk = KpagChunk::decode_bytes(&payload)
                    .map_err(|e| format!("Decoded payload corrupted: {}", e))?;
                return Ok(chunk);
            }
        }
    }

    Err(format!(
        "Timed out after {}s waiting for audio chunk",
        timeout.as_secs()
    ))
}

fn build_record_stream<T: SizedSample>(
    dev: &cpal::Device,
    cfg: &cpal::StreamConfig,
    heard: Arc<Mutex<Vec<f32>>>,
) -> Result<cpal::Stream, String>
where
    f32: FromSample<T>,
{
    let channels = cfg.channels.max(1) as usize;
    let max_buffer = (cfg.sample_rate as usize) * 4; // Bound buffer to at most 4 seconds of audio

    dev.build_input_stream(
        cfg,
        move |data: &[T], _| {
            if let Ok(mut h) = heard.lock() {
                if h.len() < max_buffer {
                    h.extend(data.chunks(channels).map(|frame| frame[0].to_sample::<f32>()));
                }
            }
        },
        |err| eprintln!("Audio microphone error: {}", err),
        None,
    )
    .map_err(|e| format!("Failed to build input stream: {}", e))
}

/// Transmits an entire message over sound by fragmenting into chunks and broadcasting sequentially.
pub fn transmit_message(
    msg_type: MsgType,
    seq_id: u32,
    payload: &[u8],
    chunk_size: usize,
    protocol: Protocol,
    volume: u8,
    delay_ms: u64,
) -> Result<(), String> {
    let chunks = fragment_payload(msg_type, seq_id, payload, chunk_size)?;
    let total = chunks.len();

    for (idx, chunk) in chunks.iter().enumerate() {
        println!(
            "[Acoustic TX] Broadcasting audio frame {}/{} (seq {}) via {:?}",
            idx + 1,
            total,
            seq_id,
            protocol
        );
        transmit_chunk(chunk, protocol, volume)?;
        if idx + 1 < total && delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }

    Ok(())
}

/// Listens on the microphone and reassembles incoming audio chunks into a complete message.
pub fn listen_for_message(
    protocol: Protocol,
    chunk_timeout: Duration,
) -> Result<(MsgType, u32, Vec<u8>), String> {
    let mut reassembler = Reassembler::new();
    println!(
        "[Acoustic RX] Listening on microphone for audio air-gap transmission ({:?})...",
        protocol
    );

    loop {
        let chunk = listen_for_chunk(protocol, chunk_timeout)?;
        println!(
            "[Acoustic RX] Heard chunk {}/{} (seq: {}, type: {:?})",
            chunk.header.part_index + 1,
            chunk.header.total_parts,
            chunk.header.seq_id,
            chunk.header.msg_type
        );

        if let Some((msg_type, seq_id, payload)) = reassembler.add_chunk(chunk)? {
            println!(
                "[Acoustic RX] Successfully reassembled complete message (seq {}, len {} bytes)",
                seq_id,
                payload.len()
            );
            return Ok((msg_type, seq_id, payload));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_chunk_encode_decode_roundtrip() {
        let chunk = KpagChunk {
            header: crate::KpagHeader {
                magic: crate::MAGIC,
                version: crate::PROTOCOL_VERSION,
                msg_type: MsgType::SphinxOut,
                seq_id: 42,
                part_index: 0,
                total_parts: 1,
                payload_len: 24,
            },
            data: b"Airgapped ggwave acoustic test".to_vec(),
            checksum: [0u8; 4],
        };

        let fs = 48000;
        let protocol = Protocol::AudibleFast;
        let samples = encode_chunk_to_samples(&chunk, protocol, 50, fs)
            .expect("Failed to encode chunk to samples");

        assert!(!samples.is_empty(), "Encoded audio samples cannot be empty");

        let decoded_chunk = decode_chunk_from_samples(&samples, protocol, fs)
            .expect("Failed to decode chunk from samples")
            .expect("Expected a chunk to be decoded from valid audio");

        assert_eq!(decoded_chunk.header.magic, chunk.header.magic);
        assert_eq!(decoded_chunk.header.msg_type, MsgType::SphinxOut);
        assert_eq!(decoded_chunk.header.seq_id, 42);
        assert_eq!(decoded_chunk.header.part_index, 0);
        assert_eq!(decoded_chunk.header.total_parts, 1);
        assert_eq!(decoded_chunk.data, chunk.data);
    }

    #[test]
    fn test_audio_multichunk_fragmentation_and_reassembly() {
        let payload = b"Sphinx packet payload transferred over physical sound waves without cameras or USB!"
            .to_vec();
        let chunks = fragment_payload(MsgType::PigeonholeDeposit, 999, &payload, DEFAULT_AUDIO_CHUNK_SIZE)
            .expect("Fragmentation failed");

        assert!(chunks.len() >= 2, "Payload should span at least 2 chunks");

        let fs = 48000;
        let protocol = Protocol::AudibleFast;
        let mut reassembler = Reassembler::new();
        let mut completed = None;

        for chunk in &chunks {
            let samples = encode_chunk_to_samples(chunk, protocol, 30, fs).unwrap();
            let decoded = decode_chunk_from_samples(&samples, protocol, fs)
                .unwrap()
                .expect("Chunk should decode");
            if let Some(msg) = reassembler.add_chunk(decoded).unwrap() {
                completed = Some(msg);
            }
        }

        let (msg_type, seq_id, recovered_payload) =
            completed.expect("Message should be successfully reassembled");
        assert_eq!(msg_type, MsgType::PigeonholeDeposit);
        assert_eq!(seq_id, 999);
        assert_eq!(recovered_payload, payload);
    }
}
