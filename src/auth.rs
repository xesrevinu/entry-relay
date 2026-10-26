use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const LABEL: &[u8] = b"EXPERIMENTAL entry-relay";
pub const FRAME_LEN: usize = 1 + 8 + 32;
pub const PURPOSE_OPEN: u8 = 1;
pub const PURPOSE_PING: u8 = 2;
/// One TLS session, then many upstream streams inside it.
pub const PURPOSE_MUX: u8 = 3;
/// Mux protocol v2 (per-stream credit). Old relays answer it with the decoy.
pub const PURPOSE_MUX2: u8 = 4;
pub const STATUS_OK: u8 = 0;
pub const STATUS_QUOTA: u8 = 2;
pub const STATUS_UPSTREAM: u8 = 3;

type HmacSha256 = Hmac<Sha256>;

pub const DECOY: &[u8] = b"\
HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Connection: close\r\n\
Cache-Control: no-store\r\n\
Content-Length: 79\r\n\
\r\n\
<!doctype html><html><head><title>OK</title></head><body><p>ok</p></body></html>\n";

pub fn frame(psk: &[u8], exporter: &[u8], purpose: u8, now: u64) -> [u8; FRAME_LEN] {
    let mut mac = HmacSha256::new_from_slice(psk).expect("hmac accepts any key length");
    mac.update(exporter);
    mac.update(&[purpose]);
    mac.update(&now.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; FRAME_LEN];
    out[0] = purpose;
    out[1..9].copy_from_slice(&now.to_be_bytes());
    out[9..].copy_from_slice(&tag);
    out
}

pub fn verify(psk: &[u8], exporter: &[u8], frame: &[u8], now: u64, skew: u64) -> Result<u8, ()> {
    if frame.len() != FRAME_LEN {
        return Err(());
    }
    let purpose = frame[0];
    if purpose != PURPOSE_OPEN && purpose != PURPOSE_PING && purpose != PURPOSE_MUX && purpose != PURPOSE_MUX2 {
        return Err(());
    }
    let mut ts_buf = [0u8; 8];
    ts_buf.copy_from_slice(&frame[1..9]);
    let ts = u64::from_be_bytes(ts_buf);
    let delta = now.abs_diff(ts);
    if delta > skew {
        return Err(());
    }
    let mut mac = HmacSha256::new_from_slice(psk).map_err(|_| ())?;
    mac.update(exporter);
    mac.update(&[purpose]);
    mac.update(&ts.to_be_bytes());
    mac.verify_slice(&frame[9..]).map_err(|_| ())?;
    Ok(purpose)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let psk = b"test-psk";
        let exporter = [7u8; 32];
        let now = 1_700_000_000;
        let frame = frame(psk, &exporter, PURPOSE_OPEN, now);
        assert_eq!(verify(psk, &exporter, &frame, now, 120), Ok(PURPOSE_OPEN));
    }

    #[test]
    fn rejects_wrong_key_and_stale_time() {
        let exporter = [7u8; 32];
        let now = 1_700_000_000;
        let frame = frame(b"right", &exporter, PURPOSE_PING, now);
        assert!(verify(b"wrong", &exporter, &frame, now, 120).is_err());
        assert!(verify(b"right", &exporter, &frame, now + 10_000, 120).is_err());
    }
}
