use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const LABEL: &[u8] = b"EXPERIMENTAL entry-relay";
pub const FRAME_LEN: usize = 1 + 8 + 32;
pub const PURPOSE_OPEN: u8 = 1;
pub const PURPOSE_PING: u8 = 2;
/// One TLS session, then many upstream streams inside it.
pub const PURPOSE_MUX: u8 = 3;
/// Mux protocol v2 (per-stream credit). Older peers do not accept it.
pub const PURPOSE_MUX2: u8 = 4;
pub const STATUS_OK: u8 = 0;
pub const STATUS_QUOTA: u8 = 2;
pub const STATUS_UPSTREAM: u8 = 3;

type HmacSha256 = Hmac<Sha256>;

const PAGE: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Notes</title></head>\n<body><h1>Notes</h1><p>Nothing posted yet.</p></body>\n</html>\n";

/// Response for a plaintext HTTP request that did not authenticate.
/// Anything else gets silence, so a fixed page is not a greeting.
pub fn public_http_response(prefix: &[u8], now: SystemTime) -> Option<Vec<u8>> {
    let method = http_method(prefix)?;
    let date = http_date(now);
    let body = if method == "HEAD" { "" } else { PAGE };
    let status = if method == "GET" || method == "HEAD" { "200 OK" } else { "405 Method Not Allowed" };
    let extra = if status.starts_with("405") { "Allow: GET, HEAD\r\n" } else { "" };
    let head = format!(
        "HTTP/1.1 {status}\r\nDate: {date}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len(),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    Some(out)
}

fn http_method(prefix: &[u8]) -> Option<&'static str> {
    const METHODS: &[(&[u8], &str)] = &[
        (b"GET ", "GET"),
        (b"HEAD ", "HEAD"),
        (b"POST ", "POST"),
        (b"PUT ", "PUT"),
        (b"DELETE ", "DELETE"),
        (b"OPTIONS ", "OPTIONS"),
        (b"PATCH ", "PATCH"),
    ];
    METHODS.iter().find(|(needle, _)| prefix.starts_with(needle)).map(|(_, name)| *name)
}

fn http_date(now: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let odt = time::OffsetDateTime::from(now).replace_nanosecond(0).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let weekday = DAYS[odt.weekday().number_days_from_monday() as usize];
    let month = MONTHS[u8::from(odt.month()) as usize - 1];
    format!("{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT", odt.day(), odt.year(), odt.hour(), odt.minute(), odt.second())
}

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

    #[test]
    fn public_page_is_http_and_silent_otherwise() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let page = public_http_response(b"GET / HTTP/1.1\r\n", now).unwrap();
        let text = String::from_utf8(page).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Date: "));
        assert!(text.contains("Nothing posted yet."));
        assert!(!text.contains("<p>ok</p>"));
        let head = public_http_response(b"HEAD / HTTP/1.1\r\n", now).unwrap();
        let head = String::from_utf8(head).unwrap();
        assert!(head.contains("Content-Length: 0\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        assert!(public_http_response(&[0, 1, 2, 3], now).is_none());
    }
}
