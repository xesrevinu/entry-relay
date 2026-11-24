//! Loopback HTTP on the SOCKS port (first byte is not 0x05).
//!
//! `GET /delay`, `/proxies/entry-balance/delay`, and `/group/entry-balance/delay`
//! report mux OPEN RTT. They do not fetch an external URL.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::balance::Shared;

const MAX_REQ: usize = 8192;

pub enum Route {
    Delay { timeout: Duration },
    GroupDelay { timeout: Duration },
    Status,
    NotFound,
}

pub fn parse_request(head: &str) -> Route {
    let line = head.lines().next().unwrap_or("").trim();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return Route::NotFound;
    }
    let (path, query) = split_query(target);
    let wait = parse_timeout(query);
    match path {
        "/delay" | "/proxies/entry-balance/delay" => Route::Delay { timeout: wait },
        "/group/entry-balance/delay" => Route::GroupDelay { timeout: wait },
        "/status" => Route::Status,
        _ => Route::NotFound,
    }
}

fn split_query(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

fn parse_timeout(query: &str) -> Duration {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k != "timeout" {
            continue;
        }
        if let Ok(ms) = v.parse::<u64>() {
            return Duration::from_millis(ms.clamp(100, 30_000));
        }
    }
    Duration::from_millis(5000)
}

pub(crate) async fn serve(mut sock: TcpStream, shared: Arc<Shared>) -> anyhow::Result<()> {
    let head = read_head(&mut sock).await?;
    let body = match parse_request(&head) {
        Route::Delay { timeout: wait } => {
            let ms = timeout(wait, shared.delay_ms(wait)).await.ok().flatten();
            delay_body(ms)
        }
        Route::GroupDelay { timeout: wait } => {
            let members = timeout(wait, shared.group_delay(wait)).await.unwrap_or_default();
            group_body(&members)
        }
        Route::Status => ok_body(&shared.status_json()),
        Route::NotFound => not_found(),
    };
    sock.write_all(body.as_bytes()).await?;
    Ok(())
}

async fn read_head(sock: &mut TcpStream) -> anyhow::Result<String> {
    let mut buf = vec![0u8; 0];
    let mut tmp = [0u8; 512];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_REQ {
            anyhow::bail!("http request too large");
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn delay_body(ms: Option<u32>) -> String {
    match ms {
        Some(ms) if ms > 0 => ok_body(&format!("{{\"delay\":{ms}}}")),
        _ => ok_body("{\"delay\":0}"),
    }
}

fn group_body(members: &[(String, u32)]) -> String {
    if members.is_empty() {
        return http(504, "{\"message\":\"all members failed\"}");
    }
    let mut json = String::from("{");
    for (i, (name, ms)) in members.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push_str(&format!("\"{}\":{ms}", escape(name)));
    }
    json.push('}');
    ok_body(&json)
}

fn not_found() -> String {
    http(404, "{\"message\":\"Resource not found\"}")
}

fn ok_body(json: &str) -> String {
    http(200, json)
}

fn http(status: u16, json: &str) -> String {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{json}",
        json.len()
    )
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_delay_paths() {
        match parse_request("GET /delay?timeout=3000 HTTP/1.1") {
            Route::Delay { timeout } => assert_eq!(timeout, Duration::from_millis(3000)),
            _ => panic!("delay"),
        }
        match parse_request("GET /proxies/entry-balance/delay?timeout=1000 HTTP/1.1") {
            Route::Delay { timeout } => assert_eq!(timeout, Duration::from_millis(1000)),
            _ => panic!("proxy delay"),
        }
        match parse_request("GET /group/entry-balance/delay HTTP/1.1") {
            Route::GroupDelay { timeout } => assert_eq!(timeout, Duration::from_millis(5000)),
            _ => panic!("group delay"),
        }
        assert!(matches!(parse_request("GET /status HTTP/1.1"), Route::Status));
        assert!(matches!(parse_request("GET /group/entry-balance/delayx HTTP/1.1"), Route::NotFound));
        assert!(matches!(parse_request("POST /delay HTTP/1.1"), Route::NotFound));
    }

    #[test]
    fn clamps_timeout() {
        match parse_request("GET /delay?timeout=1 HTTP/1.1") {
            Route::Delay { timeout } => assert_eq!(timeout, Duration::from_millis(100)),
            _ => panic!(),
        }
        match parse_request("GET /delay?timeout=999999 HTTP/1.1") {
            Route::Delay { timeout } => assert_eq!(timeout, Duration::from_millis(30_000)),
            _ => panic!(),
        }
    }

    #[test]
    fn json_shapes() {
        let body = delay_body(Some(38));
        assert!(body.contains("{\"delay\":38}"));
        let group = group_body(&[("relay-a".into(), 41)]);
        assert!(group.contains("{\"relay-a\":41}"));
        assert!(group.starts_with("HTTP/1.1 200"));
        assert!(group_body(&[]).starts_with("HTTP/1.1 504"));
        assert!(not_found().contains("Resource not found"));
    }
}
