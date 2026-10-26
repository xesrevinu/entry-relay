use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

pub fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub async fn accept<S>(sock: &mut S) -> std::io::Result<ConnectRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    sock.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not socks5"));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xff]).await?;
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "auth required"));
    }
    sock.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        reject(sock, 0x07).await?;
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "only connect"));
    }
    let (host, port) = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await?;
            (Ipv4Addr::from(ip).to_string(), u16::from_be_bytes(port_buf))
        }
        3 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await?;
            let host = String::from_utf8(name).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "domain is not utf-8")
            })?;
            (host, u16::from_be_bytes(port_buf))
        }
        4 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            let mut port_buf = [0u8; 2];
            sock.read_exact(&mut port_buf).await?;
            (Ipv6Addr::from(ip).to_string(), u16::from_be_bytes(port_buf))
        }
        _ => {
            reject(sock, 0x08).await?;
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad atyp"));
        }
    };
    Ok(ConnectRequest { host, port })
}

pub async fn reply_ok<S>(sock: &mut S) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

pub async fn reject<S>(sock: &mut S, code: u8) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    sock.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

pub fn allowed(request: &ConnectRequest, allow: &[String]) -> bool {
    let printed = endpoint(&request.host, request.port);
    allow.iter().any(|item| item == &printed || item == &request.host)
}

pub fn parse_socket(host: &str, port: u16) -> Option<SocketAddr> {
    let ip: IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_ip_and_port() {
        let request = ConnectRequest { host: "192.0.2.1".into(), port: 443 };
        assert!(allowed(&request, &["192.0.2.1:443".into()]));
        assert!(!allowed(&request, &["192.0.2.1:80".into()]));
    }
}
