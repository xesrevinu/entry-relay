use std::path::Path;
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn install_provider() {
    let _ = default_provider().install_default();
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, ()> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn from_hex(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

pub fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let raw = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(raw.as_slice());
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>().map_err(|err| anyhow::anyhow!(err))
}

pub fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let raw = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(raw.as_slice());
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))
}

pub fn server_config(cert: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> anyhow::Result<Arc<ServerConfig>> {
    install_provider();
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if sha256(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(rustls::PeerIncompatible::ServerDoesNotSupportTls12Or13))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config(pin: [u8; 32]) -> Arc<ClientConfig> {
    install_provider();
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_secret_extraction = true;
    Arc::new(config)
}

pub fn write_self_signed(dir: &Path, name: &str) -> anyhow::Result<[u8; 32]> {
    std::fs::create_dir_all(dir)?;
    let key = KeyPair::generate()?;
    let params = CertificateParams::new(vec![name.to_string()])?;
    let cert = params.self_signed(&key)?;
    std::fs::write(dir.join("cert.pem"), cert.pem())?;
    std::fs::write(dir.join("key.pem"), key.serialize_pem())?;
    let pin = sha256(cert.der());
    std::fs::write(dir.join("pin.hex"), encode_hex(&pin))?;
    Ok(pin)
}
