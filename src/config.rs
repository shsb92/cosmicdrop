use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use rand::Rng;

/// AirDrop receiver flags, recovered from sharingd's receiverSupportsX methods.
/// A valid node needs to either have SUPPORTS_PIPELINING or SUPPORTS_MIXED_TYPES
/// according to sharingd`[SDBonjourBrowser removeInvalidNodes:]`.
/// Default flags on macOS: 0x3fb according to sharingd`[SDRapportBrowser defaultSFNodeFlags]`
#[allow(dead_code)]
pub struct AirDropReceiverFlags;

#[allow(dead_code)]
impl AirDropReceiverFlags {
    pub const SUPPORTS_URL: u32 = 0x01;
    pub const SUPPORTS_DVZIP: u32 = 0x02;
    pub const SUPPORTS_PIPELINING: u32 = 0x04;
    pub const SUPPORTS_MIXED_TYPES: u32 = 0x08;
    pub const SUPPORTS_UNKNOWN1: u32 = 0x10;
    pub const SUPPORTS_UNKNOWN2: u32 = 0x20;
    pub const SUPPORTS_IRIS: u32 = 0x40;
    pub const SUPPORTS_DISCOVER_MAYBE: u32 =
        0x80; // Probably indicates that server supports /Discover URL
    pub const SUPPORTS_UNKNOWN3: u32 = 0x100;
    pub const SUPPORTS_ASSET_BUNDLE: u32 = 0x200;
}

#[derive(Clone)]
pub struct AirDropConfig {
    pub host_name: String,
    pub computer_name: String,
    pub computer_model: String,
    pub port: u16,
    #[allow(dead_code)]
    pub airdrop_dir: PathBuf,
    pub service_id: String,
    #[allow(dead_code)]
    pub email: Vec<String>,
    #[allow(dead_code)]
    pub phone: Vec<String>,
    pub debug: bool,
    pub debug_dir: PathBuf,
    pub interface: String,
    pub flags: u32,
    #[allow(dead_code)]
    pub root_ca_file: PathBuf,
    pub key_dir: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    #[allow(dead_code)]
    pub record_file: PathBuf,
    pub record_data: Option<Vec<u8>>,
}

#[allow(dead_code)]
static DEFAULT_ROOT_CA: &[u8] = include_bytes!("certs/apple_root_ca.pem");

impl AirDropConfig {
    pub fn new(
        host_name: Option<String>,
        computer_name: Option<String>,
        computer_model: Option<String>,
        server_port: Option<u16>,
        airdrop_dir: Option<PathBuf>,
        service_id: Option<String>,
        email: Option<Vec<String>>,
        phone: Option<Vec<String>>,
        debug: bool,
        interface: Option<String>,
    ) -> Result<Self> {
        let host_name = host_name.unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "cosmicdrop".to_string())
        });
        let computer_name = computer_name.unwrap_or_else(|| host_name.clone());
        let computer_model = computer_model.unwrap_or_else(|| "CosmicDrop".to_string());
        let port = server_port.unwrap_or(8771);
        let service_id = service_id.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let v: u64 = rng.gen::<u64>() & 0xFFFFFFFFFFFF;
            format!("{v:012x}")
        });
        let airdrop_dir = airdrop_dir.unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".opendrop")
        });
        let debug_dir = airdrop_dir.join("debug");
        let interface = if let Some(interface) = interface {
            interface
        } else {
            detect_airdrop_interface()
        };

        // Bare minimum, currently not supporting anything else
        let flags = AirDropReceiverFlags::SUPPORTS_MIXED_TYPES
            | AirDropReceiverFlags::SUPPORTS_DISCOVER_MAYBE;

        let key_dir = airdrop_dir.join("keys");
        let cert_file = key_dir.join("certificate.pem");
        let key_file = key_dir.join("key.pem");
        let record_file = key_dir.join("validation_record.cms");

        let record_data = if record_file.exists() {
            log::debug!("Using provided Apple ID Validation Record");
            Some(std::fs::read(&record_file)?)
        } else {
            log::debug!("No Apple ID Validation Record found");
            None
        };

        let config = AirDropConfig {
            host_name,
            computer_name,
            computer_model,
            port,
            airdrop_dir: airdrop_dir.clone(),
            service_id,
            email: email.unwrap_or_default(),
            phone: phone.unwrap_or_default(),
            debug,
            debug_dir,
            interface,
            flags,
            root_ca_file: PathBuf::from("apple_root_ca.pem"),
            key_dir,
            cert_file,
            key_file,
            record_file,
            record_data,
        };

        if !config.cert_file.exists() || !config.key_file.exists() {
            log::info!("Key file or certificate does not exist");
            config.create_default_key()?;
        }

        Ok(config)
    }

    pub fn create_default_key(&self) -> Result<()> {
        log::info!(
            "Create new self-signed certificate in {}",
            self.key_dir.display()
        );
        std::fs::create_dir_all(&self.key_dir)?;

        let subject_alt_names = vec![self.computer_name.clone()];
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(subject_alt_names)
                .map_err(|e| anyhow!("Failed to generate certificate: {e}"))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(&self.cert_file, cert_pem)?;
        std::fs::write(&self.key_file, key_pem)?;

        Ok(())
    }

    /// Build a rustls server config from the persisted cert/key.
    pub fn server_tls(&self) -> Result<rustls::ServerConfig> {
        let certs = load_certs(&self.cert_file)?;
        let key = load_key(&self.key_file)?;
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![];
        Ok(config)
    }

    /// Build a rustls client config that skips certificate validation
    /// (as Apple does with self-signed certs).
    pub fn client_tls(&self) -> Result<rustls::ClientConfig> {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        Ok(config)
    }

    pub fn write_debug(&self, data: &[u8], file_name: &str) {
        if !self.debug {
            return;
        }
        let _ = std::fs::create_dir_all(&self.debug_dir);
        let path = self.debug_dir.join(file_name);
        let _ = std::fs::write(path, data);
    }
}

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::ServerName;
use rustls::Error as RustlsError;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> std::vec::Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        ]
    }
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read_to_string(path)?;
    let mut certs = Vec::new();
    for block in data.split("-----BEGIN CERTIFICATE-----") {
        if let Some(end) = block.find("-----END CERTIFICATE-----") {
            let pem = format!(
                "-----BEGIN CERTIFICATE-----{}\n-----END CERTIFICATE-----",
                &block[..end + 2]
            );
            let mut reader = pem.as_bytes();
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| anyhow!("PEM parse error: {e}"))?;
                certs.push(cert);
            }
        }
    }
    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read_to_string(path)?;
    let mut reader = data.as_bytes();
    let pkcs8: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("PKCS8 parse error: {e}"))?;
    if let Some(key) = pkcs8.into_iter().last() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }
    let mut reader = data.as_bytes();
    let rsa: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow!("RSA parse error: {e}"))?;
    if let Some(key) = rsa.into_iter().last() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }
    Err(anyhow!("No private key found in {}", path.display()))
}

/// Get the IPv6 address for a given network interface.
///
/// When `ipv6` is true, prefers a link-local IPv6 address (fe80::/10) since
/// that is the address AirDrop advertises and connects over.
pub fn get_ip_for_interface(interface_name: &str, ipv6: bool) -> Option<IpAddr> {
    let mut any_v6 = None;
    for iface in if_addrs::get_if_addrs().ok()? {
        if iface.name == interface_name {
            let ip = iface.ip();
            if ipv6 {
                if let IpAddr::V6(v6) = ip {
                    if v6.segments()[0] & 0xffc0 == 0xfe80 {
                        // link-local preferred
                        return Some(ip);
                    }
                    if any_v6.is_none() {
                        any_v6 = Some(ip);
                    }
                }
            } else if ip.is_ipv4() {
                return Some(ip);
            }
        }
    }
    if ipv6 {
        any_v6
    } else {
        None
    }
}

/// Choose the best interface for AirDrop discovery.
///
/// Prefers Apple's AWDL interface (`awdl0`) when present, since real AirDrop
/// runs over it. Otherwise falls back to the first Wi-Fi interface, and finally
/// to any active interface that has an IP address.
fn detect_airdrop_interface() -> String {
    let ifaces = if_addrs::get_if_addrs().ok();
    let has_ip = |name: &str| -> bool {
        if let Some(list) = &ifaces {
            list.iter().any(|i| {
                i.name == name
                    && (i.ip().is_ipv4() || (i.ip().is_ipv6() && !i.ip().is_unspecified()))
            })
        } else {
            false
        }
    };
    let names: Vec<String> = if let Some(list) = &ifaces {
        list.iter().map(|i| i.name.clone()).collect()
    } else {
        Vec::new()
    };

    if names.iter().any(|n| n == "awdl0") && has_ip("awdl0") {
        return "awdl0".to_string();
    }
    // Any wifi interface (wlan0, wl*, etc.)
    for name in &names {
        if (name.starts_with("wl") || name == "wlan0") && has_ip(name) {
            return name.clone();
        }
    }
    // Any interface with an IP, excluding loopback.
    if let Some(list) = &ifaces {
        for i in list {
            if i.name != "lo" && (i.ip().is_ipv4() || !i.ip().is_unspecified()) {
                return i.name.clone();
            }
        }
    }
    "awdl0".to_string()
}
