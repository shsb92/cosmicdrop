use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver as MpscReceiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use plist::{Dictionary, Value};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::{AirDropConfig, AirDropReceiverFlags};
use crate::util;

/// A discovered AirDrop receiver.
#[derive(Clone, Debug)]
pub struct Receiver {
    pub id: String,
    pub name: Option<String>,
    pub address: IpAddr,
    pub port: u16,
    pub hostname: String,
    #[allow(dead_code)]
    pub flags: u32,
    pub discoverable: bool,
}

#[allow(dead_code)]
pub struct AirDropBrowser {
    mdns: ServiceDaemon,
    receivers: Arc<Mutex<HashMap<String, Receiver>>>,
    pub events: MpscReceiver<BrowserEvent>,
}

pub enum BrowserEvent {
    Found(Receiver),
    Removed(String),
}

impl AirDropBrowser {
    pub fn start(config: &AirDropConfig) -> Result<(Self, Sender<()>)> {
        let mdns = ServiceDaemon::new()?;
        let service_type = "_airdrop._tcp.local.";
        let receiver = mdns.browse(service_type)?;

        let receivers: Arc<Mutex<HashMap<String, Receiver>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = channel();
        let (stop_tx, stop_rx) = channel::<()>();

        let browser = AirDropBrowser {
            mdns: mdns.clone(),
            receivers: receivers.clone(),
            events: rx,
        };

        let config = config.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                loop {
                    if let Ok(event) = receiver.try_recv() {
                        match event {
                            ServiceEvent::ServiceResolved(info) => {
                                let address = info
                                    .get_addresses()
                                    .iter()
                                    .next()
                                    .cloned()
                                    .unwrap_or(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]));
                                let id = info.get_fullname().split('.').next().unwrap_or("").to_string();
                                let flags = info
                                    .get_property_val_str("flags")
                                    .and_then(|f| f.parse::<u32>().ok())
                                    .unwrap_or(AirDropReceiverFlags::SUPPORTS_DISCOVER_MAYBE);
                                let receiver = Receiver {
                                    id,
                                    name: None,
                                    address,
                                    port: info.get_port(),
                                    hostname: info.get_hostname().to_string(),
                                    flags,
                                    discoverable: false,
                                };
                                {
                                    let mut map = receivers.lock().unwrap();
                                    map.entry(receiver.id.clone())
                                        .or_insert(receiver.clone());
                                }

                                // send discover using the current async context
                                let client = AirDropClient::new(&config, &receiver);
                                let name = client.send_discover_async().await;
                                let discoverable = name.is_some();
                                let mut map = receivers.lock().unwrap();
                                if let Some(entry) = map.get_mut(&receiver.id) {
                                    entry.name = name;
                                    entry.discoverable = discoverable;
                                }
                                let recv = map.get(&receiver.id).cloned();
                                drop(map);
                                if let Some(recv) = recv {
                                    let _ = tx.send(BrowserEvent::Found(recv));
                                }
                            }
                            ServiceEvent::ServiceRemoved(_ty, fullname) => {
                                let id = fullname.split('.').next().unwrap_or("").to_string();
                                receivers.lock().unwrap().remove(&id);
                                let _ = tx.send(BrowserEvent::Removed(id));
                            }
                            _ => {}
                        }
                    }
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
            let _ = mdns.shutdown();
        });

        Ok((browser, stop_tx))
    }
}

pub struct AirDropClient {
    config: AirDropConfig,
    pub receiver: Receiver,
}

impl AirDropClient {
    pub fn new(config: &AirDropConfig, receiver: &Receiver) -> Self {
        AirDropClient {
            config: config.clone(),
            receiver: receiver.clone(),
        }
    }

    /// Send a POST request over TLS and return (success, response body).
    async fn send_post(
        &self,
        url: &str,
        body: Vec<u8>,
        additional_headers: &[(&str, String)],
    ) -> Result<(bool, Vec<u8>)> {
        let host = self.receiver.address;
        let port = self.receiver.port;

        log::debug!("Sending POST {url} to {host}:{port}");
        self.config
            .write_debug(&body, &format!("send_{}_request.plist", url.trim_start_matches('/')));

        let tls = self.config.client_tls()?;
        let connector = TlsConnector::from(Arc::new(tls));
        let server_name_host = host;
        let server_name = match server_name_host {
            std::net::IpAddr::V6(v6) => {
                rustls::pki_types::ServerName::IpAddress(
                    rustls::pki_types::IpAddr::V6(v6.into()),
                )
            }
            std::net::IpAddr::V4(v4) => {
                rustls::pki_types::ServerName::IpAddress(
                    rustls::pki_types::IpAddr::V4(v4.into()),
                )
            }
        };
        let stream = TcpStream::connect((host, port)).await?;
        let mut conn = connector.connect(server_name, stream).await?;

        let mut header = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: AirDrop/1.0\r\nAccept-Language: en-us\r\nAccept-Encoding: br, gzip, deflate\r\nContent-Length: {}\r\n",
            url,
            host,
            port,
            body.len()
        );
        for (key, val) in additional_headers {
            header.push_str(&format!("{key}: {val}\r\n"));
        }
        header.push_str("\r\n");
        conn.write_all(header.as_bytes()).await?;
        conn.write_all(&body).await?;
        conn.flush().await?;

        let response = read_http_response(&mut conn).await?;
        self.config.write_debug(
            &response,
            &format!("send_{}_response.plist", url.trim_start_matches('/')),
        );

        let status: bool = response.starts_with(b"HTTP/1.1 200");
        // Extract body after \r\n\r\n
        let body = match find_header_end(&response) {
            Some(idx) => response[idx..].to_vec(),
            None => Vec::new(),
        };

        Ok((status, body))
    }
    #[allow(dead_code)]
    pub fn send_discover(&self) -> Option<String> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(self.send_discover_async())
    }

    pub async fn send_discover_async(&self) -> Option<String> {
        let mut discover: Dictionary = Dictionary::new();
        if let Some(record) = &self.config.record_data {
            discover.insert(
                "SenderRecordData".to_string(),
                Value::Data(record.clone()),
            );
        }
        let plist_binary = match value_to_binary(Value::Dictionary(discover)) {
            Ok(b) => b,
            Err(_) => return None,
        };

        match self.send_post("/Discover", plist_binary, &[]).await {
            Ok((_success, resp)) => {
                let parsed = plist::Value::from_reader(std::io::Cursor::new(resp)).ok()?;
                match parsed {
                    Value::Dictionary(dict) => dict
                        .get("ReceiverComputerName")
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_string()),
                    _ => None,
                }
            }
            Err(e) => {
                log::debug!("Discover failed: {e}");
                None
            }
        }
    }

    #[allow(dead_code)]
    pub fn send_ask(&self, file_path: &std::path::Path) -> Result<bool> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(self.send_ask_async(file_path))
    }

    pub async fn send_ask_async(&self, file_path: &std::path::Path) -> Result<bool> {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        let mut ask: Dictionary = Dictionary::new();
        ask.insert(
            "SenderComputerName".to_string(),
            Value::String(self.config.computer_name.clone()),
        );
        ask.insert(
            "BundleID".to_string(),
            Value::String("com.apple.finder".to_string()),
        );
        ask.insert(
            "SenderModelName".to_string(),
            Value::String(self.config.computer_model.clone()),
        );
        ask.insert(
            "SenderID".to_string(),
            Value::String(self.config.service_id.clone()),
        );
        ask.insert("ConvertMediaFormats".to_string(), Value::Boolean(false));

        if let Some(record) = &self.config.record_data {
            ask.insert("SenderRecordData".to_string(), Value::Data(record.clone()));
        }

        // Files
        let file_type = if file_path.is_dir() {
            "public.folder".to_string()
        } else {
            let bytes = std::fs::read(file_path).unwrap_or_default();
            let header = bytes.get(0..128).unwrap_or(&bytes[..]).to_vec();
            util::get_uti_type(&header).to_string()
        };

        let mut file_entry: Dictionary = Dictionary::new();
        file_entry.insert("FileName".to_string(), Value::String(file_name.clone()));
        file_entry.insert("FileType".to_string(), Value::String(file_type));
        file_entry.insert(
            "FileBomPath".to_string(),
            Value::String(format!("./{file_name}")),
        );
        file_entry.insert(
            "FileIsDirectory".to_string(),
            Value::Boolean(file_path.is_dir()),
        );
        file_entry.insert("ConvertMediaFormats".to_string(), Value::Integer(0.into()));

        let files = vec![Value::Dictionary(file_entry)];
        ask.insert("Files".to_string(), Value::Array(files));

        // Add icon for images
        if !file_path.is_dir() {
            if let Some(icon) = util::generate_file_icon(file_path) {
                ask.insert("FileIcon".to_string(), Value::Data(icon));
            }
        }

        let plist_binary = value_to_binary(Value::Dictionary(ask))?;
        let (success, _) = self.send_post("/Ask", plist_binary, &[]).await?;
        Ok(success)
    }

    #[allow(dead_code)]
    pub fn send_upload(&self, file_path: &std::path::Path) -> Result<bool> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(self.send_upload_async(file_path))
    }

    pub async fn send_upload_async(&self, file_path: &std::path::Path) -> Result<bool> {
        // Create an archive in memory
        let archive = create_cpio_archive(file_path)?;

        let headers = vec![("Content-Type", "application/x-cpio".to_string())];
        let (success, _) = self.send_post("/Upload", archive, &headers).await?;
        Ok(success)
    }
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

async fn read_http_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(idx) = find_header_end(&buf) {
            // We have the full headers. Determine if there's a body.
            let headers_end = idx;
            let header_text = String::from_utf8_lossy(&buf[..headers_end]);
            let content_length = header_text
                .lines()
                .find_map(|line| {
                    let lower = line.to_lowercase();
                    lower
                        .starts_with("content-length:")
                        .then(|| line.split(':').nth(1)?.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if buf.len() >= headers_end + content_length {
                return Ok(buf);
            }
        }
    }
    Ok(buf)
}

/// Create a gzipped tar archive of a file or directory (single top-level entry).
/// Apple's AirDrop receiver extracts the upload archive using libarchive, which
/// transparently handles tar (including gzip).
fn create_cpio_archive(path: &std::path::Path) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        if path.is_dir() {
            builder.append_dir_all(&file_name, path)?;
        } else {
            builder.append_path_with_name(path, &file_name)?;
        }
        builder.finish()?;
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_buf)?;
    let gz = encoder.finish()?;
    Ok(gz)
}

/// Serialize a plist `Value` to binary format.
fn value_to_binary(value: Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.to_writer_binary(&mut out)?;
    Ok(out)
}
