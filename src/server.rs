use std::io::Read;
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use plist::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::config::AirDropConfig;

/// A "receive mode" event sent to the GUI.
#[derive(Clone, Debug)]
pub enum ServerEvent {
    Start,
    Ask {
        sender_name: String,
        file_name: String,
        #[allow(dead_code)]
        file_size: u64,
    },
    Accepted,
    ReceiveProgress {
        #[allow(dead_code)]
        file_name: String,
        #[allow(dead_code)]
        bytes: u64,
        #[allow(dead_code)]
        total_bytes: u64,
    },
    Received {
        file_name: String,
    },
    Error(String),
}

pub struct AirDropServer {
    #[allow(dead_code)]
    mdns: ServiceDaemon,
    pub events: Receiver<ServerEvent>,
    #[allow(dead_code)]
    pub status: Arc<Mutex<ServerStatus>>,
    #[allow(dead_code)]
    pub port: u16,
}

#[derive(Default)]
pub struct ServerStatus {
    pub running: bool,
}

impl AirDropServer {
    /// Start the AirDrop receive server. It advertises via mDNS and serves
    /// the HTTP(S) endpoint on the configured interface.
    pub fn start(config: &AirDropConfig) -> Result<(Self, Sender<()>)> {
        let server_tls = config.server_tls()?;
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));

        // Determine the IPv6 address of the configured interface.
        let ip_addr = crate::config::get_ip_for_interface(&config.interface, true)
            .ok_or_else(|| {
                anyhow!(
                    "Interface {} does not have an IPv6 address. \
                     AirDrop advertises a link-local IPv6 (fe80::/10) address, \
                     so the receive server cannot start on this interface. \
                     If this is a Wi-Fi card without AWDL support (e.g. Intel \
                     iwlwifi), AirDrop peers cannot be reached anyway; try a \
                     different interface or a compatible adapter.",
                    config.interface
                )
            })?;

        // Build the service info and register over mDNS.
        let mdns = ServiceDaemon::new()?;
        let mut props: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        props.insert("flags".to_string(), config.flags.to_string());
        let info = ServiceInfo::new(
            "_airdrop._tcp.local.",
            config.service_id.as_str(),
            format!("{}.local.", config.host_name).as_str(),
            ip_addr,
            config.port,
            props,
        )?;
        mdns.register(info)?;

        let (event_tx, event_rx) = channel();
        let (stop_tx, stop_rx) = channel::<()>();

        let status: Arc<Mutex<ServerStatus>> = Arc::new(Mutex::new(ServerStatus {
            running: true,
        }));

        let cfg = config.clone();
        let status_clone = status.clone();
        let bind_ip = ip_addr;
        let mdns_handle = mdns.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let _ = event_tx.send(ServerEvent::Start);
                let listener = bind_with_retry(bind_ip, cfg.port, &event_tx).await;
                let listener = match listener {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = event_tx.send(ServerEvent::Error(format!(
                            "Failed to bind: {e}"
                        )));
                        return;
                    }
                };
                loop {
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                    if let Ok(Ok((stream, _peer))) =
                        tokio::time::timeout(Duration::from_millis(100), listener.accept()).await
                    {
                        let cfg = cfg.clone();
                        let acceptor = acceptor.clone();
                        let event_tx = event_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream,
                                acceptor,
                                &cfg,
                                &event_tx,
                            )
                            .await
                            {
                                log::debug!("Connection handler error: {e}");
                            }
                        });
                    }
                }
            });
            let _ = mdns_handle.shutdown();
            let mut s = status_clone.lock().unwrap();
            s.running = false;
        });

        let server = AirDropServer {
            mdns: mdns.clone(),
            events: event_rx,
            status,
            port: config.port,
        };

        Ok((server, stop_tx))
    }
}

async fn bind_with_retry(
    ip: std::net::IpAddr,
    port: u16,
    _event_tx: &Sender<ServerEvent>,
) -> Result<TcpListener> {
    match TcpListener::bind(SocketAddr::new(ip, port)).await {
        Ok(l) => Ok(l),
        Err(e) => {
            log::warn!("Port {port} in use, trying port {}: {e}", port + 1);
            TcpListener::bind(SocketAddr::new(ip, port + 1))
                .await
                .map_err(|e| anyhow!("Failed to bind: {e}"))
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    config: &AirDropConfig,
    event_tx: &Sender<ServerEvent>,
) -> Result<()> {
    let tls = acceptor.accept(stream).await?;
    let mut reader = BufReader::new(tls);
    let mut buffer = Vec::new();
    let mut tmp = [0u8; 8192];

    // Read request headers until \r\n\r\n (within a reasonable cap).
    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&tmp[..n]);
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") || buffer.len() > 64 * 1024 {
            break;
        }
    }

    let head_end = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("Malformed request"))?;
    let header_text = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let path = parts.next().unwrap_or("");

    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    // Read body according to Content-Length.
    let content_type = headers
        .get("content-type")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let body_start = head_end + 4;
    while buffer.len() < body_start + content_length {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&tmp[..n]);
    }
    let body = buffer[body_start..body_start + content_length.min(buffer.len() - body_start)]
        .to_vec();

    if method == "POST" {
        match path {
            "/Discover" => {
                config.write_debug(&body, "receive_discover_request.plist");
                let mut discover_answer: plist::Dictionary = plist::Dictionary::new();
                discover_answer.insert(
                    "ReceiverComputerName".to_string(),
                    Value::String(config.computer_name.clone()),
                );
                discover_answer.insert(
                    "ReceiverModelName".to_string(),
                    Value::String(config.computer_model.clone()),
                );
                discover_answer.insert(
                    "ReceiverMediaCapabilities".to_string(),
                    Value::String(r#"{"Version":1}"#.to_string()),
                );
                if let Some(record) = &config.record_data {
                    discover_answer.insert(
                        "ReceiverRecordData".to_string(),
                        Value::Data(record.clone()),
                    );
                }
                let answer_binary = value_to_binary(Value::Dictionary(discover_answer))?;
                config.write_debug(&answer_binary, "receive_discover_response.plist");
                write_response(&mut reader, 200, &answer_binary).await?;
            }
            "/Ask" => {
                config.write_debug(&body, "receive_ask_request.plist");
                let parsed = Value::from_reader(std::io::Cursor::new(&body))
                    .ok()
                    .and_then(|v| match v {
                        Value::Dictionary(d) => Some(d),
                        _ => None,
                    });
                let sender_name = parsed
                    .as_ref()
                    .and_then(|d| d.get("SenderComputerName"))
                    .and_then(|v| v.as_string())
                    .unwrap_or("Unknown")
                    .to_string();
                let file_name = parsed
                    .as_ref()
                    .and_then(|d| d.get("Files"))
                    .and_then(|v| match v {
                        Value::Array(a) => a.first(),
                        _ => None,
                    })
                    .and_then(|f| match f {
                        Value::Dictionary(d) => d.get("FileName"),
                        _ => None,
                    })
                    .and_then(|v| v.as_string())
                    .unwrap_or("file")
                    .to_string();

                let _ = event_tx.send(ServerEvent::Ask {
                    sender_name,
                    file_name,
                    file_size: 0,
                });

                let mut ask_response: plist::Dictionary = plist::Dictionary::new();
                ask_response.insert(
                    "ReceiverModelName".to_string(),
                    Value::String(config.computer_model.clone()),
                );
                ask_response.insert(
                    "ReceiverComputerName".to_string(),
                    Value::String(config.computer_name.clone()),
                );
                let resp_binary = value_to_binary(Value::Dictionary(ask_response))?;
                config.write_debug(&resp_binary, "receive_ask_response.plist");
                write_response(&mut reader, 200, &resp_binary).await?;
            }
            "/Upload" => {
                // For simplicity, we extract the entire body archive.
                let _ = event_tx.send(ServerEvent::Accepted);
                let bytes = body.len() as u64;
                let file_name = "incoming".to_string();
                let _ = event_tx.send(ServerEvent::ReceiveProgress {
                    file_name: file_name.clone(),
                    bytes,
                    total_bytes: bytes,
                });

                let dest = std::env::current_dir().unwrap_or_default();
                match extract_upload(&body, &dest) {
                    Ok(names) => {
                        for name in names {
                            let _ = event_tx.send(ServerEvent::Received { file_name: name });
                        }
                    }
                    Err(e) => {
                        let _ = event_tx.send(ServerEvent::Error(format!(
                            "Failed to extract upload: {e}"
                        )));
                    }
                }

                let _ = content_type;
                write_response(&mut reader, 200, &[]).await?;
            }
            _ => {
                write_response(&mut reader, 400, &[]).await?;
            }
        }
    } else {
        // GET / HEAD
        write_response(&mut reader, 200, b"\n").await?;
    }

    Ok(())
}

/// Write an HTTP/1.1 response over the TLS stream.
async fn write_response<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        406 => "Not Acceptable",
        _ => "Unknown",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Serialize a plist `Value` to binary format.
fn value_to_binary(value: Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.to_writer_binary(&mut out)?;
    Ok(out)
}

/// Best-effort extraction of a gzipped tar (or plain tar / cpio) archive.
fn extract_upload(data: &[u8], dest: &std::path::Path) -> Result<Vec<String>> {
    use std::io::Cursor;

    let mut names = Vec::new();
    let reader: Box<dyn Read> = if data.starts_with(&[0x1F, 0x8B]) {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(data.to_vec()));
        Box::new(decoder)
    } else {
        Box::new(Cursor::new(data.to_vec()))
    };

    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if let Some(file_name) = path.file_name() {
            names.push(file_name.to_string_lossy().to_string());
        }
        entry.unpack_in(dest)?;
    }

    Ok(names)
}
