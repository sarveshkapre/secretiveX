use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

use secretive_core::{EmptyStore, FileStore, FileStoreConfig, KeyStore, KeyStoreRegistry};
use bytes::BytesMut;
use secretive_proto::{read_request_with_buffer, write_response, AgentRequest, AgentResponse, Identity};

#[derive(Debug, Deserialize)]
struct Config {
    socket_path: Option<String>,
    key_paths: Option<Vec<String>>,
    scan_default_dir: Option<bool>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = load_config();

    let mut registry = KeyStoreRegistry::new();
    let mut store_config = FileStoreConfig::default();
    if let Some(paths) = config.key_paths.clone() {
        store_config.paths = paths.into_iter().map(PathBuf::from).collect();
    }
    if let Some(scan) = config.scan_default_dir {
        store_config.scan_default_dir = scan;
    }

    let file_store = match FileStore::load(store_config) {
        Ok(store) => {
            let store = Arc::new(store);
            registry.register(store.clone());
            Some(store)
        }
        Err(err) => {
            warn!(?err, "failed to load file-based keys");
            registry.register(Arc::new(EmptyStore));
            None
        }
    };

    if let Ok(identities) = registry.list_identities() {
        info!(count = identities.len(), "loaded identities");
    }

    #[cfg(unix)]
    if let Some(store) = file_store.clone() {
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::hangup()) {
                while stream.recv().await.is_some() {
                    if let Err(err) = store.reload() {
                        warn!(?err, "failed to reload keys");
                    } else if let Ok(identities) = store.list_identities() {
                        info!(count = identities.len(), "reloaded identities");
                    }
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(config.socket_path);
        if let Err(err) = run_unix(socket_path, registry).await {
            error!(?err, "agent exited with error");
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = resolve_pipe_name(config.socket_path);
        if let Err(err) = run_windows(pipe_name, registry).await {
            error!(?err, "agent exited with error");
        }
    }
}

fn load_config() -> Config {
    let path = std::env::var("SECRETIVE_CONFIG").ok();
    if let Some(path) = path {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(config) = serde_json::from_str::<Config>(&contents) {
                return config;
            }
        }
    }
    Config {
        socket_path: None,
        key_paths: None,
        scan_default_dir: None,
    }
}

#[cfg(unix)]
fn resolve_socket_path(override_path: Option<String>) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("SECRETIVE_SOCK") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".secretive").join("agent.sock")
}

#[cfg(windows)]
fn resolve_pipe_name(override_path: Option<String>) -> String {
    if let Some(path) = override_path {
        return path;
    }
    if let Ok(path) = std::env::var("SECRETIVE_PIPE") {
        return path;
    }
    r"\\.\pipe\secretive-agent".to_string()
}

#[cfg(unix)]
async fn run_unix(socket_path: PathBuf, registry: KeyStoreRegistry) -> std::io::Result<()> {
    use tokio::net::UnixListener;

    if let Some(dir) = socket_path.parent() {
        if let Err(err) = std::fs::create_dir_all(dir) {
            warn!(?err, "failed to create socket directory");
        }
    }

    if socket_path.exists() {
        if let Err(err) = std::fs::remove_file(&socket_path) {
            warn!(?err, "failed to remove existing socket file");
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!(path = %socket_path.display(), "secretive agent listening");

    let registry = Arc::new(registry);
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let registry = registry.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, registry).await {
                                warn!(?err, "connection error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(?err, "accept failed");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
async fn run_windows(pipe_name: String, registry: KeyStoreRegistry) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    info!(pipe = %pipe_name, "secretive agent listening");
    let registry = Arc::new(registry);

    loop {
        let server = ServerOptions::new().create(&pipe_name)?;
        server.connect().await?;
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(server, registry).await {
                warn!(?err, "connection error");
            }
        });
    }
}

async fn handle_connection<S>(stream: S, registry: Arc<KeyStoreRegistry>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut buffer = BytesMut::with_capacity(4096);
    loop {
        let request = match read_request_with_buffer(&mut reader, &mut buffer).await {
            Ok(req) => req,
            Err(err) => {
                warn!(?err, "failed to read request");
                break;
            }
        };

        let response = handle_request(registry.clone(), request).await;
        if let Err(err) = write_response(&mut writer, &response).await {
            warn!(?err, "failed to write response");
            break;
        }
    }

    Ok(())
}

async fn handle_request(registry: Arc<KeyStoreRegistry>, request: AgentRequest) -> AgentResponse {
    match request {
        AgentRequest::RequestIdentities => {
            match registry.list_identities() {
                Ok(identities) => AgentResponse::IdentitiesAnswer {
                    identities: identities.into_iter().map(|id| Identity {
                        key_blob: id.key_blob,
                        comment: id.comment,
                    }).collect(),
                },
                Err(err) => {
                    warn!(?err, "failed to list identities");
                    AgentResponse::Failure
                }
            }
        }
        AgentRequest::SignRequest { key_blob, data, flags } => {
            let result = tokio::task::spawn_blocking(move || registry.sign(&key_blob, &data, flags)).await;
            match result {
                Ok(Ok(signature_blob)) => AgentResponse::SignResponse { signature_blob },
                Ok(Err(err)) => {
                    warn!(?err, "sign request failed");
                    AgentResponse::Failure
                }
                Err(err) => {
                    warn!(?err, "sign worker failed");
                    AgentResponse::Failure
                }
            }
        }
        AgentRequest::Unknown { message_type, .. } => {
            warn!(message_type, "unknown request type");
            AgentResponse::Failure
        }
    }
}
