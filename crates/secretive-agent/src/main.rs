use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

use notify::{RecursiveMode, Watcher};
use secretive_core::{
    EmptyStore, FileStore, FileStoreConfig, KeyStore, KeyStoreRegistry, Pkcs11Config, Pkcs11Store,
};
use bytes::BytesMut;
use secretive_proto::{read_request_with_buffer, write_response, AgentRequest, AgentResponse, Identity};

#[derive(Debug, Deserialize)]
struct Config {
    socket_path: Option<String>,
    key_paths: Option<Vec<String>>,
    scan_default_dir: Option<bool>,
    stores: Option<Vec<StoreConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoreConfig {
    File {
        paths: Option<Vec<String>>,
        scan_default_dir: Option<bool>,
    },
    SecureEnclave,
    Pkcs11 {
        module_path: String,
        slot: Option<u64>,
        pin_env: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = parse_args();
    let mut config = load_config(args.config_path.as_deref());
    if let Some(socket_path) = args.socket_path {
        config.socket_path = Some(socket_path);
    }
    if config.stores.is_none() {
        if !args.key_paths.is_empty() {
            config.key_paths = Some(args.key_paths);
        }
        if let Some(scan) = args.scan_default_dir {
            config.scan_default_dir = Some(scan);
        }
    } else if !args.key_paths.is_empty() || args.scan_default_dir.is_some() {
        warn!("config includes store definitions; ignoring CLI file-store overrides");
    }

    let mut registry = KeyStoreRegistry::new();
    let mut reloadable_stores: Vec<Arc<FileStore>> = Vec::new();

    let stores = if let Some(stores) = config.stores.take() {
        stores
    } else {
        vec![StoreConfig::File {
            paths: config.key_paths.clone(),
            scan_default_dir: config.scan_default_dir,
        }]
    };

    for store in stores {
        match store {
            StoreConfig::File { paths, scan_default_dir } => {
                let mut store_config = FileStoreConfig::default();
                if let Some(paths) = paths {
                    store_config.paths = paths.into_iter().map(PathBuf::from).collect();
                }
                if let Some(scan) = scan_default_dir {
                    store_config.scan_default_dir = scan;
                }

                match FileStore::load(store_config) {
                    Ok(store) => {
                        let store = Arc::new(store);
                        registry.register(store.clone());
                        reloadable_stores.push(store);
                    }
                    Err(err) => {
                        warn!(?err, "failed to load file-based keys");
                    }
                }
            }
            StoreConfig::SecureEnclave => match secretive_core::SecureEnclaveStore::load() {
                Ok(store) => {
                    let store = Arc::new(store);
                    registry.register(store);
                }
                Err(err) => {
                    warn!(?err, "failed to load secure enclave store");
                }
            },
            StoreConfig::Pkcs11 { module_path, slot, pin_env } => {
                let config = Pkcs11Config {
                    module_path: PathBuf::from(module_path),
                    slot,
                    pin_env,
                };
                match Pkcs11Store::load(config) {
                    Ok(store) => {
                        let store = Arc::new(store);
                        registry.register(store);
                    }
                    Err(err) => {
                        warn!(?err, "failed to load pkcs11 store");
                    }
                }
            }
        }
    }

    if reloadable_stores.is_empty() {
        registry.register(Arc::new(EmptyStore));
    }

    if let Ok(identities) = registry.list_identities() {
        info!(count = identities.len(), "loaded identities");
    }

    let mut _watchers = Vec::new();
    if !reloadable_stores.is_empty() {
        let mut watch_paths = Vec::new();
        for store in &reloadable_stores {
            watch_paths.extend(store.watch_paths());
        }
        watch_paths.sort();
        watch_paths.dedup();

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
        if let Ok(mut watcher) = notify::recommended_watcher(move |res| {
            let _ = notify_tx.send(res);
        }) {
            for path in &watch_paths {
                let _ = watcher.watch(path, RecursiveMode::Recursive);
            }
            _watchers.push(watcher);
        }

        let reloadable_stores = reloadable_stores.clone();
        tokio::spawn(async move {
            while let Some(_event) = notify_rx.recv().await {
                for store in &reloadable_stores {
                    if let Err(err) = store.reload() {
                        warn!(?err, "failed to reload keys");
                    }
                }
                let count = reloadable_stores
                    .iter()
                    .filter_map(|store| store.list_identities().ok())
                    .map(|ids| ids.len())
                    .sum::<usize>();
                info!(count, "reloaded identities (watch)");
            }
        });
    }

    #[cfg(unix)]
    if !reloadable_stores.is_empty() {
        let reloadable_stores = reloadable_stores.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::hangup()) {
                while stream.recv().await.is_some() {
                    for store in &reloadable_stores {
                        if let Err(err) = store.reload() {
                            warn!(?err, "failed to reload keys");
                        }
                    }
                    let count = reloadable_stores
                        .iter()
                        .filter_map(|store| store.list_identities().ok())
                        .map(|ids| ids.len())
                        .sum::<usize>();
                    info!(count, "reloaded identities");
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

fn load_config(path_override: Option<&str>) -> Config {
    let path = path_override
        .map(|value| value.to_string())
        .or_else(|| std::env::var("SECRETIVE_CONFIG").ok());
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
        stores: None,
    }
}

struct Args {
    config_path: Option<String>,
    socket_path: Option<String>,
    key_paths: Vec<String>,
    scan_default_dir: Option<bool>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        config_path: None,
        socket_path: None,
        key_paths: Vec::new(),
        scan_default_dir: None,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => parsed.config_path = args.next(),
            "--socket" => parsed.socket_path = args.next(),
            "--key" => {
                if let Some(path) = args.next() {
                    parsed.key_paths.push(path);
                }
            }
            "--no-default-scan" => parsed.scan_default_dir = Some(false),
            "--default-scan" => parsed.scan_default_dir = Some(true),
            _ => {}
        }
    }

    parsed
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
        if let Err(err) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            warn!(?err, "failed to set socket directory permissions");
        }
    }

    if socket_path.exists() {
        if let Err(err) = std::fs::remove_file(&socket_path) {
            warn!(?err, "failed to remove existing socket file");
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    if let Err(err) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
        warn!(?err, "failed to set socket permissions");
    }
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
