use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::Duration;

use directories::BaseDirs;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
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
    max_signers: Option<usize>,
    watch_files: Option<bool>,
    metrics_every: Option<u64>,
    pid_file: Option<String>,
}

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGN_TIME_NS: AtomicU64 = AtomicU64::new(0);
static METRICS_EVERY: AtomicU64 = AtomicU64::new(1000);

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
    if args.help {
        print_help();
        return;
    }
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
    if let Some(max_signers) = args.max_signers {
        config.max_signers = Some(max_signers);
    }
    if let Some(watch_files) = args.watch_files {
        config.watch_files = Some(watch_files);
    }
    if let Some(metrics_every) = args.metrics_every {
        config.metrics_every = Some(metrics_every);
    }
    if let Some(pid_file) = args.pid_file {
        config.pid_file = Some(pid_file);
    }

    let _pid_guard = match config.pid_file.clone() {
        Some(path) => PidFileGuard::create(path).ok(),
        None => None,
    };

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
    let watch_files = config.watch_files.unwrap_or(true);
    if watch_files && !reloadable_stores.is_empty() {
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
            let debounce = Duration::from_millis(200);
            loop {
                let Some(_event) = notify_rx.recv().await else { break; };
                let mut deadline = Instant::now() + debounce;
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let wait = deadline - now;
                    match tokio::time::timeout(wait, notify_rx.recv()).await {
                        Ok(Some(_)) => {
                            deadline = Instant::now() + debounce;
                        }
                        _ => break,
                    }
                }

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
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::user_defined1()) {
                while stream.recv().await.is_some() {
                    let count = SIGN_COUNT.load(Ordering::Relaxed);
                    let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
                    let avg = if count > 0 { total / count as f64 } else { 0.0 };
                    info!(count, avg_ns = avg, "signing metrics snapshot");
                }
            }
        });
    }

    let default_max_signers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .saturating_mul(4);
    let max_signers = config.max_signers.unwrap_or(default_max_signers);
    info!(max_signers, "sign concurrency limit");
    let sign_semaphore = Arc::new(Semaphore::new(max_signers));

    let metrics_every = config.metrics_every.unwrap_or(1000);
    METRICS_EVERY.store(metrics_every, Ordering::Relaxed);

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(config.socket_path);
        if let Err(err) = run_unix(socket_path, registry, sign_semaphore.clone()).await {
            error!(?err, "agent exited with error");
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = resolve_pipe_name(config.socket_path);
        if let Err(err) = run_windows(pipe_name, registry, sign_semaphore.clone()).await {
            error!(?err, "agent exited with error");
        }
    }
}

fn load_config(path_override: Option<&str>) -> Config {
    let path = path_override
        .map(|value| value.to_string())
        .or_else(|| std::env::var("SECRETIVE_CONFIG").ok())
        .or_else(|| default_config_path().map(|path| path.display().to_string()));
    if let Some(path) = path {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<Config>(&contents) {
                info!(path = %path, "loaded config");
                return config;
            }
        }
    }
    Config {
        socket_path: None,
        key_paths: None,
        scan_default_dir: None,
        stores: None,
        max_signers: None,
        watch_files: None,
        metrics_every: None,
        pid_file: None,
    }
}

fn default_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("secretive").join("agent.json"));
    }
    BaseDirs::new().map(|dirs| dirs.config_dir().join("secretive").join("agent.json"))
}

struct Args {
    config_path: Option<String>,
    socket_path: Option<String>,
    key_paths: Vec<String>,
    scan_default_dir: Option<bool>,
    max_signers: Option<usize>,
    watch_files: Option<bool>,
    metrics_every: Option<u64>,
    pid_file: Option<String>,
    help: bool,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        config_path: None,
        socket_path: None,
        key_paths: Vec::new(),
        scan_default_dir: None,
        max_signers: None,
        watch_files: None,
        metrics_every: None,
        pid_file: None,
        help: false,
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
            "--max-signers" => {
                if let Some(value) = args.next() {
                    parsed.max_signers = value.parse().ok();
                }
            }
            "--watch" => parsed.watch_files = Some(true),
            "--no-watch" => parsed.watch_files = Some(false),
            "--metrics-every" => {
                if let Some(value) = args.next() {
                    parsed.metrics_every = value.parse().ok();
                }
            }
            "--pid-file" => parsed.pid_file = args.next(),
            "-h" | "--help" => parsed.help = true,
            _ => {}
        }
    }

    parsed
}

fn print_help() {
    println!("secretive-agent usage:\n");
    println!("  --config <path> --socket <path> --key <path>");
    println!("  --default-scan | --no-default-scan");
    println!("  --max-signers <n> --metrics-every <n>");
    println!("  --watch | --no-watch --pid-file <path>\n");
    println!("Notes:");
    println!("  Use JSON config for store definitions (see docs/RUST_CONFIG.md).");
}

#[cfg(unix)]
fn resolve_socket_path(override_path: Option<String>) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("SECRETIVE_SOCK") {
        return PathBuf::from(path);
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("secretive").join("agent.sock");
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

struct PidFileGuard {
    path: PathBuf,
}

impl PidFileGuard {
    fn create(path: String) -> std::io::Result<Self> {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, std::process::id().to_string())?;
        Ok(Self { path })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
async fn run_unix(
    socket_path: PathBuf,
    registry: KeyStoreRegistry,
    sign_semaphore: Arc<Semaphore>,
) -> std::io::Result<()> {
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

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

    #[cfg(unix)]
    if socket_path.as_os_str().as_bytes().len() > 100 {
        warn!(path = %socket_path.display(), "socket path may be too long for some systems");
    }

    let listener = UnixListener::bind(&socket_path)?;
    if let Err(err) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)) {
        warn!(?err, "failed to set socket permissions");
    }
    info!(path = %socket_path.display(), "secretive agent listening");

    let registry = Arc::new(registry);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    if let Ok(mut sigterm) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        tokio::spawn(async move {
            let _ = sigterm.recv().await;
            let _ = shutdown_tx.send(());
        });
    }
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let registry = registry.clone();
                        let sign_semaphore = sign_semaphore.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, registry, sign_semaphore).await {
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
            _ = &mut shutdown_rx => {
                info!("shutdown requested (SIGTERM)");
                break;
            }
        }
    }

    if socket_path.exists() {
        if let Err(err) = std::fs::remove_file(&socket_path) {
            warn!(?err, "failed to remove socket file on shutdown");
        }
    }

    Ok(())
}

#[cfg(windows)]
async fn run_windows(
    pipe_name: String,
    registry: KeyStoreRegistry,
    sign_semaphore: Arc<Semaphore>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    info!(pipe = %pipe_name, "secretive agent listening");
    let registry = Arc::new(registry);

    loop {
        let server = ServerOptions::new().create(&pipe_name)?;
        server.connect().await?;
        let registry = registry.clone();
        let sign_semaphore = sign_semaphore.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(server, registry, sign_semaphore).await {
                warn!(?err, "connection error");
            }
        });
    }
}

async fn handle_connection<S>(
    stream: S,
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
) -> std::io::Result<()>
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

        let response = handle_request(registry.clone(), request, sign_semaphore.clone()).await;
        if let Err(err) = write_response(&mut writer, &response).await {
            warn!(?err, "failed to write response");
            break;
        }
    }

    Ok(())
}

async fn handle_request(
    registry: Arc<KeyStoreRegistry>,
    request: AgentRequest,
    sign_semaphore: Arc<Semaphore>,
) -> AgentResponse {
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
            let start = Instant::now();
            let permit = match sign_semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("signing semaphore closed");
                    return AgentResponse::Failure;
                }
            };
            let result = tokio::task::spawn_blocking(move || registry.sign(&key_blob, &data, flags)).await;
            drop(permit);
            match result {
                Ok(Ok(signature_blob)) => {
                    let elapsed = start.elapsed();
                    let count = SIGN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                    SIGN_TIME_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
                    let every = METRICS_EVERY.load(Ordering::Relaxed);
                    if every > 0 && count % every == 0 {
                        let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
                        let avg = total / count as f64;
                        info!(count, avg_ns = avg, "signing metrics");
                    }
                    AgentResponse::SignResponse { signature_blob }
                }
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
