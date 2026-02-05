use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::Duration;

use directories::BaseDirs;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use notify::{RecursiveMode, Watcher};
use secretive_core::{
    EmptyStore, FileStore, FileStoreConfig, KeyIdentity, KeyStoreRegistry, Pkcs11Config,
    Pkcs11Store,
};
use bytes::{Bytes, BytesMut};
use secretive_proto::{
    read_request_with_buffer, write_payload, write_response_with_buffer, AgentRequest, AgentResponse,
    Identity, ProtoError,
};

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
    identity_cache_ms: Option<u64>,
}

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGN_TIME_NS: AtomicU64 = AtomicU64::new(0);
static SIGN_ERRORS: AtomicU64 = AtomicU64::new(0);
static METRICS_EVERY: AtomicU64 = AtomicU64::new(1000);
static MAX_SIGNERS: AtomicU64 = AtomicU64::new(0);
static CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static LIST_COUNT: AtomicU64 = AtomicU64::new(0);
static LIST_CACHE_HIT: AtomicU64 = AtomicU64::new(0);
static LIST_CACHE_STALE: AtomicU64 = AtomicU64::new(0);
static LIST_REFRESH: AtomicU64 = AtomicU64::new(0);
static LIST_ERRORS: AtomicU64 = AtomicU64::new(0);
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

#[derive(Debug)]
struct IdentityCache {
    payload: parking_lot::RwLock<Bytes>,
    last_refresh_ms: AtomicU64,
    ttl_ms: u64,
    has_snapshot: AtomicBool,
    refreshing: AtomicBool,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl IdentityCache {
    fn new(ttl_ms: u64) -> Self {
        let empty_payload = secretive_proto::encode_response(&AgentResponse::IdentitiesAnswer {
            identities: Vec::new(),
        });
        Self {
            payload: parking_lot::RwLock::new(empty_payload),
            last_refresh_ms: AtomicU64::new(0),
            ttl_ms,
            has_snapshot: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn get_payload_or_refresh(
        self: &Arc<Self>,
        registry: Arc<KeyStoreRegistry>,
    ) -> Result<Bytes, secretive_core::CoreError> {
        if self.ttl_ms == 0 {
            let _guard = self.refresh_lock.lock().await;
            return self.refresh_and_update(registry).await;
        }

        let now = now_ms();
        let last = self.last_refresh_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) <= self.ttl_ms {
            LIST_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
            return Ok(self.payload.read().clone());
        }

        if self.has_snapshot.load(Ordering::Relaxed) {
            LIST_CACHE_STALE.fetch_add(1, Ordering::Relaxed);
            if !self.refreshing.swap(true, Ordering::AcqRel) {
                let cache = Arc::clone(self);
                let registry = registry.clone();
                tokio::spawn(async move {
                    let _guard = cache.refresh_lock.lock().await;
                    let now = now_ms();
                    let last = cache.last_refresh_ms.load(Ordering::Relaxed);
                    if last != 0 && now.saturating_sub(last) <= cache.ttl_ms {
                        cache.refreshing.store(false, Ordering::Release);
                        return;
                    }
                    if let Err(err) = cache.refresh_and_update(registry).await {
                        warn!(?err, "failed to refresh identities");
                    }
                    cache.refreshing.store(false, Ordering::Release);
                });
            }
            return Ok(self.payload.read().clone());
        }

        let _guard = self.refresh_lock.lock().await;
        let now = now_ms();
        let last = self.last_refresh_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) <= self.ttl_ms {
            LIST_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
            return Ok(self.payload.read().clone());
        }

        self.refresh_and_update(registry).await
    }

    async fn update_from_identities(&self, identities: Vec<Identity>) {
        let payload = encode_identities_payload(identities);
        *self.payload.write() = payload;
        self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
        self.has_snapshot.store(true, Ordering::Relaxed);
        self.refreshing.store(false, Ordering::Release);
    }

    fn invalidate(&self) {
        self.last_refresh_ms.store(0, Ordering::Relaxed);
    }

    async fn refresh_and_update(
        &self,
        registry: Arc<KeyStoreRegistry>,
    ) -> Result<Bytes, secretive_core::CoreError> {
        let result = tokio::task::spawn_blocking(move || registry.list_identities()).await;
        match result {
            Ok(Ok(identities)) => {
                let payload = encode_identities_payload(map_identities(identities));
                *self.payload.write() = payload.clone();
                self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
                self.has_snapshot.store(true, Ordering::Relaxed);
                LIST_REFRESH.fetch_add(1, Ordering::Relaxed);
                Ok(payload)
            }
            Ok(Err(err)) => {
                LIST_ERRORS.fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
            Err(_) => {
                LIST_ERRORS.fetch_add(1, Ordering::Relaxed);
                Err(secretive_core::CoreError::Internal("identity task failed"))
            }
        }
    }
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
    info!(version = env!("CARGO_PKG_VERSION"), "secretive-agent starting");

    let args = parse_args();
    if args.help {
        print_help();
        return;
    }
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
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
    if let Some(identity_cache_ms) = args.identity_cache_ms {
        config.identity_cache_ms = Some(identity_cache_ms);
    }
    if config.max_signers.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_MAX_SIGNERS") {
            config.max_signers = value.parse().ok();
        }
    }
    if config.metrics_every.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_EVERY") {
            config.metrics_every = value.parse().ok();
        }
    }
    if config.watch_files.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_WATCH_FILES") {
            config.watch_files = parse_bool_env(&value);
        }
    }
    if config.identity_cache_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_IDENTITY_CACHE_MS") {
            config.identity_cache_ms = value.parse().ok();
        }
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

    let identity_cache_ms = config.identity_cache_ms.unwrap_or(1000);
    info!(identity_cache_ms, "identity cache ttl");
    let registry = Arc::new(registry);
    let identity_cache = Arc::new(IdentityCache::new(identity_cache_ms));
    if let Ok(identities) = registry.list_identities() {
        info!(count = identities.len(), "loaded identities");
        identity_cache
            .update_from_identities(map_identities(identities))
            .await;
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
        info!(count = watch_paths.len(), "watching key paths");

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
        match notify::recommended_watcher(move |res| {
            let _ = notify_tx.send(res);
        }) {
            Ok(mut watcher) => {
                for path in &watch_paths {
                    let mode = if path.is_dir() {
                        RecursiveMode::Recursive
                    } else {
                        RecursiveMode::NonRecursive
                    };
                    if let Err(err) = watcher.watch(path, mode) {
                        warn!(?err, path = %path.display(), "failed to watch key path");
                    }
                }
                _watchers.push(watcher);
            }
            Err(err) => {
                warn!(?err, "failed to initialize file watcher");
            }
        }

        let reloadable_stores = reloadable_stores.clone();
        let identity_cache = identity_cache.clone();
        let registry = registry.clone();
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
                match registry.list_identities() {
                    Ok(identities) => {
                        let count = identities.len();
                        identity_cache
                            .update_from_identities(map_identities(identities))
                            .await;
                        info!(count, "reloaded identities (watch)");
                    }
                    Err(err) => {
                        identity_cache.invalidate();
                        warn!(?err, "failed to refresh identities after reload");
                    }
                }
            }
        });
    } else if !watch_files {
        info!("file watching disabled");
    } else {
        info!("no file stores to watch");
    }

    #[cfg(unix)]
    if !reloadable_stores.is_empty() {
        let reloadable_stores = reloadable_stores.clone();
        let identity_cache = identity_cache.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::hangup()) {
                while stream.recv().await.is_some() {
                    for store in &reloadable_stores {
                        if let Err(err) = store.reload() {
                            warn!(?err, "failed to reload keys");
                        }
                    }
                    match registry.list_identities() {
                        Ok(identities) => {
                            let count = identities.len();
                            identity_cache
                                .update_from_identities(map_identities(identities))
                                .await;
                            info!(count, "reloaded identities");
                        }
                        Err(err) => {
                            identity_cache.invalidate();
                            warn!(?err, "failed to refresh identities after reload");
                        }
                    }
                }
            }
        });
    }

    let default_max_signers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .saturating_mul(4);
    let mut max_signers = config.max_signers.unwrap_or(default_max_signers);
    if max_signers == 0 {
        warn!("max_signers was 0; defaulting to 1");
        max_signers = 1;
    }
    info!(max_signers, "sign concurrency limit");
    MAX_SIGNERS.store(max_signers as u64, Ordering::Relaxed);
    let sign_semaphore = Arc::new(Semaphore::new(max_signers));

    let metrics_every = config.metrics_every.unwrap_or(1000);
    METRICS_EVERY.store(metrics_every, Ordering::Relaxed);
    if metrics_every == 0 {
        info!("signing metrics disabled");
    } else {
        info!(metrics_every, "signing metrics interval");
    }

    #[cfg(unix)]
    {
        let sign_semaphore = sign_semaphore.clone();
        let max_signers = max_signers as u64;
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::user_defined1()) {
                while stream.recv().await.is_some() {
                    let count = SIGN_COUNT.load(Ordering::Relaxed);
                    let errors = SIGN_ERRORS.load(Ordering::Relaxed);
                    let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
                    let avg = if count > 0 { total / count as f64 } else { 0.0 };
                    let available = sign_semaphore.available_permits() as u64;
                    let in_flight = max_signers.saturating_sub(available);
                    let list_count = LIST_COUNT.load(Ordering::Relaxed);
                    let list_hit = LIST_CACHE_HIT.load(Ordering::Relaxed);
                    let list_stale = LIST_CACHE_STALE.load(Ordering::Relaxed);
                    let list_refresh = LIST_REFRESH.load(Ordering::Relaxed);
                    let list_errors = LIST_ERRORS.load(Ordering::Relaxed);
                    let connections = CONNECTION_COUNT.load(Ordering::Relaxed);
                    let active_connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                    info!(
                        count,
                        errors,
                        avg_ns = avg,
                        in_flight,
                        max_signers,
                        connections,
                        active_connections,
                        list_count,
                        list_hit,
                        list_stale,
                        list_refresh,
                        list_errors,
                        "signing metrics snapshot"
                    );
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(config.socket_path);
        if let Err(err) =
            run_unix(socket_path, registry.clone(), sign_semaphore.clone(), identity_cache.clone())
                .await
        {
            error!(?err, "agent exited with error");
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = resolve_pipe_name(config.socket_path);
        if let Err(err) =
            run_windows(pipe_name, registry.clone(), sign_semaphore.clone(), identity_cache.clone())
                .await
        {
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
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<Config>(&contents) {
                Ok(config) => {
                    info!(path = %path, "loaded config");
                    return config;
                }
                Err(err) => {
                    warn!(?err, path = %path, "failed to parse config");
                }
            },
            Err(err) => {
                warn!(?err, path = %path, "failed to read config");
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
        identity_cache_ms: None,
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
    identity_cache_ms: Option<u64>,
    help: bool,
    version: bool,
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
        identity_cache_ms: None,
        help: false,
        version: false,
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
            "--identity-cache-ms" => {
                if let Some(value) = args.next() {
                    parsed.identity_cache_ms = value.parse().ok();
                }
            }
            "-h" | "--help" => parsed.help = true,
            "--version" => parsed.version = true,
            _ => {}
        }
    }

    parsed
}

fn parse_bool_env(value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn print_help() {
    println!("secretive-agent usage:\n");
    println!("  --config <path> --socket <path> --key <path>");
    println!("  --default-scan | --no-default-scan");
    println!("  --max-signers <n> --metrics-every <n>");
    println!("  --watch | --no-watch --pid-file <path>");
    println!("  --identity-cache-ms <n>\n");
    println!("  --version\n");
    println!("Notes:");
    println!("  Use JSON config for store definitions (see docs/RUST_CONFIG.md).");
    println!("  identity_cache_ms controls caching of list-identity responses.");
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
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
    identity_cache: Arc<IdentityCache>,
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
                        CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                        let registry = registry.clone();
                        let sign_semaphore = sign_semaphore.clone();
                        let identity_cache = identity_cache.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                handle_connection(stream, registry, sign_semaphore, identity_cache)
                                    .await
                            {
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
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
    identity_cache: Arc<IdentityCache>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    info!(pipe = %pipe_name, "secretive agent listening");

    loop {
        let server = ServerOptions::new().create(&pipe_name)?;
        server.connect().await?;
        let registry = registry.clone();
        let sign_semaphore = sign_semaphore.clone();
        let identity_cache = identity_cache.clone();
        CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(server, registry, sign_semaphore, identity_cache).await
            {
                warn!(?err, "connection error");
            }
        });
    }
}

async fn handle_connection<S>(
    stream: S,
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
    identity_cache: Arc<IdentityCache>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _guard = ConnectionGuard::acquire();
    let (mut reader, mut writer) = tokio::io::split(stream);

    let mut buffer = BytesMut::with_capacity(4096);
    let mut response_buffer = BytesMut::with_capacity(256);
    loop {
        let request = match read_request_with_buffer(&mut reader, &mut buffer).await {
            Ok(req) => req,
            Err(err) => {
                if matches!(err, ProtoError::UnexpectedEof) {
                    break;
                }
                warn!(?err, "failed to read request");
                break;
            }
        };

        match request {
            AgentRequest::RequestIdentities => {
                LIST_COUNT.fetch_add(1, Ordering::Relaxed);
                match identity_cache.get_payload_or_refresh(registry.clone()).await {
                    Ok(payload) => {
                        if let Err(err) = write_payload(&mut writer, &payload).await {
                            warn!(?err, "failed to write identities");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to list identities");
                        if let Err(err) = write_response_with_buffer(
                            &mut writer,
                            &AgentResponse::Failure,
                            &mut response_buffer,
                        )
                        .await
                        {
                            warn!(?err, "failed to write failure response");
                            break;
                        }
                    }
                }
            }
            _ => {
                let response =
                    handle_request(registry.clone(), request, sign_semaphore.clone()).await;
                if let Err(err) = write_response_with_buffer(
                    &mut writer,
                    &response,
                    &mut response_buffer,
                )
                .await
                {
                    warn!(?err, "failed to write response");
                    break;
                }
            }
        }
    }

    Ok(())
}

struct ConnectionGuard;

impl ConnectionGuard {
    fn acquire() -> Self {
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_request(
    registry: Arc<KeyStoreRegistry>,
    request: AgentRequest,
    sign_semaphore: Arc<Semaphore>,
) -> AgentResponse {
    match request {
        AgentRequest::RequestIdentities => AgentResponse::Failure,
        AgentRequest::SignRequest { key_blob, data, flags } => {
            let start = Instant::now();
            let permit = match sign_semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("signing semaphore closed");
                    SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
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
                        let errors = SIGN_ERRORS.load(Ordering::Relaxed);
                        let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
                        let avg = total / count as f64;
                        let max_signers = MAX_SIGNERS.load(Ordering::Relaxed);
                        let available = sign_semaphore.available_permits() as u64;
                        let in_flight = max_signers.saturating_sub(available);
                        info!(
                            count,
                            errors,
                            avg_ns = avg,
                            in_flight,
                            max_signers,
                            "signing metrics"
                        );
                    }
                    AgentResponse::SignResponse { signature_blob }
                }
                Ok(Err(err)) => {
                    warn!(?err, "sign request failed");
                    SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::Failure
                }
                Err(err) => {
                    warn!(?err, "sign worker failed");
                    SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
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

fn map_identities(identities: Vec<KeyIdentity>) -> Vec<Identity> {
    identities
        .into_iter()
        .map(|id| Identity {
            key_blob: id.key_blob,
            comment: id.comment,
        })
        .collect()
}

fn encode_identities_payload(identities: Vec<Identity>) -> Bytes {
    secretive_proto::encode_response(&AgentResponse::IdentitiesAnswer { identities })
}

fn now_ms() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}
