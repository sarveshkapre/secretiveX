use arc_swap::ArcSwap;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::time::Duration;

use directories::BaseDirs;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use bytes::{BufMut, Bytes, BytesMut};
use notify::{RecursiveMode, Watcher};
use secretive_core::{
    EmptyStore, FileStore, FileStoreConfig, KeyIdentity, KeyStoreRegistry, Pkcs11Config,
    Pkcs11Store,
};
use secretive_proto::{
    write_response_with_buffer, AgentResponse, MessageType, ProtoError, MAX_FRAME_LEN,
};

#[derive(Debug, Deserialize)]
struct Config {
    profile: Option<String>,
    socket_path: Option<String>,
    socket_backlog: Option<u32>,
    key_paths: Option<Vec<String>>,
    scan_default_dir: Option<bool>,
    stores: Option<Vec<StoreConfig>>,
    max_signers: Option<usize>,
    max_connections: Option<usize>,
    max_blocking_threads: Option<usize>,
    worker_threads: Option<usize>,
    watch_files: Option<bool>,
    watch_debounce_ms: Option<u64>,
    metrics_every: Option<u64>,
    metrics_json: Option<bool>,
    sign_timeout_ms: Option<u64>,
    pid_file: Option<String>,
    identity_cache_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    inline_sign: Option<bool>,
}

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGN_TIME_NS: AtomicU64 = AtomicU64::new(0);
static SIGN_ERRORS: AtomicU64 = AtomicU64::new(0);
static SIGN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static METRICS_EVERY: AtomicU64 = AtomicU64::new(1000);
static METRICS_JSON: AtomicBool = AtomicBool::new(false);
static MAX_SIGNERS: AtomicU64 = AtomicU64::new(0);
static MAX_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);
static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static MAX_ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static CONNECTION_REJECTED: AtomicU64 = AtomicU64::new(0);
static LIST_COUNT: AtomicU64 = AtomicU64::new(0);
static LIST_CACHE_HIT: AtomicU64 = AtomicU64::new(0);
static LIST_CACHE_STALE: AtomicU64 = AtomicU64::new(0);
static LIST_REFRESH: AtomicU64 = AtomicU64::new(0);
static LIST_ERRORS: AtomicU64 = AtomicU64::new(0);
static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static FAILURE_FRAME: OnceLock<Bytes> = OnceLock::new();

#[derive(Debug)]
struct IdentityCache {
    payload: ArcSwap<Bytes>,
    last_refresh_ms: AtomicU64,
    ttl_ms: u64,
    has_snapshot: AtomicBool,
    refreshing: AtomicBool,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl IdentityCache {
    fn new(ttl_ms: u64) -> Self {
        let empty_payload = encode_identities_frame_from_keyidentities(&[])
            .expect("empty identity frame encoding failed");
        Self {
            payload: ArcSwap::from_pointee(empty_payload),
            last_refresh_ms: AtomicU64::new(0),
            ttl_ms,
            has_snapshot: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn get_payload_or_refresh(
        self: &Arc<Self>,
        registry: &Arc<KeyStoreRegistry>,
    ) -> Result<Arc<Bytes>, secretive_core::CoreError> {
        if self.ttl_ms == 0 {
            let _guard = self.refresh_lock.lock().await;
            return self.refresh_and_update(Arc::clone(registry)).await;
        }

        let now = now_ms();
        let last = self.last_refresh_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) <= self.ttl_ms {
            LIST_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
            return Ok(self.payload.load_full());
        }

        if self.has_snapshot.load(Ordering::Relaxed) {
            LIST_CACHE_STALE.fetch_add(1, Ordering::Relaxed);
            if !self.refreshing.swap(true, Ordering::AcqRel) {
                let cache = Arc::clone(self);
                let registry = Arc::clone(registry);
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
            return Ok(self.payload.load_full());
        }

        let _guard = self.refresh_lock.lock().await;
        let now = now_ms();
        let last = self.last_refresh_ms.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) <= self.ttl_ms {
            LIST_CACHE_HIT.fetch_add(1, Ordering::Relaxed);
            return Ok(self.payload.load_full());
        }

        self.refresh_and_update(Arc::clone(registry)).await
    }

    async fn update_from_identities(&self, identities: Vec<KeyIdentity>) {
        match encode_identities_frame_from_keyidentities(&identities) {
            Ok(payload) => {
                self.payload.store(Arc::new(payload));
                self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
                self.has_snapshot.store(true, Ordering::Relaxed);
                LIST_REFRESH.fetch_add(1, Ordering::Relaxed);
                self.refreshing.store(false, Ordering::Release);
            }
            Err(err) => {
                LIST_ERRORS.fetch_add(1, Ordering::Relaxed);
                warn!(?err, "failed to encode identities");
                self.refreshing.store(false, Ordering::Release);
            }
        }
    }

    fn invalidate(&self) {
        self.last_refresh_ms.store(0, Ordering::Relaxed);
    }

    async fn refresh_and_update(
        &self,
        registry: Arc<KeyStoreRegistry>,
    ) -> Result<Arc<Bytes>, secretive_core::CoreError> {
        let result = tokio::task::spawn_blocking(move || registry.list_identities()).await;
        match result {
            Ok(Ok(identities)) => {
                let payload = match encode_identities_frame_from_keyidentities(&identities) {
                    Ok(payload) => payload,
                    Err(err) => {
                        LIST_ERRORS.fetch_add(1, Ordering::Relaxed);
                        warn!(?err, "failed to encode identities");
                        return Err(secretive_core::CoreError::Internal(
                            "identity frame too large",
                        ));
                    }
                };
                let payload = Arc::new(payload);
                self.payload.store(Arc::clone(&payload));
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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "secretive-agent starting"
    );

    let args = parse_args();
    if args.help {
        print_help();
        return;
    }
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let check_config = args.check_config;
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
    if let Some(max_connections) = args.max_connections {
        config.max_connections = Some(max_connections);
    }
    if let Some(max_blocking_threads) = args.max_blocking_threads {
        config.max_blocking_threads = Some(max_blocking_threads);
    }
    if let Some(worker_threads) = args.worker_threads {
        config.worker_threads = Some(worker_threads);
    }
    if let Some(watch_files) = args.watch_files {
        config.watch_files = Some(watch_files);
    }
    if let Some(watch_debounce_ms) = args.watch_debounce_ms {
        config.watch_debounce_ms = Some(watch_debounce_ms);
    }
    if let Some(metrics_every) = args.metrics_every {
        config.metrics_every = Some(metrics_every);
    }
    if let Some(metrics_json) = args.metrics_json {
        config.metrics_json = Some(metrics_json);
    }
    if let Some(sign_timeout_ms) = args.sign_timeout_ms {
        config.sign_timeout_ms = Some(sign_timeout_ms);
    }
    if let Some(pid_file) = args.pid_file {
        config.pid_file = Some(pid_file);
    }
    if let Some(identity_cache_ms) = args.identity_cache_ms {
        config.identity_cache_ms = Some(identity_cache_ms);
    }
    if let Some(socket_backlog) = args.socket_backlog {
        config.socket_backlog = Some(socket_backlog);
    }
    if let Some(idle_timeout_ms) = args.idle_timeout_ms {
        config.idle_timeout_ms = Some(idle_timeout_ms);
    }
    if let Some(inline_sign) = args.inline_sign {
        config.inline_sign = Some(inline_sign);
    }
    if let Some(profile) = args.profile {
        config.profile = Some(profile);
    }
    if config.max_signers.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_MAX_SIGNERS") {
            config.max_signers = value.parse().ok();
        }
    }
    if config.max_connections.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_MAX_CONNECTIONS") {
            config.max_connections = value.parse().ok();
        }
    }
    if config.metrics_every.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_EVERY") {
            config.metrics_every = value.parse().ok();
        }
    }
    if config.metrics_json.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_JSON") {
            config.metrics_json = parse_bool_env(&value);
        }
    }
    if config.sign_timeout_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_SIGN_TIMEOUT_MS") {
            config.sign_timeout_ms = value.parse().ok();
        }
    }
    if config.watch_files.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_WATCH_FILES") {
            config.watch_files = parse_bool_env(&value);
        }
    }
    if config.watch_debounce_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_WATCH_DEBOUNCE_MS") {
            config.watch_debounce_ms = value.parse().ok();
        }
    }
    if config.identity_cache_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_IDENTITY_CACHE_MS") {
            config.identity_cache_ms = value.parse().ok();
        }
    }
    if config.max_blocking_threads.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_MAX_BLOCKING_THREADS") {
            config.max_blocking_threads = value.parse().ok();
        }
    }
    if config.worker_threads.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_WORKER_THREADS") {
            config.worker_threads = value.parse().ok();
        }
    }
    if config.socket_backlog.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_SOCKET_BACKLOG") {
            config.socket_backlog = value.parse().ok();
        }
    }
    if config.idle_timeout_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_IDLE_TIMEOUT_MS") {
            config.idle_timeout_ms = value.parse().ok();
        }
    }
    if config.inline_sign.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_INLINE_SIGN") {
            config.inline_sign = parse_bool_env(&value);
        }
    }
    if config.profile.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_PROFILE") {
            config.profile = Some(value);
        }
    }
    apply_profile_defaults(&mut config);
    if check_config {
        let validation = validate_config(&config);
        for warning in validation.warnings {
            eprintln!("warning: {warning}");
        }
        if validation.errors.is_empty() {
            println!("config validation OK");
            return;
        }
        eprintln!("config validation failed:");
        for error in validation.errors {
            eprintln!("- {error}");
        }
        std::process::exit(2);
    }

    let max_signers = compute_max_signers(&config);
    let max_blocking_threads = config.max_blocking_threads.unwrap_or(max_signers).max(1);
    info!(max_blocking_threads, "blocking thread pool size");
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime
        .enable_all()
        .max_blocking_threads(max_blocking_threads);
    if let Some(worker_threads) = config.worker_threads {
        let worker_threads = if worker_threads == 0 {
            warn!("worker_threads was 0; defaulting to 1");
            1
        } else {
            worker_threads
        };
        info!(worker_threads, "worker thread count");
        runtime.worker_threads(worker_threads);
    }
    let runtime = runtime.build().expect("failed to build tokio runtime");

    runtime.block_on(run_async(config, max_signers));
}

async fn run_async(mut config: Config, max_signers: usize) {
    let _pid_guard = match config.pid_file.clone() {
        Some(path) => PidFileGuard::create(path).ok(),
        None => None,
    };

    let mut registry = KeyStoreRegistry::new();

    let stores = if let Some(stores) = config.stores.take() {
        stores
    } else {
        vec![StoreConfig::File {
            paths: config.key_paths.clone(),
            scan_default_dir: config.scan_default_dir,
        }]
    };

    let mut reloadable_stores: Vec<Arc<FileStore>> = Vec::with_capacity(stores.len());
    for store in stores {
        match store {
            StoreConfig::File {
                paths,
                scan_default_dir,
            } => {
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
            StoreConfig::Pkcs11 {
                module_path,
                slot,
                pin_env,
            } => {
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
    let reloadable_stores = Arc::new(reloadable_stores);

    let identity_cache_ms = config.identity_cache_ms.unwrap_or(1000);
    info!(identity_cache_ms, "identity cache ttl");
    let registry = Arc::new(registry);
    let identity_cache = Arc::new(IdentityCache::new(identity_cache_ms));
    let idle_timeout = config.idle_timeout_ms.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(Duration::from_millis(value))
        }
    });
    if let Some(timeout) = idle_timeout {
        info!(
            idle_timeout_ms = timeout.as_millis(),
            "connection idle timeout"
        );
    } else {
        info!("connection idle timeout disabled");
    }
    let inline_sign = config.inline_sign.unwrap_or(false);
    if inline_sign {
        info!("inline signing enabled");
    } else {
        info!("inline signing disabled");
    }
    let registry_clone = registry.clone();
    match tokio::task::spawn_blocking(move || registry_clone.list_identities()).await {
        Ok(Ok(identities)) => {
            info!(count = identities.len(), "loaded identities");
            identity_cache.update_from_identities(identities).await;
        }
        Ok(Err(err)) => {
            warn!(?err, "failed to load identities on startup");
        }
        Err(err) => {
            warn!(?err, "identity load task failed");
        }
    }

    let mut _watchers = Vec::new();
    let watch_files = config.watch_files.unwrap_or(true);
    if watch_files && !reloadable_stores.is_empty() {
        use std::collections::HashMap;

        let mut raw_paths = Vec::new();
        for store in reloadable_stores.iter() {
            let paths = store.watch_paths();
            raw_paths.reserve(paths.len());
            raw_paths.extend(paths);
        }
        let mut watch_targets: HashMap<PathBuf, RecursiveMode> =
            HashMap::with_capacity(raw_paths.len());
        for path in raw_paths {
            let meta = path.metadata();
            if meta.as_ref().map(|m| m.is_file()).unwrap_or(false) {
                let target = path.parent().unwrap_or(&path).to_path_buf();
                watch_targets
                    .entry(target)
                    .and_modify(|mode| {
                        if matches!(mode, RecursiveMode::Recursive) {
                            return;
                        }
                        *mode = RecursiveMode::NonRecursive;
                    })
                    .or_insert(RecursiveMode::NonRecursive);
            } else if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                watch_targets
                    .entry(path)
                    .and_modify(|mode| {
                        if matches!(mode, RecursiveMode::Recursive) {
                            return;
                        }
                        *mode = RecursiveMode::Recursive;
                    })
                    .or_insert(RecursiveMode::Recursive);
            } else {
                let target = path.parent().unwrap_or(&path).to_path_buf();
                watch_targets
                    .entry(target)
                    .and_modify(|mode| {
                        if matches!(mode, RecursiveMode::Recursive) {
                            return;
                        }
                        *mode = RecursiveMode::NonRecursive;
                    })
                    .or_insert(RecursiveMode::NonRecursive);
            }
        }

        info!(count = watch_targets.len(), "watching key paths");

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();
        match notify::recommended_watcher(move |res| {
            let _ = notify_tx.send(res);
        }) {
            Ok(mut watcher) => {
                for (path, mode) in &watch_targets {
                    if let Err(err) = watcher.watch(path, *mode) {
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
        let debounce_ms = config.watch_debounce_ms.unwrap_or(200).max(1);
        info!(watch_debounce_ms = debounce_ms, "watch debounce");
        tokio::spawn(async move {
            let debounce = Duration::from_millis(debounce_ms);
            loop {
                let Some(_event) = notify_rx.recv().await else {
                    break;
                };
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

                let stores = reloadable_stores.clone();
                let registry = registry.clone();
                let reload = tokio::task::spawn_blocking(move || {
                    for store in stores.iter() {
                        if let Err(err) = store.reload() {
                            warn!(?err, "failed to reload keys");
                        }
                    }
                    registry.list_identities()
                })
                .await;

                match reload {
                    Ok(Ok(identities)) => {
                        let count = identities.len();
                        identity_cache.update_from_identities(identities).await;
                        info!(count, "reloaded identities (watch)");
                    }
                    Ok(Err(err)) => {
                        identity_cache.invalidate();
                        warn!(?err, "failed to refresh identities after reload");
                    }
                    Err(err) => {
                        identity_cache.invalidate();
                        warn!(?err, "reload task failed");
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
                    let stores = reloadable_stores.clone();
                    let registry = registry.clone();
                    let reload = tokio::task::spawn_blocking(move || {
                        for store in stores.iter() {
                            if let Err(err) = store.reload() {
                                warn!(?err, "failed to reload keys");
                            }
                        }
                        registry.list_identities()
                    })
                    .await;

                    match reload {
                        Ok(Ok(identities)) => {
                            let count = identities.len();
                            identity_cache.update_from_identities(identities).await;
                            info!(count, "reloaded identities");
                        }
                        Ok(Err(err)) => {
                            identity_cache.invalidate();
                            warn!(?err, "failed to refresh identities after reload");
                        }
                        Err(err) => {
                            identity_cache.invalidate();
                            warn!(?err, "reload task failed");
                        }
                    }
                }
            }
        });
    }

    info!(max_signers, "sign concurrency limit");
    MAX_SIGNERS.store(max_signers as u64, Ordering::Relaxed);
    let sign_semaphore = Arc::new(Semaphore::new(max_signers));

    let max_connections = config.max_connections.unwrap_or(0);
    MAX_CONNECTIONS.store(max_connections as u64, Ordering::Relaxed);
    let connection_semaphore = if max_connections == 0 {
        info!("connection limit disabled");
        None
    } else {
        info!(max_connections, "connection limit");
        Some(Arc::new(Semaphore::new(max_connections)))
    };

    let metrics_every = config.metrics_every.unwrap_or(1000);
    METRICS_EVERY.store(metrics_every, Ordering::Relaxed);
    let metrics_json = config.metrics_json.unwrap_or(false);
    METRICS_JSON.store(metrics_json, Ordering::Relaxed);
    if metrics_json {
        info!("metrics format: json");
    } else {
        info!("metrics format: log");
    }
    if metrics_every == 0 {
        info!("signing metrics disabled");
    } else {
        info!(metrics_every, "signing metrics interval");
    }
    let sign_timeout = config.sign_timeout_ms.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(Duration::from_millis(value))
        }
    });
    if let Some(timeout) = sign_timeout {
        info!(sign_timeout_ms = timeout.as_millis(), "sign timeout");
    } else {
        info!("sign timeout disabled");
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
                    let timeouts = SIGN_TIMEOUTS.load(Ordering::Relaxed);
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
                    let max_active_connections = MAX_ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                    let max_connections = MAX_CONNECTIONS.load(Ordering::Relaxed);
                    let connection_rejected = CONNECTION_REJECTED.load(Ordering::Relaxed);
                    let snapshot = SignMetricsSnapshot {
                        count,
                        errors,
                        timeouts,
                        avg_ns: avg,
                        in_flight,
                        max_signers,
                        connections,
                        active_connections,
                        max_active_connections,
                        max_connections,
                        connection_rejected,
                        list_count,
                        list_hit,
                        list_stale,
                        list_refresh,
                        list_errors,
                    };
                    emit_sign_metrics("snapshot", &snapshot);
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let socket_path = resolve_socket_path(config.socket_path);
        let socket_backlog = config.socket_backlog;
        if let Err(err) = run_unix(
            socket_path,
            socket_backlog,
            registry.clone(),
            sign_semaphore.clone(),
            connection_semaphore.clone(),
            identity_cache.clone(),
            idle_timeout,
            inline_sign,
            sign_timeout,
        )
        .await
        {
            error!(?err, "agent exited with error");
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = resolve_pipe_name(config.socket_path);
        if let Err(err) = run_windows(
            pipe_name,
            registry.clone(),
            sign_semaphore.clone(),
            connection_semaphore.clone(),
            identity_cache.clone(),
            idle_timeout,
            inline_sign,
            sign_timeout,
        )
        .await
        {
            error!(?err, "agent exited with error");
        }
    }
}

fn compute_max_signers(config: &Config) -> usize {
    let default_max_signers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .saturating_mul(4);
    let mut max_signers = config.max_signers.unwrap_or(default_max_signers);
    if max_signers == 0 {
        warn!("max_signers was 0; defaulting to 1");
        max_signers = 1;
    }
    max_signers
}

#[derive(Debug, Clone, Copy)]
enum ConfigProfile {
    Balanced,
    Fanout,
    LowMemory,
}

impl ConfigProfile {
    fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("balanced") {
            return Some(Self::Balanced);
        }
        if value.eq_ignore_ascii_case("fanout") {
            return Some(Self::Fanout);
        }
        if value.eq_ignore_ascii_case("low-memory")
            || value.eq_ignore_ascii_case("low_memory")
            || value.eq_ignore_ascii_case("lowmemory")
        {
            return Some(Self::LowMemory);
        }
        None
    }
}

fn apply_profile_defaults(config: &mut Config) {
    let Some(profile_name) = config.profile.as_deref() else {
        return;
    };
    let Some(profile) = ConfigProfile::parse(profile_name) else {
        warn!(profile = profile_name, "unknown config profile");
        return;
    };

    let cores = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4);

    match profile {
        ConfigProfile::Balanced => {
            if config.max_connections.is_none() {
                config.max_connections = Some(1024);
            }
            if config.sign_timeout_ms.is_none() {
                config.sign_timeout_ms = Some(500);
            }
            if config.identity_cache_ms.is_none() {
                config.identity_cache_ms = Some(1000);
            }
            if config.watch_debounce_ms.is_none() {
                config.watch_debounce_ms = Some(200);
            }
            if config.max_signers.is_none() {
                config.max_signers = Some(cores.saturating_mul(4).max(1));
            }
            if config.max_blocking_threads.is_none() {
                config.max_blocking_threads = config.max_signers;
            }
        }
        ConfigProfile::Fanout => {
            if config.max_signers.is_none() {
                config.max_signers = Some(cores.saturating_mul(8).max(8));
            }
            if config.max_blocking_threads.is_none() {
                config.max_blocking_threads = config.max_signers;
            }
            if config.max_connections.is_none() {
                config.max_connections = Some(8192);
            }
            if config.worker_threads.is_none() {
                config.worker_threads = Some(cores.max(1));
            }
            if config.identity_cache_ms.is_none() {
                config.identity_cache_ms = Some(5000);
            }
            if config.sign_timeout_ms.is_none() {
                config.sign_timeout_ms = Some(250);
            }
            if config.socket_backlog.is_none() {
                config.socket_backlog = Some(2048);
            }
            if config.idle_timeout_ms.is_none() {
                config.idle_timeout_ms = Some(10000);
            }
        }
        ConfigProfile::LowMemory => {
            if config.max_signers.is_none() {
                config.max_signers = Some(cores.saturating_mul(2).max(2));
            }
            if config.max_blocking_threads.is_none() {
                config.max_blocking_threads = config.max_signers;
            }
            if config.max_connections.is_none() {
                config.max_connections = Some(256);
            }
            if config.identity_cache_ms.is_none() {
                config.identity_cache_ms = Some(250);
            }
            if config.sign_timeout_ms.is_none() {
                config.sign_timeout_ms = Some(2000);
            }
            if config.watch_debounce_ms.is_none() {
                config.watch_debounce_ms = Some(1000);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SignMetricsSnapshot {
    count: u64,
    errors: u64,
    timeouts: u64,
    avg_ns: f64,
    in_flight: u64,
    max_signers: u64,
    connections: u64,
    active_connections: u64,
    max_active_connections: u64,
    max_connections: u64,
    connection_rejected: u64,
    list_count: u64,
    list_hit: u64,
    list_stale: u64,
    list_refresh: u64,
    list_errors: u64,
}

fn format_metrics_json(kind: &str, metrics: &SignMetricsSnapshot) -> String {
    serde_json::json!({
        "kind": kind,
        "count": metrics.count,
        "errors": metrics.errors,
        "timeouts": metrics.timeouts,
        "avg_ns": metrics.avg_ns,
        "in_flight": metrics.in_flight,
        "max_signers": metrics.max_signers,
        "connections": metrics.connections,
        "active_connections": metrics.active_connections,
        "max_active_connections": metrics.max_active_connections,
        "max_connections": metrics.max_connections,
        "connection_rejected": metrics.connection_rejected,
        "list_count": metrics.list_count,
        "list_hit": metrics.list_hit,
        "list_stale": metrics.list_stale,
        "list_refresh": metrics.list_refresh,
        "list_errors": metrics.list_errors
    })
    .to_string()
}

fn emit_sign_metrics(kind: &str, metrics: &SignMetricsSnapshot) {
    if METRICS_JSON.load(Ordering::Relaxed) {
        let payload = format_metrics_json(kind, metrics);
        info!(kind, metrics_json = %payload, "signing metrics");
        return;
    }

    let message = if kind == "snapshot" {
        "signing metrics snapshot"
    } else {
        "signing metrics"
    };

    info!(
        count = metrics.count,
        errors = metrics.errors,
        timeouts = metrics.timeouts,
        avg_ns = metrics.avg_ns,
        in_flight = metrics.in_flight,
        max_signers = metrics.max_signers,
        connections = metrics.connections,
        active_connections = metrics.active_connections,
        max_active_connections = metrics.max_active_connections,
        max_connections = metrics.max_connections,
        connection_rejected = metrics.connection_rejected,
        list_count = metrics.list_count,
        list_hit = metrics.list_hit,
        list_stale = metrics.list_stale,
        list_refresh = metrics.list_refresh,
        list_errors = metrics.list_errors,
        "{}",
        message
    );
}

#[derive(Debug, Default)]
struct ConfigValidation {
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn validate_config(config: &Config) -> ConfigValidation {
    let mut out = ConfigValidation::default();

    if matches!(config.max_signers, Some(0)) {
        out.errors
            .push("max_signers must be greater than 0".to_string());
    }
    if matches!(config.max_blocking_threads, Some(0)) {
        out.errors
            .push("max_blocking_threads must be greater than 0".to_string());
    }
    if matches!(config.worker_threads, Some(0)) {
        out.errors
            .push("worker_threads must be greater than 0".to_string());
    }
    if matches!(config.watch_debounce_ms, Some(0)) {
        out.errors
            .push("watch_debounce_ms must be greater than 0".to_string());
    }

    let mut has_key_source = false;
    let mut has_pkcs11 = false;

    if let Some(stores) = &config.stores {
        if stores.is_empty() {
            out.errors.push("stores must not be empty".to_string());
        }
        for (idx, store) in stores.iter().enumerate() {
            match store {
                StoreConfig::File {
                    paths,
                    scan_default_dir,
                } => {
                    let has_paths = paths
                        .as_ref()
                        .map(|value| !value.is_empty())
                        .unwrap_or(false);
                    let scan_default_dir = scan_default_dir.unwrap_or(true);
                    if has_paths || scan_default_dir {
                        has_key_source = true;
                    } else {
                        out.warnings.push(format!(
                            "stores[{idx}] file store has no paths and scan_default_dir=false; it will load no keys"
                        ));
                    }
                }
                StoreConfig::SecureEnclave => {
                    out.errors.push(format!(
                        "stores[{idx}] secure_enclave is not implemented yet"
                    ));
                }
                StoreConfig::Pkcs11 {
                    module_path,
                    pin_env: _,
                    slot: _,
                } => {
                    has_key_source = true;
                    has_pkcs11 = true;
                    if !cfg!(feature = "pkcs11") {
                        out.errors.push(format!(
                            "stores[{idx}] pkcs11 requires building secretive-core with feature \"pkcs11\""
                        ));
                    }
                    if module_path.trim().is_empty() {
                        out.errors.push(format!(
                            "stores[{idx}] pkcs11 module_path must not be empty"
                        ));
                    } else if !Path::new(module_path).exists() {
                        out.warnings.push(format!(
                            "stores[{idx}] pkcs11 module_path does not exist on this machine: {module_path}"
                        ));
                    }
                }
            }
        }
    } else {
        let has_paths = config
            .key_paths
            .as_ref()
            .map(|value| !value.is_empty())
            .unwrap_or(false);
        let scan_default_dir = config.scan_default_dir.unwrap_or(true);
        has_key_source = has_paths || scan_default_dir;
    }

    if !has_key_source {
        out.warnings.push(
            "configuration defines no key source; list/sign requests will return no identities"
                .to_string(),
        );
    }

    if config.inline_sign == Some(true) && has_pkcs11 {
        out.warnings.push(
            "inline_sign=true with pkcs11 store may increase latency due to token I/O on runtime threads"
                .to_string(),
        );
    }

    out
}

fn load_config(path_override: Option<&str>) -> Config {
    let path = path_override
        .map(|value| value.to_string())
        .or_else(|| std::env::var("SECRETIVE_CONFIG").ok())
        .or_else(|| default_config_path().map(|path| path.display().to_string()));
    if let Some(path) = path {
        match std::fs::read(&path) {
            Ok(contents) => match serde_json::from_slice::<Config>(&contents) {
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
        profile: None,
        socket_path: None,
        socket_backlog: None,
        key_paths: None,
        scan_default_dir: None,
        stores: None,
        max_signers: None,
        max_connections: None,
        max_blocking_threads: None,
        worker_threads: None,
        watch_files: None,
        watch_debounce_ms: None,
        metrics_every: None,
        metrics_json: None,
        sign_timeout_ms: None,
        pid_file: None,
        identity_cache_ms: None,
        idle_timeout_ms: None,
        inline_sign: None,
    }
}

fn default_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("secretive").join("agent.json"));
    }
    BaseDirs::new().map(|dirs| dirs.config_dir().join("secretive").join("agent.json"))
}

struct Args {
    profile: Option<String>,
    config_path: Option<String>,
    socket_path: Option<String>,
    socket_backlog: Option<u32>,
    key_paths: Vec<String>,
    scan_default_dir: Option<bool>,
    max_signers: Option<usize>,
    max_connections: Option<usize>,
    max_blocking_threads: Option<usize>,
    worker_threads: Option<usize>,
    watch_files: Option<bool>,
    watch_debounce_ms: Option<u64>,
    metrics_every: Option<u64>,
    metrics_json: Option<bool>,
    pid_file: Option<String>,
    identity_cache_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    inline_sign: Option<bool>,
    sign_timeout_ms: Option<u64>,
    check_config: bool,
    help: bool,
    version: bool,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        profile: None,
        config_path: None,
        socket_path: None,
        socket_backlog: None,
        key_paths: Vec::new(),
        scan_default_dir: None,
        max_signers: None,
        max_connections: None,
        max_blocking_threads: None,
        worker_threads: None,
        watch_files: None,
        watch_debounce_ms: None,
        metrics_every: None,
        metrics_json: None,
        pid_file: None,
        identity_cache_ms: None,
        idle_timeout_ms: None,
        inline_sign: None,
        sign_timeout_ms: None,
        check_config: false,
        help: false,
        version: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => parsed.profile = args.next(),
            "--config" => parsed.config_path = args.next(),
            "--socket" => parsed.socket_path = args.next(),
            "--socket-backlog" => {
                if let Some(value) = args.next() {
                    parsed.socket_backlog = value.parse().ok();
                }
            }
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
            "--max-connections" => {
                if let Some(value) = args.next() {
                    parsed.max_connections = value.parse().ok();
                }
            }
            "--max-blocking-threads" => {
                if let Some(value) = args.next() {
                    parsed.max_blocking_threads = value.parse().ok();
                }
            }
            "--worker-threads" => {
                if let Some(value) = args.next() {
                    parsed.worker_threads = value.parse().ok();
                }
            }
            "--watch" => parsed.watch_files = Some(true),
            "--no-watch" => parsed.watch_files = Some(false),
            "--watch-debounce-ms" => {
                if let Some(value) = args.next() {
                    parsed.watch_debounce_ms = value.parse().ok();
                }
            }
            "--metrics-every" => {
                if let Some(value) = args.next() {
                    parsed.metrics_every = value.parse().ok();
                }
            }
            "--metrics-json" => parsed.metrics_json = Some(true),
            "--no-metrics-json" => parsed.metrics_json = Some(false),
            "--sign-timeout-ms" => {
                if let Some(value) = args.next() {
                    parsed.sign_timeout_ms = value.parse().ok();
                }
            }
            "--pid-file" => parsed.pid_file = args.next(),
            "--identity-cache-ms" => {
                if let Some(value) = args.next() {
                    parsed.identity_cache_ms = value.parse().ok();
                }
            }
            "--idle-timeout-ms" => {
                if let Some(value) = args.next() {
                    parsed.idle_timeout_ms = value.parse().ok();
                }
            }
            "--inline-sign" => parsed.inline_sign = Some(true),
            "--no-inline-sign" => parsed.inline_sign = Some(false),
            "--check-config" => parsed.check_config = true,
            "-h" | "--help" => parsed.help = true,
            "--version" => parsed.version = true,
            _ => {}
        }
    }

    parsed
}

fn parse_bool_env(value: &str) -> Option<bool> {
    let trimmed = value.trim();
    match trimmed {
        "1" => return Some(true),
        "0" => return Some(false),
        _ => {}
    }
    if trimmed.eq_ignore_ascii_case("true")
        || trimmed.eq_ignore_ascii_case("yes")
        || trimmed.eq_ignore_ascii_case("on")
    {
        return Some(true);
    }
    if trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("no")
        || trimmed.eq_ignore_ascii_case("off")
    {
        return Some(false);
    }
    None
}

fn print_help() {
    println!("secretive-agent usage:\n");
    println!("  --profile <balanced|fanout|low-memory>");
    println!("  --config <path> --socket <path> --key <path>");
    println!("  --socket-backlog <n>");
    println!("  --default-scan | --no-default-scan");
    println!(
        "  --max-signers <n> --max-connections <n> --max-blocking-threads <n> --worker-threads <n>"
    );
    println!("  --metrics-every <n>");
    println!("  --metrics-json | --no-metrics-json");
    println!("  --sign-timeout-ms <n>");
    println!("  --watch | --no-watch --watch-debounce-ms <n> --pid-file <path>");
    println!("  --identity-cache-ms <n>");
    println!("  --inline-sign | --no-inline-sign");
    println!("  --idle-timeout-ms <n>\n");
    println!("  --check-config");
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
        return normalize_pipe_name(path);
    }
    if let Ok(path) = std::env::var("SECRETIVE_PIPE") {
        return normalize_pipe_name(path);
    }
    r"\\.\pipe\secretive-agent".to_string()
}

#[cfg(windows)]
fn normalize_pipe_name(value: String) -> String {
    const PREFIX: &str = r"\\.\pipe\";
    if value.starts_with(PREFIX) {
        return value;
    }
    let trimmed = value.trim_start_matches('\\').trim_start_matches('/');
    let trimmed = trimmed
        .strip_prefix("pipe\\")
        .or_else(|| trimmed.strip_prefix("pipe/"))
        .unwrap_or(trimmed);
    let mut out = String::with_capacity(PREFIX.len() + trimmed.len());
    out.push_str(PREFIX);
    out.push_str(trimmed);
    out
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
    socket_backlog: Option<u32>,
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
    connection_semaphore: Option<Arc<Semaphore>>,
    identity_cache: Arc<IdentityCache>,
    idle_timeout: Option<Duration>,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener as StdUnixListener;
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

    let std_listener = StdUnixListener::bind(&socket_path)?;
    if let Some(backlog) = socket_backlog.filter(|value| *value > 0) {
        info!(backlog, "socket backlog override");
        let backlog = backlog.min(i32::MAX as u32) as libc::c_int;
        let rc = unsafe { libc::listen(std_listener.as_raw_fd(), backlog) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;
    if let Err(err) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
    {
        warn!(?err, "failed to set socket permissions");
    }
    info!(path = %socket_path.display(), "secretive agent listening");

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    if let Ok(mut sigterm) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::spawn(async move {
            let _ = sigterm.recv().await;
            let _ = shutdown_tx.send(());
        });
    }
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let connection_permit = if let Some(semaphore) =
                            connection_semaphore.as_ref()
                        {
                            match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => {
                                    let rejected =
                                        CONNECTION_REJECTED.fetch_add(1, Ordering::Relaxed) + 1;
                                    if rejected % 100 == 0 {
                                        warn!(rejected, "connection limit reached");
                                    }
                                    continue;
                                }
                            }
                        } else {
                            None
                        };
                        CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                        let registry = registry.clone();
                        let sign_semaphore = sign_semaphore.clone();
                        let identity_cache = identity_cache.clone();
                        let idle_timeout = idle_timeout;
                        let inline_sign = inline_sign;
                        let sign_timeout = sign_timeout;
                        tokio::spawn(async move {
                            let _permit = connection_permit;
                            if let Err(err) =
                                handle_connection(
                                    stream,
                                    registry,
                                    sign_semaphore,
                                    identity_cache,
                                    idle_timeout,
                                    inline_sign,
                                    sign_timeout,
                                )
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
            _ = &mut ctrl_c => {
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
    connection_semaphore: Option<Arc<Semaphore>>,
    identity_cache: Arc<IdentityCache>,
    idle_timeout: Option<Duration>,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    info!(pipe = %pipe_name, "secretive agent listening");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        let server = ServerOptions::new().create(&pipe_name)?;
        tokio::select! {
            result = server.connect() => {
                if let Err(err) = result {
                    warn!(?err, "named pipe connect failed");
                    continue;
                }
                let connection_permit = if let Some(semaphore) = connection_semaphore.as_ref() {
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            let rejected =
                                CONNECTION_REJECTED.fetch_add(1, Ordering::Relaxed) + 1;
                            if rejected % 100 == 0 {
                                warn!(rejected, "connection limit reached");
                            }
                            continue;
                        }
                    }
                } else {
                    None
                };
                let registry = registry.clone();
                let sign_semaphore = sign_semaphore.clone();
                let identity_cache = identity_cache.clone();
                let idle_timeout = idle_timeout;
                let inline_sign = inline_sign;
                let sign_timeout = sign_timeout;
                CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _permit = connection_permit;
                    if let Err(err) =
                        handle_connection(
                            server,
                            registry,
                            sign_semaphore,
                            identity_cache,
                            idle_timeout,
                            inline_sign,
                            sign_timeout,
                        )
                        .await
                    {
                        warn!(?err, "connection error");
                    }
                });
            }
            _ = &mut ctrl_c => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection<S>(
    stream: S,
    registry: Arc<KeyStoreRegistry>,
    sign_semaphore: Arc<Semaphore>,
    identity_cache: Arc<IdentityCache>,
    idle_timeout: Option<Duration>,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _guard = ConnectionGuard::acquire();
    let mut stream = stream;

    let mut buffer = BytesMut::with_capacity(4096);
    let mut response_buffer: Option<BytesMut> = None;
    loop {
        let read_result = if let Some(timeout) = idle_timeout {
            match tokio::time::timeout(timeout, read_request_with_buffer(&mut stream, &mut buffer))
                .await
            {
                Ok(result) => result,
                Err(_) => break,
            }
        } else {
            read_request_with_buffer(&mut stream, &mut buffer).await
        };
        let request = match read_result {
            Ok(request) => request,
            Err(err) => {
                if matches!(err, ProtoError::UnexpectedEof) {
                    break;
                }
                warn!(?err, "failed to read request");
                break;
            }
        };

        match request {
            ParsedRequest::RequestIdentities => {
                LIST_COUNT.fetch_add(1, Ordering::Relaxed);
                match identity_cache.get_payload_or_refresh(&registry).await {
                    Ok(payload) => {
                        if let Err(err) = stream.write_all(payload.as_ref()).await {
                            warn!(?err, "failed to write identities");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to list identities");
                        if let Err(err) = stream.write_all(failure_frame()).await {
                            warn!(?err, "failed to write failure response");
                            break;
                        }
                    }
                }
            }
            ParsedRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                let response = handle_sign_request(
                    &registry,
                    key_blob,
                    data,
                    flags,
                    sign_semaphore.as_ref(),
                    inline_sign,
                    sign_timeout,
                )
                .await;
                match response {
                    AgentResponse::Failure => {
                        if let Err(err) = stream.write_all(failure_frame()).await {
                            warn!(?err, "failed to write failure response");
                            break;
                        }
                    }
                    response => {
                        if response_buffer.is_none() {
                            response_buffer = Some(BytesMut::with_capacity(1024));
                        }
                        if let Err(err) = write_response_with_buffer(
                            &mut stream,
                            &response,
                            response_buffer.as_mut().expect("response buffer"),
                        )
                        .await
                        {
                            warn!(?err, "failed to write response");
                            break;
                        }
                    }
                }
            }
            ParsedRequest::Unknown { message_type } => {
                warn!(message_type, "unknown request type");
                if let Err(err) = stream.write_all(failure_frame()).await {
                    warn!(?err, "failed to write failure response");
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
        let active = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        MAX_ACTIVE_CONNECTIONS.fetch_max(active, Ordering::Relaxed);
        ConnectionGuard
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn read_request_with_buffer<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
) -> Result<ParsedRequest, ProtoError>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader
        .read_u32()
        .await
        .map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    if len == 0 {
        return Err(ProtoError::InvalidMessage("missing message type"));
    }
    if len == 1 {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|_| ProtoError::UnexpectedEof)?;
        let message_type = byte[0];
        return match message_type {
            x if x == MessageType::RequestIdentities as u8 => Ok(ParsedRequest::RequestIdentities),
            x if x == MessageType::SignRequest as u8 => Err(ProtoError::UnexpectedEof),
            _ => Ok(ParsedRequest::Unknown { message_type }),
        };
    }
    buffer.clear();
    buffer.reserve(len);
    unsafe {
        buffer.set_len(len);
    }
    reader
        .read_exact(&mut buffer[..])
        .await
        .map_err(|_| ProtoError::UnexpectedEof)?;
    // Move the frame out without cloning to avoid a full copy per request.
    let frame = buffer.split().freeze();
    decode_request_frame(&frame)
}

fn decode_request_frame(frame: &Bytes) -> Result<ParsedRequest, ProtoError> {
    let bytes = frame.as_ref();
    if bytes.is_empty() {
        return Err(ProtoError::InvalidMessage("missing message type"));
    }
    let message_type = bytes[0];
    let mut offset = 1usize;

    fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, ProtoError> {
        if bytes.len() < *offset + 4 {
            return Err(ProtoError::UnexpectedEof);
        }
        let value = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;
        Ok(value)
    }

    fn read_slice(frame: &Bytes, bytes: &[u8], offset: &mut usize) -> Result<Bytes, ProtoError> {
        let len = read_u32(bytes, offset)? as usize;
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge(len));
        }
        if bytes.len() < *offset + len {
            return Err(ProtoError::UnexpectedEof);
        }
        let start = *offset;
        let end = start + len;
        *offset = end;
        Ok(frame.slice(start..end))
    }

    match message_type {
        x if x == MessageType::RequestIdentities as u8 => Ok(ParsedRequest::RequestIdentities),
        x if x == MessageType::SignRequest as u8 => {
            let key_blob = read_slice(frame, bytes, &mut offset)?;
            let data = read_slice(frame, bytes, &mut offset)?;
            let flags = read_u32(bytes, &mut offset)?;
            Ok(ParsedRequest::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        _ => Ok(ParsedRequest::Unknown { message_type }),
    }
}

#[derive(Debug)]
enum ParsedRequest {
    RequestIdentities,
    SignRequest {
        key_blob: Bytes,
        data: Bytes,
        flags: u32,
    },
    Unknown {
        message_type: u8,
    },
}

async fn handle_sign_request(
    registry: &Arc<KeyStoreRegistry>,
    key_blob: Bytes,
    data: Bytes,
    flags: u32,
    sign_semaphore: &Semaphore,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> AgentResponse {
    let metrics_every = METRICS_EVERY.load(Ordering::Relaxed);
    let start = if metrics_every > 0 {
        Some(Instant::now())
    } else {
        None
    };
    let permit = match sign_timeout {
        Some(timeout) => match tokio::time::timeout(timeout, sign_semaphore.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                warn!("signing semaphore closed");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::Failure;
            }
            Err(_) => {
                let timeouts = SIGN_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
                if timeouts % 100 == 0 {
                    warn!(timeouts, "sign timeout");
                }
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::Failure;
            }
        },
        None => match sign_semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("signing semaphore closed");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::Failure;
            }
        },
    };
    let registry = Arc::clone(registry);
    let result = if inline_sign {
        Ok(registry.sign(key_blob.as_ref(), data.as_ref(), flags))
    } else {
        tokio::task::spawn_blocking(move || registry.sign(key_blob.as_ref(), data.as_ref(), flags))
            .await
    };
    drop(permit);
    match result {
        Ok(Ok(signature_blob)) => {
            let count = SIGN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(start) = start {
                let elapsed = start.elapsed();
                SIGN_TIME_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
                if count % metrics_every == 0 {
                    let errors = SIGN_ERRORS.load(Ordering::Relaxed);
                    let timeouts = SIGN_TIMEOUTS.load(Ordering::Relaxed);
                    let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
                    let avg = total / count as f64;
                    let max_signers = MAX_SIGNERS.load(Ordering::Relaxed);
                    let available = sign_semaphore.available_permits() as u64;
                    let in_flight = max_signers.saturating_sub(available);
                    let connections = CONNECTION_COUNT.load(Ordering::Relaxed);
                    let active_connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                    let max_connections = MAX_CONNECTIONS.load(Ordering::Relaxed);
                    let max_active_connections = MAX_ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                    let connection_rejected = CONNECTION_REJECTED.load(Ordering::Relaxed);
                    let list_count = LIST_COUNT.load(Ordering::Relaxed);
                    let list_hit = LIST_CACHE_HIT.load(Ordering::Relaxed);
                    let list_stale = LIST_CACHE_STALE.load(Ordering::Relaxed);
                    let list_refresh = LIST_REFRESH.load(Ordering::Relaxed);
                    let list_errors = LIST_ERRORS.load(Ordering::Relaxed);
                    let snapshot = SignMetricsSnapshot {
                        count,
                        errors,
                        timeouts,
                        avg_ns: avg,
                        in_flight,
                        max_signers,
                        connections,
                        active_connections,
                        max_active_connections,
                        max_connections,
                        connection_rejected,
                        list_count,
                        list_hit,
                        list_stale,
                        list_refresh,
                        list_errors,
                    };
                    emit_sign_metrics("interval", &snapshot);
                }
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

fn encode_identities_frame_from_keyidentities(
    identities: &[KeyIdentity],
) -> Result<Bytes, ProtoError> {
    let mut payload_len: usize = 1 + 4;
    for identity in identities {
        payload_len = payload_len
            .saturating_add(4 + identity.key_blob.len())
            .saturating_add(4 + identity.comment.len());
    }
    if payload_len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(payload_len));
    }
    let mut buf = BytesMut::with_capacity(4 + payload_len);
    buf.put_u32(payload_len as u32);
    buf.put_u8(MessageType::IdentitiesAnswer as u8);
    buf.put_u32(identities.len() as u32);
    for identity in identities {
        buf.put_u32(identity.key_blob.len() as u32);
        buf.put_slice(&identity.key_blob);
        buf.put_u32(identity.comment.len() as u32);
        buf.put_slice(identity.comment.as_bytes());
    }
    Ok(buf.freeze())
}

fn failure_frame() -> &'static Bytes {
    FAILURE_FRAME.get_or_init(|| {
        secretive_proto::encode_response_frame(&AgentResponse::Failure)
            .expect("failure frame encoding failed")
    })
}

fn now_ms() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn empty_config() -> Config {
        Config {
            profile: None,
            socket_path: None,
            socket_backlog: None,
            key_paths: None,
            scan_default_dir: None,
            stores: None,
            max_signers: None,
            max_connections: None,
            max_blocking_threads: None,
            worker_threads: None,
            watch_files: None,
            watch_debounce_ms: None,
            metrics_every: None,
            metrics_json: None,
            sign_timeout_ms: None,
            pid_file: None,
            identity_cache_ms: None,
            idle_timeout_ms: None,
            inline_sign: None,
        }
    }

    #[test]
    fn decode_request_identities() {
        let frame = Bytes::from_static(&[MessageType::RequestIdentities as u8]);
        let parsed = decode_request_frame(&frame).expect("decode");
        match parsed {
            ParsedRequest::RequestIdentities => {}
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn decode_request_sign() {
        let expected_key_blob = vec![1u8, 2, 3];
        let expected_data = vec![9u8, 8, 7, 6];
        let request = secretive_proto::AgentRequest::SignRequest {
            key_blob: expected_key_blob.clone(),
            data: expected_data.clone(),
            flags: 42,
        };
        let frame = secretive_proto::encode_request(&request);
        let parsed = decode_request_frame(&frame).expect("decode");
        match parsed {
            ParsedRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob.as_ref(), expected_key_blob.as_slice());
                assert_eq!(data.as_ref(), expected_data.as_slice());
                assert_eq!(flags, 42);
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_request_fast_path() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(1u32.to_be_bytes()));
        frame.push(MessageType::RequestIdentities as u8);

        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&frame).await.expect("write");

        let mut buffer = BytesMut::new();
        let parsed = read_request_with_buffer(&mut server, &mut buffer)
            .await
            .expect("read");
        assert!(matches!(parsed, ParsedRequest::RequestIdentities));
    }

    #[tokio::test]
    async fn read_request_sign_drains_buffer() {
        let request = secretive_proto::AgentRequest::SignRequest {
            key_blob: vec![1, 2, 3, 4],
            data: vec![5, 6, 7, 8],
            flags: 9,
        };
        let frame = secretive_proto::encode_request_frame(&request).expect("frame");
        let (mut client, mut server) = tokio::io::duplex(256);
        client.write_all(&frame).await.expect("write");

        let mut buffer = BytesMut::with_capacity(64);
        let parsed = read_request_with_buffer(&mut server, &mut buffer)
            .await
            .expect("read");
        match parsed {
            ParsedRequest::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob.as_ref(), [1, 2, 3, 4]);
                assert_eq!(data.as_ref(), [5, 6, 7, 8]);
                assert_eq!(flags, 9);
            }
            other => panic!("unexpected request: {other:?}"),
        }
        assert!(buffer.is_empty());
    }

    #[test]
    fn validate_config_rejects_secure_enclave_store() {
        let mut config = empty_config();
        config.stores = Some(vec![StoreConfig::SecureEnclave]);
        let validation = validate_config(&config);
        assert!(!validation.errors.is_empty());
        assert!(validation
            .errors
            .iter()
            .any(|entry| entry.contains("secure_enclave is not implemented yet")));
    }

    #[test]
    fn validate_config_warns_when_no_key_source() {
        let mut config = empty_config();
        config.stores = Some(vec![StoreConfig::File {
            paths: Some(Vec::new()),
            scan_default_dir: Some(false),
        }]);
        let validation = validate_config(&config);
        assert!(validation.errors.is_empty());
        assert!(validation
            .warnings
            .iter()
            .any(|entry| entry.contains("defines no key source")));
    }

    #[test]
    fn profile_fanout_sets_expected_defaults() {
        let mut config = empty_config();
        config.profile = Some("fanout".to_string());
        apply_profile_defaults(&mut config);

        assert_eq!(config.max_connections, Some(8192));
        assert_eq!(config.socket_backlog, Some(2048));
        assert_eq!(config.sign_timeout_ms, Some(250));
        assert_eq!(config.identity_cache_ms, Some(5000));
        assert_eq!(config.idle_timeout_ms, Some(10000));
        assert!(config.max_signers.unwrap_or(0) >= 8);
    }

    #[test]
    fn profile_does_not_override_explicit_values() {
        let mut config = empty_config();
        config.profile = Some("low-memory".to_string());
        config.max_connections = Some(123);
        config.sign_timeout_ms = Some(456);
        apply_profile_defaults(&mut config);

        assert_eq!(config.max_connections, Some(123));
        assert_eq!(config.sign_timeout_ms, Some(456));
    }

    #[test]
    fn metrics_json_contains_expected_fields() {
        let snapshot = SignMetricsSnapshot {
            count: 1,
            errors: 2,
            timeouts: 3,
            avg_ns: 4.0,
            in_flight: 5,
            max_signers: 6,
            connections: 7,
            active_connections: 8,
            max_active_connections: 9,
            max_connections: 10,
            connection_rejected: 11,
            list_count: 12,
            list_hit: 13,
            list_stale: 14,
            list_refresh: 15,
            list_errors: 16,
        };
        let payload = format_metrics_json("snapshot", &snapshot);
        assert!(payload.contains("\"kind\":\"snapshot\""));
        assert!(payload.contains("\"count\":1"));
        assert!(payload.contains("\"max_signers\":6"));
        assert!(payload.contains("\"list_errors\":16"));
    }
}
