use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::time::Duration;

use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
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

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    profile: Option<String>,
    socket_path: Option<String>,
    socket_backlog: Option<u32>,
    key_paths: Option<Vec<String>>,
    scan_default_dir: Option<bool>,
    stores: Option<Vec<StoreConfig>>,
    policy: Option<AccessPolicyConfig>,
    max_signers: Option<usize>,
    max_connections: Option<usize>,
    max_blocking_threads: Option<usize>,
    worker_threads: Option<usize>,
    watch_files: Option<bool>,
    watch_debounce_ms: Option<u64>,
    metrics_every: Option<u64>,
    metrics_interval_ms: Option<u64>,
    metrics_json: Option<bool>,
    metrics_output_path: Option<String>,
    audit_requests: Option<bool>,
    sign_timeout_ms: Option<u64>,
    pid_file: Option<String>,
    identity_cache_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    inline_sign: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: None,
            socket_path: None,
            socket_backlog: None,
            key_paths: None,
            scan_default_dir: None,
            stores: None,
            policy: None,
            max_signers: None,
            max_connections: None,
            max_blocking_threads: None,
            worker_threads: None,
            watch_files: None,
            watch_debounce_ms: None,
            metrics_every: None,
            metrics_interval_ms: None,
            metrics_json: None,
            metrics_output_path: None,
            audit_requests: None,
            sign_timeout_ms: None,
            pid_file: None,
            identity_cache_ms: None,
            idle_timeout_ms: None,
            inline_sign: None,
        }
    }
}

static SIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static SIGN_TIME_NS: AtomicU64 = AtomicU64::new(0);
static SIGN_QUEUE_WAIT_NS: AtomicU64 = AtomicU64::new(0);
static SIGN_QUEUE_WAIT_MAX_NS: AtomicU64 = AtomicU64::new(0);
const QUEUE_WAIT_BUCKET_BOUNDS: [u64; 25] = [
    500,
    1_000,
    2_000,
    4_000,
    8_000,
    16_000,
    32_000,
    64_000,
    128_000,
    256_000,
    512_000,
    1_000_000,
    2_000_000,
    4_000_000,
    8_000_000,
    16_000_000,
    32_000_000,
    64_000_000,
    128_000_000,
    256_000_000,
    512_000_000,
    1_000_000_000,
    2_000_000_000,
    4_000_000_000,
    8_000_000_000,
];
const QUEUE_WAIT_BUCKET_COUNT: usize = QUEUE_WAIT_BUCKET_BOUNDS.len() + 1;
static QUEUE_WAIT_BUCKETS: [AtomicU64; QUEUE_WAIT_BUCKET_COUNT] =
    [const { AtomicU64::new(0) }; QUEUE_WAIT_BUCKET_COUNT];
#[derive(Debug, Clone, Copy, serde::Serialize)]
struct QueueWaitPercentileValue {
    ns: u64,
    open_ended: bool,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
struct QueueWaitPercentiles {
    p50: Option<QueueWaitPercentileValue>,
    p90: Option<QueueWaitPercentileValue>,
    p95: Option<QueueWaitPercentileValue>,
    p99: Option<QueueWaitPercentileValue>,
}

#[derive(Clone, Copy)]
enum QueueWaitPercentileLabel {
    P50,
    P90,
    P95,
    P99,
}

const QUEUE_WAIT_PERCENTILE_TARGETS: &[(f64, QueueWaitPercentileLabel)] = &[
    (0.50, QueueWaitPercentileLabel::P50),
    (0.90, QueueWaitPercentileLabel::P90),
    (0.95, QueueWaitPercentileLabel::P95),
    (0.99, QueueWaitPercentileLabel::P99),
];
static SIGN_ERRORS: AtomicU64 = AtomicU64::new(0);
static SIGN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static METRICS_WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);
static METRICS_EVERY: AtomicU64 = AtomicU64::new(1000);
static METRICS_JSON: AtomicBool = AtomicBool::new(false);
static METRICS_OUTPUT_PATH: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
static AUDIT_REQUESTS: AtomicBool = AtomicBool::new(false);
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
static STORE_SIGN_FILE: AtomicU64 = AtomicU64::new(0);
static STORE_SIGN_PKCS11: AtomicU64 = AtomicU64::new(0);
static STORE_SIGN_SECURE_ENCLAVE: AtomicU64 = AtomicU64::new(0);
static STORE_SIGN_OTHER: AtomicU64 = AtomicU64::new(0);
static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static AGENT_STARTED_UNIX_MS: OnceLock<u64> = OnceLock::new();
static QUEUE_WAIT_SUGGESTION: OnceLock<QueueWaitSuggestion> = OnceLock::new();
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

#[derive(Debug, Deserialize, Serialize)]
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
        refresh_min_interval_ms: Option<u64>,
    },
}

#[derive(Debug, Deserialize, Default, Serialize)]
struct AccessPolicyConfig {
    pin_fingerprints: Option<Vec<String>>,
    allow_key_blobs: Option<Vec<String>>,
    deny_key_blobs: Option<Vec<String>>,
    allow_fingerprints: Option<Vec<String>>,
    deny_fingerprints: Option<Vec<String>>,
    allow_comments: Option<Vec<String>>,
    deny_comments: Option<Vec<String>>,
    confirm_command: Option<Vec<String>>,
    confirm_timeout_ms: Option<u64>,
    confirm_cache_ms: Option<u64>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "secretive-agent starting"
    );
    AGENT_STARTED_UNIX_MS.get_or_init(unix_now_ms);

    let args = parse_args();
    if args.help {
        print_help();
        return;
    }
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.suggest_queue_wait && args.reset_metrics {
        eprintln!("--suggest-queue-wait cannot be combined with --reset-metrics");
        std::process::exit(2);
    }
    if args.pid.is_some() && !args.reset_metrics {
        eprintln!("--pid is only valid with --reset-metrics");
        std::process::exit(2);
    }
    if args.reset_metrics {
        #[cfg(unix)]
        {
            let target_pid = if let Some(pid) = args.pid {
                Some(pid)
            } else if let Some(path) = args.pid_file.as_deref() {
                match read_pid_file(path) {
                    Ok(pid) => Some(pid),
                    Err(err) => {
                        eprintln!("failed to read pid file {path}: {err}");
                        None
                    }
                }
            } else {
                None
            };
            let Some(pid) = target_pid else {
                eprintln!("--reset-metrics requires --pid or --pid-file on Unix");
                std::process::exit(2);
            };
            if let Err(err) = send_reset_metrics_signal(pid) {
                eprintln!("failed to send reset-metrics signal to pid {pid}: {err}");
                std::process::exit(2);
            }
            println!("sent reset-metrics signal to pid {pid}");
            return;
        }
        #[cfg(not(unix))]
        {
            eprintln!("--reset-metrics is only supported on Unix builds");
            std::process::exit(2);
        }
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
    if let Some(metrics_interval_ms) = args.metrics_interval_ms {
        config.metrics_interval_ms = Some(metrics_interval_ms);
    }
    if let Some(metrics_json) = args.metrics_json {
        config.metrics_json = Some(metrics_json);
    }
    if let Some(metrics_output_path) = args.metrics_output_path {
        config.metrics_output_path = Some(metrics_output_path);
    }
    if let Some(audit_requests) = args.audit_requests {
        config.audit_requests = Some(audit_requests);
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
    if config.metrics_interval_ms.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_INTERVAL_MS") {
            config.metrics_interval_ms = value.parse().ok();
        }
    }
    if config.metrics_json.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_JSON") {
            config.metrics_json = parse_bool_env(&value);
        }
    }
    if config.metrics_output_path.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_METRICS_OUTPUT") {
            let value = value.trim();
            if !value.is_empty() {
                config.metrics_output_path = Some(value.to_string());
            }
        }
    }
    if config.audit_requests.is_none() {
        if let Ok(value) = std::env::var("SECRETIVE_AUDIT_REQUESTS") {
            config.audit_requests = parse_bool_env(&value);
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

    if args.dump_effective_config {
        match serde_json::to_string_pretty(&config) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to render effective config: {err}");
                std::process::exit(2);
            }
        }
        if !check_config && !args.suggest_queue_wait {
            return;
        }
    }
    let max_signers = compute_max_signers(&config);
    if args.suggest_queue_wait {
        if args.suggest_queue_wait_json && args.suggest_queue_wait_quiet {
            eprintln!(
                "--suggest-queue-wait-json cannot be combined with --suggest-queue-wait-quiet"
            );
            std::process::exit(2);
        }
        if check_config {
            let validation = validate_config(&config);
            for warning in validation.warnings {
                eprintln!("warning: {warning}");
            }
            if !validation.errors.is_empty() {
                eprintln!("config validation failed:");
                for error in validation.errors {
                    eprintln!("- {error}");
                }
                std::process::exit(2);
            }
        }
        emit_queue_wait_suggestion(
            &config,
            max_signers,
            args.suggest_queue_wait_json,
            args.suggest_queue_wait_quiet,
        );
        return;
    }
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

    // Expose the recommended queue wait guardrail alongside observed queue wait telemetry so
    // dashboards can compare "actual vs suggested" without consulting CI logs.
    let _ = QUEUE_WAIT_SUGGESTION.set(build_queue_wait_suggestion(&config, max_signers));

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
    let mut has_pkcs11_store = false;
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
                refresh_min_interval_ms,
            } => {
                has_pkcs11_store = true;
                let config = Pkcs11Config {
                    module_path: PathBuf::from(module_path),
                    slot,
                    pin_env,
                    refresh_min_interval_ms,
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
    let inline_sign = effective_inline_sign(config.inline_sign, has_pkcs11_store);
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
    if let Ok(mut guard) = METRICS_OUTPUT_PATH.lock() {
        *guard = config.metrics_output_path.as_ref().map(PathBuf::from);
    } else {
        warn!("failed to set metrics output path");
    }
    if metrics_json {
        info!("metrics format: json");
    } else {
        info!("metrics format: log");
    }
    if let Some(path) = config.metrics_output_path.as_ref() {
        info!(path, "metrics output path");
    } else {
        info!("metrics output path disabled");
    }
    if metrics_every == 0 {
        info!("signing metrics disabled");
    } else {
        info!(metrics_every, "signing metrics interval");
    }
    let metrics_interval = config.metrics_interval_ms.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(Duration::from_millis(value))
        }
    });
    if let Some(interval) = metrics_interval {
        info!(
            metrics_interval_ms = interval.as_millis(),
            "periodic metrics"
        );
    } else {
        info!("periodic metrics disabled");
    }
    let audit_requests = config.audit_requests.unwrap_or(false);
    AUDIT_REQUESTS.store(audit_requests, Ordering::Relaxed);
    if audit_requests {
        info!("request auditing enabled");
    } else {
        info!("request auditing disabled");
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

    let access_policy = Arc::new(AccessPolicy::from_config(config.policy.as_ref()));
    if access_policy.is_enabled() {
        info!(
            allow_key_blobs = access_policy.allow_key_blobs.len(),
            deny_key_blobs = access_policy.deny_key_blobs.len(),
            allow_fingerprints = access_policy.allow_fingerprints.len(),
            deny_fingerprints = access_policy.deny_fingerprints.len(),
            allow_comments = access_policy.allow_comments.len(),
            deny_comments = access_policy.deny_comments.len(),
            "access policy enabled"
        );
    } else {
        info!("access policy disabled");
    }

    if let Some(interval) = metrics_interval {
        let sign_semaphore = Arc::clone(&sign_semaphore);
        let max_signers = max_signers as u64;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let snapshot = build_metrics_snapshot(&sign_semaphore, max_signers);
                emit_sign_metrics("periodic", &snapshot);
            }
        });
    }

    #[cfg(unix)]
    {
        let sign_semaphore = sign_semaphore.clone();
        let max_signers = max_signers as u64;
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::user_defined1()) {
                while stream.recv().await.is_some() {
                    let snapshot = build_metrics_snapshot(&sign_semaphore, max_signers);
                    emit_sign_metrics("snapshot", &snapshot);
                }
            }
        });
    }

    #[cfg(unix)]
    {
        let sign_semaphore = sign_semaphore.clone();
        let max_signers = max_signers as u64;
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut stream) = signal(SignalKind::user_defined2()) {
                while stream.recv().await.is_some() {
                    reset_sign_metrics();
                    info!("sign metrics reset via SIGUSR2");
                    let snapshot = build_metrics_snapshot(&sign_semaphore, max_signers);
                    emit_sign_metrics("reset", &snapshot);
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
            access_policy.clone(),
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
            access_policy.clone(),
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

fn effective_inline_sign(explicit: Option<bool>, has_pkcs11_store: bool) -> bool {
    explicit.unwrap_or(!has_pkcs11_store)
}

#[derive(Debug, Clone)]
struct QueueWaitSuggestion {
    profile_label: String,
    profile_inferred: bool,
    cpu_cores: usize,
    max_signers: usize,
    signers_per_core: f64,
    tail_ns: u64,
    tail_ratio: f64,
    inline_sign: bool,
    has_pkcs11: bool,
    max_connections: Option<usize>,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct QueueWaitDefaults {
    tail_ns: u64,
    tail_ratio: f64,
    baseline_signers_per_core: f64,
}

fn queue_wait_profile_info(config: &Config) -> (Option<ConfigProfile>, String, bool) {
    if let Some(name) = config.profile.as_deref() {
        if let Some(profile) = ConfigProfile::parse(name) {
            return (Some(profile), name.to_string(), false);
        }
        return (None, format!("custom ({name})"), false);
    }
    (
        Some(ConfigProfile::Balanced),
        "balanced (implicit)".to_string(),
        true,
    )
}

fn queue_wait_defaults(profile: Option<ConfigProfile>) -> QueueWaitDefaults {
    match profile {
        Some(ConfigProfile::Pssh) => QueueWaitDefaults {
            tail_ns: 4_000_000,
            tail_ratio: 0.03,
            baseline_signers_per_core: 12.0,
        },
        Some(ConfigProfile::Fanout) => QueueWaitDefaults {
            tail_ns: 6_000_000,
            tail_ratio: 0.04,
            baseline_signers_per_core: 8.0,
        },
        Some(ConfigProfile::LowMemory) => QueueWaitDefaults {
            tail_ns: 12_000_000,
            tail_ratio: 0.07,
            baseline_signers_per_core: 2.0,
        },
        _ => QueueWaitDefaults {
            tail_ns: 8_000_000,
            tail_ratio: 0.05,
            baseline_signers_per_core: 4.0,
        },
    }
}

fn config_has_pkcs11_store(config: &Config) -> bool {
    config
        .stores
        .as_ref()
        .map(|stores| {
            stores
                .iter()
                .any(|store| matches!(store, StoreConfig::Pkcs11 { .. }))
        })
        .unwrap_or(false)
}

fn queue_wait_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .max(1)
}

fn build_queue_wait_suggestion(config: &Config, max_signers: usize) -> QueueWaitSuggestion {
    let cpu_cores = queue_wait_cpu_cores();
    build_queue_wait_suggestion_with_cores(config, max_signers, cpu_cores)
}

fn build_queue_wait_suggestion_with_cores(
    config: &Config,
    max_signers: usize,
    cpu_cores: usize,
) -> QueueWaitSuggestion {
    let (profile, profile_label, profile_inferred) = queue_wait_profile_info(config);
    let defaults = queue_wait_defaults(profile);
    let signers_per_core = max_signers as f64 / cpu_cores as f64;
    let mut tail_ns = defaults.tail_ns;
    let mut tail_ratio = defaults.tail_ratio;
    let mut reasons = Vec::new();
    reasons.push(format!(
        "profile {profile_label} starts with {:.2} ms tail and {:.1}% ratio guardrail",
        tail_ns as f64 / 1_000_000.0,
        tail_ratio * 100.0
    ));

    let baseline = defaults.baseline_signers_per_core.max(1.0);
    let concurrency_ratio = signers_per_core / baseline;
    if concurrency_ratio > 1.1 {
        let scale = 1.0 + ((concurrency_ratio - 1.0).min(1.5)) * 0.35;
        tail_ns = ((tail_ns as f64) * scale).round() as u64;
        tail_ratio = (tail_ratio + 0.01 + (concurrency_ratio - 1.0).min(1.0) * 0.01).min(0.15);
        reasons.push(format!(
            "max_signers={max_signers} (~{signers_per_core:.1} per core) exceeds the {baseline:.1}/core baseline; bump tail by {:+.0}% to keep queue churn sane",
            (scale - 1.0) * 100.0
        ));
    } else if concurrency_ratio < 0.9 {
        let scale = 1.0 - ((1.0 - concurrency_ratio).min(0.5)) * 0.25;
        tail_ns = ((tail_ns as f64) * scale).round() as u64;
        tail_ratio = (tail_ratio - 0.005).max(0.02);
        reasons.push(format!(
            "max_signers={max_signers} (~{signers_per_core:.1} per core) is below the {baseline:.1}/core baseline; tighten guardrail by {:+.0}%",
            (1.0 - scale) * 100.0
        ));
    }

    let has_pkcs11 = config_has_pkcs11_store(config);
    let inline_sign = effective_inline_sign(config.inline_sign, has_pkcs11);
    if has_pkcs11 {
        tail_ns = ((tail_ns as f64) * 1.2).round() as u64;
        tail_ratio = (tail_ratio + 0.005).min(0.15);
        reasons.push("pkcs11 store detected; add 20% slack for token RTT churn".to_string());
    }
    if !inline_sign {
        tail_ns = ((tail_ns as f64) * 1.1).round() as u64;
        tail_ratio = (tail_ratio + 0.003).min(0.15);
        reasons.push("inline signing disabled; account for blocking thread contention".to_string());
    }

    if config.max_connections.unwrap_or(0) >= 20_000 {
        tail_ratio = (tail_ratio + 0.003).min(0.15);
        reasons.push(
            "max_connections >= 20000 implies very high fan-out; allow +0.3pp queue tail"
                .to_string(),
        );
    }

    tail_ns = tail_ns.clamp(1_000_000, 40_000_000);
    tail_ratio = tail_ratio.clamp(0.02, 0.15);

    QueueWaitSuggestion {
        profile_label,
        profile_inferred,
        cpu_cores,
        max_signers,
        signers_per_core,
        tail_ns,
        tail_ratio,
        inline_sign,
        has_pkcs11,
        max_connections: config.max_connections,
        reasons,
    }
}

fn queue_wait_suggestion_json(suggestion: &QueueWaitSuggestion) -> serde_json::Value {
    serde_json::json!({
        "profile": {
            "label": suggestion.profile_label,
            "inferred": suggestion.profile_inferred,
        },
        "cpu_cores": suggestion.cpu_cores,
        "max_signers": suggestion.max_signers,
        "signers_per_core": suggestion.signers_per_core,
        "max_connections": suggestion.max_connections,
        "inline_sign": suggestion.inline_sign,
        "pkcs11_store_present": suggestion.has_pkcs11,
        "tail_ns": suggestion.tail_ns,
        "tail_ratio": suggestion.tail_ratio,
        "env": {
            "SLO_QUEUE_WAIT_TAIL_NS": suggestion.tail_ns,
            "SLO_QUEUE_WAIT_TAIL_MAX_RATIO": suggestion.tail_ratio,
            "SECRETIVE_BENCH_QUEUE_WAIT_TAIL_NS": suggestion.tail_ns,
            "SECRETIVE_BENCH_QUEUE_WAIT_TAIL_MAX_RATIO": suggestion.tail_ratio,
        },
        "reasons": suggestion.reasons,
    })
}

fn emit_queue_wait_suggestion(config: &Config, max_signers: usize, json: bool, quiet: bool) {
    let suggestion = build_queue_wait_suggestion(config, max_signers);
    if json {
        println!("{}", queue_wait_suggestion_json(&suggestion));
        return;
    }
    if quiet {
        println!("SLO_QUEUE_WAIT_TAIL_NS={}", suggestion.tail_ns);
        println!("SLO_QUEUE_WAIT_TAIL_MAX_RATIO={:.4}", suggestion.tail_ratio);
        return;
    }
    let inferred = if suggestion.profile_inferred {
        " (inferred)"
    } else {
        ""
    };
    println!("Queue wait guardrail suggestion");
    println!("  profile: {}{}", suggestion.profile_label, inferred);
    println!("  cpu_cores: {}", suggestion.cpu_cores);
    println!("  max_signers: {}", suggestion.max_signers);
    println!("  signers_per_core: {:.1}", suggestion.signers_per_core);
    if let Some(max_connections) = suggestion.max_connections {
        println!("  max_connections: {}", max_connections);
    } else {
        println!("  max_connections: unlimited");
    }
    println!("  inline_sign: {}", suggestion.inline_sign);
    println!("  pkcs11_store_present: {}", suggestion.has_pkcs11);
    println!(
        "  recommended tail_ns: {} (~{:.2} ms)",
        suggestion.tail_ns,
        suggestion.tail_ns as f64 / 1_000_000.0
    );
    println!("  recommended tail_ratio: {:.3}", suggestion.tail_ratio);
    println!("  export suggestions:");
    println!("    SLO_QUEUE_WAIT_TAIL_NS={}", suggestion.tail_ns);
    println!(
        "    SLO_QUEUE_WAIT_TAIL_MAX_RATIO={:.4}",
        suggestion.tail_ratio
    );
    println!(
        "    SECRETIVE_BENCH_QUEUE_WAIT_TAIL_NS={}",
        suggestion.tail_ns
    );
    println!(
        "    SECRETIVE_BENCH_QUEUE_WAIT_TAIL_MAX_RATIO={:.4}",
        suggestion.tail_ratio
    );
    println!("  rationale:");
    for reason in suggestion.reasons {
        println!("    - {reason}");
    }
}

fn update_atomic_max(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while value > current {
        match target.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn record_queue_wait_bucket(wait_ns: u64) {
    let bucket = QUEUE_WAIT_BUCKET_BOUNDS
        .iter()
        .position(|&bound| wait_ns <= bound)
        .unwrap_or(QUEUE_WAIT_BUCKET_COUNT - 1);
    QUEUE_WAIT_BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);
}

fn bucket_bound_ns(bucket_index: usize) -> (u64, bool) {
    if bucket_index < QUEUE_WAIT_BUCKET_BOUNDS.len() {
        (QUEUE_WAIT_BUCKET_BOUNDS[bucket_index], false)
    } else {
        (
            *QUEUE_WAIT_BUCKET_BOUNDS
                .last()
                .expect("queue wait bucket bounds should not be empty"),
            true,
        )
    }
}

fn assign_queue_wait_percentile(
    percentiles: &mut QueueWaitPercentiles,
    label: QueueWaitPercentileLabel,
    value: QueueWaitPercentileValue,
) {
    match label {
        QueueWaitPercentileLabel::P50 => percentiles.p50 = Some(value),
        QueueWaitPercentileLabel::P90 => percentiles.p90 = Some(value),
        QueueWaitPercentileLabel::P95 => percentiles.p95 = Some(value),
        QueueWaitPercentileLabel::P99 => percentiles.p99 = Some(value),
    }
}

fn compute_queue_wait_percentiles_from_histogram(
    histogram: &[u64; QUEUE_WAIT_BUCKET_COUNT],
) -> QueueWaitPercentiles {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return QueueWaitPercentiles::default();
    }

    let mut thresholds = [0u64; QUEUE_WAIT_PERCENTILE_TARGETS.len()];
    let mut labels = [QueueWaitPercentileLabel::P50; QUEUE_WAIT_PERCENTILE_TARGETS.len()];
    for (idx, (fraction, label)) in QUEUE_WAIT_PERCENTILE_TARGETS.iter().enumerate() {
        let threshold = ((*fraction * total as f64).ceil() as u64).max(1);
        thresholds[idx] = threshold;
        labels[idx] = *label;
    }

    let mut percentiles = QueueWaitPercentiles::default();
    let mut threshold_index = 0usize;
    let mut cumulative = 0u64;
    for (bucket_index, count) in histogram.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        while threshold_index < thresholds.len() && cumulative >= thresholds[threshold_index] {
            let (ns, open_ended) = bucket_bound_ns(bucket_index);
            assign_queue_wait_percentile(
                &mut percentiles,
                labels[threshold_index],
                QueueWaitPercentileValue { ns, open_ended },
            );
            threshold_index += 1;
        }
        if threshold_index >= thresholds.len() {
            break;
        }
    }

    percentiles
}

fn reset_sign_metrics() {
    SIGN_COUNT.store(0, Ordering::Relaxed);
    SIGN_TIME_NS.store(0, Ordering::Relaxed);
    SIGN_QUEUE_WAIT_NS.store(0, Ordering::Relaxed);
    SIGN_QUEUE_WAIT_MAX_NS.store(0, Ordering::Relaxed);
    SIGN_ERRORS.store(0, Ordering::Relaxed);
    SIGN_TIMEOUTS.store(0, Ordering::Relaxed);
    CONNECTION_COUNT.store(0, Ordering::Relaxed);
    CONNECTION_REJECTED.store(0, Ordering::Relaxed);
    let active = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    MAX_ACTIVE_CONNECTIONS.store(active, Ordering::Relaxed);
    LIST_COUNT.store(0, Ordering::Relaxed);
    LIST_CACHE_HIT.store(0, Ordering::Relaxed);
    LIST_CACHE_STALE.store(0, Ordering::Relaxed);
    LIST_REFRESH.store(0, Ordering::Relaxed);
    LIST_ERRORS.store(0, Ordering::Relaxed);
    STORE_SIGN_FILE.store(0, Ordering::Relaxed);
    STORE_SIGN_PKCS11.store(0, Ordering::Relaxed);
    STORE_SIGN_SECURE_ENCLAVE.store(0, Ordering::Relaxed);
    STORE_SIGN_OTHER.store(0, Ordering::Relaxed);
    for bucket in &QUEUE_WAIT_BUCKETS {
        bucket.store(0, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn read_pid_file(path: &str) -> io::Result<u32> {
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "pid file is empty"));
    }
    trimmed.parse::<u32>().map_err(|err| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("failed to parse pid file {path}: {err}"),
        )
    })
}

#[cfg(unix)]
fn send_reset_metrics_signal(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            "pid is too large for target platform",
        )
    })?;
    if pid <= 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "pid must be positive",
        ));
    }
    let rc = unsafe { libc::kill(pid, libc::SIGUSR2) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigProfile {
    Balanced,
    Fanout,
    Pssh,
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
        if value.eq_ignore_ascii_case("pssh")
            || value.eq_ignore_ascii_case("high-fanout")
            || value.eq_ignore_ascii_case("high_fanout")
            || value.eq_ignore_ascii_case("highfanout")
        {
            return Some(Self::Pssh);
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
        ConfigProfile::Pssh => {
            if config.max_signers.is_none() {
                config.max_signers = Some(cores.saturating_mul(12).max(32));
            }
            if config.max_blocking_threads.is_none() {
                config.max_blocking_threads = config.max_signers;
            }
            if config.max_connections.is_none() {
                config.max_connections = Some(32768);
            }
            if config.worker_threads.is_none() {
                config.worker_threads = Some(cores.max(2));
            }
            if config.identity_cache_ms.is_none() {
                config.identity_cache_ms = Some(10000);
            }
            if config.sign_timeout_ms.is_none() {
                config.sign_timeout_ms = Some(150);
            }
            if config.socket_backlog.is_none() {
                config.socket_backlog = Some(4096);
            }
            if config.idle_timeout_ms.is_none() {
                config.idle_timeout_ms = Some(5000);
            }
            if config.watch_debounce_ms.is_none() {
                config.watch_debounce_ms = Some(500);
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

#[derive(Debug, Default)]
struct AccessPolicy {
    allow_key_blobs: HashSet<Vec<u8>>,
    deny_key_blobs: HashSet<Vec<u8>>,
    allow_fingerprints: HashSet<String>,
    deny_fingerprints: HashSet<String>,
    allow_comments: HashSet<String>,
    deny_comments: HashSet<String>,
    confirm: Option<ConfirmPolicy>,
}

#[derive(Debug)]
struct ConfirmPolicy {
    argv: Vec<String>,
    timeout: Duration,
    cache_ms: u64,
    cache: tokio::sync::Mutex<HashMap<String, Instant>>,
}

#[derive(Debug, Clone, Copy)]
enum PolicyDecision {
    Allow,
    Deny(&'static str),
}

impl AccessPolicy {
    fn from_config(config: Option<&AccessPolicyConfig>) -> Self {
        let mut policy = Self::default();
        let Some(config) = config else {
            return policy;
        };

        if let Some(values) = &config.allow_key_blobs {
            for value in values {
                match hex::decode(value.trim()) {
                    Ok(key_blob) => {
                        policy.allow_key_blobs.insert(key_blob);
                    }
                    Err(err) => {
                        warn!(?err, key_blob = value, "invalid allow_key_blobs entry");
                    }
                }
            }
        }
        if let Some(values) = &config.deny_key_blobs {
            for value in values {
                match hex::decode(value.trim()) {
                    Ok(key_blob) => {
                        policy.deny_key_blobs.insert(key_blob);
                    }
                    Err(err) => {
                        warn!(?err, key_blob = value, "invalid deny_key_blobs entry");
                    }
                }
            }
        }
        if let Some(values) = &config.allow_fingerprints {
            for value in values {
                if let Some(normalized) = normalize_fingerprint(value) {
                    policy.allow_fingerprints.insert(normalized);
                } else {
                    warn!(fingerprint = value, "invalid allow_fingerprints entry");
                }
            }
        }
        if let Some(values) = &config.pin_fingerprints {
            for value in values {
                if let Some(normalized) = normalize_fingerprint(value) {
                    policy.allow_fingerprints.insert(normalized);
                } else {
                    warn!(fingerprint = value, "invalid pin_fingerprints entry");
                }
            }
        }
        if let Some(values) = &config.deny_fingerprints {
            for value in values {
                if let Some(normalized) = normalize_fingerprint(value) {
                    policy.deny_fingerprints.insert(normalized);
                } else {
                    warn!(fingerprint = value, "invalid deny_fingerprints entry");
                }
            }
        }
        if let Some(values) = &config.allow_comments {
            for value in values {
                let normalized = normalize_comment(value);
                if !normalized.is_empty() {
                    policy.allow_comments.insert(normalized);
                }
            }
        }
        if let Some(values) = &config.deny_comments {
            for value in values {
                let normalized = normalize_comment(value);
                if !normalized.is_empty() {
                    policy.deny_comments.insert(normalized);
                }
            }
        }

        if let Some(command) = &config.confirm_command {
            let argv: Vec<String> = command
                .iter()
                .map(|value| value.trim().to_string())
                .collect();
            let argv_is_valid = !argv.is_empty() && !argv[0].is_empty();
            if !argv_is_valid {
                warn!("invalid policy.confirm_command (must be a non-empty argv list)");
            } else {
                let timeout_ms = config.confirm_timeout_ms.unwrap_or(30_000).max(1);
                let cache_ms = config.confirm_cache_ms.unwrap_or(0);
                policy.confirm = Some(ConfirmPolicy {
                    argv,
                    timeout: Duration::from_millis(timeout_ms),
                    cache_ms,
                    cache: tokio::sync::Mutex::new(HashMap::new()),
                });
            }
        }

        policy
    }

    fn is_enabled(&self) -> bool {
        !self.allow_key_blobs.is_empty()
            || !self.deny_key_blobs.is_empty()
            || !self.allow_fingerprints.is_empty()
            || !self.deny_fingerprints.is_empty()
            || !self.allow_comments.is_empty()
            || !self.deny_comments.is_empty()
            || self.confirm.is_some()
    }

    fn requires_comment_lookup(&self) -> bool {
        !self.allow_comments.is_empty() || !self.deny_comments.is_empty()
    }

    fn confirm_enabled(&self) -> bool {
        self.confirm.is_some()
    }

    fn evaluate(&self, key_blob: &[u8], comment: Option<&str>) -> PolicyDecision {
        if !self.is_enabled() {
            return PolicyDecision::Allow;
        }

        if self.deny_key_blobs.contains(key_blob) {
            return PolicyDecision::Deny("deny_key_blob");
        }

        let fingerprint = key_blob_fingerprint(key_blob);
        if let Some(fingerprint) = fingerprint.as_deref() {
            if self.deny_fingerprints.contains(fingerprint) {
                return PolicyDecision::Deny("deny_fingerprint");
            }
        }

        let comment = comment.map(normalize_comment);
        if let Some(comment) = comment.as_deref() {
            if self.deny_comments.contains(comment) {
                return PolicyDecision::Deny("deny_comment");
            }
        }

        let has_allowlist = !self.allow_key_blobs.is_empty()
            || !self.allow_fingerprints.is_empty()
            || !self.allow_comments.is_empty();
        if !has_allowlist {
            return PolicyDecision::Allow;
        }

        if self.allow_key_blobs.contains(key_blob) {
            return PolicyDecision::Allow;
        }
        if let Some(fingerprint) = fingerprint.as_deref() {
            if self.allow_fingerprints.contains(fingerprint) {
                return PolicyDecision::Allow;
            }
        }
        if let Some(comment) = comment.as_deref() {
            if self.allow_comments.contains(comment) {
                return PolicyDecision::Allow;
            }
        }

        PolicyDecision::Deny("allowlist_miss")
    }

    async fn confirm_sign_request(
        &self,
        key_blob: &[u8],
        comment: Option<&str>,
        flags: u32,
        data_len: usize,
    ) -> Result<ConfirmOutcome, ConfirmError> {
        let Some(confirm) = self.confirm.as_ref() else {
            return Ok(ConfirmOutcome::Skipped);
        };

        let key_id = confirm_key_id(key_blob);
        if confirm.cache_ms > 0 {
            let now = Instant::now();
            let mut cache = confirm.cache.lock().await;
            if let Some(expiry) = cache.get(&key_id).copied() {
                if expiry > now {
                    return Ok(ConfirmOutcome::CachedAllow);
                }
                cache.remove(&key_id);
            }
        }

        let status = run_confirm_command(
            &confirm.argv,
            confirm.timeout,
            &ConfirmEnv {
                key_id: &key_id,
                key_fingerprint: key_blob_fingerprint(key_blob).as_deref(),
                key_comment: comment,
                flags,
                data_len,
            },
        )
        .await?;

        if status.success() {
            if confirm.cache_ms > 0 {
                let expiry = Instant::now() + Duration::from_millis(confirm.cache_ms);
                let mut cache = confirm.cache.lock().await;
                cache.insert(key_id, expiry);
            }
            Ok(ConfirmOutcome::Allow)
        } else {
            Ok(ConfirmOutcome::Deny)
        }
    }
}

fn normalize_comment(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_fingerprint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some((prefix, suffix)) = trimmed.split_once(':') {
        let mut normalized = String::with_capacity(prefix.len() + 1 + suffix.len());
        normalized.push_str(&prefix.to_ascii_uppercase());
        normalized.push(':');
        normalized.push_str(suffix);
        return normalized
            .parse::<ssh_key::Fingerprint>()
            .ok()
            .map(|fp| fp.to_string());
    }
    let mut prefixed = String::with_capacity("SHA256:".len() + trimmed.len());
    prefixed.push_str("SHA256:");
    prefixed.push_str(trimmed);
    prefixed
        .parse::<ssh_key::Fingerprint>()
        .ok()
        .map(|fp| fp.to_string())
}

fn key_blob_fingerprint(key_blob: &[u8]) -> Option<String> {
    ssh_key::PublicKey::from_bytes(key_blob)
        .ok()
        .map(|public_key| public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmOutcome {
    Skipped,
    CachedAllow,
    Allow,
    Deny,
}

#[derive(Debug, thiserror::Error)]
enum ConfirmError {
    #[error("confirm command timed out")]
    Timeout,
    #[error("confirm command failed to spawn: {0}")]
    Spawn(#[from] io::Error),
    #[error("confirm command wait failed: {0}")]
    Wait(io::Error),
}

struct ConfirmEnv<'a> {
    key_id: &'a str,
    key_fingerprint: Option<&'a str>,
    key_comment: Option<&'a str>,
    flags: u32,
    data_len: usize,
}

fn confirm_key_id(key_blob: &[u8]) -> String {
    if let Some(fingerprint) = key_blob_fingerprint(key_blob) {
        return fingerprint;
    }
    let prefix_len = key_blob.len().min(16);
    let prefix_hex = hex::encode(&key_blob[..prefix_len]);
    format!("blob:{}:{}", key_blob.len(), prefix_hex)
}

async fn run_confirm_command(
    argv: &[String],
    timeout: Duration,
    env: &ConfirmEnv<'_>,
) -> Result<std::process::ExitStatus, ConfirmError> {
    let program = argv
        .first()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "confirm argv is empty"))?;
    let mut cmd = Command::new(program);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.env("SECRETIVE_CONFIRM_REQUEST", "sign");
    cmd.env("SECRETIVE_CONFIRM_KEY_ID", env.key_id);
    cmd.env(
        "SECRETIVE_CONFIRM_KEY_FINGERPRINT",
        env.key_fingerprint.unwrap_or(""),
    );
    cmd.env(
        "SECRETIVE_CONFIRM_KEY_COMMENT",
        env.key_comment.unwrap_or(""),
    );
    cmd.env("SECRETIVE_CONFIRM_FLAGS", env.flags.to_string());
    cmd.env("SECRETIVE_CONFIRM_DATA_LEN", env.data_len.to_string());
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn()?;
    let status = tokio::time::timeout(timeout, child.wait())
        .await
        .map_err(|_| ConfirmError::Timeout)?;
    status.map_err(ConfirmError::Wait)
}

#[derive(Debug, Clone, Copy)]
struct SignMetricsSnapshot {
    captured_unix_ms: u64,
    started_unix_ms: u64,
    count: u64,
    errors: u64,
    timeouts: u64,
    avg_ns: f64,
    queue_wait_avg_ns: f64,
    queue_wait_max_ns: u64,
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
    store_sign_file: u64,
    store_sign_pkcs11: u64,
    store_sign_secure_enclave: u64,
    store_sign_other: u64,
    queue_wait_histogram: [u64; QUEUE_WAIT_BUCKET_COUNT],
    queue_wait_percentiles: QueueWaitPercentiles,
}

fn build_metrics_snapshot(sign_semaphore: &Semaphore, max_signers: u64) -> SignMetricsSnapshot {
    let captured_unix_ms = unix_now_ms();
    let started_unix_ms = *AGENT_STARTED_UNIX_MS.get_or_init(unix_now_ms);
    let count = SIGN_COUNT.load(Ordering::Relaxed);
    let errors = SIGN_ERRORS.load(Ordering::Relaxed);
    let timeouts = SIGN_TIMEOUTS.load(Ordering::Relaxed);
    let total = SIGN_TIME_NS.load(Ordering::Relaxed) as f64;
    let avg_ns = if count > 0 { total / count as f64 } else { 0.0 };
    let wait_total = SIGN_QUEUE_WAIT_NS.load(Ordering::Relaxed) as f64;
    let queue_wait_avg_ns = if count > 0 {
        wait_total / count as f64
    } else {
        0.0
    };
    let queue_wait_max_ns = SIGN_QUEUE_WAIT_MAX_NS.load(Ordering::Relaxed);
    let available = sign_semaphore.available_permits() as u64;
    let in_flight = max_signers.saturating_sub(available);
    let connections = CONNECTION_COUNT.load(Ordering::Relaxed);
    let active_connections = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    let max_active_connections = MAX_ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
    let max_connections = MAX_CONNECTIONS.load(Ordering::Relaxed);
    let connection_rejected = CONNECTION_REJECTED.load(Ordering::Relaxed);
    let list_count = LIST_COUNT.load(Ordering::Relaxed);
    let list_hit = LIST_CACHE_HIT.load(Ordering::Relaxed);
    let list_stale = LIST_CACHE_STALE.load(Ordering::Relaxed);
    let list_refresh = LIST_REFRESH.load(Ordering::Relaxed);
    let list_errors = LIST_ERRORS.load(Ordering::Relaxed);
    let store_sign_file = STORE_SIGN_FILE.load(Ordering::Relaxed);
    let store_sign_pkcs11 = STORE_SIGN_PKCS11.load(Ordering::Relaxed);
    let store_sign_secure_enclave = STORE_SIGN_SECURE_ENCLAVE.load(Ordering::Relaxed);
    let store_sign_other = STORE_SIGN_OTHER.load(Ordering::Relaxed);
    let mut queue_wait_histogram = [0u64; QUEUE_WAIT_BUCKET_COUNT];
    for (idx, bucket) in QUEUE_WAIT_BUCKETS.iter().enumerate() {
        queue_wait_histogram[idx] = bucket.load(Ordering::Relaxed);
    }
    let queue_wait_percentiles =
        compute_queue_wait_percentiles_from_histogram(&queue_wait_histogram);
    SignMetricsSnapshot {
        captured_unix_ms,
        started_unix_ms,
        count,
        errors,
        timeouts,
        avg_ns,
        queue_wait_avg_ns,
        queue_wait_max_ns,
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
        store_sign_file,
        store_sign_pkcs11,
        store_sign_secure_enclave,
        store_sign_other,
        queue_wait_histogram,
        queue_wait_percentiles,
    }
}

fn format_metrics_json(kind: &str, metrics: &SignMetricsSnapshot) -> String {
    let suggested = QUEUE_WAIT_SUGGESTION.get().map(|suggestion| {
        serde_json::json!({
            "tail_ns": suggestion.tail_ns,
            "tail_ratio": suggestion.tail_ratio,
            "profile": {
                "label": suggestion.profile_label,
                "inferred": suggestion.profile_inferred,
            },
        })
    });

    serde_json::json!({
        "kind": kind,
        "captured_unix_ms": metrics.captured_unix_ms,
        "started_unix_ms": metrics.started_unix_ms,
        "count": metrics.count,
        "errors": metrics.errors,
        "timeouts": metrics.timeouts,
        "avg_ns": metrics.avg_ns,
        "queue_wait_avg_ns": metrics.queue_wait_avg_ns,
        "queue_wait_max_ns": metrics.queue_wait_max_ns,
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
        "list_errors": metrics.list_errors,
        "store_sign_file": metrics.store_sign_file,
        "store_sign_pkcs11": metrics.store_sign_pkcs11,
        "store_sign_secure_enclave": metrics.store_sign_secure_enclave,
        "store_sign_other": metrics.store_sign_other,
        "queue_wait_histogram": metrics.queue_wait_histogram,
        "queue_wait_percentiles": metrics.queue_wait_percentiles,
        "queue_wait_suggested": suggested,
    })
    .to_string()
}

fn metrics_output_path() -> Option<PathBuf> {
    METRICS_OUTPUT_PATH
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

fn note_metrics_write_error(path: &Path, err: &std::io::Error) {
    let errors = METRICS_WRITE_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
    if errors == 1 || errors % 100 == 0 {
        warn!(
            errors,
            path = %path.display(),
            ?err,
            "failed to write metrics output"
        );
    }
}

fn emit_metrics_output(kind: &str, metrics: &SignMetricsSnapshot) {
    let Some(path) = metrics_output_path() else {
        return;
    };

    let payload = format_metrics_json(kind, metrics);
    tracing::debug!(kind, path = %path.display(), "writing metrics snapshot");
    if let Some(parent) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            note_metrics_write_error(&path, &err);
            return;
        }
    }

    let temp_path = path.with_extension("tmp");
    if let Err(err) = std::fs::write(&temp_path, payload.as_bytes()) {
        note_metrics_write_error(&path, &err);
        return;
    }
    if let Err(err) = std::fs::rename(&temp_path, &path) {
        let _ = std::fs::remove_file(&temp_path);
        note_metrics_write_error(&path, &err);
    }
}

fn emit_sign_metrics(kind: &str, metrics: &SignMetricsSnapshot) {
    emit_metrics_output(kind, metrics);

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
        queue_wait_avg_ns = metrics.queue_wait_avg_ns,
        queue_wait_max_ns = metrics.queue_wait_max_ns,
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
        store_sign_file = metrics.store_sign_file,
        store_sign_pkcs11 = metrics.store_sign_pkcs11,
        store_sign_secure_enclave = metrics.store_sign_secure_enclave,
        store_sign_other = metrics.store_sign_other,
        queue_wait_histogram = ?metrics.queue_wait_histogram,
        queue_wait_percentiles = ?metrics.queue_wait_percentiles,
        captured_unix_ms = metrics.captured_unix_ms,
        started_unix_ms = metrics.started_unix_ms,
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
    if let Some(path) = config.metrics_output_path.as_ref() {
        if path.trim().is_empty() {
            out.errors
                .push("metrics_output_path must not be empty when set".to_string());
        }
    }
    let metrics_every_enabled = config.metrics_every.unwrap_or(1000) > 0;
    let metrics_interval_enabled = config.metrics_interval_ms.unwrap_or(0) > 0;
    if !metrics_every_enabled && !metrics_interval_enabled {
        out.warnings.push(
            "metrics_every=0 and metrics_interval_ms unset/0 disable automatic metrics emission"
                .to_string(),
        );
    }
    if config.metrics_output_path.is_some() && !metrics_every_enabled && !metrics_interval_enabled {
        out.warnings.push(
            "metrics_output_path is set but automatic metrics emission is disabled".to_string(),
        );
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
                    if cfg!(target_os = "macos") {
                        has_key_source = true;
                    } else {
                        out.errors.push(format!(
                            "stores[{idx}] secure_enclave is only supported on macOS"
                        ));
                    }
                }
                StoreConfig::Pkcs11 {
                    module_path,
                    pin_env: _,
                    slot: _,
                    refresh_min_interval_ms: _,
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

    if let Some(policy) = &config.policy {
        if let Some(values) = &policy.allow_key_blobs {
            for (idx, value) in values.iter().enumerate() {
                if hex::decode(value.trim()).is_err() {
                    out.errors.push(format!(
                        "policy.allow_key_blobs[{idx}] must be valid hex key blob"
                    ));
                }
            }
        }
        if let Some(values) = &policy.deny_key_blobs {
            for (idx, value) in values.iter().enumerate() {
                if hex::decode(value.trim()).is_err() {
                    out.errors.push(format!(
                        "policy.deny_key_blobs[{idx}] must be valid hex key blob"
                    ));
                }
            }
        }
        if let Some(values) = &policy.allow_fingerprints {
            for (idx, value) in values.iter().enumerate() {
                if normalize_fingerprint(value).is_none() {
                    out.errors.push(format!(
                        "policy.allow_fingerprints[{idx}] must be a valid fingerprint"
                    ));
                }
            }
        }
        if let Some(values) = &policy.pin_fingerprints {
            for (idx, value) in values.iter().enumerate() {
                if normalize_fingerprint(value).is_none() {
                    out.errors.push(format!(
                        "policy.pin_fingerprints[{idx}] must be a valid fingerprint"
                    ));
                }
            }
        }
        if let Some(values) = &policy.deny_fingerprints {
            for (idx, value) in values.iter().enumerate() {
                if normalize_fingerprint(value).is_none() {
                    out.errors.push(format!(
                        "policy.deny_fingerprints[{idx}] must be a valid fingerprint"
                    ));
                }
            }
        }
        if let Some(values) = &policy.allow_comments {
            for (idx, value) in values.iter().enumerate() {
                if normalize_comment(value).is_empty() {
                    out.errors
                        .push(format!("policy.allow_comments[{idx}] must not be empty"));
                }
            }
        }
        if let Some(values) = &policy.deny_comments {
            for (idx, value) in values.iter().enumerate() {
                if normalize_comment(value).is_empty() {
                    out.errors
                        .push(format!("policy.deny_comments[{idx}] must not be empty"));
                }
            }
        }

        if let Some(argv) = &policy.confirm_command {
            if argv.is_empty() {
                out.errors
                    .push("policy.confirm_command must be a non-empty argv list".to_string());
            } else if argv[0].trim().is_empty() {
                out.errors
                    .push("policy.confirm_command[0] (program) must not be empty".to_string());
            } else if argv.iter().any(|value| value.trim().is_empty()) {
                out.warnings.push(
                    "policy.confirm_command contains empty argv entries; trim or remove them"
                        .to_string(),
                );
            }
            if matches!(policy.confirm_timeout_ms, Some(0)) {
                out.errors
                    .push("policy.confirm_timeout_ms must be greater than 0 when set".to_string());
            }
            if policy.confirm_cache_ms.unwrap_or(0) == 0 {
                out.warnings.push(
                    "policy.confirm_cache_ms is 0: confirm_command will run for every sign request (expect high overhead)"
                        .to_string(),
                );
            }
        }
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
    Config::default()
}

fn default_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(path).join("secretive").join("agent.json"));
    }
    BaseDirs::new().map(|dirs| dirs.config_dir().join("secretive").join("agent.json"))
}

#[cfg(test)]
mod queue_wait_suggestion_tests {
    use super::*;

    fn config_with_profile(profile: Option<&str>) -> Config {
        let mut config = Config::default();
        if let Some(name) = profile {
            config.profile = Some(name.to_string());
        }
        config
    }

    #[test]
    fn pssh_profile_expands_tail_for_high_concurrency() {
        let config = config_with_profile(Some("pssh"));
        let suggestion = build_queue_wait_suggestion_with_cores(&config, 240, 16);
        assert!(suggestion.tail_ns > 4_000_000);
        assert!(suggestion.tail_ratio > 0.03);
    }

    #[test]
    fn balanced_profile_tightens_when_signers_low() {
        let config = config_with_profile(None);
        let suggestion = build_queue_wait_suggestion_with_cores(&config, 8, 16);
        assert!(suggestion.tail_ns < 8_000_000);
        assert!(suggestion.tail_ratio <= 0.05);
    }

    #[test]
    fn pkcs11_store_adds_margin() {
        let mut config = config_with_profile(Some("fanout"));
        config.stores = Some(vec![StoreConfig::Pkcs11 {
            module_path: "/tmp/libpkcs11.so".to_string(),
            slot: None,
            pin_env: None,
            refresh_min_interval_ms: None,
        }]);
        let suggestion = build_queue_wait_suggestion_with_cores(&config, 64, 8);
        assert!(suggestion.tail_ns > 6_000_000);
        assert!(suggestion.has_pkcs11);
    }

    #[test]
    fn suggestion_json_contains_env_fields() {
        let config = config_with_profile(Some("pssh"));
        let suggestion = build_queue_wait_suggestion_with_cores(&config, 64, 8);
        let json = queue_wait_suggestion_json(&suggestion);
        assert_eq!(json["tail_ns"].as_u64(), Some(suggestion.tail_ns));
        assert!(json["env"]["SLO_QUEUE_WAIT_TAIL_NS"].as_u64().is_some());
        assert!(json["env"]["SLO_QUEUE_WAIT_TAIL_MAX_RATIO"]
            .as_f64()
            .is_some());
    }
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
    metrics_interval_ms: Option<u64>,
    metrics_json: Option<bool>,
    metrics_output_path: Option<String>,
    audit_requests: Option<bool>,
    pid_file: Option<String>,
    identity_cache_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    inline_sign: Option<bool>,
    sign_timeout_ms: Option<u64>,
    reset_metrics: bool,
    pid: Option<u32>,
    check_config: bool,
    dump_effective_config: bool,
    suggest_queue_wait: bool,
    suggest_queue_wait_json: bool,
    suggest_queue_wait_quiet: bool,
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
        metrics_interval_ms: None,
        metrics_json: None,
        metrics_output_path: None,
        audit_requests: None,
        pid_file: None,
        identity_cache_ms: None,
        idle_timeout_ms: None,
        inline_sign: None,
        sign_timeout_ms: None,
        reset_metrics: false,
        pid: None,
        check_config: false,
        dump_effective_config: false,
        suggest_queue_wait: false,
        suggest_queue_wait_json: false,
        suggest_queue_wait_quiet: false,
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
            "--metrics-interval-ms" => {
                if let Some(value) = args.next() {
                    parsed.metrics_interval_ms = value.parse().ok();
                }
            }
            "--metrics-json" => parsed.metrics_json = Some(true),
            "--no-metrics-json" => parsed.metrics_json = Some(false),
            "--metrics-output" => parsed.metrics_output_path = args.next(),
            "--audit-requests" => parsed.audit_requests = Some(true),
            "--no-audit-requests" => parsed.audit_requests = Some(false),
            "--sign-timeout-ms" => {
                if let Some(value) = args.next() {
                    parsed.sign_timeout_ms = value.parse().ok();
                }
            }
            "--suggest-queue-wait" => parsed.suggest_queue_wait = true,
            "--suggest-queue-wait-json" => {
                parsed.suggest_queue_wait = true;
                parsed.suggest_queue_wait_json = true;
            }
            "--suggest-queue-wait-quiet" => {
                parsed.suggest_queue_wait = true;
                parsed.suggest_queue_wait_quiet = true;
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
            "--reset-metrics" => parsed.reset_metrics = true,
            "--pid" => {
                if let Some(value) = args.next() {
                    parsed.pid = value.parse().ok();
                }
            }
            "--check-config" => parsed.check_config = true,
            "--dump-effective-config" => parsed.dump_effective_config = true,
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
    println!("  --profile <balanced|fanout|pssh|low-memory>");
    println!("  --config <path> --socket <path> --key <path>");
    println!("  --socket-backlog <n>");
    println!("  --default-scan | --no-default-scan");
    println!(
        "  --max-signers <n> --max-connections <n> --max-blocking-threads <n> --worker-threads <n>"
    );
    println!("  --metrics-every <n>");
    println!("  --metrics-interval-ms <n>");
    println!("  --metrics-json | --no-metrics-json");
    println!("  --metrics-output <path>");
    println!("  --audit-requests | --no-audit-requests");
    println!("  --sign-timeout-ms <n>");
    println!("  --suggest-queue-wait");
    println!("  --suggest-queue-wait-json");
    println!("  --suggest-queue-wait-quiet");
    println!("  --watch | --no-watch --watch-debounce-ms <n> --pid-file <path>");
    println!("  --identity-cache-ms <n>");
    println!("  --inline-sign | --no-inline-sign");
    println!("  --idle-timeout-ms <n>");
    println!("  --check-config");
    println!("  --dump-effective-config");
    println!("  --version");
    println!("  --reset-metrics (admin helper; requires --pid or --pid-file on Unix)");
    println!("  --pid <pid> (admin helper used with --reset-metrics)\n");
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
    access_policy: Arc<AccessPolicy>,
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
                        let access_policy = access_policy.clone();
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
                                    access_policy,
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
    access_policy: Arc<AccessPolicy>,
    idle_timeout: Option<Duration>,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    info!(pipe = %pipe_name, "secretive agent listening");

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut first_pipe_instance = true;
    loop {
        let mut options = ServerOptions::new();
        options.reject_remote_clients(true);
        if first_pipe_instance {
            options.first_pipe_instance(true);
        }
        let server = match options.create(&pipe_name) {
            Ok(server) => {
                first_pipe_instance = false;
                server
            }
            Err(err) => {
                if first_pipe_instance {
                    warn!(
                        ?err,
                        "failed to claim first pipe instance; continuing without first-instance guard"
                    );
                    first_pipe_instance = false;
                    continue;
                }
                return Err(err);
            }
        };
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
                let access_policy = access_policy.clone();
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
                            access_policy,
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
    access_policy: Arc<AccessPolicy>,
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
                let audit_started = audit_start();
                LIST_COUNT.fetch_add(1, Ordering::Relaxed);
                match identity_cache.get_payload_or_refresh(&registry).await {
                    Ok(payload) => {
                        if let Err(err) = stream.write_all(payload.as_ref()).await {
                            warn!(?err, "failed to write identities");
                            emit_list_audit("write_error", payload.len(), audit_started);
                            break;
                        }
                        emit_list_audit("ok", payload.len(), audit_started);
                    }
                    Err(err) => {
                        warn!(?err, "failed to list identities");
                        emit_list_audit("lookup_error", 0, audit_started);
                        if let Err(err) = stream.write_all(failure_frame()).await {
                            warn!(?err, "failed to write failure response");
                            emit_list_audit("write_error", 0, audit_started);
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
                    &access_policy,
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
                emit_unknown_audit(message_type);
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
    buffer.resize(len, 0);
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
    access_policy: &Arc<AccessPolicy>,
    sign_semaphore: &Semaphore,
    inline_sign: bool,
    sign_timeout: Option<Duration>,
) -> AgentResponse {
    let audit_started = audit_start();
    let audit_key = if audit_started.is_some() {
        Some(audit_key_id(key_blob.as_ref()))
    } else {
        None
    };
    let audit_data_len = data.len();

    let key_comment = if access_policy.is_enabled() && access_policy.requires_comment_lookup() {
        find_comment_for_key(registry, key_blob.as_ref()).await
    } else {
        None
    };

    if access_policy.is_enabled() {
        match access_policy.evaluate(key_blob.as_ref(), key_comment.as_deref()) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => {
                warn!(reason, "policy denied sign request");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "policy_denied",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
        }
    }

    let metrics_every = METRICS_EVERY.load(Ordering::Relaxed);
    let start = if metrics_every > 0 {
        Some(Instant::now())
    } else {
        None
    };
    let wait_started = Instant::now();
    let permit = match sign_timeout {
        Some(timeout) => match tokio::time::timeout(timeout, sign_semaphore.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                warn!("signing semaphore closed");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "semaphore_closed",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
            Err(_) => {
                let timeouts = SIGN_TIMEOUTS.fetch_add(1, Ordering::Relaxed) + 1;
                if timeouts % 100 == 0 {
                    warn!(timeouts, "sign timeout");
                }
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(key_id, audit_data_len, flags, "timeout", audit_started);
                }
                return AgentResponse::Failure;
            }
        },
        None => match sign_semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("signing semaphore closed");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "semaphore_closed",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
        },
    };
    let wait_ns = wait_started.elapsed().as_nanos() as u64;
    SIGN_QUEUE_WAIT_NS.fetch_add(wait_ns, Ordering::Relaxed);
    update_atomic_max(&SIGN_QUEUE_WAIT_MAX_NS, wait_ns);
    record_queue_wait_bucket(wait_ns);

    if access_policy.confirm_enabled() {
        match access_policy
            .confirm_sign_request(
                key_blob.as_ref(),
                key_comment.as_deref(),
                flags,
                audit_data_len,
            )
            .await
        {
            Ok(ConfirmOutcome::Skipped | ConfirmOutcome::CachedAllow | ConfirmOutcome::Allow) => {}
            Ok(ConfirmOutcome::Deny) => {
                warn!("confirm command denied sign request");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "confirm_denied",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
            Err(ConfirmError::Timeout) => {
                warn!("confirm command timed out");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "confirm_timeout",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
            Err(err) => {
                warn!(?err, "confirm command failed");
                SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
                if let Some(key_id) = audit_key.as_deref() {
                    emit_sign_audit(
                        key_id,
                        audit_data_len,
                        flags,
                        "confirm_error",
                        audit_started,
                    );
                }
                return AgentResponse::Failure;
            }
        }
    }

    let registry = Arc::clone(registry);
    let result = if inline_sign {
        Ok(registry.sign_with_store(key_blob.as_ref(), data.as_ref(), flags))
    } else {
        tokio::task::spawn_blocking(move || {
            registry.sign_with_store(key_blob.as_ref(), data.as_ref(), flags)
        })
        .await
    };
    drop(permit);
    match result {
        Ok(Ok((signature_blob, store_kind))) => {
            match store_kind {
                "file" => {
                    STORE_SIGN_FILE.fetch_add(1, Ordering::Relaxed);
                }
                "pkcs11" => {
                    STORE_SIGN_PKCS11.fetch_add(1, Ordering::Relaxed);
                }
                "secure_enclave" => {
                    STORE_SIGN_SECURE_ENCLAVE.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    STORE_SIGN_OTHER.fetch_add(1, Ordering::Relaxed);
                }
            }
            let count = SIGN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(start) = start {
                let elapsed = start.elapsed();
                SIGN_TIME_NS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
                if count % metrics_every == 0 {
                    let max_signers = MAX_SIGNERS.load(Ordering::Relaxed);
                    let snapshot = build_metrics_snapshot(sign_semaphore, max_signers);
                    emit_sign_metrics("interval", &snapshot);
                }
            }
            if let Some(key_id) = audit_key.as_deref() {
                emit_sign_audit(key_id, audit_data_len, flags, "ok", audit_started);
            }
            AgentResponse::SignResponse { signature_blob }
        }
        Ok(Err(err)) => {
            warn!(?err, "sign request failed");
            SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
            if let Some(key_id) = audit_key.as_deref() {
                emit_sign_audit(key_id, audit_data_len, flags, "sign_error", audit_started);
            }
            AgentResponse::Failure
        }
        Err(err) => {
            warn!(?err, "sign worker failed");
            SIGN_ERRORS.fetch_add(1, Ordering::Relaxed);
            if let Some(key_id) = audit_key.as_deref() {
                emit_sign_audit(key_id, audit_data_len, flags, "worker_error", audit_started);
            }
            AgentResponse::Failure
        }
    }
}

async fn find_comment_for_key(registry: &Arc<KeyStoreRegistry>, key_blob: &[u8]) -> Option<String> {
    let registry = Arc::clone(registry);
    let key_blob = key_blob.to_vec();
    let result = tokio::task::spawn_blocking(move || registry.list_identities()).await;
    match result {
        Ok(Ok(identities)) => identities
            .into_iter()
            .find(|identity| identity.key_blob == key_blob)
            .map(|identity| identity.comment),
        _ => None,
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

fn audit_start() -> Option<Instant> {
    if AUDIT_REQUESTS.load(Ordering::Relaxed) {
        Some(Instant::now())
    } else {
        None
    }
}

fn audit_latency_us(started: Option<Instant>) -> u64 {
    started
        .map(|value| value.elapsed().as_micros() as u64)
        .unwrap_or(0)
}

fn audit_key_id(key_blob: &[u8]) -> String {
    if let Some(fingerprint) = key_blob_fingerprint(key_blob) {
        return fingerprint;
    }
    format!("blob:{}b", key_blob.len())
}

fn emit_list_audit(outcome: &str, payload_bytes: usize, started: Option<Instant>) {
    if !AUDIT_REQUESTS.load(Ordering::Relaxed) {
        return;
    }
    info!(
        event = "request_audit",
        request = "list",
        outcome,
        payload_bytes,
        latency_us = audit_latency_us(started),
        "request audit"
    );
}

fn emit_unknown_audit(message_type: u8) {
    if !AUDIT_REQUESTS.load(Ordering::Relaxed) {
        return;
    }
    info!(
        event = "request_audit",
        request = "unknown",
        outcome = "failure",
        message_type,
        "request audit"
    );
}

fn emit_sign_audit(
    key_id: &str,
    data_len: usize,
    flags: u32,
    outcome: &str,
    started: Option<Instant>,
) {
    if !AUDIT_REQUESTS.load(Ordering::Relaxed) {
        return;
    }
    info!(
        event = "request_audit",
        request = "sign",
        outcome,
        key_id = %key_id,
        data_len,
        flags,
        latency_us = audit_latency_us(started),
        "request audit"
    );
}

fn now_ms() -> u64 {
    let start = START_INSTANT.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn metrics_test_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn empty_config() -> Config {
        Config {
            profile: None,
            socket_path: None,
            socket_backlog: None,
            key_paths: None,
            scan_default_dir: None,
            stores: None,
            policy: None,
            max_signers: None,
            max_connections: None,
            max_blocking_threads: None,
            worker_threads: None,
            watch_files: None,
            watch_debounce_ms: None,
            metrics_every: None,
            metrics_interval_ms: None,
            metrics_json: None,
            metrics_output_path: None,
            audit_requests: None,
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
    fn validate_config_validates_secure_enclave_store_for_platform() {
        let mut config = empty_config();
        config.stores = Some(vec![StoreConfig::SecureEnclave]);
        let validation = validate_config(&config);
        if cfg!(target_os = "macos") {
            assert!(validation.errors.is_empty());
        } else {
            assert!(validation
                .errors
                .iter()
                .any(|entry| entry.contains("secure_enclave is only supported on macOS")));
        }
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
    fn profile_pssh_sets_expected_defaults() {
        let mut config = empty_config();
        config.profile = Some("pssh".to_string());
        apply_profile_defaults(&mut config);

        assert_eq!(config.max_connections, Some(32768));
        assert_eq!(config.socket_backlog, Some(4096));
        assert_eq!(config.sign_timeout_ms, Some(150));
        assert_eq!(config.identity_cache_ms, Some(10000));
        assert_eq!(config.idle_timeout_ms, Some(5000));
        assert_eq!(config.watch_debounce_ms, Some(500));
        assert!(config.max_signers.unwrap_or(0) >= 32);
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
    fn inline_sign_defaults_to_true_without_pkcs11() {
        assert!(effective_inline_sign(None, false));
        assert!(!effective_inline_sign(None, true));
    }

    #[test]
    fn inline_sign_explicit_override_wins() {
        assert!(effective_inline_sign(Some(true), true));
        assert!(!effective_inline_sign(Some(false), false));
    }

    #[test]
    fn update_atomic_max_tracks_largest_value() {
        let value = AtomicU64::new(10);
        update_atomic_max(&value, 7);
        assert_eq!(value.load(Ordering::Relaxed), 10);
        update_atomic_max(&value, 12);
        assert_eq!(value.load(Ordering::Relaxed), 12);
    }

    #[test]
    fn reset_sign_metrics_zeroes_counters() {
        let _guard = metrics_test_lock().lock().expect("metrics test lock");
        SIGN_COUNT.store(9, Ordering::Relaxed);
        SIGN_TIME_NS.store(123, Ordering::Relaxed);
        SIGN_QUEUE_WAIT_NS.store(456, Ordering::Relaxed);
        SIGN_QUEUE_WAIT_MAX_NS.store(789, Ordering::Relaxed);
        SIGN_ERRORS.store(3, Ordering::Relaxed);
        SIGN_TIMEOUTS.store(4, Ordering::Relaxed);
        CONNECTION_COUNT.store(5, Ordering::Relaxed);
        CONNECTION_REJECTED.store(6, Ordering::Relaxed);
        LIST_COUNT.store(7, Ordering::Relaxed);
        LIST_CACHE_HIT.store(8, Ordering::Relaxed);
        LIST_CACHE_STALE.store(9, Ordering::Relaxed);
        LIST_REFRESH.store(10, Ordering::Relaxed);
        LIST_ERRORS.store(11, Ordering::Relaxed);
        STORE_SIGN_FILE.store(12, Ordering::Relaxed);
        STORE_SIGN_PKCS11.store(13, Ordering::Relaxed);
        STORE_SIGN_SECURE_ENCLAVE.store(14, Ordering::Relaxed);
        STORE_SIGN_OTHER.store(15, Ordering::Relaxed);
        ACTIVE_CONNECTIONS.store(4, Ordering::Relaxed);
        MAX_ACTIVE_CONNECTIONS.store(99, Ordering::Relaxed);
        QUEUE_WAIT_BUCKETS[0].store(2, Ordering::Relaxed);
        QUEUE_WAIT_BUCKETS[QUEUE_WAIT_BUCKET_COUNT - 1].store(3, Ordering::Relaxed);

        reset_sign_metrics();

        assert_eq!(SIGN_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(SIGN_ERRORS.load(Ordering::Relaxed), 0);
        assert_eq!(CONNECTION_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(LIST_REFRESH.load(Ordering::Relaxed), 0);
        assert_eq!(STORE_SIGN_FILE.load(Ordering::Relaxed), 0);
        assert_eq!(
            MAX_ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
            ACTIVE_CONNECTIONS.load(Ordering::Relaxed)
        );
        assert!(QUEUE_WAIT_BUCKETS
            .iter()
            .all(|bucket| bucket.load(Ordering::Relaxed) == 0));

        ACTIVE_CONNECTIONS.store(0, Ordering::Relaxed);
        reset_sign_metrics();
    }

    #[test]
    fn compute_queue_wait_percentiles_from_histogram_assigns_expected_bounds() {
        let mut histogram = [0u64; QUEUE_WAIT_BUCKET_COUNT];
        histogram[0] = 50;
        histogram[5] = 40;
        histogram[QUEUE_WAIT_BUCKET_COUNT - 1] = 10;
        let percentiles = compute_queue_wait_percentiles_from_histogram(&histogram);
        let p50 = percentiles.p50.expect("p50");
        assert_eq!(p50.ns, QUEUE_WAIT_BUCKET_BOUNDS[0]);
        assert!(!p50.open_ended);
        let p90 = percentiles.p90.expect("p90");
        assert_eq!(p90.ns, QUEUE_WAIT_BUCKET_BOUNDS[5]);
        assert!(!p90.open_ended);
        let p99 = percentiles.p99.expect("p99");
        assert_eq!(p99.ns, *QUEUE_WAIT_BUCKET_BOUNDS.last().unwrap());
        assert!(p99.open_ended);
    }

    #[test]
    fn metrics_json_contains_expected_fields() {
        let snapshot = SignMetricsSnapshot {
            captured_unix_ms: 1,
            started_unix_ms: 2,
            count: 1,
            errors: 2,
            timeouts: 3,
            avg_ns: 4.0,
            queue_wait_avg_ns: 5.0,
            queue_wait_max_ns: 6,
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
            store_sign_file: 17,
            store_sign_pkcs11: 18,
            store_sign_secure_enclave: 19,
            store_sign_other: 20,
            queue_wait_histogram: [0; QUEUE_WAIT_BUCKET_COUNT],
            queue_wait_percentiles: QueueWaitPercentiles::default(),
        };
        let payload = format_metrics_json("snapshot", &snapshot);
        assert!(payload.contains("\"kind\":\"snapshot\""));
        assert!(payload.contains("\"count\":1"));
        assert!(payload.contains("\"max_signers\":6"));
        assert!(payload.contains("\"queue_wait_avg_ns\":5.0"));
        assert!(payload.contains("\"queue_wait_max_ns\":6"));
        assert!(payload.contains("\"list_errors\":16"));
        assert!(payload.contains("\"store_sign_file\":17"));
        assert!(payload.contains("\"queue_wait_histogram\""));
        assert!(payload.contains("\"captured_unix_ms\":1"));
        assert!(payload.contains("\"started_unix_ms\":2"));
        assert!(payload.contains("\"queue_wait_suggested\":null"));
    }

    #[test]
    fn emit_metrics_output_writes_json_file() {
        let path = std::env::temp_dir().join(format!(
            "secretive-metrics-{}-{}.json",
            std::process::id(),
            now_ms()
        ));
        {
            let mut guard = METRICS_OUTPUT_PATH
                .lock()
                .expect("metrics output path lock");
            *guard = Some(path.clone());
        }

        let snapshot = SignMetricsSnapshot {
            captured_unix_ms: 100,
            started_unix_ms: 50,
            count: 1,
            errors: 0,
            timeouts: 0,
            avg_ns: 2.0,
            queue_wait_avg_ns: 1.0,
            queue_wait_max_ns: 3,
            in_flight: 0,
            max_signers: 4,
            connections: 5,
            active_connections: 6,
            max_active_connections: 7,
            max_connections: 8,
            connection_rejected: 0,
            list_count: 0,
            list_hit: 0,
            list_stale: 0,
            list_refresh: 0,
            list_errors: 0,
            store_sign_file: 1,
            store_sign_pkcs11: 0,
            store_sign_secure_enclave: 0,
            store_sign_other: 0,
            queue_wait_histogram: [0; QUEUE_WAIT_BUCKET_COUNT],
            queue_wait_percentiles: QueueWaitPercentiles::default(),
        };
        emit_metrics_output("snapshot", &snapshot);
        let content = std::fs::read_to_string(&path).expect("read metrics output");
        assert!(content.contains("\"kind\":\"snapshot\""));
        assert!(content.contains("\"queue_wait_max_ns\":3"));
        assert!(content.contains("\"queue_wait_histogram\""));
        assert!(content.contains("\"captured_unix_ms\":100"));
        assert!(content.contains("\"started_unix_ms\":50"));

        let _ = std::fs::remove_file(&path);
        {
            let mut guard = METRICS_OUTPUT_PATH
                .lock()
                .expect("metrics output path lock");
            *guard = None;
        }
    }

    #[test]
    fn audit_key_id_formats_fingerprint_or_blob_length() {
        let public_key = ssh_key::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICG6kjK0iJxESpkwvCTOwwcUsJcggrGhSdHyaP0JHGub",
        )
        .expect("public key");
        let key_blob = public_key.to_bytes().expect("key blob");
        let fingerprint = audit_key_id(&key_blob);
        assert!(fingerprint.starts_with("SHA256:"));

        let fallback = audit_key_id(&[1, 2, 3]);
        assert_eq!(fallback, "blob:3b");
    }

    #[test]
    fn policy_deny_fingerprint_blocks_sign() {
        let public_key = ssh_key::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICG6kjK0iJxESpkwvCTOwwcUsJcggrGhSdHyaP0JHGub",
        )
        .expect("public key");
        let key_blob = public_key.to_bytes().expect("key blob");
        let fingerprint =
            normalize_fingerprint(&public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
                .expect("fingerprint");

        let mut policy = AccessPolicy::default();
        policy.deny_fingerprints.insert(fingerprint);
        let decision = policy.evaluate(&key_blob, None);
        assert!(matches!(decision, PolicyDecision::Deny("deny_fingerprint")));
    }

    #[test]
    fn policy_allow_comments_requires_match() {
        let policy = AccessPolicy {
            allow_comments: HashSet::from([normalize_comment("prod-key")]),
            ..AccessPolicy::default()
        };
        assert!(matches!(
            policy.evaluate(&[1, 2, 3], Some("prod-key")),
            PolicyDecision::Allow
        ));
        assert!(matches!(
            policy.evaluate(&[1, 2, 3], Some("other")),
            PolicyDecision::Deny("allowlist_miss")
        ));
    }

    #[test]
    fn validate_config_rejects_invalid_policy_fingerprint() {
        let mut config = empty_config();
        config.policy = Some(AccessPolicyConfig {
            allow_fingerprints: Some(vec!["not-a-fingerprint".to_string()]),
            ..AccessPolicyConfig::default()
        });
        let validation = validate_config(&config);
        assert!(validation.errors.iter().any(|entry| {
            entry.contains("policy.allow_fingerprints[0] must be a valid fingerprint")
        }));
    }

    #[test]
    fn validate_config_rejects_invalid_pin_fingerprint() {
        let mut config = empty_config();
        config.policy = Some(AccessPolicyConfig {
            pin_fingerprints: Some(vec!["bad-pin".to_string()]),
            ..AccessPolicyConfig::default()
        });
        let validation = validate_config(&config);
        assert!(validation.errors.iter().any(|entry| {
            entry.contains("policy.pin_fingerprints[0] must be a valid fingerprint")
        }));
    }

    #[test]
    fn validate_config_rejects_empty_confirm_command() {
        let mut config = empty_config();
        config.policy = Some(AccessPolicyConfig {
            confirm_command: Some(vec![]),
            ..AccessPolicyConfig::default()
        });
        let validation = validate_config(&config);
        assert!(validation.errors.iter().any(|entry| {
            entry.contains("policy.confirm_command must be a non-empty argv list")
        }));
    }

    #[test]
    fn validate_config_rejects_empty_metrics_output_path() {
        let mut config = empty_config();
        config.metrics_output_path = Some("  ".to_string());
        let validation = validate_config(&config);
        assert!(validation
            .errors
            .iter()
            .any(|entry| entry.contains("metrics_output_path must not be empty")));
    }

    #[test]
    fn validate_config_warns_when_metrics_emission_disabled() {
        let mut config = empty_config();
        config.metrics_every = Some(0);
        let validation = validate_config(&config);
        assert!(validation
            .warnings
            .iter()
            .any(|entry| { entry.contains("disable automatic metrics emission") }));
    }

    #[test]
    fn validate_config_warns_when_metrics_output_without_emission() {
        let mut config = empty_config();
        config.metrics_every = Some(0);
        config.metrics_interval_ms = Some(0);
        config.metrics_output_path = Some("/tmp/metrics.json".to_string());
        let validation = validate_config(&config);
        assert!(validation.warnings.iter().any(|entry| entry
            .contains("metrics_output_path is set but automatic metrics emission is disabled")));
    }
}
