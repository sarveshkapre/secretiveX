use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use rand::SeedableRng;
use secretive_proto::{
    encode_request_frame, read_response_type_with_buffer, write_request_with_buffer, AgentRequest,
    AgentResponse, MessageType, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient as AgentStream;
#[cfg(unix)]
use tokio::net::UnixStream as AgentStream;

static LIST_FRAME: OnceLock<Bytes> = OnceLock::new();
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
const QUEUE_WAIT_PERCENTILE_LABELS: [(&str, f64); 4] =
    [("p50", 0.50), ("p90", 0.90), ("p95", 0.95), ("p99", 0.99)];
const METRICS_FILE_ENV: &str = "SECRETIVE_BENCH_METRICS";
const QUEUE_WAIT_TAIL_NS_ENV: &str = "SECRETIVE_BENCH_QUEUE_WAIT_TAIL_NS";
const QUEUE_WAIT_TAIL_RATIO_ENV: &str = "SECRETIVE_BENCH_QUEUE_WAIT_TAIL_MAX_RATIO";
const QUEUE_WAIT_PROFILE_ENV: &str = "SECRETIVE_BENCH_QUEUE_WAIT_PROFILE";

#[derive(Debug)]
struct Args {
    socket_path: Option<String>,
    concurrency: usize,
    requests_per_worker: usize,
    warmup: usize,
    payload_size: usize,
    flags: u32,
    key_blob_hex: Option<String>,
    reconnect: bool,
    list_only: bool,
    randomize_payload: bool,
    json: bool,
    json_compact: bool,
    csv: bool,
    csv_header: bool,
    response_timeout_ms: Option<u64>,
    latency: bool,
    latency_max_samples: usize,
    worker_start_spread_ms: u64,
    metrics_file: Option<String>,
    queue_wait_tail_ns: Option<u64>,
    queue_wait_tail_max_ratio: Option<f64>,
    queue_wait_tail_profile: Option<String>,
    help: bool,
    version: bool,
    duration_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct WorkerResult {
    completed: usize,
    latencies_us: Vec<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args();
    if args.help {
        print_help();
        return Ok(());
    }
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let socket_path = Arc::new(resolve_socket_path(args.socket_path.clone()));
    let shared_key = if args.list_only {
        None
    } else if let Some(hex_key) = args.key_blob_hex.as_deref() {
        Some(hex::decode(hex_key)?)
    } else {
        Some(fetch_first_key(socket_path.as_ref()).await?)
    };

    let total_requests = args.concurrency * args.requests_per_worker;
    if let Some(duration) = args.duration_secs {
        info!(
            ?socket_path,
            concurrency = args.concurrency,
            duration,
            "starting benchmark"
        );
    } else {
        info!(
            ?socket_path,
            concurrency = args.concurrency,
            total_requests,
            "starting benchmark"
        );
    }

    let started_unix_ms = unix_now_ms();
    let start = Instant::now();
    let deadline = args
        .duration_secs
        .map(|secs| start + Duration::from_secs(secs));
    let response_timeout = args.response_timeout_ms.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(Duration::from_millis(value))
        }
    });
    let latency_samples_per_worker = if args.latency {
        args.latency_max_samples
            .checked_div(args.concurrency.max(1))
            .unwrap_or(0)
            .max(1)
    } else {
        0
    };

    let mut handles = Vec::with_capacity(args.concurrency);
    for worker_id in 0..args.concurrency {
        let socket_path = socket_path.clone();
        let requests = args.requests_per_worker;
        let warmup = args.warmup;
        let payload_size = args.payload_size;
        let flags = args.flags;
        let shared_key = shared_key.clone();
        let reconnect = args.reconnect;
        let list_only = args.list_only;
        let randomize_payload = args.randomize_payload;
        let deadline = deadline.clone();
        let response_timeout = response_timeout;
        let latency_samples_per_worker = latency_samples_per_worker;
        let worker_start_delay_ms =
            worker_start_delay_ms(worker_id, args.concurrency, args.worker_start_spread_ms);
        handles.push(tokio::spawn(async move {
            run_worker(
                worker_id,
                socket_path,
                requests,
                warmup,
                payload_size,
                flags,
                shared_key,
                reconnect,
                list_only,
                randomize_payload,
                deadline,
                response_timeout,
                latency_samples_per_worker,
                worker_start_delay_ms,
            )
            .await
        }));
    }

    let mut ok = 0usize;
    let mut failures = 0usize;
    let mut latencies_us = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Ok(worker)) => {
                ok += worker.completed;
                if args.latency {
                    for sample in worker.latencies_us {
                        if latencies_us.len() >= args.latency_max_samples {
                            break;
                        }
                        latencies_us.push(sample);
                    }
                }
            }
            Ok(Err(err)) => {
                error!(?err, "worker failed");
                failures += 1;
            }
            Err(err) => {
                error!(?err, "worker join failed");
                failures += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    let rps = if elapsed.as_secs_f64() > 0.0 {
        ok as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let latency = compute_latency_stats(latencies_us);

    let finished_unix_ms = unix_now_ms();
    let attempted = ok + failures;
    let failure_rate = if attempted > 0 {
        failures as f64 / attempted as f64
    } else {
        0.0
    };
    let success_rate = if attempted > 0 {
        ok as f64 / attempted as f64
    } else {
        0.0
    };

    let socket_value = socket_path.display().to_string();
    let payload = BenchOutput {
        ok,
        failures,
        attempted,
        success_rate,
        failure_rate,
        elapsed_ms: elapsed.as_millis() as u64,
        rps,
        mode: if args.list_only { "list" } else { "sign" },
        reconnect: args.reconnect,
        concurrency: args.concurrency,
        requests_per_worker: args.requests_per_worker,
        requested_total: if args.duration_secs.is_none() {
            Some(total_requests)
        } else {
            None
        },
        duration_secs: args.duration_secs,
        randomize_payload: args.randomize_payload,
        payload_size: args.payload_size,
        flags: args.flags,
        socket_path: socket_value,
        response_timeout_ms: args.response_timeout_ms,
        latency_enabled: args.latency,
        latency_max_samples: args.latency_max_samples,
        worker_start_spread_ms: args.worker_start_spread_ms,
        latency,
        meta: BenchMetadata {
            schema_version: 2,
            bench_version: env!("CARGO_PKG_VERSION"),
            started_unix_ms,
            finished_unix_ms,
            pid: std::process::id(),
            hostname: hostname(),
            target_os: std::env::consts::OS,
            target_arch: std::env::consts::ARCH,
        },
        queue_wait: queue_wait_report(&args),
    };

    if args.csv {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        write_csv_output(&mut handle, &payload, args.csv_header)?;
    } else if args.json || args.json_compact {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if args.json_compact {
            serde_json::to_writer(&mut handle, &payload)?;
        } else {
            serde_json::to_writer_pretty(&mut handle, &payload)?;
        }
        writeln!(handle)?;
    } else {
        println!("Completed {ok} requests in {elapsed:?} ({rps:.2} req/s). Failures: {failures}");
        if let Some(latency) = payload.latency.as_ref() {
            println!(
                "Latency(us): p50={} p95={} p99={} max={} avg={:.2} samples={}",
                latency.p50_us,
                latency.p95_us,
                latency.p99_us,
                latency.max_us,
                latency.avg_us,
                latency.samples
            );
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct BenchOutput {
    ok: usize,
    failures: usize,
    attempted: usize,
    success_rate: f64,
    failure_rate: f64,
    elapsed_ms: u64,
    rps: f64,
    mode: &'static str,
    reconnect: bool,
    concurrency: usize,
    requests_per_worker: usize,
    requested_total: Option<usize>,
    duration_secs: Option<u64>,
    randomize_payload: bool,
    payload_size: usize,
    flags: u32,
    socket_path: String,
    response_timeout_ms: Option<u64>,
    latency_enabled: bool,
    latency_max_samples: usize,
    worker_start_spread_ms: u64,
    latency: Option<LatencyStats>,
    meta: BenchMetadata,
    queue_wait: Option<QueueWaitReport>,
}

#[derive(Serialize)]
struct LatencyStats {
    samples: usize,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
    avg_us: f64,
}

#[derive(Serialize)]
struct BenchMetadata {
    schema_version: u32,
    bench_version: &'static str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    pid: u32,
    hostname: Option<String>,
    target_os: &'static str,
    target_arch: &'static str,
}

#[derive(Debug, Serialize)]
struct QueueWaitReport {
    metrics_path: Option<String>,
    metrics_loaded: bool,
    metrics_error: Option<String>,
    tail_threshold_ns: Option<u64>,
    tail_max_ratio: Option<f64>,
    tail_target_percentile: Option<f64>,
    auto_profile: Option<String>,
    auto_profile_applied: bool,
    tail_mode: Option<QueueWaitTailMode>,
    tail_percentile: Option<QueueWaitPercentileSample>,
    tail_histogram: Option<QueueWaitHistogramSample>,
    percentiles: Option<QueueWaitPercentiles>,
    queue_wait_avg_ns: Option<f64>,
    queue_wait_max_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
struct QueueWaitPercentiles {
    #[serde(default)]
    p50: Option<QueueWaitPercentileValue>,
    #[serde(default)]
    p90: Option<QueueWaitPercentileValue>,
    #[serde(default)]
    p95: Option<QueueWaitPercentileValue>,
    #[serde(default)]
    p99: Option<QueueWaitPercentileValue>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
struct QueueWaitPercentileValue {
    ns: Option<u64>,
    #[serde(default)]
    open_ended: bool,
}

#[derive(Debug, Clone, Serialize)]
struct QueueWaitPercentileSample {
    label: String,
    percentile: f64,
    ns: u64,
    derived_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
struct QueueWaitHistogramSample {
    ratio: f64,
    tail_count: u64,
    total: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum QueueWaitTailMode {
    Percentile,
    Histogram,
}

#[derive(Debug, Deserialize)]
struct AgentMetricsSnapshot {
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    queue_wait_avg_ns: Option<f64>,
    #[serde(default)]
    queue_wait_max_ns: Option<u64>,
    #[serde(default)]
    queue_wait_histogram: Option<Vec<u64>>,
    #[serde(default)]
    queue_wait_percentiles: Option<QueueWaitPercentiles>,
}

fn compute_latency_stats(mut latencies_us: Vec<u64>) -> Option<LatencyStats> {
    if latencies_us.is_empty() {
        return None;
    }
    latencies_us.sort_unstable();
    let len = latencies_us.len();
    let percentile = |p: usize| -> u64 {
        let idx = ((len.saturating_sub(1)) * p) / 100;
        latencies_us[idx]
    };
    let sum: u128 = latencies_us.iter().map(|value| *value as u128).sum();
    let avg_us = sum as f64 / len as f64;
    let max_us = *latencies_us.last().expect("non-empty latency samples");
    Some(LatencyStats {
        samples: len,
        p50_us: percentile(50),
        p95_us: percentile(95),
        p99_us: percentile(99),
        max_us,
        avg_us,
    })
}

fn maybe_record_latency(
    started_at: Option<Instant>,
    latencies_us: &mut Vec<u64>,
    max_samples: usize,
) {
    if let Some(started_at) = started_at {
        if latencies_us.len() < max_samples {
            latencies_us.push(started_at.elapsed().as_micros() as u64);
        }
    }
}

fn unix_now_ms() -> u64 {
    let now = SystemTime::now();
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hostname() -> Option<String> {
    if let Ok(value) = std::env::var("HOSTNAME") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    if let Ok(value) = std::env::var("COMPUTERNAME") {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    None
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn csv_header_row() -> &'static str {
    "timestamp_unix_ms,started_unix_ms,finished_unix_ms,bench_version,target_os,target_arch,hostname,pid,mode,reconnect,concurrency,requests_per_worker,requested_total,duration_secs,payload_size,flags,response_timeout_ms,randomize_payload,latency_enabled,latency_max_samples,worker_start_spread_ms,ok,failures,attempted,success_rate,failure_rate,elapsed_ms,rps,p50_us,p95_us,p99_us,max_us,avg_us,latency_samples,socket_path"
}

fn csv_data_row(payload: &BenchOutput) -> String {
    let latency = payload.latency.as_ref();
    let mut fields = Vec::with_capacity(35);
    fields.push(payload.meta.finished_unix_ms.to_string());
    fields.push(payload.meta.started_unix_ms.to_string());
    fields.push(payload.meta.finished_unix_ms.to_string());
    fields.push(csv_escape(payload.meta.bench_version));
    fields.push(csv_escape(payload.meta.target_os));
    fields.push(csv_escape(payload.meta.target_arch));
    fields.push(csv_escape(payload.meta.hostname.as_deref().unwrap_or("")));
    fields.push(payload.meta.pid.to_string());
    fields.push(csv_escape(payload.mode));
    fields.push(payload.reconnect.to_string());
    fields.push(payload.concurrency.to_string());
    fields.push(payload.requests_per_worker.to_string());
    fields.push(
        payload
            .requested_total
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    fields.push(
        payload
            .duration_secs
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    fields.push(payload.payload_size.to_string());
    fields.push(payload.flags.to_string());
    fields.push(
        payload
            .response_timeout_ms
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    fields.push(payload.randomize_payload.to_string());
    fields.push(payload.latency_enabled.to_string());
    fields.push(payload.latency_max_samples.to_string());
    fields.push(payload.worker_start_spread_ms.to_string());
    fields.push(payload.ok.to_string());
    fields.push(payload.failures.to_string());
    fields.push(payload.attempted.to_string());
    fields.push(format!("{:.6}", payload.success_rate));
    fields.push(format!("{:.6}", payload.failure_rate));
    fields.push(payload.elapsed_ms.to_string());
    fields.push(format!("{:.6}", payload.rps));
    fields.push(
        latency
            .map(|value| value.p50_us.to_string())
            .unwrap_or_default(),
    );
    fields.push(
        latency
            .map(|value| value.p95_us.to_string())
            .unwrap_or_default(),
    );
    fields.push(
        latency
            .map(|value| value.p99_us.to_string())
            .unwrap_or_default(),
    );
    fields.push(
        latency
            .map(|value| value.max_us.to_string())
            .unwrap_or_default(),
    );
    fields.push(
        latency
            .map(|value| format!("{:.6}", value.avg_us))
            .unwrap_or_default(),
    );
    fields.push(
        latency
            .map(|value| value.samples.to_string())
            .unwrap_or_default(),
    );
    fields.push(csv_escape(&payload.socket_path));
    fields.join(",")
}

fn write_csv_output<W: Write>(
    writer: &mut W,
    payload: &BenchOutput,
    include_header: bool,
) -> Result<()> {
    if include_header {
        writeln!(writer, "{}", csv_header_row())?;
    }
    writeln!(writer, "{}", csv_data_row(payload))?;
    Ok(())
}

fn queue_wait_report(args: &Args) -> Option<QueueWaitReport> {
    let should_emit = args.metrics_file.is_some()
        || args.queue_wait_tail_ns.is_some()
        || args.queue_wait_tail_max_ratio.is_some()
        || args.queue_wait_tail_profile.is_some();
    if !should_emit {
        return None;
    }

    let mut tail_threshold_ns = args.queue_wait_tail_ns;
    let mut tail_max_ratio = args.queue_wait_tail_max_ratio;
    let mut auto_profile_applied = false;
    let mut auto_profile = args.queue_wait_tail_profile.clone();

    if let Some(profile) = auto_profile.clone() {
        if tail_threshold_ns.is_none() || tail_max_ratio.is_none() {
            if let Some((default_threshold, default_ratio)) = queue_wait_profile_defaults(&profile)
            {
                if tail_threshold_ns.is_none() {
                    tail_threshold_ns = Some(default_threshold);
                    auto_profile_applied = true;
                }
                if tail_max_ratio.is_none() {
                    tail_max_ratio = Some(default_ratio);
                    auto_profile_applied = true;
                }
            } else {
                warn!(%profile, "unknown queue wait profile override");
                auto_profile = None;
            }
        }
    }

    let tail_target_percentile = tail_max_ratio.map(|ratio| (1.0 - ratio).clamp(0.0, 1.0));

    let mut metrics_loaded = false;
    let mut metrics_error = None;
    let mut percentiles = None;
    let mut queue_wait_avg_ns = None;
    let mut queue_wait_max_ns = None;
    let mut tail_mode = None;
    let mut tail_percentile = None;
    let mut tail_histogram = None;
    let metrics_path = args.metrics_file.clone();

    if let Some(path) = metrics_path.clone() {
        match load_agent_metrics(&path) {
            Ok(snapshot) => {
                metrics_loaded = true;
                percentiles = snapshot.queue_wait_percentiles;
                queue_wait_avg_ns = snapshot.queue_wait_avg_ns;
                queue_wait_max_ns = snapshot.queue_wait_max_ns;
                if let (Some(threshold_ns), Some(max_ratio)) = (tail_threshold_ns, tail_max_ratio) {
                    let target_percentile = (1.0 - max_ratio).clamp(0.0, 1.0);
                    if let Some(percentile_values) = snapshot.queue_wait_percentiles {
                        if let Some(sample) =
                            choose_queue_wait_percentile(&percentile_values, target_percentile)
                        {
                            tail_mode = Some(QueueWaitTailMode::Percentile);
                            tail_percentile = Some(sample);
                        }
                    }
                    if tail_percentile.is_none() {
                        if let Some(histogram) = snapshot.queue_wait_histogram.as_deref() {
                            if let Some((tail_count, total)) =
                                histogram_tail_ratio(histogram, threshold_ns, snapshot.count)
                            {
                                tail_mode = Some(QueueWaitTailMode::Histogram);
                                let ratio = if total == 0 {
                                    0.0
                                } else {
                                    tail_count as f64 / total as f64
                                };
                                tail_histogram = Some(QueueWaitHistogramSample {
                                    ratio,
                                    tail_count,
                                    total,
                                });
                            }
                        }
                    }
                }
            }
            Err(err) => {
                metrics_error = Some(err.to_string());
            }
        }
    } else if tail_threshold_ns.is_some() || tail_max_ratio.is_some() {
        metrics_error = Some("metrics file not provided".to_string());
    }

    Some(QueueWaitReport {
        metrics_path,
        metrics_loaded,
        metrics_error,
        tail_threshold_ns,
        tail_max_ratio,
        tail_target_percentile,
        auto_profile,
        auto_profile_applied,
        tail_mode,
        tail_percentile,
        tail_histogram,
        percentiles,
        queue_wait_avg_ns,
        queue_wait_max_ns,
    })
}

fn load_agent_metrics(path: &str) -> Result<AgentMetricsSnapshot> {
    let data = fs::read(path)?;
    let snapshot = serde_json::from_slice::<AgentMetricsSnapshot>(&data)?;
    Ok(snapshot)
}

fn queue_wait_profile_defaults(profile: &str) -> Option<(u64, f64)> {
    let normalized = profile.to_ascii_lowercase();
    match normalized.as_str() {
        "pssh" => Some((4_000_000, 0.03)),
        "fanout" => Some((6_000_000, 0.04)),
        "balanced" => Some((8_000_000, 0.05)),
        "low-memory" => Some((12_000_000, 0.07)),
        _ => None,
    }
}

fn choose_queue_wait_percentile(
    percentiles: &QueueWaitPercentiles,
    target_percentile: f64,
) -> Option<QueueWaitPercentileSample> {
    for (label, percentile_value) in QUEUE_WAIT_PERCENTILE_LABELS {
        let entry = match label {
            "p50" => percentiles.p50,
            "p90" => percentiles.p90,
            "p95" => percentiles.p95,
            "p99" => percentiles.p99,
            _ => None,
        };
        let Some(entry) = entry else {
            continue;
        };
        let Some(ns) = entry.ns else {
            continue;
        };
        if entry.open_ended {
            continue;
        }
        if percentile_value + f64::EPSILON >= target_percentile {
            let derived_ratio = (1.0 - percentile_value).clamp(0.0, 1.0);
            return Some(QueueWaitPercentileSample {
                label: label.to_string(),
                percentile: percentile_value,
                ns,
                derived_ratio,
            });
        }
    }
    None
}

fn histogram_tail_ratio(
    histogram: &[u64],
    threshold_ns: u64,
    fallback_total: Option<u64>,
) -> Option<(u64, u64)> {
    if histogram.len() != QUEUE_WAIT_BUCKET_BOUNDS.len() + 1 {
        return None;
    }
    let mut total = histogram.iter().copied().sum::<u64>();
    if total == 0 {
        total = fallback_total.unwrap_or(0);
    }
    let mut tail = 0u64;
    let mut tail_started = threshold_ns == 0;
    for (idx, &value) in histogram.iter().enumerate() {
        if !tail_started {
            let upper = QUEUE_WAIT_BUCKET_BOUNDS.get(idx).copied();
            if upper.map(|bound| threshold_ns <= bound).unwrap_or(true) {
                tail_started = true;
            }
        }
        if tail_started {
            tail = tail.saturating_add(value);
        }
    }
    Some((tail, total))
}

async fn run_worker(
    worker_id: usize,
    socket_path: Arc<PathBuf>,
    requests: usize,
    warmup: usize,
    payload_size: usize,
    flags: u32,
    shared_key: Option<Vec<u8>>,
    reconnect: bool,
    list_only: bool,
    randomize_payload: bool,
    deadline: Option<Instant>,
    response_timeout: Option<Duration>,
    latency_max_samples: usize,
    worker_start_delay_ms: u64,
) -> Result<WorkerResult> {
    if worker_start_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(worker_start_delay_ms)).await;
    }
    if list_only {
        return run_list_worker(
            socket_path,
            requests,
            warmup,
            reconnect,
            deadline,
            response_timeout,
            latency_max_samples,
        )
        .await;
    }

    let mut latencies_us = Vec::with_capacity(latency_max_samples.min(4096));

    let key_blob = if let Some(key_blob) = shared_key {
        key_blob
    } else {
        fetch_first_key(socket_path.as_ref()).await?
    };

    let mut rng = if randomize_payload && payload_size > 0 {
        Some(rand::rngs::SmallRng::from_entropy())
    } else {
        None
    };
    let request_capacity = 1 + 4 + key_blob.len() + 4 + payload_size + 4;
    let mut request_buffer = BytesMut::new();
    let mut request: Option<AgentRequest> = None;
    let sign_frame = if randomize_payload && payload_size > 0 {
        request_buffer = BytesMut::with_capacity(request_capacity);
        request = Some(AgentRequest::SignRequest {
            key_blob,
            data: vec![0u8; payload_size],
            flags,
        });
        None
    } else {
        let request = AgentRequest::SignRequest {
            key_blob,
            data: vec![0u8; payload_size],
            flags,
        };
        Some(encode_request_frame(&request)?)
    };

    if reconnect {
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            let mut stream = connect(socket_path.as_ref()).await?;
            if let Some(frame) = &sign_frame {
                stream.write_all(frame).await?;
            } else {
                if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                    (&mut rng, request.as_mut())
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(
                    &mut stream,
                    request.as_ref().expect("sign request"),
                    &mut request_buffer,
                )
                .await?;
            }
            let response_type =
                read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout).await?;
            if response_type != MessageType::SignResponse as u8 {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }
    } else {
        let mut stream = connect(socket_path.as_ref()).await?;
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            if let Some(frame) = &sign_frame {
                stream.write_all(frame).await?;
            } else {
                if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                    (&mut rng, request.as_mut())
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(
                    &mut stream,
                    request.as_ref().expect("sign request"),
                    &mut request_buffer,
                )
                .await?;
            }
            let response_type =
                read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout).await?;
            if response_type != MessageType::SignResponse as u8 {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }

        let mut completed = 0usize;
        if let Some(deadline) = deadline {
            while Instant::now() < deadline {
                let started_at = if latency_max_samples > 0 {
                    Some(Instant::now())
                } else {
                    None
                };
                if let Some(frame) = &sign_frame {
                    stream.write_all(frame).await?;
                } else {
                    if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                        (&mut rng, request.as_mut())
                    {
                        rng.fill_bytes(data);
                    }
                    write_request_with_buffer(
                        &mut stream,
                        request.as_ref().expect("sign request"),
                        &mut request_buffer,
                    )
                    .await?;
                }
                let response_type =
                    read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout)
                        .await?;
                if response_type == MessageType::SignResponse as u8 {
                    completed += 1;
                    maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
                } else {
                    return Err(anyhow::anyhow!("unexpected sign response"));
                }
            }
        } else {
            for _ in 0..requests {
                let started_at = if latency_max_samples > 0 {
                    Some(Instant::now())
                } else {
                    None
                };
                if let Some(frame) = &sign_frame {
                    stream.write_all(frame).await?;
                } else {
                    if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                        (&mut rng, request.as_mut())
                    {
                        rng.fill_bytes(data);
                    }
                    write_request_with_buffer(
                        &mut stream,
                        request.as_ref().expect("sign request"),
                        &mut request_buffer,
                    )
                    .await?;
                }
                let response_type =
                    read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout)
                        .await?;
                if response_type == MessageType::SignResponse as u8 {
                    completed += 1;
                    maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
                } else {
                    return Err(anyhow::anyhow!("unexpected sign response"));
                }
            }
        }

        debug!(worker_id, completed, "worker done");
        return Ok(WorkerResult {
            completed,
            latencies_us,
        });
    }

    let mut buffer = BytesMut::with_capacity(4096);
    let mut completed = 0usize;
    if let Some(deadline) = deadline {
        while Instant::now() < deadline {
            let started_at = if latency_max_samples > 0 {
                Some(Instant::now())
            } else {
                None
            };
            let mut stream = connect(socket_path.as_ref()).await?;
            if let Some(frame) = &sign_frame {
                stream.write_all(frame).await?;
            } else {
                if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                    (&mut rng, request.as_mut())
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(
                    &mut stream,
                    request.as_ref().expect("sign request"),
                    &mut request_buffer,
                )
                .await?;
            }
            let response_type =
                read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout).await?;
            if response_type == MessageType::SignResponse as u8 {
                completed += 1;
                maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
            } else {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }
    } else {
        for _ in 0..requests {
            let started_at = if latency_max_samples > 0 {
                Some(Instant::now())
            } else {
                None
            };
            let mut stream = connect(socket_path.as_ref()).await?;
            if let Some(frame) = &sign_frame {
                stream.write_all(frame).await?;
            } else {
                if let (Some(rng), Some(AgentRequest::SignRequest { data, .. })) =
                    (&mut rng, request.as_mut())
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(
                    &mut stream,
                    request.as_ref().expect("sign request"),
                    &mut request_buffer,
                )
                .await?;
            }
            let response_type =
                read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout).await?;
            if response_type == MessageType::SignResponse as u8 {
                completed += 1;
                maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
            } else {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }
    }

    debug!(worker_id, completed, "worker done");
    Ok(WorkerResult {
        completed,
        latencies_us,
    })
}

async fn run_list_worker(
    socket_path: Arc<PathBuf>,
    requests: usize,
    warmup: usize,
    reconnect: bool,
    deadline: Option<Instant>,
    response_timeout: Option<Duration>,
    latency_max_samples: usize,
) -> Result<WorkerResult> {
    let list_frame = list_request_frame();
    let mut latencies_us = Vec::with_capacity(latency_max_samples.min(4096));

    if reconnect {
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            list_once(
                socket_path.as_ref(),
                &list_frame,
                &mut buffer,
                response_timeout,
            )
            .await?;
        }
    } else {
        let mut stream = connect(socket_path.as_ref()).await?;
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            stream.write_all(&list_frame).await?;
            let response_type =
                read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout).await?;
            if response_type != MessageType::IdentitiesAnswer as u8 {
                return Err(anyhow::anyhow!("unexpected identities response"));
            }
        }

        let mut completed = 0usize;
        if let Some(deadline) = deadline {
            while Instant::now() < deadline {
                let started_at = if latency_max_samples > 0 {
                    Some(Instant::now())
                } else {
                    None
                };
                stream.write_all(&list_frame).await?;
                let response_type =
                    read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout)
                        .await?;
                if response_type == MessageType::IdentitiesAnswer as u8 {
                    completed += 1;
                    maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
                } else {
                    return Err(anyhow::anyhow!("unexpected identities response"));
                }
            }
        } else {
            for _ in 0..requests {
                let started_at = if latency_max_samples > 0 {
                    Some(Instant::now())
                } else {
                    None
                };
                stream.write_all(&list_frame).await?;
                let response_type =
                    read_response_type_with_timeout(&mut stream, &mut buffer, response_timeout)
                        .await?;
                if response_type == MessageType::IdentitiesAnswer as u8 {
                    completed += 1;
                    maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
                } else {
                    return Err(anyhow::anyhow!("unexpected identities response"));
                }
            }
        }

        return Ok(WorkerResult {
            completed,
            latencies_us,
        });
    }

    let mut buffer = BytesMut::with_capacity(4096);
    let mut completed = 0usize;
    if let Some(deadline) = deadline {
        while Instant::now() < deadline {
            let started_at = if latency_max_samples > 0 {
                Some(Instant::now())
            } else {
                None
            };
            list_once(
                socket_path.as_ref(),
                &list_frame,
                &mut buffer,
                response_timeout,
            )
            .await?;
            completed += 1;
            maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
        }
    } else {
        for _ in 0..requests {
            let started_at = if latency_max_samples > 0 {
                Some(Instant::now())
            } else {
                None
            };
            list_once(
                socket_path.as_ref(),
                &list_frame,
                &mut buffer,
                response_timeout,
            )
            .await?;
            completed += 1;
            maybe_record_latency(started_at, &mut latencies_us, latency_max_samples);
        }
    }

    Ok(WorkerResult {
        completed,
        latencies_us,
    })
}

async fn read_response_type_with_timeout<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
    timeout: Option<Duration>,
) -> Result<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match timeout {
        Some(timeout) => {
            match tokio::time::timeout(timeout, read_response_type_with_buffer(reader, buffer))
                .await
            {
                Ok(result) => Ok(result?),
                Err(_) => Err(anyhow::anyhow!("response timeout")),
            }
        }
        None => Ok(read_response_type_with_buffer(reader, buffer).await?),
    }
}

async fn list_once(
    socket_path: &Path,
    list_frame: &Bytes,
    response_buffer: &mut BytesMut,
    response_timeout: Option<Duration>,
) -> Result<()> {
    let mut stream = connect(socket_path).await?;
    stream.write_all(list_frame).await?;
    let response_type =
        read_response_type_with_timeout(&mut stream, response_buffer, response_timeout).await?;
    if response_type == MessageType::IdentitiesAnswer as u8 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unexpected identities response"))
    }
}

async fn fetch_first_key(socket_path: &Path) -> Result<Vec<u8>> {
    let mut stream = connect(socket_path).await?;
    let mut buffer = BytesMut::with_capacity(4096);
    stream.write_all(list_request_frame()).await?;
    let response = secretive_proto::read_response_with_buffer(&mut stream, &mut buffer).await?;
    match response {
        AgentResponse::IdentitiesAnswer { identities } => identities
            .into_iter()
            .next()
            .map(|id| id.key_blob)
            .ok_or_else(|| anyhow::anyhow!("no identities")),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
}

fn list_request_frame() -> &'static Bytes {
    LIST_FRAME.get_or_init(|| {
        encode_request_frame(&AgentRequest::RequestIdentities)
            .expect("list request frame encoding failed")
    })
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        socket_path: None,
        concurrency: 32,
        requests_per_worker: 100,
        warmup: 10,
        payload_size: 32,
        flags: 0,
        key_blob_hex: None,
        reconnect: false,
        list_only: false,
        randomize_payload: true,
        json: false,
        json_compact: false,
        csv: false,
        csv_header: true,
        response_timeout_ms: None,
        latency: false,
        latency_max_samples: 100_000,
        worker_start_spread_ms: 0,
        metrics_file: None,
        queue_wait_tail_ns: None,
        queue_wait_tail_max_ratio: None,
        queue_wait_tail_profile: None,
        help: false,
        version: false,
        duration_secs: None,
    };

    if let Ok(value) = std::env::var(METRICS_FILE_ENV) {
        if !value.trim().is_empty() {
            parsed.metrics_file = Some(value);
        }
    }
    if let Ok(value) = std::env::var(QUEUE_WAIT_TAIL_NS_ENV) {
        if let Ok(parsed_value) = value.parse() {
            parsed.queue_wait_tail_ns = Some(parsed_value);
        }
    }
    if let Ok(value) = std::env::var(QUEUE_WAIT_TAIL_RATIO_ENV) {
        if let Ok(parsed_value) = value.parse() {
            parsed.queue_wait_tail_max_ratio = Some(parsed_value);
        }
    }
    if let Ok(value) = std::env::var(QUEUE_WAIT_PROFILE_ENV) {
        if !value.trim().is_empty() {
            parsed.queue_wait_tail_profile = Some(value);
        }
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => parsed.socket_path = args.next(),
            "--concurrency" => {
                if let Some(value) = args.next() {
                    parsed.concurrency = value.parse().unwrap_or(parsed.concurrency);
                }
            }
            "--requests" => {
                if let Some(value) = args.next() {
                    parsed.requests_per_worker =
                        value.parse().unwrap_or(parsed.requests_per_worker);
                }
            }
            "--warmup" => {
                if let Some(value) = args.next() {
                    parsed.warmup = value.parse().unwrap_or(parsed.warmup);
                }
            }
            "--payload-size" => {
                if let Some(value) = args.next() {
                    parsed.payload_size = value.parse().unwrap_or(parsed.payload_size);
                }
            }
            "--list" => parsed.list_only = true,
            "--reconnect" => parsed.reconnect = true,
            "--fixed" => parsed.randomize_payload = false,
            "--flags" => {
                if let Some(value) = args.next() {
                    if let Some(parsed_value) = parse_flags(&value) {
                        parsed.flags = parsed_value;
                    }
                }
            }
            "--duration" => {
                if let Some(value) = args.next() {
                    parsed.duration_secs = value.parse().ok();
                }
            }
            "--key" => parsed.key_blob_hex = args.next(),
            "--json" => parsed.json = true,
            "--json-compact" => parsed.json_compact = true,
            "--csv" => parsed.csv = true,
            "--no-csv-header" => parsed.csv_header = false,
            "--response-timeout-ms" => {
                if let Some(value) = args.next() {
                    parsed.response_timeout_ms = value.parse().ok();
                }
            }
            "--latency" => parsed.latency = true,
            "--latency-max-samples" => {
                if let Some(value) = args.next() {
                    parsed.latency_max_samples =
                        value.parse().unwrap_or(parsed.latency_max_samples);
                }
            }
            "--worker-start-spread-ms" => {
                if let Some(value) = args.next() {
                    parsed.worker_start_spread_ms =
                        value.parse().unwrap_or(parsed.worker_start_spread_ms);
                }
            }
            "--metrics-file" => parsed.metrics_file = args.next(),
            "--queue-wait-tail-ns" => {
                if let Some(value) = args.next() {
                    parsed.queue_wait_tail_ns = value.parse().ok();
                }
            }
            "--queue-wait-tail-max-ratio" => {
                if let Some(value) = args.next() {
                    parsed.queue_wait_tail_max_ratio = value.parse().ok();
                }
            }
            "--queue-wait-tail-profile" => parsed.queue_wait_tail_profile = args.next(),
            "-h" | "--help" => parsed.help = true,
            "--version" => parsed.version = true,
            _ => {}
        }
    }

    normalize_queue_wait_args(&mut parsed);
    parsed
}

fn print_help() {
    println!("secretive-bench usage:\n");
    println!("  --concurrency <n> --requests <n> [--warmup <n>]");
    println!("  --duration <seconds> (overrides --requests)");
    println!("  --worker-start-spread-ms <n>");
    println!("  --payload-size <bytes> --flags <u32> --key <hex_blob>");
    println!("  --socket <path> --json --json-compact --csv [--no-csv-header] --reconnect --list --fixed");
    println!("  --response-timeout-ms <n> --latency --latency-max-samples <n>");
    println!("  --metrics-file <path> --queue-wait-tail-profile <profile>");
    println!("  --queue-wait-tail-ns <ns> --queue-wait-tail-max-ratio <ratio>\n");
    println!("  --version\n");
    println!("Notes:");
    println!("  Use --key to reuse a specific identity from secretive-client.");
    println!("  Use --list to benchmark list-identities instead of signing.");
    println!("  --flags accepts numeric values or rsa hash names (sha256/sha512/ssh-rsa).");
    println!("  --fixed disables randomizing payload bytes per request.");
    println!("  --latency records request latencies and reports p50/p95/p99/max/avg.");
    println!("  --csv emits a single CSV row (header included by default).");
    println!("  --worker-start-spread-ms staggers worker start over N milliseconds.");
}

fn normalize_queue_wait_args(args: &mut Args) {
    if let Some(value) = args.metrics_file.as_ref() {
        if value.trim().is_empty() {
            args.metrics_file = None;
        }
    }
    if matches!(args.queue_wait_tail_ns, Some(0)) {
        args.queue_wait_tail_ns = None;
    }
    if let Some(ratio) = args.queue_wait_tail_max_ratio {
        if ratio <= 0.0 {
            args.queue_wait_tail_max_ratio = None;
        }
    }
    if let Some(profile) = args.queue_wait_tail_profile.as_ref() {
        if profile.trim().is_empty() {
            args.queue_wait_tail_profile = None;
        }
    }
}

fn worker_start_delay_ms(worker_id: usize, concurrency: usize, spread_ms: u64) -> u64 {
    if spread_ms == 0 || concurrency <= 1 {
        return 0;
    }
    ((worker_id as u128 * spread_ms as u128) / (concurrency as u128 - 1)) as u64
}

fn parse_flags(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if let Ok(parsed) = trimmed.parse() {
        return Some(parsed);
    }
    if trimmed.eq_ignore_ascii_case("sha256") || trimmed.eq_ignore_ascii_case("rsa-sha2-256") {
        return Some(SSH_AGENT_RSA_SHA2_256);
    }
    if trimmed.eq_ignore_ascii_case("sha512") || trimmed.eq_ignore_ascii_case("rsa-sha2-512") {
        return Some(SSH_AGENT_RSA_SHA2_512);
    }
    if trimmed.eq_ignore_ascii_case("ssh-rsa") || trimmed.eq_ignore_ascii_case("sha1") {
        return Some(0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        choose_queue_wait_percentile, compute_latency_stats, csv_data_row, csv_escape,
        csv_header_row, histogram_tail_ratio, parse_flags, queue_wait_profile_defaults,
        worker_start_delay_ms, BenchMetadata, BenchOutput, LatencyStats, QueueWaitPercentileValue,
        QueueWaitPercentiles, QUEUE_WAIT_BUCKET_BOUNDS,
    };

    #[test]
    fn parse_flags_names() {
        assert_eq!(parse_flags("sha256"), Some(2));
        assert_eq!(parse_flags("rsa-sha2-256"), Some(2));
        assert_eq!(parse_flags("sha512"), Some(4));
        assert_eq!(parse_flags("rsa-sha2-512"), Some(4));
        assert_eq!(parse_flags("ssh-rsa"), Some(0));
        assert_eq!(parse_flags("sha1"), Some(0));
    }

    #[test]
    fn latency_stats_percentiles() {
        let stats = compute_latency_stats(vec![100, 200, 300, 400, 500]).expect("stats");
        assert_eq!(stats.samples, 5);
        assert_eq!(stats.p50_us, 300);
        assert_eq!(stats.p95_us, 400);
        assert_eq!(stats.p99_us, 400);
        assert_eq!(stats.max_us, 500);
        assert!((stats.avg_us - 300.0).abs() < f64::EPSILON);
    }

    #[test]
    fn csv_escape_quotes_commas_and_quotes() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn csv_header_and_row_align() {
        let payload = BenchOutput {
            ok: 10,
            failures: 0,
            attempted: 10,
            success_rate: 1.0,
            failure_rate: 0.0,
            elapsed_ms: 25,
            rps: 400.0,
            mode: "sign",
            reconnect: true,
            concurrency: 2,
            requests_per_worker: 5,
            requested_total: Some(10),
            duration_secs: None,
            randomize_payload: false,
            payload_size: 64,
            flags: 0,
            socket_path: "/tmp/agent.sock".to_string(),
            response_timeout_ms: Some(500),
            latency_enabled: true,
            latency_max_samples: 100,
            worker_start_spread_ms: 50,
            latency: Some(LatencyStats {
                samples: 3,
                p50_us: 10,
                p95_us: 20,
                p99_us: 30,
                max_us: 30,
                avg_us: 20.0,
            }),
            meta: BenchMetadata {
                schema_version: 2,
                bench_version: "0.1.0",
                started_unix_ms: 1000,
                finished_unix_ms: 1025,
                pid: 123,
                hostname: Some("host".to_string()),
                target_os: "linux",
                target_arch: "x86_64",
            },
            queue_wait: None,
        };
        let header = csv_header_row();
        let row = csv_data_row(&payload);
        assert_eq!(header.split(',').count(), row.split(',').count());
    }

    #[test]
    fn worker_start_delay_spreads_across_concurrency() {
        assert_eq!(worker_start_delay_ms(0, 4, 120), 0);
        assert_eq!(worker_start_delay_ms(1, 4, 120), 40);
        assert_eq!(worker_start_delay_ms(2, 4, 120), 80);
        assert_eq!(worker_start_delay_ms(3, 4, 120), 120);
        assert_eq!(worker_start_delay_ms(0, 1, 120), 0);
        assert_eq!(worker_start_delay_ms(2, 4, 0), 0);
    }

    #[test]
    fn queue_wait_profile_defaults_match_expected() {
        assert_eq!(queue_wait_profile_defaults("pssh"), Some((4_000_000, 0.03)));
        assert_eq!(
            queue_wait_profile_defaults("FANOUT"),
            Some((6_000_000, 0.04))
        );
        assert_eq!(
            queue_wait_profile_defaults("balanced"),
            Some((8_000_000, 0.05))
        );
        assert_eq!(
            queue_wait_profile_defaults("low-memory"),
            Some((12_000_000, 0.07))
        );
        assert!(queue_wait_profile_defaults("unknown").is_none());
    }

    #[test]
    fn choose_queue_wait_percentile_selects_first_target() {
        let percentiles = QueueWaitPercentiles {
            p50: Some(QueueWaitPercentileValue {
                ns: Some(500),
                open_ended: false,
            }),
            p90: Some(QueueWaitPercentileValue {
                ns: Some(5_000),
                open_ended: false,
            }),
            p95: Some(QueueWaitPercentileValue {
                ns: Some(7_500),
                open_ended: false,
            }),
            p99: Some(QueueWaitPercentileValue {
                ns: Some(9_000),
                open_ended: false,
            }),
        };
        let sample = choose_queue_wait_percentile(&percentiles, 0.9).expect("sample");
        assert_eq!(sample.label, "p90");
        assert_eq!(sample.ns, 5_000);
    }

    #[test]
    fn histogram_tail_ratio_counts_expected_buckets() {
        let mut histogram = vec![0u64; QUEUE_WAIT_BUCKET_BOUNDS.len() + 1];
        histogram[5] = 5;
        histogram[6] = 10;
        let result = histogram_tail_ratio(&histogram, 16_000, Some(15)).expect("ratio");
        assert_eq!(result.0, 15);
        assert_eq!(result.1, 15);
    }
}

#[cfg(unix)]
async fn connect(socket_path: &Path) -> std::io::Result<AgentStream> {
    AgentStream::connect(socket_path).await
}

#[cfg(windows)]
async fn connect(socket_path: &Path) -> std::io::Result<AgentStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    ClientOptions::new().open(socket_path.to_string_lossy().as_ref())
}

#[cfg(unix)]
fn resolve_socket_path(override_path: Option<String>) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("SECRETIVE_SOCK") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("SSH_AUTH_SOCK") {
        return PathBuf::from(path);
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("secretive").join("agent.sock");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".secretive").join("agent.sock")
}

#[cfg(windows)]
fn resolve_socket_path(override_path: Option<String>) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(normalize_pipe_name(path));
    }
    if let Ok(path) = std::env::var("SECRETIVE_PIPE") {
        return PathBuf::from(normalize_pipe_name(path));
    }
    PathBuf::from(r"\\.\pipe\secretive-agent")
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
