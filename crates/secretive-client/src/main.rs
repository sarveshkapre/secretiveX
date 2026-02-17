use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use secretive_proto::{
    encode_request_frame, read_response_with_buffer, write_request_with_buffer, AgentRequest,
    AgentResponse, Identity, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512,
};
use serde::ser::{SerializeSeq, Serializer};
use serde::Deserialize;
use serde::Serialize;
use ssh_key::Signature;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Duration;

#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient as AgentStream;
#[cfg(unix)]
use tokio::net::UnixStream as AgentStream;

static LIST_FRAME: OnceLock<Bytes> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    if args.help {
        print_help();
        return Ok(());
    }
    if args.version {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let guardrail = build_queue_wait_guardrail(&args)?;
    if args.pssh_hints {
        let socket_path = resolve_socket_path(args.socket_path.clone());
        print_pssh_hints(&socket_path)?;
        return Ok(());
    }
    if guardrail.is_some() && args.metrics_file.is_none() {
        return Err(anyhow::anyhow!(
            "queue wait guardrail flags require --metrics-file"
        ));
    }
    if let Some(path) = args.metrics_file.as_deref() {
        let snapshot = load_metrics_snapshot(path)?;
        render_metrics_snapshot(&snapshot, args.json, args.json_compact)?;
        if let Some(guardrail) = guardrail.as_ref() {
            let verdict = evaluate_queue_wait_guardrail(&snapshot, guardrail);
            emit_guardrail_verdict(&verdict, args.json)?;
            if !verdict.passed {
                std::process::exit(3);
            }
        }
        return Ok(());
    }
    let socket_path = resolve_socket_path(args.socket_path.clone());
    let stream = connect(&socket_path).await?;
    let response_timeout = args.response_timeout_ms.and_then(|value| {
        if value == 0 {
            None
        } else {
            Some(Duration::from_millis(value))
        }
    });

    let mut stream = stream;
    let mut buffer = BytesMut::with_capacity(4096);

    if args.list {
        let opts = ListIdentitiesOptions {
            show_openssh: args.show_openssh,
            json_output: args.json,
            json_compact: args.json_compact,
            raw_output: args.raw,
            filter: args.filter.as_deref(),
            response_timeout,
        };
        list_identities(&mut stream, &mut buffer, opts).await?;
        return Ok(());
    }

    if args.health {
        health_identities(
            &mut stream,
            &mut buffer,
            args.json,
            args.json_compact,
            args.filter.as_deref(),
            response_timeout,
        )
        .await?;
        return Ok(());
    }

    let mut request_buffer = BytesMut::with_capacity(256);
    if args.sign_key_blob.is_some()
        || args.sign_comment.is_some()
        || args.sign_fingerprint.is_some()
    {
        let key_blob = if let Some(key_hex) = args.sign_key_blob {
            hex::decode(key_hex)?
        } else if let Some(comment) = args.sign_comment.as_deref() {
            select_key_by_comment(&mut stream, &mut buffer, comment, response_timeout).await?
        } else if let Some(fingerprint) = args.sign_fingerprint.as_deref() {
            select_key_by_fingerprint(&mut stream, &mut buffer, fingerprint, response_timeout)
                .await?
        } else {
            return Err(anyhow::anyhow!("missing key selector"));
        };
        let data = if let Some(path) = args.sign_path {
            std::fs::read(path)?
        } else {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        };
        let request_capacity = 1 + 4 + key_blob.len() + 4 + data.len() + 4;
        request_buffer.reserve(request_capacity);
        let signature_blob = sign_data(
            &mut stream,
            &mut buffer,
            &mut request_buffer,
            key_blob,
            data,
            args.flags,
            response_timeout,
        )
        .await?;
        let signature = decode_signature_blob(&signature_blob)?;
        if args.json {
            let algorithm = signature.algorithm();
            let payload = JsonSignature {
                algorithm: algorithm.as_str(),
                signature_hex: hex::encode(signature.as_bytes()),
                signature_blob_hex: hex::encode(signature_blob),
            };
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if args.json_compact {
                serde_json::to_writer(&mut handle, &payload)?;
            } else {
                serde_json::to_writer_pretty(&mut handle, &payload)?;
            }
            writeln!(handle)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            writeln!(handle, "algorithm: {}", signature.algorithm().as_str())?;
            writeln!(handle, "signature: {}", hex::encode(signature.as_bytes()))?;
        }
        return Ok(());
    }

    eprintln!("No command provided. Use --list or --sign.");
    Ok(())
}

struct ListIdentitiesOptions<'a> {
    show_openssh: bool,
    json_output: bool,
    json_compact: bool,
    raw_output: bool,
    filter: Option<&'a str>,
    response_timeout: Option<Duration>,
}

async fn list_identities<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    opts: ListIdentitiesOptions<'_>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut identities = fetch_identities(stream, buffer, opts.response_timeout).await?;
    if let Some(filter) = opts.filter {
        apply_identity_filter(&mut identities, filter);
    }

    if opts.json_output {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if opts.json_compact {
            let mut ser = serde_json::Serializer::new(&mut handle);
            let mut seq = ser.serialize_seq(Some(identities.len()))?;
            for identity in &identities {
                if opts.raw_output {
                    let item = JsonIdentity {
                        key_blob_hex: hex::encode(&identity.key_blob),
                        comment: &identity.comment,
                        algorithm: None,
                        fingerprint: None,
                        openssh: None,
                    };
                    seq.serialize_element(&item)?;
                    continue;
                }
                if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                    let algorithm = public_key.algorithm();
                    let alg = algorithm.as_str();
                    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                    let openssh = if opts.show_openssh {
                        public_key
                            .to_openssh()
                            .ok()
                            .map(|ssh| ssh.trim().to_string())
                    } else {
                        None
                    };
                    let item = JsonIdentity {
                        key_blob_hex: hex::encode(&identity.key_blob),
                        comment: &identity.comment,
                        algorithm: Some(alg),
                        fingerprint: Some(fp),
                        openssh,
                    };
                    seq.serialize_element(&item)?;
                    continue;
                }
                let item = JsonIdentity {
                    key_blob_hex: hex::encode(&identity.key_blob),
                    comment: &identity.comment,
                    algorithm: None,
                    fingerprint: None,
                    openssh: None,
                };
                seq.serialize_element(&item)?;
            }
            seq.end()?;
            writeln!(handle)?;
        } else {
            let mut ser = serde_json::Serializer::pretty(&mut handle);
            let mut seq = ser.serialize_seq(Some(identities.len()))?;
            for identity in &identities {
                if opts.raw_output {
                    let item = JsonIdentity {
                        key_blob_hex: hex::encode(&identity.key_blob),
                        comment: &identity.comment,
                        algorithm: None,
                        fingerprint: None,
                        openssh: None,
                    };
                    seq.serialize_element(&item)?;
                    continue;
                }
                if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                    let algorithm = public_key.algorithm();
                    let alg = algorithm.as_str();
                    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                    let openssh = if opts.show_openssh {
                        public_key
                            .to_openssh()
                            .ok()
                            .map(|ssh| ssh.trim().to_string())
                    } else {
                        None
                    };
                    let item = JsonIdentity {
                        key_blob_hex: hex::encode(&identity.key_blob),
                        comment: &identity.comment,
                        algorithm: Some(alg),
                        fingerprint: Some(fp),
                        openssh,
                    };
                    seq.serialize_element(&item)?;
                    continue;
                }
                let item = JsonIdentity {
                    key_blob_hex: hex::encode(&identity.key_blob),
                    comment: &identity.comment,
                    algorithm: None,
                    fingerprint: None,
                    openssh: None,
                };
                seq.serialize_element(&item)?;
            }
            seq.end()?;
            writeln!(handle)?;
        }
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        for identity in identities {
            if opts.raw_output {
                writeln!(
                    handle,
                    "{} {}",
                    hex::encode(identity.key_blob),
                    identity.comment
                )?;
                continue;
            }
            if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                let algorithm = public_key.algorithm();
                let alg = algorithm.as_str();
                let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
                if opts.show_openssh {
                    if let Ok(ssh) = public_key.to_openssh() {
                        writeln!(
                            handle,
                            "{} {} {} {} {}",
                            hex::encode(identity.key_blob),
                            identity.comment,
                            alg,
                            fp,
                            ssh.trim()
                        )?;
                        continue;
                    }
                    writeln!(
                        handle,
                        "{} {} {} {}",
                        hex::encode(identity.key_blob),
                        identity.comment,
                        alg,
                        fp
                    )?;
                    continue;
                } else {
                    writeln!(
                        handle,
                        "{} {} {} {}",
                        hex::encode(identity.key_blob),
                        identity.comment,
                        alg,
                        fp
                    )?;
                    continue;
                }
            }
            writeln!(
                handle,
                "{} {}",
                hex::encode(identity.key_blob),
                identity.comment
            )?;
        }
    }

    Ok(())
}

async fn health_identities<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    json_output: bool,
    json_compact: bool,
    filter: Option<&str>,
    response_timeout: Option<Duration>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut identities = fetch_identities(stream, buffer, response_timeout).await?;
    if let Some(filter) = filter {
        apply_identity_filter(&mut identities, filter);
    }
    let report = build_health_report(&identities);

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if json_output {
        if json_compact {
            serde_json::to_writer(&mut handle, &report)?;
        } else {
            serde_json::to_writer_pretty(&mut handle, &report)?;
        }
        writeln!(handle)?;
        return Ok(());
    }

    writeln!(handle, "total_identities: {}", report.total_identities)?;
    writeln!(handle, "valid_identities: {}", report.valid_identities)?;
    writeln!(handle, "invalid_key_blobs: {}", report.invalid_key_blobs)?;
    writeln!(handle, "unique_key_blobs: {}", report.unique_key_blobs)?;
    writeln!(
        handle,
        "duplicate_key_blobs: {}",
        report.duplicate_key_blobs
    )?;
    writeln!(
        handle,
        "unique_fingerprints: {}",
        report.unique_fingerprints
    )?;
    writeln!(
        handle,
        "duplicate_fingerprints: {}",
        report.duplicate_fingerprints
    )?;
    writeln!(handle, "duplicate_comments: {}", report.duplicate_comments)?;
    writeln!(handle, "algorithms:")?;
    for (algorithm, count) in report.algorithms {
        writeln!(handle, "{} {}", algorithm, count)?;
    }

    Ok(())
}

fn apply_identity_filter(identities: &mut Vec<Identity>, filter: &str) {
    let filter_lower = if is_ascii_lowercase(filter) {
        Cow::Borrowed(filter.as_bytes())
    } else {
        Cow::Owned(ascii_lowercase_bytes(filter))
    };
    let filter_fp = parse_fingerprint_input(filter);
    identities.retain(|id| {
        if contains_ignore_ascii_case(&id.comment, filter_lower.as_ref()) {
            return true;
        }
        if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&id.key_blob) {
            if let Some(target_fp) = filter_fp {
                let fp = public_key.fingerprint(target_fp.algorithm());
                return fp == target_fp;
            }
            let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
            return contains_ignore_ascii_case(&fp, filter_lower.as_ref());
        }
        false
    });
}

fn build_health_report(identities: &[Identity]) -> HealthReport {
    let mut unique_blobs = HashSet::with_capacity(identities.len());
    let mut fingerprint_counts: HashMap<String, usize> = HashMap::new();
    let mut comment_counts: HashMap<String, usize> = HashMap::new();
    let mut algorithms: BTreeMap<String, usize> = BTreeMap::new();
    let mut valid_identities = 0usize;
    let mut invalid_key_blobs = 0usize;

    for identity in identities {
        unique_blobs.insert(identity.key_blob.clone());
        *comment_counts.entry(identity.comment.clone()).or_insert(0) += 1;

        if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
            valid_identities += 1;
            let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
            *fingerprint_counts.entry(fp).or_insert(0) += 1;
            let algorithm = public_key.algorithm().as_str().to_string();
            *algorithms.entry(algorithm).or_insert(0) += 1;
        } else {
            invalid_key_blobs += 1;
        }
    }

    let total_identities = identities.len();
    let unique_key_blobs = unique_blobs.len();
    let duplicate_key_blobs = total_identities.saturating_sub(unique_key_blobs);
    let unique_fingerprints = fingerprint_counts.len();
    let duplicate_fingerprints = fingerprint_counts
        .values()
        .map(|count| count.saturating_sub(1))
        .sum();
    let duplicate_comments = comment_counts
        .values()
        .map(|count| count.saturating_sub(1))
        .sum();

    HealthReport {
        total_identities,
        valid_identities,
        invalid_key_blobs,
        unique_key_blobs,
        duplicate_key_blobs,
        unique_fingerprints,
        duplicate_fingerprints,
        duplicate_comments,
        algorithms,
    }
}

async fn sign_data<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    request_buffer: &mut BytesMut,
    key_blob: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
    response_timeout: Option<Duration>,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = AgentRequest::SignRequest {
        key_blob,
        data,
        flags,
    };
    write_request_with_buffer(stream, &request, request_buffer).await?;
    let response = read_response_with_timeout(stream, buffer, response_timeout).await?;
    match response {
        AgentResponse::SignResponse { signature_blob } => Ok(signature_blob),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
}

async fn fetch_identities<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    response_timeout: Option<Duration>,
) -> Result<Vec<Identity>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(list_request_frame()).await?;
    let response = read_response_with_timeout(stream, buffer, response_timeout).await?;
    match response {
        AgentResponse::IdentitiesAnswer { identities } => Ok(identities),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
}

fn list_request_frame() -> &'static Bytes {
    LIST_FRAME.get_or_init(|| {
        encode_request_frame(&AgentRequest::RequestIdentities)
            .expect("list request frame encoding failed")
    })
}

async fn read_response_with_timeout<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    response_timeout: Option<Duration>,
) -> Result<AgentResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match response_timeout {
        Some(timeout) => {
            match tokio::time::timeout(timeout, read_response_with_buffer(stream, buffer)).await {
                Ok(result) => Ok(result?),
                Err(_) => Err(anyhow::anyhow!("response timeout")),
            }
        }
        None => Ok(read_response_with_buffer(stream, buffer).await?),
    }
}

async fn select_key_by_comment<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    comment: &str,
    response_timeout: Option<Duration>,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let identities = fetch_identities(stream, buffer, response_timeout).await?;
    identities
        .into_iter()
        .find(|id| id.comment == comment || id.comment.eq_ignore_ascii_case(comment))
        .map(|id| id.key_blob)
        .ok_or_else(|| anyhow::anyhow!("no identity with comment: {comment}"))
}

async fn select_key_by_fingerprint<S>(
    stream: &mut S,
    buffer: &mut BytesMut,
    fingerprint: &str,
    response_timeout: Option<Duration>,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let identities = fetch_identities(stream, buffer, response_timeout).await?;
    let target = fingerprint.trim();
    let target_stripped = strip_sha256_prefix(target);
    let target_fp = parse_fingerprint_input(target);
    if let Some(target_fp) = target_fp {
        for identity in identities {
            if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                let fp = public_key.fingerprint(target_fp.algorithm());
                if fp == target_fp {
                    return Ok(identity.key_blob);
                }
            }
        }
    } else {
        for identity in identities {
            if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                let fp_stripped = strip_sha256_prefix(&fp);
                if fp == target
                    || fp_stripped == target
                    || fp == target_stripped
                    || fp.eq_ignore_ascii_case(target)
                    || fp_stripped.eq_ignore_ascii_case(target)
                    || fp.eq_ignore_ascii_case(target_stripped)
                {
                    return Ok(identity.key_blob);
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "no identity with fingerprint: {fingerprint}"
    ))
}

fn strip_sha256_prefix(value: &str) -> &str {
    match value.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("sha256:") => &value[7..],
        _ => value,
    }
}

fn parse_fingerprint_input(input: &str) -> Option<ssh_key::Fingerprint> {
    let trimmed = input.trim();
    if let Some((prefix, rest)) = trimmed.split_once(':') {
        if prefix == "SHA256" || prefix == "SHA512" {
            if let Ok(parsed) = trimmed.parse() {
                return Some(parsed);
            }
        }
        let mut normalized = String::with_capacity(prefix.len() + 1 + rest.len());
        normalized.push_str(&prefix.to_ascii_uppercase());
        normalized.push(':');
        normalized.push_str(rest);
        return normalized.parse().ok();
    }
    let mut normalized = String::with_capacity("SHA256:".len() + trimmed.len());
    normalized.push_str("SHA256:");
    normalized.push_str(trimmed);
    normalized.parse().ok()
}

fn ascii_lowercase_bytes(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    out.extend(value.as_bytes().iter().map(|b| ascii_lower(*b)));
    out
}

fn is_ascii_lowercase(value: &str) -> bool {
    value.as_bytes().iter().all(|b| !b.is_ascii_uppercase())
}

fn contains_ignore_ascii_case(haystack: &str, needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    let haystack_bytes = haystack.as_bytes();
    if needle_lower.len() > haystack_bytes.len() {
        return false;
    }
    let first = needle_lower[0];
    let limit = haystack_bytes.len() - needle_lower.len();
    for idx in 0..=limit {
        if ascii_lower(haystack_bytes[idx]) != first {
            continue;
        }
        if needle_lower.len() == 1 {
            return true;
        }
        let mut matched = true;
        for (offset, &b) in needle_lower[1..].iter().enumerate() {
            if ascii_lower(haystack_bytes[idx + 1 + offset]) != b {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

#[inline]
fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + 32
    } else {
        byte
    }
}

fn decode_signature_blob(blob: &[u8]) -> Result<Signature> {
    let mut cursor = blob;
    let algorithm = read_string_ref(&mut cursor)?;
    let signature = read_string(&mut cursor)?;
    let algorithm = std::str::from_utf8(algorithm)?;
    let signature = Signature::new(ssh_key::Algorithm::new(algorithm)?, signature)?;
    Ok(signature)
}

#[cfg(unix)]
async fn connect(socket_path: &Path) -> Result<AgentStream> {
    Ok(AgentStream::connect(socket_path).await?)
}

#[cfg(windows)]
async fn connect(socket_path: &Path) -> Result<AgentStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    Ok(ClientOptions::new().open(socket_path.to_string_lossy().as_ref())?)
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

#[derive(Debug, Deserialize, Serialize)]
struct MetricsSnapshot {
    kind: String,
    count: u64,
    errors: u64,
    timeouts: u64,
    avg_ns: f64,
    captured_unix_ms: Option<u64>,
    started_unix_ms: Option<u64>,
    queue_wait_avg_ns: Option<f64>,
    queue_wait_max_ns: Option<u64>,
    in_flight: u64,
    max_signers: u64,
    connections: Option<u64>,
    active_connections: Option<u64>,
    max_active_connections: Option<u64>,
    max_connections: Option<u64>,
    connection_rejected: Option<u64>,
    list_count: Option<u64>,
    list_hit: Option<u64>,
    list_stale: Option<u64>,
    list_refresh: Option<u64>,
    list_errors: Option<u64>,
    store_sign_file: Option<u64>,
    store_sign_pkcs11: Option<u64>,
    store_sign_secure_enclave: Option<u64>,
    store_sign_other: Option<u64>,
    confirm_allow: Option<u64>,
    confirm_cache_hit: Option<u64>,
    confirm_denied: Option<u64>,
    confirm_timeout: Option<u64>,
    confirm_error: Option<u64>,
    queue_wait_histogram: Option<Vec<u64>>,
    queue_wait_percentiles: Option<MetricsQueueWaitPercentiles>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
struct MetricsQueueWaitPercentiles {
    p50: Option<MetricsPercentileValue>,
    p90: Option<MetricsPercentileValue>,
    p95: Option<MetricsPercentileValue>,
    p99: Option<MetricsPercentileValue>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
struct MetricsPercentileValue {
    ns: u64,
    open_ended: bool,
}

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

const QUEUE_WAIT_PERCENTILES: &[(f64, &str)] = &[
    (0.50, "queue_wait_p50_ns"),
    (0.90, "queue_wait_p90_ns"),
    (0.95, "queue_wait_p95_ns"),
    (0.99, "queue_wait_p99_ns"),
];

struct QueueWaitPercentile {
    label: &'static str,
    value_ns: u64,
    open_ended: bool,
}

fn compute_queue_wait_percentiles(histogram: &[u64]) -> Vec<QueueWaitPercentile> {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return Vec::new();
    }

    let thresholds: Vec<(u64, &'static str)> = QUEUE_WAIT_PERCENTILES
        .iter()
        .map(|(fraction, label)| {
            let threshold = ((*fraction * total as f64).ceil() as u64).max(1);
            (threshold, *label)
        })
        .collect();

    let mut out = Vec::with_capacity(thresholds.len());
    let mut threshold_index = 0usize;
    let mut cumulative = 0u64;

    for (bucket_index, count) in histogram.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        while threshold_index < thresholds.len() && cumulative >= thresholds[threshold_index].0 {
            let (value_ns, open_ended) = bucket_bound_ns(bucket_index);
            out.push(QueueWaitPercentile {
                label: thresholds[threshold_index].1,
                value_ns,
                open_ended,
            });
            threshold_index += 1;
        }
        if threshold_index >= thresholds.len() {
            break;
        }
    }

    out
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

fn format_percentile_value(entry: &QueueWaitPercentile) -> String {
    format_percentile_value_from_parts(entry.value_ns, entry.open_ended)
}

fn format_duration_ns(value_ns: u64) -> String {
    const NS_IN_US: f64 = 1_000.0;
    const NS_IN_MS: f64 = 1_000_000.0;
    const NS_IN_S: f64 = 1_000_000_000.0;

    if value_ns as f64 >= NS_IN_S {
        format!("{:.2} s", value_ns as f64 / NS_IN_S)
    } else if value_ns as f64 >= NS_IN_MS {
        format!("{:.2} ms", value_ns as f64 / NS_IN_MS)
    } else if value_ns as f64 >= NS_IN_US {
        format!("{:.2} us", value_ns as f64 / NS_IN_US)
    } else {
        format!("{value_ns} ns")
    }
}

fn format_percentile_value_from_parts(value_ns: u64, open_ended: bool) -> String {
    let approx = format_duration_ns(value_ns);
    if open_ended {
        format!(">= {value_ns} ns ({approx})")
    } else {
        format!("<= {value_ns} ns ({approx})")
    }
}

const GUARDRAIL_PERCENTILE_FIELDS: [(&str, f64); 4] =
    [("p50", 0.50), ("p90", 0.90), ("p95", 0.95), ("p99", 0.99)];

#[derive(Debug, Clone)]
struct QueueWaitGuardrail {
    tail_threshold_ns: Option<u64>,
    tail_max_ratio: Option<f64>,
    target_percentile: Option<f64>,
    max_age_ms: Option<u64>,
    auto_profile: Option<String>,
    auto_profile_applied: bool,
}

#[derive(Debug, Default)]
struct QueueWaitGuardrailVerdict {
    passed: bool,
    messages: Vec<String>,
    failures: Vec<String>,
}

impl QueueWaitGuardrailVerdict {
    fn new() -> Self {
        Self {
            passed: true,
            messages: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, message: String) {
        self.passed = false;
        self.failures.push(message);
    }

    fn record(&mut self, message: String) {
        self.messages.push(message);
    }
}

struct GuardrailPercentileSample {
    label: &'static str,
    percentile: f64,
    ns: u64,
}

fn emit_guardrail_verdict(verdict: &QueueWaitGuardrailVerdict, json_output: bool) -> Result<()> {
    if verdict.messages.is_empty() && verdict.failures.is_empty() {
        return Ok(());
    }
    if json_output {
        for line in &verdict.messages {
            eprintln!("{line}");
        }
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        for line in &verdict.messages {
            writeln!(handle, "{line}")?;
        }
    }
    for line in &verdict.failures {
        eprintln!("{line}");
    }
    Ok(())
}

fn build_queue_wait_guardrail(args: &Args) -> Result<Option<QueueWaitGuardrail>> {
    if args.queue_wait_tail_ns.is_none()
        && args.queue_wait_tail_max_ratio.is_none()
        && args.queue_wait_tail_profile.is_none()
        && args.queue_wait_max_age_ms.is_none()
    {
        return Ok(None);
    }

    let mut tail_threshold_ns = parse_u64_flag(&args.queue_wait_tail_ns, "--queue-wait-tail-ns")?;
    if matches!(tail_threshold_ns, Some(0)) {
        anyhow::bail!("--queue-wait-tail-ns must be greater than 0");
    }
    let mut tail_max_ratio = parse_ratio_flag(
        &args.queue_wait_tail_max_ratio,
        "--queue-wait-tail-max-ratio",
    )?;
    if let Some(ratio) = tail_max_ratio {
        if !(ratio.is_finite() && ratio > 0.0 && ratio < 1.0) {
            anyhow::bail!("--queue-wait-tail-max-ratio must be between 0 and 1 (exclusive)");
        }
    }

    let mut auto_profile_applied = false;
    let auto_profile = args.queue_wait_tail_profile.clone();
    if let Some(profile) = auto_profile.clone() {
        if tail_threshold_ns.is_none() || tail_max_ratio.is_none() {
            if let Some((default_ns, default_ratio)) = queue_wait_profile_defaults(&profile) {
                if tail_threshold_ns.is_none() {
                    tail_threshold_ns = Some(default_ns);
                    auto_profile_applied = true;
                }
                if tail_max_ratio.is_none() {
                    tail_max_ratio = Some(default_ratio);
                    auto_profile_applied = true;
                }
            } else {
                anyhow::bail!("unknown queue-wait profile '{profile}'");
            }
        }
    }

    if tail_threshold_ns.is_some() ^ tail_max_ratio.is_some() {
        anyhow::bail!(
            "queue wait tail checks require both --queue-wait-tail-ns and --queue-wait-tail-max-ratio (or a profile)"
        );
    }

    let max_age_ms = parse_u64_flag(&args.queue_wait_max_age_ms, "--queue-wait-max-age-ms")?
        .filter(|value| *value > 0);

    if tail_threshold_ns.is_none() && max_age_ms.is_none() {
        return Ok(None);
    }

    Ok(Some(QueueWaitGuardrail {
        tail_threshold_ns,
        tail_max_ratio,
        target_percentile: tail_max_ratio.map(|ratio| (1.0 - ratio).clamp(0.0, 1.0)),
        max_age_ms,
        auto_profile,
        auto_profile_applied,
    }))
}

fn parse_u64_flag(raw: &Option<String>, flag: &str) -> Result<Option<u64>> {
    match raw.as_deref() {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                anyhow::bail!("{flag} requires a numeric value");
            }
            let parsed = trimmed
                .parse::<u64>()
                .with_context(|| format!("{flag} expects an integer value: {value}"))?;
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}

fn parse_ratio_flag(raw: &Option<String>, flag: &str) -> Result<Option<f64>> {
    match raw.as_deref() {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                anyhow::bail!("{flag} requires a numeric value");
            }
            let parsed = trimmed
                .parse::<f64>()
                .with_context(|| format!("{flag} expects a numeric value: {value}"))?;
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
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

fn evaluate_queue_wait_guardrail(
    snapshot: &MetricsSnapshot,
    guardrail: &QueueWaitGuardrail,
) -> QueueWaitGuardrailVerdict {
    let mut verdict = QueueWaitGuardrailVerdict::new();
    if let Some(profile) = guardrail.auto_profile.as_deref() {
        if guardrail.auto_profile_applied {
            verdict.record(format!(
                "queue_wait guardrail profile '{profile}' applied defaults"
            ));
        } else {
            verdict.record(format!(
                "queue_wait guardrail profile override '{profile}' in effect"
            ));
        }
    }
    if let (Some(threshold_ns), Some(max_ratio)) =
        (guardrail.tail_threshold_ns, guardrail.tail_max_ratio)
    {
        verdict.record(format!(
            "queue_wait guardrail thresholds: tail_ns={threshold_ns}ns max_ratio={max_ratio:.4}"
        ));
        let target_percentile = guardrail.target_percentile.unwrap_or(1.0);
        if let Some(percentiles) = snapshot.queue_wait_percentiles.as_ref() {
            if let Some(sample) = choose_guardrail_percentile(percentiles, target_percentile) {
                let pass = sample.ns <= threshold_ns;
                let derived_ratio = (1.0 - sample.percentile).clamp(0.0, 1.0);
                let message = format!(
                    "queue_wait percentile {label}={ns}ns (derived ratio {ratio:.4}) vs tail_ns {threshold_ns}ns",
                    label = sample.label,
                    ns = sample.ns,
                    ratio = derived_ratio
                );
                if pass {
                    verdict.record(format!("{message} ✅"));
                } else {
                    verdict.fail(format!("{message} ❌"));
                }
            } else if let Some(histogram) = snapshot.queue_wait_histogram.as_deref() {
                verdict.record(
                    "queue_wait percentiles unavailable for target; using histogram fallback"
                        .into(),
                );
                evaluate_histogram_tail(
                    histogram,
                    threshold_ns,
                    max_ratio,
                    snapshot.count,
                    &mut verdict,
                );
            } else {
                verdict.fail(
                    "queue_wait guardrail FAILED: percentiles missing and histogram unavailable"
                        .into(),
                );
            }
        } else if let Some(histogram) = snapshot.queue_wait_histogram.as_deref() {
            verdict.record("queue_wait percentiles missing; using histogram fallback".into());
            evaluate_histogram_tail(
                histogram,
                threshold_ns,
                max_ratio,
                snapshot.count,
                &mut verdict,
            );
        } else {
            verdict.fail(
                "queue_wait guardrail FAILED: queue-wait percentiles and histogram unavailable"
                    .into(),
            );
        }
    }

    if let Some(max_age_ms) = guardrail.max_age_ms {
        if let Some(captured_unix_ms) = snapshot.captured_unix_ms {
            let age_ms = unix_now_ms().saturating_sub(captured_unix_ms);
            if age_ms <= max_age_ms {
                verdict.record(format!(
                    "queue_wait metrics age {age_ms}ms ≤ max {max_age_ms}ms ✅"
                ));
            } else {
                verdict.fail(format!(
                    "queue_wait metrics age {age_ms}ms exceeded max {max_age_ms}ms ❌"
                ));
            }
        } else {
            verdict.fail(
                "queue_wait guardrail FAILED: metrics snapshot missing captured_unix_ms".into(),
            );
        }
    }

    if verdict.passed {
        verdict.record("queue_wait guardrail PASS".into());
    } else {
        verdict.failures.push("queue_wait guardrail FAILED".into());
    }

    verdict
}

fn evaluate_histogram_tail(
    histogram: &[u64],
    threshold_ns: u64,
    max_ratio: f64,
    fallback_total: u64,
    verdict: &mut QueueWaitGuardrailVerdict,
) {
    if let Some((tail_count, total)) =
        histogram_tail_ratio_guardrail(histogram, threshold_ns, fallback_total)
    {
        let ratio = if total == 0 {
            0.0
        } else {
            tail_count as f64 / total as f64
        };
        let message = format!(
            "queue_wait histogram tail ratio={ratio:.4} (tail={tail_count} total={total}) vs max_ratio={max_ratio:.4}"
        );
        if ratio <= max_ratio {
            verdict.record(format!("{message} ✅"));
        } else {
            verdict.fail(format!("{message} ❌"));
        }
    } else {
        verdict.fail("queue_wait guardrail FAILED: histogram missing or malformed".into());
    }
}

fn choose_guardrail_percentile(
    percentiles: &MetricsQueueWaitPercentiles,
    target_percentile: f64,
) -> Option<GuardrailPercentileSample> {
    let target = target_percentile.clamp(0.0, 1.0);
    for (field, percentile_value) in GUARDRAIL_PERCENTILE_FIELDS {
        let entry = match field {
            "p50" => percentiles.p50?,
            "p90" => percentiles.p90?,
            "p95" => percentiles.p95?,
            "p99" => percentiles.p99?,
            _ => continue,
        };
        if entry.open_ended {
            continue;
        }
        if percentile_value + f64::EPSILON >= target {
            return Some(GuardrailPercentileSample {
                label: field,
                percentile: percentile_value,
                ns: entry.ns,
            });
        }
    }
    None
}

fn histogram_tail_ratio_guardrail(
    histogram: &[u64],
    threshold_ns: u64,
    fallback_total: u64,
) -> Option<(u64, u64)> {
    if histogram.len() != QUEUE_WAIT_BUCKET_BOUNDS.len() + 1 {
        return None;
    }
    let mut total = histogram.iter().copied().sum::<u64>();
    if total == 0 {
        total = fallback_total;
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

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn load_metrics_snapshot(path: &str) -> Result<MetricsSnapshot> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("failed to read metrics {path}"))?;
    let metrics: MetricsSnapshot =
        serde_json::from_str(&content).with_context(|| format!("invalid metrics JSON {path}"))?;
    Ok(metrics)
}

fn render_metrics_snapshot(
    metrics: &MetricsSnapshot,
    json_output: bool,
    json_compact: bool,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if json_output {
        if json_compact {
            serde_json::to_writer(&mut handle, metrics)?;
        } else {
            serde_json::to_writer_pretty(&mut handle, metrics)?;
        }
        writeln!(handle)?;
        return Ok(());
    }

    writeln!(handle, "kind: {}", metrics.kind)?;
    writeln!(handle, "count: {}", metrics.count)?;
    writeln!(handle, "errors: {}", metrics.errors)?;
    writeln!(handle, "timeouts: {}", metrics.timeouts)?;
    writeln!(handle, "avg_ns: {:.2}", metrics.avg_ns)?;
    if let Some(value) = metrics.captured_unix_ms {
        writeln!(handle, "captured_unix_ms: {}", value)?;
        let age_ms = unix_now_ms().saturating_sub(value);
        writeln!(handle, "captured_age_ms: {}", age_ms)?;
    }
    if let Some(value) = metrics.started_unix_ms {
        writeln!(handle, "started_unix_ms: {}", value)?;
        if let Some(captured) = metrics.captured_unix_ms {
            if captured >= value {
                writeln!(handle, "agent_uptime_ms: {}", captured - value)?;
            }
        }
    }
    if let Some(value) = metrics.queue_wait_avg_ns {
        writeln!(handle, "queue_wait_avg_ns: {:.2}", value)?;
    }
    if let Some(value) = metrics.queue_wait_max_ns {
        writeln!(handle, "queue_wait_max_ns: {}", value)?;
    }
    if let Some(hist) = metrics.queue_wait_histogram.as_ref() {
        if !hist.is_empty() {
            writeln!(handle, "queue_wait_histogram: {}", format_histogram(hist))?;
        }
    }
    let mut percentiles_written = false;
    if let Some(percentiles) = metrics.queue_wait_percentiles.as_ref() {
        percentiles_written = write_metrics_queue_wait_percentiles(&mut handle, percentiles)?;
    }
    if !percentiles_written {
        if let Some(hist) = metrics.queue_wait_histogram.as_ref() {
            if !hist.is_empty() {
                let percentiles = compute_queue_wait_percentiles(hist);
                if !percentiles.is_empty() {
                    for percentile in percentiles {
                        writeln!(
                            handle,
                            "{}: {}",
                            percentile.label,
                            format_percentile_value(&percentile)
                        )?;
                    }
                }
            }
        }
    }
    writeln!(handle, "in_flight: {}", metrics.in_flight)?;
    writeln!(handle, "max_signers: {}", metrics.max_signers)?;
    if let Some(value) = metrics.connections {
        writeln!(handle, "connections: {}", value)?;
    }
    if let Some(value) = metrics.active_connections {
        writeln!(handle, "active_connections: {}", value)?;
    }
    if let Some(value) = metrics.max_active_connections {
        writeln!(handle, "max_active_connections: {}", value)?;
    }
    if let Some(value) = metrics.max_connections {
        writeln!(handle, "max_connections: {}", value)?;
    }
    if let Some(value) = metrics.connection_rejected {
        writeln!(handle, "connection_rejected: {}", value)?;
    }
    if let Some(value) = metrics.list_count {
        writeln!(handle, "list_count: {}", value)?;
    }
    if let Some(value) = metrics.list_hit {
        writeln!(handle, "list_hit: {}", value)?;
    }
    if let Some(value) = metrics.list_stale {
        writeln!(handle, "list_stale: {}", value)?;
    }
    if let Some(value) = metrics.list_refresh {
        writeln!(handle, "list_refresh: {}", value)?;
    }
    if let Some(value) = metrics.list_errors {
        writeln!(handle, "list_errors: {}", value)?;
    }
    if let Some(value) = metrics.store_sign_file {
        writeln!(handle, "store_sign_file: {}", value)?;
    }
    if let Some(value) = metrics.store_sign_pkcs11 {
        writeln!(handle, "store_sign_pkcs11: {}", value)?;
    }
    if let Some(value) = metrics.store_sign_secure_enclave {
        writeln!(handle, "store_sign_secure_enclave: {}", value)?;
    }
    if let Some(value) = metrics.store_sign_other {
        writeln!(handle, "store_sign_other: {}", value)?;
    }
    if let Some(value) = metrics.confirm_allow {
        writeln!(handle, "confirm_allow: {}", value)?;
    }
    if let Some(value) = metrics.confirm_cache_hit {
        writeln!(handle, "confirm_cache_hit: {}", value)?;
    }
    if let Some(value) = metrics.confirm_denied {
        writeln!(handle, "confirm_denied: {}", value)?;
    }
    if let Some(value) = metrics.confirm_timeout {
        writeln!(handle, "confirm_timeout: {}", value)?;
    }
    if let Some(value) = metrics.confirm_error {
        writeln!(handle, "confirm_error: {}", value)?;
    }

    Ok(())
}

fn format_histogram(hist: &[u64]) -> String {
    const MAX_ITEMS: usize = 10;
    if hist.len() <= MAX_ITEMS {
        return format!("{hist:?}");
    }
    let mut head: Vec<String> = hist[..MAX_ITEMS]
        .iter()
        .map(|value| value.to_string())
        .collect();
    head.push("...".to_string());
    head.push(hist.last().copied().unwrap_or_default().to_string());
    format!("[{}]", head.join(", "))
}

fn write_metrics_queue_wait_percentiles<W: Write>(
    handle: &mut W,
    percentiles: &MetricsQueueWaitPercentiles,
) -> std::io::Result<bool> {
    let mut wrote = false;
    let entries = [
        ("queue_wait_p50_ns", percentiles.p50),
        ("queue_wait_p90_ns", percentiles.p90),
        ("queue_wait_p95_ns", percentiles.p95),
        ("queue_wait_p99_ns", percentiles.p99),
    ];
    for (label, value) in entries {
        if let Some(value) = value {
            writeln!(
                handle,
                "{}: {}",
                label,
                format_percentile_value_from_parts(value.ns, value.open_ended)
            )?;
            wrote = true;
        }
    }
    Ok(wrote)
}

fn print_pssh_hints(socket_path: &Path) -> Result<()> {
    let message = render_pssh_hints(socket_path);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write!(handle, "{}", message)?;
    Ok(())
}

fn render_pssh_hints(socket_path: &Path) -> String {
    let socket = socket_path.to_string_lossy();
    format!(
        "Recommended pssh options for high fan-out:\n\n\
export SECRETIVE_SOCK='{socket}'\n\
pssh -h hosts.txt -P -p 1000 -x \"-o IdentitiesOnly=yes -o IdentityAgent=$SECRETIVE_SOCK -o PreferredAuthentications=publickey\"\n\n\
Optional ~/.ssh/config baseline:\n\n\
Host *\n\
  IdentitiesOnly yes\n\
  IdentityAgent {socket}\n\
  PreferredAuthentications publickey\n"
    )
}

#[derive(Serialize)]
struct JsonIdentity<'a> {
    key_blob_hex: String,
    comment: &'a str,
    algorithm: Option<&'a str>,
    fingerprint: Option<String>,
    openssh: Option<String>,
}

#[derive(Serialize)]
struct JsonSignature<'a> {
    algorithm: &'a str,
    signature_hex: String,
    signature_blob_hex: String,
}

#[derive(Serialize)]
struct HealthReport {
    total_identities: usize,
    valid_identities: usize,
    invalid_key_blobs: usize,
    unique_key_blobs: usize,
    duplicate_key_blobs: usize,
    unique_fingerprints: usize,
    duplicate_fingerprints: usize,
    duplicate_comments: usize,
    algorithms: BTreeMap<String, usize>,
}

fn read_string(buf: &mut &[u8]) -> Result<Vec<u8>> {
    if buf.len() < 4 {
        return Err(anyhow::anyhow!("invalid blob"));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err(anyhow::anyhow!("invalid blob"));
    }
    let mut out = vec![0u8; len];
    out.copy_from_slice(&buf[..len]);
    *buf = &buf[len..];
    Ok(out)
}

fn read_string_ref<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    if buf.len() < 4 {
        return Err(anyhow::anyhow!("invalid blob"));
    }
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return Err(anyhow::anyhow!("invalid blob"));
    }
    let (out, rest) = buf.split_at(len);
    *buf = rest;
    Ok(out)
}

#[derive(Debug)]
struct Args {
    socket_path: Option<String>,
    metrics_file: Option<String>,
    pssh_hints: bool,
    list: bool,
    health: bool,
    show_openssh: bool,
    json: bool,
    json_compact: bool,
    raw: bool,
    filter: Option<String>,
    sign_key_blob: Option<String>,
    sign_comment: Option<String>,
    sign_fingerprint: Option<String>,
    sign_path: Option<String>,
    flags: u32,
    response_timeout_ms: Option<u64>,
    help: bool,
    version: bool,
    queue_wait_tail_ns: Option<String>,
    queue_wait_tail_max_ratio: Option<String>,
    queue_wait_tail_profile: Option<String>,
    queue_wait_max_age_ms: Option<String>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        socket_path: None,
        metrics_file: None,
        pssh_hints: false,
        list: false,
        health: false,
        show_openssh: false,
        json: false,
        json_compact: false,
        raw: false,
        filter: None,
        sign_key_blob: None,
        sign_comment: None,
        sign_fingerprint: None,
        sign_path: None,
        flags: 0,
        response_timeout_ms: None,
        help: false,
        version: false,
        queue_wait_tail_ns: None,
        queue_wait_tail_max_ratio: None,
        queue_wait_tail_profile: None,
        queue_wait_max_age_ms: None,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => parsed.socket_path = args.next(),
            "--metrics-file" => parsed.metrics_file = args.next(),
            "--queue-wait-tail-ns" => parsed.queue_wait_tail_ns = args.next(),
            "--queue-wait-tail-max-ratio" => parsed.queue_wait_tail_max_ratio = args.next(),
            "--queue-wait-tail-profile" => parsed.queue_wait_tail_profile = args.next(),
            "--queue-wait-max-age-ms" => parsed.queue_wait_max_age_ms = args.next(),
            "--pssh-hints" => parsed.pssh_hints = true,
            "--list" => parsed.list = true,
            "--health" => parsed.health = true,
            "--openssh" => parsed.show_openssh = true,
            "--json" => parsed.json = true,
            "--json-compact" => {
                parsed.json = true;
                parsed.json_compact = true;
            }
            "--raw" => parsed.raw = true,
            "--filter" => parsed.filter = args.next(),
            "--sign" => parsed.sign_key_blob = args.next(),
            "--comment" => parsed.sign_comment = args.next(),
            "--fingerprint" => parsed.sign_fingerprint = args.next(),
            "--data" => parsed.sign_path = args.next(),
            "--flags" => {
                if let Some(value) = args.next() {
                    if let Some(parsed_value) = parse_flags(&value) {
                        parsed.flags = parsed_value;
                    }
                }
            }
            "--response-timeout-ms" => {
                if let Some(value) = args.next() {
                    parsed.response_timeout_ms = value.parse().ok();
                }
            }
            "-h" | "--help" => parsed.help = true,
            "--version" => parsed.version = true,
            _ => {}
        }
    }

    parsed
}

fn print_help() {
    println!("secretive-client usage:\n");
    println!("  --list [--json|--json-compact] [--openssh] [--raw] [--filter <substring>]");
    println!("  --health [--json|--json-compact] [--filter <substring>]");
    println!("  --metrics-file <path> [--json|--json-compact]");
    println!("    [--queue-wait-tail-profile <name>]");
    println!("    [--queue-wait-tail-ns <nanoseconds>]");
    println!("    [--queue-wait-tail-max-ratio <0.0-1.0>]");
    println!("    [--queue-wait-max-age-ms <milliseconds>]");
    println!("  --pssh-hints [--socket <path>]");
    println!("  --sign <key_blob_hex> [--data <path>] [--flags <u32>] [--json|--json-compact]");
    println!("  --comment <comment> [--data <path>] [--flags <u32>] [--json|--json-compact]");
    println!(
        "  --fingerprint <SHA256:...> [--data <path>] [--flags <u32>] [--json|--json-compact]"
    );
    println!("  --socket <path>");
    println!("  --response-timeout-ms <n>\n");
    println!("  --version\n");
    println!("Notes:");
    println!("  If --data is omitted, stdin is used for signing.");
    println!("  --health reports identity quality and duplicate diagnostics.");
    println!("  --metrics-file reads a metrics JSON snapshot file (no socket required).");
    println!("  --pssh-hints prints OpenSSH/pssh options for high-fanout runs.");
    println!("  --flags accepts numeric values or rsa hash names (sha256/sha512/ssh-rsa).");
    println!("  --raw skips public key parsing (no fingerprint/openssh fields).");
    println!("  --json-compact emits compact JSON (no pretty formatting).");
    println!("  Queue-wait guardrail flags require --metrics-file and exit non-zero on failure.");
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
        build_health_report, choose_guardrail_percentile, compute_queue_wait_percentiles,
        evaluate_queue_wait_guardrail, format_percentile_value, histogram_tail_ratio_guardrail,
        parse_fingerprint_input, parse_flags, queue_wait_profile_defaults, render_pssh_hints,
        write_metrics_queue_wait_percentiles, MetricsPercentileValue, MetricsQueueWaitPercentiles,
        MetricsSnapshot, QueueWaitGuardrail, QUEUE_WAIT_BUCKET_BOUNDS, QUEUE_WAIT_PERCENTILES,
    };
    use secretive_proto::Identity;
    use std::path::PathBuf;

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
    fn parse_fingerprint_accepts_prefixes() {
        let sample = "SHA256:JQ6FV0rf7qqJHZqIj4zNH8eV0oB8KLKh9Pph3FTD98g";
        assert!(parse_fingerprint_input(sample).is_some());
        assert!(
            parse_fingerprint_input("sha256:JQ6FV0rf7qqJHZqIj4zNH8eV0oB8KLKh9Pph3FTD98g").is_some()
        );
    }

    #[test]
    fn parse_fingerprint_accepts_bare() {
        let sample = "JQ6FV0rf7qqJHZqIj4zNH8eV0oB8KLKh9Pph3FTD98g";
        assert!(parse_fingerprint_input(sample).is_some());
    }

    #[test]
    fn health_report_counts_invalid_and_duplicates() {
        let key = ssh_key::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICG6kjK0iJxESpkwvCTOwwcUsJcggrGhSdHyaP0JHGub",
        )
        .expect("public key");
        let key_blob = key.to_bytes().expect("key blob");
        let identities = vec![
            Identity {
                key_blob: key_blob.clone(),
                comment: "one".to_string(),
            },
            Identity {
                key_blob: key_blob.clone(),
                comment: "dup".to_string(),
            },
            Identity {
                key_blob: vec![1, 2, 3],
                comment: "dup".to_string(),
            },
        ];

        let report = build_health_report(&identities);
        assert_eq!(report.total_identities, 3);
        assert_eq!(report.valid_identities, 2);
        assert_eq!(report.invalid_key_blobs, 1);
        assert_eq!(report.unique_key_blobs, 2);
        assert_eq!(report.duplicate_key_blobs, 1);
        assert_eq!(report.unique_fingerprints, 1);
        assert_eq!(report.duplicate_fingerprints, 1);
        assert_eq!(report.duplicate_comments, 1);
        assert_eq!(report.algorithms.get("ssh-ed25519"), Some(&2));
    }

    #[test]
    fn metrics_snapshot_parses_optional_fields() {
        let raw = r#"{
            "kind":"snapshot",
            "count":100,
            "errors":2,
            "timeouts":1,
            "avg_ns":42.0,
            "captured_unix_ms":1700000000000,
            "started_unix_ms":1699999999000,
            "queue_wait_avg_ns":7.5,
            "queue_wait_max_ns":900,
            "in_flight":3,
            "max_signers":64,
            "store_sign_file":80,
            "store_sign_pkcs11":20,
            "confirm_allow":30,
            "confirm_cache_hit":10,
            "confirm_denied":2,
            "confirm_timeout":1,
            "confirm_error":0,
            "queue_wait_percentiles":{
                "p50":{"ns":512,"open_ended":false},
                "p99":{"ns":8000000000,"open_ended":true}
            }
        }"#;
        let snapshot: MetricsSnapshot = serde_json::from_str(raw).expect("metrics json");
        assert_eq!(snapshot.kind, "snapshot");
        assert_eq!(snapshot.count, 100);
        assert_eq!(snapshot.queue_wait_max_ns, Some(900));
        assert_eq!(snapshot.captured_unix_ms, Some(1_700_000_000_000));
        assert_eq!(snapshot.started_unix_ms, Some(1_699_999_999_000));
        assert_eq!(snapshot.store_sign_file, Some(80));
        assert_eq!(snapshot.store_sign_pkcs11, Some(20));
        assert_eq!(snapshot.store_sign_other, None);
        assert_eq!(snapshot.confirm_allow, Some(30));
        assert_eq!(snapshot.confirm_cache_hit, Some(10));
        assert_eq!(snapshot.confirm_denied, Some(2));
        assert_eq!(snapshot.confirm_timeout, Some(1));
        assert_eq!(snapshot.confirm_error, Some(0));
        let percentiles = snapshot.queue_wait_percentiles.expect("percentiles");
        assert_eq!(percentiles.p50.unwrap().ns, 512);
        assert!(!percentiles.p50.unwrap().open_ended);
        assert!(percentiles.p99.unwrap().open_ended);
    }

    #[test]
    fn pssh_hints_prints_expected_shape() {
        let path = PathBuf::from("/tmp/secretive.sock");
        let out = render_pssh_hints(&path);
        assert!(out.contains("IdentitiesOnly=yes"));
        assert!(out.contains("IdentityAgent /tmp/secretive.sock"));
        assert!(out.contains("Host *"));
    }

    #[test]
    fn queue_wait_percentiles_cover_histogram() {
        let mut hist = vec![0u64; QUEUE_WAIT_BUCKET_BOUNDS.len() + 1];
        hist[0] = 5;
        hist[5] = 4;
        *hist.last_mut().expect("hist") = 1;

        let percentiles = compute_queue_wait_percentiles(&hist);
        assert_eq!(percentiles.len(), QUEUE_WAIT_PERCENTILES.len());
        assert_eq!(percentiles[0].label, "queue_wait_p50_ns");
        assert_eq!(percentiles[0].value_ns, QUEUE_WAIT_BUCKET_BOUNDS[0]);
        assert!(!percentiles[0].open_ended);

        let tail = percentiles.last().expect("tail percentile");
        assert!(tail.open_ended);
        assert!(format_percentile_value(tail).starts_with(">="));
    }

    #[test]
    fn write_metrics_queue_wait_percentiles_prefers_snapshot_values() {
        let percentiles = MetricsQueueWaitPercentiles {
            p50: Some(MetricsPercentileValue {
                ns: 512,
                open_ended: false,
            }),
            p90: None,
            p95: Some(MetricsPercentileValue {
                ns: 16_000_000,
                open_ended: false,
            }),
            p99: Some(MetricsPercentileValue {
                ns: 8_000_000_000,
                open_ended: true,
            }),
        };
        let mut buf = Vec::new();
        let wrote = write_metrics_queue_wait_percentiles(&mut buf, &percentiles)
            .expect("write percentiles");
        assert!(wrote);
        let output = String::from_utf8(buf).expect("utf8");
        assert!(output.contains("queue_wait_p50_ns: <="));
        assert!(output.contains("queue_wait_p95_ns: <="));
        assert!(output.contains("queue_wait_p99_ns: >="));
    }

    #[test]
    fn queue_wait_profile_defaults_match_expected() {
        assert_eq!(queue_wait_profile_defaults("pssh"), Some((4_000_000, 0.03)));
        assert_eq!(
            queue_wait_profile_defaults("fanout"),
            Some((6_000_000, 0.04))
        );
        assert_eq!(
            queue_wait_profile_defaults("balanced"),
            Some((8_000_000, 0.05))
        );
        assert_eq!(
            queue_wait_profile_defaults("LOW-MEMORY"),
            Some((12_000_000, 0.07))
        );
        assert!(queue_wait_profile_defaults("custom").is_none());
    }

    #[test]
    fn choose_guardrail_percentile_selects_expected_label() {
        let percentiles = MetricsQueueWaitPercentiles {
            p50: Some(MetricsPercentileValue {
                ns: 1_000,
                open_ended: false,
            }),
            p90: Some(MetricsPercentileValue {
                ns: 2_000,
                open_ended: false,
            }),
            p95: Some(MetricsPercentileValue {
                ns: 4_000,
                open_ended: false,
            }),
            p99: Some(MetricsPercentileValue {
                ns: 8_000,
                open_ended: false,
            }),
        };
        let sample = choose_guardrail_percentile(&percentiles, 0.9).expect("sample");
        assert_eq!(sample.label, "p90");
        assert_eq!(sample.ns, 2_000);
    }

    #[test]
    fn histogram_tail_ratio_guardrail_counts_tail() {
        let mut hist = vec![0u64; QUEUE_WAIT_BUCKET_BOUNDS.len() + 1];
        hist[0] = 50;
        hist[6] = 25;
        hist[10] = 25;
        let (tail, total) =
            histogram_tail_ratio_guardrail(&hist, 32_000, 0).expect("hist ratio available");
        assert_eq!(total, 100);
        // threshold 32_000ns means tail should include bucket index >=6
        assert_eq!(tail, 25 + 25);
    }

    #[test]
    fn guardrail_evaluation_passes_with_percentile() {
        let mut snapshot = sample_metrics_snapshot();
        snapshot.queue_wait_percentiles = Some(MetricsQueueWaitPercentiles {
            p50: None,
            p90: Some(MetricsPercentileValue {
                ns: 2_000,
                open_ended: false,
            }),
            p95: Some(MetricsPercentileValue {
                ns: 3_000,
                open_ended: false,
            }),
            p99: None,
        });
        let guardrail = QueueWaitGuardrail {
            tail_threshold_ns: Some(5_000),
            tail_max_ratio: Some(0.05),
            target_percentile: Some(0.95),
            max_age_ms: None,
            auto_profile: None,
            auto_profile_applied: false,
        };
        let verdict = evaluate_queue_wait_guardrail(&snapshot, &guardrail);
        assert!(verdict.passed);
    }

    #[test]
    fn guardrail_evaluation_fails_with_histogram_ratio() {
        let mut snapshot = sample_metrics_snapshot();
        snapshot.queue_wait_percentiles = None;
        let mut hist = vec![0u64; QUEUE_WAIT_BUCKET_BOUNDS.len() + 1];
        hist[0] = 94;
        hist[10] = 6; // bucket >= 512_000ns
        snapshot.queue_wait_histogram = Some(hist);
        let guardrail = QueueWaitGuardrail {
            tail_threshold_ns: Some(400_000),
            tail_max_ratio: Some(0.05),
            target_percentile: Some(0.95),
            max_age_ms: None,
            auto_profile: None,
            auto_profile_applied: false,
        };
        let verdict = evaluate_queue_wait_guardrail(&snapshot, &guardrail);
        assert!(!verdict.passed);
    }

    fn sample_metrics_snapshot() -> MetricsSnapshot {
        MetricsSnapshot {
            kind: "snapshot".to_string(),
            count: 100,
            errors: 0,
            timeouts: 0,
            avg_ns: 0.0,
            captured_unix_ms: Some(1_700_000_000_000),
            started_unix_ms: Some(1_699_999_999_000),
            queue_wait_avg_ns: Some(0.0),
            queue_wait_max_ns: Some(0),
            in_flight: 0,
            max_signers: 0,
            connections: Some(0),
            active_connections: Some(0),
            max_active_connections: Some(0),
            max_connections: Some(0),
            connection_rejected: Some(0),
            list_count: Some(0),
            list_hit: Some(0),
            list_stale: Some(0),
            list_refresh: Some(0),
            list_errors: Some(0),
            store_sign_file: Some(0),
            store_sign_pkcs11: Some(0),
            store_sign_secure_enclave: Some(0),
            store_sign_other: Some(0),
            confirm_allow: Some(0),
            confirm_cache_hit: Some(0),
            confirm_denied: Some(0),
            confirm_timeout: Some(0),
            confirm_error: Some(0),
            queue_wait_histogram: Some(vec![0; QUEUE_WAIT_BUCKET_BOUNDS.len() + 1]),
            queue_wait_percentiles: None,
        }
    }
}
