use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::RngCore;
use rand::SeedableRng;
use bytes::BytesMut;
use secretive_proto::{
    read_response_with_buffer, write_request_with_buffer, AgentRequest, AgentResponse,
};
use tracing::{error, info};

#[cfg(unix)]
use tokio::net::UnixStream as AgentStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient as AgentStream;

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
    help: bool,
    version: bool,
    duration_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
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
    let socket_path = resolve_socket_path(args.socket_path.clone());
    let shared_key = if args.list_only {
        None
    } else if let Some(hex_key) = args.key_blob_hex.as_deref() {
        Some(hex::decode(hex_key)?)
    } else {
        Some(fetch_first_key(&socket_path).await?)
    };

    let total_requests = args.concurrency * args.requests_per_worker;
    if let Some(duration) = args.duration_secs {
        info!(?socket_path, concurrency = args.concurrency, duration, "starting benchmark");
    } else {
        info!(?socket_path, concurrency = args.concurrency, total_requests, "starting benchmark");
    }

    let start = Instant::now();
    let deadline = args.duration_secs.map(|secs| start + Duration::from_secs(secs));

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
            )
            .await
        }));
    }

    let mut ok = 0usize;
    let mut failures = 0usize;
    for handle in handles {
        match handle.await {
            Ok(Ok(count)) => ok += count,
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

    if args.json {
        let payload = serde_json::json!({
            "ok": ok,
            "failures": failures,
            "elapsed_ms": elapsed.as_millis(),
            "rps": rps,
            "mode": if args.list_only { "list" } else { "sign" },
            "reconnect": args.reconnect,
            "concurrency": args.concurrency,
            "requests_per_worker": args.requests_per_worker,
            "duration_secs": args.duration_secs,
            "randomize_payload": args.randomize_payload,
            "payload_size": args.payload_size,
            "flags": args.flags,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Completed {ok} requests in {elapsed:?} ({rps:.2} req/s). Failures: {failures}");
    }

    Ok(())
}

async fn run_worker(
    worker_id: usize,
    socket_path: PathBuf,
    requests: usize,
    warmup: usize,
    payload_size: usize,
    flags: u32,
    shared_key: Option<Vec<u8>>,
    reconnect: bool,
    list_only: bool,
    randomize_payload: bool,
    deadline: Option<Instant>,
) -> Result<usize> {
    if list_only {
        return run_list_worker(socket_path, requests, warmup, reconnect, deadline).await;
    }

    let key_blob = if let Some(key_blob) = shared_key {
        key_blob
    } else {
        fetch_first_key(&socket_path).await?
    };

    let mut rng = if randomize_payload {
        Some(rand::rngs::SmallRng::from_entropy())
    } else {
        None
    };
    let mut request_buffer = BytesMut::with_capacity(128);
    let mut request = AgentRequest::SignRequest {
        key_blob: key_blob.clone(),
        data: vec![0u8; payload_size],
        flags,
    };

    if reconnect {
        for _ in 0..warmup {
            if let (Some(rng), AgentRequest::SignRequest { data, .. }) = (&mut rng, &mut request) {
                rng.fill_bytes(data);
            }
            let stream = connect(&socket_path).await?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut buffer = BytesMut::with_capacity(4096);
            write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
            let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
            if !matches!(response, AgentResponse::SignResponse { .. }) {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }
    } else {
        let stream = connect(&socket_path).await?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            if let (Some(rng), AgentRequest::SignRequest { data, .. }) = (&mut rng, &mut request) {
                rng.fill_bytes(data);
            }
            write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
            let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
            if !matches!(response, AgentResponse::SignResponse { .. }) {
                return Err(anyhow::anyhow!("unexpected sign response"));
            }
        }

        let mut completed = 0usize;
        if let Some(deadline) = deadline {
            while Instant::now() < deadline {
                if let (Some(rng), AgentRequest::SignRequest { data, .. }) =
                    (&mut rng, &mut request)
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
                let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
                if matches!(response, AgentResponse::SignResponse { .. }) {
                    completed += 1;
                }
            }
        } else {
            for _ in 0..requests {
                if let (Some(rng), AgentRequest::SignRequest { data, .. }) =
                    (&mut rng, &mut request)
                {
                    rng.fill_bytes(data);
                }
                write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
                let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
                if matches!(response, AgentResponse::SignResponse { .. }) {
                    completed += 1;
                }
            }
        }

        info!(worker_id, completed, "worker done");
        return Ok(completed);
    }

    let mut completed = 0usize;
    if let Some(deadline) = deadline {
        while Instant::now() < deadline {
            if let (Some(rng), AgentRequest::SignRequest { data, .. }) = (&mut rng, &mut request) {
                rng.fill_bytes(data);
            }
            let stream = connect(&socket_path).await?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut buffer = BytesMut::with_capacity(4096);
            write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
            let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
            if matches!(response, AgentResponse::SignResponse { .. }) {
                completed += 1;
            }
        }
    } else {
        for _ in 0..requests {
            if let (Some(rng), AgentRequest::SignRequest { data, .. }) = (&mut rng, &mut request) {
                rng.fill_bytes(data);
            }
            let stream = connect(&socket_path).await?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut buffer = BytesMut::with_capacity(4096);
            write_request_with_buffer(&mut writer, &request, &mut request_buffer).await?;
            let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
            if matches!(response, AgentResponse::SignResponse { .. }) {
                completed += 1;
            }
        }
    }

    info!(worker_id, completed, "worker done");
    Ok(completed)
}

async fn run_list_worker(
    socket_path: PathBuf,
    requests: usize,
    warmup: usize,
    reconnect: bool,
    deadline: Option<Instant>,
) -> Result<usize> {
    let mut request_buffer = BytesMut::with_capacity(64);

    if reconnect {
        for _ in 0..warmup {
            list_once(&socket_path, &mut request_buffer).await?;
        }
    } else {
        let stream = connect(&socket_path).await?;
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut buffer = BytesMut::with_capacity(4096);
        for _ in 0..warmup {
            write_request_with_buffer(
                &mut writer,
                &AgentRequest::RequestIdentities,
                &mut request_buffer,
            )
            .await?;
            let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
            if !matches!(response, AgentResponse::IdentitiesAnswer { .. }) {
                return Err(anyhow::anyhow!("unexpected identities response"));
            }
        }

        let mut completed = 0usize;
        if let Some(deadline) = deadline {
            while Instant::now() < deadline {
                write_request_with_buffer(
                    &mut writer,
                    &AgentRequest::RequestIdentities,
                    &mut request_buffer,
                )
                .await?;
                let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
                if matches!(response, AgentResponse::IdentitiesAnswer { .. }) {
                    completed += 1;
                }
            }
        } else {
            for _ in 0..requests {
                write_request_with_buffer(
                    &mut writer,
                    &AgentRequest::RequestIdentities,
                    &mut request_buffer,
                )
                .await?;
                let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
                if matches!(response, AgentResponse::IdentitiesAnswer { .. }) {
                    completed += 1;
                }
            }
        }

        return Ok(completed);
    }

    let mut completed = 0usize;
    if let Some(deadline) = deadline {
        while Instant::now() < deadline {
            list_once(&socket_path, &mut request_buffer).await?;
            completed += 1;
        }
    } else {
        for _ in 0..requests {
            list_once(&socket_path, &mut request_buffer).await?;
            completed += 1;
        }
    }

    Ok(completed)
}

async fn list_once(socket_path: &PathBuf, request_buffer: &mut BytesMut) -> Result<()> {
    let stream = connect(socket_path).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(4096);
    write_request_with_buffer(
        &mut writer,
        &AgentRequest::RequestIdentities,
        request_buffer,
    )
    .await?;
    let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
    if matches!(response, AgentResponse::IdentitiesAnswer { .. }) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unexpected identities response"))
    }
}

async fn fetch_first_key(socket_path: &Path) -> Result<Vec<u8>> {
    let stream = connect(socket_path).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(4096);
    let mut request_buffer = BytesMut::with_capacity(128);
    write_request_with_buffer(
        &mut writer,
        &AgentRequest::RequestIdentities,
        &mut request_buffer,
    )
    .await?;
    let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
    match response {
        AgentResponse::IdentitiesAnswer { identities } => identities
            .into_iter()
            .next()
            .map(|id| id.key_blob)
            .ok_or_else(|| anyhow::anyhow!("no identities")),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
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
        help: false,
        version: false,
        duration_secs: None,
    };

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
                    parsed.requests_per_worker = value.parse().unwrap_or(parsed.requests_per_worker);
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
            "-h" | "--help" => parsed.help = true,
            "--version" => parsed.version = true,
            _ => {}
        }
    }

    parsed
}

fn print_help() {
    println!("secretive-bench usage:\n");
    println!("  --concurrency <n> --requests <n> [--warmup <n>]");
    println!("  --duration <seconds> (overrides --requests)");
    println!("  --payload-size <bytes> --flags <u32> --key <hex_blob>");
    println!("  --socket <path> --json --reconnect --list --fixed\n");
    println!("  --version\n");
    println!("Notes:");
    println!("  Use --key to reuse a specific identity from secretive-client.");
    println!("  Use --list to benchmark list-identities instead of signing.");
    println!("  --flags accepts numeric values or rsa hash names (sha256/sha512/ssh-rsa).");
    println!("  --fixed disables randomizing payload bytes per request.");
}

fn parse_flags(value: &str) -> Option<u32> {
    match value.trim().to_lowercase().as_str() {
        "sha256" | "rsa-sha2-256" => Some(2),
        "sha512" | "rsa-sha2-512" => Some(4),
        "ssh-rsa" | "sha1" => Some(0),
        _ => value.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_flags;

    #[test]
    fn parse_flags_names() {
        assert_eq!(parse_flags("sha256"), Some(2));
        assert_eq!(parse_flags("rsa-sha2-256"), Some(2));
        assert_eq!(parse_flags("sha512"), Some(4));
        assert_eq!(parse_flags("rsa-sha2-512"), Some(4));
        assert_eq!(parse_flags("ssh-rsa"), Some(0));
        assert_eq!(parse_flags("sha1"), Some(0));
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
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("SECRETIVE_PIPE") {
        return PathBuf::from(path);
    }
    PathBuf::from(r"\\.\pipe\secretive-agent")
}
