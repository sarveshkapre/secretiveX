use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use rand::RngCore;
use rand::SeedableRng;
use secretive_proto::{read_response, write_request, AgentRequest, AgentResponse};
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = parse_args();
    let socket_path = resolve_socket_path(args.socket_path.clone());

    let total_requests = args.concurrency * args.requests_per_worker;
    info!(?socket_path, concurrency = args.concurrency, total_requests, "starting benchmark");

    let start = Instant::now();

    let mut handles = Vec::with_capacity(args.concurrency);
    for worker_id in 0..args.concurrency {
        let socket_path = socket_path.clone();
        let requests = args.requests_per_worker;
        let warmup = args.warmup;
        handles.push(tokio::spawn(async move {
            run_worker(worker_id, socket_path, requests, warmup).await
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

    println!("Completed {ok} requests in {elapsed:?} ({rps:.2} req/s). Failures: {failures}");
}

async fn run_worker(
    worker_id: usize,
    socket_path: PathBuf,
    requests: usize,
    warmup: usize,
) -> Result<usize> {
    let stream = connect(&socket_path).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);

    write_request(&mut writer, &AgentRequest::RequestIdentities).await?;
    let response = read_response(&mut reader).await?;
    let key_blob = match response {
        AgentResponse::IdentitiesAnswer { identities } => identities
            .into_iter()
            .next()
            .map(|id| id.key_blob)
            .ok_or_else(|| anyhow::anyhow!("no identities"))?,
        _ => {
            return Err(anyhow::anyhow!("unexpected response"))
        }
    };

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut data = vec![0u8; 32];

    for _ in 0..warmup {
        rng.fill_bytes(&mut data);
        let request = AgentRequest::SignRequest {
            key_blob: key_blob.clone(),
            data: data.clone(),
            flags: 0,
        };
        write_request(&mut writer, &request).await?;
        let response = read_response(&mut reader).await?;
        if !matches!(response, AgentResponse::SignResponse { .. }) {
            return Err(anyhow::anyhow!("unexpected sign response"));
        }
    }

    let mut completed = 0usize;
    for _ in 0..requests {
        rng.fill_bytes(&mut data);
        let request = AgentRequest::SignRequest {
            key_blob: key_blob.clone(),
            data: data.clone(),
            flags: 0,
        };
        write_request(&mut writer, &request).await?;
        let response = read_response(&mut reader).await?;
        if matches!(response, AgentResponse::SignResponse { .. }) {
            completed += 1;
        }
    }

    info!(worker_id, completed, "worker done");
    Ok(completed)
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        socket_path: None,
        concurrency: 32,
        requests_per_worker: 100,
        warmup: 10,
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
            _ => {}
        }
    }

    parsed
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
