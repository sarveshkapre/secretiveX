use std::path::{Path, PathBuf};
use std::io::Read;

use anyhow::Result;
use bytes::BytesMut;
use secretive_proto::{read_response_with_buffer, write_request, AgentRequest, AgentResponse, Identity};
use ssh_key::Signature;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
use tokio::net::UnixStream as AgentStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient as AgentStream;

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
    let socket_path = resolve_socket_path(args.socket_path.clone());
    let stream = connect(&socket_path).await?;

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(4096);

    if args.list {
        list_identities(
            &mut reader,
            &mut writer,
            &mut buffer,
            args.show_openssh,
            args.json,
            args.filter.as_deref(),
        )
            .await?;
        return Ok(());
    }

    if args.sign_key_blob.is_some() || args.sign_comment.is_some() || args.sign_fingerprint.is_some() {
        let key_blob = if let Some(key_hex) = args.sign_key_blob {
            hex::decode(key_hex)?
        } else if let Some(comment) = args.sign_comment.as_deref() {
            select_key_by_comment(&mut reader, &mut writer, &mut buffer, comment).await?
        } else if let Some(fingerprint) = args.sign_fingerprint.as_deref() {
            select_key_by_fingerprint(&mut reader, &mut writer, &mut buffer, fingerprint).await?
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
        let signature_blob = sign_data(&mut reader, &mut writer, &mut buffer, key_blob, data, args.flags)
            .await?;
        let signature = decode_signature_blob(&signature_blob)?;
        if args.json {
            let payload = serde_json::json!({
                "algorithm": signature.algorithm().as_str(),
                "signature_hex": hex::encode(signature.as_bytes()),
                "signature_blob_hex": hex::encode(signature_blob),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("algorithm: {}", signature.algorithm().as_str());
            println!("signature: {}", hex::encode(signature.as_bytes()));
        }
        return Ok(());
    }

    eprintln!("No command provided. Use --list or --sign.");
    Ok(())
}

async fn list_identities<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut BytesMut,
    show_openssh: bool,
    json_output: bool,
    filter: Option<&str>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut identities = fetch_identities(reader, writer, buffer).await?;
    if let Some(filter) = filter {
        identities.retain(|id| id.comment.contains(filter));
    }

    if json_output {
        let mut out = Vec::new();
        for identity in identities {
            let mut alg = None;
            let mut fp = None;
            let mut openssh = None;
            if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                alg = Some(public_key.algorithm().as_str().to_string());
                fp = Some(public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string());
                if show_openssh {
                    if let Ok(ssh) = public_key.to_openssh() {
                        openssh = Some(ssh.trim().to_string());
                    }
                }
            }
            out.push(serde_json::json!({
                "key_blob_hex": hex::encode(&identity.key_blob),
                "comment": identity.comment,
                "algorithm": alg,
                "fingerprint": fp,
                "openssh": openssh,
            }));
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for identity in identities {
            let mut details = String::new();
            if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
                let alg = public_key.algorithm().as_str().to_string();
                let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
                if show_openssh {
                    if let Ok(ssh) = public_key.to_openssh() {
                        details = format!(" {} {} {}", alg, fp, ssh.trim());
                    } else {
                        details = format!(" {} {}", alg, fp);
                    }
                } else {
                    details = format!(" {} {}", alg, fp);
                }
            }
            println!("{} {}{}", hex::encode(identity.key_blob), identity.comment, details);
        }
    }

    Ok(())
}

async fn sign_data<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut BytesMut,
    key_blob: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let request = AgentRequest::SignRequest {
        key_blob,
        data,
        flags,
    };
    write_request(writer, &request).await?;
    let response = read_response_with_buffer(reader, buffer).await?;
    match response {
        AgentResponse::SignResponse { signature_blob } => Ok(signature_blob),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
}

async fn fetch_identities<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut BytesMut,
) -> Result<Vec<Identity>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_request(writer, &AgentRequest::RequestIdentities).await?;
    let response = read_response_with_buffer(reader, buffer).await?;
    match response {
        AgentResponse::IdentitiesAnswer { identities } => Ok(identities),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
}

async fn select_key_by_comment<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut BytesMut,
    comment: &str,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let identities = fetch_identities(reader, writer, buffer).await?;
    identities
        .into_iter()
        .find(|id| id.comment == comment)
        .map(|id| id.key_blob)
        .ok_or_else(|| anyhow::anyhow!("no identity with comment: {comment}"))
}

async fn select_key_by_fingerprint<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut BytesMut,
    fingerprint: &str,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let identities = fetch_identities(reader, writer, buffer).await?;
    for identity in identities {
        if let Ok(public_key) = ssh_key::PublicKey::from_bytes(&identity.key_blob) {
            let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
            if fp == fingerprint {
                return Ok(identity.key_blob);
            }
        }
    }
    Err(anyhow::anyhow!("no identity with fingerprint: {fingerprint}"))
}

fn decode_signature_blob(blob: &[u8]) -> Result<Signature> {
    let mut cursor = &blob[..];
    let algorithm = read_string(&mut cursor)?;
    let signature = read_string(&mut cursor)?;
    let algorithm = std::str::from_utf8(&algorithm)?;
    let signature = Signature::new(ssh_key::Algorithm::new(algorithm)?, signature)?;
    Ok(signature)
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
    let out = buf[..len].to_vec();
    *buf = &buf[len..];
    Ok(out)
}

#[derive(Debug)]
struct Args {
    socket_path: Option<String>,
    list: bool,
    show_openssh: bool,
    json: bool,
    filter: Option<String>,
    sign_key_blob: Option<String>,
    sign_comment: Option<String>,
    sign_fingerprint: Option<String>,
    sign_path: Option<String>,
    flags: u32,
    help: bool,
    version: bool,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        socket_path: None,
        list: false,
        show_openssh: false,
        json: false,
        filter: None,
        sign_key_blob: None,
        sign_comment: None,
        sign_fingerprint: None,
        sign_path: None,
        flags: 0,
        help: false,
        version: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => parsed.socket_path = args.next(),
            "--list" => parsed.list = true,
            "--openssh" => parsed.show_openssh = true,
            "--json" => parsed.json = true,
            "--filter" => parsed.filter = args.next(),
            "--sign" => parsed.sign_key_blob = args.next(),
            "--comment" => parsed.sign_comment = args.next(),
            "--fingerprint" => parsed.sign_fingerprint = args.next(),
            "--data" => parsed.sign_path = args.next(),
            "--flags" => {
                if let Some(value) = args.next() {
                    parsed.flags = value.parse().unwrap_or(parsed.flags);
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
    println!("  --list [--json] [--openssh] [--filter <substring>]");
    println!("  --sign <key_blob_hex> [--data <path>] [--flags <u32>] [--json]");
    println!("  --comment <comment> [--data <path>] [--flags <u32>] [--json]");
    println!("  --fingerprint <SHA256:...> [--data <path>] [--flags <u32>] [--json]");
    println!("  --socket <path>\n");
    println!("Notes:");
    println!("  If --data is omitted, stdin is used for signing.");
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
