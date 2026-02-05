use std::path::{Path, PathBuf};
use std::io::Read;

use anyhow::Result;
use bytes::BytesMut;
use secretive_proto::{read_response_with_buffer, write_request, AgentRequest, AgentResponse};
use ssh_key::Signature;

#[cfg(unix)]
use tokio::net::UnixStream as AgentStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient as AgentStream;

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();
    let socket_path = resolve_socket_path(args.socket_path.clone());
    let mut stream = connect(&socket_path).await?;

    if args.list {
        list_identities(&mut stream, args.show_openssh, args.json).await?;
        return Ok(());
    }

    if let Some(key_hex) = args.sign_key_blob {
        let key_blob = hex::decode(key_hex)?;
        let data = if let Some(path) = args.sign_path {
            std::fs::read(path)?
        } else {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        };
        let signature_blob = sign_data(&mut stream, key_blob, data, args.flags).await?;
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

async fn list_identities(
    stream: &mut AgentStream,
    show_openssh: bool,
    json_output: bool,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(4096);
    write_request(&mut writer, &AgentRequest::RequestIdentities).await?;
    let response = read_response_with_buffer(&mut reader, &mut buffer).await?;

    match response {
        AgentResponse::IdentitiesAnswer { identities } => {
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
        }
        _ => {
            println!("Unexpected response");
        }
    }

    Ok(())
}

async fn sign_data(
    stream: &mut AgentStream,
    key_blob: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
) -> Result<Vec<u8>> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = BytesMut::with_capacity(4096);
    let request = AgentRequest::SignRequest {
        key_blob,
        data,
        flags,
    };
    write_request(&mut writer, &request).await?;
    let response = read_response_with_buffer(&mut reader, &mut buffer).await?;
    match response {
        AgentResponse::SignResponse { signature_blob } => Ok(signature_blob),
        _ => Err(anyhow::anyhow!("unexpected response")),
    }
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
    sign_key_blob: Option<String>,
    sign_path: Option<String>,
    flags: u32,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        socket_path: None,
        list: false,
        show_openssh: false,
        json: false,
        sign_key_blob: None,
        sign_path: None,
        flags: 0,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => parsed.socket_path = args.next(),
            "--list" => parsed.list = true,
            "--openssh" => parsed.show_openssh = true,
            "--json" => parsed.json = true,
            "--sign" => parsed.sign_key_blob = args.next(),
            "--data" => parsed.sign_path = args.next(),
            "--flags" => {
                if let Some(value) = args.next() {
                    parsed.flags = value.parse().unwrap_or(parsed.flags);
                }
            }
            _ => {}
        }
    }

    parsed
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
