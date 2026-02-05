use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{AgentRequest, AgentResponse, Identity, MessageType, ProtoError, Result};

pub const MAX_FRAME_LEN: usize = 1024 * 1024; // 1 MiB for now

pub async fn read_request<R>(reader: &mut R) -> Result<AgentRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(|_| ProtoError::UnexpectedEof)?;
    decode_request(&buf)
}

pub async fn read_response<R>(reader: &mut R) -> Result<AgentResponse>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await.map_err(|_| ProtoError::UnexpectedEof)?;
    decode_response(&buf)
}

pub async fn read_request_with_buffer<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
) -> Result<AgentRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    buffer.resize(len, 0);
    reader
        .read_exact(&mut buffer[..])
        .await
        .map_err(|_| ProtoError::UnexpectedEof)?;
    decode_request(&buffer[..])
}

pub async fn write_response<W>(writer: &mut W, response: &AgentResponse) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let payload = encode_response(response);
    writer.write_u32(payload.len() as u32).await.map_err(|_| ProtoError::UnexpectedEof)?;
    writer.write_all(&payload).await.map_err(|_| ProtoError::UnexpectedEof)?;
    writer.flush().await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub async fn write_request<W>(writer: &mut W, request: &AgentRequest) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let payload = encode_request(request);
    writer.write_u32(payload.len() as u32).await.map_err(|_| ProtoError::UnexpectedEof)?;
    writer.write_all(&payload).await.map_err(|_| ProtoError::UnexpectedEof)?;
    writer.flush().await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub fn decode_request(frame: &[u8]) -> Result<AgentRequest> {
    let mut buf = Bytes::copy_from_slice(frame);
    if !buf.has_remaining() {
        return Err(ProtoError::InvalidMessage("missing message type"));
    }
    let message_type = buf.get_u8();
    match message_type {
        x if x == MessageType::RequestIdentities as u8 => Ok(AgentRequest::RequestIdentities),
        x if x == MessageType::SignRequest as u8 => {
            let key_blob = read_string(&mut buf)?;
            let data = read_string(&mut buf)?;
            if buf.remaining() < 4 {
                return Err(ProtoError::UnexpectedEof);
            }
            let flags = buf.get_u32();
            Ok(AgentRequest::SignRequest { key_blob, data, flags })
        }
        other => Ok(AgentRequest::Unknown {
            message_type: other,
            payload: buf,
        }),
    }
}

pub fn decode_response(frame: &[u8]) -> Result<AgentResponse> {
    let mut buf = Bytes::copy_from_slice(frame);
    if !buf.has_remaining() {
        return Err(ProtoError::InvalidMessage("missing message type"));
    }
    let message_type = buf.get_u8();
    match message_type {
        x if x == MessageType::Failure as u8 => Ok(AgentResponse::Failure),
        x if x == MessageType::Success as u8 => Ok(AgentResponse::Success),
        x if x == MessageType::IdentitiesAnswer as u8 => {
            if buf.remaining() < 4 {
                return Err(ProtoError::UnexpectedEof);
            }
            let count = buf.get_u32() as usize;
            let mut identities = Vec::with_capacity(count);
            for _ in 0..count {
                let key_blob = read_string(&mut buf)?;
                let comment = read_string(&mut buf)?;
                let comment = String::from_utf8(comment).map_err(|_| ProtoError::InvalidMessage("invalid utf8 comment"))?;
                identities.push(Identity { key_blob, comment });
            }
            Ok(AgentResponse::IdentitiesAnswer { identities })
        }
        x if x == MessageType::SignResponse as u8 => {
            let signature_blob = read_string(&mut buf)?;
            Ok(AgentResponse::SignResponse { signature_blob })
        }
        _ => Err(ProtoError::InvalidMessage("unknown response")),
    }
}

pub fn encode_response(response: &AgentResponse) -> Bytes {
    let mut buf = match response {
        AgentResponse::IdentitiesAnswer { identities } => {
            let mut cap = 1 + 4;
            for identity in identities {
                cap += 4 + identity.key_blob.len();
                cap += 4 + identity.comment.len();
            }
            BytesMut::with_capacity(cap)
        }
        AgentResponse::SignResponse { signature_blob } => {
            BytesMut::with_capacity(1 + 4 + signature_blob.len())
        }
        _ => BytesMut::with_capacity(1),
    };
    match response {
        AgentResponse::Failure => buf.put_u8(MessageType::Failure as u8),
        AgentResponse::Success => buf.put_u8(MessageType::Success as u8),
        AgentResponse::IdentitiesAnswer { identities } => {
            buf.put_u8(MessageType::IdentitiesAnswer as u8);
            buf.put_u32(identities.len() as u32);
            for identity in identities {
                write_string(&mut buf, &identity.key_blob);
                write_string(&mut buf, identity.comment.as_bytes());
            }
        }
        AgentResponse::SignResponse { signature_blob } => {
            buf.put_u8(MessageType::SignResponse as u8);
            write_string(&mut buf, signature_blob);
        }
    }
    buf.freeze()
}

pub fn encode_request(request: &AgentRequest) -> Bytes {
    let mut buf = BytesMut::new();
    match request {
        AgentRequest::RequestIdentities => buf.put_u8(MessageType::RequestIdentities as u8),
        AgentRequest::SignRequest { key_blob, data, flags } => {
            buf.put_u8(MessageType::SignRequest as u8);
            write_string(&mut buf, key_blob);
            write_string(&mut buf, data);
            buf.put_u32(*flags);
        }
        AgentRequest::Unknown { message_type, payload } => {
            buf.put_u8(*message_type);
            buf.put_slice(payload);
        }
    }
    buf.freeze()
}

pub fn encode_signature_blob(algorithm: &str, signature: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    write_string(&mut buf, algorithm.as_bytes());
    write_string(&mut buf, signature);
    buf.to_vec()
}

fn read_string(buf: &mut Bytes) -> Result<Vec<u8>> {
    if buf.remaining() < 4 {
        return Err(ProtoError::UnexpectedEof);
    }
    let len = buf.get_u32() as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    if buf.remaining() < len {
        return Err(ProtoError::UnexpectedEof);
    }
    let data = buf.copy_to_bytes(len).to_vec();
    Ok(data)
}

fn write_string(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn decode_request_identities() {
        let frame = [MessageType::RequestIdentities as u8];
        let request = decode_request(&frame).unwrap();
        assert!(matches!(request, AgentRequest::RequestIdentities));
    }

    #[test]
    fn encode_identities_answer() {
        let response = AgentResponse::IdentitiesAnswer {
            identities: vec![Identity { key_blob: vec![1, 2, 3], comment: "test".into() }],
        };
        let encoded = encode_response(&response);
        let mut buf = Bytes::from(encoded);
        assert_eq!(buf.get_u8(), MessageType::IdentitiesAnswer as u8);
        assert_eq!(buf.get_u32(), 1);
        assert_eq!(buf.get_u32(), 3);
        assert_eq!(buf.copy_to_bytes(3).to_vec(), vec![1, 2, 3]);
        assert_eq!(buf.get_u32(), 4);
        assert_eq!(buf.copy_to_bytes(4).to_vec(), b"test");
    }

    #[test]
    fn encode_signature_blob_format() {
        let encoded = encode_signature_blob("ssh-ed25519", &[1, 2, 3, 4]);
        let mut buf = Bytes::from(encoded);
        assert_eq!(buf.get_u32(), 11);
        assert_eq!(buf.copy_to_bytes(11).to_vec(), b"ssh-ed25519");
        assert_eq!(buf.get_u32(), 4);
        assert_eq!(buf.copy_to_bytes(4).to_vec(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn encode_request_sign() {
        let request = AgentRequest::SignRequest {
            key_blob: vec![1, 2],
            data: vec![3, 4, 5],
            flags: 7,
        };
        let encoded = encode_request(&request);
        let mut buf = Bytes::from(encoded);
        assert_eq!(buf.get_u8(), MessageType::SignRequest as u8);
        assert_eq!(buf.get_u32(), 2);
        assert_eq!(buf.copy_to_bytes(2).to_vec(), vec![1, 2]);
        assert_eq!(buf.get_u32(), 3);
        assert_eq!(buf.copy_to_bytes(3).to_vec(), vec![3, 4, 5]);
        assert_eq!(buf.get_u32(), 7);
    }

    #[test]
    fn decode_response_identities() {
        let response = AgentResponse::IdentitiesAnswer {
            identities: vec![Identity {
                key_blob: vec![9],
                comment: "x".into(),
            }],
        };
        let encoded = encode_response(&response);
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            AgentResponse::IdentitiesAnswer { identities } => {
                assert_eq!(identities.len(), 1);
                assert_eq!(identities[0].key_blob, vec![9]);
                assert_eq!(identities[0].comment, "x");
            }
            _ => panic!("unexpected response"),
        }
    }
}
