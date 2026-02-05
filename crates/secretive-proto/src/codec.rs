use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{AgentRequest, AgentResponse, MessageType, ProtoError, Result};

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

pub fn encode_response(response: &AgentResponse) -> Bytes {
    let mut buf = BytesMut::new();
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
}
