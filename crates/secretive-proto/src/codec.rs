use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{AgentRequest, AgentResponse, Identity, MessageType, ProtoError, Result};

pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024; // 4 MiB to handle large identity sets

pub async fn read_request<R>(reader: &mut R) -> Result<AgentRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut buf = Vec::with_capacity(len);
    unsafe {
        buf.set_len(len);
    }
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
    let mut buf = Vec::with_capacity(len);
    unsafe {
        buf.set_len(len);
    }
    reader.read_exact(&mut buf).await.map_err(|_| ProtoError::UnexpectedEof)?;
    decode_response(&buf)
}

pub async fn read_response_with_buffer<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
) -> Result<AgentResponse>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
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
    decode_response(&buffer[..])
}

pub async fn read_response_type_with_buffer<R>(
    reader: &mut R,
    buffer: &mut BytesMut,
) -> Result<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let len = reader.read_u32().await.map_err(|_| ProtoError::UnexpectedEof)? as usize;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    if len == 0 {
        return Err(ProtoError::InvalidMessage("missing message type"));
    }
    let mut header = [0u8; 1];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| ProtoError::UnexpectedEof)?;
    let mut remaining = len - 1;
    if remaining == 0 {
        return Ok(header[0]);
    }

    buffer.clear();
    if buffer.capacity() == 0 {
        buffer.reserve(1024);
    }
    while remaining > 0 {
        let chunk = remaining.min(buffer.capacity());
        unsafe {
            buffer.set_len(chunk);
        }
        reader
            .read_exact(&mut buffer[..chunk])
            .await
            .map_err(|_| ProtoError::UnexpectedEof)?;
        remaining -= chunk;
    }

    Ok(header[0])
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
    buffer.clear();
    buffer.reserve(len);
    unsafe {
        buffer.set_len(len);
    }
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

    let frame = encode_response_frame(response)?;
    writer.write_all(&frame).await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub async fn write_response_with_buffer<W>(
    writer: &mut W,
    response: &AgentResponse,
    buffer: &mut BytesMut,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    encode_response_frame_into(response, buffer)?;
    writer.write_all(&buffer[..]).await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub async fn write_request<W>(writer: &mut W, request: &AgentRequest) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let frame = encode_request_frame(request)?;
    writer.write_all(&frame).await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub async fn write_request_with_buffer<W>(
    writer: &mut W,
    request: &AgentRequest,
    buffer: &mut BytesMut,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    encode_request_frame_into(request, buffer)?;
    writer.write_all(&buffer[..]).await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub async fn write_payload<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let frame = encode_frame(payload)?;
    writer.write_all(&frame).await.map_err(|_| ProtoError::UnexpectedEof)?;
    Ok(())
}

pub fn decode_request(frame: &[u8]) -> Result<AgentRequest> {
    let mut buf = &frame[..];
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
            payload: buf.copy_to_bytes(buf.remaining()),
        }),
    }
}

pub fn decode_response(frame: &[u8]) -> Result<AgentResponse> {
    let mut buf = &frame[..];
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

pub fn encode_frame(payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(payload.len()));
    }
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.put_slice(payload);
    Ok(buf.freeze())
}

pub fn encode_response_frame(response: &AgentResponse) -> Result<Bytes> {
    let mut buffer = BytesMut::new();
    encode_response_frame_into(response, &mut buffer)?;
    Ok(buffer.freeze())
}

pub fn encode_response_into(response: &AgentResponse, buffer: &mut BytesMut) {
    buffer.clear();
    match response {
        AgentResponse::IdentitiesAnswer { identities } => {
            let mut cap = 1 + 4;
            for identity in identities {
                cap += 4 + identity.key_blob.len();
                cap += 4 + identity.comment.len();
            }
            buffer.reserve(cap);
            buffer.put_u8(MessageType::IdentitiesAnswer as u8);
            buffer.put_u32(identities.len() as u32);
            for identity in identities {
                write_string(buffer, &identity.key_blob);
                write_string(buffer, identity.comment.as_bytes());
            }
        }
        AgentResponse::SignResponse { signature_blob } => {
            buffer.reserve(1 + 4 + signature_blob.len());
            buffer.put_u8(MessageType::SignResponse as u8);
            write_string(buffer, signature_blob);
        }
        AgentResponse::Failure => {
            buffer.reserve(1);
            buffer.put_u8(MessageType::Failure as u8);
        }
        AgentResponse::Success => {
            buffer.reserve(1);
            buffer.put_u8(MessageType::Success as u8);
        }
    }
}

pub fn encode_response_frame_into(response: &AgentResponse, buffer: &mut BytesMut) -> Result<()> {
    buffer.clear();
    let payload_cap = match response {
        AgentResponse::IdentitiesAnswer { identities } => {
            let mut cap = 1 + 4;
            for identity in identities {
                cap += 4 + identity.key_blob.len();
                cap += 4 + identity.comment.len();
            }
            cap
        }
        AgentResponse::SignResponse { signature_blob } => 1 + 4 + signature_blob.len(),
        AgentResponse::Failure | AgentResponse::Success => 1,
    };
    if payload_cap > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(payload_cap));
    }
    buffer.reserve(4 + payload_cap);
    buffer.put_u32(payload_cap as u32);
    match response {
        AgentResponse::Failure => buffer.put_u8(MessageType::Failure as u8),
        AgentResponse::Success => buffer.put_u8(MessageType::Success as u8),
        AgentResponse::IdentitiesAnswer { identities } => {
            buffer.put_u8(MessageType::IdentitiesAnswer as u8);
            buffer.put_u32(identities.len() as u32);
            for identity in identities {
                write_string(buffer, &identity.key_blob);
                write_string(buffer, identity.comment.as_bytes());
            }
        }
        AgentResponse::SignResponse { signature_blob } => {
            buffer.put_u8(MessageType::SignResponse as u8);
            write_string(buffer, signature_blob);
        }
    }
    debug_assert_eq!(buffer.len(), 4 + payload_cap);
    Ok(())
}

pub fn encode_request(request: &AgentRequest) -> Bytes {
    let mut buf = match request {
        AgentRequest::RequestIdentities => BytesMut::with_capacity(1),
        AgentRequest::SignRequest { key_blob, data, .. } => {
            BytesMut::with_capacity(1 + 4 + key_blob.len() + 4 + data.len() + 4)
        }
        AgentRequest::Unknown { payload, .. } => BytesMut::with_capacity(1 + payload.len()),
    };
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

pub fn encode_request_frame(request: &AgentRequest) -> Result<Bytes> {
    let mut buffer = BytesMut::new();
    encode_request_frame_into(request, &mut buffer)?;
    Ok(buffer.freeze())
}

pub fn encode_request_into(request: &AgentRequest, buffer: &mut BytesMut) {
    buffer.clear();
    match request {
        AgentRequest::RequestIdentities => {
            buffer.reserve(1);
            buffer.put_u8(MessageType::RequestIdentities as u8);
        }
        AgentRequest::SignRequest { key_blob, data, flags } => {
            buffer.reserve(1 + 4 + key_blob.len() + 4 + data.len() + 4);
            buffer.put_u8(MessageType::SignRequest as u8);
            write_string(buffer, key_blob);
            write_string(buffer, data);
            buffer.put_u32(*flags);
        }
        AgentRequest::Unknown { message_type, payload } => {
            buffer.reserve(1 + payload.len());
            buffer.put_u8(*message_type);
            buffer.put_slice(payload);
        }
    }
}

pub fn encode_request_frame_into(request: &AgentRequest, buffer: &mut BytesMut) -> Result<()> {
    buffer.clear();
    let payload_cap = match request {
        AgentRequest::RequestIdentities => 1,
        AgentRequest::SignRequest { key_blob, data, .. } => {
            1 + 4 + key_blob.len() + 4 + data.len() + 4
        }
        AgentRequest::Unknown { payload, .. } => 1 + payload.len(),
    };
    if payload_cap > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(payload_cap));
    }
    buffer.reserve(4 + payload_cap);
    buffer.put_u32(payload_cap as u32);
    match request {
        AgentRequest::RequestIdentities => buffer.put_u8(MessageType::RequestIdentities as u8),
        AgentRequest::SignRequest { key_blob, data, flags } => {
            buffer.put_u8(MessageType::SignRequest as u8);
            write_string(buffer, key_blob);
            write_string(buffer, data);
            buffer.put_u32(*flags);
        }
        AgentRequest::Unknown { message_type, payload } => {
            buffer.put_u8(*message_type);
            buffer.put_slice(payload);
        }
    }
    debug_assert_eq!(buffer.len(), 4 + payload_cap);
    Ok(())
}

pub fn encode_signature_blob(algorithm: &str, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + algorithm.len() + signature.len());
    out.extend_from_slice(&(algorithm.len() as u32).to_be_bytes());
    out.extend_from_slice(algorithm.as_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(signature);
    out
}

fn read_string<B: Buf>(buf: &mut B) -> Result<Vec<u8>> {
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
    let mut data = vec![0u8; len];
    buf.copy_to_slice(&mut data);
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
    fn encode_response_into_matches() {
        let response = AgentResponse::SignResponse {
            signature_blob: vec![7, 8, 9],
        };
        let mut buffer = BytesMut::new();
        encode_response_into(&response, &mut buffer);
        assert_eq!(buffer.freeze(), encode_response(&response));
    }

    #[test]
    fn encode_response_frame_prefix() {
        let response = AgentResponse::Failure;
        let framed = encode_response_frame(&response).expect("frame");
        let mut buf = Bytes::from(framed);
        let len = buf.get_u32() as usize;
        assert_eq!(len, 1);
        assert_eq!(buf.get_u8(), MessageType::Failure as u8);
    }

    #[test]
    fn encode_response_frame_into_prefix() {
        let response = AgentResponse::Failure;
        let mut buffer = BytesMut::new();
        encode_response_frame_into(&response, &mut buffer).expect("frame");
        let mut buf = buffer.freeze();
        let len = buf.get_u32() as usize;
        assert_eq!(len, 1);
        assert_eq!(buf.get_u8(), MessageType::Failure as u8);
    }

    #[test]
    fn encode_request_frame_prefix() {
        let request = AgentRequest::RequestIdentities;
        let framed = encode_request_frame(&request).expect("frame");
        let mut buf = Bytes::from(framed);
        let len = buf.get_u32() as usize;
        assert_eq!(len, 1);
        assert_eq!(buf.get_u8(), MessageType::RequestIdentities as u8);
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
    fn encode_request_into_matches() {
        let request = AgentRequest::SignRequest {
            key_blob: vec![1, 2],
            data: vec![3, 4, 5],
            flags: 7,
        };
        let mut buffer = BytesMut::new();
        encode_request_into(&request, &mut buffer);
        assert_eq!(buffer.freeze(), encode_request(&request));
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

    #[tokio::test]
    async fn read_response_with_buffer_roundtrip() {
        let response = AgentResponse::Failure;
        let encoded = encode_response(&response);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        frame.extend_from_slice(&encoded);

        let mut cursor = std::io::Cursor::new(frame);
        let mut buffer = BytesMut::new();
        let decoded = read_response_with_buffer(&mut cursor, &mut buffer).await.unwrap();
        assert!(matches!(decoded, AgentResponse::Failure));
    }

    #[tokio::test]
    async fn read_response_type_with_buffer_skips_payload() {
        let payload_len = 2048usize;
        let mut frame = Vec::with_capacity(4 + payload_len);
        frame.extend_from_slice(&(payload_len as u32).to_be_bytes());
        frame.push(MessageType::Failure as u8);
        frame.extend(std::iter::repeat(0u8).take(payload_len - 1));

        let mut cursor = std::io::Cursor::new(frame);
        let mut buffer = BytesMut::new();
        let message_type = read_response_type_with_buffer(&mut cursor, &mut buffer)
            .await
            .unwrap();
        assert_eq!(message_type, MessageType::Failure as u8);
    }
}
