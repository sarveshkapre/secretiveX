mod codec;
mod message;

pub use codec::{
    decode_request, decode_response, encode_request, encode_response, encode_signature_blob,
    read_request, read_request_with_buffer, read_response, read_response_with_buffer, write_request,
    write_response,
    MAX_FRAME_LEN,
};
pub use message::{AgentRequest, AgentResponse, Identity, MessageType};

pub type Result<T> = std::result::Result<T, ProtoError>;

#[derive(thiserror::Error, Debug)]
pub enum ProtoError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("unexpected end of frame")]
    UnexpectedEof,
    #[error("invalid message: {0}")]
    InvalidMessage(&'static str),
}
