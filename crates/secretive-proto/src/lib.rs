mod codec;
mod message;

pub use codec::{decode_request, encode_response, read_request, write_response, MAX_FRAME_LEN};
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
