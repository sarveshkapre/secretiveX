use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    RequestIdentities = 11,
    IdentitiesAnswer = 12,
    SignRequest = 13,
    SignResponse = 14,
    Failure = 5,
    Success = 6,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub enum AgentRequest {
    RequestIdentities,
    SignRequest {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    Unknown {
        message_type: u8,
        payload: Bytes,
    },
}

#[derive(Debug, Clone)]
pub enum AgentResponse {
    Failure,
    Success,
    IdentitiesAnswer { identities: Vec<Identity> },
    SignResponse { signature_blob: Vec<u8> },
}
