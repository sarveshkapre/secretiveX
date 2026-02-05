#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("key not found")]
    KeyNotFound,
    #[error("invalid key data")]
    InvalidKey,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(&'static str),
    #[error("internal error: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyIdentity {
    pub key_blob: Vec<u8>,
    pub comment: String,
    pub source: String,
}

pub trait KeyStore: Send + Sync {
    fn list_identities(&self) -> Result<Vec<KeyIdentity>>;
    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>>;
    fn store_kind(&self) -> &'static str {
        "unknown"
    }
}
