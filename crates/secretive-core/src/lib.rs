use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("key not found")]
    KeyNotFound,
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
}

#[derive(Default)]
pub struct KeyStoreRegistry {
    stores: Vec<Arc<dyn KeyStore>>,
}

impl KeyStoreRegistry {
    pub fn new() -> Self {
        Self { stores: Vec::new() }
    }

    pub fn register(&mut self, store: Arc<dyn KeyStore>) {
        self.stores.push(store);
    }

    pub fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        let mut out = Vec::new();
        for store in &self.stores {
            out.extend(store.list_identities()?);
        }
        Ok(out)
    }

    pub fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        for store in &self.stores {
            match store.sign(key_blob, data, flags) {
                Ok(sig) => return Ok(sig),
                Err(CoreError::KeyNotFound) => continue,
                Err(err) => return Err(err),
            }
        }
        Err(CoreError::KeyNotFound)
    }
}

pub struct EmptyStore;

impl KeyStore for EmptyStore {
    fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        Ok(Vec::new())
    }

    fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        Err(CoreError::KeyNotFound)
    }
}
