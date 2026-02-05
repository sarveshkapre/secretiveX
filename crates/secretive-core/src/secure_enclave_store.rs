use crate::{CoreError, KeyIdentity, KeyStore, Result};

#[derive(Clone)]
pub struct SecureEnclaveStore;

impl SecureEnclaveStore {
    pub fn load() -> Result<Self> {
        Err(CoreError::Unsupported(
            "secure enclave store not yet implemented",
        ))
    }
}

impl KeyStore for SecureEnclaveStore {
    fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        Err(CoreError::Unsupported(
            "secure enclave store not yet implemented",
        ))
    }

    fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        Err(CoreError::Unsupported(
            "secure enclave store not yet implemented",
        ))
    }
}
