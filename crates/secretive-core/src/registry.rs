use std::sync::Arc;

use dashmap::DashMap;

use crate::{CoreError, KeyIdentity, KeyStore, Result};

#[derive(Default)]
pub struct KeyStoreRegistry {
    stores: Vec<Arc<dyn KeyStore>>,
    index: DashMap<Vec<u8>, Arc<dyn KeyStore>>,
}

impl KeyStoreRegistry {
    pub fn new() -> Self {
        Self {
            stores: Vec::new(),
            index: DashMap::new(),
        }
    }

    pub fn register(&mut self, store: Arc<dyn KeyStore>) {
        if let Ok(identities) = store.list_identities() {
            for identity in identities {
                self.index.insert(identity.key_blob, store.clone());
            }
        }
        self.stores.push(store);
    }

    pub fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        let mut out = Vec::new();
        for store in &self.stores {
            let identities = store.list_identities()?;
            for identity in &identities {
                self.index.insert(identity.key_blob.clone(), store.clone());
            }
            out.extend(identities);
        }
        Ok(out)
    }

    pub fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        if let Some(store) = self.index.get(key_blob) {
            if let Ok(sig) = store.sign(key_blob, data, flags) {
                return Ok(sig);
            }
        }

        for store in &self.stores {
            match store.sign(key_blob, data, flags) {
                Ok(sig) => {
                    self.index.insert(key_blob.to_vec(), store.clone());
                    return Ok(sig);
                }
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
