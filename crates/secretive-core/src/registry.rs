use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::{CoreError, KeyIdentity, KeyStore, Result};

#[derive(Default)]
pub struct KeyStoreRegistry {
    stores: Vec<Arc<dyn KeyStore>>,
    index: ArcSwap<DashMap<Vec<u8>, Arc<dyn KeyStore>>>,
}

impl KeyStoreRegistry {
    pub fn new() -> Self {
        Self {
            stores: Vec::new(),
            index: ArcSwap::from_pointee(DashMap::new()),
        }
    }

    pub fn register(&mut self, store: Arc<dyn KeyStore>) {
        if let Ok(identities) = store.list_identities() {
            let index = self.index.load();
            for identity in identities {
                index.insert(identity.key_blob, store.clone());
            }
        }
        self.stores.push(store);
    }

    pub fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        let mut out = Vec::new();
        let mut new_index: DashMap<Vec<u8>, Arc<dyn KeyStore>> = DashMap::new();
        let mut last_err = None;
        let mut any_ok = false;
        for store in &self.stores {
            match store.list_identities() {
                Ok(identities) => {
                    any_ok = true;
                    out.reserve(identities.len());
                    let _ = new_index.try_reserve(identities.len());
                    for identity in &identities {
                        new_index.insert(identity.key_blob.clone(), store.clone());
                    }
                    out.extend(identities);
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        if !any_ok {
            return Err(last_err.unwrap_or(CoreError::Internal("no key stores")));
        }
        self.index.store(Arc::new(new_index));
        if out.len() > 1 {
            out.sort_by(|a, b| {
                let comment = a.comment.cmp(&b.comment);
                if comment == std::cmp::Ordering::Equal {
                    a.key_blob.cmp(&b.key_blob)
                } else {
                    comment
                }
            });
        }
        Ok(out)
    }

    pub fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let index = self.index.load();
        if let Some(store) = index.get(key_blob).map(|entry| entry.value().clone()) {
            match store.sign(key_blob, data, flags) {
                Ok(sig) => return Ok(sig),
                Err(CoreError::KeyNotFound) => {
                    index.remove(key_blob);
                }
                Err(err) => return Err(err),
            }
        }

        for store in &self.stores {
            match store.sign(key_blob, data, flags) {
                Ok(sig) => {
                    self.index.load().insert(key_blob.to_vec(), store.clone());
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStore {
        identities: Vec<KeyIdentity>,
    }

    impl KeyStore for TestStore {
        fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
            Ok(self.identities.clone())
        }

        fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>> {
            Err(CoreError::KeyNotFound)
        }
    }

    #[test]
    fn identities_are_sorted() {
        let store_a = Arc::new(TestStore {
            identities: vec![KeyIdentity {
                key_blob: vec![2],
                comment: "b".into(),
                source: "a".into(),
            }],
        });
        let store_b = Arc::new(TestStore {
            identities: vec![KeyIdentity {
                key_blob: vec![1],
                comment: "a".into(),
                source: "b".into(),
            }],
        });

        let mut registry = KeyStoreRegistry::new();
        registry.register(store_a);
        registry.register(store_b);

        let identities = registry.list_identities().expect("identities");
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].comment, "a");
        assert_eq!(identities[1].comment, "b");
    }
}
