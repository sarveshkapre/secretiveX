use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use directories::BaseDirs;
use ssh_key::{Algorithm, HashAlg, PrivateKey};

use crate::{CoreError, KeyIdentity, KeyStore, Result};

const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Clone, Debug)]
pub struct FileStoreConfig {
    pub paths: Vec<PathBuf>,
    pub scan_default_dir: bool,
}

impl Default for FileStoreConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            scan_default_dir: true,
        }
    }
}

#[derive(Clone)]
pub struct FileStore {
    entries: Arc<DashMap<Vec<u8>, Arc<KeyEntry>>>,
    config: Arc<FileStoreConfig>,
}

#[derive(Debug)]
struct KeyEntry {
    private_key: PrivateKey,
    identity: KeyIdentity,
}

impl FileStore {
    pub fn load(config: FileStoreConfig) -> Result<Self> {
        let entries = load_entries(&config)?;
        Ok(Self {
            entries: Arc::new(entries),
            config: Arc::new(config),
        })
    }

    pub fn load_default() -> Result<Self> {
        Self::load(FileStoreConfig::default())
    }

    pub fn reload(&self) -> Result<()> {
        let entries = load_entries(&self.config)?;
        self.entries.clear();
        for entry in entries.into_iter() {
            self.entries.insert(entry.0, entry.1);
        }
        Ok(())
    }

    pub fn watch_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(self.config.paths.iter().cloned());

        if self.config.scan_default_dir {
            if let Some(dir) = default_ssh_dir() {
                paths.push(dir);
            }
        }

        paths
    }
}

impl KeyStore for FileStore {
    fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        let mut identities = Vec::with_capacity(self.entries.len());
        for entry in self.entries.iter() {
            identities.push(entry.value().identity.clone());
        }
        Ok(identities)
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(key_blob)
            .ok_or(CoreError::KeyNotFound)?
            .value()
            .clone();

        let key_data = entry.private_key.key_data();

        let signature = if let Some(rsa) = key_data.rsa() {
            sign_rsa(rsa, data, flags)?
        } else {
            use signature::Signer;
            entry
                .private_key
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("sign failed"))?
        };

        let signature_blob = secretive_proto::encode_signature_blob(
            signature.algorithm().as_str(),
            signature.as_bytes(),
        );
        Ok(signature_blob)
    }
}

fn discover_private_keys(ssh_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    let entries = match std::fs::read_dir(ssh_dir) {
        Ok(entries) => entries,
        Err(_) => return candidates,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if filename.ends_with(".pub") {
            continue;
        }
        if matches!(
            filename,
            "known_hosts" | "authorized_keys" | "config" | "known_hosts.old"
        ) {
            continue;
        }

        candidates.push(path);
    }

    candidates
}

fn load_entries(config: &FileStoreConfig) -> Result<DashMap<Vec<u8>, Arc<KeyEntry>>> {
    let mut candidates = VecDeque::new();
    candidates.extend(config.paths.iter().cloned());

    if config.scan_default_dir {
        if let Some(ssh_dir) = default_ssh_dir() {
            candidates.extend(discover_private_keys(&ssh_dir));
        }
    }

    let entries = DashMap::new();
    let mut seen = BTreeSet::new();

    while let Some(path) = candidates.pop_front() {
        let canonical = match path.canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }

        if canonical.is_dir() {
            for child in discover_private_keys(&canonical) {
                candidates.push_back(child);
            }
            continue;
        }

        let private_key = match PrivateKey::read_openssh_file(&canonical) {
            Ok(key) => key,
            Err(_) => continue,
        };

        if private_key.is_encrypted() {
            continue;
        }

        let public_key = private_key.public_key();
        let key_blob = public_key
            .to_bytes()
            .map_err(|_| CoreError::InvalidKey)?;

        let comment = public_key.comment().to_string();
        let comment = if comment.is_empty() {
            canonical
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            comment
        };

        let identity = KeyIdentity {
            key_blob: key_blob.clone(),
            comment,
            source: canonical.display().to_string(),
        };

        let entry = Arc::new(KeyEntry {
            private_key,
            identity,
        });

        entries.insert(key_blob, entry);
    }

    Ok(entries)
}

fn default_ssh_dir() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| base_dirs.home_dir().join(".ssh"))
}

fn sign_rsa(
    keypair: &ssh_key::private::RsaKeypair,
    data: &[u8],
    flags: u32,
) -> Result<ssh_key::Signature> {
    use rsa::pkcs1v15::SigningKey;
    use sha2::{Sha256, Sha512};
    use signature::{SignatureEncoding, Signer};

    let use_sha512 = flags & SSH_AGENT_RSA_SHA2_512 != 0;
    if !use_sha512 {
        let signing_key = SigningKey::<Sha256>::try_from(keypair)
            .map_err(|_| CoreError::Crypto("rsa signing key"))?;
        let signature = signing_key
            .try_sign(data)
            .map_err(|_| CoreError::Crypto("rsa sha256 sign"))?
            .to_vec();
        return Ok(ssh_key::Signature::new(
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            signature,
        )
        .map_err(|_| CoreError::Crypto("rsa sha256 signature"))?);
    }

    let signing_key = SigningKey::<Sha512>::try_from(keypair)
        .map_err(|_| CoreError::Crypto("rsa signing key"))?;
    let signature = signing_key
        .try_sign(data)
        .map_err(|_| CoreError::Crypto("rsa sha512 sign"))?
        .to_vec();

    Ok(ssh_key::Signature::new(
        Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
        signature,
    )
    .map_err(|_| CoreError::Crypto("rsa sha512 signature"))?)
}

// signature encoding delegated to secretive-proto

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    #[test]
    fn load_identity_from_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("id_ed25519");
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("key");
        key.write_openssh_file(&path, LineEnding::LF).expect("write");

        let store = FileStore::load(FileStoreConfig {
            paths: vec![path],
            scan_default_dir: false,
        })
        .expect("store");

        let identities = store.list_identities().expect("identities");
        assert_eq!(identities.len(), 1);
    }
}
