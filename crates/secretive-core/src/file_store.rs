use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::RandomState;
use arc_swap::ArcSwap;
use directories::BaseDirs;
use sha1::Sha1;
use ssh_key::PrivateKey;

use crate::{CoreError, KeyIdentity, KeyStore, Result};

type EntryMap = HashMap<Vec<u8>, Arc<KeyEntry>, RandomState>;
type PathSet = HashSet<PathBuf, RandomState>;

const SSH_AGENT_RSA_SHA2_256: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_256;
const SSH_AGENT_RSA_SHA2_512: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_512;
const SSH_AGENT_OLD_SIGNATURE: u32 = 1;

#[derive(Clone, Copy)]
enum RsaSignAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

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
    entries: Arc<ArcSwap<EntryMap>>,
    config: Arc<FileStoreConfig>,
}

#[derive(Debug)]
struct KeyEntry {
    private_key: PrivateKey,
    comment: String,
    source: String,
    rsa_signers: Option<Arc<RsaSigners>>,
}

#[derive(Clone, Debug)]
struct RsaSigners {
    sha1: Option<rsa::pkcs1v15::SigningKey<Sha1>>,
    sha256: rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    sha512: rsa::pkcs1v15::SigningKey<sha2::Sha512>,
}

impl RsaSigners {
    fn new(keypair: &ssh_key::private::RsaKeypair) -> Result<Self> {
        let sha1 = rsa::pkcs1v15::SigningKey::<Sha1>::try_from(keypair).ok();
        let sha256 = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::try_from(keypair)
            .map_err(|_| CoreError::Crypto("rsa sha256 signing key"))?;
        let sha512 = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::try_from(keypair)
            .map_err(|_| CoreError::Crypto("rsa sha512 signing key"))?;
        Ok(Self {
            sha1,
            sha256,
            sha512,
        })
    }
}

impl FileStore {
    pub fn load(config: FileStoreConfig) -> Result<Self> {
        let entries = load_entries(&config)?;
        Ok(Self {
            entries: Arc::new(ArcSwap::from_pointee(entries)),
            config: Arc::new(config),
        })
    }

    pub fn load_default() -> Result<Self> {
        Self::load(FileStoreConfig::default())
    }

    pub fn reload(&self) -> Result<()> {
        let entries = load_entries(&self.config)?;
        self.entries.store(Arc::new(entries));
        Ok(())
    }

    pub fn watch_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::with_capacity(self.config.paths.len().saturating_add(1));
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
        let entries = self.entries.load();
        let mut identities = Vec::with_capacity(entries.len());
        for (key_blob, entry) in entries.iter() {
            identities.push(KeyIdentity {
                key_blob: key_blob.clone(),
                comment: entry.comment.clone(),
                source: entry.source.clone(),
            });
        }
        Ok(identities)
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let entries = self.entries.load();
        let entry = entries.get(key_blob).ok_or(CoreError::KeyNotFound)?;
        let entry = entry.as_ref();

        let signature_blob = if let Some(signers) = entry.rsa_signers.as_ref() {
            sign_rsa_with_signers(signers, data, flags)?
        } else if let Some(rsa) = entry.private_key.key_data().rsa() {
            sign_rsa(rsa, data, flags)?
        } else {
            use signature::Signer;
            let signature = entry
                .private_key
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("sign failed"))?;
            secretive_proto::encode_signature_blob(
                signature.algorithm().as_str(),
                signature.as_bytes(),
            )
        };

        Ok(signature_blob)
    }

    fn store_kind(&self) -> &'static str {
        "file"
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
        if let Ok(file_type) = entry.file_type() {
            if !(file_type.is_file() || file_type.is_symlink()) {
                continue;
            }
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

fn load_entries(config: &FileStoreConfig) -> Result<EntryMap> {
    let mut candidates = VecDeque::with_capacity(config.paths.len().saturating_add(1));
    candidates.extend(config.paths.iter().cloned());

    if config.scan_default_dir {
        if let Some(ssh_dir) = default_ssh_dir() {
            candidates.extend(discover_private_keys(&ssh_dir));
        }
    }

    let mut entries = HashMap::with_capacity_and_hasher(candidates.len(), RandomState::new());
    let mut seen: PathSet = HashSet::with_capacity_and_hasher(candidates.len(), RandomState::new());

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
        let key_blob = public_key.to_bytes().map_err(|_| CoreError::InvalidKey)?;

        let comment = public_key.comment();
        let comment = if comment.is_empty() {
            canonical
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            comment.to_string()
        };

        let source = canonical.to_string_lossy().into_owned();

        let rsa_signers = match private_key.key_data().rsa() {
            Some(rsa) => match RsaSigners::new(rsa) {
                Ok(signers) => Some(Arc::new(signers)),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        path = %canonical.display(),
                        "failed to precompute RSA signers"
                    );
                    None
                }
            },
            None => None,
        };

        let entry = Arc::new(KeyEntry {
            private_key,
            comment,
            source,
            rsa_signers,
        });

        entries.insert(key_blob, entry);
    }

    Ok(entries)
}

fn default_ssh_dir() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| base_dirs.home_dir().join(".ssh"))
}

fn rsa_sign_algorithm(flags: u32) -> RsaSignAlgorithm {
    let selected = flags & (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512);
    if selected & SSH_AGENT_RSA_SHA2_512 != 0 {
        RsaSignAlgorithm::Sha512
    } else if selected & SSH_AGENT_RSA_SHA2_256 != 0 {
        RsaSignAlgorithm::Sha256
    } else if flags & SSH_AGENT_OLD_SIGNATURE != 0 {
        RsaSignAlgorithm::Sha1
    } else {
        // Prefer SHA-256 by default for modern OpenSSH compatibility.
        RsaSignAlgorithm::Sha256
    }
}

fn sign_rsa(keypair: &ssh_key::private::RsaKeypair, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};
    use signature::{SignatureEncoding, Signer};

    let (algorithm, signature) = match rsa_sign_algorithm(flags) {
        RsaSignAlgorithm::Sha512 => {
            let signing_key = SigningKey::<Sha512>::try_from(keypair)
                .map_err(|_| CoreError::Crypto("rsa signing key"))?;
            let signature = signing_key
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("rsa sha512 sign"))?
                .to_bytes();
            ("rsa-sha2-512", signature)
        }
        RsaSignAlgorithm::Sha256 => {
            let signing_key = SigningKey::<Sha256>::try_from(keypair)
                .map_err(|_| CoreError::Crypto("rsa signing key"))?;
            let signature = signing_key
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("rsa sha256 sign"))?
                .to_bytes();
            ("rsa-sha2-256", signature)
        }
        RsaSignAlgorithm::Sha1 => match SigningKey::<Sha1>::try_from(keypair) {
            Ok(signing_key) => {
                let signature = signing_key
                    .try_sign(data)
                    .map_err(|_| CoreError::Crypto("rsa sha1 sign"))?
                    .to_bytes();
                ("ssh-rsa", signature)
            }
            Err(_) => {
                let signing_key = SigningKey::<Sha256>::try_from(keypair)
                    .map_err(|_| CoreError::Crypto("rsa signing key"))?;
                let signature = signing_key
                    .try_sign(data)
                    .map_err(|_| CoreError::Crypto("rsa sha256 sign"))?
                    .to_bytes();
                ("rsa-sha2-256", signature)
            }
        },
    };

    Ok(secretive_proto::encode_signature_blob(
        algorithm,
        signature.as_ref(),
    ))
}

fn sign_rsa_with_signers(signers: &RsaSigners, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    use signature::{SignatureEncoding, Signer};

    let (algorithm, signature) = match rsa_sign_algorithm(flags) {
        RsaSignAlgorithm::Sha512 => (
            "rsa-sha2-512",
            signers
                .sha512
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("rsa sha512 sign"))?
                .to_bytes(),
        ),
        RsaSignAlgorithm::Sha256 => (
            "rsa-sha2-256",
            signers
                .sha256
                .try_sign(data)
                .map_err(|_| CoreError::Crypto("rsa sha256 sign"))?
                .to_bytes(),
        ),
        RsaSignAlgorithm::Sha1 => {
            if let Some(sha1) = signers.sha1.as_ref() {
                (
                    "ssh-rsa",
                    sha1.try_sign(data)
                        .map_err(|_| CoreError::Crypto("rsa sha1 sign"))?
                        .to_bytes(),
                )
            } else {
                (
                    "rsa-sha2-256",
                    signers
                        .sha256
                        .try_sign(data)
                        .map_err(|_| CoreError::Crypto("rsa sha256 sign"))?
                        .to_bytes(),
                )
            }
        }
    };

    Ok(secretive_proto::encode_signature_blob(
        algorithm,
        signature.as_ref(),
    ))
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
        key.write_openssh_file(&path, LineEnding::LF)
            .expect("write");

        let store = FileStore::load(FileStoreConfig {
            paths: vec![path],
            scan_default_dir: false,
        })
        .expect("store");

        let identities = store.list_identities().expect("identities");
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn rsa_flags_prefer_sha512_when_both_set() {
        assert!(matches!(rsa_sign_algorithm(0), RsaSignAlgorithm::Sha256));
        assert!(matches!(
            rsa_sign_algorithm(SSH_AGENT_OLD_SIGNATURE),
            RsaSignAlgorithm::Sha1
        ));
        assert!(matches!(
            rsa_sign_algorithm(SSH_AGENT_RSA_SHA2_256),
            RsaSignAlgorithm::Sha256
        ));
        assert!(matches!(
            rsa_sign_algorithm(SSH_AGENT_RSA_SHA2_512),
            RsaSignAlgorithm::Sha512
        ));
        assert!(matches!(
            rsa_sign_algorithm(SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512),
            RsaSignAlgorithm::Sha512
        ));
    }
}
