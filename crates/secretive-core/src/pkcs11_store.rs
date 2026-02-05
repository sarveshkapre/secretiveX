use std::path::PathBuf;
use std::sync::Arc;

use crate::{CoreError, KeyIdentity, KeyStore, Result};

#[derive(Clone, Debug)]
pub struct Pkcs11Config {
    pub module_path: PathBuf,
    pub slot: Option<u64>,
    pub pin_env: Option<String>,
}

impl Pkcs11Config {
    pub fn pin(&self) -> Option<String> {
        self.pin_env
            .as_ref()
            .and_then(|name| std::env::var(name).ok())
    }
}

#[cfg(not(feature = "pkcs11"))]
#[derive(Clone)]
pub struct Pkcs11Store {
    _config: Arc<Pkcs11Config>,
}

#[cfg(not(feature = "pkcs11"))]
impl Pkcs11Store {
    pub fn load(config: Pkcs11Config) -> Result<Self> {
        let _ = config;
        Err(CoreError::Unsupported("pkcs11 feature not enabled"))
    }
}

#[cfg(not(feature = "pkcs11"))]
impl KeyStore for Pkcs11Store {
    fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
        Err(CoreError::Unsupported("pkcs11 feature not enabled"))
    }

    fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        Err(CoreError::Unsupported("pkcs11 feature not enabled"))
    }
}

#[cfg(feature = "pkcs11")]
mod enabled {
    use std::collections::HashMap;
    use std::sync::Arc;

    use ahash::RandomState;
    use arc_swap::ArcSwap;
    use cryptoki::context::{Pkcs11, Pkcs11Flags};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    use cryptoki::session::{Session, SessionFlags, UserType};
    use cryptoki::types::slot::Slot;
    use ssh_key::{public::KeyData, PublicKey};
    use crate::{CoreError, KeyIdentity, KeyStore, Result};

    const SSH_AGENT_RSA_SHA2_256: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_256;
    const SSH_AGENT_RSA_SHA2_512: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_512;

    use super::Pkcs11Config;

    #[derive(Clone)]
    pub struct Pkcs11Store {
        context: Arc<Pkcs11>,
        slot: Slot,
        pin: Option<String>,
        key_map: Arc<ArcSwap<HashMap<Vec<u8>, Pkcs11Key, RandomState>>>,
    }

    #[derive(Clone)]
    struct Pkcs11Key {
        key_handle: cryptoki::object::ObjectHandle,
        key_blob: Vec<u8>,
        label: String,
    }

    impl Pkcs11Store {
        pub fn load(config: Pkcs11Config) -> Result<Self> {
            let context = Pkcs11::new(config.module_path)
                .map_err(|_| CoreError::Internal("pkcs11 init"))?;
            context
                .initialize(Pkcs11Flags::empty())
                .map_err(|_| CoreError::Internal("pkcs11 initialize"))?;

            let slots = context
                .get_slots_with_token()
                .map_err(|_| CoreError::Internal("pkcs11 slots"))?;
            let slot = if let Some(slot_id) = config.slot {
                Slot::from(slot_id)
            } else {
                *slots.first().ok_or(CoreError::Internal("pkcs11 no slot"))?
            };

            let pin = config.pin();
            let store = Self {
                context: Arc::new(context),
                slot,
                pin,
                key_map: Arc::new(ArcSwap::from_pointee(HashMap::with_hasher(RandomState::new()))),
            };

            store.refresh_keys()?;
            Ok(store)
        }

        fn open_session(&self) -> Result<Session> {
            let flags = SessionFlags::SERIAL_SESSION | SessionFlags::RW_SESSION;
            let session = self
                .context
                .open_session_no_callback(self.slot, flags)
                .map_err(|_| CoreError::Internal("pkcs11 open session"))?;

            if let Some(pin) = &self.pin {
                let _ = session.login(UserType::User, Some(pin));
            }

            Ok(session)
        }

        fn refresh_keys(&self) -> Result<()> {
            let session = self.open_session()?;

            let template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Token(true),
            ];

            let objects = session
                .find_objects(&template)
                .map_err(|_| CoreError::Internal("pkcs11 find objects"))?;

            let mut map: HashMap<Vec<u8>, Pkcs11Key, RandomState> =
                HashMap::with_capacity_and_hasher(objects.len(), RandomState::new());

            for object in objects {
                let attributes = session
                    .get_attributes(
                        object,
                        &[AttributeType::Modulus, AttributeType::PublicExponent, AttributeType::Label],
                    )
                    .unwrap_or_default();

                let mut modulus = None;
                let mut exponent = None;
                let mut label = None;
                for attribute in attributes {
                    match attribute {
                        Attribute::Modulus(value) => modulus = Some(value),
                        Attribute::PublicExponent(value) => exponent = Some(value),
                        Attribute::Label(value) => label = Some(value),
                        _ => {}
                    }
                }

                let (modulus, exponent) = match (modulus, exponent) {
                    (Some(n), Some(e)) => (n, e),
                    _ => continue,
                };

                let key_blob = build_rsa_key_blob(&modulus, &exponent)?;
                let label = label
                    .and_then(|value| String::from_utf8(value).ok())
                    .unwrap_or_else(|| "pkcs11-key".to_string());

                let private_key = find_private_key(&session, &modulus, &exponent)?;
                map.insert(
                    key_blob.clone(),
                    Pkcs11Key {
                        key_handle: private_key,
                        key_blob,
                        label,
                    },
                );
            }

            self.key_map.store(Arc::new(map));
            Ok(())
        }
    }

    impl KeyStore for Pkcs11Store {
        fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
            self.refresh_keys()?;
            let guard = self.key_map.load();
            let identities = guard
                .values()
                .map(|entry| KeyIdentity {
                    key_blob: entry.key_blob.clone(),
                    comment: entry.label.clone(),
                    source: "pkcs11".to_string(),
                })
                .collect();
            Ok(identities)
        }

        fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
            let key = self.key_map.load().get(key_blob).cloned();
            let key = if let Some(key) = key {
                key
            } else {
                self.refresh_keys()?;
                self.key_map
                    .load()
                    .get(key_blob)
                    .cloned()
                    .ok_or(CoreError::KeyNotFound)?
            };

            let session = self.open_session()?;

            let mechanism = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                Mechanism::Sha512RsaPkcs
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                Mechanism::Sha256RsaPkcs
            } else {
                Mechanism::Sha1RsaPkcs
            };

            let signature = session
                .sign(&mechanism, key.key_handle, data)
                .map_err(|_| CoreError::Crypto("pkcs11 sign"))?;

            let algorithm = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                "rsa-sha2-512"
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                "rsa-sha2-256"
            } else {
                "ssh-rsa"
            };

            Ok(secretive_proto::encode_signature_blob(algorithm, &signature))
        }
    }

    fn build_rsa_key_blob(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
        let rsa = ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(exponent).map_err(|_| CoreError::InvalidKey)?,
            n: ssh_key::Mpint::from_positive_bytes(modulus).map_err(|_| CoreError::InvalidKey)?,
        };
        let key_data = KeyData::Rsa(rsa);
        let public_key = PublicKey::from(key_data);
        public_key
            .to_bytes()
            .map_err(|_| CoreError::InvalidKey)
    }

    fn find_private_key(session: &Session, modulus: &[u8], exponent: &[u8]) -> Result<cryptoki::object::ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Modulus(modulus.to_vec()),
            Attribute::PublicExponent(exponent.to_vec()),
        ];

        let mut objects = session
            .find_objects(&template)
            .map_err(|_| CoreError::Internal("pkcs11 find private"))?;

        objects
            .pop()
            .ok_or(CoreError::KeyNotFound)
    }

    // signature encoding delegated to secretive-proto

    pub(super) use Pkcs11Store as EnabledPkcs11Store;
}

#[cfg(feature = "pkcs11")]
pub use enabled::EnabledPkcs11Store as Pkcs11Store;
