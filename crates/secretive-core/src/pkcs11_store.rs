use std::path::PathBuf;
#[cfg(not(feature = "pkcs11"))]
use std::sync::Arc;

#[cfg(not(feature = "pkcs11"))]
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

    fn store_kind(&self) -> &'static str {
        "pkcs11"
    }
}

#[cfg(feature = "pkcs11")]
mod enabled {
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::sync::Arc;

    use crate::{CoreError, KeyIdentity, KeyStore, Result};
    use ahash::RandomState;
    use arc_swap::ArcSwap;
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use ssh_key::{public::KeyData, PublicKey};

    const SSH_AGENT_RSA_SHA2_256: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_256;
    const SSH_AGENT_RSA_SHA2_512: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_512;
    const SSH_AGENT_OLD_SIGNATURE: u32 = 1;

    use super::Pkcs11Config;

    #[derive(Clone)]
    pub struct Pkcs11Store {
        context: Arc<Pkcs11>,
        slot: Slot,
        pin: Option<String>,
        key_map: Arc<ArcSwap<HashMap<Vec<u8>, Pkcs11Key, RandomState>>>,
        refresh_lock: Arc<std::sync::Mutex<()>>,
    }

    #[derive(Clone)]
    struct Pkcs11Key {
        key_handle: cryptoki::object::ObjectHandle,
        label: String,
    }

    impl Pkcs11Store {
        pub fn load(config: Pkcs11Config) -> Result<Self> {
            let pin = config.pin();
            let slot_override = config.slot;
            let module_path = config.module_path;
            let context =
                Pkcs11::new(module_path).map_err(|_| CoreError::Internal("pkcs11 init"))?;
            context
                .initialize(CInitializeArgs::OsThreads)
                .map_err(|_| CoreError::Internal("pkcs11 initialize"))?;

            let slots = context
                .get_slots_with_token()
                .map_err(|_| CoreError::Internal("pkcs11 slots"))?;
            let slot = if let Some(slot_id) = slot_override {
                Slot::try_from(slot_id).map_err(|_| CoreError::Internal("pkcs11 slot"))?
            } else {
                *slots.first().ok_or(CoreError::Internal("pkcs11 no slot"))?
            };

            let store = Self {
                context: Arc::new(context),
                slot,
                pin,
                key_map: Arc::new(ArcSwap::from_pointee(HashMap::with_hasher(
                    RandomState::new(),
                ))),
                refresh_lock: Arc::new(std::sync::Mutex::new(())),
            };

            store.refresh_keys_serialized()?;
            Ok(store)
        }

        fn open_session(&self) -> Result<Session> {
            let session = self
                .context
                .open_rw_session(self.slot)
                .map_err(|_| CoreError::Internal("pkcs11 open session"))?;

            if let Some(pin) = &self.pin {
                let pin = AuthPin::new(pin.clone().into());
                let _ = session.login(UserType::User, Some(&pin));
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
                        &[
                            AttributeType::Modulus,
                            AttributeType::PublicExponent,
                            AttributeType::Label,
                        ],
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
                    key_blob,
                    Pkcs11Key {
                        key_handle: private_key,
                        label,
                    },
                );
            }

            self.key_map.store(Arc::new(map));
            Ok(())
        }

        fn refresh_keys_serialized(&self) -> Result<()> {
            let _guard = self
                .refresh_lock
                .lock()
                .map_err(|_| CoreError::Internal("pkcs11 refresh lock"))?;
            self.refresh_keys()
        }
    }

    impl KeyStore for Pkcs11Store {
        fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
            self.refresh_keys_serialized()?;
            let guard = self.key_map.load();
            let mut identities = Vec::with_capacity(guard.len());
            for (key_blob, value) in guard.iter() {
                identities.push(KeyIdentity {
                    key_blob: key_blob.clone(),
                    comment: value.label.clone(),
                    source: "pkcs11".to_string(),
                });
            }
            Ok(identities)
        }

        fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
            let key_handle = if let Some(entry) = self.key_map.load().get(key_blob) {
                entry.key_handle
            } else {
                self.refresh_keys_serialized()?;
                self.key_map
                    .load()
                    .get(key_blob)
                    .map(|entry| entry.key_handle)
                    .ok_or(CoreError::KeyNotFound)?
            };

            let session = self.open_session()?;

            let selected = flags & (SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512);
            let (mechanism, algorithm) = if selected & SSH_AGENT_RSA_SHA2_512 != 0 {
                (Mechanism::Sha512RsaPkcs, "rsa-sha2-512")
            } else if selected & SSH_AGENT_RSA_SHA2_256 != 0 {
                (Mechanism::Sha256RsaPkcs, "rsa-sha2-256")
            } else if flags & SSH_AGENT_OLD_SIGNATURE != 0 {
                (Mechanism::Sha1RsaPkcs, "ssh-rsa")
            } else {
                (Mechanism::Sha256RsaPkcs, "rsa-sha2-256")
            };

            let signature = session
                .sign(&mechanism, key_handle, data)
                .map_err(|_| CoreError::Crypto("pkcs11 sign"))?;

            Ok(secretive_proto::encode_signature_blob(
                algorithm, &signature,
            ))
        }

        fn store_kind(&self) -> &'static str {
            "pkcs11"
        }
    }

    fn build_rsa_key_blob(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
        let rsa = ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(exponent).map_err(|_| CoreError::InvalidKey)?,
            n: ssh_key::Mpint::from_positive_bytes(modulus).map_err(|_| CoreError::InvalidKey)?,
        };
        let key_data = KeyData::Rsa(rsa);
        let public_key = PublicKey::from(key_data);
        public_key.to_bytes().map_err(|_| CoreError::InvalidKey)
    }

    fn find_private_key(
        session: &Session,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<cryptoki::object::ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Modulus(modulus.to_vec()),
            Attribute::PublicExponent(exponent.to_vec()),
        ];

        let mut objects = session
            .find_objects(&template)
            .map_err(|_| CoreError::Internal("pkcs11 find private"))?;

        objects.pop().ok_or(CoreError::KeyNotFound)
    }

    // signature encoding delegated to secretive-proto

}

#[cfg(feature = "pkcs11")]
pub use enabled::Pkcs11Store;
