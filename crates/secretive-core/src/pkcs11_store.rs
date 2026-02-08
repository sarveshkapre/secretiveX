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
    pub refresh_min_interval_ms: Option<u64>,
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{CoreError, KeyIdentity, KeyStore, Result};
    use ahash::RandomState;
    use arc_swap::ArcSwap;
    use cryptoki::context::{CInitializeArgs, Function, Pkcs11};
    use cryptoki::error::{Error as Pkcs11Error, RvError};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use ssh_key::{public::KeyData, PublicKey};

    const SSH_AGENT_RSA_SHA2_256: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_256;
    const SSH_AGENT_RSA_SHA2_512: u32 = secretive_proto::SSH_AGENT_RSA_SHA2_512;
    const SSH_AGENT_OLD_SIGNATURE: u32 = 1;
    const OPEN_SESSION_MAX_ATTEMPTS: usize = 4;
    const REFRESH_KEYS_MAX_ATTEMPTS: usize = 3;
    const SIGN_MAX_ATTEMPTS: usize = 4;
    const SESSION_POOL_WAIT_SPINS: usize = 80;
    const SESSION_POOL_WAIT_MS: u64 = 2;

    use super::Pkcs11Config;

    #[derive(Clone)]
    pub struct Pkcs11Store {
        context: Arc<Pkcs11>,
        slot_override: Option<Slot>,
        active_slot: Arc<AtomicU64>,
        pin: Option<String>,
        key_map: Arc<ArcSwap<HashMap<Vec<u8>, Pkcs11Key, RandomState>>>,
        refresh_lock: Arc<std::sync::Mutex<()>>,
        refresh_min_interval_ms: u64,
        last_refresh_ms: Arc<AtomicU64>,
        session_pool: Arc<std::sync::Mutex<Vec<Session>>>,
        session_total: Arc<AtomicU64>,
        session_pool_max: usize,
    }

    #[derive(Clone)]
    struct Pkcs11Key {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
        label: String,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Pkcs11ErrorClass {
        Retryable,
        KeyChurn,
        Auth,
        Fatal,
    }

    enum SignAttemptError {
        KeyNotFound,
        Pkcs11(Pkcs11Error),
    }

    struct BorrowedSession<'a> {
        store: &'a Pkcs11Store,
        session: Option<Session>,
        broken: bool,
    }

    impl<'a> BorrowedSession<'a> {
        fn new(store: &'a Pkcs11Store, session: Session) -> Self {
            Self {
                store,
                session: Some(session),
                broken: false,
            }
        }

        fn session(&self) -> &Session {
            self.session.as_ref().expect("borrowed session missing")
        }

        fn mark_broken(&mut self) {
            self.broken = true;
        }
    }

    impl Drop for BorrowedSession<'_> {
        fn drop(&mut self) {
            if let Some(session) = self.session.take() {
                self.store.return_session(session, self.broken);
            }
        }
    }

    impl Pkcs11Store {
        pub fn load(config: Pkcs11Config) -> Result<Self> {
            let pin = config.pin();
            let slot_override = config.slot;
            let module_path = config.module_path;
            let refresh_min_interval_ms = config.refresh_min_interval_ms.unwrap_or(250);
            let context =
                Pkcs11::new(module_path).map_err(|_| CoreError::Internal("pkcs11 init"))?;
            context
                .initialize(CInitializeArgs::OsThreads)
                .map_err(|_| CoreError::Internal("pkcs11 initialize"))?;
            let slot_override = slot_override
                .map(Slot::try_from)
                .transpose()
                .map_err(|_| CoreError::Internal("pkcs11 slot"))?;
            let startup_slot = resolve_slot(&context, slot_override)?;
            let session_pool_max = compute_session_pool_max();

            let store = Self {
                context: Arc::new(context),
                slot_override,
                active_slot: Arc::new(AtomicU64::new(startup_slot.id())),
                pin,
                key_map: Arc::new(ArcSwap::from_pointee(HashMap::with_hasher(
                    RandomState::new(),
                ))),
                refresh_lock: Arc::new(std::sync::Mutex::new(())),
                refresh_min_interval_ms,
                last_refresh_ms: Arc::new(AtomicU64::new(0)),
                session_pool: Arc::new(std::sync::Mutex::new(Vec::new())),
                session_total: Arc::new(AtomicU64::new(0)),
                session_pool_max,
            };

            store.refresh_keys_forced()?;
            Ok(store)
        }

        fn current_slot(&self) -> Result<Slot> {
            if let Some(slot) = self.slot_override {
                return Ok(slot);
            }
            let observed = self.active_slot.load(Ordering::Relaxed);
            if observed != 0 {
                if let Ok(slot) = Slot::try_from(observed) {
                    return Ok(slot);
                }
            }
            self.refresh_active_slot()
        }

        fn refresh_active_slot(&self) -> Result<Slot> {
            let slot = resolve_slot(&self.context, self.slot_override)?;
            self.active_slot.store(slot.id(), Ordering::Relaxed);
            Ok(slot)
        }

        fn open_session_on_slot(&self, slot: Slot) -> std::result::Result<Session, Pkcs11Error> {
            let session = self.context.open_rw_session(slot)?;

            if let Some(pin) = &self.pin {
                let pin = AuthPin::new(pin.clone().into());
                match session.login(UserType::User, Some(&pin)) {
                    Ok(()) => {}
                    Err(Pkcs11Error::Pkcs11(
                        RvError::UserAlreadyLoggedIn | RvError::UserAnotherAlreadyLoggedIn,
                        Function::Login,
                    )) => {}
                    Err(err) => return Err(err),
                }
            }

            Ok(session)
        }

        fn open_session_with_retry(&self) -> Result<Session> {
            let mut last_class = Pkcs11ErrorClass::Fatal;
            for attempt in 0..OPEN_SESSION_MAX_ATTEMPTS {
                let slot = if attempt == 0 {
                    self.current_slot()?
                } else {
                    self.refresh_active_slot()
                        .or_else(|_| self.current_slot())?
                };
                match self.open_session_on_slot(slot) {
                    Ok(session) => return Ok(session),
                    Err(err) => {
                        let class = classify_pkcs11_error(&err);
                        last_class = class;
                        match class {
                            Pkcs11ErrorClass::Retryable
                                if attempt + 1 < OPEN_SESSION_MAX_ATTEMPTS =>
                            {
                                sleep_backoff(attempt + 1);
                                continue;
                            }
                            Pkcs11ErrorClass::Auth => {
                                return Err(CoreError::Crypto("pkcs11 auth failed"));
                            }
                            _ => break,
                        }
                    }
                }
            }

            match last_class {
                Pkcs11ErrorClass::Auth => Err(CoreError::Crypto("pkcs11 auth failed")),
                _ => Err(CoreError::Internal("pkcs11 open session")),
            }
        }

        fn try_take_pooled_session(&self) -> Option<Session> {
            let mut guard = self.session_pool.lock().ok()?;
            guard.pop()
        }

        fn return_session(&self, session: Session, broken: bool) {
            if broken {
                self.session_total.fetch_sub(1, Ordering::Relaxed);
                drop(session);
                return;
            }
            match self.session_pool.lock() {
                Ok(mut pool) => {
                    if pool.len() < self.session_pool_max {
                        pool.push(session);
                    } else {
                        self.session_total.fetch_sub(1, Ordering::Relaxed);
                        drop(session);
                    }
                }
                Err(_) => {
                    self.session_total.fetch_sub(1, Ordering::Relaxed);
                    drop(session);
                }
            }
        }

        fn borrow_session(&self) -> Result<BorrowedSession<'_>> {
            if let Some(session) = self.try_take_pooled_session() {
                return Ok(BorrowedSession::new(self, session));
            }

            for _ in 0..SESSION_POOL_WAIT_SPINS {
                if let Some(session) = self.try_take_pooled_session() {
                    return Ok(BorrowedSession::new(self, session));
                }

                let mut total = self.session_total.load(Ordering::Relaxed);
                while total < self.session_pool_max as u64 {
                    match self.session_total.compare_exchange_weak(
                        total,
                        total + 1,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => match self.open_session_with_retry() {
                            Ok(session) => return Ok(BorrowedSession::new(self, session)),
                            Err(err) => {
                                self.session_total.fetch_sub(1, Ordering::Relaxed);
                                return Err(err);
                            }
                        },
                        Err(observed) => total = observed,
                    }
                }

                thread::sleep(Duration::from_millis(SESSION_POOL_WAIT_MS));
            }

            Err(CoreError::Internal("pkcs11 session pool exhausted"))
        }

        fn refresh_keys_once(
            &self,
            session: &Session,
        ) -> std::result::Result<HashMap<Vec<u8>, Pkcs11Key, RandomState>, Pkcs11Error> {
            let template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Token(true),
            ];

            let objects = session.find_objects(&template)?;

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

                let key_blob = match build_rsa_key_blob(&modulus, &exponent) {
                    Ok(blob) => blob,
                    Err(_) => continue,
                };
                let label = label
                    .and_then(|value| String::from_utf8(value).ok())
                    .unwrap_or_else(|| "pkcs11-key".to_string());

                map.insert(
                    key_blob,
                    Pkcs11Key {
                        modulus,
                        exponent,
                        label,
                    },
                );
            }

            Ok(map)
        }

        fn refresh_keys(&self) -> Result<()> {
            for attempt in 0..REFRESH_KEYS_MAX_ATTEMPTS {
                let mut session = self.borrow_session()?;
                match self.refresh_keys_once(session.session()) {
                    Ok(map) => {
                        self.key_map.store(Arc::new(map));
                        return Ok(());
                    }
                    Err(err) => {
                        let class = classify_pkcs11_error(&err);
                        match class {
                            Pkcs11ErrorClass::Retryable | Pkcs11ErrorClass::KeyChurn
                                if attempt + 1 < REFRESH_KEYS_MAX_ATTEMPTS =>
                            {
                                session.mark_broken();
                                if self.slot_override.is_none() {
                                    let _ = self.refresh_active_slot();
                                }
                                sleep_backoff(attempt + 1);
                            }
                            Pkcs11ErrorClass::Auth => {
                                session.mark_broken();
                                return Err(CoreError::Crypto("pkcs11 auth failed"));
                            }
                            _ => {
                                return Err(CoreError::Internal("pkcs11 refresh keys"));
                            }
                        }
                    }
                }
            }
            Err(CoreError::Internal("pkcs11 refresh keys"))
        }

        fn refresh_keys_serialized(&self) -> Result<()> {
            self.refresh_keys_with_mode(false)
        }

        fn refresh_keys_forced(&self) -> Result<()> {
            self.refresh_keys_with_mode(true)
        }

        fn refresh_keys_with_mode(&self, force: bool) -> Result<()> {
            let _guard = self
                .refresh_lock
                .lock()
                .map_err(|_| CoreError::Internal("pkcs11 refresh lock"))?;
            let now = now_ms();
            let last = self.last_refresh_ms.load(Ordering::Relaxed);
            let should_skip = !force
                && self.refresh_min_interval_ms > 0
                && last != 0
                && now.saturating_sub(last) < self.refresh_min_interval_ms
                && !self.key_map.load().is_empty();
            if should_skip {
                return Ok(());
            }
            self.refresh_keys()?;
            self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
            Ok(())
        }

        fn resolve_key_for_blob(&self, key_blob: &[u8]) -> Result<Pkcs11Key> {
            if let Some(entry) = self.key_map.load().get(key_blob) {
                return Ok(entry.clone());
            }
            self.refresh_keys_forced()?;
            self.key_map
                .load()
                .get(key_blob)
                .cloned()
                .ok_or(CoreError::KeyNotFound)
        }

        fn sign_once(
            &self,
            session: &Session,
            key: &Pkcs11Key,
            data: &[u8],
            flags: u32,
        ) -> std::result::Result<Vec<u8>, SignAttemptError> {
            let key_handle = match find_private_key(session, &key.modulus, &key.exponent) {
                Ok(Some(handle)) => handle,
                Ok(None) => return Err(SignAttemptError::KeyNotFound),
                Err(err) => return Err(SignAttemptError::Pkcs11(err)),
            };

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
                .map_err(SignAttemptError::Pkcs11)?;

            Ok(secretive_proto::encode_signature_blob(
                algorithm, &signature,
            ))
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
            let mut refreshed = false;
            for attempt in 0..SIGN_MAX_ATTEMPTS {
                let key = self.resolve_key_for_blob(key_blob)?;
                let mut session = self.borrow_session()?;
                match self.sign_once(session.session(), &key, data, flags) {
                    Ok(signature) => return Ok(signature),
                    Err(SignAttemptError::KeyNotFound) => {
                        if !refreshed {
                            self.refresh_keys_forced()?;
                            refreshed = true;
                            continue;
                        }
                        return Err(CoreError::KeyNotFound);
                    }
                    Err(SignAttemptError::Pkcs11(err)) => {
                        let class = classify_pkcs11_error(&err);
                        match class {
                            Pkcs11ErrorClass::KeyChurn => {
                                session.mark_broken();
                                if !refreshed {
                                    self.refresh_keys_forced()?;
                                    refreshed = true;
                                    continue;
                                }
                                return Err(CoreError::KeyNotFound);
                            }
                            Pkcs11ErrorClass::Retryable if attempt + 1 < SIGN_MAX_ATTEMPTS => {
                                session.mark_broken();
                                if self.slot_override.is_none() {
                                    let _ = self.refresh_active_slot();
                                }
                                sleep_backoff(attempt + 1);
                                continue;
                            }
                            Pkcs11ErrorClass::Auth => {
                                session.mark_broken();
                                return Err(CoreError::Crypto("pkcs11 auth failed"));
                            }
                            Pkcs11ErrorClass::Retryable => {
                                session.mark_broken();
                                return Err(CoreError::Internal("pkcs11 sign transient failure"));
                            }
                            Pkcs11ErrorClass::Fatal => {
                                return Err(CoreError::Crypto("pkcs11 sign"));
                            }
                        }
                    }
                }
            }
            Err(CoreError::Internal("pkcs11 sign retries exhausted"))
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
    ) -> std::result::Result<Option<cryptoki::object::ObjectHandle>, Pkcs11Error> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Modulus(modulus.to_vec()),
            Attribute::PublicExponent(exponent.to_vec()),
        ];

        let mut objects = session.find_objects(&template)?;

        Ok(objects.pop())
    }

    // signature encoding delegated to secretive-proto

    fn resolve_slot(context: &Pkcs11, slot_override: Option<Slot>) -> Result<Slot> {
        let slots = context
            .get_slots_with_token()
            .map_err(|_| CoreError::Internal("pkcs11 slots"))?;
        if let Some(slot) = slot_override {
            if slots.iter().any(|candidate| *candidate == slot) {
                return Ok(slot);
            }
            return Err(CoreError::Internal("pkcs11 configured slot unavailable"));
        }
        slots
            .first()
            .copied()
            .ok_or(CoreError::Internal("pkcs11 no slot"))
    }

    fn classify_pkcs11_error(err: &Pkcs11Error) -> Pkcs11ErrorClass {
        let Pkcs11Error::Pkcs11(rv, _) = err else {
            return Pkcs11ErrorClass::Fatal;
        };
        match rv {
            RvError::PinIncorrect
            | RvError::PinInvalid
            | RvError::PinLocked
            | RvError::PinExpired
            | RvError::UserNotLoggedIn
            | RvError::UserPinNotInitialized
            | RvError::UserTypeInvalid => Pkcs11ErrorClass::Auth,
            RvError::ObjectHandleInvalid
            | RvError::KeyHandleInvalid
            | RvError::KeyChanged
            | RvError::KeyNeeded => Pkcs11ErrorClass::KeyChurn,
            RvError::DeviceError
            | RvError::DeviceRemoved
            | RvError::TokenNotPresent
            | RvError::TokenNotRecognized
            | RvError::SessionClosed
            | RvError::SessionHandleInvalid
            | RvError::SessionCount
            | RvError::FunctionFailed
            | RvError::OperationActive
            | RvError::GeneralError
            | RvError::CryptokiNotInitialized
            | RvError::CryptokiAlreadyInitialized => Pkcs11ErrorClass::Retryable,
            _ => Pkcs11ErrorClass::Fatal,
        }
    }

    fn compute_session_pool_max() -> usize {
        let cores = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        cores.saturating_mul(4).max(8).min(64)
    }

    fn sleep_backoff(attempt: usize) {
        let shift = attempt.min(6) as u32;
        let delay_ms = 4u64.saturating_mul(1u64 << shift).min(200);
        thread::sleep(Duration::from_millis(delay_ms));
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cryptoki::context::Function;

        #[test]
        fn classify_pkcs11_errors() {
            let auth = Pkcs11Error::Pkcs11(RvError::PinIncorrect, Function::Login);
            assert_eq!(classify_pkcs11_error(&auth), Pkcs11ErrorClass::Auth);

            let churn = Pkcs11Error::Pkcs11(RvError::KeyHandleInvalid, Function::Sign);
            assert_eq!(classify_pkcs11_error(&churn), Pkcs11ErrorClass::KeyChurn);

            let retry = Pkcs11Error::Pkcs11(RvError::SessionClosed, Function::Sign);
            assert_eq!(classify_pkcs11_error(&retry), Pkcs11ErrorClass::Retryable);
        }

        #[test]
        fn session_pool_bounds_are_sane() {
            let size = compute_session_pool_max();
            assert!((8..=64).contains(&size));
        }
    }
}

#[cfg(feature = "pkcs11")]
pub use enabled::Pkcs11Store;
