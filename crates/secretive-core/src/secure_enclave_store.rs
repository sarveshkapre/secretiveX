use crate::{CoreError, KeyIdentity, KeyStore, Result};

#[cfg(target_os = "macos")]
fn write_ssh_string(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value);
}

#[cfg(target_os = "macos")]
fn encode_ecdsa_public_key_blob(algorithm: &str, curve_name: &str, public_key: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(algorithm.len() + curve_name.len() + public_key.len() + 12);
    write_ssh_string(&mut blob, algorithm.as_bytes());
    write_ssh_string(&mut blob, curve_name.as_bytes());
    write_ssh_string(&mut blob, public_key);
    blob
}

#[cfg(target_os = "macos")]
fn read_der_length(input: &[u8], offset: &mut usize) -> Result<usize> {
    if *offset >= input.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    let first = input[*offset];
    *offset += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let bytes = (first & 0x7f) as usize;
    if bytes == 0 || bytes > 4 || *offset + bytes > input.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    let mut out = 0usize;
    for _ in 0..bytes {
        out = (out << 8) | input[*offset] as usize;
        *offset += 1;
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn normalize_mpint_bytes(raw: &[u8]) -> Vec<u8> {
    let mut idx = 0usize;
    while idx < raw.len() && raw[idx] == 0 {
        idx += 1;
    }
    let mut out = if idx == raw.len() {
        vec![0]
    } else {
        raw[idx..].to_vec()
    };
    if out.first().copied().unwrap_or(0) & 0x80 != 0 {
        let mut prefixed = Vec::with_capacity(out.len() + 1);
        prefixed.push(0);
        prefixed.extend_from_slice(&out);
        out = prefixed;
    }
    out
}

#[cfg(target_os = "macos")]
fn ecdsa_der_signature_to_ssh_blob(der: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    if der.get(offset).copied() != Some(0x30) {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    offset += 1;
    let sequence_len = read_der_length(der, &mut offset)?;
    if offset + sequence_len != der.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    if der.get(offset).copied() != Some(0x02) {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    offset += 1;
    let r_len = read_der_length(der, &mut offset)?;
    if offset + r_len > der.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    let r = &der[offset..offset + r_len];
    offset += r_len;

    if der.get(offset).copied() != Some(0x02) {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    offset += 1;
    let s_len = read_der_length(der, &mut offset)?;
    if offset + s_len > der.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }
    let s = &der[offset..offset + s_len];
    offset += s_len;
    if offset != der.len() {
        return Err(CoreError::Crypto("invalid secure enclave signature"));
    }

    let r_mpint = normalize_mpint_bytes(r);
    let s_mpint = normalize_mpint_bytes(s);
    let mut out = Vec::with_capacity(r_mpint.len() + s_mpint.len() + 8);
    write_ssh_string(&mut out, &r_mpint);
    write_ssh_string(&mut out, &s_mpint);
    Ok(out)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{
        ecdsa_der_signature_to_ssh_blob, encode_ecdsa_public_key_blob, CoreError, KeyIdentity,
        KeyStore, Result,
    };
    use ahash::RandomState;
    use arc_swap::ArcSwap;
    use core_foundation::base::{TCFType, ToVoid};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Limit, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, SecKey};
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrApplicationLabel, kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeEC,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    type EntryMap = HashMap<Vec<u8>, SecureEnclaveKeyEntry, RandomState>;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum EcdsaCurve {
        NistP256,
        NistP384,
        NistP521,
    }

    impl EcdsaCurve {
        fn from_key_bits(bits: i64) -> Option<Self> {
            match bits {
                256 => Some(Self::NistP256),
                384 => Some(Self::NistP384),
                521 => Some(Self::NistP521),
                _ => None,
            }
        }

        fn algorithm_name(self) -> &'static str {
            match self {
                Self::NistP256 => "ecdsa-sha2-nistp256",
                Self::NistP384 => "ecdsa-sha2-nistp384",
                Self::NistP521 => "ecdsa-sha2-nistp521",
            }
        }

        fn curve_name(self) -> &'static str {
            match self {
                Self::NistP256 => "nistp256",
                Self::NistP384 => "nistp384",
                Self::NistP521 => "nistp521",
            }
        }

        fn expected_point_len(self) -> usize {
            match self {
                Self::NistP256 => 65,
                Self::NistP384 => 97,
                Self::NistP521 => 133,
            }
        }

        fn signing_algorithm(self) -> Algorithm {
            match self {
                Self::NistP256 => Algorithm::ECDSASignatureMessageX962SHA256,
                Self::NistP384 => Algorithm::ECDSASignatureMessageX962SHA384,
                Self::NistP521 => Algorithm::ECDSASignatureMessageX962SHA512,
            }
        }
    }

    #[derive(Clone)]
    struct SecureEnclaveKeyEntry {
        application_label: Vec<u8>,
        curve: EcdsaCurve,
    }

    struct LoadedIdentity {
        identity: KeyIdentity,
        entry: SecureEnclaveKeyEntry,
    }

    #[derive(Clone)]
    pub struct SecureEnclaveStore {
        entries: Arc<ArcSwap<EntryMap>>,
    }

    impl SecureEnclaveStore {
        pub fn load() -> Result<Self> {
            let store = Self {
                entries: Arc::new(ArcSwap::from_pointee(HashMap::with_hasher(
                    RandomState::new(),
                ))),
            };
            let _ = store.refresh_entries()?;
            Ok(store)
        }

        fn refresh_entries(&self) -> Result<Vec<KeyIdentity>> {
            let loaded = query_secure_enclave_keys()?;
            let mut entries = HashMap::with_capacity_and_hasher(loaded.len(), RandomState::new());
            let mut identities = Vec::with_capacity(loaded.len());
            for item in loaded {
                entries.insert(item.identity.key_blob.clone(), item.entry);
                identities.push(item.identity);
            }
            self.entries.store(Arc::new(entries));
            Ok(identities)
        }

        fn find_entry(&self, key_blob: &[u8]) -> Option<SecureEnclaveKeyEntry> {
            self.entries.load().get(key_blob).cloned()
        }
    }

    impl KeyStore for SecureEnclaveStore {
        fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
            self.refresh_entries()
        }

        fn sign(&self, key_blob: &[u8], data: &[u8], _flags: u32) -> Result<Vec<u8>> {
            let entry = if let Some(found) = self.find_entry(key_blob) {
                found
            } else {
                let _ = self.refresh_entries()?;
                self.find_entry(key_blob).ok_or(CoreError::KeyNotFound)?
            };
            let key = load_secure_enclave_key(&entry.application_label, entry.curve)?;
            let der_signature = key
                .create_signature(entry.curve.signing_algorithm(), data)
                .map_err(|_| CoreError::Crypto("secure enclave sign failed"))?;
            let ssh_signature = ecdsa_der_signature_to_ssh_blob(&der_signature)?;
            Ok(secretive_proto::encode_signature_blob(
                entry.curve.algorithm_name(),
                &ssh_signature,
            ))
        }

        fn store_kind(&self) -> &'static str {
            "secure_enclave"
        }
    }

    fn query_secure_enclave_keys() -> Result<Vec<LoadedIdentity>> {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .load_refs(true)
            .limit(Limit::All);
        let results = match query.search() {
            Ok(results) => results,
            Err(err) if err.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(_) => return Err(CoreError::Internal("secure enclave keychain query failed")),
        };

        let mut identities = Vec::new();
        for result in results {
            let SearchResult::Ref(Reference::Key(key)) = result else {
                continue;
            };
            let attributes = key.attributes();
            if !is_secure_enclave_key(&attributes) {
                continue;
            }
            let Some(curve) = curve_from_attributes(&attributes) else {
                continue;
            };
            let Some(application_label) = key.application_label().or_else(|| {
                extract_data_attr(&attributes, unsafe { kSecAttrApplicationLabel.to_void() })
            }) else {
                continue;
            };

            let Some(public_key) = key.public_key() else {
                continue;
            };
            let Some(public_key_data) = public_key.external_representation() else {
                continue;
            };
            let public_key_data = public_key_data.to_vec();
            if public_key_data.len() != curve.expected_point_len() {
                continue;
            }
            if public_key_data.first().copied() != Some(0x04) {
                continue;
            }

            let key_blob = encode_ecdsa_public_key_blob(
                curve.algorithm_name(),
                curve.curve_name(),
                &public_key_data,
            );
            let comment = extract_string_attr(&attributes, unsafe { kSecAttrLabel.to_void() })
                .unwrap_or_else(|| {
                    format!(
                        "secure-enclave-{}",
                        hex::encode(&application_label)
                            .chars()
                            .take(12)
                            .collect::<String>()
                    )
                });
            let source = format!("secure_enclave:{}", hex::encode(&application_label));
            let identity = KeyIdentity {
                key_blob,
                comment,
                source,
            };
            let entry = SecureEnclaveKeyEntry {
                application_label,
                curve,
            };
            identities.push(LoadedIdentity { identity, entry });
        }
        Ok(identities)
    }

    fn load_secure_enclave_key(
        application_label: &[u8],
        expected_curve: EcdsaCurve,
    ) -> Result<SecKey> {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .application_label(application_label)
            .load_refs(true)
            .limit(Limit::All);
        let results = match query.search() {
            Ok(results) => results,
            Err(err) if err.code() == errSecItemNotFound => return Err(CoreError::KeyNotFound),
            Err(_) => return Err(CoreError::Internal("secure enclave key lookup failed")),
        };

        for result in results {
            let SearchResult::Ref(Reference::Key(key)) = result else {
                continue;
            };
            let attributes = key.attributes();
            if !is_secure_enclave_key(&attributes) {
                continue;
            }
            if curve_from_attributes(&attributes) != Some(expected_curve) {
                continue;
            }
            return Ok(key);
        }

        Err(CoreError::KeyNotFound)
    }

    fn is_secure_enclave_key(attributes: &CFDictionary) -> bool {
        let Some(value) = attributes.find(unsafe { kSecAttrTokenID.to_void() }) else {
            return false;
        };
        let token = unsafe { CFString::wrap_under_get_rule(value.cast()) };
        let expected = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
        token == expected
    }

    fn extract_data_attr(
        attributes: &CFDictionary,
        key: *const std::ffi::c_void,
    ) -> Option<Vec<u8>> {
        let value = attributes.find(key)?;
        let data = unsafe { CFData::wrap_under_get_rule(value.cast()) };
        Some(data.to_vec())
    }

    fn extract_string_attr(
        attributes: &CFDictionary,
        key: *const std::ffi::c_void,
    ) -> Option<String> {
        let value = attributes.find(key)?;
        let text = unsafe { CFString::wrap_under_get_rule(value.cast()) };
        Some(text.to_string())
    }

    fn curve_from_attributes(attributes: &CFDictionary) -> Option<EcdsaCurve> {
        let key_type_ref = attributes.find(unsafe { kSecAttrKeyType.to_void() })?;
        let key_type = unsafe { CFString::wrap_under_get_rule(key_type_ref.cast()) };
        let ec = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeEC) };
        let ec_prime = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
        if key_type != ec && key_type != ec_prime {
            return None;
        }

        let bits_ref = attributes.find(unsafe { kSecAttrKeySizeInBits.to_void() })?;
        let bits = unsafe { CFNumber::wrap_under_get_rule(bits_ref.cast()) }.to_i64()?;
        EcdsaCurve::from_key_bits(bits)
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::*;

    #[derive(Clone)]
    pub struct SecureEnclaveStore;

    impl SecureEnclaveStore {
        pub fn load() -> Result<Self> {
            Err(CoreError::Unsupported(
                "secure enclave store is only supported on macOS",
            ))
        }
    }

    impl KeyStore for SecureEnclaveStore {
        fn list_identities(&self) -> Result<Vec<KeyIdentity>> {
            Err(CoreError::Unsupported(
                "secure enclave store is only supported on macOS",
            ))
        }

        fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Result<Vec<u8>> {
            Err(CoreError::Unsupported(
                "secure enclave store is only supported on macOS",
            ))
        }

        fn store_kind(&self) -> &'static str {
            "secure_enclave"
        }
    }
}

pub use platform::SecureEnclaveStore;

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{ecdsa_der_signature_to_ssh_blob, encode_ecdsa_public_key_blob};

    #[test]
    fn der_signature_converts_to_ssh_blob() {
        // ASN.1 DER: SEQUENCE(INTEGER(1), INTEGER(2))
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let ssh = ecdsa_der_signature_to_ssh_blob(&der).expect("convert");
        let algorithm = ssh_key::Algorithm::new("ecdsa-sha2-nistp256").expect("algorithm");
        let parsed = ssh_key::Signature::new(algorithm, ssh).expect("signature");
        assert_eq!(parsed.algorithm().as_str(), "ecdsa-sha2-nistp256");
    }

    #[test]
    fn der_signature_high_bit_integers_are_mpint_encoded() {
        // ASN.1 DER: SEQUENCE(INTEGER(0x80), INTEGER(0xff))
        let der = [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0xff];
        let ssh = ecdsa_der_signature_to_ssh_blob(&der).expect("convert");
        // r len(2): 00 80, s len(2): 00 ff
        assert_eq!(ssh, vec![0, 0, 0, 2, 0x00, 0x80, 0, 0, 0, 2, 0x00, 0xff]);
    }

    #[test]
    fn ecdsa_public_key_blob_roundtrips() {
        // P-256 generator point, uncompressed SEC1 format.
        let mut point = vec![0x04];
        point.extend_from_slice(
            &hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                .expect("x"),
        );
        point.extend_from_slice(
            &hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cbf1f5d9e98bf9292dc29f8f41dbd28")
                .expect("y"),
        );

        let blob = encode_ecdsa_public_key_blob("ecdsa-sha2-nistp256", "nistp256", &point);
        let parsed = ssh_key::PublicKey::from_bytes(&blob).expect("parse");
        assert_eq!(parsed.algorithm().as_str(), "ecdsa-sha2-nistp256");
    }
}
