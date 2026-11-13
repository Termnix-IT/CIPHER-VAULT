//! The CIPHER VAULT byte formats: `.cvault` backups and the v2 entry and password-slot envelopes.
//! It covers the bytes only, not storage, sessions or nonce reservation. The legacy format's
//! secrets and verifiers were removed with that format.

use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use serde_json::{Map, Value, json};
use sha2::Sha256;
use zeroize::Zeroizing;

pub type Secret = Zeroizing<Vec<u8>>;

const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const SALT_BYTES: usize = 16;
const STRONG_LOG_N: u8 = 17;
pub(crate) const BACKUP_KDF: &str = "scrypt-N131072-r8-p1";
pub(crate) const CIPHER: &str = "aes-256-gcm";
const V2_PROFILE: &str = "scrypt-n17-r8-p1-k32";
pub const V2_WRAP_INFO: &str = "CIPHER-VAULT/v2/password-wrap";
pub const V2_ENTRY_INFO: &str = "CIPHER-VAULT/v2/entry";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The input does not follow the format, so no decryption was attempted.
    Format,
    /// AES-GCM authentication failed: wrong key, altered data or altered AAD.
    Authentication,
    /// The envelope is authentic-looking but belongs to another context.
    ContextMismatch,
    /// A KDF rejected its parameters.
    Kdf,
}

type Result<T> = std::result::Result<T, CryptoError>;

fn scrypt_key(password: &[u8], salt: &[u8], log_n: u8) -> Result<Secret> {
    let params = scrypt::Params::new(log_n, 8, 1).map_err(|_| CryptoError::Kdf)?;
    let mut key = Zeroizing::new(vec![0u8; KEY_BYTES]);
    scrypt::scrypt(password, salt, &params, &mut key).map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// KDF shared by `.cvault` backups and the v2 password slot. Uses decoded salt bytes.
pub fn derive_strong_key(password: &[u8], salt: &[u8]) -> Result<Secret> {
    scrypt_key(password, salt, STRONG_LOG_N)
}

/// HKDF-SHA256 with the 16 UUID bytes as salt and a per-purpose info string.
pub fn derive_v2_purpose_key(input_key: &[u8], vault_id: &str, info: &str) -> Result<Secret> {
    derive_purpose_key(input_key, &uuid_bytes(vault_id)?, info)
}

/// HKDF-SHA256 with a caller-chosen salt, for keys that must never equal another purpose's key.
pub fn derive_purpose_key(input_key: &[u8], salt: &[u8], info: &str) -> Result<Secret> {
    let mut key = Zeroizing::new(vec![0u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(Some(salt), input_key)
        .expand(info.as_bytes(), &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(key)
}

/// AES-256-GCM with a fresh random IV, returned as (iv, tag, ciphertext). Only for a key of its
/// own that no vault format uses: such a key is outside the v2 nonce reservation, and random
/// 96-bit IVs stay safe for far more writes than a settings file sees.
pub fn seal_with_random_iv(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut iv = vec![0u8; IV_BYTES];
    getrandom::fill(&mut iv).map_err(|_| CryptoError::Kdf)?;
    let (ciphertext, tag) = seal(key, &iv, plaintext, aad)?;
    Ok((iv, tag, ciphertext))
}

fn uuid_bytes(value: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value.replace('-', "")).map_err(|_| CryptoError::Format)?;
    if bytes.len() == 16 { Ok(bytes) } else { Err(CryptoError::Format) }
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Format)
}

fn nonce(iv: &[u8]) -> Result<Nonce<Aes256Gcm>> {
    Nonce::<Aes256Gcm>::try_from(iv).map_err(|_| CryptoError::Format)
}

/// AES-256-GCM decryption from separate fields, as the formats store them.
pub fn open(key: &[u8], iv: &[u8], tag: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Secret> {
    if tag.len() != TAG_BYTES {
        return Err(CryptoError::Format);
    }
    let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_BYTES);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    cipher(key)?
        .decrypt(&nonce(iv)?, Payload { msg: &sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

/// Encrypts with a caller-chosen IV so tests can compare bytes with fixed vectors.
/// Reusing an IV under one key breaks AES-GCM: real writers need the app's nonce reservation.
pub fn seal_with_fixed_iv_for_test(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    seal(key, iv, plaintext, aad)
}

fn seal(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut sealed = cipher(key)?
        .encrypt(&nonce(iv)?, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Authentication)?;
    let tag = sealed.split_off(sealed.len() - TAG_BYTES);
    Ok((sealed, tag))
}

/// Seals one v2 entry into its stored JSON envelope. The IV must already be durably reserved
/// in `vault_nonces`: without that, a crash could lead to reusing it under the same key.
pub fn seal_v2_entry(root: &[u8], iv: &[u8], plaintext: &[u8], vault_id: &str, key_id: &str, entry_id: &str, revision: u64) -> Result<String> {
    let entry_key = derive_v2_purpose_key(root, vault_id, V2_ENTRY_INFO)?;
    let (ciphertext, tag) = seal(&entry_key, iv, plaintext, &v2_entry_aad(vault_id, key_id, entry_id, revision))?;
    Ok(json!({
        "cryptoVersion": 2, "cipher": CIPHER, "vaultId": vault_id, "keyId": key_id, "entryId": entry_id, "revision": revision,
        "iv": STANDARD.encode(iv), "tag": STANDARD.encode(tag), "data": STANDARD.encode(ciphertext)
    })
    .to_string())
}

/// Canonical Base64 only. Node's `Buffer.from(value, "base64")` also accepts malformed
/// text, but the app only ever writes the canonical form accepted here.
pub fn decode_base64(value: &str, exact_bytes: Option<usize>) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value).map_err(|_| CryptoError::Format)?;
    match exact_bytes {
        Some(length) if bytes.len() != length => Err(CryptoError::Format),
        _ => Ok(bytes),
    }
}

/// Seals a `.cvault` payload. The caller supplies a fresh random IV: each backup has its own
/// salt and therefore its own key, so one IV per key is enough.
pub fn seal_backup(key: &[u8], iv: &[u8], plaintext: &[u8], version: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    seal(key, iv, plaintext, &backup_aad(version))
}

pub fn backup_aad(version: u64) -> Vec<u8> {
    format!("CIPHER-VAULT:{version}:{BACKUP_KDF}:{CIPHER}").into_bytes()
}

// The AAD values below are ASCII, where serde_json and JSON.stringify agree byte for byte.
// That is not true of every string (line separators, for example), and the entry id stays
// safe here only because the format hex-encodes it.
pub fn v2_slot_aad(vault_id: &str, key_id: &str, slot_revision: u64, salt: &str) -> Vec<u8> {
    json!(["CIPHER-VAULT", 2, "password-slot", vault_id, key_id, "password", slot_revision, V2_PROFILE, salt])
        .to_string()
        .into_bytes()
}

pub fn v2_entry_aad(vault_id: &str, key_id: &str, entry_id: &str, revision: u64) -> Vec<u8> {
    json!(["CIPHER-VAULT", 2, "entry", vault_id, key_id, hex::encode(entry_id.as_bytes()), revision])
        .to_string()
        .into_bytes()
}

fn exact_object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(CryptoError::Format)?;
    let matches = object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field));
    if matches { Ok(object) } else { Err(CryptoError::Format) }
}

fn parse_json(content: &str) -> Result<Value> {
    serde_json::from_str(content).map_err(|_| CryptoError::Format)
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object.get(field).and_then(Value::as_str).ok_or(CryptoError::Format)
}

fn number(object: &Map<String, Value>, field: &str) -> Result<u64> {
    object.get(field).and_then(Value::as_u64).ok_or(CryptoError::Format)
}

fn require(condition: bool) -> Result<()> {
    if condition { Ok(()) } else { Err(CryptoError::Format) }
}

/// Opens a `.cvault` file of any version and returns the authenticated plaintext JSON.
pub fn open_backup(content: &str, passphrase: &[u8]) -> Result<Secret> {
    let value = parse_json(content)?;
    let envelope = exact_object(&value, &["format", "version", "kdf", "cipher", "salt", "iv", "tag", "data"])?;
    let version = number(envelope, "version")?;
    require(text(envelope, "format")? == "CIPHER-VAULT" && (1..=3).contains(&version))?;
    require(text(envelope, "kdf")? == BACKUP_KDF && text(envelope, "cipher")? == CIPHER)?;
    let salt = decode_base64(text(envelope, "salt")?, Some(SALT_BYTES))?;
    let iv = decode_base64(text(envelope, "iv")?, Some(IV_BYTES))?;
    let tag = decode_base64(text(envelope, "tag")?, Some(TAG_BYTES))?;
    let data = decode_base64(text(envelope, "data")?, None)?;
    let key = derive_strong_key(passphrase, &salt)?;
    let plaintext = open(&key, &iv, &tag, &data, &backup_aad(version))?;
    let payload = serde_json::from_slice::<Value>(&plaintext).map_err(|_| CryptoError::Format)?;
    let decoded = exact_object(&payload, &["version", "entries"])?;
    require(number(decoded, "version")? == version)?;
    Ok(plaintext)
}

fn v2_header(envelope: &Map<String, Value>) -> Result<(&str, &str)> {
    require(number(envelope, "cryptoVersion")? == 2 && text(envelope, "cipher")? == CIPHER)?;
    Ok((text(envelope, "vaultId")?, text(envelope, "keyId")?))
}

/// Opens the v2 password slot and returns the random root key.
pub fn unwrap_v2_root(envelope_json: &str, password: &[u8], vault_id: &str, key_id: &str, slot_revision: u64) -> Result<Secret> {
    let value = parse_json(envelope_json)?;
    let envelope = exact_object(&value, &["cryptoVersion", "cipher", "vaultId", "keyId", "slotId", "slotRevision", "kdf", "iv", "tag", "data"])?;
    let header = v2_header(envelope)?;
    require(text(envelope, "slotId")? == "password")?;
    let kdf_value = envelope.get("kdf").ok_or(CryptoError::Format)?;
    let kdf = exact_object(kdf_value, &["profile", "salt"])?;
    require(text(kdf, "profile")? == V2_PROFILE)?;
    if header != (vault_id, key_id) || number(envelope, "slotRevision")? != slot_revision {
        return Err(CryptoError::ContextMismatch);
    }
    let salt_text = text(kdf, "salt")?;
    let salt = decode_base64(salt_text, Some(SALT_BYTES))?;
    let iv = decode_base64(text(envelope, "iv")?, Some(IV_BYTES))?;
    let tag = decode_base64(text(envelope, "tag")?, Some(TAG_BYTES))?;
    let data = decode_base64(text(envelope, "data")?, Some(KEY_BYTES))?;
    let derived = derive_strong_key(password, &salt)?;
    let wrap_key = derive_v2_purpose_key(&derived, vault_id, V2_WRAP_INFO)?;
    open(&wrap_key, &iv, &tag, &data, &v2_slot_aad(vault_id, key_id, slot_revision, salt_text))
}

/// wrapRootKey: seals the root key in a new password slot. The caller supplies a fresh random
/// salt and IV; the salt gives the slot its own key, so one IV per salt is enough. The fields
/// follow the order the TypeScript app writes them in.
pub fn wrap_v2_root(root: &[u8], password: &[u8], vault_id: &str, key_id: &str, slot_revision: u64, salt: &[u8], iv: &[u8]) -> Result<String> {
    require(root.len() == KEY_BYTES && salt.len() == SALT_BYTES)?;
    let salt_text = STANDARD.encode(salt);
    let derived = derive_strong_key(password, salt)?;
    let wrap_key = derive_v2_purpose_key(&derived, vault_id, V2_WRAP_INFO)?;
    let (data, tag) = seal(&wrap_key, iv, root, &v2_slot_aad(vault_id, key_id, slot_revision, &salt_text))?;
    Ok(json!({
        "cryptoVersion": 2, "cipher": CIPHER, "vaultId": vault_id, "keyId": key_id, "slotRevision": slot_revision, "slotId": "password",
        "kdf": { "profile": V2_PROFILE, "salt": salt_text }, "iv": STANDARD.encode(iv), "tag": STANDARD.encode(tag), "data": STANDARD.encode(data)
    })
    .to_string())
}

/// Opens one v2 entry. The expected context comes from the caller, not from the envelope.
pub fn open_v2_entry(root: &[u8], envelope_json: &str, vault_id: &str, key_id: &str, entry_id: &str, revision: u64) -> Result<Secret> {
    let value = parse_json(envelope_json)?;
    let envelope = exact_object(&value, &["cryptoVersion", "cipher", "vaultId", "keyId", "entryId", "revision", "iv", "tag", "data"])?;
    let header = v2_header(envelope)?;
    if header != (vault_id, key_id) || text(envelope, "entryId")? != entry_id || number(envelope, "revision")? != revision {
        return Err(CryptoError::ContextMismatch);
    }
    let iv = decode_base64(text(envelope, "iv")?, Some(IV_BYTES))?;
    let tag = decode_base64(text(envelope, "tag")?, Some(TAG_BYTES))?;
    let data = decode_base64(text(envelope, "data")?, None)?;
    require(!data.is_empty())?;
    let entry_key = derive_v2_purpose_key(root, vault_id, V2_ENTRY_INFO)?;
    open(&entry_key, &iv, &tag, &data, &v2_entry_aad(vault_id, key_id, entry_id, revision))
}
