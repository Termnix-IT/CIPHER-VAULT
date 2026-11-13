//! Checks Rust against the Python-generated vectors shared with tests/crypto-compatibility.test.mjs.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cipher_vault_core::crypto::*;
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("../../../tests/fixtures/crypto-compatibility.json");

fn fixture() -> Value {
    let value: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(value["testOnly"], true);
    value
}

fn s(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn b64(value: &Value) -> Vec<u8> {
    decode_base64(s(value), None).unwrap()
}

fn flip_first_byte(value: &Value) -> String {
    let mut bytes = b64(value);
    bytes[0] ^= 1;
    STANDARD.encode(bytes)
}

#[test]
fn backup_v1_decrypts_and_rejects_every_kind_of_change() {
    let fixture = fixture();
    let backup = &fixture["backupV1"];
    let envelope = &backup["envelope"];
    let passphrase = s(&backup["passphrase"]).as_bytes();
    let key = derive_strong_key(passphrase, &b64(&envelope["salt"])).unwrap();
    assert_eq!(hex::encode(&*key), s(&backup["keyHex"]));
    assert_eq!(hex::encode(backup_aad(1)), s(&backup["aadHex"]));

    let plaintext = open_backup(&envelope.to_string(), passphrase).unwrap();
    assert_eq!(std::str::from_utf8(&plaintext).unwrap(), s(&backup["plaintext"]));
    let decoded: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(decoded["entries"], fixture["legacy"]["entries"]);

    let wrong = open_backup(&envelope.to_string(), b"fixture-wrong-backup-passphrase");
    assert_eq!(wrong.unwrap_err(), CryptoError::Authentication);
    for field in ["salt", "iv", "tag", "data"] {
        let mut changed = envelope.clone();
        changed[field] = json!(flip_first_byte(&envelope[field]));
        assert_eq!(open_backup(&changed.to_string(), passphrase).unwrap_err(), CryptoError::Authentication, "{field}");
    }
    let salt_with_newline = format!("{}\n", s(&envelope["salt"]));
    for (field, value) in [("format", json!("UNKNOWN")), ("kdf", json!("scrypt-arbitrary")),
        ("cipher", json!("aes-128-gcm")), ("salt", json!(salt_with_newline)), ("version", json!(4))] {
        let mut changed = envelope.clone();
        changed[field] = value;
        assert_eq!(open_backup(&changed.to_string(), passphrase).unwrap_err(), CryptoError::Format, "{field}");
    }
    // The version is authenticated: relabelling a v1 file as v2 must fail.
    let mut relabelled = envelope.clone();
    relabelled["version"] = json!(2);
    assert_eq!(open_backup(&relabelled.to_string(), passphrase).unwrap_err(), CryptoError::Authentication);
    let mut extra = envelope.clone();
    extra["extra"] = json!(1);
    assert_eq!(open_backup(&extra.to_string(), passphrase).unwrap_err(), CryptoError::Format);
}

#[test]
fn v2_slot_reproduces_the_key_chain_and_wrapped_root_bytes() {
    let fixture = fixture();
    let v2 = &fixture["draftV2"];
    let (vault, key_id) = (s(&v2["vaultId"]), s(&v2["keyId"]));
    let revision = v2["slotRevision"].as_u64().unwrap();
    let salt = s(&v2["salt"]);
    let derived = derive_strong_key(s(&v2["masterPassword"]).as_bytes(), &b64(&v2["salt"])).unwrap();
    assert_eq!(hex::encode(&*derived), s(&v2["kdfKeyHex"]));
    let wrap_key = derive_v2_purpose_key(&derived, vault, s(&v2["wrapInfo"])).unwrap();
    assert_eq!(hex::encode(&*wrap_key), s(&v2["wrapKeyHex"]));
    let root = hex::decode(s(&v2["rootKeyHex"])).unwrap();
    let entry_key = derive_v2_purpose_key(&root, vault, s(&v2["entryInfo"])).unwrap();
    assert_eq!(hex::encode(&*entry_key), s(&v2["entryKeyHex"]));
    assert_eq!(s(&v2["wrapInfo"]), V2_WRAP_INFO);
    assert_eq!(s(&v2["entryInfo"]), V2_ENTRY_INFO);

    let aad = v2_slot_aad(vault, key_id, revision, salt);
    assert_eq!(hex::encode(&aad), s(&v2["wrapAadHex"]));
    let (data, tag) = seal_with_fixed_iv_for_test(&wrap_key, &b64(&v2["wrapIv"]), &root, &aad).unwrap();
    assert_eq!(STANDARD.encode(&data), s(&v2["wrappedRoot"]));
    assert_eq!(STANDARD.encode(&tag), s(&v2["wrapTag"]));

    // The same slot through the whole envelope entry point, including wrong-input paths.
    let envelope = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": vault, "keyId": key_id,
        "slotId": "password", "slotRevision": revision, "kdf": { "profile": s(&v2["profile"]), "salt": salt },
        "iv": v2["wrapIv"], "tag": v2["wrapTag"], "data": v2["wrappedRoot"] }).to_string();
    let password = s(&v2["masterPassword"]).as_bytes();
    assert_eq!(*unwrap_v2_root(&envelope, password, vault, key_id, revision).unwrap(), root);
    assert_eq!(unwrap_v2_root(&envelope, b"wrong", vault, key_id, revision).unwrap_err(), CryptoError::Authentication);
    assert_eq!(unwrap_v2_root(&envelope, password, vault, key_id, revision + 1).unwrap_err(), CryptoError::ContextMismatch);

    // Wrapping with the fixture's salt and IV writes the app's slot byte for byte.
    let ordered = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": vault, "keyId": key_id, "slotRevision": revision, "slotId": "password",
        "kdf": { "profile": s(&v2["profile"]), "salt": salt }, "iv": v2["wrapIv"], "tag": v2["wrapTag"], "data": v2["wrappedRoot"] }).to_string();
    assert_eq!(wrap_v2_root(&root, password, vault, key_id, revision, &b64(&v2["salt"]), &b64(&v2["wrapIv"])).unwrap(), ordered);

    let changed_salt = STANDARD.encode([0u8; 16]);
    let changed = v2_slot_aad(vault, key_id, revision, &changed_salt);
    let opened = open(&wrap_key, &b64(&v2["wrapIv"]), &b64(&v2["wrapTag"]), &b64(&v2["wrappedRoot"]), &changed);
    assert_eq!(opened.unwrap_err(), CryptoError::Authentication);
}

#[test]
fn v2_entry_reproduces_bytes_and_binds_identity_revision_and_purpose() {
    let fixture = fixture();
    let v2 = &fixture["draftV2"];
    let (vault, key_id, entry_id) = (s(&v2["vaultId"]), s(&v2["keyId"]), s(&v2["entryId"]));
    let revision = v2["revision"].as_u64().unwrap();
    let key = hex::decode(s(&v2["entryKeyHex"])).unwrap();
    let (iv, tag, data) = (b64(&v2["entryIv"]), b64(&v2["entryTag"]), b64(&v2["entryData"]));
    let aad = v2_entry_aad(vault, key_id, entry_id, revision);
    assert_eq!(hex::encode(&aad), s(&v2["entryAadHex"]));
    let plaintext = s(&v2["entryPlaintext"]);
    let (sealed, sealed_tag) = seal_with_fixed_iv_for_test(&key, &iv, plaintext.as_bytes(), &aad).unwrap();
    assert_eq!(sealed, data);
    assert_eq!(sealed_tag, tag);
    assert_eq!(std::str::from_utf8(&open(&key, &iv, &tag, &data, &aad).unwrap()).unwrap(), plaintext);

    let hex_entry = hex::encode(entry_id.as_bytes());
    let other_entry = hex::encode(s(&fixture["legacy"]["entries"][1]["id"]).as_bytes());
    let base = json!(["CIPHER-VAULT", 2, "entry", vault, key_id, hex_entry, revision]);
    for (index, replacement) in [(1, json!(3)), (2, json!("password-slot")), (3, json!(key_id)),
        (4, json!(vault)), (5, json!(other_entry)), (6, json!(2))] {
        let mut changed = base.clone();
        changed[index] = replacement;
        let opened = open(&key, &iv, &tag, &data, changed.to_string().as_bytes());
        assert_eq!(opened.unwrap_err(), CryptoError::Authentication, "AAD index {index}");
    }

    let root = hex::decode(s(&v2["rootKeyHex"])).unwrap();
    let envelope = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": vault, "keyId": key_id,
        "entryId": entry_id, "revision": revision, "iv": v2["entryIv"], "tag": v2["entryTag"], "data": v2["entryData"] }).to_string();
    assert_eq!(std::str::from_utf8(&open_v2_entry(&root, &envelope, vault, key_id, entry_id, revision).unwrap()).unwrap(), plaintext);
    assert_eq!(open_v2_entry(&root, &envelope, vault, key_id, entry_id, revision + 1).unwrap_err(), CryptoError::ContextMismatch);
    assert_eq!(open_v2_entry(&[0u8; 32], &envelope, vault, key_id, entry_id, revision).unwrap_err(), CryptoError::Authentication);
}

#[test]
fn v2_sealing_reproduces_the_stored_bytes_and_opens_again() {
    let fixture = fixture();
    let v2 = &fixture["draftV2"];
    let root = hex::decode(s(&v2["rootKeyHex"])).unwrap();
    let (vault_id, key_id, entry_id) = (s(&v2["vaultId"]), s(&v2["keyId"]), s(&v2["entryId"]));
    let revision = v2["revision"].as_u64().unwrap();
    let plaintext = s(&v2["entryPlaintext"]).as_bytes();
    let envelope = seal_v2_entry(&root, &b64(&v2["entryIv"]), plaintext, vault_id, key_id, entry_id, revision).unwrap();
    let parsed: Value = serde_json::from_str(&envelope).unwrap();
    assert_eq!(parsed["data"], v2["entryData"]);
    assert_eq!(parsed["tag"], v2["entryTag"]);
    assert_eq!(parsed["iv"], v2["entryIv"]);
    assert_eq!(&*open_v2_entry(&root, &envelope, vault_id, key_id, entry_id, revision).unwrap(), plaintext);
    // The revision is authenticated, so a replayed envelope cannot pass as a newer one.
    let moved = envelope.replace(&format!("\"revision\":{revision}"), &format!("\"revision\":{}", revision + 1));
    assert_eq!(open_v2_entry(&root, &moved, vault_id, key_id, entry_id, revision + 1), Err(CryptoError::Authentication));
}
