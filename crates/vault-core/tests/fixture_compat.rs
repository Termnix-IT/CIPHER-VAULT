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
fn legacy_kdf_pins_salt_text_unicode_form_and_both_verifiers() {
    let fixture = fixture();
    let legacy = &fixture["legacy"];
    let password = s(&legacy["password"]);
    let salt = s(&legacy["salt"]);
    let key = derive_legacy_key(password.as_bytes(), salt).unwrap();
    assert_eq!(hex::encode(&*key), s(&legacy["keyHex"]));

    // No Unicode normalization: the precomposed spelling must derive a different key.
    let nfc = password.replace("e\u{301}", "\u{e9}");
    assert_ne!(nfc, password);
    let nfc_key = derive_legacy_key(nfc.as_bytes(), salt).unwrap();
    assert_eq!(hex::encode(&*nfc_key), s(&legacy["nfcKeyHex"]));

    // The Base64 text is the salt. Decoding it first must give the other pinned key.
    let decoded = scrypt_with_decoded_salt(password, salt);
    assert_eq!(hex::encode(&*decoded), s(&legacy["decodedSaltKeyHex"]));
    assert_ne!(*key, *decoded);

    assert_eq!(legacy_verifier(&key).unwrap(), s(&legacy["verifier"]));
    assert_eq!(STANDARD.encode(&*key), s(&legacy["metadata"]["passwordVerifier"]));

    assert!(verify_legacy_key(&key, s(&legacy["verifier"]), false));
    assert!(verify_legacy_key(&key, s(&legacy["metadata"]["passwordVerifier"]), true));
    assert!(!verify_legacy_key(&key, s(&legacy["metadata"]["passwordVerifier"]), false));
    assert!(!verify_legacy_key(&nfc_key, s(&legacy["verifier"]), false));
    assert!(!verify_legacy_key(&nfc_key, s(&legacy["metadata"]["passwordVerifier"]), true));
}

fn scrypt_with_decoded_salt(password: &str, salt_text: &str) -> Secret {
    let params = scrypt::Params::new(14, 8, 1).unwrap();
    let mut key = zeroize::Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), &decode_base64(salt_text, None).unwrap(), &params, &mut key).unwrap();
    key
}

#[test]
fn legacy_rows_decrypt_to_the_expected_entries() {
    let fixture = fixture();
    let legacy = &fixture["legacy"];
    let key = hex::decode(s(&legacy["keyHex"])).unwrap();
    let rows = legacy["rows"].as_array().unwrap();
    let entries = legacy["entries"].as_array().unwrap();
    assert_eq!(rows.len(), entries.len());
    for (row, entry) in rows.iter().zip(entries) {
        assert_eq!(row["id"], entry["id"]);
        let password = open_legacy_secret(&key, s(&row["encrypted_password"])).unwrap();
        assert_eq!(std::str::from_utf8(&password).unwrap(), s(&entry["password"]));
        // A NULL notes column reads back as the empty string.
        let notes = match row["encrypted_notes"].as_str() {
            Some(payload) => open_legacy_secret(&key, payload).unwrap().to_vec(),
            None => Vec::new(),
        };
        assert_eq!(std::str::from_utf8(&notes).unwrap(), s(&entry["notes"]));
    }
    assert!(open_legacy_secret(&key, s(&legacy["emptyCiphertext"])).unwrap().is_empty());
}

#[test]
fn legacy_packing_rejects_altered_short_and_wrong_key_input() {
    let fixture = fixture();
    let legacy = &fixture["legacy"];
    let key = hex::decode(s(&legacy["keyHex"])).unwrap();
    let payload = s(&legacy["rows"][0]["encrypted_password"]);
    let packed = decode_base64(payload, None).unwrap();
    for offset in [0, 12, 28] {
        let mut changed = packed.clone();
        changed[offset] ^= 1;
        assert_eq!(open_legacy_secret(&key, &STANDARD.encode(changed)).unwrap_err(), CryptoError::Authentication);
    }
    for length in [0, 11, 12, 13] {
        assert_eq!(open_legacy_secret(&key, &STANDARD.encode(&packed[..length])).unwrap_err(), CryptoError::Format);
    }
    assert_eq!(open_legacy_secret(&key, &STANDARD.encode(&packed[..28])).unwrap_err(), CryptoError::Authentication);
    assert_eq!(open_legacy_secret(&[0u8; 32], payload).unwrap_err(), CryptoError::Authentication);
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
    // A v2 record must not open through the legacy path, which uses no AAD.
    let packed = [iv.as_slice(), tag.as_slice(), data.as_slice()].concat();
    assert_eq!(open_legacy_secret(&key, &STANDARD.encode(packed)).unwrap_err(), CryptoError::Authentication);

    let root = hex::decode(s(&v2["rootKeyHex"])).unwrap();
    let envelope = json!({ "cryptoVersion": 2, "cipher": "aes-256-gcm", "vaultId": vault, "keyId": key_id,
        "entryId": entry_id, "revision": revision, "iv": v2["entryIv"], "tag": v2["entryTag"], "data": v2["entryData"] }).to_string();
    assert_eq!(std::str::from_utf8(&open_v2_entry(&root, &envelope, vault, key_id, entry_id, revision).unwrap()).unwrap(), plaintext);
    assert_eq!(open_v2_entry(&root, &envelope, vault, key_id, entry_id, revision + 1).unwrap_err(), CryptoError::ContextMismatch);
    assert_eq!(open_v2_entry(&[0u8; 32], &envelope, vault, key_id, entry_id, revision).unwrap_err(), CryptoError::Authentication);
}

#[test]
fn legacy_sealing_reproduces_the_stored_bytes() {
    let fixture = fixture();
    let legacy = &fixture["legacy"];
    let key = hex::decode(s(&legacy["keyHex"])).unwrap();
    let mut compared = 0;
    for row in legacy["rows"].as_array().unwrap() {
        let entry = legacy["entries"].as_array().unwrap().iter().find(|entry| entry["id"] == row["id"]).unwrap();
        for (payload, plaintext) in [(&row["encrypted_password"], &entry["password"]), (&row["encrypted_notes"], &entry["notes"])] {
            let Some(payload) = payload.as_str() else { continue };
            let iv = &decode_base64(payload, None).unwrap()[..12];
            assert_eq!(seal_legacy_secret(&key, iv, s(plaintext).as_bytes()).unwrap(), payload);
            compared += 1;
        }
    }
    assert!(compared >= 2);
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
