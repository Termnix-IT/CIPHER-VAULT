//! Reads output written by the app's own TypeScript codecs, as opposed to the Python vectors.
//! Run generate-node-vectors.mjs first. See docs/開発・配布手順.md for the commands.

use cipher_vault_crypto_compat::*;
use serde_json::Value;
use std::time::Instant;

fn s(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
#[ignore = "needs CIPHER_VAULT_NODE_VECTORS from generate-node-vectors.mjs"]
fn rust_reads_what_the_typescript_codecs_wrote() {
    let path = std::env::var("CIPHER_VAULT_NODE_VECTORS").expect("set CIPHER_VAULT_NODE_VECTORS to the generated file");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(vectors["testOnly"], true);

    let legacy = &vectors["legacy"];
    let key = derive_legacy_key(s(&legacy["password"]).as_bytes(), s(&legacy["salt"])).unwrap();
    assert_eq!(legacy_verifier(&key).unwrap(), s(&legacy["verifier"]));
    let secrets = legacy["secrets"].as_array().unwrap();
    assert!(!secrets.is_empty());
    for secret in secrets {
        let plaintext = open_legacy_secret(&key, s(&secret["payload"])).unwrap();
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), s(&secret["plaintext"]));
    }

    let passphrase = s(&vectors["backupPassphrase"]).as_bytes();
    let backups = vectors["backups"].as_array().unwrap();
    assert_eq!(backups.len(), 3);
    for backup in backups {
        let plaintext = open_backup(s(&backup["content"]), passphrase).unwrap();
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), s(&backup["plaintext"]));
    }

    let v2 = &vectors["v2"];
    let (vault, key_id) = (s(&v2["vaultId"]), s(&v2["keyId"]));
    let slot_revision = v2["slotRevision"].as_u64().unwrap();
    let started = Instant::now();
    let root = unwrap_v2_root(s(&v2["slot"]), s(&v2["password"]).as_bytes(), vault, key_id, slot_revision).unwrap();
    println!("v2 password slot opened in {:?}", started.elapsed());
    assert_eq!(hex::encode(&*root), s(&v2["rootKeyHex"]));
    let entries = v2["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    for entry in entries {
        let revision = entry["revision"].as_u64().unwrap();
        let plaintext = open_v2_entry(&root, s(&entry["envelope"]), vault, key_id, s(&entry["entryId"]), revision).unwrap();
        assert_eq!(std::str::from_utf8(&plaintext).unwrap(), s(&entry["plaintext"]));
    }
}
