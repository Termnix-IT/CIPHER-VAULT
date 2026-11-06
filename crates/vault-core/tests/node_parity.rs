//! Runs the same calls on the Rust core and on the TypeScript services it replaces, and compares
//! every answer: the value, or the status and message of the error. The Node side is
//! tests/rust-parity-engine.mjs, which calls the services the way the Electron app does.
//!
//! It needs Node.js and the built API (`npm run build:api`), so it is ignored by default:
//! `npm run test:rust-parity` builds the API and runs it. Only synthetic vaults in temporary
//! folders are used.
//!
//! Each scenario runs on Rust first and then on Node, each on its own copy of the same starting
//! folder, so the waits after wrong passwords are measured within one engine. Values that differ by
//! nature (ids, session ids, times, generated passwords) are replaced by names in order of
//! appearance before the comparison.

use cipher_vault_core::{Vault, VaultError, backup, crypto};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

const PASSWORD: &str = "synthetic-parity-master-password";
const WRONG: &str = "synthetic-parity-wrong-password";
const UNDEFINED: &str = "$undefined";
const SESSION: &str = "$session";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn engine_script() -> PathBuf {
    repository().join("tests").join("rust-parity-engine.mjs")
}

fn node(args: &[&str]) -> Value {
    let output = Command::new("node").arg(engine_script()).args(args).current_dir(repository()).output().expect("Node.js is needed for the parity test");
    assert!(output.status.success(), "node {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("cipher-vault-parity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_directory(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for item in std::fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_directory(&item.path(), &target);
        } else {
            std::fs::copy(item.path(), target).unwrap();
        }
    }
}

// ---- The engines

trait Engine {
    /// Answers {"ok": value} or {"error": {"status", "message"}}.
    fn call(&mut self, method: &str, args: &[Value]) -> Value;
}

struct RustEngine(Vault);

impl Engine for RustEngine {
    fn call(&mut self, method: &str, args: &[Value]) -> Value {
        let arg = |index: usize| args.get(index).filter(|value| value.as_str() != Some(UNDEFINED));
        let vault = &self.0;
        let result = match method {
            "status" => vault.status(),
            "activity" => vault.record_activity(arg(0)),
            "setup" => vault.setup(arg(0), arg(1)),
            "unlock" => vault.unlock(arg(0), arg(1)),
            "reset" => vault.reset(arg(0), arg(1)),
            "lock" => vault.lock(arg(0)),
            "list" => vault.list_entries(arg(0)),
            "get" => vault.get_entry(arg(0), arg(1)),
            "create" => vault.create_entry(arg(0), arg(1)),
            "update" => vault.update_entry(arg(0), arg(1), arg(2)),
            "delete" => vault.delete_entry(arg(0), arg(1)),
            "setGroup" => vault.set_entries_group(arg(0), arg(1)),
            "generate" => vault.generate_password(arg(0), arg(1)),
            "exportBackup" => vault.export_backup(arg(0), arg(1)),
            "restoreBackup" => vault.restore_backup(arg(0), arg(1)),
            "decodeBackup" => decode_backup(args[0].as_str().unwrap(), args[1].as_str().unwrap()),
            other => panic!("unknown method {other}"),
        };
        match result {
            Ok(value) => json!({ "ok": value }),
            Err(error) => json!({ "error": { "status": error.status, "message": error.message } }),
        }
    }
}

/// Reads a file the other engine wrote, without a vault.
fn decode_backup(content: &str, passphrase: &str) -> Result<Value, VaultError> {
    let envelope = backup::parse(content)?;
    let key = crypto::derive_strong_key(passphrase.as_bytes(), &envelope.salt).unwrap();
    Ok(json!({ "version": envelope.version, "entries": backup::decode(&envelope, &key)? }))
}

struct NodeEngine {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl NodeEngine {
    fn start(data_directory: &Path) -> Self {
        let mut child = Command::new("node")
            .arg(engine_script())
            .arg("serve")
            .current_dir(repository())
            .env("PASSWORD_MANAGER_DATA_DIR", data_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Node.js is needed for the parity test");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self { child, input, output }
    }
}

impl Engine for NodeEngine {
    fn call(&mut self, method: &str, args: &[Value]) -> Value {
        writeln!(self.input, "{}", json!({ "method": method, "args": args })).unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        assert!(self.output.read_line(&mut line).unwrap() > 0, "the Node engine stopped");
        serde_json::from_str(&line).unwrap()
    }
}

impl Drop for NodeEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- Scenarios

enum Step {
    Call { label: String, method: &'static str, args: Vec<Value> },
    Wait(Duration),
    /// Changes the engine's data folder between calls.
    Change(fn(&Path)),
}

#[derive(Default)]
struct Scenario(Vec<Step>);

impl Scenario {
    fn call(&mut self, label: impl Into<String>, method: &'static str, args: Vec<Value>) -> &mut Self {
        self.0.push(Step::Call { label: label.into(), method, args });
        self
    }

    fn session(&mut self, method: &'static str, rest: Vec<Value>) -> &mut Self {
        let label = format!("{method} {}", Value::from(rest.clone()));
        let mut args = vec![Value::from(SESSION)];
        args.extend(rest);
        self.call(label, method, args)
    }
}

fn entry(index: usize) -> Value {
    Value::from(format!("$entry:{index}"))
}

/// Gives the values that differ between runs names in order of appearance.
#[derive(Default)]
struct Names {
    kinds: HashMap<&'static str, Vec<String>>,
}

impl Names {
    fn name(&mut self, kind: &'static str, value: &str) -> String {
        let known = self.kinds.entry(kind).or_default();
        let index = known.iter().position(|item| item == value).unwrap_or_else(|| {
            known.push(value.to_string());
            known.len() - 1
        });
        format!("<{kind}:{index}>")
    }

    fn entry(&self, index: usize) -> Value {
        self.kinds.get("entry").and_then(|ids| ids.get(index)).map_or(Value::from("unknown-entry"), |id| Value::from(id.as_str()))
    }

    fn normalize(&mut self, value: &Value, key: Option<&str>) -> Value {
        match value {
            Value::String(text) if key == Some("sessionId") => Value::from(self.name("session", text)),
            Value::String(text) if matches!(key, Some("id" | "ids")) => Value::from(self.name("entry", text)),
            Value::String(text) if is_time(text) => Value::from("<time>"),
            Value::String(text) if is_uuid(text) => Value::from(self.name("uuid", text)),
            Value::Array(items) => Value::Array(items.iter().map(|item| self.normalize(item, key)).collect()),
            Value::Object(fields) => {
                Value::Object(fields.iter().map(|(name, item)| (name.clone(), self.normalize(item, Some(name)))).collect::<Map<_, _>>())
            }
            other => other.clone(),
        }
    }
}

fn is_time(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 24 && bytes[4] == b'-' && bytes[10] == b'T' && bytes[19] == b'.' && bytes[23] == b'Z'
}

fn is_uuid(text: &str) -> bool {
    text.len() == 36 && text.chars().enumerate().all(|(index, char)| if matches!(index, 8 | 13 | 18 | 23) { char == '-' } else { char.is_ascii_hexdigit() })
}

fn run(engine: &mut dyn Engine, directory: &Path, scenario: &Scenario) -> Vec<(String, Value)> {
    let mut names = Names::default();
    let mut answers = Vec::new();
    for step in &scenario.0 {
        match step {
            Step::Wait(duration) => std::thread::sleep(*duration),
            Step::Change(change) => change(directory),
            Step::Call { label, method, args } => {
                let session = engine.call("status", &[])["ok"]["sessionId"].clone();
                let args: Vec<Value> = args
                    .iter()
                    .map(|arg| match arg.as_str() {
                        Some(SESSION) => session.clone(),
                        Some(text) if text.starts_with("$entry:") => names.entry(text["$entry:".len()..].parse().unwrap()),
                        _ => arg.clone(),
                    })
                    .collect();
                let mut answer = engine.call(method, &args);
                if *method == "generate"
                    && let Some(password) = answer["ok"]["password"].as_str()
                {
                    // Random by design: only the length and the character groups are compared.
                    let groups: Vec<bool> = [char::is_ascii_uppercase, char::is_ascii_lowercase, char::is_ascii_digit, char::is_ascii_punctuation]
                        .iter()
                        .map(|group| password.chars().any(|char| group(&char)))
                        .collect();
                    answer["ok"]["password"] = json!({ "length": password.chars().count(), "groups": groups });
                }
                // A backup is sealed with a random salt and IV: only its version and name are compared.
                if *method == "exportBackup"
                    && let Some(file) = answer.get_mut("ok").and_then(Value::as_object_mut)
                {
                    let name = file["fileName"].as_str().unwrap_or_default();
                    let named = name.starts_with("CIPHER-VAULT-") && name.ends_with("Z.cvault") && name.len() == "CIPHER-VAULT-2026-01-01T00-00-00-000Z.cvault".len();
                    let version = serde_json::from_str::<Value>(file["content"].as_str().unwrap_or_default()).map(|content| content["version"].clone()).unwrap_or_default();
                    *file = Map::from_iter([("fileName".to_string(), json!(named)), ("version".to_string(), version)]);
                }
                // Recovery itself arrives in a later phase, and the Rust core gives no hint for it yet.
                if let Some(maintenance) = answer["ok"].get_mut("maintenance").and_then(Value::as_object_mut) {
                    maintenance.remove("recoveryOperation");
                }
                answers.push((label.clone(), names.normalize(&answer, None)));
                // Keeps the update times of consecutive writes apart, so list order never depends on a tie.
                std::thread::sleep(Duration::from_millis(3));
            }
        }
    }
    answers
}

fn compare(kind: &str, scenario: &Scenario) {
    let folder = TemporaryDirectory::new();
    let source = folder.0.join("source");
    node(&["prepare", kind, source.to_str().unwrap()]);
    let (rust_directory, node_directory) = (folder.0.join("rust"), folder.0.join("node"));
    copy_directory(&source, &rust_directory);
    copy_directory(&source, &node_directory);

    let rust = run(&mut RustEngine(Vault::open(&rust_directory).unwrap()), &rust_directory, scenario);
    let node = run(&mut NodeEngine::start(&node_directory), &node_directory, scenario);
    assert_eq!(rust.len(), node.len());
    let differences: Vec<String> = rust
        .iter()
        .zip(&node)
        .filter(|((_, rust), (_, node))| rust != node)
        .map(|((label, rust), (_, node))| format!("{label}\n  rust: {rust}\n  node: {node}"))
        .collect();
    assert!(differences.is_empty(), "{kind}: {} of {} answers differ\n{}", differences.len(), rust.len(), differences.join("\n"));
}

fn login() -> Value {
    json!({ "serviceName": "Parity login", "loginId": "parity-user", "password": "synthetic-parity-entry", "notes": "memo", "url": "https://example.test/", "tags": ["a", "b"], "group": "仕事" })
}

fn additional_items() -> [Value; 3] {
    [
        json!({ "type": "apiKey", "serviceName": "Parity key", "apiKey": { "key": "synthetic-key", "keyId": "kid", "expiresOn": "2030-01-31" } }),
        json!({ "type": "creditCard", "serviceName": "Parity card", "card": { "number": "4111111111111111", "cardholder": "TEST", "expiryMonth": "2030-01", "securityCode": "123" } }),
        json!({ "type": "financial", "serviceName": "Parity bank", "financial": { "loginId": "bank-id", "loginPassword": "synthetic-bank", "tradingPassword": "synthetic-trade", "extraSecrets": [{ "label": "PIN", "value": "0000" }] } }),
    ]
}

/// The shared invalid-input cases from tests/input-contract-fixtures.mjs that Phase 1 covers.
fn contract_cases(scenario: &mut Scenario) {
    let fixtures = node(&["fixtures"]);
    for case in fixtures["invalid"].as_array().unwrap() {
        let method = match case["operation"].as_str().unwrap() {
            "createEntry" => "create",
            "generatePassword" => "generate",
            "unlockVault" => "unlock",
            "resetVault" => "reset",
            "setEntriesGroup" => "setGroup",
            _ => continue,
        };
        scenario.session(method, vec![case["payload"].clone()]);
    }
    scenario.session("create", vec![fixtures["valid"].clone()]);
}

fn throttling(scenario: &mut Scenario, password: &str) {
    for _ in 0..5 {
        scenario.session("unlock", vec![json!({ "masterPassword": WRONG })]);
    }
    scenario.session("unlock", vec![json!({ "masterPassword": password })]);
    scenario.0.push(Step::Wait(Duration::from_millis(1100)));
    scenario.session("unlock", vec![json!({ "masterPassword": WRONG })]);
    scenario.session("unlock", vec![json!({ "masterPassword": password })]);
    scenario.0.push(Step::Wait(Duration::from_millis(2100)));
    scenario.session("unlock", vec![json!({ "masterPassword": password })]);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn a_new_vault_answers_as_the_node_services_do() {
    let mut scenario = Scenario::default();
    let password = json!({ "masterPassword": PASSWORD });
    scenario
        .call("status", "status", vec![])
        .session("list", vec![])
        .call("setup with another session", "setup", vec![json!("another-session"), password.clone()])
        .call("setup without a session", "setup", vec![json!(UNDEFINED), password.clone()])
        .session("setup", vec![json!(UNDEFINED)])
        .session("setup", vec![json!(null)])
        .session("setup", vec![json!({ "masterPassword": "short" })])
        .session("setup", vec![json!({ "masterPassword": 1 })])
        .session("setup", vec![json!({ "masterPassword": PASSWORD, "extra": true })])
        .session("unlock", vec![password.clone()])
        .session("reset", vec![json!({ "confirmation": "RESET_ALL_DATA" })])
        .session("setup", vec![password.clone()])
        .call("status", "status", vec![])
        .session("setup", vec![password.clone()]);
    contract_cases(&mut scenario);
    let [api_key, _, _] = additional_items();
    scenario
        .session("create", vec![login()])
        .session("create", vec![api_key])
        .session("list", vec![])
        .session("get", vec![entry(0)])
        .session("get", vec![entry(1)])
        .session("get", vec![json!("missing")])
        .session("get", vec![json!(1)])
        .session("get", vec![json!("")])
        .session("get", vec![json!(UNDEFINED)])
        .session("update", vec![entry(1), json!({ "serviceName": "Changed", "loginId": "changed-user", "password": "synthetic-parity-changed" })])
        .session("update", vec![entry(1), json!({ "serviceName": "Changed again", "loginId": "changed-user", "password": "synthetic-parity-changed" })])
        .session("get", vec![entry(1)])
        .session("update", vec![json!("missing"), login()])
        .session("update", vec![entry(1), json!({})])
        .session("setGroup", vec![json!({ "ids": [entry(0), entry(1)], "group": "私用" })])
        .session("setGroup", vec![json!({ "ids": [entry(0)], "group": null })])
        .session("setGroup", vec![json!({ "ids": ["missing"], "group": "x" })])
        .session("list", vec![])
        .session("delete", vec![entry(0)])
        .session("delete", vec![entry(0)])
        .session("get", vec![entry(0)])
        .session("generate", vec![json!(UNDEFINED)])
        .session("generate", vec![json!(null)])
        .session("generate", vec![json!({ "length": 12, "includeSymbols": false })])
        .session("generate", vec![json!({ "length": 64, "includeUppercase": false, "includeNumbers": false })])
        .session("generate", vec![json!({ "length": 12.5 })])
        .session("generate", vec![json!({ "includeUppercase": false, "includeLowercase": false, "includeNumbers": false, "includeSymbols": false })])
        .session("activity", vec![])
        .call("activity with another session", "activity", vec![json!("another-session")])
        .call("lock with another session", "lock", vec![json!("another-session")])
        .session("lock", vec![])
        .session("list", vec![]);
    throttling(&mut scenario, PASSWORD);
    scenario
        .session("list", vec![])
        .session("reset", vec![json!({ "confirmation": "reset" })])
        .session("reset", vec![json!({ "confirmation": "RESET_ALL_DATA" })])
        .call("status", "status", vec![])
        .session("list", vec![])
        .session("setup", vec![password]);
    compare("empty", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn an_existing_legacy_vault_answers_as_the_node_services_do() {
    let password = node(&["prepare", "legacy", TemporaryDirectory::new().0.join("probe").to_str().unwrap()])["password"].clone();
    let mut scenario = Scenario::default();
    scenario
        .call("status", "status", vec![])
        .session("unlock", vec![json!({ "masterPassword": WRONG })])
        .session("unlock", vec![json!({ "masterPassword": password })])
        .session("list", vec![])
        .session("get", vec![entry(0)])
        .session("get", vec![entry(1)])
        .session("update", vec![entry(0), json!({ "serviceName": "Changed", "loginId": "changed", "password": "synthetic-parity-changed", "tags": ["x"] })])
        .session("create", vec![login()])
        .session("list", vec![])
        .session("get", vec![entry(0)])
        .session("lock", vec![])
        .session("unlock", vec![json!({ "masterPassword": password })])
        .session("get", vec![entry(0)]);
    compare("legacy", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn a_legacy_vault_from_before_password_changed_at_is_upgraded_as_in_node() {
    let mut scenario = Scenario::default();
    scenario
        .call("status", "status", vec![])
        .session("setup", vec![json!({ "masterPassword": PASSWORD })])
        .session("create", vec![login()])
        .session("list", vec![])
        .session("get", vec![entry(0)]);
    compare("legacy-old-schema", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn a_v2_vault_answers_as_the_node_services_do() {
    let password = node(&["prepare", "v2", TemporaryDirectory::new().0.join("probe").to_str().unwrap()])["password"].clone();
    let mut scenario = Scenario::default();
    scenario
        .call("status", "status", vec![])
        .session("reset", vec![json!({ "confirmation": "RESET_ALL_DATA" })])
        .session("setup", vec![json!({ "masterPassword": PASSWORD })])
        .session("unlock", vec![json!({ "masterPassword": password })])
        .session("list", vec![])
        .session("get", vec![entry(0)])
        .session("get", vec![entry(1)])
        .session("create", vec![login()]);
    for item in additional_items() {
        scenario.session("create", vec![item]);
    }
    scenario
        .session("list", vec![])
        .session("get", vec![entry(2)])
        .session("get", vec![entry(3)])
        .session("get", vec![entry(4)])
        .session("get", vec![entry(5)])
        .session("update", vec![entry(3), json!({ "type": "apiKey", "serviceName": "Changed key", "apiKey": { "key": "synthetic-changed" } })])
        .session("update", vec![entry(3), login()])
        .session("get", vec![entry(3)])
        .session("setGroup", vec![json!({ "ids": [entry(2), entry(4)], "group": "家族" })])
        .session("delete", vec![entry(5)])
        .session("get", vec![entry(5)])
        .session("list", vec![])
        .session("lock", vec![]);
    throttling(&mut scenario, password.as_str().unwrap());
    scenario.session("list", vec![]).session("reset", vec![json!({ "confirmation": "RESET_ALL_DATA" })]);
    compare("v2", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn a_vault_needing_recovery_is_refused_as_in_node() {
    let mut scenario = Scenario::default();
    scenario
        .call("status", "status", vec![])
        .session("setup", vec![json!({ "masterPassword": PASSWORD })])
        .session("unlock", vec![json!({ "masterPassword": PASSWORD })])
        .session("reset", vec![json!({ "confirmation": "RESET_ALL_DATA" })])
        .session("list", vec![])
        .session("generate", vec![json!({})]);
    compare("recovery", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn a_vault_changed_underneath_stops_as_in_node() {
    let mut scenario = Scenario::default();
    scenario.session("setup", vec![json!({ "masterPassword": PASSWORD })]).session("create", vec![login()]).session("list", vec![]);
    scenario.0.push(Step::Change(|directory| {
        std::fs::write(directory.join("vault-current.json"), r#"{"format":"CIPHER-VAULT-ACTIVE","version":1,"vaultId":"11111111-1111-4111-8111-111111111111"}"#).unwrap();
    }));
    scenario
        .session("list", vec![])
        .session("list", vec![])
        .call("status", "status", vec![])
        .session("unlock", vec![json!({ "masterPassword": PASSWORD })])
        .session("create", vec![login()]);
    compare("empty", &scenario);
}

// ---- Backups

fn backup_files() -> Value {
    node(&["backups"])
}

fn backup_payload(files: &Value, version: &str) -> Value {
    json!({ "passphrase": files["passphrase"], "content": files[version] })
}

fn export_cases(scenario: &mut Scenario, passphrase: &Value) {
    scenario
        .session("exportBackup", vec![json!(UNDEFINED)])
        .session("exportBackup", vec![json!({ "passphrase": "short" })])
        .session("exportBackup", vec![json!({ "passphrase": 12 })])
        .session("exportBackup", vec![json!({ "passphrase": passphrase, "content": "" })])
        .session("exportBackup", vec![json!({ "passphrase": passphrase })]);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn backups_of_a_legacy_vault_answer_as_the_node_services_do() {
    let files = backup_files();
    let passphrase = files["passphrase"].clone();
    let mut scenario = Scenario::default();
    scenario
        .session("exportBackup", vec![json!({ "passphrase": passphrase })])
        .session("setup", vec![json!({ "masterPassword": PASSWORD })])
        .session("exportBackup", vec![json!({ "passphrase": passphrase })])
        .session("restoreBackup", vec![json!({ "passphrase": passphrase })])
        .session("restoreBackup", vec![json!({ "passphrase": passphrase, "content": 1 })])
        .session("restoreBackup", vec![json!({ "passphrase": passphrase, "content": "not json" })])
        .session("restoreBackup", vec![json!({ "passphrase": passphrase, "content": "{\"version\":4}" })])
        .session("restoreBackup", vec![json!({ "passphrase": passphrase, "content": files["v1"].as_str().unwrap().replace("\"kdf\"", "\"extra\":1,\"kdf\"") })])
        .session("restoreBackup", vec![json!({ "passphrase": "synthetic-parity-wrong-passphrase", "content": files["v1"] })])
        .session("restoreBackup", vec![backup_payload(&files, "v3")])
        .session("restoreBackup", vec![backup_payload(&files, "v1")])
        .session("list", vec![])
        .session("get", vec![entry(0)])
        .session("get", vec![entry(1)])
        .session("restoreBackup", vec![backup_payload(&files, "v1")]);
    export_cases(&mut scenario, &passphrase);
    scenario.session("create", vec![login()]).session("exportBackup", vec![json!({ "passphrase": passphrase })]);
    compare("empty", &scenario);
}

#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn backups_of_a_v2_vault_answer_as_the_node_services_do() {
    let password = node(&["prepare", "v2", TemporaryDirectory::new().0.join("probe").to_str().unwrap()])["password"].clone();
    let files = backup_files();
    let mut scenario = Scenario::default();
    scenario
        .session("unlock", vec![json!({ "masterPassword": password })])
        .session("list", vec![])
        .session("restoreBackup", vec![backup_payload(&files, "v3")])
        .session("delete", vec![entry(0)])
        .session("delete", vec![entry(1)])
        .session("restoreBackup", vec![json!({ "passphrase": "synthetic-parity-wrong-passphrase", "content": files["v3"] })])
        .session("restoreBackup", vec![backup_payload(&files, "v3")])
        .session("list", vec![])
        .session("get", vec![entry(2)])
        .session("get", vec![entry(3)])
        .session("get", vec![entry(4)]);
    export_cases(&mut scenario, &files["passphrase"]);
    scenario
        .session("delete", vec![entry(2)])
        .session("delete", vec![entry(3)])
        .session("delete", vec![entry(4)])
        .session("restoreBackup", vec![backup_payload(&files, "v1")])
        .session("list", vec![])
        .session("exportBackup", vec![json!({ "passphrase": files["passphrase"] })])
        .session("restoreBackup", vec![backup_payload(&files, "v2")]);
    compare("v2", &scenario);
}

/// Each engine opens the file the other one wrote, with every kind of entry.
#[test]
#[ignore = "needs Node.js and the built API: npm run test:rust-parity"]
fn backups_written_by_each_engine_open_in_the_other() {
    let password = node(&["prepare", "v2", TemporaryDirectory::new().0.join("probe").to_str().unwrap()])["password"].clone();
    let passphrase = json!("synthetic-parity-cross-passphrase");
    let folder = TemporaryDirectory::new();
    let source = folder.0.join("source");
    node(&["prepare", "v2", source.to_str().unwrap()]);
    let (rust_directory, node_directory) = (folder.0.join("rust"), folder.0.join("node"));
    copy_directory(&source, &rust_directory);
    copy_directory(&source, &node_directory);
    let mut rust = RustEngine(Vault::open(&rust_directory).unwrap());
    let mut node_engine = NodeEngine::start(&node_directory);
    let mut written = Vec::new();
    for engine in [&mut rust as &mut dyn Engine, &mut node_engine] {
        let id = |engine: &mut dyn Engine| engine.call("status", &[])["ok"]["sessionId"].clone();
        let current = id(engine);
        assert!(engine.call("unlock", &[current, json!({ "masterPassword": password })]).get("ok").is_some());
        for item in additional_items() {
            let current = id(engine);
            assert!(engine.call("create", &[current, item]).get("ok").is_some());
        }
        let current = id(engine);
        let items = engine.call("list", &[current])["ok"]["items"].as_array().unwrap().clone();
        let entries: Vec<Value> = items.iter().map(|item| { let current = id(engine); engine.call("get", &[current, item["id"].clone()])["ok"].clone() }).collect();
        let current = id(engine);
        let content = engine.call("exportBackup", &[current, json!({ "passphrase": passphrase })])["ok"]["content"].clone();
        written.push((content, entries));
    }
    let (rust_file, rust_entries) = &written[0];
    let (node_file, node_entries) = &written[1];
    assert_eq!(node_engine.call("decodeBackup", &[rust_file.clone(), passphrase.clone()]), json!({ "ok": { "version": 3, "entries": rust_entries } }));
    assert_eq!(rust.call("decodeBackup", &[node_file.clone(), passphrase.clone()]), json!({ "ok": { "version": 3, "entries": node_entries } }));
}
