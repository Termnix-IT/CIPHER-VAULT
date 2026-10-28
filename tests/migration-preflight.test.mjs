import assert from "node:assert/strict";
import { after, afterEach, mock, test } from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { TextDecoder } from "node:util";
import crypto from "node:crypto";
import Database from "better-sqlite3";
import { verifyLegacyMigrationSource, LegacyPreflightError } from "../apps/api/dist/apps/api/src/migration/preflight.js";
import { PREFLIGHT_RAW_BYTES } from "../apps/api/dist/apps/api/src/migration/legacy-reader.js";
import { decodeBackupV1, encodeBackupV1, parseBackupV1 } from "../apps/api/dist/apps/api/src/crypto/backup-v1.js";
import { encryptLegacySecret } from "../apps/api/dist/apps/api/src/crypto/legacy-codec.js";
import { INPUT_LIMITS } from "../apps/api/dist/apps/api/src/lib/input-validation.js";
import * as storage from "../apps/api/dist/apps/api/src/db/database.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import { restoreBackup } from "../apps/api/dist/apps/api/src/services/backup-service.js";
import { vaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
const legacy = fixture.legacy;
const schema = readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8");
const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-preflight-")); let sequence = 0;
const file = () => path.join(root, `${++sequence}.sqlite`);
const credentials = () => ({ masterPassword: legacy.password, backupPassphrase: fixture.backupV1.passphrase });
const code = expected => error => {
  assert.ok(error instanceof LegacyPreflightError); assert.equal(error.code, expected);
  for (const secret of [root, legacy.password, legacy.keyHex, "preflight-secret-canary"]) assert.ok(!String(error).includes(secret));
  return true;
};
function raw(name, action) { const db = new Database(name); try { return action(db); } finally { db.close(); } }
function seed({ hmac = false, missing = [], encoding } = {}) {
  const name = file();
  raw(name, db => {
    if (encoding) db.pragma(`encoding = '${encoding}'`);
    db.exec(missing.reduce((sql, column) => sql.replace(new RegExp(`\\s*${column} TEXT,`), ""), schema));
    const metadata = legacy.metadata;
    db.prepare("INSERT INTO vault_metadata VALUES (1, ?, ?, ?, ?, ?)").run(metadata.passwordSalt, hmac ? legacy.verifier : metadata.passwordVerifier,
      hmac ? JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }) : metadata.kdfParams, metadata.createdAt, metadata.updatedAt);
    const columns = db.pragma("table_info(password_entries)").map(column => column.name);
    const insert = db.prepare(`INSERT INTO password_entries (${columns.join(",")}) VALUES (${columns.map(column => "@" + column).join(",")})`);
    for (const row of legacy.rows) insert.run(Object.fromEntries(columns.map(column => [column, row[column]])));
  });
  return name;
}
const digest = name => crypto.createHash("sha256").update(readFileSync(name)).digest("hex");
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); vaultSession.lock(); storage.closeDatabase(); });
after(() => {
  assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-preflight-"));
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("migration imports do not open, configure or create any vault", () => {
  const before = readdirSync(root), url = new URL("../apps/api/dist/apps/api/src/migration/preflight.js", import.meta.url).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)});`], {
    cwd: root, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: path.join(root, "must-not-exist") }, encoding: "utf8", timeout: 10000
  });
  assert.equal(result.status, 0, result.stdout + result.stderr); assert.deepEqual(readdirSync(root), before);
});

test("the shared v1 codec retains independent Python bytes in both directions", () => {
  const v = fixture.backupV1, key = Buffer.from(v.keyHex, "hex");
  mock.method(crypto, "randomBytes", length => { assert.equal(length, 12); return Buffer.from(v.envelope.iv, "base64"); }); syncBuiltinESMExports();
  try {
    assert.deepEqual(decodeBackupV1(parseBackupV1(JSON.stringify(v.envelope)), key), legacy.entries);
    assert.deepEqual(JSON.parse(encodeBackupV1(legacy.entries, key, Buffer.from(v.envelope.salt, "base64"))), v.envelope);
  } finally { key.fill(0); }
});

test("raw and HMAC legacy sources produce verified v1 backups without altering the source", async () => {
  for (const hmac of [false, true]) {
    const name = seed({ hmac }), before = digest(name), names = readdirSync(root);
    const result = await verifyLegacyMigrationSource(name, credentials());
    assert.ok(Object.isFrozen(result) && Object.isFrozen(result.report));
    assert.equal(result.report.entryCount, legacy.entries.length); assert.equal(result.report.backupVerified, true);
    assert.equal(result.report.verifierFormat, hmac ? "hmac-sha256-v1" : "raw-key");
    assert.equal(result.report.plaintextBytes, Buffer.byteLength(JSON.stringify({ version: 1, entries: legacy.entries })));
    assert.equal(result.report.backupBytes, Buffer.byteLength(result.backup.content));
    assert.equal(digest(name), before); assert.deepEqual(readdirSync(root), names);
    assert.ok(!JSON.stringify(result).includes(legacy.password)); assert.ok(!JSON.stringify(result).includes(legacy.keyHex));
    raw(name, db => assert.equal(db.prepare("SELECT password_verifier FROM vault_metadata").get().password_verifier, hmac ? legacy.verifier : legacy.metadata.passwordVerifier));
  }
});

test("the emitted backup restores through the real service into a different vault with every DTO field intact", async () => {
  const name = seed(), result = await verifyLegacyMigrationSource(name, credentials());
  const target = path.join(root, `target-${++sequence}`); mkdirSync(target);
  storage.openDatabase({ dataDirectory: target });
  await vault.setupVault({ masterPassword: "synthetic-independent-target-password" });
  await restoreBackup({ passphrase: credentials().backupPassphrase, content: result.backup.content });
  for (const original of legacy.entries) assert.deepEqual(entries.getEntryById(original.id), original);
});

test("old optional columns are projected as null without ALTER or metadata upgrade", async () => {
  for (const missing of [["group_name"], ["password_changed_at"], ["group_name", "password_changed_at"]]) {
    const name = seed({ missing }), before = digest(name);
    const result = await verifyLegacyMigrationSource(name, credentials());
    assert.deepEqual(result.report.missingLegacyColumns, missing);
    assert.equal(result.report.entryCount, 2); assert.equal(digest(name), before);
    raw(name, db => { const columns = db.pragma("table_info(password_entries)").map(column => column.name); for (const column of missing) assert.ok(!columns.includes(column)); });
  }
});

test("wrong passwords and pre-aborted requests leave the original untouched", async () => {
  const name = seed(), before = digest(name), controller = new AbortController(); controller.abort("preflight-secret-canary");
  await assert.rejects(verifyLegacyMigrationSource(name, { ...credentials(), masterPassword: "preflight-secret-canary" }), code("AUTHENTICATION_FAILED"));
  await assert.rejects(verifyLegacyMigrationSource(name, credentials(), { signal: controller.signal }), code("CANCELLED"));
  assert.equal(digest(name), before);
});

test("unknown schemas, KDF metadata, encoding and invalid metadata UTF-8 fail before derivation", async () => {
  const cases = [db => db.pragma("user_version = 2"), db => db.exec("CREATE TABLE unknown (id INTEGER)"),
    db => db.exec("UPDATE vault_metadata SET kdf_params = '{\"algorithm\":\"scrypt\",\"keyLength\":32,\"N\":1}'"),
    db => db.exec("UPDATE vault_metadata SET password_salt = CAST(x'ff' AS TEXT)"), db => db.exec("DELETE FROM vault_metadata")];
  let calls = 0; mock.method(crypto, "scrypt", () => { calls++; throw new Error("preflight-secret-canary"); }); syncBuiltinESMExports();
  for (const mutate of cases) {
    const name = seed(); raw(name, mutate); const before = digest(name);
    await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("INVALID_SOURCE")); assert.equal(digest(name), before);
  }
  const utf16 = seed({ encoding: "UTF-16le" });
  await assert.rejects(verifyLegacyMigrationSource(utf16, credentials()), code("INVALID_SOURCE")); assert.equal(calls, 0);
});

test("malformed IDs, stored types, tags, dates, ciphertext and UTF-8 are rejected rather than repaired", async () => {
  const cases = ["UPDATE password_entries SET id = 'invalid-id'", "UPDATE password_entries SET tags = '{bad-json}'",
    "UPDATE password_entries SET tags = '[\"ok\",1]'", "UPDATE password_entries SET tags = '[\"\\ud800\"]'",
    "UPDATE password_entries SET service_name = CAST(x'ff' AS TEXT)", "UPDATE password_entries SET login_id = CAST('blob' AS BLOB)",
    "UPDATE password_entries SET updated_at = 'invalid-date'", "UPDATE password_entries SET encrypted_password = '!!!!'",
    "UPDATE password_entries SET encrypted_notes = ''", "UPDATE password_entries SET id = NULL"];
  for (const sql of cases) {
    const name = seed(); raw(name, db => db.prepare(sql + " WHERE id = ?").run(legacy.entries[0].id)); const before = digest(name);
    await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("INVALID_SOURCE")); assert.equal(digest(name), before);
  }
  const name = seed(), iv = Buffer.alloc(12, 2), key = Buffer.from(legacy.keyHex, "hex");
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv); const data = Buffer.concat([cipher.update(Buffer.from([0xff])), cipher.final()]);
    raw(name, db => db.prepare("UPDATE password_entries SET encrypted_notes = ?").run(Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64")));
  } finally { key.fill(0); }
  await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("INVALID_SOURCE"));
});

test("historical long values retain whitespace, null, tag order and all original content", async () => {
  const name = seed(), key = Buffer.from(legacy.keyHex, "hex");
  try {
    raw(name, db => db.prepare(`UPDATE password_entries SET service_name = ?, encrypted_password = ?, encrypted_notes = ?, tags = ?, group_name = ?, url = ? WHERE id = ?`)
      .run("  " + "s".repeat(1500), encryptLegacySecret(key, "p".repeat(70000)), encryptLegacySecret(key, "n".repeat(300000)),
        JSON.stringify(Array.from({ length: 150 }, (_, index) => index % 2 ? "e\u0301" : "repeat")), "g".repeat(1300), "https://fixture.test/" + "x".repeat(9000), legacy.entries[0].id));
  } finally { key.fill(0); }
  const before = digest(name), result = await verifyLegacyMigrationSource(name, credentials());
  assert.equal(result.report.backupVerified, true); assert.equal(result.report.entryCount, 2); assert.equal(digest(name), before);
});

test("the plaintext boundary accepts exactly 11 MiB and refuses one extra byte without truncation", { timeout: 120000 }, async () => {
  const name = seed(), key = Buffer.from(legacy.keyHex, "hex"), values = structuredClone(legacy.entries);
  values[0].notes = "";
  const count = INPUT_LIMITS.backupPlaintextBytes - Buffer.byteLength(JSON.stringify({ version: 1, entries: values }));
  try {
    for (const excess of [0, 1]) {
      raw(name, db => db.prepare("UPDATE password_entries SET encrypted_notes = ? WHERE id = ?").run(encryptLegacySecret(key, "x".repeat(count + excess)), values[0].id));
      const before = digest(name);
      if (excess) await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("CAPACITY"));
      else assert.equal((await verifyLegacyMigrationSource(name, credentials())).report.plaintextBytes, INPUT_LIMITS.backupPlaintextBytes);
      assert.equal(digest(name), before);
    }
  } finally { key.fill(0); }
});

test("entry-count and raw-byte limits reject before KDF or unbounded row loading", async () => {
  const large = seed(); raw(large, db => db.prepare("UPDATE password_entries SET encrypted_notes = printf('%.*c', ?, 'A')").run(PREFLIGHT_RAW_BYTES + 1));
  const many = seed(); raw(many, db => db.exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < 9999)
    INSERT INTO password_entries (id, service_name, login_id, encrypted_password, tags, created_at, updated_at)
    SELECT printf('%036x',x), 'fixture', 'fixture', 'fixture', '[]', '2025-01-01T00:00:00.000Z', '2025-01-01T00:00:00.000Z' FROM n`));
  let calls = 0; mock.method(crypto, "scrypt", () => { calls++; throw new Error("preflight-secret-canary"); }); syncBuiltinESMExports();
  for (const name of [large, many]) { const before = digest(name); await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("CAPACITY")); assert.equal(digest(name), before); }
  assert.equal(calls, 0);
});

test("passwords, all derived keys and decoded buffers are wiped when the verified result is returned", async () => {
  const name = seed(), passwords = [], keys = [], decoded = [], derive = crypto.scrypt, decode = TextDecoder.prototype.decode;
  mock.method(crypto, "scrypt", (password, salt, size, options, callback) => {
    if (Buffer.isBuffer(password)) passwords.push(password);
    return derive(password, salt, size, options, (error, key) => { if (key) keys.push(key); callback(error, key); });
  }); syncBuiltinESMExports();
  mock.method(TextDecoder.prototype, "decode", function (value, ...rest) { if (Buffer.isBuffer(value)) decoded.push(value); return decode.call(this, value, ...rest); });
  await verifyLegacyMigrationSource(name, credentials());
  assert.equal(keys.length, 4); assert.equal(passwords.length, 4);
  assert.ok([...keys, ...passwords, ...decoded].every(bytes => bytes.every(value => value === 0)));
});

test("a cancelled native KDF retains the operation slot, wipes its late result and allows a later retry", async () => {
  const name = seed(), controller = new AbortController(); let finish, encoded, derived;
  mock.method(crypto, "scrypt", (password, _salt, _size, _options, callback) => {
    encoded = password; finish = () => { derived = Buffer.from(legacy.keyHex, "hex"); callback(null, derived); };
  }); syncBuiltinESMExports();
  const pending = verifyLegacyMigrationSource(name, credentials(), { signal: controller.signal });
  const rejected = assert.rejects(pending, code("CANCELLED")); controller.abort();
  try { await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("BUSY")); }
  finally { finish(); }
  await rejected; assert.ok(encoded.every(value => value === 0)); assert.ok(derived.every(value => value === 0));
  mock.restoreAll(); syncBuiltinESMExports(); assert.equal((await verifyLegacyMigrationSource(name, credentials())).report.backupVerified, true);
});

test("native failures are redacted, wipe supplied late keys and release the operation slot", async () => {
  const name = seed(); let held, encoded;
  mock.method(crypto, "scrypt", (password, _salt, _size, _options, callback) => {
    encoded = password; held = Buffer.alloc(32, 7); callback(new Error("preflight-secret-canary"), held);
  }); syncBuiltinESMExports();
  await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("FAILED"));
  assert.ok(held.every(value => value === 0) && encoded.every(value => value === 0));
  mock.restoreAll(); syncBuiltinESMExports(); await verifyLegacyMigrationSource(name, credentials());
});

test("WAL commits during the read snapshot invalidate the report", async () => {
  const name = seed(), writer = new Database(name), derive = crypto.scrypt; let first = true;
  try {
    writer.pragma("journal_mode = WAL");
    mock.method(crypto, "scrypt", (...args) => {
      if (first) { first = false; writer.prepare("UPDATE password_entries SET service_name = ?").run("changed-by-other-writer"); }
      return derive(...args);
    }); syncBuiltinESMExports();
    await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("SOURCE_CHANGED"));
    assert.equal(writer.prepare("SELECT service_name FROM password_entries LIMIT 1").get().service_name, "changed-by-other-writer");
  } finally { writer.close(); }
});

test("a restored-field mismatch produces no verified result and preserves the original", async () => {
  const name = seed(), before = digest(name), prepare = Database.prototype.prepare;
  mock.method(Database.prototype, "prepare", function (sql) {
    const statement = prepare.call(this, sql);
    if (this.memory && sql.startsWith("INSERT INTO password_entries")) return { run: value => statement.run({ ...value, group_name: "preflight-secret-canary" }) };
    return statement;
  });
  await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("BACKUP_MISMATCH")); assert.equal(digest(name), before);
});

test("preflight leaves an independently unlocked live provider and its key untouched", async () => {
  const name = seed(), target = path.join(root, `live-${++sequence}`); mkdirSync(target);
  const provider = storage.openDatabase({ dataDirectory: target });
  await vault.setupVault({ masterPassword: "synthetic-live-fixture-password" });
  const state = vaultSession.getState(), liveKey = vaultSession.requireKey(), before = Buffer.from(liveKey);
  try {
    await verifyLegacyMigrationSource(name, credentials());
    assert.equal(storage.getDatabase(), provider); assert.deepEqual(vaultSession.getState(), state); assert.deepEqual(liveKey, before);
  } finally { before.fill(0); }
});

test("configured empty vaults are verified, while invalid inputs never start a KDF or create a file", async () => {
  const name = seed(); raw(name, db => db.exec("DELETE FROM password_entries"));
  assert.equal((await verifyLegacyMigrationSource(name, credentials())).report.entryCount, 0);
  let calls = 0; mock.method(crypto, "scrypt", () => { calls++; throw new Error("preflight-secret-canary"); }); syncBuiltinESMExports();
  const absent = path.join(root, "absent.sqlite");
  for (const invalid of [{ masterPassword: null }, { masterPassword: "invalid\ud800" }, { backupPassphrase: "short" }, { unexpected: true }]) {
    await assert.rejects(verifyLegacyMigrationSource(absent, { ...credentials(), ...invalid }), code("INVALID_INPUT"));
  }
  await assert.rejects(verifyLegacyMigrationSource(absent, credentials(), { signal: { aborted: false } }), code("INVALID_INPUT"));
  assert.equal(calls, 0); assert.ok(!readdirSync(root).includes("absent.sqlite"));
});

test("the backup reader derives from the emitted Salt and refuses a mismatched file header", async () => {
  const name = seed(), before = digest(name), stringify = JSON.stringify;
  mock.method(JSON, "stringify", (value, ...rest) => {
    if (value?.format === "CIPHER-VAULT") {
      const salt = Buffer.from(value.salt, "base64"); salt[0] ^= 1;
      return stringify({ ...value, salt: salt.toString("base64") }, ...rest);
    }
    return stringify(value, ...rest);
  });
  await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("FAILED")); assert.equal(digest(name), before);
});

test("scratch initialization failures close the source, release the gate and never leave target files", async () => {
  const name = seed(), before = digest(name), names = readdirSync(root), exec = Database.prototype.exec;
  mock.method(Database.prototype, "exec", function (sql) {
    if (this.memory && sql.includes("CREATE TABLE")) throw new Error("preflight-secret-canary");
    return exec.call(this, sql);
  });
  await assert.rejects(verifyLegacyMigrationSource(name, credentials()), code("FAILED"));
  assert.equal(digest(name), before); assert.deepEqual(readdirSync(root), names);
  mock.restoreAll(); syncBuiltinESMExports(); await verifyLegacyMigrationSource(name, credentials());
});
