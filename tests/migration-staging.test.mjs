import assert from "node:assert/strict";
import { after, afterEach, mock, test } from "node:test";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire, syncBuiltinESMExports } from "node:module";
import crypto from "node:crypto";
import Database from "better-sqlite3";
import { stageLegacyVault, MigrationStageError } from "../apps/api/dist/apps/api/src/migration/staging.js";
import { openV2Store } from "../apps/api/dist/apps/api/src/db/v2-store.js";
import { openEntry, unwrapRootKey } from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";
import { verifyBackupRecovery } from "../apps/api/dist/apps/api/src/migration/backup-recovery.js";
import * as storage from "../apps/api/dist/apps/api/src/db/database.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import { vaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const require = createRequire(import.meta.url);
const fixture = JSON.parse(fs.readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
const legacy = fixture.legacy, schema = fs.readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8");
const root = fs.mkdtempSync(path.join(tmpdir(), "cipher-vault-staging-")); let sequence = 0;
const credentials = () => ({ masterPassword: legacy.password, newMasterPassword: "synthetic-new-master-🔐-password",
  confirmNewMasterPassword: "synthetic-new-master-🔐-password", backupPassphrase: fixture.backupV1.passphrase });
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function raw(file, action) { const db = new Database(file, { timeout: 0 }); try { return action(db); } finally { db.close(); } }
function seed({ hmac = false, missing = [], empty = false } = {}) {
  const directory = path.join(root, `case-${++sequence}`); fs.mkdirSync(directory);
  const source = path.join(directory, "password-manager.db"), parent = path.join(directory, "vaults"); fs.mkdirSync(parent);
  raw(source, db => {
    db.exec(missing.reduce((sql, column) => sql.replace(new RegExp(`\\s*${column} TEXT,`), ""), schema));
    const m = legacy.metadata;
    db.prepare("INSERT INTO vault_metadata VALUES (1, ?, ?, ?, ?, ?)").run(m.passwordSalt, hmac ? legacy.verifier : m.passwordVerifier,
      hmac ? JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }) : m.kdfParams, m.createdAt, m.updatedAt);
    const columns = db.pragma("table_info(password_entries)").map(column => column.name);
    const insert = db.prepare(`INSERT INTO password_entries (${columns.join(",")}) VALUES (${columns.map(column => "@" + column).join(",")})`);
    if (!empty) for (const row of legacy.rows) insert.run(Object.fromEntries(columns.map(column => [column, row[column]])));
  });
  return { directory, source, parent };
}
const code = expected => error => {
  assert.ok(error instanceof MigrationStageError); assert.equal(error.code, expected);
  for (const secret of [root, legacy.password, legacy.keyHex, credentials().newMasterPassword, "staging-secret-canary"])
    assert.ok(!String(error).includes(secret));
  return true;
};
const stage = (fixture, input = credentials(), options) => stageLegacyVault(fixture.source, fixture.parent, input, options);
const artifact = f => path.join(f.parent, fs.readdirSync(f.parent)[0]);
async function readV2(result) {
  const store = openV2Store(result.files.database, { vaultId: result.vaultId, keyId: result.keyId, slotRevision: 1 });
  let key;
  try {
    key = await unwrapRootKey(store.readPasswordSlot(), credentials().newMasterPassword,
      { vaultId: result.vaultId, keyId: result.keyId, slotRevision: 1 });
    return store.listEntryContexts().map(context => {
      const plain = openEntry(key, store.readEntry(context.entryId), context);
      try { return JSON.parse(plain.toString("utf8")); } finally { plain.fill(0); }
    });
  } finally { key?.fill(0); store.close(); }
}
function unchanged(f, before) {
  assert.equal(hash(f.source), before);
  raw(f.source, db => { db.exec("BEGIN IMMEDIATE; ROLLBACK"); });
  assert.ok(!fs.existsSync(path.join(f.directory, "vault-current.json")));
}
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); vaultSession.lock(); storage.closeDatabase(); });
after(() => {
  assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-staging-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("staging imports have no filesystem, provider or environment side effects", () => {
  const before = fs.readdirSync(root), url = new URL("../apps/api/dist/apps/api/src/migration/staging.js", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)})`], {
    cwd: root, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: path.join(root, "not-created") }, encoding: "utf8", timeout: 10000
  });
  assert.equal(child.status, 0, child.stdout + child.stderr); assert.deepEqual(fs.readdirSync(root), before);
});

test("raw/HMAC sources stage fresh whole-entry ciphertext, flushed recovery files and no activation", async () => {
  for (const hmac of [false, true]) {
    const f = seed({ hmac }), before = hash(f.source), keys = [], passwords = [], roots = [];
    const scrypt = crypto.scrypt, random = crypto.randomBytes;
    mock.method(crypto, "randomBytes", length => { const bytes = random(length); if (length === 32) roots.push(bytes); return bytes; });
    mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
      passwords.push(password);
      return scrypt(password, salt, length, options, (error, key) => { if (key) keys.push(key); callback(error, key); });
    }); syncBuiltinESMExports();
    const result = await stage(f);
    assert.equal(result.state, "v2-verified"); assert.ok(Object.isFrozen(result) && Object.isFrozen(result.files));
    assert.equal(result.entryCount, legacy.entries.length);
    assert.deepEqual(fs.readdirSync(result.files.directory).sort(), ["legacy.cvault", "legacy.sqlite", "v2-export.cvault", "vault.sqlite"]);
    assert.equal(path.dirname(result.files.directory), f.parent); assert.equal(path.basename(result.files.directory), result.vaultId);
    unchanged(f, before);
    assert.ok(keys.length >= 10 && keys.every(key => key.every(byte => byte === 0)));
    assert.ok(passwords.every(password => !Buffer.isBuffer(password) || password.every(byte => byte === 0)));
    assert.ok(roots.length >= 4 && roots.every(key => key.every(byte => byte === 0)));
    crypto.scrypt.mock.restore(); crypto.randomBytes.mock.restore(); syncBuiltinESMExports();
    assert.deepEqual(await readV2(result), legacy.entries);
    for (const name of [result.files.backup, result.files.exportBackup]) {
      const pass = Buffer.from(credentials().backupPassphrase);
      try { assert.deepEqual(await verifyBackupRecovery(fs.readFileSync(name, "utf8"), pass, () => {}), legacy.entries); }
      finally { pass.fill(0); }
    }
    const bytes = fs.readFileSync(result.files.database);
    for (const entry of legacy.entries) for (const value of [entry.serviceName, entry.loginId, entry.password, entry.notes])
      if (value && Buffer.byteLength(value) > 6) assert.equal(bytes.includes(Buffer.from(value)), false);
  }
});

test("a pre-existing crash WAL is included in recovery without checkpointing or changing the source files", async () => {
  const f = seed();
  const child = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1]);d.pragma('journal_mode=WAL');d.exec("UPDATE password_entries SET service_name='crash-WAL-value'");process.exit(0)`, f.source], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stdout + child.stderr);
  const before = hash(f.source), walBefore = hash(f.source + "-wal"), result = await stage(f);
  assert.equal(hash(f.source), before); assert.equal(hash(f.source + "-wal"), walBefore);
  const expected = structuredClone(legacy.entries); expected.forEach(entry => { entry.serviceName = "crash-WAL-value"; });
  assert.deepEqual(await readV2(result), expected);
});

test("DELETE and WAL locks block independent process writers throughout snapshot and release after success", async () => {
  for (const mode of ["DELETE", "WAL"]) {
    const f = seed(), writer = new Database(f.source, { timeout: 0 }); writer.pragma(`journal_mode=${mode}`);
    if (mode === "WAL") writer.prepare("UPDATE password_entries SET service_name='only-in-WAL' WHERE id=?").run(legacy.entries[0].id);
    const before = hash(f.source), backup = Database.prototype.backup; let checked = false;
    mock.method(Database.prototype, "backup", function (...args) {
      assert.throws(() => writer.exec("UPDATE password_entries SET login_id='blocked'"), error => error.code === "SQLITE_BUSY");
      const child = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1],{timeout:0});try{d.exec("UPDATE password_entries SET login_id='blocked'");process.exitCode=2}catch(e){if(e.code!=='SQLITE_BUSY')throw e}finally{d.close()}`, f.source], { encoding: "utf8", timeout: 10000 });
      assert.equal(child.status, 0, child.stdout + child.stderr); checked = true;
      return backup.apply(this, args);
    });
    try {
      const result = await stage(f); assert.equal(checked, true); unchanged(f, before);
      const expected = structuredClone(legacy.entries); if (mode === "WAL") expected[0].serviceName = "only-in-WAL";
      assert.deepEqual(await readV2(result), expected);
      raw(result.files.snapshot, db => assert.equal(db.pragma("journal_mode", { simple: true }), "delete"));
      writer.exec("BEGIN IMMEDIATE; ROLLBACK");
    } finally { Database.prototype.backup.mock.restore(); writer.close(); }
  }
});

test("password reuse, confirmation mismatch, invalid Unicode, options and pre-abort create no artifacts", async () => {
  const f = seed(), before = hash(f.source);
  for (const change of [
    { newMasterPassword: legacy.password, confirmNewMasterPassword: legacy.password },
    { confirmNewMasterPassword: "mismatch" }, { newMasterPassword: "short", confirmNewMasterPassword: "short" },
    { newMasterPassword: "unpaired-\ud800-password", confirmNewMasterPassword: "unpaired-\ud800-password" },
    { masterPassword: Buffer.from(legacy.password) },
    { extra: true }
  ]) await assert.rejects(stage(f, { ...credentials(), ...change }), code("INVALID_INPUT"));
  await assert.rejects(stage(f, credentials(), { signal: true }), code("INVALID_INPUT"));
  await assert.rejects(stage(f, credentials(), { signal: AbortSignal.abort() }), code("CANCELLED"));
  assert.deepEqual(fs.readdirSync(f.parent), []); unchanged(f, before);
});

test("wrong legacy password, unsupported schema, active writer and snapshot capacity stop before artifacts", async () => {
  const f = seed(), before = hash(f.source);
  await assert.rejects(stage(f, { ...credentials(), masterPassword: "incorrect-master" }), code("AUTHENTICATION_FAILED"));
  const writer = new Database(f.source); writer.exec("BEGIN IMMEDIATE");
  try { await assert.rejects(stage(f), code("LOCKED")); } finally { writer.exec("ROLLBACK"); writer.close(); }
  unchanged(f, before); assert.deepEqual(fs.readdirSync(f.parent), []);
  raw(f.source, db => db.exec("CREATE TABLE unknown(value TEXT)")); const unsupported = hash(f.source);
  await assert.rejects(stage(f), code("INVALID_SOURCE")); unchanged(f, unsupported);
  const large = seed(); raw(large.source, db => {
    db.exec("UPDATE password_entries SET encrypted_notes=zeroblob(67108864); DELETE FROM password_entries");
  });
  await assert.rejects(stage(large), code("CAPACITY")); assert.deepEqual(fs.readdirSync(large.parent), []);
});

test("native cancellation retains the busy gate until callback and wipes late keys", async () => {
  const f = seed(), before = hash(f.source), abort = new AbortController(), scrypt = crypto.scrypt;
  let release, started;
  const ready = new Promise(resolve => { started = resolve; });
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
    return scrypt(password, salt, length, options, (error, key) => { release = () => { callback(error, key); return key; }; started(); });
  }); syncBuiltinESMExports();
  const pending = stage(f, credentials(), { signal: abort.signal }); await ready; abort.abort();
  await assert.rejects(stage(f), code("BUSY"));
  const key = release(); await assert.rejects(pending, code("CANCELLED")); assert.ok(key.every(byte => byte === 0));
  assert.deepEqual(fs.readdirSync(f.parent), []); unchanged(f, before);
});

test("a partial backup write is retained and fsync failure never creates the v2 DB", async () => {
  const f = seed(), before = hash(f.source);
  mock.method(fs, "fsyncSync", () => { throw new Error("staging-secret-canary disk full"); }); syncBuiltinESMExports();
  await assert.rejects(stage(f), code("IO_FAILED"));
  assert.deepEqual(fs.readdirSync(artifact(f)), ["legacy.cvault"]); unchanged(f, before);
});

test("a failed v2 file flush cannot produce a verified result", async () => {
  const f = seed(), before = hash(f.source), sync = fs.fsyncSync; let calls = 0;
  mock.method(fs, "fsyncSync", descriptor => {
    if (++calls === 3) throw new Error("staging-secret-canary flush failure");
    return sync(descriptor);
  }); syncBuiltinESMExports();
  await assert.rejects(stage(f), code("IO_FAILED")); unchanged(f, before); assert.equal(calls, 3);
  assert.equal(fs.existsSync(path.join(artifact(f), "vault.sqlite")), true);
  assert.equal(fs.existsSync(path.join(artifact(f), "v2-export.cvault")), false);
});

test("root collision and late native wrap failure wipe keys and leave only recovery files", async () => {
  for (const collision of [true, false]) {
    const f = seed(), before = hash(f.source), random = crypto.randomBytes, scrypt = crypto.scrypt, roots = [];
    let lateKey;
    mock.method(crypto, "randomBytes", length => {
      const bytes = collision && length === 32 ? Buffer.from(legacy.keyHex, "hex") : random(length);
      if (length === 32) roots.push(bytes); return bytes;
    });
    if (!collision) mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
      const wrapping = options.N === 131072 && fs.readdirSync(f.parent).some(name => fs.existsSync(path.join(f.parent, name, "legacy.sqlite")));
      if (!wrapping) return scrypt(password, salt, length, options, callback);
      lateKey = Buffer.alloc(32, 37); setImmediate(() => callback(new Error("staging-secret-canary native failure"), lateKey));
    });
    syncBuiltinESMExports();
    await assert.rejects(stage(f), code(collision ? "VERIFICATION_FAILED" : "IO_FAILED")); unchanged(f, before);
    assert.ok(roots.every(key => key.every(byte => byte === 0)));
    if (lateKey) assert.ok(lateKey.every(byte => byte === 0));
    assert.deepEqual(fs.readdirSync(artifact(f)).sort(), ["legacy.cvault", "legacy.sqlite"]);
    crypto.randomBytes.mock.restore(); crypto.scrypt.mock?.restore(); syncBuiltinESMExports();
  }
});

test("a failed target close is retried during cleanup and never reports success", async () => {
  const f = seed(), before = hash(f.source), close = Database.prototype.close; let injected = false, retried = false;
  mock.method(Database.prototype, "close", function () {
    if (path.basename(this.name) === "vault.sqlite") {
      if (!injected) { injected = true; throw new Error("staging-secret-canary close failure"); }
      retried = true;
    }
    return close.call(this);
  });
  await assert.rejects(stage(f), code("IO_FAILED")); assert.ok(injected && retried); unchanged(f, before);
  await assert.rejects(stage(f, { ...credentials(), confirmNewMasterPassword: "invalid" }), code("INVALID_INPUT"));
});

test("snapshot failure retains the verified encrypted backup and releases the source lock", async () => {
  const f = seed(), before = hash(f.source);
  mock.method(Database.prototype, "backup", async () => { throw new Error("staging-secret-canary snapshot failure"); });
  await assert.rejects(stage(f), code("IO_FAILED")); unchanged(f, before);
  assert.deepEqual(fs.readdirSync(artifact(f)).sort(), ["legacy.cvault", "legacy.sqlite"]);
  const pass = Buffer.from(credentials().backupPassphrase);
  try { assert.deepEqual(await verifyBackupRecovery(fs.readFileSync(path.join(artifact(f), "legacy.cvault"), "utf8"), pass, () => {}), legacy.entries); }
  finally { pass.fill(0); }
});

test("a snapshot metadata mismatch rejects staging before any new ciphertext", async () => {
  const f = seed(), before = hash(f.source), backup = Database.prototype.backup;
  mock.method(Database.prototype, "backup", async function (destination, options) {
    const result = await backup.call(this, destination, options);
    raw(destination, db => db.exec("UPDATE vault_metadata SET updated_at='2030-01-01T00:00:00.000Z'")); return result;
  });
  await assert.rejects(stage(f), code("VERIFICATION_FAILED")); unchanged(f, before);
  assert.equal(fs.existsSync(path.join(artifact(f), "vault.sqlite")), false);
});

test("tampering with the saved backup is caught after file read and before snapshot/staging", async () => {
  const f = seed(), before = hash(f.source), read = fs.readFileSync;
  mock.method(fs, "readFileSync", (file, options) => {
    const content = read(file, options);
    if (typeof file !== "number") return content;
    const value = JSON.parse(content), data = Buffer.from(value.data, "base64"); data[0] ^= 1; value.data = data.toString("base64");
    return JSON.stringify(value);
  }); syncBuiltinESMExports();
  await assert.rejects(stage(f), code("IO_FAILED")); unchanged(f, before);
  assert.deepEqual(fs.readdirSync(artifact(f)), ["legacy.cvault"]);
});

test("entry persistence failure retains nonce reservation and never reuses or overwrites failed staging", async () => {
  const f = seed(), before = hash(f.source), prepare = Database.prototype.prepare;
  mock.method(Database.prototype, "prepare", function (sql) {
    const statement = prepare.call(this, sql);
    if (sql.startsWith("INSERT INTO vault_entries")) statement.run = () => { throw new Error("staging-secret-canary disk full"); };
    return statement;
  });
  await assert.rejects(stage(f), code("IO_FAILED")); unchanged(f, before);
  Database.prototype.prepare.mock.restore();
  const directory = artifact(f), file = path.join(directory, "vault.sqlite"), beforePartial = hash(file);
  raw(file, db => { assert.equal(db.prepare("SELECT COUNT(*) n FROM vault_nonces").get().n, 1); assert.equal(db.prepare("SELECT COUNT(*) n FROM vault_entries").get().n, 0); });
  const uuid = path.basename(directory), random = crypto.randomUUID; let count = 0;
  mock.method(crypto, "randomUUID", () => count++ === 0 ? uuid : random()); syncBuiltinESMExports();
  await assert.rejects(stage(f), code("EXISTS")); assert.equal(hash(file), beforePartial); unchanged(f, before);
});

test("close/reopen authenticates every stored entry and rejects valid-shaped ciphertext tampering", async () => {
  const f = seed(), before = hash(f.source), close = Database.prototype.close; let changed = false;
  mock.method(Database.prototype, "close", function () {
    const file = this.name, result = close.call(this);
    if (!changed && path.basename(file) === "vault.sqlite") {
      changed = true; raw(file, db => {
        const row = db.prepare("SELECT entry_id,envelope FROM vault_entries LIMIT 1").get(), envelope = JSON.parse(row.envelope);
        const bytes = Buffer.from(envelope.data, "base64"); bytes[0] ^= 1; envelope.data = bytes.toString("base64");
        db.prepare("UPDATE vault_entries SET envelope=? WHERE entry_id=?").run(JSON.stringify(envelope), row.entry_id);
      });
    }
    return result;
  });
  await assert.rejects(stage(f), code("VERIFICATION_FAILED")); assert.equal(changed, true); unchanged(f, before);
  assert.equal(fs.existsSync(path.join(artifact(f), "v2-export.cvault")), false);
});

test("cancellation during export verification keeps all recovery files but returns no verified result", async () => {
  const f = seed(), before = hash(f.source), abort = new AbortController(), scrypt = crypto.scrypt; let cancelled = false;
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, key) => {
    if (fs.readdirSync(f.parent).some(name => fs.existsSync(path.join(f.parent, name, "v2-export.cvault")))) { abort.abort(); cancelled = true; }
    callback(error, key);
  })); syncBuiltinESMExports();
  await assert.rejects(stage(f, credentials(), { signal: abort.signal }), code("CANCELLED"));
  assert.equal(cancelled, true); unchanged(f, before); assert.equal(fs.readdirSync(artifact(f)).length, 4);
});

test("old optional columns, historical whitespace/length and configured-empty vaults remain lossless", async () => {
  const f = seed({ missing: ["group_name", "password_changed_at"] }), expected = structuredClone(legacy.entries);
  expected.forEach(entry => { entry.group = null; entry.passwordChangedAt = null; });
  expected[0].serviceName = "  historical-" + "長".repeat(1200) + "  "; expected[0].tags = ["  unchanged  ", "second", "  unchanged  "];
  raw(f.source, db => db.prepare("UPDATE password_entries SET service_name=?,tags=? WHERE id=?")
    .run(expected[0].serviceName, JSON.stringify(expected[0].tags), expected[0].id));
  const before = hash(f.source), result = await stage(f); unchanged(f, before); assert.deepEqual(await readV2(result), expected);
  const empty = seed({ empty: true }), emptyResult = await stage(empty); assert.equal(emptyResult.entryCount, 0);
  assert.deepEqual(await readV2(emptyResult), []);
});

test("an independent active legacy provider and Session are unchanged by staging", async () => {
  const current = path.join(root, `provider-${++sequence}`); fs.mkdirSync(current);
  storage.openDatabase({ dataDirectory: current }); await vault.setupVault({ masterPassword: "synthetic-current-master" });
  const database = storage.getDatabase(), sessionId = vaultSession.requireUnlocked(), key = Buffer.from(vaultSession.requireKey()), f = seed();
  await stage(f);
  assert.equal(storage.getDatabase(), database); assert.equal(vaultSession.requireUnlocked(), sessionId);
  assert.deepEqual(vaultSession.requireKey(), key); key.fill(0);
});

test("abrupt process exit after reservation leaves source/recovery intact and a non-resumable partial target", () => {
  const f = seed(), before = hash(f.source), url = new URL("../apps/api/dist/apps/api/src/migration/staging.js", import.meta.url).href;
  const script = `import {createRequire} from 'node:module';const require=createRequire(import.meta.url);const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const prepare=D.prototype.prepare;D.prototype.prepare=function(sql){const s=prepare.call(this,sql);if(sql.startsWith('INSERT INTO vault_entries'))s.run=()=>process.exit(79);return s};const {stageLegacyVault}=await import(${JSON.stringify(url)});await stageLegacyVault(process.argv[1],process.argv[2],JSON.parse(process.argv[3]));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "--eval", script, f.source, f.parent, JSON.stringify(credentials())], { encoding: "utf8", timeout: 30000 });
  assert.equal(child.status, 79, child.stdout + child.stderr); unchanged(f, before);
  raw(path.join(artifact(f), "vault.sqlite"), db => {
    assert.equal(db.prepare("SELECT COUNT(*) n FROM vault_nonces").get().n, 1);
    assert.equal(db.prepare("SELECT COUNT(*) n FROM vault_entries").get().n, 0);
  });
  assert.deepEqual(fs.readdirSync(artifact(f)).sort(), ["legacy.cvault", "legacy.sqlite", "vault.sqlite"]);
});
