import assert from "node:assert/strict";
import { after, afterEach, mock, test } from "node:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import * as storage from "../apps/api/dist/apps/api/src/db/database.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import { vaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-storage-"));
const schema = readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8");
const previousDirectory = process.env.PASSWORD_MANAGER_DATA_DIR;
let number = 0;
const directory = () => path.join(root, String(++number));
const filename = dir => path.join(dir, "password-manager.db");
const code = expected => error => {
  assert.ok(error instanceof storage.VaultStorageError);
  assert.equal(error.code, expected);
  assert.ok(!String(error).includes(root));
  assert.ok(!String(error).includes("synthetic-storage-canary"));
  return true;
};
function seed(dir, sql = schema) {
  mkdirSync(dir, { recursive: true });
  const database = new Database(filename(dir));
  try { database.exec(sql); } finally { database.close(); }
}
const oldSchema = schema.replace(/\s*group_name TEXT,/, "").replace(/\s*password_changed_at TEXT,/, "");

afterEach(() => {
  mock.restoreAll();
  vaultSession.lock();
  storage.closeDatabase();
  if (previousDirectory === undefined) delete process.env.PASSWORD_MANAGER_DATA_DIR;
  else process.env.PASSWORD_MANAGER_DATA_DIR = previousDirectory;
});
after(() => {
  assert.equal(path.dirname(root), path.resolve(tmpdir()));
  assert.ok(path.basename(root).startsWith("cipher-vault-storage-"));
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("storage, router and service imports neither open nor create a database", () => {
  const dir = directory(); mkdirSync(dir);
  const marker = path.join(dir, "synthetic-storage-canary"); writeFileSync(marker, "synthetic sentinel");
  const modules = ["db/database", "routes/router", "services/vault-service", "services/entry-service", "services/backup-service", "services/audit-service"]
    .map(name => new URL(`../apps/api/dist/apps/api/src/${name}.js`, import.meta.url).href);
  const script = `for (const url of ${JSON.stringify(modules)}) await import(url); const storage = await import(${JSON.stringify(modules[0])}); try {storage.getDatabase(); process.exit(2);} catch(error) {if(error.code !== 'NOT_OPEN') throw error;}`;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
    cwd: dir, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: marker }, encoding: "utf8", timeout: 15000
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(readdirSync(dir), ["synthetic-storage-canary"]);
  assert.equal(readFileSync(marker, "utf8"), "synthetic sentinel");
});

test("missing-file inspection and prohibited creation leave directories untouched", () => {
  const dir = directory();
  assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "missing", needsMigration: false });
  for (const options of [{ readonly: true }, { createIfMissing: false }]) {
    assert.throws(() => storage.openDatabase({ dataDirectory: dir, ...options }), code("NOT_FOUND"));
    assert.equal(existsSync(dir), false);
    assert.throws(() => storage.getDatabase(), code("NOT_OPEN"));
  }
});

test("explicit open initializes a new legacy schema and does not replace a live connection", () => {
  const dir = directory(), other = directory();
  const database = storage.openDatabase({ dataDirectory: dir });
  assert.equal(storage.getDatabase(), database);
  assert.equal(storage.getDatabasePath(), filename(dir));
  assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: false });
  assert.equal(database.pragma("secure_delete", { simple: true }), 1);
  assert.equal(database.pragma("application_id", { simple: true }), 0);
  assert.equal(database.pragma("user_version", { simple: true }), 0);
  assert.throws(() => storage.openDatabase({ dataDirectory: other }), code("ALREADY_OPEN"));
  assert.equal(storage.getDatabase(), database); assert.equal(existsSync(other), false);
});

test("current legacy databases can be read without schema changes or writable access", () => {
  const dir = directory(); seed(dir);
  const before = readFileSync(filename(dir));
  const database = storage.openDatabase({ dataDirectory: dir, readonly: true });
  assert.equal(database.readonly, true);
  assert.equal(vault.getVaultStatus().isConfigured, false);
  assert.throws(() => database.exec("DELETE FROM password_entries"), error => error.code === "SQLITE_READONLY");
  storage.closeDatabase();
  assert.deepEqual(readFileSync(filename(dir)), before);
  assert.deepEqual(readdirSync(dir), ["password-manager.db"]);
});

test("old optional columns are inspected read-only and migrated without changing ciphertext", () => {
  for (const sql of [oldSchema, schema.replace(/\s*password_changed_at TEXT,/, ""), schema.replace(/\s*group_name TEXT,/, "")]) {
    const dir = directory(); seed(dir, sql);
    const raw = new Database(filename(dir));
    raw.prepare("INSERT INTO password_entries (id, service_name, login_id, encrypted_password, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run("fixture", "fixture", "fixture", "synthetic-preserved-ciphertext", "[]", "2025-01-01T00:00:00.000Z", "2025-01-01T00:00:00.000Z");
    raw.close();
    const before = readFileSync(filename(dir));
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: true });
    assert.throws(() => storage.openDatabase({ dataDirectory: dir, readonly: true }), code("MIGRATION_REQUIRED"));
    assert.deepEqual(readFileSync(filename(dir)), before);
    const database = storage.openDatabase({ dataDirectory: dir });
    const row = database.prepare("SELECT * FROM password_entries").get();
    assert.equal(row.encrypted_password, "synthetic-preserved-ciphertext");
    assert.equal(row.group_name, null); assert.equal(row.password_changed_at, null);
    storage.closeDatabase();
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: false });
  }
});

test("empty existing databases initialize only on a writable open", () => {
  for (const kind of ["zero-byte", "sqlite"]) {
    const dir = directory(); mkdirSync(dir);
    if (kind === "zero-byte") writeFileSync(filename(dir), ""); else seed(dir, "VACUUM");
    const before = readFileSync(filename(dir));
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "empty", needsMigration: true });
    assert.throws(() => storage.openDatabase({ dataDirectory: dir, readonly: true }), code("MIGRATION_REQUIRED"));
    assert.deepEqual(readFileSync(filename(dir)), before);
    storage.openDatabase({ dataDirectory: dir }); storage.closeDatabase();
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: false });
  }
});

test("unknown versions, partial schemas, extra objects and incompatible columns fail before writable SQL", () => {
  const fixtures = ["CREATE TABLE other (id INTEGER)", schema + "PRAGMA application_id = 1129728818", schema + "PRAGMA user_version = 2",
    "CREATE TABLE vault_metadata (id INTEGER)", schema + "ALTER TABLE password_entries ADD COLUMN crypto_version INTEGER",
    schema.replace("login_id TEXT NOT NULL,", ""), schema.replace("service_name TEXT NOT NULL", "service_name BLOB NOT NULL"),
    schema + "CREATE TABLE extra (id INTEGER)", schema + "CREATE INDEX extra ON password_entries(login_id)",
    schema + "CREATE TRIGGER synthetic_trigger AFTER DELETE ON password_entries BEGIN SELECT 1; END",
    schema.replace(/CREATE TABLE IF NOT EXISTS password_entries \([\s\S]*?\);/, "CREATE VIEW password_entries AS SELECT 1 AS id;")];
  const original = Database.prototype.pragma; const reads = [];
  mock.method(Database.prototype, "pragma", function (...args) { reads.push(this.readonly); return original.apply(this, args); });
  for (const sql of fixtures) {
    const dir = directory(); seed(dir, sql); const before = readFileSync(filename(dir));
    reads.length = 0;
    assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("UNSUPPORTED_FORMAT"));
    assert.ok(reads.length && reads.every(Boolean));
    assert.throws(() => storage.getDatabase(), code("NOT_OPEN"));
    assert.deepEqual(readFileSync(filename(dir)), before);
    assert.deepEqual(readdirSync(dir), ["password-manager.db"]);
  }
});

test("non-SQLite files and invalid paths fail generically without overwriting input", () => {
  const dir = directory(); mkdirSync(dir);
  writeFileSync(filename(dir), "synthetic-storage-canary invalid DB");
  const before = readFileSync(filename(dir));
  assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("INVALID_DATABASE"));
  assert.deepEqual(readFileSync(filename(dir)), before);
  assert.deepEqual(readdirSync(dir), ["password-manager.db"]);
  const wrong = directory(); mkdirSync(filename(wrong), { recursive: true });
  assert.throws(() => storage.openDatabase({ dataDirectory: wrong }), code("OPEN_FAILED"));
  const file = directory(); writeFileSync(file, "synthetic-storage-canary");
  assert.throws(() => storage.openDatabase({ dataDirectory: file }), code("OPEN_FAILED"));
});

test("a failure during the second old-column migration rolls back the first and closes the candidate", () => {
  const dir = directory(); seed(dir, oldSchema);
  const before = readFileSync(filename(dir)), held = [];
  const original = Database.prototype.exec;
  mock.method(Database.prototype, "exec", function (sql) {
    if (sql.includes("ADD COLUMN password_changed_at")) { held.push(this); throw new Error("synthetic-storage-canary"); }
    return original.call(this, sql);
  });
  assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("OPEN_FAILED"));
  assert.ok(held.length && held.every(database => !database.open));
  assert.throws(() => storage.getDatabase(), code("NOT_OPEN"));
  assert.deepEqual(readFileSync(filename(dir)), before);
  mock.restoreAll();
  storage.openDatabase({ dataDirectory: dir });
});

test("the schema is rechecked after preflight and before any migration", () => {
  const dir = directory(); seed(dir, oldSchema);
  const close = Database.prototype.close; let armed = true, changed;
  mock.method(Database.prototype, "close", function () {
    const mutate = armed && this.readonly; const result = close.call(this);
    if (mutate) {
      armed = false;
      const writer = new Database(filename(dir)); writer.exec("ALTER TABLE password_entries ADD COLUMN unknown INTEGER"); close.call(writer);
      changed = readFileSync(filename(dir));
    }
    return result;
  });
  assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("UNSUPPORTED_FORMAT"));
  assert.ok(changed); assert.deepEqual(readFileSync(filename(dir)), changed);
  assert.throws(() => storage.getDatabase(), code("NOT_OPEN"));
});

test("WAL preflight sees committed schema in sidecars and never treats the main file alone as empty", () => {
  const dir = directory(); mkdirSync(dir);
  const writer = new Database(filename(dir));
  try {
    writer.pragma("journal_mode = WAL"); writer.pragma("wal_autocheckpoint = 0"); writer.exec(schema);
    assert.ok(existsSync(filename(dir) + "-wal"));
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: false });
    storage.openDatabase({ dataDirectory: dir, readonly: true }); storage.closeDatabase();
    writer.exec("CREATE TABLE future_vault_format (id INTEGER)");
    const wal = readFileSync(filename(dir) + "-wal");
    assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("UNSUPPORTED_FORMAT"));
    assert.deepEqual(readFileSync(filename(dir) + "-wal"), wal);
  } finally { writer.close(); }
});

test("close is idempotent, rejects active transactions and makes stale native statements unusable", () => {
  const dir = directory(); const database = storage.openDatabase({ dataDirectory: dir });
  const stale = database.prepare("SELECT * FROM password_entries");
  database.transaction(() => {
    assert.throws(() => storage.closeDatabase(), code("CLOSE_FAILED"));
    assert.equal(storage.getDatabase(), database);
  })();
  const iterator = database.prepare("SELECT 1 UNION ALL SELECT 2").iterate();
  iterator.next();
  try {
    assert.throws(() => storage.closeDatabase(), code("CLOSE_FAILED"));
    assert.equal(storage.getDatabase(), database);
  } finally { iterator.return(); }
  storage.closeDatabase(); storage.closeDatabase();
  assert.equal(database.open, false); assert.throws(() => stale.all());
  assert.throws(() => vault.getVaultStatus(), code("NOT_OPEN"));
  assert.throws(() => storage.getDatabasePath(), code("NOT_OPEN"));
  const reopened = storage.openDatabase({ dataDirectory: dir }); assert.notEqual(reopened, database);
});

test("services use the new connection after close/reopen and resolve environment only at explicit open", async () => {
  const first = directory(), second = directory();
  process.env.PASSWORD_MANAGER_DATA_DIR = first;
  storage.openDatabase();
  await vault.setupVault({ masterPassword: "synthetic-first-master-password" });
  const entry = entries.createEntry({ serviceName: "first fixture", loginId: "fixture", password: "synthetic-entry-secret" });
  vaultSession.lock(); storage.closeDatabase();
  process.env.PASSWORD_MANAGER_DATA_DIR = second;
  storage.openDatabase();
  assert.equal(vault.getVaultStatus().isConfigured, false);
  await vault.setupVault({ masterPassword: "synthetic-second-master-password" });
  assert.deepEqual(entries.listEntries(), { items: [] });
  vaultSession.lock(); storage.closeDatabase();
  storage.openDatabase({ dataDirectory: first, createIfMissing: false });
  await vault.unlockVault({ masterPassword: "synthetic-first-master-password" });
  assert.equal(entries.getEntryById(entry.id).password, "synthetic-entry-secret");
  assert.equal(entries.listEntries().items.length, 1);
});

test("a competing writer prevents migration without partial schema changes", { timeout: 12000 }, () => {
  const dir = directory(); seed(dir, oldSchema);
  const writer = new Database(filename(dir)), before = readFileSync(filename(dir));
  try {
    writer.exec("BEGIN IMMEDIATE");
    assert.throws(() => storage.openDatabase({ dataDirectory: dir }), code("OPEN_FAILED"));
    assert.throws(() => storage.getDatabase(), code("NOT_OPEN"));
    assert.deepEqual(readFileSync(filename(dir)), before);
    writer.exec("ROLLBACK");
    storage.openDatabase({ dataDirectory: dir });
  } finally { if (writer.inTransaction) writer.exec("ROLLBACK"); writer.close(); }
});

test("the real HTTP entry point refuses an unsupported DB before listening", () => {
  const dir = directory(); seed(dir, schema + "PRAGMA user_version = 2");
  const before = readFileSync(filename(dir));
  const server = new URL("../apps/api/dist/apps/api/src/server.js", import.meta.url);
  const result = spawnSync(process.execPath, [fileURLToPath(server)], {
    env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: dir, PASSWORD_MANAGER_API_HOST: "127.0.0.1", PASSWORD_MANAGER_API_PORT: "0" },
    encoding: "utf8", timeout: 10000
  });
  assert.notEqual(result.status, 0); assert.equal(result.signal, null); assert.equal(result.error, undefined);
  assert.ok(!(result.stdout + result.stderr).includes("API listening"));
  assert.ok((result.stdout + result.stderr).includes("UNSUPPORTED_FORMAT"));
  assert.deepEqual(readFileSync(filename(dir)), before);
});

test("an HTTP listen failure locks the session and closes the explicit connection", async () => {
  const occupied = createServer();
  await new Promise(resolve => occupied.listen(0, "127.0.0.1", resolve));
  try {
    const dir = directory();
    const storageUrl = new URL("../apps/api/dist/apps/api/src/db/database.js", import.meta.url).href;
    const sessionUrl = new URL("../apps/api/dist/apps/api/src/services/vault-session.js", import.meta.url).href;
    const serverUrl = new URL("../apps/api/dist/apps/api/src/server.js", import.meta.url).href;
    const script = `const storage = await import(${JSON.stringify(storageUrl)}); const {vaultSession} = await import(${JSON.stringify(sessionUrl)}); vaultSession.unlock(Buffer.alloc(32, 7)); const held = vaultSession.requireKey(); process.on('beforeExit', () => { if(vaultSession.getState().isUnlocked || held.some(value => value !== 0)) throw Error('session not cleared'); try {storage.getDatabase(); throw Error('still open');} catch(error) {if(error.code !== 'NOT_OPEN') throw error;} console.log('storage cleanup verified'); }); await import(${JSON.stringify(serverUrl)});`;
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
      env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: dir, PASSWORD_MANAGER_API_HOST: "127.0.0.1", PASSWORD_MANAGER_API_PORT: String(occupied.address().port) },
      encoding: "utf8", timeout: 10000
    });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.equal(result.error, undefined); assert.match(result.stdout, /storage cleanup verified/);
    assert.deepEqual(storage.inspectDatabaseFile(filename(dir)), { format: "legacy", needsMigration: false });
  } finally { await new Promise(resolve => occupied.close(resolve)); }
});
