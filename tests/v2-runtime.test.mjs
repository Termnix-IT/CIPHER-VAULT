import assert from "node:assert/strict";
import { before, after, afterEach, mock, test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import crypto from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import Database from "better-sqlite3";
import { createMigratedFixture, compatibility, v2Password } from "./v2-runtime-fixture.mjs";
import * as storage from "../apps/api/dist/apps/api/src/db/vault-context.js";
import { getDatabase, hasOpenDatabase } from "../apps/api/dist/apps/api/src/db/database.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import { exportBackup, restoreBackup } from "../apps/api/dist/apps/api/src/services/backup-service.js";
import { auditVault } from "../apps/api/dist/apps/api/src/services/audit-service.js";
import { encryptSecret, decryptSecret } from "../apps/api/dist/apps/api/src/services/crypto-service.js";
import { vaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import { router } from "../apps/api/dist/apps/api/src/routes/router.js";
import { encodeBackupV1 } from "../apps/api/dist/apps/api/src/crypto/backup-v1.js";

const root = fs.mkdtempSync(path.join(tmpdir(), "cipher-vault-v2-runtime-")), base = path.join(root, "base");
const legacy = compatibility.legacy, passphrase = compatibility.backupV1.passphrase;
let context, sequence = 0;
const fixture = () => { const directory = path.join(root, `case-${++sequence}`); fs.cpSync(base, directory, { recursive: true }); return directory; };
const dbFile = directory => path.join(directory, "vaults", context.vaultId, "vault.sqlite");
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const raw = (directory, action) => { const db = new Database(dbFile(directory)); try { return action(db); } finally { db.close(); } };
const sorted = values => [...values].sort((a, b) => a.id.localeCompare(b.id));
const payload = (entry, changes = {}) => { const { serviceName, loginId, password, notes, url, tags, group } = entry; return { serviceName, loginId, password, notes, url, tags, group: group ?? undefined, ...changes }; };
const sample = () => ({ serviceName: "  synthetic-v2-service-canary  ", loginId: " v2-login-canary ", password: "v2-password-canary", notes: "v2-notes-canary", url: "https://v2-canary.example.test", group: " v2-group-canary ", tags: ["v2-tag-canary"] });
async function opened(directory = fixture(), options = {}) { storage.openVaultStorage({ dataDirectory: directory, ...options }); await vault.unlockVault({ masterPassword: v2Password }); return directory; }
function all() { return entries.listEntries().items.map(entry => entries.getEntryById(entry.id)); }
function clear() { for (const entry of entries.listEntries().items) entries.deleteEntry(entry.id); }
before(async () => { context = await createMigratedFixture(base); });
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); storage.closeVaultStorage(); });
after(() => {
  assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-v2-runtime-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("context and service imports do not open or create environment-selected storage", () => {
  const directory = fixture(), before = fs.readdirSync(directory), url = new URL("../apps/api/dist/apps/api/src/db/vault-context.js", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)});`], { cwd: directory,
    env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: path.join(directory, "must-not-exist") }, encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stdout + child.stderr); assert.deepEqual(fs.readdirSync(directory), before);
  assert.equal(hasOpenDatabase(), false); assert.equal(storage.isV2Vault(), false);
});

test("legacy startup still creates, sets up and operates through synchronous legacy services", async () => {
  const directory = path.join(root, `new-${++sequence}`); storage.openVaultStorage({ dataDirectory: directory });
  assert.equal(storage.isV2Vault(), false); assert.equal(vault.getVaultStatus().isConfigured, false);
  await vault.setupVault({ masterPassword: "synthetic-legacy-new-master" });
  const created = entries.createEntry(sample()); assert.equal(typeof created.then, "undefined"); assert.equal(entries.getEntryById(created.id).password, sample().password);
  assert.equal(getDatabase().open, true);
});

test("a running legacy Context refuses services and previously prepared SQL after a pointer switch", async () => {
  for (const operation of ["service", "prepared"]) {
    const directory = fixture(), pointer = fs.readFileSync(path.join(directory, "vault-current.json")), receipt = fs.readFileSync(path.join(directory, "vault-activation.json"));
    fs.unlinkSync(path.join(directory, "vault-current.json")); fs.unlinkSync(path.join(directory, "vault-activation.json"));
    storage.openVaultStorage({ dataDirectory: directory }); await vault.unlockVault({ masterPassword: legacy.password });
    const database = getDatabase(), prepared = database.prepare("UPDATE password_entries SET service_name=? WHERE id=?"), key = vaultSession.requireKey();
    const before = hash(path.join(directory, "password-manager.db")), states = [], unsubscribe = vault.onVaultState(state => states.push(state));
    assert.equal(database.prepare("SELECT COUNT(*) count FROM sqlite_schema WHERE type='trigger'").get().count, 0);
    assert.equal(database.prepare("SELECT COUNT(*) count FROM sqlite_temp_schema WHERE type='trigger'").get().count, 6);
    fs.writeFileSync(path.join(directory, "vault-current.json"), pointer); fs.writeFileSync(path.join(directory, "vault-activation.json"), receipt);
    try {
      if (operation === "service") assert.throws(() => entries.createEntry(sample()), { statusCode: 503 });
      else assert.throws(() => prepared.run("must-not-write-to-legacy", legacy.entries[0].id), { statusCode: 503 });
      assert.deepEqual(key, Buffer.alloc(32)); assert.equal(states.at(-1).isUnlocked, false); assert.equal(states.at(-1).isConfigured, true);
      assert.equal(hash(path.join(directory, "password-manager.db")), before);
    } finally { unsubscribe(); storage.closeVaultStorage(); }
    await opened(directory); assert.deepEqual(sorted(all()), sorted(legacy.entries)); storage.closeVaultStorage();
  }
});

test("legacy initialization rechecks selection after acquiring its SQLite lock and does not migrate a stale source", () => {
  const directory = fixture(), pointer = fs.readFileSync(path.join(directory, "vault-current.json")), receipt = fs.readFileSync(path.join(directory, "vault-activation.json"));
  fs.unlinkSync(path.join(directory, "vault-current.json")); fs.unlinkSync(path.join(directory, "vault-activation.json"));
  const source = path.join(directory, "password-manager.db"), old = new Database(source); old.exec("ALTER TABLE password_entries DROP COLUMN group_name"); old.close();
  const before = hash(source), factory = Database.prototype.transaction; let switched = false;
  mock.method(Database.prototype, "transaction", function (...args) {
    const transaction = factory.apply(this, args), database = this;
    const wrapped = (...values) => transaction(...values);
    wrapped.immediate = (...values) => {
      if (!switched && database.name === source) {
        switched = true; fs.writeFileSync(path.join(directory, "vault-current.json"), pointer); fs.writeFileSync(path.join(directory, "vault-activation.json"), receipt);
      }
      return transaction.immediate(...values);
    };
    return wrapped;
  });
  assert.throws(() => storage.openVaultStorage({ dataDirectory: directory }), error => error.code === "OPEN_FAILED");
  assert.ok(switched); assert.equal(hasOpenDatabase(), false); assert.equal(hash(source), before);
  const reader = new Database(source, { readonly: true });
  try { assert.equal(reader.pragma("table_info(password_entries)").some(column => column.name === "group_name"), false); } finally { reader.close(); }
});

test("a committed v2 pointer opens locked without touching or opening the original legacy DB", async () => {
  const directory = fixture(), original = hash(path.join(directory, "password-manager.db")); storage.openVaultStorage({ dataDirectory: directory });
  assert.equal(storage.isV2Vault(), true); assert.equal(vault.getVaultStatus().isConfigured, true); assert.equal(vault.getVaultStatus().isUnlocked, false);
  assert.throws(() => getDatabase(), error => error.code === "NOT_OPEN"); assert.throws(() => entries.listEntries(), { statusCode: 423 });
  await assert.rejects(vault.setupVault({ masterPassword: "synthetic-unwanted-setup" }), { statusCode: 409 });
  await assert.rejects(vault.unlockVault({ masterPassword: legacy.password }), { statusCode: 401 });
  await vault.unlockVault({ masterPassword: v2Password }); assert.deepEqual(sorted(all()), sorted(legacy.entries));
  const key = vaultSession.requireKey(); vault.lockVault(); assert.deepEqual(key, Buffer.alloc(32));
  assert.equal(hash(path.join(directory, "password-manager.db")), original);
});

test("v2 CRUD preserves DTO fields, password-change dates, tombstones and persisted revision", async () => {
  const directory = await opened(), original = hash(path.join(directory, "password-manager.db")), initial = storage.getV2Vault().store.getUsage().encryptionCount;
  const created = await entries.createEntry(sample()); assert.equal(created.serviceName, sample().serviceName.trim());
  const edited = await entries.updateEntry(created.id, payload(created, { notes: "edited notes" })); assert.equal(edited.passwordChangedAt, created.passwordChangedAt);
  const changed = await entries.updateEntry(created.id, payload(edited, { password: "different-secret" })); assert.equal(changed.passwordChangedAt, changed.updatedAt);
  assert.deepEqual(entries.getEntryById(created.id), changed);
  assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, initial + 3);
  entries.deleteEntry(created.id); assert.throws(() => entries.getEntryById(created.id), { statusCode: 404 });
  raw(directory, db => { const row = db.prepare("SELECT revision,envelope FROM vault_entries WHERE entry_id=?").get(created.id); assert.equal(row.revision, 3); assert.equal(row.envelope, null); });
  storage.closeVaultStorage(); await opened(directory); assert.deepEqual(sorted(all()), sorted(legacy.entries));
  assert.equal(hash(path.join(directory, "password-manager.db")), original);
});

test("summaries omit secrets and all v2 metadata fields remain ciphertext on disk", async () => {
  const directory = await opened(), created = await entries.createEntry(sample());
  const summary = entries.listEntries().items.find(entry => entry.id === created.id);
  assert.deepEqual(Object.keys(summary).sort(), ["group", "id", "loginId", "serviceName", "tags", "updatedAt"]);
  const bytes = fs.readFileSync(dbFile(directory));
  for (const value of [created.serviceName, created.loginId, created.password, created.notes, created.url, created.group, ...created.tags]) assert.equal(bytes.includes(Buffer.from(value)), false);
  assert.throws(() => encryptSecret("must-not-use-legacy"), { statusCode: 409 }); assert.throws(() => decryptSecret("must-not-use-legacy"), { statusCode: 409 });
});

test("v1 backup restores atomically into empty v2 using later tombstone revisions and into a different legacy key", async () => {
  const directory = await opened(), expected = sorted(all()), content = await exportBackup({ passphrase }), before = storage.getV2Vault().store.getUsage().encryptionCount;
  await assert.rejects(restoreBackup({ passphrase, content: content.content }), { statusCode: 409 }); clear();
  assert.deepEqual(await restoreBackup({ passphrase, content: content.content }), { restoredCount: expected.length }); assert.deepEqual(sorted(all()), expected);
  assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before + expected.length);
  raw(directory, db => assert.ok(db.prepare("SELECT revision FROM vault_entries").all().every(row => row.revision === 2)));
  storage.closeVaultStorage(); storage.openVaultStorage({ dataDirectory: path.join(root, `restore-legacy-${++sequence}`) });
  await vault.setupVault({ masterPassword: "synthetic-independent-legacy-restore" }); await restoreBackup({ passphrase, content: content.content }); assert.deepEqual(sorted(all()), expected);
});

test("a failed bulk insert rolls back every entry but keeps committed nonce reservations across reopen", async () => {
  const directory = await opened(), backup = await exportBackup({ passphrase }); clear(); const before = storage.getV2Vault().store.getUsage().encryptionCount;
  const prepare = Database.prototype.prepare; let writes = 0;
  mock.method(Database.prototype, "prepare", function (sql) {
    const statement = prepare.call(this, sql);
    if (sql.startsWith("INSERT INTO vault_entries")) return { run: (...args) => { if (++writes === 2) throw new Error("synthetic insert failure"); return statement.run(...args); } };
    return statement;
  });
  await assert.rejects(restoreBackup({ passphrase, content: backup.content }), { statusCode: 503 }); assert.equal(vault.getVaultStatus().isUnlocked, false);
  Database.prototype.prepare.mock.restore(); storage.closeVaultStorage(); await opened(directory);
  assert.deepEqual(entries.listEntries().items, []); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before + legacy.entries.length);
});

test("invalid Unicode is rejected before reservation without faulting the unlocked v2 vault", async () => {
  await opened(); const before = storage.getV2Vault().store.getUsage().encryptionCount;
  await assert.rejects(entries.createEntry({ ...sample(), notes: "unpaired-\ud800" }), { statusCode: 400 });
  assert.equal(vault.getVaultStatus().isUnlocked, true); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before);
  clear(); const invalid = structuredClone(legacy.entries); invalid[1].notes = "invalid-\ud800";
  const vector = compatibility.backupV1, key = Buffer.from(vector.keyHex, "hex");
  try {
    const content = encodeBackupV1(invalid, key, Buffer.from(vector.envelope.salt, "base64"));
    await assert.rejects(restoreBackup({ passphrase: vector.passphrase, content }), { statusCode: 400 });
    assert.deepEqual(entries.listEntries().items, []); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before);
  } finally { key.fill(0); }
});

test("lock after nonce reservation prevents a late write and destroys the Session key", async () => {
  const directory = await opened(), before = storage.getV2Vault().store.getUsage().encryptionCount, key = vaultSession.requireKey(), cipher = crypto.createCipheriv;
  mock.method(crypto, "createCipheriv", (...args) => { const result = cipher(...args); vault.lockVault(); return result; }); syncBuiltinESMExports();
  await assert.rejects(entries.createEntry(sample()), error => [409, 423].includes(error.statusCode)); assert.deepEqual(key, Buffer.alloc(32));
  crypto.createCipheriv.mock.restore(); syncBuiltinESMExports(); await vault.unlockVault({ masterPassword: v2Password });
  assert.deepEqual(sorted(all()), sorted(legacy.entries)); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before + 1);
  assert.equal(hash(path.join(directory, "password-manager.db")), hash(path.join(base, "password-manager.db")));
});

test("lock during bulk restore prevents partial entries while retaining the consumed nonce", async () => {
  await opened(); const backup = await exportBackup({ passphrase }); clear(); const before = storage.getV2Vault().store.getUsage().encryptionCount, cipher = crypto.createCipheriv;
  mock.method(crypto, "createCipheriv", (...args) => { const result = cipher(...args); vault.lockVault(); return result; }); syncBuiltinESMExports();
  await assert.rejects(restoreBackup({ passphrase, content: backup.content }), error => [409, 423].includes(error.statusCode));
  crypto.createCipheriv.mock.restore(); syncBuiltinESMExports(); await vault.unlockVault({ masterPassword: v2Password });
  assert.deepEqual(entries.listEntries().items, []); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before + 1);
});

test("idle expiry at the storage continuation rejects a write even before the timer fires", async () => {
  await opened(); const before = storage.getV2Vault().store.getUsage().encryptionCount, key = vaultSession.requireKey(), cipher = crypto.createCipheriv, now = Date.now;
  mock.method(crypto, "createCipheriv", (...args) => { const result = cipher(...args); mock.method(Date, "now", () => now() + 300001); return result; }); syncBuiltinESMExports();
  await assert.rejects(entries.createEntry(sample()), error => [409, 423].includes(error.statusCode)); assert.deepEqual(key, Buffer.alloc(32));
  Date.now.mock.restore(); crypto.createCipheriv.mock.restore(); syncBuiltinESMExports(); await vault.unlockVault({ masterPassword: v2Password });
  assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before + 1); assert.deepEqual(sorted(all()), sorted(legacy.entries));
});

test("key-limit errors refuse create/restore without destroying the readable Session or spending uses", async () => {
  await opened(); const backup = await exportBackup({ passphrase }); clear(); const before = storage.getV2Vault().store.getUsage().encryptionCount, prepare = Database.prototype.prepare;
  mock.method(Database.prototype, "prepare", function (sql) {
    const statement = prepare.call(this, sql);
    if (sql === "SELECT * FROM vault_header LIMIT 2") return { all: () => statement.all().map(row => ({ ...row, encryption_count: 2 ** 20 })) };
    return statement;
  });
  mock.method(crypto, "createCipheriv", () => assert.fail("exhausted keys must not encrypt")); syncBuiltinESMExports();
  await assert.rejects(entries.createEntry(sample()), { statusCode: 409 });
  await assert.rejects(restoreBackup({ passphrase, content: backup.content }), { statusCode: 409 });
  assert.equal(vault.getVaultStatus().isUnlocked, true); Database.prototype.prepare.mock.restore();
  assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before); assert.deepEqual(entries.listEntries().items, []);
});

test("startup identity-read failure closes every v2 handle and permits a later explicit open", async () => {
  const directory = fixture(), stat = fs.statSync, close = Database.prototype.close, handles = [];
  mock.method(fs, "statSync", (...args) => { if (args[0] === dbFile(directory)) throw new Error("synthetic stat failure"); return stat(...args); });
  mock.method(Database.prototype, "close", function () { if (this.name === dbFile(directory)) handles.push(this); return close.call(this); }); syncBuiltinESMExports();
  assert.throws(() => storage.openVaultStorage({ dataDirectory: directory }), error => error.code === "OPEN_FAILED");
  assert.ok(handles.length > 0 && handles.every(handle => handle.open === false)); assert.equal(storage.isV2Vault(), false); assert.equal(hasOpenDatabase(), false);
  fs.statSync.mock.restore(); syncBuiltinESMExports(); await opened(directory); assert.deepEqual(sorted(all()), sorted(legacy.entries));
});

test("a late delete guard rolls the tombstone update back after Session invalidation", async () => {
  await opened(); const id = legacy.entries[0].id, prepare = Database.prototype.prepare;
  mock.method(Database.prototype, "prepare", function (sql) {
    const statement = prepare.call(this, sql);
    if (sql.startsWith("UPDATE vault_entries SET envelope = NULL")) return { run: (...args) => { const result = statement.run(...args); vault.lockVault(); return result; } };
    return statement;
  });
  assert.throws(() => entries.deleteEntry(id), error => [409, 423].includes(error.statusCode)); Database.prototype.prepare.mock.restore();
  await vault.unlockVault({ masterPassword: v2Password }); assert.deepEqual(entries.getEntryById(id), legacy.entries[0]);
});

test("pointer replacement before write commit locks the vault and cannot fall back to legacy", async () => {
  const directory = await opened(), cipher = crypto.createCipheriv, original = hash(path.join(directory, "password-manager.db"));
  mock.method(crypto, "createCipheriv", (...args) => {
    const result = cipher(...args); fs.writeFileSync(path.join(directory, "vault-current.json"), JSON.stringify({ format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: crypto.randomUUID() })); return result;
  }); syncBuiltinESMExports();
  await assert.rejects(entries.createEntry(sample()), error => [409, 423, 503].includes(error.statusCode)); assert.equal(vault.getVaultStatus().isUnlocked, false);
  assert.throws(() => entries.listEntries(), error => [423, 503].includes(error.statusCode)); storage.closeVaultStorage();
  assert.throws(() => storage.openVaultStorage({ dataDirectory: directory }), error => error.code === "RECOVERY_REQUIRED");
  assert.equal(hash(path.join(directory, "password-manager.db")), original); assert.equal(hasOpenDatabase(), false);
  raw(directory, db => assert.equal(db.prepare("SELECT COUNT(*) count FROM vault_entries WHERE envelope IS NOT NULL").get().count, legacy.entries.length));
});

test("old pending work cannot invalidate a newly opened Context or Session", async () => {
  const first = await opened(), second = fixture(), key = Buffer.from(vaultSession.requireKey()), cipher = crypto.createCipheriv;
  mock.method(crypto, "createCipheriv", (...args) => {
    const result = cipher(...args); storage.closeVaultStorage(); storage.openVaultStorage({ dataDirectory: second }); vaultSession.unlock(key); return result;
  }); syncBuiltinESMExports();
  await assert.rejects(entries.createEntry(sample()), error => [409, 423].includes(error.statusCode));
  assert.equal(storage.getVaultStoragePath(), dbFile(second)); assert.equal(vault.getVaultStatus().isUnlocked, true); assert.deepEqual(sorted(all()), sorted(legacy.entries)); key.fill(0);
  raw(first, db => assert.equal(db.prepare("SELECT COUNT(*) count FROM vault_entries WHERE envelope IS NOT NULL").get().count, legacy.entries.length));
});

test("fault notifications cannot invalidate a replacement Context opened synchronously by an observer", async () => {
  const first = await opened(), second = fixture(), key = Buffer.from(vaultSession.requireKey()); let replaced = false;
  const unsubscribe = vaultSession.subscribe(state => {
    if (!state.isUnlocked && !replaced) {
      replaced = true; storage.closeVaultStorage(); storage.openVaultStorage({ dataDirectory: second }); vaultSession.unlock(key);
    }
  });
  try {
    fs.writeFileSync(path.join(first, "vault-current.json"), "{");
    assert.throws(() => entries.listEntries(), { statusCode: 503 });
    assert.equal(replaced, true); assert.equal(storage.getVaultStoragePath(), dbFile(second));
    assert.equal(vault.getVaultStatus().isUnlocked, true); assert.deepEqual(sorted(all()), sorted(legacy.entries));
  } finally { unsubscribe(); key.fill(0); }
});

test("a failed synchronous read cannot fault a newer Context installed before the error propagates", async () => {
  await opened(); const second = fixture(), key = Buffer.from(vaultSession.requireKey());
  mock.method(crypto, "createDecipheriv", () => {
    storage.closeVaultStorage(); storage.openVaultStorage({ dataDirectory: second }); vaultSession.unlock(key);
    throw new Error("synthetic late read failure");
  }); syncBuiltinESMExports();
  assert.throws(() => entries.getEntryById(legacy.entries[0].id), { statusCode: 409 });
  crypto.createDecipheriv.mock.restore(); syncBuiltinESMExports();
  assert.equal(vault.getVaultStatus().isUnlocked, true); assert.equal(storage.getVaultStoragePath(), dbFile(second));
  assert.deepEqual(sorted(all()), sorted(legacy.entries)); key.fill(0);
});

test("reset cancels late unlock but preserves v2 root, data, pointer and nonce history", async () => {
  const directory = fixture(); storage.openVaultStorage({ dataDirectory: directory }); const before = hash(dbFile(directory)), scrypt = crypto.scrypt; let release, started;
  const ready = new Promise(resolve => { started = resolve; });
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, key) => { release = () => { callback(error, key); return key; }; started(); })); syncBuiltinESMExports();
  const pending = vault.unlockVault({ masterPassword: v2Password }); await ready;
  assert.throws(() => vault.resetVault({ confirmation: "RESET_ALL_DATA" }), { statusCode: 409 });
  await assert.rejects(vault.unlockVault({ masterPassword: v2Password }), { statusCode: 409 });
  const key = release(); await assert.rejects(pending, { statusCode: 409 }); assert.deepEqual(key, Buffer.alloc(32)); assert.equal(hash(dbFile(directory)), before);
});

test("ciphertext corruption fails closed during unlock and during an unlocked read", async () => {
  for (const unlocked of [false, true]) {
    const directory = fixture(); storage.openVaultStorage({ dataDirectory: directory }); if (unlocked) await vault.unlockVault({ masterPassword: v2Password });
    const key = unlocked ? vaultSession.requireKey() : undefined;
    raw(directory, db => {
      const row = db.prepare("SELECT entry_id,envelope FROM vault_entries LIMIT 1").get(), envelope = JSON.parse(row.envelope), bytes = Buffer.from(envelope.data, "base64"); bytes[0] ^= 1; envelope.data = bytes.toString("base64");
      db.prepare("UPDATE vault_entries SET envelope=? WHERE entry_id=?").run(JSON.stringify(envelope), row.entry_id);
    });
    if (unlocked) assert.throws(() => entries.listEntries(), { statusCode: 503 });
    else await assert.rejects(vault.unlockVault({ masterPassword: v2Password }), { statusCode: 503 });
    assert.equal(vault.getVaultStatus().isUnlocked, false); if (key) assert.deepEqual(key, Buffer.alloc(32)); assert.equal(hasOpenDatabase(), false); storage.closeVaultStorage();
  }
});

test("broken or prepared selection metadata is rejected before a legacy DB can open", () => {
  for (const name of ["vault-current.json", "vault-activation.json"]) {
    const directory = fixture(), before = hash(path.join(directory, "password-manager.db")); fs.unlinkSync(path.join(directory, name));
    assert.throws(() => storage.openVaultStorage({ dataDirectory: directory }), error => error.code === "RECOVERY_REQUIRED");
    assert.equal(hash(path.join(directory, "password-manager.db")), before); assert.equal(hasOpenDatabase(), false);
  }
});

test("read-only v2 storage permits reads and refuses mutations without spending a nonce", async () => {
  await opened(undefined, { readonly: true }); const before = storage.getV2Vault().store.getUsage().encryptionCount;
  assert.deepEqual(sorted(all()), sorted(legacy.entries)); await assert.rejects(entries.createEntry(sample()), { statusCode: 403 });
  assert.equal(vault.getVaultStatus().isUnlocked, true); assert.equal(storage.getV2Vault().store.getUsage().encryptionCount, before);
});

test("v2 audit uses decrypted DTOs, emits no passwords and cancels after lock", async () => {
  await opened(); const result = await auditVault(); assert.equal(result.total, legacy.entries.length);
  for (const entry of legacy.entries) assert.equal(JSON.stringify(result).includes(entry.password), false);
  const pending = auditVault(); vault.lockVault(); await assert.rejects(pending, error => [409, 423].includes(error.statusCode));
});

test("HTTP awaits v2 CRUD and shares unlock cooldown and backup contracts", async () => {
  const directory = fixture(); storage.openVaultStorage({ dataDirectory: directory });
  const server = createServer((request, response) => void router(request, response)); await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const request = async (route, body, method = "POST") => {
    const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
    return fetch(`${origin}${route}`, { method, headers: { Origin: origin, "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": vault.getVaultStatus().sessionId }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  };
  try {
    for (let attempt = 0; attempt < 5; attempt++) assert.equal((await request("/vault/unlock", { masterPassword: "wrong-v2-password" })).status, 401);
    const blocked = await request("/vault/unlock", { masterPassword: v2Password }); assert.equal(blocked.status, 429); assert.equal(blocked.headers.get("retry-after"), "1"); await delay(1050);
    assert.equal((await request("/vault/unlock", { masterPassword: v2Password })).status, 200);
    const created = await request("/entries", sample()); assert.equal(created.status, 201); const entry = await created.json(); assert.equal(entry.password, sample().password);
    const updated = await request(`/entries/${entry.id}`, payload(entry, { notes: "HTTP changed" }), "PUT"); assert.equal(updated.status, 200); assert.equal((await updated.json()).notes, "HTTP changed");
    const backup = await request("/vault/backup/export", { passphrase }); assert.equal(backup.status, 200); assert.equal(typeof (await backup.json()).content, "string");
    assert.equal((await request(`/entries/${entry.id}`, undefined, "DELETE")).status, 200);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

async function launch(directory) {
  const url = new URL("../apps/api/dist/apps/api/src/server.js", import.meta.url).href;
  const source = `import {Server} from 'node:http';const listen=Server.prototype.listen;Server.prototype.listen=function(...args){this.once('listening',()=>console.log('TEST_PORT:'+this.address().port));return listen.apply(this,args)};await import(${JSON.stringify(url)});`;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", source], { windowsHide: true, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: directory, PASSWORD_MANAGER_API_HOST: "127.0.0.1", PASSWORD_MANAGER_API_PORT: "0" }, stdio: ["ignore", "pipe", "pipe"] });
  let output = ""; child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8"); child.stdout.on("data", value => { output += value; }); child.stderr.on("data", value => { output += value; });
  for (let i = 0; i < 200; i++) { const match = output.match(/TEST_PORT:(\d+)/); if (match) return { child, origin: `http://127.0.0.1:${match[1]}` }; if (child.exitCode !== null) break; await delay(25); }
  child.kill(); throw new Error(`Synthetic server startup failed: ${output}`);
}
test("the actual server selects v2 at startup, persists async writes and reopens it after restart", async () => {
  const directory = fixture(), original = hash(path.join(directory, "password-manager.db")); let created;
  for (let run = 0; run < 2; run++) {
    const { child, origin } = await launch(directory);
    const request = async (route, body) => {
      const state = await (await fetch(`${origin}/vault/status`)).json(), { token } = await (await fetch(`${origin}/vault/csrf`)).json();
      return fetch(`${origin}${route}`, { method: "POST", headers: { Origin: origin, "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": state.sessionId }, body: JSON.stringify(body) });
    };
    try {
      assert.equal((await (await fetch(`${origin}/vault/status`)).json()).isUnlocked, false);
      assert.equal((await request("/vault/unlock", { masterPassword: v2Password })).status, 200);
      if (run === 0) { const response = await request("/entries", sample()); assert.equal(response.status, 201); created = await response.json(); }
      else {
        const state = await (await fetch(`${origin}/vault/status`)).json();
        const response = await fetch(`${origin}/entries/${created.id}`, { headers: { Origin: origin, "X-Cipher-Vault-Session": state.sessionId } }); assert.equal(response.status, 200); assert.deepEqual(await response.json(), created);
      }
    } finally { const exited = once(child, "exit"); child.kill("SIGTERM"); await exited; }
  }
  assert.equal(hash(path.join(directory, "password-manager.db")), original);
});
