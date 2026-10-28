import assert from "node:assert/strict";
import { after, afterEach, mock, test } from "node:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import native from "node:crypto";
import Database from "better-sqlite3";
import { createV2Store, openV2Store, V2StoreError, V2_STORE_LIMITS, V2_APPLICATION_ID, V2_SCHEMA_VERSION } from "../apps/api/dist/apps/api/src/db/v2-store.js";
import { openDatabase, closeDatabase } from "../apps/api/dist/apps/api/src/db/database.js";
import * as codec from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";

const v = JSON.parse(readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8")).draftV2;
const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-v2-store-"));
const handles = new Set(); let sequence = 0;
const file = () => path.join(root, `vault-${++sequence}.sqlite`);
const key = () => Buffer.from(v.rootKeyHex, "hex");
const expected = () => ({ vaultId: v.vaultId, keyId: v.keyId, slotRevision: v.slotRevision });
const context = (revision = 1, entryId = v.entryId) => ({ vaultId: v.vaultId, keyId: v.keyId, entryId, revision });
const slot = () => ({ cryptoVersion: 2, cipher: "aes-256-gcm", ...expected(), slotId: "password", kdf: { profile: v.profile, salt: v.salt }, iv: v.wrapIv, tag: v.wrapTag, data: v.wrappedRoot });
const plaintext = id => JSON.stringify({ ...JSON.parse(v.entryPlaintext), id: id ?? v.entryId });
function track(handle) { handles.add(handle); return handle; }
const create = (name = file()) => track(createV2Store(name, slot()));
const open = (name, options) => track(openV2Store(name, expected(), options));
const code = value => error => {
  assert.ok(error instanceof V2StoreError || error instanceof codec.VaultCodecError);
  assert.equal(error.code, value);
  assert.ok(!String(error).includes(root)); assert.ok(!String(error).includes("fixture-storage-secret-canary"));
  return true;
};
function raw(name, action) { const db = new Database(name); try { return action(db); } finally { db.close(); } }
function fixedRandom(...values) {
  native.randomBytes.mock?.restore();
  mock.method(native, "randomBytes", size => { const value = values.shift(); assert.equal(size, 12); assert.ok(value); return Buffer.from(value); });
  syncBuiltinESMExports();
}
afterEach(() => {
  mock.restoreAll(); syncBuiltinESMExports();
  for (const handle of handles) handle.close(); handles.clear();
  closeDatabase();
});
after(() => {
  assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-v2-store-"));
  rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("importing v2 storage does not open or create any vault", () => {
  const marker = file(); writeFileSync(marker, "synthetic sentinel");
  const before = readdirSync(root);
  const url = new URL("../apps/api/dist/apps/api/src/db/v2-store.js", import.meta.url).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)});`], {
    cwd: root, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: marker }, timeout: 10000, encoding: "utf8"
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(readdirSync(root), before); assert.equal(readFileSync(marker, "utf8"), "synthetic sentinel");
});

test("creation pins the v2 schema and durability settings; no raw connection is exposed", () => {
  const name = file(), handle = create(name);
  assert.ok(Object.isFrozen(handle)); assert.equal(handle.closed, false); assert.equal(handle.database, undefined);
  assert.deepEqual(handle.readPasswordSlot(), slot());
  assert.deepEqual(handle.getUsage(), { encryptionCount: 0, maxEncryptions: 2 ** 20 });
  raw(name, db => {
    assert.equal(db.pragma("application_id", { simple: true }), V2_APPLICATION_ID);
    assert.equal(db.pragma("user_version", { simple: true }), V2_SCHEMA_VERSION);
    assert.equal(db.pragma("journal_mode", { simple: true }), "delete");
    assert.ok(db.pragma("table_list").filter(row => ["vault_header", "vault_entries", "vault_nonces"].includes(row.name)).every(row => row.strict === 1));
  });
  const original = Database.prototype.prepare; const observed = [];
  mock.method(Database.prototype, "prepare", function (sql) {
    if (sql.startsWith("SELECT * FROM vault_header")) observed.push(this.pragma("synchronous", { simple: true }));
    return original.call(this, sql);
  });
  handle.readPasswordSlot(); assert.ok(observed.length && observed.every(value => value === 3));
});

test("creation never overwrites an existing, legacy or zero-byte file; open never creates", () => {
  for (const bytes of ["", "fixture-storage-secret-canary"]) {
    const name = file(); writeFileSync(name, bytes);
    assert.throws(() => createV2Store(name, slot()), code("EXISTS")); assert.equal(readFileSync(name, "utf8"), bytes);
  }
  const name = file();
  assert.throws(() => open(name), code("IO_FAILED")); assert.equal(existsSync(name), false);
  assert.throws(() => createV2Store(name, { ...slot(), cipher: "unknown" }), code("INVALID_FORMAT")); assert.equal(existsSync(name), false);
  assert.throws(() => createV2Store(path.join(name, "missing-parent.sqlite"), slot()), code("IO_FAILED"));
  for (const invalid of [null, "", "bad\0path"]) assert.throws(() => createV2Store(invalid, slot()), code("INVALID_STORE"));
});

test("entries persist only ciphertext and roundtrip through independent fixed vectors after reopen", async () => {
  const name = file(); const handle = create(name), rootKey = key();
  try {
    fixedRandom(Buffer.from(v.entryIv, "base64"));
    const sealed = await handle.writeEntry(rootKey, v.entryPlaintext, context());
    assert.equal(sealed.data, v.entryData); assert.equal(sealed.tag, v.entryTag);
    handle.close(); const reopened = open(name);
    const restoredKey = await codec.unwrapRootKey(reopened.readPasswordSlot(), v.masterPassword, expected());
    try {
      const decrypted = codec.openEntry(restoredKey, reopened.readEntry(v.entryId), context());
      assert.equal(decrypted.toString(), v.entryPlaintext); decrypted.fill(0);
    } finally { restoredKey.fill(0); }
    assert.deepEqual(reopened.listEntryContexts(), [context()]);
    assert.deepEqual(reopened.getUsage(), { encryptionCount: 1, maxEncryptions: V2_STORE_LIMITS.encryptions });
    for (const field of ["serviceName", "loginId", "password", "notes", "url"]) {
      const value = JSON.parse(v.entryPlaintext)[field];
      if (value.length > 12) assert.equal(readFileSync(name).includes(Buffer.from(value)), false, field);
    }
    assert.equal(rootKey.toString("hex"), v.rootKeyHex);
  } finally { rootKey.fill(0); }
});

test("reopening defaults to read-only, validates caller context and cannot mutate", async () => {
  const name = file(); create(name).close(); const before = readFileSync(name), handle = open(name);
  await assert.rejects(handle.writeEntry(key(), plaintext(), context()), code("READ_ONLY"));
  assert.throws(() => handle.deleteEntry(context()), code("READ_ONLY")); handle.close();
  for (const changed of [{ vaultId: v.keyId }, { keyId: v.vaultId }, { slotRevision: 2 }]) assert.throws(() => openV2Store(name, { ...expected(), ...changed }), code("INVALID_STORE"));
  assert.throws(() => openV2Store(name, expected(), { writable: "yes" }), code("INVALID_STORE"));
  assert.deepEqual(readFileSync(name), before);
});

test("legacy and unknown versions, changed constraints, triggers and counter mismatches are refused before writable access", () => {
  const mutations = [db => db.pragma("user_version = 99"), db => db.pragma("application_id = 0"),
    db => db.exec("CREATE TABLE unknown (id INTEGER)"), db => db.exec("CREATE TRIGGER altered AFTER INSERT ON vault_entries BEGIN SELECT 1; END"),
    db => db.exec("ALTER TABLE vault_entries ADD COLUMN unknown TEXT"), db => db.exec("UPDATE vault_header SET encryption_count = 1"),
    db => db.exec("UPDATE vault_header SET password_slot = '{}'"),
    db => {
      const sql = db.prepare("SELECT sql FROM sqlite_schema WHERE name = 'vault_nonces'").get().sql;
      db.exec("DROP TABLE vault_nonces;" + sql.replace("CHECK (length(iv) = 12)", ""));
    }];
  for (const mutate of mutations) {
    const name = file(); create(name).close(); raw(name, mutate); const before = readFileSync(name);
    assert.throws(() => open(name, { writable: true }), code("INVALID_STORE")); assert.deepEqual(readFileSync(name), before);
  }
  const name = file(); raw(name, db => db.exec(readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8")));
  const before = readFileSync(name); assert.throws(() => open(name, { writable: true }), code("INVALID_STORE")); assert.deepEqual(readFileSync(name), before);
});

test("legacy startup rejects a v2 DB without adding legacy tables", () => {
  const dir = path.join(root, `legacy-${++sequence}`); const name = path.join(dir, "password-manager.db");
  mkdirSync(dir); create(name).close(); const before = readFileSync(name);
  assert.throws(() => openDatabase({ dataDirectory: dir }), error => error.code === "UNSUPPORTED_FORMAT");
  assert.deepEqual(readFileSync(name), before);
  raw(name, db => assert.equal(db.prepare("SELECT 1 FROM sqlite_schema WHERE name = 'password_entries'").get(), undefined));
});

test("revisions and deletion tombstones do not permit old writes or nonce reuse", async () => {
  const name = file(), handle = create(name), rootKey = key();
  try {
    await handle.writeEntry(rootKey, plaintext(), context());
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("CONFLICT"));
    await handle.writeEntry(rootKey, plaintext(), context(2));
    assert.throws(() => handle.deleteEntry(context()), code("CONFLICT"));
    handle.deleteEntry(context(2)); assert.equal(handle.readEntry(v.entryId), null); assert.deepEqual(handle.listEntryContexts(), []);
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("CONFLICT"));
    await handle.writeEntry(rootKey, plaintext(), context(3));
    assert.equal(handle.getUsage().encryptionCount, 3);
    assert.equal(raw(name, db => db.prepare("SELECT COUNT(*) AS count FROM vault_nonces").get().count), 3);
  } finally { rootKey.fill(0); }
});

test("collisions are retried without spending extra uses and remain reserved across reopen", async () => {
  const name = file(), handle = create(name), rootKey = key(), first = Buffer.alloc(12, 1), second = Buffer.alloc(12, 2);
  try {
    fixedRandom(first); await handle.writeEntry(rootKey, plaintext(), context()); handle.close();
    const reopened = open(name, { writable: true }); fixedRandom(first, second);
    const result = await reopened.writeEntry(rootKey, plaintext(), context(2)); assert.deepEqual(Buffer.from(result.iv, "base64"), second);
    assert.equal(reopened.getUsage().encryptionCount, 2);
    fixedRandom(...Array.from({ length: 8 }, () => first));
    await assert.rejects(reopened.writeEntry(rootKey, plaintext(), context(3)), code("NONCE_UNAVAILABLE"));
    assert.equal(reopened.getUsage().encryptionCount, 2);
  } finally { rootKey.fill(0); }
});

test("entry-write failure burns the committed nonce, faults the handle and never reuses that IV", async () => {
  const name = file(), handle = create(name), rootKey = key(), used = Buffer.alloc(12, 3);
  const original = Database.prototype.prepare;
  try {
    fixedRandom(used);
    mock.method(Database.prototype, "prepare", function (sql) {
      if (sql.startsWith("INSERT INTO vault_entries")) return { run() { throw new Error("fixture-storage-secret-canary"); } };
      return original.call(this, sql);
    });
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("IO_FAILED"));
    assert.throws(() => handle.getUsage(), code("FAULTED")); handle.close(); mock.restoreAll(); syncBuiltinESMExports();
    const reopened = open(name, { writable: true }); assert.equal(reopened.readEntry(v.entryId), null); assert.equal(reopened.getUsage().encryptionCount, 1);
    fixedRandom(used, Buffer.alloc(12, 4)); await reopened.writeEntry(rootKey, plaintext(), context());
    assert.equal(reopened.getUsage().encryptionCount, 2);
  } finally { rootKey.fill(0); }
});

test("reservation failure rolls back count and nonce and never reaches encryption", async () => {
  const name = file(), handle = create(name), rootKey = key(); let encrypted = 0;
  const prepare = Database.prototype.prepare;
  mock.method(native, "createCipheriv", () => { encrypted++; throw new Error("must not encrypt"); }); syncBuiltinESMExports();
  mock.method(Database.prototype, "prepare", function (sql) {
    if (sql.startsWith("UPDATE vault_header SET encryption_count")) return { run() { throw new Error("fixture-storage-secret-canary"); } };
    return prepare.call(this, sql);
  });
  try {
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("IO_FAILED")); assert.equal(encrypted, 0);
    handle.close(); mock.restoreAll(); syncBuiltinESMExports();
    assert.equal(open(name).getUsage().encryptionCount, 0);
  } finally { rootKey.fill(0); }
});

test("invalid plaintext, IDs and pre-aborted calls do not reserve a nonce", async () => {
  const handle = create(), rootKey = key(), controller = new AbortController(); controller.abort();
  try {
    for (const input of ["{}", "null", Buffer.from([0xff])]) await assert.rejects(handle.writeEntry(rootKey, input, context()), code("INVALID_FORMAT"));
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), { ...context(), entryId: "" }), code("INVALID_FORMAT"));
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), { ...context(), vaultId: v.keyId }), code("INVALID_STORE"));
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context(), { signal: controller.signal }), code("CANCELLED"));
    assert.equal(handle.getUsage().encryptionCount, 0);
  } finally { rootKey.fill(0); }
});

test("busy, close and cancellation after reservation preserve the consumed use without a late write", async () => {
  for (const action of ["close", "abort"]) {
    const name = file(), handle = create(name), rootKey = key(), controller = new AbortController();
    try {
      const pending = handle.writeEntry(rootKey, plaintext(), context(), { signal: controller.signal });
      const rejectedBusy = assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("BUSY"));
      const rejectedPending = assert.rejects(pending, code(action === "close" ? "CLOSED" : "CANCELLED"));
      assert.throws(() => handle.deleteEntry(context()), code("BUSY"));
      if (action === "close") handle.close(); else controller.abort();
      await rejectedBusy; await rejectedPending;
      handle.close(); const reopened = open(name); assert.equal(reopened.getUsage().encryptionCount, 1); assert.equal(reopened.readEntry(v.entryId), null);
    } finally { rootKey.fill(0); }
  }
});

test("a competing revision wins once while both independent reservations remain consumed", async () => {
  const name = file(), first = create(name), second = open(name, { writable: true }), rootKey = key();
  try {
    const results = await Promise.allSettled([first.writeEntry(rootKey, plaintext(), context()), second.writeEntry(rootKey, plaintext(), context())]);
    assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
    assert.equal(results.filter(result => result.status === "rejected" && result.reason.code === "CONFLICT").length, 1);
    assert.equal(first.getUsage().encryptionCount, 2); assert.equal(first.listEntryContexts().length, 1);
  } finally { rootKey.fill(0); }
});

test("an abrupt process exit after reservation keeps the IV spent before ciphertext exists", () => {
  const name = file(); create(name).close();
  const storeUrl = new URL("../apps/api/dist/apps/api/src/db/v2-store.js", import.meta.url).href;
  const script = `import crypto from 'node:crypto'; import {syncBuiltinESMExports} from 'node:module'; import {openV2Store} from ${JSON.stringify(storeUrl)}; const store=openV2Store(${JSON.stringify(name)},${JSON.stringify(expected())},{writable:true}); crypto.randomBytes=n=>Buffer.alloc(n,170); crypto.createCipheriv=()=>process.exit(91); syncBuiltinESMExports(); await store.writeEntry(Buffer.from(${JSON.stringify(v.rootKeyHex)},'hex'),${JSON.stringify(plaintext())},${JSON.stringify(context())});`;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], { encoding: "utf8", timeout: 15000, env: { ...process.env } });
  assert.equal(result.status, 91, result.stdout + result.stderr);
  const reopened = open(name); assert.equal(reopened.getUsage().encryptionCount, 1); assert.equal(reopened.readEntry(v.entryId), null);
  raw(name, db => assert.deepEqual(db.prepare("SELECT iv FROM vault_nonces").get().iv, Buffer.alloc(12, 170)));
});

test("the actual 2^20 reservation limit allows the last use and rejects further encryption even after delete/reopen", { timeout: 120000 }, async () => {
  const name = file(); create(name).close();
  raw(name, db => db.transaction(() => {
    db.prepare(`WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value + 1 FROM n WHERE value < ?)
      INSERT INTO vault_nonces SELECT ?, CAST(printf('%012x', value) AS BLOB), 'capacity-fixture', 1 FROM n`)
      .run(V2_STORE_LIMITS.encryptions - 1, v.keyId);
    db.prepare("UPDATE vault_header SET encryption_count = ?").run(V2_STORE_LIMITS.encryptions - 1);
  })());
  const handle = open(name, { writable: true }), rootKey = key();
  try {
    await handle.writeEntry(rootKey, plaintext(), context()); assert.equal(handle.getUsage().encryptionCount, V2_STORE_LIMITS.encryptions);
    handle.deleteEntry(context()); handle.close();
    const reopened = open(name, { writable: true });
    await assert.rejects(reopened.writeEntry(rootKey, plaintext(), context(2)), code("KEY_LIMIT"));
    assert.equal(reopened.getUsage().encryptionCount, V2_STORE_LIMITS.encryptions);
  } finally { rootKey.fill(0); }
});

test("a failed schema initialization leaves no partial v2 identity or tables and is never silently retried", () => {
  const name = file(), original = Database.prototype.exec;
  mock.method(Database.prototype, "exec", function (sql) {
    if (sql.includes("CREATE TABLE vault_header")) {
      original.call(this, sql.slice(0, sql.indexOf(";")));
      throw new Error("fixture-storage-secret-canary");
    }
    return original.call(this, sql);
  });
  assert.throws(() => createV2Store(name, slot()), code("IO_FAILED"));
  mock.restoreAll();
  assert.ok(existsSync(name));
  raw(name, db => {
    assert.equal(db.pragma("application_id", { simple: true }), 0);
    assert.equal(db.pragma("user_version", { simple: true }), 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema").get().count, 0);
  });
  assert.throws(() => createV2Store(name, slot()), code("EXISTS"));
});

test("stored identity and missing reservations fail closed; ciphertext authentication remains the codec's responsibility", async () => {
  const rootKey = key();
  try {
    for (const change of ["revision", "nonce", "tag"]) {
      const name = file(), handle = create(name); const sealed = await handle.writeEntry(rootKey, plaintext(), context());
      raw(name, db => {
        if (change === "revision") db.exec("UPDATE vault_entries SET revision = 2");
        if (change === "nonce") db.exec("DELETE FROM vault_nonces");
        if (change === "tag") {
          const tag = Buffer.from(sealed.tag, "base64"); tag[0] ^= 1;
          db.prepare("UPDATE vault_entries SET envelope = ?").run(JSON.stringify({ ...sealed, tag: tag.toString("base64") }));
        }
      });
      if (change === "tag") assert.throws(() => codec.openEntry(rootKey, handle.readEntry(v.entryId), context()), code("AUTHENTICATION_FAILED"));
      else {
        assert.throws(() => handle.readEntry(v.entryId), code("INVALID_STORE"));
        assert.throws(() => handle.getUsage(), code("FAULTED"));
      }
    }
  } finally { rootKey.fill(0); }
});

test("the active-entry cap accepts updates, rejects new entries and permits a new entry after deletion", { timeout: 120000 }, async () => {
  const name = file(); create(name).close(); const rootKey = key(), rows = [];
  try {
    // Build valid synthetic ciphertext in memory, then batch-load the capacity fixture.
    for (let index = 0; index < V2_STORE_LIMITS.entries; index++) {
      const id = `capacity-${index}`;
      rows.push(await codec.sealEntry(rootKey, plaintext(id), context(1, id), () => true));
    }
    raw(name, db => db.transaction(() => {
      const nonce = db.prepare("INSERT INTO vault_nonces VALUES (?, ?, ?, ?)");
      const entry = db.prepare("INSERT INTO vault_entries VALUES (?, ?, ?)");
      for (const row of rows) {
        nonce.run(row.keyId, Buffer.from(row.iv, "base64"), row.entryId, row.revision);
        entry.run(row.entryId, row.revision, JSON.stringify(row));
      }
      db.prepare("UPDATE vault_header SET encryption_count = ?").run(rows.length);
    })());
    const handle = open(name, { writable: true });
    await assert.rejects(handle.writeEntry(rootKey, plaintext(), context()), code("ENTRY_LIMIT"));
    assert.equal(handle.getUsage().encryptionCount, V2_STORE_LIMITS.entries);
    await handle.writeEntry(rootKey, plaintext("capacity-0"), context(2, "capacity-0"));
    handle.deleteEntry(context(2, "capacity-0"));
    await handle.writeEntry(rootKey, plaintext(), context());
    assert.equal(handle.listEntryContexts().length, V2_STORE_LIMITS.entries);
    assert.equal(handle.getUsage().encryptionCount, V2_STORE_LIMITS.entries + 2);
  } finally { rootKey.fill(0); }
});

test("a close failure is redacted, faults the handle and permits a later close retry", () => {
  const handle = create(), original = Database.prototype.close; let fail = true;
  mock.method(Database.prototype, "close", function () {
    if (fail) throw new Error("fixture-storage-secret-canary");
    return original.call(this);
  });
  assert.throws(() => handle.close(), code("IO_FAILED"));
  assert.equal(handle.closed, false); assert.throws(() => handle.getUsage(), code("FAULTED"));
  fail = false; handle.close(); handle.close(); assert.equal(handle.closed, true);
});

test("cancellation after encryption but before the storage continuation burns the nonce without persisting", async () => {
  const name = file(), handle = create(name), rootKey = key(), controller = new AbortController();
  const createCipher = native.createCipheriv;
  mock.method(native, "createCipheriv", (...args) => {
    const cipher = createCipher(...args);
    queueMicrotask(() => controller.abort("fixture-storage-secret-canary"));
    return cipher;
  });
  syncBuiltinESMExports();
  try {
    const options = { signal: controller.signal };
    const pending = handle.writeEntry(rootKey, plaintext(), context(), options);
    options.signal = new AbortController().signal;
    await assert.rejects(pending, code("CANCELLED"));
    assert.equal(handle.getUsage().encryptionCount, 1);
    assert.equal(handle.readEntry(v.entryId), null);
  } finally { rootKey.fill(0); }
});
