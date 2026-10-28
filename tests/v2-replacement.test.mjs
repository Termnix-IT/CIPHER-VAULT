import assert from "node:assert/strict";
import { before, after, afterEach, mock, test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import crypto from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";
import { compatibility, createMigratedFixture, v2Password } from "./v2-runtime-fixture.mjs";
import { replaceV2Vault, recoverV2Replacement, inspectV2Replacement, V2ReplacementError } from "../apps/api/dist/apps/api/src/migration/v2-replacement.js";
import { inspectVaultSelection } from "../apps/api/dist/apps/api/src/migration/active-pointer.js";
import { unwrapRootKey, openEntry } from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";
import { openV2Store } from "../apps/api/dist/apps/api/src/db/v2-store.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import * as storage from "../apps/api/dist/apps/api/src/db/vault-context.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import { verifyBackupRecovery } from "../apps/api/dist/apps/api/src/migration/backup-recovery.js";

const require = createRequire(import.meta.url), root = fs.mkdtempSync(path.join(tmpdir(), "cipher-vault-replacement-")), base = path.join(root, "base");
const passphrase = compatibility.backupV1.passphrase, newPassword = "synthetic-replacement-new-master-password", sessions = [];
let context, sourceKey, sequence = 0;
const input = (mode = "rekey") => ({ mode, masterPassword: v2Password, newMasterPassword: newPassword,
  confirmNewMasterPassword: newPassword, backupPassphrase: passphrase, ...(mode === "reset" ? { confirmation: "RESET_ALL_DATA" } : {}) });
const file = (f, name) => path.join(f, name), source = f => path.join(f, "vaults", context.vaultId, "vault.sqlite");
const fixture = () => { const f = file(root, `case-${++sequence}`); fs.cpSync(base, f, { recursive: true }); return f; };
const hash = f => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const raw = (f, action) => { const db = new Database(f, { timeout: 0 }); try { return action(db); } finally { db.close(); } };
const sorted = values => [...values].sort((a, b) => a.id.localeCompare(b.id));
const owner = (key = sourceKey) => { const session = new VaultSession(); session.unlock(key); sessions.push(session); return { session, sessionId: session.requireUnlocked() }; };
const code = expected => error => { assert.ok(error instanceof V2ReplacementError); assert.equal(error.code, expected);
  for (const secret of [root, v2Password, newPassword, passphrase]) assert.ok(!String(error).includes(secret)); return true; };
function restoreMocks() { mock.restoreAll(); syncBuiltinESMExports(); }
function beforeState(f) { return { source: hash(source(f)), pointer: hash(file(f, "vault-current.json")), receipt: hash(file(f, "vault-activation.json")) }; }
function unchanged(f, before) { assert.deepEqual(beforeState(f), before); assert.deepEqual(inspectVaultSelection(f).context, context);
  raw(source(f), db => db.exec("BEGIN IMMEDIATE; ROLLBACK")); }
function failRename(f, boundary, after = false) {
  const rename = fs.renameSync; let fired = false, acknowledgments = 0;
  mock.method(fs, "renameSync", (from, to) => {
    const name = path.basename(to); if (name === "vault-activation.json") acknowledgments++;
    const hit = !fired && (boundary === "prepared" ? name === "vault-activation.json" && acknowledgments === 1 :
      boundary === "committed" ? name === "vault-activation.json" && acknowledgments === 2 :
      name === boundary) && to.startsWith(f + path.sep);
    if (hit) { fired = true; if (after) rename(from, to); throw new Error("synthetic interruption"); }
    return rename(from, to);
  }); syncBuiltinESMExports(); return () => assert.ok(fired);
}
async function interrupted(f, mode = "rekey", boundary = "vault-current.json", after = false) {
  const fired = failRename(f, boundary, after);
  await assert.rejects(replaceV2Vault(f, context, input(mode), owner()), code("RECOVERY_REQUIRED")); fired(); restoreMocks();
  assert.throws(() => inspectVaultSelection(f), { code: "RECOVERY_REQUIRED" });
  assert.throws(() => storage.openVaultStorage({ dataDirectory: f }), { code: "RECOVERY_REQUIRED" });
  return inspectV2Replacement(f);
}
async function decode(f, selected, password = newPassword) {
  const store = openV2Store(path.join(f, "vaults", selected.vaultId, "vault.sqlite"), selected), key = await unwrapRootKey(store.readPasswordSlot(), password, selected);
  try { return store.listEntryContexts().map(c => { const text = openEntry(key, store.readEntry(c.entryId), c); try { return JSON.parse(text.toString("utf8")); } finally { text.fill(0); } }); }
  finally { key.fill(0); store.close(); }
}
before(async () => {
  context = await createMigratedFixture(base); const store = openV2Store(source(base), context);
  try { sourceKey = await unwrapRootKey(store.readPasswordSlot(), v2Password, context); } finally { store.close(); }
});
afterEach(() => { restoreMocks(); storage.closeVaultStorage(); sessions.splice(0).forEach(session => session.lock()); });
after(() => {
  sourceKey?.fill(0); assert.equal(path.dirname(root), path.resolve(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-replacement-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("replacement import has no environment-selected storage or file side effects", () => {
  const f = fixture(), names = fs.readdirSync(f), url = new URL("../apps/api/dist/apps/api/src/migration/v2-replacement.js", import.meta.url).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)})`], {
    cwd: f, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: file(f, "must-not-exist") }, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stdout + result.stderr); assert.deepEqual(fs.readdirSync(f), names); assert.equal(storage.hasVaultStorage(), false);
});

test("rekey preserves every DTO field, changes root and identities, and wipes owned KDF/session buffers", async () => {
  const f = fixture(), before = beforeState(f), authorization = owner(), ownedKey = authorization.session.requireKey(), keys = [], passwords = [];
  const scrypt = crypto.scrypt;
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
    passwords.push(password); return scrypt(password, salt, length, options, (error, key) => { if (key) keys.push(key); callback(error, key); });
  }); syncBuiltinESMExports();
  const result = await replaceV2Vault(f, context, input(), authorization);
  assert.equal(result.state, "v2-selected"); assert.equal(result.mode, "rekey"); assert.equal(result.targetCount, compatibility.legacy.entries.length);
  assert.ok(Object.isFrozen(result)); assert.equal(result.durability, process.platform === "win32" ? "file-sync" : "file-and-directory-sync");
  assert.notEqual(result.target.vaultId, context.vaultId); assert.notEqual(result.target.keyId, context.keyId);
  assert.deepEqual(sorted(await decode(f, result.target)), sorted(compatibility.legacy.entries));
  const store = openV2Store(result.files.database, result.target);
  try {
    await assert.rejects(unwrapRootKey(store.readPasswordSlot(), v2Password, result.target), { code: "AUTHENTICATION_FAILED" });
    const key = await unwrapRootKey(store.readPasswordSlot(), newPassword, result.target); assert.notDeepEqual(key, sourceKey); key.fill(0);
    assert.equal(store.getUsage().encryptionCount, result.targetCount);
    for (const c of store.listEntryContexts()) { assert.equal(c.revision, 1); assert.throws(() => openEntry(sourceKey, store.readEntry(c.entryId), c), { code: "AUTHENTICATION_FAILED" }); }
  } finally { store.close(); }
  assert.equal(hash(source(f)), before.source); assert.deepEqual(ownedKey, Buffer.alloc(32)); assert.equal(authorization.session.getState().isUnlocked, false);
  assert.ok(keys.length >= 10); assert.ok(keys.every(key => key.every(byte => byte === 0)));
  assert.ok(passwords.every(password => !Buffer.isBuffer(password) || password.every(byte => byte === 0)));
  assert.ok(fs.existsSync(result.files.archive)); assert.ok(!fs.existsSync(file(f, "vault-transition.json")));
  raw(source(f), db => db.exec("BEGIN IMMEDIATE; ROLLBACK")); raw(result.files.database, db => db.exec("BEGIN IMMEDIATE; ROLLBACK"));
  storage.openVaultStorage({ dataDirectory: f }); await vault.unlockVault({ masterPassword: newPassword });
  const created = await entries.createEntry({ serviceName: "replacement-service", loginId: "synthetic-login", password: "synthetic-secret" });
  assert.equal(entries.getEntryById(created.id).password, "synthetic-secret"); entries.deleteEntry(created.id);
});

test("reset selects a newly keyed empty vault while source DB and restorable encrypted backup survive", async () => {
  const f = fixture(), before = beforeState(f), result = await replaceV2Vault(f, context, input("reset"), owner());
  assert.equal(result.targetCount, 0); assert.equal(result.sourceCount, compatibility.legacy.entries.length); assert.equal(hash(source(f)), before.source);
  assert.deepEqual(await decode(f, result.target), []); assert.deepEqual(sorted(await decode(f, context, v2Password)), sorted(compatibility.legacy.entries));
  const recovered = await verifyBackupRecovery(fs.readFileSync(result.files.backup, "utf8"), Buffer.from(passphrase), () => {});
  assert.deepEqual(sorted(recovered), sorted(compatibility.legacy.entries)); recovered.length = 0;
  const store = openV2Store(result.files.database, result.target); assert.equal(store.getUsage().encryptionCount, 0); store.close();
  storage.openVaultStorage({ dataDirectory: f }); await assert.rejects(vault.unlockVault({ masterPassword: v2Password }), { statusCode: 401 });
  await vault.unlockVault({ masterPassword: newPassword }); assert.equal(entries.listEntries().items.length, 0);
});

test("invalid confirmation, reused password, malformed Unicode and unknown fields stop before KDF or artifact creation", async () => {
  const f = fixture(), before = beforeState(f), names = fs.readdirSync(file(f, "vaults")), authorization = owner();
  mock.method(crypto, "scrypt", () => { throw new Error("must not derive"); }); syncBuiltinESMExports();
  for (const change of [{ confirmNewMasterPassword: "mismatch" }, { newMasterPassword: v2Password, confirmNewMasterPassword: v2Password },
    { newMasterPassword: "synthetic-\ud800-password", confirmNewMasterPassword: "synthetic-\ud800-password" }, { extra: true },
    { mode: "unknown" }, { mode: "reset" }, { confirmation: "RESET_ALL_DATA" }, { masterPassword: Buffer.from(v2Password) }])
    await assert.rejects(replaceV2Vault(f, context, { ...input(), ...change }, authorization), code("INVALID_INPUT"));
  await assert.rejects(replaceV2Vault(f, context, input(), authorization, { signal: AbortSignal.abort() }), code("CANCELLED"));
  authorization.session.lock(); await assert.rejects(replaceV2Vault(f, context, input(), authorization), code("CANCELLED"));
  unchanged(f, before); assert.deepEqual(fs.readdirSync(file(f, "vaults")), names);
});

test("normal Context and direct legacy provider must be closed before replacement", async () => {
  const f = fixture(), before = beforeState(f); storage.openVaultStorage({ dataDirectory: f });
  await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("IN_USE")); storage.closeVaultStorage(); unchanged(f, before);
  const { openDatabase, closeDatabase } = await import("../apps/api/dist/apps/api/src/db/database.js");
  openDatabase({ dataDirectory: f });
  try { await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("IN_USE")); } finally { closeDatabase(); }
});

test("old master and the independently owned Session must both authenticate the selected source", async () => {
  for (const [request, authorization] of [[{ ...input(), masterPassword: "synthetic-wrong-master" }, owner()], [input(), owner(Buffer.alloc(32, 91))]]) {
    const f = fixture(), before = beforeState(f), names = fs.readdirSync(file(f, "vaults"));
    await assert.rejects(replaceV2Vault(f, context, request, authorization), code("AUTHENTICATION_FAILED"));
    unchanged(f, before); assert.deepEqual(fs.readdirSync(file(f, "vaults")), names); assert.equal(authorization.session.getState().isUnlocked, false);
  }
});

test("late cancellation holds single-flight until native KDF completion and cannot lock a newer Session generation", async () => {
  const f = fixture(), before = beforeState(f), authorization = owner(), abort = new AbortController(), scrypt = crypto.scrypt;
  let captured, key; const ready = new Promise(resolve => {
    mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, derived) => {
      key = derived; captured = () => callback(error, derived); resolve();
    })); syncBuiltinESMExports();
  });
  const pending = replaceV2Vault(f, context, input(), authorization, { signal: abort.signal }); await ready;
  abort.abort(); authorization.session.unlock(Buffer.alloc(32, 87)); const generation = authorization.session.requireUnlocked();
  await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("BUSY")); captured();
  await assert.rejects(pending, code("CANCELLED")); assert.deepEqual(key, Buffer.alloc(32));
  assert.equal(authorization.session.requireUnlocked(), generation); unchanged(f, before);
});

test("source and target IMMEDIATE locks exclude independent writers during KDF and publication", async () => {
  const f = fixture(), scrypt = crypto.scrypt, checks = []; let checked = 0;
  function writer(database) {
    const result = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1],{timeout:0});try{d.exec('BEGIN IMMEDIATE');process.exitCode=2}catch(e){if(e.code!=='SQLITE_BUSY')throw e}finally{d.close()}`, database], { encoding: "utf8", timeout: 10000 });
    if (result.error) throw result.error;
    checks.push(result.status);
  }
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => { if (!checked) { writer(source(f)); checked++; } return scrypt(password, salt, length, options, callback); });
  const rename = fs.renameSync;
  mock.method(fs, "renameSync", (from, to) => {
    if (path.basename(to) === "vault-current.json") { const pending = inspectV2Replacement(f); writer(source(f)); writer(path.join(f, "vaults", pending.target.vaultId, "vault.sqlite")); checked++; }
    return rename(from, to);
  }); syncBuiltinESMExports();
  await replaceV2Vault(f, context, input(), owner()); assert.equal(checked, 2);
  assert.deepEqual(checks, [0, 0, 0], "source during KDF, source and target during publication must remain locked");
});

test("replacement recovery retains source and target locks through hash checks and publication", async () => {
  const f = fixture(), hint = await interrupted(f), rename = fs.renameSync, checks = [];
  mock.method(fs, "renameSync", (from, to) => {
    if (path.basename(to) === "vault-current.json") for (const database of [source(f), path.join(f, "vaults", hint.target.vaultId, "vault.sqlite")]) {
      const writer = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1],{timeout:0});try{d.exec('BEGIN IMMEDIATE');process.exitCode=2}catch(e){if(e.code!=='SQLITE_BUSY')throw e}finally{d.close()}`, database], { encoding: "utf8", timeout: 10000 });
      if (writer.error) throw writer.error;
      checks.push(writer.status);
    }
    return rename(from, to);
  }); syncBuiltinESMExports();
  await recoverV2Replacement(f, hint, input(), owner());
  assert.deepEqual(checks, [0, 0], "recovery must not drop locks when raw fingerprint descriptors close");
});

test("a source at the actual 2^20 nonce limit can rekey without resetting or reusing its old ledger", { timeout: 180000 }, async () => {
  const f = fixture(), entryId = compatibility.legacy.entries[0].id, maximum = 2 ** 20;
  raw(source(f), db => {
    const count = db.prepare("SELECT encryption_count n FROM vault_header").get().n;
    const insert = db.prepare("INSERT INTO vault_nonces(key_id,iv,entry_id,revision) VALUES(?,?,?,2)"), iv = Buffer.alloc(12);
    db.transaction(() => {
      for (let index = count; index < maximum; index++) { iv.writeBigUInt64BE(BigInt(index), 4); insert.run(context.keyId, iv, entryId); }
      db.prepare("UPDATE vault_header SET encryption_count=?").run(maximum);
    }).immediate(); iv.fill(0);
  });
  assert.ok(fs.statSync(source(f)).size > 64 * 1024 * 1024); const before = hash(source(f));
  const result = await replaceV2Vault(f, context, input(), owner()); assert.equal(hash(source(f)), before);
  const old = openV2Store(source(f), context), next = openV2Store(result.files.database, result.target);
  try { assert.equal(old.getUsage().encryptionCount, maximum); assert.equal(next.getUsage().encryptionCount, compatibility.legacy.entries.length); }
  finally { old.close(); next.close(); }
  assert.deepEqual(sorted(await decode(f, result.target)), sorted(compatibility.legacy.entries));
});

for (const failure of ["backup-write", "snapshot-flush", "backup-close", "journal-flush"]) {
  test(`${failure} failure retains the selected source and releases every database handle`, async () => {
    const f = fixture(), before = beforeState(f), open = fs.openSync, write = fs.writeFileSync, flush = fs.fsyncSync, close = fs.closeSync, descriptors = new Map();
    let failed = false;
    mock.method(fs, "openSync", (name, ...args) => { const fd = open(name, ...args); descriptors.set(fd, String(name)); return fd; });
    mock.method(fs, "writeFileSync", (fd, ...args) => {
      if (!failed && failure === "backup-write" && descriptors.get(fd)?.endsWith("source.cvault")) { failed = true; throw new Error("synthetic write failure"); }
      return write(fd, ...args);
    });
    mock.method(fs, "fsyncSync", fd => {
      const name = descriptors.get(fd) ?? "";
      if (!failed && (failure === "snapshot-flush" && name.endsWith("source.sqlite") || failure === "journal-flush" && path.basename(name).startsWith(".vault-transition.json."))) {
        failed = true; throw new Error("synthetic flush failure");
      } return flush(fd);
    });
    mock.method(fs, "closeSync", fd => {
      const name = descriptors.get(fd); descriptors.delete(fd); close(fd);
      if (!failed && failure === "backup-close" && name?.endsWith("source.cvault")) { failed = true; throw new Error("synthetic close failure after descriptor closed"); }
    }); syncBuiltinESMExports();
    await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("IO_FAILED")); assert.ok(failed); restoreMocks(); unchanged(f, before);
    assert.equal(fs.existsSync(file(f, "vault-transition.json")), false);
  });
}

test("current source edits and revision history are preserved even when the original activation count is stale", async () => {
  const f = fixture(); storage.openVaultStorage({ dataDirectory: f }); await vault.unlockVault({ masterPassword: v2Password });
  const first = entries.listEntries().items[0], original = entries.getEntryById(first.id), { id, createdAt, updatedAt, passwordChangedAt, ...payload } = original;
  await entries.updateEntry(id, { ...payload, group: payload.group ?? undefined, notes: "synthetic edited notes" });
  const added = await entries.createEntry({ serviceName: "later-created", loginId: "later-id", password: "later-password", tags: ["z", "a"] });
  const expected = entries.listEntries().items.map(item => entries.getEntryById(item.id)); storage.closeVaultStorage(); const before = hash(source(f));
  const result = await replaceV2Vault(f, context, input(), owner()); assert.equal(result.sourceCount, compatibility.legacy.entries.length + 1);
  assert.deepEqual(sorted(await decode(f, result.target)), sorted(expected)); assert.equal(hash(source(f)), before);
  const store = openV2Store(source(f), context); try { assert.equal(store.listEntryContexts().find(c => c.entryId === id).revision, 2); } finally { store.close(); }
  assert.ok(added.id);
});

for (const boundary of ["vault-transition.json", "prepared", "vault-current.json", "committed", "replacement.json"]) {
  test(`interruption before ${boundary} keeps source bytes; explicit recovery verifies and finishes an existing journal`, async () => {
    const f = fixture(), before = beforeState(f), fired = failRename(f, boundary);
    await assert.rejects(replaceV2Vault(f, context, input(), owner()), code(boundary === "vault-transition.json" ? "IO_FAILED" : "RECOVERY_REQUIRED")); fired(); restoreMocks();
    assert.equal(hash(source(f)), before.source);
    if (boundary === "vault-transition.json") { unchanged(f, before); return; }
    const hint = inspectV2Replacement(f); assert.throws(() => inspectVaultSelection(f), { code: "RECOVERY_REQUIRED" });
    const result = await recoverV2Replacement(f, hint, input(), owner()); assert.deepEqual(inspectVaultSelection(f).context, result.target);
    assert.deepEqual(sorted(await decode(f, result.target)), sorted(compatibility.legacy.entries)); assert.equal(hash(source(f)), before.source);
  });
}

test("a journal whose rename succeeded but flush failed still blocks startup and can recover", async () => {
  const f = fixture(), hint = await interrupted(f, "rekey", "vault-transition.json", true);
  const result = await recoverV2Replacement(f, hint, input(), owner()); assert.deepEqual(inspectVaultSelection(f).context, result.target);
});

test("reset recovery retains its explicit confirmation and verifies both the old data and empty target", async () => {
  const f = fixture(), hint = await interrupted(f, "reset"), before = hash(source(f));
  await assert.rejects(recoverV2Replacement(f, hint, { ...input("reset"), confirmation: undefined }, owner()), code("INVALID_INPUT"));
  const result = await recoverV2Replacement(f, hint, input("reset"), owner()); assert.deepEqual(await decode(f, result.target), []); assert.equal(hash(source(f)), before);
});

test("explicit recovery preserves malformed global metadata and refuses a valid unrelated pointer", async () => {
  const f = fixture(), hint = await interrupted(f);
  fs.writeFileSync(file(f, "vault-current.json"), JSON.stringify({ format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: crypto.randomUUID() }));
  const unrelated = hash(file(f, "vault-current.json"));
  await assert.rejects(recoverV2Replacement(f, hint, input(), owner()), code("RECOVERY_REQUIRED")); assert.equal(hash(file(f, "vault-current.json")), unrelated);
  fs.writeFileSync(file(f, "vault-current.json"), Buffer.from([255, 0, 1])); fs.writeFileSync(file(f, "vault-activation.json"), "{broken receipt");
  const result = await recoverV2Replacement(f, hint, input(), owner());
  const preserved = fs.readdirSync(result.files.directory).filter(name => name.startsWith("preserved-")); assert.equal(preserved.length, 2);
  const contents = preserved.map(name => Buffer.from(fs.readFileSync(file(result.files.directory, name), "utf8"), "base64"));
  assert.ok(contents.some(bytes => bytes.equals(Buffer.from([255, 0, 1])))); assert.ok(contents.some(bytes => bytes.toString() === "{broken receipt"));
});

test("any changed source, target, snapshot or recovery backup rejects recovery without entry writes", async () => {
  const seed = fixture(), hint = await interrupted(seed), names = ["source", "vault.sqlite", "source.sqlite", "source.cvault", "target.cvault", "source-pointer.json", "source-receipt.json"];
  for (const name of names) {
    const f = file(root, `tamper-${++sequence}`); fs.cpSync(seed, f, { recursive: true });
    const changed = name === "source" ? source(f) : path.join(f, "vaults", hint.target.vaultId, name);
    if (name.endsWith("sqlite") || name === "source") raw(changed, db => db.exec("UPDATE vault_header SET password_slot=password_slot||' '"));
    else fs.appendFileSync(changed, " ");
    const sourceHash = hash(source(f)), targetHash = hash(path.join(f, "vaults", hint.target.vaultId, "vault.sqlite"));
    await assert.rejects(recoverV2Replacement(f, hint, input(), owner()), code("RECOVERY_REQUIRED"));
    assert.equal(hash(source(f)), sourceHash); assert.equal(hash(path.join(f, "vaults", hint.target.vaultId, "vault.sqlite")), targetHash);
    assert.throws(() => inspectVaultSelection(f), { code: "RECOVERY_REQUIRED" });
  }
});

test("unknown, noncanonical, missing and mismatched journals cannot be guessed or repaired automatically", async () => {
  const f = fixture(); fs.writeFileSync(file(f, "vault-transition.json"), "{}");
  assert.throws(() => inspectV2Replacement(f), code("RECOVERY_REQUIRED")); assert.throws(() => storage.openVaultStorage({ dataDirectory: f }), { code: "RECOVERY_REQUIRED" });
  fs.unlinkSync(file(f, "vault-current.json")); fs.unlinkSync(file(f, "vault-activation.json"));
  assert.throws(() => inspectVaultSelection(f), { code: "RECOVERY_REQUIRED" }); // No fallback even with both globals absent.
  const g = fixture(), hint = await interrupted(g), journal = file(g, "vault-transition.json"), bytes = fs.readFileSync(journal);
  fs.appendFileSync(journal, "\n"); assert.throws(() => inspectV2Replacement(g), code("RECOVERY_REQUIRED")); fs.writeFileSync(journal, bytes);
  await assert.rejects(recoverV2Replacement(g, { ...hint, target: { ...hint.target, keyId: crypto.randomUUID() } }, input(), owner()), code("RECOVERY_REQUIRED"));
});

test("a failed target is retained with spent nonces and is never resumed or reused by the next attempt", async () => {
  const f = fixture(), before = beforeState(f), transaction = Database.prototype.transaction; let failed = false;
  mock.method(Database.prototype, "transaction", function (...args) {
    const wrapped = transaction.apply(this, args), database = this, result = (...values) => wrapped(...values);
    result.immediate = (...values) => { const value = wrapped.immediate(...values);
      if (!failed && database.name.endsWith("vault.sqlite") && database.name !== source(f) &&
          database.prepare("SELECT encryption_count n FROM vault_header").get()?.n > 0) { failed = true; throw new Error("synthetic interrupted target write"); }
      return value;
    }; return result;
  });
  await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("VERIFICATION_FAILED")); assert.ok(failed); restoreMocks(); unchanged(f, before);
  const candidates = fs.readdirSync(file(f, "vaults")).filter(id => id !== context.vaultId); assert.equal(candidates.length, 1);
  const abandoned = path.join(f, "vaults", candidates[0], "vault.sqlite"), abandonedHash = hash(abandoned);
  raw(abandoned, db => assert.ok(db.prepare("SELECT encryption_count n FROM vault_header").get().n > 0));
  const result = await replaceV2Vault(f, context, input(), owner()); assert.notEqual(result.target.vaultId, candidates[0]); assert.equal(hash(abandoned), abandonedHash);
});

test("hard-linked source metadata and linked recovery files are rejected without overwriting the target", async () => {
  const f = fixture(), alias = file(f, "pointer-alias"); fs.linkSync(file(f, "vault-current.json"), alias);
  await assert.rejects(replaceV2Vault(f, context, input(), owner()), code("VERIFICATION_FAILED"));
  const g = fixture(), hint = await interrupted(g), snapshot = path.join(g, "vaults", hint.target.vaultId, "source.sqlite"), before = hash(snapshot);
  fs.linkSync(snapshot, file(g, "snapshot-alias")); await assert.rejects(recoverV2Replacement(g, hint, input(), owner()), code("RECOVERY_REQUIRED")); assert.equal(hash(snapshot), before);
});

test("a pending transition invalidates an already running v2 Context and zeros its global Session", async () => {
  const f = fixture(); storage.openVaultStorage({ dataDirectory: f }); await vault.unlockVault({ masterPassword: v2Password });
  const { vaultSession } = await import("../apps/api/dist/apps/api/src/services/vault-session.js"), key = vaultSession.requireKey(), before = hash(source(f));
  fs.writeFileSync(file(f, "vault-transition.json"), "{}"); assert.throws(() => entries.listEntries(), { statusCode: 503 });
  assert.deepEqual(key, Buffer.alloc(32)); assert.equal(hash(source(f)), before);
});

for (const boundary of ["vault-transition.json", "prepared", "vault-current.json", "committed", "replacement.json"]) {
  test(`process exit immediately after ${boundary} has a deterministic selection and retains the original DB`, async () => {
    const f = fixture(), before = hash(source(f)), module = new URL("../apps/api/dist/apps/api/src/migration/v2-replacement.js", import.meta.url).href,
      sessionModule = new URL("../apps/api/dist/apps/api/src/services/vault-session.js", import.meta.url).href;
    const script = `import fs from 'node:fs';import path from 'node:path';import{syncBuiltinESMExports}from'node:module';import{replaceV2Vault}from${JSON.stringify(module)};import{VaultSession}from${JSON.stringify(sessionModule)};
      const rename=fs.renameSync;let receipts=0;fs.renameSync=(a,b)=>{rename(a,b);const name=path.basename(b);if(name==='vault-activation.json')receipts++;const at=${JSON.stringify(boundary)};if(at==='prepared'?name==='vault-activation.json'&&receipts===1:at==='committed'?name==='vault-activation.json'&&receipts===2:name===at)process.exit(71)};syncBuiltinESMExports();const session=new VaultSession(),key=Buffer.from(${JSON.stringify(sourceKey.toString("hex"))},'hex');session.unlock(key);key.fill(0);await replaceV2Vault(${JSON.stringify(f)},${JSON.stringify(context)},${JSON.stringify(input())},{session,sessionId:session.requireUnlocked()});`;
    const child = spawnSync(process.execPath, ["--input-type=module", "--eval", script], { encoding: "utf8", timeout: 30000 });
    assert.equal(child.status, 71, child.stdout + child.stderr); assert.equal(hash(source(f)), before);
    if (boundary === "replacement.json") { const selected = inspectVaultSelection(f); assert.notEqual(selected.context.vaultId, context.vaultId); assert.deepEqual(sorted(await decode(f, selected.context)), sorted(compatibility.legacy.entries)); }
    else { const hint = inspectV2Replacement(f); assert.throws(() => inspectVaultSelection(f), { code: "RECOVERY_REQUIRED" }); await recoverV2Replacement(f, hint, input(), owner()); }
  });
}
