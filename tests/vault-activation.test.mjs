import assert from "node:assert/strict";
import { before, after, afterEach, mock, test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import crypto from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { spawnSync } from "node:child_process";
import Database from "better-sqlite3";
import { stageLegacyVault } from "../apps/api/dist/apps/api/src/migration/staging.js";
import { activateStagedVault, recoverVaultActivation, inspectVaultSelection, VaultActivationError } from "../apps/api/dist/apps/api/src/migration/activation.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import { openV2Store } from "../apps/api/dist/apps/api/src/db/v2-store.js";
import { unwrapRootKey } from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";

const require = createRequire(import.meta.url), fixture = JSON.parse(fs.readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
const legacy = fixture.legacy, schema = fs.readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8");
const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cipher-vault-activation-")), base = path.join(root, "base");
const input = () => ({ masterPassword: legacy.password, newMasterPassword: "synthetic-activation-new-password", backupPassphrase: fixture.backupV1.passphrase });
let context, sequence = 0; const sessions = [];
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const raw = (file, action) => { const db = new Database(file, { timeout: 0 }); try { return action(db); } finally { db.close(); } };
const file = (f, name) => path.join(f, name);
const target = f => path.join(f, "vaults", context.vaultId, "vault.sqlite");
const artifact = (f, name) => path.join(f, "vaults", context.vaultId, name);
function owner(key = Buffer.from(legacy.keyHex, "hex"), clock) {
  const session = clock ? new VaultSession(clock, () => () => {}) : new VaultSession(); session.unlock(key); key.fill(0); sessions.push(session);
  return { session, sessionId: session.requireUnlocked() };
}
const copy = () => { const f = path.join(root, `case-${++sequence}`); fs.cpSync(base, f, { recursive: true }); return f; };
const code = expected => error => {
  assert.ok(error instanceof VaultActivationError); assert.equal(error.code, expected);
  for (const value of [root, legacy.password, legacy.keyHex, input().newMasterPassword, "activation-secret-canary"]) assert.ok(!String(error).includes(value));
  return true;
};
function receipt(f) { return JSON.parse(fs.readFileSync(file(f, "vault-activation.json"), "utf8")); }
function pointer(f) { return JSON.parse(fs.readFileSync(file(f, "vault-current.json"), "utf8")); }
function unchanged(f, original, staged) {
  assert.equal(hash(file(f, "password-manager.db")), original); assert.equal(hash(target(f)), staged);
  for (const database of [file(f, "password-manager.db"), target(f)]) raw(database, db => db.exec("BEGIN IMMEDIATE; ROLLBACK"));
}
before(async () => {
  fs.mkdirSync(base); fs.mkdirSync(file(base, "vaults"));
  raw(file(base, "password-manager.db"), db => {
    db.exec(schema); const m = legacy.metadata;
    db.prepare("INSERT INTO vault_metadata VALUES(1,?,?,?,?,?)").run(m.passwordSalt, m.passwordVerifier, m.kdfParams, m.createdAt, m.updatedAt);
    const columns = db.pragma("table_info(password_entries)").map(column => column.name);
    const insert = db.prepare(`INSERT INTO password_entries(${columns.join(",")}) VALUES(${columns.map(column => "@" + column).join(",")})`);
    for (const row of legacy.rows) insert.run(row);
  });
  const result = await stageLegacyVault(file(base, "password-manager.db"), file(base, "vaults"), {
    ...input(), confirmNewMasterPassword: input().newMasterPassword
  });
  context = { vaultId: result.vaultId, keyId: result.keyId, slotRevision: 1 };
});
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); sessions.splice(0).forEach(session => session.lock()); });
after(() => {
  assert.equal(path.dirname(root), fs.realpathSync(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-activation-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

test("coordinator imports and missing-pointer inspection create no files or provider", () => {
  const f = copy(), names = fs.readdirSync(f), url = new URL("../apps/api/dist/apps/api/src/migration/activation.js", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(url)});`], {
    cwd: f, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: file(f, "must-not-exist") }, encoding: "utf8", timeout: 10000
  });
  assert.equal(child.status, 0, child.stdout + child.stderr); assert.deepEqual(fs.readdirSync(f), names);
  assert.deepEqual(inspectVaultSelection(f), { format: "legacy", database: file(f, "password-manager.db") });
});

test("activation reauthenticates all recovery artifacts, commits strict pointer/receipt and locks its Session", async () => {
  const f = copy(), authorization = owner(), original = hash(file(f, "password-manager.db")), staged = hash(target(f)), keys = [], passwords = [];
  const scrypt = crypto.scrypt;
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
    passwords.push(password); return scrypt(password, salt, length, options, (error, key) => { if (key) keys.push(key); callback(error, key); });
  }); syncBuiltinESMExports();
  const result = await activateStagedVault(f, context, input(), authorization);
  assert.equal(result.state, "v2-selected"); assert.ok(Object.isFrozen(result)); assert.equal(result.entryCount, legacy.entries.length);
  assert.equal(result.durability, process.platform === "win32" ? "file-sync" : "file-and-directory-sync");
  assert.deepEqual(pointer(f), { format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: context.vaultId });
  assert.deepEqual(receipt(f), { format: "CIPHER-VAULT-ACTIVATION", version: 1, vaultId: context.vaultId, keyId: context.keyId, entryCount: legacy.entries.length, state: "committed" });
  assert.equal(authorization.session.getState().isUnlocked, false); unchanged(f, original, staged);
  assert.deepEqual(inspectVaultSelection(f), { format: "v2", database: target(f), context });
  assert.ok(keys.length >= 7 && keys.every(key => key.every(byte => byte === 0)));
  assert.ok(passwords.every(password => !Buffer.isBuffer(password) || password.every(byte => byte === 0)));
});

test("source and target locks exclude writers through KDF and publication and preserve a pre-existing WAL", async () => {
  const f = copy(), source = file(f, "password-manager.db");
  const child = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1]);d.pragma('journal_mode=WAL');d.exec('UPDATE password_entries SET service_name=service_name');process.exit(0)`, source], { encoding: "utf8", timeout: 10000 });
  assert.equal(child.status, 0, child.stdout + child.stderr);
  const before = hash(source), wal = hash(source + "-wal"), scrypt = crypto.scrypt, rename = fs.renameSync, checks = []; let checked = false;
  function checkWriters() {
    for (const database of [source, target(f)]) {
      const writer = spawnSync(process.execPath, ["-e", `const D=require(${JSON.stringify(require.resolve("better-sqlite3"))});const d=new D(process.argv[1],{timeout:0});try{d.exec('BEGIN IMMEDIATE');process.exitCode=2}catch(e){if(e.code!=='SQLITE_BUSY')throw e}finally{d.close()}`, database], { encoding: "utf8", timeout: 10000 });
      if (writer.error) throw writer.error;
      checks.push(writer.status);
    }
  }
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => {
    if (!checked) {
      checkWriters();
      checked = true;
    }
    return scrypt(password, salt, length, options, callback);
  });
  mock.method(fs, "renameSync", (from, to) => { if (path.basename(to) === "vault-current.json") checkWriters(); return rename(from, to); });
  syncBuiltinESMExports();
  await activateStagedVault(f, context, input(), owner()); assert.ok(checked);
  assert.deepEqual(checks, [0, 0, 0, 0], "both DB locks must survive the target's pre-publication fsync");
  assert.equal(hash(source), before); assert.equal(hash(source + "-wal"), wal);
});

test("a stale source cannot activate a previously verified candidate", async () => {
  const f = copy(); raw(file(f, "password-manager.db"), db => db.exec("UPDATE password_entries SET service_name='new legacy edit'"));
  const before = hash(file(f, "password-manager.db")), staged = hash(target(f));
  await assert.rejects(activateStagedVault(f, context, input(), owner()), code("VERIFICATION_FAILED"));
  assert.equal(inspectVaultSelection(f).format, "legacy"); unchanged(f, before, staged);
});

test("wrong credentials and unrelated Session keys never publish a pointer", async () => {
  for (const [change, authorization] of [[{ masterPassword: "incorrect-master" }, owner()], [{ newMasterPassword: "incorrect-new-password" }, owner()], [{}, owner(Buffer.alloc(32, 19))]]) {
    const f = copy(); await assert.rejects(activateStagedVault(f, context, { ...input(), ...change }, authorization), code("AUTHENTICATION_FAILED"));
    assert.equal(inspectVaultSelection(f).format, "legacy"); assert.equal(authorization.session.getState().isUnlocked, false);
  }
});

test("invalid inputs and pre-aborted or locked generations do not start a KDF", async () => {
  const f = copy(), authorization = owner();
  mock.method(crypto, "scrypt", () => { throw new Error("must not derive"); }); syncBuiltinESMExports();
  for (const change of [{ extra: true }, { newMasterPassword: legacy.password }, { newMasterPassword: "bad-\ud800-password" }, { masterPassword: Buffer.from(legacy.password) }])
    await assert.rejects(activateStagedVault(f, context, { ...input(), ...change }, authorization), code("INVALID_INPUT"));
  await assert.rejects(activateStagedVault(f, { ...context, slotRevision: 2 }, input(), authorization), code("INVALID_INPUT"));
  await assert.rejects(activateStagedVault(f, context, input(), authorization, { signal: AbortSignal.abort() }), code("CANCELLED"));
  authorization.session.lock(); await assert.rejects(activateStagedVault(f, context, input(), authorization), code("CANCELLED"));
  assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("a competing target writer blocks activation before any new files", async () => {
  const f = copy(), writer = new Database(target(f)); writer.exec("BEGIN IMMEDIATE");
  try { await assert.rejects(activateStagedVault(f, context, input(), owner()), code("LOCKED")); }
  finally { writer.exec("ROLLBACK"); writer.close(); }
  assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("cancelled native KDF keeps the operation busy and wipes its late result", async () => {
  const f = copy(), authorization = owner(), abort = new AbortController(), scrypt = crypto.scrypt; let release, started;
  const ready = new Promise(resolve => { started = resolve; });
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, key) => {
    release = () => { callback(error, key); return key; }; started();
  })); syncBuiltinESMExports();
  const pending = activateStagedVault(f, context, input(), authorization, { signal: abort.signal }); await ready; abort.abort();
  await assert.rejects(activateStagedVault(f, context, input(), owner()), code("BUSY"));
  const key = release(); await assert.rejects(pending, code("CANCELLED")); assert.ok(key.every(byte => byte === 0));
  assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("a newer Session generation survives an old operation's cleanup", async () => {
  const f = copy(), authorization = owner(), scrypt = crypto.scrypt; let release, started;
  const ready = new Promise(resolve => { started = resolve; });
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, key) => { release = () => callback(error, key); started(); })); syncBuiltinESMExports();
  const pending = activateStagedVault(f, context, input(), authorization); await ready;
  const fresh = Buffer.alloc(32, 41); authorization.session.lock(); authorization.session.unlock(fresh); const state = authorization.session.getState(); release();
  await assert.rejects(pending, code("CANCELLED")); assert.deepEqual(authorization.session.getState(), state); assert.deepEqual(authorization.session.requireKey(), fresh); fresh.fill(0);
  assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("idle expiry during KDF prevents publication without waiting five minutes", async () => {
  const f = copy(); let now = 1000; const authorization = owner(undefined, () => ({ monotonic: now, wall: now })), scrypt = crypto.scrypt;
  mock.method(crypto, "scrypt", (password, salt, length, options, callback) => scrypt(password, salt, length, options, (error, key) => { now += 300001; callback(error, key); })); syncBuiltinESMExports();
  await assert.rejects(activateStagedVault(f, context, input(), authorization), code("CANCELLED")); assert.equal(authorization.session.getState().isUnlocked, false);
  assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("artifact tampering and incomplete candidate files fail before publication", async () => {
  for (const name of ["legacy.cvault", "legacy.sqlite", "v2-export.cvault", "vault.sqlite"]) {
    const f = copy(), namePath = artifact(f, name);
    if (name === "legacy.sqlite") raw(namePath, db => db.exec("UPDATE vault_metadata SET updated_at='2030-01-01T00:00:00.000Z'"));
    else if (name === "vault.sqlite") raw(namePath, db => db.exec("UPDATE vault_header SET encryption_count=encryption_count+1"));
    else { const value = JSON.parse(fs.readFileSync(namePath, "utf8")), bytes = Buffer.from(value.data, "base64"); bytes[0] ^= 1; value.data = bytes.toString("base64"); fs.writeFileSync(namePath, JSON.stringify(value)); }
    await assert.rejects(activateStagedVault(f, context, input(), owner()), error => error instanceof VaultActivationError);
    assert.equal(inspectVaultSelection(f).format, "legacy");
  }
});

test("pre-receipt partial-write/fsync/rename failures preserve legacy selection and all databases", async () => {
  for (const failing of ["writeFileSync", "fsyncSync", "renameSync"]) {
    const f = copy(), original = hash(file(f, "password-manager.db")), staged = hash(target(f));
    const write = fs.writeFileSync;
    mock.method(fs, failing, (...args) => {
      if (failing === "writeFileSync") write(args[0], args[1].subarray(0, 20));
      throw new Error("activation-secret-canary IO failure");
    }); syncBuiltinESMExports();
    await assert.rejects(activateStagedVault(f, context, input(), owner()), code("IO_FAILED")); unchanged(f, original, staged);
    assert.equal(inspectVaultSelection(f).format, "legacy"); fs[failing].mock.restore(); syncBuiltinESMExports();
  }
});

test("a temporary-file close failure prevents rename and releases authorization", async () => {
  const f = copy(), authorization = owner(), open = fs.openSync, close = fs.closeSync, names = new Map();
  mock.method(fs, "openSync", (name, ...args) => { const fd = open(name, ...args); names.set(fd, String(name)); return fd; });
  mock.method(fs, "closeSync", fd => {
    const name = names.get(fd), result = close(fd); names.delete(fd);
    if (name && path.basename(name).startsWith(".vault-activation.")) throw new Error("activation-secret-canary close failure");
    return result;
  }); syncBuiltinESMExports();
  await assert.rejects(activateStagedVault(f, context, input(), authorization), code("IO_FAILED"));
  assert.equal(authorization.session.getState().isUnlocked, false); assert.equal(inspectVaultSelection(f).format, "legacy");
});

test("generation changes just before pointer rename leave a prepared recovery state", async () => {
  const f = copy(), authorization = owner(), open = fs.openSync, sync = fs.fsyncSync, names = new Map(); let cancelled = false;
  mock.method(fs, "openSync", (name, ...args) => { const fd = open(name, ...args); names.set(fd, String(name)); return fd; });
  mock.method(fs, "fsyncSync", fd => {
    const result = sync(fd), name = names.get(fd);
    if (!cancelled && name && path.basename(name).startsWith(".vault-current.")) { cancelled = true; authorization.session.lock(); }
    return result;
  }); syncBuiltinESMExports();
  await assert.rejects(activateStagedVault(f, context, input(), authorization), code("RECOVERY_REQUIRED"));
  assert.ok(cancelled); assert.equal(receipt(f).state, "prepared"); assert.equal(fs.existsSync(file(f, "vault-current.json")), false);
  assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED"));
});

test("pointer rename failure leaves prepared receipt and explicit recovery completes the same verified candidate", async () => {
  const f = copy(), rename = fs.renameSync, original = hash(file(f, "password-manager.db")), staged = hash(target(f));
  mock.method(fs, "renameSync", (from, to) => { if (path.basename(to) === "vault-current.json") throw new Error("activation-secret-canary rename failure"); return rename(from, to); }); syncBuiltinESMExports();
  await assert.rejects(activateStagedVault(f, context, input(), owner()), code("RECOVERY_REQUIRED"));
  assert.equal(receipt(f).state, "prepared"); assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED"));
  fs.renameSync.mock.restore(); syncBuiltinESMExports();
  const result = await recoverVaultActivation(f, context, input(), owner()); assert.equal(result.state, "v2-selected");
  assert.equal(inspectVaultSelection(f).format, "v2"); unchanged(f, original, staged);
});

test("an error after pointer rename cannot be reported as success and the prepared state blocks normal selection", async () => {
  const f = copy(), rename = fs.renameSync;
  mock.method(fs, "renameSync", (from, to) => { const result = rename(from, to); if (path.basename(to) === "vault-current.json") throw new Error("activation-secret-canary after rename"); return result; }); syncBuiltinESMExports();
  await assert.rejects(activateStagedVault(f, context, input(), owner()), code("RECOVERY_REQUIRED"));
  assert.equal(pointer(f).vaultId, context.vaultId); assert.equal(receipt(f).state, "prepared"); assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED"));
  fs.renameSync.mock.restore(); syncBuiltinESMExports(); await recoverVaultActivation(f, context, input(), owner()); assert.equal(receipt(f).state, "committed");
});

test("explicit malformed-pointer recovery preserves its bytes and never repairs an unknown target", async () => {
  const f = copy(); await activateStagedVault(f, context, input(), owner()); const damaged = Buffer.from('{"invalid":"activation-secret-canary"}');
  fs.writeFileSync(file(f, "vault-current.json"), damaged); assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED"));
  await recoverVaultActivation(f, context, input(), owner());
  const preserved = fs.readdirSync(f).filter(name => name.startsWith(".vault-current-preserved.")); assert.equal(preserved.length, 1);
  assert.deepEqual(fs.readFileSync(file(f, preserved[0])), damaged);
  fs.writeFileSync(file(f, "vault-current.json"), JSON.stringify({ format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: crypto.randomUUID() }));
  const before = hash(file(f, "vault-current.json")); await assert.rejects(recoverVaultActivation(f, context, input(), owner()), code("RECOVERY_REQUIRED")); assert.equal(hash(file(f, "vault-current.json")), before);
});

test("missing/corrupt pointer or receipt never silently selects the old database", async () => {
  const active = copy(); await activateStagedVault(active, context, input(), owner());
  for (const name of ["vault-current.json", "vault-activation.json"]) for (const contents of [undefined, "{", "x".repeat(513), '{"format":"unknown"}', fs.readFileSync(file(active, name), "utf8") + "\n"]) {
    const f = path.join(root, `case-${++sequence}`); fs.cpSync(active, f, { recursive: true });
    if (contents === undefined) fs.unlinkSync(file(f, name)); else fs.writeFileSync(file(f, name), contents);
    assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED"));
  }
  raw(target(active), db => db.exec("PRAGMA user_version=99")); assert.throws(() => inspectVaultSelection(active), code("RECOVERY_REQUIRED"));
});

test("junctions, hard links and path-shaped identifiers are refused before publication", async () => {
  const f = copy(), outside = copy(), saved = file(f, "vaults-preserved"); fs.renameSync(file(f, "vaults"), saved);
  fs.symlinkSync(file(outside, "vaults"), file(f, "vaults"), process.platform === "win32" ? "junction" : "dir");
  const outsideHash = hash(target(outside)); await assert.rejects(activateStagedVault(f, context, input(), owner()), code("UNSAFE_PATH")); assert.equal(hash(target(outside)), outsideHash);
  const linked = copy(); fs.linkSync(target(linked), file(linked, "linked.sqlite"));
  await assert.rejects(activateStagedVault(linked, context, input(), owner()), code("UNSAFE_PATH"));
  await assert.rejects(activateStagedVault(copy(), { ...context, vaultId: "../escape" }, input(), owner()), code("INVALID_INPUT"));
});

test("post-activation edits remain selected normally but cannot be overwritten by legacy recovery", async () => {
  const f = copy(); await activateStagedVault(f, context, input(), owner());
  const store = openV2Store(target(f), context, { writable: true }), key = await unwrapRootKey(store.readPasswordSlot(), input().newMasterPassword, context);
  try { const entry = { ...legacy.entries[0], serviceName: "new v2 edit" }; await store.writeEntry(key, JSON.stringify(entry), { vaultId: context.vaultId, keyId: context.keyId, entryId: entry.id, revision: 2 }); }
  finally { key.fill(0); store.close(); }
  assert.equal(inspectVaultSelection(f).format, "v2"); const before = hash(target(f)); fs.unlinkSync(file(f, "vault-current.json"));
  await assert.rejects(recoverVaultActivation(f, context, input(), owner()), code("RECOVERY_REQUIRED")); assert.equal(hash(target(f)), before);
});

test("abrupt exits at receipt/pointer/acknowledgment boundaries retain a deterministic selection", async () => {
  const url = new URL("../apps/api/dist/apps/api/src/migration/activation.js", import.meta.url).href;
  const sessionUrl = new URL("../apps/api/dist/apps/api/src/services/vault-session.js", import.meta.url).href;
  for (const boundary of ["receipt", "pointer", "ack"]) {
    const f = copy(), original = hash(file(f, "password-manager.db")), staged = hash(target(f));
    const script = `import fs from 'node:fs';import path from 'node:path';import {syncBuiltinESMExports} from 'node:module';const rename=fs.renameSync;let receipts=0;fs.renameSync=(from,to)=>{const result=rename(from,to);const name=path.basename(to);if(name==='vault-activation.json')receipts++;if((process.argv[4]==='receipt'&&receipts===1)||(process.argv[4]==='pointer'&&name==='vault-current.json')||(process.argv[4]==='ack'&&receipts===2))process.exit(83);return result};syncBuiltinESMExports();const {VaultSession}=await import(${JSON.stringify(sessionUrl)});const {activateStagedVault}=await import(${JSON.stringify(url)});const session=new VaultSession();session.unlock(Buffer.from(process.argv[3],'hex'));await activateStagedVault(process.argv[1],JSON.parse(process.argv[2]),${JSON.stringify(input())},{session,sessionId:session.requireUnlocked()});`;
    const child = spawnSync(process.execPath, ["--input-type=module", "--eval", script, f, JSON.stringify(context), legacy.keyHex, boundary], { encoding: "utf8", timeout: 30000 });
    assert.equal(child.status, 83, child.stdout + child.stderr); unchanged(f, original, staged);
    if (boundary === "ack") assert.equal(inspectVaultSelection(f).format, "v2");
    else { assert.throws(() => inspectVaultSelection(f), code("RECOVERY_REQUIRED")); await recoverVaultActivation(f, context, input(), owner()); assert.equal(inspectVaultSelection(f).format, "v2"); }
  }
});
