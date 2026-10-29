import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { syncBuiltinESMExports } from "node:module";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { generateLocalIdentity } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { nativeTransportExecutable } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { createDeviceKeyProtector, IdentityStorageError } from "../apps/electron/dist/apps/electron/src/device-key-protector.js";
import { ProtectedLocalIdentityStore, localIdentityFile } from "../apps/electron/dist/apps/electron/src/protected-local-identity.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const rejected = error => error instanceof IdentityStorageError && error.code === "LOCAL_IDENTITY_STORAGE_UNAVAILABLE";
const host = patch => ({ isReady: () => true, platform: "linux", electronVersion: "45.0.0", chromiumVersion: "156.0.8078.48", hasSwitch: () => false, ...patch });
function nativeStorage(tag = "v11") {
  const secret = randomBytes(32), calls = { available: 0, encrypted: 0, decrypted: 0 };
  const storage = {
    async isAsyncEncryptionAvailable() { calls.available++; return true; },
    async encryptStringAsync(value) { calls.encrypted++; const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", secret, nonce);
      return Buffer.concat([Buffer.from(tag), nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]); },
    async decryptStringAsync(value) { calls.decrypted++; const decipher = createDecipheriv("aes-256-gcm", secret, value.subarray(3, 15)); decipher.setAuthTag(value.subarray(-16));
      return { result: Buffer.concat([decipher.update(value.subarray(15, -16)), decipher.final()]).toString(), shouldReEncrypt: false }; }
  };
  return { storage, calls, dispose: () => secret.fill(0) };
}
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function fixture() {
  const context = createLocalAuthFixture(executable), identity = await generateLocalIdentity({ executable, role: "host" });
  const reference = { identityId: randomUUID(), role: "host", fingerprint256: new X509Certificate(identity.certificate).fingerprint256 };
  const native = nativeStorage(), protector = createDeviceKeyProtector(host(), native.storage), store = new ProtectedLocalIdentityStore(protector);
  return { ...context, identity, reference, native, protector, store, file: localIdentityFile(context.directory, reference.identityId), dispose() { identity.dispose(); native.dispose(); context.dispose(); } };
}

test("immutable protected files survive reopen with no plaintext private key and bind the exact credential reference", { timeout: 20000 }, async () => {
  const context = await fixture(); let restored;
  try {
    await context.store.save(context.file, context.identity, context.reference, () => {});
    const bytes = fs.readFileSync(context.file); assert.equal(bytes.includes(context.identity.privateKey), false); assert.equal(bytes.includes(Buffer.from("PRIVATE KEY")), false);
    const reopened = new ProtectedLocalIdentityStore(createDeviceKeyProtector(host(), context.native.storage));
    restored = await reopened.load(context.file, context.reference, () => {});
    assert.equal(restored.identity.privateKey.equals(context.identity.privateKey), true); assert.equal(restored.shouldReEncrypt, false);
    assert.equal(restored.identity.certificate.equals(context.identity.certificate), true);
    let now = Date.now() + 6 * 60000;
    mock.method(Date, "now", () => now);
    const older = await reopened.load(context.file, context.reference, () => {});
    try { assert.equal(older.identity.privateKey.equals(context.identity.privateKey), true); } finally { older.identity.dispose(); }
    now += 366 * 86400000;
    await assert.rejects(reopened.load(context.file, context.reference, () => {}), rejected);
    mock.restoreAll();
    const calls = context.native.calls.encrypted;
    await assert.rejects(context.store.save(context.file, context.identity, context.reference, () => {}), rejected);
    assert.equal(fs.readFileSync(context.file).equals(bytes), true); assert.equal(context.native.calls.encrypted, calls);
    for (const patch of [{ role: "client" }, { fingerprint256: "00:".repeat(31) + "00" }, { identityId: randomUUID() }]) {
      await assert.rejects(reopened.load(context.file, { ...context.reference, ...patch }, () => {}), rejected);
    }
    if (process.platform !== "win32") assert.equal(fs.statSync(context.file).mode & 0o777, 0o600);
  } finally { mock.restoreAll(); restored?.identity.dispose(); context.dispose(); }
});

test("tampering, linked/oversized records and native decryption errors never return a private key", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    await context.store.save(context.file, context.identity, context.reference, () => {});
    const original = fs.readFileSync(context.file), envelope = JSON.parse(original);
    for (const field of ["data", "tag", "iv", "wrappedKey", "certificate"]) {
      const modified = structuredClone(envelope), value = Buffer.from(modified[field], "base64"); value[0] ^= 1; modified[field] = value.toString("base64");
      fs.writeFileSync(context.file, JSON.stringify(modified)); await assert.rejects(context.store.load(context.file, context.reference, () => {}), rejected);
    }
    for (const patch of [{ version: 9 }, { provider: "windows-dpapi" }, { extra: "synthetic-private-canary" }]) {
      fs.writeFileSync(context.file, JSON.stringify({ ...envelope, ...patch })); await assert.rejects(context.store.load(context.file, context.reference, () => {}), rejected);
    }
    fs.writeFileSync(context.file, Buffer.alloc(32769)); await assert.rejects(context.store.load(context.file, context.reference, () => {}), rejected);
    fs.writeFileSync(context.file, original); fs.linkSync(context.file, context.file + ".hard-link"); await assert.rejects(context.store.load(context.file, context.reference, () => {}), rejected);
  } finally { context.dispose(); }
});

test("provider policy rejects fixed-key Linux fallback, unknown versions, mock keychain and calls before readiness", async () => {
  const key = randomBytes(32);
  try {
    for (const patch of [{ isReady: () => false }, { electronVersion: "46.0.0" }, { chromiumVersion: "unknown" }, { platform: "other" }, { hasSwitch: () => true }]) {
      const native = nativeStorage();
      try { await assert.rejects(createDeviceKeyProtector(host(patch), native.storage).wrap(key), rejected); assert.equal(native.calls.available, 0); }
      finally { native.dispose(); }
    }
    const fallback = nativeStorage("v10");
    try { await assert.rejects(createDeviceKeyProtector(host(), fallback.storage).wrap(key), rejected); assert.equal(fallback.calls.decrypted, 0); }
    finally { fallback.dispose(); }
    for (const [platform, tag, provider] of [["win32", "v10", "windows-dpapi"], ["darwin", "v10", "macos-keychain"], ["linux", "v11", "linux-secret-service"], ["linux", "v12", "linux-secret-portal"]]) {
      const native = nativeStorage(tag); let wrapped, unwrapped;
      try { const protector = createDeviceKeyProtector(host({ platform }), native.storage); wrapped = await protector.wrap(key); assert.equal(wrapped.provider, provider);
        unwrapped = await protector.unwrap(wrapped); assert.equal(unwrapped.key.equals(key), true); }
      finally { wrapped?.data.fill(0); unwrapped?.key.fill(0); native.dispose(); }
    }
  } finally { key.fill(0); }
});

test("timeout/cancellation returns no key and keeps the native busy gate until its late completion", async () => {
  const native = nativeStorage(), available = deferred(), key = randomBytes(32), cancel = new AbortController();
  native.storage.isAsyncEncryptionAvailable = () => available.promise;
  const protector = createDeviceKeyProtector(host(), native.storage);
  try {
    mock.timers.enable({ apis: ["setTimeout"] });
    const timedOut = protector.wrap(key); mock.timers.tick(10000); await assert.rejects(timedOut, rejected);
    await assert.rejects(protector.wrap(key), rejected); available.resolve(true); await new Promise(resolve => queueMicrotask(resolve)); await new Promise(resolve => queueMicrotask(resolve));
    assert.equal(native.calls.encrypted, 0); mock.timers.reset();
    const pending = deferred(); native.storage.isAsyncEncryptionAvailable = () => pending.promise;
    const cancelled = protector.wrap(key, cancel.signal); cancel.abort(); await assert.rejects(cancelled, rejected);
    pending.resolve(true); await new Promise(resolve => queueMicrotask(resolve)); await new Promise(resolve => queueMicrotask(resolve));
    native.storage.isAsyncEncryptionAvailable = async () => true;
    const recovered = await protector.wrap(key); recovered.data.fill(0);
  } finally { mock.timers.reset(); native.dispose(); key.fill(0); }
});

test("lock or cancellation during protection cannot create a file, and pending native output is wiped", { timeout: 20000 }, async () => {
  const context = await fixture(), session = new VaultSession(), entered = deferred(), released = deferred(), nativeEncrypt = context.native.storage.encryptStringAsync;
  let late;
  session.unlock(Buffer.alloc(32, 9)); const generation = session.getState().sessionId;
  context.native.storage.encryptStringAsync = async value => { late = await nativeEncrypt(value); entered.resolve(); return released.promise; };
  try {
    const pending = context.store.save(context.file, context.identity, context.reference, () => session.requireUnlocked(generation));
    await entered.promise; session.lock(); released.resolve(late); await assert.rejects(pending, rejected);
    assert.equal(fs.existsSync(context.file), false); assert.equal(late.every(value => value === 0), true);
  } finally { session.lock(); context.dispose(); }
});

test("native errors are redacted and failed file sync preserves its recovery candidate", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const sync = fs.fsyncSync;
    mock.method(fs, "fsyncSync", () => { throw new Error("synthetic-private-native-detail"); }); syncBuiltinESMExports();
    await assert.rejects(context.store.save(context.file, context.identity, context.reference, () => {}), error => rejected(error) && !String(error).includes(context.directory));
    assert.equal(fs.existsSync(context.file), true); mock.restoreAll(); syncBuiltinESMExports(); assert.equal(fs.fsyncSync, sync);
    const saved = fs.readFileSync(context.file); await assert.rejects(context.store.save(context.file, context.identity, context.reference, () => {}), rejected);
    assert.equal(fs.readFileSync(context.file).equals(saved), true);
  } finally { mock.restoreAll(); syncBuiltinESMExports(); context.dispose(); }
});
