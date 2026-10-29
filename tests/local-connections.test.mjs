import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes, randomUUID, createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { generateLocalIdentity } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { nativeTransportExecutable, connectNativeTransport } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { createManagedLocalClientStore, openManagedLocalClientStore, createLocalClientStore, openLocalClientStore } from "../apps/electron/dist/apps/electron/src/local-client-store.js";
import { LocalConnections } from "../apps/electron/dist/apps/electron/src/local-connections.js";
import { encodeLocalPairingRequest } from "../apps/electron/dist/apps/electron/src/local-pairing.js";
import { authenticateLocalHost } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import { readSelectedPairingRequest, writeSelectedConnectionInfo } from "../apps/electron/dist/apps/electron/src/local-pairing-files.js";
import Database from "better-sqlite3";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const digest = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function syntheticProtector() {
  const secret = randomBytes(32), calls = { wrap: 0, unwrap: 0 };
  return { calls,
    async wrap(key) { calls.wrap++; const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", secret, iv);
      return { provider: "windows-dpapi", data: Buffer.concat([iv, cipher.update(key), cipher.final(), cipher.getAuthTag()]) }; },
    async unwrap(value) { calls.unwrap++; const data = value.data, decipher = createDecipheriv("aes-256-gcm", secret, data.subarray(0, 12)); decipher.setAuthTag(data.subarray(-16));
      return { key: Buffer.concat([decipher.update(data.subarray(12, -16)), decipher.final()]), shouldReEncrypt: false }; },
    dispose() { secret.fill(0); }
  };
}
async function fixture() {
  const context = createLocalAuthFixture(executable), protector = syntheticProtector(), session = new VaultSession();
  const client = await generateLocalIdentity({ executable, role: "client" });
  let runtime = new LocalConnections(context.directory, executable, protector, session);
  const unlock = () => { session.unlock(Buffer.alloc(32, 7)); return session.getState().sessionId; };
  return { ...context, client, protector, session, unlock, get runtime() { return runtime; },
    async reopen() { await runtime.close(); session.lock(); runtime = new LocalConnections(context.directory, executable, protector, session); },
    async dispose() { await runtime.close(); session.lock(); client.dispose(); protector.dispose(); context.dispose(); } };
}
async function ready(context, id) {
  for (let i = 0; i < 200; i++) { const value = context.runtime.state(id); if (value.status === "ready") return value; if (value.status === "unavailable") assert.fail("Runtime became unavailable"); await delay(25); }
  assert.fail("Runtime did not become ready");
}
async function enroll(context, id) {
  context.runtime.stage(id, encodeLocalPairingRequest({ displayName: "合成接続元", kind: "agent", certificate: context.client.certificate }));
  const review = context.runtime.state(id).review;
  await context.runtime.approve(id, { pendingId: review.pendingId, expectedRevision: review.revision, fingerprint256: review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" });
  return context.runtime.state(id).clients[0];
}
async function connect(context, id, clientId) {
  const receipt = JSON.parse(context.runtime.connectionInfo(id, clientId)); let endpoint;
  for (let i = 0; i < 200; i++) {
    assert.equal(context.runtime.state(id).status, "ready");
    endpoint = JSON.parse(fs.readFileSync(receipt.discoveryFile)).clients.find(client => client.clientId === clientId)?.endpoint;
    if (endpoint) break; await delay(25);
  }
  assert.ok(endpoint, "An idle client listener must be published after its previous connection closes");
  const native = await connectNativeTransport({ executable, endpoint });
  try { const remote = await authenticateLocalHost(native, context.client, Buffer.from(receipt.hostCertificate, "base64")); return { receipt, native, remote }; }
  catch (error) { await native.close(); throw error; }
}

test("managed registry persists host references and stop state without changing legacy registry formats", { timeout: 20000 }, async () => {
  const context = createLocalAuthFixture(executable), host = await generateLocalIdentity({ executable, role: "host" }); let store;
  try {
    const file = path.join(context.directory, "managed.sqlite"), identityId = randomUUID();
    store = createManagedLocalClientStore(file, { identityId, certificate: host.certificate });
    assert.equal(store.configuration().enabled, false); assert.equal(store.read().revision, 0);
    store.setEnabled(0, true); assert.equal(store.read().revision, 1);
    assert.throws(() => store.setEnabled(0, false)); assert.equal(store.configuration().enabled, true);
    store.setEnabled(1, true); assert.equal(store.read().revision, 1); store.close();
    assert.throws(() => openLocalClientStore(file, host.certificate));
    store = openManagedLocalClientStore(file); assert.equal(store.configuration().reference.identityId, identityId);
    store.setEnabled(1, false); store.close();
    const raw = new Database(file); try { assert.equal(raw.pragma("user_version", { simple: true }), 3); } finally { raw.close(); }
    const legacy = path.join(context.directory, "legacy.sqlite"), previous = createLocalClientStore(legacy, host.certificate); previous.close();
    const before = digest(legacy); assert.throws(() => openManagedLocalClientStore(legacy)); assert.equal(digest(legacy), before);
    const reopened = openLocalClientStore(legacy, host.certificate); reopened.close();
  } finally { store?.close(); host.dispose(); context.dispose(); }
});

test("initial startup creates no integration data; explicit enable protects the host and persists a managed registry", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const root = path.join(context.directory, "local-connections"); assert.equal(fs.existsSync(root), false);
    await assert.rejects(context.runtime.setEnabled(context.session.getState().sessionId, 0, true)); assert.equal(context.protector.calls.wrap, 0);
    const id = context.unlock(); assert.equal(context.runtime.state(id).status, "disabled");
    await context.runtime.setEnabled(id, 0, true); assert.equal(context.runtime.state(id).status, "ready");
    const records = fs.readdirSync(root).filter(name => name.endsWith(".cvkey")); assert.equal(records.length, 1);
    assert.equal(fs.readFileSync(path.join(root, records[0])).includes(Buffer.from("PRIVATE KEY")), false);
    assert.equal(context.runtime.state(id).revision, 1); assert.equal(context.protector.calls.wrap, 1);
    const client = await enroll(context, id); await context.runtime.close();
    const raw = new Database(path.join(root, "clients.sqlite"), { readonly: true });
    try { assert.equal(raw.pragma("user_version", { simple: true }), 3); } finally { raw.close(); }
    assert.ok(client.clientId);
  } finally { await context.dispose(); }
});

test("registered clients authenticate through discovery; application bytes are denied and stop/revoke closes live TLS", { timeout: 20000 }, async () => {
  const context = await fixture(); let connection;
  try {
    const id = context.unlock(); await context.runtime.setEnabled(id, 0, true); const client = await enroll(context, id);
    connection = await connect(context, id, client.clientId); assert.equal(connection.remote.socket.getProtocol(), "TLSv1.3");
    connection.remote.socket.write("synthetic-unsupported-operation"); await connection.native.closed; await connection.remote.close(); connection = undefined;
    await delay(350);
    connection = await connect(context, id, client.clientId); await context.runtime.revoke(id, context.runtime.state(id).revision, client.clientId);
    await connection.native.closed; assert.equal(context.runtime.state(id).clients[0].state, "revoked");
    assert.throws(() => context.runtime.connectionInfo(id, client.clientId));
  } finally { await connection?.remote.close(); await connection?.native.close(); await context.dispose(); }
});

test("stop survives restart; explicit resume and later unlock restore the same protected host and client registration", { timeout: 20000 }, async () => {
  const context = await fixture(); let connection;
  try {
    let id = context.unlock(); await context.runtime.setEnabled(id, 0, true); const client = await enroll(context, id);
    const original = JSON.parse(context.runtime.connectionInfo(id, client.clientId)); connection = await connect(context, id, client.clientId);
    await context.runtime.setEnabled(id, context.runtime.state(id).revision, false); await connection.native.closed; await connection.remote.close(); connection = undefined;
    assert.equal(context.runtime.state(id).status, "paused"); const calls = context.protector.calls.unwrap;
    await context.reopen(); id = context.unlock(); await delay(100); assert.equal(context.runtime.state(id).status, "paused"); assert.equal(context.protector.calls.unwrap, calls);
    await context.runtime.setEnabled(id, context.runtime.state(id).revision, true); await ready(context, id);
    connection = await connect(context, id, client.clientId); assert.equal(connection.receipt.hostFingerprint256, original.hostFingerprint256); await connection.remote.close(); connection = undefined;
    await context.reopen(); id = context.unlock(); await ready(context, id); assert.equal(context.runtime.state(id).clients[0].clientId, client.clientId);
    connection = await connect(context, id, client.clientId); context.session.lock(); await connection.native.closed;
    assert.throws(() => context.runtime.state(id));
  } finally { await connection?.remote.close(); await connection?.native.close(); await context.dispose(); }
});

test("lock during delayed key protection leaves no credential file or implicit registration", { timeout: 20000 }, async () => {
  const context = await fixture(); const nativeWrap = context.protector.wrap; let entered, release;
  const reached = new Promise(resolve => { entered = resolve; }), deferred = new Promise(resolve => { release = resolve; });
  context.protector.wrap = async key => { entered(); await deferred; return nativeWrap(key); };
  try {
    const id = context.unlock(), pending = context.runtime.setEnabled(id, 0, true); await reached; context.session.lock(); release(); await assert.rejects(pending);
    assert.deepEqual(fs.readdirSync(path.join(context.directory, "local-connections")), []);
    context.protector.wrap = nativeWrap; const next = context.unlock(); await context.runtime.setEnabled(next, 0, true); assert.equal(context.runtime.state(next).status, "ready");
  } finally { release?.(); await context.dispose(); }
});

test("unknown or incomplete connection files are retained and never overwritten during startup or enable", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    await context.runtime.close(); const root = path.join(context.directory, "local-connections"); fs.mkdirSync(root, { mode: 0o700 });
    const candidate = path.join(root, `identity-${randomUUID()}.cvkey`); fs.writeFileSync(candidate, "synthetic-incomplete-record"); const before = digest(candidate);
    await context.reopen(); const id = context.unlock(); assert.equal(context.runtime.state(id).status, "unavailable");
    await assert.rejects(context.runtime.setEnabled(id, 0, true)); assert.equal(digest(candidate), before); assert.equal(fs.existsSync(path.join(root, "clients.sqlite")), false);
    assert.equal(context.session.getState().isUnlocked, true);
  } finally { await context.dispose(); }
});

test("dialog files are bounded public requests and connection exports never overwrite an existing file", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const content = encodeLocalPairingRequest({ displayName: "合成client", kind: "agent", certificate: context.client.certificate });
    const request = path.join(context.directory, "synthetic.cvpair"), receipt = path.join(context.directory, "synthetic.cvconnection"); fs.writeFileSync(request, content);
    assert.equal(readSelectedPairingRequest(request).equals(content), true); fs.writeFileSync(request, Buffer.alloc(16385)); assert.throws(() => readSelectedPairingRequest(request));
    assert.throws(() => readSelectedPairingRequest(path.join(context.directory, "vault.sqlite")));
    fs.writeFileSync(request, content); fs.linkSync(request, request + ".link"); assert.throws(() => readSelectedPairingRequest(request));
    writeSelectedConnectionInfo(receipt, Buffer.from('{"version":1}')); const before = digest(receipt);
    assert.throws(() => writeSelectedConnectionInfo(receipt, Buffer.from('{"version":2}'))); assert.equal(digest(receipt), before);
  } finally { await context.dispose(); }
});
