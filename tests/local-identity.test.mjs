import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate, createPrivateKey } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { fileURLToPath } from "node:url";
import { generateLocalIdentity, LocalIdentityError } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { nativeTransportExecutable, listenNativeTransport, connectNativeTransport } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { authenticateLocalClient, authenticateLocalHost } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { parseLocalPublicCertificate } from "../apps/electron/dist/apps/electron/src/local-certificates.js";
import { createLocalClientStore, openLocalClientStore } from "../apps/electron/dist/apps/electron/src/local-client-store.js";
import Database from "better-sqlite3";
import path from "node:path";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const issue = role => generateLocalIdentity({ executable, role });
const unavailable = error => error instanceof LocalIdentityError && error.code === "LOCAL_IDENTITY_UNAVAILABLE" && error.message === "ローカル接続資格を発行できません";
async function pair(options) {
  const listener = await listenNativeTransport(options);
  try { const [host, client] = await Promise.all([listener.accepted, connectNativeTransport(options)]); return { host, client, close: async () => { await client.close(); await host.close(); await listener.close(); } }; }
  catch (error) { await listener.close(); throw error; }
}

test("native standard APIs issue independent non-CA P-256 host/client credentials and purpose-bound issuers", { timeout: 20000 }, async () => {
  const issued = [];
  try {
    for (const role of ["host", "client", "client"]) {
      const identity = await issue(role); issued.push(identity); assert.ok(Object.isFrozen(identity));
      const { leaf: cert, issuer } = parseLocalPublicCertificate(identity.certificate), key = createPrivateKey(identity.privateKey);
      assert.equal(cert.ca, false); assert.equal(cert.verify(issuer.publicKey), true); assert.equal(cert.checkPrivateKey(key), true);
      assert.equal(issuer.ca, true); assert.equal(issuer.checkPrivateKey(key), false);
      assert.equal(key.asymmetricKeyDetails.namedCurve, "prime256v1");
      assert.deepEqual(cert.keyUsage, [role === "host" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"]);
      assert.equal(identity.expiresAt, Date.parse(cert.validTo)); assert.ok(identity.expiresAt > Date.now());
      assert.equal(cert.subjectAltName, role === "host" ? "DNS:cipher-vault.local" : undefined);
    }
    assert.equal(new Set(issued.map(value => new X509Certificate(value.certificate).fingerprint256)).size, 3);
    for (const value of issued) { value.dispose(); value.dispose(); assert.equal(value.privateKey.every(byte => byte === 0), true); }
  } finally { for (const value of issued) value.dispose(); }
});

test("issued credentials authenticate through actual native peers and cannot substitute the opposite TLS purpose", { timeout: 30000 }, async () => {
  const fixture = createLocalAuthFixture(executable); let host, client, connections, store, channels = [];
  try {
    host = await issue("host"); client = await issue("client");
    const file = path.join(fixture.directory, "issued-clients.sqlite"), now = Date.now();
    store = createLocalClientStore(file, host.certificate); store.enroll(0, { displayName: "Issued client", kind: "agent", certificate: client.certificate, expiresAt: now + 60000 }, now); store.close();
    store = openLocalClientStore(file, host.certificate);
    connections = await pair(fixture.options);
    channels = await Promise.all([authenticateLocalClient(connections.host, host, store.read().clients),
      authenticateLocalHost(connections.client, client, host.certificate)]);
    assert.equal(channels[0].clientId, store.read().clients[0].clientId); assert.equal(channels[1].socket.getProtocol(), "TLSv1.3");
    for (const channel of channels) await channel.close(); channels = []; await connections.close(); connections = undefined;
    for (const swap of ["host", "client"]) {
      connections = await pair(fixture.options);
      const server = swap === "host" ? client : host, remote = swap === "client" ? host : client;
      const outcomes = await Promise.allSettled([authenticateLocalClient(connections.host, server, [{ clientId: "wrong-purpose", certificate: remote.certificate }]),
        authenticateLocalHost(connections.client, remote, server.certificate)]);
      assert.ok(outcomes.every(value => value.status === "rejected")); await connections.close(); connections = undefined;
    }
  } finally { for (const channel of channels) await channel.close(); await connections?.close(); store?.close(); host?.dispose(); client?.dispose(); fixture.dispose(); }
});

test("version-1 registrations remain readable and adding a certificate chain upgrades atomically without replacing old pins", { timeout: 20000 }, async () => {
  const fixture = createLocalAuthFixture(executable); let host, client, store;
  try {
    host = await issue("host"); client = await issue("client");
    const legacy = fixture.identity("legacy"), file = path.join(fixture.directory, "old-registrations.sqlite"), now = Date.now();
    const input = certificate => ({ displayName: "Synthetic registration", kind: "agent", certificate, expiresAt: now + 60000 });
    store = createLocalClientStore(file, host.certificate); const previous = store.enroll(0, input(legacy.certificate), now); store.close();
    const old = new Database(file); old.pragma("user_version = 1"); old.close();
    store = openLocalClientStore(file, host.certificate); assert.equal(store.read().clients[0].fingerprint256, previous.fingerprint256);
    const prepare = Database.prototype.prepare;
    mock.method(Database.prototype, "prepare", function (sql) {
      if (sql.startsWith("UPDATE local_host SET revision")) throw new Error("Synthetic registry commit failure");
      return prepare.call(this, sql);
    });
    assert.throws(() => store.enroll(1, input(client.certificate), now)); mock.restoreAll(); store.close();
    const rolledBack = new Database(file);
    try { assert.equal(rolledBack.pragma("user_version", { simple: true }), 1); assert.equal(rolledBack.prepare("SELECT COUNT(*) AS count FROM local_clients").get().count, 1); }
    finally { rolledBack.close(); }
    store = openLocalClientStore(file, host.certificate);
    store.enroll(1, input(client.certificate), now); store.close();
    const upgraded = new Database(file); try { assert.equal(upgraded.pragma("user_version", { simple: true }), 2); } finally { upgraded.close(); }
    store = openLocalClientStore(file, host.certificate); assert.equal(store.read().clients.length, 2);
    assert.equal(store.read().clients.find(value => value.clientId === previous.clientId).fingerprint256, previous.fingerprint256);
    const parts = parseLocalPublicCertificate(client.certificate), other = parseLocalPublicCertificate(host.certificate);
    assert.throws(() => parseLocalPublicCertificate(Buffer.from(parts.leaf.toString() + other.issuer.toString())));
    assert.throws(() => parseLocalPublicCertificate(Buffer.from(client.certificate.toString() + other.issuer.toString())));
  } finally { mock.restoreAll(); store?.close(); host?.dispose(); client?.dispose(); fixture.dispose(); }
});

function fakeSpawn(send) {
  mock.method(childProcess, "spawn", (file, args, options) => {
    assert.equal(file, executable); assert.deepEqual(args, ["identity", "client"]); assert.equal(options.windowsHide, true);
    assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
    for (const key of Object.keys(options.env)) assert.equal(/^(?:PASSWORD_MANAGER_|ELECTRON_RUN_AS_NODE$|NODE_OPTIONS$|NODE_PATH$|SSLKEYLOGFILE$)/i.test(key), false);
    const child = new EventEmitter(); child.pid = 123456; child.stdout = new PassThrough(); child.stderr = new PassThrough();
    let closed = false;
    child.kill = signal => { assert.equal(signal, "SIGKILL"); queueMicrotask(() => { if (!closed) { closed = true; child.emit("close", null, signal); } }); return true; };
    queueMicrotask(() => send(child, () => { if (!closed) { closed = true; child.emit("close", 0, null); } }));
    return child;
  });
  syncBuiltinESMExports();
}
function wire(identity, patch = {}, trailing = false) {
  const publicPem = identity.certificate, privatePem = identity.privateKey;
  // Native PEM has no trailing newline; Node's public certificate serializer adds one.
  const header = Buffer.from(JSON.stringify({ protocol: 1, event: "identity", processId: 123456, role: "client", certificateBytes: publicPem.length, privateKeyBytes: privatePem.length, ...patch }));
  const length = Buffer.alloc(4); length.writeUInt32BE(header.length);
  return Buffer.concat([length, header, publicPem, privatePem, ...(trailing ? [Buffer.from("synthetic-trailing-private-canary")] : [])]);
}
test("bounded identity framing rejects forged PID/role/length, extra data and oversized output and wipes received bytes", { timeout: 20000 }, async () => {
  const credential = await issue("client");
  try {
    for (const [patch, trailing] of [[{ processId: 999 }, false], [{ role: "host" }, false], [{ privateKeyBytes: -1 }, false], [{ extra: "synthetic-private-canary" }, false], [{}, true]]) {
      const payload = wire(credential, patch, trailing);
      fakeSpawn((child, close) => { child.stdout.write(payload); close(); });
      await assert.rejects(issue("client"), unavailable); assert.equal(payload.every(byte => byte === 0), true);
      mock.restoreAll(); syncBuiltinESMExports();
    }
    const overflow = Buffer.alloc(8193, 0x42);
    fakeSpawn(child => child.stdout.write(overflow)); await assert.rejects(issue("client"), unavailable); assert.equal(overflow.every(byte => byte === 0), true);
  } finally { mock.restoreAll(); syncBuiltinESMExports(); credential.dispose(); }
});

test("cancellation and the single issuance gate stop the owned helper without exposing its output", { timeout: 20000 }, async () => {
  const cancel = new AbortController(); let captured;
  try {
    fakeSpawn(child => { captured = child; });
    const pending = generateLocalIdentity({ executable, role: "client", signal: cancel.signal });
    await assert.rejects(issue("client"), unavailable); cancel.abort(); await assert.rejects(pending, unavailable);
    assert.ok(captured);
    mock.restoreAll(); syncBuiltinESMExports();
    const already = new AbortController(); already.abort();
    await assert.rejects(generateLocalIdentity({ executable, role: "client", signal: already.signal }), unavailable);
    await assert.rejects(generateLocalIdentity({ executable, role: "bad" }), unavailable);
    await assert.rejects(generateLocalIdentity({ executable, role: "client", signal: {} }), unavailable);
    await assert.rejects(generateLocalIdentity({ executable: executable + ".missing", role: "client" }), unavailable);
    const recovered = await issue("client"); recovered.dispose();
  } finally { mock.restoreAll(); syncBuiltinESMExports(); }
});
