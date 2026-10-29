import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import { createLocalClientStore, openLocalClientStore, LocalClientRegistryError } from "../apps/electron/dist/apps/electron/src/local-client-store.js";
import { LocalClientRegistry } from "../apps/electron/dist/apps/electron/src/local-client-registry.js";
import { authenticateLocalHost, LocalClientAuthenticationError } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";
import { listenNativeTransport, connectNativeTransport, nativeTransportExecutable } from "../apps/electron/dist/apps/electron/src/native-transport.js";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const code = expected => error => error instanceof LocalClientRegistryError && error.code === expected;
function fixture() {
  const context = createLocalAuthFixture(executable), host = context.identity("host"), client = context.identity("client");
  const file = path.join(context.directory, "clients.sqlite"), store = createLocalClientStore(file, host.certificate), session = new VaultSession();
  session.unlock(Buffer.alloc(32, 1)); let now = Date.now(); const timers = new Set();
  const registry = new LocalClientRegistry(store, session, () => now, callback => { timers.add(callback); return () => timers.delete(callback); });
  const sessionId = session.getState().sessionId;
  const input = identity => ({ displayName: "合成テスト Agent", kind: "agent", certificate: identity.certificate, expiresAt: now + 60000 });
  const registration = registry.enroll(sessionId, 0, input(client));
  return { ...context, host, client, store, file, session, sessionId, registry, registration, input,
    identity(name, issuer) { const value = context.identity(name, issuer); now = Math.max(now, Date.now()); return value; },
    advance(milliseconds, runTimers = true) { now += milliseconds; if (runTimers) { const pending = [...timers]; timers.clear(); for (const callback of pending) callback(); } },
    dispose() { registry.close(); session.lock(); context.dispose(); } };
}
async function pair(options) {
  const listener = await listenNativeTransport(options);
  try { const [host, client] = await Promise.all([listener.accepted, connectNativeTransport(options)]); return { host, client, close: async () => { await client.close(); await host.close(); await listener.close(); } }; }
  catch (error) { await listener.close(); throw error; }
}
async function authenticated(context, connections, identity = context.client, signal) {
  return Promise.all([context.registry.authenticate(connections.host, context.host, context.sessionId, signal),
    authenticateLocalHost(connections.client, identity, context.host.certificate)]);
}

test("persisted registration identifies a real TLS peer, and revocation immediately closes its channel", { timeout: 20000 }, async () => {
  const context = fixture(); let connections, host, client;
  try {
    const listing = context.registry.list(context.sessionId); assert.equal(listing.clients[0].state, "active"); assert.equal(listing.clients[0].certificate, undefined);
    connections = await pair(context.options); [host, client] = await authenticated(context, connections);
    assert.equal(host.clientId, context.registration.clientId); host.assertCurrent();
    const received = once(host.socket, "data"); client.socket.write("synthetic-registry-payload"); assert.equal((await received)[0].toString(), "synthetic-registry-payload");
    context.registry.revoke(listing.revision, host.clientId); assert.equal(host.socket.destroyed, true);
    await Promise.all([connections.host.closed, connections.client.closed]); assert.equal(client.socket.destroyed, true);
    assert.throws(host.assertCurrent, code("DENIED"));
    context.registry.close(); const reopened = openLocalClientStore(context.file, context.host.certificate);
    try { assert.equal(reopened.read().clients[0].revokedAt !== null, true); } finally { reopened.close(); }
  } finally { await client?.close(); await host?.close(); await connections?.close(); context.dispose(); }
});

test("lock and generation replacement cancel all live channels; locked enrollment is denied", { timeout: 20000 }, async () => {
  const context = fixture(); let connections, host, client;
  try {
    for (const transition of [() => context.session.lock(), () => context.session.unlock(Buffer.alloc(32, 2))]) {
      context.sessionId = context.session.getState().sessionId;
      if (!context.session.getState().isUnlocked) { context.session.unlock(Buffer.alloc(32, 3)); context.sessionId = context.session.getState().sessionId; }
      connections = await pair(context.options); [host, client] = await authenticated(context, connections);
      transition(); assert.equal(host.socket.destroyed, true); await Promise.all([connections.host.closed, connections.client.closed]);
      assert.throws(host.assertCurrent, code("DENIED")); await connections.close(); connections = undefined;
    }
    context.session.lock(); assert.throws(() => context.registry.enroll(context.sessionId, 1, context.input(context.client)), code("DENIED"));
    context.registry.revoke(1, null); assert.equal(context.store.read().clients[0].revokedAt !== null, true);
  } finally { await client?.close(); await host?.close(); await connections?.close(); context.dispose(); }
});

test("expired credentials close on the timer and are denied even before that timer runs", { timeout: 20000 }, async () => {
  for (const timers of [true, false]) {
    const context = fixture(); let connections, host, client;
    try {
      connections = await pair(context.options); [host, client] = await authenticated(context, connections);
      context.advance(60001, timers);
      if (!timers) assert.throws(host.assertCurrent, code("DENIED"));
      assert.equal(host.socket.destroyed, true); await Promise.all([connections.host.closed, connections.client.closed]);
      assert.equal(context.registry.list(context.sessionId).clients[0].state, "expired");
      await connections.close(); connections = await pair(context.options);
      await assert.rejects(authenticated(context, connections), LocalClientAuthenticationError);
    } finally { await client?.close(); await host?.close(); await connections?.close(); context.dispose(); }
  }
});

test("revocation during a handshake cannot yield an authenticated registered capability", { timeout: 20000 }, async () => {
  const context = fixture(); let connections;
  try {
    connections = await pair(context.options);
    const pending = context.registry.authenticate(connections.host, context.host, context.sessionId); pending.catch(() => {});
    context.registry.revoke(1, context.registration.clientId);
    const result = await Promise.allSettled([pending, authenticateLocalHost(connections.client, context.client, context.host.certificate)]);
    assert.ok(result.every(value => value.status === "rejected")); assert.ok(result[0].reason instanceof LocalClientAuthenticationError);
  } finally { await connections?.close(); context.dispose(); }
});

test("revoking one client preserves another authenticated client, while store failures cancel both", { timeout: 30000 }, async () => {
  const context = fixture(), other = context.identity("other-client"); let first, second, channels = [];
  try {
    const registration = context.registry.enroll(context.sessionId, 1, context.input(other));
    first = await pair(context.options); const firstChannels = await authenticated(context, first); channels.push(...firstChannels);
    // A distinct endpoint allows two actual helper pairs without broadening the listener.
    const endpoint = process.platform === "win32" ? context.options.endpoint + "" : path.join(context.directory, "other.sock");
    const options = { ...context.options, endpoint: process.platform === "win32" ? context.options.endpoint.replace(/.$/, context.options.endpoint.endsWith("0") ? "1" : "0") : endpoint };
    second = await pair(options); const secondChannels = await authenticated(context, second, other); channels.push(...secondChannels);
    context.registry.revoke(2, context.registration.clientId); assert.equal(firstChannels[0].socket.destroyed, true); secondChannels[0].assertCurrent();
    assert.equal(secondChannels[0].socket.destroyed, false);
    const prepare = Database.prototype.prepare;
    mock.method(Database.prototype, "prepare", function (sql) { if (sql.startsWith("UPDATE local_clients")) throw new Error("synthetic-storage-private-canary"); return prepare.call(this, sql); });
    assert.throws(() => context.registry.revoke(3, registration.clientId), code("UNAVAILABLE"));
    assert.equal(secondChannels[0].socket.destroyed, true); assert.throws(() => context.registry.list(context.sessionId), code("UNAVAILABLE"));
    mock.restoreAll();
  } finally { mock.restoreAll(); for (const channel of channels) await channel.close(); await first?.close(); await second?.close(); context.dispose(); }
});

test("wrong host, stale session, caller cancellation and clock rollback fail closed", { timeout: 30000 }, async () => {
  const context = fixture(), wrong = context.identity("wrong-host"); let connections, channels = [];
  try {
    for (const [host, sessionId] of [[wrong, context.sessionId], [context.host, "stale-session"]]) {
      connections = await pair(context.options);
      await assert.rejects(context.registry.authenticate(connections.host, host, sessionId), LocalClientAuthenticationError);
      await connections.close(); connections = undefined;
    }
    const cancel = new AbortController(); connections = await pair(context.options); channels = await authenticated(context, connections, context.client, cancel.signal);
    cancel.abort(); assert.equal(channels[0].socket.destroyed, true); await connections.close(); connections = undefined;
    connections = await pair(context.options); channels = await authenticated(context, connections);
    context.advance(-1, false); assert.throws(channels[0].assertCurrent, code("UNAVAILABLE")); assert.equal(channels[0].socket.destroyed, true);
  } finally { for (const channel of channels) await channel.close(); await connections?.close(); context.dispose(); }
});
