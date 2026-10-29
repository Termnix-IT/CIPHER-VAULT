import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { nativeTransportExecutable, listenNativeTransport, connectNativeTransport } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { generateLocalIdentity } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { createLocalClientStore, openLocalClientStore } from "../apps/electron/dist/apps/electron/src/local-client-store.js";
import { LocalClientRegistry } from "../apps/electron/dist/apps/electron/src/local-client-registry.js";
import { LocalPairingCoordinator, LocalPairingError, encodeLocalPairingRequest, LOCAL_PAIRING_LIMITS } from "../apps/electron/dist/apps/electron/src/local-pairing.js";
import { authenticateLocalHost } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const rejected = error => error instanceof LocalPairingError && error.code === "LOCAL_PAIRING_UNAVAILABLE";
const approve = review => ({ pendingId: review.pendingId, expectedRevision: review.revision, fingerprint256: review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" });
async function fixture() {
  const context = createLocalAuthFixture(executable);
  const host = await generateLocalIdentity({ executable, role: "host" }), client = await generateLocalIdentity({ executable, role: "client" });
  const now = { wall: Date.now(), monotonic: 1000 }, clock = () => ({ ...now });
  const session = new VaultSession(clock, () => () => {}); session.unlock(Buffer.alloc(32, 8));
  const sessionId = session.getState().sessionId, file = path.join(context.directory, "pairing-clients.sqlite");
  const store = createLocalClientStore(file, host.certificate), registry = new LocalClientRegistry(store, session, () => now.wall, () => () => {});
  const pairing = new LocalPairingCoordinator(registry, session, clock);
  const request = (identity = client) => encodeLocalPairingRequest({ displayName: "合成ブラウザ", kind: "browser", certificate: identity.certificate }, now.wall);
  return { ...context, host, client, now, session, sessionId, file, store, registry, pairing, request,
    dispose() { pairing.close(); registry.close(); session.lock(); host.dispose(); client.dispose(); context.dispose(); } };
}

test("trusted review enrolls only the captured public credential, once, and survives registry reopen", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const request = context.request(), review = context.pairing.stage(context.sessionId, request);
    assert.equal(request.includes(context.client.privateKey), false); assert.equal(request.includes(Buffer.from("PRIVATE KEY")), false);
    assert.equal(Object.isFrozen(review), true); assert.equal(review.certificate, undefined); assert.equal(review.privateKey, undefined);
    assert.equal(review.registrationExpiresAt, context.now.wall + LOCAL_PAIRING_LIMITS.registrationLifetimeMs);
    assert.equal(context.registry.list(context.sessionId).clients.length, 0);
    request.fill(0); // The displayed snapshot must not retain caller-owned request bytes.
    const result = context.pairing.approve(context.sessionId, approve(review));
    assert.equal(result.fingerprint256, review.fingerprint256); assert.equal(result.certificate, undefined);
    assert.equal(context.pairing.current(context.sessionId), null);
    assert.throws(() => context.pairing.approve(context.sessionId, approve(review)), rejected);
    context.pairing.close(); context.registry.close();
    const reopened = openLocalClientStore(context.file, context.host.certificate);
    try { assert.equal(reopened.read().clients[0].clientId, result.clientId); assert.equal(reopened.read().clients[0].fingerprint256, review.fingerprint256); }
    finally { reopened.close(); }
  } finally { context.dispose(); }
});

test("public requests reject private material, host purpose, wrong schemas, control characters and stale requests", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const original = JSON.parse(context.request()), input = value => Buffer.from(JSON.stringify(value));
    for (const patch of [{ version: 2 }, { requestId: "caller-chosen" }, { extra: "synthetic-private-detail" }, { displayName: "name\nspoof" },
      { displayName: "name\u202espoof" }, { kind: "admin" }, { certificate: context.host.certificate.toString("base64") },
      { certificate: Buffer.concat([context.client.certificate, context.client.privateKey]).toString("base64") },
      { createdAt: context.now.wall + 1 }, { expiresAt: context.now.wall }, { expiresAt: context.now.wall + LOCAL_PAIRING_LIMITS.requestLifetimeMs + 1 }]) {
      assert.throws(() => context.pairing.stage(context.sessionId, input({ ...original, ...patch })), rejected);
      assert.equal(context.registry.list(context.sessionId).clients.length, 0);
    }
    for (const malformed of [Buffer.alloc(LOCAL_PAIRING_LIMITS.bytes + 1), Buffer.from([0xff]), input([]), input(null)]) {
      assert.throws(() => context.pairing.stage(context.sessionId, malformed), rejected);
    }
    assert.throws(() => encodeLocalPairingRequest({ displayName: "host", kind: "agent", certificate: context.host.certificate }), rejected);
    assert.throws(() => encodeLocalPairingRequest({ displayName: "hidden", kind: "browser", certificate: Buffer.concat([context.client.certificate, context.client.privateKey]) }), rejected);
  } finally { context.dispose(); }
});

test("wrong review handles, missing acknowledgement and fingerprints never authorize a registration", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const review = context.pairing.stage(context.sessionId, context.request()), approval = approve(review);
    for (const patch of [{ pendingId: randomUUID() }, { expectedRevision: review.revision + 1 }, { fingerprint256: "00:".repeat(31) + "00" }, { confirmation: false }, { extra: true }]) {
      assert.throws(() => context.pairing.approve(context.sessionId, { ...approval, ...patch }), rejected);
      assert.equal(context.registry.list(context.sessionId).clients.length, 0);
    }
    const newer = context.pairing.stage(context.sessionId, context.request());
    assert.notEqual(newer.pendingId, review.pendingId); assert.throws(() => context.pairing.approve(context.sessionId, approval), rejected);
    assert.equal(context.pairing.current(context.sessionId).pendingId, newer.pendingId);
    context.pairing.cancel(context.sessionId, newer.pendingId);
    assert.throws(() => context.pairing.approve(context.sessionId, approve(newer)), rejected);
  } finally { context.dispose(); }
});

test("review expires by monotonic or wall clock even without timers; rollback fails closed", { timeout: 20000 }, async () => {
  for (const change of [time => { time.monotonic += LOCAL_PAIRING_LIMITS.reviewLifetimeMs; }, time => { time.wall += LOCAL_PAIRING_LIMITS.reviewLifetimeMs; }, time => { time.wall--; }]) {
    const context = await fixture();
    try {
      const review = context.pairing.stage(context.sessionId, context.request()); change(context.now);
      assert.throws(() => context.pairing.approve(context.sessionId, approve(review)), rejected);
      assert.equal(context.store.read().clients.length, 0);
    } finally { context.dispose(); }
  }
});

test("lock, session replacement and registry revisions invalidate a previously displayed review", { timeout: 20000 }, async () => {
  const context = await fixture(); let other;
  try {
    for (const transition of [() => context.session.lock(), () => context.session.unlock(Buffer.alloc(32, 3))]) {
      context.session.unlock(Buffer.alloc(32, 2)); const sessionId = context.session.getState().sessionId;
      const review = context.pairing.stage(sessionId, context.request()); transition();
      assert.throws(() => context.pairing.approve(sessionId, approve(review)), rejected); assert.equal(context.store.read().clients.length, 0);
    }
    context.session.unlock(Buffer.alloc(32, 4)); const sessionId = context.session.getState().sessionId;
    const review = context.pairing.stage(sessionId, context.request());
    other = await generateLocalIdentity({ executable, role: "client" });
    context.registry.enroll(sessionId, review.revision, { displayName: "別の合成client", kind: "agent", certificate: other.certificate, expiresAt: context.now.wall + 60000 });
    assert.equal(context.pairing.current(sessionId), null); assert.throws(() => context.pairing.approve(sessionId, approve(review)), rejected);
    const fresh = context.pairing.stage(sessionId, context.request()); context.pairing.close();
    assert.throws(() => context.pairing.approve(sessionId, approve(fresh)), rejected); assert.equal(context.store.read().clients.length, 1);
  } finally { other?.dispose(); context.dispose(); }
});

test("a failed durable enrollment consumes its approval and cannot expose raw storage errors", { timeout: 20000 }, async () => {
  const context = await fixture();
  try {
    const review = context.pairing.stage(context.sessionId, context.request()); context.store.close();
    assert.throws(() => context.pairing.approve(context.sessionId, approve(review)), error => rejected(error) && !String(error).includes(context.directory));
    assert.throws(() => context.pairing.approve(context.sessionId, approve(review)), rejected);
  } finally { context.dispose(); }
});

test("approved pairing authenticates a real peer and locked revocation closes it without reviving old reviews", { timeout: 20000 }, async () => {
  const context = await fixture(); let listener, hostNative, clientNative, host, client;
  try {
    const review = context.pairing.stage(context.sessionId, context.request()), result = context.pairing.approve(context.sessionId, approve(review));
    listener = await listenNativeTransport(context.options);
    [hostNative, clientNative] = await Promise.all([listener.accepted, connectNativeTransport(context.options)]);
    [host, client] = await Promise.all([context.registry.authenticate(hostNative, context.host, context.sessionId), authenticateLocalHost(clientNative, context.client, context.host.certificate)]);
    assert.equal(host.clientId, result.clientId); host.assertCurrent();
    const received = once(host.socket, "data"); client.socket.write("synthetic-pairing-payload");
    assert.equal((await received)[0].toString(), "synthetic-pairing-payload");
    context.session.lock(); const lockedId = context.session.getState().sessionId;
    context.pairing.revoke(lockedId, 1, result.clientId);
    await Promise.all([hostNative.closed, clientNative.closed]); assert.equal(host.socket.destroyed, true); assert.equal(client.socket.destroyed, true);
    assert.notEqual(context.store.read().clients[0].revokedAt, null);
    context.session.unlock(Buffer.alloc(32, 9));
    assert.throws(() => context.pairing.stage(context.session.getState().sessionId, context.request()), rejected);
    assert.throws(() => context.pairing.revoke(lockedId, 2, null), rejected);
  } finally { await client?.close(); await host?.close(); await clientNative?.close(); await hostNative?.close(); await listener?.close(); context.dispose(); }
});
