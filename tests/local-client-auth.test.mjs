import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { listenNativeTransport, connectNativeTransport, nativeTransportExecutable } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { authenticateLocalClient, authenticateLocalHost, LocalClientAuthenticationError } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: root });
const fixture = () => createLocalAuthFixture(executable);
async function pair(options) {
  const listener = await listenNativeTransport(options);
  try { const [host, client] = await Promise.all([listener.accepted, connectNativeTransport(options)]); return { host, client, close: async () => { await client.close(); await host.close(); await listener.close(); } }; }
  catch (error) { await listener.close(); throw error; }
}
async function receive(stream, size) {
  const result = Buffer.alloc(size); let offset = 0;
  while (offset < size) {
    const chunk = stream.read(Math.min(size - offset, Math.max(1, stream.readableLength)));
    if (chunk) { chunk.copy(result, offset); offset += chunk.length; continue; }
    if (stream.destroyed) throw new Error("Authenticated channel closed"); await once(stream, "readable");
  }
  return result;
}

test("registered client and pinned host authenticate with TLS 1.3; native wire has no plaintext canary", { timeout: 20000 }, async () => {
  const context = fixture(); let connections, host, client;
  try {
    const hostIdentity = context.identity("host"), clientIdentity = context.identity("client"); connections = await pair(context.options);
    const encrypted = [];
    for (const connection of [connections.host, connections.client]) connection.stream.on("data", data => encrypted.push(Buffer.from(data)));
    [host, client] = await Promise.all([
      authenticateLocalClient(connections.host, hostIdentity, [{ clientId: "registered-client", certificate: clientIdentity.certificate }]),
      authenticateLocalHost(connections.client, clientIdentity, hostIdentity.certificate)
    ]);
    assert.equal(host.clientId, "registered-client"); assert.equal(client.clientId, "desktop");
    assert.equal(host.peerProcessId, connections.client.processId); assert.equal(client.peerProcessId, connections.host.processId);
    const canary = Buffer.from("synthetic-local-auth-canary-" + randomUUID());
    const payload = receive(host.socket, canary.length); client.socket.write(canary); assert.deepEqual(await payload, canary);
    assert.equal(Buffer.concat(encrypted).includes(canary), false);
    assert.equal(host.socket.authorized, true); assert.equal(client.socket.authorized, true);
    assert.equal(host.socket.getProtocol(), "TLSv1.3");
  } finally { await client?.close(); await host?.close(); await connections?.close(); context.dispose(); }
});

test("same-user OS peer with an unregistered certificate is denied on both ends", { timeout: 20000 }, async () => {
  const context = fixture(); let connections;
  try {
    const host = context.identity("host"), registered = context.identity("registered"), rogue = context.identity("rogue"); connections = await pair(context.options);
    const results = await Promise.allSettled([
      authenticateLocalClient(connections.host, host, [{ clientId: "registered-client", certificate: registered.certificate }]),
      authenticateLocalHost(connections.client, rogue, host.certificate)
    ]);
    for (const result of results) { assert.equal(result.status, "rejected"); assert.ok(result.reason instanceof LocalClientAuthenticationError); assert.equal(result.reason.code, "LOCAL_CLIENT_AUTH_FAILED"); }
  } finally { await connections?.close(); context.dispose(); }
});

test("a host certificate outside the client's explicit pin is denied", { timeout: 20000 }, async () => {
  const context = fixture(); let connections;
  try {
    const host = context.identity("host"), client = context.identity("client"), other = context.identity("other"); connections = await pair(context.options);
    const results = await Promise.allSettled([
      authenticateLocalClient(connections.host, host, [{ clientId: "registered-client", certificate: client.certificate }]),
      authenticateLocalHost(connections.client, client, other.certificate)
    ]);
    assert.equal(results[0].status, "rejected"); assert.equal(results[1].status, "rejected");
  } finally { await connections?.close(); context.dispose(); }
});

test("invalid registration and an already revoked connection do not authenticate", { timeout: 20000 }, async () => {
  const context = fixture(); let connections;
  try {
    const host = context.identity("host"); connections = await pair(context.options);
    await assert.rejects(authenticateLocalClient(connections.host, host, []), LocalClientAuthenticationError);
    const controller = new AbortController(); controller.abort();
    await assert.rejects(authenticateLocalHost(connections.client, host, host.certificate, controller.signal), LocalClientAuthenticationError);
  } finally { await connections?.close(); context.dispose(); }
});

test("a valid chain cannot substitute a different leaf for an explicitly registered client or host", { timeout: 20000 }, async () => {
  const context = fixture(); let connections;
  try {
    const host = context.identity("host"), client = context.identity("client");
    const siblingClient = context.identity("sibling-client", client), siblingHost = context.identity("sibling-host", host);
    for (const replaced of ["client", "host"]) {
      connections = await pair(context.options);
      const results = await Promise.allSettled([
        authenticateLocalClient(connections.host, replaced === "host" ? siblingHost : host, [{ clientId: "registered-client", certificate: client.certificate }]),
        authenticateLocalHost(connections.client, replaced === "client" ? siblingClient : client, host.certificate)
      ]);
      for (const result of results) { assert.equal(result.status, "rejected"); assert.ok(result.reason instanceof LocalClientAuthenticationError); }
      await connections.close(); connections = undefined;
    }
  } finally { await connections?.close(); context.dispose(); }
});

test("revocation after mutual authentication closes both channels", { timeout: 20000 }, async () => {
  const context = fixture(), controller = new AbortController(); let connections, host, client;
  try {
    const hostIdentity = context.identity("host"), clientIdentity = context.identity("client"); connections = await pair(context.options);
    [host, client] = await Promise.all([
      authenticateLocalClient(connections.host, hostIdentity, [{ clientId: "registered-client", certificate: clientIdentity.certificate }], controller.signal),
      authenticateLocalHost(connections.client, clientIdentity, hostIdentity.certificate)
    ]);
    const closed = Promise.all([connections.host.closed, connections.client.closed]); controller.abort();
    assert.equal(host.socket.destroyed, true); await closed;
    assert.equal(host.socket.destroyed, true); assert.equal(client.socket.destroyed, true);
  } finally { await client?.close(); await host?.close(); await connections?.close(); context.dispose(); }
});
