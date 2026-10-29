import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, chmodSync, realpathSync, rmSync, renameSync, writeFileSync, readFileSync, lstatSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { listenNativeTransport, connectNativeTransport, nativeTransportExecutable, LocalTransportError } from "../apps/electron/dist/apps/electron/src/native-transport.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: root });
function fixture() {
  const directory = mkdtempSync(path.join(realpathSync(tmpdir()), "cv-nt-"));
  if (process.platform !== "win32") chmodSync(directory, 0o700);
  const endpoint = process.platform === "win32" ? `\\\\.\\pipe\\cipher-vault-${randomUUID()}` : path.join(directory, "transport.sock");
  return { directory, options: { executable, endpoint }, dispose() {
    assert.equal(path.dirname(directory), realpathSync(tmpdir())); assert.ok(path.basename(directory).startsWith("cv-nt-")); rmSync(directory, { recursive: true, force: true });
  } };
}
async function receive(stream, length) {
  const result = Buffer.alloc(length); let offset = 0;
  while (offset < length) {
    const bytes = stream.read(Math.min(length - offset, Math.max(1, stream.readableLength)));
    if (bytes) { bytes.copy(result, offset); offset += bytes.length; continue; }
    if (stream.destroyed) throw new Error("Transport closed before complete payload");
    await once(stream, "readable");
  }
  return result;
}

test("compiled native helpers report real OS peers and relay larger-than-pipe-buffer data in both directions", { timeout: 15000 }, async () => {
  const context = fixture(); let listener, server, client;
  try {
    listener = await listenNativeTransport(context.options);
    [server, client] = await Promise.all([listener.accepted, connectNativeTransport(context.options)]);
    assert.equal(server.peerProcessId, client.processId); assert.equal(client.peerProcessId, server.processId);
    const first = Buffer.alloc(256 * 1024, 0x35), second = Buffer.alloc(128 * 1024, 0x7c);
    const serverRead = receive(server.stream, first.length), clientRead = receive(client.stream, second.length);
    client.stream.write(first); server.stream.write(second);
    assert.deepEqual(await serverRead, first); assert.deepEqual(await clientRead, second);
    await client.close(); await server.closed;
  } finally { await client?.close(); await server?.close(); await listener?.close(); context.dispose(); }
});

test("duplicate native listeners fail closed while the first listener remains available", { timeout: 15000 }, async () => {
  const context = fixture(); let listener;
  try {
    listener = await listenNativeTransport(context.options);
    await assert.rejects(listenNativeTransport(context.options), error => error instanceof LocalTransportError && error.code === "LOCAL_TRANSPORT_UNAVAILABLE");
  } finally { await listener?.close(); context.dispose(); }
});

test("aborting a listener closes its helper and never yields an accepted connection", { timeout: 15000 }, async () => {
  const context = fixture(), controller = new AbortController(); let listener;
  try {
    listener = await listenNativeTransport({ ...context.options, signal: controller.signal }); controller.abort();
    await assert.rejects(listener.accepted, LocalTransportError); await listener.closed;
  } finally { await listener?.close(); context.dispose(); }
});

test("missing native executable is rejected without starting an endpoint", async () => {
  const context = fixture();
  try { await assert.rejects(listenNativeTransport({ ...context.options, executable: path.join(path.dirname(executable), "missing-transport") }), LocalTransportError); }
  finally { context.dispose(); }
});

if (process.platform !== "win32") test("compiled Unix helper retains a substituted path when aborted", { timeout: 15000 }, async () => {
  const context = fixture(); let listener;
  try {
    listener = await listenNativeTransport(context.options);
    const original = path.join(context.directory, "original.sock"); renameSync(context.options.endpoint, original);
    writeFileSync(context.options.endpoint, "synthetic replacement canary");
    await listener.close(); await assert.rejects(listener.accepted, LocalTransportError);
    assert.equal(readFileSync(context.options.endpoint, "utf8"), "synthetic replacement canary");
    assert.equal(lstatSync(original).isSocket(), true);
  } finally { await listener?.close(); context.dispose(); }
});
