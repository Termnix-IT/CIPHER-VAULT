import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, chmodSync, realpathSync, rmSync, renameSync, writeFileSync, readFileSync, lstatSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { spawn } from "node:child_process";
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

if (process.platform === "win32") test("native client rejects an explicitly broad pipe ACL before sending protocol bytes", { timeout: 20000 }, async () => {
  const context = fixture(), name = context.options.endpoint.slice("\\\\.\\pipe\\".length);
  const script = `
    $ErrorActionPreference = 'Stop'
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $acl = [System.IO.Pipes.PipeSecurity]::new()
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($user, $everyone)) {
      $acl.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($sid, [System.IO.Pipes.PipeAccessRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow))
    }
    $pipe = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create('${name}', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 4096, 4096, $acl)
    try {
      [Console]::Out.WriteLine('READY')
      $pipe.WaitForConnection()
      if ($pipe.ReadByte() -ne -1) { throw 'Unexpected protocol byte' }
      [Console]::Out.WriteLine('EOF_WITHOUT_PROTOCOL')
    } finally { $pipe.Dispose() }
  `;
  const child = spawn("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "", errors = "";
  const closed = once(child, "close"); closed.catch(() => {});
  const ready = new Promise((resolve, reject) => {
    child.stdout.on("data", bytes => { output += bytes; if (output.includes("READY\n") || output.includes("READY\r\n")) resolve(); });
    child.stderr.on("data", bytes => { errors += bytes; });
    child.once("error", reject);
    child.once("close", () => reject(new Error("Synthetic pipe fixture exited: " + errors.slice(-1000))));
  });
  const timer = setTimeout(() => child.kill(), 15000);
  try {
    await ready;
    await assert.rejects(connectNativeTransport(context.options), LocalTransportError);
    const [code] = await closed;
    assert.equal(code, 0, errors.slice(-1000));
    assert.ok(output.includes("EOF_WITHOUT_PROTOCOL"));
  } finally { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) { child.kill(); await closed.catch(() => {}); } context.dispose(); }
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
