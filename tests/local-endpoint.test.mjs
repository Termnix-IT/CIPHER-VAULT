import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, createConnection } from "node:net";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

assert.ok(["win32", "linux", "darwin"].includes(process.platform), "Native local endpoint probe is unsupported on this OS");
const fixtures = fileURLToPath(new URL("./fixtures/", import.meta.url));
const windows = process.platform === "win32";

function fixture() {
  const directory = mkdtempSync(path.join(realpathSync(tmpdir()), "cv-ep-")), children = new Set();
  const name = `cipher-vault-probe-${randomUUID()}`, endpoint = windows ? `\\\\.\\pipe\\${name}` : path.join(directory, "probe.sock");
  if (!windows) { chmodSync(directory, 0o700); assert.ok(Buffer.byteLength(endpoint) < 100, "Temporary socket path exceeds portable sockaddr_un limits"); }
  function run(command, args) {
    const child = spawn(command, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); children.add(child);
    let output = "", errors = "", readyResolve, readyReject;
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; }); ready.catch(() => {});
    const timer = setTimeout(() => child.kill(), 45000);
    child.stdout.on("data", data => {
      output += data;
      if (output.includes("\n")) { try { if (JSON.parse(output.slice(0, output.indexOf("\n"))).ready === true) readyResolve(); } catch { /* Wait for a complete protocol line. */ } }
      if (output.length > 8192) child.kill();
    });
    child.stderr.on("data", data => { errors += data; if (errors.length > 8192) child.kill(); });
    const done = new Promise(resolve => {
      child.once("error", error => { clearTimeout(timer); readyReject(error); resolve({ code: -1, output, errors: error.code }); });
      child.once("close", (code, signal) => { clearTimeout(timer); children.delete(child); readyReject(new Error(errors || "Native helper exited before readiness")); resolve({ code, signal, output, errors }); });
    });
    return { child, ready, done };
  }
  const helper = (mode, expected = process.pid, count = 3) => windows ?
    run("pwsh", ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", path.join(fixtures, "local-endpoint-windows.ps1"), "-Mode", mode, "-PipeName", name, "-ExpectedPeer", String(expected), "-Count", String(count)]) :
    run("python3", ["-B", path.join(fixtures, "local-endpoint-posix.py"), mode, endpoint, String(expected), ...(mode === "serve" ? [String(count)] : [])]);
  return {
    directory, endpoint, helper, run,
    async dispose() {
      const closes = [...children].map(async child => { const closed = once(child, "close").catch(() => {}); child.kill(); await closed; });
      await Promise.all(closes);
      assert.equal(path.dirname(directory), realpathSync(tmpdir())); assert.ok(path.basename(directory).startsWith("cv-ep-"));
      rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  };
}
async function inspection(context, expected = process.pid) {
  const result = await context.helper("inspect", expected).done;
  assert.equal(result.code, 0, result.errors); assert.equal(result.signal, null);
  return JSON.parse(result.output);
}
async function request(endpoint, claimed) {
  const socket = createConnection(endpoint), packet = Buffer.alloc(4); packet.writeUInt32BE(claimed);
  let response = "";
  try {
    await new Promise((resolve, reject) => {
      socket.setTimeout(5000, () => socket.destroy(new Error("Probe timeout")));
      socket.once("connect", () => socket.write(packet)); socket.once("error", reject);
      socket.once("close", () => { if (!response.includes("\n")) reject(new Error("Probe connection closed without a response")); });
      socket.on("data", data => {
        response += data;
        if (response.length > 1024) socket.destroy(new Error("Probe response too large"));
        else if (response.includes("\n")) resolve();
      });
    });
    return JSON.parse(response);
  } finally { socket.destroy(); }
}

test("native client inspects the connected Node endpoint and rejects the wrong server identity", { timeout: 60000 }, async () => {
  const context = fixture(), sockets = new Set(), server = createServer(socket => {
    sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket));
    socket.setTimeout(5000, () => socket.destroy()); socket.end("synthetic probe only\n");
  });
  try {
    server.listen(context.endpoint); await once(server, "listening");
    if (!windows) chmodSync(context.endpoint, 0o600);
    const result = await inspection(context); assert.equal(result.accepted, true); assert.equal(result.peerMatches, true);
    if (windows) {
      assert.equal(typeof result.acl.onlyUserAllowed, "boolean");
      assert.equal(typeof result.acl.broadReadAllowAce, "boolean");
      // A measured ACL is reported without publishing a SID or assuming every machine has the same policy.
      console.log(`Node pipe ACL: user-only=${result.acl.onlyUserAllowed}, broad-read-allow-ace=${result.acl.broadReadAllowAce}`);
    } else assert.equal(result.userMatches, true);
    const wrong = await inspection(context, process.pid + 1); assert.equal(wrong.accepted, false); assert.equal(wrong.peerMatches, false);
  } finally {
    for (const socket of sockets) socket.destroy();
    if (server.listening) await new Promise(resolve => server.close(resolve));
    await context.dispose();
  }
});

test("native endpoints reject PID spoofing and a client rejects a rebound endpoint", { timeout: 60000 }, async () => {
  const context = fixture();
  try {
    const server = context.helper("serve"); await server.ready;
    const duplicate = await context.helper("serve", process.pid, 1).done; assert.notEqual(duplicate.code, 0, "A duplicate endpoint must not replace the first server");
    const checked = await inspection(context, server.child.pid); assert.equal(checked.accepted, true);
    if (windows) assert.deepEqual(checked.acl, { ownerMatchesUser: true, onlyUserAllowed: true, broadReadAllowAce: false });
    // The inspection consumed a connection without a payload. The remaining two prove PID binding.
    const own = await request(context.endpoint, 0);
    assert.deepEqual(own, { accepted: true, peerMatches: true, userMatches: true, claimedMatches: false });
    const attacker = await context.run(process.execPath, [path.join(fixtures, "local-endpoint-client.mjs"), context.endpoint, String(process.pid)]).done;
    if (attacker.code !== 0) { const stopped = await server.done; assert.fail(JSON.stringify({ client: attacker, server: stopped })); }
    assert.equal(attacker.code, 0, attacker.errors);
    assert.deepEqual(JSON.parse(attacker.output), { accepted: false, peerMatches: false, userMatches: true, claimedMatches: true });
    const completion = await server.done; assert.equal(completion.code, 0, completion.errors); assert.equal(completion.signal, null);
    if (!windows) assert.equal(existsSync(context.endpoint), false);
    const replacement = createServer(socket => { socket.on("error", () => {}); socket.end("synthetic replacement only\n"); });
    try {
      replacement.listen(context.endpoint); await once(replacement, "listening");
      if (!windows) chmodSync(context.endpoint, 0o600);
      const rebound = await inspection(context, server.child.pid);
      assert.equal(rebound.accepted, false); assert.equal(rebound.peerMatches, false);
    } finally { if (replacement.listening) await new Promise(resolve => replacement.close(resolve)); }
  } finally { await context.dispose(); }
});

if (!windows) test("Unix cleanup preserves a file substituted for the socket while its server is alive", { timeout: 60000 }, async () => {
  const context = fixture();
  try {
    const server = context.helper("serve", process.pid, 1); await server.ready;
    const original = path.join(context.directory, "original.sock"); renameSync(context.endpoint, original);
    writeFileSync(context.endpoint, "synthetic replacement canary");
    assert.notEqual((await context.helper("inspect").done).code, 0);
    assert.deepEqual(await request(original, 0), { accepted: true, peerMatches: true, userMatches: true, claimedMatches: false });
    const completion = await server.done; assert.equal(completion.code, 0, completion.errors);
    assert.equal(readFileSync(context.endpoint, "utf8"), "synthetic replacement canary");
    assert.equal(lstatSync(original).isSocket(), true);
  } finally { await context.dispose(); }
});

if (!windows) test("native Unix probe refuses shared directories, existing files and symlink endpoints without deleting them", { timeout: 60000 }, async () => {
  const context = fixture();
  try {
    const canary = path.join(context.directory, "canary"); writeFileSync(canary, "synthetic endpoint canary");
    chmodSync(context.directory, 0o755);
    assert.notEqual((await context.helper("serve", process.pid, 1).done).code, 0);
    assert.equal(existsSync(context.endpoint), false); chmodSync(context.directory, 0o700);
    writeFileSync(context.endpoint, "synthetic existing endpoint");
    assert.notEqual((await context.helper("serve", process.pid, 1).done).code, 0);
    assert.equal(readFileSync(context.endpoint, "utf8"), "synthetic existing endpoint"); rmSync(context.endpoint);
    symlinkSync(canary, context.endpoint);
    for (const mode of ["inspect", "serve"]) assert.notEqual((await context.helper(mode, process.pid, 1).done).code, 0);
    assert.equal(lstatSync(context.endpoint).isSymbolicLink(), true); assert.equal(readFileSync(canary, "utf8"), "synthetic endpoint canary");
  } finally { await context.dispose(); }
});
