import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import { createCipheriv, createDecipheriv, randomBytes, randomUUID, createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import Database from "better-sqlite3";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { BrowserMessageDecoder, browserRequest, encodeBrowserMessage, runBrowserMessage } from "../apps/electron/dist/apps/electron/src/browser-message.js";
import { BrowserClient } from "../apps/electron/dist/apps/electron/src/browser-client.js";
import { openBrowserClientStore } from "../apps/electron/dist/apps/electron/src/browser-client-store.js";
import { parseBrowserConnectionInfo, browserDiscoveryEndpoint } from "../apps/electron/dist/apps/electron/src/browser-connection-info.js";
import { readLocalPublicFile } from "../apps/electron/dist/apps/electron/src/local-public-files.js";
import { LocalConnections } from "../apps/electron/dist/apps/electron/src/local-connections.js";
import { nativeTransportExecutable } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: fileURLToPath(new URL("../", import.meta.url)) });
const request = operation => ({ version: 1, id: randomUUID(), operation });
const sha = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function protector() {
  const secret = randomBytes(32), calls = { wrap: 0, unwrap: 0 };
  return { calls,
    async wrap(key) { calls.wrap++; const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", secret, iv);
      return { provider: "windows-dpapi", data: Buffer.concat([iv, cipher.update(key), cipher.final(), cipher.getAuthTag()]) }; },
    async unwrap(value) { calls.unwrap++; const bytes = value.data, decipher = createDecipheriv("aes-256-gcm", secret, bytes.subarray(0, 12)); decipher.setAuthTag(bytes.subarray(-16));
      return { key: Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]), shouldReEncrypt: false }; },
    dispose() { secret.fill(0); }
  };
}
async function fixture(options = {}) {
  const context = createLocalAuthFixture(executable), protectedKeys = protector(), session = new VaultSession();
  const profile = path.join(context.directory, "browser-profile"); fs.mkdirSync(profile, { mode: 0o700 });
  let browser = new BrowserClient(profile, executable, protectedKeys, options.clientKind ?? "chrome");
  const desktop = new LocalConnections(context.directory, executable, protectedKeys, session, options.search);
  session.unlock(Buffer.alloc(32, 9)); const id = session.getState().sessionId;
  return { ...context, profile, protectedKeys, session, desktop, id,
    get browser() { return browser; },
    reopen() { browser.close(); browser = new BrowserClient(profile, executable, protectedKeys, options.clientKind ?? "chrome"); },
    async dispose() { browser.close(); await desktop.close(); session.lock(); protectedKeys.dispose(); context.dispose(); }
  };
}
async function pairing(context) {
  const file = path.join(context.directory, randomUUID() + ".cvpair");
  const state = await context.browser.preparePairing(file);
  await context.desktop.setEnabled(context.id, context.desktop.state(context.id).revision, true);
  context.desktop.stage(context.id, fs.readFileSync(file)); const review = context.desktop.state(context.id).review;
  assert.equal(review.fingerprint256, state.fingerprint256);
  await context.desktop.approve(context.id, { pendingId: review.pendingId, expectedRevision: review.revision, fingerprint256: review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" });
  const client = context.desktop.state(context.id).clients.find(value => value.fingerprint256 === review.fingerprint256);
  const receipt = context.desktop.connectionInfo(context.id, client.clientId), receiptFile = path.join(context.directory, randomUUID() + ".cvconnection");
  fs.writeFileSync(receiptFile, receipt); await context.browser.importConnection(receiptFile);
  return { file, state, client, receipt, receiptFile };
}

test("Native Messaging framing is bounded, split-safe, strict UTF-8 and single-use", () => {
  const value = request("get-state"), bytes = encodeBrowserMessage(value);
  assert.equal(bytes.readUInt32LE(), bytes.length - 4);
  for (let split = 1; split < bytes.length; split++) {
    const decoder = new BrowserMessageDecoder(); assert.equal(decoder.push(bytes.subarray(0, split)), undefined);
    assert.deepEqual(browserRequest(decoder.push(bytes.subarray(split))), value); assert.throws(() => decoder.push(bytes));
  }
  for (const size of [0, 1, 65537, 0xffffffff]) { const length = Buffer.alloc(4); length.writeUInt32LE(size); assert.throws(() => new BrowserMessageDecoder().push(length)); }
  assert.throws(() => new BrowserMessageDecoder().push(Buffer.from([2, 0, 0, 0, 0xff, 0xff])));
  assert.throws(() => new BrowserMessageDecoder().push(Buffer.concat([bytes, bytes])));
  for (const patch of [{ operation: "get_password" }, { path: "synthetic-path" }, { id: "old" }, { version: 2 }]) assert.throws(() => browserRequest({ ...value, ...patch }));
});

test("Codex client sends bounded candidate search over real mutual TLS; revoke and browser clients cannot search", { timeout: 25000 }, async () => {
  let calls = 0;
  const context = await fixture({ clientKind: "codex", search: async input => { calls++; assert.equal(input.query, "synthetic"); return [{ id: "candidate", serviceName: "Synthetic service", origin: "https://example.test" }]; } });
  try {
    const result = await pairing(context); assert.equal(JSON.parse(fs.readFileSync(result.file)).kind, "agent");
    assert.equal(context.browser.state().displayName.startsWith("Codex MCP"), true);
    const items = await context.browser.searchCandidates("synthetic"); assert.equal(items[0].id, "candidate"); assert.equal(calls, 1);
    await context.desktop.revoke(context.id, context.desktop.state(context.id).revision, result.client.clientId);
    await assert.rejects(context.browser.searchCandidates("synthetic")); assert.equal(calls, 1);
  } finally { await context.dispose(); }
  const browser = await fixture({ search: async () => { assert.fail("Browser registration must not gain search"); } });
  try { await pairing(browser); await assert.rejects(browser.browser.searchCandidates("synthetic")); }
  finally { await browser.dispose(); }
});

test("Native Messaging cancels EOF/duplicate/deadline and never reflects arbitrary errors", async () => {
  const input = new PassThrough(), output = new PassThrough(), chunks = []; output.on("data", chunk => chunks.push(chunk));
  const command = request("get-state"), done = runBrowserMessage(input, output, async () => ({ state: "unpaired" }));
  input.write(encodeBrowserMessage(command)); await done;
  assert.deepEqual(new BrowserMessageDecoder().push(Buffer.concat(chunks)), { version: 1, id: command.id, ok: true, result: { state: "unpaired" } });
  input.destroy(); output.destroy();
  for (const stop of [stream => stream.end(), stream => stream.write(encodeBrowserMessage(request("get-state"))), () => {}]) {
    const source = new PassThrough(), target = new PassThrough(); target.resume(); let cancelled = false;
    const running = runBrowserMessage(source, target, async (_request, signal) => {
      await new Promise(resolve => signal.addEventListener("abort", () => { cancelled = true; resolve(); }, { once: true })); return {};
    }, 40);
    source.write(encodeBrowserMessage(request("get-state"))); stop(source); await assert.rejects(running); assert.equal(cancelled, true); source.destroy(); target.destroy();
  }
  const source = new PassThrough(), target = new PassThrough(), result = []; target.on("data", chunk => result.push(chunk));
  const running = runBrowserMessage(source, target, async () => { throw new Error("synthetic-private-canary"); });
  source.write(encodeBrowserMessage(request("get-state"))); await assert.rejects(running);
  assert.equal(Buffer.concat(result).includes(Buffer.from("synthetic-private-canary")), false); source.destroy(); target.destroy();
  const blockedInput = new PassThrough(), blockedOutput = new Writable({ highWaterMark: 1, write() {} });
  const blocked = runBrowserMessage(blockedInput, blockedOutput, async () => ({ state: "unpaired" }), 40);
  blockedInput.write(encodeBrowserMessage(request("get-state"))); await assert.rejects(blocked); blockedInput.destroy(); blockedOutput.destroy();
});

test("browser pairing protects a client key, restores public state, and authenticates the pinned desktop", { timeout: 25000 }, async () => {
  const context = await fixture();
  try {
    assert.deepEqual(context.browser.state(), { state: "unpaired", displayName: null, fingerprint256: null });
    assert.equal(fs.existsSync(path.join(context.profile, "data")), false); assert.deepEqual(context.protectedKeys.calls, { wrap: 0, unwrap: 0 });
    const result = await pairing(context); assert.equal(context.browser.state().state, "configured");
    const before = context.browser.state(), calls = { ...context.protectedKeys.calls }; context.reopen();
    assert.deepEqual(context.browser.state(), before); assert.deepEqual(context.protectedKeys.calls, calls);
    assert.equal((await context.browser.checkConnection()).checked, true);
    const publicRequest = fs.readFileSync(result.file), keys = fs.readdirSync(path.join(context.profile, "data")).filter(file => file.endsWith(".cvkey"));
    assert.equal(keys.length, 1); assert.equal(publicRequest.includes(Buffer.from("PRIVATE KEY")), false);
    assert.equal(fs.readFileSync(path.join(context.profile, "data", keys[0])).includes(Buffer.from("PRIVATE KEY")), false);
    await context.desktop.revoke(context.id, context.desktop.state(context.id).revision, result.client.clientId);
    await assert.rejects(context.browser.checkConnection()); assert.equal(context.browser.state().state, "configured");
    await context.browser.resetPairing(); assert.equal(context.browser.state().state, "request-ready");
    assert.notEqual(context.browser.state().fingerprint256, before.fingerprint256);
    assert.equal(fs.readdirSync(path.join(context.profile, "data")).filter(file => file.endsWith(".cvkey")).length, 2);
    await assert.rejects(context.browser.importConnection(result.receiptFile));
  } finally { await context.dispose(); }
});

test("public receipts bind own client and exact host; discovery cannot substitute a peer", { timeout: 25000 }, async () => {
  const context = await fixture();
  try {
    const result = await pairing(context), receipt = JSON.parse(result.receipt), content = JSON.parse(fs.readFileSync(result.file)), certificate = Buffer.from(content.certificate, "base64");
    for (const patch of [{ clientId: "anything" }, { clientFingerprint256: "00:".repeat(31) + "00" }, { hostFingerprint256: content.certificate }, { discoveryFile: "relative/connection.json" },
      { discoveryFile: "\\\\server\\share\\connection.json" }, { hostCertificate: content.certificate }, { extra: "private" }]) assert.throws(() => parseBrowserConnectionInfo(Buffer.from(JSON.stringify({ ...receipt, ...patch })), certificate));
    const discovery = JSON.parse(fs.readFileSync(receipt.discoveryFile));
    assert.ok(browserDiscoveryEndpoint(Buffer.from(JSON.stringify(discovery)), receipt));
    for (const patch of [{ generation: "anything" }, { hostFingerprint256: content.certificate }, { clients: [] }, { clients: [{ clientId: receipt.clientId, endpoint: "https://example.invalid" }] },
      { clients: [discovery.clients[0], discovery.clients[0]] }, { extra: true }]) assert.throws(() => browserDiscoveryEndpoint(Buffer.from(JSON.stringify({ ...discovery, ...patch })), receipt));
    const altered = { ...receipt, clientId: randomUUID() }, file = path.join(context.directory, "altered.cvconnection"); fs.writeFileSync(file, JSON.stringify(altered));
    await assert.rejects(context.browser.importConnection(file)); context.reopen(); assert.equal(context.browser.state().state, "configured");
    assert.equal(context.browser.state().fingerprint256, result.state.fingerprint256);
  } finally { await context.dispose(); }
});

test("cancelled protection and immutable exports retain candidates without adopting or overwriting credentials", { timeout: 25000 }, async () => {
  const context = await fixture();
  try {
    const file = path.join(context.directory, "request.cvpair"); fs.writeFileSync(file, "synthetic-existing");
    await assert.rejects(context.browser.preparePairing(file)); assert.equal(fs.readFileSync(file, "utf8"), "synthetic-existing");
    const previous = context.browser.state(), before = context.protectedKeys.calls.wrap;
    await context.browser.preparePairing(path.join(context.directory, "next.cvpair")); assert.deepEqual(context.browser.state(), previous); assert.equal(context.protectedKeys.calls.wrap, before);
    const controller = new AbortController(); controller.abort(); await assert.rejects(context.browser.resetPairing(controller.signal)); assert.deepEqual(context.browser.state(), previous);
    const root = path.join(context.profile, "data"); context.browser.close();
    fs.writeFileSync(path.join(root, "unknown-candidate"), "keep"); assert.throws(() => context.reopen()); assert.equal(fs.readFileSync(path.join(root, "unknown-candidate"), "utf8"), "keep");
  } finally { await context.dispose(); }
});

test("browser metadata rejects unknown schemas, leases, oversized fields and linked public files", { timeout: 25000 }, async () => {
  const context = await fixture(); let store;
  try {
    await context.browser.preparePairing(path.join(context.directory, "request.cvpair")); const file = path.join(context.profile, "data/client.sqlite");
    assert.throws(() => openBrowserClientStore(file)); context.browser.close(); const before = sha(file);
    assert.throws(() => openBrowserClientStore(file, true)); assert.equal(sha(file), before);
    store = openBrowserClientStore(file); const snapshot = store.read(); assert.ok(snapshot.credential); store.close();
    const original = fs.readFileSync(file);
    for (const statement of ["UPDATE browser_client SET certificate=zeroblob(4097)", "UPDATE browser_client SET identity_id=NULL,certificate=zeroblob(4097),receipt=NULL", "UPDATE browser_client SET receipt=zeroblob(16385)", "CREATE TABLE unexpected(value TEXT)"]) {
      const raw = new Database(file); raw.exec(statement); raw.close(); assert.throws(() => openBrowserClientStore(file)); fs.writeFileSync(file, original);
    }
    const oversized = path.join(context.directory, "large.cvconnection"); fs.writeFileSync(oversized, Buffer.alloc(16385)); assert.throws(() => readLocalPublicFile(oversized));
    const linked = path.join(context.directory, "linked.cvconnection"); fs.writeFileSync(linked, "{}"); fs.linkSync(linked, linked + ".link"); assert.throws(() => readLocalPublicFile(linked));
  } finally { store?.close(); await context.dispose(); }
});

test("aborted or unavailable key protection never installs a new reference, including late completion", { timeout: 25000 }, async () => {
  const context = await fixture(); let release;
  try {
    await context.browser.preparePairing(path.join(context.directory, "first.cvpair")); const before = context.browser.state();
    const wrap = context.protectedKeys.wrap;
    context.protectedKeys.wrap = async () => { throw new Error("synthetic-provider-private-canary"); };
    await assert.rejects(context.browser.resetPairing()); assert.deepEqual(context.browser.state(), before);
    let entered; const started = new Promise(resolve => { entered = resolve; });
    context.protectedKeys.wrap = async key => { const result = await wrap(key); entered(); await new Promise(resolve => { release = resolve; }); return result; };
    const controller = new AbortController(), resetting = context.browser.resetPairing(controller.signal); await started;
    await assert.rejects(context.browser.resetPairing()); controller.abort(); release(); await assert.rejects(resetting);
    assert.deepEqual(context.browser.state(), before); context.reopen(); assert.deepEqual(context.browser.state(), before);
  } finally { release?.(); await context.dispose(); }
});
