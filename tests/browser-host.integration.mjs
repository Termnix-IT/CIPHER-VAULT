import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { randomUUID, X509Certificate } from "node:crypto";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { encodeBrowserMessage, BrowserMessageDecoder } from "../apps/electron/dist/apps/electron/src/browser-message.js";
import { nativeTransportExecutable } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { generateLocalIdentity } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { createLocalClientStore } from "../apps/electron/dist/apps/electron/src/local-client-store.js";
import { LocalClientRegistry } from "../apps/electron/dist/apps/electron/src/local-client-registry.js";
import { LocalConnectionServer } from "../apps/electron/dist/apps/electron/src/local-connection-server.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const electron = createRequire(import.meta.url)("electron"), workspaceRoot = fs.realpathSync(path.resolve("."));
const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot });
const main = path.join(workspaceRoot, "apps/electron/dist/apps/electron/src/main.js");

test("browser launcher and client role use real OS protection, isolated restarts and pinned mutual TLS", { timeout: 120000 }, async () => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cv-browser-host-")), directory = path.join(root, "native-host"); fs.mkdirSync(directory, { mode: 0o700 });
  const binary = process.platform === "win32" ? "cipher-vault-native-host.exe" : "cipher-vault-native-host", launcher = path.join(directory, binary);
  fs.copyFileSync(path.join(path.dirname(executable), binary), launcher); fs.chmodSync(launcher, 0o700);
  const configFile = path.join(directory, "host-config.json"), profile = path.join(directory, "client-profile");
  fs.writeFileSync(configFile, JSON.stringify({ version: 1, browser: "chrome", extensionOrigin: BROWSER_EXTENSION_ORIGIN, applicationExecutable: fs.realpathSync(electron), applicationEntry: main }));
  const session = new VaultSession(); let host, registry, server;
  const env = { ...process.env, CIPHER_VAULT_TEST_ROOT: root, ELECTRON_NO_ATTACH_CONSOLE: "1" }; delete env.ELECTRON_RUN_AS_NODE;
  async function command(operation, fixture, options = {}) {
    const id = randomUUID(), chunks = [], errors = [];
    const args = fixture ? ["tests/browser-host-fixture.integration.mjs", `--cipher-vault-native-host=${configFile}`, `--cipher-vault-caller-origin=${BROWSER_EXTENSION_ORIGIN}`, `--user-data-dir=${profile}`] : [BROWSER_EXTENSION_ORIGIN, ...(process.platform === "win32" ? ["--parent-window=0"] : [])];
    const child = spawn(fixture ? electron : launcher, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"], env: { ...env, ...(fixture ? { CIPHER_VAULT_BROWSER_FIXTURE: fixture } : {}), ...options.env } });
    let bytes = 0; const timer = setTimeout(() => child.kill(), 20000);
    child.stdout.on("data", chunk => { bytes += chunk.length; if (bytes > 65540) child.kill(); else chunks.push(chunk); });
    child.stderr.on("data", chunk => { if (errors.length < 8) errors.push(chunk); }); child.stdin.on("error", () => {});
    const exit = new Promise((resolve, reject) => { child.on("error", reject); child.once("close", code => resolve(code)); });
    child.stdin.write(encodeBrowserMessage({ version: 1, id, operation })); // Keep stdin open; EOF deliberately cancels Native Messaging.
    const code = await exit; clearTimeout(timer);
    let output = Buffer.concat(chunks);
    if (fixture && process.platform === "win32" && output.subarray(0,2).equals(Buffer.from([13,10]))) output = output.subarray(2);
    assert.ok(output.length > 4, `Missing native reply (${code}): ${Buffer.concat(errors).toString().slice(0, 250)}`);
    let response; try { response = new BrowserMessageDecoder().push(output); } catch { assert.fail(`Native frame length ${output.length}, prefix ${output.subarray(0, 16).toString("hex")}, exit ${code}, stages ${Buffer.concat(errors).toString().slice(0, 500)}`); }
    assert.equal(response.version, 1); assert.equal(response.id, id);
    if (response.ok) assert.equal(code, 0); else { assert.notEqual(code, 0); assert.equal(response.error, "UNAVAILABLE"); }
    assert.equal(output.includes(Buffer.from("PRIVATE KEY")), false); return response;
  }
  try {
    assert.equal((await command("get-state")).result.state, "unpaired"); assert.equal(fs.existsSync(path.join(profile, "data")), false);
    assert.equal((await command("prepare-pairing", "cancel")).result.cancelled, true); assert.equal(fs.existsSync(path.join(profile, "data")), false);
    const prepared = (await command("prepare-pairing", "prepare")).result; assert.equal(prepared.state, "request-ready");
    const request = JSON.parse(fs.readFileSync(path.join(root, "synthetic.cvpair"))); assert.equal(request.kind, "browser");
    host = await generateLocalIdentity({ executable, role: "host" }); session.unlock(Buffer.alloc(32, 8)); const sessionId = session.getState().sessionId;
    const store = createLocalClientStore(path.join(root, "synthetic-host.sqlite"), host.certificate); registry = new LocalClientRegistry(store, session);
    const client = registry.enroll(sessionId, 0, { displayName: request.displayName, kind: "browser", certificate: Buffer.from(request.certificate, "base64"), expiresAt: Date.now() + 60000 });
    const discovery = path.join(root, "connection.json"); server = new LocalConnectionServer(executable, discovery, registry, host, sessionId, () => assert.fail("Synthetic server failed")); await server.sync();
    fs.writeFileSync(path.join(root, "synthetic.cvconnection"), JSON.stringify({ version: 1, clientId: client.clientId, clientFingerprint256: prepared.fingerprint256, hostCertificate: host.certificate.toString("base64"),
      hostFingerprint256: new X509Certificate(host.certificate).fingerprint256, discoveryFile: discovery }));
    assert.equal((await command("import-connection", "import")).result.state, "configured");
    assert.equal((await command("get-state")).result.fingerprint256, prepared.fingerprint256);
    assert.equal((await command("check-connection", undefined, { env: { PASSWORD_MANAGER_DATA_DIR: path.join(root, "forbidden-vault"), NODE_OPTIONS: "--invalid-synthetic-option", ELECTRON_ENABLE_LOGGING: "1" } })).result.checked, true);
    assert.equal(fs.existsSync(path.join(root, "forbidden-vault")), false);
    registry.revoke(registry.list(sessionId).revision, client.clientId); await server.sync();
    assert.equal((await command("check-connection")).ok, false);
    assert.equal((await command("reset-pairing", "reset-cancel")).result.cancelled, true);
    const reset = (await command("reset-pairing", "reset")).result; assert.equal(reset.state, "request-ready"); assert.notEqual(reset.fingerprint256, prepared.fingerprint256);
    assert.equal(fs.readdirSync(path.join(profile, "data")).filter(name => name.endsWith(".cvkey")).length, 2);
    assert.equal(fs.existsSync(path.join(profile, "data/password-manager.db")), false); assert.equal(fs.existsSync(path.join(profile, "data/vaults")), false);
    console.log("PASS actual native launcher, OS-protected client key across restarts, TLS pin, revoke and explicit reset");
  } finally {
    await server?.close(); registry?.close(); session.lock(); host?.dispose();
    await delay(200); assert.ok(path.basename(root).startsWith("cv-browser-host-")); fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});
