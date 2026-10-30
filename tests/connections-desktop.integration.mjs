// Real product renderer/preload/main with synthetic profiles and a real OS protector. Three actual app processes.
import { app, dialog, powerMonitor, safeStorage } from "electron";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, X509Certificate } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { generateLocalIdentity } from "../apps/electron/dist/apps/electron/src/local-identity.js";
import { ProtectedLocalIdentityStore, localIdentityFile } from "../apps/electron/dist/apps/electron/src/protected-local-identity.js";
import { electronDeviceKeyProtector } from "../apps/electron/dist/apps/electron/src/device-key-protector.js";
import { encodeLocalPairingRequest } from "../apps/electron/dist/apps/electron/src/local-pairing.js";
import { nativeTransportExecutable, connectNativeTransport } from "../apps/electron/dist/apps/electron/src/native-transport.js";
import { authenticateLocalHost } from "../apps/electron/dist/apps/electron/src/local-client-auth.js";
import { vaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const root = process.env.CIPHER_VAULT_TEST_ROOT, phase = process.env.CIPHER_VAULT_CONNECTIONS_PHASE, relative = path.relative(tmpdir(), root ?? "");
assert.ok(root && relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
assert.ok(["create", "restart", "paused"].includes(phase));
const profile = path.join(root, "connections-profile"), clientDirectory = path.join(root, "synthetic-client"), metadataFile = path.join(root, "synthetic-public-client.json");
const requestFile = path.join(root, "synthetic.cvpair"), receiptFile = path.join(root, `${phase}.cvconnection`), password = "synthetic-connections-master";
if (phase === "create") { fs.mkdirSync(profile, { recursive: true }); fs.mkdirSync(clientDirectory, { mode: 0o700 }); }
app.disableHardwareAcceleration(); app.setPath("userData", profile); app.setPath("sessionData", profile);
assert.equal(path.resolve(app.commandLine.getSwitchValue("user-data-dir")), profile);
process.env.PASSWORD_MANAGER_RENDERER_URL = "http://127.0.0.1:1";
powerMonitor.getSystemIdleState = () => "active";
dialog.showErrorBox = () => { console.error("FAIL connections startup"); app.exit(1); };
dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [requestFile] });
dialog.showSaveDialog = async () => ({ canceled: false, filePath: receiptFile });
let window, identity, native, remote;
const created = new Promise(resolve => app.once("browser-window-created", (_event, value) => { window = value; value.hide(); value.webContents.setBackgroundThrottling(false); value.webContents.once("did-finish-load", resolve); }));
const timeout = setTimeout(() => { console.error("FAIL connections test timeout", phase); app.exit(1); }, 120000);
const evaluate = source => window.webContents.executeJavaScript(source);
async function waitFor(source) { for (let i = 0; i < 300; i++) { if (await evaluate(source)) return; await delay(50); } throw new Error("Connections UI condition failed: " + source); }
const click = selector => evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
async function fill(selector, value) { await evaluate(`(()=>{const input=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`); }
async function fillMaster(value) { for (const selector of ['.cipher-form input[name=master]', '.cipher-form input[name=confirm]']) if (await evaluate(`!!document.querySelector(${JSON.stringify(selector)})`)) await fill(selector, value); }
async function open() {
  await evaluate("[...document.querySelectorAll('.app-menu-trigger')].find(b=>b.textContent==='ツール').click()");
  await waitFor("[...document.querySelectorAll('.app-menu-item')].some(b=>b.textContent==='外部アプリの接続'&&!b.disabled)");
  await evaluate("[...document.querySelectorAll('.app-menu-item')].find(b=>b.textContent==='外部アプリの接続').click()");
  await waitFor("!!document.querySelector('.local-connections-dialog[open] .connections-status')");
}
async function save() { await click(".connections-export"); await waitFor("document.querySelector('.local-connections-dialog .vault-tool-message')?.textContent.includes('保存しました')"); return JSON.parse(fs.readFileSync(receiptFile)); }
async function connect(receipt, executable) {
  const discovery = JSON.parse(fs.readFileSync(receipt.discoveryFile)), target = discovery.clients.find(client => client.clientId === receipt.clientId);
  assert.ok(target); native = await connectNativeTransport({ executable, endpoint: target.endpoint });
  remote = await authenticateLocalHost(native, identity, Buffer.from(receipt.hostCertificate, "base64")); assert.equal(remote.socket.getProtocol(), "TLSv1.3");
}

async function run() { try {
  await import("../apps/electron/dist/apps/electron/src/main.js"); await created;
  assert.equal(await evaluate("document.fonts.load('500 14px \"Noto Sans JP\"','接続の管理').then(fonts=>fonts.length>0&&fonts.every(font=>font.status==='loaded'))"), true);
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')"); assert.equal(vaultSession.getState().isUnlocked, false);
  await fillMaster(password); await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
  await open();
  const executable = nativeTransportExecutable({ packaged: false, resourcesPath: "", workspaceRoot: path.resolve(".") });
  const keys = new ProtectedLocalIdentityStore(electronDeviceKeyProtector(app, safeStorage));
  const current = () => vaultSession.requireUnlocked();
  let metadata;
  if (phase === "create") {
    await waitFor("document.querySelector('.connections-status strong')?.textContent.includes('オフ')");
    await click('.connections-status button'); await waitFor("!!document.querySelector('.connections-ready')");
    identity = await generateLocalIdentity({ executable, role: "client" });
    const reference = { identityId: randomUUID(), role: "client", fingerprint256: new X509Certificate(identity.certificate).fingerprint256 };
    await keys.save(localIdentityFile(clientDirectory, reference.identityId), identity, reference, current);
    fs.writeFileSync(requestFile, encodeLocalPairingRequest({ displayName: "合成ブラウザ連携", kind: "browser", certificate: identity.certificate }));
    await click('.connections-select'); await waitFor("!!document.querySelector('.connections-review')");
    assert.equal(await evaluate("document.querySelector('.connections-approve').disabled"), true);
    await click('.local-connections-dialog > .vault-tool-heading button'); await waitFor("!document.querySelector('.local-connections-dialog[open]')");
    await open(); await waitFor("!!document.querySelector('.connections-ready')&&!document.querySelector('.connections-review')");
    await click('.connections-select'); await waitFor("!!document.querySelector('.connections-review')");
    window.setContentSize(1000, 680); await waitFor("innerWidth===1000");
    assert.equal(await evaluate("(()=>{const d=document.querySelector('.local-connections-dialog');return d.scrollWidth<=d.clientWidth})()"), true);
    await evaluate("document.querySelector('.connections-approve').scrollIntoView({block:'end'})");
    assert.equal(await evaluate("document.querySelector('.connections-approve').getBoundingClientRect().bottom<=innerHeight"), true);
    window.setContentSize(1100, 820); await delay(350); await evaluate("document.querySelector('.local-connections-dialog').scrollTop=0");
    fs.writeFileSync(path.resolve("dist-desktop/connections-ui-review.png"), (await window.webContents.capturePage()).toPNG());
    await click('.connections-review input[type=checkbox]'); await waitFor("!document.querySelector('.connections-approve').disabled");
    await click('.connections-approve'); await waitFor("!!document.querySelector('.connections-row')&&!document.querySelector('.connections-review')");
    const receipt = await save(); assert.equal(receipt.clientFingerprint256, reference.fingerprint256);
    metadata = { reference, clientId: receipt.clientId, hostFingerprint256: receipt.hostFingerprint256 }; fs.writeFileSync(metadataFile, JSON.stringify(metadata));
    await connect(receipt, executable); await remote.close(); remote = undefined; native = undefined;
    console.log("PASS product UI enables real OS protection, confirms fingerprint, registers and exports public connection info");
  } else {
    metadata = JSON.parse(fs.readFileSync(metadataFile));
    if (phase === "paused") {
      await waitFor("document.querySelector('.connections-status strong')?.textContent.includes('停止中')");
      await click('.connections-status button');
    }
    await waitFor("!!document.querySelector('.connections-ready')&&!!document.querySelector('.connections-row')");
    identity = (await keys.load(localIdentityFile(clientDirectory, metadata.reference.identityId), metadata.reference, current)).identity;
    const receipt = await save(); assert.equal(receipt.clientId, metadata.clientId); assert.equal(receipt.hostFingerprint256, metadata.hostFingerprint256);
    await connect(receipt, executable);
    if (phase === "restart") {
      await click('.connections-status button'); await waitFor("document.querySelector('.connections-status strong')?.textContent.includes('停止中')");
      await native.closed; assert.equal(remote.socket.destroyed, true);
      console.log("PASS actual product restart stays locked, restores the same host/registration after unlock, and stop closes TLS");
    } else {
      await click('.connections-revoke'); await waitFor("!document.querySelector('.connections-row')&&!!document.querySelector('.connections-history')");
      await native.closed; assert.equal(remote.socket.destroyed, true);
      const old = vaultSession.getState().sessionId; vaultSession.lock(); await waitFor("!document.querySelector('.local-connections-dialog[open]')");
      assert.equal(await evaluate(`window.passwordManager.getLocalConnections(${JSON.stringify(old)}).then(()=>false,()=>true)`), true);
      console.log("PASS stopped configuration survives actual restart; explicit resume, immediate revocation and stale IPC refusal");
    }
  }
  await remote?.close(); await native?.close(); identity?.dispose(); clearTimeout(timeout); app.quit();
} catch (error) {
  await remote?.close(); await native?.close(); identity?.dispose(); clearTimeout(timeout);
  console.error("FAIL connections desktop", phase, error); app.exit(1);
} }
void run();
