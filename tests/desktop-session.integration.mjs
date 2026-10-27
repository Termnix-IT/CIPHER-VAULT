// Run with Electron, never with the user's application profile.
import { app, clipboard, ClipboardItem, powerMonitor } from "electron";
import assert from "node:assert/strict";
import { appendFileSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { invalidContractCases } from "./input-contract-fixtures.mjs";

// Prevent Electron's default error dialog from hiding startup or shutdown failures.
process.on("uncaughtException", (error) => { console.error("FAIL uncaught desktop test error", error); app.exit(1); });
process.on("unhandledRejection", (error) => { console.error("FAIL unhandled desktop test rejection", error); app.exit(1); });

const temporaryRoot = process.env.CIPHER_VAULT_TEST_ROOT;
assert.ok(temporaryRoot, "Run with node scripts/run-desktop-tests.mjs");
const relativeRoot = path.relative(tmpdir(), temporaryRoot);
assert.ok(relativeRoot.startsWith("cipher-vault-desktop-session-") && !relativeRoot.includes(path.sep));
const profile = path.join(temporaryRoot, "profile");
mkdirSync(profile);
app.setPath("userData", profile);
// All clipboard operations remain synthetic, including delayed cleanup after lock.
const nativeClipboard = { write: clipboard.write, read: clipboard.read, clear: clipboard.clear };
let clipboardItems = [], clipboardWrites = 0, clipboardClears = 0;
clipboard.write = async (items) => { clipboardItems = items; clipboardWrites++; };
clipboard.read = async () => clipboardItems;
clipboard.clear = () => { clipboardItems = []; clipboardClears++; };
app.once("quit", () => { Object.assign(clipboard, nativeClipboard); });
// CI runner desktop state must not decide whether the synthetic vault can open.
const nativeIdleState = powerMonitor.getSystemIdleState;
let simulatedIdleState = "active";
powerMonitor.getSystemIdleState = () => simulatedIdleState;
app.once("quit", () => { powerMonitor.getSystemIdleState = nativeIdleState; });
// Force the built renderer, even if another development server is running.
process.env.PASSWORD_MANAGER_RENDERER_URL = process.env.CIPHER_VAULT_TEST_RENDERER_URL ?? "http://127.0.0.1:1";
const output = process.env.CIPHER_VAULT_QA_OUTPUT;
const realIdle = process.env.CIPHER_VAULT_QA_REAL_IDLE === "1";
if (output) {
  mkdirSync(output, { recursive: true });
  writeFileSync(path.join(output, "desktop-session.log"), "");
  const log = (...values) => appendFileSync(path.join(output, "desktop-session.log"), values.map((value) => value instanceof Error ? value.stack : String(value)).join(" ") + "\n");
  console.log = log;
  console.error = log;
}
console.log("START isolated desktop session integration");
let window;
let developmentConnected = false;
let testExitCode = 0;
const created = new Promise((resolve) => app.once("browser-window-created", (_event, value) => {
  window = value;
  console.log("WINDOW created");
  value.webContents.setBackgroundThrottling(false);
  value.hide();
  value.webContents.once("did-finish-load", () => { console.log("RENDERER loaded"); resolve(value); });
  value.webContents.on("preload-error", () => console.error("PRELOAD failed"));
  value.webContents.on("console-message", (event) => {
    if (event.message === "[vite] connected.") developmentConnected = true;
  });
}));
app.on("will-quit", (event) => {
  if (!testExitCode) return;
  // Let the application's other will-quit listeners close SQLite before exiting.
  event.preventDefault();
  setImmediate(() => app.exit(testExitCode));
});

const timeout = setTimeout(() => { console.error("FAIL desktop session integration timed out"); testExitCode = 1; app.quit(); }, realIdle ? 9 * 60 * 1000 : 180000);
const evaluate = (source) => window.webContents.executeJavaScript(source);
async function waitFor(source, attempts = 200) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    if (await evaluate(source)) return;
    await delay(50);
  }
  throw new Error(`UI condition failed: ${source}`);
}
async function click(selector) {
  await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
}
async function fill(selector, value) {
  await evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(selector)});
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
}
async function capture(name) {
  if (!output) return;
  mkdirSync(output, { recursive: true });
  window.showInactive();
  // Inspect settled frames, not the initial opacity of the existing transitions.
  await delay(2500);
  writeFileSync(path.join(output, name), (await window.capturePage()).toPNG());
  window.hide();
}

async function run() {
try {
  await import("../apps/electron/dist/apps/electron/src/main.js");
  await created;
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
  if (process.env.CIPHER_VAULT_TEST_RENDERER_URL) {
    for (let i = 0; i < 100 && !developmentConnected; i++) await delay(50);
    assert.equal(developmentConnected, true, "Vite HMR connection did not open");
    console.log("PASS development CSP allows the local Vite HMR connection");
  }
  const preferences = window.webContents.getLastWebPreferences();
  assert.equal(preferences.sandbox, true);
  assert.equal(preferences.contextIsolation, true);
  assert.equal(preferences.nodeIntegration, false);
  assert.equal(await evaluate("typeof require === 'undefined' && typeof process === 'undefined' && typeof Buffer === 'undefined' && Object.isFrozen(window.passwordManager)"), true);
  assert.equal(await evaluate("(async () => { const a = await document.fonts.load('400 16px \"Share Tech Mono\"'); const b = await document.fonts.load('500 16px \"JetBrains Mono\"'); return a.length > 0 && b.length > 0 && a.every(x => x.status === 'loaded') && b.every(x => x.status === 'loaded'); })()"), true);
  await evaluate("window.__policyViolations = []; document.addEventListener('securitypolicyviolation', event => window.__policyViolations.push(event.effectiveDirective));");
  if (!process.env.CIPHER_VAULT_TEST_RENDERER_URL) {
    await evaluate("(() => { const script = document.createElement('script'); script.textContent = 'window.__inlineExecuted = true'; document.head.append(script); script.remove(); })()");
    await delay(50);
    assert.equal(await evaluate("window.__inlineExecuted === undefined && window.__policyViolations.includes('script-src-elem')"), true);
    const outside = path.join(temporaryRoot, "outside-renderer.js");
    writeFileSync(outside, "window.__outsideFileExecuted = true;");
    await evaluate(`new Promise(resolve => { const script = document.createElement('script'); script.src = ${JSON.stringify(pathToFileURL(outside).href)}; script.onload = script.onerror = () => { script.remove(); resolve(); }; document.head.append(script); })`);
    assert.equal(await evaluate("window.__outsideFileExecuted === undefined"), true);
    assert.equal(await evaluate("fetch('http://127.0.0.1:1/csp-test').then(() => false, () => true)"), true);
    await waitFor("window.__policyViolations.includes('connect-src')");
  }
  const baseUri = await evaluate("document.baseURI");
  await evaluate("(() => { const base = document.createElement('base'); base.href = 'http://127.0.0.1:1/foreign/'; document.head.prepend(base); })()");
  assert.equal(await evaluate("document.baseURI"), baseUri);
  await evaluate("document.querySelector('base').remove()");
  assert.equal(await evaluate("navigator.permissions.query({name:'geolocation'}).then(result => result.state)"), "denied");
  assert.equal(await evaluate("Notification.requestPermission()"), "denied");
  const updateState = await evaluate("window.passwordManager.getUpdateState()");
  assert.equal(updateState.status, "unsupported");
  await evaluate("window.passwordManager.checkForUpdates()");
  await evaluate("window.passwordManager.downloadUpdate()");
  assert.equal(await evaluate("window.passwordManager.installUpdate(false)"), undefined);
  console.log("PASS sandbox preload, local fonts, CSP and denied browser permissions preserve desktop update APIs");
  assert.equal(path.resolve(app.getPath("userData")), path.resolve(profile));
  const services = await import("../apps/api/dist/apps/api/src/services/vault-service.js");
  const { vaultSession, VAULT_IDLE_TIMEOUT_MS } = await import("../apps/api/dist/apps/api/src/services/vault-session.js");
  const { getDatabase, getDatabasePath } = await import("../apps/api/dist/apps/api/src/db/database.js");
  const database = getDatabase();
  assert.equal(path.resolve(getDatabasePath()), path.join(profile, "data", "password-manager.db"));

  // Exercise the real React handlers and the preload/IPC path with synthetic inputs.
  await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
  await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.cipher-dashboard') && !document.querySelector('.sidebar-lock').disabled");
  const backupFile = await evaluate(`(async () => window.passwordManager.exportBackup({passphrase:"synthetic-sandbox-backup-passphrase"}, (await window.passwordManager.fetchVaultStatus()).sessionId))()`);
  assert.deepEqual(await evaluate(`(async () => window.passwordManager.restoreBackup(${JSON.stringify({ passphrase: "synthetic-sandbox-backup-passphrase", content: backupFile.content })}, (await window.passwordManager.fetchVaultStatus()).sessionId))()`), { restoredCount: 0 });
  const downloadTarget = path.join(temporaryRoot, "sandbox-backup.cvault");
  let downloadTimeout;
  const downloaded = new Promise((resolve, reject) => {
    downloadTimeout = setTimeout(() => reject(new Error("sandbox backup download timed out")), 10000);
    window.webContents.session.once("will-download", (_event, item) => {
      item.setSavePath(downloadTarget);
      item.once("done", (_done, state) => { state === "completed" ? resolve() : reject(new Error(`download ${state}`)); });
    });
  });
  await evaluate(`(() => { const url = URL.createObjectURL(new Blob([${JSON.stringify(backupFile.content)}], {type:'application/json'})); const a = document.createElement('a'); a.href = url; a.download = 'sandbox-backup.cvault'; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 5000); })()`);
  try { await downloaded; } finally { clearTimeout(downloadTimeout); }
  assert.equal(readFileSync(downloadTarget, "utf8"), backupFile.content);
  console.log("PASS sandbox backup export, restore and Blob download");
  await click('.sidebar-add');
  await waitFor("!!document.querySelector('.editor-fields')");
  await fill('.editor-fields .editor-field:nth-child(1) input', "Session QA");
  await fill('.editor-fields .editor-field:nth-child(2) input', "fixture-user");
  await fill('.editor-fields input[type=password]', "synthetic-entry-password");
  await click('.entry-editor button[type=submit]');
  await waitFor("!!document.querySelector('.entry-view-fields') && document.querySelector('.inspector-title').textContent === 'Session QA'");
  await click('.inspector-actions > button');
  await waitFor("!!document.querySelector('.editor-fields')");
  await fill('.editor-fields .editor-field:nth-child(2) input', "fixture-user-checked");
  await click('.entry-editor button[type=submit]');
  await waitFor("!!document.querySelector('.entry-view-fields') && document.body.textContent.includes('fixture-user-checked')");
  const before = database.prepare("SELECT * FROM password_entries").get();
  const unlockedId = services.getVaultStatus().sessionId;
  for (const item of invalidContractCases()) {
    await assert.rejects(evaluate(`window.passwordManager[${JSON.stringify(item.operation)}](${JSON.stringify(item.payload)}, ${JSON.stringify(unlockedId)})`),
      (error) => error.message.includes(item.message));
    assert.equal(services.getVaultStatus().sessionId, unlockedId);
    assert.equal(services.getVaultStatus().isUnlocked, true);
    assert.deepEqual(database.prepare("SELECT * FROM password_entries").get(), before);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM password_entries").get().count, 1);
  }
  console.log("PASS real IPC rejects the same malformed contract fixtures as HTTP without changing the vault");

  for (const value of [null, 1, {}, [], "x".repeat(1024 * 1024 + 1)]) {
    await assert.rejects(evaluate(`window.passwordManager.copyText(${JSON.stringify(value)}, ${JSON.stringify(unlockedId)})`), /文字列で指定|容量が上限/);
  }
  assert.equal(clipboardWrites, 0);
  await evaluate(`window.passwordManager.copyText("synthetic clipboard fixture", ${JSON.stringify(unlockedId)})`);
  assert.equal(clipboardWrites, 1);
  assert.equal(await (await clipboardItems[0].getType("text/plain")).text(), "synthetic clipboard fixture");
  for (const method of ["fetchEntry", "deleteEntry"]) {
    await assert.rejects(evaluate(`window.passwordManager.${method}(42, ${JSON.stringify(unlockedId)})`), /エントリIDは文字列/);
  }
  console.log("PASS real IPC validates IDs and clipboard input before a mocked clipboard write");

  const entryService = await import("../apps/api/dist/apps/api/src/services/entry-service.js");
  const cryptoService = await import("../apps/api/dist/apps/api/src/services/crypto-service.js");
  const legacy = entryService.createEntry({ serviceName: "Legacy read fixture", loginId: "fixture", password: "synthetic" });
  database.prepare("UPDATE password_entries SET encrypted_notes = ? WHERE id = ?")
    .run(cryptoService.encryptSecret("あ".repeat(100000)), legacy.id);
  assert.equal(await evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(legacy.id)}, ${JSON.stringify(unlockedId)}).then(entry => entry.notes.length)`), 100000);
  await evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(legacy.id)}, ${JSON.stringify(unlockedId)})`);
  console.log("PASS real IPC still reads a legacy field above the new write limit");
  await click('.inspector-actions > button');
  await waitFor("!!document.querySelector('.editor-fields')");
  await fill('.editor-fields .editor-field:nth-child(1) input', "x".repeat(1025));
  await click('.entry-editor button[type=submit]');
  await waitFor("document.body.textContent.includes('サービス名の容量が上限を超えています') && !document.querySelector('.entry-editor button[type=submit]').disabled");
  assert.equal(await evaluate("document.querySelector('.editor-fields .editor-field:nth-child(1) input').value.length"), 1025);
  assert.deepEqual(database.prepare("SELECT * FROM password_entries").get(), before);
  services.lockVault();
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
  await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
  await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.entry-row') && !document.querySelector('.sidebar-lock').disabled");
  await click('.entry-row');
  await waitFor("!!document.querySelector('.entry-view-fields')");
  console.log("PASS the renderer retains a rejected edit, displays the limit and preserves the stored row");
  await click('button[aria-label="パスワードをコピー"]');
  await waitFor("document.body.textContent.includes('30秒後またはロック時に消去')");
  for (const event of ["poll-locked", "lock-screen", "unlock-screen", "suspend", "resume"]) {
    const id = services.getVaultStatus().sessionId;
    await evaluate(`window.passwordManager.copyText("synthetic OS clipboard fixture", ${JSON.stringify(id)})`);
    const retainedKey = vaultSession.requireKey();
    if (event === "poll-locked") {
      simulatedIdleState = "locked";
      await assert.rejects(evaluate(`window.passwordManager.recordVaultActivity(${JSON.stringify(id)})`), /画面ロック・スリープ中/);
    } else powerMonitor.emit(event); // The real OS is never locked or suspended by this test.
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    assert.equal(services.getVaultStatus().isUnlocked, false);
    assert.deepEqual(retainedKey, Buffer.alloc(32));
    for (let i = 0; i < 100 && clipboardItems.length; i++) await delay(10);
    assert.equal(clipboardItems.length, 0);
    if (event === "poll-locked" || event === "lock-screen" || event === "suspend") {
      await assert.rejects(evaluate(`window.passwordManager.unlockVault({masterPassword:"desktop-session-fixture-passphrase"}, ${JSON.stringify(services.getVaultStatus().sessionId)})`), /画面ロック・スリープ中/);
      simulatedIdleState = "active";
      powerMonitor.emit(event === "suspend" ? "resume" : "unlock-screen");
      assert.equal(services.getVaultStatus().isUnlocked, false);
    }
    await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
    await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.entry-row') && !document.querySelector('.sidebar-lock').disabled");
    await click('.entry-row');
    await waitFor("!!document.querySelector('.entry-view-fields')");
  }
  console.log("PASS simulated OS events and locked-screen polling lock Core, wipe the key and clipboard, block unlock while suspended/locked and never auto-unlock");

  await evaluate(`window.passwordManager.copyText("synthetic clipboard fixture", ${JSON.stringify(services.getVaultStatus().sessionId)})`);
  const replacement = new ClipboardItem({ "text/plain": "another application's synthetic copy" });
  clipboardItems = [replacement];
  const clearsBeforeReplacement = clipboardClears;
  services.lockVault();
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
  await delay(50);
  assert.equal(clipboardClears, clearsBeforeReplacement);
  assert.equal(clipboardItems[0], replacement);
  await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
  await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.entry-row') && !document.querySelector('.sidebar-lock').disabled");
  await click('.entry-row');
  await waitFor("!!document.querySelector('.entry-view-fields')");
  console.log("PASS another application's replacement clipboard is preserved on lock");

  await evaluate(`window.passwordManager.copyText("synthetic thirty-second clipboard fixture", ${JSON.stringify(services.getVaultStatus().sessionId)})`);
  const copiedAt = performance.now();
  console.log("WAIT real thirty-second clipboard expiry (synthetic clipboard)");
  for (let i = 0; i < 400 && clipboardItems.length; i++) await delay(100);
  assert.equal(clipboardItems.length, 0);
  assert.ok(performance.now() - copiedAt >= 29000);
  console.log("PASS real thirty-second clipboard timer expires the synthetic owned clipboard");
  await capture("session-unlocked.png");
  console.log("PASS real renderer setup/create/detail via preload and IPC");

  await click('.inspector-actions > button');
  await waitFor("!!document.querySelector('.editor-fields')");
  await fill('.editor-fields input[type=password]', "unsaved-synthetic-draft");
  const realNow = Date.now;
  try {
    if (!realIdle) Date.now = () => realNow() + VAULT_IDLE_TIMEOUT_MS + 1;
    else console.log("WAIT real five-minute Core idle expiry");
    // Core expiry is checked by the real renderer's status polling, not a UI idle timer.
    await waitFor("!document.querySelector('.cipher-dashboard') && document.body.textContent.includes('5分間操作がなかった')", realIdle ? 7000 : 200);
    assert.equal(services.getVaultStatus().isUnlocked, false);
    assert.equal(await evaluate("document.body.textContent.includes('fixture-user') || [...document.querySelectorAll('input')].some(x => x.value.includes('synthetic'))"), false);
    assert.equal(await evaluate("document.querySelectorAll('.app-titlebar').length"), 1);
    await capture("session-idle-locked.png");
  } finally { Date.now = realNow; }
  assert.deepEqual(database.prepare("SELECT * FROM password_entries").get(), before);
  console.log(`PASS ${realIdle ? "real" : "simulated"} five-minute Core expiry clears the unsaved renderer and preserves the DB`);

  await fill('.cipher-form input[type=password]', "wrong-fixture-password");
  await click('.cipher-form button[type=submit]');
  await waitFor("document.body.textContent.includes('マスターパスワードが正しくありません')");
  assert.equal(services.getVaultStatus().isUnlocked, false);
  await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
  await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.entry-row') && !document.querySelector('.sidebar-lock').disabled");
  await click('.entry-row');
  await waitFor("!!document.querySelector('.entry-view-fields')");
  const status = services.getVaultStatus();
  const fromPreload = await evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(before.id)}, ${JSON.stringify(status.sessionId)})`);
  assert.equal(fromPreload.password, "synthetic-entry-password");
  await click('.sidebar-lock');
  await waitFor("!document.querySelector('.cipher-dashboard')");
  assert.equal(services.getVaultStatus().isUnlocked, false);
  console.log("PASS wrong password, re-unlock, existing ciphertext read and manual lock");

  // Hold the real async crypto callback to make the IPC cancellation race deterministic.
  const nativeCrypto = createRequire(import.meta.url)("node:crypto");
  const originalScrypt = nativeCrypto.scrypt;
  let held;
  nativeCrypto.scrypt = (...args) => {
    const callback = args.pop();
    return originalScrypt(...args, (error, key) => { held = { key, finish: () => callback(error, key) }; });
  };
  syncBuiltinESMExports();
  try {
    const intent = services.getVaultStatus().sessionId;
    const pending = evaluate(`window.passwordManager.unlockVault({ masterPassword: "desktop-session-fixture-passphrase" }, ${JSON.stringify(intent)})`);
    const rejected = assert.rejects(pending, /保管庫の状態が変わりました/);
    for (let i = 0; i < 200 && !held; i++) await delay(10);
    assert.ok(held, "async KDF callback did not arrive");
    assert.equal((await evaluate("window.passwordManager.fetchVaultStatus()")).isUnlocked, false);
    await assert.rejects(evaluate(`window.passwordManager.unlockVault({ masterPassword: "desktop-session-fixture-passphrase" }, ${JSON.stringify(intent)})`), /処理の完了を待って/);
    powerMonitor.emit("lock-screen");
    held.finish();
    await rejected;
    assert.deepEqual(held.key, Buffer.alloc(32));
    assert.equal(services.getVaultStatus().isUnlocked, false);
    powerMonitor.emit("unlock-screen");
  } finally {
    nativeCrypto.scrypt = originalScrypt;
    syncBuiltinESMExports();
  }
  console.log("PASS real IPC remains responsive during KDF, rejects concurrent unlock and cancels a late key");

  for (let i = 0; i < 5; i++) {
    const intent = services.getVaultStatus().sessionId;
    await assert.rejects(evaluate(`window.passwordManager.unlockVault({ masterPassword: "wrong-fixture-password" }, ${JSON.stringify(intent)})`), /マスターパスワードが正しくありません/);
  }
  await assert.rejects(evaluate(`window.passwordManager.unlockVault({ masterPassword: "desktop-session-fixture-passphrase" }, ${JSON.stringify(services.getVaultStatus().sessionId)})`), /秒後/);
  await delay(1050);
  console.log("PASS real IPC enforces the unlock cooldown");

  await services.unlockVault({ masterPassword: "desktop-session-fixture-passphrase" });
  await waitFor("!!document.querySelector('.cipher-dashboard')");
  await assert.rejects(evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(before.id)}, ${JSON.stringify(status.sessionId)})`), /保管庫の状態が変わりました/);
  console.log("PASS real IPC rejects requests from a previous unlocked generation");
  const key = vaultSession.requireKey();
  await evaluate(`window.passwordManager.copyText("synthetic crash clipboard fixture", ${JSON.stringify(services.getVaultStatus().sessionId)})`);
  window.webContents.forcefullyCrashRenderer();
  for (let i = 0; i < 100 && services.getVaultStatus().isUnlocked; i++) await delay(50);
  assert.equal(services.getVaultStatus().isUnlocked, false);
  assert.deepEqual(key, Buffer.alloc(32));
  for (let i = 0; i < 100 && clipboardItems.length; i++) await delay(10);
  assert.equal(clipboardItems.length, 0);
  console.log("PASS real renderer crash destroys the key");

  window.webContents.reload();
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
  await fill('.cipher-form input[type=password]', "desktop-session-fixture-passphrase");
  await click('.cipher-form button[type=submit]');
  await waitFor("!!document.querySelector('.entry-row') && !document.querySelector('.sidebar-lock').disabled");
  await evaluate(`window.passwordManager.copyText("synthetic exit clipboard fixture", ${JSON.stringify(services.getVaultStatus().sessionId)})`);
  const closingKey = vaultSession.requireKey();
  app.once("will-quit", () => {
    assert.equal(clipboardItems.length, 0);
    assert.equal(database.open, false);
    assert.throws(() => getDatabase(), error => error.code === "NOT_OPEN");
    console.log("PASS graceful exit awaits owned clipboard cleanup");
    console.log("PASS graceful exit closes the explicit storage connection");
  });
  window.once("closed", () => {
    assert.equal(services.getVaultStatus().isUnlocked, false);
    assert.deepEqual(closingKey, Buffer.alloc(32));
    console.log("PASS real window close destroys the key before application exit");
  });
  clearTimeout(timeout);
  window.destroy();
  app.quit();
} catch (error) {
  clearTimeout(timeout);
  console.error("FAIL desktop session integration", error);
  testExitCode = 1;
  app.quit();
}
}

// Do not hold Electron's ESM entry evaluation open while waiting for app.whenReady().
void run();
