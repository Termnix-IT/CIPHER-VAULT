import { app, BrowserWindow } from "electron";
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";

process.on("uncaughtException", (error) => { console.error("FAIL web policy integration", error); app.exit(1); });
process.on("unhandledRejection", (error) => { console.error("FAIL web policy integration", error); app.exit(1); });
const root = process.env.CIPHER_VAULT_TEST_ROOT;
assert.ok(root);
const relative = path.relative(tmpdir(), root);
assert.ok(relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
const profile = path.join(root, "profile"); mkdirSync(profile);
app.setPath("userData", profile);
process.env.PASSWORD_MANAGER_DATA_DIR = path.join(profile, "data");
process.env.PASSWORD_MANAGER_WEB_DIST = path.resolve("apps/web/dist");
app.on("window-all-closed", () => {});
const watchdog = setTimeout(() => { console.error("FAIL web policy timed out"); app.exit(1); }, 60000);

async function run() {
  let server, window, storage;
  try {
    await app.whenReady();
    storage = await import("../apps/api/dist/apps/api/src/db/database.js");
    storage.openDatabase();
    assert.equal(path.resolve(storage.getDatabasePath()), path.join(profile, "data", "password-manager.db"));
    const { router } = await import("../apps/api/dist/apps/api/src/routes/router.js");
    server = createServer((request, response) => { void router(request, response); });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const response = await fetch(origin);
    assert.ok(response.headers.get("content-security-policy").includes("frame-ancestors 'none'"));
    window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, partition: "cipher-vault-web-policy" } });
    window.webContents.session.setPermissionCheckHandler(() => false);
    window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    window.webContents.setBackgroundThrottling(false);
    const evaluate = (source) => window.webContents.executeJavaScript(source);
    const waitFor = async (source) => {
      for (let i = 0; i < 200; i++) { if (await evaluate(source)) return; await delay(50); }
      throw new Error(`web UI condition failed: ${source}`);
    };
    const fill = async (selector, value) => evaluate(`(() => { const input=document.querySelector(${JSON.stringify(selector)}); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)}); input.dispatchEvent(new Event('input',{bubbles:true})); })()`);
    const click = async (selector) => evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
    await window.loadURL(origin);
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    assert.equal(await evaluate("typeof window.passwordManager === 'undefined' && typeof require === 'undefined'"), true);
    await fill('.cipher-form input[type=password]', "synthetic-web-policy-passphrase");
    await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.cipher-dashboard') && !document.querySelector('.sidebar-lock').disabled");
    await click('.sidebar-add');
    await waitFor("!!document.querySelector('.editor-fields')");
    const maliciousTitle = '<img src=x onerror="window.__unsafeEntry=true">';
    await fill('.editor-fields .editor-field:nth-child(1) input', maliciousTitle);
    await fill('.editor-fields .editor-field:nth-child(2) input', "fixture-user");
    await fill('.editor-fields input[type=password]', "synthetic-entry-password");
    await click('.entry-editor button[type=submit]');
    await waitFor("!!document.querySelector('.entry-view-fields')");
    assert.equal(await evaluate("document.querySelector('.inspector-title').textContent"), maliciousTitle);
    assert.equal(await evaluate("window.__unsafeEntry === undefined && document.querySelector('[onerror]') === null"), true);
    assert.equal(await evaluate("document.fonts.load('500 16px \"JetBrains Mono\"').then(fonts => fonts.length > 0 && fonts.every(x => x.status === 'loaded'))"), true);
    await evaluate("window.__violations=[]; document.addEventListener('securitypolicyviolation',e=>window.__violations.push(e.effectiveDirective)); const script=document.createElement('script'); script.textContent='window.__inlineExecuted=true'; document.head.append(script); script.remove();");
    await delay(50);
    assert.equal(await evaluate("window.__inlineExecuted === undefined && window.__violations.includes('script-src-elem')"), true);
    assert.equal(await evaluate("fetch('/vault/status').then(response=>response.ok)"), true);
    assert.equal(await evaluate("fetch('http://127.0.0.1:1/blocked').then(()=>false,()=>true)"), true);
    await waitFor("window.__violations.includes('connect-src')");
    console.log("PASS production HTTP CSP permits the real Web vault flow and local fonts, blocks inline scripts/external fetch and renders hostile entry text safely");
    clearTimeout(watchdog);
    server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); server = undefined;
    storage.closeDatabase(); storage = undefined;
    window.destroy(); app.quit();
  } catch (error) {
    clearTimeout(watchdog);
    console.error("FAIL web policy integration", error);
    server?.closeAllConnections(); server?.close();
    storage?.closeDatabase();
    app.exit(1);
  }
}
void run();
