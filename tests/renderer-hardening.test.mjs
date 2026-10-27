import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import vm from "node:vm";
import { rendererContentSecurityPolicy, localDevelopmentUrl } from "../packages/shared/dist/renderer-policy.js";
import { installRendererSessionSecurity, isAllowedRendererResource } from "../apps/electron/dist/apps/electron/src/renderer-session.js";

test("sandbox preload runs with only Electron require, exposes explicit methods and strips event capabilities", async () => {
  const events = new EventEmitter(), calls = []; let api;
  const electron = { contextBridge: { exposeInMainWorld(name, value) { assert.equal(name, "passwordManager"); api = value; } },
    ipcRenderer: { invoke: (...args) => { calls.push(args); return Promise.resolve({ ok: true }); },
      on: (...args) => events.on(...args), removeListener: (...args) => events.removeListener(...args) } };
  const source = readFileSync(new URL("../apps/electron/dist/apps/electron/src/preload.cjs", import.meta.url), "utf8");
  vm.runInNewContext(source, { require(name) { assert.equal(name, "electron"); return electron; } });
  assert.deepEqual(Object.keys(api).sort(), ["auditVault", "checkForUpdates", "copyText", "createEntry", "deleteEntry", "downloadUpdate", "exportBackup", "fetchEntries", "fetchEntry", "fetchVaultStatus", "generatePassword", "getUpdateState", "installUpdate", "lockVault", "onUpdateState", "onVaultState", "openReleasePage", "recordVaultActivity", "resetVault", "restoreBackup", "setupVault", "unlockVault", "updateEntry"].sort());
  await api.setupVault({ masterPassword: "synthetic" }, "epoch");
  await api.updateEntry("entry", { serviceName: "synthetic" }, "epoch");
  await api.exportBackup({ passphrase: "synthetic" }, "epoch");
  assert.deepEqual(calls.map((args) => args[0]), ["vault:setup", "entries:update", "backup:export"]);
  assert.deepEqual(calls[1].slice(1), ["epoch", "entry", { serviceName: "synthetic" }]);
  for (const [method, channel] of [["onVaultState", "vault:state"], ["onUpdateState", "updates:state"]]) {
    let received;
    const unsubscribe = api[method]((...args) => { received = args; });
    const state = { status: "synthetic" };
    events.emit(channel, { sender: "privileged capability" }, state);
    assert.deepEqual(received, [state]);
    unsubscribe(); assert.equal(events.listenerCount(channel), 0);
  }
});

test("production CSP blocks inline scripts and external connections, keeping development exceptions local", () => {
  const directives = (policy) => Object.fromEntries(policy.split("; ").map((part) => { const [name, ...values] = part.split(" "); return [name, values]; }));
  for (const mode of ["web", "desktop"]) {
    const parsed = directives(rendererContentSecurityPolicy(mode));
    assert.deepEqual(parsed["script-src"], ["'self'"]);
    for (const name of ["object-src", "frame-src", "base-uri", "form-action", "worker-src"]) assert.deepEqual(parsed[name], ["'none'"]);
    assert.deepEqual(parsed["font-src"], ["'self'"]);
    assert.deepEqual(parsed["connect-src"], [mode === "web" ? "'self'" : "'none'"]);
    assert.ok(!rendererContentSecurityPolicy(mode).includes("unsafe-eval"));
  }
  const dev = directives(rendererContentSecurityPolicy("development", "http://127.0.0.1:5173/"));
  assert.ok(dev["script-src"].includes("'unsafe-inline'"));
  assert.ok(dev["connect-src"].includes("ws://127.0.0.1:5173"));
  for (const url of ["https://remote.invalid/", "file:///app/index.html", "http://user@localhost:5173", "data:text/html,test"]) assert.throws(() => localDevelopmentUrl(url));
});

test("renderer resource policy confines file loads to real assets and development to one origin", () => {
  const root = mkdtempSync(path.join(tmpdir(), "cipher-vault-renderer-policy-"));
  try {
    const web = path.join(root, "web"); mkdirSync(web);
    for (const file of ["index.html", "asset.js", "font.ttf", "icon.png"]) writeFileSync(path.join(web, file), "fixture");
    writeFileSync(path.join(root, "outside.js"), "must not load");
    const linked = path.join(root, "linked"); mkdirSync(linked);
    writeFileSync(path.join(linked, "escape.js"), "must not load through a link");
    symlinkSync(linked, path.join(web, "alias"), process.platform === "win32" ? "junction" : "dir");
    const document = pathToFileURL(path.join(web, "index.html")).href;
    assert.equal(isAllowedRendererResource(pathToFileURL(path.join(web, "asset.js")).href, "script", document, web), true);
    assert.equal(isAllowedRendererResource(pathToFileURL(path.join(web, "font.ttf")).href, "font", document, web), true);
    assert.equal(isAllowedRendererResource(pathToFileURL(path.join(web, "alias", "escape.js")).href, "script", document, web), false);
    for (const [url, type] of [[pathToFileURL(path.join(root, "outside.js")).href, "script"], [document, "xhr"],
      ["file://remote.invalid/share/asset.js", "script"], ["https://remote.invalid/", "image"], ["data:text/javascript,test", "script"]]) {
      assert.equal(isAllowedRendererResource(url, type, document, web), false);
    }
    const dev = "http://127.0.0.1:5173/";
    assert.equal(isAllowedRendererResource(dev + "src/main.tsx", "script", dev, web), true);
    assert.equal(isAllowedRendererResource("ws://127.0.0.1:5173/", "webSocket", dev, web), true);
    assert.equal(isAllowedRendererResource("ws://127.0.0.1:5174/", "webSocket", dev, web), false);
    assert.equal(isAllowedRendererResource(document, "script", dev, web), false);
  } finally {
    const relative = path.relative(tmpdir(), root);
    assert.ok(relative.startsWith("cipher-vault-renderer-policy-") && !relative.includes(path.sep));
    rmSync(root, { recursive: true, force: true });
  }
});

test("session policy denies permissions/devices, fences renderer requests and preserves updater traffic and other headers", () => {
  const hooks = {};
  const session = {
    setPermissionCheckHandler: (handler) => { hooks.check = handler; },
    setPermissionRequestHandler: (handler) => { hooks.request = handler; },
    setDevicePermissionHandler: (handler) => { hooks.device = handler; },
    webRequest: { onBeforeRequest: (_filter, handler) => { hooks.before = handler; }, onHeadersReceived: (_filter, handler) => { hooks.headers = handler; } }
  };
  installRendererSessionSecurity(session, () => 7, () => "http://127.0.0.1:5173/", "/unused");
  for (const permission of ["media", "geolocation", "notifications", "clipboard-read", "fileSystem", "local-fonts", "unknown"]) {
    assert.equal(hooks.check(null, permission, "", {}), false);
    let granted; hooks.request({}, permission, (value) => { granted = value; }, {}); assert.equal(granted, false);
  }
  assert.equal(hooks.device({}), false);
  let answer;
  hooks.before({ webContentsId: 7, url: "http://127.0.0.1:5173/asset.js", resourceType: "script" }, (value) => { answer = value; });
  assert.equal(answer.cancel, false);
  hooks.before({ webContentsId: 8, url: "http://127.0.0.1:5173/asset.js", resourceType: "script" }, (value) => { answer = value; });
  assert.equal(answer.cancel, true);
  hooks.before({ webContentsId: 0, url: "https://updater.invalid/", resourceType: "xhr" }, (value) => { answer = value; });
  assert.deepEqual(answer, {});
  hooks.headers({ webContentsId: 7, resourceType: "mainFrame", responseHeaders: { "content-security-policy": ["old"], Other: ["keep"] } }, (value) => { answer = value; });
  assert.deepEqual(answer.responseHeaders.Other, ["keep"]);
  assert.equal(answer.responseHeaders["content-security-policy"], undefined);
  assert.ok(answer.responseHeaders["Content-Security-Policy"][0].includes("frame-ancestors 'none'"));
});

test("local fonts retain pinned source hashes, original font signatures and required licenses", () => {
  const fontRoot = new URL("../apps/web/public/fonts/", import.meta.url);
  const manifest = JSON.parse(readFileSync(new URL("sources.json", fontRoot), "utf8"));
  assert.match(manifest.revision, /^[0-9a-f]{40}$/);
  for (const file of manifest.files) {
    assert.ok(file.source.startsWith(`https://raw.githubusercontent.com/google/fonts/${manifest.revision}/`));
    const bytes = readFileSync(new URL(file.file, fontRoot));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), file.sha256);
    if (file.file.endsWith(".ttf")) assert.equal(bytes.subarray(0, 4).toString("hex"), "00010000");
    else assert.ok(bytes.toString("utf8").includes("SIL OPEN FONT LICENSE"));
  }
  const html = readFileSync(new URL("../apps/web/dist/index.html", import.meta.url), "utf8");
  assert.ok(html.includes('http-equiv="Content-Security-Policy"'));
  assert.ok(!html.includes("__CIPHER_VAULT_CSP__") && !html.includes("fonts.googleapis.com"));
});
