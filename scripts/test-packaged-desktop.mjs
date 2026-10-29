import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { once } from "node:events";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { inspectDesktopPackage } from "./verify-desktop-package.mjs";
import { connectInspector } from "../tests/inspector-client.mjs";
import { probePackagedNative } from "../tests/packaged-native-probe.mjs";

const appDir = process.argv[2] === "--appdir";
assert.ok(appDir ? process.platform === "linux" && process.argv.length === 4 : process.argv.length === 2 || process.argv.length === 3, "Expected an optional unpacked application directory, or --appdir <directory> on Linux");
const project = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const defaultDirectory = process.platform === "darwin" ? `dist-desktop/macos/mac${process.arch === "x64" ? "" : `-${process.arch}`}/${project.productName}.app` :
  process.platform === "linux" ? `dist-desktop/linux/linux${process.arch === "x64" ? "" : `-${process.arch}`}-unpacked` : "dist-desktop/win-unpacked";
const source = inspectDesktopPackage(process.argv[appDir ? 3 : 2] ?? defaultDirectory);
const temporary = mkdtempSync(path.join(realpathSync(tmpdir()), "cipher-vault-packaged-"));
const application = path.join(temporary, process.platform === "darwin" ? `${source.productName}.app` : "application");
const profile = path.join(temporary, "profile 日本語");
const executable = path.join(application, appDir ? "AppRun" : process.platform === "darwin" ? `Contents/MacOS/${source.productName}` : process.platform === "win32" ? `${source.productName}.exe` : "cipher-vault");
const marker = "CIPHER_PACKAGE_SHUTDOWN_OK";
const electron = "globalThis.__cipherPackageElectron";
const master = "synthetic-packaged-legacy-master", next = "synthetic-packaged-v2-master", backup = "synthetic-packaged-backup-passphrase";
const title = "Packaged synthetic fixture", password = "synthetic-packaged-entry-password";
let child, inspector, closed, nativeProbe, output = "";
const diagnostics = () => output.replaceAll(temporary, "<temporary>").replaceAll(source.root, "<package>").slice(-3000);

async function evaluate(expression) {
  const response = await inspector.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.exception?.description ?? "Packaged evaluation failed");
  return response.result?.value;
}
const renderer = expression => evaluate(`${electron}.BrowserWindow.getAllWindows()[0].webContents.executeJavaScript(${JSON.stringify(expression)})`);
async function waitFor(expression) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Packaged app exited: " + diagnostics());
    try {
      const failure = await evaluate("globalThis.__cipherPackageFailure ?? null");
      if (failure) throw new Error("Packaged startup failed: " + String(failure).replaceAll(temporary, "<temporary>"));
      if (await evaluate(expression)) return;
    } catch (error) {
      // Only these read-only readiness polls may retry a startup context transition.
      // Mutation/IPC/TLS probes still fail on their first error.
      if (!(error instanceof Error) || !/^Inspector Runtime\.evaluate: (?:Cannot find context with specified id|Execution context was destroyed\.?)$/.test(error.message)) throw error;
    }
    await delay(50);
  }
  throw new Error("Packaged condition timed out: " + expression + "\n" + diagnostics());
}
const waitForRenderer = expression => waitFor(`${electron}.BrowserWindow.getAllWindows().length>0 && ${electron}.BrowserWindow.getAllWindows()[0].webContents.executeJavaScript(${JSON.stringify(expression)})`);
const click = selector => renderer(`document.querySelector(${JSON.stringify(selector)}).click()`);
const fill = (selector, value) => renderer(`(()=>{const input=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
const ipc = (method, ...args) => renderer(`(async()=>{const id=(await window.passwordManager.fetchVaultStatus()).sessionId;return window.passwordManager[${JSON.stringify(method)}](...${JSON.stringify(args)},id)})()`);

async function launch() {
  output = "";
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (["electron_run_as_node", "node_options", "node_path"].includes(key.toLowerCase())) delete environment[key];
  // Linux's native initialization is isolated even before the early debugger hook.
  if (process.platform === "linux") { environment.XDG_CONFIG_HOME = path.join(profile, "config"); environment.XDG_CACHE_HOME = path.join(profile, "cache"); }
  child = spawn(executable, ["--inspect-brk=127.0.0.1:0", `--user-data-dir=${profile}`], { cwd: temporary, env: environment, stdio: ["ignore", "pipe", "pipe"], windowsHide: true, detached: process.platform !== "win32" });
  closed = once(child, "close"); closed.catch(() => {});
  child.stdout.on("data", data => { output += data; }); child.stderr.on("data", data => { output += data; });
  let endpoint;
  for (let attempt = 0; attempt < 200; attempt++) {
    endpoint = output.match(/Debugger listening on (ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+)/i)?.[1];
    if (endpoint) break;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Packaged debugger startup failed (code=${child.exitCode}, signal=${child.signalCode}): ` + diagnostics());
    await delay(50);
  }
  assert.ok(endpoint, "Packaged inspector was not available"); inspector = await connectInspector(endpoint);
  await inspector.send("Debugger.enable"); const paused = inspector.event("Debugger.paused"); paused.catch(() => {});
  await inspector.send("Runtime.runIfWaitingForDebugger"); const frame = (await paused).callFrames[0].callFrameId;
  const configured = await inspector.send("Debugger.evaluateOnCallFrame", { callFrameId: frame, returnByValue: true, expression: `(()=>{
    const e=process.getBuiltinModule('module').createRequire(process.execPath)('electron');
    if(e.app.isReady())throw new Error('Profile must be isolated before readiness');
    e.app.setPath('userData',${JSON.stringify(profile)});
    e.app.setPath('sessionData',${JSON.stringify(profile)});
    if(e.app.getPath('userData')!==${JSON.stringify(profile)})throw new Error('Unexpected profile');
    globalThis.__cipherPackageElectron=e;
    e.dialog.showErrorBox=(_title,message)=>{globalThis.__cipherPackageFailure=message;};
    e.powerMonitor.getSystemIdleState=()=> 'active';
    e.app.on('browser-window-created',(_event,w)=>{w.hide();w.webContents.setBackgroundThrottling(false);});
    return true;
  })()` });
  assert.equal(configured.exceptionDetails, undefined, configured.exceptionDetails?.exception?.description);
  assert.equal(configured.result?.value, true);
  await inspector.send("Debugger.resume"); await inspector.send("Debugger.disable");
  await waitForRenderer("!!document.querySelector('.cipher-form input[type=password]')");
  assert.equal(await evaluate(`${electron}.app.isPackaged`), true);
  assert.equal(await evaluate(`${electron}.app.commandLine.hasSwitch('no-sandbox') || ${electron}.app.commandLine.hasSwitch('disable-setuid-sandbox')`), false, "Package must keep Chromium sandboxing enabled");
  assert.equal(await evaluate(`${electron}.app.getPath('userData')`), profile);
  assert.equal(await evaluate(`${electron}.app.getPath('sessionData')`), profile);
  assert.ok((await evaluate(`${electron}.app.getAppPath()`)).startsWith(application + path.sep));
  assert.deepEqual(await evaluate(`(()=>{const p=${electron}.BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();return {sandbox:p.sandbox,contextIsolation:p.contextIsolation,nodeIntegration:p.nodeIntegration}})()`), { sandbox: true, contextIsolation: true, nodeIntegration: false });
  assert.equal(await renderer("typeof require==='undefined' && typeof process==='undefined' && Object.isFrozen(window.passwordManager)"), true);
  assert.equal(await renderer("document.fonts.load('500 14px \"Noto Sans JP\"','接続の管理').then(fonts=>fonts.length>0&&fonts.every(font=>font.status==='loaded'))"), true, "Packaged Japanese font must load from the copied application");
  assert.equal(await renderer("window.passwordManager.getUpdateState().then(state=>state.currentVersion)"), source.version);
}

async function unlock(value) {
  await fill('.cipher-form input[type=password]', value); await click('.cipher-form button[type=submit]');
  await waitForRenderer("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
}
async function stop() {
  const capture = await evaluate(`(()=>{
    const app=${electron}.app,req=process.getBuiltinModule('module').createRequire(app.getAppPath()+'/package.json');
    const session=req(app.getAppPath()+'/apps/api/dist/apps/api/src/services/vault-session.js').vaultSession;
    const store=req(app.getAppPath()+'/apps/api/dist/apps/api/src/db/vault-context.js').getV2Vault().store,key=session.requireKey();
    app.once('will-quit',()=>{if(!store.closed || key.some(value=>value!==0))throw new Error('Packaged shutdown did not clear its vault');console.log(${JSON.stringify(marker)});});
    return session.getState().sessionId;
  })()`);
  assert.equal(capture, (await ipc("fetchVaultStatus")).sessionId);
  await evaluate(`setTimeout(()=>${electron}.app.quit(),50); true`); inspector.close(); inspector = undefined;
  const timer = setTimeout(() => child.kill(), 15000);
  try { const [code, signal] = await closed; assert.equal(code, 0, diagnostics()); assert.equal(signal, null); assert.ok(output.includes(marker), "Packaged shutdown was not verified"); }
  finally { clearTimeout(timer); }
  child = undefined;
}

try {
  mkdirSync(profile);
  cpSync(source.root, application, { recursive: true, verbatimSymlinks: true });
  const copied = inspectDesktopPackage(application); assert.ok(existsSync(executable));
  await launch(); assert.equal((await ipc("fetchVaultStatus")).isConfigured, false);
  nativeProbe = await probePackagedNative(evaluate, electron, copied.nativeHelper);
  console.log("PASS packaged native issuance, real peer identity, mutual TLS and lock outside checkout");
  console.log(nativeProbe.protectedKeys ? "PASS real OS provider protects private credentials before persistence" : "PASS unavailable OS protection refuses credential persistence without plaintext fallback");
  await unlock(master);
  await click('.sidebar-add'); await waitForRenderer("!!document.querySelector('.editor-fields')");
  await fill('.editor-fields .editor-field:nth-child(1) input', title);
  await fill('.editor-fields .editor-field:nth-child(2) input', "synthetic-packaged-user");
  await fill('.editor-fields input[type=password]', password); await click('.entry-editor button[type=submit]');
  await waitForRenderer("!!document.querySelector('.entry-view-fields')");
  const entry = (await ipc("fetchEntries")).items[0]; assert.equal(entry.serviceName, title);
  await renderer("[...document.querySelectorAll('.app-menu-trigger')].find(b=>b.textContent==='ツール').click()");
  await waitForRenderer("[...document.querySelectorAll('.app-menu-item')].some(b=>b.textContent==='保管庫の管理'&&!b.disabled)");
  await renderer("[...document.querySelectorAll('.app-menu-item')].find(b=>b.textContent==='保管庫の管理').click()");
  await waitForRenderer("!!document.querySelector('.vault-maintenance-dialog[open] form')");
  for (const [index, value] of [master, next, next, backup, backup].entries()) await fill(`.maintenance-fields label:nth-child(${index + 1}) input`, value);
  await click('.vault-maintenance-dialog button[type=submit]');
  await waitForRenderer("document.querySelector('.vault-tool-message')?.textContent.includes('切り替えを完了')");
  await click('.vault-maintenance-dialog .vault-tool-heading button');
  await waitForRenderer("!document.querySelector('.vault-maintenance-dialog[open]')"); await unlock(next);
  assert.equal((await ipc("fetchEntry", entry.id)).password, password); assert.equal((await ipc("auditVault")).total, 1);
  assert.equal(JSON.parse((await ipc("exportBackup", { passphrase: backup })).content).version, 1);
  assert.ok(existsSync(path.join(profile, "data/vault-current.json")));
  await stop(); console.log("PASS isolated packaged sandbox, SQLite, entry creation, v2 migration, backup and key cleanup");
  await launch(); const restarted = await ipc("fetchVaultStatus"); assert.equal(restarted.isUnlocked, false); assert.equal(restarted.maintenance.format, "v2");
  await nativeProbe.afterRestart();
  if (nativeProbe.protectedKeys) console.log("PASS credentials restored after actual application restart authenticate the same registration and revoke");
  await unlock(next); assert.equal((await ipc("fetchEntry", entry.id)).password, password);
  await stop(); console.log("PASS packaged restart opens the same v2 vault locked and unlocks retained data");
} finally {
  inspector?.close();
  if (child && child.exitCode === null && child.signalCode === null) {
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
    else { try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; } }
    await closed.catch(() => {});
  }
  nativeProbe?.dispose();
  assert.equal(path.dirname(temporary), realpathSync(tmpdir())); assert.ok(path.basename(temporary).startsWith("cipher-vault-packaged-"));
  rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
