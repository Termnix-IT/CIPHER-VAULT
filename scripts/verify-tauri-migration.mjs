// Checks the move from the Electron app to the Tauri app on this machine, with synthetic data only.
// Both apps are built under a test product name, so they use %APPDATA%\CIPHER VAULT Migration Test
// and never the real vault, shortcuts or uninstall entries.
//
// 1. The Electron setup is installed into a temporary folder, and the installed Electron app sets up
//    a vault with one entry through its screen API. Its in-app update must send users to the
//    releases page, as the last Electron release does.
// 2. While the Electron app runs, the Tauri app refuses to open the shared folder.
// 3. The Tauri setup, run silently while the Electron app still runs, removes the Electron app
//    with its own uninstaller and keeps every file of the vault.
// 4. The installed Tauri app opens that vault with the same password and finds the entry, and it
//    may update itself. The portable exe opens the same vault and may not.
// Everything installed or written is removed at the end.
// Usage: node scripts/verify-tauri-migration.mjs (after npm run build:desktop and npm run build:web:tauri)
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connectInspector } from "../tests/inspector-client.mjs";
import { connect, powershell, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DESKTOP = path.join(ROOT, "apps", "desktop");
const TARGET = path.join(ROOT, "target", "migration-check");
const TAURI_CLI = path.join(ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");
const ELECTRON_BUILDER = path.join(ROOT, "node_modules", "electron-builder", "cli.js");
const PRODUCT = "CIPHER VAULT Migration Test";
const ELECTRON_ID = "io.github.termnix-it.ciphervault.migrationtest.electron";
// The Electron setup keeps a copy of itself in %LOCALAPPDATA%\<package name>-updater, so the test
// package has its own name and never replaces the copy the installed app updates from.
const ELECTRON_PACKAGE = "cipher-vault-migration-test";
const TAURI_ID = "io.github.termnix-it.ciphervault.migrationtest";
const PUBLISHER = "Termnix-IT";
const PASSWORD = "synthetic-migration-check-password";
const ENTRY_PASSWORD = "synthetic-migration-entry-password";
const PORT = 9371;
const UNINSTALL = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const vaultFolder = path.join(process.env.APPDATA, PRODUCT);
const dataFolder = path.join(vaultFolder, "data");
assert.ok(PRODUCT.endsWith("Test") && path.basename(vaultFolder) === PRODUCT, "only the test product's folder is ever written");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`${path.basename(command)} ${args.slice(0, 3).join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  return result;
}
const quote = (text) => text.replaceAll("'", "''");
/** The uninstall entries whose uninstaller has the given file name. */
const uninstallEntries = (uninstaller) => powershell(`@(Get-ChildItem '${UNINSTALL}' | Where-Object { (Get-ItemProperty $_.PSPath).UninstallString -like '*\\${quote(uninstaller)}*' }).Count`);
const processesFrom = (folder) => powershell(`@(Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith('${quote(folder)}\\') }).Count`);

if (existsSync(vaultFolder)) throw new Error(`${vaultFolder} already exists. Remove what an earlier run left before checking again.`);
const base = mkdtempSync(path.join(tmpdir(), "cipher-vault-migration-"));
const electronInstall = path.join(base, "electron");
const tauriInstall = path.join(base, "tauri");
const result = {};
let electron = null;
/** Tauri processes started by the check, stopped at the end however the check ends. */
const tauriApps = [];

/** Starts the installed Electron app with its inspector, which only test runs use. */
async function startElectron() {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (["electron_run_as_node", "node_options", "node_path"].includes(key.toLowerCase())) delete environment[key];
  const child = spawn(path.join(electronInstall, `${PRODUCT}.exe`), ["--inspect=127.0.0.1:0"], { env: environment, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (data) => { output += data; });
  child.stderr.on("data", (data) => { output += data; });
  const endpoint = await until("the Electron inspector", () => output.match(/Debugger listening on (ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+)/i)?.[1], 60000);
  const inspector = await connectInspector(endpoint);
  const evaluate = async (expression) => {
    const response = await inspector.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.exception?.description ?? "Electron evaluation failed");
    return response.result?.value;
  };
  const app = "process.getBuiltinModule('module').createRequire(process.execPath)('electron')";
  const renderer = (expression) => evaluate(`${app}.BrowserWindow.getAllWindows()[0].webContents.executeJavaScript(${JSON.stringify(expression)})`);
  await until("the Electron screen", async () => {
    try { return await evaluate(`${app}.BrowserWindow.getAllWindows().length > 0`) && await renderer("!!window.passwordManager"); } catch { return false; }
  }, 60000);
  return { child, evaluate, renderer, app, close: () => inspector.close() };
}
async function quitElectron() {
  await electron.evaluate(`setTimeout(() => ${electron.app}.app.quit(), 50); true`);
  electron.close();
  await until("the Electron app to exit", () => electron.child.exitCode !== null, 30000);
  electron = null;
}

try {
  // ---- The two test builds.
  const electronOutput = path.join(base, "electron-dist");
  run(process.execPath, [ELECTRON_BUILDER, "--win", "nsis", "--publish", "never",
    `-c.productName=${PRODUCT}`, `-c.extraMetadata.productName=${PRODUCT}`, `-c.extraMetadata.name=${ELECTRON_PACKAGE}`, `-c.appId=${ELECTRON_ID}`, `-c.directories.output=${electronOutput}`], { cwd: ROOT });
  const electronSetup = path.join(electronOutput, readdirSync(electronOutput).find((file) => file.endsWith("-setup.exe")));
  const overlay = path.join(base, "tauri.migration-check.json");
  writeFileSync(overlay, JSON.stringify({ productName: PRODUCT, identifier: TAURI_ID }));
  run(process.execPath, [TAURI_CLI, "build", "--debug", "--features", "e2e", "--bundles", "nsis", "--config", overlay], { cwd: DESKTOP, env: { ...process.env, CARGO_TARGET_DIR: TARGET } });
  const bundle = path.join(TARGET, "debug", "bundle", "nsis");
  const tauriSetup = path.join(bundle, readdirSync(bundle).find((file) => file.startsWith(`${PRODUCT}_`) && file.endsWith("-setup.exe")));
  const portable = path.join(TARGET, "debug", "cipher-vault.exe");

  // ---- 1. The Electron app, installed, sets up the vault.
  run(electronSetup, ["/S", "/currentuser", `/D=${electronInstall}`]);
  assert.equal(uninstallEntries(`Uninstall ${PRODUCT}.exe`), "1", "the Electron app is registered");
  electron = await startElectron();
  assert.equal(await electron.evaluate(`${electron.app}.app.getPath("userData")`), vaultFolder);
  let { sessionId } = await electron.renderer("window.passwordManager.fetchVaultStatus()");
  await electron.renderer(`window.passwordManager.setupVault({ masterPassword: ${JSON.stringify(PASSWORD)} }, ${JSON.stringify(sessionId)})`);
  ({ sessionId } = await electron.renderer("window.passwordManager.fetchVaultStatus()"));
  const created = await electron.renderer(`window.passwordManager.createEntry({ serviceName: "Migration check", loginId: "synthetic-user", password: ${JSON.stringify(ENTRY_PASSWORD)} }, ${JSON.stringify(sessionId)})`);
  result.electronUpdates = (await electron.renderer("window.passwordManager.getUpdateState()")).status;
  assert.equal(result.electronUpdates, "unsupported", "the last Electron release sends users to the releases page");
  await quitElectron();
  const vaultFiles = readdirSync(dataFolder).sort();
  result.vaultFiles = vaultFiles.length;
  assert.ok(vaultFiles.length > 0);

  // ---- 2. The Tauri app does not open the folder while the Electron app runs.
  electron = await startElectron();
  const refused = spawnSync(portable, [], { env: { ...process.env, CIPHER_VAULT_DATA_DIR: undefined }, encoding: "utf8", timeout: 30000 });
  result.whileElectronRuns = { exitCode: refused.status, reported: refused.stdout.includes("e2e-event electron-running"), message: refused.stderr.includes(`Electron版の${PRODUCT}が起動しています`) };
  assert.deepEqual(result.whileElectronRuns, { exitCode: 2, reported: true, message: true });

  // ---- 3. The Tauri setup removes the running Electron app and keeps the vault.
  run(tauriSetup, ["/S", "/NS", `/D=${tauriInstall}`], { timeout: 180000 });
  await until("the Electron app to be closed", () => electron.child.exitCode !== null, 30000);
  electron.close();
  electron = null;
  result.afterSetup = {
    electronEntries: uninstallEntries(`Uninstall ${PRODUCT}.exe`),
    electronFolder: existsSync(electronInstall),
    tauriEntries: powershell(`@(Get-ChildItem '${UNINSTALL}' | Where-Object { $_.PSChildName -eq '${quote(PRODUCT)}' }).Count`),
    vaultFiles: readdirSync(dataFolder).filter((file) => vaultFiles.includes(file)).length
  };
  assert.deepEqual(result.afterSetup, { electronEntries: "0", electronFolder: false, tauriEntries: "1", vaultFiles: vaultFiles.length });

  // ---- 4. The installed app and the portable exe open the same vault.
  const openWith = async (exe) => {
    const started = startE2eProcess(exe, PORT, { CIPHER_VAULT_DATA_DIR: undefined, CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT), CIPHER_VAULT_E2E_PROFILE: path.join(base, "profile") });
    tauriApps.push(started);
    const page = await connect(PORT);
    started.page = page;
    await until("the screen", () => page.evaluate(`document.readyState === "complete" && !!window.passwordManager`), 60000);
    const status = await page.evaluate("window.passwordManager.fetchVaultStatus()");
    const opened = await page.evaluate(`window.passwordManager.unlockVault({ masterPassword: ${JSON.stringify(PASSWORD)} }, ${JSON.stringify(status.sessionId)})`);
    const entry = await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(created.id)}, ${JSON.stringify(opened.sessionId)})`);
    const updates = await page.evaluate("window.passwordManager.getUpdateState()");
    page.close();
    started.page = null;
    powershell(`[void](Get-Process -Id ${started.child.pid}).CloseMainWindow()`);
    await until("the app to exit", () => started.child.exitCode !== null, 30000);
    return {
      configured: status.isConfigured, unlocked: opened.isUnlocked, entry: entry.serviceName, password: entry.password === ENTRY_PASSWORD,
      updates: updates.status, support: started.events.find((event) => event.startsWith("update-support "))
    };
  };
  const installed = path.join(tauriInstall, readdirSync(tauriInstall).find((file) => file.endsWith(".exe") && file !== "uninstall.exe"));
  result.installed = await openWith(installed);
  assert.deepEqual(result.installed, { configured: true, unlocked: true, entry: "Migration check", password: true, updates: "idle", support: "update-support true" });
  result.portable = await openWith(portable);
  assert.deepEqual(result.portable, { ...result.installed, updates: "unsupported", support: "update-support false" });
  console.log(JSON.stringify(result, null, 2));
} finally {
  if (electron) { try { electron.child.kill(); electron.close(); } catch { /* already gone */ } }
  for (const started of tauriApps) {
    try { started.page?.close(); } catch { /* already closed */ }
    if (started.child.exitCode === null) started.child.kill();
  }
  await until("the Tauri apps to exit", () => tauriApps.every((started) => started.child.exitCode !== null || started.child.signalCode !== null), 30000).catch(() => undefined);
  for (const folder of [electronInstall, tauriInstall]) {
    try { powershell(`Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith('${quote(folder)}\\') } | Stop-Process -Force`); } catch { /* nothing runs */ }
  }
  // Both uninstallers copy themselves elsewhere and return early, so the folders are watched.
  const electronUninstaller = path.join(electronInstall, `Uninstall ${PRODUCT}.exe`);
  if (existsSync(electronUninstaller)) spawnSync(electronUninstaller, ["/currentuser", "/S"], { timeout: 60000 });
  if (existsSync(path.join(tauriInstall, "uninstall.exe"))) spawnSync(path.join(tauriInstall, "uninstall.exe"), ["/S"], { timeout: 60000 });
  await until("the uninstallers", () => !existsSync(electronUninstaller) && !existsSync(path.join(tauriInstall, "uninstall.exe")), 60000).catch(() => undefined);
  powershell(`$key = 'HKCU:\\Software\\${PUBLISHER}'; Remove-Item -LiteralPath "$key\\${quote(PRODUCT)}" -Recurse -ErrorAction SilentlyContinue
    if ((Test-Path $key) -and (Get-Item $key).SubKeyCount -eq 0 -and (Get-Item $key).ValueCount -eq 0) { Remove-Item -LiteralPath $key }`);
  const leftovers = {
    electronEntries: uninstallEntries(`Uninstall ${PRODUCT}.exe`),
    tauriEntries: powershell(`@(Get-ChildItem '${UNINSTALL}' | Where-Object { $_.PSChildName -eq '${quote(PRODUCT)}' }).Count`),
    processes: processesFrom(base)
  };
  await sleep(500);
  rmSync(vaultFolder, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
  rmSync(path.join(process.env.LOCALAPPDATA, TAURI_ID), { recursive: true, force: true });
  rmSync(path.join(process.env.LOCALAPPDATA, `${ELECTRON_PACKAGE}-updater`), { recursive: true, force: true });
  rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
  if (Object.values(leftovers).some((count) => count !== "0") || existsSync(vaultFolder)) {
    console.error(`The test install left something behind: ${JSON.stringify({ ...leftovers, vaultFolder: existsSync(vaultFolder) })}`);
    process.exitCode = 1;
  }
}
