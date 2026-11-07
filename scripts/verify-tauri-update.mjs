// Checks manual updates of the Tauri app with two real setups. It builds the e2e app twice, as
// versions 0.0.1 and 0.0.2 under a test name and identifier, so it never meets a real install, and
// signs them with a key made for this run only. Version 0.0.1 is installed into a temporary folder
// and a vault with one synthetic entry is set up. A local server then offers the same version
// (nothing to do), the new version with the old version's signature and the new version with its own
// signature but one byte added (both refused after the download), and the new version as signed. Declining the unsaved-edits question keeps the app as it is; accepting
// it locks the vault, runs the installer and exits. The installer must restart the app as 0.0.2,
// and the same password must open the same entry. The test install is removed at the end.
// Usage: node scripts/verify-tauri-update.mjs (after npm run build:web)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect, powershell, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DESKTOP = path.join(ROOT, "apps", "desktop");
// Its own Cargo folder, so the signed test builds never replace the builds the other checks use.
const TARGET = path.join(ROOT, "target", "update-check");
const PRODUCT = "CIPHER VAULT Update Test";
const IDENTIFIER = "io.github.termnix-it.ciphervault.updatetest";
// The publisher in tauri.conf.json, under which the installer keeps its settings.
const PUBLISHER = "Termnix-IT";
const OLD_VERSION = "0.0.1", NEW_VERSION = "0.0.2";
const PASSWORD = "synthetic-update-check-password";
const KEY_PASSWORD = "synthetic-update-signing-password";
const FAILED = "更新処理に失敗しました。通信環境と公開済みの更新ファイルを確認して、再試行してください。";
const NOTES = "Synthetic release notes for the update check.";
const PORT = 9361;
const settle = (page, expression) => page.evaluate(`Promise.resolve().then(() => ${expression}).then((value) => ({ value }), (error) => ({ error: String(error?.message ?? error) }))`);
const api = (page, call) => page.evaluate(`window.passwordManager.${call}`);
const updateState = (page) => api(page, "getUpdateState()");

const TAURI_CLI = path.join(ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  return result;
}

const base = mkdtempSync(path.join(tmpdir(), "cipher-vault-update-"));
const install = path.join(base, "install");
const settings = {
  CIPHER_VAULT_DATA_DIR: path.join(base, "data"),
  CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT),
  CIPHER_VAULT_E2E_PROFILE: path.join(base, "profile"),
  CIPHER_VAULT_E2E_DOWNLOADS: path.join(base, "downloads")
};
mkdirSync(settings.CIPHER_VAULT_DATA_DIR);
mkdirSync(settings.CIPHER_VAULT_E2E_DOWNLOADS);
// Passed as arguments only: the installer restarts the app with its arguments, not its environment.
const argumentsFor = (extra = {}) => Object.entries({ ...settings, ...extra }).map(([name, value]) => `--e2e-env=${name}=${value}`);
const result = {};

// ---- The local release server. Its answer is switched between the cases below.
let offer = null;
const served = [];
const server = createServer((request, response) => {
  served.push(request.url);
  if (request.url === "/latest.json" && offer) {
    response.writeHead(200, { "content-type": "application/json" });
    return response.end(JSON.stringify(offer.manifest));
  }
  if (offer && request.url === servedPath(offer.setup)) {
    // GitHub sends the length, and the app needs it to show progress.
    const body = offer.tamper ? Buffer.concat([readFileSync(offer.setup), Buffer.from([0])]) : readFileSync(offer.setup);
    response.writeHead(200, { "content-type": "application/octet-stream", "content-length": body.length });
    return response.end(body);
  }
  response.writeHead(404);
  response.end();
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
// The setups' names have spaces, so they are served under a plain name.
const servedPath = (setup) => `/${path.basename(path.dirname(setup))}-setup.exe`;
const manifest = (version, setup, signature) => ({
  version, notes: NOTES, pub_date: new Date().toISOString(),
  platforms: { "windows-x86_64": { signature, url: `${origin}${servedPath(setup)}` } }
});

let child = null;
let app = null;
try {
  // ---- A signing key for this run only, and the two signed setups.
  const keyFile = path.join(base, "key", "updater.key");
  run(process.execPath, [TAURI_CLI, "signer", "generate", "--ci", "-p", KEY_PASSWORD, "-w", keyFile], { cwd: DESKTOP });
  const publicKey = readFileSync(`${keyFile}.pub`, "utf8").trim();
  const build = (version) => {
    const overlay = {
      productName: PRODUCT, version, identifier: IDENTIFIER,
      bundle: { createUpdaterArtifacts: true },
      plugins: { updater: { pubkey: publicKey, endpoints: [`${origin}/latest.json`], dangerousInsecureTransportProtocol: true } }
    };
    const overlayFile = path.join(base, `tauri.update-check.${version}.json`);
    writeFileSync(overlayFile, JSON.stringify(overlay));
    run(process.execPath, [TAURI_CLI, "build", "--debug", "--features", "e2e", "--bundles", "nsis", "--config", overlayFile], {
      cwd: DESKTOP,
      env: { ...process.env, CARGO_TARGET_DIR: TARGET, TAURI_SIGNING_PRIVATE_KEY: readFileSync(keyFile, "utf8"), TAURI_SIGNING_PRIVATE_KEY_PASSWORD: KEY_PASSWORD }
    });
    const bundle = path.join(TARGET, "debug", "bundle", "nsis");
    const name = readdirSync(bundle).find((file) => file.endsWith("-setup.exe") && file.includes(`_${version}_`));
    assert.ok(name, `the ${version} setup was built`);
    const folder = path.join(base, version);
    mkdirSync(folder);
    for (const file of [name, `${name}.sig`]) copyFileSync(path.join(bundle, file), path.join(folder, file));
    return { setup: path.join(folder, name), signature: readFileSync(path.join(folder, `${name}.sig`), "utf8") };
  };
  const older = build(OLD_VERSION);
  const newer = build(NEW_VERSION);
  result.setups = [path.basename(older.setup), path.basename(newer.setup)];

  // ---- Install the old version without shortcuts.
  run(older.setup, ["/S", "/NS", `/D=${install}`]);
  const exe = path.join(install, readdirSync(install).find((file) => file.endsWith(".exe") && file !== "uninstall.exe"));
  result.installed = path.basename(exe);

  const launch = async (extra) => {
    const started = startE2eProcess(exe, PORT, {}, argumentsFor(extra));
    child = started.child;
    const page = await connect(PORT);
    await until("the screen", () => page.evaluate(`document.readyState === "complete" && !!window.passwordManager`));
    return { ...started, page };
  };
  const unlock = async (page) => {
    const { sessionId } = await api(page, "fetchVaultStatus()");
    return api(page, `unlockVault({ masterPassword: ${JSON.stringify(PASSWORD)} }, ${JSON.stringify(sessionId)})`);
  };
  const closeApp = async () => {
    powershell(`[void](Get-Process -Id ${child.pid}).CloseMainWindow()`);
    await until("the app to exit", () => child.exitCode !== null);
  };
  const downloadFrom = async (page, nextOffer) => {
    offer = nextOffer;
    await api(page, "checkForUpdates()");
    const available = await updateState(page);
    await api(page, "downloadUpdate()");
    return { available, after: await updateState(page) };
  };

  // ---- First run: a vault, then the cases that leave the app as it is.
  app = await launch();
  assert.ok(app.events.includes("update-support true"), "the setup with a key updates itself");
  let { sessionId } = await api(app.page, "fetchVaultStatus()");
  await api(app.page, `setupVault({ masterPassword: ${JSON.stringify(PASSWORD)} }, ${JSON.stringify(sessionId)})`);
  ({ sessionId } = await api(app.page, "fetchVaultStatus()"));
  const created = await api(app.page, `createEntry({ serviceName: "Update check", loginId: "synthetic-user", password: "synthetic-entry-password" }, ${JSON.stringify(sessionId)})`);
  result.firstState = await updateState(app.page);
  assert.deepEqual(result.firstState, { status: "idle", currentVersion: OLD_VERSION });

  offer = { manifest: manifest(OLD_VERSION, older.setup, older.signature), setup: older.setup };
  await api(app.page, "checkForUpdates()");
  result.sameVersion = await updateState(app.page);
  assert.deepEqual(result.sameVersion, { status: "current", currentVersion: OLD_VERSION });

  // The new setup offered with the old one's signature: found and downloaded in full, then refused.
  result.wrongSignature = await downloadFrom(app.page, { manifest: manifest(NEW_VERSION, newer.setup, older.signature), setup: newer.setup });
  assert.deepEqual(result.wrongSignature, {
    available: { status: "available", currentVersion: OLD_VERSION, latestVersion: NEW_VERSION, releaseNotes: NOTES },
    after: { status: "error", currentVersion: OLD_VERSION, latestVersion: NEW_VERSION, releaseNotes: NOTES, progress: 100, message: FAILED }
  });

  const signed = { manifest: manifest(NEW_VERSION, newer.setup, newer.signature), setup: newer.setup };
  // The right signature for a setup that was changed on the way: the signature itself must fail.
  result.tampered = await downloadFrom(app.page, { ...signed, tamper: true });
  assert.deepEqual(result.tampered.after, result.wrongSignature.after);
  assert.ok(app.events.filter((event) => event.startsWith("update-failed ")).length === 2, "both refusals come from the download");
  result.signed = await downloadFrom(app.page, signed);
  assert.deepEqual(result.signed.after, { status: "downloaded", currentVersion: OLD_VERSION, latestVersion: NEW_VERSION, releaseNotes: NOTES, progress: 100 });
  result.declined = await settle(app.page, "window.passwordManager.installUpdate(true)");
  assert.deepEqual(result.declined, { value: false });
  assert.ok(app.events.includes("update-dialog"));
  assert.equal((await updateState(app.page)).status, "downloaded");
  assert.equal((await api(app.page, "fetchVaultStatus()")).isUnlocked, true, "going back to editing keeps the vault open");
  app.page.close();
  await closeApp();

  // ---- Second run: discarding the edits installs the update.
  app = await launch({ CIPHER_VAULT_E2E_UPDATE_ANSWER: "discard" });
  await unlock(app.page);
  result.reinstall = await downloadFrom(app.page, signed);
  assert.equal(result.reinstall.after.status, "downloaded");
  const installer = settle(app.page, "window.passwordManager.installUpdate(true)");
  await until("the app to exit for the installer", () => child.exitCode !== null, 60000);
  void installer.catch(() => undefined);
  const exitReports = [...new Set(app.events.filter((event) => event.startsWith("vault-locked ") || event === "exit-complete" || event === "update-dialog"))];
  result.installExit = { exitCode: child.exitCode, reports: exitReports };
  assert.deepEqual(result.installExit, { exitCode: 0, reports: ["update-dialog", "vault-locked update", "vault-locked window-closed", "exit-complete"] });
  assert.ok(served.includes(servedPath(newer.setup)));
  app.page.close();
  child = null;

  // ---- The installer restarts the app, which is now the new version with the same vault.
  const page = await connect(PORT);
  await until("the restarted screen", () => page.evaluate(`document.readyState === "complete" && !!window.passwordManager`), 60000);
  result.restarted = { state: await updateState(page), vault: await api(page, "fetchVaultStatus()").then(({ isConfigured, isUnlocked }) => ({ isConfigured, isUnlocked })) };
  assert.deepEqual(result.restarted, { state: { status: "idle", currentVersion: NEW_VERSION }, vault: { isConfigured: true, isUnlocked: false } });
  const opened = await unlock(page);
  assert.equal(opened.isUnlocked, true);
  const { items } = await api(page, `fetchEntries(${JSON.stringify(opened.sessionId)})`);
  const entry = await api(page, `fetchEntry(${JSON.stringify(created.id)}, ${JSON.stringify(opened.sessionId)})`);
  result.keptEntry = { count: items.length, serviceName: entry.serviceName, password: entry.password === "synthetic-entry-password" };
  assert.deepEqual(result.keptEntry, { count: 1, serviceName: "Update check", password: true });
  page.close();
  // The restarted app is not this script's child, so it is found by its path and closed like a window.
  const quotedExe = exe.replaceAll("'", "''");
  powershell(`Get-Process | Where-Object { $_.Path -eq '${quotedExe}' } | ForEach-Object { [void]$_.CloseMainWindow() }`);
  await until("the restarted app to exit", () => powershell(`@(Get-Process | Where-Object { $_.Path -eq '${quotedExe}' }).Count`) === "0", 30000);
  result.installedVersion = powershell(`(Get-Item -LiteralPath '${quotedExe}').VersionInfo.ProductVersion`);
  assert.equal(result.installedVersion, NEW_VERSION);
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  // What the app and the server saw, for the reason behind a failure.
  console.error(JSON.stringify({ events: app?.events, errors: app?.errors?.join(""), served }, null, 2));
  throw error;
} finally {
  server.close();
  // An update installer runs from a temporary copy, so it is found by its arguments and allowed to
  // finish before the test install is removed.
  const updaters = () => powershell(`@(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*/UPDATE*' -and $_.ExecutablePath -like '*setup*.exe' }).ProcessId -join ','`);
  await until("the update installer to finish", () => updaters() === "", 120000).catch(() => {
    powershell(`Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*/UPDATE*' -and $_.ExecutablePath -like '*setup*.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`);
  });
  // Stop whatever runs from the test install, then remove it with its own uninstaller.
  const quoted = install.replaceAll("'", "''");
  try { powershell(`Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith('${quoted}\\') } | Stop-Process -Force`); } catch { /* nothing runs */ }
  if (existsSync(path.join(install, "uninstall.exe"))) {
    spawnSync(path.join(install, "uninstall.exe"), ["/S"], { timeout: 60000 });
    // The uninstaller copies itself elsewhere and returns before it has finished.
    await until("the uninstaller", () => !existsSync(path.join(install, "uninstall.exe")), 60000).catch(() => undefined);
  }
  // The uninstaller keeps the installer's language choice unless the app data is deleted too.
  powershell(`$key = 'HKCU:\\Software\\${PUBLISHER}'; Remove-Item -LiteralPath "$key\\${PRODUCT}" -Recurse -ErrorAction SilentlyContinue
    if ((Test-Path $key) -and (Get-Item $key).SubKeyCount -eq 0 -and (Get-Item $key).ValueCount -eq 0) { Remove-Item -LiteralPath $key }`);
  const leftover = powershell(`@(Get-ChildItem 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall' | Where-Object { $_.PSChildName -eq '${PRODUCT}' }).Count`);
  await sleep(500);
  rmSync(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
  if (leftover !== "0") {
    console.error(`The test install's uninstall entry is still there: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${PRODUCT}`);
    process.exitCode = 1;
  }
}
