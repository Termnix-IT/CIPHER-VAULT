// Checks the Tauri app in apps/desktop through its `e2e` build: it refuses to start without a test
// folder or on a folder holding real data, the screen sets up, adds to, locks and unlocks a vault
// in a temporary folder through the Rust core, and the window keeps refusing outside connections,
// navigation, new windows and ungranted commands. Only synthetic passwords are used.
// Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect, powershell, screenshot, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const [exe, screenshotDirectory] = process.argv.slice(2);
if (!exe || !screenshotDirectory) throw new Error("Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>");
mkdirSync(screenshotDirectory, { recursive: true });

const NOT_PORTED = "この機能はこの版ではまだ使えません。現行のアプリを使ってください";
const PASSWORD = "synthetic-shell-check-password";
const PORT = 9341;
const settle = (page, expression) => page.evaluate(`Promise.resolve().then(() => ${expression}).then((value) => ({ value }), (error) => ({ error: String(error?.message ?? error) }))`);
const status = (page) => page.evaluate("window.passwordManager.fetchVaultStatus()");
const screenHas = (page, text) => page.evaluate(`document.body.innerText.includes(${JSON.stringify(text)})`);
const click = (page, selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
const lockScreenShown = (page) => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`);

async function type(page, selector, text) {
  assert.equal(await page.evaluate(`(() => { const input = document.querySelector(${JSON.stringify(selector)}); if (!input) return false; input.focus(); input.select(); return true; })()`), true, `${selector} is on screen`);
  await page.send("Input.insertText", { text });
}
const field = (label) => `[...document.querySelectorAll(".editor-field")].find((node) => node.querySelector(".form-label")?.textContent === ${JSON.stringify(label)})?.querySelector("input, textarea")`;
async function fill(page, label, text) {
  assert.equal(await page.evaluate(`(() => { const input = ${field(label)}; if (!input) return false; input.focus(); input.select(); return true; })()`), true, `the field ${label} is on screen`);
  await page.send("Input.insertText", { text });
}

async function submitPassword(page, password, confirm) {
  await until("the lock screen", () => lockScreenShown(page));
  // The screen polls the session every second, and a stale session id would be refused.
  await sleep(1500);
  await type(page, 'input[aria-label="マスターパスワード"]', password);
  if (confirm) await type(page, 'input[aria-label="マスターパスワードをもう一度入力"]', password);
  await click(page, 'button[type="submit"]');
}

/** The app must exit before opening a window when the folder is missing or holds real data. */
function startupRefusals(base) {
  const refusedWith = (environment) => {
    const run = spawnSync(exe, [], { env: { ...process.env, CIPHER_VAULT_DATA_DIR: "", ...environment }, encoding: "utf8", timeout: 20000 });
    return { exitCode: run.status, stderr: run.stderr.trim() };
  };
  const roaming = path.join(base, "roaming");
  const inAppData = path.join(roaming, "CIPHER VAULT", "data");
  const releaseData = path.join(base, "release", "data");
  mkdirSync(inAppData, { recursive: true });
  mkdirSync(releaseData, { recursive: true });
  const result = {
    unset: refusedWith({ CIPHER_VAULT_DATA_DIR: undefined }),
    relative: refusedWith({ CIPHER_VAULT_DATA_DIR: "relative-folder" }),
    missing: refusedWith({ CIPHER_VAULT_DATA_DIR: path.join(base, "missing") }),
    appData: refusedWith({ CIPHER_VAULT_DATA_DIR: inAppData, APPDATA: roaming }),
    releaseData: refusedWith({ CIPHER_VAULT_DATA_DIR: releaseData })
  };
  for (const [name, refusal] of Object.entries(result)) {
    assert.equal(refusal.exitCode, 2, `${name}: ${refusal.stderr}`);
    assert.match(refusal.stderr, /CIPHER_VAULT_DATA_DIR/, name);
  }
  assert.deepEqual(readdirSync(inAppData), [], "nothing is written to a refused folder");
  assert.deepEqual(readdirSync(releaseData), []);
  return result;
}

// A fresh WebView2 profile and vault folder for each run, so the check never touches a real install.
const base = mkdtempSync(path.join(tmpdir(), "cipher-vault-e2e-"));
const profile = path.join(base, "profile");
const data = path.join(base, "data");
mkdirSync(data);
const result = { startupRefusals: startupRefusals(base) };
const { child, events, errors } = startE2eProcess(exe, PORT, { CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT), CIPHER_VAULT_E2E_PROFILE: profile, CIPHER_VAULT_DATA_DIR: data });
let page;
try {
  page = await connect(PORT);
  await until("the screen", () => page.evaluate(`document.readyState === "complete" && document.title === "CIPHER VAULT" && !!window.passwordManager`));

  // ---- The vault, through the screen
  const initial = await status(page);
  assert.equal(initial.isConfigured, false);
  assert.equal(initial.isUnlocked, false);
  assert.equal(initial.idleTimeoutMs, 300000);
  await submitPassword(page, PASSWORD, true);
  await until("the unlocked screen", async () => !(await lockScreenShown(page)) && (await status(page)).isUnlocked);
  result.setUp = true;

  await click(page, ".sidebar-add");
  await until("the new form", () => page.evaluate(`!!(${field("サービス")})`));
  await fill(page, "サービス", "画面で追加");
  await fill(page, "ログインID", "synthetic-shell-id");
  await page.evaluate(`[...document.querySelectorAll(".vault-detail button")].find((node) => node.textContent.trim() === "生成").click()`);
  await until("the generated password", () => page.evaluate(`${field("パスワード")}.value.length === 20`));
  const generated = await page.evaluate(`${field("パスワード")}.value`);
  await click(page, ".editor-save-btn");
  await until("the saved entry", () => screenHas(page, "画面で追加"));
  const { sessionId } = await status(page);
  const listed = (await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(sessionId)})`)).items;
  assert.equal(listed.length, 1);
  assert.equal(listed[0].serviceName, "画面で追加");
  assert.equal("password" in listed[0], false, "the list never carries the password");
  const stored = await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(listed[0].id)}, ${JSON.stringify(sessionId)})`);
  assert.equal(stored.password, generated);
  result.createdThroughForm = true;
  await sleep(500);
  await screenshot(page, screenshotDirectory, "tauri-shell-unlocked");

  await page.evaluate(`window.passwordManager.lockVault(${JSON.stringify(sessionId)})`);
  await until("the lock screen", () => lockScreenShown(page));
  result.lockReason = (await status(page)).lockReason;
  assert.equal(result.lockReason, "manual");
  result.readAfterLock = await settle(page, `window.passwordManager.fetchEntries(${JSON.stringify(sessionId)})`);
  assert.ok(result.readAfterLock.error, "the old session must not read after the lock");

  await submitPassword(page, "synthetic-wrong-password", false);
  await until("the refusal", () => screenHas(page, "マスターパスワードが正しくありません"));
  result.wrongPassword = "マスターパスワードが正しくありません";
  await submitPassword(page, PASSWORD, false);
  await until("the unlocked list", async () => !(await lockScreenShown(page)) && (await screenHas(page, "画面で追加")));
  result.unlockedAgain = true;

  // The vault file sits in the test folder, and the password is not stored as plain text.
  const file = readFileSync(path.join(data, "password-manager.db"));
  result.passwordInPlainText = file.includes(Buffer.from(generated));
  assert.equal(result.passwordInPlainText, false);
  result.notPorted = await settle(page, `window.passwordManager.copyText("x", ${JSON.stringify((await status(page)).sessionId)})`);
  assert.deepEqual(result.notPorted, { error: NOT_PORTED });

  // ---- The shell
  await until("the IPC response", () => page.responses.some((response) => response.url.startsWith("http://ipc.localhost/vault_status")));
  result.ipcCommands = [...new Set(page.responses.filter((response) => response.url.startsWith("http://ipc.localhost/")).map(({ url, status }) => `${status} ${new URL(url).pathname}`))];
  result.apiFrozen = await page.evaluate(`Object.isFrozen(window.passwordManager) && !Object.getOwnPropertyDescriptor(window, "passwordManager").writable`);
  assert.equal(result.apiFrozen, true);

  result.outsideFetch = await settle(page, `fetch("https://example.test/")`);
  assert.ok(result.outsideFetch.error, "an outside connection must fail");
  result.ungrantedCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("plugin:window|set_title", { label: "main", value: "changed" })`);
  assert.ok(result.ungrantedCommand.error, "a command no capability grants must be refused");
  result.unknownCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("backup_export", {})`);
  assert.ok(result.unknownCommand.error);
  result.newWindow = await page.evaluate(`window.open("https://example.test/") === null`);

  await page.evaluate(`location.href = "https://example.test/"`);
  await sleep(1500);
  result.locationAfterNavigation = await page.evaluate("location.origin");
  assert.equal(result.locationAfterNavigation, "http://tauri.localhost");

  result.windowTitle = powershell(`(Get-Process -Id ${child.pid}).MainWindowTitle`);
  assert.equal(result.windowTitle, "CIPHER VAULT");
  result.windowCount = Number(powershell(`@(Get-Process -Name cipher-vault -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }).Count`));
  assert.equal(result.windowCount, 1, "window.open must not have opened a window");
  result.webviewSettings = events.find((event) => event.startsWith("webview-settings "));
  assert.equal(result.webviewSettings, "webview-settings autofill=false autosave=false accelerators=false");

  const messages = [...new Set(page.messages)];
  result.ipcFallback = messages.some((message) => message.includes("IPC custom protocol failed"));
  assert.equal(result.ipcFallback, false, "IPC must not fall back to postMessage");
  // The refusal of an outside connection quotes the directive, which names ipc.localhost too.
  result.ipcBlockedByPolicy = messages.some((message) => /(Connecting to|cannot load) '?http:\/\/ipc\.localhost/.test(message));
  assert.equal(result.ipcBlockedByPolicy, false);
  result.outsideBlockedByPolicy = messages.some((message) => message.includes("https://example.test/") && message.includes("connect-src"));
  assert.equal(result.outsideBlockedByPolicy, true);
  result.console = messages.filter((message) => !message.startsWith("verbose:"));
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  if (page) await screenshot(page, screenshotDirectory, "tauri-shell-failure").catch(() => undefined);
  console.error(JSON.stringify({ stderr: errors.join(""), events, console: [...new Set(page?.messages ?? [])] }));
  // Without a page there is nothing else to report, so show whether WebView2 got the debugging argument.
  if (!page) {
    try {
      console.error(powershell(`Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId) $($_.CommandLine)" } | Select-Object -First 3`));
      console.error(powershell(`Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -ge 9000 | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) $($_.OwningProcess)" }`));
    } catch (diagnosis) { console.error(String(diagnosis)); }
  }
  throw error;
} finally {
  page?.close();
  child.kill();
  await until("the app to exit", () => child.exitCode !== null || child.signalCode !== null).catch(() => undefined);
  // WebView2's helper processes release the profile a moment after the app exits.
  rmSync(base, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
}
