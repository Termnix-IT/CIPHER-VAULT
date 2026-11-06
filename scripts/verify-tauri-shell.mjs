// Checks the Tauri shell in apps/desktop through its `e2e` build: the screen loads under the
// Tauri CSP, IPC uses Tauri's own protocol instead of the postMessage fallback, and the window
// refuses outside connections, navigation, new windows and ungranted commands.
// Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>
import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { connect, powershell, screenshot, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const [exe, screenshotDirectory] = process.argv.slice(2);
if (!exe || !screenshotDirectory) throw new Error("Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>");
mkdirSync(screenshotDirectory, { recursive: true });

const NOT_PORTED = "この版では保管庫をまだ開けません。現行のアプリを使ってください";
const PORT = 9341;
const settle = (page, expression) => page.evaluate(`Promise.resolve().then(() => ${expression}).then((value) => ({ value }), (error) => ({ error: String(error?.message ?? error) }))`);

const { child, events, errors } = startE2eProcess(exe, PORT);
let page;
try {
  page = await connect(PORT);
  await until("the screen", () => page.evaluate(`document.readyState === "complete" && document.title === "CIPHER VAULT" && !!window.passwordManager`));
  const result = {};

  result.status = await settle(page, "window.passwordManager.fetchVaultStatus()");
  assert.deepEqual(result.status, { error: NOT_PORTED });
  await until("the IPC response", () => page.responses.some((response) => response.url.startsWith("http://ipc.localhost/vault_status")));
  result.ipcResponses = page.responses.filter((response) => response.url.startsWith("http://ipc.localhost/")).map(({ url, status }) => `${status} ${url}`);
  result.apiFrozen = await page.evaluate(`Object.isFrozen(window.passwordManager) && !Object.getOwnPropertyDescriptor(window, "passwordManager").writable`);
  assert.equal(result.apiFrozen, true);

  result.outsideFetch = await settle(page, `fetch("https://example.test/")`);
  assert.ok(result.outsideFetch.error, "an outside connection must fail");
  result.ungrantedCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("plugin:window|set_title", { label: "main", value: "changed" })`);
  assert.ok(result.ungrantedCommand.error, "a command no capability grants must be refused");
  result.unknownCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("entries_list", {})`);
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

  await sleep(500);
  await screenshot(page, screenshotDirectory, "tauri-shell");
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
  throw error;
} finally {
  page?.close();
  child.kill();
}
