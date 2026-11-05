// Drives the prototype's `e2e` build on synthetic vaults through the WebView2 debugging port, then
// reports the checks as JSON. That build uses a fake clipboard, so the real clipboard is untouched.
// OS events are simulated by sending the same window messages Windows sends; the PC is never locked
// or suspended. The normal build is only checked for its debugging port staying closed.
// Usage: node verify-ui.mjs <e2e-exe> <sample.json from create-sample-vault.mjs> <screenshot-directory> <normal-exe>
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const [exe, samplePath, screenshotDirectory, normalExe] = process.argv.slice(2);
if (!exe || !samplePath || !screenshotDirectory || !normalExe) throw new Error("Usage: node verify-ui.mjs <e2e-exe> <sample.json> <screenshot-directory> <normal-exe>");
const sample = JSON.parse(readFileSync(samplePath, "utf8"));
const CLIPBOARD_CLEAR_AFTER_MS = 30_000;
const WM_POWERBROADCAST = 0x218, WM_WTSSESSION_CHANGE = 0x2b1;
const OS_SCENARIOS = [
  { name: "screenLock", away: [WM_WTSSESSION_CHANGE, 7], awayReason: "screen-lock", back: [WM_WTSSESSION_CHANGE, 8], backReason: "screen-unlock" },
  { name: "suspend", away: [WM_POWERBROADCAST, 4], awayReason: "suspend", back: [WM_POWERBROADCAST, 7], backReason: "resume" },
  { name: "suspendAutomaticResume", away: [WM_POWERBROADCAST, 4], awayReason: "suspend", back: [WM_POWERBROADCAST, 0x12], backReason: "resume" }
];

function powershell(script) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`PowerShell failed: ${result.stderr}`);
  return result.stdout.trim();
}

function sendOsMessage(window, [message, wparam]) {
  powershell(`Add-Type -Namespace E2E -Name Win32 -MemberDefinition '[DllImport("user32.dll")] public static extern System.IntPtr SendMessageW(System.IntPtr window, uint message, System.IntPtr wparam, System.IntPtr lparam);'
    [void][E2E.Win32]::SendMessageW([IntPtr][long]${Number(window)}, ${message}, [IntPtr]${wparam}, [IntPtr]0)`);
}
if (sample.testOnly !== true) throw new Error("Refusing data that is not marked as a synthetic sample");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const digest = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

async function until(label, check, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for: ${label}`);
    await sleep(100);
  }
}

async function connect(port) {
  const pages = await until("debugging port", async () => {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      return list.some((page) => page.type === "page") ? list : null;
    } catch { return null; }
  });
  const socket = new WebSocket(pages.find((page) => page.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  const pending = new Map(), messages = [];
  let sequence = 0;
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined) { pending.get(message.id)?.(message); pending.delete(message.id); }
    else if (message.method === "Log.entryAdded") messages.push(`${message.params.entry.level}: ${message.params.entry.text}`);
    else if (message.method === "Runtime.consoleAPICalled") messages.push(`${message.params.type}: ${message.params.args.map((arg) => arg.value ?? arg.description).join(" ")}`);
    else if (message.method === "Runtime.exceptionThrown") messages.push(`exception: ${message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text}`);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, (message) => message.error ? reject(new Error(`${method}: ${message.error.message}`)) : resolve(message.result));
    socket.send(JSON.stringify({ id, method, params }));
  });
  await send("Runtime.enable"); await send("Log.enable"); await send("Page.enable");
  const evaluate = async (expression) => {
    const { result, exceptionDetails } = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  };
  return { send, evaluate, messages, close: () => socket.close() };
}

async function submitPassword(page, password) {
  await page.evaluate(`document.querySelector('input[aria-label="マスターパスワード"]').focus(); document.querySelector('input[aria-label="マスターパスワード"]').select()`);
  await page.send("Input.insertText", { text: password });
  await page.evaluate(`document.querySelector('button[type="submit"]').click()`);
}

async function screenshot(page, name) {
  const { data } = await page.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(path.join(screenshotDirectory, `${name}.png`), Buffer.from(data, "base64"));
}

const lockScreenShown = (page) => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`);
const fetchStatus = (page) => page.evaluate("window.passwordManager.fetchVaultStatus()");
const copy = (page, sessionId) => page.evaluate(`window.passwordManager.copyText("synthetic-clipboard-value", ${JSON.stringify(sessionId)}).then(() => "copied", (error) => error.message)`);

async function unlockThroughScreen(page, password) {
  await until("lock screen", () => lockScreenShown(page));
  // The screen polls the session every second, and a stale session id would be refused.
  await sleep(1500);
  await submitPassword(page, password);
  await until("unlocked screen", async () => !(await lockScreenShown(page)) && (await fetchStatus(page)).isUnlocked);
  return (await fetchStatus(page)).sessionId;
}

async function checkOsScenario(page, events, window, password, scenario) {
  const sessionId = await unlockThroughScreen(page, password);
  const result = { copied: await copy(page, sessionId) };
  await until("clipboard write report", () => events.includes("clipboard-write"));
  const mark = events.length;
  sendOsMessage(window, scenario.away);
  // Sending the message blocks this process, so the reports are read only after it returns.
  await until("OS event reports", () => events.slice(mark).includes("clipboard-clear"));
  result.events = events.slice(mark);
  const away = await fetchStatus(page);
  result.awayStatus = { isUnlocked: away.isUnlocked, lockReason: away.lockReason };
  await until("lock screen while away", () => lockScreenShown(page));
  result.unlockWhileAway = await page.evaluate(`window.passwordManager.unlockVault({ masterPassword: ${JSON.stringify(password)} }, ${JSON.stringify(away.sessionId)}).then(() => "unlocked", (error) => error.message)`);
  result.copyWhileAway = await copy(page, away.sessionId);
  result.readAfterLock = await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(sessionId)}).then(() => "readable", (error) => error.message)`);
  sendOsMessage(window, scenario.back);
  const back = await fetchStatus(page);
  result.backStatus = { isUnlocked: back.isUnlocked, lockReason: back.lockReason };

  assert.equal(result.copied, "copied");
  assert.deepEqual(result.events, [`vault-locked ${scenario.awayReason}`, "clipboard-clear"], "the key goes first, then the clipboard");
  assert.deepEqual(result.awayStatus, { isUnlocked: false, lockReason: scenario.awayReason });
  for (const refused of [result.unlockWhileAway, result.copyWhileAway, result.readAfterLock]) assert.match(refused, /画面ロック・スリープ中/);
  assert.deepEqual(result.backStatus, { isUnlocked: false, lockReason: scenario.backReason }, "returning never unlocks by itself");
  return result;
}

async function checkOsIntegration(page, events, password, child) {
  const window = events.find((event) => event.startsWith("os-window ")).split(" ")[1];
  const checks = { webviewSettings: events.find((event) => event.startsWith("webview-settings ")) };
  for (const scenario of OS_SCENARIOS) checks[scenario.name] = await checkOsScenario(page, events, window, password, scenario);

  const sessionId = await unlockThroughScreen(page, password);
  checks.oversizedCopy = await page.evaluate(`window.passwordManager.copyText("x".repeat(1024 * 1024 + 1), ${JSON.stringify(sessionId)}).then(() => "copied", (error) => error.message)`);
  checks.staleSessionCopy = await copy(page, "stale-session");

  // The real deadline, while the vault stays unlocked: the watchdog must clear it without the page.
  let mark = events.length;
  const copiedAt = Date.now();
  checks.expiryCopy = await copy(page, sessionId);
  await until("clipboard expiry", () => events.slice(mark).includes("clipboard-clear"), CLIPBOARD_CLEAR_AFTER_MS + 5000);
  checks.expiryAfterMs = Date.now() - copiedAt;
  checks.unlockedAfterExpiry = (await fetchStatus(page)).isUnlocked;

  mark = events.length;
  checks.exitCopy = await copy(page, (await fetchStatus(page)).sessionId);
  powershell(`[void](Get-Process -Id ${child.pid}).CloseMainWindow()`);
  await until("process exit", () => child.exitCode !== null);
  await until("exit reports", () => events.includes("exit-complete"));
  checks.exitEvents = events.slice(mark).filter((event) => event !== "clipboard-write");

  assert.equal(checks.webviewSettings, "webview-settings autofill=false autosave=false accelerators=false");
  assert.equal(checks.oversizedCopy, "コピーする内容が大きすぎます");
  assert.notEqual(checks.staleSessionCopy, "copied");
  assert.ok(checks.expiryAfterMs >= CLIPBOARD_CLEAR_AFTER_MS && checks.expiryAfterMs < CLIPBOARD_CLEAR_AFTER_MS + 3000, `cleared after ${checks.expiryAfterMs} ms`);
  assert.equal(checks.unlockedAfterExpiry, true);
  assert.deepEqual(checks.exitEvents, ["vault-locked window-closed", "clipboard-clear", "exit-complete"]);
  return checks;
}

function startE2eBuild(database, port) {
  const events = [];
  const child = spawn(exe, [], { stdio: ["ignore", "pipe", "ignore"], env: { ...process.env, CIPHER_VAULT_POC_DB: database,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-allow-origins=*` } });
  let buffered = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    const lines = (buffered + chunk).split("\n");
    buffered = lines.pop();
    for (const line of lines) if (line.startsWith("e2e-event ")) events.push(line.slice("e2e-event ".length).trim());
  });
  return { child, events };
}

// A crashed page cannot be trusted to lock anything, so the native side must do it.
async function checkRendererCrash({ database, password }, port) {
  const { child, events } = startE2eBuild(database, port);
  try {
    const page = await connect(port);
    const sessionId = await unlockThroughScreen(page, password);
    assert.equal(await copy(page, sessionId), "copied");
    const mark = events.length;
    page.send("Page.crash").catch(() => undefined);
    await until("renderer crash reports", () => events.slice(mark).includes("clipboard-clear"));
    const result = events.slice(mark).filter((event) => event !== "clipboard-write");
    assert.deepEqual(result, ["vault-locked renderer-gone", "clipboard-clear"]);
    page.close();
    return result;
  } finally {
    child.kill();
    await sleep(800);
  }
}

async function checkNormalBuildKeepsPortClosed(database, port) {
  const child = spawn(normalExe, [], { stdio: "ignore", env: { ...process.env, CIPHER_VAULT_POC_DB: database,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-allow-origins=*` } });
  try {
    await until("normal build window", () => powershell(`(Get-Process -Id ${child.pid}).MainWindowHandle`) !== "0", 30000);
    await sleep(3000);
    const commandLines = JSON.parse(powershell(`ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process -Filter "ParentProcessId=${child.pid} AND Name='msedgewebview2.exe'" | ForEach-Object CommandLine)`));
    const portOpen = await fetch(`http://127.0.0.1:${port}/json`).then(() => true, () => false);
    const result = { webviewProcesses: commandLines.length, argumentReachedWebview: commandLines.some((line) => line.includes("remote-debugging-port")), portOpen };
    assert.deepEqual(result, { webviewProcesses: 1, argumentReachedWebview: false, portOpen: false });
    return result;
  } finally {
    child.kill();
    await sleep(800);
  }
}

async function runVault(format, port) {
  const { database, password } = sample[format];
  const before = digest(database), checks = {};
  const { child, events } = startE2eBuild(database, port);
  let page;
  try {
    page = await connect(port);
    await until("lock screen", () => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`));
    checks.origin = await page.evaluate("location.origin");
    checks.desktopApi = await page.evaluate("typeof window.passwordManager?.fetchEntries");
    await screenshot(page, `${format}-1-lock`);

    await submitPassword(page, "synthetic-wrong-password");
    checks.wrongPasswordMessage = await until("wrong password message", () =>
      page.evaluate(`[...document.querySelectorAll('[role="alert"], .form-error, .error-message')].map((node) => node.textContent).join(" ").trim() ||
        (document.body.innerText.includes("マスターパスワードが正しくありません") ? "マスターパスワードが正しくありません" : "")`));

    const started = Date.now();
    await submitPassword(page, password);
    await until("entry list", () => page.evaluate(`!document.querySelector('input[aria-label="マスターパスワード"]') && document.body.innerText.includes(${JSON.stringify(format === "v2" ? "合成銀行" : "Second fixture")})`));
    checks.unlockToListMs = Date.now() - started;
    await sleep(800);
    await screenshot(page, `${format}-2-list`);
    const status = await page.evaluate("window.passwordManager.fetchVaultStatus()");
    checks.format = status.maintenance.format;
    checks.isUnlocked = status.isUnlocked;
    const list = await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(status.sessionId)})`);
    checks.listedTypes = list.items.map((item) => item.type ?? "login");
    checks.listCarriesSecrets = JSON.stringify(list).includes("password\"") || JSON.stringify(list).includes("synthetic-api-key");
    const details = [];
    for (const item of list.items) details.push(await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(item.id)}, ${JSON.stringify(status.sessionId)})`));
    checks.decryptedSecrets = details.map((entry) => entry.password ?? entry.apiKey?.key ?? entry.card?.number ?? entry.financial?.loginPassword).filter(Boolean).length;
    if (format === "v2") checks.cardLast4 = list.items.find((item) => item.type === "creditCard")?.cardLast4;

    await page.evaluate(`[...document.querySelectorAll('[role="option"], [role="listitem"] button, li button, .entry-row, .entry-list button')].find((node) => node.textContent.includes(${JSON.stringify(list.items[0].serviceName)}))?.click()`);
    await sleep(500);
    await screenshot(page, `${format}-3-detail`);

    checks.writeRejected = await page.evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(list.items[0].id)}, ${JSON.stringify(status.sessionId)}).then(() => "deleted", (error) => error.message)`);
    checks.unknownCommandRejected = await page.evaluate(`window.__TAURI_INTERNALS__.invoke("plugin:shell|execute", {}).then(() => "allowed", (error) => "rejected: " + String(error).slice(0, 80))`);
    checks.pluginWindowCommandRejected = await page.evaluate(`window.__TAURI_INTERNALS__.invoke("plugin:window|set_title", { value: "x" }).then(() => "allowed", (error) => "rejected: " + String(error).slice(0, 80))`);
    checks.externalFetchBlocked = await page.evaluate(`fetch("https://example.test/").then(() => "reachable", (error) => "blocked: " + error.message)`);
    checks.inlineScriptBlocked = await page.evaluate(`(() => { const node = document.createElement("script"); node.textContent = "window.__inlineRan = true"; document.head.append(node); return window.__inlineRan !== true; })()`);
    const beforeNavigation = await page.evaluate("location.href");
    await page.evaluate(`location.href = "https://example.test/"`).catch(() => undefined);
    await sleep(800);
    checks.navigationBlocked = (await page.evaluate("location.href")) === beforeNavigation;
    checks.windowOpenBlocked = await page.evaluate(`(() => { const opened = window.open("https://example.test/"); return opened === null || opened === undefined; })()`);
    await sleep(300);
    checks.apiImmutable = await page.evaluate(`(() => { try { window.passwordManager.fetchEntries = null; } catch {} return typeof window.passwordManager.fetchEntries; })()`);

    checks.copyButton = await page.evaluate(`(() => { const button = [...document.querySelectorAll("button")].find((node) => /コピー/.test(node.textContent + (node.getAttribute("aria-label") ?? ""))); button?.click(); return button ? "clicked" : "absent"; })()`);
    await sleep(500);
    checks.copyButtonWrote = events.includes("clipboard-write");
    const clearsBeforeLock = events.filter((event) => event === "clipboard-clear").length;
    const lockedStatus = await page.evaluate(`window.passwordManager.lockVault(${JSON.stringify(status.sessionId)})`);
    checks.lockReason = lockedStatus.lockReason;
    checks.manualLockClearedClipboard = events.filter((event) => event === "clipboard-clear").length === clearsBeforeLock + 1;
    await until("lock screen after locking", () => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`));
    checks.readAfterLock = await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(lockedStatus.sessionId)}).then(() => "readable", (error) => error.message)`);
    checks.listClearedFromScreen = !(await page.evaluate(`document.body.innerText.includes(${JSON.stringify(list.items[0].serviceName)})`));
    await screenshot(page, `${format}-4-locked`);
    checks.osIntegration = await checkOsIntegration(page, events, password, child);
    checks.consoleMessages = [...new Set(page.messages)];
  } catch (error) {
    if (page) {
      await screenshot(page, `${format}-failure`).catch(() => undefined);
      const text = await page.evaluate("document.body.innerText").catch(() => "(unavailable)");
      console.error(JSON.stringify({ format, checks, screen: text, console: [...new Set(page.messages)] }, null, 2));
    }
    throw error;
  } finally {
    page?.close();
    child.kill();
    await sleep(800);
  }
  checks.databaseUnchanged = digest(database) === before;
  return checks;
}

const results = {
  legacy: await runVault("legacy", 9331),
  v2: await runVault("v2", 9332),
  rendererCrash: await checkRendererCrash(sample.v2, 9334),
  normalBuild: await checkNormalBuildKeepsPortClosed(sample.v2.database, 9333)
};
console.log(JSON.stringify(results, null, 2));
