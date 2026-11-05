// Drives the built prototype on synthetic vaults through the WebView2 debugging port, then reports
// the checks as JSON. The port is opened only by this script's environment, for this test process.
// Usage: node verify-ui.mjs <exe> <sample.json from create-sample-vault.mjs> <screenshot-directory>
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const [exe, samplePath, screenshotDirectory] = process.argv.slice(2);
if (!exe || !samplePath || !screenshotDirectory) throw new Error("Usage: node verify-ui.mjs <exe> <sample.json> <screenshot-directory>");
const sample = JSON.parse(readFileSync(samplePath, "utf8"));
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

async function runVault(format, port) {
  const { database, password } = sample[format];
  const before = digest(database), checks = {};
  const child = spawn(exe, [], { stdio: "ignore", env: { ...process.env, CIPHER_VAULT_POC_DB: database,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-allow-origins=*` } });
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

    const lockedStatus = await page.evaluate(`window.passwordManager.lockVault(${JSON.stringify(status.sessionId)})`);
    checks.lockReason = lockedStatus.lockReason;
    await until("lock screen after locking", () => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`));
    checks.readAfterLock = await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(lockedStatus.sessionId)}).then(() => "readable", (error) => error.message)`);
    checks.listClearedFromScreen = !(await page.evaluate(`document.body.innerText.includes(${JSON.stringify(list.items[0].serviceName)})`));
    await screenshot(page, `${format}-4-locked`);
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

const results = { legacy: await runVault("legacy", 9331), v2: await runVault("v2", 9332) };
console.log(JSON.stringify(results, null, 2));
