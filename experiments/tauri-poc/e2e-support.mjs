// Helpers shared by verify-ui.mjs and verify-write.mjs for driving the prototype's `e2e` build.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const EVALUATE_TIMEOUT_MS = 60_000;

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const digest = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

export function powershell(script) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`PowerShell failed: ${result.stderr}`);
  return result.stdout.trim();
}

export function sendOsMessage(window, [message, wparam]) {
  powershell(`Add-Type -Namespace E2E -Name Win32 -MemberDefinition '[DllImport("user32.dll")] public static extern System.IntPtr SendMessageW(System.IntPtr window, uint message, System.IntPtr wparam, System.IntPtr lparam);'
    [void][E2E.Win32]::SendMessageW([IntPtr][long]${Number(window)}, ${message}, [IntPtr]${wparam}, [IntPtr]0)`);
}

export async function until(label, check, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for: ${label}`);
    await sleep(100);
  }
}

export async function connect(port) {
  const pages = await until("debugging port", async () => {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      return list.some((page) => page.type === "page") ? list : null;
    } catch { return null; }
  });
  const socket = new WebSocket(pages.find((page) => page.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  const pending = new Map(), messages = [], dialogs = [];
  let sequence = 0;
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id !== undefined) { pending.get(message.id)?.(message); pending.delete(message.id); }
    else if (message.method === "Page.javascriptDialogOpening") {
      // A native confirmation blocks the page until answered, so accept it the way the user would.
      dialogs.push(message.params.message);
      socket.send(JSON.stringify({ id: ++sequence, method: "Page.handleJavaScriptDialog", params: { accept: true } }));
    }
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
    // A request the native side never answers must fail the check instead of stopping it forever.
    const timedOut = new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`No answer from the page: ${expression.slice(0, 120)}`)), EVALUATE_TIMEOUT_MS);
      timer.unref();
    });
    const { result, exceptionDetails } = await Promise.race([send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }), timedOut]);
    if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
    return result.value;
  };
  return { send, evaluate, messages, dialogs, close: () => socket.close() };
}

export async function submitPassword(page, password) {
  await page.evaluate(`document.querySelector('input[aria-label="マスターパスワード"]').focus(); document.querySelector('input[aria-label="マスターパスワード"]').select()`);
  await page.send("Input.insertText", { text: password });
  await page.evaluate(`document.querySelector('button[type="submit"]').click()`);
}

export async function screenshot(page, directory, name) {
  const { data } = await page.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(path.join(directory, `${name}.png`), Buffer.from(data, "base64"));
}

export const lockScreenShown = (page) => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`);
export const fetchStatus = (page) => page.evaluate("window.passwordManager.fetchVaultStatus()");

export async function unlockThroughScreen(page, password) {
  await until("lock screen", () => lockScreenShown(page));
  // The screen polls the session every second, and a stale session id would be refused.
  await sleep(1500);
  await submitPassword(page, password);
  await until("unlocked screen", async () => !(await lockScreenShown(page)) && (await fetchStatus(page)).isUnlocked);
  return (await fetchStatus(page)).sessionId;
}

export function startE2eBuild(exe, database, port, extraEnvironment = {}) {
  const events = [], errors = [];
  const child = spawn(exe, [], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CIPHER_VAULT_POC_DB: database,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-allow-origins=*`, ...extraEnvironment } });
  let buffered = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    const lines = (buffered + chunk).split("\n");
    buffered = lines.pop();
    for (const line of lines) if (line.startsWith("e2e-event ")) events.push(line.slice("e2e-event ".length).trim());
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => errors.push(chunk));
  return { child, events, errors };
}
