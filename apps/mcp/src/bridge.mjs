import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { BrowserMessageDecoder, encodeBrowserMessage } from "../../electron/dist/apps/electron/src/browser-message.js";
import { candidateQuery, candidateResult } from "../../electron/dist/apps/electron/src/candidate-search.js";

export const workspace = fileURLToPath(new URL("../../../", import.meta.url));
export const unavailable = () => new Error("接続・保管庫の解除・アプリ側の検索許可を確認してください");
export function agentProfile(value, create = false) {
  if (typeof value !== "string" || !path.isAbsolute(value) || path.resolve(value) !== value || value.startsWith("\\\\") || /[\x00-\x1f]/.test(value)) throw unavailable();
  if (create && !fs.existsSync(value)) fs.mkdirSync(value, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(value); if (!info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(value) !== value) throw unavailable();
  return value;
}
export async function callAgent(profileInput, operation, query, signal) {
  const profile = agentProfile(profileInput), id = randomUUID();
  if (process.platform !== "win32" || !["state", "pair", "import", "search"].includes(operation) || signal?.aborted) throw unavailable();
  if (operation === "search") candidateQuery(query);
  const entry = path.join(workspace, "apps/electron/dist/apps/electron/src/main.js");
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(?:PASSWORD_MANAGER_|ELECTRON_|NODE_OPTIONS$|NODE_PATH$|SSLKEYLOGFILE$)/i.test(key)) delete env[key];
  env.ELECTRON_NO_ATTACH_CONSOLE = "1";
  const child = spawn(createRequire(import.meta.url)("electron"), [entry, `--cipher-vault-agent=${profile}`, `--user-data-dir=${profile}`, "--disable-logging"], { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const chunks = []; let length = 0, cancelled = false;
  const stop = () => { cancelled = true; child.kill(); };
  const timer = setTimeout(stop, operation === "pair" || operation === "import" ? 120000 : 45000); signal?.addEventListener("abort", stop, { once: true });
  child.stdout.on("data", chunk => { length += chunk.length; if (length > 65542) stop(); else chunks.push(chunk); });
  child.stderr.resume(); child.stdin.on("error", () => {});
  const closed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  child.stdin.end(encodeBrowserMessage({ version: 1, id, operation, ...(operation === "search" ? { query } : {}) }));
  try {
    const code = await closed; if (cancelled || signal?.aborted || code !== 0) throw unavailable();
    let bytes = Buffer.concat(chunks); if (bytes.subarray(0, 2).equals(Buffer.from([13, 10]))) bytes = bytes.subarray(2);
    const response = new BrowserMessageDecoder().push(bytes);
    if (!response || Object.keys(response).sort().join(",") !== "id,ok,result,version" || response.version !== 1 || response.id !== id || response.ok !== true) throw unavailable();
    if (operation === "search") {
      if (!response.result || Object.keys(response.result).join(",") !== "items") throw unavailable();
      return { items: candidateResult(response.result.items) };
    }
    const result = response.result;
    if (!result || typeof result !== "object" || !["unpaired", "request-ready", "configured"].includes(result.state) ||
        Object.keys(result).sort().join(",") !== (result.cancelled === true ? "cancelled,displayName,fingerprint256,state" : "displayName,fingerprint256,state") ||
        (result.state === "unpaired" ? result.displayName !== null || result.fingerprint256 !== null :
          typeof result.fingerprint256 !== "string" || !/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(result.fingerprint256) ||
          result.displayName !== `Codex MCP · ${result.fingerprint256.replaceAll(":", "").slice(0, 8)}`)) throw unavailable();
    return result;
  } catch { throw unavailable(); }
  finally { clearTimeout(timer); signal?.removeEventListener("abort", stop); }
}
