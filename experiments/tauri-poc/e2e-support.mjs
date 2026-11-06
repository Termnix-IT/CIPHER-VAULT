// Helpers for verify-ui.mjs and verify-write.mjs. The generic WebView2 driving lives in
// scripts/lib/webview-e2e.mjs; what is left here knows the prototype's environment and screen.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { sleep, startE2eProcess, until } from "../../scripts/lib/webview-e2e.mjs";

export { connect, powershell, screenshot, sendOsMessage, sleep, until } from "../../scripts/lib/webview-e2e.mjs";

export const digest = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

export async function submitPassword(page, password) {
  await page.evaluate(`document.querySelector('input[aria-label="マスターパスワード"]').focus(); document.querySelector('input[aria-label="マスターパスワード"]').select()`);
  await page.send("Input.insertText", { text: password });
  await page.evaluate(`document.querySelector('button[type="submit"]').click()`);
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

export const startE2eBuild = (exe, database, port, extraEnvironment = {}) =>
  startE2eProcess(exe, port, { CIPHER_VAULT_POC_DB: database, ...extraEnvironment });
