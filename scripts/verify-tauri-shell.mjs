// Checks the Tauri app in apps/desktop through its `e2e` build: it refuses to start without a test
// folder or on a folder holding real data, the screen sets up, adds to, locks and unlocks a vault
// in a temporary folder through the Rust core, saves a backup and restores it into the emptied
// vault, audits it, migrates it to the v2 format and opens it with the new password. It copies through the
// e2e build's fake clipboard (the user's clipboard is never written), checks that copies expire and that
// screen lock and sleep notifications lock the vault and clear the copy, that a second launch on the same
// folder exits, and that closing the window locks, clears and exits. This build is not the setup, so the
// version dialog offers only the releases page and checking for updates does nothing. The window keeps
// refusing outside connections, navigation, new windows, downloads it did not make and ungranted
// commands, the updater plugin's own commands included. Only synthetic passwords are used.
// Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect, powershell, screenshot, sendOsMessage, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const [exe, screenshotDirectory] = process.argv.slice(2);
if (!exe || !screenshotDirectory) throw new Error("Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>");
mkdirSync(screenshotDirectory, { recursive: true });

const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const RELEASE_PAGE = "https://github.com/Termnix-IT/CIPHER-VAULT/releases/latest";
const PASSWORD = "synthetic-shell-check-password";
const BACKUP_PASSPHRASE = "synthetic-shell-backup-passphrase";
const MIGRATED_PASSWORD = "synthetic-shell-migrated-password";
const AWAY_MESSAGE = "画面ロック・スリープ中は保管庫を操作できません。OSへ戻ってから解除してください";
const CLIPBOARD_CLEAR_AFTER_MS = 30000;
// The messages Windows sends for a screen lock and for sleep (WM_WTSSESSION_CHANGE, WM_POWERBROADCAST).
const WM_POWERBROADCAST = 0x218, WM_WTSSESSION_CHANGE = 0x2b1;
const OS_SCENARIOS = [
  { name: "screenLock", away: [WM_WTSSESSION_CHANGE, 7], awayReason: "screen-lock", back: [WM_WTSSESSION_CHANGE, 8], backReason: "screen-unlock" },
  { name: "suspend", away: [WM_POWERBROADCAST, 4], awayReason: "suspend", back: [WM_POWERBROADCAST, 7], backReason: "resume" },
  { name: "suspendAutomaticResume", away: [WM_POWERBROADCAST, 4], awayReason: "suspend", back: [WM_POWERBROADCAST, 0x12], backReason: "resume" }
];
const PORT = 9341;
const settle = (page, expression) => page.evaluate(`Promise.resolve().then(() => ${expression}).then((value) => ({ value }), (error) => ({ error: String(error?.message ?? error) }))`);
const status = (page) => page.evaluate("window.passwordManager.fetchVaultStatus()");
const screenHas = (page, text) => page.evaluate(`document.body.innerText.includes(${JSON.stringify(text)})`);
const click = (page, selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
const menu = (page, group, item) => page.evaluate(`(() => {
  [...document.querySelectorAll(".app-menu-trigger")].find((node) => node.textContent === ${JSON.stringify(group)}).click();
  return new Promise((resolve) => setTimeout(() => {
    [...document.querySelectorAll(".app-menu-item")].find((node) => node.textContent.endsWith(${JSON.stringify(item)})).click();
    resolve(true);
  }, 100));
})()`);
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
const downloads = path.join(base, "downloads");
mkdirSync(data);
mkdirSync(downloads);
const result = { startupRefusals: startupRefusals(base) };
const { child, events, errors } = startE2eProcess(exe, PORT, { CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT), CIPHER_VAULT_E2E_PROFILE: profile, CIPHER_VAULT_DATA_DIR: data, CIPHER_VAULT_E2E_DOWNLOADS: downloads });
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

  // ---- A backup, saved through the screen and restored into the emptied vault
  await menu(page, "ツール", "バックアップ");
  await until("the backup dialog", () => page.evaluate(`!!document.querySelector("#backup-export")`));
  await type(page, "#backup-export label:nth-of-type(1) input", BACKUP_PASSPHRASE);
  await type(page, "#backup-export label:nth-of-type(2) input", BACKUP_PASSPHRASE);
  await click(page, 'button[form="backup-export"]');
  await until("the saved backup", () => events.includes("download-finished true"));
  const [backupName] = readdirSync(downloads);
  assert.match(backupName, /^CIPHER-VAULT-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z\.cvault$/);
  const backupFile = readFileSync(path.join(downloads, backupName), "utf8");
  const envelope = JSON.parse(backupFile);
  assert.equal(envelope.format, "CIPHER-VAULT");
  assert.equal(envelope.version, 1);
  assert.equal(backupFile.includes(generated) || backupFile.includes("synthetic-shell-id"), false, "the backup is encrypted");
  assert.equal(await screenHas(page, "ファイルの保存を始めました"), true);
  result.backupSaved = { version: envelope.version, name: "CIPHER-VAULT-<time>.cvault" };
  await screenshot(page, screenshotDirectory, "tauri-shell-backup");
  await click(page, 'button[aria-label="閉じる"]');

  // A download the screen did not make is refused and nothing is saved. A data: link is stopped by
  // the navigation guard before WebView2 starts a download; the download guard covers the rest.
  await page.evaluate(`(() => { const anchor = document.createElement("a"); anchor.href = "data:application/octet-stream,x"; anchor.download = "other.cvault"; document.body.append(anchor); anchor.click(); anchor.remove(); })()`);
  await sleep(1500);
  assert.deepEqual(readdirSync(downloads), [backupName]);
  assert.equal(events.filter((event) => event.startsWith("download-finished")).length, 1);
  result.otherDownloadRefused = true;

  const unlocked = await status(page);
  await page.evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(listed[0].id)}, ${JSON.stringify(unlocked.sessionId)})`);
  await menu(page, "ファイル", "一覧を更新");
  await until("the emptied list", async () => !(await screenHas(page, "画面で追加")));
  await menu(page, "ツール", "バックアップ");
  await until("the backup dialog", () => page.evaluate(`!!document.querySelector("#backup-export")`));
  await page.evaluate(`[...document.querySelectorAll('[role="tab"]')].find((node) => node.textContent === "読み込む").click()`);
  await until("the restore form", () => page.evaluate(`!!document.querySelector("#backup-restore")`));
  const { result: input } = await page.send("Runtime.evaluate", { expression: `document.querySelector('#backup-restore input[type="file"]')` });
  await page.send("DOM.setFileInputFiles", { objectId: input.objectId, files: [path.join(downloads, backupName)] });
  await type(page, '#backup-restore input[type="password"]', "synthetic-wrong-backup-phrase");
  await until("the restore button", () => page.evaluate(`!document.querySelector('button[form="backup-restore"]').disabled`));
  await click(page, 'button[form="backup-restore"]');
  await until("the wrong passphrase", () => screenHas(page, "パスフレーズが違うか、バックアップファイルが破損しています"));
  await type(page, '#backup-restore input[type="password"]', BACKUP_PASSPHRASE);
  await click(page, 'button[form="backup-restore"]');
  await until("the restore", () => screenHas(page, "1件を読み込みました。"));
  await click(page, 'button[aria-label="閉じる"]');
  await until("the restored entry", () => screenHas(page, "画面で追加"));
  const restoredSession = (await status(page)).sessionId;
  const [restored] = (await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(restoredSession)})`)).items;
  assert.equal(restored.id, listed[0].id);
  assert.equal((await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(restored.id)}, ${JSON.stringify(restoredSession)})`)).password, generated);
  result.restoredThroughScreen = true;
  result.restoreIntoFullVault = await settle(page, `window.passwordManager.restoreBackup({ passphrase: ${JSON.stringify(BACKUP_PASSPHRASE)}, content: ${JSON.stringify(backupFile)} }, ${JSON.stringify(restoredSession)})`);
  assert.deepEqual(result.restoreIntoFullVault, { error: "復元できるのは空の保管庫のみです" });

  // ---- The audit, through the screen. The generated password is strong and unique, and the entry has no URL.
  await menu(page, "ツール", "パスワードの点検");
  await until("the audit", () => page.evaluate(`document.querySelector(".audit-score strong")?.textContent === "100"`));
  result.audit = await page.evaluate(`window.passwordManager.auditVault(${JSON.stringify(restoredSession)})`);
  assert.equal(result.audit.total, 1);
  assert.deepEqual(result.audit.counts, { weak: 0, duplicate: 0, oldPassword: 0, missingUrl: 1, staleEntry: 0 });
  assert.equal(JSON.stringify(result.audit).includes(generated), false, "the audit never carries a password");
  result.audit = { score: result.audit.score, total: result.audit.total, counts: result.audit.counts };
  await screenshot(page, screenshotDirectory, "tauri-shell-audit");
  await click(page, 'button[aria-label="閉じる"]');

  // ---- Migration to the v2 format, through the screen. The vault locks and opens with the new password only.
  await menu(page, "ツール", "保管庫を更新…");
  await until("the maintenance form", () => page.evaluate(`!!document.querySelector("#maintenance-form")`));
  const maintenanceField = (index) => `#maintenance-form .maintenance-fields label:nth-of-type(${index}) input`;
  for (const [index, text] of [PASSWORD, MIGRATED_PASSWORD, MIGRATED_PASSWORD, BACKUP_PASSPHRASE, BACKUP_PASSPHRASE].entries()) {
    await type(page, maintenanceField(index + 1), text);
  }
  await click(page, 'button[form="maintenance-form"]');
  await until("the migration", () => screenHas(page, "変更しました。新しいマスターパスワードで開いてください。"), 120000);
  const migrated = await status(page);
  assert.deepEqual({ isUnlocked: migrated.isUnlocked, maintenance: migrated.maintenance }, { isUnlocked: false, maintenance: { state: "ready", format: "v2" } });
  await screenshot(page, screenshotDirectory, "tauri-shell-migrated");
  await click(page, '.vault-maintenance-dialog button[aria-label="閉じる"]');
  await submitPassword(page, PASSWORD, false);
  await until("the refusal of the old password", () => screenHas(page, "マスターパスワードが正しくありません"));
  await submitPassword(page, MIGRATED_PASSWORD, false);
  await until("the migrated list", async () => !(await lockScreenShown(page)) && (await screenHas(page, "画面で追加")));
  const migratedSession = (await status(page)).sessionId;
  const [carried] = (await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(migratedSession)})`)).items;
  assert.equal((await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(carried.id)}, ${JSON.stringify(migratedSession)})`)).password, generated);
  const files = readdirSync(data, { recursive: true }).map((name) => path.join(data, name)).filter((file) => statSync(file).isFile());
  assert.ok(files.some((file) => path.basename(file) === "vault-current.json"), "the v2 vault is selected");
  result.migratedThroughScreen = { format: "v2", passwordInPlainText: files.some((file) => readFileSync(file).includes(Buffer.from(generated))) };
  assert.equal(result.migratedThroughScreen.passwordInPlainText, false);

  // ---- The clipboard and the OS. Only the vault-locked and clipboard reports are compared.
  const osWindow = events.find((event) => event.startsWith("os-window ")).split(" ")[1];
  const reportsSince = (mark) => events.slice(mark).filter((event) => event.startsWith("vault-locked ") || event.startsWith("clipboard-"));
  const copy = async () => settle(page, `window.passwordManager.copyText("synthetic-clipboard-value", ${JSON.stringify((await status(page)).sessionId)})`);
  let mark = events.length;
  await click(page, `button[data-entry-id="${carried.id}"]`);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "画面で追加"`));
  await menu(page, "編集", "パスワードをコピー");
  await until("the copy notice", () => screenHas(page, "パスワードをコピーしました"));
  assert.deepEqual(reportsSince(mark), ["clipboard-write"]);
  mark = events.length;
  await menu(page, "ファイル", "ロック");
  await until("the cleared copy", () => events.slice(mark).includes("clipboard-clear"));
  result.copyThroughScreen = { lockReports: reportsSince(mark).sort() };
  assert.deepEqual(result.copyThroughScreen.lockReports, ["clipboard-clear", "vault-locked manual"]);

  result.osEvents = {};
  for (const scenario of OS_SCENARIOS) {
    await submitPassword(page, MIGRATED_PASSWORD, false);
    await until("the unlocked list", async () => (await status(page)).isUnlocked);
    assert.deepEqual(await copy(), { value: null });
    mark = events.length;
    sendOsMessage(osWindow, scenario.away);
    await until("the cleared copy", () => events.slice(mark).includes("clipboard-clear"));
    const away = await status(page);
    // While away, unlocking is refused even with the right password.
    const refused = await settle(page, `window.passwordManager.unlockVault({ masterPassword: ${JSON.stringify(MIGRATED_PASSWORD)} }, ${JSON.stringify(away.sessionId)})`);
    sendOsMessage(osWindow, scenario.back);
    const back = await status(page);
    result.osEvents[scenario.name] = { reports: reportsSince(mark), awayReason: away.lockReason, refused: refused.error, backReason: back.lockReason };
    assert.deepEqual(result.osEvents[scenario.name], { reports: [`vault-locked ${scenario.awayReason}`, "clipboard-clear", `vault-locked ${scenario.backReason}`], awayReason: scenario.awayReason, refused: AWAY_MESSAGE, backReason: scenario.backReason });
    assert.equal(back.isUnlocked, false, "returning never unlocks by itself");
  }

  // A copy clears itself after 30 seconds while the vault stays open.
  await submitPassword(page, MIGRATED_PASSWORD, false);
  await until("the unlocked list", async () => (await status(page)).isUnlocked);
  assert.deepEqual(await copy(), { value: null });
  mark = events.length;
  const copiedAt = Date.now();
  await until("the copy to expire", () => events.slice(mark).includes("clipboard-clear"), CLIPBOARD_CLEAR_AFTER_MS + 5000);
  result.copyExpiry = { afterSeconds: Math.round((Date.now() - copiedAt) / 1000), stillUnlocked: (await status(page)).isUnlocked };
  assert.ok(result.copyExpiry.afterSeconds >= 29, "not before the deadline");
  assert.equal(result.copyExpiry.stillUnlocked, true);
  result.copyRefusedForOtherSession = await settle(page, `window.passwordManager.copyText("x", "another-session")`);
  assert.ok(result.copyRefusedForOtherSession.error);

  // A second launch on the same folder exits before it opens the vault.
  const second = spawnSync(exe, [], { env: { ...process.env, CIPHER_VAULT_DATA_DIR: data }, encoding: "utf8", timeout: 20000 });
  result.secondLaunch = { exitCode: second.status, reported: second.stdout.includes("e2e-event already-running") };
  assert.deepEqual(result.secondLaunch, { exitCode: 0, reported: true });

  // ---- Updates. Only the setup updates itself, so this build points to the releases page.
  const unsupported = { status: "unsupported", currentVersion: VERSION };
  result.updates = { support: events.find((event) => event.startsWith("update-support ")), state: await settle(page, "window.passwordManager.getUpdateState()") };
  assert.deepEqual(result.updates, { support: "update-support false", state: { value: unsupported } });
  await menu(page, "ヘルプ", "バージョンと更新");
  await until("the version dialog", () => screenHas(page, "このバージョンはアプリ内で更新できません"));
  assert.equal(await page.evaluate(`[...document.querySelectorAll(".app-info-actions button")].map((node) => node.textContent).join()`), "ダウンロードページを開く");
  await page.evaluate(`[...document.querySelectorAll(".app-info-actions button")].find((node) => node.textContent === "ダウンロードページを開く").click()`);
  await until("the releases page", () => events.includes(`release-page ${RELEASE_PAGE}`));
  await page.evaluate(`document.querySelector(".app-info-dialog").close()`);
  result.updates.check = await settle(page, "window.passwordManager.checkForUpdates()");
  result.updates.download = await settle(page, "window.passwordManager.downloadUpdate()");
  result.updates.install = await settle(page, "window.passwordManager.installUpdate(false)");
  result.updates.invalidInstall = await settle(page, `window.passwordManager.installUpdate("yes")`);
  result.updates.after = await settle(page, "window.passwordManager.getUpdateState()");
  assert.deepEqual(result.updates, { ...result.updates, check: { value: null }, download: { value: null }, install: { value: null }, invalidInstall: { error: "Invalid update request" }, after: { value: unsupported } });
  // The plugin registers its own commands for the screen, but no capability grants them.
  for (const command of ["check", "download", "install", "download_and_install"]) {
    const refused = await settle(page, `window.__TAURI_INTERNALS__.invoke("plugin:updater|${command}", {})`);
    assert.match(refused.error ?? "", new RegExp(`^updater\\.${command} not allowed\\. Permissions`), `plugin:updater|${command} must be refused for lack of permission`);
  }
  assert.ok(!events.includes("update-dialog"), "no update step ran");

  // ---- The shell
  await until("the IPC response", () => page.responses.some((response) => response.url.startsWith("http://ipc.localhost/vault_status")));
  result.ipcCommands = [...new Set(page.responses.filter((response) => response.url.startsWith("http://ipc.localhost/")).map(({ url, status }) => `${status} ${new URL(url).pathname}`))];
  result.apiFrozen = await page.evaluate(`Object.isFrozen(window.passwordManager) && !Object.getOwnPropertyDescriptor(window, "passwordManager").writable`);
  assert.equal(result.apiFrozen, true);

  result.outsideFetch = await settle(page, `fetch("https://example.test/")`);
  assert.ok(result.outsideFetch.error, "an outside connection must fail");
  result.ungrantedCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("plugin:window|set_title", { label: "main", value: "changed" })`);
  assert.ok(result.ungrantedCommand.error, "a command no capability grants must be refused");
  result.unknownCommand = await settle(page, `window.__TAURI_INTERNALS__.invoke("update_apply", {})`);
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

  // ---- Closing the window locks the vault, clears this app's copy and exits.
  assert.deepEqual(await copy(), { value: null });
  mark = events.length;
  powershell(`[void](Get-Process -Id ${child.pid}).CloseMainWindow()`);
  await until("the app to exit", () => child.exitCode !== null);
  const exitReports = [...new Set(events.slice(mark).filter((event) => event !== "renderer-gone"))];
  result.exit = { exitCode: child.exitCode, reports: exitReports };
  assert.deepEqual(result.exit, { exitCode: 0, reports: ["vault-locked window-closed", "clipboard-clear", "exit-complete"] });
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
