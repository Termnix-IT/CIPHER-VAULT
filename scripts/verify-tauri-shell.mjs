// Checks the Tauri app in apps/desktop through its `e2e` build: it refuses to start without a test
// folder or on a folder holding real data, the screen sets up a v2 vault, adds to, locks and unlocks it
// in a temporary folder through the Rust core, saves a backup and restores it into the emptied
// vault, audits it, changes its master password and opens it with the new one. It copies through the
// e2e build's fake clipboard (the user's clipboard is never written), checks that copies expire and that
// screen lock and sleep notifications lock the vault and clear the copy, that a second launch on the same
// folder exits, and that closing the window locks, clears and exits. This build is not the setup, so the
// version dialog offers only the releases page and checking for updates does nothing. The call-up shortcut
// is set through the screen and pressed through the e2e build's marker file, so no real key is needed;
// the compact window is resized and its size is kept for the next time. The window keeps
// refusing outside connections, navigation, new windows, downloads it did not make and ungranted
// commands, the updater plugin's own commands included. Only synthetic passwords are used.
// Usage: node scripts/verify-tauri-shell.mjs <e2e-exe> <screenshot-directory>
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
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
const NEW_PASSWORD = "synthetic-shell-changed-password";
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
  document.querySelector(${JSON.stringify(`.app-menu-trigger[aria-label="${group}"]`)}).click();
  return new Promise((resolve) => setTimeout(() => {
    // The label is compared without its shortcut hint.
    [...document.querySelectorAll(".app-menu-item")].find((node) => [...node.childNodes].filter((child) => !child.classList?.contains("app-menu-shortcut")).map((child) => child.textContent).join("").endsWith(${JSON.stringify(item)})).click();
    resolve(true);
  }, 100));
})()`);
const ALT = 1, CTRL = 2, SHIFT = 8;
/** A shortcut as the keyboard sends it: rawKeyDown types nothing, as with Ctrl held. */
async function press(page, code, key, keyCode, modifiers) {
  await page.send("Input.dispatchKeyEvent", { type: "rawKeyDown", modifiers, key, code, windowsVirtualKeyCode: keyCode });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", modifiers, key, code, windowsVirtualKeyCode: keyCode });
}
/** Sets a select the way a person does, so React sees the change. */
const choose = (page, selector, value) => page.evaluate(`(() => {
  const select = document.querySelector(${JSON.stringify(selector)});
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(select, ${JSON.stringify(value)});
  select.dispatchEvent(new Event("change", { bubbles: true }));
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
const summonFile = path.join(base, "summon");
mkdirSync(data);
mkdirSync(downloads);
const result = { startupRefusals: startupRefusals(base) };
const { child, events, errors } = startE2eProcess(exe, PORT, { CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT), CIPHER_VAULT_E2E_PROFILE: profile, CIPHER_VAULT_DATA_DIR: data, CIPHER_VAULT_E2E_DOWNLOADS: downloads, CIPHER_VAULT_E2E_SUMMON_FILE: summonFile });
let page;
try {
  page = await connect(PORT);
  await until("the screen", () => page.evaluate(`document.readyState === "complete" && document.title === "CIPHER VAULT" && !!window.passwordManager`));

  // ---- The vault, through the screen
  const initial = await status(page);
  assert.equal(initial.isConfigured, false);
  assert.equal(initial.isUnlocked, false);
  // No vault and no setting yet: the original five minutes. Setup writes fifteen (checked below).
  assert.deepEqual({ minutes: initial.autoLockMinutes, idleTimeoutMs: initial.idleTimeoutMs }, { minutes: 5, idleTimeoutMs: 300000 });
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

  // Setup made a v2 vault in the test folder, selected by its pointer, with no legacy file, and
  // neither the password nor the names are stored as plain text.
  const vaultFiles = () => readdirSync(data, { recursive: true }).map((name) => path.join(data, name)).filter((file) => statSync(file).isFile());
  assert.ok(vaultFiles().some((file) => path.basename(file) === "vault-current.json"), "the v2 vault is selected");
  assert.equal(vaultFiles().some((file) => path.basename(file) === "password-manager.db"), false, "no legacy file is made");
  result.passwordInPlainText = vaultFiles().some((file) => ["synthetic-shell-id", "画面で追加", generated].some((text) => readFileSync(file).includes(Buffer.from(text))));
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
  // An open dialog blocks the rest of the screen, the menus included, but not the window buttons of
  // the title bar, and Escape still closes it.
  result.dialogBlocking = await page.evaluate(`({
    menus: !!document.querySelector(".app-menu-bar").closest("[inert]"),
    list: !!document.querySelector(".vault-sidebar").closest("[inert]"),
    windowButtons: !!document.querySelector(".window-controls").closest("[inert]"),
    dialog: !!document.querySelector("dialog[open]").closest("[inert]")
  })`);
  assert.deepEqual(result.dialogBlocking, { menus: true, list: true, windowButtons: false, dialog: false });
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await until("the closed dialog", () => page.evaluate(`!document.querySelector("dialog[open]") && !document.querySelector("[inert]") && !document.querySelector(".modal-backdrop")`));

  // A download the screen did not make is refused and nothing is saved. A data: link is stopped by
  // the navigation guard before WebView2 starts a download; the download guard covers the rest.
  await page.evaluate(`(() => { const anchor = document.createElement("a"); anchor.href = "data:application/octet-stream,x"; anchor.download = "other.cvault"; document.body.append(anchor); anchor.click(); anchor.remove(); })()`);
  await sleep(1500);
  assert.deepEqual(readdirSync(downloads), [backupName]);
  // Whichever guard stops it, only the backup finished saving; a download the guard refused ends as unsaved.
  assert.equal(events.filter((event) => event === "download-finished true").length, 1);
  assert.equal(events.filter((event) => event === "download-finished false").length, events.filter((event) => event === "download-refused").length);
  result.otherDownloadRefused = true;

  const unlocked = await status(page);
  await page.evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(listed[0].id)}, ${JSON.stringify(unlocked.sessionId)})`);
  await menu(page, "項目", "一覧を更新");
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
  await click(page, 'dialog[open] button[aria-label="閉じる"]');
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
  await click(page, 'dialog[open] button[aria-label="閉じる"]');

  // ---- A new master password, through the screen. The vault locks and opens with the new password only.
  await menu(page, "ツール", "マスターパスワードを変更…");
  await until("the maintenance form", () => page.evaluate(`!!document.querySelector("#maintenance-form")`));
  const maintenanceField = (index) => `#maintenance-form .maintenance-fields label:nth-of-type(${index}) input`;
  for (const [index, text] of [PASSWORD, NEW_PASSWORD, NEW_PASSWORD, BACKUP_PASSPHRASE, BACKUP_PASSPHRASE].entries()) {
    await type(page, maintenanceField(index + 1), text);
  }
  await click(page, 'button[form="maintenance-form"]');
  await until("the new password", () => screenHas(page, "変更しました。新しいマスターパスワードで開いてください。"), 120000);
  const rekeyed = await status(page);
  assert.deepEqual({ isUnlocked: rekeyed.isUnlocked, maintenance: rekeyed.maintenance }, { isUnlocked: false, maintenance: { state: "ready", format: "v2" } });
  await screenshot(page, screenshotDirectory, "tauri-shell-rekeyed");
  await click(page, '.vault-maintenance-dialog button[aria-label="閉じる"]');
  await submitPassword(page, PASSWORD, false);
  await until("the refusal of the old password", () => screenHas(page, "マスターパスワードが正しくありません"));
  await submitPassword(page, NEW_PASSWORD, false);
  await until("the list after the new password", async () => !(await lockScreenShown(page)) && (await screenHas(page, "画面で追加")));
  const rekeyedSession = (await status(page)).sessionId;
  const [carried] = (await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(rekeyedSession)})`)).items;
  assert.equal((await page.evaluate(`window.passwordManager.fetchEntry(${JSON.stringify(carried.id)}, ${JSON.stringify(rekeyedSession)})`)).password, generated);
  result.rekeyedThroughScreen = { passwordInPlainText: vaultFiles().some((file) => readFileSync(file).includes(Buffer.from(generated))) };
  assert.equal(result.rekeyedThroughScreen.passwordInPlainText, false);

  // ---- The title bar shows icons only, each named for tooltips and screen readers.
  result.titleBar = await page.evaluate(`({
    text: document.querySelector(".app-titlebar").innerText.trim(),
    names: [...document.querySelectorAll(".app-menu-bar button")].map((node) => node.getAttribute("aria-label"))
  })`);
  assert.deepEqual(result.titleBar, { text: "", names: ["一覧をアイコンだけにする", "項目", "表示", "ツール", "バージョンと更新", "ロック"] });

  // ---- An icon set through the screen is kept encrypted inside its entry, and the list shows it.
  const row = `button[data-entry-id="${carried.id}"]`;
  await click(page, row);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "画面で追加"`));
  await click(page, ".inspector-icon");
  await until("the icon editor", () => page.evaluate(`!!document.querySelector(".icon-picker")`));
  await page.evaluate(`[...document.querySelectorAll('.icon-picker [role="tab"]')].find((node) => node.textContent === "SVG").click()`);
  await until("the symbols", () => page.evaluate(`!!document.querySelector('.icon-picker-symbol[aria-label="銀行"]')`));
  await click(page, '.icon-picker-symbol[aria-label="銀行"]');
  await page.evaluate(`[...document.querySelectorAll(".icon-picker-actions button")].find((node) => node.textContent === "保存").click()`);
  await until("the saved icon", () => page.evaluate(`!document.querySelector(".icon-picker") && !!document.querySelector(${JSON.stringify(`${row} .entry-badge--colored svg`)})`));
  const iconSession = (await status(page)).sessionId;
  result.entryIcon = (await page.evaluate(`window.passwordManager.fetchEntries(${JSON.stringify(iconSession)})`)).items.find((item) => item.id === carried.id).icon;
  assert.deepEqual(result.entryIcon, { kind: "symbol", symbol: "bank", color: "teal" });
  assert.equal(vaultFiles().some((file) => path.basename(file) === "entry-icons.json"), false, "no icon file beside the vault");
  assert.equal(vaultFiles().some((file) => ["teal", "画面で追加"].some((text) => readFileSync(file).includes(Buffer.from(text)))), false, "the icon is encrypted");
  result.entryIconRefusals = {
    svgImage: await settle(page, `window.passwordManager.setEntryIcon(${JSON.stringify(carried.id)}, { kind: "image", image: "data:image/svg+xml;base64,PHN2Zz4=" }, ${JSON.stringify(iconSession)})`),
    unknownEntry: await settle(page, `window.passwordManager.setEntryIcon("missing", { kind: "letter", color: "red" }, ${JSON.stringify(iconSession)})`)
  };
  assert.deepEqual(result.entryIconRefusals, { svgImage: { error: "アイコンの形式が正しくありません" }, unknownEntry: { error: "エントリが見つかりません" } });

  // ---- The list pane folds to one column of icons from the title bar and remembers it.
  await click(page, '.app-menu-bar button[aria-label="一覧をアイコンだけにする"]');
  await until("the folded list", () => page.evaluate(`!!document.querySelector(".cipher-dashboard--collapsed") && !document.querySelector(".entry-info") && document.querySelector(${JSON.stringify(row)}).getAttribute("data-tooltip") === "画面で追加"`));
  // The pane narrows in a short animation.
  await until("the narrow pane", () => page.evaluate(`document.querySelector(".vault-sidebar").getBoundingClientRect().width <= 64`));
  await screenshot(page, screenshotDirectory, "tauri-shell-folded");
  result.foldedList = await page.evaluate(`({ saved: localStorage.getItem("cipher-vault.sidebar-collapsed"), width: document.querySelector(".vault-sidebar").getBoundingClientRect().width, resizer: !!document.querySelector(".pane-resizer") })`);
  assert.deepEqual(result.foldedList, { saved: "true", width: result.foldedList.width, resizer: false });
  assert.ok(result.foldedList.width <= 64, "the folded pane is narrow");
  await click(page, '.app-menu-bar button[aria-label="一覧を広げる"]');
  await until("the full list", () => page.evaluate(`!document.querySelector(".cipher-dashboard--collapsed") && !!document.querySelector(".entry-info")`));
  // The pane's edge moves with the keyboard as with the pointer, and the width is kept.
  await page.evaluate(`document.querySelector(".pane-resizer").focus()`);
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39 });
  await until("the wider pane", () => page.evaluate(`localStorage.getItem("cipher-vault.sidebar-width") === "296"`));
  // A narrow window shows the widest list narrower, so the detail keeps 440px, and keeps the saved width.
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: "End", code: "End", windowsVirtualKeyCode: 35 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: "End", code: "End", windowsVirtualKeyCode: 35 });
  await until("the widest pane", () => page.evaluate(`localStorage.getItem("cipher-vault.sidebar-width") === "440"`));
  const paneAt = async (width) => {
    await page.send("Emulation.setDeviceMetricsOverride", { width, height: 560, deviceScaleFactor: 1, mobile: false });
    await sleep(400);
    return page.evaluate(`({ list: document.querySelector(".vault-sidebar").getBoundingClientRect().width, detail: document.querySelector(".vault-detail").getBoundingClientRect().width,
      max: document.querySelector(".pane-resizer").getAttribute("aria-valuemax"), saved: localStorage.getItem("cipher-vault.sidebar-width") })`);
  };
  result.paneInNarrowWindow = { at720: await paneAt(720), at880: await paneAt(880) };
  await page.send("Emulation.clearDeviceMetricsOverride");
  assert.deepEqual(result.paneInNarrowWindow, { at720: { list: 280, detail: 440, max: "280", saved: "440" }, at880: { list: 440, detail: 440, max: "440", saved: "440" } });
  await page.evaluate(`localStorage.removeItem("cipher-vault.sidebar-width")`);

  // ---- The clipboard and the OS. Only the vault-locked and clipboard reports are compared.
  const osWindow = events.find((event) => event.startsWith("os-window ")).split(" ")[1];

  // ---- The window opens at 960x680, or smaller on a work area that cannot hold it. Its 720x560
  // minimum applies only while the user drags its edge, which this check cannot do; it is checked by hand.
  const initialSize = powershell(`Add-Type -Namespace E2E -Name Size -MemberDefinition '
      [DllImport("user32.dll")] public static extern bool GetClientRect(System.IntPtr w, out RECT r);
      [DllImport("user32.dll")] public static extern uint GetDpiForWindow(System.IntPtr w);
      public struct RECT { public int Left, Top, Right, Bottom; }'
    $w = (Get-Process -Id ${child.pid}).MainWindowHandle
    $s = [E2E.Size]::GetDpiForWindow($w) / 96
    $r = New-Object E2E.Size+RECT; [void][E2E.Size]::GetClientRect($w, [ref]$r)
    "$([math]::Round($r.Right / $s)) $([math]::Round($r.Bottom / $s))"`).split(" ").map(Number);
  result.initialWindowSize = initialSize;
  assert.equal(initialSize[0], 960, "the default width");
  assert.ok(initialSize[1] >= 560 && initialSize[1] <= 680, "the default height, or the work area's");
  // ---- Usability: the auto-lock setting, favorites, recent use, the URL, the shortcuts and the compact layout.
  // The window's client size in logical pixels, and whether it is kept above other windows.
  // The window is found by its title among the process's visible top-level windows, because MainWindowHandle
  // can name another visible window of the same process.
  const windowState = () => powershell(`Add-Type -Namespace E2E -Name State -MemberDefinition '
      public delegate bool EnumProc(System.IntPtr w, System.IntPtr l);
      [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, System.IntPtr l);
      [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr w, out uint p);
      [DllImport("user32.dll")] public static extern bool IsWindowVisible(System.IntPtr w);
      [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(System.IntPtr w, System.Text.StringBuilder s, int n);
      [DllImport("user32.dll")] public static extern bool GetClientRect(System.IntPtr w, out RECT r);
      [DllImport("user32.dll")] public static extern uint GetDpiForWindow(System.IntPtr w);
      [DllImport("user32.dll")] public static extern int GetWindowLong(System.IntPtr w, int i);
      [DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow();
      public struct RECT { public int Left, Top, Right, Bottom; }'
    $script:w = [System.IntPtr]::Zero
    [void][E2E.State]::EnumWindows({ param($h, $l) $p = 0; [void][E2E.State]::GetWindowThreadProcessId($h, [ref]$p)
      $t = New-Object System.Text.StringBuilder 64; [void][E2E.State]::GetWindowText($h, $t, 64)
      if ($p -eq ${child.pid} -and [E2E.State]::IsWindowVisible($h) -and $t.ToString() -eq "CIPHER VAULT") { $script:w = $h; return $false }
      $true }, [System.IntPtr]::Zero)
    $w = $script:w
    $s = [E2E.State]::GetDpiForWindow($w) / 96
    $r = New-Object E2E.State+RECT; [void][E2E.State]::GetClientRect($w, [ref]$r)
    "$([math]::Round($r.Right / $s)) $([math]::Round($r.Bottom / $s)) $((([E2E.State]::GetWindowLong($w, -20)) -band 8) -ne 0) $([E2E.State]::GetForegroundWindow() -eq $w)"`).split(" ");
  // Resizes the window from outside. Unlike dragging its edge, this skips the app's minimum and maximum,
  // so only sizes inside them are used here.
  const resizeWindow = (width, height) => powershell(`Add-Type -Namespace E2E -Name Resize -MemberDefinition '
      public delegate bool EnumProc(System.IntPtr w, System.IntPtr l);
      [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, System.IntPtr l);
      [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr w, out uint p);
      [DllImport("user32.dll")] public static extern bool IsWindowVisible(System.IntPtr w);
      [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(System.IntPtr w, System.Text.StringBuilder s, int n);
      [DllImport("user32.dll")] public static extern uint GetDpiForWindow(System.IntPtr w);
      [DllImport("user32.dll")] public static extern bool SetWindowPos(System.IntPtr w, System.IntPtr a, int x, int y, int cx, int cy, uint f);
      [DllImport("user32.dll")] public static extern bool GetWindowRect(System.IntPtr w, out RECT r);
      [DllImport("user32.dll")] public static extern bool GetClientRect(System.IntPtr w, out RECT r);
      public struct RECT { public int Left, Top, Right, Bottom; }'
    $script:w = [System.IntPtr]::Zero
    [void][E2E.Resize]::EnumWindows({ param($h, $l) $p = 0; [void][E2E.Resize]::GetWindowThreadProcessId($h, [ref]$p)
      $t = New-Object System.Text.StringBuilder 64; [void][E2E.Resize]::GetWindowText($h, $t, 64)
      if ($p -eq ${child.pid} -and [E2E.Resize]::IsWindowVisible($h) -and $t.ToString() -eq "CIPHER VAULT") { $script:w = $h; return $false }
      $true }, [System.IntPtr]::Zero)
    $s = [E2E.Resize]::GetDpiForWindow($script:w) / 96
    $o = New-Object E2E.Resize+RECT; $c = New-Object E2E.Resize+RECT
    [void][E2E.Resize]::GetWindowRect($script:w, [ref]$o); [void][E2E.Resize]::GetClientRect($script:w, [ref]$c)
    # The sizes are of the inside of the window, as windowState reads them; the frame is added on.
    $fw = ($o.Right - $o.Left) - $c.Right; $fh = ($o.Bottom - $o.Top) - $c.Bottom
    [void][E2E.Resize]::SetWindowPos($script:w, [System.IntPtr]::Zero, 0, 0, [int](${width} * $s) + $fw, [int](${height} * $s) + $fh, 0x0016)`);
  const summonAndWait = async (label) => {
    const mark = events.length;
    writeFileSync(summonFile, "");
    await until(label, () => events.slice(mark).some((event) => event === "summoned" || event === "summon-hidden"));
    return events.slice(mark).find((event) => event === "summoned" || event === "summon-hidden");
  };
  // Waits for the window's topmost style, and names the last state it read when it times out.
  // Windows may not apply it to a window in the background, which happens when another window takes the
  // focus during the check; that case is reported as unverified instead of failing.
  const untilTopmost = async (expected) => {
    let last;
    await until(`the window's topmost style ${expected}`, () => (last = windowState())[2] === expected, 10000).catch((error) => {
      if (expected === "True" && last?.[3] === "False") { (result.topmostUnverified ??= []).push(last); return; }
      throw new Error(`${error.message}; last state ${JSON.stringify(last)}`);
    });
  };
  const settingsFile = path.join(data, "app-settings.json");
  const usable = await status(page);
  result.autoLock = { minutes: usable.autoLockMinutes, idleTimeoutMs: usable.idleTimeoutMs, file: readFileSync(settingsFile, "utf8") };
  assert.deepEqual(result.autoLock, { minutes: 15, idleTimeoutMs: 900000, file: '{"autoLockMinutes":15}' }, "a new vault locks after 15 minutes");
  await menu(page, "ツール", "設定…");
  await until("the settings", () => page.evaluate(`document.querySelector(".settings-dialog[open] select")?.value === "15"`));
  await choose(page, ".settings-dialog select", "off");
  await until("the warning", () => page.evaluate(`!!document.querySelector(".settings-warning")`));
  await screenshot(page, screenshotDirectory, "tauri-shell-settings");
  await click(page, '.settings-dialog button[type="submit"]');
  await until("the saved setting", async () => (await status(page)).idleTimeoutMs === null && !(await page.evaluate(`!!document.querySelector("dialog[open]")`)));
  assert.equal(readFileSync(settingsFile, "utf8"), '{"autoLockMinutes":null}');
  const settingSession = JSON.stringify((await status(page)).sessionId);
  result.autoLockRefused = await settle(page, `window.passwordManager.setAutoLock({ autoLockMinutes: 7 }, ${settingSession})`);
  assert.deepEqual(result.autoLockRefused, { error: "自動ロックの時間が正しくありません" });
  assert.equal((await settle(page, `window.passwordManager.setAutoLock({ autoLockMinutes: 15 }, ${settingSession})`)).value.idleTimeoutMs, 900000);

  const usableSession = JSON.stringify((await status(page)).sessionId);
  const login = (name, url) => `window.passwordManager.createEntry(${JSON.stringify({ serviceName: name, loginId: `synthetic-${name}-id`, password: `synthetic-${name}-password`, url, notes: "synthetic note", tags: [] })}, ${usableSession})`;
  const withUrl = await page.evaluate(login("URLあり", "https://example.test/login"));
  const scriptUrl = await page.evaluate(login("スクリプト", "javascript:alert(1)"));
  const fileUrl = await page.evaluate(login("ファイル", "file:///C:/Windows/win.ini"));
  const credentialUrl = await page.evaluate(login("認証付き", "https://user:secret@example.test/"));
  result.urlRefusals = {};
  for (const [name, entry] of Object.entries({ script: scriptUrl, file: fileUrl, credentials: credentialUrl, none: carried })) {
    result.urlRefusals[name] = await settle(page, `window.passwordManager.openEntryUrl(${JSON.stringify(entry.id)}, ${usableSession})`);
  }
  const REFUSED_URL = "開けるのは http:// か https:// で始まるWebのURLだけです";
  assert.deepEqual(result.urlRefusals, { script: { error: REFUSED_URL }, file: { error: REFUSED_URL }, credentials: { error: REFUSED_URL }, none: { error: "URLが登録されていません" } });
  assert.equal(events.some((event) => event.startsWith("url-opened ")), false, "a refused URL is never opened");
  for (const entry of [scriptUrl, fileUrl, credentialUrl]) await page.evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(entry.id)}, ${usableSession})`);
  await menu(page, "項目", "一覧を更新");
  const urlRow = `button[data-entry-id="${withUrl.id}"]`;
  await until("the new row", () => page.evaluate(`!!document.querySelector(${JSON.stringify(urlRow)}) && document.querySelectorAll(".entry-row").length === 2`));
  await click(page, urlRow);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "URLあり"`));
  // A favorite is kept encrypted inside its entry; the first one keeps a copy of the vault for older releases.
  await click(page, ".inspector-header .favorites-toggle");
  await until("the favorite star", () => page.evaluate(`!!document.querySelector(${JSON.stringify(`${urlRow} .entry-favorite`)})`));
  const favoriteItem = (await page.evaluate(`window.passwordManager.fetchEntries(${usableSession})`)).items.find((item) => item.id === withUrl.id);
  result.favorite = { favorite: favoriteItem.favorite, updatedAt: favoriteItem.updatedAt === withUrl.updatedAt,
    compatibilityCopy: vaultFiles().some((file) => path.basename(file) === "before-v5.sqlite"),
    plainText: vaultFiles().some((file) => ["favorite", "URLあり"].some((text) => readFileSync(file).includes(Buffer.from(text)))) };
  assert.deepEqual(result.favorite, { favorite: true, updatedAt: true, compatibilityCopy: true, plainText: false });
  await click(page, ".list-meta .favorites-toggle");
  await until("the favorites only", () => page.evaluate(`document.querySelectorAll(".entry-row").length === 1`));
  await click(page, ".list-meta .favorites-toggle");
  await until("every entry", () => page.evaluate(`document.querySelectorAll(".entry-row").length === 2`));

  // The shortcuts act on the open entry, copy through the fake clipboard, and count as using it.
  let usableMark = events.length;
  await press(page, "KeyB", "b", 66, CTRL);
  await until("the login ID copy", () => screenHas(page, "URLありのログインIDをコピーしました"));
  await press(page, "KeyC", "C", 67, CTRL | SHIFT);
  await until("the password copy", () => screenHas(page, "URLありのパスワードをコピーしました"));
  await press(page, "KeyU", "u", 85, CTRL);
  await until("the opened URL", () => events.slice(usableMark).includes("url-opened https://example.test/login"));
  result.shortcuts = { reports: events.slice(usableMark).filter((event) => event.startsWith("clipboard-") || event.startsWith("url-opened ")) };
  assert.deepEqual(result.shortcuts.reports, ["clipboard-write", "clipboard-write", "url-opened https://example.test/login"]);
  await until("the use date", async () => !!(await page.evaluate(`window.passwordManager.fetchEntries(${usableSession})`)).items.find((item) => item.id === withUrl.id).lastUsedAt);
  // A shortcut inside an open form does nothing to the clipboard, and Ctrl+F still finds the search.
  await click(page, ".sidebar-add");
  await until("the new form", () => page.evaluate(`!!(${field("サービス")})`));
  usableMark = events.length;
  await press(page, "KeyB", "b", 66, CTRL);
  await until("the refusal notice", () => screenHas(page, "編集を終えてから使えます"));
  assert.equal(events.slice(usableMark).some((event) => event.startsWith("clipboard-")), false);
  await page.evaluate(`[...document.querySelectorAll(".editor-actions button")].find((node) => node.textContent.trim() === "キャンセル").click()`);
  await press(page, "KeyF", "f", 70, CTRL);
  await until("the search focus", () => page.evaluate(`document.activeElement?.classList.contains("search-input")`));
  await click(page, urlRow);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "URLあり"`));

  // Compact: a narrow column with the sign-in values only, no maximize, and the normal size back afterwards.
  await press(page, "KeyM", "M", 77, CTRL | SHIFT);
  await until("the compact view", () => page.evaluate(`document.querySelector(".compact-detail-title")?.textContent === "URLあり"`));
  await sleep(500);
  result.compact = { window: windowState().slice(0, 3), ...await page.evaluate(`({
    fields: [...document.querySelectorAll(".compact-view .entry-view-field dt")].map((node) => node.textContent),
    notes: document.body.innerText.includes("synthetic note"),
    maximize: !!document.querySelector('.window-control[aria-label="最大化"]'),
    listToggle: !!document.querySelector('.app-menu-bar button[aria-label="一覧をアイコンだけにする"]')
  })`) };
  assert.deepEqual(result.compact, { window: ["400", result.compact.window[1], "False"], fields: ["ログインID", "パスワード", "URL"], notes: false, maximize: false, listToggle: false });
  await screenshot(page, screenshotDirectory, "tauri-shell-compact");
  usableMark = events.length;
  await click(page, '.compact-view button[aria-label="URLをブラウザで開く"]');
  await until("the opened URL", () => events.slice(usableMark).includes("url-opened https://example.test/login"));
  await page.evaluate(`document.querySelector(".compact-detail button").focus()`);
  await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
  await until("the compact list", () => page.evaluate(`!!document.querySelector(".compact-list")`));
  result.compactList = await page.evaluate(`[...document.querySelectorAll(".compact-list [role=group]")].map((node) => node.getAttribute("aria-label") + ":" + node.querySelectorAll(".entry-row").length)`);
  assert.deepEqual(result.compactList, ["お気に入り:1", "そのほか:1"]);
  // In the list, the shortcuts wait for an entry to be opened: the row in focus may not be the one opened before.
  usableMark = events.length;
  await press(page, "KeyC", "C", 67, CTRL | SHIFT);
  await until("the refusal in the list", () => screenHas(page, "項目を開いてから使えます"));
  assert.equal(events.slice(usableMark).some((event) => event.startsWith("clipboard-")), false);
  await type(page, ".compact-head .search-input", "画面");
  await until("the search", () => page.evaluate(`document.querySelectorAll(".compact-list .entry-row").length === 1`));
  await click(page, ".compact-pin");
  await until("the topmost report", () => events.includes("always-on-top true"));
  await untilTopmost("True");
  await menu(page, "表示", "ルミナスデザイン");
  await sleep(400);
  await screenshot(page, screenshotDirectory, "tauri-shell-compact-luminous");
  await menu(page, "表示", "シンプルデザイン");
  await click(page, ".compact-pin");
  await until("the normal report", () => events.includes("always-on-top false"));
  await untilTopmost("False");
  await click(page, '.compact-head button[aria-label="通常表示に戻す"]');
  await until("the normal view", () => page.evaluate(`!document.querySelector(".compact-view") && !!document.querySelector(".vault-sidebar")`));
  await sleep(500);
  result.afterCompact = windowState().slice(0, 3);
  assert.deepEqual(result.afterCompact, [String(initialSize[0]), String(initialSize[1]), "False"], "the normal size comes back");
  await page.evaluate(`localStorage.removeItem("cipher-vault.list-favorites-only")`);

  // ---- The call-up shortcut: off until chosen, checked again by the desktop, and never revealing anything.
  const prefsFile = path.join(data, "window-prefs.json");
  result.hotkey = { initial: await page.evaluate("window.passwordManager.getGlobalShortcut()") };
  assert.deepEqual(result.hotkey.initial, { shortcut: null, summonCompact: true, registered: false, error: null }, "no system-wide key is taken until the user chooses one");
  const hotkeySession = JSON.stringify((await status(page)).sessionId);
  result.hotkey.refused = {};
  for (const [name, shortcut] of Object.entries({ oneModifier: "Ctrl+K", inApp: "Ctrl+Shift+C", spelling: "ctrl+alt+k" })) {
    result.hotkey.refused[name] = await settle(page, `window.passwordManager.setGlobalShortcut(${JSON.stringify({ shortcut, summonCompact: true })}, ${hotkeySession})`);
  }
  assert.deepEqual(result.hotkey.refused, {
    oneModifier: { error: "呼び出しキーは、Ctrl・Alt・Shiftのうち2つ以上と、英数字・F1〜F11・Spaceのいずれかを組み合わせてください" },
    inApp: { error: "このキーはアプリの中で使っているため選べません" },
    spelling: { error: "呼び出しキーは、Ctrl・Alt・Shiftのうち2つ以上と、英数字・F1〜F11・Spaceのいずれかを組み合わせてください" }
  });
  result.hotkey.staleSession = await settle(page, `window.passwordManager.setGlobalShortcut({ shortcut: "Ctrl+Alt+Shift+F11", summonCompact: true }, "00000000-0000-4000-8000-000000000000")`);
  assert.ok(result.hotkey.staleSession.error, "another session cannot change the key");
  // Through the settings: the key is recorded from a key press, then saved.
  await menu(page, "ツール", "設定…");
  await until("the shortcut setting", () => page.evaluate(`document.querySelector(".settings-dialog[open] .shortcut-recorder")?.textContent === "なし"`));
  // A mouse click also focuses the button, which then reads the keys; element.click() alone does not.
  // Recording stops when the window loses the focus, so it is started again until it holds.
  await until("the recorder waiting for a key", () => page.evaluate(`(() => {
    const recorder = document.querySelector(".shortcut-recorder");
    if (document.activeElement === recorder && recorder.matches(".shortcut-recorder--recording")) return true;
    recorder.focus();
    if (!recorder.matches(".shortcut-recorder--recording")) recorder.click();
    return false;
  })()`));
  await press(page, "KeyK", "K", 75, CTRL);
  await until("the refused key", () => screenHas(page, "Ctrl・Alt・Shiftのうち2つ以上"));
  await press(page, "F11", "F11", 122, CTRL | ALT | SHIFT);
  await until("the recorded key", () => page.evaluate(`document.querySelector(".shortcut-recorder").textContent === "Ctrl+Alt+Shift+F11"`));
  await screenshot(page, screenshotDirectory, "tauri-shell-settings-shortcut");
  await click(page, '.settings-dialog button[type="submit"]');
  await until("the saved key", async () => !(await page.evaluate(`!!document.querySelector("dialog[open]")`)));
  result.hotkey.saved = await page.evaluate("window.passwordManager.getGlobalShortcut()");
  result.hotkey.file = JSON.parse(readFileSync(prefsFile, "utf8"));
  // Another app may already hold the key on this machine; the setting then says so instead of failing silently.
  assert.equal(result.hotkey.saved.shortcut, "Ctrl+Alt+Shift+F11");
  assert.equal(result.hotkey.file.globalShortcut, "Ctrl+Alt+Shift+F11");
  if (!result.hotkey.saved.registered) assert.ok(result.hotkey.saved.error, "a refused key names the reason");
  // Pressed from another app while open: the window comes forward in the compact layout, at the search, with no entry open.
  await click(page, `button[data-entry-id="${carried.id}"]`);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "画面で追加"`));
  await page.evaluate("window.passwordManager.minimizeWindow()");
  await sleep(400);
  assert.equal(await summonAndWait("the summoned window"), "summoned");
  await until("the compact search", () => page.evaluate(`!!document.querySelector(".compact-list") && document.activeElement === document.querySelector(".compact-head .search-input")`));
  result.hotkey.summoned = await page.evaluate(`({ detail: !!document.querySelector(".compact-detail"), secrets: document.body.innerText.includes(${JSON.stringify(generated)}) })`);
  assert.deepEqual(result.hotkey.summoned, { detail: false, secrets: false });
  // The compact window keeps a height of the user's choosing, scrolls instead of breaking, and gets it back next time.
  resizeWindow(400, 420);
  await sleep(600);
  result.compactResized = { window: windowState().slice(0, 3), ...await page.evaluate(`({
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    listScrolls: getComputedStyle(document.querySelector(".compact-list")).overflowY
  })`) };
  assert.equal(result.compactResized.window[1], "420", "the compact height follows the window edge");
  assert.equal(result.compactResized.overflow, false, "nothing sticks out sideways");
  resizeWindow(400, 460);
  await sleep(600);
  await click(page, '.compact-head button[aria-label="通常表示に戻す"]');
  await until("the normal view", () => page.evaluate(`!document.querySelector(".compact-view")`));
  await sleep(500);
  result.compactSaved = JSON.parse(readFileSync(prefsFile, "utf8")).compactBounds;
  assert.equal(Math.round(result.compactSaved.height), 460);
  await press(page, "KeyM", "M", 77, CTRL | SHIFT);
  await until("the compact view again", () => page.evaluate(`!!document.querySelector(".compact-view")`));
  await sleep(600);
  assert.equal(windowState()[1], "460", "the compact window comes back at the height it had");
  await press(page, "KeyM", "M", 77, CTRL | SHIFT);
  await until("the normal view", () => page.evaluate(`!document.querySelector(".compact-view")`));
  await sleep(500);
  assert.deepEqual(windowState().slice(0, 3), [String(initialSize[0]), String(initialSize[1]), "False"], "the normal size comes back again");
  // Pressed while locked: only the lock screen comes forward, waiting for the master password.
  await click(page, '.app-menu-bar button[aria-label="ロック"]');
  await until("the lock screen", () => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`));
  await page.evaluate("window.passwordManager.minimizeWindow()");
  await sleep(400);
  assert.equal(await summonAndWait("the summoned lock screen"), "summoned");
  await until("the password field", () => page.evaluate(`document.activeElement === document.querySelector('input[aria-label="マスターパスワード"]')`));
  assert.equal(await page.evaluate(`!!document.querySelector(".compact-view") || !!document.querySelector(".vault-sidebar")`), false, "nothing of the vault is shown while locked");
  await submitPassword(page, NEW_PASSWORD, false);
  await until("unlocked again", async () => (await status(page)).isUnlocked);
  await page.evaluate(`window.passwordManager.setGlobalShortcut({ shortcut: null, summonCompact: true }, ${JSON.stringify((await status(page)).sessionId)})`);
  assert.equal(JSON.parse(readFileSync(prefsFile, "utf8")).globalShortcut, null);

  const reportsSince = (mark) => events.slice(mark).filter((event) => event.startsWith("vault-locked ") || event.startsWith("clipboard-"));
  const copy = async () => settle(page, `window.passwordManager.copyText("synthetic-clipboard-value", ${JSON.stringify((await status(page)).sessionId)})`);
  let mark = events.length;
  await click(page, `button[data-entry-id="${carried.id}"]`);
  await until("the selected entry", () => page.evaluate(`document.querySelector(".inspector-title")?.textContent === "画面で追加"`));
  await menu(page, "項目", "パスワードをコピー");
  await until("the copy notice", () => screenHas(page, "パスワードをコピーしました"));
  assert.deepEqual(reportsSince(mark), ["clipboard-write"]);
  mark = events.length;
  await click(page, '.app-menu-bar button[aria-label="ロック"]');
  await until("the cleared copy", () => events.slice(mark).includes("clipboard-clear"));
  result.copyThroughScreen = { lockReports: reportsSince(mark).sort() };
  assert.deepEqual(result.copyThroughScreen.lockReports, ["clipboard-clear", "vault-locked manual"]);

  result.osEvents = {};
  for (const scenario of OS_SCENARIOS) {
    await submitPassword(page, NEW_PASSWORD, false);
    await until("the unlocked list", async () => (await status(page)).isUnlocked);
    assert.deepEqual(await copy(), { value: null });
    mark = events.length;
    sendOsMessage(osWindow, scenario.away);
    await until("the cleared copy", () => events.slice(mark).includes("clipboard-clear"));
    const away = await status(page);
    // While away, unlocking is refused even with the right password.
    const refused = await settle(page, `window.passwordManager.unlockVault({ masterPassword: ${JSON.stringify(NEW_PASSWORD)} }, ${JSON.stringify(away.sessionId)})`);
    sendOsMessage(osWindow, scenario.back);
    const back = await status(page);
    result.osEvents[scenario.name] = { reports: reportsSince(mark), awayReason: away.lockReason, refused: refused.error, backReason: back.lockReason };
    assert.deepEqual(result.osEvents[scenario.name], { reports: [`vault-locked ${scenario.awayReason}`, "clipboard-clear", `vault-locked ${scenario.backReason}`], awayReason: scenario.awayReason, refused: AWAY_MESSAGE, backReason: scenario.backReason });
    assert.equal(back.isUnlocked, false, "returning never unlocks by itself");
  }

  // A copy clears itself after 30 seconds while the vault stays open.
  await submitPassword(page, NEW_PASSWORD, false);
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
  await click(page, '.app-menu-bar button[aria-label="バージョンと更新"]');
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
  // The window has no native frame: the screen's title bar maximizes and restores it through the
  // window operations its capability grants, while every other window command stays refused.
  assert.deepEqual(await page.evaluate(`[...document.querySelectorAll(".window-control")].map((node) => node.getAttribute("aria-label"))`), ["最小化", "最大化", "閉じる"]);
  await page.evaluate("window.passwordManager.toggleMaximizeWindow()");
  await until("the maximized window", () => page.evaluate("window.passwordManager.isWindowMaximized()"));
  await until("the restore button", () => page.evaluate(`!!document.querySelector('.window-control[aria-label="元に戻す"]')`));
  await page.evaluate("window.passwordManager.toggleMaximizeWindow()");
  await until("the restored window", async () => !(await page.evaluate("window.passwordManager.isWindowMaximized()")));
  result.windowControls = true;
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
  // The window has no native frame, so it closes through the title bar's own button.
  await page.evaluate(`document.querySelector(".window-control--close").click()`).catch(() => undefined);
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
