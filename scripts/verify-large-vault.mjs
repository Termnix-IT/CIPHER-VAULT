// Measures the screen of the `e2e` build with 100 and then 500 synthetic entries in a temporary folder:
// unlocking, the list, search, the favorites filter, groups, the icon list, the compact layout, opening
// and saving an entry, scrolling, and a backup restored into the emptied vault. Each step must finish
// within a generous limit, so the check fails on a real slowdown and not on a busy machine.
// Only synthetic data is used, and the user's vault is never opened.
// Usage: node scripts/verify-large-vault.mjs <e2e-exe> [<screenshot-directory>]
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { connect, screenshot, sleep, startE2eProcess, until } from "./lib/webview-e2e.mjs";

const [exe, screenshotDirectory] = process.argv.slice(2);
const PASSWORD = "synthetic-large-vault-password";
const PASSPHRASE = "synthetic-large-vault-backup";
const PORT = 9342;
const SIZES = [100, 500];
const GROUPS = 10;
const FAVORITE_EVERY = 25;
// Limits in milliseconds. They are several times what a typical laptop takes, see docs/開発・配布手順.md.
const LIMIT = { unlock: 8000, step: 1500, frame: 250, backup: 20000 };

const status = (page) => page.evaluate("window.passwordManager.fetchVaultStatus()");
const lockScreenShown = (page) => page.evaluate(`!!document.querySelector('input[aria-label="マスターパスワード"]')`);
/** Runs `action` in the page and waits, frame by frame, until `condition` holds; returns the time it took. */
const timed = (page, action, condition, limit = 20000) => page.evaluate(`(async () => {
  const frame = () => new Promise((resolve) => requestAnimationFrame(resolve));
  const start = performance.now();
  ${action};
  while (!(${condition})) {
    if (performance.now() - start > ${limit}) throw new Error("timed out: " + ${JSON.stringify(condition)});
    await frame();
  }
  await frame();
  return Math.round(performance.now() - start);
})()`);
const setInput = (selector, text) => `(() => {
  const input = document.querySelector(${JSON.stringify(selector)});
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, ${JSON.stringify(text)});
  input.dispatchEvent(new Event("input", { bubbles: true }));
})()`;
const shortcut = (code, shift) => `window.dispatchEvent(new KeyboardEvent("keydown", { code: ${JSON.stringify(code)}, ctrlKey: true, shiftKey: ${shift} }))`;
const rows = `document.querySelectorAll(".entry-row").length`;
const menuItem = (group, item) => `(async () => {
  document.querySelector(${JSON.stringify(`.app-menu-trigger[aria-label="${group}"]`)}).click();
  await new Promise((resolve) => setTimeout(resolve, 50));
  [...document.querySelectorAll(".app-menu-item")].find((node) => [...node.childNodes].filter((child) => !child.classList?.contains("app-menu-shortcut")).map((child) => child.textContent).join("").endsWith(${JSON.stringify(item)})).click();
})()`;

async function submitPassword(page, confirm) {
  await until("the lock screen", () => lockScreenShown(page));
  await sleep(1500);
  await page.evaluate(`document.querySelector('input[aria-label="マスターパスワード"]').focus()`);
  await page.send("Input.insertText", { text: PASSWORD });
  if (confirm) {
    await page.evaluate(`document.querySelector('input[aria-label="マスターパスワードをもう一度入力"]').focus()`);
    await page.send("Input.insertText", { text: PASSWORD });
  }
  await page.evaluate(`document.querySelector('button[type="submit"]').click()`);
}

function entry(index) {
  const number = String(index).padStart(4, "0");
  return {
    serviceName: `合成サービス ${number}`, loginId: `synthetic-user-${number}`, password: `synthetic-password-${number}-${"x".repeat(12)}`,
    url: `https://service-${number}.example.test/login`, notes: `synthetic note ${number}`, tags: [`tag-${index % 7}`], group: `グループ ${index % GROUPS}`
  };
}

async function seed(page, from, to) {
  const session = JSON.stringify((await status(page)).sessionId);
  const started = Date.now();
  for (let index = from; index < to; index++) {
    const created = await page.evaluate(`window.passwordManager.createEntry(${JSON.stringify(entry(index))}, ${session})`);
    if (index % FAVORITE_EVERY === 0) await page.evaluate(`window.passwordManager.setEntryFavorite(${JSON.stringify(created.id)}, true, ${session})`);
    if (index % 3 === 0) await page.evaluate(`window.passwordManager.recordEntryUse(${JSON.stringify(created.id)}, ${session})`);
  }
  return Math.round((Date.now() - started) / (to - from));
}

async function measure(page, size) {
  const result = {};
  const favorites = Math.ceil(size / FAVORITE_EVERY);
  const session = () => status(page).then((state) => JSON.stringify(state.sessionId));
  await page.evaluate(`window.passwordManager.lockVault(${await session()})`);
  const unlockStarted = Date.now();
  await submitPassword(page, false);
  await until("the full list", async () => (await page.evaluate(rows)) === size, LIMIT.unlock + 5000);
  result.unlockAndList = Date.now() - unlockStarted;
  result.search = await timed(page, setInput(".sidebar-head .search-input", "サービス 0042"), `${rows} === 1`);
  result.searchCleared = await timed(page, setInput(".sidebar-head .search-input", ""), `${rows} === ${size}`);
  result.favoritesOnly = await timed(page, `document.querySelector(".list-meta .favorites-toggle").click()`, `${rows} === ${favorites}`);
  result.favoritesOff = await timed(page, `document.querySelector(".list-meta .favorites-toggle").click()`, `${rows} === ${size}`);
  result.recentOrder = await timed(page, `(() => { const select = document.querySelector(".list-sort"); Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(select, "used"); select.dispatchEvent(new Event("change", { bubbles: true })); })()`,
    `[...document.querySelectorAll(".list-section")].some((node) => node.textContent === "未使用")`);
  result.groups = await timed(page, menuItem("表示", "グループ別"), `document.querySelectorAll(".group-header").length === ${GROUPS}`);
  result.allAgain = await timed(page, menuItem("表示", "すべて"), `!document.querySelector(".group-header") && ${rows} === ${size}`);
  // Scrolling: the slowest frame while the list moves through its whole length.
  result.scroll = await page.evaluate(`(async () => {
    const list = document.querySelector(".vault-sidebar .entry-list");
    const frame = () => new Promise((resolve) => requestAnimationFrame(resolve));
    let worst = 0, last = performance.now(), frames = 0;
    const start = last;
    for (let top = 0; top <= list.scrollHeight; top += 240) {
      list.scrollTop = top; await frame();
      const now = performance.now(); worst = Math.max(worst, now - last); last = now; frames++;
    }
    list.scrollTop = 0;
    return { frames, worstFrame: Math.round(worst), averageFrame: Math.round((last - start) / frames) };
  })()`);
  const target = `[...document.querySelectorAll(".entry-row")].find((node) => node.textContent.includes("サービス 0007"))`;
  result.openEntry = await timed(page, `${target}.click()`, `document.querySelector(".inspector-title")?.textContent === "合成サービス 0007"`);
  result.editEntry = await timed(page, `[...document.querySelectorAll(".inspector-actions button")].find((node) => node.textContent === "編集").click()`, `!!document.querySelector(".editor-save-btn")`);
  result.saveEntry = await timed(page, `(() => {
    const input = [...document.querySelectorAll(".editor-field")].find((node) => node.querySelector(".form-label")?.textContent === "ログインID").querySelector("input");
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, "synthetic-user-0007-edited");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    setTimeout(() => document.querySelector(".editor-save-btn").click(), 0);
  })()`, `!document.querySelector(".editor-save-btn") && document.body.innerText.includes("synthetic-user-0007-edited")`);
  result.iconList = await timed(page, `document.querySelector('.app-menu-bar button[aria-label="一覧をアイコンだけにする"]').click()`, `!!document.querySelector(".cipher-dashboard--collapsed") && ${rows} === ${size}`);
  result.iconListOff = await timed(page, `document.querySelector('.app-menu-bar button[aria-label="一覧を広げる"]').click()`, `!document.querySelector(".cipher-dashboard--collapsed") && !!document.querySelector(".entry-info")`);
  result.compact = await timed(page, shortcut("KeyM", true), `!!document.querySelector(".compact-view") && (!!document.querySelector(".compact-detail-title") || ${rows} === ${size})`);
  await page.evaluate(`document.querySelector('.compact-detail button[aria-label="一覧に戻る"]')?.click()`);
  await until("the compact list", () => page.evaluate(`!!document.querySelector(".compact-list")`));
  result.compactSearch = await timed(page, setInput(".compact-head .search-input", "サービス 0123"), `${rows} === ${size > 123 ? 1 : 0}`);
  if (screenshotDirectory) await screenshot(page, screenshotDirectory, `large-vault-${size}-compact`);
  result.compactOff = await timed(page, shortcut("KeyM", true), `!document.querySelector(".compact-view") && ${rows} === ${size}`);
  if (screenshotDirectory) await screenshot(page, screenshotDirectory, `large-vault-${size}`);
  // The next round measures the change of order again from name order.
  await page.evaluate(`(() => { const select = document.querySelector(".list-sort"); Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(select, "name"); select.dispatchEvent(new Event("change", { bubbles: true })); })()`);

  // A backup of everything, restored into the emptied vault, keeps favorites and use dates.
  const before = (await page.evaluate(`window.passwordManager.fetchEntries(${await session()})`)).items;
  const exportStarted = Date.now();
  const { content } = await page.evaluate(`window.passwordManager.exportBackup({ passphrase: ${JSON.stringify(PASSPHRASE)} }, ${await session()})`);
  result.backupExport = Date.now() - exportStarted;
  const current = await session();
  for (const item of before) await page.evaluate(`window.passwordManager.deleteEntry(${JSON.stringify(item.id)}, ${current})`);
  const restoreStarted = Date.now();
  assert.deepEqual(await page.evaluate(`window.passwordManager.restoreBackup({ passphrase: ${JSON.stringify(PASSPHRASE)}, content: ${JSON.stringify(content)} }, ${current})`), { restoredCount: size });
  result.backupRestore = Date.now() - restoreStarted;
  const after = (await page.evaluate(`window.passwordManager.fetchEntries(${await session()})`)).items;
  const key = (items) => items.map((item) => `${item.id} ${item.favorite ?? ""} ${item.lastUsedAt ?? ""}`).sort();
  assert.deepEqual(key(after), key(before), "the restore keeps every entry with its favorite and use date");
  await page.evaluate(menuItem("項目", "一覧を更新"));
  await until("the restored list", async () => (await page.evaluate(rows)) === size);

  for (const [name, value] of Object.entries(result)) {
    if (name === "scroll") assert.ok(value.worstFrame <= LIMIT.frame, `scroll: the slowest frame took ${value.worstFrame}ms`);
    else if (name === "unlockAndList") assert.ok(value <= LIMIT.unlock, `${name}: ${value}ms`);
    else if (name.startsWith("backup")) assert.ok(value <= LIMIT.backup, `${name}: ${value}ms`);
    else assert.ok(value <= LIMIT.step, `${name}: ${value}ms`);
  }
  return result;
}

const base = mkdtempSync(path.join(tmpdir(), "cipher-vault-large-"));
const data = path.join(base, "data");
mkdirSync(data);
const { child, errors } = startE2eProcess(exe, PORT, { CIPHER_VAULT_E2E_DEBUG_PORT: String(PORT), CIPHER_VAULT_E2E_PROFILE: path.join(base, "profile"), CIPHER_VAULT_DATA_DIR: data });
let page;
try {
  page = await connect(PORT);
  await until("the screen", () => page.evaluate(`document.readyState === "complete" && !!window.passwordManager`));
  await submitPassword(page, true);
  await until("the unlocked screen", async () => (await status(page)).isUnlocked);
  const report = { limits: LIMIT };
  let seeded = 0;
  for (const size of SIZES) {
    report[`createPerEntry${size}`] = await seed(page, seeded, size);
    seeded = size;
    report[size] = await measure(page, size);
  }
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  if (page && screenshotDirectory) await screenshot(page, screenshotDirectory, "large-vault-failure").catch(() => undefined);
  console.error(errors.join(""));
  throw error;
} finally {
  page?.close();
  child.kill();
  await until("the app to exit", () => child.exitCode !== null || child.signalCode !== null).catch(() => undefined);
  rmSync(base, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
}
