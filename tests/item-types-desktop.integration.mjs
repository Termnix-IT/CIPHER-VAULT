// Real application UI/preload/services with owned synthetic profiles and an in-memory clipboard port.
import { app, clipboard, dialog, powerMonitor } from "electron";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createMigratedFixture, v2Password } from "./v2-runtime-fixture.mjs";

const root = process.env.CIPHER_VAULT_TEST_ROOT, phase = process.env.CIPHER_VAULT_ITEM_TYPES_PHASE;
const relative = path.relative(tmpdir(), root ?? "");
assert.ok(root && relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
assert.ok(phase === "legacy" || phase === "v2");
const profile = path.join(root, `item-types-${phase}-profile`);
mkdirSync(profile, { recursive: true }); app.disableHardwareAcceleration(); app.setPath("userData", profile); app.setPath("sessionData", profile);
assert.equal(path.resolve(app.commandLine.getSwitchValue("user-data-dir")), profile);
process.env.PASSWORD_MANAGER_RENDERER_URL = "http://127.0.0.1:1";
const nativeIdle = powerMonitor.getSystemIdleState, nativeClipboard = { write: clipboard.write, read: clipboard.read, clear: clipboard.clear };
let clipboardItems = [], clipboardWrites = 0;
powerMonitor.getSystemIdleState = () => "active";
clipboard.write = async items => { clipboardItems = items; clipboardWrites++; };
clipboard.read = async () => clipboardItems;
clipboard.clear = () => { clipboardItems = []; };
app.once("quit", () => { powerMonitor.getSystemIdleState = nativeIdle; Object.assign(clipboard, nativeClipboard); });
dialog.showErrorBox = () => { console.error("FAIL item-types application startup"); app.exit(1); };
process.on("uncaughtException", error => { console.error("FAIL item-types uncaught", error); app.exit(1); });
process.on("unhandledRejection", error => { console.error("FAIL item-types rejection", error); app.exit(1); });
const timeout = setTimeout(() => { console.error("FAIL item-types timeout", phase); app.exit(1); }, 120000);
let window;
const created = new Promise(resolve => app.once("browser-window-created", (_event, value) => {
  window = value; value.hide(); value.webContents.setBackgroundThrottling(false);
  value.webContents.once("did-finish-load", () => { value.hide(); resolve(); });
}));
const evaluate = source => window.webContents.executeJavaScript(source);
async function waitFor(source) {
  for (let attempt = 0; attempt < 200; attempt++) { if (await evaluate(source)) return; await delay(50); }
  throw new Error(`Item-types UI condition failed: ${source}`);
}
const click = selector => evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
async function fill(selector, value) {
  await evaluate(`(()=>{const input=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
}
async function fillMaster(value) { for (const selector of ['.cipher-form input[name=master]', '.cipher-form input[name=confirm]']) if (await evaluate(`!!document.querySelector(${JSON.stringify(selector)})`)) await fill(selector, value); }
async function fillField(label, value) {
  await evaluate(`(()=>{const field=[...document.querySelectorAll('.editor-fields .editor-field')].find(field=>field.querySelector('.form-label')?.textContent===${JSON.stringify(label)});const input=field.querySelector('input');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
}
async function choose(type) {
  await click(`.type-tabs button[data-type="${type}"]`);
}
const ipc = (method, ...args) => evaluate(`(async()=>{const id=(await window.passwordManager.fetchVaultStatus()).sessionId;return window.passwordManager[${JSON.stringify(method)}](...${JSON.stringify(args)},id)})()`);
const hash = file => createHash("sha256").update(readFileSync(file)).digest("hex");
const secretAbsent = value => evaluate(`!document.body.textContent.includes(${JSON.stringify(value)})`);
function revealButton(label, visible = false) { return `.entry-editor button[aria-label="${label}を${visible ? "隠す" : "表示（2回クリック）"}"]`; }
async function reveal(label, value) {
  assert.equal(await secretAbsent(value), true);
  await click(revealButton(label)); assert.equal(await secretAbsent(value), true, "A single activation must keep the credential hidden");
  await click(revealButton(label)); await waitFor(`document.body.textContent.includes(${JSON.stringify(value)})`);
}
async function copy(label, value) {
  const before = clipboardWrites;
  await click(`.entry-editor button[aria-label="${label}をコピー"]`);
  for (let attempt = 0; attempt < 100 && clipboardWrites === before; attempt++) await delay(20);
  assert.equal(clipboardWrites, before + 1, "The real clipboard IPC should receive exactly one user action");
  assert.equal(await (await clipboardItems[0].getType("text/plain")).text(), value);
  await waitFor("!!document.querySelector('.copy-btn--copied')");
}
async function newItem(type) {
  await click(".sidebar-add"); await waitFor("!!document.querySelector('.type-tabs')");
  await choose(type); await waitFor(`!!document.querySelector('.entry-editor--${type} .editor-fields')`);
}
async function saved(title) {
  await click(".entry-editor button[type=submit]");
  await waitFor(`!!document.querySelector('.entry-view-fields')&&document.querySelector('.inspector-title').textContent===${JSON.stringify(title)}&&!document.querySelector('.sidebar-lock').disabled`);
  assert.equal(await evaluate("document.querySelector('.type-tabs')===null"), true);
}
async function checkLayout(name) {
  for (const [width, height] of [[1000, 680], [1200, 780]]) {
    window.setSize(width, height); await delay(300);
    // A hidden CI window can pause compositor animations; measure their final layout.
    await evaluate("document.getAnimations().forEach(animation=>animation.finish())");
    const layout = await evaluate(`(()=>{const r=(document.querySelector('.editor-actions')??document.querySelector('.inspector-actions')).getBoundingClientRect();return {scrollWidth:document.documentElement.scrollWidth,width:innerWidth,height:innerHeight,left:r.left,right:r.right,bottom:r.bottom};})()`);
    assert.ok(layout.scrollWidth <= layout.width && layout.left >= -1 && layout.right <= layout.width + 1 && layout.bottom <= layout.height + 1, `Actions must remain reachable: ${JSON.stringify(layout)}`);
  }
}
async function select(id) {
  await click(`.entry-row[data-entry-id="${id}"]`);
  await waitFor(`!!document.querySelector('.entry-view-fields')&&document.querySelector('.entry-row--active')?.dataset.entryId===${JSON.stringify(id)}&&!document.querySelector('.sidebar-lock').disabled`);
}

async function run() {
  try {
    const directory = path.join(profile, "data");
    let legacyHash;
    if (phase === "v2") { await createMigratedFixture(directory); legacyHash = hash(path.join(directory, "password-manager.db")); }
    await import("../apps/electron/dist/apps/electron/src/main.js"); await created;
    assert.equal(path.resolve(app.getPath("userData")), profile);
    assert.equal(path.resolve(app.getPath("sessionData")), profile);
    const preferences = window.webContents.getLastWebPreferences();
    assert.equal(preferences.sandbox, true); assert.equal(preferences.nodeIntegration, false); assert.equal(preferences.contextIsolation, true);
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    await fillMaster(phase === "v2" ? v2Password : "synthetic-item-types-legacy-master");
    await click(".cipher-form button[type=submit]");
    await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
    assert.equal((await ipc("fetchVaultStatus")).maintenance.format, phase);

    if (phase === "legacy") {
      await click(".sidebar-add");
      for (const type of ["apiKey", "creditCard"]) {
        await choose(type); await waitFor("!!document.querySelector('.entry-migration-notice')");
        assert.equal(await evaluate("document.querySelector('.entry-editor button[type=submit]').disabled"), true);
        assert.equal(await evaluate("document.querySelector('.editor-fields')===null"), true);
        await evaluate("document.querySelector('.entry-editor').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))");
        assert.equal((await ipc("fetchEntries")).items.length, 0);
      }
      // Exercise both answers at the existing confirmation boundary without a native modal in CI.
      await evaluate("void(window.confirm=()=>false)"); await click(".entry-migration-notice button");
      assert.equal(await evaluate("document.querySelector('.vault-maintenance-dialog[open]')===null&&!!document.querySelector('.entry-migration-notice')"), true);
      await evaluate("void(window.confirm=()=>true)"); await click(".entry-migration-notice button");
      await waitFor("!!document.querySelector('.vault-maintenance-dialog[open] form')");
      assert.equal(await evaluate("document.querySelector('.entry-editor')===null"), true);
      assert.equal((await ipc("fetchEntries")).items.length, 0);
      console.log("PASS actual legacy UI blocks API/card saves and opens migration only after the discard confirmation");
    } else {
      const apiTitle = "Synthetic API UI", apiSecret = "  SYNTHETIC_API_TOKEN_NOT_VALID  ", editedApi = "SYNTHETIC_API_TOKEN_EDITED_NOT_VALID";
      const cardTitle = "Synthetic Card UI", number = "4111111111111111", securityCode = "839";
      await newItem("apiKey");
      await checkLayout("api-form");
      await fillField("名前", apiTitle); await fillField("キー", apiSecret); await fillField("キーID", "synthetic-key-id");
      await fillField("有効期限", "2029-12-31"); await fillField("URL", "https://api.example.test");
      await click(".editor-more button"); await waitFor("!!document.querySelector('.editor-fields .editor-field textarea')"); await fillField("グループ", "Synthetic group"); await fillField("タグ", "synthetic, api");
      await saved(apiTitle);
      let summaries = (await ipc("fetchEntries")).items, api = summaries.find(entry => entry.serviceName === apiTitle);
      assert.equal(api.type, "apiKey"); assert.equal(Object.hasOwn(api, "apiKey"), false);
      assert.equal((await ipc("fetchEntry", api.id)).apiKey.key, apiSecret);
      await reveal("キー", apiSecret); await copy("キー", apiSecret);
      await click(".inspector-actions > button"); await waitFor("!!document.querySelector('.entry-editor--apiKey .editor-fields')");
      assert.equal(await evaluate("document.querySelector('.type-tabs')===null"), true);
      assert.equal(await evaluate("document.querySelector('.editor-fields input[autocomplete=\"new-password\"]').type"), "password");
      await fillField("キー", editedApi); await saved(apiTitle);
      assert.equal((await ipc("fetchEntry", api.id)).apiKey.key, editedApi); assert.equal(await secretAbsent(editedApi), true);
      console.log("PASS actual API form, immutable saved type, exact credential copy and edit/save hide state");

      await newItem("creditCard"); await fillField("名前", cardTitle); await fillField("カード番号", "4111 1111 1111 1111");
      await checkLayout("card-form");
      await fillField("名義", "SYNTHETIC OWNER"); await fillField("有効期限", "2029-12"); await fillField("セキュリティコード", securityCode);
      await saved(cardTitle); summaries = (await ipc("fetchEntries")).items;
      const card = summaries.find(entry => entry.serviceName === cardTitle);
      assert.equal(card.type, "creditCard"); assert.equal(card.cardLast4, "1111"); assert.equal(Object.hasOwn(card, "card"), false);
      const detail = await ipc("fetchEntry", card.id);
      await checkLayout("card-detail");
      assert.equal(detail.card.number, number); assert.equal(detail.card.expiryMonth, "2029-12"); assert.equal(detail.card.securityCode, securityCode);
      assert.equal(await evaluate(`document.querySelector('.entry-list').textContent.includes('•••• 1111')&&!document.querySelector('.entry-list').textContent.includes(${JSON.stringify(number)})&&!document.querySelector('.entry-list').textContent.includes(${JSON.stringify(editedApi)})`), true);
      await reveal("カード番号", number); assert.equal(await secretAbsent(securityCode), true);
      await reveal("セキュリティコード", securityCode); await click(revealButton("カード番号", true));
      assert.equal(await secretAbsent(number), true); assert.equal(await secretAbsent(securityCode), false, "Hiding one field must not change another field's visibility");
      await copy("カード番号", number); await copy("セキュリティコード", securityCode);
      await click(".inspector-actions > button"); await waitFor("!!document.querySelector('.entry-editor--creditCard .editor-fields')");
      assert.equal(await evaluate("[...document.querySelectorAll('.editor-fields input[autocomplete=\"new-password\"]')].every(input=>input.type==='password')"), true);
      await fillField("名義", "SYNTHETIC EDITED OWNER"); await saved(cardTitle);
      assert.equal((await ipc("fetchEntry", card.id)).card.cardholder, "SYNTHETIC EDITED OWNER");
      await select(api.id); await reveal("キー", editedApi); await select(card.id); await select(api.id);
      assert.equal(await secretAbsent(editedApi), true); await select(card.id);
      assert.equal(await secretAbsent(number), true); assert.equal(await secretAbsent(securityCode), true);
      console.log("PASS actual card form, separate two-activation reveals, synthetic clipboard and selection/edit reset");

      // A secret does not become searchable just because its detail was previously loaded.
      await fill(".search-input", editedApi); await waitFor("document.querySelectorAll('.entry-row').length===0");
      await fill(".search-input", ""); await waitFor("document.querySelectorAll('.entry-row').length>=2");
      await reveal("カード番号", number); await reveal("セキュリティコード", securityCode); await copy("カード番号", number);
      const { vaultSession } = await import("../apps/api/dist/apps/api/src/services/vault-session.js");
      const key = vaultSession.requireKey(); await click(".sidebar-lock");
      await waitFor("!!document.querySelector('.cipher-form input[type=password]')&&document.querySelector('.entry-editor')===null");
      for (const secret of [apiSecret, editedApi, number, securityCode]) {
        assert.equal(await secretAbsent(secret), true);
        assert.equal(await evaluate(`[...document.querySelectorAll('input,textarea')].every(input=>!input.value.includes(${JSON.stringify(secret)}))`), true);
      }
      for (let attempt = 0; attempt < 100 && clipboardItems.length; attempt++) await delay(20);
      assert.equal(clipboardItems.length, 0); assert.deepEqual(key, Buffer.alloc(32));
      assert.equal(hash(path.join(directory, "password-manager.db")), legacyHash);
      console.log("PASS actual lock removes all item secrets from DOM, clears the owned clipboard and erases the vault key");
    }
    clearTimeout(timeout); window.destroy(); app.quit();
  } catch (error) { clearTimeout(timeout); console.error("FAIL item-types integration", phase, error); app.exit(1); }
}
void run();
