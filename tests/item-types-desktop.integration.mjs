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
  await waitFor(`!!document.querySelector('.entry-view-fields')&&document.querySelector('.inspector-title').textContent===${JSON.stringify(title)}&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')`);
  assert.equal(await evaluate("document.querySelector('.type-tabs')===null"), true);
}
async function checkLayout(name) {
  for (const [width, height] of [[780, 680], [880, 780]]) {
    window.setSize(width, height); await delay(300);
    // A hidden CI window can pause compositor animations; measure their final layout.
    await evaluate("document.getAnimations().forEach(animation=>animation.finish())");
    const layout = await evaluate(`(()=>{const r=(document.querySelector('.editor-actions')??document.querySelector('.inspector-actions')).getBoundingClientRect();return {scrollWidth:document.documentElement.scrollWidth,width:innerWidth,height:innerHeight,left:r.left,right:r.right,bottom:r.bottom};})()`);
    assert.ok(layout.scrollWidth <= layout.width && layout.left >= -1 && layout.right <= layout.width + 1 && layout.bottom <= layout.height + 1, `Actions must remain reachable: ${JSON.stringify(layout)}`);
  }
}
async function select(id) {
  await click(`.entry-row[data-entry-id="${id}"]`);
  await waitFor(`!!document.querySelector('.entry-view-fields')&&document.querySelector('.entry-row--active')?.dataset.entryId===${JSON.stringify(id)}&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')`);
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
    await waitFor("!!document.querySelector('.cipher-dashboard')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')");
    assert.equal((await ipc("fetchVaultStatus")).maintenance.format, phase);

    if (phase === "legacy") {
      await click(".sidebar-add");
      for (const type of ["apiKey", "creditCard", "financial"]) {
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

      const bankTitle = "Synthetic Bank UI", bankId = "synthetic-contract-id", bankLogin = "  SYNTHETIC_BANK_LOGIN  ", bankTrading = "SYNTHETIC_BANK_TRADING", bankExtra = "SYNTHETIC_BANK_EXTRA", editedTrading = "SYNTHETIC_BANK_TRADING_EDITED";
      await newItem("financial");
      await fillField("名前", bankTitle); await fillField("ログインID", bankId); await fillField("ログインパスワード", bankLogin); await fillField("取引パスワード", bankTrading);
      await click(".editor-more button"); await waitFor("!!document.querySelector('.editor-extra-secret')");
      await fill(".editor-extra-secret input:not([type=password])", "第2暗証番号"); await fill(".editor-extra-secret input[type=password]", bankExtra);
      await checkLayout("financial-form");
      assert.equal(await evaluate("document.querySelectorAll('.editor-fields .btn--small').length"), 1, "Only the login password offers generation");
      await saved(bankTitle); await checkLayout("financial-detail");
      const bank = (await ipc("fetchEntries")).items.find(entry => entry.serviceName === bankTitle);
      assert.equal(bank.type, "financial"); assert.equal(Object.hasOwn(bank, "financial"), false); assert.equal(Object.hasOwn(bank, "loginId"), false);
      assert.deepEqual((await ipc("fetchEntry", bank.id)).financial, { loginId: bankId, loginPassword: bankLogin, tradingPassword: bankTrading, extraSecrets: [{ label: "第2暗証番号", value: bankExtra }] });
      assert.equal(await evaluate(`document.querySelector('.entry-row--active').textContent.includes('銀行/証券')&&!document.querySelector('.entry-list').textContent.includes(${JSON.stringify(bankId)})`), true);
      assert.equal(await evaluate("[...document.querySelectorAll('.list-filter button')].map(button=>button.textContent).join()"), "すべて,ログイン,APIキー,カード,銀行/証券");
      await reveal("ログインパスワード", bankLogin); await reveal("取引パスワード", bankTrading); await reveal("第2暗証番号", bankExtra);
      await click(revealButton("取引パスワード", true)); assert.equal(await secretAbsent(bankTrading), true); assert.equal(await secretAbsent(bankExtra), false, "Hiding one field must not change another field's visibility");
      await copy("ログインパスワード", bankLogin); await copy("取引パスワード", bankTrading); await copy("第2暗証番号", bankExtra);
      await click(".inspector-actions > button"); await waitFor("!!document.querySelector('.entry-editor--financial .editor-fields')");
      assert.equal(await evaluate("[...document.querySelectorAll('.editor-fields input[autocomplete=\"new-password\"]')].every(input=>input.type==='password')"), true);
      await fillField("取引パスワード", editedTrading); await saved(bankTitle);
      assert.equal((await ipc("fetchEntry", bank.id)).financial.tradingPassword, editedTrading); assert.equal(await secretAbsent(editedTrading), true);
      await click(".inspector-actions > button"); await waitFor("!!document.querySelector('.editor-extra-secret')");
      await click('.editor-extra-secret button[aria-label="第2暗証番号を削除"]'); await waitFor("!document.querySelector('.editor-extra-secret')");
      await saved(bankTitle); assert.deepEqual((await ipc("fetchEntry", bank.id)).financial.extraSecrets, []);
      await select(card.id);
      console.log("PASS actual financial form, separate secrets, added and removed extras, generation scope and safe summary");

      const rowName = id => `.entry-row[data-entry-id="${id}"]`;
      const ready = () => waitFor("!!document.querySelector('.cipher-dashboard[aria-busy=false]')");
      const openMenu = async id => {
        await evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(rowName(id))}).getBoundingClientRect();document.querySelector(${JSON.stringify(rowName(id))}).dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,button:2,clientX:r.left+20,clientY:r.top+10}))})()`);
        await waitFor("!!document.querySelector('.entry-menu')");
      };
      const menuItem = label => evaluate(`[...document.querySelectorAll('.entry-menu .app-menu-item')].find(b=>b.textContent.replace('✓','')===${JSON.stringify(label)}).click()`);
      const entryGroup = async id => (await ipc("fetchEntries")).items.find(entry => entry.id === id).group;
      const pickByName = name => evaluate(`[...document.querySelectorAll('.group-pick')].find(row=>row.querySelector('.group-pick-name').textContent===${JSON.stringify(name)}).querySelector('input').click()`);

      await select(card.id);
      await click(".sidebar-group-add"); await waitFor("!!document.querySelector('.group-dialog[open]')");
      assert.equal(await evaluate("document.querySelector('.group-dialog button[type=submit]').disabled"), true);
      await fill(".group-dialog input[name=groupName]", "グループなし");
      await waitFor("document.querySelector('.group-dialog-hint').textContent.includes('使えません')");
      await fill(".group-dialog input[name=groupName]", "UI Work");
      assert.equal(await evaluate("document.querySelector('.group-dialog button[type=submit]').disabled"), true, "A group needs at least one item");
      await pickByName(apiTitle); await pickByName(bankTitle);
      await waitFor("document.querySelector('.group-dialog .dialog-footer-meta').textContent==='2件を選択'&&!document.querySelector('.group-dialog button[type=submit]').disabled");
      assert.equal(await evaluate("document.querySelector('.group-dialog').textContent.includes('Synthetic group')"), true, "Each row shows the item's current group");
      await click(".group-dialog button[type=submit]");
      await waitFor("!document.querySelector('.group-dialog')&&[...document.querySelectorAll('.group-header-name')].some(h=>h.textContent==='UI Work')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')");
      await waitFor("document.querySelector('.toast--copy')?.textContent==='「UI Work」に2件追加しました'");
      assert.equal(await entryGroup(api.id), "UI Work", "A new group moves an item out of its previous group"); assert.equal(await entryGroup(bank.id), "UI Work");
      assert.equal(await evaluate("document.querySelector('.entry-row--active').dataset.entryId"), card.id);
      assert.equal(await evaluate("document.querySelector('.group-dialog')===null&&[...document.querySelectorAll('.group-header-name')].every(h=>h.textContent!=='Synthetic group')"), true, "An emptied group disappears");

      await click(".sidebar-group-add"); await waitFor("!!document.querySelector('.group-dialog[open]')");
      await fill(".group-dialog input[name=groupName]", "UI Work");
      await waitFor("document.querySelector('.group-dialog-hint').textContent==='既存のグループに追加されます'");
      await click('.group-dialog button[aria-label="閉じる"]'); await waitFor("!document.querySelector('.group-dialog')");

      await openMenu(api.id);
      assert.equal(await evaluate("document.querySelector('.entry-row--active').dataset.entryId"), card.id, "Right-click keeps the selection");
      assert.equal(await evaluate("document.activeElement===document.querySelector('.entry-menu-add')"), true);
      await menuItem("グループへ追加"); await waitFor("!!document.querySelector('.entry-menu-groups')");
      assert.equal(await evaluate("document.querySelector('.entry-menu-groups [aria-checked=true]').textContent.includes('UI Work')"), true);
      await menuItem("グループから削除");
      await waitFor(`!document.querySelector('.entry-menu')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')`); await ready();
      assert.equal(await entryGroup(api.id), null);

      await openMenu(api.id);
      assert.equal(await evaluate("[...document.querySelectorAll('.entry-menu .app-menu-item')].find(b=>b.textContent==='グループから削除').disabled"), true, "An ungrouped item has nothing to remove");
      await menuItem("グループへ追加"); await waitFor("!!document.querySelector('.entry-menu-groups')");
      await menuItem("UI Work"); await waitFor("!document.querySelector('.entry-menu')"); await ready();
      assert.equal(await entryGroup(api.id), "UI Work");

      await openMenu(card.id); await menuItem("グループへ追加"); await waitFor("!!document.querySelector('.entry-menu-groups')");
      await menuItem("新しいグループ…"); await waitFor("!!document.querySelector('.group-dialog[open]')");
      assert.equal(await evaluate("document.querySelector('.group-dialog .dialog-footer-meta').textContent"), "1件を選択", "The opened item starts checked");
      assert.equal(await evaluate("document.querySelector('.group-pick').querySelector('input').checked&&document.querySelector('.group-pick-name').textContent"), cardTitle);
      await fill(".group-dialog input[name=groupName]", "UI Cards"); await click(".group-dialog button[type=submit]");
      await waitFor("!document.querySelector('.group-dialog')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')");
      await waitFor(`[...document.querySelectorAll('.entry-view-fields *')].some(node=>node.textContent==='UI Cards')`);
      assert.equal((await ipc("fetchEntry", card.id)).card.number, number, "Changing the group keeps the secret");

      await openMenu(api.id);
      await evaluate("document.querySelector('.entry-menu').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"); await waitFor("!document.querySelector('.entry-menu')");
      await openMenu(api.id);
      await evaluate("document.body.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true}))"); await waitFor("!document.querySelector('.entry-menu')");
      await openMenu(api.id);
      await evaluate("document.querySelector('.entry-list').dispatchEvent(new Event('scroll'))"); await waitFor("!document.querySelector('.entry-menu')");
      await evaluate(`document.querySelector(${JSON.stringify(rowName(api.id))}).dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,button:0}))`);
      await waitFor("!!document.querySelector('.entry-menu')");
      assert.equal(await evaluate(`(()=>{const m=document.querySelector('.entry-menu').getBoundingClientRect(),r=document.querySelector(${JSON.stringify(rowName(api.id))}).getBoundingClientRect();return m.top>=r.bottom-1||m.bottom<=innerHeight})()`), true, "The menu key opens at the row");
      await evaluate("document.querySelector('.entry-menu').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"); await waitFor("!document.querySelector('.entry-menu')");

      // Unsaved edits are protected, and declining leaves both the form and the group as they were.
      await click(".inspector-actions > button"); await waitFor("!!document.querySelector('.entry-editor--creditCard .editor-fields')");
      await fillField("名義", "SYNTHETIC UNSAVED OWNER");
      let prompts = [];
      await evaluate("void(window.__prompts=[],window.confirm=message=>{window.__prompts.push(message);return false})");
      await openMenu(api.id); await menuItem("グループから削除"); await delay(100);
      assert.equal(await entryGroup(api.id), "UI Work"); assert.equal(await evaluate("!!document.querySelector('.entry-editor--creditCard .editor-fields')"), true);
      prompts = await evaluate("window.__prompts"); assert.deepEqual(prompts, ["保存していない変更を破棄しますか？"]);
      await evaluate("void(window.confirm=()=>true)");
      await openMenu(api.id); await menuItem("グループから削除");
      await waitFor("!!document.querySelector('.entry-view-fields')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')");
      assert.equal(await entryGroup(api.id), null); assert.equal((await ipc("fetchEntry", card.id)).card.cardholder, "SYNTHETIC EDITED OWNER");

      // Deleting another item keeps the open one; the red button deletes the open one after the same confirmation.
      const created = async name => ipc("createEntry", { serviceName: name, loginId: "synthetic-delete", password: "synthetic-delete-secret" });
      const firstDelete = await created("Synthetic Delete Menu"), secondDelete = await created("Synthetic Delete Button");
      await evaluate("[...document.querySelectorAll('.app-menu-trigger')].find(button=>button.textContent==='ファイル').click()");
      await waitFor("!!document.querySelector('#app-menu-file .app-menu-item')");
      await evaluate("[...document.querySelectorAll('#app-menu-file .app-menu-item')].find(button=>button.textContent==='一覧を更新').click()");
      await waitFor(`!!document.querySelector(${JSON.stringify(rowName(secondDelete.id))})`); await ready();
      await evaluate("void(window.__prompts=[],window.confirm=message=>{window.__prompts.push(message);return false})");
      await openMenu(firstDelete.id); await menuItem("項目削除"); await delay(50);
      assert.ok((await ipc("fetchEntries")).items.some(entry => entry.id === firstDelete.id));
      assert.deepEqual(await evaluate("window.__prompts"), ["「Synthetic Delete Menu」を削除しますか？元に戻せません。"]);
      await evaluate("void(window.confirm=()=>true)");
      await openMenu(firstDelete.id); await menuItem("項目削除");
      await waitFor(`!document.querySelector(${JSON.stringify(rowName(firstDelete.id))})&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')`);
      assert.equal(await evaluate("document.querySelector('.entry-row--active').dataset.entryId"), card.id, "Deleting another item keeps the open one");
      assert.equal(await evaluate("!!document.querySelector('.entry-view-fields')"), true);
      await select(secondDelete.id);
      assert.equal(await evaluate("[...document.querySelectorAll('.inspector-actions > button')].map(b=>[b.textContent,b.classList.contains('btn--danger')]).join()"), "編集,false,削除,true");
      await click(".inspector-actions .btn--danger");
      await waitFor(`!document.querySelector(${JSON.stringify(rowName(secondDelete.id))})&&!document.querySelector('.entry-view-fields')&&!!document.querySelector('.cipher-dashboard[aria-busy=false]')`);
      assert.equal((await ipc("fetchEntries")).items.some(entry => entry.id === secondDelete.id), false);
      await select(card.id);
      console.log("PASS actual group dialog, right-click menu, unsaved-edit guard and red delete button");

      // A secret does not become searchable just because its detail was previously loaded.
      await fill(".search-input", editedApi); await waitFor("document.querySelectorAll('.entry-row').length===0");
      await fill(".search-input", ""); await waitFor("document.querySelectorAll('.entry-row').length>=2");
      await reveal("カード番号", number); await reveal("セキュリティコード", securityCode); await copy("カード番号", number);
      const { vaultSession } = await import("../apps/api/dist/apps/api/src/services/vault-session.js");
      const key = vaultSession.requireKey();
      await evaluate("[...document.querySelectorAll('.app-menu-trigger')].find(button=>button.textContent==='ファイル').click()");
      await waitFor("!!document.querySelector('#app-menu-file .app-menu-item')");
      await evaluate("[...document.querySelectorAll('#app-menu-file .app-menu-item')].find(button=>button.textContent==='ロック').click()");
      await waitFor("!!document.querySelector('.cipher-form input[type=password]')&&document.querySelector('.entry-editor')===null");
      for (const secret of [apiSecret, editedApi, number, securityCode, bankLogin, bankTrading, editedTrading, bankExtra]) {
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
