// Actual main/preload/renderer with a synthetic migrated vault; never use an installed profile.
import { app, dialog, powerMonitor } from "electron";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import crypto, { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createMigratedFixture, compatibility, v2Password } from "./v2-runtime-fixture.mjs";

const temporaryRoot = process.env.CIPHER_VAULT_TEST_ROOT, relative = path.relative(tmpdir(), temporaryRoot ?? "");
assert.ok(temporaryRoot && relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
const profile = path.join(temporaryRoot, "v2-profile"); mkdirSync(profile); app.setPath("userData", profile);
process.env.PASSWORD_MANAGER_RENDERER_URL = "http://127.0.0.1:1";
const nativeIdle = powerMonitor.getSystemIdleState; powerMonitor.getSystemIdleState = () => "active";
app.once("quit", () => { powerMonitor.getSystemIdleState = nativeIdle; });
dialog.showErrorBox = (_title, message) => { console.error("FAIL v2 startup", message); app.exit(1); };
process.on("uncaughtException", error => { console.error("FAIL v2 desktop", error); app.exit(1); });
process.on("unhandledRejection", error => { console.error("FAIL v2 desktop", error); app.exit(1); });
const timeout = setTimeout(() => { console.error("FAIL v2 desktop timeout"); app.exit(1); }, 120000);
let window;
const created = new Promise(resolve => app.once("browser-window-created", (_event, value) => {
  window = value; value.hide(); value.webContents.setBackgroundThrottling(false); value.webContents.once("did-finish-load", () => { value.hide(); resolve(); });
}));
const evaluate = source => window.webContents.executeJavaScript(source);
async function waitFor(source) {
  for (let i = 0; i < 200; i++) { if (await evaluate(source)) return; await delay(50); }
  throw new Error(`V2 UI condition failed: ${source}`);
}
async function fill(selector, value) {
  await evaluate(`(()=>{const input=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`);
}
const click = selector => evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
const ipc = (method, ...args) => evaluate(`(async()=>{const session=(await window.passwordManager.fetchVaultStatus()).sessionId;return window.passwordManager[${JSON.stringify(method)}](...${JSON.stringify(args)},session)})()`);
const digest = file => createHash("sha256").update(readFileSync(file)).digest("hex");

async function run() {
  try {
    const directory = path.join(profile, "data"), context = await createMigratedFixture(directory), original = digest(path.join(directory, "password-manager.db"));
    await import("../apps/electron/dist/apps/electron/src/main.js"); await created;
    const storage = await import("../apps/api/dist/apps/api/src/db/vault-context.js"), { vaultSession } = await import("../apps/api/dist/apps/api/src/services/vault-session.js");
    assert.equal(storage.isV2Vault(), true); assert.equal(storage.getVaultStoragePath(), path.join(directory, "vaults", context.vaultId, "vault.sqlite"));
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    assert.equal(await evaluate("typeof require==='undefined'&&typeof process==='undefined'&&Object.isFrozen(window.passwordManager)"), true);
    await fill('.cipher-form input[type=password]', v2Password); await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
    assert.equal((await ipc("fetchEntries")).items.length, compatibility.legacy.entries.length);
    await click('.sidebar-add'); await waitFor("!!document.querySelector('.editor-fields')");
    await fill('.editor-fields .editor-field:nth-child(1) input', "V2 desktop synthetic");
    await fill('.editor-fields .editor-field:nth-child(2) input', "v2-desktop-user");
    await fill('.editor-fields input[type=password]', "synthetic-v2-entry-password"); await click('.entry-editor button[type=submit]');
    await waitFor("!!document.querySelector('.entry-view-fields')&&document.querySelector('.inspector-title').textContent==='V2 desktop synthetic'");
    await click('.inspector-actions > button'); await waitFor("!!document.querySelector('.editor-fields')");
    await fill('.editor-fields .editor-field:nth-child(2) input', "v2-desktop-edited"); await click('.entry-editor button[type=submit]');
    await waitFor("!!document.querySelector('.entry-view-fields')&&document.body.textContent.includes('v2-desktop-edited')");
    console.log("PASS actual v2 renderer unlock, create and update through sandbox preload/IPC");
    const summaries = (await ipc("fetchEntries")).items, added = summaries.find(entry => entry.serviceName === "V2 desktop synthetic");
    assert.equal((await ipc("fetchEntry", added.id)).loginId, "v2-desktop-edited");
    const backup = await ipc("exportBackup", { passphrase: compatibility.backupV1.passphrase });
    for (const entry of summaries) await ipc("deleteEntry", entry.id);
    assert.deepEqual(await ipc("restoreBackup", { passphrase: compatibility.backupV1.passphrase, content: backup.content }), { restoredCount: summaries.length });
    assert.equal((await ipc("fetchEntry", added.id)).loginId, "v2-desktop-edited");
    assert.equal((await ipc("auditVault")).total, summaries.length);
    const key = vaultSession.requireKey(); await ipc("lockVault"); assert.deepEqual(key, Buffer.alloc(32));
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    await fill('.cipher-form input[type=password]', v2Password); await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.entry-row')&&!document.querySelector('.sidebar-lock').disabled");
    assert.equal((await ipc("fetchEntries")).items.length, summaries.length);
    assert.equal(digest(path.join(directory, "password-manager.db")), original);
    console.log("PASS actual v2 IPC delete, atomic v1 restore, audit and lock/re-unlock preserve the legacy original");
    const previousStore = storage.getV2Vault().store, previousKey = vaultSession.requireKey(), previousPath = storage.getVaultStoragePath(), previousHash = digest(previousPath);
    const replacementPassword = "synthetic-desktop-replacement-password";
    const replaced = await ipc("runVaultMaintenance", { operation: "rekey", masterPassword: v2Password, newMasterPassword: replacementPassword,
      confirmNewMasterPassword: replacementPassword, backupPassphrase: compatibility.backupV1.passphrase, confirmBackupPassphrase: compatibility.backupV1.passphrase });
    assert.equal(replaced.isUnlocked, false); assert.equal(replaced.maintenance.state, "ready"); assert.equal(previousStore.closed, true);
    assert.deepEqual(previousKey, Buffer.alloc(32)); assert.equal(digest(previousPath), previousHash); assert.notEqual(storage.getVaultStoragePath(), previousPath);
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    await fill('.cipher-form input[type=password]', replacementPassword); await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.entry-row')&&!document.querySelector('.sidebar-lock').disabled");
    assert.equal((await ipc("fetchEntries")).items.length, summaries.length);
    console.log("PASS actual maintenance IPC rekeys, preserves the source, reopens locked and unlocks with the new master");
    async function openMaintenance() {
      await evaluate("[...document.querySelectorAll('.app-menu-trigger')].find(b=>b.textContent==='ツール').click()");
      await waitFor("[...document.querySelectorAll('.app-menu-item')].some(b=>b.textContent==='保管庫の管理'&&!b.disabled)");
      await evaluate("[...document.querySelectorAll('.app-menu-item')].find(b=>b.textContent==='保管庫の管理').click()");
      try { await waitFor("!!document.querySelector('.vault-maintenance-dialog[open] form')"); }
      catch(error) {
        console.error("Management view diagnostics", await ipc("fetchVaultStatus"), await evaluate("(()=>{const d=document.querySelector('.vault-maintenance-dialog');return {dialogOpen:d?.open,formCount:d?.querySelectorAll('form').length,dashboard:!!document.querySelector('.cipher-dashboard'),activeElement:document.activeElement?.tagName}})()"));
        throw error;
      }
    }
    async function fillMaintenance(master, next) {
      for (const [index,value] of [master,next,next,compatibility.backupV1.passphrase,compatibility.backupV1.passphrase].entries())
        await fill(`.maintenance-fields label:nth-child(${index+1}) input`,value);
    }
    async function finishMaintenance(password) {
      await waitFor("document.querySelector('.vault-maintenance-dialog .vault-tool-message')?.textContent.includes('切り替えを完了')");
      assert.equal((await ipc("fetchVaultStatus")).isUnlocked,false);
      await click('.vault-maintenance-dialog .vault-tool-heading button');
      await waitFor("!document.querySelector('.vault-maintenance-dialog[open]')");
      assert.equal(await evaluate("document.querySelector('.reset-entry-link')===null"),true);
      await fill('.cipher-form input[type=password]',password);await click('.cipher-form button[type=submit]');
      await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
    }
    const uiPassword="synthetic-maintenance-ui-new-password",beforeUiPath=storage.getVaultStoragePath(),beforeUiHash=digest(beforeUiPath);
    await openMaintenance();await fillMaintenance(replacementPassword,uiPassword);
    await fill('.maintenance-fields label:nth-child(3) input','synthetic-wrong-confirmation');await click('.vault-maintenance-dialog button[type=submit]');
    await waitFor("document.querySelector('.vault-maintenance-dialog .form-error')?.textContent.includes('一致しません')");assert.equal(vaultSession.getState().isUnlocked,true);
    await fill('.maintenance-fields label:nth-child(3) input',uiPassword);await click('.vault-maintenance-dialog button[type=submit]');
    await waitFor("!!document.querySelector('.maintenance-progress')");
    assert.equal(await evaluate("[...document.querySelectorAll('.vault-maintenance-dialog input[type=password]')].every(i=>i.value==='')"),true);
    await finishMaintenance(uiPassword);assert.equal(digest(beforeUiPath),beforeUiHash);assert.equal((await ipc('fetchEntries')).items.length,summaries.length);
    console.log("PASS actual management form validates confirmation, clears credentials and rekeys through the renderer");
    for (let repeat=0;repeat<3;repeat++) {
      await openMaintenance();
      if (repeat===1) { window.webContents.sendInputEvent({type:"keyDown",keyCode:"Escape"}); window.webContents.sendInputEvent({type:"keyUp",keyCode:"Escape"}); }
      else await click('.vault-maintenance-dialog .vault-tool-heading button');
      await waitFor("!document.querySelector('.vault-maintenance-dialog[open]')");
    }
    const emptyPassword="synthetic-empty-vault-ui-password",beforeResetPath=storage.getVaultStoragePath(),beforeResetHash=digest(beforeResetPath);
    await openMaintenance();await click('.maintenance-options button:nth-child(2)');await fillMaintenance(uiPassword,emptyPassword);
    await click('.vault-maintenance-dialog button[type=submit]');assert.equal(vaultSession.getState().isUnlocked,true);assert.equal(storage.getVaultStoragePath(),beforeResetPath);
    await click('.maintenance-acknowledgement input');await click('.vault-maintenance-dialog button[type=submit]');await finishMaintenance(emptyPassword);
    assert.equal((await ipc('fetchEntries')).items.length,0);assert.equal(digest(beforeResetPath),beforeResetHash);
    console.log("PASS actual safe-reset form requires acknowledgement and preserves the previous vault");
    await openMaintenance();await fillMaintenance(emptyPassword,'synthetic-cancelled-ui-password');
    const scrypt=crypto.scrypt,beforeCancelPath=storage.getVaultStoragePath(),beforeCancelHash=digest(beforeCancelPath);let releaseKdf;
    const kdfStarted=new Promise(resolve=>{crypto.scrypt=(p,s,n,o,done)=>scrypt(p,s,n,o,(error,key)=>{releaseKdf=()=>done(error,key);resolve()});syncBuiltinESMExports()});
    try{
      await click('.vault-maintenance-dialog button[type=submit]');await kdfStarted;await waitFor("!!document.querySelector('.maintenance-progress')");
      await evaluate("[...document.querySelectorAll('.vault-maintenance-dialog button')].find(b=>b.textContent==='処理を取り消す').click()");
      await waitFor("document.querySelector('.vault-maintenance-dialog .vault-tool-message')?.textContent.includes('取消を要求')");releaseKdf();releaseKdf=undefined;
      await waitFor("!document.querySelector('.maintenance-progress')&&!!document.querySelector('.vault-maintenance-dialog .vault-tool-heading button')");
      assert.equal(storage.getVaultStoragePath(),beforeCancelPath);assert.equal(digest(beforeCancelPath),beforeCancelHash);assert.equal(vaultSession.getState().isUnlocked,false);
      await click('.vault-maintenance-dialog .vault-tool-heading button');
    }finally{crypto.scrypt=scrypt;syncBuiltinESMExports();releaseKdf?.()}
    await fill('.cipher-form input[type=password]',emptyPassword);await click('.cipher-form button[type=submit]');
    await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
    console.log("PASS actual cancel action invalidates the pending operation without switching its source");
    const store = storage.getV2Vault().store, closingKey = vaultSession.requireKey();
    app.once("will-quit", () => {
      assert.equal(store.closed, true); assert.deepEqual(closingKey, Buffer.alloc(32));
      assert.equal(digest(path.join(directory, "password-manager.db")), original);
      console.log("PASS actual v2 shutdown closes storage and destroys the root key");
    });
    clearTimeout(timeout); window.destroy(); app.quit();
  } catch (error) { clearTimeout(timeout); console.error("FAIL v2 integration", error); app.exit(1); }
}
void run();
