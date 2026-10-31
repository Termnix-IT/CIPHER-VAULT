// A real renderer starts with a synthetic interrupted replacement, never an installed user profile.
import {app,dialog,powerMonitor} from "electron";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {tmpdir} from "node:os";
import {createHash} from "node:crypto";
import {syncBuiltinESMExports} from "node:module";
import {setTimeout as delay} from "node:timers/promises";
import {createMigratedFixture,compatibility,v2Password} from "./v2-runtime-fixture.mjs";
import * as maintenance from "../apps/api/dist/apps/api/src/services/vault-maintenance-service.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as storage from "../apps/api/dist/apps/api/src/db/vault-context.js";
import {vaultSession} from "../apps/api/dist/apps/api/src/services/vault-session.js";
import Database from "better-sqlite3";
import {deriveVaultKey,deriveVerifier,encryptLegacySecret} from "../apps/api/dist/apps/api/src/crypto/legacy-codec.js";

const root=process.env.CIPHER_VAULT_TEST_ROOT,relative=path.relative(tmpdir(),root??"");
assert.ok(root&&relative.startsWith("cipher-vault-desktop-session-")&&!relative.includes(path.sep));
const profile=path.join(root,"maintenance-profile"),directory=path.join(profile,"data"),password="synthetic-desktop-recovery-password";
fs.mkdirSync(profile);app.setPath("userData",profile);process.env.PASSWORD_MANAGER_RENDERER_URL="http://127.0.0.1:1";
const nativeIdle=powerMonitor.getSystemIdleState;powerMonitor.getSystemIdleState=()=>"active";app.once("quit",()=>{powerMonitor.getSystemIdleState=nativeIdle});
dialog.showErrorBox=(_title,message)=>{console.error("FAIL maintenance startup",message);app.exit(1)};
process.on("uncaughtException",error=>{console.error("FAIL maintenance desktop",error);app.exit(1)});
process.on("unhandledRejection",error=>{console.error("FAIL maintenance desktop",error);app.exit(1)});
const timeout=setTimeout(()=>{console.error("FAIL maintenance desktop timeout");app.exit(1)},120000);let window;
const created=new Promise(resolve=>app.once("browser-window-created",(_event,value)=>{window=value;value.hide();value.webContents.setBackgroundThrottling(false);value.webContents.once("did-finish-load",()=>{value.hide();resolve()})}));
const evaluate=source=>window.webContents.executeJavaScript(source);
async function waitFor(source){for(let i=0;i<200;i++){if(await evaluate(source))return;await delay(50)}throw new Error("Maintenance UI condition failed: "+source)}
async function fill(selector,value){await evaluate(`(()=>{const input=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(value)});input.dispatchEvent(new Event('input',{bubbles:true}));})()`)}
async function fillMaster(value) { for (const selector of ['.cipher-form input[name=master]', '.cipher-form input[name=confirm]']) if (await evaluate(`!!document.querySelector(${JSON.stringify(selector)})`)) await fill(selector, value); }
const click=selector=>evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
const hash=file=>createHash("sha256").update(fs.readFileSync(file)).digest("hex");
async function run(){
  try{
    const context=await createMigratedFixture(directory),source=path.join(directory,"vaults",context.vaultId,"vault.sqlite"),sourceHash=hash(source),legacyHash=hash(path.join(directory,"password-manager.db"));
    maintenance.openApplicationVault({dataDirectory:directory});await vault.unlockVault({masterPassword:v2Password});const rename=fs.renameSync;let interrupted=false;
    try{
      fs.renameSync=(a,b)=>{if(!interrupted&&path.basename(b)==="vault-current.json"){interrupted=true;throw new Error("synthetic interruption")}return rename(a,b)};syncBuiltinESMExports();
      await assert.rejects(maintenance.runVaultMaintenance({operation:"rekey",masterPassword:v2Password,newMasterPassword:password,confirmNewMasterPassword:password,
        backupPassphrase:compatibility.backupV1.passphrase,confirmBackupPassphrase:compatibility.backupV1.passphrase},vault.getVaultStatus().sessionId),{statusCode:503});
    }finally{fs.renameSync=rename;syncBuiltinESMExports();maintenance.closeApplicationVault()}
    assert.ok(interrupted);await import("../apps/electron/dist/apps/electron/src/main.js");await created;
    await waitFor("!!document.querySelector('.vault-maintenance-dialog[open] form')");assert.equal(storage.hasVaultStorage(),false);assert.equal(vaultSession.getState().isUnlocked,false);
    assert.equal(await evaluate("!document.querySelector('.cipher-form')&&!document.querySelector('.entry-row')&&!document.querySelector('.reset-entry-link')"),true);
    window.setContentSize(1000,720);await waitFor("innerWidth===1000");
    assert.equal(await evaluate("(()=>{const dialog=document.querySelector('.vault-maintenance-dialog');return dialog.scrollWidth<=dialog.clientWidth})()"),true);
    window.setContentSize(1100,820);
    for(const [index,value] of [v2Password,password,password,compatibility.backupV1.passphrase].entries())await fill(`.maintenance-fields label:nth-child(${index+1}) input`,value);
    await click('.vault-maintenance-dialog button[type=submit]');await waitFor("document.querySelector('.vault-tool-message')?.textContent.includes('新しいマスターパスワードで開いて')");
    assert.equal(vaultSession.getState().isUnlocked,false);assert.equal(hash(source),sourceHash);assert.equal(hash(path.join(directory,"password-manager.db")),legacyHash);
    await click('.vault-maintenance-dialog .vault-tool-heading button');await waitFor("!document.querySelector('.vault-maintenance-dialog[open]')");
    await fillMaster(password);await click('.cipher-form button[type=submit]');await waitFor("!!document.querySelector('.entry-row')");
    const state=vault.getVaultStatus();assert.equal(state.isUnlocked,true);assert.equal(state.maintenance.state,"ready");
    console.log("PASS actual recovery-only startup hides normal unlock and shows the bounded recovery form at the desktop minimum size");
    console.log("PASS actual recovery form authenticates the interrupted target, preserves sources and unlocks with its new master");
    const legacyDirectory=path.join(profile,"legacy-ui-data"),legacySource=path.join(legacyDirectory,"password-manager.db"),migrationPassword="synthetic-legacy-ui-migration-password",shortPassword="";
    fs.mkdirSync(legacyDirectory);fs.copyFileSync(path.join(directory,"password-manager.db"),legacySource);
    const database=new Database(legacySource),legacyKey=await deriveVaultKey(shortPassword,compatibility.legacy.metadata.passwordSalt);
    try{
      database.prepare("UPDATE vault_metadata SET password_verifier=?,kdf_params=?").run(deriveVerifier(legacyKey),JSON.stringify({algorithm:"scrypt",keyLength:32,verifierAlgorithm:"hmac-sha256-v1"}));
      const update=database.prepare("UPDATE password_entries SET encrypted_password=?,encrypted_notes=? WHERE id=?");
      for(const entry of compatibility.legacy.entries)update.run(encryptLegacySecret(legacyKey,entry.password),encryptLegacySecret(legacyKey,entry.notes),entry.id);
    }finally{legacyKey.fill(0);database.close()}
    maintenance.closeApplicationVault();maintenance.openApplicationVault({dataDirectory:legacyDirectory});
    await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
    await fillMaster(shortPassword);await click('.cipher-form button[type=submit]');await waitFor("!!document.querySelector('.entry-row')");
    const beforeMigration=hash(legacySource);
    await evaluate("[...document.querySelectorAll('.app-menu-trigger')].find(b=>b.textContent==='ツール').click()");
    await waitFor("[...document.querySelectorAll('.app-menu-item')].some(b=>b.textContent==='保管庫を更新…'&&!b.disabled)");
    await evaluate("[...document.querySelectorAll('.app-menu-item')].find(b=>b.textContent==='保管庫を更新…').click()");
    await waitFor("document.querySelector('.vault-maintenance-dialog[open] button[type=submit]')?.textContent==='更新する'");
    for(const [index,value] of [shortPassword,migrationPassword,migrationPassword,compatibility.backupV1.passphrase,compatibility.backupV1.passphrase].entries())await fill(`.maintenance-fields label:nth-child(${index+1}) input`,value);
    await click('.vault-maintenance-dialog button[type=submit]');await waitFor("document.querySelector('.vault-tool-message')?.textContent.includes('新しいマスターパスワードで開いて')");
    assert.equal(hash(legacySource),beforeMigration);assert.equal(storage.isV2Vault(),true);assert.equal(vaultSession.getState().isUnlocked,false);
    await click('.vault-maintenance-dialog .vault-tool-heading button');await waitFor("!document.querySelector('.vault-maintenance-dialog[open]')");
    await fillMaster(migrationPassword);await click('.cipher-form button[type=submit]');await waitFor("!!document.querySelector('.entry-row')");
    console.log("PASS actual legacy management form migrates entries, retains the source and unlocks the new format");
    const key=vaultSession.requireKey(),store=storage.getV2Vault().store;app.once("will-quit",()=>{assert.deepEqual(key,Buffer.alloc(32));assert.equal(store.closed,true);console.log("PASS recovered vault shutdown destroys its key and closes storage")});
    clearTimeout(timeout);window.destroy();app.quit();
  }catch(error){clearTimeout(timeout);console.error("FAIL maintenance integration",error);app.exit(1)}
}
void run();
