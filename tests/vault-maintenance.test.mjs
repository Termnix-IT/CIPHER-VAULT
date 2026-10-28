import assert from "node:assert/strict";
import {before,after,afterEach,mock,test} from "node:test";
import fs from "node:fs";
import path from "node:path";
import {tmpdir} from "node:os";
import crypto from "node:crypto";
import {syncBuiltinESMExports} from "node:module";
import {createServer} from "node:http";
import {spawn} from "node:child_process";
import {once} from "node:events";
import {setTimeout as delay} from "node:timers/promises";
import {compatibility,createMigratedFixture,v2Password} from "./v2-runtime-fixture.mjs";
import * as maintenance from "../apps/api/dist/apps/api/src/services/vault-maintenance-service.js";
import * as storage from "../apps/api/dist/apps/api/src/db/vault-context.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import {vaultSession} from "../apps/api/dist/apps/api/src/services/vault-session.js";
import {router} from "../apps/api/dist/apps/api/src/routes/router.js";

const root=fs.mkdtempSync(path.join(tmpdir(),"cipher-vault-maintenance-")),base=path.join(root,"base"),newPassword="synthetic-maintenance-new-password";
let context,sequence=0;
before(async()=>{context=await createMigratedFixture(base)});
const fixture=()=>{const dir=path.join(root,`case-${++sequence}`);fs.cpSync(base,dir,{recursive:true});return dir};
const source=dir=>path.join(dir,"vaults",context.vaultId,"vault.sqlite");
const hash=file=>crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const payload=(operation="rekey",masterPassword=v2Password)=>({operation,masterPassword,newMasterPassword:newPassword,confirmNewMasterPassword:newPassword,
  backupPassphrase:compatibility.backupV1.passphrase,confirmBackupPassphrase:compatibility.backupV1.passphrase,...(operation==="reset"?{confirmation:"RESET_ALL_DATA"}:{})});
const run=value=>maintenance.runVaultMaintenance(value,vault.getVaultStatus().sessionId);
const sorted=items=>[...items].sort((a,b)=>a.id.localeCompare(b.id));
async function open(dir=fixture()){maintenance.openApplicationVault({dataDirectory:dir});await vault.unlockVault({masterPassword:v2Password});return dir}
afterEach(async()=>{mock.restoreAll();syncBuiltinESMExports();maintenance.closeApplicationVault();await maintenance.waitForVaultMaintenance();storage.closeVaultStorage()});
after(()=>{assert.equal(path.dirname(root),path.resolve(tmpdir()));assert.ok(path.basename(root).startsWith("cipher-vault-maintenance-"));fs.rmSync(root,{recursive:true,force:true,maxRetries:5,retryDelay:200})});

test("normal rekey closes the source, reopens the verified target locked, and reports no secrets or paths",async()=>{
  const dir=await open(),before=hash(source(dir)),states=[],unsubscribe=vault.onVaultState(state=>states.push(state)),key=vaultSession.requireKey(),generation=vaultSession.requireUnlocked();
  await run(payload());unsubscribe();const status=vault.getVaultStatus();
  assert.equal(status.isUnlocked,false);assert.deepEqual(status.maintenance,{state:"ready",format:"v2"});assert.deepEqual(key,Buffer.alloc(32));
  assert.ok(states.some(s=>s.maintenance?.state==="running"));assert.equal(hash(source(dir)),before);assert.notEqual(storage.getVaultStoragePath(),source(dir));
  assert.ok(states.filter(s=>s.maintenance?.state==="running").every(s=>!s.isUnlocked));
  assert.ok(states.filter(s=>s.maintenance?.state==="running").every(s=>s.maintenance.sourceSessionId===generation));
  assert.ok(!JSON.stringify(states).includes(dir));assert.ok(!JSON.stringify(states).includes(newPassword));
  await vault.unlockVault({masterPassword:newPassword});assert.deepEqual(sorted(entries.listEntries().items.map(e=>entries.getEntryById(e.id))),sorted(compatibility.legacy.entries));
});
test("legacy migration preserves its source and activates a new fully authenticated v2 context",async()=>{
  const dir=fixture();for(const name of ["vault-current.json","vault-activation.json"])fs.unlinkSync(path.join(dir,name));
  maintenance.openApplicationVault({dataDirectory:dir});await vault.unlockVault({masterPassword:compatibility.legacy.password});
  const before=hash(path.join(dir,"password-manager.db"));await run(payload("migrate",compatibility.legacy.password));assert.equal(hash(path.join(dir,"password-manager.db")),before);
  assert.equal(storage.isV2Vault(),true);assert.equal(vault.getVaultStatus().isUnlocked,false);await vault.unlockVault({masterPassword:newPassword});
  assert.equal(entries.listEntries().items.length,compatibility.legacy.entries.length);
});
test("safe reset requires credentials and explicit confirmation, and selects a new empty vault",async()=>{
  const dir=await open(),before=hash(source(dir));await assert.rejects(run({...payload("reset"),confirmation:undefined}),{statusCode:400});
  await run(payload("reset"));assert.equal(hash(source(dir)),before);await vault.unlockVault({masterPassword:newPassword});assert.equal(entries.listEntries().items.length,0);
});
test("locked and stale generations, input extras and readonly storage refuse changes before native KDF",async()=>{
  const dir=await open(),old=vault.getVaultStatus().sessionId;vault.lockVault();
  mock.method(crypto,"scrypt",()=>{throw new Error("must not derive")});syncBuiltinESMExports();
  await assert.rejects(maintenance.runVaultMaintenance(payload(),old),{statusCode:409});await assert.rejects(run(payload()),{statusCode:423});
  await assert.rejects(run({...payload(),dataDirectory:dir}),{statusCode:400});
  maintenance.closeApplicationVault();maintenance.openApplicationVault({dataDirectory:dir,readonly:true});await assert.rejects(run(payload()),{statusCode:403});
});
test("wrong source master leaves the original selected and requires a new unlock",async()=>{
  const dir=await open(),before=hash(source(dir));await assert.rejects(run(payload("rekey","synthetic-wrong-master")),{statusCode:401});
  assert.equal(hash(source(dir)),before);assert.equal(storage.getVaultStoragePath(),source(dir));assert.equal(vault.getVaultStatus().isUnlocked,false);
});
test("a new password rejected by ordinary unlock cannot create an inaccessible replacement",async()=>{
  const dir=await open(),before=hash(source(dir)),password="\0".repeat(200000);
  mock.method(crypto,"scrypt",()=>{throw new Error("must not derive")});syncBuiltinESMExports();
  await assert.rejects(run({...payload(),newMasterPassword:password,confirmNewMasterPassword:password}),{statusCode:413});
  assert.equal(hash(source(dir)),before);assert.equal(vaultSession.getState().isUnlocked,true);
});
test("manual lock cancels native KDF, rejects concurrent controls and keeps the gate until cleanup",async()=>{
  const dir=await open(),before=hash(source(dir)),scrypt=crypto.scrypt;let callback,key;
  const ready=new Promise(resolve=>{mock.method(crypto,"scrypt",(password,salt,length,options,done)=>scrypt(password,salt,length,options,(error,derived)=>{key=derived;callback=()=>done(error,derived);resolve()}));syncBuiltinESMExports()});
  const job=run(payload());await ready;assert.equal(vault.getVaultStatus().maintenance.state,"running");
  await assert.rejects(vault.unlockVault({masterPassword:v2Password}),{statusCode:409});await assert.rejects(run(payload()),{statusCode:409});
  vault.lockVault("suspend");callback();await assert.rejects(job,{statusCode:409});assert.deepEqual(key,Buffer.alloc(32));assert.equal(hash(source(dir)),before);assert.equal(vault.getVaultStatus().isUnlocked,false);
});
test("interrupted replacement survives actual server restart, permits only authenticated recovery and reopens locked",async()=>{
  const dir=await open(),rename=fs.renameSync;let failed=false;
  mock.method(fs,"renameSync",(a,b)=>{if(!failed&&path.basename(b)==="vault-current.json"){failed=true;throw new Error("synthetic interruption")}return rename(a,b)});syncBuiltinESMExports();
  await assert.rejects(run(payload()),{statusCode:503});assert.ok(failed);mock.restoreAll();syncBuiltinESMExports();
  assert.equal(vault.getVaultStatus().maintenance.state,"recovery-required");assert.equal(storage.hasVaultStorage(),false);
  maintenance.closeApplicationVault();maintenance.openApplicationVault({dataDirectory:dir});assert.equal(vault.getVaultStatus().isConfigured,true);
  await assert.rejects(vault.unlockVault({masterPassword:v2Password}),{statusCode:503});await assert.rejects(Promise.resolve().then(()=>vault.resetVault({confirmation:"RESET_ALL_DATA"})),{statusCode:503});
  maintenance.closeApplicationVault();const before=hash(source(dir)),probe=createServer();await new Promise(resolve=>probe.listen(0,"127.0.0.1",resolve));
  const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
  const child=spawn(process.execPath,["apps/api/dist/apps/api/src/server.js"],{env:{...process.env,PASSWORD_MANAGER_DATA_DIR:dir,PASSWORD_MANAGER_API_HOST:"127.0.0.1",PASSWORD_MANAGER_API_PORT:String(port)},stdio:["ignore","pipe","pipe"],windowsHide:true});
  let output="";child.stdout.on("data",bytes=>{output+=bytes});child.stderr.on("data",bytes=>{output+=bytes});
  try{
    const base=`http://127.0.0.1:${port}`;let initial;
    for(let attempt=0;attempt<200;attempt++){
      if(child.exitCode!==null)throw new Error("Synthetic recovery server exited: "+output);
      try{const response=await fetch(base+"/vault/status");if(response.ok){initial=await response.json();break}}catch{}
      await delay(50);
    }
    assert.ok(initial,"recovery server readiness");assert.equal(initial.maintenance.state,"recovery-required");assert.equal(initial.isUnlocked,false);
    const shell=await fetch(base+"/");assert.equal(shell.status,200);await shell.text();
    const token=(await(await fetch(base+"/vault/csrf")).json()).token;
    const headers={"Content-Type":"application/json","X-Cipher-Vault-CSRF":token,"X-Cipher-Vault-Session":initial.sessionId};
    let response=await fetch(base+"/vault/unlock",{method:"POST",headers,body:JSON.stringify({masterPassword:v2Password})});assert.equal(response.status,503);await response.json();
    response=await fetch(base+"/vault/maintenance",{method:"POST",headers,body:JSON.stringify(payload("recover"))});assert.equal(response.status,200);const recovered=await response.json();
    assert.equal(recovered.maintenance.state,"ready");assert.equal(recovered.isUnlocked,false);assert.equal(hash(source(dir)),before);
    response=await fetch(base+"/vault/unlock",{method:"POST",headers:{...headers,"X-Cipher-Vault-Session":recovered.sessionId},body:JSON.stringify({masterPassword:newPassword})});assert.equal(response.status,200);const unlocked=await response.json();
    response=await fetch(base+"/entries",{headers:{"X-Cipher-Vault-Session":unlocked.sessionId}});assert.equal(response.status,200);assert.equal((await response.json()).items.length,compatibility.legacy.entries.length);
  }finally{const closed=once(child,"close");child.kill();await closed}
});
test("unknown malformed storage is never accepted as a recoverable startup",()=>{
  const dir=fixture();fs.writeFileSync(path.join(dir,"vault-transition.json"),"{}");assert.throws(()=>maintenance.openApplicationVault({dataDirectory:dir}));assert.equal(storage.hasVaultStorage(),false);
});

test("a failed v2 operation cannot reopen the legacy original when both selection records disappear",async()=>{
  const dir=await open(),before=hash(source(dir)),scrypt=crypto.scrypt;let changed=false;
  mock.method(crypto,"scrypt",(...args)=>{if(!changed){changed=true;for(const name of ["vault-current.json","vault-activation.json"])fs.unlinkSync(path.join(dir,name))}return scrypt(...args)});syncBuiltinESMExports();
  await assert.rejects(run(payload()),{statusCode:503});assert.equal(hash(source(dir)),before);assert.equal(storage.hasVaultStorage(),false);assert.equal(vault.getVaultStatus().maintenance.state,"recovery-required");
});
test("shutdown during native KDF cancels the operation and never reopens storage",async()=>{
  const dir=await open(),before=hash(source(dir)),scrypt=crypto.scrypt;let callback;
  const ready=new Promise(resolve=>{mock.method(crypto,"scrypt",(p,s,n,o,done)=>scrypt(p,s,n,o,(error,key)=>{callback=()=>done(error,key);resolve()}));syncBuiltinESMExports()});
  const job=run(payload());await ready;maintenance.closeApplicationVault();callback();await assert.rejects(job,{statusCode:409});await maintenance.waitForVaultMaintenance();
  assert.equal(storage.hasVaultStorage(),false);assert.equal(vaultSession.getState().isUnlocked,false);assert.equal(hash(source(dir)),before);
});
test("legacy activation can also recover after an application restart",async()=>{
  const dir=fixture();for(const name of ["vault-current.json","vault-activation.json"])fs.unlinkSync(path.join(dir,name));
  maintenance.openApplicationVault({dataDirectory:dir});await vault.unlockVault({masterPassword:compatibility.legacy.password});const rename=fs.renameSync;let failed=false;
  mock.method(fs,"renameSync",(a,b)=>{if(!failed&&path.basename(b)==="vault-current.json"){failed=true;throw new Error("synthetic interruption")}return rename(a,b)});syncBuiltinESMExports();
  await assert.rejects(run(payload("migrate",compatibility.legacy.password)),{statusCode:503});mock.restoreAll();syncBuiltinESMExports();assert.ok(failed);
  maintenance.closeApplicationVault();maintenance.openApplicationVault({dataDirectory:dir});assert.equal(vault.getVaultStatus().maintenance.recoveryOperation,"migrate");
  await run(payload("recover",compatibility.legacy.password));await vault.unlockVault({masterPassword:newPassword});assert.equal(entries.listEntries().items.length,compatibility.legacy.entries.length);
});
test("HTTP maintenance requires trusted origin, CSRF, current generation and source unlock",async()=>{
  await open();const server=createServer((req,res)=>void router(req,res));await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    const base=`http://127.0.0.1:${server.address().port}`,token=(await(await fetch(base+"/vault/csrf")).json()).token,sessionId=vault.getVaultStatus().sessionId;
    const headers={"Content-Type":"application/json","X-Cipher-Vault-CSRF":token,"X-Cipher-Vault-Session":sessionId};
    let response=await fetch(base+"/vault/maintenance",{method:"POST",headers:{...headers,Origin:"https://untrusted.example.test"},body:JSON.stringify(payload())});assert.equal(response.status,403);
    response=await fetch(base+"/vault/maintenance",{method:"POST",headers:{...headers,"X-Cipher-Vault-CSRF":"wrong"},body:JSON.stringify(payload())});assert.equal(response.status,403);
    response=await fetch(base+"/vault/maintenance",{method:"POST",headers:{...headers,"X-Cipher-Vault-Session":"stale"},body:JSON.stringify(payload())});assert.equal(response.status,409);
    const largePassword='"'.repeat(300000),body=JSON.stringify({...payload(),newMasterPassword:largePassword,confirmNewMasterPassword:largePassword});assert.ok(Buffer.byteLength(body)>1024*1024);
    response=await fetch(base+"/vault/maintenance",{method:"POST",headers,body});assert.equal(response.status,200);const status=await response.json();assert.equal(status.isUnlocked,false);assert.equal(status.maintenance.format,"v2");
    await vault.unlockVault({masterPassword:largePassword});assert.equal(entries.listEntries().items.length,compatibility.legacy.entries.length);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
});

test("HTTP disconnection cancels a pending native KDF and releases its source without publication",async()=>{
  const dir=await open(),before=hash(source(dir)),scrypt=crypto.scrypt;let callback,markClosed;
  const disconnected=new Promise(resolve=>{markClosed=resolve}),server=createServer((req,res)=>{if(req.url==="/vault/maintenance")res.once("close",markClosed);void router(req,res)});
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    const base=`http://127.0.0.1:${server.address().port}`,token=(await(await fetch(base+"/vault/csrf")).json()).token;
    const ready=new Promise(resolve=>{mock.method(crypto,"scrypt",(p,s,n,o,done)=>scrypt(p,s,n,o,(error,key)=>{callback=()=>done(error,key);resolve()}));syncBuiltinESMExports()});
    const abort=new AbortController(),request=fetch(base+"/vault/maintenance",{method:"POST",signal:abort.signal,headers:{"Content-Type":"application/json","X-Cipher-Vault-CSRF":token,"X-Cipher-Vault-Session":vault.getVaultStatus().sessionId},body:JSON.stringify(payload())}).catch(error=>error);
    await ready;abort.abort();await disconnected;callback();await maintenance.waitForVaultMaintenance();assert.equal((await request).name,"AbortError");
    assert.equal(hash(source(dir)),before);assert.equal(vault.getVaultStatus().isUnlocked,false);assert.equal(vault.getVaultStatus().maintenance.state,"ready");
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}
});
