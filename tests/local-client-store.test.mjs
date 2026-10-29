import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, linkSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import Database from "better-sqlite3";
import { createLocalAuthFixture } from "./local-auth-fixture.mjs";
import { createLocalClientStore, openLocalClientStore, LocalClientRegistryError } from "../apps/electron/dist/apps/electron/src/local-client-store.js";

const code = expected => error => { assert.ok(error instanceof LocalClientRegistryError); assert.equal(error.code, expected); assert.equal(error.message, "クライアント登録を利用できません"); return true; };
function fixture() {
  const context = createLocalAuthFixture("unused"), host = context.identity("host");
  return { ...context, host, createIdentity: context.identity, file: path.join(context.directory, "clients.sqlite") };
}
const input = (identity, now, name = "合成クライアント") => ({ displayName: name, kind: "agent", certificate: identity.certificate, expiresAt: now + 60000 });

test("registration persists only canonical public certificates, immutable IDs and revocation tombstones", () => {
  const context = fixture();
  let store;
  try {
    const credential = context.createIdentity("client"), now = Date.now();
    store = createLocalClientStore(context.file, context.host.certificate);
    assert.deepEqual(store.read(), { revision: 0, clients: [] });
    const registration = store.enroll(0, { ...input(credential, now), certificate: Buffer.concat([credential.certificate, credential.privateKey]) }, now);
    assert.ok(Object.isFrozen(registration)); assert.equal(registration.certificate, undefined);
    assert.notEqual(registration.clientId, "合成クライアント");
    assert.throws(() => store.enroll(0, input(credential, now), now), code("CONFLICT"));
    store.revoke(1, registration.clientId, now + 1); store.close();
    store = openLocalClientStore(context.file, context.host.certificate);
    assert.equal(store.read().revision, 2); assert.equal(store.read().clients[0].revokedAt, now + 1);
    assert.throws(() => store.enroll(2, input(credential, now), now), code("CONFLICT"));
    store.close();
    const bytes = readFileSync(context.file);
    assert.equal(bytes.includes(credential.privateKey), false); assert.equal(bytes.includes(Buffer.from("PRIVATE KEY")), false);
    const raw = new Database(context.file);
    try { assert.equal(raw.pragma("application_id", { simple: true }), 0x43564c52); assert.equal(raw.pragma("user_version", { simple: true }), 2); }
    finally { raw.close(); }
  } finally { store?.close(); context.dispose(); }
});

test("open/create never replace existing data and reject wrong host, unsupported schema and hard links", () => {
  const context = fixture(); let store;
  try {
    assert.throws(() => openLocalClientStore(context.file, context.host.certificate), code("UNAVAILABLE")); assert.equal(existsSync(context.file), false);
    for (const content of ["", "synthetic-existing-data-canary"]) {
      const file = context.file + content.length; writeFileSync(file, content);
      assert.throws(() => createLocalClientStore(file, context.host.certificate), code("UNAVAILABLE")); assert.equal(readFileSync(file, "utf8"), content);
    }
    store = createLocalClientStore(context.file, context.host.certificate); store.close();
    const wrong = context.createIdentity("wrong-host"); assert.throws(() => openLocalClientStore(context.file, wrong.certificate), code("INVALID_STORE"));
    linkSync(context.file, context.file + ".link"); assert.throws(() => openLocalClientStore(context.file, context.host.certificate), code("INVALID_STORE"));
    const other = context.file + ".schema"; store = createLocalClientStore(other, context.host.certificate); store.close();
    const raw = new Database(other); raw.pragma("user_version = 99"); raw.close();
    assert.throws(() => openLocalClientStore(other, context.host.certificate), code("INVALID_STORE"));
    assert.throws(() => createLocalClientStore("relative.sqlite", context.host.certificate), code("INVALID_INPUT"));
  } finally { store?.close(); context.dispose(); }
});

test("exclusive registry ownership prevents a second connection/process from mutating client pins", () => {
  const context = fixture(); let store;
  try {
    store = createLocalClientStore(context.file, context.host.certificate);
    assert.throws(() => openLocalClientStore(context.file, context.host.certificate), code("UNAVAILABLE"));
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `import D from ${JSON.stringify(import.meta.resolve("better-sqlite3"))};const d=new D(process.argv[1],{timeout:0});try{d.exec("UPDATE local_host SET revision=revision+1");process.exitCode=2}catch(e){if(e.code!=="SQLITE_BUSY")throw e}finally{d.close()}`, context.file], { env: process.env, windowsHide: true, encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 0, result.stdout + result.stderr); assert.equal(store.read().revision, 0);
    store.close(); store = openLocalClientStore(context.file, context.host.certificate); assert.equal(store.read().revision, 0);
  } finally { store?.close(); context.dispose(); }
});

test("enrollment validates names, certificate lifetime, exact fields and active client quota", () => {
  const context = fixture(); let store;
  try {
    store = createLocalClientStore(context.file, context.host.certificate); const client = context.createIdentity("client"); let now = Date.now();
    const valid = input(client, now);
    for (const patch of [{ displayName: " " }, { displayName: "spoof\u202eagent" }, { displayName: "a\nclient" }, { kind: "admin" }, { privateKey: client.privateKey }, { expiresAt: now }, { expiresAt: now + 2 * 86400000 }, { certificate: Buffer.from("synthetic-private-canary") }]) {
      assert.throws(() => store.enroll(0, { ...valid, ...patch }, now), code("INVALID_INPUT")); assert.equal(store.read().revision, 0);
    }
    assert.throws(() => store.enroll(0, input(context.host, now), now), code("CONFLICT"));
    for (let i = 0; i < 16; i++) { const credential = context.createIdentity("quota-" + i); now = Date.now(); store.enroll(i, input(credential, now), now); }
    assert.throws(() => store.enroll(16, valid, now), code("LIMIT")); assert.equal(store.read().clients.length, 16);
    store.revoke(16, store.read().clients[0].clientId, now + 1); store.enroll(17, valid, now + 2);
    assert.equal(store.read().clients.length, 17);
  } finally { store?.close(); context.dispose(); }
});
