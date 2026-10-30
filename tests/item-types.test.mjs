import test, { before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import Database from "better-sqlite3";
import { compatibility, createMigratedFixture, v2Password } from "./v2-runtime-fixture.mjs";
import * as maintenance from "../apps/api/dist/apps/api/src/services/vault-maintenance-service.js";
import * as vault from "../apps/api/dist/apps/api/src/services/vault-service.js";
import * as entries from "../apps/api/dist/apps/api/src/services/entry-service.js";
import * as backup from "../apps/api/dist/apps/api/src/services/backup-service.js";
import { auditVault } from "../apps/api/dist/apps/api/src/services/audit-service.js";
import { getV2Vault, getVaultStoragePath } from "../apps/api/dist/apps/api/src/db/vault-context.js";
import { parseBackupV1 } from "../apps/api/dist/apps/api/src/crypto/backup-v1.js";
import { parseVaultBackup, decodeVaultBackup, validateVaultEntries } from "../apps/api/dist/apps/api/src/crypto/vault-backup.js";
import { deriveBackupKey } from "../apps/api/dist/apps/api/src/crypto/backup-v1.js";
import { parseVaultEntryPayload } from "../apps/api/dist/apps/api/src/lib/vault-entry-validation.js";
import { router } from "../apps/api/dist/apps/api/src/routes/router.js";

const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cipher-vault-item-types-")), base = path.join(root, "base");
const secret = "  synthetic-api-secret-🔑\n", code = "007", number = "4111111111111111", passphrase = compatibility.backupV1.passphrase;
const api = () => ({ type: "apiKey", serviceName: "Synthetic API", url: "https://user:synthetic@example.test/path?private=canary", apiKey: { key: secret, keyId: "private-id-canary", expiresOn: "2029-12-31" }, tags: ["api"], group: "Synthetic" });
const card = () => ({ type: "creditCard", serviceName: "Synthetic Card", card: { number: "4111-1111 1111 1111", cardholder: "SYNTHETIC OWNER", expiryMonth: "2029-12", securityCode: code } });
let sequence = 0;
before(async () => { await createMigratedFixture(base); });
async function open() { const dir = path.join(root, `case-${++sequence}`); fs.cpSync(base, dir, { recursive: true }); maintenance.openApplicationVault({ dataDirectory: dir }); await vault.unlockVault({ masterPassword: v2Password }); return dir; }
const usage = () => getV2Vault().store.getUsage().encryptionCount;
afterEach(async () => { maintenance.closeApplicationVault(); await maintenance.waitForVaultMaintenance(); });
after(() => { assert.equal(path.dirname(root), fs.realpathSync(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-item-types-")); fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); });

test("typed CRUD encrypts every field, keeps credentials exact, redacts summaries and marks old-app incompatibility", async () => {
  const dir = await open(), original = fs.readFileSync(path.join(dir, "password-manager.db"));
  const key = await entries.createEntry(api()), credit = await entries.createEntry(card());
  assert.equal(key.apiKey.key, secret); assert.equal(credit.card.number, number); assert.equal(credit.card.securityCode, code);
  assert.equal(Object.hasOwn(key, "password"), false); assert.equal(Object.hasOwn(credit, "loginId"), false);
  const list = entries.listEntries().items;
  assert.deepEqual(Object.keys(list.find(item => item.id === key.id)).sort(), ["group", "id", "serviceName", "tags", "type", "updatedAt"]);
  assert.equal(list.find(item => item.id === credit.id).cardLast4, "1111");
  for (const value of [secret, number, "SYNTHETIC OWNER", "private-id-canary"]) assert.equal(JSON.stringify(list).includes(value), false);
  const file = getVaultStoragePath(), db = new Database(file, { readonly: true });
  try { assert.equal(db.pragma("user_version", { simple: true }), 2); } finally { db.close(); }
  const bytes = fs.readFileSync(file);
  for (const value of [secret, number, "SYNTHETIC OWNER", "private-id-canary", "Synthetic API"]) assert.equal(bytes.includes(Buffer.from(value)), false);
  assert.deepEqual(fs.readFileSync(path.join(dir, "password-manager.db")), original);
  const updated = await entries.updateEntry(key.id, { ...api(), apiKey: { key: "replacement-exact", expiresOn: "" } });
  assert.deepEqual(updated.apiKey, { key: "replacement-exact", keyId: "", expiresOn: null });
  await assert.rejects(entries.updateEntry(key.id, card()), { statusCode: 400 });
  vault.lockVault(); await vault.unlockVault({ masterPassword: v2Password });
  assert.equal(entries.getEntryById(credit.id).card.securityCode, code);
  entries.deleteEntry(key.id); assert.throws(() => entries.getEntryById(key.id), { statusCode: 404 });
});

test("invalid nested input is rejected before nonce reservation without evaluating accessors", async () => {
  await open(); const beforeUses = usage(); let touched = false;
  const accessor = Object.defineProperty({}, "key", { enumerable: true, get() { touched = true; return secret; } });
  const cases = [{ ...api(), password: "private" }, { ...api(), apiKey: accessor }, { ...api(), apiKey: { key: "\ud800" } },
    { ...api(), apiKey: { key: "x".repeat(65537) } }, { ...api(), apiKey: { key: secret, expiresOn: "2027-02-30" } },
    { ...card(), card: { ...card().card, pin: "1234" } }, { ...card(), card: { ...card().card, securityCode: "1a3" } },
    { ...card(), card: { ...card().card, expiryMonth: "2027-13" } }, { ...card(), card: { ...card().card, number: 4111111111111111 } }];
  for (const value of cases) assert.throws(() => entries.createEntry(value));
  assert.equal(touched, false); assert.equal(usage(), beforeUses); assert.equal(vault.getVaultStatus().isUnlocked, true);
  assert.throws(() => validateVaultEntries([Object.defineProperty({}, "type", { get() { touched = true; } })])); assert.equal(touched, false);
  assert.equal(parseVaultEntryPayload(api()).apiKey.key, secret);
});

test("legacy storage refuses new kinds without altering existing records", async () => {
  const dir = path.join(root, `legacy-${++sequence}`); maintenance.openApplicationVault({ dataDirectory: dir });
  await vault.setupVault({ masterPassword: "synthetic-legacy-master" });
  const file = getVaultStoragePath(), original = fs.readFileSync(file);
  for (const payload of [api(), card()]) assert.throws(() => entries.createEntry(payload), { statusCode: 409 });
  assert.equal(entries.listEntries().items.length, 0); assert.deepEqual(fs.readFileSync(file), original);
});

test("mixed encrypted backup roundtrips all kinds into a differently keyed vault; login-only export remains v1", async () => {
  await open(); const oldBackup = await backup.exportBackup({ passphrase }); assert.equal(JSON.parse(oldBackup.content).version, 1);
  await entries.createEntry(api()); await entries.createEntry(card());
  const expected = entries.listEntries().items.map(item => entries.getEntryById(item.id));
  const exported = await backup.exportBackup({ passphrase }); assert.equal(JSON.parse(exported.content).version, 2); assert.throws(() => parseBackupV1(exported.content));
  for (const value of [secret, number, "private-id-canary"]) assert.equal(exported.content.includes(value), false);
  const envelope = parseVaultBackup(exported.content), key = await deriveBackupKey(passphrase, envelope.salt);
  try { assert.deepEqual(new Map(decodeVaultBackup(envelope, key).map(item => [item.id, item])), new Map(expected.map(item => [item.id, item]))); }
  finally { key.fill(0); }
  maintenance.closeApplicationVault();
  const target = path.join(root, `target-${++sequence}`); await createMigratedFixture(target); maintenance.openApplicationVault({ dataDirectory: target }); await vault.unlockVault({ masterPassword: v2Password });
  for (const item of entries.listEntries().items) entries.deleteEntry(item.id);
  await backup.restoreBackup({ passphrase, content: exported.content });
  assert.deepEqual(new Map(entries.listEntries().items.map(item => [item.id, entries.getEntryById(item.id)])), new Map(expected.map(item => [item.id, item])));
  const changedVersion = JSON.parse(exported.content); changedVersion.version = 1;
  const badEnvelope = parseVaultBackup(JSON.stringify(changedVersion)), badKey = await deriveBackupKey(passphrase, badEnvelope.salt);
  try { assert.throws(() => decodeVaultBackup(badEnvelope, badKey)); } finally { badKey.fill(0); }
  maintenance.closeApplicationVault(); await maintenance.waitForVaultMaintenance();
  const legacy = path.join(root, `legacy-restore-${++sequence}`); maintenance.openApplicationVault({ dataDirectory: legacy });
  await vault.setupVault({ masterPassword: "synthetic-legacy-restore-master" });
  const original = fs.readFileSync(getVaultStoragePath());
  await assert.rejects(backup.restoreBackup({ passphrase, content: exported.content }), { statusCode: 409 });
  assert.deepEqual(fs.readFileSync(getVaultStoragePath()), original); assert.equal(entries.listEntries().items.length, 0);
});

test("audit checks only logins in a mixed vault", async () => {
  await open(); await entries.createEntry(api()); await entries.createEntry(card());
  assert.equal((await auditVault()).total, compatibility.legacy.entries.length);
});

test("HTTP shares typed validation and returns only safe summaries", async () => {
  await open(); const server = createServer(router); await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}`, token = (await (await fetch(url + "/vault/csrf")).json()).token;
    const headers = { "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": vault.getVaultStatus().sessionId };
    const response = await fetch(url + "/entries", { method: "POST", headers, body: JSON.stringify(card()) }); assert.equal(response.status, 201);
    const created = await response.json(); assert.equal(created.card.securityCode, code);
    const summaries = await (await fetch(url + "/entries", { headers })).json();
    const summary = summaries.items.find(item => item.id === created.id); assert.equal(summary.type, "creditCard"); assert.equal(summary.cardLast4, "1111"); assert.equal(Object.hasOwn(summary, "card"), false);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
