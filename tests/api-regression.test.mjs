import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, request as httpRequest } from "node:http";
import { createCipheriv, scryptSync } from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import Database from "better-sqlite3";
import { validEntryPayload, invalidContractCases, contractRoutes } from "./input-contract-fixtures.mjs";

const temporaryRoot = mkdtempSync(path.join(tmpdir(), "cipher-vault-regression-"));
process.env.PASSWORD_MANAGER_DATA_DIR = path.join(temporaryRoot, "db");
process.env.PASSWORD_MANAGER_WEB_DIST = path.join(temporaryRoot, "web");
mkdirSync(process.env.PASSWORD_MANAGER_DATA_DIR);
const oldDatabase = new Database(path.join(process.env.PASSWORD_MANAGER_DATA_DIR, "password-manager.db"));
oldDatabase.exec(readFileSync(new URL("../apps/api/src/db/schema.sql", import.meta.url), "utf8").replace(/\s*password_changed_at TEXT,/, ""));
oldDatabase.prepare(`INSERT INTO password_entries
  (id, service_name, login_id, encrypted_password, tags, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)`)
  .run("00000000-0000-0000-0000-000000000001", "Migration", "fixture", "existing-ciphertext", "[]", "2025-01-01T00:00:00.000Z", "2025-01-01T00:00:00.000Z");
oldDatabase.close();
mkdirSync(process.env.PASSWORD_MANAGER_WEB_DIST);
writeFileSync(path.join(temporaryRoot, "web", "index.html"), "app shell");
writeFileSync(path.join(temporaryRoot, "web", "icon.png"), "test image");
mkdirSync(path.join(temporaryRoot, "web", "fonts"));
writeFileSync(path.join(temporaryRoot, "web", "fonts", "fixture.ttf"), "synthetic font MIME fixture");
mkdirSync(path.join(temporaryRoot, "web", "assets"));
mkdirSync(path.join(temporaryRoot, "web-private"));
writeFileSync(path.join(temporaryRoot, "web-private", "secret.txt"), "must not be served");

const base = "../apps/api/dist/apps/api/src/";
const { openDatabase, closeDatabase } = await import(`${base}db/database.js`);
const database = openDatabase();
const vault = await import(`${base}services/vault-service.js`);
const entries = await import(`${base}services/entry-service.js`);
const crypto = await import(`${base}services/crypto-service.js`);
const store = await import(`${base}services/vault-store.js`);
const { generatePassword } = await import(`${base}services/password-service.js`);
const { router } = await import(`${base}routes/router.js`);
const backup = await import(`${base}services/backup-service.js`);
const { auditVault } = await import(`${base}services/audit-service.js`);
const { tryServeStaticAsset } = await import(`${base}lib/static.js`);
const { vaultSession, VAULT_IDLE_TIMEOUT_MS } = await import(`${base}services/vault-session.js`);
const server = createServer((request, response) => void router(request, response));
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

async function apiRequest(pathname, init = {}) {
  const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
  return fetch(`${origin}${pathname}`, {
    ...init,
    headers: { "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": vault.getVaultStatus().sessionId, Origin: origin, ...init.headers }
  });
}

// Use node:http for attack fixtures: Fetch can normalize or discard Host/metadata headers.
function rawRequest(pathname, method, headers, body) {
  return new Promise((resolve, reject) => {
    const request = httpRequest(`${origin}${pathname}`, { method, headers }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode));
    });
    request.on("error", reject);
    request.end(body);
  });
}

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  vault.lockVault();
  closeDatabase();
  const relative = path.relative(tmpdir(), temporaryRoot);
  assert.ok(relative.startsWith("cipher-vault-regression-") && !relative.includes(path.sep));
  rmSync(temporaryRoot, { recursive: true, force: true });
});

const backupPassphrase = "backup-only-test-passphrase";
function entryPayload(entry, changes = {}) {
  const { serviceName, loginId, password, notes, url, tags, group } = entry;
  return { serviceName, loginId, password, notes, url, tags, group, ...changes };
}
test("old database gains an unknown password change date without rewriting ciphertext", () => {
  const row = database.prepare("SELECT encrypted_password, password_changed_at FROM password_entries").get();
  assert.equal(row.password_changed_at, null);
  assert.equal(row.encrypted_password, "existing-ciphertext");
});
async function freshVault() {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  await vault.setupVault({ masterPassword: "temporary-test-password" });
}

test("HTTP rejects foreign origins, DNS rebinding hosts and unverified mutations without resetting a locked vault", async () => {
  await freshVault();
  const created = entries.createEntry({ serviceName: "CSRF fixture", loginId: "fixture", password: "dummy secret" });
  vault.lockVault();
  const csrfResponse = await fetch(`${origin}/vault/csrf`);
  assert.equal(csrfResponse.headers.get("cache-control"), "no-store");
  const { token } = await csrfResponse.json();
  assert.match(token, /^[a-f0-9]{64}$/);
  const body = JSON.stringify({ confirmation: "RESET_ALL_DATA" });
  for (const headers of [
    { "Content-Type": "text/plain", Origin: "http://evil.example" },
    { "Content-Type": "application/json", Origin: "http://evil.example", "X-Cipher-Vault-CSRF": token },
    { "Content-Type": "application/json", Origin: "null", "X-Cipher-Vault-CSRF": token },
    { "Content-Type": "application/json", Origin: "http://localhost:5200", "X-Cipher-Vault-CSRF": token },
    { "Content-Type": "application/json", Origin: origin, "Sec-Fetch-Site": "cross-site", "X-Cipher-Vault-CSRF": token },
    { "Content-Type": "application/json", Origin: origin },
    { "Content-Type": "application/json", Origin: origin, "X-Cipher-Vault-CSRF": "0".repeat(64) },
    { "Content-Type": "application/json", Origin: origin, "X-Cipher-Vault-CSRF": "é".repeat(64) },
    { "Content-Type": "text/plain", Origin: origin, "X-Cipher-Vault-CSRF": token },
    { "Content-Type": "application/json", Host: `evil.example:${server.address().port}`, "X-Cipher-Vault-CSRF": token }
  ]) {
    const status = await rawRequest("/vault/reset", "POST", headers, body);
    assert.ok([403, 415].includes(status), `unexpected status ${status}`);
    assert.equal(vault.getVaultStatus().isConfigured, true);
    assert.equal(vault.getVaultStatus().isUnlocked, false);
  }
  for (const pathname of ["/vault/csrf", "/entries", `/entries/${created.id}`]) {
    assert.equal(await rawRequest(pathname, "GET", { Origin: "http://evil.example" }), 403);
    assert.equal(await rawRequest(pathname, "GET", { "Sec-Fetch-Site": "cross-site" }), 403);
    assert.equal(await rawRequest(pathname, "GET", { Host: `evil.example:${server.address().port}` }), 403);
  }
  assert.equal((await apiRequest("/vault/unlock", { method: "POST", body: JSON.stringify({ masterPassword: "temporary-test-password" }) })).status, 200);
  assert.equal((await apiRequest(`/entries/${created.id}`)).status, 200);
  assert.equal((await apiRequest(`/entries/${created.id}`, { method: "DELETE" })).status, 200);
  assert.equal((await apiRequest("/vault/lock", { method: "POST" })).status, 200);
  assert.equal((await apiRequest("/vault/reset", { method: "POST", body })).status, 200);
  assert.equal(vault.getVaultStatus().isConfigured, false);
});

test("encrypted backup restores all fields under a different vault key and rejects nonempty vaults", async () => {
  await freshVault();
  const created = entries.createEntry({ serviceName: "秘密のサービス", loginId: "private@example.test", password: "sensitive-password", notes: "秘密のメモ", url: "https://example.test", tags: ["日本語", "work"], group: "個人" });
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  const second = await backup.exportBackup({ passphrase: backupPassphrase });
  assert.notEqual(exported.content, second.content);
  assert.ok(exported.fileName.endsWith(".cvault"));
  for (const secret of [created.serviceName, created.loginId, created.password, created.notes, created.url, backupPassphrase]) {
    assert.ok(!exported.content.includes(secret));
  }
  await assert.rejects(backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase }), { statusCode: 409 });
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  await vault.setupVault({ masterPassword: "different-master-password" });
  assert.deepEqual(await backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase }), { restoredCount: 1 });
  vault.lockVault();
  await vault.unlockVault({ masterPassword: "different-master-password" });
  assert.deepEqual(entries.getEntryById(created.id), created);
});

test("backup rejects wrong passphrase, tampering, invalid versions and rolls back failed writes", async () => {
  await freshVault();
  const first = entries.createEntry({ serviceName: "One", loginId: "one", password: "secret" });
  entries.createEntry({ serviceName: "Two", loginId: "two", password: "secret2" });
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  await freshVault();
  await assert.rejects(backup.restoreBackup({ content: exported.content, passphrase: "incorrect-passphrase" }), { statusCode: 400 });
  for (const field of ["data", "tag", "iv", "salt"]) {
    const modified = JSON.parse(exported.content);
    const bytes = Buffer.from(modified[field], "base64"); bytes[0] ^= 1;
    modified[field] = bytes.toString("base64");
    await assert.rejects(backup.restoreBackup({ content: JSON.stringify(modified), passphrase: backupPassphrase }), { statusCode: 400 });
  }
  for (const content of ["not json", "null", JSON.stringify({ ...JSON.parse(exported.content), version: 99 })]) {
    await assert.rejects(backup.restoreBackup({ content, passphrase: backupPassphrase }), { statusCode: 400 });
  }
  await assert.rejects(backup.restoreBackup({ content: "x".repeat(16 * 1024 * 1024 + 1), passphrase: backupPassphrase }), { statusCode: 413 });
  assert.deepEqual(entries.listEntries().items, []);
  database.exec("CREATE TRIGGER reject_second_restore BEFORE INSERT ON password_entries WHEN (SELECT COUNT(*) FROM password_entries) > 0 BEGIN SELECT RAISE(ABORT, 'test restore failure'); END");
  try {
    await assert.rejects(backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase }), /test restore failure/);
    assert.deepEqual(entries.listEntries().items, []);
  } finally { database.exec("DROP TRIGGER reject_second_restore"); }
  await backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase });
  assert.equal(entries.getEntryById(first.id).password, "secret");
});

test("backup operations enforce lock state and session changes during key derivation", async () => {
  await freshVault();
  const inFlight = backup.exportBackup({ passphrase: backupPassphrase });
  const cancelled = assert.rejects(inFlight, (error) => [409, 423].includes(error.statusCode));
  await assert.rejects(backup.exportBackup({ passphrase: backupPassphrase }), { statusCode: 409 });
  vault.lockVault();
  await vault.unlockVault({ masterPassword: "temporary-test-password" });
  await cancelled;
  vault.lockVault();
  await assert.rejects(backup.exportBackup({ passphrase: backupPassphrase }), { statusCode: 423 });
  await assert.rejects(backup.restoreBackup({ passphrase: backupPassphrase, content: "{}" }), { statusCode: 423 });
  await assert.rejects(auditVault(), { statusCode: 423 });
});

test("restore rejects authenticated invalid records and rechecks empty state after key derivation", async () => {
  await freshVault();
  const entry = entries.createEntry({ serviceName: "Record", loginId: "user", password: "secret" });
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  await freshVault();
  const envelope = JSON.parse(exported.content);
  const key = scryptSync(backupPassphrase, Buffer.from(envelope.salt, "base64"), 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  try {
    for (const records of [[entry, entry], [{ ...entry, password: 123 }], [{ ...entry, passwordChangedAt: "not a date" }]]) {
      const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
      cipher.setAAD(Buffer.from("CIPHER-VAULT:1:scrypt-N131072-r8-p1:aes-256-gcm"));
      const data = Buffer.concat([cipher.update(JSON.stringify({ version: 1, entries: records })), cipher.final()]);
      const content = JSON.stringify({ ...envelope, data: data.toString("base64"), tag: cipher.getAuthTag().toString("base64") });
      await assert.rejects(backup.restoreBackup({ content, passphrase: backupPassphrase }), { statusCode: 400 });
      assert.equal(entries.listEntries().items.length, 0);
    }
  } finally { key.fill(0); }
  const pending = backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase });
  const concurrent = entries.createEntry({ serviceName: "Concurrent", loginId: "user", password: "keep this" });
  await assert.rejects(pending, { statusCode: 409 });
  assert.equal(entries.listEntries().items.length, 1);
  assert.equal(entries.getEntryById(concurrent.id).password, "keep this");
});

test("audit reports local issues without secrets and tracks password changes separately", async () => {
  await freshVault();
  assert.equal((await auditVault()).score, null);
  const first = entries.createEntry({ serviceName: "One", loginId: "one", password: "password", notes: "never return notes" });
  const second = entries.createEntry({ serviceName: "Two", loginId: "two", password: "password", url: "https://example.test" });
  const strong = entries.createEntry({ serviceName: "Three", loginId: "three", password: "9M!z2G$qP7v#D4w@K8nX", url: "https://example.test" });
  const old = new Date(Date.now() - 366 * 86400000).toISOString();
  database.prepare("UPDATE password_entries SET created_at = ?, updated_at = ?, password_changed_at = ? WHERE id = ?").run(old, old, old, first.id);
  database.prepare("UPDATE password_entries SET password_changed_at = NULL WHERE id = ?").run(second.id);
  const result = await auditVault();
  assert.deepEqual(result.counts, { weak: 2, duplicate: 2, oldPassword: 1, missingUrl: 1, staleEntry: 1 });
  assert.equal(result.score, 33);
  assert.equal(result.unknownPasswordAgeCount, 1);
  assert.ok(!JSON.stringify(result).includes(strong.password));
  assert.ok(!JSON.stringify(result).includes("never return notes"));
  const changedNotes = entries.updateEntry(first.id, entryPayload(first, { notes: "changed notes" }));
  assert.equal(changedNotes.passwordChangedAt, old);
  assert.equal((await auditVault()).counts.staleEntry, 0);
  assert.equal((await auditVault()).counts.oldPassword, 1);
  const changedPassword = entries.updateEntry(first.id, entryPayload(changedNotes, { password: "new-password-value" }));
  assert.notEqual(changedPassword.passwordChangedAt, old);
  const changedLegacyNotes = entries.updateEntry(second.id, entryPayload(second, { notes: "new notes" }));
  assert.equal(changedLegacyNotes.passwordChangedAt, null);
  assert.equal((await auditVault()).counts.duplicate, 0);
  const scanning = auditVault();
  await assert.rejects(auditVault(), { statusCode: 409 });
  vault.lockVault();
  await assert.rejects(scanning, { statusCode: 423 });
});

test("HTTP backup and audit use shared validation and enforce body size limits", async () => {
  await freshVault();
  const exported = await apiRequest("/vault/backup/export", { method: "POST", body: JSON.stringify({ passphrase: backupPassphrase }) });
  assert.equal(exported.status, 200);
  const file = await exported.json();
  const restored = await apiRequest("/vault/backup/restore", { method: "POST", body: JSON.stringify({ content: file.content, passphrase: backupPassphrase }) });
  assert.equal(restored.status, 200);
  assert.deepEqual(await restored.json(), { restoredCount: 0 });
  const audit = await apiRequest("/vault/audit", { method: "POST" });
  assert.equal(audit.status, 200);
  assert.equal((await audit.json()).score, null);
  const invalid = await apiRequest("/vault/backup/export", { method: "POST", body: "null" });
  assert.equal(invalid.status, 400);
  const large = await apiRequest("/vault/backup/export", { method: "POST", body: "x".repeat(1024 * 1024 + 1) });
  assert.equal(large.status, 413);
});

test("invalid generation options return 400", () => {
  for (const value of [null, [], { length: 12.5 }, { length: "20" }, { length: NaN }, { includeNumbers: "false" }]) {
    assert.throws(() => generatePassword(value), { statusCode: 400 });
  }
  assert.equal(generatePassword({ length: 64 }).password.length, 64);
});

test("HTTP rejects malformed JSON and handles query strings", async () => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  const malformed = await apiRequest("/vault/unlock", { method: "POST", body: "{" });
  assert.equal(malformed.status, 400);
  assert.equal((await fetch(`${origin}/health?check=1`)).status, 200);
  assert.equal((await apiRequest("/vault/setup", { method: "POST", body: "null" })).status, 400);
});

test("static serving rejects sibling paths and directories and supplies PNG MIME", async () => {
  const shell = await fetch(origin);
  assert.match(shell.headers.get("content-security-policy"), /script-src 'self';/);
  assert.match(shell.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(shell.headers.get("x-frame-options"), "DENY");
  const font = await fetch(`${origin}/fonts/fixture.ttf`);
  assert.equal(font.headers.get("content-type"), "font/ttf");
  assert.equal(font.headers.get("x-content-type-options"), "nosniff");
  assert.equal(tryServeStaticAsset("/../web-private/secret.txt", {}), false);
  assert.equal(tryServeStaticAsset("/assets", {}), false);
  const response = await fetch(`${origin}/icon.png`);
  assert.equal(response.headers.get("content-type"), "image/png");
  assert.equal(await response.text(), "test image");
  assert.equal((await fetch(`${origin}/assets`)).status, 200);
  assert.equal((await fetch(`${origin}/health`)).status, 200);
});

test("entry validation rejects invalid fields without inserting data; new vault survives lock", async () => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  await vault.setupVault({ masterPassword: "temporary-test-password" });
  const metadata = store.getVaultMetadata();
  const derived = await crypto.deriveVaultKey("temporary-test-password", metadata.passwordSalt);
  assert.notEqual(metadata.passwordVerifier, derived.toString("base64"));
  derived.fill(0);
  const valid = { serviceName: "Example", loginId: "test", password: "secret" };
  for (const value of [null, { ...valid, serviceName: 42 }, { ...valid, password: {} }, { ...valid, notes: 1 }, { ...valid, tags: [1] }]) {
    assert.throws(() => entries.createEntry(value), { statusCode: 400 });
  }
  assert.deepEqual(entries.listEntries().items, []);
  const created = entries.createEntry(valid);
  vault.lockVault();
  assert.throws(() => entries.getEntryById(created.id), { statusCode: 423 });
  await vault.unlockVault({ masterPassword: "temporary-test-password" });
  assert.equal(entries.getEntryById(created.id).password, "secret");
});

test("legacy verifier upgrades only after authentication and preserves encrypted entries", async () => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  const password = "legacy-test-password";
  const salt = crypto.createPasswordSalt();
  const key = await crypto.deriveVaultKey(password, salt);
  const legacy = { id: 1, passwordSalt: salt, passwordVerifier: key.toString("base64"), kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32 }), createdAt: "2025-01-01", updatedAt: "2025-01-01" };
  store.saveVaultMetadata(legacy);
  crypto.setActiveVaultKey(key);
  key.fill(0);
  const created = entries.createEntry({ serviceName: "Legacy", loginId: "user", password: "old secret", notes: "old notes" });
  vault.lockVault();
  await assert.rejects(vault.unlockVault({ masterPassword: "wrong password" }), { statusCode: 401 });
  assert.deepEqual(store.getVaultMetadata(), legacy);
  database.exec("CREATE TRIGGER reject_migration BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'test write failure'); END");
  await assert.rejects(vault.unlockVault({ masterPassword: password }), /test write failure/);
  assert.equal(vault.getVaultStatus().isUnlocked, false);
  assert.equal(crypto.hasActiveVaultKey(), false);
  assert.deepEqual(store.getVaultMetadata(), legacy);
  database.exec("DROP TRIGGER reject_migration");
  await vault.unlockVault({ masterPassword: password });
  assert.equal(entries.getEntryById(created.id).password, "old secret");
  assert.equal(entries.getEntryById(created.id).notes, "old notes");
  const migrated = store.getVaultMetadata();
  assert.notEqual(migrated.passwordVerifier, legacy.passwordVerifier);
  assert.equal(JSON.parse(migrated.kdfParams).verifierAlgorithm, "hmac-sha256-v1");
  vault.lockVault();
  await assert.rejects(vault.unlockVault({ masterPassword: "wrong password" }), { statusCode: 401 });
  await vault.unlockVault({ masterPassword: password });
  assert.equal(entries.getEntryById(created.id).password, "old secret");
  assert.deepEqual(store.getVaultMetadata(), migrated);
  vault.lockVault();
  store.saveVaultMetadata({ ...migrated, kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "unknown" }) });
  await assert.rejects(vault.unlockVault({ masterPassword: password }), { statusCode: 400 });
  assert.equal(vault.getVaultStatus().isUnlocked, false);
});

test("expiry is enforced across services and HTTP without a timer, without changing stored ciphertext", async () => {
  await freshVault();
  const created = entries.createEntry({ serviceName: "Session fixture", loginId: "fixture", password: "synthetic secret", notes: "synthetic notes" });
  const ciphertext = database.prepare("SELECT encrypted_password, encrypted_notes FROM password_entries WHERE id = ?").get(created.id);
  const metadata = store.getVaultMetadata();
  const id = vault.getVaultStatus().sessionId;
  const retainedKey = vaultSession.requireKey();
  const realNow = Date.now;
  try {
    Date.now = () => realNow() + VAULT_IDLE_TIMEOUT_MS + 1;
    assert.throws(() => entries.getEntryById(created.id), { statusCode: 423 });
    assert.throws(() => entries.listEntries(), { statusCode: 423 });
    assert.throws(() => entries.createEntry({ serviceName: "Denied", loginId: "x", password: "x" }), { statusCode: 423 });
    assert.throws(() => entries.updateEntry(created.id, { ...created, password: "not saved" }), { statusCode: 423 });
    assert.throws(() => entries.deleteEntry(created.id), { statusCode: 423 });
    await assert.rejects(backup.exportBackup({ passphrase: backupPassphrase }), { statusCode: 423 });
    await assert.rejects(auditVault(), { statusCode: 423 });
    assert.throws(() => vault.recordVaultActivity(id), { statusCode: 423 });
    assert.equal((await apiRequest("/entries")).status, 423);
    assert.equal((await apiRequest("/password/generate", { method: "POST" })).status, 423);
    assert.deepEqual(retainedKey, Buffer.alloc(32));
  } finally { Date.now = realNow; }
  assert.equal(vault.getVaultStatus().isUnlocked, false);
  await vault.unlockVault({ masterPassword: "temporary-test-password" });
  assert.equal(entries.getEntryById(created.id).password, created.password);
  assert.equal(entries.getEntryById(created.id).notes, created.notes);
  assert.deepEqual(database.prepare("SELECT encrypted_password, encrypted_notes FROM password_entries WHERE id = ?").get(created.id), ciphertext);
  assert.deepEqual(store.getVaultMetadata(), metadata);
});

test("expired generations cannot read, mutate, touch or lock a newly unlocked vault", async () => {
  await freshVault();
  const created = entries.createEntry({ serviceName: "Generation fixture", loginId: "fixture", password: "keep" });
  const old = vault.getVaultStatus().sessionId;
  vault.lockVault(); await vault.unlockVault({ masterPassword: "temporary-test-password" });
  const current = vault.getVaultStatus().sessionId;
  for (const [pathname, init] of [
    ["/entries", {}], [`/entries/${created.id}`, {}],
    [`/entries/${created.id}`, { method: "DELETE" }],
    ["/entries", { method: "POST", body: JSON.stringify({ serviceName: "Denied", loginId: "x", password: "x" }) }],
    ["/vault/activity", { method: "POST" }], ["/vault/lock", { method: "POST" }],
    ["/vault/unlock", { method: "POST", body: JSON.stringify({ masterPassword: "temporary-test-password" }) }],
    ["/vault/reset", { method: "POST", body: JSON.stringify({ confirmation: "RESET_ALL_DATA" }) }],
    ["/password/generate", { method: "POST" }], ["/vault/audit", { method: "POST" }],
    ["/vault/backup/export", { method: "POST", body: JSON.stringify({ passphrase: backupPassphrase }) }]
  ]) {
    const response = await apiRequest(pathname, { ...init, headers: { "X-Cipher-Vault-Session": old } });
    assert.equal(response.status, 409);
    assert.equal(vault.getVaultStatus().sessionId, current);
    assert.equal(vault.getVaultStatus().isUnlocked, true);
  }
  assert.equal((await fetch(`${origin}/entries`)).status, 409);
  assert.equal((await apiRequest("/vault/activity", { method: "POST" })).status, 200);
  assert.equal(entries.getEntryById(created.id).password, "keep");
});

test("a mutation whose body finishes in a different generation never writes", async () => {
  await freshVault();
  const old = vault.getVaultStatus().sessionId;
  const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
  const received = new Promise((resolve) => server.once("request", resolve));
  let request;
  const result = new Promise((resolve, reject) => {
    request = httpRequest(`${origin}/entries`, { method: "POST", headers: {
      "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": old
    } }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode)); });
    request.on("error", reject);
    request.flushHeaders();
    request.write('{"serviceName":"Delayed",');
  });
  await received;
  vault.lockVault(); await vault.unlockVault({ masterPassword: "temporary-test-password" });
  request.end('"loginId":"fixture","password":"must not save"}');
  assert.equal(await result, 409);
  assert.equal(entries.listEntries().items.length, 0);
});

test("backup and audit cannot finish after the idle deadline passes during an await", async () => {
  for (const action of [() => backup.exportBackup({ passphrase: backupPassphrase }), () => auditVault()]) {
    await freshVault();
    entries.createEntry({ serviceName: "Await fixture", loginId: "fixture", password: "synthetic" });
    const realNow = Date.now;
    const pending = action();
    const rejected = assert.rejects(pending, { statusCode: 423 });
    try {
      Date.now = () => realNow() + VAULT_IDLE_TIMEOUT_MS + 1;
      await rejected;
      assert.equal(vault.getVaultStatus().isUnlocked, false);
    } finally { Date.now = realNow; }
  }
});

test("locking an already locked vault invalidates an unlock still receiving its request body", async () => {
  await freshVault(); vault.lockVault();
  const intent = vault.getVaultStatus().sessionId;
  const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
  let request;
  const result = new Promise((resolve, reject) => {
    request = httpRequest(`${origin}/vault/unlock`, { method: "POST", headers: {
      "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": intent
    } }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode)); });
    request.on("error", reject);
    request.write('{"masterPassword":');
  });
  await new Promise((resolve) => setImmediate(resolve));
  vault.lockVault();
  request.end('"temporary-test-password"}');
  assert.equal(await result, 409);
  assert.equal(vault.getVaultStatus().isUnlocked, false);
});

// Hold only the native callback, keeping production APIs free of test-only hooks.
function holdVaultKdf(t) {
  const native = createRequire(import.meta.url)("node:crypto");
  const callbacks = [];
  const mocked = t.mock.method(native, "scrypt", (...args) => { callbacks.push(args.at(-1)); });
  syncBuiltinESMExports();
  const restore = () => { mocked.mock.restore(); syncBuiltinESMExports(); };
  t.after(restore);
  return { callbacks, restore };
}

test("pending setup is single-flight across HTTP and service calls, while status and cancellation remain responsive", async (t) => {
  for (const route of ["/vault/lock", "/vault/reset"]) {
    vault.resetVault({ confirmation: "RESET_ALL_DATA" });
    const held = holdVaultKdf(t);
    const pending = vault.setupVault({ masterPassword: "temporary-test-password" });
    const rejected = assert.rejects(pending, { statusCode: 409 });
    assert.equal(held.callbacks.length, 1);
    await assert.rejects(vault.setupVault({ masterPassword: "another-fixture-password" }), { statusCode: 409 });
    assert.equal((await apiRequest("/vault/setup", { method: "POST", body: JSON.stringify({ masterPassword: "another-fixture-password" }) })).status, 409);
    const status = await (await apiRequest("/vault/status")).json();
    assert.equal(status.isConfigured, false);
    assert.equal(status.isUnlocked, false);
    assert.equal((await apiRequest(route, { method: "POST", body: route === "/vault/reset" ? JSON.stringify({ confirmation: "RESET_ALL_DATA" }) : undefined })).status, 200);
    // Cancellation does not release the KDF slot before its callback returns.
    await assert.rejects(vault.setupVault({ masterPassword: "another-fixture-password" }), { statusCode: 409 });
    assert.equal(held.callbacks.length, 1);
    const key = Buffer.alloc(32, 7);
    held.callbacks[0](null, key);
    await rejected;
    assert.deepEqual(key, Buffer.alloc(32));
    assert.equal(store.getVaultMetadata(), null);
    assert.equal(vault.getVaultStatus().isUnlocked, false);
    held.restore();
    await vault.setupVault({ masterPassword: "temporary-test-password" });
  }
});

test("lock and reset during unlock reject late keys and cannot resurrect legacy metadata", async (t) => {
  for (const operation of ["lock", "reset"]) {
    await freshVault();
    const metadata = store.getVaultMetadata();
    const key = await crypto.deriveVaultKey("temporary-test-password", metadata.passwordSalt);
    const legacy = { ...metadata, passwordVerifier: key.toString("base64"), kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32 }) };
    store.saveVaultMetadata(legacy);
    const created = entries.createEntry({ serviceName: "Cancellation", loginId: "fixture", password: "preserved" });
    const row = database.prepare("SELECT * FROM password_entries WHERE id = ?").get(created.id);
    vault.lockVault();
    const held = holdVaultKdf(t);
    const pending = vault.unlockVault({ masterPassword: "temporary-test-password" });
    const rejected = assert.rejects(pending, { statusCode: 409 });
    await assert.rejects(vault.unlockVault({ masterPassword: "temporary-test-password" }), { statusCode: 409 });
    if (operation === "lock") vault.lockVaultForSession(vault.getVaultStatus().sessionId);
    else vault.resetVault({ confirmation: "RESET_ALL_DATA" });
    held.callbacks[0](null, key);
    await rejected;
    assert.deepEqual(key, Buffer.alloc(32));
    assert.equal(vault.getVaultStatus().isUnlocked, false);
    assert.deepEqual(store.getVaultMetadata(), operation === "lock" ? legacy : null);
    assert.deepEqual(database.prepare("SELECT * FROM password_entries WHERE id = ?").get(created.id), operation === "lock" ? row : undefined);
    held.restore();
  }
});

test("native KDF errors release the slot, and successful unlock wipes the temporary key after one derivation", async (t) => {
  await freshVault();
  const metadata = store.getVaultMetadata();
  const key = await crypto.deriveVaultKey("temporary-test-password", metadata.passwordSalt);
  vault.lockVault();
  const held = holdVaultKdf(t);
  const failed = vault.unlockVault({ masterPassword: "temporary-test-password" });
  const rejection = assert.rejects(failed, /synthetic native failure/);
  held.callbacks[0](new Error("synthetic native failure"));
  await rejection;
  const pending = vault.unlockVault({ masterPassword: "temporary-test-password" });
  assert.equal(held.callbacks.length, 2);
  held.callbacks[1](null, key);
  assert.equal((await pending).isUnlocked, true);
  assert.deepEqual(key, Buffer.alloc(32));
  assert.notDeepEqual(vaultSession.requireKey(), Buffer.alloc(32));
  assert.deepEqual(store.getVaultMetadata(), metadata);
});

test("HTTP exposes the shared unlock cooldown with Retry-After and success clears it", async (t) => {
  await freshVault();
  const key = await crypto.deriveVaultKey("temporary-test-password", store.getVaultMetadata().passwordSalt);
  vault.lockVault();
  const held = holdVaultKdf(t);
  for (let i = 0; i < 5; i++) {
    const pending = vault.unlockVault({ masterPassword: "wrong-fixture-password" });
    const rejected = assert.rejects(pending, { statusCode: 401 });
    const wrongKey = Buffer.alloc(32, i + 1);
    held.callbacks[i](null, wrongKey);
    await rejected;
    assert.deepEqual(wrongKey, Buffer.alloc(32));
  }
  vault.lockVault();
  const response = await apiRequest("/vault/unlock", { method: "POST", body: JSON.stringify({ masterPassword: "temporary-test-password" }) });
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("Retry-After"), "1");
  assert.match((await response.json()).error, /秒後/);
  assert.equal(held.callbacks.length, 5);
  await new Promise((resolve) => setTimeout(resolve, 1050));
  const pending = vault.unlockVault({ masterPassword: "temporary-test-password" });
  held.callbacks[5](null, key);
  assert.equal((await pending).isUnlocked, true);
  held.restore();
});

test("HTTP and direct services reject the same malformed contracts without changing the vault", async () => {
  await freshVault();
  const status = vault.getVaultStatus();
  const metadata = store.getVaultMetadata();
  const actions = { createEntry: entries.createEntry, generatePassword, exportBackup: backup.exportBackup,
    restoreBackup: backup.restoreBackup, unlockVault: vault.unlockVault, resetVault: vault.resetVault };
  for (const item of invalidContractCases()) {
    await assert.rejects(async () => actions[item.operation](item.payload), { statusCode: item.status, message: item.message });
    const response = await apiRequest(contractRoutes[item.operation], { method: "POST", body: JSON.stringify(item.payload) });
    assert.equal(response.status, item.status);
    assert.equal((await response.json()).error, item.message);
    assert.deepEqual(vault.getVaultStatus(), status);
    assert.deepEqual(store.getVaultMetadata(), metadata);
    assert.equal(entries.listEntries().items.length, 0);
  }
});

test("invalid setup/unlock inputs are rejected before any native KDF starts", async (t) => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  const held = holdVaultKdf(t);
  for (const payload of [null, [], { masterPassword: 1 }, { masterPassword: "short" },
    { masterPassword: "temporary-test-password", extra: true }]) {
    await assert.rejects(vault.setupVault(payload), { statusCode: 400 });
    assert.equal((await apiRequest("/vault/setup", { method: "POST", body: JSON.stringify(payload) })).status, 400);
  }
  const oversized = { masterPassword: "x".repeat(1024 * 1024 + 1) };
  await assert.rejects(vault.setupVault(oversized), { statusCode: 413 });
  assert.equal((await apiRequest("/vault/setup", { method: "POST", body: JSON.stringify(oversized) })).status, 413);
  assert.equal(held.callbacks.length, 0);
  held.restore();
  await vault.setupVault({ masterPassword: "temporary-test-password" });
  const heldUnlock = holdVaultKdf(t);
  for (let i = 0; i < 6; i++) await assert.rejects(vault.unlockVault({ masterPassword: [] }), { statusCode: 400 });
  await assert.rejects(vault.unlockVault(oversized), { statusCode: 413 });
  assert.equal(heldUnlock.callbacks.length, 0);
  heldUnlock.restore();
  assert.equal((await vault.unlockVault({ masterPassword: "temporary-test-password" })).isUnlocked, true);
});

test("HTTP rejects invalid UTF-8, chunked oversize bodies and unexpected control bodies without effects", async () => {
  await freshVault();
  const created = entries.createEntry(validEntryPayload());
  const initial = vault.getVaultStatus();
  const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
  const headers = { "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, "X-Cipher-Vault-Session": initial.sessionId };
  const invalidUtf8 = Buffer.concat([Buffer.from('{"serviceName":"'), Buffer.from([0xff]), Buffer.from('","loginId":"fixture","password":"synthetic"}')]);
  assert.equal(await rawRequest("/entries", "POST", headers, invalidUtf8), 400);
  assert.equal(await rawRequest("/entries", "POST", { ...headers, "Transfer-Encoding": "chunked" }, "x".repeat(1024 * 1024 + 1)), 413);
  for (const [route, method] of [["/vault/activity", "POST"], ["/vault/audit", "POST"], ["/vault/lock", "POST"], [`/entries/${created.id}`, "DELETE"]]) {
    for (const body of ["{", "null", "[]", '{"extra":true}']) {
      assert.equal((await apiRequest(route, { method, body })).status, 400);
      assert.deepEqual(vault.getVaultStatus(), initial);
      assert.equal(entries.getEntryById(created.id).password, created.password);
    }
  }
  assert.equal(entries.listEntries().items.length, 1);
});

test("legacy long fields remain readable and v1 backup roundtrips losslessly; rejected edits never truncate", async () => {
  await freshVault();
  const created = entries.createEntry(validEntryPayload());
  const legacyNotes = "あ".repeat(100000);
  const legacyPassword = "x".repeat(65537);
  const legacyTags = Array(101).fill("legacy");
  database.prepare("UPDATE password_entries SET encrypted_notes = ?, encrypted_password = ?, tags = ? WHERE id = ?")
    .run(crypto.encryptSecret(legacyNotes), crypto.encryptSecret(legacyPassword), JSON.stringify(legacyTags), created.id);
  const expected = entries.getEntryById(created.id);
  const row = database.prepare("SELECT * FROM password_entries WHERE id = ?").get(created.id);
  assert.equal(expected.notes, legacyNotes);
  assert.equal(expected.password, legacyPassword);
  assert.deepEqual(await (await apiRequest(`/entries/${created.id}`)).json(), expected);
  assert.throws(() => entries.updateEntry(created.id, entryPayload(expected)), { statusCode: 413 });
  assert.equal((await apiRequest(`/entries/${created.id}`, { method: "PUT", body: JSON.stringify(entryPayload(expected)) })).status, 413);
  assert.deepEqual(database.prepare("SELECT * FROM password_entries WHERE id = ?").get(created.id), row);
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  await freshVault();
  assert.deepEqual(await backup.restoreBackup({ passphrase: backupPassphrase, content: exported.content }), { restoredCount: 1 });
  assert.deepEqual(entries.getEntryById(created.id), expected);
});

test("the new-entry count limit preserves viewing and deletion of existing records", async () => {
  await freshVault();
  const created = entries.createEntry(validEntryPayload());
  database.exec(`WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value + 1 FROM n WHERE value < 9999)
    INSERT INTO password_entries (id, service_name, login_id, encrypted_password, tags, created_at, updated_at)
    SELECT 'capacity-' || value, 'Capacity', 'fixture', 'unread-test-ciphertext', '[]', '2025-01-01', '2025-01-01' FROM n`);
  assert.equal(entries.listEntries().items.length, 10000);
  assert.throws(() => entries.createEntry(validEntryPayload()), { statusCode: 413 });
  assert.equal((await apiRequest("/entries", { method: "POST", body: JSON.stringify(validEntryPayload()) })).status, 413);
  assert.equal(entries.getEntryById(created.id).password, created.password);
  entries.deleteEntry("capacity-1");
  assert.ok(entries.createEntry(validEntryPayload()).id);
  assert.equal(entries.listEntries().items.length, 10000);
});
