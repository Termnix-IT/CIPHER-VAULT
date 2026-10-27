import assert from "node:assert/strict";
import { verifyReleaseLock } from "../scripts/web-release-manifest.mjs";
import { after, test } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, cpSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, request as httpRequest } from "node:http";
import { spawnSync } from "node:child_process";
import { createCipheriv, scryptSync } from "node:crypto";
import Database from "better-sqlite3";

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
mkdirSync(path.join(temporaryRoot, "web", "assets"));
mkdirSync(path.join(temporaryRoot, "web-private"));
writeFileSync(path.join(temporaryRoot, "web-private", "secret.txt"), "must not be served");

const base = "../apps/api/dist/apps/api/src/";
const { database } = await import(`${base}db/database.js`);
const vault = await import(`${base}services/vault-service.js`);
const entries = await import(`${base}services/entry-service.js`);
const crypto = await import(`${base}services/crypto-service.js`);
const store = await import(`${base}services/vault-store.js`);
const { generatePassword } = await import(`${base}services/password-service.js`);
const { router } = await import(`${base}routes/router.js`);
const backup = await import(`${base}services/backup-service.js`);
const { auditVault } = await import(`${base}services/audit-service.js`);
const { tryServeStaticAsset } = await import(`${base}lib/static.js`);
const server = createServer((request, response) => void router(request, response));
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

async function apiRequest(pathname, init = {}) {
  const { token } = await (await fetch(`${origin}/vault/csrf`)).json();
  return fetch(`${origin}${pathname}`, {
    ...init,
    headers: { "Content-Type": "application/json", "X-Cipher-Vault-CSRF": token, Origin: origin, ...init.headers }
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
  database.close();
  const relative = path.relative(tmpdir(), temporaryRoot);
  assert.ok(relative.startsWith("cipher-vault-regression-") && !relative.includes(path.sep));
  rmSync(temporaryRoot, { recursive: true, force: true });
});

const backupPassphrase = "backup-only-test-passphrase";
test("old database gains an unknown password change date without rewriting ciphertext", () => {
  const row = database.prepare("SELECT encrypted_password, password_changed_at FROM password_entries").get();
  assert.equal(row.password_changed_at, null);
  assert.equal(row.encrypted_password, "existing-ciphertext");
});
function freshVault() {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  vault.setupVault({ masterPassword: "temporary-test-password" });
}

test("HTTP rejects foreign origins, DNS rebinding hosts and unverified mutations without resetting a locked vault", async () => {
  freshVault();
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
    assert.deepEqual(vault.getVaultStatus(), { isConfigured: true, isUnlocked: false });
  }
  for (const pathname of ["/vault/csrf", "/entries", `/entries/${created.id}`]) {
    assert.equal(await rawRequest(pathname, "GET", { Origin: "http://evil.example" }), 403);
    assert.equal(await rawRequest(pathname, "GET", { "Sec-Fetch-Site": "cross-site" }), 403);
    assert.equal(await rawRequest(pathname, "GET", { Host: `evil.example:${server.address().port}` }), 403);
  }
  assert.equal((await apiRequest("/vault/unlock", { method: "POST", body: JSON.stringify({ masterPassword: "temporary-test-password" }) })).status, 200);
  assert.equal((await fetch(`${origin}/entries/${created.id}`)).status, 200);
  assert.equal((await apiRequest(`/entries/${created.id}`, { method: "DELETE" })).status, 200);
  assert.equal((await apiRequest("/vault/lock", { method: "POST" })).status, 200);
  assert.equal((await apiRequest("/vault/reset", { method: "POST", body })).status, 200);
  assert.equal(vault.getVaultStatus().isConfigured, false);
});

test("encrypted backup restores all fields under a different vault key and rejects nonempty vaults", async () => {
  freshVault();
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
  vault.setupVault({ masterPassword: "different-master-password" });
  assert.deepEqual(await backup.restoreBackup({ content: exported.content, passphrase: backupPassphrase }), { restoredCount: 1 });
  vault.lockVault();
  vault.unlockVault({ masterPassword: "different-master-password" });
  assert.deepEqual(entries.getEntryById(created.id), created);
});

test("backup rejects wrong passphrase, tampering, invalid versions and rolls back failed writes", async () => {
  freshVault();
  const first = entries.createEntry({ serviceName: "One", loginId: "one", password: "secret" });
  entries.createEntry({ serviceName: "Two", loginId: "two", password: "secret2" });
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  freshVault();
  await assert.rejects(backup.restoreBackup({ content: exported.content, passphrase: "incorrect-passphrase" }), { statusCode: 400 });
  for (const field of ["data", "tag", "iv", "salt"]) {
    const modified = JSON.parse(exported.content);
    const bytes = Buffer.from(modified[field], "base64"); bytes[0] ^= 1;
    modified[field] = bytes.toString("base64");
    await assert.rejects(backup.restoreBackup({ content: JSON.stringify(modified), passphrase: backupPassphrase }), { statusCode: 400 });
  }
  for (const content of ["not json", "null", JSON.stringify({ ...JSON.parse(exported.content), version: 99 }), "x".repeat(16 * 1024 * 1024 + 1)]) {
    await assert.rejects(backup.restoreBackup({ content, passphrase: backupPassphrase }), { statusCode: 400 });
  }
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
  freshVault();
  const inFlight = backup.exportBackup({ passphrase: backupPassphrase });
  await assert.rejects(backup.exportBackup({ passphrase: backupPassphrase }), { statusCode: 409 });
  vault.lockVault();
  vault.unlockVault({ masterPassword: "temporary-test-password" });
  await assert.rejects(inFlight, { statusCode: 409 });
  vault.lockVault();
  await assert.rejects(backup.exportBackup({ passphrase: backupPassphrase }), { statusCode: 423 });
  await assert.rejects(backup.restoreBackup({ passphrase: backupPassphrase, content: "{}" }), { statusCode: 423 });
  await assert.rejects(auditVault(), { statusCode: 423 });
});

test("restore rejects authenticated invalid records and rechecks empty state after key derivation", async () => {
  freshVault();
  const entry = entries.createEntry({ serviceName: "Record", loginId: "user", password: "secret" });
  const exported = await backup.exportBackup({ passphrase: backupPassphrase });
  freshVault();
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
  freshVault();
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
  const changedNotes = entries.updateEntry(first.id, { ...first, notes: "changed notes" });
  assert.equal(changedNotes.passwordChangedAt, old);
  assert.equal((await auditVault()).counts.staleEntry, 0);
  assert.equal((await auditVault()).counts.oldPassword, 1);
  const changedPassword = entries.updateEntry(first.id, { ...changedNotes, password: "new-password-value" });
  assert.notEqual(changedPassword.passwordChangedAt, old);
  const changedLegacyNotes = entries.updateEntry(second.id, { ...second, notes: "new notes" });
  assert.equal(changedLegacyNotes.passwordChangedAt, null);
  assert.equal((await auditVault()).counts.duplicate, 0);
  const scanning = auditVault();
  await assert.rejects(auditVault(), { statusCode: 409 });
  vault.lockVault();
  await assert.rejects(scanning, { statusCode: 423 });
});

test("HTTP backup and audit use shared validation and enforce body size limits", async () => {
  freshVault();
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
  const malformed = await apiRequest("/password/generate", { method: "POST", body: "{" });
  assert.equal(malformed.status, 400);
  assert.equal((await fetch(`${origin}/health?check=1`)).status, 200);
  assert.equal((await apiRequest("/vault/setup", { method: "POST", body: "null" })).status, 400);
});

test("static serving rejects sibling paths and directories and supplies PNG MIME", async () => {
  assert.equal(tryServeStaticAsset("/../web-private/secret.txt", {}), false);
  assert.equal(tryServeStaticAsset("/assets", {}), false);
  const response = await fetch(`${origin}/icon.png`);
  assert.equal(response.headers.get("content-type"), "image/png");
  assert.equal(await response.text(), "test image");
  assert.equal((await fetch(`${origin}/assets`)).status, 200);
  assert.equal((await fetch(`${origin}/health`)).status, 200);
});

test("entry validation rejects invalid fields without inserting data; new vault survives lock", () => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  vault.setupVault({ masterPassword: "temporary-test-password" });
  const metadata = store.getVaultMetadata();
  assert.notEqual(metadata.passwordVerifier, crypto.deriveVaultKey("temporary-test-password", metadata.passwordSalt).toString("base64"));
  const valid = { serviceName: "Example", loginId: "test", password: "secret" };
  for (const value of [null, { ...valid, serviceName: 42 }, { ...valid, password: {} }, { ...valid, notes: 1 }, { ...valid, tags: [1] }]) {
    assert.throws(() => entries.createEntry(value), { statusCode: 400 });
  }
  assert.deepEqual(entries.listEntries().items, []);
  const created = entries.createEntry(valid);
  vault.lockVault();
  assert.throws(() => entries.getEntryById(created.id), { statusCode: 423 });
  vault.unlockVault({ masterPassword: "temporary-test-password" });
  assert.equal(entries.getEntryById(created.id).password, "secret");
});

test("legacy verifier upgrades only after authentication and preserves encrypted entries", () => {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  const password = "legacy-test-password";
  const salt = crypto.createPasswordSalt();
  const key = crypto.deriveVaultKey(password, salt);
  const legacy = { id: 1, passwordSalt: salt, passwordVerifier: key.toString("base64"), kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32 }), createdAt: "2025-01-01", updatedAt: "2025-01-01" };
  store.saveVaultMetadata(legacy);
  crypto.setActiveVaultKey(key);
  key.fill(0);
  const created = entries.createEntry({ serviceName: "Legacy", loginId: "user", password: "old secret", notes: "old notes" });
  vault.lockVault();
  assert.throws(() => vault.unlockVault({ masterPassword: "wrong password" }), { statusCode: 401 });
  assert.deepEqual(store.getVaultMetadata(), legacy);
  database.exec("CREATE TRIGGER reject_migration BEFORE UPDATE ON vault_metadata BEGIN SELECT RAISE(ABORT, 'test write failure'); END");
  assert.throws(() => vault.unlockVault({ masterPassword: password }), /test write failure/);
  assert.equal(vault.getVaultStatus().isUnlocked, false);
  assert.equal(crypto.hasActiveVaultKey(), false);
  assert.deepEqual(store.getVaultMetadata(), legacy);
  database.exec("DROP TRIGGER reject_migration");
  vault.unlockVault({ masterPassword: password });
  assert.equal(entries.getEntryById(created.id).password, "old secret");
  assert.equal(entries.getEntryById(created.id).notes, "old notes");
  const migrated = store.getVaultMetadata();
  assert.notEqual(migrated.passwordVerifier, legacy.passwordVerifier);
  assert.equal(JSON.parse(migrated.kdfParams).verifierAlgorithm, "hmac-sha256-v1");
  vault.lockVault();
  assert.throws(() => vault.unlockVault({ masterPassword: "wrong password" }), { statusCode: 401 });
  vault.unlockVault({ masterPassword: password });
  assert.equal(entries.getEntryById(created.id).password, "old secret");
  assert.deepEqual(store.getVaultMetadata(), migrated);
  vault.lockVault();
  store.saveVaultMetadata({ ...migrated, kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "unknown" }) });
  assert.throws(() => vault.unlockVault({ masterPassword: password }), { statusCode: 400 });
  assert.equal(vault.getVaultStatus().isUnlocked, false);
});

test("Web packaging excludes development DB and preserves existing release data", () => {
  const fixture = path.join(temporaryRoot, "package");
  for (const directory of ["scripts", "apps/api/dist", "apps/web/dist", "apps/api/data", "packages/shared/dist"]) {
    mkdirSync(path.join(fixture, directory), { recursive: true });
  }
  for (const file of ["scripts/package-release.ps1", "scripts/web-release-manifest.mjs", "scripts/start-web-release.mjs",
    "package.json", "package-lock.json", "apps/api/package.json", "packages/shared/package.json"]) {
    cpSync(new URL(`../${file}`, import.meta.url), path.join(fixture, file));
  }
  writeFileSync(path.join(fixture, "packages/shared/dist/index.js"), "export const fixture = true;");
  writeFileSync(path.join(fixture, "apps/api/data/password-manager.db"), "development sentinel");
  const run = () => spawnSync("pwsh", ["-NoProfile", "-File", path.join(fixture, "scripts/package-release.ps1")], {
    cwd: temporaryRoot, encoding: "utf8", env: { ...process.env, npm_config_cache: path.join(fixture, "empty-npm-cache") }
  });
  const first = run();
  assert.equal(first.status, 0, first.stdout + first.stderr);
  assert.deepEqual(readdirSync(path.join(fixture, "release/data")), []);
  const releaseManifest = JSON.parse(readFileSync(path.join(fixture, "release/package.json"), "utf8").replace(/^\uFEFF/, ""));
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/core"]);
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/language-common"]);
  assert.ok(releaseManifest.dependencies["@zxcvbn-ts/language-en"]);
  assert.deepEqual(releaseManifest.workspaces, ["packages/shared"]);
  assert.equal(readFileSync(path.join(fixture, "release/packages/shared/dist/index.js"), "utf8"), "export const fixture = true;");
  verifyReleaseLock(fixture, path.join(fixture, "release"));
  const lockPath = path.join(fixture, "release/package-lock.json");
  const lockBytes = readFileSync(lockPath);
  assert.equal(run().status, 0, "a second clean package generation should succeed");
  assert.deepEqual(readFileSync(lockPath), lockBytes, "packaging must preserve deterministic locked resolutions");
  const changedLock = JSON.parse(lockBytes);
  changedLock.packages["node_modules/better-sqlite3"].integrity = "sha512-untrusted-fixture";
  writeFileSync(lockPath, JSON.stringify(changedLock));
  assert.throws(() => verifyReleaseLock(fixture, path.join(fixture, "release")), /Locked package changed/);
  changedLock.packages["node_modules/better-sqlite3"].dev = true;
  writeFileSync(lockPath, JSON.stringify(changedLock));
  assert.throws(() => verifyReleaseLock(fixture, path.join(fixture, "release")), /Unexpected non-runtime/);
  writeFileSync(lockPath, lockBytes);

  const apiPath = path.join(fixture, "apps/api/package.json");
  const apiBytes = readFileSync(apiPath);
  const changedApi = JSON.parse(apiBytes);
  changedApi.dependencies["better-sqlite3"] = "999.0.0";
  writeFileSync(apiPath, JSON.stringify(changedApi));
  assert.notEqual(run().status, 0);
  assert.deepEqual(readFileSync(lockPath), lockBytes, "failed preparation must preserve the previous release");
  writeFileSync(apiPath, apiBytes);
  const protectedDatabase = path.join(fixture, "release/data/password-manager.db");
  writeFileSync(protectedDatabase, "existing user data sentinel");
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(protectedDatabase, "utf8"), "existing user data sentinel");
});
