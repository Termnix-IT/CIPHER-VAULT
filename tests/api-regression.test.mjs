import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, cpSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";

const temporaryRoot = mkdtempSync(path.join(tmpdir(), "cipher-vault-regression-"));
process.env.PASSWORD_MANAGER_DATA_DIR = path.join(temporaryRoot, "db");
process.env.PASSWORD_MANAGER_WEB_DIST = path.join(temporaryRoot, "web");
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
const { tryServeStaticAsset } = await import(`${base}lib/static.js`);
const server = createServer((request, response) => void router(request, response));
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

after(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  vault.lockVault();
  database.close();
  const relative = path.relative(tmpdir(), temporaryRoot);
  assert.ok(relative.startsWith("cipher-vault-regression-") && !relative.includes(path.sep));
  rmSync(temporaryRoot, { recursive: true, force: true });
});

test("invalid generation options return 400", () => {
  for (const value of [null, [], { length: 12.5 }, { length: "20" }, { length: NaN }, { includeNumbers: "false" }]) {
    assert.throws(() => generatePassword(value), { statusCode: 400 });
  }
  assert.equal(generatePassword({ length: 64 }).password.length, 64);
});

test("HTTP rejects malformed JSON and handles query strings", async () => {
  const malformed = await fetch(`${origin}/password/generate`, { method: "POST", body: "{" });
  assert.equal(malformed.status, 400);
  assert.equal((await fetch(`${origin}/health?check=1`)).status, 200);
  assert.equal((await fetch(`${origin}/vault/setup`, { method: "POST", body: "null" })).status, 400);
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
  for (const directory of ["scripts", "apps/api/dist", "apps/web/dist", "apps/api/data"]) {
    mkdirSync(path.join(fixture, directory), { recursive: true });
  }
  cpSync(new URL("../scripts/package-release.ps1", import.meta.url), path.join(fixture, "scripts/package-release.ps1"));
  writeFileSync(path.join(fixture, "apps/api/data/password-manager.db"), "development sentinel");
  const run = () => spawnSync("pwsh", ["-NoProfile", "-File", path.join(fixture, "scripts/package-release.ps1")], { cwd: temporaryRoot, encoding: "utf8" });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.deepEqual(readdirSync(path.join(fixture, "release/data")), []);
  const protectedDatabase = path.join(fixture, "release/data/password-manager.db");
  writeFileSync(protectedDatabase, "existing user data sentinel");
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(protectedDatabase, "utf8"), "existing user data sentinel");
});
