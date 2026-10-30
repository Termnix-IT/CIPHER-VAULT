import assert from "node:assert/strict";
import { before, after, afterEach, mock, test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import Database from "better-sqlite3";
import { compatibility, createMigratedFixture, v2Password } from "./v2-runtime-fixture.mjs";
import { openV2Store } from "../apps/api/dist/apps/api/src/db/v2-store.js";
import { openEntry, unwrapRootKey } from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";
import { deriveBackupKey } from "../apps/api/dist/apps/api/src/crypto/backup-v1.js";
import { encodeVaultBackup } from "../apps/api/dist/apps/api/src/crypto/vault-backup.js";
import { verifyBackupRecovery } from "../apps/api/dist/apps/api/src/migration/backup-recovery.js";
import { replaceV2Vault, recoverV2Replacement, inspectV2Replacement } from "../apps/api/dist/apps/api/src/migration/v2-replacement.js";
import { inspectVaultSelection } from "../apps/api/dist/apps/api/src/migration/active-pointer.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

const root = fs.mkdtempSync(path.join(fs.realpathSync(tmpdir()), "cipher-vault-item-maintenance-")), base = path.join(root, "base");
const passphrase = compatibility.backupV1.passphrase, newPassword = "synthetic-item-maintenance-new-master";
const common = { notes: "synthetic-private-notes", url: "https://synthetic.example.test/path", tags: ["synthetic-tag"], group: "Synthetic",
  createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-02T00:00:00.000Z" };
const additional = [
  { ...common, id: "00000000-0000-4000-8000-000000000002", type: "apiKey", serviceName: "Synthetic API",
    apiKey: { key: "  synthetic-api-secret  ", keyId: "synthetic-key-id", expiresOn: "2029-12-31" } },
  { ...common, id: "00000000-0000-4000-8000-000000000003", type: "creditCard", serviceName: "Synthetic Card",
    card: { number: "4111111111111111", cardholder: "SYNTHETIC OWNER", expiryMonth: "2029-12", securityCode: "123" } }
];
const expected = [...compatibility.legacy.entries, ...additional], asMap = entries => new Map(entries.map(entry => [entry.id, entry]));
let context, sourceKey, sequence = 0; const sessions = [];
const fixture = () => { const dir = path.join(root, `case-${++sequence}`); fs.cpSync(base, dir, { recursive: true }); return dir; };
const source = dir => path.join(dir, "vaults", context.vaultId, "vault.sqlite");
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const owner = () => { const session = new VaultSession(); session.unlock(sourceKey); sessions.push(session); return { session, sessionId: session.requireUnlocked() }; };
const input = (mode = "rekey") => ({ mode, masterPassword: v2Password, newMasterPassword: newPassword, confirmNewMasterPassword: newPassword,
  backupPassphrase: passphrase, ...(mode === "reset" ? { confirmation: "RESET_ALL_DATA" } : {}) });
async function read(file, selected, password) {
  const store = openV2Store(file, selected); let key;
  try {
    key = await unwrapRootKey(store.readPasswordSlot(), password, selected);
    return store.listEntryContexts().map(entry => {
      const plaintext = openEntry(key, store.readEntry(entry.entryId), entry);
      try { return JSON.parse(plaintext.toString("utf8")); } finally { plaintext.fill(0); }
    });
  } finally { key?.fill(0); store.close(); }
}
before(async () => {
  context = await createMigratedFixture(base); const store = openV2Store(source(base), context, { writable: true });
  try {
    sourceKey = await unwrapRootKey(store.readPasswordSlot(), v2Password, context);
    for (const entry of additional) await store.writeEntry(sourceKey, JSON.stringify(entry), { vaultId: context.vaultId, keyId: context.keyId, entryId: entry.id, revision: 1 });
  } finally { store.close(); }
});
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); sessions.splice(0).forEach(session => session.lock()); });
after(() => {
  sourceKey?.fill(0); assert.equal(path.dirname(root), fs.realpathSync(tmpdir())); assert.ok(path.basename(root).startsWith("cipher-vault-item-maintenance-"));
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

test("mixed backups prove actual independently keyed v2 restore, preserve input ordering and clean cancelled scratch storage", async () => {
  const entries = [...expected].reverse(), salt = crypto.randomBytes(16), key = await deriveBackupKey(passphrase, salt); let content;
  try { content = encodeVaultBackup(entries, key, salt); } finally { key.fill(0); }
  assert.equal(JSON.parse(content).version, 2);
  await assert.rejects(verifyBackupRecovery(content, Buffer.from(passphrase), () => {}), { statusCode: 400 });
  const created = [], create = fs.mkdtempSync;
  mock.method(fs, "mkdtempSync", (...args) => { const directory = create(...args); if (path.basename(directory).startsWith("cipher-vault-typed-recovery-")) created.push(directory); return directory; });
  syncBuiltinESMExports();
  const restored = await verifyBackupRecovery(content, Buffer.from(passphrase), () => {}, { allowTyped: true });
  assert.deepEqual(restored, entries); assert.equal(created.length, 1); assert.equal(fs.existsSync(created[0]), false);
  await assert.rejects(verifyBackupRecovery(content, Buffer.from(passphrase), () => {
    if (created.length === 2) throw new Error("synthetic cancellation");
  }, { allowTyped: true }), /synthetic cancellation/);
  assert.equal(created.length, 2); assert.equal(fs.existsSync(created[1]), false);
});

test("mixed rekey preserves login, API and card fields and changes only the selected vault", async () => {
  const dir = fixture(), before = hash(source(dir)), result = await replaceV2Vault(dir, context, input(), owner());
  assert.equal(hash(source(dir)), before); assert.deepEqual(asMap(await read(result.files.database, result.target, newPassword)), asMap(expected));
  assert.equal(JSON.parse(fs.readFileSync(result.files.backup, "utf8")).version, 2);
  assert.equal(JSON.parse(fs.readFileSync(result.files.targetBackup, "utf8")).version, 2);
  const db = new Database(result.files.database, { readonly: true }); try { assert.equal(db.pragma("user_version", { simple: true }), 2); } finally { db.close(); }
  await assert.rejects(read(result.files.database, result.target, v2Password), { code: "AUTHENTICATION_FAILED" });
});

test("interrupted mixed rekey refuses a changed recovery backup and recovers every field without rewriting either vault", async () => {
  const dir = fixture(), before = hash(source(dir)), rename = fs.renameSync; let interrupted = false;
  mock.method(fs, "renameSync", (from, to) => {
    if (!interrupted && path.basename(to) === "vault-current.json" && to.startsWith(dir + path.sep)) { interrupted = true; throw new Error("synthetic interruption"); }
    return rename(from, to);
  }); syncBuiltinESMExports();
  await assert.rejects(replaceV2Vault(dir, context, input(), owner()), { code: "RECOVERY_REQUIRED" }); assert.equal(interrupted, true);
  mock.restoreAll(); syncBuiltinESMExports(); const hint = inspectV2Replacement(dir), folder = path.join(dir, "vaults", hint.target.vaultId);
  const backup = path.join(folder, "source.cvault"), content = fs.readFileSync(backup), target = path.join(folder, "vault.sqlite"), targetBefore = hash(target);
  fs.writeFileSync(backup, "{}");
  await assert.rejects(recoverV2Replacement(dir, hint, input(), owner()), { code: "RECOVERY_REQUIRED" });
  assert.equal(hash(source(dir)), before); assert.equal(hash(target), targetBefore); fs.writeFileSync(backup, content);
  const result = await recoverV2Replacement(dir, hint, input(), owner());
  assert.equal(hash(source(dir)), before); assert.equal(hash(target), targetBefore); assert.deepEqual(inspectVaultSelection(dir).context, result.target);
  assert.deepEqual(asMap(await read(target, result.target, newPassword)), asMap(expected));
});

test("mixed reset preserves an independently restorable source backup and selects an empty freshly keyed vault", async () => {
  const dir = fixture(), before = hash(source(dir)), result = await replaceV2Vault(dir, context, input("reset"), owner());
  assert.equal(hash(source(dir)), before); assert.equal(result.targetCount, 0); assert.deepEqual(await read(result.files.database, result.target, newPassword), []);
  const restored = await verifyBackupRecovery(fs.readFileSync(result.files.backup, "utf8"), Buffer.from(passphrase), () => {}, { allowTyped: true });
  assert.deepEqual(asMap(restored), asMap(expected)); assert.equal(JSON.parse(fs.readFileSync(result.files.targetBackup, "utf8")).version, 1);
});
