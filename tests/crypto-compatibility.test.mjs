import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createCipheriv, hkdfSync, scrypt, webcrypto } from "node:crypto";
import { promisify } from "node:util";

// Fixed, synthetic outputs produced with Python hashlib/hmac and cryptography.
// Python is not required. Draft-v2 reference checks stay independent of the codec.
const fixture = JSON.parse(readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
assert.equal(fixture.testOnly, true);
const { legacy, backupV1, draftV2 } = fixture;
const temporaryRoot = mkdtempSync(path.join(tmpdir(), "cipher-vault-crypto-vectors-"));
process.env.PASSWORD_MANAGER_DATA_DIR = temporaryRoot;
const base = "../apps/api/dist/apps/api/src/";
const { openDatabase, closeDatabase } = await import(`${base}db/database.js`);
const database = openDatabase();
const crypto = await import(`${base}services/crypto-service.js`);
const vault = await import(`${base}services/vault-service.js`);
const store = await import(`${base}services/vault-store.js`);
const entries = await import(`${base}services/entry-service.js`);
const backup = await import(`${base}services/backup-service.js`);
const derive = promisify(scrypt);
const strongProfile = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const bytes = (value) => Buffer.from(value, "base64");
const storedRows = () => database.prepare("SELECT * FROM password_entries ORDER BY id").all();

after(() => {
  vault.lockVault(); closeDatabase();
  assert.equal(path.dirname(temporaryRoot), path.resolve(tmpdir()));
  assert.ok(path.basename(temporaryRoot).startsWith("cipher-vault-crypto-vectors-"));
  rmSync(temporaryRoot, { recursive: true, force: true });
});

function seedLegacy(hmac = false) {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  store.saveVaultMetadata(hmac ? { ...legacy.metadata, passwordVerifier: legacy.verifier,
    kdfParams: JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }) } : legacy.metadata);
  const columns = Object.keys(legacy.rows[0]);
  const insert = database.prepare(`INSERT INTO password_entries (${columns.join(",")}) VALUES (${columns.map(name => "@" + name).join(",")})`);
  for (const row of legacy.rows) insert.run(row);
}

async function emptyTarget() {
  vault.resetVault({ confirmation: "RESET_ALL_DATA" });
  await vault.setupVault({ masterPassword: "fixture-different-master-password" });
}

async function subtleDecrypt(key, iv, ciphertext, tag, aad) {
  const imported = await webcrypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  return Buffer.from(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128,
    ...(aad === undefined ? {} : { additionalData: aad }) }, imported, Buffer.concat([ciphertext, tag])));
}

test("Python vectors pin legacy Salt text, Unicode normalization and both verifier forms", async () => {
  const key = await crypto.deriveVaultKey(legacy.password, legacy.salt);
  const nfc = await crypto.deriveVaultKey(legacy.password.normalize("NFC"), legacy.salt);
  const decodedSalt = await derive(legacy.password, bytes(legacy.salt), 32, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  try {
    assert.equal(key.toString("hex"), legacy.keyHex);
    assert.equal(nfc.toString("hex"), legacy.nfcKeyHex);
    assert.equal(decodedSalt.toString("hex"), legacy.decodedSaltKeyHex);
    assert.notDeepEqual(key, nfc); assert.notDeepEqual(key, decodedSalt);
    assert.equal(crypto.deriveVerifier(key), legacy.verifier);
    assert.equal(crypto.verifyVaultKey(key, legacy.metadata.passwordVerifier, true), true);
    assert.equal(crypto.verifyVaultKey(key, legacy.verifier), true);
    assert.equal(crypto.verifyVaultKey(key, legacy.metadata.passwordVerifier), false);
    assert.equal(key.toString("hex"), legacy.keyHex);
  } finally { key.fill(0); nfc.fill(0); decodedSalt.fill(0); }
});

test("fixed legacy DB rows survive wrong passwords and verifier upgrade without ciphertext rewrites", async () => {
  seedLegacy();
  const before = storedRows();
  await assert.rejects(vault.unlockVault({ masterPassword: "fixture-wrong-master-password" }), { statusCode: 401 });
  assert.deepEqual(store.getVaultMetadata(), legacy.metadata);
  assert.deepEqual(storedRows(), before);
  await vault.unlockVault({ masterPassword: legacy.password });
  for (const entry of legacy.entries) assert.deepEqual(entries.getEntryById(entry.id), entry);
  assert.deepEqual(storedRows(), before);
  const upgraded = store.getVaultMetadata();
  assert.equal(upgraded.passwordVerifier, legacy.verifier);
  assert.equal(JSON.parse(upgraded.kdfParams).verifierAlgorithm, "hmac-sha256-v1");
  assert.equal(upgraded.passwordSalt, legacy.metadata.passwordSalt);
  vault.lockVault();
  await vault.unlockVault({ masterPassword: legacy.password });
  assert.deepEqual(store.getVaultMetadata(), upgraded);
  assert.deepEqual(storedRows(), before);
});

test("fixed HMAC DB rows retain null and empty fields without rewriting metadata", async () => {
  seedLegacy(true);
  const metadata = store.getVaultMetadata();
  const before = storedRows();
  await vault.unlockVault({ masterPassword: legacy.password });
  for (const entry of legacy.entries) assert.deepEqual(entries.getEntryById(entry.id), entry);
  assert.deepEqual(store.getVaultMetadata(), metadata);
  assert.deepEqual(storedRows(), before);
});

test("legacy GCM packing authenticates IV, tag and ciphertext, including an empty secret", async () => {
  const key = Buffer.from(legacy.keyHex, "hex");
  try {
    crypto.setActiveVaultKey(key);
    assert.equal(crypto.decryptSecret(legacy.emptyCiphertext), "");
    const packed = bytes(legacy.rows[0].encrypted_password);
    for (const offset of [0, 12, 28]) {
      const changed = Buffer.from(packed); changed[offset] ^= 1;
      assert.throws(() => crypto.decryptSecret(changed.toString("base64")));
    }
    for (const length of [0, 11, 12, 13, 28]) assert.throws(() => crypto.decryptSecret(packed.subarray(0, length).toString("base64")));
    const plaintext = "fixture-new-secret\u0000日本語e\u0301";
    const written = bytes(crypto.encryptSecret(plaintext));
    assert.equal(written.length, Buffer.byteLength(plaintext) + 28);
    assert.equal((await subtleDecrypt(key, written.subarray(0, 12), written.subarray(28), written.subarray(12, 28))).toString("utf8"), plaintext);
    crypto.setActiveVaultKey(Buffer.alloc(32));
    assert.throws(() => crypto.decryptSecret(legacy.rows[0].encrypted_password));
  } finally { key.fill(0); crypto.clearActiveVaultKey(); }
  assert.throws(() => crypto.decryptSecret(legacy.emptyCiphertext), { statusCode: 423 });
});

test("a fixed Python backup v1 decrypts and restores every field under a different master key", async () => {
  const key = await derive(backupV1.passphrase, bytes(backupV1.envelope.salt), 32, strongProfile);
  try {
    assert.equal(key.toString("hex"), backupV1.keyHex);
    const plain = await subtleDecrypt(key, bytes(backupV1.envelope.iv), bytes(backupV1.envelope.data), bytes(backupV1.envelope.tag), Buffer.from(backupV1.aadHex, "hex"));
    assert.equal(plain.toString("utf8"), backupV1.plaintext);
    plain.fill(0);
  } finally { key.fill(0); }
  await emptyTarget();
  const metadata = store.getVaultMetadata();
  assert.deepEqual(await backup.restoreBackup({ passphrase: backupV1.passphrase, content: JSON.stringify(backupV1.envelope) }), { restoredCount: 2 });
  for (const entry of legacy.entries) assert.deepEqual(entries.getEntryById(entry.id), entry);
  assert.deepEqual(store.getVaultMetadata(), metadata);
  vault.lockVault();
  await vault.unlockVault({ masterPassword: "fixture-different-master-password" });
  for (const entry of legacy.entries) assert.deepEqual(entries.getEntryById(entry.id), entry);
});

test("fixed backup failures never write data or alter the target key metadata", async () => {
  await emptyTarget();
  const metadata = store.getVaultMetadata();
  const reject = async (envelope, passphrase = backupV1.passphrase) => {
    await assert.rejects(backup.restoreBackup({ passphrase, content: JSON.stringify(envelope) }), { statusCode: 400 });
    assert.deepEqual(storedRows(), []); assert.deepEqual(store.getVaultMetadata(), metadata);
  };
  await reject(backupV1.envelope, "fixture-wrong-backup-passphrase");
  for (const field of ["salt", "iv", "tag", "data"]) {
    const changed = bytes(backupV1.envelope[field]); changed[0] ^= 1;
    await reject({ ...backupV1.envelope, [field]: changed.toString("base64") });
  }
  for (const [field, value] of [["format", "UNKNOWN"], ["version", 2], ["kdf", "scrypt-arbitrary"], ["cipher", "aes-128-gcm"], ["salt", backupV1.envelope.salt + "\n"]]) {
    await reject({ ...backupV1.envelope, [field]: value });
  }
});

test("the backup v1 writer stays interoperable with Web Crypto and the fixed AAD", async () => {
  seedLegacy(true); await vault.unlockVault({ masterPassword: legacy.password });
  const exported = JSON.parse((await backup.exportBackup({ passphrase: backupV1.passphrase })).content);
  assert.deepEqual(Object.keys(exported).sort(), Object.keys(backupV1.envelope).sort());
  for (const field of ["format", "version", "kdf", "cipher"]) assert.equal(exported[field], backupV1.envelope[field]);
  assert.equal(bytes(exported.salt).length, 16); assert.equal(bytes(exported.iv).length, 12); assert.equal(bytes(exported.tag).length, 16);
  const key = await derive(backupV1.passphrase, bytes(exported.salt), 32, strongProfile);
  try {
    const plain = await subtleDecrypt(key, bytes(exported.iv), bytes(exported.data), bytes(exported.tag), Buffer.from(backupV1.aadHex, "hex"));
    const decoded = JSON.parse(plain.toString("utf8")); plain.fill(0);
    assert.equal(decoded.version, 1);
    assert.deepEqual(decoded.entries.sort((a, b) => a.id.localeCompare(b.id)), legacy.entries);
    await assert.rejects(subtleDecrypt(key, bytes(exported.iv), bytes(exported.data), bytes(exported.tag), Buffer.from("wrong-fixture-AAD")));
  } finally { key.fill(0); }
});

test("draft v2 vectors fix raw-salt scrypt, HKDF domain separation and the wrapped random root", async () => {
  const value = draftV2;
  const kdf = await derive(value.masterPassword, bytes(value.salt), 32, strongProfile);
  const vaultIdBytes = Buffer.from(value.vaultId.replaceAll("-", ""), "hex");
  const wrapKey = Buffer.from(hkdfSync("sha256", kdf, vaultIdBytes, value.wrapInfo, 32));
  const entryKey = Buffer.from(hkdfSync("sha256", Buffer.from(value.rootKeyHex, "hex"), vaultIdBytes, value.entryInfo, 32));
  try {
    assert.equal(kdf.toString("hex"), value.kdfKeyHex);
    assert.equal(wrapKey.toString("hex"), value.wrapKeyHex);
    assert.equal(entryKey.toString("hex"), value.entryKeyHex);
    assert.notDeepEqual(wrapKey, entryKey);
    const aad = Buffer.from(JSON.stringify(["CIPHER-VAULT", 2, "password-slot", value.vaultId, value.keyId, "password", value.slotRevision, value.profile, value.salt]));
    assert.equal(aad.toString("hex"), value.wrapAadHex);
    const cipher = createCipheriv("aes-256-gcm", wrapKey, bytes(value.wrapIv)); cipher.setAAD(aad);
    assert.equal(Buffer.concat([cipher.update(Buffer.from(value.rootKeyHex, "hex")), cipher.final()]).toString("base64"), value.wrappedRoot);
    assert.equal(cipher.getAuthTag().toString("base64"), value.wrapTag);
    const root = await subtleDecrypt(wrapKey, bytes(value.wrapIv), bytes(value.wrappedRoot), bytes(value.wrapTag), aad);
    assert.equal(root.toString("hex"), value.rootKeyHex); root.fill(0);
    const changed = JSON.parse(aad.toString()); changed[8] = bytes(value.salt).fill(0).toString("base64");
    await assert.rejects(subtleDecrypt(wrapKey, bytes(value.wrapIv), bytes(value.wrappedRoot), bytes(value.wrapTag), Buffer.from(JSON.stringify(changed))));
  } finally { kdf.fill(0); wrapKey.fill(0); entryKey.fill(0); }
});

test("draft v2 whole-record vectors bind identity, revision and purpose and cannot use legacy no-AAD decryption", async () => {
  const value = draftV2;
  const key = Buffer.from(value.entryKeyHex, "hex");
  const context = ["CIPHER-VAULT", 2, "entry", value.vaultId, value.keyId, Buffer.from(value.entryId).toString("hex"), value.revision];
  const aad = Buffer.from(JSON.stringify(context));
  try {
    assert.equal(aad.toString("hex"), value.entryAadHex);
    const cipher = createCipheriv("aes-256-gcm", key, bytes(value.entryIv)); cipher.setAAD(aad);
    assert.equal(Buffer.concat([cipher.update(value.entryPlaintext, "utf8"), cipher.final()]).toString("base64"), value.entryData);
    assert.equal(cipher.getAuthTag().toString("base64"), value.entryTag);
    const plain = await subtleDecrypt(key, bytes(value.entryIv), bytes(value.entryData), bytes(value.entryTag), aad);
    assert.equal(plain.toString("utf8"), value.entryPlaintext); plain.fill(0);
    for (const [index, replacement] of [[1, 3], [2, "password-slot"], [3, value.keyId], [4, value.vaultId], [5, Buffer.from(legacy.entries[1].id).toString("hex")], [6, 2]]) {
      const changed = [...context]; changed[index] = replacement;
      await assert.rejects(subtleDecrypt(key, bytes(value.entryIv), bytes(value.entryData), bytes(value.entryTag), Buffer.from(JSON.stringify(changed))));
    }
    crypto.setActiveVaultKey(key);
    assert.throws(() => crypto.decryptSecret(Buffer.concat([bytes(value.entryIv), bytes(value.entryTag), bytes(value.entryData)]).toString("base64")));
  } finally { key.fill(0); crypto.clearActiveVaultKey(); }
});
