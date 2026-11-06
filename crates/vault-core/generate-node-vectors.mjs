// Writes synthetic data with the app's own TypeScript codecs for tests/node_interop.rs.
// Touches no vault: it runs the pure codecs only. Requires `npm run build:api`.
import { randomBytes, randomUUID, scrypt } from "node:crypto";
import { writeFileSync } from "node:fs";
import { promisify } from "node:util";

const outputPath = process.argv[2];
if (!outputPath) throw new Error("Usage: node generate-node-vectors.mjs <output.json>");

const load = (file) => import(new URL(`../../apps/api/dist/apps/api/src/crypto/${file}`, import.meta.url).href);
const { deriveVaultKey, deriveVerifier, encryptLegacySecret } = await load("legacy-codec.js");
const { deriveBackupKey, encodeBackupVersion } = await load("backup-v1.js");
const { createRootKey, sealEntry, wrapRootKey } = await load("v2-codec.js");

const legacyPassword = "node-互換🔐é-password";
const legacySalt = randomBytes(16).toString("base64");
const legacyKey = await deriveVaultKey(legacyPassword, legacySalt);
const legacySecrets = ["", "ascii-secret", "日本語🔐é\u0000終端", "x".repeat(4096)]
  .map((plaintext) => ({ plaintext, payload: encryptLegacySecret(legacyKey, plaintext) }));

const entry = (id) => ({ id, serviceName: "合成サービス🔐", loginId: "node-fixture", password: "node-秘密é", notes: "一行目\n二行目",
  url: "https://fixture.example.test/", tags: ["合成"], group: null, createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z", passwordChangedAt: null });

const backupPassphrase = "node-backup-互換é-passphrase";
const backupSalt = randomBytes(16);
const backupKey = await deriveBackupKey(backupPassphrase, Buffer.from(backupSalt));
// The envelope is what is compared here, so all versions carry the same entry shape.
const backups = [1, 2, 3].map((version) => {
  const entries = [entry(randomUUID())];
  return { version, plaintext: JSON.stringify({ version, entries }), content: encodeBackupVersion(entries, backupKey, backupSalt, version) };
});

const vaultId = randomUUID(), keyId = randomUUID(), slotRevision = 3, v2Password = "node-v2-互換🔐é-master";
const root = createRootKey();
const slot = await wrapRootKey(root, v2Password, { vaultId, keyId, slotRevision });
const usedNonces = new Set();
const reserveNonce = (_keyId, iv) => {
  const value = iv.toString("hex");
  if (usedNonces.has(value)) return false;
  usedNonces.add(value);
  return true;
};
// A non-ASCII id exercises the hex encoding of the entry id inside the AAD.
const v2Entries = await Promise.all([[randomUUID(), 1], ["項目-🔐-é", 7]].map(async ([entryId, revision]) => {
  const plaintext = JSON.stringify(entry(entryId));
  const envelope = await sealEntry(root, plaintext, { vaultId, keyId, entryId, revision }, reserveNonce);
  return { entryId, revision, plaintext, envelope: JSON.stringify(envelope) };
}));

// Measured on the same machine so the Rust KDF time has a baseline.
const started = performance.now();
await promisify(scrypt)(v2Password, randomBytes(16), 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
console.log(`Node scrypt N=2^17 took ${Math.round(performance.now() - started)} ms`);

writeFileSync(outputPath, JSON.stringify({ testOnly: true,
  legacy: { password: legacyPassword, salt: legacySalt, verifier: deriveVerifier(legacyKey), secrets: legacySecrets },
  backupPassphrase, backups,
  v2: { vaultId, keyId, slotRevision, password: v2Password, rootKeyHex: root.toString("hex"), slot: JSON.stringify(slot), entries: v2Entries }
}));
