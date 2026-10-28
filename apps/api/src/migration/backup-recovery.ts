import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { createMemoryDatabase } from "../db/database.js";
import { restoreLegacyEntries } from "../db/legacy-entry-writer.js";
import { decodeBackupV1, deriveBackupKey, parseBackupV1 } from "../crypto/backup-v1.js";
import { deriveVaultKey, deriveVerifier, encryptLegacySecret, verifyVaultKey } from "../crypto/legacy-codec.js";
import { LegacyPreflightError, readLegacyEntries, readLegacyMetadata } from "./legacy-reader.js";

/** Authenticate the actual envelope, then restore into an independent, differently keyed memory vault. */
export async function verifyBackupRecovery(content: string, passphrase: Buffer, active: () => void) {
  let backupKey: Buffer | undefined, scratchKey: Buffer | undefined, password: Buffer | undefined;
  let scratch: ReturnType<typeof createMemoryDatabase> | undefined;
  let entries: ReturnType<typeof decodeBackupV1> | undefined;
  let verified: Awaited<ReturnType<typeof readLegacyEntries>> | undefined;
  let success = false;
  try {
    active();
    const envelope = parseBackupV1(content);
    backupKey = await deriveBackupKey(passphrase, envelope.salt); active();
    entries = decodeBackupV1(envelope, backupKey);
    const seed = randomBytes(32);
    try { password = Buffer.from(seed.toString("base64")); } finally { seed.fill(0); }
    const salt = randomBytes(16).toString("base64");
    scratchKey = await deriveVaultKey(password, salt); active();
    scratch = createMemoryDatabase();
    const now = new Date().toISOString();
    scratch.prepare("INSERT INTO vault_metadata VALUES (1, ?, ?, ?, ?, ?)").run(salt, deriveVerifier(scratchKey),
      JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }), now, now);
    const metadata = readLegacyMetadata(scratch);
    if (!verifyVaultKey(scratchKey, metadata.verifier)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    const key = scratchKey;
    restoreLegacyEntries(scratch, entries, text => { active(); return encryptLegacySecret(key, text); }, active);
    verified = await readLegacyEntries(scratch, scratchKey, active); active();
    if (!isDeepStrictEqual(verified.entries, entries)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    success = true;
    return entries;
  } finally {
    backupKey?.fill(0); scratchKey?.fill(0); password?.fill(0);
    if (verified) verified.entries.length = 0;
    if (!success && entries) entries.length = 0;
    if (scratch?.open) scratch.close();
  }
}
