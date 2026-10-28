import Database from "better-sqlite3";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { createMemoryDatabase } from "../db/database.js";
import { restoreLegacyEntries } from "../db/legacy-entry-writer.js";
import { deriveVaultKey, deriveVerifier, encryptLegacySecret, verifyVaultKey } from "../crypto/legacy-codec.js";
import { decodeBackupV1, deriveBackupKey, encodeBackupV1, parseBackupV1 } from "../crypto/backup-v1.js";
import { copyPlaintext, record } from "../crypto/v2-format.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { inspectLegacySource, LegacyPreflightError, readLegacyEntries, readLegacyMetadata } from "./legacy-reader.js";
export { LegacyPreflightError } from "./legacy-reader.js";

let busy = false;
export type LegacyPreflightReport = Readonly<{
  format: "legacy"; verifierFormat: "raw-key" | "hmac-sha256-v1"; entryCount: number;
  plaintextBytes: number; backupBytes: number; backupVerified: true; missingLegacyColumns: readonly string[]
}>;
export type LegacyPreflightResult = Readonly<{ report: LegacyPreflightReport; backup: Readonly<{ fileName: string; content: string }> }>;

/** Independent read-only examination. This does not grant permission to stage or switch a live vault. */
export async function verifyLegacyMigrationSource(filePath: string,
  input: { masterPassword: string; backupPassphrase: string }, options: { signal?: AbortSignal } = {}): Promise<LegacyPreflightResult> {
  if (busy) throw new LegacyPreflightError("BUSY");
  busy = true;
  let source: Database.Database | undefined, scratch: Database.Database | undefined;
  let master: Buffer | undefined, passphrase: Buffer | undefined, sourceKey: Buffer | undefined;
  let backupKey: Buffer | undefined, scratchKey: Buffer | undefined, scratchPassword: Buffer | undefined;
  let sourceEntries: Awaited<ReturnType<typeof readLegacyEntries>> | undefined;
  try {
    let signal: AbortSignal | undefined;
    try {
      const value = record(input, ["masterPassword", "backupPassphrase"]);
      const settings = record(options, ["signal"], []);
      if (settings.signal !== undefined && !(settings.signal instanceof AbortSignal)) throw new Error("invalid signal");
      signal = settings.signal as AbortSignal | undefined;
      master = copyPlaintext(value.masterPassword, INPUT_LIMITS.masterPasswordBytes);
      const backup = parseBackupPayload({ passphrase: value.backupPassphrase }, false);
      passphrase = copyPlaintext(backup.passphrase, 4096);
      if (typeof filePath !== "string" || !filePath || filePath.includes("\0")) throw new Error("invalid path");
    } catch { throw new LegacyPreflightError("INVALID_INPUT"); }
    const active = () => { if (signal?.aborted) throw new LegacyPreflightError("CANCELLED"); };
    active();
    source = new Database(path.resolve(filePath), { readonly: true, fileMustExist: true });
    source.pragma("temp_store = MEMORY");
    const version = source.pragma("data_version", { simple: true });
    // An explicit read transaction may span awaits; better-sqlite3 transaction callbacks must not.
    source.exec("BEGIN");
    const inspection = inspectLegacySource(source), metadata = readLegacyMetadata(source);
    sourceKey = await deriveVaultKey(master, metadata.salt); active();
    if (!verifyVaultKey(sourceKey, metadata.verifier, metadata.rawVerifier)) throw new LegacyPreflightError("AUTHENTICATION_FAILED");
    sourceEntries = await readLegacyEntries(source, sourceKey, active); active();
    const salt = randomBytes(16);
    backupKey = await deriveBackupKey(passphrase, salt); active();
    const content = encodeBackupV1(sourceEntries.entries, backupKey, salt);
    // Parse and derive again: verify the emitted file's Salt and metadata, not only the writer's key.
    backupKey.fill(0); backupKey = undefined;
    const envelope = parseBackupV1(content);
    backupKey = await deriveBackupKey(passphrase, envelope.salt); active();
    const restored = decodeBackupV1(envelope, backupKey);
    if (!isDeepStrictEqual(restored, sourceEntries.entries)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    const seed = randomBytes(32);
    try { scratchPassword = Buffer.from(seed.toString("base64")); } finally { seed.fill(0); }
    const scratchSalt = randomBytes(16).toString("base64");
    scratchKey = await deriveVaultKey(scratchPassword, scratchSalt); active();
    scratch = createMemoryDatabase();
    const now = new Date().toISOString();
    scratch.prepare("INSERT INTO vault_metadata VALUES (1, ?, ?, ?, ?, ?)").run(scratchSalt, deriveVerifier(scratchKey),
      JSON.stringify({ algorithm: "scrypt", keyLength: 32, verifierAlgorithm: "hmac-sha256-v1" }), now, now);
    const restoredMetadata = readLegacyMetadata(scratch);
    if (!verifyVaultKey(scratchKey, restoredMetadata.verifier)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    const key = scratchKey;
    restoreLegacyEntries(scratch, restored, plaintext => { active(); return encryptLegacySecret(key, plaintext); }, active);
    const verified = await readLegacyEntries(scratch, scratchKey, active); active();
    if (!isDeepStrictEqual(verified.entries, sourceEntries.entries)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    verified.entries.length = 0; restored.length = 0;
    source.exec("ROLLBACK");
    if (source.pragma("data_version", { simple: true }) !== version) throw new LegacyPreflightError("SOURCE_CHANGED");
    active();
    return Object.freeze({ report: Object.freeze({ format: "legacy", verifierFormat: metadata.rawVerifier ? "raw-key" : "hmac-sha256-v1",
      entryCount: inspection.count, plaintextBytes: sourceEntries.plaintextBytes, backupBytes: Buffer.byteLength(content),
      backupVerified: true, missingLegacyColumns: inspection.missing }),
    backup: Object.freeze({ fileName: "CIPHER-VAULT-preflight.cvault", content }) });
  } catch (error) {
    if (error instanceof LegacyPreflightError) throw error;
    throw new LegacyPreflightError("FAILED");
  } finally {
    master?.fill(0); passphrase?.fill(0); sourceKey?.fill(0); backupKey?.fill(0); scratchKey?.fill(0); scratchPassword?.fill(0);
    if (sourceEntries) sourceEntries.entries.length = 0;
    let failed = false;
    try { if (source?.inTransaction) source.exec("ROLLBACK"); } catch { failed = true; }
    try { if (source?.open) source.close(); } catch { failed = true; }
    try { if (scratch?.open) scratch.close(); } catch { failed = true; }
    busy = false;
    if (failed) throw new LegacyPreflightError("FAILED");
  }
}
