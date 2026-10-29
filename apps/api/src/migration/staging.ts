import Database from "better-sqlite3";
import { randomBytes, randomUUID } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import type { PasswordEntry } from "@password-manager/shared/types";
import { deriveBackupKey, encodeBackupV1 } from "../crypto/backup-v1.js";
import { deriveVaultKey, verifyVaultKey } from "../crypto/legacy-codec.js";
import { createRootKey, openEntry, unwrapRootKey, VaultCodecError, wrapRootKey } from "../crypto/v2-codec.js";
import { copyPlaintext, parsePasswordSlotContext, record } from "../crypto/v2-format.js";
import { createV2Store, openV2Store } from "../db/v2-store.js";
import type { V2Store } from "../db/v2-store.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { verifyBackupRecovery } from "./backup-recovery.js";
import { inspectLegacySource, LegacyPreflightError, readLegacyEntries, readLegacyMetadata } from "./legacy-reader.js";
import { verifyLegacyMigrationSource } from "./preflight.js";
import { createStageDirectory, existingPath, flushFile, loadBackup, MigrationStageError, reserveSnapshot, saveBackup, SNAPSHOT_MAX_BYTES } from "./staging-files.js";
export { MigrationStageError } from "./staging-files.js";

let busy = false;
type Credentials = { masterPassword: string; newMasterPassword: string; confirmNewMasterPassword: string; backupPassphrase: string };
export type MigrationStageResult = Readonly<{
  state: "v2-verified"; vaultId: string; keyId: string; slotRevision: 1; entryCount: number;
  files: ReturnType<typeof createStageDirectory>
}>;

function same(actual: unknown, expected: unknown, code: "BACKUP_MISMATCH" | "VERIFICATION_FAILED" = "VERIFICATION_FAILED") {
  if (!isDeepStrictEqual(actual, expected)) throw new MigrationStageError(code);
}
function snapshotCapacity(database: Database.Database) {
  const pageSize = database.pragma("page_size", { simple: true }) as number;
  if (pageSize * (database.pragma("page_count", { simple: true }) as number) > SNAPSHOT_MAX_BYTES) throw new MigrationStageError("CAPACITY");
  return pageSize;
}

/** Offline staging only. No normal service, Session, environment path or active-pointer access. */
export async function stageLegacyVault(sourcePath: string, vaultsDirectory: string, input: Credentials,
  options: { signal?: AbortSignal } = {}): Promise<MigrationStageResult> {
  if (busy) throw new MigrationStageError("BUSY");
  busy = true;
  let locker: Database.Database | undefined, reader: Database.Database | undefined, snapshot: Database.Database | undefined;
  let store: V2Store | undefined;
  let master: Buffer | undefined, passphrase: Buffer | undefined, oldKey: Buffer | undefined, root: Buffer | undefined;
  let reopenedRoot: Buffer | undefined, backupKey: Buffer | undefined;
  let expected: PasswordEntry[] = [], actual: PasswordEntry[] = [], recovered: PasswordEntry[] = [], snapshotEntries: PasswordEntry[] = [];
  let oldPassword: string | undefined, newPassword: string | undefined;
  try {
    let signal: AbortSignal | undefined;
    try {
      const value = record(input, ["masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase"]);
      const settings = record(options, ["signal"], []);
      if (settings.signal !== undefined && !(settings.signal instanceof AbortSignal)) throw new Error();
      signal = settings.signal as AbortSignal | undefined;
      if (typeof value.masterPassword !== "string") throw new Error();
      master = copyPlaintext(value.masterPassword, INPUT_LIMITS.masterPasswordBytes);
      const password = copyPlaintext(value.newMasterPassword, INPUT_LIMITS.masterPasswordBytes);
      try {
        if (typeof value.newMasterPassword !== "string" || value.newMasterPassword.length < 12 ||
            value.confirmNewMasterPassword !== value.newMasterPassword || value.newMasterPassword === value.masterPassword) throw new Error();
      } finally { password.fill(0); }
      oldPassword = value.masterPassword as string; newPassword = value.newMasterPassword as string;
      passphrase = copyPlaintext(parseBackupPayload({ passphrase: value.backupPassphrase }, false).passphrase, 4096);
    } catch { throw new MigrationStageError("INVALID_INPUT"); }
    const active = () => { if (signal?.aborted) throw new MigrationStageError("CANCELLED"); };
    active();
    const source = existingPath(sourcePath, false), parent = existingPath(vaultsDirectory, true);
    // Reject unknown formats before any writable connection, then recheck after obtaining the lock.
    reader = new Database(source, { readonly: true, fileMustExist: true, timeout: 0 });
    inspectLegacySource(reader); readLegacyMetadata(reader); snapshotCapacity(reader);
    // Keep this read-only connection alive until AFTER the RW locker closes. This prevents
    // SQLite's last-RW-connection close from checkpointing a pre-existing source WAL.
    locker = new Database(source, { fileMustExist: true, timeout: 0 });
    locker.pragma("temp_store = MEMORY");
    if (!["delete", "wal"].includes(locker.pragma("journal_mode", { simple: true }) as string)) throw new MigrationStageError("INVALID_SOURCE");
    // A read-only WAL connection does NOT exclude writers, even after BEGIN IMMEDIATE.
    // This private RW connection executes no data/schema writes and is always rolled back.
    locker.exec("BEGIN IMMEDIATE");
    const inspection = inspectLegacySource(locker), metadata = readLegacyMetadata(locker), pageSize = snapshotCapacity(locker);
    const metadataRows = locker.prepare("SELECT * FROM vault_metadata").all();
    const checked = await verifyLegacyMigrationSource(source, { masterPassword: oldPassword!, backupPassphrase: passphrase.toString("utf8") }, { signal }); active();
    const context = parsePasswordSlotContext({ vaultId: randomUUID(), keyId: randomUUID(), slotRevision: 1 });
    if (context.vaultId === context.keyId) throw new MigrationStageError("VERIFICATION_FAILED");
    const files = createStageDirectory(parent, context.vaultId);
    saveBackup(files.backup, checked.backup.content);
    expected = await verifyBackupRecovery(loadBackup(files.backup), passphrase, active); active();
    same(expected.length, checked.report.entryCount, "BACKUP_MISMATCH");
    reserveSnapshot(files.snapshot);
    // Backup from a separate reader: a backup on the write-transaction connection is not supported.
    await reader.backup(files.snapshot, { progress: progress => {
      active();
      if (progress.totalPages * pageSize > SNAPSHOT_MAX_BYTES) throw new MigrationStageError("CAPACITY");
      return 100;
    } }); active();
    // Make the recovery file standalone even when the source is WAL; never checkpoint/change the source.
    snapshot = new Database(files.snapshot, { fileMustExist: true });
    same(snapshot.pragma("journal_mode = DELETE", { simple: true }), "delete");
    snapshot.close(); snapshot = undefined;
    flushFile(files.snapshot);
    snapshot = new Database(files.snapshot, { readonly: true, fileMustExist: true });
    same(snapshot.pragma("quick_check", { simple: true }), "ok");
    same(inspectLegacySource(snapshot).missing, inspection.missing);
    same(snapshot.prepare("SELECT * FROM vault_metadata").all(), metadataRows);
    const savedMetadata = readLegacyMetadata(snapshot);
    oldKey = await deriveVaultKey(master, savedMetadata.salt); active();
    if (!verifyVaultKey(oldKey, savedMetadata.verifier, savedMetadata.rawVerifier)) throw new MigrationStageError("VERIFICATION_FAILED");
    snapshotEntries = (await readLegacyEntries(snapshot, oldKey, active)).entries; active();
    same(snapshotEntries, expected); snapshotEntries.length = 0;
    same(savedMetadata, metadata);
    snapshot.close(); snapshot = undefined;
    root = createRootKey();
    if (root.equals(oldKey)) throw new MigrationStageError("VERIFICATION_FAILED");
    const slot = await wrapRootKey(root, newPassword, context, { signal }); active();
    store = createV2Store(files.database, slot);
    for (const entry of expected) {
      active();
      const plaintext = copyPlaintext(JSON.stringify(entry));
      try { await store.writeEntry(root, plaintext, { vaultId: context.vaultId, keyId: context.keyId, entryId: entry.id, revision: 1 }, { signal }); }
      finally { plaintext.fill(0); }
      await setImmediate(); active();
    }
    same(store.getUsage().encryptionCount, expected.length);
    store.close(); store = undefined;
    flushFile(files.database); active();
    store = openV2Store(files.database, context);
    const savedSlot = store.readPasswordSlot();
    reopenedRoot = await unwrapRootKey(savedSlot, newPassword, context, { signal }); active();
    same(reopenedRoot, root); root.fill(0); root = undefined;
    let acceptedOldPassword = false;
    try {
      const invalidRoot = await unwrapRootKey(savedSlot, oldPassword, context, { signal });
      invalidRoot.fill(0); acceptedOldPassword = true;
    } catch (error) {
      if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error;
    }
    active();
    if (acceptedOldPassword) throw new MigrationStageError("VERIFICATION_FAILED");
    const contexts = store.listEntryContexts(); same(contexts.length, expected.length);
    for (const entryContext of contexts) {
      active();
      same(entryContext.revision, 1);
      const envelope = store.readEntry(entryContext.entryId);
      const plaintext = openEntry(reopenedRoot, envelope, entryContext, { signal });
      try { actual.push(JSON.parse(plaintext.toString("utf8")) as PasswordEntry); } finally { plaintext.fill(0); }
      // Prove that the legacy data key cannot authenticate newly encrypted entries.
      try { const invalid = openEntry(oldKey, envelope, entryContext, { signal }); invalid.fill(0); throw new MigrationStageError("VERIFICATION_FAILED"); }
      catch (error) { if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error; }
      await setImmediate(); active();
    }
    same(actual, expected);
    store.close(); store = undefined;
    reopenedRoot.fill(0); reopenedRoot = undefined;
    const salt = randomBytes(16);
    backupKey = await deriveBackupKey(passphrase, salt); active();
    saveBackup(files.exportBackup, encodeBackupV1(actual, backupKey, salt));
    backupKey.fill(0); backupKey = undefined;
    recovered = await verifyBackupRecovery(loadBackup(files.exportBackup), passphrase, active); active();
    same(recovered, expected, "BACKUP_MISMATCH");
    // The result is only produced after all handles close; no persistent activation marker is written.
    return Object.freeze({ state: "v2-verified", vaultId: context.vaultId, keyId: context.keyId, slotRevision: 1,
      entryCount: expected.length, files });
  } catch (error) {
    if (error instanceof MigrationStageError) throw error;
    if (error instanceof LegacyPreflightError) {
      const code = error.code === "SOURCE_CHANGED" ? "VERIFICATION_FAILED" : error.code === "FAILED" ? "IO_FAILED" : error.code;
      throw new MigrationStageError(code);
    }
    if (error instanceof VaultCodecError && (error.code === "CANCELLED" || error.code === "BUSY")) throw new MigrationStageError(error.code);
    if (error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED") throw new MigrationStageError("VERIFICATION_FAILED");
    if ((error as NodeJS.ErrnoException)?.code === "SQLITE_BUSY") throw new MigrationStageError("LOCKED");
    throw new MigrationStageError("IO_FAILED");
  } finally {
    master?.fill(0); passphrase?.fill(0); oldKey?.fill(0); root?.fill(0); reopenedRoot?.fill(0); backupKey?.fill(0);
    oldPassword = undefined; newPassword = undefined;
    expected.length = 0; actual.length = 0; recovered.length = 0; snapshotEntries.length = 0;
    let failed = false;
    try { if (store && !store.closed) store.close(); } catch { failed = true; }
    for (const database of [snapshot, locker, reader]) {
      try { if (database?.inTransaction) database.exec("ROLLBACK"); } catch { failed = true; }
      try { if (database?.open) database.close(); } catch { failed = true; }
    }
    busy = false;
    if (failed) throw new MigrationStageError("IO_FAILED");
  }
}
