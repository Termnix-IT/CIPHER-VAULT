import Database from "better-sqlite3";
import { setImmediate } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import type { PasswordEntry } from "@password-manager/shared/types";
import { deriveVaultKey, verifyVaultKey } from "../crypto/legacy-codec.js";
import { openEntry, unwrapRootKey, VaultCodecError } from "../crypto/v2-codec.js";
import { copyPlaintext, parsePasswordSlotContext, record } from "../crypto/v2-format.js";
import type { PasswordSlotContext } from "../crypto/v2-format.js";
import { openV2Store } from "../db/v2-store.js";
import type { V2Store } from "../db/v2-store.js";
import { SqliteFileScope } from "../db/sqlite-file-scope.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { VaultSession } from "../services/vault-session.js";
import { verifyBackupRecovery } from "./backup-recovery.js";
import { inspectLegacySource, LegacyPreflightError, readLegacyEntries, readLegacyMetadata } from "./legacy-reader.js";
import { boundedRead, dataRoot, inspectVaultSelection, present, publishPointer, readPointer, readReceipt, safePath, stagedFiles, VaultActivationError } from "./active-pointer.js";
export { inspectVaultSelection, VaultActivationError } from "./active-pointer.js";

type Credentials = { masterPassword: string; newMasterPassword: string; backupPassphrase: string };
type Authorization = { session: VaultSession; sessionId: string };
let busy = false;
const mismatch = (): never => { throw new VaultActivationError("VERIFICATION_FAILED"); };
function same(actual: unknown, expected: unknown) { if (!isDeepStrictEqual(actual, expected)) mismatch(); }

/** Internal coordinator only. The caller must bind this legacy Session to the migration UI. */
export function activateStagedVault(directory: string, context: PasswordSlotContext, input: Credentials, authorization: Authorization,
  options: { signal?: AbortSignal } = {}) { return activate(directory, context, input, authorization, options, false); }
/** Explicit recovery revalidates the known candidate; it never copies a DB or resumes a partial writer. */
export function recoverVaultActivation(directory: string, context: PasswordSlotContext, input: Credentials, authorization: Authorization,
  options: { signal?: AbortSignal } = {}) { return activate(directory, context, input, authorization, options, true); }

async function activate(directory: string, contextInput: PasswordSlotContext, input: Credentials, authorization: Authorization,
  options: { signal?: AbortSignal }, recovery: boolean) {
  if (busy) throw new VaultActivationError("BUSY");
  busy = true;
  const rawFiles = new SqliteFileScope();
  let source: Database.Database | undefined, locker: Database.Database | undefined, targetLocker: Database.Database | undefined;
  let snapshot: Database.Database | undefined, store: V2Store | undefined;
  let master: Buffer | undefined, passphrase: Buffer | undefined, oldKey: Buffer | undefined, root: Buffer | undefined;
  let oldPassword: string | undefined, newPassword: string | undefined, session: VaultSession | undefined, sessionId: string | undefined;
  let expected: PasswordEntry[] = [], original: PasswordEntry[] = [], saved: PasswordEntry[] = [], actual: PasswordEntry[] = [], exported: PasswordEntry[] = [];
  let rootPath: string | undefined, started = false;
  try {
    let context: PasswordSlotContext, signal: AbortSignal | undefined;
    try {
      const value = record(input, ["masterPassword", "newMasterPassword", "backupPassphrase"]), settings = record(options, ["signal"], []);
      const owner = record(authorization, ["session", "sessionId"]);
      context = parsePasswordSlotContext(contextInput);
      if (context.slotRevision !== 1 || !(owner.session instanceof VaultSession) || typeof owner.sessionId !== "string" ||
          (settings.signal !== undefined && !(settings.signal instanceof AbortSignal)) || typeof value.masterPassword !== "string" ||
          typeof value.newMasterPassword !== "string" || value.newMasterPassword.length < 12 || value.masterPassword === value.newMasterPassword) throw new Error();
      session = owner.session; sessionId = owner.sessionId; signal = settings.signal as AbortSignal | undefined;
      master = copyPlaintext(value.masterPassword, INPUT_LIMITS.masterPasswordBytes);
      const password = copyPlaintext(value.newMasterPassword, INPUT_LIMITS.masterPasswordBytes); password.fill(0);
      passphrase = copyPlaintext(parseBackupPayload({ passphrase: value.backupPassphrase }, false).passphrase, 4096);
      oldPassword = value.masterPassword; newPassword = value.newMasterPassword;
    } catch { throw new VaultActivationError("INVALID_INPUT"); }
    const active = () => {
      if (signal?.aborted) throw new VaultActivationError("CANCELLED");
      try { session!.requireUnlocked(sessionId); } catch { throw new VaultActivationError("CANCELLED"); }
    };
    active(); started = true;
    rootPath = dataRoot(directory);
    const checkState = () => {
      if (!recovery) { if (inspectVaultSelection(rootPath!).format !== "legacy") throw new VaultActivationError("RECOVERY_REQUIRED"); }
      else {
        const receipt = readReceipt(rootPath!);
        same({ vaultId: receipt.vaultId, keyId: receipt.keyId, slotRevision: 1 }, context);
        const pointer = safePath(rootPath!, ["vault-current.json"], false, true);
        if (present(pointer)) {
          let target: string | undefined;
          try { target = readPointer(rootPath!); } catch { /* Explicit recovery may replace a malformed, preserved pointer. */ }
          if (target !== undefined && target !== context.vaultId) throw new VaultActivationError("RECOVERY_REQUIRED");
        }
      }
    };
    checkState();
    let files = stagedFiles(rootPath, context);
    const sourceFile = safePath(rootPath, ["password-manager.db"]);
    source = new Database(sourceFile, { readonly: true, fileMustExist: true, timeout: 0 });
    inspectLegacySource(source); readLegacyMetadata(source);
    // Preserve the source WAL by keeping the RO connection until after the private RW lock closes.
    locker = new Database(sourceFile, { fileMustExist: true, timeout: 0 });
    locker.pragma("temp_store = MEMORY");
    if (!["delete", "wal"].includes(locker.pragma("journal_mode", { simple: true }) as string)) mismatch();
    locker.exec("BEGIN IMMEDIATE"); active(); checkState();
    store = openV2Store(files.database, context); store.close(); store = undefined;
    targetLocker = new Database(files.database, { fileMustExist: true, timeout: 0 });
    targetLocker.exec("BEGIN IMMEDIATE");
    store = openV2Store(files.database, context);
    const metadata = readLegacyMetadata(locker); inspectLegacySource(locker);
    oldKey = await deriveVaultKey(master, metadata.salt); active();
    if (!verifyVaultKey(oldKey, metadata.verifier, metadata.rawVerifier)) throw new VaultActivationError("AUTHENTICATION_FAILED");
    if (!session!.requireKey().equals(oldKey)) throw new VaultActivationError("AUTHENTICATION_FAILED");
    original = (await readLegacyEntries(source, oldKey, active)).entries; active();
    const readBackup = (file: string) => boundedRead(file, INPUT_LIMITS.backupFileBytes).toString("utf8");
    expected = await verifyBackupRecovery(readBackup(files.backup), passphrase, active); active(); same(expected, original);
    snapshot = new Database(files.snapshot, { readonly: true, fileMustExist: true });
    same(snapshot.pragma("quick_check", { simple: true }), "ok");
    same(inspectLegacySource(snapshot).missing, inspectLegacySource(source).missing);
    same(snapshot.prepare("SELECT * FROM vault_metadata").all(), source.prepare("SELECT * FROM vault_metadata").all());
    saved = (await readLegacyEntries(snapshot, oldKey, active)).entries; active(); same(saved, expected);
    snapshot.close(); snapshot = undefined;
    root = await unwrapRootKey(store.readPasswordSlot(), newPassword, context, { signal }); active();
    if (root.equals(oldKey)) mismatch();
    try { const invalid = await unwrapRootKey(store.readPasswordSlot(), oldPassword, context, { signal }); invalid.fill(0); mismatch(); }
    catch (error) { if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error; }
    active();
    const contexts = store.listEntryContexts(); same(contexts.length, expected.length); same(store.getUsage().encryptionCount, expected.length);
    for (const entryContext of contexts) {
      active(); same(entryContext.revision, 1);
      const envelope = store.readEntry(entryContext.entryId), plaintext = openEntry(root, envelope, entryContext, { signal });
      try { actual.push(JSON.parse(plaintext.toString("utf8")) as PasswordEntry); } finally { plaintext.fill(0); }
      try { const invalid = openEntry(oldKey, envelope, entryContext, { signal }); invalid.fill(0); mismatch(); }
      catch (error) { if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error; }
      await setImmediate(); active();
    }
    same(actual, expected); store.close(); store = undefined; root.fill(0); root = undefined;
    exported = await verifyBackupRecovery(readBackup(files.exportBackup), passphrase, active); active(); same(exported, expected);
    checkState(); files = stagedFiles(rootPath, context);
    const receipt = Object.freeze({ format: "CIPHER-VAULT-ACTIVATION" as const, version: 1 as const,
      vaultId: context.vaultId, keyId: context.keyId, entryCount: expected.length,
      state: recovery ? readReceipt(rootPath).state : "prepared" as const });
    if (recovery) same(readReceipt(rootPath), receipt);
    const durability = publishPointer(rootPath, receipt, recovery, active, rawFiles.deferClose); active();
    return Object.freeze({ state: "v2-selected" as const, context, entryCount: expected.length, database: files.database, durability });
  } catch (error) {
    // Any observed receipt means publication may have happened. Require explicit recovery, never rollback.
    let receiptObserved = false;
    try { receiptObserved = rootPath !== undefined && present(safePath(rootPath, ["vault-activation.json"], false, true)); }
    catch { throw new VaultActivationError("RECOVERY_REQUIRED"); }
    if (receiptObserved) throw new VaultActivationError("RECOVERY_REQUIRED");
    if (error instanceof VaultActivationError) throw error;
    if (error instanceof VaultCodecError || error instanceof LegacyPreflightError) {
      if (error.code === "CANCELLED" || error.code === "BUSY" || error.code === "AUTHENTICATION_FAILED") throw new VaultActivationError(error.code);
      throw new VaultActivationError("VERIFICATION_FAILED");
    }
    if ((error as NodeJS.ErrnoException)?.code === "SQLITE_BUSY") throw new VaultActivationError("LOCKED");
    throw new VaultActivationError("IO_FAILED");
  } finally {
    master?.fill(0); passphrase?.fill(0); oldKey?.fill(0); root?.fill(0); oldPassword = undefined; newPassword = undefined;
    for (const entries of [expected, original, saved, actual, exported]) entries.length = 0;
    let failed = false;
    try { if (store && !store.closed) store.close(); } catch { failed = true; }
    for (const database of [snapshot, targetLocker, locker, source]) {
      try { if (database?.inTransaction) database.exec("ROLLBACK"); } catch { failed = true; }
      try { if (database?.open) database.close(); } catch { failed = true; }
    }
    if (!rawFiles.close()) failed = true;
    try { if (started && session && session.getState().sessionId === sessionId) session.lock(); } catch { failed = true; }
    busy = false;
    if (failed) throw new VaultActivationError("RECOVERY_REQUIRED");
  }
}
