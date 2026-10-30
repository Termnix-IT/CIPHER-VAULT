import Database from "better-sqlite3";
import { renameSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import type { VaultEntry } from "@password-manager/shared/types";
import { createRootKey, unwrapRootKey, VaultCodecError, wrapRootKey } from "../crypto/v2-codec.js";
import { copyPlaintext, parsePasswordSlotContext, record } from "../crypto/v2-format.js";
import type { PasswordSlotContext } from "../crypto/v2-format.js";
import { hasVaultStorage } from "../db/vault-context.js";
import { createV2Store, openV2Store, V2StoreError } from "../db/v2-store.js";
import type { V2Store } from "../db/v2-store.js";
import { SqliteFileScope } from "../db/sqlite-file-scope.js";
import { HttpError } from "../lib/errors.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { VaultSession } from "../services/vault-session.js";
import { vaultUnlockGuard } from "../services/vault-unlock-guard.js";
import { boundedRead, dataRoot, inspectVaultSelection, present, readPointer, readReceipt, safePath, syncDirectory, syncFile, VaultActivationError } from "./active-pointer.js";
import { reserveSnapshot, saveBackup } from "./staging-files.js";
import { createReplacementDirectory, hashFile, readTransition, replacementFiles, REPLACEMENT_SNAPSHOT_BYTES, V2ReplacementError, writeState } from "./v2-replacement-state.js";
import type { ReplacementMode, Transition } from "./v2-replacement-state.js";
import { exportBackup, readV2Entries, same, verifyBackup, verifySnapshot } from "./v2-replacement-verification.js";
export { inspectV2Replacement, V2ReplacementError } from "./v2-replacement-state.js";

type Request = { mode: ReplacementMode; masterPassword: string; newMasterPassword: string; confirmNewMasterPassword: string;
  backupPassphrase: string; confirmation?: "RESET_ALL_DATA" };
type Authorization = { session: VaultSession; sessionId: string };
type RecoveryContext = { source: PasswordSlotContext; target: PasswordSlotContext; mode: ReplacementMode };
let busy = false;
const recoveryRequired = (): never => { throw new V2ReplacementError("RECOVERY_REQUIRED"); };
const receiptFor = (context: PasswordSlotContext, count: number, state: "prepared" | "committed") => ({
  format: "CIPHER-VAULT-ACTIVATION", version: 1, vaultId: context.vaultId, keyId: context.keyId, entryCount: count, state });

/** Offline only: close the normal Context first and retain a separately owned, authenticated source Session. */
export function replaceV2Vault(directory: string, source: PasswordSlotContext, request: Request, authorization: Authorization,
  options: { signal?: AbortSignal } = {}) { return replace(directory, source, undefined, request, authorization, options); }
/** No encryption or entry writes. Reauthenticate and verify the exact interrupted candidate before selecting it. */
export function recoverV2Replacement(directory: string, expected: RecoveryContext, request: Request, authorization: Authorization,
  options: { signal?: AbortSignal } = {}) { return replace(directory, undefined, expected, request, authorization, options); }

async function replace(directory: string, sourceInput: PasswordSlotContext | undefined, recoveryInput: RecoveryContext | undefined,
  input: Request, authorization: Authorization, options: { signal?: AbortSignal }) {
  if (busy) throw new V2ReplacementError("BUSY"); busy = true;
  const rawFiles = new SqliteFileScope();
  let sourceStore: V2Store | undefined, targetStore: V2Store | undefined;
  let sourceLocker: Database.Database | undefined, targetLocker: Database.Database | undefined, snapshotReader: Database.Database | undefined;
  let sourceKey: Buffer | undefined, targetKey: Buffer | undefined, passphrase: Buffer | undefined;
  let oldPassword: string | undefined, newPassword: string | undefined, root: string | undefined;
  let session: VaultSession | undefined, sessionId: string | undefined, started = false, publishing = false;
  let original: VaultEntry[] = [], actual: VaultEntry[] = [];
  try {
    let source: PasswordSlotContext, target: PasswordSlotContext | undefined, mode: ReplacementMode, signal: AbortSignal | undefined;
    try {
      const value = record(input, ["mode", "masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase", "confirmation"],
        ["mode", "masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase"]);
      const settings = record(options, ["signal"], []), owner = record(authorization, ["session", "sessionId"]);
      if (!(owner.session instanceof VaultSession) || typeof owner.sessionId !== "string" ||
          (settings.signal !== undefined && !(settings.signal instanceof AbortSignal)) || !["rekey", "reset"].includes(value.mode as string) ||
          typeof value.masterPassword !== "string" || typeof value.newMasterPassword !== "string" || value.newMasterPassword.length < 12 ||
          value.newMasterPassword === value.masterPassword || value.newMasterPassword !== value.confirmNewMasterPassword ||
          (value.mode === "reset" ? value.confirmation !== "RESET_ALL_DATA" : value.confirmation !== undefined)) throw new Error();
      for (const password of [value.masterPassword, value.newMasterPassword]) copyPlaintext(password, INPUT_LIMITS.masterPasswordBytes).fill(0);
      passphrase = copyPlaintext(parseBackupPayload({ passphrase: value.backupPassphrase }, false).passphrase, 4096);
      oldPassword = value.masterPassword; newPassword = value.newMasterPassword; mode = value.mode as ReplacementMode;
      if (recoveryInput !== undefined) {
        const expected = record(recoveryInput, ["source", "target", "mode"]);
        source = parsePasswordSlotContext(expected.source); target = parsePasswordSlotContext(expected.target);
        if (expected.mode !== mode || target.slotRevision !== 1) throw new Error();
      } else source = parsePasswordSlotContext(sourceInput);
      if (source.slotRevision !== 1) throw new Error();
      session = owner.session; sessionId = owner.sessionId; signal = settings.signal as AbortSignal | undefined;
    } catch { throw new V2ReplacementError("INVALID_INPUT"); }
    const active = () => {
      if (signal?.aborted) throw new V2ReplacementError("CANCELLED");
      try { session!.requireUnlocked(sessionId); } catch { throw new V2ReplacementError("CANCELLED"); }
      if (hasVaultStorage()) throw new V2ReplacementError("IN_USE");
    };
    active(); started = true; root = dataRoot(directory);
    let transition: Transition | undefined, pointer: Buffer | undefined, receipt: Buffer | undefined;
    const selectedSource = () => {
      const selected = inspectVaultSelection(root!);
      if (selected.format !== "v2") return recoveryRequired();
      same(selected.context, source);
      if (pointer) same(boundedRead(safePath(root!, ["vault-current.json"]), 512), pointer);
      if (receipt) same(boundedRead(safePath(root!, ["vault-activation.json"]), 512), receipt);
    };
    if (recoveryInput !== undefined) {
      transition = readTransition(root); same(transition.source, source); same(transition.target, target); same(transition.mode, mode);
      publishing = true; // An existing journal always requires explicit recovery on failure.
    } else {
      selectedSource(); pointer = boundedRead(safePath(root, ["vault-current.json"]), 512);
      receipt = boundedRead(safePath(root, ["vault-activation.json"]), 512); selectedSource();
    }
    const sourcePath = safePath(root, ["vaults", source.vaultId, "vault.sqlite"]);
    sourceStore = openV2Store(sourcePath, source); // Validate unknown formats before opening a writer.
    sourceLocker = new Database(sourcePath, { fileMustExist: true, timeout: 0 }); sourceLocker.exec("BEGIN IMMEDIATE");
    active(); if (!transition) selectedSource();
    const pageSize = sourceLocker.pragma("page_size", { simple: true }) as number;
    if (pageSize * (sourceLocker.pragma("page_count", { simple: true }) as number) > REPLACEMENT_SNAPSHOT_BYTES) throw new V2ReplacementError("CAPACITY");
    sourceKey = await vaultUnlockGuard.run(async () => {
      let key: Buffer | undefined;
      try {
        try { key = await unwrapRootKey(sourceStore!.readPasswordSlot(), oldPassword, source, { signal }); }
        catch (error) {
          if (error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED") throw new HttpError(401, "保管庫の認証に失敗しました");
          throw error;
        }
        active();
        if (!key.equals(session!.requireKey())) throw new HttpError(401, "保管庫の認証に失敗しました");
        const result = key; key = undefined; return result;
      } finally { key?.fill(0); }
    }); active();
    original = await readV2Entries(sourceStore, sourceKey, active);
    const sourceUses = sourceStore.getUsage().encryptionCount;
    if (transition) { same(original.length, transition.sourceCount); same(sourceUses, transition.sourceUses); }
    else {
      target = parsePasswordSlotContext({ vaultId: randomUUID(), keyId: randomUUID(), slotRevision: 1 });
      if (target.vaultId === target.keyId || [target.vaultId, target.keyId].some(id => [source.vaultId, source.keyId].includes(id))) throw new V2ReplacementError("VERIFICATION_FAILED");
    }
    let files = transition ? replacementFiles(root, target!) : createReplacementDirectory(root, target!);
    if (!transition) {
      saveBackup(files.sourcePointer, pointer!.toString("utf8")); saveBackup(files.sourceReceipt, receipt!.toString("utf8"));
      await exportBackup(files.backup, original, passphrase!, active); active();
      reserveSnapshot(files.snapshot);
      snapshotReader = new Database(sourcePath, { readonly: true, fileMustExist: true, timeout: 0 });
      await snapshotReader.backup(files.snapshot, { progress: progress => {
        active(); if (progress.totalPages * pageSize > REPLACEMENT_SNAPSHOT_BYTES) throw new V2ReplacementError("CAPACITY"); return 100;
      } }); active(); snapshotReader.close(); snapshotReader = undefined; syncFile(files.snapshot);
      await verifySnapshot(files.snapshot, source, oldPassword!, sourceKey, original, sourceUses, active, signal); active();
      targetKey = createRootKey(); if (targetKey.equals(sourceKey)) throw new V2ReplacementError("VERIFICATION_FAILED");
      const slot = await wrapRootKey(targetKey, newPassword, target!, { signal }); active();
      targetStore = createV2Store(files.database, slot);
      if (mode === "rekey") for (const entry of original) {
        active(); const plaintext = copyPlaintext(JSON.stringify(entry), INPUT_LIMITS.backupPlaintextBytes);
        try { await targetStore.writeEntry(targetKey, plaintext, { vaultId: target!.vaultId, keyId: target!.keyId, entryId: entry.id, revision: 1 },
          { signal, assertCurrent: active }); } finally { plaintext.fill(0); }
      }
      targetStore.close(); targetStore = undefined; syncFile(files.database);
    } else {
      await checkHashes(root, transition, active, rawFiles.deferClose);
      await verifyBackup(files.backup, passphrase!, original, active);
      await verifySnapshot(files.snapshot, source, oldPassword!, sourceKey, original, sourceUses, active, signal);
      const savedPointer = JSON.parse(boundedRead(files.sourcePointer, 512).toString("utf8"));
      const savedReceipt = JSON.parse(boundedRead(files.sourceReceipt, 512).toString("utf8"));
      same(savedPointer, { format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: source.vaultId });
      if (!Number.isInteger(savedReceipt.entryCount) || savedReceipt.entryCount < 0 || savedReceipt.entryCount > 10000) recoveryRequired();
      same(savedReceipt, receiptFor(source, savedReceipt.entryCount, "committed"));
    }
    // Acquire the target lock after creation; hold both private locks throughout publication/recovery.
    targetStore = openV2Store(files.database, target!); targetStore.close(); targetStore = undefined;
    targetLocker = new Database(files.database, { fileMustExist: true, timeout: 0 }); targetLocker.exec("BEGIN IMMEDIATE");
    targetStore = openV2Store(files.database, target!);
    let reopened: Buffer | undefined;
    try {
      reopened = await unwrapRootKey(targetStore.readPasswordSlot(), newPassword, target!, { signal }); active();
      if (targetKey) same(reopened, targetKey);
      if (reopened.equals(sourceKey)) throw new V2ReplacementError("VERIFICATION_FAILED");
      try { const invalid = await unwrapRootKey(targetStore.readPasswordSlot(), oldPassword, target!, { signal }); invalid.fill(0); same(true, false); }
      catch (error) { if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error; }
      active(); actual = await readV2Entries(targetStore, reopened, active, true, sourceKey);
      same(actual, mode === "reset" ? [] : original); same(targetStore.getUsage().encryptionCount, actual.length);
    } finally { reopened?.fill(0); }
    targetStore.close(); targetStore = undefined;
    if (transition) {
      await verifyBackup(files.targetBackup, passphrase!, actual, active);
      await checkHashes(root, transition, active, rawFiles.deferClose); // Includes the target after its writer lock is held.
      same(readTransition(root), transition); preserveGlobals(root, files.directory, source, target!, active);
    } else {
      await exportBackup(files.targetBackup, actual, passphrase!, active); active();
      files = replacementFiles(root, target!);
      transition = Object.freeze({ format: "CIPHER-VAULT-TRANSITION", version: 1, mode, source, target: target!,
        sourceCount: original.length, targetCount: actual.length, sourceUses, hashes: await fingerprints(root, source, target!, active, rawFiles.deferClose) });
      for (const file of [files.database, files.snapshot, files.backup, files.sourcePointer, files.sourceReceipt, files.targetBackup]) {
        active(); syncFile(file, file === files.database ? rawFiles.deferClose : undefined);
      }
      syncDirectory(files.directory); syncDirectory(path.dirname(files.directory)); syncDirectory(root);
      active(); selectedSource();
      writeState(root, "vault-transition.json", transition, () => { active(); selectedSource(); }, true);
      publishing = true;
    }
    const checkPending = () => { active(); replacementFiles(root!, target!); same(readTransition(root!), transition); };
    checkPending();
    writeState(root, "vault-activation.json", receiptFor(target!, actual.length, "prepared"), checkPending);
    writeState(root, "vault-current.json", { format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: target!.vaultId }, checkPending);
    writeState(root, "vault-activation.json", receiptFor(target!, actual.length, "committed"), checkPending);
    checkPending(); same(readPointer(root), target!.vaultId); same(readReceipt(root), receiptFor(target!, actual.length, "committed"));
    files = replacementFiles(root, target!); if (present(files.archive)) recoveryRequired();
    renameSync(safePath(root, ["vault-transition.json"]), files.archive); syncFile(files.archive);
    syncDirectory(files.directory); const directorySynced = syncDirectory(root);
    return Object.freeze({ state: "v2-selected" as const, mode, source, target: target!, sourceCount: original.length,
      targetCount: actual.length, files, durability: directorySynced ? "file-and-directory-sync" as const : "file-sync" as const });
  } catch (error) {
    let pending = publishing;
    try { pending ||= root !== undefined && present(safePath(root, ["vault-transition.json"], false, true)); }
    catch { pending = true; }
    if (pending) throw new V2ReplacementError("RECOVERY_REQUIRED");
    if (error instanceof V2ReplacementError) throw error;
    if (error instanceof HttpError) {
      if (error.statusCode === 401) throw new V2ReplacementError("AUTHENTICATION_FAILED");
      if (error.statusCode === 409 || error.statusCode === 429) throw new V2ReplacementError("BUSY");
    }
    if (error instanceof VaultCodecError) {
      if (["CANCELLED", "BUSY", "AUTHENTICATION_FAILED"].includes(error.code)) throw new V2ReplacementError(error.code as "CANCELLED" | "BUSY" | "AUTHENTICATION_FAILED");
      throw new V2ReplacementError("VERIFICATION_FAILED");
    }
    if (error instanceof V2StoreError || error instanceof VaultActivationError) throw new V2ReplacementError("VERIFICATION_FAILED");
    if ((error as NodeJS.ErrnoException)?.code === "SQLITE_BUSY") throw new V2ReplacementError("LOCKED");
    throw new V2ReplacementError("IO_FAILED");
  } finally {
    sourceKey?.fill(0); targetKey?.fill(0); passphrase?.fill(0); oldPassword = undefined; newPassword = undefined;
    original.length = 0; actual.length = 0; let failed = false;
    for (const store of [targetStore, sourceStore]) { try { store?.close(); } catch { failed = true; } }
    for (const db of [snapshotReader, targetLocker, sourceLocker]) {
      try { if (db?.inTransaction) db.exec("ROLLBACK"); } catch { failed = true; }
      try { if (db?.open) db.close(); } catch { failed = true; }
    }
    if (!rawFiles.close()) failed = true;
    try { if (started && session && session.getState().sessionId === sessionId) session.lock(); } catch { failed = true; }
    busy = false;
    if (failed) throw new V2ReplacementError("RECOVERY_REQUIRED");
  }
}

async function fingerprints(root: string, source: PasswordSlotContext, target: PasswordSlotContext, active: () => void,
  releaseDatabaseFile: (fd: number) => void) {
  const files = replacementFiles(root, target);
  return Object.freeze({ source: await hashFile(safePath(root, ["vaults", source.vaultId, "vault.sqlite"]), REPLACEMENT_SNAPSHOT_BYTES, active, releaseDatabaseFile),
    snapshot: await hashFile(files.snapshot, REPLACEMENT_SNAPSHOT_BYTES, active), backup: await hashFile(files.backup, INPUT_LIMITS.backupFileBytes, active),
    sourcePointer: await hashFile(files.sourcePointer, 512, active), sourceReceipt: await hashFile(files.sourceReceipt, 512, active),
    target: await hashFile(files.database, REPLACEMENT_SNAPSHOT_BYTES, active, releaseDatabaseFile), targetBackup: await hashFile(files.targetBackup, INPUT_LIMITS.backupFileBytes, active) });
}
async function checkHashes(root: string, transition: Transition, active: () => void, releaseDatabaseFile: (fd: number) => void) {
  same(await fingerprints(root, transition.source, transition.target, active, releaseDatabaseFile), transition.hashes);
}
function preserveGlobals(root: string, directory: string, source: PasswordSlotContext, target: PasswordSlotContext, active: () => void) {
  // Preserve bounded malformed metadata too, but never overwrite a valid selection of an unrelated vault.
  for (const name of ["vault-current.json", "vault-activation.json"]) {
    const file = safePath(root, [name], false, true); if (!present(file)) continue;
    const bytes = boundedRead(file, 512);
    if (name === "vault-current.json") {
      let id: string | undefined; try { id = readPointer(root); } catch { /* Preserved below. */ }
      if (id !== undefined && ![source.vaultId, target.vaultId].includes(id)) recoveryRequired();
    } else {
      let value: ReturnType<typeof readReceipt> | undefined; try { value = readReceipt(root); } catch { /* Preserved below. */ }
      if (value && ![source, target].some(context => context.vaultId === value!.vaultId && context.keyId === value!.keyId)) recoveryRequired();
    }
    active(); saveBackup(path.join(directory, `preserved-${name}-${randomUUID()}`), bytes.toString("base64"));
  }
  syncDirectory(directory);
}
