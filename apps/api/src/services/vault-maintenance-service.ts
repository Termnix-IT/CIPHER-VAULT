import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import type { VaultMaintenancePayload, VaultMaintenanceState } from "@password-manager/shared/types";
import { deriveVaultKey, verifyVaultKey } from "../crypto/legacy-codec.js";
import { unwrapRootKey } from "../crypto/v2-codec.js";
import { copyPlaintext, record } from "../crypto/v2-format.js";
import { resolveDataDirectory } from "../db/database.js";
import type { DatabaseOptions } from "../db/database.js";
import { assertVaultStorage, closeVaultStorage, getVaultDataDirectory, hasVaultStorage, isV2Vault, openVaultStorage } from "../db/vault-context.js";
import { openV2Store } from "../db/v2-store.js";
import { HttpError } from "../lib/errors.js";
import { INPUT_LIMITS, parseBackupPayload } from "../lib/input-validation.js";
import { activateStagedVault, recoverVaultActivation } from "../migration/activation.js";
import { dataRoot, inspectVaultSelection, present, readReceipt, safePath, VaultActivationError } from "../migration/active-pointer.js";
import { inspectLegacySource, readLegacyMetadata } from "../migration/legacy-reader.js";
import { stageLegacyVault } from "../migration/staging.js";
import { inspectV2Replacement, recoverV2Replacement, replaceV2Vault } from "../migration/v2-replacement.js";
import { VaultSession, vaultSession } from "./vault-session.js";
import { vaultUnlockGuard } from "./vault-unlock-guard.js";

let configuration: DatabaseOptions | undefined, status: VaultMaintenanceState | undefined;
let busy = false, stopping = false, pending: Promise<void> | undefined;
const listeners = new Set<() => void>();
function publish(value: VaultMaintenanceState | undefined) {
  status = value && Object.freeze({ ...value });
  for (const listener of listeners) { try { listener(); } catch { /* Observers never control storage. */ } }
}
export function getVaultMaintenanceState() { return status; }
export function isApplicationVaultStopping() { return stopping; }
export function onVaultMaintenanceState(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }
export function assertVaultMaintenanceReady() {
  if (busy || stopping) throw new HttpError(409, "保管庫の切り替えが完了するまでお待ちください");
  if (status?.state === "recovery-required") throw new HttpError(503, "保管庫の復旧を先に完了してください");
}
function recovery(directory: string) {
  if (present(safePath(directory, ["vault-transition.json"], false, true))) return { kind: "v2" as const, ...inspectV2Replacement(directory) };
  const receipt = readReceipt(directory), source = safePath(directory, ["password-manager.db"]);
  const reader = new Database(source, { readonly: true, fileMustExist: true, timeout: 0 });
  try { inspectLegacySource(reader); readLegacyMetadata(reader); } finally { reader.close(); }
  const target = { vaultId: receipt.vaultId, keyId: receipt.keyId, slotRevision: 1 };
  const store = openV2Store(safePath(directory, ["vaults", target.vaultId, "vault.sqlite"]), target); store.close();
  return { kind: "legacy" as const, target, mode: "migrate" as const };
}
/** Ordinary startup still rejects unknown storage; only a known interrupted operation enters recovery mode. */
export function openApplicationVault(options: DatabaseOptions = {}) {
  if (configuration || busy || hasVaultStorage()) throw new HttpError(409, "保管庫はすでに開いています");
  stopping = false;
  try {
    openVaultStorage(options);
    configuration = { ...options, dataDirectory: getVaultDataDirectory() };
    publish({ state: "ready", format: isV2Vault() ? "v2" : "legacy" });
  } catch (error) {
    if (!(error instanceof VaultActivationError && error.code === "RECOVERY_REQUIRED")) throw error;
    const directory = dataRoot(options.dataDirectory ?? resolveDataDirectory()), hint = recovery(directory);
    configuration = { ...options, dataDirectory: directory }; vaultSession.lock();
    publish({ state: "recovery-required", format: "unknown", operation: "recover", recoveryOperation: hint.mode });
  }
}
export function closeApplicationVault() {
  stopVaultMaintenance();
  if (!busy) { closeVaultStorage(); configuration = undefined; publish(undefined); }
}
export function stopVaultMaintenance() { stopping = true; vaultSession.lock(); }
export async function waitForVaultMaintenance() { await pending; }

function parse(value: unknown): VaultMaintenancePayload {
  try {
    const input = record(value, ["operation", "masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase", "confirmBackupPassphrase", "confirmation"],
      ["operation", "masterPassword", "newMasterPassword", "confirmNewMasterPassword", "backupPassphrase"]);
    if (!["migrate", "rekey", "reset", "recover"].includes(input.operation as string) || typeof input.masterPassword !== "string" ||
        typeof input.newMasterPassword !== "string" || input.newMasterPassword.length < 12 || input.newMasterPassword === input.masterPassword ||
        input.newMasterPassword !== input.confirmNewMasterPassword ||
        (input.operation !== "recover" && input.backupPassphrase !== input.confirmBackupPassphrase) ||
        (input.operation === "reset" ? input.confirmation !== "RESET_ALL_DATA" : input.operation !== "recover" && input.confirmation !== undefined) ||
        (input.confirmation !== undefined && input.confirmation !== "RESET_ALL_DATA")) throw new Error();
    for (const password of [input.masterPassword, input.newMasterPassword]) copyPlaintext(password, INPUT_LIMITS.masterPasswordBytes).fill(0);
    copyPlaintext(parseBackupPayload({ passphrase: input.backupPassphrase }, false).passphrase, 4096).fill(0);
    if (input.confirmBackupPassphrase !== undefined && input.confirmBackupPassphrase !== input.backupPassphrase) throw new Error();
    return input as unknown as VaultMaintenancePayload;
  } catch { throw new HttpError(400, "操作・パスワード・確認入力・バックアップ用パスフレーズを確認してください"); }
}
function translate(error: unknown): HttpError {
  if (error instanceof HttpError) return error;
  const code = typeof error === "object" && error !== null && "code" in error ? error.code : undefined;
  if (code === "AUTHENTICATION_FAILED") return new HttpError(401, "パスワードが正しくないか、保管庫の認証に失敗しました");
  if (code === "INVALID_INPUT") return new HttpError(400, "入力内容を確認してください");
  if (code === "CAPACITY") return new HttpError(413, "移行・復旧に対応する容量を超えています");
  if (["BUSY", "LOCKED", "IN_USE", "CANCELLED"].includes(code as string)) return new HttpError(409, "処理が取り消されたか、別の処理が進行中です");
  return new HttpError(503, "保管庫の検証または切り替えを完了できませんでした。元のファイルを保持し、状態を確認してください");
}
async function authenticateSource(directory: string, input: VaultMaintenancePayload, active: () => void,
  source?: ReturnType<typeof inspectV2Replacement>["source"], signal?: AbortSignal) {
  let key: Buffer | undefined;
  try {
    active();
    if (source) {
      const store = openV2Store(safePath(directory, ["vaults", source.vaultId, "vault.sqlite"]), source);
      try { key = await unwrapRootKey(store.readPasswordSlot(), input.masterPassword, source, { signal }); } finally { store.close(); }
    } else {
      const reader = new Database(safePath(directory, ["password-manager.db"]), { readonly: true, fileMustExist: true, timeout: 0 });
      try {
        inspectLegacySource(reader); const metadata = readLegacyMetadata(reader);
        key = await deriveVaultKey(input.masterPassword, metadata.salt); active();
        if (!verifyVaultKey(key, metadata.verifier, metadata.rawVerifier)) throw new HttpError(401, "マスターパスワードが正しくありません");
      } finally { reader.close(); }
    }
    active(); const result = key; key = undefined; return result!;
  } catch (error) { throw translate(error); } finally { key?.fill(0); }
}

/** Captures a validated request, closes the runtime, then reopens only a verified selection, always locked. */
export async function runVaultMaintenance(value: unknown, expectedSessionId: unknown, options: { signal?: AbortSignal } = {}) {
  if (busy || stopping) throw new HttpError(409, "保管庫の切り替えが進行中です");
  if (options.signal?.aborted) throw new HttpError(409, "保管庫の切り替えは取り消されました");
  const input = parse(value), generation = vaultSession.requireGeneration(expectedSessionId);
  if (!configuration) throw new HttpError(503, "保管庫の管理サービスが初期化されていません");
  if (configuration.readonly) throw new HttpError(403, "読取専用の保管庫では切り替えできません");
  const recovering = input.operation === "recover";
  if (recovering ? status?.state !== "recovery-required" : status?.state === "recovery-required") throw new HttpError(409, "現在の保管庫ではこの操作を実行できません");
  let directory: string, hint: ReturnType<typeof recovery> | undefined, selected: ReturnType<typeof inspectVaultSelection> | undefined;
  try {
    directory = dataRoot(configuration.dataDirectory!);
    hint = recovering ? recovery(directory) : undefined;
    selected = recovering ? undefined : inspectVaultSelection(directory);
  } catch (error) { throw translate(error); }
  if (!recovering && ((input.operation === "migrate") !== (selected!.format === "legacy"))) throw new HttpError(409, "保管庫の形式に対応する操作を選択してください");
  if (hint?.mode === "reset" && input.confirmation !== "RESET_ALL_DATA") throw new HttpError(400, "空の保管庫への切り替え確認が必要です");
  if (hint?.mode !== "reset" && recovering && input.confirmation !== undefined) throw new HttpError(400, "復旧内容に対応しない確認項目です");
  const owner = new VaultSession(), abort = new AbortController();
  const credentials = { masterPassword: input.masterPassword, newMasterPassword: input.newMasterPassword, backupPassphrase: input.backupPassphrase };
  const confirmed = { ...credentials, confirmNewMasterPassword: input.confirmNewMasterPassword };
  const replacement = { ...confirmed, ...(input.confirmation ? { confirmation: input.confirmation } : {}) };
  let original: Buffer | undefined, closing = true, ignoredOwnLock = false;
  if (!recovering) {
    assertVaultStorage();
    if (getVaultDataDirectory() !== directory) throw new HttpError(409, "保管庫の接続が変更されました");
    vaultSession.requireUnlocked(generation); original = Buffer.from(vaultSession.requireKey()); owner.unlock(original); original.fill(0);
  }
  busy = true;
  const unsubscribe = vaultSession.subscribe(state => {
    if (closing && !ignoredOwnLock && !state.isUnlocked) { ignoredOwnLock = true; return; }
    abort.abort(); owner.lock(state.lockReason);
  });
  const cancel = () => { abort.abort(); owner.lock(); };
  options.signal?.addEventListener("abort", cancel, { once: true });
  const active = () => {
    if (abort.signal.aborted || stopping) throw new HttpError(409, "保管庫の切り替えは取り消されました");
    if (hasVaultStorage()) throw new HttpError(409, "保管庫の接続が変更されました");
  };
  let release!: () => void; pending = new Promise(resolve => { release = resolve; });
  try {
    closeVaultStorage(); closing = false; active();
    publish({ state: "running", format: selected?.format ?? "unknown", operation: input.operation });
    const legacy = selected?.format === "legacy" || hint?.kind === "legacy";
    if (legacy) await vaultUnlockGuard.run(async () => {
      try {
        const key = await authenticateSource(directory, input, active);
        try {
          if (recovering) owner.unlock(key);
          else if (!key.equals(owner.requireKey())) throw new HttpError(401, "保管庫の認証に失敗しました");
        } finally { key.fill(0); }
        active(); const authorization = { session: owner, sessionId: owner.requireUnlocked() };
        if (hint?.kind === "legacy") await recoverVaultActivation(directory, hint.target, credentials, authorization, { signal: abort.signal });
        else {
          const parent = safePath(directory, ["vaults"], true, true); if (!present(parent)) mkdirSync(parent, { mode: 0o700 });
          const staged = await stageLegacyVault(safePath(directory, ["password-manager.db"]), safePath(directory, ["vaults"], true), confirmed, { signal: abort.signal });
          active(); await activateStagedVault(directory, { vaultId: staged.vaultId, keyId: staged.keyId, slotRevision: 1 }, credentials, authorization, { signal: abort.signal });
        }
      } catch (error) { throw translate(error); }
    });
    else if (hint?.kind === "v2") {
      const key = await vaultUnlockGuard.run(() => authenticateSource(directory, input, active, hint.source, abort.signal));
      try { active(); owner.unlock(key); } finally { key.fill(0); }
      await recoverV2Replacement(directory, { source: hint.source, target: hint.target, mode: hint.mode }, { ...replacement, mode: hint.mode },
        { session: owner, sessionId: owner.requireUnlocked() }, { signal: abort.signal });
    } else if (selected?.format === "v2") {
      await replaceV2Vault(directory, selected.context, { ...replacement, mode: input.operation as "rekey" | "reset" },
        { session: owner, sessionId: owner.requireUnlocked() }, { signal: abort.signal });
    }
  } catch (error) { throw translate(error); }
  finally {
    unsubscribe(); options.signal?.removeEventListener("abort", cancel); owner.lock(); original?.fill(0); closing = false;
    try {
      if (stopping) { configuration = undefined; publish(undefined); }
      else if (!hasVaultStorage()) {
        try {
          const after = inspectVaultSelection(directory);
          if ((selected?.format === "v2" || hint !== undefined) && after.format === "legacy") throw new Error("selection missing");
          openVaultStorage({ ...configuration, createIfMissing: false }); publish({ state: "ready", format: isV2Vault() ? "v2" : "legacy" });
        }
        catch {
          let recoveryOperation: VaultMaintenanceState["recoveryOperation"];
          try { recoveryOperation = recovery(directory).mode; } catch { /* No guessed recovery target. */ }
          publish({ state: "recovery-required", format: "unknown", operation: "recover", ...(recoveryOperation ? { recoveryOperation } : {}) });
        }
      } else publish({ state: "recovery-required", format: "unknown", operation: "recover" });
    } finally { busy = false; release(); pending = undefined; }
  }
}
