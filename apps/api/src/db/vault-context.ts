import { existsSync, mkdirSync, statSync } from "node:fs";
import path from "node:path";
import { closeDatabase, getDatabase, getDatabasePath, hasOpenDatabase, openDatabase, resolveDataDirectory, VaultStorageError } from "./database.js";
import type { DatabaseOptions } from "./database.js";
import { openV2Store } from "./v2-store.js";
import { dataRoot, inspectVaultSelection, present, readPointer, readReceipt, safePath } from "../migration/active-pointer.js";
import { HttpError } from "../lib/errors.js";
import { vaultSession } from "../services/vault-session.js";

type V2Context = Readonly<{ format: "v2"; directory: string; database: string; store: ReturnType<typeof openV2Store>;
  expected: Readonly<{ vaultId: string; keyId: string; slotRevision: number }>; signal: AbortSignal; assertCurrent(): void }>;
type LegacyContext = Readonly<{ format: "legacy"; signal: AbortSignal; assertCurrent(): void }>;
let current: LegacyContext | V2Context | undefined;
let abort: AbortController | undefined;
let failed = false;

export function isV2Vault() { return current?.format === "v2"; }
export function hasVaultStorage() { return current !== undefined || hasOpenDatabase(); }
export function isVaultContextFailed() { return current !== undefined && failed; }
export function assertVaultStorage() { current?.assertCurrent(); }
export function getV2Vault(): V2Context | null {
  if (current?.format !== "v2") return null;
  current.assertCurrent(); return current;
}
export function failVaultContext(): never {
  const owner = current, controller = abort;
  failed = true; controller?.abort();
  if (current === owner) vaultSession.lock();
  throw new HttpError(503, "保管庫の検証に失敗しました。再起動して復旧を確認してください");
}
function assertLegacyNamespace(root: string) {
  if (present(safePath(root, ["vault-current.json"], false, true)) ||
      present(safePath(root, ["vault-activation.json"], false, true)) ||
      present(safePath(root, ["vault-transition.json"], false, true))) throw new VaultStorageError("OPEN_FAILED");
}

/** Startup owns one format; services never silently reopen or fall back to the legacy file. */
export function openVaultStorage(options: DatabaseOptions = {}) {
  if (current || hasOpenDatabase()) throw new VaultStorageError("ALREADY_OPEN");
  vaultSession.lock(); failed = false;
  const directory = options.dataDirectory ? path.resolve(options.dataDirectory) : resolveDataDirectory();
  if (!existsSync(directory)) {
    if (options.readonly || options.createIfMissing === false) throw new VaultStorageError("NOT_FOUND");
    mkdirSync(directory, { recursive: true });
  }
  const root = dataRoot(directory), selected = inspectVaultSelection(root);
  if (selected.format === "legacy") {
    // The callback runs after SQLite acquires the initialization transaction's lock.
    const database = openDatabase({ ...options, dataDirectory: root }, () => assertLegacyNamespace(root));
    const controller = new AbortController(); abort = controller;
    try {
      const identity = statSync(database.name);
      const context: LegacyContext = Object.freeze({ format: "legacy", signal: controller.signal,
        assertCurrent() {
          if (current !== context) throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
          if (failed || controller.signal.aborted || !database.open || !hasOpenDatabase() || getDatabase() !== database) return failVaultContext();
          try {
            assertLegacyNamespace(root);
            const stat = statSync(safePath(root, ["password-manager.db"]));
            if (stat.dev !== identity.dev || stat.ino !== identity.ino) throw new Error("context changed");
          } catch { return failVaultContext(); }
        }
      });
      current = context;
      database.pragma("temp_store = MEMORY");
      database.function("cipher_vault_storage_guard", () => { context.assertCurrent(); return null; });
      // Connection-local TEMP triggers check AFTER a waiting SQL writer acquires its lock.
      // No trigger or schema change is persisted to the legacy file.
      for (const table of ["vault_metadata", "password_entries"]) for (const operation of ["INSERT", "UPDATE", "DELETE"]) {
        database.exec(`CREATE TEMP TRIGGER cipher_guard_${table}_${operation} BEFORE ${operation} ON main.${table}
          BEGIN SELECT cipher_vault_storage_guard(); END`);
      }
      context.assertCurrent(); return;
    } catch (error) { controller.abort(); closeDatabase(); current = undefined; abort = undefined; throw error; }
  }
  const store = openV2Store(selected.database, selected.context, { writable: options.readonly !== true });
  let identity: ReturnType<typeof statSync>;
  try { identity = statSync(selected.database); } catch { store.close(); throw new VaultStorageError("OPEN_FAILED"); }
  const controller = new AbortController(); abort = controller;
  const context: V2Context = Object.freeze({ format: "v2", directory: root, database: selected.database, store,
    expected: selected.context, signal: controller.signal,
    assertCurrent() {
      if (current !== context) throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
      if (failed || controller.signal.aborted || store.closed) return failVaultContext();
      try {
        if (present(safePath(root, ["vault-transition.json"], false, true))) throw new Error("transition pending");
        const receipt = readReceipt(root), file = safePath(root, ["vaults", selected.context.vaultId, "vault.sqlite"]), stat = statSync(file);
        if (readPointer(root) !== selected.context.vaultId || receipt.state !== "committed" || receipt.vaultId !== selected.context.vaultId ||
            receipt.keyId !== selected.context.keyId || stat.dev !== identity.dev || stat.ino !== identity.ino) throw new Error("context changed");
      } catch { return failVaultContext(); }
    }
  });
  current = context;
  try { context.assertCurrent(); } catch (error) { store.close(); current = undefined; abort = undefined; throw error; }
}
export function closeVaultStorage() {
  vaultSession.lock(); abort?.abort();
  if (current?.format === "v2") current.store.close(); else closeDatabase();
  current = undefined; abort = undefined; failed = false;
}
export function getVaultStoragePath() { return current?.format === "v2" ? current.database : getDatabasePath(); }
