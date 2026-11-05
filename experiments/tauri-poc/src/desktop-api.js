// Stands in for apps/electron/src/preload.ts, so apps/web runs unchanged.
(() => {
  const isWellFormed = (value) => {
    if (typeof value === "string") return value.isWellFormed();
    if (Array.isArray(value)) return value.every(isWellFormed);
    if (value === null || typeof value !== "object") return true;
    return Object.entries(value).every(([key, item]) => key.isWellFormed() && isWellFormed(item));
  };
  const call = async (command, args) => {
    // Tauri's IPC drops a request it cannot decode without answering, which would leave the screen waiting.
    if (!isWellFormed(args)) throw new Error("入力に使えない文字が含まれています");
    try {
      return await window.__TAURI_INTERNALS__.invoke(command, args);
    } catch (error) {
      throw new Error(typeof error === "string" ? error : "処理に失敗しました");
    }
  };
  const unsupported = async () => { throw new Error("この試作版では未対応です"); };
  const noSubscription = () => () => undefined;
  const api = {
    // The UI polls the status every second, so state events are not needed for this prototype.
    fetchVaultStatus: () => call("vault_status"),
    onVaultState: noSubscription,
    unlockVault: (payload, sessionId) => call("vault_unlock", { sessionId, payload }),
    lockVault: (sessionId) => call("vault_lock", { sessionId }),
    recordVaultActivity: (sessionId) => call("vault_activity", { sessionId }),
    fetchEntries: (sessionId) => call("entries_list", { sessionId }),
    fetchEntry: (id, sessionId) => call("entries_get", { sessionId, id }),
    getUpdateState: async () => ({ status: "unsupported", currentVersion: "0.0.0" }),
    onUpdateState: noSubscription,
    checkForUpdates: unsupported, downloadUpdate: unsupported, installUpdate: unsupported, openReleasePage: unsupported,
    setupVault: unsupported, resetVault: unsupported, runVaultMaintenance: unsupported,
    exportBackup: unsupported, restoreBackup: unsupported, auditVault: unsupported,
    // The native side refuses these unless the prototype was started in write mode.
    createEntry: (payload, sessionId) => call("entries_create", { sessionId, payload }),
    updateEntry: (id, payload, sessionId) => call("entries_update", { sessionId, id, payload }),
    deleteEntry: (id, sessionId) => call("entries_delete", { sessionId, id }),
    setEntriesGroup: (payload, sessionId) => call("entries_set_group", { sessionId, payload }),
    generatePassword: (options = {}, sessionId) => call("password_generate", { sessionId, options }),
    copyText: (value, sessionId) => call("clipboard_write", { sessionId, value })
  };
  Object.defineProperty(window, "passwordManager", { value: Object.freeze(api) });
})();
