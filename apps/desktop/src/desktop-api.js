// Stands in for apps/electron/src/preload.ts, so apps/web runs unchanged.
// Each method moves to a native command as the services are ported; until then it is refused.
// The arguments keep the preload's order and reach the commands by name.
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
  const notPorted = async () => { throw new Error("この機能はこの版ではまだ使えません。現行のアプリを使ってください"); };
  const noSubscription = () => () => undefined;
  // The screen polls the status every second, so the lock reaches it without a pushed event.
  const api = {
    fetchVaultStatus: () => call("vault_status"),
    onVaultState: noSubscription,
    onUpdateState: noSubscription,
    getUpdateState: async () => ({ status: "unsupported", currentVersion: "" }),
    recordVaultActivity: (sessionId) => call("vault_activity", { sessionId }),
    setupVault: (payload, sessionId) => call("vault_setup", { sessionId, payload }),
    unlockVault: (payload, sessionId) => call("vault_unlock", { sessionId, payload }),
    lockVault: (sessionId) => call("vault_lock", { sessionId }),
    resetVault: (payload, sessionId) => call("vault_reset", { sessionId, payload }),
    fetchEntries: (sessionId) => call("entries_list", { sessionId }),
    fetchEntry: (id, sessionId) => call("entries_get", { sessionId, id }),
    createEntry: (payload, sessionId) => call("entries_create", { sessionId, payload }),
    updateEntry: (id, payload, sessionId) => call("entries_update", { sessionId, id, payload }),
    deleteEntry: (id, sessionId) => call("entries_delete", { sessionId, id }),
    setEntriesGroup: (payload, sessionId) => call("entries_set_group", { sessionId, payload }),
    generatePassword: (options, sessionId) => call("password_generate", { sessionId, options }),
    exportBackup: (payload, sessionId) => call("backup_export", { sessionId, payload }),
    restoreBackup: (payload, sessionId) => call("backup_restore", { sessionId, payload }),
    auditVault: (sessionId) => call("vault_audit", { sessionId }),
    runVaultMaintenance: (payload, sessionId) => call("vault_maintenance", { sessionId, payload }),
    copyText: (value, sessionId) => call("clipboard_write", { sessionId, value }),
    checkForUpdates: notPorted, downloadUpdate: notPorted, installUpdate: notPorted, openReleasePage: notPorted
  };
  Object.defineProperty(window, "passwordManager", { value: Object.freeze(api) });
})();
