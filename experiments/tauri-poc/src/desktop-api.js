// Stands in for apps/electron/src/preload.ts, so apps/web runs unchanged.
(() => {
  const call = async (command, args) => {
    try {
      return await window.__TAURI_INTERNALS__.invoke(command, args);
    } catch (error) {
      throw new Error(typeof error === "string" ? error : "処理に失敗しました");
    }
  };
  const readOnly = async () => { throw new Error("この試作版は読取専用です"); };
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
    checkForUpdates: readOnly, downloadUpdate: readOnly, installUpdate: readOnly, openReleasePage: readOnly,
    setupVault: readOnly, resetVault: readOnly, runVaultMaintenance: readOnly,
    createEntry: readOnly, updateEntry: readOnly, deleteEntry: readOnly, setEntriesGroup: readOnly,
    exportBackup: readOnly, restoreBackup: readOnly, auditVault: readOnly,
    generatePassword: readOnly, copyText: readOnly
  };
  Object.defineProperty(window, "passwordManager", { value: Object.freeze(api) });
})();
