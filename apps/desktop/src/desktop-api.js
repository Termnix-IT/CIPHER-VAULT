// Stands in for apps/electron/src/preload.ts, so apps/web runs unchanged.
// Each method moves to a native command as the services are ported; until then it is refused.
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
  const notPorted = async () => { throw new Error("この版では保管庫をまだ開けません。現行のアプリを使ってください"); };
  const noSubscription = () => () => undefined;
  const api = {
    fetchVaultStatus: () => call("vault_status"),
    onVaultState: noSubscription,
    onUpdateState: noSubscription,
    getUpdateState: async () => ({ status: "unsupported", currentVersion: "" }),
    recordVaultActivity: notPorted, setupVault: notPorted, unlockVault: notPorted, lockVault: notPorted, resetVault: notPorted,
    runVaultMaintenance: notPorted, exportBackup: notPorted, restoreBackup: notPorted, auditVault: notPorted,
    fetchEntries: notPorted, fetchEntry: notPorted, createEntry: notPorted, updateEntry: notPorted, deleteEntry: notPorted,
    setEntriesGroup: notPorted, generatePassword: notPorted, copyText: notPorted,
    checkForUpdates: notPorted, downloadUpdate: notPorted, installUpdate: notPorted, openReleasePage: notPorted
  };
  Object.defineProperty(window, "passwordManager", { value: Object.freeze(api) });
})();
