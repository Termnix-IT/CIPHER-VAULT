// The screen API (window.passwordManager) that the Electron preload script used to provide, so apps/web runs unchanged.
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
  const noSubscription = () => () => undefined;
  // The screen polls the vault status every second, so the lock reaches it without a pushed event.
  // The update state is polled here for the same reason, and passed on only when it changes.
  const watchUpdates = (listener) => {
    let last = "";
    const timer = setInterval(() => {
      call("update_state").then((state) => {
        const key = JSON.stringify(state);
        if (key !== last) { last = key; listener(state); }
      }, () => undefined);
    }, 500);
    return () => clearInterval(timer);
  };
  const api = {
    fetchVaultStatus: () => call("vault_status"),
    onVaultState: noSubscription,
    onUpdateState: watchUpdates,
    getUpdateState: () => call("update_state"),
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
    fetchEntryIcons: (sessionId) => call("entry_icons_get", { sessionId }),
    setEntryIcon: (id, icon, sessionId) => call("entry_icon_set", { sessionId, id, icon }),
    generatePassword: (options, sessionId) => call("password_generate", { sessionId, options }),
    exportBackup: (payload, sessionId) => call("backup_export", { sessionId, payload }),
    restoreBackup: (payload, sessionId) => call("backup_restore", { sessionId, payload }),
    auditVault: (sessionId) => call("vault_audit", { sessionId }),
    runVaultMaintenance: (payload, sessionId) => call("vault_maintenance", { sessionId, payload }),
    copyText: (value, sessionId) => call("clipboard_write", { sessionId, value }),
    checkForUpdates: () => call("update_check"),
    downloadUpdate: () => call("update_download"),
    installUpdate: (hasUnsavedChanges) => call("update_install", { hasUnsavedChanges }),
    openReleasePage: () => call("update_open_releases"),
    // The title bar's buttons. They act on this window only and never reach the vault.
    minimizeWindow: () => call("plugin:window|minimize", { label: "main" }),
    toggleMaximizeWindow: () => call("plugin:window|toggle_maximize", { label: "main" }),
    closeWindow: () => call("plugin:window|close", { label: "main" }),
    isWindowMaximized: () => call("plugin:window|is_maximized", { label: "main" })
  };
  Object.defineProperty(window, "passwordManager", { value: Object.freeze(api) });
})();
