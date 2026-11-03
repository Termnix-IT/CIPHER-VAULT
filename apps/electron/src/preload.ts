import { contextBridge, ipcRenderer } from "electron";
import type {
  PasswordGenerationOptions,
  PasswordManagerDesktopApi,
  VaultEntryUpsertPayload,
  VaultResetPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";

// Electron prepends the channel name to every rejection; the UI shows only the handler's own message.
const IPC_ERROR_PREFIX = /^Error invoking remote method '[^']*': (?:Error: )?/;

async function invoke(channel: string, ...args: unknown[]) {
  try {
    return await ipcRenderer.invoke(channel, ...args);
  } catch (error) {
    throw new Error(error instanceof Error ? error.message.replace(IPC_ERROR_PREFIX, "") : "処理に失敗しました");
  }
}

const passwordManagerApi: PasswordManagerDesktopApi = {
  runVaultMaintenance: (payload, sessionId) => invoke("vault:maintenance", sessionId, payload),
  exportBackup: (payload, sessionId) => invoke("backup:export", sessionId, payload),
  restoreBackup: (payload, sessionId) => invoke("backup:restore", sessionId, payload),
  auditVault: (sessionId) => invoke("vault:audit", sessionId),
  getUpdateState: () => invoke("updates:state"),
  checkForUpdates: () => invoke("updates:check"),
  downloadUpdate: () => invoke("updates:download"),
  installUpdate: (hasUnsavedChanges) => invoke("updates:install", hasUnsavedChanges),
  openReleasePage: () => invoke("updates:releases"),
  onUpdateState: (listener) => {
    const handler = (_event: Electron.IpcRendererEvent, state: import("@password-manager/shared/types").AppUpdateState) => listener(state);
    ipcRenderer.on("updates:state", handler);
    return () => ipcRenderer.removeListener("updates:state", handler);
  },
  fetchVaultStatus: () => invoke("vault:getStatus"),
  onVaultState: (listener) => {
    const handler = (_event: Electron.IpcRendererEvent, state: import("@password-manager/shared/types").VaultStatus) => listener(state);
    ipcRenderer.on("vault:state", handler);
    return () => { ipcRenderer.removeListener("vault:state", handler); };
  },
  recordVaultActivity: (sessionId) => invoke("vault:activity", sessionId),
  setupVault: (payload: VaultSetupPayload, sessionId) => invoke("vault:setup", sessionId, payload),
  unlockVault: (payload: VaultUnlockPayload, sessionId) => invoke("vault:unlock", sessionId, payload),
  lockVault: (sessionId) => invoke("vault:lock", sessionId),
  resetVault: (payload: VaultResetPayload, sessionId) => invoke("vault:reset", sessionId, payload),
  fetchEntries: (sessionId) => invoke("entries:list", sessionId),
  fetchEntry: (id: string, sessionId) => invoke("entries:getById", sessionId, id),
  createEntry: (payload: VaultEntryUpsertPayload, sessionId) => invoke("entries:create", sessionId, payload),
  updateEntry: (id: string, payload: VaultEntryUpsertPayload, sessionId) => invoke("entries:update", sessionId, id, payload),
  deleteEntry: (id: string, sessionId) => invoke("entries:delete", sessionId, id),
  generatePassword: (options: PasswordGenerationOptions, sessionId) => invoke("password:generate", sessionId, options),
  copyText: (value: string, sessionId) => invoke("clipboard:writeText", sessionId, value)
};

contextBridge.exposeInMainWorld("passwordManager", passwordManagerApi);
