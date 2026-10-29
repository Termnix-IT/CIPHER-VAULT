import { contextBridge, ipcRenderer } from "electron";
import type {
  PasswordGenerationOptions,
  PasswordManagerDesktopApi,
  PasswordEntryUpsertPayload,
  VaultResetPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";

const passwordManagerApi: PasswordManagerDesktopApi = {
  getLocalConnections: (id) => ipcRenderer.invoke("connections:state", id),
  setLocalConnectionsEnabled: (enabled, revision, id) => ipcRenderer.invoke("connections:enabled", id, enabled, revision),
  selectLocalPairingRequest: (id) => ipcRenderer.invoke("connections:select", id),
  approveLocalPairing: (approval, id) => ipcRenderer.invoke("connections:approve", id, approval),
  cancelLocalPairing: (pendingId, id) => ipcRenderer.invoke("connections:cancel", id, pendingId),
  revokeLocalClient: (clientId, revision, id) => ipcRenderer.invoke("connections:revoke", id, clientId, revision),
  saveLocalConnectionInfo: (clientId, id) => ipcRenderer.invoke("connections:save", id, clientId),
  runVaultMaintenance: (payload, sessionId) => ipcRenderer.invoke("vault:maintenance", sessionId, payload),
  exportBackup: (payload, sessionId) => ipcRenderer.invoke("backup:export", sessionId, payload),
  restoreBackup: (payload, sessionId) => ipcRenderer.invoke("backup:restore", sessionId, payload),
  auditVault: (sessionId) => ipcRenderer.invoke("vault:audit", sessionId),
  getUpdateState: () => ipcRenderer.invoke("updates:state"),
  checkForUpdates: () => ipcRenderer.invoke("updates:check"),
  downloadUpdate: () => ipcRenderer.invoke("updates:download"),
  installUpdate: (hasUnsavedChanges) => ipcRenderer.invoke("updates:install", hasUnsavedChanges),
  openReleasePage: () => ipcRenderer.invoke("updates:releases"),
  onUpdateState: (listener) => {
    const handler = (_event: Electron.IpcRendererEvent, state: import("@password-manager/shared/types").AppUpdateState) => listener(state);
    ipcRenderer.on("updates:state", handler);
    return () => ipcRenderer.removeListener("updates:state", handler);
  },
  fetchVaultStatus: () => ipcRenderer.invoke("vault:getStatus"),
  onVaultState: (listener) => {
    const handler = (_event: Electron.IpcRendererEvent, state: import("@password-manager/shared/types").VaultStatus) => listener(state);
    ipcRenderer.on("vault:state", handler);
    return () => { ipcRenderer.removeListener("vault:state", handler); };
  },
  recordVaultActivity: (sessionId) => ipcRenderer.invoke("vault:activity", sessionId),
  setupVault: (payload: VaultSetupPayload, sessionId) => ipcRenderer.invoke("vault:setup", sessionId, payload),
  unlockVault: (payload: VaultUnlockPayload, sessionId) => ipcRenderer.invoke("vault:unlock", sessionId, payload),
  lockVault: (sessionId) => ipcRenderer.invoke("vault:lock", sessionId),
  resetVault: (payload: VaultResetPayload, sessionId) => ipcRenderer.invoke("vault:reset", sessionId, payload),
  fetchEntries: (sessionId) => ipcRenderer.invoke("entries:list", sessionId),
  fetchEntry: (id: string, sessionId) => ipcRenderer.invoke("entries:getById", sessionId, id),
  createEntry: (payload: PasswordEntryUpsertPayload, sessionId) => ipcRenderer.invoke("entries:create", sessionId, payload),
  updateEntry: (id: string, payload: PasswordEntryUpsertPayload, sessionId) => ipcRenderer.invoke("entries:update", sessionId, id, payload),
  deleteEntry: (id: string, sessionId) => ipcRenderer.invoke("entries:delete", sessionId, id),
  generatePassword: (options: PasswordGenerationOptions, sessionId) => ipcRenderer.invoke("password:generate", sessionId, options),
  copyText: (value: string, sessionId) => ipcRenderer.invoke("clipboard:writeText", sessionId, value)
};

contextBridge.exposeInMainWorld("passwordManager", passwordManagerApi);
