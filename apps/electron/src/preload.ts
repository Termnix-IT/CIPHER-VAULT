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
  setupVault: (payload: VaultSetupPayload) => ipcRenderer.invoke("vault:setup", payload),
  unlockVault: (payload: VaultUnlockPayload) => ipcRenderer.invoke("vault:unlock", payload),
  lockVault: () => ipcRenderer.invoke("vault:lock"),
  resetVault: (payload: VaultResetPayload) => ipcRenderer.invoke("vault:reset", payload),
  fetchEntries: () => ipcRenderer.invoke("entries:list"),
  fetchEntry: (id: string) => ipcRenderer.invoke("entries:getById", id),
  createEntry: (payload: PasswordEntryUpsertPayload) => ipcRenderer.invoke("entries:create", payload),
  updateEntry: (id: string, payload: PasswordEntryUpsertPayload) => ipcRenderer.invoke("entries:update", id, payload),
  deleteEntry: (id: string) => ipcRenderer.invoke("entries:delete", id),
  generatePassword: (options: PasswordGenerationOptions = {}) => ipcRenderer.invoke("password:generate", options),
  copyText: (value: string) => ipcRenderer.invoke("clipboard:writeText", value)
};

contextBridge.exposeInMainWorld("passwordManager", passwordManagerApi);
