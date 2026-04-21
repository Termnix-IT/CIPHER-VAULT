import { contextBridge, ipcRenderer } from "electron";
import type {
  PasswordGenerationOptions,
  PasswordManagerDesktopApi,
  PasswordEntryUpsertPayload,
  VaultSetupPayload,
  VaultUnlockPayload
} from "@password-manager/shared/types";

const passwordManagerApi: PasswordManagerDesktopApi = {
  fetchVaultStatus: () => ipcRenderer.invoke("vault:getStatus"),
  setupVault: (payload: VaultSetupPayload) => ipcRenderer.invoke("vault:setup", payload),
  unlockVault: (payload: VaultUnlockPayload) => ipcRenderer.invoke("vault:unlock", payload),
  lockVault: () => ipcRenderer.invoke("vault:lock"),
  fetchEntries: () => ipcRenderer.invoke("entries:list"),
  fetchEntry: (id: string) => ipcRenderer.invoke("entries:getById", id),
  createEntry: (payload: PasswordEntryUpsertPayload) => ipcRenderer.invoke("entries:create", payload),
  updateEntry: (id: string, payload: PasswordEntryUpsertPayload) => ipcRenderer.invoke("entries:update", id, payload),
  deleteEntry: (id: string) => ipcRenderer.invoke("entries:delete", id),
  generatePassword: (options: PasswordGenerationOptions = {}) => ipcRenderer.invoke("password:generate", options),
  copyText: (value: string) => ipcRenderer.invoke("clipboard:writeText", value)
};

contextBridge.exposeInMainWorld("passwordManager", passwordManagerApi);
