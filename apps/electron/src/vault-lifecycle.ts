import type { BrowserWindow } from "electron";
import type { VaultLockReason } from "@password-manager/shared/types";

export function attachVaultWindowLifecycle(window: BrowserWindow, lock: (reason: VaultLockReason) => void) {
  window.on("closed", () => lock("window-closed"));
  window.webContents.on("render-process-gone", () => lock("renderer-gone"));
}
