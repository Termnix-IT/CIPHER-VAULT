import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";
import electronUpdater from "electron-updater";
import { ManualUpdater } from "./manual-updater.js";

const RELEASE_PAGE = "https://github.com/Termnix-IT/CIPHER-VAULT/releases/latest";

export function registerUpdateHandlers(getWindow: () => BrowserWindow | null, lockVault: () => void, version: string) {
  const { autoUpdater } = electronUpdater;
  const controller = new ManualUpdater(autoUpdater, version,
    app.isPackaged && process.platform === "win32" && !process.env.PORTABLE_EXECUTABLE_FILE,
    (state) => {
      const window = getWindow();
      if (window && !window.isDestroyed()) window.webContents.send("updates:state", state);
    });
  const assertSender = (event: Electron.IpcMainInvokeEvent) => {
    const window = getWindow();
    if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame) {
      throw new Error("Invalid update request");
    }
  };
  ipcMain.handle("updates:state", (event) => { assertSender(event); return controller.getState(); });
  ipcMain.handle("updates:check", (event) => { assertSender(event); return controller.check(); });
  ipcMain.handle("updates:download", (event) => { assertSender(event); return controller.download(); });
  ipcMain.handle("updates:releases", (event) => { assertSender(event); return shell.openExternal(RELEASE_PAGE); });
  ipcMain.handle("updates:install", (event, hasUnsavedChanges: unknown) => {
    assertSender(event);
    if (typeof hasUnsavedChanges !== "boolean") throw new Error("Invalid update request");
    return controller.install(async () => {
      const window = getWindow();
      if (!window) return false;
      if (hasUnsavedChanges) {
        const result = await dialog.showMessageBox(window, {
          type: "warning", title: "未保存の編集があります",
          message: "編集内容を破棄して更新しますか？",
          detail: "保存する場合は「編集に戻る」を選び、保存後にもう一度更新してください。",
          buttons: ["編集に戻る", "破棄して更新"], defaultId: 0, cancelId: 0, noLink: true,
        });
        if (result.response !== 1) return false;
      }
      lockVault();
      return true;
    });
  });
}
