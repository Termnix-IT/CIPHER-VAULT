import { app, dialog } from "electron";

// Do not top-level-await app.whenReady indirectly: Electron's default loader waits for this module.
void import("./desktop-main.js").catch(() => {
  void app.whenReady().then(() => { dialog.showErrorBox("CIPHER VAULT", "アプリを起動できませんでした"); app.exit(1); });
});
