import { app, dialog } from "electron";
import { BROWSER_NATIVE_SWITCH } from "@password-manager/shared/browser-integration";

// Dispatch before importing Vault services or constructing the normal application. Even a malformed
// client invocation must fail in that role, never fall back to the Vault window or its database.
const nativeHost = app.commandLine.hasSwitch(BROWSER_NATIVE_SWITCH) ||
  process.argv.some(value => value === `--${BROWSER_NATIVE_SWITCH}` || value.startsWith(`--${BROWSER_NATIVE_SWITCH}=`));
// Do not top-level-await app.whenReady indirectly: Electron's default loader waits for this module.
void import(nativeHost ? "./native-host-main.js" : "./desktop-main.js").catch(() => {
  if (nativeHost) app.exit(1);
  else void app.whenReady().then(() => { dialog.showErrorBox("CIPHER VAULT", "アプリを起動できませんでした"); app.exit(1); });
});
