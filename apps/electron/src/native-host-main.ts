import { app, dialog, safeStorage } from "electron";
import { existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { PassThrough } from "node:stream";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BROWSER_NATIVE_SWITCH, BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { readBrowserNativeConfig } from "./browser-native-config.js";
import { BrowserConnectionError, runBrowserMessage } from "./browser-message.js";
import { BrowserClient } from "./browser-client.js";
import { electronDeviceKeyProtector } from "./device-key-protector.js";
import { nativeTransportExecutable } from "./native-transport.js";
import { readBrowserNativeFrame } from "./browser-native-stdio.js";

let client: BrowserClient | undefined;
process.stdout.on("error", () => { client?.close(); app.exit(1); });
process.stdin.on("error", () => { client?.close(); app.exit(1); });
const deadline = setTimeout(() => { client?.close(); app.exit(1); }, 130000);
app.disableHardwareAcceleration();
app.on("before-quit", () => client?.close());
app.on("window-all-closed", () => {});

try {
  const configFile = app.commandLine.getSwitchValue(BROWSER_NATIVE_SWITCH);
  const caller = app.commandLine.getSwitchValue("cipher-vault-caller-origin");
  const { config, profile } = readBrowserNativeConfig(configFile);
  const entry = fileURLToPath(new URL("./main.js", import.meta.url));
  if (caller !== BROWSER_EXTENSION_ORIGIN || realpathSync(process.execPath) !== config.applicationExecutable ||
      (app.isPackaged ? config.applicationEntry !== null : config.applicationEntry !== realpathSync(entry)) ||
      app.commandLine.getSwitchValue("user-data-dir") !== profile) throw new BrowserConnectionError();
  if (!existsSync(profile)) mkdirSync(profile, { mode: 0o700 });
  const info = lstatSync(profile);
  if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(profile) !== profile ||
      (process.platform !== "win32" && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw new BrowserConnectionError();
  app.setPath("userData", profile); app.setPath("sessionData", profile);
  if (!app.requestSingleInstanceLock()) throw new BrowserConnectionError();
  let workspaceRoot = path.dirname(entry);
  while (!existsSync(path.join(workspaceRoot, "apps/web"))) {
    const parent = path.dirname(workspaceRoot); if (parent === workspaceRoot) throw new BrowserConnectionError(); workspaceRoot = parent;
  }
  const executable = nativeTransportExecutable({ packaged: app.isPackaged, resourcesPath: process.resourcesPath, workspaceRoot });
  void app.whenReady().then(async () => {
    client = new BrowserClient(profile, executable, electronDeviceKeyProtector(app, safeStorage), config.browser);
    const frame = await readBrowserNativeFrame(), input = new PassThrough();
    const command = runBrowserMessage(input, process.stdout, async (request, signal) => {
      const active = () => { if (signal.aborted) throw new BrowserConnectionError(); };
      switch (request.operation) {
        case "get-state": return client!.state();
        case "prepare-pairing": {
          const result = await dialog.showSaveDialog({ title: "接続リクエストを保存", defaultPath: "cipher-vault-browser.cvpair", filters: [{ name: "接続リクエスト", extensions: ["cvpair"] }], properties: ["showOverwriteConfirmation"] });
          active(); if (result.canceled || !result.filePath) return { ...client!.state(), cancelled: true };
          return client!.preparePairing(result.filePath, signal);
        }
        case "import-connection": {
          const result = await dialog.showOpenDialog({ title: "接続情報を読み込む", filters: [{ name: "接続情報", extensions: ["cvconnection"] }], properties: ["openFile", "dontAddToRecent"] });
          active(); if (result.canceled || result.filePaths.length !== 1) return { ...client!.state(), cancelled: true };
          return client!.importConnection(result.filePaths[0], signal);
        }
        case "check-connection": return client!.checkConnection(signal);
        case "reset-pairing": {
          const result = await dialog.showMessageBox({ type: "warning", title: "ブラウザ接続を作り直す", message: "このブラウザの接続資格を作り直しますか？",
            detail: "現在の接続情報を解除します。以前の登録は、CIPHER VAULTの「接続の管理」でも取り消してください。保管庫の内容は変更しません。", buttons: ["キャンセル", "作り直す"], defaultId: 0, cancelId: 0, noLink: true });
          active(); if (result.response !== 1) return { ...client!.state(), cancelled: true };
          return client!.resetPairing(signal);
        }
      }
    });
    input.write(frame); await command; input.destroy();
  }).then(() => { clearTimeout(deadline); client?.close(); app.exit(0); }).catch(() => { clearTimeout(deadline); client?.close(); app.exit(1); });
} catch { clearTimeout(deadline); client?.close(); app.exit(1); }
