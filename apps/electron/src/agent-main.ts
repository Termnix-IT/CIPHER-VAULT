import { app, dialog, safeStorage } from "electron";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BrowserClient } from "./browser-client.js";
import { readBrowserNativeFrame } from "./browser-native-stdio.js";
import { BrowserMessageDecoder, BrowserConnectionError, encodeBrowserMessage } from "./browser-message.js";
import { candidateQuery, candidateResult } from "./candidate-search.js";
import { electronDeviceKeyProtector } from "./device-key-protector.js";
import { nativeTransportExecutable } from "./native-transport.js";

let client: BrowserClient | undefined;
const exit = (code: number) => { client?.close(); app.exit(code); };
const timer = setTimeout(() => exit(1), 120000);
process.stdout.on("error", () => exit(1));
process.on("uncaughtException", () => exit(1)); process.on("unhandledRejection", () => exit(1));
app.disableHardwareAcceleration(); app.on("window-all-closed", () => {});
try {
  const profile = app.commandLine.getSwitchValue("cipher-vault-agent");
  if (process.platform !== "win32" || app.commandLine.hasSwitch("cipher-vault-native-host") || !path.isAbsolute(profile) || path.resolve(profile) !== profile ||
      profile.startsWith("\\\\") || realpathSync(profile) !== profile || app.commandLine.getSwitchValue("user-data-dir") !== profile) throw new BrowserConnectionError();
  const info = lstatSync(profile); if (!info.isDirectory() || info.isSymbolicLink()) throw new BrowserConnectionError();
  app.setPath("userData", profile); app.setPath("sessionData", profile);
  if (!app.requestSingleInstanceLock()) throw new BrowserConnectionError();
  let root = path.dirname(fileURLToPath(import.meta.url));
  while (!existsSync(path.join(root, "apps/web"))) { const parent = path.dirname(root); if (root === parent) throw new BrowserConnectionError(); root = parent; }
  const executable = nativeTransportExecutable({ packaged: app.isPackaged, resourcesPath: process.resourcesPath, workspaceRoot: root });
  void app.whenReady().then(async () => {
    const value = new BrowserMessageDecoder().push(await readBrowserNativeFrame()) as Record<string, unknown>;
    if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== 1 || typeof value.id !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id) ||
        !["state", "pair", "import", "search"].includes(value.operation as string) ||
        Object.keys(value).sort().join(",") !== (value.operation === "search" ? "id,operation,query,version" : "id,operation,version")) throw new BrowserConnectionError();
    client = new BrowserClient(profile, executable, electronDeviceKeyProtector(app, safeStorage), "codex");
    let result: unknown, ok = true;
    try {
      switch (value.operation) {
        case "state": result = client.state(); break;
        case "pair": {
          const selected = await dialog.showSaveDialog({ title: "Codexの接続リクエストを保存", defaultPath: "cipher-vault-codex.cvpair", filters: [{ name: "接続リクエスト", extensions: ["cvpair"] }] });
          result = selected.canceled || !selected.filePath ? { ...client.state(), cancelled: true } : await client.preparePairing(selected.filePath); break;
        }
        case "import": {
          const selected = await dialog.showOpenDialog({ title: "アプリが保存した接続情報を選択", filters: [{ name: "接続情報", extensions: ["cvconnection"] }], properties: ["openFile", "dontAddToRecent"] });
          result = selected.canceled || selected.filePaths.length !== 1 ? { ...client.state(), cancelled: true } : await client.importConnection(selected.filePaths[0]); break;
        }
        case "search": result = { items: candidateResult(await client.searchCandidates(candidateQuery(value.query))) }; break;
      }
    } catch { ok = false; }
    await new Promise<void>((resolve, reject) => process.stdout.write(encodeBrowserMessage(ok ? { version: 1, id: value.id, ok: true, result } : { version: 1, id: value.id, ok: false, error: "UNAVAILABLE" }), error => error ? reject(error) : resolve()));
    clearTimeout(timer); exit(ok ? 0 : 1);
  }).catch(() => { clearTimeout(timer); exit(1); });
} catch { clearTimeout(timer); exit(1); }
