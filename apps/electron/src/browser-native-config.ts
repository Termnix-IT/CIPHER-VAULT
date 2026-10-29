import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { BROWSER_EXTENSION_ORIGIN } from "@password-manager/shared/browser-integration";
import { BrowserConnectionError } from "./browser-message.js";
import { readLocalPublicFile, localPublicPath } from "./local-public-files.js";

export type BrowserNativeConfig = Readonly<{ version: 1; browser: "chrome" | "edge"; extensionOrigin: string; applicationExecutable: string; applicationEntry: string | null }>;
export function readBrowserNativeConfig(file: string) {
  try {
    if (path.basename(file) !== "host-config.json") throw new BrowserConnectionError();
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(readLocalPublicFile(file))) as BrowserNativeConfig;
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "applicationEntry,applicationExecutable,browser,extensionOrigin,version" ||
        value.version !== 1 || !["chrome", "edge"].includes(value.browser) || value.extensionOrigin !== BROWSER_EXTENSION_ORIGIN) throw new BrowserConnectionError();
    for (const candidate of [value.applicationExecutable, ...(value.applicationEntry === null ? [] : [value.applicationEntry])]) {
      localPublicPath(candidate); const info = lstatSync(candidate);
      if (!info.isFile() || info.isSymbolicLink() || realpathSync(candidate) !== candidate) throw new BrowserConnectionError();
    }
    const directory = path.dirname(file), info = lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(directory) !== directory ||
        (process.platform !== "win32" && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw new BrowserConnectionError();
    return Object.freeze({ config: Object.freeze({ ...value }), profile: path.join(directory, "client-profile") });
  } catch { throw new BrowserConnectionError(); }
}
