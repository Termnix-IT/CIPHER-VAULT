import { realpathSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Session } from "electron";
import { localDevelopmentUrl, rendererContentSecurityPolicy } from "@password-manager/shared";

export function isAllowedRendererResource(value: string, resourceType: string, documentUrl: string | null, webRoot: string) {
  if (!documentUrl) return false;
  try {
    const url = new URL(value), document = new URL(documentUrl);
    if (url.username || url.password) return false;
    if (url.protocol === "blob:") return ["other", "mainFrame"].includes(resourceType);
    if (url.protocol === "data:") return resourceType === "image";
    if (document.protocol === "file:") {
      if (url.protocol !== "file:" || !["mainFrame", "script", "stylesheet", "font", "image"].includes(resourceType)) return false;
      if (url.hostname) return false; // Never probe UNC/network paths from a renderer URL.
      const candidate = fileURLToPath(url);
      const lexical = path.relative(path.resolve(webRoot), candidate);
      if (lexical === ".." || lexical.startsWith(`..${path.sep}`) || path.isAbsolute(lexical)) return false;
      const target = realpathSync(candidate);
      const relative = path.relative(realpathSync(webRoot), target);
      return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative) && statSync(target).isFile();
    }
    const development = localDevelopmentUrl(documentUrl);
    if (url.origin === development.origin) return true;
    development.protocol = development.protocol === "https:" ? "wss:" : "ws:";
    return resourceType === "webSocket" && url.origin === development.origin;
  } catch { return false; }
}

export function installRendererSessionSecurity(
  session: Pick<Session, "setPermissionCheckHandler" | "setPermissionRequestHandler" | "setDevicePermissionHandler" | "webRequest">,
  windowId: () => number | null, documentUrl: () => string | null, webRoot: string
) {
  // Renderer clipboard APIs are unnecessary: the validated main-process API owns copying.
  session.setPermissionCheckHandler(() => false);
  session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.setDevicePermissionHandler(() => false);
  session.webRequest.onBeforeRequest({ urls: ["<all_urls>"] }, (details, callback) => {
    // Main-process updater traffic has no renderer id and uses a separate session.
    if (!details.webContentsId) { callback({}); return; }
    callback({ cancel: details.webContentsId !== windowId() ||
      !isAllowedRendererResource(details.url, details.resourceType, documentUrl(), webRoot) });
  });
  session.webRequest.onHeadersReceived({ urls: ["<all_urls>"] }, (details, callback) => {
    if (details.webContentsId !== windowId() || details.resourceType !== "mainFrame") { callback({}); return; }
    const target = documentUrl();
    if (!target) { callback({}); return; }
    const mode = new URL(target).protocol === "file:" ? "desktop" : "development";
    const headers = Object.fromEntries(Object.entries(details.responseHeaders ?? {}).filter(([key]) => key.toLowerCase() !== "content-security-policy"));
    headers["Content-Security-Policy"] = [rendererContentSecurityPolicy(mode, target) + "; frame-ancestors 'none'"];
    callback({ responseHeaders: headers });
  });
}
