import type { BrowserWindow, IpcMainInvokeEvent } from "electron";
import { fileURLToPath, pathToFileURL } from "node:url";

export function isTrustedRendererUrl(candidate: string, expected: string | null) {
  if (!expected) return false;
  try {
    const actualUrl = new URL(candidate);
    const expectedUrl = new URL(expected);
    if (!["http:", "https:", "file:"].includes(actualUrl.protocol) || actualUrl.username || actualUrl.password) return false;
    actualUrl.hash = "";
    expectedUrl.hash = "";
    if (actualUrl.protocol === "file:" && expectedUrl.protocol === "file:") {
      // Chromium and Node may encode the same path differently (for example ~ / %7E).
      actualUrl.pathname = pathToFileURL(fileURLToPath(actualUrl)).pathname;
      expectedUrl.pathname = pathToFileURL(fileURLToPath(expectedUrl)).pathname;
    }
    return actualUrl.href === expectedUrl.href;
  } catch {
    return false;
  }
}

export function createSenderGuard(getWindow: () => BrowserWindow | null, getTrustedUrl: () => string | null) {
  return (event: IpcMainInvokeEvent) => {
    const window = getWindow();
    // Check both identity and URL: the same WebContents can navigate to an untrusted page.
    if (!window || window.isDestroyed() || event.sender !== window.webContents ||
        event.senderFrame !== window.webContents.mainFrame || !event.senderFrame ||
        !isTrustedRendererUrl(event.senderFrame.url, getTrustedUrl()) ||
        !isTrustedRendererUrl(window.webContents.getURL(), getTrustedUrl())) {
      throw new Error("Invalid IPC request");
    }
  };
}
