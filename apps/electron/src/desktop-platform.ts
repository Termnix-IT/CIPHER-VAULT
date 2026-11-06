import path from "node:path";

export function supportsScreenLockEvents(platform: string) {
  return platform === "win32" || platform === "darwin";
}

export function desktopPlatformCapabilities(options: { platform: string; packaged: boolean; portable: boolean }) {
  return Object.freeze({
    operatingSystem: options.platform === "win32" ? "windows" : options.platform === "darwin" ? "macos" : options.platform === "linux" ? "linux" : "unsupported",
    screenLockEvents: supportsScreenLockEvents(options.platform),
    keepAliveAfterLastWindow: options.platform === "darwin",
    // The Electron app is being replaced by the Tauri app (docs/設計.md#rust版への移行). Its last
    // release updates nothing itself and sends every user to the releases page for the new setup,
    // which removes the Electron app and keeps the vault.
    inAppUpdates: false
  });
}

export function desktopVaultDataDirectory(host: { isReady: () => boolean; getPath: (name: "userData") => string }) {
  if (!host.isReady()) throw new Error("Desktop storage requires Electron readiness");
  const userData = host.getPath("userData");
  if (!path.isAbsolute(userData)) throw new Error("Desktop storage requires an absolute userData directory");
  // Keep the existing application identity and portable profile location.
  return path.join(userData, "data");
}
