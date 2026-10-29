import path from "node:path";
import type { SafeStorage } from "electron";

export function supportsScreenLockEvents(platform: string) {
  return platform === "win32" || platform === "darwin";
}

export function desktopPlatformCapabilities(options: { platform: string; packaged: boolean; portable: boolean }) {
  return Object.freeze({
    operatingSystem: options.platform === "win32" ? "windows" : options.platform === "darwin" ? "macos" : options.platform === "linux" ? "linux" : "unsupported",
    screenLockEvents: supportsScreenLockEvents(options.platform),
    keepAliveAfterLastWindow: options.platform === "darwin",
    inAppUpdates: options.platform === "win32" && options.packaged && !options.portable
  });
}

export function desktopVaultDataDirectory(host: { isReady: () => boolean; getPath: (name: "userData") => string }) {
  if (!host.isReady()) throw new Error("Desktop storage requires Electron readiness");
  const userData = host.getPath("userData");
  if (!path.isAbsolute(userData)) throw new Error("Desktop storage requires an absolute userData directory");
  // Keep the existing application identity and portable profile location.
  return path.join(userData, "data");
}

export type DeviceProtectionCapability = Readonly<{
  availability: "not-ready" | "available" | "unavailable" | "probe-failed";
  protection: "unverified";
  deviceUnlockEnabled: false;
}>;

// Explicit diagnostic only: initialization can contact an OS key store. Never
// probe during startup, and never treat API availability as backend attestation.
export async function probeDeviceProtectionCapability(host: { isReady: () => boolean },
  storage: Pick<SafeStorage, "isAsyncEncryptionAvailable">): Promise<DeviceProtectionCapability> {
  const result = (availability: DeviceProtectionCapability["availability"]): DeviceProtectionCapability =>
    Object.freeze({ availability, protection: "unverified", deviceUnlockEnabled: false });
  if (!host.isReady()) return result("not-ready");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const available = await Promise.race([
      storage.isAsyncEncryptionAvailable(),
      new Promise<null>(resolve => { timer = setTimeout(() => resolve(null), 2000); })
    ]);
    return result(available === true ? "available" : available === false ? "unavailable" : "probe-failed");
  } catch { return result("probe-failed"); }
  finally { clearTimeout(timer); }
}
