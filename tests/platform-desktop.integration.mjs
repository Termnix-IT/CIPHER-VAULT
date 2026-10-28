// Probe only a disposable profile. No vault key, password or real OS credential is supplied.
import { app, safeStorage } from "electron";
import assert from "node:assert/strict";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { desktopPlatformCapabilities, desktopVaultDataDirectory, probeDeviceProtectionCapability } from "../apps/electron/dist/apps/electron/src/desktop-platform.js";

const root = process.env.CIPHER_VAULT_TEST_ROOT, relative = path.relative(tmpdir(), root ?? "");
assert.ok(root && relative.startsWith("cipher-vault-desktop-session-") && !relative.includes(path.sep));
const profile = path.join(root, "platform-profile"); mkdirSync(profile); app.setPath("userData", profile);
const timeout = setTimeout(() => { console.error("FAIL platform capability timeout"); app.exit(1); }, 15000);
void app.whenReady().then(async () => {
  try {
    assert.equal(desktopVaultDataDirectory(app), path.join(profile, "data"));
    const capability = desktopPlatformCapabilities({ platform: process.platform, packaged: app.isPackaged, portable: Boolean(process.env.PORTABLE_EXECUTABLE_FILE) });
    assert.equal(capability.inAppUpdates, false);
    const device = await probeDeviceProtectionCapability(app, safeStorage);
    assert.ok(["available", "unavailable", "probe-failed"].includes(device.availability));
    assert.equal(device.protection, "unverified"); assert.equal(device.deviceUnlockEnabled, false);
    assert.equal(app.getPath("userData"), profile); assert.equal(existsSync(path.join(profile, "data")), false);
    console.log("PASS actual Electron data location and OS capability", capability.operatingSystem);
    console.log("PASS explicit async key-provider probe remains unverified with device unlock disabled", device.availability);
    clearTimeout(timeout); app.quit();
  } catch (error) { clearTimeout(timeout); console.error("FAIL platform capability", error); app.exit(1); }
});
