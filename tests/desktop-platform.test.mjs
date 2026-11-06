import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { tmpdir } from "node:os";
import { desktopPlatformCapabilities, desktopVaultDataDirectory } from "../apps/electron/dist/apps/electron/src/desktop-platform.js";

test("the last Electron release updates nothing in-app; macOS alone stays alive after closing windows", () => {
  const cases = [
    ["win32", true, false, "windows", true, false, false],
    ["win32", true, true, "windows", true, false, false],
    ["win32", false, false, "windows", true, false, false],
    ["win32", false, true, "windows", true, false, false],
    ["darwin", true, false, "macos", true, true, false],
    ["darwin", false, false, "macos", true, true, false],
    ["linux", true, false, "linux", false, false, false],
    ["linux", false, false, "linux", false, false, false],
    ["freebsd", true, false, "unsupported", false, false, false]
  ];
  for (const [platform, packaged, portable, operatingSystem, screenLockEvents, keepAliveAfterLastWindow, inAppUpdates] of cases) {
    const capability = desktopPlatformCapabilities({ platform, packaged, portable });
    assert.deepEqual(capability, { operatingSystem, screenLockEvents, keepAliveAfterLastWindow, inAppUpdates });
    assert.equal(Object.isFrozen(capability), true);
  }
});

test("desktop storage retains userData/data, requires readiness and never falls back to cwd", () => {
  let reads = 0;
  const userData = path.join(tmpdir(), "synthetic-profile"), host = {
    isReady: () => false, getPath: name => { reads++; assert.equal(name, "userData"); return userData; }
  };
  assert.throws(() => desktopVaultDataDirectory(host), /readiness/); assert.equal(reads, 0);
  host.isReady = () => true;
  assert.equal(desktopVaultDataDirectory(host), path.join(userData, "data"));
  host.getPath = () => "relative-profile";
  assert.throws(() => desktopVaultDataDirectory(host), /absolute/);
});
