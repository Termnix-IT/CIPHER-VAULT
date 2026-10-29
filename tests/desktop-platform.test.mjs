import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { tmpdir } from "node:os";
import { desktopPlatformCapabilities, desktopVaultDataDirectory, probeDeviceProtectionCapability } from "../apps/electron/dist/apps/electron/src/desktop-platform.js";

test("only packaged Windows setup enables in-app updates; macOS alone stays alive after closing windows", () => {
  const cases = [
    ["win32", true, false, "windows", true, false, true],
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

test("device protection diagnostics never initialize a key provider before app readiness", async () => {
  let calls = 0;
  const result = await probeDeviceProtectionCapability({ isReady: () => false }, { isAsyncEncryptionAvailable: async () => { calls++; return true; } });
  assert.deepEqual(result, { availability: "not-ready", protection: "unverified", deviceUnlockEnabled: false });
  assert.equal(calls, 0);
});

test("API availability never attests OS protection or enables device unlock, and failures expose no native error", async () => {
  for (const [check, expected] of [[async () => true, "available"], [async () => false, "unavailable"],
    [async () => { throw new Error("synthetic-native-private-detail"); }, "probe-failed"]]) {
    const storage = new Proxy({}, { get(_target, property) { assert.equal(property, "isAsyncEncryptionAvailable"); return check; } });
    const result = await probeDeviceProtectionCapability({ isReady: () => true }, storage);
    assert.deepEqual(result, { availability: expected, protection: "unverified", deviceUnlockEnabled: false });
    assert.equal(Object.isFrozen(result), true);
    assert.equal(JSON.stringify(result).includes("synthetic-native-private-detail"), false);
  }
});

test("an unresponsive native probe is bounded and a late result cannot upgrade its failed report", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let complete;
  const pending = probeDeviceProtectionCapability({ isReady: () => true }, { isAsyncEncryptionAvailable: () => new Promise(resolve => { complete = resolve; }) });
  t.mock.timers.tick(2000);
  const result = await pending;
  assert.equal(result.availability, "probe-failed");
  complete(true); await Promise.resolve();
  assert.deepEqual(result, { availability: "probe-failed", protection: "unverified", deviceUnlockEnabled: false });
});
