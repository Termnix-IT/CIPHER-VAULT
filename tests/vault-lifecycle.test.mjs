import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { attachVaultWindowLifecycle } from "../apps/electron/dist/apps/electron/src/vault-lifecycle.js";
import { VaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";
import { VaultPowerGuard } from "../apps/electron/dist/apps/electron/src/vault-power-guard.js";

test("closing the last window or losing its renderer destroys the key without waiting for app quit", () => {
  for (const event of ["closed", "render-process-gone"]) {
    const window = new EventEmitter(); window.webContents = new EventEmitter();
    const session = new VaultSession(); session.unlock(Buffer.alloc(32, 5));
    const key = session.requireKey();
    attachVaultWindowLifecycle(window, (reason) => session.lock(reason));
    (event === "closed" ? window : window.webContents).emit(event);
    assert.equal(session.getState().isUnlocked, false);
    assert.deepEqual(key, Buffer.alloc(32));
    assert.equal(session.getState().lockReason, event === "closed" ? "window-closed" : "renderer-gone");
    session.unlock(Buffer.alloc(32, 6));
    assert.equal(session.getState().isUnlocked, true);
    session.lock();
  }
});

test("OS lock/suspend/resume events destroy keys, block background access and never unlock automatically", () => {
  const monitor = new EventEmitter(); monitor.getSystemIdleState = () => "active";
  const session = new VaultSession();
  const guard = new VaultPowerGuard(monitor, (reason) => session.lock(reason), "win32");
  for (const [event, reason, blocked] of [["lock-screen", "screen-lock", true], ["unlock-screen", "screen-unlock", false], ["suspend", "suspend", true], ["resume", "resume", false]]) {
    session.unlock(Buffer.alloc(32, 7)); const key = session.requireKey();
    monitor.emit(event);
    assert.equal(session.getState().isUnlocked, false); assert.equal(session.getState().lockReason, reason);
    assert.deepEqual(key, Buffer.alloc(32));
    if (blocked) assert.throws(() => guard.assertAvailable(), /画面ロック・スリープ中/);
    else guard.assertAvailable();
  }
  guard.dispose();
  assert.equal(monitor.listenerCount("resume"), 0);
});

test("startup detects a supported locked screen; unknown/Linux state retains the Core fallback", () => {
  for (const platform of ["win32", "darwin", "linux"]) {
    const monitor = new EventEmitter(); monitor.getSystemIdleState = () => "locked";
    const session = new VaultSession(); session.unlock(Buffer.alloc(32, 1));
    const guard = new VaultPowerGuard(monitor, (reason) => session.lock(reason), platform);
    if (platform === "linux") { guard.assertAvailable(); assert.equal(monitor.listenerCount("lock-screen"), 0); }
    else { assert.equal(session.getState().isUnlocked, false); assert.throws(() => guard.assertAvailable()); }
    guard.dispose(); session.lock();
  }
  const monitor = new EventEmitter(); monitor.getSystemIdleState = () => { throw new Error("unsupported"); };
  const guard = new VaultPowerGuard(monitor, () => {}, "darwin");
  guard.assertAvailable(); guard.dispose();
});
