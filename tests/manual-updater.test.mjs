import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { ManualUpdater } from "../apps/electron/dist/apps/electron/src/manual-updater.js";

class FakeUpdater extends EventEmitter {
  checks = 0;
  downloads = 0;
  installs = 0;
  async checkForUpdates() {
    this.checks++;
    this.emit("update-available", { version: "0.2.0", releaseNotes: "Changes" });
    return {};
  }
  async downloadUpdate() {
    this.downloads++;
    this.emit("download-progress", { percent: 50 });
    this.emit("update-downloaded");
    return [];
  }
  quitAndInstall(silent, relaunch) {
    assert.equal(silent, false);
    assert.equal(relaunch, true);
    this.installs++;
  }
}
function setup(supported = true) {
  const updater = new FakeUpdater();
  const states = [];
  const controller = new ManualUpdater(updater, "0.1.0", supported, (s) => states.push(s));
  return { updater, controller, states };
}

test("startup, check and download never install or start the next step automatically", async () => {
  const { updater, controller, states } = setup();
  assert.equal(updater.checks, 0);
  assert.equal(updater.autoDownload, false);
  assert.equal(updater.autoInstallOnAppQuit, false);
  assert.equal(updater.allowPrerelease, false);
  assert.equal(updater.allowDowngrade, false);
  await controller.check();
  assert.equal(updater.downloads, 0);
  await controller.download();
  assert.equal(updater.installs, 0);
  assert.equal(controller.getState().status, "downloaded");
  assert.equal(states.find((s) => s.status === "downloading" && s.progress === 50).progress, 50);
  // Closing About or quitting must not enable the updater's on-quit installer.
  assert.equal(updater.autoInstallOnAppQuit, false);
  await controller.check();
  assert.equal(controller.getState().status, "downloaded");
});

test("unsaved edit cancellation retains the downloaded update; explicit consent installs once", async () => {
  const { updater, controller } = setup();
  await controller.check(); await controller.download();
  await controller.install(async () => false);
  assert.equal(controller.getState().status, "downloaded");
  assert.equal(updater.installs, 0);
  let locked = false;
  await controller.install(async () => { locked = true; return true; });
  assert.equal(locked, true);
  assert.equal(updater.installs, 1);
  await controller.install(async () => true);
  assert.equal(updater.installs, 1);
});

test("unsupported distributions and out-of-order commands do nothing", async () => {
  for (const supported of [false, true]) {
    const { updater, controller } = setup(supported);
    await controller.download(); await controller.install(async () => true);
    assert.equal(updater.downloads + updater.installs, 0);
    if (!supported) { await controller.check(); assert.equal(updater.checks, 0); }
  }
});

test("concurrent requests are deduplicated even while confirmation is pending", async () => {
  const { updater, controller } = setup();
  await Promise.all([controller.check(), controller.check()]);
  assert.equal(updater.checks, 1);
  await Promise.all([controller.download(), controller.download()]);
  assert.equal(updater.downloads, 1);
  let resolve;
  const first = controller.install(() => new Promise((r) => { resolve = r; }));
  await controller.install(async () => true);
  resolve(true); await first;
  assert.equal(updater.installs, 1);
});

test("network or checksum failure blocks install and permits a fresh check", async () => {
  const { updater, controller } = setup();
  updater.checkForUpdates = async () => { throw new Error("offline"); };
  await controller.check();
  assert.equal(controller.getState().status, "error");
  updater.checkForUpdates = FakeUpdater.prototype.checkForUpdates;
  await controller.check();
  updater.downloadUpdate = async () => { updater.emit("error", new Error("checksum")); throw new Error("checksum"); };
  await controller.download();
  assert.equal(controller.getState().status, "error");
  await controller.install(async () => true);
  assert.equal(updater.installs, 0);
  await controller.check();
  assert.equal(controller.getState().status, "available");
});

test("latest version and preparation failure remain recoverable", async () => {
  const { updater, controller } = setup();
  updater.checkForUpdates = async () => { updater.emit("update-not-available"); return {}; };
  await controller.check();
  assert.equal(controller.getState().status, "current");
  updater.checkForUpdates = FakeUpdater.prototype.checkForUpdates;
  await controller.check(); await controller.download();
  await controller.install(async () => { throw new Error("lock failed"); });
  assert.equal(updater.installs, 0);
  assert.equal(controller.getState().status, "error");
});
