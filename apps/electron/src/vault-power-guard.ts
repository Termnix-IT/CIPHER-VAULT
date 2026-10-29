import type { PowerMonitor } from "electron";
import type { VaultLockReason } from "@password-manager/shared/types";
import { supportsScreenLockEvents } from "./desktop-platform.js";

// OS policy stays in Electron; Core still owns the key, deadlines and generations.
export class VaultPowerGuard {
  private screenLocked = false;
  private suspended = false;
  private readonly screenEventsSupported: boolean;
  private readonly handlers: [string, () => void][] = [];

  constructor(
    private readonly monitor: Pick<NodeJS.EventEmitter, "on" | "off"> & Pick<PowerMonitor, "getSystemIdleState">,
    private readonly lock: (reason: VaultLockReason) => void,
    platform: string = process.platform
  ) {
    this.screenEventsSupported = supportsScreenLockEvents(platform);
    this.listen("suspend", () => { this.suspended = true; lock("suspend"); });
    this.listen("resume", () => { this.suspended = false; lock("resume"); });
    if (this.screenEventsSupported) {
      this.listen("lock-screen", () => { this.screenLocked = true; lock("screen-lock"); });
      this.listen("unlock-screen", () => { this.screenLocked = false; lock("screen-unlock"); });
    }
    this.detectLockedScreen();
  }

  assertAvailable() {
    this.detectLockedScreen();
    if (this.screenLocked || this.suspended) throw new Error("画面ロック・スリープ中は保管庫を操作できません。OSへ戻ってから解除してください");
  }

  dispose() {
    for (const [event, handler] of this.handlers) this.monitor.off(event, handler);
    this.handlers.length = 0;
  }

  private detectLockedScreen() {
    if (!this.screenEventsSupported) return;
    try {
      if (!this.screenLocked && this.monitor.getSystemIdleState(1) === "locked") {
        this.screenLocked = true;
        this.lock("screen-lock");
      }
    } catch { /* Unsupported OS detection retains the Core idle/lifecycle protection. */ }
  }

  private listen(event: string, handler: () => void) {
    this.monitor.on(event, handler);
    this.handlers.push([event, handler]);
  }
}
