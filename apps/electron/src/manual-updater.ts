import type { AppUpdater, UpdateInfo } from "electron-updater";
import type { AppUpdateState } from "@password-manager/shared/types";

// No network requests or installation are triggered by construction or app exit.
export class ManualUpdater {
  private state: AppUpdateState;
  private busy = false;

  constructor(
    private readonly updater: AppUpdater,
    version: string,
    supported: boolean,
    private readonly notify: (state: AppUpdateState) => void,
  ) {
    updater.autoDownload = false;
    updater.autoInstallOnAppQuit = false;
    updater.autoRunAppAfterInstall = true;
    updater.allowPrerelease = false;
    updater.allowDowngrade = false;
    this.state = { currentVersion: version, status: supported ? "idle" : "unsupported" };
    updater.on("update-available", (info: UpdateInfo) => {
      const notes = typeof info.releaseNotes === "string" ? info.releaseNotes
        : info.releaseNotes?.map((entry) => `${entry.version}\n${entry.note ?? ""}`).join("\n\n");
      this.set({ status: "available", latestVersion: info.version, releaseNotes: notes?.slice(0, 20000) });
    });
    updater.on("update-not-available", () => this.set({ status: "current" }));
    updater.on("download-progress", (progress) => this.set({ status: "downloading", progress: Math.max(0, Math.min(100, progress.percent)) }));
    updater.on("update-downloaded", () => this.set({ status: "downloaded", progress: 100 }));
    updater.on("error", () => this.fail());
  }

  getState() { return { ...this.state }; }

  private set(patch: Partial<AppUpdateState>) {
    this.state = { ...this.state, message: undefined, ...patch };
    this.notify(this.getState());
  }

  private fail() {
    this.set({ status: "error", message: "更新処理に失敗しました。通信環境と公開済みの更新ファイルを確認して、再試行してください。" });
  }

  async check() {
    if (this.busy || !["idle", "current", "available", "error"].includes(this.state.status)) return;
    this.busy = true;
    this.set({ status: "checking", latestVersion: undefined, releaseNotes: undefined, progress: undefined });
    try {
      const result = await this.updater.checkForUpdates();
      if (!result) this.fail();
    } catch { this.fail(); }
    finally { this.busy = false; }
  }

  async download() {
    if (this.busy || this.state.status !== "available") return;
    this.busy = true;
    this.set({ status: "downloading", progress: 0 });
    try { await this.updater.downloadUpdate(); }
    catch { this.fail(); }
    finally { this.busy = false; }
  }

  async install(prepare: () => Promise<boolean>) {
    if (this.busy || this.state.status !== "downloaded") return;
    this.busy = true;
    try {
      if (!await prepare()) return false;
      this.set({ status: "installing" });
      this.updater.quitAndInstall(false, true);
    } catch { this.fail(); }
    finally { this.busy = false; }
  }
}
