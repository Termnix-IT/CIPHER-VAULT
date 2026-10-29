import { performance } from "node:perf_hooks";
import { HttpError } from "../lib/errors.js";

// Shared by setup/unlock across HTTP and IPC. Reject rather than queue passwords.
export class VaultUnlockGuard {
  private busy = false;
  private failures = 0;
  private retryAt = 0;

  constructor(private readonly now: () => number = () => performance.now()) {}

  async run<T>(action: () => Promise<T>): Promise<T> {
    if (this.busy) throw new HttpError(409, "初期設定・解除処理の完了を待ってください");
    const retryAfter = Math.ceil((this.retryAt - this.now()) / 1000);
    if (retryAfter > 0) {
      throw new HttpError(429, `認証の失敗が続いています。${retryAfter}秒後にもう一度お試しください`, retryAfter);
    }
    this.busy = true;
    try {
      const result = await action();
      this.failures = 0;
      this.retryAt = 0;
      return result;
    } catch (error) {
      if (error instanceof HttpError && error.statusCode === 401) {
        this.failures = Math.min(this.failures + 1, 10);
        if (this.failures >= 5) this.retryAt = this.now() + Math.min(30000, 1000 * 2 ** (this.failures - 5));
      }
      throw error;
    } finally {
      this.busy = false;
    }
  }
}

export const vaultUnlockGuard = new VaultUnlockGuard();
