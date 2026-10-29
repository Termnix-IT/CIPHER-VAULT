import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { CLIPBOARD_CLEAR_AFTER_MS } from "@password-manager/shared";

export type ClipboardPort = {
  write: (text: string, owner: string) => Promise<void>;
  matches: (owner: string, digest: Buffer) => Promise<boolean>;
  clear: () => void;
};
type Clock = () => { monotonic: number; wall: number };
type Schedule = (callback: () => void, delay: number) => () => void;
type Lease = { owner: string; digest: Buffer; started: ReturnType<Clock> };
const scheduleTimeout: Schedule = (callback, delay) => {
  const timer = setTimeout(callback, delay);
  timer.unref();
  return () => clearTimeout(timer);
};

// Timers retain a digest and random owner token, never the copied plaintext.
export class ExpiringClipboard {
  private lease?: Lease;
  private revision = 0;
  private writing?: Promise<void>;
  private clearing?: Promise<boolean>;
  private cancelTimer?: () => void;

  constructor(
    private readonly port: ClipboardPort,
    private readonly clock: Clock = () => ({ monotonic: performance.now(), wall: Date.now() }),
    private readonly schedule: Schedule = scheduleTimeout
  ) {}

  async copy(text: string, assertCurrent: () => void): Promise<void> {
    if (this.writing || this.clearing) throw new Error("コピー処理の完了を待ってください");
    assertCurrent();
    const revision = ++this.revision;
    const candidate: Lease = { owner: randomUUID(), digest: createHash("sha256").update(text, "utf8").digest(), started: this.clock() };
    this.stopTimer();
    const job = (async () => {
      try {
        await this.port.write(text, candidate.owner);
        this.forgetLease();
        this.lease = candidate;
        assertCurrent();
        if (revision !== this.revision || this.remaining(candidate) <= 0) throw new Error("コピー中に保管庫の状態または期限が変わりました");
        this.arm(candidate);
      } catch (error) {
        if (this.lease === candidate) await this.clearLease(candidate);
        else {
          candidate.digest.fill(0);
          if (revision === this.revision && this.lease) this.arm(this.lease);
        }
        throw error;
      }
    })();
    this.writing = job;
    try { await job; }
    finally { if (this.writing === job) this.writing = undefined; }
  }

  async clearOwned(): Promise<boolean> {
    if (this.clearing) return this.clearing;
    ++this.revision; // Also invalidates a native clipboard write still in flight.
    this.stopTimer();
    const pending = this.writing;
    const job = (async () => {
      if (pending) await pending.catch(() => undefined);
      return this.lease ? this.clearLease(this.lease) : true;
    })();
    this.clearing = job;
    try { return await job; }
    finally { if (this.clearing === job) this.clearing = undefined; }
  }

  private remaining(lease: Lease) {
    const now = this.clock();
    if (!Number.isFinite(now.monotonic) || !Number.isFinite(now.wall) ||
        now.monotonic < lease.started.monotonic || now.wall < lease.started.wall) return 0;
    return CLIPBOARD_CLEAR_AFTER_MS - Math.max(now.monotonic - lease.started.monotonic, now.wall - lease.started.wall);
  }

  private arm(lease: Lease) {
    const revision = this.revision;
    this.stopTimer();
    this.cancelTimer = this.schedule(() => {
      if (revision !== this.revision || this.lease !== lease) return;
      if (this.remaining(lease) > 0) this.arm(lease);
      else void this.clearOwned();
    }, Math.max(1, this.remaining(lease)));
  }

  private async clearLease(lease: Lease): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const matches = await Promise.race([
        this.port.matches(lease.owner, lease.digest),
        new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("clipboard read timeout")), 1000); })
      ]);
      if (this.lease !== lease) return true;
      if (matches) this.port.clear();
      this.forgetLease(); // A changed clipboard belongs to another copy operation.
      return true;
    } catch {
      // Keep only the lease for a retry on lock/resume/quit. Never clear on read failure.
      return false;
    } finally { clearTimeout(timer); }
  }

  private stopTimer() { this.cancelTimer?.(); this.cancelTimer = undefined; }
  private forgetLease() { this.lease?.digest.fill(0); this.lease = undefined; }
}
