import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { VaultLockReason, VaultSessionState } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";
import { parseSessionId } from "../lib/input-validation.js";

export const VAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000;

type Clock = () => { monotonic: number; wall: number };
type Schedule = (callback: () => void, delay: number) => () => void;

const scheduleTimeout: Schedule = (callback, delay) => {
  const timer = setTimeout(callback, delay);
  timer.unref();
  return () => clearTimeout(timer);
};

// This owns the only live key and the lifetime of every operation using it.
export class VaultSession {
  private key: Buffer | null = null;
  private sessionId = randomUUID();
  private lockReason: VaultLockReason | undefined;
  private clockChanged = false;
  private activity = { monotonic: 0, wall: 0 };
  private observed = this.activity;
  private cancelTimer?: () => void;
  private readonly listeners = new Set<(state: VaultSessionState) => void>();

  constructor(
    private readonly clock: Clock = () => ({ monotonic: performance.now(), wall: Date.now() }),
    private readonly schedule: Schedule = scheduleTimeout
  ) {}

  getState(): VaultSessionState {
    this.expireIfNeeded();
    return this.snapshot();
  }

  unlock(key: Buffer) {
    this.destroyKey();
    this.key = Buffer.from(key);
    this.sessionId = randomUUID();
    this.lockReason = undefined;
    this.clockChanged = false;
    this.activity = this.observed = this.clock();
    this.armTimer();
    this.notify();
  }

  lock(reason: VaultLockReason = "manual") {
    // Even a lock while already locked invalidates pending unlock/reset requests.
    this.destroyKey();
    this.sessionId = randomUUID();
    this.lockReason = reason;
    this.notify();
  }

  requireGeneration(expectedSessionId: unknown) {
    const expected = requireSessionId(expectedSessionId);
    this.expireIfNeeded();
    if (expected !== this.sessionId) throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
    return this.sessionId;
  }

  requireUnlocked(expectedSessionId?: string) {
    this.expireIfNeeded();
    if (!this.key) throw new HttpError(423, "保管庫はロックされています");
    if (expectedSessionId !== undefined && expectedSessionId !== this.sessionId) {
      throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
    }
    return this.sessionId;
  }

  requireKey() {
    this.requireUnlocked();
    return this.key!;
  }

  recordActivity(expectedSessionId: string) {
    // Check expiry BEFORE touching the deadline: late traffic cannot revive a key.
    this.requireUnlocked(expectedSessionId);
    this.activity = this.observed = this.clock();
    this.armTimer();
  }

  subscribe(listener: (state: VaultSessionState) => void) {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  private snapshot(): VaultSessionState {
    return { sessionId: this.sessionId, isUnlocked: this.key !== null,
      idleTimeoutMs: VAULT_IDLE_TIMEOUT_MS, lockReason: this.lockReason };
  }

  private remaining() {
    const now = this.clock();
    if (!Number.isFinite(now.monotonic) || !Number.isFinite(now.wall) ||
        now.monotonic < this.observed.monotonic || now.wall < this.observed.wall) {
      this.clockChanged = true;
      return 0;
    }
    this.observed = now;
    // Wall time covers suspend on platforms where the monotonic clock pauses.
    return VAULT_IDLE_TIMEOUT_MS - Math.max(now.monotonic - this.activity.monotonic, now.wall - this.activity.wall);
  }

  private expireIfNeeded() {
    if (this.key && this.remaining() <= 0) this.lock(this.clockChanged ? "clock-change" : "idle");
  }

  private armTimer() {
    this.cancelTimer?.();
    const sessionId = this.sessionId;
    this.cancelTimer = this.schedule(() => {
      if (!this.key || sessionId !== this.sessionId) return;
      this.expireIfNeeded();
      if (this.key) this.armTimer();
    }, Math.max(1, this.remaining()));
  }

  private destroyKey() {
    this.cancelTimer?.();
    this.cancelTimer = undefined;
    this.key?.fill(0);
    this.key = null;
  }

  private notify() {
    const state = this.snapshot();
    for (const listener of this.listeners) {
      // Observers must never prevent key destruction or notifications to other views.
      try { listener(state); } catch { /* The key/state transition is already complete. */ }
    }
  }
}

export const vaultSession = new VaultSession();

export function requireSessionId(value: unknown) {
  return parseSessionId(value);
}

export async function withVaultSession<T>(expectedSessionId: unknown, action: (sessionId: string) => T | Promise<T>) {
  const sessionId = vaultSession.requireUnlocked(requireSessionId(expectedSessionId));
  const result = await action(sessionId);
  vaultSession.requireUnlocked(sessionId);
  return result;
}
