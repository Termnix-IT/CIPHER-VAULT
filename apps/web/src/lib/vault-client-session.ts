import type { VaultStatus } from "@password-manager/shared/types";

export class VaultSessionChangedError extends Error {
  constructor() { super("保管庫の状態が変わりました。もう一度操作してください"); }
}

// Fence promises at the transport boundary, including dialogs outside App's state.
export class VaultClientSession {
  private state: VaultStatus | null = null;
  private revision = 0;
  private control = 0;
  private blockedSessionId: string | null = null;
  private readonly listeners = new Set<(state: VaultStatus) => void>();

  subscribe(listener: (state: VaultStatus) => void) {
    this.listeners.add(listener);
    if (this.state) listener(this.state);
    return () => { this.listeners.delete(listener); };
  }

  observe(state: VaultStatus, expectedRevision = this.revision) {
    if (expectedRevision !== this.revision && state.sessionId !== this.state?.sessionId) {
      throw new VaultSessionChangedError();
    }
    // Reconnecting must not resurrect a view that was cleared locally. Unlock anew.
    if (state.sessionId === this.blockedSessionId && state.isUnlocked) {
      state = { ...state, isUnlocked: false, lockReason: undefined };
    } else if (state.sessionId !== this.blockedSessionId) {
      this.blockedSessionId = null;
    }
    if (this.state?.sessionId !== state.sessionId || this.state.isUnlocked !== state.isUnlocked ||
        this.state.isConfigured !== state.isConfigured || this.state.lockReason !== state.lockReason) {
      this.state = state;
      this.revision++;
      for (const listener of this.listeners) listener(state);
    }
    return state;
  }

  lockLocally() {
    if (this.state?.isUnlocked) {
      this.blockedSessionId = this.state.sessionId;
      this.observe({ ...this.state, isUnlocked: false, lockReason: undefined });
    }
  }

  requireSessionId() {
    if (!this.state?.isUnlocked) throw new VaultSessionChangedError();
    return this.state.sessionId;
  }

  async readStatus(read: () => Promise<VaultStatus>) {
    const revision = this.revision;
    return this.observe(await read(), revision);
  }

  async change(action: (sessionId: string) => Promise<VaultStatus>) {
    if (!this.state) throw new VaultSessionChangedError();
    const sessionId = this.state.sessionId;
    const control = ++this.control;
    const revision = ++this.revision;
    const state = await action(sessionId);
    if (control !== this.control) throw new VaultSessionChangedError();
    return this.observe(state, revision);
  }

  async run<T>(action: (sessionId: string) => Promise<T>, read: () => Promise<VaultStatus>): Promise<T> {
    const revision = this.revision;
    const sessionId = this.state?.sessionId;
    if (!this.state?.isUnlocked || !sessionId) throw new VaultSessionChangedError();
    const assertCurrent = () => {
      if (revision !== this.revision || sessionId !== this.state?.sessionId || !this.state?.isUnlocked) {
        throw new VaultSessionChangedError();
      }
    };
    try {
      const result = await action(sessionId);
      assertCurrent();
      this.observe(await read(), revision);
      assertCurrent();
      return result;
    } catch (error) {
      if (revision === this.revision) {
        try { this.observe(await read(), revision); }
        catch (statusError) { if (!(statusError instanceof VaultSessionChangedError)) this.lockLocally(); }
      }
      assertCurrent();
      throw error;
    }
  }
}
