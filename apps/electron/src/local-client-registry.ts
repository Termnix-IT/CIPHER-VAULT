import type { VaultSessionState } from "@password-manager/shared/types";
import { authenticateLocalClient, LocalClientAuthenticationError, type AuthenticatedLocalChannel, type LocalIdentity } from "./local-client-auth.js";
import type { NativeConnection } from "./native-transport.js";
import { LocalClientRegistryError, publicLocalCertificate, registrationSummary, type ClientEnrollment, type LocalClientStore } from "./local-client-store.js";

type Session = { requireUnlocked(sessionId?: string): string; subscribe(listener: (state: VaultSessionState) => void): () => void };
type Schedule = (callback: () => void, delay: number) => () => void;
type Connection = { controller: AbortController; sessionId: string; clientId?: string; cancelTimer?: () => void };
const scheduleTimeout: Schedule = (callback, delay) => { const timer = setTimeout(callback, delay); timer.unref(); return () => clearTimeout(timer); };

// Trusted main-process capability only. Registration authenticates a connection; it grants no vault operation.
export class LocalClientRegistry {
  private readonly connections = new Set<Connection>();
  private closed = false;
  private faulted = false;
  private observedTime = 0;
  private readonly unsubscribe: () => void;
  constructor(private readonly store: LocalClientStore, private readonly session: Session,
    private readonly clock: () => number = Date.now, private readonly schedule: Schedule = scheduleTimeout) {
    this.unsubscribe = session.subscribe(state => {
      for (const connection of this.connections) if (!state.isUnlocked || state.sessionId !== connection.sessionId) connection.controller.abort();
    });
  }
  private abort(predicate: (connection: Connection) => boolean = () => true) {
    for (const connection of this.connections) if (predicate(connection)) connection.controller.abort();
  }
  private run<T>(action: () => T): T {
    if (this.closed) throw new LocalClientRegistryError("CLOSED");
    if (this.faulted) throw new LocalClientRegistryError("UNAVAILABLE");
    try { return action(); }
    catch (cause) {
      if (!(cause instanceof LocalClientRegistryError) || ["INVALID_STORE", "UNAVAILABLE", "CLOSED"].includes(cause.code)) { this.faulted = true; this.abort(); }
      throw cause instanceof LocalClientRegistryError ? cause : new LocalClientRegistryError("UNAVAILABLE");
    }
  }
  private now() {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < this.observedTime || now <= 0) { this.faulted = true; this.abort(); throw new LocalClientRegistryError("UNAVAILABLE"); }
    return this.observedTime = now;
  }
  private unlocked(sessionId: string) {
    if (typeof sessionId !== "string" || sessionId.length < 1) throw new LocalClientRegistryError("DENIED");
    try { if (this.session.requireUnlocked(sessionId) !== sessionId) throw new Error(); }
    catch { throw new LocalClientRegistryError("DENIED"); }
  }
  list(sessionId: string) {
    return this.run(() => { this.unlocked(sessionId); const snapshot = this.store.read(), now = this.now();
      return Object.freeze({ revision: snapshot.revision, clients: Object.freeze(snapshot.clients.map(client => Object.freeze({ ...registrationSummary(client),
        state: client.revokedAt !== null ? "revoked" : client.expiresAt <= now ? "expired" : "active" }))) }); });
  }
  enroll(sessionId: string, expectedRevision: number, input: ClientEnrollment) {
    return this.run(() => { this.unlocked(sessionId); const result = this.store.enroll(expectedRevision, input, this.now());
      this.abort(connection => !connection.clientId); return result; });
  }
  // Revocation remains available while locked, but only through the trusted owner capability.
  revoke(expectedRevision: number, clientId: string | null) {
    this.run(() => {
      if (this.store.read().revision !== expectedRevision) throw new LocalClientRegistryError("CONFLICT");
      this.abort(connection => !connection.clientId || clientId === null || connection.clientId === clientId);
      this.store.revoke(expectedRevision, clientId, this.now());
    });
  }
  async authenticate(native: NativeConnection, host: LocalIdentity, sessionId: string, signal?: AbortSignal): Promise<AuthenticatedLocalChannel & { assertCurrent(): void }> {
    let connection: Connection | undefined, removeAbort: (() => void) | undefined;
    const cleanup = () => { if (connection) { connection.cancelTimer?.(); this.connections.delete(connection); } removeAbort?.(); };
    try {
      const initial = this.run(() => {
        this.unlocked(sessionId); const now = this.now(), hostCert = publicLocalCertificate(host.certificate);
        if (signal?.aborted || this.connections.size >= 16 || hostCert.fingerprint !== this.store.hostFingerprint || now < hostCert.from || now >= hostCert.until) throw new LocalClientRegistryError("DENIED");
        return { snapshot: this.store.read(), hostUntil: hostCert.until, now };
      });
      connection = { controller: new AbortController(), sessionId }; this.connections.add(connection);
      const active = connection, abort = () => active.controller.abort();
      signal?.addEventListener("abort", abort, { once: true }); removeAbort = () => signal?.removeEventListener("abort", abort);
      void native.closed.then(cleanup);
      if (signal?.aborted) abort();
      const registered = initial.snapshot.clients.filter(client => client.revokedAt === null && client.expiresAt > initial.now);
      const channel = await authenticateLocalClient(native, host, registered, active.controller.signal);
      const selected = registered.find(client => client.clientId === channel.clientId);
      const assertCurrent = () => this.run(() => {
        try {
          this.unlocked(sessionId); const now = this.now(), current = this.store.read();
          const client = current.clients.find(value => value.clientId === channel.clientId);
          if (active.controller.signal.aborted || !selected || !client || client.revokedAt !== null || client.expiresAt <= now || initial.hostUntil <= now ||
              client.fingerprint256 !== selected.fingerprint256 || (!active.clientId && current.revision !== initial.snapshot.revision)) throw new LocalClientRegistryError("DENIED");
        } catch (cause) { abort(); throw cause; }
      });
      assertCurrent(); active.clientId = channel.clientId;
      const expire = () => {
        if (active.controller.signal.aborted) return;
        try { assertCurrent(); active.cancelTimer = this.schedule(expire, Math.max(1, Math.min(2147483647, Math.min(selected!.expiresAt, initial.hostUntil) - this.now()))); }
        catch { abort(); }
      };
      expire(); assertCurrent();
      return Object.freeze({ ...channel, assertCurrent });
    } catch { connection?.controller.abort(); cleanup(); await native.close(); throw new LocalClientAuthenticationError(); }
  }
  close() {
    if (this.closed) return;
    this.closed = true; this.abort(); this.unsubscribe(); this.store.close();
  }
}
