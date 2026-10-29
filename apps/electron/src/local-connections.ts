import { randomUUID, X509Certificate } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import type { LocalConnectionsState, LocalPairingApproval, VaultSessionState } from "@password-manager/shared/types";
import type { DeviceKeyProtector } from "./device-key-protector.js";
import { generateLocalIdentity, type IssuedLocalIdentity } from "./local-identity.js";
import { assertNativeHelperExecutable } from "./native-transport.js";
import { ProtectedLocalIdentityStore, localIdentityFile } from "./protected-local-identity.js";
import { createManagedLocalClientStore, openManagedLocalClientStore, type ManagedLocalClientStore } from "./local-client-store.js";
import { LocalClientRegistry } from "./local-client-registry.js";
import { LocalPairingCoordinator, LocalPairingError } from "./local-pairing.js";
import { LocalConnectionServer } from "./local-connection-server.js";

type Session = { getState(): VaultSessionState; requireUnlocked(sessionId?: string): string; requireGeneration(id: unknown): string; subscribe(listener: (state: VaultSessionState) => void): () => void };
const unavailable = () => new LocalPairingError();

export class LocalConnections {
  private readonly root: string;
  private readonly keys: ProtectedLocalIdentityStore;
  private store?: ManagedLocalClientStore;
  private registry?: LocalClientRegistry;
  private pairing?: LocalPairingCoordinator;
  private identity?: IssuedLocalIdentity;
  private server?: LocalConnectionServer;
  private abort?: AbortController;
  private operation?: Promise<void>;
  private readonly cleanup = new Set<Promise<void>>();
  private faulted = false;
  private closed = false;
  private readonly unsubscribe: () => void;
  constructor(directory: string, private readonly executable: string, protector: DeviceKeyProtector, private readonly session: Session) {
    this.root = path.join(realpathSync(directory), "local-connections"); this.keys = new ProtectedLocalIdentityStore(protector);
    try {
      if (existsSync(this.root)) {
        this.directory();
        if (existsSync(this.databaseFile())) this.install(openManagedLocalClientStore(this.databaseFile()));
        else if (readdirSync(this.root).length !== 0) throw unavailable();
      }
    } catch { this.faulted = true; }
    this.unsubscribe = session.subscribe(state => {
      this.halt();
      if (state.isUnlocked) {
        const pending = this.operation ?? Promise.resolve();
        void pending.catch(() => {}).then(async () => {
          if (this.closed || this.faulted || this.session.getState().sessionId !== state.sessionId || !this.store?.configuration().enabled) return;
          await this.enable(state.sessionId, this.store.read().revision, false);
        }).catch(() => { if (!this.closed && this.session.getState().sessionId === state.sessionId) this.fail(); });
      }
    });
  }
  private databaseFile() { return path.join(this.root, "clients.sqlite"); }
  private discoveryFile() { return path.join(this.root, "connection.json"); }
  private directory() {
    const info = lstatSync(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(this.root) !== this.root ||
        (process.platform !== "win32" && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw unavailable();
  }
  private install(store: ManagedLocalClientStore) { this.store = store; this.registry = new LocalClientRegistry(store, this.session); }
  private halt() {
    this.abort?.abort(); this.abort = undefined;
    this.pairing?.close(); this.pairing = undefined;
    this.server?.stop();
    if (this.server) {
      const pending = this.server.close().catch(() => { this.faulted = true; }); this.cleanup.add(pending);
      void pending.finally(() => this.cleanup.delete(pending)); this.server = undefined;
    }
    this.identity?.dispose(); this.identity = undefined;
  }
  private fail() { this.faulted = true; this.halt(); }
  private current(sessionId: string) { if (this.closed || this.session.requireUnlocked(sessionId) !== sessionId) throw unavailable(); }
  async setEnabled(sessionId: string, expectedRevision: number, enabled: boolean) {
    if (typeof enabled !== "boolean" || !Number.isInteger(expectedRevision) || expectedRevision < 0 || expectedRevision >= 2147483647) throw unavailable();
    if (!enabled) {
      if (this.closed || this.session.requireGeneration(sessionId) !== sessionId) throw unavailable();
      this.halt(); await this.operation?.catch(() => {}); await Promise.all(this.cleanup);
      if (this.session.requireGeneration(sessionId) !== sessionId) throw unavailable();
      try { if (this.store) this.store.setEnabled(expectedRevision, false); else if (expectedRevision !== 0) throw unavailable(); this.faulted = false; }
      catch { this.fail(); throw unavailable(); }
      return;
    }
    return this.enable(sessionId, expectedRevision, true);
  }
  private async enable(sessionId: string, expectedRevision: number, persist: boolean) {
    this.current(sessionId); if (this.operation) throw unavailable();
    if (this.store && this.store.read().revision !== expectedRevision) throw unavailable();
    if (this.identity && this.server && !this.faulted) return;
    this.halt();
    const controller = new AbortController(); this.abort = controller;
    const active = () => { this.current(sessionId); if (controller.signal.aborted) throw unavailable(); };
    const action = async () => {
      try {
        await Promise.all(this.cleanup); active(); assertNativeHelperExecutable(this.executable);
        if (!this.store) {
          if (expectedRevision !== 0 || !persist) throw unavailable();
          if (!existsSync(this.root)) mkdirSync(this.root, { mode: 0o700 }); this.directory();
          if (readdirSync(this.root).length !== 0) throw unavailable();
          this.faulted = false;
          const identity = await generateLocalIdentity({ executable: this.executable, role: "host", signal: controller.signal });
          this.identity = identity; active();
          const reference = { identityId: randomUUID(), role: "host" as const, fingerprint256: new X509Certificate(identity.certificate).fingerprint256 };
          await this.keys.save(localIdentityFile(this.root, reference.identityId), identity, reference, active, controller.signal); active();
          this.install(createManagedLocalClientStore(this.databaseFile(), { identityId: reference.identityId, certificate: identity.certificate }));
        } else {
          if (this.faulted) { if (!persist) throw unavailable(); this.registry!.list(sessionId); this.faulted = false; }
          const configuration = this.store.configuration();
          if (!persist && !configuration.enabled) return;
          this.identity?.dispose(); this.identity = undefined;
          const loaded = await this.keys.load(localIdentityFile(this.root, configuration.reference.identityId), configuration.reference, active, controller.signal);
          this.identity = loaded.identity; active(); if (loaded.shouldReEncrypt) throw unavailable();
        }
        active();
        if (persist) this.store!.setEnabled(expectedRevision, true);
        if (!this.store!.configuration().enabled) throw unavailable();
        this.pairing = new LocalPairingCoordinator(this.registry!, this.session);
        this.server = new LocalConnectionServer(this.executable, this.discoveryFile(), this.registry!, this.identity!, sessionId, () => this.fail());
        await this.server.sync(); active();
      } catch { if (!controller.signal.aborted) this.faulted = true; this.halt(); throw unavailable(); }
    };
    this.operation = action();
    try { await this.operation; } finally { this.operation = undefined; }
  }
  state(sessionId: string): LocalConnectionsState {
    this.current(sessionId);
    try {
      const listing = this.registry?.list(sessionId) ?? { revision: 0, clients: [] };
      const enabled = this.store?.configuration().enabled ?? false;
      return Object.freeze({ status: this.faulted ? "unavailable" : this.operation ? "starting" : !this.store ? "disabled" : this.identity && this.server ? "ready" : this.store.configuration().enabled ? "locked" : "paused",
        enabled, revision: listing.revision, clients: listing.clients, review: this.pairing?.current(sessionId) ?? null });
    } catch { this.fail(); return Object.freeze({ status: "unavailable", enabled: false, revision: 0, clients: [], review: null }); }
  }
  stage(sessionId: string, content: Buffer) {
    this.current(sessionId); if (this.faulted || !this.identity || !this.pairing || this.operation) throw unavailable();
    this.pairing.stage(sessionId, content);
  }
  async approve(sessionId: string, approval: LocalPairingApproval) {
    this.current(sessionId); if (this.faulted || !this.pairing || !this.server || this.operation) throw unavailable();
    this.pairing.approve(sessionId, approval);
    try { await this.server.sync(); this.current(sessionId); } catch { if (this.session.getState().sessionId === sessionId) this.fail(); else this.halt(); throw unavailable(); }
  }
  cancel(sessionId: string, pendingId: string) { this.current(sessionId); if (typeof pendingId !== "string" || !this.pairing) throw unavailable(); this.pairing.cancel(sessionId, pendingId); }
  async revoke(sessionId: string, expectedRevision: number, clientId: string) {
    if (this.closed || this.session.requireGeneration(sessionId) !== sessionId || typeof clientId !== "string" || !this.registry) throw unavailable();
    this.registry.revoke(expectedRevision, clientId);
    this.pairing?.close(); this.pairing = this.identity ? new LocalPairingCoordinator(this.registry, this.session) : undefined;
    if (this.server) await this.server.sync();
  }
  connectionInfo(sessionId: string, clientId: string): Buffer {
    this.current(sessionId); if (!this.store || !this.registry || typeof clientId !== "string") throw unavailable();
    const client = this.registry.list(sessionId).clients.find(value => value.clientId === clientId && value.state === "active");
    if (!client) throw unavailable();
    const host = this.store.configuration();
    return Buffer.from(JSON.stringify({ version: 1, clientId: client.clientId, clientFingerprint256: client.fingerprint256,
      hostCertificate: host.certificate.toString("base64"), hostFingerprint256: host.reference.fingerprint256, discoveryFile: this.discoveryFile() }));
  }
  async close() {
    if (!this.closed) { this.closed = true; this.unsubscribe(); this.halt(); }
    await this.operation?.catch(() => {}); await Promise.all(this.cleanup); this.registry?.close();
  }
}
