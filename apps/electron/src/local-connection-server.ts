import { randomUUID, X509Certificate } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { listenNativeTransport, type NativeConnection } from "./native-transport.js";
import type { IssuedLocalIdentity } from "./local-identity.js";
import type { LocalClientRegistry } from "./local-client-registry.js";
import type { AuthenticatedLocalChannel } from "./local-client-auth.js";
import { serveCandidateSearch, type CandidateSearch } from "./candidate-search.js";

type Job = { controller: AbortController; done: Promise<void>; endpoint?: string };

// Authenticated transport only. No vault/secret operation is exposed; application bytes are rejected.
export class LocalConnectionServer {
  private readonly generation = randomUUID();
  // macOS TMPDIR can exceed sockaddr_un's path bound. This is transport scratch space, never vault/key storage.
  private readonly directory = process.platform === "win32" ? undefined : mkdtempSync(path.join(realpathSync(process.platform === "darwin" ? "/tmp" : tmpdir()), "cv-live-"));
  private readonly jobs = new Map<string, Job>();
  private stopped = false;
  constructor(private readonly executable: string, private readonly discoveryFile: string, private readonly registry: LocalClientRegistry,
    private readonly identity: IssuedLocalIdentity, private readonly sessionId: string, private readonly fault: () => void, private readonly search?: CandidateSearch) {
    if (this.directory) chmodSync(this.directory, 0o700);
  }
  private publish() {
    if (this.stopped) return;
    const content = Buffer.from(JSON.stringify({ version: 1, generation: this.generation,
      hostFingerprint256: new X509Certificate(this.identity.certificate).fingerprint256,
      clients: [...this.jobs].filter(([, job]) => job.endpoint && !job.controller.signal.aborted).map(([clientId, job]) => ({ clientId, endpoint: job.endpoint })) }));
    const candidate = `${this.discoveryFile}.${randomUUID()}.tmp`;
    writeFileSync(candidate, content, { flag: "wx", mode: 0o600 }); renameSync(candidate, this.discoveryFile);
  }
  async sync() {
    if (this.stopped) return;
    const active = this.registry.list(this.sessionId).clients.filter(client => client.state === "active");
    for (const [id, job] of this.jobs) if (!active.some(client => client.clientId === id)) job.controller.abort();
    const starts: Promise<void>[] = [];
    for (const client of active) {
      if (this.jobs.has(client.clientId)) continue;
      let started!: () => void, failed!: (error: unknown) => void;
      const ready = new Promise<void>((resolve, reject) => { started = resolve; failed = reject; });
      ready.catch(() => {});
      const job: Job = { controller: new AbortController(), done: Promise.resolve() }; this.jobs.set(client.clientId, job);
      job.done = this.serve(client.clientId, client.expiresAt, job, started).catch(error => {
        failed(error); if (!this.stopped && !job.controller.signal.aborted) this.fault();
      }).finally(() => { this.jobs.delete(client.clientId); if (!this.stopped) { try { this.publish(); } catch { this.fault(); } } });
      starts.push(ready);
    }
    this.publish(); await Promise.all(starts);
  }
  private async serve(clientId: string, expiresAt: number, job: Job, ready: () => void) {
    const { signal } = job.controller;
    let expiry: ReturnType<typeof setTimeout> | undefined;
    const expire = () => {
      const remaining = Math.min(expiresAt, this.identity.expiresAt) - Date.now();
      if (remaining <= 0) job.controller.abort(); else { expiry = setTimeout(expire, Math.min(remaining, 60000)); expiry.unref(); }
    }; expire();
    try {
      while (!this.stopped && !signal.aborted) {
        const endpoint = this.directory ? path.join(this.directory, `${randomUUID()}.sock`) : `\\\\.\\pipe\\cipher-vault-${randomUUID()}`;
        let listener: Awaited<ReturnType<typeof listenNativeTransport>> | undefined, native: NativeConnection | undefined, channel: (AuthenticatedLocalChannel & { assertCurrent(): void }) | undefined;
        let rotate: ReturnType<typeof setTimeout> | undefined;
        try {
          listener = await listenNativeTransport({ executable: this.executable, endpoint, signal });
          listener.accepted.catch(() => {});
          if (signal.aborted || this.stopped) break;
          job.endpoint = endpoint; this.publish(); ready();
          // Native peer-wait has a bounded lifetime; rotate a fresh endpoint before it expires.
          const current = listener; rotate = setTimeout(() => { void current.close(); }, 30000); rotate.unref();
          try { native = await listener.accepted; } catch { if (signal.aborted || this.stopped) break; await delay(250, undefined, { signal }).catch(() => {}); continue; }
          clearTimeout(rotate); job.endpoint = undefined; this.publish();
          try {
            channel = await this.registry.authenticate(native, this.identity, this.sessionId, signal);
            if (channel.clientId !== clientId) { await channel.close(); await delay(250, undefined, { signal }).catch(() => {}); continue; }
            const client = this.registry.list(this.sessionId).clients.find(value => value.clientId === clientId);
            if (this.search && client?.kind === "agent") serveCandidateSearch(channel, client, this.search);
            else channel.socket.on("data", (chunk: Buffer) => { chunk.fill(0); void channel?.close(); });
            await native.closed;
          } catch { if (signal.aborted || this.stopped) break; }
        } finally {
          clearTimeout(rotate); job.endpoint = undefined;
          await channel?.close(); await native?.close(); await listener?.close();
        }
        if (!signal.aborted && !this.stopped) await delay(250, undefined, { signal }).catch(() => {});
      }
    } finally { clearTimeout(expiry); if (signal.aborted) ready(); }
  }
  stop() {
    if (!this.stopped) { this.stopped = true; for (const job of this.jobs.values()) job.controller.abort(); }
  }
  async close() {
    this.stop(); await Promise.all([...this.jobs.values()].map(job => job.done));
    try {
      const info = lstatSync(this.discoveryFile);
      if (info.isFile() && info.nlink === 1 && info.size < 16384 && JSON.parse(readFileSync(this.discoveryFile, "utf8")).generation === this.generation) unlinkSync(this.discoveryFile);
    } catch { /* A changed/unavailable discovery record is left; it is never an authentication source. */ }
    if (this.directory && existsSync(this.directory)) { try { rmdirSync(this.directory); } catch { /* Preserve unexpected socket/files. */ } }
  }
}
