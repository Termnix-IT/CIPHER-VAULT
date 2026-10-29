import { randomUUID, X509Certificate } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import type { DeviceKeyProtector } from "./device-key-protector.js";
import { BrowserConnectionError } from "./browser-message.js";
import { browserDiscoveryEndpoint, parseBrowserConnectionInfo } from "./browser-connection-info.js";
import { openBrowserClientStore, type BrowserClientStore } from "./browser-client-store.js";
import { generateLocalIdentity, type IssuedLocalIdentity } from "./local-identity.js";
import { ProtectedLocalIdentityStore, localIdentityFile } from "./protected-local-identity.js";
import { encodeLocalPairingRequest } from "./local-pairing.js";
import { connectNativeTransport } from "./native-transport.js";
import { authenticateLocalHost } from "./local-client-auth.js";
import { readLocalPublicFile, writeNewLocalPublicFile } from "./local-public-files.js";
import { queryCandidateSearch } from "./candidate-search.js";

export type BrowserClientState = Readonly<{ state: "unpaired" | "request-ready" | "configured"; displayName: string | null; fingerprint256: string | null }>;

// Client-only capability. It never imports the Vault database, session, entry or password services.
// Production entry points supply native-dialog-selected files; no extension message supplies a path.
export class BrowserClient {
  private readonly root: string;
  private readonly keys: ProtectedLocalIdentityStore;
  private store?: BrowserClientStore;
  private busy = false;
  private closed = false;
  private readonly controller = new AbortController();
  constructor(directory: string, private readonly executable: string, protector: DeviceKeyProtector, private readonly browser: "chrome" | "edge" | "codex") {
    if (!["chrome", "edge", "codex"].includes(browser)) throw new BrowserConnectionError();
    this.root = path.join(realpathSync(directory), "data"); this.keys = new ProtectedLocalIdentityStore(protector);
    if (existsSync(this.root)) {
      this.directory();
      if (existsSync(this.database())) this.store = openBrowserClientStore(this.database());
      else if (readdirSync(this.root).length !== 0) throw new BrowserConnectionError();
    }
  }
  private database() { return path.join(this.root, "client.sqlite"); }
  private directory() {
    const info = lstatSync(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() || realpathSync(this.root) !== this.root ||
        (process.platform !== "win32" && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw new BrowserConnectionError();
    const files = readdirSync(this.root);
    if (files.length > 35 || files.some(file => !["client.sqlite", "client.sqlite-journal"].includes(file) && !/^identity-[0-9a-f-]{36}\.cvkey$/.test(file))) throw new BrowserConnectionError();
  }
  private active(signal?: AbortSignal) { if (this.closed || this.controller.signal.aborted || signal?.aborted) throw new BrowserConnectionError(); }
  private name(fingerprint: string) { return `${this.browser === "codex" ? "Codex MCP" : this.browser === "chrome" ? "Chrome ブラウザ連携" : "Edge ブラウザ連携"} · ${fingerprint.replaceAll(":", "").slice(0, 8)}`; }
  state(): BrowserClientState {
    this.active(); const value = this.store?.read().credential;
    return Object.freeze({ state: value ? value.receipt ? "configured" : "request-ready" : "unpaired",
      displayName: value ? this.name(value.reference.fingerprint256) : null, fingerprint256: value?.reference.fingerprint256 ?? null });
  }
  private async run<T>(signal: AbortSignal | undefined, action: (active: () => void, signal: AbortSignal) => Promise<T>) {
    this.active(signal); if (this.busy) throw new BrowserConnectionError(); this.busy = true;
    const combined = signal ? AbortSignal.any([signal, this.controller.signal]) : this.controller.signal;
    try { return await action(() => this.active(combined), combined); }
    catch { throw new BrowserConnectionError(); }
    finally { this.busy = false; }
  }
  private async replace(active: () => void, signal: AbortSignal) {
    let identity: IssuedLocalIdentity | undefined;
    try {
      active();
      if (!this.store) {
        if (!existsSync(this.root)) mkdirSync(this.root, { mode: 0o700 }); this.directory();
        if (readdirSync(this.root).length !== 0) throw new BrowserConnectionError();
        this.store = openBrowserClientStore(this.database(), true);
      }
      this.directory();
      // Keep failed candidates and previous encrypted keys; stop at a bounded count instead of deleting them.
      if (readdirSync(this.root).filter(file => file.endsWith(".cvkey")).length >= 32) throw new BrowserConnectionError();
      const previous = this.store.read(); identity = await generateLocalIdentity({ executable: this.executable, role: "client", signal }); active();
      const identityId = randomUUID();
      const { fingerprint256 } = new X509Certificate(identity.certificate);
      await this.keys.save(localIdentityFile(this.root, identityId), identity, { identityId, role: "client", fingerprint256 }, active, signal); active();
      this.store.replace(previous.revision, identityId, identity.certificate); active();
    } finally { identity?.dispose(); }
  }
  async preparePairing(selectedFile: string, signal?: AbortSignal) {
    return this.run(signal, async (active, combined) => {
      if (!this.store?.read().credential) await this.replace(active, combined);
      active(); const value = this.store!.read().credential!;
      const content = encodeLocalPairingRequest({ displayName: this.name(value.reference.fingerprint256), kind: this.browser === "codex" ? "agent" : "browser", certificate: value.certificate });
      active(); writeNewLocalPublicFile(selectedFile, content, ".cvpair"); return this.state();
    });
  }
  async resetPairing(signal?: AbortSignal) { return this.run(signal, async (active, combined) => { await this.replace(active, combined); return this.state(); }); }
  async importConnection(selectedFile: string, signal?: AbortSignal) {
    return this.run(signal, async active => {
      active(); if (path.extname(selectedFile).toLowerCase() !== ".cvconnection" || !this.store?.read().credential) throw new BrowserConnectionError();
      const value = this.store.read(); const content = readLocalPublicFile(selectedFile);
      active(); this.store.importReceipt(value.revision, content); return this.state();
    });
  }
  async checkConnection(signal?: AbortSignal) {
    return this.connection(signal, async () => Object.freeze({ ...this.state(), checked: true as const }));
  }
  async searchCandidates(query: string, signal?: AbortSignal) {
    if (this.browser !== "codex") throw new BrowserConnectionError();
    return this.connection(signal, (channel, combined) => queryCandidateSearch(channel, query, combined));
  }
  private async connection<T>(signal: AbortSignal | undefined, action: (channel: Awaited<ReturnType<typeof authenticateLocalHost>>, signal: AbortSignal) => Promise<T>) {
    return this.run(signal, async (active, combined) => {
      active(); const value = this.store?.read().credential; if (!value?.receipt) throw new BrowserConnectionError();
      const receipt = parseBrowserConnectionInfo(Buffer.from(JSON.stringify(value.receipt)), value.certificate);
      const endpoint = browserDiscoveryEndpoint(readLocalPublicFile(receipt.discoveryFile), receipt);
      let identity: IssuedLocalIdentity | undefined;
      let native: Awaited<ReturnType<typeof connectNativeTransport>> | undefined;
      let channel: Awaited<ReturnType<typeof authenticateLocalHost>> | undefined;
      try {
        const loaded = await this.keys.load(localIdentityFile(this.root, value.reference.identityId), value.reference, active, combined);
        identity = loaded.identity; active(); if (loaded.shouldReEncrypt) throw new BrowserConnectionError();
        native = await connectNativeTransport({ executable: this.executable, endpoint, signal: combined }); active();
        channel = await authenticateLocalHost(native, identity, Buffer.from(receipt.hostCertificate, "base64"), combined); active();
        return await action(channel, combined);
      } finally {
        try { await channel?.close(); }
        finally { try { await native?.close(); } finally { identity?.dispose(); } }
      }
    });
  }
  close() { if (this.closed) return; this.closed = true; this.controller.abort(); this.store?.close(); }
}
