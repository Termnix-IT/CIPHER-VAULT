import { constants, X509Certificate } from "node:crypto";
import { createServer, connect, type TLSSocket } from "node:tls";
import type { NativeConnection } from "./native-transport.js";

const ready = Buffer.from("CIPHER-VAULT-LOCAL/1\n", "ascii");
const protocol = "cipher-vault-local/1";
export type LocalIdentity = Readonly<{ certificate: Buffer; privateKey: Buffer }>;
export type RegisteredLocalClient = Readonly<{ clientId: string; certificate: Buffer }>;
export class LocalClientAuthenticationError extends Error {
  readonly code = "LOCAL_CLIENT_AUTH_FAILED";
  constructor() { super("ローカル接続の認証に失敗しました"); this.name = "LocalClientAuthenticationError"; }
}
export type AuthenticatedLocalChannel = Readonly<{
  socket: TLSSocket;
  clientId: string;
  peerProcessId: number;
  close: () => Promise<void>;
}>;
function certificate(value: Buffer) {
  if (!Buffer.isBuffer(value) || value.length < 1 || value.length > 16384) throw new LocalClientAuthenticationError();
  return new X509Certificate(value);
}
function identity(value: LocalIdentity) {
  certificate(value.certificate);
  if (!Buffer.isBuffer(value.privateKey) || value.privateKey.length < 1 || value.privateKey.length > 32768) throw new LocalClientAuthenticationError();
  return { key: value.privateKey, cert: value.certificate };
}
function channel(socket: TLSSocket, native: NativeConnection, clientId: string, signal?: AbortSignal): AuthenticatedLocalChannel {
  socket.disableRenegotiation();
  const abort = () => { socket.destroy(); void native.close(); };
  signal?.addEventListener("abort", abort, { once: true });
  socket.once("close", () => { signal?.removeEventListener("abort", abort); void native.close(); });
  void native.closed.then(() => socket.destroy());
  if (signal?.aborted) abort();
  return Object.freeze({ socket, clientId, peerProcessId: native.peerProcessId, close: async () => { socket.destroy(); await native.close(); } });
}
function waitForAuthentication<T>(native: NativeConnection, signal: AbortSignal | undefined,
  start: (accept: (value: T) => void, fail: () => void) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    let finished = false;
    const fail = () => { if (!finished) { finished = true; clearTimeout(timer); void native.close(); reject(new LocalClientAuthenticationError()); } };
    const timer = setTimeout(fail, 10000);
    const abort = () => { fail(); void native.close(); };
    signal?.addEventListener("abort", abort, { once: true });
    void native.closed.then(() => { signal?.removeEventListener("abort", abort); fail(); });
    if (signal?.aborted) { fail(); return; }
    try { start(value => { if (!finished) { finished = true; clearTimeout(timer); resolve(value); } }, fail); }
    catch { fail(); }
  });
}

// No client ID, OS PID or Agent name received over the stream is accepted as identity.
export async function authenticateLocalClient(native: NativeConnection, host: LocalIdentity,
  clients: readonly RegisteredLocalClient[], signal?: AbortSignal): Promise<AuthenticatedLocalChannel> {
  try {
    if (clients.length < 1 || clients.length > 16) throw new LocalClientAuthenticationError();
    const fingerprints = new Map<string, string>(), ids = new Set<string>();
    for (const client of clients) {
      const fingerprint = certificate(client.certificate).fingerprint256;
      if (!/^[a-z0-9-]{1,64}$/.test(client.clientId) || ids.has(client.clientId) || fingerprints.has(fingerprint)) throw new LocalClientAuthenticationError();
      fingerprints.set(fingerprint, client.clientId); ids.add(client.clientId);
    }
    const options = { ...identity(host), ca: clients.map(client => client.certificate), requestCert: true, rejectUnauthorized: true,
      minVersion: "TLSv1.3" as const, maxVersion: "TLSv1.3" as const, ALPNProtocols: [protocol],
      secureOptions: constants.SSL_OP_NO_TICKET, handshakeTimeout: 10000 };
    return await waitForAuthentication(native, signal, (accept, fail) => {
      const server = createServer(options, socket => {
        socket.on("error", fail);
        const fingerprint = socket.getPeerX509Certificate()?.fingerprint256;
        const clientId = fingerprint ? fingerprints.get(fingerprint) : undefined;
        if (!socket.authorized || socket.getProtocol() !== "TLSv1.3" || socket.alpnProtocol !== protocol || socket.isSessionReused() || !clientId) { socket.destroy(); fail(); return; }
        socket.write(ready, error => error ? fail() : accept(channel(socket, native, clientId, signal)));
      });
      server.on("error", fail); server.on("tlsClientError", fail);
      // Documented Node API: a TLS server can accept any Duplex through this event.
      server.emit("connection", native.stream);
    });
  } catch { await native.close(); throw new LocalClientAuthenticationError(); }
}

export async function authenticateLocalHost(native: NativeConnection, client: LocalIdentity,
  trustedHost: Buffer, signal?: AbortSignal): Promise<AuthenticatedLocalChannel> {
  try {
    const pinned = certificate(trustedHost).fingerprint256;
    const options = { ...identity(client), socket: native.stream, ca: [trustedHost], servername: "cipher-vault.local", rejectUnauthorized: true,
      minVersion: "TLSv1.3" as const, maxVersion: "TLSv1.3" as const, ALPNProtocols: [protocol], secureOptions: constants.SSL_OP_NO_TICKET };
    return await waitForAuthentication(native, signal, (accept, fail) => {
      const socket = connect(options); socket.on("error", fail);
      socket.once("secureConnect", () => {
        if (!socket.authorized || socket.getProtocol() !== "TLSv1.3" || socket.alpnProtocol !== protocol || socket.isSessionReused() || socket.getPeerX509Certificate()?.fingerprint256 !== pinned) { socket.destroy(); fail(); return; }
        const received = Buffer.alloc(ready.length); let offset = 0;
        const read = () => {
          while (offset < received.length) {
            const bytes: Buffer | null = socket.read(Math.min(received.length - offset, Math.max(1, socket.readableLength)));
            if (!bytes) return;
            bytes.copy(received, offset); offset += bytes.length;
          }
          socket.removeListener("readable", read);
          if (!received.equals(ready)) { socket.destroy(); fail(); return; }
          accept(channel(socket, native, "desktop", signal));
        };
        socket.on("readable", read); socket.once("close", fail); read();
      });
    });
  } catch { await native.close(); throw new LocalClientAuthenticationError(); }
}
