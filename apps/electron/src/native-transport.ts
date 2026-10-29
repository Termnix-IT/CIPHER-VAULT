import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { Duplex, type Readable } from "node:stream";

export class LocalTransportError extends Error {
  readonly code = "LOCAL_TRANSPORT_UNAVAILABLE";
  constructor() { super("ローカル接続を利用できません"); this.name = "LocalTransportError"; }
}
export type NativeConnection = Readonly<{
  stream: Duplex;
  processId: number;
  peerProcessId: number;
  closed: Promise<void>;
  close: () => Promise<void>;
}>;
export type NativeTransportOptions = Readonly<{ executable: string; endpoint: string; signal?: AbortSignal }>;

export function nativeTransportExecutable(options: { packaged: boolean; resourcesPath: string; workspaceRoot: string }) {
  if (!["win32", "linux", "darwin"].includes(process.platform) || !["x64", "arm64"].includes(process.arch)) throw new LocalTransportError();
  const directory = options.packaged ? path.join(options.resourcesPath, "native-transport") :
    path.join(options.workspaceRoot, "dist-desktop/native-transport", `${process.platform}-${process.arch}`);
  return path.join(directory, process.platform === "win32" ? "cipher-vault-transport.exe" : "cipher-vault-transport");
}

function launch(mode: "serve" | "connect", options: NativeTransportOptions) {
  if (options.signal?.aborted || !path.isAbsolute(options.executable) || !path.isAbsolute(path.dirname(options.endpoint))) throw new LocalTransportError();
  try {
    const info = lstatSync(options.executable);
    if (!info.isFile() || info.isSymbolicLink() || realpathSync(options.executable) !== options.executable) throw new LocalTransportError();
  } catch { throw new LocalTransportError(); }
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(?:PASSWORD_MANAGER_|ELECTRON_RUN_AS_NODE$|NODE_OPTIONS$|NODE_PATH$|SSLKEYLOGFILE$)/i.test(key)) delete env[key];
  const child: ChildProcessWithoutNullStreams = spawn(options.executable, [mode, options.endpoint], {
    cwd: path.dirname(options.executable), env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"]
  });
  let stream: Duplex | undefined, stopped = false;
  const closed = new Promise<void>(resolve => {
    child.once("close", () => { options.signal?.removeEventListener("abort", abort); stream?.destroy(); resolve(); });
  });
  child.on("error", () => { child.stdout.destroy(new LocalTransportError()); });
  child.stdin.on("error", () => {}); child.stderr.resume(); child.stdout.on("error", () => {});
  function abort() { void close(); }
  async function close() {
    if (!stopped) { stopped = true; stream?.destroy(); child.stdin.destroy(); child.stdout.destroy(); if (child.exitCode === null && child.signalCode === null) child.kill(); }
    await closed;
  }
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();
  const connection = (peerProcessId: number): NativeConnection => {
    stream = Duplex.from({ readable: child.stdout, writable: child.stdin }); stream.on("error", () => {});
    stream.once("close", () => { void close(); });
    return Object.freeze({ stream, processId: child.pid!, peerProcessId, closed, close });
  };
  return { child, closed, close, connection };
}

async function readExactly(stream: Readable, size: number): Promise<Buffer> {
  const result = Buffer.alloc(size); let offset = 0;
  while (offset < size) {
    const value: Buffer | null = stream.read(Math.min(size - offset, Math.max(1, stream.readableLength)));
    if (value !== null) { value.copy(result, offset); offset += value.length; continue; }
    if (stream.destroyed || stream.readableEnded) throw new LocalTransportError();
    await new Promise<void>((resolve, reject) => {
      const cleanup = () => { stream.removeListener("readable", readable); stream.removeListener("end", ended); stream.removeListener("error", ended); stream.removeListener("close", ended); };
      const readable = () => { cleanup(); resolve(); }, ended = () => { cleanup(); reject(new LocalTransportError()); };
      stream.once("readable", readable); stream.once("end", ended); stream.once("error", ended); stream.once("close", ended);
    });
  }
  return result;
}
async function control(run: ReturnType<typeof launch>, event: "ready" | "peer") {
  const timer = setTimeout(() => { void run.close(); }, event === "ready" ? 10000 : 35000);
  try {
    const length = (await readExactly(run.child.stdout, 4)).readUInt32BE();
    if (length < 2 || length > 1024) throw new LocalTransportError();
    const payload = new TextDecoder("utf-8", { fatal: true }).decode(await readExactly(run.child.stdout, length));
    const value: unknown = JSON.parse(payload);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new LocalTransportError();
    const frame = value as Record<string, unknown>;
    if (Object.keys(frame).sort().join(",") !== "currentUser,event,peerProcessId,processId,protocol" || frame.protocol !== 1 || frame.event !== event ||
        frame.processId !== run.child.pid || !Number.isSafeInteger(frame.peerProcessId) ||
        (event === "ready" ? frame.peerProcessId !== 0 || frame.currentUser !== false : (frame.peerProcessId as number) <= 0 || frame.currentUser !== true)) throw new LocalTransportError();
    return frame.peerProcessId as number;
  } catch { await run.close(); throw new LocalTransportError(); }
  finally { clearTimeout(timer); }
}

// Main-process capability only. No HTTP, renderer IPC, vault references or automatic listener.
export async function listenNativeTransport(options: NativeTransportOptions) {
  const run = launch("serve", options);
  await control(run, "ready");
  const accepted = control(run, "peer").then(peer => run.connection(peer)); accepted.catch(() => {});
  return Object.freeze({ processId: run.child.pid!, accepted, closed: run.closed, close: run.close });
}
export async function connectNativeTransport(options: NativeTransportOptions) {
  const run = launch("connect", options);
  return run.connection(await control(run, "peer"));
}
