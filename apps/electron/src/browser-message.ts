import type { Readable, Writable } from "node:stream";

export const BROWSER_MESSAGE_LIMIT = 65536;
export const BROWSER_OPERATIONS = ["get-state", "prepare-pairing", "import-connection", "check-connection", "reset-pairing"] as const;
export type BrowserOperation = typeof BROWSER_OPERATIONS[number];
export type BrowserRequest = Readonly<{ version: 1; id: string; operation: BrowserOperation }>;
export class BrowserConnectionError extends Error {
  readonly code = "BROWSER_CONNECTION_UNAVAILABLE";
  constructor() { super("ブラウザ接続を完了できません"); this.name = "BrowserConnectionError"; }
}
export function browserRequest(value: unknown): BrowserRequest {
  const input = value as BrowserRequest;
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join(",") !== "id,operation,version" ||
      input.version !== 1 || typeof input.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.id) ||
      !BROWSER_OPERATIONS.includes(input.operation)) throw new BrowserConnectionError();
  return Object.freeze({ ...input });
}

// Native Messaging is little endian on our supported x64/arm64 platforms. This is deliberately
// separate from the big endian control frames used by the native local transport helper.
export class BrowserMessageDecoder {
  private header = Buffer.alloc(4);
  private headerBytes = 0;
  private payload?: Buffer;
  private payloadBytes = 0;
  private ended = false;
  push(chunk: Buffer): unknown | undefined {
    try {
      if (this.ended || !Buffer.isBuffer(chunk) || chunk.length === 0) throw new BrowserConnectionError();
      let offset = 0;
      if (this.headerBytes < 4) {
        const count = Math.min(4 - this.headerBytes, chunk.length);
        chunk.copy(this.header, this.headerBytes, 0, count); this.headerBytes += count; offset += count;
        if (this.headerBytes < 4) return;
        const length = this.header.readUInt32LE();
        if (length < 2 || length > BROWSER_MESSAGE_LIMIT) throw new BrowserConnectionError();
        this.payload = Buffer.alloc(length);
      }
      const remaining = this.payload!.length - this.payloadBytes;
      if (chunk.length - offset > remaining) throw new BrowserConnectionError();
      chunk.copy(this.payload!, this.payloadBytes, offset); this.payloadBytes += chunk.length - offset;
      if (this.payloadBytes !== this.payload!.length) return;
      this.ended = true;
      const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(this.payload));
      this.payload!.fill(0); this.payload = undefined; return value;
    } catch { this.dispose(); throw new BrowserConnectionError(); }
  }
  dispose() { this.ended = true; this.header.fill(0); this.payload?.fill(0); this.payload = undefined; }
}
export function encodeBrowserMessage(value: unknown) {
  const content = Buffer.from(JSON.stringify(value), "utf8");
  if (content.length < 2 || content.length > BROWSER_MESSAGE_LIMIT) throw new BrowserConnectionError();
  const length = Buffer.alloc(4); length.writeUInt32LE(content.length); return Buffer.concat([length, content]);
}

// One request per native process. Additional bytes, EOF and deadlines cancel the owned job.
export async function runBrowserMessage(input: Readable, output: Writable,
  action: (request: BrowserRequest, signal: AbortSignal) => Promise<unknown>, lifetimeMs = 120000) {
  const decoder = new BrowserMessageDecoder(), controller = new AbortController();
  let started = false, completed = false, request: BrowserRequest | undefined;
  const timer = setTimeout(() => controller.abort(), lifetimeMs);
  let rejectInterrupted!: (cause: Error) => void;
  const interrupted = new Promise<never>((_resolve, reject) => { rejectInterrupted = reject; });
  const abort = () => { controller.abort(); rejectInterrupted(new BrowserConnectionError()); };
  controller.signal.addEventListener("abort", abort, { once: true });
  const ended = () => { if (!completed) abort(); };
  input.on("end", ended); input.on("error", abort); input.on("close", ended); output.on("error", abort);
  const command = new Promise<unknown>((resolve, reject) => {
    const data = (chunk: Buffer) => {
      try {
        if (started) { abort(); return; }
        const value = decoder.push(chunk); if (value === undefined) return;
        request = browserRequest(value); started = true;
        void action(request, controller.signal).then(resolve, reject);
      } catch { abort(); reject(new BrowserConnectionError()); }
    };
    input.on("data", data);
    controller.signal.addEventListener("abort", () => input.removeListener("data", data), { once: true });
  });
  try {
    const reply = (value: unknown) => Promise.race([new Promise<void>((resolve, reject) =>
      output.write(encodeBrowserMessage(value), error => error ? reject(error) : resolve())), interrupted]);
    let result: unknown;
    try { result = await Promise.race([command, interrupted]); }
    catch {
      if (request && !controller.signal.aborted) await reply({ version: 1, id: request.id, ok: false, error: "UNAVAILABLE" });
      throw new BrowserConnectionError();
    }
    if (controller.signal.aborted || !request) throw new BrowserConnectionError();
    await reply({ version: 1, id: request.id, ok: true, result });
    completed = true;
  } catch {
    throw new BrowserConnectionError();
  } finally {
    completed = true; clearTimeout(timer); decoder.dispose(); controller.abort();
    input.removeListener("end", ended); input.removeListener("error", abort); input.removeListener("close", ended); output.removeListener("error", abort);
  }
}
