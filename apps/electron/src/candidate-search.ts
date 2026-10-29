import { randomUUID } from "node:crypto";
import type { AuthenticatedLocalChannel } from "./local-client-auth.js";
import { BrowserMessageDecoder, BrowserConnectionError, encodeBrowserMessage } from "./browser-message.js";

export type VaultCandidate = Readonly<{ id: string; serviceName: string; origin: string | null }>;
export type CandidateSearch = (input: Readonly<{ clientId: string; displayName: string; query: string; signal: AbortSignal }>) => Promise<readonly VaultCandidate[]>;
export function candidateQuery(value: unknown): string {
  if (typeof value !== "string" || value.trim().length < 1 || Buffer.byteLength(value) > 256 || /[\p{C}\p{Zl}\p{Zp}]/u.test(value)) throw new BrowserConnectionError();
  return value.trim();
}
export function candidateResult(value: unknown): readonly VaultCandidate[] {
  if (!Array.isArray(value) || value.length > 20) throw new BrowserConnectionError();
  const ids = new Set<string>();
  return Object.freeze(value.map(item => {
    if (!item || typeof item !== "object" || Array.isArray(item) || Object.keys(item).sort().join(",") !== "id,origin,serviceName" ||
        typeof item.id !== "string" || item.id.length < 1 || item.id.length > 128 || /[\p{C}]/u.test(item.id) || ids.has(item.id) ||
        typeof item.serviceName !== "string" || Buffer.byteLength(item.serviceName) > 1024 ||
        (item.origin !== null && (typeof item.origin !== "string" || item.origin.length > 1024 || !["https:", "http:"].includes(new URL(item.origin).protocol) || new URL(item.origin).origin !== item.origin))) throw new BrowserConnectionError();
    ids.add(item.id); return Object.freeze({ id: item.id, serviceName: item.serviceName, origin: item.origin });
  }));
}
export function candidateOrigin(value: unknown) {
  try { if (typeof value !== "string" || value.length > 8192) return null; const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && url.origin.length <= 1024 ? url.origin : null;
  } catch { return null; }
}

// Only the desktop owner installs this capability. Registration by itself grants no search.
export function serveCandidateSearch(channel: AuthenticatedLocalChannel & { assertCurrent(): void }, client: { clientId: string; displayName: string; kind: string }, search: CandidateSearch) {
  const decoder = new BrowserMessageDecoder(), controller = new AbortController(); let started = false;
  const close = () => { controller.abort(); decoder.dispose(); void channel.close(); };
  const timer = setTimeout(close, 30000);
  channel.socket.once("close", () => { clearTimeout(timer); controller.abort(); decoder.dispose(); });
  channel.socket.on("data", (chunk: Buffer) => {
    try {
      if (started || client.kind !== "agent") throw new BrowserConnectionError();
      const value = decoder.push(chunk) as Record<string, unknown> | undefined; if (value === undefined) return;
      if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "id,operation,query,version" ||
          value.version !== 1 || value.operation !== "search-candidates" || typeof value.id !== "string" ||
          !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id)) throw new BrowserConnectionError();
      const query = candidateQuery(value.query); started = true; channel.assertCurrent();
      void search({ clientId: client.clientId, displayName: client.displayName, query, signal: controller.signal }).then(async items => {
        channel.assertCurrent(); if (controller.signal.aborted || channel.socket.destroyed) throw new BrowserConnectionError();
        const frame = encodeBrowserMessage({ version: 1, id: value.id, items: candidateResult(items) });
        await new Promise<void>((resolve, reject) => channel.socket.write(frame, error => error ? reject(error) : resolve())); close();
      }).catch(close);
    } catch { close(); }
    finally { chunk.fill(0); }
  });
}
export async function queryCandidateSearch(channel: AuthenticatedLocalChannel, query: string, signal?: AbortSignal) {
  const input = candidateQuery(query), id = randomUUID(), decoder = new BrowserMessageDecoder();
  return new Promise<readonly VaultCandidate[]>((resolve, reject) => {
    let finished = false;
    const fail = () => { if (finished) return; finished = true; cleanup(); reject(new BrowserConnectionError()); void channel.close(); };
    const timer = setTimeout(fail, 35000);
    const cleanup = () => { clearTimeout(timer); decoder.dispose(); signal?.removeEventListener("abort", fail); channel.socket.removeListener("data", data); channel.socket.removeListener("close", fail); };
    const data = (chunk: Buffer) => {
      try {
        const value = decoder.push(chunk) as Record<string, unknown> | undefined; if (value === undefined) return;
        if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "id,items,version" || value.version !== 1 || value.id !== id) throw new BrowserConnectionError();
        const items = candidateResult(value.items); finished = true; cleanup(); resolve(items);
      } catch { fail(); }
    };
    channel.socket.on("data", data); channel.socket.once("close", fail); signal?.addEventListener("abort", fail, { once: true });
    if (signal?.aborted) { fail(); return; }
    channel.socket.write(encodeBrowserMessage({ version: 1, id, operation: "search-candidates", query: input }), error => { if (error) fail(); });
  });
}
