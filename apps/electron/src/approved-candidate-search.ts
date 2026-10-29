import { BrowserConnectionError } from "./browser-message.js";
import { candidateOrigin, candidateQuery, candidateResult, type CandidateSearch } from "./candidate-search.js";

export function approvedCandidateSearch(options: {
  requireUnlocked(expected?: string): string;
  confirm(input: { displayName: string; query: string }): Promise<boolean>;
  list(): { items: readonly { id: string; serviceName: string }[] };
  detail(id: string): { url: string };
}): CandidateSearch {
  let busy = false;
  return async input => {
    const query = candidateQuery(input.query); let session: string;
    try { session = options.requireUnlocked(); } catch { throw new BrowserConnectionError(); }
    if (busy || input.signal.aborted) throw new BrowserConnectionError(); busy = true;
    const deadline = Date.now() + 30000;
    const active = () => { options.requireUnlocked(session); if (input.signal.aborted || Date.now() >= deadline) throw new BrowserConnectionError(); };
    try {
      if (!await options.confirm({ displayName: input.displayName, query })) throw new BrowserConnectionError(); active();
      const matches = options.list().items.filter(item => item.serviceName.toLowerCase().includes(query.toLowerCase()) && Buffer.byteLength(item.serviceName) <= 1024).slice(0, 20);
      const items = matches.map(item => { active(); return { id: item.id, serviceName: item.serviceName, origin: candidateOrigin(options.detail(item.id).url) }; });
      active(); return candidateResult(items);
    } catch { throw new BrowserConnectionError(); }
    finally { busy = false; }
  };
}
