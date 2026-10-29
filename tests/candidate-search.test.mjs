import test from "node:test";
import assert from "node:assert/strict";
import { Duplex } from "node:stream";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { approvedCandidateSearch } from "../apps/electron/dist/apps/electron/src/approved-candidate-search.js";
import { candidateQuery, candidateResult, candidateOrigin, serveCandidateSearch } from "../apps/electron/dist/apps/electron/src/candidate-search.js";
import { BrowserMessageDecoder, encodeBrowserMessage } from "../apps/electron/dist/apps/electron/src/browser-message.js";

test("candidate response survives relay buffering until receiver close; a second request still closes the channel", async () => {
  for (const termination of ["receiver-close", "second-request"]) {
    const frames = [], items = [{ id: "candidate", serviceName: "Synthetic", origin: null }];
    let closes = 0, signal;
    const socket = new Duplex({ read() {}, write(frame, _encoding, done) { frames.push(Buffer.from(frame)); done(); } });
    const closed = once(socket, "close");
    const channel = { socket, assertCurrent() {}, async close() { closes++; socket.destroy(); } };
    const request = { version: 1, id: randomUUID(), operation: "search-candidates", query: "synthetic" };
    try {
      serveCandidateSearch(channel, { clientId: "client", displayName: "Codex", kind: "agent" }, async input => { signal = input.signal; return items; });
      socket.push(encodeBrowserMessage(request)); await setImmediate();
      assert.equal(closes, 0, "A local write callback does not acknowledge receipt through the native relay");
      assert.equal(signal.aborted, false);
      assert.deepEqual(new BrowserMessageDecoder().push(Buffer.concat(frames)), { version: 1, id: request.id, items });
      if (termination === "receiver-close") socket.destroy();
      else socket.push(encodeBrowserMessage({ ...request, id: randomUUID() }));
      await closed;
      assert.equal(signal.aborted, true);
      assert.equal(closes, termination === "receiver-close" ? 0 : 1);
    } finally { socket.destroy(); await closed; }
  }
});

test("approved search returns only bounded candidate fields and origin, without credentials or URL query", async () => {
  let reads = 0; const signal = new AbortController().signal;
  const search = approvedCandidateSearch({ requireUnlocked: () => "current", confirm: async () => true,
    list: () => ({ items: Array.from({ length: 30 }, (_, i) => ({ id: String(i), serviceName: "Synthetic Service", loginId: "private-login-canary" })) }),
    detail: () => { reads++; return { url: "https://user:secret@example.test/path?token=private-query-canary#secret", password: "private-password-canary", notes: "private-note-canary" }; } });
  const result = await search({ query: "service", clientId: "synthetic", displayName: "Codex", signal });
  assert.equal(result.length, 20); assert.equal(reads, 20); assert.equal(result[0].origin, "https://example.test");
  assert.deepEqual(Object.keys(result[0]).sort(), ["id", "origin", "serviceName"]); assert.equal(JSON.stringify(result).includes("private-"), false);
  assert.equal(candidateOrigin("javascript:secret"), null); assert.equal(candidateOrigin("broken"), null);
});
test("denial, lock, generation replacement, cancellation and concurrent dialogs never read the Vault", async () => {
  for (const scenario of ["denied", "locked", "generation", "aborted", "pending"]) {
    let reads = 0, generation = "current", release; const controller = new AbortController();
    const search = approvedCandidateSearch({ requireUnlocked(expected) { if (scenario === "locked" || (expected && expected !== generation)) throw new Error("private-error-canary"); return generation; },
      async confirm() { if (scenario === "generation") generation = "replaced"; if (scenario === "aborted") controller.abort(); if (scenario === "pending") return new Promise(resolve => { release = resolve; }); return scenario !== "denied"; },
      list: () => { reads++; return { items: [] }; }, detail: () => assert.fail("No detail reads") });
    const input = { query: "service", clientId: "synthetic", displayName: "Codex", signal: controller.signal };
    if (scenario === "pending") { const first = search(input); await assert.rejects(search(input)); release(false); await assert.rejects(first); }
    else await assert.rejects(search(input));
    assert.equal(reads, 0);
  }
});
test("candidate contracts reject unknown/private fields, unsafe origins, duplicates and invalid queries", () => {
  for (const value of ["", " ", "query\nspoof", "x".repeat(257), null]) assert.throws(() => candidateQuery(value));
  const value = { id: "id", serviceName: "Synthetic", origin: "https://example.test" };
  for (const item of [{ ...value, password: "private" }, { ...value, origin: "https://example.test/path?secret=canary" }, { ...value, origin: "file:///private" }, { ...value, id: "" }]) assert.throws(() => candidateResult([item]));
  assert.throws(() => candidateResult([value, value])); assert.throws(() => candidateResult(Array(21).fill(value)));
});
