import test from "node:test";
import assert from "node:assert/strict";
import { approvedCandidateSearch } from "../apps/electron/dist/apps/electron/src/approved-candidate-search.js";
import { candidateQuery, candidateResult, candidateOrigin } from "../apps/electron/dist/apps/electron/src/candidate-search.js";

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
