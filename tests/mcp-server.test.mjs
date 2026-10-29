import test from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { candidateMcpServer } from "../apps/mcp/src/server.mjs";

test("official MCP SDK exposes only candidate search and never reflects secrets or raw bridge errors", async () => {
  let calls = 0;
  const server = candidateMcpServer(async query => {
    calls++;
    if (query === "denied") throw new Error("private-error-canary");
    if (query === "bad-result") return [{ id: "candidate", serviceName: "Synthetic", origin: null, password: "private-password-canary" }];
    return [{ id: "candidate", serviceName: "Synthetic Service", origin: "https://example.test" }];
  });
  const client = new Client({ name: "synthetic-mvp-test", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport); await client.connect(clientTransport);
    const tools = await client.listTools(); assert.deepEqual(tools.tools.map(tool => tool.name), ["search_candidates"]);
    const result = await client.callTool({ name: "search_candidates", arguments: { query: "synthetic" } });
    assert.equal(result.isError, undefined); assert.equal(result.structuredContent.items[0].origin, "https://example.test");
    for (const query of ["denied", "bad-result"]) {
      const result = await client.callTool({ name: "search_candidates", arguments: { query } });
      assert.equal(result.isError, true); assert.equal(JSON.stringify(result).includes("private-"), false);
    }
    assert.equal(calls, 3);
    for (const args of [{ query: "" }, { query: "x".repeat(257) }, { query: "synthetic", extra: "private-canary" }]) {
      try { await client.callTool({ name: "search_candidates", arguments: args }); } catch { }
      assert.equal(calls, 3);
    }
    await assert.rejects(client.callTool({ name: "get_password", arguments: {} })); assert.equal(calls, 3);
  } finally { await client.close(); await server.close(); }
});
