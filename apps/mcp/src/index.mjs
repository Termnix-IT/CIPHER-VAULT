import path from "node:path";
import { parseArgs } from "node:util";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { candidateMcpServer } from "./server.mjs";
import { agentProfile, callAgent } from "./bridge.mjs";

try {
  const { values, positionals } = parseArgs({ options: { profile: { type: "string" } }, allowPositionals: true, strict: true });
  if (positionals.length !== 1 || !["serve", "pair", "import", "status", "config"].includes(positionals[0])) throw new Error();
  const mode = positionals[0], profile = agentProfile(values.profile, mode === "pair");
  if (mode === "serve") {
    const handle = serveStdio(() => candidateMcpServer(async (query, signal) => (await callAgent(profile, "search", query, signal)).items), { onerror: () => {} });
    const close = () => { void handle.close(); };
    process.once("SIGTERM", close); process.once("SIGINT", close);
  } else if (mode === "config") {
    console.log(`[mcp_servers.cipher_vault]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(path.resolve(process.argv[1]))}, "serve", "--profile", ${JSON.stringify(profile)}]\ntool_timeout_sec = 45`);
  } else {
    const result = await callAgent(profile, mode === "status" ? "state" : mode);
    console.log(JSON.stringify(result, null, 2));
  }
} catch { console.error("CIPHER VAULT MCPを開始できません。ビルド済みアプリ、操作名、絶対パスの--profileを確認してください。"); process.exitCode = 1; }
