import { app, dialog, powerMonitor } from "electron";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { encodeBrowserMessage, BrowserMessageDecoder } from "../apps/electron/dist/apps/electron/src/browser-message.js";
const root = process.env.CIPHER_VAULT_TEST_ROOT, node = process.env.CIPHER_VAULT_TEST_NODE;
const relative = path.relative(tmpdir(), root ?? ""); assert.ok(relative.startsWith("cv-mcp-desktop-") && !relative.includes(path.sep)); assert.ok(node && path.isAbsolute(node));
const profile = path.join(root, "desktop-profile"), agent = path.join(root, "agent-profile"); fs.mkdirSync(agent, { mode: 0o700 });
app.disableHardwareAcceleration(); app.setPath("userData", profile); app.setPath("sessionData", profile);
assert.equal(app.commandLine.getSwitchValue("user-data-dir"), profile);
process.env.PASSWORD_MANAGER_RENDERER_URL = "http://127.0.0.1:1"; powerMonitor.getSystemIdleState = () => "active";
let approval = true, approvals = 0;
dialog.showMessageBox = async (_window, options) => { assert.equal(options.title, "MCPの候補検索"); approvals++; return { response: approval ? 1 : 0, checkboxChecked: false }; };
dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [path.join(root, "synthetic.cvpair")] });
dialog.showSaveDialog = async () => ({ canceled: false, filePath: path.join(root, "synthetic.cvconnection") });
dialog.showErrorBox = () => { console.error("FAIL MVP desktop startup"); app.exit(1); };
let window, client, transport;
const created = new Promise(resolve => app.once("browser-window-created", (_event, value) => { window = value; value.hide(); value.webContents.setBackgroundThrottling(false); value.webContents.once("did-finish-load", resolve); }));
const timeout = setTimeout(() => { console.error("FAIL MVP timeout"); app.exit(1); }, process.env.CIPHER_VAULT_TEST_CODEX === "1" ? 240000 : 120000);
const evaluate = source => window.webContents.executeJavaScript(source);
const ipc = (name, ...args) => evaluate(`(async()=>{const p=window.passwordManager;return p[${JSON.stringify(name)}](...${JSON.stringify(args)},(await p.fetchVaultStatus()).sessionId)})()`);
async function waitFor(source) { for (let i = 0; i < 200; i++) { if (await evaluate(source)) return; await delay(40); } throw new Error("MVP UI condition timed out"); }
async function unlock() {
  await waitFor("!!document.querySelector('.cipher-form input[type=password]')");
  await evaluate("(()=>{for(const i of document.querySelectorAll('.cipher-form input[type=password]')){Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,'synthetic-mvp-master');i.dispatchEvent(new Event('input',{bubbles:true}))}document.querySelector('.cipher-form button[type=submit]').click()})()");
  await waitFor("!!document.querySelector('.cipher-dashboard')&&!document.querySelector('.sidebar-lock').disabled");
}
async function agentCommand(operation) {
  const id = randomUUID(), env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE; env.ELECTRON_NO_ATTACH_CONSOLE = "1";
  const child = spawn(process.execPath, ["tests/mcp-agent-fixture.integration.mjs", `--cipher-vault-agent=${agent}`, `--user-data-dir=${agent}`], { env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  const chunks = [], errors = []; child.stdout.on("data", chunk => chunks.push(chunk)); child.stderr.on("data", chunk => errors.push(chunk)); child.stdin.on("error", () => {});
  const done = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
  child.stdin.end(encodeBrowserMessage({ version: 1, id, operation })); const code = await done; assert.equal(code, 0, Buffer.concat(errors).toString().slice(-500));
  let bytes = Buffer.concat(chunks); if (bytes.subarray(0, 2).equals(Buffer.from([13, 10]))) bytes = bytes.subarray(2);
  const response = new BrowserMessageDecoder().push(bytes); assert.equal(response.id, id); assert.equal(response.ok, true); return response.result;
}
async function codexSearch() {
  const entry = path.join(process.env.APPDATA, "npm/node_modules/@openai/codex/bin/codex.js"); assert.ok(fs.existsSync(entry));
  const directory = path.join(root, "codex-client"); fs.mkdirSync(directory);
  const args = [entry, "exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--cd", directory,
    "-c", `mcp_servers.cipher_vault.command=${JSON.stringify(node)}`,
    "-c", `mcp_servers.cipher_vault.args=${JSON.stringify([path.resolve("apps/mcp/src/index.mjs"), "serve", "--profile", agent])}`,
    "-c", "mcp_servers.cipher_vault.tool_timeout_sec=45", "-c", 'approval_policy="never"',
    "This is an integration test with synthetic data. Use only the cipher_vault MCP search_candidates tool exactly once with query Synthetic MCP. Report its returned candidate ID, service name and origin. Do not run shell commands or use any other tool."];
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  const child = spawn(node, args, { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let output = "", errors = ""; const limit = setTimeout(() => child.kill(), 150000);
  child.stdout.on("data", chunk => { output += chunk; if (output.length > 4 * 1024 * 1024) child.kill(); });
  child.stderr.on("data", chunk => { if (errors.length < 4000) errors += chunk; });
  const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }); clearTimeout(limit);
  assert.equal(code, 0, errors.replaceAll(root, "<temporary>"));
  const events = output.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line));
  const calls = events.filter(event => event.type === "item.completed" && event.item?.type === "mcp_tool_call" && event.item.server === "cipher_vault" && event.item.tool === "search_candidates");
  if (calls.length !== 1) console.error("Codex event types:", events.map(event => ({ type: event.type, itemType: event.item?.type, server: event.item?.server, tool: event.item?.tool })));
  assert.equal(calls.length, 1); assert.equal(calls[0].item.status, "completed");
  assert.equal(JSON.stringify(calls[0]).includes("Synthetic MCP Service"), true);
  assert.equal(output.includes("private-"), false); assert.equal(errors.includes("private-"), false);
  console.log("PASS actual Codex CLI calls the candidate search MCP tool and receives the allowed synthetic candidate");
}
async function run() {
  try {
    await import("../apps/electron/dist/apps/electron/src/main.js"); await created; await unlock();
    await ipc("createEntry", { serviceName: "Synthetic MCP Service", loginId: "private-login-canary", password: "private-password-canary", notes: "private-notes-canary", url: "https://user:secret@example.test/path?token=private-url-canary", tags: [] });
    await ipc("setLocalConnectionsEnabled", true, 0);
    const prepared = await agentCommand("pair"); assert.equal(prepared.state, "request-ready");
    await ipc("selectLocalPairingRequest"); const state = await ipc("getLocalConnections");
    assert.equal(state.review.fingerprint256, prepared.fingerprint256);
    await ipc("approveLocalPairing", { pendingId: state.review.pendingId, expectedRevision: state.review.revision, fingerprint256: state.review.fingerprint256, confirmation: "MATCHED_FINGERPRINT" });
    const registration = (await ipc("getLocalConnections")).clients.find(value => value.fingerprint256 === prepared.fingerprint256);
    assert.equal(registration.kind, "agent"); await ipc("saveLocalConnectionInfo", registration.clientId);
    assert.equal((await agentCommand("import")).state, "configured");
    const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
    transport = new StdioClientTransport({ command: node, args: [path.resolve("apps/mcp/src/index.mjs"), "serve", "--profile", agent], env, stderr: "pipe" });
    let diagnostics = ""; transport.stderr?.on("data", data => { diagnostics += data.toString(); });
    client = new Client({ name: "synthetic-codex-mvp", version: "1" }); await client.connect(transport);
    assert.deepEqual((await client.listTools()).tools.map(value => value.name), ["search_candidates"]);
    const search = () => client.callTool({ name: "search_candidates", arguments: { query: "Synthetic MCP" } });
    const result = await search(); assert.equal(result.isError, undefined); assert.equal(approvals, 1);
    assert.equal(result.structuredContent.items.length, 1); assert.deepEqual(Object.keys(result.structuredContent.items[0]).sort(), ["id", "origin", "serviceName"]);
    assert.equal(result.structuredContent.items[0].origin, "https://example.test"); assert.equal(JSON.stringify(result).includes("private-"), false);
    if (process.env.CIPHER_VAULT_TEST_CODEX === "1") { await codexSearch(); assert.equal(approvals, 2); }
    const accepted = approvals;
    await ipc("lockVault"); assert.equal((await search()).isError, true); assert.equal(approvals, accepted);
    await unlock();
    for (let i = 0; i < 100 && (await ipc("getLocalConnections")).status !== "ready"; i++) await delay(40);
    approval = false; assert.equal((await search()).isError, true); assert.equal(approvals, accepted + 1);
    const current = await ipc("getLocalConnections"); await ipc("revokeLocalClient", registration.clientId, current.revision);
    approval = true; assert.equal((await search()).isError, true); assert.equal(approvals, accepted + 1);
    assert.equal(diagnostics.includes("private-"), false); await client.close(); client = undefined;
    assert.equal(fs.existsSync(path.join(agent, "data/password-manager.db")), false);
    console.log("PASS real desktop Vault, DPAPI pairing, official stdio MCP search, owner approval, lock, denial and revoke without secret fields");
    clearTimeout(timeout); app.quit();
  } catch (cause) { console.error("FAIL MVP", cause); clearTimeout(timeout); await client?.close(); app.exit(1); }
}
void run();
