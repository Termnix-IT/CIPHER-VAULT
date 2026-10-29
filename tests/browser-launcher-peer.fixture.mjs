// Synthetic peer for launcher protocol/lifetime tests. Never used by the product entrypoint.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const mode = process.env.CIPHER_VAULT_LAUNCHER_FIXTURE;
const chunks = []; let length = 0;
for await (const chunk of process.stdin) { length += chunk.length; if (length > 65540) process.exit(1); chunks.push(chunk); }
const request = JSON.parse(Buffer.concat(chunks).subarray(4));
if (mode === "wait") {
  fs.writeFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "synthetic-peer.pid"), String(process.pid));
  setInterval(() => {}, 1000);
} else {
  const response = { version: 1, id: request.id, ok: true, result: { state: "unpaired", displayName: null, fingerprint256: null } };
  if (mode === "private-field") response.result.privateKey = "synthetic-private-canary";
  if (mode === "private-error") { response.ok = false; delete response.result; response.error = "synthetic-private-canary"; }
  if (mode === "wrong-id") response.id = "unrelated";
  const bytes = Buffer.from(JSON.stringify(response)), header = Buffer.alloc(4); header.writeUInt32LE(bytes.length);
  const frame = Buffer.concat([header, bytes]);
  if (mode === "prefix") process.stdout.write("synthetic-private-canary\n");
  if (mode === "dev-crlf") process.stdout.write(Buffer.from([13, 10]));
  process.stdout.write(frame);
  if (mode === "duplicate") process.stdout.write(frame);
  if (mode === "trailing") process.stdout.write("synthetic-private-canary");
}
