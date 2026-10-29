import assert from "node:assert/strict";
import { createConnection } from "node:net";

// A different same-user process claiming its parent's PID. No vault API exists here.
const [endpoint, claimed] = process.argv.slice(2);
assert.ok(endpoint && /^\d+$/.test(claimed));
const request = Buffer.alloc(4); request.writeUInt32BE(Number(claimed));
const socket = createConnection(endpoint); let response = "";
socket.setTimeout(5000, () => socket.destroy(new Error("Probe client timeout")));
socket.once("connect", () => socket.write(request));
socket.on("data", data => {
  response += data; assert.ok(response.length <= 1024);
  if (response.includes("\n")) { console.log(response.trim()); socket.destroy(); }
});
socket.on("error", error => { console.error(error.code ?? "PROBE_CLIENT_FAILED"); process.exitCode = 1; });
socket.on("close", () => { if (!response.includes("\n")) process.exitCode = 1; });
