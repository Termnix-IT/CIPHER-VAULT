import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { rendererContentSecurityPolicy } from "../packages/shared/dist/renderer-policy.js";

// Run after npm run build:web, which writes the screen the Tauri app embeds.
const builtHtml = () => readFileSync(new URL("../apps/web/dist-tauri/index.html", import.meta.url), "utf8");

test("the screen's CSP blocks inline scripts and allows connections only to Tauri's IPC", () => {
  const policy = rendererContentSecurityPolicy();
  const directives = Object.fromEntries(policy.split("; ").map((part) => { const [name, ...values] = part.split(" "); return [name, values]; }));
  assert.deepEqual(directives["default-src"], ["'none'"]);
  assert.deepEqual(directives["script-src"], ["'self'"]);
  assert.deepEqual(directives["style-src-elem"], ["'self'"]);
  assert.deepEqual(directives["connect-src"], ["ipc:", "http://ipc.localhost"]);
  assert.deepEqual(directives["worker-src"], ["'none'"]);
  assert.ok(!policy.includes("unsafe-eval") && !policy.includes("ws:"));
});

test("Tauri's CSP and the built screen's meta CSP are the same text", () => {
  // Tauri applies both, so a difference would silently narrow or widen one of them.
  const config = JSON.parse(readFileSync(new URL("../apps/desktop/tauri.conf.json", import.meta.url), "utf8"));
  assert.equal(config.app.security.csp, rendererContentSecurityPolicy());
  const html = builtHtml();
  assert.ok(html.includes(`http-equiv="Content-Security-Policy" content="${rendererContentSecurityPolicy()}"`));
  assert.ok(!html.includes("__CIPHER_VAULT_CSP__"));
});

test("local fonts retain pinned source hashes, original font signatures and required licenses", () => {
  const fontRoot = new URL("../apps/web/public/fonts/", import.meta.url);
  const manifest = JSON.parse(readFileSync(new URL("sources.json", fontRoot), "utf8"));
  assert.match(manifest.revision, /^[0-9a-f]{40}$/);
  for (const file of manifest.files) {
    assert.ok(file.source.startsWith(`https://raw.githubusercontent.com/google/fonts/${manifest.revision}/`));
    const bytes = readFileSync(new URL(file.file, fontRoot));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), file.sha256);
    if (file.file.endsWith(".ttf")) assert.equal(bytes.subarray(0, 4).toString("hex"), "00010000");
    else assert.ok(bytes.toString("utf8").includes("SIL OPEN FONT LICENSE"));
  }
  assert.ok(!builtHtml().includes("fonts.googleapis.com"));
});
