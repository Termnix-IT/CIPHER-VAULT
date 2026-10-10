import test from "node:test";
import assert from "node:assert/strict";
import { createSenderGuard, isTrustedRendererUrl } from "../apps/electron/dist/apps/electron/src/renderer-security.js";

test("renderer trust requires the exact loaded document, allowing only fragment changes", () => {
  for (const expected of ["http://localhost:5173/", "file:///C:/app/web/index.html"]) {
    assert.equal(isTrustedRendererUrl(expected, expected), true);
    assert.equal(isTrustedRendererUrl(`${expected}#section`, expected), true);
    for (const candidate of ["", "about:blank", "data:text/html,test", "https://evil.example", `${expected}?changed=1`, `${expected}/other`]) {
      assert.equal(isTrustedRendererUrl(candidate, expected), false);
    }
    assert.equal(isTrustedRendererUrl(expected, null), false);
  }
  assert.equal(isTrustedRendererUrl("http://localhost:5173/other", "http://localhost:5173/"), false);
  assert.equal(isTrustedRendererUrl("http://localhost:5174/", "http://localhost:5173/"), false);
  assert.equal(isTrustedRendererUrl("http://user@localhost:5173/", "http://localhost:5173/"), false);
  assert.equal(isTrustedRendererUrl("file:///C:/app/web/other.html", "file:///C:/app/web/index.html"), false);
});

test("IPC guard rejects other windows, subframes, destroyed windows and a navigated main window", () => {
  const url = "file:///C:/app/web/index.html";
  const frame = { url };
  const contents = { mainFrame: frame, getURL: () => frame.url };
  let destroyed = false;
  let window = { webContents: contents, isDestroyed: () => destroyed };
  const guard = createSenderGuard(() => window, () => url);
  const event = { sender: contents, senderFrame: frame };
  assert.doesNotThrow(() => guard(event));
  for (const bad of [{ ...event, sender: {} }, { ...event, senderFrame: { url } }, { ...event, senderFrame: null }]) {
    assert.throws(() => guard(bad), /Invalid IPC request/);
  }
  frame.url = "https://evil.example";
  assert.throws(() => guard(event), /Invalid IPC request/);
  frame.url = url;
  contents.getURL = () => "https://evil.example";
  assert.throws(() => guard(event), /Invalid IPC request/);
  contents.getURL = () => url;
  destroyed = true;
  assert.throws(() => guard(event), /Invalid IPC request/);
  window = null;
  assert.throws(() => guard(event), /Invalid IPC request/);
});
