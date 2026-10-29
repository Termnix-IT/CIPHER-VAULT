import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ExpiringClipboard } from "../apps/electron/dist/apps/electron/src/expiring-clipboard.js";
import { createClipboardPort, CLIPBOARD_OWNER_FORMAT } from "../apps/electron/dist/apps/electron/src/clipboard-port.js";

const hash = (text) => createHash("sha256").update(text).digest();
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function deferred() { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; }
function fixture() {
  let monotonic = 0, wall = 1000, value, clears = 0;
  const timers = [], digests = [];
  const port = {
    async write(text, owner) { value = { text, owner }; },
    async matches(owner, digest) { digests.push(digest); return value?.owner === owner && hash(value.text).equals(digest); },
    clear() { value = undefined; clears++; }
  };
  const clipboard = new ExpiringClipboard(port, () => ({ monotonic, wall }), (callback, delay) => {
    const timer = { callback, delay, cancelled: false }; timers.push(timer); return () => { timer.cancelled = true; };
  });
  return { clipboard, port, timers, digests, get value() { return value; }, set value(next) { value = next; }, get clears() { return clears; },
    advance: (ms) => { monotonic += ms; wall += ms; }, wallOnly: (ms) => { wall += ms; } };
}
const current = () => undefined;

test("the default production clock and scheduler can copy and clear without an injected timer", async () => {
  let owner;
  const clipboard = new ExpiringClipboard({
    async write(_text, token) { owner = token; },
    async matches(token) { return token === owner; },
    clear() { owner = undefined; }
  });
  await clipboard.copy("synthetic default-timer fixture", current);
  assert.equal(typeof owner, "string");
  assert.equal(await clipboard.clearOwned(), true);
  assert.equal(owner, undefined);
});

test("owned clipboard expires at thirty seconds; early timers rearm and retained digests are wiped", async () => {
  const f = fixture();
  await f.clipboard.copy("synthetic secret", current);
  assert.equal(f.timers.at(-1).delay, 30000);
  f.advance(29999); f.timers.at(-1).callback(); await flush();
  assert.equal(f.clears, 0); assert.equal(f.timers.at(-1).delay, 1);
  f.advance(1); f.timers.at(-1).callback(); await flush();
  assert.equal(f.clears, 1); assert.equal(f.value, undefined);
  assert.deepEqual(f.digests[0], Buffer.alloc(32));
});

test("new owner, changed text and nontext replacements are preserved on lock and expiry", async () => {
  for (const replacement of ["owner", "text", "image"]) {
    const f = fixture(); await f.clipboard.copy("synthetic secret", current);
    const previous = f.value;
    f.value = replacement === "owner" ? { ...previous, owner: "other-copy" } : replacement === "text" ? { ...previous, text: "new user's copy" } : undefined;
    const expected = f.value;
    assert.equal(await f.clipboard.clearOwned(), true);
    assert.equal(f.value, expected); assert.equal(f.clears, 0);
    f.advance(30000); f.timers.at(-1).callback(); await flush();
    assert.equal(f.clears, 0);
  }
});

test("cancelled expiry callbacks cannot clear a newer copy; failed native writes retain the previous deadline", async () => {
  const f = fixture(); await f.clipboard.copy("first", current);
  const oldTimer = f.timers.at(-1);
  f.advance(1000); await f.clipboard.copy("second", current);
  oldTimer.callback(); await flush(); assert.equal(f.value.text, "second");
  f.port.write = async () => { throw new Error("synthetic write failure"); };
  f.advance(1000);
  await assert.rejects(f.clipboard.copy("failed", current), /synthetic write failure/);
  assert.equal(f.timers.at(-1).delay, 29000);
  assert.equal(await f.clipboard.clearOwned(), true);
  assert.equal(f.value, undefined);
});

test("lock during an asynchronous write rejects its late result and clears its owned clipboard", async () => {
  const f = fixture(), native = f.port.write, held = deferred();
  f.port.write = async (...args) => { await held.promise; await native(...args); };
  const copying = f.clipboard.copy("late synthetic secret", current);
  const rejected = assert.rejects(copying, /状態または期限/);
  await assert.rejects(f.clipboard.copy("must not queue", current), /処理の完了/);
  const clearing = f.clipboard.clearOwned();
  held.resolve(); await rejected;
  assert.equal(await clearing, true); assert.equal(f.value, undefined);
  f.port.write = native;
  await f.clipboard.copy("fresh copy", current);
  await f.clipboard.clearOwned();
});

test("an expired, rolled-back or no-longer-authorized native write never arms a fresh lifetime", async () => {
  for (const [change, allowedAfterWrite] of [[(f) => f.advance(30000), true], [(f) => f.wallOnly(30000), true], [(f) => f.wallOnly(-1), true], [() => {}, false]]) {
    const f = fixture(), held = deferred(), native = f.port.write;
    let allowed = true;
    f.port.write = async (...args) => { await held.promise; await native(...args); };
    const copying = f.clipboard.copy("synthetic", () => { if (!allowed) throw new Error("session changed"); });
    const rejected = assert.rejects(copying);
    change(f); allowed = allowedAfterWrite;
    held.resolve(); await rejected; assert.equal(f.value, undefined);
  }
});

test("read failure preserves the clipboard for a later retry; slow stale reads cannot clear a fresh copy", async () => {
  const f = fixture(), original = f.port.matches;
  await f.clipboard.copy("synthetic", current);
  f.port.matches = async () => { throw new Error("synthetic access failure"); };
  assert.equal(await f.clipboard.clearOwned(), false); assert.equal(f.clears, 0);
  f.port.matches = original;
  assert.equal(await f.clipboard.clearOwned(), true); assert.equal(f.clears, 1);
  await f.clipboard.copy("old copy", current);
  const stale = deferred(); f.port.matches = () => stale.promise;
  const clearing = f.clipboard.clearOwned();
  await assert.rejects(f.clipboard.copy("blocked", current), /処理の完了/);
  assert.equal(await clearing, false);
  f.port.matches = original;
  await f.clipboard.copy("new copy", current);
  stale.resolve(true); await flush(); assert.equal(f.value.text, "new copy");
  await f.clipboard.clearOwned();
});

class SyntheticItem {
  constructor(values) { this.values = values; this.types = Object.keys(values); }
  async getType(type) { return new Blob([this.values[type]]); }
}
test("the Electron port writes text and owner together and matches both before clearing", async () => {
  let entries, writes = 0;
  const port = createClipboardPort({ async write(items) { entries = items; writes++; }, async read() { return entries; }, clear() { entries = []; } }, (values) => new SyntheticItem(values));
  const digest = hash("synthetic");
  await port.write("synthetic", "owner-token");
  assert.equal(writes, 1); assert.equal(entries.length, 1);
  assert.equal(await port.matches("owner-token", digest), true);
  for (const values of [
    { "text/plain": "synthetic" }, { "text/plain": "synthetic", [CLIPBOARD_OWNER_FORMAT]: "other" },
    { "text/plain": "changed", [CLIPBOARD_OWNER_FORMAT]: "owner-token" },
    { "text/plain": "synthetic", "text/html": "<b>new</b>", [CLIPBOARD_OWNER_FORMAT]: "owner-token" },
    { "text/plain": "x".repeat(1024 * 1024 + 1), [CLIPBOARD_OWNER_FORMAT]: "owner-token" }
  ]) { entries = [new SyntheticItem(values)]; assert.equal(await port.matches("owner-token", digest), false); }
  digest.fill(0);
});
