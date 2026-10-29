import test from "node:test";
import assert from "node:assert/strict";
import { VaultSession, VAULT_IDLE_TIMEOUT_MS, vaultSession, withVaultSession } from "../apps/api/dist/apps/api/src/services/vault-session.js";

function fixture() {
  let monotonic = 0, wall = 1000000;
  const timers = [];
  const session = new VaultSession(() => ({ monotonic, wall }), (callback, delay) => {
    const timer = { callback, delay, cancelled: false };
    timers.push(timer);
    return () => { timer.cancelled = true; };
  });
  session.unlock(Buffer.alloc(32, 7));
  return { session, timers, advance: (ms) => { monotonic += ms; wall += ms; },
    wallOnly: (ms) => { wall += ms; }, monotonicOnly: (ms) => { monotonic += ms; } };
}

test("the core expires without firing a timer, wipes its key and rejects late activity", () => {
  const { session, advance } = fixture();
  const id = session.getState().sessionId;
  const retainedKey = session.requireKey();
  advance(VAULT_IDLE_TIMEOUT_MS - 1);
  assert.equal(session.requireUnlocked(id), id);
  advance(1);
  assert.throws(() => session.recordActivity(id), { statusCode: 423 });
  assert.equal(session.getState().isUnlocked, false);
  assert.equal(session.getState().lockReason, "idle");
  assert.notEqual(session.getState().sessionId, id);
  assert.deepEqual(retainedKey, Buffer.alloc(32));
  assert.throws(() => session.requireKey(), { statusCode: 423 });
});

test("reads do not renew idle time; only current-generation activity renews it", () => {
  const { session, advance } = fixture();
  const id = session.getState().sessionId;
  advance(VAULT_IDLE_TIMEOUT_MS - 1000);
  session.getState(); session.requireKey(); session.requireUnlocked();
  assert.throws(() => session.recordActivity("old-generation"), { statusCode: 409 });
  session.recordActivity(id);
  advance(1000);
  assert.equal(session.getState().isUnlocked, true);
  advance(VAULT_IDLE_TIMEOUT_MS - 1000);
  assert.equal(session.getState().isUnlocked, false);
});

test("cancelled timers cannot lock a new key; repeated locks stay locked and invalidate intents", () => {
  const { session, advance, timers } = fixture();
  const events = [];
  const unsubscribe = session.subscribe((state) => events.push(state));
  const oldTimer = timers.at(-1);
  const firstKey = session.requireKey();
  session.unlock(Buffer.alloc(32, 9));
  assert.deepEqual(firstKey, Buffer.alloc(32));
  assert.equal(oldTimer.cancelled, true);
  oldTimer.callback();
  assert.equal(session.getState().isUnlocked, true);
  advance(VAULT_IDLE_TIMEOUT_MS);
  timers.at(-1).callback();
  assert.equal(events.at(-1).lockReason, "idle");
  const lockedId = session.getState().sessionId;
  session.lock();
  assert.equal(session.getState().isUnlocked, false);
  assert.throws(() => session.requireGeneration(lockedId), { statusCode: 409 });
  unsubscribe();
});

test("suspend-like wall time, monotonic elapsed time and clock rollback all fail closed", () => {
  for (const change of [
    (f) => f.wallOnly(VAULT_IDLE_TIMEOUT_MS),
    (f) => f.monotonicOnly(VAULT_IDLE_TIMEOUT_MS),
    (f) => f.wallOnly(-1),
    (f) => f.monotonicOnly(-1)
  ]) {
    const f = fixture();
    change(f);
    assert.equal(f.session.getState().isUnlocked, false);
    assert.ok(["idle", "clock-change"].includes(f.session.getState().lockReason));
  }
});

test("observer failures cannot prevent key destruction or other lock observers", () => {
  const { session } = fixture();
  let notified = false;
  session.subscribe(() => { throw new Error("synthetic observer failure"); });
  session.subscribe(() => { notified = true; });
  const key = session.requireKey();
  session.lock("window-closed");
  assert.equal(notified, true);
  assert.deepEqual(key, Buffer.alloc(32));
});

test("the transport fence rejects old generations before execution and after an await", async (t) => {
  t.after(() => vaultSession.lock());
  vaultSession.unlock(Buffer.alloc(32, 1));
  const old = vaultSession.getState().sessionId;
  let release;
  const waiting = new Promise((resolve) => { release = resolve; });
  const pending = withVaultSession(old, async () => { await waiting; return "synthetic secret result"; });
  vaultSession.lock(); vaultSession.unlock(Buffer.alloc(32, 2));
  let executed = false;
  await assert.rejects(withVaultSession(old, () => { executed = true; }), { statusCode: 409 });
  assert.equal(executed, false);
  release();
  await assert.rejects(pending, { statusCode: 409 });
  await assert.rejects(withVaultSession(undefined, () => {}), { statusCode: 409 });
});
