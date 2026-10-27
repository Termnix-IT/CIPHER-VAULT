import test from "node:test";
import assert from "node:assert/strict";
import { VaultClientSession, VaultSessionChangedError } from "../apps/web/src/lib/vault-client-session.ts";

const state = (sessionId, isUnlocked = true) => ({ sessionId, isUnlocked, isConfigured: true, idleTimeoutMs: 300000 });
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("detail, generated-password and dialog results from before lock cannot reach a new view", async () => {
  for (const result of [{ password: "synthetic secret" }, { content: "synthetic backup" }, { restoredCount: 1 }]) {
    const client = new VaultClientSession(); client.observe(state("first"));
    const delayed = deferred();
    const pending = client.run(() => delayed.promise, async () => state("second"));
    client.observe(state("locked", false)); client.observe(state("second"));
    delayed.resolve(result);
    await assert.rejects(pending, VaultSessionChangedError);
  }
});

test("a delayed status read or unlock response cannot overwrite a later lock", async () => {
  for (const operation of ["status", "unlock"]) {
    const client = new VaultClientSession(); client.observe(state("first", false));
    const delayed = deferred();
    const pending = operation === "status" ? client.readStatus(() => delayed.promise) : client.change(() => delayed.promise);
    let last;
    client.subscribe((value) => { last = value; });
    client.observe(state("locked-later", false));
    delayed.resolve(state("old-unlocked"));
    await assert.rejects(pending, VaultSessionChangedError);
    assert.equal(last.sessionId, "locked-later");
    assert.equal(last.isUnlocked, false);
  }
});

test("post-response status checks detect a missed lock notification and API restarts", async () => {
  const client = new VaultClientSession(); client.observe(state("first"));
  await assert.rejects(client.run(async () => "synthetic secret", async () => state("process-restarted", false)), VaultSessionChangedError);
  await assert.rejects(client.run(async () => assert.fail("must not execute"), async () => state("first")), VaultSessionChangedError);
});

test("lock initiation immediately invalidates pending results, even before a notification arrives", async () => {
  const client = new VaultClientSession(); client.observe(state("first"));
  const delayed = deferred();
  const pending = client.run(() => delayed.promise, async () => state("first"));
  const lockResponse = deferred();
  const locking = client.change(() => lockResponse.promise);
  delayed.resolve("synthetic secret");
  await assert.rejects(pending, VaultSessionChangedError);
  lockResponse.resolve(state("locked", false));
  await locking;
});

test("the unlock notification and its matching response are accepted; unrelated errors are retained", async () => {
  const client = new VaultClientSession(); client.observe(state("initial", false));
  const opening = client.change(async () => { client.observe(state("unlocked")); return state("unlocked"); });
  await opening;
  assert.equal(await client.run(async (id) => id, async () => state("unlocked")), "unlocked");
  await assert.rejects(client.run(async () => { throw new Error("synthetic validation error"); }, async () => state("unlocked")), /synthetic validation error/);
});

test("an unavailable backend clears the local unlocked view instead of returning an unverified result", async () => {
  const client = new VaultClientSession(); client.observe(state("first"));
  let last;
  client.subscribe((value) => { last = value; });
  await assert.rejects(client.run(async () => "synthetic secret", async () => { throw new Error("offline"); }), VaultSessionChangedError);
  assert.equal(last.isUnlocked, false);
  await client.readStatus(async () => state("first"));
  assert.equal(last.isUnlocked, false);
  await client.change(async () => state("new-unlock"));
  assert.equal(last.isUnlocked, true);
});
