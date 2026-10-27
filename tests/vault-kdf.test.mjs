import test from "node:test";
import assert from "node:assert/strict";
import { VaultUnlockGuard } from "../apps/api/dist/apps/api/src/services/vault-unlock-guard.js";
import { HttpError } from "../apps/api/dist/apps/api/src/lib/errors.js";
import { deriveVaultKey, deriveVerifier, verifyVaultKey, setActiveVaultKey, clearActiveVaultKey, decryptSecret } from "../apps/api/dist/apps/api/src/services/crypto-service.js";

// Fixed outputs from the previous scryptSync implementation, using synthetic data.
const vectors = [
  { password: "compatibility-fixture-password", key: "19c28222254d174871ffc3085a7855878b8f67e3c803fedf930c506723d9581f",
    verifier: "ws/aY0d++3RAokIhqkC+p3CalIL0nT5SC6k/q/5a3Xo=",
    ciphertext: "BAQEBAQEBAQEBAQEjYvSS4W8yJWWqTzFxKU2Z/gG/jQXG2D6Hgem0wCqoOpvUWtLmA==" },
  { password: "互換確認🔐e\u0301", key: "a918c46cfc312dc89e0a28008e112e27097141fec5547444ffb4f033d9d41443",
    verifier: "NTuNIvnHVrnBPpHma0bn2QXO/qAXYF18ccBgF3lAScM=",
    ciphertext: "BAQEBAQEBAQEBAQENBtIwCynaXooBY0n+ixip+gCeuBzwDYihHmSP9HfVX+xeGFfSA==" }
];

test("async scrypt preserves stored Salt text, Unicode, legacy keys, HMAC and existing ciphertext", async () => {
  try {
    for (const vector of vectors) {
      const key = await deriveVaultKey(vector.password, "AAECAwQFBgcICQoLDA0ODw==");
      try {
        assert.equal(key.toString("hex"), vector.key);
        assert.equal(deriveVerifier(key), vector.verifier);
        assert.equal(verifyVaultKey(key, vector.verifier), true);
        assert.equal(verifyVaultKey(key, Buffer.from(vector.key, "hex").toString("base64"), true), true);
        assert.equal(verifyVaultKey(key, Buffer.alloc(32).toString("base64")), false);
        assert.equal(verifyVaultKey(key, "invalid"), false);
        assert.equal(key.toString("hex"), vector.key);
        setActiveVaultKey(key);
        assert.equal(decryptSecret(vector.ciphertext), "合成の既存秘密");
      } finally { key.fill(0); clearActiveVaultKey(); }
    }
  } finally { clearActiveVaultKey(); }
});

test("key derivation yields to the event loop instead of completing synchronously", async () => {
  let completed = false;
  const pending = deriveVaultKey(vectors[0].password, "AAECAwQFBgcICQoLDA0ODw==");
  void pending.then(() => { completed = true; });
  await Promise.resolve();
  assert.equal(completed, false);
  const key = await pending;
  key.fill(0);
});

test("the unlock guard rejects parallel work without queuing it and releases on error", async () => {
  const guard = new VaultUnlockGuard();
  let finish;
  const pending = guard.run(() => new Promise((resolve) => { finish = resolve; }));
  await assert.rejects(guard.run(async () => assert.fail("must not start another KDF")), { statusCode: 409 });
  finish("done");
  assert.equal(await pending, "done");
  await assert.rejects(guard.run(async () => { throw new Error("native failure"); }), /native failure/);
  assert.equal(await guard.run(async () => "recovered"), "recovered");
});

test("five failures trigger exponential cooldown capped at 30 seconds; rejected retries do not extend it", async () => {
  let now = 1000;
  const guard = new VaultUnlockGuard(() => now);
  const fail = () => guard.run(async () => { throw new HttpError(401, "synthetic wrong password"); });
  for (let attempt = 1; attempt <= 12; attempt++) {
    await assert.rejects(fail(), { statusCode: 401 });
    if (attempt < 5) continue;
    const seconds = Math.min(30, 2 ** (attempt - 5));
    for (let repeat = 0; repeat < 3; repeat++) {
      await assert.rejects(guard.run(async () => assert.fail("cooldown must skip KDF")), { statusCode: 429, retryAfterSeconds: seconds });
    }
    now += seconds * 1000 - 1;
    await assert.rejects(fail(), { statusCode: 429, retryAfterSeconds: 1 });
    now++;
  }
  await guard.run(async () => "authenticated");
  for (let i = 0; i < 4; i++) await assert.rejects(fail(), { statusCode: 401 });
  assert.equal(await guard.run(async () => "success resets failures"), "success resets failures");
});

test("validation, cancellation and storage failures do not count as authentication failures", async () => {
  const guard = new VaultUnlockGuard(() => 0);
  for (const statusCode of [400, 409, 500, 400, 409, 500]) {
    await assert.rejects(guard.run(async () => { throw new HttpError(statusCode, "synthetic non-auth error"); }), { statusCode });
  }
  assert.equal(await guard.run(async () => "available"), "available");
});
