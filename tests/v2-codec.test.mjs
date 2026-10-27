import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { TextDecoder } from "node:util";
import native from "node:crypto";
import * as codec from "../apps/api/dist/apps/api/src/crypto/v2-codec.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/crypto-compatibility.json", import.meta.url), "utf8"));
const v = fixture.draftV2;
const b64 = value => Buffer.from(value, "base64");
const root = () => Buffer.from(v.rootKeyHex, "hex");
const slotContext = () => ({ vaultId: v.vaultId, keyId: v.keyId, slotRevision: v.slotRevision });
const entryContext = () => ({ vaultId: v.vaultId, keyId: v.keyId, entryId: v.entryId, revision: v.revision });
const slot = () => ({ cryptoVersion: 2, cipher: "aes-256-gcm", ...slotContext(), slotId: "password",
  kdf: { profile: v.profile, salt: v.salt }, iv: v.wrapIv, tag: v.wrapTag, data: v.wrappedRoot });
const entry = () => ({ cryptoVersion: 2, cipher: "aes-256-gcm", ...entryContext(), iv: v.entryIv, tag: v.entryTag, data: v.entryData });
const code = expected => error => {
  assert.ok(error instanceof codec.VaultCodecError); assert.equal(error.code, expected); return true;
};
const zeroed = bytes => bytes.every(value => value === 0);
function patch(name, implementation) { mock.method(native, name, implementation); syncBuiltinESMExports(); }
function fixedRandom(...values) {
  patch("randomBytes", length => {
    const next = values.shift(); assert.ok(next, "unexpected random request"); assert.equal(next.length, length); return Buffer.from(next);
  });
}
function referenceSeal(plaintext) {
  // Synthetic malformed records only. Fixed IVs never enter the public writer API.
  const cipher = native.createCipheriv("aes-256-gcm", Buffer.from(v.entryKeyHex, "hex"), b64(v.entryIv), { authTagLength: 16 });
  cipher.setAAD(Buffer.from(v.entryAadHex, "hex"));
  return { ...entry(), data: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); });

test("importing the codec has no DB or file creation side effect", () => {
  const temporary = mkdtempSync(path.join(tmpdir(), "cipher-vault-codec-import-"));
  try {
    const marker = path.join(temporary, "not-a-data-directory"); writeFileSync(marker, "synthetic sentinel");
    const module = new URL("../apps/api/dist/apps/api/src/crypto/v2-codec.js", import.meta.url).href;
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `await import(${JSON.stringify(module)}); console.log('codec imported');`], {
      cwd: temporary, env: { ...process.env, PASSWORD_MANAGER_DATA_DIR: marker }, encoding: "utf8", timeout: 15000
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /codec imported/);
    assert.equal(readFileSync(marker, "utf8"), "synthetic sentinel");
    assert.deepEqual(readdirSync(temporary), ["not-a-data-directory"]);
  } finally {
    assert.equal(path.dirname(temporary), path.resolve(tmpdir()));
    assert.ok(path.basename(temporary).startsWith("cipher-vault-codec-import-"));
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("password wrapping and unwrapping match the independent Python vector byte for byte", async () => {
  fixedRandom(b64(v.salt), b64(v.wrapIv));
  const key = root();
  try {
    const written = await codec.wrapRootKey(key, v.masterPassword, slotContext());
    assert.deepEqual(written, slot());
    assert.equal(codec.passwordSlotAad(slotContext(), written.kdf).toString("hex"), v.wrapAadHex);
    assert.ok(codec.passwordSlotAad(slotContext(), written.kdf).toString().includes(v.salt));
    assert.equal(key.toString("hex"), v.rootKeyHex);
    const restored = await codec.unwrapRootKey(JSON.stringify(written), v.masterPassword, slotContext());
    assert.equal(restored.toString("hex"), v.rootKeyHex); restored.fill(0);
    assert.ok(Object.isFrozen(written) && Object.isFrozen(written.kdf));
  } finally { key.fill(0); }
});

test("whole-entry sealing and opening match Python and a reservation cannot replace its IV", async () => {
  fixedRandom(b64(v.entryIv));
  const key = root(); let called = 0;
  try {
    const sealed = await codec.sealEntry(key, v.entryPlaintext, entryContext(), (keyId, iv) => {
      called++; assert.equal(keyId, v.keyId); assert.deepEqual(iv, b64(v.entryIv)); iv.fill(0); return true;
    });
    assert.equal(called, 1); assert.deepEqual(sealed, entry());
    assert.equal(codec.entryAad(entryContext()).toString("hex"), v.entryAadHex);
    for (const encoded of [sealed, JSON.stringify(sealed), Buffer.from(JSON.stringify(sealed))]) {
      const plain = codec.openEntry(key, encoded, entryContext());
      assert.equal(plain.toString("utf8"), v.entryPlaintext); plain.fill(0);
    }
    assert.equal(key.toString("hex"), v.rootKeyHex);
  } finally { key.fill(0); }
});

test("normal writers generate fresh root keys, Salt and IVs", async () => {
  const first = codec.createRootKey(), second = codec.createRootKey();
  try {
    assert.equal(first.length, 32); assert.equal(second.length, 32); assert.notDeepEqual(first, second);
    const a = await codec.wrapRootKey(first, v.masterPassword, slotContext());
    const b = await codec.wrapRootKey(first, v.masterPassword, slotContext());
    assert.notEqual(a.kdf.salt, b.kdf.salt); assert.notEqual(a.iv, b.iv); assert.notEqual(a.data, b.data);
    const used = new Set();
    const reserve = (_id, iv) => { const id = iv.toString("hex"); if (used.has(id)) return false; used.add(id); return true; };
    const c = await codec.sealEntry(first, v.entryPlaintext, entryContext(), reserve);
    const d = await codec.sealEntry(first, v.entryPlaintext, entryContext(), reserve);
    assert.notEqual(c.iv, d.iv); assert.notEqual(c.data, d.data); assert.equal(used.size, 2);
  } finally { first.fill(0); second.fill(0); }
});

test("unknown formats, malformed encodings and non-data properties fail before any KDF", async () => {
  let called = 0, getter = 0;
  patch("scrypt", () => { called++; throw new Error("must not derive"); });
  const invalid = [null, [], true, "not-json", "null", Buffer.from([0xff]), " ".repeat(codec.V2_LIMITS.envelopeBytes + 1)];
  for (const [field, value] of [["cryptoVersion", 1], ["cryptoVersion", "2"], ["cipher", "aes-128-gcm"], ["slotId", "recovery"],
    ["iv", Buffer.alloc(11).toString("base64")], ["tag", Buffer.alloc(15).toString("base64")], ["data", Buffer.alloc(31).toString("base64")]]) invalid.push({ ...slot(), [field]: value });
  for (const salt of [v.salt.trimEnd().slice(0, -2), v.salt + "\n", v.salt.replace(/w==$/, "x=="), "!!!!", Buffer.alloc(17).toString("base64")]) invalid.push({ ...slot(), kdf: { profile: v.profile, salt } });
  for (const kdf of [{ profile: "arbitrary", salt: v.salt }, { profile: v.profile, salt: v.salt, N: 2 ** 25 }, { profile: v.profile, salt: v.salt, maxmem: 2 ** 40 }]) invalid.push({ ...slot(), kdf });
  invalid.push({ ...slot(), unknown: "fixture-input-canary" }, { ...slot(), [Symbol("fixture")]: true }, Object.create(slot()),
    Object.defineProperty(slot(), "tag", { get() { getter++; return v.wrapTag; } }),
    { ...slot(), toJSON() { getter++; throw new Error("fixture-input-canary"); } });
  const missing = slot(); delete missing.tag; invalid.push(missing);
  for (const input of invalid) {
    await assert.rejects(codec.unwrapRootKey(input, v.masterPassword, slotContext()), error => {
      code("INVALID_FORMAT")(error); assert.ok(!String(error).includes("fixture-input-canary")); return true;
    });
  }
  assert.equal(called, 0); assert.equal(getter, 0);
});

test("validated envelopes are immutable snapshots and allow null-prototype records", () => {
  const original = slot(); const parsed = codec.parsePasswordSlotEnvelope(Object.assign(Object.create(null), original));
  original.kdf.salt = Buffer.alloc(16).toString("base64"); original.keyId = "changed";
  assert.equal(parsed.kdf.salt, v.salt); assert.equal(parsed.keyId, v.keyId);
  assert.ok(Object.isFrozen(parsed) && Object.isFrozen(parsed.kdf));
  assert.throws(() => codec.parseEntryEnvelope(fixture.legacy.rows[0].encrypted_password), code("INVALID_FORMAT"));
});

test("AAD validates exact IDs, UTF-8 byte limits and unsigned revisions without normalization", () => {
  const exact = "あ".repeat(42) + "ab";
  assert.equal(Buffer.byteLength(exact), 128);
  assert.equal(JSON.parse(codec.entryAad({ ...entryContext(), entryId: exact }))[5], Buffer.from(exact).toString("hex"));
  const nfd = codec.entryAad({ ...entryContext(), entryId: "e\u0301" });
  assert.notDeepEqual(nfd, codec.entryAad({ ...entryContext(), entryId: "é" }));
  for (const id of ["", exact + "c", "nul\0id", "bad\ud800id"]) assert.throws(() => codec.entryAad({ ...entryContext(), entryId: id }), code("INVALID_FORMAT"));
  for (const revision of [1, 0xffffffff]) assert.ok(codec.entryAad({ ...entryContext(), revision }).length > 0);
  for (const revision of [0, -1, 1.5, 0x100000000, NaN, Infinity, "1"]) assert.throws(() => codec.entryAad({ ...entryContext(), revision }), code("INVALID_FORMAT"));
  for (const vaultId of [v.vaultId.toUpperCase(), v.vaultId.replace("4aaa", "1aaa"), "not-a-uuid"]) assert.throws(() => codec.entryAad({ ...entryContext(), vaultId }), code("INVALID_FORMAT"));
  assert.throws(() => codec.entryAad({ ...entryContext(), iv: v.entryIv }), code("INVALID_FORMAT"));
});

test("entry identity, revision, IV, tag, ciphertext and wrong root keys are authenticated", () => {
  const key = root();
  try {
    assert.throws(() => codec.openEntry(key, entry()), code("INVALID_FORMAT"));
    for (const [field, value] of [["vaultId", v.keyId], ["keyId", v.vaultId], ["entryId", "another-fixture"], ["revision", 2]]) {
      const changed = { ...entry(), [field]: value };
      assert.throws(() => codec.openEntry(key, changed, entryContext()), code("AUTHENTICATION_FAILED"));
      assert.throws(() => codec.openEntry(key, changed, { ...entryContext(), [field]: value }), code("AUTHENTICATION_FAILED"));
    }
    for (const field of ["iv", "tag", "data"]) {
      const changed = b64(entry()[field]); changed[0] ^= 1;
      assert.throws(() => codec.openEntry(key, { ...entry(), [field]: changed.toString("base64") }, entryContext()), code("AUTHENTICATION_FAILED"));
    }
    assert.throws(() => codec.openEntry(Buffer.alloc(32), entry(), entryContext()), code("AUTHENTICATION_FAILED"));
    assert.equal(key.toString("hex"), v.rootKeyHex);
  } finally { key.fill(0); }
});

test("password authentication fails generically and the expected slot cannot be self-asserted", async () => {
  await assert.rejects(codec.unwrapRootKey(slot(), "fixture-wrong-master-password", slotContext()), code("AUTHENTICATION_FAILED"));
  let called = 0;
  patch("scrypt", (_password, _salt, _length, _options, callback) => { called++; callback(null, Buffer.from(v.kdfKeyHex, "hex")); });
  await assert.rejects(codec.unwrapRootKey(slot(), v.masterPassword), code("INVALID_FORMAT"));
  await assert.rejects(codec.unwrapRootKey(slot(), v.masterPassword, { ...slotContext(), slotRevision: 2 }), code("AUTHENTICATION_FAILED"));
  assert.equal(called, 0);
  for (const field of ["iv", "tag", "data"]) {
    const changed = b64(slot()[field]); changed[0] ^= 1;
    await assert.rejects(codec.unwrapRootKey({ ...slot(), [field]: changed.toString("base64") }, v.masterPassword, slotContext()), code("AUTHENTICATION_FAILED"));
  }
  for (const [field, value] of [["slotRevision", 2], ["vaultId", v.keyId], ["keyId", v.vaultId]]) {
    await assert.rejects(codec.unwrapRootKey({ ...slot(), [field]: value }, v.masterPassword, { ...slotContext(), [field]: value }), code("AUTHENTICATION_FAILED"));
  }
  await assert.rejects(codec.unwrapRootKey({ ...slot(), kdf: { profile: v.profile, salt: Buffer.alloc(16).toString("base64") } }, v.masterPassword, slotContext()), code("AUTHENTICATION_FAILED"));
});

test("authenticated invalid entry payloads and invalid UTF-8 never become accepted plaintext", async () => {
  const key = root(), base = JSON.parse(v.entryPlaintext);
  try {
    const bad = [{ ...base, id: "another-id" }, { ...base, extra: true }, { ...base, password: "" }, { ...base, notes: null },
      { ...base, tags: [42] }, { ...base, group: 42 }, { ...base, serviceName: " " }, { ...base, notes: "invalid\ud800" },
      { ...base, createdAt: "2026-01-01T00:00:00.000Z" }, { ...base, updatedAt: "not-a-date" }, { ...base, passwordChangedAt: "2024-01-01T00:00:00.000Z" }];
    const missing = { ...base }; delete missing.password; bad.push(missing);
    for (const value of [...bad.map(value => Buffer.from(JSON.stringify(value))), Buffer.from([0xff]), Buffer.from("null"), Buffer.from("{}"), Buffer.from("\ufeff" + v.entryPlaintext)]) {
      assert.throws(() => codec.openEntry(key, referenceSeal(value), entryContext()), code("INVALID_FORMAT"));
      await assert.rejects(codec.sealEntry(key, value, entryContext(), () => assert.fail("must not reserve for invalid plaintext")), code("INVALID_FORMAT"));
    }
  } finally { key.fill(0); }
});

test("entry limits accept exactly 11 MiB, reject excess and retain legacy long fields", async () => {
  const key = root(), value = JSON.parse(v.entryPlaintext);
  try {
    value.notes = "";
    value.notes = "x".repeat(codec.V2_LIMITS.plaintextBytes - Buffer.byteLength(JSON.stringify(value)));
    const text = JSON.stringify(value); assert.equal(Buffer.byteLength(text), codec.V2_LIMITS.plaintextBytes);
    const sealed = await codec.sealEntry(key, text, entryContext(), () => true);
    const opened = codec.openEntry(key, JSON.stringify(sealed), entryContext()); assert.equal(opened.toString(), text); opened.fill(0);
    await assert.rejects(codec.sealEntry(key, text + " ", entryContext(), () => assert.fail("oversized plaintext")), code("INVALID_FORMAT"));
    assert.throws(() => codec.parseEntryEnvelope({ ...entry(), data: Buffer.alloc(codec.V2_LIMITS.plaintextBytes + 1).toString("base64") }), code("INVALID_FORMAT"));
  } finally { key.fill(0); }
});

test("nonce reservation is mandatory, bounded on collisions and fails closed on errors", async () => {
  const key = root();
  try {
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext()), code("INVALID_INPUT"));
    let attempts = 0;
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext(), () => { attempts++; return false; }), code("NONCE_UNAVAILABLE"));
    assert.equal(attempts, 8);
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext(), () => "yes"), code("NONCE_UNAVAILABLE"));
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext(), () => { throw new Error("fixture-reservation-canary"); }), error => {
      code("NONCE_UNAVAILABLE")(error); assert.ok(!String(error).includes("fixture-reservation-canary")); return true;
    });
    attempts = 0;
    const result = await codec.sealEntry(key, v.entryPlaintext, entryContext(), () => ++attempts === 3);
    assert.equal(attempts, 3); assert.ok(codec.openEntry(key, result, entryContext()).length > 0);
  } finally { key.fill(0); }
});

test("asynchronous sealing snapshots its key, plaintext and context before reservation", async () => {
  fixedRandom(b64(v.entryIv));
  const key = root(), plaintext = Buffer.from(v.entryPlaintext), context = entryContext(); let finish;
  const pending = codec.sealEntry(key, plaintext, context, () => new Promise(resolve => { finish = resolve; }));
  key.fill(0); plaintext.fill(0); context.entryId = "changed";
  finish(true);
  assert.deepEqual(await pending, entry());
});

test("abort before operations and during reservation never returns a ciphertext", async () => {
  const key = root(), before = new AbortController(), during = new AbortController();
  before.abort("fixture-secret-reason"); let finish;
  try {
    await assert.rejects(codec.wrapRootKey(key, v.masterPassword, slotContext(), { signal: before.signal }), code("CANCELLED"));
    await assert.rejects(codec.unwrapRootKey(slot(), v.masterPassword, slotContext(), { signal: before.signal }), code("CANCELLED"));
    assert.throws(() => codec.openEntry(key, entry(), entryContext(), { signal: before.signal }), code("CANCELLED"));
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext(), () => assert.fail("already aborted"), { signal: before.signal }), code("CANCELLED"));
    const pending = codec.sealEntry(key, v.entryPlaintext, entryContext(), () => new Promise(resolve => { finish = resolve; }), { signal: during.signal });
    const rejected = assert.rejects(pending, code("CANCELLED")); during.abort("fixture-secret-reason"); finish(true); await rejected;
  } finally { key.fill(0); }
});

test("cancelled native KDF holds its slot until completion and wipes password, salt and late key", async () => {
  let finish, encoded, salt, derived, calls = 0;
  patch("scrypt", (password, actualSalt, length, options, callback) => {
    calls++; encoded = password; salt = actualSalt;
    assert.deepEqual(password, Buffer.from(v.masterPassword)); assert.deepEqual(salt, b64(v.salt)); assert.equal(length, 32);
    assert.deepEqual(options, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    finish = () => { derived = Buffer.from(v.kdfKeyHex, "hex"); callback(null, derived); };
  });
  const controller = new AbortController();
  const pending = codec.unwrapRootKey(slot(), v.masterPassword, slotContext(), { signal: controller.signal });
  const rejected = assert.rejects(pending, code("CANCELLED"));
  try {
    controller.abort("fixture-secret-reason");
    await assert.rejects(codec.unwrapRootKey(slot(), v.masterPassword, slotContext()), code("BUSY"));
  } finally { finish(); }
  await rejected;
  assert.ok(zeroed(encoded) && zeroed(salt) && zeroed(derived));
  const second = codec.unwrapRootKey(slot(), v.masterPassword, slotContext()); finish();
  const restored = await second; assert.equal(restored.toString("hex"), v.rootKeyHex); restored.fill(0);
  assert.equal(calls, 2); assert.ok(zeroed(encoded) && zeroed(salt) && zeroed(derived));
});

test("native KDF failures release the slot, redact causes and wipe temporary buffers", async () => {
  const held = [];
  patch("scrypt", (password, salt, _length, _options, callback) => {
    const key = Buffer.alloc(32, 7); held.push(password, salt, key); callback(new Error("fixture-native-secret-canary"), key);
  });
  await assert.rejects(codec.unwrapRootKey(slot(), v.masterPassword, slotContext()), error => {
    code("CRYPTO_FAILED")(error); assert.ok(!String(error).includes("fixture-native-secret-canary")); return true;
  });
  assert.ok(held.every(zeroed));
  patch("scrypt", (_password, _salt, _length, _options, callback) => callback(null, Buffer.from(v.kdfKeyHex, "hex")));
  const restored = await codec.unwrapRootKey(slot(), v.masterPassword, slotContext()); restored.fill(0);
});

test("password operations snapshot their root, context and envelope before awaiting KDF", async () => {
  fixedRandom(b64(v.salt), b64(v.wrapIv));
  let finish;
  patch("scrypt", (_password, _salt, _length, _options, callback) => { finish = () => callback(null, Buffer.from(v.kdfKeyHex, "hex")); });
  const key = root(), context = slotContext();
  const wrapping = codec.wrapRootKey(key, v.masterPassword, context);
  key.fill(0); context.keyId = v.vaultId; finish();
  assert.deepEqual(await wrapping, slot());
  const envelope = slot(), expected = slotContext();
  const unwrapping = codec.unwrapRootKey(envelope, v.masterPassword, expected);
  envelope.kdf.salt = "changed"; envelope.data = "changed"; expected.vaultId = v.keyId; finish();
  const restored = await unwrapping; assert.equal(restored.toString("hex"), v.rootKeyHex); restored.fill(0);
});

test("RNG and HKDF failures are redacted and caller-owned keys remain unchanged", async () => {
  const key = root();
  try {
    patch("randomBytes", () => { throw new Error("fixture-random-secret-canary"); });
    assert.throws(() => codec.createRootKey(), code("CRYPTO_FAILED"));
    await assert.rejects(codec.wrapRootKey(key, v.masterPassword, slotContext()), code("CRYPTO_FAILED"));
    await assert.rejects(codec.sealEntry(key, v.entryPlaintext, entryContext(), () => true), code("CRYPTO_FAILED"));
    let held;
    patch("hkdfSync", (_digest, input) => { held = input; throw new Error("fixture-hkdf-secret-canary"); });
    assert.throws(() => codec.openEntry(key, entry(), entryContext()), error => {
      code("CRYPTO_FAILED")(error); assert.ok(!String(error).includes("fixture-hkdf-secret-canary")); return true;
    });
    assert.ok(zeroed(held)); assert.equal(key.toString("hex"), v.rootKeyHex);
  } finally { key.fill(0); }
});

test("authenticated but invalid plaintext is wiped after decoding fails", () => {
  const malformed = referenceSeal(Buffer.from([0xff]));
  const original = TextDecoder.prototype.decode; const decoded = [];
  mock.method(TextDecoder.prototype, "decode", function (input, ...rest) { decoded.push(input); return original.call(this, input, ...rest); });
  const key = root();
  try {
    assert.throws(() => codec.openEntry(key, malformed, entryContext()), code("INVALID_FORMAT"));
    assert.equal(decoded.length, 1); assert.ok(decoded.every(zeroed));
  } finally { key.fill(0); }
});

test("unauthenticated partial plaintext is wiped and is never sent to the JSON decoder", () => {
  const original = native.createDecipheriv; const partials = []; let decodes = 0;
  patch("createDecipheriv", (...args) => {
    const decipher = original(...args);
    return { setAAD: (...values) => decipher.setAAD(...values), setAuthTag: (...values) => decipher.setAuthTag(...values),
      update: (...values) => { const partial = decipher.update(...values); partials.push(partial); return partial; }, final: () => decipher.final() };
  });
  const decode = TextDecoder.prototype.decode;
  mock.method(TextDecoder.prototype, "decode", function (...args) { decodes++; return decode.apply(this, args); });
  const key = root(), tag = b64(v.entryTag); tag[0] ^= 1;
  try {
    assert.throws(() => codec.openEntry(key, { ...entry(), tag: tag.toString("base64") }, entryContext()), code("AUTHENTICATION_FAILED"));
    assert.equal(decodes, 0); assert.ok(partials.length > 0 && partials.every(zeroed));
    const plain = codec.openEntry(key, entry(), entryContext());
    assert.equal(plain.toString(), v.entryPlaintext); assert.ok(partials.every(zeroed)); plain.fill(0);
  } finally { key.fill(0); }
});

test("invalid key lengths, password bounds and caller-specified IV options are rejected", async () => {
  let calls = 0;
  patch("scrypt", () => { calls++; throw new Error("must not derive"); });
  const key = root();
  try {
    for (const input of [Buffer.alloc(31), Buffer.alloc(33), v.rootKeyHex, null]) {
      await assert.rejects(codec.wrapRootKey(input, v.masterPassword, slotContext()), code("INVALID_INPUT"));
      assert.throws(() => codec.openEntry(input, entry(), entryContext()), code("INVALID_INPUT"));
    }
    for (const password of [null, "short", "fixture-bad-\ud800-password", "x".repeat(codec.V2_LIMITS.passwordBytes + 1)]) await assert.rejects(codec.wrapRootKey(key, password, slotContext()), code("INVALID_INPUT"));
    await assert.rejects(codec.wrapRootKey(key, v.masterPassword, slotContext(), { iv: v.wrapIv }), code("INVALID_FORMAT"));
    await assert.rejects(codec.wrapRootKey(key, v.masterPassword, slotContext(), { signal: { aborted: false } }), code("INVALID_INPUT"));
    assert.equal(calls, 0);
  } finally { key.fill(0); }
});
