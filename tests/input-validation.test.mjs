import test from "node:test";
import assert from "node:assert/strict";
import { INPUT_LIMITS as limits, parseEntryPayload, parseMasterPassword, parseBackupPayload, parseGenerationOptions,
  parseRecord, parseEntryId, parseSessionId, parseClipboardText, parseEmptyPayload, requireArgumentCount } from "../apps/api/dist/apps/api/src/lib/input-validation.js";
import { validEntryPayload, invalidContractCases } from "./input-contract-fixtures.mjs";

test("entry write bounds count UTF-8 bytes and dense tags, accepting each exact boundary", () => {
  for (const [field, bytes] of [["serviceName", limits.serviceNameBytes], ["loginId", limits.loginIdBytes],
    ["password", limits.passwordBytes], ["notes", limits.notesBytes], ["url", limits.urlBytes], ["group", limits.groupBytes]]) {
    const value = "あ".repeat(Math.floor(bytes / 3)) + "x".repeat(bytes % 3);
    assert.equal(Buffer.byteLength(value), bytes);
    assert.equal(parseEntryPayload({ ...validEntryPayload(), [field]: value })[field], value);
    assert.throws(() => parseEntryPayload({ ...validEntryPayload(), [field]: value + "x" }), { statusCode: 413 });
  }
  assert.equal(parseEntryPayload({ ...validEntryPayload(), tags: Array(100).fill("x".repeat(256)) }).tags.length, 100);
  assert.throws(() => parseEntryPayload({ ...validEntryPayload(), tags: new Array(1) }), { statusCode: 400 });
});

test("record validation rejects inherited data, accessors, symbols, unknown and cyclic fields without evaluating them", () => {
  let getterRead = false;
  for (const value of [new Date(), new Map(), new Uint8Array(1), Object.create({ masterPassword: "inherited" }),
    { get masterPassword() { getterRead = true; return "must not be read"; } }, { [Symbol("x")]: 1 },
    JSON.parse('{"__proto__":{"polluted":true}}')]) {
    assert.throws(() => parseMasterPassword(value, false), { statusCode: 400 });
  }
  assert.equal(getterRead, false);
  const value = { ...validEntryPayload() }; value.extra = value;
  assert.throws(() => parseEntryPayload(value), { statusCode: 400 });
  assert.equal({}.polluted, undefined);
  assert.equal(parseMasterPassword(Object.assign(Object.create(null), { masterPassword: "  legacy 🔐  " }), false), "  legacy 🔐  ");
});

test("master and backup passphrases remain exact; oversized values fail before KDF", () => {
  assert.equal(parseMasterPassword({ masterPassword: "" }, false), "");
  assert.throws(() => parseMasterPassword({ masterPassword: "short" }, true), { statusCode: 400 });
  assert.equal(parseMasterPassword({ masterPassword: " x ".repeat(4096) }, false), " x ".repeat(4096));
  assert.throws(() => parseMasterPassword({ masterPassword: "x".repeat(limits.masterPasswordBytes + 1) }, false), { statusCode: 413 });
  const passphrase = "あ".repeat(1024);
  assert.equal(parseBackupPayload({ passphrase }, false).passphrase, passphrase);
  assert.equal(parseBackupPayload({ passphrase, content: "x".repeat(limits.backupFileBytes) }, true).content.length, limits.backupFileBytes);
  assert.throws(() => parseBackupPayload({ passphrase, content: "x".repeat(limits.backupFileBytes + 1) }, true), { statusCode: 413 });
});

test("canonical JSON limits also bound escaping overhead for IPC, without generic serialization of input objects", () => {
  const value = { ...validEntryPayload(), notes: "\0".repeat(limits.notesBytes) };
  assert.throws(() => parseEntryPayload(value), { statusCode: 413 });
  const long = { ...validEntryPayload(), notes: "x".repeat(limits.notesBytes + 1), tags: Array(101).fill("legacy") };
  assert.equal(parseEntryPayload(long, "backup").notes, long.notes);
  assert.throws(() => parseEntryPayload(long), { statusCode: 413 });
});

test("generation, IDs, clipboard and argument counts reject unsupported shapes and bound resources", () => {
  assert.equal(parseGenerationOptions().length, 20);
  for (const length of [NaN, Infinity, 12.5, null, "20", 11, 65]) assert.throws(() => parseGenerationOptions({ length }), { statusCode: 400 });
  assert.throws(() => parseGenerationOptions({ includeUppercase: false, includeLowercase: false, includeNumbers: false, includeSymbols: false }), { statusCode: 400 });
  for (const value of [null, [], 42, "", "bad\0id"]) assert.throws(() => parseEntryId(value), { statusCode: 400 });
  assert.equal(parseEntryId("x".repeat(limits.idBytes)).length, limits.idBytes);
  assert.throws(() => parseEntryId("x".repeat(limits.idBytes + 1)), { statusCode: 413 });
  assert.throws(() => parseSessionId("あ".repeat(43)), { statusCode: 409 });
  assert.equal(parseClipboardText("x".repeat(limits.clipboardBytes)).length, limits.clipboardBytes);
  assert.throws(() => parseClipboardText("x".repeat(limits.clipboardBytes + 1)), { statusCode: 413 });
  assert.throws(() => parseClipboardText({ text: "unexpected" }), { statusCode: 400 });
  requireArgumentCount([1, 2], 2);
  for (const args of [[], [1], [1, 2, 3]]) assert.throws(() => requireArgumentCount(args, 2), { statusCode: 400 });
  parseEmptyPayload({});
  for (const value of [null, [], { extra: 1 }]) assert.throws(() => parseEmptyPayload(value), { statusCode: 400 });
});

test("portable invalid contract fixtures carry no input values in errors", () => {
  const parsers = { createEntry: parseEntryPayload, generatePassword: parseGenerationOptions,
    exportBackup: (value) => parseBackupPayload(value, false), restoreBackup: (value) => parseBackupPayload(value, true),
    unlockVault: (value) => parseMasterPassword(value, false), resetVault: (value) => parseRecord(value, ["confirmation"]) };
  for (const item of invalidContractCases()) {
    assert.throws(() => parsers[item.operation](item.payload), { statusCode: item.status, message: item.message });
  }
});
