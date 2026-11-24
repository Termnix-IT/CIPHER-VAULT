import test from "node:test";
import assert from "node:assert/strict";
import { byLastUsed, loginIdOf, matchesSearch, primarySecretOf, sectionLabel, sections, sortFor } from "../apps/web/src/lib/entry-list.ts";
import { GLOBAL_SHORTCUT_FORM, GLOBAL_SHORTCUT_IN_APP, globalShortcutOf, shortcutOf } from "../apps/web/src/lib/shortcuts.ts";

const summary = (serviceName, extra = {}) => ({ id: serviceName, serviceName, loginId: `${serviceName}-id`, tags: [], updatedAt: "2026-01-01T00:00:00.000Z", createdAt: "2026-01-01T00:00:00.000Z", ...extra });
const keys = (code, modifiers = {}) => ({ code, ctrlKey: true, altKey: false, metaKey: false, shiftKey: false, ...modifiers });

test("the shortcuts take Ctrl with the listed keys only, by position", () => {
  assert.deepEqual(["KeyF", "KeyN", "KeyB", "KeyU", "KeyL"].map((code) => shortcutOf(keys(code))), ["search", "new", "copyLoginId", "openUrl", "lock"]);
  assert.equal(shortcutOf(keys("KeyC", { shiftKey: true })), "copySecret");
  assert.equal(shortcutOf(keys("KeyM", { shiftKey: true })), "compact");
  // The editing keys and anything with Alt, Win or without Ctrl stay with the field or the OS.
  for (const code of ["KeyC", "KeyV", "KeyX", "KeyA", "KeyZ", "KeyM"]) assert.equal(shortcutOf(keys(code)), null, code);
  for (const code of ["KeyF", "KeyN", "KeyB", "KeyU", "KeyL"]) assert.equal(shortcutOf(keys(code, { shiftKey: true })), null, `Shift+${code}`);
  assert.equal(shortcutOf(keys("KeyB", { altKey: true })), null);
  assert.equal(shortcutOf(keys("KeyB", { metaKey: true })), null);
  assert.equal(shortcutOf(keys("KeyB", { ctrlKey: false })), null);
});

test("recent use orders by the last use, and entries never used follow by name", () => {
  const items = [summary("b"), summary("c", { lastUsedAt: "2026-03-20T00:00:00.000Z" }), summary("a"), summary("d", { lastUsedAt: "2026-04-01T00:00:00.000Z" })];
  assert.deepEqual([...items].sort(byLastUsed).map((item) => item.serviceName), ["d", "c", "a", "b"]);
  assert.equal(sortFor("used"), byLastUsed);
  const now = Date.parse("2026-04-01T12:00:00.000Z");
  assert.deepEqual(sections([...items].sort(byLastUsed), sectionLabel("used", now)).map(([label, list]) => `${label}:${list.length}`), ["24時間以内:1", "30日以内:1", "未使用:2"]);
});

test("the search never looks at secrets", () => {
  const entry = summary("Mail", { password: "needle-secret", notes: "needle-note", tags: ["work"] });
  assert.equal(matchesSearch(entry, "needle"), false);
  assert.equal(matchesSearch(entry, "work"), true);
  assert.equal(matchesSearch(entry, "mail-id"), true);
});

test("each kind gives the value its sign-in needs", () => {
  const login = { ...summary("Login"), password: "p" };
  const apiKey = { ...summary("Key"), type: "apiKey", apiKey: { key: "k", keyId: "", expiresOn: null } };
  const card = { ...summary("Card"), type: "creditCard", card: { number: "4111", cardholder: "", expiryMonth: null, securityCode: "" } };
  const bank = { ...summary("Bank"), type: "financial", financial: { loginId: "contract", loginPassword: "lp", tradingPassword: "", extraSecrets: [] } };
  assert.deepEqual([login, apiKey, card, bank].map(loginIdOf), ["Login-id", null, null, "contract"]);
  assert.deepEqual([login, apiKey, card, bank].map(primarySecretOf), [
    { value: "p", label: "パスワード" }, { value: "k", label: "キー" }, { value: "4111", label: "カード番号" }, { value: "lp", label: "ログインパスワード" }
  ]);
});

test("the call-up key needs two or more of Ctrl, Alt and Shift and is spelled as the desktop reads it", () => {
  const named = (code, modifiers) => globalShortcutOf(keys(code, { ctrlKey: false, ...modifiers }));
  assert.deepEqual(named("Space", { ctrlKey: true, altKey: true }), { text: "Ctrl+Alt+Space" });
  assert.deepEqual(named("KeyK", { ctrlKey: true, shiftKey: true, altKey: true }), { text: "Ctrl+Alt+Shift+K" });
  assert.deepEqual(named("Digit7", { altKey: true, shiftKey: true }), { text: "Alt+Shift+7" });
  assert.deepEqual(named("F11", { ctrlKey: true, altKey: true }), { text: "Ctrl+Alt+F11" });
  // With the Windows key code, the key is the one Windows will watch: Z on a German keyboard sits where Y is.
  assert.deepEqual(globalShortcutOf({ ...keys("KeyY", { altKey: true }), keyCode: 90 }), { text: "Ctrl+Alt+Z" });
  assert.deepEqual(globalShortcutOf({ ...keys("Numpad1", { altKey: true }), keyCode: 97 }), { problem: GLOBAL_SHORTCUT_FORM });
  // Only modifiers so far: keep waiting for the key.
  assert.equal(named("ControlLeft", { ctrlKey: true }), null);
  assert.equal(named("ShiftRight", { ctrlKey: true, shiftKey: true }), null);
  for (const [code, modifiers] of [["KeyK", { ctrlKey: true }], ["F4", { altKey: true }], ["Space", { shiftKey: true }], ["KeyK", { ctrlKey: true, altKey: true, metaKey: true }],
    ["Tab", { ctrlKey: true, altKey: true }], ["F12", { ctrlKey: true, altKey: true }], ["F13", { ctrlKey: true, altKey: true }], ["Escape", { ctrlKey: true, shiftKey: true }], ["Numpad1", { ctrlKey: true, altKey: true }]]) {
    assert.deepEqual(named(code, modifiers), { problem: GLOBAL_SHORTCUT_FORM }, code);
  }
  // The app's own Ctrl+Shift keys would stop working inside the window.
  assert.deepEqual(named("KeyC", { ctrlKey: true, shiftKey: true }), { problem: GLOBAL_SHORTCUT_IN_APP });
  assert.deepEqual(named("KeyM", { ctrlKey: true, shiftKey: true }), { problem: GLOBAL_SHORTCUT_IN_APP });
});
