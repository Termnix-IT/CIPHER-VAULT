// Checks the prototype's writes against the app's own TypeScript services on synthetic vaults.
// Every scenario works on its own copy inside the new work directory, and the prototype and the
// services never have one database open at the same time. It simulates OS events and crashes; the PC
// is never locked or suspended. Requires `npm run build:api` and the `e2e` build.
// Usage: node verify-write.mjs <e2e-exe> <new-work-directory> <screenshot-directory>
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { connect, digest, fetchStatus, powershell, screenshot, sendOsMessage, sleep, startE2eBuild, unlockThroughScreen, until } from "./e2e-support.mjs";

const [exe, workArgument, screenshotDirectory] = process.argv.slice(2);
if (!exe || !workArgument || !screenshotDirectory) throw new Error("Usage: node verify-write.mjs <e2e-exe> <new-work-directory> <screenshot-directory>");
const workDirectory = path.resolve(workArgument);
if (existsSync(workDirectory)) throw new Error("The work directory must not exist yet");
mkdirSync(workDirectory);

const dist = (file) => import(new URL(`../../apps/api/dist/apps/api/src/${file}`, import.meta.url).href);
const maintenance = await dist("services/vault-maintenance-service.js");
const vaultService = await dist("services/vault-service.js");
const entryService = await dist("services/entry-service.js");
const passwordService = await dist("services/password-service.js");
const { parseVaultEntryPayload } = await dist("lib/vault-entry-validation.js");

const sampleRoot = path.join(workDirectory, "sample");
const created = spawnSync(process.execPath, [fileURLToPath(new URL("./create-sample-vault.mjs", import.meta.url)), sampleRoot], { encoding: "utf8" });
if (created.status !== 0) throw new Error(`The sample vault could not be created: ${created.stderr}`);
const sample = JSON.parse(created.stdout);
if (sample.testOnly !== true) throw new Error("Refusing data that is not marked as a synthetic sample");

const WM_POWERBROADCAST = 0x218, PBT_APMSUSPEND = 4, PBT_APMRESUMESUSPEND = 7;
const READ_ONLY = "この試作版は読取専用です";
let copies = 0, nextPort = 9340;

function copyVault(format) {
  const root = path.join(workDirectory, `${format}-${++copies}`);
  if (format === "v2") {
    cpSync(sampleRoot, root, { recursive: true });
    return { format, root, database: path.join(root, path.relative(sampleRoot, sample.v2.database)), password: sample.v2.password };
  }
  // On its own, so that the app's services treat the directory as a legacy vault.
  mkdirSync(root);
  copyFileSync(sample.legacy.database, path.join(root, "password-manager.db"));
  return { format, root, database: path.join(root, "password-manager.db"), password: sample.legacy.password };
}

const plain = (value) => value === undefined ? value : JSON.parse(JSON.stringify(value));

function nodeEngine() {
  const attempt = async (run) => {
    try { return { ok: plain(await run()) }; } catch (error) { return { error: error.message }; }
  };
  return {
    create: (payload) => attempt(() => entryService.createEntry(payload)),
    update: (id, payload) => attempt(() => entryService.updateEntry(id, payload)),
    remove: (id) => attempt(() => entryService.deleteEntry(id)),
    group: (payload) => attempt(() => entryService.setEntriesGroup(payload)),
    generate: (options) => attempt(() => passwordService.generatePassword(options)),
    get: (id) => attempt(() => entryService.getEntryById(id)),
    list: () => attempt(() => entryService.listEntries())
  };
}

function rustEngine(page, sessionId) {
  const literal = JSON.stringify;
  const call = async (method, ...args) => {
    // Long runs must not reach the idle lock, which has its own checks.
    await page.evaluate(`window.passwordManager.recordVaultActivity(${literal(sessionId)})`);
    return page.evaluate(`window.passwordManager.${method}(${[...args, sessionId].map(literal).join(", ")}).then((ok) => ({ ok }), (error) => ({ error: error.message }))`);
  };
  return {
    create: (payload) => call("createEntry", payload),
    update: (id, payload) => call("updateEntry", id, payload),
    remove: (id) => call("deleteEntry", id),
    group: (payload) => call("setEntriesGroup", payload),
    generate: (options) => call("generatePassword", options),
    get: (id) => call("fetchEntry", id),
    list: () => call("fetchEntries")
  };
}

async function withNode(vault, action) {
  maintenance.openApplicationVault({ dataDirectory: vault.root });
  try {
    await vaultService.unlockVault({ masterPassword: vault.password });
    return await action(nodeEngine());
  } finally {
    vaultService.lockVault();
    maintenance.closeApplicationVault();
  }
}

async function stop(child) {
  child.kill();
  await until("process exit", () => child.exitCode !== null || child.signalCode !== null);
  // WebView2 helpers release the debugging port and the profile a moment later.
  await sleep(800);
}

async function withRust(vault, action, { write = true, environment = {} } = {}) {
  const started = startE2eBuild(exe, vault.database, nextPort++, { ...(write ? { CIPHER_VAULT_POC_WRITE: "1" } : {}), ...environment });
  let page;
  try {
    // connect() accepts native confirmations, which an override set before the document loads would not cover.
    page = await connect(nextPort - 1);
    const sessionId = await unlockThroughScreen(page, vault.password);
    return await action({ page, sessionId, engine: rustEngine(page, sessionId), ...started });
  } catch (error) {
    if (page) await screenshot(page, screenshotDirectory, `failure-${vault.format}-${Date.now()}`).catch(() => undefined);
    console.error(JSON.stringify({ vault: vault.format, stderr: started.errors.join(""), console: [...new Set(page?.messages ?? [])] }));
    throw error;
  } finally {
    page?.close();
    await stop(started.child);
  }
}

// ---- Differential matrix: the same inputs and the same order for both implementations.

const SPACES = ["﻿", " ", "\u0085", "​", "　", " ", " ", "\t", "\n", "᠎"];
const repeat = (text, count) => text.repeat(count);
const L = { serviceName: "合成", loginId: "synthetic-id", password: "synthetic-password" };
const API = (detail = {}, extra = {}) => ({ type: "apiKey", serviceName: "合成API", apiKey: { key: "synthetic-key", ...detail }, ...extra });
const CARD = (detail = {}, extra = {}) => ({ type: "creditCard", serviceName: "合成カード", card: { number: "4111111111111111", ...detail }, ...extra });
const FIN = (detail = {}, extra = {}) => ({ type: "financial", serviceName: "合成銀行", financial: { loginId: "synthetic-contract", loginPassword: "synthetic-login", ...detail }, ...extra });
const without = (object, name) => { const copy = { ...object }; delete copy[name]; return copy; };

/** The first size the app refuses, found with its own parser, so the checks sit on the exact limit. */
function firstRefusedSize(make) {
  const refused = (size) => {
    try { parseVaultEntryPayload(make(size)); return false; } catch (error) { assert.equal(error.message, "リクエストの容量が上限を超えています"); return true; }
  };
  // The upper bound keeps the notes under their own limit, so only the request size can refuse.
  let low = 0, high = 30000;
  assert.ok(refused(high));
  while (high - low > 1) {
    const middle = Math.floor((low + high) / 2);
    if (refused(middle)) high = middle; else low = middle;
  }
  return high;
}

function matrix() {
  const cases = [];
  const add = (label, payload) => cases.push([label, payload]);
  for (const space of SPACES) {
    const code = space.codePointAt(0).toString(16);
    const around = (text) => `${space}${text}${space}`;
    add(`every field around U+${code}`, { serviceName: around("S"), loginId: around("I"), password: around("P"), notes: around("N"), url: around("U"), group: around("G"), tags: [around("T")] });
    add(`name is only U+${code}`, { ...L, serviceName: space });
    add(`login id is only U+${code}`, { ...L, loginId: space });
    add(`password is only U+${code}`, { ...L, password: space });
    add(`url and group are only U+${code}`, { ...L, url: space, group: space });
    add(`typed name is only U+${code}`, API({}, { serviceName: space }));
    add(`typed fields around U+${code}`, FIN({ loginId: around("I"), loginPassword: around("P"), tradingPassword: around("T"), extraSecrets: [{ label: around("L"), value: around("V") }] }, { serviceName: around("S"), url: around("U"), group: around("G") }));
  }
  add("NUL and emoji", { serviceName: "a\0b😀", loginId: "😀\0", password: "\0", notes: "\0😀", url: "\0", group: "\0", tags: ["\0", "😀"] });

  for (const [field, limit] of [["serviceName", 1024], ["loginId", 4096], ["password", 65536], ["notes", 262144], ["url", 8192], ["group", 1024]]) {
    add(`${field} at ${limit} bytes`, { ...L, [field]: repeat("a", limit) });
    add(`${field} one byte over`, { ...L, [field]: repeat("a", limit + 1) });
    add(`${field} multibyte at the limit`, { ...L, [field]: repeat("あ", Math.floor(limit / 3)) });
    add(`${field} multibyte over`, { ...L, [field]: repeat("あ", Math.floor(limit / 3) + 1) });
    add(`${field} wrong type`, { ...L, [field]: 1 });
    add(`${field} null`, { ...L, [field]: null });
    add(`${field} missing`, without(L, field));
  }
  add("tags at the count limit", { ...L, tags: Array(100).fill("t") });
  add("tags over the count limit", { ...L, tags: Array(101).fill("t") });
  add("tag at its limit", { ...L, tags: [repeat("t", 256)] });
  add("tag over its limit", { ...L, tags: [repeat("t", 257)] });
  add("tags wrong type", { ...L, tags: "t" });
  add("tags object", { ...L, tags: {} });
  add("tag wrong type", { ...L, tags: [1] });
  add("tag null", { ...L, tags: [null] });
  add("tags null", { ...L, tags: null });
  add("empty notes and url", { ...L, notes: "", url: "", group: "", tags: [] });

  const escapes = "\u0001\"\\\n 😀é";
  const loginOfSize = (size) => ({ ...L, notes: repeat(escapes, 1000) + repeat("\u0001", 170000) + repeat("a", size) });
  const apiOfSize = (size) => API({}, { notes: repeat(escapes, 1000) + repeat("\u0001", 170000) + repeat("a", size) });
  const loginLimit = firstRefusedSize(loginOfSize), apiLimit = firstRefusedSize(apiOfSize);
  add("login request at the exact limit", loginOfSize(loginLimit - 1));
  add("login request one byte over", loginOfSize(loginLimit));
  add("typed request at the exact limit", apiOfSize(apiLimit - 1));
  add("typed request one byte over", apiOfSize(apiLimit));

  for (const value of [null, [], "x", 1, true, {}]) add(`payload ${JSON.stringify(value)}`, value);
  add("unknown field", { ...L, extra: 1 });
  add("type login", { ...L, type: "login" });
  add("type login with a detail", { ...L, type: "login", apiKey: { key: "k" } });
  add("no type with a detail", { ...L, apiKey: { key: "k" } });
  for (const type of ["other", null, 1, "", true, ["apiKey"]]) add(`type ${JSON.stringify(type)}`, { ...L, type });

  add("api key complete", API({ keyId: " id ", expiresOn: "2029-12-31" }, { notes: " n ", url: " u ", group: " g ", tags: [" t "] }));
  for (const date of ["2028-02-29", "2029-02-29", "2029-2-1", "2029-02-28\n", "", "0000-01-01", "9999-12-31", "2029-13-01", "2029-00-10", "2029-01-00", "2029-04-31", "２０２９-01-01", "2029-12", null, 1]) add(`api key date ${JSON.stringify(date)}`, API({ expiresOn: date }));
  add("api key without a key", { type: "apiKey", serviceName: "x", apiKey: {} });
  add("api key empty", API({ key: "" }));
  add("api key spaces kept", API({ key: "  k  " }));
  add("api key over its limit", API({ key: repeat("k", 65537) }));
  add("api key id null", API({ keyId: null }));
  add("api key id over its limit", API({ keyId: repeat("k", 4097) }));
  add("api key unknown detail", API({ other: 1 }));
  for (const detail of [null, [], "x"]) add(`api key detail ${JSON.stringify(detail)}`, { type: "apiKey", serviceName: "x", apiKey: detail });
  add("api key detail missing", { type: "apiKey", serviceName: "x" });
  add("api key with a card detail", API({}, { card: { number: "4111111111111111" } }));
  add("api key with login fields", API({}, { loginId: "x" }));
  add("typed name missing", without(API(), "serviceName"));
  add("typed name over its limit", API({}, { serviceName: repeat("n", 1025) }));
  add("typed tags wrong type", API({}, { tags: "t" }));
  add("typed tags over the limit", API({}, { tags: Array(101).fill("t") }));
  add("typed tag wrong type", API({}, { tags: [1] }));
  add("typed notes null", API({}, { notes: null }));

  for (const number of ["4111-1111 1111 1111", repeat("1", 11), repeat("1", 12), repeat("1", 19), repeat("1", 20), "４１１１１１１１１１１１１１１１", "4111\t1111\t1111\t1111", "4111 1111 1111", "abcd1111111111", repeat("1", 65), repeat(" ", 64), "", null]) add(`card number ${JSON.stringify(number)}`, CARD({ number }));
  for (const securityCode of ["", "12", "123", "1234", "12345", "１２３", "abc", " 12", null, 123]) add(`security code ${JSON.stringify(securityCode)}`, CARD({ securityCode }));
  for (const expiryMonth of ["2029-12", "2029-13", "2029-00", "2029-12-01", "", null, "0000-01"]) add(`card month ${JSON.stringify(expiryMonth)}`, CARD({ expiryMonth }));
  add("cardholder at its limit", CARD({ cardholder: repeat("c", 1024) }));
  add("cardholder over its limit", CARD({ cardholder: repeat("c", 1025) }));
  add("cardholder spaces kept", CARD({ cardholder: " c " }));
  add("card unknown detail", CARD({ other: 1 }));

  const extras = (count) => Array.from({ length: count }, (_value, index) => ({ label: `L${index}`, value: `V${index}` }));
  add("financial complete", FIN({ tradingPassword: " t ", extraSecrets: extras(8) }));
  add("financial too many extras", FIN({ extraSecrets: extras(9) }));
  add("financial blank login id", FIN({ loginId: "  " }));
  add("financial empty password", FIN({ loginPassword: "" }));
  add("financial trading null", FIN({ tradingPassword: null }));
  add("financial trading wrong type", FIN({ tradingPassword: 1 }));
  add("financial extras null", FIN({ extraSecrets: null }));
  add("financial extras wrong type", FIN({ extraSecrets: "x" }));
  for (const label of ["ログインID", "ログインパスワード", "取引パスワード", "URL", " URL ", "", "  ", repeat("l", 256), repeat("l", 257)]) add(`extra label ${label.slice(0, 12)} (${label.length})`, FIN({ extraSecrets: [{ label, value: "v" }] }));
  add("extra label duplicate", FIN({ extraSecrets: [{ label: "a", value: "1" }, { label: "a", value: "2" }] }));
  add("extra label duplicate after trimming", FIN({ extraSecrets: [{ label: "a", value: "1" }, { label: "﻿a ", value: "2" }] }));
  add("extra value empty", FIN({ extraSecrets: [{ label: "a", value: "" }] }));
  add("extra value at its limit", FIN({ extraSecrets: [{ label: "a", value: repeat("v", 65536) }] }));
  add("extra value over its limit", FIN({ extraSecrets: [{ label: "a", value: repeat("v", 65537) }] }));
  add("extra not an object", FIN({ extraSecrets: ["x"] }));
  add("extra unknown field", FIN({ extraSecrets: [{ label: "a", value: "b", c: 1 }] }));
  add("extra label wrong type", FIN({ extraSecrets: [{ label: 1, value: "b" }] }));
  return cases;
}

const GENERATION_OPTIONS = [null, [], "x", {}, { length: 12 }, { length: 64 }, { length: 11 }, { length: 65 }, { length: 12.5 }, { length: 20.0 }, { length: "20" }, { length: null },
  { length: 1e3 }, { other: 1 }, { includeUppercase: "x" }, { includeUppercase: null }, { includeUppercase: false, includeLowercase: false, includeNumbers: false, includeSymbols: false },
  { includeUppercase: false, includeLowercase: false, includeNumbers: false }, { includeUppercase: false, includeLowercase: false, includeSymbols: false }];

function cleanEntry(value) {
  if (value === null || typeof value !== "object" || !("id" in value)) return value;
  const { id, createdAt, updatedAt, passwordChangedAt, ...rest } = value;
  const changed = passwordChangedAt === null ? "null" : passwordChangedAt === updatedAt ? "at update" : passwordChangedAt === createdAt ? "at creation" : "other";
  return { ...rest, id: typeof id, ...("createdAt" in value ? { ordered: createdAt <= updatedAt } : {}), ...("passwordChangedAt" in value ? { changed } : {}) };
}
const cleanList = (value) => ({ items: value.items.map(cleanEntry).map((item) => JSON.stringify(item, Object.keys(item).sort())).sort() });
function cleanGenerated({ password }) {
  const has = (pattern) => pattern.test(password);
  return { length: password.length, upper: has(/[A-Z]/), lower: has(/[a-z]/), digit: has(/\d/), symbol: has(/[^A-Za-z0-9]/), excluded: has(/[IOl01]/) };
}

async function differentialScenario(engine, vaultFormat) {
  const log = [];
  const step = async (label, run, clean = cleanEntry) => {
    const outcome = await run();
    log.push({ label, ...("error" in outcome ? { error: outcome.error } : { ok: clean(outcome.ok) }) });
    return outcome.ok;
  };
  for (const [label, payload] of matrix()) await step(`create: ${label}`, () => engine.create(payload));

  const login = await step("login to edit", () => engine.create({ ...L, notes: "n", group: "g", tags: ["t"], url: "https://example.test/" }));
  const edited = { ...L, serviceName: "編集後" };
  await sleep(5);
  await step("update keeping the password", () => engine.update(login.id, edited));
  await sleep(5);
  await step("update changing the password", () => engine.update(login.id, { ...edited, password: "another-synthetic-password" }));
  await step("update bad payload", () => engine.update(login.id, { ...edited, password: "" }));
  await step("update unknown field", () => engine.update(login.id, { ...edited, extra: 1 }));
  await step("update to another kind", () => engine.update(login.id, API()));
  await step("update type login", () => engine.update(login.id, { ...edited, type: "login" }));
  for (const id of ["missing", "", "\0", repeat("i", 128), repeat("i", 129), 1, null, [], {}]) {
    await step(`update id ${JSON.stringify(id).slice(0, 20)}`, () => engine.update(id, edited));
    await step(`update id ${JSON.stringify(id).slice(0, 20)} with a bad payload`, () => engine.update(id, {}));
    await step(`update id ${JSON.stringify(id).slice(0, 20)} with a typed payload`, () => engine.update(id, API()));
    await step(`delete id ${JSON.stringify(id).slice(0, 20)}`, () => engine.remove(id));
  }
  const apiKey = await step("api key to edit", () => engine.create(API({ expiresOn: "2029-12-31" })));
  const typedId = apiKey?.id ?? "no-typed-entry";
  await step("typed update", () => engine.update(typedId, API({ key: "another-key" }, { serviceName: " 変更 " })));
  await step("typed update to a login", () => engine.update(typedId, edited));
  await step("typed update to a card", () => engine.update(typedId, CARD()));
  await step("typed read", () => engine.get(typedId));

  const second = await step("second login", () => engine.create({ ...L, serviceName: "二件目" }));
  const ids = [login.id, second.id];
  for (const [label, payload] of [["not an object", null], ["array", []], ["no ids", { group: "g" }], ["ids wrong type", { ids: "x", group: "g" }], ["ids empty", { ids: [], group: "g" }], ["id wrong type", { ids: [1], group: "g" }],
    ["id empty", { ids: [""], group: "g" }], ["id over its limit", { ids: [repeat("i", 129)], group: "g" }], ["too many ids", { ids: Array.from({ length: 10001 }, (_value, index) => `id-${index}`), group: "g" }],
    ["no group", { ids }], ["group empty", { ids, group: "" }], ["group spaces", { ids, group: " ﻿ " }], ["reserved name", { ids, group: "グループなし" }], ["reserved name with spaces", { ids, group: " グループなし " }],
    ["group wrong type", { ids, group: 1 }], ["group over its limit", { ids, group: repeat("g", 1025) }], ["unknown field", { ids, group: "g", other: 1 }], ["unknown id", { ids: [login.id, "missing"], group: "ロールバック" }]]) {
    await step(`group: ${label}`, () => engine.group(payload));
  }
  await step("group: set with duplicates", () => engine.group({ ids: [...ids, login.id], group: " 新しいグループ " }));
  await step("group: unchanged", () => engine.group({ ids, group: "新しいグループ" }));
  await step("group: read after setting", () => engine.get(login.id));
  await step("group: cleared", () => engine.group({ ids, group: null }));
  await step("group: read after clearing", () => engine.get(second.id));
  for (const options of GENERATION_OPTIONS) await step(`generate ${JSON.stringify(options)}`, () => engine.generate(options), cleanGenerated);

  await step("delete", () => engine.remove(login.id));
  await step("delete again", () => engine.remove(login.id));
  await step("read deleted", () => engine.get(login.id));
  await step("update deleted", () => engine.update(login.id, edited));
  await step("group with a deleted id", () => engine.group({ ids: [second.id, login.id], group: "x" }));
  await step("read missing", () => engine.get("missing"));
  await step("list", () => engine.list(), cleanList);
  assert.equal(log.filter((entry) => entry.label.startsWith("create:")).length, matrix().length, vaultFormat);
  return log;
}

function assertSameLog(actual, expected, description) {
  assert.equal(actual.length, expected.length, description);
  for (let index = 0; index < expected.length; index++) {
    try { assert.deepEqual(actual[index], expected[index]); } catch {
      throw new Error(`${description}: ${expected[index].label}\nRust: ${JSON.stringify(actual[index]).slice(0, 600)}\nNode: ${JSON.stringify(expected[index]).slice(0, 600)}`);
    }
  }
}

async function snapshot(engine) {
  const list = await engine.list();
  assert.ok(list.ok, `The list could not be read: ${list.error}`);
  const entries = {};
  for (const { id } of list.ok.items) {
    const entry = await engine.get(id);
    assert.ok(entry.ok, `An entry could not be read: ${entry.error}`);
    entries[id] = entry.ok;
  }
  return { summaries: Object.fromEntries(list.ok.items.map((item) => [item.id, item])), entries };
}

function assertSameSnapshot(actual, expected, description) {
  assert.deepEqual(Object.keys(actual.entries).sort(), Object.keys(expected.entries).sort(), description);
  for (const id of Object.keys(expected.entries)) {
    assert.deepEqual(actual.entries[id], expected.entries[id], `${description}: entry`);
    assert.deepEqual(actual.summaries[id], expected.summaries[id], `${description}: summary`);
  }
}

function v2Counts(database) {
  const connection = new Database(database, { readonly: true });
  try {
    return {
      encryptionCount: connection.prepare("SELECT encryption_count AS value FROM vault_header").get().value,
      nonces: connection.prepare("SELECT COUNT(*) AS value FROM vault_nonces").get().value,
      entries: connection.prepare("SELECT COUNT(*) AS value FROM vault_entries WHERE envelope IS NOT NULL").get().value,
      tombstones: connection.prepare("SELECT COUNT(*) AS value FROM vault_entries WHERE envelope IS NULL").get().value,
      userVersion: connection.pragma("user_version", { simple: true })
    };
  } finally { connection.close(); }
}

async function checkDifferential(format) {
  const rustVault = copyVault(format), nodeVault = copyVault(format);
  const rust = await withRust(rustVault, async ({ engine }) => ({ log: await differentialScenario(engine, format), snapshot: await snapshot(engine) }));
  const node = await withNode(nodeVault, async (engine) => ({ log: await differentialScenario(engine, format), snapshot: await snapshot(engine) }));
  assertSameLog(rust.log, node.log, `${format} differs from the app`);

  // Each side must accept everything the other wrote, under its own strict checks.
  const nodeReadsRust = await withNode(rustVault, snapshot);
  assertSameSnapshot(nodeReadsRust, rust.snapshot, `${format}: the app reads what Rust wrote`);
  const rustReadsNode = await withRust(nodeVault, ({ engine }) => snapshot(engine));
  assertSameSnapshot(rustReadsNode, node.snapshot, `${format}: Rust reads what the app wrote`);

  const result = { steps: rust.log.length, accepted: rust.log.filter((entry) => "ok" in entry).length, refused: rust.log.filter((entry) => "error" in entry).length, distinctMessages: new Set(rust.log.map((entry) => entry.error).filter(Boolean)).size, entriesCrossRead: Object.keys(nodeReadsRust.entries).length };
  if (format === "v2") {
    result.counts = v2Counts(rustVault.database);
    assert.equal(result.counts.encryptionCount, result.counts.nonces);
  }
  return { ...result, vault: rustVault };
}

async function checkRoundTrip(format, vault) {
  const nextLogin = (name) => ({ ...L, serviceName: name, notes: `${name} のメモ`, password: `${name}-synthetic` });
  const first = await withRust(vault, async ({ engine }) => {
    const toUpdate = (await engine.create(nextLogin("Rust作成A"))).ok, toDelete = (await engine.create(nextLogin("Rust作成B"))).ok;
    return { ids: { toUpdate: toUpdate.id, toDelete: toDelete.id }, snapshot: await snapshot(engine) };
  });
  const second = await withNode(vault, async (engine) => {
    assertSameSnapshot(await snapshot(engine), first.snapshot, `${format}: the app reads Rust's writes`);
    assert.ok((await engine.update(first.ids.toUpdate, nextLogin("Nodeが更新"))).ok);
    assert.ok((await engine.remove(first.ids.toDelete)).ok);
    const created = (await engine.create(nextLogin("Node作成"))).ok;
    return { created: created.id, snapshot: await snapshot(engine) };
  });
  const third = await withRust(vault, async ({ engine }) => {
    assertSameSnapshot(await snapshot(engine), second.snapshot, `${format}: Rust reads the app's writes`);
    assert.equal((await engine.get(first.ids.toDelete)).error, "エントリが見つかりません");
    assert.ok((await engine.update(second.created, nextLogin("Rustが更新"))).ok);
    assert.ok((await engine.update(first.ids.toUpdate, nextLogin("Rustが再更新"))).ok);
    assert.ok((await engine.group({ ids: [second.created, first.ids.toUpdate], group: "往復" })).ok);
    return await snapshot(engine);
  });
  await withNode(vault, async (engine) => {
    assertSameSnapshot(await snapshot(engine), third, `${format}: the app reads Rust's later writes`);
    assert.equal((await engine.get(first.ids.toDelete)).error, "エントリが見つかりません");
    assert.equal((await engine.get(second.created)).ok.serviceName, "Rustが更新");
  });
  return { entries: Object.keys(third.entries).length, ...(format === "v2" ? { counts: v2Counts(vault.database) } : {}) };
}

// ---- Failures

async function checkCrash({ format, point, act, expectNonceAdded }) {
  const vault = copyVault(format);
  const before = await withNode(vault, snapshot);
  const countsBefore = format === "v2" ? v2Counts(vault.database) : null;
  const started = startE2eBuild(exe, vault.database, nextPort++, { CIPHER_VAULT_POC_WRITE: "1", CIPHER_VAULT_POC_E2E_CRASH: point });
  const page = await connect(nextPort - 1);
  const sessionId = await unlockThroughScreen(page, vault.password);
  // A login entry, so the login payload below is a valid change of it and reaches the save.
  const target = Object.values(before.entries).find((entry) => (entry.type ?? "login") === "login").id;
  // The write never answers, because the process dies in the middle of it. An answer means it did not.
  let answer;
  page.send("Runtime.evaluate", { expression: `${act(sessionId, target)}.then(() => "written", (error) => error.message)`, awaitPromise: true, returnByValue: true })
    .then((reply) => { answer = reply.result?.value; }, () => undefined);
  await until(`crash at ${point}`, () => {
    if (answer !== undefined) throw new Error(`${format} ${point}: the write answered instead of crashing: ${answer}`);
    return started.child.exitCode !== null || started.child.signalCode !== null;
  });
  const exitCode = started.child.exitCode;
  page.close();
  await sleep(800);
  assert.notEqual(exitCode, 0, "the process must really have crashed");
  assert.notEqual(exitCode, 2, "the failure must not be a startup refusal");

  // The app opens first, under its own strict checks: this is the user's way back.
  const afterCrash = await withNode(vault, snapshot);
  assertSameSnapshot(afterCrash, before, `${format} ${point}: the entries are what they were before the crash`);
  const counts = format === "v2" ? v2Counts(vault.database) : null;
  if (counts) {
    assert.equal(counts.encryptionCount, counts.nonces);
    assert.equal(counts.nonces, countsBefore.nonces + (expectNonceAdded ? 1 : 0), "a reserved nonce stays used");
  }
  const written = await withRust(vault, async ({ engine }) => {
    assertSameSnapshot(await snapshot(engine), before, `${format} ${point}: Rust reads the same entries`);
    return (await engine.create({ ...L, serviceName: "クラッシュ後" })).ok;
  });
  await withNode(vault, async (engine) => assert.equal((await engine.get(written.id)).ok.serviceName, "クラッシュ後"));
  return { exitCode: `0x${(exitCode >>> 0).toString(16)}`, nonces: counts && { before: countsBefore.nonces, after: counts.nonces } };
}

const writeExpression = (method, args, sessionId) => `window.passwordManager.${method}(${[...args, sessionId].map((value) => JSON.stringify(value)).join(", ")})`;
const crashes = () => [
  { name: "v2CreateAfterReservation", format: "v2", point: "reserve", expectNonceAdded: true, act: (sessionId) => writeExpression("createEntry", [{ ...L, serviceName: "保存されない" }], sessionId) },
  { name: "v2UpdateBeforeCommit", format: "v2", point: "save", expectNonceAdded: true, act: (sessionId, id) => writeExpression("updateEntry", [id, { ...L, serviceName: "保存されない" }], sessionId) },
  { name: "v2DeleteBeforeCommit", format: "v2", point: "save", expectNonceAdded: false, act: (sessionId, id) => writeExpression("deleteEntry", [id], sessionId) },
  { name: "legacyCreateBeforeCommit", format: "legacy", point: "save", expectNonceAdded: false, act: (sessionId) => writeExpression("createEntry", [{ ...L, serviceName: "保存されない" }], sessionId) },
  { name: "legacyUpdateBeforeCommit", format: "legacy", point: "save", expectNonceAdded: false, act: (sessionId, id) => writeExpression("updateEntry", [id, { ...L, serviceName: "保存されない" }], sessionId) }
];

async function refusedWrites(engine, id) {
  return {
    create: await engine.create({ ...L, serviceName: "保存されない" }),
    update: await engine.update(id, { ...L, serviceName: "保存されない" }),
    remove: await engine.remove(id),
    group: await engine.group({ ids: [id], group: "保存されない" })
  };
}

async function checkSessionsAndOsAway(format) {
  const vault = copyVault(format);
  return withRust(vault, async ({ page, sessionId, events }) => {
    const id = (await rustEngine(page, sessionId).list()).ok.items[0].id;
    const before = digest(vault.database);
    const settle = (method, ...args) => page.evaluate(`window.passwordManager.${method}(${args.map((value) => JSON.stringify(value)).join(", ")}).then(() => "written", (error) => error.message)`);
    const attempts = async (session) => [
      await settle("createEntry", { ...L, serviceName: "保存されない" }, session),
      await settle("updateEntry", id, { ...L, serviceName: "保存されない" }, session),
      await settle("deleteEntry", id, session),
      await settle("setEntriesGroup", { ids: [id], group: "保存されない" }, session),
      await settle("generatePassword", {}, session)
    ];
    const result = { staleSession: await attempts("stale-session") };

    const window = events.find((event) => event.startsWith("os-window ")).split(" ")[1];
    sendOsMessage(window, [WM_POWERBROADCAST, PBT_APMSUSPEND]);
    await until("the vault to lock", async () => !(await fetchStatus(page)).isUnlocked);
    result.whileAway = await attempts((await fetchStatus(page)).sessionId);
    sendOsMessage(window, [WM_POWERBROADCAST, PBT_APMRESUMESUSPEND]);
    const back = await fetchStatus(page);
    result.afterReturn = await attempts(back.sessionId);
    result.oldSessionAfterReturn = await attempts(sessionId);
    result.stillLocked = !back.isUnlocked;

    for (const refused of result.staleSession) assert.equal(refused, "保管庫の状態が変わりました。もう一度操作してください");
    for (const refused of result.whileAway) assert.match(refused, /画面ロック・スリープ中/);
    for (const refused of [...result.afterReturn, ...result.oldSessionAfterReturn]) assert.equal(refused, "保管庫はロックされています");
    assert.equal(result.stillLocked, true);
    assert.equal(digest(vault.database), before, "nothing reached the file");
    return { checked: result.staleSession.length + result.whileAway.length + result.afterReturn.length + result.oldSessionAfterReturn.length, unchanged: true };
  });
}

async function checkDefaultModeIsReadOnly(format) {
  const vault = copyVault(format);
  const before = digest(vault.database);
  return withRust(vault, async ({ page, sessionId, engine, child }) => {
    const id = (await engine.list()).ok.items[0].id;
    const refused = await refusedWrites(engine, id);
    for (const outcome of Object.values(refused)) assert.equal(outcome.error, READ_ONLY);
    const title = powershell(`(Get-Process -Id ${child.pid}).MainWindowTitle`);
    assert.match(title, /read-only/);
    assert.equal(digest(vault.database), before, "nothing reached the file");
    assert.ok(page && sessionId);
    return { refused: Object.keys(refused).length, title, unchanged: true };
  }, { write: false });
}

async function checkLoneSurrogate(format) {
  const vault = copyVault(format);
  const refused = await withRust(vault, async ({ page, sessionId }) => {
    const before = digest(vault.database);
    // Tauri's IPC cannot carry this text and drops the request without answering, so a refusal
    // that arrives at all is part of what is checked. evaluate() times out otherwise.
    const attempt = (call) => page.evaluate(`${call}.then(() => "accepted", (error) => error.message)`);
    const outcomes = [
      await attempt(`window.passwordManager.createEntry({ serviceName: "\\ud800", loginId: "x", password: "\\ud800" }, ${JSON.stringify(sessionId)})`),
      await attempt(`window.passwordManager.createEntry({ "\\udc00": "x" }, ${JSON.stringify(sessionId)})`),
      await attempt(`window.passwordManager.copyText("\\ud800", ${JSON.stringify(sessionId)})`)
    ];
    for (const outcome of outcomes) assert.equal(outcome, "入力に使えない文字が含まれています");
    assert.equal(digest(vault.database), before);
    // The next request still works, so the screen is not left waiting.
    assert.equal(await attempt(`window.passwordManager.createEntry({ serviceName: "直後の保存", loginId: "x", password: "y" }, ${JSON.stringify(sessionId)})`), "accepted");
    return outcomes;
  });
  return { refused: refused.length };
}

function checkProtectedLocations() {
  const refusedAt = (database, environment = {}) => {
    mkdirSync(path.dirname(database), { recursive: true });
    copyFileSync(sample.legacy.database, database);
    const before = digest(database);
    const result = spawnSync(exe, [], { encoding: "utf8", timeout: 20000, env: { ...process.env, CIPHER_VAULT_POC_DB: database, CIPHER_VAULT_POC_WRITE: "1", ...environment } });
    assert.equal(result.status, 2, `${database}: ${result.stderr}`);
    assert.match(result.stderr, /保管庫のコピーを指定/);
    assert.equal(digest(database), before);
    return true;
  };
  const root = path.join(workDirectory, "protected");
  return {
    releaseData: refusedAt(path.join(root, "release", "data", "password-manager.db")),
    apiData: refusedAt(path.join(root, "apps", "api", "data", "password-manager.db")),
    appData: refusedAt(path.join(root, "roaming", "CIPHER VAULT", "data", "password-manager.db"), { APPDATA: path.join(root, "roaming") })
  };
}

// ---- The real form

const fieldInput = (label) => `[...document.querySelectorAll(".editor-field")].find((node) => node.querySelector(".form-label")?.textContent === ${JSON.stringify(label)})?.querySelector("input, textarea")`;
async function fill(page, label, value) {
  assert.equal(await page.evaluate(`(() => { const input = ${fieldInput(label)}; if (!input) return false; input.focus(); input.select(); return true; })()`), true, `The field ${label} is on screen`);
  await page.send("Input.insertText", { text: value });
}
const click = (page, selector) => page.evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
// Only inside the detail pane: the menu bar has its own 編集 button.
const clickText = (page, text) => page.evaluate(`[...document.querySelectorAll(".vault-detail button")].find((node) => node.textContent.trim() === ${JSON.stringify(text)}).click()`);
const screenHas = (page, text) => page.evaluate(`document.body.innerText.includes(${JSON.stringify(text)})`);
const fieldValue = (page, label) => page.evaluate(`${fieldInput(label)}.value`);

async function checkForm(format) {
  const vault = copyVault(format);
  const shot = (page, name) => screenshot(page, screenshotDirectory, `write-${format}-${name}`);
  const checks = {};
  const remaining = await withRust(vault, async ({ page, sessionId, engine }) => {
    await click(page, ".sidebar-add");
    await until("the new form", () => page.evaluate(`!!(${fieldInput("サービス")})`));
    await fill(page, "サービス", "   ");
    await fill(page, "ログインID", "synthetic-form-id");
    await fill(page, "パスワード", "x");
    await click(page, ".editor-save-btn");
    await until("the refusal", () => screenHas(page, "サービス名は必須です"));
    checks.blankNameMessage = "サービス名は必須です";
    // The unlock animation still covers the screen for a moment after the vault opens.
    await sleep(1500);
    await shot(page, "1-refused");

    await fill(page, "サービス", "画面で追加");
    await clickText(page, "生成");
    await until("the generated password", async () => (await fieldValue(page, "パスワード")).length === 20);
    const generated = await fieldValue(page, "パスワード");
    await click(page, ".editor-save-btn");
    const added = await until("the saved entry", async () => (await engine.list()).ok.items.find((item) => item.serviceName === "画面で追加"));
    const stored = (await engine.get(added.id)).ok;
    assert.equal(stored.password, generated);
    await until("the entry on screen", () => screenHas(page, "画面で追加"));
    await sleep(400);
    await shot(page, "2-added");
    checks.createdThroughForm = true;

    await clickText(page, "編集");
    await until("the edit form", () => page.evaluate(`!!(${fieldInput("サービス")})`));
    await fill(page, "サービス", "画面で変更");
    await click(page, ".editor-save-btn");
    await until("the changed entry", async () => (await engine.get(added.id)).ok?.serviceName === "画面で変更");
    await until("the change on screen", () => screenHas(page, "画面で変更"));
    await sleep(400);
    await shot(page, "3-edited");
    const edited = (await engine.get(added.id)).ok;
    assert.equal(edited.password, generated, "editing the name keeps the password");
    assert.equal(edited.passwordChangedAt, stored.passwordChangedAt, "and its change date");
    checks.editedThroughForm = true;

    await clickText(page, "編集");
    await until("the delete button", () => page.evaluate(`!!document.querySelector(".entry-delete")`));
    await click(page, ".entry-delete");
    await until("the entry to go", async () => !(await engine.list()).ok.items.some((item) => item.id === added.id));
    assert.ok(page.dialogs.includes("「画面で変更」を削除しますか？元に戻せません。"), "the screen asked before deleting");
    await until("the entry to leave the screen", async () => !(await screenHas(page, "画面で変更")));
    await sleep(400);
    await shot(page, "4-deleted");
    checks.deletedThroughForm = true;

    await click(page, ".sidebar-add");
    await until("the new form", () => page.evaluate(`!!document.querySelector('[role="tab"][data-type="apiKey"]')`));
    await click(page, '[role="tab"][data-type="apiKey"]');
    if (format === "v2") {
      await until("the API key form", () => page.evaluate(`!!(${fieldInput("キー")})`));
      await fill(page, "名前", "画面で追加したキー");
      await fill(page, "キー", "synthetic-form-api-key");
      await fill(page, "有効期限", "2030-01-31");
      await click(page, ".editor-save-btn");
      await until("the saved key", async () => (await engine.list()).ok.items.some((item) => item.serviceName === "画面で追加したキー"));
      await sleep(400);
      await shot(page, "5-api-key");
      checks.typedThroughForm = true;
    } else {
      await until("the migration notice", () => page.evaluate(`!!document.querySelector(".entry-migration-notice")`));
      assert.equal(await page.evaluate(`document.querySelector(".editor-save-btn").disabled`), true);
      await shot(page, "5-migration-required");
      checks.legacyRefusesTypedItems = true;
    }
    checks.console = [...new Set(page.messages)].filter((message) => !/^(log|info|debug):/.test(message));
    assert.ok(sessionId);
    return snapshot(engine);
  });
  const fromApp = await withNode(vault, snapshot);
  assertSameSnapshot(fromApp, remaining, `${format}: the app reads what the form saved`);
  checks.readByTheApp = Object.keys(fromApp.entries).length;
  return checks;
}

const results = { protectedLocations: checkProtectedLocations() };
for (const format of ["legacy", "v2"]) {
  const { vault, ...differential } = await checkDifferential(format);
  results[format] = { differential, roundTrip: await checkRoundTrip(format, vault), sessionsAndOsAway: await checkSessionsAndOsAway(format),
    defaultMode: await checkDefaultModeIsReadOnly(format), loneSurrogate: await checkLoneSurrogate(format), form: await checkForm(format) };
}
results.crashes = {};
for (const crash of crashes()) results.crashes[crash.name] = await checkCrash(crash);
console.log(JSON.stringify(results, null, 2));
process.exit(0);
