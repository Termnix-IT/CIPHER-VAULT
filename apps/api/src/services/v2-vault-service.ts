import { randomUUID } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import type { PasswordEntry, VaultEntry, VaultEntrySummary, VaultEntryUpsertPayload } from "@password-manager/shared/types";
import { openEntry, unwrapRootKey, VaultCodecError } from "../crypto/v2-codec.js";
import { validateEntryPlaintext } from "../crypto/v2-format.js";
import { failVaultContext, getV2Vault } from "../db/vault-context.js";
import { V2StoreError } from "../db/v2-store.js";
import { HttpError } from "../lib/errors.js";
import { INPUT_LIMITS, parseEntryId, parseEntryPayload, parseMasterPassword } from "../lib/input-validation.js";
import { vaultSession } from "./vault-session.js";
import { vaultUnlockGuard } from "./vault-unlock-guard.js";
import { parseVaultEntryPayload } from "../lib/vault-entry-validation.js";

type Context = NonNullable<ReturnType<typeof getV2Vault>>;
function runtime() { const value = getV2Vault(); if (!value) throw new HttpError(409, "保管庫の状態が変わりました"); return value; }
function entryContext(context: Context, entryId: string, revision: number) {
  return { vaultId: context.expected.vaultId, keyId: context.expected.keyId, entryId, revision };
}
function translate(error: unknown): never {
  if (error instanceof HttpError) throw error;
  if (error instanceof V2StoreError) {
    if (error.code === "BUSY" || error.code === "CONFLICT") throw new HttpError(409, "保管庫の処理が競合しました。もう一度操作してください");
    if (error.code === "KEY_LIMIT") throw new HttpError(409, "保管庫の鍵更新が必要です");
    if (error.code === "ENTRY_LIMIT") throw new HttpError(413, "保管庫への新規登録は10000件まで対応しています");
    if (error.code === "READ_ONLY") throw new HttpError(403, "この保管庫は読取専用です");
  }
  if (error instanceof VaultCodecError && error.code === "CANCELLED") throw new HttpError(409, "保管庫の状態が変わりました。もう一度操作してください");
  return failVaultContext();
}
function read(context: Context, root: Buffer, id: string): VaultEntry {
  const envelope = context.store.readEntry(id);
  if (!envelope) throw new HttpError(404, "エントリが見つかりません");
  const plaintext = openEntry(root, envelope, entryContext(context, id, envelope.revision));
  try { return JSON.parse(plaintext.toString("utf8")) as VaultEntry; } finally { plaintext.fill(0); }
}
function readOperation<T>(action: (context: Context, root: Buffer, active: () => void) => T) {
  const session = vaultSession.requireUnlocked(), context = runtime();
  const active = () => { vaultSession.requireUnlocked(session); context.assertCurrent(); };
  try { const result = action(context, vaultSession.requireKey(), active); active(); return result; }
  catch (error) { active(); return translate(error); }
}
async function mutation<T>(action: (context: Context, root: Buffer, options: { signal: AbortSignal; assertCurrent(): void }) => Promise<T>) {
  const session = vaultSession.requireUnlocked(), context = runtime(), controller = new AbortController();
  const unsubscribe = vaultSession.subscribe(state => { if (!state.isUnlocked || state.sessionId !== session) controller.abort(); });
  const signal = AbortSignal.any([controller.signal, context.signal]);
  const active = () => { vaultSession.requireUnlocked(session); context.assertCurrent(); };
  try { active(); const result = await action(context, vaultSession.requireKey(), { signal, assertCurrent: active }); active(); return result; }
  catch (error) { active(); return translate(error); }
  finally { unsubscribe(); }
}

export async function unlockV2Vault(input: unknown) {
  const password = parseMasterPassword(input, false), context = runtime(), intent = vaultSession.getState().sessionId;
  return vaultUnlockGuard.run(async () => {
    let root: Buffer | undefined;
    try {
      root = await unwrapRootKey(context.store.readPasswordSlot(), password, context.expected);
      vaultSession.requireGeneration(intent); context.assertCurrent();
      // Do not install a Session key until every current entry authenticates with its stored context.
      for (const [index, entry] of context.store.listEntryContexts().entries()) {
        read(context, root, entry.entryId);
        if (index % 32 === 0) { await setImmediate(); vaultSession.requireGeneration(intent); context.assertCurrent(); }
      }
      vaultSession.requireGeneration(intent); context.assertCurrent(); vaultSession.unlock(root);
    } catch (error) {
      vaultSession.requireGeneration(intent); context.assertCurrent();
      if (root === undefined && error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED") throw new HttpError(401, "マスターパスワードが正しくありません");
      return translate(error);
    } finally { root?.fill(0); }
  });
}
export function listV2Entries() {
  return readOperation((context, root, active) => {
    const items: VaultEntrySummary[] = [];
    for (const entryContext of context.store.listEntryContexts()) {
      active(); const entry = read(context, root, entryContext.entryId);
      const { id, serviceName, tags, group, updatedAt } = entry;
      const base = { id, serviceName, tags, group, updatedAt };
      if (entry.type === "apiKey") items.push({ ...base, type: "apiKey" });
      else if (entry.type === "creditCard") items.push({ ...base, type: "creditCard", cardLast4: entry.card.number.slice(-4) });
      else items.push({ ...base, loginId: entry.loginId });
    }
    items.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id));
    return { items };
  });
}
export function getV2Entry(input: unknown) { return readOperation((context, root) => read(context, root, parseEntryId(input))); }
function fields(payload: VaultEntryUpsertPayload) {
  const base = { serviceName: payload.serviceName.trim(), notes: payload.notes ?? "", url: payload.url?.trim() || "", tags: payload.tags ?? [], group: payload.group?.trim() || null };
  if ("type" in payload && payload.type === "apiKey") return { ...base, type: "apiKey" as const,
    apiKey: { key: payload.apiKey.key, keyId: payload.apiKey.keyId ?? "", expiresOn: payload.apiKey.expiresOn || null } };
  if ("type" in payload && payload.type === "creditCard") return { ...base, type: "creditCard" as const,
    card: { number: payload.card.number, cardholder: payload.card.cardholder ?? "", expiryMonth: payload.card.expiryMonth || null, securityCode: payload.card.securityCode ?? "" } };
  const login = payload as import("@password-manager/shared/types").PasswordEntryUpsertPayload;
  return { ...base, loginId: login.loginId.trim(), password: login.password };
}
function serialize(entry: VaultEntry) {
  const plaintext = Buffer.from(JSON.stringify(entry));
  try { validateEntryPlaintext(plaintext, entry.id); return plaintext; }
  catch { plaintext.fill(0); throw new HttpError(400, "エントリの形式が正しくありません"); }
}
export function createV2Entry(input: unknown) {
  vaultSession.requireUnlocked(); const payload = parseVaultEntryPayload(input);
  return mutation(async (context, root, options) => {
    if (context.store.listEntryContexts().length >= INPUT_LIMITS.entries) throw new HttpError(413, "保管庫への新規登録は10000件まで対応しています");
    const now = new Date().toISOString(), id = randomUUID();
    const data = fields(payload);
    const entry: VaultEntry = "type" in data ? { id, ...data, createdAt: now, updatedAt: now } : { id, ...data, createdAt: now, updatedAt: now, passwordChangedAt: now };
    const plaintext = serialize(entry);
    try { await context.store.writeEntry(root, plaintext, entryContext(context, id, 1), options); return entry; }
    finally { plaintext.fill(0); }
  });
}
export function updateV2Entry(inputId: unknown, input: unknown) {
  vaultSession.requireUnlocked(); const id = parseEntryId(inputId), payload = parseVaultEntryPayload(input);
  return mutation(async (context, root, options) => {
    const envelope = context.store.readEntry(id);
    if (!envelope) throw new HttpError(404, "エントリが見つかりません");
    const existing = read(context, root, id), now = new Date(Math.max(Date.now(), Date.parse(existing.updatedAt))).toISOString();
    const data = fields(payload);
    if ((existing.type ?? "login") !== ("type" in data ? data.type : "login")) throw new HttpError(400, "保存済みの項目の種類は変更できません");
    const entry: VaultEntry = "type" in data ? { id, ...data, createdAt: existing.createdAt, updatedAt: now } :
      { id, ...data, createdAt: existing.createdAt, updatedAt: now,
        passwordChangedAt: (existing as PasswordEntry).password === data.password ? (existing as PasswordEntry).passwordChangedAt : now };
    const plaintext = serialize(entry);
    try { await context.store.writeEntry(root, plaintext, entryContext(context, id, envelope.revision + 1), options); return entry; }
    finally { plaintext.fill(0); }
  });
}
export function deleteV2Entry(input: unknown) {
  return readOperation((context, root, active) => {
    const id = parseEntryId(input), entry = context.store.readEntry(id); read(context, root, id); active();
    context.store.deleteEntry(entryContext(context, id, entry!.revision), { assertCurrent: active });
    return { success: true };
  });
}
export function restoreV2Entries(entries: VaultEntry[]) {
  return mutation(async (context, root, options) => {
    const snapshots: { entryId: string; plaintext: Buffer }[] = [];
    try {
      for (const entry of entries) snapshots.push({ entryId: entry.id, plaintext: serialize(entry) });
      return await context.store.restoreEntries(root, snapshots, options);
    }
    finally { snapshots.forEach(entry => entry.plaintext.fill(0)); }
  });
}
