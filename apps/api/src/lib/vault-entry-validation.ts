import type { ApiKeyEntry, CreditCardEntry, FinancialEntry, FinancialExtraSecret, VaultEntryUpsertPayload } from "@password-manager/shared/types";
import { HttpError } from "./errors.js";
import { INPUT_LIMITS, jsonSize, parseEntryPayload, parseRecord, text } from "./input-validation.js";

const commonFields = ["serviceName", "notes", "url", "tags", "group"];
const financialFields = ["loginId", "loginPassword", "tradingPassword", "extraSecrets"];
// Extra secrets are identified by label on screen, so they must not collide with a fixed row's label.
const fixedFinancialLabels = ["ログインID", "ログインパスワード", "取引パスワード", "URL"];
const detailField = (type: unknown) => type === "apiKey" ? "apiKey" : type === "financial" ? "financial" : "card";
function invalid(): never { throw new HttpError(400, "項目の形式が正しくありません"); }
function string(value: unknown, label: string, limit: number) {
  const result = text(value, label, limit);
  if (Buffer.from(result, "utf8").toString("utf8") !== result) invalid();
  return result;
}
function date(value: unknown, monthOnly = false): string {
  if (value === undefined || value === "") return "";
  if (typeof value !== "string" || !(monthOnly ? /^\d{4}-(0[1-9]|1[0-2])$/ : /^\d{4}-\d{2}-\d{2}$/).test(value)) invalid();
  const full = monthOnly ? value + "-01" : value;
  const parsed = new Date(full + "T00:00:00.000Z");
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== full) invalid();
  return value;
}
function common(input: Record<string, unknown>, stored: boolean) {
  const limit = (n: number) => stored ? INPUT_LIMITS.backupPlaintextBytes : n;
  const serviceName = string(input.serviceName, "名前", limit(INPUT_LIMITS.serviceNameBytes));
  if (!serviceName.trim()) invalid();
  const notes = string(input.notes ?? "", "メモ", limit(INPUT_LIMITS.notesBytes));
  const url = string(input.url ?? "", "URL", limit(INPUT_LIMITS.urlBytes));
  const group = string(input.group ?? "", "グループ", limit(INPUT_LIMITS.groupBytes));
  const rawTags = input.tags ?? [];
  if (!Array.isArray(rawTags) || rawTags.length > INPUT_LIMITS.tags) invalid();
  const tags: string[] = [];
  for (let i = 0; i < rawTags.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(rawTags, String(i));
    if (!descriptor || !("value" in descriptor)) invalid();
    tags.push(string(descriptor.value, "タグ", limit(INPUT_LIMITS.tagBytes)));
  }
  return { serviceName, notes, url, group, tags };
}
function extraSecrets(input: unknown): FinancialExtraSecret[] {
  const raw = input ?? [];
  if (!Array.isArray(raw) || raw.length > INPUT_LIMITS.financialExtraSecrets) invalid();
  const labels = new Set(fixedFinancialLabels), result: FinancialExtraSecret[] = [];
  for (let i = 0; i < raw.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, String(i));
    if (!descriptor || !("value" in descriptor)) invalid();
    const item = parseRecord(descriptor.value, ["label", "value"]);
    const label = string(item.label, "追加の秘密の名前", INPUT_LIMITS.financialLabelBytes).trim();
    const value = string(item.value, "追加の秘密", INPUT_LIMITS.passwordBytes);
    if (!label || !value.length) invalid();
    if (labels.has(label)) throw new HttpError(400, `「${label}」は名前に使えないか、すでに使われています`);
    labels.add(label); result.push({ label, value });
  }
  return result;
}
export function parseVaultEntryPayload(input: unknown, stored = false): VaultEntryUpsertPayload {
  const value = parseRecord(input, [...commonFields, "loginId", "password", "type", "apiKey", "card", "financial"]);
  if (value.type === undefined) return parseEntryPayload(input, stored ? "backup" : "write");
  if (value.type === "login") {
    const { type: _type, ...login } = parseRecord(input, [...commonFields, "loginId", "password", "type"]);
    return parseEntryPayload(login, stored ? "backup" : "write");
  }
  if (value.type !== "apiKey" && value.type !== "creditCard" && value.type !== "financial") invalid();
  const parsed = parseRecord(input, [...commonFields, "type", detailField(value.type)]);
  const metadata = common(parsed, stored);
  let result: VaultEntryUpsertPayload;
  if (value.type === "financial") {
    const financial = parseRecord(parsed.financial, financialFields);
    const loginId = string(financial.loginId, "ログインID", INPUT_LIMITS.loginIdBytes);
    const loginPassword = string(financial.loginPassword, "ログインパスワード", INPUT_LIMITS.passwordBytes);
    if (!loginId.trim() || !loginPassword.length) invalid(); // Preserve the exact credentials; never trim or normalize them.
    result = { ...metadata, type: "financial", financial: { loginId, loginPassword, tradingPassword: string(financial.tradingPassword ?? "", "取引パスワード", INPUT_LIMITS.passwordBytes), extraSecrets: extraSecrets(financial.extraSecrets) } };
  } else if (value.type === "apiKey") {
    const apiKey = parseRecord(parsed.apiKey, ["key", "keyId", "expiresOn"]);
    const key = string(apiKey.key, "キー／トークン", INPUT_LIMITS.passwordBytes);
    if (!key.length) invalid(); // Preserve the exact credential; never trim or normalize it.
    result = { ...metadata, type: "apiKey", apiKey: { key, keyId: string(apiKey.keyId ?? "", "キーID", INPUT_LIMITS.loginIdBytes), expiresOn: date(apiKey.expiresOn) } };
  } else {
    const card = parseRecord(parsed.card, ["number", "cardholder", "expiryMonth", "securityCode"]);
    const raw = string(card.number, "カード番号", 64), number = raw.replace(/[ -]/g, "");
    if (!/^\d{12,19}$/.test(number)) invalid();
    const securityCode = string(card.securityCode ?? "", "セキュリティコード", 4);
    if (securityCode !== "" && !/^\d{3,4}$/.test(securityCode)) invalid();
    result = { ...metadata, type: "creditCard", card: { number, cardholder: string(card.cardholder ?? "", "名義", 1024), expiryMonth: date(card.expiryMonth, true), securityCode } };
  }
  jsonSize(result, stored ? INPUT_LIMITS.backupPlaintextBytes : INPUT_LIMITS.requestBytes);
  return result;
}
export function validateAdditionalEntry(input: unknown, expectedId?: string): ApiKeyEntry | CreditCardEntry | FinancialEntry {
  const value = parseRecord(input, ["id", "type", ...commonFields, "createdAt", "updatedAt", "apiKey", "card", "financial"]);
  if (value.type !== "apiKey" && value.type !== "creditCard" && value.type !== "financial") invalid();
  parseRecord(input, ["id", "type", ...commonFields, "createdAt", "updatedAt", detailField(value.type)]);
  if (typeof value.id !== "string" || !/^[0-9a-f-]{36}$/i.test(value.id) || (expectedId !== undefined && value.id !== expectedId)) invalid();
  for (const field of ["serviceName", "notes", "url"]) if (typeof value[field] !== "string") invalid();
  if (!(value.group === null || typeof value.group === "string") || !Array.isArray(value.tags)) invalid();
  const validDate = (v: unknown): v is string => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
  if (!validDate(value.createdAt) || !validDate(value.updatedAt) || value.createdAt > value.updatedAt) invalid();
  if (value.type === "financial") {
    const financial = parseRecord(value.financial, financialFields);
    for (const field of ["loginId", "loginPassword", "tradingPassword"]) if (typeof financial[field] !== "string") invalid();
    if (!Array.isArray(financial.extraSecrets)) invalid();
    const { id: _id, createdAt: _createdAt, updatedAt: _updatedAt, ...payload } = value;
    parseVaultEntryPayload({ ...payload, group: value.group ?? "" }, true);
    return input as FinancialEntry;
  }
  const detail = value.type === "apiKey" ? parseRecord(value.apiKey, ["key", "keyId", "expiresOn"]) : parseRecord(value.card, ["number", "cardholder", "expiryMonth", "securityCode"]);
  const dateField = value.type === "apiKey" ? "expiresOn" : "expiryMonth";
  if (!(detail[dateField] === null || (typeof detail[dateField] === "string" && detail[dateField] !== ""))) invalid();
  for (const field of value.type === "apiKey" ? ["key", "keyId"] : ["number", "cardholder", "securityCode"]) if (typeof detail[field] !== "string") invalid();
  const { id: _id, createdAt: _createdAt, updatedAt: _updatedAt, ...payload } = value;
  parseVaultEntryPayload({ ...payload, group: value.group ?? "", [value.type === "apiKey" ? "apiKey" : "card"]: { ...detail, [dateField]: detail[dateField] ?? "" } }, true);
  if (value.type === "creditCard" && detail.number !== String(detail.number).replace(/[ -]/g, "")) invalid();
  return input as ApiKeyEntry | CreditCardEntry;
}
