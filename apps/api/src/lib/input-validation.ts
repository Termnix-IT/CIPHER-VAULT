import type { PasswordEntryUpsertPayload, PasswordGenerationOptions } from "@password-manager/shared/types";
import { HttpError } from "./errors.js";

// Write limits do not apply to records already stored in a vault or v1 backup.
export const INPUT_LIMITS = Object.freeze({
  requestBytes: 1024 * 1024, restoreRequestBytes: 18 * 1024 * 1024,
  maintenanceRequestBytes: 4 * 1024 * 1024,
  masterPasswordBytes: 1024 * 1024, clipboardBytes: 1024 * 1024, idBytes: 128,
  serviceNameBytes: 1024, loginIdBytes: 4096, passwordBytes: 64 * 1024,
  notesBytes: 256 * 1024, urlBytes: 8192, groupBytes: 1024,
  tags: 100, tagBytes: 256, entries: 10000,
  backupFileBytes: 16 * 1024 * 1024, backupPlaintextBytes: 11 * 1024 * 1024
});

export function parseRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new HttpError(400, "入力はオブジェクトで指定してください");
  }
  const result: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !fields.includes(key)) throw new HttpError(400, "未対応の入力項目があります");
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor)) throw new HttpError(400, "入力項目は値で指定してください");
    result[key] = descriptor.value;
  }
  return result;
}

export function text(value: unknown, label: string, maxBytes: number) {
  if (typeof value !== "string") throw new HttpError(400, `${label}は文字列で指定してください`);
  if (value.length > maxBytes || Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new HttpError(413, `${label}の容量が上限を超えています（${maxBytes} byteまで）`);
  }
  return value;
}

export function jsonSize(value: object, maxBytes = INPUT_LIMITS.requestBytes) {
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > maxBytes) {
    throw new HttpError(413, "リクエストの容量が上限を超えています");
  }
}

export function parseEntryPayload(value: unknown, mode: "write" | "backup" = "write"): Required<PasswordEntryUpsertPayload> {
  const input = parseRecord(value, ["serviceName", "loginId", "password", "notes", "url", "tags", "group"]);
  const limit = (bytes: number) => mode === "write" ? bytes : Infinity;
  const serviceName = text(input.serviceName, "サービス名", limit(INPUT_LIMITS.serviceNameBytes));
  const loginId = text(input.loginId, "ログインID", limit(INPUT_LIMITS.loginIdBytes));
  const password = text(input.password, "パスワード", limit(INPUT_LIMITS.passwordBytes));
  if (!serviceName.trim()) throw new HttpError(400, "サービス名は必須です");
  if (!loginId.trim()) throw new HttpError(400, "ログインIDは必須です");
  if (!password) throw new HttpError(400, "パスワードは必須です");
  const notes = text(input.notes ?? "", "メモ", limit(INPUT_LIMITS.notesBytes));
  const url = text(input.url ?? "", "URL", limit(INPUT_LIMITS.urlBytes));
  const group = text(input.group ?? "", "グループ", limit(INPUT_LIMITS.groupBytes));
  const rawTags = input.tags ?? [];
  if (!Array.isArray(rawTags)) throw new HttpError(400, "タグは文字列の配列で指定してください");
  if (rawTags.length > limit(INPUT_LIMITS.tags)) throw new HttpError(413, "タグは100件まで指定できます");
  const tags: string[] = [];
  for (let index = 0; index < rawTags.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(rawTags, String(index));
    if (!descriptor || !("value" in descriptor)) throw new HttpError(400, "タグは文字列の配列で指定してください");
    tags.push(text(descriptor.value, "タグ", limit(INPUT_LIMITS.tagBytes)));
  }
  const result = { serviceName, loginId, password, notes, url, group, tags };
  if (mode === "write") jsonSize(result);
  return result;
}

export function parseMasterPassword(value: unknown, setup: boolean) {
  const input = parseRecord(value, ["masterPassword"]);
  const password = text(input.masterPassword, "マスターパスワード", INPUT_LIMITS.masterPasswordBytes);
  if (setup && password.length < 12) throw new HttpError(400, "マスターパスワードは12文字以上で入力してください");
  jsonSize({ masterPassword: password });
  return password; // Never trim or normalize an existing password.
}

export function parseResetPayload(value: unknown) {
  if (parseRecord(value, ["confirmation"]).confirmation !== "RESET_ALL_DATA") {
    throw new HttpError(400, "保管庫のリセット確認が必要です");
  }
}

export function parseGenerationOptions(value: unknown = {}): Required<PasswordGenerationOptions> {
  const input = parseRecord(value, ["length", "includeUppercase", "includeLowercase", "includeNumbers", "includeSymbols"]);
  const length = input.length === undefined ? 20 : input.length;
  if (typeof length !== "number" || !Number.isInteger(length) || length < 12 || length > 64) {
    throw new HttpError(400, "パスワードの長さは12文字以上64文字以下で指定してください");
  }
  const flags: Record<string, boolean> = {};
  for (const field of ["includeUppercase", "includeLowercase", "includeNumbers", "includeSymbols"] as const) {
    if (input[field] !== undefined && typeof input[field] !== "boolean") throw new HttpError(400, "文字種の指定は真偽値で指定してください");
    flags[field] = input[field] !== false;
  }
  if (!Object.values(flags).some(Boolean)) throw new HttpError(400, "少なくとも1つの文字種を有効にしてください");
  return { length, ...flags } as Required<PasswordGenerationOptions>;
}

export function parseBackupPayload(value: unknown, restore: false): { passphrase: string };
export function parseBackupPayload(value: unknown, restore: true): { passphrase: string; content: string };
export function parseBackupPayload(value: unknown, restore: boolean) {
  const input = parseRecord(value, restore ? ["passphrase", "content"] : ["passphrase"]);
  if (typeof input.passphrase !== "string" || input.passphrase.length < 12 || input.passphrase.length > 1024) {
    throw new HttpError(400, "バックアップ用パスフレーズは12〜1024文字で入力してください");
  }
  const passphrase = text(input.passphrase, "バックアップ用パスフレーズ", 4096);
  if (!restore) return { passphrase };
  const content = text(input.content, "バックアップファイル", INPUT_LIMITS.backupFileBytes);
  const result = { passphrase, content };
  jsonSize(result, INPUT_LIMITS.restoreRequestBytes);
  return result;
}

export function parseEntryId(value: unknown) {
  const id = text(value, "エントリID", INPUT_LIMITS.idBytes);
  if (!id || id.includes("\0")) throw new HttpError(400, "エントリIDの形式が正しくありません");
  return id;
}

export function parseClipboardText(value: unknown) {
  return text(value, "コピーする内容", INPUT_LIMITS.clipboardBytes);
}

export function parseSessionId(value: unknown) {
  if (typeof value !== "string" || value.length === 0 || value.length > INPUT_LIMITS.idBytes ||
      Buffer.byteLength(value, "utf8") > INPUT_LIMITS.idBytes) {
    throw new HttpError(409, "保管庫の状態を再取得してください");
  }
  return value;
}

export function requireArgumentCount(args: unknown[], count: number) {
  if (args.length !== count) throw new HttpError(400, "引数の個数が正しくありません");
}

export function parseEmptyPayload(value: unknown) { parseRecord(value, []); }
