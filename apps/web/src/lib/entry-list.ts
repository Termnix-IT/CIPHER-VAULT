// Ordering, search and the values of each kind of entry, shared by the normal list and the compact view.
import type { VaultEntry, VaultEntrySummary, VaultEntryType } from "@password-manager/shared/types";

export type SortOrder = "name" | "updated" | "used";

const KANA_ROWS = ["あ", "か", "さ", "た", "な", "は", "ま", "や", "ら", "わ"];
const DAY_MS = 24 * 60 * 60 * 1000;

export function entryTypeLabel(type?: VaultEntryType) {
  return type === "apiKey" ? "APIキー" : type === "creditCard" ? "クレジットカード" : type === "financial" ? "銀行/証券" : "ログイン";
}
export const entryType = (entry: VaultEntrySummary): VaultEntryType => entry.type ?? "login";
export const byName = (a: VaultEntrySummary, b: VaultEntrySummary) => a.serviceName.localeCompare(b.serviceName, "ja", { numeric: true, sensitivity: "base" });
export const byUpdated = (a: VaultEntrySummary, b: VaultEntrySummary) => b.updatedAt.localeCompare(a.updatedAt) || byName(a, b);
/** Most recently used first; entries never used follow in name order. */
export const byLastUsed = (a: VaultEntrySummary, b: VaultEntrySummary) => (b.lastUsedAt ?? "").localeCompare(a.lastUsedAt ?? "") || byName(a, b);
export const sortFor = (order: SortOrder) => order === "name" ? byName : order === "updated" ? byUpdated : byLastUsed;

/** The search covers the names and labels the list shows, never a secret. */
export function matchesSearch(entry: VaultEntrySummary, search: string) {
  return !search || [entry.serviceName, entry.loginId ?? "", entry.group ?? "", entryTypeLabel(entry.type), ...entry.tags]
    .some((field) => field.toLocaleLowerCase("ja-JP").includes(search));
}
export const normalizeSearch = (text: string) => text.trim().toLocaleLowerCase("ja-JP");

export function entrySubtitle(entry: VaultEntrySummary) {
  return entry.type === "creditCard" ? `•••• ${entry.cardLast4}` : entry.type === "apiKey" || entry.type === "financial" ? entryTypeLabel(entry.type) : entry.loginId;
}

/** Index heading for name order: Latin initial, kana row, kanji, or "#" for digits and symbols. */
export function nameSection(name: string) {
  const first = name.trim().normalize("NFKC").charAt(0);
  if (/[a-z]/i.test(first)) return first.toUpperCase();
  // Katakana to hiragana, then drop voicing marks so が falls under か.
  const kana = first.replace(/[ァ-ヶ]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0x60)).normalize("NFD").charAt(0);
  if (/[ぁ-ゖ]/.test(kana)) return `${[...KANA_ROWS].reverse().find((row) => row <= kana) ?? "あ"}行`;
  if (/\p{Script=Han}/u.test(first)) return "漢字";
  return "#";
}
export function ageSection(date: string, now: number) {
  const age = now - new Date(date).getTime();
  return age < DAY_MS ? "24時間以内" : age < 7 * DAY_MS ? "7日以内" : age < 30 * DAY_MS ? "30日以内" : "それ以前";
}
export function sectionLabel(order: SortOrder, now: number) {
  return (entry: VaultEntrySummary) => order === "name" ? nameSection(entry.serviceName)
    : order === "updated" ? ageSection(entry.updatedAt, now) : entry.lastUsedAt ? ageSection(entry.lastUsedAt, now) : "未使用";
}
export function sections(items: VaultEntrySummary[], label: (entry: VaultEntrySummary) => string) {
  const result = new Map<string, VaultEntrySummary[]>();
  for (const entry of items) { const key = label(entry); result.set(key, [...(result.get(key) ?? []), entry]); }
  return [...result.entries()];
}

/** The login ID of an entry, for the entries that have one. A bank's is its contract number. */
export function loginIdOf(entry: VaultEntry): string | null {
  return entry.type === "financial" ? entry.financial.loginId : entry.type === "apiKey" || entry.type === "creditCard" ? null : entry.loginId;
}

/** The secret a sign-in needs most: the password, an API key, or a card number. */
export function primarySecretOf(entry: VaultEntry): { value: string; label: string } {
  return entry.type === "apiKey" ? { value: entry.apiKey.key, label: "キー" }
    : entry.type === "creditCard" ? { value: entry.card.number, label: "カード番号" }
    : entry.type === "financial" ? { value: entry.financial.loginPassword, label: "ログインパスワード" }
    : { value: entry.password, label: "パスワード" };
}
