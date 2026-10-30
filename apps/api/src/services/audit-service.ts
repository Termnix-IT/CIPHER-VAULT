import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import { setImmediate } from "node:timers/promises";
import * as common from "@zxcvbn-ts/language-common";
import * as english from "@zxcvbn-ts/language-en";
import type { AuditIssue, SecurityAudit, PasswordEntry } from "@password-manager/shared/types";
import { getDatabase } from "../db/database.js";
import { decryptSecret, getVaultSession } from "./crypto-service.js";
import { HttpError } from "../lib/errors.js";
import { getEntryById, listEntries, requireUnlockedVault } from "./entry-service.js";
import { isV2Vault } from "../db/vault-context.js";

const estimator = new ZxcvbnFactory({
  dictionary: { ...common.dictionary, ...english.dictionary },
  graphs: common.adjacencyGraphs,
  translations: english.translations,
  maxLength: 256
});

const DAY = 86400000;
let busy = false;
export async function auditVault(): Promise<SecurityAudit> {
  requireUnlockedVault();
  if (busy) throw new HttpError(409, "監査の完了を待ってください");
  const session = getVaultSession();
  const now = Date.now();
  const rows = isV2Vault() ? listEntries().items.filter(summary => summary.type !== "apiKey" && summary.type !== "creditCard").map(summary => {
    const entry = getEntryById(summary.id) as PasswordEntry;
    return { id: entry.id, service_name: entry.serviceName, login_id: entry.loginId, encrypted_password: "",
      password: entry.password, url: entry.url, updated_at: entry.updatedAt, password_changed_at: entry.passwordChangedAt };
  }) : getDatabase().prepare(`SELECT id, service_name, login_id, encrypted_password, url,
    updated_at, password_changed_at FROM password_entries`).all() as {
      id: string; service_name: string; login_id: string; encrypted_password: string;
      url: string | null; updated_at: string; password_changed_at: string | null;
      password?: string;
    }[];
  const passwords: string[] = [];
  const frequency = new Map<string, number>();
  busy = true;
  try {
    for (const row of rows) passwords.push(row.password !== undefined ? row.password : decryptSecret(row.encrypted_password));
    for (const password of passwords) frequency.set(password, (frequency.get(password) ?? 0) + 1);
    const counts: SecurityAudit["counts"] = { weak: 0, duplicate: 0, oldPassword: 0, missingUrl: 0, staleEntry: 0 };
    let unknownPasswordAgeCount = 0;
    const items: SecurityAudit["items"] = [];
    for (const [index, row] of rows.entries()) {
      if (index % 8 === 0) {
        await setImmediate();
        requireUnlockedVault();
        if (getVaultSession() !== session) throw new HttpError(409, "保管庫の状態が変わりました。もう一度解析してください");
      }
      const issues: AuditIssue[] = [];
      if (estimator.check(passwords[index], [row.service_name, row.login_id]).score < 3) issues.push("weak");
      if (frequency.get(passwords[index])! > 1) issues.push("duplicate");
      if (row.password_changed_at === null) unknownPasswordAgeCount++;
      else if (now - Date.parse(row.password_changed_at) >= 365 * DAY) issues.push("oldPassword");
      if (!row.url?.trim()) issues.push("missingUrl");
      if (now - Date.parse(row.updated_at) >= 365 * DAY) issues.push("staleEntry");
      for (const issue of issues) counts[issue]++;
      if (issues.length > 0) items.push({ id: row.id, serviceName: row.service_name, loginId: row.login_id, issues });
    }
    // Each entry contributes 60 points for strength and 40 for uniqueness.
    requireUnlockedVault(session);
    return {
      score: rows.length === 0 ? null : Math.round(100 - (60 * counts.weak + 40 * counts.duplicate) / rows.length),
      total: rows.length, checkedAt: new Date(now).toISOString(), unknownPasswordAgeCount, counts, items
    };
  } finally {
    passwords.fill("");
    rows.forEach(row => { if (row.password !== undefined) row.password = ""; });
    frequency.clear();
    busy = false;
  }
}
