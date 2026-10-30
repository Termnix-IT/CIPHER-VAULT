import { randomBytes } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import type { VaultEntry } from "@password-manager/shared/types";
import { deriveBackupKey } from "../crypto/backup-v1.js";
import { encodeVaultBackup, validateVaultEntries } from "../crypto/vault-backup.js";
import { openEntry, unwrapRootKey, VaultCodecError } from "../crypto/v2-codec.js";
import type { PasswordSlotContext } from "../crypto/v2-format.js";
import { openV2Store } from "../db/v2-store.js";
import type { V2Store } from "../db/v2-store.js";
import { INPUT_LIMITS } from "../lib/input-validation.js";
import { boundedRead } from "./active-pointer.js";
import { verifyBackupRecovery } from "./backup-recovery.js";
import { saveBackup } from "./staging-files.js";
import { V2ReplacementError } from "./v2-replacement-state.js";

export function same(actual: unknown, expected: unknown) {
  if (!isDeepStrictEqual(actual, expected)) throw new V2ReplacementError("VERIFICATION_FAILED");
}
export async function readV2Entries(store: V2Store, root: Buffer, active: () => void, fresh = false, oldRoot?: Buffer) {
  const entries: VaultEntry[] = []; let success = false, size = Buffer.byteLength('{"version":1,"entries":[]}');
  try {
    for (const context of store.listEntryContexts()) {
      active(); if (fresh) same(context.revision, 1);
      const envelope = store.readEntry(context.entryId), plaintext = openEntry(root, envelope, context);
      try {
        size += plaintext.length + (entries.length ? 1 : 0);
        if (size > INPUT_LIMITS.backupPlaintextBytes) throw new V2ReplacementError("CAPACITY");
        entries.push(JSON.parse(plaintext.toString("utf8")) as VaultEntry);
      } finally { plaintext.fill(0); }
      if (oldRoot) {
        try { const invalid = openEntry(oldRoot, envelope, context); invalid.fill(0); same(true, false); }
        catch (error) { if (!(error instanceof VaultCodecError && error.code === "AUTHENTICATION_FAILED")) throw error; }
      }
      await setImmediate(); active();
    }
    validateVaultEntries(entries); success = true; return entries;
  } finally { if (!success) entries.length = 0; }
}
export async function verifyBackup(file: string, passphrase: Buffer, expected: VaultEntry[], active: () => void) {
  const entries = await verifyBackupRecovery(boundedRead(file, INPUT_LIMITS.backupFileBytes).toString("utf8"), passphrase, active, { allowTyped: true });
  try { active(); same(entries, expected); } finally { entries.length = 0; }
}
export async function exportBackup(file: string, entries: VaultEntry[], passphrase: Buffer, active: () => void) {
  let key: Buffer | undefined;
  try {
    const salt = randomBytes(16); key = await deriveBackupKey(passphrase, salt); active();
    saveBackup(file, encodeVaultBackup(entries, key, salt));
  } finally { key?.fill(0); }
  await verifyBackup(file, passphrase, entries, active);
}
export async function verifySnapshot(file: string, context: PasswordSlotContext, password: string, root: Buffer,
  entries: VaultEntry[], uses: number, active: () => void, signal?: AbortSignal) {
  let store: V2Store | undefined, key: Buffer | undefined, saved: VaultEntry[] = [];
  try {
    store = openV2Store(file, context);
    key = await unwrapRootKey(store.readPasswordSlot(), password, context, { signal }); active(); same(key, root);
    same(store.getUsage().encryptionCount, uses);
    saved = await readV2Entries(store, key, active); same(saved, entries);
  } finally { key?.fill(0); saved.length = 0; store?.close(); }
}
