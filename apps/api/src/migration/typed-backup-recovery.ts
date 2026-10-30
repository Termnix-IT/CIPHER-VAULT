import { randomBytes, randomUUID } from "node:crypto";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { setImmediate } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import type { VaultEntry } from "@password-manager/shared/types";
import { deriveBackupKey } from "../crypto/backup-v1.js";
import { decodeVaultBackup, parseVaultBackup, validateVaultEntries } from "../crypto/vault-backup.js";
import { createRootKey, openEntry, unwrapRootKey, wrapRootKey } from "../crypto/v2-codec.js";
import { copyPlaintext } from "../crypto/v2-format.js";
import { createV2Store, openV2Store } from "../db/v2-store.js";
import type { V2Store } from "../db/v2-store.js";
import { INPUT_LIMITS } from "../lib/input-validation.js";
import { LegacyPreflightError } from "./legacy-reader.js";

/** Prove typed backups through the actual atomic v2 restore path and an independent reopen. */
export async function verifyTypedBackupRecovery(content: string, passphrase: Buffer, active: () => void): Promise<VaultEntry[]> {
  let backupKey: Buffer | undefined, scratchKey: Buffer | undefined, reopenedKey: Buffer | undefined, password: Buffer | undefined;
  let store: V2Store | undefined, directory: string | undefined, temporaryRoot: string | undefined;
  let entries: VaultEntry[] = [], restored: VaultEntry[] = [], plaintexts: { entryId: string; plaintext: Buffer }[] = [];
  let success = false;
  try {
    active(); const envelope = parseVaultBackup(content);
    if (envelope.version !== 2) throw new LegacyPreflightError("BACKUP_MISMATCH");
    backupKey = await deriveBackupKey(passphrase, envelope.salt); active();
    entries = decodeVaultBackup(envelope, backupKey);
    scratchKey = createRootKey(); password = randomBytes(32);
    if (scratchKey.equals(backupKey)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    const context = { vaultId: randomUUID(), keyId: randomUUID(), slotRevision: 1 };
    const slot = await wrapRootKey(scratchKey, password.toString("base64"), context); active();
    temporaryRoot = realpathSync(tmpdir());
    directory = mkdtempSync(path.join(temporaryRoot, "cipher-vault-typed-recovery-"));
    const file = path.join(directory, "vault.sqlite");
    store = createV2Store(file, slot);
    for (const entry of entries) {
      active(); plaintexts.push({ entryId: entry.id, plaintext: copyPlaintext(JSON.stringify(entry), INPUT_LIMITS.backupPlaintextBytes) });
    }
    await store.restoreEntries(scratchKey, plaintexts, { assertCurrent: active }); active();
    plaintexts.forEach(entry => entry.plaintext.fill(0)); plaintexts.length = 0;
    store.close(); store = undefined;
    store = openV2Store(file, context);
    reopenedKey = await unwrapRootKey(store.readPasswordSlot(), password.toString("base64"), context); active();
    if (!reopenedKey.equals(scratchKey)) throw new LegacyPreflightError("BACKUP_MISMATCH");
    for (const entry of store.listEntryContexts()) {
      active(); const plaintext = openEntry(reopenedKey, store.readEntry(entry.entryId), entry);
      try { restored.push(JSON.parse(plaintext.toString("utf8")) as VaultEntry); }
      finally { plaintext.fill(0); }
      await setImmediate(); active();
    }
    validateVaultEntries(restored);
    const byId = (values: VaultEntry[]) => new Map(values.map(entry => [entry.id, entry]));
    if (!isDeepStrictEqual(byId(restored), byId(entries))) throw new LegacyPreflightError("BACKUP_MISMATCH");
    success = true; return entries;
  } finally {
    backupKey?.fill(0); scratchKey?.fill(0); reopenedKey?.fill(0); password?.fill(0);
    plaintexts.forEach(entry => entry.plaintext.fill(0)); plaintexts.length = 0; restored.length = 0;
    if (!success) entries.length = 0;
    try { store?.close(); }
    finally {
      if (directory !== undefined) {
        if (path.dirname(directory) !== temporaryRoot || !path.basename(directory).startsWith("cipher-vault-typed-recovery-") ||
            lstatSync(directory).isSymbolicLink() || realpathSync(directory) !== directory) throw new LegacyPreflightError("BACKUP_MISMATCH");
        rmSync(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  }
}
