import { closeSync, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { TextDecoder } from "node:util";
import { parsePasswordSlotContext, record } from "../crypto/v2-format.js";
import type { PasswordSlotContext } from "../crypto/v2-format.js";
import { openV2Store } from "../db/v2-store.js";

type Code = "INVALID_INPUT" | "UNSAFE_PATH" | "RECOVERY_REQUIRED" | "VERIFICATION_FAILED" | "AUTHENTICATION_FAILED" |
  "LOCKED" | "BUSY" | "CANCELLED" | "IO_FAILED";
export class VaultActivationError extends Error {
  constructor(readonly code: Code) { super(`Vault activation: ${code}`); this.name = "VaultActivationError"; }
}
export type ActivationReceipt = Readonly<{ format: "CIPHER-VAULT-ACTIVATION"; version: 1; vaultId: string; keyId: string;
  entryCount: number; state: "prepared" | "committed" }>;
const fail = (): never => { throw new VaultActivationError("RECOVERY_REQUIRED"); };
export function dataRoot(value: string) {
  if (typeof value !== "string" || !value || value.includes("\0")) throw new VaultActivationError("INVALID_INPUT");
  const root = realpathSync(value);
  if (!lstatSync(root).isDirectory()) throw new VaultActivationError("UNSAFE_PATH");
  return root;
}
/** Components are fixed names or validated UUIDs. Reject links, mount escapes and hard-linked files. */
export function safePath(root: string, components: string[], directory = false, missing = false) {
  let current = root;
  const device = lstatSync(root).dev;
  for (let index = 0; index < components.length; index++) {
    const part = components[index];
    if (!part || part === "." || part === ".." || /[\\/:\0]/.test(part)) throw new VaultActivationError("UNSAFE_PATH");
    current = path.join(current, part);
    const last = index === components.length - 1;
    let info;
    try { info = lstatSync(current); }
    catch (error) { if (last && missing && (error as NodeJS.ErrnoException).code === "ENOENT") return current; throw error; }
    if (info.isSymbolicLink() || info.dev !== device || path.relative(current, realpathSync(current)) !== "" ||
        (last && !directory ? !info.isFile() || info.nlink !== 1 : !info.isDirectory())) throw new VaultActivationError("UNSAFE_PATH");
  }
  return current;
}
export function present(file: string) {
  try { lstatSync(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}
export function boundedRead(file: string, max: number) {
  const fd = openSync(file, "r");
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > max) fail();
    const bytes = readFileSync(fd);
    if (bytes.length !== stat.size || bytes.length > max) fail();
    return bytes;
  } finally { closeSync(fd); }
}
function jsonFile(file: string) {
  const bytes = boundedRead(file, 512), value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!bytes.equals(Buffer.from(JSON.stringify(value)))) fail();
  return value;
}
export function readReceipt(root: string): ActivationReceipt {
  const value = record(jsonFile(safePath(root, ["vault-activation.json"])), ["format", "version", "vaultId", "keyId", "entryCount", "state"]);
  if (value.format !== "CIPHER-VAULT-ACTIVATION" || value.version !== 1 || !Number.isInteger(value.entryCount) ||
      (value.entryCount as number) < 0 || (value.entryCount as number) > 10000 || !["prepared", "committed"].includes(value.state as string)) fail();
  const context = parsePasswordSlotContext({ vaultId: value.vaultId, keyId: value.keyId, slotRevision: 1 });
  return Object.freeze({ format: "CIPHER-VAULT-ACTIVATION", version: 1, vaultId: context.vaultId, keyId: context.keyId,
    entryCount: value.entryCount as number, state: value.state as "prepared" | "committed" });
}
export function readPointer(root: string) {
  const value = record(jsonFile(safePath(root, ["vault-current.json"])), ["format", "version", "vaultId"]);
  if (value.format !== "CIPHER-VAULT-ACTIVE" || value.version !== 1) fail();
  return parsePasswordSlotContext({ vaultId: value.vaultId, keyId: value.vaultId, slotRevision: 1 }).vaultId;
}
export function stagedFiles(root: string, context: PasswordSlotContext) {
  const prefix = ["vaults", context.vaultId];
  const directory = safePath(root, prefix, true);
  return Object.freeze({ directory, snapshot: safePath(root, [...prefix, "legacy.sqlite"]), backup: safePath(root, [...prefix, "legacy.cvault"]),
    database: safePath(root, [...prefix, "vault.sqlite"]), exportBackup: safePath(root, [...prefix, "v2-export.cvault"]) });
}
export function syncFile(file: string, release: (fd: number) => void = closeSync) {
  const fd = openSync(file, "r+"); try { fsyncSync(fd); } finally { release(fd); }
}
export function syncDirectory(directory: string) {
  // Node/libuv cannot fsync Windows directories. Do not silently claim directory durability.
  if (process.platform === "win32") return false;
  const fd = openSync(directory, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
  return true;
}
function temporary(root: string, label: string, bytes: Buffer) {
  const file = path.join(root, `.${label}.${randomUUID()}.tmp`), fd = openSync(file, "wx", 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  return file;
}

/** Called only while the legacy writer lock and authorization are held, after full verification. */
export function publishPointer(root: string, receipt: ActivationReceipt, recovery: boolean, active: () => void,
  releaseDatabaseFile: (fd: number) => void) {
  const context = parsePasswordSlotContext({ vaultId: receipt.vaultId, keyId: receipt.keyId, slotRevision: 1 });
  const files = stagedFiles(root, context);
  for (const file of [files.backup, files.snapshot, files.database, files.exportBackup]) {
    active(); syncFile(file, file === files.database ? releaseDatabaseFile : undefined);
  }
  syncDirectory(files.directory); syncDirectory(path.dirname(files.directory)); syncDirectory(root); active();
  const marker = safePath(root, ["vault-activation.json"], false, !recovery);
  const pointer = safePath(root, ["vault-current.json"], false, true);
  if (!recovery) {
    if (present(marker) || present(pointer)) fail();
    const pending = temporary(root, "vault-activation", Buffer.from(JSON.stringify(receipt))); active();
    if (present(marker) || present(pointer)) fail();
    renameSync(pending, marker); syncFile(marker); syncDirectory(root);
  } else {
    if (JSON.stringify(readReceipt(root)) !== JSON.stringify(receipt)) fail();
    if (present(pointer)) {
      const previous = boundedRead(pointer, 512);
      // Explicit recovery preserves even malformed pointer bytes before replacement.
      temporary(root, "vault-current-preserved", previous);
    }
  }
  active();
  const pending = temporary(root, "vault-current", Buffer.from(JSON.stringify({ format: "CIPHER-VAULT-ACTIVE", version: 1, vaultId: receipt.vaultId })));
  active(); stagedFiles(root, context);
  if (JSON.stringify(readReceipt(root)) !== JSON.stringify(receipt)) fail();
  safePath(root, ["vault-current.json"], false, true);
  renameSync(pending, pointer); syncFile(pointer);
  const directorySynced = syncDirectory(root);
  if (readPointer(root) !== receipt.vaultId) fail();
  const committed = { ...receipt, state: "committed" };
  const acknowledgment = temporary(root, "vault-activation", Buffer.from(JSON.stringify(committed)));
  active(); renameSync(acknowledgment, marker); syncFile(marker); syncDirectory(root);
  if (JSON.stringify(readReceipt(root)) !== JSON.stringify(committed)) fail();
  return directorySynced ? "file-and-directory-sync" as const : "file-sync" as const;
}

export function inspectVaultSelection(directory: string) {
  try {
    const root = dataRoot(directory), marker = safePath(root, ["vault-activation.json"], false, true), pointer = safePath(root, ["vault-current.json"], false, true);
    if (present(safePath(root, ["vault-transition.json"], false, true))) fail();
    if (!present(marker) && !present(pointer)) return Object.freeze({ format: "legacy" as const, database: safePath(root, ["password-manager.db"], false, true) });
    if (!present(marker) || !present(pointer)) fail();
    const receipt = readReceipt(root);
    if (receipt.state !== "committed") fail();
    if (readPointer(root) !== receipt.vaultId) fail();
    const context = parsePasswordSlotContext({ vaultId: receipt.vaultId, keyId: receipt.keyId, slotRevision: 1 });
    const file = safePath(root, ["vaults", context.vaultId, "vault.sqlite"]);
    const store = openV2Store(file, context); store.close();
    return Object.freeze({ format: "v2" as const, database: file, context });
  } catch { throw new VaultActivationError("RECOVERY_REQUIRED"); }
}
