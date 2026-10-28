import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { INPUT_LIMITS } from "../lib/input-validation.js";

export const SNAPSHOT_MAX_BYTES = 64 * 1024 * 1024;
type StageCode = "INVALID_INPUT" | "INVALID_SOURCE" | "AUTHENTICATION_FAILED" | "CAPACITY" | "BUSY" |
  "CANCELLED" | "LOCKED" | "EXISTS" | "BACKUP_MISMATCH" | "VERIFICATION_FAILED" | "IO_FAILED";
export class MigrationStageError extends Error {
  constructor(readonly code: StageCode) { super(`Vault migration staging: ${code}`); this.name = "MigrationStageError"; }
}
export function existingPath(value: string, directory: boolean) {
  if (typeof value !== "string" || !value || value.includes("\0")) throw new MigrationStageError("INVALID_INPUT");
  const resolved = realpathSync(value), info = lstatSync(resolved);
  if (directory ? !info.isDirectory() : !info.isFile()) throw new MigrationStageError("INVALID_INPUT");
  return resolved;
}
export function createStageDirectory(parent: string, vaultId: string) {
  const directory = path.join(parent, vaultId);
  try { mkdirSync(directory, { mode: 0o700 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new MigrationStageError("EXISTS");
    throw error;
  }
  return Object.freeze({ directory, snapshot: path.join(directory, "legacy.sqlite"), backup: path.join(directory, "legacy.cvault"),
    database: path.join(directory, "vault.sqlite"), exportBackup: path.join(directory, "v2-export.cvault") });
}
export function reserveSnapshot(filePath: string) { closeSync(openSync(filePath, "wx", 0o600)); }
export function flushFile(filePath: string) {
  const descriptor = openSync(filePath, "r+");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}
export function saveBackup(filePath: string, content: string) {
  const descriptor = openSync(filePath, "wx", 0o600);
  try { writeFileSync(descriptor, content, "utf8"); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}
export function loadBackup(filePath: string) {
  if (!lstatSync(filePath).isFile() || lstatSync(filePath).isSymbolicLink()) throw new MigrationStageError("VERIFICATION_FAILED");
  const descriptor = openSync(filePath, "r");
  try {
    const size = fstatSync(descriptor).size;
    if (size > INPUT_LIMITS.backupFileBytes) throw new MigrationStageError("CAPACITY");
    const content = readFileSync(descriptor, "utf8");
    if (Buffer.byteLength(content) !== size) throw new MigrationStageError("VERIFICATION_FAILED");
    return content;
  } finally { closeSync(descriptor); }
}
