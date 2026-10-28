import { closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readSync, renameSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import path from "node:path";
import { parsePasswordSlotContext, record } from "../crypto/v2-format.js";
import type { PasswordSlotContext } from "../crypto/v2-format.js";
import { boundedRead, dataRoot, present, safePath, syncDirectory, syncFile } from "./active-pointer.js";

type Code = "INVALID_INPUT" | "AUTHENTICATION_FAILED" | "VERIFICATION_FAILED" | "CANCELLED" | "BUSY" |
  "IN_USE" | "LOCKED" | "CAPACITY" | "IO_FAILED" | "RECOVERY_REQUIRED";
export class V2ReplacementError extends Error {
  constructor(readonly code: Code) { super(`V2 vault replacement: ${code}`); this.name = "V2ReplacementError"; }
}
export const REPLACEMENT_SNAPSHOT_BYTES = 512 * 1024 * 1024;
export type ReplacementMode = "rekey" | "reset";
export type Transition = Readonly<{ format: "CIPHER-VAULT-TRANSITION"; version: 1; mode: ReplacementMode;
  source: PasswordSlotContext; target: PasswordSlotContext; sourceCount: number; targetCount: number; sourceUses: number;
  hashes: Readonly<{ source: string; snapshot: string; backup: string; sourcePointer: string; sourceReceipt: string; target: string; targetBackup: string }> }>;
const fail = (): never => { throw new V2ReplacementError("RECOVERY_REQUIRED"); };
export function replacementFiles(root: string, target: PasswordSlotContext) {
  const prefix = ["vaults", target.vaultId];
  return Object.freeze({ directory: safePath(root, prefix, true), database: safePath(root, [...prefix, "vault.sqlite"], false, true),
    snapshot: safePath(root, [...prefix, "source.sqlite"], false, true), backup: safePath(root, [...prefix, "source.cvault"], false, true),
    sourcePointer: safePath(root, [...prefix, "source-pointer.json"], false, true), sourceReceipt: safePath(root, [...prefix, "source-receipt.json"], false, true),
    targetBackup: safePath(root, [...prefix, "target.cvault"], false, true), archive: safePath(root, [...prefix, "replacement.json"], false, true) });
}
export function createReplacementDirectory(root: string, target: PasswordSlotContext) {
  const parent = safePath(root, ["vaults"], true); mkdirSync(path.join(parent, target.vaultId), { mode: 0o700 });
  return replacementFiles(root, target);
}
export function readTransition(root: string): Transition {
  try {
    const bytes = boundedRead(safePath(root, ["vault-transition.json"]), 4096), parsed = JSON.parse(bytes.toString("utf8"));
    if (!bytes.equals(Buffer.from(JSON.stringify(parsed)))) fail();
    const value = record(parsed, ["format", "version", "mode", "source", "target", "sourceCount", "targetCount", "sourceUses", "hashes"]);
    const source = parsePasswordSlotContext(value.source), target = parsePasswordSlotContext(value.target);
    if (value.format !== "CIPHER-VAULT-TRANSITION" || value.version !== 1 || !["rekey", "reset"].includes(value.mode as string) ||
        source.slotRevision !== 1 || target.slotRevision !== 1 || target.vaultId === target.keyId ||
        [target.vaultId, target.keyId].some(id => [source.vaultId, source.keyId].includes(id)) ||
        !Number.isInteger(value.sourceCount) || (value.sourceCount as number) < 0 || (value.sourceCount as number) > 10000 ||
        !Number.isInteger(value.targetCount) || value.targetCount !== (value.mode === "reset" ? 0 : value.sourceCount) ||
        !Number.isInteger(value.sourceUses) || (value.sourceUses as number) < (value.sourceCount as number) || (value.sourceUses as number) > 2 ** 20) fail();
    const hashes = record(value.hashes, ["source", "snapshot", "backup", "sourcePointer", "sourceReceipt", "target", "targetBackup"]);
    if (Object.values(hashes).some(hash => typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash))) fail();
    return Object.freeze({ format: "CIPHER-VAULT-TRANSITION", version: 1, mode: value.mode as ReplacementMode, source, target,
      sourceCount: value.sourceCount as number, targetCount: value.targetCount as number, sourceUses: value.sourceUses as number,
      hashes: Object.freeze({ ...hashes }) as Transition["hashes"] });
  } catch { return fail(); }
}
/** Recovery hint only; the caller still authenticates both vaults and all artifacts. */
export function inspectV2Replacement(directory: string) {
  try {
    const transition = readTransition(dataRoot(directory));
    return Object.freeze({ source: transition.source, target: transition.target, mode: transition.mode });
  } catch { return fail(); }
}
export async function hashFile(file: string, maximum: number, active: () => void) {
  const fd = openSync(file, "r"), chunk = Buffer.alloc(64 * 1024), hash = createHash("sha256");
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maximum) throw new V2ReplacementError("CAPACITY");
    let offset = 0;
    while (offset < stat.size) {
      active(); const count = readSync(fd, chunk, 0, Math.min(chunk.length, stat.size - offset), offset);
      if (!count) fail(); hash.update(chunk.subarray(0, count)); offset += count;
      if (offset % (2 * 1024 * 1024) === 0) await setImmediate();
    }
    if (fstatSync(fd).size !== stat.size) fail(); active(); return hash.digest("hex");
  } finally { chunk.fill(0); closeSync(fd); }
}
/** Same-directory write/fsync/close/rename. An interrupted temporary file is retained. */
export function writeState(root: string, name: string, value: unknown, active: () => void, exclusive = false) {
  const destination = safePath(root, [name], false, true), temporary = path.join(root, `.${name}.${randomUUID()}.tmp`);
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, JSON.stringify(value), "utf8"); fsyncSync(fd); } finally { closeSync(fd); }
  active(); safePath(root, [name], false, true);
  if (exclusive && present(destination)) fail();
  renameSync(temporary, destination); syncFile(destination); syncDirectory(root);
}
