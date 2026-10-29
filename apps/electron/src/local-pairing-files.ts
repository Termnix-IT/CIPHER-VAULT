import { closeSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { LocalPairingError, LOCAL_PAIRING_LIMITS } from "./local-pairing.js";

// Only native-dialog selections enter here; renderer callers never supply filesystem paths.
export function readSelectedPairingRequest(file: string) {
  try {
    if (typeof file !== "string" || !path.isAbsolute(file) || path.extname(file).toLowerCase() !== ".cvpair") throw new LocalPairingError();
    const before = lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > LOCAL_PAIRING_LIMITS.bytes || realpathSync(file) !== file) throw new LocalPairingError();
    const descriptor = openSync(file, "r"), buffer = Buffer.alloc(LOCAL_PAIRING_LIMITS.bytes + 1);
    try {
      const opened = fstatSync(descriptor);
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1 || opened.size !== before.size) throw new LocalPairingError();
      let length = 0, count: number;
      do { count = readSync(descriptor, buffer, length, buffer.length - length, null); length += count; } while (count > 0 && length < buffer.length);
      if (length !== before.size || length > LOCAL_PAIRING_LIMITS.bytes || fstatSync(descriptor).size !== before.size) throw new LocalPairingError();
      return Buffer.from(buffer.subarray(0, length));
    } finally { buffer.fill(0); closeSync(descriptor); }
  } catch { throw new LocalPairingError(); }
}
export function writeSelectedConnectionInfo(file: string, content: Buffer) {
  try {
    if (!path.isAbsolute(file) || path.resolve(file) !== file || path.extname(file).toLowerCase() !== ".cvconnection" || realpathSync(path.dirname(file)) !== path.dirname(file) ||
        !Buffer.isBuffer(content) || content.length < 1 || content.length > LOCAL_PAIRING_LIMITS.bytes) throw new LocalPairingError();
    const descriptor = openSync(file, "wx", 0o600);
    try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  } catch { throw new LocalPairingError(); }
}
