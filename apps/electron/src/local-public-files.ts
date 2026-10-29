import { closeSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { BrowserConnectionError } from "./browser-message.js";

export function localPublicPath(file: string) {
  if (typeof file !== "string" || file.length > 4096 || !path.isAbsolute(file) || path.resolve(file) !== file ||
      /[\x00-\x1f]/.test(file) || file.startsWith("\\\\") || file.startsWith("//") || realpathSync(path.dirname(file)) !== path.dirname(file)) throw new BrowserConnectionError();
}
export function readLocalPublicFile(file: string, maximum = 16384) {
  try {
    localPublicPath(file);
    const before = lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > maximum || realpathSync(file) !== file) throw new BrowserConnectionError();
    const descriptor = openSync(file, "r"), buffer = Buffer.alloc(maximum + 1);
    try {
      const opened = fstatSync(descriptor);
      if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1 || opened.size !== before.size) throw new BrowserConnectionError();
      let length = 0, count: number;
      do { count = readSync(descriptor, buffer, length, buffer.length - length, null); length += count; } while (count > 0 && length < buffer.length);
      if (length !== before.size || length > maximum || fstatSync(descriptor).size !== before.size) throw new BrowserConnectionError();
      return Buffer.from(buffer.subarray(0, length));
    } finally { buffer.fill(0); closeSync(descriptor); }
  } catch { throw new BrowserConnectionError(); }
}
export function writeNewLocalPublicFile(file: string, content: Buffer, extension: string) {
  try {
    localPublicPath(file);
    if (path.extname(file).toLowerCase() !== extension || !Buffer.isBuffer(content) || content.length < 1 || content.length > 16384) throw new BrowserConnectionError();
    const descriptor = openSync(file, "wx", 0o600);
    try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
  } catch { throw new BrowserConnectionError(); }
}
