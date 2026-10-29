import { read } from "node:fs";
import { BROWSER_MESSAGE_LIMIT, BrowserConnectionError } from "./browser-message.js";

// Electron replaces process.stdin with EOF on Windows. Read exactly one bounded frame from the
// inherited descriptor; do not leave a blocking pipe read pending when Electron exits.
// The native launcher owns subsequent-byte/EOF cancellation and the child process lifetime.
export async function readBrowserNativeFrame() {
  const exact = async (buffer: Buffer) => {
    let offset = 0;
    while (offset < buffer.length) {
      const bytes = await new Promise<number>((resolve, reject) => read(0, buffer, offset, buffer.length - offset, null,
        (error, count) => error ? reject(error) : resolve(count)));
      if (bytes < 1) throw new BrowserConnectionError(); offset += bytes;
    }
  };
  const header = Buffer.alloc(4); await exact(header); const length = header.readUInt32LE();
  if (length < 2 || length > BROWSER_MESSAGE_LIMIT) throw new BrowserConnectionError();
  const payload = Buffer.alloc(length); await exact(payload); return Buffer.concat([header, payload]);
}
