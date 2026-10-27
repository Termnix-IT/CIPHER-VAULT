import { createHash, timingSafeEqual } from "node:crypto";
import type { Clipboard, ClipboardItem } from "electron";

export const CLIPBOARD_OWNER_FORMAT = "web application/x.cipher-vault-owner";

export function createClipboardPort(
  clipboard: Pick<Clipboard, "write" | "read" | "clear">,
  item: (values: Record<string, string>) => ClipboardItem
) {
  return {
    write: (text: string, owner: string) => clipboard.write([item({ "text/plain": text, [CLIPBOARD_OWNER_FORMAT]: owner })]),
    async matches(owner: string, expected: Buffer) {
      const entries = await clipboard.read();
      if (entries.length !== 1) return false;
      const current = entries[0];
      if (!current.types.includes(CLIPBOARD_OWNER_FORMAT) || !current.types.includes("text/plain")) return false;
      // Native text aliases may be exposed alongside MIME types. Rich/foreign
      // MIME payloads indicate another application's copy and must be preserved.
      if (current.types.some((type) => type !== CLIPBOARD_OWNER_FORMAT && type !== "text/plain" &&
          !type.startsWith("electron application/osclipboard;"))) return false;
      const marker = await current.getType(CLIPBOARD_OWNER_FORMAT);
      if (marker.size > 128 || await marker.text() !== owner) return false;
      const content = await current.getType("text/plain");
      if (content.size > 1024 * 1024) return false;
      const bytes = Buffer.from(await content.arrayBuffer());
      const actual = createHash("sha256").update(bytes).digest();
      try { return actual.length === expected.length && timingSafeEqual(actual, expected); }
      finally { bytes.fill(0); actual.fill(0); }
    },
    clear: () => clipboard.clear()
  };
}
