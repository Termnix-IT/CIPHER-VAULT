// The keyboard shortcuts of the vault screen. They work inside the app window only; none is registered with the OS.

export type Shortcut = "search" | "new" | "copyLoginId" | "copySecret" | "openUrl" | "lock" | "compact";
type Keys = Pick<KeyboardEvent, "ctrlKey" | "altKey" | "metaKey" | "shiftKey" | "code">;

/**
 * The shortcut a key press asks for, by the key's position (event.code), so it is the same with any
 * keyboard layout or input method. Ctrl+C, Ctrl+V and the other editing keys are never taken.
 */
export function shortcutOf(event: Keys): Shortcut | null {
  if (!event.ctrlKey || event.altKey || event.metaKey) return null;
  const shift = event.shiftKey;
  switch (event.code) {
    case "KeyF": return shift ? null : "search";
    case "KeyN": return shift ? null : "new";
    case "KeyB": return shift ? null : "copyLoginId";
    case "KeyC": return shift ? "copySecret" : null;
    case "KeyU": return shift ? null : "openUrl";
    case "KeyL": return shift ? null : "lock";
    case "KeyM": return shift ? "compact" : null;
    default: return null;
  }
}
