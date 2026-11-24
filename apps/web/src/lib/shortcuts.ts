// The keyboard shortcuts of the vault screen. They work inside the app window only. The one key that
// works from other apps is the call-up shortcut chosen in the settings (globalShortcutOf below); it only
// brings the window forward.

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

/** The same messages as apps/desktop/src/global_hotkey.rs, which checks the key again before registering it. */
export const GLOBAL_SHORTCUT_FORM = "ショートカットは Ctrl・Alt・Shift のうち2つ以上と、英数字・F1〜F11・Space の組み合わせにしてください";
export const GLOBAL_SHORTCUT_IN_APP = "このキーはアプリの中で使っているため選べません";
const IN_APP = ["Ctrl+Shift+C", "Ctrl+Shift+M"];

// The Windows key code where the event has one: RegisterHotKey reads keys by it, so a key recorded on
// any keyboard layout is the key Windows watches. The position (code) is used only without it.
function keyName(code: string, keyCode = 0) {
  if (keyCode) {
    if ((keyCode >= 65 && keyCode <= 90) || (keyCode >= 48 && keyCode <= 57)) return String.fromCharCode(keyCode);
    if (keyCode >= 112 && keyCode <= 122) return `F${keyCode - 111}`;
    return keyCode === 32 ? "Space" : null;
  }
  const letter = /^Key([A-Z])$/.exec(code);
  if (letter) return letter[1];
  const digit = /^Digit([0-9])$/.exec(code);
  if (digit) return digit[1];
  if (/^F([1-9]|1[01])$/.test(code)) return code;
  return code === "Space" ? "Space" : null;
}

/**
 * The call-up shortcut a key press names, spelled as global_hotkey.rs reads it ("Ctrl+Alt+Space").
 * null while only modifier keys are down. Two or more of Ctrl, Alt and Shift are needed, so ordinary app
 * shortcuts such as Ctrl+S stay with the app in use; the Windows key is left to Windows.
 */
export function globalShortcutOf(event: Keys & { keyCode?: number }): { text: string } | { problem: string } | null {
  if (/^(Control|Alt|Shift|Meta|OS)(Left|Right)?$/.test(event.code)) return null;
  const modifiers = [event.ctrlKey && "Ctrl", event.altKey && "Alt", event.shiftKey && "Shift"].filter(Boolean);
  const key = keyName(event.code, event.keyCode);
  if (event.metaKey || !key || modifiers.length < 2) return { problem: GLOBAL_SHORTCUT_FORM };
  const text = [...modifiers, key].join("+");
  return IN_APP.includes(text) ? { problem: GLOBAL_SHORTCUT_IN_APP } : { text };
}
