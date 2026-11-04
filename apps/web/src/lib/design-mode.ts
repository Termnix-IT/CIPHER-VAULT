export type DesignMode = "simple" | "luminous";

const STORAGE_KEY = "cipher-vault.design-mode";

// The lock screen needs this before unlocking, so it lives outside the vault. It holds only the mode name.
export function readDesignMode(): DesignMode {
  try { return localStorage.getItem(STORAGE_KEY) === "luminous" ? "luminous" : "simple"; }
  catch { return "simple"; }
}

export function applyDesignMode(mode: DesignMode) {
  document.documentElement.dataset.design = mode;
}

export function saveDesignMode(mode: DesignMode) {
  // A failed save only means the next launch starts with the default design.
  try { localStorage.setItem(STORAGE_KEY, mode); } catch { /* keep the mode for this run */ }
}
