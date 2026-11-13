// The list pane's width and whether it shows icons only. Like the design mode, these are not vault
// data and hold no entry information, so they stay in localStorage outside the vault.

const WIDTH_KEY = "cipher-vault.sidebar-width";
const COLLAPSED_KEY = "cipher-vault.sidebar-collapsed";
export const SIDEBAR_DEFAULT_WIDTH = 280;
export const SIDEBAR_MIN_WIDTH = 220;
export const SIDEBAR_MAX_WIDTH = 440;

export function clampSidebarWidth(width: number) {
  return Math.round(Math.min(SIDEBAR_MAX_WIDTH, Math.max(SIDEBAR_MIN_WIDTH, width)));
}

export function readSidebarWidth() {
  try {
    const saved = Number(localStorage.getItem(WIDTH_KEY));
    return Number.isFinite(saved) && saved > 0 ? clampSidebarWidth(saved) : SIDEBAR_DEFAULT_WIDTH;
  } catch { return SIDEBAR_DEFAULT_WIDTH; }
}

export function saveSidebarWidth(width: number) {
  try { localStorage.setItem(WIDTH_KEY, String(clampSidebarWidth(width))); } catch { /* the width lasts for this run */ }
}

export function readSidebarCollapsed() {
  try { return localStorage.getItem(COLLAPSED_KEY) === "true"; } catch { return false; }
}

export function saveSidebarCollapsed(collapsed: boolean) {
  try { localStorage.setItem(COLLAPSED_KEY, String(collapsed)); } catch { /* the choice lasts for this run */ }
}
