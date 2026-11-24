// The list pane's width and whether it shows icons only. Like the design mode, these are not vault
// data and hold no entry information, so they stay in localStorage outside the vault.

const WIDTH_KEY = "cipher-vault.sidebar-width";
const COLLAPSED_KEY = "cipher-vault.sidebar-collapsed";
export const SIDEBAR_DEFAULT_WIDTH = 280;
export const SIDEBAR_MIN_WIDTH = 220;
export const SIDEBAR_MAX_WIDTH = 440;
// The detail pane keeps this much of the window, so a wide list never squeezes the entry's values.
// With the default list width this sets the window's minimum width (720px in apps/desktop/src/main.rs).
export const DETAIL_MIN_WIDTH = 440;

/** The widest the list may be in a window this wide: 440px, less when the detail pane would get under 440px. */
export function sidebarMaxWidth(windowWidth = Infinity) {
  return Math.max(SIDEBAR_MIN_WIDTH, Math.min(SIDEBAR_MAX_WIDTH, windowWidth - DETAIL_MIN_WIDTH));
}

export function clampSidebarWidth(width: number, windowWidth = Infinity) {
  return Math.round(Math.min(sidebarMaxWidth(windowWidth), Math.max(SIDEBAR_MIN_WIDTH, width)));
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

// The list's order and whether it shows favorites only. They name a view, never an entry.
const SORT_KEY = "cipher-vault.list-sort";
const FAVORITES_KEY = "cipher-vault.list-favorites-only";
const SORT_ORDERS = ["name", "updated", "used"] as const;
export type ListSortOrder = (typeof SORT_ORDERS)[number];

export function readListSort(): ListSortOrder {
  try {
    const saved = localStorage.getItem(SORT_KEY);
    return SORT_ORDERS.find((order) => order === saved) ?? "name";
  } catch { return "name"; }
}

export function saveListSort(order: ListSortOrder) {
  try { localStorage.setItem(SORT_KEY, order); } catch { /* the choice lasts for this run */ }
}

export function readFavoritesOnly() {
  try { return localStorage.getItem(FAVORITES_KEY) === "true"; } catch { return false; }
}

export function saveFavoritesOnly(favoritesOnly: boolean) {
  try { localStorage.setItem(FAVORITES_KEY, String(favoritesOnly)); } catch { /* the choice lasts for this run */ }
}
