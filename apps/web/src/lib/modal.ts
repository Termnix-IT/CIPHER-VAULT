// Dialogs that block the screen but leave the window's title bar usable.
//
// The window has no native frame, so its title bar (minimize, maximize, close, drag) is part of
// the screen. showModal() would make it inert along with everything else, and the window could
// then not be moved or closed while a dialog is open. These dialogs open with show() instead, and
// the rest of the screen, including the menus, is made inert here. Escape still sends the dialog
// a cancelable "cancel" event, as showModal() does, so the dialogs keep their own rules for it.

const TITLE_BAR = ".app-titlebar";
const KEPT_IN_TITLE_BAR = ".app-menu-bar";

type Open = { dialog: HTMLDialogElement; inert: Element[]; backdrop: HTMLElement; onKey: (event: KeyboardEvent) => void; onClose: () => void };
const stack: Open[] = [];

// A dialog removed while open (its component unmounted) sends no "close" event, so release it here.
let watcher: MutationObserver | undefined;
function watchRemovals() {
  watcher ??= new MutationObserver(() => {
    for (const entry of [...stack]) if (!entry.dialog.isConnected || !entry.dialog.open) entry.onClose();
    if (!stack.length) { watcher?.disconnect(); watcher = undefined; }
  });
  watcher.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["open"] });
}

/** Every element outside `kept` that does not contain one of them, below `root`. */
function outside(root: Element, kept: Element[]): Element[] {
  const result: Element[] = [];
  for (const child of root.children) {
    if (kept.includes(child)) continue;
    if (kept.some((element) => child.contains(element))) result.push(...outside(child, kept));
    else result.push(child);
  }
  return result;
}

function release(entry: Open) {
  for (const element of entry.inert) element.removeAttribute("inert");
  entry.backdrop.remove();
  document.removeEventListener("keydown", entry.onKey, true);
  entry.dialog.removeEventListener("close", entry.onClose);
}

export function showModalDialog(dialog: HTMLDialogElement) {
  if (dialog.open) return;
  const titleBar = document.querySelector(TITLE_BAR);
  const kept = [dialog, ...(titleBar ? [titleBar] : [])];
  const inert = [...outside(document.body, kept), ...(titleBar?.querySelector(KEPT_IN_TITLE_BAR) ? [titleBar.querySelector(KEPT_IN_TITLE_BAR)!] : [])]
    .filter((element) => !element.hasAttribute("inert") && element.tagName !== "SCRIPT");
  for (const element of inert) element.setAttribute("inert", "");
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  document.body.append(backdrop);
  const onKey = (event: KeyboardEvent) => {
    if (event.key !== "Escape" || stack[stack.length - 1]?.dialog !== dialog) return;
    event.preventDefault();
    event.stopPropagation();
    const cancel = new Event("cancel", { cancelable: true });
    if (dialog.dispatchEvent(cancel)) dialog.close();
  };
  const onClose = () => {
    const index = stack.findIndex((entry) => entry.dialog === dialog);
    if (index >= 0) release(stack.splice(index, 1)[0]);
  };
  const entry: Open = { dialog, inert, backdrop, onKey, onClose };
  document.addEventListener("keydown", onKey, true);
  dialog.addEventListener("close", onClose);
  stack.push(entry);
  dialog.show();
  watchRemovals();
}
