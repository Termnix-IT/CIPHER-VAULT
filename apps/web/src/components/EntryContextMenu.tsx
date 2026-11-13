import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import type { VaultEntrySummary } from "@password-manager/shared/types";
import { ChevronIcon } from "./Icons";

const VIEWPORT_MARGIN = 8;

type EntryContextMenuProps = {
  entry: VaultEntrySummary;
  x: number;
  y: number;
  groupNames: string[];
  onAddToGroup: (group: string) => void;
  onNewGroup: () => void;
  onRemoveFromGroup: () => void;
  onDelete: () => void;
  onChangeIcon: () => void;
  /** restoreFocus is false when the pointer already moved on to something else. */
  onClose: (restoreFocus: boolean) => void;
};

export function EntryContextMenu({ entry, x, y, groupNames, onAddToGroup, onNewGroup, onRemoveFromGroup, onDelete, onChangeIcon, onClose }: EntryContextMenuProps) {
  const [expanded, setExpanded] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const addButton = useRef<HTMLButtonElement>(null);

  // Keep the whole menu on screen, including after the group list opens.
  useLayoutEffect(() => {
    const element = menu.current;
    if (!element) return;
    const { width, height } = element.getBoundingClientRect();
    element.style.left = `${Math.max(VIEWPORT_MARGIN, Math.min(x, window.innerWidth - width - VIEWPORT_MARGIN))}px`;
    element.style.top = `${Math.max(VIEWPORT_MARGIN, Math.min(y, window.innerHeight - height - VIEWPORT_MARGIN))}px`;
  }, [x, y, expanded, groupNames.length]);

  useEffect(() => { addButton.current?.focus(); }, []);

  useEffect(() => {
    const inside = (event: Event) => event.target instanceof Node && menu.current?.contains(event.target);
    const closeOutside = (event: Event) => { if (!inside(event)) onClose(false); };
    const closeWindow = () => onClose(false);
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("scroll", closeOutside, true);
    window.addEventListener("blur", closeWindow);
    window.addEventListener("resize", closeWindow);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("scroll", closeOutside, true);
      window.removeEventListener("blur", closeWindow);
      window.removeEventListener("resize", closeWindow);
    };
  }, [onClose]);

  function run(action: () => void) {
    onClose(true);
    action();
  }

  function moveFocus(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      onClose(true);
      return;
    }
    if (event.key === "ArrowRight" && document.activeElement === addButton.current) { event.preventDefault(); setExpanded(true); return; }
    if (event.key === "ArrowLeft" && expanded) { event.preventDefault(); setExpanded(false); addButton.current?.focus(); return; }
    const items = [...(menu.current?.querySelectorAll<HTMLButtonElement>(".app-menu-item:not(:disabled)") ?? [])];
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = event.key === "ArrowDown" ? (current + 1) % items.length
      : event.key === "ArrowUp" ? (current - 1 + items.length) % items.length
      : event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : -1;
    if (next < 0) return;
    event.preventDefault();
    items[next]?.focus();
  }

  return <div className="app-menu-popup entry-menu" ref={menu} role="menu" aria-label={`${entry.serviceName}の操作`}
    onKeyDown={moveFocus} onContextMenu={(event) => event.preventDefault()}>
    <button type="button" className="app-menu-item entry-menu-add" ref={addButton} role="menuitem" aria-haspopup="true" aria-expanded={expanded}
      onClick={() => setExpanded((current) => !current)}>
      <span className="entry-menu-label">グループへ追加</span><ChevronIcon />
    </button>
    {expanded && <div className="entry-menu-groups" role="group" aria-label="追加先のグループ">
      {groupNames.map((name) => <button type="button" className="app-menu-item" key={name} role="menuitemradio" aria-checked={name === entry.group}
        onClick={() => run(() => { if (name !== entry.group) onAddToGroup(name); })}>
        <span className="app-menu-check" aria-hidden="true">{name === entry.group ? "✓" : ""}</span><span className="entry-menu-label">{name}</span>
      </button>)}
      <button type="button" className="app-menu-item" role="menuitem" onClick={() => run(onNewGroup)}>
        <span className="app-menu-check" aria-hidden="true" /><span className="entry-menu-label">新しいグループ…</span>
      </button>
    </div>}
    <button type="button" className="app-menu-item" role="menuitem" disabled={!entry.group} onClick={() => run(onRemoveFromGroup)}>グループから削除</button>
    <button type="button" className="app-menu-item" role="menuitem" onClick={() => { onClose(false); onChangeIcon(); }}>アイコンを変更…</button>
    <hr className="app-menu-separator" />
    <button type="button" className="app-menu-item entry-menu-delete" role="menuitem" onClick={() => run(onDelete)}>項目削除</button>
  </div>;
}
