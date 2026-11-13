import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { EntryIcon } from "@password-manager/shared/types";
import { DEFAULT_ICON_COLOR, ICON_COLORS, imageToIcon, sameIcon } from "../lib/entry-icons";
import { ENTRY_SYMBOLS, EntryIconBadge } from "./EntryIconBadge";
import { CloseIcon, ImageIcon, SearchIcon } from "./Icons";

type Tab = "letter" | "symbol" | "image";
const TABS: { tab: Tab; label: string }[] = [{ tab: "letter", label: "文字" }, { tab: "symbol", label: "SVG" }, { tab: "image", label: "画像" }];
const VIEWPORT_MARGIN = 8;

type EntryIconPickerProps = {
  name: string;
  icon: EntryIcon | null;
  /** The point the popover opens from, such as the bottom left of the icon that opened it. */
  x: number;
  y: number;
  onSave: (icon: EntryIcon | null) => Promise<void>;
  onClose: () => void;
};

/** A small popover for one entry's icon: a letter, a preset symbol or a local picture, each with a preview. */
export function EntryIconPicker({ name, icon, x, y, onSave, onClose }: EntryIconPickerProps) {
  const [tab, setTab] = useState<Tab>(icon?.kind ?? "letter");
  const [draft, setDraft] = useState<EntryIcon | null>(icon);
  const [color, setColor] = useState(icon && icon.kind !== "image" ? icon.color : DEFAULT_ICON_COLOR);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const popover = useRef<HTMLDivElement>(null);
  const openedTab = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const search = query.trim().toLocaleLowerCase("ja-JP");
  const symbols = useMemo(() => ENTRY_SYMBOLS.filter((symbol) => !search || `${symbol.name} ${symbol.label} ${symbol.keywords}`.toLocaleLowerCase("ja-JP").includes(search)), [search]);
  const changed = !sameIcon(draft, icon);

  useLayoutEffect(() => {
    const element = popover.current;
    if (!element) return;
    const { width, height } = element.getBoundingClientRect();
    element.style.left = `${Math.max(VIEWPORT_MARGIN, Math.min(x, window.innerWidth - width - VIEWPORT_MARGIN))}px`;
    element.style.top = `${Math.max(VIEWPORT_MARGIN, Math.min(y, window.innerHeight - height - VIEWPORT_MARGIN))}px`;
  }, [x, y, tab]);

  useEffect(() => { openedTab.current?.focus(); }, []);

  useEffect(() => {
    const closeOutside = (event: PointerEvent) => {
      if (!saving && event.target instanceof Node && !popover.current?.contains(event.target)) onClose();
    };
    document.addEventListener("pointerdown", closeOutside);
    window.addEventListener("resize", onClose);
    return () => { document.removeEventListener("pointerdown", closeOutside); window.removeEventListener("resize", onClose); };
  }, [onClose, saving]);

  function pickColor(next: string) {
    setColor(next); setError("");
    setDraft(tab === "symbol" && draft?.kind === "symbol" ? { ...draft, color: next } : tab === "symbol" ? { kind: "symbol", symbol: ENTRY_SYMBOLS[0].name, color: next } : { kind: "letter", color: next });
  }

  async function pickImage(file: File | undefined) {
    if (!file) return;
    setError("");
    try { setDraft(await imageToIcon(file)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "画像を読み込めませんでした"); }
  }

  async function save(next: EntryIcon | null) {
    setSaving(true); setError("");
    try { await onSave(next); onClose(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "アイコンを保存できませんでした"); }
    finally { setSaving(false); }
  }

  const colors = <div className="icon-picker-colors" role="radiogroup" aria-label="色">
    {ICON_COLORS.map((option) => <button key={option.name} type="button" role="radio" className="icon-picker-color"
      aria-checked={color === option.name && draft?.kind !== "image"} aria-label={option.label} data-tooltip={option.label}
      style={{ ["--icon-color" as string]: option.value }} disabled={saving} onClick={() => pickColor(option.name)} />)}
  </div>;

  return <div className="icon-picker" ref={popover} role="dialog" aria-labelledby={titleId}
    onKeyDown={(event) => { if (event.key === "Escape" && !saving) { event.preventDefault(); event.stopPropagation(); onClose(); } }}>
    <div className="icon-picker-head">
      <h2 id={titleId}>アイコンを編集</h2>
      <button className="icon-btn" type="button" aria-label="閉じる" disabled={saving} onClick={onClose}><CloseIcon /></button>
    </div>
    <div className="icon-picker-preview">
      <EntryIconBadge name={name} icon={draft} className="entry-badge--large" />
      <span className="icon-picker-name">{name}</span>
    </div>
    <div className="segmented icon-picker-tabs" role="tablist" aria-label="アイコンの種類">
      {TABS.map(({ tab: value, label }) => <button key={value} ref={value === (icon?.kind ?? "letter") ? openedTab : undefined} type="button" role="tab"
        aria-selected={tab === value} disabled={saving} onClick={() => { setTab(value); setError(""); }}>{label}</button>)}
    </div>
    <div className="icon-picker-body" role="tabpanel">
      {tab === "letter" && <>
        {colors}
        <p className="icon-picker-note">名前の最初の文字「{[...name.trim()][0] ?? "?"}」を選んだ色で表示します</p>
      </>}
      {tab === "symbol" && <>
        {colors}
        <div className="search-box icon-picker-search">
          <SearchIcon />
          <input className="search-input" type="search" aria-label="アイコンを検索" placeholder="アイコンを検索" value={query} onChange={(event) => setQuery(event.target.value)} />
        </div>
        <div className="icon-picker-grid" role="radiogroup" aria-label="アイコン">
          {symbols.map((symbol) => <button key={symbol.name} type="button" role="radio" className="icon-picker-symbol"
            aria-checked={draft?.kind === "symbol" && draft.symbol === symbol.name} aria-label={symbol.label} data-tooltip={symbol.label} disabled={saving}
            onClick={() => { setError(""); setDraft({ kind: "symbol", symbol: symbol.name, color }); }}>
            <EntryIconBadge name={name} icon={{ kind: "symbol", symbol: symbol.name, color }} className="entry-badge--plain" />
          </button>)}
          {symbols.length === 0 && <p className="icon-picker-note">見つかりません</p>}
        </div>
      </>}
      {tab === "image" && <>
        <label className="file-drop icon-picker-file">
          <ImageIcon />画像を選ぶ…
          <input type="file" accept="image/png,image/jpeg,image/webp" disabled={saving}
            onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; void pickImage(file); }} />
        </label>
        <p className="icon-picker-note">PNG・JPEG・WebP（5MBまで）。64pxに縮小し、保管庫の鍵で暗号化して保存します</p>
      </>}
      {error && <p className="form-error" role="alert">{error}</p>}
    </div>
    <div className="icon-picker-actions">
      <button className="text-btn" type="button" disabled={saving || !icon} onClick={() => void save(null)}>初期設定に戻す</button>
      <span className="editor-actions-spacer" />
      <button className="btn btn--small" type="button" disabled={saving} onClick={onClose}>キャンセル</button>
      <button className="btn btn--small btn--primary" type="button" disabled={saving || !changed || !draft} onClick={() => void save(draft)}>{saving ? "保存中…" : "保存"}</button>
    </div>
  </div>;
}
