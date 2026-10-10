import { useEffect, useRef, useState } from "react";
import type { PasswordEntry } from "@password-manager/shared/types";
import { AppInfo } from "./AppInfo";
import { VaultTools } from "./VaultTools";

type MenuName = "file" | "edit" | "view" | "tools" | "help";
type AppMenuProps = {
  isUnlocked: boolean;
  isBusy: boolean;
  isLoading: boolean;
  hasUnsavedChanges: boolean;
  entryCount: number;
  selectedEntry: PasswordEntry | null;
  isFormOpen: boolean;
  isGroupedView: boolean;
  onRefresh: () => Promise<void>;
  onLock: () => Promise<void>;
  onNewEntry: () => void;
  onGroupedViewChange: (grouped: boolean) => void;
  onSelectEntry: (id: string) => Promise<void>;
  onCopy: (value: string, label: string) => Promise<void>;
};

export function AppMenu(props: AppMenuProps) {
  const [opened, setOpened] = useState<MenuName | null>(null);
  const barRef = useRef<HTMLDivElement>(null);
  const triggerRefs = useRef<Partial<Record<MenuName, HTMLButtonElement | null>>>({});
  const disabled = !props.isUnlocked || props.isBusy;
  const toolsDisabled = disabled || props.hasUnsavedChanges || props.isLoading;

  useEffect(() => {
    if (!opened) return;
    const closeOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !barRef.current?.contains(event.target)) setOpened(null);
    };
    const closeEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setOpened(null);
      triggerRefs.current[opened]?.focus();
    };
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("keydown", closeEscape);
    };
  }, [opened]);

  useEffect(() => { setOpened(null); }, [props.isUnlocked]);

  function run(action: () => void | Promise<void>) {
    if (opened) triggerRefs.current[opened]?.focus();
    setOpened(null);
    // Operation errors are displayed by App or the dialog that owns the action.
    void Promise.resolve().then(action).catch(() => undefined);
  }

  function group(name: MenuName, label: string, items: { label: string; disabled?: boolean; selected?: boolean; action: () => void | Promise<void> }[]) {
    return <div className="app-menu-group" key={name}>
      <button type="button" className="app-menu-trigger" ref={(node) => { triggerRefs.current[name] = node; }}
        aria-expanded={opened === name} aria-controls={`app-menu-${name}`}
        onClick={() => setOpened((current) => current === name ? null : name)}>{label}</button>
      {opened === name && <div className="app-menu-popup" id={`app-menu-${name}`}>
        {items.map((item) => <button type="button" className="app-menu-item" key={item.label}
          disabled={item.disabled} aria-pressed={item.selected} onClick={() => run(item.action)}>
          {item.selected !== undefined && <span aria-hidden="true">{item.selected ? "✓ " : "　 "}</span>}{item.label}
        </button>)}
      </div>}
    </div>;
  }

  return <AppInfo hasUnsavedChanges={props.hasUnsavedChanges} isSaving={props.isBusy}
    onClose={() => triggerRefs.current.help?.focus()} renderTrigger={(openInfo) => (
    <VaultTools key={props.isUnlocked ? "unlocked" : "locked"} entryCount={props.entryCount} disabled={toolsDisabled} onRefresh={props.onRefresh}
      onSelect={props.onSelectEntry} onLock={props.onLock} onClose={() => triggerRefs.current.tools?.focus()} renderTrigger={(openTool) => (
        <div className="app-titlebar" role="banner">
          <div className="app-menu-bar" aria-label="アプリメニュー" ref={barRef} onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setOpened(null);
          }}>
            {group("file", "ファイル", [
              { label: "一覧を更新", disabled: disabled || props.isLoading, action: props.onRefresh },
              { label: "保管庫をロック", disabled: disabled || props.isLoading, action: props.onLock }
            ])}
            {group("edit", "編集", [
              { label: "新規エントリ", disabled: disabled || props.isFormOpen || props.isLoading, action: props.onNewEntry },
              { label: "ログインIDをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !props.selectedEntry, action: () => props.selectedEntry ? props.onCopy(props.selectedEntry.loginId, "ログインID") : undefined },
              { label: "パスワードをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !props.selectedEntry, action: () => props.selectedEntry ? props.onCopy(props.selectedEntry.password, "パスワード") : undefined }
            ])}
            {group("view", "表示", [
              { label: "全件表示", disabled, selected: !props.isGroupedView, action: () => props.onGroupedViewChange(false) },
              { label: "グループ表示", disabled, selected: props.isGroupedView, action: () => props.onGroupedViewChange(true) }
            ])}
            {group("tools", "ツール", [
              { label: "セキュリティ監査", disabled: toolsDisabled, action: () => openTool("audit") },
              { label: "バックアップ / 復元", disabled: toolsDisabled, action: () => openTool("backup") }
            ])}
            {group("help", "ヘルプ", [{ label: "アプリ情報 / 更新", action: openInfo }])}
          </div>
          <div className="app-titlebar-spacer" aria-hidden="true" />
        </div>
      )} />
  )} />;
}
