import { useEffect, useRef, useState } from "react";
import type { PasswordEntry, VaultEntry, VaultMaintenanceOperation, VaultMaintenanceState } from "@password-manager/shared/types";
import { AppInfo } from "./AppInfo";
import { VaultTools } from "./VaultTools";

type MenuName = "file" | "edit" | "view" | "tools" | "help";
type MenuItem = { label: string; disabled?: boolean; selected?: boolean; action: () => void | Promise<void> } | "separator";
type AppMenuProps = {
  isUnlocked: boolean;
  isBusy: boolean;
  isLoading: boolean;
  hasUnsavedChanges: boolean;
  entryCount: number;
  selectedEntry: VaultEntry | null;
  isFormOpen: boolean;
  isEditingEntry: boolean;
  isGroupedView: boolean;
  vaultFormat: VaultMaintenanceState["format"];
  onRefresh: () => Promise<void>;
  onLock: () => Promise<void>;
  onNewEntry: () => void;
  onEditEntry: () => void;
  onGroupedViewChange: (grouped: boolean) => void;
  onSelectEntry: (id: string) => Promise<void>;
  onCopy: (value: string, label: string) => Promise<void>;
  onMaintenance: (operation: VaultMaintenanceOperation) => void;
  onConnections: () => void;
  connectionsAvailable: boolean;
};

export function AppMenu(props: AppMenuProps) {
  const selectedLogin = props.selectedEntry?.type === "apiKey" || props.selectedEntry?.type === "creditCard" ? null : props.selectedEntry as PasswordEntry | null;
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

  function group(name: MenuName, label: string, items: MenuItem[]) {
    return <div className="app-menu-group" key={name}>
      <button type="button" className="app-menu-trigger" ref={(node) => { triggerRefs.current[name] = node; }}
        aria-expanded={opened === name} aria-controls={`app-menu-${name}`}
        onClick={() => setOpened((current) => current === name ? null : name)}>{label}</button>
      {opened === name && <div className="app-menu-popup" id={`app-menu-${name}`}>
        {items.map((item, index) => item === "separator" ? <hr className="app-menu-separator" key={`separator-${index}`} /> :
          <button type="button" className="app-menu-item" key={item.label}
            disabled={item.disabled} aria-pressed={item.selected} onClick={() => run(item.action)}>
            {item.selected !== undefined && <span className="app-menu-check" aria-hidden="true">{item.selected ? "✓" : ""}</span>}{item.label}
          </button>)}
      </div>}
    </div>;
  }

  return <AppInfo hasUnsavedChanges={props.hasUnsavedChanges} isSaving={props.isBusy}
    onClose={() => triggerRefs.current.help?.focus()} renderTrigger={(openInfo) => (
    <VaultTools key={props.isUnlocked ? "unlocked" : "locked"} entryCount={props.entryCount} disabled={toolsDisabled} onRefresh={props.onRefresh}
      onSelect={props.onSelectEntry} onClose={() => triggerRefs.current.tools?.focus()} renderTrigger={(openTool) => (
        <div className="app-titlebar" role="banner">
          <div className="app-menu-bar" aria-label="アプリメニュー" ref={barRef} onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setOpened(null);
          }}>
            {group("file", "ファイル", [
              { label: "一覧を更新", disabled: disabled || props.isLoading, action: props.onRefresh },
              { label: "ロック", disabled: disabled || props.isLoading, action: props.onLock }
            ])}
            {group("edit", "編集", [
              { label: "新しい項目", disabled: disabled || props.isFormOpen || props.isLoading, action: props.onNewEntry },
              { label: "選択中の項目を編集", disabled: disabled || props.isLoading || props.isFormOpen || props.isEditingEntry || !props.selectedEntry, action: props.onEditEntry },
              "separator",
              { label: "ログインIDをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !selectedLogin, action: () => selectedLogin ? props.onCopy(selectedLogin.loginId, "ログインID") : undefined },
              { label: "パスワードをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !selectedLogin, action: () => selectedLogin ? props.onCopy(selectedLogin.password, "パスワード") : undefined }
            ])}
            {group("view", "表示", [
              { label: "すべて", disabled, selected: !props.isGroupedView, action: () => props.onGroupedViewChange(false) },
              { label: "グループ別", disabled, selected: props.isGroupedView, action: () => props.onGroupedViewChange(true) }
            ])}
            {group("tools", "ツール", [
              { label: "パスワードの点検", disabled: toolsDisabled, action: () => openTool("audit") },
              { label: "バックアップ", disabled: toolsDisabled, action: () => openTool("backup") },
              "separator",
              ...(props.vaultFormat !== "v2"
                ? [{ label: "保管庫を更新…", disabled: toolsDisabled, action: () => props.onMaintenance("migrate") }]
                : [{ label: "マスターパスワードを変更…", disabled: toolsDisabled, action: () => props.onMaintenance("rekey") },
                  { label: "保管庫を空にする…", disabled: toolsDisabled, action: () => props.onMaintenance("reset") }]),
              "separator",
              { label: "外部アプリの接続", disabled: toolsDisabled || !props.connectionsAvailable, action: props.onConnections }
            ])}
            {group("help", "ヘルプ", [{ label: "バージョンと更新", action: openInfo }])}
          </div>
          <div className="app-titlebar-spacer" aria-hidden="true" />
        </div>
      )} />
  )} />;
}
