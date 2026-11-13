import { useEffect, useRef, useState, type ReactNode } from "react";
import type { PasswordEntry, VaultEntry, VaultMaintenanceOperation, VaultMaintenanceState } from "@password-manager/shared/types";
import type { DesignMode } from "../lib/design-mode";
import { windowControls } from "../lib/api";
import { EntriesIcon, EyeIcon, HelpIcon, LockIcon, MaximizeIcon, MinimizeIcon, RestoreIcon, SidebarIcon, WindowCloseIcon, WrenchIcon } from "./Icons";
import { AppInfo } from "./AppInfo";
import { VaultTools } from "./VaultTools";

// The title bar shows icons only; each says its name in a tooltip and to screen readers.
// The former File and Edit menus are one entries menu, Lock and Help are single buttons, and the
// list pane's toggle sits first, so every former menu item still has a way in.
type MenuName = "entries" | "view" | "tools";
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
  isSidebarCollapsed: boolean;
  onSidebarCollapsedChange: (collapsed: boolean) => void;
  designMode: DesignMode;
  onDesignModeChange: (mode: DesignMode) => void;
  vaultFormat: VaultMaintenanceState["format"];
  onRefresh: () => Promise<void>;
  onLock: () => Promise<void>;
  onNewEntry: () => void;
  onEditEntry: () => void;
  onGroupedViewChange: (grouped: boolean) => void;
  onSelectEntry: (id: string) => Promise<void>;
  onCopy: (value: string, label: string) => Promise<void>;
  onMaintenance: (operation: VaultMaintenanceOperation) => void;
};

export function AppMenu(props: AppMenuProps) {
  const selected = props.selectedEntry;
  const selectedLogin = selected?.type === "financial" ? { loginId: selected.financial.loginId, password: selected.financial.loginPassword }
    : selected?.type === "apiKey" || selected?.type === "creditCard" ? null : selected as PasswordEntry | null;
  const [opened, setOpened] = useState<MenuName | null>(null);
  const barRef = useRef<HTMLDivElement>(null);
  const triggerRefs = useRef<Partial<Record<MenuName, HTMLButtonElement | null>>>({});
  const helpRef = useRef<HTMLButtonElement>(null);
  const disabled = !props.isUnlocked || props.isBusy;
  const [isMaximized, setIsMaximized] = useState(false);

  // The maximize button shows "restore" while the window is maximized; any resize may change that.
  // A drag resize fires many events, so the window is asked once it settles.
  useEffect(() => {
    let active = true, timer: ReturnType<typeof setTimeout> | undefined;
    const read = () => { windowControls.isMaximized().then((value) => { if (active) setIsMaximized(value); }, () => undefined); };
    const settled = () => { clearTimeout(timer); timer = setTimeout(read, 150); };
    read();
    window.addEventListener("resize", settled);
    return () => { active = false; clearTimeout(timer); window.removeEventListener("resize", settled); };
  }, []);
  const toolsDisabled = disabled || props.hasUnsavedChanges || props.isLoading;
  const sidebarLabel = props.isSidebarCollapsed ? "一覧を広げる" : "一覧をアイコンだけにする";

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

  function group(name: MenuName, label: string, icon: ReactNode, items: MenuItem[]) {
    return <div className="app-menu-group" key={name}>
      <button type="button" className="app-menu-trigger" ref={(node) => { triggerRefs.current[name] = node; }}
        aria-label={label} data-tooltip={label} aria-haspopup="menu" aria-expanded={opened === name} aria-controls={`app-menu-${name}`}
        onClick={() => setOpened((current) => current === name ? null : name)}>{icon}</button>
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
    onClose={() => helpRef.current?.focus()} renderTrigger={(openInfo) => (
    <VaultTools key={props.isUnlocked ? "unlocked" : "locked"} entryCount={props.entryCount} disabled={toolsDisabled} onRefresh={props.onRefresh}
      onSelect={props.onSelectEntry} onClose={() => triggerRefs.current.tools?.focus()} renderTrigger={(openTool) => (
        // The empty parts of the bar move the window, and a double click maximizes it (data-tauri-drag-region).
        <div className="app-titlebar" role="banner" data-tauri-drag-region>
          <div className="app-menu-bar" aria-label="アプリメニュー" ref={barRef} onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) setOpened(null);
          }}>
            {props.isUnlocked && <>
              <button type="button" className="app-menu-trigger" aria-label={sidebarLabel} data-tooltip={sidebarLabel}
                onClick={() => { setOpened(null); props.onSidebarCollapsedChange(!props.isSidebarCollapsed); }}><SidebarIcon collapsed={props.isSidebarCollapsed} /></button>
              <span className="app-menu-divider" aria-hidden="true" />
              {group("entries", "項目", <EntriesIcon />, [
                { label: "新しい項目", disabled: disabled || props.isFormOpen || props.isLoading, action: props.onNewEntry },
                { label: "選択中の項目を編集", disabled: disabled || props.isLoading || props.isFormOpen || props.isEditingEntry || !props.selectedEntry, action: props.onEditEntry },
                "separator",
                { label: "ログインIDをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !selectedLogin, action: () => selectedLogin ? props.onCopy(selectedLogin.loginId, "ログインID") : undefined },
                { label: "パスワードをコピー", disabled: disabled || props.isLoading || props.isFormOpen || !selectedLogin, action: () => selectedLogin ? props.onCopy(selectedLogin.password, "パスワード") : undefined },
                "separator",
                { label: "一覧を更新", disabled: disabled || props.isLoading, action: props.onRefresh }
              ])}
            </>}
            {group("view", "表示", <EyeIcon />, [
              ...(props.isUnlocked ? [
                { label: "すべて", disabled, selected: !props.isGroupedView, action: () => props.onGroupedViewChange(false) },
                { label: "グループ別", disabled, selected: props.isGroupedView, action: () => props.onGroupedViewChange(true) },
                "separator" as const,
                { label: "一覧をアイコンだけで表示", selected: props.isSidebarCollapsed, action: () => props.onSidebarCollapsedChange(!props.isSidebarCollapsed) },
                "separator" as const
              ] : []),
              // The design is not vault data, so it stays available on the lock screen.
              { label: "シンプルデザイン", selected: props.designMode === "simple", action: () => props.onDesignModeChange("simple") },
              { label: "ルミナスデザイン", selected: props.designMode === "luminous", action: () => props.onDesignModeChange("luminous") }
            ])}
            {props.isUnlocked && group("tools", "ツール", <WrenchIcon />, [
              { label: "パスワードの点検", disabled: toolsDisabled, action: () => openTool("audit") },
              { label: "バックアップ", disabled: toolsDisabled, action: () => openTool("backup") },
              "separator",
              ...(props.vaultFormat !== "v2"
                ? [{ label: "保管庫を更新…", disabled: toolsDisabled, action: () => props.onMaintenance("migrate") }]
                : [{ label: "マスターパスワードを変更…", disabled: toolsDisabled, action: () => props.onMaintenance("rekey") },
                  { label: "保管庫を空にする…", disabled: toolsDisabled, action: () => props.onMaintenance("reset") }])
            ])}
            <button type="button" className="app-menu-trigger" ref={helpRef} aria-label="バージョンと更新" data-tooltip="バージョンと更新"
              onClick={() => { setOpened(null); openInfo(); }}><HelpIcon /></button>
            {props.isUnlocked && <>
              <span className="app-menu-divider" aria-hidden="true" />
              <button type="button" className="app-menu-trigger" aria-label="ロック" data-tooltip="ロック" disabled={disabled || props.isLoading}
                onClick={() => { setOpened(null); void Promise.resolve().then(props.onLock).catch(() => undefined); }}><LockIcon /></button>
            </>}
          </div>
          <div className="app-titlebar-spacer" aria-hidden="true" data-tauri-drag-region />
          <div className="window-controls" aria-label="ウィンドウ">
            <button type="button" className="window-control" aria-label="最小化" title="最小化"
              onClick={() => { void windowControls.minimize().catch(() => undefined); }}><MinimizeIcon /></button>
            <button type="button" className="window-control" aria-label={isMaximized ? "元に戻す" : "最大化"} title={isMaximized ? "元に戻す" : "最大化"}
              onClick={() => { void windowControls.toggleMaximize().catch(() => undefined); }}>{isMaximized ? <RestoreIcon /> : <MaximizeIcon />}</button>
            <button type="button" className="window-control window-control--close" aria-label="閉じる" title="閉じる"
              onClick={() => { void windowControls.close().catch(() => undefined); }}><WindowCloseIcon /></button>
          </div>
        </div>
      )} />
  )} />;
}
