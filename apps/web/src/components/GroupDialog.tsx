import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { UNGROUPED_GROUP_NAME } from "@password-manager/shared";
import type { VaultEntrySummary } from "@password-manager/shared/types";
import { CloseIcon, SearchIcon } from "./Icons";

// The service limit, checked here so a long name is explained before the dialog closes.
const MAX_GROUP_NAME_BYTES = 1024;

type GroupDialogProps = {
  entries: VaultEntrySummary[];
  groupNames: string[];
  initialIds: string[];
  /** A rejection closes the dialog; the owner shows the error and has already re-read the list. */
  onSubmit: (ids: string[], group: string) => Promise<void>;
  onClose: () => void;
};

export function GroupDialog({ entries, groupNames, initialIds, onSubmit, onClose }: GroupDialogProps) {
  const [name, setName] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(() => new Set(initialIds));
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  const groupName = name.trim();
  const isExisting = groupNames.includes(groupName);
  const nameError = groupName === UNGROUPED_GROUP_NAME ? `「${UNGROUPED_GROUP_NAME}」はグループ名に使えません`
    : new TextEncoder().encode(groupName).length > MAX_GROUP_NAME_BYTES ? "グループ名が長すぎます" : "";
  const canSubmit = !busy && Boolean(groupName) && !nameError && selected.size > 0;
  // Items picked before the dialog opened stay on top so they are visible without scrolling.
  const ordered = useMemo(() => [...entries].sort((a, b) => Number(initialIds.includes(b.id)) - Number(initialIds.includes(a.id))
    || a.serviceName.localeCompare(b.serviceName, "ja", { numeric: true, sensitivity: "base" })), [entries, initialIds]);
  const term = search.trim().toLocaleLowerCase("ja-JP");
  const visible = ordered.filter((entry) => !term || [entry.serviceName, entry.loginId ?? "", entry.group ?? ""]
    .some((field) => field.toLocaleLowerCase("ja-JP").includes(term)));

  useEffect(() => {
    alive.current = true;
    if (!dialog.current?.open) dialog.current?.showModal();
    nameInput.current?.focus();
    return () => { alive.current = false; };
  }, []);

  function toggle(id: string, checked: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    await onSubmit([...selected], groupName).catch(() => undefined);
    if (alive.current) dialog.current?.close();
  }

  return <dialog ref={dialog} className="vault-tool-dialog group-dialog" aria-labelledby="group-dialog-title"
    onCancel={(event) => { if (busy) event.preventDefault(); }} onClose={onClose}>
    <form className="group-dialog-form" onSubmit={(event) => void submit(event)}>
      <header className="vault-tool-heading">
        <h2 id="group-dialog-title">新しいグループ</h2>
        <button className="icon-btn" type="button" aria-label="閉じる" disabled={busy} onClick={() => dialog.current?.close()}><CloseIcon /></button>
      </header>
      <div className="dialog-body">
        <label className="vault-tool-field group-dialog-name">グループ名
          <input ref={nameInput} name="groupName" autoComplete="off" placeholder="仕事" disabled={busy} value={name} onChange={(event) => setName(event.target.value)} />
        </label>
        <p className={`group-dialog-hint ${nameError ? "form-error" : ""}`} role={nameError ? "alert" : "status"}>
          {nameError || (isExisting ? "既存のグループに追加されます" : "")}
        </p>
        <p className="dialog-section-label">対象の項目</p>
        <div className="search-box">
          <SearchIcon />
          <input className="search-input" type="search" aria-label="項目を検索" placeholder="検索" disabled={busy} value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") event.preventDefault(); }} />
        </div>
        <div className="group-pick-list" role="group" aria-label="対象の項目">
          {visible.map((entry) => <label className="group-pick" key={entry.id}>
            <input type="checkbox" disabled={busy} checked={selected.has(entry.id)} onChange={(event) => toggle(entry.id, event.target.checked)} />
            <span className="group-pick-name">{entry.serviceName}</span>
            <span className="group-pick-group">{entry.group || UNGROUPED_GROUP_NAME}</span>
          </label>)}
          {visible.length === 0 && <p className="empty-state-text">見つかりません</p>}
        </div>
      </div>
      <footer className="dialog-footer dialog-footer--split">
        <span className="dialog-footer-meta" role="status">{selected.size}件を選択</span>
        <div className="group-dialog-actions">
          <button className="btn" type="button" disabled={busy} onClick={() => dialog.current?.close()}>キャンセル</button>
          <button className="btn btn--primary" type="submit" disabled={!canSubmit}>{busy ? "追加中…" : isExisting ? "追加" : "作成"}</button>
        </div>
      </footer>
    </form>
  </dialog>;
}
