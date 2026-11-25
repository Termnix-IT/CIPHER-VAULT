import { useEffect, useRef, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { currentConfirm, subscribeConfirms, type ConfirmRequest } from "../lib/confirm";
import { showModalDialog } from "../lib/modal";
import { CloseIcon } from "./Icons";

/** Shows the questions asked with askConfirm (lib/confirm.ts), one at a time. */
export function ConfirmHost() {
  const request = useSyncExternalStore(subscribeConfirms, currentConfirm);
  // Placed straight under <body> and only while asking: a dialog that is already open makes the
  // rest of the page inert (lib/modal.ts), and a question asked from it must stay usable.
  return request ? createPortal(<ConfirmDialog key={request.id} request={request} />, document.body) : null;
}

function ConfirmDialog({ request }: { request: ConfirmRequest }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  // A close made by the effect's cleanup is not an answer (React runs the effect twice in development).
  const closedByCleanup = useRef(false);

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    showModalDialog(element);
    // The safe answer has the focus, so Enter right after the question keeps the data.
    cancel.current?.focus();
    return () => {
      if (element.open) { closedByCleanup.current = true; element.close(); }
      // The page stays inert until the dialog's close event, so the focus goes back after it,
      // unless the answer already moved it somewhere.
      setTimeout(() => {
        const unfocused = !document.activeElement || document.activeElement === document.body;
        if (unfocused && returnFocus?.isConnected && !returnFocus.closest("[inert]")) returnFocus.focus();
      });
    };
  }, [request]);

  return <dialog ref={dialog} className="vault-tool-dialog confirm-dialog" role="alertdialog"
    aria-labelledby="confirm-dialog-title" aria-describedby="confirm-dialog-message"
    onClose={() => {
      // Escape closes the dialog without a button: that is "no".
      if (closedByCleanup.current) closedByCleanup.current = false;
      else request.answer(false);
    }}>
    <header className="vault-tool-heading">
      <h2 id="confirm-dialog-title">{request.title}</h2>
      <button className="icon-btn" type="button" aria-label="閉じる" data-tooltip="閉じる" onClick={() => request.answer(false)}><CloseIcon /></button>
    </header>
    <p className="confirm-dialog-message" id="confirm-dialog-message">{request.message}</p>
    <footer className="dialog-footer">
      <button ref={cancel} className="btn" type="button" data-confirm-cancel onClick={() => request.answer(false)}>{request.cancelLabel ?? "キャンセル"}</button>
      <button className="btn btn--danger" type="button" data-confirm-accept onClick={() => request.answer(true)}>{request.confirmLabel}</button>
    </footer>
  </dialog>;
}
