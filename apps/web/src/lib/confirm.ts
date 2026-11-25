// The app's own confirmations, in place of window.confirm and the desktop's message boxes.
//
// askConfirm() queues a question and resolves with the answer; ConfirmHost (components/ConfirmDialog.tsx)
// shows the first one. The answer arrives later than window.confirm's, so callers check again
// afterwards that what they asked about still applies. Locking answers every open question with
// "no" (dismissConfirms), so a question about the vault never stays on the lock screen.

export type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel?: string;
};

export type ConfirmRequest = ConfirmOptions & { id: number; answer: (accepted: boolean) => void };

let queue: ConfirmRequest[] = [];
let nextId = 0;
const listeners = new Set<() => void>();
const notify = () => { for (const listener of listeners) listener(); };

export function askConfirm(options: ConfirmOptions): Promise<boolean> {
  return new Promise((resolve) => {
    const id = ++nextId;
    const answer = (accepted: boolean) => {
      if (!queue.some((request) => request.id === id)) return;
      queue = queue.filter((request) => request.id !== id);
      notify();
      resolve(accepted);
    };
    queue = [...queue, { ...options, id, answer }];
    notify();
  });
}

/** The question asked before unsaved input is dropped; `action` finishes "変更を破棄して…か？". */
export function askDiscard(confirmLabel: string, action?: string) {
  return askConfirm({
    title: "保存していない変更があります",
    message: action ? `変更を破棄して${action}か？` : "変更を破棄しますか？",
    confirmLabel,
    cancelLabel: "編集に戻る"
  });
}

/** Answers every open question with "no". */
export function dismissConfirms() {
  for (const request of [...queue]) request.answer(false);
}

export function currentConfirm(): ConfirmRequest | null {
  return queue[0] ?? null;
}

export function subscribeConfirms(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
