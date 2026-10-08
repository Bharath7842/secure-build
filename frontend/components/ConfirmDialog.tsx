"use client";

import { useCallback, useState } from "react";

export interface ConfirmOptions {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Red confirm button for destructive/stop actions (the default — every
   * current call site is one of those two). */
  danger?: boolean;
}

interface PendingConfirm extends ConfirmOptions {
  resolve: (value: boolean) => void;
}

/**
 * Promise-based replacement for `window.confirm()` that renders an actual
 * modal instead of a native browser dialog. Usage mirrors `window.confirm`:
 *
 *   const { confirm, dialog } = useConfirmDialog();
 *   if (!(await confirm("Stop this scan?"))) return;
 *   ...
 *   return <>{dialog}{...rest of the component}</>;
 *
 * `dialog` renders nothing until `confirm()` is pending, so it's safe to
 * always include in the tree.
 */
export function useConfirmDialog() {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirm = useCallback((options: ConfirmOptions | string): Promise<boolean> => {
    const opts: ConfirmOptions = typeof options === "string" ? { message: options } : options;
    return new Promise<boolean>((resolve) => {
      setPending({ danger: true, ...opts, resolve });
    });
  }, []);

  function settle(value: boolean) {
    pending?.resolve(value);
    setPending(null);
  }

  const dialog = pending ? (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-message"
    >
      <div className="w-full max-w-sm rounded-lg bg-white p-6 shadow-xl">
        {pending.title && (
          <h2 className="font-display text-lg text-[var(--ink)]">{pending.title}</h2>
        )}
        <p
          id="confirm-dialog-message"
          className={`text-sm text-[var(--muted)] ${pending.title ? "mt-2" : ""}`}
        >
          {pending.message}
        </p>
        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            autoFocus
            onClick={() => settle(false)}
            className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
          >
            {pending.cancelLabel ?? "Cancel"}
          </button>
          <button
            type="button"
            onClick={() => settle(true)}
            className={`rounded-md px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 ${
              pending.danger ? "bg-red-600" : "bg-[var(--accent)]"
            }`}
          >
            {pending.confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return { confirm, dialog };
}
