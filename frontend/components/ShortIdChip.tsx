"use client";

import { useEffect, useState } from "react";

/** The issue's short ID (`SB-7F3A9C21`); click copies it. Sits inside a clickable row, so it never toggles the row. */
export default function ShortIdChip({ id }: { id: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 1500);
    return () => clearTimeout(t);
  }, [state]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(id);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  return (
    <span
      role="button"
      tabIndex={0}
      data-testid="finding-short-id"
      title="Issue ID: click to copy. Give it to the secure-fix Claude skill, e.g. /secure-fix plan"
      onClick={(e) => {
        e.stopPropagation();
        void copy();
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          e.stopPropagation();
          void copy();
        }
      }}
      className="cursor-pointer rounded-md border border-slate-200 bg-white px-1.5 py-0.5 font-mono text-[11px] font-medium text-slate-600 hover:border-[var(--accent)] hover:text-[var(--accent)]"
    >
      <span aria-live="polite">{state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : id}</span>
    </span>
  );
}
