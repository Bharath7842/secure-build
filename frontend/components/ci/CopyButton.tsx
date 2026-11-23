"use client";

import { useEffect, useState } from "react";

/** Copies `text` and says so for a moment (also to screen readers). */
export default function CopyButton({
  text,
  label = "Copy",
  className,
  variant = "ghost",
}: {
  text: string;
  label?: string;
  className?: string;
  variant?: "ghost" | "primary" | "dark";
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 1800);
    return () => clearTimeout(t);
  }, [state]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  const styles = {
    ghost: "border border-slate-200 bg-white text-[var(--ink)] hover:border-[var(--accent)] hover:text-[var(--accent)]",
    primary: "bg-[var(--accent)] text-white hover:opacity-90",
    dark: "border border-white/15 bg-white/10 text-slate-100 hover:bg-white/20",
  }[variant];

  return (
    <button
      type="button"
      onClick={copy}
      disabled={!text}
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${styles} ${className ?? ""}`}
    >
      <svg aria-hidden viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
        {state === "copied" ? (
          <path d="M3 8.5l3 3 7-7" strokeLinecap="round" strokeLinejoin="round" />
        ) : (
          <>
            <rect x="5" y="5" width="8.5" height="8.5" rx="1.5" />
            <path d="M3 10.5V3.5A1 1 0 0 1 4 2.5h6.5" strokeLinecap="round" />
          </>
        )}
      </svg>
      <span aria-live="polite">{state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : label}</span>
    </button>
  );
}
