"use client";

import type { ReactNode } from "react";

export type ArtifactTone = "blue" | "emerald" | "purple" | "red" | "amber";

const TONE_STYLES: Record<ArtifactTone, string> = {
  blue: "bg-blue-100 text-blue-600",
  emerald: "bg-emerald-100 text-emerald-600",
  purple: "bg-purple-100 text-purple-600",
  red: "bg-red-100 text-red-600",
  amber: "bg-amber-100 text-amber-700",
};

export interface AgentArtifactCardProps {
  icon: ReactNode;
  title: string;
  subtitle: string;
  active?: boolean;
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  ariaLabel?: string;
  tone?: ArtifactTone;
}

export default function AgentArtifactCard({
  icon,
  title,
  subtitle,
  active = false,
  disabled = false,
  loading = false,
  onClick,
  ariaLabel,
  tone = "blue",
}: AgentArtifactCardProps) {
  const interactive = !disabled && !loading && Boolean(onClick);

  return (
    <button
      type="button"
      onClick={interactive ? onClick : undefined}
      disabled={disabled || loading}
      aria-pressed={active}
      aria-disabled={disabled || loading || undefined}
      aria-label={ariaLabel ?? title}
      aria-busy={loading || undefined}
      className={[
        "agent-focus-ring agent-artifact-card flex w-full max-w-md items-center gap-3 border px-4 py-3 text-left transition-colors",
        "disabled:cursor-not-allowed",
        active ? "is-active" : "",
        loading ? "is-loading" : "",
        disabled ? "is-disabled" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <span
        className={`relative flex h-10 w-10 shrink-0 items-center justify-center rounded-md ${TONE_STYLES[tone]}`}
      >
        {icon}
        {loading && (
          <span
            className="absolute inset-0 animate-pulse rounded-md bg-white/50"
            aria-hidden
          />
        )}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-[var(--ink)]">{title}</span>
        <span className="block truncate text-xs text-[var(--muted)]">{subtitle}</span>
      </span>
      <span className="shrink-0 text-xs font-medium text-[var(--accent)]">View →</span>
    </button>
  );
}
