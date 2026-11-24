"use client";

import type { AgentPriorityItem, VulnSeverity } from "@/lib/types";
import { SEVERITY_PILL } from "@/lib/vulnReport";

function severityClass(severity: string | null): string {
  const key = (severity || "").toUpperCase() as VulnSeverity;
  return SEVERITY_PILL[key] ?? "border-slate-200 bg-slate-50 text-slate-600";
}

export default function AgentPriorityList({
  items,
  onPick,
  scheduledIds,
  onToggleScheduled,
}: {
  items: AgentPriorityItem[];
  onPick?: (item: AgentPriorityItem) => void;
  scheduledIds?: ReadonlySet<string>;
  onToggleScheduled?: (shortId: string | null | undefined) => void;
}) {
  if (items.length === 0) {
    return <p className="px-4 py-6 text-sm text-[var(--muted)]">No items in this list.</p>;
  }
  return (
    <ol className="overflow-hidden rounded-md border border-slate-200 bg-white">
      {items.map((item) => {
        const body = (
          <>
            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white text-xs font-semibold tabular-nums text-[var(--ink)] ring-1 ring-slate-200">
              {item.rank}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                {item.short_id ? (
                  <span className="font-mono text-[11px] font-medium text-[var(--ink)]">{item.short_id}</span>
                ) : null}
                {item.severity ? (
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityClass(item.severity)}`}
                  >
                    {item.severity}
                  </span>
                ) : null}
              </div>
              <p className="mt-0.5 text-sm font-medium text-[var(--ink)]">{item.title}</p>
              {item.reason ? <p className="mt-0.5 text-xs leading-relaxed text-[var(--muted)]">{item.reason}</p> : null}
              {item.file_path ? (
                <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--muted)]">{item.file_path}</p>
              ) : null}
            </div>
          </>
        );
        const marked = Boolean(item.short_id && scheduledIds?.has(item.short_id.toUpperCase()));
        return (
          <li key={`${item.rank}-${item.short_id ?? item.title}`} className="border-b border-slate-100 last:border-b-0">
            <div className={`flex items-start gap-2 px-3 py-3 ${marked ? "bg-blue-50/70" : ""}`}>
              {onToggleScheduled ? (
                <input
                  type="checkbox"
                  className="mt-1.5 h-4 w-4 shrink-0 accent-[var(--accent)]"
                  disabled={!item.short_id}
                  checked={marked}
                  onChange={() => onToggleScheduled(item.short_id)}
                  aria-label={item.short_id ? `Mark ${item.short_id} for scheduled fix` : "No issue id to mark"}
                  title={item.short_id ? "Mark for scheduled fix" : "Needs an issue id"}
                />
              ) : null}
              {onPick ? (
                <button type="button" onClick={() => onPick(item)} className="flex min-w-0 flex-1 gap-3 text-left hover:opacity-90">
                  {body}
                </button>
              ) : (
                <div className="flex min-w-0 flex-1 gap-3">{body}</div>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
