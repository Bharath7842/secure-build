"use client";

import { useCallback, useEffect, useState } from "react";

import AgentPriorityList from "@/components/agent-reports/AgentPriorityList";
import { ICON_SPARKLE, Icon } from "@/components/FindingExplainDrawer";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import { ApiError, api } from "@/lib/api";
import type { AgentReport, AgentReportSummary } from "@/lib/types";
import { formatDate } from "@/lib/vulnReport";

export default function NetraInbox() {
  const { activeProject } = useActiveProject();
  const [rows, setRows] = useState<AgentReportSummary[]>([]);
  const [selected, setSelected] = useState<AgentReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const projectId = activeProject?.id ?? null;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.agentReports.list(projectId);
      setRows(list);
      if (list[0]) {
        setSelected(await api.agentReports.get(list[0].id));
      } else {
        setSelected(null);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load the inbox.");
      setRows([]);
      setSelected(null);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function open(id: string) {
    try {
      setSelected(await api.agentReports.get(id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not open that list.");
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(16rem,20rem)_1fr]">
      <aside className="rounded-md border border-slate-200 bg-white">
        <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--ink)]">Pushed lists</h2>
          <button type="button" onClick={() => void load()} className="text-xs font-medium text-[var(--accent)] hover:underline">
            Refresh
          </button>
        </div>
        {loading ? <p className="px-4 py-6 text-sm text-[var(--muted)]">Loading…</p> : null}
        {!loading && rows.length === 0 ? (
          <p className="px-4 py-6 text-sm text-[var(--muted)]">
            Nothing here yet. A Claude or Codex schedule POSTs a summary and an ordered list to{" "}
            <code className="font-mono text-[11px]">/agent-reports</code>.
          </p>
        ) : null}
        <ul>
          {rows.map((row) => (
            <li key={row.id}>
              <button
                type="button"
                onClick={() => void open(row.id)}
                className={`w-full border-b border-slate-100 px-4 py-3 text-left last:border-b-0 ${
                  selected?.id === row.id ? "bg-blue-50" : "hover:bg-slate-50"
                }`}
              >
                <p className="truncate text-sm font-medium text-[var(--ink)]">{row.title}</p>
                <p className="mt-0.5 text-[11px] text-[var(--muted)]">
                  {row.source} · {row.item_count} {row.item_count === 1 ? "item" : "items"}
                  {row.created_at ? ` · ${formatDate(row.created_at)}` : ""}
                </p>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      <section className="flex min-h-[24rem] flex-col rounded-md border border-blue-200 bg-gradient-to-br from-blue-50 via-white to-violet-50">
        <div className="flex items-center gap-2 border-b border-blue-100 px-5 py-4">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-gradient-to-br from-blue-600 to-violet-600 text-white shadow-sm">
            <Icon d={ICON_SPARKLE} size={15} />
          </span>
          <h2 className="text-base font-semibold text-[var(--ink)]">Netra</h2>
          <span className="text-xs text-[var(--muted)]">Shows the list in the order it was pushed</span>
        </div>
        {error ? (
          <p className="px-5 py-4 text-sm text-red-700" role="alert">
            {error}
          </p>
        ) : null}
        {selected ? (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="px-5 py-4">
              <p className="text-xs font-medium uppercase tracking-wide text-blue-700">{selected.source}</p>
              <h3 className="mt-1 text-lg font-semibold text-[var(--ink)]">{selected.title}</h3>
              <p className="mt-1 text-[11px] text-[var(--muted)]">
                {selected.actor_label || "scheduler"}
                {selected.created_at ? ` · ${formatDate(selected.created_at)}` : ""}
              </p>
              <p className="mt-2 text-sm leading-relaxed text-[var(--ink)]">{selected.summary}</p>
              {selected.context ? (
                <p className="mt-2 rounded-md border border-slate-200 bg-white/80 px-3 py-2 text-xs leading-relaxed text-[var(--muted)]">
                  {selected.context}
                </p>
              ) : null}
            </div>
            <div className="mx-5 mb-5">
              <AgentPriorityList items={selected.items} />
            </div>
          </div>
        ) : !loading ? (
          <p className="px-5 py-10 text-sm text-[var(--muted)]">Select a list to open it in Netra.</p>
        ) : null}
      </section>
    </div>
  );
}
