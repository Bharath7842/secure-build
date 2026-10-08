"use client";

import { useCallback, useEffect, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import { displayPackTitle } from "@/components/DastRulePackPicker";
import { ApiError, api } from "@/lib/api";
import type { DastCheckMode, DastRuleConfigPatch, DastRuleSettings, DastRuleSettingsCheck, DastSource } from "@/lib/types";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const MODES: DastCheckMode[] = ["automated", "opt-in", "assist-only"];
const field = "agent-focus-ring rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-[var(--ink)]";

function SourceBadge({ source }: { source: DastSource }) {
  const style = source === "project" ? "bg-blue-50 text-blue-700" : source === "global" ? "bg-purple-50 text-purple-700" : "bg-slate-100 text-slate-500";
  return <span className={`rounded px-1.5 py-0.5 text-[10px] ${style}`}>{source}</span>;
}

/** Rule packs and per-check enabled / severity / mode (DAST-15-030, -040). With `projectId` it edits
 *  that project's overrides on top of the global ones; without, the global defaults. Each value shows
 *  where it comes from. */
export default function DastRuleManager({ projectId, refreshKey }: { projectId?: string; refreshKey?: number }) {
  const [data, setData] = useState<DastRuleSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const { confirm, dialog } = useConfirmDialog();

  const load = useCallback(async () => {
    try {
      setData(await api.dast.ruleSettings(projectId));
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load rules.");
    }
  }, [projectId]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount and when a custom rule changes
    void load();
  }, [load, refreshKey]);

  async function patch(label: string, body: DastRuleConfigPatch) {
    setBusy(label);
    setError(null);
    try {
      if (projectId) await api.dast.rules.updateProject(projectId, body);
      else await api.dast.rules.updateGlobal(body);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save.");
    } finally {
      setBusy(null);
    }
  }

  async function resetProject() {
    if (!projectId) return;
    if (!(await confirm({ title: "Reset project rules?", message: "This project goes back to the global rule settings. Its own overrides are removed.", confirmLabel: "Reset" }))) return;
    setBusy("reset");
    try {
      await api.dast.rules.resetProject(projectId);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reset.");
    } finally {
      setBusy(null);
    }
  }

  async function toggleCheck(check: DastRuleSettingsCheck, enabled: boolean) {
    if (!enabled && !check.passive && !(await confirm({ title: `Turn off ${check.title}?`, message: "Scans will stop running this check. You can turn it back on at any time.", confirmLabel: "Turn off" }))) return;
    await patch(check.check_id, { checks: { [check.check_id]: { enabled } } });
  }

  if (!data) {
    return error ? <p role="alert" className="text-sm text-red-700">{error}</p> : <p role="status" className="text-sm text-[var(--muted)]">Loading rules…</p>;
  }
  const q = filter.trim().toLowerCase();
  const checks = data.checks.filter((c) => !q || c.title.toLowerCase().includes(q) || c.check_id.toLowerCase().includes(q));

  return (
    <div className="space-y-5">
      {dialog}
      <p className="text-sm text-[var(--muted)]">{data.applies_to}</p>
      {error && <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

      <div>
        <h3 className="text-sm font-semibold text-[var(--ink)]">Rule packs</h3>
        <ul className="mt-2 grid gap-2 sm:grid-cols-2">
          {data.packs.map((pack) => (
            <li key={pack.id} className="rounded-md border border-slate-200 p-3">
              <label className="flex items-start gap-2.5 text-sm">
                <input type="checkbox" className="agent-focus-ring mt-0.5" checked={pack.enabled} disabled={busy !== null} onChange={(e) => patch(pack.id, { packs: { [pack.id]: e.target.checked } })} />
                <span className="min-w-0">
                  <span className="font-medium text-[var(--ink)]">{displayPackTitle(pack.title)}</span> <SourceBadge source={pack.source} />
                  <span className="block text-xs text-[var(--muted)]">{pack.description} · {pack.check_ids.length} checks</span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-[var(--ink)]">Checks ({checks.length})</h3>
          <div className="flex items-center gap-2">
            <label className="sr-only" htmlFor={`rule-filter-${projectId ?? "global"}`}>Filter checks</label>
            <input id={`rule-filter-${projectId ?? "global"}`} type="search" placeholder="Filter checks" value={filter} onChange={(e) => setFilter(e.target.value)} className={`${field} w-44`} />
            {projectId && <button type="button" onClick={resetProject} disabled={busy !== null} className="agent-focus-ring rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium hover:bg-slate-50 disabled:opacity-50">Reset to global</button>}
          </div>
        </div>
        <div className="mt-2 overflow-x-auto">
          <table className="w-full min-w-[44rem] text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs text-[var(--muted)]">
                <th scope="col" className="py-2 pr-3 font-medium">On</th>
                <th scope="col" className="py-2 pr-3 font-medium">Check</th>
                <th scope="col" className="py-2 pr-3 font-medium">Severity</th>
                <th scope="col" className="py-2 font-medium">Mode</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.check_id} className="border-b border-slate-100 align-top">
                  <td className="py-2 pr-3">
                    <input type="checkbox" className="agent-focus-ring" aria-label={`${c.title} enabled`} checked={c.enabled.value} disabled={busy !== null} onChange={(e) => toggleCheck(c, e.target.checked)} />
                    <div className="mt-1"><SourceBadge source={c.enabled.source} /></div>
                  </td>
                  <td className="py-2 pr-3">
                    <p className="font-medium text-[var(--ink)]">{c.title}{c.custom && <span className="ml-1.5 rounded bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-800">custom</span>}</p>
                    <p className="font-mono text-[11px] text-[var(--muted)]">{c.check_id}</p>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">{c.description}</p>
                    {c.requires.length > 0 && <p className="mt-0.5 text-[11px] text-[var(--muted)]">Needs: {c.requires.join(", ")}</p>}
                    {c.load_generating && <p className="mt-0.5 text-[11px] text-amber-800">Generates load on the target.</p>}
                    {c.notes.map((n) => <p key={n} className="mt-0.5 text-[11px] text-amber-800">{n}</p>)}
                  </td>
                  <td className="py-2 pr-3">
                    <select aria-label={`${c.title} severity`} className={field} value={c.severity.value} disabled={busy !== null} onChange={(e) => patch(c.check_id, { checks: { [c.check_id]: { severity: e.target.value } } })}>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <div className="mt-1"><SourceBadge source={c.severity.source} /></div>
                  </td>
                  <td className="py-2">
                    <select aria-label={`${c.title} mode`} className={field} value={c.mode.value} disabled={busy !== null} onChange={(e) => patch(c.check_id, { checks: { [c.check_id]: { mode: e.target.value as DastCheckMode } } })}>
                      {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
                    </select>
                    <div className="mt-1"><SourceBadge source={c.mode.source} /></div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
