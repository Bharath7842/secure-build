"use client";

import { useEffect, useMemo, useState } from "react";

import { api, apiFetch } from "@/lib/api";
import { STAGE_LABEL } from "@/lib/review";
import type { DecisionDiff, DecisionDiffChange, DecisionDiffEntry, Scan } from "@/lib/types";
import { unresolvedReasonLabel } from "@/lib/verdict";

interface Props {
  scanId: string;
  projectId: string;
}

const CHANGE_LABEL: Record<DecisionDiffChange, string> = {
  added: "Added",
  removed: "Removed",
  verdict_changed: "Verdict changed",
  issue_class_changed: "Issue class changed",
  unchanged: "Unchanged",
};

const CHANGE_CHIP: Record<DecisionDiffChange, string> = {
  added: "bg-blue-50 text-blue-700",
  removed: "bg-slate-100 text-slate-700",
  verdict_changed: "bg-amber-50 text-amber-800",
  issue_class_changed: "bg-violet-50 text-violet-700",
  unchanged: "bg-emerald-50 text-emerald-700",
};

const VERDICT_WORD: Record<string, string> = {
  true_positive: "Confirmed",
  false_positive: "False positive",
  unverified: "Unresolved",
  added: "added",
  removed: "removed",
};

/** The two transitions a reviewer must look at first: a confirmed finding that is now dismissed
 *  or gone. A scanner change is judged by these, not by how many rows it removed. */
const REVIEW_FIRST = new Set(["true_positive>false_positive", "true_positive>removed"]);

const ROW_LIMIT = 500;
const SCANNER_KEYS: [string, string][] = [
  ["engine_commit", "engine"],
  ["rule_catalog_sha256", "rule catalog"],
  ["result_cache_version", "cache version"],
  ["llm_model", "model"],
];

function word(verdict: string | null | undefined): string {
  return verdict ? (VERDICT_WORD[verdict] ?? verdict) : "—";
}

function side(state: DecisionDiffEntry["old"]): string {
  if (!state) return "—";
  const why = state.verdict === "unverified" ? unresolvedReasonLabel(state.unresolved_reason) : null;
  return `${word(state.verdict)}${why ? ` (${why})` : ""}`;
}

/** What differs between the two scans' recorded versions, in words. */
function scannerChanges(diff: DecisionDiff): string[] {
  const changes: string[] = [];
  for (const [key, label] of SCANNER_KEYS) {
    const a = diff.base.evidence_version[key];
    const b = diff.scan.evidence_version[key];
    if (a !== undefined && b !== undefined && a !== b) {
      const short = (value: unknown) => String(value).slice(0, 12);
      changes.push(`${label} ${short(a)} → ${short(b)}`);
    }
  }
  return changes;
}

async function downloadXlsx(scanId: string, base: string, includeUnchanged: boolean): Promise<void> {
  const params = new URLSearchParams({ base });
  if (includeUnchanged) params.set("include_unchanged", "true");
  const res = await apiFetch(`/api/scans/${scanId}/decision-diff/xlsx?${params}`, { cache: "no-store" });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body && typeof body === "object" && "detail" in body ? String(body.detail) : `Export failed (${res.status})`);
  }
  const blob = await res.blob();
  const match = /filename="?([^"]+)"?/i.exec(res.headers.get("content-disposition") || "");
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = match?.[1] || "decision-diff.xlsx";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** "Compare with…" for a finished SAST scan: pick another scan of the project and see every
 *  occurrence whose decision changed, in both directions, and which stage changed it. */
export default function ScanDecisionDiffPanel({ scanId, projectId }: Props) {
  const [open, setOpen] = useState(false);
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [base, setBase] = useState("");
  const [includeUnchanged, setIncludeUnchanged] = useState(false);
  const [diff, setDiff] = useState<DecisionDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [changeFilter, setChangeFilter] = useState<DecisionDiffChange | "">("");
  const [ruleFilter, setRuleFilter] = useState("");
  const [exportError, setExportError] = useState<string | null>(null);

  // The project's other finished SAST scans, loaded the first time the panel opens.
  useEffect(() => {
    if (!open || scans !== null) return;
    let active = true;
    api.scans
      .list(projectId, "sast")
      .then((all) => {
        if (active) setScans(all.filter((s) => s.id !== scanId && s.status === "success"));
      })
      .catch(() => active && setScans([]));
    return () => {
      active = false;
    };
  }, [open, scans, projectId, scanId]);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (!base) return;
    let active = true;
    setLoading(true);
    setError(null);
    api.scans
      .decisionDiff(scanId, base, includeUnchanged)
      .then((result) => {
        if (!active) return;
        setDiff(result);
        setChangeFilter("");
        setRuleFilter("");
      })
      .catch((err) => {
        if (!active) return;
        setDiff(null);
        setError(err instanceof Error ? err.message : "Could not compare the scans.");
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [scanId, base, includeUnchanged]);

  const rows = useMemo(() => {
    if (!diff) return [];
    return diff.entries.filter(
      (e) => (!changeFilter || e.change === changeFilter) && (!ruleFilter || e.rule_id === ruleFilter),
    );
  }, [diff, changeFilter, ruleFilter]);

  const changed = diff
    ? diff.counts.added + diff.counts.removed + diff.counts.verdict_changed + diff.counts.issue_class_changed
    : 0;
  const scannerDiffs = diff ? scannerChanges(diff) : [];

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls="decision-diff-panel"
        className="agent-focus-ring inline-flex h-7 items-center gap-1 rounded-md border border-slate-200 bg-white px-2 text-[11px] font-medium text-[var(--ink)] transition-colors hover:bg-slate-50"
      >
        Compare with…
      </button>
      {open ? (
        <section
          id="decision-diff-panel"
          aria-label="Decision diff between scans"
          className="fixed right-6 top-16 z-40 flex max-h-[80vh] w-[min(980px,calc(100vw-3rem))] flex-col overflow-hidden rounded-md border border-slate-200 bg-white text-xs shadow-xl"
        >
          <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-4 py-3">
            <label htmlFor="decision-diff-base" className="font-medium text-[var(--ink)]">
              Compare with
            </label>
            <select
              id="decision-diff-base"
              value={base}
              onChange={(e) => setBase(e.target.value)}
              disabled={scans === null}
              className="agent-focus-ring rounded-md border border-slate-300 bg-white px-2 py-1 text-xs"
            >
              <option value="">{scans === null ? "Loading scans…" : "Choose a scan"}</option>
              {(scans ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  v{s.version} · {new Date(s.created_at).toLocaleDateString()}
                  {s.commit_sha ? ` · ${s.commit_sha.slice(0, 7)}` : ""}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1.5 text-[var(--muted)]">
              <input
                type="checkbox"
                checked={includeUnchanged}
                onChange={(e) => setIncludeUnchanged(e.target.checked)}
              />
              Show unchanged
            </label>
            <div className="ml-auto flex items-center gap-2">
              {diff ? (
                <button
                  type="button"
                  onClick={() => {
                    setExportError(null);
                    downloadXlsx(scanId, base, includeUnchanged).catch((err) =>
                      setExportError(err instanceof Error ? err.message : "Export failed"),
                    );
                  }}
                  className="agent-focus-ring inline-flex h-7 items-center rounded-md border border-emerald-200 bg-emerald-50 px-2 text-[11px] font-bold text-emerald-700 hover:bg-emerald-100"
                >
                  Excel
                </button>
              ) : null}
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="agent-focus-ring rounded-md px-2 py-1 text-[var(--muted)] hover:bg-slate-100"
                aria-label="Close comparison"
              >
                Close
              </button>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
            {exportError ? <p role="alert" className="mb-2 text-red-700">{exportError}</p> : null}
            {!base && !loading ? (
              <p className="text-[var(--muted)]">
                {scans && scans.length === 0
                  ? "This project has no other finished SAST scan to compare with."
                  : "Pick another scan of this project to see what the scanner decided differently."}
              </p>
            ) : null}
            {loading ? <p className="text-[var(--muted)]">Comparing…</p> : null}
            {error ? <p role="alert" className="text-red-700">{error}</p> : null}

            {diff && !loading ? (
              <div className="space-y-4">
                <p className="text-[var(--muted)]">
                  v{diff.scan.version} compared with v{diff.base.version}: {changed} occurrence
                  {changed === 1 ? "" : "s"} changed
                  {diff.commit_differs ? " · the two scans are of different commits" : ""}
                  {diff.file_level_joins > 0
                    ? ` · ${diff.file_level_joins} joined at file level only (weaker identity)`
                    : ""}
                </p>
                {scannerDiffs.length > 0 ? (
                  <p className="rounded border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-amber-900">
                    The scanner itself changed between these scans: {scannerDiffs.join("; ")}.
                  </p>
                ) : null}

                <div className="flex flex-wrap gap-2">
                  {(Object.keys(CHANGE_LABEL) as DecisionDiffChange[]).map((change) => (
                    <span
                      key={change}
                      className={`rounded-full px-2.5 py-0.5 font-medium tabular-nums ${CHANGE_CHIP[change]}`}
                    >
                      {CHANGE_LABEL[change]} {diff.counts[change]}
                    </span>
                  ))}
                </div>

                {diff.summary.transitions.length > 0 ? (
                  <div>
                    <h3 className="mb-1 font-semibold text-[var(--ink)]">Verdict transitions</h3>
                    <ul className="space-y-0.5">
                      {diff.summary.transitions.map((t) => {
                        const urgent = REVIEW_FIRST.has(`${t.from}>${t.to}`);
                        return (
                          <li key={`${t.from}>${t.to}`} className={urgent ? "font-medium text-red-700" : ""}>
                            <span className="tabular-nums">{t.count}×</span> {word(t.from)} → {word(t.to)}
                            {urgent ? " — review these first" : ""}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ) : null}

                <div className="flex flex-wrap items-center gap-3">
                  <label className="flex items-center gap-1.5">
                    <span className="text-[var(--muted)]">Change</span>
                    <select
                      value={changeFilter}
                      onChange={(e) => setChangeFilter(e.target.value as DecisionDiffChange | "")}
                      className="agent-focus-ring rounded-md border border-slate-300 bg-white px-2 py-1"
                    >
                      <option value="">All</option>
                      {(Object.keys(CHANGE_LABEL) as DecisionDiffChange[])
                        .filter((c) => diff.entries.some((e) => e.change === c))
                        .map((c) => (
                          <option key={c} value={c}>
                            {CHANGE_LABEL[c]}
                          </option>
                        ))}
                    </select>
                  </label>
                  <label className="flex items-center gap-1.5">
                    <span className="text-[var(--muted)]">Rule</span>
                    <select
                      value={ruleFilter}
                      onChange={(e) => setRuleFilter(e.target.value)}
                      className="agent-focus-ring max-w-[16rem] rounded-md border border-slate-300 bg-white px-2 py-1"
                    >
                      <option value="">All</option>
                      {Object.keys(diff.summary.by_rule).map((rule) => (
                        <option key={rule} value={rule}>
                          {rule}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span className="text-[var(--muted)]">
                    {rows.length} row{rows.length === 1 ? "" : "s"}
                  </span>
                </div>

                {rows.length === 0 ? (
                  <p className="text-[var(--muted)]">
                    {diff.entries.length === 0
                      ? "No occurrence was decided differently."
                      : "No row matches the filters."}
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[720px] border-collapse text-left">
                      <thead>
                        <tr className="border-b border-slate-200 text-[var(--muted)]">
                          <th className="py-1.5 pr-3 font-medium">Change</th>
                          <th className="py-1.5 pr-3 font-medium">Rule</th>
                          <th className="py-1.5 pr-3 font-medium">Location</th>
                          <th className="py-1.5 pr-3 font-medium">Before</th>
                          <th className="py-1.5 pr-3 font-medium">Now</th>
                          <th className="py-1.5 font-medium">Decided by</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.slice(0, ROW_LIMIT).map((e) => (
                          <tr key={e.occurrence_id} className="border-b border-slate-100 align-top">
                            <td className="py-1.5 pr-3">
                              <span className={`rounded px-1.5 py-0.5 font-medium ${CHANGE_CHIP[e.change]}`}>
                                {CHANGE_LABEL[e.change]}
                              </span>
                            </td>
                            <td className="py-1.5 pr-3 font-mono">{e.rule_id ?? "—"}</td>
                            <td className="max-w-[20rem] break-all py-1.5 pr-3 font-mono">
                              {e.file_path ?? "—"}
                              {e.line ? `:${e.line}` : ""}
                              {e.identity_quality === "file_level" ? (
                                <span className="ml-1 font-sans text-[var(--muted)]" title="No enclosing method could be resolved">
                                  (file level)
                                </span>
                              ) : null}
                            </td>
                            <td className="py-1.5 pr-3">{side(e.old)}</td>
                            <td className="py-1.5 pr-3" title={e.verdict_reason ?? undefined}>
                              {side(e.new)}
                            </td>
                            <td className="py-1.5 text-[var(--muted)]">
                              {e.stage ? (STAGE_LABEL[e.stage] ?? e.stage) : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {rows.length > ROW_LIMIT ? (
                      <p className="mt-2 text-[var(--muted)]">
                        Showing the first {ROW_LIMIT} of {rows.length} rows; the Excel export has them all.
                      </p>
                    ) : null}
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </section>
      ) : null}
    </div>
  );
}
