"use client";

import { useEffect, useState } from "react";

import DastHttpExchange from "@/components/DastHttpExchange";
import ScanExportButtons from "@/components/ScanExportButtons";
import { api } from "@/lib/api";
import { DAST_VERDICT_LABEL, RISK_DOT, RISK_STYLES, VERDICT_ROW, VERDICT_TEXT, normalizeSeverity } from "@/lib/findingStyles";
import type { DastDiffEntry, DastDiffStatus, DastReport, DastReportFinding, Scan } from "@/lib/types";
import { displayFindingTitle, hideInconclusive } from "@/lib/httpLabel";
import { dastVerdictKind } from "@/lib/verdict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const STATUS_STYLE: Record<DastDiffStatus, { label: string; head: string; chip: string }> = {
  new: { label: "New", head: "text-red-700", chip: "border-red-200 bg-red-50 text-red-700" },
  still_open: { label: "Still open", head: "text-amber-800", chip: "border-amber-200 bg-amber-50 text-amber-800" },
  fixed: { label: "Fixed", head: "text-emerald-700", chip: "border-emerald-200 bg-emerald-50 text-emerald-700" },
};

function ReportFinding({ finding }: { finding: DastReportFinding }) {
  const severity = normalizeSeverity(finding.severity, true);
  const kind = dastVerdictKind(finding.verdict);
  const evidence = finding.evidence;
  return (
    <li className={`rounded-md border px-3 py-2.5 ${VERDICT_ROW[kind]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${RISK_STYLES[severity]?.chip ?? ""}`}>
          {severity}
        </span>
        <span className={`text-xs font-semibold ${VERDICT_TEXT[kind]}`}>{DAST_VERDICT_LABEL[kind]}</span>
        {finding.check_id && <span className="font-mono text-[11px] text-[var(--muted)]">{finding.check_id}</span>}
      </div>
      <p className="mt-1.5 text-sm font-medium text-[var(--ink)]">{displayFindingTitle(finding.title, finding)}</p>
      {finding.reason && <p className="mt-1 text-sm text-[var(--muted)]">{hideInconclusive(finding.reason)}</p>}
      {evidence && (
        <DastHttpExchange
          request={
            evidence.request?.method || evidence.request?.url
              ? evidence.request
              : { method: (finding.target || "").split(/\s+/)[0] || "", url: finding.target, parameter: finding.param, location: finding.location }
          }
          baseline={evidence.baseline}
          response={evidence.test}
          signals={evidence.signals}
        />
      )}
    </li>
  );
}

function DiffList({ status, entries }: { status: DastDiffStatus; entries: DastDiffEntry[] }) {
  const style = STATUS_STYLE[status];
  return (
    <section aria-labelledby={`diff-${status}`}>
      <h4 id={`diff-${status}`} className={`text-xs font-semibold uppercase tracking-wide ${style.head}`}>
        {style.label} ({entries.length})
      </h4>
      {entries.length === 0 ? (
        <p className="mt-1 text-xs text-[var(--muted)]">None.</p>
      ) : (
        <ul className="mt-1.5 space-y-1">
          {entries.map((e, i) => (
            <li key={`${e.check_id}-${e.target}-${e.param}-${i}`} className="flex flex-wrap items-center gap-2 rounded border border-slate-200 bg-white px-2 py-1 text-xs">
              <span className={`rounded border px-1.5 py-0.5 font-semibold ${style.chip}`}>{style.label}</span>
              <span className="font-mono text-[var(--muted)]">{e.check_id}</span>
              <span className="min-w-0 break-all font-mono text-[var(--ink)]">{e.target}</span>
              {e.param && <span className="text-[var(--muted)]">[{e.param}]</span>}
              {e.roles.length > 1 && <span className="text-[var(--muted)]">{e.roles[0]} → {e.roles[1]}</span>}
              <span className="ml-auto flex items-center gap-1.5">
                <span className="font-medium text-[var(--ink)]">{e.severity}</span>
                {e.verdict === "false_positive" && <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-emerald-800">Dismissed</span>}
              </span>
              {e.note && <span className="w-full text-[11px] text-[var(--muted)]">{e.note}</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

interface DastReportPanelProps {
  scanId: string;
  projectId: string;
  version: number | null;
  running: boolean;
  onClose: () => void;
}

/** The report view (DAST-14-030): confirmed severity totals with unverified apart, what changed since a
 *  chosen earlier scan (New / Still open / Fixed), checks that were skipped or limited, the rule packs
 *  used, and the PDF and Excel downloads. */
export default function DastReportPanel({ scanId, projectId, version, running, onClose }: DastReportPanelProps) {
  const [against, setAgainst] = useState("");
  const [report, setReport] = useState<DastReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [earlier, setEarlier] = useState<Scan[]>([]);

  useEffect(() => {
    let active = true;
    api.scans
      .list(projectId, "dast")
      .then((scans) => active && setEarlier(scans.filter((s) => s.id !== scanId && s.status === "success" && (version == null || s.version < version)).sort((a, b) => b.version - a.version)))
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [projectId, scanId, version]);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await api.scans.report(scanId, against || undefined);
        if (!active) return;
        setReport(data);
        setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Could not load the report.");
      }
    }
    load();
    if (!running) return () => { active = false; };
    const timer = setInterval(load, 4000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [scanId, against, running]);

  const diff = report?.diff;
  const entries = (status: DastDiffStatus) => (diff?.entries ?? []).filter((e) => e.status === status);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-[var(--ink)]">Report</h2>
          <p className="truncate text-xs text-[var(--muted)]">{report ? `${report.scan.project} · v${report.scan.version} · ${report.scan.target}` : "Loading…"}</p>
        </div>
        <div className="flex shrink-0 items-start gap-3">
          <ScanExportButtons scanId={scanId} compact disabled={running} />
          <button type="button" onClick={onClose} aria-label="Close report" className="agent-focus-ring rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100">
            ✕
          </button>
        </div>
      </div>
      <div className="min-h-0 flex-1 space-y-6 overflow-auto px-4 py-4">
        {error && <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
        {!report && !error && <p className="text-sm text-[var(--muted)]">Loading the report…</p>}
        {running && <p className="rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-xs text-blue-800">The scan is still running: this report is partial and the downloads open when it finishes.</p>}
        {report && (
          <>
            <section aria-labelledby="rep-summary">
              <h3 id="rep-summary" className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">Severity summary (confirmed findings)</h3>
              <div className="mt-2 flex flex-wrap gap-2">
                {SEVERITIES.map((sev) => {
                  const key = sev.toUpperCase();
                  return (
                    <span key={sev} className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${RISK_STYLES[key]?.chip}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${RISK_DOT[key]}`} aria-hidden />
                      {key.charAt(0) + key.slice(1).toLowerCase()} <span className="tabular-nums">{report.summary.severity_counts[sev]}</span>
                    </span>
                  );
                })}
              </div>
              <p className="mt-2 text-xs text-[var(--muted)]">
                {report.summary.confirmed} confirmed. {report.summary.dismissed + report.summary.unverified} dismissed.
              </p>
              {report.summary.total === 0 && <p className="mt-2 text-sm text-[var(--muted)]">This scan produced no findings.</p>}
            </section>

            {report.confirmed.length > 0 && (
              <section aria-labelledby="rep-confirmed">
                <h3 id="rep-confirmed" className="text-xs font-semibold uppercase tracking-wide text-red-700">Confirmed findings</h3>
                <ul className="mt-2 space-y-3">{report.confirmed.map((f) => <ReportFinding key={f.id} finding={f} />)}</ul>
              </section>
            )}
            {(report.dismissed.length > 0 || report.unverified.length > 0) && (
              <section aria-labelledby="rep-dismissed">
                <h3 id="rep-dismissed" className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Dismissed</h3>
                <ul className="mt-2 space-y-3">{[...report.dismissed, ...report.unverified].map((f) => <ReportFinding key={f.id} finding={f} />)}</ul>
              </section>
            )}

            <section aria-labelledby="rep-changes" className="space-y-3">
              <div className="flex flex-wrap items-end justify-between gap-3">
                <h3 id="rep-changes" className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">Changes since the baseline scan</h3>
                <div>
                  <label htmlFor="dast-baseline" className="block text-[11px] font-medium text-[var(--muted)]">Compare with</label>
                  <select id="dast-baseline" value={against} onChange={(e) => setAgainst(e.target.value)} className="mt-0.5 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs">
                    <option value="">The previous scan (default)</option>
                    {earlier.map((s) => (
                      <option key={s.id} value={s.id}>
                        v{s.version} · {new Date(s.created_at).toLocaleDateString()}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              {diff && !diff.baseline ? (
                <p className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-[var(--muted)]">
                  No baseline: there is no earlier successful scan of this target, so every finding is new.
                </p>
              ) : (
                diff && <p className="text-xs text-[var(--muted)]">Compared with scan v{diff.previous_version}.</p>
              )}
              {diff && (
                <>
                  <p className="text-sm text-[var(--ink)]">
                    <strong>{diff.counts.new}</strong> new · <strong>{diff.counts.still_open}</strong> still open · <strong>{diff.counts.fixed}</strong> fixed
                  </p>
                  {diff.notes.filter((n) => diff.baseline || !n.startsWith("No baseline")).map((note) => (
                    <p key={note} className="text-xs text-[var(--muted)]">{note}</p>
                  ))}
                  <DiffList status="new" entries={entries("new")} />
                  <DiffList status="still_open" entries={entries("still_open")} />
                  <DiffList status="fixed" entries={entries("fixed")} />
                  {diff.not_comparable.length > 0 && (
                    <section aria-labelledby="diff-nc">
                      <h4 id="diff-nc" className="text-xs font-semibold uppercase tracking-wide text-slate-600">Not comparable ({diff.not_comparable.length})</h4>
                      <ul className="mt-1.5 space-y-1">
                        {diff.not_comparable.map((n, i) => (
                          <li key={i} className="rounded border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-[var(--muted)]">
                            <span className="font-mono text-[var(--ink)]">{n.check_id}</span> {n.target} — {n.reason}
                          </li>
                        ))}
                      </ul>
                    </section>
                  )}
                </>
              )}
            </section>

            <section aria-labelledby="rep-packs">
              <h3 id="rep-packs" className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">Rule packs used</h3>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {report.rule_packs.map((p) => (
                  <li key={p.id} className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-xs text-[var(--ink)]">{p.title}</li>
                ))}
                {report.custom_rules.map((c) => (
                  <li key={c.id} className="rounded-full border border-purple-200 bg-purple-50 px-2.5 py-0.5 text-xs text-purple-800">custom: {c.id} v{c.version}</li>
                ))}
              </ul>
              <p className="mt-1.5 text-xs text-[var(--muted)]">Catalog version {report.catalog_version || "—"}</p>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
