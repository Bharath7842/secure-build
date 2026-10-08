"use client";

import { RISK_DOT, RISK_STYLES } from "@/lib/findingStyles";
import type { DastSummary } from "@/lib/types";

function Tile({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: "warn" }) {
  return (
    <div className={`min-w-[6.5rem] rounded-md border px-3 py-1.5 ${tone === "warn" ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"}`}>
      <p className="text-[10px] font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className={`truncate text-base font-semibold tabular-nums ${tone === "warn" ? "text-amber-700" : "text-[var(--ink)]"}`}>{value}</p>
      {hint && <p className="truncate text-[10px] text-[var(--muted)]">{hint}</p>}
    </div>
  );
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

/** Live counters while a scan runs (and the final numbers afterwards): pages, endpoints, requests,
 *  tests, confirmed findings by severity, dismissed findings, model use. */
export default function DastCountersBar({ summary, embedded }: { summary: DastSummary | null; embedded?: boolean }) {
  if (!summary) {
    return (
      <div className={embedded ? "text-xs text-[var(--muted)]" : "px-6 py-3 text-xs text-[var(--muted)]"} role="status">
        Loading counters…
      </div>
    );
  }
  const confirmed = summary.findings.by_verdict.true_positive ?? 0;
  const dismissed = (summary.findings.by_verdict.false_positive ?? 0) + (summary.findings.by_verdict.unverified ?? 0);
  return (
    <div className={embedded ? "space-y-2" : "space-y-2 border-b border-slate-200 bg-slate-50/50 px-6 py-3"} role="region" aria-label="Scan counters">
      <div className="flex flex-wrap gap-2">
        <Tile label="Pages" value={summary.pages_crawled} />
        <Tile label="Endpoints" value={summary.endpoints_discovered} />
        <Tile label="Requests" value={summary.requests_sent} hint={summary.requests_denied > 0 ? `${summary.requests_denied} denied` : "none denied"} />
        <Tile label="Tests" value={summary.tests_run} hint={summary.replays > 0 ? `${summary.replays} replays` : undefined} />
        <Tile label="Inputs" value={summary.browser_inputs ?? 0} hint="markers typed" />
        <Tile label="Confirmed" value={confirmed} />
        <Tile label="Dismissed" value={dismissed} />
        <Tile label="Model" value={`${summary.model_calls} calls`} hint={`$${summary.model_cost_usd.toFixed(4)}`} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5" aria-label="Confirmed findings by severity">
        <span className="mr-1 text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">Confirmed by severity</span>
        {SEVERITIES.map((sev) => (
          <span
            key={sev}
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${RISK_STYLES[sev]?.chip ?? ""} ${summary.findings.by_severity[sev] ? "" : "opacity-50"}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${RISK_DOT[sev]}`} aria-hidden />
            {sev.charAt(0) + sev.slice(1).toLowerCase()} <span className="tabular-nums">{summary.findings.by_severity[sev] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
