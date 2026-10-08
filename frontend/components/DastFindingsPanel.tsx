"use client";

import { useEffect, useMemo, useState } from "react";

import DastHttpExchange from "@/components/DastHttpExchange";
import type { DastTraffic } from "@/lib/types";
import {
  DAST_VERDICT_LABEL,
  RISK_DOT,
  RISK_STYLES,
  VERDICT_ROW,
  VERDICT_TEXT,
  formatConfidence,
  normalizeSeverity,
} from "@/lib/findingStyles";
import { api } from "@/lib/api";
import type { DastFindingFilter, Finding } from "@/lib/types";
import { displayFindingTarget, displayFindingTitle, hideInconclusive } from "@/lib/httpLabel";
import { dastVerdictKind, type VerdictKind } from "@/lib/verdict";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const VERDICT_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "All verdicts" },
  { value: "true_positive", label: "Confirmed" },
  { value: "false_positive", label: "Dismissed" },
];

function payloadFromSnippet(snippet: string | null | undefined): string {
  for (const line of (snippet || "").split("\n")) {
    if (line.startsWith("Input: ") || line.startsWith("Payload: ")) return line.slice(line.indexOf(": ") + 2).trim();
  }
  return "";
}

function requestFromFinding(finding: Finding): DastTraffic | null {
  const evidence = finding.evidence;
  if (evidence?.request && (evidence.request.method || evidence.request.url)) return evidence.request;
  const bits = (finding.target || finding.file_path || "").split(/\s+/);
  const method = bits[0] && /^[A-Za-z]{2,10}$/.test(bits[0]) ? bits[0].toUpperCase() : "";
  const path = method ? bits.slice(1).join(" ") : finding.target || finding.file_path || "";
  return {
    method,
    url: finding.sink || path,
    parameter: finding.param,
    location: finding.location,
    payload: evidence?.request?.payload || payloadFromSnippet(finding.snippet),
    seq: evidence?.audit_ref ? Number(evidence.audit_ref) : null,
  };
}

function EvidenceBlock({ finding }: { finding: Finding }) {
  const evidence = finding.evidence;
  if (!evidence) return null;
  const request = requestFromFinding(finding);
  return (
    <DastHttpExchange
      request={request}
      baseline={evidence.baseline_excerpt}
      response={evidence.test_excerpt}
      signals={evidence.signals}
    />
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const severity = normalizeSeverity(finding.severity, true);
  const risk = RISK_STYLES[severity];
  const kind: VerdictKind = dastVerdictKind(finding.verdict);
  const confidence = formatConfidence(finding.confidence);
  const roles = finding.roles ?? [];
  const affected = finding.affected_files ?? [];
  return (
    <li className={`rounded-md border px-3 py-2.5 ${VERDICT_ROW[kind]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${risk?.chip ?? "bg-slate-100 text-slate-600"}`}>
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${RISK_DOT[severity] ?? "bg-slate-400"}`} aria-hidden />
          {severity}
        </span>
        <span className={`text-xs font-semibold ${VERDICT_TEXT[kind]}`}>{DAST_VERDICT_LABEL[kind]}</span>
        {finding.confidence_label && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700">{finding.confidence_label} confidence</span>}
        {!finding.confidence_label && confidence && <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700">{confidence} confidence</span>}
        {finding.rule_id && <span className="font-mono text-[11px] text-[var(--muted)]">{finding.rule_id}</span>}
      </div>
      <p className="mt-1.5 text-sm font-medium text-[var(--ink)]">{displayFindingTitle(finding.title, finding)}</p>
      <dl className="mt-1.5 grid gap-x-4 gap-y-0.5 text-xs sm:grid-cols-2">
        <div className="flex gap-1.5">
          <dt className="text-[var(--muted)]">Target</dt>
          <dd className="min-w-0 break-all font-mono text-[var(--ink)]">{displayFindingTarget(finding)}</dd>
        </div>
        {finding.param && (
          <div className="flex gap-1.5">
            <dt className="text-[var(--muted)]">Parameter</dt>
            <dd className="font-mono text-[var(--ink)]">
              {finding.param}
              {finding.location && <span className="text-[var(--muted)]"> ({finding.location})</span>}
            </dd>
          </div>
        )}
        {roles.length > 0 && (
          <div className="flex gap-1.5">
            <dt className="text-[var(--muted)]">Role pair</dt>
            <dd className="text-[var(--ink)]">
              {roles[0]} <span aria-hidden>→</span>
              <span className="sr-only"> replayed as </span> {roles[1] ?? "?"}
            </dd>
          </div>
        )}
        {finding.standards && finding.standards.length > 0 && (
          <div className="flex gap-1.5 sm:col-span-2">
            <dt className="text-[var(--muted)]">Standards</dt>
            <dd className="flex flex-wrap gap-1">
              {finding.standards.map((s) => (
                <span key={s} className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-700">
                  {s}
                </span>
              ))}
            </dd>
          </div>
        )}
      </dl>
      {finding.verdict_reason && <p className="mt-1.5 text-sm text-[var(--muted)]">{hideInconclusive(finding.verdict_reason)}</p>}
      <EvidenceBlock finding={finding} />
      {affected.length > 1 && (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-[var(--muted)]">Also seen on {affected.length - 1} other endpoint{affected.length === 2 ? "" : "s"}</summary>
          <ul className="mt-1 space-y-0.5 font-mono text-[var(--ink)]">
            {affected.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </details>
      )}
      {finding.remediation && (
        <div className="mt-2 rounded border border-emerald-100 bg-emerald-50/60 px-2.5 py-2">
          <p className="text-xs font-medium text-emerald-900">How to fix it</p>
          <p className="mt-0.5 whitespace-pre-wrap text-xs text-[var(--ink)]">{finding.remediation}</p>
        </div>
      )}
    </li>
  );
}

interface DastFindingsPanelProps {
  scanId: string;
  /** Re-fetch on an interval while the scan runs. */
  live: boolean;
  /** `owner:actor` from the authorization matrix, or null. Shared with the matrix so each drives the other. */
  rolePair: string | null;
  onRolePairChange: (pair: string | null) => void;
  onClose: () => void;
}

/** Findings with evidence and filters (DAST-14-010). Confirmed findings come first; dismissed
 *  (false positive) findings follow. */
export default function DastFindingsPanel({ scanId, live, rolePair, onRolePairChange, onClose }: DastFindingsPanelProps) {
  const [severities, setSeverities] = useState<string[]>([]);
  const [verdict, setVerdict] = useState("");
  const [check, setCheck] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [all, setAll] = useState<Finding[] | null>(null);
  const [totals, setTotals] = useState<{ tp: number; dismissed: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const effectiveRole = rolePair ?? roleFilter;

  useEffect(() => {
    let active = true;
    async function load() {
      const filter: DastFindingFilter = {};
      if (severities.length) filter.severity = severities.join(",");
      if (verdict) filter.verdict = verdict;
      if (check) filter.check = check;
      if (effectiveRole) filter.role = effectiveRole;
      try {
        const res = await api.scans.dastFindings(scanId, filter);
        if (!active) return;
        setAll(res.findings);
        setTotals({
          tp: res.tp_count,
          dismissed: (res.fp_count ?? 0) + (res.unverified_count ?? 0),
          total: res.total_count ?? res.findings.length,
        });
        setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Could not load findings.");
      }
    }
    load();
    if (!live) return () => { active = false; };
    const timer = setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [scanId, live, severities, verdict, check, effectiveRole]);

  // Options come from what exists, so a filter can never offer something that matches nothing.
  const [catalog, setCatalog] = useState<{ checks: string[]; roles: string[] }>({ checks: [], roles: [] });
  useEffect(() => {
    let active = true;
    api.scans
      .dastFindings(scanId, {})
      .then((res) => {
        if (!active) return;
        const checks = Array.from(new Set(res.findings.map((f) => f.rule_id).filter(Boolean) as string[])).sort();
        const pairs = new Set<string>();
        const labels = new Set<string>();
        for (const f of res.findings) {
          const r = f.roles ?? [];
          if (r.length >= 2) pairs.add(`${r[0]}:${r[1]}`);
          r.forEach((x) => labels.add(x));
        }
        setCatalog({ checks, roles: [...Array.from(labels).sort(), ...Array.from(pairs).sort()] });
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [scanId, all?.length]);

  const groups = useMemo(() => {
    const list = all ?? [];
    return {
      confirmed: list.filter((f) => dastVerdictKind(f.verdict) === "confirmed"),
      dismissed: list.filter((f) => dastVerdictKind(f.verdict) === "dismissed"),
    };
  }, [all]);

  const filtered = severities.length > 0 || verdict !== "" || check !== "" || effectiveRole !== "";

  function toggleSeverity(sev: string) {
    setSeverities((cur) => (cur.includes(sev) ? cur.filter((s) => s !== sev) : [...cur, sev]));
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-[var(--ink)]">Findings</h2>
          <p className="truncate text-xs text-[var(--muted)]">
            {totals ? `${totals.tp} confirmed · ${totals.dismissed} dismissed${filtered ? ` · showing ${all?.length ?? 0} of ${totals.total}` : ""}` : "Loading…"}
          </p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close findings" className="agent-focus-ring rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100">
          ✕
        </button>
      </div>

      <div className="shrink-0 space-y-2 border-b border-slate-100 px-4 py-3">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITIES.map((sev) => {
            const on = severities.includes(sev);
            return (
              <button
                key={sev}
                type="button"
                aria-pressed={on}
                onClick={() => toggleSeverity(sev)}
                className={`agent-focus-ring inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide transition-colors ${on ? RISK_STYLES[sev].active : `${RISK_STYLES[sev].chip} hover:opacity-90`}`}
              >
                <span className={`h-1.5 w-1.5 rounded-full ${RISK_DOT[sev]}`} aria-hidden />
                {sev}
              </button>
            );
          })}
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <div>
            <label htmlFor="dast-f-verdict" className="sr-only">Filter by verdict</label>
            <select id="dast-f-verdict" value={verdict} onChange={(e) => setVerdict(e.target.value)} className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs">
              {VERDICT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="dast-f-check" className="sr-only">Filter by check</label>
            <select id="dast-f-check" value={check} onChange={(e) => setCheck(e.target.value)} className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs">
              <option value="">All checks</option>
              {catalog.checks.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="dast-f-role" className="sr-only">Filter by role or role pair</label>
            <select
              id="dast-f-role"
              value={effectiveRole}
              onChange={(e) => {
                onRolePairChange(null);
                setRoleFilter(e.target.value);
              }}
              className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs"
            >
              <option value="">All roles</option>
              {effectiveRole && !catalog.roles.includes(effectiveRole) && <option value={effectiveRole}>{effectiveRole.replace(":", " → ")}</option>}
              {catalog.roles.map((r) => (
                <option key={r} value={r}>{r.includes(":") ? `pair ${r.replace(":", " → ")}` : `role ${r}`}</option>
              ))}
            </select>
          </div>
        </div>
        {filtered && (
          <button
            type="button"
            onClick={() => {
              setSeverities([]);
              setVerdict("");
              setCheck("");
              setRoleFilter("");
              onRolePairChange(null);
            }}
            className="text-xs font-medium text-[var(--accent)] hover:underline"
          >
            Clear filters
          </button>
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-5 overflow-auto px-4 py-4 agent-scroll">
        {error && <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
        {all === null && !error && <p className="text-sm text-[var(--muted)]">Loading findings…</p>}
        {all !== null && all.length === 0 && (
          <p className="text-sm text-[var(--muted)]">{filtered ? "No findings match these filters." : live ? "No findings yet." : "This scan produced no findings."}</p>
        )}
        {groups.confirmed.length > 0 && (
          <section aria-labelledby="dast-g-confirmed">
            <h3 id="dast-g-confirmed" className="text-xs font-semibold uppercase tracking-wide text-red-700">Confirmed ({groups.confirmed.length})</h3>
            <ul className="mt-2 space-y-3">{groups.confirmed.map((f) => <FindingCard key={f.id} finding={f} />)}</ul>
          </section>
        )}
        {groups.dismissed.length > 0 && (
          <section aria-labelledby="dast-g-dismissed">
            <h3 id="dast-g-dismissed" className="text-xs font-semibold uppercase tracking-wide text-emerald-700">Dismissed ({groups.dismissed.length})</h3>
            <ul className="mt-2 space-y-3">{groups.dismissed.map((f) => <FindingCard key={f.id} finding={f} />)}</ul>
          </section>
        )}
      </div>
    </div>
  );
}
