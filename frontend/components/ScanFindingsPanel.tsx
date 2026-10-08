"use client";

import { useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api";
import { buildClaudeCodeLink, buildFixPrompt } from "@/lib/ideLinks";
import { toModulePath } from "@/lib/modulePath";
import type { Finding, ScanReport } from "@/lib/types";
import {
  RISK_DOT,
  RISK_LEVELS,
  RISK_STYLES,
  VERDICT_LABEL,
  VERDICT_ROW,
  VERDICT_TEXT,
  formatConfidence,
  normalizeSeverity,
} from "@/lib/findingStyles";
import { verdictKind } from "@/lib/verdict";
import FlowTracePanel, { hopsForFinding } from "@/components/FlowTracePanel";

function ShieldIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

/** Generic "AI sparkle" glyph — paired with Claude's clay/terracotta brand
 *  tone below so the button reads as "AI-powered" without reproducing the
 *  actual (trademarked) Claude logo. */
function SparkleIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden
    >
      <path d="M12 2.5c.3 0 .55.2.62.5l1.2 5.1c.3 1.3 1.3 2.3 2.6 2.6l5.1 1.2c.3.07.5.32.5.62s-.2.55-.5.62l-5.1 1.2c-1.3.3-2.3 1.3-2.6 2.6l-1.2 5.1c-.07.3-.32.5-.62.5s-.55-.2-.62-.5l-1.2-5.1c-.3-1.3-1.3-2.3-2.6-2.6l-5.1-1.2c-.3-.07-.5-.32-.5-.62s.2-.55.5-.62l5.1-1.2c1.3-.3 2.3-1.3 2.6-2.6l1.2-5.1c.07-.3.32-.5.62-.5z" />
    </svg>
  );
}

interface ScanFindingsPanelProps {
  scanId: string;
  report: ScanReport;
  /** When true, re-fetch findings on an interval (during live CRITICAL scan). */
  live?: boolean;
  /** Absolute local checkout path (Scan.local_root_path) used to build the
   *  "Fix with Claude Code" deep link below. Hidden when this is unset —
   *  only meaningful when the browser and
   *  backend run on the same machine. */
  localRootPath?: string | null;
}

export default function ScanFindingsPanel({
  scanId,
  live = false,
  localRootPath = null,
}: ScanFindingsPanelProps) {
  const [verdictFilter] = useState<
    "true_positive" | "false_positive" | "unverified" | null
  >(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setFindingsLoading(true);
      try {
        const res = await api.scans.findings(scanId, verdictFilter ?? undefined);
        if (!cancelled) setFindings(res.findings);
      } catch {
        if (!cancelled) setFindings([]);
      } finally {
        if (!cancelled) setFindingsLoading(false);
      }
    }
    load();

    if (!live) {
      return () => {
        cancelled = true;
      };
    }

    const timer = setInterval(load, 2000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scanId, verdictFilter, live]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const finding of findings ?? []) {
      const sev = normalizeSeverity(finding.severity);
      counts[sev] = (counts[sev] ?? 0) + 1;
    }
    return counts;
  }, [findings]);

  // Drop a severity chip that no longer matches (e.g. HIGH selected, then
  // switch to dismissed where that severity has 0) so dismissed findings show.
  useEffect(() => {
    if (severityFilter && (severityCounts[severityFilter] ?? 0) === 0) {
      setSeverityFilter(null);
    }
  }, [severityFilter, severityCounts]);

  const visibleFindings = useMemo(() => {
    if (!findings) return [];
    if (!severityFilter) return findings;
    return findings.filter((f) => normalizeSeverity(f.severity) === severityFilter);
  }, [findings, severityFilter]);

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-blue-500 bg-gradient-to-br from-white via-white to-blue-50/40 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          <span className="flex h-6 w-6 items-center justify-center rounded bg-blue-100 text-blue-600">
            <ShieldIcon />
          </span>
          Findings
        </h3>
        <div className="mt-3 flex flex-wrap gap-2">
          {RISK_LEVELS.map((risk) => {
            const selected = severityFilter === risk;
            const count = severityCounts[risk] ?? 0;
            const style = RISK_STYLES[risk];
            return (
              <button
                type="button"
                key={risk}
                disabled={count === 0 && !selected}
                onClick={() => setSeverityFilter((current) => (current === risk ? null : risk))}
                className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                  selected ? style.active : `${style.chip} hover:opacity-90`
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${RISK_DOT[risk]}`}
                  aria-hidden
                />
                {risk}
                <span className="font-semibold tabular-nums">{count}</span>
              </button>
            );
          })}
        </div>

        {findingsLoading ? (
          <p className="mt-3 text-sm text-[var(--muted)]">Loading findings…</p>
        ) : visibleFindings.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--muted)]">No findings match this filter.</p>
        ) : (
          <ul className="mt-3 max-h-[70vh] space-y-3 overflow-y-auto agent-scroll">
            {visibleFindings.map((finding) => {
              const severity = normalizeSeverity(finding.severity);
              const riskStyle = RISK_STYLES[severity];
              const kind = verdictKind(finding.verdict);
              const confidence = formatConfidence(finding.confidence);
              const hasTaintFlow = Boolean(
                finding.source?.trim() || finding.sink?.trim() || finding.data_flow?.trim(),
              );
              const flowHops = hopsForFinding(finding);
              return (
                <li
                  key={finding.id}
                  className={`rounded-md border px-3 py-2 ${VERDICT_ROW[kind]}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${
                        riskStyle?.chip ?? "bg-slate-100 text-slate-600"
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${
                          RISK_DOT[severity] ?? "bg-slate-400"
                        }`}
                        aria-hidden
                      />
                      {severity}
                    </span>
                    {confidence && (
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                        {confidence} confidence
                      </span>
                    )}
                    {finding.cwe && (
                      <span className="text-xs text-[var(--muted)]">{finding.cwe}</span>
                    )}
                    <span className="text-xs text-[var(--muted)]">{finding.owasp_category}</span>
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-[var(--ink)]">{finding.title}</p>
                  {finding.verdict_reason && (
                    <p className="mt-1 text-sm text-[var(--muted)]">{finding.verdict_reason}</p>
                  )}
                  {finding.ai_fix && (
                    <div className="mt-2 rounded border border-emerald-100 bg-emerald-50/60 px-2.5 py-2">
                      <p className="text-xs font-medium text-emerald-900">Suggested fix</p>
                      <p className="mt-0.5 whitespace-pre-wrap text-xs text-[var(--ink)]">
                        {finding.ai_fix}
                      </p>
                    </div>
                  )}
                  {hasTaintFlow && (
                    <dl className="mt-2 space-y-1 rounded border border-sky-100 bg-sky-50/60 px-2.5 py-2 text-xs">
                      {finding.source?.trim() && (
                        <div>
                          <dt className="font-medium text-sky-900">Source</dt>
                          <dd className="mt-0.5 font-mono text-[var(--ink)]">{finding.source}</dd>
                        </div>
                      )}
                      {finding.sink?.trim() && (
                        <div>
                          <dt className="font-medium text-sky-900">Sink</dt>
                          <dd className="mt-0.5 font-mono text-[var(--ink)]">{finding.sink}</dd>
                        </div>
                      )}
                      {finding.data_flow?.trim() && (
                        <div>
                          <dt className="font-medium text-sky-900">Data flow</dt>
                          <dd className="mt-0.5 text-[var(--ink)]">{finding.data_flow}</dd>
                        </div>
                      )}
                    </dl>
                  )}
                  {finding.affected_files && finding.affected_files.length > 1 ? (
                    <div className="mt-2 rounded border border-slate-200 bg-slate-50 p-2">
                      <p className="text-xs font-medium text-[var(--muted)]">
                        Found in {finding.affected_files.length} files
                      </p>
                      <ul className="mt-1 max-h-40 space-y-0.5 overflow-y-auto">
                        {finding.affected_files.map((path, idx) => (
                          <li
                            key={idx}
                            className="font-mono text-xs text-[var(--ink)]"
                            title={path}
                          >
                            • {toModulePath(path)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <p
                      className="mt-2 truncate font-mono text-xs font-medium text-[var(--ink)]"
                      title={finding.file_path ?? ""}
                    >
                      {toModulePath(finding.file_path ?? "")}
                      {finding.line ? `:${finding.line}` : ""}
                    </p>
                  )}
                  {flowHops.length >= 2 ? (
                    <FlowTracePanel hops={flowHops} />
                  ) : finding.snippet ? (
                    <pre className="mt-1.5 max-h-96 overflow-auto rounded border border-slate-200 bg-slate-950/5 p-3 font-mono text-xs leading-relaxed text-[var(--ink)]">
                      {finding.snippet}
                    </pre>
                  ) : null}
                  <div className="mt-1.5 text-xs">
                    <span className="font-medium text-[var(--muted)]">Verdict: </span>
                    <span className={`font-medium ${VERDICT_TEXT[kind]}`}>{VERDICT_LABEL[kind]}</span>
                  </div>
                  {localRootPath && finding.file_path && (
                    <div className="mt-2">
                      <a
                        href={buildClaudeCodeLink(localRootPath, buildFixPrompt(finding))}
                        title="Opens a Claude Code terminal in this repo with a pre-filled remediation prompt — requires Claude Code installed and this app opened on the same machine as the backend. Nothing is sent until you press Enter."
                        className="group inline-flex items-center gap-2 rounded-md border border-[#CC785C]/30 bg-gradient-to-r from-[#CC785C]/10 via-[#CC785C]/5 to-transparent px-3 py-1.5 text-xs font-semibold text-[#a8583c] shadow-sm transition-all hover:border-[#CC785C]/60 hover:from-[#CC785C]/20 hover:via-[#CC785C]/10 hover:shadow-md hover:-translate-y-0.5"
                      >
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[#CC785C] text-white shadow-sm transition-transform group-hover:scale-110">
                          <SparkleIcon />
                        </span>
                        Fix with Claude Code
                      </a>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}
