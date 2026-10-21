"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api";
import { toModulePath } from "@/lib/modulePath";
import type { Finding, ScanReport } from "@/lib/types";
import {
  RISK_DOT,
  RISK_LEVELS,
  RISK_STYLES,
  VERDICT_LABEL,
  VERDICT_ROW,
  VERDICT_TEXT,
  normalizeSeverity,
} from "@/lib/findingStyles";
import {
  reviewStateLabel,
  unresolvedReasonLabel,
  verdictKind,
  type VerdictKind,
} from "@/lib/verdict";
import {
  ISSUE_STATUS_CHIP,
  ISSUE_STATUS_LABEL,
  llmVerdictLabel,
} from "@/lib/review";
import FindingReviewForm from "@/components/FindingReviewForm";
import FlowTracePanel, { hopsForFinding } from "@/components/FlowTracePanel";
import ReachabilityEvidence from "@/components/ReachabilityEvidence";

function ChevronIcon() {
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
      <path d="m9 18 6-6-6-6" />
    </svg>
  );
}

const VERDICT_SHORT: Record<VerdictKind, string> = {
  confirmed: "Confirmed",
  dismissed: "False positive",
  unverified: "Unresolved",
  unknown: "Unknown",
};

const AFFECTED_FILES_PREVIEW = 5;

/** A group can span hundreds of files; show a few and let the user opt in to
 * the rest, so the list never needs its own inner scrollbar. */
function AffectedFiles({ paths }: { paths: string[] }) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? paths : paths.slice(0, AFFECTED_FILES_PREVIEW);
  const hidden = paths.length - shown.length;
  return (
    <>
      <ul className="mt-1 space-y-0.5">
        {shown.map((path, idx) => (
          <li key={idx} className="break-all font-mono text-xs text-[var(--ink)]" title={path}>
            • {toModulePath(path)}
          </li>
        ))}
      </ul>
      {paths.length > AFFECTED_FILES_PREVIEW && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="mt-1 text-xs font-medium text-blue-700 hover:underline"
        >
          {showAll ? "Show fewer" : `Show ${hidden} more`}
        </button>
      )}
    </>
  );
}

function AffectedLines({ locations }: { locations: { file_path: string; line: number }[] }) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? locations : locations.slice(0, AFFECTED_FILES_PREVIEW);
  const hidden = locations.length - shown.length;
  return (
    <div className="mt-2 rounded border border-slate-200 bg-slate-50 p-2">
      <p className="text-xs font-medium text-[var(--muted)]">
        {locations.length} locations in this group
      </p>
      <ul className="mt-1 space-y-0.5">
        {shown.map((loc, idx) => (
          <li key={idx} className="break-all font-mono text-xs text-[var(--ink)]" title={loc.file_path}>
            • {toModulePath(loc.file_path)}:{loc.line}
          </li>
        ))}
      </ul>
      {locations.length > AFFECTED_FILES_PREVIEW && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="mt-1 text-xs font-medium text-blue-700 hover:underline"
        >
          {showAll ? "Show fewer" : `Show ${hidden} more`}
        </button>
      )}
    </div>
  );
}

interface ScanFindingsPanelProps {
  scanId: string;
  report: ScanReport;
  /** When true, re-fetch findings on an interval (during live CRITICAL scan). */
  live?: boolean;
}

export default function ScanFindingsPanel({
  scanId,
  live = false,
}: ScanFindingsPanelProps) {
  const [verdictFilter] = useState<
    "true_positive" | "false_positive" | "unverified" | null
  >(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  // `null` means "not loaded yet". Polling must never flip back to a loading
  // state: that unmounted the whole list every 2s and reset the scroll position.
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set());
  // Bumped after a review is saved so the list (verdicts, counts, badges) is re-fetched.
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await api.scans.findings(scanId, verdictFilter ?? undefined);
        if (!cancelled) setFindings(res.findings);
      } catch {
        // Keep whatever is already on screen if a poll fails.
        if (!cancelled) setFindings((current) => current ?? []);
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
  }, [scanId, verdictFilter, live, reloadKey]);

  // Findings arrive grouped. Chips count actionable groups (true positive +
  // unverified) with their occurrences — the same basis as the PDF headline —
  // while `severityCounts` still includes dismissed groups so a severity
  // holding only dismissed ones stays selectable.
  const { severityCounts, actionableCounts } = useMemo(() => {
    const all: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const actionable: Record<string, { groups: number; occurrences: number }> = {
      CRITICAL: { groups: 0, occurrences: 0 },
      HIGH: { groups: 0, occurrences: 0 },
      MEDIUM: { groups: 0, occurrences: 0 },
      LOW: { groups: 0, occurrences: 0 },
    };
    for (const finding of findings ?? []) {
      const sev = normalizeSeverity(finding.severity);
      all[sev] = (all[sev] ?? 0) + 1;
      // Same test as scan_export._is_dismissed, so chips match the PDF.
      if ((finding.verdict ?? "").toLowerCase() !== "false_positive") {
        const bucket = (actionable[sev] ??= { groups: 0, occurrences: 0 });
        bucket.groups += 1;
        bucket.occurrences += finding.occurrence_count ?? 1;
      }
    }
    return { severityCounts: all, actionableCounts: actionable };
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

  const toggleOpen = useCallback((id: string) => {
    setOpenIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const allOpen =
    visibleFindings.length > 0 && visibleFindings.every((f) => openIds.has(f.id));

  return (
    <div className="space-y-5">
      {/* overflow-clip (not -hidden) so the sticky toolbar below still sticks to
          the panel's scroll container. */}
      <section className="overflow-clip rounded-md border border-slate-200 border-t-2 border-t-blue-500 bg-gradient-to-br from-white via-white to-blue-50/40 p-5">
        <div className="sticky top-0 z-10 -mx-5 -mt-5 border-b border-slate-200 bg-white/95 px-5 pb-3 pt-5 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2">
          {RISK_LEVELS.map((risk) => {
            const selected = severityFilter === risk;
            const count = severityCounts[risk] ?? 0;
            const actionable = actionableCounts[risk] ?? { groups: 0, occurrences: 0 };
            const style = RISK_STYLES[risk];
            return (
              <button
                type="button"
                key={risk}
                disabled={count === 0 && !selected}
                title={`${actionable.groups} actionable ${actionable.groups === 1 ? "group" : "groups"} · ${actionable.occurrences} ${actionable.occurrences === 1 ? "occurrence" : "occurrences"}`}
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
                <span className="font-semibold tabular-nums">{actionable.groups}</span>
                {actionable.occurrences > actionable.groups ? (
                  <span className="font-normal normal-case tabular-nums opacity-75">
                    · {actionable.occurrences}×
                  </span>
                ) : null}
              </button>
            );
          })}
          {visibleFindings.length > 0 ? (
            <button
              type="button"
              onClick={() =>
                setOpenIds(allOpen ? new Set() : new Set(visibleFindings.map((f) => f.id)))
              }
              className="ml-auto rounded-md px-2.5 py-1 text-xs font-medium text-blue-700 transition-colors hover:bg-blue-50"
            >
              {allOpen ? "Collapse all" : "Expand all"}
            </button>
          ) : null}
        </div>
        </div>

        {findings === null ? (
          <p className="mt-3 text-sm text-[var(--muted)]">Loading findings…</p>
        ) : visibleFindings.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--muted)]">No findings match this filter.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {visibleFindings.map((finding) => {
              const open = openIds.has(finding.id);
              const severity = normalizeSeverity(finding.severity);
              const riskStyle = RISK_STYLES[severity];
              const kind = verdictKind(finding.verdict);
              // `verdict` is the effective one (the reviewer's, once there is one); what the
              // scanner decided is `llm_verdict`. Both are shown, by their real names.
              const scannerKind = verdictKind(finding.llm_verdict ?? finding.verdict);
              const reviewState = reviewStateLabel(finding.review_state);
              const unresolvedWhy =
                scannerKind === "unverified" ? unresolvedReasonLabel(finding.unresolved_reason) : null;
              const hasTaintFlow = Boolean(
                finding.source?.trim() || finding.sink?.trim() || finding.data_flow?.trim(),
              );
              const flowHops = hopsForFinding(finding);
              return (
                <li
                  key={finding.id}
                  className={`rounded-md border ${VERDICT_ROW[kind]}`}
                >
                  <button
                    type="button"
                    onClick={() => toggleOpen(finding.id)}
                    aria-expanded={open}
                    className="agent-focus-ring flex w-full items-start gap-2 rounded-md px-3 py-2 text-left"
                  >
                    <span
                      className={`mt-1 flex-shrink-0 text-[var(--muted)] transition-transform ${
                        open ? "rotate-90" : ""
                      }`}
                    >
                      <ChevronIcon />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
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
                        <span
                          className={`text-xs font-medium ${VERDICT_TEXT[scannerKind]}`}
                          title={unresolvedWhy ? `Unresolved: ${unresolvedWhy}` : undefined}
                        >
                          Scanner: {VERDICT_SHORT[scannerKind]}
                          <span className="font-normal text-[var(--muted)]"> · Review: {reviewState}</span>
                        </span>
                        {finding.review?.reviewer_verdict ? (
                          <span className={ISSUE_STATUS_CHIP[finding.review.issue_status]}>
                            {ISSUE_STATUS_LABEL[finding.review.issue_status]}
                          </span>
                        ) : null}
                        {(finding.occurrence_count ?? 1) > 1 && (
                          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium tabular-nums text-slate-700">
                            {finding.occurrence_count}×
                          </span>
                        )}
                        {finding.cwe && (
                          <span className="text-xs text-[var(--muted)]">{finding.cwe}</span>
                        )}
                      </span>
                      <span
                        className={`mt-1 block text-sm font-medium text-[var(--ink)] ${
                          open ? "" : "line-clamp-2"
                        }`}
                      >
                        {finding.title}
                      </span>
                      <span
                        className="mt-0.5 block truncate font-mono text-xs text-[var(--muted)]"
                        title={finding.file_path ?? ""}
                      >
                        {toModulePath(finding.file_path ?? "")}
                        {finding.line ? `:${finding.line}` : ""}
                        {(() => {
                          const more = Math.max(
                            (finding.affected_files?.length ?? 1) - 1,
                            (finding.affected_lines?.length ?? 1) - 1,
                          );
                          return more > 0 ? ` +${more} more` : "";
                        })()}
                      </span>
                    </span>
                  </button>
                  {open && (
                  <div className="border-t border-slate-200/70 px-3 pb-3 pt-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
                    {finding.owasp_category && <span>{finding.owasp_category}</span>}
                  </div>
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
                  {finding.reachability && (finding.reachability.taint_path?.length ?? 0) > 0 && (
                    <ReachabilityEvidence evidence={finding.reachability} />
                  )}
                  {finding.affected_files && finding.affected_files.length > 1 ? (
                    <div className="mt-2 rounded border border-slate-200 bg-slate-50 p-2">
                      <p className="text-xs font-medium text-[var(--muted)]">
                        Found in {finding.affected_files.length} files
                        {(finding.occurrence_count ?? 0) > finding.affected_files.length
                          ? ` (${finding.occurrence_count} occurrences)`
                          : ""}
                      </p>
                      <AffectedFiles paths={finding.affected_files} />
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
                  {(finding.affected_lines?.length ?? 0) > 1 && (
                    <AffectedLines locations={finding.affected_lines ?? []} />
                  )}
                  {flowHops.length >= 2 ? (
                    <FlowTracePanel hops={flowHops} />
                  ) : finding.snippet ? (
                    <pre className="mt-1.5 overflow-x-auto rounded border border-slate-200 bg-slate-950/5 p-3 font-mono text-xs leading-relaxed text-[var(--ink)]">
                      {finding.snippet}
                    </pre>
                  ) : null}
                  <div className="mt-1.5 text-xs">
                    <span className="font-medium text-[var(--muted)]">Scanner verdict: </span>
                    <span className={`font-medium ${VERDICT_TEXT[scannerKind]}`}>
                      {VERDICT_LABEL[scannerKind]}
                    </span>
                    {unresolvedWhy ? (
                      <span className="ml-1 text-[var(--muted)]">({unresolvedWhy})</span>
                    ) : null}
                    <span className="ml-2 text-[var(--muted)]">
                      · Review: {reviewState}
                      {kind !== scannerKind ? ` (effective verdict: ${VERDICT_LABEL[kind]})` : ""}
                    </span>
                    {finding.review?.reviewer_verdict ? (
                      <span className="ml-2 text-[var(--muted)]">
                        (LLM said {llmVerdictLabel(finding.llm_verdict)}; reviewed by {finding.review.reviewer})
                      </span>
                    ) : null}
                  </div>
                  <FindingReviewForm
                    scanId={scanId}
                    findingId={finding.id}
                    llmVerdict={finding.llm_verdict ?? finding.verdict}
                    hasReview={Boolean(finding.review)}
                    onSaved={() => setReloadKey((n) => n + 1)}
                  />
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
