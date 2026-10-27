"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api";
import { toModulePath } from "@/lib/modulePath";
import type { CweGroup, Finding, ScanReport } from "@/lib/types";
import {
  RISK_DOT,
  RISK_STYLES,
  VERDICT_LABEL,
  VERDICT_ROW,
  VERDICT_TEXT,
  normalizeSeverity,
} from "@/lib/findingStyles";
import {
  VERDICT_TABS,
  severityChips,
  verdictTabCounts,
  type SeverityGroupCounts,
  type VerdictTab,
} from "@/lib/findingCounts";
import {
  reviewStateLabel,
  unresolvedReasonLabel,
  verdictKind,
  type VerdictKind,
} from "@/lib/verdict";
import {
  ISSUE_STATUS_CHIP,
  ISSUE_STATUS_LABEL,
  constructMixLabel,
  isMixedConstruct,
  llmVerdictLabel,
} from "@/lib/review";
import FindingDecisionHistory from "@/components/FindingDecisionHistory";
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

/** "HIGH · CVSS 3.1 8.8 · CWE-89 baseline: … · PR:L — … · was MEDIUM", or null. */
function severityExplanation(finding: Finding): string | null {
  const basis = finding.severity_basis;
  if (!basis) return null;
  const parts = [normalizeSeverity(finding.severity, true)];
  if (finding.cvss != null) parts.push(`CVSS 3.1 ${finding.cvss.toFixed(1)}`);
  if (basis.source === "cwe") parts.push(`${basis.cwe} baseline${basis.rationale ? `: ${basis.rationale}` : ""}`);
  else if (basis.source === "rule") parts.push(`rule-specific vector (${basis.cwe ?? "no CWE"})`);
  else if (basis.note) parts.push(basis.note);
  for (const a of basis.adjustments ?? []) parts.push(`${a.metric}:${a.to} — ${a.why}`);
  if ((basis.source === "rule" || basis.source === "cwe") && basis.note) parts.push(basis.note);
  if (basis.original_severity && basis.original_severity !== normalizeSeverity(finding.severity, true)) {
    parts.push(`rule/model said ${basis.original_severity}`);
  }
  return parts.join(" · ");
}

interface FindingRowProps {
  scanId: string;
  finding: Finding;
  open: boolean;
  onToggle: () => void;
  onConstructFilter: (key: string | null) => void;
  onSaved: () => void;
}

/** One issue group (a rule/construct row): its verdict, evidence, history and review form. */
function FindingRow({ scanId, finding, open, onToggle, onConstructFilter, onSaved }: FindingRowProps) {
  const severity = normalizeSeverity(finding.severity, true);
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
      className={`rounded-md border ${VERDICT_ROW[kind]}`}
    >
      <button
        type="button"
        onClick={onToggle}
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
            {finding.cvss != null ? (
              <span
                className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium tabular-nums text-slate-700"
                title={finding.cvss_vector ?? "CVSS v3.1 base score"}
              >
                CVSS {finding.cvss.toFixed(1)}
              </span>
            ) : null}
            <span
              className={`text-xs font-medium ${VERDICT_TEXT[scannerKind]}`}
              title={unresolvedWhy ? `Scanner verdict: Unresolved (${unresolvedWhy})` : "Scanner verdict"}
            >
              {VERDICT_SHORT[scannerKind]}
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
            {finding.review_coverage &&
            finding.review_coverage.reviewed < finding.review_coverage.total ? (
              <span
                className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium tabular-nums text-slate-700"
                title="Occurrences of this group the confirmation actually looked at"
              >
                Reviewed {finding.review_coverage.reviewed} of {finding.review_coverage.total}
              </span>
            ) : null}
            {finding.construct_mix && isMixedConstruct(finding.construct_mix) ? (
              <span
                role="button"
                tabIndex={0}
                data-testid="construct-mix-chip"
                title="This construct has members with different outcomes. Click to show only its rows."
                onClick={(e) => {
                  e.stopPropagation();
                  onConstructFilter(finding.construct_key ?? null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    e.stopPropagation();
                    onConstructFilter(finding.construct_key ?? null);
                  }
                }}
                className="cursor-pointer rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-900 hover:bg-amber-200"
              >
                {constructMixLabel(finding.construct_mix)}
              </span>
            ) : null}
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
      {severityExplanation(finding) ? (
        <p className="mt-1 text-xs text-[var(--muted)]">
          <span className="font-medium text-[var(--ink)]">Severity: </span>
          {severityExplanation(finding)}
          {finding.cvss_vector ? (
            <span className="ml-1 break-all font-mono text-[11px]">({finding.cvss_vector})</span>
          ) : null}
        </p>
      ) : null}
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
        <span className={`font-medium ${VERDICT_TEXT[scannerKind]}`} title="Scanner verdict">
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
      <FindingDecisionHistory scanId={scanId} findingId={finding.id} />
      <FindingReviewForm
        scanId={scanId}
        findingId={finding.id}
        llmVerdict={finding.llm_verdict ?? finding.verdict}
        hasReview={Boolean(finding.review)}
        constructMixed={isMixedConstruct(finding.construct_mix)}
        occurrenceCount={finding.occurrence_count ?? 1}
        onSaved={onSaved}
      />
      </div>
      )}
    </li>
  );
}

const BUCKET_SHORT: { key: string; label: string; className: string }[] = [
  { key: "true_positive", label: "confirmed", className: "text-red-700" },
  { key: "unverified", label: "unresolved", className: "text-amber-700" },
  { key: "false_positive", label: "false positive", className: "text-emerald-700" },
  { key: "unknown", label: "unknown", className: "text-slate-700" },
];

function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** The finding ids, groups, occurrences and files of `row` in the selected tab. */
function tabSlice(row: CweGroup, tab: VerdictTab) {
  const cells = tab === "all" ? Object.values(row.by_bucket) : [row.by_bucket[tab]].filter(Boolean);
  return {
    ids: cells.flatMap((c) => c.finding_ids),
    groups: cells.reduce((n, c) => n + c.groups, 0),
    occurrences: cells.reduce((n, c) => n + c.occurrences, 0),
    files: tab === "all" ? row.file_count : cells.reduce((n, c) => n + c.files, 0),
  };
}

function groupPaths(findings: Finding[]): string[] {
  const seen = new Set<string>();
  for (const f of findings) {
    for (const p of f.affected_files?.length ? f.affected_files : [f.file_path ?? ""]) {
      if (p) seen.add(p);
    }
  }
  return [...seen];
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
  // Confirmed first: unresolved and dismissed groups are one click away, not in the way.
  const [tab, setTab] = useState<VerdictTab>("true_positive");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  // Set by the "Mixed" chip: show only the rows of one construct, whatever their outcome.
  const [constructFilter, setConstructFilter] = useState<string | null>(null);
  // `null` means "not loaded yet". Polling must never flip back to a loading
  // state: that unmounted the whole list every 2s and reset the scroll position.
  const [findings, setFindings] = useState<Finding[] | null>(null);
  // `null` when the backend predates the CWE roll-up: the list then falls back to flat rows.
  const [cweGroups, setCweGroups] = useState<CweGroup[] | null>(null);
  const [hiddenFpCount, setHiddenFpCount] = useState(0);
  // The server's counts (`count_findings`); the tabs and chips show them as they are.
  const [counts, setCounts] = useState<SeverityGroupCounts | null>(null);
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set());
  const [openCwes, setOpenCwes] = useState<Set<string>>(() => new Set());
  // Bumped after a review is saved so the list (verdicts, counts, badges) is re-fetched.
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await api.scans.findings(scanId);
        if (!cancelled) {
          setFindings(res.findings);
          setCweGroups(res.cwe_groups ?? null);
          setHiddenFpCount(res.hidden_fp_count ?? 0);
          setCounts(res.severity_group_counts ?? null);
        }
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
  }, [scanId, live, reloadKey]);

  const tabCounts = useMemo(() => verdictTabCounts(counts), [counts]);
  const { levels: chipLevels, counts: chipCounts } = useMemo(
    () => severityChips(counts, tab),
    [counts, tab],
  );

  // Drop a severity chip that no longer matches (e.g. HIGH selected, then
  // switch to a tab where that severity has 0).
  useEffect(() => {
    if (severityFilter && (chipCounts[severityFilter]?.groups ?? 0) === 0) {
      setSeverityFilter(null);
    }
  }, [severityFilter, chipCounts]);

  const byId = useMemo(() => {
    const map = new Map<string, { finding: Finding; index: number }>();
    (findings ?? []).forEach((finding, index) => map.set(finding.id, { finding, index }));
    return map;
  }, [findings]);

  const severityMatches = useCallback(
    (f: Finding) => !severityFilter || normalizeSeverity(f.severity, true) === severityFilter,
    [severityFilter],
  );

  // One row per CWE that has groups in this tab, each with its groups in the server's order.
  const visibleCwes = useMemo(() => {
    return (cweGroups ?? [])
      .map((row) => {
        const slice = tabSlice(row, tab);
        const members = slice.ids
          .map((id) => byId.get(id))
          .filter((m): m is { finding: Finding; index: number } => Boolean(m))
          .sort((a, b) => a.index - b.index)
          .map((m) => m.finding)
          .filter(severityMatches);
        return { row, slice, members };
      })
      .filter((entry) => entry.members.length > 0);
  }, [cweGroups, tab, byId, severityMatches]);

  // Flat rows: the "Mixed" chip shows one construct's rows across every tab, and a backend
  // without `cwe_groups` gets the tab's rows ungrouped rather than an empty list.
  const flatFindings = useMemo(() => {
    if (constructFilter) return (findings ?? []).filter((f) => f.construct_key === constructFilter);
    if (cweGroups !== null) return [];
    return (findings ?? []).filter((f) => {
      if (tab === "all") return true;
      const verdict = f.verdict ?? "";
      const bucket = ["true_positive", "unverified", "false_positive"].includes(verdict) ? verdict : "unknown";
      return bucket === tab;
    });
  }, [findings, constructFilter, cweGroups, tab]);
  const flat = Boolean(constructFilter) || cweGroups === null;

  const toggle = useCallback((setter: typeof setOpenIds, id: string) => {
    setter((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const allOpen =
    visibleCwes.length > 0 && visibleCwes.every((entry) => openCwes.has(entry.row.key));
  const reasons = Object.entries(counts?.by_unresolved_reason ?? {});

  const renderRow = (finding: Finding) => (
    <FindingRow
      key={finding.id}
      scanId={scanId}
      finding={finding}
      open={openIds.has(finding.id)}
      onToggle={() => toggle(setOpenIds, finding.id)}
      onConstructFilter={setConstructFilter}
      onSaved={() => setReloadKey((n) => n + 1)}
    />
  );

  return (
    <div className="space-y-5">
      {/* overflow-clip (not -hidden) so the sticky toolbar below still sticks to
          the panel's scroll container. */}
      <section className="overflow-clip rounded-md border border-slate-200 border-t-2 border-t-blue-500 bg-gradient-to-br from-white via-white to-blue-50/40 p-5">
        <div className="sticky top-0 z-10 -mx-5 -mt-5 border-b border-slate-200 bg-white/95 px-5 pb-3 pt-5 backdrop-blur">
        <div role="tablist" aria-label="Verdict" className="mb-3 flex flex-wrap gap-1">
          {VERDICT_TABS.map(({ key, label }) => {
            const selected = tab === key;
            const cell = tabCounts[key];
            return (
              <button
                type="button"
                role="tab"
                key={key}
                aria-selected={selected}
                onClick={() => {
                  setTab(key);
                  setConstructFilter(null);
                }}
                title={`${plural(cell.groups, "group")} · ${plural(cell.occurrences, "occurrence")}`}
                className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  selected
                    ? "bg-blue-600 text-white"
                    : "text-[var(--muted)] hover:bg-slate-100 hover:text-[var(--ink)]"
                }`}
              >
                {label}
                <span className={`ml-1.5 tabular-nums ${selected ? "text-blue-100" : ""}`}>
                  {cell.groups}
                </span>
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {chipLevels.map((risk) => {
            const selected = severityFilter === risk;
            const cell = chipCounts[risk] ?? { groups: 0, occurrences: 0 };
            const style = RISK_STYLES[risk];
            return (
              <button
                type="button"
                key={risk}
                disabled={cell.groups === 0 && !selected}
                title={`${plural(cell.groups, "group")} · ${plural(cell.occurrences, "occurrence")}`}
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
                <span className="font-semibold tabular-nums">{cell.groups}</span>
                {cell.occurrences > cell.groups ? (
                  <span className="font-normal normal-case tabular-nums opacity-75">
                    · {cell.occurrences}×
                  </span>
                ) : null}
              </button>
            );
          })}
          {constructFilter ? (
            <button
              type="button"
              onClick={() => setConstructFilter(null)}
              className="inline-flex items-center gap-1.5 rounded-full bg-amber-100 px-3 py-1 text-xs font-medium text-amber-900 hover:bg-amber-200"
              title="Show every finding again"
            >
              One construct only · clear
            </button>
          ) : null}
          {!flat && visibleCwes.length > 0 ? (
            <button
              type="button"
              onClick={() =>
                setOpenCwes(allOpen ? new Set() : new Set(visibleCwes.map((entry) => entry.row.key)))
              }
              className="ml-auto rounded-md px-2.5 py-1 text-xs font-medium text-blue-700 transition-colors hover:bg-blue-50"
            >
              {allOpen ? "Collapse all" : "Expand all"}
            </button>
          ) : null}
        </div>
        {!constructFilter && tab === "unverified" && reasons.length > 0 ? (
          <p className="mt-2 text-xs text-[var(--muted)]">
            Why these are unresolved:{" "}
            {reasons
              .map(([reason, n]) => `${n} — ${unresolvedReasonLabel(reason) ?? reason}`)
              .join(" · ")}
          </p>
        ) : null}
        {!constructFilter && tab === "false_positive" && hiddenFpCount > 0 ? (
          <p className="mt-2 text-xs text-[var(--muted)]">
            {plural(hiddenFpCount, "false positive")} the scanner was at least 90% sure of{" "}
            {hiddenFpCount === 1 ? "is" : "are"} not shown.
          </p>
        ) : null}
        </div>

        {findings === null ? (
          <p className="mt-3 text-sm text-[var(--muted)]">Loading findings…</p>
        ) : flat && flatFindings.some(severityMatches) ? (
          <ul className="mt-3 space-y-2">{flatFindings.filter(severityMatches).map(renderRow)}</ul>
        ) : flat || visibleCwes.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--muted)]">
            {tab === "true_positive" && !severityFilter && tabCounts.unverified.groups > 0 ? (
              <>
                No confirmed findings.{" "}
                <button
                  type="button"
                  onClick={() => setTab("unverified")}
                  className="font-medium text-blue-700 hover:underline"
                >
                  Show {plural(tabCounts.unverified.groups, "unresolved group")}
                </button>
              </>
            ) : (
              "No findings match this filter."
            )}
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {visibleCwes.map(({ row, slice, members }) => {
              const open = openCwes.has(row.key);
              const severity = normalizeSeverity(members[0].severity, true);
              const files = tab === "all" ? row.files : groupPaths(members);
              const breakdown = BUCKET_SHORT.filter((b) => row.by_bucket[b.key]);
              return (
                <li key={row.key} className="rounded-md border border-slate-200 bg-white">
                  <button
                    type="button"
                    onClick={() => toggle(setOpenCwes, row.key)}
                    aria-expanded={open}
                    className="agent-focus-ring flex w-full items-start gap-2 rounded-md px-3 py-2.5 text-left"
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
                            RISK_STYLES[severity]?.chip ?? "bg-slate-100 text-slate-600"
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
                        <span className="text-xs font-semibold text-[var(--ink)]">
                          {row.cwe ?? "No CWE"}
                        </span>
                        <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium tabular-nums text-slate-700">
                          {plural(slice.occurrences, "occurrence")} · {plural(slice.files, "file")}
                        </span>
                        {breakdown.length > 1 || tab === "all" ? (
                          <span className="text-xs text-[var(--muted)]">
                            {breakdown.map((b, i) => (
                              <span key={b.key}>
                                {i > 0 ? " · " : ""}
                                <span className={b.className}>
                                  {row.by_bucket[b.key].occurrences} {b.label}
                                </span>
                              </span>
                            ))}
                          </span>
                        ) : null}
                      </span>
                      <span
                        className={`mt-1 block text-sm font-medium text-[var(--ink)] ${
                          open ? "" : "line-clamp-2"
                        }`}
                      >
                        {row.title}
                      </span>
                      {members.length > 1 ? (
                        <span className="mt-0.5 block text-xs text-[var(--muted)]">
                          {plural(members.length, "issue group")} under this CWE
                        </span>
                      ) : null}
                    </span>
                  </button>
                  {open && (
                    <div className="border-t border-slate-200/70 px-3 pb-3 pt-2">
                      {files.length > 0 ? (
                        <div className="rounded border border-slate-200 bg-slate-50 p-2">
                          <p className="text-xs font-medium text-[var(--muted)]">
                            Found in {plural(files.length, "file")}
                          </p>
                          <AffectedFiles paths={files} />
                        </div>
                      ) : null}
                      <ul className="mt-2 space-y-2">{members.map(renderRow)}</ul>
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
