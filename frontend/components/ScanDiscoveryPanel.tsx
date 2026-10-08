"use client";

import { useMemo, useState, type ReactNode } from "react";

import { toModulePath } from "@/lib/modulePath";
import type { ScanDiscovery, ScanDiscoveryAstFinding, ScanDiscoveryFile } from "@/lib/types";

const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const RISK_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/** Severity palette: red / amber / green (RAG). */
const RISK_DOT: Record<string, string> = {
  CRITICAL: "bg-red-700",
  HIGH: "bg-red-500",
  MEDIUM: "bg-amber-500",
  LOW: "bg-emerald-500",
};

const RISK_STYLES: Record<string, { chip: string; icon: string; active: string }> = {
  CRITICAL: {
    chip: "bg-red-100 text-red-800",
    icon: "bg-red-100 text-red-700",
    active: "bg-red-50 ring-1 ring-red-400",
  },
  HIGH: {
    chip: "bg-red-50 text-red-700",
    icon: "bg-red-50 text-red-600",
    active: "bg-red-50 ring-1 ring-red-300",
  },
  MEDIUM: {
    chip: "bg-amber-50 text-amber-800",
    icon: "bg-amber-100 text-amber-600",
    active: "bg-amber-50 ring-1 ring-amber-300",
  },
  LOW: {
    chip: "bg-emerald-50 text-emerald-700",
    icon: "bg-emerald-50 text-emerald-600",
    active: "bg-emerald-50 ring-1 ring-emerald-300",
  },
};

const BLUE = {
  iconBg: "bg-blue-100",
  iconFg: "text-blue-600",
  active: "bg-blue-50 ring-1 ring-blue-300",
};
const EMERALD = {
  iconBg: "bg-emerald-100",
  iconFg: "text-emerald-600",
  active: "bg-emerald-50 ring-1 ring-emerald-300",
};

const CATEGORY_META: Record<
  string,
  { label: string; iconBg: string; iconFg: string; active: string }
> = {
  source: { label: "Source", ...BLUE },
  config: { label: "Config", ...EMERALD },
  dependency: { label: "Dependency", ...BLUE },
  test: { label: "Test", ...EMERALD },
  build: { label: "Build", ...BLUE },
  other: { label: "Other", ...EMERALD },
};

const CONFIDENCE_STYLES: Record<string, string> = {
  high: "border-emerald-200 bg-emerald-50 text-emerald-700",
  medium: "border-blue-200 bg-blue-50 text-blue-700",
  low: "border-blue-100 bg-blue-50/60 text-blue-600",
};

const EMPTY_FILES: ScanDiscoveryFile[] = [];

function IconShell({ children }: { children: ReactNode }) {
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
      {children}
    </svg>
  );
}

function CategoryIcon({ category }: { category: string }) {
  switch (category) {
    case "source":
      return (
        <IconShell>
          <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />
        </IconShell>
      );
    case "config":
      return (
        <IconShell>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" />
        </IconShell>
      );
    case "dependency":
      return (
        <IconShell>
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        </IconShell>
      );
    case "test":
      return (
        <IconShell>
          <path d="M9 3h6l1 7H8L9 3zM8 10h8v2a4 4 0 0 1-8 0v-2z" />
        </IconShell>
      );
    case "build":
      return (
        <IconShell>
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
        </IconShell>
      );
    default:
      return (
        <IconShell>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6" />
        </IconShell>
      );
  }
}

function StackIcon() {
  return (
    <IconShell>
      <path d="M12 2 2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
    </IconShell>
  );
}

function CheckIcon() {
  return (
    <IconShell>
      <path d="M20 6 9 17l-5-5" />
    </IconShell>
  );
}

function FilesIcon() {
  return (
    <IconShell>
      <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z" />
      <path d="M14 2v4a2 2 0 0 0 2 2h4" />
    </IconShell>
  );
}

function ShieldIcon() {
  return (
    <IconShell>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </IconShell>
  );
}

function RiskAreaIcon({ index }: { index: number }) {
  const icons = [
    <path key="a" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
    <path key="b" d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01" />,
    <path key="c" d="M12 1a3 3 0 0 0-3 3v2H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-2V4a3 3 0 0 0-3-3z" />,
  ];
  return <IconShell>{icons[index % icons.length]}</IconShell>;
}

/** Weighted risk score 0–100 for the gradient meter needle. */
function riskScore(riskCounts: Record<string, number>): number {
  const critical = riskCounts.CRITICAL ?? 0;
  const high = riskCounts.HIGH ?? 0;
  const medium = riskCounts.MEDIUM ?? 0;
  const low = riskCounts.LOW ?? 0;
  const total = critical + high + medium + low;
  if (total === 0) return 8;
  const weighted = critical * 100 + high * 72 + medium * 42 + low * 15;
  return Math.max(8, Math.min(96, Math.round(weighted / total)));
}

function sortFiles(files: ScanDiscoveryFile[]): ScanDiscoveryFile[] {
  return [...files].sort((a, b) => {
    const riskDiff = (RISK_ORDER[a.risk_level] ?? 99) - (RISK_ORDER[b.risk_level] ?? 99);
    if (riskDiff !== 0) return riskDiff;
    return a.path.localeCompare(b.path);
  });
}

interface ScanDiscoveryPanelProps {
  discovery: ScanDiscovery;
}

export default function ScanDiscoveryPanel({ discovery }: ScanDiscoveryPanelProps) {
  const [riskFilter, setRiskFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  const { llm_analysis, module_plan, categorized_counts, scan_summary, ast_findings } = discovery;
  const files = module_plan.files ?? EMPTY_FILES;
  const riskCounts = module_plan.risk_counts ?? ({} as Record<string, number>);
  const score = riskScore(riskCounts);

  const astFindingsList = useMemo(() => {
    return ast_findings?.findings ?? [];
  }, [ast_findings]);
  const falsePositiveCount = useMemo(
    () => astFindingsList.filter((f: ScanDiscoveryAstFinding) => f.llm_verdict === "false_positive").length,
    [astFindingsList]
  );

  const visibleFiles = useMemo(() => {
    return sortFiles(
      files.filter((f) => {
        if (riskFilter && f.risk_level !== riskFilter) return false;
        if (categoryFilter && f.category !== categoryFilter) return false;
        return true;
      })
    );
  }, [files, riskFilter, categoryFilter]);

  const hasActiveFilter = Boolean(riskFilter) || Boolean(categoryFilter);
  const confidence = (llm_analysis.confidence || "low").toLowerCase();

  function clearFilters() {
    setRiskFilter(null);
    setCategoryFilter(null);
  }

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-blue-400 bg-gradient-to-br from-white via-white to-blue-50/40 p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 items-start gap-3">
            <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-blue-100 text-blue-600">
              <StackIcon />
            </span>
            <div className="min-w-0">
              <h2 className="font-display text-xl text-[var(--ink)]">{llm_analysis.tech_stack}</h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                {llm_analysis.project_type} · {scan_summary.total_files} files scanned
                {llm_analysis.llm_used ? "" : " · heuristics only"}
              </p>
            </div>
          </div>
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-wide ${
              CONFIDENCE_STYLES[confidence] ?? CONFIDENCE_STYLES.low
            }`}
          >
            {confidence === "high" && <CheckIcon />}
            {confidence} confidence
          </span>
        </div>
        {llm_analysis.reasoning && (
          <p className="mt-3 text-sm text-[var(--ink)]">{llm_analysis.reasoning}</p>
        )}
        {llm_analysis.risk_areas.length > 0 && (
          <ul className="mt-4 space-y-2">
            {llm_analysis.risk_areas.map((area, i) => (
              <li
                key={area}
                className="flex items-center gap-2.5 text-sm text-[var(--ink)]"
              >
                <span
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${
                    i % 2 === 0
                      ? "bg-blue-100 text-blue-600"
                      : "bg-emerald-100 text-emerald-600"
                  }`}
                >
                  <RiskAreaIcon index={i} />
                </span>
                {area}
              </li>
            ))}
          </ul>
        )}
      </section>

      {ast_findings && (
        <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-blue-500 bg-gradient-to-br from-white via-white to-blue-50/40 p-5">
          <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            <span className="flex h-6 w-6 items-center justify-center rounded bg-blue-100 text-blue-600">
              <ShieldIcon />
            </span>
            AST findings
          </h3>
          <p className="mt-2 text-sm text-[var(--ink)]">
            {ast_findings.raw_count} pattern match(es) · {ast_findings.confirmed_count} confirmed by LLM ·{" "}
            {falsePositiveCount} false positive(s)
          </p>
          {astFindingsList.length === 0 ? (
            <p className="mt-3 text-sm text-[var(--muted)]">
              No AST findings in this scan.
            </p>
          ) : (
            <ul className="mt-3 max-h-96 space-y-3 overflow-y-auto agent-scroll">
              {astFindingsList.map((finding) => {
                const riskStyle = RISK_STYLES[finding.severity];
                const isConfirmed = finding.llm_verdict === "confirmed";
                return (
                  <li
                    key={`${finding.file_path}-${finding.line_number}-${finding.rule_id}`}
                    className={`rounded-md border px-3 py-2 ${
                      isConfirmed
                        ? "border-blue-100 bg-blue-50/50"
                        : "border-amber-100 bg-amber-50/30"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${
                          riskStyle?.chip ?? "bg-slate-100 text-slate-600"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${
                            RISK_DOT[finding.severity] ?? "bg-slate-400"
                          }`}
                          aria-hidden
                        />
                        {finding.severity}
                      </span>
                      <span className="text-xs font-medium text-[var(--ink)]">
                        {finding.rule_id}
                      </span>
                      <span className="text-xs text-[var(--muted)]">
                        {finding.category}
                      </span>
                    </div>
                    <p className="mt-1.5 truncate font-mono text-xs font-medium text-[var(--ink)]" title={finding.file_path}>
                      {toModulePath(finding.file_path)}:{finding.line_number}
                    </p>
                    <pre className="mt-1.5 max-h-24 overflow-auto rounded bg-slate-950/5 p-2 font-mono text-xs text-[var(--ink)]">
                      {finding.code_snippet}
                    </pre>
                    <div className="mt-1.5 text-xs">
                      <span className="font-medium text-[var(--muted)]">LLM verdict: </span>
                      <span
                        className={`font-medium ${
                          isConfirmed
                            ? "text-emerald-700"
                            : "text-amber-700"
                        }`}
                      >
                        {isConfirmed ? "Confirmed" : "False Positive"}
                      </span>
                      {finding.llm_explanation && (
                        <p className="mt-0.5 text-[var(--muted)]">
                          {finding.llm_explanation}
                        </p>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}

      <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-emerald-400 bg-gradient-to-br from-white via-white to-emerald-50/30 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            <span className="flex h-6 w-6 items-center justify-center rounded bg-blue-100 text-blue-600">
              <FilesIcon />
            </span>
            Files by category
          </h3>
          {hasActiveFilter && (
            <button
              type="button"
              onClick={clearFilters}
              className="text-xs font-medium text-[var(--accent)] hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
        <div className="mt-3 grid grid-cols-3 gap-2 sm:grid-cols-6">
          {Object.entries(categorized_counts).map(([category, count]) => {
            const meta = CATEGORY_META[category] ?? CATEGORY_META.other;
            const selected = categoryFilter === category;
            return (
              <button
                type="button"
                key={category}
                onClick={() =>
                  setCategoryFilter((current) => (current === category ? null : category))
                }
                disabled={count === 0}
                className={`rounded-md px-3 py-2 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                  selected ? meta.active : "hover:bg-slate-50"
                }`}
              >
                <span
                  className={`mb-1.5 inline-flex h-6 w-6 items-center justify-center rounded ${meta.iconBg} ${meta.iconFg}`}
                >
                  <CategoryIcon category={category} />
                </span>
                <p className="text-xs uppercase tracking-wide text-[var(--muted)]">
                  {meta.label}
                </p>
                <p className="mt-1 text-2xl font-semibold text-[var(--ink)]">{count}</p>
              </button>
            );
          })}
        </div>

        <h3 className="mt-5 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          <span className="flex h-6 w-6 items-center justify-center rounded bg-red-100 text-red-600">
            <ShieldIcon />
          </span>
          Severity
        </h3>

        <div className="relative mt-3 mb-4 px-1">
          <div
            className="h-2.5 rounded-full"
            style={{
              background:
                "linear-gradient(90deg, #34d399 0%, #fbbf24 40%, #f97316 70%, #dc2626 100%)",
            }}
            role="img"
            aria-label={`Overall severity position ${score} of 100`}
          />
          <span
            className="absolute top-full mt-0.5 -translate-x-1/2 text-slate-500"
            style={{ left: `${score}%` }}
            aria-hidden
          >
            <svg width="10" height="8" viewBox="0 0 10 8" fill="currentColor">
              <path d="M5 0L10 8H0L5 0Z" />
            </svg>
          </span>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {RISK_LEVELS.map((risk) => {
            const style = RISK_STYLES[risk];
            const selected = riskFilter === risk;
            return (
              <button
                type="button"
                key={risk}
                onClick={() => setRiskFilter((current) => (current === risk ? null : risk))}
                disabled={!riskCounts[risk]}
                className={`flex items-center gap-2 rounded-md px-3 py-2 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                  selected ? style.active : "hover:bg-slate-50"
                }`}
              >
                <span
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${style.icon}`}
                  aria-hidden
                >
                  <span className={`h-2 w-2 rounded-full ${RISK_DOT[risk]}`} />
                </span>
                <span>
                  <span className="block text-xs uppercase tracking-wide text-[var(--muted)]">
                    {risk}
                  </span>
                  <span className="block text-lg font-semibold text-[var(--ink)]">
                    {riskCounts[risk] ?? 0}
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      </section>

      <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-slate-300 bg-white">
        <div className="border-b border-slate-200 bg-slate-50/80 px-4 py-3">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            Files ({visibleFiles.length}
            {visibleFiles.length !== files.length ? ` of ${files.length}` : ""})
          </h3>
        </div>
        {visibleFiles.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--muted)]">
            No files match the current filters.
          </div>
        ) : (
          <div className="agent-scroll overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase tracking-wide text-[var(--muted)]">
                <tr>
                  <th className="px-4 py-2 font-medium">Severity</th>
                  <th className="px-4 py-2 font-medium">Path</th>
                  <th className="px-4 py-2 font-medium">Module</th>
                  <th className="px-4 py-2 font-medium">Category</th>
                  <th className="px-4 py-2 font-medium">Why</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {visibleFiles.map((file) => {
                  const riskStyle = RISK_STYLES[file.risk_level];
                  const catMeta = CATEGORY_META[file.category] ?? CATEGORY_META.other;
                  return (
                    <tr key={file.path} className="hover:bg-slate-50">
                      <td className="px-4 py-2">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${
                            riskStyle?.chip ?? "bg-slate-100 text-slate-600"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${
                              RISK_DOT[file.risk_level] ?? "bg-slate-400"
                            }`}
                            aria-hidden
                          />
                          {file.risk_level}
                        </span>
                      </td>
                      <td
                        className="max-w-xs truncate px-4 py-2 font-mono text-xs text-[var(--ink)]"
                        title={file.path}
                      >
                        {toModulePath(file.path)}
                      </td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)]">{file.module}</td>
                      <td className="px-4 py-2">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-xs ${catMeta.iconBg} ${catMeta.iconFg}`}
                        >
                          <CategoryIcon category={file.category} />
                          {catMeta.label}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)]">{file.reason}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
