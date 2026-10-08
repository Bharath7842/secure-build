"use client";

import { useMemo, useState, type KeyboardEvent } from "react";

import type { DerivedRule, DerivedRulesSummary } from "@/lib/types";

interface DerivedRulesPanelProps {
  rules: DerivedRule[];
  summary?: DerivedRulesSummary;
  onClose: () => void;
  expanded?: boolean;
  onToggleExpand?: () => void;
}

function CloseIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  );
}

function ExpandIcon() {
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
      <path d="M8 3H3v5M16 3h5v5M8 21H3v-5M16 21h5v-5" />
    </svg>
  );
}

function CollapseIcon() {
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
      <path d="M4 9h4V5M4 9l5-5M20 9h-4V5M20 9l-5-5M4 15h4v4M4 15l5 5M20 15h-4v4M20 15l-5 5" />
    </svg>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700",
  HIGH: "bg-orange-100 text-orange-700",
  MEDIUM: "bg-amber-100 text-amber-700",
  LOW: "bg-slate-100 text-[var(--muted)]",
};

function RuleRow({ rule }: { rule: DerivedRule }) {
  const fromLlm = rule.id.startsWith("runtime-llm-");
  return (
    <div className="rounded-md border border-slate-200 bg-white px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-xs font-semibold text-[var(--ink)]">{rule.title}</span>
        <span
          className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-none ${
            SEVERITY_STYLES[rule.severity] ?? SEVERITY_STYLES.LOW
          }`}
        >
          {rule.severity}
        </span>
        {rule.cwe && (
          <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium leading-none text-[var(--muted)]">
            {rule.cwe}
          </span>
        )}
        <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium leading-none text-[var(--muted)]">
          {fromLlm ? "LLM-proposed" : "call-graph wrapper"}
        </span>
      </div>
      {rule.description && (
        <p className="mt-1 text-xs text-[var(--muted)]">{rule.description}</p>
      )}
      <pre className="mt-1.5 overflow-x-auto rounded bg-slate-50 px-2 py-1 font-mono text-[11px] text-[var(--ink)]">
        {rule.pattern}
      </pre>
    </div>
  );
}

export default function DerivedRulesPanel({
  rules,
  summary,
  onClose,
  expanded = false,
  onToggleExpand,
}: DerivedRulesPanelProps) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rules;
    return rules.filter(
      (r) =>
        r.title.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.pattern.toLowerCase().includes(q) ||
        r.cwe.toLowerCase().includes(q)
    );
  }, [rules, query]);

  const isSearching = query.trim().length > 0;
  const noMatches = isSearching && filtered.length === 0;
  const isEmpty = rules.length === 0;

  function onSearchKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Escape" && query) {
      e.preventDefault();
      setQuery("");
    }
  }

  return (
    <div
      className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white"
      style={{ transition: `opacity var(--agent-panel-transition), transform var(--agent-panel-transition)` }}
    >
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-gradient-to-r from-purple-50/80 to-white px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-purple-100 text-purple-600">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
              <path d="M4 7V4h16v3M9 20h6M12 4v16" />
            </svg>
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--ink)]">Derived rules</p>
            <p className="truncate text-xs text-[var(--muted)]">
              {isEmpty ? "No rules derived" : `${rules.length} rule(s) for this scan`}
              {summary?.failed ? ` · ${summary.failed} failed` : ""}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {onToggleExpand && (
            <button
              type="button"
              onClick={onToggleExpand}
              aria-label={expanded ? "Collapse to split view" : "Expand to full page"}
              className="agent-focus-ring rounded-md p-1.5 text-[var(--muted)] transition-colors hover:bg-slate-100 hover:text-[var(--ink)]"
            >
              {expanded ? <CollapseIcon /> : <ExpandIcon />}
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="agent-focus-ring rounded-md p-1.5 text-[var(--muted)] transition-colors hover:bg-slate-100 hover:text-[var(--ink)]"
          >
            <CloseIcon />
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 flex-col gap-3 px-5 py-6">
        {summary?.failed ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            <p className="font-medium">
              {summary.failed} candidate{summary.failed === 1 ? "" : "s"} failed validation and{" "}
              {summary.failed === 1 ? "was" : "were"} dropped — never retried or auto-corrected.
            </p>
            {Object.keys(summary.failed_by_reason).length > 0 && (
              <ul className="mt-1 space-y-0.5">
                {Object.entries(summary.failed_by_reason)
                  .sort((a, b) => b[1] - a[1])
                  .map(([reason, count]) => (
                    <li key={reason} className="font-mono">
                      {reason}: {count}
                    </li>
                  ))}
              </ul>
            )}
          </div>
        ) : null}
        {isEmpty ? (
          <p className="text-sm text-[var(--muted)]">No runtime-derived regex rules recorded for this scan.</p>
        ) : (
          <>
            <div>
              <label htmlFor="derived-rules-search" className="sr-only">
                Filter derived rules
              </label>
              <div className="flex items-center gap-2">
                <input
                  id="derived-rules-search"
                  type="search"
                  role="searchbox"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={onSearchKeyDown}
                  placeholder="Filter rules, CWE, pattern…"
                  className="agent-focus-ring w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm text-[var(--ink)] placeholder:text-[var(--muted)]"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    className="agent-focus-ring shrink-0 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-[var(--muted)] hover:bg-slate-50 hover:text-[var(--ink)]"
                  >
                    Clear
                  </button>
                )}
              </div>
              {isSearching && (
                <p className="mt-1.5 text-xs text-[var(--muted)]" aria-live="polite">
                  {noMatches ? "No matches" : `${filtered.length} match(es)`}
                </p>
              )}
            </div>

            {noMatches ? (
              <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-6 text-center">
                <p className="text-sm text-[var(--muted)]">
                  No matches for &quot;{query.trim()}&quot;
                </p>
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="agent-focus-ring mt-3 text-xs font-medium text-[var(--accent)] hover:underline"
                >
                  Clear search
                </button>
              </div>
            ) : (
              <div className="agent-scroll min-h-0 flex-1 space-y-2 overflow-y-auto">
                {filtered.map((rule) => (
                  <RuleRow key={rule.id} rule={rule} />
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
