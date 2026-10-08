"use client";

import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";

import { buildAstTree, countAstLeaves, filterAstTree, type AstTreeNode } from "@/lib/astSummaryTree";
import type { AstSummary } from "@/lib/types";

interface AstSummaryPanelProps {
  summary: AstSummary;
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

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className={`shrink-0 transition-transform ${open ? "rotate-90" : ""}`}
    >
      <path d="m9 6 6 6-6 6" />
    </svg>
  );
}

function WarningIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="shrink-0"
    >
      <path d="M12 9v4M12 17h.01" />
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
    </svg>
  );
}

function highlightMatch(text: string, query: string): ReactNode {
  if (!query) return text;
  const lower = text.toLowerCase();
  const q = query.toLowerCase();
  const idx = lower.indexOf(q);
  if (idx < 0) return text;
  return (
    <>
      {text.slice(0, idx)}
      <mark className="rounded-sm bg-blue-100 text-[var(--ink)]">{text.slice(idx, idx + query.length)}</mark>
      {text.slice(idx + query.length)}
    </>
  );
}

function TreeRow({
  node,
  depth,
  query,
  collapsedIds,
  onToggle,
  forceExpanded,
}: {
  node: AstTreeNode;
  depth: number;
  query: string;
  collapsedIds: Set<string>;
  onToggle: (id: string) => void;
  forceExpanded: boolean;
}) {
  const hasChildren = Boolean(node.children && node.children.length > 0);
  const open = forceExpanded || !collapsedIds.has(node.id);
  const warning = node.tone === "warning";

  return (
    <div>
      <button
        type="button"
        onClick={hasChildren ? () => onToggle(node.id) : undefined}
        disabled={!hasChildren}
        className={`agent-focus-ring flex w-full items-start gap-1.5 rounded-md px-1.5 py-1 text-left text-xs transition-colors ${
          hasChildren ? "hover:bg-slate-100" : ""
        } ${hasChildren ? "cursor-pointer" : "cursor-default"}`}
        style={{ paddingLeft: `${depth * 16 + 6}px` }}
      >
        {hasChildren ? (
          <ChevronIcon open={open} />
        ) : (
          <span className="inline-block h-3 w-3 shrink-0" aria-hidden />
        )}
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-1.5">
            {warning && (
              <span className="text-amber-600">
                <WarningIcon />
              </span>
            )}
            <span
              className={`font-mono ${warning ? "text-amber-800" : "text-[var(--ink)]"} ${
                hasChildren ? "font-semibold" : ""
              }`}
            >
              {highlightMatch(node.label, query)}
            </span>
            {node.badge && (
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-none ${
                  warning ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-[var(--muted)]"
                }`}
              >
                {node.badge}
              </span>
            )}
          </span>
          {node.meta && (
            <span className="mt-0.5 block truncate font-mono text-[11px] text-[var(--muted)]">
              {highlightMatch(node.meta, query)}
            </span>
          )}
        </span>
      </button>
      {hasChildren && open && (
        <div>
          {node.children!.map((child) => (
            <TreeRow
              key={child.id}
              node={child}
              depth={depth + 1}
              query={query}
              collapsedIds={collapsedIds}
              onToggle={onToggle}
              forceExpanded={forceExpanded}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function AstSummaryPanel({
  summary,
  onClose,
  expanded = false,
  onToggleExpand,
}: AstSummaryPanelProps) {
  const [query, setQuery] = useState("");
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(new Set());

  const tree = useMemo(() => buildAstTree(summary), [summary]);
  const stackCount = tree.length;
  const leafCount = useMemo(() => countAstLeaves(tree), [tree]);
  const emptyTree = tree.length === 0;

  const filtered = useMemo(() => filterAstTree(tree, query), [tree, query]);
  const isSearching = query.trim().length > 0;
  const noMatches = isSearching && filtered.length === 0;

  function toggleNode(id: string) {
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

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
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-gradient-to-r from-blue-50/80 to-white px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-100 text-blue-600">
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
              <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />
            </svg>
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--ink)]">AST structure</p>
            <p className="truncate text-xs text-[var(--muted)]">
              {emptyTree
                ? "No structure available"
                : `${stackCount} ${stackCount === 1 ? "stack" : "stacks"} · ${leafCount} ${
                    leafCount === 1 ? "entry" : "entries"
                  }`}
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
        {emptyTree ? (
          <p className="text-sm text-[var(--muted)]">No AST structure recorded for this scan.</p>
        ) : (
          <>
            <div>
              <label htmlFor="ast-structure-search" className="sr-only">
                Filter AST structure
              </label>
              <div className="flex items-center gap-2">
                <input
                  id="ast-structure-search"
                  type="search"
                  role="searchbox"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={onSearchKeyDown}
                  placeholder="Filter annotations, entry points, routes…"
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
                  {noMatches
                    ? "No matches"
                    : `${countAstLeaves(filtered)} ${countAstLeaves(filtered) === 1 ? "match" : "matches"}`}
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
              <div className="agent-scroll min-h-0 flex-1 overflow-x-hidden overflow-y-auto rounded-md border border-slate-200 bg-slate-50 px-2 py-2">
                {filtered.map((node) => (
                  <TreeRow
                    key={node.id}
                    node={node}
                    depth={0}
                    query={query.trim()}
                    collapsedIds={collapsedIds}
                    onToggle={toggleNode}
                    forceExpanded={isSearching}
                  />
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
