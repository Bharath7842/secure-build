"use client";

import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";

interface ProjectStructurePanelProps {
  tree: string[];
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

function highlightMatch(line: string, query: string): ReactNode {
  if (!query) return line;
  const lower = line.toLowerCase();
  const q = query.toLowerCase();
  const idx = lower.indexOf(q);
  if (idx < 0) return line;
  return (
    <>
      {line.slice(0, idx)}
      <mark className="rounded-sm bg-blue-100 text-[var(--ink)]">{line.slice(idx, idx + query.length)}</mark>
      {line.slice(idx + query.length)}
    </>
  );
}

/** Prefer directory headers (`…:`) as the one ancestor context line for a match. */
function findAncestorIndex(tree: string[], matchIndex: number): number | null {
  for (let i = matchIndex - 1; i >= 0; i--) {
    const line = tree[i];
    if (line.endsWith(":") || (!line.startsWith("├") && !line.startsWith("└") && !line.startsWith("│"))) {
      return i;
    }
  }
  return null;
}

function filterTreeWithAncestors(tree: string[], query: string): { line: string; i: number }[] {
  const q = query.trim().toLowerCase();
  if (!q) return tree.map((line, i) => ({ line, i }));

  const include = new Set<number>();
  tree.forEach((line, i) => {
    if (!line.toLowerCase().includes(q)) return;
    include.add(i);
    const ancestor = findAncestorIndex(tree, i);
    if (ancestor != null) include.add(ancestor);
  });

  return tree
    .map((line, i) => ({ line, i }))
    .filter(({ i }) => include.has(i));
}

export default function ProjectStructurePanel({
  tree,
  onClose,
  expanded = false,
  onToggleExpand,
}: ProjectStructurePanelProps) {
  const [query, setQuery] = useState("");
  const title = tree[0]?.replace(/:$/, "") || "Project";
  const entryCount = Math.max(0, tree.length - 1);
  const emptyTree = tree.length === 0;

  const filtered = useMemo(() => filterTreeWithAncestors(tree, query), [tree, query]);
  const directMatchCount = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    return tree.filter((line) => line.toLowerCase().includes(q)).length;
  }, [tree, query]);

  const matchCount = query.trim() ? filtered.length : null;

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
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            </svg>
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--ink)]">Project structure</p>
            <p className="truncate text-xs text-[var(--muted)]">
              {emptyTree
                ? "No structure available"
                : `${title} · ${entryCount} ${entryCount === 1 ? "entry" : "entries"}`}
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
          <p className="text-sm text-[var(--muted)]">No project structure recorded for this scan.</p>
        ) : (
          <>
            <div>
              <label htmlFor="structure-search" className="sr-only">
                Filter project structure
              </label>
              <div className="flex items-center gap-2">
                <input
                  id="structure-search"
                  type="search"
                  role="searchbox"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={onSearchKeyDown}
                  placeholder="Filter structure…"
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
              <p className="mt-1.5 text-xs text-[var(--muted)]" aria-live="polite">
                {directMatchCount == null
                  ? null
                  : directMatchCount === 0
                    ? "No matches"
                    : `${directMatchCount} ${directMatchCount === 1 ? "match" : "matches"}`}
              </p>
            </div>

            {query.trim() && directMatchCount === 0 ? (
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
              <pre className="agent-scroll min-h-0 flex-1 overflow-x-hidden overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-xs leading-5 text-[var(--ink)]">
                {filtered.map(({ line, i }) => (
                  <span key={i} className="block">
                    {highlightMatch(line, query.trim())}
                  </span>
                ))}
              </pre>
            )}
          </>
        )}
      </div>
    </div>
  );
}
