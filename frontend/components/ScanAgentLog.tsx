"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import AgentArtifactCard from "@/components/AgentArtifactCard";
import {
  isLlmResponseBoundaryLine,
  isLlmResponseHeaderLine,
  isProjectStructureTreeLine,
  parseScanLogLines,
} from "@/lib/parseScanLog";
import type { Scan, ScanLogLine } from "@/lib/types";

export interface SectionCard {
  /** Match against a `### <label>` section from STEP_LABELS (case-insensitive). */
  afterLabel: string;
  node: ReactNode;
}

interface ScanAgentLogProps {
  lines: ScanLogLine[];
  live: boolean;
  /**
   * Artifact cards placed after a named agent section (e.g. Discovery after
   * "Mapping module risk"). Cards whose label never appears fall back to the
   * end of the feed.
   */
  sectionCards?: SectionCard[];
  scanStatus?: Scan["status"] | null;
  progress?: number | null;
  failureMessage?: string | null;
  onStop?: () => void;
  stopping?: boolean;
  showStop?: boolean;
  /** Opens project structure in the side panel (like Discovery results). */
  onOpenStructure?: (tree: string[]) => void;
  structureOpen?: boolean;
}

const SCROLL_THROTTLE_MS = 100;

function StopScanButton({
  stopping,
  onStop,
  compact = false,
}: {
  stopping?: boolean;
  onStop: () => void;
  compact?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={stopping}
      onClick={onStop}
      className={`agent-focus-ring shrink-0 rounded-md border border-red-200 bg-red-50 font-medium text-red-700 transition-colors hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 ${
        compact ? "px-2 py-0.5 text-xs" : "px-2.5 py-1 text-xs"
      }`}
    >
      {stopping ? "Stopping…" : "Stop scan"}
    </button>
  );
}

function FolderIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
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
  );
}

function CheckCircleIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="12" cy="12" r="10" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function LiveCircleIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="animate-spin"
    >
      <path d="M21 12a9 9 0 1 1-6.2-8.6" />
    </svg>
  );
}

function InfoCircleIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}

function AgentShieldIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12h6M12 9v6" />
    </svg>
  );
}

/** ASCII / box-drawing tree lines from the discovery agent's project structure. */
function isTreeLine(line: string): boolean {
  return isProjectStructureTreeLine(line);
}

// "<detected signal> -> <rationale> -> N targeted rule(s)." — one line per
// vulnerability surface (sast_scan_agent.py's `_log_active_surfaces`).
// Internal reasoning narration, not shown in the UI — renderSectionLines
// skips both this and its header rather than rendering them.
const SURFACE_RULE_LINE_RE = /^(.+?)\s*->\s*(\d+)\s+targeted rule\(s\)\.$/;
const SURFACE_LIST_HEADER_RE = /known vulnerability surface\(s\):$/;

function ProjectStructureCard({
  tree,
  onOpen,
  active,
}: {
  tree: string[];
  onOpen?: (tree: string[]) => void;
  active?: boolean;
}) {
  const title = tree[0]?.replace(/:$/, "") || "Project";
  const entryCount = Math.max(0, tree.length - 1);

  return (
    <div className="mt-1">
      <AgentArtifactCard
        icon={<FolderIcon />}
        tone="blue"
        title="Project structure"
        subtitle={`${title} · ${entryCount} ${entryCount === 1 ? "entry" : "entries"}`}
        active={active}
        onClick={onOpen ? () => onOpen(tree) : undefined}
        ariaLabel="Open project structure"
      />
    </div>
  );
}

/** If `lines[start]` opens a JSON value (a bare `{`/`[` line, or a whole
 * one-line object/array), return it re-indented — the log parser trims every
 * line, which would otherwise flatten pretty-printed JSON into a column of
 * unindented fragments. */
function takeJsonBlock(lines: string[], start: number): { text: string; next: number } | null {
  const first = lines[start];
  if (!first || (first[0] !== "{" && first[0] !== "[")) return null;
  const maxEnd = first.length > 1 ? start : Math.min(lines.length - 1, start + 400);
  for (let end = start; end <= maxEnd; end++) {
    try {
      const parsed = JSON.parse(lines.slice(start, end + 1).join("\n"));
      if (parsed === null || typeof parsed !== "object") return null;
      return { text: JSON.stringify(parsed, null, 2), next: end + 1 };
    } catch {
      // keep extending a multi-line block until it parses
    }
  }
  return null;
}

const THINKING_LINE_RE = /^\[thinking\]\s*(.*)$/;

function renderSectionLines(
  lines: string[],
  onOpenStructure?: (tree: string[]) => void,
  structureOpen?: boolean,
) {
  const blocks: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const json = takeJsonBlock(lines, i);
    if (json) {
      blocks.push(
        <pre
          key={`json-${i}`}
          className="max-h-64 overflow-auto rounded-md border border-slate-200 bg-white px-3 py-2 font-mono text-xs leading-snug text-slate-700"
        >
          {json.text}
        </pre>
      );
      i = json.next;
      continue;
    }

    const thinking = lines[i].match(THINKING_LINE_RE);
    if (thinking && thinking[1]) {
      blocks.push(
        <p key={`think-${i}`} className="text-sm italic text-slate-600 leading-relaxed whitespace-pre-wrap break-words">
          {thinking[1]}
        </p>
      );
      i += 1;
      continue;
    }

    // Skip legacy LLM response dumps (no longer logged; hide old scan noise).
    if (isLlmResponseHeaderLine(lines[i])) {
      let j = i + 1;
      while (j < lines.length && !isLlmResponseBoundaryLine(lines[j])) {
        j += 1;
      }
      i = j;
      continue;
    }

    if (lines[i] === "Project structure:" && i + 1 < lines.length && isTreeLine(lines[i + 1])) {
      const tree: string[] = [];
      i += 1;
      while (i < lines.length && isTreeLine(lines[i])) {
        tree.push(lines[i]);
        i += 1;
      }
      blocks.push(
        <ProjectStructureCard
          key={`tree-${i}`}
          tree={tree}
          onOpen={onOpenStructure}
          active={structureOpen}
        />
      );
      continue;
    }

    if (
      isTreeLine(lines[i]) &&
      (lines[i].startsWith("├──") || lines[i].startsWith("└──") || lines[i].endsWith(":"))
    ) {
      const tree: string[] = [];
      let j = i;
      while (j < lines.length && isTreeLine(lines[j])) {
        tree.push(lines[j]);
        j += 1;
      }
      // A real tree has at least one drawn branch (├──/└──) under the header —
      // a lone path-like line is just a heading, not a structure dump.
      const hasBranches = tree.some((l) => l.startsWith("├──") || l.startsWith("└──"));
      if (!hasBranches) {
        blocks.push(
          <p key={`line-${i}`} className="text-sm leading-relaxed text-[var(--ink)]">
            {lines[i]}
          </p>
        );
        i += 1;
        continue;
      }
      i = j;
      blocks.push(
        <ProjectStructureCard
          key={`tree-${i}`}
          tree={tree}
          onOpen={onOpenStructure}
          active={structureOpen}
        />
      );
      continue;
    }

    // Vulnerability-surface mapping narration ("Mapping the detected stack
    // onto N known vulnerability surface(s):" + one "signal -> N rules" line
    // per surface) is internal reasoning, not something scan viewers act on
    // — skip the whole block rather than rendering it.
    if (SURFACE_LIST_HEADER_RE.test(lines[i])) {
      i += 1;
      continue;
    }

    const surfaceMatch = lines[i].match(SURFACE_RULE_LINE_RE);
    if (surfaceMatch) {
      let j = i;
      while (j < lines.length && SURFACE_RULE_LINE_RE.test(lines[j])) {
        j += 1;
      }
      i = j;
      continue;
    }

    blocks.push(
      <p key={`line-${i}`} className="break-words text-sm leading-relaxed text-[var(--ink)]">
        {lines[i]}
      </p>
    );
    i += 1;
  }
  return blocks;
}

/**
 * Phase label is derived from the latest parsed section title (backend prints
 * `### <label>` from STEP_LABELS). No frontend step→string map.
 */
function derivePhaseLabel(sections: { label: string }[]): string | null {
  if (sections.length === 0) return null;
  return sections[sections.length - 1].label;
}

export default function ScanAgentLog({
  lines,
  live,
  sectionCards = [],
  scanStatus,
  progress = null,
  failureMessage = null,
  onStop,
  stopping = false,
  showStop = false,
  onOpenStructure,
  structureOpen = false,
}: ScanAgentLogProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [stickToBottom, setStickToBottom] = useState(true);
  const lastScrollAtRef = useRef(0);
  const pendingScrollRef = useRef<number | null>(null);

  const sections = useMemo(() => parseScanLogLines(lines), [lines]);
  // Phase copy follows backend STEP_LABELS via ### banners — see derivePhaseLabel.
  const phaseLabel = derivePhaseLabel(sections);
  const failed = scanStatus === "failed";
  const cancelled = scanStatus === "cancelled";
  const terminal = !live;
  const progressValue = Math.max(0, Math.min(100, progress ?? 0));

  const cardsByLabel = useMemo(() => {
    const map = new Map<string, ReactNode[]>();
    for (const card of sectionCards) {
      const key = card.afterLabel.trim().toLowerCase();
      const list = map.get(key) ?? [];
      list.push(card.node);
      map.set(key, list);
    }
    return map;
  }, [sectionCards]);

  const placedLabels = useMemo(() => {
    const found = new Set<string>();
    for (const section of sections) {
      const key = section.label.trim().toLowerCase();
      if (cardsByLabel.has(key)) found.add(key);
    }
    return found;
  }, [sections, cardsByLabel]);

  const fallbackCards = useMemo(() => {
    const nodes: ReactNode[] = [];
    for (const card of sectionCards) {
      const key = card.afterLabel.trim().toLowerCase();
      if (!placedLabels.has(key)) nodes.push(card.node);
    }
    return nodes;
  }, [sectionCards, placedLabels]);

  const hasCards = sectionCards.length > 0;

  function scrollToBottom(immediate = false) {
    const el = scrollRef.current;
    if (!el) return;

    const run = () => {
      el.scrollTop = el.scrollHeight;
      lastScrollAtRef.current = Date.now();
      pendingScrollRef.current = null;
    };

    if (immediate) {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
        pendingScrollRef.current = null;
      }
      run();
      return;
    }

    const elapsed = Date.now() - lastScrollAtRef.current;
    if (elapsed >= SCROLL_THROTTLE_MS) {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
      }
      pendingScrollRef.current = requestAnimationFrame(run);
      return;
    }

    if (pendingScrollRef.current != null) return;
    pendingScrollRef.current = requestAnimationFrame(() => {
      const wait = SCROLL_THROTTLE_MS - (Date.now() - lastScrollAtRef.current);
      window.setTimeout(run, Math.max(0, wait));
    });
  }

  useEffect(() => {
    if (!stickToBottom) return;
    scrollToBottom(false);
    return () => {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
        pendingScrollRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- throttle helper is stable enough via refs
  }, [lines, sections, sectionCards, stickToBottom]);

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    setStickToBottom(atBottom);
  }

  const streamingCopy =
    live && sections.length === 0
      ? "Waiting for the agent…"
      : live && phaseLabel
        ? `${phaseLabel}…`
        : null;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-white">
      <div className="border-b border-slate-200 px-5 py-4">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-100 text-blue-600">
            <AgentShieldIcon />
          </span>
          <h3 className="font-display text-lg text-[var(--ink)]">Secure Build Agent</h3>
          {live && (
            <span className="flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
              Live
            </span>
          )}
          {live && phaseLabel && (
            <span className="text-xs text-[var(--muted)]" aria-live="polite">
              {phaseLabel}…
            </span>
          )}
          {showStop && onStop && live && (
            <StopScanButton stopping={stopping} onStop={onStop} />
          )}
        </div>

        {progress != null && (
          <div
            className="mt-3 overflow-hidden rounded-full"
            style={{
              height: "var(--agent-progress-height)",
              background: "var(--agent-progress-track)",
            }}
            role="progressbar"
            aria-valuenow={progressValue}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Scan progress"
          >
            <div
              className="agent-progress-fill"
              data-failed={failed ? "true" : undefined}
              style={{ width: `${terminal && !failed && !cancelled ? 100 : progressValue}%` }}
            />
          </div>
        )}
      </div>

      <div className="relative min-h-0 flex-1">
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="agent-scroll h-full overflow-y-auto px-5 py-6"
        >
          {sections.length === 0 && !hasCards && !failed ? (
            <div
              className="flex min-h-48 flex-col items-center justify-center gap-2 text-center"
              style={{
                borderRadius: "var(--agent-block-radius)",
                padding: "var(--agent-block-pad-y) var(--agent-block-pad-x)",
              }}
            >
              <p className="text-sm text-[var(--muted)]">
                {live ? "Waiting for the agent to start…" : "No agent activity recorded."}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-200">
              {sections.map((section, index) => {
                const isLatest = index === sections.length - 1;
                const isLiveSection = live && isLatest;
                const muted = live && !isLatest;
                const sectionKey = section.label.trim().toLowerCase();
                const afterCards = cardsByLabel.get(sectionKey);

                return (
                  <div key={section.seq}>
                    <div
                      className={`agent-section-enter py-5 first:pt-0 last:pb-0 ${
                        isLiveSection ? "relative" : ""
                      }`}
                      style={{
                        opacity: muted
                          ? "var(--agent-section-done-opacity)"
                          : "var(--agent-section-live-opacity)",
                      }}
                    >
                      {isLiveSection && (
                        <span
                          className="agent-edge-pulse absolute top-5 bottom-5 left-0 rounded-full"
                          style={{
                            width: "var(--agent-accent-edge-width)",
                            background: "var(--agent-accent-edge-color)",
                          }}
                          aria-hidden
                        />
                      )}
                      <div
                        style={{
                          background: "var(--agent-block-bg)",
                          borderRadius: "var(--agent-block-radius)",
                          padding: `var(--agent-block-pad-y) var(--agent-block-pad-x)`,
                          marginLeft: isLiveSection ? "var(--agent-accent-edge-gap)" : 0,
                        }}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex min-w-0 items-center gap-2">
                            <span
                              className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full ${
                                isLiveSection
                                  ? "bg-blue-100 text-blue-600"
                                  : "bg-emerald-100 text-emerald-600"
                              }`}
                            >
                              {isLiveSection ? (
                                <LiveCircleIcon />
                              ) : muted || terminal ? (
                                <CheckCircleIcon />
                              ) : (
                                <InfoCircleIcon />
                              )}
                            </span>
                            <p className="text-sm font-bold tracking-wide text-slate-800">
                              {section.label}
                            </p>
                          </div>
                          {isLiveSection && showStop && onStop && (
                            <StopScanButton stopping={stopping} onStop={onStop} compact />
                          )}
                        </div>
                        <div className="mt-1.5 space-y-1">
                          {renderSectionLines(
                            section.lines,
                            onOpenStructure,
                            structureOpen,
                          )}
                        </div>
                      </div>
                    </div>
                    {afterCards &&
                      !isLiveSection &&
                      afterCards.map((node, cardIndex) => (
                        <div key={`${section.seq}-card-${cardIndex}`} className="py-5 last:pb-0">
                          {node}
                        </div>
                      ))}
                  </div>
                );
              })}

              {live && !hasCards && streamingCopy && (
                <div className="py-5 last:pb-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="agent-pulse-bar mb-2 max-w-xs" aria-hidden />
                      <p className="text-sm text-[var(--muted)]" aria-live="polite">
                        {streamingCopy}
                      </p>
                    </div>
                    {showStop && onStop && (
                      <StopScanButton stopping={stopping} onStop={onStop} compact />
                    )}
                  </div>
                </div>
              )}

              {fallbackCards.map((node, index) => (
                <div key={`fallback-card-${index}`} className="py-5 last:pb-0">
                  {node}
                </div>
              ))}

              {failed && failureMessage && (
                <div className="py-5 last:pb-0">
                  <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {failureMessage}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {!stickToBottom && (sections.length > 0 || hasCards) && (
          <div className="pointer-events-none absolute inset-x-0 bottom-4 z-10 flex justify-center">
            <button
              type="button"
              aria-label="Jump to latest agent output"
              onClick={() => {
                setStickToBottom(true);
                scrollToBottom(true);
              }}
              className="agent-focus-ring pointer-events-auto rounded-full border border-blue-200 bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-md transition-colors hover:bg-blue-700"
            >
              Jump to latest ↓
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
