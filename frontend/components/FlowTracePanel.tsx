"use client";

import { useLayoutEffect, useMemo, useRef, useState } from "react";

import { toModulePath } from "@/lib/modulePath";
import type { Finding, FlowHop } from "@/lib/types";

function fileKey(path: string | undefined): string {
  return (path || "").replace(/\\/g, "/").toLowerCase();
}

function basename(path: string): string {
  const posix = path.replace(/\\/g, "/");
  const parts = posix.split("/");
  return parts[parts.length - 1] || path;
}

function hopsForFile(hops: FlowHop[], file: string): FlowHop[] {
  const key = fileKey(file);
  return hops.filter((h) => fileKey(h.file) === key);
}

function snippetOf(hop: FlowHop, fallback = ""): string {
  return hop.snippet || (hop as FlowHop & { body?: string }).body || fallback;
}

/** Only real call-graph hops that leave the entry file. Intra-file LLM
 *  source→sink strings keep the single snippet, not a fake Steps rail. */
export function hopsForFinding(finding: Finding): FlowHop[] {
  const stored = (finding.flow_path || []).filter(Boolean);
  if (stored.length < 2) return [];
  const files = new Set(stored.map((hop) => fileKey(hop.file)));
  if (files.size < 2) return [];
  return stored.map((hop, i) => ({
    ...hop,
    step: hop.step || i + 1,
    snippet: snippetOf(hop, finding.snippet || ""),
  }));
}

type ParsedLine = {
  sourceLine: number;
  display: string;
  tags: number[];
};

function parseLines(hop: FlowHop, fileHops: FlowHop[]): ParsedLine[] {
  const markers = new Map<number, number[]>();
  for (const h of fileHops) {
    if (!h.line) continue;
    const list = markers.get(h.line) ?? [];
    list.push(h.step);
    markers.set(h.line, list);
  }
  const rawLines = snippetOf(hop).split("\n");
  const alreadyNumbered = rawLines.some((line) => /^\d+:/.test(line));
  const start = hop.start_line || 1;
  return rawLines.map((raw, idx) => {
    const numbered = raw.match(/^(\d+):\s?(.*)$/);
    const sourceLine = numbered
      ? Number(numbered[1])
      : alreadyNumbered
        ? 0
        : start + idx;
    const body = (numbered ? numbered[2] : raw).replace(/\s*<--\s*$/, "");
    const tags = markers.get(sourceLine) ?? [];
    const tag = tags.length ? `${tags.map((s) => `[${s}]`).join("")} ` : "";
    const display = numbered
      ? `${numbered[1]}: ${tag}${body}`
      : alreadyNumbered
        ? raw
        : `${start + idx}: ${tag}${body}`;
    return { sourceLine, display, tags };
  });
}

export default function FlowTracePanel({ hops }: { hops: FlowHop[] }) {
  const ordered = useMemo(
    () => [...hops].sort((a, b) => (a.step || 0) - (b.step || 0)),
    [hops],
  );
  const [active, setActive] = useState(0);
  const current = ordered[active] ?? ordered[0];
  const activeLineRef = useRef<HTMLDivElement | null>(null);

  const files = useMemo(
    () => new Set(ordered.map((h) => fileKey(h.file))),
    [ordered],
  );
  const fileHops = current ? hopsForFile(ordered, current.file) : [];
  const lines = current ? parseLines(current, fileHops) : [];

  useLayoutEffect(() => {
    activeLineRef.current?.scrollIntoView({ block: "center", inline: "nearest" });
  }, [active, current?.file, current?.line]);

  if (!current) return null;

  return (
    <div className="mt-2 overflow-hidden rounded border border-sky-200 bg-white">
      <div className="border-b border-sky-100 bg-sky-50/80 px-3 py-2">
        <p className="truncate font-mono text-xs text-[var(--ink)]" title={current.file}>
          {current.method || basename(current.file) || toModulePath(current.file)}
        </p>
        <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--muted)]" title={current.file}>
          {toModulePath(current.file) || current.file}
        </p>
        <p className="mt-0.5 text-xs text-[var(--muted)]">
          {ordered.length} step{ordered.length === 1 ? "" : "s"} across {files.size}{" "}
          file{files.size === 1 ? "" : "s"}
        </p>
      </div>
      <div className="flex min-h-[12rem] max-h-[28rem] flex-col sm:flex-row">
        <ol className="flex max-h-40 flex-shrink-0 gap-0 overflow-x-auto border-b border-slate-200 bg-slate-50 agent-scroll sm:max-h-none sm:w-48 sm:flex-col sm:overflow-y-auto sm:border-b-0 sm:border-r">
          {ordered.map((hop, idx) => {
            const selected = idx === active;
            const role =
              hop.role === "source" ? "Source" : hop.role === "sink" ? "Sink" : null;
            return (
              <li key={`${hop.file}:${hop.line}:${hop.step}:${idx}`} className="min-w-[9rem] sm:min-w-0">
                <button
                  type="button"
                  onClick={() => setActive(idx)}
                  className={`w-full border-b-2 px-2.5 py-2 text-left text-xs sm:border-b-0 sm:border-l-2 ${
                    selected
                      ? "border-sky-500 bg-white"
                      : "border-transparent hover:bg-white/70"
                  }`}
                >
                  <span className="flex items-center gap-1.5 font-medium text-[var(--ink)]">
                    Step {hop.step || idx + 1}
                    {role && (
                      <span className="rounded bg-sky-100 px-1 py-0.5 text-[10px] uppercase tracking-wide text-sky-800">
                        {role}
                      </span>
                    )}
                  </span>
                  <span className="mt-0.5 block truncate font-mono text-[11px] text-[var(--ink)]">
                    {hop.method || hop.label || basename(hop.file)}
                  </span>
                  <span className="block truncate font-mono text-[11px] text-[var(--muted)]">
                    {basename(hop.file)}
                    {hop.line ? `:${hop.line}` : ""}
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
        <div className="min-w-0 flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed text-[var(--ink)] agent-scroll">
          {lines.map((line, idx) => {
            const isActive = line.sourceLine === current.line;
            return (
              <div
                key={`${line.sourceLine}:${idx}`}
                ref={isActive ? activeLineRef : undefined}
                className={`whitespace-pre ${isActive ? "bg-sky-100" : ""}`}
              >
                {line.display || " "}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
