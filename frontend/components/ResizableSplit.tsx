"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

import { DESKTOP_SPLIT_QUERY, useMediaQuery } from "@/lib/useMediaQuery";

const STORAGE_KEY = "scan-split-right-width";
const MIN_RIGHT = 320;
const MAX_RIGHT = 960;
const MIN_LEFT = 380;
const DEFAULT_RIGHT = 480;
const KEY_STEP = 24;

interface ResizableSplitProps {
  left: ReactNode;
  /** Side panel content, or null when no panel is open. */
  right: ReactNode | null;
  /** Right panel is popped to full-page view; left pane is hidden entirely. */
  expanded?: boolean;
}

function readStoredWidth(): number | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const parsed = raw != null ? Number(raw) : NaN;
    return Number.isFinite(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function persistWidth(width: number) {
  try {
    window.localStorage.setItem(STORAGE_KEY, String(Math.round(width)));
  } catch {
    // Best-effort: a private-browsing tab or full quota shouldn't break the split.
  }
}

export default function ResizableSplit({ left, right, expanded = false }: ResizableSplitProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);
  const [rightWidth, setRightWidth] = useState(DEFAULT_RIGHT);
  const isDesktop = useMediaQuery(DESKTOP_SPLIT_QUERY);

  useEffect(() => {
    const stored = readStoredWidth();
    if (stored != null) setRightWidth(clampWidth(stored));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- read once on mount
  }, []);

  function clampWidth(candidate: number): number {
    const containerWidth = containerRef.current?.clientWidth ?? window.innerWidth;
    const upperBound = Math.max(MIN_RIGHT, Math.min(MAX_RIGHT, containerWidth - MIN_LEFT));
    return Math.min(Math.max(candidate, MIN_RIGHT), upperBound);
  }

  function beginDrag(e: React.PointerEvent<HTMLDivElement>) {
    if (!right || !isDesktop) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    draggingRef.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }

  function onDrag(e: React.PointerEvent<HTMLDivElement>) {
    if (!draggingRef.current || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setRightWidth(clampWidth(rect.right - e.clientX));
  }

  function endDrag(e: React.PointerEvent<HTMLDivElement>) {
    if (!draggingRef.current) return;
    draggingRef.current = false;
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
    setRightWidth((w) => {
      persistWidth(w);
      return w;
    });
  }

  function commitWidth(width: number) {
    const clamped = clampWidth(width);
    setRightWidth(clamped);
    persistWidth(clamped);
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    switch (e.key) {
      case "ArrowLeft":
        e.preventDefault();
        commitWidth(rightWidth + KEY_STEP);
        break;
      case "ArrowRight":
        e.preventDefault();
        commitWidth(rightWidth - KEY_STEP);
        break;
      case "Home":
        e.preventDefault();
        commitWidth(MIN_RIGHT);
        break;
      case "End":
        e.preventDefault();
        commitWidth(MAX_RIGHT);
        break;
      default:
        break;
    }
  }

  if (!right) {
    return <div className="h-full min-h-0 w-full overflow-hidden">{left}</div>;
  }

  if (expanded) {
    return <div className="h-full min-h-0 w-full overflow-hidden">{right}</div>;
  }

  if (!isDesktop) {
    return (
      <div className="relative h-full min-h-0 w-full overflow-hidden">
        {left}
        <div className="fixed inset-0 z-40 flex flex-col overflow-hidden bg-white">{right}</div>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="flex h-full min-h-0 w-full overflow-hidden">
      <div className="h-full min-h-0 min-w-0 flex-1 overflow-hidden">{left}</div>

      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize panel"
        aria-valuenow={Math.round(rightWidth)}
        aria-valuemin={MIN_RIGHT}
        aria-valuemax={MAX_RIGHT}
        tabIndex={0}
        onPointerDown={beginDrag}
        onPointerMove={onDrag}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        onKeyDown={onKeyDown}
        className="agent-focus-ring group relative w-2 shrink-0 cursor-col-resize touch-none select-none"
      >
        <div className="pointer-events-none absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-slate-200 transition-colors group-hover:bg-[var(--accent)] group-focus-visible:bg-[var(--accent)]" />
        <div className="pointer-events-none absolute top-1/2 left-1/2 h-10 w-1 -translate-x-1/2 -translate-y-1/2 rounded-full bg-slate-300 opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100" />
      </div>

      <div className="h-full min-h-0 shrink-0 overflow-hidden" style={{ width: rightWidth }}>
        {right}
      </div>
    </div>
  );
}
