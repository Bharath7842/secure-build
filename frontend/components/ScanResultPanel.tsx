"use client";

import { useCallback } from "react";

import ScanDiscoveryPanel from "@/components/ScanDiscoveryPanel";
import type { ScanDiscovery } from "@/lib/types";

interface ScanResultPanelProps {
  discovery: ScanDiscovery;
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

function DownloadIcon() {
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
      <path d="M12 3v12m0 0-4-4m4 4 4-4M4 21h16" />
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

function DiscoveryHeaderIcon() {
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
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

export default function ScanResultPanel({
  discovery,
  onClose,
  expanded = false,
  onToggleExpand,
}: ScanResultPanelProps) {
  const handleDownload = useCallback(() => {
    const blob = new Blob([JSON.stringify(discovery, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "discovery-results.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [discovery]);

  return (
    <div
      className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white"
      style={{ transition: `opacity var(--agent-panel-transition), transform var(--agent-panel-transition)` }}
    >
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-gradient-to-r from-emerald-50/80 to-white px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-emerald-100 text-emerald-600">
            <DiscoveryHeaderIcon />
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--ink)]">Discovery results</p>
            <p className="truncate text-xs text-[var(--muted)]">
              {discovery.llm_analysis.tech_stack} · JSON
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            type="button"
            onClick={handleDownload}
            className="agent-focus-ring flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-[var(--ink)] transition-colors hover:bg-slate-50"
          >
            <DownloadIcon />
            Download
          </button>
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
      <div className="agent-scroll min-h-0 flex-1 overflow-y-auto px-5 py-6">
        <ScanDiscoveryPanel discovery={discovery} />
      </div>
    </div>
  );
}
