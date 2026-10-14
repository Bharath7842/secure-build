"use client";

import type { ScanReport } from "@/lib/types";

import ScanExportButtons from "@/components/ScanExportButtons";
import ScanFindingsPanel from "@/components/ScanFindingsPanel";

interface ScanFindingsResultPanelProps {
  scanId: string;
  report: ScanReport;
  onClose: () => void;
  expanded?: boolean;
  onToggleExpand?: () => void;
  live?: boolean;
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

function FindingsHeaderIcon() {
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
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12h6M12 9v6" />
    </svg>
  );
}

export default function ScanFindingsResultPanel({
  scanId,
  report,
  onClose,
  expanded = false,
  onToggleExpand,
  live = false,
}: ScanFindingsResultPanelProps) {
  return (
    <div
      className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white"
      style={{ transition: `opacity var(--agent-panel-transition), transform var(--agent-panel-transition)` }}
    >
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 bg-gradient-to-r from-blue-50/80 to-white px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-100 text-blue-600">
            <FindingsHeaderIcon />
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--ink)]">Findings</p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <ScanExportButtons scanId={scanId} compact />
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
        <ScanFindingsPanel
          scanId={scanId}
          report={report}
          live={live}
        />
      </div>
    </div>
  );
}
