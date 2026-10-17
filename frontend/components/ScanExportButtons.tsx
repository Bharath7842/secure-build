"use client";

import { useState } from "react";

import { useCan } from "@/components/auth/AuthProvider";
import { apiFetch } from "@/lib/api";

type ExportFormat = "pdf" | "xlsx";

interface ScanExportButtonsProps {
  scanId: string;
  disabled?: boolean;
  /** Compact header chips (PDF / Excel only) — default is the large labeled buttons. */
  compact?: boolean;
}

async function downloadExport(scanId: string, format: ExportFormat): Promise<void> {
  const res = await apiFetch(`/api/scans/${scanId}/export/${format}`, { cache: "no-store" });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail =
      body && typeof body === "object" && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : `Export failed (${res.status})`;
    throw new Error(detail);
  }

  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  const match = /filename="?([^"]+)"?/i.exec(disposition);
  const filename = match?.[1] || `scan-export.${format}`;

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function DownloadIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.25"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M12 3v12m0 0-4-4m4 4 4-4M4 21h16" />
    </svg>
  );
}

export default function ScanExportButtons({
  scanId,
  disabled,
  compact = false,
}: ScanExportButtonsProps) {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const can = useCan();

  async function handleExport(format: ExportFormat) {
    setBusy(format);
    setError(null);
    try {
      await downloadExport(scanId, format);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setBusy(null);
    }
  }

  if (compact) {
    return (
      <div className="flex flex-col items-end gap-1">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={disabled || busy !== null}
            onClick={() => handleExport("pdf")}
            title={busy === "pdf" ? "Preparing PDF…" : "Download PDF"}
            aria-label={busy === "pdf" ? "Preparing PDF" : "Download PDF"}
            className="agent-focus-ring inline-flex h-7 items-center gap-1 rounded-md border border-red-200 bg-red-50 px-2 text-[10px] font-bold tracking-wide text-red-700 transition-colors hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <DownloadIcon />
            {busy === "pdf" ? "…" : "PDF"}
          </button>
          <button
            type="button"
            disabled={disabled || busy !== null}
            onClick={() => handleExport("xlsx")}
            title={busy === "xlsx" ? "Preparing Excel…" : "Download Excel"}
            aria-label={busy === "xlsx" ? "Preparing Excel" : "Download Excel"}
            className="agent-focus-ring inline-flex h-7 items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2 text-[10px] font-bold tracking-wide text-emerald-700 transition-colors hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <DownloadIcon />
            {busy === "xlsx" ? "…" : "Excel"}
          </button>
        </div>
        {error && <p className="max-w-[12rem] text-right text-[10px] text-red-600">{error}</p>}
      </div>
    );
  }

  if (!can("reports.export")) return null;

  return (
    <div className="flex flex-col items-stretch gap-2 sm:items-end">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={disabled || busy !== null}
          onClick={() => handleExport("pdf")}
          className="group inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-[var(--ink)] shadow-sm transition hover:border-[var(--accent)]/40 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span className="inline-flex h-7 w-7 items-center justify-center rounded bg-red-50 text-[11px] font-bold tracking-wide text-red-700 ring-1 ring-red-100">
            PDF
          </span>
          <span className="text-left leading-tight">
            <span className="block">{busy === "pdf" ? "Preparing…" : "Download PDF"}</span>
            <span className="block text-xs font-normal text-[var(--muted)]">Print-ready report</span>
          </span>
        </button>

        <button
          type="button"
          disabled={disabled || busy !== null}
          onClick={() => handleExport("xlsx")}
          className="group inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3.5 py-2 text-sm font-medium text-[var(--ink)] shadow-sm transition hover:border-emerald-500/40 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span className="inline-flex h-7 w-7 items-center justify-center rounded bg-emerald-50 text-[10px] font-bold tracking-wide text-emerald-700 ring-1 ring-emerald-100">
            XLS
          </span>
          <span className="text-left leading-tight">
            <span className="block">{busy === "xlsx" ? "Preparing…" : "Download Excel"}</span>
            <span className="block text-xs font-normal text-[var(--muted)]">Summary + findings</span>
          </span>
        </button>
      </div>
      {error && <p className="max-w-sm text-right text-xs text-red-600">{error}</p>}
    </div>
  );
}
