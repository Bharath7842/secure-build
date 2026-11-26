"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import ScanExportButtons from "@/components/ScanExportButtons";
import ScanFindingsPanel from "@/components/ScanFindingsPanel";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import type { Project, Scan, ScanReport, ScanStatus } from "@/lib/types";
import { canStopScan } from "@/lib/access";
import { useAuth } from "@/components/auth/AuthProvider";

const POLL_INTERVAL_MS = 2000;

function isTerminalStatus(status: string): boolean {
  return status !== "queued" && status !== "running";
}

interface IacScanDetailProps {
  scanId: string;
}

export default function IacScanDetail({ scanId }: IacScanDetailProps) {
  const me = useAuth();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [scanRecord, setScanRecord] = useState<Scan | null>(null);
  const [stopError, setStopError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const { confirm, dialog } = useConfirmDialog();

  // ── Status polling ──────────────────────────────────────────────────────
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;

    async function poll() {
      try {
        const data = await api.scans.status(scanId);
        if (!active) return;
        setStatus(data);
        setNotFound(false);
        if (isTerminalStatus(data.status) && timer) {
          clearInterval(timer);
          timer = null;
        }
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
          if (timer) { clearInterval(timer); timer = null; }
        }
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => { active = false; if (timer) clearInterval(timer); };
  }, [scanId]);

  // ── Project / scan record meta ──────────────────────────────────────────
  useEffect(() => {
    const projectId = status?.project_id;
    if (!projectId) return;
    let active = true;

    async function loadMeta(pid: string) {
      const [projectData, scans] = await Promise.all([
        api.projects.get(pid).catch(() => null),
        api.scans.list(pid, "iac").catch(() => []),
      ]);
      if (!active) return;
      setProject(projectData);
      setScanRecord(scans.find((s) => s.id === scanId) ?? null);
    }

    loadMeta(projectId);
    return () => { active = false; };
  }, [status?.project_id, scanId]);

  async function stopScan() {
    if (!(await confirm({ message: "Stop this scan?", confirmLabel: "Stop" }))) return;
    setStopping(true);
    setStopError(null);
    try {
      const updated = await api.scans.cancel(scanId);
      setStatus(updated);
    } catch (err) {
      setStopError(err instanceof ApiError ? err.message : "Could not stop scan.");
    } finally {
      setStopping(false);
    }
  }

  if (notFound) {
    return (
      <div className="flex h-full items-center justify-center px-12 py-10">
        <div className="rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
          <p className="text-sm text-[var(--muted)]">Scan not found.</p>
          <Link href="/iac" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
            ← Back to IaC
          </Link>
        </div>
      </div>
    );
  }

  if (!status) {
    return <p className="px-12 py-10 text-sm text-[var(--muted)]">Loading scan…</p>;
  }

  const terminal = isTerminalStatus(status.status);
  const canExport = terminal && status.status === "success";

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-white">
      {dialog}

      {/* ── Header ── */}
      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-slate-200 px-6 py-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link
            href="/iac"
            className="shrink-0 text-sm font-medium text-[var(--accent)] hover:underline"
          >
            ← IaC
          </Link>
          <span className="shrink-0 text-slate-300">/</span>
          <p className="min-w-0 truncate text-sm text-[var(--ink)]">
            <span className="font-medium">{project?.name ?? status.project_id}</span>
            {scanRecord?.branch && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">Branch: {scanRecord.branch}</span>
              </>
            )}
            {scanRecord && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">Scan · v{scanRecord.version}</span>
              </>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          {!terminal && canStopScan(me, status) && (
            <button
              type="button"
              onClick={stopScan}
              disabled={stopping}
              className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-[var(--ink)] hover:bg-slate-50 disabled:opacity-50"
            >
              {stopping ? "Stopping…" : "Stop scan"}
            </button>
          )}
          {canExport && <ScanExportButtons scanId={scanId} compact />}
          <ScanStatusBadge status={status.status} />
        </div>
      </div>

      {/* ── Notices ── */}
      {(stopError || (terminal && status.status === "failed" && status.message)) && (
        <div className="shrink-0 space-y-2 border-b border-slate-200 px-6 py-3">
          {stopError && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {stopError}
            </div>
          )}
          {terminal && status.status === "failed" && status.message && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {status.message}
            </div>
          )}
        </div>
      )}

      {/* ── Main content ── */}
      <div className="agent-scroll h-full min-h-0 overflow-y-auto px-6 py-6">
        <ScanFindingsPanel
          scanId={scanId}
          report={{} as ScanReport}
          live={!terminal}
        />
      </div>
    </div>
  );
}
