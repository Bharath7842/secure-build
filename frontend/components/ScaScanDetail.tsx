"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import ScanExportButtons from "@/components/ScanExportButtons";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import type { Finding, Project, ScaDiscovery, Scan, ScanStatus } from "@/lib/types";
import { useAuth } from "@/components/auth/AuthProvider";
import { canStopScan } from "@/lib/access";

const POLL_INTERVAL_MS = 2000;

function isTerminalStatus(status: string): boolean {
  return status !== "queued" && status !== "running";
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  LOW: "border-blue-200 bg-blue-50 text-blue-700",
  UNKNOWN: "border-slate-200 bg-slate-50 text-slate-600",
};

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.UNKNOWN;
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${style}`}
    >
      {severity}
    </span>
  );
}

function SummaryStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "warn";
}) {
  return (
    <div
      className={`rounded-md border px-4 py-3 ${
        tone === "warn" ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"
      }`}
    >
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p
        className={`mt-1 text-2xl font-semibold ${
          tone === "warn" ? "text-amber-700" : "text-[var(--ink)]"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

interface ScaScanDetailProps {
  scanId: string;
}

/** Dedicated, self-contained detail view for scan_type=sca — deliberately
 * separate from the main SAST ScanDetailPage (which is tightly coupled to
 * the LangGraph discovery agent's log/AST/usage panels) rather than
 * threading scan_type through that component's deep hook/memo graph. Reuses
 * the same generic building blocks (ScanStatusBadge, ScanExportButtons) and
 * the same `GET /scans/{id}/findings` + `/results` endpoints — `Finding`
 * rows with kind="sca" need no backend changes to show up here. */
export default function ScaScanDetail({ scanId }: ScaScanDetailProps) {
  const me = useAuth();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [scanRecord, setScanRecord] = useState<Scan | null>(null);
  const [discovery, setDiscovery] = useState<ScaDiscovery | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [resultsError, setResultsError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const { confirm, dialog } = useConfirmDialog();

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
          if (timer) {
            clearInterval(timer);
            timer = null;
          }
        }
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [scanId]);

  useEffect(() => {
    const projectId = status?.project_id;
    if (!projectId) return;
    let active = true;

    async function loadMeta(pid: string) {
      const [projectData, scans] = await Promise.all([
        api.projects.get(pid).catch(() => null),
        api.scans.list(pid, "sca").catch(() => []),
      ]);
      if (!active) return;
      setProject(projectData);
      setScanRecord(scans.find((scan) => scan.id === scanId) ?? null);
    }

    loadMeta(projectId);
    return () => {
      active = false;
    };
  }, [status?.project_id, scanId]);

  useEffect(() => {
    if (!status) return;
    const terminal = isTerminalStatus(status.status);
    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function fetchResults() {
      try {
        const data = await api.scans.results(scanId);
        if (!active) return;
        setDiscovery((data.discovery as ScaDiscovery | null) ?? null);
        setResultsError(null);
        if (isTerminalStatus(data.status) && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 409) {
          timer = setTimeout(fetchResults, POLL_INTERVAL_MS);
        } else if (terminal) {
          setResultsError(err instanceof ApiError ? err.message : "Failed to load scan results.");
        }
      }
    }

    fetchResults();
    if (!terminal) {
      interval = setInterval(fetchResults, POLL_INTERVAL_MS);
    }
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
      if (interval) clearInterval(interval);
    };
  }, [scanId, status]);

  useEffect(() => {
    if (!status) return;
    const terminal = isTerminalStatus(status.status);
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function loadFindings() {
      try {
        const data = await api.scans.findings(scanId);
        if (!active) return;
        setFindings(data.findings);
        if (terminal && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch {
        // Best-effort — the summary cards above still render from discovery.
      }
    }

    loadFindings();
    if (!terminal) {
      interval = setInterval(loadFindings, POLL_INTERVAL_MS);
    }
    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [scanId, status]);

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
          <Link href="/sca" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
            ← Back to SCA
          </Link>
        </div>
      </div>
    );
  }

  if (!status) {
    return <p className="px-12 py-10 text-sm text-[var(--muted)]">Loading scan…</p>;
  }

  const terminal = isTerminalStatus(status.status);
  const canExport = terminal && findings.length > 0;
  const severityCounts = discovery?.dependency_summary.severity_counts ?? null;

  return (
    <div className="h-full min-h-0 overflow-auto bg-white px-6 py-6">
      {dialog}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link
            href="/sca"
            className="shrink-0 text-sm font-medium text-[var(--accent)] hover:underline"
          >
            ← SCA
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
        <div className="flex items-center gap-3">
          <ScanStatusBadge status={status.status} />
          {canExport && <ScanExportButtons scanId={scanId} compact />}
        </div>
      </div>

      {stopError && (
        <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {stopError}
        </div>
      )}
      {terminal && status.status === "failed" && status.message && (
        <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {status.message}
        </div>
      )}
      {resultsError && (
        <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {resultsError}
        </div>
      )}

      {!terminal && (
        <div className="mt-4 flex items-center justify-between gap-4 rounded-md border border-blue-200 bg-blue-50 px-4 py-3">
          <p className="text-sm text-blue-800">
            {status.status === "queued" ? "Queued…" : "Scanning dependency manifests…"} (
            {status.progress}%)
          </p>
          {canStopScan(me, status) && (
            <button
              type="button"
              disabled={stopping}
              onClick={stopScan}
              className="rounded-md border border-blue-300 bg-white px-3 py-1 text-xs font-medium text-blue-800 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {stopping ? "Stopping…" : "Stop scan"}
            </button>
          )}
        </div>
      )}

      {discovery && (
        <div className="mt-6">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            Dependency inventory
          </h2>
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <SummaryStat label="Dependencies" value={discovery.dependency_summary.total_dependencies} />
            <SummaryStat
              label="Vulnerable"
              value={discovery.dependency_summary.vulnerable_dependencies}
              tone={discovery.dependency_summary.vulnerable_dependencies > 0 ? "warn" : undefined}
            />
            <SummaryStat label="Manifests" value={discovery.dependency_summary.manifests_parsed.length} />
            <SummaryStat
              label="Ecosystems"
              value={discovery.dependency_summary.ecosystems.join(", ") || "—"}
            />
          </div>
          {severityCounts && (
            <div className="mt-3 flex flex-wrap gap-2">
              {SEVERITY_ORDER.filter((level) => (severityCounts[level] ?? 0) > 0).map((level) => (
                <span
                  key={level}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${SEVERITY_STYLES[level]}`}
                >
                  {severityCounts[level]} {level}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="mt-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          Vulnerabilities ({findings.length})
        </h2>
        {findings.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--muted)]">
            {terminal ? "No known vulnerabilities found in declared dependencies." : "Scanning…"}
          </p>
        ) : (
          <table className="mt-4 w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                <th className="py-2 font-medium">Severity</th>
                <th className="py-2 font-medium">Package</th>
                <th className="py-2 font-medium">Advisory</th>
                <th className="py-2 font-medium">CVSS</th>
                <th className="py-2 font-medium">Manifest</th>
                <th className="py-2 font-medium">Suggested fix</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} className="border-b border-slate-100 align-top">
                  <td className="py-3">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="py-3 font-mono text-xs text-[var(--ink)]">
                    {finding.matched_text ?? "—"}
                  </td>
                  <td className="py-3 text-[var(--ink)]">
                    <div className="font-medium">{finding.rule_id ?? "—"}</div>
                    {finding.snippet && (
                      <div className="mt-1 max-w-md text-xs text-[var(--muted)]">{finding.snippet}</div>
                    )}
                  </td>
                  <td className="py-3 text-[var(--muted)]">
                    {finding.cvss != null ? finding.cvss.toFixed(1) : "—"}
                  </td>
                  <td className="py-3 text-xs text-[var(--muted)]">{finding.file_path ?? "—"}</td>
                  <td className="py-3 text-xs text-[var(--muted)]">{finding.ai_fix ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
