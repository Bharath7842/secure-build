"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import ScanExportButtons from "@/components/ScanExportButtons";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import type {
  Project,
  Scan,
  ScanStatus,
  SbomComponent,
  SbomCostClassification,
  SbomDiscovery,
} from "@/lib/types";

const POLL_INTERVAL_MS = 2000;

function isTerminalStatus(status: string): boolean {
  return status !== "queued" && status !== "running";
}

const COST_ORDER = ["fully_free", "partially_free", "fully_paid", "unknown"] as const;

const COST_STYLES: Record<string, string> = {
  fully_free: "border-emerald-200 bg-emerald-50 text-emerald-700",
  partially_free: "border-amber-200 bg-amber-50 text-amber-700",
  fully_paid: "border-red-200 bg-red-50 text-red-700",
  unknown: "border-slate-200 bg-slate-50 text-slate-600",
};

const COST_LABELS: Record<string, string> = {
  fully_free: "Fully free",
  partially_free: "Partially free",
  fully_paid: "Fully paid",
  unknown: "Unknown",
};

const TYPE_STYLES: Record<string, string> = {
  "Open Source": "border-emerald-200 bg-emerald-50 text-emerald-700",
  Proprietary: "border-red-200 bg-red-50 text-red-700",
  Internal: "border-slate-200 bg-slate-50 text-slate-600",
};

function TypeBadge({ type }: { type: string }) {
  const style = TYPE_STYLES[type] ?? TYPE_STYLES["Open Source"];
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${style}`}
    >
      {type}
    </span>
  );
}

function CostBadge({ classification }: { classification: SbomCostClassification }) {
  const style = COST_STYLES[classification] ?? COST_STYLES.unknown;
  const label = COST_LABELS[classification] ?? COST_LABELS.unknown;
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${style}`}
    >
      {label}
    </span>
  );
}

function SummaryStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-[var(--ink)]">{value}</p>
    </div>
  );
}

interface SbomScanDetailProps {
  scanId: string;
}

/** Dedicated, self-contained detail view for scan_type=sbom — mirrors
 * `ScaScanDetail.tsx`'s polling/status structure but renders a component
 * inventory (with license/cost classification) instead of vulnerability
 * findings. Export reuses the same PDF/Excel `ScanExportButtons` as SAST/SCA
 * — the backend's `/export.pdf` and `/export.xlsx` endpoints render a
 * dedicated component-inventory layout for scan_type=sbom (see
 * `scan_export.py`); there is no separate CycloneDX/SPDX download surface. */
export default function SbomScanDetail({ scanId }: SbomScanDetailProps) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [scanRecord, setScanRecord] = useState<Scan | null>(null);
  const [discovery, setDiscovery] = useState<SbomDiscovery | null>(null);
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
        api.scans.list(pid, "sbom").catch(() => []),
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
        setDiscovery((data.discovery as SbomDiscovery | null) ?? null);
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
          <Link href="/sbom" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
            ← Back to SBOM
          </Link>
        </div>
      </div>
    );
  }

  if (!status) {
    return <p className="px-12 py-10 text-sm text-[var(--muted)]">Loading scan…</p>;
  }

  const terminal = isTerminalStatus(status.status);
  const canExport = terminal && Boolean(discovery && discovery.component_summary.total_components > 0);
  const licenseSummary = discovery?.component_summary.license_summary ?? null;
  const components: SbomComponent[] = discovery?.components ?? [];

  return (
    <div className="h-full min-h-0 overflow-auto bg-white px-6 py-6">
      {dialog}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link
            href="/sbom"
            className="shrink-0 text-sm font-medium text-[var(--accent)] hover:underline"
          >
            ← SBOM
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
            {status.status === "queued"
              ? "Queued…"
              : "Scanning dependency manifests and classifying licenses…"}{" "}
            ({status.progress}%)
          </p>
          <button
            type="button"
            disabled={stopping}
            onClick={stopScan}
            className="rounded-md border border-blue-300 bg-white px-3 py-1 text-xs font-medium text-blue-800 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {stopping ? "Stopping…" : "Stop scan"}
          </button>
        </div>
      )}

      {discovery && (
        <div className="mt-6">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            Component inventory
          </h2>
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <SummaryStat label="Components" value={discovery.component_summary.total_components} />
            <SummaryStat label="Ecosystems" value={discovery.component_summary.ecosystems.join(", ") || "—"} />
            <SummaryStat label="Manifests" value={discovery.component_summary.manifests_parsed.length} />
            <SummaryStat
              label="Licenses resolved"
              value={
                discovery.component_summary.total_components -
                (licenseSummary?.unknown ?? 0)
              }
            />
          </div>
          {licenseSummary && (
            <div className="mt-3 flex flex-wrap gap-2">
              {COST_ORDER.filter((level) => (licenseSummary[level] ?? 0) > 0).map((level) => (
                <span
                  key={level}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${COST_STYLES[level]}`}
                >
                  {licenseSummary[level]} {COST_LABELS[level]}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="mt-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          Components ({components.length})
        </h2>
        {components.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--muted)]">
            {terminal ? "No components found in declared manifests." : "Scanning…"}
          </p>
        ) : (
          <table className="mt-4 w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                <th className="py-2 font-medium">#</th>
                <th className="py-2 font-medium">Component Name</th>
                <th className="py-2 font-medium">Version</th>
                <th className="py-2 font-medium">Supplier</th>
                <th className="py-2 font-medium">Type</th>
                <th className="py-2 font-medium">License</th>
                <th className="py-2 font-medium">Cost</th>
                <th className="py-2 font-medium">Dependency Relationship</th>
              </tr>
            </thead>
            <tbody>
              {components.map((component, idx) => (
                <tr key={component["bom-ref"]} className="border-b border-slate-100 align-top">
                  <td className="py-3 text-[var(--muted)]">{idx + 1}</td>
                  <td className="py-3 text-[var(--ink)]">
                    <div className="font-medium">
                      {component.group ? `${component.group}:${component.name}` : component.name}
                    </div>
                  </td>
                  <td className="py-3 text-[var(--muted)]">{component.version ?? "—"}</td>
                  <td className="py-3 text-[var(--muted)]">{component.vendor ?? "Unknown"}</td>
                  <td className="py-3">
                    <TypeBadge type={component.origin_type || "Open Source"} />
                  </td>
                  <td className="py-3 text-[var(--muted)]">
                    {component.licenses[0]?.spdx_id ?? "Unknown"}
                  </td>
                  <td className="py-3">
                    <CostBadge classification={component.cost_classification} />
                  </td>
                  <td className="py-3 text-[var(--muted)]">
                    {component.dependency_relationship || "Direct"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
