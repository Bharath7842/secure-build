"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import PageContainer from "@/components/PageContainer";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import { claudeModelName } from "@/lib/formatUsage";
import type { Scan } from "@/lib/types";
import { useAuth, useCan } from "@/components/auth/AuthProvider";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import { canStopScan, startedByLabel } from "@/lib/access";

function formatDate(value: string): string {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function llmLabel(scan: Scan): string {
  // Only use the per-scan snapshot — never the project's *current* LLM,
  // otherwise every historical row incorrectly shows the latest setting.
  const provider = scan.llm_provider;
  const model = scan.llm_model;
  if (!provider && !model) return "None";
  if (provider === "ollama") {
    return model ? `${model} (Ollama)` : "Ollama";
  }
  if (provider === "claude_cli") {
    return claudeModelName(model);
  }
  if (provider === "bedrock") {
    if (model && /haiku/i.test(model)) return "Claude Haiku (Bedrock)";
    if (model && /sonnet/i.test(model)) return "Claude Sonnet (Bedrock)";
    return model ? `${model} (Bedrock)` : "Bedrock";
  }
  if (provider) {
    return model ? `${provider}/${model}` : provider;
  }
  return model ?? "—";
}

export default function ScanHistoryPage() {
  const can = useCan();
  const { activeProject, loading: projectLoading } = useActiveProject();
  const activeProjectId = activeProject?.id;
  const me = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const projects = useMemo(() => (activeProject ? [activeProject] : []), [activeProject]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [selectedScanIds, setSelectedScanIds] = useState<Set<string>>(new Set());
  /** "" = everyone. Only offered to people who can see other users' scans. */
  const [startedBy, setStartedBy] = useState("");
  const seesAll = can("scans.view_all");
  const [deleting, setDeleting] = useState(false);
  const [stopping, setStopping] = useState<string | null>(null);
  const { confirm, dialog } = useConfirmDialog();

  useEffect(() => {
    let active = true;

    async function load() {
      if (!activeProjectId) {
        setScans([]);
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const scanList = await api.scans.list(activeProjectId, "sast");
        if (active) setScans(scanList);
      } catch (err) {
        if (active) {
          setError(err instanceof ApiError ? err.message : "Failed to load scan history.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, [activeProjectId]);

  const projectNames = useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects]
  );

  // Everyone who started one of the loaded scans, for the "Started by" filter.
  const starters = useMemo(() => {
    const labels = new Set(scans.map((scan) => startedByLabel(scan, me)));
    return [...labels].sort((a, b) => (a === "You" ? -1 : b === "You" ? 1 : a.localeCompare(b)));
  }, [scans, me]);

  const filteredScans = useMemo(() => {
    const list = scans.filter(
      (scan) =>
                (!startedBy || startedByLabel(scan, me) === startedBy),
    );
    return [...list].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }, [scans, startedBy, me]);

  const allFilteredSelected =
    filteredScans.length > 0 && filteredScans.every((scan) => selectedScanIds.has(scan.id));

  function toggleScan(scanId: string) {
    setSelectedScanIds((prev) => {
      const next = new Set(prev);
      if (next.has(scanId)) next.delete(scanId);
      else next.add(scanId);
      return next;
    });
  }

  function toggleSelectAllFiltered() {
    if (allFilteredSelected) {
      setSelectedScanIds(new Set());
      return;
    }
    setSelectedScanIds(new Set(filteredScans.map((scan) => scan.id)));
  }

  async function deleteScans(ids: string[]) {
    if (ids.length === 0) return;
    const label =
      ids.length === 1
        ? "Delete this scan and its findings?"
        : `Delete ${ids.length} scans and their findings?`;
    if (!(await confirm({ message: label, confirmLabel: "Delete" }))) return;

    setDeleting(true);
    setActionError(null);
    const failed: string[] = [];
    for (const id of ids) {
      try {
        await api.scans.delete(id);
      } catch (err) {
        failed.push(err instanceof ApiError ? err.message : id);
      }
    }

    try {
      setScans(await api.scans.list(activeProjectId, "sast"));
    } catch {
      setScans((prev) => prev.filter((scan) => !ids.includes(scan.id)));
    }
    setSelectedScanIds(new Set());
    if (failed.length > 0) {
      setActionError(`Could not delete ${failed.length} scan(s): ${failed[0]}`);
    }
    setDeleting(false);
  }

  async function stopScan(scanId: string) {
    if (!(await confirm({ message: "Stop this scan? You can delete it afterward.", confirmLabel: "Stop" })))
      return;
    setStopping(scanId);
    setActionError(null);
    try {
      await api.scans.cancel(scanId);
      setScans(await api.scans.list(activeProjectId, "sast"));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Could not stop scan.");
    } finally {
      setStopping(null);
    }
  }

  return (
    <PageContainer>
      {dialog}
      <div>
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <h1 className="font-display text-3xl text-[var(--ink)]">SAST Scan History</h1>
            {activeProject && (
              <p className="mt-1 text-sm font-medium text-[var(--ink)]">Project: {activeProject.name}</p>
            )}
            <p className="mt-2 text-sm text-[var(--muted)]">
              {seesAll
                ? "Every SAST scan across all projects, and who started it."
                : "SAST scans you started. Only you and admins can see them."}
            </p>
          </div>
          {can("scans.create") && (
            <Link
              href="/scans/new"
              className="shrink-0 rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              New SAST scan
            </Link>
          )}
        </div>

        {error && (
          <div className="mt-8 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}
        {actionError && (
          <div className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {actionError}
          </div>
        )}


        {!projectLoading && !activeProject && (
          <div className="mt-8 rounded-md border border-dashed border-slate-300 bg-white/60 px-6 py-10 text-center">
            <p className="text-sm text-[var(--muted)]">
              Select a project in the sidebar to see its SAST scans.{" "}
              <Link href="/projects" className="font-medium text-[var(--accent)] hover:underline">
                Choose a project
              </Link>
            </p>
          </div>
        )}

        {activeProject && seesAll && starters.length > 1 && (
          <label className="mt-4 flex items-center gap-3 text-sm text-[var(--ink)]">
            <span className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">Started by</span>
            <select
              value={startedBy}
              onChange={(e) => {
                setStartedBy(e.target.value);
                setSelectedScanIds(new Set());
              }}
              className="rounded-md border border-slate-200 bg-white px-2 py-1 text-sm"
            >
              <option value="">Everyone</option>
              {starters.map((label) => (
                <option key={label} value={label}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        )}

        {!activeProject ? null : loading ? (
          <p className="mt-10 text-sm text-[var(--muted)]">Loading scans…</p>
        ) : !error && filteredScans.length === 0 ? (
          <div className="mt-10 rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
            <p className="text-sm text-[var(--muted)]">
              {scans.length > 0
                ? "No scans match these filters."
                : seesAll
                  ? "No scans yet."
                  : "You haven't started any scans yet. Scans you start appear here; only you and admins can see them."}
            </p>
            {scans.length === 0 && can("scans.create") && (
              <Link href="/scans/new" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
                Trigger your first scan →
              </Link>
            )}
          </div>
        ) : filteredScans.length > 0 ? (
          <>
            <div className="mt-6 flex items-center justify-between gap-4">
              <p className="text-sm text-[var(--muted)]">
                Showing {filteredScans.length}
                 scan
                {filteredScans.length === 1 ? "" : "s"}
              </p>
              {can("scans.delete") && (
                <button
                  type="button"
                  disabled={deleting || selectedScanIds.size === 0}
                  onClick={() => deleteScans([...selectedScanIds])}
                  className="rounded-md border border-red-200 bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 transition-opacity hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {deleting ? "Deleting…" : `Delete selected (${selectedScanIds.size})`}
                </button>
              )}
            </div>

            <table className="mt-4 w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                  <th className="w-10 py-2 font-medium">
                    <input
                      type="checkbox"
                      checked={allFilteredSelected}
                      onChange={toggleSelectAllFiltered}
                      aria-label="Select all visible scans"
                      className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
                    />
                  </th>
                  <th className="w-12 py-2 font-medium">#</th>
                  <th className="py-2 font-medium">Project</th>
                  <th className="py-2 font-medium">Scan ID</th>
                  <th className="py-2 font-medium">Version</th>
                  <th className="py-2 font-medium">LLM</th>
                  <th className="py-2 font-medium">Started by</th>
                  <th className="py-2 font-medium">Status</th>
                  <th className="py-2 font-medium">Started</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan, index) => {
                  const isActive = scan.status === "queued" || scan.status === "running";
                  const serial = filteredScans.length - index;
                  return (
                    <tr key={scan.id} className="border-b border-slate-100">
                      <td className="py-3">
                        <input
                          type="checkbox"
                          checked={selectedScanIds.has(scan.id)}
                          onChange={() => toggleScan(scan.id)}
                          disabled={isActive}
                          title={isActive ? "Stop the scan first, then delete" : undefined}
                          aria-label={`Select scan ${scan.id}`}
                          className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30 disabled:opacity-40"
                        />
                      </td>
                      <td className="py-3 text-[var(--muted)]">{serial}</td>
                      <td className="py-3 text-[var(--ink)]">
                        {projectNames.get(scan.project_id) ?? "Unknown project"}
                      </td>
                      <td className="py-3 font-mono text-xs text-[var(--muted)]" title={scan.id}>
                        {scan.id.slice(0, 8)}
                      </td>
                      <td className="py-3 text-[var(--muted)]">v{scan.version}</td>
                      <td className="py-3 text-[var(--muted)]">
                        {llmLabel(scan)}
                      </td>
                      <td className="py-3 text-[var(--muted)]" title={scan.created_by_email ?? undefined}>
                        {startedByLabel(scan, me)}
                      </td>
                      <td className="py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="py-3 text-[var(--muted)]">{formatDate(scan.created_at)}</td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <Link href={`/scans/${scan.id}`} className="font-medium text-[var(--accent)]">
                            View →
                          </Link>
                          {isActive && canStopScan(me, scan) && (
                            <button
                              type="button"
                              disabled={stopping === scan.id}
                              onClick={() => stopScan(scan.id)}
                              title="Stop this scan"
                              className="font-medium text-amber-700 hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:no-underline"
                            >
                              {stopping === scan.id ? "Stopping…" : "Stop"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        ) : null}
      </div>
    </PageContainer>
  );
}
