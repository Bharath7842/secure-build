"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import PageContainer from "@/components/PageContainer";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { useAuth, useCan } from "@/components/auth/AuthProvider";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import { startedByLabel } from "@/lib/access";

function formatDate(value: string): string {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export default function ScaDashboardPage() {
  const can = useCan();
  const { activeProject, loading: projectLoading } = useActiveProject();
  const activeProjectId = activeProject?.id;
  const me = useAuth();
  const seesAll = can("scans.view_all");
  const [scans, setScans] = useState<Scan[]>([]);
  const projects = useMemo(() => (activeProject ? [activeProject] : []), [activeProject]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [deleting, setDeleting] = useState<string | null>(null);
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
        const scanList = await api.scans.list(activeProjectId, "sca");
        if (active) setScans(scanList);
      } catch (err) {
        if (active) {
          setError(err instanceof ApiError ? err.message : "Failed to load SCA scan history.");
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

  const filteredScans = useMemo(() => {
    const list =
      scans;
    return [...list].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }, [scans]);

  async function deleteScan(id: string) {
    if (
      !(await confirm({
        message: "Delete this SCA scan and its findings?",
        confirmLabel: "Delete",
      }))
    )
      return;
    setDeleting(id);
    setActionError(null);
    try {
      await api.scans.delete(id);
      setScans(await api.scans.list(activeProjectId, "sca"));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : "Could not delete scan.");
    } finally {
      setDeleting(null);
    }
  }

  const totalVulnerable = scans.filter((s) => s.status === "success").length;

  return (
    <PageContainer>
      {dialog}
      <div>
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <h1 className="font-display text-3xl text-[var(--ink)]">SCA</h1>
            {activeProject && (
              <p className="mt-1 text-sm font-medium text-[var(--ink)]">Project: {activeProject.name}</p>
            )}
            <p className="mt-2 max-w-2xl text-sm text-[var(--muted)]">
              Software Composition Analysis — inventories every dependency declared in a
              project&apos;s manifests (pom.xml, package.json, requirements.txt, ...) and checks each
              declared version against known vulnerabilities via OSV.dev.
            </p>
          </div>
          {can("scans.create") && (
            <Link
              href="/scans/new?type=sca"
              className="shrink-0 rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              New SCA scan
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
              Select a project in the sidebar to see its SCA scans.{" "}
              <Link href="/projects" className="font-medium text-[var(--accent)] hover:underline">
                Choose a project
              </Link>
            </p>
          </div>
        )}

        {!activeProject ? null : loading ? (
          <p className="mt-10 text-sm text-[var(--muted)]">Loading scans…</p>
        ) : !error && filteredScans.length === 0 ? (
          <div className="mt-10 rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
            <p className="text-sm text-[var(--muted)]">
              {scans.length === 0
                ? seesAll
                  ? "No SCA scans yet."
                  : "You haven't started any SCA scans yet. Only you and admins can see the ones you start."
                : "No SCA scans for the selected projects."}
            </p>
            {scans.length === 0 && projects.length > 0 && can("scans.create") && (
              <Link
                href="/scans/new?type=sca"
                className="mt-2 inline-block text-sm font-medium text-[var(--accent)]"
              >
                Trigger your first SCA scan →
              </Link>
            )}
          </div>
        ) : (
          <>
            <p className="mt-6 text-sm text-[var(--muted)]">
              Showing {filteredScans.length}
               scan
              {filteredScans.length === 1 ? "" : "s"}
              {totalVulnerable > 0 ? ` · ${totalVulnerable} completed` : ""}
            </p>

            <table className="mt-4 w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                  <th className="w-12 py-2 font-medium">#</th>
                  <th className="py-2 font-medium">Project</th>
                  {seesAll && <th className="py-2 font-medium">Started by</th>}
                  <th className="py-2 font-medium">Scan ID</th>
                  <th className="py-2 font-medium">Version</th>
                  <th className="py-2 font-medium">Branch</th>
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
                      <td className="py-3 text-[var(--muted)]">{serial}</td>
                      <td className="py-3 text-[var(--ink)]">
                        {projectNames.get(scan.project_id) ?? "Unknown project"}
                      </td>
                      {seesAll && (
                        <td className="py-3 text-[var(--muted)]" title={scan.created_by_email ?? undefined}>
                          {startedByLabel(scan, me)}
                        </td>
                      )}
                      <td className="py-3 font-mono text-xs text-[var(--muted)]" title={scan.id}>
                        {scan.id.slice(0, 8)}
                      </td>
                      <td className="py-3 text-[var(--muted)]">v{scan.version}</td>
                      <td className="py-3 text-[var(--muted)]">{scan.branch}</td>
                      <td className="py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="py-3 text-[var(--muted)]">{formatDate(scan.created_at)}</td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <Link href={`/scans/${scan.id}`} className="font-medium text-[var(--accent)]">
                            View →
                          </Link>
                          {can("scans.delete") && (
                            <button
                              type="button"
                              disabled={deleting === scan.id || isActive}
                              onClick={() => deleteScan(scan.id)}
                              title={isActive ? "Stop the scan first, then delete" : "Delete scan"}
                              className="font-medium text-red-600 hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:no-underline"
                            >
                              {deleting === scan.id ? "Deleting…" : "Delete"}
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
        )}
      </div>
    </PageContainer>
  );
}
