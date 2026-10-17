"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import DeleteProjectModal from "@/components/DeleteProjectModal";
import PageContainer from "@/components/PageContainer";
import ProjectForm from "@/components/ProjectForm";
import { ApiError, api } from "@/lib/api";
import type { Project, ProjectCreateInput, Scan } from "@/lib/types";
import { useCan } from "@/components/auth/AuthProvider";

const SCAN_STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  success: "Success",
  failed: "Failed",
};

function formatDate(value: string): string {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export default function ProjectDetailPage() {
  const can = useCan();
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;

  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setLoadError(null);
      try {
        const proj = await api.projects.get(id);
        const scanList = await api.scans.list(id).catch(() => []);
        if (active) {
          setProject(proj);
          setScans(scanList);
        }
      } catch (err) {
        if (active) {
          setLoadError(err instanceof ApiError ? err.message : "Failed to load project.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, [id]);

  async function handleSubmit(input: ProjectCreateInput) {
    const updated = await api.projects.update(id, input);
    setProject(updated);
    setSavedAt(Date.now());
  }

  if (loading) {
    return (
      <PageContainer>
        <p className="text-sm text-[var(--muted)]">Loading project…</p>
      </PageContainer>
    );
  }

  if (loadError || !project) {
    return (
      <PageContainer>
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {loadError ?? "Project not found."}
        </div>
      </PageContainer>
    );
  }

  return (
    <PageContainer>
      <div className="max-w-3xl">
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <h1 className="font-display text-3xl text-[var(--ink)]">Edit project</h1>
            <p className="mt-1 text-sm text-[var(--muted)]">
              {project.name}
              {" · LLM: "}
              {project.llm_provider === "ollama"
                ? `${project.llm_model || "Ollama"} (Ollama)`
                : project.llm_model && /haiku/i.test(project.llm_model)
                  ? "Claude Haiku (Bedrock)"
                  : project.llm_model && /sonnet/i.test(project.llm_model)
                    ? "Claude Sonnet (Bedrock)"
                    : project.llm_model
                    ? `${project.llm_model} (Bedrock)`
                    : "Claude Haiku (Bedrock)"}
            </p>
            <p className="mt-1 text-sm text-[var(--muted)]">{project.default_git_url}</p>
            {project.monorepo_path && (
              <p className="mt-1 text-sm text-[var(--muted)]">Path: {project.monorepo_path}</p>
            )}
          </div>
          <div className="flex shrink-0 flex-col gap-2">
            {can("scans.create") && (
              <Link
                href={`/scans/new?project_id=${project.id}`}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                New Scan
              </Link>
            )}
            {can("projects.manage") && (
              <Link
                href={`/projects/${project.id}/settings`}
                className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
              >
                Settings
              </Link>
            )}
            {can("projects.manage") && (
              <button
                type="button"
                onClick={() => setShowDeleteModal(true)}
                className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100"
              >
                Delete project
              </button>
            )}
          </div>
        </div>

        {savedAt && (
          <div className="mt-6 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
            Changes saved.
          </div>
        )}

        <section className="mt-10">
          <ProjectForm mode="edit" initial={project} onSubmit={handleSubmit} />
        </section>

        <section className="mt-14 border-t border-slate-200 pt-8">
          <h2 className="font-display text-xl text-[var(--ink)]">Recent scans</h2>
          {scans.length === 0 ? (
            <p className="mt-3 text-sm text-[var(--muted)]">No scans yet for this project.</p>
          ) : (
            <table className="mt-4 w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                  <th className="py-2 font-medium">Version</th>
                  <th className="py-2 font-medium">Branch</th>
                  <th className="py-2 font-medium">Status</th>
                  <th className="py-2 font-medium">Started</th>
                  <th className="py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-100">
                    <td className="py-3 text-[var(--muted)]">v{scan.version}</td>
                    <td className="py-3 text-[var(--ink)]">{scan.branch}</td>
                    <td className="py-3 text-[var(--muted)]">
                      {SCAN_STATUS_LABELS[scan.status] ?? scan.status}
                    </td>
                    <td className="py-3 text-[var(--muted)]">{formatDate(scan.created_at)}</td>
                    <td className="py-3 text-right">
                      <Link href={`/scans/${scan.id}`} className="font-medium text-[var(--accent)]">
                        View →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      {showDeleteModal && (
        <DeleteProjectModal
          project={project}
          scanCount={scans.length}
          onClose={() => setShowDeleteModal(false)}
          onDeleted={() => router.push("/projects")}
        />
      )}
    </PageContainer>
  );
}
