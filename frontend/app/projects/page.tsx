"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import DeleteProjectModal from "@/components/DeleteProjectModal";
import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";
import type { Project } from "@/lib/types";
import { useCan } from "@/components/auth/AuthProvider";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";

export default function ProjectsPage() {
  const can = useCan();
  const { activeProject, setActiveProjectId, refresh } = useActiveProject();
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);
  const [justCreated, setJustCreated] = useState(false);

  // Set by the create page after a successful save; the flag is dropped from
  // the URL so a refresh doesn't show the banner again.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("created") === "1") {
      setJustCreated(true);
      window.history.replaceState(null, "", "/projects");
    }
  }, []);

  // Nothing of the user's yet: the first thing to do is create a project.
  useEffect(() => {
    if (!loading && projects.length === 0 && can("projects.manage")) router.replace("/projects/new");
  }, [loading, projects.length, can, router]);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await api.projects.list();
        if (active) setProjects(data);
      } catch (err) {
        if (active) {
          setError(err instanceof ApiError ? err.message : "Failed to load projects.");
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, []);

  return (
    <PageContainer>
      <div>
        <div className="flex items-baseline justify-between">
          <div>
            <h1 className="font-display text-3xl text-[var(--ink)]">Projects</h1>
            <p className="mt-2 text-sm text-[var(--muted)]">
              Repositories configured for automated security scanning.
            </p>
          </div>
          {can("projects.manage") && (
            <Link
              href="/projects/new"
              className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
            >
              New project
            </Link>
          )}
        </div>

        {justCreated && (
          <div className="mt-6 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
            Project created successfully.
          </div>
        )}

        {error && (
          <div className="mt-8 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {loading ? (
          <p className="mt-10 text-sm text-[var(--muted)]">Loading projects…</p>
        ) : !error && projects.length === 0 ? (
          <div className="mt-10 rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
            <p className="text-sm text-[var(--muted)]">No projects yet.</p>
            {can("projects.manage") && (
              <Link href="/projects/new" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
                Create your first project →
              </Link>
            )}
          </div>
        ) : projects.length > 0 ? (
          <table className="mt-10 w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                <th className="py-2 font-medium">Name</th>
                <th className="py-2 font-medium">Branch</th>
                <th className="py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id} className="border-b border-slate-100">
                  <td className="py-3">
                    <Link
                      href={`/projects/${project.id}`}
                      className="font-medium text-[var(--ink)] hover:text-[var(--accent)]"
                    >
                      {project.name}
                    </Link>
                  </td>
                  <td className="py-3 text-[var(--muted)]">{project.default_branch || "—"}</td>
                  <td className="py-3 text-right">
                    <div className="flex items-center justify-end gap-4">
                      {can("scans.create") && (
                        <button
                          type="button"
                          onClick={() => {
                            // The scan page scans whichever project is active.
                            setActiveProjectId(project.id);
                            router.push("/scans/new");
                          }}
                          className="font-medium text-[var(--accent)] hover:underline"
                        >
                          New SAST scan
                        </button>
                      )}
                      <Link
                        href={`/projects/${project.id}`}
                        className="font-medium text-[var(--ink)] hover:text-[var(--accent)]"
                      >
                        Edit
                      </Link>
                      {activeProject?.id === project.id ? (
                        <span className="font-medium text-[var(--muted)]">Active</span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setActiveProjectId(project.id)}
                          className="font-medium text-[var(--accent)]"
                        >
                          Use this project
                        </button>
                      )}
                      {can("projects.manage") && (
                        <button
                          type="button"
                          onClick={() => setDeleteTarget(project)}
                          className="font-medium text-red-600 hover:text-red-700"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      {deleteTarget && (
        <DeleteProjectModal
          project={deleteTarget}
          onClose={() => setDeleteTarget(null)}
          onDeleted={() => {
            setProjects((prev) => prev.filter((p) => p.id !== deleteTarget.id));
            setDeleteTarget(null);
            void refresh();
          }}
        />
      )}
    </PageContainer>
  );
}
