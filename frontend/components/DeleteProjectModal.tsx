"use client";

import { useState } from "react";

import { ApiError, api } from "@/lib/api";
import type { Project, ProjectDeleteResult } from "@/lib/types";

type Phase = "confirm" | "deleting" | "done" | "error";

interface DeleteProjectModalProps {
  project: Project;
  /** Known scan count, when the caller already has it loaded (project detail page). */
  scanCount?: number;
  onClose: () => void;
  onDeleted: (result: ProjectDeleteResult) => void;
}

const STEP_DELAY_MS = 450;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function providerLabel(project: Project): string {
  return project.git_provider === "gitlab" ? "GitLab" : "GitHub";
}

export default function DeleteProjectModal({
  project,
  scanCount,
  onClose,
  onDeleted,
}: DeleteProjectModalProps) {
  const [phase, setPhase] = useState<Phase>("confirm");
  const [confirmText, setConfirmText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProjectDeleteResult | null>(null);
  const [completedSteps, setCompletedSteps] = useState(0);

  const nameMatches = confirmText.trim() === project.name;

  const steps = [
    "Stopping tracked scans and deleting scan history",
    "Removing the local repository workspace",
    ...(project.git_connected ? [`Disconnecting ${providerLabel(project)}`] : []),
    "Deleting the project",
  ];

  async function handleDelete() {
    if (!nameMatches || phase === "deleting") return;
    setError(null);
    setPhase("deleting");
    setCompletedSteps(0);
    try {
      const [res] = await Promise.all([
        api.projects.delete(project.id),
        (async () => {
          for (let i = 0; i < steps.length - 1; i++) {
            await sleep(STEP_DELAY_MS);
            setCompletedSteps((n) => n + 1);
          }
        })(),
      ]);
      setCompletedSteps(steps.length);
      await sleep(200);
      setResult(res);
      setPhase("done");
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to delete the project. Please try again."
      );
      setPhase("error");
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-project-title"
    >
      <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
        {phase === "confirm" && (
          <>
            <div className="flex items-start gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-red-100 text-red-600">
                <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5">
                  <path
                    fillRule="evenodd"
                    d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 6a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 6Zm0 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
                    clipRule="evenodd"
                  />
                </svg>
              </span>
              <div>
                <h2 id="delete-project-title" className="font-display text-lg text-[var(--ink)]">
                  Delete project
                </h2>
                <p className="mt-1 text-sm text-[var(--muted)]">
                  This permanently deletes <strong className="text-[var(--ink)]">{project.name}</strong>,{" "}
                  {typeof scanCount === "number"
                    ? `its ${scanCount} scan${scanCount === 1 ? "" : "s"}`
                    : "all of its scans"}
                  , and its local repository workspace
                  {project.git_connected ? `, and disconnects it from ${providerLabel(project)}` : ""}.
                  This cannot be undone.
                </p>
              </div>
            </div>

            <div className="mt-5">
              <label htmlFor="delete-confirm-name" className="text-sm font-medium text-[var(--ink)]">
                Type <span className="font-mono text-[var(--muted)]">{project.name}</span> to confirm
              </label>
              <input
                id="delete-confirm-name"
                autoFocus
                autoComplete="off"
                value={confirmText}
                onChange={(event) => setConfirmText(event.target.value)}
                className="mt-2 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-[var(--accent)] focus:outline-none"
                placeholder={project.name}
              />
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={!nameMatches}
                className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Delete permanently
              </button>
            </div>
          </>
        )}

        {phase === "deleting" && (
          <>
            <h2 className="font-display text-lg text-[var(--ink)]">Deleting {project.name}…</h2>
            <ul className="mt-5 space-y-3">
              {steps.map((step, i) => (
                <li key={step} className="flex items-center gap-3 text-sm">
                  <span
                    className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] ${
                      i < completedSteps
                        ? "bg-emerald-500 text-white"
                        : "border border-slate-300 text-transparent"
                    }`}
                  >
                    {i < completedSteps ? "✓" : "•"}
                  </span>
                  <span className={i < completedSteps ? "text-[var(--ink)]" : "text-[var(--muted)]"}>
                    {step}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}

        {phase === "done" && result && (
          <>
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-emerald-100 text-emerald-600">
                <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5">
                  <path
                    fillRule="evenodd"
                    d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                    clipRule="evenodd"
                  />
                </svg>
              </span>
              <h2 className="font-display text-lg text-[var(--ink)]">Project deleted</h2>
            </div>
            <ul className="mt-4 space-y-1 text-sm text-[var(--muted)]">
              <li>
                • {result.scans_deleted} scan{result.scans_deleted === 1 ? "" : "s"} removed
              </li>
              <li>• Repository workspace {result.workspace_removed ? "removed" : "was already clean"}</li>
              {result.git_disconnected && <li>• Disconnected from {providerLabel(project)}</li>}
            </ul>
            <div className="mt-6 flex justify-end">
              <button
                type="button"
                onClick={() => onDeleted(result)}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Done
              </button>
            </div>
          </>
        )}

        {phase === "error" && (
          <>
            <h2 className="font-display text-lg text-[var(--ink)]">Couldn&apos;t delete project</h2>
            <div className="mt-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {error}
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
              >
                Close
              </button>
              <button
                type="button"
                onClick={() => setPhase("confirm")}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Try again
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
