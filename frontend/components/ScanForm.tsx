"use client";

import { useEffect, useState, type FormEvent } from "react";

import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import {
  DEFAULT_FALLBACK_PRESET_ID,
  LLM_PRESETS,
  LLM_PRESET_ENTRIES,
  isBedrockPrimaryPreset,
  llmPresetForProviderModel,
  type LlmPresetId,
} from "@/lib/llmPresets";
import type { Project, ScanCreateInput } from "@/lib/types";

interface ScanFormProps {
  projectId?: string;
  /** "sast" (default) | "sca" | "sbom" — "sca"/"sbom" hide the LLM fields
   * (unused by either deterministic engine) and skip them in the submitted
   * payload. */
  scanType?: "sast" | "sca" | "sbom";
  onSubmit: (input: ScanCreateInput) => Promise<void>;
}

export default function ScanForm({ projectId, scanType = "sast", onSubmit }: ScanFormProps) {
  const isSca = scanType === "sca";
  const isSbom = scanType === "sbom";
  const isLlmFree = isSca || isSbom;
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [projectsError, setProjectsError] = useState<string | null>(null);

  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [repoPath, setRepoPath] = useState("");
  const [branch, setBranch] = useState("");
  const [force, setForce] = useState(false);
  // LLM scanning is always on for SAST scans now — no UI toggle. SCA/SBOM
  // never use it regardless (see isLlmFree below).
  const useLlm = true;
  const [llmPreset, setLlmPreset] = useState<LlmPresetId>("bedrock-haiku");
  // Fallback-model choice isn't exposed in the UI — always granite-code:3b.
  const fallbackPreset = DEFAULT_FALLBACK_PRESET_ID;

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedProject = projects.find((p) => p.id === selectedProjectId) ?? null;
  const projectSelectValue = projects.some((p) => p.id === selectedProjectId)
    ? selectedProjectId
    : "";

  useEffect(() => {
    let active = true;

    async function load() {
      setLoadingProjects(true);
      setProjectsError(null);
      try {
        const allProjects = await api.projects.list();
        const data = isSca
          ? allProjects.filter((p) => p.enable_sca)
          : isSbom
            ? allProjects.filter((p) => p.enable_sbom)
            : allProjects;
        if (active) {
          setProjects(data);
          const fromUrl =
            projectId && data.some((p) => p.id === projectId) ? projectId : null;
          setSelectedProjectId((current) => {
            if (current && data.some((p) => p.id === current)) return current;
            return fromUrl ?? data[0]?.id ?? "";
          });
        }
      } catch (err) {
        if (active) {
          setProjectsError(err instanceof ApiError ? err.message : "Failed to load projects.");
        }
      } finally {
        if (active) setLoadingProjects(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, [projectId, isSca, isSbom]);

  useEffect(() => {
    if (!selectedProject) return;
    setLlmPreset(llmPresetForProviderModel(selectedProject.llm_provider, selectedProject.llm_model));
    setGitUrl(selectedProject.default_git_url || "");
    setRepoPath(selectedProject.monorepo_path || "");
    setBranch((current) => current || selectedProject.default_branch || "");
  }, [selectedProject]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();

    if (!selectedProjectId) {
      setError("Select a project to scan.");
      return;
    }
    if (!gitUrl.trim()) {
      setError("Repository URL is required.");
      return;
    }

    const payload: ScanCreateInput = {
      project_id: selectedProjectId,
      git_url: gitUrl.trim(),
      repo_path: repoPath.trim() || null,
      branch: branch.trim() || null,
      // Always blank from the UI — the backend auto-resolves the branch's
      // latest commit on git.
      commit_sha: null,
      force,
      scan_type: scanType,
      use_llm: isLlmFree ? false : useLlm,
      metadata: {
        source: "app",
      },
    };

    if (!isLlmFree && useLlm) {
      const preset = LLM_PRESETS[llmPreset];
      payload.llm_provider = preset.provider;
      payload.llm_model = preset.model;
      if (isBedrockPrimaryPreset(llmPreset)) {
        const fallback = LLM_PRESETS[fallbackPreset];
        payload.fallback_llm_provider = fallback.provider;
        payload.fallback_llm_model = fallback.model;
      }
    }

    setError(null);
    setSubmitting(true);
    try {
      await onSubmit(payload);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}
      {projectsError && (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {projectsError}
        </div>
      )}

      <div>
        <label htmlFor="scan-project" className="block text-sm font-medium text-[var(--ink)]">
          Project
        </label>
        <select
          id="scan-project"
          value={projectSelectValue}
          onChange={(event) => setSelectedProjectId(event.target.value)}
          className={selectClass}
          disabled={loadingProjects || projects.length === 0}
          required
        >
          <option value="" disabled>
            {loadingProjects ? "Loading projects…" : "Select a project"}
          </option>
          {projects.map((project) => (
            <option key={project.id} value={project.id}>
              {project.name}
            </option>
          ))}
        </select>
        {!loadingProjects && projects.length === 0 && !projectsError && (
          <p className="mt-1 text-xs text-[var(--muted)]">
            {isSca
              ? "No projects have SCA enabled yet. Enable it in a project's settings first."
              : isSbom
                ? "No projects have SBOM enabled yet. Enable it in a project's settings first."
                : "No projects yet. Create one first."}
          </p>
        )}
      </div>

      <div>
        <label htmlFor="scan-git-url" className="block text-sm font-medium text-[var(--ink)]">
          Repository URL
        </label>
        <input
          id="scan-git-url"
          value={gitUrl}
          onChange={(event) => setGitUrl(event.target.value)}
          className={inputClass}
          placeholder="https://github.com/org/repo.git"
          required
        />
        <p className="mt-1 text-xs text-[var(--muted)]">
          Defaults to the project&apos;s Git URL. Override for a one-off scan target.
        </p>
      </div>

      <div>
        <label htmlFor="scan-repo-path" className="block text-sm font-medium text-[var(--ink)]">
          Repo path
        </label>
        <input
          id="scan-repo-path"
          value={repoPath}
          onChange={(event) => setRepoPath(event.target.value)}
          className={inputClass}
          placeholder="apps/api (optional)"
        />
        <p className="mt-1 text-xs text-[var(--muted)]">
          Optional subdirectory inside the repo to scan. Leave blank to scan the full repository.
        </p>
      </div>

      {isSca ? (
        <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-[var(--muted)]">
          SCA scans parse dependency manifests and check each declared version against OSV.dev —
          no LLM is used for this scan type.
        </div>
      ) : isSbom ? (
        <div className="rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-[var(--muted)]">
          SBOM scans parse dependency manifests into a CycloneDX/SPDX component inventory with a
          best-effort license/cost classification — no LLM is used for this scan type.
        </div>
      ) : null}

      {!isLlmFree && useLlm && (
        <>
          <div>
            <label htmlFor="scan-llm" className="block text-sm font-medium text-[var(--ink)]">
              LLM for this scan
            </label>
            <p className="mt-0.5 text-xs text-[var(--muted)]">
              Used for the one-shot tech-stack detection call. Defaults to the project model.
            </p>
            <select
              id="scan-llm"
              value={llmPreset}
              onChange={(event) => setLlmPreset(event.target.value as LlmPresetId)}
              className={selectClass}
            >
              {LLM_PRESET_ENTRIES.map(([id, preset]) => (
                <option key={id} value={id}>
                  {preset.label}
                </option>
              ))}
            </select>
          </div>
        </>
      )}

      <div>
        <label htmlFor="scan-branch" className="block text-sm font-medium text-[var(--ink)]">
          Branch
        </label>
        <input
          id="scan-branch"
          value={branch}
          onChange={(event) => setBranch(event.target.value)}
          className={inputClass}
          placeholder="main"
        />
      </div>

      <label className="flex items-center gap-2 text-sm text-[var(--ink)]">
        <input
          type="checkbox"
          checked={force}
          onChange={(event) => setForce(event.target.checked)}
          className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
        />
        Force scan even if a recent scan already exists
      </label>

      <div className="flex items-center gap-4 border-t border-slate-200 pt-6">
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting
            ? "Starting…"
            : isSca
              ? "Start SCA scan"
              : isSbom
                ? "Start SBOM scan"
                : "Start scan"}
        </button>
      </div>
    </form>
  );
}
