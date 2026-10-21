"use client";

import { useEffect, useState, type FormEvent } from "react";

import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import { llmPresetForProviderModel, type LlmPresetId } from "@/lib/llmPresets";
import type { Project, ScanCreateInput } from "@/lib/types";
import { useModelCatalog } from "@/lib/useModelCatalog";

interface ScanFormProps {
  /** The active project (chosen in the sidebar). */
  project: Project;
  /** "sast" (default) | "sca" | "sbom" — "sca"/"sbom" hide the LLM fields
   * (unused by either deterministic engine) and skip them in the submitted
   * payload. */
  scanType?: "sast" | "sca" | "sbom";
  onSubmit: (input: ScanCreateInput) => Promise<void>;
}

export default function ScanForm({ project, scanType = "sast", onSubmit }: ScanFormProps) {
  const isSca = scanType === "sca";
  const isSbom = scanType === "sbom";
  const isLlmFree = isSca || isSbom;
  const [gitUrl, setGitUrl] = useState("");
  const [repoPath, setRepoPath] = useState("");
  const [branch, setBranch] = useState("");
  // LLM scanning is always on for SAST scans now — no UI toggle. SCA/SBOM
  // never use it regardless (see isLlmFree below).
  const useLlm = true;
  const { presets, sastOptions } = useModelCatalog();
  const [llmPreset, setLlmPreset] = useState<LlmPresetId>("bedrock-haiku");

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedProject = project;
  const selectedProjectId = project.id;

  useEffect(() => {
    setLlmPreset(llmPresetForProviderModel(project.llm_provider, project.llm_model));
    setGitUrl(project.default_git_url || "");
    setRepoPath(project.monorepo_path || "");
    setBranch(project.default_branch || "");
  }, [project]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();

    if (!gitUrl.trim()) {
      setError("Repository URL is required.");
      return;
    }
    if (!branch.trim()) {
      setError("Enter the branch to scan.");
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
      // Always rescan, even when a recent scan of the same commit exists.
      force: true,
      scan_type: scanType,
      use_llm: isLlmFree ? false : useLlm,
      metadata: {
        source: "app",
      },
    };

    if (!isLlmFree && useLlm) {
      const preset = presets[llmPreset];
      payload.llm_provider = preset.provider;
      // An OpenAI-compatible server serves whatever model id the project
      // configured; the preset's model is only a placeholder.
      payload.llm_model =
        preset.provider === "openai_compat" && selectedProject?.llm_provider === "openai_compat"
          ? selectedProject.llm_model
          : preset.model;
      // The cost-cutoff fallback comes from the project (default "none":
      // stop LLM work rather than silently switching to a local Ollama).
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
      <div>
        <p className="block text-sm font-medium text-[var(--ink)]">Project</p>
        <p className="mt-1 font-display text-2xl text-[var(--ink)]">{project.name}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">Change the project from the selector in the sidebar.</p>
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
              {sastOptions(llmPreset).map(([id, preset]) => (
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
          Branch to scan *
        </label>
        <input
          id="scan-branch"
          value={branch}
          onChange={(event) => setBranch(event.target.value)}
          className={inputClass}
          required
          aria-required="true"
        />
      </div>

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
