"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import {
  LLM_PRESETS,
  LLM_PRESET_ENTRIES,
  isBedrockPrimaryPreset,
  llmPresetForProviderModel,
  type LlmPresetId,
} from "@/lib/llmPresets";
import type { GitRepo, Project, ProjectCreateInput } from "@/lib/types";

interface ProjectFormProps {
  mode: "create" | "edit";
  initial?: Project;
  onSubmit: (input: ProjectCreateInput) => Promise<void>;
}

const GIT_PROVIDER_LABELS: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab",
};

// sessionStorage key for the in-progress "New Project" form, saved right
// before "Connect GitHub"/"Connect GitLab" navigates the browser away to the
// provider's authorize page, and restored when it comes back.
const NEW_PROJECT_DRAFT_KEY = "new-project-draft";

interface NewProjectDraft {
  name: string;
  description: string;
  defaultGitUrl: string;
  defaultBranch: string;
  monorepoPath: string;
  llmChoice: LlmPresetId;
  fallbackChoice: LlmPresetId;
}

function FormSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <fieldset className="border-t border-slate-200 pt-6 first:border-t-0 first:pt-0">
      <legend className="mb-3 block w-full">
        <span className="font-display text-lg text-[var(--ink)]">{title}</span>
        {description && <p className="mt-1 text-sm text-[var(--muted)]">{description}</p>}
      </legend>
      <div className="space-y-3">{children}</div>
    </fieldset>
  );
}

function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="block text-sm font-medium text-[var(--ink)]">
        {label}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-[var(--muted)]">{hint}</p>}
    </div>
  );
}

function GitHubLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function GitLabLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden="true">
      <path d="M23.6004 9.5927l-.0318-.0817-3.3243-8.4664a.851.851 0 00-.3374-.4046.8748.8748 0 00-1.021.0561.8748.8748 0 00-.2839.4046l-2.2258 6.8102H7.5769L5.351 1.19631a.8748.8748 0 00-.2846-.404.8749.8749 0 00-1.021-.0561.8749.8749 0 00-.3374.404L.3844 9.5107l-.032.082a6.0657 6.0657 0 002.0138 7.0135l.011.0083.0312.0209 5.1618 3.869 2.5599 1.9354 1.5622 1.1793a1.0273 1.0273 0 001.2416 0l1.5622-1.1793 2.5599-1.9354 5.1926-3.8919.0122-.0093a6.0657 6.0657 0 002.0009-7.0009z" />
    </svg>
  );
}

function ProviderLogo({ provider, className }: { provider: string | null; className?: string }) {
  return provider === "gitlab" ? (
    <GitLabLogo className={className} />
  ) : (
    <GitHubLogo className={className} />
  );
}

export default function ProjectForm({ mode, initial, onSubmit }: ProjectFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [defaultGitUrl, setDefaultGitUrl] = useState(initial?.default_git_url ?? "");
  const [defaultBranch, setDefaultBranch] = useState(initial?.default_branch ?? "main");
  const [monorepoPath, setMonorepoPath] = useState(initial?.monorepo_path ?? "");
  // SAST + Secrets are always on; SCA/SBOM are user-toggleable per project.
  const enableSast = true;
  const enableSecrets = true;
  const [enableSca, setEnableSca] = useState(initial?.enable_sca ?? true);
  const [enableSbom, setEnableSbom] = useState(initial?.enable_sbom ?? true);
  const [llmChoice, setLlmChoice] = useState<LlmPresetId>(
    llmPresetForProviderModel(initial?.llm_provider, initial?.llm_model),
  );
  const [fallbackChoice, setFallbackChoice] = useState<LlmPresetId>(
    llmPresetForProviderModel(
      initial?.fallback_llm_provider || "ollama",
      initial?.fallback_llm_model || "granite-code:3b",
    ),
  );

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const searchParams = useSearchParams();
  // Edit mode: connection state lives on `initial` (a real project row).
  // Create mode: no project row exists yet, so a completed OAuth round-trip
  // comes back as a `git_connection_id`/`git_provider` query pair (see
  // app/git-auth/[provider]/callback/page.tsx) that gets submitted with the
  // rest of the form instead of being attached immediately.
  const [gitProvider, setGitProvider] = useState<string | null>(initial?.git_provider ?? null);
  const [gitConnected, setGitConnected] = useState(initial?.git_connected ?? false);
  const [pendingConnectionId, setPendingConnectionId] = useState<string | null>(null);
  const [connectingProvider, setConnectingProvider] = useState<"github" | "gitlab" | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const [gitError, setGitError] = useState<string | null>(null);
  const [repos, setRepos] = useState<GitRepo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState("");

  useEffect(() => {
    if (mode !== "create") return;
    const connectionId = searchParams.get("git_connection_id");
    const provider = searchParams.get("git_provider");
    if (connectionId && provider) {
      setPendingConnectionId(connectionId);
      setGitProvider(provider);
      setGitConnected(true);

      // Restore whatever the user had typed before "Connect GitHub"/"Connect
      // GitLab" navigated the browser away to the provider and back.
      try {
        const raw = sessionStorage.getItem(NEW_PROJECT_DRAFT_KEY);
        if (raw) {
          const draft = JSON.parse(raw) as Partial<NewProjectDraft>;
          if (draft.name !== undefined) setName(draft.name);
          if (draft.description !== undefined) setDescription(draft.description);
          if (draft.defaultGitUrl !== undefined) setDefaultGitUrl(draft.defaultGitUrl);
          if (draft.defaultBranch !== undefined) setDefaultBranch(draft.defaultBranch);
          if (draft.monorepoPath !== undefined) setMonorepoPath(draft.monorepoPath);
          if (draft.llmChoice !== undefined) setLlmChoice(draft.llmChoice);
          if (draft.fallbackChoice !== undefined) setFallbackChoice(draft.fallbackChoice);
        }
        sessionStorage.removeItem(NEW_PROJECT_DRAFT_KEY);
      } catch {
        /* sessionStorage unavailable (private mode, etc.) — draft is best-effort */
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  useEffect(() => {
    if (!gitConnected || !gitProvider) {
      setRepos([]);
      return;
    }
    const provider = gitProvider === "gitlab" ? "gitlab" : "github";
    const by =
      mode === "edit" && initial?.id
        ? { projectId: initial.id }
        : pendingConnectionId
          ? { connectionId: pendingConnectionId }
          : null;
    if (!by) return;

    let active = true;
    setReposLoading(true);
    setGitError(null);
    api.gitAuth
      .listRepos(provider, by)
      .then((list) => {
        if (active) setRepos(list);
      })
      .catch((err) => {
        if (active) {
          setGitError(
            err instanceof ApiError ? err.message : `Failed to list ${GIT_PROVIDER_LABELS[provider]} repositories.`
          );
        }
      })
      .finally(() => {
        if (active) setReposLoading(false);
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gitConnected, gitProvider, pendingConnectionId]);

  function handleSelectRepo(cloneUrl: string) {
    setSelectedRepo(cloneUrl);
    if (!cloneUrl) return;
    setDefaultGitUrl(cloneUrl);
    const repo = repos.find((r) => r.clone_url === cloneUrl);
    if (repo?.default_branch) setDefaultBranch(repo.default_branch);
  }

  async function handleConnect(provider: "github" | "gitlab") {
    setGitError(null);
    setConnectingProvider(provider);
    try {
      const { authorize_url } = await api.gitAuth.authorizeUrl(
        provider,
        mode === "edit" ? initial?.id : undefined
      );
      if (mode === "create") {
        try {
          const draft: NewProjectDraft = {
            name,
            description,
            defaultGitUrl,
            defaultBranch,
            monorepoPath,
            llmChoice,
            fallbackChoice,
          };
          sessionStorage.setItem(NEW_PROJECT_DRAFT_KEY, JSON.stringify(draft));
        } catch {
          /* sessionStorage unavailable — connecting still works, just loses the draft */
        }
      }
      window.location.href = authorize_url;
    } catch (err) {
      setGitError(
        err instanceof ApiError ? err.message : `Failed to start ${GIT_PROVIDER_LABELS[provider]} connection.`
      );
      setConnectingProvider(null);
    }
  }

  async function handleDisconnect() {
    setGitError(null);
    if (mode === "edit" && initial?.id) {
      setDisconnecting(true);
      try {
        await api.gitAuth.disconnect(initial.id);
        setGitProvider(null);
        setGitConnected(false);
      } catch (err) {
        setGitError(err instanceof ApiError ? err.message : "Failed to disconnect.");
      } finally {
        setDisconnecting(false);
      }
      return;
    }
    // Create mode: nothing persisted yet — just forget the pending connection.
    setPendingConnectionId(null);
    setGitProvider(null);
    setGitConnected(false);
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();

    if (!name.trim()) {
      setError("Name is required.");
      return;
    }

    // Reference sources (OWASP/NVD Top 10 URLs, etc.) are no longer managed
    // here: omitting these fields lets the backend fill OWASP + NVD Top 10
    // automatically on create, and leaves whatever a project already has
    // untouched on update.
    const payload: ProjectCreateInput = {
      name: name.trim(),
      description: description.trim() || null,
      default_git_url: defaultGitUrl.trim(),
      default_branch: defaultBranch.trim() || "main",
      monorepo_path: monorepoPath.trim() || null,
      enable_sast: enableSast,
      enable_sca: enableSca,
      enable_sbom: enableSbom,
      enable_secrets: enableSecrets,
      scan_mode: "full",
      llm_provider: LLM_PRESETS[llmChoice].provider,
      llm_model: LLM_PRESETS[llmChoice].model,
    };
    if (mode === "create" && pendingConnectionId) {
      payload.git_connection_id = pendingConnectionId;
    }
    if (isBedrockPrimaryPreset(llmChoice)) {
      payload.fallback_llm_provider = LLM_PRESETS[fallbackChoice].provider;
      payload.fallback_llm_model = LLM_PRESETS[fallbackChoice].model;
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

      <FormSection title="Overview" description="What this project is and where it lives.">
        <Field label="Project Name" htmlFor="name">
          <input
            id="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            className={inputClass}
            placeholder="Project Name"
          />
        </Field>
        <Field label="Description" htmlFor="description">
          <textarea
            id="description"
            rows={3}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            className={inputClass}
            placeholder="What this project does and who owns it."
          />
        </Field>
      </FormSection>

      <FormSection
        title="Git provider"
        description="Connect GitHub or GitLab so scans can clone this project's private repository, or paste a Git URL below directly."
      >
        {gitError && (
          <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {gitError}
          </div>
        )}
        {gitConnected ? (
          <div className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${
                    gitProvider === "gitlab" ? "bg-orange-50 text-orange-600" : "bg-slate-900 text-white"
                  }`}
                >
                  <ProviderLogo provider={gitProvider} className="h-5 w-5" />
                </span>
                <div>
                  <p className="text-sm font-medium text-[var(--ink)]">
                    Connected to {GIT_PROVIDER_LABELS[gitProvider ?? ""] ?? gitProvider}
                  </p>
                  {mode === "create" && pendingConnectionId && (
                    <p className="text-xs text-[var(--muted)]">Will be saved when you create this project</p>
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={handleDisconnect}
                disabled={disconnecting}
                className="shrink-0 rounded-md border border-red-200 bg-red-50 px-3 py-1.5 text-sm font-medium text-red-700 transition-opacity hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {disconnecting ? "Disconnecting…" : "Disconnect"}
              </button>
            </div>
            <div className="mt-4 border-t border-slate-100 pt-4">
              <Field
                label="Repository"
                htmlFor="repo-picker"
                hint="Picking a repository here fills in the Git URL (and default branch) below."
              >
                <select
                  id="repo-picker"
                  value={selectedRepo}
                  onChange={(event) => handleSelectRepo(event.target.value)}
                  className={selectClass}
                  disabled={reposLoading || repos.length === 0}
                >
                  <option value="">
                    {reposLoading
                      ? "Loading repositories…"
                      : repos.length === 0
                        ? "No repositories found"
                        : "Select a repository"}
                  </option>
                  {repos.map((repo) => (
                    <option key={repo.clone_url} value={repo.clone_url}>
                      {repo.full_name}
                      {repo.private ? " (private)" : ""}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              onClick={() => handleConnect("github")}
              disabled={connectingProvider !== null}
              className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white px-4 py-3.5 text-left transition-all hover:-translate-y-0.5 hover:border-slate-400 hover:shadow-md disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:translate-y-0 disabled:hover:shadow-none"
            >
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-900 text-white">
                <GitHubLogo className="h-5 w-5" />
              </span>
              <span>
                <span className="block text-sm font-medium text-[var(--ink)]">
                  {connectingProvider === "github" ? "Redirecting…" : "Connect GitHub"}
                </span>
                <span className="block text-xs text-[var(--muted)]">Authorize access to your repositories</span>
              </span>
            </button>
            <button
              type="button"
              onClick={() => handleConnect("gitlab")}
              disabled={connectingProvider !== null}
              className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white px-4 py-3.5 text-left transition-all hover:-translate-y-0.5 hover:border-orange-300 hover:shadow-md disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:translate-y-0 disabled:hover:shadow-none"
            >
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-orange-50 text-orange-600">
                <GitLabLogo className="h-5 w-5" />
              </span>
              <span>
                <span className="block text-sm font-medium text-[var(--ink)]">
                  {connectingProvider === "gitlab" ? "Redirecting…" : "Connect GitLab"}
                </span>
                <span className="block text-xs text-[var(--muted)]">Authorize access to your projects</span>
              </span>
            </button>
          </div>
        )}
      </FormSection>

      <FormSection
        title="Repository"
        description="Default source location used when a SAST/SCA/SBOM scan is triggered. Leave blank for a project used only for DAST scans — those target a URL directly, not a repository."
      >
        <Field label="Git URL" htmlFor="git-url">
          <input
            id="git-url"
            value={defaultGitUrl}
            onChange={(event) => setDefaultGitUrl(event.target.value)}
            className={inputClass}
            placeholder="https://github.com/org/repo.git (optional for DAST-only projects)"
          />
        </Field>
        <Field label="Default branch" htmlFor="branch">
          <input
            id="branch"
            value={defaultBranch}
            onChange={(event) => setDefaultBranch(event.target.value)}
            className={inputClass}
            placeholder="main"
          />
        </Field>
        <Field
          label="Repo path"
          htmlFor="repo-path"
          hint="Optional subdirectory to scan by default (e.g. apps/api). Leave blank for the full repo."
        >
          <input
            id="repo-path"
            value={monorepoPath}
            onChange={(event) => setMonorepoPath(event.target.value)}
            className={inputClass}
            placeholder="apps/api"
          />
        </Field>
      </FormSection>

      <FormSection title="Scan settings" description="LLM model and scan types available for this project.">
        <Field label="LLM model" htmlFor="llm-choice">
          <select
            id="llm-choice"
            value={llmChoice}
            onChange={(event) => setLlmChoice(event.target.value as LlmPresetId)}
            className={selectClass}
          >
            {LLM_PRESET_ENTRIES.map(([id, preset]) => (
              <option key={id} value={id}>
                {preset.label}
              </option>
            ))}
          </select>
        </Field>
        <label className="flex items-center gap-2 text-sm text-[var(--ink)]">
          <input
            type="checkbox"
            checked={enableSca}
            onChange={(event) => setEnableSca(event.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
          />
          Enable SCA (dependency vulnerability) scanning
        </label>
        <label className="flex items-center gap-2 text-sm text-[var(--ink)]">
          <input
            type="checkbox"
            checked={enableSbom}
            onChange={(event) => setEnableSbom(event.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
          />
          Enable SBOM generation
        </label>
      </FormSection>

      <div className="flex items-center gap-4 border-t border-slate-200 pt-6">
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Saving…" : mode === "create" ? "Create project" : "Save changes"}
        </button>
      </div>
    </form>
  );
}
