"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import { LLM_PRESETS, llmPresetForProviderModel, type LlmPresetId } from "@/lib/llmPresets";
import { useModelCatalog } from "@/lib/useModelCatalog";
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
// before "Connect GitLab" navigates the browser away to the
// provider's authorize page, and restored when it comes back.
const NEW_PROJECT_DRAFT_KEY = "new-project-draft";

interface NewProjectDraft {
  name: string;
  description: string;
  defaultGitUrl: string;
  defaultBranch: string;
  monorepoPath: string;
  llmChoice: LlmPresetId;
  // Never the API key: a secret has no business in sessionStorage.
  llmModel?: string;
  llmBaseUrl?: string;
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

function GitLabLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="currentColor" aria-hidden="true">
      <path d="M23.6004 9.5927l-.0318-.0817-3.3243-8.4664a.851.851 0 00-.3374-.4046.8748.8748 0 00-1.021.0561.8748.8748 0 00-.2839.4046l-2.2258 6.8102H7.5769L5.351 1.19631a.8748.8748 0 00-.2846-.404.8749.8749 0 00-1.021-.0561.8749.8749 0 00-.3374.404L.3844 9.5107l-.032.082a6.0657 6.0657 0 002.0138 7.0135l.011.0083.0312.0209 5.1618 3.869 2.5599 1.9354 1.5622 1.1793a1.0273 1.0273 0 001.2416 0l1.5622-1.1793 2.5599-1.9354 5.1926-3.8919.0122-.0093a6.0657 6.0657 0 002.0009-7.0009z" />
    </svg>
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
  const { presets, sastOptions } = useModelCatalog();
  const [llmChoice, setLlmChoice] = useState<LlmPresetId>(
    llmPresetForProviderModel(initial?.llm_provider, initial?.llm_model),
  );
  // OpenAI-compatible servers serve whatever model id they were started
  // with, so the model is free text for that provider.
  const [llmModel, setLlmModel] = useState(
    initial?.llm_provider === "openai_compat" ? initial.llm_model : LLM_PRESETS["openai-compat-qwen-coder-32b"].model,
  );
  const [llmBaseUrl, setLlmBaseUrl] = useState(initial?.llm_base_url ?? "");
  const [llmApiKey, setLlmApiKey] = useState("");
  const isOpenAiCompat = presets[llmChoice]?.provider === "openai_compat";

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
  const [connectingProvider, setConnectingProvider] = useState<"gitlab" | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const [gitError, setGitError] = useState<string | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [repoLookup, setRepoLookup] = useState<GitRepo | null>(null);
  const [repoLookupLoading, setRepoLookupLoading] = useState(false);
  const [repoLookupError, setRepoLookupError] = useState<string | null>(null);
  // How to reach the repository: sign in with GitLab, or paste its URL with an access token.
  const [gitMethod, setGitMethod] = useState<"oauth" | "token">("oauth");
  const [tokenUrl, setTokenUrl] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [tokenChecking, setTokenChecking] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);

  useEffect(() => {
    if (mode !== "create") return;
    const connectionId = searchParams.get("git_connection_id");
    const provider = searchParams.get("git_provider");
    if (connectionId && provider) {
      setPendingConnectionId(connectionId);
      setGitProvider(provider);
      setGitConnected(true);

      // Restore whatever the user had typed before "Connect GitLab"
      // navigated the browser away to the provider and back.
      try {
        const raw = sessionStorage.getItem(NEW_PROJECT_DRAFT_KEY);
        if (raw) {
          const draft = JSON.parse(raw) as Partial<NewProjectDraft>;
          if (draft.name !== undefined) setName(draft.name);
          if (draft.description !== undefined) setDescription(draft.description);
          if (draft.defaultGitUrl !== undefined) setDefaultGitUrl(draft.defaultGitUrl);
          if (draft.defaultBranch !== undefined) setDefaultBranch(draft.defaultBranch);
          if (draft.monorepoPath !== undefined) setMonorepoPath(draft.monorepoPath);
          if (draft.llmChoice !== undefined && draft.llmChoice in LLM_PRESETS) setLlmChoice(draft.llmChoice);
          if (draft.llmModel !== undefined) setLlmModel(draft.llmModel);
          if (draft.llmBaseUrl !== undefined) setLlmBaseUrl(draft.llmBaseUrl);
        }
        sessionStorage.removeItem(NEW_PROJECT_DRAFT_KEY);
      } catch {
        /* sessionStorage unavailable (private mode, etc.) — draft is best-effort */
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  // Look up the one pasted repository instead of listing every project the
  // account can see (a list is capped at one page and hides the rest).
  async function handleLookupRepo() {
    const provider = "gitlab";
    const by =
      mode === "edit" && initial?.id
        ? { projectId: initial.id }
        : pendingConnectionId
          ? { connectionId: pendingConnectionId }
          : null;
    if (!by) return;
    if (!repoUrl.trim()) {
      setRepoLookupError("Paste the full Git URL of the repository.");
      return;
    }

    setRepoLookupLoading(true);
    setRepoLookupError(null);
    setRepoLookup(null);
    try {
      const repo = await api.gitAuth.lookupRepo(provider, repoUrl.trim(), by);
      setRepoLookup(repo);
      setDefaultGitUrl(repo.clone_url);
      if (repo.default_branch) setDefaultBranch(repo.default_branch);
    } catch (err) {
      setRepoLookupError(
        err instanceof ApiError ? err.message : `Failed to look up the ${GIT_PROVIDER_LABELS[provider]} repository.`
      );
    } finally {
      setRepoLookupLoading(false);
    }
  }

  // Confirm a repository with an access token. On success the token is kept
  // server-side (on the project, or as a pending connection for a new one) and
  // the form behaves as if the account were connected.
  async function handleCheckToken() {
    if (!tokenUrl.trim() || !accessToken.trim()) return;
    setGitError(null);
    setTokenError(null);
    setTokenChecking(true);
    try {
      const repo = await api.gitAuth.checkToken("gitlab", {
        url: tokenUrl.trim(),
        access_token: accessToken.trim(),
        project_id: mode === "edit" ? initial?.id : undefined,
      });
      setRepoLookup(repo);
      setDefaultGitUrl(repo.clone_url);
      if (repo.default_branch) setDefaultBranch(repo.default_branch);
      setGitProvider("gitlab");
      setGitConnected(true);
      if (mode === "create") setPendingConnectionId(repo.connection_id ?? null);
      setAccessToken("");
    } catch (err) {
      setTokenError(err instanceof ApiError ? err.message : "Could not confirm the repository.");
    } finally {
      setTokenChecking(false);
    }
  }

  async function handleConnect(provider: "gitlab") {
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
            llmModel,
            llmBaseUrl,
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

  // A repository URL that hasn't been confirmed (found through the provider or
  // checked with a token) blocks saving. Leaving the URL blank is fine for a
  // DAST-only project, and an unchanged saved URL needs no new check.
  const trimmedGitUrl = defaultGitUrl.trim();
  const repoConfirmed = !!repoLookup && repoLookup.clone_url === trimmedGitUrl;
  const repoNeedsConfirm =
    trimmedGitUrl !== "" && trimmedGitUrl !== (initial?.default_git_url ?? "").trim() && !repoConfirmed;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();

    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    if (repoNeedsConfirm) {
      setError("Confirm the repository in the Git provider section before saving.");
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
      // SCA and SBOM are always on for a project.
      enable_sca: true,
      enable_sbom: true,
      enable_secrets: enableSecrets,
      scan_mode: "full",
      llm_provider: presets[llmChoice].provider,
      llm_model: isOpenAiCompat ? llmModel.trim() || presets[llmChoice].model : presets[llmChoice].model,
    };
    if (isOpenAiCompat) {
      payload.llm_base_url = llmBaseUrl.trim() || null;
      // Blank keeps whatever key is stored; the key is never read back.
      if (llmApiKey.trim()) payload.llm_api_key = llmApiKey.trim();
    }
    if (mode === "create" && pendingConnectionId) {
      payload.git_connection_id = pendingConnectionId;
    }
    // No fallback is sent: the project's (default "none") applies, so a
    // scan stops LLM work at the cost cutoff instead of silently moving to
    // a local Ollama model nobody configured.

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

      <div className="space-y-6">
        <Field label="Project Name *" htmlFor="name">
          <input
            id="name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            maxLength={500}
            aria-required="true"
            className={inputClass}
            placeholder="Project Name"
          />
        </Field>
        <Field label="Description (optional)" htmlFor="description">
          <textarea
            id="description"
            rows={3}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            className={inputClass}
            placeholder="What this project does and who owns it."
          />
        </Field>
      </div>

      <FormSection
        title="Git provider"
        description="Connect GitLab, or paste the repository URL with an access token. Confirm the repository before you save."
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
                    gitProvider === "gitlab" ? "bg-orange-50 text-orange-600" : "bg-slate-100 text-slate-600"
                  }`}
                >
                  {gitProvider === "gitlab" && <GitLabLogo className="h-5 w-5" />}
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
                label="Repository URL"
                htmlFor="repo-url"
                hint={`Paste the repository's full Git URL. It is checked against your ${
                  GIT_PROVIDER_LABELS[gitProvider ?? ""] ?? "Git"
                } account, then fills in the default branch below.`}
              >
                <div className="flex gap-2">
                  <input
                    id="repo-url"
                    value={repoUrl}
                    onChange={(event) => {
                      setRepoUrl(event.target.value);
                      setRepoLookup(null);
                      setRepoLookupError(null);
                    }}
                    onKeyDown={(event) => {
                      // Enter looks the repository up; it must not submit the whole project form.
                      if (event.key === "Enter") {
                        event.preventDefault();
                        void handleLookupRepo();
                      }
                    }}
                    className={inputClass}
                    placeholder="https://gitlab.com/group/project.git"
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <button
                    type="button"
                    onClick={() => void handleLookupRepo()}
                    disabled={repoLookupLoading || !repoUrl.trim()}
                    className="shrink-0 rounded-md border border-slate-300 bg-white px-3.5 py-1.5 text-sm font-medium text-[var(--ink)] transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {repoLookupLoading ? "Checking…" : "Find repository"}
                  </button>
                </div>
              </Field>
              {repoLookup && (
                <p className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
                  Found <span className="font-medium">{repoLookup.full_name}</span>
                  {repoLookup.private ? " (private)" : " (public)"}
                  {repoLookup.default_branch ? ` · default branch ${repoLookup.default_branch}` : ""}
                </p>
              )}
              {repoLookupError && (
                <p className="mt-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {repoLookupError}
                </p>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div role="tablist" aria-label="How to reach the repository" className="inline-flex rounded-md border border-slate-200 bg-slate-50 p-0.5 text-sm">
              {(
                [
                  ["oauth", "Connect GitLab"],
                  ["token", "Repo URL + access token"],
                ] as const
              ).map(([method, label]) => (
                <button
                  key={method}
                  type="button"
                  role="tab"
                  aria-selected={gitMethod === method}
                  onClick={() => setGitMethod(method)}
                  className={`rounded px-3 py-1.5 font-medium transition-colors ${
                    gitMethod === method ? "bg-white text-[var(--ink)] shadow-sm" : "text-[var(--muted)] hover:text-[var(--ink)]"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {gitMethod === "oauth" ? (
              <div className="flex flex-col gap-3 rounded-lg border border-slate-200 bg-white p-4 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-sm text-[var(--muted)]">
                  Sign in to GitLab once and pick this project&apos;s repository. Scans can then clone private repositories.
                </p>
                <button
                  type="button"
                  onClick={() => handleConnect("gitlab")}
                  disabled={connectingProvider !== null}
                  className="inline-flex shrink-0 items-center justify-center gap-2 rounded-md bg-orange-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-orange-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <GitLabLogo className="h-4 w-4" />
                  {connectingProvider === "gitlab" ? "Redirecting to GitLab…" : "Authorize with GitLab"}
                  <span aria-hidden>→</span>
                </button>
              </div>
            ) : (
              <div className="grid gap-3 rounded-lg border border-slate-200 bg-white p-4">
                <Field label="Repository URL" htmlFor="token-repo-url" hint="The full Git URL, for example https://gitlab.com/group/project.git.">
                  <input
                    id="token-repo-url"
                    value={tokenUrl}
                    onChange={(event) => setTokenUrl(event.target.value)}
                    className={inputClass}
                    placeholder="https://gitlab.com/group/project.git"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </Field>
                <Field
                  label="Access token"
                  htmlFor="token-value"
                  hint="A personal access token that can read this repository. It is stored on the server and never shown again."
                >
                  <input
                    id="token-value"
                    type="password"
                    value={accessToken}
                    onChange={(event) => setAccessToken(event.target.value)}
                    onKeyDown={(event) => {
                      // Enter confirms the repository; it must not submit the whole project form.
                      if (event.key === "Enter") {
                        event.preventDefault();
                        void handleCheckToken();
                      }
                    }}
                    className={inputClass}
                    autoComplete="new-password"
                  />
                </Field>
                <div>
                  <button
                    type="button"
                    onClick={() => void handleCheckToken()}
                    disabled={tokenChecking || !tokenUrl.trim() || !accessToken.trim()}
                    className="rounded-md border border-slate-300 bg-white px-3.5 py-1.5 text-sm font-medium text-[var(--ink)] transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {tokenChecking ? "Confirming…" : "Confirm repository"}
                  </button>
                </div>
                {tokenError && (
                  <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {tokenError}
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </FormSection>

      <FormSection
        title="Repository"
        description="The repository comes from the Git provider section above. Leave it unconfirmed for a project used only for DAST scans — those target a URL directly, not a repository."
      >
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
            {sastOptions(llmChoice).map(([id, preset]) => (
              <option key={id} value={id}>
                {preset.label}
              </option>
            ))}
          </select>
        </Field>
        {isOpenAiCompat && (
          <>
            <Field label="Model" htmlFor="llm-model" hint="The model id your server serves, e.g. Qwen/Qwen2.5-Coder-32B-Instruct.">
              <input
                id="llm-model"
                value={llmModel}
                onChange={(event) => setLlmModel(event.target.value)}
                className={inputClass}
                autoComplete="off"
              />
            </Field>
            <Field
              label="Base URL"
              htmlFor="llm-base-url"
              hint="Include the API version prefix. Leave blank to use the server default."
            >
              <input
                id="llm-base-url"
                type="url"
                value={llmBaseUrl}
                onChange={(event) => setLlmBaseUrl(event.target.value)}
                placeholder="http://localhost:8000/v1"
                className={inputClass}
                autoComplete="off"
              />
            </Field>
            <Field
              label="API key"
              htmlFor="llm-api-key"
              hint={
                initial?.llm_api_key_set
                  ? "A key is saved. Leave blank to keep it."
                  : "Optional for local servers. Stored server-side and never shown again."
              }
            >
              <input
                id="llm-api-key"
                type="password"
                value={llmApiKey}
                onChange={(event) => setLlmApiKey(event.target.value)}
                className={inputClass}
                autoComplete="new-password"
              />
            </Field>
          </>
        )}
      </FormSection>

      <div className="flex items-center gap-4 border-t border-slate-200 pt-6">
        <button
          type="submit"
          disabled={submitting || repoNeedsConfirm}
          className="rounded-md bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Saving…" : mode === "create" ? "Create project" : "Save changes"}
        </button>
        {repoNeedsConfirm && (
          <p className="text-sm text-amber-700">Confirm the repository in the Git provider section first.</p>
        )}
      </div>
    </form>
  );
}
