"use client";

import { useEffect, useId, useState, type FormEvent } from "react";

import DastIdentitiesEditor, { identityProblems, newIdentity, toIdentityInput, type IdentityDraft } from "@/components/DastIdentitiesEditor";
import DastModelPicker from "@/components/DastModelPicker";
import DastRulePackPicker from "@/components/DastRulePackPicker";
import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";
import type {
  DastIntensity,
  DastModelChoice,
  DastModelTask,
  DastProviders,
  DastSettings,
  Project,
  ScanCreateInput,
} from "@/lib/types";

const NEW_PROJECT_VALUE = "__new__";
/** Local Employee Management practice target — pre-filled so a scan can start without retyping. */
const PRACTICE_TARGET_URL = "http://localhost:4200";
const PRACTICE_IDENTITY = {
  label: "Employee Management demo user",
  role: "user" as const,
  method: "form" as const,
  loginUrl: "http://localhost:4200/login",
  username: "Morgan",
  password: "pwd1",
};
const INTENSITIES: { value: DastIntensity; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "standard", label: "Standard" },
  { value: "deep", label: "Deep" },
];

interface DastScanFormProps {
  projectId?: string;
  onSubmit: (input: ScanCreateInput) => Promise<void>;
}

/** The address must be an absolute http(s) URL: checked as the user types, not only on submit. */
export function targetUrlProblem(value: string): string | null {
  const text = value.trim();
  if (!text) return null;
  try {
    const url = new URL(text);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "Use an http:// or https:// address.";
    if (!url.hostname) return "The address needs a host name.";
    return null;
  } catch {
    return "That is not a valid URL (for example http://localhost:4200).";
  }
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">{children}</p>;
}

function describePreset(preset: Record<string, number> | undefined): string {
  if (!preset) return "";
  return `up to ${preset.max_targets} endpoints, ${preset.max_tests_per_target} tests each, ${preset.max_pages} pages, depth ${preset.max_depth}`;
}

/** Inputs for a DAST scan: the target and authorization, scope and safety, identities, rule packs and model. */
export default function DastScanForm({ projectId, onSubmit }: DastScanFormProps) {
  const uid = useId();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [creatingNewProject, setCreatingNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");

  const [targetUrl, setTargetUrl] = useState(PRACTICE_TARGET_URL);
  const [targetTouched, setTargetTouched] = useState(false);
  const [authorized, setAuthorized] = useState(true);

  const [intensity, setIntensity] = useState<DastIntensity>("light");
  const [headless, setHeadless] = useState(true);

  const [identities, setIdentities] = useState<IdentityDraft[]>(() => [newIdentity(PRACTICE_IDENTITY)]);
  const [rulePacks, setRulePacks] = useState<string[] | null>(null);
  const [modelRouting, setModelRouting] = useState<Partial<Record<DastModelTask, DastModelChoice>>>({});

  const [settings, setSettings] = useState<DastSettings | null>(null);
  const [providers, setProviders] = useState<DastProviders | null>(null);

  const [showErrors, setShowErrors] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoadingProjects(true);
      try {
        const data = await api.projects.list();
        if (active) {
          setProjects(data || []);
          setSelectedProjectId((current) => {
            if (current && data.some((p) => p.id === current)) return current;
            const fromUrl = projectId && data.some((p) => p.id === projectId) ? projectId : null;
            return fromUrl ?? data[0]?.id ?? "";
          });
        }
      } catch (err) {
        console.error("Failed to load projects:", err);
        if (active) setProjects([]);
      } finally {
        if (active) setLoadingProjects(false);
      }
    }
    load();
    // Settings and provider status are best-effort: the form still works without them.
    api.dast.settings.get().then((s) => {
      if (!active || !s) return;
      setSettings(s);
    }).catch(() => undefined);
    api.dast.providers().then((p) => active && setProviders(p)).catch(() => undefined);
    return () => {
      active = false;
    };
  }, [projectId]);

  const projectSelectValue = creatingNewProject
    ? NEW_PROJECT_VALUE
    : projects.some((p) => p.id === selectedProjectId)
      ? selectedProjectId
      : "";

  function handleProjectSelect(value: string) {
    if (value === NEW_PROJECT_VALUE) {
      setCreatingNewProject(true);
      return;
    }
    setCreatingNewProject(false);
    setSelectedProjectId(value);
  }

  const urlProblem = targetUrlProblem(targetUrl);
  const identityIssues = identities.map((d) => identityProblems(d, identities));
  const authenticated = identities.length;

  const canSubmit = Boolean(targetUrl.trim()) && !urlProblem && authorized && !submitting;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setShowErrors(true);
    if (creatingNewProject) {
      if (!newProjectName.trim()) return setError("Enter a name for the new project.");
    } else if (!selectedProjectId) {
      return setError("Select a project to scan.");
    }
    if (!targetUrl.trim() || urlProblem) return setError(urlProblem ?? "Target URL is required.");
    if (identityIssues.some((p) => Object.keys(p).length > 0)) return setError("Fix the highlighted identity fields.");
    if (!authorized) return setError("Confirm that you are authorized to test this target.");

    setError(null);
    setSubmitting(true);
    try {
      let project = selectedProjectId;
      if (creatingNewProject) {
        // A project used only for DAST has no repository — name alone is enough.
        const created = await api.projects.create({ name: newProjectName.trim() });
        project = created.id;
        setProjects((prev) => [...prev, created]);
        setSelectedProjectId(created.id);
        setCreatingNewProject(false);
      }

      const payload: ScanCreateInput = {
        project_id: project,
        scan_type: "dast",
        use_llm: false,
        metadata: { source: "app" },
        dast: {
          target_url: targetUrl.trim(),
          authorized,
          intensity,
          method_policy: "opt_in_mutating",
          target_disposable: true,
          browser_marker_posts: true,
          headless,
          ...(identities.length > 0 ? { identities: identities.map(toIdentityInput) } : {}),
          ...(rulePacks ? { rule_packs: rulePacks } : {}),
          ...(Object.keys(modelRouting).length > 0 ? { model_routing: modelRouting } : {}),
        },
      };
      await onSubmit(payload);
      // The scan page takes over; nothing secret is kept in this form once the request is sent.
      setIdentities((current) => current.map((d) => ({ ...d, password: "", token: "", storageState: "" })));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  const presets = settings?.presets;

  return (
    <form onSubmit={handleSubmit} className="space-y-8" noValidate>
      {error && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <section aria-labelledby={`${uid}-target`} className="space-y-5">
        <SectionLabel>
          <span id={`${uid}-target`}>Target</span>
        </SectionLabel>

        <div>
          <label htmlFor="dast-project" className="block text-sm font-medium text-[var(--ink)]">
            Project
          </label>
          <select
            id="dast-project"
            value={projectSelectValue}
            onChange={(event) => handleProjectSelect(event.target.value)}
            className={selectClass}
            disabled={loadingProjects}
          >
            <option value="" disabled>
              {loadingProjects ? "Loading projects…" : "Select a project"}
            </option>
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
            <option value={NEW_PROJECT_VALUE}>+ New project…</option>
          </select>
          {creatingNewProject ? (
            <div className="mt-2">
              <label htmlFor="dast-new-project-name" className="sr-only">
                New project name
              </label>
              <input
                id="dast-new-project-name"
                value={newProjectName}
                onChange={(event) => setNewProjectName(event.target.value)}
                className={inputClass}
                placeholder="Project name"
                autoFocus
                required
              />
              <p className="mt-1 text-xs text-[var(--muted)]">
                Created when you start the scan — just a name, no repository needed. It&apos;ll show up on the Projects page too.{" "}
                {projects.length > 0 && (
                  <button type="button" onClick={() => handleProjectSelect(projects[0]!.id)} className="font-medium text-[var(--accent)] hover:underline">
                    Pick an existing project instead
                  </button>
                )}
              </p>
            </div>
          ) : (
            !loadingProjects &&
            projects.length === 0 && (
              <p className="mt-1 text-xs text-[var(--muted)]">No projects yet — pick &quot;+ New project…&quot; above to create one.</p>
            )
          )}
        </div>

        <div>
          <label htmlFor="dast-target" className="block text-sm font-medium text-[var(--ink)]">
            Target address
          </label>
          <input
            id="dast-target"
            type="url"
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            onBlur={() => setTargetTouched(true)}
            className={inputClass}
            placeholder="http://localhost:4200"
            aria-invalid={Boolean(urlProblem) && (targetTouched || showErrors)}
            aria-describedby={`dast-target-hint${urlProblem && (targetTouched || showErrors) ? " dast-target-error" : ""}`}
            required
          />
          <p id="dast-target-hint" className="mt-1 text-xs text-[var(--muted)]">
            The running application to test. Requests never leave this address (same-host scope).
          </p>
          {urlProblem && (targetTouched || showErrors) && (
            <p id="dast-target-error" role="alert" className="mt-1 text-xs text-red-700">
              {urlProblem}
            </p>
          )}
        </div>

        <label className="flex items-start gap-2 text-sm text-[var(--ink)]">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
            aria-describedby="dast-authorized-hint"
          />
          <span>
            I own this target or am explicitly authorized to test it.
            <span id="dast-authorized-hint" className="block text-xs text-[var(--muted)]">
              Required. Every request is recorded in the scan&apos;s audit log.
            </span>
          </span>
        </label>
      </section>

      <section aria-labelledby={`${uid}-scope`} className="space-y-5">
        <SectionLabel>
          <span id={`${uid}-scope`}>Scan coverage</span>
        </SectionLabel>

        <div>
          <label htmlFor="dast-intensity" className="block text-sm font-medium text-[var(--ink)]">
            Intensity
          </label>
          <select id="dast-intensity" value={intensity} onChange={(e) => setIntensity(e.target.value as DastIntensity)} className={selectClass}>
            {INTENSITIES.map((i) => (
              <option key={i.value} value={i.value}>
                {i.label}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-[var(--muted)]">{presets ? describePreset(presets[intensity]) : "Loading what each preset means…"}</p>
        </div>

        <label className="flex items-center gap-2 text-sm text-[var(--ink)]">
          <input
            type="checkbox"
            checked={headless}
            onChange={(event) => setHeadless(event.target.checked)}
            className="h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
          />
          Run the browser headless
        </label>

        <p className="text-xs text-[var(--muted)]">
          Stored-XSS form markers are submitted automatically for the approved disposable practice target, then checked again on crawled pages.
        </p>
      </section>

      <DastIdentitiesEditor identities={identities} onChange={setIdentities} showErrors={showErrors} />

      <DastRulePackPicker
        projectId={creatingNewProject ? null : selectedProjectId || null}
        hasSecondIdentity={authenticated >= 2}
        oastConfigured={Boolean(settings?.oast_configured)}
        onChange={setRulePacks}
      />

      <DastModelPicker settings={settings} providers={providers} value={modelRouting} onChange={setModelRouting} />

      <div className="flex flex-wrap items-center gap-4 border-t border-slate-200 pt-6">
        <button
          type="submit"
          disabled={!canSubmit}
          className="agent-focus-ring rounded-md bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? "Starting…" : "Start DAST scan"}
        </button>
        {!authorized && <p className="text-xs text-[var(--muted)]">Confirm authorization to start.</p>}
        {authorized && !targetUrl.trim() && <p className="text-xs text-[var(--muted)]">Enter the target address to start.</p>}
        {authorized && urlProblem && <p className="text-xs text-red-700">Fix the target address to start.</p>}
      </div>
    </form>
  );
}
