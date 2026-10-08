"use client";

import { useEffect, useId, useMemo, useState, type FormEvent } from "react";

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
/** Local Juice Shop practice target — pre-filled so a scan can start without retyping. */
const PRACTICE_TARGET_URL = "http://127.0.0.1:3001";
const PRACTICE_IDENTITY = {
  label: "test",
  role: "user" as const,
  method: "form" as const,
  loginUrl: "http://127.0.0.1:3001/#/login",
  username: "tester@example.test",
  password: "Test1234!",
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
    return "That is not a valid URL (for example http://localhost:3000).";
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
  const [disposable, setDisposable] = useState(true);
  const [authorized, setAuthorized] = useState(true);

  const [intensity, setIntensity] = useState<DastIntensity>("light");
  const [safeMode, setSafeMode] = useState(true);
  const [rateLimit, setRateLimit] = useState("5");
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxPages, setMaxPages] = useState("5");
  const [headless, setHeadless] = useState(true);
  const [markerPosts, setMarkerPosts] = useState(false);

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
      if (s.browser_marker_posts) setMarkerPosts(true);
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
  const rateLimits = settings?.limits.rate_limit_per_sec;
  const rateProblem = useMemo(() => {
    if (!rateLimit.trim()) return null;
    const n = Number(rateLimit);
    if (!Number.isFinite(n) || n <= 0) return "Enter a number greater than zero.";
    if (rateLimits && (n < rateLimits.min || n > rateLimits.max)) return `Use a value between ${rateLimits.min} and ${rateLimits.max}.`;
    return null;
  }, [rateLimit, rateLimits]);
  const unsafeNeedsDisposable = !safeMode && !disposable;
  const markerNeedsDisposable = markerPosts && !disposable;
  const identityIssues = identities.map((d) => identityProblems(d, identities));
  const authenticated = identities.length;

  const canSubmit = Boolean(targetUrl.trim()) && !urlProblem && authorized && !unsafeNeedsDisposable && !markerNeedsDisposable && !submitting;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setShowErrors(true);
    if (creatingNewProject) {
      if (!newProjectName.trim()) return setError("Enter a name for the new project.");
    } else if (!selectedProjectId) {
      return setError("Select a project to scan.");
    }
    if (!targetUrl.trim() || urlProblem) return setError(urlProblem ?? "Target URL is required.");
    if (rateProblem) return setError(`Request rate limit: ${rateProblem}`);
    if (identityIssues.some((p) => Object.keys(p).length > 0)) return setError("Fix the highlighted identity fields.");
    if (unsafeNeedsDisposable) return setError("State-changing methods can only be enabled for a target marked as disposable.");
    if (markerNeedsDisposable) return setError("Stored XSS marker submits can only be enabled for a target marked as disposable.");
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
          method_policy: safeMode ? "safe" : "opt_in_mutating",
          target_disposable: disposable,
          browser_marker_posts: markerPosts,
          headless,
          ...(rateLimit.trim() ? { rate_limit_per_sec: Number(rateLimit) } : {}),
          ...(maxDepth.trim() ? { max_depth: Number(maxDepth) } : {}),
          ...(maxPages.trim() ? { max_pages: Number(maxPages) } : {}),
          max_targets: 5,
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
            placeholder="http://localhost:3000"
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
            checked={disposable}
            onChange={(event) => setDisposable(event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
          />
          <span>
            This is a disposable target <span className="text-[var(--muted)]">— a test or practice instance I can safely change or break. Needed to allow state-changing methods.</span>
          </span>
        </label>

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
          <span id={`${uid}-scope`}>Scope &amp; safety</span>
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

        <div
          className={`rounded-md border px-4 py-3 ${safeMode ? "border-emerald-200 bg-emerald-50/60" : "border-amber-300 bg-amber-50"}`}
          role="group"
          aria-labelledby={`${uid}-safe`}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p id={`${uid}-safe`} className="text-sm font-medium text-[var(--ink)]">
              Safe mode is {safeMode ? "ON" : "OFF"}
              <span className="ml-2 font-normal text-[var(--muted)]">
                {safeMode ? "Only read-only methods (GET, HEAD, OPTIONS) are sent." : "State-changing methods (POST, PUT, PATCH, DELETE) may be sent."}
              </span>
            </p>
            <button
              type="button"
              onClick={() => setSafeMode((v) => !v)}
              className="agent-focus-ring rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-[var(--ink)] hover:bg-slate-50"
            >
              {safeMode ? "Allow state-changing methods…" : "Turn safe mode back on"}
            </button>
          </div>
          {!safeMode && (
            <div role="alert" className="mt-3 space-y-1 text-sm text-amber-900">
              <p className="font-medium">Warning: this scan can create, change and delete data.</p>
              <p>
                Only do this against a disposable target. Checks may submit forms, call write endpoints and replay requests as other
                roles. {unsafeNeedsDisposable && <strong>Mark the target as disposable above to continue.</strong>}
              </p>
            </div>
          )}
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label htmlFor="dast-rate" className="block text-sm font-medium text-[var(--ink)]">
              Request rate limit <span className="font-normal text-[var(--muted)]">(per second)</span>
            </label>
            <input
              id="dast-rate"
              inputMode="decimal"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
              className={inputClass}
              placeholder={settings ? String(settings.rate_limit_per_sec) : "default"}
              aria-invalid={Boolean(rateProblem)}
              aria-describedby={rateProblem ? "dast-rate-error" : undefined}
            />
            {rateProblem && (
              <p id="dast-rate-error" role="alert" className="mt-1 text-xs text-red-700">
                {rateProblem}
              </p>
            )}
          </div>
          <div>
            <label htmlFor="dast-depth" className="block text-sm font-medium text-[var(--ink)]">
              Crawl depth
            </label>
            <input id="dast-depth" type="number" min={1} max={10} value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} className={inputClass} />
          </div>
          <div>
            <label htmlFor="dast-pages" className="block text-sm font-medium text-[var(--ink)]">
              Max pages
            </label>
            <input id="dast-pages" type="number" min={1} max={1000} value={maxPages} onChange={(e) => setMaxPages(e.target.value)} className={inputClass} />
          </div>
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

        <label className="flex items-start gap-2 text-sm text-[var(--ink)]">
          <input
            type="checkbox"
            checked={markerPosts}
            onChange={(event) => setMarkerPosts(event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
          />
          <span>
            Submit stored-XSS markers
            <span className="block text-xs text-[var(--muted)]">
              POSTs an inert marker into forms, then revisits pages. This writes data. Only for a disposable target. Safe mode stays on for every other request.
            </span>
          </span>
        </label>
        {markerPosts && (
          <p role="alert" className="text-sm text-amber-900">
            Warning: this scan will store a unique marker in the target. Mark the target disposable
            {markerNeedsDisposable ? " — it is not disposable yet, so the scan cannot start." : "."}
          </p>
        )}
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
