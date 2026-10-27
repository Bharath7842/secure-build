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
  /** The active project. DAST needs no repository: the target address is entered per scan. */
  project: Project;
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
export default function DastScanForm({ project, onSubmit }: DastScanFormProps) {
  const uid = useId();
  const [targetUrl, setTargetUrl] = useState(PRACTICE_TARGET_URL);
  const [targetTouched, setTargetTouched] = useState(false);
  const [authorized, setAuthorized] = useState(true);

  const [intensity, setIntensity] = useState<DastIntensity>("light");
  const [headless, setHeadless] = useState(true);
  const [agentMode, setAgentMode] = useState<boolean | null>(null);
  const [agentTurns, setAgentTurns] = useState("");
  const [hypothesisTurns, setHypothesisTurns] = useState("");

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
    // Settings and provider status are best-effort: the form still works without them.
    api.dast.settings.get().then((s) => {
      if (!active || !s) return;
      setSettings(s);
    }).catch(() => undefined);
    api.dast.providers().then((p) => active && setProviders(p)).catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  const urlProblem = targetUrlProblem(targetUrl);
  const identityIssues = identities.map((d) => identityProblems(d, identities));
  const authenticated = identities.length;

  const canSubmit = Boolean(targetUrl.trim()) && !urlProblem && authorized && !submitting;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setShowErrors(true);
    if (!targetUrl.trim() || urlProblem) return setError(urlProblem ?? "Target URL is required.");
    if (identityIssues.some((p) => Object.keys(p).length > 0)) return setError("Fix the highlighted identity fields.");
    if (!authorized) return setError("Confirm that you are authorized to test this target.");

    for (const [value, limit, label] of [[agentTurns, 1000, "Adaptive turns per scan"], [hypothesisTurns, 20, "Turns per hypothesis"]] as const) {
      if (value && (!Number.isInteger(Number(value)) || Number(value) < 1 || Number(value) > limit)) {
        return setError(`${label} must be a whole number between 1 and ${limit}.`);
      }
    }
    setError(null);
    setSubmitting(true);
    try {
      const payload: ScanCreateInput = {
        project_id: project.id,
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
          agent_mode: agentMode ?? settings?.agent_mode ?? false,
          ...(agentTurns ? { max_agent_turns: Number(agentTurns) } : {}),
          ...(hypothesisTurns ? { max_turns_per_hypothesis: Number(hypothesisTurns) } : {}),
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
          <p className="block text-sm font-medium text-[var(--ink)]">Project</p>
          <p className="mt-1 text-sm text-[var(--ink)]">{project.name}</p>
          <p className="mt-1 text-xs text-[var(--muted)]">
            Change the project from the selector in the sidebar. DAST scans a running web address, so the project needs no repository.
          </p>
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

        <div className="space-y-3">
          <label className="flex items-start gap-2 text-sm text-[var(--ink)]">
            <input type="checkbox" className="agent-focus-ring mt-0.5" checked={agentMode ?? settings?.agent_mode ?? false} onChange={(e) => setAgentMode(e.target.checked)} />
            <span>Agent mode<span className="block text-xs text-[var(--muted)]">Plan tests by OWASP category and adapt follow-up probes to the results. Adds bounded model calls.</span></span>
          </label>
          {(agentMode ?? settings?.agent_mode ?? false) && (
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="text-sm text-[var(--ink)]">Adaptive turns per scan
                <input type="number" min={1} max={1000} step={1} className={inputClass} placeholder={String(settings?.max_agent_turns ?? 60)} value={agentTurns} onChange={(e) => setAgentTurns(e.target.value)} />
              </label>
              <label className="text-sm text-[var(--ink)]">Turns per hypothesis
                <input type="number" min={1} max={20} step={1} className={inputClass} placeholder={String(settings?.max_turns_per_hypothesis ?? 4)} value={hypothesisTurns} onChange={(e) => setHypothesisTurns(e.target.value)} />
              </label>
              <p className="text-xs text-[var(--muted)] sm:col-span-2">Leave blank to use the global defaults. Small local models use lower limits.</p>
            </div>
          )}
        </div>

        <p className="text-xs text-[var(--muted)]">
          Stored-XSS form markers are submitted automatically for the approved disposable practice target, then checked again on crawled pages.
        </p>
      </section>

      <DastIdentitiesEditor identities={identities} onChange={setIdentities} showErrors={showErrors} />

      <DastRulePackPicker
        projectId={project.id}
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
