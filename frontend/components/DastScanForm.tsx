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
  DastScanPrefill,
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
  /** An earlier DAST scan whose saved settings fill the form (never its passwords or tokens). */
  fromScanId?: string;
}

type DastInputSaved = DastScanPrefill["dast_input"];
interface Prefill {
  version?: number | null;
  input: DastInputSaved;
}

/** Identities as the form holds them, from a scan's saved request. Secrets are not stored, so they stay empty. */
function identitiesFromSaved(saved: DastInputSaved): IdentityDraft[] {
  return (saved.identities ?? [])
    .filter((i) => !i.implicit && i.auth_method !== "none" && i.role !== "anonymous")
    .map((i) => {
      const role = (["admin", "user", "viewer", "custom"] as const).find((r) => r === i.role) ?? "user";
      return newIdentity({
        label: i.label,
        role,
        customRole: role === "custom" ? (i.role_label ?? "") : "",
        method: i.auth_method as IdentityDraft["method"],
        loginUrl: i.login_url ?? "",
        username: i.username ?? "",
        ...(i.header_name ? { headerName: i.header_name } : {}),
        ...(i.scheme ? { scheme: i.scheme } : {}),
      });
    });
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

const MAX_EXTRA_ENDPOINTS_CHARS = 65536;

function describePreset(preset: Record<string, number> | undefined): string {
  if (!preset) return "";
  return `up to ${preset.max_targets} endpoints, ${preset.max_tests_per_target} tests each, ${preset.max_pages} pages, depth ${preset.max_depth}`;
}

/** Inputs for a DAST scan: the target and authorization, scope and safety, identities, rule packs and model.
 *  With `fromScanId` the form starts from that scan's saved settings instead of the defaults. */
export default function DastScanForm({ project, onSubmit, fromScanId }: DastScanFormProps) {
  const [prefill, setPrefill] = useState<Prefill | null>(null);
  const [loadingPrefill, setLoadingPrefill] = useState(Boolean(fromScanId));
  const [prefillError, setPrefillError] = useState<string | null>(null);

  useEffect(() => {
    if (!fromScanId) return;
    let active = true;
    api.scans
      .dastInput(fromScanId)
      .then((saved) => active && setPrefill({ version: saved.version, input: saved.dast_input }))
      .catch((err) => active && setPrefillError(err instanceof ApiError ? err.message : "Could not load that scan's settings."))
      .finally(() => active && setLoadingPrefill(false));
    return () => {
      active = false;
    };
  }, [fromScanId]);

  // The form's state is seeded once, so it mounts only after the saved settings have arrived.
  if (loadingPrefill) return <p className="text-sm text-[var(--muted)]">Loading the previous scan&apos;s settings…</p>;
  return <DastScanFormBody project={project} onSubmit={onSubmit} prefill={prefill} prefillError={prefillError} />;
}

function DastScanFormBody({
  project,
  onSubmit,
  prefill,
  prefillError,
}: Pick<DastScanFormProps, "project" | "onSubmit"> & { prefill: Prefill | null; prefillError: string | null }) {
  const uid = useId();
  const saved = prefill?.input;
  const [targetUrl, setTargetUrl] = useState(saved?.target_url || PRACTICE_TARGET_URL);
  const [targetTouched, setTargetTouched] = useState(false);
  const [authorized, setAuthorized] = useState(true);

  const [intensity, setIntensity] = useState<DastIntensity>(saved?.intensity ?? "light");
  const [headless, setHeadless] = useState(saved?.headless ?? true);
  const [agentMode, setAgentMode] = useState<boolean | null>(saved?.agent_mode ?? null);
  const [agentTurns, setAgentTurns] = useState(saved?.max_agent_turns ? String(saved.max_agent_turns) : "");
  const [hypothesisTurns, setHypothesisTurns] = useState(saved?.max_turns_per_hypothesis ? String(saved.max_turns_per_hypothesis) : "");
  const [extraEndpoints, setExtraEndpoints] = useState("");

  const [identities, setIdentities] = useState<IdentityDraft[]>(() => (saved ? identitiesFromSaved(saved) : [newIdentity(PRACTICE_IDENTITY)]));
  const [rulePacks, setRulePacks] = useState<string[] | null>(saved?.rule_packs ?? null);
  const [modelRouting, setModelRouting] = useState<Partial<Record<DastModelTask, DastModelChoice>>>(saved?.model_routing ?? {});

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
    if (extraEndpoints.length > MAX_EXTRA_ENDPOINTS_CHARS) {
      return setError(`The API list is longer than ${MAX_EXTRA_ENDPOINTS_CHARS.toLocaleString()} characters. Remove some entries.`);
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
          ...(extraEndpoints.trim() ? { extra_endpoints: extraEndpoints } : {}),
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

      {prefill && (
        <div role="status" className="rounded-md border border-slate-200 bg-white px-4 py-3 text-sm text-[var(--ink)]">
          Filled in from the settings of scan v{prefill.version ?? "?"}. Passwords, tokens and saved sessions are never stored, so enter them
          again under Identities.
        </div>
      )}
      {prefillError && (
        <div role="status" className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          {prefillError} Starting from the defaults instead.
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

      <section aria-labelledby={`${uid}-apis`} className="space-y-3">
        <SectionLabel>
          <span id={`${uid}-apis`}>Known API endpoints (optional)</span>
        </SectionLabel>
        <label htmlFor="dast-extra-endpoints" className="block text-sm font-medium text-[var(--ink)]">
          APIs the crawl may miss
        </label>
        <textarea
          id="dast-extra-endpoints"
          rows={8}
          value={extraEndpoints}
          onChange={(e) => setExtraEndpoints(e.target.value)}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          aria-describedby="dast-extra-endpoints-hint"
          placeholder={"GET /api/users/1\nPOST /api/orders {\"qty\": 1}\nhttp://localhost:3000/api/admin/stats\ncurl -X DELETE http://localhost:3000/api/items/9"}
          className="agent-focus-ring w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs text-[var(--ink)]"
        />
        <p id="dast-extra-endpoints-hint" className="text-xs text-[var(--muted)]">
          One per line, in any form: <code>METHOD /path</code>, a full URL on this target, a curl command, or an OpenAPI/Swagger document. Messy lines are tidied up and
          anything the scan already found is merged, not repeated. Do not paste tokens, cookies or Authorization headers (they are refused); add the login under Identities.
          Because this scan treats the target as disposable, POST, PUT, PATCH and DELETE entries are tested too.
          {extraEndpoints.trim() && (
            <span className="ml-1">
              {extraEndpoints.split("\n").filter((l) => l.trim()).length} line(s), {extraEndpoints.length.toLocaleString()} / {MAX_EXTRA_ENDPOINTS_CHARS.toLocaleString()} characters.
            </span>
          )}
        </p>
      </section>

      <DastIdentitiesEditor identities={identities} onChange={setIdentities} showErrors={showErrors} />

      <DastRulePackPicker
        projectId={project.id}
        hasSecondIdentity={authenticated >= 2}
        oastConfigured={Boolean(settings?.oast_configured)}
        initialPacks={saved?.rule_packs ?? null}
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
