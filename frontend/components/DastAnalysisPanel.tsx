"use client";

import { useState } from "react";

import DastHttpExchange, { trafficFromParts } from "@/components/DastHttpExchange";
import { displayEndpoint, hideInconclusive, originOf, stripQueryFragment, withHttpUrl } from "@/lib/httpLabel";
import type {
  DastApiAnalysis,
  DastApiCall,
  DastApiCheck,
  DastDiscovery,
  DastInventoryEntry,
  DastRecorded,
} from "@/lib/types";

const VERDICT_STYLES: Record<string, string> = {
  FAIL: "bg-red-50 text-red-700 border-red-200",
  PASS: "bg-emerald-50 text-emerald-700 border-emerald-200",
};

function endpointLabel(api: DastApiAnalysis, origin = ""): string {
  const method = (api.method || "GET").toUpperCase();
  const dest = api.url || api.recorded?.url || api.path || "";
  const labeled = displayEndpoint(method, dest, origin);
  if (labeled !== method) return labeled;
  return origin ? withHttpUrl(api.label || method, origin) : api.label || method;
}

function shownCheckVerdict(check: DastApiCheck): string {
  const verdict = (check.verdict || "").toUpperCase();
  if (verdict === "FAIL" || verdict === "PASS") return verdict;
  const proposed = (check.guardrail?.proposed || "").toUpperCase();
  if (proposed === "FAIL" || proposed === "PASS") return proposed;
  return "PASS";
}

function shownOverall(api: DastApiAnalysis): string {
  if (api.checks.some((c) => shownCheckVerdict(c) === "FAIL")) return "FAIL";
  const overall = (api.overall_verdict || "").toUpperCase();
  return overall === "FAIL" ? "FAIL" : "PASS";
}

function checkCounts(api: DastApiAnalysis): { fail: number; pass: number } {
  let fail = 0;
  let pass = 0;
  for (const check of api.checks) {
    if (shownCheckVerdict(check) === "FAIL") fail += 1;
    else pass += 1;
  }
  return { fail, pass };
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800 border-red-300",
  HIGH: "bg-red-50 text-red-700 border-red-200",
  MEDIUM: "bg-amber-50 text-amber-800 border-amber-200",
  LOW: "bg-blue-50 text-blue-700 border-blue-200",
  INFO: "bg-slate-50 text-slate-600 border-slate-200",
};

const METHOD_STYLES: Record<string, string> = {
  GET: "bg-emerald-50 text-emerald-700 border-emerald-200",
  POST: "bg-blue-50 text-blue-700 border-blue-200",
  PUT: "bg-amber-50 text-amber-700 border-amber-200",
  PATCH: "bg-amber-50 text-amber-700 border-amber-200",
  DELETE: "bg-red-50 text-red-700 border-red-200",
};

function Pill({ label, styles }: { label: string; styles: Record<string, string> }) {
  const key = (label || "").toUpperCase();
  return (
    <span
      className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
        styles[key] ?? "border-slate-200 bg-slate-50 text-slate-600"
      }`}
    >
      {label}
    </span>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <div className="mt-0.5 text-xs text-[var(--ink)]">{children}</div>
    </div>
  );
}

function CheckRow({ check, api }: { check: DastApiCheck; api: DastApiAnalysis }) {
  const [open, setOpen] = useState(check.verdict === "FAIL");
  const request = check.request ?? trafficFromParts({
    method: api.method,
    url: api.url,
    parameter: check.target,
    location: check.location,
    payload: check.payload,
    seq: check.audit_ref,
    responseStatus: check.response.status_code,
  });
  const baseline =
    check.baseline && (check.baseline.status_code != null || check.baseline.length)
      ? `HTTP ${check.baseline.status_code ?? "—"}, ${check.baseline.length} bytes`
      : null;
  return (
    <div className="rounded-md border border-slate-200 bg-white">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-slate-50"
        aria-expanded={open}
      >
        <span className="w-3 shrink-0 text-[var(--muted)]">{open ? "▾" : "▸"}</span>
        <span className="min-w-0 flex-1 truncate text-xs font-medium text-[var(--ink)]">
          {check.check}
          {check.target && <span className="text-[var(--muted)]"> · {check.target}</span>}
        </span>
        <Pill label={check.severity} styles={SEVERITY_STYLES} />
        <Pill label={shownCheckVerdict(check)} styles={VERDICT_STYLES} />
      </button>

      {open && (
        <div className="space-y-2.5 border-t border-slate-100 px-3 py-3">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--muted)]">
            {check.cwe && <span>{check.cwe}</span>}
            {check.owasp_category && <span>{check.owasp_category}</span>}
            {check.confidence && <span>Confidence: {check.confidence}</span>}
          </div>

          {check.response.error && (
            <p className="text-xs text-amber-700">Transport error: {check.response.error}</p>
          )}

          <DastHttpExchange
            request={request}
            baseline={baseline}
            response={check.response.evidence || check.response.error}
            responseStatus={check.response.status_code}
            responseMeta={check.response.content_type || undefined}
            signals={check.signals}
          />

          {check.guardrail && check.guardrail.overridden && (
            <Field label="Guardrail">
              <p className="text-amber-800">
                The model's verdict was overridden:{" "}
                {hideInconclusive(check.guardrail.reason || "")}
              </p>
            </Field>
          )}
          {check.finding && (
            <Field label="Finding">
              <p>{check.finding}</p>
            </Field>
          )}
          {check.evidence && (
            <Field label="Why">
              <p className="text-[var(--muted)]">{check.evidence}</p>
            </Field>
          )}
        </div>
      )}
    </div>
  );
}

const OVERALL_HINT: Record<string, string> = {
  FAIL: "Overall fail: at least one check on this endpoint is a confirmed issue.",
  PASS: "Overall pass: no confirmed issues on this endpoint.",
};

function recordedFor(
  api: DastApiAnalysis,
  inventory?: DastInventoryEntry[] | null,
  apiCalls?: DastApiCall[] | null,
): DastRecorded {
  if (api.recorded) return api.recorded;
  const method = (api.method || "").toUpperCase();
  const inv = inventory?.find(
    (entry) =>
      (entry.method || "").toUpperCase() === method &&
      (entry.path_template === api.path || entry.url === api.url),
  );
  const call = apiCalls?.find(
    (item) =>
      (item.method || "").toUpperCase() === method &&
      (item.url === api.url || item.url.endsWith(api.path)),
  );
  return {
    method: api.method,
    url: api.url,
    path: api.path,
    status_code: inv?.status_code ?? call?.status_code ?? null,
    content_type: inv?.content_type ?? call?.content_type ?? "",
    kind: inv?.kind ?? api.kind ?? "api",
    parameters: (inv?.parameters ?? []).map((parameter) => ({
      name: parameter.name,
      location: parameter.location,
      values: parameter.values ?? [],
    })),
  };
}

function RecordedSnapshot({ recorded }: { recorded: DastRecorded }) {
  const method = (recorded.method || "GET").toUpperCase();
  const status = recorded.status_code != null ? `HTTP ${recorded.status_code}` : "no status";
  const type = recorded.content_type || "unknown type";
  const params = recorded.parameters ?? [];
  return (
    <div className="space-y-2 rounded-md border border-slate-200 bg-slate-50/80 px-3 py-2.5">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">
        Recorded during discovery
      </p>
      <div className="flex min-w-0 items-center gap-2">
        <Pill label={method} styles={METHOD_STYLES} />
        <span className="min-w-0 truncate font-mono text-xs text-[var(--ink)]" title={recorded.url || recorded.path}>
          {recorded.url ? stripQueryFragment(recorded.url) : recorded.path}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <Field label="Status">{status}</Field>
        <Field label="Content type">{type}</Field>
        <Field label="Kind">{recorded.kind || "api"}</Field>
      </div>
      <Field label="Parameters">
        {params.length === 0 ? (
          <span className="text-[var(--muted)]">none observed</span>
        ) : (
          <ul className="space-y-0.5">
            {params.map((parameter) => {
              const sample = (parameter.values ?? []).filter(Boolean).slice(0, 2).join(", ");
              return (
                <li key={`${parameter.location}:${parameter.name}`}>
                  <span className="font-mono">{parameter.name}</span>
                  <span className="text-[var(--muted)]"> · {parameter.location}</span>
                  {sample ? <span className="text-[var(--muted)]"> · {sample}</span> : null}
                </li>
              );
            })}
          </ul>
        )}
      </Field>
    </div>
  );
}

function ApiChecks({ api }: { api: DastApiAnalysis }) {
  if (api.checks.length === 0) {
    return <p className="text-xs text-[var(--muted)]">No applicable checks for this endpoint.</p>;
  }
  return (
    <div className="space-y-2">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">
        Checks for this API
      </p>
      {api.checks.map((check, i) => (
        <CheckRow key={`${check.check_id}:${check.target}:${i}`} check={check} api={api} />
      ))}
    </div>
  );
}

function ApiCard({
  api,
  defaultOpen,
  inventory,
  apiCalls,
  origin,
}: {
  api: DastApiAnalysis;
  defaultOpen: boolean;
  inventory?: DastInventoryEntry[] | null;
  apiCalls?: DastApiCall[] | null;
  origin?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const method = (api.method || "GET").toUpperCase();
  const label = endpointLabel(api, origin);
  const dest = label.replace(new RegExp(`^${method}\\s+`), "");
  return (
    <div className="rounded-md border border-slate-200 bg-white">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-slate-50"
        aria-expanded={open}
      >
        <span className="w-3 shrink-0 text-[var(--muted)]">{open ? "▾" : "▸"}</span>
        <Pill label={method} styles={METHOD_STYLES} />
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-[var(--ink)]" title={label}>
          {dest}
        </span>
        <span className="shrink-0 text-[11px] text-[var(--muted)]">
          {checkCounts(api).fail} failing · {checkCounts(api).pass} passed
        </span>
        <Pill label={shownOverall(api)} styles={VERDICT_STYLES} />
      </button>

      {open && (
        <div className="space-y-2 border-t border-slate-100 px-3 py-3">
          <p className="text-xs text-[var(--muted)]">{api.summary || OVERALL_HINT[shownOverall(api)] || `Overall ${shownOverall(api)}.`}</p>
          <RecordedSnapshot recorded={recordedFor(api, inventory, apiCalls)} />
          <ApiChecks api={api} />
        </div>
      )}
    </div>
  );
}

/** One finished endpoint in scan order: what discovery recorded, then the checks for that API. */
export function ApiWalkthrough({
  api,
  inventory,
  apiCalls,
  origin,
}: {
  api: DastApiAnalysis;
  inventory?: DastInventoryEntry[] | null;
  apiCalls?: DastApiCall[] | null;
  origin?: string;
}) {
  const method = (api.method || "GET").toUpperCase();
  const label = endpointLabel(api, origin);
  const dest = label.replace(new RegExp(`^${method}\\s+`), "");
  return (
    <section className="dast-fade-in space-y-2 rounded-md border border-slate-200 bg-white p-3" aria-label={label}>
      <div className="flex items-center gap-2">
        <Pill label={method} styles={METHOD_STYLES} />
        <h4 className="min-w-0 flex-1 truncate font-mono text-sm text-[var(--ink)]" title={label}>
          {dest}
        </h4>
        <Pill label={shownOverall(api)} styles={VERDICT_STYLES} />
      </div>
      <p className="text-xs text-[var(--muted)]">
        {checkCounts(api).fail} failing · {checkCounts(api).pass} passed
        {api.tests_sent != null ? ` · ${api.tests_sent} test${api.tests_sent === 1 ? "" : "s"} sent` : ""}
      </p>
      <RecordedSnapshot recorded={recordedFor(api, inventory, apiCalls)} />
      <ApiChecks api={api} />
    </section>
  );
}

export function ApiWalkthroughList({
  apis,
  inventory,
  apiCalls,
  origin,
}: {
  apis: DastApiAnalysis[];
  inventory?: DastInventoryEntry[] | null;
  apiCalls?: DastApiCall[] | null;
  origin?: string;
}) {
  if (apis.length === 0) return null;
  return (
    <div className="space-y-3" aria-label="APIs tested">
      {apis.map((api, i) => (
        <ApiWalkthrough key={`${api.label}:${i}`} api={api} inventory={inventory} apiCalls={apiCalls} origin={origin} />
      ))}
    </div>
  );
}

function Counter({ label, value, tone }: { label: string; value: number | string; tone?: "warn" }) {
  return (
    <div className={`rounded-md border px-2.5 py-1.5 ${tone === "warn" ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"}`}>
      <p className="text-[10px] font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className={`text-sm font-semibold tabular-nums ${tone === "warn" ? "text-amber-800" : "text-[var(--ink)]"}`}>{value}</p>
    </div>
  );
}

/** What the testing stages did overall: passive results, tests sent, what was dropped and why, what the
 *  guardrail changed, and what was left untested. */
function CoverageSummary({ discovery }: { discovery: DastDiscovery }) {
  const active = discovery.active_testing;
  const passive = discovery.passive_analysis;
  const authorization = discovery.authorization;
  if (!active && !passive) return null;
  return (
    <section className="space-y-2.5 rounded-md border border-slate-200 bg-slate-50/60 p-3" aria-label="Coverage">
      <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">What was tested</p>
      {passive && (
        <div>
          <p className="text-xs text-[var(--ink)]">
            <span className="font-medium">Passive analysis</span>: {passive.checks_run} checks over {passive.exchanges} recorded responses (no requests sent), {passive.findings} finding{passive.findings === 1 ? "" : "s"}
            {passive.unverified > 0 ? `, ${passive.unverified} dismissed` : ""}.
          </p>
          {passive.cors?.note && <p className="mt-0.5 text-[11px] text-[var(--muted)]">CORS: {passive.cors.note}</p>}
        </div>
      )}
      {active && (
        <>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Counter label="Endpoints tested" value={`${active.targets_tested} / ${active.targets_total}`} />
            <Counter label="Tests sent" value={active.tests_sent} />
            <Counter label="Unsafe inputs dropped" value={active.dropped_unsafe} tone={active.dropped_unsafe > 0 ? "warn" : undefined} />
            <Counter label="Unknown checks dropped" value={active.dropped_unknown_check} />
            <Counter label="Guardrail downgrades" value={active.guardrail_downgrades} tone={active.guardrail_downgrades > 0 ? "warn" : undefined} />
            <Counter label="Guardrail overrides" value={active.guardrail_overrides} />
            <Counter label="Fallback targets" value={active.fallback_targets} />
            <Counter label="Over the per-target cap" value={active.over_cap} />
          </div>
          {active.ssrf && (
            <p className="text-xs text-[var(--ink)]">
              <span className="font-medium">Out-of-band (SSRF)</span>:{" "}
              {active.ssrf.reason ? active.ssrf.reason : `${active.ssrf.tests} test${active.ssrf.tests === 1 ? "" : "s"}, ${active.ssrf.confirmed} confirmed by callback`}.
            </p>
          )}
          {active.targets_capped > 0 && <p className="text-xs text-amber-800">{active.targets_capped} more endpoint{active.targets_capped === 1 ? " was" : "s were"} not tested (the per-scan cap).</p>}
          {active.not_tested.length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-[var(--muted)]">{active.not_tested.length} endpoint{active.not_tested.length === 1 ? "" : "s"} not tested</summary>
              <ul className="mt-1 space-y-0.5">
                {active.not_tested.map((n) => (
                  <li key={n.label}><span className="font-mono text-[var(--ink)]">{withHttpUrl(n.label, originOf(discovery.target_url))}</span> <span className="text-[var(--muted)]">— {n.reason}</span></li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
      {authorization && (
        <p className="text-xs text-[var(--ink)]">
          <span className="font-medium">Authorization</span>:{" "}
          {authorization.ran ? `${authorization.total_replays} replays, ${authorization.findings} finding${authorization.findings === 1 ? "" : "s"}.` : "did not run."}
          {authorization.degraded_reason ? ` ${authorization.degraded_reason}.` : ""}
        </p>
      )}
    </section>
  );
}

export default function DastAnalysisPanel({
  analysis,
  discovery,
  onClose,
}: {
  analysis: DastApiAnalysis[];
  /** The scan's discovery dict: supplies the coverage summary above the per-endpoint results. */
  discovery?: DastDiscovery | null;
  onClose: () => void;
}) {
  const totals = analysis.reduce(
    (acc, a) => {
      const counts = checkCounts(a);
      acc.fail += counts.fail;
      acc.pass += counts.pass;
      return acc;
    },
    { fail: 0, pass: 0 },
  );
  // Surface failing endpoints first; open the first one by default.
  const ordered = [...analysis].sort((a, b) => {
    const rank = (api: DastApiAnalysis) => (shownOverall(api) === "FAIL" ? 0 : 1);
    return rank(a) - rank(b);
  });

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-[var(--ink)]">API security analysis</h2>
          <p className="truncate text-xs text-[var(--muted)]">
            {analysis.length} endpoint{analysis.length !== 1 ? "s" : ""} tested · {totals.fail} failing ·{" "}
            {totals.pass} passed
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close API security analysis"
          className="rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100"
        >
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-2.5 overflow-auto px-4 py-4">
        {discovery && <CoverageSummary discovery={discovery} />}
        {ordered.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No endpoints were actively tested.</p>
        ) : (
          ordered.map((api, i) => (
            <ApiCard
              key={`${api.label}:${i}`}
              api={api}
              defaultOpen={i === 0}
              inventory={discovery?.inventory}
              apiCalls={discovery?.api_calls}
              origin={originOf(discovery?.target_url)}
            />
          ))
        )}
      </div>
    </div>
  );
}
