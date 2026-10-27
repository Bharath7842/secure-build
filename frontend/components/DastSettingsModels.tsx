"use client";

import { useState } from "react";

import { ApiError, api } from "@/lib/api";
import { defaultDastModel } from "@/lib/dastModels";
import type { DastModelProvider, DastModelRoute, DastModelRouteTestResult, DastModelTask, DastProviders } from "@/lib/types";
import { useModelCatalog } from "@/lib/useModelCatalog";

const TASK_LABEL: Record<DastModelTask, string> = {
  fingerprint: "Fingerprinting the target",
  crawl_plan: "Planning the crawl",
  login_selectors: "Finding login fields",
  normalize_endpoints: "Cleaning up your API list",
  plan: "Planning adaptive tests",
  construct: "Constructing tests",
  rule: "Ruling on test results",
  narrate: "Narrating the scan",
};
const PROVIDERS: DastModelProvider[] = ["ollama", "bedrock", "openai", "anthropic", "claude_cli"];

const field = "agent-focus-ring w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-[var(--ink)]";

interface Props {
  routes: DastModelRoute[];
  providers: DastProviders | null;
  onSaved: (routes: DastModelRoute[]) => void;
}

/** Provider and model per task (DAST-15-010). Provider keys are read-only here: they live in the
 *  environment, and this page only shows whether each one is set. */
export default function DastSettingsModels({ routes, providers, onSaved }: Props) {
  const { dastOptions, dastProviders } = useModelCatalog();
  const [draft, setDraft] = useState<DastModelRoute[]>(routes);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [tests, setTests] = useState<Record<string, DastModelRouteTestResult | "running">>({});
  const configured = new Map((providers?.providers ?? []).map((p) => [p.provider, p]));
  const dirty = JSON.stringify(draft.map((r) => [r.task, r.provider, r.model])) !== JSON.stringify(routes.map((r) => [r.task, r.provider, r.model]));

  function edit(task: DastModelTask, patch: Partial<DastModelRoute>) {
    setDraft((rows) =>
      rows.map((r) => {
        if (r.task !== task) return r;
        const next = { ...r, ...patch };
        if (patch.provider && patch.provider !== r.provider && patch.model === undefined) {
          next.model = defaultDastModel(patch.provider, null, providers, dastOptions(patch.provider));
        }
        return next;
      }),
    );
    setTests((t) => {
      const next = { ...t };
      delete next[task];
      return next;
    });
  }

  async function save() {
    setSaving(true);
    setMessage(null);
    try {
      const saved = await api.dast.modelRouting.update(draft.map(({ task, provider, model }) => ({ task, provider, model })));
      setDraft(saved);
      onSaved(saved);
      setMessage({ kind: "ok", text: "Saved. New scans use this routing; scans already running keep theirs." });
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof ApiError ? err.message : "Could not save." });
    } finally {
      setSaving(false);
    }
  }

  async function test(route: DastModelRoute) {
    setTests((t) => ({ ...t, [route.task]: "running" }));
    try {
      const result = await api.dast.modelRouting.test({ task: route.task, provider: route.provider, model: route.model });
      setTests((t) => ({ ...t, [route.task]: result }));
    } catch (err) {
      setTests((t) => ({ ...t, [route.task]: { ok: false, task: route.task, latency_ms: null, error: err instanceof ApiError ? err.message : "Test failed." } }));
    }
  }

  return (
    <section aria-labelledby="models-heading" className="rounded-lg border border-slate-200 bg-white p-6">
      <h2 id="models-heading" className="text-base font-semibold text-[var(--ink)]">Models</h2>
      <p className="mt-1 text-sm text-[var(--muted)]">Which provider and model each part of a scan uses. Test sends one harmless request; it never uses scan data.</p>

      <ul className="mt-4 flex flex-wrap gap-2" aria-label="Provider credentials">
        {(providers?.providers ?? []).map((p) => (
          <li key={p.provider} className={`rounded-full border px-2.5 py-1 text-xs ${p.configured ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-slate-200 bg-slate-50 text-slate-600"}`} title={p.detail}>
            <span className="font-medium">{p.provider}</span>: {p.provider === "claude_cli" ? (p.configured ? "found" : "not found") : p.configured ? "key set" : "not set"}
          </li>
        ))}
      </ul>
      <p className="mt-1.5 text-xs text-[var(--muted)]">Keys are set in the server environment and cannot be viewed or changed here.</p>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left text-sm">
          <thead>
            <tr className="border-b border-slate-200 text-xs text-[var(--muted)]">
              <th scope="col" className="py-2 pr-3 font-medium">Task</th>
              <th scope="col" className="py-2 pr-3 font-medium">Provider</th>
              <th scope="col" className="py-2 pr-3 font-medium">Model</th>
              <th scope="col" className="py-2 font-medium"><span className="sr-only">Test</span></th>
            </tr>
          </thead>
          <tbody>
            {draft.map((route) => {
              const result = tests[route.task];
              const missing = configured.get(route.provider)?.configured === false;
              return (
                <tr key={route.task} className="border-b border-slate-100 align-top">
                  <td className="py-2 pr-3 text-[var(--ink)]">
                    {TASK_LABEL[route.task] ?? route.task}
                    {route.overridden && <span className="ml-1.5 rounded bg-blue-50 px-1.5 py-0.5 text-[10px] text-blue-700">edited</span>}
                  </td>
                  <td className="py-2 pr-3">
                    <select aria-label={`Provider for ${TASK_LABEL[route.task]}`} className={field} value={route.provider} onChange={(e) => edit(route.task, { provider: e.target.value as DastModelProvider })}>
                      {dastProviders(PROVIDERS, route.provider).map((p) => <option key={p} value={p}>{p}</option>)}
                    </select>
                    {missing && <p className="mt-1 text-xs text-amber-800">{route.provider === "claude_cli" ? "The claude CLI was not found on the server." : "No key set for this provider."}</p>}
                  </td>
                  <td className="py-2 pr-3">
                    <select
                      aria-label={`Model for ${TASK_LABEL[route.task]}`}
                      className={`${field} font-mono`}
                      value={route.model}
                      onChange={(e) => edit(route.task, { model: e.target.value })}
                    >
                      {dastOptions(route.provider, route.model).map((o) => (
                        <option key={o.id} value={o.id}>
                          {o.label}
                        </option>
                      ))}
                      {route.model && !dastOptions(route.provider, route.model).some((o) => o.id === route.model) && (
                        <option value={route.model}>{route.model}</option>
                      )}
                    </select>
                  </td>
                  <td className="py-2">
                    <button type="button" disabled={result === "running" || !route.model.trim()} onClick={() => test(route)} className="agent-focus-ring rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-[var(--ink)] hover:bg-slate-50 disabled:opacity-50">
                      {result === "running" ? "Testing…" : "Test"}
                    </button>
                    {result && result !== "running" && (
                      <p role="status" className={`mt-1 text-xs ${result.ok ? "text-emerald-700" : "text-red-700"}`}>
                        {result.ok ? `Works (${result.latency_ms ?? "?"} ms)` : `Failed: ${result.error ?? "unknown error"}`}
                      </p>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button type="button" onClick={save} disabled={!dirty || saving} className="agent-focus-ring rounded-md bg-[var(--accent)] px-3.5 py-2 text-sm font-medium text-white disabled:opacity-50">
          {saving ? "Saving…" : "Save routing"}
        </button>
        {dirty && <button type="button" onClick={() => setDraft(routes)} className="agent-focus-ring rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100">Discard changes</button>}
        {message && <p role={message.kind === "error" ? "alert" : "status"} className={`text-sm ${message.kind === "error" ? "text-red-700" : "text-emerald-700"}`}>{message.text}</p>}
      </div>
    </section>
  );
}
