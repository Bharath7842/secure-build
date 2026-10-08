"use client";

import { useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import { ApiError, api } from "@/lib/api";
import type { DastSettings, DastSettingsUpdate } from "@/lib/types";

const field = "agent-focus-ring w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-[var(--ink)]";

function SourceTag({ edited }: { edited: boolean }) {
  return <span className={`ml-1.5 rounded px-1.5 py-0.5 text-[10px] ${edited ? "bg-blue-50 text-blue-700" : "bg-slate-100 text-slate-500"}`}>{edited ? "edited" : "environment default"}</span>;
}

type NumericKey = "max_runtime_minutes" | "max_depth" | "max_pages" | "max_per_pattern" | "rate_limit_per_sec" | "max_targets" | "max_tests_per_target" | "browser_probe_max_inputs";
const NUMERIC: NumericKey[] = ["max_runtime_minutes", "max_depth", "max_pages", "max_per_pattern", "rate_limit_per_sec", "max_targets", "max_tests_per_target", "browser_probe_max_inputs"];

/** Scan defaults (DAST-15-020): limits, scope mode, rate, the safe-mode default and the OAST
 *  callback address. Every value shows whether an edit or the environment decides it. */
export default function DastSettingsDefaults({ settings, onSaved }: { settings: DastSettings; onSaved: (next: DastSettings) => void }) {
  const [values, setValues] = useState<Record<NumericKey, string>>(() => Object.fromEntries(NUMERIC.map((k) => [k, String(settings[k])])) as Record<NumericKey, string>);
  const [mode, setMode] = useState(settings.same_domain_mode);
  const [safe, setSafe] = useState(settings.safe_mode_default);
  const [probe, setProbe] = useState(settings.browser_probe_enabled);
  const [markerPosts, setMarkerPosts] = useState(settings.browser_marker_posts);
  const [oast, setOast] = useState("");
  const [clearOast, setClearOast] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const { confirm, dialog } = useConfirmDialog();

  async function save() {
    const patch: DastSettingsUpdate = {};
    const problems: string[] = [];
    for (const key of NUMERIC) {
      if (values[key].trim() === "") {
        problems.push(`${settings.limits[key]?.label ?? key}: enter a number`);
        continue;
      }
      const n = Number(values[key]);
      if (!Number.isFinite(n)) {
        problems.push(`${settings.limits[key]?.label ?? key}: must be a number`);
        continue;
      }
      if (n !== settings[key]) patch[key] = n;
    }
    if (problems.length > 0) {
      setMessage({ kind: "error", text: problems.join("; ") });
      return;
    }
    if (mode !== settings.same_domain_mode) patch.same_domain_mode = mode;
    if (probe !== settings.browser_probe_enabled) patch.browser_probe_enabled = probe;
    if (markerPosts !== settings.browser_marker_posts) {
      patch.browser_marker_posts = markerPosts;
      if (markerPosts) {
        const ok = await confirm({
          title: "Allow stored-XSS marker submits by default?",
          message: "New scans of a disposable target will POST an inert marker into forms and look for it later. The marker changes data on that target. Scans of a target that is not disposable still refuse it.",
          confirmLabel: "Allow marker submits",
        });
        if (!ok) return;
        patch.confirm_unsafe = true;
      }
    }
    if (safe !== settings.safe_mode_default) {
      patch.safe_mode_default = safe;
      if (!safe) {
        const ok = await confirm({
          title: "Turn safe mode off by default?",
          message: "New scans will be allowed to send requests that change data on the target. Only do this when every target you scan is disposable.",
          confirmLabel: "Turn off safe mode",
        });
        if (!ok) return;
        patch.confirm_unsafe = true;
      }
    }
    if (clearOast) patch.oast_callback_url = "";
    else if (oast.trim()) patch.oast_callback_url = oast.trim();
    if (Object.keys(patch).length === 0) {
      setMessage({ kind: "ok", text: "Nothing changed." });
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const next = await api.dast.settings.update(patch);
      onSaved(next);
      setOast("");
      setClearOast(false);
      setMessage({ kind: "ok", text: "Saved. These apply to scans created from now on." });
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof ApiError ? err.message : "Could not save." });
    } finally {
      setSaving(false);
    }
  }

  const overridden = new Set(settings.overridden);

  return (
    <section aria-labelledby="defaults-heading" className="rounded-lg border border-slate-200 bg-white p-6">
      {dialog}
      <h2 id="defaults-heading" className="text-base font-semibold text-[var(--ink)]">Scan defaults</h2>
      <p className="mt-1 text-sm text-[var(--muted)]">{settings.applies_to}</p>

      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        {NUMERIC.map((key) => {
          const limit = settings.limits[key];
          return (
            <div key={key}>
              <label htmlFor={`def-${key}`} className="text-sm font-medium text-[var(--ink)]">{limit?.label ?? key}<SourceTag edited={overridden.has(key)} /></label>
              <input id={`def-${key}`} type="number" inputMode="decimal" min={limit?.min} max={limit?.max} step="any" className={`${field} mt-1`} value={values[key]} onChange={(e) => setValues((v) => ({ ...v, [key]: e.target.value }))} aria-describedby={`def-${key}-hint`} />
              {limit && <p id={`def-${key}-hint`} className="mt-0.5 text-xs text-[var(--muted)]">Between {limit.min} and {limit.max}.</p>}
            </div>
          );
        })}
        <div>
          <label htmlFor="def-mode" className="text-sm font-medium text-[var(--ink)]">Scope<SourceTag edited={overridden.has("same_domain_mode")} /></label>
          <select id="def-mode" className={`${field} mt-1`} value={mode} onChange={(e) => setMode(e.target.value as DastSettings["same_domain_mode"])}>
            <option value="exact">Exact host only</option>
            <option value="root-domain">The whole registrable domain</option>
          </select>
          <p className="mt-0.5 text-xs text-[var(--muted)]">Shared-hosting suffixes (such as github.io) are never treated as one site.</p>
        </div>
      </div>

      <div className="mt-5 rounded-md border border-slate-200 p-3">
        <label className="flex items-start gap-2.5 text-sm">
          <input type="checkbox" className="agent-focus-ring mt-0.5" checked={safe} onChange={(e) => setSafe(e.target.checked)} />
          <span>
            <span className="font-medium text-[var(--ink)]">Safe mode on by default<SourceTag edited={overridden.has("safe_mode_default")} /></span>
            <span className="block text-xs text-[var(--muted)]">Safe mode refuses requests that change data. Turning it off asks you to confirm.</span>
          </span>
        </label>
        {!safe && <p role="alert" className="mt-2 text-xs font-medium text-red-700">New scans will be able to modify data on their targets.</p>}
      </div>

      <div className="mt-3 rounded-md border border-slate-200 p-3 space-y-3">
        <label className="flex items-start gap-2.5 text-sm">
          <input type="checkbox" className="agent-focus-ring mt-0.5" checked={probe} onChange={(e) => setProbe(e.target.checked)} />
          <span>
            <span className="font-medium text-[var(--ink)]">Probe inputs in the browser<SourceTag edited={overridden.has("browser_probe_enabled")} /></span>
            <span className="block text-xs text-[var(--muted)]">Type an inert marker into crawled fields and URL parameters. This sends GET requests only.</span>
          </span>
        </label>
        <label className="flex items-start gap-2.5 text-sm">
          <input type="checkbox" className="agent-focus-ring mt-0.5" checked={markerPosts} onChange={(e) => setMarkerPosts(e.target.checked)} />
          <span>
            <span className="font-medium text-[var(--ink)]">Allow stored-XSS marker submits<SourceTag edited={overridden.has("browser_marker_posts")} /></span>
            <span className="block text-xs text-[var(--muted)]">POST the marker into forms on disposable targets, then revisit pages. Off unless you confirm.</span>
          </span>
        </label>
        {markerPosts && <p role="alert" className="text-xs font-medium text-red-700">New scans of a disposable target will write a marker into stored fields.</p>}
      </div>

      <div className="mt-5">
        <label htmlFor="def-oast" className="text-sm font-medium text-[var(--ink)]">Out-of-band callback address</label>
        <p className="text-xs text-[var(--muted)]">{settings.oast_configured ? "An address is configured. It is never shown again; enter a new one to replace it." : "None configured. Without one, out-of-band checks (such as SSRF) are skipped and reported as such."}</p>
        <input id="def-oast" type="url" autoComplete="off" placeholder={settings.oast_configured ? "•••••• (write-only)" : "https://callbacks.example.com"} className={`${field} mt-1`} value={oast} disabled={clearOast} onChange={(e) => setOast(e.target.value)} />
        {settings.oast_configured && (
          <label className="mt-1.5 flex items-center gap-2 text-xs text-[var(--muted)]">
            <input type="checkbox" className="agent-focus-ring" checked={clearOast} onChange={(e) => setClearOast(e.target.checked)} /> Remove the configured address
          </label>
        )}
      </div>

      <div className="mt-5 flex items-center gap-3">
        <button type="button" onClick={save} disabled={saving} className="agent-focus-ring rounded-md bg-[var(--accent)] px-3.5 py-2 text-sm font-medium text-white disabled:opacity-50">{saving ? "Saving…" : "Save defaults"}</button>
        {message && <p role={message.kind === "error" ? "alert" : "status"} className={`text-sm ${message.kind === "error" ? "text-red-700" : "text-emerald-700"}`}>{message.text}</p>}
      </div>
    </section>
  );
}
