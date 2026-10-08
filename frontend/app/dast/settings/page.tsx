"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import DastCustomRulesEditor from "@/components/DastCustomRulesEditor";
import DastRuleManager from "@/components/DastRuleManager";
import DastSettingsDefaults from "@/components/DastSettingsDefaults";
import DastSettingsModels from "@/components/DastSettingsModels";
import DastVulnerabilityCoveragePanel from "@/components/DastVulnerabilityCoverage";
import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";
import type { DastModelRoute, DastProviders, DastSettings } from "@/lib/types";

export default function DastSettingsPage() {
  const [settings, setSettings] = useState<DastSettings | null>(null);
  const [routes, setRoutes] = useState<DastModelRoute[] | null>(null);
  const [providers, setProviders] = useState<DastProviders | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rulesKey, setRulesKey] = useState(0);

  useEffect(() => {
    let active = true;
    Promise.all([api.dast.settings.get(), api.dast.modelRouting.get(), api.dast.providers()])
      .then(([s, r, p]) => {
        if (!active) return;
        setSettings(s);
        setRoutes(r);
        setProviders(p);
      })
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Could not load DAST settings."));
    return () => {
      active = false;
    };
  }, []);

  return (
    <PageContainer>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <Link href="/dast" className="text-sm font-medium text-[var(--accent)] hover:underline">← DAST</Link>
          <h1 className="mt-2 text-2xl font-semibold text-[var(--ink)]">DAST settings</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">Defaults for every DAST scan. Changes apply to scans created afterwards.</p>
        </div>

        {error && <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
        {!settings && !error && <p role="status" className="text-sm text-[var(--muted)]">Loading settings…</p>}

        {settings && routes && <DastSettingsModels routes={routes} providers={providers} onSaved={setRoutes} />}
        {settings && <DastSettingsDefaults settings={settings} onSaved={setSettings} />}

        {settings && (
          <section aria-labelledby="rules-heading" className="rounded-lg border border-slate-200 bg-white p-6">
            <h2 id="rules-heading" className="text-base font-semibold text-[var(--ink)]">Rules</h2>
            <div className="mt-3"><DastRuleManager refreshKey={rulesKey} /></div>
          </section>
        )}
        {settings && (
          <section aria-labelledby="custom-heading" className="rounded-lg border border-slate-200 bg-white p-6">
            <h2 id="custom-heading" className="text-base font-semibold text-[var(--ink)]">Custom rules</h2>
            <p className="mb-3 mt-1 text-sm text-[var(--muted)]">Rules your team writes in YAML. They form their own pack, which is on by default.</p>
            <DastCustomRulesEditor onChanged={() => setRulesKey((k) => k + 1)} />
          </section>
        )}
        {settings && (
          <section aria-labelledby="coverage-heading" className="rounded-lg border border-slate-200 bg-white p-6">
            <h2 id="coverage-heading" className="text-base font-semibold text-[var(--ink)]">Vulnerability coverage</h2>
            <div className="mt-3"><DastVulnerabilityCoveragePanel /></div>
          </section>
        )}
      </div>
    </PageContainer>
  );
}
