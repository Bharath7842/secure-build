"use client";

import type { DastDiscovery, DastInventoryEntry } from "@/lib/types";

const METHOD_STYLES: Record<string, string> = {
  GET: "bg-emerald-50 text-emerald-700 border-emerald-200",
  POST: "bg-blue-50 text-blue-700 border-blue-200",
  PUT: "bg-amber-50 text-amber-700 border-amber-200",
  PATCH: "bg-amber-50 text-amber-700 border-amber-200",
  DELETE: "bg-red-50 text-red-700 border-red-200",
};

const SOURCE_LABEL: Record<DastInventoryEntry["source"], string> = {
  observed: "observed",
  schema: "from schema",
  both: "observed + schema",
};

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: "warn" }) {
  return (
    <div className={`rounded-md border px-3 py-2 ${tone === "warn" ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"}`}>
      <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className={`mt-0.5 truncate text-lg font-semibold ${tone === "warn" ? "text-amber-700" : "text-[var(--ink)]"}`}>{value}</p>
    </div>
  );
}

function MethodTag({ method }: { method: string }) {
  return (
    <span className={`mt-0.5 shrink-0 rounded border px-1.5 py-0.5 font-mono text-[11px] font-medium ${METHOD_STYLES[method] ?? "border-slate-200 bg-slate-50 text-slate-600"}`}>{method}</span>
  );
}

function Heading({ children }: { children: React.ReactNode }) {
  return <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">{children}</h3>;
}

/** What the scan found out about the target (DAST-13-060): its fingerprint, the identities that
 *  got in, pages and forms, every endpoint with where it came from, and the undocumented ones. */
export default function DastDiscoveryPanel({ discovery, onClose }: { discovery: DastDiscovery; onClose: () => void }) {
  const inventory = discovery.inventory ?? [];
  const undocumented = discovery.inventory_diff?.undocumented ?? [];
  const identities = discovery.identities ?? [];
  const labelById = new Map(identities.map((i) => [i.identity_id, i.label]));
  const reached = new Map<string, number>();
  for (const entry of inventory) for (const id of entry.identities) reached.set(id, (reached.get(id) ?? 0) + 1);
  const forms = discovery.pages.flatMap((p) => p.forms.map((f) => ({ page: p.url, form: f })));
  const problem = discovery.connection_error || discovery.authentication_failed || (discovery.stop_reason ? `Stopped: ${discovery.stop_reason}` : "") || discovery.login_error;
  const fp = discovery.fingerprint;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-[var(--ink)]">Discovery results</h2>
          <p className="truncate text-xs text-[var(--muted)]">{discovery.target_url}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close discovery results" className="agent-focus-ring rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100">
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-6 overflow-auto px-4 py-4">
        {problem && <div role="alert" className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">{problem}</div>}

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Pages" value={discovery.pages.length} />
          <Stat label="Forms" value={discovery.forms_count} />
          <Stat label="Endpoints" value={discovery.inventory_count ?? discovery.api_calls.length} />
          <Stat label="Undocumented" value={undocumented.length} tone={undocumented.length > 0 ? "warn" : undefined} />
        </div>
        {discovery.crawl_stop_reason && <p className="text-xs text-[var(--muted)]">Crawl ended: {discovery.crawl_stop_reason}</p>}

        <section>
          <Heading>Fingerprint</Heading>
          {fp ? (
            <dl className="mt-2 grid grid-cols-3 gap-2 text-xs">
              <div className="rounded border border-slate-200 px-2.5 py-1.5"><dt className="text-[var(--muted)]">Shape</dt><dd className="font-medium text-[var(--ink)]">{fp.shape}</dd></div>
              <div className="rounded border border-slate-200 px-2.5 py-1.5"><dt className="text-[var(--muted)]">Authentication</dt><dd className="font-medium text-[var(--ink)]">{fp.auth}</dd></div>
              <div className="rounded border border-slate-200 px-2.5 py-1.5"><dt className="text-[var(--muted)]">API description</dt><dd className="font-medium text-[var(--ink)]">{fp.schema}</dd></div>
              {fp.evidence && fp.evidence.length > 0 && (
                <ul className="col-span-3 list-disc space-y-0.5 pl-5 text-[var(--muted)]">{fp.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
              )}
            </dl>
          ) : (
            <p className="mt-2 text-sm text-[var(--muted)]">The target was not fingerprinted (the scan stopped first).</p>
          )}
        </section>

        <section>
          <Heading>Identities ({identities.length})</Heading>
          {identities.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">No identities were used: the scan ran anonymously.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {identities.map((i) => (
                <li key={i.identity_id} className="flex flex-wrap items-center gap-2 rounded border border-slate-200 px-2.5 py-1.5 text-xs">
                  <span className="font-medium text-[var(--ink)]">{i.label}</span>
                  <span className="text-[var(--muted)]">{i.role_label || i.role} · {i.auth_method}</span>
                  <span className={`rounded border px-1.5 py-0.5 ${i.status === "authenticated" || i.status === "anonymous" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}>{i.status}</span>
                  <span className="ml-auto text-[var(--muted)]">reached {reached.get(i.identity_id) ?? 0} endpoint{(reached.get(i.identity_id) ?? 0) === 1 ? "" : "s"}</span>
                  {i.failure && <span className="w-full text-red-700">{i.failure}</span>}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <Heading>Pages ({discovery.pages.length})</Heading>
          {discovery.pages.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">No pages were crawled{discovery.fingerprint?.shape === "api" ? " (an API-only target has none)" : ""}.</p>
          ) : (
            <table className="mt-2 w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-[var(--muted)]">
                  <th scope="col" className="py-1.5 pr-2 font-medium">Depth</th>
                  <th scope="col" className="py-1.5 pr-2 font-medium">URL</th>
                  <th scope="col" className="py-1.5 pr-2 font-medium">Forms</th>
                  <th scope="col" className="py-1.5 font-medium">Links</th>
                </tr>
              </thead>
              <tbody>
                {discovery.pages.map((page) => (
                  <tr key={page.url} className="border-b border-slate-100 align-top">
                    <td className="py-1.5 pr-2 text-[var(--muted)]">{page.depth}</td>
                    <td className="py-1.5 pr-2">
                      <p className="break-all font-mono text-[var(--ink)]">{page.url}</p>
                      {page.title && <p className="text-[var(--muted)]">{page.title}</p>}
                    </td>
                    <td className="py-1.5 pr-2 text-[var(--ink)]">{page.forms.length}</td>
                    <td className="py-1.5 text-[var(--ink)]">{page.links_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section>
          <Heading>Forms ({forms.length})</Heading>
          {forms.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">No forms were found.</p>
          ) : (
            <ul className="mt-2 space-y-1 text-xs">
              {forms.map((f, i) => {
                const form = f.form as { action?: string; method?: string; inputs?: { name?: string | null; type?: string }[] };
                const fields = (form.inputs ?? []).filter((x) => x.name);
                return (
                  <li key={i} className="space-y-1">
                    <div className="flex items-start gap-2">
                    <MethodTag method={(form.method ?? "GET").toUpperCase()} />
                    <span className="min-w-0 break-all font-mono text-[var(--ink)]">{form.action || f.page}</span>
                    <span className="shrink-0 text-[var(--muted)]">{fields.length} fields</span>
                    </div>
                    {fields.length > 0 && <p className="pl-12 text-[11px] text-[var(--muted)]">Fields inspected: {fields.map((x) => `${x.name}${x.type ? ` (${x.type})` : ""}`).join(", ")}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section>
          <Heading>Endpoints ({inventory.length || discovery.api_calls.length})</Heading>
          {inventory.length === 0 && discovery.api_calls.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">No endpoints were found.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {(inventory.length > 0 ? inventory : []).map((entry) => (
                <li key={`${entry.method}:${entry.path_template}`} className="flex flex-wrap items-start gap-2 text-xs">
                  <MethodTag method={entry.method} />
                  <span className="min-w-0 flex-1 break-all font-mono text-[var(--ink)]">{entry.path_template}</span>
                  <span className={`shrink-0 rounded border px-1.5 py-0.5 ${entry.source === "both" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : entry.source === "schema" ? "border-blue-200 bg-blue-50 text-blue-700" : "border-slate-200 bg-slate-50 text-slate-600"}`}>
                    {SOURCE_LABEL[entry.source]}
                  </span>
                  {entry.user_supplied && <span className="shrink-0 rounded border border-violet-200 bg-violet-50 px-1.5 py-0.5 text-violet-700">you added</span>}
                  {entry.state_changing && <span className="shrink-0 rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-amber-800">changes state</span>}
                  {entry.status_code != null && <span className="shrink-0 text-[var(--muted)]">{entry.status_code}</span>}
                  {entry.identities.length > 0 && <span className="shrink-0 text-[var(--muted)]">{entry.identities.map((id) => labelById.get(id) ?? id).join(", ")}</span>}
                </li>
              ))}
              {inventory.length === 0 &&
                discovery.api_calls.map((call) => (
                  <li key={`${call.method}:${call.url}`} className="flex items-start gap-2 text-xs">
                    <MethodTag method={call.method} />
                    <span className="min-w-0 flex-1 break-all font-mono text-[var(--ink)]">{call.url}</span>
                    {call.status_code != null && <span className="shrink-0 text-[var(--muted)]">{call.status_code}</span>}
                  </li>
                ))}
            </ul>
          )}
        </section>

        <section>
          <Heading>Undocumented endpoints ({undocumented.length})</Heading>
          {discovery.inventory_diff && !discovery.inventory_diff.compared ? (
            <p className="mt-2 text-sm text-[var(--muted)]">Not compared: {discovery.inventory_diff.reason || "no API description was found"}.</p>
          ) : undocumented.length === 0 ? (
            <p className="mt-2 text-sm text-[var(--muted)]">Every observed API endpoint is in the published description.</p>
          ) : (
            <ul className="mt-2 space-y-1">
              {undocumented.map((e) => (
                <li key={`${e.method}:${e.path_template}`} className="flex items-start gap-2 text-xs">
                  <MethodTag method={e.method} />
                  <span className="min-w-0 break-all font-mono text-[var(--ink)]">{e.path_template}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        {discovery.failed_urls.length > 0 && (
          <section>
            <Heading>Failed URLs ({discovery.failed_urls.length})</Heading>
            <ul className="mt-2 space-y-1 text-xs">
              {discovery.failed_urls.map((item) => (
                <li key={item.url} className="break-all">
                  <span className="font-mono text-[var(--ink)]">{item.url}</span>
                  <span className="text-[var(--muted)]"> — {item.error}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {discovery.warnings.length > 0 && (
          <section>
            <Heading>Warnings ({discovery.warnings.length})</Heading>
            <ul className="mt-2 space-y-1 text-xs text-[var(--muted)]">
              {discovery.warnings.map((warning, index) => (
                <li key={index}>
                  {warning.event ? `${warning.event}: ` : ""}
                  {warning.details}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}
