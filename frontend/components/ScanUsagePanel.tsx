"use client";

import type { UsageSummary } from "@/lib/types";
import {
  estimateStepCostUsd,
  formatCostUsd,
  formatPricePerMtok,
  formatTokenCount,
  llmLabel,
  stepLabel,
} from "@/lib/formatUsage";

interface ScanUsagePanelProps {
  usage: UsageSummary;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white px-3 py-2.5">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className="mt-1 text-lg font-semibold tabular-nums text-[var(--ink)]">{value}</p>
    </div>
  );
}

export default function ScanUsagePanel({ usage }: ScanUsagePanelProps) {
  const steps = Object.entries(usage.by_step ?? {}).sort(([a], [b]) => a.localeCompare(b));
  const activeProvider = usage.active_provider ?? usage.provider;
  const activeModel = usage.active_model ?? usage.model;
  const switched = Boolean(usage.fallback_switched);
  const estimated = Boolean(usage.estimated);

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-md border border-slate-200 border-t-2 border-t-violet-500 bg-gradient-to-br from-white via-white to-violet-50/40 p-5">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
          LLM token usage
        </h3>
        <p className="mt-2 text-sm text-[var(--ink)]">
          Totals for this scan across {formatTokenCount(usage.call_count)} LLM call
          {usage.call_count === 1 ? "" : "s"}.
        </p>

        {estimated && (
          <p className="mt-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            Token counts are estimated (provider did not return exact usage metadata).
          </p>
        )}

        {((usage.result_cache_hits ?? 0) > 0 || (usage.cache_read_input_tokens ?? 0) > 0) && (
          <p className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800">
            {(usage.result_cache_hits ?? 0) > 0 && (
              <>
                {formatTokenCount(usage.result_cache_hits ?? 0)} response
                {usage.result_cache_hits === 1 ? "" : "s"} reused from earlier scans of unchanged
                code (~{formatTokenCount(usage.result_cache_saved_tokens ?? 0)} tokens not re-sent).{" "}
              </>
            )}
            {(usage.cache_read_input_tokens ?? 0) > 0 && (
              <>
                {formatTokenCount(usage.cache_read_input_tokens ?? 0)} input tokens were served from
                the provider prompt cache at a reduced rate (still counted above).
              </>
            )}
          </p>
        )}

        {switched && (
          <p className="mt-2 rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-800">
            Bedrock spend reached the configured cutoff — remaining calls used{" "}
            {llmLabel(usage.fallback_switched ? activeProvider : usage.provider, activeModel, "paren")}.
          </p>
        )}

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric label="Input tokens" value={formatTokenCount(usage.input_tokens)} />
          <Metric label="Output tokens" value={formatTokenCount(usage.output_tokens)} />
          <Metric label="Total tokens" value={formatTokenCount(usage.total_tokens)} />
          <Metric label="Estimated cost" value={formatCostUsd(usage.cost_usd)} />
        </div>

        <dl className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-[var(--muted)]">Primary provider</dt>
            <dd className="font-medium text-[var(--ink)]">
              {llmLabel(usage.provider, usage.model)}
            </dd>
          </div>
          <div>
            <dt className="text-[var(--muted)]">Active at end</dt>
            <dd className="font-medium text-[var(--ink)]">
              {llmLabel(activeProvider, activeModel)}
            </dd>
          </div>
          {usage.input_price_per_mtok != null && usage.output_price_per_mtok != null && (
            <div className="sm:col-span-2">
              <dt className="text-[var(--muted)]">Pricing (primary provider)</dt>
              <dd className="font-medium text-[var(--ink)]">
                Input {formatPricePerMtok(usage.input_price_per_mtok)} · Output{" "}
                {formatPricePerMtok(usage.output_price_per_mtok)}
              </dd>
            </div>
          )}
          {usage.cost_cutoff_usd != null && usage.cost_cutoff_usd > 0 && (
            <div>
              <dt className="text-[var(--muted)]">Cost cutoff</dt>
              <dd className="font-medium text-[var(--ink)]">{formatCostUsd(usage.cost_cutoff_usd)}</dd>
            </div>
          )}
        </dl>
      </section>

      {steps.length > 0 && (
        <section className="rounded-md border border-slate-200 p-5">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
            By pipeline step
          </h3>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[32rem] text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                  <th className="pb-2 pr-4 font-medium">Step</th>
                  <th className="pb-2 pr-4 font-medium text-right">Calls</th>
                  <th className="pb-2 pr-4 font-medium text-right">Input</th>
                  <th className="pb-2 pr-4 font-medium text-right">Output</th>
                  <th className="pb-2 font-medium text-right">Est. cost</th>
                </tr>
              </thead>
              <tbody>
                {steps.map(([step, row]) => (
                  <tr key={step} className="border-b border-slate-100 last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--ink)]">{stepLabel(step)}</td>
                    <td className="py-2.5 pr-4 text-right tabular-nums text-[var(--ink)]">
                      {row.calls}
                      {(row.result_cache_hits ?? 0) > 0 && (
                        <span className="text-[var(--muted)]"> +{row.result_cache_hits} reused</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-4 text-right tabular-nums text-[var(--muted)]">
                      {formatTokenCount(row.input_tokens)}
                    </td>
                    <td className="py-2.5 pr-4 text-right tabular-nums text-[var(--muted)]">
                      {formatTokenCount(row.output_tokens)}
                    </td>
                    <td className="py-2.5 text-right tabular-nums text-[var(--ink)]">
                      {formatCostUsd(estimateStepCostUsd(row, usage))}
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr className="border-t border-slate-200 font-medium">
                  <td className="pt-3 pr-4 text-[var(--ink)]">Total</td>
                  <td className="pt-3 pr-4 text-right tabular-nums">{usage.call_count}</td>
                  <td className="pt-3 pr-4 text-right tabular-nums text-[var(--muted)]">
                    {formatTokenCount(usage.input_tokens)}
                  </td>
                  <td className="pt-3 pr-4 text-right tabular-nums text-[var(--muted)]">
                    {formatTokenCount(usage.output_tokens)}
                  </td>
                  <td className="pt-3 text-right tabular-nums">{formatCostUsd(usage.cost_usd)}</td>
                </tr>
              </tfoot>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
