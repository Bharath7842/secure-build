"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { formatCostUsd, formatTokenCount, llmLabel, providerLabel, stepLabel } from "@/lib/formatUsage";
import type { LlmMonitor, LlmMonitorPoint, LlmMonitorRange } from "@/lib/types";

const RANGES: { value: LlmMonitorRange; label: string }[] = [
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
  { value: "90d", label: "90 days" },
];

type SeriesMetric = "cost_usd" | "tokens" | "calls";
const SERIES_METRICS: { value: SeriesMetric; label: string }[] = [
  { value: "cost_usd", label: "Cost" },
  { value: "tokens", label: "Tokens" },
  { value: "calls", label: "Calls" },
];

function seriesValue(point: LlmMonitorPoint, metric: SeriesMetric): number {
  if (metric === "tokens") return point.input_tokens + point.output_tokens;
  return point[metric];
}

function formatSeriesValue(value: number, metric: SeriesMetric): string {
  return metric === "cost_usd" ? formatCostUsd(value) : formatTokenCount(value);
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(value > 0 && value < 0.1 ? 1 : 0)}%`;
}

function bucketLabel(iso: string, granularity: "hour" | "day"): string {
  const date = new Date(iso);
  return granularity === "hour"
    ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function modelName(provider: string | null | undefined, model: string | null | undefined): string {
  return model ? llmLabel(provider ?? undefined, model) : providerLabel(provider ?? undefined);
}

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white px-4 py-3">
      <p className="text-xs font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p className="mt-1 text-xl font-semibold tabular-nums text-[var(--ink)]">{value}</p>
      {hint && <p className="mt-0.5 text-xs text-[var(--muted)]">{hint}</p>}
    </div>
  );
}

function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex flex-wrap gap-1 rounded-md border border-slate-200 bg-white p-1">
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(option.value)}
            className={`min-h-9 rounded px-3 text-sm transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent)] ${
              active ? "bg-[var(--ink)] text-white" : "text-[var(--muted)] hover:bg-slate-100 hover:text-[var(--ink)]"
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

function Section({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="rounded-md border border-slate-200 bg-white p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">{title}</h2>
        {action}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function UsageChart({ data }: { data: LlmMonitor }) {
  const hasCost = data.series.some((p) => p.cost_usd > 0);
  const [metric, setMetric] = useState<SeriesMetric>(hasCost ? "cost_usd" : "tokens");
  const values = data.series.map((p) => seriesValue(p, metric));
  const max = Math.max(0, ...values);
  const total = values.reduce((a, b) => a + b, 0);
  const peakIndex = max > 0 ? values.indexOf(max) : -1;
  const labelEvery = Math.max(1, Math.ceil(data.series.length / 8));
  const summary =
    total === 0
      ? "No LLM usage in this period."
      : `${formatSeriesValue(total, metric)} in total; peak ${formatSeriesValue(max, metric)} on ${bucketLabel(
          data.series[peakIndex].bucket,
          data.granularity,
        )}.`;

  return (
    <Section
      title={data.granularity === "hour" ? "Usage per hour" : "Usage per day"}
      action={<Segmented label="Chart metric" options={SERIES_METRICS} value={metric} onChange={setMetric} />}
    >
      <p className="text-sm text-[var(--ink)]">{summary}</p>
      <div className="mt-4 flex h-48 items-end gap-[3px] border-b border-slate-200" role="img" aria-label={`Bar chart. ${summary}`}>
        {data.series.map((point, i) => {
          const value = values[i];
          const height = max > 0 ? Math.max(value > 0 ? 2 : 0, (value / max) * 100) : 0;
          return (
            <div key={point.bucket} className="group relative flex h-full min-w-0 flex-1 items-end">
              <div
                className="w-full rounded-t-sm bg-[var(--accent)] opacity-80 transition-opacity group-hover:opacity-100"
                style={{ height: `${height}%` }}
                title={`${bucketLabel(point.bucket, data.granularity)}: ${formatSeriesValue(value, metric)} · ${point.scans} scan${
                  point.scans === 1 ? "" : "s"
                }`}
              />
            </div>
          );
        })}
      </div>
      <div className="mt-1.5 flex gap-[3px]" aria-hidden>
        {data.series.map((point, i) => (
          <span key={point.bucket} className="min-w-0 flex-1 truncate text-center text-[11px] text-[var(--muted)]">
            {i % labelEvery === 0 ? bucketLabel(point.bucket, data.granularity) : ""}
          </span>
        ))}
      </div>
    </Section>
  );
}

function Table({ head, rows, empty }: { head: string[]; rows: React.ReactNode[][]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-[var(--muted)]">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[32rem] text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
            {head.map((h, i) => (
              <th key={h} scope="col" className={`py-2 pr-4 font-medium ${i > 0 ? "text-right" : ""}`}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cells, r) => (
            <tr key={r} className="border-b border-slate-100 last:border-0">
              {cells.map((cell, i) => (
                <td key={i} className={`py-2 pr-4 text-[var(--ink)] ${i > 0 ? "text-right tabular-nums" : ""}`}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function LlmMonitorDashboard() {
  const [range, setRange] = useState<LlmMonitorRange>("7d");
  const [data, setData] = useState<LlmMonitor | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The range whose request has finished (successfully or not); anything else is loading.
  const [settledRange, setSettledRange] = useState<LlmMonitorRange | null>(null);
  const loading = settledRange !== range;

  useEffect(() => {
    let active = true;
    api.monitor
      .llm(range)
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Could not load LLM usage."))
      .finally(() => active && setSettledRange(range));
    return () => {
      active = false;
    };
  }, [range]);

  const t = data?.totals;
  const typeSummary = useMemo(
    () => (data?.by_type ?? []).map((b) => `${b.scans} ${b.scan_type.toUpperCase()}`).join(" · "),
    [data],
  );

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl text-[var(--ink)]">LLM observability</h1>
          <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
            Model calls, tokens and cost across every scan, from each scan&apos;s own usage record.
          </p>
        </div>
        <Segmented label="Time range" options={RANGES} value={range} onChange={setRange} />
      </div>

      {error && (
        <p className="mt-6 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
          {error}
        </p>
      )}

      {!data && loading && !error && (
        <div className="mt-8 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" aria-busy="true" aria-label="Loading">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-[76px] animate-pulse rounded-md border border-slate-200 bg-white" />
          ))}
        </div>
      )}

      {data && t && (
        <div className={`mt-8 space-y-6 transition-opacity ${loading ? "opacity-60" : ""}`} aria-busy={loading}>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Metric label="Scans" value={formatTokenCount(t.scans)} hint={typeSummary || undefined} />
            <Metric label="LLM calls" value={formatTokenCount(t.llm_calls)} hint={`${formatTokenCount(t.scans_with_llm)} scans used a model`} />
            <Metric label="Input tokens" value={formatTokenCount(t.input_tokens)} />
            <Metric label="Output tokens" value={formatTokenCount(t.output_tokens)} />
            <Metric label="Cost" value={formatCostUsd(t.cost_usd)} hint={t.estimated_scans ? "some token counts estimated" : undefined} />
            <Metric
              label="Reused answers"
              value={formatPercent(t.result_cache_hit_rate)}
              hint={`${formatTokenCount(t.result_cache_saved_tokens)} tokens not re-sent`}
            />
          </div>

          {(t.fallback_scans > 0 || t.budget_exhausted_scans > 0 || t.failed_scans > 0) && (
            <p className="text-sm text-[var(--muted)]">
              {[
                t.fallback_scans > 0 && `${t.fallback_scans} scan${t.fallback_scans === 1 ? "" : "s"} switched to the fallback model`,
                t.budget_exhausted_scans > 0 && `${t.budget_exhausted_scans} hit the spend cutoff`,
                t.failed_scans > 0 && `${t.failed_scans} failed`,
              ]
                .filter(Boolean)
                .join(" · ")}
              .
            </p>
          )}

          <UsageChart key={`${data.range}-${data.from}`} data={data} />

          <div className="grid gap-6 xl:grid-cols-2">
            <Section title="By model">
              <Table
                head={["Model", "Scans", "Calls", "Tokens", "Cost"]}
                empty="No model calls in this period."
                rows={data.by_model.map((m) => [
                  modelName(m.provider, m.model),
                  formatTokenCount(m.scans),
                  formatTokenCount(m.calls),
                  formatTokenCount(m.input_tokens + m.output_tokens),
                  formatCostUsd(m.cost_usd),
                ])}
              />
            </Section>
            <Section title="By step">
              <Table
                head={["Step", "Calls", "Input", "Output", "Reused"]}
                empty="No model calls in this period."
                rows={data.by_step.map((s) => [
                  <span key="s">
                    {stepLabel(s.step)}
                    {s.truncated > 0 && <span className="ml-2 text-xs text-amber-700">{s.truncated} truncated</span>}
                  </span>,
                  formatTokenCount(s.calls),
                  formatTokenCount(s.input_tokens),
                  formatTokenCount(s.output_tokens),
                  formatTokenCount(s.result_cache_hits),
                ])}
              />
            </Section>
          </div>

          <Section title="Most expensive scans">
            <Table
              head={["Scan", "Model", "Calls", "Tokens", "Cost"]}
              empty="No scan in this period used a model."
              rows={data.top_scans.map((s) => [
                <Link key="scan" href={`/scans/${encodeURIComponent(s.scan_id)}`} className="text-[var(--accent)] hover:underline">
                  {s.project_name ?? "Project"} · {s.scan_type.toUpperCase()} #{s.version ?? "?"}
                  <span className="ml-2 text-xs text-[var(--muted)]">{new Date(s.created_at).toLocaleDateString()}</span>
                </Link>,
                modelName(s.provider, s.model),
                formatTokenCount(s.calls),
                formatTokenCount(s.total_tokens),
                formatCostUsd(s.cost_usd),
              ])}
            />
          </Section>

          {t.scans_without_usage > 0 && (
            <p className="text-xs text-[var(--muted)]">
              {t.scans_without_usage} scan{t.scans_without_usage === 1 ? "" : "s"} in this period recorded no usage (no model used, still
              running, or created before usage was recorded).
            </p>
          )}
        </div>
      )}
    </>
  );
}
