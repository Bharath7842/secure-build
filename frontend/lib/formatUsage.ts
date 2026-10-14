import type { UsageStepSummary, UsageSummary } from "@/lib/types";

export function formatTokenCount(value: number): string {
  return value.toLocaleString(undefined, { maximumFractionDigits: 0 });
}

export function formatCostUsd(value: number): string {
  if (value === 0) return "$0.00";
  if (value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

export function formatPricePerMtok(value: number): string {
  return `$${value.toFixed(2)}/M`;
}

export function providerLabel(provider: string | undefined): string {
  const key = (provider || "").trim().toLowerCase();
  if (key === "bedrock") return "Bedrock";
  if (key === "ollama") return "Ollama";
  if (key === "openai_compat") return "OpenAI-compatible";
  if (key === "anthropic") return "Anthropic";
  if (key === "openai") return "OpenAI";
  return provider || "Unknown";
}

export function stepLabel(step: string): string {
  const labels: Record<string, string> = {
    scan_deep_files: "Deep file scan",
    verify_flow_slices: "Inter-file flow slices",
    derive_runtime_rules: "Runtime-derived regex",
    scan_triage_files: "Regex triage",
    group_confirm_triage_findings: "Grouped triage confirmation",
    // The agentic hunt was removed; kept for usage summaries on older scans.
    hunt_plan: "Agentic hunt — planning",
    hunt_investigate: "Agentic hunt — investigation",
    hunt_verify: "Agentic hunt — independent verification",
    // Pre-rename step keys, kept so usage summaries persisted on older scans
    // still render a label instead of a raw identifier.
    scan_critical_files: "File scan",
    scan_low_files: "Regex triage",
    // DAST model-gateway tasks (one step per task)
    fingerprint: "Fingerprint & login classification",
    crawl_plan: "Crawl planning",
    login_selectors: "Login steps",
    construct: "Test construction",
    rule: "Check rulings",
    narrate: "Narration",
    unknown: "Other",
  };
  return labels[step] ?? step.replace(/_/g, " ");
}

export function estimateStepCostUsd(
  step: UsageStepSummary,
  summary: UsageSummary
): number {
  // DAST reports each step's own cost; SAST derives it from one summary-wide price.
  if (typeof step.cost_usd === "number") return step.cost_usd;
  const inPrice = summary.input_price_per_mtok ?? 0;
  const outPrice = summary.output_price_per_mtok ?? 0;
  // Mirrors llm_client.llm_cost_usd: prompt-cache reads bill at 0.1x input,
  // writes at 1.25x; input_tokens already includes both.
  const read = step.cache_read_input_tokens ?? 0;
  const write = step.cache_write_input_tokens ?? 0;
  const uncached = Math.max(0, step.input_tokens - read - write);
  return (
    ((uncached + read * 0.1 + write * 1.25) / 1_000_000) * inPrice +
    (step.output_tokens / 1_000_000) * outPrice
  );
}

export function hasUsageData(summary: UsageSummary | null | undefined): boolean {
  if (!summary) return false;
  return (
    (summary.call_count ?? 0) > 0 ||
    (summary.total_tokens ?? 0) > 0 ||
    (summary.result_cache_hits ?? 0) > 0
  );
}

export function usageCardSubtitle(summary: UsageSummary): string {
  const parts = [
    `${formatTokenCount(summary.total_tokens ?? 0)} tokens`,
    formatCostUsd(summary.cost_usd ?? 0),
  ];
  if (summary.result_cache_hits) {
    parts.push(`${formatTokenCount(summary.result_cache_hits)} reused`);
  }
  if (summary.fallback_switched) {
    parts.push("fallback used");
  }
  return parts.join(" · ");
}
