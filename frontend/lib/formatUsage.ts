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
  if (key === "claude_cli") return "Claude";
  if (key === "openai_cli") return "OpenAI";
  if (key === "anthropic") return "Anthropic";
  if (key === "openai") return "OpenAI";
  return provider || "Unknown";
}

/** "claude-sonnet-5-5" -> "Claude Sonnet 5.5" (a short alias like "sonnet" -> "Claude Sonnet"). */
export function claudeModelName(model: string | undefined | null): string {
  const words = (model || "")
    .replace(/-\d{8}$/, "")
    .replace(/(?<=\d)-(?=\d)/g, ".")
    .split("-")
    .filter(Boolean)
    .map((w) => (/^\d/.test(w) ? w : w.charAt(0).toUpperCase() + w.slice(1)));
  if (words.length === 0) return "Claude";
  return words[0] === "Claude" ? words.join(" ") : `Claude ${words.join(" ")}`;
}

/** "gpt-5.6-sol" -> "GPT-5.6 Sol", "gpt-6-astra" -> "GPT-6 Astra". */
export function gptModelName(model: string | undefined | null): string {
  const parts = (model || "").split("-").filter(Boolean);
  if (parts.length < 2 || parts[0].toLowerCase() !== "gpt") return model || "OpenAI";
  const rest = parts.slice(2).map((w) => (/^\d/.test(w) ? w : w.charAt(0).toUpperCase() + w.slice(1)));
  return [`GPT-${parts[1]}`, ...rest].join(" ");
}

/**
 * Provider + model as shown in usage panels. The Claude and OpenAI CLIs are just ways of running
 * a model, so they read "Claude Sonnet 5.5" / "GPT-5.6 Sol"; other providers keep
 * "Provider · model" (or "Provider (model)").
 */
export function llmLabel(
  provider: string | undefined,
  model: string | undefined,
  style: "dot" | "paren" = "dot",
): string {
  const key = (provider || "").trim().toLowerCase();
  if (key === "claude_cli") return claudeModelName(model);
  if (key === "openai_cli") return gptModelName(model);
  return style === "paren"
    ? `${providerLabel(provider)} (${model})`
    : `${providerLabel(provider)} · ${model}`;
}

export function stepLabel(step: string): string {
  const labels: Record<string, string> = {
    scan_deep_files: "Deep file scan",
    verify_flow_slices: "Inter-file flow slices",
    derive_runtime_rules: "Runtime-derived regex",
    classify_dependencies: "Dependency classification",
    rerank_leftover_files: "Unclassified file re-rank",
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
    plan: "Adaptive test planning",
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
