import { LLM_PRESETS } from "@/lib/llmPresets";
import type { DastModelProvider, DastProviders, DastSettings } from "@/lib/types";

/** Claude Haiku 4.5 on Bedrock — the DAST default whenever the operator picks Amazon Bedrock. */
export const BEDROCK_HAIKU_MODEL = LLM_PRESETS["bedrock-haiku"].model;

export const BEDROCK_SONNET_MODEL = "us.anthropic.claude-sonnet-5";

export const DAST_MODEL_OPTIONS: Record<DastModelProvider, { id: string; label: string }[]> = {
  bedrock: [
    { id: BEDROCK_HAIKU_MODEL, label: "Claude Haiku 4.5" },
    { id: BEDROCK_SONNET_MODEL, label: "Claude Sonnet 5" },
  ],
  ollama: [
    { id: "gpt-oss:20b", label: "gpt-oss:20b" },
    { id: "gpt-oss:latest", label: "gpt-oss:latest" },
    { id: "granite-code:3b-instruct", label: "granite-code:3b-instruct" },
    { id: "granite-code:3b", label: "granite-code:3b" },
    { id: "granite-code:8b", label: "granite-code:8b" },
    { id: "granite4.2:3b", label: "granite4.2:3b" },
    { id: "gemma4:12b", label: "gemma4:12b" },
    { id: "phi4-mini:3.8b", label: "phi4-mini:3.8b" },
  ],
  claude_cli: [
    { id: "claude-sonnet-5-5", label: "Claude Sonnet 5.5" },
    { id: "claude-haiku-5-5", label: "Claude Haiku 5.5" },
  ],
  openai: [{ id: "gpt-4o-mini", label: "gpt-4o-mini" }],
  anthropic: [{ id: "claude-haiku-4-5", label: "Claude Haiku 4.5" }],
};

const PROVIDER_NAMES: Record<string, string> = {
  bedrock: "Bedrock",
  ollama: "Ollama",
  openai: "OpenAI",
  anthropic: "Anthropic",
  claude_cli: "Claude",
};

/** Short label for a provider/model pair, e.g. "Claude Haiku 4.5 (Bedrock)". */
export function formatDastModel(provider: string, model = ""): string {
  const key = provider.toLowerCase();
  const named = (DAST_MODEL_OPTIONS[key as DastModelProvider] ?? []).find((o) => o.id === model)?.label;
  const modelLabel = named || (/haiku/i.test(model) ? "Claude Haiku 4.5" : model);
  const host = PROVIDER_NAMES[key] || provider;
  if (modelLabel && host) return `${modelLabel} (${host})`;
  return modelLabel || host || "—";
}

/** The LLM this DAST scan used, from frozen `model_routing` (`task -> [provider, model]`). */
export function dastRoutingLabel(routing: unknown): string | null {
  if (!routing || typeof routing !== "object") return null;
  const seen = new Set<string>();
  const labels: string[] = [];
  for (const value of Object.values(routing as Record<string, unknown>)) {
    const pair = Array.isArray(value) ? value : null;
    const provider = typeof pair?.[0] === "string" ? pair[0] : "";
    const model = typeof pair?.[1] === "string" ? pair[1] : "";
    if (!provider) continue;
    const key = `${provider}\0${model}`;
    if (seen.has(key)) continue;
    seen.add(key);
    labels.push(formatDastModel(provider, model));
  }
  return labels.length ? labels.join(" · ") : null;
}

/** Model to fill in when the provider dropdown changes. Bedrock always lands on Haiku. `visible` is
 *  the provider's options after Settings hides some; the last-resort pick comes from it. */
export function defaultDastModel(
  provider: DastModelProvider,
  settings?: DastSettings | null,
  providers?: DastProviders | null,
  visible?: { id: string }[],
): string {
  if (provider === "bedrock") {
    return providers?.default_models?.bedrock || settings?.model_routing.find((r) => r.provider === "bedrock")?.model || BEDROCK_HAIKU_MODEL;
  }
  const fromApi = providers?.default_models?.[provider];
  if (fromApi) return fromApi;
  const fromRouting = settings?.model_routing.find((r) => r.provider === provider)?.model;
  if (fromRouting) return fromRouting;
  return (visible ?? DAST_MODEL_OPTIONS[provider])[0]?.id ?? "";
}
