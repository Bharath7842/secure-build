import type { SastLlmProvider } from "@/lib/types";

export type LlmPresetId =
  | "bedrock-haiku"
  | "bedrock-sonnet"
  | "openai-compat"
  | "ollama-granite-3b"
  | "ollama-granite4-2-3b"
  | "ollama-granite-3b-instruct"
  | "ollama-granite-8b"
  | "ollama-gpt-oss"
  | "ollama-gpt-oss-20b"
  | "ollama-gpt-oss-safeguard"
  | "ollama-codegemma";

export const LLM_PRESETS: Record<
  LlmPresetId,
  { label: string; provider: SastLlmProvider; model: string }
> = {
  "bedrock-haiku": {
    label: "AWS Bedrock — Claude Haiku 4.5",
    provider: "bedrock",
    model: "us.anthropic.claude-haiku-4-5-20251001-v1:0",
  },
  "bedrock-sonnet": {
    label: "AWS Bedrock — Claude Sonnet 4.5",
    provider: "bedrock",
    model: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
  },
  // Any OpenAI-compatible /chat/completions server; the model id and base URL
  // are entered on the project form (mirrors backend llm_presets.py).
  "openai-compat": {
    label: "OpenAI-compatible endpoint (vLLM, LM Studio, llama.cpp, OpenAI, …)",
    provider: "openai_compat",
    model: "Qwen/Qwen2.5-Coder-32B-Instruct",
  },
  "ollama-granite-3b": {
    label: "Ollama — granite-code:3b (local)",
    provider: "ollama",
    model: "granite-code:3b",
  },
  "ollama-granite4-2-3b": {
    label: "Ollama — granite4.2:3b (local)",
    provider: "ollama",
    model: "granite4.2:3b",
  },
  "ollama-granite-3b-instruct": {
    label: "Ollama — granite-code:3b-instruct (local)",
    provider: "ollama",
    model: "granite-code:3b-instruct",
  },
  "ollama-granite-8b": {
    label: "Ollama — granite-code:8b (local)",
    provider: "ollama",
    model: "granite-code:8b",
  },
  "ollama-gpt-oss": {
    label: "Ollama — gpt-oss:latest (local)",
    provider: "ollama",
    model: "gpt-oss:latest",
  },
  "ollama-gpt-oss-20b": {
    label: "Ollama — gpt-oss:20b (local)",
    provider: "ollama",
    model: "gpt-oss:20b",
  },
  "ollama-gpt-oss-safeguard": {
    label: "Ollama — gpt-oss-safeguard:latest (local)",
    provider: "ollama",
    model: "gpt-oss-safeguard:latest",
  },
  "ollama-codegemma": {
    label: "Ollama — CodeGemma:latest (local)",
    provider: "ollama",
    model: "codegemma:latest",
  },
};

/** Ollama model id → preset id (for round-trip from stored project/scan settings). */
const OLLAMA_MODEL_TO_PRESET: Record<string, LlmPresetId> = Object.fromEntries(
  (Object.entries(LLM_PRESETS) as [LlmPresetId, (typeof LLM_PRESETS)[LlmPresetId]][])
    .filter(([, p]) => p.provider === "ollama")
    .map(([id, p]) => [p.model, id])
) as Record<string, LlmPresetId>;

export function llmPresetForProviderModel(
  provider: string | undefined,
  model: string | undefined
): LlmPresetId {
  if (provider === "ollama" && model) {
    const preset = OLLAMA_MODEL_TO_PRESET[model];
    if (preset) return preset;
    return "ollama-granite-3b";
  }
  if (provider === "openai_compat") return "openai-compat";
  return "bedrock-haiku";
}

export const LLM_PRESET_ENTRIES = Object.entries(LLM_PRESETS) as [
  LlmPresetId,
  (typeof LLM_PRESETS)[LlmPresetId],
][];

/** Ollama-only presets for the post–Bedrock-cutoff fallback selector. */
export const OLLAMA_PRESET_ENTRIES = LLM_PRESET_ENTRIES.filter(
  ([, preset]) => preset.provider === "ollama"
);

export const DEFAULT_FALLBACK_PRESET_ID: LlmPresetId = "ollama-granite-3b";

export function isBedrockPrimaryPreset(presetId: LlmPresetId): boolean {
  return LLM_PRESETS[presetId].provider === "bedrock";
}
