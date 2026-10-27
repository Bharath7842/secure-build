import type { SastLlmProvider } from "@/lib/types";

/** Catalog id; matches the backend `app/defaults/llm_presets.py` ids. */
export type LlmPresetId = string;

export interface LlmPresetInfo {
  label: string;
  provider: SastLlmProvider;
  model: string;
}

/**
 * Bundled copy of the backend preset catalog (`app/defaults/llm_presets.py`). The backend is the
 * source of truth and `useModelCatalog` loads it (with Settings visibility); this copy is the
 * fallback when that request fails and what stored project/scan settings are matched against.
 */
export const LLM_PRESETS: Record<LlmPresetId, LlmPresetInfo> = {
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
  // The local `claude` CLI, one Claude session per scan; `model` is a CLI alias.
  "claude-cli-sonnet": {
    label: "Claude Sonnet 5.5",
    provider: "claude_cli",
    model: "claude-sonnet-5-5",
  },
  "claude-cli-haiku": {
    label: "Claude Haiku 5.5",
    provider: "claude_cli",
    model: "claude-haiku-5-5",
  },
  // A local OpenAI-model CLI, one thread per scan; labels name the model only.
  "openai-cli-sol": { label: "GPT-5.6 Sol", provider: "openai_cli", model: "gpt-5.6-sol" },
  "openai-cli-astra": { label: "GPT-6 Astra", provider: "openai_cli", model: "gpt-6-astra" },
  "openai-cli-terra": { label: "GPT-5.6 Terra", provider: "openai_cli", model: "gpt-5.6-terra" },
  "openai-cli-luna": { label: "GPT-5.6 Luna", provider: "openai_cli", model: "gpt-5.6-luna" },
  // Any OpenAI-compatible /chat/completions server; the model id and base URL
  // are entered on the project form.
  "openai-compat-qwen-coder-32b": {
    label: "OpenAI-compatible — Qwen2.5-Coder-32B-Instruct (vLLM / LM Studio)",
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
  "ollama-starcoder2-3b": {
    label: "Ollama — starcoder2:3b (local)",
    provider: "ollama",
    model: "starcoder2:3b",
  },
  "ollama-qwen2-72b": {
    label: "Ollama — Qwen2 72B Instruct (local)",
    provider: "ollama",
    model: "hf.co/bartowski/Qwen2-72B-Instruct-GGUF:Q4_K_M",
  },
  "ollama-codegemma": {
    label: "Ollama — CodeGemma:latest (local)",
    provider: "ollama",
    model: "codegemma:latest",
  },
};

/**
 * Preset id for stored project/scan settings. Matches against `presets` (default: the bundled
 * catalog, hidden models included) so a project on a hidden model still round-trips.
 */
export function llmPresetForProviderModel(
  provider: string | undefined,
  model: string | undefined,
  presets: Record<LlmPresetId, LlmPresetInfo> = LLM_PRESETS,
): LlmPresetId {
  const entries = Object.entries(presets);
  if (provider === "ollama" && model) {
    const match = entries.find(([, p]) => p.provider === "ollama" && p.model === model);
    return match ? match[0] : "ollama-granite-3b-instruct";
  }
  if (provider === "claude_cli") {
    const match = entries.find(([, p]) => p.provider === "claude_cli" && p.model === model);
    return match ? match[0] : "claude-cli-sonnet";
  }
  if (provider === "openai_cli") {
    const match = entries.find(([, p]) => p.provider === "openai_cli" && p.model === model);
    return match ? match[0] : "openai-cli-sol";
  }
  if (provider === "openai_compat") {
    return entries.find(([, p]) => p.provider === "openai_compat")?.[0] ?? "openai-compat-qwen-coder-32b";
  }
  return "bedrock-haiku";
}
