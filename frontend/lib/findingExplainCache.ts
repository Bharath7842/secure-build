import type { ExplainMessage } from "@/lib/findingExplainStream";

export type ExplainChatMessage = ExplainMessage & {
  /** The model's reasoning for an assistant reply, shown collapsed above it. */
  thinking?: string;
  /** The local model that wrote an assistant reply. */
  model?: string;
  /** The reply was cut short by Stop. */
  stopped?: boolean;
};

export type ExplainSession = {
  messages: ExplainChatMessage[];
  error: string | null;
};

/** In-memory chat per scan+finding for this browser session (not persisted to the server). */
const sessions = new Map<string, ExplainSession>();

function key(scanId: string, findingId: string, purpose = "explain") {
  return `${purpose}:${scanId}:${findingId}`;
}

export function loadExplainSession(scanId: string, findingId: string, purpose = "explain"): ExplainSession | undefined {
  return sessions.get(key(scanId, findingId, purpose));
}

export function saveExplainSession(scanId: string, findingId: string, session: ExplainSession, purpose = "explain") {
  sessions.set(key(scanId, findingId, purpose), {
    messages: session.messages.map((m) => ({ ...m })),
    error: session.error,
  });
}

export function clearExplainSession(scanId: string, findingId: string, purpose = "explain") {
  sessions.delete(key(scanId, findingId, purpose));
}

export function hasExplainContent(session: ExplainSession | undefined): boolean {
  return Boolean(
    session?.messages.some((m) => m.role === "assistant" && m.content.trim().length > 0),
  );
}

const MODEL_STORAGE_KEY = "secure-build.ai-remediation.model";

export function loadPreferredModel(): string | null {
  try {
    return window.localStorage.getItem(MODEL_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function savePreferredModel(model: string) {
  try {
    window.localStorage.setItem(MODEL_STORAGE_KEY, model);
  } catch {
    // storage unavailable (private mode); the choice just isn't remembered
  }
}

/** Always listed in Netra chat pickers (How to fix, Insights, Export to Jira). */
export const NETRA_CHAT_MODELS = ["gpt-oss:20b", "gemma4:12b"] as const;

const NO_THINK_PREFIXES = ["gemma", "phi4", "granite4"];

export function netraChatModelOptions(pulled: string[], selected: string | null | undefined): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of [...NETRA_CHAT_MODELS, ...pulled, selected ?? ""]) {
    if (!m || seen.has(m)) continue;
    seen.add(m);
    out.push(m);
  }
  return out;
}

/** The stored choice if it is still pulled, else the server default, else any gpt-oss, else the first. */
export function pickModel(models: string[], defaultModel: string, preferred: string | null): string {
  if (preferred && models.includes(preferred)) return preferred;
  if (models.includes(defaultModel) || models.length === 0) return defaultModel;
  return models.find((m) => m.startsWith("gpt-oss")) ?? models.find((m) => m.startsWith("gemma4")) ?? models[0];
}

function thinkingOff(model: string, noThink?: string[]): boolean {
  if (noThink?.includes(model)) return true;
  const n = model.toLowerCase();
  return NO_THINK_PREFIXES.some((p) => n.startsWith(p));
}

/** Option text for a Netra chat model picker. */
export function explainModelOptionLabel(
  model: string,
  info: { default_model?: string; no_think?: string[]; models?: string[] } | null,
): string {
  const tags: string[] = [];
  if (info && model === info.default_model) tags.push("default");
  if (thinkingOff(model, info?.no_think)) tags.push("thinking off");
  if (info?.models && info.models.length > 0 && !info.models.includes(model)) tags.push("not pulled");
  return tags.length ? `${model} (${tags.join(", ")})` : model;
}
