import { apiFetch } from "@/lib/api";

export type ExplainMessage = { role: "user" | "assistant"; content: string };

/** An issue Netra's Insights may cite as `[V3]`. */
export type InsightRef = { id: string; title: string; severity: string; scan_type: string };

type ActiveExplain = {
  controller: AbortController;
  reader: ReadableStreamDefaultReader<Uint8Array> | null;
};

/** Only one Explain AI HTTP stream may run in this tab at a time. */
let activeExplain: ActiveExplain | null = null;

export function abortActiveExplainStream() {
  if (!activeExplain) return;
  activeExplain.controller.abort();
  void activeExplain.reader?.cancel().catch(() => undefined);
  activeExplain = null;
}

export interface ExplainStreamHandlers {
  signal?: AbortSignal;
  /** The local model the backend actually used for this reply (and, for insights, the issue references). */
  onMeta?: (meta: { provider: string; model: string; refs?: Record<string, InsightRef> }) => void;
  onThinking?: (text: string) => void;
  onChunk?: (text: string) => void;
  onError?: (message: string) => void;
}

function handleSseEvent(
  parsed: { event: string; data: string },
  handlers: ExplainStreamHandlers,
): "done" | "error" | void {
  let payload: {
    content?: string;
    message?: string;
    provider?: string;
    model?: string;
    refs?: Record<string, InsightRef>;
  } = {};
  try {
    payload = JSON.parse(parsed.data) as typeof payload;
  } catch {
    return;
  }
  if (parsed.event === "meta" && payload.model) {
    handlers.onMeta?.({ provider: payload.provider ?? "ollama", model: payload.model, refs: payload.refs });
  } else if (parsed.event === "thinking" && payload.content) {
    handlers.onThinking?.(payload.content);
  } else if (parsed.event === "chunk" && payload.content) {
    handlers.onChunk?.(payload.content);
  } else if (parsed.event === "error") {
    handlers.onError?.(payload.message ?? "Model error");
    return "error";
  } else if (parsed.event === "done") {
    return "done";
  }
}

function parseSseBlock(block: string): { event: string; data: string } | null {
  let event = "message";
  const dataLines: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
  }
  if (!dataLines.length) return null;
  return { event, data: dataLines.join("\n") };
}

export function consumeFindingExplainStream(
  scanId: string,
  findingId: string,
  messages: ExplainMessage[],
  handlers: ExplainStreamHandlers,
  model?: string | null,
  purpose: "explain" | "jira" = "explain",
): Promise<void> {
  return consumeExplainSse(
    `/api/scans/${scanId}/findings/${findingId}/explain/stream`,
    { purpose },
    messages,
    handlers,
    model,
  );
}

/** Netra's prioritised fix plan for a project's vulnerability report. */
export function consumeVulnerabilityInsightsStream(
  projectId: string,
  filters: { branch?: string | null; scanType?: string | null },
  messages: ExplainMessage[],
  handlers: ExplainStreamHandlers,
  model?: string | null,
): Promise<void> {
  return consumeExplainSse(
    `/api/projects/${projectId}/vulnerability-report/insights/stream`,
    { branch: filters.branch ?? null, scan_type: filters.scanType || null },
    messages,
    handlers,
    model,
  );
}

async function consumeExplainSse(
  path: string,
  extraBody: Record<string, unknown>,
  messages: ExplainMessage[],
  handlers: ExplainStreamHandlers,
  model?: string | null,
): Promise<void> {
  abortActiveExplainStream();

  const controller = new AbortController();
  if (handlers.signal) {
    if (handlers.signal.aborted) {
      controller.abort();
    } else {
      handlers.signal.addEventListener("abort", () => controller.abort(), { once: true });
    }
  }
  activeExplain = { controller, reader: null };

  try {
    const res = await apiFetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...extraBody,
        messages: messages.map(({ role, content }) => ({ role, content })),
        model: model || null,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      let message = text || `Explain request failed (${res.status})`;
      try {
        const json = JSON.parse(text) as { detail?: string | { msg?: string }[] };
        if (typeof json.detail === "string") message = json.detail;
        else if (Array.isArray(json.detail) && json.detail[0]?.msg) message = json.detail[0].msg;
      } catch {
        // keep raw text
      }
      throw new Error(message);
    }
    const reader = res.body?.getReader();
    if (!reader) throw new Error("No response body");
    if (activeExplain?.controller === controller) {
      activeExplain.reader = reader;
    }

    const decoder = new TextDecoder();
    let buffer = "";

    for (;;) {
      if (controller.signal.aborted) {
        await reader.cancel();
        throw new DOMException("The operation was aborted.", "AbortError");
      }
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() ?? "";
      for (const part of parts) {
        const parsed = parseSseBlock(part.trim());
        if (!parsed) continue;
        const outcome = handleSseEvent(parsed, handlers);
        if (outcome) return;
      }
    }

    const tail = buffer.trim();
    if (tail) {
      const parsed = parseSseBlock(tail);
      if (parsed) handleSseEvent(parsed, handlers);
    }
  } finally {
    if (activeExplain?.controller === controller) {
      activeExplain = null;
    }
  }
}