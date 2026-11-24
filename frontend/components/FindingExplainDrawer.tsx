"use client";

import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import MarkdownView from "@/components/MarkdownView";
import { api } from "@/lib/api";
import {
  clearExplainSession,
  hasExplainContent,
  loadExplainSession,
  loadPreferredModel,
  pickModel,
  saveExplainSession,
  savePreferredModel,
  explainModelOptionLabel,
  netraChatModelOptions,
  type ExplainChatMessage,
} from "@/lib/findingExplainCache";
import { abortActiveExplainStream, consumeFindingExplainStream } from "@/lib/findingExplainStream";
import { RISK_DOT, RISK_STYLES, normalizeSeverity } from "@/lib/findingStyles";
import { toModulePath } from "@/lib/modulePath";
import type { ExplainModels, Finding } from "@/lib/types";

const FOLLOW_UPS = [
  "Show the fixed code for this file",
  "How do I test that the fix works?",
  "Is this exploitable in this codebase?",
];

export function Icon({ d, size = 16 }: { d: string; size?: number }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d={d} />
    </svg>
  );
}

export const ICON_CLOSE = "M18 6 6 18M6 6l12 12";
export const ICON_SPARKLE = "M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3zM19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15z";
const ICON_BRAIN = "M9 4a3 3 0 0 0-3 3v.2A3 3 0 0 0 4 10a3 3 0 0 0 1 2.2A3 3 0 0 0 6 17a3 3 0 0 0 3 3h1V4H9zm6 0a3 3 0 0 1 3 3v.2A3 3 0 0 1 20 10a3 3 0 0 1-1 2.2A3 3 0 0 1 18 17a3 3 0 0 1-3 3h-1V4h1z";
export const ICON_REFRESH = "M3 12a9 9 0 0 1 15.5-6.3L21 8M21 3v5h-5M21 12a9 9 0 0 1-15.5 6.3L3 16M3 21v-5h5";
export const ICON_SEND = "M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z";
export const ICON_STOP = "M6 6h12v12H6z";
const ICON_CHEVRON = "m9 18 6-6-6-6";

/** The model's reasoning: collapsible, scrollable, kept apart from the answer. */
function ReasoningPanel({ text, live }: { text: string; live: boolean }) {
  const [open, setOpen] = useState(live);
  const boxRef = useRef<HTMLDivElement | null>(null);
  const expanded = open || live;

  useEffect(() => {
    if (live && boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [text, live]);

  return (
    <div className="mb-3 overflow-hidden rounded-md border border-violet-200/80 bg-violet-50/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={expanded}
        className="agent-focus-ring flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-violet-900 hover:bg-violet-50"
      >
        <span className={`transition-transform ${expanded ? "rotate-90" : ""}`}>
          <Icon d={ICON_CHEVRON} size={12} />
        </span>
        <Icon d={ICON_BRAIN} size={14} />
        {live ? (
          <span className="flex items-center gap-1.5">
            Thinking
            <span className="flex gap-0.5" aria-hidden>
              <span className="h-1 w-1 animate-bounce rounded-full bg-violet-500 [animation-delay:-0.3s]" />
              <span className="h-1 w-1 animate-bounce rounded-full bg-violet-500 [animation-delay:-0.15s]" />
              <span className="h-1 w-1 animate-bounce rounded-full bg-violet-500" />
            </span>
          </span>
        ) : (
          <span>Model reasoning</span>
        )}
        <span className="ml-auto font-normal text-violet-700/70">{text.length.toLocaleString()} chars</span>
      </button>
      {expanded ? (
        <div
          ref={boxRef}
          className="agent-scroll max-h-56 overflow-y-auto border-t border-violet-200/70 bg-white/60 px-3 py-2 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap text-slate-600"
        >
          {text}
        </div>
      ) : null}
    </div>
  );
}

/** Before the first token: the model is loading and reading the finding context. */
function WaitingStatus({ model }: { model?: string }) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => window.clearInterval(id);
  }, []);
  return (
    <p className="mb-3 flex items-center gap-2 text-xs text-[var(--muted)]">
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-violet-300 border-t-violet-600" aria-hidden />
      {model ? <span className="font-mono">{model}</span> : "The model"} is reading the context…
      <span className="tabular-nums">{seconds}s</span>
    </p>
  );
}

export function AssistantCard({
  message,
  live = false,
  liveThinking = false,
}: {
  message: ExplainChatMessage;
  live?: boolean;
  liveThinking?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">
        <span className="flex h-5 w-5 items-center justify-center rounded bg-blue-100 text-blue-700">
          <Icon d={ICON_SPARKLE} size={12} />
        </span>
        Netra
        {message.model ? (
          <span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 font-mono text-[10.5px] normal-case tracking-normal text-slate-600">
            {message.model}
          </span>
        ) : null}
      </div>
      {message.thinking ? <ReasoningPanel text={message.thinking} live={liveThinking} /> : null}
      {message.content ? (
        <MarkdownView text={message.content} />
      ) : live && !liveThinking ? (
        <div className="space-y-2" aria-label="Waiting for the model">
          {!message.thinking ? <WaitingStatus model={message.model} /> : null}
          <div className="h-3 w-2/3 animate-pulse rounded bg-slate-100" />
          <div className="h-3 w-full animate-pulse rounded bg-slate-100" />
          <div className="h-3 w-5/6 animate-pulse rounded bg-slate-100" />
        </div>
      ) : null}
      {live && message.content ? (
        <span className="mt-1 inline-block h-4 w-1.5 animate-pulse rounded-sm bg-blue-500 align-middle" aria-hidden />
      ) : null}
      {message.stopped ? (
        <p className="mt-3 text-xs italic text-[var(--muted)]">Stopped before the model finished.</p>
      ) : null}
    </div>
  );
}

interface FindingExplainDrawerProps {
  scanId: string;
  finding: Finding;
  onClose: () => void;
  /** Shown above the conversation (e.g. how-to-fix steps and a copyable fix prompt). */
  remediation?: ReactNode;
  /** The AI conversation; off for findings the explain endpoint does not support (non-SAST). */
  chatEnabled?: boolean;
  /** Why the conversation is off, shown in its place. */
  chatDisabledReason?: string;
}

export default function FindingExplainDrawer({
  scanId,
  finding,
  onClose,
  remediation,
  chatEnabled = true,
  chatDisabledReason,
}: FindingExplainDrawerProps) {
  const cached = loadExplainSession(scanId, finding.id);
  const [messages, setMessages] = useState<ExplainChatMessage[]>(() => cached?.messages ?? []);
  const [error, setError] = useState<string | null>(() => cached?.error ?? null);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState<ExplainChatMessage | null>(null);
  const [modelsInfo, setModelsInfo] = useState<ExplainModels | null>(null);
  const [model, setModel] = useState<string | null>(null);
  const [portalReady, setPortalReady] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const stoppedRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const autoStartedRef = useRef(false);

  const severity = normalizeSeverity(finding.severity, true);
  const location = `${toModulePath(finding.file_path ?? "")}${finding.line ? `:${finding.line}` : ""}`;

  const persist = useCallback(
    (nextMessages: ExplainChatMessage[], nextError: string | null) => {
      saveExplainSession(scanId, finding.id, { messages: nextMessages, error: nextError });
    },
    [scanId, finding.id],
  );

  const runStream = useCallback(
    async (history: ExplainChatMessage[], useModel: string | null) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      stoppedRef.current = false;
      setBusy(true);
      setError(null);
      const reply: ExplainChatMessage = { role: "assistant", content: "", thinking: "", model: useModel ?? undefined };
      setLive({ ...reply });
      const finish = (stopped: boolean) => {
        if (!reply.content.trim()) return history;
        const done: ExplainChatMessage = {
          ...reply,
          content: reply.content.trim(),
          thinking: reply.thinking?.trim() || undefined,
          stopped: stopped || undefined,
        };
        const next = [...history, done];
        setMessages(next);
        return next;
      };
      try {
        await consumeFindingExplainStream(
          scanId,
          finding.id,
          history,
          {
            signal: ac.signal,
            onMeta: ({ model: used }) => {
              reply.model = used;
              setLive({ ...reply });
            },
            onThinking: (t) => {
              reply.thinking = (reply.thinking ?? "") + t;
              setLive({ ...reply });
            },
            onChunk: (t) => {
              reply.content += t;
              setLive({ ...reply });
            },
            onError: (msg) => setError(msg),
          },
          useModel,
        );
        persist(finish(false), null);
      } catch (e) {
        if ((e as Error).name === "AbortError") {
          if (stoppedRef.current) persist(finish(true), null);
        } else {
          const msg = e instanceof Error ? e.message : "Request failed";
          setError(msg);
          persist(finish(false), msg);
        }
      } finally {
        if (abortRef.current === ac) {
          setLive(null);
          setBusy(false);
        }
      }
    },
    [scanId, finding.id, persist],
  );

  useEffect(() => {
    setPortalReady(true);
  }, []);

  useEffect(() => {
    if (!chatEnabled) return;
    let cancelled = false;
    api.scans
      .explainModels(scanId)
      .then((info) => {
        if (cancelled) return;
        setModelsInfo(info);
        setModel(pickModel(info.models, info.default_model, loadPreferredModel()));
      })
      .catch(() => {
        if (cancelled) return;
        setModelsInfo(null);
        setModel(loadPreferredModel() ?? "");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, chatEnabled]);

  useEffect(() => {
    if (!chatEnabled || model === null || autoStartedRef.current) return;
    autoStartedRef.current = true;
    if (hasExplainContent({ messages, error })) return;
    void runStream([], model || null);
  }, [chatEnabled, model, messages, error, runStream]);

  useEffect(
    () => () => {
      abortRef.current?.abort();
      abortActiveExplainStream();
    },
    [],
  );

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages.length, live?.content, error]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function changeModel(next: string) {
    setModel(next);
    savePreferredModel(next);
  }

  function stop() {
    stoppedRef.current = true;
    abortRef.current?.abort();
    abortActiveExplainStream();
  }

  function regenerate() {
    if (busy) return;
    clearExplainSession(scanId, finding.id);
    setMessages([]);
    void runStream([], model || null);
  }

  async function send(text: string) {
    const question = text.trim();
    if (!question || busy) return;
    const next: ExplainChatMessage[] = [...messages, { role: "user", content: question }];
    setMessages(next);
    persist(next, null);
    setDraft("");
    await runStream(next, model || null);
  }

  if (!portalReady) return null;

  const models = modelsInfo?.models ?? [];
  const options = netraChatModelOptions(models, model);
  const ollamaDown = Boolean(modelsInfo?.error);
  const hasAnswer = messages.some((m) => m.role === "assistant");

  const panel = (
    <>
      <button
        type="button"
        aria-label="Close Netra"
        className="fixed inset-0 z-[120] bg-slate-900/40 backdrop-blur-[1px]"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-label="Netra"
        className="fixed inset-y-0 right-0 z-[130] flex w-full max-w-2xl flex-col border-l border-slate-200 bg-[var(--canvas)] shadow-2xl"
      >
        <header className="shrink-0 border-b border-slate-200 bg-white">
          <div className="flex items-start gap-3 px-5 pt-4 pb-3">
            <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-blue-600 to-violet-600 text-white shadow-sm">
              <Icon d={ICON_SPARKLE} size={18} />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold uppercase tracking-wide text-blue-700">Netra · AI remediation</p>
              <h2 className="mt-0.5 line-clamp-2 text-[15px] font-semibold leading-snug text-[var(--ink)]">
                {finding.title}
              </h2>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs">
                <span
                  className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 font-medium uppercase tracking-wide ${
                    RISK_STYLES[severity]?.chip ?? "bg-slate-100 text-slate-600"
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${RISK_DOT[severity] ?? "bg-slate-400"}`} aria-hidden />
                  {severity}
                </span>
                {finding.cwe ? (
                  <span className="rounded-full bg-slate-100 px-2 py-0.5 font-medium text-slate-700">{finding.cwe}</span>
                ) : null}
                {location ? (
                  <span className="truncate font-mono text-[11px] text-[var(--muted)]" title={finding.file_path ?? ""}>
                    {location}
                  </span>
                ) : null}
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="agent-focus-ring shrink-0 rounded-md p-1.5 text-[var(--muted)] hover:bg-slate-100 hover:text-[var(--ink)]"
            >
              <Icon d={ICON_CLOSE} />
            </button>
          </div>

          {chatEnabled ? (
          <div className="flex flex-wrap items-center gap-2 border-t border-slate-100 bg-slate-50/70 px-5 py-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                ollamaDown
                  ? "border-red-200 bg-red-50 text-red-700"
                  : "border-emerald-200 bg-emerald-50 text-emerald-800"
              }`}
              title={modelsInfo?.error ?? "Runs on your local Ollama server; code never leaves this machine"}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${ollamaDown ? "bg-red-500" : "bg-emerald-500"}`} aria-hidden />
              Local · Ollama
            </span>
            <label className="flex items-center gap-1.5 text-xs text-[var(--muted)]">
              Model
              <select
                value={model ?? ""}
                onChange={(e) => changeModel(e.target.value)}
                disabled={model === null}
                className="agent-focus-ring rounded-md border border-slate-200 bg-white py-1 pr-7 pl-2 font-mono text-xs text-[var(--ink)] disabled:opacity-60"
              >
                {model === null ? <option value="">Loading…</option> : null}
                {options.map((m) => (
                  <option key={m} value={m}>
                    {explainModelOptionLabel(m, modelsInfo)}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              onClick={regenerate}
              disabled={busy || model === null}
              className="agent-focus-ring ml-auto inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-[var(--ink)] hover:bg-slate-50 disabled:opacity-50"
              title="Ask the selected model again from scratch"
            >
              <Icon d={ICON_REFRESH} size={13} />
              Regenerate
            </button>
          </div>
          ) : null}
        </header>

        <div className="agent-scroll min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-5">
          {remediation}
          {!chatEnabled ? (
            <p className="rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-[var(--muted)]">
              {chatDisabledReason ?? "The AI explanation is not available for this finding."}
            </p>
          ) : null}
          {chatEnabled && ollamaDown && !busy && !hasAnswer ? (
            <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
              {modelsInfo?.error}. Start Ollama and pull a model, e.g. <code className="font-mono">ollama pull gpt-oss:20b</code>.
            </div>
          ) : null}

          {messages.map((msg, i) =>
            msg.role === "user" ? (
              <div key={`u-${i}`} className="flex justify-end">
                <div className="max-w-[85%] rounded-lg rounded-br-sm bg-blue-600 px-3.5 py-2 text-sm leading-relaxed whitespace-pre-wrap text-white shadow-sm">
                  {msg.content}
                </div>
              </div>
            ) : (
              <AssistantCard key={`a-${i}`} message={msg} />
            ),
          )}

          {live ? <AssistantCard message={live} live liveThinking={Boolean(live.thinking) && !live.content} /> : null}

          {error ? (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
              <p className="font-medium">The model could not answer</p>
              <p className="mt-0.5 text-xs">{error}</p>
            </div>
          ) : null}
          <div ref={bottomRef} />
        </div>

        {chatEnabled ? (
        <footer className="shrink-0 border-t border-slate-200 bg-white px-5 pt-3 pb-4">
          {hasAnswer && !busy ? (
            <div className="mb-2.5 flex flex-wrap gap-1.5">
              {FOLLOW_UPS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => void send(q)}
                  className="agent-focus-ring rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs text-[var(--ink)] hover:border-blue-300 hover:bg-blue-50"
                >
                  {q}
                </button>
              ))}
            </div>
          ) : null}
          <div className="flex items-end gap-2 rounded-lg border border-slate-200 bg-white p-1.5 focus-within:border-blue-400 focus-within:ring-2 focus-within:ring-blue-100">
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              rows={2}
              disabled={busy}
              placeholder={busy ? "The model is answering…" : "Ask a follow-up about this finding…"}
              className="max-h-40 min-h-[2.5rem] flex-1 resize-none bg-transparent px-2 py-1.5 text-sm text-[var(--ink)] outline-none placeholder:text-slate-400 disabled:opacity-60"
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send(draft);
                }
              }}
            />
            {busy ? (
              <button
                type="button"
                onClick={stop}
                className="agent-focus-ring inline-flex shrink-0 items-center gap-1.5 rounded-md bg-slate-800 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700"
              >
                <Icon d={ICON_STOP} size={12} />
                Stop
              </button>
            ) : (
              <button
                type="button"
                disabled={!draft.trim()}
                onClick={() => void send(draft)}
                className="agent-focus-ring inline-flex shrink-0 items-center gap-1.5 rounded-md bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
              >
                <Icon d={ICON_SEND} size={13} />
                Send
              </button>
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-[var(--muted)]">
            Enter to send · Shift+Enter for a new line · Esc to close. AI output can be wrong; verify before applying.
          </p>
        </footer>
        ) : null}
      </aside>
    </>
  );

  return createPortal(panel, document.body);
}
