"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { displayLogLine, hideInconclusive, originOf } from "@/lib/httpLabel";
import type {
  DastNarration,
  DastNarrationStep,
  DastPage,
  DastSessionAssessment,
} from "@/lib/types";

const SCROLL_THROTTLE_MS = 100;

function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1 align-middle" aria-hidden>
      {[0, 150, 300].map((delay) => (
        <span
          key={delay}
          className="h-1.5 w-1.5 animate-bounce rounded-full bg-slate-400"
          style={{ animationDelay: `${delay}ms` }}
        />
      ))}
    </span>
  );
}

/** What the pulse line says while a step is in progress. */
const RUNNING_CUE: Record<string, string> = {
  connection: "Checking the application is reachable…",
  auth: "Signing in to the application…",
  discovery: "Mapping the attack surface…",
  passive: "Analyzing the application…",
  testing: "Running security checks…",
  authorization: "Checking who can access what…",
  analysis: "Validating security findings…",
};

/** What the pulse line says while that step has not started yet. */
const WAITING_CUE: Record<string, string> = {
  connection: "Preparing DAST scan…",
  auth: "Preparing to sign in…",
  discovery: "Preparing to map the attack surface…",
  passive: "Preparing application analysis…",
  testing: "Identifying security test cases…",
  authorization: "Preparing authorization checks…",
  analysis: "Analyzing scan results…",
};

function runningCue(stepId: string): string {
  return RUNNING_CUE[stepId] ?? "Running security checks…";
}

/** The next step that has not finished, or the report once every step is done. */
function waitingCue(steps: DastNarrationStep[], afterId?: string): string {
  const start = afterId ? steps.findIndex((s) => s.id === afterId) + 1 : 0;
  const next = steps.slice(Math.max(start, 0)).find((s) => s.status === "pending" || s.status === "running");
  if (!next) return "Generating security report…";
  return WAITING_CUE[next.id] ?? "Preparing the next security check…";
}

function PlanningCue({ label }: { label: string }) {
  return (
    <div className="dast-fade-in" aria-live="polite" aria-label={label}>
      <div className="agent-pulse-bar mb-2 max-w-xs" aria-hidden />
      <p className="flex items-center gap-2 text-sm text-[var(--muted)]">
        <TypingDots />
        {label}
      </p>
    </div>
  );
}

const THINKING_LINE_RE = /^\s*\[thinking\]\s*(.*)$/;
const PLANNER_LINE_RE = /^\s*\[planner\]\s*(.*)$/;
const SCREENSHOT_LINE_RE = /^\s*\[screenshot:\s*([A-Za-z0-9._-]+\.jpg)\]\s*$/;
const VISIT_RE = /Visiting\s+(https?:\/\/\S+)/;
const LOGIN_STEP_RE = /\[2\/4\] Extracting login page details/;

function screenshotForUrl(url: string, pages: DastPage[] | null | undefined): string | null {
  if (!url || !pages?.length) return null;
  const exact = pages.find((p) => p.url === url && p.screenshot);
  if (exact?.screenshot) return exact.screenshot;
  const loose = pages.find((p) => p.screenshot && (p.url.startsWith(url) || url.startsWith(p.url)));
  return loose?.screenshot ?? null;
}

function LogScreenshot({ scanId, filename, label }: { scanId: string; filename: string; label: string }) {
  const [enlarged, setEnlarged] = useState(false);
  const [missing, setMissing] = useState(false);
  const src = `/api/scans/${scanId}/screenshots/${filename}`;

  useEffect(() => {
    if (!enlarged) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setEnlarged(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enlarged]);

  if (missing) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => setEnlarged(true)}
        className="agent-focus-ring mt-1 block overflow-hidden rounded-md border border-slate-200 bg-white"
        aria-label={`Enlarge screenshot of ${label}`}
        title={label}
      >
        {/* eslint-disable-next-line @next/next/no-img-element -- per-scan thumbs behind a bearer-authed proxy */}
        <img src={src} alt={label} onError={() => setMissing(true)} className="block max-h-48 w-auto max-w-full object-contain" />
      </button>
      {enlarged && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-6"
          role="dialog"
          aria-modal="true"
          aria-label={label}
          onClick={() => setEnlarged(false)}
        >
          {/* eslint-disable-next-line @next/next/no-img-element -- see above */}
          <img src={src} alt={label} className="max-h-full max-w-full rounded-md shadow-2xl" />
        </div>
      )}
    </>
  );
}

/** Thinking and technical log in arrival order, like a chat transcript — no
 * inner scroll, no separate "thinking on top / log below" stacks. A visit or
 * login-page line is followed by that page's screenshot. */
function StepFeed({
  evidence,
  scanId,
  pages,
  origin,
}: {
  evidence: string[];
  scanId: string;
  pages?: DastPage[] | null;
  origin: string;
}) {
  const lastLine = evidence[evidence.length - 1];
  const hasLoginShot = evidence.some((l) => l.match(SCREENSHOT_LINE_RE)?.[1] === "login.jpg");
  const rendered = useMemo(
    () => (
      <div className="space-y-1">
        {evidence.map((line, i) => {
          const shot = line.match(SCREENSHOT_LINE_RE);
          if (shot) {
            return <LogScreenshot key={i} scanId={scanId} filename={shot[1]} label={shot[1]} />;
          }
          const think = line.match(THINKING_LINE_RE) || line.match(PLANNER_LINE_RE);
          const visit = line.match(VISIT_RE);
          const nextIsShot = i + 1 < evidence.length && SCREENSHOT_LINE_RE.test(evidence[i + 1]);
          const fallbackShot = !nextIsShot
            ? visit
              ? screenshotForUrl(visit[1], pages)
              : !hasLoginShot && LOGIN_STEP_RE.test(line)
                ? "login.jpg"
                : null
            : null;
          const shown = think?.[1] ?? displayLogLine(line, origin);
          return (
            <div key={i}>
              {think?.[1] ? (
                <p className="whitespace-pre-wrap break-words text-sm italic leading-relaxed text-[var(--muted)]">
                  {shown}
                </p>
              ) : (
                <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-[var(--ink)]">{shown}</p>
              )}
              {fallbackShot && <LogScreenshot scanId={scanId} filename={fallbackShot} label={visit?.[1] || fallbackShot} />}
            </div>
          );
        })}
      </div>
    ),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-render when the log grows or pages arrive
    [evidence.length, lastLine, scanId, pages, origin, hasLoginShot],
  );

  if (evidence.length === 0) return null;
  return rendered;
}

/** One phase: interleaved think+log, then reasoning bullets when they arrive. */
function Message({
  step,
  scanId,
  pages,
  origin,
}: {
  step: DastNarrationStep;
  scanId: string;
  pages?: DastPage[] | null;
  origin: string;
}) {
  const failed = step.status === "failed";
  const running = step.status === "running";

  return (
    <div className="dast-fade-in">
      <h3 className={`mb-1.5 text-sm font-semibold ${failed ? "text-red-700" : "text-[var(--ink)]"}`}>
        {step.title}
      </h3>

      <StepFeed evidence={step.evidence} scanId={scanId} pages={pages} origin={origin} />

      {step.reasoning.length > 0 && (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-[var(--muted)]">
          {step.reasoning.map((line, i) => (
            <li key={i}>{hideInconclusive(line)}</li>
          ))}
        </ul>
      )}

      {running && (
        <div className="mt-3">
          <PlanningCue label={runningCue(step.id)} />
        </div>
      )}
    </div>
  );
}

function SessionAssessmentCard({ assessment }: { assessment: DastSessionAssessment }) {
  const positive = assessment.verdict === "true_positive";
  const label = positive ? "True positive" : "False positive";
  const source = assessment.model || assessment.provider || "Rules";
  const confidence =
    typeof assessment.confidence === "number"
      ? `${Math.round(assessment.confidence * 100)}% confidence · `
      : "";

  return (
    <section
      className={`rounded-xl border bg-white p-4 ${positive ? "border-red-200" : "border-emerald-200"}`}
      aria-label={`Session warning verdict: ${label}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-[var(--ink)]">Session warning checked</h3>
          <p className="mt-0.5 text-xs text-[var(--muted)]">Claim checked: {assessment.claim.toLowerCase()}</p>
        </div>
        <span
          className={`shrink-0 rounded-full border px-2.5 py-1 text-xs font-semibold ${
            positive
              ? "border-red-200 bg-red-50 text-red-700"
              : "border-emerald-200 bg-emerald-50 text-emerald-700"
          }`}
        >
          {label}
        </span>
      </div>
      <p className="mt-3 text-sm leading-relaxed text-[var(--ink)]">
        <strong>Why:</strong> {assessment.why}
      </p>
      <p className="mt-2 text-xs leading-relaxed text-[var(--muted)]">
        <strong>Evidence:</strong> {assessment.evidence.join(" · ")}
      </p>
      <p className="mt-2 text-[11px] text-slate-400">{confidence}{source}</p>
    </section>
  );
}

/** Show reached steps in order, stopping at the first one still running so
 * the next step does not appear until this one is done. */
function sequentialVisibleSteps(steps: DastNarrationStep[], liveScan: boolean): DastNarrationStep[] {
  const reached = steps.filter((s) => s.status !== "pending" && s.status !== "cancelled");
  if (!liveScan) return reached;
  const visible: DastNarrationStep[] = [];
  for (const step of reached) {
    visible.push(step);
    if (step.status === "running") break;
  }
  return visible;
}

export default function DastNarrationTimeline({
  narration,
  scanId,
  pages,
  targetUrl,
  discoveryCard,
  analysisCard,
  browserCard,
  findingsCard,
  matrixCard,
  reportCard,
  summaryCard,
}: {
  narration: DastNarration | null;
  scanId: string;
  /** Pages crawled so far — used to attach a screenshot under each visit line. */
  pages?: DastPage[] | null;
  /** Scan target, used to expand `GET /api/x` log lines into full http URLs. */
  targetUrl?: string | null;
  /** Rendered right after the crawl finishes, like SAST's "Discovery
   * results" card — opens the full results in the side panel on click. */
  discoveryCard?: ReactNode | null;
  /** Rendered right after the API-testing phase — opens the per-API security
   * analysis drill-down in the side panel on click. */
  analysisCard?: ReactNode | null;
  /** Rendered after testing to make browser/form coverage visible beside API testing. */
  browserCard?: ReactNode | null;
  /** Rendered after passive analysis and active testing, where the findings first exist. */
  findingsCard?: ReactNode | null;
  /** Rendered after the authorization step: the role-pair matrix. */
  matrixCard?: ReactNode | null;
  /** Rendered once the scan is done: the printable report and the diff against the last scan. */
  reportCard?: ReactNode | null;
  /** Rendered at the end of the conversation once the scan is done — opens
   * the finished summary in the side panel on click. */
  summaryCard?: ReactNode | null;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [stickToBottom, setStickToBottom] = useState(true);
  const lastScrollAtRef = useRef(0);
  const pendingScrollRef = useRef<number | null>(null);

  function scrollToBottom(immediate = false) {
    const el = scrollRef.current;
    if (!el) return;

    const run = () => {
      el.scrollTop = el.scrollHeight;
      lastScrollAtRef.current = Date.now();
      pendingScrollRef.current = null;
    };

    if (immediate) {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
        pendingScrollRef.current = null;
      }
      run();
      return;
    }

    const elapsed = Date.now() - lastScrollAtRef.current;
    if (elapsed >= SCROLL_THROTTLE_MS) {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
      }
      pendingScrollRef.current = requestAnimationFrame(run);
      return;
    }

    if (pendingScrollRef.current != null) return;
    pendingScrollRef.current = requestAnimationFrame(() => {
      const wait = SCROLL_THROTTLE_MS - (Date.now() - lastScrollAtRef.current);
      window.setTimeout(run, Math.max(0, wait));
    });
  }

  useEffect(() => {
    if (!stickToBottom) return;
    scrollToBottom(false);
    return () => {
      if (pendingScrollRef.current != null) {
        cancelAnimationFrame(pendingScrollRef.current);
        pendingScrollRef.current = null;
      }
    };
  }, [narration, stickToBottom]);

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    setStickToBottom(atBottom);
  }

  if (!narration) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-8">
        <PlanningCue label="Preparing DAST scan…" />
      </div>
    );
  }

  const stopped = narration.status === "cancelled";
  const live = narration.status === "queued" || narration.status === "running";
  const visible = sequentialVisibleSteps(narration.steps, live);
  const liveStep = visible[visible.length - 1];
  const betweenSteps = live && (!liveStep || liveStep.status !== "running");
  const origin = originOf(targetUrl);

  return (
    <div className="relative h-full min-h-0">
      <div ref={scrollRef} onScroll={handleScroll} className="agent-scroll h-full overflow-y-auto">
        <div className="mx-auto max-w-3xl px-6 py-8">
          <div className="min-w-0 space-y-5" role="log" aria-live="polite" aria-label="Scan activity">
            {visible.map((step) => (
              <div key={step.id} className="space-y-3">
                <Message step={step} scanId={scanId} pages={pages} origin={origin} />
                {step.id === "discovery" && step.status !== "running" && discoveryCard}
                {step.id === "discovery" && step.status !== "running" && narration.assessment ? (
                  <SessionAssessmentCard assessment={narration.assessment} />
                ) : null}
                {step.id === "testing" && step.status !== "running" && analysisCard}
                {step.id === "testing" && step.status !== "running" && browserCard}
                {step.id === "testing" && step.status !== "running" && findingsCard}
                {step.id === "authorization" && step.status !== "running" && matrixCard}
              </div>
            ))}

            {betweenSteps ? (
              <PlanningCue label={waitingCue(narration.steps, liveStep?.id)} />
            ) : null}

            {stopped && (
              <p className="dast-fade-in text-sm text-[var(--muted)]">
                The scan was stopped before I could finish.
              </p>
            )}

            {reportCard && <div className="dast-fade-in">{reportCard}</div>}
            {summaryCard && <div className="dast-fade-in">{summaryCard}</div>}
          </div>
        </div>
      </div>

      {!stickToBottom && (
        <div className="pointer-events-none absolute inset-x-0 bottom-4 z-10 flex justify-center">
          <button
            type="button"
            aria-label="Jump to latest activity"
            onClick={() => {
              setStickToBottom(true);
              scrollToBottom(true);
            }}
            className="agent-focus-ring pointer-events-auto rounded-full border border-blue-200 bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white shadow-md transition-colors hover:bg-blue-700"
          >
            Jump to latest ↓
          </button>
        </div>
      )}
    </div>
  );
}
