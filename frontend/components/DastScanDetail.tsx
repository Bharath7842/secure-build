"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import AgentArtifactCard from "@/components/AgentArtifactCard";
import { useConfirmDialog } from "@/components/ConfirmDialog";
import DastAnalysisPanel from "@/components/DastAnalysisPanel";
import DastAuthzMatrixPanel from "@/components/DastAuthzMatrix";
import DastCountersBar from "@/components/DastCountersBar";
import DastDiscoveryPanel from "@/components/DastDiscoveryPanel";
import DastFindingsPanel from "@/components/DastFindingsPanel";
import DastNarrationTimeline from "@/components/DastNarrationTimeline";
import DastReportPanel from "@/components/DastReportPanel";
import ResizableSplit from "@/components/ResizableSplit";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import { dastRoutingLabel, formatDastModel } from "@/lib/dastModels";
import type { DastDiscovery, DastNarration, DastSummary, Project, Scan, ScanStatus } from "@/lib/types";

const POLL_INTERVAL_MS = 2000;

function isTerminalStatus(status: string): boolean {
  return status !== "queued" && status !== "running";
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: "warn" }) {
  return (
    <div
      className={`rounded-md border px-3 py-2 ${
        tone === "warn" ? "border-amber-200 bg-amber-50" : "border-slate-200 bg-white"
      }`}
    >
      <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <p
        className={`mt-0.5 truncate text-lg font-semibold ${
          tone === "warn" ? "text-amber-700" : "text-[var(--ink)]"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

/** Mirrors the backend's `dast_report.coverage_narrative`: whether the run's results reflect
 * full coverage, built only from fields the discovery payload already carries. A partial run
 * should never read as a confident verdict, confirmed findings or not. */
function coverageNarrative(discovery: DastDiscovery | null | undefined): { complete: boolean; reasons: string[] } {
  if (!discovery) return { complete: true, reasons: [] };
  const reasons: string[] = [];
  if (discovery.stop_reason === "cancelled") reasons.push("the scan was cancelled before it finished");
  else if (discovery.stop_reason) reasons.push(`the scan stopped early (${discovery.stop_reason})`);
  if (discovery.credentials_lost) reasons.push("credentials were lost mid-scan and could not be refreshed");
  if (discovery.authentication_failed) reasons.push(`an identity failed to authenticate (${discovery.authentication_failed})`);
  const active = discovery.active_testing;
  if (active?.targets_capped) reasons.push(`${active.targets_capped} endpoint(s) were left untested by the target cap`);
  if (active?.session_lost_reason) reasons.push(`the active-testing session was lost mid-scan (${active.session_lost_reason})`);
  const authz = discovery.authorization;
  if (authz?.degraded) reasons.push(authz.degraded_reason || "the authorization checks ran degraded");
  if (authz?.cap_reached) reasons.push("the authorization replay cap was reached before every candidate was tried");
  return { complete: reasons.length === 0, reasons };
}

function overallLabel(
  status: string,
  confirmed: number,
  dismissed: number,
  coverage: { complete: boolean; reasons: string[] } = { complete: true, reasons: [] },
): { title: string; detail: string; tone: "ok" | "warn" | "bad" | "info" } {
  if (status === "failed") return { title: "Scan failed", detail: "The scan did not finish, so results are incomplete.", tone: "bad" };
  if (status === "cancelled") return { title: "Scan stopped", detail: "Requests already sent cannot be recalled. Findings so far are kept.", tone: "warn" };
  if (status === "queued" || status === "running") return { title: "Scan in progress", detail: "Live counts below update as pages, tests and findings arrive.", tone: "info" };
  if (!coverage.complete) {
    const base = confirmed > 0 ? `${confirmed} confirmed${dismissed > 0 ? ` · ${dismissed} dismissed` : ""}. ` : "";
    return { title: "Partial coverage", detail: `${base}${coverage.reasons.join("; ")}.`, tone: "warn" };
  }
  if (confirmed > 0) return { title: "Issues found", detail: `${confirmed} confirmed${dismissed > 0 ? ` · ${dismissed} dismissed` : ""}`, tone: "bad" };
  if (dismissed > 0) return { title: "No confirmed issues", detail: `${dismissed} check${dismissed === 1 ? "" : "s"} dismissed as false positive.`, tone: "ok" };
  return { title: "No confirmed issues", detail: "The scan finished and did not confirm any vulnerabilities.", tone: "ok" };
}

function formatDuration(startIso: string, endIso: string | null): string {
  const ms = (endIso ? new Date(endIso).getTime() : Date.now()) - new Date(startIso).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  return m > 0 ? `${m}m ${total % 60}s` : `${total}s`;
}

function DiscoveryIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
      <path d="M11 8v6M8 11h6" />
    </svg>
  );
}

/** Inline chat card that opens the full discovery results in the side
 * panel — same interaction as the SAST scan page's "Discovery results" card. */
function DastResultCard({
  discovery,
  active,
  onOpen,
}: {
  discovery: DastDiscovery;
  active: boolean;
  onOpen: () => void;
}) {
  return (
    <AgentArtifactCard
      icon={<DiscoveryIcon />}
      tone="emerald"
      title="Discovery results"
      subtitle={`${discovery.pages.length} pages · ${discovery.inventory_count ?? discovery.api_calls.length} endpoints · ${discovery.forms_count} forms`}
      active={active}
      onClick={onOpen}
      ariaLabel="Open discovery results"
    />
  );
}

function ShieldIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

/** Inline chat card that opens the per-REST-API security analysis in the side
 * panel — the Discover → API → Check → Payload → Response → Finding → Verdict
 * drill-down. Only shown once the analysis stage produced results. */
function DastAnalysisCard({
  discovery,
  active,
  onOpen,
}: {
  discovery: DastDiscovery;
  active: boolean;
  onOpen: () => void;
}) {
  const summary = discovery.analysis_summary;
  const tested = summary?.apis_tested ?? discovery.api_analysis?.length ?? 0;
  const fail = summary?.fail ?? 0;
  const passed = summary?.pass ?? 0;
  return (
    <AgentArtifactCard
      icon={<ShieldIcon />}
      tone={fail > 0 ? "red" : "amber"}
      title="API security analysis"
      subtitle={`${tested} API${tested !== 1 ? "s" : ""} tested · ${fail} failing · ${passed} passed`}
      active={active}
      onClick={onOpen}
      ariaLabel="Open API security analysis"
    />
  );
}

function iconSvg(paths: React.ReactNode) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {paths}
    </svg>
  );
}

function DastFindingsCard({ summary, active, onOpen }: { summary: DastSummary | null; active: boolean; onOpen: () => void }) {
  const confirmed = summary?.findings.by_verdict.true_positive ?? 0;
  const dismissed = summary?.findings.by_verdict.false_positive ?? 0;
  return (
    <AgentArtifactCard
      icon={iconSvg(<><path d="M12 9v4" /><path d="M12 17h.01" /><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></>)}
      tone={confirmed > 0 ? "red" : "emerald"}
      title="Findings"
      subtitle={`${confirmed} confirmed${dismissed > 0 ? ` · ${dismissed} dismissed` : ""}`}
      active={active}
      onClick={onOpen}
      ariaLabel="Open findings"
    />
  );
}

function DastMatrixCard({ discovery, active, onOpen }: { discovery: DastDiscovery; active: boolean; onOpen: () => void }) {
  const authz = discovery.authorization;
  return (
    <AgentArtifactCard
      icon={iconSvg(<><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>)}
      tone={authz && authz.findings > 0 ? "red" : "purple"}
      title="Authorization"
      subtitle={
        authz?.ran
          ? `${authz.total_replays} request${authz.total_replays === 1 ? "" : "s"} checked · ${authz.findings} issue${authz.findings === 1 ? "" : "s"}`
          : "did not run"
      }
      active={active}
      onClick={onOpen}
      ariaLabel="Open authorization"
    />
  );
}

function DastReportCard({ active, onOpen }: { active: boolean; onOpen: () => void }) {
  return (
    <AgentArtifactCard
      icon={iconSvg(<><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><path d="M14 3v6h6" /><path d="M8 13h8M8 17h5" /></>)}
      tone="blue"
      title="Report and changes"
      subtitle="Findings, what changed since the last scan, downloads"
      active={active}
      onClick={onOpen}
      ariaLabel="Open report"
    />
  );
}

function SummaryIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <rect x="4" y="3" width="16" height="18" rx="2" />
      <path d="M8 8h8M8 12h8M8 16h5" />
    </svg>
  );
}

/** Inline chat card that opens the finished scan's summary in the side
 * panel — same click-to-open interaction as the "Discovery results" card.
 * Only rendered once the scan is done: a running scan's duration and
 * resource counts are still changing, so showing them mid-run just invites
 * the reader to watch a half-finished number. */
function DastSummaryCard({
  overall,
  discovery,
  active,
  onOpen,
}: {
  overall: { title: string; detail: string };
  discovery: DastDiscovery | null;
  active: boolean;
  onOpen: () => void;
}) {
  return (
    <AgentArtifactCard
      icon={<SummaryIcon />}
      tone="blue"
      title="Scan summary"
      subtitle={`${overall.title} · ${overall.detail}${discovery ? ` · ${discovery.pages.length} pages` : ""}`}
      active={active}
      onClick={onOpen}
      ariaLabel="Open scan summary"
    />
  );
}

function DastSummaryPanel({
  status,
  scan,
  discovery,
  overall,
  counters,
  onClose,
}: {
  status: ScanStatus;
  scan: Scan | null;
  discovery: DastDiscovery | null;
  overall: { title: string; detail: string; tone: "ok" | "warn" | "bad" | "info" };
  counters: DastSummary | null;
  onClose: () => void;
}) {
  const terminal = isTerminalStatus(status.status);
  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-[var(--ink)]">Scan summary</h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close scan summary"
          className="rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100"
        >
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-6 overflow-auto px-4 py-4">
        <div
          className={`rounded-md border px-3 py-2.5 ${
            overall.tone === "bad"
              ? "border-red-200 bg-red-50"
              : overall.tone === "warn"
                ? "border-amber-200 bg-amber-50"
                : overall.tone === "ok"
                  ? "border-emerald-200 bg-emerald-50"
                  : "border-slate-200 bg-slate-50"
          }`}
        >
          <p className="text-sm font-semibold text-[var(--ink)]">{overall.title}</p>
          <p className="mt-0.5 text-xs text-[var(--muted)]">
            {overall.detail}
            {scan && (
              <>
                <span className="mx-1.5">·</span>
                {formatDuration(scan.created_at, terminal ? scan.updated_at : null)}
              </>
            )}
            {(discovery?.target_url || scan?.git_url) && (
              <>
                <span className="mx-1.5">·</span>
                <span className="font-mono">{discovery?.target_url ?? scan?.git_url}</span>
              </>
            )}
          </p>
        </div>

        <DastCountersBar summary={counters} embedded />

        <dl className="space-y-2 text-sm">
          <div className="flex justify-between gap-3">
            <dt className="text-[var(--muted)]">Target</dt>
            <dd className="min-w-0 truncate text-right text-[var(--ink)]" title={scan?.git_url}>
              {discovery?.target_url ?? scan?.git_url ?? "—"}
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-[var(--muted)]">Status</dt>
            <dd><ScanStatusBadge status={status.status} /></dd>
          </div>
          {scan && (
            <>
              <div className="flex justify-between gap-3">
                <dt className="text-[var(--muted)]">Started at</dt>
                <dd className="text-[var(--ink)]">{new Date(scan.created_at).toLocaleString()}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-[var(--muted)]">Duration</dt>
                <dd className="text-[var(--ink)]">{formatDuration(scan.created_at, scan.updated_at)}</dd>
              </div>
            </>
          )}
        </dl>
        {discovery && (
          <div className="grid grid-cols-3 gap-2 text-center">
            <Stat label="Pages" value={discovery.pages.length} />
            <Stat label="APIs" value={discovery.api_calls.length} />
            <Stat label="Forms" value={discovery.forms_count} />
          </div>
        )}
        {discovery?.analysis_summary && (
          <div className="grid grid-cols-3 gap-2 text-center">
            <Stat label="APIs tested" value={discovery.analysis_summary.apis_tested} />
            <Stat
              label="Failing"
              value={discovery.analysis_summary.fail}
              tone={discovery.analysis_summary.fail > 0 ? "warn" : undefined}
            />
            <Stat label="Passed" value={discovery.analysis_summary.pass} />
          </div>
        )}
      </div>
    </div>
  );
}

interface DastScanDetailProps {
  scanId: string;
}

/** Detail view for scan_type=dast — same shape as the SAST page: the live
 * engine log on the left, discovery results in a resizable side panel. */
export default function DastScanDetail({ scanId }: DastScanDetailProps) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [scanRecord, setScanRecord] = useState<Scan | null>(null);
  const [narration, setNarration] = useState<DastNarration | null>(null);
  const [discovery, setDiscovery] = useState<DastDiscovery | null>(null);
  const [dastRouting, setDastRouting] = useState<unknown>(null);
  const [resultsError, setResultsError] = useState<string | null>(null);
  const [counters, setCounters] = useState<DastSummary | null>(null);
  const [rolePair, setRolePair] = useState<string | null>(null);
  const [sidePanel, setSidePanel] = useState<"discovery" | "analysis" | "findings" | "matrix" | "report" | "summary" | null>(null);
  const [autoOpened, setAutoOpened] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const { confirm, dialog } = useConfirmDialog();

  // Status
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;

    async function poll() {
      try {
        const data = await api.scans.status(scanId);
        if (!active) return;
        setStatus(data);
        setNotFound(false);
        if (isTerminalStatus(data.status) && timer) {
          clearInterval(timer);
          timer = null;
        }
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
          if (timer) clearInterval(timer);
          timer = null;
        }
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [scanId]);

  // Project / scan row for the header
  useEffect(() => {
    const projectId = status?.project_id;
    if (!projectId) return;
    let active = true;
    Promise.all([
      api.projects.get(projectId).catch(() => null),
      api.scans.list(projectId, "dast").catch(() => []),
    ]).then(([projectData, scans]) => {
      if (!active) return;
      setProject(projectData);
      setScanRecord(scans.find((scan) => scan.id === scanId) ?? null);
    });
    return () => {
      active = false;
    };
  }, [status?.project_id, scanId]);

  // Live counters: cheap, so poll with the status; one last read after the scan ends.
  const counterStatus = status?.status ?? null;
  useEffect(() => {
    if (counterStatus === null) return;
    const live = !isTerminalStatus(counterStatus);
    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;
    async function read() {
      try {
        const data = await api.scans.summary(scanId);
        if (active) setCounters(data);
      } catch {
        // Counters are informational; the rest of the page does not depend on them.
      }
    }
    read();
    if (live) timer = setInterval(read, POLL_INTERVAL_MS);
    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [scanId, counterStatus]);

  // Per-step log, thinking and reasoning. Keep polling while the scan runs and
  // while any finished step is still waiting on its reasoning.
  const scanStatusValue = status?.status ?? null;
  useEffect(() => {
    if (scanStatusValue === null) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;

    async function poll() {
      let keepGoing = !isTerminalStatus(scanStatusValue as string);
      try {
        const data = await api.scans.narration(scanId);
        if (!active) return;
        setNarration(data);
        keepGoing = keepGoing || data.pending;
      } catch {
        // Best-effort: narration must not disrupt the rest of the page.
      }
      if (active && keepGoing) timer = setTimeout(poll, POLL_INTERVAL_MS);
    }

    poll();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [scanId, scanStatusValue]);

  // Discovery results (409 until the engine has written something)
  const statusValue = status?.status ?? null;
  useEffect(() => {
    if (statusValue === null) return;
    const terminal = isTerminalStatus(statusValue);
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function fetchResults() {
      try {
        const data = await api.scans.results(scanId);
        if (!active) return;
        setDiscovery((data.discovery as DastDiscovery | null) ?? null);
        setDastRouting((data.dast_effective as { model_routing?: unknown } | null)?.model_routing ?? null);
        setResultsError(null);
        if (isTerminalStatus(data.status) && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch (err) {
        if (!active) return;
        if (!(err instanceof ApiError && err.status === 409) && terminal) {
          setResultsError(err instanceof ApiError ? err.message : "Failed to load scan results.");
        }
      }
    }

    fetchResults();
    if (!terminal) interval = setInterval(fetchResults, POLL_INTERVAL_MS);
    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [scanId, statusValue]);

  async function stopScan() {
    if (!(await confirm({ message: "Stop this scan? Requests already sent cannot be recalled; findings so far are kept.", confirmLabel: "Stop" }))) return;
    setStopping(true);
    setStopError(null);
    try {
      setStatus(await api.scans.cancel(scanId));
    } catch (err) {
      setStopError(err instanceof ApiError ? err.message : "Could not stop scan.");
    } finally {
      setStopping(false);
    }
  }

  const terminal = status ? isTerminalStatus(status.status) : false;
  const confirmedCount = counters?.findings.by_verdict.true_positive ?? 0;
  const dismissedCount =
    (counters?.findings.by_verdict.false_positive ?? 0) + (counters?.findings.by_verdict.unverified ?? 0);

  useEffect(() => {
    if (autoOpened || !terminal) return;
    if (confirmedCount + dismissedCount > 0) {
      setSidePanel("findings");
      setAutoOpened(true);
    } else if ((discovery?.api_analysis?.length ?? 0) > 0) {
      setSidePanel("analysis");
      setAutoOpened(true);
    } else if (discovery) {
      setSidePanel("summary");
      setAutoOpened(true);
    }
  }, [autoOpened, terminal, confirmedCount, dismissedCount, discovery]);

  if (notFound) {
    return (
      <div className="flex h-full items-center justify-center px-12 py-10">
        <div className="rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
          <p className="text-sm text-[var(--muted)]">Scan not found.</p>
          <Link href="/dast" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
            ← Back to DAST
          </Link>
        </div>
      </div>
    );
  }
  if (!status) {
    return <p className="px-12 py-10 text-sm text-[var(--muted)]">Loading scan…</p>;
  }

  const overall = overallLabel(status.status, confirmedCount, dismissedCount, coverageNarrative(discovery));
  const llmLabel =
    dastRoutingLabel(dastRouting) ||
    (scanRecord?.llm_provider || scanRecord?.llm_model
      ? formatDastModel(scanRecord.llm_provider || "", scanRecord.llm_model || "")
      : null);

  const failed = terminal && status.status === "failed" && status.message;
  const hasNotices = stopError || resultsError || failed || status.status === "cancelled";
  const hasFindings = (counters?.findings.total ?? 0) > 0 || (discovery?.passive_analysis?.findings ?? 0) > 0;
  const hasAuthz = !!discovery?.authorization;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-white">
      {dialog}
      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-slate-200 px-6 py-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link
            href="/dast"
            className="shrink-0 text-sm font-medium text-[var(--accent)] hover:underline"
          >
            ← DAST
          </Link>
          <span className="shrink-0 text-slate-300">/</span>
          <p className="min-w-0 truncate text-sm text-[var(--ink)]">
            <span className="font-medium">{project?.name ?? status.project_id}</span>
            {scanRecord?.git_url && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">{scanRecord.git_url}</span>
              </>
            )}
            {scanRecord && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">Scan · v{scanRecord.version}</span>
              </>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          {llmLabel && (
            <span className="max-w-[20rem] truncate text-xs font-medium text-[var(--muted)]" title={llmLabel}>
              {llmLabel}
            </span>
          )}
          <ScanStatusBadge status={status.status} />
        </div>
      </div>

      {hasNotices && (
        <div className="shrink-0 space-y-2 border-b border-slate-200 px-6 py-3">
          {stopError && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {stopError}
            </div>
          )}
          {resultsError && (
            <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {resultsError}
            </div>
          )}
          {failed && (
            <div role="alert" className="rounded-md border border-red-300 bg-red-50 px-3 py-2.5 text-sm text-red-800">
              <p className="font-semibold">The scan failed</p>
              <p className="mt-0.5 break-words">{status.message}</p>
            </div>
          )}
          {status.status === "cancelled" && (
            <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
              This scan was stopped. Delete it from the{" "}
              <Link href="/dast" className="font-medium underline">
                DAST list
              </Link>{" "}
              if you no longer need it.
            </div>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">
        <ResizableSplit
          left={
            <div className="flex h-full min-h-0 flex-col">
              <div className="min-h-0 flex-1 overflow-hidden">
                <DastNarrationTimeline
                  narration={narration}
                  scanId={scanId}
                  pages={discovery?.pages}
                  targetUrl={discovery?.target_url ?? scanRecord?.git_url}
                  apiAnalysis={discovery?.api_analysis}
                  inventory={discovery?.inventory}
                  apiCalls={discovery?.api_calls}
                  discoveryCard={
                    discovery ? (
                      <DastResultCard
                        discovery={discovery}
                        active={sidePanel === "discovery"}
                        onOpen={() => setSidePanel("discovery")}
                      />
                    ) : null
                  }
                  analysisCard={
                    discovery && (discovery.api_analysis?.length ?? 0) > 0 ? (
                      <DastAnalysisCard
                        discovery={discovery}
                        active={sidePanel === "analysis"}
                        onOpen={() => setSidePanel("analysis")}
                      />
                    ) : null
                  }
                  findingsCard={
                    hasFindings || (terminal && counters) ? (
                      <DastFindingsCard summary={counters} active={sidePanel === "findings"} onOpen={() => setSidePanel("findings")} />
                    ) : null
                  }
                  matrixCard={
                    discovery && hasAuthz ? (
                      <DastMatrixCard discovery={discovery} active={sidePanel === "matrix"} onOpen={() => setSidePanel("matrix")} />
                    ) : null
                  }
                  reportCard={terminal && status.status === "success" ? <DastReportCard active={sidePanel === "report"} onOpen={() => setSidePanel("report")} /> : null}
                  summaryCard={
                    terminal ? (
                      <DastSummaryCard
                        overall={overall}
                        discovery={discovery}
                        active={sidePanel === "summary"}
                        onOpen={() => setSidePanel("summary")}
                      />
                    ) : null
                  }
                />
              </div>
              {!terminal && (
                <div className="flex shrink-0 items-center justify-between gap-3 border-t border-slate-200 px-6 py-3">
                  <p className="text-xs text-[var(--muted)]">Scan in progress · {status.progress}%</p>
                  <button
                    type="button"
                    onClick={stopScan}
                    disabled={stopping}
                    className="agent-focus-ring rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-[var(--ink)] hover:bg-slate-50 disabled:opacity-50"
                  >
                    {stopping ? "Stopping…" : "Stop scan"}
                  </button>
                </div>
              )}
            </div>
          }
          right={
            sidePanel === "discovery" && discovery ? (
              <DastDiscoveryPanel discovery={discovery} onClose={() => setSidePanel(null)} />
            ) : sidePanel === "analysis" && discovery?.api_analysis ? (
              <DastAnalysisPanel
                analysis={discovery.api_analysis}
                discovery={discovery}
                onClose={() => setSidePanel(null)}
              />
            ) : sidePanel === "findings" ? (
              <DastFindingsPanel scanId={scanId} live={!terminal} rolePair={rolePair} onRolePairChange={setRolePair} onClose={() => setSidePanel(null)} />
            ) : sidePanel === "matrix" ? (
              <DastAuthzMatrixPanel
                scanId={scanId}
                live={!terminal}
                selected={rolePair}
                onSelect={(pair) => {
                  setRolePair(pair);
                  if (pair) setSidePanel("findings");
                }}
                onClose={() => setSidePanel(null)}
              />
            ) : sidePanel === "report" ? (
              <DastReportPanel scanId={scanId} projectId={status.project_id} version={scanRecord?.version ?? null} running={!terminal} onClose={() => setSidePanel(null)} />
            ) : sidePanel === "summary" ? (
              <DastSummaryPanel
                status={status}
                scan={scanRecord}
                discovery={discovery}
                overall={overall}
                counters={counters}
                onClose={() => setSidePanel(null)}
              />
            ) : null
          }
        />
      </div>
    </div>
  );
}
