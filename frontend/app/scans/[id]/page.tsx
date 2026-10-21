"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import ScanAgentLog, { type SectionCard } from "@/components/ScanAgentLog";
import ProjectStructurePanel from "@/components/ProjectStructurePanel";
import AstSummaryPanel from "@/components/AstSummaryPanel";
import DerivedRulesCard from "@/components/DerivedRulesCard";
import DerivedRulesPanel from "@/components/DerivedRulesPanel";
import ResizableSplit from "@/components/ResizableSplit";
import ScanUsageCard from "@/components/ScanUsageCard";
import ScanUsageResultPanel from "@/components/ScanUsageResultPanel";
import ScanFindingsCard from "@/components/ScanFindingsCard";
import ScanFindingsResultPanel from "@/components/ScanFindingsResultPanel";
import ScanExportButtons from "@/components/ScanExportButtons";
import ScanResultCard from "@/components/ScanResultCard";
import ScanResultPanel from "@/components/ScanResultPanel";
import ScaScanDetail from "@/components/ScaScanDetail";
import DastScanDetail from "@/components/DastScanDetail";
import SbomScanDetail from "@/components/SbomScanDetail";
import ScanStatusBadge from "@/components/ScanStatusBadge";
import { ApiError, api } from "@/lib/api";
import { hasUsageData } from "@/lib/formatUsage";
import { DEEP_SCAN_SECTION_RE, TRIAGE_SECTION_RE, extractProjectStructureTree } from "@/lib/parseScanLog";
import { DESKTOP_SPLIT_QUERY, useMediaQuery } from "@/lib/useMediaQuery";
import type { Project, Scan, ScanDiscovery, ScanLogLine, ScanResults, ScanStatus } from "@/lib/types";
import { useAuth } from "@/components/auth/AuthProvider";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import { canStopScan } from "@/lib/access";

const POLL_INTERVAL_MS = 2000;
const RESULTS_RETRY_MS = 2000;

function isTerminalStatus(status: string): boolean {
  return status !== "queued" && status !== "running";
}

function isActiveStatus(status: string): boolean {
  return status === "queued" || status === "running";
}

export default function ScanDetailPage() {
  const me = useAuth();
  const { setActiveProjectId, setViewedScanType } = useActiveProject();
  const params = useParams<{ id: string }>();
  const searchParams = useSearchParams();
  const id = params.id;
  const reused = searchParams.get("reused") === "1";

  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [statusRetrying, setStatusRetrying] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const [project, setProject] = useState<Project | null>(null);
  const [scanRecord, setScanRecord] = useState<Scan | null>(null);

  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const { confirm, dialog } = useConfirmDialog();

  const [results, setResults] = useState<ScanResults | null>(null);
  const [resultsError, setResultsError] = useState<string | null>(null);
  const [findingsSummary, setFindingsSummary] = useState<{
    tp_count: number;
    fp_count: number;
    unverified_count: number;
    files_scanned: number;
  } | null>(null);
  const [sidePanel, setSidePanel] = useState<
    "discovery" | "findings" | "usage" | "structure" | "ast" | "rules" | null
  >(null);
  const [panelExpanded, setPanelExpanded] = useState(false);
  const [structureTree, setStructureTree] = useState<string[] | null>(null);
  const isDesktop = useMediaQuery(DESKTOP_SPLIT_QUERY);

  function closeSidePanel() {
    setSidePanel(null);
    setPanelExpanded(false);
  }

  const [logLines, setLogLines] = useState<ScanLogLine[]>([]);
  const logAfterRef = useRef(0);
  const logPollingRef = useRef(false);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;

    async function poll() {
      try {
        const data = await api.scans.status(id);
        if (!active) return;
        setStatus(data);
        setStatusRetrying(false);
        setNotFound(false);
        if (isTerminalStatus(data.status) && timer) {
          clearInterval(timer);
          timer = null;
        }
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true);
          if (timer) {
            clearInterval(timer);
            timer = null;
          }
        } else {
          setStatusRetrying(true);
        }
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [id]);

  useEffect(() => {
    // SCA/SBOM scans render an entirely separate detail view (ScaScanDetail/
    // SbomScanDetail below) that never shows the engine log panel — skip
    // polling it for those scan_types once known, rather than running an
    // unused interval for the page's lifetime.
    if (
      status?.scan_type === "sca" ||
      status?.scan_type === "sbom" ||
      status?.scan_type === "dast"
    )
      return;

    let active = true;
    let timer: ReturnType<typeof setInterval> | null = null;
    let stopAfterNextPoll = false;
    logAfterRef.current = 0;
    setLogLines([]);

    async function poll() {
      if (logPollingRef.current) return;
      logPollingRef.current = true;
      try {
        const data = await api.scans.logs(id, logAfterRef.current);
        if (!active) return;
        logAfterRef.current = data.next_after;
        if (data.lines.length > 0) {
          setLogLines((prev) => {
            const seen = new Set(prev.map((line) => line.seq));
            const fresh = data.lines.filter((line) => !seen.has(line.seq));
            return fresh.length > 0 ? [...prev, ...fresh] : prev;
          });
        }
        if (isTerminalStatus(data.status)) {
          if (stopAfterNextPoll && timer) {
            clearInterval(timer);
            timer = null;
          } else {
            stopAfterNextPoll = true;
          }
        }
      } catch {
        // Best-effort: the live log is a nice-to-have, don't disrupt the rest of the page.
      } finally {
        logPollingRef.current = false;
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [id, status?.scan_type]);

  // The sidebar follows the scan: its project and its type's menu.
  useEffect(() => {
    if (status?.project_id) setActiveProjectId(status.project_id);
  }, [status?.project_id, setActiveProjectId]);

  const viewedType = scanRecord?.scan_type ?? null;
  useEffect(() => {
    setViewedScanType(viewedType);
    return () => setViewedScanType(null);
  }, [viewedType, setViewedScanType]);

  useEffect(() => {
    const projectId = status?.project_id;
    if (!projectId) return;

    let active = true;

    async function loadMeta(pid: string) {
      const [projectData, scans] = await Promise.all([
        api.projects.get(pid).catch(() => null),
        api.scans.list(pid).catch(() => []),
      ]);
      if (!active) return;
      setProject(projectData);
      setScanRecord(scans.find((scan) => scan.id === id) ?? null);
    }

    loadMeta(projectId);
    return () => {
      active = false;
    };
  }, [status?.project_id, id]);

  // Poll results once Mapping module risk may have persisted discovery (progress
  // ≥ 95) — including while the scan is still running CRITICAL-file scanning.
  useEffect(() => {
    if (!status) return;
    // handled entirely by ScaScanDetail/SbomScanDetail
    if (status.scan_type === "sca" || status.scan_type === "sbom" || status.scan_type === "dast")
      return;
    const terminal = isTerminalStatus(status.status);
    const mayHaveDiscovery = terminal || (status.progress ?? 0) >= 95;
    if (!mayHaveDiscovery) return;

    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function fetchResults() {
      try {
        const data = await api.scans.results(id);
        if (!active) return;
        setResults(data);
        setResultsError(null);
        if (isTerminalStatus(data.status) && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch (err) {
        if (!active) return;
        if (err instanceof ApiError && err.status === 409) {
          timer = setTimeout(fetchResults, RESULTS_RETRY_MS);
        } else if (terminal) {
          setResultsError(err instanceof ApiError ? err.message : "Failed to load scan results.");
        }
      }
    }

    fetchResults();
    if (!terminal) {
      interval = setInterval(fetchResults, POLL_INTERVAL_MS);
    }

    return () => {
      active = false;
      if (timer) clearTimeout(timer);
      if (interval) clearInterval(interval);
    };
  }, [id, status]);

  // Load finding counts from DB — poll only while CRITICAL-file scanning is
  // still running; terminal scans (including cancelled) fetch once.
  useEffect(() => {
    if (!status) return;
    // handled entirely by ScaScanDetail/SbomScanDetail
    if (status.scan_type === "sca" || status.scan_type === "sbom" || status.scan_type === "dast")
      return;
    const pollFindings =
      isActiveStatus(status.status) && (status.progress ?? 0) >= 97;
    const shouldLoadFindings = pollFindings || isTerminalStatus(status.status);
    if (!shouldLoadFindings) return;

    const scanStatus = status.status;
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function loadFindings() {
      try {
        const data = await api.scans.findings(id);
        if (!active) return;
        setFindingsSummary({
          tp_count: data.tp_count,
          fp_count: data.fp_count,
          unverified_count: data.unverified_count ?? 0,
          files_scanned: data.files_scanned,
        });
        if (isTerminalStatus(scanStatus) && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch {
        if (!active) return;
        setFindingsSummary(null);
      }
    }

    loadFindings();
    if (pollFindings) {
      interval = setInterval(loadFindings, POLL_INTERVAL_MS);
    }

    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [id, status]);

  useEffect(() => {
    const tree = extractProjectStructureTree(logLines);
    if (tree) setStructureTree(tree);
  }, [logLines]);

  // This page's own rendering (below) is SAST-only — for scan_type=sca we
  // return <ScaScanDetail> before any of this is used, but `discovery` still
  // has to be computed unconditionally above that check (hooks can't be
  // conditional). Safe to assert the SAST shape here since nothing below
  // ever reaches the DOM for an sca-typed scan.
  const discovery = (results?.discovery ?? null) as ScanDiscovery | null;
  const reportFromResults = discovery?.report ?? null;
  const effectiveReport = useMemo(() => {
    const fromMeta = reportFromResults;
    const metaTotal =
      (fromMeta?.tp_count ?? 0) +
      (fromMeta?.fp_count ?? 0) +
      (fromMeta?.unverified_count ?? 0);
    const dbTotal =
      (findingsSummary?.tp_count ?? 0) +
      (findingsSummary?.fp_count ?? 0) +
      (findingsSummary?.unverified_count ?? 0);
    if (fromMeta && metaTotal >= dbTotal && metaTotal > 0) {
      return fromMeta;
    }
    if (findingsSummary && dbTotal > 0) {
      return {
        files_scanned: Math.max(
          fromMeta?.files_scanned ?? 0,
          findingsSummary.files_scanned,
        ),
        tp_count: findingsSummary.tp_count,
        fp_count: findingsSummary.fp_count,
        unverified_count: findingsSummary.unverified_count,
        by_owasp_category: fromMeta?.by_owasp_category ?? {},
      };
    }
    return fromMeta;
  }, [reportFromResults, findingsSummary]);
  const usageSummary = results?.usage_summary ?? null;
  const scanningFindings =
    status != null && isActiveStatus(status.status) && (status.progress ?? 0) >= 70;
  const scanningLow =
    scanningFindings && (status?.progress ?? 0) >= 97;
  const hasSavedFindings = Boolean(
    findingsSummary &&
      (findingsSummary.tp_count > 0 ||
        findingsSummary.fp_count > 0 ||
        findingsSummary.unverified_count > 0)
  );
  const hasFindingsReport = Boolean(
    effectiveReport &&
      (effectiveReport.tp_count > 0 ||
        effectiveReport.fp_count > 0 ||
        (effectiveReport.unverified_count ?? 0) > 0 ||
        effectiveReport.files_scanned > 0)
  );
  const canExportFindings =
    status != null && isTerminalStatus(status.status) && hasSavedFindings;
  const showUsageCard =
    status != null &&
    isTerminalStatus(status.status) &&
    hasUsageData(usageSummary);

  const astSummary = discovery?.llm_analysis?.ast_summary;
  const derivedRules = discovery?.derived_rules ?? [];
  const derivedRulesSummary = discovery?.derived_rules_summary;
  const hasDerivedRules = derivedRules.length > 0 || (derivedRulesSummary?.failed ?? 0) > 0;

  const sectionCards = useMemo(() => {
    const cards: SectionCard[] = [];
    if (discovery) {
      cards.push({
        afterLabel: "Mapping module risk",
        node: (
          <ScanResultCard
            discovery={discovery}
            active={sidePanel === "discovery"}
            onOpen={() => setSidePanel("discovery")}
          />
        ),
      });
    }
    if (hasDerivedRules) {
      cards.push({
        afterLabel: "Deriving runtime regex",
        node: (
          <DerivedRulesCard
            rules={derivedRules}
            summary={derivedRulesSummary}
            active={sidePanel === "rules"}
            onOpen={() => setSidePanel("rules")}
          />
        ),
      });
    }
    if (hasFindingsReport && effectiveReport) {
      cards.push({
        afterLabel: scanningLow
          ? TRIAGE_SECTION_RE
          : scanningFindings
            ? DEEP_SCAN_SECTION_RE
            : "Generating report",
        node: (
          <ScanFindingsCard
            report={effectiveReport}
            active={sidePanel === "findings"}
            onOpen={() => setSidePanel("findings")}
          />
        ),
      });
    }
    if (showUsageCard && usageSummary) {
      cards.push({
        afterLabel: "Generating report",
        node: (
          <ScanUsageCard
            usage={usageSummary}
            active={sidePanel === "usage"}
            onOpen={() => setSidePanel("usage")}
          />
        ),
      });
    }
    return cards;
  }, [
    discovery,
    hasDerivedRules,
    derivedRules,
    derivedRulesSummary,
    hasFindingsReport,
    effectiveReport,
    sidePanel,
    scanningFindings,
    scanningLow,
    showUsageCard,
    usageSummary,
  ]);

  if (notFound) {
    return (
      <div className="flex h-full items-center justify-center px-12 py-10">
        <div className="rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center">
          <p className="text-sm text-[var(--muted)]">Scan not found.</p>
          <Link href="/scans" className="mt-2 inline-block text-sm font-medium text-[var(--accent)]">
            ← Back to scan history
          </Link>
        </div>
      </div>
    );
  }

  if (statusRetrying && !status) {
    return (
      <div className="px-12 py-10">
        <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          Having trouble reaching the server, retrying…
        </div>
        <p className="mt-4 text-sm text-[var(--muted)]">Loading scan…</p>
      </div>
    );
  }

  if (!status) {
    return <p className="px-12 py-10 text-sm text-[var(--muted)]">Loading scan…</p>;
  }

  if (status.scan_type === "sca") {
    return <ScaScanDetail scanId={id} />;
  }
  if (status.scan_type === "sbom") {
    return <SbomScanDetail scanId={id} />;
  }
  if (status.scan_type === "dast") {
    return <DastScanDetail scanId={id} />;
  }

  const terminal = isTerminalStatus(status.status);

  async function stopScan() {
    if (!(await confirm({ message: "Stop this scan?", confirmLabel: "Stop" }))) return;
    setStopping(true);
    setStopError(null);
    try {
      const updated = await api.scans.cancel(id);
      setStatus(updated);
    } catch (err) {
      setStopError(err instanceof ApiError ? err.message : "Could not stop scan.");
    } finally {
      setStopping(false);
    }
  }

  const notices = (
    <>
      {stopError && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {stopError}
        </div>
      )}
      {status.status === "cancelled" && (
        <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
          <p>
            This scan was stopped.
            {hasSavedFindings && findingsSummary ? (
              <>
                {" "}
                {findingsSummary.tp_count +
                  findingsSummary.fp_count +
                  findingsSummary.unverified_count}{" "}
                finding(s) saved so far ({findingsSummary.tp_count} confirmed,{" "}
                {findingsSummary.fp_count} false positive
                {findingsSummary.unverified_count
                  ? `, ${findingsSummary.unverified_count} unresolved`
                  : ""}
                ).
              </>
            ) : null}{" "}
            Delete it from{" "}
            <Link href="/scans" className="font-medium underline">
              Scan History
            </Link>{" "}
            if you no longer need it.
          </p>
          {canExportFindings && <ScanExportButtons scanId={id} compact />}
        </div>
      )}
      {reused && (
        <div className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-sm text-sky-800">
          No changes since the last scan for this branch — showing the existing results below
          instead of running a new scan. Check &quot;Force scan&quot; on the Agentic SAST SCAN form to
          re-scan anyway.
        </div>
      )}
      {statusRetrying && (
        <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
          Having trouble reaching the server, retrying…
        </div>
      )}
      {resultsError && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {resultsError}
        </div>
      )}
      {terminal && status.status === "failed" && status.message && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {status.message}
        </div>
      )}
    </>
  );

  const hasNotices =
    stopError ||
    status.status === "cancelled" ||
    reused ||
    statusRetrying ||
    resultsError ||
    (terminal && status.status === "failed" && status.message);

  const scanLabel = scanRecord ? `Scan · v${scanRecord.version}` : null;
  const source = scanRecord ? (scanRecord.triggered_by === "jenkins" ? "Jenkins" : "App") : null;

  const rightPanel =
    sidePanel === "discovery" && discovery ? (
      <ScanResultPanel
        discovery={discovery}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : sidePanel === "findings" && effectiveReport ? (
      <ScanFindingsResultPanel
        scanId={id}
        report={effectiveReport}
        live={scanningFindings}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : sidePanel === "usage" && usageSummary ? (
      <ScanUsageResultPanel
        usage={usageSummary}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : sidePanel === "structure" && structureTree ? (
      <ProjectStructurePanel
        tree={structureTree}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : sidePanel === "ast" && astSummary ? (
      <AstSummaryPanel
        summary={astSummary}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : sidePanel === "rules" ? (
      <DerivedRulesPanel
        rules={derivedRules}
        summary={derivedRulesSummary}
        onClose={closeSidePanel}
        expanded={panelExpanded}
        onToggleExpand={isDesktop ? () => setPanelExpanded((v) => !v) : undefined}
      />
    ) : null;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-white">
      {dialog}
      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-slate-200 px-6 py-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link
            href="/scans"
            className="shrink-0 text-sm font-medium text-[var(--accent)] hover:underline"
          >
            ← Scans
          </Link>
          <span className="shrink-0 text-slate-300">/</span>
          <p className="min-w-0 truncate text-sm text-[var(--ink)]">
            <span className="font-medium">{project?.name ?? status.project_id}</span>
            {scanRecord?.branch && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">Branch: {scanRecord.branch}</span>
              </>
            )}
            {scanLabel && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">{scanLabel}</span>
              </>
            )}
            {source && (
              <>
                <span className="mx-1.5 text-[var(--muted)]">·</span>
                <span className="text-[var(--muted)]">Source: {source}</span>
              </>
            )}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          {canExportFindings && <ScanExportButtons scanId={id} compact />}
          <ScanStatusBadge status={status.status} />
        </div>
      </div>

      {hasNotices && (
        <div className="shrink-0 space-y-2 border-b border-slate-200 px-6 py-3">{notices}</div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden">
        <ResizableSplit
          left={
            <ScanAgentLog
              lines={logLines}
              live={!terminal}
              scanStatus={status.status}
              progress={status.progress}
              failureMessage={terminal && status.status === "failed" ? status.message : null}
              showStop={isActiveStatus(status.status) && canStopScan(me, status)}
              stopping={stopping}
              onStop={stopScan}
              structureOpen={sidePanel === "structure"}
              onOpenStructure={(tree) => {
                setStructureTree(tree);
                setSidePanel("structure");
              }}
              sectionCards={sectionCards}
            />
          }
          right={rightPanel}
          expanded={panelExpanded}
        />
      </div>
    </div>
  );
}
