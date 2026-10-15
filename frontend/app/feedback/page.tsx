"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";

import FindingReviewForm from "@/components/FindingReviewForm";
import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";
import { RISK_LEVELS, RISK_STYLES, normalizeSeverity } from "@/lib/findingStyles";
import {
  ISSUE_STATUS_CHIP,
  ISSUE_STATUS_LABEL,
  LEARNING_CHIP,
  LEARNING_LABEL,
  OVERRIDE_CHIP,
  REVIEWER_VERDICT_LABEL,
  formatWhen,
  llmVerdictLabel,
  useReviewerName,
} from "@/lib/review";
import type { FeedbackFilter, FeedbackRow, Project, Scan } from "@/lib/types";

const PAGE_SIZE = 50;
const ALL_SCANS = "__reviewed__";

const FILTER_FIELD =
  "w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs text-[var(--ink)]";

interface Filters {
  reviewer_verdict: string;
  llm_verdict: string;
  override: string;
  severity: string;
  rule_id: string;
  cwe: string;
  reviewer: string;
  review_status: string;
  resolution_status: string;
  learning_status: string;
  reviewed_from: string;
  reviewed_to: string;
  q: string;
}

const NO_FILTERS: Filters = {
  reviewer_verdict: "",
  llm_verdict: "",
  override: "",
  severity: "",
  rule_id: "",
  cwe: "",
  reviewer: "",
  review_status: "",
  resolution_status: "",
  learning_status: "",
  reviewed_from: "",
  reviewed_to: "",
  q: "",
};

function Field({ id, label, children }: { id: string; label: string; children: React.ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">
        {label}
      </label>
      {children}
    </div>
  );
}

export default function FeedbackPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [projectId, setProjectId] = useState("");
  const [scanId, setScanId] = useState("");
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [page, setPage] = useState(0);
  const [data, setData] = useState<{ total: number; items: FeedbackRow[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [reviewer] = useReviewerName();
  const [reload, setReload] = useState(0);

  useEffect(() => {
    api.projects.list().then(setProjects).catch(() => undefined);
  }, []);

  // A project's finished SAST scans, newest first; the latest is selected by default.
  useEffect(() => {
    setScans([]);
    setScanId("");
    if (!projectId) return;
    let active = true;
    api.scans
      .list(projectId, "sast")
      .then((list) => {
        if (!active) return;
        const usable = list
          .filter((s) => s.status === "success" || s.status === "cancelled")
          .sort((a, b) => b.created_at.localeCompare(a.created_at));
        setScans(usable);
        setScanId(usable[0]?.id ?? ALL_SCANS);
      })
      .catch(() => active && setScanId(ALL_SCANS));
    return () => {
      active = false;
    };
  }, [projectId]);

  const query: FeedbackFilter = useMemo(() => {
    const q: FeedbackFilter = { limit: PAGE_SIZE, offset: page * PAGE_SIZE };
    if (projectId) q.project_id = projectId;
    if (scanId && scanId !== ALL_SCANS) q.scan_id = scanId;
    for (const [key, value] of Object.entries(filters)) {
      if (value) (q as Record<string, unknown>)[key] = value;
    }
    return q;
  }, [projectId, scanId, filters, page]);

  // Listing needs either a scan or "reviewed items" mode; wait until a project's scans are known.
  const ready = !projectId || scanId !== "";

  useEffect(() => {
    if (!ready) return;
    let active = true;
    setError(null);
    api.feedback
      .list(query)
      .then((res) => {
        if (active) setData({ total: res.total, items: res.items });
      })
      .catch((err) => {
        if (active) setError(err instanceof ApiError ? err.message : "Failed to load feedback.");
      });
    return () => {
      active = false;
    };
  }, [query, ready, reload]);

  const rowKey = (row: FeedbackRow) => row.review_id ?? `${row.scan_id}:${row.finding_id}`;

  const setFilter = useCallback((key: keyof Filters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(0);
  }, []);

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const selectable = (data?.items ?? []).filter((r) => r.review_id);

  function toggle(reviewId: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(reviewId)) next.delete(reviewId);
      else next.add(reviewId);
      return next;
    });
  }

  async function learningAction(kind: "approve" | "processed") {
    const ids = [...selected];
    if (ids.length === 0) return;
    setNotice(null);
    setError(null);
    try {
      const result =
        kind === "approve"
          ? await api.feedback.approveForLearning(ids, reviewer.trim())
          : await api.feedback.markProcessed(ids, reviewer.trim());
      setNotice(
        `${result.updated} updated${result.skipped ? `, ${result.skipped} skipped (not in the required state)` : ""}.`,
      );
      setSelected(new Set());
      setReload((n) => n + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Learning update failed.");
    }
  }

  async function exportLabels(format: "jsonl" | "csv") {
    setNotice(null);
    setError(null);
    try {
      const params = new URLSearchParams({ format });
      if (filters.learning_status) params.set("learning_status", filters.learning_status);
      if (projectId) params.set("project_id", projectId);
      const res = await fetch(`/api/feedback/export?${params.toString()}`);
      if (!res.ok) {
        const body = await res.json().catch(() => undefined);
        throw new ApiError(res.status, body);
      }
      const blob = await res.blob();
      const name = /filename="?([^"]+)"?/i.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? `sast-feedback.${format}`;
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Export failed.");
    }
  }

  const needsName = reviewer.trim() === "";

  return (
    <PageContainer>
      <h1 className="font-display text-3xl text-[var(--ink)]">Feedback &amp; Review</h1>
      <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
        Every reviewer decision on SAST findings, next to what the LLM originally concluded. A finding is closed only
        once it is dismissed as a false positive, or confirmed and then resolved or risk-accepted. Approved decisions
        become labelled data for the next learning phase.
      </p>

      <section className="mt-6 rounded-lg border border-slate-200 bg-white p-4" aria-label="Filters">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field id="fb-project" label="Project">
            <select id="fb-project" className={FILTER_FIELD} value={projectId} onChange={(e) => { setProjectId(e.target.value); setPage(0); }}>
              <option value="">All projects (reviewed only)</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </Field>
          <Field id="fb-scan" label="Scan">
            <select id="fb-scan" className={FILTER_FIELD} value={scanId || ALL_SCANS} disabled={!projectId} onChange={(e) => { setScanId(e.target.value); setPage(0); }}>
              <option value={ALL_SCANS}>All scans (reviewed only)</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  v{s.version} · {s.commit_sha?.slice(0, 7) ?? s.branch} · {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </Field>
          <Field id="fb-reviewer-verdict" label="Reviewer verdict">
            <select id="fb-reviewer-verdict" className={FILTER_FIELD} value={filters.reviewer_verdict} onChange={(e) => setFilter("reviewer_verdict", e.target.value)}>
              <option value="">Any</option>
              {Object.entries(REVIEWER_VERDICT_LABEL).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </Field>
          <Field id="fb-llm-verdict" label="Original LLM verdict">
            <select id="fb-llm-verdict" className={FILTER_FIELD} value={filters.llm_verdict} onChange={(e) => setFilter("llm_verdict", e.target.value)}>
              <option value="">Any</option>
              <option value="true_positive">Confirmed Issue</option>
              <option value="false_positive">False Positive</option>
              <option value="unverified">Unverified</option>
            </select>
          </Field>
          <Field id="fb-override" label="Verdict overrides">
            <select id="fb-override" className={FILTER_FIELD} value={filters.override} onChange={(e) => setFilter("override", e.target.value)}>
              <option value="">All</option>
              <option value="true">Overridden only</option>
              <option value="false">Not overridden</option>
            </select>
          </Field>
          <Field id="fb-severity" label="Severity">
            <select id="fb-severity" className={FILTER_FIELD} value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)}>
              <option value="">Any</option>
              {RISK_LEVELS.map((level) => (
                <option key={level} value={level}>{level}</option>
              ))}
            </select>
          </Field>
          <Field id="fb-rule" label="Rule ID">
            <input id="fb-rule" className={FILTER_FIELD} value={filters.rule_id} onChange={(e) => setFilter("rule_id", e.target.value)} placeholder="e.g. csrf-disabled" />
          </Field>
          <Field id="fb-cwe" label="CWE">
            <input id="fb-cwe" className={FILTER_FIELD} value={filters.cwe} onChange={(e) => setFilter("cwe", e.target.value)} placeholder="e.g. CWE-89" />
          </Field>
          <Field id="fb-reviewer" label="Reviewer">
            <input id="fb-reviewer" className={FILTER_FIELD} value={filters.reviewer} onChange={(e) => setFilter("reviewer", e.target.value)} placeholder="Name contains…" />
          </Field>
          <Field id="fb-review-status" label="Review status">
            <select id="fb-review-status" className={FILTER_FIELD} value={filters.review_status} onChange={(e) => setFilter("review_status", e.target.value)}>
              <option value="">Any</option>
              <option value="unreviewed">Unreviewed</option>
              <option value="needs_info">Needs information</option>
              <option value="reviewed">Reviewed</option>
            </select>
          </Field>
          <Field id="fb-resolution" label="Resolution status">
            <select id="fb-resolution" className={FILTER_FIELD} value={filters.resolution_status} onChange={(e) => setFilter("resolution_status", e.target.value)}>
              <option value="">Any</option>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="risk_accepted">Risk accepted</option>
            </select>
          </Field>
          <Field id="fb-learning" label="Learning state">
            <select id="fb-learning" className={FILTER_FIELD} value={filters.learning_status} onChange={(e) => setFilter("learning_status", e.target.value)}>
              <option value="">Any</option>
              {Object.entries(LEARNING_LABEL).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </Field>
          <Field id="fb-from" label="Reviewed from">
            <input id="fb-from" type="date" className={FILTER_FIELD} value={filters.reviewed_from} onChange={(e) => setFilter("reviewed_from", e.target.value)} />
          </Field>
          <Field id="fb-to" label="Reviewed to">
            <input id="fb-to" type="date" className={FILTER_FIELD} value={filters.reviewed_to} onChange={(e) => setFilter("reviewed_to", e.target.value)} />
          </Field>
          <Field id="fb-q" label="Search">
            <input id="fb-q" className={FILTER_FIELD} value={filters.q} onChange={(e) => setFilter("q", e.target.value)} placeholder="Title, file, comment…" />
          </Field>
          <div className="flex items-end">
            <button type="button" className="rounded-md border border-slate-200 px-3 py-1.5 text-xs font-medium text-[var(--ink)] hover:bg-slate-50" onClick={() => { setFilters(NO_FILTERS); setPage(0); }}>
              Clear filters
            </button>
          </div>
        </div>
      </section>

      <section className="mt-4 flex flex-wrap items-center gap-2 text-xs" aria-label="Learning data">
        <span className="text-[var(--muted)]">Selected: {selected.size}</span>
        <button type="button" disabled={selected.size === 0 || needsName} onClick={() => learningAction("approve")} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium disabled:opacity-50" title={needsName ? "Enter your name on any finding's review form first" : undefined}>
          Approve for learning
        </button>
        <button type="button" disabled={selected.size === 0 || needsName} onClick={() => learningAction("processed")} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium disabled:opacity-50">
          Mark processed
        </button>
        <span className="ml-auto flex gap-2">
          <button type="button" onClick={() => exportLabels("jsonl")} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium">
            Export JSONL
          </button>
          <button type="button" onClick={() => exportLabels("csv")} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-medium">
            Export CSV
          </button>
        </span>
      </section>
      {needsName ? (
        <p className="mt-1 text-xs text-[var(--muted)]">Learning actions are recorded under your name; open a finding below and enter it once.</p>
      ) : null}

      {error ? <div role="alert" className="mt-4 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div> : null}
      {notice ? <div role="status" className="mt-4 rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">{notice}</div> : null}

      <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200 bg-white">
        <table className="w-full min-w-[1180px] table-fixed text-left text-sm">
          <colgroup>
            <col className="w-10" />
            <col />
            <col className="w-28" />
            <col className="w-32" />
            <col className="w-40" />
            <col className="w-28" />
            <col className="w-28" />
            <col className="w-40" />
            <col className="w-40" />
          </colgroup>
          <thead>
            <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
              <th className="w-8 px-3 py-2" aria-label="Select" />
              <th className="px-3 py-2">Finding</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">LLM verdict</th>
              <th className="px-3 py-2">Reviewer verdict</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Reviewer</th>
              <th className="px-3 py-2">Reviewed</th>
              <th className="px-3 py-2">Learning</th>
            </tr>
          </thead>
          <tbody>
            {data === null && !error ? (
              <tr><td colSpan={9} className="px-3 py-6 text-center text-[var(--muted)]">Loading…</td></tr>
            ) : data && data.items.length === 0 ? (
              <tr><td colSpan={9} className="px-3 py-6 text-center text-[var(--muted)]">No findings match these filters.</td></tr>
            ) : (
              data?.items.map((row) => {
                const key = rowKey(row);
                const open = openKey === key;
                const severity = normalizeSeverity(row.severity);
                return (
                  <Fragment key={key}>
                    <tr className="border-b border-slate-100 align-top hover:bg-slate-50/60">
                      <td className="px-3 py-2">
                        {row.review_id ? (
                          <input type="checkbox" aria-label={`Select ${row.title ?? row.finding_id}`} checked={selected.has(row.review_id)} onChange={() => toggle(row.review_id!)} />
                        ) : null}
                      </td>
                      <td className="min-w-0 px-3 py-2">
                        <button type="button" aria-expanded={open} onClick={() => setOpenKey(open ? null : key)} className="agent-focus-ring block w-full min-w-0 text-left">
                          <span className="block break-words font-medium text-[var(--ink)]">{row.title ?? row.rule_id ?? "Finding"}</span>
                          <span className="mt-0.5 block break-all font-mono text-xs text-[var(--muted)]" title={row.file_path ?? ""}>
                            {row.rule_id ?? "—"}{row.cwe ? ` · ${row.cwe}` : ""} · {row.file_path ?? ""}{row.line ? `:${row.line}` : ""}
                            {(row.occurrence_count ?? 1) > 1 ? ` · ${row.occurrence_count}×` : ""}
                          </span>
                        </button>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase ${RISK_STYLES[severity]?.chip ?? ""}`}>{severity}</span>
                      </td>
                      <td className="px-3 py-2 text-xs">
                        {llmVerdictLabel(row.llm_verdict)}
                      </td>
                      <td className="px-3 py-2 text-xs">
                        {row.reviewer_verdict ? REVIEWER_VERDICT_LABEL[row.reviewer_verdict] : <span className="text-[var(--muted)]">Unreviewed</span>}
                        {row.is_override ? <span className={`ml-1 ${OVERRIDE_CHIP}`}>Override</span> : null}
                      </td>
                      <td className="px-3 py-2"><span className={ISSUE_STATUS_CHIP[row.issue_status]}>{ISSUE_STATUS_LABEL[row.issue_status]}</span></td>
                      <td className="px-3 py-2 text-xs">{row.reviewer ?? "—"}</td>
                      <td className="px-3 py-2 text-xs">{formatWhen(row.reviewed_at)}</td>
                      <td className="px-3 py-2">
                        {row.learning_status ? <span className={LEARNING_CHIP[row.learning_status]}>{LEARNING_LABEL[row.learning_status]}</span> : <span className="text-xs text-[var(--muted)]">—</span>}
                      </td>
                    </tr>
                    {open ? (
                      <tr className="border-b border-slate-100 bg-slate-50/50">
                        <td />
                        <td colSpan={8} className="px-3 py-3">
                          {row.llm_explanation ? <p className="text-sm text-[var(--muted)]">{row.llm_explanation}</p> : null}
                          {row.llm_remediation ? (
                            <div className="mt-2 rounded border border-emerald-100 bg-emerald-50/60 px-2.5 py-2 text-sm">
                              <div className="text-xs font-semibold text-emerald-800">Recommended remediation</div>
                              <div className="whitespace-pre-wrap">{row.llm_remediation}</div>
                            </div>
                          ) : null}
                          {row.snippet ? (
                            <pre className="mt-2 overflow-x-auto rounded border border-slate-200 bg-slate-950/5 p-3 font-mono text-xs">{row.snippet}</pre>
                          ) : null}
                          <FindingReviewForm
                            scanId={row.scan_id}
                            findingId={row.finding_id}
                            llmVerdict={row.llm_verdict}
                            hasReview={Boolean(row.review_id)}
                            onSaved={() => setReload((n) => n + 1)}
                          />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-3 flex items-center justify-between text-xs text-[var(--muted)]">
        <span>{total} item{total === 1 ? "" : "s"}{selectable.length ? ` · ${selectable.length} reviewed on this page` : ""}</span>
        <span className="flex items-center gap-2">
          <button type="button" disabled={page === 0} onClick={() => setPage((p) => p - 1)} className="rounded-md border border-slate-200 bg-white px-2.5 py-1 disabled:opacity-50">Previous</button>
          <span>Page {page + 1} of {pages}</span>
          <button type="button" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)} className="rounded-md border border-slate-200 bg-white px-2.5 py-1 disabled:opacity-50">Next</button>
        </span>
      </div>
    </PageContainer>
  );
}
