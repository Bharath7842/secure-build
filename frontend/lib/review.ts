/** Wording, styling and small helpers shared by every reviewer-feedback view. */

import type {
  ConstructMix,
  IssueStatus,
  LearningStatus,
  ReviewDecision,
  ReviewEvent,
  ReviewStatus,
  ReviewerVerdict,
} from "@/lib/types";

export const DECISION_LABEL: Record<ReviewDecision, string> = {
  confirmed_issue: "Confirmed Issue",
  false_positive: "False Positive",
  needs_more_info: "Needs More Information",
  resolved: "Resolved",
  accept_risk: "Accept Risk",
};

export const REVIEWER_VERDICT_LABEL: Record<ReviewerVerdict, string> = {
  confirmed_issue: "Confirmed Issue",
  false_positive: "False Positive",
  needs_more_info: "Needs More Information",
};

export const REVIEW_STATUS_LABEL: Record<ReviewStatus, string> = {
  unreviewed: "Unreviewed",
  needs_info: "Needs information",
  reviewed: "Reviewed",
};

export const ISSUE_STATUS_LABEL: Record<IssueStatus, string> = {
  open: "Open",
  needs_info: "Needs information",
  resolved: "Resolved",
  risk_accepted: "Risk accepted",
  closed_false_positive: "Closed — false positive",
};

export const LEARNING_LABEL: Record<LearningStatus, string> = {
  pending_learning: "Pending Learning",
  approved_for_learning: "Approved for Learning",
  processed: "Processed",
};

/** A construct is mixed when its members did not all get the same outcome. */
export function isMixedConstruct(mix: ConstructMix | null | undefined): boolean {
  if (!mix) return false;
  return [mix.tp, mix.fp, mix.unresolved].filter((n) => n > 0).length > 1;
}

/** "Mixed: 3 confirmed · 150 false positive · 3 unresolved". */
export function constructMixLabel(mix: ConstructMix): string {
  const parts: string[] = [];
  if (mix.tp) parts.push(`${mix.tp} confirmed`);
  if (mix.fp) parts.push(`${mix.fp} false positive`);
  if (mix.unresolved) parts.push(`${mix.unresolved} unresolved`);
  return `Mixed: ${parts.join(" · ")}`;
}

/** What the engine itself concluded, in the reviewer's vocabulary. */
export function llmVerdictLabel(verdict: string | null | undefined): string {
  if (verdict === "true_positive") return "Confirmed Issue";
  if (verdict === "false_positive") return "False Positive";
  if (verdict === "unverified") return "Unverified";
  return "—";
}

const CHIP = "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium";

export const ISSUE_STATUS_CHIP: Record<IssueStatus, string> = {
  open: `${CHIP} bg-red-50 text-red-700`,
  needs_info: `${CHIP} bg-amber-50 text-amber-800`,
  resolved: `${CHIP} bg-emerald-50 text-emerald-700`,
  risk_accepted: `${CHIP} bg-slate-100 text-slate-700`,
  closed_false_positive: `${CHIP} bg-emerald-50 text-emerald-700`,
};

export const LEARNING_CHIP: Record<LearningStatus, string> = {
  pending_learning: `${CHIP} bg-amber-50 text-amber-800`,
  approved_for_learning: `${CHIP} bg-sky-50 text-sky-700`,
  processed: `${CHIP} bg-slate-100 text-slate-600`,
};

export const OVERRIDE_CHIP = `${CHIP} bg-violet-50 text-violet-700`;

export function formatWhen(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

/** Where in the pipeline a machine decision was made (`FindingDecision.stage`). */
export const STAGE_LABEL: Record<string, string> = {
  deep_scan: "Deep scan",
  triage_regex: "Regex match",
  triage_llm: "LLM triage",
  group_confirm: "Grouped review",
  flow_verify: "Flow verification",
  reachability_floor: "Reachability evidence",
  joern_confirm: "Code-graph review",
  reconcile: "Final sweep",
  sca_match: "Dependency match",
};

/** "Unresolved → Confirmed (90% confidence)" for a machine decision, or the reviewer's change. */
export function describeVerdictChange(entry: {
  source: string;
  from_verdict: string | null;
  to_verdict: string | null;
  confidence: number | null;
  action: string | null;
}): string {
  if (entry.source === "human") {
    const label = (v: string | null) => REVIEWER_VERDICT_LABEL[v as ReviewerVerdict] ?? v ?? "none";
    return entry.from_verdict && entry.from_verdict !== entry.to_verdict
      ? `${label(entry.from_verdict)} → ${label(entry.to_verdict)}`
      : label(entry.to_verdict);
  }
  const label = (v: string | null) =>
    v === "true_positive" ? "Confirmed" : v === "false_positive" ? "False positive" : v === "unverified" ? "Unresolved" : "—";
  const confidence = entry.confidence == null ? "" : ` (${Math.round(entry.confidence * 100)}% confidence)`;
  return entry.from_verdict && entry.from_verdict !== entry.to_verdict
    ? `${label(entry.from_verdict)} → ${label(entry.to_verdict)}${confidence}`
    : `${label(entry.to_verdict)}${confidence}`;
}

/** One line for a history entry, e.g. "alice changed the verdict: Confirmed Issue → False Positive". */
export function describeEvent(event: ReviewEvent): string {
  const verdict = (v: string | null) => REVIEWER_VERDICT_LABEL[v as ReviewerVerdict] ?? v ?? "none";
  switch (event.action) {
    case "verdict_set":
      return `${event.actor} set the verdict to ${verdict(event.to_verdict)}`;
    case "verdict_changed":
      return `${event.actor} changed the verdict: ${verdict(event.from_verdict)} → ${verdict(event.to_verdict)}`;
    case "verdict_reaffirmed":
      return `${event.actor} reaffirmed ${verdict(event.to_verdict)}`;
    case "resolved":
      return `${event.actor} marked the issue resolved`;
    case "risk_accepted":
      return `${event.actor} accepted the risk`;
    case "reopened":
      return `${event.actor} reopened the issue`;
    case "learning_approved":
      return `${event.actor} approved it for learning`;
    case "learning_processed":
      return `${event.actor} marked it processed`;
    case "learning_reset":
      return "Learning state reset to pending";
    case "member_decided":
      return `${event.actor} applied the decision to one occurrence`;
    default:
      return `${event.actor} — ${event.action}`;
  }
}
