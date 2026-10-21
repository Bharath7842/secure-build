/** Shared finding-verdict classification.
 *
 * Findings carry one of three verdicts: `true_positive` (confirmed),
 * `false_positive` (dismissed) and `unverified` — unresolved: a regex match, an
 * unusable model answer or an inconclusive DAST check that nobody has decided.
 * `unverified` is deliberately neither confirmed nor dismissed, so it gets its
 * own kind instead of falling into an else branch. A missing or unrecognised
 * value is `unknown` — never "dismissed" — so a verdict outside the contract
 * cannot pass for a decision. Every UI that renders a verdict (SAST findings
 * panel, DAST findings, report) must go through this. */

export type VerdictKind = "confirmed" | "dismissed" | "unverified" | "unknown";

export function verdictKind(verdict: string | null | undefined): VerdictKind {
  if (verdict === "true_positive") return "confirmed";
  if (verdict === "unverified") return "unverified";
  if (verdict === "false_positive") return "dismissed";
  return "unknown";
}

/** DAST findings preserve the three persisted states so browser observations that need review
 * remain visible instead of being silently grouped with dismissed findings. DAST has always
 * read an absent verdict as dismissed; that is unchanged. */
export function dastVerdictKind(verdict: string | null | undefined): VerdictKind {
  const kind = verdictKind(verdict);
  return kind === "unknown" ? "dismissed" : kind;
}

/** Why an `unverified` finding is undecided (`Finding.unresolved_reason`), in words. */
const UNRESOLVED_REASON_LABEL: Record<string, string> = {
  not_reviewed_regex: "regex match, not reviewed",
  not_reviewed_joern: "code-graph query, not reviewed",
  not_reviewed_sca: "dependency match, not reviewed",
  llm_missing_verdict: "the model gave no verdict",
  llm_unrecognised_verdict: "the model's verdict was not recognised",
  llm_call_failed: "the model call failed",
  llm_budget_exhausted: "the LLM budget was reached",
  cap_reached: "the review cap was reached",
  evidence_missing: "evidence is missing",
};

export function unresolvedReasonLabel(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return UNRESOLVED_REASON_LABEL[reason] ?? reason;
}

/** The human review workflow (`Finding.review_state`), apart from what the scanner decided. */
export type ReviewState = "pending" | "agreed" | "overridden" | "resolved";

export function reviewStateLabel(state: string | null | undefined): ReviewState {
  return state === "agreed" || state === "overridden" || state === "resolved" ? state : "pending";
}
