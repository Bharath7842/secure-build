/** Shared finding-verdict classification.
 *
 * Findings carry one of three verdicts: `true_positive` (confirmed),
 * `false_positive` (dismissed) and `unverified` — a regex match or an
 * inconclusive DAST check that nobody has confirmed. `unverified` is
 * deliberately neither confirmed nor dismissed, so it gets its own kind
 * instead of falling into an else branch. Every UI that renders a verdict
 * (SAST findings panel, DAST findings, report) must go through this. */

export type VerdictKind = "confirmed" | "dismissed" | "unverified";

export function verdictKind(verdict: string | null | undefined): VerdictKind {
  if (verdict === "true_positive") return "confirmed";
  if (verdict === "unverified") return "unverified";
  return "dismissed";
}

/** DAST findings preserve the three persisted states so browser observations that need review
 * remain visible instead of being silently grouped with dismissed findings. */
export function dastVerdictKind(verdict: string | null | undefined): VerdictKind {
  return verdictKind(verdict);
}
