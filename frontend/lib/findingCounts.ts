/** Severity chips for the SAST findings panel, read from the server's `severity_group_counts`.
 *
 *  The numbers are computed once, on the server (`scan_export.count_findings`), and shown here as
 *  they are: the chips, the PDF cover and the Excel summary cannot disagree because there is no
 *  second counting implementation to drift. Keys are upper-cased for display; INFO gets a chip
 *  only when the scan has an INFO finding. */

import type { ScanFindings } from "@/lib/types";

export type SeverityGroupCounts = NonNullable<ScanFindings["severity_group_counts"]>;

const CHIP_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export interface SeverityChips {
  /** The levels to render a chip for, in order. */
  levels: string[];
  /** Groups per severity across every verdict (a severity holding only false positives stays
   *  selectable). */
  all: Record<string, number>;
  /** Actionable (confirmed + unresolved) groups and their occurrences per severity. */
  actionable: Record<string, { groups: number; occurrences: number }>;
}

export function severityChips(counts: SeverityGroupCounts | null | undefined): SeverityChips {
  const all: Record<string, number> = {};
  const actionable: Record<string, { groups: number; occurrences: number }> = {};
  for (const level of [...CHIP_LEVELS, "INFO"]) {
    const key = level.toLowerCase();
    const open = counts?.actionable?.[key] ?? { groups: 0, occurrences: 0 };
    const dismissed = counts?.by_verdict?.false_positive?.[key]?.groups ?? 0;
    actionable[level] = open;
    all[level] = open.groups + dismissed;
  }
  const levels: string[] = [...CHIP_LEVELS];
  if (all.INFO > 0) levels.push("INFO");
  return { levels, all, actionable };
}
