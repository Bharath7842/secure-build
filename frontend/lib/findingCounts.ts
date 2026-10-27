/** Verdict tabs and severity chips for the SAST findings panel, read from the server's
 *  `severity_group_counts`.
 *
 *  The numbers are computed once, on the server (`scan_export.count_findings`), and shown here as
 *  they are: the tabs, the chips, the PDF cover and the Excel summary cannot disagree because there
 *  is no second counting implementation to drift. Keys are upper-cased for display; INFO gets a
 *  chip only when the scan has an INFO finding. */

import type { ScanFindings } from "@/lib/types";

export type SeverityGroupCounts = NonNullable<ScanFindings["severity_group_counts"]>;

export interface Cell {
  groups: number;
  occurrences: number;
}

/** A verdict bucket, or every bucket. */
export type VerdictTab = "true_positive" | "unverified" | "false_positive" | "all";

export const VERDICT_TABS: { key: VerdictTab; label: string }[] = [
  { key: "true_positive", label: "Confirmed" },
  { key: "unverified", label: "Unresolved" },
  { key: "false_positive", label: "False positive" },
  { key: "all", label: "All" },
];

const CHIP_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const EMPTY: Cell = { groups: 0, occurrences: 0 };

export interface SeverityChips {
  /** The levels to render a chip for, in order. */
  levels: string[];
  /** Groups and their occurrences per severity, in the selected tab. */
  counts: Record<string, Cell>;
}

function cellFor(counts: SeverityGroupCounts | null | undefined, tab: VerdictTab, severity: string): Cell {
  if (tab !== "all") return counts?.by_verdict?.[tab]?.[severity] ?? EMPTY;
  // Actionable already includes a verdict outside the contract; add the dismissed groups.
  const open = counts?.actionable?.[severity] ?? EMPTY;
  const dismissed = counts?.by_verdict?.false_positive?.[severity] ?? EMPTY;
  return { groups: open.groups + dismissed.groups, occurrences: open.occurrences + dismissed.occurrences };
}

export function severityChips(
  counts: SeverityGroupCounts | null | undefined,
  tab: VerdictTab = "all",
): SeverityChips {
  const out: Record<string, Cell> = {};
  for (const level of [...CHIP_LEVELS, "INFO"]) out[level] = cellFor(counts, tab, level.toLowerCase());
  const levels: string[] = [...CHIP_LEVELS];
  if (out.INFO.groups > 0) levels.push("INFO");
  return { levels, counts: out };
}

/** Groups and occurrences per verdict tab, from the server's bucket totals. */
export function verdictTabCounts(counts: SeverityGroupCounts | null | undefined): Record<VerdictTab, Cell> {
  const totals = counts?.totals ?? {};
  const all = Object.values(totals).reduce(
    (sum, cell) => ({ groups: sum.groups + cell.groups, occurrences: sum.occurrences + cell.occurrences }),
    EMPTY,
  );
  return {
    true_positive: totals.true_positive ?? EMPTY,
    unverified: totals.unverified ?? EMPTY,
    false_positive: totals.false_positive ?? EMPTY,
    all,
  };
}
