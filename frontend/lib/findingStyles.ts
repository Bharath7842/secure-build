/** Severity and verdict styling shared by every findings view (SAST/SCA/SBOM panel, DAST panel,
 *  report). One place, so a severity or a verdict looks and reads the same everywhere. */

import type { VerdictKind } from "@/lib/verdict";

export const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const RISK_DOT: Record<string, string> = {
  CRITICAL: "bg-red-700",
  HIGH: "bg-red-500",
  MEDIUM: "bg-amber-500",
  LOW: "bg-emerald-500",
  INFO: "bg-slate-400",
};

export const RISK_STYLES: Record<string, { chip: string; active: string }> = {
  CRITICAL: { chip: "bg-red-100 text-red-800", active: "bg-red-100 text-red-800 ring-1 ring-red-300" },
  HIGH: { chip: "bg-red-50 text-red-700", active: "bg-red-50 text-red-700 ring-1 ring-red-300" },
  MEDIUM: { chip: "bg-amber-50 text-amber-800", active: "bg-amber-50 text-amber-800 ring-1 ring-amber-300" },
  LOW: { chip: "bg-emerald-50 text-emerald-700", active: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-300" },
  INFO: { chip: "bg-slate-100 text-slate-600", active: "bg-slate-100 text-slate-700 ring-1 ring-slate-300" },
};

/** Unknown severities read as MEDIUM, so a finding never vanishes from the count. `allowInfo` keeps
 *  INFO as its own level (DAST has one; the SAST panel does not and keeps its old behaviour). */
export function normalizeSeverity(severity: string | null | undefined, allowInfo = false): string {
  const key = (severity || "").trim().toUpperCase();
  return RISK_LEVELS.includes(key as RiskLevel) || (allowInfo && key === "INFO") ? key : "MEDIUM";
}

export const VERDICT_ROW: Record<VerdictKind, string> = {
  confirmed: "border-red-100 bg-red-50/40",
  dismissed: "border-emerald-100 bg-emerald-50/30",
  unverified: "border-amber-100 bg-amber-50/30",
  unknown: "border-slate-300 bg-slate-100/60",
};

export const VERDICT_TEXT: Record<VerdictKind, string> = {
  confirmed: "text-red-700",
  dismissed: "text-emerald-700",
  unverified: "text-amber-700",
  unknown: "text-slate-700",
};

/** The SAST wording: the scanner's verdict by its real name. An unverified finding is
 *  unresolved; `unresolvedReasonLabel` says why. */
export const VERDICT_LABEL: Record<VerdictKind, string> = {
  confirmed: "Confirmed",
  dismissed: "False positive",
  unverified: "Unresolved",
  unknown: "Unknown verdict",
};

/** DAST wording: confirmed is the model's FAIL, dismissed is the model's PASS. */
export const DAST_VERDICT_LABEL: Record<VerdictKind, string> = {
  confirmed: "Confirmed",
  dismissed: "Dismissed",
  unverified: "Dismissed",
  unknown: "Dismissed",
};

export function formatConfidence(value: number | null | undefined): string | null {
  if (value == null || Number.isNaN(value)) return null;
  const pct = value > 1 ? value / 100 : value;
  const clamped = Math.max(0, Math.min(1, pct));
  return `${Math.round(clamped * 100)}%`;
}
